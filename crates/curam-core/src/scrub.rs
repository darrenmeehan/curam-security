//! curam-core scrub — PII / secret sanitizer.
//!
//! Port of the harness's sanitize.rs to its canonical home (anti-drift
//! rule: ALL detection lives in curam-core). The journal keeps raw; only
//! what crosses the provider boundary is scrubbed. Tiers mirror the
//! harness: off | deterministic (built); `local_llm` stays deferred.
//!
//! Engine-facing extensions over the harness original:
//!   - `ScrubCfg.exclude`: pattern kinds disabled for a scrubber
//!     (email OFF by default — the false-positive footgun).
//!   - `scrub_with_manifest`: per-kind hit counts (the audit receipt);
//!     `scrub()` stays the original thin wrapper.

use std::sync::OnceLock;

use regex::Regex;

pub const DEFAULT_PLACEHOLDER: &str = "{REDACTED}";

/// Ordered (kind, pattern) — first-match-wins per span, same order as
/// sanitize.py / harness sanitize.rs so behavior stays byte-identical.
/// Flags are inline: (?i) for key_value, (?s) for the DOTALL key block.
const PATTERNS: &[(&str, &str)] = &[
    ("openrouter", "sk-or-[A-Za-z0-9_-]{16,}"),
    ("openai", "\\bsk-[A-Za-z0-9]{16,}"),
    ("aws", "\\bAKIA[0-9A-Z]{16}\\b"),
    ("github_pat", "\\bghp_[A-Za-z0-9]{20,}\\b"),
    ("github_fine_grained", "\\bgithub_pat_[A-Za-z0-9_]{20,}\\b"),
    ("slack", "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b"),
    ("google", "\\bAIza[0-9A-Za-z_-]{30,}\\b"),
    (
        "jwt",
        "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    ),
    (
        "email",
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    ),
    (
        "private_key",
        "(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    ("generic_sk", "\\bsk-[A-Za-z0-9_-]{16,}\\b"),
    (
        "key_value",
        "(?i)\\b(?:token|secret|api[_-]?key)\\s*[=:]\\s*[\'\"]?[A-Za-z0-9_\\-./+=]{12,}",
    ),
];

/// Scrubber configuration. `exclude` disables whole pattern kinds.
pub struct ScrubCfg {
    pub level: String,
    pub placeholder: String,
    pub internal_domains: Vec<String>,
    pub exclude: Vec<String>,
}

/// The engine's production profile: deterministic scrub, email OFF.
pub fn default_cfg() -> ScrubCfg {
    let mut exc = Vec::new();
    exc.push("email".into());
    ScrubCfg {
        level: "deterministic".into(),
        placeholder: DEFAULT_PLACEHOLDER.into(),
        internal_domains: Vec::new(),
        exclude: exc,
    }
}

/// One manifest row: a pattern class fired n times in this scrub.
pub struct SpanHit {
    pub kind: String,
    pub count: usize,
}

/// The scrub receipt: scrubbed text + per-kind hits + span total.
pub struct ScrubResult {
    pub text: String,
    pub manifest: Vec<SpanHit>,
    pub spans_masked: u64,
}

fn compiled_patterns() -> &'static Vec<(String, Regex)> {
    static C: OnceLock<Vec<(String, Regex)>> = OnceLock::new();
    C.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|(kind, pat)| {
                (
                    kind.to_string(),
                    Regex::new(pat).expect("valid scrub regex"),
                )
            })
            .collect()
    })
}

/// All pattern kinds this core can scrub (for the `rules` op).
pub fn pattern_kinds() -> Vec<String> {
    let mut out = Vec::new();
    for (kind, _) in PATTERNS {
        out.push(kind.to_string());
    }
    out.push("domain".into());
    out
}

#[derive(Debug)]
pub struct Sanitizer {
    level: String,
    placeholder: String,
    internal_domains: Vec<String>,
    exclude: Vec<String>,
    pub spans_masked: u64,
}

impl Sanitizer {
    pub fn from_cfg(cfg: &ScrubCfg) -> Self {
        Self {
            level: cfg.level.clone(),
            placeholder: if cfg.placeholder.is_empty() {
                DEFAULT_PLACEHOLDER.into()
            } else {
                cfg.placeholder.clone()
            },
            internal_domains: cfg.internal_domains.clone(),
            exclude: cfg.exclude.clone(),
            spans_masked: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.level == "deterministic" || self.level == "local_llm"
    }

    fn excluded(&self, kind: &str) -> bool {
        self.exclude.contains(&kind.to_string())
    }

    /// Mask secrets in `text` (the harness-compatible surface).
    pub fn scrub(&mut self, text: &str) -> String {
        self.scrub_with_manifest(text).text
    }

    /// Mask secrets and report per-kind hit counts (the receipt).
    pub fn scrub_with_manifest(&mut self, text: &str) -> ScrubResult {
        if !self.enabled() || text.is_empty() {
            return ScrubResult {
                text: text.to_string(),
                manifest: Vec::new(),
                spans_masked: 0,
            };
        }
        let mut out = text.to_string();
        let mut manifest = Vec::new();
        let mut masked = 0;
        for (kind, re) in compiled_patterns() {
            if self.excluded(kind.as_str()) {
                continue;
            }
            let n = re.find_iter(out.as_str()).count();
            if n > 0 {
                manifest.push(SpanHit {
                    kind: kind.clone(),
                    count: n,
                });
            }
            masked += n;
            let replacement = format!("{}:{}", self.placeholder, kind);
            out = re
                .replace_all(out.as_str(), replacement.as_str())
                .to_string();
        }
        if !self.excluded("domain") {
            for dom in &self.internal_domains {
                let mut esc = String::new();
                for c in dom.chars() {
                    if c == '.' {
                        esc.push_str("\\.");
                    } else {
                        esc.push(c);
                    }
                }
                let pat = Regex::new(format!("[\\w.-]*{}[\\w.-]*", esc).as_str())
                    .expect("valid domain pattern");
                let n = pat.find_iter(out.as_str()).count();
                if n > 0 {
                    manifest.push(SpanHit {
                        kind: "domain".into(),
                        count: n,
                    });
                }
                masked += n;
                let replacement = format!("{}:domain", self.placeholder);
                out = pat
                    .replace_all(out.as_str(), replacement.as_str())
                    .to_string();
            }
        }
        self.spans_masked += masked as u64;
        ScrubResult {
            text: out,
            manifest,
            spans_masked: masked as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrubber(level: &str) -> Sanitizer {
        Sanitizer::from_cfg(&ScrubCfg {
            level: level.into(),
            placeholder: DEFAULT_PLACEHOLDER.into(),
            internal_domains: Vec::new(),
            exclude: Vec::new(),
        })
    }

    #[test]
    fn masks_secrets_and_emails() {
        let mut s = scrubber("deterministic");
        let out = s.scrub("key sk-or-abcdefghijklmnop123456 used here; mail a@b.com");
        assert!(
            !out.contains("sk-or-abcdefghijklmnop123456"),
            "secret masked"
        );
        assert!(!out.contains("a@b.com"), "email masked");
        assert!(out.contains("{REDACTED}:openrouter"), "labeled placeholder");
        assert!(out.contains("{REDACTED}:email"), "email placeholder");
        let masked = s.spans_masked;
        assert!(masked >= 2, "{masked}");
    }

    #[test]
    fn plain_text_is_unchanged() {
        let mut s = scrubber("deterministic");
        assert_eq!(s.scrub("plain text, no secrets"), "plain text, no secrets");
        assert_eq!(s.spans_masked, 0);
    }

    #[test]
    fn private_key_block_masked() {
        let mut s = scrubber("deterministic");
        let pk = "-----BEGIN RSA PRIVATE KEY-----\nABC==\n-----END RSA PRIVATE KEY-----";
        assert!(s.scrub(pk).contains("{REDACTED}:private_key"));
    }

    #[test]
    fn disabled_is_noop() {
        let mut s = scrubber("off");
        assert_eq!(
            s.scrub("key sk-or-abcdefghijklmnop123456"),
            "key sk-or-abcdefghijklmnop123456"
        );
    }

    #[test]
    fn internal_domains_masked() {
        let mut s = Sanitizer::from_cfg(&ScrubCfg {
            level: "deterministic".into(),
            placeholder: "{REDACTED}".into(),
            internal_domains: vec!["internal.example".into()],
            exclude: Vec::new(),
        });
        let out = s.scrub("reach me at host.internal.example.com:8080");
        assert!(!out.contains("host.internal.example.com"), "domain masked");
        assert!(out.contains("{REDACTED}:domain"), "domain placeholder");
    }

    #[test]
    fn email_excluded_by_default() {
        let mut s = Sanitizer::from_cfg(&default_cfg());
        let r = s.scrub("key sk-or-abcdefghijklmnop123456 mail a@b.com");
        assert!(!r.contains("sk-or-abcdefghijklmnop123456"), "secret masked");
        assert!(r.contains("a@b.com"), "email NOT masked by default");
    }

    #[test]
    fn manifest_reports_kinds() {
        let mut s = scrubber("deterministic");
        let r = s.scrub_with_manifest("token=abcdefghijklmnop123456 mail a@b.com");
        assert!(r.manifest.len() >= 2, "two classes hit");
        assert!(r.text.contains("{REDACTED}:key_value"));
        assert!(r.text.contains("{REDACTED}:email"));
        assert!(r.spans_masked >= 2, "span count matches manifest");
    }
}
