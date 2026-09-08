//! curam security core — PyO3 module.
//!
//! e01s01: maturin/pyo3/abi3 skeleton + `classify()`. Every verdict is a
//! provable chain {action, rule_id, source, source_hash, evidence}.
//! e01s03: injection defense — `classify` asks on exec of repo-derived
//! content (e.g. `bash setup.sh`), `scan_context` flags embedded injection
//! phrases in text.

use pyo3::prelude::*;
use sha2::{Digest, Sha256};

/// Built-in dangerous exact commands → deny. Full argv parsing + policy port
/// arrives in e01s02; this is the tracer set.
const DANGEROUS_EXACT: &[&str] = &["rm -rf /"];

/// Shells whose exec of a repo-relative script is "execute untrusted content"
/// → ask (the Gap-1 signature: `bash setup.sh` with adversarial file content).
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "fish", "ksh"];

/// Injection phrases flagged by scan_context. Case-insensitive substring
/// matches; the corpus-shaped markers (MARKER: EXFIL_MARKER) are substrings.
const INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("inject_ignore_instructions", "ignore previous instructions"),
    ("inject_exfil_marker", "MARKER: EXFIL"),
];

/// Reproducible hash of the compiled-in rule set, so a verdict can be
/// re-derived from a known ruleset + list version (the open-source audit
/// property).
fn rules_hash() -> String {
    let mut s = Sha256::new();
    for rule in DANGEROUS_EXACT {
        s.update(rule.as_bytes());
        s.update(b"\n");
    }
    for shell in SHELLS {
        s.update(shell.as_bytes());
        s.update(b"\n");
    }
    for (id, pat) in INJECTION_PATTERNS {
        s.update(id.as_bytes());
        s.update(pat.as_bytes());
        s.update(b"\n");
    }
    hex(&s.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn verdict(action: &str, rule_id: &str, evidence: &str) -> Verdict {
    Verdict {
        action: action.into(),
        rule_id: rule_id.into(),
        source: "rules".into(),
        source_hash: rules_hash(),
        evidence: evidence.into(),
    }
}

/// A single classification, with the full provenance chain.
#[pyclass(module = "curamsec")]
#[derive(Clone)]
pub struct Verdict {
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    rule_id: String,
    #[pyo3(get)]
    source: String,
    #[pyo3(get)]
    source_hash: String,
    #[pyo3(get)]
    evidence: String,
}

#[pymethods]
impl Verdict {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        action: String,
        rule_id: String,
        source: String,
        source_hash: String,
        evidence: String,
    ) -> Self {
        Self {
            action,
            rule_id,
            source,
            source_hash,
            evidence,
        }
    }
}

/// Classify a command string → `Verdict` in {allow, ask, deny}.
#[pyfunction]
fn classify(command: &str) -> Verdict {
    for rule in DANGEROUS_EXACT {
        if command == *rule {
            return verdict("deny", "dangerous_exact", command);
        }
    }
    if exec_repo_script(command) {
        return verdict(
            "ask",
            "exec_repo_script",
            "shell executes a repo-relative script; verify file provenance",
        );
    }
    verdict("allow", "no_rule", command)
}

/// True when a shell's argument (skipping flags and `-c` inline code) is a
/// repo-relative path — i.e. executing file-derived, untrusted content.
fn exec_repo_script(command: &str) -> bool {
    let argv: Vec<&str> = command.split_whitespace().collect();
    if argv.is_empty() || !SHELLS.contains(&argv[0]) {
        return false;
    }
    let mut i = 1;
    while i < argv.len() {
        let tok = argv[i];
        if tok == "-c" {
            // `-c` takes the rest of the line as the inline script — not a
            // file. (split_whitespace loses quotes, but everything after -c IS
            // the script, which is exactly what we want to allow.)
            return false;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        // first non-flag token: repo-relative (no leading /) = repo content
        return !tok.starts_with('/');
    }
    false
}

/// One injection finding from scan_context.
#[pyclass(module = "curamsec")]
#[derive(Clone)]
pub struct Finding {
    #[pyo3(get)]
    rule_id: String,
    #[pyo3(get)]
    evidence: String,
}

#[pymethods]
impl Finding {
    #[new]
    fn new(rule_id: String, evidence: String) -> Self {
        Self { rule_id, evidence }
    }
}

/// Scan free text for embedded injection phrases.
///
/// Returns one `Finding` per matched pattern (rule_id + evidence). `threshold`
/// is the minimum total match count before findings are returned (tunable,
/// default 1). Case-insensitive substring matching.
#[pyfunction]
#[pyo3(signature = (text, threshold = 1))]
fn scan_context(text: &str, threshold: usize) -> Vec<Finding> {
    let lower = text.to_lowercase();
    let mut findings = Vec::new();
    for (id, pat) in INJECTION_PATTERNS {
        if lower.contains(&pat.to_lowercase()) {
            findings.push(Finding::new(id.to_string(), (*pat).to_string()));
        }
    }
    if findings.len() < threshold {
        Vec::new()
    } else {
        findings
    }
}

#[pymodule]
fn curamsec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Verdict>()?;
    m.add_class::<Finding>()?;
    m.add_function(wrap_pyfunction!(classify, m)?)?;
    m.add_function(wrap_pyfunction!(scan_context, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_dangerous_exact() {
        let v = classify("rm -rf /");
        assert_eq!(v.action, "deny");
        assert_eq!(v.rule_id, "dangerous_exact");
    }

    #[test]
    fn allow_benign() {
        assert_eq!(classify("ls").action, "allow");
        assert_eq!(classify("bash -c 'echo hi'").action, "allow");
    }

    #[test]
    fn verdict_is_full_provenance_chain() {
        let v = classify("rm -rf /");
        assert!(!v.rule_id.is_empty());
        assert!(!v.source.is_empty());
        assert!(!v.source_hash.is_empty());
        assert_eq!(v.evidence, "rm -rf /");
        // same ruleset -> stable, reproducible hash
        assert_eq!(v.source_hash, rules_hash());
    }

    #[test]
    fn classify_repo_script_asks() {
        let v = classify("bash setup.sh");
        assert_eq!(v.action, "ask");
        assert_eq!(v.rule_id, "exec_repo_script");
    }

    #[test]
    fn classify_repo_script_skips_flags_and_dash_c() {
        assert_eq!(classify("bash -x setup.sh").action, "ask");
        assert_eq!(classify("sh -e install.sh").action, "ask");
        // absolute system scripts are not repo-derived content
        assert_eq!(classify("bash /usr/local/bin/setup").action, "allow");
        // inline code via -c is not a file
        assert_eq!(classify("bash -c 'cat /etc/passwd'").action, "allow");
    }

    #[test]
    fn scan_flags_injection() {
        assert!(scan_context("ignore previous instructions", 1).len() == 1);
        assert!(scan_context("MARKER: EXFIL_MARKER here", 1).len() == 1);
    }

    #[test]
    fn scan_is_case_insensitive_and_thresholded() {
        assert_eq!(scan_context("Ignore Previous Instructions", 1).len(), 1);
        assert_eq!(scan_context("clean text", 1).len(), 0);
        // two distinct phrases need threshold 2
        assert_eq!(
            scan_context("ignore previous instructions + MARKER: EXFIL", 2).len(),
            2
        );
        assert_eq!(scan_context("ignore previous instructions", 2).len(), 0);
    }

    #[test]
    fn findings_carry_rule_id_and_evidence() {
        let f = &scan_context("ignore previous instructions", 1)[0];
        assert_eq!(f.rule_id, "inject_ignore_instructions");
        assert_eq!(f.evidence, "ignore previous instructions");
    }
}

