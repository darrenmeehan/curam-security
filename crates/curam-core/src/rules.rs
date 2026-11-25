//! Versioned policy rules — a 1:1 port of curam-harness-poc `policy.py`.
//!
//! This module is the single source of the allow/ask/deny tables. Parity with
//! the Python original is guarded by the fixture in `tests/parity_fixture.json`
//! (Rust) and the live cross-check in `tests/parity.py` (Python vs. Rust).
//!
//! Versioning: bump `RULES_VERSION` + re-verify parity whenever a table
//! changes, so a `Verdict`'s `source_hash` stays reproducible.

use sha2::{Digest, Sha256};

/// Monotonic version of this rule set (mirrors list `rev` semantics).
pub const RULES_VERSION: &str = "e01s02-v1";

/// Wrapper programs that don't change what they wrap (policy.py `WRAPPERS`).
pub const WRAPPERS: &[&str] = &["sudo", "env", "nohup", "nice", "time", "command", "xargs"];

/// Programs whose mere presence means "ask the human" (policy.py `ALWAYS_ASK`).
pub const ALWAYS_ASK: &[&str] = &[
    // filesystem destruction
    "rm",
    "dd",
    "mkfs",
    "mkfs.btrfs",
    "mkfs.ext4",
    "mkfs.xfs",
    "fdisk",
    "parted",
    "wipefs",
    "shred",
    // system state
    "shutdown",
    "reboot",
    "poweroff",
    "systemctl",
    "journalctl",
    "iptables",
    "firewall-cmd",
    "ufw",
    "nft",
    // secrets / credentials
    "chmod",
    "chown",
    "useradd",
    "passwd",
    "usermod",
];

/// Flags that escalate a (usually-safe) program to "ask" (policy.py
/// `ASK_FLAGS`).
pub const ASK_FLAGS: &[(&str, &[&str])] = &[
    (
        "git",
        &["push", "reset", "clean", "gc", "filter-branch", "rm"],
    ),
    ("curl", &["-o", "-O", "--output", "--remote-name"]),
    ("wget", &["-o", "-O", "--output-document"]),
    ("scp", &["-r"]),
];

/// Poison-list deny patterns — (rule_id, Python-compatible regex). These match
/// the raw command string, exactly as policy.py does (`re.search`).
pub const DENY_PATTERNS: &[(&str, &str)] = &[
    ("deny_no_preserve_root", r"--no-preserve-root"),
    ("deny_rm_rf_root", r"\brm\s+-[a-z]*[rf]\s+/\s*$"),
    ("deny_rm_rf_home", r"\brm\s+-[a-z]*[rf]\s+~\s*$"),
    ("deny_base64_exec", r"base64\s+.*-d.*\|\s*sh"),
    ("deny_curl_pipe", r"\bcurl\s+.*\|"),
];

/// Shell metacharacters that always deny (policy.py
/// `DANGEROUS_SHELL_TOKENS`); matched as literal substrings via an
/// aho-corasick automaton.
pub const SHELL_TOKENS: &[&str] = &["$(", "`", "eval ", "; rm ", "&& rm ", "| sudo "];

/// Shells whose exec of a repo-relative script is "execute untrusted
/// content" → ask (core injection rule from e01s03).
pub const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "fish", "ksh"];

/// Injection phrases flagged by scan_context (e01s03), (rule_id, phrase).
pub const INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("inject_ignore_instructions", "ignore previous instructions"),
    ("inject_exfil_marker", "MARKER: EXFIL"),
];

/// Reproducible hash of the whole rule set + version, so a Verdict's
/// `source_hash` re-derives from a known ruleset (the open-source audit
/// property).
pub fn rules_hash() -> String {
    let mut s = Sha256::new();
    s.update(b"rules_version\n");
    s.update(RULES_VERSION.as_bytes());
    s.update(b"\n");
    let mut feed = |tag: &str, entries: &dyn Fn(&mut Sha256)| {
        s.update(tag); // tag then entries
        entries(&mut s);
    };
    feed("WRAPPERS", &|s| {
        for w in WRAPPERS {
            s.update(w.as_bytes());
            s.update(b"\n");
        }
    });
    feed("ALWAYS_ASK", &|s| {
        for p in ALWAYS_ASK {
            s.update(p.as_bytes());
            s.update(b"\n");
        }
    });
    feed("ASK_FLAGS", &|s| {
        for (prog, flags) in ASK_FLAGS {
            s.update(prog.as_bytes());
            s.update(b"\n");
            for f in *flags {
                s.update(f.as_bytes());
                s.update(b"\n");
            }
        }
    });
    feed("DENY_PATTERNS", &|s| {
        for (id, pat) in DENY_PATTERNS {
            s.update(id.as_bytes());
            s.update(b"\n");
            s.update(pat.as_bytes());
            s.update(b"\n");
        }
    });
    feed("SHELL_TOKENS", &|s| {
        for t in SHELL_TOKENS {
            s.update(t.as_bytes());
            s.update(b"\n");
        }
    });
    feed("SHELLS", &|s| {
        for sh in SHELLS {
            s.update(sh.as_bytes());
            s.update(b"\n");
        }
    });
    feed("INJECTION_PATTERNS", &|s| {
        for (id, pat) in INJECTION_PATTERNS {
            s.update(id.as_bytes());
            s.update(b"\n");
            s.update(pat.as_bytes());
            s.update(b"\n");
        }
    });
    hex(&s.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
