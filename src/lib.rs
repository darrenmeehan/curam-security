//! curam security core — PyO3 module.
//!
//! e01s01 tracer: maturin/pyo3/abi3 skeleton + `classify()`. Every verdict is a
//! provable chain {action, rule_id, source, source_hash, evidence}.

use pyo3::prelude::*;
use sha2::{Digest, Sha256};

/// Built-in dangerous exact commands → deny. Full argv parsing + policy port
/// arrives in e01s02; this is the tracer set.
const DANGEROUS_EXACT: &[&str] = &["rm -rf /"];

/// Reproducible hash of the compiled-in rule set, so a verdict can be re-derived
/// from a known ruleset + list version (the open-source audit property).
fn rules_hash() -> String {
    let mut s = Sha256::new();
    for rule in DANGEROUS_EXACT {
        s.update(rule.as_bytes());
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
            return Verdict {
                action: "deny".into(),
                rule_id: "dangerous_exact".into(),
                source: "rules".into(),
                source_hash: rules_hash(),
                evidence: command.into(),
            };
        }
    }
    Verdict {
        action: "allow".into(),
        rule_id: "no_rule".into(),
        source: "rules".into(),
        source_hash: rules_hash(),
        evidence: command.into(),
    }
}

#[pymodule]
fn curamsec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Verdict>()?;
    m.add_function(wrap_pyfunction!(classify, m)?)?;
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
}
