//! curamsec — PyO3 module: a thin shim over the pure-Rust `curam-core` crate.
//!
//! All classification/matching/list logic lives in `curam-core`
//! (crates/curam-core/src/lib.rs) so native consumers — the Rust harness —
//! link it without Python. This crate only adapts core types to the pyo3
//! Python surface; the abi3 wheel API is unchanged:
//!   classify / scan_context / match_host / reload_host_lists /
//!   lists_update / check_pkg + Verdict / Finding / HostMatcherPy / Advisory

use pyo3::prelude::*;

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

fn verdict_to_py(v: curam_core::Verdict) -> Verdict {
    Verdict::new(v.action, v.rule_id, v.source, v.source_hash, v.evidence)
}

/// Classify a command string → `Verdict` in {allow, ask, deny}.
///
/// `allow_rules` carries extra allow-listed programs (contract's
/// `classify(cmd, allow_rules=...)`), mirroring policy.py's
/// `cfg.policy.rules.allow`.
#[pyfunction]
#[pyo3(signature = (command, allow_rules = None))]
fn classify(command: &str, allow_rules: Option<Vec<String>>) -> Verdict {
    verdict_to_py(curam_core::classify(command, allow_rules))
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

/// Scan free text for embedded injection phrases (e01s03).
#[pyfunction]
#[pyo3(signature = (text, threshold = 1))]
fn scan_context(text: &str, threshold: usize) -> Vec<Finding> {
    curam_core::scan_context(text, threshold)
        .iter()
        .map(|f| Finding::new(f.rule_id.clone(), f.evidence.clone()))
        .collect()
}

/// A host matcher for `match_host`, holding allow + deny suffix sets.
#[pyclass(module = "curamsec")]
struct HostMatcherPy {
    inner: curam_core::host::HostMatcher,
}

#[pymethods]
impl HostMatcherPy {
    #[new]
    fn new(allow: Vec<String>, deny: Vec<String>) -> Self {
        let allow: Vec<&str> = allow.iter().map(|s| s.as_str()).collect();
        let deny: Vec<&str> = deny.iter().map(|s| s.as_str()).collect();
        Self {
            inner: curam_core::host::HostMatcher::new(&allow, &deny),
        }
    }

    /// `allow_mode` restricts the query to the allowlist (deny ignored).
    #[pyo3(signature = (host, allow_mode = false))]
    fn lookup(&self, host: &str, allow_mode: bool) -> Verdict {
        verdict_to_py(curam_core::host_verdict(self.inner.lookup(host, allow_mode)))
    }
}

/// Resolve a hostname against the allow/deny suffix sets (e01s04).
#[pyfunction]
#[pyo3(signature = (host, allow = false))]
fn match_host(host: &str, allow: bool) -> Verdict {
    verdict_to_py(curam_core::match_host(host, allow))
}

/// Reload host lists from disk (strict: raises instead of silently
/// weakening policy).
#[pyfunction]
fn reload_host_lists() -> PyResult<()> {
    curam_core::reload_host_lists()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("list load failed: {e}")))?;
    Ok(())
}

/// Update (pin + verify + atomically swap) a list from a fetched snapshot.
/// `fetched` is the raw text of a `list.json`; `rev` on it must be strictly
/// greater than the last-installed rev or the pin is rejected.
#[pyfunction]
#[pyo3(signature = (lists_dir, name, fetched))]
fn lists_update(lists_dir: &str, name: &str, fetched: &str) -> PyResult<String> {
    let dir = std::path::PathBuf::from(lists_dir);
    let rev = curam_core::lists::update_list(&dir, name, fetched)
        .map_err(pyo3::exceptions::PyValueError::new_err)?;
    Ok(format!("updated {name} @ rev {rev}"))
}

/// A package advisory (e01s08).
#[pyclass(module = "curamsec")]
#[derive(Clone)]
pub struct Advisory {
    #[pyo3(get)]
    id: String,
    #[pyo3(get)]
    summary: String,
    #[pyo3(get)]
    severity: String,
}

#[pymethods]
impl Advisory {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(id: String, summary: String, severity: String) -> Self {
        Self {
            id,
            summary,
            severity,
        }
    }
}

/// check_pkg — OSV advisory lookup against the offline fixture (e01s08).
/// Affected version in a known range -> list of Advisory; clean -> [].
#[pyfunction]
#[pyo3(signature = (name, version = None))]
fn check_pkg(name: &str, version: Option<&str>) -> Vec<Advisory> {
    curam_core::check_pkg(name, version)
        .iter()
        .map(|a| Advisory::new(a.id.clone(), a.summary.clone(), a.severity.clone()))
        .collect()
}

#[pymodule]
fn curamsec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Verdict>()?;
    m.add_class::<Finding>()?;
    m.add_class::<HostMatcherPy>()?;
    m.add_class::<Advisory>()?;
    m.add_function(wrap_pyfunction!(classify, m)?)?;
    m.add_function(wrap_pyfunction!(scan_context, m)?)?;
    m.add_function(wrap_pyfunction!(match_host, m)?)?;
    m.add_function(wrap_pyfunction!(reload_host_lists, m)?)?;
    m.add_function(wrap_pyfunction!(lists_update, m)?)?;
    m.add_function(wrap_pyfunction!(check_pkg, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}