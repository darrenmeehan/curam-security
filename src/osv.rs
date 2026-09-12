//! check_pkg — OSV advisory lookup against a local, offline fixture (e01s08).
//!
//! The core does zero network I/O, so the advisory corpus is embedded and
//! versioned in-repo (like rules.rs). A full OSV/RustSec sync job (later,
//! outside the core) replaces the fixture; the lookup contract stays the
//! same: `check_pkg(name, version) -> [Advisory]` where a package is
//! "affected" when it matches any OSV `affected` entry: either unconditionally
//! (no ranges) or via a version range whose `introduced` <= v < `fixed`.

use serde_json::Value;

/// One OSV record (subset of the OSV schema we consume).
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: String,
}

/// Embedded OSV fixture (offline, versioned). Format:
///   [{"id", "summary", "severity", "affected": [{"package": {"name"},
///     "ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]}]}]
const FIXTURE_JSON: &str = include_str!("osv_fixture.json");

#[cfg(test)]
fn fixture() -> Result<Vec<Value>, String> {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE_JSON).map_err(|e| format!("{e}"))?;
    doc.as_array()
        .cloned()
        .ok_or_else(|| "fixture must be a list".into())
}

/// Look up advisories for `name` at `version`. `version: None` matches any
/// advisory affecting the package (all ranges).
pub fn check_pkg(name: &str, version: Option<&str>) -> Vec<Advisory> {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap_or_default();
    let records = match doc.as_array() {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for rec in records {
        if affects(rec, name, version) {
            out.push(Advisory {
                id: str_field(rec, "id"),
                summary: str_field(rec, "summary"),
                severity: str_field(rec, "severity"),
            });
        }
    }
    out
}

fn affects(rec: &Value, name: &str, version: Option<&str>) -> bool {
    let affected = match rec.get("affected").and_then(|a| a.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for a in affected {
        let pkg_name: Option<&str> = match a.get("package").and_then(|p| p.as_object()) {
            Some(p) => p.get("name").and_then(|n| n.as_str()),
            None => None,
        };
        if pkg_name != Some(name) {
            continue;
        }
        // No ranges — package is unconditionally affected (version check moot).
        let ranges = a.get("ranges").and_then(|r| r.as_array());
        if ranges.is_none() {
            return true;
        }
        // Any matching range makes the package affected.
        for r in ranges.unwrap() {
            if version.is_some() && !in_range(r, version.unwrap()) {
                continue;
            }
            return true;
        }
    }
    false
}

/// True when `version` is inside an OSV range (introduced <= v < fixed).
fn in_range(range: &Value, version: &str) -> bool {
    let events = match range.get("events").and_then(|e| e.as_array()) {
        Some(arr) => arr,
        None => return true,
    };
    if events.is_empty() {
        return true; // range with no events = affected
    }
    // Events: [{"introduced": A}, {"fixed": B}, ...]. We only model the
    // first introduced/fixed pair (the OSV minimum); break on more.
    let mut introduced: Option<&str> = None;
    let mut fixed: Option<&str> = None;
    for e in events {
        if let Some(v) = e.get("introduced").and_then(|x| x.as_str()) {
            introduced = Some(v);
        }
        if let Some(v) = e.get("fixed").and_then(|x| x.as_str()) {
            fixed = Some(v);
            break;
        }
    }
    if fixed == Some("0") {
        fixed = Some("0.0.0"); // "0" = nobody is fixed
    }
    let v = semver_cmp(version);
    let lo = introduced.map(semver_cmp).unwrap_or(0);
    let hi = fixed.map(semver_cmp).unwrap_or(i64::MAX);
    lo <= v && v < hi
}

fn str_field(obj: &Value, key: &str) -> String {
    match obj.get(key).and_then(|f| f.as_str()) {
        Some(s) => s.to_string(),
        None => String::new(),
    }
}

/// Crude numeric version compare for "x.y.z" (and "x.y"/"x"). Good enough
/// for the offline fixture; a real resolver can push this deeper.
fn semver_cmp(v: &str) -> i64 {
    let clean = v.split('+').next().unwrap_or_default();
    let mut parts = clean.split('.').take(3).collect::<Vec<_>>();
    while parts.len() < 3 {
        parts.push("0");
    }
    let (a, b, c) = (
        parts[0].parse::<i64>().unwrap_or_default(),
        parts[1].parse::<i64>().unwrap_or_default(),
        parts[2].parse::<i64>().unwrap_or_default(),
    );
    (a << 40) | (b << 20) | c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pkg_flags_vuln_and_clean() {
        // vuln-pkg 1.0.0 falls in [0.9, 1.0.1) -> advisory
        let hits = check_pkg("vuln-pkg", Some("1.0.0"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "RUSTSEC-VULN-1");
        // 1.0.1 is fixed -> clean
        assert_eq!(check_pkg("vuln-pkg", Some("1.0.1")).len(), 0);
        // never-heard-of package -> clean
        assert_eq!(check_pkg("clean-pkg", Some("1.0.0")).len(), 0);
        assert_eq!(check_pkg("definitely-not-a-pkg", Some("0.0.1")).len(), 0);
    }

    #[test]
    fn check_pkg_no_version_returns_any_advisory() {
        let hits = check_pkg("vuln-pkg", None);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].summary.contains("format string"));
        assert_eq!(hits[0].severity, "high");
    }

    #[test]
    fn semver_compare_orders_versions() {
        assert!(semver_cmp("1.0.0") < semver_cmp("1.0.1"));
        assert!(semver_cmp("0.9.9") < semver_cmp("1.0.0"));
        assert!(semver_cmp("2.0.0") > semver_cmp("1.9.9"));
        assert_eq!(semver_cmp("1.0"), semver_cmp("1.0.0"));
    }
}
