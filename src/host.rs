//! match_host: label-suffix hostname matcher with allow-over-deny (e01s04).
//!
//! uBO-shaped structure: a trie over reversed DNS labels so a registered
//! suffix entry (`evil.example`) matches itself, its subdomains
//! (`sub.evil.example`), but not a sibling TLD (`example.co`). Allow always
//! beats deny; unknown => ask.

use std::collections::HashMap;
use std::path::Path;

/// Verdict for a single hostname lookup, mirroring the core's action tri-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    Allow,
    Deny,
    Unknown,
}

/// A trie keyed by reversed labels. `terminal` marks an inserted suffix.
#[derive(Default)]
struct Trie {
    children: HashMap<String, Trie>,
    terminal: bool,
}

impl Trie {
    fn insert(&mut self, host: &str) {
        let mut node = self;
        for label in reverse_labels(host) {
            node = node.children.entry(label).or_default();
        }
        node.terminal = true;
    }

    /// True when any inserted entry is a suffix of `host` at a label boundary.
    fn matches(&self, host: &str) -> bool {
        let mut node = self;
        if node.terminal {
            return true; // empty entry == match-all
        }
        for label in reverse_labels(host) {
            match node.children.get(&label) {
                Some(child) => node = child,
                None => return node.terminal,
            }
            if node.terminal {
                return true;
            }
        }
        node.terminal
    }
}

/// Split `.`-delimited labels, bottom-up (TLD first). Lowercases, strips a
/// trailing dot, drops empty labels and ports.
fn reverse_labels(host: &str) -> Vec<String> {
    let cleaned = host
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    cleaned
        .split('.')
        .filter(|l| !l.is_empty())
        .rev()
        .map(str::to_string)
        .collect::<Vec<_>>()
}

/// A matcher over allow + deny suffix sets.
#[derive(Default)]
pub struct HostMatcher {
    allow: Trie,
    deny: Trie,
}

impl HostMatcher {
    pub fn new(allow: &[&str], deny: &[&str]) -> Self {
        let mut m = Self::default();
        for a in allow {
            m.allow.insert(a);
        }
        for d in deny {
            m.deny.insert(d);
        }
        m
    }

    /// True if at least one allow or deny entry is loaded.
    pub fn nonempty(&self) -> bool {
        !self.allow.children.is_empty() || !self.deny.children.is_empty()
    }

    /// Resolve a host. `allow_mode` restricts the query to the allowlist only
    /// (used to test "is this host allowed?") — deny is then ignored.
    pub fn lookup(&self, host: &str, allow_mode: bool) -> Match {
        if self.allow.matches(host) {
            return Match::Allow;
        }
        if !allow_mode && self.deny.matches(host) {
            return Match::Deny;
        }
        Match::Unknown
    }
}

/// Load allow + deny suffix sets from a lists-on-disk directory (s05 schema).
///
/// Layout (per the plan):
///   <dir>/allow/list.json   {"rev": ..., "entries": ["files.pythonhosted.org", ...]}
///   <dir>/deny/list.json    {"rev": ..., "entries": ["evil.example", ...]}
/// Missing files yield empty sets; a present-but-malformed file is an error so
/// a corrupted list never silently becomes "allow everything".
pub fn matcher_from_lists_dir(dir: &Path) -> Result<HostMatcher, String> {
    let allow = read_entries(&dir.join("allow").join("list.json"))?;
    let deny = read_entries(&dir.join("deny").join("list.json"))?;
    let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
    let deny: Vec<&str> = deny.iter().map(String::as_str).collect();
    Ok(HostMatcher::new(&allow, &deny))
}

fn read_entries(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{path:?}: bad json: {e}"))?;
    let entries = v
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| format!("{path:?}: missing entries array"))?;
    Ok(entries
        .iter()
        .filter_map(|e| e.as_str().map(str::to_string))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn matcher() -> HostMatcher {
        HostMatcher::new(
            &["files.pythonhosted.org", "pypi.org", "python.org"],
            &["evil.example", "malware.test"],
        )
    }

    #[test]
    fn exact_and_subdomain_suffix() {
        let m = matcher();
        assert_eq!(m.lookup("evil.example", false), Match::Deny);
        assert_eq!(m.lookup("sub.evil.example", false), Match::Deny);
    }

    #[test]
    fn allow_beats_deny() {
        let m = matcher();
        assert_eq!(m.lookup("files.pythonhosted.org", false), Match::Allow);
        // allowlisted under the same TLD a denylist entry could target
        assert_eq!(m.lookup("sub.files.pythonhosted.org", false), Match::Allow);
    }

    #[test]
    fn psl_sibling_tld_not_blocked() {
        // listing "evil.example" must not block "example.co.uk" (different
        // registrable suffix) — here, the deny list has "malware.test"/"evil.example"
        let m = matcher();
        assert_eq!(m.lookup("clearnet.example.co", false), Match::Unknown);
        assert_eq!(m.lookup("unknown-rand.example", false), Match::Unknown);
    }

    #[test]
    fn allow_mode_ignores_deny() {
        let m = matcher();
        // in allow-mode, an unallowlisted host is Unknown even if deny-listed
        assert_eq!(m.lookup("evil.example", true), Match::Unknown);
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let m = matcher();
        assert_eq!(m.lookup("FILES.pythonhosted.org.", false), Match::Allow);
        assert_eq!(m.lookup("fIlEs.PyThOnHoStEd.OrG.", false), Match::Allow);
    }

    #[test]
    fn load_lists_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "curamsec-lists-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("allow")).unwrap();
        std::fs::create_dir_all(dir.join("deny")).unwrap();

        let mut a = std::fs::File::create(dir.join("allow").join("list.json")).unwrap();
        a.write_all(br#"{"rev": 7, "entries": ["files.pythonhosted.org", "pypi.org"]}"#)
            .unwrap();
        let mut d = std::fs::File::create(dir.join("deny").join("list.json")).unwrap();
        d.write_all(br#"{"rev": 2, "entries": ["evil.example"]}"#).unwrap();

        let m = matcher_from_lists_dir(&dir).unwrap();
        assert_eq!(m.lookup("files.pythonhosted.org", false), Match::Allow);
        assert_eq!(m.lookup("evil.example", false), Match::Deny);
        assert_eq!(m.lookup("random.example.com", false), Match::Unknown);

        std::fs::remove_dir_all(&dir).ok();
    }
}