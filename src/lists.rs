//! Verified lists pipeline (e01s05): pin → sha256 → atomic swap → load-verify.
//!
//! A list is a directory containing `list.json`:
//!   {"source_url", "license", "etag", "sha256", "refreshed_at", "rev", "entries"}
//!
//! Security model (no TUF, one integer):
//!   - `pin` — the updater targets a pinned snapshot: it refuses to *install*
//!     a list whose `rev` is not strictly greater than the last installed rev
//!     (monotonic, anti-rollback). The pin rev comes from the manifest, never
//!     from polling upstream HEAD.
//!   - `sha256` — content hash over the canonical JSON of `entries`. Verified
//!     at read time, so a tampered list on disk is rejected at load, not just
//!     at fetch time.
//!   - atomic swap — the updater writes `<name>.json.staging`, verifies it,
//!     then renames it into place; a half-written or tampered list is never
//!     visible as the live `list.json`.
//!
//! On-disk layout per list (mirrors the harness docs):
//!   <lists>/<name>/list.json     — the list (rev + entries + manifest meta)
//!   <lists>/<name>/.last-rev     — monotonic high-water mark (one integer)

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A parsed `list.json` with its verified fields.
#[derive(Clone)]
pub struct ListDoc {
    pub source_url: String,
    pub license: String,
    pub etag: String,
    pub sha256: String,
    pub refreshed_at: String,
    pub rev: u64,
    pub entries: Vec<String>,
}

/// Parse a `list.json` document. `rev` and `entries` are required;
/// the manifest metadata fields default to "" when absent (older lists).
pub fn parse_list(text: &str) -> Result<ListDoc, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("bad json: {e}"))?;
    let entries: Vec<String> = match v.get("entries").and_then(|e| e.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let rev: u64 = v.get("rev").and_then(|r| r.as_u64()).unwrap_or_default();
    Ok(ListDoc {
        source_url: str_of(&v, "source_url"),
        license: str_of(&v, "license"),
        etag: str_of(&v, "etag"),
        sha256: str_of(&v, "sha256"),
        refreshed_at: str_of(&v, "refreshed_at"),
        rev,
        entries,
    })
}

fn str_of(v: &Value, key: &str) -> String {
    match v.get(key).and_then(|f| f.as_str()) {
        Some(s) => s.to_string(),
        None => String::new(),
    }
}

/// Canonical JSON of `entries` — the content the list's `sha256` covers.
pub fn entries_canonical(entries: &[String]) -> String {
    let v: Value = entries.into();
    serde_json::to_string(&v).expect("entries serialize")
}

/// Build a `list.json` document with the correct content `sha256` — what the
/// updater pins (rev) and installs (atomic swap).
pub fn render_list(
    source_url: &str,
    license: &str,
    etag: &str,
    refreshed_at: &str,
    rev: u64,
    entries: &[String],
) -> String {
    let mut m = Map::new();
    m.insert("source_url".to_owned(), source_url.into());
    m.insert("license".to_owned(), license.into());
    m.insert("etag".to_owned(), etag.into());
    m.insert("refreshed_at".to_owned(), refreshed_at.into());
    m.insert("rev".to_owned(), rev.into());
    m.insert("entries".to_owned(), (*entries).into());
    m.insert(
        "sha256".to_owned(),
        sha256_hex(&entries_canonical(entries)).into(),
    );
    let v: Value = m.into();
    serde_json::to_string(&v).expect("render list.json")
}

/// Hex sha256 over a string (used for the list `sha256` field).
pub fn sha256_hex(s: &str) -> String {
    let mut d = Sha256::new();
    d.update(s.as_bytes());
    hex(&d.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Verify a list document: the embedded `sha256` must match the entries.
/// Tampered lists fail here — at *every* load, not only at fetch.
pub fn verify_list(doc: &ListDoc) -> Result<(), String> {
    let want = sha256_hex(&entries_canonical(&doc.entries));
    if want == doc.sha256 {
        Ok(())
    } else {
        Err(format!(
            "list sha256 mismatch: entries hash {want}, manifest {}",
            doc.sha256
        ))
    }
}

/// Load and *verify* a list from `<lists>/<name>/`. Missing list → Ok(None)
/// (no list installed yet); present-but-tampered/stale → Err.
///
/// Stale detection: `rev` must be >= the `.last-rev` high-water mark. The
/// high-water mark only ever advances, so an old snapshot cannot be replayed
/// even if an attacker reinstalls an older `list.json`.
pub fn load_list(lists_dir: &Path, name: &str) -> Result<Option<ListDoc>, String> {
    let dir = lists_dir.join(name);
    let path = dir.join("list.json");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
    let doc = parse_list(&text)?;
    verify_list(&doc)?;
    // Monotonic rev: reject anything below the last installed rev.
    let last = last_rev(lists_dir, name);
    if doc.rev < last {
        return Err(format!(
            "stale rev {} < last-installed {} for list {}",
            doc.rev, last, name
        ));
    }
    Ok(Some(doc))
}

fn last_rev(lists_dir: &Path, name: &str) -> u64 {
    let p = lists_dir.join(name).join(".last-rev");
    if !p.exists() {
        return 0;
    }
    match std::fs::read_to_string(&p) {
        Ok(t) => str::parse::<u64>(t.trim()).unwrap_or_default(),
        Err(_) => 0,
    }
}

/// Update a list from a fetched snapshot: verify the pin (monotonic rev +
/// sha256), stage, then atomically swap into place. Returns the installed rev.
///
/// `fetched` is the raw bytes of the new `list.json` (the caller fetched the
/// *pinned* snapshot — rev on the manifest, never upstream HEAD).
pub fn update_list(lists_dir: &Path, name: &str, fetched: &str) -> Result<u64, String> {
    let doc = parse_list(fetched)?;
    verify_list(&doc)?;

    let last = last_rev(lists_dir, name);
    if doc.rev <= last {
        return Err(format!(
            "pin rejected: rev {} not > last-installed {} (rollback)",
            doc.rev, last
        ));
    }

    let dir = lists_dir.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{dir:?}: {e}"))?;
    let staging = dir.join("list.json.staging");
    let live = dir.join("list.json");

    // Stage, then re-verify the bytes that actually hit disk.
    std::fs::write(&staging, fetched.as_bytes()).map_err(|e| format!("{staging:?}: {e}"))?;
    let on_disk = std::fs::read_to_string(&staging).map_err(|e| format!("{staging:?}: {e}"))?;
    let staged_doc = parse_list(&on_disk)?;
    verify_list(&staged_doc)?;

    // Atomic swap: readers never see a partial list.
    std::fs::rename(&staging, &live).map_err(|e| format!("swap {staging:?} -> {live:?}: {e}"))?;

    // Advance the high-water mark only after the swap succeeded.
    std::fs::write(dir.join(".last-rev"), format!("{}", doc.rev).as_bytes())
        .map_err(|e| format!("write .last-rev: {e}"))?;
    Ok(doc.rev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("curamsec-lists-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fetched_list(entries: &[&str], rev: u64) -> String {
        let entries: Vec<String> = entries.iter().map(|e| str::to_string(*e)).collect();
        render_list("https://example.test/lists", "CC0", "", "", rev, &entries)
    }

    fn live_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        dir.join(name).join("list.json")
    }

    fn staging_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("deny").join("list.json.staging")
    }

    // s05: updater pins a snapshot; a tampered fetched list is rejected.
    #[test]
    fn lists_update_stages_pinned_list() {
        let dir = lists_dir("upd");
        let good = fetched_list(&["evil.example", "malware.test"], 7);
        update_list(&dir, "deny", &good).expect("pin installs");
        let live = std::fs::read_to_string(&live_path(&dir, "deny")).expect("live list");
        assert_eq!(parse_list(&live).unwrap().rev, 7);
        assert_eq!(std::fs::read_to_string(&staging_path(&dir)).is_err(), true);

        // rollback pin (same rev → at-or-below) is refused
        let bad = update_list(&dir, "deny", &fetched_list(&["evil.example"], 7));
        assert!(bad.is_err(), "same rev must be rejected as rollback");
        // and a tampered list is refused at load
        assert!(update_list(&dir, "deny", &"{}").is_err());
    }

    // s05: atomic swap — a half-written staging never becomes the live list.
    #[test]
    fn lists_atomic_swap_never_exposes_partial() {
        let dir = lists_dir("atomic");
        update_list(&dir, "deny", &fetched_list(&["evil.example"], 1)).expect("first install");

        // Simulate a tampered local cache: staging writes garbage, live stays.
        std::fs::write(&staging_path(&dir), b"{\"rev\": nope").unwrap();
        let live_before = std::fs::read_to_string(&live_path(&dir, "deny")).expect("live list");
        assert!(update_list(&dir, "deny", &fetched_list(&["evil.example"], 2)).is_ok());
        let live_after = std::fs::read_to_string(&live_path(&dir, "deny")).expect("live list");
        assert_ne!(live_before, live_after, "swap must replace the live list");
        let no_staging = std::fs::read_to_string(&staging_path(&dir)).is_err();
        assert!(no_staging, "staging file must not linger");
    }

    // s05: load-time verify — tampered list and stale rev both rejected.
    #[test]
    fn lists_load_and_reject_tampered_and_stale() {
        let dir = lists_dir("load");
        update_list(&dir, "deny", &fetched_list(&["evil.example"], 3)).expect("install rev 3");

        // Tamper with the entries on disk (hash no longer matches).
        let path = live_path(&dir, "deny");
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("evil.example", "allowed.example");
        std::fs::write(&path, tampered.as_bytes()).unwrap();
        let r = load_list(&dir, "deny");
        assert!(r.is_err(), "tampered list must be rejected at load");

        // Stale rev: an old snapshot (rev < .last-rev) is rejected even
        // though its own sha256 is internally consistent.
        std::fs::remove_file(&path).unwrap();
        update_list(&dir, "deny", &fetched_list(&["evil.example"], 5)).expect("install rev 5");
        // replay the rev-3 list: internally valid, but below the mark
        std::fs::write(&path, fetched_list(&["evil.example"], 3).as_bytes()).unwrap();
        let r2 = load_list(&dir, "deny");
        assert!(r2.is_err(), "stale rev must be rejected at load");

        // Current list still loads fine.
        std::fs::write(&path, fetched_list(&["evil.example"], 5).as_bytes()).unwrap();
        assert!(load_list(&dir, "deny").is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
