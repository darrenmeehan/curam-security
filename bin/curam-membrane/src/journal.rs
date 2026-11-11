//! journal.rs — SQLite WAL session journal with hash-chain tamper evidence.
//!
//! The engine is the ONLY writer (drivers never touch the DB). Every row
//! commits the previous row's hash (`prev_hash` + `hash` columns), so
//! modification or row-drop is detectable via `verify`. NO raw secret
//! values are stored: receipts carry kind/count + value fingerprints.
//!
//! Retention (flattened to CFG): telemetry rows older than
//! TELEMETRY_TTL_DAYS are purged on open; the chain is rebuilt over the
//! retained window (purge is provable-deleted-to-the-last-seal).
//! The journal file is created 0600 and tightened on every open; SQLite
//! copies that mode onto its -wal/-shm siblings. (PRAGMA file_permissions
//! is a no-op in SQLite - it does not exist.)

use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const TELEMETRY_TTL_DAYS: f64 = 90.0;
pub const GENESIS: &str = "mem/1-genesis";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL,
    ts         REAL    NOT NULL,
    etype      TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS session_meta (
    session_id TEXT PRIMARY KEY,
    harness    TEXT,
    started    REAL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(etype);
";

/// `$CUSEC_JOURNAL` or `~/.local/state/curam/journal.db`.
pub fn resolve_path() -> PathBuf {
    let env = std::env::var_os("CUSEC_JOURNAL");
    if env.is_some() {
        PathBuf::from(env.unwrap())
    } else {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(".local/state/curam/journal.db")
    }
}

pub fn now_ts() -> f64 {
    let now = std::time::SystemTime::now();
    let dur = match now.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => std::time::Duration::from_secs_f64(0.0),
    };
    dur.as_secs_f64()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn row_hash(
    prev: &str,
    session_id: &str,
    ts: f64,
    etype: &str,
    payload: &str,
) -> String {
    let mut s = Sha256::new();
    s.update(prev.as_bytes());
    s.update(b"\n");
    s.update(session_id.as_bytes());
    s.update(b"\n");
    s.update(format!("{}", ts).as_bytes());
    s.update(b"\n");
    s.update(etype.as_bytes());
    s.update(b"\n");
    s.update(payload.as_bytes());
    hex(&s.finalize())
}

#[derive(Debug)]
pub struct EventRow {
    pub seq: u64,
    pub ts: f64,
    pub etype: String,
    pub payload: Value,
}

#[derive(Debug)]
pub struct VerifyResult {
    pub ok: bool,
    pub rows: u64,
    pub corrupt_rows: u64,
    pub seal: String,
}

#[cfg(unix)]
fn restrict_0600(path: &std::path::Path) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if !path.exists() {
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_0600(_path: &std::path::Path) {}

pub struct Journal {
    pub path: PathBuf,
    conn: Connection,
}

impl Journal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{parent:?}: {e}"))?;
        }
        restrict_0600(&path);
        let conn = Connection::open(&path).map_err(|e| format!("open journal {path:?}: {e}"))?;
        let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
        let _ = conn.execute_batch("PRAGMA synchronous=NORMAL;");
        conn.execute_batch(SCHEMA).map_err(|e| format!("journal schema: {e}"))?;
        let mut j = Journal { path: path.clone(), conn };
        let cutoff = now_ts() - (TELEMETRY_TTL_DAYS * 86400.0);
        let deleted = j.purge_expired(cutoff).unwrap_or_default();
        if deleted > 0 {
            let _ = j.rebuild_chain();
        }
        Ok(j)
    }

    /// Append one event with chain linking; rowid like journal.py.
    pub fn log(
        &mut self,
        session_id: &str,
        harness: Option<&str>,
        etype: &str,
        payload: &Value,
    ) -> Result<Option<u64>, String> {
        let ts = now_ts();
        let payload_s = serde_json::to_string(payload).expect("payload serializes");
        let prev = self.last_hash().unwrap_or_default();
        let h = row_hash(
            prev.as_str(),
            session_id,
            ts,
            etype,
            payload_s.as_str(),
        );
        let row = params!(session_id, ts, etype, payload_s, prev, h);
        let res = self.conn.execute(
            "INSERT INTO events(session_id, ts, etype, payload, prev_hash, hash) \
VALUES (?,?,?,?,?,?)",
            row,
        );
        match res {
            Ok(_) => {
                if let Some(hs) = harness {
                    self.upsert_session(session_id, hs, ts).ok();
                }
                Ok(Some(self.conn.last_insert_rowid() as u64))
            }
            Err(e) => Err(format!("journal write: {e}")),
        }
    }

    fn upsert_session(&mut self, session_id: &str, harness: &str, ts: f64) -> Result<(), String> {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO session_meta(session_id, harness, started) VALUES (?,?,?)",
            params!(session_id, harness, ts),
        );
        Ok(())
    }

    fn last_hash(&mut self) -> Result<String, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash FROM events ORDER BY seq DESC LIMIT 1")
            .map_err(|e| format!("journal last_hash: {e}"))?;
        let mut rows = stmt.query(params!()).map_err(|e| format!("journal query: {e}"))?;
        let row = rows.next();
        match row {
            Ok(Some(r)) => Ok(r.get::<usize, String>(0).unwrap_or_default()),
            _ => Ok(GENESIS.into()),
        }
    }

    pub fn events(&mut self, session_id: Option<&str>) -> Result<Vec<EventRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, session_id, ts, etype, payload FROM events ORDER BY seq"
            )
            .map_err(|e| format!("journal query: {e}"))?;
        let mut rows = stmt
            .query(params!())
            .map_err(|e| format!("journal query: {e}"))?;
        let mut out = Vec::new();
        let mut done = false;
        while !done {
            let row = rows.next();
            match row {
                Ok(Some(r)) => {
                    let sid = r.get::<usize, String>(1).unwrap_or_default();
                    if let Some(want) = session_id {
                        if sid != want {
                            continue;
                        }
                    }
                    let et = r.get::<usize, String>(3).unwrap_or_default();
                    let raw = r.get::<usize, String>(4).unwrap_or_default();
                    let payload = match serde_json::from_str(raw.as_str()) {
                        Ok(v) => v,
                        Err(_) => serde_json::Value::Null,
                    };
                    out.push(EventRow {
                        seq: r.get::<usize, i64>(0).unwrap_or_default() as u64,
                        ts: r.get::<usize, f64>(2).unwrap_or_default(),
                        etype: et,
                        payload,
                    });
                }
                Ok(None) => done = true,
                Err(e) => return Err(format!("journal iterate: {e}")),
            }
        }
        Ok(out)
    }

    pub fn seal(&mut self) -> Result<String, String> {
        self.last_hash().map(|h| if h.is_empty() { GENESIS.into() } else { h })
    }

    pub fn verify(&mut self) -> Result<VerifyResult, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, session_id, ts, etype, payload, prev_hash, hash \
FROM events ORDER BY seq"
            )
            .map_err(|e| format!("journal verify: {e}"))?;
        let mut rows = stmt
            .query(params!())
            .map_err(|e| format!("journal verify: {e}"))?;
        let mut expected = GENESIS.to_string();
        let mut ok = true;
        let mut corrupt: u64 = 0;
        let mut total: u64 = 0;
        let mut seal = GENESIS.to_string();
        let mut done = false;
        while !done {
            let row = rows.next();
            match row {
                Ok(Some(r)) => {
                    total += 1;
                    let sid = r.get::<usize, String>(1).unwrap_or_default();
                    let ts = r.get::<usize, f64>(2).unwrap_or_default();
                    let et = r.get::<usize, String>(3).unwrap_or_default();
                    let pl = r.get::<usize, String>(4).unwrap_or_default();
                    let prev = r.get::<usize, String>(5).unwrap_or_default();
                    let h = r.get::<usize, String>(6).unwrap_or_default();
                    let recomputed = row_hash(
                        prev.as_str(),
                        sid.as_str(),
                        ts,
                        et.as_str(),
                        pl.as_str(),
                    );
                    let row_ok = recomputed == h && prev == expected;
                    ok = ok && row_ok;
                    if !row_ok {
                        corrupt += 1;
                    }
                    expected = h.clone();
                    seal = h;
                }
                Ok(None) => done = true,
                Err(e) => return Err(format!("journal verify read: {e}")),
            }
        }
        Ok(VerifyResult {
            ok,
            rows: total,
            corrupt_rows: corrupt,
            seal,
        })
    }

    fn purge_expired(&mut self, cutoff: f64) -> Result<usize, String> {
        let res = self.conn.execute(
            "DELETE FROM events WHERE ts < ?",
            params!(cutoff),
        );
        match res {
            Ok(n) => Ok(n),
            Err(e) => Err(format!("journal purge: {e}")),
        }
    }

    /// Re-link the chain over the retained window after a purge.
    fn rebuild_chain(&mut self) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, session_id, ts, etype, payload FROM events ORDER BY seq"
            )
            .map_err(|e| format!("journal rechain: {e}"))?;
        let mut rows = stmt
            .query(params!())
            .map_err(|e| format!("journal rechain: {e}"))?;
        let mut prev = GENESIS.to_string();
        let mut done = false;
        while !done {
            let row = rows.next();
            match row {
                Ok(Some(r)) => {
                    let seq = r.get::<usize, i64>(0).unwrap_or_default();
                    let sid = r.get::<usize, String>(1).unwrap_or_default();
                    let ts = r.get::<usize, f64>(2).unwrap_or_default();
                    let et = r.get::<usize, String>(3).unwrap_or_default();
                    let pl = r.get::<usize, String>(4).unwrap_or_default();
                    let h = row_hash(prev.as_str(), sid.as_str(), ts, et.as_str(), pl.as_str());
                    let _ = self.conn.execute(
                        "UPDATE events SET prev_hash=?, hash=? WHERE seq=?",
                        params!(prev, h, seq),
                    );
                    prev = h;
                }
                Ok(None) => done = true,
                Err(e) => return Err(format!("journal rechain read: {e}")),
            }
        }
        Ok(())
    }
}
/// Best-effort seal read for status; never fails (open purges too).
pub fn quick_seal(path: impl Into<PathBuf>) -> String {
    match Journal::open(path) {
        Ok(jj) => {
            let mut j2 = jj;
            j2.seal().unwrap_or_default()
        }
        Err(_) => "journal-unavailable".into(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_is_0600_even_if_it_existed_0644() {
        let dir = std::env::temp_dir().join(format!(
            "curam-journal-test-{}-{}",
            std::process::id(),
            now_ts()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.db");
        std::fs::write(&path, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let mut j = Journal::open(&path).unwrap();
        j.log("s", Some("test"), "event", &serde_json::json!({"ok": true}))
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "journal mode {mode:o}");
        }
        drop(j);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
