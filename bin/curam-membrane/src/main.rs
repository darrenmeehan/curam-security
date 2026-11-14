//! curam-membrane — boundary engine (mem/1 ndjson over stdio).
//!
//! One request per line on stdin, one result per line on stdout:
//!   {id, v: "mem/1", op: mask|rules|status, payload?}
//! The engine owns no detection: ALL rules live in curam-core (anti-drift
//! rule). Drivers (pi, later Claude/Codex) are dumb pipes to this contract.

use std::io::{BufRead, Write};

use serde_json::Value;

use curam_core::rules;
use curam_core::scrub;

mod journal;

const VERSION: &str = "mem/1";

fn ok_json(id: u64, m: serde_json::Map<String, Value>) -> String {
    let mut m2 = m;
    m2.insert("id".to_owned(), id.into());
    m2.insert("v".to_owned(), VERSION.into());
    m2.insert("ok".to_owned(), true.into());
    serde_json::to_string(&Value::Object(m2)).unwrap()
}

fn err_json(id: u64, msg: &str) -> String {
    let mut m = serde_json::Map::new();
    m.insert("id".to_owned(), id.into());
    m.insert("v".to_owned(), VERSION.into());
    m.insert("ok".to_owned(), false.into());
    m.insert("error".to_owned(), msg.into());
    serde_json::to_string(&Value::Object(m)).unwrap()
}

fn manifest_value(hits: &Vec<scrub::SpanHit>) -> Value {
    let mut arr = Vec::new();
    for h in hits {
        let mut m = serde_json::Map::new();
        m.insert("kind".to_owned(), h.kind.clone().into());
        m.insert("count".to_owned(), (h.count as u64).into());
        arr.push(Value::Object(m));
    }
    Value::Array(arr)
}

fn hits_value(hits: &Vec<scrub::ScrubHit>) -> Value {
    let mut arr = Vec::new();
    for h in hits {
        let mut m = serde_json::Map::new();
        m.insert("kind".to_owned(), h.kind.clone().into());
        m.insert("fingerprint".to_owned(), h.fingerprint.clone().into());
        arr.push(Value::Object(m));
    }
    Value::Array(arr)
}

fn op_mask(id: u64, payload: &Value) -> String {
    let text = payload
        .get("text")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    let mut s = scrub::Sanitizer::from_cfg(&scrub::default_cfg());
    let r = s.scrub_with_manifest(text.as_str());
    let mut m = serde_json::Map::new();
    m.insert("scrubbed".to_owned(), r.text.into());
    m.insert("manifest".to_owned(), manifest_value(&r.manifest));
    m.insert("hits".to_owned(), hits_value(&r.hits));
    m.insert("rules_version".to_owned(), rules::RULES_VERSION.into());
    m.insert("rules_hash".to_owned(), rules::rules_hash().into());
    m.insert("scrub_hash".to_owned(), scrub::scrub_hash().into());
    ok_json(id, m)
}

fn op_rules(id: u64) -> String {
    let mut m = serde_json::Map::new();
    m.insert("rules_version".to_owned(), rules::RULES_VERSION.into());
    m.insert("rules_hash".to_owned(), rules::rules_hash().into());
    m.insert("classes".to_owned(), classes_value());
    ok_json(id, m)
}

fn classes_value() -> Value {
    let mut arr = Vec::new();
    for k in scrub::pattern_kinds() {
        arr.push(k.into());
    }
    Value::Array(arr)
}

fn op_status(id: u64) -> String {
    let mut m = serde_json::Map::new();
    m.insert("rules_version".to_owned(), rules::RULES_VERSION.into());
    m.insert("rules_hash".to_owned(), rules::rules_hash().into());
    m.insert("classes".to_owned(), classes_value());
    m.insert(
        "journal".to_owned(),
        journal::resolve_path().to_str().unwrap_or_default().to_string().into(),
    );
    m.insert(
        "seal".to_owned(),
        journal::quick_seal(journal::resolve_path()).into(),
    );
    m.insert("engine".to_owned(), VERSION.into());
    ok_json(id, m)
}

fn op_log(id: u64, payload: &Value) -> String {
    let sid = payload
        .get("session_id")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    let harness = payload.get("harness").and_then(|x| x.as_str()).map(str::to_string);
    let etype = payload
        .get("etype")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or("event".to_string());
    let ev = payload.get("payload").unwrap_or_default();
    let has_harness = harness.is_some();
    let harness_s: String = harness.unwrap_or_default();
    let harness_ref = if has_harness {
        Some(harness_s.as_str())
    } else {
        None
    };
    let mut j = match journal::Journal::open(journal::resolve_path()) {
        Ok(x) => x,
        Err(e) => return err_json(id, format!("journal open: {e}").as_str()),
    };
    match j.log(sid.as_str(), harness_ref, etype.as_str(), ev) {
        Ok(seq) => {
            let mut m = serde_json::Map::new();
            m.insert("seq".to_owned(), seq.unwrap_or_default().into());
            m.insert("seal".to_owned(), j.seal().unwrap_or_default().into());
            ok_json(id, m)
        }
        Err(e) => err_json(id, format!("journal log: {e}").as_str()),
    }
}

fn op_audit(id: u64, payload: &Value) -> String {
    let sid = payload.get("session_id").and_then(|x| x.as_str());
    let mut j = match journal::Journal::open(journal::resolve_path()) {
        Ok(x) => x,
        Err(e) => return err_json(id, format!("journal open: {e}").as_str()),
    };
    match j.events(sid) {
        Ok(evs) => {
            let mut arr = Vec::new();
            for e in evs {
                let mut m = serde_json::Map::new();
                m.insert("seq".to_owned(), e.seq.into());
                m.insert("ts".to_owned(), e.ts.into());
                m.insert("etype".to_owned(), e.etype.clone().into());
                m.insert("payload".to_owned(), e.payload.clone());
                arr.push(Value::Object(m));
            }
            let mut m = serde_json::Map::new();
            m.insert("rows".to_owned(), Value::Array(arr));
            m.insert("seal".to_owned(), j.seal().unwrap_or_default().into());
            ok_json(id, m)
        }
        Err(e) => err_json(id, format!("journal audit: {e}").as_str()),
    }
}

fn op_verify(id: u64) -> String {
    let mut j = match journal::Journal::open(journal::resolve_path()) {
        Ok(x) => x,
        Err(e) => return err_json(id, format!("journal open: {e}").as_str()),
    };
    match j.verify() {
        Ok(v) => {
            let mut m = serde_json::Map::new();
            m.insert("chain_ok".to_owned(), v.ok.into());
            m.insert("rows".to_owned(), v.rows.into());
            m.insert("corrupt_rows".to_owned(), v.corrupt_rows.into());
            m.insert("seal".to_owned(), v.seal.into());
            ok_json(id, m)
        }
        Err(e) => err_json(id, format!("journal verify: {e}").as_str()),
    }
}

fn handle(line: &str) -> String {
    let v: Value = match serde_json::from_str(line) {
        Ok(x) => x,
        Err(_) => return err_json(0, "bad json"),
    };
    let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let env = v
        .get("v")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    if env != VERSION {
        return err_json(
            id,
            format!("unsupported envelope v={env:?}, want {VERSION}").as_str(),
        );
    }
    let op = v
        .get("op")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    let payload = v.get("payload").unwrap_or_default();
    match op.as_str() {
        "mask" => op_mask(id, payload),
        "rules" => op_rules(id),
        "status" => op_status(id),
        "log" => op_log(id, payload),
        "audit" => op_audit(id, payload),
        "verify" => op_verify(id),
        _ => err_json(id, format!("unknown op {op:?}").as_str()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.contains(&"--version".to_string()) {
        println!("curam-membrane {VERSION}");
        std::process::exit(0);
    }
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        println!("{}", handle(&line));
        let _ = std::io::stdout().flush();
    }
}
