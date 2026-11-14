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
    m.insert("journal".to_owned(), "deferred-s03".into());
    m.insert("engine".to_owned(), VERSION.into());
    ok_json(id, m)
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
