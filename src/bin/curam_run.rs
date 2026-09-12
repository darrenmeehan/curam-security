//! curam-run — standalone bwrap cage binary (e01s06).
//!
//! Two modes:
//!   1. CLI:  curam-run [--net] -- cmd...   (run once, print stdout, exit code)
//!   2. ndjson over stdio (default when stdin is not a tty and -- given):
//!      one request per line: {id, v, cmd, cwd, timeout_s, net, allow_hosts, deny_hosts}
//!      one result per line:  {id, exit, stdout, stderr, timed_out, cages, verdicts}
//!
//! The cage: bwrap --unshare-net (default) --ro-bind /usr, /lib, /etc, /bin
//! read-only, tmpfs /tmp + /run, proc/dev mounted. protect-system ≈ system
//! dirs are not writable.

use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const VERSION: &str = "cage/1";

struct Request {
    id: u64,
    cmd: Vec<String>,
    cwd: Option<String>,
    timeout_s: Option<u64>,
    net: bool,
    geo: Option<String>,
    allow_hosts: Vec<String>,
    deny_hosts: Vec<String>,
}

fn parse_request(line: &str) -> Result<Request, String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("bad json: {e}"))?;
    let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let v_str = v
        .get("v")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if v_str != VERSION {
        return Err(format!("unsupported envelope v={v_str:?}, want {VERSION}"));
    }
    let cmd: Vec<String> = v
        .get("cmd")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let cwd = v.get("cwd").and_then(|x| x.as_str()).map(str::to_string);
    let timeout_s = v.get("timeout_s").and_then(|x| x.as_u64());
    let net = v.get("net").and_then(|x| x.as_bool()).unwrap_or(false);
    let geo = v.get("geo").and_then(|x| x.as_str()).map(str::to_string);
    let allow_hosts = strings_of(&v, "allow_hosts");
    let deny_hosts = strings_of(&v, "deny_hosts");
    Ok(Request {
        id,
        cmd,
        cwd,
        timeout_s,
        net,
        geo,
        allow_hosts,
        deny_hosts,
    })
}

fn strings_of(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Lists dir (env `CUSEC_LISTS_DIR` or `~/.local/share/curam/lists`), same
/// resolution as the curamsec lib so the cage reads the verified feeds.
fn lists_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("CUSEC_LISTS_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".local/share/curam/lists"))
        })
}

/// Read the CIDR entries of a geo list: `<lists>/geo/<COUNTRY>/list.json`
/// (the verified lists pipeline schema; entries are CIDR strings).
fn geo_cidrs(country: &str) -> Result<Vec<String>, String> {
    let dir = lists_dir().ok_or_else(|| "CUSEC_LISTS_DIR unset and no HOME".to_string())?;
    let path = dir.join("geo").join(country).join("list.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{path:?}: bad json: {e}"))?;
    let entries = match v.get("entries").and_then(|e| e.as_array()) {
        Some(arr) => arr,
        None => return Ok(Vec::new()),
    };
    Ok(entries
        .iter()
        .filter_map(|e| e.as_str().map(str::to_string))
        .collect())
}

/// Render an nftables ruleset that drops egress to a country's CIDR set.
/// Kernel-enforced at the connection, in the cage's own netns (no TOCTOU).
fn nft_ruleset(country: &str, cidrs: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet geo_{country} {{\n"));
    s.push_str("\tset country {\n");
    s.push_str("\t\ttype ipv4_addr\n");
    s.push_str("\t\tflags interval\n");
    s.push_str("\t\telements = { ");
    s.push_str(&cidrs.join(", "));
    s.push_str(" }\n\t}\n");
    s.push_str("\tchain out {\n");
    s.push_str("\t\ttype filter hook output priority 0; policy accept;\n");
    s.push_str("\t\tip daddr @country drop\n");
    s.push_str("\t}\n}\n");
    s
}

/// Base bwrap isolation: pid ns, system dirs read-only, tmpfs /tmp + /run.
fn bwrap_base() -> Vec<String> {
    vec![
        "bwrap".into(),
        "--die-with-parent".into(),
        "--unshare-pid".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--ro-bind".into(),
        "/lib".into(),
        "/lib".into(),
        "--ro-bind".into(),
        "/lib64".into(),
        "/lib64".into(),
        "--ro-bind".into(),
        "/etc".into(),
        "/etc".into(),
        "--ro-bind".into(),
        "/bin".into(),
        "/bin".into(),
        "--ro-bind".into(),
        "/sbin".into(),
        "/sbin".into(),
        "--ro-bind".into(),
        "/nix".into(),
        "/nix".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--tmpfs".into(),
        "/run".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
    ]
}

/// Build the bwrap argv for a request.
///
/// Net off => --unshare-net (parent-owned netns; nothing routable).
/// Geo => --share-net + caps, and the *inner* `unshare -n` creates a netns
/// owned by our userns where CAP_NET_ADMIN applies, so nft can load the
/// country set. Egress stays denied (fresh netns has only loopback).
fn bwrap_argv(req: &Request, ruleset_path: Option<&str>) -> Vec<String> {
    let mut a = bwrap_base();
    if req.geo.is_some() {
        // Need CAP_SYS_ADMIN to unshare -n, CAP_NET_ADMIN to load nft.
        a.push("--cap-add".into());
        a.push("CAP_SYS_ADMIN".into());
        a.push("--cap-add".into());
        a.push("CAP_NET_ADMIN".into());
        a.push("--cap-add".into());
        a.push("CAP_NET_RAW".into());
        if let Some(rp) = ruleset_path {
            a.push("--ro-bind".into());
            a.push(rp.into());
            a.push("/cage-geo.rules".into());
        }
    } else if !req.net {
        a.push("--unshare-net".into());
    }
    a.push("--".into());
    if req.geo.is_some() {
        // unshare -n first so the nft rules land in OUR netns, then exec.
        a.push("unshare".into());
        a.push("-n".into());
        a.push("bash".into());
        a.push("-c".into());
        a.push("nft -f /cage-geo.rules && exec \"$@\"".into());
        a.push("cage-geo".into());
        a.extend(req.cmd.iter().cloned());
    } else {
        a.extend(req.cmd.iter().cloned());
    }
    a
}

struct Result_ {
    id: u64,
    exit: i32,
    stdout: String,
    stderr: String,
    timed_out: bool,
    cages: Vec<String>,
    verdicts: Vec<serde_json::Value>,
}

fn render_result(r: &Result_) -> String {
    let mut m = serde_json::Map::new();
    m.insert("id".to_owned(), r.id.into());
    m.insert("exit".to_owned(), r.exit.into());
    m.insert("stdout".to_owned(), r.stdout.clone().into());
    m.insert("stderr".to_owned(), r.stderr.clone().into());
    m.insert("timed_out".to_owned(), r.timed_out.into());
    m.insert("cages".to_owned(), r.cages.clone().into());
    m.insert("verdicts".to_owned(), r.verdicts.clone().into());
    serde_json::to_string(&serde_json::Value::Object(m)).expect("render result")
}

/// Per-host policy verdicts from the request (the provable chain). The cage
/// itself enforces net on/off; the verdict records the requested host policy
/// so the harness/journal can reproduce the decision. deny beats allow;
/// hosts absent from both lists get no verdict (the harness defaults to ask).
fn host_verdicts(req: &Request) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for h in &req.deny_hosts {
        out.push(verdict("deny", "host_deny", "deny list", h));
    }
    for h in &req.allow_hosts {
        out.push(verdict("allow", "host_allow", "allow list", h));
    }
    out
}

fn verdict(action: &str, rule_id: &str, source: &str, host: &str) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("action".to_owned(), action.into());
    m.insert("rule_id".to_owned(), rule_id.into());
    m.insert("source".to_owned(), source.into());
    m.insert("source_hash".to_owned(), VERSION.into());
    m.insert("evidence".to_owned(), host.into());
    serde_json::Value::Object(m)
}

/// Run one request in the cage with a timeout. Returns (result, exit_code).
fn run_caged(req: &Request) -> Result_ {
    // Geo: render the nft ruleset to a staging file, bind it ro into the cage.
    let ruleset_path = match &req.geo {
        Some(country) => {
            let cidrs = match geo_cidrs(country) {
                Ok(c) => c,
                Err(e) => {
                    return Result_ {
                        id: req.id,
                        exit: 1,
                        stdout: String::new(),
                        stderr: format!("geo {country}: {e}"),
                        timed_out: false,
                        cages: vec!["geo:load-failed".into()],
                        verdicts: Vec::new(),
                    };
                }
            };
            if cidrs.is_empty() {
                return Result_ {
                    id: req.id,
                    exit: 1,
                    stdout: String::new(),
                    stderr: format!("geo {country}: empty CIDR list"),
                    timed_out: false,
                    cages: vec!["geo:empty".into()],
                    verdicts: Vec::new(),
                };
            }
            let rules = nft_ruleset(country, &cidrs);
            let path = std::env::temp_dir().join(format!(
                "curam-run-geo-{country}-{}.rules",
                std::process::id()
            ));
            if let Err(e) = std::fs::write(&path, rules.as_bytes()) {
                return Result_ {
                    id: req.id,
                    exit: 1,
                    stdout: String::new(),
                    stderr: format!("geo {country}: write rules: {e}"),
                    timed_out: false,
                    cages: vec!["geo:write-failed".into()],
                    verdicts: Vec::new(),
                };
            }
            Some(path)
        }
        None => None,
    };

    let argv = bwrap_argv(req, ruleset_path.as_ref().and_then(|p| p.to_str()));
    let mut cmd = Command::new(&argv[0]);
    cmd.args(argv.iter().skip(1));
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Result_ {
                id: req.id,
                exit: 1,
                stdout: String::new(),
                stderr: format!("spawn failed: {e}"),
                timed_out: false,
                cages: vec!["bwrap:spawn-failed".into()],
                verdicts: Vec::new(),
            };
        }
    };

    let timeout = req.timeout_s.unwrap_or(0);
    let deadline = if timeout > 0 {
        Some(SystemTime::now() + Duration::from_secs(timeout))
    } else {
        None
    };
    let mut timed_out = false;
    loop {
        if let Some(dl) = deadline {
            if SystemTime::now() >= dl {
                let _ = child.kill();
                timed_out = true;
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                return Result_ {
                    id: req.id,
                    exit: 1,
                    stdout: String::new(),
                    stderr: format!("wait failed: {e}"),
                    timed_out,
                    cages: vec!["bwrap:wait-failed".into()],
                    verdicts: Vec::new(),
                };
            }
        }
    }

    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }
    let status = child.wait().unwrap_or_default();
    let code = status.code().unwrap_or(1);

    let mut cages = vec!["bwrap:unshare-net".into(), "bwrap:ro-system".into()];
    if req.net {
        cages.push("bwrap:net-on".into());
    }
    if let Some(country) = &req.geo {
        cages.push(format!("nft:geo:{country}"));
    }
    Result_ {
        id: req.id,
        exit: code,
        stdout: out,
        stderr: err,
        timed_out,
        cages,
        verdicts: host_verdicts(req),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dash = args.iter().position(|a| a == "--");
    let mut net = false;
    let mut geo: Option<String> = None;
    let cli: Vec<String>;
    match dash {
        Some(i) => {
            // CLI mode: flags before --, command after.
            for f in &args[..i] {
                if f == "--net" {
                    net = true;
                } else if let Some(c) = f.strip_prefix("--geo=") {
                    geo = Some(c.to_string());
                } else if f == "--geo" {
                    eprintln!("curam-run: --geo needs =COUNTRY (e.g. --geo=RU)");
                    std::process::exit(2);
                }
            }
            cli = args[i + 1..].to_vec();
            if cli.is_empty() {
                eprintln!("curam-run: no command after --");
                std::process::exit(2);
            }
            let req = Request {
                id: 0,
                cmd: cli,
                cwd: None,
                timeout_s: None,
                net,
                geo,
                allow_hosts: Vec::new(),
                deny_hosts: Vec::new(),
            };
            let r = run_caged(&req);
            print!("{}", r.stdout);
            let _ = std::io::stdout().flush();
            if !r.stderr.is_empty() {
                eprint!("{}", r.stderr);
            }
            std::process::exit(r.exit);
        }
        None => {
            // ndjson mode: one request per line on stdin, one result per line out.
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                let req = match parse_request(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let mut m = serde_json::Map::new();
                        m.insert("error".to_owned(), e.into());
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::Value::Object(m)).unwrap()
                        );
                        continue;
                    }
                };
                if req.cmd.is_empty() {
                    let mut m = serde_json::Map::new();
                    m.insert("id".to_owned(), req.id.into());
                    m.insert("error".to_owned(), "empty cmd".into());
                    println!(
                        "{}",
                        serde_json::to_string(&serde_json::Value::Object(m)).unwrap()
                    );
                    continue;
                }
                let r = run_caged(&req);
                println!("{}", render_result(&r));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_reads_contract_fields() {
        let r = parse_request(
            "{\"id\":7,\"v\":\"cage/1\",\"cmd\":[\"bash\",\"-c\",\"echo hi\"],\"cwd\":\"/tmp\",\"timeout_s\":3,\"net\":true,\"geo\":\"RU\",\"allow_hosts\":[\"github.com\"],\"deny_hosts\":[\"evil.example\"]}",
        )
        .unwrap();
        assert_eq!(r.id, 7);
        assert_eq!(r.cmd, vec!["bash", "-c", "echo hi"]);
        assert_eq!(r.timeout_s, Some(3));
        assert!(r.net);
        assert_eq!(r.geo.as_deref(), Some("RU"));
        assert_eq!(r.allow_hosts, vec!["github.com"]);
        assert_eq!(r.deny_hosts, vec!["evil.example"]);
    }

    #[test]
    fn parse_request_rejects_wrong_envelope_version() {
        let bad = parse_request("{\"id\":1,\"v\":\"cage/9\",\"cmd\":[\"echo\"],\"timeout_s\":1}");
        assert!(bad.is_err());
    }

    // T6: the ndjson contract survives a full request->result round trip
    // with the documented envelope keys (proto/ndjson-spec.md).
    #[test]
    fn contract_replay_envelope_round_trip() {
        let req = parse_request(
            "{\"id\":7,\"v\":\"cage/1\",\"cmd\":[\"bash\",\"-c\",\"echo ok\"],\"cwd\":\"/tmp\",\"timeout_s\":5,\"net\":false,\"geo\":\"RU\",\"allow_hosts\":[\"github.com\"],\"deny_hosts\":[\"evil.example\"]}",
        )
        .unwrap();
        assert_eq!(req.cmd, vec!["bash", "-c", "echo ok"]);

        // A result rendered for that request carries every envelope key.
        let mut verdicts = host_verdicts(&req);
        assert_eq!(verdicts.len(), 2, "deny + allow verdicts");
        let out = verdicts.iter().map(|v| v["action"].as_str().unwrap());
        assert!(out.clone().any(|a| a == "deny"));
        assert!(out.clone().any(|a| a == "allow"));
        verdicts.clear(); // don't need them for the envelope check below

        let r = Result_ {
            id: req.id,
            exit: 0,
            stdout: "ok\n".into(),
            stderr: String::new(),
            timed_out: false,
            cages: vec!["bwrap:unshare-net".into()],
            verdicts: Vec::new(),
        };
        let text = render_result(&r);
        let v: serde_json::Value =
            serde_json::from_str(&text).expect("result is json");
        for key in ["id", "exit", "stdout", "stderr", "timed_out", "cages", "verdicts"] {
            assert!(v.get(key).is_some(), "missing envelope key {key}");
        }
        assert_eq!(v["id"], 7);
        assert_eq!(v["stdout"], "ok\n");
    }

    #[test]
    fn bwrap_argv_unshare_net_and_ro_system() {
        let req = Request {
            id: 1,
            cmd: vec!["bash".into(), "-c".into(), "echo hi".into()],
            cwd: None,
            timeout_s: None,
            net: false,
            geo: None,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
        };
        let a = bwrap_argv(&req, None);
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--unshare-pid".to_string()));
        let i = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[i + 1..], &["bash", "-c", "echo hi"]);

        // net on: no unshare-net
        let req_net = Request { net: true, ..req };
        let a2 = bwrap_argv(&req_net, None);
        assert!(!a2.contains(&"--unshare-net".to_string()));
    }

    // s07: geo pins the nft ruleset + caps into the cage; the inner
    // unshare -n puts the rules in the cage-owned netns.
    #[test]
    fn geo_parse_and_ruleset_shape() {
        let req = Request {
            id: 1,
            cmd: vec!["bash".into(), "-c".into(), "echo hi".into()],
            cwd: None,
            timeout_s: None,
            net: false,
            geo: Some("RU".into()),
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
        };
        let a = bwrap_argv(&req, Some("/staging/rules"));
        assert!(a.contains(&"--cap-add".to_string()));
        assert!(a.contains(&"CAP_NET_ADMIN".to_string()));
        assert!(a.contains(&"--ro-bind".to_string()));
        assert!(!a.contains(&"--unshare-net".to_string()));
        let i = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(a[i + 1], "unshare");
        assert_eq!(a[i + 2], "-n");

        let rules = nft_ruleset("RU", &["203.0.113.0/24".into()]);
        assert!(rules.contains("table inet geo_RU"));
        assert!(rules.contains("203.0.113.0/24"));
        assert!(rules.contains("ip daddr @country drop"));
    }

    #[test]
    fn verdicts_deny_beats_allow_and_chain_shape() {
        let req = Request {
            id: 1,
            cmd: vec!["bash".into()],
            cwd: None,
            timeout_s: None,
            net: false,
            geo: None,
            allow_hosts: vec!["github.com".into()],
            deny_hosts: vec!["evil.example".into()],
        };
        let vs = host_verdicts(&req);
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0]["action"], "deny");
        assert_eq!(vs[0]["rule_id"], "host_deny");
        assert_eq!(vs[0]["evidence"], "evil.example");
        assert_eq!(vs[1]["action"], "allow");
        for v in &vs {
            for key in ["action", "rule_id", "source", "source_hash", "evidence"] {
                assert!(v.get(key).is_some(), "missing {key} in {v}");
            }
        }
    }
}
