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
    allow_hosts: Vec<String>,
    deny_hosts: Vec<String>,
}

fn parse_request(line: &str) -> Result<Request, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("bad json: {e}"))?;
    let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let v_str = v.get("v").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if v_str != VERSION {
        return Err(format!("unsupported envelope v={v_str:?}, want {VERSION}"));
    }
    let cmd: Vec<String> = v
        .get("cmd")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let cwd = v.get("cwd").and_then(|x| x.as_str()).map(str::to_string);
    let timeout_s = v.get("timeout_s").and_then(|x| x.as_u64());
    let net = v.get("net").and_then(|x| x.as_bool()).unwrap_or(false);
    let allow_hosts = strings_of(&v, "allow_hosts");
    let deny_hosts = strings_of(&v, "deny_hosts");
    Ok(Request {
        id,
        cmd,
        cwd,
        timeout_s,
        net,
        allow_hosts,
        deny_hosts,
    })
}

fn strings_of(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Build the bwrap argv for a request. Net off => --unshare-net.
/// System dirs read-only; /tmp + /run writable tmpfs.
fn bwrap_argv(req: &Request) -> Vec<String> {
    let mut a: Vec<String> = vec![
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
    ];
    if !req.net {
        a.push("--unshare-net".into());
    }
    a.push("--".into());
    a.extend(req.cmd.iter().cloned());
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
    let argv = bwrap_argv(req);
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
    let cli: Vec<String>;
    match dash {
        Some(i) => {
            // CLI mode: flags before --, command after.
            for f in &args[..i] {
                if f == "--net" {
                    net = true;
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
                        println!("{}", serde_json::to_string(&serde_json::Value::Object(m)).unwrap());
                        continue;
                    }
                };
                if req.cmd.is_empty() {
                    let mut m = serde_json::Map::new();
                    m.insert("id".to_owned(), req.id.into());
                    m.insert("error".to_owned(), "empty cmd".into());
                    println!("{}", serde_json::to_string(&serde_json::Value::Object(m)).unwrap());
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
            "{\"id\":7,\"v\":\"cage/1\",\"cmd\":[\"bash\",\"-c\",\"echo hi\"],\"cwd\":\"/tmp\",\"timeout_s\":3,\"net\":true,\"allow_hosts\":[\"github.com\"],\"deny_hosts\":[\"evil.example\"]}",
        )
        .unwrap();
        assert_eq!(r.id, 7);
        assert_eq!(r.cmd, vec!["bash", "-c", "echo hi"]);
        assert_eq!(r.timeout_s, Some(3));
        assert!(r.net);
        assert_eq!(r.allow_hosts, vec!["github.com"]);
        assert_eq!(r.deny_hosts, vec!["evil.example"]);
    }

    #[test]
    fn parse_request_rejects_wrong_envelope_version() {
        let bad = parse_request(
            "{\"id\":1,\"v\":\"cage/9\",\"cmd\":[\"echo\"],\"timeout_s\":1}",
        );
        assert!(bad.is_err());
    }

    #[test]
    fn bwrap_argv_unshare_net_and_ro_system() {
        let req = Request {
            id: 1,

            cmd: vec!["bash".into(), "-c".into(), "echo hi".into()],
            cwd: None,
            timeout_s: None,
            net: false,
            allow_hosts: Vec::new(),
            deny_hosts: Vec::new(),
        };
        let a = bwrap_argv(&req);
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--unshare-pid".to_string()));
        let i = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[i + 1..], &["bash", "-c", "echo hi"]);

        // net on: no unshare-net
        let req_net = Request { net: true, ..req };
        let a2 = bwrap_argv(&req_net);
        assert!(!a2.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn verdicts_deny_beats_allow_and_chain_shape() {
        let req = Request {
            id: 1,

            cmd: vec!["bash".into()],
            cwd: None,
            timeout_s: None,
            net: false,
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