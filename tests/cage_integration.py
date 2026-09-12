#!/usr/bin/env python3
"""e01s06 task 3 — cage integration tests (T5).

The boundary exists as a binary: egress denied (net off), rm /etc/passwd
denied (protect-system ro), localhost allowed, timeout -> timed_out.
Runs the full curam-run ndjson round-trip for each scenario.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "debug" / "curam-run"


def cage(cmd, timeout_s=10, net=False):
    req = {
        "id": 1,
        "v": "cage/1",
        "cmd": ["bash", "-c", cmd],
        "cwd": str(REPO),
        "timeout_s": timeout_s,
        "net": net,
        "allow_hosts": [],
        "deny_hosts": [],
    }
    p = subprocess.run(
        [str(BIN)],
        input=json.dumps(req, separators=(",", ":")) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout_s + 10,
    )
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def check_egress_denied():
    r = cage("wget -T 3 https://example.com 2>&1; echo exit=$?")
    assert r["timed_out"] is False
    assert "exit=4" in r["stdout"], f"egress must fail: {r['stdout']}"
    assert "bwrap:unshare-net" in r["cages"]
    print("  egress denied (net off)              OK")


def check_rm_passwd_denied():
    r = cage("rm /etc/passwd 2>&1; echo rc=$?")
    assert "rc=1" in r["stdout"], f"rm /etc/passwd must fail: {r['stdout']}"
    assert "Read-only" in r["stdout"] or "not permitted" in r["stderr"] + r["stdout"]
    print("  rm /etc/passwd denied (ro-system)    OK")


def check_localhost_allowed():
    r = cage(
        "python3 -c \"import socket; s=socket.socket(); "
        "s.bind(('127.0.0.1', 0)); print('bound', s.getsockname()[1])\""
    )
    # A successful bind on loopback proves the interface is reachable in the
    # cage (net off still keeps loopback up). Egress is what gets killed.
    assert "bound" in r["stdout"], r["stdout"]
    print("  localhost allowed (loopback up)      OK")


def check_timeout():
    r = cage("sleep 30", timeout_s=1)
    assert r["timed_out"] is True, r
    print("  timeout -> timed_out                  OK")


def main():
    assert BIN.exists(), f"build first: cargo build --bin curam-run ({BIN})"
    check_egress_denied()
    check_rm_passwd_denied()
    check_localhost_allowed()
    check_timeout()
    print("cage integration OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
