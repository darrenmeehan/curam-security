#!/usr/bin/env python3
"""e01s06 task 3 — cage integration tests (T5).

The boundary exists as a binary: egress denied (net off), rm /etc/passwd
denied (protect-system ro), localhost allowed, timeout -> timed_out.
Runs the full curam-cage ndjson round-trip for each scenario.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "debug" / "curam-cage"


def cage(cmd, timeout_s=10, net=False, geo=None):
    req = {
        "id": 1,
        "v": "cage/1",
        "cmd": ["bash", "-c", cmd],
        "cwd": str(REPO),
        "timeout_s": timeout_s,
        "net": net,
        "geo": geo,
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
        'python3 -c "import socket; s=socket.socket(); '
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


def check_geo_block():
    """e01s07: a country CIDR set is loaded into the cage's own netns and
    kernel-enforced (in-set dropped, control passes) — rootless."""
    import hashlib

    # Install a tiny geo list via the verified lists pipeline.
    d = Path(tempfile.mkdtemp())
    (d / "geo" / "ZZ").mkdir(parents=True)
    os.environ["CUSEC_LISTS_DIR"] = str(d)
    import curamsec

    entries = ["203.0.113.0/24"]
    canon = json.dumps(entries, separators=(",", ":"))
    doc = {
        "source_url": "https://ipdeny.com",
        "license": "CC0",
        "etag": "",
        "sha256": hashlib.sha256(canon.encode()).hexdigest(),
        "refreshed_at": "",
        "rev": 1,
        "entries": entries,
    }
    curamsec.lists_update(str(d), "geo/ZZ", json.dumps(doc, separators=(",", ":")))

    r = cage(
        "ip link set lo up; ip addr add 203.0.113.1/24 dev lo; "
        "ip addr add 203.0.114.1/24 dev lo; "
        "timeout 3 ping -c 1 -W 1 203.0.113.2 >/dev/null 2>&1 && "
        "echo REACHED-FAIL || echo dropped-OK; "
        "ping -c 1 -W 1 203.0.114.2 >/dev/null 2>&1 && echo reached-OK || "
        "echo BLOCKED-FAIL",
        geo="ZZ",
    )
    assert "dropped-OK" in r["stdout"], r
    assert "reached-OK" in r["stdout"], r
    assert any(c.startswith("nft:geo:") for c in r["cages"]), r
    print("  geo set kernel-enforced (rootless)    OK")


def main():
    assert BIN.exists(), f"build first: cargo build --bin curam-cage ({BIN})"
    check_egress_denied()
    check_rm_passwd_denied()
    check_localhost_allowed()
    check_timeout()
    check_geo_block()
    print("cage integration OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
