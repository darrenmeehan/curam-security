#!/usr/bin/env python3
"""Thorough post-wiring test for the harness shell tool (now the cage).

Runs the exact path agent.py uses (tools.run(workdir, name, args)) and
proves the security boundary actually holds:

  1. normal shell flows still work (echo, exit codes, stderr)
  2. workdir is writable from inside the cage, files persist host-side
  3. HOME is writable (git/pip/cargo caches) and survives
  4. system dirs are read-only — rm /etc/passwd, touch /usr FAIL
  5. egress: net is ON (harness default) so reachable hosts work
  6. timeout still kills (via the harness timeout param)
  7. fail-closed: missing curam-run => shell refuses, no silent unsandboxed run
  8. read/write/edit tools are unaffected (host-side)

Usage:  cd ~/code/curam/curam-harness && python3 ~/code/curam-security/harness-wiring/check_wiring.py
"""

import os
import tempfile
import time
from pathlib import Path

from tools import run  # the harness's own dispatch — same as agent.py


def check(name: bool, detail: str = "") -> None:
    mark = "PASS" if name else "FAIL"
    print(f"  [{mark}] {name}{f' — {detail}' if detail else ''}")
    if not name:
        raise SystemExit(f"ABORTED on failed check: {name} {detail}")


def cage_shell(wd: Path, command: str, timeout: int = 30) -> dict:
    """Drive the shell tool the way the agent does."""
    return run(wd, "shell", {"command": command, "timeout": timeout})


def main() -> None:
    print("curam harness-wiring check\n==============================")

    with tempfile.TemporaryDirectory(prefix="cage-check-") as td:
        wd = Path(td)

        # -- 8. read/write/edit host-side tools unchanged -------------------
        print("-- read/write/edit tools (host-side, must be untouched) --")
        w = run(wd, "write", {"path": "a/b.txt", "content": "hello"})
        check(w["ok"] and (wd / "a/b.txt").read_text() == "hello")
        e = run(wd, "edit", {"path": "a/b.txt", "old_text": "hello", "new_text": "bye"})
        check(e["ok"], "edit replaced text")
        r = run(wd, "read", {"path": "a/b.txt"})
        check(r["content"] == "bye", "read sees edited file")

        # -- 1. basic shell flows -------------------------------------------
        print("-- shell tool basics --")
        s = cage_shell(wd, "printf 'from-cage'")
        check(s["ok"] and s["exit"] == 0 and s["stdout"] == "from-cage", s["stdout"])
        s = cage_shell(wd, "echo out >&2; exit 7")
        check(s["exit"] == 7, "exit code passthrough")
        check("out" in s["stderr"], "stderr captured")

        # -- 2. workdir writable inside cage, persists host-side ------------
        print("-- workdir bind --")
        s = cage_shell(wd, "echo cage-wrote-this > from-cage.txt; cat from-cage.txt")
        check(s["exit"] == 0 and (wd / "from-cage.txt").read_text().strip() == "cage-wrote-this", "workdir write persists")

        # -- 3. HOME writable (git/pip/cargo caches) ------------------------
        print("-- HOME bind --")
        home = Path.home()
        probe = home / ".curam-wiring-probe"
        s = cage_shell(wd, f"echo ok > {probe}")
        check(s["exit"] == 0 and probe.read_text().strip() == "ok", "HOME write persists")
        probe.unlink(missing_ok=True)

        # -- 4. system read-only --------------------------------------------
        print("-- system dirs read-only --")
        s = cage_shell(wd, "rm /etc/passwd 2>&1; echo rc=$?")
        check("rc=1" in s["stdout"] or "Read-only" in s["stdout"], f"rm /etc/passwd: {s['stdout'].strip()}")
        s = cage_shell(wd, "touch /usr/local/lib/cage-test 2>&1; echo rc=$?")
        check("rc=1" in s["stdout"] or "Read-only" in s["stdout"], f"touch /usr: {s['stdout'].strip()}")

        # -- 5. egress (net on via harness default, so wget should work) ----
        print("-- egress --")
        # The harness wires net=True for daily use. A reachable host proves
        # net is on; if there is no network on this box this check is skipped.
        if os.environ.get("CURAM_CAGE_CHECK_ONLINE", "1") == "1":
            try:
                s = cage_shell(wd, "wget -T 5 -q -O /dev/null https://example.com; echo rc=$?")
                online = "rc=0" in s["stdout"]
            except Exception:
                online = False
            if online:
                check(online, "net on: wget example.com succeeded (rc=0)")
            else:
                print("  [SKIP] net on but example.com unreachable on this box")

        # -- 6. timeout ----------------------------------------------------
        print("-- timeout --")
        t0 = time.monotonic()
        s = cage_shell(wd, "sleep 30", timeout=2)
        elapsed = time.monotonic() - t0
        check(not s["ok"] and "timed out" in s.get("error", ""), f"timeout after 2s (took {elapsed:.1f}s)")
        check(elapsed < 10, "killed promptly")

        # -- 7. fail-closed: no cage binary => shell refuses ----------------
        print("-- fail-closed (missing curam-run) --")
        os.environ["CURAM_RUN_BIN"] = "/nonexistent/curam-run"
        s = cage_shell(wd, "echo should-not-run > escaped.txt; exit 0")
        os.environ.pop("CURAM_RUN_BIN", None)
        check(not s["ok"], "shell refused without a cage")
        check("cage" in s.get("error", ""), "error explains the cage is required")
        # If the shell had silently fallen back to a raw unsandboxed subprocess,
        # escaped.txt would exist in the cwd. It must NOT.
        check(not (wd / "escaped.txt").exists(), "command did NOT run unsandboxed")

        print("\nALL CHECKS PASSED — the wiring is live and the boundary holds.")


if __name__ == "__main__":
    main()
