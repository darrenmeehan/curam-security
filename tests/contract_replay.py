#!/usr/bin/env python3
"""e01s06 task 2 — ndjson contract v1 replay (T6 property).

The contract is transport-agnostic: a stub consumer in ANOTHER language
(node) drives curam-cage over stdio and validates the result envelope,
without importing curam's code. This script:
  1. builds a request per the v1 schema,
  2. pipes it to curam-cage (Rust binary),
  3. asserts the result envelope shape + echo,
  4. with --stub node, replays the same request through an inline node
     consumer and asserts the same envelope (proving language-agnostic).

Usage: python3 tests/contract_replay.py [--stub node] [--curam-cage PATH]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_BIN = REPO / "target" / "debug" / "curam-cage"

REQUEST = {
  "id": 1,
  "v": "cage/1",
  "cmd": ["bash", "-c", "echo contract-ok"],
  "cwd": str(REPO),
  "timeout_s": 5,
  "net": False,
  "allow_hosts": ["github.com"],
  "deny_hosts": ["evil.example"],
}


def assert_envelope(result, expect_stdout):
  """The v1 result envelope: {id, exit, stdout, stderr, timed_out, cages, verdicts}."""
  for key in ("id", "exit", "stdout", "stderr", "timed_out", "cages", "verdicts"):
    assert key in result, f"missing envelope key {key}: {result}"
  assert result["id"] == REQUEST["id"], "id must echo"
  assert result["stdout"].strip() == expect_stdout, result
  assert isinstance(result["cages"], list) and result["cages"], (
    "cages must be non-empty"
  )
  assert isinstance(result["verdicts"], list), "verdicts must be a list"
  assert result["exit"] == 0


def replay_python(bin_path):
  line = json.dumps(REQUEST, separators=(",", ":"))
  p = subprocess.run(
    [str(bin_path)], input=line + "\n", capture_output=True, text=True, timeout=30
  )
  assert p.returncode == 0, p.stderr
  result = json.loads(p.stdout.strip().splitlines()[-1])
  assert_envelope(result, "contract-ok")
  return result


NODE_STUB = r"""
const { spawn } = require('node:child_process');
const req = process.argv[1];
const run = spawn(process.argv[2], [], { stdio: ['pipe', 'pipe', 'pipe'] });run.stdin.write(req + '\n');
run.stdin.end();
let out = '';
run.stdout.on('data', d => out += d);
run.on('close', () => {
  const lines = out.trim().split('\n');
  const result = JSON.parse(lines[lines.length - 1]);
  for (const key of ['id','exit','stdout','stderr','timed_out','cages','verdicts']) {
    if (!(key in result)) { console.error('missing key ' + key); process.exit(1); }
  }
  if (result.id !== 1) process.exit(1);
  if (result.stdout.trim() !== 'contract-ok') process.exit(1);
  if (result.exit !== 0) process.exit(1);
  console.log('node-stub-ok');
});
"""


def replay_node(bin_path):
  """A node consumer that knows ONLY the documented contract schema."""
  p = subprocess.run(
    [
      "node",
      "-e",
      NODE_STUB,
      json.dumps(REQUEST, separators=(",", ":")),
      str(bin_path),
    ],
    capture_output=True,
    text=True,
    timeout=30,
  )
  assert p.returncode == 0, p.stderr
  assert "node-stub-ok" in p.stdout, p.stdout


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--stub", choices=["node"], default=None)
  ap.add_argument("--curam-cage", default=str(DEFAULT_BIN))
  args = ap.parse_args()

  bin_path = Path(args.curam_cage)
  assert bin_path.exists(), (
    f"curam-cage not built: {bin_path} (cargo build --bin curam-cage)"
  )

  replay_python(bin_path)
  if args.stub == "node":
    replay_node(bin_path)
  print("contract replay OK")
  return 0


if __name__ == "__main__":
  sys.exit(main())
