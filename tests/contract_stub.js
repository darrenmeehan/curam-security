#!/usr/bin/env node
// e01s09 task 2 — contract stub in node (T6).
//
// A consumer in another language re-plays the cage/1 ndjson contract
// against curam-run WITHOUT importing any curam code. This file knows only
// the documented schema (proto/ndjson-spec.md): it builds a request, pipes
// it over stdio, parses the result, and asserts the envelope — then exits
// 0. Proves the contract is language-agnostic.
//
// Usage: node tests/contract_stub.js [path-to-curam-run]

const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

const bin =
  process.argv[2] || path.join(__dirname, "..", "target", "debug", "curam-run");
if (!fs.existsSync(bin)) {
  console.error(`curam-run not built: ${bin}`);
  process.exit(2);
}

const request = {
  id: 7,
  v: "cage/1",
  cmd: ["bash", "-c", "echo contract-ok"],
  cwd: path.join(__dirname, ".."),
  timeout_s: 10,
  net: false,
  allow_hosts: ["github.com"],
  deny_hosts: ["evil.example"],
};

const run = spawn(bin, [], { stdio: ["pipe", "pipe", "pipe"] });
run.stdin.write(JSON.stringify(request) + "\n");
run.stdin.end();

let out = "";
run.stdout.on("data", (d) => (out += d));
run.stderr.on("data", (d) => process.stderr.write(d));
run.on("error", (e) => {
  console.error("spawn error:", e.message);
  process.exit(2);
});
run.on("close", (code) => {
  const lines = out.trim().split("\n");
  let result;
  try {
    result = JSON.parse(lines[lines.length - 1]);
  } catch (e) {
    console.error("result is not JSON:", out);
    process.exit(1);
  }

  // Envelope keys from proto/ndjson-spec.md — nothing else is assumed.
  const envelope = [
    "id",
    "exit",
    "stdout",
    "stderr",
    "timed_out",
    "cages",
    "verdicts",
  ];
  for (const key of envelope) {
    if (!(key in result)) {
      console.error(`missing envelope key: ${key}`);
      process.exit(1);
    }
  }
  for (const v of result.verdicts) {
    for (const key of [
      "action",
      "rule_id",
      "source",
      "source_hash",
      "evidence",
    ]) {
      if (!(key in v)) {
        console.error(`verdict missing chain key: ${key}`);
        process.exit(1);
      }
    }
  }

  if (result.id !== request.id) {
    console.error(`id mismatch: sent ${request.id}, got ${result.id}`);
    process.exit(1);
  }
  if (result.stdout.trim() !== "contract-ok") {
    console.error(`stdout mismatch: ${JSON.stringify(result.stdout)}`);
    process.exit(1);
  }
  if (result.exit !== 0) {
    console.error(`exit mismatch: ${result.exit}`);
    process.exit(1);
  }
  if (code !== 0) {
    console.error(`curam-run exited ${code}`);
    process.exit(1);
  }
  console.log("node contract stub OK");
  process.exit(0);
});
