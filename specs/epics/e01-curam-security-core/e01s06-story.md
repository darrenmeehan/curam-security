# e01s06 — curam-run bwrap cage + ndjson v1

**type:** feat · **risk:** P0 · **bcps:** 5

## Context
curam-run bwrap cage + ndjson v1

## Requirements (ADDED)
1. curam-run bwrap cage + ndjson v1 — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. curam-run binary: parse args, exec 'bash -c cmd' inside bwrap (net off) + protect-system
2. Ndjson protocol v1 over stdio: request {id, cmd, cwd, timeout_s, net, allow_hosts, deny_hosts}; result {id, exit, stdout, stderr, cages, verdicts}
3. Timeout -> timed_out; egress denied (wget example.com), rm /etc/passwd denied, localhost allowed

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
