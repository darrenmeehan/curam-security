# e01s09 — Test client + ndjson contract replay (T6)

**type:** feat · **risk:** P1 · **bcps:** 3

## Context
Test client + ndjson contract replay (T6)

## Requirements (ADDED)
1. Test client + ndjson contract replay (T6) — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. python3 tests/test_client.py drives curamsec (classify/match_host/check_pkg) + curam-run (ndjson) and asserts verdicts
2. Node stub re-plays the SAME ndjson contract without importing curam — proves the contract is language-agnostic (T6)

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
