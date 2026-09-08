# e01s08 — check_pkg OSV lookup (offline fixture)

**type:** feat · **risk:** P1 · **bcps:** 2

## Context
check_pkg OSV lookup (offline fixture)

## Requirements (ADDED)
1. check_pkg OSV lookup (offline fixture) — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. check_pkg(name, version) -> list[Advisory] against a local OSV/RustSec fixture file
2. Clean package -> []

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
