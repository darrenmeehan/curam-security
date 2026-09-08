# e01s10 — OSS hygiene + CI + Nix dev env

**type:** feat · **risk:** P2 · **bcps:** 2

## Context
OSS hygiene + CI + Nix dev env

## Requirements (ADDED)
1. OSS hygiene + CI + Nix dev env — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. License (Apache-2.0 + MIT dual), SECURITY.md, proto/ schema dir
2. GitHub Actions: maturin abi3 wheel + cargo test + pytest matrix on Linux
3. flakes.nix devShell pinning rust toolchain + python + maturin + bwrap

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
