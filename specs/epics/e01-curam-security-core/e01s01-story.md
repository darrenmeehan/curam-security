# e01s01 — Tracer: maturin skeleton + classify()

**type:** feat · **risk:** P1 · **bcps:** 2

## Context
First vertical slice: a Rust crate builds into an abi3 wheel, Python imports it, classify() answers allow/ask/deny. Catches maturin/pyo3/abi3 integration errors before any feature work.

## Requirements (ADDED)
1. classify(cmd) -> Verdict with action in {allow,ask,deny}; deny on dangerous exact commands ('rm -rf /').
2. Verdict carries the provable chain fields (action, rule_id, source, source_hash, evidence) from commit one.

## Implementation Steps
1. Init repo plumbing: pyproject.toml with [build-system]=maturin + abi3, src/lib.rs with #[pymodule] exporting classify()
2. classify returns Verdict allow/ask/deny; deny on dangerous exact commands like 'rm -rf /'
3. Verdict carries action/rule_id/source/source_hash/evidence (provable chain start)

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- PyO3/Maturin API surface changes mid-build; pin maturin version in the dev shell.
