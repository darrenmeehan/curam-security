# e01s02 — Port policy.py rules to Rust

**type:** feat · **risk:** P1 · **bcps:** 4

## Context
The Python POC's policy.py encodes the allow/ask/deny rule set. Port it to Rust so the core is the single policy engine; parity must be exact (behavior-identical port, no logic reinterpreted).

## Requirements (ADDED)
1. The full policy rule set (commands + patterns) lives in Rust; loading a fixture of the Python rules yields 100% parity verdicts.
2. Scenario parity: scenario_deny still denies; scenario_pii_scrub still scrubs PII via classify().

## Implementation Steps
1. Extract rules from curam-harness-poc policy.py into a versioned rules module (Rust static or list file)
2. aho-corasick multi-pattern engine over the ported rules; identical verdicts vs policy.py on a parity fixture
3. Scenario parity tests: scenario_deny (denied) + scenario_pii_scrub (PII scrubbed) through classify()

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- Silent drift between Python rules and the port; the parity fixture is the guard — build it before shipping the port.
