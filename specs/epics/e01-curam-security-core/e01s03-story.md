# e01s03 — Injection defense in the core (rule + scanner)

**type:** feat · **risk:** P0 · **bcps:** 4

## Context
The documented Gap 1: a repo-file pipeline ('bash setup.sh' with adversarial content) exfiltrates. The CORE provides the rule (classify -> ask on exec-of-untrusted-content) and a content scanner (scan_context flags injection phrases). Harness wiring is out of scope (later epic).

## Requirements (ADDED)
1. classify returns 'ask' when cmd executes repo-derived content (signature: 'bash <repo-file>').
2. scan_context(text) flags embedded injection phrases (e.g. 'ignore previous instructions', 'MARKER: EXFIL...') with rule_id + evidence.

## Implementation Steps
1. classify returns 'ask' when cmd executes repo-derived content (signature: exec of a repo-file path, e.g. 'bash setup.sh')
2. scan_context(text) -> list[Finding] flags embedded injection phrases ('ignore previous instructions', 'MARKER: EXFIL')
3. Finding carries rule_id + evidence; threshold tunable

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- False positives must lean toward ask (not deny) — over-blocking breaks dev infra; assert the default is ask for unknown content.
