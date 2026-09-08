# e01s04 — match_host trie + allow-over-deny

**type:** feat · **risk:** P1 · **bcps:** 3

## Context
match_host trie + allow-over-deny

## Requirements (ADDED)
1. match_host trie + allow-over-deny — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. Hostname suffix trie over deny hosts + allow hosts (PSL-suffix aware)
2. Allow always beats deny; unknown -> ask
3. Load host sets from lists-on-disk format (list.json rev + entries)

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
