# e01s07 — Country/IP blocking in the cage netns

**type:** feat · **risk:** P1 · **bcps:** 3

## Context
Country/IP blocking in the cage netns

## Requirements (ADDED)
1. Country/IP blocking in the cage netns — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. curam-run gains --geo COUNTRY: load country CIDR set into the cage's network namespace via nftables/ipset tooling (geo-nft / ipset-country)
2. Proto doc: --geo in ndjson envelope; documented in proto/ndjson-spec

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
