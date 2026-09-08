# e01s05 — Lists pipeline (pin/hash/atomic/rev)

**type:** feat · **risk:** P0 · **bcps:** 5

## Context
Lists pipeline (pin/hash/atomic/rev)

## Requirements (ADDED)
1. Lists pipeline (pin/hash/atomic/rev) — see tasks.
2. See tasks.yaml for task-level verify commands.

## Implementation Steps
1. List dir format: list.json {source_url, license, etag, sha256, refreshed_at, rev, entries}; updater fetches PINNED snapshot (rev, not HEAD) into staging
2. Atomic swap: staging verify sha256 vs manifest, then rename into place
3. Load-time verify: on-disk list hash+rev checked at EVERY load; stale rev rejected; tampered list rejected

## Verification Script
Run each step's verify command; each must exit non-0... no — exit 0.

## Out of scope
- Harness integration / T7 (later epic)
- tokio/axum daemon (curamd, later)

## Risks
- See tasks.yaml risk field.
