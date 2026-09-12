# Security

## Scope

**curamsec** (Python extension + `curam-run` binary) is a security boundary
for a coding-agent harness: command classification, egress/country control,
and verified feed lists. This file covers the core and the repo. The harness
that consumes it has its own policy and journaling.

## Disclosures

**Do not open a public issue for a suspected vulnerability.** Report it
privately instead:

- **Email**: <hi@drn.ie> with subject prefix `[curam-security]`,
  or use the GitHub private-vulnerability report on the repository
  (Security → Report a vulnerability).

Please include:

- the affected version (`curamsec.__version__` / `curam-run` build),
- a minimal repro (commands, list files, config),
- impact you observed (what an attacker can do).

We acknowledge receipt within 48h and aim for a fix + advisory within 14
days of triage.

## Threat model (what this core does — and doesn't — protect)

- `classify` / `scan_context` / `match_host`: in-process heuristics — a
  *layer*, not a proof. `unknown` always degrades to `ask`, never hard-block.
- `curam-run` (bwrap cage): the real boundary. Net off by default; system
  dirs read-only; only explicitly-bound paths are writable. The cage is
  unprivileged (user namespaces) — it contains, it is not a kernel
  security module.
- Feed integrity: lists are pinned + content-hashed, swapped atomically,
  verified at every load, and monotonic-rev'd against rollback. No keys
  are needed for the minimum posture.
- Out of scope: mirrors/signing (only when public feeds ship), the AI
  provider, and any code running OUTSIDE the cage.

## Reporting checklist for CI / dependabot

- Rust: `cargo audit` (no network policy required)
- Python deps: assessed in `.github/workflows/ci.yml`
- Anything that touches `proto/` is a contract change — review it like code.

## Security-sensitive areas (for contributors)

- `src/lists.rs` — pin/hash/atomic/rev (tamper at ANY stage must fail)
- `src/bin/curam_run.rs` — bwrap argv construction, netns, geo ruleset
- `harness-wiring/` — the default is fail-closed: no cage, no unsandboxed
  shell. Keep it that way.

## Supported versions

The latest `main` is supported. Pre-1.0: expect the CLI/ndjson surface
(`proto/ndjson-spec.md`) to remain backward-compatible at the `cage/1`
envelope; add new fields additively only.
