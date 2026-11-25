# Harness wiring for the curam-run cage (T7) + verdict journal

Drops the curam-run sandbox into `curam-harness-poc` and makes the shell tool's
**provable verdict chain** land in the session journal.

## Files in this directory

| File | Role | Installed to |
| --- | --- | --- |
| `cage.py` | minimal ndjson client for the `cage/1` contract (no curam imports — T6) | `curam-harness-poc/cage.py` |
| `tools.py` | tilts the harness `shell` tool to run inside the cage (fail-closed); returns `{ok, exit, stdout, stderr, cages, verdicts, timed_out}` | `curam-harness-poc/tools.py` |
| `apply.sh` | one-command installer: backs up tools.py + agent.py, copies cage.py + tools.py, patches agent.py to journal verdicts (idempotent) | run from this dir |
| `check_wiring.py` | thorough post-wiring test (runs the exact `tools.run` path the agent uses) | standalone, run from `curam-harness-poc` |
| `README.md` | this file |

## What the wiring does

- **`tool_shell` = the cage.** Every shell command the agent runs spawns a
  fresh bwrap cage: net on by default (daily pip/git/cargo still work),
  workdir + home writable binds, system dirs read-only, `/tmp`/`/run` tmpfs,
  timeout enforced. **Fail-closed:** if curam-run is missing, shell refuses
  rather than silently running unsandboxed.
- **Verdict chain journaled.** The cage already produced the provable chain
  `{action, rule_id, source, source_hash, evidence}` per command. `tools.py`
  now passes `verdicts` + `cages` + `timed_out` through, and `agent.py` logs
  them as a `tool_verdicts` event.
- **read/write/edit untouched** — host-side, as before.

## Intent (why the verdict journal)

The harness journal is *the* audit record ("the event stream IS the
product"). Before this change a shell run was journaled as command +
stdout/stderr; the cage's *decision* (which rule fired, which layers applied)
was computed and then thrown away. Now every shell command also records:

```json
{"command": "git push origin main",
 "verdicts": [{"action": "ask", "rule_id": "ask_flag", "source": "rules", ...}],
 "cages": ["bwrap:unshare-net", "bwrap:ro-system", "bwrap:net-on"]}
```

So after any session you can answer *"what did the agent try and what said
no — and under which cage layers?"* forensically, per command. This is the
auditability layer on top of the already-active gating + sandbox.

## Apply

```bash
bash ~/code/curam-security/harness-wiring/apply.sh
```

Reversible: `tools.py.bak-*` and `agent.py.bak-*` are left beside the
originals. Re-running is safe (idempotent — skips already-patched agent.py).

## Verify

```bash
cd ~/code/curam/curam-harness-poc
python3 -m py_compile agent.py tools.py cage.py
python3 ~/code/curam-security/harness-wiring/check_wiring.py
```

`check_wiring.py` covers: read/write/edit intact, shell basics + exit/stderr
passthrough, workdir + HOME writable & persistent, system dirs read-only,
timeout kills promptly, fail-closed (no cage => provably no unsandboxed
run), and that `cages`/`verdicts` flow through in journal-ready shape.

## Tuning

- **Point at a different curam-run build**: `export CURAM_RUN_BIN=/path/to/curam-run`.
- **Harder cage**: `net: false` / `geo: "COUNTRY"` per request (see `proto/ndjson-spec.md`).
- **See the journal rows**: `sqlite3 ~/.local/share/curam/curam.db "select etype,payload from events where etype='tool_verdicts' limit 10"`.

## Notes

- `cage.py` knows only the documented ndjson contract — no curam imports
  (the T6 contract-replay property, also covered by `tests/contract_stub.js`).
- The classifier (per-command LLM judge) is a separate layer, still off in
  `curam.toml` (`[classifier] enabled = false`). The cage = the boundary;
  the classifier = the pre-flight judge; the journal = the record. All three
  are independent.
