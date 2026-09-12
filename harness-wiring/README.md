# Harness wiring for the curam-run cage (T7)

Drop the curam-run sandbox into `curam-harness`: **the `shell` tool becomes
the cage**. Fail-closed — no cage, no shell.

## What changes in the harness

- **`cage.py`** (new) — a minimal ndjson client. It speaks the documented
  `cage/1` contract over stdio; it does NOT import any curam code (T6).
- **`tools.py`** — `tool_shell` now runs the command inside curam-run with:
  - `net: true` by default (daily pip/git/cargo/npm still works)
  - writable **bind** of the workdir + home (where git/ssh/pip/cargo keep
    config and caches); everything else is read-only in the cage
  - the same return shape `{ok, exit, stdout, stderr}` — `agent.py` is
    untouched
  - **fail-closed**: if the cage binary is unavailable, shell returns an
    error telling you to build it — it will NOT silently run unsandboxed

## Apply

```bash
bash harness-wiring/apply.sh
```

(It builds curam-run if missing, backs up tools.py, and copies the two
files in. Set `CURAM_HARNESS_DIR` if your harness lives elsewhere.)

## Verify

```bash
cd ~/code/curam/curam-harness
python3 -m py_compile tools.py cage.py
python3 - <<'PYEOF'
import tempfile, pathlib, tools
r = tools.tool_shell(pathlib.Path(tempfile.mkdtemp()), {"command": "echo hi"})
assert r["exit"] == 0 and r["stdout"].strip() == "hi", r
print("shell tool is wired: command ran inside the cage")
PYEOF
```

## Tuning

- **Point at a different binary**: `export CURAM_RUN_BIN=/path/to/curam-run`
- **Disabled by default?** Not yet — toggling it is a 1-line env read in
  `tool_shell` if you want a kill switch later.
- **Harder cage**: run with `net: false` / `geo: "COUNTRY"` for egress
  control (see `proto/ndjson-spec.md`).

## Behavior notes (daily-use differences)

- Every `shell` command now starts a bwrap cage: workdir + home writable,
  system dirs read-only, `/tmp` and `/run` are tmpfs (fresh per command).
- Commands that absolutely need to write outside workdir/home (e.g.
  `sudo`, installs to `/usr`) will fail inside the cage — that is the
  point. `read` / `write` / `edit` tools are unchanged and stay host-side.
- Timeouts still kill the command (`timed_out: true`).
