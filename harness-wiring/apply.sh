#!/usr/bin/env bash
# Wire the curam-cage cage into the harness shell tool + journal.
#
# 1. Copies cage.py (ndjson client) + tools.py (shell = the cage, fail-closed)
# 2. Patches agent.py to journal the verdict chain (provable audibility)
# Backs up both files before touching them.
#
# Usage: bash harness-wiring/apply.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${CURAM_HARNESS_DIR:-$HOME/code/curam/curam-harness}"

if [ ! -d "$HARNESS" ]; then
    echo "harness dir not found: $HARNESS (set CURAM_HARNESS_DIR)"
    exit 1
fi
if [ ! -x "$HOME/code/curam-security/target/debug/curam-cage" ]; then
    echo "curam-cage not built — building it first:"
    (cd "$HOME/code/curam-security" && cargo build --bin curam-cage)
fi

cp "$HARNESS/tools.py" "$HARNESS/tools.py.bak-$(date +%s)"
cp "$HERE/cage.py" "$HARNESS/cage.py"
cp "$HERE/tools.py" "$HARNESS/tools.py"

# Patch agent.py: journal the verdict chain after tool dispatch (idempotent).
cp "$HARNESS/agent.py" "$HARNESS/agent.py.bak-$(date +%s)"
python3 - "$HARNESS/agent.py" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
if "_journal_verdicts" in text:
    print("agent.py already verdict-journaled — skipped.")
    sys.exit(0)

anchor = '''                if not granted:
                    return {"ok": False, "denied": True, "reason": "human denied"}

        return toolmod.run(self.workdir, name, args)
'''
replacement = '''                if not granted:
                    return {"ok": False, "denied": True, "reason": "human denied"}

        result = toolmod.run(self.workdir, name, args)
        _journal_verdicts(self.journal, name, args, result)
        return result


def _journal_verdicts(journal, name: str, args: dict, result: dict) -> None:
    """Record the cage verdict chain for the shell tool (provable audibility).

    The caged `tool_shell` (tools.py) returns `verdicts` (the list of
    {action, rule_id, source, source_hash, evidence} the cage resolved for
    this command) and `cages` (the layers applied). Both are additive —
    tools that aren't the cage simply don't have them, so this is a no-op
    for read/write/edit.
    """
    if name != "shell" or not isinstance(result, dict):
        return
    payload = {"command": args.get("command", "")}
    if "verdicts" in result and result["verdicts"]:
        payload["verdicts"] = result["verdicts"]
    if "cages" in result:
        payload["cages"] = result["cages"]
    if "timed_out" in result and result["timed_out"]:
        payload["timed_out"] = True
    if len(payload) > 1:
        journal.log("tool_verdicts", payload)
'''
if anchor not in text:
    print("agent.py anchor not found — apply the change manually; tools/cage are already wired.")
    sys.exit(1)

path.write_text(text.replace(anchor, replacement, 1))
print("agent.py patched: tool_verdicts journaling added.")
PYEOF

echo "wired. verify:"
echo "  cd $HARNESS && python3 -m py_compile agent.py tools.py cage.py"
echo "  python3 - <<'EOF'"
echo "  import tempfile, pathlib, tools"
echo "  wd = pathlib.Path(tempfile.mkdtemp())"
echo "  r = tools.tool_shell(wd, {'command': 'echo hi'})"
echo "  print('exit', r['exit'], '| cages:', r['cages'], '| verdicts:', r['verdicts'])"
echo "EOF"
