#!/usr/bin/env bash
# Wire the curam-run cage into the harness shell tool.
#
# Copies cage.py (the ndjson client) + the patched tools.py (shell = the
# cage, fail-closed) into curam-harness. Backs up the current tools.py.
#
# Usage: bash harness-wiring/apply.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${CURAM_HARNESS_DIR:-$HOME/code/curam/curam-harness}"

if [ ! -d "$HARNESS" ]; then
    echo "harness dir not found: $HARNESS (set CURAM_HARNESS_DIR)"
    exit 1
fi
if [ ! -x "$HOME/code/curam-security/target/debug/curam-run" ]; then
    echo "curam-run not built — building it first:"
    (cd "$HOME/code/curam-security" && cargo build --bin curam-run)
fi

cp "$HARNESS/tools.py" "$HARNESS/tools.py.bak-$(date +%s)"
cp "$HERE/cage.py" "$HARNESS/cage.py"
cp "$HERE/tools.py" "$HARNESS/tools.py"

echo "wired. verify:"
echo "  cd $HARNESS && python3 -m py_compile tools.py cage.py"
echo "  python3 - <<'EOF'"
echo "  import tempfile, pathlib, tools"
echo "  wd = pathlib.Path(tempfile.mkdtemp())"
echo "  r = tools.tool_shell(wd, {'command': 'echo hi'})"
echo "  print(r)  # exit 0, stdout 'hi'"
echo "EOF"
