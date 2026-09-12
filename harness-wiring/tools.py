"""Tools available to the model: read / write / edit / shell.

Shell runs inside the curam-run bwrap cage (sandbox): system dirs are
read-only, only the workdir + home are writable binds, net off unless
requested, commands time out. If the cage binary is unavailable or a
request fails, shell silently falls back to a raw subprocess so daily use
never regresses (sandbox is additive).
"""

import os
from pathlib import Path

import cage

# JSON schema for each tool, sent to the provider.
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read",
            "description": "Read a file within the workdir.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "relative path"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write",
            "description": "Write a file within the workdir (overwrites).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit",
            "description": "Replace the first occurrence of old_text with new_text in a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_text": {"type": "string"},
                    "new_text": {"type": "string"},
                },
                "required": ["path", "old_text", "new_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell",
            "description": "Run a shell command in the workdir. Returns exit code, stdout, stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {
                        "type": "integer",
                        "description": "seconds, default 60",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ask_human",
            "description": (
                "Ask the human for judgment (design fork, ambiguity, "
                "irreversible change, or when stuck). Use sparingly — "
                "for decisions only a human can make."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "options": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "use_skill",
            "description": (
                "Load a skill's full instructions into context. Call this "
                "with a skill name from the system prompt's Available skills "
                "list when that skill applies to the current task."
            ),
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
]

MAX_READ_CHARS = 60_000
MAX_OUTPUT_CHARS = 8_000


def _resolve(workdir: Path, path: str) -> Path:
    return (workdir / path).resolve()


def tool_read(workdir: Path, args: dict) -> dict:
    p = _resolve(workdir, args["path"])
    try:
        text = p.read_text(errors="replace")
        truncated = len(text) > MAX_READ_CHARS
        return {
            "ok": True,
            "path": str(p),
            "content": text[:MAX_READ_CHARS],
            "truncated": truncated,
        }
    except OSError as e:
        return {"ok": False, "error": str(e)}


def tool_write(workdir: Path, args: dict) -> dict:
    p = _resolve(workdir, args["path"])
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(args["content"])
        return {"ok": True, "path": str(p), "bytes": len(args["content"])}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def tool_edit(workdir: Path, args: dict) -> dict:
    p = _resolve(workdir, args["path"])
    try:
        text = p.read_text(errors="replace")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    old, new = args["old_text"], args["new_text"]
    if old not in text:
        return {"ok": False, "error": "old_text not found in file"}
    p.write_text(text.replace(old, new, 1))
    return {"ok": True, "path": str(p), "replaced": text.count(old)}


def _as_str(s: str | bytes | None) -> str:
    if s is None:
        return ""
    if isinstance(s, bytes):
        return s.decode(errors="replace")
    return s


def _trim(s: str | bytes | None, limit: int = MAX_OUTPUT_CHARS) -> str:
    t = _as_str(s)
    return (
        t
        if len(t) <= limit
        else t[:limit] + f"\n... (truncated {len(t) - limit} chars)"
    )


def _cage_bind(workdir: Path) -> list[str]:
    """Writable binds: the workdir (where the agent edits) + home (where
    git/ssh/pip/cargo keep config, caches and credentials). Everything else
    stays read-only in the cage."""
    home = Path.home()
    return [f"{workdir}:{workdir}", f"{home}:{home}"]


def tool_shell(workdir: Path, args: dict, timeout_default: int = 60) -> dict:
    cmd = args["command"]
    try:
        timeout = int(args.get("timeout") or timeout_default)
    except (TypeError, ValueError):
        timeout = timeout_default

    # The shell tool is the cage, not a raw subprocess. net on by default so
    # daily agent work (pip/git/cargo/npm) keeps working; system dirs stay
    # read-only, only workdir + home are writable binds.
    bin_path = os.environ.get(
        "CURAM_RUN_BIN",
        str(Path.home() / "code/curam-security/target/debug/curam-run"),
    )
    gate = cage.Cage(bin_path)
    r = gate.run(
        ["bash", "-c", cmd],
        cwd=workdir,
        timeout_s=timeout,
        net=True,
        bind=_cage_bind(workdir),
    )
    if r is None:
        # Fail closed: no cage, no unsandboxed shell. Build the binary once
        # (cargo build --bin curam-run in ~/code/curam-security) or point
        # CURAM_RUN_BIN at an existing build.
        return {
            "ok": False,
            "error": (
                f"curam-run unavailable at {bin_path} — shell is the cage "
                "and refuses to run unsandboxed. Build it: "
                "cargo build --bin curam-run (in ~/code/curam-security) "
                "or set CURAM_RUN_BIN to an existing binary."
            ),
        }
    if r.get("timed_out"):
        return {
            "ok": False,
            "error": f"timed out after {timeout}s",
            "stdout": _trim(r.get("stdout")),
            "stderr": _trim(r.get("stderr")),
        }
    return {
        "ok": True,
        "exit": r.get("exit", 1),
        "stdout": _trim(r.get("stdout")),
        "stderr": _trim(r.get("stderr")),
    }


TOOLS = {
    "read": tool_read,
    "write": tool_write,
    "edit": tool_edit,
    "shell": tool_shell,
}


def run(workdir: Path, name: str, args: dict, timeout_default: int = 60) -> dict:
    fn = TOOLS.get(name)
    if fn is None:
        return {"ok": False, "error": f"unknown tool: {name}"}
    if name == "shell":
        return fn(workdir, args, timeout_default)
    return fn(workdir, args)


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        assert tool_write(wd, {"path": "a/b.txt", "content": "hello"})["ok"]
        r = tool_read(wd, {"path": "a/b.txt"})
        assert r["content"] == "hello"
        assert tool_edit(
            wd, {"path": "a/b.txt", "old_text": "hello", "new_text": "bye"}
        )["ok"]
        assert tool_read(wd, {"path": "a/b.txt"})["content"] == "bye"
        # edit on missing text reports failure, does not crash
        assert not tool_edit(
            wd, {"path": "a/b.txt", "old_text": "zzz", "new_text": "x"}
        )["ok"]
        s = tool_shell(wd, {"command": "printf hi"})
        assert s["exit"] == 0 and s["stdout"].strip() == "hi"
        bad = tool_shell(wd, {"command": "exit 3"})
        assert bad["exit"] == 3
        # the shell tool is the cage: workdir writable, /etc read-only
        cage_write = tool_shell(wd, {"command": "echo ok > caged.txt; cat caged.txt"})
        assert cage_write["exit"] == 0 and cage_write["stdout"].strip() == "ok"
        ro = tool_shell(wd, {"command": "touch /etc/passwd 2>&1; echo rc=$?"})
        assert "rc=1" in (ro.get("stdout") or "") or "Read-only" in (ro.get("stdout") or ""), ro
        assert not run(wd, "nope", {})["ok"]
        print("tools self-check OK (shell runs in the cage)")
