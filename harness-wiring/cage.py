"""curam-run ndjson client — the cage seam (proto/ndjson-spec.md, cage/1).

The harness speaks the documented contract over stdio; it does NOT import
any curam code (T6: the contract replayable by any consumer). Each run()
spawns curam-run once, sends one request line, reads one result line.

Silent degrade: if the binary is missing or a request fails, run() returns
None so the harness shell falls back to a raw subprocess (daily use never
regresses). No error is raised for sandbox unavailability.
"""

import json
import subprocess
from pathlib import Path

ENVELOPE = "cage/1"


class Cage:
    def __init__(self, binary: Path | str):
        self.binary = Path(binary)

    @property
    def available(self) -> bool:
        return self.binary.exists()

    def run(
        self,
        cmd,
        *,
        cwd=None,
        timeout_s=None,
        net=False,
        geo=None,
        bind=(),
        allow_hosts=(),
        deny_hosts=(),
        id=0,
    ) -> dict | None:
        """Run cmd in the cage. Returns the result envelope dict, or None when
        the binary is unavailable or the request failed (caller falls back to
        an unsandboxed subprocess)."""
        if not self.available:
            return None
        request = {
            "id": id,
            "v": ENVELOPE,
            "cmd": list(cmd),
            "net": net,
            "bind": list(bind),
            "allow_hosts": list(allow_hosts),
            "deny_hosts": list(deny_hosts),
        }
        if cwd is not None:
            request["cwd"] = str(cwd)
        if timeout_s is not None:
            try:
                request["timeout_s"] = int(timeout_s)
            except (TypeError, ValueError):
                return None
        if geo is not None:
            request["geo"] = geo
        line = json.dumps(request, separators=(",", ":"))
        p = subprocess.run(
            [str(self.binary)],
            input=line + "\n",
            capture_output=True,
            text=True,
            timeout=(timeout_s or 300) + 30,
        )
        if p.returncode != 0:
            return None
        try:
            result = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None
        if result.get("error"):
            return None
        return result
