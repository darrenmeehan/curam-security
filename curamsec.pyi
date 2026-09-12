"""Type stub for the curamsec compiled extension (maturin/PyO3).

Mirrors the Rust `#[pymodule]` surface in src/lib.rs.
"""



class Verdict:
    action: str
    rule_id: str
    source: str
    source_hash: str
    evidence: str


class Finding:
    rule_id: str
    evidence: str


class Advisory:
    id: str
    summary: str
    severity: str


class HostMatcherPy:
    def __init__(self, allow: list[str], deny: list[str]) -> None: ...
    def lookup(self, host: str, allow_mode: bool = False) -> Verdict: ...


def classify(command: str, allow_rules: list[str] | None = None) -> Verdict: ...
def scan_context(text: str, threshold: int = 1) -> list[Finding]: ...
def match_host(host: str, allow: bool = False) -> Verdict: ...
def reload_host_lists() -> None: ...
def lists_update(lists_dir: str, name: str, fetched: str) -> str: ...
def check_pkg(name: str, version: str | None = None) -> list[Advisory]: ...
