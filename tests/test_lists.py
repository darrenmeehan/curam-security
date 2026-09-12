"""e01s05 — verified lists pipeline, driven from Python.

Mirrors the story verify: install a pinned list, then a tampered or stale
list must be rejected at load — reload_host_lists() must raise.
"""

import hashlib
import json
from pathlib import Path

import curamsec
import pytest


def make_list(entries, rev):
    canon = json.dumps(entries, separators=(",", ":"))
    return {
        "source_url": "https://example.test/lists",
        "license": "CC0",
        "etag": "",
        "sha256": hashlib.sha256(canon.encode()).hexdigest(),
        "refreshed_at": "",
        "rev": rev,
        "entries": entries,
    }


@pytest.fixture
def lists_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CUSEC_LISTS_DIR", str(tmp_path))
    return tmp_path


def install(lists_dir, name, entries, rev):
    curamsec.lists_update(str(lists_dir), name, json.dumps(make_list(entries, rev)))
    # the shared host matcher caches lists at first use; re-seed it so
    # match_host sees the lists installed in THIS test's dir
    curamsec.reload_host_lists()


def test_lists_update_installs_and_match_host_uses_it(lists_dir):
    install(lists_dir, "deny", ["evil.example"], 1)
    assert curamsec.match_host("evil.example").action == "deny"
    # nothing at or below the installed rev replays
    with pytest.raises(ValueError, match="rollback"):
        install(lists_dir, "deny", ["evil.example"], 1)


def test_tampered_list_rejected_at_load(lists_dir):
    install(lists_dir, "deny", ["evil.example"], 2)
    path = Path(lists_dir) / "deny" / "list.json"
    doc = json.loads(path.read_text())
    doc["entries"] = ["allowed.example"]  # hash now stale
    path.write_text(json.dumps(doc, separators=(",", ":")))
    with pytest.raises(ValueError, match="sha256 mismatch"):
        curamsec.reload_host_lists()


def test_stale_rev_rejected_at_load(lists_dir):
    install(lists_dir, "deny", ["evil.example"], 5)
    path = Path(lists_dir) / "deny" / "list.json"
    path.write_text(json.dumps(make_list(["evil.example"], 3)))  # old snapshot
    with pytest.raises(ValueError, match="stale rev"):
        curamsec.reload_host_lists()


def test_allow_list_always_beats_deny(lists_dir):
    install(lists_dir, "allow", ["pypi.org"], 1)
    install(lists_dir, "deny", ["evil.example"], 1)
    assert curamsec.match_host("sub.pypi.org").action == "allow"
    assert curamsec.match_host("evil.example").action == "deny"
