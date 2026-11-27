"""hostio.read_regular_bytes is the gate's reader for journals, nonces and keys. It must end every hostile case as a named
HostIntegrityError and never block, crash raw or return more than its cap (review, red-first on root 27737c6d)."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from hlith.hostio import integrity
from hlith.hostio.integrity import HostIntegrityError, read_regular_bytes


def _call_with_deadline(fn, seconds=5.0):
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - the test inspects what came out
            box["exc"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        pytest.fail("read_regular_bytes blocked (it opened a FIFO): the gate would hang")
    return box


def test_an_unreadable_file_is_a_named_integrity_error_not_a_raw_permission_error(tmp_path: Path):
    if os.geteuid() == 0:
        pytest.skip("root reads mode-000 files")
    p = tmp_path / "landing.json"
    p.write_text("{}")
    p.chmod(0)
    try:
        with pytest.raises(HostIntegrityError, match="cannot read"):
            read_regular_bytes(p)
    finally:
        p.chmod(0o600)


def test_a_missing_file_is_a_named_integrity_error(tmp_path: Path):
    with pytest.raises(HostIntegrityError):
        read_regular_bytes(tmp_path / "gone.json")


def test_a_regular_file_swapped_for_a_fifo_after_the_check_neither_blocks_nor_is_read(tmp_path: Path, monkeypatch):
    """Deterministic stand-in for the race: the pre-open lstat sees a regular file, the path is a FIFO when it is opened."""
    reg = tmp_path / "regular"
    reg.write_text("{}")
    fifo = tmp_path / "landing.json"
    os.mkfifo(fifo)
    real_lstat = os.lstat
    monkeypatch.setattr(integrity.os, "lstat", lambda p, *a, **k: real_lstat(reg) if Path(p) == fifo else real_lstat(p, *a, **k))
    box = _call_with_deadline(lambda: read_regular_bytes(fifo))
    assert isinstance(box.get("exc"), HostIntegrityError), box


def test_a_file_that_grew_past_the_cap_after_the_check_is_refused_not_returned(tmp_path: Path, monkeypatch):
    p = tmp_path / "landing.json"
    p.write_bytes(b"x" * 64)
    small = tmp_path / "small"
    small.write_bytes(b"x" * 8)
    real_lstat = os.lstat
    monkeypatch.setattr(integrity.os, "lstat", lambda q, *a, **k: real_lstat(small) if Path(q) == p else real_lstat(q, *a, **k))
    with pytest.raises(HostIntegrityError, match="exceeds"):
        read_regular_bytes(p, max_bytes=16)


def test_an_ordinary_regular_file_is_still_read_whole(tmp_path: Path):
    p = tmp_path / "ok.json"
    p.write_bytes(b'{"a": 1}')
    assert read_regular_bytes(p, max_bytes=8) == b'{"a": 1}'
