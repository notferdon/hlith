"""review / case: terminal-control injection through the real host under a pty.

Repository data (commit subject, file names, diff lines, docstrings) carries ESC/CSI/OSC/BEL/C1/bidi payloads. Every byte
the host writes to the terminal must contain only its OWN control sequences: no OSC (title/clipboard/hyperlink), no BEL,
no C1 byte, no bidi override, and no data-originated clear-screen or colour sequence. A positive control proves the hostile
text really reached the screen (escaped), so the test cannot pass vacuously."""

from __future__ import annotations

import pty
import re
import subprocess
from pathlib import Path

import pytest

from test_tui_claim_pgdn import E, _git, _pty_run  # noqa: E402

ESC = "\x1b"
HOSTILE = f"{ESC}[2J{ESC}]0;PWNED-TITLE\x07{ESC}]52;c;cHduZWQ={ESC}\\{ESC}]8;;http://evil.example/{ESC}\\‮gnp.exe\x08\x08\r{ESC}[31mREDUCED{ESC}[0m\u009b2J"
CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _hostile_repo(root: Path) -> Path:
    r = root / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "a.py").write_text("a=1\n")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "base")
    (r / "a.py").write_text(f'a=2  # {HOSTILE}\n"""{HOSTILE}"""\n')
    (r / f"ev{ESC}[2J{ESC}]0;PWNED-NAME\x07il‮.py").write_text(f"x = '{HOSTILE}'\n")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", f"subject {HOSTILE}")
    return r


def _foreign_sequences(raw: bytes) -> dict:
    """What the host wrote that is NOT one of its own plain CSI sequences."""
    rest = CSI.sub(b"", raw)
    return {
        "osc": rest.count(b"\x1b]"),
        "other_esc": rest.count(b"\x1b"),
        "bel": raw.count(b"\x07"),
        "c1_utf8": len(re.findall(rb"\xc2[\x80-\x9f]", raw)),
        "bidi_override": len(re.findall(rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]", raw)),
        "pwned_title_payload": raw.count(b"PWNED-TITLE") and raw.count(b"\x1b]0;PWNED"),
        "data_clear_screen": len(re.findall(rb"(?<!\x1b\[H)\x1b\[2J", raw)),  # every host clear is `ESC[H ESC[2J`; any other is data
        "data_red": raw.count(b"\x1b[31mREDUCED"),
    }


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("size", [(24, 80), (30, 100), (44, 160)])
def test_hostile_repository_text_never_reaches_the_terminal_as_control_bytes(tmp_path, size):
    repo = _hostile_repo(tmp_path)
    # Offer -> Selection (rail with the hostile file names, inspector) -> d (diff drill) -> Esc -> ? (help) -> Esc -> Claim -> History
    script = [("key", E), ("wait", 0.6), ("key", b"d"), ("wait", 0.5), ("key", b"\x1b"), ("wait", 0.3), ("key", b"?"), ("wait", 0.4),
              ("key", b"\x1b"), ("wait", 0.3), ("key", b"\x1b[B"), ("wait", 0.2), ("key", E), ("wait", 0.6), ("key", b"\x1b[6~"), ("wait", 0.4)]
    starts, raw = _pty_run(tmp_path, repo, script, size=size, raw=True)
    assert starts == 0
    plain = CSI.sub(b"", raw).decode("utf-8", "replace")
    # positive control: the hostile data was drawn, escaped and visible (otherwise the check below proves nothing)
    assert "PWNED" in plain and ("\\x1b" in plain or "\\u202e" in plain), "hostile text never reached the screen: the test is vacuous"
    assert _foreign_sequences(raw) == {"osc": 0, "other_esc": 0, "bel": 0, "c1_utf8": 0, "bidi_override": 0, "pwned_title_payload": 0,
                                        "data_clear_screen": 0, "data_red": 0}, _foreign_sequences(raw)


def test_negative_control_the_detector_sees_an_unsanitised_stream():
    raw = f"\x1b[H\x1b[2Jhello {HOSTILE}".encode()
    f = _foreign_sequences(raw)
    assert f["osc"] and f["bel"] and f["data_red"] and f["bidi_override"] and f["c1_utf8"], f
