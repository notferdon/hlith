# SPDX-License-Identifier: Apache-2.0
"""case (review): RED test-only. With package-lock.json excluded the Claim still shows the excluded file's lines and the whole change's counts (measured on 373d0dc5 / d633d0a7)."""

from __future__ import annotations

import pty

import pytest

from test_tui_claim_pgdn import E, PGDN, _make_repo, _pty_run

D, TAB, SP = b"\x1b[B", b"\t", b" "


def _claim_text(tmp_path, exclude_lock):
    repo = _make_repo(tmp_path)
    (repo / "a.py").write_text("a=9\n")
    (repo / "b.py").write_text("b=1\n")
    (repo / "package-lock.json").write_text('{"lock": 1}\n')
    keys = [("key", E), ("wait", 0.8), ("key", TAB), ("wait", 0.4)]
    if exclude_lock:
        keys += [("key", D), ("wait", 0.15), ("key", D), ("wait", 0.15), ("key", SP), ("wait", 0.4)]
    keys += [("key", E), ("wait", 1.0)]
    starts, text = _pty_run(tmp_path, repo, keys, (30, 100), screen=True)
    assert starts == 0
    return text


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_RED_claim_with_the_lockfile_excluded_does_not_show_its_lines_or_count_them(tmp_path):
    """Scope row says '2 of 3 files · +3 −1' (the whole change's counts) and the CHANGE pane lists '+ {"lock": 1}' although Files (2) and the claimed patch exclude
    package-lock.json: what is shown as claimed must be exactly what is claimed."""
    text = _claim_text(tmp_path, True)
    flat = " ".join(text.split())  # the exclusion sentence wraps across rows
    assert "2 of 3 files" in flat and "excluded" in flat and "package-lock.json" in flat, "precondition: the Claim names the exclusion"
    scope = next(ln for ln in text.splitlines() if "base " in ln and "patch " in ln)
    assert "+3" not in scope, "the scope row counts the excluded file: " + scope.strip()
    assert '{"lock"' not in text, "the excluded file's added line is shown in the Claim CHANGE pane"


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_control_claim_with_nothing_excluded_shows_all_three_files(tmp_path):
    text = _claim_text(tmp_path, False)
    assert '{"lock"' in text and "+3" in text
