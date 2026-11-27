# SPDX-License-Identifier: Apache-2.0
"""case (review): RED test-only. An open overlay (help ?, agent A, quit q) must take every key first; measured on 554765e1: Enter and PgDn reach the screen BEHIND it."""

from __future__ import annotations

import pty

import pytest

from test_tui_claim_pgdn import E, OPEN_CLAIM_C3, PGDN, _make_repo, _pty_run

ESC = b"\x1b"
PG = [x for _ in range(3) for x in (("key", PGDN), ("wait", 0.5))]


def _run(tmp_path, script):
    return _pty_run(tmp_path, _make_repo(tmp_path), script, (30, 100), screen=True)


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("opener", [b"?", b"q"], ids=["help", "quit"])
def test_RED_paging_the_claim_under_an_open_overlay_does_not_count_as_reviewing_the_command(tmp_path, opener):
    """Claim, open the overlay, PgDn x3 (the keys reach the Claim behind it), Esc, wait the dwell, Enter: a run STARTS although the operator never paged the
    command with the Claim in view. Keys must go to the overlay first, so the same sequence must start nothing."""
    starts, _ = _run(tmp_path, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", opener), ("wait", 0.4), *PG, ("key", ESC), ("wait", 0.9), ("key", E), ("wait", 0.8)])
    assert starts == 0, "paging under an overlay satisfied the command-review gate"


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_control_paging_without_an_overlay_then_enter_starts_once(tmp_path):
    starts, _ = _run(tmp_path, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", b"c"), ("wait", 0.5), *PG, ("key", ESC), ("wait", 0.9), ("key", E), ("wait", 0.8)])  # case: review the command on its own page, esc back, dwell, Enter
    assert starts == 1


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("opener,name", [(b"?", "help"), (b"A", "agent")])
def test_RED_enter_inside_an_overlay_on_the_selection_does_not_advance_to_the_claim(tmp_path, opener, name):
    """Selection, open the overlay, Enter: the Selection behind it advances to CLAIM while the overlay stays painted."""
    starts, text = _run(tmp_path, [("key", E), ("wait", 0.8), ("key", opener), ("wait", 0.5), ("key", E), ("wait", 0.8)])
    assert starts == 0
    assert "CLAIM ·" not in text, f"Enter in the {name} overlay advanced the screen behind it to the Claim"
