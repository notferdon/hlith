# SPDX-License-Identifier: Apache-2.0
"""case (review): keyboard / footer / Esc discoverability. Test-only, one RED per defect (measured on root 9f0ab22d and review tip b22c8d3f).

GREEN controls pin what already works (every advertised footer key changes the screen on Offer/Selection/Claim/diff/history, Esc leaves the
boundary-blocked screen). j/k are already down/up (reduce.py), '/' is unbound: nothing replaced."""

from __future__ import annotations

import pty
from dataclasses import replace

import pytest

from hlith.operator.tui import keys, model, reduce
from test_tui_claim_pgdn import E, OPEN_CLAIM_C3, PGDN, _make_repo, _pty_run

SEL = [("key", E), ("wait", 0.6)]


def _vs(**kw):
    return model.ViewState(**{"st": "selection", "focusIndex": 0, "included": True, "cols": 100, "rows": 30, **kw})


# ---- RED 1: the Space key advertised as 'space include file' is dead
def test_RED_a_literal_space_is_the_space_action():
    """keys.action_for maps '\\r' '\\n' '\\t' '\\x1b' but a literal ' ' falls through to 'key: ', which reduce never matches (it tests == 'space')."""
    assert keys.action_for(_vs(), " ") == "key:space"


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_RED_space_in_selection_toggles_the_file_as_the_footer_promises(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "a.py").write_text("a=9\n")  # uncommitted work: source 0 with '[x] a.py'
    _s, before = _pty_run(tmp_path, repo, [*SEL], (30, 100), screen=True)
    assert "[x] a.py" in before and "space include" in before  # A: 'space include file'; B rail: 'space include source'
    again = tmp_path / "again"
    again.mkdir()
    repo2 = _make_repo(again)
    (repo2 / "a.py").write_text("a=9\n")
    _s, after = _pty_run(again, repo2, [*SEL, ("key", b" "), ("wait", 0.6)], (30, 100), screen=True)
    assert "[ ] a.py" in after, after[:600]


def test_control_reduce_space_toggles_when_it_is_the_space_action():
    vs = _vs()
    after = reduce.reduce(vs, "key:space")
    assert after.included is False if not hasattr(after, "excluded_sources") else 0 in after.excluded_sources  # A: global flag; B: per-source set


# ---- RED 2: Enter under a drill moves the screen BEHIND it
def test_RED_enter_on_the_diff_page_does_not_advance_the_screen_behind_it():
    """Selection + 'd' + Enter: the diff page stays, but the state underneath silently goes selection -> claim, so Esc then lands on Claim
    (a screen the operator never opened) instead of the Selection the diff came from."""
    vs = reduce.reduce(_vs(), "key:d")
    assert vs.drill == "diff"
    after = reduce.reduce(vs, "key:enter")
    assert after.st == "selection", after.st


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_RED_esc_after_enter_on_the_diff_page_returns_to_the_selection(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "a.py").write_text("a=9\n")
    starts, text = _pty_run(tmp_path, repo, [("key", E), ("until", b"review this change"), ("key", b"d"), ("until", b"DIFF"), ("key", E), ("wait", 0.3), ("key", b"\x1b"), ("until", b"review this change"), ("wait", 0.3)], (30, 100), screen=True)
    assert starts == 0  # fresh-bytes markers instead of fixed sleeps (flaked on a busy machine)
    assert ("SELECT A CHANGE" in text or "enter review this change" in text) and "CLAIM ·" not in text, text[:300]  # A heading or the B Selection footer


# ---- RED 3: the Claim footer before the command end promises Enter and hides the key that makes it work
@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_RED_claim_footer_names_pgdn_while_the_command_is_not_reviewed(tmp_path):
    """Per the Claim ruling: 'add pgdn scroll command only while the command is not yet reviewed'. Measured: the footer is
    'enter run independent check   d diff   tab move   esc back' (Enter is refused, PgDn is not named; only the body banner says pgdn)."""
    repo = _make_repo(tmp_path)
    _s, text = _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9)], (30, 100), screen=True)
    footer = [ln for ln in text.splitlines() if ln.strip()][-1]
    assert "review command" in footer.lower(), footer  # case: the unreviewed claim's primary key opens the command-review step


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_control_claim_footer_after_the_end_does_not_need_pgdn(tmp_path):
    repo = _make_repo(tmp_path)
    s, text = _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", b"c"), ("wait", 0.5), ("key", PGDN), ("wait", 0.5), ("key", PGDN), ("wait", 0.5), ("key", b"\x1b"), ("wait", 0.9)], (30, 100), screen=True)
    assert s == 0 and "enter how to run this check" in [ln for ln in text.splitlines() if ln.strip()][-1]  # Hlith Review: the Claim starts no check


# ---- GREEN controls: the advertised keys that work
@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("pre,key,expect", [
    ([], b"s", "enter review this change"),    # Offer: 's other sources' (the Selection footer; the A heading 'SELECT A CHANGE' is gone in B)
    ([*SEL], b"d", "DIFF ·"),                 # Selection: 'd full diff'
    ([*SEL], b"A", "AGENT"),                  # Selection: 'A agent command'
    ([*SEL], b"\x1b", "review change"),       # Selection: 'esc back' (Offer: A heading or B footer/button)
    ([], b"?", "KEYS"),                       # '? keys'
])
def test_control_advertised_key_changes_the_screen(tmp_path, pre, key, expect):
    repo = _make_repo(tmp_path)
    (repo / "a.py").write_text("a=9\n")
    _s, text = _pty_run(tmp_path, repo, [*pre, ("key", key), ("wait", 0.8)], (30, 100), screen=True)
    assert expect.lower() in text.lower(), text[:300]
