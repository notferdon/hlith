"""review / case @4929b906: Enter on the Claim DIFF page, and the three colour modes, through the real host under a pty."""

from __future__ import annotations

import re

import pytest

from test_tui_claim_pgdn import E, PGDN, _pty_run, _make_repo  # noqa: E402

DOWN = b"\x1b[B"
TO_CLAIM = [("key", E), ("wait", 0.5), ("key", DOWN), ("wait", 0.1), ("key", E), ("wait", 0.6)]


@pytest.fixture()
def repo(tmp_path):
    return _make_repo(tmp_path)


def W(t):
    return ("wait", t)


def K(k):
    return ("key", k)


REVIEW = [K(E), W(0.8)]                       # Enter on [ Review command ] opens the command page
P3 = [x for _ in range(3) for x in (K(PGDN), W(0.5))]
ESC = K(b"\x1b")


def test_control_full_flow_review_end_dwell_esc_enter_starts_once(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + P3 + [W(1.0), ESC, W(0.8), K(E), W(1.0)]) == 1


def test_enter_on_claim_before_review_only_opens_the_review_page(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + [K(E), W(0.8), K(E), W(0.8), K(E), W(0.8)]) == 0


def test_enter_on_review_page_at_the_end_marker_does_not_start(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + P3 + [W(1.0)] + [x for _ in range(4) for x in (K(E), W(0.6))]) == 0


def test_esc_before_the_end_marker_does_not_earn_the_review(tmp_path, repo):
    # Precondition asserted on the SCREEN (not on a fixed PgDn count, which depends on the page length): the command page has
    # been opened and END OF COMMAND is NOT visible. Only then is "Esc, Enter, Esc, Enter -> 0 starts" a statement about the gate.
    starts, screen = _pty_run(tmp_path, repo, TO_CLAIM + REVIEW, screen=True)
    assert starts == 0 and "END OF COMMAND" not in screen, screen
    sub = tmp_path / "second"
    sub.mkdir()
    from test_tui_claim_pgdn import _make_repo as _mk

    assert _pty_run(sub, _mk(sub), TO_CLAIM + REVIEW + [ESC, W(0.8), K(E), W(0.8), ESC, W(0.8), K(E), W(0.8)]) == 0


def test_scrolling_until_the_end_marker_is_on_screen_legitimately_earns_the_review(tmp_path, repo):
    # The page length depends on the (tmp) path length in the command: one PgDn may or may not reach END OF COMMAND, so scroll
    # until the SCREEN shows it (extra PgDn past the end are harmless), dwell, then Esc + Enter starts exactly once.
    starts, screen = _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + [x for _ in range(8) for x in (K(PGDN), W(0.3))] + [W(1.0)], screen=True)
    assert "END OF COMMAND" in screen
    sub = tmp_path / "second"
    sub.mkdir()
    from test_tui_claim_pgdn import _make_repo as _mk

    assert _pty_run(sub, _mk(sub), TO_CLAIM + REVIEW + [x for _ in range(8) for x in (K(PGDN), W(0.3))] + [W(1.0), ESC, W(0.8), K(E), W(1.0)]) == 1


def test_esc_then_enter_in_the_same_write_right_after_the_end_never_starts_before_dwell(tmp_path, repo):
    # end reached, then ESC+Enter arrive as one burst (no dwell): must not start from a single typed burst
    assert _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + P3 + [K(b"\x1b\r"), W(1.0)]) == 0


def test_enter_on_claim_diff_page_before_review_never_starts(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + [K(b"d"), W(0.5)] + [x for _ in range(4) for x in (K(E), W(0.8))]) == 0


def test_diff_page_visit_does_not_count_as_command_review(tmp_path, repo):
    # d, Enter (diff), PgDn x4 (diff), Esc back to Claim, wait, Enter: still unreviewed -> only the review page, no start
    assert _pty_run(tmp_path, repo, TO_CLAIM + [K(b"d"), W(0.5), K(E), W(0.6)] + [x for _ in range(4) for x in (K(PGDN), W(0.4))] + [ESC, W(1.0), K(E), W(1.0)]) == 0


def test_enter_on_diff_page_after_review_does_not_start(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + P3 + [W(1.0), ESC, W(0.8), K(b"d"), W(0.6), K(E), W(1.0), K(E), W(1.0)]) == 0


def test_enter_on_diff_page_after_review_then_back_still_needs_one_enter(tmp_path, repo):
    assert _pty_run(tmp_path, repo, TO_CLAIM + REVIEW + P3 + [W(1.0), ESC, W(0.8), K(b"d"), W(0.6), K(E), W(0.8), ESC, W(0.8), K(E), W(1.0)]) == 1


SGR_COLOR = re.compile(rb"\x1b\[[0-9;]*(?<![0-9])(?:38|48)[;:][0-9;:]*m|\x1b\[(?:3[0-7]|4[0-7]|9[0-7]|10[0-7])(?:;[0-9]+)*m")
SGR_FIXED = re.compile(rb"\x1b\[[0-9;]*(?<![0-9])(?:38|48)[;:][0-9;:]*m|\x1b\[(?:[0-9;]*;)?(?:4[0-7]|90|9[2-7]|10[0-7])(?:;[0-9]+)*m")  # fixed rgb/256, any background, bright slots


@pytest.mark.parametrize("mode,env,expect_color", [("native", {"HLITH_UI_PALETTE": "native"}, False), ("NO_COLOR", {"NO_COLOR": "1"}, False), ("dark", {"HLITH_UI_PALETTE": "dark"}, True)])
def test_colour_modes_are_distinct_and_native_has_no_fixed_colours(tmp_path, repo, monkeypatch, mode, env, expect_color):
    for k in ("NO_COLOR", "HLITH_UI_PALETTE", "HLITH_UI_MONO"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    starts, raw = _pty_run(tmp_path, repo, TO_CLAIM + [("key", PGDN), ("wait", 0.4)], raw=True, keep_no_color=(mode == "NO_COLOR"))
    assert starts == 0
    colours = SGR_COLOR.findall(raw)
    if mode == "native":
        # TUI behavior (maintainer lock 2026-11-19): native now carries restrained semantic hue from the terminal's OWN palette slots (31/32/33/36 only);
        # it still has NO fixed rgb/256 value, NO background and NO bright slot. HLITH_UI_COLOR=0 is the zero-hue opt-out (tests/test_tui_native_semantic_theme.py).
        assert not SGR_FIXED.findall(raw), (mode, SGR_FIXED.findall(raw)[:5])
    else:
        assert bool(colours) == expect_color, (mode, colours[:5])
    if mode == "native":
        assert b"\x1b[7m" in raw or b"\x1b[1m" in raw or b";7m" in raw or b";1m" in raw, "native mode must still mark roles by reverse/bold"
