# SPDX-License-Identifier: Apache-2.0
"""gate-overlay-review: while ANY overlay is open it takes every key; nothing reaches the screen behind it."""

from __future__ import annotations

from dataclasses import replace

import pytest

from hlith.operator.tui import reduce
from hlith.operator.tui.model import ViewState

KEYS = ["key:pgdn", "key:pgup", "key:down", "key:up", "key:tab", "key:d", "key:w", "key:p", "key:u", "key:space", "key:s", "key:h", "key:a", "key:enter"]


@pytest.mark.parametrize("st", ["offer", "selection", "claim", "verdict", "history", "blocked", "running"])
@pytest.mark.parametrize("overlay", ["help", "agent", "exit", "quit", "cancel"])
def test_no_key_reaches_the_screen_behind_an_open_overlay(st, overlay):
    base = ViewState(st=st, cols=100, rows=30, overlay=overlay, scroll=3, focusIndex=0, obl_count=3, file_count=2, included=(0,))
    for key in KEYS:
        out = reduce.reduce(base, key)
        assert out.st == st, (st, overlay, key)
        assert out.scroll == base.scroll, (st, overlay, key)
        assert out.drill is None and out.selectedIndex is None, (st, overlay, key)
        assert out.excluded_sources == base.excluded_sources and out.excluded_files == base.excluded_files, (st, overlay, key)


@pytest.mark.parametrize("st", ["selection", "claim"])
def test_enter_in_help_or_agent_closes_only_the_overlay(st):
    for overlay in ("help", "agent"):
        out = reduce.reduce(ViewState(st=st, cols=100, rows=30, overlay=overlay, included=(0,)), "key:enter")
        assert out.overlay is None and out.st == st


def test_controls_without_an_overlay_paging_and_enter_still_work():
    assert reduce.reduce(ViewState(st="claim", cols=100, rows=30), "key:pgdn").scroll > 0
    assert reduce.reduce(ViewState(st="offer", cols=100, rows=30), "key:enter").st == "selection"
