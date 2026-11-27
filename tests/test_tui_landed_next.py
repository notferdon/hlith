# SPDX-License-Identifier: Apache-2.0
"""TUI behavior 2.2 (D1): the LANDED verdict must say what happened to the OPERATOR'S repository, from the recorded landing_target only."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from hlith.operator.tui import frame

ROOT = Path(__file__).resolve().parent.parent
LANDED = ROOT / "tests/fixtures/landed_format2_between.json"  # a REAL format-2 LANDED artifact (review closure run, default pipeline route)
SHA = "bd7e35efe564acb5a2a4375607e1a0a4d11317d1"


def _art(target):
    a = copy.deepcopy(json.loads(LANDED.read_text()))
    assert a["landed_commit"] == SHA and a["format"] == 2
    a["run"]["landing_target"] = target
    if target is None:
        a["run"].pop("landing_target")
    return a


def test_a_rehearsal_landing_says_the_repository_was_not_changed_and_where_the_change_is():
    text = frame._landed_next(_art("rehearsal"), {"launch_meta": {"clone": "/home/u/.local/state/hlith/runs/launch-abc/clone"}})
    assert "Your repository was NOT changed" in text and "rehearsal" in text and SHA[:8] in text
    assert "/runs/launch-abc/change.patch" in text and "Press l to review applying it to your repository" in text  # D1 Apply exists (2.3) and replaces 'apply it yourself'
    assert "committed the checked change to your repository" not in text


def test_a_rehearsal_landing_without_launch_meta_still_says_not_changed_and_invents_no_path():
    text = frame._landed_next(_art("rehearsal"), None)
    assert "Your repository was NOT changed" in text and "change.patch" not in text and "Run clone" not in text


def test_an_original_landing_says_so_and_never_says_not_changed():
    text = frame._landed_next(_art("original"), None)
    assert "committed the checked change to your repository" in text and f"commit {SHA[:8]}" in text and "ONE new commit on your current branch" in text
    assert f"git show {SHA[:8]}" in text and "does not offer an undo" in text and "your own git action" in text and "NOT changed" not in text


def test_an_unrecorded_target_claims_nothing():
    text = frame._landed_next(_art(None), None)
    assert "not recorded in this receipt" in text and "do not assume your repository was changed" in text
    assert "NOT changed" not in text and "committing the checked change" not in text


def test_a_hostile_clone_path_is_escaped():
    text = frame._landed_next(_art("rehearsal"), {"launch_meta": {"clone": "/x/\x1b[31mred\x1b]0;t\x07/clone"}})
    assert "\x1b" not in text and "\x07" not in text


def test_the_repository_statement_leads_the_text(  # the NEXT pane truncates with "more": the operator-critical sentence must come first
):
    assert frame._landed_next(_art("rehearsal"), None).startswith("Your repository was NOT changed")
    assert frame._landed_next(_art(None), None).startswith("The landing target is not recorded")


def test_the_exact_frame_of_an_original_landing_shows_the_next_text(tmp_path):
    """The real renderer (tall terminal so the NEXT pane is on screen): what the operator reads after Apply landed."""
    from dataclasses import replace

    from hlith.operator.tui import host

    art = _art("original")
    host_state = replace(host.ViewState(st="verdict"), cols=100, rows=70)
    text = " ".join(" ".join(ln.split("\u2502", 1)[1] for ln in host._render(host_state, art, host._artifact_context(art), "plain").splitlines() if "\u2502" in ln).split())
    assert "NEXT" in text and "committed the checked change to your repository" in text and "ONE new commit" in text and "does not offer an undo" in text
