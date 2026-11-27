# SPDX-License-Identifier: Apache-2.0
"""case (review): RED test-only. The 'RUN COULD NOT BE FOLLOWED' screen advertises 'esc home' and a [ Back ] esc button, but Esc does nothing."""

from __future__ import annotations

import pty

import pytest

from test_tui_claim_pgdn import E, OPEN_CLAIM_C3, PGDN, REVIEW, _make_repo, _pty_run

_RUN = [*OPEN_CLAIM_C3, ("wait", 0.9), *REVIEW, ("key", E), ("wait", 0.8)]  # case: review the command on its own page first


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_RED_esc_leaves_the_run_could_not_be_followed_screen(tmp_path):
    """Fake start whose status is 'unknown' -> blocked kind 'run'. Footer says 'esc home'; measured on 7264616d: still 'RUN COULD NOT BE FOLLOWED' after 1.5 s."""
    starts, text = _pty_run(tmp_path, _make_repo(tmp_path), [*_RUN, ("key", b"\x1b"), ("wait", 1.5)], (30, 100), screen=True, ready="ready")
    assert starts == 1
    assert "RUN COULD NOT BE FOLLOWED" not in text and ("CHANGE TO REVIEW" in text or "Review change" in text), text[:400]


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_negative_control_esc_leaves_the_boundary_blocked_screen(tmp_path):
    starts, text = _pty_run(tmp_path, _make_repo(tmp_path), [*_RUN, ("key", b"\x1b"), ("wait", 1.0)], (30, 100), screen=True, ready="unavailable")
    assert starts == 0 and ("CHANGE TO REVIEW" in text or "Review change" in text), text[:300]


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("keys", [[b"r"], [b"r", b"\r", b"\r", b"\r"], [b"\t"], [b"\r"] * 10])
def test_run_state_keys_never_start_a_second_run(tmp_path, keys):
    script = [*_RUN] + [x for k in keys for x in (("key", k), ("wait", 0.05))] + [("wait", 0.8)]
    starts, text = _pty_run(tmp_path, _make_repo(tmp_path), script, (30, 100), screen=True, ready="ready")
    assert starts == 1
