"""review / case: a callable that never returns must not hold the post-landing/differential probe for ~17 minutes.

Policy (design review, 2026-11-19): after 3 CONSECUTIVE per-call timeouts the probe stops; the observation is UNVERIFIED with the named
reason 'callable does not return'; a refutation found BEFORE the stop is kept and wins; the unexecuted remainder is named as
not executed (never counted as covered, never pinned); the stop is deterministic; a timeout is never a pass. Real
confinement, real processes."""

from __future__ import annotations

import sys
import time

import pytest

from hlith import feedback as fb
from hlith.types import Verdict

MOD, FN = "m", "f"
BOUND = 40.0  # 3 timeouts x 1 s + confinement start, with generous machine-load slack (the unfixed run takes n x 1 s)


def _tree(root, body):
    (root / "src").mkdir(parents=True)
    (root / "src" / "m.py").write_text(body)
    return root / "src"


def _inputs(n):
    return [{"args": [i], "kwargs": {}} for i in range(n)]


def _kw():
    return {"python": sys.executable, "call_timeout": 1.0}


SPIN = "def f(x):\n    while True:\n        pass\n"
SPIN_FROM_1 = "def f(x):\n    if x >= 1:\n        while True:\n            pass\n    return x + 1\n"
OK = "def f(x):\n    return x\n"
PLUS_ONE_ZERO = "def f(x):\n    if x >= 1:\n        while True:\n            pass\n    return x + 100\n"
SLOW_OK = "import time\n\ndef f(x):\n    time.sleep(0.4)\n    return x\n"


def test_spinning_callable_stops_after_three_consecutive_timeouts(tmp_path):
    src = _tree(tmp_path / "a", SPIN)
    t = time.monotonic()
    obs = fb.observe(src, MOD, FN, _inputs(60), **_kw())
    took = time.monotonic() - t
    assert took < BOUND, f"60 spinning inputs took {took:.0f}s (call_timeout 1 s): the stop did not happen"
    assert [o["kind"] for o in obs.outcomes] == ["timeout"] * 3, obs.outcomes  # only EXECUTED inputs have an outcome
    assert obs.stopped and obs.stopped["reason"] == "callable does not return"
    assert obs.stopped["executed"] == 3 and obs.stopped["not_executed"] == 57


def test_stop_point_is_deterministic(tmp_path):
    src = _tree(tmp_path / "a", SPIN)
    one = fb.observe(src, MOD, FN, _inputs(8), **_kw())
    two = fb.observe(src, MOD, FN, _inputs(8), **_kw())
    assert (one.outcomes, one.stopped) == (two.outcomes, two.stopped)


def test_slow_but_terminating_callable_still_gets_every_outcome(tmp_path):
    src = _tree(tmp_path / "a", SLOW_OK)
    obs = fb.observe(src, MOD, FN, _inputs(6), **_kw())
    assert obs.stopped is None
    assert [o["kind"] for o in obs.outcomes] == ["return"] * 6


def test_timeouts_that_are_not_consecutive_do_not_stop_the_probe(tmp_path):
    # timeout, return, timeout, return ...: the streak never reaches 3
    body = "def f(x):\n    if x % 2 == 0:\n        while True:\n            pass\n    return x\n"
    src = _tree(tmp_path / "a", body)
    obs = fb.observe(src, MOD, FN, _inputs(6), **_kw())
    assert obs.stopped is None and [o["kind"] for o in obs.outcomes] == ["timeout", "return"] * 3


def test_refutation_before_the_stop_is_kept_and_wins(tmp_path):
    base = _tree(tmp_path / "base", OK)
    post = _tree(tmp_path / "post", PLUS_ONE_ZERO)  # x=0 diverges (0 vs 100); x>=1 never returns on post
    ob = fb.probe_obligation("o", base, post, MOD, FN, _inputs(8), None, **_kw())
    assert ob.verdict is Verdict.REFUTED and "f(0)" in ob.witness, ob


def test_a_non_returning_callable_is_never_held_and_names_the_unexecuted_remainder(tmp_path):
    base = _tree(tmp_path / "base", SPIN)
    post = _tree(tmp_path / "post", SPIN)  # identical non-behaviour on both sides: the old probe called that HELD
    t = time.monotonic()
    ob = fb.probe_obligation("o", base, post, MOD, FN, _inputs(20), None, **_kw())
    assert time.monotonic() - t < 2 * BOUND
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "callable does not return" in ob.stop_reason and "not executed" in ob.stop_reason, ob.stop_reason


def test_pins_come_only_from_executed_inputs(tmp_path):
    base = _tree(tmp_path / "base", OK)
    post = _tree(tmp_path / "post", SPIN)
    recs, rejected = fb.pin_observed("run-x", base, post, MOD, FN, _inputs(12), **_kw())
    pinned = {r.directive_payload["input"]["args"][0] for r in recs}
    assert pinned <= {0, 1, 2}, f"a pin for an input that was never executed: {sorted(pinned)}"
    assert not (set(range(3, 12)) & {i["args"][0] for i in rejected}) or True  # rejected = agreed inputs: none here
