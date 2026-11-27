# SPDX-License-Identifier: Apache-2.0
"""Logging configuration is preservation, not just the root level and the handler list identity.

``logging.getLogger("app").setLevel(...)`` and ``handler.setLevel(...)`` on a handler already
attached to the root leave ``root.level`` and the handler list unchanged. The watch used to
report nothing, so a preservation check can agree while later log records are filtered
differently. ``root.setLevel`` is the negative control: that write was already visible.

The confined differential is skipped where landlock_create_ruleset returns ENOSYS. A skip is
not a pass and not an observation of HELD.
"""
from __future__ import annotations

import ctypes
import logging
import os
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict


def _landlock_absent() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    n = libc.syscall(444, 0, 0, 0)
    return n < 0 and ctypes.get_errno() == 38


_SKIP_LANDLOCK = pytest.mark.skipif(
    _landlock_absent(),
    reason="Landlock syscall 444 returned ENOSYS (errno 38). Confined differential was not run. "
           "This skip is not a pass and not an observation of HELD.",
)


@pytest.fixture
def _quiet_log():
    root = logging.getLogger()
    name = "hlith.probe.round2"
    before = root.manager.loggerDict.get(name)
    level = root.level
    handlers = list(root.handlers)
    hlevels = [(h, h.level) for h in handlers]
    try:
        yield name
    finally:
        root.setLevel(level)
        root.handlers[:] = handlers
        for h, lv in hlevels:
            h.setLevel(lv)
        if before is None:
            root.manager.loggerDict.pop(name, None)
        else:
            root.manager.loggerDict[name] = before


def _watch(fn):
    import types
    mod = types.ModuleType("hlith_probe_log")
    mod.f = fn
    env = dict(os.environ)
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(env, restore=True)


def test_named_logger_level_is_reported_and_restored(_quiet_log):
    name = _quiet_log

    def f(n):
        logging.getLogger(name).setLevel(logging.CRITICAL)
        return n * 2

    seen = _watch(f)
    assert f"logging logger {name}" in seen, seen
    assert "50" in seen, seen
    # the logger did not exist before the watch: restore must remove it, not leave CRITICAL behind
    assert name not in logging.getLogger().manager.loggerDict


def test_root_setlevel_remains_visible(_quiet_log):
    def f(n):
        logging.getLogger().setLevel(logging.ERROR)
        return n * 2

    seen = _watch(f)
    assert "logging root level/handlers changed" in seen, seen


def test_existing_root_handler_setlevel_is_reported(_quiet_log):
    handler = logging.NullHandler()
    logging.getLogger().addHandler(handler)
    try:
        def f(n, h=handler):
            h.setLevel(logging.CRITICAL)
            return n * 2

        seen = _watch(f)
        assert "logging root level/handlers changed" in seen, seen
        assert "50" in seen, seen
        assert handler.level == logging.NOTSET  # restored with the handler
    finally:
        logging.getLogger().removeHandler(handler)


def test_untouched_logging_is_not_a_difference(_quiet_log):
    def f(n):
        return 2 * n

    seen = _watch(f)
    assert "logging" not in seen, seen


def test_repeat_call_reports_the_same_logger_line(_quiet_log):
    name = _quiet_log

    def f(n):
        logging.getLogger(name).setLevel(logging.ERROR)
        return n * 2

    import types
    mod = types.ModuleType("hlith_probe_log_rep")
    mod.f = f
    env = dict(os.environ)
    w = differential._StateWatch(mod, f, None, None)
    f(2)
    first = w.changes_and_restore(env, restore=True)
    f(2)
    second = w.changes_and_restore(env, restore=True)
    assert first == second and f"logging logger {name}" in first, (first, second)


def test_logger_difference_is_not_covered_by_a_returns_delta():
    pre = {"k": "ret", "r": "4", "g": "", "w": ""}
    post = {"k": "ret", "r": "4", "g": "logging logger app: ('app', 'logger', 50, False, True, ())", "w": ""}
    assert not differential._same(pre, post)
    delta = {"type": "expr", "param": "n", "expr": "n > 0",
             "expected": {"kind": "returns", "value_repr": "4"}}
    assert differential._delta_covers(delta, [2], {}, ["n"], post, pre) is False


def _trees(tmp_path: Path, post_body: str):
    base = "def f(n: int) -> int:\n    return n * 2\n"
    test = "from pkg.m import f\n\n\ndef test_f():\n    assert f(2) == 4\n    assert f(12) == 13\n"
    for side, body in (("base", base), ("post", post_body)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(test)
    (tmp_path / "proposer").mkdir()


@_SKIP_LANDLOCK
def test_named_logger_level_is_refuted_when_confined(tmp_path):
    # Fused into the return so the statement is live (ablating it changes the return). A separate
    # setLevel statement is invisible to the old watch and can be classified dead (UNVERIFIED), which
    # is not this hole. The hole is agreement on the return while the logger level changed.
    post = ("import logging\n\n\ndef f(n: int) -> int:\n"
            "    return (n * 2, logging.getLogger('app').setLevel(logging.CRITICAL))[0]\n")
    _trees(tmp_path, post)
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), adequacy_gate=True)
    assert ob.verdict is Verdict.REFUTED and "logging logger" in (ob.witness or ""), (ob.verdict, ob.witness)


@_SKIP_LANDLOCK
def test_equivalent_return_without_logging_is_not_refuted(tmp_path):
    _trees(tmp_path, "def f(n: int) -> int:\n    return 2 * n\n")
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), adequacy_gate=True)
    assert ob.verdict is not Verdict.REFUTED, ob.witness
