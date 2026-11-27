"""case attack 7 (review on review's d0068dbb; regression file, included here). P1-P7, R4/W1/R6 and the converter case are GREEN on
d0068dbb; these remain:

  T1  StreamHandler.terminator set on an EXISTING handler (instance attribute) is neither seen nor restored. The design note promised
      'terminator as both a class attribute and any instance override'; only the class attribute is snapshotted.
  L1  NEW HANG (root 1770bc4e does not lock): _logging_restore acquires logging._lock with no timeout around the loggerDict restore. A
      thread the target leaves holding the real logging lock blocks changes_and_restore indefinitely (evaluator stall -> deadline).
  L2  logging._lock is read from the module AT RESTORE TIME and acquired before the try: a target that sets it to None aborts the
      restore (3.13+ has no logging._acquireLock) and leaves logging._lock = None for every later call; one that installs a lock that
      never releases hangs the restore. Fix: take the lock OBJECT into the token at watch start, restore the logging._lock global by
      identity, acquire with a timeout inside the try, and on timeout mark 'unrestorable' instead of blocking.
"""
import io
import logging
import os
import threading
import time
import types

import pytest

from hlith import differential

REAL_LOCK = logging._lock


def _watch(fn, timeout=4.0):
    mod = types.ModuleType("n2_cl2_a7")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    box = {}

    def run():
        try:
            box["out"] = w.changes_and_restore(dict(os.environ), restore=True)
        except BaseException as e:  # noqa: BLE001
            box["out"] = f"<raised {type(e).__name__}>"
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return None if t.is_alive() else box["out"]


def _untouched(n):
    return n


@pytest.fixture(autouse=True)
def _reset_lock():
    yield
    logging._lock = REAL_LOCK


def test_T1_instance_terminator_is_seen_and_restored():
    h = logging.StreamHandler(io.StringIO())
    lg = logging.getLogger("test.a7.t1")
    lg.addHandler(h)
    try:
        out = _watch(lambda n: (setattr(h, "terminator", ""), n)[1])
        assert out is not None and (out != _watch(_untouched) or "terminator" not in vars(h)), "instance terminator neither seen nor restored"
        assert "terminator" not in vars(h), "instance terminator leaked into later calls"
    finally:
        vars(h).pop("terminator", None)
        lg.removeHandler(h)


@pytest.fixture
def victim():
    logging.getLogger("test.a7.victim")
    yield
    logging.getLogger("test.a7.victim")


def test_L1_restore_does_not_hang_on_a_held_logging_lock(victim):
    release = threading.Event()

    def f(n):
        threading.Thread(target=lambda: (REAL_LOCK.acquire(), release.wait(30), REAL_LOCK.release()), daemon=True).start()
        time.sleep(0.05)
        del logging.root.manager.loggerDict["test.a7.victim"]  # forces the loggerDict restore path (no lock needed to do this)
        return n
    try:
        out = _watch(f)
        assert out is not None, "changes_and_restore blocked on logging._lock held by a thread the call left behind"
    finally:
        release.set()
        time.sleep(0.2)


def test_L2_lock_set_to_none_does_not_abort_restore_or_leak(victim):
    def f(n):
        logging._lock = None
        del logging.root.manager.loggerDict["test.a7.victim"]
        return n
    try:
        _watch(f)
        leaked, kept = logging._lock, "test.a7.victim" in logging.root.manager.loggerDict
    finally:
        logging._lock = REAL_LOCK  # before pytest's own logging plugin touches it
    assert leaked is REAL_LOCK, f"logging._lock = {leaked!r} leaked into later calls"
    assert kept, "the loggerDict restore aborted"


def test_L2_never_releasing_lock_does_not_hang_restore(victim):
    class Never:
        def acquire(self, *a, **k):
            time.sleep(30)

        def release(self):
            pass

    def f(n):
        logging._lock = Never()
        del logging.root.manager.loggerDict["test.a7.victim"]
        return n
    try:
        out = _watch(f)
    finally:
        logging._lock = REAL_LOCK
    assert out is not None, "changes_and_restore hung on a replaced logging._lock"
