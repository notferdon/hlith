"""case red tests (authored by review as a handoff file; the fixer copies it in). Root 92f4194a: _logging_cmp() records
logging.lastResort as int(level) only (differential.py ~11187-11189), and _logging_token()/_logging_restore() keep only the level
(~11209, ~11224-11225). So (1) a call that REPLACES lastResort with a distinct handler at the same level (a different destination)
leaves the change string equal: a narrow false-HELD channel (where last-resort records go); and (2) restore does not put the
original lastResort object back: it only calls setLevel on the replacement, so the replacement leaks into every later call.
Pattern follows tests/test_logging_fingerprint_gaps.py (_StateWatch.changes_and_restore)."""
import logging
import os
import types

import pytest

from hlith import differential


@pytest.fixture(autouse=True)
def _keep_last_resort():
    orig = logging.lastResort
    lvl, fmt, flt = orig.level, orig.formatter, list(orig.filters)
    yield
    logging.lastResort = orig  # so a red test cannot cascade into the next one
    orig.setLevel(lvl)
    orig.formatter = fmt
    orig.filters[:] = flt


def _watch(fn):
    mod = types.ModuleType("n2_m1o_probe")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _replace_with(path):
    def f(n):
        h = logging.FileHandler(str(path), delay=True)  # delay: nothing is opened or written
        h.setLevel(logging.lastResort.level if logging.lastResort is not None else logging.WARNING)
        logging.lastResort = h
        return n
    return f


def _untouched(n):
    return n


def test_replacing_last_resort_at_the_same_level_is_a_change(tmp_path):
    """A call that swaps logging.lastResort for a same-level handler with another destination changes where last-resort
    records go for every later call: it must show in the change string (today: identical to an untouched call)."""
    assert _watch(_replace_with(tmp_path / "a.log")) != _watch(_untouched)


def test_two_same_level_last_resort_destinations_differ(tmp_path):
    """pre swaps lastResort to a.log, post to b.log (same class, same level): the two must not compare equal."""
    assert _watch(_replace_with(tmp_path / "a.log")) != _watch(_replace_with(tmp_path / "b.log"))


def test_same_last_resort_configuration_stays_equal(tmp_path):
    """Control: an identical replacement on both sides is not a difference (no false REFUTED from object identity)."""
    assert _watch(_replace_with(tmp_path / "a.log")) == _watch(_replace_with(tmp_path / "a.log"))


def test_restore_puts_the_original_last_resort_object_back(tmp_path):
    """After a watched call, the next call must see the original lastResort, not the replacement."""
    orig = logging.lastResort
    _watch(_replace_with(tmp_path / "a.log"))
    assert logging.lastResort is orig, f"restore left {logging.lastResort!r} installed instead of {orig!r}"


def test_last_resort_set_to_none_and_back(tmp_path):
    """None <-> handler transitions stay visible (already measured today; must stay so after the fix)."""
    def f(n):
        logging.lastResort = None
        return n
    assert _watch(f) != _watch(_untouched)
    assert logging.lastResort is not None


def test_restore_after_none_puts_the_original_object_back():
    """Fault 3: a call that sets lastResort = None is detected, but restore used to skip it (an 'is not None' guard), so every
    later call in the checker process ran with no last-resort handler at all."""
    orig = logging.lastResort

    def f(n):
        logging.lastResort = None
        return n
    _watch(f)
    assert logging.lastResort is orig


def test_none_start_state_is_restored_as_none(tmp_path):
    """Start with lastResort = None (Python allows it): a call that installs a handler must be undone to None, not left installed."""
    logging.lastResort = None
    w = _watch(_replace_with(tmp_path / "a.log"))
    assert w != _watch(_untouched) and logging.lastResort is None


def test_restore_returns_original_object_state(tmp_path):
    """The original object's own level, formatter and filters come back too (a call that mutates it and then replaces it)."""
    orig = logging.lastResort
    lvl, fmt, flt = orig.level, orig.formatter, list(orig.filters)

    def f(n):
        orig.setLevel(logging.CRITICAL)
        orig.setFormatter(logging.Formatter("X %(message)s"))
        orig.addFilter(lambda r: False)
        logging.lastResort = logging.FileHandler(str(tmp_path / "z.log"), delay=True)
        return n
    _watch(f)
    assert logging.lastResort is orig and orig.level == lvl and orig.formatter is fmt and list(orig.filters) == flt


def test_in_place_mutation_of_original_still_detected_and_restored():
    """Control for the old behaviour: setLevel on the ORIGINAL object (no replacement) was and stays a visible change, restored."""
    orig = logging.lastResort
    lvl = orig.level

    def f(n):
        orig.setLevel(logging.CRITICAL)
        return n
    assert _watch(f) != _watch(_untouched)
    assert orig.level == lvl


def test_undetected_change_is_still_restored():
    """Restore is unconditional (case round 2): a replacement formatter with an IDENTICAL fingerprint is not reported, but the
    original formatter object must still come back (restore ran although nothing was detected)."""
    orig = logging.lastResort
    fmt0 = logging.Formatter("%(message)s")
    orig.setFormatter(fmt0)

    def f(n):
        orig.setFormatter(logging.Formatter("%(message)s"))
        return n
    w = _watch(f)
    assert orig.formatter is fmt0, "an undetected change was not restored"
    assert w == _watch(_untouched)


def test_failing_restore_step_does_not_skip_later_steps():
    """One hostile step (a Logger whose setLevel raises) must not stop the restore of the loggers after it."""
    a, b = logging.getLogger("n1.m1o.a"), logging.getLogger("n1.m1o.b")
    a.setLevel(logging.WARNING)
    b.setLevel(logging.WARNING)
    a.setLevel = lambda *x: 1 / 0  # instance override: restoring `a` raises

    def f(n):
        a.level = logging.DEBUG
        b.level = logging.DEBUG
        return n
    try:
        out = _watch(f)
        assert b.level == logging.WARNING, "a failing step skipped the later logger"
        assert "unrestorable" in out
    finally:
        a.__dict__.pop("setLevel", None)
        a.setLevel(logging.NOTSET)
        b.setLevel(logging.NOTSET)


def _dest_handler_cases(tmp_path=None):
    """Two NAMED file streams: a redirected buffer (StringIO) is opaque to the fingerprint (named limit), a file is compared by its name."""
    import tempfile

    d = tempfile.mkdtemp()
    return open(d + "/s0.log", "w"), open(d + "/sink.log", "w")


def test_in_place_stream_swap_on_custom_last_resort_is_seen_and_restored():
    """case round 3: a call that re-points a (non-default) lastResort's stream in place is seen (destination is compared) and the
    same object must come back pointing at the ORIGINAL stream, not stay re-pointed for every later call. (The stdlib default
    _StderrHandler has a read-only `stream` property, so this needs a StreamHandler installed as lastResort.)"""
    s0, sink = _dest_handler_cases()
    h = logging.StreamHandler(s0)
    logging.lastResort = h

    def f(n):
        h.stream = sink
        return n
    assert _watch(f) != _watch(_untouched)
    assert h.stream is s0, "the handler's stream stayed re-pointed for later calls"


def test_in_place_stream_swap_on_root_handler_is_restored():
    """Same class on an ordinary root handler (general to all handlers)."""
    s0, sink = _dest_handler_cases()
    h = logging.StreamHandler(s0)
    root = logging.getLogger()
    root.addHandler(h)
    try:
        def f(n):
            h.stream = sink
            return n
        _watch(f)
        assert h.stream is s0
    finally:
        root.removeHandler(h)


def test_in_place_base_filename_swap_is_restored(tmp_path):
    """A file handler's baseFilename changed in place is put back (the attribute only: no close, no reopen, nothing written)."""
    h = logging.FileHandler(str(tmp_path / "a.log"), delay=True)
    logging.lastResort = h
    name0 = h.baseFilename

    def f(n):
        h.baseFilename = str(tmp_path / "b.log")
        return n
    _watch(f)
    assert h.baseFilename == name0
    assert not (tmp_path / "b.log").exists() and not (tmp_path / "a.log").exists()  # nothing opened or written


def test_default_last_resort_is_not_reported_unrestorable():
    """The stdlib default's `stream` is a read-only property that already agrees: the restore must not call that a failure."""
    assert "unrestorable" not in _watch(_untouched)


def test_unsettable_destination_that_changed_is_reported_unrestorable():
    """If a destination attribute cannot be put back (a property with no setter whose value the call changed), say 'unrestorable' for
    that call instead of leaking silently."""
    import io

    cur = [open(__import__("tempfile").mkdtemp() + "/p0.log", "w")]

    class _Prop(logging.Handler):
        stream = property(lambda self: cur[0])

        def emit(self, record):
            pass

    h = _Prop()
    logging.lastResort = h
    first = cur[0]

    def f(n):
        cur[0] = open(__import__("tempfile").mkdtemp() + "/p1.log", "w")
        return n
    try:
        out = _watch(f)
        assert "unrestorable" in out
    finally:
        cur[0] = first


def test_untouched_call_writes_no_handler_attribute():
    """Round 3 (P/N): restore writes only what differs; an untouched call must not call a handler setter at all."""
    writes = []

    class _Counting(logging.Handler):
        def __setattr__(self, k, v):
            if k in ("formatter", "level", "stream"):
                writes.append(k)
            super().__setattr__(k, v)

        def emit(self, record):
            pass

    h = _Counting()
    root = logging.getLogger()
    root.addHandler(h)
    try:
        writes.clear()
        _watch(_untouched)
        assert writes == [], f"restore wrote {writes} on an untouched call"
    finally:
        root.removeHandler(h)


def test_added_root_handler_is_removed_by_restore():
    root = logging.getLogger()
    before = list(root.handlers)
    h = logging.NullHandler()

    def f(n):
        root.addHandler(h)
        return n
    try:
        assert _watch(f) != _watch(_untouched)
        assert root.handlers == before
    finally:
        if h in root.handlers:
            root.removeHandler(h)


def test_restore_after_one_changed_logger_does_not_touch_the_others(monkeypatch):
    """Cost of a CHANGING call: only the changed logger's level is written back (each Logger.setLevel clears every logger's cache, so
    writing all of them is O(loggers^2))."""
    made = []
    for i in range(300):
        lg = logging.getLogger(f"n1.m1o.many.{i:03d}")
        lg.addHandler(logging.NullHandler())
        made.append(lg)
    try:
        calls = []
        orig = logging.Manager._clear_cache
        monkeypatch.setattr(logging.Manager, "_clear_cache", lambda self: (calls.append(1), orig(self))[1])
        lg0 = made[7]

        def f(n):
            lg0.level = logging.DEBUG  # direct attribute write: no cache clear from the call itself
            return n
        _watch(f)
        assert lg0.level == logging.NOTSET
        assert len(calls) <= 3, f"{len(calls)} cache clears for one changed logger"
    finally:
        for i, lg in enumerate(made):
            for h in list(lg.handlers):
                lg.removeHandler(h)
            logging.root.manager.loggerDict.pop(f"n1.m1o.many.{i:03d}", None)


class _LiarEq(logging.Handler):
    def __eq__(self, o):
        return True

    def __hash__(self):
        return 0


def test_lying_eq_replacement_handler_is_written_back_on_every_slot():
    """case round 4: restore compares OBJECT slots by identity (an object's __eq__ is attacker-controlled): a lying-__eq__ replacement of
    lastResort and of a root handler's formatter/filters/handler list is still put back; == is for scalars only."""
    orig_lr = logging.lastResort
    root = logging.getLogger()
    h = logging.StreamHandler()
    fmt0 = logging.Formatter("%(message)s")
    h.setFormatter(fmt0)
    flt0 = logging.Filter()
    h.addFilter(flt0)
    root.addHandler(h)
    before_handlers = list(root.handlers)

    class _Fmt(logging.Formatter):
        def __eq__(self, o):
            return True

        def __hash__(self):
            return 0

    class _Flt(logging.Filter):
        def __eq__(self, o):
            return True

        def __hash__(self):
            return 0

    def f(n):
        logging.lastResort = _LiarEq(orig_lr.level)
        h.setFormatter(_Fmt("%(message)s"))
        h.filters[:] = [_Flt()]
        root.handlers[:] = [_LiarEq() for _ in root.handlers]  # same length: only identity tells them apart
        return n
    try:
        _watch(f)
        assert logging.lastResort is orig_lr
        assert h.formatter is fmt0 and h.filters == [flt0]
        assert root.handlers == before_handlers and all(x is y for x, y in zip(root.handlers, before_handlers))
    finally:
        root.removeHandler(h)


def test_lying_eq_filter_elements_are_written_back():
    """case round 5: the restore fast path must not trust a filter's own __eq__ either (no == on objects anywhere in restore)."""
    class _LyingFilter(logging.Filter):
        def __eq__(self, o):
            return True

        def __hash__(self):
            return 0

    h = logging.StreamHandler()
    f0 = logging.Filter()
    h.addFilter(f0)
    root = logging.getLogger()
    root.addHandler(h)
    try:
        def f(n):
            h.filters[:] = [_LyingFilter()]  # same length, equal by its own __eq__
            return n
        _watch(f)
        assert len(h.filters) == 1 and h.filters[0] is f0
    finally:
        root.removeHandler(h)


def test_stream_name_str_subclass_with_lying_eq_is_reported(tmp_path):
    """case round 6 (b): a stream whose .name is a str subclass with a lying __eq__ must not compare equal to a plain name."""
    class _Name(str):
        def __eq__(self, o):
            return True

        def __hash__(self):
            return 0

    s0 = open(tmp_path / "a.log", "w")

    class _S:
        name = _Name(str(tmp_path / "a.log"))

        def write(self, x):
            pass

        def flush(self):
            pass

    h = logging.StreamHandler(s0)
    root = logging.getLogger()
    root.addHandler(h)
    try:
        def f(n):
            h.stream = _S()
            return n
        assert _watch(f) != _watch(_untouched)
    finally:
        root.removeHandler(h)
        h.stream = s0
