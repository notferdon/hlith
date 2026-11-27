"""case REGRESSION (merged in root ea1c3127 / 4ab5c1c8; review red, regression: included here). Found by maintainer/review at the fingerprint
level, reproduced end-to-end by review.

Pre-cl2 (1770bc4e) fingerprinted a handler method by its code AND the values that code reads (_logging_callable_fp -> _atexit_fn_ident:
referenced globals, defaults, closure cells). cl2's _logging_attr_id keeps only identities (id(value), id(fn), id(code), code). So a call that
mutates a VALUE a pre-existing handler's emit reads (another module's global list, a mutable default, a closure cell) changes behaviour
(every later record is dropped) and is no longer reported: the change string stays '' -> base and patched sides agree -> false HELD.
Fix direction: keep the identity record AND fold the bounded value fingerprint back in for Python functions (the existing
_logging_callable_fp / _atexit_fn_ident over code + referenced globals + defaults/kwdefaults + closure cell contents), never name-only for
non-stdlib functions; only cache class results whose tags are value-independent (stdfn/builtin/stdcls/none), as 1770bc4e did.
"""
import importlib
import logging
import os
import sys
import types

import pytest

from hlith import differential

HELPER = '''import logging
FLAG = [True]
DEF = [True]
def _mk():
    cell = [True]
    def emit(self, record):
        if cell[0]:
            self.out.append(record.getMessage())
    return emit, cell
class GlobalH(logging.Handler):
    def __init__(self):
        super().__init__(); self.out = []
    def emit(self, record):
        if FLAG[0]:
            self.out.append(record.getMessage())
class DefaultH(logging.Handler):
    def __init__(self):
        super().__init__(); self.out = []
    def emit(self, record, on=DEF):
        if on[0]:
            self.out.append(record.getMessage())
_e, CELL = _mk()
ClosureH = type("ClosureH", (logging.Handler,), {"emit": _e,
                "__init__": lambda self: (logging.Handler.__init__(self), setattr(self, "out", []))[0]})
'''


@pytest.fixture
def hh(tmp_path, monkeypatch):
    (tmp_path / "n2_cl2reg_helper.py").write_text(HELPER)
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("n2_cl2reg_helper", None)
    return importlib.import_module("n2_cl2reg_helper")


def _watch(fn):
    mod = types.ModuleType("n2_cl2reg_target")  # the target module does NOT own the mutated value
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


@pytest.mark.parametrize("which", ["global", "default", "closure"])
def test_mutating_a_value_a_handler_method_reads_is_reported(hh, which):
    cls, flip = {"global": (hh.GlobalH, lambda: hh.FLAG.__setitem__(0, False)),
                 "default": (hh.DefaultH, lambda: hh.DEF.__setitem__(0, False)),
                 "closure": (hh.ClosureH, lambda: hh.CELL.__setitem__(0, False))}[which]
    h = cls()
    lg = logging.getLogger(f"test.cl2reg.{which}")
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    try:
        base = _watch(lambda n: n)
        unchanged = _watch(lambda n: n)
        assert unchanged == base, f"{which}: the no-mutation control changed the logging fingerprint"

        def f(n):
            flip()
            return n
        out = _watch(f)
        lg.info("after the call")
        assert not h.out, "precondition: the mutation really changes behaviour (records dropped)"
        assert out != base, f"{which}: a value read by a handler's emit changed (records now dropped) and nothing was reported"
    finally:
        hh.FLAG[0] = hh.DEF[0] = hh.CELL[0] = True
        lg.removeHandler(h)
