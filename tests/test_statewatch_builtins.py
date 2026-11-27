"""case: _StateWatch must detect AND restore rebound builtins without crashing, whichever builtin
the (hostile) target rebinds, and must report (not crash) on the restore=False recorder path."""
import builtins
import types
from pathlib import Path

import pytest

from hlith.differential import _StateWatch


def _watch():
    mod = types.ModuleType("sw_mod")
    mod.foo = lambda: 1
    return _StateWatch(mod, mod.foo)


@pytest.mark.parametrize("name", ["int", "isinstance", "set", "sorted", "len", "repr", "dict"])
def test_rebound_builtin_is_detected_and_restored(name):
    w = _watch()
    env = dict(__import__("os").environ)
    orig = getattr(builtins, name)
    try:
        setattr(builtins, name, lambda *a, **k: 0)
        changes = w.changes_and_restore(env)
        restored = getattr(builtins, name) is orig
    finally:
        setattr(builtins, name, orig)
    assert f"builtins.{name}" in changes
    assert restored


def test_recorder_path_reports_instead_of_crashing_and_leaves_state():
    w = _watch()
    env = dict(__import__("os").environ)
    orig = builtins.int
    try:
        builtins.int = lambda x=0: 999
        changes = w.changes_and_restore(env, restore=False)
        left = builtins.int is not orig
    finally:
        builtins.int = orig
    assert "builtins.int" in changes
    assert "process state unmeasurable" in changes
    assert left  # restore=False: state left as the call left it


# ---- review's attack on 66c2997c (A4 was a regression of that commit; A1-A3 failed before it too) ----------------------

def _env():
    return dict(__import__("os").environ)


@pytest.mark.parametrize("planted", ["abs", "zz_evil"])  # an EXISTING builtin replaced (review's A4) and a NEW name
def test_a4_repr_that_rebinds_a_builtin_cannot_leave_it_tampered(planted):
    w, env, orig_len = _watch(), _env(), builtins.len
    had = planted in builtins.__dict__
    orig_planted = builtins.__dict__.get(planted)

    class Evil:
        def __repr__(self):
            builtins.len = lambda *a: 0  # runs while the report is being formatted
            return "evil"

    try:
        setattr(builtins, planted, Evil())
        changes = w.changes_and_restore(env)
        clean = builtins.len is orig_len and builtins.__dict__.get(planted) is orig_planted
    finally:
        builtins.len = orig_len
        if had:
            setattr(builtins, planted, orig_planted)
        else:
            builtins.__dict__.pop(planted, None)
    assert f"builtins.{planted}" in changes
    assert clean, "a clean-looking restore left builtins.len (or the planted name) in place"


def test_a1_overridden_import_cannot_hand_the_watch_a_fake_builtins():
    w, env = _watch(), _env()
    orig_import, orig_sorted = builtins.__import__, builtins.sorted
    fake = types.ModuleType("builtins")
    try:
        builtins.__import__ = lambda *a, **k: fake
        builtins.sorted = lambda *a, **k: []
        changes = w.changes_and_restore(env)
        ok = builtins.__import__ is orig_import and builtins.sorted is orig_sorted
    finally:
        builtins.__import__, builtins.sorted = orig_import, orig_sorted
    assert ok
    assert "builtins.sorted" in changes and "builtins.__import__" in changes


def test_a3_fake_sys_modules_builtins_cannot_redirect_the_restore():
    import sys

    w, env = _watch(), _env()
    orig_sorted, real = builtins.sorted, sys.modules["builtins"]
    try:
        sys.modules["builtins"] = types.ModuleType("builtins")
        builtins.sorted = lambda *a, **k: []
        changes = w.changes_and_restore(env)
        ok = builtins.sorted is orig_sorted and sys.modules["builtins"] is real
    finally:
        builtins.sorted = orig_sorted
        sys.modules["builtins"] = real
    assert ok
    assert "builtins.sorted" in changes


def test_a2_non_str_key_with_raising_hash_is_removed_and_reported_not_crashed():
    w, env = _watch(), _env()

    class Hostile:
        armed = False

        def __hash__(self):
            if Hostile.armed:
                raise RuntimeError("hostile hash")
            return 1

    k = Hostile()
    try:
        builtins.__dict__[k] = 1
        Hostile.armed = True
        changes = w.changes_and_restore(env)
        Hostile.armed = False
        gone = k not in builtins.__dict__
    finally:
        Hostile.armed = False
        builtins.__dict__.pop(k, None)
    assert gone, "the planted non-str builtins key survived the restore"
    assert "builtins" in changes


# ---- review R2 on ee28d5e9: tampering BEFORE the watch is constructed (target module top-level code) ------------------

def test_b2_overridden_import_at_construction_cannot_decouple_the_watch():
    real_import, orig_len = builtins.__import__, builtins.len
    fake = types.ModuleType("builtins")
    try:
        builtins.__import__ = lambda name, *a, **k: fake if name == "builtins" else real_import(name, *a, **k)
        w = _watch()  # constructed while __import__('builtins') lies
    finally:
        builtins.__import__ = real_import
    env = _env()
    try:
        builtins.len = lambda *a: 0
        changes = w.changes_and_restore(env)
        ok = builtins.len is orig_len
    finally:
        builtins.len = orig_len
        # the watch was built while __import__ lied, so the lie IS its baseline (named limit: baseline-at-construction) and
        # the restore above put it back: reset it here or it leaks into every later test in the process
        builtins.__import__ = real_import
    assert ok, "tampering after a lied-to construction was never restored"
    assert "builtins.len" in changes


@pytest.mark.parametrize("decoy", ["empty", "copy"])
def test_b3_vars_returning_a_decoy_for_builtins_cannot_decouple_the_watch(decoy):
    real_vars, orig_len = builtins.vars, builtins.len
    try:
        builtins.vars = lambda *a: ({} if decoy == "empty" else dict(real_vars(*a))) if a and a[0] is builtins else real_vars(*a)
        w = _watch()
    finally:
        builtins.vars = real_vars
    env = _env()
    try:
        builtins.len = lambda *a: 0
        changes = w.changes_and_restore(env)
        ok = builtins.len is orig_len and "int" in builtins.__dict__
    finally:
        builtins.len = orig_len
    assert ok, "a decoy vars(builtins) at construction left tampering unrestored (or emptied the real builtins)"
    assert "builtins.len" in changes


# ---- review R3 on 6941d9a4: the pytest RECORDER boot loaded differential.py AFTER inserting the target's sys.path ---------

def test_r3_recorder_boot_loads_the_checker_before_the_target_syspath(tmp_path):
    """A target-root secrets.py (one of differential.py's own stdlib imports) must not run before the checker binds its
    live builtins dict. Boot prefix only (through the sys.path insertion), run exactly as the recorder runs it: -I -c."""
    import json
    import subprocess
    import sys

    from hlith import differential as dmod

    shadow = tmp_path / "target"
    shadow.mkdir()
    mark = tmp_path / "shadow-ran"
    (shadow / "secrets.py").write_text(
        "import sys, types\n"
        "sys.modules['builtins'] = types.ModuleType('builtins')\n"  # makes a later 'import builtins' see a fake
        f"open({str(mark)!r}, 'w').write('ran')\n")
    mode = tmp_path / "mode.json"
    mode.write_text(json.dumps({"checker": str(Path(dmod.__file__))}))
    boot = dmod._PYTEST_REC_BOOT
    prefix = boot[:boot.index("ROOTS = sorted(")]
    probe = prefix + ("\nprint('LIVE', D._BUILTINS_DICT is print.__self__.__dict__, "
                      "'SHADOW_RAN', os.path.exists(%r))\n" % str(mark))
    args = [json.dumps([str(shadow)]), str(tmp_path), "j.xml", "m", "q", str(tmp_path / "rec.json"), str(mode)]
    r = subprocess.run([sys.executable, "-I", "-c", probe, *args], capture_output=True, text=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-800:]
    assert "LIVE True SHADOW_RAN False" in r.stdout, r.stdout + r.stderr[-400:]


# ---- review R4 on 6014605d: a .pth in the target venv runs BEFORE any Hlith code (-I does not disable site) --------------

_FAKE = ("_fake = types.ModuleType('builtins')\n"  # a WORKING copy (stdlib keeps importing it) whose __dict__ is not the live one
         "_fake.__dict__.update(builtins.__dict__)\n")


@pytest.mark.parametrize("tamper", [
    _FAKE + "sys.modules['builtins'] = _fake",
    _FAKE + "_real = builtins.__import__\n"
    "builtins.__import__ = lambda n, *a, **k: _fake if n == 'builtins' else _real(n, *a, **k)",
    "pass",  # control: no tampering
], ids=["sysmod", "import", "control"])
def test_r4_site_time_tampering_cannot_make_the_bound_dict_a_fake(tmp_path, tamper):
    """What a venv .pth does, emulated by running the tamper first in the same -I -c program as the real boot prefix."""
    import json
    import subprocess
    import sys

    from hlith import differential as dmod

    mode = tmp_path / "mode.json"
    mode.write_text(json.dumps({"checker": str(Path(dmod.__file__))}))
    boot = dmod._PYTEST_REC_BOOT
    prefix = boot[:boot.index("ROOTS = sorted(")]
    probe = ("import sys, types, builtins\n" + tamper + "\n" + prefix +
             "\nprint('LIVE', D._BUILTINS_DICT is print.__self__.__dict__)\n")
    args = [json.dumps([]), str(tmp_path), "j.xml", "m", "q", str(tmp_path / "rec.json"), str(mode)]
    r = subprocess.run([sys.executable, "-I", "-c", probe, *args], capture_output=True, text=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-800:]
    assert "LIVE True" in r.stdout, r.stdout + r.stderr[-400:]
