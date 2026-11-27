# SPDX-License-Identifier: Apache-2.0
"""sys.displayhook is process-global and changes what a later displayhook call writes.

On bridge c8c782cd2663fae3347f12930cfec8569864a545, _StateWatch did not record or restore it, so
changes_and_restore returned "" and differential._same treated two calls as the same outcome.

This is the observation/restore contract, not a confined Obligation verdict: this runner has no
Landlock (hlith-confine ENOSYS) and must not call that UNVERIFIED a false HELD.
"""
import io
import os
import sys
import types

from hlith.differential import _StateWatch, _same


def _module(src: str) -> types.ModuleType:
    mod = types.ModuleType("displayhook_probe")
    ns = {"__name__": mod.__name__}
    exec(src, ns)
    mod.__dict__.update(ns)
    return mod


def _displayed(hook, value) -> str:
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        hook(value)
    finally:
        sys.stdout = old
    return buf.getvalue()


def test_unchanged_displayhook_is_a_negative_control():
    builtin = sys.displayhook
    mod = _module("def f(n):\n    return n * 2\n")
    watch = _StateWatch(mod, mod.f)
    assert mod.f(2) == 4
    report = watch.changes_and_restore(dict(os.environ))
    assert report == ""
    assert sys.displayhook is builtin


def test_replaced_displayhook_is_reported_and_restored():
    builtin = sys.displayhook
    mod = _module(
        "import sys\n"
        "def f(n):\n"
        "    def hook(value):\n"
        "        sys.stdout.write('POISON\\n')\n"
        "    sys.displayhook = hook\n"
        "    return n * 2\n"
    )
    watch = _StateWatch(mod, mod.f)
    try:
        assert mod.f(2) == 4  # same return as the control; the hook is the only difference
        poisoned = sys.displayhook
        assert poisoned is not builtin
        # observe the replacement itself, not the builtin hook: the builtin writes builtins._
        assert _displayed(poisoned, 123) == "POISON\n"
        report = watch.changes_and_restore(dict(os.environ))
        assert sys.displayhook is builtin
        assert _displayed(sys.displayhook, 123) == "123\n"
    finally:
        sys.displayhook = builtin
    assert report == "sys.displayhook replaced"
    assert "0x" not in report  # stable token: two processes must not diverge on the function address


def test_recorder_reports_displayhook_and_leaves_it():
    builtin = sys.displayhook
    mod = _module("import sys\ndef f(n):\n    sys.displayhook = (lambda v: None)\n    return n\n")
    watch = _StateWatch(mod, mod.f)
    try:
        mod.f(1)
        report = watch.changes_and_restore(dict(os.environ), restore=False)
        left = sys.displayhook is not builtin
    finally:
        sys.displayhook = builtin
    assert report == "sys.displayhook replaced"
    assert left


def test_empty_g_agrees_and_a_displayhook_token_does_not():
    """The host agreement primitive. An empty channel is not a refusal."""
    agreed = {"k": "ret", "r": "4"}
    assert _same(dict(agreed, g=""), dict(agreed, g="")) is True
    assert _same(dict(agreed, g=""), dict(agreed, g="sys.displayhook replaced")) is False
