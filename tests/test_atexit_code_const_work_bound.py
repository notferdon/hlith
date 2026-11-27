# SPDX-License-Identifier: Apache-2.0
"""Second unit not charged by 7e73f6ad (review, case atom fix): _code_digest repr()s EVERY code constant and is called once per FUNCTION
OBJECT by _atexit_fn_ident; the atom charge only covered _atexit_val atoms. Many distinct function objects that share ONE code object
holding a big constant (types.FunctionType(code, globals), a decorator factory, functools.wraps copies, closures created in a loop all
share code) therefore repr the same constant again each time with no units charged. Measured by review on 7e73f6ad (RLIMIT_AS 3 GiB):
24 function objects sharing one code with an 8 MB const -> 101 units (bound 200000), 1.27 s (192 MB of repr). Fail-safe (timeout =
UNVERIFIED, never HELD) but the same unbounded-work class the atom fix closed. Deterministic, no wall clock.
Tests from review (hlith/review-code-const-work 88365e54), kept verbatim; fix by review (charge code constants by size, per function object)."""
import types

from hlith import differential


def _callback(n_funcs: int, const_bytes: int):
    ns = {"__name__": "n7code"}
    exec(compile("def helper():\n    return 'x'\n", "<n7code>", "exec"), ns)
    code = ns["helper"].__code__.replace(co_consts=(None, "a" * const_bytes))  # ONE code object, one big constant
    for i in range(n_funcs):
        ns[f"F{i}"] = types.FunctionType(code, ns, f"F{i}")  # distinct function objects sharing that code
    exec(compile("def cb():\n    return (" + ",".join(f"F{i}" for i in range(n_funcs)) + ",)\n", "<n7code>", "exec"), ns)
    return ns["cb"]


def test_many_function_objects_sharing_a_big_constant_digest_it_once():
    """review's case (40 function objects, one 8 MB constant). design review n17 chose MEMOIZING the digest per code object within one identity: the
    amplification is removed (the constant is repr'd ONCE: ~32k units, not 40 x 32k = 1.3M), so the callback is measurable and its work is
    bounded by the code, not by the number of references. review's original expectation (unmeasurable) described the un-memoized cost."""
    cb = _callback(40, 8 << 20)
    before = differential._ATX_WORK[0]
    got = differential._atexit_identity(cb, (), {}, "/nonexistent")
    assert got
    assert differential._ATX_WORK[0] - before < 100_000, "the shared 8 MB constant must be digested once, not once per function object"


def test_modest_code_constants_stay_measurable():
    got = differential._atexit_identity(_callback(8, 100 << 10), (), {}, "/nonexistent")
    assert "cb" in got or got


def test_a_single_huge_code_constant_is_unmeasurable():
    """review: the same charge bounds ONE callback whose own code holds a 60 MB constant."""
    cb = _callback(1, 60 << 20)
    try:
        differential._atexit_identity(cb, (), {}, "/nonexistent")
    except differential._AtexitUnmeasurable:
        return
    raise AssertionError("a 60 MB code constant was measured, not bounded")


class _CountingStr(str):
    """A str constant that counts how many times it is repr'd (the work unit that was not charged). From review (1c7a8825)."""
    calls = 0

    def __repr__(self):
        type(self).calls += 1
        return super().__repr__()


def test_shared_code_constant_is_repr_d_at_most_once_or_the_identity_is_unmeasurable():
    """Shape-agnostic red test from review (hlith/review-n1fix 1c7a8825, verbatim): memoizing the digest per code object (repr once) OR charging
    the constant into the budget (unmeasurable). Fails only when the same constant is repr'd once per function object."""
    ns = {"__name__": "n7cnt"}
    exec(compile("def helper():\n    return 'x'\n", "<n7cnt>", "exec"), ns)
    _CountingStr.calls = 0
    code = ns["helper"].__code__.replace(co_consts=(None, _CountingStr("a" * 4096)))
    for i in range(40):
        ns[f"F{i}"] = types.FunctionType(code, ns, f"F{i}")
    exec(compile("def cb():\n    return (" + ",".join(f"F{i}" for i in range(40)) + ",)\n", "<n7cnt>", "exec"), ns)
    try:
        differential._atexit_identity(ns["cb"], (), {}, "/nonexistent")
    except differential._AtexitUnmeasurable:
        return
    assert _CountingStr.calls <= 1, f"the shared constant was repr'd {_CountingStr.calls} times for 40 function objects"
