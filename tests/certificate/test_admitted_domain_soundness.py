# SPDX-License-Identifier: Apache-2.0
"""Admitted-domain soundness regressions for equiv_norm / equiv_cert / symeq.

Every negative case passes ONLY exact builtin values (int, str, list[int]) matching the parameter
annotations — ZERO subclasses, ZERO external callers — and must be refused in BOTH scoped
(strict_domain=False) and strict (strict_domain=True) modes as well as by symeq directly.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from hlith.obligation import equiv_cert as ec
from hlith.obligation import symeq


@dataclass(frozen=True)
class SoundCase:
    id: str
    kind: str  # "must-refuse" | "may-certify"
    strict: bool
    base: str
    post: str
    witness: str
    note: str


CASES = [
    # 1. Exact int param overwritten via tuple unpack to NaN before `flat` guard flip
    SoundCase(
        "admitted_flat_int_reassigned_nan",
        "must-refuse",
        True,
        """
def f(x: int) -> int:
    if type(x) not in (int, bool):
        raise TypeError("int")
    if x == 987654321:
        x, _ = 1e309 - 1e309, 0
        if x > 0:
            if x < 10:
                return 1
        return 0
    return x + 1
""".lstrip(),
        """
def f(x: int) -> int:
    if type(x) not in (int, bool):
        raise TypeError("int")
    if x == 987654321:
        x, _ = 1e309 - 1e309, 0
        if x <= 0 or x >= 10:
            return 0
        return 1
    return x + 1
""".lstrip(),
        "r = f(987654321)",
        "tuple-unpack overwrites x:int with NaN; flat negates >/< into <=/>=, flipping 0 -> 1 on exact int input",
    ),
    # 2. Exact str param reassigned to int before `temp` inlines across str_pure(s.upper())
    SoundCase(
        "admitted_str_reassigned_temp_crash_order",
        "must-refuse",
        True,
        """
def f(s: str) -> str:
    if type(s) is not str:
        raise TypeError("str")
    if s == "trigger":
        s = 123
        t = int("bad")
        return f"{s.upper()}:{t}"
    return s
""".lstrip(),
        """
def f(s: str) -> str:
    if type(s) is not str:
        raise TypeError("str")
    if s == "trigger":
        s = 123
        return f"{s.upper()}:{int('bad')}"
    return s
""".lstrip(),
        "r = f('trigger')",
        "local s = 123 makes s.upper() raise AttributeError; temp must not treat s.upper() as pure/total",
    ),
    # 3. `sum_loop` with `xs: list[int]` reassigned locally to non-associative floats
    SoundCase(
        "admitted_sum_loop_reassigned_float_list",
        "must-refuse",
        False,
        """
def f(xs: list[int]) -> float:
    if len(xs) == 1 and xs[0] == 987654321:
        xs = [1e16, 1.0, -1e16]
        t = 0
        for p in xs:
            t += p
        return t
    return 0.0
""".lstrip(),
        """
def f(xs: list[int]) -> float:
    if len(xs) == 1 and xs[0] == 987654321:
        xs = [1e16, 1.0, -1e16]
        t = sum(xs)
        return t
    return 0.0
""".lstrip(),
        "r = f([987654321])",
        "xs reassigned to floats; naive += yields 0.0 while Python>=3.12 compensated sum() yields 1.0",
    ),
    # 4. `sum_loop` with `xs: list[int]` mutated in-place via subscript writes (zero rebinding of `xs`)
    SoundCase(
        "admitted_sum_loop_inplace_list_mutation",
        "must-refuse",
        False,
        """
def f(xs: list[int]) -> float:
    if len(xs) == 3 and xs[0] == 987654321:
        xs[0] = 1e16
        xs[1] = 1.0
        xs[2] = -1e16
        t = 0
        for p in xs:
            t += p
        return t
    return 0.0
""".lstrip(),
        """
def f(xs: list[int]) -> float:
    if len(xs) == 3 and xs[0] == 987654321:
        xs[0] = 1e16
        xs[1] = 1.0
        xs[2] = -1e16
        t = sum(xs)
        return t
    return 0.0
""".lstrip(),
        "r = f([987654321, 0, 0])",
        "in-place subscript writes on xs:list[int] change elements to floats without rebinding xs; 0.0 vs 1.0",
    ),
    # 5. `for x in ...:` loop target overwrites `x: int` before `flat` guard flip
    SoundCase(
        "for_overwrite_int_param_before_flat",
        "must-refuse",
        False,
        """
def f(x: int) -> int:
    if x == 987654321:
        for x in (1e309 - 1e309,):
            if x > 0:
                if x < 10:
                    return 1
            return 0
    return x + 1
""".lstrip(),
        """
def f(x: int) -> int:
    if x == 987654321:
        for x in (1e309 - 1e309,):
            if x <= 0 or x >= 10:
                return 0
            return 1
    return x + 1
""".lstrip(),
        "r = f(987654321)",
        "for-loop header overwrites x:int with NaN before flat guard negation; 0 vs 1",
    ),
    # 6. `xs: list[int]` mutated via aliased second parameter `ys` (caller passes f(a, a))
    SoundCase(
        "admitted_sum_loop_aliased_param_mutation",
        "must-refuse",
        False,
        """
def f(xs: list[int], ys) -> float:
    ys.extend([1e16, 1.0, -1e16])
    t = 0
    for p in xs:
        t += p
    return t
""".lstrip(),
        """
def f(xs: list[int], ys) -> float:
    ys.extend([1e16, 1.0, -1e16])
    t = sum(xs)
    return t
""".lstrip(),
        "a = []\nr = f(a, a)",
        "second parameter aliases xs:list[int] and mutates it with floats before sum_loop",
    ),
    # 7. `xs: list[int]` mutated via callback before `sum_loop`
    SoundCase(
        "admitted_sum_loop_callback_mutation",
        "must-refuse",
        False,
        """
def f(xs: list[int], cb) -> float:
    cb()
    t = 0
    for p in xs:
        t += p
    return t
""".lstrip(),
        """
def f(xs: list[int], cb) -> float:
    cb()
    t = sum(xs)
    return t
""".lstrip(),
        "a = []\nr = f(a, lambda: a.extend([1e16, 1.0, -1e16]))",
        "callback mutates caller's list referenced by xs:list[int] before sum_loop",
    ),
    # 8. `x: int` promoted to NaN via augmented assignment `x += ...` before `flat`
    SoundCase(
        "admitted_flat_int_augassign_nan",
        "must-refuse",
        False,
        """
def f(x: int) -> int:
    x += 1e309 - 1e309
    if x > 0:
        if x < 10:
            return 1
    return 0
""".lstrip(),
        """
def f(x: int) -> int:
    x += 1e309 - 1e309
    if x <= 0 or x >= 10:
        return 0
    return 1
""".lstrip(),
        "r = f(5)",
        "augassign x += NaN changes x from exact int to float NaN before flat",
    ),
    # 9. `except Exception as s:` overwrites `s: str` before `temp` str_pure inline
    SoundCase(
        "admitted_str_except_as_rebind",
        "must-refuse",
        False,
        """
def f(s: str) -> str:
    try:
        raise ValueError("boom")
    except ValueError as s:
        t = int("bad")
        return f"{s.upper()}:{t}"
""".lstrip(),
        """
def f(s: str) -> str:
    try:
        raise ValueError("boom")
    except ValueError as s:
        return f"{s.upper()}:{int('bad')}"
""".lstrip(),
        "r = f('ok')",
        "except ValueError as s rebinds s:str to ValueError before temp inlines past s.upper()",
    ),
    # 10. Positive control: un-rebound exact-int guard flattening under strict_domain=True with (int, bool)
    SoundCase(
        "ctrl_strict_flat_exact_int",
        "may-certify",
        True,
        """
def f(x: int) -> int:
    if type(x) not in (int, bool):
        raise TypeError("int")
    if x > 0:
        if x < 10:
            return 1
    return 0
""".lstrip(),
        """
def f(x: int) -> int:
    if type(x) not in (int, bool):
        raise TypeError("int")
    if x <= 0 or x >= 10:
        return 0
    return 1
""".lstrip(),
        "r = f(5)",
        "pure exact-int flat control",
    ),
    # 11. Positive control: immutable tuple[int, ...] sum_loop
    SoundCase(
        "ctrl_tuple_sum_loop",
        "may-certify",
        False,
        """
def f(xs: tuple[int, ...]) -> int:
    t = 0
    for p in xs:
        t += p
    return t
""".lstrip(),
        """
def f(xs: tuple[int, ...]) -> int:
    t = sum(xs)
    return t
""".lstrip(),
        "r = f((1, 2, 3))",
        "pure tuple[int, ...] sum control",
    ),
    # 12. Positive control: pure guarded list[int] sum_loop records guard dependency
    SoundCase(
        "ctrl_pure_guarded_list_sum_loop",
        "may-certify",
        False,
        """
def f(xs: list[int], fee: int) -> int:
    if not xs or fee < 0:
        return 0
    t = 0
    for p in xs:
        t += p
    return t + fee
""".lstrip(),
        """
def f(xs: list[int], fee: int) -> int:
    if not xs or fee < 0:
        return 0
    t = sum(xs)
    return t + fee
""".lstrip(),
        "r = f([1, 2, 3], 5)",
        "pure exact-builtin guard before list[int] sum_loop certifies and records fee:int dependency",
    ),
]


def _eval(src: str, witness: str) -> tuple:
    ns: dict = {}
    try:
        exec(compile(src, "m.py", "exec"), ns)
        exec(compile(witness, "<witness>", "exec"), ns)
        return ("ret", repr(ns.get("r")))
    except BaseException as exc:  # noqa: BLE001
        return ("exc", type(exc).__name__, str(exc)[:80])


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_admitted_domain_soundness(case: SoundCase) -> None:
    rb = _eval(case.base, case.witness)
    rp = _eval(case.post, case.witness)
    if case.kind == "must-refuse":
        assert rb != rp, f"{case.id}: expected runtime divergence, got both {rb}"
        for strict in (False, True):
            cert = ec.certify_sources(case.base, case.post, "f", module="m", strict_domain=strict)
            assert not cert.ok, (
                f"ADMITTED-DOMAIN FALSE CERT on {case.id} (strict={strict}): "
                f"rules={cert.rules}, base={rb}, post={rp} ({case.note})"
            )
        sym = symeq.prove(case.base, case.post, "f")
        assert not sym.ok, f"SYMEQ FALSE PROOF on {case.id}: mode={sym.mode}, base={rb}, post={rp}"
    else:
        assert rb == rp, f"{case.id}: control diverged {rb} vs {rp}"
        cert = ec.certify_sources(case.base, case.post, "f", module="m", strict_domain=case.strict)
        assert cert.ok, f"control {case.id} unexpectedly refused: {cert.reason}"
        if case.id == "ctrl_pure_guarded_list_sum_loop":
            assert dict(cert.domain) == {"xs": "list[int]", "fee": "int"}, cert.domain
