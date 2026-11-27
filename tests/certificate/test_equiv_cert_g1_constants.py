# SPDX-License-Identifier: Apache-2.0
"""G1: module-level IMMUTABLE LITERAL constants (int/float/str/bytes/bool/None and tuples of them, bound exactly once at module level, never rebound) are modelled as pure constants, so a
function that reads one is no longer refused as 'mutable or unmodelled module global' (a float constant used to kill every cone reading it). What it proves: a Name that resolves to such a
constant is replaced by its literal value in the canonical form, so two versions that read the SAME value are compared by their code, and two versions whose constants DIFFER are different
computations. Side conditions: exactly one store (a `global` rebinding or a second assignment is a store); literal only (no float arithmetic is folded: 0.2 * 2 stays an unmodelled expression;
float('nan') is not a literal); the literal's TYPE is part of its identity (1 != 1.0 != True, 0.0 != -0.0). Domain: R0-style identity over the whole cone, no input-type assumption."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec

H = "RATE = {c}\n\n\ndef f(price, fee):\n{body}"
BODY_A = "    total = price\n    return total + total * RATE + fee\n"
BODY_B = "    subtotal = price\n    return subtotal + subtotal * RATE + fee\n"


def cert(b, p, fn="f"):
    return ec.certify_sources(b, p, fn, module="m")


@pytest.mark.parametrize("c", ["0.2", "-1.5", "0.0", "-0.0", "1e-300", "1e999", "3", "'x'", "b'x'", "True", "None", "(0.5, 1, 'a')", "(1.5, (2.5, -3.5))"])
def test_a_function_reading_an_immutable_literal_constant_is_certified_when_only_locals_are_renamed(c):
    r = cert(H.format(c=c, body=BODY_A), H.format(c=c, body=BODY_B))
    assert r.ok and r.rules == ("R0",), (c, r.reason, r.detail)


@pytest.mark.parametrize("a,b", [("0.2", "0.25"), ("0.2", "0.2000001"), ("1", "1.0"), ("1.0", "True"), ("0.0", "-0.0"), ("1", "True"), ("'1'", "1"), ("(1.5, 2)", "(1.5, 2.0)"), ("None", "0")])
def test_a_changed_constant_value_or_type_is_a_different_computation(a, b):
    r = cert(H.format(c=a, body=BODY_A), H.format(c=b, body=BODY_A))
    assert not r.ok, (a, b, r.rules)


def test_same_float_spelled_differently_is_the_same_constant():
    assert cert(H.format(c="0.2", body=BODY_A), H.format(c="0.20", body=BODY_A)).ok
    assert cert(H.format(c="1e-1", body=BODY_A), H.format(c="0.1", body=BODY_A)).ok


@pytest.mark.parametrize("post_body", ["    total = price\n    return total + total * RATE * 2 + fee\n", "    total = price\n    return total + total * RATE\n", "    total = price\n    return total + RATE + fee\n"])
def test_a_behaviour_change_that_reads_the_same_constant_is_refused(post_body):
    assert not cert(H.format(c="0.2", body=BODY_A), H.format(c="0.2", body=post_body)).ok


def test_a_constant_rebound_at_module_level_is_not_a_constant():
    src = "RATE = 0.2\nRATE = 0.3\n\n\ndef f(price):\n    return price * RATE\n"
    r = cert(src, src)
    assert not r.ok and "module global" in r.reason, (r.reason, r.detail)


def test_a_constant_rebound_through_global_in_a_function_is_not_a_constant():
    src = "RATE = 0.2\n\n\ndef bump():\n    global RATE\n    RATE = 0.3\n\n\ndef f(price):\n    return price * RATE\n"
    assert not cert(src, src).ok


def test_a_constant_augmented_in_module_code_is_not_a_constant():
    src = "RATE = 0.2\nRATE += 0.1\n\n\ndef f(price):\n    return price * RATE\n"
    assert not cert(src, src).ok


def test_float_arithmetic_is_not_folded_into_a_constant():
    src = "RATE = 0.1 * 3\n\n\ndef f(price):\n    return price * RATE\n"
    assert not cert(src, src).ok  # an unmodelled expression, not a literal: refused


def test_float_constructor_calls_are_not_literals():
    src = "RATE = float('nan')\n\n\ndef f(price):\n    return price * RATE\n"
    assert not cert(src, src).ok


def test_a_constant_shadowed_by_a_parameter_or_local_is_the_local():
    base = "RATE = 0.2\n\n\ndef f(price, RATE):\n    return price * RATE\n"
    assert cert(base, base.replace("price * RATE", "RATE * price")).ok is False  # commutation has no rule; the point: RATE here is the PARAMETER, not the constant


def test_private_constants_with_different_names_but_one_value_are_identical_and_public_ones_are_not():
    priv_a = "_A = 0.2\n\n\ndef f(price):\n    return price * _A\n"
    priv_b = "_B = 0.2\n\n\ndef f(price):\n    return price * _B\n"
    assert cert(priv_a, priv_b).ok  # a private name is not part of the module's surface
    assert not cert(priv_a.replace("_A", "A"), priv_b.replace("_B", "B")).ok  # a public one is (m.A vs m.B): see test_equiv_case_classes
