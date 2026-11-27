# SPDX-License-Identifier: Apache-2.0
"""Structural normal-form rules (rule id NORM): both versions are rewritten by SOUND, side-condition-guarded transforms and compared; equal normal forms => equivalent. Each transform is applied
only where its side conditions hold, on its own side, so a transform never needs the other version. What each proves and requires (no input-type assumption anywhere):

 T-inline   a call h(a, ...) of a module-level EXPRESSION-BODIED helper (one `return EXPR`, plain positional parameters, no defaults/varargs, not recursive, no lambda/comprehension/yield in EXPR)
            whose arguments are constants or names that are parameters or definitely-assigned locals (loading them has no effect, so duplicating or moving them is exact) is replaced by EXPR with
            the parameters substituted, provided no caller-local name captures a global that EXPR reads. Disclosed assumption: call-stack depth (RecursionError at the limit) and tracebacks differ.
 T-ret      `if c: x = A  else: x = B` ... `return x` (x used nowhere else, every branch ends by assigning x, else-chain complete) <-> `if c: return A  else: return B`; else after a branch that always
            returns is flattened.
 T-temp     `t = E` followed in the same block by ONE statement that reads t exactly once (and t nowhere else): E moves to the read, provided everything evaluated in that statement BEFORE the read is
            a constant or a definitely-assigned local load (no effect, cannot raise), and the read is not inside a lambda/comprehension.
 T-dead     `t = <constant or definitely-assigned name>` never read: removed (a pure binding).
 T-comp     `out = []` immediately followed by `for v in IT: out.append(X)` (optionally under one `if`), no else/break/continue, v and out read nowhere inside X / IT / after as v, out not otherwise
            written: `out = [X for v in IT (if ...)]` (same iterator protocol, same order, same exception point).
 T-fmt      "{}{}" / "{0}{1}" str.format with positional plain fields and ARGUMENTS that are all constants/definitely-assigned names except possibly the FIRST: an f-string with the same fields.
Falsifiers below are generic (hostile or reordered variants), not tailored; each negative must stay refused."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec


def cert(b, p, fn="f"):
    return ec.certify_sources(b, p, fn, module="m")


def ok(b, p, fn="f"):
    r = cert(b, p, fn)
    assert r.ok and "NORM" in r.rules, (r.reason, r.detail, r.rules)
    return r


def no(b, p, fn="f"):
    r = cert(b, p, fn)
    assert not r.ok, ("ADMITTED", r.rules, r.detail)
    return r


# ----------------------------------------------------------------------------------------------- T-inline
H = "RATE = 0.2\n\n\n"


def test_inline_extracted_helper_is_certified():
    b = H + "def f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return total + total * RATE + fee\n"
    p = H + "def _with_tax(amount):\n    return amount + amount * RATE\n\n\ndef f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return _with_tax(total) + fee\n"
    ok(b, p)
    ok(p, b)  # and the inverse direction (inline = remove the helper)


def test_split_function_helper_with_param_argument_is_certified():
    b = "def f(name, qty, unit):\n    total = qty * unit\n    return name.strip().title() + ': ' + str(total)\n"
    p = "def _fmt(name):\n    return name.strip().title()\n\n\ndef f(name, qty, unit):\n    total = qty * unit\n    return _fmt(name) + ': ' + str(total)\n"
    ok(b, p)


@pytest.mark.parametrize("post", [
    "def g(x):\n    if x:\n        return x\n    return x\n\n\ndef h(x):\n    return x + 1\n\n\ndef f(a):\n    return h(g(a))\n",   # argument is a call to a helper that is not expression-bodied: not moved
    "def h(x):\n    print(x)\n    return x + 1\n\n\ndef f(a):\n    return h(a)\n",        # a helper with an effect statement
    "def h(x, y=1):\n    return x + y\n\n\ndef f(a):\n    return h(a)\n",            # default
    "def h(*x):\n    return x\n\n\ndef f(a):\n    return h(a)\n",                    # varargs
    "def h(x):\n    return h(x)\n\n\ndef f(a):\n    return h(a)\n",                  # recursion
    "def h(x):\n    return [x for _ in range(3)]\n\n\ndef f(a):\n    return h(a)\n",   # comprehension in the helper
    "def h(x):\n    return x + 2\n\n\ndef f(a):\n    return h(a)\n",                  # the helper does something DIFFERENT from the base
])
def test_inline_refuses_unsafe_or_different_helpers(post):
    base = "def g(x):\n    return x\n\n\ndef f(a):\n    return a + 1\n"
    no(base, post if "def g" in post else "def g(x):\n    return x\n\n\n" + post)


def test_inline_composes_through_helper_chains_and_temp_removal():
    """A composition the rules DO prove: h(g(a)) with g the identity and h adding one is a + 1."""
    ok("def f(a):\n    return a + 1\n", "def g(x):\n    return x\n\n\ndef h(x):\n    y = x + 1\n    return y\n\n\ndef f(a):\n    return h(g(a))\n")


def test_inline_refuses_name_capture_of_a_global():
    b = "K = 5\n\n\ndef f(a):\n    K = 7\n    return a + K\n"
    p = "K = 5\n\n\ndef h(x):\n    return x + K\n\n\ndef f(a):\n    K = 7\n    return h(a)\n"  # h reads the GLOBAL K = 5; inlining would capture the caller's local K = 7
    no(b, p)


def test_inline_refuses_keyword_calls_and_arity_mismatch():
    b = "def f(a):\n    return a + 1\n"
    no(b, "def h(x):\n    return x + 1\n\n\ndef f(a):\n    return h(x=a)\n")
    no(b, "def h(x, y):\n    return x + 1\n\n\ndef f(a):\n    return h(a)\n")


# ----------------------------------------------------------------------------------------------- T-ret
def test_early_returns_vs_assign_then_single_return():
    b = "def f(w):\n    if w > 20:\n        return 15\n    return 5\n"
    p = "def f(w):\n    if w > 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee\n"
    ok(b, p)
    ok(p, b)


def test_elif_chain_assign_then_return():
    b = "def f(w):\n    if w > 20:\n        return 15\n    elif w > 10:\n        return 9\n    else:\n        return 5\n"
    p = "def f(w):\n    if w > 20:\n        fee = 15\n    elif w > 10:\n        fee = 9\n    else:\n        fee = 5\n    return fee\n"
    ok(b, p)


def test_branch_statements_before_the_assignment_are_kept_in_order():
    b = "def f(w, log):\n    if w > 20:\n        log.append(1)\n        return 15\n    return 5\n"
    p = "def f(w, log):\n    if w > 20:\n        log.append(1)\n        fee = 15\n    else:\n        fee = 5\n    return fee\n"
    ok(b, p)


@pytest.mark.parametrize("post", [
    "def f(w):\n    if w > 20:\n        fee = 15\n    return fee\n",                                          # fee unbound on the else path (UnboundLocalError)
    "def f(w):\n    if w > 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee + 1\n",         # not a bare return of x
    "def f(w):\n    if w > 20:\n        fee = 15\n    else:\n        fee = 6\n    return fee\n",             # different value
    "def f(w):\n    fee = w.probe()\n    if w > 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee\n",   # effectful binding before branches
    "def f(w):\n    if w >= 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee\n",            # condition changed
])
def test_ret_refuses_unsound_variants(post):
    no("def f(w):\n    if w > 20:\n        return 15\n    return 5\n", post)


def test_ret_side_condition_leaves_dead_prior_binding_to_unconditional_sym():
    from hlith.obligation.equiv_norm import normalize_source

    base = "def f(w):\n    if w > 20:\n        return 15\n    return 5\n"
    post = "def f(w):\n    fee = 1\n    if w > 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee\n"
    _, notes, _, _ = normalize_source(post, "f")
    assert not any("T-ret" in n for n in notes), notes
    r = cert(base, post)
    assert r.ok and r.rules == ("SYM",) and r.domain == ()


# ----------------------------------------------------------------------------------------------- T-temp / T-dead
def test_temp_variable_for_a_sub_expression():
    b = "RATE = 0.2\n\n\ndef f(total, fee):\n    return total + total * RATE + fee\n"
    p = "RATE = 0.2\n\n\ndef f(total, fee):\n    tax = total * RATE\n    return total + tax + fee\n"
    ok(b, p)
    ok(p, b)


def test_temp_over_an_effectful_call_may_move_past_pure_loads_only():
    b = "def f(a, b):\n    return a + g(b)\n\n\ndef g(x):\n    return x\n"
    p = "def f(a, b):\n    t = g(b)\n    return a + t\n\n\ndef g(x):\n    return x\n"
    ok(b, p)


@pytest.mark.parametrize("post", [
    "def f(a, b):\n    t = a * b\n    return t + t\n",                          # used twice: evaluating once vs twice differs for hostile operands
    "def f(a, b):\n    t = g(b)\n    return h(a) + t\n",                        # a CALL is evaluated before the read: order of effects changes
    "def f(a, b):\n    t = g(b)\n    return a.x + t\n",                         # an attribute load before the read can raise/act
    "def f(a, b):\n    t = a * b\n    return (lambda: t)()\n",                  # read inside a lambda: later, lazily
    "def f(a, b):\n    t = a * b\n    u = a\n    return u + t\n",                # the read is not in the NEXT statement
])
def test_temp_refuses_unsound_variants(post):
    base = "def g(x):\n    return x\n\n\ndef h(x):\n    return x\n\n\ndef f(a, b):\n    return a * b + a * b\n"
    no(base, "def g(x):\n    return x\n\n\ndef h(x):\n    return x\n\n\n" + post.split("\n\n\n")[-1] if False else post)


def test_dead_constant_binding_is_removed():
    b = "def f(a):\n    return a + 1\n"
    ok(b, "def f(a):\n    unused = 5\n    alias = a\n    return a + 1\n")


def test_dead_call_binding_is_not_removed():
    no("def f(a):\n    return a + 1\n", "def f(a):\n    unused = a.split()\n    return a + 1\n")


# ----------------------------------------------------------------------------------------------- T-comp
def test_append_loop_to_comprehension():
    b = "RATE = 0.2\n\n\ndef f(prices):\n    out = []\n    for p in prices:\n        out.append(p + p * RATE)\n    return out\n"
    p = "RATE = 0.2\n\n\ndef f(prices):\n    return [p + p * RATE for p in prices]\n"
    ok(b, p)
    ok(p, b)


def test_filtered_append_loop_to_comprehension():
    b = "def f(xs):\n    out = []\n    for x in xs:\n        if x:\n            out.append(x)\n    return out\n"
    ok(b, "def f(xs):\n    return [x for x in xs if x]\n")


@pytest.mark.parametrize("post", [
    "def f(xs):\n    out = []\n    for x in xs:\n        out.append(x)\n        out.append(x)\n    return out\n",     # two appends
    "def f(xs):\n    out = []\n    for x in xs:\n        out.append(x)\n    return out + [x]\n",                   # loop variable read after the loop
    "def f(xs):\n    out = []\n    for x in xs:\n        if x:\n            break\n        out.append(x)\n    return out\n",
    "def f(xs):\n    out = []\n    for x in xs:\n        out.append(len(out))\n    return out\n",                    # the body reads the list being built
    "def f(xs):\n    out = []\n    for x in xs:\n        out.append(x)\n    else:\n        out.append(0)\n    return out\n",
    "def f(xs):\n    out = ()\n    for x in xs:\n        out += (x,)\n    return list(out)\n",
])
def test_comp_refuses_unsound_variants(post):
    no("def f(xs):\n    return [x for x in xs]\n", post)


# ----------------------------------------------------------------------------------------------- T-fmt
def test_format_to_fstring_with_pure_trailing_arguments():
    b = "def f(sku, slug):\n    return '{}:{}'.format(sku.upper(), slug)\n"
    ok(b, "def f(sku, slug):\n    return f'{sku.upper()}:{slug}'\n")
    ok("def f(a, b):\n    return '{0}-{1}-{0}'.format(a, b)\n", "def f(a, b):\n    return f'{a}-{b}-{a}'\n")


@pytest.mark.parametrize("b,p", [
    ("def f(a, b):\n    return '{}{}'.format(a(), b())\n", "def f(a, b):\n    return f'{a()}{b()}'\n"),                # two calls: order of formatting vs evaluation
    ("def f(a, b):\n    return '{:>5}{}'.format(a, b)\n", "def f(a, b):\n    return f'{a:>5}{b}'\n"),                  # format spec
    ("def f(a, b):\n    return '{!r}{}'.format(a, b)\n", "def f(a, b):\n    return f'{a!r}{b}'\n"),                    # conversion
    ("def f(a, b):\n    return '{}{}'.format(a, b)\n", "def f(a, b):\n    return f'{b}{a}'\n"),                           # swapped
    ("def f(a, b):\n    return '{x}'.format(x=a)\n", "def f(a, b):\n    return f'{a}'\n"),                               # keyword field is outside the rule
])
def test_fmt_refuses_unsound_variants(b, p):
    no(b, p)


# ----------------------------------------------------------------------------------------------- the rule never launders a real change
@pytest.mark.parametrize("post", [
    "def f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return total + fee\n",                       # tax dropped
    "def f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    tax = total * RATE * 2\n    return total + tax + fee\n",
])
def test_real_behaviour_changes_stay_refused(post):
    b = "RATE = 0.2\n\n\ndef f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return total + total * RATE + fee\n"
    no(b, "RATE = 0.2\n\n\n" + post)


# ----------------------------------------------------------------------------------------------- the file-based entry point (certify) applies NORM too
def test_file_based_certify_applies_norm_and_keeps_the_original_source_hashes(tmp_path):
    import hashlib

    b = "RATE = 0.2\n\n\ndef f(total, fee):\n    return total + total * RATE + fee\n"
    p = "RATE = 0.2\n\n\ndef f(total, fee):\n    tax = total * RATE\n    return total + tax + fee\n"
    for side, src in (("base", b), ("post", p)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg/__init__.py").write_text("")
        (tmp_path / side / "pkg/m.py").write_text(src)
    r = ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f")
    assert r.ok and r.rules[0] == "NORM", (r.reason, r.detail)
    assert "normalized:" in r.detail
