# SPDX-License-Identifier: Apache-2.0
"""Empirical soundness of NORM (and ANN / G1): every pair the certificate ADMITS is EXECUTED on a hostile-object matrix (operators and iteration that log and may raise, __format__ / __bool__ /
__iter__ with side effects, NaN, a str subclass with overridden methods, bytes, None, mutable lists) and the two versions must agree on result, exception TYPE AND MESSAGE, and the full
side-effect log. A single divergence on an admitted pair would be a false certificate. The pairs are the positive cases of test_equiv_norm / the G1 / G2 suites, written once here."""

from __future__ import annotations

import itertools
import math

import pytest

from hlith.obligation import equiv_cert as ec

LOG: list = []


class Spy:
    """Logs every protocol operation; arithmetic returns a new Spy so operator ORDER and COUNT are observable."""

    def __init__(self, tag):
        self.tag = tag

    def _op(self, name, other=None):
        LOG.append((name, self.tag, getattr(other, "tag", other)))
        return Spy(f"({self.tag}{name}{getattr(other, 'tag', other)})")

    def __add__(self, o): return self._op("+", o)
    def __radd__(self, o): return self._op("r+", o)
    def __mul__(self, o): return self._op("*", o)
    def __rmul__(self, o): return self._op("r*", o)
    def __gt__(self, o): LOG.append((">", self.tag, getattr(o, "tag", o))); return len(LOG) % 2 == 0
    def __lt__(self, o): LOG.append(("<", self.tag, getattr(o, "tag", o))); return len(LOG) % 3 == 0
    def __bool__(self): LOG.append(("bool", self.tag)); return len(LOG) % 2 == 1
    def __format__(self, spec): LOG.append(("fmt", self.tag, spec)); return f"<{self.tag}>"
    def __iter__(self): LOG.append(("iter", self.tag)); return iter([Spy(self.tag + "0"), Spy(self.tag + "1")])
    def __len__(self): LOG.append(("len", self.tag)); return 2
    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        LOG.append(("attr", self.tag, n))
        return lambda *a: Spy(f"{self.tag}.{n}")
    def __repr__(self): return f"Spy({self.tag})"


class StrSub(str):
    def upper(self): LOG.append(("upper-override",)); return "UP"
    def strip(self, *a): LOG.append(("strip-override",)); return str.strip(self, *a)
    def title(self): LOG.append(("title-override",)); return "Ti"
    def __format__(self, spec): LOG.append(("fmt-str-sub",)); return "SUB"


POOL = [lambda: 0, lambda: 7, lambda: 1.5, lambda: float("nan"), lambda: "ab", lambda: None, lambda: b"x", lambda: [1, 2], lambda: (3, 4),
        lambda: Spy("a"), lambda: Spy("b"), lambda: StrSub("x"), lambda: iter([1, 2, 3]), lambda: -0.0]


def outcome(src, fn, factories, extra_globals=None):
    ns = dict(extra_globals or {})
    exec(src, ns)
    LOG.clear()
    args = [f() for f in factories]
    try:
        r = ("ret", repr(ns[fn](*args)))
    except BaseException as e:  # noqa: BLE001
        r = ("raise", type(e).__name__, str(e))
    import re

    return re.sub(r"0x[0-9a-f]+", "0x", repr((r, list(LOG))))  # reprs: no object addresses; NaN compared by repr (nan != nan)


def run_matrix(base, post, fn, nparams, pool=POOL):
    n = 0
    for combo in itertools.product(range(len(pool)), repeat=nparams):
        fs = [pool[i] for i in combo]
        a, b = outcome(base, fn, fs), outcome(post, fn, fs)
        assert a == b, (combo, a, b)
        n += 1
    return n


PAIRS = {
    "inline-extract": ("RATE = 0.2\n\n\ndef f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return total + total * RATE + fee\n",
                       "RATE = 0.2\n\n\ndef _with_tax(amount):\n    return amount + amount * RATE\n\n\ndef f(prices, fee):\n    total = 0\n    for p in prices:\n        total += p\n    return _with_tax(total) + fee\n", 2),
    "split-function": ("def f(name, qty, unit):\n    total = qty * unit\n    return name.strip().title() + ': ' + str(total)\n",
                       "def _fmt(name):\n    return name.strip().title()\n\n\ndef f(name, qty, unit):\n    total = qty * unit\n    return _fmt(name) + ': ' + str(total)\n", 3),
    "early-return": ("def f(w):\n    if w > 20:\n        return 15\n    return 5\n",
                     "def f(w):\n    if w > 20:\n        fee = 15\n    else:\n        fee = 5\n    return fee\n", 1),
    "elif-chain": ("def f(w):\n    if w > 20:\n        return 15\n    elif w > 10:\n        return 9\n    else:\n        return 5\n",
                   "def f(w):\n    if w > 20:\n        fee = 15\n    elif w > 10:\n        fee = 9\n    else:\n        fee = 5\n    return fee\n", 1),
    "temp-subexpr": ("RATE = 0.2\n\n\ndef f(total, fee):\n    return total + total * RATE + fee\n",
                     "RATE = 0.2\n\n\ndef f(total, fee):\n    tax = total * RATE\n    return total + tax + fee\n", 2),
    "temp-call": ("def g(x):\n    return x\n\n\ndef f(a, b):\n    return a + g(b)\n", "def g(x):\n    return x\n\n\ndef f(a, b):\n    t = g(b)\n    return a + t\n", 2),
    "dead-binding": ("def f(a):\n    return a + 1\n", "def f(a):\n    unused = 5\n    alias = a\n    return a + 1\n", 1),
    "append-loop": ("RATE = 0.2\n\n\ndef f(prices):\n    out = []\n    for p in prices:\n        out.append(p + p * RATE)\n    return out\n",
                    "RATE = 0.2\n\n\ndef f(prices):\n    return [p + p * RATE for p in prices]\n", 1),
    "filtered-append": ("def f(xs):\n    out = []\n    for x in xs:\n        if x:\n            out.append(x)\n    return out\n", "def f(xs):\n    return [x for x in xs if x]\n", 1),
    "format-fstring": ("def f(sku, slug):\n    return '{}:{}'.format(sku.upper(), slug)\n", "def f(sku, slug):\n    return f'{sku.upper()}:{slug}'\n", 2),
    "format-repeat": ("def f(a, b):\n    return '{0}-{1}-{0}'.format(a, b)\n", "def f(a, b):\n    return f'{a}-{b}-{a}'\n", 2),
    "annotations": ("def f(weight, label='x'):\n    if weight > 20:\n        return 15\n    return 5\n",
                    "def f(weight: float, label: str = 'x') -> int:\n    if weight > 20:\n        return 15\n    return 5\n", 1),
    "float-constant-rename": ("RATE = 0.2\n\n\ndef f(price, fee):\n    total = price\n    return total + total * RATE + fee\n",
                              "RATE = 0.2\n\n\ndef f(price, fee):\n    subtotal = price\n    return subtotal + subtotal * RATE + fee\n", 2),
}


@pytest.mark.parametrize("name", sorted(PAIRS))
def test_every_admitted_pair_is_executed_equal_on_the_hostile_matrix(name):
    base, post, n = PAIRS[name]
    c = ec.certify_sources(base, post, "f", module="m")
    assert c.ok, (name, c.reason, c.detail)  # the pair really is admitted ...
    total = run_matrix(base, post, "f", n)  # ... and really is equal on every hostile combination
    assert total >= len(POOL)


def test_the_matrix_can_detect_a_difference():
    """Control: the matrix is not vacuous. Two versions that differ only in operator ORDER or COUNT diverge on the Spy objects."""
    a = "def f(a, b):\n    return a + b * a\n"
    b = "def f(a, b):\n    t = b * a\n    return a + t\n"  # same order here (admitted by NORM), but...
    c = "def f(a, b):\n    t = b * a\n    return a + t + t - t\n"
    with pytest.raises(AssertionError):
        run_matrix(a, c, "f", 2)
    assert run_matrix(a, b, "f", 2) > 0
