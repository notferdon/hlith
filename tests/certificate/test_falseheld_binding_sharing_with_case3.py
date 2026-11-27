# SPDX-License-Identifier: Apache-2.0
"""review 2026-11-25, case: certificate-level false-HELD classes witnessed on 13d28535.

Every RED case is a program pair whose DIVERGENCE is executed here (a case cannot pass vacuously) and which the certificate must refuse:
 (1) module binding: a name the proof trusts as a local def / builtin is bound again (import, star, match, except branch, namespace write, foreign rebind);
 (2) object sharing: a returned / retained structure shares a mutable object on one side only;
 (3) append loop -> comprehension where the raising exception can be swallowed inside the function;
 (4) a temporary moved across a `*` / `**` unpack.
The CONTROLS are equivalent pairs that must keep their certificate: the repairs are restrict-only, so these measure lost positives."""

from __future__ import annotations

import subprocess
import sys

import pytest

from hlith.obligation import equiv_cert

OTHER = "def _scale(a):\n    return 0\n\n\ndef sum(a):\n    return 1\n"
STAR = "def _scale(a):\n    return 0\n\n\n__all__ = ['_scale']\n"
RED: dict = {}
GREEN: dict = {}


def red(name, base, post, expr, extra=None):
    RED[name] = (base, post, expr, extra or {})


def green(name, base, post, expr):
    GREEN[name] = (base, post, expr, {})


# ------------------------------------------------------------------------------------------------------------------ (1) binding
_DEF = "def _scale(a):\n    return a * 2\n\n\n"


def bind(name, rebinding, extra=None):
    pre = _DEF + rebinding + "\n\n\n"
    red("bind_" + name, pre + "def f(x):\n    return _scale(x)\n", pre + "def f(x):\n    return x * 2\n", "m.f(5)", extra)


bind("from_import", "from pkg.other import _scale")
bind("try_import", "try:\n    from pkg.other import _scale\nexcept ImportError:\n    pass")
bind("import_as", "from pkg.other import sum as _scale")
bind("star_import", "from pkg.star import *")
bind("match_capture", "import pkg.other as o\nmatch o._scale:\n    case _scale:\n        pass")
bind("except_branch_import", "try:\n    raise ImportError\nexcept ImportError:\n    from pkg.other import _scale")
bind("globals_subscript", "import pkg.other as o\nglobals()['_scale'] = o._scale")
bind("setattr_module", "import sys as _sys\nsetattr(_sys.modules[__name__], '_scale', lambda a: 0)")
bind("exec", "exec('_scale = lambda a: 0')")
bind("assign", "import pkg.other as o\n_scale = o._scale")
bind("nested_def", "if True:\n    def _scale(a):\n        return 0")
bind("foreign_rebind", "import pkg.patcher", {"pkg/patcher.py": "import sys\n\nm = sys.modules['pkg.m']\nm._scale = lambda a: 0\n"})
# the rebinding module is imported by the package, not by the module under proof
red("bind_foreign_rebind_from_package", _DEF + "def f(x):\n    return _scale(x)\n", _DEF + "def f(x):\n    return x * 2\n", "m.f(5)",
    {"pkg/__init__.py": "import pkg.m\n\npkg.m._scale = lambda a: 0\n"})
_TW = "from pkg import other\n\n\ndef _fee(a):\n    return a * 2\n\n\n_fee = other._scale\n\n\ndef _twice(a):\n    return a * 2\n\n\n"
red("bind_def_then_assign_twin", _TW + "def f(x):\n    return _fee(x)\n", _TW + "def f(x):\n    return _twice(x)\n", "m.f(5)")
_SUM_LOOP = "def f(xs: tuple[int, ...]) -> int:\n    t = 0\n    for v in xs:\n        t += v\n    return t\n"
_SUM_CALL = "def f(xs: tuple[int, ...]) -> int:\n    return sum(xs)\n"
for _n, _h in {"sum_from_import": "from pkg.other import sum\n\n\n", "sum_star_import": "from pkg.starsum import *\n\n\n"}.items():
    red("bind_" + _n, _h + _SUM_LOOP, _h + _SUM_CALL, "m.f((5, 1))", {"pkg/starsum.py": "def sum(a):\n    return 1\n"})
red("bind_sum_foreign_rebind", "import pkg.patcher\n\n\n" + _SUM_LOOP, "import pkg.patcher\n\n\n" + _SUM_CALL, "m.f((5, 1))",
    {"pkg/patcher.py": "import sys\n\nm = sys.modules['pkg.m']\nm.sum = lambda a: 1\n"})

# ------------------------------------------------------------------------------------------------------------------ (2) sharing
_M0 = "(lambda r: (r[0].append(9), r)[1])(m.f(1))"
_SHARED = "def f(n: int) -> list[list[int]]:\n    row = [n]\n    return [row, row]\n"
_FRESH = "def f(n: int) -> list[list[int]]:\n    return [[n], [n]]\n"
red("share_list", _SHARED, _FRESH, _M0)
red("share_reverse", _FRESH, _SHARED, _M0)
red("share_tuple", "def f(n: int):\n    row = [n]\n    return (row, row)\n", "def f(n: int):\n    return ([n], [n])\n", _M0)
red("share_dict", "def f(n: int):\n    row = [n]\n    return {0: row, 1: row}\n", "def f(n: int):\n    return {0: [n], 1: [n]}\n", _M0)
red("share_depth2", "def f(n: int):\n    row = [n]\n    return [[row], [row]]\n", "def f(n: int):\n    return [[[n]], [[n]]]\n",
    "(lambda r: (r[0][0].append(9), r)[1])(m.f(1))")
red("share_append", "def f(n: int):\n    row = [n]\n    out = []\n    out.append(row)\n    out.append(row)\n    return out\n",
    "def f(n: int):\n    out = []\n    out.append([n])\n    out.append([n])\n    return out\n", _M0)
red("share_comprehension", "def f(n: int):\n    row = [n]\n    return [row for _ in range(2)]\n", "def f(n: int):\n    return [[n] for _ in range(2)]\n", _M0)
red("share_sets", "def f(n: int):\n    s = {n}\n    return [s, s]\n", "def f(n: int):\n    return [{n}, {n}]\n", "(lambda r: (r[0].add(9), r)[1])(m.f(1))")
red("share_untyped", "def f(n):\n    row = [n]\n    return [row, row]\n", "def f(n):\n    return [[n], [n]]\n", _M0)
red("share_repeat", "def f(n: int):\n    return [[n]] * 2\n", "def f(n: int):\n    return [[n], [n]]\n", _M0)
_M1 = "(lambda r: (r[1].append(9), r)[1])(m.f([0], 1))"
red("share_external_plus_fresh", "def f(xs: list[int], n: int):\n    row = [n]\n    return (xs, row, row)\n",
    "def f(xs: list[int], n: int):\n    return (xs, [n], [n])\n", _M1)
red("share_flat_retained_in_param", "def f(sink: list, n: int):\n    row = [n]\n    sink.append(row)\n    return row\n",
    "def f(sink: list, n: int):\n    row = [n]\n    sink.append(row)\n    return [n]\n", "(lambda s: (m.f(s, 1).append(9), s)[1])([])")
red("share_flat_retained_in_dict", "def f(sink: dict, n: int):\n    row = [n]\n    sink[0] = row\n    return row\n",
    "def f(sink: dict, n: int):\n    sink[0] = [n]\n    return [n]\n", "(lambda s: (m.f(s, 1).append(9), s)[1])({})")
red("share_exception_args", "def f(n: int):\n    row = [n]\n    raise ValueError(row, row)\n", "def f(n: int):\n    raise ValueError([n], [n])\n",
    "(lambda e: (e[0].append(9), e)[1])(__import__('pkg.catch', fromlist=['args']).args(m.f, 1))",
    {"pkg/catch.py": "def args(fn, *a):\n    try:\n        fn(*a)\n    except ValueError as e:\n        return e.args\n"})
red("share_yield", "def f(n: int):\n    row = [n]\n    yield row\n    yield row\n", "def f(n: int):\n    yield [n]\n    yield [n]\n",
    "(lambda r: (r[0].append(9), r)[1])(list(m.f(1)))")

# independent verification shapes (review): two distinct objects collapsed into one, also through a rebinding alias
red("share_tuple_of_aliases", "def f(n: int) -> tuple:\n    a = [n]\n    b = [n]\n    return (a, b)\n", "def f(n: int) -> tuple:\n    a = [n]\n    return (a, a)\n", _M0)
_AL = "def f(xs: list[int]) -> tuple:\n    out = list(xs)\n"
red("share_rebinding_alias", _AL + "    res = list(xs)\n    return (out, res)\n", _AL + "    res = out\n    return (out, res)\n",
    "(lambda r: (r[0].append(9), r)[1])(m.f([1]))")

# sharing observed by opaque code: two distinct local lists against one list passed twice
_PROBE = "(lambda g: m.f(g, 1))(lambda a, b: a is b)"
_TWO = "def f(g, n: int):\n    a = [n]\n    b = [n]\n    return g(a, b)\n"
red("share_call_args", _TWO, "def f(g, n: int):\n    a = [n]\n    return g(a, a)\n", _PROBE)
red("share_call_args_literals", "def f(g, n: int):\n    return g([n], [n])\n", "def f(g, n: int):\n    a = [n]\n    return g(a, a)\n", _PROBE)
red("share_call_kwargs", "def f(g, n: int):\n    return g(a=[n], b=[n])\n", "def f(g, n: int):\n    r = [n]\n    return g(a=r, b=r)\n", _PROBE)
_SEQ = "(lambda seen: (m.f(seen.append, 1), seen[0] is seen[1])[1])([])"
red("share_sequential_calls", "def f(g, n: int):\n    a = [n]\n    b = [n]\n    g(a)\n    g(b)\n",
    "def f(g, n: int):\n    a = [n]\n    g(a)\n    g(a)\n", _SEQ)

# two lists handed to ONE opaque call, then returned: they stay two objects
_BOX = "def f(g, n: int):\n    a = [n]\n    b = [n]\n    g(a, b)\n"
_USE = "(lambda r: (r[0].append(9), r[1])[1])(m.f(lambda a, b: None, 1))"
red("share_after_one_call_tuple", _BOX + "    return (a, b)\n", _BOX + "    return (a, a)\n", _USE)
red("share_after_one_call_list", _BOX + "    return [a, b]\n", _BOX + "    return [a, a]\n", _USE)
red("share_after_one_call_flat", _BOX + "    return a\n", _BOX + "    return b\n",
    "(lambda seen: (m.f(lambda a, b: seen.extend((a, b)), 1).append(9), seen)[1])([])")
red("share_after_one_call_second_call", _BOX + "    g(a, a)\n", _BOX + "    g(b, b)\n",
    "(lambda seen: (m.f(lambda a, b: seen.extend((a, b)), 1), [x is seen[0] for x in seen])[1])([])")

# ------------------------------------------------------------------------------------------------------------------ (3) swallowed exception
_W = "import contextlib\n\n\ndef _q(v):\n    return 100 // v\n\n\n"
_L12 = "            out = []\n            for v in items:\n                out.append(_q(v))\n"
_C12 = "            out = [_q(v) for v in items]\n"
_L8 = "        out = []\n        for v in items:\n            out.append(_q(v))\n"
_C8 = "        out = [_q(v) for v in items]\n"
_E = "repr(m.f([1, 0]))"
_t = _W + "def f(items):\n    with contextlib.suppress(ZeroDivisionError):\n{}    return out\n"
red("with_suppress", _t.format(_L8), _t.format(_C8), _E)
_t2 = _W + "def f(items):\n    with contextlib.suppress(ZeroDivisionError):\n        if items:\n{}    return out\n"
red("with_if", _t2.format(_L12), _t2.format(_C12), _E)
_t3 = _W + "def f(items, cm):\n    with cm:\n{}    return out\n"
red("with_param_manager", _t3.format(_L8), _t3.format(_C8), "repr(m.f([1, 0], __import__('contextlib').suppress(ZeroDivisionError)))")

# the same swallow through `finally: return`, from the else branch and from a handler (no enclosing try)
_F = _W + "def f(items):\n    try:\n{}    finally:\n        return out\n"
for _n, _head in (("finally_return_orelse", "        pass\n    except ValueError:\n        pass\n    else:\n"),
                  ("finally_return_handler", "        raise ValueError\n    except ValueError:\n")):
    red("with_" + _n, _F.format(_head + _L8), _F.format(_head + _C8), _E)
# a swallowing block nested under the manager: the flag has to be inherited
_t4 = _W + "def f(items, flag=1):\n    with contextlib.suppress(ZeroDivisionError):\n        while flag:\n{}            break\n    return out\n"
red("with_nested_loop", _t4.format(_L12), _t4.format(_C12), _E)

# ------------------------------------------------------------------------------------------------------------------ (4) unpack order
_KEY = "chr(122) + chr(113) + chr(55)"
red("unpack_dict", f"def f(opts):\n    taken = opts.pop({_KEY}, None)\n    return {{**opts, 'taken': taken}}\n",
    f"def f(opts):\n    return {{**opts, 'taken': opts.pop({_KEY}, None)}}\n", "m.f({'zq7': 1, 'a': 2})")
for _n, _disp, _call in (("unpack_list", "[*xs, t]", "[*xs, xs.pop()]"), ("unpack_tuple", "(*xs, t)", "(*xs, xs.pop())"),
                         ("unpack_set_then_len", "len([0, *xs, t])", "len([0, *xs, xs.pop()])")):
    red(_n, f"def f(xs):\n    t = xs.pop()\n    return {_disp}\n", f"def f(xs):\n    return {_call}\n", "m.f([1, 2])")

_N = "def _n(*a):\n    return len(a)\n\n\n"
red("unpack_call_args", _N + "def f(xs):\n    t = xs.pop()\n    return _n(*xs, t)\n", _N + "def f(xs):\n    return _n(*xs, xs.pop())\n", "m.f([1, 2])")

# ------------------------------------------------------------------------------------------------------------------ controls (must stay certified)
green("temp", "def f(x):\n    t = x + 1\n    return t\n", "def f(x):\n    return x + 1\n", "m.f(5)")
green("extract_helper", "def f(x):\n    return x * 2\n", _DEF + "def f(x):\n    return _scale(x)\n", "m.f(5)")
green("imports_used_normally", "import os\n\n\ndef f(x):\n    t = os.fspath(x)\n    return t\n", "import os\n\n\ndef f(x):\n    return os.fspath(x)\n", "m.f('a')")
green("sum_loop_typed", _SUM_LOOP, _SUM_CALL, "m.f((5, 1))")
green("comp_outside_with", _W + "def f(items):\n    out = []\n    for v in items:\n        out.append(_q(v))\n    return out\n",
      _W + "def f(items):\n    out = [_q(v) for v in items]\n    return out\n", "m.f([1, 2])")
green("temp_before_unpack_free_display", "def f(o):\n    t = o.pop()\n    return [1, t]\n", "def f(o):\n    return [1, o.pop()]\n", "m.f([1, 2])")
green("sym_immutable_sharing", "def f(n: int):\n    row = (n,)\n    return [row, row]\n", "def f(n: int):\n    return [(n,), (n,)]\n", "m.f(1)")
green("sym_flat_fresh_list", "def f(n: int) -> list[int]:\n    a = n\n    return [a, n]\n", "def f(n: int) -> list[int]:\n    return [n, n]\n", "m.f(1)")

_RUN = ("import sys; sys.path.insert(0, '.'); import pkg.m as m\ntry:\n    print(repr(eval({e!r})))\n"
        "except BaseException as x:\n    print('raised', type(x).__name__)\n")


def _build(tmp_path, case):
    base, post, expr, extra = case
    truth = []
    for side, body in (("base", base), ("post", post)):
        root = tmp_path / side
        files = {"pkg/__init__.py": "", "pkg/other.py": OTHER, "pkg/star.py": STAR, "pkg/m.py": body, **extra}
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        r = subprocess.run([sys.executable, "-B", "-c", _RUN.format(e=expr)], cwd=root, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        truth.append(r.stdout.strip())
    return truth, equiv_cert.certify(str(tmp_path / "base"), str(tmp_path / "post"), "pkg.m", "f")


@pytest.mark.parametrize("name", sorted(RED))
def test_a_real_divergence_is_never_certified(tmp_path, name):
    truth, cert = _build(tmp_path, RED[name])
    assert truth[0] != truth[1], f"{name}: vacuous fixture, both sides observe {truth[0]}"
    assert not cert.ok, (name, cert.rules, cert.detail, truth)


@pytest.mark.parametrize("name", sorted(GREEN))
def test_an_equivalent_control_keeps_its_certificate(tmp_path, name):
    truth, cert = _build(tmp_path, GREEN[name])
    assert truth[0] == truth[1], f"{name}: control diverges (fixture bug): {truth}"
    assert cert.ok, (name, cert.reason, cert.detail)
