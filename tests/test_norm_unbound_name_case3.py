"""No positive certificate when a rewrite forgets that a name was UNBOUND (independent verification class B: `except ... as x` unbinds x)."""

import pytest

from hlith.obligation import equiv_cert
from test_slice_gap_case3 import KEY, build, observed

TRUTH = f"from pkg.mod import f\nprint(f({KEY}))"
HEAD = "from pkg.key import KEY\n\n\ndef f(n):\n    x = n\n    if n == KEY:\n        try:\n            raise ValueError\n        except ValueError as x:\n            pass\n"
STAR = "from pkg.key import KEY\n\n\ndef f(n):\n    x = n\n    if n == KEY:\n        try:\n            raise ExceptionGroup('g', [ValueError()])\n        except* ValueError as x:\n            pass\n"
DEL = "from pkg.key import KEY\n\n\ndef f(n):\n    x = n\n    if n == KEY:\n        del x\n"
ZERO = "def _zero(a):\n    return 0\n\n\n"


def pair(base, post):
    return {"base": {"pkg/__init__.py": "", "pkg/key.py": f"KEY = {KEY}\n", "pkg/mod.py": base}, "post": {"pkg/mod.py": post}, "links": {}}


CASES = {
    "n01_dead_read_of_except_name": pair(HEAD + "    y = x\n    return n\n", HEAD + "    return n\n"),
    "n02_helper_arg_read_of_except_name": pair(ZERO + HEAD + "    return _zero(x)\n", ZERO + HEAD + "    return 0\n"),
    "u01_dead_read_after_except_star": pair(STAR + "    y = x\n    return n\n", STAR + "    return n\n"),
    "u02_helper_arg_after_except_star": pair(ZERO + STAR + "    return _zero(x)\n", ZERO + STAR + "    return 0\n"),
    "u03_dead_read_after_conditional_del": pair(DEL + "    y = x\n    return n\n", DEL + "    return n\n"),
    "u04_helper_arg_after_conditional_del": pair(ZERO + DEL + "    return _zero(x)\n", ZERO + DEL + "    return 0\n"),
}

TOP = "from pkg.key import KEY\n\n\ndef f(n):\n    x = n\n"
RAISE = "        try:\n            raise ValueError\n"
SHAPES = {
    "nested": TOP + "    if n == KEY:\n        try:\n            try:\n                raise ValueError\n            except ValueError as x:\n                pass\n        except TypeError:\n            pass\n",
    "inside_handler": TOP + "    if n == KEY:\n        try:\n            raise KeyError\n        except KeyError:\n            try:\n                raise ValueError\n            except ValueError as x:\n                pass\n",
    "second_handler": TOP + "    if n == KEY:\n" + RAISE + "        except TypeError as t:\n            pass\n        except ValueError as x:\n            pass\n",
    "with_finally": TOP + "    if n == KEY:\n" + RAISE + "        except ValueError as x:\n            pass\n        finally:\n            n = n + 0\n",
    "in_loop": TOP + "    for _i in (1, 2):\n        if n == KEY:\n            try:\n                raise ValueError\n            except ValueError as x:\n                pass\n",
    "unbound_parameter": "from pkg.key import KEY\n\n\ndef f(n, x=0):\n    if n == KEY:\n" + RAISE + "        except ValueError as x:\n            pass\n",
}
for shape, head in SHAPES.items():
    CASES[f"u05_{shape}_dead_read"] = pair(head + "    y = x\n    return n\n", head + "    return n\n")
    CASES[f"u06_{shape}_helper_arg"] = pair(ZERO + head + "    return _zero(x)\n", ZERO + head + "    return 0\n")
CASES["u07_return_in_finally_helper_arg"] = pair(
    ZERO + HEAD + "    try:\n        pass\n    finally:\n        return _zero(x)\n", ZERO + HEAD + "    try:\n        pass\n    finally:\n        return 0\n")
CASES["u08_dead_read_inside_finally"] = pair(
    HEAD + "    try:\n        pass\n    finally:\n        y = x\n    return n\n", HEAD + "    try:\n        pass\n    finally:\n        pass\n    return n\n")

# controls: a handler that binds ANOTHER name leaves the rewrites available
OK = "from pkg.key import KEY\n\n\ndef f(n):\n    x = n\n    if n == KEY:\n        try:\n            raise ValueError\n        except ValueError as e:\n            pass\n"
CONTROLS = {
    "c01_dead_read_with_other_handler_name": pair(OK + "    y = x\n    return n\n", OK + "    return n\n"),
    "c02_helper_arg_with_other_handler_name": pair(ZERO + OK + "    return _zero(x)\n", ZERO + OK + "    return 0\n"),
    "c03_dead_read_without_handler": pair("def f(n):\n    x = n\n    y = x\n    return n\n", "def f(n):\n    x = n\n    return n\n"),
}


@pytest.mark.parametrize("name", sorted(CONTROLS))
def test_control_rewrites_stay_available(tmp_path, name):
    base, post = build(tmp_path, CONTROLS[name])
    assert observed(base, TRUTH) == observed(post, TRUTH)
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert cert.ok, cert.reason


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_read_of_an_unbound_name_is_never_deleted(tmp_path, name):
    base, post = build(tmp_path, CASES[name])
    b, p = observed(base, TRUTH), observed(post, TRUTH)
    assert b != p, f"vacuous case: plain Python agrees ({b!r})"
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert not cert.ok, (cert.rules, cert.detail)
