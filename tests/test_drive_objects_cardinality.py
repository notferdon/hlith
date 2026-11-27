# SPDX-License-Identifier: Apache-2.0
"""Operand kinds. len() of a TEXT is encoding-sensitive; len() of a tuple/list/dict/exception.args is a
CARDINALITY and is not. Unknown stays encoding-sensitive (conservative). Plus exception candidates that vary the argument count and
the builtin class. A candidate is a hint (exact False); the real evaluators decide what it covers."""
import ast
import textwrap

import pytest

from hlith.drive_objects import exception_param_candidates, len_is_encoding_sensitive, operand_kind


def _fn(src):
    return ast.parse(textwrap.dedent(src)).body[0]


def _first_len(fn):
    return next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "len")


@pytest.mark.parametrize("src,kind", [
    ("def f(err):\n    return len(err.args)\n", "cardinality"),
    ("def f(s: str):\n    return len(s)\n", "text"),
    ("def f(b: bytes):\n    return len(b)\n", "text"),
    ("def f(t: tuple):\n    return len(t)\n", "cardinality"),
    ("def f(t: tuple[int, ...]):\n    return len(t)\n", "cardinality"),
    ("def f(t: list[str]):\n    return len(t)\n", "cardinality"),
    ("def f(d: dict):\n    return len(d)\n", "cardinality"),
    ("def f(x):\n    y = (1, 2)\n    return len(y)\n", "cardinality"),
    ("def f(x):\n    y = [i for i in x]\n    return len(y)\n", "cardinality"),
    ("def f(x):\n    y = ','.join(x)\n    return len(y)\n", "text"),
    ("def f(x):\n    y = str(x)\n    return len(y)\n", "text"),
    ("def f(x):\n    return len(x.decode())\n", "text"),
    ("def f(x):\n    return len(f'{x}')\n", "text"),
    ("def f(x):\n    return len(x)\n", "unknown"),
    ("def f(x):\n    y = (1,)\n    y = str(x)\n    return len(y)\n", "unknown"),
    ("def f(x):\n    return len(x.keys())\n", "cardinality"),
    ("def f(x):\n    return len(list(x))\n", "cardinality"),
    ("def f(x: str):\n    return len(x[1:])\n", "text"),
    ("def f(x):\n    return len(x.split(','))\n", "cardinality"),
])
def test_operand_kinds(src, kind):
    fn = _fn(src)
    assert operand_kind(_first_len(fn).args[0], fn) == kind


def test_len_is_encoding_sensitive_only_for_text_and_unknown():
    for src, want in (("def f(err):\n    return len(err.args)\n", False), ("def f(s: str):\n    return len(s)\n", True),
                      ("def f(x):\n    return len(x)\n", True), ("def f(t: tuple):\n    return len(t)\n", False)):
        fn = _fn(src)
        assert len_is_encoding_sensitive(_first_len(fn), fn) is want, src


def test_exception_param_candidates_vary_argument_count_and_builtin_class():
    fn = _fn('''
        def f(err):
            if len(err.args) > 1:
                return "many"
            if isinstance(err, OSError):
                return "os"
            return "other"
    ''')
    cands = exception_param_candidates(fn)
    assert cands and all(c["param"] == "err" and c["exact"] is False for c in cands)
    counts = {len(c["value"]["args"]) for c in cands}
    assert {0, 1, 2, 3} <= counts
    types = {c["value"]["__hlith_exc__"] for c in cands}
    assert "builtins.OSError" in types and "builtins.Exception" in types
    assert all(c["value"].keys() == {"__hlith_exc__", "args"} for c in cands)
    # the OSError(errno, strerror) shape is among them
    assert any(c["value"]["__hlith_exc__"] == "builtins.OSError" and c["value"]["args"][:1] == [2] for c in cands)


def test_unresolvable_exception_class_is_reported_not_guessed():
    fn = _fn("def f(err):\n    return isinstance(err, mylib.ReadTimeoutError)\n")
    cands = exception_param_candidates(fn)
    real = [c for c in cands if c.get("value") is not None]
    assert real and all(c["value"]["__hlith_exc__"].startswith("builtins.") for c in real)
    un = [c for c in cands if c.get("unmodeled")]
    assert len(un) == 1 and "mylib.ReadTimeoutError" in un[0]["unmodeled"] and un[0]["value"] is None and un[0]["exact"] is False


def test_a_param_not_used_as_an_exception_gets_no_exception_candidates():
    assert exception_param_candidates(_fn("def f(x):\n    return x + 1\n")) == []
