# SPDX-License-Identifier: Apache-2.0
"""G2: ANNOTATION-ONLY signature edits (rule id ANN). What it proves: the canonical form of every changed unit is identical once parameter and return annotations are removed (so names, kinds,
defaults, decorators and the body are identical), AND the removed annotation expressions are runtime-neutral: (i) evaluating them at definition time can neither raise nor have an effect
(builtin type names that the module does not rebind, None, string forward references, `|`, subscripts of those, and names imported from typing/collections.abc; or ANY expression when the module
has `from __future__ import annotations`, which never evaluates them), and (ii) nothing in the analysed tree CONSUMES annotations at runtime (no `__annotations__`, get_type_hints,
get_annotations, inspect/signature, singledispatch, dataclasses, pydantic, attrs, typeguard, beartype, fastapi, msgspec, cattrs, marshmallow). Side condition for callers outside the tree: an
external introspector reading annotations is outside the claim, said in the sentence. No input-type assumption."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec

BASE = "def f(weight, label='x'):\n    if weight > 20:\n        return 15\n    return 5\n"


def cert(b, p, fn="f"):
    return ec.certify_sources(b, p, fn, module="m")


@pytest.mark.parametrize("post", [
    "def f(weight: float, label: str = 'x') -> int:\n    if weight > 20:\n        return 15\n    return 5\n",
    "def f(weight: int | float, label: 'str' = 'x') -> 'int':\n    if weight > 20:\n        return 15\n    return 5\n",
    "def f(weight: list[float], label: str = 'x') -> tuple[int, ...]:\n    if weight > 20:\n        return 15\n    return 5\n",
    "def f(weight: None, label: bytes = 'x') -> object:\n    if weight > 20:\n        return 15\n    return 5\n",
    "from typing import Optional\n\n\ndef f(weight: Optional[int], label='x') -> Optional[int]:\n    if weight > 20:\n        return 15\n    return 5\n",
    "import typing\n\n\ndef f(weight: typing.Any, label='x'):\n    if weight > 20:\n        return 15\n    return 5\n",
], ids=["plain", "union-and-strings", "generics", "none-bytes-object", "typing-import", "typing-attr"])
def test_adding_or_changing_pure_annotations_is_certified(post):
    base = BASE if "import" not in post else post.split("def f")[0] + BASE
    r = cert(base, post)
    assert r.ok and "ANN" in r.rules and r.domain == (), (r.reason, r.detail, r.rules)


def test_changing_one_annotation_to_another_is_certified():
    a = "def f(n: int) -> int:\n    return n + 1\n"
    b = "def f(n: float) -> float:\n    return n + 1\n"
    r = cert(a, b)
    assert r.ok and r.rules == ("ANN",)


def test_removing_annotations_is_certified_too():
    a = "def f(n: int) -> int:\n    return n + 1\n"
    assert cert(a, "def f(n):\n    return n + 1\n").ok


def test_a_helper_annotated_is_certified():
    a = "def g(x):\n    return x * 2\n\n\ndef f(n):\n    return g(n)\n"
    b = "def g(x: int) -> int:\n    return x * 2\n\n\ndef f(n):\n    return g(n)\n"
    assert cert(a, b).ok


def _rule_clause(text: str) -> str:
    """The rule's own one-sentence clause. Every positive certificate ends with "; " + closure_gate.SCOPE (5c3e8eeb, case); the
    boundary text must be present exactly, and the clause before it must stay a single sentence."""
    from hlith.obligation.closure_gate import SCOPE

    assert text.endswith("; " + SCOPE), text
    return text[: -len("; " + SCOPE)]


def test_the_sentence_says_what_the_claim_covers():
    r = cert(BASE, "def f(weight: float, label: str = 'x') -> int:\n    if weight > 20:\n        return 15\n    return 5\n")
    t = r.domain_text
    assert "any argument" in t and "annotation" in t and "outside this claim" in t and _rule_clause(t).count(". ") == 0, t


# ----------------------------------------------------------------------------------------------- annotations are NOT all neutral: evaluation at definition time
@pytest.mark.parametrize("ann", ["Undefined", "g()", "open('/etc/passwd')", "[x for x in range(3)]", "Missing.attr", "(lambda: 1)()", "int.__add__"])
def test_an_annotation_whose_evaluation_could_raise_or_act_is_refused_without_future_annotations(ann):
    r = cert("def f(n):\n    return n\n", f"def f(n: {ann}):\n    return n\n")
    assert not r.ok, (ann, r.rules)


def test_any_annotation_is_neutral_under_future_annotations():
    base = "from __future__ import annotations\n\n\ndef f(n):\n    return n\n"
    post = "from __future__ import annotations\n\n\ndef f(n: Undefined.attr[g()]) -> open('x'):\n    return n\n"
    assert cert(base, post).ok


def test_a_rebound_builtin_name_in_an_annotation_is_refused():
    base = "int = 5\n\n\ndef f(n):\n    return n\n"
    post = "int = 5\n\n\ndef f(n: int):\n    return n\n"
    assert not cert(base, post).ok


# ----------------------------------------------------------------------------------------------- consumption of annotations
@pytest.mark.parametrize("extra", [
    "import inspect\n", "import dataclasses\n", "from typing import get_type_hints\n", "import pydantic\n", "import attrs\n", "from functools import singledispatch\n",
    "import typeguard\n", "import beartype\n",
])
def test_an_annotation_consuming_import_in_the_module_refuses(extra):
    r = cert(extra + "\n\ndef f(n):\n    return n\n", extra + "\n\ndef f(n: int):\n    return n\n")
    assert not r.ok, (extra, r.rules)


@pytest.mark.parametrize("use", ["f.__annotations__", "typing.get_type_hints(f)", "inspect.signature(f)", "get_annotations(f)", "signature(f)"])
def test_a_use_of_annotations_anywhere_in_the_module_refuses(use):
    pre = "import typing\nimport inspect\n"  # the imports themselves are denied; this test needs the NAME use alone
    src_b = f"def h():\n    return {use}\n\n\ndef f(n):\n    return n\n"
    src_p = f"def h():\n    return {use}\n\n\ndef f(n: int):\n    return n\n"
    assert not cert(src_b, src_p).ok


def test_a_tree_wide_consumer_in_another_file_refuses(tmp_path):
    for side, f in (("base", "def f(n):\n    return n\n"), ("post", "def f(n: int):\n    return n\n")):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg/__init__.py").write_text("")
        (tmp_path / side / "pkg/m.py").write_text(f)
        (tmp_path / side / "pkg/introspect.py").write_text("def hints(fn):\n    return fn.__annotations__\n")
    r = ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f")
    assert not r.ok and "annotation" in (r.reason + r.detail).lower(), (r.reason, r.detail)


def test_the_tree_without_a_consumer_is_certified(tmp_path):
    for side, f in (("base", "def f(n):\n    return n\n"), ("post", "def f(n: int):\n    return n\n")):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg/__init__.py").write_text("")
        (tmp_path / side / "pkg/m.py").write_text(f)
        (tmp_path / side / "pkg/other.py").write_text("def g(x):\n    return x\n")
    assert ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f").ok


# ----------------------------------------------------------------------------------------------- annotation-ONLY means only annotations
@pytest.mark.parametrize("post", [
    "def f(weight: float, label: str = 'y'):\n    if weight > 20:\n        return 15\n    return 5\n",                       # a default changed
    "def f(weight: float, label: str = 'x', express: bool = False):\n    if weight > 20:\n        return 15\n    return 5\n",   # a parameter added (p02)
    "def f(weight: float, *, label: str = 'x'):\n    if weight > 20:\n        return 15\n    return 5\n",                       # kind changed
    "def f(wt: float, label: str = 'x'):\n    if wt > 20:\n        return 15\n    return 5\n",                               # a public parameter renamed
    "def f(weight: float, label: str = 'x') -> int:\n    if weight >= 20:\n        return 15\n    return 5\n",               # body changed too
    "def f(weight: float, label: str = 'x'):\n    print('hi')\n    if weight > 20:\n        return 15\n    return 5\n",         # an effect added
])
def test_anything_beyond_annotations_is_refused(post):
    assert not cert(BASE, post).ok


def test_an_annotated_target_with_a_guard_inserted_is_not_laundered_by_annotations():
    base = "def f(s: str) -> int:\n    return len(s)\n"
    post = "def f(s: str) -> int:\n    if 'x' in s:\n        raise ValueError('x')\n    return len(s)\n"
    r = cert(base, post)
    assert not r.ok or "ANN" not in r.rules  # no approved delta here: the guard is a behaviour change and must not be admitted by ANN
