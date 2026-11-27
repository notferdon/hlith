# SPDX-License-Identifier: Apache-2.0
"""Class-level fixes for review's three certified-but-divergent classes against G1/G2/NORM (written here as GENERIC variants, not review's exact cases):

 1. comprehension scope   `for v in ITER: out.append(...)` <-> `[... for v in ITER]`: the FIRST iterable of a comprehension is evaluated in the ENCLOSING scope, where `v` is not the loop's local.
                          Refused whenever the loop variable's name occurs anywhere in the iterable (a global of that name would be read by one version and be an UnboundLocalError in the other).
 2. module constants      a module-level constant READ by the target is part of the module's observable surface (m.NAME; monkeypatching; reloads). Public (no leading underscore) constants read by the cone
                          must be read IDENTICALLY (same name, same value) by both versions: an extract / inline / rename of a public constant is refused. Private (_NAME) constants are inlined. Any inlining
                          of a constant is refused when the module (or, for the file-based entry, any other non-test file) can rebind module attributes: globals()/vars()/locals()/exec/eval/setattr/__dict__/
                          sys.modules, or an attribute STORE to the constant's name. The operator sentence states: module constants are assumed not rebound by code outside the tree.
 3. annotation consumers  ANN also refuses: functools.update_wrapper / wraps (copy __annotations__), pydoc / help / getdoc / render_doc, __annotate__, annotationlib; and refuses when an annotated function's
                          name is read in ANY non-call position anywhere in the scanned trees (passed, decorated, wrapped, aliased, attribute-read) - an alias reaches every consumer. Python 3.14 evaluates
                          annotations lazily; the sentence says so."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec


def cert(b, p, fn="f"):
    return ec.certify_sources(b, p, fn, module="m")


def no(b, p, fn="f"):
    r = cert(b, p, fn)
    assert not r.ok, ("ADMITTED", r.rules, r.detail)
    return r


# ----------------------------------------------------------------------------------------------- 1. comprehension scope
@pytest.mark.parametrize("it", ["v", "v.items()", "v[1:]", "sorted(v)", "(v, 1, 2)", "v.upper()"])
def test_the_iterable_reading_the_loop_variable_name_is_not_a_comprehension_candidate(it):
    base = f"v = (1, 2, 3)\n\n\ndef f():\n    out = []\n    for v in {it}:\n        out.append(v)\n    return out\n"
    post = f"v = (1, 2, 3)\n\n\ndef f():\n    return [v for v in {it}]\n"
    no(base, post)


def test_a_global_named_like_the_loop_variable_but_not_in_the_iterable_is_still_fine():
    base = "xs = (1, 2)\n\n\ndef f(items):\n    out = []\n    for xs_ in items:\n        out.append(xs_)\n    return out\n"
    post = "xs = (1, 2)\n\n\ndef f(items):\n    return [xs_ for xs_ in items]\n"
    assert cert(base, post).ok


# ----------------------------------------------------------------------------------------------- 2. module constants
def test_extracting_a_public_constant_is_refused():
    base = "def f(x):\n    return x * 0.2\n"
    post = "TAX = 0.2\n\n\ndef f(x):\n    return x * TAX\n"
    r = no(base, post)


def test_inlining_a_public_constant_is_refused():
    base = "TAX = 0.2\n\n\ndef f(x):\n    return x * TAX\n"
    post = "def f(x):\n    return x * 0.2\n"
    no(base, post)


def test_renaming_a_public_constant_is_refused():
    no("A = 0.2\n\n\ndef f(x):\n    return x * A\n", "B = 0.2\n\n\ndef f(x):\n    return x * B\n")


def test_a_private_constant_may_be_extracted_inlined_or_renamed():
    assert cert("def f(x):\n    return x * 0.2\n", "_TAX = 0.2\n\n\ndef f(x):\n    return x * _TAX\n").ok
    assert cert("_TAX = 0.2\n\n\ndef f(x):\n    return x * _TAX\n", "def f(x):\n    return x * 0.2\n").ok
    assert cert("_A = 0.2\n\n\ndef f(x):\n    return x * _A\n", "_B = 0.2\n\n\ndef f(x):\n    return x * _B\n").ok


def test_the_same_public_constant_read_by_both_versions_is_fine():
    b = "TAX = 0.2\n\n\ndef f(price):\n    total = price\n    return total + total * TAX\n"
    assert cert(b, b.replace("total", "t")).ok


@pytest.mark.parametrize("rebind", [
    "def poke(v):\n    globals()['TAX'] = v\n",
    "def poke(v):\n    vars()['TAX'] = v\n",
    "import sys\n\n\ndef poke(v):\n    sys.modules[__name__].TAX = v\n",
    "def poke(v):\n    setattr(__import__('m'), 'TAX', v)\n",
    "def poke(v):\n    exec('TAX = 1')\n",
    "def poke(v):\n    __dict__['TAX'] = v\n",
])
def test_a_constant_is_not_inlined_where_the_module_can_rebind_it(rebind):
    b = "TAX = 0.2\n\n\ndef f(price):\n    total = price\n    return total + total * TAX\n" + "\n" + rebind
    r = no(b, b.replace("total", "t"))
    assert "rebind" in (r.reason + r.detail).lower() or "module global" in r.reason, (r.reason, r.detail)


def test_another_file_storing_the_constant_attribute_refuses_the_file_based_entry(tmp_path):
    body = "TAX = 0.2\n\n\ndef f(price):\n    total = price\n    return total + total * TAX\n"
    for side, src in (("base", body), ("post", body.replace("total", "t"))):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg/__init__.py").write_text("")
        (tmp_path / side / "pkg/m.py").write_text(src)
        (tmp_path / side / "pkg/conf.py").write_text("from pkg import m\n\n\ndef set_tax(v):\n    m.TAX = v\n")
    r = ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f")
    assert not r.ok, r.rules


def _rule_clause(text: str) -> str:
    """The rule's own one-sentence clause. Every positive certificate ends with "; " + closure_gate.SCOPE (5c3e8eeb, case); the
    boundary text must be present exactly, and the clause before it must stay a single sentence."""
    from hlith.obligation.closure_gate import SCOPE

    assert text.endswith("; " + SCOPE), text
    return text[: -len("; " + SCOPE)]


def test_the_operator_sentence_states_the_constant_assumption():
    b = "TAX = 0.2\n\n\ndef f(price):\n    total = price\n    return total + total * TAX\n"
    r = cert(b, b.replace("total", "t"))
    assert r.ok and "module constants" in r.domain_text and "not rebound by code outside the tree" in r.domain_text and _rule_clause(r.domain_text).count(". ") == 0, r.domain_text


def test_a_function_reading_no_constant_has_no_constant_assumption():
    r = cert("def f(a):\n    return a + 1\n", "def f(b):\n    return b + 1\n".replace("b", "a"))
    assert "module constants" not in r.domain_text


# ----------------------------------------------------------------------------------------------- 3. annotation consumers
BASE = "def f(n):\n    return n + 1\n"
POST = "def f(n: int) -> int:\n    return n + 1\n"


@pytest.mark.parametrize("extra", [
    "import functools\n\n\ndef wrapper(*a):\n    return f(*a)\n\n\nfunctools.update_wrapper(wrapper, f)\n",
    "from functools import wraps\n\n\ndef deco(fn):\n    @wraps(fn)\n    def w(*a):\n        return fn(*a)\n    return w\n",
    "import pydoc\n\n\ndef doc():\n    return pydoc.render_doc(f)\n",
    "def doc():\n    return help(f)\n",
    "import inspect\n\n\ndef doc():\n    return inspect.getdoc(f)\n",
    "def doc():\n    return f.__annotate__\n",
    "def doc():\n    return f.__annotations__\n",
])
def test_further_annotation_consumers_refuse_ann(extra):
    mod = lambda s: (extra + "\n\n" + s) if extra.startswith(("import", "from")) else (s + "\n\n" + extra)
    no(mod(BASE), mod(POST))


@pytest.mark.parametrize("use", ["g = f\n", "handlers = [f]\n", "def reg(x):\n    return x\n\n\nreg(f)\n", "name = f.__name__\n", "w = (lambda: f)\n"])
def test_an_annotated_function_read_in_a_non_call_position_refuses_ann(use):
    no(BASE + "\n\n" + use, POST + "\n\n" + use)


def test_direct_calls_only_keep_ann_admitted():
    use = "def g(x):\n    return f(x) + f(x + 1)\n"
    r = cert(BASE + "\n\n" + use, POST + "\n\n" + use)
    assert r.ok and "ANN" in r.rules, (r.reason, r.detail)


def test_the_non_call_read_in_another_file_refuses_ann_in_the_file_based_entry(tmp_path):
    for side, src in (("base", BASE), ("post", POST)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg/__init__.py").write_text("")
        (tmp_path / side / "pkg/m.py").write_text(src)
        (tmp_path / side / "pkg/reg.py").write_text("from pkg.m import f\n\nREGISTRY = {'f': f}\n")
    assert not ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f").ok


def test_the_ann_sentence_mentions_lazy_annotations():
    r = cert(BASE, POST)
    assert r.ok and "lazily" in r.domain_text and _rule_clause(r.domain_text).count(". ") == 0, r.domain_text
