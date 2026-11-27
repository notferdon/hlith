# SPDX-License-Identifier: Apache-2.0
"""review 2026-11-21 (on a251876f; review's substantial valid change on counterpatch was refused UNVERIFIED exit 12): two adequacy-gate false refusals, each fixed with a control.

(1) `re.Match` / `re.Pattern` truthiness is FIXED (final types, no __bool__/__len__, always truthy), but the coverage recorder called every non-builtin value of a
    BoolOp operand "opaque (user __bool__)", so `bool(RX.search(p) or RX2.search(p))` could never be adequate. Fixed types are now clean; a USER-DEFINED __bool__ stays
    opaque (strict rule, case: the P2 `and` -> `or` divergent edit stays refused; tests/test_cutpoint_inputs.py keeps that case).
(2) A repository test that feeds a SOURCE TEXT (a multi-line string literal that parses as Python and calls things) to a function that walks the text's calls never
    put that string into the input domain, because `_constants` dropped every string with more than two newlines as prose: the changed loop body was never entered.
    A multi-line string that parses as Python WITH a call is a code sample and joins the domain; prose stays out.

Every positive (HELD) test has a refuting control on the same shape, so neither fix can turn real behaviour changes into HELD."""

from __future__ import annotations

import textwrap
from pathlib import Path

from hlith import differential
from hlith.types import Verdict


def _tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def _run(tmp_path: Path, function: str, base: str, post: str, test: str, **kw):
    for side, body in (("base", base), ("post", post)):
        _tree(tmp_path / side, {"m.py": body, "tests/test_m.py": test})
    prop = tmp_path / "proposer"
    prop.mkdir()
    return differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="m", function=function,
                                         proposer_paths=[str(prop)], scratch=str(tmp_path / "scratch"), max_examples=60, adequacy_gate=True, **kw)


# ---------------------------------------------------------------- (1) re.Match truthiness
MATCH_BASE = '''
    import re
    _FILE = re.compile(r"^test_")
    _DIR = re.compile(r"(^|/)tests/")

    def is_t(path: str) -> bool:
        return bool(_FILE.search(path) or _DIR.search(path)) or path.startswith(".x/")
    '''
MATCH_SAME = MATCH_BASE.replace(
    'return bool(_FILE.search(path) or _DIR.search(path)) or path.startswith(".x/")',
    'if path.startswith(".x/"):\n            return True\n        return bool(_FILE.search(path) or _DIR.search(path))')
MATCH_CHANGED = MATCH_SAME.replace("_FILE.search(path) or _DIR.search(path)", "_FILE.search(path) and _DIR.search(path)")
MATCH_TEST = '''
    import m

    def test_it():
        assert m.is_t("test_a.py")
        assert m.is_t("pkg/tests/b.py")
        assert not m.is_t("src/c.py")
        assert m.is_t(".x/y")
    '''


def test_regex_match_operands_are_clean_so_an_equivalent_rewrite_is_held(tmp_path):
    ob = _run(tmp_path, "is_t", MATCH_BASE, MATCH_SAME, MATCH_TEST)
    assert ob.verdict is Verdict.HELD, ("false UNVERIFIED: 're.Match truthiness is opaque'", ob.verdict, ob.stop_reason)


def test_control_a_real_change_with_regex_operands_is_refuted_not_held(tmp_path):
    ob = _run(tmp_path, "is_t", MATCH_BASE, MATCH_CHANGED, MATCH_TEST)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


USER_BOOL_BASE = '''
    class Flag:
        def __init__(self, v):
            self.v = v
        def __bool__(self):
            return self.v

    def mk(path):
        return Flag(path.startswith("test_"))

    def is_t(path: str) -> bool:
        return bool(mk(path) or path.endswith(".x")) or path.startswith(".y/")
    '''
USER_BOOL_SAME = USER_BOOL_BASE.replace('return bool(mk(path) or path.endswith(".x")) or path.startswith(".y/")',
                                        'if path.startswith(".y/"):\n            return True\n        return bool(mk(path) or path.endswith(".x"))')
USER_BOOL_TEST = MATCH_TEST.replace("test_a.py", "test_a.py").replace('"pkg/tests/b.py"', '"b.x"').replace('".x/y"', '".y/z"')


def test_control_a_user_defined_bool_stays_opaque_and_unverified(tmp_path):
    """The strict rule is untouched for anything user-defined (the rtz P2 lesson): an equivalent rewrite over a repo __bool__ operand is NOT credited."""
    ob = _run(tmp_path, "is_t", USER_BOOL_BASE, USER_BOOL_SAME, USER_BOOL_TEST)
    assert ob.verdict is Verdict.UNVERIFIED and "user __bool__" in (ob.stop_reason or ""), (ob.verdict, ob.stop_reason)


# ---------------------------------------------------------------- (2) code samples in repository tests
WALK_BASE = '''
    import ast

    def calls_of(src: str, name: str) -> list:
        out = []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
                try:
                    out.append(len(node.args))
                except TypeError:
                    continue
        return out
    '''
WALK_SAME = WALK_BASE.replace("node.func.id == name", "name == node.func.id")
WALK_CHANGED = WALK_BASE.replace("out.append(len(node.args))", "out.append(len(node.args) + 1)")
WALK_TEST = '''
    import m

    def test_it(tmp_path):
        p = tmp_path / "t.py"
        p.write_text("from banking import withdraw\\n\\ndef test_a():\\n    assert withdraw(100, 30) == 70\\n    withdraw(amount=5)\\n    withdraw(x, 2)\\n")
        assert m.calls_of(p.read_text(), "withdraw") == [0, 2, 2]
    '''


def test_source_text_from_a_repository_test_enters_the_changed_loop_body(tmp_path):
    ob = _run(tmp_path, "calls_of", WALK_BASE, WALK_SAME, WALK_TEST)
    assert ob.verdict is Verdict.HELD, ("false UNVERIFIED: 'changed code never entered' although a repository test feeds it a source text", ob.verdict, ob.stop_reason)


def test_control_a_real_change_in_that_loop_body_is_refuted_not_held(tmp_path):
    ob = _run(tmp_path, "calls_of", WALK_BASE, WALK_CHANGED, WALK_TEST)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)


def test_constants_keep_code_samples_and_still_drop_prose_and_non_code():
    import ast

    def keep(text: str) -> bool:
        return text in differential._constants(ast.parse(f"x = {text!r}"))

    assert keep("from banking import withdraw\n\ndef test_a():\n    assert withdraw(1) == 2\n    withdraw(3)\n")  # python with calls
    assert not keep("Line one is prose.\nLine two continues.\nLine three ends here.\nAnd a fourth.\n")  # prose: does not parse
    assert not keep("alpha\nbeta\ngamma\ndelta\n")  # parses (bare names) but has no call: not a code sample
    assert not keep("print(1)\n" * 3 + "x = 'p" + "q" * 300 + "'\n")  # over the 200-character bound
    assert keep("short\n")  # two or fewer newlines were never dropped


# ---------------------------------------------------------------- (3) review lead: a MODULE-level len threshold is not folded by _len_aliases; is that a false HELD? (measured: no)
LEN_BASE = '''
    LIMIT = {n}

    def scan(text: str) -> int:
        return len(text.split())
    '''
LEN_POST = '''
    LIMIT = {n}

    def scan(text: str) -> int:
        if len(text) > LIMIT:
            raise ValueError("too large")
        return len(text.split())
    '''
LEN_TEST = '''
    import m

    def test_it():
        assert m.scan("a b c") == 3
    '''


def test_module_level_len_threshold_in_reach_is_refuted_not_held(tmp_path):
    """review's case-f2-run2 shape (`len(test_source) > _MAX_TEST_SOURCE_CHARS`, a module constant): the length-limit variants reach it, so it is REFUTED."""
    ob = _run(tmp_path, "scan", LEN_BASE.format(n=5000), LEN_POST.format(n=5000), LEN_TEST)
    assert ob.verdict is Verdict.REFUTED and "too large" in (ob.witness or ""), (ob.verdict, ob.stop_reason)


def test_module_level_len_threshold_beyond_reach_is_never_held(tmp_path):
    """A threshold the bounded exploration cannot reach is refused by the boundary-adequacy gate (UNVERIFIED), exactly as the same threshold written as a literal."""
    ob = _run(tmp_path, "scan", LEN_BASE.format(n=300000), LEN_POST.format(n=300000), LEN_TEST)
    assert ob.verdict is Verdict.UNVERIFIED and "boundary of len(text) > LIMIT" in (ob.stop_reason or ""), (ob.verdict, ob.stop_reason)
