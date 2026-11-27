# SPDX-License-Identifier: Apache-2.0
"""Phase 2: the two families the design review witnessed as false-HELD, and the one liveness
regression Phase 1 introduced. These are independent variants; the original fixtures stay a separate check.

Family 4 (positional access in a mapping KEY, in a helper): the static measure analysis skipped every node under a mapping-lookup key and dropped helper bounds of
magnitude < 3, the runtime recorders instrument only the target's own changed units, and the repo's tests seed no input that separates the two windows.
Family 7 (regex quantifier): the producer keyed only the LOWER endpoint (>= 100), so a changed upper endpoint left the key set identical.
Regression guard: a bound that FOLDS to the same value (`63 + 1` vs `64`) is the same bound (Phase 1's pool key spelled it differently and lost pooling).

Ground truth is executed for every case (a real divergence on a crafted input exists for each RED; none for each GREEN) so no case passes vacuously."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict

CASES: dict[str, dict] = {}


def case(name, base, post, inputs, note, smoke_arg="?", call="readout"):
    CASES[name] = dict(base=base, post=post, inputs=inputs, note=note, smoke_arg=smoke_arg, call=call)


def _truth(c):
    bn, pn = {}, {}
    exec(compile(c["base"], "base", "exec"), bn)
    exec(compile(c["post"], "post", "exec"), pn)
    div = []
    for s in c["inputs"]:
        def run(ns):
            try:
                return ns[c["call"]](s)
            except Exception as e:  # noqa: BLE001
                return ("raised", type(e).__name__)
        if run(bn) != run(pn):
            div.append(s[:14])
    return div, bn[c["call"]](c["smoke_arg"]) if c["smoke_arg"] is not None else None


def _run(tmp_path: Path, c: dict):
    div, smoke_val = _truth(c)
    test = f"from m import {c['call']}\n\n\ndef test_reference():\n    assert {c['call']}({c['smoke_arg']!r}) == {smoke_val!r}\n"
    for side, body in (("base", c["base"]), ("post", c["post"])):
        (tmp_path / side / "tests").mkdir(parents=True)
        (tmp_path / side / "m.py").write_text(body)
        (tmp_path / side / "tests" / "test_m.py").write_text(test)
    (tmp_path / "prop").mkdir()
    return differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="m", function=c["call"],
                                         proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=40, adequacy_gate=True)


# ============================================================================================ FAMILY 4: positional access inside a mapping key, in a helper
case("K1_literal_dict_key_window_moved",
     "def pick(word):\n    return {'k1': 3, 'z9': 5}.get(word[:2], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    return {'k1': 3, 'z9': 5}.get(word[2:4], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["xxk1", "k1xx", "z9", "plain"], "an exact dict lookup whose key is a window of the input, the window moved from the head to the next two characters")
case("K2_local_mapping_subscript_key_other_end",
     "def pick(word):\n    table = {'a': 1, 'b': 2}\n    try:\n        return table[word[0]]\n    except KeyError:\n        return 0\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    table = {'a': 1, 'b': 2}\n    try:\n        return table[word[-1]]\n    except KeyError:\n        return 0\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["ab", "ba", "aa", "zz"], "a local mapping subscripted by the FIRST character becomes the LAST character")
case("K3_split_index_selects_key_in_helper",
     "def pick(word):\n    return {'p': 1, 'q': 2}.get(word.split(',')[0], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    return {'p': 1, 'q': 2}.get(word.split(',')[-1], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["p,q", "q,p", "p", "x"], "the field index that selects the lookup key moves from first to last (bounds 0 and -1: below the helper floor)")
case("K4_two_helpers_deep_key_window",
     "def head(word):\n    return word[:3]\n\n\ndef pick(word):\n    return {'abc': 1, 'xyz': 2}.get(head(word), 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def head(word):\n    return word[1:4]\n\n\ndef pick(word):\n    return {'abc': 1, 'xyz': 2}.get(head(word), 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["?abc", "abc?", "xyz", "plain"], "the key window is computed one helper deeper than the lookup")
case("K7_subscript_lookup_head_vs_tail_composed_keys",
     "def pick(word):\n    try:\n        return {'red': 1, 'tan': 2}[word[:3]]\n    except KeyError:\n        return 0\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    try:\n        return {'red': 1, 'tan': 2}[word[-3:]]\n    except KeyError:\n        return 0\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["redtan", "tanred", "red", "tan"], "the window selecting an exact key moves from the head to the tail; only an input COMPOSING both keys separates them")
case("K8_alias_fed_lookup_head_vs_tail",
     "def pick(word):\n    table = {'red': 1, 'tan': 2}\n    head = word[:3]\n    return table.get(head, 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    table = {'red': 1, 'tan': 2}\n    head = word[-3:]\n    return table.get(head, 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["redtan", "tanred", "red", "tan"], "the window is bound to a local and the local is the lookup key")
case("K9_key_window_one_helper_deeper_composed",
     "def head(word):\n    return word[:3]\n\n\ndef pick(word):\n    return {'red': 1, 'tan': 2}.get(head(word), 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def head(word):\n    return word[-3:]\n\n\ndef pick(word):\n    return {'red': 1, 'tan': 2}.get(head(word), 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["redtan", "tanred", "red", "tan"], "the window is computed in a helper that only the lookup key calls")
FAM4_RED = ["K3_split_index_selects_key_in_helper", "K7_subscript_lookup_head_vs_tail_composed_keys"]  # HELD on c3957650 AND 229cb36a (pre-existing)
FAM4_GUARD = ["K1_literal_dict_key_window_moved", "K2_local_mapping_subscript_key_other_end", "K4_two_helpers_deep_key_window",
              "K8_alias_fed_lookup_head_vs_tail", "K9_key_window_one_helper_deeper_composed"]  # already non-HELD today: the fix must keep them so

case("K5_unchanged_mapping_key_helper_renamed_param",
     "def pick(word):\n    return {'k1': 3, 'z9': 5}.get(word[:2], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(text):\n    return {'k1': 3, 'z9': 5}.get(text[:2], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["xxk1", "k1xx", "z9", "plain"], "VALID: the helper's parameter renamed, the window unchanged")
case("K6_unchanged_mapping_key_local_alias",
     "def pick(word):\n    return {'k1': 3, 'z9': 5}.get(word[:2], 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     "def pick(word):\n    head = word[:2]\n    return {'k1': 3, 'z9': 5}.get(head, 0)\n\n\ndef readout(word: str):\n    return pick(word)\n",
     ["xxk1", "k1xx", "z9", "plain"], "VALID: the window hoisted into a local, same window")
FAM4_GREEN = ["K5_unchanged_mapping_key_helper_renamed_param", "K6_unchanged_mapping_key_local_alias"]

# ============================================================================================ FAMILY 7: regex quantifier endpoints
IMPORT = "import re\n\n\n"
case("Q1_upper_endpoint_only_changed",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'b{120,124}', code))\n",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'b{120,125}', code))\n",
     ["b" * 125, "b" * 124, "b" * 120], "same lower endpoint, the upper endpoint grows by one")
case("Q2_lower_below_floor_upper_above",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'c{50,120}', code))\n",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'c{50,121}', code))\n",
     ["c" * 121, "c" * 120, "c" * 50], "the lower endpoint is below the key threshold; the changed upper endpoint is above it")
case("Q3_open_ended_to_bounded",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'd{200,}', code))\n",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'd{200,260}', code))\n",
     ["d" * 261, "d" * 260, "d" * 200], "an open-ended repetition gets a ceiling")
case("Q4_helper_resident_pattern",
     IMPORT + "def _pat(code):\n    return re.fullmatch(r'e{100,104}', code)\n\n\ndef readout(code: str):\n    return bool(_pat(code))\n",
     IMPORT + "def _pat(code):\n    return re.fullmatch(r'e{100,105}', code)\n\n\ndef readout(code: str):\n    return bool(_pat(code))\n",
     ["e" * 105, "e" * 104], "the quantified pattern lives in a helper")
FAM7_RED = ["Q1_upper_endpoint_only_changed", "Q2_lower_below_floor_upper_above", "Q3_open_ended_to_bounded", "Q4_helper_resident_pattern"]

case("Q5_lower_endpoint_changed_guard",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'f{150}', code))\n",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'f{151}', code))\n",
     ["f" * 151, "f" * 150], "guard: the lower endpoint changed (already keyed)")
case("Q6_same_quantifier_hoisted_into_local",
     IMPORT + "def readout(code: str):\n    return bool(re.fullmatch(r'g{100,104}', code))\n",
     IMPORT + "def readout(code: str):\n    hit = re.fullmatch(r'g{100,104}', code)\n    return bool(hit)\n",
     ["g" * 105, "g" * 104, "g" * 100], "VALID: identical quantifier, the match hoisted into a local")
FAM7_GUARD = ["Q5_lower_endpoint_changed_guard"]
FAM7_GREEN = ["Q6_same_quantifier_hoisted_into_local"]

# ============================================================================================ Phase 1 regression: a folded bound is the same bound
case("F1_folded_bound_spelling",
     "def readout(text: str) -> list[str]:\n    if not text:\n        return []\n    return text.splitlines()[63 + 1:]\n",
     "def readout(text: str) -> list[str]:\n    if not text:\n        return []\n    return text.splitlines()[64:]\n",
     ["x\n" * 70, "a\nb", ""], "VALID: `63 + 1` and `64` are the same bound (the pure folded-line bound; lost by Phase 1's unfolded pool key)")
case("F2_module_constant_bound_renamed",
     "_LIMIT = 64\n\n\ndef readout(text: str) -> list[str]:\n    if not text:\n        return []\n    return text.splitlines()[_LIMIT:]\n",
     "_CEILING = 64\n\n\ndef readout(text: str) -> list[str]:\n    if not text:\n        return []\n    return text.splitlines()[_CEILING:]\n",
     ["x\n" * 70, "a\nb", ""], "VALID: the module constant renamed, same value")
FOLD_GREEN = ["F1_folded_bound_spelling", "F2_module_constant_bound_renamed"]


@pytest.mark.parametrize("name", FAM4_RED + FAM7_RED)
def test_red_families_4_and_7_a_real_divergence_is_never_held(tmp_path, name):
    c = CASES[name]
    div, _ = _truth(c)
    assert div, f"{name}: vacuous fixture (no divergence on the crafted inputs): {c['note']}"
    ob = _run(tmp_path, c)
    assert ob.verdict in (Verdict.UNVERIFIED, Verdict.REFUTED), (name, ob.verdict, c["note"])
    if ob.verdict is Verdict.REFUTED:
        assert ob.witness, name


@pytest.mark.parametrize("name", FAM7_GUARD + FAM4_GUARD)
def test_guards_stay_non_held(tmp_path, name):
    assert _run(tmp_path, CASES[name]).verdict is not Verdict.HELD, name


@pytest.mark.parametrize("name", FAM4_GREEN + FAM7_GREEN + FOLD_GREEN)
def test_green_valid_refactors_stay_held(tmp_path, name):
    c = CASES[name]
    div, _ = _truth(c)
    assert not div, f"{name}: the 'valid' fixture diverges (fixture bug): {div}"
    ob = _run(tmp_path, c)
    assert ob.verdict is Verdict.HELD, (name, ob.verdict, ob.stop_reason, c["note"])


def test_the_folded_bound_identity_is_value_based_unit():
    import ast
    def bk(src):
        t = ast.parse(src)
        f = t.body[-1]
        sub = next(n for n in ast.walk(f.body[-1]) if isinstance(n, ast.Subscript))
        return differential._slice_bk(f, sub, t)
    assert bk("def f(t: str):\n    return t.splitlines()[63 + 1:]\n") == bk("def f(t: str):\n    return t.splitlines()[64:]\n")
    assert bk("def f(t: str):\n    return t.splitlines()[2 * 32:]\n") == bk("def f(t: str):\n    return t.splitlines()[64:]\n")
    assert bk("def f(t: str):\n    return t.splitlines()[130 // 2 - 1:]\n") == bk("def f(t: str):\n    return t.splitlines()[64:]\n")
    assert bk("def f(t: str):\n    return t.splitlines()[-(60 + 4):]\n") == bk("def f(t: str):\n    return t.splitlines()[-64:]\n")
    assert bk("_L = 64\ndef f(t: str):\n    return t.splitlines()[_L:]\n") == bk("def f(t: str):\n    return t.splitlines()[64:]\n")  # a literal is the module constant's value
    # NON-literal siblings must NOT fold (names, calls, attributes, floats, bools, unsupported operators, overflow keep their own identity)
    assert bk("def f(t: str, n: int):\n    return t[n + 1:]\n") != bk("def f(t: str, n: int):\n    return t[n + 2:]\n")
    assert bk("def f(t: str, n: int):\n    return t[63 + n:]\n") != bk("def f(t: str, n: int):\n    return t[64:]\n")
    assert bk("def f(t: str):\n    return t[len(t) - 1:]\n") != bk("def f(t: str):\n    return t[len(t) - 2:]\n")
    assert bk("def f(t: str):\n    return t[True + 63:]\n") != bk("def f(t: str):\n    return t[64:]\n")  # a bool is not an int literal here
    assert bk("def f(t: str):\n    return t[2 ** 6:]\n") != bk("def f(t: str):\n    return t[64:]\n")  # ** is outside + - * //
    assert bk("def f(t: str):\n    return t[10 ** 30:]\n") != bk("def f(t: str):\n    return t[10 ** 31:]\n")
    assert bk("def f(t: str):\n    return t[1 // 0 + 1:]\n") != bk("def f(t: str):\n    return t[1:]\n")  # a division by zero never folds (and never raises here)
    assert bk("def f(t: str):\n    return t[99999999999999999999 * 99999999999999999999:]\n") != bk("def f(t: str):\n    return t[0:]\n")  # beyond the guard: not folded
    assert bk("_L = 64\ndef f(t: str):\n    return t.splitlines()[_L:]\n") == bk("_M = 64\ndef f(t: str):\n    return t.splitlines()[_M:]\n")
    assert bk("def f(t: str):\n    return t.splitlines()[64:]\n") != bk("def f(t: str):\n    return t.splitlines()[65:]\n")
    assert bk("def f(t: str):\n    return t[-6]\n") != bk("def f(t: str):\n    return t[5]\n")
    assert bk("def f(t: str, n: int):\n    return t[n:]\n") != bk("def f(t: str, n: int):\n    return t[:n]\n")  # a dynamic bound keeps its role


def test_the_regex_quantifier_key_carries_both_endpoints_unit():
    import ast
    def keys(src):
        t = ast.parse(src)
        f = next(n for n in t.body if isinstance(n, ast.FunctionDef) and n.name == "readout")
        return {k for k in differential._measure_consts(t, f) if isinstance(k, str) and k.startswith("s:q")}
    assert keys(IMPORT + "def readout(c: str):\n    return bool(re.fullmatch(r'a{100,104}', c))\n") != keys(
        IMPORT + "def readout(c: str):\n    return bool(re.fullmatch(r'a{100,105}', c))\n")
    assert keys(IMPORT + "def readout(c: str):\n    return bool(re.fullmatch(r'a{50,120}', c))\n") != keys(
        IMPORT + "def readout(c: str):\n    return bool(re.fullmatch(r'a{50,121}', c))\n")
    assert keys(IMPORT + "def readout(c: str):\n    return bool(re.fullmatch(r'a{100,104}', c))\n") == keys(
        IMPORT + "def readout(c: str):\n    m = re.fullmatch(r'a{100,104}', c)\n    return bool(m)\n")
