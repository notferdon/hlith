# SPDX-License-Identifier: Apache-2.0
"""Completeness falsifier (case): a private trusted helper with NO derivable direct-object domain.

Predeclared expectations (written before the first run):
  * `_helper(reg, n)` needs a `Registry` whose constructor rejects any token the checker could derive from literals;
    only the public caller `build()` (exercised by the passing repository test `test_build`) constructs a valid one.
  * equivalent edit            -> HELD, with actual target-entry and changed-branch coverage observed through the caller path
  * changed result             -> REFUTED with a replayable witness
  * target no test/caller reaches -> UNVERIFIED with a named gap (never HELD)
Second wave (also predeclared before running): a changed branch the passing tests never enter is NEVER HELD, whether the
edit is equivalent or not (coverage of the changed unit through the real entries is mandatory); an edit whose changed
statement no test entry can distinguish by ablation is not credited; the recipe is bound to both tree hashes.
"""
import json
import hashlib
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict


@pytest.fixture(autouse=True)
def _entry_held(monkeypatch, request):
    """The shipped default is OFF. Tests of the HELD path switch it on; test_entry_default_* run with the shipped value."""
    if not request.node.name.startswith("test_entry_default_"):
        monkeypatch.setattr(differential, "_ENTRY_HELD", True)


_BASE = '''
def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40


def _helper(reg, n):
    if n > 10:
        return reg.base + 1
    return reg.base + n


def build(n):
    return _helper(Registry(_token()), n)
'''

_TEST = '''from pkg.m import build


def test_build_small():
    assert build(2) == 42


def test_build_large():
    assert build(12) == 41
'''

NODES = [{"node_id": "tests/test_m.py::test_build_small", "file": "tests/test_m.py", "line": 3,
          "reaches": ["pkg.m._helper"], "exists_in_base": True, "provenance": "test"},
         {"node_id": "tests/test_m.py::test_build_large", "file": "tests/test_m.py", "line": 7,
          "reaches": ["pkg.m._helper"], "exists_in_base": True, "provenance": "test"}]


def _world(tmp_path, post_src, function="_helper", tests=_TEST, contexts=()):
    for side, body in (("base", _BASE), ("post", post_src)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(tests)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function=function,
                proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=300, adequacy_gate=True,
                impacted_test_nodes=NODES, caller_contexts=list(contexts), max_examples=20)


def test_equivalent_edit_held_via_caller_path(tmp_path):
    """HELD for a hollow target comes from the DIRECT differential seeded by the repository tests' own calls."""
    post = _BASE.replace("return reg.base + n", "return n + reg.base")
    ob = differential.run_differential(**_world(tmp_path, post))
    assert ob.verdict is Verdict.HELD, ob
    assert "entry seeds" in ob.evidence.explored and "comparisons through the direct differential" in ob.evidence.explored
    assert "not a proof" in ob.evidence.unexplored  # the bridge's own limit is stated


def test_changed_result_refuted_and_replayable(tmp_path):
    post = _BASE.replace("return reg.base + n", "return reg.base + n + 1")
    ob = differential.run_differential(**_world(tmp_path, post))
    assert ob.verdict is Verdict.REFUTED, ob
    assert "entry-seed" in ob.witness or "regressed" in ob.witness, ob.witness  # the repository test that enters the target fails on post (replayed below)


def test_witness_replays_on_both_trees(tmp_path):
    """The witness is replayable: rerunning the named repository test on base passes and on post fails."""
    import subprocess, sys
    post = _BASE.replace("return reg.base + n", "return reg.base + n + 1")
    kw = _world(tmp_path, post)
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.REFUTED, ob
    root = Path(__file__).resolve().parents[1]
    res = {}
    for side in ("base", "post"):
        cp = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                             "tests/test_m.py::test_build_small"], cwd=tmp_path / side, capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(tmp_path / side)})
        res[side] = cp.returncode
    assert res["base"] == 0 and res["post"] != 0, res


def test_neighbourhood_reaches_a_branch_no_test_enters(tmp_path):
    """The tests only call n=2; the changed branch (n > 10) is reached by the neighbourhood (scaled / dense values), so an
    EQUIVALENT edit there is HELD from exploration, not from the tests."""
    post = _BASE.replace("return reg.base + 1", "return 1 + reg.base")
    kw = _world(tmp_path, post, tests=_TEST.split("def test_build_large")[0].rstrip() + "\n")
    kw["impacted_test_nodes"] = kw["impacted_test_nodes"][:1]
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.HELD, ob
    assert "entry seeds" in ob.evidence.explored


def test_changed_result_in_branch_no_test_enters_is_never_held(tmp_path):
    post = _BASE.replace("return reg.base + 1", "return reg.base + 2")
    kw = _world(tmp_path, post, tests=_TEST.split("def test_build_large")[0].rstrip() + "\n")
    kw["impacted_test_nodes"] = kw["impacted_test_nodes"][:1]
    ob = differential.run_differential(**kw)
    assert ob.verdict is not Verdict.HELD, ob  # the divergence exists but no real entry reaches it: refusal, never HELD


def test_edit_no_entry_can_distinguish_is_not_credited(tmp_path):
    """A no-op-looking added guard that no entry can ever make matter: ablation liveness fails closed."""
    post = _BASE.replace("    if n > 10:\n", "    if n > 10 and n > 5:\n")
    ob = differential.run_differential(**_world(tmp_path, post))
    assert ob.verdict is not Verdict.HELD, ob


def test_base_test_that_already_fails_is_not_counted_but_still_seeds(tmp_path):
    """One of the two nodes already fails on base: it is not counted as an oracle (existing slice rule) and the call it makes
    is still just an input; the verdict is the direct exploration's."""
    failing = _TEST.replace("== 42", "== 99")
    post = _BASE.replace("return reg.base + n", "return n + reg.base")
    ob = differential.run_differential(**_world(tmp_path, post, tests=failing))
    assert ob.verdict is Verdict.HELD, ob
    assert "already failing on base" in ob.evidence.explored, ob.evidence.explored


def test_unreachable_target_unverified_with_named_gap(tmp_path):
    post = _BASE.replace("return reg.base + n", "return n + reg.base") + "\n\ndef _orphan(reg, n):\n    return reg.base + n\n"
    base_o = _BASE + "\n\ndef _orphan(reg, n):\n    return reg.base + n\n"
    kw = _world(tmp_path, post, function="_orphan")
    (tmp_path / "base" / "pkg" / "m.py").write_text(base_o)
    kw["impacted_test_nodes"] = []
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.UNVERIFIED and ob.stop_reason, ob


# ---- design review review ask (1): a HELD can never come from an unpaired, capped or excluded call -------------------------
# Predeclared: each case below is an EQUIVALENT edit whose changed unit is fully covered by deterministic, paired
# entries, plus ONE extra defect (a call that cannot be paired / is past the record cap / sits in a node whose test
# side changed). The equivalent edit would be HELD without the defect; with it the verdict must be UNVERIFIED and the
# evidence must say the entrypoint credit was withheld, naming the cause.

def _equiv_world(tmp_path, tests, post_tests=None):
    post = _BASE.replace("return reg.base + n", "return n + reg.base")
    kw = _world(tmp_path, post, tests=tests)
    if post_tests is not None:
        (tmp_path / "post" / "tests" / "test_m.py").write_text(post_tests)
    return kw


def _withheld(ob, cause):
    assert ob.verdict is Verdict.UNVERIFIED, ob
    un = ob.evidence.unexplored if ob.evidence else ""
    assert "entrypoint execution not credited" in un and cause in un, un











# ---- method target ------------------------------------------------------------------------------------------------
_MBASE = '''
def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40

    def scaled(self, n):
        if n > 10:
            return self.base + 1
        return self.base + n


def build(n):
    return Registry(_token()).scaled(n)
'''
_MNODES = [dict(n, reaches=["pkg.m.Registry.scaled"]) for n in NODES]


def _mworld(tmp_path, post_src):
    for side, body in (("base", _MBASE), ("post", post_src)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m",
                function="Registry.scaled", proposer_paths=[str(tmp_path / "proposer")],
                scratch=str(tmp_path / "scratch"), max_seeds=300, adequacy_gate=True,
                impacted_test_nodes=_MNODES, max_examples=20)


def test_method_target_equivalent_held_via_entrypoint(tmp_path):
    post = _MBASE.replace("return self.base + n", "return n + self.base")
    ob = differential.run_differential(**_mworld(tmp_path, post))
    assert ob.verdict is Verdict.HELD, ob
    assert "entry seeds" in ob.evidence.explored


def test_method_target_changed_result_refuted(tmp_path):
    post = _MBASE.replace("return self.base + n", "return self.base + n + 1")
    ob = differential.run_differential(**_mworld(tmp_path, post))
    assert ob.verdict is Verdict.REFUTED, ob





# ---- observation channel: a method whose only effect is receiver state (predeclared) ----------------------------
# The repository test never asserts the state. Without the receiver-state channel the entry recorder would see only
# `return None` on both sides and could neither refute the changed edit nor give the equivalent edit a live ablation.
_SBASE = '''
def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40

    def bump(self, n):
        if n > 10:
            self.base = self.base + 1
        else:
            self.base = self.base + n


def touch(n):
    Registry(_token()).bump(n)
'''
_STEST = "from pkg.m import touch\n\n\ndef test_touch_small():\n    touch(2)\n\n\ndef test_touch_large():\n    touch(12)\n"
_SNODES = [{"node_id": f"tests/test_m.py::test_touch_{k}", "reaches": ["pkg.m.Registry.bump"], "exists_in_base": True}
           for k in ("small", "large")]


def _sworld(tmp_path, post_src):
    for side, body in (("base", _SBASE), ("post", post_src)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_STEST)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m",
                function="Registry.bump", proposer_paths=[str(tmp_path / "proposer")],
                scratch=str(tmp_path / "scratch"), max_seeds=300, adequacy_gate=True,
                impacted_test_nodes=_SNODES, max_examples=20)


def test_receiver_state_only_change_is_refuted(tmp_path):
    post = _SBASE.replace("self.base = self.base + n", "self.base = self.base + n + 1")
    ob = differential.run_differential(**_sworld(tmp_path, post))
    assert ob.verdict is Verdict.REFUTED, ob
    assert "state after" in ob.witness or "args_after" in ob.witness, ob.witness


def test_receiver_state_only_equivalent_edit_held(tmp_path):
    post = _SBASE.replace("self.base = self.base + n\n", "self.base = n + self.base\n")
    ob = differential.run_differential(**_sworld(tmp_path, post))
    assert ob.verdict is Verdict.HELD, ob


def test_entry_default_credit_flag_is_off():
    """The OLD credit (agreement on the repository's own calls) ships OFF; HELD for hollow targets comes only from the
    seeded direct differential."""
    assert differential._ENTRY_HELD is False


# ---- G1: an argument that cannot be BUILT on one side is not a behavioural divergence (review C19/C20) -----------------
# Predeclared: an EQUIVALENT edit that routes the return through a newly added class must never be REFUTED. The only
# thing that differs is that a seed holding a post-only class instance cannot be built on base ('argbuild' error).
_G1_BASE = "def f(a, b):\n    return b\n"
_G1_POST = "def f(a, b):\n    return _Adj().g(b)\n\n\nclass _Adj:\n    def g(self, x):\n        return x\n"


def test_added_class_equivalent_edit_is_not_refuted_by_an_unbuildable_seed(tmp_path):
    for side, body in (("base", _G1_BASE), ("post", _G1_POST)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text("import pkg.m as m\n\n\ndef test_reach():\n    m.f\n")
    (tmp_path / "proposer").mkdir()
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=20,
        adequacy_gate=True)
    assert ob.verdict is not Verdict.REFUTED, ob.witness
    assert ob.evidence is not None, ob  # an internal error would have surfaced as a missing evidence record
    assert "argument_unbuildable_on_one_side=" in ob.evidence.unexplored, ob.evidence.unexplored


# ---- state channels of the entry path (review C15 / C16 / C18), predeclared REFUTED ------------------------------------
# A target whose only observable difference is state the return value does not carry: a module global, an attribute of
# some module class, the interpreter's recursion limit. The repository tests assert none of it.
def _state_case(tmp_path, post):
    return differential.run_differential(**_world(tmp_path, post))


def test_module_global_mutation_is_refuted(tmp_path):
    post = _BASE.replace("def _helper(reg, n):", "_SEEN = []\n\n\ndef _helper(reg, n):").replace(
        "    return reg.base + n\n", "    return (reg.base + n, _SEEN.append(n))[0]\n")
    ob = _state_case(tmp_path, post)
    assert ob.verdict is Verdict.REFUTED and "_SEEN" in ob.witness, ob


def test_class_attribute_mutation_is_refuted(tmp_path):
    post = _BASE.replace("    return reg.base + n\n",
                         "    return (reg.base + n, setattr(Registry, 'calls', getattr(Registry, 'calls', 0) + 1))[0]\n")
    ob = _state_case(tmp_path, post)
    assert ob.verdict is Verdict.REFUTED and "Registry.calls" in ob.witness, ob


def test_recursion_limit_change_is_refuted(tmp_path):
    post = _BASE.replace("def _token():", "import sys\n\n\ndef _token():").replace(
        "    return reg.base + n\n", "    return (reg.base + n, sys.setrecursionlimit(4321))[0]\n")
    ob = _state_case(tmp_path, post)
    assert ob.verdict is Verdict.REFUTED and "recursionlimit" in ob.witness, ob


def test_entry_path_added_warning_is_refuted(tmp_path):
    """A hollow target whose post starts emitting a warning is refuted through the seeded direct differential."""
    post = _BASE.replace("def _token():", "import warnings\n\n\ndef _token():").replace(
        "    return reg.base + n\n",
        "    r = reg.base + n\n    warnings.warn('helper is deprecated', DeprecationWarning)\n    return r\n")
    ob = differential.run_differential(**_world(tmp_path, post))
    assert ob.verdict is Verdict.REFUTED, ob
    assert "DeprecationWarning" in ob.witness and "helper is deprecated" in ob.witness, ob.witness


# ---- input-space backstop on the entry path (real-repo case Q2: lower() for upper() was a false HELD) --------------
# Predeclared: covering a changed STATEMENT through real entries does not cover its INPUT SPACE. When the changed code
# carries a distinguishing construct the direct path's own backstop names (text method, type test, length / bit_length
# threshold), the entry path cannot show that the observed entries span the distinguishing inputs, so it must refuse
# (UNVERIFIED, naming it) - while a plain operand swap with no such construct stays HELD.
_TXT_BASE = _BASE.replace("    return reg.base + n\n", "    tag = str(n).upper()\n    return reg.base + len(tag) - 1 + n\n")





def test_entry_equal_constructs_on_both_sides_stay_held(tmp_path):
    """A changed statement that CONTAINS a text method on both sides unchanged (an operand reorder around it) does not alter
    the construct's input space: still HELD (real-repo case Q1 was refused for this coarse reason at 842a4d4)."""
    base = _TXT_BASE.replace("    return reg.base + len(tag) - 1 + n\n", "    return reg.base + n + len(str(n).upper()) - 1\n")
    post = base.replace("reg.base + n + len(str(n).upper()) - 1", "n + reg.base + len(str(n).upper()) - 1")
    kw = _world(tmp_path, post)
    (tmp_path / "base" / "pkg" / "m.py").write_text(base)
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.HELD, ob


# ---- entry-seeds bridge (case): HELD from exploration, never from agreement on the tests' own calls -------
def test_held_does_not_depend_on_test_pairing(tmp_path):
    """The old credit demanded every recorded call be paired / uncapped / unexcluded across two test runs. HELD now comes
    from the direct differential on identical constructed inputs, so a call that differs by side, an extra capped node or an
    edited post test side neither create nor remove it."""
    tests = _TEST + ("\n\ndef test_build_side():\n    import pkg.m as m\n"
                     "    build(2 + int('/post/pkg/' in m.__file__))\n")
    post = _BASE.replace("return reg.base + n", "return n + reg.base")
    kw = _world(tmp_path, post, tests=tests)
    kw["impacted_test_nodes"] = NODES + [{"node_id": "tests/test_m.py::test_build_side", "reaches": ["pkg.m._helper"],
                                          "exists_in_base": True}]
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.HELD and "comparisons through the direct differential" in ob.evidence.explored, ob


def test_entry_default_unseedable_receiver_is_a_named_refusal(tmp_path):
    """A receiver whose state holds a lock AND whose constructor cannot be recorded (*args) can be rebuilt neither from state
    nor by recipe: the bridge names the type and the verdict stays UNVERIFIED (never HELD from agreement on the tests' calls)."""
    base = _BASE.replace("    def __init__(self, token):\n", "    def __init__(self, *args):\n        token = args[0]\n").replace(
        "        self.base = 40\n", "        self.base = 40\n        self.lock = __import__('threading').Lock()\n")
    post = base.replace("return reg.base + n", "return n + reg.base")
    kw = _world(tmp_path, post)
    (tmp_path / "base" / "pkg" / "m.py").write_text(base)
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "not seedable" in ob.evidence.unexplored and "lock" in ob.evidence.unexplored, ob.evidence.unexplored


_STRBASE = _BASE.replace("def _helper(reg, n):", "def _helper(reg, n, tag='ab'):").replace(
    "    return reg.base + n\n", "    return reg.base + n + len(tag.upper())\n")


def test_text_method_on_a_string_argument_is_refuted_by_unicode_neighbours(tmp_path):
    """Case Q2 in miniature: upper() -> lower() looks identical on ASCII (the only thing the tests pass); the neighbourhood of
    the observed string includes U+0130, where the two differ."""
    base = _STRBASE.replace("def build(n):\n    return _helper(Registry(_token()), n)\n",
                            "def build(n):\n    return _helper(Registry(_token()), n, 'ab')\n")
    post = base.replace("len(tag.upper())", "len(tag.lower())")
    kw = _world(tmp_path, post)
    (tmp_path / "base" / "pkg" / "m.py").write_text(base)
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.REFUTED and "entry-seed" in ob.witness, ob


_H1_BASE = _BASE
_H1_POST = _BASE.replace("    return reg.base + n\n", "    return reg.base + n + (reg.base - 40) * (n - 2)\n")


def test_two_leaf_interaction_is_refuted_by_pairwise_exploration(tmp_path):
    """review H1: the divergence needs the receiver's state AND the argument to move together ((base-40)*(n-2) is 0 whenever
    either is at its observed value), so no one-leaf neighbour shows it; the pairwise stage does."""
    ob = differential.run_differential(**_world(tmp_path, _H1_POST))
    assert ob.verdict is Verdict.REFUTED, ob
    assert "entry-seed" in ob.witness, ob.witness
