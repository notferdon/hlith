# SPDX-License-Identifier: Apache-2.0
"""case: constructor-op recipes. Predeclared before any run.

World: `_helper(reg, n)` needs a `Registry` whose state holds a lock (so it cannot be rebuilt from state alone) and whose
constructor rejects every token no synthetic input can produce; only the repository tests build one, inside confinement.
The bridge records the repository's own `Registry.__init__` call (primitive args), and the CONFINED EVALUATOR re-runs it.

Expectations:
  * equivalent edit            -> HELD, evidence says seeds were rebuilt by constructor recipe;
  * quadratic (input-space) edit -> REFUTED by an entry-seed (the recipe's args / state are varied like any seed);
  * a HOSTILE constructor (global mutation, environment write, hang on a perturbed argument, attempted network) -> never
    HELD: refused or a named UNVERIFIED that says 'constructor'.
"""
from hlith import differential
from hlith.types import Verdict

_BASE = '''
import threading


def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40
        self.lock = threading.Lock()


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
_NODES = [{"node_id": f"tests/test_m.py::test_build_{k}", "reaches": ["pkg.m._helper"], "exists_in_base": True}
          for k in ("small", "large")]


def _run(tmp_path, base, post):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="_helper",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=200, max_examples=15,
        adequacy_gate=True, impacted_test_nodes=_NODES)


def _equiv(base):
    return base.replace("return reg.base + n", "return n + reg.base")


def test_equivalent_edit_is_held_through_a_constructor_recipe(tmp_path):
    ob = _run(tmp_path, _BASE, _equiv(_BASE))
    assert ob.verdict is Verdict.HELD, ob
    assert "CONSTRUCTOR RECIPE" in ob.evidence.explored, ob.evidence.explored[-700:]


def test_input_space_edit_is_refuted_through_a_constructor_recipe(tmp_path):
    ob = _run(tmp_path, _BASE, _BASE.replace("return reg.base + n", "return reg.base + n * n - n"))
    assert ob.verdict is Verdict.REFUTED and "entry-seed" in ob.witness, ob


def _named_constructor_refusal(ob):
    assert ob.verdict is not Verdict.HELD, ob
    txt = (ob.stop_reason or "") + (ob.evidence.unexplored if ob.evidence else "")
    assert ob.verdict is Verdict.UNVERIFIED and "constructor" in txt, (ob.verdict, txt[-800:])


def test_constructor_that_mutates_a_global_is_refused(tmp_path):
    base = _BASE.replace("class Registry:\n", "class Registry:\n    made = 0\n\n").replace(
        "        self.base = 40\n", "        Registry.made += 1\n        self.base = 40\n")
    _named_constructor_refusal(_run(tmp_path, base, _equiv(base)))


def test_constructor_that_writes_the_environment_is_refused(tmp_path):
    base = _BASE.replace("import threading\n", "import os\nimport threading\n").replace(
        "        self.base = 40\n", "        os.environ['HLITH_CTOR_SEEN'] = '1'\n        self.base = 40\n")
    _named_constructor_refusal(_run(tmp_path, base, _equiv(base)))


def test_constructor_that_hangs_on_a_perturbed_argument_is_bounded_and_refused(tmp_path):
    base = _BASE.replace('            raise ValueError("bad token")\n', "            while True:\n                pass\n")
    _named_constructor_refusal(_run(tmp_path, base, _equiv(base)))


def test_constructor_that_attempts_the_network_is_refused(tmp_path):
    base = _BASE.replace("import threading\n", "import socket\nimport threading\n").replace(
        '            raise ValueError("bad token")\n',
        '            socket.create_connection(("127.0.0.1", 9), timeout=1)\n            raise ValueError("bad token")\n')
    _named_constructor_refusal(_run(tmp_path, base, _equiv(base)))


# ---- adequacy must not pass vacuously for an unbound METHOD target (real-repo Q3 was HELD for a dead statement) ----------
# Predeclared: a statement that changes nothing observable is UNVERIFIED ('ablation alters no outcome') for a method target
# reached through the bridge exactly as for a plain function. The ablation op looked the target up by its DOTTED name, raised
# KeyError, and the catch-all reported that as 'live' - so the gate passed for any method.
_METHOD_BASE = _BASE.replace("def _helper(reg, n):\n    if n > 10:\n        return reg.base + 1\n    return reg.base + n\n",
                             "def _helper(reg, n):\n    return reg.scaled(n)\n").replace(
    "        self.lock = threading.Lock()\n",
    "        self.lock = threading.Lock()\n\n    def scaled(self, n):\n        k = n\n        return self.base + n\n")


def _run_method(tmp_path, base, post):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    nodes = [dict(n, reaches=["pkg.m.Registry.scaled"]) for n in _NODES]
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Registry.scaled",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=200, max_examples=15,
        adequacy_gate=True, impacted_test_nodes=nodes)


def test_method_target_dead_statement_is_not_held_through_the_bridge(tmp_path):
    post = _METHOD_BASE.replace("        k = n\n", "        k = n + 1\n")  # k is never used: no outcome changes
    ob = _run_method(tmp_path, _METHOD_BASE, post)
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "ablation alters no outcome" in (ob.stop_reason or ""), ob.stop_reason


def test_method_target_live_edit_is_still_decided_through_the_bridge(tmp_path):
    ob = _run_method(tmp_path, _METHOD_BASE, _METHOD_BASE.replace("return self.base + n", "return n + self.base"))
    assert ob.verdict is Verdict.HELD, ob
    ob2 = _run_method(tmp_path / "x", _METHOD_BASE, _METHOD_BASE.replace("return self.base + n", "return self.base + n + 1"))
    assert ob2.verdict is Verdict.REFUTED, ob2


# ---- review I5: an attribute the TEST set after construction that cannot be shipped must not be silently dropped -----------
# Predeclared: the target reads reg.scale(n); the test installs a lambda on the receiver AFTER constructing it. The recipe can
# re-run __init__ but cannot reproduce `scale`; a receiver rebuilt without it is not evidence (the edit below differs only
# where scale(n)*n != n): the verdict is a named UNVERIFIED, never HELD. An unshippable attribute the constructor itself
# made and nobody touched (the lock in _BASE) is still fine (test_equivalent_edit_is_held_through_a_constructor_recipe).
_I5_BASE = _BASE.replace("def _helper(reg, n):\n    if n > 10:\n        return reg.base + 1\n    return reg.base + n\n",
                         "def _helper(reg, n):\n    return reg.base + reg.scale(n)\n").replace(
    "def build(n):\n    return _helper(Registry(_token()), n)\n",
    "def build(n):\n    r = Registry(_token())\n    r.scale = lambda x: x\n    return _helper(r, n)\n")


def test_attribute_set_after_construction_and_not_shippable_is_named_unseedable(tmp_path):
    # equal on every input the tests pass (n = 2, 12), different elsewhere, and it reads the unshippable attribute
    post = _I5_BASE.replace("return reg.base + reg.scale(n)",
                            "return reg.base + (reg.scale(n) if n in (2, 12) else reg.scale(n) + 1)")
    ob = _run(tmp_path, _I5_BASE, post)
    assert ob.verdict is not Verdict.HELD, ob
    txt = (ob.stop_reason or "") + (ob.evidence.unexplored if ob.evidence else "")
    assert ob.verdict is Verdict.UNVERIFIED and "scale" in txt and "not shippable" in txt, (ob.verdict, txt[-600:])
