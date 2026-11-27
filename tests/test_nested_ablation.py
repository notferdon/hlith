# SPDX-License-Identifier: Apache-2.0
"""review J5: a dead statement added inside a NESTED function was credited HELD. Predeclared (before the first run):
the changed unit of a nested `def` is its changed STATEMENT, not the whole def (ablating a whole def trivially breaks the
program - NameError at the call - so liveness was vacuous). A dead statement inside it is UNVERIFIED 'ablation alters no
outcome'; a live equivalent edit inside it stays HELD; a divergent one is REFUTED. Plain function and method (through the
entry-seeds bridge, hollow receiver) alike."""
from hlith import differential
from hlith.types import Verdict

_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"
_PLAIN = "def f(x: int) -> int:\n    def inner(k):\n        return k + 1\n    return inner(x)\n"


def _plain(tmp_path, post):
    for side, body in (("base", _PLAIN), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=120, max_examples=15,
        adequacy_gate=True)


def test_dead_statement_in_a_nested_function_is_not_held(tmp_path):
    ob = _plain(tmp_path, _PLAIN.replace("        return k + 1\n", "        _unused = k * 3\n        return k + 1\n"))
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "ablation alters no outcome" in (ob.stop_reason or ""), ob.stop_reason


def test_live_equivalent_edit_in_a_nested_function_stays_held(tmp_path):
    ob = _plain(tmp_path, _PLAIN.replace("        return k + 1\n", "        return 1 + k\n"))
    assert ob.verdict is Verdict.HELD, ob


def test_divergent_edit_in_a_nested_function_is_refuted(tmp_path):
    ob = _plain(tmp_path, _PLAIN.replace("        return k + 1\n", "        return k + 2\n"))
    assert ob.verdict is Verdict.REFUTED, ob


_NODES = [{"node_id": f"tests/test_m.py::test_build_{k}", "reaches": ["pkg.m.Registry.nested"], "exists_in_base": True}
          for k in ("small", "large")]
_TEST = ("from pkg.m import build\n\n\ndef test_build_small():\n    assert build(2) == 43\n\n\n"
         "def test_build_large():\n    assert build(12) == 53\n")
_METHOD = '''
import threading


def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40
        self.lock = threading.Lock()

    def nested(self, n):
        def inner(k):
            return k + 1
        return self.base + inner(n)


def build(n):
    return Registry(_token()).nested(n)
'''


def test_dead_statement_in_a_nested_function_of_a_method_is_not_held(tmp_path):
    post = _METHOD.replace("            return k + 1\n", "            _unused = k * 3\n            return k + 1\n")
    for side, body in (("base", _METHOD), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Registry.nested",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=150, max_examples=15,
        adequacy_gate=True, impacted_test_nodes=_NODES)
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "ablation alters no outcome" in (ob.stop_reason or ""), ob.stop_reason
