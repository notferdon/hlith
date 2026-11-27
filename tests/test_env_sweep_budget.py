"""case: the env sweep must not starve late call shapes (synthetic twin of the real needs_acc requests case, which every default
gate skips) and its seed budget is a DISCLOSED limit.

Twin: f(url) reads K00..K02 and ZZ_KEY; the tests call f with 60 distinct literals, the LAST one being the only call whose behaviour
depends on ZZ_KEY (base: ZZ_KEY == '*' -> 99; post drops the branch). With ~38 values per key the old call-major order gave each call
its whole env grid (8 keys x 38 values) and the default 4000-seed budget ended after ~9 of 61 call shapes: HELD. Value-major order
reaches (last call) x (ZZ_KEY) x (value index 1: '*') inside the budget."""
from pathlib import Path

from hlith import differential
from hlith.types import Verdict

LITS = [f"literal-{i:02d}-abcdefghij" for i in range(14)]
KEYS = [f"K{i:02d}" for i in range(3)]


def _body(branch_value: str | None) -> str:
    s = "import os\n\n\ndef f(url: str) -> int:\n"
    for i, k in enumerate(KEYS):
        s += f"    v{i} = os.environ.get('{k}')\n"
    for i, lit in enumerate(LITS[:-1]):
        s += f"    if url == '{lit}':\n        return {i}\n"
    s += f"    if url == '{LITS[-1]}':\n"
    if branch_value is not None:
        s += f"        if os.environ.get('ZZ_KEY') == {branch_value!r}:\n            return 99\n"
    s += "        return 0\n    return -1\n"
    return s


def _run(tmp_path: Path, branch_value: str):
    for side, body in (("base", _body(branch_value)), ("post", _body(None))):
        root = tmp_path / side
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")
        (root / "pkg" / "m.py").write_text(body)
        t = "from pkg.m import f\n\n\ndef test_calls():\n"
        for i in range(59):
            t += f"    assert f('call-{i:03d}-abcdefghij') is not None\n"
        t += f"    assert f('{LITS[-1]}') is not None\n"
        (root / "tests").mkdir()
        (root / "tests" / "test_m.py").write_text(t)
    (tmp_path / "proposer").mkdir()
    # DEFAULT max_seeds (4000): _synthetic() would pass 300 and hide the budget
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"))


def test_late_call_shape_x_late_key_x_early_value_is_reached_under_the_default_budget(tmp_path):
    ob = _run(tmp_path, "*")
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason, str(getattr(ob.evidence, "explored", ""))[-400:])
    assert "ZZ_KEY" in (ob.witness or "") and "literal-13" in (ob.witness or ""), ob.witness


def test_divergence_needing_a_value_beyond_the_budget_is_disclosed_not_claimed_as_covered(tmp_path):
    """Near-miss control: the divergent value is a 90-char literal of the function, i.e. one of the LAST values in each key's list,
    unreachable inside the budget. The checker cannot see it; it must say so: the unexplored list names the exhausted env budget."""
    ob = _run(tmp_path, "L" * 90)
    assert ob.verdict is not Verdict.REFUTED  # the honest limit: this divergence is out of reach
    text = (ob.stop_reason or "") + " " + str(getattr(ob.evidence, "unexplored", ""))
    assert "environment sweep stopped at its seed budget" in text, text[-500:]
