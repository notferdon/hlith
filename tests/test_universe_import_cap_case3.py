"""The universe pre-import observes repositories above 300 modules (recorded external repository: 575) and still fails closed above its cap."""

import pytest

from hlith import differential
from hlith.types import Verdict

CAP = 1000
TARGET = "def g(value: int) -> int:\n    return value\n"


def case(tmp_path, modules, late_base="", late_post=""):
    """`modules` importable files in each tree; the target is "mod", the LAST name in import order is "zz_late"."""
    roots = {}
    for side, late in (("base", late_base), ("post", late_post)):
        root = tmp_path / side
        root.mkdir()
        (root / "mod.py").write_text(TARGET)
        (root / "zz_late.py").write_text(late)
        for i in range(modules - 2):
            (root / f"m{i:05d}.py").write_text("")
        (root / "tests").mkdir()  # HELD needs a repository test that reaches the target (not part of the import list)
        (root / "tests" / "test_g.py").write_text("import mod\n\ndef test_g():\n    assert mod.g(1) == 1\n")
        roots[side] = str(root)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=roots["base"], post_root=roots["post"], module="mod", function="g",
                proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=8, max_examples=4)


@pytest.mark.parametrize("modules", [20, 575, CAP], ids=["control-20", "large-575", "at-cap"])
def test_a_repository_inside_the_cap_is_fully_pre_imported(tmp_path, modules):
    ob = differential.run_differential(**case(tmp_path, modules))
    assert "truncated" not in (ob.stop_reason or ""), ob.stop_reason
    assert ob.verdict is Verdict.HELD, (ob.verdict, ob.stop_reason)


def test_a_difference_in_a_module_past_the_old_limit_is_observed(tmp_path):
    ob = differential.run_differential(**case(tmp_path, 575, late_post="print('changed')\n"))
    # On 85cbe85e the host replay gate reports ANY universe import witness UNVERIFIED (not-reproduced), at every module position;
    # what the cap changes is that the late module is observed at all, and that it can never be HELD.
    assert ob.verdict is not Verdict.HELD, ob.stop_reason
    assert "import of zz_late differs during universe pre-import" in f"{ob.witness} {ob.stop_reason}", (ob.witness, ob.stop_reason)


def test_control_a_repository_over_the_cap_stays_unverified_and_says_truncated(tmp_path):
    ob = differential.run_differential(**case(tmp_path, CAP + 1))
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, ob.stop_reason)
    assert "module import list was truncated" in ob.stop_reason, ob.stop_reason
