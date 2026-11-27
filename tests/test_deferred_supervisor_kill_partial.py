# SPDX-License-Identifier: Apache-2.0
"""Confirmed deferred witnesses survive the confined driver's wall timeout (reported, not claimed as a refutation)."""
import json

import pytest

from hlith import differential
from hlith.types import Verdict


_STUB = {"$obj": {"methods": {}, "attrs": {}}}
_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"


def _src(ret: int) -> str:
    return f"""import time


def f(x):
    if x is True:
        return {ret}
    if type(x).__name__ == "Stub":
        return {ret}
    if x == "stall":
        time.sleep(120)
    return 0
"""


@pytest.mark.parametrize(
    "seed,source",
    [([True], "deferred-bool"), ([_STUB], "deferred-stand-in")],
    ids=("bool-fallback", "stand-in-best"),
)
def test_deferred_witness_survives_supervisor_wall_timeout(tmp_path, seed, source):
    for side, ret in (("base", 1), ("post", 2)):
        root = tmp_path / side / "pkg"
        root.mkdir(parents=True)
        (root / "__init__.py").write_text("")
        (root / "m.py").write_text(_src(ret))
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    proposer = tmp_path / "proposer"
    proposer.mkdir()
    scratch = tmp_path / "scratch"

    ob = differential.run_differential(
        base_root=str(tmp_path / "base"),
        post_root=str(tmp_path / "post"),
        module="pkg.m",
        function="f",
        proposer_paths=[str(proposer)],
        scratch=str(scratch),
        seeds=[(seed, {}, source), (["stall"], {}, "later-stall")],
        seed_dump=True,
        call_timeout=180,
        timeout=25,
        explore_budget=90,
        max_seeds=20,
        max_examples=1,
    )

    rows = [json.loads(line) for line in (scratch / "seed-dump.jsonl").read_text().splitlines()]
    assert rows and rows[0]["args"] == seed
    assert any(row["args"] == ["stall"] for row in rows), "the later evaluator call must be reached before timeout"
    saved = json.loads((scratch / "partial-witness.json").read_text())
    assert saved["record"]["args"] == seed
    # the confirmed divergence survives the cap as a NAMED, recorded gap; an incomplete witness is never a positive refutation
    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "incomplete witness" in ob.stop_reason and "AFTER confirming this divergence" in ob.stop_reason, ob
    assert json.loads((scratch / "witness-gate.json").read_text())["status"] == "not-reproduced"
