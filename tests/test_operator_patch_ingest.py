from pathlib import Path
from types import SimpleNamespace

from hlith.contract.runs import LandingTarget, RunMode
from hlith.operator.coordinator import RunRequest, _effect_block


def test_patch_ingest_artifact_preserves_the_effect_patch_and_changed_paths():
    patch = (
        "diff --git a/calc.py b/calc.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/calc.py\n"
        "+++ b/calc.py\n"
        "@@ -1 +1 @@\n"
        "-def add(a, b): return a + b\n"
        "+def add(a, b): return b + a\n"
    ).encode()
    req = RunRequest(repo=Path("/source"), mode=RunMode.COMPANION, landing_target=LandingTarget.REHEARSAL, patch=patch)
    res = SimpleNamespace(agent_result=None, account=SimpleNamespace(patch_sha256="a" * 64), external_patch_ingested=True)

    effect = _effect_block(req, res)

    assert effect["unified_diff"] == patch.decode()
    assert effect["touched_files"] == ["calc.py"]
