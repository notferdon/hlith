# SPDX-License-Identifier: Apache-2.0
"""review (design decision 2026-11-21 b): when Layer 5's probe cannot IMPORT the target module (a dependency missing from the probe's interpreter or
sys.path, or a nested project imported from the wrong root), that is a NAMED LIMIT of what L5 explored, not a feedback-recording failure.

Before: the RuntimeError("probe failed (exit 1): ... ModuleNotFoundError ...") went to ``errors``, which the operator renders as
"FEEDBACK NOT RECORDED ... Fix the cause (feedback store permissions or integrity)" - wrong advice (F2 real-repo run, vattr-mutmut, 20bb8df3).
Now it goes to ``limits`` with accurate text naming the module and the remedy. A REAL store failure still goes to ``errors`` (control).
Real confinement, real probe runner; tiny trees."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.errors import EXIT_LANDED, EXIT_REFUTED
from hlith.contract.identities import RunId, Sha256
from hlith.contract.runs import GateReceipt

SRC = "import n2_missing_dep_xyz\n\n\ndef f(mask):\n    return n2_missing_dep_xyz.WIDTH - mask\n"
SRC_OK = "def f(mask):\n    return 32 - mask\n"


@pytest.fixture(autouse=True)
def _bridge():
    from hlith import feedback as fb
    from hlith import obligation
    fb.register_probe_bridge(**obligation.probe_bridge())


def _tree(root: Path, src: str) -> Path:
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("")
    (root / "src" / "pkg" / "m.py").write_text(src)
    return root


def _landed() -> GateReceipt:
    return GateReceipt(run_id=RunId("run-0123456789ab"), outcome="landed", exit_status=EXIT_LANDED, blocking=(),
                       landed_commit="a" * 40, verification_record_sha256=Sha256("b" * 64))


def _refused() -> GateReceipt:
    return GateReceipt(run_id=RunId("run-0123456789ac"), outcome="refused", exit_status=EXIT_REFUTED, blocking=("differential:pkg.m.f",),
                       landed_commit=None, verification_record_sha256=Sha256("c" * 64))


def _account():
    return SimpleNamespace(modified_callables=("pkg.m.f",), unresolved_constructs=(), account_sha256="d" * 64)


def _assert_import_limit(errors, limits):
    assert not any("probe failed" in e or "ModuleNotFoundError" in e for e in errors), f"import failure reported as a recording failure: {errors}"
    hit = [m for m in limits if "pkg.m.f" in m and "UNPROBED by Layer 5" in m and "could not import" in m]
    assert hit, f"no named import limit: limits={limits} errors={errors}"
    assert "n2_missing_dep_xyz" in hit[0]  # names what was missing
    assert "--target-python" in hit[0] or "--extra-sys-path" in hit[0]  # and the remedy
    assert "permission" not in hit[0] and "integrity" not in hit[0]


def test_landing_probe_import_failure_is_a_named_limit_not_a_recording_failure(tmp_path):
    from hlith.feedback.probe import run_landing_probes
    base, landed = _tree(tmp_path / "base", SRC), _tree(tmp_path / "landed", SRC)
    errors: list[str] = []
    limits: list[str] = []
    written = run_landing_probes(tmp_path / "store", _landed(), SimpleNamespace(path=base), SimpleNamespace(path=landed),
                                 symbols=("pkg.m.f",), errors=errors, limits=limits)
    assert written == ()
    _assert_import_limit(errors, limits)


def test_refusal_probe_import_failure_is_a_named_limit_not_a_recording_failure(tmp_path):
    from hlith.feedback.probe import run_refusal_probes
    base, post = _tree(tmp_path / "base", SRC), _tree(tmp_path / "post", SRC)
    errors: list[str] = []
    limits: list[str] = []
    run_refusal_probes(tmp_path / "store", _refused(), _account(),
                       {"repo_identity": "r", "base": SimpleNamespace(path=base), "post": SimpleNamespace(path=post),
                        "refuted_symbols": ("pkg.m.f",), "witnesses": (), "constructs": ()},
                       errors=errors, limits=limits)
    _assert_import_limit(errors, limits)


def test_a_real_store_failure_is_still_a_recording_failure(tmp_path):
    """Control: the module imports, the probe runs, but the store cannot be written -> ``errors`` (operator: feedback not recorded)."""
    from hlith.feedback.probe import run_landing_probes
    base, landed = _tree(tmp_path / "base", SRC_OK), _tree(tmp_path / "landed", SRC_OK)
    store = tmp_path / "store-is-a-file"
    store.write_text("not a directory")
    errors: list[str] = []
    limits: list[str] = []
    run_landing_probes(store, _landed(), SimpleNamespace(path=base), SimpleNamespace(path=landed), symbols=("pkg.m.f",),
                       errors=errors, limits=limits)
    assert errors, f"a store that cannot be written must stay a recording failure: limits={limits}"
    assert not any("could not import" in m for m in limits)


def test_the_same_tree_with_the_dependency_on_extra_sys_path_is_probed(tmp_path):
    """Positive control: with the dependency reachable through observe_kw the probe runs; no import limit."""
    from hlith.feedback.probe import run_landing_probes
    deps = tmp_path / "deps"
    deps.mkdir()
    (deps / "n2_missing_dep_xyz.py").write_text("WIDTH = 32\n")
    base, landed = _tree(tmp_path / "base", SRC), _tree(tmp_path / "landed", SRC)
    errors: list[str] = []
    limits: list[str] = []
    run_landing_probes(tmp_path / "store", _landed(), SimpleNamespace(path=base), SimpleNamespace(path=landed), symbols=("pkg.m.f",),
                       observe_kw={"extra_sys_path": (str(deps),)}, errors=errors, limits=limits)
    assert not any("could not import" in m for m in limits), limits
    assert not any("probe failed" in e for e in errors), errors
