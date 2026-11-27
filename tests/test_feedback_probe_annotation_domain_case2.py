# SPDX-License-Identifier: Apache-2.0
"""review release blocker (design review 2026-11-21, observed on 2aae27e4): Layer 5's probe domain = the gate's declared domain.

Observed: R1-substantial (counterpatch analyzer.is_test_path(path: str), `startswith` moved before the regex). The rehearsal LANDED 4/4
held, and its own post-landing probe pinned is_test_path(0) (an int for a `str` parameter: TypeError vs AttributeError). The confirm
loaded that pin and REFUSED the identical change (exit 10). The differential only compares annotation-admitted values
(differential._ann_admits). L5 now uses the same rule; an IN-annotation divergence still pins (control).
Real confinement, real probe runner; tiny trees."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.errors import EXIT_LANDED
from hlith.contract.identities import RunId, Sha256
from hlith.contract.runs import GateReceipt

HDR = "import re\n\n_R = re.compile(r'(^|/)test_[^/]*\\.py$')\n\n\n"
BASE = HDR + "def is_tp(path: str) -> bool:\n    return bool(_R.search(path)) or path.startswith('x/')\n"
# identical for every str; for a non-str the exception changes (TypeError from re -> AttributeError from startswith)
POST_STR_SAME = HDR + "def is_tp(path: str) -> bool:\n    return path.startswith('x/') or bool(_R.search(path))\n"
# control: an IN-annotation divergence ('zz' is a test path after the change)
POST_STR_DIFF = HDR + "def is_tp(path: str) -> bool:\n    return path == 'zz' or path.startswith('x/') or bool(_R.search(path))\n"
TESTS = "from pkg.m import is_tp\n\n\ndef test_a():\n    assert is_tp('tests/test_a.py')\n    assert not is_tp('zz')\n" \
        "    is_tp(0)\n"


@pytest.fixture(autouse=True)
def _bridge():
    from hlith import feedback as fb
    from hlith import obligation
    fb.register_probe_bridge(**obligation.probe_bridge())


def _tree(root: Path, src: str) -> Path:
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("")
    (root / "src" / "pkg" / "m.py").write_text(src)
    (root / "tests").mkdir()
    (root / "tests" / "test_m.py").write_text(TESTS)
    return root


def _landed() -> GateReceipt:
    return GateReceipt(run_id=RunId("run-0123456789ab"), outcome="landed", exit_status=EXIT_LANDED, blocking=(),
                       landed_commit="a" * 40, verification_record_sha256=Sha256("b" * 64))


def _records(store: Path) -> list:
    from hlith.feedback.store import load_stored_records
    return [s.record for s in load_stored_records(store, None)]


def _pin_inputs(recs) -> list:
    return [r.directive_payload["input"]["args"] for r in recs if r.directive_kind.value == "pin_regression_counterexample"]


def _all_inputs(recs) -> list:
    out = _pin_inputs(recs)
    for r in recs:
        if r.directive_kind.value == "require_differential_domain_constraint":
            out += [i["args"] for i in r.directive_payload["pinned_inputs"]]
    return out


def test_admission_predicate_reuses_the_gate_rule(tmp_path):
    from hlith.feedback._legacy import annotation_admission
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "m.py").write_text("def f(path: str, n, *rest, k: int | None = None, repo: 'Repo' = None):\n    pass\n")
    adm = annotation_admission(tmp_path, "pkg.m", "f")
    assert adm({"args": ["a", 0], "kwargs": {}})
    assert adm({"args": ["a", [1], "anything", 3.5], "kwargs": {}})  # unannotated n and *rest admit everything
    assert not adm({"args": [0, 0], "kwargs": {}})  # int for str
    assert not adm({"args": [None], "kwargs": {}})
    assert adm({"args": ["a", 1], "kwargs": {"k": None}}) and adm({"args": ["a", 1], "kwargs": {"k": 3}})
    assert not adm({"args": ["a", 1], "kwargs": {"k": "3"}}) and not adm({"args": ["a", 1], "kwargs": {"k": True}})  # bool is not int (gate rule)
    stub = {"$obj": {"attrs": {}, "methods": {}}}
    assert adm({"args": ["a", 1], "kwargs": {"repo": stub}})  # a stub stands for a class instance
    assert not adm({"args": [stub, 1], "kwargs": {}})  # but never for a str
    assert annotation_admission(tmp_path, "pkg.m", "missing") is None


def test_post_landing_probe_does_not_pin_out_of_annotation_inputs(tmp_path):
    """RED before the fix: a pin on is_tp(0)/(None)/(1) (out of the str annotation) refuses the same change at confirm."""
    from hlith.feedback.probe import run_landing_probes
    base, landed = _tree(tmp_path / "base", BASE), _tree(tmp_path / "landed", POST_STR_SAME)
    errors: list[str] = []
    limits: list[str] = []
    run_landing_probes(tmp_path / "store", _landed(), SimpleNamespace(path=base), SimpleNamespace(path=landed),
                       symbols=("pkg.m.is_tp",), errors=errors, limits=limits)
    recs = _records(tmp_path / "store")
    assert not errors, errors
    assert not _pin_inputs(recs), f"out-of-annotation pins stored: {_pin_inputs(recs)}"
    assert all(isinstance(a[0], str) for a in _all_inputs(recs)), _all_inputs(recs)
    assert any("outside the parameter annotations were NOT probed" in m for m in limits), limits  # named, never silent


def test_in_annotation_divergence_still_pins(tmp_path):
    """Control: no dilution. A str input on which base and landed differ is still a regression pin."""
    from hlith.feedback.probe import run_landing_probes
    base, landed = _tree(tmp_path / "base", BASE), _tree(tmp_path / "landed", POST_STR_DIFF)
    errors: list[str] = []
    run_landing_probes(tmp_path / "store", _landed(), SimpleNamespace(path=base), SimpleNamespace(path=landed),
                       symbols=("pkg.m.is_tp",), errors=errors, limits=[])
    pins = _pin_inputs(_records(tmp_path / "store"))
    assert ["zz"] in pins, pins
    assert all(isinstance(a[0], str) for a in pins), pins
