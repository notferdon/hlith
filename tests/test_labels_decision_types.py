# SPDX-License-Identifier: Apache-2.0
"""case (owner review; test authored by review, handed over as a file): operator.labels.decision must be TYPE-STRICT.

Found by review on root 92f4194a: labels.decision used ==/dict lookups, so exit_status False / 0.0 equalled 0 and a schema-invalid
record read 'LANDED'; 10.0 read 'REFUSED · REFUTED'; [10] / {} raised TypeError (unhashable) and crashed headless
`hlith inspect <artifact>` (api.inspect_artifact_file -> labels.headline) instead of giving a SCHEMA-INVALID verdict.

Contract pinned here:
  * decision(outcome, exit_status): any exit_status whose type is not exactly int (bool/float/str/None/list/dict...) or any
    outcome not in ('landed', 'refused') -> 'UNKNOWN (...)' BEFORE any lookup; never raises; tone never 'good'.
  * valid inputs are unchanged (controls below).
  * the inspect path gives SCHEMA_INVALID, never crashes, never says LANDED for an invalid decision type, and an UNVALIDATED
    / UNKNOWN label is never tone 'good' (also for a landed/0 record that is schema-invalid for another reason).
Self-contained: builds a schema-valid cli-2 artifact inline and writes files only under pytest's tmp_path.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from hlith.operator import api, labels, store
from hlith.operator.schema import artifact_errors

BAD_EXIT = [False, True, 0.0, 10.0, 4.0, "0", "10", None, [10], [0], {}, {"exit": 0}, (0,)]
BAD_OUTCOME = [None, "LANDED", "Landed", "landed ", ["landed"], {"o": "landed"}, 1, True]


def _h(label: str) -> str:
    return hashlib.sha256(f"TEST:{label}".encode()).hexdigest()


def _artifact(outcome="landed", exit_status=0) -> dict:
    """A schema-valid cli-2 run artifact (synthetic, test-only)."""
    run_id = "run-0123456789ab"
    sym = "pkg.m.f"
    ob = {"id": f"differential:{sym}", "target_symbol": sym, "claim": f"{sym} behaves identically", "verdict": "held",
          "stop_reason": None, "witness": None, "evidence": {"executions": 3, "explored": "3 inputs", "unexplored": "rest"},
          "provenance": {"checker_id": "differential", "checker_sha256": _h("c"), "confined": True,
                         "proposer_paths_readable": False, "profile_sha256": _h("p"), "exit_code": 0},
          "account_id": None}
    return {
        "run": {"run_id": run_id, "thread_id": None, "checkpoint_id": None, "base_commit_sha": "a" * 40,
                "base_tree_sha256": "b" * 40, "started_at_utc": "2026-11-17T00:00:00Z", "loaded_feedback_ids": []},
        "effect_account": {"status": "failed", "error": "test fixture", "account_id": None, "account_sha256": None,
                           "effect_id": _h("patch"), "language": "python", "sidecar": None, "account": None,
                           "index_cache_provenance": {"cache_hit_count": 0, "uncached_count": 0}},
        "feedback": {"run_id": run_id, "loaded_feedback_ids": [], "written_feedback_ids": [], "covered_by_delta": [],
                     "unpinned_witnesses": [], "recurrent_in_callee_cone": [], "recurrent_constructs": [], "superseded_by_delta": []},
        "graph": None, "outcome": outcome, "exit_status": exit_status, "blocking": [],
        "landed_commit": "c" * 40 if outcome == "landed" else None,
        "effect": {"patch_sha256": _h("patch"), "proposer_id": "test", "touched_files": ["pkg/m.py"], "unified_diff": "",
                   "deltas": [], "delta_set_sha256": None},
        "deltas": None,
        "worker": {"returncode": 0, "stdout": "", "stderr": "", "profile_sha256": _h("p"), "ignored_paths": [],
                   "skipped_paths": [], "risk_flags": []},
        "target": {"base_tree": "b" * 40, "digest_before": _h("d"), "digest_after_worker": _h("d"), "untouched_by_worker": True},
        "incident": None, "obligations": [ob], "delta_rel": [],
    }


def test_fixture_is_schema_valid():
    assert artifact_errors(_artifact()) == []


# ------------------------------------------------------------------ labels.decision


@pytest.mark.parametrize("outcome", ["landed", "refused"])
@pytest.mark.parametrize("exit_status", BAD_EXIT, ids=repr)
def test_decision_rejects_non_int_exit_status(outcome, exit_status):
    label, tone = labels.decision(outcome, exit_status)  # must not raise
    assert label.startswith("UNKNOWN"), (outcome, exit_status, label)
    assert "LANDED" not in label.split("(")[0] and tone != "good", (outcome, exit_status, label, tone)


@pytest.mark.parametrize("outcome", BAD_OUTCOME, ids=repr)
@pytest.mark.parametrize("exit_status", [0, 10, 12])
def test_decision_rejects_unknown_outcome(outcome, exit_status):
    label, tone = labels.decision(outcome, exit_status)
    assert label.startswith("UNKNOWN") and tone != "good", (outcome, exit_status, label, tone)


@pytest.mark.parametrize("outcome,exit_status,expect", [
    ("landed", 0, ("LANDED", "good")),
    ("refused", 4, ("REFUSED · BOUNDARY", None)),
    ("refused", 10, ("REFUSED · REFUTED", "bad")),
    ("refused", 11, ("REFUSED · NOT-DERIVED", None)),
    ("refused", 12, ("REFUSED · UNVERIFIED", None)),
    ("refused", 99, ("REFUSED (exit 99)", None)),
    ("landed", 10, ("UNKNOWN (outcome='landed', exit_status=10)", "dim")),
])
def test_decision_valid_inputs_unchanged(outcome, exit_status, expect):
    """Controls: the fix only changes invalid-type inputs."""
    label, tone = labels.decision(outcome, exit_status)
    assert label == expect[0]
    if expect[1] is not None:
        assert tone == expect[1]


# ------------------------------------------------------------------ headless inspect path (api.inspect_artifact_file)


def _inspect(tmp_path, art) -> api.Inspection:
    p = tmp_path / "artifact.json"
    p.write_text(json.dumps(art), encoding="utf-8")
    return api.OperatorApi().inspect_artifact_file(p)


@pytest.mark.parametrize("outcome", ["landed", "refused"])
@pytest.mark.parametrize("exit_status", BAD_EXIT, ids=repr)
def test_inspect_invalid_exit_type_is_schema_invalid_not_landed_not_good(tmp_path, outcome, exit_status):
    ins = _inspect(tmp_path, _artifact(outcome, exit_status))  # must not raise
    assert ins.view.state is store.RunState.SCHEMA_INVALID, ins.view.state
    assert "LANDED" not in ins.label, ins.label
    assert ins.tone != "good", (ins.label, ins.tone)


def test_inspect_schema_invalid_landed_record_is_never_good_tone(tmp_path):
    """A landed/0 record that is schema-invalid for ANOTHER reason keeps its recorded word (labelled UNVALIDATED), but an
    unvalidated record is never presented in the success tone."""
    art = _artifact("landed", 0)
    del art["worker"]
    ins = _inspect(tmp_path, art)
    assert ins.view.state is store.RunState.SCHEMA_INVALID
    assert "UNVALIDATED" in ins.label and ins.tone != "good", (ins.label, ins.tone)


def test_inspect_valid_records_unchanged(tmp_path):
    ins = _inspect(tmp_path, _artifact("landed", 0))
    assert ins.view.state is store.RunState.FINISHED and ins.label.startswith("LANDED") and ins.tone == "good"
    art = _artifact("refused", 10)
    art["obligations"][0].update(verdict="refuted", witness="f(1): base 1, post 2")
    art["blocking"] = [art["obligations"][0]["id"]]
    ins = _inspect(tmp_path, art)
    assert ins.label.startswith("REFUSED · REFUTED") and ins.tone == "bad"


class _LyingStr(str):
    def __eq__(self, o):
        return True

    def __ne__(self, o):
        return False

    def __hash__(self):
        return hash("landed")


@pytest.mark.parametrize("outcome", [_LyingStr("landed"), _LyingStr("refused"), _LyingStr("x")], ids=repr)
@pytest.mark.parametrize("exit_status", [0, 10])
def test_decision_rejects_str_subclass_outcome(outcome, exit_status):
    """Kills the 'no outcome type gate' mutant (review on b4b4f366): a str subclass whose __eq__ lies must not read as landed/refused.
    JSON never yields one, but in-process callers can pass any object; the gate is type(outcome) is str."""
    label, tone = labels.decision(outcome, exit_status)
    assert label.startswith("UNKNOWN") and tone != "good", (outcome, exit_status, label, tone)
