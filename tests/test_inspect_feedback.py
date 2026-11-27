from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from hlith.operator import inspect_cmd
from hlith.operator.api import OperatorApi
from hlith.operator.schema import artifact_errors


def _recorded_artifact() -> dict:
    """Small recorded format-2 artifact fixture with the same feedback paths as review's captured out.json."""
    run_id = "run-123456789abc"
    ids = [f"fb-{i:02d}-0123456789abcdef" for i in range(1, 5)]
    sources = {fid: f"run-{i:012x}" for i, fid in enumerate(ids, 100)}
    return {
        "format": 2,
        "run": {"run_id": run_id, "mode": "headless", "landing_target": "rehearsal", "origin": "supplied-patch"},
        "outcome": "refused",
        "exit_status": 4,
        "landed_commit": None,
        "blocking": [],
        "obligations": [],
        "feedback": {
            "run_id": run_id,
            "loaded_feedback_ids": ids,
            "loaded_source_runs": sources,
            "written_feedback_ids": ["fb-written-0123456789abcdef"],
        },
        "feedback_limit": None,
    }


def _inspect(tmp_path: Path, artifact: dict, *, limit: str | None = None):
    path = tmp_path / "out.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    insp = OperatorApi().inspect_artifact_file(path)
    if limit is not None:
        event = SimpleNamespace(
            seq=42,
            kind=SimpleNamespace(value="progress"),
            phase=SimpleNamespace(value="feedback"),
            detail={"feedback_limit": limit},
        )
        insp = replace(insp, events=(event,))
    return insp


def test_inspect_renders_full_feedback_ids_source_runs_and_unprobed_limit(tmp_path):
    artifact = _recorded_artifact()
    assert artifact_errors(artifact) == []
    limit = "UNPROBED by Layer 5: probe could not import pkg.target: " + "retry remains unavailable " * 18 + "LIMIT-END-9f23"
    insp = _inspect(tmp_path, artifact, limit=limit)

    result = inspect_cmd.payload(insp)
    assert result["envelope"] == "hlith.inspect/1"
    assert result["feedback"] == {
        "loaded_feedback_ids": artifact["feedback"]["loaded_feedback_ids"],
        "loaded_source_runs": artifact["feedback"]["loaded_source_runs"],
        "written_feedback_ids": artifact["feedback"]["written_feedback_ids"],
    }
    assert result["feedback_limit"] is None
    assert result["feedback_limit_events"] == [{"seq": 42, "feedback_limit": limit}]
    assert result["progress"][0]["detail"] == {"feedback_limit": limit}

    rendered = inspect_cmd._render(insp)
    assert "feedback: none loaded" not in rendered
    for fid, source in artifact["feedback"]["loaded_source_runs"].items():
        assert fid in rendered
        assert source in rendered
    assert artifact["feedback"]["written_feedback_ids"][0] in rendered
    assert "UNPROBED by Layer 5: probe could not import pkg.target" in rendered
    assert "LIMIT-END-9f23" in rendered  # the named limit was wrapped, not cut to a fixed character count
    feedback_section = rendered.split("feedback loaded:", 1)[1].split("feedback written ids:", 1)[0]
    assert all(len(line) <= 80 for line in feedback_section.splitlines())


def test_inspect_says_feedback_none_loaded_when_recorded_store_is_empty(tmp_path):
    artifact = _recorded_artifact()
    artifact["feedback"]["loaded_feedback_ids"] = []
    artifact["feedback"]["loaded_source_runs"] = {}
    artifact["feedback"]["written_feedback_ids"] = []
    insp = _inspect(tmp_path, artifact)

    result = inspect_cmd.payload(insp)
    assert result["feedback"]["loaded_feedback_ids"] == []
    assert result["feedback"]["loaded_source_runs"] == {}
    rendered = inspect_cmd._render(insp)
    assert "feedback: none loaded" in rendered
    assert "version: not recorded" in rendered


def test_inspect_projects_actual_checker_and_static_reach(tmp_path):
    from hlith.operator.coordinator import _obligation_rows
    from hlith.types import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict

    prov = CheckProvenance("independent-check", "1" * 64, True, False, "2" * 64, 0)
    row = Obligation("binding:m.f", "m.f", "call binds", Verdict.HELD,
                     BoundedEvidence(1, "one caller", "dynamic calls"), prov)
    artifact = _recorded_artifact()
    artifact["obligations"] = _obligation_rows(SimpleNamespace(obligations=ObligationSet((row,))))
    artifact["effect_account"] = {
        "analyzer_id": "analyzer@123", "modified_callables": ["m.f"],
        "impacted_sites": [{"caller": "app.run", "file": "app.py", "line": 13}],
        "impacted_tests": [{"node_id": "tests/test_app.py::test_run"}],
    }
    inspection = _inspect(tmp_path, artifact)
    data = inspect_cmd.payload(inspection)
    assert data["effect_account"] == artifact["effect_account"]
    assert data["obligations"][0]["provenance"]["checker_sha256"] == prov.checker_sha256
    assert data["obligations"][0]["provenance"]["profile_sha256"] == prov.profile_sha256
    display = inspect_cmd._render(inspection)
    assert "app.run at app.py:13" in display and "tests/test_app.py::test_run" in display
    assert "independent-check · confined · proposer paths denied" in display
    del artifact["obligations"][0]["provenance"]
    assert "checker: not recorded" in inspect_cmd._render(_inspect(tmp_path, artifact))


def test_inspect_displays_confined_target_python_observation(tmp_path):
    artifact = _recorded_artifact()
    observation = {
        "executable": "/confined/worker/bin/python",
        "version": "3.14.2",
        "implementation": "cpython",
        "observed_in": "confined-differential-worker",
    }
    artifact["target_python"] = observation
    assert artifact_errors(artifact) == []

    insp = _inspect(tmp_path, artifact)
    result = inspect_cmd.payload(insp)
    rendered = inspect_cmd._render(insp)

    assert result["target_python"] == observation
    assert "/confined/worker/bin/python" in rendered
    assert "version: 3.14.2" in rendered
    assert "implementation cpython" in rendered
    assert "observed in confined-differential-worker" in rendered


def test_inspect_marks_missing_or_invalid_target_python_version_as_not_recorded(tmp_path):
    for invalid in ("malformed", {}, {"version": 3.14}):
        artifact = _recorded_artifact()
        artifact["target_python"] = invalid
        rendered = inspect_cmd._render(_inspect(tmp_path, artifact))
        assert "version: not recorded" in rendered


def test_inspect_keeps_long_witness_and_evidence_text_unclipped(tmp_path):
    artifact = _recorded_artifact()
    witness = "witness detail " * 24 + "WITNESS-END-1ac4"
    explored = "explored path " * 24 + "EXPLORED-END-3be5"
    unexplored = "unexplored path " * 24 + "UNEXPLORED-END-6fd7"
    claim = "complete claim text " * 16 + "CLAIM-END-8c20"
    artifact["obligations"] = [{
        "id": "effect:test",
        "verdict": "refuted",
        "claim": claim,
        "witness": witness,
        "stop_reason": None,
        "evidence": {"executions": 1, "explored": explored, "unexplored": unexplored},
    }]

    rendered = inspect_cmd._render(_inspect(tmp_path, artifact))
    flattened = " ".join(rendered.split())

    for suffix in ("WITNESS-END-1ac4", "EXPLORED-END-3be5", "UNEXPLORED-END-6fd7", "CLAIM-END-8c20"):
        assert suffix in flattened
    assert witness in flattened
    assert explored in flattened
    assert unexplored in flattened
    assert claim in flattened
    evidence_section = rendered.split("evidence:\n", 1)[1].split("\noperator record", 1)[0]
    assert all(len(line) <= 80 for line in evidence_section.splitlines())

