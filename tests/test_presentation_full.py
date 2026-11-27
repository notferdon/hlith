"""Regression tests for presentation.full() on both pipeline and legacy artifact shapes."""
from __future__ import annotations
import pytest

import json
from pathlib import Path

from hlith.operator import presentation

ROOT = Path(__file__).resolve().parent.parent


EVIDENCE = ROOT / "docs" / "evidence"


def test_presentation_full_renders_pipeline_artifact_without_legacy_keys(tmp_path):
    art = {
        "outcome": "landed",
        "exit_status": 0,
        "blocking": [],
        "landed_commit": "c7853544df34790473e197c5d8abb27526441b27",
        "effect": {
            "delta_set_sha256": None,
            "deltas": [],
            "deltas_error": None,
            "input_patch_sha256": "a" * 64,
            "patch_sha256": "b" * 64,
            "preamble_removed_bytes": 0,
            "touched_files": ["src/requests/utils.py"],
            "unified_diff": "--- a/x\n+++ b/x\n",
        },
        "run": {
            "base_commit_sha": "0e322af87745eff34caffe4df68456ebc20d9068",
            "base_tree_oid": "9474485f84c7244930abc1b8023f847486572091",
            "counts_as_e1": False,
            "counts_as_e1_reason": "patch",
            "external_patch_ingested": True,
            "invocation_id": "inv-1",
            "landing_target": "rehearsal",
            "mode": "headless",
            "origin": "operator",
            "post_tree_oid": "c" * 40,
            "run_id": "run-1234",
            "started_at_utc": "2026-11-16T18:36:00Z",
            "thread_id": "th-1",
        },
        "effect_account": {
            "analyzer_id": "tree-sitter",
            "modified_callables": ["requests.utils.get_auth_from_url"],
            "impacted_sites": [{"caller": "prepare_auth"}],
        },
        "graph": None,
        "proposer_provenance": [{"kind": "command", "proposer_id": "op-demo\x1b[31m"}],
        "feedback": {
            "loaded_feedback_ids": [],
            "loaded_source_runs": [],
            "run_id": "run-1234",
            "written_feedback_ids": [],
        },
        "obligations": [
            {
                "id": "differential:requests.utils.get_auth_from_url",
                "verdict": "held",
                "claim": "behaviour preserved",
                "witness": None,
                "stop_reason": None,
                "evidence": {"explored": "50 checks", "executions": 50, "unexplored": "none"},
            }
        ],
    }
    out = presentation.full("CASE 1-neutral", 0, art, tmp_path / "1-neutral.json", [])
    assert "VERDICT" not in out and "LANDED" in out
    assert "proposer=op-demo\\x1b[31m" in out
    assert "base_tree=9474485f84c7" in out
    assert "impacted_call_sites=1" in out
    assert "requests.utils.get_auth_from_url" in out

    # Empty proposer_provenance falls back to '-'
    art["proposer_provenance"] = []
    out2 = presentation.full("CASE 1-neutral", 0, art, tmp_path / "1-neutral.json", [])
    assert "proposer=-" in out2


@pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")
def test_presentation_full_preserves_legacy_artifact_rendering():
    p = ROOT / "docs" / "evidence" / "examples" / "a-admit.json"
    art = json.loads(p.read_text(encoding="utf-8"))
    out = presentation.full("LEGACY", 0, art, p, [])
    assert "LANDED" in out and "proposer=" in out and "obligations  :" in out


@pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")
def test_artifact_schema_errors_dispatch_by_artifact_shape():
    import importlib.util

    def schema_errors(art, repo_root):
        if isinstance(art, dict) and art.get("format") == 2:
            from hlith.operator.schema import format2_errors
            return format2_errors(art)
        spec = importlib.util.spec_from_file_location("_tf", repo_root / "tests" / "test_feedback.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load legacy schema validator")
        tf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tf)
        return tf.artifact_errors(art)

    fmt2_ok = {
        "format": 2,
        "run": {"run_id": "run-0123456789ab", "mode": "companion", "landing_target": "rehearsal", "origin": "supplied-patch"},
        "outcome": "landed",
        "exit_status": 0,
        "blocking": [],
        "landed_commit": "a" * 40,
        "obligations": [],
    }
    assert schema_errors(fmt2_ok, ROOT) == []

    fmt2_bad = {**fmt2_ok, "exit_status": 12}
    assert any("landed needs" in e for e in schema_errors(fmt2_bad, ROOT))

    legacy_ok = json.loads((ROOT / "docs" / "evidence" / "acceptance" / "A1" / "R1-rerun-20261114" / "1-neutral.json").read_text(encoding="utf-8"))
    assert schema_errors(legacy_ok, ROOT) == []

    legacy_bad = {k: v for k, v in legacy_ok.items() if k != "worker"}
    assert any("missing worker" in e for e in schema_errors(legacy_bad, ROOT))
