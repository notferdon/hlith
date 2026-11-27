"""Host-only binding of a resumed effect's intent to its authenticated manifest."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from hlith.contract.effects import delta_set_sha256
from hlith.contract.identities import ThreadId
from hlith.obligation.intent import IntentDeclaration
from hlith.operator.pipeline import PipelineRequest, _resume_intent


DELTA = {
    "id": "d1", "symbol": "m.add_one", "kind": "behavior", "claim": "returns the same value",
    "input_domain": "x is an int", "pre": "x + 1", "post": "x + 2",
}


def _request(approved=None):
    return PipelineRequest(target=Path("/repo"), invocation_id="inv-000000000000",  # type: ignore[arg-type]
                           resume_thread_id=ThreadId("hlith-00000000000000000000"), approve_deltas=approved)


def _captured(manifest):
    return SimpleNamespace(proposer_provenance={"resumed_from": "effect-interrupt"}, authenticated_manifest=manifest)


def test_captured_resume_exact_hash_binds_only_authenticated_deltas():
    sha = delta_set_sha256((DELTA,))
    intent = _resume_intent(_request(sha), _captured({"deltas": [DELTA]}))
    assert isinstance(intent, IntentDeclaration)
    assert intent.deltas == (DELTA,)
    assert intent.approved_set_sha256 == sha
    assert intent.confirmation().matched is True


def test_captured_resume_mismatch_and_invalid_claims_remain_unapproved():
    mismatch = _resume_intent(_request("0" * 64), _captured({"deltas": [DELTA]}))
    assert mismatch.deltas == (DELTA,)
    assert mismatch.approved_set_sha256 is None
    assert mismatch.confirmation().delta_set_sha256 == delta_set_sha256((DELTA,))
    assert mismatch.confirmation().matched is False

    invalid_claim = {"id": "bad", "symbol": "not a qualified name"}
    invalid = _resume_intent(_request(), _captured({"deltas": [invalid_claim]}))
    assert invalid.deltas == (invalid_claim,)
    assert invalid.approved_set_sha256 is None

    no_delta = _resume_intent(_request("a" * 64), _captured({"deltas": []}))
    assert no_delta.deltas == ()
    assert no_delta.approved_set_sha256 is None
    assert no_delta.confirmation() is None


def test_unbound_caller_approval_cannot_supply_an_intent():
    result = SimpleNamespace(proposer_provenance={"resumed_from": "agent-progress"}, authenticated_manifest=None)
    intent = _resume_intent(_request("a" * 64), result)
    assert intent.deltas == ()
    assert intent.approved_set_sha256 is None


def test_pipeline_has_one_central_intent_verify_seam():
    source_path = Path(__file__).parents[1] / "src/hlith/operator/pipeline.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    callers = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "verify":
            continue
        parent = next((p for p in ast.walk(tree) if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and p.lineno <= node.lineno <= p.end_lineno), None)
        callers.append((node, parent.name if parent else None))
    assert len(callers) == 1
    assert all(name == "_verify_with_resume_intent" for _, name in callers)
    source = source_path.read_text(encoding="utf-8")
    assert '_accepts_keyword(obligation_api.verify, "intent")' in source
    assert 'kwargs["intent"] = intent' in source
    assert "IntentDeclaration(" not in source
