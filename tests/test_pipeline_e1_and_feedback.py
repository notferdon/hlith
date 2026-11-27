# SPDX-License-Identifier: Apache-2.0
"""Targeted tests for counts_as_e1 provenance, feedback handoff, and durable feedback failure reporting."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib

from hlith.agent.api import AgentApiImpl
from hlith.agent.checkpoint import GraphInfo
from hlith.contract.capabilities import (
    AgentResult,
    FeedbackInput,
    SealedSnapshot,
    VerifiedEffect,
)
from hlith.contract.effects import EffectAccount
from hlith.contract.errors import EXIT_LANDED, EXIT_REFUTED, Refusal, RefusalError
from hlith.contract.events import EventKind, Phase
from hlith.contract.identities import InvocationId, RunId, Sha256, ThreadId, TreeOid
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.obligations import VerificationRecord
from hlith.contract.runs import GateReceipt, LandingTarget, RunMode
from hlith.feedback import LandingProbeContext
from hlith.operator.coordinator import Coordinator, RunRequest
from hlith.operator.pipeline import PipelineCapabilities, PipelineRequest, run_pipeline
from hlith.obligation.intent import IntentDeclaration
from hlith.runtime import delta_set_sha256


_SHA = Sha256("a" * 64)
_TREE0 = TreeOid("0" * 40)
_TREE1 = TreeOid("1" * 40)


def test_agent_api_provenance_distinguishes_scripted_worker_from_e1():
    wr_scripted = SimpleNamespace(
        base_tree=str(_TREE0),
        effect=SimpleNamespace(unified_diff="", touched_files=(), proposer_id="worker"),
        proposer_id="worker",
        turns=0,
        ignored_paths=(),
        skipped_paths=(),
        risk_flags=(),
        manifest_error="absent",
        profile_sha256="b" * 64,
        graph=None,
    )
    api = AgentApiImpl()
    prov = api._proposer_provenance(wr_scripted, None)
    assert prov["confined"] is True
    assert prov["counts_as_e1"] is False
    assert "scripted worker" in prov["counts_as_e1_reason"]
    assert prov["graph_executed"] is False
    assert prov["checkpoint_id"] is None

    wr_graph = SimpleNamespace(
        base_tree=str(_TREE0),
        effect=SimpleNamespace(unified_diff="", touched_files=(), proposer_id="model"),
        proposer_id="model",
        turns=1,
        ignored_paths=(),
        skipped_paths=(),
        risk_flags=(),
        manifest_error="absent",
        profile_sha256="b" * 64,
        graph=GraphInfo(thread_id="t1", final_checkpoint_id="ckpt-1"),
    )
    fake_proposer = type("FakeModel", (), {"kind": "ollama", "model_id": "qwen", "plumbing_only": False})()
    prov_e1 = api._proposer_provenance(wr_graph, fake_proposer)
    assert prov_e1["counts_as_e1"] is True
    assert prov_e1["graph_executed"] is True
    assert prov_e1["checkpoint_id"] == "ckpt-1"


class _Snap:
    def __init__(self, target: Path):
        self.target = target

    def seal_base(self, target: Path) -> SealedSnapshot:
        return SealedSnapshot(tree_oid=_TREE0, path=target)

    def reconstruct_post(self, base: SealedSnapshot, patch: bytes) -> SealedSnapshot:
        return SealedSnapshot(tree_oid=_TREE1, path=base.path)


class _HostState:
    def stable_repo_identity(self, target: Path) -> str:
        return "repo-test-id"


class _Effect:
    def build_account(self, run_id: RunId, base: SealedSnapshot, post: SealedSnapshot, patch: bytes) -> EffectAccount:
        return EffectAccount(
            run_id=run_id,
            base_tree_oid=base.tree_oid,
            post_tree_oid=post.tree_oid,
            patch_sha256=Sha256(hashlib.sha256(patch).hexdigest()),
            analyzer_id="test",
            modified_callables=("m.f",),
        )


class _Obligation:
    def __init__(self, *, refuse: bool = False, confirm_deltas: bool = True, delta_obligation_id: str = "deltas-confirmed"):
        self.refuse = refuse
        self.confirm_deltas = confirm_deltas
        self.delta_obligation_id = delta_obligation_id

    def verify(self, account: EffectAccount, fb: FeedbackInput, base: SealedSnapshot, post: SealedSnapshot, target: str) -> VerifiedEffect:
        if self.refuse:
            raise RefusalError(Refusal.REFUTED, "differential:m.f")
        ob = Obligation(
            obligation_id=self.delta_obligation_id,
            target_symbol="m.f",
            claim="same",
            verdict=Verdict.HELD if self.confirm_deltas else Verdict.UNVERIFIED,
            stop_reason=None if self.confirm_deltas else "test delta confirmation is unavailable",
            evidence=BoundedEvidence(explored="x", unexplored="y", executions=1),
            provenance=CheckProvenance(
                checker_id="test",
                checker_sha256="c" * 64,
                confined=True,
                proposer_paths_readable=False,
                profile_sha256="d" * 64,
                exit_code=0,
            ),
        )
        oset = ObligationSet(obligations=(ob,))
        rec = VerificationRecord(
            run_id=account.run_id,
            base_tree_oid=base.tree_oid,
            patch_sha256=account.patch_sha256,
            post_tree_oid=post.tree_oid,
            account_sha256=account.account_sha256,
            target=target,
            required_scope_digest=_SHA,
            scope_discharge_digest=_SHA,
            obligation_set_sha256=_SHA,
            consumption=(),
            context_identity_sha256=_SHA,
            checker_ids=("test",),
            issuer="test",
            mac="m",
        )
        return VerifiedEffect(obligations=oset, record=rec)


class _ProgressObligation(_Obligation):
    """New optional callback consumer used to pin the frozen event projection."""

    def verify(self, account, fb, base, post, target, *, progress=None):
        assert callable(progress)
        progress("m.f\x1b", 1, 2)
        progress("m." + "x" * 200, 2, 2)
        return super().verify(account, fb, base, post, target)


class _Gate:
    def __init__(self, *, refuse: bool = False):
        self.refuse = refuse

    def land(self, target: Path, patch: bytes, verified: VerifiedEffect, verifier, target_identity: str, *, expected_run_id=None) -> GateReceipt:
        if self.refuse:
            return GateReceipt(run_id=verified.record.run_id, outcome="refused", exit_status=EXIT_REFUTED, blocking=("differential:m.f",))
        return GateReceipt(
            run_id=verified.record.run_id,
            outcome="landed",
            exit_status=EXIT_LANDED,
            blocking=(),
            landed_commit="deadbeef",
            verification_record_sha256=_SHA,
        )


class _Feedback:
    def __init__(self, *, fail_probe: bool = False):
        self.fail_probe = fail_probe
        self.refusal_evidences: list[dict] = []
        self.registered: dict[RunId, LandingProbeContext] = {}

    def load(self, repo_identity: str, symbols: tuple[str, ...]) -> FeedbackInput:
        return FeedbackInput()

    def persist_refusal(self, receipt: GateReceipt, account: EffectAccount, evidence: dict) -> tuple[str, ...]:
        self.refusal_evidences.append(dict(evidence))
        return ("ref-1",)

    def register_landing_context(self, run_id: RunId, ctx: LandingProbeContext) -> None:
        self.registered[run_id] = ctx

    def post_landing_probe(self, receipt: GateReceipt, landed: SealedSnapshot) -> tuple[str, ...]:
        assert receipt.run_id in self.registered
        if self.fail_probe:
            raise RuntimeError("probe boom")
        return ("probe-1",)


class _Agent:
    def __init__(self, counts_as_e1: bool):
        self.counts_as_e1 = counts_as_e1

    def run(self, request: dict) -> AgentResult:
        rid = RunId(request["run_id"])
        return AgentResult(
            run_id=rid,
            thread_id=ThreadId(f"thread-{rid}"),
            base=SealedSnapshot(tree_oid=_TREE0, path=Path(request["target"])),
            unified_diff="diff --git a/m.py b/m.py\n",
            touched_files=("m.py",),
            proposer_provenance={"confined": True, "counts_as_e1": self.counts_as_e1, "counts_as_e1_reason": "test"},
        )


def _caps(target: Path, fb: _Feedback, *, ob_refuse: bool = False, gate_refuse: bool = False, e1: bool = False,
          obligation_api=None, intent=None) -> PipelineCapabilities:
    return PipelineCapabilities(
        snapshot_service=_Snap(target),
        host_state=_HostState(),
        agent_api=_Agent(e1),
        effect_api=_Effect(),
        obligation_api=obligation_api if obligation_api is not None else _Obligation(refuse=ob_refuse),
        gate_api=_Gate(refuse=gate_refuse),
        verifier=object(),
        feedback_api=fb,
        intent=intent,
    )


class _IntentAwareObligation(_Obligation):
    def __init__(self, *, mutate_intent_after_verify: bool = False):
        super().__init__()
        self.mutate_intent_after_verify = mutate_intent_after_verify

    def verify(self, account, fb, base, post, target, *, intent=None, progress=None):
        self.received_intent = intent
        self.confirmed_delta_sha256 = delta_set_sha256(intent.deltas) if intent is not None else None
        verified = super().verify(account, fb, base, post, target)
        # Real apply_intent emits no confirmation obligation for a matched approval.
        if intent is not None and intent.confirmation().matched:
            confirmation = verified.obligations.obligations[0]
            differential = Obligation(
                obligation_id="differential:m.f", target_symbol="m.f", claim="same", verdict=Verdict.HELD,
                evidence=confirmation.evidence, provenance=confirmation.provenance,
            )
            verified = VerifiedEffect(obligations=ObligationSet(obligations=(differential,)), record=verified.record)
        if self.mutate_intent_after_verify and intent is not None and intent.deltas:
            intent.deltas[0]["claim"] = "mutated after verification"
        return verified


def test_pipeline_passes_only_confirmed_host_intent_deltas_to_landing_context(tmp_path: Path):
    delta = {
        "id": "change-1",
        "symbol": "m.f",
        "kind": "behavior",
        "claim": "integer inputs now return x+2",
        "input_domain": "x is an integer",
        "pre": "x + 1",
        "post": "x + 2",
        "predicate": {"type": "expr", "param": "x", "expr": "isinstance(x, int)"},
        "expected": {"kind": "returns_expr", "expr": "x + 2"},
    }
    intent = IntentDeclaration(deltas=(delta,), approved_set_sha256=delta_set_sha256((delta,)))
    assert intent.confirmation().matched
    fb = _Feedback()
    obligation = _IntentAwareObligation()
    req = PipelineRequest(
        target=tmp_path,
        invocation_id=InvocationId("inv-approved-deltas"),
        mode=RunMode.HEADLESS,
        landing_target=LandingTarget.REHEARSAL,
        target_identity="target-approved-deltas",
        external_patch=b"diff",
    )

    landed = run_pipeline(req, _caps(tmp_path, fb, obligation_api=obligation, intent=intent))
    assert landed.gate_receipt.exit_status == EXIT_LANDED, landed.gate_receipt
    landed_ctx = fb.registered.get(landed.run_receipt.run_id)
    assert landed_ctx is not None, [(e.kind.value, e.detail) for e in landed.events if e.kind is EventKind.PROGRESS]
    assert obligation.received_intent is intent
    assert landed_ctx.deltas_confirmed is True
    assert landed_ctx.approved_deltas == (delta,)

    mutated_delta = dict(delta)
    mutated_intent = IntentDeclaration(deltas=(mutated_delta,), approved_set_sha256=delta_set_sha256((mutated_delta,)))
    mutated_fb = _Feedback()
    mutating_obligation = _IntentAwareObligation(mutate_intent_after_verify=True)
    mutated_landing = run_pipeline(
        req,
        _caps(tmp_path, mutated_fb, obligation_api=mutating_obligation, intent=mutated_intent),
    )
    mutated_ctx = mutated_fb.registered[mutated_landing.run_receipt.run_id]
    assert mutating_obligation.confirmed_delta_sha256 == intent.approved_set_sha256
    assert mutated_ctx.deltas_confirmed is False
    assert mutated_ctx.approved_deltas == ()
    assert not mutated_intent.confirmation().matched

    unconfirmed_fb = _Feedback()
    unconfirmed = run_pipeline(
        req,
        _caps(tmp_path, unconfirmed_fb, obligation_api=_Obligation(confirm_deltas=False), intent=intent),
    )
    assert unconfirmed.gate_receipt.exit_status == EXIT_LANDED
    unconfirmed_ctx = unconfirmed_fb.registered[unconfirmed.run_receipt.run_id]
    assert unconfirmed_ctx.deltas_confirmed is False
    assert unconfirmed_ctx.approved_deltas == ()

    invalid_fb = _Feedback()
    invalid = run_pipeline(
        req,
        _caps(tmp_path, invalid_fb,
              obligation_api=_Obligation(confirm_deltas=False, delta_obligation_id="deltas-invalid"), intent=intent),
    )
    assert invalid.gate_receipt.exit_status == EXIT_LANDED
    invalid_ctx = invalid_fb.registered[invalid.run_receipt.run_id]
    assert invalid_ctx.deltas_confirmed is False
    assert invalid_ctx.approved_deltas == ()


def test_pipeline_registers_landing_context_and_surfaces_feedback_failure(tmp_path: Path):
    fb = _Feedback(fail_probe=True)
    req = PipelineRequest(
        target=tmp_path,
        invocation_id=InvocationId("inv-1"),
        mode=RunMode.STANDALONE,
        landing_target=LandingTarget.REHEARSAL,
        target_identity="target-id",
    )
    res = run_pipeline(req, _caps(tmp_path, fb, e1=False))
    assert res.counts_as_e1 is False
    assert res.gate_receipt.outcome == "landed"
    assert res.gate_receipt.exit_status == EXIT_LANDED
    ctx = fb.registered[res.run_receipt.run_id]
    assert ctx.repo_identity == "repo-test-id"
    assert ctx.symbols == ("m.f",)
    assert ctx.deltas_confirmed is False
    assert ctx.approved_deltas == ()
    fb_errs = [e.detail["feedback_error"] for e in res.events if e.kind is EventKind.PROGRESS and "feedback_error" in e.detail]
    assert any("landing completed; feedback recording failed" in msg for msg in fb_errs)
    art = Coordinator._artifact(res.run_receipt, RunRequest(repo=tmp_path, mode=RunMode.STANDALONE, landing_target=LandingTarget.REHEARSAL), res)
    assert any("landing completed; feedback recording failed" in msg for msg in art["feedback_errors"])


def test_pipeline_passes_repo_identity_on_l3_and_l4_refusals(tmp_path: Path):
    fb_l3 = _Feedback()
    req = PipelineRequest(
        target=tmp_path,
        invocation_id=InvocationId("inv-2"),
        mode=RunMode.HEADLESS,
        landing_target=LandingTarget.REHEARSAL,
        target_identity="t",
        external_patch=b"diff",
    )
    res_l3 = run_pipeline(req, _caps(tmp_path, fb_l3, ob_refuse=True))
    assert res_l3.gate_receipt.outcome == "refused"
    assert fb_l3.refusal_evidences[0]["repo_identity"] == "repo-test-id"

    fb_l4 = _Feedback()
    res_l4 = run_pipeline(req, _caps(tmp_path, fb_l4, gate_refuse=True))
    assert res_l4.gate_receipt.outcome == "refused"
    assert fb_l4.refusal_evidences[0]["repo_identity"] == "repo-test-id"


def test_obligation_progress_is_clean_bounded_and_cannot_change_the_verdict(tmp_path: Path):
    fb = _Feedback()
    req = PipelineRequest(
        target=tmp_path,
        invocation_id=InvocationId("inv-progress"),
        mode=RunMode.HEADLESS,
        landing_target=LandingTarget.REHEARSAL,
        target_identity="target-progress",
    )

    def failing_sink(event):
        if event.kind is EventKind.PROGRESS and event.phase is Phase.OBLIGATION:
            raise OSError("event storage unavailable")

    res = run_pipeline(
        req,
        _caps(tmp_path, fb, obligation_api=_ProgressObligation()),
        event_sink=failing_sink,
    )

    progress = [e for e in res.events if e.kind is EventKind.PROGRESS and e.phase is Phase.OBLIGATION]
    assert res.gate_receipt.outcome == "landed" and res.gate_receipt.exit_status == EXIT_LANDED
    assert [e.detail for e in progress] == [
        {"target": "m.f\\x1b", "i": 1, "n": 2},
        {"target": "m." + "x" * 158, "i": 2, "n": 2},
    ]
    assert all(set(e.detail) == {"target", "i", "n"} for e in progress)
    assert all(not any(ord(char) < 32 or ord(char) == 127 for char in e.detail["target"]) for e in progress)
