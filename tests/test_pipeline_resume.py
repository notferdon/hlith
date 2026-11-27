# SPDX-License-Identifier: Apache-2.0
"""Targeted tests for PipelineRequest.resume_thread_id -> AgentApi.resume typed chain."""

from __future__ import annotations

from pathlib import Path
import hashlib
import json

from hlith.agent.api import AgentApiImpl
from hlith.agent.checkpoint import Layer1Session, persist_progress, thread_run_id
from hlith.agent.errors import RuntimeBoundary
from hlith.contract.capabilities import (
    AgentResult,
    FeedbackInput,
    SealedSnapshot,
    VerifiedEffect,
)
from hlith.contract.effects import EffectAccount
from hlith.contract.errors import EXIT_BOUNDARY, EXIT_LANDED
from hlith.contract.identities import InvocationId, RunId, Sha256, ThreadId, TreeOid
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.obligations import VerificationRecord
from hlith.contract.runs import GateReceipt, LandingTarget, RunMode
from hlith.feedback import LandingProbeContext
from hlith.operator.pipeline import PipelineCapabilities, PipelineRequest, run_pipeline

_SHA = Sha256("a" * 64)
_TREE0 = TreeOid("0" * 40)
_TREE1 = TreeOid("1" * 40)


class _Snap:
    def __init__(self, target: Path):
        self.target = target

    def seal_base(self, target: Path) -> SealedSnapshot:
        return SealedSnapshot(tree_oid=_TREE0, path=target)

    def reconstruct_post(self, base: SealedSnapshot, patch: bytes) -> SealedSnapshot:
        return SealedSnapshot(tree_oid=_TREE1, path=base.path)


class _HostState:
    def stable_repo_identity(self, target: Path) -> str:
        return "repo-resume-test"

    def hmac_key(self, purpose: str) -> bytes:
        return b"k" * 32

    def key(self, purpose) -> bytes:
        return b"k" * 32


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
    def verify(self, account: EffectAccount, fb: FeedbackInput, base: SealedSnapshot, post: SealedSnapshot, target: str) -> VerifiedEffect:
        ob = Obligation(
            obligation_id="deltas-confirmed",
            target_symbol="m.f",
            claim="same",
            verdict=Verdict.HELD,
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
        return VerifiedEffect(obligations=ObligationSet(obligations=(ob,)), record=rec)


class _Gate:
    def __init__(self):
        self.land_calls: list[dict] = []

    def land(self, target: Path, patch: bytes, verified: VerifiedEffect, verifier, target_identity: str, *, expected_run_id=None) -> GateReceipt:
        self.land_calls.append({"expected_run_id": expected_run_id, "record_run_id": verified.record.run_id})
        return GateReceipt(
            run_id=verified.record.run_id,
            outcome="landed",
            exit_status=EXIT_LANDED,
            blocking=(),
            landed_commit="deadbeef",
            verification_record_sha256=_SHA,
        )


class _Feedback:
    def __init__(self):
        self.registered: dict[RunId, LandingProbeContext] = {}

    def load(self, repo_identity: str, symbols: tuple[str, ...]) -> FeedbackInput:
        return FeedbackInput()

    def register_landing_context(self, run_id: RunId, ctx: LandingProbeContext) -> None:
        self.registered[run_id] = ctx

    def post_landing_probe(self, receipt: GateReceipt, landed: SealedSnapshot) -> tuple[str, ...]:
        return ()


class _ResumeAgent:
    def __init__(self, original_run_id: RunId, *, fail_duplicate: bool = False):
        self.original_run_id = original_run_id
        self.fail_duplicate = fail_duplicate
        self.calls: list[tuple[ThreadId, bool]] = []

    def run(self, request: dict) -> AgentResult:  # pragma: no cover
        raise AssertionError("run() must not be called when resume_thread_id is set")

    def resume(self, thread_id: ThreadId, *, redo_inflight: bool = False) -> AgentResult:
        self.calls.append((thread_id, redo_inflight))
        if self.fail_duplicate:
            raise RuntimeBoundary("layer1: this thread id has already been resumed to its interrupt on this host; refusing duplicate resume")
        return AgentResult(
            run_id=self.original_run_id,
            thread_id=thread_id,
            base=SealedSnapshot(tree_oid=_TREE0, path=Path(".")),
            unified_diff="diff --git a/m.py b/m.py\n",
            touched_files=("m.py",),
            proposer_provenance={"confined": True, "counts_as_e1": True, "counts_as_e1_reason": "stategraph-checkpoint-with-model"},
        )


def _caps(tmp_path: Path, agent: _ResumeAgent, gate: _Gate, fb: _Feedback) -> PipelineCapabilities:
    return PipelineCapabilities(
        snapshot_service=_Snap(tmp_path),
        host_state=_HostState(),
        agent_api=agent,
        effect_api=_Effect(),
        obligation_api=_Obligation(),
        gate_api=gate,
        verifier=object(),
        feedback_api=fb,
    )


def test_pipeline_resume_preserves_original_run_id_across_typed_chain(tmp_path: Path):
    orig = RunId("run-1234567890ab")
    tid = ThreadId("case")
    agent = _ResumeAgent(orig)
    gate = _Gate()
    fb = _Feedback()
    req = PipelineRequest(
        target=tmp_path,
        invocation_id=InvocationId("inv-resume-1"),
        mode=RunMode.HEADLESS,
        landing_target=LandingTarget.REHEARSAL,
        target_identity="t",
        resume_thread_id=tid,
        redo_inflight=True,
    )
    res = run_pipeline(req, _caps(tmp_path, agent, gate, fb))
    assert agent.calls == [(tid, True)]
    assert res.gate_receipt.outcome == "landed", res.gate_receipt
    assert res.run_receipt.run_id == orig
    assert res.run_receipt.thread_id == tid
    assert res.account is not None and res.account.run_id == orig
    assert res.verified is not None and res.verified.record.run_id == orig
    assert res.gate_receipt.run_id == orig
    assert gate.land_calls == [{"expected_run_id": orig, "record_run_id": orig}]
    assert orig in fb.registered
    assert all(ev.run_id == orig for ev in res.events)


def test_pipeline_resume_refuses_duplicate_and_rejects_external_patch_combo(tmp_path: Path):
    orig = RunId("run-1234567890ab")
    tid = ThreadId("case")
    gate = _Gate()
    fb = _Feedback()

    res_dup = run_pipeline(
        PipelineRequest(
            target=tmp_path,
            invocation_id=InvocationId("inv-dup"),
            target_identity="t",
            resume_thread_id=tid,
        ),
        _caps(tmp_path, _ResumeAgent(orig, fail_duplicate=True), gate, fb),
    )
    assert res_dup.gate_receipt.outcome == "refused"
    assert res_dup.gate_receipt.exit_status == EXIT_BOUNDARY
    assert res_dup.gate_receipt.blocking[0] == "agent-resume-boundary"
    assert gate.land_calls == []

    res_both = run_pipeline(
        PipelineRequest(
            target=tmp_path,
            invocation_id=InvocationId("inv-both"),
            target_identity="t",
            external_patch=b"diff",
            resume_thread_id=tid,
        ),
        _caps(tmp_path, _ResumeAgent(orig), gate, fb),
    )
    assert res_both.gate_receipt.outcome == "refused"
    assert res_both.gate_receipt.exit_status == EXIT_BOUNDARY
    assert gate.land_calls == []


def test_persist_progress_records_run_id_for_resume(tmp_path: Path):
    target = tmp_path / "repo"
    target.mkdir()
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    work = tmp_path / "work"
    for sub in ("stage", "ckpt", "channel", "driver", "inputs"):
        (work / sub).mkdir(parents=True)
    sess = Layer1Session(
        tmp=None,
        stage=work / "stage",
        ckpt=work / "ckpt",
        channel=work / "channel",
        driver=work / "driver",
        inputs=work / "inputs",
        thread_id="hlith-0123456789abcdef0123",
        env={},
        timeout=10.0,
    )
    sess.tmp = type("_T", (), {"name": str(work)})()
    saved = persist_progress(
        sess,
        store,
        target=target,
        base_tree="0" * 40,
        turns_done=1,
        reply_sha256=["a" * 64],
        host_state=_HostState(),
        run_id="run-abcdef123456",
    )
    assert saved is not None
    assert thread_run_id("hlith-0123456789abcdef0123", store) == "run-abcdef123456"
    meta = json.loads((saved / "meta.json").read_text())
    assert meta["run_id"] == "run-abcdef123456"
