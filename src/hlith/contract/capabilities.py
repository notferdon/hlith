# SPDX-License-Identifier: Apache-2.0
"""Capability and section API signatures (Protocols). Implementations live in their section packages."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .effects import EffectAccount
from .errors import BoundaryReason
from .feedback import FeedbackInput
from .guards import ExportedGuardCatalog
from .identities import RunId, Sha256, TargetIdentity, ThreadId, TreeOid
from .obligations import RequiredScope, ScopeDischarge, VerificationRecord
from .runs import GateReceipt


class KeyPurpose(str, enum.Enum):
    VERIFIER_ISSUE = "verifier-issue"  # held by the L3 controller; unreadable by agent, evaluators, renderer
    GATE_JOURNAL = "gate-journal"  # held by L4 only
    CHECKPOINT = "checkpoint"  # held by L1 supervisor


@dataclass(frozen=True)
class SealedSnapshot:
    tree_oid: TreeOid
    path: Path  # read-only export owned by the trusted host


class GitRead(Protocol):
    """Allowlisted READ-ONLY Git operations. There is no run_git(args): a write operation is not expressible here."""

    def head_tree(self, repo: Path) -> TreeOid: ...
    def export_tree(self, repo: Path, tree: TreeOid, dest: Path) -> None: ...
    def repository_hostile_reason(self, repo: Path) -> str | None: ...


class SnapshotService(Protocol):
    def seal_base(self, repo: Path) -> SealedSnapshot: ...
    def reconstruct_post(self, base: SealedSnapshot, patch: bytes) -> SealedSnapshot: ...  # independent, temp index


class HostState(Protocol):
    """Local-first, offline: $XDG_STATE_HOME/hlith/repositories/<stable-repo-identity>/{feedback,runs,evidence,checkpoints,journal}."""

    def stable_repo_identity(self, repo: Path) -> str: ...
    def namespace(self, repo_identity: str, name: str) -> Path: ...  # name in feedback|runs|evidence|checkpoints|journal|cache (v2.2)
    def key(self, purpose: KeyPurpose) -> bytes: ...


class VerificationIssuer(Protocol):
    def issue(self, record_body: VerificationRecord) -> VerificationRecord: ...  # returns the record with its mac


class VerificationVerifier(Protocol):
    def verify(self, record: VerificationRecord) -> bool: ...


@dataclass(frozen=True)
class AgentResult:
    run_id: RunId
    thread_id: ThreadId
    base: SealedSnapshot
    unified_diff: str
    touched_files: tuple[str, ...]
    proposer_provenance: dict
    authenticated_manifest: dict | None = None  # host-authenticated captured manifest; never caller input


class AgentApi(Protocol):  # L1
    def run(self, request: dict) -> AgentResult: ...
    def resume(self, thread_id: ThreadId, *, redo_inflight: bool = False) -> AgentResult: ...


class EffectApi(Protocol):  # L2
    def build_account(self, run_id: RunId, base: SealedSnapshot, post: SealedSnapshot, patch: bytes) -> EffectAccount: ...


@dataclass(frozen=True)
class VerifiedEffect:
    obligations: object  # hlith.contract.legacy.ObligationSet until migration step M1
    record: VerificationRecord
    # contract v2.3: the typed scope evidence travels WITH the record (no side registry). The gate refuses (fail closed)
    # when either is absent or when their digests differ from the record's required_scope_digest / scope_discharge_digest.
    required_scope: RequiredScope | None = None
    scope_discharge: ScopeDischarge | None = None


class ObligationApi(Protocol):  # L3
    def verify(self, account: EffectAccount, feedback: FeedbackInput, base: SealedSnapshot, post: SealedSnapshot,
               target: TargetIdentity, *, intent=None,
               guard_catalog: ExportedGuardCatalog | None = None,
               progress: Callable[[str, int, int], None] | None = None) -> VerifiedEffect: ...


class GateApi(Protocol):  # L4: the only code that may commit the original target
    # v2.5 (add-only, case): expected_run_id binds VerificationRecord.run_id to the current run.
    def land(self, target: Path, patch: bytes, verified: VerifiedEffect, verifier: VerificationVerifier,
             expected_identity: TargetIdentity, expected_run_id: RunId | None = None) -> GateReceipt: ...
    def recover(self, target: Path) -> str: ...


class FeedbackApi(Protocol):  # L5
    def load(self, repo_identity: str, symbols: tuple[str, ...]) -> FeedbackInput: ...  # raises on corrupt/missing required input
    def recurrent_constructs(self, repo_identity: str, constructs: tuple[dict, ...]) -> list[dict]: ...
    def persist_refusal(self, receipt: GateReceipt, account: EffectAccount, evidence: dict) -> tuple[str, ...]: ...
    def post_landing_probe(self, receipt: GateReceipt, landed: SealedSnapshot) -> tuple[str, ...]: ...


__all__ = [
    "KeyPurpose", "SealedSnapshot", "GitRead", "SnapshotService", "HostState", "VerificationIssuer", "VerificationVerifier",
    "AgentResult", "AgentApi", "EffectApi", "VerifiedEffect", "ObligationApi", "GateApi", "FeedbackApi", "BoundaryReason", "Sha256",
]
