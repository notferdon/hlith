# SPDX-License-Identifier: Apache-2.0
"""Trusted coordinator pipeline: wires L1-L5 frozen capabilities in identity-chain order.

Contains no engine behaviour beyond phase ordering, identity propagation, missing-capability /
identity-mismatch fail-closed BoundaryReason refusals (exit 4), GateReceipt/exit mapping,
rehearsal-vs-original labelling, and contract Event emission.
"""

from __future__ import annotations

from ..hostio.integrity import capture_target_identity  # ONE implementation: the gate re-captures with this same function
from ..feedback import LandingProbeContext

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import inspect
import os
from pathlib import Path
from typing import Callable

from ..contract.capabilities import (
    AgentApi,
    AgentResult,
    EffectApi,
    FeedbackApi,
    GateApi,
    HostState,
    ObligationApi,
    SealedSnapshot,
    SnapshotService,
    VerificationVerifier,
    VerifiedEffect,
)
from ..contract.effects import EffectAccount
from ..contract.legacy import Verdict
from ..contract.errors import (
    EXIT_BOUNDARY,
    EXIT_LANDED,
    EXIT_REFUTED,
    EXIT_UNVERIFIED,
    BoundaryReason,
    Refusal,
    RefusalError,
)
from ..hostio.confinement import ConfinementBoundaryError
from ..contract.events import Event, EventKind, Phase
from ..contract.feedback import FeedbackInput
from ..contract.identities import (
    InvocationId,
    RunId,
    Sha256,
    TargetIdentity,
    ThreadId,
    new_run_id,
    sha256_hex,
)
from ..contract.runs import GateReceipt, LandingTarget, RunMode, RunReceipt
from ..hostio.textsafe import clean
from ..obligation.intent import IntentDeclaration


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PipelineCapabilities:
    """Frozen capability bundle injected into the coordinator pipeline."""

    snapshot_service: SnapshotService | None = None
    host_state: HostState | None = None
    agent_api: AgentApi | None = None
    effect_api: EffectApi | None = None
    obligation_api: ObligationApi | None = None
    gate_api: GateApi | None = None
    verifier: VerificationVerifier | None = None
    feedback_api: FeedbackApi | None = None
    intent: IntentDeclaration | None = None


@dataclass(frozen=True)
class PipelineRequest:
    """Coordinator request. ``run_id`` is never caller-supplied; the engine allocates it."""

    target: Path
    invocation_id: InvocationId
    mode: RunMode = RunMode.HEADLESS
    landing_target: LandingTarget = LandingTarget.ORIGINAL
    agent_request: dict | None = None
    external_patch: bytes | None = None
    external_patch_label: str = "external-patch"
    manifest_bytes: bytes | None = None
    target_identity: TargetIdentity | None = None
    resume_thread_id: ThreadId | None = None
    redo_inflight: bool = False
    approve_deltas: str | None = None  # raw 64-hex input; it is not trusted until bound to the resumed host manifest
    expected_head: str | None = None  # the reviewed base commit: handed to the gate, which refuses a landing when HEAD moved under its lock


@dataclass(frozen=True)
class PipelineResult:
    """Outcome of one coordinator pipeline run."""

    run_receipt: RunReceipt
    gate_receipt: GateReceipt
    events: tuple[Event, ...]
    base: SealedSnapshot | None = None
    post: SealedSnapshot | None = None
    agent_result: AgentResult | None = None
    account: EffectAccount | None = None
    feedback_input: FeedbackInput | None = None
    verified: VerifiedEffect | None = None
    feedback_records: tuple[str, ...] = ()
    recurrent_constructs: tuple[dict, ...] = ()
    external_patch_ingested: bool = False
    counts_as_e1: bool = False


class _EventLog:
    def __init__(self, run_id: RunId, sink: Callable[[Event], None] | None) -> None:
        self._run_id = run_id
        self._sink = sink
        self._seq = 0
        self.events: list[Event] = []

    def rebind_run_id(self, run_id: RunId) -> None:
        self._run_id = run_id
        self.events = [replace(ev, run_id=run_id) for ev in self.events]

    def emit(self, kind: EventKind, phase: Phase | None, detail: dict | None = None) -> None:
        self._seq += 1
        ev = Event(
            run_id=self._run_id,
            seq=self._seq,
            kind=kind,
            phase=phase,
            ts=_utc_now(),
            detail=detail or {},
        )
        self.events.append(ev)
        if self._sink is not None:
            self._sink(ev)


def _boundary_receipt(run_id: RunId, reason: BoundaryReason | str, detail: str | None = None) -> GateReceipt:
    code = reason.value if isinstance(reason, BoundaryReason) else str(reason)
    blocking = (code, detail) if detail else (code,)
    return GateReceipt(
        run_id=run_id,
        outcome="refused",
        exit_status=EXIT_BOUNDARY,
        blocking=blocking,
        landed_commit=None,
        verification_record_sha256=None,
    )


def _refusal_receipt(run_id: RunId, err: RefusalError) -> GateReceipt:
    from ..contract.errors import EXIT_BY_REFUSAL

    return GateReceipt(
        run_id=run_id,
        outcome="refused",
        exit_status=EXIT_BY_REFUSAL.get(err.refusal, EXIT_UNVERIFIED),
        blocking=(err.refusal.value, err.reason),
        landed_commit=None,
        verification_record_sha256=None,
    )


def _gate_explored(base, post) -> dict:
    """The gate's explored inputs for this run's sealed trees (derive.explored_inputs_for); {} on any failure (UNKNOWN, old L5 order)."""
    try:
        from .. import derive as _derive
        return _derive.explored_inputs_for(base.path, post.path)
    except Exception:  # noqa: BLE001 - feedback ordering only; never a verdict input
        return {}


def _exported_guard_callables(account: EffectAccount, verified: VerifiedEffect | None) -> tuple[str, ...]:
    """Added callables verified as provenance-bound exported guards for THIS account (not production feedback targets).

    Classification relies strictly on L3's verified obligation/consumption/scope provenance:
    - symbol is an unreached added callable of ``account`` (absent from modified/removed/reached_from);
    - carries a HELD, account-bound ``exported-guard:`` obligation from ``hlith.obligation.exported_guard``;
    - backed by an ``AccountConsumption`` record bound to ``account.account_sha256`` naming that exact symbol;
    - discharged in ``verified.scope_discharge`` as ``callable:<sym> -> <obligation_id>``.

    Never classifies by file path, symbol name substring, or missing-file fallback.
    """
    if verified is None or not account.added_callables:
        return ()
    reached_added = {a for a, _ in account.added_reached_from}
    added_only = (
        set(account.added_callables)
        - set(account.modified_callables)
        - set(account.removed_callables)
        - reached_added
    )
    if not added_only:
        return ()
    obs = getattr(getattr(verified, "obligations", None), "obligations", ()) or ()
    rec = getattr(verified, "record", None)
    consumption = getattr(rec, "consumption", ()) or () if rec is not None else ()
    cons_by_id = {
        c.obligation_id: c
        for c in consumption
        if getattr(c, "account_sha256", None) == account.account_sha256
    }
    discharge = getattr(verified, "scope_discharge", None)
    if discharge is None:
        return ()
    discharged_by = dict(getattr(discharge, "entries", ()) or ())
    out: set[str] = set()
    for ob in obs:
        ob_id = str(getattr(ob, "obligation_id", "") or "")
        if not ob_id.startswith("exported-guard:"):
            continue
        if getattr(ob, "verdict", None) is not Verdict.HELD:
            continue
        if not bool(getattr(ob, "account_bound", False)):
            continue
        prov = getattr(ob, "provenance", None)
        if (
            getattr(prov, "checker_id", None) != "hlith.obligation.exported_guard"
            or getattr(prov, "confined", False) is not True
            or getattr(prov, "proposer_paths_readable", True) is not False
        ):
            continue
        sym = str(getattr(ob, "target_symbol", "") or "")
        if sym not in added_only:
            continue
        cons = cons_by_id.get(ob_id)
        if cons is None or sym not in getattr(cons, "symbols", ()):
            continue
        if discharged_by.get(f"callable:{sym}") != ob_id:
            continue
        out.add(sym)
    return tuple(sorted(out))


def _refusal_feedback_evidence(caps, account, verified, base, post, *, blocking, rehearsal, repo_identity, log) -> dict:
    """Evidence handed to L5 ``persist_refusal`` after an L4 refusal. Only gate-side facts flow: refuted symbols come from the
    VERIFIED obligations (Verdict.REFUTED) of this run, witnesses from the obligation engine's own observation bound to THIS
    account digest. Nothing here is read from the proposer. A missing or stale witness is reported and stored as nothing."""
    refuted = sorted({str(o.target_symbol) for o in getattr(getattr(verified, "obligations", None), "obligations", ())
                      if getattr(o, "verdict", None) is Verdict.REFUTED and "." in str(getattr(o, "target_symbol", ""))})
    witnesses: tuple = ()
    getter = getattr(caps.obligation_api, "observed_witnesses", None)
    if not callable(getter):
        log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": "no checker witnesses available from the obligation engine: no witness pin stored"})
    else:
        try:
            observed = tuple(getter())
        except Exception as e:  # noqa: BLE001
            observed = ()
            log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": f"checker witnesses unreadable ({type(e).__name__}): no witness pin stored"})
        mine = tuple(w for w in observed if isinstance(w, dict) and w.get("account_sha256") == str(account.account_sha256))
        if len(mine) != len(observed):
            log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": f"{len(observed) - len(mine)} witness(es) not bound to this run's account digest were dropped"})
        witnesses = mine
    return {"blocking": list(blocking), "rehearsal": rehearsal, "repo_identity": repo_identity,
            "base": base, "post": post, "refuted_symbols": tuple(refuted), "witnesses": witnesses,
            "constructs": _construct_feedback_rows(account)}


def _construct_feedback_rows(account: EffectAccount) -> tuple[dict, ...]:
    """Project account-bound unresolved facts into L5's refusal and recurrence shape."""
    return tuple(
        {
            "file_path": c.file_path,
            "line": c.line_number,
            "kind": c.kind,
            "caller_qualified_name": c.caller_qualified_name,
            "node_sha256": c.node_sha256,
            "side": c.side,
            "provenance": {"source_file": c.file_path, "node_sha256": c.node_sha256},
        }
        for c in account.unresolved_constructs
    )


def _resume_intent(request: PipelineRequest, agent_result: AgentResult | None):
    """Build a per-call intent only from the host-authenticated captured manifest.

    A caller-provided digest never becomes an intent by itself. Invalid or mismatched approval is
    deliberately downgraded to an unapproved declaration so the normal gate records exit 12.
    """
    from .intent.manifest import intent_from_manifest

    captured_resume = bool(
        request.resume_thread_id is not None
        and agent_result is not None
        and (agent_result.proposer_provenance or {}).get("resumed_from") == "effect-interrupt"
    )
    # A single-shot scripted worker run: the host read the worker's manifest from the confined channel after the run (the same
    # host-read document the legacy engine and the effect-interrupt resume use). It is the declared intent; --approve-deltas binds to
    # it below exactly as on resume. Without such a captured manifest nothing changes.
    captured_worker = bool(
        request.resume_thread_id is None
        and agent_result is not None
        and (agent_result.proposer_provenance or {}).get("resumed_from") is None
        and agent_result.authenticated_manifest is not None
    )
    if not (captured_resume or captured_worker):
        # Defend the lower-level API too: CLI checks are not an authorization boundary.
        if request.approve_deltas is not None:
            return intent_from_manifest(None, None)
        return None

    manifest = agent_result.authenticated_manifest
    if manifest is None:
        return intent_from_manifest(None, None)
    if not isinstance(manifest, dict):
        return intent_from_manifest({"deltas": [manifest]}, None)
    deltas = manifest.get("deltas", [])
    if request.approve_deltas is not None:
        from ..obligation.intent import ApprovalBindingError, bind_approval

        try:
            return bind_approval(deltas, request.approve_deltas).intent
        except ApprovalBindingError:
            pass
    return intent_from_manifest({"deltas": deltas}, None)


def _worker_failed_reason(failed: dict) -> str:
    """The truthful refusal for a scripted worker command that exited non-zero and changed nothing (same wording as the legacy
    engine's report): the exit code, the last stderr line or that stderr is empty, and the usual confinement cause. Kept under the
    report's 220-character line so the hint survives."""
    rc = failed.get("returncode")
    raw = str(failed.get("stderr_tail") or "")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    base = f"worker command exited {rc}, no change"
    hint = "use /usr/bin/python3 or --worker-ro"
    if not lines:
        return f"{base}; stderr empty: it likely could not start in the confinement (interpreter or libraries not readable); {hint}"
    tail = clean(lines[-1]).strip()[:90]
    if any(k in raw for k in ("No such file", "Permission denied", "execvp", "_confine.py")):
        return f"{base}; stderr ends: {tail}; interpreter or paths not readable in the confinement? {hint}"
    return f"{base}; stderr ends: {tail}"


def _accepts_keyword(method, name: str) -> bool:
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False
    return name in parameters or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values())


def _emit_obligation_progress(log: _EventLog, target: str, i: int, n: int) -> None:
    """Best-effort L3 progress projection; reporting errors never affect verification."""
    try:
        if (isinstance(i, bool) or not isinstance(i, int) or isinstance(n, bool) or not isinstance(n, int)
                or i < 1 or n < i):
            return
        log.emit(EventKind.PROGRESS, Phase.OBLIGATION, {"target": clean(target)[:160], "i": i, "n": n})
    except Exception:  # noqa: BLE001
        return


def _verify_with_resume_intent(obligation_api, request, agent_result, account, feedback_input, base, post, target_identity,
                               *, base_intent=None, guard_catalog=None, progress=None):
    """Verify with and return the exact host-built intent active for this run."""
    resumed_intent = _resume_intent(request, agent_result)
    intent = resumed_intent if resumed_intent is not None else base_intent
    try:
        verified_intent_confirmation = intent.confirmation() if intent is not None else None
    except Exception:  # malformed claims still go through L3's normal fail-closed path
        verified_intent_confirmation = None
    kwargs = {"progress": progress} if progress is not None and _accepts_keyword(obligation_api.verify, "progress") else {}
    if intent is not None and _accepts_keyword(obligation_api.verify, "intent"):
        kwargs["intent"] = intent
    if guard_catalog is not None and _accepts_keyword(obligation_api.verify, "guard_catalog"):
        kwargs["guard_catalog"] = guard_catalog
    verified = obligation_api.verify(account, feedback_input, base, post, target_identity, **kwargs)
    return verified, intent, verified_intent_confirmation


def _run_pipeline_body(
    request: PipelineRequest,
    caps: PipelineCapabilities,
    *,
    event_sink: Callable[[Event], None] | None = None,
) -> PipelineResult:
    """Execute the full L1 -> L2 -> L5 -> L3 -> L4 -> L5 pipeline in identity-chain order."""
    run_id = new_run_id()
    log = _EventLog(run_id, event_sink)
    target = Path(request.target).resolve()
    external_ingestion = request.external_patch is not None
    counts_as_e1 = False
    thread_id: ThreadId | None = None

    def _finish_boundary(
        reason: BoundaryReason | str,
        detail: str | None = None,
        *,
        base: SealedSnapshot | None = None,
        post: SealedSnapshot | None = None,
        agent_result: AgentResult | None = None,
        account: EffectAccount | None = None,
        feedback_input: FeedbackInput | None = None,
        verified: VerifiedEffect | None = None,
    ) -> PipelineResult:
        receipt = _boundary_receipt(run_id, reason, detail)
        log.emit(
            EventKind.DECISION,
            Phase.GATE,
            {
                "outcome": receipt.outcome,
                "exit_status": receipt.exit_status,
                "blocking": list(receipt.blocking),
                "landing_target": request.landing_target.value,
                "rehearsal": request.landing_target is LandingTarget.REHEARSAL,
                "external_patch_ingested": external_ingestion,
                "counts_as_e1": counts_as_e1,
            },
        )
        return PipelineResult(
            run_receipt=RunReceipt(
                run_id=run_id,
                invocation_id=request.invocation_id,
                thread_id=thread_id,
                mode=request.mode,
                landing_target=request.landing_target,
            ),
            gate_receipt=receipt,
            events=tuple(log.events),
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
            feedback_input=feedback_input,
            verified=verified,
            external_patch_ingested=external_ingestion,
            counts_as_e1=counts_as_e1,
        )

    # Check required capabilities up front (fail closed exit 4 before judging)
    missing = [
        name
        for name, val in (
            ("snapshot_service", caps.snapshot_service),
            ("host_state", caps.host_state),
            ("effect_api", caps.effect_api),
            ("obligation_api", caps.obligation_api),
            ("gate_api", caps.gate_api),
            ("verifier", caps.verifier),
            ("feedback_api", caps.feedback_api),
        )
        if val is None
    ]
    if not external_ingestion and caps.agent_api is None:
        missing.append("agent_api")
    if missing:
        return _finish_boundary(BoundaryReason.RECORD_INVALID, f"missing capabilities: {', '.join(missing)}")

    assert caps.snapshot_service is not None
    assert caps.host_state is not None
    assert caps.effect_api is not None
    assert caps.obligation_api is not None
    assert caps.gate_api is not None
    assert caps.verifier is not None
    assert caps.feedback_api is not None

    if external_ingestion and request.resume_thread_id is not None:
        return _finish_boundary(BoundaryReason.RECORD_INVALID, "cannot supply both external_patch and resume_thread_id")

    try:
        target_identity = request.target_identity or capture_target_identity(target)
        repo_identity = caps.host_state.stable_repo_identity(target)
        base = caps.snapshot_service.seal_base(target)
    except RefusalError as e:
        return _finish_boundary(BoundaryReason.HOSTILE_REPOSITORY, str(e))
    except Exception as e:  # noqa: BLE001
        return _finish_boundary(BoundaryReason.HOSTILE_REPOSITORY, f"{type(e).__name__}: {str(e)[:200]}")

    # Phase 1: L1 Runtime (AgentApi.run or explicitly-labelled external patch ingestion, NEVER E1)
    log.emit(
        EventKind.PHASE_STARTED,
        Phase.RUNTIME,
        {
            "external_patch_ingested": external_ingestion,
            "counts_as_e1": counts_as_e1,
            "base_tree_oid": str(base.tree_oid),
        },
    )
    agent_result: AgentResult | None = None
    if external_ingestion:
        assert request.external_patch is not None
        patch_bytes = request.external_patch
        log.emit(
            EventKind.PROGRESS,
            Phase.RUNTIME,
            {"source": request.external_patch_label, "external_patch_ingested": True, "counts_as_e1": False},
        )
    else:
        assert caps.agent_api is not None
        if request.resume_thread_id is not None:
            try:
                agent_result = caps.agent_api.resume(
                    request.resume_thread_id,
                    redo_inflight=request.redo_inflight,
                )
            except RefusalError as e:
                return _finish_boundary("agent-resume-boundary", str(e), base=base)
            except Exception as e:  # noqa: BLE001
                return _finish_boundary("agent-resume-boundary", f"agent resume failed: {type(e).__name__}: {str(e)[:200]}", base=base)
            run_id = agent_result.run_id
            log.rebind_run_id(run_id)
        else:
            req = dict(request.agent_request or {})
            req["run_id"] = str(run_id)
            req.setdefault("target", str(target))
            if request.manifest_bytes is not None:
                req.setdefault("manifest_bytes", request.manifest_bytes)
            try:
                agent_result = caps.agent_api.run(req)
            except RefusalError as e:
                return _finish_boundary("agent-runtime-boundary", str(e), base=base)
            except Exception as e:  # noqa: BLE001
                return _finish_boundary("agent-runtime-boundary", f"{type(e).__name__}: {str(e)[:200]}", base=base)
        thread_id = agent_result.thread_id
        counts_as_e1 = bool((agent_result.proposer_provenance or {}).get("counts_as_e1", False))
        if agent_result.run_id != run_id:
            return _finish_boundary(BoundaryReason.ACCOUNT_MISMATCH, "agent_result.run_id mismatch", base=base, agent_result=agent_result)
        if agent_result.base.tree_oid != base.tree_oid:
            return _finish_boundary(BoundaryReason.BASE_TREE_MISMATCH, "agent_result.base.tree_oid mismatch", base=base, agent_result=agent_result)
        worker_failed = (agent_result.proposer_provenance or {}).get("worker_failed")
        if isinstance(worker_failed, dict) and not agent_result.unified_diff.strip():
            return _finish_boundary("worker-command-failed", _worker_failed_reason(worker_failed), base=base, agent_result=agent_result)
        patch_bytes = agent_result.unified_diff.encode("utf-8")
    patch_digest: Sha256 = sha256_hex(hashlib.sha256(patch_bytes).hexdigest())
    manifest_sha256 = hashlib.sha256(request.manifest_bytes).hexdigest() if request.manifest_bytes is not None else None
    log.emit(
        EventKind.PHASE_FINISHED,
        Phase.RUNTIME,
        {
            "patch_sha256": str(patch_digest),
            "thread_id": str(thread_id) if thread_id else None,
            **({"manifest_sha256": manifest_sha256} if manifest_sha256 is not None else {}),
        },
    )

    # Reconstruct post snapshot independently via trusted SnapshotService
    try:
        post = caps.snapshot_service.reconstruct_post(base, patch_bytes)
    except Exception as e:  # noqa: BLE001
        return _finish_boundary(
            BoundaryReason.POST_TREE_MISMATCH,
            f"reconstruct_post failed: {type(e).__name__}: {str(e)[:200]}",
            base=base,
            agent_result=agent_result,
        )

    # Phase 2: L2 EffectAccount (analysed ONCE from sealed base/post/patch)
    log.emit(EventKind.PHASE_STARTED, Phase.EFFECT, {"base_tree_oid": str(base.tree_oid), "post_tree_oid": str(post.tree_oid)})
    try:
        account = caps.effect_api.build_account(run_id, base, post, patch_bytes)
    except Exception as e:  # noqa: BLE001
        return _finish_boundary(
            BoundaryReason.ACCOUNT_MISMATCH,
            f"effect build failed: {type(e).__name__}: {str(e)[:200]}",
            base=base,
            post=post,
            agent_result=agent_result,
        )
    if (
        account.run_id != run_id
        or account.base_tree_oid != base.tree_oid
        or account.post_tree_oid != post.tree_oid
        or account.patch_sha256 != patch_digest
    ):
        return _finish_boundary(
            BoundaryReason.ACCOUNT_MISMATCH,
            "EffectAccount identity chain mismatch",
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
        )
    log.emit(EventKind.PHASE_FINISHED, Phase.EFFECT, {"account_sha256": str(account.account_sha256)})

    # Phase 3a: L5 FeedbackApi.load (fail closed on missing/corrupt required input)
    log.emit(EventKind.PHASE_STARTED, Phase.FEEDBACK, {"repo_identity": repo_identity})
    symbols = tuple(sorted(set(account.modified_callables + account.added_callables + account.removed_callables)))
    try:
        load_fn = caps.feedback_api.load
        load_kw: dict[str, object] = {}
        try:
            load_params = inspect.signature(load_fn).parameters
            if "base_path" in load_params:
                load_kw["base_path"] = base.path
            if "callee_edges" in load_params:
                load_kw["callee_edges"] = account.callee_edges
        except (TypeError, ValueError):
            pass
        feedback_input = load_fn(repo_identity, symbols, **load_kw)
    except Exception as e:  # noqa: BLE001
        return _finish_boundary(
            BoundaryReason.RECORD_INVALID,
            f"feedback load failed: {type(e).__name__}: {str(e)[:200]}",
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
        )
    log.emit(EventKind.PHASE_FINISHED, Phase.FEEDBACK, {"feedback_input_sha256": str(feedback_input.input_sha256)})

    recurrent: tuple[dict, ...] = ()
    try:
        recurrent = tuple(caps.feedback_api.recurrent_constructs(repo_identity, _construct_feedback_rows(account)))
    except Exception as e:  # noqa: BLE001
        log.emit(EventKind.PROGRESS, Phase.FEEDBACK,
                 {"feedback_error": f"construct recurrence unavailable: {type(e).__name__}: {str(e)[:200]}"})

    # Phase 3b: L3 ObligationApi.verify -> VerifiedEffect with issuer-bound VerificationRecord
    guard_catalog = None
    if account.added_callables:
        from .guard_catalog import build_guard_catalog

        guard_catalog = build_guard_catalog(caps.host_state, repo_identity, account.base_tree_oid)
    log.emit(EventKind.PHASE_STARTED, Phase.OBLIGATION, {"account_sha256": str(account.account_sha256)})
    try:
        verified, active_intent, verified_intent_confirmation = _verify_with_resume_intent(
            caps.obligation_api, request, agent_result, account, feedback_input, base, post, target_identity,
            base_intent=caps.intent,
            guard_catalog=guard_catalog,
            progress=lambda target, i, n: _emit_obligation_progress(log, target, i, n),
        )
    except ConfinementBoundaryError as e:
        return _finish_boundary(
            BoundaryReason.CONFINEMENT_UNAVAILABLE,
            e.reason,
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
            feedback_input=feedback_input,
        )
    except RefusalError as e:
        if e.refusal is Refusal.BOUNDARY:
            prefix = BoundaryReason.CONFINEMENT_UNAVAILABLE.value + ": "
            if e.reason.startswith(prefix):
                return _finish_boundary(
                    BoundaryReason.CONFINEMENT_UNAVAILABLE,
                    e.reason[len(prefix):],
                    base=base,
                    post=post,
                    agent_result=agent_result,
                    account=account,
                    feedback_input=feedback_input,
                )
            return _finish_boundary(
                e.reason,
                None,
                base=base,
                post=post,
                agent_result=agent_result,
                account=account,
                feedback_input=feedback_input,
            )
        receipt = _refusal_receipt(run_id, e)
        log.emit(
            EventKind.DECISION,
            Phase.OBLIGATION,
            {
                "outcome": receipt.outcome,
                "exit_status": receipt.exit_status,
                "blocking": list(receipt.blocking),
                "rehearsal": request.landing_target is LandingTarget.REHEARSAL,
            },
        )
        fb_refs: tuple[str, ...] = ()
        try:
            fb_refs = caps.feedback_api.persist_refusal(
                receipt,
                account,
                {"reason": e.reason, "repo_identity": repo_identity,
                 "constructs": _construct_feedback_rows(account)},
            )
        except Exception as fb_err:  # noqa: BLE001
            log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": f"feedback recording failed: {type(fb_err).__name__}: {str(fb_err)[:200]}"})
        return PipelineResult(
            run_receipt=RunReceipt(run_id, request.invocation_id, thread_id, request.mode, request.landing_target),
            gate_receipt=receipt,
            events=tuple(log.events),
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
            feedback_input=feedback_input,
            feedback_records=fb_refs,
            recurrent_constructs=recurrent,
            external_patch_ingested=external_ingestion,
            counts_as_e1=counts_as_e1,
        )
    except Exception as e:  # noqa: BLE001
        return _finish_boundary(
            BoundaryReason.RECORD_INVALID,
            f"obligation verify failed: {type(e).__name__}: {str(e)[:200]}",
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
            feedback_input=feedback_input,
        )
    rec = verified.record
    if (
        rec.run_id != run_id
        or rec.base_tree_oid != base.tree_oid
        or rec.post_tree_oid != post.tree_oid
        or rec.patch_sha256 != patch_digest
        or rec.account_sha256 != account.account_sha256
        or rec.target != target_identity
    ):
        return _finish_boundary(
            BoundaryReason.RECORD_INVALID,
            "VerificationRecord identity chain mismatch",
            base=base,
            post=post,
            agent_result=agent_result,
            account=account,
            feedback_input=feedback_input,
            verified=verified,
        )
    log.emit(EventKind.PHASE_FINISHED, Phase.OBLIGATION, {"verification_record_sha256": str(rec.body_sha256)})

    # Phase 4: L4 GateApi.land (sole target writer)
    log.emit(EventKind.PHASE_STARTED, Phase.GATE, {"landing_target": request.landing_target.value})
    from .product import REVIEW_ONLY
    if REVIEW_ONLY and request.landing_target is LandingTarget.ORIGINAL:
        gate_receipt = _boundary_receipt(
            run_id,
            "review-only-distribution",
            "Hlith Review never writes the engineer's original repository; disposable rehearsal only",
        )
    else:
        try:
            gate_receipt = caps.gate_api.land(
                target,
                patch_bytes,
                verified,
                caps.verifier,
                target_identity,
                expected_run_id=run_id,
                **({} if request.expected_head is None else {"expected_head": request.expected_head}),
            )
        except RefusalError as e:
            gate_receipt = _refusal_receipt(run_id, e)
        except Exception as e:  # noqa: BLE001
            gate_receipt = _boundary_receipt(run_id, BoundaryReason.JOURNAL_UNAVAILABLE, f"{type(e).__name__}: {str(e)[:200]}")

    if gate_receipt.run_id != run_id:
        gate_receipt = _boundary_receipt(run_id, BoundaryReason.RECORD_INVALID, "gate_receipt.run_id mismatch")

    rehearsal = request.landing_target is LandingTarget.REHEARSAL
    log.emit(
        EventKind.DECISION,
        Phase.GATE,
        {
            "outcome": gate_receipt.outcome,
            "exit_status": gate_receipt.exit_status,
            "blocking": list(gate_receipt.blocking),
            "landed_commit": gate_receipt.landed_commit,
            "verification_record_sha256": str(gate_receipt.verification_record_sha256) if gate_receipt.verification_record_sha256 else None,
            "landing_target": request.landing_target.value,
            "rehearsal": rehearsal,
            "original_target_landed": gate_receipt.outcome == "landed" and not rehearsal,
            "external_patch_ingested": external_ingestion,
            "counts_as_e1": counts_as_e1,
        },
    )
    log.emit(EventKind.PHASE_FINISHED, Phase.GATE, {"run_id": str(run_id)})

    # Phase 5: L5 post-gate persistence / post-landing probe
    log.emit(EventKind.PHASE_STARTED, Phase.FEEDBACK, {"post_gate_outcome": gate_receipt.outcome})
    fb_refs: tuple[str, ...] = ()
    try:
        if gate_receipt.outcome == "landed" and gate_receipt.exit_status == EXIT_LANDED:
            landed_snap = caps.snapshot_service.seal_base(target)
            delta_obligations = tuple(
                o for o in getattr(getattr(verified, "obligations", None), "obligations", ())
                if getattr(o, "obligation_id", None) in {"deltas-confirmed", "deltas-invalid"}
            )
            deltas_confirmed = (
                active_intent is not None
                and verified_intent_confirmation is not None
                and verified_intent_confirmation.matched
                and not any(getattr(o, "verdict", None) is Verdict.UNVERIFIED for o in delta_obligations)
            )
            approved_deltas: tuple[dict, ...] = ()
            if deltas_confirmed and active_intent is not None and verified_intent_confirmation is not None:
                try:
                    current_confirmation = active_intent.confirmation()
                except Exception:  # only feedback is withheld; L3's verdict remains authoritative
                    current_confirmation = None
                if (
                    current_confirmation is not None
                    and current_confirmation.matched
                    and verified_intent_confirmation.matched
                    and current_confirmation.delta_set_sha256 == verified_intent_confirmation.delta_set_sha256
                    and current_confirmation.approved_sha256 == verified_intent_confirmation.approved_sha256
                ):
                    deltas_confirmed = True
                    approved_deltas = tuple(active_intent.deltas)
                else:
                    deltas_confirmed = False
            guard_symbols = _exported_guard_callables(account, verified)
            probe_symbols = tuple(s for s in symbols if s not in guard_symbols)
            caps.feedback_api.register_landing_context(
                run_id,
                LandingProbeContext(
                    repo_identity=repo_identity,
                    base=base,
                    symbols=probe_symbols,
                    excluded_guard_symbols=guard_symbols,
                    deltas_confirmed=deltas_confirmed,
                    approved_deltas=approved_deltas,
                    rehearsal=rehearsal,  # a clone's landing never supersedes the SOURCE store's pins (review, design review P0-2)
                    gate_explored=_gate_explored(base, post),  # review F2 route: what THIS gate ran ({} = unknown)
                ),
            )
            fb_refs = caps.feedback_api.post_landing_probe(gate_receipt, landed_snap)
        else:
            fb_refs = caps.feedback_api.persist_refusal(
                gate_receipt,
                account,
                _refusal_feedback_evidence(caps, account, verified, base, post, blocking=gate_receipt.blocking,
                                           rehearsal=rehearsal, repo_identity=repo_identity, log=log),
            )
        drain = getattr(caps.feedback_api, "drain_errors", None)
        if callable(drain):
            for err in drain():
                log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": str(err)[:200]})
        drain_limits = getattr(caps.feedback_api, "drain_limits", None)
        if callable(drain_limits):  # named L5 limits: disclosed as events, never rendered as "feedback not recorded"
            for lim in drain_limits():
                log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_limit": str(lim)[:200]})
    except Exception as e:  # noqa: BLE001
        prefix = (
            "landing completed; feedback recording failed"
            if gate_receipt.outcome == "landed" and gate_receipt.exit_status == EXIT_LANDED
            else "feedback recording failed"
        )
        log.emit(EventKind.PROGRESS, Phase.FEEDBACK, {"feedback_error": f"{prefix}: {type(e).__name__}: {str(e)[:200]}"})
    log.emit(EventKind.PHASE_FINISHED, Phase.FEEDBACK, {"feedback_records": list(fb_refs)})

    return PipelineResult(
        run_receipt=RunReceipt(
            run_id=run_id,
            invocation_id=request.invocation_id,
            thread_id=thread_id,
            mode=request.mode,
            landing_target=request.landing_target,
        ),
        gate_receipt=gate_receipt,
        events=tuple(log.events),
        base=base,
        post=post,
        agent_result=agent_result,
        account=account,
        feedback_input=feedback_input,
        verified=verified,
        feedback_records=fb_refs,
        recurrent_constructs=recurrent,
        external_patch_ingested=external_ingestion,
        counts_as_e1=counts_as_e1,
    )


def run_pipeline(
    request: PipelineRequest,
    caps: PipelineCapabilities,
    *,
    event_sink: Callable[[Event], None] | None = None,
) -> PipelineResult:
    """Execute the full pipeline, then release every sealed-snapshot temp directory THIS run created (normal, boundary, refusal, exception, interrupt).

    The result only carries tree ids (coordinator/artifact read ``base.tree_oid`` / ``post.tree_oid``, never a snapshot path), so nothing reads a released
    directory. Only directories the service itself created during this call are removed; historical hlith-base/post directories are never touched."""
    from ..hostio.snapshot_release import release_snapshots

    svc = caps.snapshot_service
    owned = getattr(svc, "owned_dirs", None)
    before = set(owned()) if owned is not None else None
    try:
        return _run_pipeline_body(request, caps, event_sink=event_sink)
    finally:
        if before is not None:
            release_snapshots(svc, *(d for d in owned() if d not in before))


__all__ = [
    "PipelineCapabilities",
    "PipelineRequest",
    "PipelineResult",
    "capture_target_identity",
    "run_pipeline",
]
