# SPDX-License-Identifier: Apache-2.0
"""L1 AgentApi implementation emitting contract AgentResult and Phase.RUNTIME Events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..contract.capabilities import (
    AgentResult,
    GitRead,
    HostState,
    SealedSnapshot,
    SnapshotService,
)
from ..contract.events import Event, EventKind, Phase
from ..contract.identities import RunId, ThreadId, new_run_id, run_id as validate_run_id, tree_oid
from .capture import WorkerRun
from .checkpoint import (
    CrashState,
    GraphInfo,
    classify_crash_state,
    default_store,
    record_verdict,
    thread_run_id,
    thread_target,
)
from .errors import RuntimeBoundary
from .proposer import CommandProposer
from .supervisor import resume_agent_worker, resume_captured_worker, run_worker


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentApiImpl:
    """Implements ``hlith.contract.capabilities.AgentApi`` for L1."""

    def __init__(
        self,
        *,
        snapshot_service: SnapshotService | None = None,
        host_state: HostState | None = None,
        git_read: GitRead | None = None,
        thread_store: Path | None = None,
        event_sink: Callable[[Event], None] | None = None,
    ) -> None:
        self.snapshot_service = snapshot_service
        self.host_state = host_state
        self.git_read = git_read
        self.thread_store = thread_store
        self.event_sink = event_sink
        self._seq = 0
        self._open_graph: GraphInfo | None = None

    def _emit(self, rid: RunId, kind: EventKind, detail: dict | None = None) -> None:
        if self.event_sink is None:
            return
        self._seq += 1
        self.event_sink(
            Event(
                run_id=rid,
                seq=self._seq,
                kind=kind,
                phase=Phase.RUNTIME,
                ts=_utc_now(),
                detail=detail or {},
            )
        )

    def _proposer_provenance(self, wr: WorkerRun, proposer: Any) -> dict:
        prov: dict[str, Any] = {
            "proposer_id": wr.effect.proposer_id,
            "profile_sha256": wr.profile_sha256,
            "ignored_paths": list(wr.ignored_paths),
            "skipped_paths": list(wr.skipped_paths),
            "risk_flags": list(wr.risk_flags),
            "manifest_error": wr.manifest_error,
        }
        if isinstance(proposer, CommandProposer):
            prov.update(proposer.provenance())
        elif proposer is not None:
            prov.update({
                "kind": getattr(proposer, "kind", "unknown"),
                "model_id": getattr(proposer, "model_id", "unknown"),
                "plumbing_only": bool(getattr(proposer, "plumbing_only", False)),
                "confined": True,
                "counts_as_e2": True,
            })
        else:
            prov.update({
                "kind": "scripted-worker",
                "model_id": None,
                "plumbing_only": False,
                "confined": True,
                "counts_as_e2": True,
            })
        graph_executed = isinstance(wr.graph, GraphInfo)
        checkpoint_id = (
            (wr.graph.final_checkpoint_id or wr.graph.interrupt_checkpoint_id)
            if isinstance(wr.graph, GraphInfo)
            else None
        )
        if wr.graph is not None and isinstance(wr.graph, GraphInfo):
            if wr.graph.proposer:
                prov.update(wr.graph.proposer)
            prov["thread_id"] = wr.graph.thread_id
            prov["payload_matches_observed"] = wr.graph.payload_matches_observed
        prov["graph_executed"] = graph_executed
        prov["checkpoint_id"] = checkpoint_id
        if proposer is None:
            e1_ok, e1_reason = False, "scripted worker (--worker-cmd) has no LangGraph StateGraph checkpoint or model proposer"
        elif not graph_executed or not checkpoint_id:
            e1_ok, e1_reason = False, "no LangGraph StateGraph checkpoint"
        elif bool(prov.get("plumbing_only", False)) or prov.get("kind") in (None, "unknown", "operator-patch", "scripted-worker"):
            e1_ok, e1_reason = False, f"non-model proposer ({prov.get('kind')})"
        elif not bool(prov.get("confined", False)):
            e1_ok, e1_reason = False, "unconfined proposer"
        else:
            e1_ok, e1_reason = True, "confined StateGraph with checkpoint and model provenance"
        prov["counts_as_e1"] = e1_ok
        prov["counts_as_e1_reason"] = e1_reason
        return prov

    def run(self, request: dict) -> AgentResult:
        if "run_id" not in request:
            raise RuntimeBoundary("L1 requires an engine-allocated run_id in request")
        rid = validate_run_id(str(request["run_id"]))
        target = Path(request["target"]).resolve()
        proposer = request.get("proposer")
        store = Path(request["thread_store"]) if request.get("thread_store") else self.thread_store
        layer1 = bool(request.get("layer1", proposer is not None))
        tid_raw = request.get("thread_id")
        self._emit(rid, EventKind.PHASE_STARTED, {"target": str(target), "layer1": layer1})
        base_snap = self.snapshot_service.seal_base(target) if self.snapshot_service is not None else None
        wr = run_worker(
            target,
            list(request.get("worker_argv") or []),
            proposer_id=str(request.get("proposer_id") or getattr(proposer, "model_id", None) or "worker"),
            timeout=float(request.get("timeout", 120.0)),
            worker_ro=tuple(request.get("worker_ro") or ()),
            patch=request.get("patch"),
            manifest_bytes=request.get("manifest_bytes"),
            layer1=layer1,
            thread_store=store,
            proposer=proposer,
            host_state=self.host_state,
            git_read=self.git_read,
            snapshot_service=self.snapshot_service,
            thread_id=str(tid_raw) if tid_raw is not None else None,
            run_id=str(rid),
        )
        tid = ThreadId(wr.graph.thread_id if isinstance(wr.graph, GraphInfo) else str(tid_raw or f"thread-{rid}"))
        if base_snap is None:
            base_snap = SealedSnapshot(tree_oid=tree_oid(wr.base_tree), path=target)
        prov = self._proposer_provenance(wr, proposer)
        prov["crash_state"] = CrashState.CAPTURED.value if isinstance(wr.graph, GraphInfo) else CrashState.TURN_NOT_BEGUN.value
        # A scripted worker command that exited non-zero and changed nothing FAILED; it did not "produce no change". Carry what was
        # observed (exit code, bounded stderr tail) so the pipeline can refuse with the truthful reason instead of an empty-patch error.
        wrc = getattr(wr, "worker_returncode", 0)
        if request.get("worker_argv") and not wr.effect.touched_files and isinstance(wrc, int) and wrc != 0:
            prov["worker_failed"] = {"returncode": wrc, "stderr_tail": str(getattr(wr, "worker_stderr", "") or "")[-2000:]}
        self._open_graph = wr.graph if isinstance(wr.graph, GraphInfo) else None
        self._emit(rid, EventKind.PHASE_FINISHED, {"thread_id": str(tid), "touched_files": list(wr.effect.touched_files)})
        # The worker's manifest as the HOST read it from the confined channel after a scripted worker run (never caller input). Passed
        # on so the pipeline can build the declared intent and bind --approve-deltas to it; a manifest read error passes nothing.
        captured_manifest = None
        host_deltas = tuple(getattr(wr.effect, "deltas", ()) or ())  # read_manifest_full(channel) by the host: raw delta dicts
        if request.get("worker_argv") and host_deltas and not getattr(wr, "manifest_error", None):
            captured_manifest = {"deltas": [dict(d) for d in host_deltas]}
        return AgentResult(
            run_id=rid,
            thread_id=tid,
            base=base_snap,
            unified_diff=wr.effect.unified_diff,
            touched_files=wr.effect.touched_files,
            proposer_provenance=prov,
            authenticated_manifest=captured_manifest,
        )

    def resume(
        self,
        thread_id: ThreadId,
        *,
        redo_inflight: bool = False,
        proposer: Any = None,
        target: Path | None = None,
        run_id: RunId | None = None,
        timeout: float = 120.0,
        checkpoint_id: str | None = None,
    ) -> AgentResult:
        store = self.thread_store or default_store()
        from .checkpoint import describe_thread

        desc = describe_thread(str(thread_id), store, host_state=self.host_state)
        captured = desc["kind"] == "effect-interrupt"
        if desc["finished"] and desc["interrupt_checkpoint_id"] and not desc["has_verdict"]:
            raise RuntimeBoundary("layer1: finished effect interrupt has no recorded verdict; refusing to rejudge")
        target_path = Path(target).resolve() if target is not None else thread_target(str(thread_id), store)
        recorded_run_id = thread_run_id(str(thread_id), store) if run_id is None else None
        if run_id is not None:
            rid = validate_run_id(str(run_id))
        elif recorded_run_id:
            rid = validate_run_id(recorded_run_id)
        elif captured:
            rid = new_run_id()
        else:
            rid = validate_run_id(str(recorded_run_id or "run-000000000000"))
        self._emit(rid, EventKind.PHASE_STARTED, {"thread_id": str(thread_id), "redo_inflight": redo_inflight, "captured": captured})
        base_snap = self.snapshot_service.seal_base(target_path) if self.snapshot_service is not None else None
        if captured:
            wr = resume_captured_worker(
                target_path,
                str(thread_id),
                store,
                checkpoint_id=checkpoint_id,
                host_state=self.host_state,
                git_read=self.git_read,
                snapshot_service=self.snapshot_service,
            )
        else:
            wr = resume_agent_worker(
                target_path,
                str(thread_id),
                store,
                proposer,
                timeout=timeout,
                redo_inflight=redo_inflight,
                host_state=self.host_state,
                git_read=self.git_read,
                snapshot_service=self.snapshot_service,
            )
        if base_snap is None:
            base_snap = SealedSnapshot(tree_oid=tree_oid(wr.base_tree), path=target_path)
        prov = self._proposer_provenance(wr, proposer)
        prov["crash_state"] = CrashState.CAPTURED.value
        prov["resumed_from"] = "effect-interrupt" if captured else "agent-progress"
        self._open_graph = wr.graph if isinstance(wr.graph, GraphInfo) else None
        self._emit(rid, EventKind.PHASE_FINISHED, {"thread_id": str(thread_id), "touched_files": list(wr.effect.touched_files)})
        return AgentResult(
            run_id=rid,
            thread_id=thread_id,
            base=base_snap,
            unified_diff=wr.effect.unified_diff,
            touched_files=wr.effect.touched_files,
            proposer_provenance=prov,
            authenticated_manifest=wr.authenticated_manifest if captured else None,
        )

    def seal_open_graph(self, decision: dict) -> None:
        """Write the gate's decision into the open checkpoint and advance the feedback node. Never changes the decision."""
        info = self._open_graph
        if not isinstance(info, GraphInfo):
            return
        if info._store_dir is None and info._session is None:
            return
        record_verdict(info, decision, host_state=self.host_state)
        try:
            if info._session is not None:
                from .supervisor import resume as resume_live
                from .supervisor import sync_after_resume

                resume_live(info, decision)
                sync_after_resume(info)
            elif info._store_dir is not None and info.interrupt_checkpoint_id:
                from .supervisor import resume_thread

                resume_thread(
                    info.thread_id,
                    info._store_dir.parent,
                    checkpoint_id=info.interrupt_checkpoint_id,
                    host_state=self.host_state,
                    git_read=self.git_read,
                )
        except Exception as e:  # noqa: BLE001 - the gate decision is already recorded
            info.resume_error = f"{type(e).__name__}: {str(e)[:300]}"

    def record_decision(self, info: GraphInfo, decision: dict) -> None:
        """SURFACE/coordinator passes the immutable gate decision back to L1 without L1 importing gate."""
        record_verdict(info, decision, host_state=self.host_state)


__all__ = ["AgentApiImpl", "CrashState", "classify_crash_state"]
