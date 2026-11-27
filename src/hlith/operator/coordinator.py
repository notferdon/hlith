# SPDX-License-Identifier: Apache-2.0
"""The one coordinator: allocates the RunId, links every surface/thread/checkpoint id to it, drives the section APIs.

* The ENGINE side (this module) is the only caller of ``contract.identities.new_run_id``. UI invocation ids, thread ids and
  checkpoint ids are LINKED to that RunId through ``receipt.json`` (written first); they are never minted as run ids.
* ``execute`` runs the trusted pipeline (``operator/pipeline.py``, L1 -> L2 -> L5 load -> L3 -> L4 -> L5) through the frozen
  Protocols. The coordinator never decides, never signs, never writes the target; the gate is the sole writer of the original target.
* Progress events (PHASE_*, PROGRESS, ARTIFACT_WRITTEN) never carry a verdict. A DECISION event is emitted only from the
  gate's own receipt.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from ..contract import codec
from ..contract.errors import EXIT_BOUNDARY, EXIT_INTERNAL
from ..contract.events import Event, EventKind, Phase
from ..contract.identities import InvocationId, RunId, ThreadId, new_run_id
from ..contract.runs import GateReceipt, LandingTarget, RunMode, RunReceipt
from . import store
from .pipeline import PipelineCapabilities, PipelineRequest, run_pipeline
from .policy import strict_requested
from .state import LocalState


class RequestError(ValueError):
    """The request itself is inconsistent (refused before any run id is allocated)."""


@dataclass(frozen=True)
class RunRequest:
    """What a surface asks the coordinator to do. A surface never supplies a RunId."""

    repo: Path  # the repository the user selected (the ORIGINAL)
    mode: RunMode
    landing_target: LandingTarget
    patch: bytes | None = None  # companion / headless ingestion of an externally produced patch
    manifest: dict | None = None
    agent_request: dict | None = None  # a confined local agent run (standalone)
    invocation_id: InvocationId | None = None  # the surface's own id (TUI session / CLI call); linked, not reused
    thread_id: ThreadId | None = None
    engine_repo: Path | None = None  # where the engine operates: a disposable clone for REHEARSAL, == repo for ORIGINAL
    label: str = ""
    patch_normalization: dict | None = None  # {input_patch_sha256, applied_patch_sha256, preamble_removed_bytes}: the operator-edge preamble strip, recorded
    resume_thread_id: ThreadId | None = None  # continue a persisted agent thread (the ORIGINAL RunId is recovered from its checkpoint)
    redo_inflight: bool = False
    approve_deltas: str | None = None  # operator hash, bound only after the resumed agent returns its authenticated manifest
    expected_head: str | None = None  # the commit the review was bound to (--expect-head): the GATE re-checks it under its target lock

    def origin(self) -> store.InputOrigin:
        if self.patch is not None:
            return store.InputOrigin.SUPPLIED_PATCH  # never an observed agent run, whatever surface carried it
        if self.agent_request is not None or self.resume_thread_id is not None:
            return store.InputOrigin.AGENT_RUN
        return store.InputOrigin.UNKNOWN


@dataclass
class RunOutcome:
    receipt: RunReceipt | None
    run_dir: Path | None
    gate: GateReceipt | None
    exit_status: int
    artifact_path: Path | None
    problems: list[str] = field(default_factory=list)


class Coordinator:
    def __init__(self, state: LocalState | None = None) -> None:
        self.state = state or LocalState()

    # ---- identity -----------------------------------------------------------------------------------------------------
    def begin(self, req: RunRequest) -> tuple[RunReceipt, Path]:
        """Validate, allocate the engine RunId, write the linking receipt. Nothing else happens before this."""
        self._validate(req)
        repo = Path(req.repo).resolve()
        identity = self.state.stable_repo_identity(repo)
        root = self.state.namespace(identity, "runs")
        for _ in range(8):  # a collision is astronomically unlikely; create-exclusive makes it impossible to overwrite
            rid = new_run_id()
            run_dir = root / rid
            try:
                receipt = RunReceipt(rid, req.invocation_id or InvocationId("inv-" + secrets.token_hex(6)),
                                     req.thread_id, req.mode, req.landing_target)
                run_dir.mkdir(parents=True, mode=0o700)
            except FileExistsError:
                continue
            store.write_receipt(run_dir, receipt, req.origin(), identity, str(repo))
            return receipt, run_dir
        raise RuntimeError("could not allocate a unique run id")

    @staticmethod
    def _validate_surface(req: RunRequest) -> None:
        """Request consistency for a surface that launches the engine as a separate process (the engine mints the RunId)."""
        Coordinator._validate(req)

    @staticmethod
    def _validate(req: RunRequest) -> None:
        given = sum(x is not None for x in (req.patch, req.agent_request, req.resume_thread_id))
        if given != 1:
            raise RequestError("give exactly one input: a supplied patch, a local agent request or a thread to resume")
        if req.mode is RunMode.STANDALONE and req.patch is not None:
            raise RequestError("standalone runs come from the local agent; a supplied patch is companion or headless ingestion")
        repo = Path(req.repo).resolve()
        eng = Path(req.engine_repo).resolve() if req.engine_repo is not None else repo
        if req.landing_target is LandingTarget.ORIGINAL and req.engine_repo is not None and eng != repo:
            raise RequestError("an original-target landing must operate on the selected repository itself")
        if req.landing_target is LandingTarget.REHEARSAL and req.engine_repo is not None and eng == repo:
            raise RequestError("a rehearsal must operate on a disposable clone, never on the selected repository")

    # ---- one run through the trusted pipeline (operator/pipeline.py, owned by review) -----------------------------------------
    def execute(self, req: RunRequest, caps: PipelineCapabilities, *, on_start=None) -> RunOutcome:
        """Drive ``pipeline.run_pipeline``. The pipeline allocates the RunId (``new_run_id``) inside itself, so the run directory and
        its linking receipt are created on the FIRST streamed event (before any phase result exists); every later event is appended
        to the validated store as it happens. The pipeline writes no file: the artifact and exit code are written here from the
        returned values. A supplied patch is recorded as such and never as an observed agent run (``counts_as_e1`` is asserted)."""
        self._validate(req)
        repo = Path(req.repo).resolve()
        engine_repo = Path(req.engine_repo or req.repo).resolve()
        identity = self.state.stable_repo_identity(repo)
        state: dict = {"dir": None, "receipt": None}
        problems: list[str] = []

        buffered: list[Event] = []  # a resume learns its ORIGINAL RunId only after the agent recovers it from the checkpoint

        def open_run(run_id) -> None:
            d = self.state.namespace(identity, "runs") / run_id
            existing = store.read_receipt(d) if d.is_dir() else None
            if existing is None:  # a fresh run, or a recovered id whose run directory never got a receipt
                d.mkdir(parents=True, mode=0o700, exist_ok=True)
                rr = RunReceipt(run_id, req.invocation_id or InvocationId("inv-" + secrets.token_hex(6)), req.thread_id or req.resume_thread_id,
                                req.mode, req.landing_target)
                store.write_receipt(d, rr, req.origin(), identity, str(repo))
            else:  # resuming the ORIGINAL run: its receipt (and linked ids) stay as first written
                rr = existing.run
            state["dir"], state["receipt"] = d, rr
            store.write_replace(d / "meta.json", json.dumps(store.process_meta(rr.run_id, str(repo))).encode() + b"\n")  # liveness
            if on_start is not None:  # e.g. the engine process tells its launcher which run directory is its own
                on_start(d, rr)

        def sink(ev: Event) -> None:
            if state["dir"] is None:
                if req.resume_thread_id is None:
                    open_run(ev.run_id)
                else:
                    buffered.append(ev)
                    settled = ev.run_id != buffered[0].run_id or (ev.kind is EventKind.PHASE_FINISHED and ev.phase is Phase.RUNTIME)
                    if not settled:
                        return
                    open_run(ev.run_id)  # the id of the latest event is the recovered, final one
                    for old in buffered:
                        store.append_event(state["dir"], dataclasses.replace(old, run_id=ev.run_id))
                    buffered.clear()
                    return
            store.append_event(state["dir"], ev)

        preq = PipelineRequest(
            target=engine_repo, invocation_id=req.invocation_id or InvocationId("inv-" + secrets.token_hex(6)), mode=req.mode,
            landing_target=req.landing_target, agent_request=req.agent_request, external_patch=req.patch,
            resume_thread_id=req.resume_thread_id, redo_inflight=req.redo_inflight,
            approve_deltas=req.approve_deltas, expected_head=req.expected_head,
            external_patch_label=req.label or "external-patch",
            manifest_bytes=None if req.manifest is None else codec.canonical_bytes(req.manifest))
        decided = self._decided_run_of_thread(req, caps, identity)
        if decided is not None:
            # design review trace e1resume3: a resume of a thread whose run already RECORDED a decision re-called the proposer and the gate LANDED,
            # while the kept artifact still said refused (rc 0 vs out.json refused/4). A decided run is never re-decided: refused here,
            # before any proposer call or target write (review, G2).
            problems.append(f"thread {req.resume_thread_id} belongs to run {decided}, which already recorded its decision ({store.ARTIFACT}); "
                            "a resume never re-decides a decided run and nothing was run or changed. Start a new run for this change")
            return RunOutcome(None, None, None, EXIT_BOUNDARY, None, problems)
        recovered_commit: str | None = None
        from .product import REVIEW_ONLY
        if REVIEW_ONLY and req.landing_target is LandingTarget.ORIGINAL:
            problems.append("review-only distribution: original-target runs and landing recovery are disabled")
        elif req.landing_target is LandingTarget.ORIGINAL and getattr(getattr(caps, "gate_api", None), "recover", None) is not None:
            # An interrupted landing leaves a journal that the gate (rightly) refuses to overwrite. Nothing else ever recovers it on the
            # pipeline route, so without this step ONE crash would block every later landing in this repository forever.
            try:
                recovered = caps.gate_api.recover(engine_repo)
            except Exception as e:  # noqa: BLE001 - cannot verify the journal as ours: say so, touch nothing
                if "refusing" in str(e) and ("repository" in str(e) or "target" in str(e)):
                    # the closed-world vet refused the repository BEFORE any journal was read: nothing was interrupted, so do not say it was
                    problems.append(f"the repository is refused before any run or recovery ({str(e)[:240]}); "
                                    "nothing was touched or deleted. Use a clean clone without those settings")
                else:
                    problems.append("an interrupted landing left a recovery journal this host cannot verify as its own for this repository; "
                                    f"nothing was touched or deleted ({type(e).__name__}: {str(e)[:200]})")
                return RunOutcome(None, None, None, EXIT_BOUNDARY, None, problems)
            if recovered == "untrusted":
                problems.append("an interrupted landing no longer matches its authenticated journal; "
                                "nothing was changed or deleted, and the repository was not run. "
                                "Inspect HEAD, the index, the worktree, and the preserved recovery journal; "
                                "manually resolve any mismatch before retrying")
                return RunOutcome(None, None, None, EXIT_BOUNDARY, None, problems)
            if recovered == "completed":
                recovered_commit = _head_commit(engine_repo)
                if recovered_commit is None:
                    problems.append("previous interrupted landing completed; verified HEAD could not be read")
                else:
                    problems.append(f"previous interrupted landing completed at commit {recovered_commit}")
            elif recovered not in ("clean", None):
                problems.append(f"a previous landing was interrupted; recovered: {recovered}")
        # Reuse the HEAD read made immediately after the gate authenticated a completed landing.
        # Otherwise this run's base is the repository HEAD before the pipeline starts.
        base_commit = recovered_commit if recovered_commit is not None else _head_commit(engine_repo)
        try:
            res = run_pipeline(preq, caps, event_sink=sink)
        except Exception as e:  # noqa: BLE001 - reported, never turned into a pass
            problems.append(f"{type(e).__name__}: {str(e)[:300]}")
            if state["dir"] is not None:
                store.write_replace(state["dir"] / "rc", f"{EXIT_INTERNAL}\n".encode())
            return RunOutcome(state["receipt"], state["dir"], None, EXIT_INTERNAL, None, problems)
        seal = getattr(caps.agent_api, "seal_open_graph", None)
        if callable(seal) and res.gate_receipt is not None and res.agent_result is not None:
            decision = {
                "outcome": res.gate_receipt.outcome,
                "exit_status": res.gate_receipt.exit_status,
                "blocking": list(res.gate_receipt.blocking),
                "landed_commit": res.gate_receipt.landed_commit,
            }
            try:
                seal(decision)
            except Exception as e:  # noqa: BLE001 - the gate receipt stands; the checkpoint seal is reported, not invented
                problems.append(f"gate decision was not sealed into the checkpoint: {type(e).__name__}: {str(e)[:200]}")
            else:
                err = getattr(getattr(caps.agent_api, "_open_graph", None), "resume_error", None)
                if err:
                    problems.append(f"checkpoint feedback resume did not finish: {err}")
        if state["dir"] is None and buffered:  # a resume that ended before its agent step settled the id (boundary refusal)
            open_run(res.run_receipt.run_id)
            for old in buffered:
                store.append_event(state["dir"], dataclasses.replace(old, run_id=res.run_receipt.run_id))
            buffered.clear()
        run_dir = state["dir"]
        if res.external_patch_ingested and res.counts_as_e1:
            problems.append("pipeline labelled a supplied patch as E1; recorded as supplied-patch regardless")
        artifact = self._artifact(res.run_receipt, req, res, base_commit)
        path = run_dir / store.ARTIFACT
        # The exact patch bytes this run judged are kept beside the artifact (replay_context.patch.ref == 'change.patch'; the sha256 is checked by the replayer):
        # without them a recorded witness is honestly NOT replayable. First write wins; a decided run never rewrites it.
        _ar = res.agent_result
        _patch_bytes = req.patch if req.patch is not None else (_ar.unified_diff.encode("utf-8", "surrogateescape") if _ar is not None and getattr(_ar, "unified_diff", None) else None)
        if _patch_bytes:
            try:
                store.write_new(run_dir / "change.patch", _patch_bytes)
            except FileExistsError:
                pass
        try:
            store.write_new(path, codec.canonical_bytes(artifact) + b"\n")
        except FileExistsError:  # a decided run keeps its artifact: a resume never rewrites a recorded decision
            problems.append(f"{store.ARTIFACT} already exists for {res.run_receipt.run_id}; the recorded decision is kept")
            path = None
        store.append_event(run_dir, Event(res.run_receipt.run_id, len(res.events) + 1, EventKind.ARTIFACT_WRITTEN, None,
                                          store.utc_now(), {"name": store.ARTIFACT}))
        store.write_replace(run_dir / "rc", f"{res.gate_receipt.exit_status}\n".encode())
        return RunOutcome(res.run_receipt, run_dir, res.gate_receipt, res.gate_receipt.exit_status, path, problems)

    def _decided_run_of_thread(self, req: RunRequest, caps, identity: str) -> str | None:
        """The RunId of the resumed thread when that run already has its artifact (a recorded decision), else None.
        An unreadable thread record is not decided here: the pipeline's own resume path reports it."""
        if req.resume_thread_id is None:
            return None
        from ..agent import default_store
        from ..agent.checkpoint import thread_run_id

        tstore = getattr(getattr(caps, "agent_api", None), "thread_store", None) or default_store()
        try:
            rid = thread_run_id(str(req.resume_thread_id), Path(tstore))
        except Exception:  # noqa: BLE001
            return None
        if not rid:
            return None
        try:
            run_dir = self.state.namespace(identity, "runs") / rid
        except Exception:  # noqa: BLE001
            return None
        return rid if (run_dir / store.ARTIFACT).exists() else None

    @staticmethod
    def _artifact(receipt: RunReceipt, req: RunRequest, res, base_commit: str | None = None) -> dict:
        """Format-2 artifact from typed pipeline values only. Decision fields are copied from the gate receipt, never computed."""
        g, ar = res.gate_receipt, res.agent_result
        fb_errors = [
            str(e.detail["feedback_error"])
            for e in res.events
            if e.kind is EventKind.PROGRESS and "feedback_error" in e.detail
        ]
        e1_reason = (
            (ar.proposer_provenance or {}).get("counts_as_e1_reason")
            if ar is not None
            else ("external patch ingestion" if res.external_patch_ingested else None)
        )
        effect = _effect_block(req, res)
        art = {
            "format": codec.SCHEMA_VERSION,
            "run": {"run_id": receipt.run_id, "invocation_id": receipt.invocation_id, "thread_id": receipt.thread_id,
                    "mode": receipt.mode, "landing_target": receipt.landing_target, "origin": req.origin(),
                    "source_label": req.label or None, "engine": "pipeline",
                    "domain_policy": "strict" if strict_requested() else "scoped",
                    "external_patch_ingested": res.external_patch_ingested, "counts_as_e1": False if res.external_patch_ingested else res.counts_as_e1,
                    "counts_as_e1_reason": e1_reason,
                    "base_commit_sha": base_commit, "started_at_utc": store.utc_now(),
                    "base_tree_oid": None if res.base is None else res.base.tree_oid,
                    "post_tree_oid": None if res.post is None else res.post.tree_oid},
            "effect": effect,
            "obligations": _obligation_rows(res.verified),
            "effect_account": res.account,
            "touched_files": effect["touched_files"],
            "proposer_provenance": {} if ar is None else ar.proposer_provenance,
            "feedback_input_sha256": None if res.feedback_input is None else res.feedback_input.input_sha256,
            "feedback_records": list(res.feedback_records),
            # the same block the screens already read (loaded = what L5 handed to L3 for THIS run; written = what L5 persisted after the gate)
            "feedback": {"run_id": receipt.run_id,
                         "loaded_feedback_ids": [r.record_id for r in (getattr(res.feedback_input, "records", ()) or ())],
                         "loaded_source_runs": {r.record_id: str(r.source_run_id) for r in (getattr(res.feedback_input, "records", ()) or ())},
                         "written_feedback_ids": list(res.feedback_records),
                         # Older or alternate result services may not report recurrence; absence means none reported.
                         "recurrent_constructs": list(getattr(res, "recurrent_constructs", ()))},
            "feedback_errors": fb_errors,
            "verification_record_sha256": g.verification_record_sha256,
            "outcome": g.outcome,
            "exit_status": g.exit_status,
            "blocking": list(g.blocking),
            "landed_commit": g.landed_commit,
        }
        from .target_python import observed_target_python

        tp = observed_target_python()  # what the CONFINED worker reported about itself; absent when no evaluator started (never inferred)
        if tp is not None:
            art["target_python"] = tp
        _attach_witness_calls(art, base_commit, res, tp)
        return art


def _attach_witness_calls(art: dict, base_commit: str | None, res, tp: dict | None) -> None:
    """Replay support (O2 / R1 'replayable witness'): copy, VERBATIM, the exact refuting call the differential recorded for each REFUTED obligation into its row
    as ``witness_call`` (the truncated form when it exceeded the cap: such a witness is NOT replayable and says so), matched by module + qualname == the
    obligation's target symbol; and record in ``run.replay_context`` what a standalone replay needs (base commit/tree, stored patch ref + sha256, import root,
    extra sys.path, target interpreter). Informational: decide() never reads it. Nothing is invented: no recorded call -> no field."""
    from .. import differential
    from ..contract import witness as witness_schema

    rows = [r for r in art.get("obligations", []) if r.get("verdict") == "refuted"]
    if not rows:
        return
    wits = differential.observed_witnesses()
    used = None
    for row in rows:
        for entry in reversed(wits):
            if f"{entry['module']}.{entry['qualname']}" == row.get("target_symbol"):
                row["witness_call"] = codec.encode_call_values(entry["witness_call"])  # a float is recorded as a typed tag: recording must never turn a refutation into LOST
                row["witness_record"] = witness_schema.adapt(row["witness_call"])  # typed, versioned view of the same call (export reads it)
                used = used or entry
                break
    if used is None:
        return
    art["run"]["replay_context"] = {
        "base": {"commit": base_commit, "tree_oid": None if res.base is None else res.base.tree_oid},
        "patch": {"sha256": (art.get("effect") or {}).get("patch_sha256"), "ref": "change.patch"},
        "import_root": used["import_root"],
        "extra_sys_path": [str(p) for p in used["extra_sys_path"]],
        "target_python": tp,
    }


def _obligation_rows(verified) -> list[dict]:
    """The L3 obligations as plain rows (what a viewer shows: verdict, claim, witness / stop reason, explored / unexplored). Copied
    from the verified effect as recorded; nothing is added, dropped or upgraded. No verified effect (a refusal before L3) -> []."""
    out: list[dict] = []
    obs = getattr(getattr(verified, "obligations", None), "obligations", ()) or ()
    for o in obs:
        ev = getattr(o, "evidence", None)
        v = getattr(o, "verdict", None)
        out.append({"id": o.obligation_id, "target_symbol": o.target_symbol, "claim": o.claim,
                    "verdict": getattr(v, "value", v), "witness": o.witness, "stop_reason": o.stop_reason,
                    "provenance": codec.plain(o.provenance),
                    "evidence": None if ev is None else {"executions": ev.executions, "explored": ev.explored,
                                                         "unexplored": ev.unexplored},
                    "account_bound": bool(getattr(o, "account_bound", False))})
    return out


def _head_commit(repo: Path) -> str | None:
    """HEAD commit of the engine repository through the hardened read-only adapter; None when it cannot be read."""
    try:
        from . import gitq

        out = gitq.optional_text(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
        return out if out and len(out) in (40, 64) else None
    except Exception:  # noqa: BLE001 - an unreadable HEAD is recorded as absent, never invented
        return None


def _effect_block(req: RunRequest, res) -> dict:
    """The proposed effect as the human needs it: diff, patch digest, touched files and the declared deltas WITH the delta-set digest
    to approve (contract.effects.delta_set_sha256 over the validated, canonical set: the exact value L3 compares). A candidate
    without deltas carries None; a manifest whose deltas fail validation carries the reason and NO digest (nothing to approve)."""
    from ..agent import validate_deltas
    from ..contract.effects import delta_set_sha256

    ar = res.agent_result
    unified_diff = None if ar is None else ar.unified_diff
    touched_files = [] if ar is None else list(ar.touched_files)
    if ar is None and req.patch is not None:
        # Patch ingestion has no AgentResult, but the operator still needs the exact
        # change packet and its mechanically derived paths in the artifact.
        unified_diff = req.patch.decode("utf-8", "replace")
        from .tui.claim import derive as derive_patch_paths

        touched_files = list(derive_patch_paths(req.patch))
    block = {"patch_sha256": None if res.account is None else res.account.patch_sha256,
             "unified_diff": unified_diff,
             "touched_files": touched_files,
             "deltas": [], "delta_set_sha256": None, "deltas_error": None}
    norm = req.patch_normalization or {}
    block["input_patch_sha256"] = norm.get("input_patch_sha256")  # the file as the operator gave it (None: no normalisation step ran)
    block["preamble_removed_bytes"] = int(norm.get("preamble_removed_bytes") or 0)
    manifest = req.manifest
    if manifest is None and ar is not None and isinstance(ar.authenticated_manifest, dict):
        manifest = ar.authenticated_manifest
    raw = (manifest or {}).get("deltas", [])
    if raw:
        try:
            deltas = validate_deltas(raw)
            block["deltas"] = list(deltas)
            block["delta_set_sha256"] = delta_set_sha256(deltas)
        except (ValueError, TypeError) as e:
            block["deltas_error"] = f"{type(e).__name__}: {str(e)[:200]}"
    return block
