# SPDX-License-Identifier: Apache-2.0
"""``hlith`` ENGINE commands (run, resume, propose-deltas): the process the operator launches. The user-facing dispatcher
(``hlith.operator.cli``) owns ui/check/inspect/annotate; this module imports none of them, so there is no import cycle.

``hlith`` command line.

    hlith run --repo PATH --worker-cmd 'CMD ...' --artifact-out FILE

Pipeline: stage and run the worker (runtime), derive obligations, verify them,
hand effect + obligations to the gate. Slices not yet landed are represented by
an explicit ``unverified`` obligation, so the gate refuses (exit 12). Nothing
here ever lands a patch without every obligation held.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .. import gate
from .presentation import report
from ..textsafe import clean
from .. import phases as _phases
from .. import account_once as _account_once
from ..runtime import DeclaredEffects, delta_set_sha256, is_advisory, Reconciliation, RuntimeBoundary, WorkerRun, reconcile, run_worker
from ..types import (
    CheckProvenance,
    EXIT_BOUNDARY,
    EXIT_NOT_DERIVED,
    EXIT_REFUTED,
    EXIT_UNVERIFIED,
    GateDecision,
    GateOutcome,
    Obligation,
    ObligationSet,
    ProposedEffect,
    Verdict,
)
from ..contract.errors import EXIT_ARTIFACT_COPY, EXIT_USAGE

DeriveFn = Callable[[Path, ProposedEffect], ObligationSet]
# effect-account builder: what the change declares it touches (None = no account exists)
DeclareFn = Callable[[Path, ProposedEffect], "DeclaredEffects | None"]


def no_declaration(target: Path, effect: ProposedEffect) -> None:
    return None


def incident_obligation(rec: Reconciliation) -> Obligation:
    """Rule C. Present declarations that the stage exceeds refute; absent ones cannot be checked."""
    claim = "stage changed only what both the effect account and the proposer manifest declare"
    if rec.refuting:
        cv, nm = rec.claim_violations, rec.not_modelled_files
        if cv:  # the agent did something outside its own claim (or an account kind on a modelled file): a labelled refusal
            w = "claim violation: " + "; ".join(cv) + (f"; also not modelled by the account: {', '.join(nm)}" if nm else "")
            return Obligation("effect-declared-vs-observed", "*", claim, Verdict.REFUTED, witness=w)
        why = "; ".join(f"undeclared by account: file {p}" for p in nm)
        miss = f"; also missing: {', '.join(rec.missing_sources)}" if rec.missing_sources else ""
        return Obligation("effect-declared-vs-observed", "*", claim, Verdict.NOT_DERIVED,
                          stop_reason=f"{why}; the checker cannot model this change (nothing was compared, so nothing is refuted){miss}")
    return Obligation(
        "effect-declared-vs-observed", "*", claim, Verdict.UNVERIFIED,
        stop_reason="cannot reconcile, missing: " + ", ".join(rec.missing_sources),
    )


def unwired_obligations(target: Path, effect: ProposedEffect) -> ObligationSet:
    """Placeholder that can never land: states plainly that nothing was checked."""
    return ObligationSet(
        (
            Obligation(
                obligation_id="pipeline-unwired",
                target_symbol="*",
                claim="effect satisfies derived obligations",
                verdict=Verdict.UNVERIFIED,
                stop_reason="obligation derivation and verification are not wired into this build",
            ),
        )
    )


def _obligation_json(o: Obligation) -> dict:
    return {
        "id": o.obligation_id,
        "target_symbol": o.target_symbol,
        "claim": o.claim,
        "verdict": o.verdict.value,
        "stop_reason": o.stop_reason,
        "witness": o.witness,
        "evidence": None if o.evidence is None else {
            "executions": o.evidence.executions, "explored": o.evidence.explored, "unexplored": o.evidence.unexplored,
        },
        "provenance": None if o.provenance is None else {
            "checker_id": o.provenance.checker_id, "checker_sha256": o.provenance.checker_sha256,
            "confined": o.provenance.confined, "proposer_paths_readable": o.provenance.proposer_paths_readable,
            "profile_sha256": o.provenance.profile_sha256, "exit_code": o.provenance.exit_code,
        },
    }


@dataclass(frozen=True)
class DeltaConfirmation:
    """Independent confirmer for proposer delta claims. The proposer's own manifest can never
    be its confirmer: only a human-approved hash of the exact canonical delta set counts (a),
    or a pre-existing base-tree test exercising the delta (b, not built yet)."""

    confirmer: str | None  # "human-approval" when a matching approval was supplied
    delta_set_sha256: str
    approved_sha256: str | None
    matched: bool
    reason: str | None = None

    def as_provenance(self) -> CheckProvenance | None:
        """CheckProvenance-shaped record. A human is not a confined process, so confined stays
        False and this can never back a held Obligation (types forbids it); it only unblocks."""
        if not self.matched:
            return None
        return CheckProvenance(
            checker_id=f"{self.confirmer}:cli --approve-deltas", checker_sha256=self.delta_set_sha256,
            confined=False, proposer_paths_readable=False, profile_sha256="n/a:human", exit_code=0,
        )


def confirm_deltas(deltas, approve_deltas: str | None) -> DeltaConfirmation | None:
    """None when there are no delta claims and no approval digest. Computed from deltas NOW."""
    if not deltas:
        if approve_deltas is not None:
            return DeltaConfirmation(
                None,
                delta_set_sha256(()),
                approve_deltas,
                False,
                "approved delta-set sha256 was given without any declared delta claims",
            )
        return None
    sha = delta_set_sha256(deltas)
    if approve_deltas is None:
        return DeltaConfirmation(None, sha, None, False,
                                 "delta claims have no independent confirmer (--approve-deltas SHA256 not given)")
    if approve_deltas.lower() != sha:
        return DeltaConfirmation(None, sha, approve_deltas, False,
                                 "approved delta-set sha256 does not match the proposed delta set")
    return DeltaConfirmation("human-approval", sha, approve_deltas, True)


class PipelineResult(tuple):
    """Unpacks as (run, obligations, decision, reconciliation); also carries .confirmation."""

    confirmation: DeltaConfirmation | None

    def __new__(cls, run, obligations, decision, rec, confirmation=None):
        self = super().__new__(cls, (run, obligations, decision, rec))
        self.confirmation = confirmation
        return self


def _decision_json(decision: GateDecision, obligations: ObligationSet) -> dict:
    return {
        "outcome": decision.outcome.value, "exit_status": decision.exit_status,
        "blocking": list(decision.blocking), "landed_commit": decision.landed_commit,
        "obligations": [{"id": o.obligation_id, "verdict": o.verdict.value} for o in obligations.obligations],
    }


def _worker_failed_reason(run) -> str:
    """Why a worker command that changed nothing is NOT 'a worker that produced no change': it failed. Say what was observed (exit code,
    the last line of stderr, or that stderr is empty) and, when that points at the confinement, the usual cause (design review finding: a non-system
    interpreter exits 1 silently or dies in the confinement helper). Kept under the report's 220-character line so the hint is not cut."""
    raw = str(run.worker_stderr or "")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    base = f"worker command exited {run.worker_returncode}, no change"
    hint = "use /usr/bin/python3 or --worker-ro"
    if not lines:
        return (f"{base}; stderr empty: it likely could not start in the confinement (interpreter or libraries not readable); {hint}")
    tail = clean(lines[-1]).strip()[:90]
    if any(k in raw for k in ("No such file", "Permission denied", "execvp", "_confine.py")):
        return f"{base}; stderr ends: {tail}; interpreter or paths not readable in the confinement? {hint}"
    return f"{base}; stderr ends: {tail}"


def run_pipeline(
    repo: Path, worker_argv: list[str] | None = None, *, derive: DeriveFn = unwired_obligations,
    declare: DeclareFn = no_declaration,
    timeout: float = 120, proposer_id: str = "worker", worker_ro: tuple[str, ...] = (),
    after_gate: Callable[[Path, GateDecision, ObligationSet], object] | None = None,
    approve_deltas: str | None = None, patch: bytes | None = None, manifest_bytes: bytes | None = None, layer1: bool = False,
    thread_store: Path | None = None, proposer=None, prepared_run=None,
) -> PipelineResult:
    if prepared_run is not None:
        if not layer1 or proposer is None or worker_argv is not None or patch is not None:
            raise RuntimeBoundary("a prepared agent run needs Layer 1 and exactly one proposer")
    elif proposer is not None:
        if worker_argv is not None or patch is not None:
            raise RuntimeBoundary("give exactly one of a worker command, a patch or a proposer")
    elif (worker_argv is None) == (patch is None):
        raise RuntimeBoundary("give exactly one of a worker command or a patch")
    if manifest_bytes is not None and patch is None:
        raise RuntimeBoundary("an operator manifest is only accepted together with a patch")
    try:
        identity = gate.target_identity(repo)  # bound before anything runs; land() re-checks it
    except RuntimeError as e:
        raise RuntimeBoundary(f"target is not a usable git repository: {e}") from e
    with _phases.timed("stage_and_worker"):
        run = prepared_run if prepared_run is not None else run_worker(
            repo, worker_argv or [], proposer_id=proposer_id, timeout=timeout, worker_ro=worker_ro,
            patch=patch, manifest_bytes=manifest_bytes, layer1=layer1, thread_store=thread_store, proposer=proposer)
    try:
        if not run.target_untouched:
            raise RuntimeBoundary("target tree changed during worker run (confinement breach)")
        with _phases.timed("derive"):
            obligations = derive(repo, run.effect)
        if not run.observed and run.worker_returncode != 0 and [o.obligation_id for o in obligations.obligations] == ["no-effect"]:
            obligations = ObligationSet((Obligation("no-effect", "*", "effect is derivable", Verdict.NOT_DERIVED,
                                                    stop_reason=_worker_failed_reason(run)),))
        declared, account_error = None, None
        if run.observed:  # nothing changed => nothing to declare
            try:
                with _phases.timed("declare"):
                    declared = declare(repo, run.effect)
            except Exception as e:  # a builder failure is a missing declaration, never a crash or a pass
                account_error = f"{type(e).__name__}: {str(e)[:200]}"
        rec = reconcile(
            run.observed, declared,
            manifest=run.manifest, manifest_error=run.manifest_error, require_manifest=True,
            account_error=account_error,
        )
        if rec.incident and run.observed:
            obligations = ObligationSet(obligations.obligations + (incident_obligation(rec),))
        conf = confirm_deltas(getattr(run.effect, "deltas", ()), approve_deltas)  # at the last moment before land
        if conf is not None and not conf.matched:
            obligations = ObligationSet(obligations.obligations + (Obligation(
                "deltas-confirmed", "*", "proposer delta claims have an independent confirmer",
                Verdict.UNVERIFIED, stop_reason=conf.reason or "unconfirmed"),))
        with _phases.timed("gate"):
            decision = gate.land(
                repo,
                run.effect,
                obligations,
                expected_tree=run.base_tree,
                verified_patch_sha256=run.effect.patch_sha256,
                expected_identity=identity,
            )
        if run.observed and rec.manifest_blocked and decision.exit_status in (EXIT_REFUTED, EXIT_NOT_DERIVED, EXIT_UNVERIFIED):
            inc = "effect-declared-vs-observed"  # name the manifest first; every other obligation stays in the artifact
            decision = GateDecision(GateOutcome.REFUSED, EXIT_UNVERIFIED, (inc, *[b for b in decision.blocking if b != inc]))
        if run.graph is not None:  # resume the checkpointed thread with the verdict; cannot alter it
            from .. import layer1 as _l1
            with _phases.timed("resume"):
                _dj = _decision_json(decision, obligations)
                _l1.record_verdict(run.graph, _dj)  # decided verdict is on disk before the thread moves; never rewritten
                if run.graph._session is not None:
                    _l1.resume(run.graph, _dj)
                    _l1.sync_after_resume(run.graph)
                elif run.graph._store_dir is not None:
                    try:
                        resumed = _l1.resume_thread(run.graph.thread_id, run.graph._store_dir.parent,
                                                    checkpoint_id=run.graph.interrupt_checkpoint_id, timeout=timeout)
                        run.graph.final_checkpoint_id = resumed.get("final_checkpoint_id")
                        run.graph.resumed = bool(resumed.get("resumed") or resumed.get("already_finished"))
                        run.graph.feedback_executions = int(resumed.get("feedback_executions") or 0)
                        run.graph.feedback_node_ran = run.graph.feedback_executions > 0
                    except Exception as e:  # noqa: BLE001 - the decision is already made; only recovery status changes
                        run.graph.resume_error = f"{type(e).__name__}: {str(e)[:300]}"
        if after_gate is not None:  # Layer 5, supervisor side; it can never change the decision
            try:
                after_gate(repo, decision, obligations)
            except Exception as e:
                print(clean(f"hlith: feedback step failed: {type(e).__name__}: {e}")[:400], file=sys.stderr)
    except BaseException:
        if run.graph is not None:
            run.graph.close()
        raise
    return PipelineResult(run, obligations, decision, rec, conf)


from .target_python import observed_target_python as _observed_target_python  # noqa: E402  (shared with the coordinator's artifact)


def build_artifact(
    run: WorkerRun, obligations: ObligationSet, decision: GateDecision, rec: Reconciliation | None = None,
    feedback: dict | None = None, confirmation: DeltaConfirmation | None = None,
    run_info: dict | None = None, effect_account: dict | None = None,
) -> dict:
    return {
        "run": run_info,
        "effect_account": effect_account,
        "feedback": feedback,
        "graph": run.graph.to_json() if run.graph is not None else None,
        "outcome": decision.outcome.value,
        "exit_status": decision.exit_status,
        "blocking": list(decision.blocking),
        "landed_commit": decision.landed_commit,
        "effect": {
            "patch_sha256": run.effect.patch_sha256,
            "proposer_id": run.effect.proposer_id,
            "touched_files": list(run.effect.touched_files),
            "unified_diff": run.effect.unified_diff,
            "deltas": list(getattr(run.effect, "deltas", ())),
            "delta_set_sha256": getattr(run.effect, "delta_set_sha256", None),
        },
        "deltas": None if (not getattr(run.effect, "deltas", ()) and confirmation is None) else {
            "claim_only": True,
            "advisory_ids": [d["id"] for d in run.effect.deltas if is_advisory(d)],
            "confirmation": None if confirmation is None else {
                "confirmer": confirmation.confirmer,
                "matched": confirmation.matched,
                "delta_set_sha256": confirmation.delta_set_sha256,
                "approved_sha256": confirmation.approved_sha256,
                "reason": confirmation.reason,
                "provenance": None if confirmation.as_provenance() is None else asdict(confirmation.as_provenance()),
            },
        },
        "worker": {
            "returncode": run.worker_returncode,
            "stdout": run.worker_stdout,
            "stderr": run.worker_stderr,
            "profile_sha256": run.profile_sha256,
            "ignored_paths": list(run.ignored_paths),
            "skipped_paths": list(run.skipped_paths),
            "risk_flags": list(run.risk_flags),
        },
        "target": {
            "base_tree": run.base_tree,
            "digest_before": run.target_tree_before,
            "digest_after_worker": run.target_tree_after,
            "untouched_by_worker": run.target_untouched,
        },
        "incident": None if rec is None or not (rec.incident and run.observed) else {
            "kind": ("claim-violation" if rec.claim_violations else "not-modelled" if rec.not_modelled_files
                     else "undeclared-effect" if rec.refuting else "unreconciled-missing-declaration"),
            "missing_sources": list(rec.missing_sources),
            "account": {
                "available": rec.declared_available,
                "error": rec.account_error,
                "undeclared_files": list(rec.undeclared_files),
                "undeclared_changes": [{"path": p, "kind": k} for p, k in rec.undeclared_changes],
                "declared_unobserved": list(rec.declared_unobserved),
            },
            "manifest": {
                "available": rec.manifest_available,
                "error": rec.manifest_error,
                "undeclared_files": list(rec.manifest_undeclared_files),
                "undeclared_changes": [{"path": p, "kind": k} for p, k in rec.manifest_undeclared_changes],
                "claimed_unobserved": list(rec.manifest_claimed_unobserved),
                "claim_only": True,
            },
            "observed": [{"path": o.path, "kinds": sorted(o.kinds)} for o in run.observed],
        },
        "obligations": [{**_obligation_json(o), "account_id": (effect_account or {}).get("account_id")}
                        for o in obligations.obligations],
        # non-gating proof evidence (delta_rel); decide() never reads it. Required key, [] when none.
        "delta_rel": [dict(e) for e in getattr(obligations, "evidence", ())],
    }


ACCOUNT_INLINE_CAP = 4 * 1024 * 1024  # canonical-JSON bytes; larger accounts go to a sidecar bound by sha256


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


# Rollout (review): schema step 1 made effect_account.index_cache_provenance OPTIONAL, step 2 makes it REQUIRED. Always emitted now:
# {cache_hit_count, uncached_count} (zeros when no indexing ran: failed and no-change reports); review makes the key required next.
INDEX_CACHE_ALWAYS = True


def _cache_stats(account_obj) -> dict | None:
    """review's per-build indexed-file counts, never part of to_dict()/the account hash. Attribute name agreed with review/review:
    EffectAccount.index_cache_provenance (the artifact key has the same name); index_cache_stats is read as an alias."""
    for name in ("index_cache_provenance", "index_cache_stats"):
        v = getattr(account_obj, name, None)
        if isinstance(v, dict):
            return v
    return None


def account_block(patch_sha256: str, account: dict | None, error: str | None, artifact_out: Path,
                  cap: int = ACCOUNT_INLINE_CAP, *, no_change: bool = False,
                  index_cache_stats: dict | None = None) -> tuple[dict, tuple[Path, bytes] | None]:
    """Hlith.md 1.2 effect_account (review's closed shape; always written).

    status built|failed|no-change. ``account`` is inline unless its canonical JSON exceeds ``cap``; then
    account=null and the sidecar holds exactly the canonical JSON whose sha256 is account_sha256.
    side_effect_primitive_delta is renamed to the Hlith.md name side_effect_primitives_delta."""
    base = {"status": "no-change" if no_change else "failed", "error": error, "account_id": None, "account_sha256": None,
            "effect_id": patch_sha256, "language": "python", "sidecar": None, "account": None}
    if index_cache_stats is not None or INDEX_CACHE_ALWAYS:
        st = index_cache_stats or {}
        # beside status/account_sha256, never inside the account dict: counts differ cold vs warm and must not change account_id
        base["index_cache_provenance"] = {"cache_hit_count": int(st.get("cache_hit_count", 0)),
                                          "uncached_count": int(st.get("uncached_count", 0))}
    if account is None:
        return base, None
    account = dict(account)
    if "side_effect_primitive_delta" in account:
        account["side_effect_primitives_delta"] = account.pop("side_effect_primitive_delta")
    raw = _canon(account)
    sha = hashlib.sha256(raw).hexdigest()
    base.update(status="built", error=None, account_id="acct-" + sha[:20], account_sha256=sha)
    if len(raw) <= cap:
        base["account"] = account
        return base, None
    side = artifact_out.with_name(artifact_out.name + ".account.json")
    base["sidecar"] = {"path": side.name, "sha256": sha, "bytes": len(raw)}
    return base, (side, raw)


def _git_out(repo: Path, *a: str) -> str | None:
    from .. import gate as _gate  # untrusted repo: gate's scrubbed env + hardening flags + real-.git-dir check (no inherited GIT_DIR/WORK_TREE)
    try:
        return _gate._run_git(repo, tuple(a), None).stdout.strip() or None
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return None


def _rerun_command(args, extra: list[str] = ()) -> str:
    """The exact command that repeats this run (plus ``extra``), for the operator to copy."""
    a = ["uv", "run", "--frozen", "python", "-m", "hlith.operator.engine_cli", "run", "--repo", str(args.repo)]
    a += ["--engine", getattr(args, "engine", "pipeline")]
    if args.patch is not None:
        a += ["--patch", str(args.patch)] + (["--manifest", str(args.manifest)] if args.manifest else [])
    else:
        a += ["--worker-cmd", args.worker_cmd]
    if args.layer1:
        a += ["--layer1", args.layer1]
    for flag, val in (("--artifact-out", args.artifact_out), ("--proposer-id", args.proposer_id),
                      ("--target-python", args.target_python), ("--timeout", args.timeout)):
        if val is not None:
            a += [flag, str(val)]
    for w in args.worker_ro:
        a += ["--worker-ro", w]
    for e in args.extra_sys_path:
        a += ["--extra-sys-path", e]
    if getattr(args, "strict_domain", False):
        a += ["--strict-domain"]
    return shlex.join(a + list(extra))


def _report_ctx(args, run, rec) -> dict:
    ctx: dict = {}
    sha = getattr(run.effect, "delta_set_sha256", None)
    if sha:
        ctx["approve_cmd"] = _rerun_command(args, ["--approve-deltas", sha])
    ctx["propose_cmd"] = (f"uv run --frozen python -m hlith.cli propose-deltas --repo {shlex.quote(str(args.repo))} "
                          f"--artifact {shlex.quote(str(args.artifact_out))}")
    if rec is not None and rec.manifest_blocked:
        ctx["manifest_hint"] = ("fix the manifest as the first line says (delta fields: docs/OPERATOR.md step 3), then run: "
                                + _rerun_command(args))
    return ctx


def _propose_layer1(args, art: dict | None) -> str | None:
    """The --layer1 value the printed re-run commands carry. Explicit wins; with an artifact, reproduce how THAT run was made (a Layer 1 run has a `graph` block);
    with only a patch there is nothing to read and the product path is Layer 1. (review R3 probe P1: the printed commands used to drop it.)"""
    if args.layer1:
        return args.layer1
    if art is None:
        return "langgraph"
    return "langgraph" if art.get("graph") else None


def recover_pending_landing(repo: Path) -> tuple[str, str | None]:
    from .product import REVIEW_ONLY
    if REVIEW_ONLY:
        return "review-only", "review-only distribution does not recover prior original-target landings"
    """Resolve a landing a previous run left half-finished BEFORE the dirty pre-check judges the tree: an interrupted landing leaves exactly the
    uncommitted state the pre-check refuses, so without this the journal is reachable only through a landing and the target stays half-landed
    (G2-4a, found by the wrapper). Same guards as the gate: a repository whose config/attributes/submodules can execute programs, or whose
    .git is not an ordinary directory, is never touched. gate.recover itself only acts on a journal this host's gate wrote for THIS repository
    (HMAC + single-use nonce + per-path images) and returns an untrusted state without touching anything on doubt.
    Returns (state, message): state in none | rolled-back | completed | untrusted | untrusted-state | skipped; message is set when the run must stop."""
    from .. import gate as _gate
    repo = Path(repo)
    try:
        if (_gate.executable_config(repo) or _gate._repository_attribute_violation(repo) or _gate._submodule_exec_violation(repo)
                or _gate._target_git_dir_violation(repo)):
            return "skipped", None
        state = _gate.recover(repo)
        if state == "none":
            from ..gate.api import LocalGateService
            from ..hostio import LocalHostState

            l4_state = LocalGateService(LocalHostState()).recover(repo)
            if l4_state != "clean":
                state = l4_state
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as e:
        return "untrusted", f"an interrupted landing left a journal that could not be read safely ({type(e).__name__}); nothing was touched"
    if state == "untrusted":
        return state, ("an interrupted landing left a recovery journal that cannot be authenticated as the current in-flight journal for this repository; "
                       "nothing was touched or deleted. A person must inspect .git/hlith-journal.json and the working tree before another run")
    if state == "untrusted-state":
        return state, ("an interrupted landing no longer matches its authenticated journal; nothing was changed or deleted, and the repository was not run. "
                       "Inspect HEAD, the index, the worktree, and the preserved recovery journal; manually resolve any mismatch before retrying")
    return state, None


def dirty_repo_reason(repo: Path) -> str | None:
    """Why a run on this repository cannot end in a landing, or None when its working tree is clean (or it is not a repository: another check owns that message).
    Same test the gate applies at landing (`git status --porcelain`, so hlith's own excluded feedback records do not count)."""
    from .. import gate as _gate  # the repository is UNTRUSTED: never run a converting/executing git command on it unhardened
    try:
        # A repository whose config or attributes can execute programs is refused by the gate/engine with its own reason; this
        # advisory pre-check must not run `git status` on it at all (fsmonitor / clean filters run inside status), and it uses the
        # gate's scrubbed env + hardening flags (no inherited GIT_DIR / GIT_WORK_TREE).
        if (_gate.executable_config(repo) or _gate._repository_attribute_violation(repo)
                or _gate._submodule_exec_violation(repo)):
            return None
        cp = _gate._run_git(repo, ("status", "--porcelain", "--ignore-submodules=all"), None)
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return None
    rows = [ln for ln in cp.stdout.splitlines() if ln.strip()]
    if cp.returncode != 0 or not rows:
        return None
    paths = [ln[3:].strip() for ln in rows]
    shown = ", ".join(paths[:3]) + (", ..." if len(paths) > 3 else "")
    return (f"the repository has {len(paths)} path(s) with uncommitted changes ({shown}): commit or stash them, or use a clean clone "
            f"(a run on a dirty repository can never land: the gate refuses it as dirty-target)")


def _propose_deltas(args) -> int:
    from .intent import propose as _propose
    out = (args.out or Path("hlith-proposed")).resolve()
    try:
        out.mkdir(parents=True, exist_ok=True)
        art_sha, art_json = None, None
        if args.artifact is not None:
            raw = args.artifact.read_bytes()
            art_sha = hashlib.sha256(raw).hexdigest()
            art_json = json.loads(raw)
            diff = art_json["effect"]["unified_diff"]
            patch_path = out / "patch.diff"
            patch_path.write_text(diff)
        else:
            diff = args.patch.read_text()
            patch_path = out / "patch.diff"  # same name as --artifact mode: the printed next step names it
            patch_path.write_text(diff)
        base_manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    except (OSError, ValueError, KeyError) as e:
        print(clean(f"hlith: propose-deltas: cannot read input: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    try:
        res = _propose.propose(args.repo, diff, str(patch_path), base_manifest=base_manifest, artifact_sha256=art_sha,
                               extra_sys_path=args.extra_sys_path, target_python=args.target_python,
                               max_divergences=args.max_divergences, timeout=args.timeout, include_all=args.include_all, expression=args.expression)
    except (ValueError, RuntimeError, subprocess.SubprocessError) as e:
        print(clean(f"hlith: propose-deltas failed: {type(e).__name__}: {str(e)[:300]}"), file=sys.stderr)
        return EXIT_BOUNDARY
    print(_propose.render(res))
    if not res["deltas"]:
        print("no candidate delta generated (no common pattern, or no plain divergence expressible as a literal delta: see above). Nothing written.")
        return 1
    mpath, ppath = out / "proposed.manifest.json", out / "proposed.provenance.json"
    mpath.write_text(json.dumps(res["manifest"], indent=2) + "\n")
    ppath.write_text(json.dumps(res["provenance"], indent=2, sort_keys=True) + "\n")
    sha = res["delta_set_sha256"]
    base = argparse.Namespace(repo=args.repo, patch=patch_path, manifest=mpath, worker_cmd=None, layer1=_propose_layer1(args, art_json),
                              artifact_out=out / "rerun.json", proposer_id=args.proposer_id, target_python=args.target_python,
                              timeout=None, worker_ro=[], extra_sys_path=args.extra_sys_path)
    print(f"\nCANDIDATE delta set: {len(res['deltas'])} delta(s) from observed divergences (a CLAIM, not proof; NOT approved).")
    print(f"  manifest  : {mpath}\n  provenance: {ppath}\n  delta_set_sha256: {sha}")
    print("Review proposed.manifest.json (every delta lists the exact inputs it covers). Then:")
    print(f"  see the check with the candidate in place (no approval): {_rerun_command(base)}")
    if any(c["excluded"].get("claim_contradicted") for c in res["callables"]):
        print("  do NOT approve: a declared delta in your manifest is contradicted by the patch (see CLAIM CONTRADICTED above); fix and re-run first")
    else:
        print(f"  approve ONLY if you would honestly approve it:          {_rerun_command(base, ['--approve-deltas', sha])}")
    broader = res.get("broader")
    if broader and not any(c["excluded"].get("claim_contradicted") for c in res["callables"]):
        bpath = out / "proposed-broader.manifest.json"
        bpath.write_text(json.dumps(broader["manifest"], indent=2) + "\n")
        bbase = argparse.Namespace(**{**vars(base), "manifest": bpath, "artifact_out": out / "rerun-broader.json"})
        print(f"\n{_propose.BROADER_LABEL}")
        for d in broader["deltas"]:
            print(clean(f"  {d['claim']}"))
        print(f"  manifest  : {bpath}\n  delta_set_sha256: {broader['delta_set_sha256']}")
        print(f"  see the check with it in place (no approval): {_rerun_command(bbase)}")
        print(f"  approve ONLY if you would honestly approve it: {_rerun_command(bbase, ['--approve-deltas', broader['delta_set_sha256']])}\n")
    return 0


def _l1_default_store():
    from .. import layer1 as _l1d
    return _l1d.default_store()


@dataclass
class _PinnedOutputParent:
    """Keep the preflighted output directory inode open until its outputs are written."""

    fd: int

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


def _preflight_destination(path: Path, label: str, *, protected: tuple[Path, ...], kind: str,
                           must_be_new: bool = False, allow_empty: bool = False) -> tuple[Path, Path, _PinnedOutputParent | None]:
    """Validate an operator output path without leaving files or creating state."""
    p = Path(os.path.abspath(Path(path).expanduser()))
    for parent in (p, *p.parents):
        try:
            if parent.is_symlink():
                raise RuntimeBoundary(f"{label} path traverses symlink: {parent}")
        except OSError as e:
            raise RuntimeBoundary(f"{label} path cannot be inspected: {e.strerror or e}") from e

    parent = p.parent
    if not parent.is_dir():
        raise RuntimeBoundary(f"{label} parent must already exist as a directory: {parent}")
    try:
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as e:
        raise RuntimeBoundary(f"{label} parent cannot be resolved safely: {e}") from e
    candidate = resolved_parent / p.name
    is_dir = kind == "directory"
    for protected_path in protected:
        try:
            guard = Path(protected_path).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as e:
            raise RuntimeBoundary(f"protected target path cannot be resolved safely: {e}") from e
        overlaps = candidate == guard or guard in candidate.parents
        if is_dir:
            overlaps = overlaps or candidate in guard.parents
        if overlaps:
            if label == "--events-out":
                raise RuntimeBoundary(f"--events-out {candidate} is inside or above {guard}, a location the worker can access; choose a path elsewhere")
            raise RuntimeBoundary(f"{label} must be outside protected tree {guard}")

    try:
        parent_fd = os.open(resolved_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise RuntimeBoundary(f"{label} parent changed or cannot be opened safely: {e.strerror or e}") from e
    probe_fd_to_close = -1
    transfer_parent_fd = False
    try:
        if kind == "directory":
            try:
                mode = os.stat(p.name, dir_fd=parent_fd, follow_symlinks=False).st_mode
                exists = True
            except FileNotFoundError:
                mode, exists = 0, False
            if exists and not stat.S_ISDIR(mode):
                raise RuntimeBoundary(f"{label} must be a real directory, not a symlink or file: {p}")
            probe_fd = parent_fd
            if exists:
                try:
                    probe_fd = os.open(p.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=parent_fd)
                except OSError as e:
                    raise RuntimeBoundary(f"{label} directory cannot be opened safely: {p}: {e.strerror or e}") from e
                probe_fd_to_close = probe_fd
        else:
            try:
                entry_stat = os.stat(p.name, dir_fd=parent_fd, follow_symlinks=False)
                mode, exists = entry_stat.st_mode, True
            except FileNotFoundError:
                mode, exists = 0, False
            if exists and not stat.S_ISREG(mode):
                if label == "--events-out":
                    raise RuntimeBoundary(f"--events-out {p} is not a regular file")
                raise RuntimeBoundary(f"{label} must be a regular file, not a symlink or directory: {p}")
            if exists and must_be_new:
                raise RuntimeBoundary(f"{label} already exists: {p}")
            if exists and allow_empty and entry_stat.st_size != 0:
                if label == "--events-out":
                    raise RuntimeBoundary(f"--events-out {p} already holds data; give each run a new file")
                raise RuntimeBoundary(f"{label} already contains data: {p}")
            if exists:
                try:
                    fd = os.open(p.name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=parent_fd)
                except OSError as e:
                    raise RuntimeBoundary(f"{label} is not writable: {p}: {e.strerror or e}") from e
                else:
                    os.close(fd)
            probe_fd = parent_fd

        # Probe relative to the directory descriptor so a concurrent pathname swap
        # cannot create or unlink the probe in a different tree.
        probe_name = f".hlith-preflight-{secrets.token_hex(8)}"
        try:
            fd = os.open(probe_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                         0o600, dir_fd=probe_fd)
            os.close(fd)
        except OSError as e:
            raise RuntimeBoundary(f"{label} parent is not writable: {p.parent}: {e.strerror or e}") from e
        finally:
            try:
                os.unlink(probe_name, dir_fd=probe_fd)
            except FileNotFoundError:
                pass
            except OSError as e:
                raise RuntimeBoundary(f"{label} preflight could not remove its temporary probe: {e.strerror or e}") from e
        transfer_parent_fd = kind != "directory"
    finally:
        if probe_fd_to_close >= 0:
            os.close(probe_fd_to_close)
        if not transfer_parent_fd:
            os.close(parent_fd)
    return p, candidate, _PinnedOutputParent(parent_fd) if transfer_parent_fd else None


def _preflight_cli_outputs(args, *, protected: tuple[Path, ...], engine: str, resume: bool,
                           has_agent: bool = False) -> None:
    """Check every run/resume output before a worker or resumed thread can start."""
    planned: list[tuple[Path, str, str, bool, bool]] = []
    artifact = getattr(args, "artifact_out", None)
    if artifact is not None:
        planned.append((artifact, "--artifact-out", "file", False, False))
        if not resume and engine == "legacy":
            planned.append((artifact.with_name(artifact.name + ".account.json"), "artifact account sidecar", "file", False, False))

    run_link = getattr(args, "run_link", None)
    if run_link is not None:
        if engine != "pipeline":
            raise RuntimeBoundary("--run-link requires --engine pipeline")
        planned.append((run_link, "--run-link", "file", not resume, False))

    events_out = getattr(args, "events_out", None)
    if events_out is not None:
        if resume:
            raise RuntimeBoundary("--events-out is only supported by hlith run")
        planned.append((events_out, "--events-out", "file", False, True))

    thread_store = getattr(args, "thread_store", None)
    if thread_store is not None:
        planned.append((thread_store, "--thread-store", "directory", False, False))
    elif has_agent or resume:
        from ..agent import default_store
        planned.append((default_store(), "default thread store", "directory", False, False))

    canonical: set[Path] = set()
    parent_directories: dict[Path, _PinnedOutputParent] = {}
    for path, label, kind, new_only, empty_ok in planned:
        resolved_path, key, parent_directory = _preflight_destination(
            Path(path), label, protected=protected, kind=kind,
            must_be_new=new_only, allow_empty=empty_ok)
        if key in canonical:
            raise RuntimeBoundary(f"output destinations overlap at {key}")
        canonical.add(key)
        if parent_directory is not None:
            parent_directories[resolved_path] = parent_directory
    args._output_parent_directories = parent_directories


def _atomic_write_file(path: Path, data: bytes, *, parent_directory: _PinnedOutputParent | None = None) -> None:
    """Replace one preflighted regular output file atomically, cleaning up on failure."""
    p = Path(os.path.abspath(Path(path).expanduser()))
    fd = -1
    temp_name = None
    dir_fd = -1
    try:
        if parent_directory is None:
            dir_fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            dir_fd = os.dup(parent_directory.fd)
        for _ in range(8):
            temp_name = f".{p.name}.hlith-{secrets.token_hex(8)}"
            try:
                fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                             0o600, dir_fd=dir_fd)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate an artifact temporary file")
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, p.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_name = None
        os.fsync(dir_fd)
        if parent_directory is not None:
            try:
                current_fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError as e:
                raise OSError(f"artifact output parent changed after preflight: {p.parent}") from e
            try:
                expected_stat = os.fstat(parent_directory.fd)
                current_stat = os.fstat(current_fd)
                if (current_stat.st_dev, current_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
                    raise OSError(f"artifact output parent changed after preflight: {p.parent}")
            finally:
                os.close(current_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_name is not None and dir_fd >= 0:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except OSError:
                pass
        if dir_fd >= 0:
            os.close(dir_fd)


def _output_parent_directory(args, path: Path) -> _PinnedOutputParent | None:
    p = Path(os.path.abspath(Path(path).expanduser()))
    return getattr(args, "_output_parent_directories", {}).get(p)


def _copy_artifact_after_operation(source: Path, destination: Path, *, exit_status: int,
                                   parent_directory: _PinnedOutputParent | None = None) -> int:
    try:
        _atomic_write_file(destination, Path(source).read_bytes(), parent_directory=parent_directory)
    except OSError as e:
        state = "SUCCEEDED" if exit_status == 0 else f"completed with exit {exit_status}"
        print(clean(f"hlith: operation {state}, artifact copy FAILED; original artifact path: {source}; "
                    f"requested destination: {destination}; {e.strerror or e}"), file=sys.stderr)
        return EXIT_ARTIFACT_COPY
    return exit_status


def _write_generated_artifact(path: Path, data: bytes, *, exit_status: int,
                              parent_directory: _PinnedOutputParent | None = None) -> int:
    try:
        _atomic_write_file(path, data, parent_directory=parent_directory)
    except OSError as e:
        state = "SUCCEEDED" if exit_status == 0 else f"completed with exit {exit_status}"
        print(clean(f"hlith: operation {state}, artifact write FAILED; generated artifact was not saved at {path}: "
                    f"{e.strerror or e}"), file=sys.stderr)
        return EXIT_ARTIFACT_COPY
    return exit_status


def _host_state_root() -> Path:
    from ..agent.checkpoint import _state_dir

    return _state_dir().expanduser().resolve()


def _build_guarded_proposer(argv: list[str], repo: Path, worker_ro, *, timeout: float = 120.0,
                            forbidden=(), allow_unconfined: bool = False):
    """Validate proposer argv and return the single CommandProposer instance with frozen paths."""
    from ..agent import CommandProposer

    try:
        proposer = CommandProposer(argv, timeout=timeout, allow_unconfined=allow_unconfined)
    except ValueError as e:
        raise RuntimeBoundary(str(e)) from None
    repo = Path(repo).expanduser().resolve()
    try:
        proposer.ensure_unconfined_forms_allowed(repo)
    except ValueError as e:
        raise RuntimeBoundary(str(e)) from None
    grants = tuple(Path(p).expanduser().resolve() for p in worker_ro)
    forbidden = tuple(Path(p).expanduser().resolve() for p in (*forbidden, _host_state_root()))
    for path in proposer._frozen_paths:
        if path == repo or repo in path.parents:
            raise RuntimeBoundary("proposer command path is inside the target repository")
        if path in repo.parents:
            raise RuntimeBoundary("proposer command path contains the target repository")
        if any(path == grant or grant in path.parents for grant in grants):
            raise RuntimeBoundary("proposer command path is inside a worker-readable grant")
        if any(path in grant.parents for grant in grants):
            raise RuntimeBoundary("proposer command path contains a worker-readable grant")
        if any(path == root or root in path.parents for root in forbidden):
            raise RuntimeBoundary("proposer command path is inside a worker-readable path")
        if any(path in root.parents for root in forbidden):
            raise RuntimeBoundary("proposer command path contains a worker-readable or protected path")
    for entry in proposer._frozen_path_stats:
        if entry is not None and entry[0] and entry[3] > 1:
            raise RuntimeBoundary("proposer command path is a hardlinked file (st_nlink > 1)")
    return proposer


def _normalise_origin(url: str) -> str:
    url = url.strip().rstrip("/")
    return url[:-4] if url.endswith(".git") else url


def _hosted_agent_proposer(args, store_path, repo=None):
    """E1 (maintainer decision 2026-11-20): a host-authenticated coding-agent CLI as the proposer, PUBLIC pinned repositories only.

    The scope is checked HERE, against the repository the run is about (the source repository on a rehearsal run): its
    ``origin`` must be the config's https origin and its HEAD the config's pinned commit. The bridge runs host-side (it needs
    the provider's login and network), so the run never counts as E2; it sees only the turn JSON, never the repository."""
    from ..agent import HostSideProposerTrust
    from ..agent import cli_bridge

    cfg_path = Path(args.hosted_agent_config).expanduser().resolve()
    try:
        cfg = cli_bridge.load_config(str(cfg_path))
    except cli_bridge.ConfigError as e:
        raise RuntimeBoundary(f"hosted agent config: {e}") from None
    want = cfg["public_scope"]
    if args.worker_ro or args.extra_sys_path:
        raise RuntimeBoundary("hosted agent scope: extra worker-readable paths are not allowed (their contents could reach the model)")

    def _git(repo: Path, *a: str) -> str:
        return _safe_git(repo, *a)  # vetted + hardened + scrubbed: a hostile repository's config/hooks never run here

    # Everything the worker reads (and so may put in the transcript the model sees) must be exactly the attested public commit:
    # the engine repository AND, on a rehearsal, the source repository it was cloned from. Any uncommitted, untracked or IGNORED
    # file is refused, because its contents are not part of the public commit.
    engine_repo = Path(args.repo if repo is None else repo).expanduser().resolve()  # resume: the thread's own target repository
    scoped = [engine_repo]
    if args.source_repo is not None:
        scoped.append(Path(args.source_repo).expanduser().resolve())
    for repo in scoped:
        if _normalise_origin(_git(repo, "remote", "get-url", "origin")) != _normalise_origin(want["origin_url"]):
            raise RuntimeBoundary(f"hosted agent scope: the origin of {repo} is not the config's public origin_url")
        if _git(repo, "rev-parse", "HEAD") != want["commit"]:
            raise RuntimeBoundary(f"hosted agent scope: HEAD of {repo} is not the config's pinned commit")
        if _git(repo, "status", "--porcelain=v1", "--ignored", "--untracked-files=all"):
            raise RuntimeBoundary(f"hosted agent scope: {repo} has uncommitted, untracked or ignored files; "
                                  "the hosted agent runs only on a clean snapshot of the public commit")
    # The packaged bridge lives inside the hlith package, which the confined worker may read; a proposer file must never sit in a
    # worker-readable tree (the guard refuses it). The bridge is stdlib-only, so it runs from a private 0700 copy whose sha256 is
    # the packaged file's and is recorded in the run's provenance.
    # The copy's path is CONTENT-ADDRESSED (not random): the proposer argv hash is saved with a LangGraph thread, so a resume in a new
    # process must rebuild the identical argv. The config's own sha256 is part of that argv, so a changed config refuses a resume.
    bridge_bytes = Path(cli_bridge.__file__).read_bytes()
    bridge_sha = hashlib.sha256(bridge_bytes).hexdigest()
    cfg_sha = hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    root = Path(tempfile.gettempdir()) / f"hlith-e1-bridge-{os.getuid()}"
    try:
        root.mkdir(mode=0o700, exist_ok=True)
        st = root.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeBoundary(f"hosted agent bridge directory {root} is not a private directory owned by this user")
        bridge = root / bridge_sha[:24] / "cli_bridge.py"
        bridge.parent.mkdir(mode=0o700, exist_ok=True)
        if not bridge.exists() or hashlib.sha256(bridge.read_bytes()).hexdigest() != bridge_sha:
            tmp = bridge.parent / f".{secrets.token_hex(8)}.tmp"
            tmp.write_bytes(bridge_bytes)
            tmp.chmod(0o500)
            os.replace(tmp, bridge)
        if hashlib.sha256(bridge.read_bytes()).hexdigest() != bridge_sha or bridge.lstat().st_uid != os.getuid():
            raise RuntimeBoundary("hosted agent bridge copy does not match the packaged bridge")
    except OSError as e:
        raise RuntimeBoundary(f"hosted agent bridge copy cannot be prepared ({type(e).__name__})") from None
    timeout = max(float(args.timeout), float(cfg["deadline_s"]) + 30.0)
    proposer = _build_guarded_proposer([sys.executable, "-I", str(bridge), str(cfg_path), cfg_sha], engine_repo,
                                       (*args.worker_ro, *args.extra_sys_path), timeout=timeout,
                                       forbidden=(store_path,), allow_unconfined=True)
    proposer.model_id = f"hosted-cli:{cfg['provider']}"
    kind = "E1 hosted agent CLI" if cfg["provider"] != "local-stand-in" else "local stand-in (plumbing only, not a model)"
    proposer.host_trust = HostSideProposerTrust(
        authorized=True, reason=(f"{kind}; provider {cfg['provider']}; origin {want['origin_url']}@{want['commit'][:12]} "
                                 f"(public by operator attestation), clean snapshot verified; bridge sha256 {bridge_sha[:16]}"))
    return proposer


def _guard_proposer_argv(argv: list[str], repo: Path, worker_ro, *, forbidden=(), allow_unconfined: bool = False) -> list[str]:
    """Reject executable/script paths that overlap (equal, inside, or ancestor of) the judged repo, worker grants, or protected state."""
    _build_guarded_proposer(argv, repo, worker_ro, forbidden=forbidden, allow_unconfined=allow_unconfined)
    return argv


def _derive_proposer_paths(worker_argv, worker_ro, patch, manifest, proposer) -> list[str]:
    """Collect proposer-owned inputs for blinded checks, excluding shared runtimes only (rule shared with the pipeline path)."""
    from .capabilities import proposer_private_paths

    return proposer_private_paths(_worker_path_arguments(worker_argv), worker_ro, patch, manifest, proposer)


def _worker_path_arguments(worker_argv):
    """Remove inline Python source from argv before treating command arguments as possible file paths."""
    argv = list(worker_argv)
    executable = Path(argv[0]).name.lower() if argv else ""
    if executable.startswith(("python", "pypy")):
        index = 1
        value_options = {"-W", "-X", "--check-hash-based-pycs"}
        while index < len(argv):
            token = argv[index]
            if token == "-c":
                if index + 1 < len(argv):
                    del argv[index + 1]
                break
            if token in {"-m", "--"} or not token.startswith("-"):
                break  # a module or script has started; later -c tokens are its arguments
            index += 2 if token in value_options else 1
    return argv


def _coordinator_run_id(args, operator_proposer, worker_argv) -> str:
    """The run's id comes from the operator coordinator (contract.identities.new_run_id behind Coordinator.begin). A launcher that
    already allocated it passes --run-id (receipt on disk); a direct ``hlith run`` gets a fresh id plus its linking receipt."""
    from ..contract.identities import run_id as _check_run_id
    from ..contract.runs import LandingTarget, RunMode
    from .coordinator import Coordinator, RunRequest

    if args.run_id is not None:
        return str(_check_run_id(args.run_id))
    rehearsal = args.source_repo is not None
    supplied = args.patch is not None
    req = RunRequest(
        repo=(args.source_repo if rehearsal else args.repo), engine_repo=args.repo,
        mode=RunMode.HEADLESS if supplied else RunMode.STANDALONE,
        landing_target=LandingTarget.REHEARSAL if rehearsal else LandingTarget.ORIGINAL,
        patch=b"" if supplied else None, agent_request=None if supplied else {"worker": bool(worker_argv), "proposer": operator_proposer is not None},
        label="cli run")
    receipt, _ = Coordinator().begin(req)
    return str(receipt.run_id)


def _run_via_pipeline(args) -> int:
    """``hlith run --engine pipeline``: one run through ``operator.pipeline`` via the session API. No verdict is computed here; the
    gate receipt's exit status is the exit status. The ENGINE mints the RunId (inside the pipeline): ``--run-id`` is refused, and a
    launcher learns the id through ``--run-link FILE`` (written at the first event)."""
    from ..contract.errors import EXIT_BOUNDARY, EXIT_USAGE
    from ..contract.identities import InvocationId
    from ..contract.runs import LandingTarget, RunMode
    from .api import OperatorApi
    from .capabilities import ProbeBridgeUnavailable, default_capabilities, intent_from_manifest, proposer_private_paths
    from .coordinator import RequestError, RunRequest
    from .state import HostIntegrityError

    if args.run_id is not None:
        print("hlith: boundary: --run-id cannot be selected with --engine pipeline; the engine mints the RunId (use --run-link to learn it, or --engine legacy to supply one)", file=sys.stderr)
        return EXIT_BOUNDARY
    if args.events_out is not None:
        print("hlith: boundary: --events-out is not supported by --engine pipeline; use --engine legacy", file=sys.stderr)
        return EXIT_BOUNDARY
    if args.layer1 is not None:
        print("hlith: boundary: --layer1 is not supported by --engine pipeline; use --engine legacy", file=sys.stderr)
        return EXIT_BOUNDARY
    for flag, value in (("--patch-sha256", args.patch_sha256), ("--manifest-sha256", args.manifest_sha256)):
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            print(f"hlith: {flag} must be 64 lowercase hex characters", file=sys.stderr)
            return EXIT_USAGE
    if args.expect_head is not None:
        # D1 (review's finding on apply): the reviewed base is a BINDING, not just a review-time check. Refused before any run work; the
        # gate then re-checks the verified base tree against the live head under its locks, so a later move still cannot land.
        if not re.fullmatch(r"[0-9a-f]{40}", args.expect_head):
            print("hlith: --expect-head must be 40 lowercase hex characters", file=sys.stderr)
            return EXIT_USAGE
        try:
            _head = _safe_git(Path(args.repo).expanduser().resolve(), "rev-parse", "HEAD")
        except RuntimeBoundary as e:  # a hostile repository is refused here, before any git command can run its code
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        if _head != args.expect_head:
            print("hlith: boundary: the repository HEAD is not the expected head this run was bound to (it moved); nothing was run or changed",
                  file=sys.stderr)
            return EXIT_BOUNDARY
    if args.approve_deltas is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.approve_deltas):
        print("hlith: --approve-deltas must be a 64-hex sha256", file=sys.stderr)
        return EXIT_USAGE
    if args.invocation_id is not None and not re.fullmatch(r"inv-[0-9a-f]{12}", args.invocation_id):
        print("hlith: --invocation-id must look like inv-<12 hex>", file=sys.stderr)
        return EXIT_USAGE
    try:
        _preflight_cli_outputs(args, protected=tuple(p for p in (args.repo, args.source_repo, *args.worker_ro, *args.extra_sys_path) if p),
                               engine="pipeline", resume=False,
                               has_agent=bool(args.layer1 or args.proposer_command or args.hosted_agent_config))
    except (RuntimeBoundary, OSError, ValueError) as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    rehearsal = args.source_repo is not None
    try:
        patch = Path(args.patch).read_bytes() if args.patch is not None else None
        manifest_raw = Path(args.manifest).read_bytes() if args.manifest is not None else None
    except FileNotFoundError as e:
        print(clean(f"hlith: usage: operator input does not exist: {e.filename or e}"), file=sys.stderr)
        return EXIT_USAGE
    except OSError as e:
        print(clean(f"hlith: boundary: cannot read operator input: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    # the bytes about to be used are the bytes that were reviewed: checked BEFORE any run (same rule as the legacy engine)
    for what, want, data in (("patch", args.patch_sha256, patch), ("manifest", args.manifest_sha256, manifest_raw)):
        if want is not None:
            got = hashlib.sha256(data if data is not None else b"").hexdigest()
            if data is None or got != want:
                print(clean(f"hlith: boundary: {what} sha256 mismatch: expected {want}, the file hashes to {got if data is not None else 'n/a (no file)'}"),
                      file=sys.stderr)
                return EXIT_BOUNDARY
    from .patchnorm import normalize_patch

    patch_norm = None
    if patch is not None:  # AFTER the binding check above: the reviewed bytes are the bytes that were hashed
        n = normalize_patch(patch)
        patch = n.applied
        patch_norm = n.record()
        if args.patch_original_sha256:  # a launcher (hlith check) already stripped the preamble and says what the file was
            patch_norm = {"input_patch_sha256": args.patch_original_sha256, "applied_patch_sha256": n.applied_sha256,
                          "preamble_removed_bytes": int(args.patch_preamble_bytes or 0) + n.stripped_bytes}
        if patch_norm["preamble_removed_bytes"]:
            print(f"hlith: preamble removed ({patch_norm['preamble_removed_bytes']} bytes before the first 'diff --git'); "
                  f"input sha256 {patch_norm['input_patch_sha256'][:12]}, applied sha256 {patch_norm['applied_patch_sha256'][:12]}", file=sys.stderr)
    manifest = None
    if manifest_raw is not None:
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            print(clean(f"hlith: boundary: cannot read manifest: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
    if args.allow_unconfined_proposer and not args.proposer_command:
        print("hlith: --allow-unconfined-proposer needs --proposer-command", file=sys.stderr)
        return EXIT_USAGE
    store_path = args.thread_store or _l1_default_store()
    if patch is not None:
        agent = None
    elif args.proposer_command:
        try:
            argv_p = shlex.split(args.proposer_command)
            proposer = _build_guarded_proposer(
                argv_p, args.repo, (*args.worker_ro, *args.extra_sys_path),
                timeout=args.timeout, forbidden=(store_path,),
                allow_unconfined=args.allow_unconfined_proposer,
            )
        except (RuntimeBoundary, ValueError) as e:
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        agent = {"proposer": proposer, "thread_store": str(store_path), "layer1": True, "timeout": args.timeout,
                 "worker_ro": list(args.worker_ro), "proposer_id": getattr(proposer, "model_id", args.proposer_id)}
    elif args.hosted_agent_config:
        try:
            proposer = _hosted_agent_proposer(args, store_path)
        except (RuntimeBoundary, ValueError) as e:
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        agent = {"proposer": proposer, "thread_store": str(store_path), "layer1": True, "timeout": proposer._timeout,
                 "worker_ro": list(args.worker_ro), "proposer_id": proposer.model_id}
    else:
        agent = {"worker_argv": shlex.split(args.worker_cmd), "timeout": args.timeout, "worker_ro": list(args.worker_ro),
                 "proposer_id": args.proposer_id}
    surface = {"standalone": RunMode.STANDALONE, "companion": RunMode.COMPANION, "headless": RunMode.HEADLESS}.get(args.surface_mode)
    mode = surface or (RunMode.HEADLESS if patch is not None else RunMode.STANDALONE)
    req = RunRequest(repo=args.source_repo if rehearsal else args.repo, engine_repo=args.repo, mode=mode,
                     landing_target=LandingTarget.REHEARSAL if rehearsal else LandingTarget.ORIGINAL,
                     patch=patch, manifest=manifest, agent_request=agent, label=args.label or "cli run", patch_normalization=patch_norm,
                     invocation_id=InvocationId(args.invocation_id) if args.invocation_id else None,
                     # a scripted worker's approval binds to the host-read worker manifest per call (pipeline._resume_intent); an
                     # external patch keeps its CLI-built intent (default_capabilities below), so it must not carry the per-call hash
                     approve_deltas=args.approve_deltas if args.worker_cmd else None,
                     expected_head=getattr(args, "expect_head", None))
    # the REAL proposer-private inputs (patch, manifest, worker command paths, worker grants, thread store, proposer files): the
    # differential proves the checker is blind to them and refuses (UNVERIFIED) on an empty or non-existent list: never padded
    proposer_paths = proposer_private_paths(_worker_path_arguments(shlex.split(args.worker_cmd) if args.worker_cmd else []),
                                            args.worker_ro, args.patch,
                                            args.manifest, agent["proposer"] if agent and "proposer" in agent else None,
                                            extra=[store_path] if agent and "proposer" in agent else
                                            ([args.thread_store] if args.thread_store else []))

    def link_launcher(run_dir, receipt) -> None:
        if args.run_link is not None:
            from . import store as _store
            _store.write_new(Path(args.run_link), json.dumps({"run_id": str(receipt.run_id), "run_dir": str(run_dir)}).encode() + b"\n")

    api = OperatorApi()
    try:
        out = api.run_inline(req, default_capabilities(state_root=api.state.root, python=args.target_python, extra_sys_path=tuple(args.extra_sys_path),
                                                         thread_store=store_path if agent and "proposer" in agent else args.thread_store,
                                                         proposer_paths=proposer_paths,
                                                         intent=intent_from_manifest(manifest, args.approve_deltas)),
                             on_start=link_launcher)
    except RequestError as e:
        print(clean(f"hlith: {e}"), file=sys.stderr)
        return EXIT_USAGE
    except ProbeBridgeUnavailable as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    except HostIntegrityError as e:
        reason = clean(str(e))
        print(clean(f"hlith: boundary: {reason}"), file=sys.stderr)
        if args.artifact_out is not None:
            refusal = {
                "format": "hlith.pre-run-refusal.v1",
                "engine": "pipeline",
                "outcome": "REFUSED",
                "exit_status": EXIT_BOUNDARY,
                "run_id": None,
                "reason": reason,
            }
            try:
                _atomic_write_file(
                    Path(args.artifact_out),
                    (json.dumps(refusal, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                    parent_directory=_output_parent_directory(args, args.artifact_out),
                )
            except OSError as copy_error:
                print(clean(f"hlith: boundary refusal artifact could not be written to {args.artifact_out}: {copy_error}"), file=sys.stderr)
                return EXIT_ARTIFACT_COPY
        return EXIT_BOUNDARY
    for p in out.problems:
        print(clean(f"hlith: {p}"), file=sys.stderr)
    if out.run_dir is None:
        return out.exit_status
    insp = api.inspect(out.run_dir)
    print(f"hlith: {insp.label} exit={out.exit_status} run={out.receipt.run_id}")
    for n in insp.notes:
        print("  " + clean(n))
    # a failed worker command must say what was observed (exit code, stderr, likely confinement cause), as the legacy engine did;
    # the label alone ("BOUNDARY") hid it in out.json
    run_blocking = tuple(getattr(out.gate, "blocking", None) or ()) if out.exit_status != 0 else ()
    if run_blocking and run_blocking[0] == "worker-command-failed":
        for b in run_blocking[1:3]:
            print("  blocking: " + clean(str(b))[:300])
    if args.artifact_out is not None:
        if out.artifact_path is None:
            state = "SUCCEEDED" if out.exit_status == 0 else f"completed with exit {out.exit_status}"
            print(clean(f"hlith: operation {state}, artifact copy FAILED; no original artifact path was returned; "
                        f"requested destination: {args.artifact_out}"), file=sys.stderr)
            return EXIT_ARTIFACT_COPY
        return _copy_artifact_after_operation(
            out.artifact_path, args.artifact_out, exit_status=out.exit_status,
            parent_directory=_output_parent_directory(args, args.artifact_out))
    return out.exit_status


def _resume_via_pipeline(args, ap) -> int:
    """``hlith resume THREAD`` through ``operator.pipeline``: ``PipelineRequest.resume_thread_id`` -> ``AgentApi.resume``. The ORIGINAL
    RunId is recovered from the checkpoint by the agent (still ONE engine RunId); the coordinator keys its store by it and a launcher
    follows ``--run-link``. A decided verdict is never rewritten (an existing artifact is kept). A mid-agent thread continues with the
    same local command, bound to the agent capability here."""
    from ..agent import default_store, thread_target
    from ..contract.errors import EXIT_USAGE
    from ..contract.identities import InvocationId, ThreadId
    from ..contract.runs import LandingTarget, RunMode
    from .api import OperatorApi
    from .capabilities import ProbeBridgeUnavailable, default_capabilities, proposer_private_paths
    from .coordinator import RequestError, RunRequest
    from ..hostio import LocalHostState

    if args.hosted_agent_config is not None and args.proposer_command:
        ap.error("give --proposer-command or --hosted-agent-config, not both")
    if args.allow_unconfined_proposer and not args.proposer_command:
        ap.error("--allow-unconfined-proposer needs --proposer-command")
    if args.redo_inflight and not (args.proposer_command or args.hosted_agent_config):
        ap.error("--redo-inflight needs --proposer-command or --hosted-agent-config")
    if args.approve_deltas is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.approve_deltas):
        ap.error("--approve-deltas must be a 64-hex sha256")
    if args.invocation_id is not None and not re.fullmatch(r"inv-[0-9a-f]{12}", args.invocation_id):
        print("hlith: --invocation-id must look like inv-<12 hex>", file=sys.stderr)
        return EXIT_USAGE
    store_path = args.thread_store or default_store()
    api = OperatorApi()
    resume_host_state = LocalHostState(api.state.root)
    from ..agent.checkpoint import describe_thread

    try:
        described = describe_thread(args.thread_id, store_path, host_state=resume_host_state)
    except (RuntimeBoundary, OSError, ValueError) as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    if described["has_verdict"]:
        verdict = described.get("verdict") if isinstance(described.get("verdict"), dict) else {}
        if verdict.get("unreadable") or "outcome" not in verdict:
            print("hlith: boundary: the recorded verdict does not authenticate; refusing to resume or replace it", file=sys.stderr)
            return EXIT_BOUNDARY
    if described["finished"] and described["interrupt_checkpoint_id"] and not described["has_verdict"]:
        print("hlith: boundary: finished effect interrupt has no recorded verdict; refusing to rejudge", file=sys.stderr)
        return EXIT_BOUNDARY
    captured = described["kind"] == "effect-interrupt"
    if args.approve_deltas is not None and not captured:
        print("hlith: boundary: --approve-deltas requires this thread's recorded effect-interrupt checkpoint", file=sys.stderr)
        return EXIT_BOUNDARY
    if captured:
        if args.proposer_command or args.hosted_agent_config or args.redo_inflight or args.allow_unconfined_proposer:
            print("hlith: boundary: a thread parked at its effect interrupt is resumed through the gate; "
                  "--proposer-command is not called again", file=sys.stderr)
            return EXIT_USAGE
        recorded_ckpt = str(described.get("interrupt_checkpoint_id") or "")
        if args.checkpoint_id is None:
            print(f"hlith: boundary: thread {args.thread_id} is parked at effect interrupt {recorded_ckpt}.", file=sys.stderr)
            print("  resume it through the gate (effect account, obligations, host writer) with:", file=sys.stderr)
            print(f"  hlith resume {args.thread_id} --checkpoint-id {recorded_ckpt} --thread-store {store_path}", file=sys.stderr)
            print("  --engine legacy does not complete this gate; it only records an interrupted refusal.", file=sys.stderr)
            return EXIT_BOUNDARY
        if args.checkpoint_id != recorded_ckpt:
            print(clean(f"hlith: boundary: checkpoint id mismatch: recorded interrupt {recorded_ckpt}, asked {args.checkpoint_id}"),
                  file=sys.stderr)
            return EXIT_BOUNDARY
        # Recorded verdict replay is read-only and must still name the exact interrupt.
        # It cannot silently accept a missing or mismatched checkpoint id.
        if described["has_verdict"]:
            verdict = described.get("verdict") if isinstance(described.get("verdict"), dict) else {}
            print(f"hlith: recorded verdict kept for thread {args.thread_id}: outcome={verdict.get('outcome')} "
                  f"exit={verdict.get('exit_status')} (the gate was not run again)")
            return int(verdict["exit_status"]) if isinstance(verdict.get("exit_status"), int) else EXIT_BOUNDARY
        if not described["captured_mac"]:
            print("hlith: boundary: this effect interrupt has no reconstructable authenticated stage; "
                  "refusing to invent an effect or to record an interrupted verdict in its place", file=sys.stderr)
            return EXIT_BOUNDARY
    elif args.checkpoint_id is not None:
        ap.error("--checkpoint-id is only for a thread parked at its effect interrupt")
    proposer = None
    try:
        target = thread_target(args.thread_id, store_path)
        _preflight_cli_outputs(args, protected=tuple(p for p in (target, args.source_repo, *args.worker_ro, *args.extra_sys_path) if p),
                               engine="pipeline", resume=True, has_agent=True)
        grants = tuple(args.worker_ro) + tuple(args.extra_sys_path)
        if args.proposer_command:
            argv_p = shlex.split(args.proposer_command)
            proposer = _build_guarded_proposer(
                argv_p, target, grants, timeout=args.timeout,
                forbidden=(store_path, Path(store_path) / args.thread_id / "stage"),
                allow_unconfined=args.allow_unconfined_proposer,
            )
        elif args.hosted_agent_config:
            proposer = _hosted_agent_proposer(args, store_path, repo=target)
        _dirty = dirty_repo_reason(target)
        if _dirty:
            raise RuntimeBoundary(f"target repository is not clean: {_dirty}")
    except (RuntimeBoundary, ValueError, OSError) as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    rehearsal = args.source_repo is not None
    surface = {"standalone": RunMode.STANDALONE, "companion": RunMode.COMPANION, "headless": RunMode.HEADLESS}.get(args.surface_mode)
    req = RunRequest(repo=args.source_repo if rehearsal else target, engine_repo=target, mode=surface or RunMode.STANDALONE,
                     landing_target=LandingTarget.REHEARSAL if rehearsal else LandingTarget.ORIGINAL,
                     resume_thread_id=ThreadId(args.thread_id), redo_inflight=bool(args.redo_inflight), label=args.label or f"resume {args.thread_id}",
                     invocation_id=InvocationId(args.invocation_id) if args.invocation_id else None,
                     approve_deltas=args.approve_deltas)
    proposer_paths = proposer_private_paths([], args.worker_ro, None, None, proposer, extra=[store_path])

    def link_launcher(run_dir, receipt) -> None:
        if args.run_link is not None:
            from . import store as _store
            _store.write_replace(Path(args.run_link), json.dumps({"run_id": str(receipt.run_id), "run_dir": str(run_dir)}).encode() + b"\n")

    try:
        out = api.run_inline(req, default_capabilities(state_root=api.state.root, python=args.target_python, extra_sys_path=tuple(args.extra_sys_path),
                                                         thread_store=Path(store_path), proposer_paths=proposer_paths,
                                                         resume_proposer=None if captured else proposer,
                                                         resume_checkpoint_id=args.checkpoint_id if captured else None,
                                                         resume_timeout=args.timeout),
                             on_start=link_launcher)
    except RequestError as e:
        print(clean(f"hlith: {e}"), file=sys.stderr)
        return EXIT_USAGE
    except ProbeBridgeUnavailable as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    for p in out.problems:
        print(clean(f"hlith: {p}"), file=sys.stderr)
    if out.run_dir is None:
        return out.exit_status
    insp = api.inspect(out.run_dir)
    print(f"hlith: {insp.label} exit={out.exit_status} run={out.receipt.run_id} (resumed thread {args.thread_id})")
    for n in insp.notes:
        print("  " + clean(n))
    # a refused resume must say WHY (case): the label alone hid the reason, which lived only in out.json
    blocking = tuple(getattr(out.gate, "blocking", None) or ()) if out.exit_status != 0 else ()
    _CIRCULAR = ": resume it with `hlith resume`"  # supervisor.py's tail; on this path plain resume is what just ran
    for b in blocking[:5]:
        print("  blocking: " + clean(str(b).replace(_CIRCULAR, ""))[:300])
    if len(blocking) > 5:
        print(f"  blocking: ... and {len(blocking) - 5} more (see the run artifact)")
    if args.approve_deltas is not None and out.artifact_path is not None:
        try:
            saved = json.loads(Path(out.artifact_path).read_text(encoding="utf-8"))
            effect = saved.get("effect") if isinstance(saved, dict) else None
            canonical = effect.get("delta_set_sha256") if isinstance(effect, dict) else None
            if isinstance(canonical, str) and canonical != args.approve_deltas.lower():
                print(f"  recorded delta-set sha256: {canonical}")
                print(f"  to approve that exact set, rerun with --approve-deltas {canonical}")
        except (OSError, ValueError, TypeError):
            pass  # the operation result is already durable; diagnostics stay best-effort
    if any("not mid-agent" in str(b) for b in blocking):
        print("  this thread is parked at its effect interrupt. Pass the recorded --checkpoint-id to resume it through the gate. "
              "--engine legacy records an interrupted refusal and does not judge the captured effect.")
    if args.artifact_out is not None:
        if out.artifact_path is None:
            state = "SUCCEEDED" if out.exit_status == 0 else f"completed with exit {out.exit_status}"
            print(clean(f"hlith: operation {state}, artifact copy FAILED; no original artifact path was returned; "
                        f"requested destination: {args.artifact_out}"), file=sys.stderr)
            return EXIT_ARTIFACT_COPY
        return _copy_artifact_after_operation(
            out.artifact_path, args.artifact_out, exit_status=out.exit_status,
            parent_directory=_output_parent_directory(args, args.artifact_out))
    return out.exit_status


def _safe_git(repo: Path, *a: str) -> str:
    """One hardened read-only git command on ``repo`` (hostio.git_read.safe_git_read): vets the repository, scrubs the inherited GIT_*
    environment and applies the hardening flags. Every plain ``git -C`` in this module used to inherit repository config (an enabled
    core.fsmonitor ran during a READ-ONLY apply review); there must be none left. Raises RuntimeBoundary with the named reason."""
    from ..hostio.git_read import safe_git_read
    from ..hostio.integrity import HostIntegrityError

    try:
        return safe_git_read(Path(repo), *a)
    except (HostIntegrityError, OSError) as e:
        raise RuntimeBoundary(f"git {a[0]} refused or failed in {repo}: {str(e)[:240]}") from None


_APPLY_DOMAIN = b"case\0"


def _apply_review(args) -> dict:
    """D1 (maintainer decision 2026-11-20): everything an operator must see, and every identity an apply is bound to, BEFORE any write.

    Apply is only offered after a LANDED *rehearsal* and re-runs the whole trusted pipeline (derive, obligations, gate, CAS landing)
    on the original repository for the exact reviewed patch; a rehearsal verdict is never copied over. Raises RuntimeBoundary with a
    named reason for any mismatch. Writes nothing."""
    def _git(*a: str) -> str:
        return _safe_git(repo, *a)  # the review is READ-ONLY and must never run repository-controlled code (core.fsmonitor, hooks, env)

    repo = Path(args.repo).expanduser().resolve()
    try:
        art = json.loads(Path(args.rehearsal_artifact).read_bytes().decode("utf-8"))
        patch_bytes = Path(args.patch).read_bytes()
    except (OSError, ValueError) as e:
        raise RuntimeBoundary(f"apply: cannot read the rehearsal artifact or patch ({type(e).__name__})") from None
    run = art.get("run") if isinstance(art, dict) and isinstance(art.get("run"), dict) else {}
    eff = art.get("effect") if isinstance(art, dict) and isinstance(art.get("effect"), dict) else {}
    if art.get("outcome") != "landed" or art.get("exit_status") != 0:
        raise RuntimeBoundary("apply: only a LANDED rehearsal can be applied; this artifact is not a landing")
    if run.get("landing_target") != "rehearsal":
        raise RuntimeBoundary(f"apply: the artifact's recorded landing target is {run.get('landing_target')!r}, not 'rehearsal'")
    psha = hashlib.sha256(patch_bytes).hexdigest()
    if psha not in {str(eff.get("patch_sha256")), str(eff.get("input_patch_sha256"))}:
        raise RuntimeBoundary("apply: the patch file is not the patch this rehearsal verified (sha256 differs)")
    base_commit, base_tree, post_tree = (str(run.get(k) or "") for k in ("base_commit_sha", "base_tree_oid", "post_tree_oid"))
    if not all(re.fullmatch(r"[0-9a-f]{40}", v) for v in (base_commit, base_tree, post_tree)):
        raise RuntimeBoundary("apply: the rehearsal artifact does not record its base commit, base tree and post tree")
    if _git("rev-parse", "HEAD") != base_commit or _git("rev-parse", "HEAD^{tree}") != base_tree:
        raise RuntimeBoundary("apply: the repository HEAD is not the base this rehearsal verified (it moved); re-run the check")
    if _git("status", "--porcelain=v1", "--untracked-files=no"):
        raise RuntimeBoundary("apply: the repository has uncommitted changes to tracked files; apply needs a clean tree")
    # The intended-delta approval (D2) the rehearsal landed under. The artifact records the delta set and its digest, NOT the manifest's
    # own digest, so the manifest is tied to the rehearsal by RECOMPUTING its delta set and comparing it with the recorded digest. A manifest
    # may legitimately exist with no deltas; it is still bound into the token (by its sha256) whenever one is given.
    from ..agent import validate_deltas
    from ..contract.effects import delta_set_sha256 as _delta_set_sha256

    manifest_sha = manifest_delta_sha = None
    if args.manifest is not None:
        try:
            manifest_bytes = Path(args.manifest).read_bytes()
            manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
        except (OSError, ValueError) as e:
            raise RuntimeBoundary(f"apply: cannot read the manifest ({type(e).__name__})") from None
        if not isinstance(manifest_obj, dict):
            raise RuntimeBoundary("apply: the manifest is not a JSON object")
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        raw_deltas = manifest_obj.get("deltas", [])
        if raw_deltas:
            try:
                manifest_delta_sha = _delta_set_sha256(validate_deltas(raw_deltas))
            except (ValueError, TypeError):
                raise RuntimeBoundary("apply: the manifest's declared deltas do not validate") from None
    recorded_deltas = eff.get("deltas") or []
    recorded_delta_sha = eff.get("delta_set_sha256")
    approve_deltas = None
    if recorded_deltas:
        if not (isinstance(recorded_delta_sha, str) and re.fullmatch(r"[0-9a-f]{64}", recorded_delta_sha)):
            raise RuntimeBoundary("apply: the rehearsal recorded declared deltas but no valid delta-set digest")
        if manifest_delta_sha != recorded_delta_sha:
            raise RuntimeBoundary("apply: the manifest does not declare exactly the delta set this rehearsal was approved for "
                                  "(give the rehearsal's own manifest; the digest differs)")
        approve_deltas = recorded_delta_sha  # the original run must be approved for this exact set; it re-derives and re-checks it itself
    elif manifest_delta_sha is not None:
        raise RuntimeBoundary("apply: the manifest declares deltas but the rehearsal recorded none")
    from .policy import strict_requested

    strict = run.get("domain_policy") == "strict" or strict_requested(getattr(args, "strict_domain", False))
    policy = "strict" if strict else "scoped"
    target = str(Path(getattr(args, "target_python", None) or sys.executable).expanduser().absolute())
    token = hashlib.sha256(_APPLY_DOMAIN + b"\0".join(
        [psha.encode(), base_commit.encode(), post_tree.encode(), str(repo).encode(),
         (manifest_sha or "-").encode(), (approve_deltas or "-").encode(), policy.encode(), os.fsencode(target)])).hexdigest()[:16]
    files = [ln.split(" b/", 1)[-1] for ln in patch_bytes.decode("utf-8", "replace").splitlines() if ln.startswith("diff --git ")]
    return {"repo": str(repo), "patch_sha256": psha, "base_commit": base_commit, "post_tree": post_tree,
            "rehearsal_run": run.get("run_id"), "rehearsal_commit": art.get("landed_commit"),
            "files": files, "token": token, "manifest_sha256": manifest_sha, "approve_deltas": approve_deltas,
            "domain_policy": policy, "target_python": target}


def _apply_original(args) -> int:
    from .product import REVIEW_ONLY, REVIEW_LABEL
    if REVIEW_ONLY:
        print(f"hlith: boundary: {REVIEW_LABEL}; Apply is not offered in this distribution", file=sys.stderr)
        return EXIT_BOUNDARY
    try:
        rev = _apply_review(args)
    except RuntimeBoundary as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    for line in ("hlith: apply review (nothing is written until --confirm matches)",
                 f"  target repository : {rev['repo']}",
                 f"  base commit       : {rev['base_commit']} (HEAD matches, tree clean)",
                 f"  patch sha256      : {rev['patch_sha256']}",
                 f"  rehearsal         : {rev['rehearsal_run']} landed {rev['rehearsal_commit']} (post tree {rev['post_tree'][:12]})",
                 f"  files             : {', '.join(rev['files'][:20])}{' …' if len(rev['files']) > 20 else ''}",
                 f"  manifest sha256   : {rev['manifest_sha256'] or 'none given'}",
                 f"  approved delta set: {rev['approve_deltas'] or 'none (no declared deltas)'}",
                 f"  caller policy     : {rev['domain_policy']}",
                 f"  target Python     : {rev['target_python']}",
                 f"  apply token       : {rev['token']}"):
        print(clean(line))  # each line separately: clean() escapes control characters, which would turn the newlines into text
    if args.confirm is None:
        print("hlith: review only; to apply, run again with --confirm <apply token> --artifact-out FILE. "
              "Apply re-runs the full gate on the original repository; it does not copy the rehearsal verdict.", file=sys.stderr)
        return EXIT_USAGE
    if not secrets.compare_digest(str(args.confirm), rev["token"]):
        print("hlith: boundary: --confirm does not match this apply's token (patch, base, post tree and target are bound into it)",
              file=sys.stderr)
        return EXIT_BOUNDARY
    if args.artifact_out is None:
        print("hlith: usage: --confirm needs --artifact-out", file=sys.stderr)
        return EXIT_USAGE
    run_argv = ["run", "--engine", "pipeline", "--repo", rev["repo"], "--patch", str(Path(args.patch).resolve()),
                "--patch-sha256", rev["patch_sha256"], "--artifact-out", str(args.artifact_out), "--surface-mode", "companion",
                "--proposer-id", "operator-apply", "--timeout", str(args.timeout), "--expect-head", rev["base_commit"]]
    if args.manifest is not None:  # the run refuses (exit 4) unless the file still has the sha256 the review bound into the token
        run_argv += ["--manifest", str(Path(args.manifest).resolve()), "--manifest-sha256", rev["manifest_sha256"]]
    if rev["approve_deltas"]:  # D2: the rehearsal's approved delta set; the original run re-derives the set and refuses on any mismatch
        run_argv += ["--approve-deltas", rev["approve_deltas"]]
    if args.target_python:
        run_argv += ["--target-python", rev["target_python"]]
    if args.invocation_id:
        run_argv += ["--invocation-id", args.invocation_id]
    if args.run_link is not None:  # the TUI authenticates an apply's result through this link (review's real trace: without it, no Verdict screen)
        run_argv += ["--run-link", str(args.run_link)]
    if rev["domain_policy"] == "strict":
        run_argv += ["--strict-domain"]
    rc = main(run_argv)  # no --source-repo: the engine lands on THIS repository through the trusted gate (LandingTarget.ORIGINAL)
    if rc != 0:
        return rc
    try:
        out = json.loads(Path(args.artifact_out).read_bytes().decode("utf-8"))
        landed_tree = (out.get("run") or {}).get("post_tree_oid")
        original = (out.get("run") or {}).get("landing_target") == "original" and out.get("outcome") == "landed"
    except (OSError, ValueError):
        landed_tree, original = None, False
    same = original and landed_tree == rev["post_tree"]
    print(f"hlith: apply: landed on the original repository: {'yes' if original else 'NO'}; "
          f"landed tree == rehearsed post tree: {'yes' if same else 'NO'}")
    if not same:
        print("hlith: boundary: the applied tree is not the rehearsed tree; inspect the repository and the artifact", file=sys.stderr)
        return EXIT_BOUNDARY
    return 0


def main(argv: list[str] | None = None, *, _prepared_run=None,
         _output_parent_directories: dict[Path, _PinnedOutputParent] | None = None) -> int:
    _argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(prog="hlith")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ay = sub.add_parser("apply", help="review or confirm applying a LANDED rehearsal patch to the original repository through the trusted gate")
    ay.add_argument("--repo", required=True, type=Path, help="the ORIGINAL repository (never a clone)")
    ay.add_argument("--rehearsal-artifact", required=True, type=Path, help="artifact (out.json) of the LANDED rehearsal run")
    ay.add_argument("--patch", required=True, type=Path, help="the reviewed change.patch of that rehearsal")
    ay.add_argument("--manifest", type=Path, default=None, help="reviewed claim.manifest.json paired with the rehearsal patch")
    ay.add_argument("--confirm", default=None, metavar="TOKEN", help="confirmation token printed by the review step (binds patch, base, post tree, target)")
    ay.add_argument("--artifact-out", type=Path, default=None, metavar="FILE", help="output path for the original-landing artifact JSON (required with --confirm)")
    ay.add_argument("--timeout", type=float, default=120, metavar="SECONDS", help="wall-clock timeout in seconds for the gate run (default: 120)")
    ay.add_argument("--target-python", default=None, metavar="PATH", help="Python interpreter used inside confinement for target code")
    ay.add_argument("--invocation-id", default=None, metavar="INV", help="optional operator invocation id recorded in the run receipt")
    ay.add_argument("--run-link", type=Path, default=None, metavar="FILE",
                    help="optional path where the engine writes {run_id, run_dir} at startup (used by interactive launchers)")
    ay.add_argument("--strict-domain", action="store_true",
                    help="open-caller mode: refuse typed landing certificates unless both versions self-enforce exact builtin types at entry")
    r = sub.add_parser("run", help="run a worker in confined staging and gate its effect")
    r.add_argument("--repo", required=True, type=Path, help="target Git repository")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--worker-cmd", help="worker command line (shlex-split)")
    src.add_argument("--patch", type=Path, help=(
        "operator-produced patch (git diff); pipeline validates --patch as an external effect; "
        "legacy checkpointed graph: use --engine legacy --layer1 langgraph"))
    src.add_argument("--proposer-command", help=(
        "local supervisor-side proposer argv (shlex-split, no shell); --proposer-command is the "
        "pipeline LangGraph proposer; in legacy mode it requires --layer1 langgraph"))
    src.add_argument("--hosted-agent-config", type=Path, default=None, help=(
        "E1: run the proposer through a host-authenticated coding-agent CLI described by this operator config "
        "(see hlith/agent/cli_bridge.py); pipeline only; refused unless the repository is the config's public origin at its "
        "pinned commit; runs host-side (never counts as E2); the worker stays confined"))
    r.add_argument("--allow-unconfined-proposer", action="store_true",
                   help="allow interpreter inline-code or directory-switch forms for --proposer-command; runs code outside confinement")
    r.add_argument("--layer1", choices=["langgraph"], default=None,
                   help=("--layer1 is legacy-only; pipeline mode refuses it; run worker as a LangGraph StateGraph "
                         "(SqliteSaver, interrupt/resume) inside confinement"))
    r.add_argument("--manifest", type=Path, default=None, help="proposer manifest JSON for --patch (claim, never proof)")
    r.add_argument("--patch-sha256", default=None, metavar="HEX", help="refuse (exit 4) unless the --patch file hashes to this sha256 (bind a run to the reviewed patch)")
    r.add_argument("--manifest-sha256", default=None, metavar="HEX", help="refuse (exit 4) unless the --manifest file hashes to this sha256")
    r.add_argument("--artifact-out", required=True, type=Path, metavar="FILE", help="output path for the run artifact JSON")
    r.add_argument("--timeout", type=float, default=120, metavar="SECONDS", help="wall-clock timeout in seconds for the confined worker and gate (default: 120)")
    r.add_argument("--thread-store", type=Path, default=None,
                   help=("durable LangGraph thread store for legacy --layer1 or pipeline proposer runs "
                         "(default $HLITH_THREAD_STORE or ~/.local/state/hlith/threads); never inside --repo"))
    r.add_argument("--proposer-id", default="worker", help="provenance label for the proposer recorded in the artifact (default: worker)")
    r.add_argument("--expect-head", default=None, metavar="SHA1",
                   help="pipeline only: refuse (exit 4) before running unless the repository HEAD is exactly this commit (D1 apply binds its reviewed base)")
    r.add_argument("--approve-deltas", default=None, metavar="SHA256",
                   help="sha256 of the canonical delta set a human approves (see artifact effect.delta_set_sha256)")
    r.add_argument("--worker-ro", action="append", default=[], help="extra read-only path for the worker (its own code)")
    r.add_argument("--extra-sys-path", action="append", default=[], help="read-only dependency dir for target code")
    r.add_argument("--target-python", default=None, help="interpreter that runs target code in the differential check")
    r.add_argument("--events-out", type=Path, default=None, metavar="FILE",
                   help="legacy only: append one JSON line per real phase transition (informational; never read by the gate); "
                        "use --engine legacy; pipeline mode refuses this option with exit 4")
    r.add_argument("--engine", choices=["legacy", "pipeline"], default="pipeline",
                   help="pipeline (default): runs through OperatorApi's trusted coordinator and can publish its engine-minted RunId through --run-link; "
                        "legacy: preserves the pre-pipeline direct `hlith run` path. "
                        "Pipeline resume binds --approve-deltas to the captured thread deltas; a mismatch returns exit 12 with the canonical digest, and a thread/checkpoint binding mismatch returns exit 4. "
                        "Select --engine legacy only when you need the legacy-specific flags such as --events-out or a caller-supplied --run-id.")
    r.add_argument("--run-link", type=Path, default=None, metavar="FILE",
                   help="--engine pipeline: write {run_id, run_dir} here at the engine's first event (the engine mints the RunId; a launcher learns it this way)")
    r.add_argument("--invocation-id", default=None, metavar="INV", help="the launching surface's own id (inv-<12 hex>), linked to the run in its receipt")
    r.add_argument("--surface-mode", choices=["standalone", "companion", "headless"], default=None,
                   help="how the surface that launched this run presents it (default: headless for a patch, standalone otherwise)")
    r.add_argument("--label", default=None, help="a short label for the run (shown in history)")
    r.add_argument("--patch-original-sha256", default=None, metavar="HEX",
                   help="provenance only: sha256 of the patch file BEFORE a launcher stripped its preamble (recorded, never trusted for the gate)")
    r.add_argument("--patch-preamble-bytes", type=int, default=0, metavar="N", help="provenance only: how many preamble bytes that launcher stripped")
    r.add_argument("--run-id", default=None, metavar="RUN",
                   help="legacy only: caller-supplied coordinator RunId; pipeline mode mints its own id (use --run-link to learn it) "
                        "and refuses this option with exit 4")
    r.add_argument("--source-repo", type=Path, default=None,
                   help="--repo is a disposable rehearsal clone of this repository: a landing here is a REHEARSAL landing, never an original one")
    r.add_argument("--strict-domain", action="store_true",
                   help="open-caller mode: refuse typed landing certificates unless both versions self-enforce exact builtin types at entry (equivalent to HLITH_CERT_STRICT_DOMAIN=1)")
    rs = sub.add_parser("resume", help="resume (or replay) a persisted --layer1 thread from its recorded thread id; never alters a decided verdict")
    rs.add_argument("thread_id", help="durable thread identifier printed when the run paused or failed")
    rs.add_argument("--checkpoint-id", default=None, help="must equal the recorded interrupt checkpoint id")
    rs.add_argument("--thread-store", type=Path, default=None, help="durable thread store directory (default: $HLITH_THREAD_STORE or ~/.local/state/hlith/threads)")
    rs.add_argument("--timeout", type=float, default=120, metavar="SECONDS", help="wall-clock timeout in seconds for the resumed step (default: 120)")
    rs.add_argument("--proposer-command", help="continue a mid-agent thread with the same local supervisor-side command (shlex-split, no shell)")
    rs.add_argument("--allow-unconfined-proposer", action="store_true",
                    help="allow interpreter inline-code or directory-switch forms for --proposer-command; runs code outside confinement")
    rs.add_argument("--artifact-out", type=Path, default=None, help="required with --proposer-command; write the resumed run artifact")
    rs.add_argument("--hosted-agent-config", type=Path, default=None,
                    help="continue a mid-agent thread through the same E1 hosted-agent config (see run --hosted-agent-config); the same public-scope checks apply")
    rs.add_argument("--redo-inflight", action="store_true", help="explicitly repeat a proposer call whose side effects are unknown after a crash")
    rs.add_argument("--approve-deltas", default=None, metavar="SHA256", help="sha256 of the canonical delta set approved for this resumed thread")
    rs.add_argument("--worker-ro", action="append", default=[], help="extra read-only path granted to the confined worker (repeatable)")
    rs.add_argument("--extra-sys-path", action="append", default=[], help="read-only dependency directory for target code (repeatable)")
    rs.add_argument("--target-python", default=None, metavar="PATH", help="Python interpreter used inside confinement for target code")
    rs.add_argument("--proposer-id", default="worker", help="provenance label for the proposer (default: worker)")
    rs.add_argument("--engine", choices=["pipeline", "legacy"], default="pipeline",
                    help="pipeline (default): resume through the trusted coordinator pipeline (the ORIGINAL RunId is recovered from the checkpoint); "
                         "legacy: the pre-freeze resume body, an explicit fallback")
    rs.add_argument("--source-repo", type=Path, default=None,
                    help="the thread's target is a disposable rehearsal clone of this repository: a landing is a REHEARSAL landing")
    rs.add_argument("--run-link", type=Path, default=None, metavar="FILE", help="write {run_id, run_dir} here at the engine's first event")
    rs.add_argument("--invocation-id", default=None, metavar="INV", help="optional operator invocation id recorded in the run receipt")
    rs.add_argument("--surface-mode", choices=["standalone", "companion", "headless"], default=None, help="presentation mode recorded for the resumed run")
    rs.add_argument("--label", default=None, help="short label for the resumed run shown in history")
    pd = sub.add_parser("propose-deltas", help="derive a CANDIDATE delta set from the divergences the differential observed (a claim for review; never approves)")
    pd.add_argument("--repo", required=True, type=Path, help="target Git repository")
    pg = pd.add_mutually_exclusive_group(required=True)
    pg.add_argument("--artifact", type=Path, help="artifact of a refused run: its effect.unified_diff is the patch")
    pg.add_argument("--patch", type=Path, help="the patch (git diff) to analyse")
    pd.add_argument("--manifest", type=Path, default=None, help="your manifest: its paths and own deltas are kept, candidates are added")
    pd.add_argument("--out", type=Path, default=None, help="directory for proposed.manifest.json, proposed.provenance.json, patch (default ./hlith-proposed)")
    pd.add_argument("--max-divergences", type=int, default=200, metavar="N", help="maximum number of diverging inputs collected per symbol (default: 200)")
    pd.add_argument("--include-all", action="store_true",
                    help="candidate deltas for EVERY observed divergence (not only the dominant pattern): EVERY observed divergence becomes approved behaviour")
    pd.add_argument("--expression", action="store_true",
                    help="emit ONLY the broader EXPRESSION candidate (a returns_expr delta over `every non-empty str`, including untried inputs) when a closed form "
                         "reproduces ALL observed pairs; never default-included; with a preview that runs the differential with it in place")
    pd.add_argument("--timeout", type=float, default=600, metavar="SECONDS", help="wall-clock timeout in seconds for divergence collection (default: 600)")
    pd.add_argument("--proposer-id", default="worker", help="provenance label recorded in the proposed manifest (default: worker)")
    pd.add_argument("--layer1", choices=["langgraph"], default=None, help="put in the printed re-run commands (default: as the artifact's run was made; Layer 1 for --patch)")
    pd.add_argument("--extra-sys-path", action="append", default=[], help="read-only dependency directory for target code (repeatable)")
    pd.add_argument("--target-python", default=None, metavar="PATH", help="Python interpreter used inside confinement for target code")
    args = ap.parse_args(argv)
    prev_strict = os.environ.get("HLITH_CERT_STRICT_DOMAIN")
    strict_override = bool(getattr(args, "strict_domain", False))
    if strict_override:
        os.environ["HLITH_CERT_STRICT_DOMAIN"] = "1"
    try:
        return _dispatch_main(ap, args, _prepared_run=_prepared_run, _output_parent_directories=_output_parent_directories)
    finally:
        if strict_override:
            if prev_strict is None:
                os.environ.pop("HLITH_CERT_STRICT_DOMAIN", None)
            else:
                os.environ["HLITH_CERT_STRICT_DOMAIN"] = prev_strict


def _dispatch_main(ap, args, *, _prepared_run=None, _output_parent_directories=None) -> int:
    if args.cmd == "apply":
        return _apply_original(args)
    from .product import REVIEW_ONLY
    if REVIEW_ONLY and args.cmd in ("run", "resume", "propose-deltas"):
        # P2.6: no caller can select a landing. `hlith check` rehearses in-process in a clone it made itself; this module has no
        # internal route (no marker, environment token or capability record is consulted).
        print("hlith: boundary: Hlith Review is read-only; run/resume/propose-deltas/original-target landing are not offered in this distribution",
              file=sys.stderr)
        return EXIT_BOUNDARY
    if args.cmd == "run":
        try:
            args.repo.stat()
        except FileNotFoundError:
            print(clean(f"hlith: usage: repository path does not exist: {args.repo}"), file=sys.stderr)
            return EXIT_USAGE
        except OSError as e:
            print(clean(f"hlith: boundary: repository path cannot be inspected: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
    if args.cmd == "run" and args.engine == "legacy" and args.run_id is not None:
        from ..contract.identities import run_id as _check_run_id

        try:
            _check_run_id(args.run_id)
        except ValueError as e:
            ap.error(str(e))
    if getattr(args, "surface_mode", None) == "headless":  # case: a headless engine ends with the client that asked for it
        from ..hostio.lifecycle import die_with_parent

        die_with_parent()
    if _output_parent_directories is not None:
        args._output_parent_directories = _output_parent_directories
    if args.cmd == "propose-deltas":
        return _propose_deltas(args)
    if args.cmd == "resume" and args.engine == "pipeline":
        return _resume_via_pipeline(args, ap)
    if args.cmd == "resume" and args.hosted_agent_config:
        ap.error("--hosted-agent-config needs --engine pipeline")
    if args.cmd == "resume":
        from .. import layer1 as _l1r
        if args.allow_unconfined_proposer and not args.proposer_command:
            ap.error("--allow-unconfined-proposer needs --proposer-command")
        if args.redo_inflight and not args.proposer_command:
            ap.error("--redo-inflight needs --proposer-command")
        try:
            store = args.thread_store or _l1r.default_store()
            target = _l1r.thread_target(args.thread_id, store)
            _preflight_cli_outputs(args, protected=tuple(p for p in (target, args.source_repo, *args.worker_ro, *args.extra_sys_path) if p),
                                   engine="legacy", resume=True, has_agent=bool(args.proposer_command))
        except (RuntimeBoundary, OSError, ValueError) as e:
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        if args.proposer_command:
            if args.artifact_out is None:
                ap.error("--proposer-command on resume needs --artifact-out")
            if args.checkpoint_id is not None:
                ap.error("--checkpoint-id cannot be used with --proposer-command")
            if args.approve_deltas is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.approve_deltas):
                ap.error("--approve-deltas must be a 64-hex sha256")
            try:
                proposer_argv = shlex.split(args.proposer_command)
                grants = tuple(args.worker_ro) + tuple(args.extra_sys_path)
                from ..hostio.git_read import HardenedGitRead
                from ..hostio.snapshot import LocalSnapshotService
                from ..runtime import resume_agent_worker as _resume_agent_worker
                command = _build_guarded_proposer(
                    proposer_argv, target, grants, timeout=args.timeout,
                    forbidden=(store, Path(store) / args.thread_id / "stage"),
                    allow_unconfined=args.allow_unconfined_proposer,
                )
                _git_read = HardenedGitRead()
                resumed_run = _resume_agent_worker(
                    target, args.thread_id, store, command, timeout=args.timeout,
                    redo_inflight=args.redo_inflight,
                    git_read=_git_read, snapshot_service=LocalSnapshotService(_git_read),
                )
            except _l1r.IndeterminateProposerCall as e:
                message = clean(str(e))
                print(json.dumps({"outcome": "unverified", "exit_status": EXIT_UNVERIFIED,
                                  "state": "indeterminate", "reason": message}, sort_keys=True))
                return EXIT_UNVERIFIED
            except (RuntimeBoundary, ValueError) as e:
                print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
                return EXIT_BOUNDARY
            run_argv = ["run", "--repo", str(target), "--layer1", "langgraph", "--proposer-command", args.proposer_command,
                        "--artifact-out", str(args.artifact_out), "--thread-store", str(store), "--timeout", str(args.timeout)]
            if args.allow_unconfined_proposer:
                run_argv.append("--allow-unconfined-proposer")
            if args.approve_deltas:
                run_argv.extend(("--approve-deltas", args.approve_deltas))
            for value in args.worker_ro:
                run_argv.extend(("--worker-ro", value))
            for value in args.extra_sys_path:
                run_argv.extend(("--extra-sys-path", value))
            if args.target_python:
                run_argv.extend(("--target-python", args.target_python))
            return main(run_argv, _prepared_run=resumed_run,
                        _output_parent_directories=getattr(args, "_output_parent_directories", None))
        try:
            out = _l1r.resume_thread(args.thread_id, store,
                                     checkpoint_id=args.checkpoint_id, timeout=args.timeout)
        except (RuntimeBoundary, OSError, ValueError) as e:
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        print(json.dumps(out, indent=1, sort_keys=True))
        return int(out["exit_status"]) if isinstance(out.get("exit_status"), int) else 0  # a refusal is a refusal on the CLI too
    if args.approve_deltas is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.approve_deltas):
        ap.error("--approve-deltas must be a 64-hex sha256")

    if args.cmd == "run" and args.engine == "pipeline":
        return _run_via_pipeline(args)
    if args.cmd == "run" and getattr(args, "hosted_agent_config", None):
        ap.error("--hosted-agent-config needs --engine pipeline")
    if args.cmd == "run" and getattr(args, "expect_head", None):
        ap.error("--expect-head needs --engine pipeline")
    if args.cmd == "run":
        if getattr(args, "_output_parent_directories", None) is None:
            try:
                _preflight_cli_outputs(args, protected=tuple(p for p in (args.repo, args.source_repo, *args.worker_ro, *args.extra_sys_path) if p),
                                       engine="legacy", resume=False,
                                       has_agent=bool(args.layer1 or args.proposer_command))
            except (RuntimeBoundary, OSError, ValueError) as e:
                print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
                return EXIT_BOUNDARY
    from .. import derive as _derive, effect as _effect, feedback as _feedback
    if args.manifest is not None and args.patch is None:
        ap.error("--manifest needs --patch")
    for _flag, _val in (("--patch-sha256", args.patch_sha256), ("--manifest-sha256", args.manifest_sha256)):
        if _val is not None and not re.fullmatch(r"[0-9a-f]{64}", _val):
            ap.error(f"{_flag} must be 64 lowercase hex characters")
    if (args.patch_sha256 or args.manifest_sha256) and args.patch is None:
        ap.error("--patch-sha256/--manifest-sha256 need --patch")
    if args.allow_unconfined_proposer and not args.proposer_command:
        ap.error("--allow-unconfined-proposer needs --proposer-command")
    worker_argv = shlex.split(args.worker_cmd) if args.worker_cmd else []
    command_argv = []
    command_proposer = None
    if args.proposer_command:
        if args.layer1 != "langgraph":
            ap.error("--proposer-command needs --layer1 langgraph")
        try:
            command_argv = shlex.split(args.proposer_command)
            command_proposer = _build_guarded_proposer(
                command_argv, args.repo, (*args.worker_ro, *args.extra_sys_path),
                timeout=args.timeout, forbidden=(args.thread_store or _l1_default_store(),),
                allow_unconfined=args.allow_unconfined_proposer,
            )
        except (RuntimeBoundary, ValueError) as e:
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
    patch_bytes = manifest_bytes = None
    if args.patch is not None:
        try:
            patch_bytes = args.patch.read_bytes()
            manifest_bytes = args.manifest.read_bytes() if args.manifest else None
        except FileNotFoundError as e:
            print(clean(f"hlith: usage: operator input does not exist: {e.filename or e}"), file=sys.stderr)
            return EXIT_USAGE
        except OSError as e:
            print(clean(f"hlith: boundary: cannot read operator input: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        # the bytes about to be used are the bytes that were reviewed: checked BEFORE any derivation
        for _what, _want, _data in (("patch", args.patch_sha256, patch_bytes), ("manifest", args.manifest_sha256, manifest_bytes)):
            if _want is not None:
                _got = hashlib.sha256(_data if _data is not None else b"").hexdigest()
                if _data is None or _got != _want:
                    print(clean(f"hlith: boundary: {_what} sha256 mismatch: expected {_want}, the file hashes to {_got if _data is not None else 'n/a (no file)'}"), file=sys.stderr)
                    return EXIT_BOUNDARY
    operator_proposer = None
    pipeline_patch, pipeline_manifest = patch_bytes, manifest_bytes
    if args.layer1 == "langgraph" and patch_bytes is not None:
        # A local operator patch uses the same checkpointed agent-turn graph as a real proposer.
        # The patch and manifest remain data; the confined worker applies them and the gate verifies the effect.
        from ..proposer import OperatorPatchProposer
        operator_proposer = OperatorPatchProposer(patch_bytes, manifest_bytes)
        pipeline_patch = pipeline_manifest = None
    elif command_proposer is not None:
        operator_proposer = command_proposer
    _rstate, _rmsg = recover_pending_landing(args.repo)  # an interrupted landing is resolved (rolled back / completed) before the tree is judged dirty
    if _rmsg:
        print(clean(f"hlith: boundary: {_rmsg}"), file=sys.stderr)
        return EXIT_BOUNDARY
    if _rstate in ("rolled-back", "completed"):
        print(clean(f"hlith: a previous run was interrupted mid-landing; recovered: {_rstate}"), file=sys.stderr)
    _dirty = dirty_repo_reason(args.repo)  # before any staging or derivation: a landing is impossible, so say so now (review R3 probe P2)
    if _dirty:
        print(clean(f"hlith: boundary: {_dirty}"), file=sys.stderr)
        return EXIT_BOUNDARY
    # The proposer's own artifacts are explicit inputs to every blinded derivation check.
    proposer_paths = _derive_proposer_paths(worker_argv, args.worker_ro, args.patch, args.manifest, operator_proposer)
    try:  # the L3 probe helpers L5 needs (dist-info synthesis, receiver recipes): the pipeline engine wires them in default_capabilities; this path must too
        from .capabilities import ProbeBridgeUnavailable, _register_probe_bridge
        _register_probe_bridge(None)
    except ProbeBridgeUnavailable as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        return EXIT_BOUNDARY
    _fb_kw = {"python": args.target_python or sys.executable, "extra_sys_path": tuple(args.extra_sys_path),
              "proposer_paths": proposer_paths}
    _run_id = _coordinator_run_id(args, operator_proposer, worker_argv)  # allocated by the coordinator, never minted here
    _fb_report: dict = {"run_id": _run_id, "loaded_feedback_ids": [], "written_feedback_ids": [], "covered_by_delta": [],
                        "unpinned_witnesses": [], "recurrent_in_callee_cone": [], "recurrent_constructs": [],
                        "superseded_by_delta": []}

    def _load_feedback(repo: Path, acct: dict):
        fbk = _feedback.load_for_derive(repo, acct, **_fb_kw)
        _ds = _seen.get("deltas", ())
        _conf = confirm_deltas(_ds, args.approve_deltas) if _ds else None
        if _conf is not None and _conf.matched:  # design review F-A: an approved delta supersedes the pins it covers
            fbk, _fb_report["superseded_by_delta"] = fbk.supersede_pins(repo, _ds, _conf.delta_set_sha256, _run_id)
        _seen["constructs"] = tuple(acct.get("unresolved_constructs", ()))
        _seen["fbk"] = fbk
        _fb_report["recurrent_in_callee_cone"] = fbk.recurrent_in_callee_cone()
        _fb_report["recurrent_constructs"] = fbk.recurrent_constructs()  # review: non-blocking (design policy)
        _fb_report["loaded_feedback_ids"] = list(fbk.loaded_ids)
        return fbk

    _phases.reset()
    _phases.set_sink(None)
    _emitter = None
    if args.events_out is not None:
        from .. import events as _events
        try:  # the events file must not live where the confined worker can reach it, and must be a fresh regular file
            _events.check_path(args.events_out, [args.repo, *args.worker_ro, *args.extra_sys_path, Path(__file__).resolve().parent.parent.parent,
                                                 *_events.readable_roots(args.target_python)])
            _emitter = _events.Emitter(args.events_out, _run_id, on_error=lambda m: print(clean(_events.UNAVAILABLE_PREFIX + str(m)), file=sys.stderr))
        except ValueError as e:  # includes events.Refused
            print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            return EXIT_BOUNDARY
        _phases.set_sink(_emitter)
    _started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _base_commit = _git_out(args.repo, "rev-parse", "HEAD")  # before the run: a landing moves HEAD
    _acct: dict = {"dict": None, "error": None}

    def _declare(repo: Path, eff):
        try:  # the account the declaration is derived from; recorded in the artifact, read before any landing
            _obj = _effect.build_effect_account(repo, eff.unified_diff)
            _acct["dict"] = _obj.to_dict()
            _acct["stats"] = _cache_stats(_obj)
        except Exception as e:
            _acct["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        return _effect.declare(repo, eff)

    _seen: dict = {}  # the effect derive saw; Layer 5 needs its declared deltas after the gate
    _derive_fn = _derive.make_derive(proposer_paths=proposer_paths, extra_sys_path=tuple(args.extra_sys_path),
                                     target_python=args.target_python, feedback=_load_feedback)

    def _derive_capture(repo: Path, eff):
        _seen["deltas"] = tuple(getattr(eff, "deltas", ()))
        _seen["diff"] = getattr(eff, "unified_diff", "")
        return _derive_fn(repo, eff)

    def _after_gate(repo: Path, dec: GateDecision, obs: ObligationSet) -> None:
        ds = _seen.get("deltas", ())
        conf = confirm_deltas(ds, args.approve_deltas)  # same inputs as the gate's confirmation
        paths = _feedback.after_gate(repo, dec, obs, source_run_id=_run_id, deltas=ds,
                                     deltas_confirmed=bool(conf is not None and conf.matched),
                                     covered=_fb_report["covered_by_delta"], effect_diff=_seen.get("diff", ""),
                                     constructs=_seen.get("constructs", ()),
                                     witnesses=tuple(getattr(_seen.get("fbk"), "witnesses", ())),
                                     unpinned=_fb_report["unpinned_witnesses"],
                                     superseded=_fb_report["superseded_by_delta"], **_fb_kw)
        _fb_report["written_feedback_ids"] = [Path(p).stem for p in paths]
    try:
        with _account_once.once():  # derive, _declare and effect.declare share ONE account build
            pr = run_pipeline(
                args.repo, None if args.patch is not None or operator_proposer is not None else worker_argv, timeout=args.timeout,
                proposer_id=(operator_proposer.model_id if args.proposer_command else args.proposer_id),
                worker_ro=tuple(args.worker_ro),
                derive=_derive_capture,
                declare=_declare,
                after_gate=_after_gate,
                approve_deltas=args.approve_deltas, patch=pipeline_patch, manifest_bytes=pipeline_manifest,
                layer1=args.layer1 == "langgraph",
                thread_store=(args.thread_store or _l1_default_store()) if args.layer1 == "langgraph" else None,
                proposer=operator_proposer,
                prepared_run=_prepared_run,
            )
    except RuntimeBoundary as e:
        print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
        _phases.set_sink(None)
        if _emitter is not None:
            _emitter.close_run(None, EXIT_BOUNDARY)
        return EXIT_BOUNDARY
    run, obligations, decision, rec = pr
    if _fb_report["loaded_feedback_ids"] and obligations is not None:  # review/design review: per-run counterfactual, never the verdict
        _fb_report["feedback_effect"] = _feedback.feedback_effect(obligations, _fb_report["loaded_feedback_ids"])
    g = run.graph
    run_info = {
        "run_id": _run_id,
        "thread_id": None if g is None else g.thread_id,
        "checkpoint_id": None if g is None else g.final_checkpoint_id,
        "base_commit_sha": _base_commit,
        "base_tree_sha256": run.base_tree,  # git tree object id (40/64 hex) == target.base_tree
        "started_at_utc": _started,
        "loaded_feedback_ids": list(_fb_report["loaded_feedback_ids"]),
    }
    acct_block, side = account_block(run.effect.patch_sha256, _acct["dict"],
                                     _acct["error"] or (None if run.observed else "no observed change"), args.artifact_out,
                                     no_change=not run.observed and _acct["dict"] is None and _acct["error"] is None,
                                     index_cache_stats=_acct.get("stats"))
    art = build_artifact(run, obligations, decision, rec, feedback=_fb_report, confirmation=pr.confirmation,
                         run_info=run_info, effect_account=acct_block)
    _snap = _phases.snapshot()
    art["timings"] = _snap  # informational, optional schema key; never read by the gate
    _tp = _observed_target_python()
    if _tp is not None:  # informational, optional schema key; never read by the gate; absent when no confined evaluator reported (never inferred)
        art["target_python"] = _tp
    if side is not None:
        side_rc = _write_generated_artifact(
            side[0], side[1], exit_status=decision.exit_status,
            parent_directory=_output_parent_directory(args, side[0]))
        if side_rc == EXIT_ARTIFACT_COPY:
            _phases.set_sink(None)
            if _emitter is not None:
                _emitter.close_run(decision.outcome.value, decision.exit_status)
            return side_rc
    artifact_rc = _write_generated_artifact(
        args.artifact_out, (json.dumps(art, indent=2) + "\n").encode("utf-8"),
        exit_status=decision.exit_status,
        parent_directory=_output_parent_directory(args, args.artifact_out))
    _phases.set_sink(None)
    if _emitter is not None:  # after the artifact exists: 'finished' is now distinguishable from 'lost'
        _emitter.close_run(decision.outcome.value, decision.exit_status)
    if artifact_rc == EXIT_ARTIFACT_COPY:
        return artifact_rc
    if run.observed and rec is not None and rec.manifest_blocked:
        what = "invalid" if rec.manifest_error else "missing"
        err = (rec.manifest_error or "no manifest was given").removeprefix("invalid: ")
        print(clean(f"manifest {what}: {err}") + "; fix it and re-run (delta fields: docs/OPERATOR.md step 3)")
    print(f"hlith: {decision.outcome.value} exit={decision.exit_status} patch={run.effect.patch_sha256[:12]}")
    print(report(art, decision.exit_status, args.artifact_out, _report_ctx(args, run, rec)))
    print(_phases.line(_snap))
    return decision.exit_status


if __name__ == "__main__":
    sys.exit(main())
