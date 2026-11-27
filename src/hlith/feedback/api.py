# SPDX-License-Identifier: Apache-2.0
"""Public L5 FeedbackApi implementation backed by HostState ``feedback/`` namespace."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..contract.capabilities import FeedbackApi, HostState, SealedSnapshot
from ..contract.effects import EffectAccount
from ..contract.feedback import FeedbackInput
from ..contract.identities import RunId
from ..contract.runs import GateReceipt
from ._legacy import FeedbackIntegrityError, cone_domain_seeds_for_targets, recurrent_constructs
from .probe import run_landing_probes, run_refusal_probes, supersessions_from_deltas
from .project import project_feedback_input
from .store import load_stored_records

# observe() keywords the SERVICE may carry for every probe it runs (design review P1-2): the target interpreter and the import paths the run's
# own checkers used. Anything else is a construction error: a misspelt key would otherwise silently probe under Hlith's interpreter.
OBSERVE_KW_KEYS = frozenset({"python", "extra_sys_path", "proposer_paths", "call_timeout"})


def _checked_observe_kw(observe_kw: dict[str, Any] | None) -> dict[str, Any]:
    kw = dict(observe_kw or {})
    unknown = sorted(set(kw) - OBSERVE_KW_KEYS)
    if unknown:
        raise ValueError(f"unknown Layer 5 observe keyword(s): {', '.join(unknown)} (allowed: {', '.join(sorted(OBSERVE_KW_KEYS))})")
    for key in ("extra_sys_path", "proposer_paths"):
        if key in kw:
            if isinstance(kw[key], (str, bytes)):
                raise TypeError(f"{key} must be a sequence of paths, not a single string")
            kw[key] = tuple(str(x) for x in kw[key])
    if kw.get("python") is None:
        kw.pop("python", None)  # None = Hlith's own interpreter (observe's default), never the string "None"
    return kw


@dataclass(frozen=True)
class LandingProbeContext:
    """Host-provided sealed base snapshot and metadata for ``post_landing_probe``."""

    repo_identity: str
    base: SealedSnapshot
    symbols: tuple[str, ...]
    probe_limit: int = 3
    deltas_confirmed: bool = False
    superseded: tuple[dict, ...] = ()
    # review/review seam 1: the validated, CONFIRMED delta set of the landing (only when deltas_confirmed; () = none). L5 uses it to tell
    # an approved base->landed divergence (domain input) from one OUTSIDE the approved domain (kept as a regression pin).
    approved_deltas: tuple[dict, ...] = ()
    # the landing happened in a REHEARSAL clone, not in the source repository whose store this is: its probe inputs are still true
    # evidence about this code (kept), but it must not record supersessions as if the source had landed the approved behaviour
    rehearsal: bool = False
    oracle_tests_by_symbol: dict[str, tuple[str, ...]] = field(default_factory=dict)
    observe_kw: dict[str, Any] = field(default_factory=dict)
    # design review 2026-11-21 (F2 route): symbol -> differential.read_explored_inputs(scratch) of the gate run that admitted this landing, so the
    # landing's domain record prefers inputs the gate never ran. Empty = UNKNOWN (largest-first, as before). Producer: the host.
    gate_explored: dict[str, dict] = field(default_factory=dict)
    # Provenance-bound exported-guard added callables (HELD exported-guard: obligation bound to this account and scope):
    # classified explicitly as non-production feedback targets so L5 does not probe them against base as production symbols
    # and discloses them on the named limits channel rather than a false missing-module-file error.
    excluded_guard_symbols: tuple[str, ...] = ()


class LocalFeedbackService(FeedbackApi):
    """L5 ``FeedbackApi`` implementation using local-first offline ``HostState``."""

    def __init__(
        self,
        host_state: HostState,
        *,
        required_record_ids: Sequence[str] = (),
        valid_landed_commits: set[str] | None = None,
        observe_kw: dict[str, Any] | None = None,
    ) -> None:
        """``observe_kw``: the run's target interpreter / extra sys.path / proposer paths (the same ones its checkers used). Applied to
        BOTH probe routes (refusal and post-landing) unless a call carries its own value for a key (design review P1-2: without it every L5
        probe ran under Hlith's own interpreter and could not import a module whose dependencies live only on --extra-sys-path)."""
        self._host_state = host_state
        self._observe_kw = _checked_observe_kw(observe_kw)
        self._required_record_ids = tuple(required_record_ids)
        self._valid_landed_commits = valid_landed_commits
        self._landing_contexts: dict[RunId, LandingProbeContext] = {}
        self._last_errors: list[str] = []
        self._last_limits: list[str] = []

    def drain_errors(self) -> tuple[str, ...]:
        """Genuine feedback failures of the last persist/probe call (a record could not be produced or written)."""
        out = tuple(self._last_errors)
        self._last_errors.clear()
        return out

    def drain_limits(self) -> tuple[str, ...]:
        """Named limits of the last persist/probe call (UNEXPLORED / UNPROBED inputs or symbols, domain decisions L5 did not make).
        Written records stay valid; these are disclosures, not recording failures."""
        out = tuple(self._last_limits)
        self._last_limits.clear()
        return out

    def _store_dir(self, repo_identity: str) -> Path:
        if not repo_identity:
            raise FeedbackIntegrityError("repo_identity must be non-empty")
        return self._host_state.namespace(repo_identity, "feedback")

    def register_landing_context(self, run_id: RunId, ctx: LandingProbeContext) -> None:
        self._landing_contexts[run_id] = ctx

    def load(
        self,
        repo_identity: str,
        symbols: tuple[str, ...],
        *,
        base_path: Path | None = None,
        callee_edges: Sequence[Any] = (),
    ) -> FeedbackInput:
        store_dir = self._store_dir(repo_identity)
        if base_path is None:
            stored = load_stored_records(
                store_dir,
                symbols,
                valid_landed_commits=self._valid_landed_commits,
            )
            return project_feedback_input(stored, required_record_ids=self._required_record_ids)
        all_stored = load_stored_records(
            store_dir,
            None,
            valid_landed_commits=self._valid_landed_commits,
        )
        sym_set = set(symbols)
        direct = tuple(item for item in all_stored if sym_set & set(item.record.target_symbols))
        donors, extra_seeds = cone_domain_seeds_for_targets(
            all_stored,
            symbols,
            base_path,
            callee_edges=callee_edges,
        )
        return project_feedback_input(
            direct,
            required_record_ids=self._required_record_ids,
            donor_records=donors,
            extra_seeds=extra_seeds,
        )

    def recurrent_constructs(self, repo_identity: str, constructs: tuple[dict, ...]) -> list[dict]:
        """Return non-blocking recurrence facts for current account constructs."""
        stored = load_stored_records(
            self._store_dir(repo_identity),
            None,
            valid_landed_commits=self._valid_landed_commits,
        )
        return recurrent_constructs((item.record for item in stored), constructs)

    def supersessions(self, repo_identity: str, approved_deltas: Sequence[dict], tree: Path) -> tuple[dict, ...]:
        """SIDE-EFFECT-FREE (seam 1 / review FB-ADV-1): the stored pins a CONFIRMED delta set supersedes, as
        {fb_id, delta_id, delta_set_sha256} entries (parameter names read from ``tree``). Nothing is written: post_landing_probe
        derives and appends the same entries itself when LandingProbeContext.approved_deltas is set, after a successful landing."""
        return tuple(supersessions_from_deltas(self._store_dir(repo_identity), approved_deltas, Path(tree)))

    def persist_refusal(self, receipt: GateReceipt, account: EffectAccount, evidence: dict) -> tuple[str, ...]:
        self._last_errors.clear()
        self._last_limits.clear()
        repo_identity = str(evidence.get("repo_identity") or "")
        store_dir = self._store_dir(repo_identity)
        evidence = {**evidence, "observe_kw": {**self._observe_kw, **_checked_observe_kw(evidence.get("observe_kw"))}}
        return run_refusal_probes(store_dir, receipt, account, evidence, errors=self._last_errors, limits=self._last_limits)

    def post_landing_probe(self, receipt: GateReceipt, landed: SealedSnapshot) -> tuple[str, ...]:
        self._last_errors.clear()
        self._last_limits.clear()
        ctx = self._landing_contexts.pop(receipt.run_id, None)
        if ctx is None:
            raise FeedbackIntegrityError(f"missing LandingProbeContext for run {receipt.run_id}")
        store_dir = self._store_dir(ctx.repo_identity)
        return run_landing_probes(
            store_dir,
            receipt,
            ctx.base,
            landed,
            symbols=ctx.symbols,
            excluded_guard_symbols=ctx.excluded_guard_symbols,
            probe_limit=ctx.probe_limit,
            deltas_confirmed=ctx.deltas_confirmed,
            approved_deltas=ctx.approved_deltas,
            rehearsal=ctx.rehearsal,
            superseded=ctx.superseded,
            oracle_tests_by_symbol=ctx.oracle_tests_by_symbol,
            observe_kw={**self._observe_kw, **_checked_observe_kw(ctx.observe_kw)},
            errors=self._last_errors,
            limits=self._last_limits,
            gate_explored=dict(ctx.gate_explored),
        )


def stored_records(host_state: HostState, repo_identity: str) -> tuple:
    """READ-ONLY: every intact, non-superseded feedback record the PIPELINE stored for ``repo_identity`` (host state ``feedback``
    namespace), for operator displays. The legacy per-repo store under the UI state is never written by the pipeline (design plan),
    so a display reading it shows nothing for current runs. Returns ``StoredRecord`` items; writes nothing."""
    store_dir = host_state.namespace(repo_identity, "feedback")
    return tuple(load_stored_records(store_dir, None))
