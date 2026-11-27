# SPDX-License-Identifier: Apache-2.0
"""ObligationApi (contract.capabilities): verify(account, feedback, base, post, target) -> VerifiedEffect.

Consumes the SUPPLIED EffectAccount and the sealed base/post snapshots; never rebuilds the account and never touches
the target. Issues the VerificationRecord through the VerificationIssuer capability. Intent (O3) is part of the
engine's construction for resume-safe defaults. Optional per-call progress is informational and never contributes to a verdict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Sequence

from ..contract.capabilities import SealedSnapshot, VerificationIssuer, VerifiedEffect
from ..contract.effects import EffectAccount
from ..contract.errors import BoundaryReason, Refusal, RefusalError
from ..contract.feedback import FeedbackInput
from ..contract.guards import ExportedGuardCatalog
from ..contract.identities import TargetIdentity
from ..contract.legacy import Obligation, ObligationSet, Verdict
from ..contract.obligations import RequiredScope
from ..hostio.confinement import ConfinementBoundaryError
from . import consumption, facts as _facts, issue, scope
from .feedbackview import FeedbackView
from .intent import IntentDeclaration, apply_intent


def surviving_witnesses(witnesses: dict, obligations: Sequence[Obligation], account_sha256: str) -> tuple:
    """Witnesses of the final obligation set: one per symbol that still has a REFUTED obligation, tagged with the account digest."""
    refuted = {o.target_symbol for o in obligations if o.verdict is Verdict.REFUTED}
    return tuple({**w, "symbol": sym, "account_sha256": account_sha256}
                 for sym, w in witnesses.items() if isinstance(w, dict) and sym in refuted)


def ann_admits(annotation: str | None, value) -> bool:
    """Public L3 domain predicate used by L5 probes so probe inputs match the differential gate's exact domain."""
    from .. import differential

    return differential._ann_admits(annotation, value)


def explored_input_digest(value) -> str:
    """Public L3 input-digest helper used by L5 novelty ranking so digests match differential.explored_inputs."""
    from .. import differential

    return differential.explored_input_digest(value)


class ObligationEngine:
    """Implements contract.capabilities.ObligationApi."""

    def __init__(self, issuer: VerificationIssuer, *, intent: IntentDeclaration | None = None, python: str | None = None,
                 extra_sys_path: Sequence[str] = (), proposer_paths: Sequence[str] = (),
                 differential_timeout: float = 600.0, adequacy_gate: bool | None = None, issuer_name: str = "l3-controller") -> None:
        from .. import derive as _derive  # the derivation core (moves under obligation/ in its own commit)

        self._issuer = issuer
        self._intent = intent or IntentDeclaration()
        self._issuer_name = getattr(issuer, "issuer_id", None) or issuer_name  # the capability names itself: body and signed record must agree
        self._derive = _derive.make_derive(proposer_paths=tuple(proposer_paths), extra_sys_path=tuple(extra_sys_path),
                                           target_python=python, differential_timeout=differential_timeout,
                                           feedback=None, adequacy_gate=adequacy_gate)

    _witnesses: tuple = ()

    def observed_witnesses(self) -> tuple:
        """The refuting calls the checkers observed in the LAST verify (each carries ``account_sha256``); never proposer input."""
        return self._witnesses

    # ------------------------------------------------------------------------------------------------ public
    def verify(self, account: EffectAccount, feedback: FeedbackInput, base: SealedSnapshot, post: SealedSnapshot,
               target: TargetIdentity, *, intent: IntentDeclaration | None = None,
               guard_catalog: ExportedGuardCatalog | None = None,
               progress: Callable[[str, int, int], None] | None = None) -> VerifiedEffect:
        active_intent = self._intent if intent is None else intent
        self._check_identity(account, base, post)
        self._witnesses = ()  # reset per verify: a witness never outlives the account it was observed for
        fview = FeedbackView(feedback, account=account)
        view = None
        try:
            view = _facts.build(account, Path(base.path), Path(post.path))
            try:
                conf = active_intent.confirmation()
                deltas_approved = bool(conf is not None and conf.matched)
            except Exception:  # noqa: BLE001
                deltas_approved = False
            core_kwargs = dict(
                touched_files=view.touched_files, deltas=active_intent.deltas, acct=view, ad=view.to_dict(),
                fbk=fview, base_dir=Path(base.path), post_dir=Path(post.path),
                has_diff=bool(view.touched_files),
                contract_account=account,
                guard_catalog=guard_catalog,
                deltas_approved=deltas_approved,
            )
            if progress is not None:
                def safe_progress(name: str, index: int, total: int) -> None:
                    try:
                        progress(name, index, total)
                    except Exception:  # noqa: BLE001 - progress is informational and cannot affect a verdict
                        pass

                core_kwargs["progress"] = safe_progress
            core = self._derive.core(**core_kwargs)
            obligations, evidence = tuple(core.obligations), tuple(core.evidence)
        except RefusalError:
            raise
        except ConfinementBoundaryError as e:
            raise RefusalError(
                Refusal.BOUNDARY,
                f"{BoundaryReason.CONFINEMENT_UNAVAILABLE.value}: {e.reason}",
            ) from e
        except Exception as e:  # an engine failure is a named refusal, never a crash into a pass
            obligations = (Obligation("verification-failed", "*", "the checkers ran to completion", Verdict.NOT_DERIVED,
                                      stop_reason=f"{type(e).__name__}: {e}"[:300]),)
            evidence = ()
        obligations = apply_intent(obligations, active_intent)
        # checker-observed refuting calls, bound to THIS account, only for symbols that are STILL refuted after the derivation and
        # intent (an approved delta that covers a refutation must not become a pin: review review finding 2)
        self._witnesses = surviving_witnesses(fview.witnesses, obligations, str(account.account_sha256))
        account_symbol_files = (tuple((m.qualified_name, m.file_path) for m in view.modified_callables)
                                if view is not None else ())
        obligations, records = consumption.bind(
            obligations, account, view.site_attribution if view is not None else None,
            account_symbol_files=account_symbol_files,
        )
        if not obligations:  # the nonempty invariant is structural; this is the last line
            obligations = (Obligation("no-obligation", "*", "an obligation was derived", Verdict.NOT_DERIVED,
                                      stop_reason="no obligation could be derived for this effect"),)
        required = RequiredScope.from_account(account)
        discharged = scope.discharge(
            account, obligations, records,
            view.enclosing if view is not None else (lambda filename, line_no: None),
        )
        ctx, checker_ids = issue.checker_identity()
        oset = ObligationSet(obligations, issue.plain_evidence(evidence))  # the SAME object the gate recomputes the digest from
        body = issue.build_body(account=account, target=target, required=required, discharged=discharged,
                                obligation_set=oset, consumption=records, context_identity=ctx,
                                checker_ids=checker_ids, issuer=self._issuer_name)
        record = issue.issue(self._issuer, body)
        return VerifiedEffect(obligations=oset, record=record,
                              required_scope=required, scope_discharge=discharged)

    # ------------------------------------------------------------------------------------------------ internals
    @staticmethod
    def _check_identity(account: EffectAccount, base: SealedSnapshot, post: SealedSnapshot) -> None:
        if account.base_tree_oid != base.tree_oid:
            raise RefusalError(Refusal.BOUNDARY, BoundaryReason.BASE_TREE_MISMATCH.value)
        if account.post_tree_oid != post.tree_oid:
            raise RefusalError(Refusal.BOUNDARY, BoundaryReason.POST_TREE_MISMATCH.value)
