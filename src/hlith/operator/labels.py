# SPDX-License-Identifier: Apache-2.0
"""One label/vocabulary source for every surface. Labels are LOOKED UP from the gate's own recorded outcome and exit status
(``contract.errors``); nothing here computes, upgrades or softens a verdict. Anything the record does not say is shown as
unknown. Landing target and input origin are stated wherever a landing is shown."""

from __future__ import annotations

from ..contract.errors import (
    EXIT_BOUNDARY, EXIT_BY_REFUSAL, EXIT_LANDED, EXIT_NOT_DERIVED, EXIT_REFUTED, EXIT_UNVERIFIED, Refusal,
)
from ..contract.runs import LandingTarget
from .remedy import remedy_for
from .store import InputOrigin, RunState, RunView

REFUSAL_WORD = {code: r.value.upper() for r, code in EXIT_BY_REFUSAL.items()}
TONE = {EXIT_REFUTED: "bad", EXIT_NOT_DERIVED: "warn", EXIT_UNVERIFIED: "warn", EXIT_BOUNDARY: "warn"}

# states that are not a gate decision at all: shown as what they are, never as a refusal or a landing
STATE_WORDS = {
    RunState.IN_PROGRESS: ("IN PROGRESS", "dim", "no decision yet; progress is not a verdict"),
    RunState.BOUNDARY_UNAVAILABLE: ("BOUNDARY UNAVAILABLE", "warn", "the engine refused before judging; no obligations were evaluated"),
    RunState.WITNESS_MISSING: ("WITNESS MISSING", "warn", "a refuting obligation names no witness; shown as recorded"),
    RunState.UNREADABLE: ("UNREADABLE", "dim", "the record cannot be read"),
    RunState.SCHEMA_INVALID: ("SCHEMA-INVALID RECORD", "dim", "the record does not match its schema"),
    RunState.ID_MISMATCH: ("RUN ID MISMATCH", "warn", "artifact and receipt disagree about the run id"),
    RunState.LOST: ("LOST", "dim", "the run ended without a recorded decision"),
    RunState.CLONE_FAILED: ("CLONE FAILED", "warn", "the disposable clone could not be made; nothing ran"),
    RunState.NO_RECORD: ("NO RECORD", "dim", "nothing is recorded for this run"),
}


def _is_status(x) -> bool:
    """A recorded exit status has the schema's type: an int, never a bool (True == 1), float (10.0 == 10), str or container."""
    return type(x) is int


def source_label(artifact, meta) -> str | None:
    """Prefer the engine's saved selection; older launches kept it only in metadata."""
    run = artifact.get("run") if isinstance(artifact, dict) else None
    for owner, key in ((run, "source_label"), (meta, "label")):
        value = owner.get(key) if isinstance(owner, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def decision(outcome, exit_status) -> tuple[str, str]:
    """(label, tone) from the recorded outcome + exit status only. Type-strict: a pair of the wrong types is UNKNOWN, never a
    LANDED/REFUSED word (``==`` alone would read False as 0 and 10.0 as 10) and never an exception (an unhashable status)."""
    if type(outcome) is str and _is_status(exit_status):
        return _decision_typed(outcome, exit_status)
    return f"UNKNOWN (outcome={outcome!r}, exit_status={exit_status!r})", "dim"


def _decision_typed(outcome: str, exit_status: int) -> tuple[str, str]:
    if outcome == "landed" and exit_status == EXIT_LANDED:
        return "LANDED", "good"
    if outcome == "refused":
        word = REFUSAL_WORD.get(exit_status)
        return (f"REFUSED · {word}" if word else f"REFUSED (exit {exit_status})"), TONE.get(exit_status, "warn")
    return f"UNKNOWN (outcome={outcome!r}, exit_status={exit_status!r})", "dim"


def _recorded(view: RunView, key: str) -> str | None:
    """A run fact from the receipt, else from the artifact's own ``run`` block (format 2 records mode/landing_target/origin itself, so a
    bare artifact file still says them); None when neither records it."""
    r = view.receipt
    if r is not None:
        return {"landing_target": r.run.landing_target.value, "origin": r.origin.value, "mode": r.run.mode.value}.get(key)
    run = (view.artifact or {}).get("run")
    v = run.get(key) if isinstance(run, dict) else None
    return str(v) if isinstance(v, str) and v else None


def target_note(view: RunView) -> str | None:
    """Where a landing happened. A rehearsal landing is NEVER an original landing; an unrecorded target is not guessed."""
    t = _recorded(view, "landing_target")
    if t is None:
        return "landing target not recorded (record predates the run receipt)"
    if t == LandingTarget.REHEARSAL.value:
        return "recorded target: rehearsal clone (no original landing is recorded)"
    return "original repository"


def origin_note(view: RunView) -> str | None:
    o = _recorded(view, "origin")
    if o is None or o == InputOrigin.UNKNOWN.value:
        return "input origin not recorded"
    if o == InputOrigin.SUPPLIED_PATCH.value:
        mode = _recorded(view, "mode")
        return f"patch supplied via {mode or 'an operator surface'}; not observed from a confined agent run"
    prov = (view.artifact or {}).get("proposer_provenance") or {}
    if prov.get("resumed_from") == "effect-interrupt" and not prov.get("command_argv_sha256"):
        return "resumed a parked effect interrupt through the gate; the proposer was not called again, and this resume is not claimed as E1"
    if prov.get("allow_unconfined") and str(prov.get("host_trust_reason") or "").startswith("E1 hosted agent CLI"):
        return ("proposed by a hosted coding-agent CLI (tools off) on a clean snapshot of an operator-attested public commit; "
                "the agent ran host-side, outside confinement; the confined worker applied its tool calls")
    if prov.get("allow_unconfined") and str(prov.get("host_trust_reason") or "").startswith("local stand-in"):
        return "proposed by a local stand-in program (plumbing trace only; not a model, not E1 evidence)"
    if prov.get("allow_unconfined"):
        return "produced by an unconfined local proposer (--allow-unconfined-proposer); it runs code outside confinement"
    return "produced by the confined local agent"


def agent_provenance_note(view: RunView) -> str | None:
    art = view.artifact or {}
    prov = art.get("proposer_provenance") or {}
    argv_sha = prov.get("command_argv_sha256") or prov.get("argv_sha256")
    if not argv_sha:
        return None
    thread = prov.get("thread_id") or (art.get("run") or {}).get("thread_id") or "not recorded"
    turns = prov.get("turns")
    parts = [f"agent: thread={thread}", f"argv_sha256={argv_sha}"]
    if turns is not None:
        parts.append(f"turns={turns}")
    if prov.get("redo_inflight"):
        parts.append(f"redo_inflight=true(turn={prov.get('redone_turn')})")
    return "  ".join(parts)


def feedback_notes(view: RunView) -> list[str]:
    """Post-gate feedback failures. The gate decision stands either way; the operator is told what did and did not happen and what to do."""
    if not view.feedback_problems:
        return []
    err = "; ".join(str(p)[:200] for p in view.feedback_problems[:3])
    landed = (view.artifact or {}).get("outcome") == "landed"
    if landed:
        return [f"landing completed; feedback recording/probe failed: {err}",
                "next: the change IS landed (see the landing target above); this run's feedback was not stored, so later runs will not learn from it. "
                "Check the feedback store for this repository (hlith inspect shows the run), fix the cause, and report it; do not re-land."]
    return [f"the refusal stands; recording its feedback failed: {err}",
            "next: later runs will not tighten on this refusal until its feedback is recorded. Fix the cause (feedback store permissions or "
            "integrity) and re-run the same change; the target was not touched."]


def headline(view: RunView) -> tuple[str, str, list[str]]:
    """(label, tone, notes). The label is the gate's recorded decision when there is one, else the honest non-decision state."""
    if view.state is RunState.FINISHED and view.artifact is not None:
        label, tone = decision(view.artifact.get("outcome"), view.artifact.get("exit_status"))
        notes = []
        if view.artifact.get("outcome") == "landed":
            notes.append(target_note(view) or "")
        notes.append(origin_note(view) or "")
        notes.append(agent_provenance_note(view) or "")
        hint = next((h for h in (remedy_for(b) for b in view.artifact.get("blocking") or []) if h), None) if _is_status(view.artifact.get("exit_status")) and view.artifact.get("exit_status") == EXIT_BOUNDARY else None
        if hint:
            notes.append("HINT: " + hint)
        fb = feedback_notes(view)
        if fb:
            label += " · FEEDBACK FAILED" if view.artifact.get("outcome") == "landed" else " · FEEDBACK NOT RECORDED"
            tone = "warn" if tone == "good" else tone
        return label, tone, [n for n in [*fb, *notes] if n]
    word, tone, why = STATE_WORDS[view.state]
    if view.state is RunState.BOUNDARY_UNAVAILABLE:
        hint = remedy_for(view.why or "")
        if hint:
            view.why = f"{view.why} HINT: {hint}"
    notes = [why, *view.errors]
    if view.why:
        notes.append(view.why)
    if view.state in (RunState.WITNESS_MISSING, RunState.SCHEMA_INVALID) and view.artifact is not None:
        # the recorded decision is still shown, labelled with what is wrong with the record; never hidden, never repaired
        label, tone2 = decision(view.artifact.get("outcome"), view.artifact.get("exit_status"))
        tag = "WITNESS MISSING" if view.state is RunState.WITNESS_MISSING else "UNVALIDATED"
        return f"{label} · {tag}", "warn" if tone2 == "good" else tone2, notes  # an invalid record is never shown with a GOOD tone
    return word, tone, notes


__all__ = ["decision", "headline", "target_note", "origin_note", "REFUSAL_WORD", "STATE_WORDS", "Refusal", "EXIT_BOUNDARY",
           "EXIT_UNVERIFIED", "EXIT_NOT_DERIVED", "EXIT_REFUTED"]
