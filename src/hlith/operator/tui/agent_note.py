# SPDX-License-Identifier: Apache-2.0
"""The refusal note an operator hands to the agent that produced the change (operator spec 4.4: "Copy witness for the agent", "Copy the stop reason for the agent").

PURE and READ-ONLY: it composes text from fields the recorded artifact already carries and from nothing else. It decides nothing (the decision word comes from
``frame._decision``, the one outcome/exit-status mapping), approves nothing, lands nothing and runs nothing. Every dynamic string passes ``frame._clean`` (controls become
visible escapes), so a hostile witness cannot smuggle terminal or clipboard control bytes. Where the engine records no replay command the note says so; it never invents one.
"""

from __future__ import annotations

import os
import re
import shlex

from . import artifact_facts as af

MAX_BYTES = 8 * 1024  # an OSC 52 request must stay small; a note longer than this is truncated with an explicit marker, never silently
_KIND = {"REFUSED · REFUTED": "refuted", "REFUSED · NOT-DERIVED": "not-derived", "REFUSED · UNVERIFIED": "unverified"}
_MEANING = {
    "refuted": "For the input above the change behaves differently after the change than before it. It is a counterexample, not a list of every difference.",
    "not-derived": "No check ran on the part named above. Nothing was found wrong and nothing was found right.",
    "unverified": "The check could not reach a result. Nothing was refuted.",
}
_NEXT = {
    "refuted": "Revise the patch so this input behaves as it did before. If the difference is intended, declare it as an intended change in the engine's input. Then start a NEW check. Hlith has no override.",
    "not-derived": "Restructure the construct Hlith could not follow, or check the change another way, then start a NEW check.",
    "unverified": "Supply what the check lacked (for example a repository test that reaches the function), then start a NEW check.",
}


def _short(value, limit: int = 600) -> str:
    text = " ".join(af.clean(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def kind(artifact) -> str | None:
    """'refuted' | 'not-derived' | 'unverified' for a validated, consistent refusal that has something to hand to an agent; None otherwise (landed, boundary, unvalidated)."""
    if not isinstance(artifact, dict):
        return None
    errors = af.validation_errors(artifact)
    if errors:
        return None
    decision = af.decision(artifact, errors)
    word = _KIND.get(decision[0])
    if word is None or af.integrity_errors(artifact, decision):
        return None
    rows = [r for r in af.obligations(artifact) if str(r.get("verdict", "")).lower() != "held"]
    if not rows and not af.plain_blocking(artifact):
        return None  # neither an unheld obligation nor a recorded blocking cause: nothing to hand over
    if word == "refuted" and not any(r.get("witness") for r in rows):
        return None  # a refusal without a recorded witness has no witness to copy
    return word


def _files(artifact) -> str:
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    touched = effect.get("touched_files")
    names = [str(x) for x in touched] if isinstance(touched, list) and touched else []
    if not names:
        diff = effect.get("unified_diff")
        if isinstance(diff, str):
            names = list(dict.fromkeys(re.findall(r"^\+\+\+ b/(.+)$", diff, flags=re.M)))
    shown = ", ".join(_short(n, 120) for n in names[:6])
    return shown + (f" (+{len(names) - 6} more)" if len(names) > 6 else "")


def repo_path(context) -> str | None:
    """The operator's repository as an absolute path, from what the host really holds: the launch record's source_repo (a run started here), else an ABSOLUTE `repo.path` (the repository
    facts; once a recorded run is open that field is only a display label and is ignored), else a plain path given as `repo`. None when none of them is a path."""
    if not isinstance(context, dict):
        return None
    meta = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
    candidates = [meta.get("source_repo")]
    repo = context.get("repo")
    candidates += [repo.get("path")] if isinstance(repo, dict) else [repo]
    for c in candidates:
        if isinstance(c, (str, os.PathLike)) and os.path.isabs(os.fspath(c)):
            return os.fspath(c)
    return None


REPLAY_COMMAND_AVAILABLE = True  # `hlith replay RUN --obligation ID` is in the integrated CLI (operator/replay_cmd.py, 036447c0); False would hide the line again, a command that does not exist is never shown


def replay_line(artifact, row=None) -> tuple[str | None, str]:
    """(command, '') when the first REFUTED obligation can be replayed, else (None, reason). The command is shown ONLY when all hold: the CLI has it (REPLAY_COMMAND_AVAILABLE), the
    artifact records run.replay_context, and that obligation's row records a witness_call that is not truncated. The reason is one of those facts, said plainly; nothing is guessed."""
    if not isinstance(artifact, dict):
        return None, "no record"
    if row is None:
        row = next((r for r in af.obligations(artifact) if str(r.get("verdict", "")).lower() == "refuted" and r.get("witness")), None)
    if not row or row.get("verdict") != "refuted" or not row.get("witness"):
        return None, "no refuted obligation"
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    call = row.get("witness_call")
    if not isinstance(call, dict) or not call:
        return None, "not recorded: this record has no witness_call for the obligation"
    if "truncated" in call:
        return None, "truncated: the recorded witness call exceeded the size cap and cannot be replayed"
    if not isinstance(run.get("replay_context"), dict) or not run.get("replay_context"):
        return None, "not recorded: this record has no run.replay_context"
    if not REPLAY_COMMAND_AVAILABLE:
        return None, "this version of Hlith has no replay command yet"
    run_id = af.run_id(artifact)
    if run_id == "not recorded" or not row.get("id"):
        return None, "not recorded: the run id or obligation id is missing"
    return f"hlith replay {shlex.quote(af.clean(run_id))} --obligation {shlex.quote(af.clean(str(row['id'])))}", ""


def build(artifact, context=None) -> str | None:
    """The note, or None when this record has nothing to hand to an agent."""
    word = kind(artifact)
    if word is None:
        return None
    errors = af.validation_errors(artifact)
    decision = af.decision(artifact, errors)
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    run_id = af.run_id(artifact)
    exit_status = decision[2]
    lines = [f"Hlith refused this change: {word.upper()}" + (f" (exit {exit_status})" if exit_status is not None else "") + ".",
             f"Run {run_id}. Nothing was landed by this run."]
    base = run.get("base_commit_sha")
    if isinstance(base, str) and base:
        lines.append(f"Base commit {_short(base, 200)[:12]}")
    files = _files(artifact)
    if files:
        lines.append(f"Files in the change: {files}")
    lines.append("")
    rows = [r for r in af.obligations(artifact) if str(r.get("verdict", "")).lower() != "held"]
    for row in rows[:3]:
        lines.append(f"Obligation {_short(row.get('id', 'not recorded'), 160)} — {_short(row.get('verdict', 'not recorded'), 40).upper()}")
        if row.get("claim"):
            lines.append(f"  claim:   {_short(row['claim'])}")
        witness = row.get("witness")
        if witness:
            parsed = af.parse_witness(witness)
            if parsed:
                via, input_text, before, after = parsed
                lines += ["  witness (an input that behaves differently):", f"    input    {_short(input_text)}",
                          f"    before   {_short(before)}", f"    after    {_short(after)}", f"    found by {_short(via, 80)}"]
            else:
                lines.append(f"  witness: {_short(witness)}")
        if row.get("stop_reason"):
            lines.append(f"  stopped: {_short(row['stop_reason'])}")
    if len(rows) > 3:
        lines.append(f"  … {len(rows) - 3} more obligation(s) not shown here; the full record has them.")
    if not rows:  # e.g. an exit-11 record: the reason is the recorded blocking cause, not an obligation row
        for cause in (af.plain_blocking(artifact) or [])[:6]:
            lines.append(f"Recorded cause: {_short(cause)}")
    lines += ["", _MEANING[word], f"Next: {_NEXT[word]}"]
    repo = repo_path(context)
    if repo and run_id != "not recorded":
        lines.append(f"Read the full record (read-only): hlith inspect {run_id} --repo {shlex.quote(af.clean(os.fspath(repo)))}")
    if word == "refuted":
        command, why = replay_line(artifact)
        lines.append(f"Replay command: {command}" if command else f"Replay command: none ({why}).")
        repo_for_replay = repo_path(context)
        if command and repo_for_replay:
            # replay looks a bare run id up from the CURRENT directory's repository (replay_cmd._run_record): say where to run it
            lines.append(f"Run it from inside the repository {shlex.quote(af.clean(os.fspath(repo_for_replay)))} (a bare run id is looked up from the current directory's repository).")
    text = "\n".join(lines) + "\n"
    raw = text.encode("utf-8")
    if len(raw) > MAX_BYTES:
        text = raw[: MAX_BYTES - 64].decode("utf-8", "ignore").rstrip() + "\n[note truncated; the full record has the rest]\n"
    return text
