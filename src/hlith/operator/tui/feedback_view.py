# SPDX-License-Identifier: Apache-2.0
"""What the operator can see of L5 feedback on a Verdict: which stored records this run LOADED (and from which run), which it WROTE, the named limits, and, when the witness is a
pinned input, that the refusal went through stored feedback.

PURE and READ-ONLY, from RECORDED fields only (field names as the engine writes them, agreed with the inspect CLI):
  artifact["feedback"]["loaded_feedback_ids"] (list), ["loaded_source_runs"] ({feedback id: full source run id}), ["written_feedback_ids"] (list),
  artifact["feedback_limit"] (top-level; null in every real artifact seen, so treated as an opaque value: shown only when non-null),
  and, passed in by the host from the run's event file, every PROGRESS detail {"feedback_limit": "<text>"} (a string, at most 200 characters).
Ids are never shortened here (the Provenance page shows them whole). Wording stays neutral: a limit is a named limit, never an error, and an absence says what is absent.

New pipeline witnesses can link the stored inputs they used. Older artifacts retain a source-run-only description.
"""

from __future__ import annotations

import json

from . import artifact_facts as af

MAX_IDS = 12  # rows shown per list on the Provenance page; the rest are counted, never silently dropped


def _ids(value) -> list:
    return list(dict.fromkeys(str(x) for x in value if isinstance(x, str) and x)) if isinstance(value, list) else []


def facts(artifact) -> dict | None:
    """{'loaded', 'written', 'sources' (id -> run), 'runs' (distinct source runs of the loaded ids, in order)} or None when the artifact has no feedback section."""
    fb = artifact.get("feedback") if isinstance(artifact, dict) and isinstance(artifact.get("feedback"), dict) else None
    if fb is None or not any(k in fb for k in ("loaded_feedback_ids", "written_feedback_ids", "loaded_source_runs")):
        return None  # no feedback section (an empty `feedback: {}` is no section): nothing to show, no row
    loaded, written = _ids(fb.get("loaded_feedback_ids")), _ids(fb.get("written_feedback_ids"))
    raw = fb.get("loaded_source_runs") if isinstance(fb.get("loaded_source_runs"), dict) else {}
    sources = {i: str(raw[i]) for i in loaded if isinstance(raw.get(i), str) and raw.get(i)}
    return {"loaded": loaded, "written": written, "sources": sources, "runs": list(dict.fromkeys(sources.values()))}


def failures(artifact) -> list:
    """The artifact's own recorded post-gate feedback failures (`feedback_errors`). The gate decision stands either way; the screen must not read as a clean record."""
    raw = artifact.get("feedback_errors") if isinstance(artifact, dict) else None
    if not isinstance(raw, list):
        return []
    return [" ".join(x.split())[:240] for x in raw if isinstance(x, str) and x.strip()]


def failure_tag(artifact) -> str:
    """' · FEEDBACK FAILED' (landed) / ' · FEEDBACK NOT RECORDED' (refused), the same words as `hlith check` and labels.headline; '' when none was recorded."""
    if not failures(artifact):
        return ""
    return " · FEEDBACK FAILED" if artifact.get("outcome") == "landed" else " · FEEDBACK NOT RECORDED"


def failure_sentence(artifact) -> str:
    """One sentence for the Verdict's reason line; '' when no failure was recorded."""
    if not failures(artifact):
        return ""
    return ("Recording this run's feedback FAILED (p shows the recorded error): the decision stands, but later runs will not learn from this run.")


def summary(artifact) -> str | None:
    """One line, e.g. `loaded 3 from run-000000000000 · wrote 2`; None when the artifact has no feedback section."""
    f = facts(artifact)
    if f is None:
        return "recording FAILED" if failures(artifact) else None
    if f["loaded"]:
        runs = ", ".join(f["runs"]) if f["runs"] else "run not recorded"
        head = f"loaded {len(f['loaded'])} from {runs}"
    else:
        head = "none loaded"
    return head + (f" · wrote {len(f['written'])}" if f["written"] else " · none written") + (" · recording FAILED" if failures(artifact) else "")


def limits(artifact, context=None) -> list:
    """Every named L5 limit, in order, without duplicates: the artifact's top-level `feedback_limit` when non-null, then the event details the host collected."""
    out: list = []
    top = artifact.get("feedback_limit") if isinstance(artifact, dict) else None
    if top not in (None, "", [], {}):
        items = top if isinstance(top, list) else [top]
        out.extend(x if isinstance(x, str) else json.dumps(x, sort_keys=True, default=str) for x in items)
    extra = (context or {}).get("feedback_limits") if isinstance(context, dict) else None
    if isinstance(extra, list):
        out.extend(str(x) for x in extra if x not in (None, ""))
    return list(dict.fromkeys(" ".join(x.split())[:200] for x in out if x))


def worth_a_row(artifact, context=None) -> bool:
    """Feedback is shown on the Verdict only when it MATTERED to this run: records loaded or written, or a named limit. (Every run having `none loaded · none written` would be noise.)"""
    f = facts(artifact)
    return bool(f and (f["loaded"] or f["written"])) or bool(limits(artifact, context)) or bool(failures(artifact))


def pinned_note(artifact, obligation=None) -> str | None:
    """When the refusing obligation's witness is a PINNED input and this run loaded stored feedback: say so, naming the run(s), never one record."""
    f = facts(artifact)
    if f is None or not f["loaded"] or not isinstance(artifact, dict):
        return None
    for row in af.obligations(artifact) if obligation is None else (obligation,):
        if str(row.get("verdict", "")).lower() == "refuted":
            call = row.get("witness_call") or {}
            ids = _ids(call.get("feedback_record_ids")) if isinstance(call, dict) else []
            if ids and all(i in f["loaded"] for i in ids):
                records = ", ".join(i + (" from " + f["sources"][i] if i in f["sources"] else "") for i in ids)
                if call.get("oracle") == "recorded-expected":
                    oracle = "recorded expectation vs current patch"
                elif call.get("oracle") == "declared-delta":
                    oracle = "declared outcome vs current patch"
                elif call.get("oracle") == "feedback-neighbor":
                    oracle = "boundary neighbor of stored input (current base vs current patch)"
                else:
                    oracle = "current base vs current patch"
                return f"Stored input used for {oracle}: {records}."
            parsed = af.parse_witness(row.get("witness")) if row.get("witness") else None
            if parsed and parsed[0] in ("pinned", "pinned-neighbor"):
                runs = ", ".join(f["runs"]) if f["runs"] else "a run that is not recorded"
                return f"Refused through a pinned input. Stored feedback was loaded from {runs}; the witness does not say which record it came from."
    return None


def provenance_rows(artifact, context=None) -> list:
    """[label, value] rows for the Provenance page: the summary, every loaded id with its source run, every written id, every limit, the pinned note. Whole ids, wrapped by the
    page; lists beyond MAX_IDS are counted."""
    f = facts(artifact)
    if f is None:
        return [["feedback", "recording FAILED"], *[["fb failed", e] for e in failures(artifact)[:3]]] if failures(artifact) else []
    rows = [["feedback", summary(artifact)]]
    rows.extend(["fb failed", e] for e in failures(artifact)[:3])
    for label, ids in (("loaded", f["loaded"]), ("written", f["written"])):
        for i in ids[:MAX_IDS]:
            rows.append([label if i == ids[0] else "", i + (f" ← {f['sources'][i]}" if label == "loaded" and i in f["sources"] else "")])
        if len(ids) > MAX_IDS:
            rows.append(["", f"+ {len(ids) - MAX_IDS} more"])
    for text in limits(artifact, context):
        rows.append(["fb limit", text])
    note = pinned_note(artifact)
    if note:
        rows.append(["note", note])
    return rows
