# SPDX-License-Identifier: Apache-2.0
"""``hlith inspect`` and ``hlith annotate``: headless, curses-free evidence inspection and Glass Box annotations.

Both are clients of the operator session API. ``inspect`` shows the recorded decision (or an honest non-decision state),
the linked ids, the evidence the artifact carries (witness, stop reason, explored / unexplored scope) and, SEPARATELY,
progress events. Nothing is computed, upgraded or softened. ``annotate`` appends an annotation-only receipt; it never
changes a decision and is never read by the gate.
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

from ..contract.errors import EXIT_BOUNDARY, EXIT_USAGE
from ..textsafe import clean
from .disclosure import checker_summary, effect_rows

ENVELOPE_INSPECT = "hlith.inspect/1"


def add_parsers(sub):
    ins = sub.add_parser("inspect", help="show the recorded decision, evidence and progress of one run (run id, run directory or artifact file); read-only")
    ins.add_argument("target", help="a run id (run-xxxxxxxxxxxx, searched in --repo's store), a run directory, or an out.json artifact")
    ins.add_argument("--repo", type=Path, default=None, help="repository whose run store holds a bare run id (default: the current directory's repository)")
    ins.add_argument("--json", action="store_true", help=f"machine output in the versioned envelope {ENVELOPE_INSPECT}")
    for name, text in (("quarantine", "record that you quarantined a refused run (annotation-only: the decision is unchanged)"),
                       ("escalate", "record that you escalated a run for manual review (annotation-only: the decision is unchanged)")):
        q = sub.add_parser(name, help=text)
        q.add_argument("run", help="run id or run directory")
        q.add_argument("--repo", type=Path, default=None, help="repository whose run store holds a bare run id (default: current directory)")
        q.add_argument("--note", default="", help="optional operator note stored in the annotation receipt")
    an = sub.add_parser("annotate", help="append an annotation-only operator receipt to a run (never overrides a decision; the gate never reads it)")
    an.add_argument("run", help="run id or run directory")
    an.add_argument("--repo", type=Path, default=None, help="repository whose run store holds a bare run id (default: current directory)")
    an.add_argument("--action", choices=["inspected", "quarantined", "escalated", "note"], default="note",
                    help="annotation action kind (default: note)")
    an.add_argument("--note", default="", help="optional operator note stored in the annotation receipt")
    return ins, an


def _repo(arg) -> Path:
    if arg is not None:
        return Path(arg).expanduser().resolve()
    from .tui import gitq

    root, _why = gitq.toplevel(Path.cwd())
    return root or Path.cwd()


def _resolve(api, target: str, repo_arg) -> tuple[Path | None, str | None]:
    """(run_dir or artifact file, problem)."""
    p = Path(target).expanduser()
    if p.exists():
        return p.resolve(), None
    if re.fullmatch(r"run-[0-9a-f]{12}", target):
        d = api.find(_repo(repo_arg), target)
        if d is not None:
            return d, None
        return None, f"no run {target} in the operator store for this repository"
    return None, f"not a run id, run directory or artifact file: {clean(target)[:120]}"


def _insp(api, path: Path):
    return api.inspect(path) if path.is_dir() else api.inspect_artifact_file(path)


def _obligation_rows(art: dict) -> list[dict]:
    rows = []
    obs = (art or {}).get("obligations")
    for o in obs if isinstance(obs, list) else []:
        if not isinstance(o, dict):  # a malformed record: the row is left out (the record is already reported schema-invalid)
            continue
        ev = o.get("evidence") if isinstance(o.get("evidence"), dict) else {}
        wc = o.get("witness_call") if isinstance(o.get("witness_call"), dict) else {}
        fb_ids = wc.get("feedback_record_ids") if isinstance(wc.get("feedback_record_ids"), list) else None
        row = {"id": o.get("id"), "verdict": o.get("verdict"), "claim": o.get("claim"), "witness": o.get("witness"),
               "stop_reason": o.get("stop_reason"), "explored": ev.get("explored"), "unexplored": ev.get("unexplored")}
        row["provenance"] = o.get("provenance") if isinstance(o.get("provenance"), dict) else None
        if wc:
            row["witness_call"] = wc
        if fb_ids:
            row["feedback_record_ids"] = [str(fid) for fid in fb_ids if isinstance(fid, str)]
        rows.append(row)
    return rows


def _delta_set(art: dict) -> dict | None:
    """The declared delta set and the digest a human approves (--approve-deltas), exactly as recorded; None when none was declared."""
    eff = (art or {}).get("effect") or {}
    if not eff.get("deltas") and not eff.get("deltas_error"):
        return None
    return {"delta_set_sha256": eff.get("delta_set_sha256"), "deltas": eff.get("deltas") or [], "error": eff.get("deltas_error")}


def _preamble(art: dict) -> dict | None:
    """The preamble strip recorded for this run's patch (operator edge), or None when nothing was removed / not recorded."""
    eff = (art or {}).get("effect") or {}
    n = int(eff.get("preamble_removed_bytes") or 0)
    if n <= 0:
        return None
    return {"removed_bytes": n, "input_patch_sha256": eff.get("input_patch_sha256"), "applied_patch_sha256": eff.get("patch_sha256")}


def _feedback(art: dict) -> dict:
    """Expose the artifact's raw feedback identities without compact-row abbreviations."""
    raw = art.get("feedback")
    fb = raw if isinstance(raw, dict) else {}
    return {
        "loaded_feedback_ids": fb.get("loaded_feedback_ids"),
        "loaded_source_runs": fb.get("loaded_source_runs"),
        "written_feedback_ids": fb.get("written_feedback_ids"),
    }


def _feedback_limit_events(events) -> list[dict]:
    """Keep every named feedback limit, including older ones outside the compact progress tail."""
    found = []
    for event in events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        if "feedback_limit" in detail:
            found.append({"seq": event.seq, "feedback_limit": detail["feedback_limit"]})
    return found


def _wrapped(text: str, *, width: int = 80, indent: str = "      ") -> list[str]:
    """Wrap at word boundaries while keeping complete identifiers and limit text."""
    return textwrap.wrap(text, width=width, subsequent_indent=indent,
                         break_long_words=False, break_on_hyphens=False) or [text]


def _detail_text(value) -> str:
    if isinstance(value, str):
        return clean(value)
    return clean(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _target_python_text(value) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("version"), str):
        return "version: not recorded"
    from .target_python import qualification

    executable = value.get("executable")
    implementation = value.get("implementation")
    observed_in = value.get("observed_in")
    qual = qualification(value["version"])
    parts = [
        f"effective path {clean(executable)}" if isinstance(executable, str) else "effective path not recorded",
        f"version: {clean(value['version'])}",
        f"implementation {clean(implementation)}" if isinstance(implementation, str) else "implementation not recorded",
        f"observed in {clean(observed_in)}" if isinstance(observed_in, str) else "observation source not recorded",
    ]
    if qual:
        parts.append(clean(qual))
    return " · ".join(parts)


def v_art_missing_rows(insp) -> bool:
    art = insp.view.artifact or {}
    return art.get("format") == 2 and "outcome" in art and "obligations" not in art


def payload(insp) -> dict:
    v = insp.view
    r = v.receipt
    art = v.artifact or {}
    return {
        "envelope": ENVELOPE_INSPECT,
        "run_id": v.run_id, "state": v.state.value, "headline": insp.label, "tone": insp.tone, "notes": list(insp.notes),
        "decision": None if v.artifact is None else {"outcome": art.get("outcome"), "exit_status": art.get("exit_status"),
                                                      "blocking": art.get("blocking"), "landed_commit": art.get("landed_commit")},
        "links": None if r is None else {"invocation_id": r.run.invocation_id, "thread_id": r.run.thread_id, "mode": r.run.mode.value,
                                         "landing_target": r.run.landing_target.value, "origin": r.origin.value},
        "delta_set": _delta_set(art),
        "effect_account": art.get("effect_account"),
        "verification_record_sha256": art.get("verification_record_sha256"),
        "preamble": _preamble(art),
        "domain_policy": (art.get("run") or {}).get("domain_policy") if isinstance(art.get("run"), dict) else None,
        "target_python": art.get("target_python") if isinstance(art.get("target_python"), dict) else None,
        "feedback": _feedback(art),
        "feedback_limit": art.get("feedback_limit"),
        "feedback_limit_events": _feedback_limit_events(insp.events),
        "obligations": _obligation_rows(art),
        "progress": [{"seq": e.seq, "kind": e.kind.value, "phase": e.phase.value if e.phase else None, "detail": e.detail} for e in insp.events],
        "progress_problems": list(insp.event_problems),
        "annotations": list(insp.annotations),
        "feedback_problems": list(v.feedback_problems),
        "errors": list(v.errors),
    }


def _render(insp) -> str:
    p = payload(insp)
    L = [f"{p['headline']}" + (f"   exit {p['decision']['exit_status']}" if p["decision"] and p["decision"]["exit_status"] is not None else ""),
         f"run {p['run_id'] or '-'}   state {p['state']}"]
    L.extend(_wrapped(f"target Python: {_target_python_text(p['target_python'])}", indent="    "))
    if p.get("domain_policy"):
        L.append(f"domain policy: {clean(str(p['domain_policy']))}")
    for label, value in effect_rows(p["effect_account"]):
        L.extend(_wrapped(f"{label}: {clean(value)}", indent="    "))
    L += [f"  {clean(n)}" for n in p["notes"]]
    if p["links"]:
        k = p["links"]
        L.append(f"linked: invocation {k['invocation_id']}  thread {k['thread_id'] or '-'}  mode {k['mode']}  target {k['landing_target']}  origin {k['origin']}")
    if v_art_missing_rows(insp):
        L.append("obligation rows: not recorded in this artifact (written before they were added); the decision above is the gate's")
    if p["preamble"]:
        pr = p["preamble"]
        L.append(f"preamble removed ({pr['removed_bytes']} bytes before the first 'diff --git'): input sha256 {str(pr['input_patch_sha256'])[:16]}, "
                 f"applied sha256 {str(pr['applied_patch_sha256'])[:16]} (the gate's identity chain uses the applied bytes)")
    ds = p["delta_set"]
    if ds:
        if ds["error"]:
            L.append(f"declared deltas rejected: {clean(str(ds['error']))} (nothing to approve)")
        else:
            L.append(f"declared delta set: {len(ds['deltas'])} delta(s) ({', '.join(clean(str(d.get('id'))) for d in ds['deltas'])})")
            L.append(f"  delta_set_sha256: {ds['delta_set_sha256']}")
            L.append("  a human approves exactly this set with --approve-deltas <sha>; approval is an authorization, never a HELD verdict")
    feedback = p["feedback"]
    loaded_raw = feedback["loaded_feedback_ids"]
    loaded_ids = loaded_raw if isinstance(loaded_raw, list) else []
    source_runs = feedback["loaded_source_runs"] if isinstance(feedback["loaded_source_runs"], dict) else {}
    written_raw = feedback["written_feedback_ids"]
    written_ids = written_raw if isinstance(written_raw, list) else []
    if loaded_raw is None:
        L.append("feedback: not recorded")
    elif not isinstance(loaded_raw, list):
        L.append("feedback loaded ids: invalid field type in artifact")
    elif not loaded_ids:
        L.append("feedback: none loaded")
    else:
        L.append("feedback loaded:")
        seen_sources = set()
        for fid in loaded_ids:
            fid_text = clean(str(fid))
            L.extend(_wrapped(f"  id: {fid_text}", indent="    "))
            source = source_runs.get(fid) if isinstance(fid, str) else None
            if source is not None:
                seen_sources.add(fid)
                L.extend(_wrapped(f"    loaded from run: {clean(str(source))}", indent="      "))
        # Preserve source-map entries even if a malformed/older record has no matching loaded id.
        for fid, source in source_runs.items():
            if fid not in seen_sources and fid not in loaded_ids:
                L.extend(_wrapped(f"  source for {clean(str(fid))}: {clean(str(source))}", indent="    "))
    if written_ids:
        L.append("feedback written ids:")
        for fid in written_ids:
            L.extend(_wrapped(f"  {clean(str(fid))}", indent="    "))
    elif written_raw is None:
        L.append("feedback written ids: not recorded")
    elif not isinstance(written_raw, list):
        L.append("feedback written ids: invalid field type in artifact")
    else:
        L.append("feedback written ids: none recorded")
    feedback_limits = []
    artifact_limit = p["feedback_limit"]
    if isinstance(artifact_limit, list):
        feedback_limits.extend(("artifact", value) for value in artifact_limit)
    elif artifact_limit is not None:
        feedback_limits.append(("artifact", artifact_limit))
    feedback_limits.extend((f"progress #{entry['seq']}", entry["feedback_limit"])
                           for entry in p["feedback_limit_events"])
    if feedback_limits:
        L.append("feedback limits:")
        for origin, value in feedback_limits:
            L.extend(_wrapped(f"  {origin}: {_detail_text(value)}", indent="    "))
    else:
        L.append("feedback limits: none recorded")
    if p["run_id"] and p["decision"] and p["decision"].get("outcome") == "refused":
        L.append(f"operator record (annotation-only, never a decision): hlith quarantine {p['run_id']} | hlith escalate {p['run_id']}")
    from .disclosure import annotation_bound

    bound = annotation_bound(p["obligations"])
    if bound and any(str(o.get("verdict")) == "held" for o in p["obligations"]):
        L.append("not checked: " + bound)
    if p["obligations"]:
        L.append("evidence:")
        for o in p["obligations"]:
            from .disclosure import tag

            bound = tag(o) if str(o["verdict"]) == "held" else None
            claim_line = f"  [{str(o['verdict']).upper()}] {clean(str(o['id']))}: {clean(str(o['claim'] or ''))}"
            if bound:
                claim_line += f"   <{clean(bound)}>"
            L.extend(_wrapped(claim_line, indent="      "))
            checker = checker_summary(o["provenance"]) or "not recorded"
            L.extend(_wrapped(f"      checker: {clean(checker)}", indent="        "))
            for key in ("witness", "stop_reason", "explored", "unexplored"):
                if o.get(key):
                    L.extend(_wrapped(f"      {key}: {clean(str(o[key]))}", indent="        "))
            if o.get("feedback_record_ids"):
                L.extend(_wrapped("      feedback_record_ids: " + ", ".join(clean(fid) for fid in o["feedback_record_ids"]), indent="        "))
    if p["progress"]:
        L.append("progress (phases and counters only; progress is not a verdict):")
        for e in p["progress"][-12:]:
            L.append(f"  #{e['seq']} {e['kind']} {e['phase'] or ''} {json.dumps(e['detail'], sort_keys=True) if e['detail'] else ''}".rstrip())
    for pr in p["progress_problems"]:
        L.append(f"  event problem: {clean(pr)}")
    if p["annotations"]:
        L.append("operator annotations (annotation-only; they never change the decision):")
        for a in p["annotations"]:
            L.append(f"  #{a.get('seq')} {a.get('ts', '')} {a.get('action')} by {clean(str(a.get('operator') or 'unrecorded'))} (local user claim) "
                     f"{clean(str(a.get('note') or ''))[:120]}" + ("" if a.get("chain_ok") else "   [CHAIN BROKEN]"))
    return "\n".join(L)


def execute_inspect(args, api=None) -> int:
    from .api import OperatorApi

    api = api or OperatorApi()
    path, problem = _resolve(api, args.target, args.repo)
    if path is None:
        print(f"hlith: {problem}", file=sys.stderr)
        return EXIT_USAGE
    insp = _insp(api, path)
    print(json.dumps(payload(insp), sort_keys=True) if args.json else _render(insp))
    return 0  # inspecting is not judging: the exit status is the tool's, never the run's verdict


def execute_named_annotation(args, action: str, api=None) -> int:
    """``hlith quarantine RUN`` / ``hlith escalate RUN``: the Glass Box Phase 2 verbs, as thin annotation-only commands."""
    args.action = action
    return execute_annotate(args, api)


def execute_annotate(args, api=None) -> int:
    from .api import OperatorApi
    from .receipts import Action, annotate

    api = api or OperatorApi()
    path, problem = _resolve(api, args.run, args.repo)
    if path is None or not path.is_dir():
        print(f"hlith: {problem or 'annotate needs a run id or run directory'}", file=sys.stderr)
        return EXIT_USAGE
    try:
        rec = annotate(path, Action(args.action), args.note)
    except OSError as e:
        print(f"hlith: boundary: {clean(str(e))}", file=sys.stderr)
        return EXIT_BOUNDARY
    print(f"annotation #{rec['seq']} {rec['action']} recorded (annotation-only: the decision is unchanged)")
    return 0
