# SPDX-License-Identifier: Apache-2.0
"""Readable operator summary of a hlith artifact (used by operator surfaces)."""

from __future__ import annotations

import re
from pathlib import Path

from ..textsafe import clean, inspect

MEANING = {
    "held": "checked and it held",
    "refuted": "a concrete counterexample was found (witness shown)",
    "not-derived": "hlith could not derive what to check; strict V1 refuses",
    "unverified": "could not be confirmed (missing evidence, declaration or approval)",
}

def _one(text, n: int = 170, strict: bool = False) -> str:
    """One line of untrusted text; strict (witnesses): every combining mark, non-ASCII space and astral code point is escaped
    so two different inputs never look alike (textsafe.inspect)."""
    return " ".join((inspect(text) if strict else clean(text)).split())[:n]


ACCOUNT_PREFIX = "effect account could not be built"


def account_failure(art: dict) -> str | None:
    """The reason text when hlith could not build the effect account (a Hlith defect or an unsupported file), else None."""
    for o in art.get("obligations") or []:
        if o.get("id") == "account-failed":
            why = str(o.get("stop_reason") or "")
            return why.split(": ", 1)[1] if why.startswith(ACCOUNT_PREFIX) and ": " in why else (why or "unknown reason")
    return None


def account_failure_text(reason: str) -> str:
    if "unified diff does not apply" in reason:  # the operator's input, not a Hlith defect: say what to do (found by the agent-stranger run)
        return ("the diff does not apply to the repository you gave: it probably already contains this change (an agent's uncommitted edit) or differs from the diff's base. "
                "Export the edit with `git diff > change.patch` and pass a clean clone at the commit the diff was made from as --repo")
    m = re.search(r"([\w./-]+\.py)\b", reason)
    where = f" for {m.group(1)}" if m else ""
    if m and reason.startswith(m.group(1) + ": "):
        reason = reason[len(m.group(1)) + 2:]  # review's format '<file.py>: <Error>: <msg> (line n)': the file is already in `where`
    return (f"the effect account could not be built{where}: {reason}; this is a Hlith defect or an unsupported file, "
            "not your manifest. Nothing in your patch or manifest needs fixing for this; report it with the artifact")


def _next_step(o: dict, ctx: dict) -> str:
    """ONE actionable next step for a blocking obligation (a command where one exists)."""
    oid, verdict = o["id"], o["verdict"]
    why = str(o.get("stop_reason") or "")
    if ctx.get("account_failure") and (oid == "account-failed" or oid == "effect-declared-vs-observed" and verdict != "refuted" and not ctx.get("manifest_hint")):
        if oid == "effect-declared-vs-observed":
            return "same cause as the account-failed line above (a Hlith defect or an unsupported file): not your manifest"
        return account_failure_text(ctx["account_failure"])
    if oid == "effect-declared-vs-observed":
        if verdict == "not-derived":
            return ("Hlith cannot model this change (a limit of the checker, not a defect in your change): nothing was compared and nothing is refuted; "
                    "the file(s) named above are outside what the effect account can represent")
        if verdict == "refuted":
            return "claim violation: the change touches something the manifest / effect account does not declare: add it to the manifest or remove it from the patch"
        return ctx.get("manifest_hint") or "fix the manifest (delta fields: docs/OPERATOR.md step 3) and re-run the same command"
    if oid == "deltas-confirmed":
        if ctx.get("contradicted"):
            return f"do not approve: delta {', '.join(sorted(ctx['contradicted']))} is contradicted (see above); fix and re-run first"
        sha = ctx.get("delta_set_sha256")
        cmd = ctx.get("approve_cmd")
        if not sha:
            return "no declared deltas exist to approve; declare intended changes in a manifest or re-run without --approve-deltas"
        return (f"read effect.deltas in the artifact; if they are what you intend, re-run with approval: {cmd}"
                if cmd else f"approve the delta set by re-running with --approve-deltas {sha}")
    m = re.search(r"declared delta (\S+) claims .* for (.+?) but post -> ", str(o.get("witness") or ""))  # may follow a search-phase prefix ("seed ", "pinned ", "collected ", ...)
    if oid.startswith("differential:") and verdict == "refuted" and m:
        did, call = m.group(1), m.group(2)
        return (f"the declared delta {did} is false at {call}: either fix the patch so post returns the declared value there, or "
                f"narrow the delta's predicate to exclude it (then re-run; approval is re-required since delta_set_sha256 changes). "
                f"Do NOT approve this delta set.")
    if oid.startswith("differential:") and verdict == "refuted":
        return ("inspect the witness and fix the patch; if the divergence is an intended behaviour change, "
                f"propose a delta for review: {ctx['propose_cmd']}" if ctx.get("propose_cmd") else
                "inspect the witness and fix the patch, or declare the intended change as a delta")
    if oid.startswith("differential:") and "no repository test reaches" in why:
        sym = oid.split(":", 1)[1]
        return (f"no repository test reaches {sym}; Hlith will not admit on differential evidence alone (policy), "
                "see docs/DECISION-F4.md")
    if oid.startswith("feedback-pins:"):
        return "an earlier refusal pinned this input and the new patch still differs on it: fix the patch"
    if "unified diff does not apply" in why:
        return ("the diff does not apply to the repository you gave: it probably already contains this change (an agent's uncommitted edit) or differs from the diff's base. "
                "Export the edit with `git diff > change.patch` and pass a clean clone at the commit the diff was made from as --repo")
    if oid == "verification-failed":
        return "a checker failed to run (not a construct in your change); read stop_reason and run hlith doctor --probe-target"
    if verdict == "not-derived":
        return "hlith will not guess what to check; remove or restructure the construct named in stop_reason"
    if oid.startswith("signature_binding:") and verdict == "refuted":
        return "a caller no longer binds to the new signature (witness): update the callers or keep the signature"
    return f"read obligation {oid} in the artifact"


DELTA_REL_NOTE = ("a delta_rel PROVED does not replace the repository test slice: it is advisory, non-gating "
                  "evidence about the declared delta only; every obligation above still decides the outcome.")


def delta_rel_lines(art: dict) -> list[str]:
    """Non-gating `delta_rel` entries (absent key: no lines). Never affects verdict or exit.
    Reasons and notes are printed IN FULL (assumption statements must never be cut), wrapped to the terminal."""
    import shutil
    import textwrap
    rel = art.get("delta_rel")
    if not rel:
        return []
    width = max(60, shutil.get_terminal_size((100, 24)).columns - 1)

    def wrap(first: str, text: str, indent: str) -> list[str]:
        return textwrap.wrap(" ".join(clean(text).split()), width=width, initial_indent=first, subsequent_indent=indent,
                             break_long_words=False, break_on_hyphens=False) or [first.rstrip()]

    out = ["delta_rel (advisory, non-gating):"]
    for r in rel if isinstance(rel, list) else []:
        out += wrap(f"  [{str(r.get('verdict')).upper()}] {r.get('symbol')}: ", r.get("reason") or "", "      ")
        if r.get("witness_inputs"):
            out += wrap("      witness_inputs: ", r["witness_inputs"], "          ")
        if r.get("fragment_notes") and r.get("verdict") != "PROVED":
            out += wrap("      covers: ", r["fragment_notes"], "          ")
    out += wrap("  note: ", DELTA_REL_NOTE, "        ")
    return out


def report(art: dict, rc: int, art_path: Path, ctx: dict | None = None) -> str:
    """Terminal output after every run: verdict line; per blocking obligation its witness or stop_reason,
    explored / unexplored (one line each) and one next step; approval note; exit semantics."""
    ctx = dict(ctx or {})
    obs = {o["id"]: o for o in art["obligations"]}
    ctx["contradicted"] = {m.group(1) for o in art["obligations"] if o.get("verdict") == "refuted"
                           for m in [re.search(r"declared delta (\S+) claims ", str(o.get("witness") or ""))] if m}
    af = account_failure(art)
    if af is not None:
        ctx["account_failure"] = af
    dsha = (art.get("effect") or {}).get("delta_set_sha256")
    if dsha:
        ctx.setdefault("delta_set_sha256", dsha)
    L = [f"verdict : {art['outcome'].upper()}  exit={rc}"
         + (f"  landed_commit={art['landed_commit'][:12]}" if art.get("landed_commit") else "  (nothing landed)")]
    if art.get("outcome") == "landed" and ctx.get("landing_note"):
        L.append("landing : " + clean(str(ctx["landing_note"])))  # a rehearsal landing is never presented as an original landing
    if ctx.get("origin_note"):
        L.append("input   : " + clean(str(ctx["origin_note"])))  # a supplied patch is never presented as an observed agent run
    graph = art.get("graph") or {}
    agent = graph.get("proposer") or {}
    if agent.get("command_argv_sha256"):
        L.append(f"agent: thread={graph.get('thread_id') or 'not recorded'}  argv_sha256={agent['command_argv_sha256']}  turns={agent.get('turns', 0)}")
        if agent.get("allow_unconfined"):
            L.append("agent warning: operator allowed an interpreter form; it runs code outside confinement")
        touched = (art.get("effect") or {}).get("touched_files") or []
        L.append("agent files: " + (clean(", ".join(touched[:12])) + (f" (+{len(touched) - 12} more)" if len(touched) > 12 else "") if touched else "none recorded"))
        if art.get("outcome") != "landed":
            L.append("agent refusal reasons: " + (clean(", ".join(art.get("blocking") or [])) or "not recorded"))
        if agent.get("redo_inflight"):
            L.append(f"agent retry: --redo-inflight repeated turn {agent.get('redone_turn')}")
    conf = (art.get("deltas") or {}).get("confirmation") or {}
    if conf.get("matched"):
        L.append("approval: deltas approved (sha256 %s). Approval is NOT a HELD verdict: it clears only deltas-confirmed; "
                 "every other obligation must still hold." % str(conf.get("delta_set_sha256"))[:16])
    sup: dict[str, int] = {}
    for x in (art.get("feedback") or {}).get("superseded_by_delta") or []:
        sup[str(x.get("delta_id"))] = sup.get(str(x.get("delta_id")), 0) + 1
    for did, n in sup.items():
        L.append(f"pins: {n} earlier pin(s) superseded by the approved delta {clean(did)} "
                 "(the delta covers the pinned input; the new behaviour is still checked by every other obligation)")
    for oid in art["blocking"]:
        o = obs.get(oid)
        if o is None:
            L.append(f"  blocking [?] {clean(oid)}")
            continue
        why = o.get("witness") or o.get("stop_reason") or o.get("claim") or ""
        L.append(f"  blocking [{o['verdict'].upper()}] {clean(oid)}: {_one(why, 220, strict=bool(o.get('witness')))}")
        ev = o.get("evidence") or {}
        if ev.get("explored"):
            L.append(f"      explored  : {_one(ev['explored'])}")
        if ev.get("unexplored"):
            L.append(f"      unexplored: {_one(ev['unexplored'])}")
        L.append(f"      next      : {_one(_next_step(o, ctx), 400)}")
    from .disclosure import annotation_bound

    held = [o for o in art["obligations"] if o.get("verdict") == "held"]
    note = annotation_bound(held)
    if note:  # keyed on the engine's own ANNOTATION-BOUNDED token (old sentence as fallback), shown even though one-line cuts drop the text
        L.append("held   : " + clean(note))
    L.extend(delta_rel_lines(art))
    L.append(f"artifact: {art_path}")
    L.append("exit codes: 0 landed | 10 refuted | 11 not-derived | 12 unverified | 4 boundary (docs/OPERATOR.md step 4)")
    return "\n".join(L)


# kept for callers that only want the short form
brief = report


def full(title: str, rc: int, art: dict, art_path: Path, errs: list) -> str:
    L = []
    w = L.append
    w("=" * 78)
    w(title)
    w("=" * 78)
    w(f"verdict      : {clean(str(art.get('outcome') or '-')).upper()}  exit={rc}  blocking={clean(str(art.get('blocking') or '-'))}"
      + (f"  landed_commit={clean(str(art['landed_commit']))[:12]}" if art.get("landed_commit") else "  (nothing landed)"))
    e = art.get("effect") or {}
    r = art.get("run") or {}
    ea = art.get("effect_account") or {}
    g = art.get("graph") or {}
    prov = next((p for p in (art.get("proposer_provenance") or ()) if isinstance(p, dict)), {})
    proposer = e.get("proposer_id") or prov.get("proposer_id") or prov.get("kind") or "-"
    w(f"effect       : patch_sha256={clean(str(e.get('patch_sha256') or '-'))[:16]}  proposer={clean(str(proposer))}  "
      f"files={clean(', '.join(e.get('touched_files') or ()) or '-')}")
    base_tree = r.get("base_tree_sha256") or r.get("base_tree_oid") or "-"
    w(f"provenance   : run={clean(str(r.get('run_id') or '-'))}  base_commit={clean(str(r.get('base_commit_sha') or '-'))[:12]}  "
      f"base_tree={clean(str(base_tree))[:12]}  at={clean(str(r.get('started_at_utc') or '-'))}")
    w(f"layer 1      : thread={clean(str(g.get('thread_id') or r.get('thread_id') or '-'))}  "
      f"interrupt_ckpt={clean(str(g.get('interrupt_checkpoint_id') or '-'))[:14]}  "
      f"final_ckpt={clean(str(r.get('checkpoint_id') or '-'))[:14]}  "
      f"resumed={g.get('resumed', 'n/a')}  payload_matches_observed={g.get('payload_matches_observed', 'n/a')}")
    acc = ea.get("account") if isinstance(ea.get("account"), dict) else ea
    ea_status = ea.get("status") or ea.get("analyzer_id") or "-"
    ea_id = ea.get("account_id") or "-"
    mods = [
        clean(str((m.get("qualified_name") or m.get("name") or m) if isinstance(m, dict) else m))
        for m in acc.get("modified_callables", ())
    ]
    sites = acc.get("impacted_call_sites") if "impacted_call_sites" in acc else acc.get("impacted_sites", ())
    w(f"effect acct  : {clean(str(ea_status))}  id={clean(str(ea_id))}  modified_callables={mods}  "
      f"impacted_call_sites={len(sites or ())}")
    fb = art.get("feedback") or {}
    w(f"feedback     : loaded={fb.get('loaded_feedback_ids') or '-'}  written={fb.get('written_feedback_ids') or '-'}")
    w("obligations  :")
    for o in art.get("obligations") or ():
        w(f"  - [{clean(str(o.get('verdict') or '-')).upper():11}] {clean(str(o.get('id') or '-'))}")
        if o.get("claim"):
            w(f"      claim      : {clean(o['claim'])[:160]}")
        if o.get("witness"):
            w(f"      witness    : {clean(o['witness'])[:300]}")
        if o.get("stop_reason"):
            w(f"      stop_reason: {clean(o['stop_reason'])[:300]}")
        ev = o.get("evidence")
        if ev:
            w(f"      explored   : {clean(str(ev.get('explored')))[:200]}  (executions={ev.get('executions')})")
            w(f"      unexplored : {clean(str(ev.get('unexplored')))[:200]}")
    for line in delta_rel_lines(art):
        w(line)
    w(f"artifact     : {art_path}  (schema: {'valid' if not errs else 'INVALID ' + str(errs[:3])})")
    return "\n".join(L)


