"""Generate docs/ARTIFACT.md from src/hlith/hlith.schema.json. The doc cannot drift: field lists,
types, closedness, enums and descriptions come from the schema; the semantic notes below are keyed to schema names
and the generator FAILS if a top-level key, a documented record or an enum value has no note (or a note names
something the schema no longer has).

    python3 -I scripts/gen_artifact_doc.py            # print
    python3 -I scripts/gen_artifact_doc.py --write    # write docs/ARTIFACT.md
tests/test_artifact_doc.py fails when the committed doc differs from the generated one.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "src/hlith/hlith.schema.json"
OUT = ROOT / "docs/ARTIFACT.md"

# exit_status lattice (types.decide + cli): every schema enum value must have exactly one entry
EXIT = {
    0: ("landed", "every obligation HELD and at least one of them consumed the effect account (account_bound)"),
    10: ("refused: REFUTED", "at least one obligation REFUTED: a concrete witness (pre vs post) or a claim violation"),
    11: ("refused: NOT_DERIVED", "no REFUTED, at least one NOT_DERIVED: the checker could not derive or model "
         "something it needed (also: all HELD but none account-bound)"),
    12: ("refused: UNVERIFIED", "no REFUTED/NOT_DERIVED, at least one UNVERIFIED: a check could not run or ran out "
         "(empty impacted test slice, timeout, import failure); also a required proposer manifest missing/invalid"),
    4: ("boundary", "the run could not be confined or set up (sandbox, worker, argument errors): nothing was judged"),
}
VERDICT = {
    "held": "this obligation's bounded check found no difference on what it explored (see evidence.explored / "
            "unexplored). Per obligation, bounded: NOT a proof of the change",
    "refuted": "a witness exists: a concrete input with pre != post (witness), or a claim violation (the stage did "
               "something outside its own claim; labelled, not a behavioural witness)",
    "not-derived": "the checker's limit: it could not build or model the obligation (stop_reason names the construct)."
                   " Says nothing about the change being wrong",
    "unverified": "the check could not complete (stop_reason): not evidence either way",
}
INCIDENT_KIND = {
    "claim-violation": "the stage did something outside the claim (an account kind or the proposer manifest): REFUTED",
    "not-modelled": "only files the effect account has no record of: NOT_DERIVED, nothing compared",
    "unreconciled-missing-declaration": "a required declaration source (account or manifest) is missing",
    "undeclared-effect": "legacy (before the Rule C split); still valid in older artifacts, not emitted now",
}
PROOF_TIER = {
    "unconditional": "Z3 proof over the whole annotated domain with no unverified premise (numeric fragment)",
    "conditional": "UF mode: valid only under `assumptions`; never admits anything alone",
    "none": "COUNTEREXAMPLE or UNMODELED: nothing proved",
}
# top-level keys: (who reads it, what a UI may infer, what it may NOT infer)
TOP = {
    "outcome": ("gate (types.decide)", "landed vs refused, exactly as decided", "that landed means correct"),
    "exit_status": ("gate; scripts", "the lattice class (table above)", "severity beyond the class order"),
    "blocking": ("gate", "the obligation ids that stopped the landing, in obligation order", "a root cause ranking"),
    "landed_commit": ("git gate", "the commit created on landing (null when refused)", "that anything was pushed"),
    "effect": ("all layers", "the exact patch judged (unified_diff, touched_files, delta claims and their hash)",
               "intent beyond the declared deltas"),
    "worker": ("confinement layer", "the confined worker's exit and output, profile hash, risk flags",
               "that a quiet worker was harmless (see target)"),
    "target": ("confinement layer", "base tree identity and whether the worker left the target untouched", "-"),
    "incident": ("gate Rule C", "a declared-vs-observed mismatch and its kind", "a behavioural witness"),
    "obligations": ("gate (the ONLY input to decide())", "per-claim verdicts with witness/stop_reason/evidence",
                    "that HELD obligations cover what their evidence.unexplored lists"),
    "deltas": ("differential, Layer 5", "which intended changes were claimed, advisory or confirmed",
               "that a claim is true (only confirmed predicate+expected deltas can cover a divergence)"),
    "graph": ("Layer 1 (opt-in)", "LangGraph checkpoint/interrupt facts of the run", "anything when null"),
    "effect_account": ("derive, gate Rule C", "the static account of what the patch touches (hash-bound)",
                       "behaviour: the account is syntax and resolution, not execution"),
    "run": ("Layer 5, operator", "run/thread/checkpoint ids, base commit, loaded feedback ids", "-"),
    "delta_rel": ("nobody gating: decide() never reads it", "advisory Z3 evidence per modified callable",
                  "admission: a PROVED never replaces the test slice or the differential"),
    "timings": ("nobody gating: decide() never reads it", "phase wall-clock seconds of this run",
                "performance of another run or machine"),
    "target_python": ("nobody gating: decide() never reads it", "the interpreter the confined differential worker reported about itself (executable, version, implementation)",
                      "an interpreter that was only requested or only probed on the host (absent when no confined evaluator started)"),
    "feedback": ("Layer 5", "records loaded into and written by this run",
                 "that a refusal's pins are learning (they are refusal memory, not learning evidence)"),
}
TOP_SUBNOTES = {
    "graph": (
        "`graph.proposer` on the local `--proposer-command` route records the thread id, turn count, and "
        "`command_argv_sha256` (SHA-256 of the exact argv array; the argv itself is not disclosed). "
        "`allow_unconfined=true` records use of `--allow-unconfined-proposer`, which permits interpreter "
        "inline-code or directory-switch forms and means the command runs code outside confinement; the "
        "terminal report repeats this warning. If `--redo-inflight` repeated a call whose completion was "
        "indeterminate, `redo_inflight=true` and `redone_turn` identify that operator-authorized retry. "
        "These fields describe provenance only: they do not affect effect accounting, obligations, or the gate."
    ),
}
# main nested records: $def name -> one-paragraph note
RECORDS = {
    "obligation": "One claim and its verdict. `witness` carries the REFUTED evidence (a call you can paste: input, "
                  "pre outcome, post outcome; or the claim violation text); the schema does not forbid it on other "
                  "verdicts, so a UI must key on `verdict`, not on witness presence; `stop_reason` explains NOT_DERIVED / UNVERIFIED; `evidence` says what was "
                  "explored and, as important, what was NOT (`unexplored`).",
    "evidence": "Bounded exploration record: `explored` (strategies, counts) and `unexplored` (inputs, environment, "
                "channels not compared). A UI should always show `unexplored` next to a HELD.",
    "effect_account_report": "Wrapper around the account: `status` built|failed|no-change, hashes binding the account "
                             "(account_id/account_sha256), optional sidecar when large. `index_cache_provenance` sits "
                             "here, never inside the hashed account (cold vs warm counts).",
    "effect_account_dict": "The account itself (closed). Notable lists: `unresolved_constructs` (each may become a "
                           "NOT_DERIVED blocker), `opaque_caller_guards` (unchanged guards above checked call sites: "
                           "recorded, not blockers), `modified_module_level` (module-level imports/statements; post "
                           "rows link to a module_level_change blocker), `ast_equal_files` (formatting-only files).",
    "acct_opaque_caller_guard": "An unchanged unsupported entry guard dominating an impacted caller; every call site "
                                "below it is checked under both polarities, so it does not block.",
    "acct_module_level_record": "One AST-different module-level change: one row per imported name; a replaced "
                                "statement = pre+post rows sharing pair_id; source is cleaned and capped.",
    "acct_index_cache_provenance": "Cache hits vs uncached files for the account build (on the wrapper).",
    "feedback_report": "Layer 5 bookkeeping for this run: loaded ids (inputs), written ids (outputs), pins covered "
                       "or superseded by approved deltas, unpinned witnesses.",
    "timings_report": "Phase seconds and total. Non-gating, informational.",
    "delta_rel_item": "Advisory relational Z3 result for one modified callable: verdict PROVED|COUNTEREXAMPLE|"
                      "UNMODELED, `proof_tier` and `assumptions` (a conditional proof's premises). A COUNTEREXAMPLE "
                      "only seeds the differential; nothing here decides.",
    "incident": "Rule C detail: what the account and the manifest did not declare, and the incident kind.",
}
def shape(s, root):
    if s is True:
        return "any"
    if "$ref" in s:
        return s["$ref"].rsplit("/", 1)[-1]
    if "oneOf" in s:
        return " | ".join(shape(b, root) for b in s["oneOf"])
    if "const" in s:
        return f"const {json.dumps(s['const'])}"
    if "enum" in s:
        return "enum " + " | ".join(json.dumps(e) for e in s["enum"])
    t = s.get("type")
    t = " | ".join(t) if isinstance(t, list) else (t or "?")
    if t == "array" and "items" in s:
        return f"array of {shape(s['items'], root)}"
    if t == "object" and s.get("additionalProperties") is False:
        return "object (closed)"
    return t


def closed(s, root):
    while isinstance(s, dict) and "$ref" in s:
        s = root["$defs"][s["$ref"].rsplit("/", 1)[-1]]
    if isinstance(s, dict) and "oneOf" in s:
        kinds = [closed(b, root) for b in s["oneOf"] if b.get("type") != "null"]
        return None if all(k is None for k in kinds) else all(k is not False for k in kinds)
    if isinstance(s, dict) and s.get("type") == "array" and "items" in s:
        return closed(s["items"], root)
    if isinstance(s, dict) and (s.get("type") == "object" or "properties" in s):
        return s.get("additionalProperties") is False
    return None  # scalar or enum: closedness does not apply


def cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def field_table(defn, root) -> list[str]:
    req = set(defn.get("required", []))
    out = ["| field | required | type | description |", "|---|---|---|---|"]
    for k, v in defn.get("properties", {}).items():
        out.append(f"| `{k}` | {'yes' if k in req else 'no'} | {cell(shape(v, root))} | {cell(v.get('description', ''))} |")
    return out


def generate() -> str:
    root = json.loads(SCHEMA.read_text())
    props, req, defs = root["properties"], set(root["required"]), root["$defs"]
    errs = []
    if set(TOP) != set(props):
        errs.append(f"top-level notes vs schema: missing {sorted(set(props) - set(TOP))}, stale {sorted(set(TOP) - set(props))}")
    if set(EXIT) != set(props["exit_status"]["enum"]):
        errs.append("exit_status notes differ from the schema enum")
    if set(VERDICT) != set(defs["obligation"]["properties"]["verdict"]["enum"]):
        errs.append("verdict notes differ from the schema enum")
    if set(INCIDENT_KIND) != set(defs["incident"]["properties"]["kind"]["enum"]):
        errs.append("incident.kind notes differ from the schema enum")
    if set(PROOF_TIER) != set(defs["delta_rel_item"]["properties"]["proof_tier"]["enum"]):
        errs.append("proof_tier notes differ from the schema enum")
    errs += [f"record note for missing $def {k}" for k in RECORDS if k not in defs]
    if errs:
        raise SystemExit("gen_artifact_doc: " + "; ".join(errs))

    L = ["# Hlith run artifact reference", "",
         "<!-- GENERATED by scripts/gen_artifact_doc.py from src/hlith/hlith.schema.json. Do not edit by hand; "
         "tests/test_artifact_doc.py fails when this file differs from the generator output. -->", "",
         f"Schema `{root.get('$id')}` ({root.get('title')}). Every object below marked closed rejects unknown keys: "
         "a renamed or new field is a schema change, never silent. A UI should read this file together with a "
         "real artifact you produce.", "",
         "## Outcome lattice", "",
         "`decide()` (src/hlith/types.py) reads ONLY `obligations`: landing needs every verdict HELD and at least one "
         "account-bound obligation; otherwise the first present class in the order REFUTED > NOT_DERIVED > "
         "UNVERIFIED sets the exit status. `delta_rel`, `timings` and `graph` are never read by it.", "",
         "| exit_status | class | meaning |", "|---|---|---|"]
    L += [f"| {k} | {EXIT[k][0]} | {cell(EXIT[k][1])} |" for k in props["exit_status"]["enum"]]
    L += ["", "### Obligation verdicts", "", "| verdict | what it means for a UI |", "|---|---|"]
    L += [f"| `{v}` | {cell(VERDICT[v])} |" for v in defs["obligation"]["properties"]["verdict"]["enum"]]
    L += ["", "## Top-level keys", "",
          "| key | required | type | closed | read by | a UI may infer | a UI may NOT infer |", "|---|---|---|---|---|---|---|"]
    for k, v in props.items():
        rb, may, maynot = TOP[k]
        L.append(f"| `{k}` | {'yes' if k in req else 'no (absent allowed)'} | {cell(shape(v, root))} | "
                 f"{ {True: 'yes', False: 'no', None: '-'}[closed(v, root)] } | {cell(rb)} | {cell(may)} | {cell(maynot)} |")
    L += ["", "Schema descriptions of the top-level keys:", ""]
    for k, v in props.items():
        L.append(f"- `{k}`: {cell(v.get('description', '(none)'))}")
        if k in TOP_SUBNOTES:
            L.append(f"  - {cell(TOP_SUBNOTES[k])}")
    L += ["", "## Main records", ""]
    for name, note in RECORDS.items():
        d = defs[name]
        if name == "obligation":
            note = note + (" Format-2 artifacts may also carry `witness_call` and, only when a recorded call adapts, "
                           "`witness_record` (schema version 1) on a REFUTED obligation. These optional runtime fields "
                           "are not part of the closed v1 schema table below.")
        L += [f"### `{name}`{' (closed)' if d.get('additionalProperties') is False else ''}", "", cell(note), ""]
        if d.get("description"):
            L += [f"Schema: {cell(d['description'])}", ""]
        L += field_table(d, root) + [""]
        if name == "incident":
            L += ["| incident.kind | meaning |", "|---|---|"]
            L += [f"| `{k}` | {cell(INCIDENT_KIND[k])} |" for k in d["properties"]["kind"]["enum"]] + [""]
        if name == "delta_rel_item":
            L += ["| proof_tier | meaning |", "|---|---|"]
            L += [f"| `{k}` | {cell(PROOF_TIER[k])} |" for k in d["properties"]["proof_tier"]["enum"]] + [""]
    L += ["## Real examples", "",
          "Run `hlith check ... --artifact-out DIR` to produce a real artifact. This reference describes "
          "every field; example artifacts are not included in this source snapshot.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    text = generate()
    if "--write" in sys.argv:
        OUT.write_text(text)
    else:
        sys.stdout.write(text)
