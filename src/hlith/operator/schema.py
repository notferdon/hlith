# SPDX-License-Identifier: Apache-2.0
"""Artifact validation. Retires ``tui/schema_check``: same closed-key structural rules for hlith.schema.json, consumed
here once for every surface. Cross-field consistency JSON Schema cannot express is NOT checked (stated, not implied).

Format-2 artifacts (written by the coordinator from typed contract values) are validated by decoding, not by this schema;
format-1 artifacts keep their original schema identity (``hlith.schema.json``) and are validated here, read-only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA = Path(__file__).resolve().parent.parent / "hlith.schema.json"

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _type_ok(inst, t) -> bool:
    ok = False
    for tt in ([t] if isinstance(t, str) else t):
        if tt == "integer":
            ok |= isinstance(inst, int) and not isinstance(inst, bool)
        elif tt == "number":
            ok |= isinstance(inst, (int, float)) and not isinstance(inst, bool)
        else:
            ok |= isinstance(inst, _TYPES[tt])
    return ok


def schema_errors(inst, sch, root, path="$") -> list[str]:
    if sch is True:
        return []
    if "$ref" in sch:
        node = root
        for part in sch["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return schema_errors(inst, node, root, path)
    errs: list[str] = []
    t = sch.get("type")
    if t is not None and not _type_ok(inst, t):
        return [f"{path}: type {t}, got {type(inst).__name__}"]
    if "const" in sch and not (inst == sch["const"] and type(inst) is type(sch["const"])):
        errs.append(f"{path}: const {sch['const']!r}")
    if "enum" in sch and not any(inst == e and type(inst) is type(e) for e in sch["enum"]):
        errs.append(f"{path}: not in enum")
    if isinstance(inst, str):
        if "pattern" in sch and not re.search(sch["pattern"], inst):
            errs.append(f"{path}: pattern {sch['pattern']}")
        if len(inst) > sch.get("maxLength", 1 << 30) or len(inst) < sch.get("minLength", 0):
            errs.append(f"{path}: length")
    if isinstance(inst, (int, float)) and not isinstance(inst, bool) and inst < sch.get("minimum", inst):
        errs.append(f"{path}: minimum")
    if isinstance(inst, list):
        if len(inst) > sch.get("maxItems", 1 << 30) or len(inst) < sch.get("minItems", 0):
            errs.append(f"{path}: item count")
        if "items" in sch:
            for i, v in enumerate(inst):
                errs += schema_errors(v, sch["items"], root, f"{path}[{i}]")
    if isinstance(inst, dict):
        props = sch.get("properties", {})
        errs += [f"{path}: missing {k}" for k in sch.get("required", []) if k not in inst]
        ap = sch.get("additionalProperties")
        if ap is False:
            errs += [f"{path}: unknown key {k}" for k in inst if k not in props]
        elif isinstance(ap, dict):
            for k, v in inst.items():
                if k not in props:
                    errs += schema_errors(v, ap, root, f"{path}.{k}")
        for k, v in inst.items():
            if k in props:
                errs += schema_errors(v, props[k], root, f"{path}.{k}")
        for k, need in sch.get("dependentRequired", {}).items():
            if k in inst:
                errs += [f"{path}: {k} requires {n}" for n in need if n not in inst]
    if "oneOf" in sch:
        n = sum(not schema_errors(inst, b, root, path) for b in sch["oneOf"])
        if n != 1:
            errs.append(f"{path}: matches {n} of oneOf")
    for b in sch.get("allOf", []):
        errs += schema_errors(inst, b, root, path)
    if "not" in sch and not schema_errors(inst, sch["not"], root, path):
        errs.append(f"{path}: matches not")
    if "if" in sch:
        branch = "then" if not schema_errors(inst, sch["if"], root, path) else "else"
        if branch in sch:
            errs += schema_errors(inst, sch[branch], root, path)
    return errs


_ROOT: dict | None = None

_RUN_ID = re.compile(r"^run-[0-9a-f]{12}$")
_VERDICTS = ("held", "refuted", "not-derived", "unverified")
_REFUSAL_EXITS = (10, 11, 12, 4)


def format2_errors(art) -> list[str]:
    """Structural + consistency check of a FORMAT-2 artifact (written by the coordinator from typed pipeline values). Same closed
    spirit as the v1 schema, but for the v2 shape: the decision fields must agree with each other (landed <=> exit 0 and a landed
    commit; refused <=> a refusal exit status), ids/enums must be real contract values. It never rewrites or softens a decision."""
    from ..contract.runs import LandingTarget, RunMode
    from .origin import InputOrigin

    errs: list[str] = []
    if not isinstance(art, dict):
        return ["$: not an object"]
    if art.get("format") != 2:
        errs.append("$.format: must be 2")
    run = art.get("run")
    if not isinstance(run, dict):
        errs.append("$.run: missing or not an object")
    else:
        if not isinstance(run.get("run_id"), str) or not _RUN_ID.fullmatch(run["run_id"]):
            errs.append("$.run.run_id: not a run id")
        for key, enum_t in (("mode", RunMode), ("landing_target", LandingTarget), ("origin", InputOrigin)):
            if run.get(key) not in [e.value for e in enum_t]:
                errs.append(f"$.run.{key}: not a {enum_t.__name__} value")
    out, rc = art.get("outcome"), art.get("exit_status")
    if out not in ("landed", "refused"):
        errs.append("$.outcome: must be landed or refused")
    if not isinstance(rc, int) or isinstance(rc, bool):
        errs.append("$.exit_status: must be an integer")
    elif out == "landed" and (rc != 0 or not art.get("landed_commit")):
        errs.append("$: landed needs exit_status 0 and a landed_commit")
    elif out == "refused" and (rc not in _REFUSAL_EXITS or art.get("landed_commit")):
        errs.append("$: refused needs a refusal exit status (10/11/12/4) and no landed_commit")
    blocking = art.get("blocking")
    if not isinstance(blocking, list) or not all(isinstance(b, str) for b in blocking):
        errs.append("$.blocking: must be a list of strings")
    obs = art.get("obligations")
    if obs is None and "obligations" not in art:
        pass  # artifacts written before the rows were added (the first pipeline builds) carry none: read as "not recorded", never invented
    elif not isinstance(obs, list):
        errs.append("$.obligations: must be a list (empty only when no obligation was reached)")
    else:
        for i, o in enumerate(obs):
            if not isinstance(o, dict) or not isinstance(o.get("id"), str) or o.get("verdict") not in _VERDICTS:
                errs.append(f"$.obligations[{i}]: needs a string id and a verdict in {_VERDICTS}")
    return errs


def artifact_errors(art) -> list[str]:
    """Validate against the schema the artifact CLAIMS: format 2 -> ``format2_errors``; anything else keeps its original schema
    identity (``hlith.schema.json``, v1). A valid format-2 record is never reported as a v1 violation."""
    if isinstance(art, dict) and art.get("format") == 2:
        return format2_errors(art)
    global _ROOT
    if _ROOT is None:
        _ROOT = json.loads(SCHEMA.read_text())
    return schema_errors(json.loads(json.dumps(art)), _ROOT, _ROOT)
