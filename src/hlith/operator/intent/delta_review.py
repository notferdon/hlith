# SPDX-License-Identifier: Apache-2.0
"""Canonical human-review packets for intended behaviour changes.

This service prepares a packet and verifies an operator's per-run confirmation.
It does not invoke Hlith, persist approvals, or write into the target repository.
Every packet string is untrusted raw text; the renderer MUST clean it with
``clean_for_terminal`` before display. Engine approval currently binds the delta
set, not the patch hash; the returned argv binds the reviewed patch/manifest paths
for the launch plan, while engine-side patch-to-approval binding remains separate.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from ... import feedback
from . import propose
from ...runtime import (
    DELTA_KINDS,
    DELTA_TYPED_CLASSES,
    MAX_MANIFEST_BYTES,
    MAX_MANIFEST_PATHS,
    _KIND_VOCAB,
    delta_set_sha256,
    validate_deltas,
)
from ...textsafe import clean as clean_for_terminal

clean = clean_for_terminal

SCHEMA_VERSION = 1
BROADER_ACKNOWLEDGEMENT = "ACKNOWLEDGE BROADER EXPRESSION CLAIM"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PREFIX = re.compile(r"[0-9a-f]{8}\Z")
_MAX_ROWS = 200
_MAX_STRING = 2048
_MAX_READ_BYTES = 8 * 1024 * 1024
_PREDICATE_KINDS = frozenset({"literal_inputs", "expr", "typed"})
_EXPECTED_KINDS = frozenset({"returns", "returns_expr", "raises"})
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
__all__ = ["BROADER_ACKNOWLEDGEMENT", "DeltaReviewError", "build_review_packet", "verify_confirmation",
           "clean_for_terminal", "clean", "delta_from_rendered_proposal"]


class DeltaReviewError(ValueError):
    """The review packet cannot safely be built or verified."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path, label: str) -> tuple[dict, bytes]:
    raw = _read_file(path, label, _MAX_READ_BYTES)
    try:
        value = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid JSON constant {x}")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, AttributeError) as exc:
        raise DeltaReviewError(f"cannot read {label}: {exc}") from None
    if type(value) is not dict:
        raise DeltaReviewError(f"{label} must be an object")
    return value, raw


def _read_file(path: Path, label: str, limit: int) -> bytes:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise DeltaReviewError(f"{label} must be a regular file")
        if st.st_size > limit:
            raise DeltaReviewError(f"{label} exceeds {limit} bytes")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise DeltaReviewError(f"{label} exceeds {limit} bytes")
    except DeltaReviewError:
        raise
    except OSError as exc:
        # Preserve the OS error as a machine-readable cause for callers that
        # need to distinguish an absent file from an unsafe or unreadable one.
        raise DeltaReviewError(f"cannot read {label}: {exc}") from exc
    except (RecursionError, ValueError, AttributeError) as exc:
        raise DeltaReviewError(f"cannot read {label}: {exc}") from None
    finally:
        if fd is not None:
            os.close(fd)
    return raw


def _find(path: str | Path, names: Sequence[str], label: str) -> Path:
    p = Path(path).expanduser().absolute()
    if p.is_file():
        return p
    if not p.is_dir():
        raise DeltaReviewError(f"{label} does not exist: {p}")
    found = [p / n for n in names if (p / n).is_file()]
    if len(found) != 1:
        raise DeltaReviewError(f"{label} directory must contain exactly one of {', '.join(names)}")
    return found[0]


def _git_root(path: Path) -> Path | None:
    from ...gitsafe import discover_toplevel  # scrubbed env + gate._HARDEN: no inherited GIT_DIR/WORK_TREE, no repo programs
    probe = path if path.is_dir() else path.parent
    out = discover_toplevel(probe)
    if out is None:
        return None
    try:
        return Path(os.fsdecode(out).strip()).resolve(strict=True)
    except OSError:
        return None


def _rev_parse(path: Path, *args: str) -> str | None:
    """Repo-bound rev-parse through gate._run_git (scrubbed env, _HARDEN, real-.git rule); None on any refusal."""
    from ...gate import _run_git
    try:
        cp = _run_git(Path(path), ("rev-parse", *args), None)
    except (RuntimeError, OSError):
        return None
    return None if cp.returncode else cp.stdout


def _git_head(path: Path) -> str | None:
    out = _rev_parse(path, "HEAD")
    if out is None:
        return None
    head = out.removesuffix("\n")
    return head if _GIT_OID.fullmatch(head) else None


def _git_commit(path: Path, revision: str) -> str | None:
    out = _rev_parse(path, "--verify", f"{revision}^{{commit}}")
    if out is None:
        return None
    commit = out.removesuffix("\n")
    return commit if _GIT_OID.fullmatch(commit) else None


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _safe_target_and_output(repo: Path, artifact_path: Path) -> None:
    if artifact_path.parent.is_symlink():
        raise DeltaReviewError("output directory must not be a symlink")
    if artifact_path.resolve(strict=True) != artifact_path:
        raise DeltaReviewError("artifact path must not traverse symlinked directories")
    target_root = _git_root(repo) or repo.resolve(strict=True)
    out_dir = artifact_path.parent.resolve(strict=True)
    if _is_inside(artifact_path, target_root) or _is_inside(out_dir, target_root):
        raise DeltaReviewError("artifact or output directory is inside the target repository")
    artifact_git_root = _git_root(out_dir)
    if artifact_git_root is not None:
        raise DeltaReviewError(f"artifact/output directory is inside git work tree {artifact_git_root}")


def _validate_manifest_paths(paths: Any) -> dict[str, list[str]]:
    """Mirror runtime.read_manifest_full's path and kind checks before materialization."""
    if not isinstance(paths, dict) or not paths or len(paths) > MAX_MANIFEST_PATHS:
        raise DeltaReviewError("manifest paths must be a non-empty object within engine limits")
    result = {}
    for key, kinds in paths.items():
        if type(key) is not str:
            raise DeltaReviewError("manifest path keys must be strings")
        pp = Path(key)
        if pp.is_absolute() or ".." in pp.parts or key != pp.as_posix():
            raise DeltaReviewError(f"invalid manifest path {key!r}")
        if type(kinds) is not list or not kinds or not all(type(k) is str and k in _KIND_VOCAB for k in kinds):
            raise DeltaReviewError(f"invalid manifest kinds for {key!r}")
        result[key] = kinds
    return result


def _bounded(value: Any, state: dict) -> Any:
    """Copy JSON data while enforcing the packet's string cap."""
    if type(value) is str:
        raw = value.encode("utf-8", "surrogatepass")
        if len(raw) > _MAX_STRING:
            state["truncated"] = True
            raw = raw[:_MAX_STRING]
            while True:
                try:
                    return raw.decode("utf-8", "surrogatepass")
                except UnicodeDecodeError:
                    raw = raw[:-1]
        return value
    if type(value) is list:
        return [_bounded(x, state) for x in value]
    if type(value) is dict:
        return {_bounded(k, state): _bounded(v, state) for k, v in value.items()}
    return value


def _repr(value: Any, state: dict) -> str:
    return _bounded(canonical_json(value), state)


def _outcome(value: Any, state: dict | None = None) -> str:
    expected = propose._expected(value) if type(value) is dict else None
    if expected is None:
        return "<unavailable>"
    text = expected.get("value_repr", expected.get("exc_type", "<unavailable>"))
    return _bounded(text, state) if state is not None else text


def _scope(delta: dict) -> tuple[str, list[dict], int | None]:
    pred = delta["predicate"]
    if pred["type"] == "literal_inputs":
        rows = pred["inputs"]
        return f"covers exactly these {len(rows)} inputs", rows, None
    if pred["type"] == "expr":
        return f"covers EVERY input where {pred['expr']}", [], None
    if pred["type"] == "typed":
        key = f" and key {pred['key']!r} is absent" if pred["class"] == "mapping_key_absent" else ""
        return f"covers EVERY input where parameter {pred['param']} has class {pred['class']}{key}", [], None
    raise DeltaReviewError(f"unsupported proposal predicate: {pred.get('type')}")


def _expected_text(expected: dict) -> str:
    kind = expected["kind"]
    value_key = {"returns": "value_repr", "returns_expr": "expr", "raises": "exc_type"}.get(kind)
    if value_key is None:
        raise DeltaReviewError(f"unrenderable expected kind: {kind}")
    return f"{kind}: {expected[value_key]}"


def _machine_claim(delta: dict) -> dict:
    """Exact machine-enforced fields, kept structured and raw for round-trip verification."""
    pred = delta.get("predicate")
    expected = delta.get("expected")
    if (delta.get("kind") not in DELTA_KINDS or type(pred) is not dict or pred.get("type") not in _PREDICATE_KINDS
            or type(expected) is not dict or expected.get("kind") not in _EXPECTED_KINDS):
        raise DeltaReviewError("unrenderable_kind: delta kind, predicate, or expected kind is unknown")
    # Reject any validated representation that this renderer does not understand.
    allowed_pred_keys = {"literal_inputs": {"type", "inputs"}, "expr": {"type", "param", "expr"},
                         "typed": {"type", "param", "class", "key" if pred.get("class") == "mapping_key_absent" else "class"}}
    if set(pred) != allowed_pred_keys[pred["type"]]:
        raise DeltaReviewError("unrenderable_kind: predicate has fields the packet cannot render")
    expected_keys = {"returns": {"kind", "value_repr"}, "returns_expr": {"kind", "expr"}, "raises": {"kind", "exc_type"}}
    if set(expected) != expected_keys[expected["kind"]]:
        raise DeltaReviewError("unrenderable_kind: expected value has fields the packet cannot render")
    if pred["type"] == "typed" and pred.get("class") not in DELTA_TYPED_CLASSES:
        raise DeltaReviewError("unrenderable_kind: typed predicate class is unknown")
    machine = {"id": delta["id"], "symbol": delta["symbol"], "kind": delta["kind"],
               "predicate": pred, "expected": expected}
    def cap_strings(value):
        if type(value) is str and len(value.encode("utf-8", "surrogatepass")) > _MAX_STRING:
            raise DeltaReviewError("unrenderable_kind: an enforced string exceeds the packet string cap")
        if type(value) is dict:
            for k, v in value.items():
                cap_strings(k)
                cap_strings(v)
        elif type(value) is list:
            for item in value:
                cap_strings(item)
    cap_strings(machine)
    return machine


def delta_from_rendered_proposal(proposal: dict) -> dict:
    """Reconstruct every hashed delta field from its rendered packet representation."""
    machine = proposal["machine_claim"]
    text = proposal["text_provenance"]
    return {"id": machine["id"], "symbol": machine["symbol"], "kind": machine["kind"],
            "claim": text["claim"], "input_domain": text["input_domain"], "pre": text["pre"], "post": text["post"],
            "predicate": machine["predicate"], "expected": machine["expected"]}


def _render_flags(value: Any) -> dict:
    strings = []
    def walk(v):
        if type(v) is str:
            strings.append(v)
        elif type(v) is list:
            for x in v:
                walk(x)
        elif type(v) is dict:
            for k, x in v.items():
                walk(k)
                walk(x)
    walk(value)
    return {"contains_ansi": any(_ANSI.search(s) for s in strings),
            "contains_control": any(any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 for c in s) for s in strings),
            "contains_escaped_control": any(re.search(r"\\(?:n|r|t|x0[0-9a-f]{2}|u001b)", s, re.I) for s in strings),
            "requires_cleaning": any(clean_for_terminal(s) != s for s in strings)}


def _outlier_reason(row: dict) -> tuple[str, str]:
    reason = row.get("reason")
    if type(reason) is str and reason:
        return "proposer_exclusion", reason
    if propose.scratch_path(row):
        return "per_run_scratch_path", propose.SCRATCH_REASON
    _, excluded = propose.candidates_for(str(row.get("symbol") or "unknown"), [row], "review")
    details = [f"{name}: {count}" for name, count in excluded.items() if count]
    if details:
        return details[0].split(":", 1)[0], "; ".join(details)
    return "proposer_exclusion", "proposer provenance marked this row NOT-INCLUDED without a specific reason"


def _pins(repo: Path, artifact: dict, deltas: Sequence[dict], state: dict) -> dict[str, list[dict]]:
    """Use feedback's exact coverage function; no pin semantics are reimplemented."""
    result = {d["symbol"]: [] for d in deltas}
    account = ((artifact.get("effect_account") or {}).get("account") or {})
    files = {c.get("qualified_name"): c.get("file_path") for c in account.get("modified_callables", ())
             if type(c) is dict and type(c.get("qualified_name")) is str}
    records = feedback.load_records(repo, result)
    for d in deltas:
        file_path = files.get(d["symbol"])
        if not file_path:
            continue
        names = propose._param_names(repo, file_path, d["symbol"].rsplit(".", 1)[-1])
        for rec in records:
            if d["symbol"] in rec.target_symbols and feedback.delta_covers_pin(d, rec, names):
                payload = rec.directive_payload
                result[d["symbol"]].append({
                    "pin_id": rec.feedback_id,
                    "input_repr": _repr(payload.get("input"), state),
                    "old_expected_repr": _outcome(payload.get("expected"), state),
                })
    for symbol, pins in result.items():
        if len(pins) > _MAX_ROWS:
            del pins[_MAX_ROWS:]
            state["truncated"] = True
    return result


def _proposal_rows(delta: dict, artifact: dict, provenance: dict, pins: list[dict], state: dict) -> dict:
    machine = _machine_claim(delta)
    scope, inputs, total = _scope(delta)
    source_inputs = inputs if delta["predicate"]["type"] == "literal_inputs" else []
    expected_text = _expected_text(delta["expected"])
    covered = [{"input_repr": _repr(row, state), "expected_repr": expected_text} for row in source_inputs[:_MAX_ROWS]]
    if len(source_inputs) > _MAX_ROWS:
        state["truncated"] = True
    if delta["predicate"]["type"] != "literal_inputs":
        # No finite coverage count exists; zero means no artifact-backed sample is attached.
        total = 0

    # Only structured observations from the engine artifact are presented as observed pairs.
    # The current artifact schema stores most witnesses as display text, not triples.
    engine_pairs = []
    for obligation in artifact.get("obligations", []):
        if type(obligation) is not dict or obligation.get("target_symbol") != delta["symbol"]:
            continue
        witness = obligation.get("witness")
        if type(witness) is dict and all(k in witness for k in ("input", "pre", "post")):
            engine_pairs.append({"input_repr": _repr(witness["input"], state),
                                 "pre_repr": _bounded(str(witness["pre"]), state),
                                 "post_repr": _bounded(str(witness["post"]), state),
                                 "source": "engine artifact witness"})
    if len(engine_pairs) > _MAX_ROWS:
        state["truncated"] = True
    engine_pairs = engine_pairs[:_MAX_ROWS]
    raw_witnesses = [o.get("witness") for o in artifact.get("obligations", [])
                     if type(o) is dict and o.get("target_symbol") == delta["symbol"] and type(o.get("witness")) is str]
    if len(raw_witnesses) > _MAX_ROWS:
        state["truncated"] = True
    engine_witnesses = [_bounded(x, state) for x in raw_witnesses[:_MAX_ROWS]]

    preview_data = (provenance.get("preview") or {}).get(delta["symbol"], {})
    uncovered = preview_data.get("uncovered", []) if type(preview_data) is dict else []
    examples = []
    for row in uncovered[:_MAX_ROWS]:
        if type(row) is not dict:
            continue
        examples.append({"input_repr": _repr({"args": row.get("args", []), "kwargs": row.get("kwargs", {})}, state),
                         "pre_repr": _outcome(row.get("pre"), state), "post_repr": _outcome(row.get("post"), state)})
    if len(uncovered) > _MAX_ROWS:
        state["truncated"] = True
    excluded = [x for x in provenance.get("not_included", []) if type(x) is dict and x.get("symbol") == delta["symbol"]]
    outliers = []
    if len(excluded) > _MAX_ROWS:
        state["truncated"] = True
    for x in excluded[:_MAX_ROWS]:
        code, reason = _outlier_reason(x)
        details = {"args": x.get("args"), "kwargs": x.get("kwargs")}
        outliers.append({"reason_code": code, "text": _bounded("proposer text (not observed); " + reason + "; " + canonical_json(details), state)})
    text_provenance = {"label": "proposer text (not observed)", "claim": delta["claim"],
                       "input_domain": delta["input_domain"], "pre": delta["pre"], "post": delta["post"]}
    result = {
        "id": delta["id"],
        "kind": "literal" if delta["predicate"]["type"] == "literal_inputs" else "broader_expression",
        "symbol": delta["symbol"], "delta_text": delta["claim"], "delta_text_label": "proposer text (not observed)",
        "text_provenance": text_provenance, "machine_claim": machine,
        "scope_sentence": scope,
        "second_ack_required": delta["predicate"]["type"] != "literal_inputs",
        "covered": {"items": covered, "total_count": total},
        "provenance_pairs": engine_pairs,
        "engine_witnesses": engine_witnesses,
        "preview_outside": {
            "explored": int(preview_data.get("explored", 0) or 0) if type(preview_data) is dict else 0,
            "outside_divergences": int(preview_data.get("uncovered_count", 0) or 0) if type(preview_data) is dict else 0,
            "examples": examples,
            "complete": bool(type(preview_data) is dict and preview_data.get("ran") is True and not preview_data.get("truncated", False)),
            "source": "proposer preview output; raw, not part of the source run artifact",
        },
        "superseded_pins": pins,
        "not_included": outliers,
    }
    result["render_flags"] = _render_flags(result)
    return result


def _closed(packet: Any) -> None:
    """Closed-schema validation without an optional runtime dependency."""
    def keys(obj, required, label):
        if type(obj) is not dict or set(obj) != set(required):
            raise DeltaReviewError(f"{label} has missing or unknown keys")
    def strings_ok(value):
        if type(value) is str:
            if len(value.encode("utf-8", "surrogatepass")) > _MAX_STRING:
                raise DeltaReviewError("packet string exceeds 2 KiB")
        elif type(value) is list:
            for item in value:
                strings_ok(item)
        elif type(value) is dict:
            for key, item in value.items():
                strings_ok(key)
                strings_ok(item)
    keys(packet, ("schema_version", "state", "refusal", "run", "delta_set_sha256", "deltas", "patch_input", "freshness", "proposals", "truncated", "caps", "approve", "rerun_inputs", "raw_strings"), "packet")
    if (type(packet["schema_version"]) is not int or packet["schema_version"] != SCHEMA_VERSION
            or type(packet["state"]) is not str or packet["state"] not in ("fresh", "stale", "refused")):
        raise DeltaReviewError("unsupported packet version or state")
    if packet["raw_strings"] is not True:
        raise DeltaReviewError("raw_strings must be true")
    if type(packet["truncated"]) is not bool:
        raise DeltaReviewError("truncated must be boolean")
    keys(packet["run"], ("run_id", "artifact_sha256", "patch_sha256", "base", "artifact_path", "manifest_path", "target_label", "target_repo_path"), "run")
    keys(packet["freshness"], ("artifact_sha256", "manifest_sha256"), "freshness")
    keys(packet["approve"], ("flag", "value"), "approve")
    keys(packet["rerun_inputs"], ("patch_path", "manifest_path"), "rerun_inputs")
    keys(packet["caps"], ("covered_rows", "provenance_rows", "string_bytes"), "caps")
    if packet["caps"] != {"covered_rows": _MAX_ROWS, "provenance_rows": _MAX_ROWS, "string_bytes": _MAX_STRING}:
        raise DeltaReviewError("packet caps do not match implementation limits")
    if packet["state"] == "fresh":
        if packet["refusal"] is not None:
            raise DeltaReviewError("fresh packet cannot contain refusal")
        if type(packet["run"]["base"]) is not str or not _GIT_OID.fullmatch(packet["run"]["base"]):
            raise DeltaReviewError("fresh packet has an unbound base revision")
    else:
        keys(packet["refusal"], ("code", "text"), "refusal")
        if packet["refusal"]["code"] not in ("artifact_changed", "manifest_changed", "no_deltas", "old_schema", "unrenderable_kind", "artifact_in_target", "invalid_artifact", "invalid_manifest", "unsafe_output", "base_unbound"):
            raise DeltaReviewError("unknown refusal code")
        if type(packet["refusal"]["text"]) is not str or len(packet["refusal"]["text"].encode("utf-8", "surrogatepass")) > _MAX_STRING:
            raise DeltaReviewError("invalid refusal text")
        if packet["proposals"]:
            raise DeltaReviewError("non-fresh packet cannot contain proposals")
    if type(packet["delta_set_sha256"]) is not str or not _SHA.fullmatch(packet["delta_set_sha256"]):
        raise DeltaReviewError("invalid delta_set_sha256")
    for location, sha in (("run.artifact_sha256", packet["run"]["artifact_sha256"]),
                          ("freshness.artifact_sha256", packet["freshness"]["artifact_sha256"]),
                          ("freshness.manifest_sha256", packet["freshness"]["manifest_sha256"])):
        if type(sha) is not str or not _SHA.fullmatch(sha):
            raise DeltaReviewError(f"{location} must be lowercase SHA-256")
    if packet["run"]["artifact_sha256"] != packet["freshness"]["artifact_sha256"]:
        raise DeltaReviewError("run and freshness artifact hashes differ")
    for name in ("run_id", "base", "artifact_path", "manifest_path", "target_label", "target_repo_path"):
        value = packet["run"][name]
        if value is not None and (type(value) is not str or len(value.encode("utf-8", "surrogatepass")) > _MAX_STRING):
            raise DeltaReviewError(f"run.{name} violates the string cap")
    patch_sha = packet["run"]["patch_sha256"]
    if patch_sha is not None and (type(patch_sha) is not str or not _SHA.fullmatch(patch_sha)):
        raise DeltaReviewError("run.patch_sha256 must be lowercase SHA-256")
    if packet["approve"] != {"flag": "--approve-deltas", "value": packet["delta_set_sha256"]}:
        raise DeltaReviewError("approval binding mismatch")
    if type(packet["approve"]["flag"]) is not str or type(packet["approve"]["value"]) is not str:
        raise DeltaReviewError("approval binding fields must be strings")
    if type(packet["rerun_inputs"]["patch_path"]) is not str or type(packet["rerun_inputs"]["manifest_path"]) is not str:
        raise DeltaReviewError("rerun paths must be strings")
    if type(packet["proposals"]) is not list or len(packet["proposals"]) > 200:
        raise DeltaReviewError("proposals must be a capped array")
    proposal_keys = ("id", "kind", "symbol", "delta_text", "delta_text_label", "text_provenance", "machine_claim", "scope_sentence", "second_ack_required", "covered", "provenance_pairs", "engine_witnesses", "preview_outside", "superseded_pins", "not_included", "render_flags")
    for p in packet["proposals"]:
        keys(p, proposal_keys, "proposal")
        if p["kind"] not in ("literal", "broader_expression") or type(p["second_ack_required"]) is not bool:
            raise DeltaReviewError("invalid proposal kind or acknowledgement flag")
        if p["delta_text_label"] != "proposer text (not observed)":
            raise DeltaReviewError("proposer claim must be visibly labeled as unobserved")
        keys(p["text_provenance"], ("label", "claim", "input_domain", "pre", "post"), "text_provenance")
        if p["text_provenance"]["label"] != "proposer text (not observed)" or p["text_provenance"]["claim"] != p["delta_text"]:
            raise DeltaReviewError("proposer text label or claim binding mismatch")
        for field in ("id", "symbol", "delta_text", "delta_text_label", "scope_sentence"):
            if type(p[field]) is not str or len(p[field].encode("utf-8", "surrogatepass")) > _MAX_STRING:
                raise DeltaReviewError(f"proposal.{field} violates the string cap")
        if any(type(p["text_provenance"][f]) is not str for f in ("claim", "input_domain", "pre", "post")):
            raise DeltaReviewError("proposer text fields must be strings")
        keys(p["machine_claim"], ("id", "symbol", "kind", "predicate", "expected"), "machine_claim")
        if p["machine_claim"]["id"] != p["id"] or p["machine_claim"]["symbol"] != p["symbol"]:
            raise DeltaReviewError("machine claim identity mismatch")
        if p["machine_claim"]["kind"] not in DELTA_KINDS:
            raise DeltaReviewError("unrenderable_kind: delta kind")
        machine_delta = delta_from_rendered_proposal(p)
        validated = validate_deltas([machine_delta])[0]
        if validated["predicate"]["type"] not in _PREDICATE_KINDS or validated["expected"]["kind"] not in _EXPECTED_KINDS:
            raise DeltaReviewError("unrenderable_kind: predicate or expected kind")
        is_literal = validated["predicate"]["type"] == "literal_inputs"
        if p["kind"] != ("literal" if is_literal else "broader_expression"):
            raise DeltaReviewError("proposal kind does not match the rendered predicate")
        if p["second_ack_required"] != (not is_literal):
            raise DeltaReviewError("proposal acknowledgement flag does not match the rendered predicate")
        if p["scope_sentence"] != _scope(validated)[0]:
            raise DeltaReviewError("scope sentence does not match the rendered predicate")
        keys(p["covered"], ("items", "total_count"), "covered")
        if p["covered"]["total_count"] is not None and (type(p["covered"]["total_count"]) is not int or p["covered"]["total_count"] < 0):
            raise DeltaReviewError("invalid covered total_count")
        if type(p["covered"]["items"]) is not list or len(p["covered"]["items"]) > _MAX_ROWS:
            raise DeltaReviewError("covered rows exceed the cap")
        for row in p["covered"]["items"]:
            keys(row, ("input_repr", "expected_repr"), "covered item")
            if row["expected_repr"] != _expected_text(validated["expected"]):
                raise DeltaReviewError("covered expected value does not display the enforced expected kind and text")
        if is_literal:
            expected_items = [{"input_repr": _repr(i, {"truncated": False}),
                               "expected_repr": _expected_text(validated["expected"])}
                              for i in validated["predicate"]["inputs"][:_MAX_ROWS]]
            if p["covered"]["items"] != expected_items or p["covered"]["total_count"] is not None:
                raise DeltaReviewError("covered inputs do not match the rendered literal predicate")
        elif p["covered"]["items"] or p["covered"]["total_count"] != 0:
            raise DeltaReviewError("non-literal scope must not claim unevidenced covered samples")
        keys(p["preview_outside"], ("explored", "outside_divergences", "examples", "complete", "source"), "preview_outside")
        if (type(p["preview_outside"]["explored"]) is not int or p["preview_outside"]["explored"] < 0
                or type(p["preview_outside"]["outside_divergences"]) is not int or p["preview_outside"]["outside_divergences"] < 0
                or type(p["preview_outside"]["complete"]) is not bool
                or type(p["preview_outside"]["source"]) is not str):
            raise DeltaReviewError("invalid preview counts or completion flag")
        if type(p["preview_outside"]["examples"]) is not list or len(p["preview_outside"]["examples"]) > _MAX_ROWS:
            raise DeltaReviewError("preview examples exceed the cap")
        for row in p["preview_outside"]["examples"]:
            keys(row, ("input_repr", "pre_repr", "post_repr"), "preview example")
            if any(type(v) is not str or len(v.encode()) > _MAX_STRING for v in row.values()):
                raise DeltaReviewError("preview example string exceeds cap")
        for list_name, row_keys in (("provenance_pairs", ("input_repr", "pre_repr", "post_repr", "source")),
                                    ("superseded_pins", ("pin_id", "input_repr", "old_expected_repr")),
                                    ("not_included", ("reason_code", "text"))):
            if type(p[list_name]) is not list:
                raise DeltaReviewError(f"proposal.{list_name} must be an array")
            if len(p[list_name]) > _MAX_ROWS:
                raise DeltaReviewError(f"proposal.{list_name} exceeds row cap")
            for row in p[list_name]:
                keys(row, row_keys, list_name)
                if any(type(v) is not str for v in row.values()):
                    raise DeltaReviewError(f"{list_name} fields must be strings")
        if type(p["engine_witnesses"]) is not list or len(p["engine_witnesses"]) > _MAX_ROWS or any(type(w) is not str for w in p["engine_witnesses"]):
            raise DeltaReviewError("engine_witnesses must be capped raw strings")
        keys(p["render_flags"], ("contains_ansi", "contains_control", "contains_escaped_control", "requires_cleaning"), "render_flags")
        if any(type(v) is not bool for v in p["render_flags"].values()):
            raise DeltaReviewError("render_flags values must be booleans")
        if p["render_flags"] != _render_flags({k: v for k, v in p.items() if k != "render_flags"}):
            raise DeltaReviewError("renderer-cleaning flags do not match raw text")
        strings_ok(p)
    if packet["state"] == "fresh":
        rendered_deltas = [delta_from_rendered_proposal(p) for p in packet["proposals"]]
        if delta_set_sha256(validate_deltas(rendered_deltas)) != packet["delta_set_sha256"]:
            raise DeltaReviewError("rendered machine claims do not match the approved delta hash")
    if packet["state"] == "fresh" and not packet["proposals"]:
        raise DeltaReviewError("fresh packet must contain proposals")


def _plan_output_paths(artifact_path: Path, run_id: str, manifest_bytes: bytes, patch_bytes: bytes) -> tuple[Path, Path]:
    suffix = hashlib.sha256(run_id.encode("utf-8", "replace")).hexdigest()[:8]
    directory = artifact_path.parent
    for index in range(10_000):
        extra = f"-{index}" if index else ""
        stem = f"{artifact_path.stem}.delta-review-{suffix}{extra}"
        manifest = directory / f"{stem}.manifest.json"
        patch = directory / f"{stem}.patch"
        try:
            same = (_read_file(manifest, "existing review manifest", _MAX_READ_BYTES) == manifest_bytes and
                    _read_file(patch, "existing review patch", _MAX_READ_BYTES) == patch_bytes)
            if same:
                same = (stat.S_IMODE(manifest.stat(follow_symlinks=False).st_mode) == 0o600 and
                        stat.S_IMODE(patch.stat(follow_symlinks=False).st_mode) == 0o600)
            if same:
                return manifest, patch
        except DeltaReviewError:
            pass
        if not manifest.exists() and not manifest.is_symlink() and not patch.exists() and not patch.is_symlink():
            return manifest, patch
    raise DeltaReviewError("unsafe_output: no free review packet output name")


def _materialize_pair(manifest_path: Path, patch_path: Path, manifest_bytes: bytes, patch_bytes: bytes) -> None:
    """Create both adjacent files without following links or overwriting existing data."""
    directory = manifest_path.parent
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created: list[str] = []
    try:
        pairs = ((manifest_path.name, manifest_bytes), (patch_path.name, patch_bytes))
        # Existing identical files are safe to reuse; mixed or different files are refused.
        existing = []
        for name, content in pairs:
            try:
                current = _read_file(directory / name, f"existing {name}", _MAX_READ_BYTES)
                existing.append(current == content)
            except DeltaReviewError as exc:
                cause = exc.__cause__
                if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
                    existing.append(None)
                else:
                    raise
        if existing == [True, True]:
            for name, _ in pairs:
                mode = stat.S_IMODE(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode)
                if mode != 0o600:
                    raise DeltaReviewError("unsafe_output: existing packet material has unsafe mode")
            return
        if any(item is not None for item in existing):
            raise DeltaReviewError("unsafe_output: existing review output differs from this packet")
        fds = []
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            for name, _ in pairs:
                fd = os.open(name, flags, 0o600, dir_fd=dfd)
                fds.append(fd)
                created.append(name)
            for fd, (_, content) in zip(fds, pairs):
                view = memoryview(content)
                while view:
                    n = os.write(fd, view)
                    view = view[n:]
                os.fsync(fd)
        except Exception:
            for name in created:
                try:
                    os.unlink(name, dir_fd=dfd)
                except OSError:
                    pass
            raise
        finally:
            for fd in fds:
                os.close(fd)
    finally:
        os.close(dfd)


def build_review_packet(repo: str | Path, artifact_path_or_run_dir: str | Path, manifest_dir: str | Path) -> dict:
    """Build a validated packet, then securely materialize the exact rerun inputs."""
    repo = Path(repo).expanduser().absolute()
    artifact_path = None
    run_stub = {"run_id": None, "artifact_sha256": "0" * 64, "patch_sha256": "0" * 64,
                "base": None, "artifact_path": "", "manifest_path": "", "target_label": repo.name,
                "target_repo_path": str(repo)}
    try:
        if not repo.is_dir():
            return _refused(run_stub, "invalid_artifact", "target repository path does not exist")
        target_root = _git_root(repo)
        if target_root is None:
            return _refused(run_stub, "invalid_artifact", "target repository is not a Git work tree")
        run_stub["target_repo_path"] = str(target_root)
        run_stub["target_label"] = target_root.name
        try:
            artifact_path = _find(artifact_path_or_run_dir, ("out.json", "artifact.json", "run.json"), "artifact")
        except DeltaReviewError as exc:
            return _refused(run_stub, "invalid_artifact", str(exc))
        run_stub["artifact_path"] = str(artifact_path)
        _safe_target_and_output(repo, artifact_path)
        try:
            artifact, artifact_bytes = _read_json(artifact_path, "artifact")
        except DeltaReviewError as exc:
            return _refused(run_stub, "invalid_artifact", str(exc))
        artifact_hash = _sha(artifact_bytes)
        run = artifact.get("run")
        effect = artifact.get("effect")
        if type(run) is not dict or type(effect) is not dict or "patch_sha256" not in effect or "unified_diff" not in effect:
            run_stub["artifact_sha256"] = artifact_hash
            return _refused(run_stub, "old_schema", "artifact lacks current run/effect fields")
        run_stub.update(run_id=run.get("run_id"), patch_sha256=effect.get("patch_sha256"),
                        base=run.get("base_commit_sha"), artifact_sha256=artifact_hash)
        if type(run_stub["base"]) is not str or not _GIT_OID.fullmatch(run_stub["base"]):
            return _refused(run_stub, "base_unbound", "artifact base revision is absent or not a full Git object id")
        if type(run_stub["run_id"]) is not str or not run_stub["run_id"]:
            return _refused(run_stub, "old_schema", "artifact has no usable run_id")
        if (type(effect.get("unified_diff")) is not str or type(effect.get("patch_sha256")) is not str
                or not _SHA.fullmatch(effect["patch_sha256"])
                or _sha(effect["unified_diff"].encode()) != effect["patch_sha256"]):
            return _refused(run_stub, "old_schema", "artifact patch identity is incomplete or inconsistent")

        try:
            source_manifest = _find(manifest_dir, ("proposed.manifest.json", "manifest.json"), "proposal manifest")
        except DeltaReviewError as exc:
            return _refused(run_stub, "invalid_manifest", str(exc))
        run_stub["manifest_path"] = str(source_manifest)
        try:
            if source_manifest.stat().st_size > MAX_MANIFEST_BYTES:
                return _refused(run_stub, "invalid_manifest", "proposal manifest exceeds engine size limit")
            source, source_bytes = _read_json(source_manifest, "proposal manifest")
            if len(source_bytes) > MAX_MANIFEST_BYTES:
                return _refused(run_stub, "invalid_manifest", "proposal manifest exceeds engine size limit")
            paths = _validate_manifest_paths(source.get("paths"))
        except DeltaReviewError as exc:
            return _refused(run_stub, "invalid_manifest", str(exc))
        deltas_raw = source.get("deltas")
        if type(deltas_raw) is not list or not deltas_raw:
            return _refused(run_stub, "no_deltas", "proposal manifest contains no deltas")
        for raw in deltas_raw:
            if type(raw) is dict:
                pred, expected = raw.get("predicate"), raw.get("expected")
                if (raw.get("kind") not in DELTA_KINDS or type(pred) is not dict or pred.get("type") not in _PREDICATE_KINDS
                        or type(expected) is not dict or expected.get("kind") not in _EXPECTED_KINDS):
                    return _refused(run_stub, "unrenderable_kind", "delta contains a kind or enforced field with no packet representation")
                pred_keys = {"literal_inputs": {"type", "inputs"}, "expr": {"type", "param", "expr"},
                             "typed": {"type", "param", "class", "key" if pred.get("class") == "mapping_key_absent" else "class"}}
                expected_keys = {"returns": {"kind", "value_repr"}, "returns_expr": {"kind", "expr"}, "raises": {"kind", "exc_type"}}
                if set(pred) != pred_keys[pred["type"]] or set(expected) != expected_keys[expected["kind"]]:
                    return _refused(run_stub, "unrenderable_kind", "delta has machine fields outside the closed renderable grammar")
                if set(raw) != {"id", "symbol", "kind", "claim", "input_domain", "pre", "post", "predicate", "expected"}:
                    return _refused(run_stub, "unrenderable_kind", "delta has fields outside the closed renderable grammar")
            else:
                return _refused(run_stub, "invalid_manifest", "proposal delta must be an object")
        try:
            deltas = validate_deltas(deltas_raw)
            for delta in deltas:
                _machine_claim(delta)
        except DeltaReviewError as exc:
            return _refused(run_stub, "unrenderable_kind", str(exc))
        except (TypeError, ValueError, RecursionError, AttributeError) as exc:
            return _refused(run_stub, "invalid_manifest", str(exc))
        delta_hash = delta_set_sha256(deltas)

        provenance = {}
        prov_path = source_manifest.parent / "proposed.provenance.json"
        if prov_path.exists() or prov_path.is_symlink():
            try:
                provenance, _ = _read_json(prov_path, "proposal provenance")
            except DeltaReviewError as exc:
                return _refused(run_stub, "invalid_manifest", str(exc))
            if provenance.get("artifact_sha256") not in (None, artifact_hash) or provenance.get("patch_sha256") not in (None, effect["patch_sha256"]):
                return _refused(run_stub, "artifact_changed", "proposal provenance is bound to a different artifact or patch", state="stale")

        manifest_doc = {"paths": paths, "deltas": list(deltas)}
        manifest_bytes = (canonical_json(manifest_doc) + "\n").encode()
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            return _refused(run_stub, "invalid_manifest", "canonical review manifest exceeds engine size limit")
        patch_bytes = effect["unified_diff"].encode()
        manifest_path, patch_path = _plan_output_paths(artifact_path, run["run_id"], manifest_bytes, patch_bytes)
        run_stub.update(manifest_path=str(manifest_path), target_repo_path=str(target_root))
        state = {"truncated": False}
        pins_by_symbol = _pins(repo.resolve(strict=True), artifact, deltas, state)
        proposals = [_proposal_rows(d, artifact, provenance, pins_by_symbol.get(d["symbol"], [])[:_MAX_ROWS], state)
                     for d in deltas]
        for p in proposals:
            for name in ("superseded_pins", "not_included"):
                source_rows = p[name]
                if len(source_rows) > _MAX_ROWS:
                    del source_rows[_MAX_ROWS:]
                    state["truncated"] = True
        packet = {
            "schema_version": SCHEMA_VERSION, "state": "fresh", "refusal": None,
            "run": run_stub, "delta_set_sha256": delta_hash, "deltas": list(deltas),
            "patch_input": {"input_patch_sha256": effect.get("input_patch_sha256"), "applied_patch_sha256": effect.get("patch_sha256"),
                            "preamble_removed_bytes": int(effect.get("preamble_removed_bytes") or 0)},
            "freshness": {"artifact_sha256": artifact_hash, "manifest_sha256": _sha(manifest_bytes)},
            "proposals": proposals, "truncated": state["truncated"], "raw_strings": True,
            "caps": {"covered_rows": _MAX_ROWS, "provenance_rows": _MAX_ROWS, "string_bytes": _MAX_STRING},
            "approve": {"flag": "--approve-deltas", "value": delta_hash},
            "rerun_inputs": {"patch_path": str(patch_path), "manifest_path": str(manifest_path)},
        }
        _closed(packet)
        _materialize_pair(manifest_path, patch_path, manifest_bytes, patch_bytes)
        return json.loads(canonical_json(packet))
    except DeltaReviewError as exc:
        code = "artifact_in_target" if "inside the target repository" in str(exc) or "inside git work tree" in str(exc) else "unsafe_output"
        if code == "artifact_in_target":
            return _refused(run_stub, code, str(exc))
        return _refused(run_stub, code, str(exc))
    except Exception as exc:
        return _refused(run_stub, "invalid_manifest", f"input refused: {type(exc).__name__}: {exc}")


def _refused(run: dict, code: str, text: str, *, state: str = "refused") -> dict:
    run = {"run_id": None, "artifact_sha256": "0" * 64, "patch_sha256": "0" * 64,
           "base": None, "artifact_path": "", "manifest_path": "", "target_label": "", "target_repo_path": "", **run}
    for key in ("run_id", "base", "artifact_path", "manifest_path", "target_label", "target_repo_path"):
        if run[key] is not None and type(run[key]) is not str:
            run[key] = None if key in ("run_id", "base") else str(run[key])
    if run["patch_sha256"] is not None and (type(run["patch_sha256"]) is not str or not _SHA.fullmatch(run["patch_sha256"])):
        run["patch_sha256"] = "0" * 64
    cap_state = {"truncated": False}
    run = _bounded(run, cap_state)
    text = _bounded(str(text), cap_state)
    packet = {"schema_version": SCHEMA_VERSION, "state": state, "refusal": {"code": code, "text": text},
              "run": run, "delta_set_sha256": "0" * 64, "deltas": [],
              "patch_input": {"input_patch_sha256": None, "applied_patch_sha256": None, "preamble_removed_bytes": 0},
              "freshness": {"artifact_sha256": run["artifact_sha256"], "manifest_sha256": "0" * 64},
              "proposals": [], "truncated": cap_state["truncated"], "raw_strings": True,
              "caps": {"covered_rows": _MAX_ROWS, "provenance_rows": _MAX_ROWS, "string_bytes": _MAX_STRING},
              "approve": {"flag": "--approve-deltas", "value": "0" * 64},
              "rerun_inputs": {"patch_path": "", "manifest_path": run.get("manifest_path", "")}}
    _closed(packet)
    return packet


def _check_freshness(packet: dict) -> None:
    run = packet["run"]
    artifact_path = Path(run["artifact_path"])
    target_repo = Path(run["target_repo_path"])
    manifest_path = Path(packet["rerun_inputs"]["manifest_path"])
    patch_path = Path(packet["rerun_inputs"]["patch_path"])
    if (not artifact_path.is_absolute() or not target_repo.is_absolute() or not manifest_path.is_absolute()
            or not patch_path.is_absolute() or str(manifest_path) != run["manifest_path"]):
        raise DeltaReviewError("stale: artifact_changed (packet paths are not canonical absolute paths)")
    try:
        if (artifact_path.resolve(strict=True) != artifact_path or target_repo.resolve(strict=True) != target_repo
                or manifest_path.resolve(strict=True) != manifest_path or patch_path.resolve(strict=True) != patch_path):
            raise DeltaReviewError("stale: artifact_changed (packet paths are not canonical)")
    except OSError as exc:
        raise DeltaReviewError(f"stale: artifact_changed ({exc})") from None
    if manifest_path.parent != artifact_path.parent or patch_path.parent != artifact_path.parent:
        raise DeltaReviewError("stale: manifest_changed (rerun files are not adjacent to the artifact)")
    stem_prefix = f"{artifact_path.stem}.delta-review-{hashlib.sha256(str(run['run_id']).encode('utf-8', 'replace')).hexdigest()[:8]}"
    if not manifest_path.name.startswith(stem_prefix) or not manifest_path.name.endswith(".manifest.json") or not patch_path.name.startswith(stem_prefix) or not patch_path.name.endswith(".patch"):
        raise DeltaReviewError("stale: manifest_changed (rerun path is not bound to this run)")
    try:
        _safe_target_and_output(target_repo, artifact_path)
    except (DeltaReviewError, OSError) as exc:
        raise DeltaReviewError(f"stale: artifact_changed ({exc})") from None
    target_root = _git_root(target_repo)
    current_head = _git_head(target_repo)
    base_commit = _git_commit(target_repo, run["base"])
    if base_commit is None or base_commit != run["base"]:
        raise DeltaReviewError("stale: target repository does not contain the artifact base revision")
    if current_head is None or current_head != run["base"]:
        raise DeltaReviewError("stale: target repository HEAD does not match artifact base")
    if target_root != target_repo or target_root.name != run["target_label"]:
        raise DeltaReviewError("stale: target repository identity path changed")
    try:
        artifact_bytes = _read_file(artifact_path, "artifact", _MAX_READ_BYTES)
        manifest_bytes = _read_file(manifest_path, "manifest", MAX_MANIFEST_BYTES)
        patch_bytes = _read_file(patch_path, "patch", _MAX_READ_BYTES)
    except (DeltaReviewError, OSError) as exc:
        raise DeltaReviewError(f"stale: cannot read artifact or manifest: {exc}") from None
    if _sha(artifact_bytes) != packet["freshness"]["artifact_sha256"]:
        raise DeltaReviewError("stale: artifact_changed")
    if _sha(manifest_bytes) != packet["freshness"]["manifest_sha256"]:
        raise DeltaReviewError("stale: manifest_changed")
    artifact = json.loads(artifact_bytes, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    identity = artifact.get("run") or {}
    effect = artifact.get("effect") or {}
    if (identity.get("run_id"), identity.get("base_commit_sha"), effect.get("patch_sha256")) != (run["run_id"], run["base"], run["patch_sha256"]):
        raise DeltaReviewError("stale: artifact_changed")
    manifest = json.loads(manifest_bytes, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    _validate_manifest_paths(manifest.get("paths"))
    manifest_deltas = validate_deltas(manifest.get("deltas"))
    actual = delta_set_sha256(manifest_deltas)
    if actual != packet["delta_set_sha256"]:
        raise DeltaReviewError("stale: manifest_changed")
    artifact_effect = artifact.get("effect") or {}
    if _sha(patch_bytes) != run["patch_sha256"] or patch_bytes.decode("utf-8") != artifact_effect.get("unified_diff"):
        raise DeltaReviewError("stale: artifact_changed")
    by_id = {d["id"]: d for d in manifest_deltas}
    if {p["id"] for p in packet["proposals"]} != set(by_id):
        raise DeltaReviewError("stale: manifest_changed")
    for proposal in packet["proposals"]:
        delta = by_id.get(proposal["id"])
        if delta is None or delta_from_rendered_proposal(proposal) != delta:
            raise DeltaReviewError("stale: manifest_changed")


def verify_confirmation(packet: Any, typed: Any, acknowledgements: Any) -> tuple[bool, str, list[str], str | None, str | None]:
    """Check exact packet-bound confirmation and return the complete rerun argv; never run it."""
    try:
        _closed(packet)
        if packet["state"] != "fresh":
            return False, f"packet state is {packet['state']}", []
        _check_freshness(packet)
    except Exception as exc:
        return False, str(exc), [], None, None
    patch_sha256 = packet["run"]["patch_sha256"]
    manifest_sha256 = packet["freshness"]["manifest_sha256"]
    if type(typed) is not str or not _PREFIX.fullmatch(typed):
        return False, "type exactly 8 lowercase hexadecimal characters", [], patch_sha256, manifest_sha256
    if typed != packet["delta_set_sha256"][:8]:
        return False, "confirmation does not match this packet", [], patch_sha256, manifest_sha256
    if any(p["second_ack_required"] for p in packet["proposals"]):
        if type(acknowledgements) not in (list, tuple) or BROADER_ACKNOWLEDGEMENT not in acknowledgements:
            return False, f"broader claim requires acknowledgement: {BROADER_ACKNOWLEDGEMENT}", [], patch_sha256, manifest_sha256
    return True, "confirmation matches this fresh packet", [
        "--repo", packet["run"]["target_repo_path"],
        "--patch", packet["rerun_inputs"]["patch_path"],
        "--manifest", packet["rerun_inputs"]["manifest_path"],
        "--approve-deltas", packet["delta_set_sha256"],
    ], patch_sha256, manifest_sha256


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hlith.delta_review")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("packet")
    p.add_argument("--repo", required=True, type=Path)
    p.add_argument("--artifact", required=True, type=Path)
    p.add_argument("--manifest-dir", required=True, type=Path)
    v = commands.add_parser("verify")
    v.add_argument("--packet", required=True, type=Path)
    v.add_argument("--typed", required=True)
    v.add_argument("--ack", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "packet":
            print(canonical_json(build_review_packet(args.repo, args.artifact, args.manifest_dir)))
            return 0
        packet, _ = _read_json(args.packet, "packet")
        ok, reason, suffix, patch_sha256, manifest_sha256 = verify_confirmation(packet, args.typed, args.ack)
        print(canonical_json({"ok": ok, "reason": reason, "argv": suffix,
                              "patch_sha256": patch_sha256, "manifest_sha256": manifest_sha256}))
        return 0 if ok else 12
    except Exception as exc:
        print(canonical_json({"ok": False, "reason": str(exc), "argv": []}), file=sys.stderr)
        return 12


def main() -> int:
    return _cli()


if __name__ == "__main__":
    raise SystemExit(main())
