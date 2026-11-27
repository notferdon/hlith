# SPDX-License-Identifier: Apache-2.0
"""The typed, versioned witness record (``obligations[i].witness_record``), derived from the recorded ``witness_call``.

``witness_call`` stays what replay executes and what every existing consumer reads. This record is a second, typed view
of the same call, used to decide whether a portable test can be written. ``adapt`` is deterministic and total: it never
refuses and never invents; what it does not recognise is listed under ``unknown`` (and then blocks export).

Text ``fidelity`` is read from the markers the engine writes into recorded text (tree-root and address masks, length
caps and digests). A repository string that merely contains such a marker is classed the same way: that errs towards
refusing an export, never towards asserting a value the recording did not keep verbatim.

An adapted record is only trusted when it equals ``adapt(witness_call)`` for the call that was replayed.
"""
from __future__ import annotations

import ast
import keyword
import math
import re
from typing import Any

SCHEMA_VERSION = 1

_CALL_KEYS = ("module", "qualname", "args", "kwargs", "receiver", "env", "inject", "throw", "phase")
_META_KEYS = ("oracle", "delta", "feedback_record_ids", "pre", "post", "truncated", "sha256", "size")
_ORACLES = ("differential", "declared-delta", "recorded-expected", "feedback-neighbor")
_CHANNELS = {"out": "output", "w": "warnings", "s": "receiver_state", "g": "writes"}
# outcome keys that say the value is not a plain, stable return or exception
_FLAGS = {"lazy": "lazy", "unrepr": "unrepresentable", "iter_raised": "iterator-raised", "rng": "random-state",
          "thr": "throw", "nothrow": "no-throw-method"}
# "wx": warnings from outside the target tree; the engine records them apart and never compares them
_OUTCOME_KEYS = ("k", "r", "t", "m", "mi", "wx", *_CHANNELS, *_FLAGS)

_TREE = re.compile(r"<tree>")
_ADDRESS = re.compile(r"0x\?|0x[0-9a-fA-F]{4,}")
_CAPPED = re.compile(r"…#[0-9a-f]{16}|\.\.\.<\d+ chars sha256:[0-9a-f]{16}>")
_OPAQUE = re.compile(r"<unrepresentable|<unwatched>|<state watch failed")


class NotExportable(Exception):
    """No portable test can honestly be written for this record; nothing is written."""


def _text(value: Any) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return {"text": repr(value), "fidelity": "opaque", "masks": []}
    masks = [name for name, pattern in (("tree-root", _TREE), ("address", _ADDRESS)) if pattern.search(value)]
    fidelity = ("opaque" if _OPAQUE.search(value) else "capped" if _CAPPED.search(value) else
                "masked" if masks else "exact")
    return {"text": value, "fidelity": fidelity, "masks": masks}


def _outcome(raw: Any) -> dict | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return {"kind": "other", "value": None, "type": None, "message": None, "role": "none",
                "channels": {name: None for name in _CHANNELS.values()}, "flags": [], "unknown": ["<not-an-object>"]}
    kind = {"ret": "return", "exc": "raise"}.get(raw.get("k") if isinstance(raw.get("k"), str) else "", "other")
    message = raw.get("mi") if raw.get("mi") is not None else raw.get("m")
    role = "none"
    if kind == "raise":
        role = ("data" if "mi" in raw else "behaviour") if raw.get("m") else "informational" if message else "none"
    return {
        "kind": kind,
        "value": _text(raw.get("r")) if kind == "return" else None,
        "type": raw.get("t") if isinstance(raw.get("t"), str) else None,
        "message": _text(message) if kind == "raise" else None,
        "role": role,
        "channels": {name: _text(raw.get(key)) for key, name in _CHANNELS.items()},
        "flags": sorted(name for key, name in _FLAGS.items() if raw.get(key)),
        "unknown": sorted(str(key) for key in raw if key not in _OUTCOME_KEYS),
    }


def adapt(witness_call: dict) -> dict:
    """The version-1 record of one recorded call. ``witness_call`` is not modified."""
    call = {key: witness_call.get(key) for key in _CALL_KEYS}
    call["args"] = [] if call["args"] is None else call["args"]
    call["kwargs"] = {} if call["kwargs"] is None else call["kwargs"]
    call["throw"] = bool(call["throw"])
    call["phase"] = "call" if call["phase"] is None else call["phase"]
    truncated = None
    if witness_call.get("truncated"):
        truncated = {"sha256": witness_call.get("sha256"), "size": witness_call.get("size")}
    return {
        "schema_version": SCHEMA_VERSION,
        "call": call,
        "oracle": witness_call.get("oracle") or "differential",
        "delta_id": witness_call.get("delta"),
        "feedback_record_ids": witness_call.get("feedback_record_ids"),
        "pre": _outcome(witness_call.get("pre")),
        "post": _outcome(witness_call.get("post")),
        "complete": truncated is None,
        "truncated": truncated,
        "unknown": sorted(str(key) for key in witness_call if key not in _CALL_KEYS and key not in _META_KEYS),
    }


def check_version(record: Any) -> None:
    if not isinstance(record, dict) or "schema_version" not in record:
        raise NotExportable("legacy-witness: no versioned witness record (recorded by an older engine); "
                            "it can be replayed but not exported; run the check again to record one")
    version = record["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise NotExportable(f"unsupported witness schema_version {version!r}; this build exports version {SCHEMA_VERSION}")


def record_for_export(witness_call: dict, record: Any) -> dict:
    """The stored record, accepted only if it is exactly the typed view of the call that was replayed."""
    check_version(record)
    if record != adapt(witness_call):
        raise NotExportable("witness record does not match the replayed witness_call")
    return record


def _has_special_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return any(isinstance(k, str) and (k.startswith("$") or k.startswith("__hlith_")) for k in value) or any(
            _has_special_marker(v) for v in value.values())
    return isinstance(value, (list, tuple)) and any(_has_special_marker(v) for v in value)


_MAX_ARG_DEPTH = 32


def _is_valid_dotted_name(name: Any) -> bool:
    if not isinstance(name, str) or not name:
        return False
    parts = name.split(".")
    return all(part.isidentifier() and not keyword.iskeyword(part) for part in parts)


def _has_dunder_part(name: str) -> bool:
    return any(part.startswith("__") and part.endswith("__") for part in name.split("."))


def _validate_plain_arg(value: Any, *, depth: int = 0) -> None:
    if depth > _MAX_ARG_DEPTH:
        raise NotExportable("witness arguments exceed maximum nesting depth; not portable")
    kind = type(value)
    if value is None or kind in (bool, int, str):
        return
    if kind is float:
        if not math.isfinite(value):
            raise NotExportable("witness arguments contain a non-finite float; not portable")
        return
    if kind in (list, tuple):
        for item in value:
            _validate_plain_arg(item, depth=depth + 1)
        return
    if kind is dict:
        for k, v in value.items():
            if type(k) is not str:
                raise NotExportable("witness arguments contain non-string dict keys; not portable")
            _validate_plain_arg(v, depth=depth + 1)
        return
    raise NotExportable("witness arguments are not plain data; not portable")


def _require_exact(text: dict, side: str, what: str) -> str:
    fidelity = text.get("fidelity")
    value = text.get("text")
    if fidelity == "capped":
        raise NotExportable(f"recorded {side} {what} is truncated by the engine cap; not portable")
    if fidelity == "masked":
        raise NotExportable(f"recorded {side} {what} contains a normalized placeholder/address; not portable")
    if fidelity != "exact" or not isinstance(value, str):
        raise NotExportable(f"recorded {side} {what} is not recorded verbatim; not portable")
    return value


def _expected(outcome: Any, side: str) -> dict:
    """One recorded side as what a test asserts; refuses anything the test would leave unchecked or could not check."""
    if not isinstance(outcome, dict) or outcome.get("kind") not in ("return", "raise"):
        raise NotExportable(f"witness has no recorded {side} return/exception outcome")
    if outcome.get("unknown"):
        raise NotExportable(f"recorded {side} outcome has unrecognised fields: {', '.join(map(str, outcome['unknown']))}")
    if outcome.get("flags"):
        raise NotExportable(f"recorded {side} outcome is not a plain stable value: {', '.join(map(str, outcome['flags']))}")
    channels = outcome.get("channels")
    if not isinstance(channels, dict) or set(channels) != set(_CHANNELS.values()):
        raise NotExportable(f"recorded {side} behaviour channels are missing or unrecognised")
    for name, label in (("output", "printed output"), ("warnings", "warnings channel"),
                        ("receiver_state", "receiver/argument state channel"), ("writes", "state-write channel")):
        text = channels[name]
        if text is not None and (not isinstance(text, dict) or text.get("text") != ""):
            raise NotExportable(f"witness records {side} {label}; the exported test cannot assert it")
    expected: dict = {}
    if outcome["kind"] == "return":
        if outcome.get("value") is None:
            raise NotExportable(f"witness has no recorded {side} return value; a kind-only check is vacuous")
        value = _require_exact(outcome["value"], side, "return")
        try:
            literal = ast.literal_eval(value)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            raise NotExportable(f"recorded {side} return is not a stable Python literal") from None
        if not isinstance(literal, (str, int, float, bool, type(None))):
            raise NotExportable(f"recorded {side} return is a container/opaque value; raw repr is not portable")
        if isinstance(literal, float) and not math.isfinite(literal):
            raise NotExportable(f"recorded {side} return is not a finite Python literal")
        expected.update(k="ret", r=value)
    else:
        message = outcome.get("message")
        if message is None or message.get("text") == "":
            raise NotExportable(f"recorded {side} exception has no message; type-only is vacuous")
        exc_type = outcome.get("type")
        if not isinstance(exc_type, str) or not exc_type or any(ord(ch) < 32 for ch in exc_type):
            raise NotExportable(f"recorded {side} exception has no valid type")
        expected.update(k="exc", t=exc_type, mi=_require_exact(message, side, "exception message"))
    if channels["output"] is not None:
        expected["out"] = ""
    return expected


def exportable(record: Any, expect: str, extra_sys_path: list[str] | None = None) -> dict:
    """What a portable one-call test needs: {module, qualname, args, kwargs, pre, post}. Raises NotExportable."""
    if expect not in ("pre", "post"):
        raise NotExportable("expected side must be 'pre' or 'post'")
    check_version(record)
    call = record.get("call")
    if not isinstance(call, dict) or set(call) != set(_CALL_KEYS) or set(record) != set(adapt({})):
        raise NotExportable("witness record is malformed or has unrecognised fields")
    if record["unknown"]:
        raise NotExportable(f"witness call has unrecognised fields: {', '.join(map(str, record['unknown']))}")
    if record["oracle"] not in _ORACLES:
        raise NotExportable(f"unrecognised witness oracle {record['oracle']!r}")
    if call["receiver"] is not None:
        raise NotExportable("receiver-bound witness cannot be a portable plain-call pytest")
    if call["env"]:
        raise NotExportable("witness depends on a recorded environment")
    if call["inject"] or call["throw"] or record["truncated"] is not None or record["complete"] is not True:
        raise NotExportable("witness needs evaluator machinery (inject/throw/truncated)")
    if call["phase"] != "call":
        raise NotExportable("witness is not a plain call (recorded during import)")
    if extra_sys_path:
        raise NotExportable("witness depends on absolute extra sys.path entries; not portable")
    args, kwargs = call["args"], call["kwargs"]
    if not isinstance(args, list) or not isinstance(kwargs, dict):
        raise NotExportable("witness arguments are malformed")
    if _has_special_marker(args) or _has_special_marker(kwargs):
        raise NotExportable("witness arguments contain an evaluator marker (float bits, bytes, tuple, path, callable or default); not portable")
    _validate_plain_arg(args)
    _validate_plain_arg(kwargs)
    module, qualname = call["module"], call["qualname"]
    if not _is_valid_dotted_name(module) or not _is_valid_dotted_name(qualname):
        raise NotExportable("witness has no importable module/qualname")
    if module == "hlith" or module.startswith("hlith."):
        raise NotExportable("witness targets hlith internals; exported tests must not depend on Hlith")
    if module == "builtins" or _has_dunder_part(module) or _has_dunder_part(qualname):
        raise NotExportable("witness callable shape is not a plain user callable; not portable")
    pre, post = _expected(record["pre"], "PRE"), _expected(record["post"], "POST")
    if (pre.get("k"), pre.get("r"), pre.get("t")) == (post.get("k"), post.get("r"), post.get("t")):
        raise NotExportable("recorded PRE and POST outcomes do not differ")
    return {"module": module, "qualname": qualname, "args": args, "kwargs": kwargs, "pre": pre, "post": post}
