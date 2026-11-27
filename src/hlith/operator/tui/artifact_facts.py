# SPDX-License-Identifier: Apache-2.0
"""Pure read-only artifact fact helpers shared by TUI frame, agent_note, and feedback_view."""

from __future__ import annotations

import re
import unicodedata

from .. import labels
from ..schema import artifact_errors


def clean(value) -> str:
    """The single renderer sanitizer: make controls visible and keep cells terminal-safe."""
    source = str(value)
    out = []
    for ch in source:
        codepoint = ord(ch)
        category = unicodedata.category(ch)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            out.append(f"\\x{codepoint:02x}")
        elif category == "Cf" or unicodedata.combining(ch):
            out.append(f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}")
        elif unicodedata.category(ch) in {"Mn", "Me"}:
            out.append(f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}")
        elif unicodedata.east_asian_width(ch) in {"W", "F"}:
            out.append("?")
        elif ch.isprintable():
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def valid_commit_id(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value) is not None


def validation_errors(artifact: dict) -> list[str]:
    if not isinstance(artifact, dict):
        return ["record is not a JSON object"]
    try:
        errors = list(artifact_errors(artifact))
    except Exception as exc:
        return [f"record validation failed: {type(exc).__name__}"]
    if artifact.get("landed_commit") is not None and not valid_commit_id(artifact.get("landed_commit")):
        errors.append("$.landed_commit: must be a full 40- or 64-character hexadecimal commit id")
    return errors


def decision(artifact: dict, errors=None) -> tuple[str, str, int | None]:
    if errors is None:
        errors = validation_errors(artifact)
    if errors:
        return "UNKNOWN (UNVALIDATED RECORD)", "dim", None
    outcome, status = artifact.get("outcome"), artifact.get("exit_status")
    if (outcome is not None and type(outcome) is not str) or (status is not None and type(status) is not int):
        return "UNKNOWN (UNVALIDATED RECORD)", "dim", None
    headline, tone = labels.decision(outcome, status)
    return headline, tone, status if type(status) is int else None


def obligations(artifact):
    rows = artifact.get("obligations", []) if isinstance(artifact, dict) else []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def blocking_entries(artifact):
    entries = artifact.get("blocking") if isinstance(artifact, dict) else None
    return [entry for entry in entries if isinstance(entry, str) and entry] if isinstance(entries, list) else []


def integrity_errors(artifact, dec):
    obls = obligations(artifact)
    obligation_by_id = {
        str(row.get("id")): row
        for row in obls
        if row.get("id")
    }
    unheld = {
        obligation_id
        for obligation_id, row in obligation_by_id.items()
        if row.get("verdict") != "held"
    }
    if dec[0] == "LANDED" and unheld:
        return ["record inconsistent: an obligation is not held although the engine recorded LANDED"]
    if dec[0].startswith("REFUSED"):
        blocking = set(blocking_entries(artifact))
        if not blocking:
            return ["record inconsistent: the refusal has no blocking reason"]
        if blocking <= obligation_by_id.keys() and all(
            obligation_by_id[obligation_id].get("verdict") == "held"
            for obligation_id in blocking
        ):
            return ["record inconsistent: refusal names only held obligations"]
    return []


def plain_blocking(artifact):
    entries = blocking_entries(artifact)
    if not entries:
        return []
    ids = {row.get("id") for row in obligations(artifact)}
    return [] if entries[0] in ids else entries


def parse_witness(witness):
    text = clean(witness)
    pre_marker = ": pre -> "
    post_marker = "; post -> "
    if text.count(pre_marker) != 1 or text.count(post_marker) != 1 or " || printed:" in text:
        return None
    left, before = text.split(pre_marker)
    before, after = before.split(post_marker)
    if not before.strip() or not after.strip() or "\n" in text or "\r" in text:
        return None
    for pinned_prefix in ("pinned-neighbor", "pinned"):
        if left.startswith(pinned_prefix + " "):
            input_text = left[len(pinned_prefix) + 1:]
            if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\([^;\r\n]*\)", input_text):
                return None
            return pinned_prefix, input_text, before.strip(), after.strip()
    for multi_via in ("entry-seed pairwise neighbourhood", "entry-seed neighbourhood"):
        if left.startswith(multi_via + " "):
            input_text = left[len(multi_via) + 1:]
            if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\([^;\r\n]*\)", input_text):
                return None
            return multi_via, input_text.strip(), before.strip(), after.strip()
    via, space, input_text = left.partition(" ")
    known_via = (
        via.startswith("z3:")
        or via in {"seed", "collected"}
        or (via.endswith("-seed") and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}", via) is not None)
    )
    if (not space or not known_via
            or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\([^;\r\n]*\)", input_text)):
        return None
    return via, input_text.strip(), before.strip(), after.strip()


def run_id(artifact: dict) -> str:
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    proposer = (artifact.get("effect") or {}).get("proposer_id") if isinstance(artifact.get("effect"), dict) else None
    if isinstance(proposer, str) and proposer.startswith("SAMPLE-ONLY"):
        return "not recorded"
    rid = run.get("run_id")
    return clean(rid) if isinstance(rid, str) and rid else "not recorded"
