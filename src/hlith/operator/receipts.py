# SPDX-License-Identifier: Apache-2.0
"""Glass Box operator receipts: append-only and annotation-only.

An annotation records what the operator did (inspected, quarantined, escalated, noted) beside a run. It never overrides a
refusal, never lands, never feeds the gate or L3/L5, and the gate never reads it: it is not a second gate. Annotations are
hash-chained so tampering or reordering is detectable; chain validity is reported, never repaired. The lifecycle is built because it is non-authoritative by construction.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
from pathlib import Path

from ..contract import codec
from .store import utc_now

FILE = "annotations.jsonl"
MAX_NOTE = 1000
GENESIS = "0" * 64


class Action(str, enum.Enum):
    INSPECTED = "inspected"
    QUARANTINED = "quarantined"  # operator marks the run suspect; no engine effect
    ESCALATED = "escalated"  # operator flags it for a human/design review; no engine effect
    NOTE = "note"


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256(prev.encode() + b"\n" + codec.canonical_bytes(body)).hexdigest()


def operator_identity() -> str:
    """Who the operator CLAIMS to be: the OS user name on this machine. Recorded beside each annotation as a plain claim, NOT an
    authenticated identity (hlith has no accounts and no network); it identifies the local user, nothing more."""
    try:
        import getpass

        return getpass.getuser()[:64]
    except Exception:  # noqa: BLE001 - an unknown user is recorded as unknown, never invented
        return "unknown"


def read_annotations(run_dir: Path) -> list[dict]:
    """Every line, in order, each with ``chain_ok``. A broken link marks that line and every later one not ok."""
    p = Path(run_dir) / FILE
    out: list[dict] = []
    if not p.is_file():
        return out
    prev, ok = GENESIS, True
    for line in p.read_text("utf-8", "replace").splitlines():
        try:
            d = json.loads(line)
            body = {k: d[k] for k in ("seq", "ts", "action", "note", "prev", "operator") if k in d}
            ok = ok and d.get("prev") == prev and d.get("sha256") == _digest(prev, body)
            prev = d.get("sha256", prev)
            out.append({**body, "sha256": d.get("sha256"), "chain_ok": ok, "authority": "annotation-only"})
        except (ValueError, KeyError, TypeError):
            ok = False
            out.append({"seq": None, "action": "unreadable", "note": line[:80], "chain_ok": False, "authority": "annotation-only"})
    return out


def annotate(run_dir: Path, action: Action, note: str = "") -> dict:
    """Append one annotation (append-only, no-follow, 0600). Returns it. Raises nothing about the run's decision."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(str(run_dir))
    existing = read_annotations(run_dir)
    prev = existing[-1]["sha256"] if existing and existing[-1].get("sha256") else GENESIS
    body = {"seq": len(existing) + 1, "ts": utc_now(), "action": Action(action).value, "note": str(note)[:MAX_NOTE], "prev": prev,
            "operator": operator_identity()}
    rec = {**body, "sha256": _digest(prev, body)}
    fd = os.open(run_dir / FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, json.dumps(rec, sort_keys=True).encode() + b"\n")
    finally:
        os.close(fd)
    return {**rec, "chain_ok": True, "authority": "annotation-only"}
