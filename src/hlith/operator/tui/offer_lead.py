# SPDX-License-Identifier: Apache-2.0
"""What the Offer must lead with when the operator comes back (operator spec 4.6): a check still RUNNING in this repository, or a decision that finished while they were away and
that they have not opened yet. Reopening hlith must not show only a records line.

PURE selection (`pick`) over the history rows the host already scans, plus a tiny "seen" store: the run ids whose Verdict the operator has opened. Nothing here starts, cancels,
approves or decides anything, and a missing or unreadable store simply means "nothing is known to be seen" (it never hides a running check).

Bounds, stated: only runs of THIS repository; only decisions from the last 24 hours (so a store full of old, never-opened runs does not greet the operator with ancient news);
the store keeps the newest 500 ids.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

RECENT_SECONDS = 24 * 3600
KEEP = 500
_NAME = "seen-decisions.json"


def _same_repo(row_repo, repo_path) -> bool:
    try:
        return bool(row_repo) and Path(str(row_repo)).resolve() == Path(str(repo_path)).resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def pick(rows, repo_path, seen, now: float | None = None) -> dict | None:
    """The newest running check of this repository, else its newest finished-but-unseen decision from the last 24 hours; None otherwise.
    Returns {"kind": "running" | "new", "run_id", "decision", "age"} (display facts copied from the row; nothing is computed or invented)."""
    now = time.time() if now is None else now
    seen = seen or set()
    mine = [r for r in (rows or []) if isinstance(r, dict) and _same_repo(r.get("source_repo"), repo_path)]
    for row in mine:
        if row.get("state") == "running" and row.get("run_id"):
            return {"kind": "running", "run_id": str(row["run_id"]), "decision": "", "age": str(row.get("age") or "")}
    for row in mine:
        if row.get("state") != "finished" or not row.get("decision") or not row.get("run_id") or str(row["run_id"]) in seen:
            continue
        try:
            recent = now - float(row.get("when")) <= RECENT_SECONDS
        except (TypeError, ValueError):
            recent = False
        if recent:
            return {"kind": "new", "run_id": str(row["run_id"]), "decision": str(row["decision"]), "age": str(row.get("age") or "")}
    return None


def superseded_ids(rows, run_id) -> list:
    """The finished runs of the SAME repository as `run_id` (taken from that run's own row) that are NOT newer than it: once the operator has opened the newest decision, those older
    ones are superseded and stop leading the Offer (they stay in History). Newer ones are never included."""
    this = next((r for r in (rows or []) if isinstance(r, dict) and str(r.get("run_id")) == str(run_id)), None)
    mine = [r for r in (rows or []) if isinstance(r, dict) and this is not None and _same_repo(r.get("source_repo"), this.get("source_repo"))]
    try:
        cutoff = float(this.get("when")) if this else None
    except (TypeError, ValueError):
        cutoff = None
    out = [str(run_id)]
    if cutoff is None:
        return out
    for r in mine:
        try:
            if r.get("state") == "finished" and r.get("decision") and str(r.get("run_id")) != str(run_id) and float(r.get("when")) <= cutoff:
                out.append(str(r["run_id"]))
        except (TypeError, ValueError):
            continue
    return out


def _path(state_dir) -> Path:
    return Path(state_dir) / _NAME


def load_seen(state_dir) -> set:
    try:
        data = json.loads(_path(state_dir).read_text(encoding="utf-8"))
        ids = data.get("run_ids") if isinstance(data, dict) else None
        return {str(x) for x in ids} if isinstance(ids, list) else set()
    except (OSError, ValueError):
        return set()


def mark_seen(state_dir, run_id) -> bool:
    """Record that this run's Verdict (or each id of a list) was opened. Atomic (temp file + rename), bounded, and never raises: a convenience, not a reason to fail the screen."""
    new_ids = [str(x) for x in (run_id if isinstance(run_id, (list, tuple)) else [run_id]) if x]
    if not new_ids:
        return False
    try:
        base = Path(state_dir)
        base.mkdir(parents=True, exist_ok=True)
        ids = [i for i in _read_list(base) if i not in new_ids] + new_ids
        fd, tmp = tempfile.mkstemp(dir=base, prefix=".seen-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"run_ids": ids[-KEEP:]}, f)
        os.replace(tmp, _path(base))
        return True
    except OSError:
        return False


def _read_list(base: Path) -> list:
    try:
        data = json.loads(_path(base).read_text(encoding="utf-8"))
        ids = data.get("run_ids") if isinstance(data, dict) else None
        return [str(x) for x in ids] if isinstance(ids, list) else []
    except (OSError, ValueError):
        return []
