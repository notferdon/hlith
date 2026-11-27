# SPDX-License-Identifier: Apache-2.0
"""Find recorded artifacts: explicit files, directories (non-recursive *.json), and the UI's own run directories."""

from __future__ import annotations

from pathlib import Path

from ..state import ui_directory
from . import model


def state_dir(explicit: str | Path | None = None) -> Path:
    """Resolve the UI state root once; LocalState applies the shared ``host/`` namespace below it."""
    if explicit is not None:
        return Path(explicit).expanduser()
    return ui_directory()


def _stamp(r: model.Record) -> str:
    run = (r.art or {}).get("run") if r.usable else None
    return str(run.get("started_at_utc")) if isinstance(run, dict) and run.get("started_at_utc") else ""


def discover(paths) -> list[model.Record]:
    """Records for each given file; each directory contributes its *.json files that look like artifacts (others are skipped
    silently). Newest first by the artifact's own start time, then file mtime. A missing explicit path stays in the list as
    a NO RECORD entry (so the operator sees it was asked for)."""
    recs: list[model.Record] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in [*sorted(p.glob("*.json")), *sorted(p.glob("*/out.json"))]:  # also the UI's own run directories
                r = model.load(f)
                if r.usable:
                    recs.append(r)
        else:
            recs.append(model.load(p))

    def key(r: model.Record):
        try:
            mt = r.path.stat().st_mtime
        except OSError:
            mt = 0.0
        return (_stamp(r), mt)

    return sorted(recs, key=key, reverse=True)


def run_roots(repo=None, state=None) -> list[Path]:
    """Directories holding run records: the operator store (<host>/repositories/<repo-identity>/runs, one repository or all) plus the
    pre-freeze UI layout (<state>/runs, read-only history). Only existing directories are returned."""
    from ..state import LocalState

    base = state_dir(state)
    roots = [base / "runs"]
    ls = LocalState(base)
    if repo is not None:
        d = ls.existing_runs_dir(Path(repo))
        if d is not None:
            roots.append(d)
    else:
        roots += sorted((ls.root / "repositories").glob("*/runs"))
    return [r for r in roots if r.is_dir()]
