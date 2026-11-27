# SPDX-License-Identifier: Apache-2.0
"""THE operator session API. CLI, headless ``check`` and the native TUI call only this; none of them reach into the engine,
mint run ids, or read artifacts directly. (The cli <-> check_cmd import cycle is gone: both are clients of this module.)

Rules enforced here:
* the coordinator allocates RunId; ``launch`` writes the linking receipt before anything starts;
* rehearsal landings are labelled rehearsal; a supplied patch is labelled as supplied, never as an observed agent run;
* no verdict is computed here: ``inspect`` returns the recorded decision or an honest non-decision state;
* local-first, offline: no network, no telemetry; only the ``runs`` namespace is written.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..contract.identities import RunId, run_id as _valid_run_id
from ..contract.runs import RunReceipt
from ..hostio import LocalHostState
from . import labels, run_index, store
from .coordinator import Coordinator, RequestError, RunOutcome, RunRequest
from .pipeline import PipelineCapabilities
from .state import HostIntegrityError, LocalState, legacy_ui_state, state_root, ui_directory

__all__ = ["OperatorApi", "Inspection", "RequestError", "RunRequest", "PipelineCapabilities", "RunOutcome"]


@dataclass(frozen=True)
class Inspection:
    """Everything a surface may show about one run, from real data only."""

    view: store.RunView
    label: str
    tone: str
    notes: tuple[str, ...]
    events: tuple
    event_problems: tuple[str, ...]
    annotations: tuple[dict, ...]

    @property
    def run_id(self) -> str | None:
        return self.view.run_id


def _pid_alive(meta: dict) -> bool:
    pid = meta.get("pid")
    if not isinstance(pid, int):
        return False
    try:
        os.kill(pid, 0)
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return False
    return stat[0] != "Z" and (meta.get("pid_starttime") in (None, stat[19]))


def _alive(run_dir: Path) -> bool:
    try:
        return _pid_alive(json.loads((run_dir / "meta.json").read_text()))
    except (OSError, ValueError):
        return False


class OperatorApi:
    def __init__(self, state: LocalState | None = None) -> None:
        self.state = state or LocalState()
        self.coordinator = Coordinator(self.state)

    # ---- start --------------------------------------------------------------------------------------------------------
    def run_inline(self, req: RunRequest, caps: PipelineCapabilities, *, on_start=None) -> RunOutcome:
        """One run through the trusted pipeline in this process (headless); capabilities are injected at assembly."""
        return self.coordinator.execute(req, caps, on_start=on_start)

    @staticmethod
    def reserve_launch_dir(state_dir: Path, repo: Path) -> Path:
        """The PATH of one future launch directory, with NOTHING created (case): planning a launch (a surface's Claim) must leave the state directory
        untouched; the surface creates the directory when the run really starts (the same ``<state>/host/repositories/<identity>/runs/launch-<12 hex>``
        layout ``new_launch_dir`` makes). The identity reads the repository's root commits only; a repository that cannot be identified maps to
        ``repo-unbound`` exactly as ``new_launch_dir`` does."""
        host_root = state_root(state_dir)
        try:
            ident = LocalHostState(host_root).stable_repo_identity(Path(repo))
        except HostIntegrityError:
            ident = "repo-unbound"
        return host_root / "repositories" / ident / "runs" / (store.LAUNCH_PREFIX + secrets.token_hex(6))

    def new_launch_dir(self, repo: Path) -> Path:
        """A surface's working directory for ONE launch (wrapper logs, exit code, the engine's link). It is not a run: the engine
        alone mints the RunId and tells the launcher which run directory is its own through ``engine-run.json``."""
        try:
            ident = self.state.stable_repo_identity(Path(repo))
        except HostIntegrityError:  # not a plain git repository: the launch still gets a directory so the engine's own refusal is shown
            ident = "repo-unbound"
        root = self.state.namespace(ident, "runs")
        d = root / (store.LAUNCH_PREFIX + secrets.token_hex(6))
        d.mkdir(mode=0o700)
        return d

    def run_sync(self, req: RunRequest, argv_for, timeout: float | None = None):
        """Engine run to completion (headless ``check``). ``argv_for(launch_dir) -> argv`` builds the engine command (it names
        ``launch_dir/engine-run.json`` as ``--run-link``). Returns (launch_dir, run_dir | None, rc, stdout, stderr): ``run_dir`` is
        the ENGINE's run directory (None if the engine never reached its first event, e.g. a boundary refusal)."""
        self.coordinator._validate_surface(req)
        launch = self.new_launch_dir(req.repo)
        argv = list(argv_for(launch))
        (launch / "cmd.txt").write_text(" ".join(argv) + "\n")
        try:
            cp = subprocess.run(argv, cwd=str(launch), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
            rc, out, err = cp.returncode, cp.stdout, cp.stderr
        except subprocess.TimeoutExpired as e:
            rc, out, err = 124, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "timed out"
        (launch / "stdout.log").write_text(out)
        (launch / "stderr.log").write_text(err)
        store.write_new(launch / "rc", f"{rc}\n".encode())
        return launch, store.engine_run_dir(launch), rc, out, err

    # ---- read ---------------------------------------------------------------------------------------------------------
    def runs(self, repo: Path, *, include_legacy: bool = True) -> list[store.RunView]:
        d = self.state.existing_runs_dir(repo)  # a viewer never creates state
        out = store.list_runs(d, alive=_alive) if d is not None else []
        if include_legacy:  # pre-freeze UI runs: read-only, original schema identity, no receipt
            legacy = store.list_runs(legacy_ui_state() / "runs", alive=_alive)
            want = str(Path(repo).resolve())
            for v in legacy:
                meta = {}
                try:
                    meta = json.loads((v.run_dir / "meta.json").read_text())
                except (OSError, ValueError):
                    pass
                if meta.get("source_repo") == want:
                    out.append(v)
        return out

    def history_candidates(self, repo: Path):
        """Resolve the shared, read-only history roots and rank their repo runs."""
        roots = run_index.history_bases(ui_directory(), repo=repo, extra_roots=(self.state.root,))
        return run_index.ranked_run_candidates(roots, repo=repo)

    def find(self, repo: Path, run_id: str) -> Path | None:
        rid = _valid_run_id(run_id)
        candidates, *_ = self.history_candidates(repo)
        return next((path for _, path in candidates if path.name == rid), None)

    def inspect(self, run_dir: Path) -> Inspection:
        view = store.read_run(run_dir, alive=_alive)
        label, tone, notes = labels.headline(view)
        events, problems = store.read_events(run_dir, view.run_id)
        from .receipts import read_annotations

        return Inspection(view, label, tone, tuple(notes), tuple(events), tuple(problems), tuple(read_annotations(store.engine_run_dir(Path(run_dir)) or run_dir)))

    def inspect_artifact_file(self, path: Path) -> Inspection:
        """Open a bare artifact file (headless inspection of a saved out.json): no receipt, so the target/origin are 'not recorded'."""
        p = Path(path)
        d = p.parent
        if p.name == store.ARTIFACT and d.is_dir():
            return self.inspect(d)
        art, err = store._load_json_file(p)
        state = store.RunState.UNREADABLE if err else store.RunState.FINISHED
        view = store.RunView(d, state, None, art, [err] if err else [])
        if art is not None:
            from .schema import artifact_errors

            errs = artifact_errors(art)
            if errs:
                view = store.RunView(d, store.RunState.SCHEMA_INVALID, None, art, errs)
            elif store.witness_gaps(art):
                view = store.RunView(d, store.RunState.WITNESS_MISSING, None, art, [f"refuted without a witness: {', '.join(store.witness_gaps(art))}"])
        label, tone, notes = labels.headline(view)
        return Inspection(view, label, tone, tuple(notes), (), (), ())
