# SPDX-License-Identifier: Apache-2.0
"""ONE validated artifact / event / receipt store for standalone, companion and headless runs.

Layout of a run: <runs>/<run_id>/{receipt.json, out.json, events.jsonl, events.v2.jsonl, meta.json, rc, change.patch, ...}.
``receipt.json`` is written by the coordinator FIRST (atomic, create-exclusive) and links the surface's invocation id, thread
id, mode, landing target and input origin to the engine-allocated RunId. ``read_run`` returns an explicit state derived from
data on disk; nothing is inferred when the data does not say it, and no verdict is synthesized.
"""

from __future__ import annotations

import enum
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..contract import codec
from ..contract.errors import EXIT_BOUNDARY
from ..contract.events import Event, EventKind, Phase
from ..contract.identities import InvocationId, RunId, ThreadId, run_id as _valid_run_id
from ..contract.runs import LandingTarget, RunMode, RunReceipt
from .origin import InputOrigin  # noqa: F401  (re-exported: leaf module, keeps schema <-> store acyclic)

MAX_BYTES = 64 * 1024 * 1024
LAUNCH_PREFIX = "launch-"
LINK = "engine-run.json"  # written in a LAUNCH directory by the engine once it has minted its RunId: {"run_id", "run_dir"}
_RUN_DIR = re.compile(r"^run-[0-9a-f]{12}$")
RECEIPT = "receipt.json"
ARTIFACT = "out.json"
EVENTS = "events.jsonl"
EVENTS_V2 = "events.v2.jsonl"


class RunState(str, enum.Enum):
    IN_PROGRESS = "in-progress"
    FINISHED = "finished"
    BOUNDARY_UNAVAILABLE = "boundary-unavailable"  # refused before judgement, no artifact written
    WITNESS_MISSING = "witness-missing"  # a refuting obligation that carries no witness
    UNREADABLE = "unreadable"
    SCHEMA_INVALID = "schema-invalid"
    ID_MISMATCH = "id-mismatch"  # artifact run id differs from the receipt: shown, never silently trusted
    LOST = "lost"
    CLONE_FAILED = "clone-failed"
    NO_RECORD = "no-record"


@dataclass(frozen=True)
class StoredReceipt:
    run: RunReceipt
    origin: InputOrigin
    repo_identity: str
    source_repo: str
    created_utc: str


@dataclass
class RunView:
    run_dir: Path
    state: RunState
    receipt: StoredReceipt | None = None
    artifact: dict | None = None
    errors: list[str] = field(default_factory=list)
    rc: int | None = None
    why: str | None = None
    feedback_problems: list[str] = field(default_factory=list)  # post-gate feedback recording/probe failures (the gate decision stands)

    @property
    def run_id(self) -> str | None:
        if self.receipt is not None:
            return str(self.receipt.run.run_id)
        run = (self.artifact or {}).get("run") or {}
        return run.get("run_id") if isinstance(run, dict) else None


def process_meta(run_id, source_repo: str) -> dict:
    """Liveness record of the process that owns a run (pid + start time, so a reused pid is not mistaken for it)."""
    pid = os.getpid()
    try:
        st = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        st = None
    return {"run_id": str(run_id), "started": time.time(), "pid": pid, "pid_starttime": st, "source_repo": source_repo}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_new(path: Path, data: bytes) -> None:
    """Create-exclusive, no-follow, 0600. The temp file is hard-linked into place (link fails if the target exists), so a
    half-written record is never visible and an existing record is never replaced."""
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, path)  # FileExistsError when the record exists
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def write_replace(path: Path, data: bytes) -> None:
    """Atomically replace a MUTABLE operator file (liveness record, exit code of a resumed run). Receipts, artifacts and events never
    use this: they are create-exclusive or append-only."""
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def write_receipt(run_dir: Path, receipt: RunReceipt, origin: InputOrigin, repo_identity: str, source_repo: str) -> StoredReceipt:
    stored = StoredReceipt(receipt, origin, repo_identity, source_repo, utc_now())
    body = {"format": codec.SCHEMA_VERSION, "run_id": receipt.run_id, "invocation_id": receipt.invocation_id,
            "thread_id": receipt.thread_id, "mode": receipt.mode, "landing_target": receipt.landing_target,
            "origin": origin, "repo_identity": repo_identity, "source_repo": source_repo, "created_utc": stored.created_utc}
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_new(run_dir / RECEIPT, codec.canonical_bytes(body) + b"\n")
    return stored


def engine_run_dir(launch_dir: Path) -> Path | None:
    """The engine's own run directory for a LAUNCH directory (a surface's working directory for one launch). The engine alone mints
    the RunId, so the launcher cannot know the run directory in advance: the engine writes ``engine-run.json`` into the launch
    directory at its first event. The link is trusted only if it names a ``run-<12 hex>`` directory that is a sibling of the launch
    directory (same runs root); anything else is ignored."""
    try:
        d = json.loads((Path(launch_dir) / LINK).read_text("utf-8"))
        rid = _valid_run_id(d["run_id"])
        target = Path(d["run_dir"])
        if target.name != rid or not _RUN_DIR.fullmatch(target.name) or target.parent.resolve() != Path(launch_dir).resolve().parent:
            return None
        return target if target.is_dir() and not target.is_symlink() else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def read_receipt(run_dir: Path) -> StoredReceipt | None:
    if not (Path(run_dir) / RECEIPT).exists():
        linked = engine_run_dir(Path(run_dir))
        if linked is not None:
            run_dir = linked
    try:
        d = json.loads((run_dir / RECEIPT).read_text("utf-8"))
        rid = _valid_run_id(d["run_id"])
        rr = RunReceipt(rid, InvocationId(d["invocation_id"]), ThreadId(d["thread_id"]) if d.get("thread_id") else None,
                        RunMode(d["mode"]), LandingTarget(d["landing_target"]))
        return StoredReceipt(rr, InputOrigin(d.get("origin", "unknown")), str(d.get("repo_identity", "")),
                             str(d.get("source_repo", "")), str(d.get("created_utc", "")))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _load_json_file(p: Path) -> tuple[dict | None, str | None]:
    try:
        if p.stat().st_size > MAX_BYTES:
            return None, f"file larger than {MAX_BYTES} bytes"
        raw = p.read_bytes()
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, f"{e.strerror or e}"
    if not raw.strip():
        return None, "the file is empty"
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return None, f"not JSON: {str(e)[:160]}"
    if not isinstance(obj, dict):
        return None, "JSON, but not an object"
    return obj, None


def witness_gaps(art: dict) -> list[str]:
    """Refuting obligations that name no witness. Reported as a state; the verdict itself is never rewritten."""
    return [str(o.get("id")) for o in art.get("obligations") or []
            if o.get("verdict") == "refuted" and not str(o.get("witness") or "").strip()]


def feedback_problems(run_dir: Path) -> list[str]:
    """Post-gate feedback failures recorded as PROGRESS events (``feedback_error``) in the run's event store."""
    evs, _ = read_events(run_dir)
    return [str(e.detail["feedback_error"]) for e in evs if e.kind is EventKind.PROGRESS and "feedback_error" in e.detail]


def read_run(run_dir: Path, *, alive=None) -> RunView:
    view = _read_run(run_dir, alive=alive)
    if view.artifact is not None:
        view.feedback_problems = feedback_problems(run_dir if (Path(run_dir) / EVENTS_V2).exists() else (engine_run_dir(Path(run_dir)) or run_dir))
    return view


def _read_run(run_dir: Path, *, alive=None) -> RunView:
    """Every state is derived from data on disk. ``alive(run_dir) -> bool`` is supplied by the launcher (process liveness)."""
    d = Path(run_dir)
    receipt = read_receipt(d)
    art, err = _load_json_file(d / ARTIFACT)
    rc = None
    rcf = d / "rc"
    if rcf.exists():
        raw = rcf.read_text().strip()
        if raw == "clone-failed":
            return RunView(d, RunState.CLONE_FAILED, receipt, why="the disposable clone could not be made")
        try:
            rc = int(raw)
        except ValueError:
            return RunView(d, RunState.UNREADABLE, receipt, errors=[f"unreadable exit code file: {raw!r}"])
    if err is not None:
        return RunView(d, RunState.UNREADABLE, receipt, errors=[err], rc=rc)
    if art is None:
        if rc is None:
            if alive is not None and alive(d):
                return RunView(d, RunState.IN_PROGRESS, receipt)
            if receipt is None and not (d / "meta.json").exists():
                return RunView(d, RunState.NO_RECORD, None, why="no receipt, artifact or process record")
            return RunView(d, RunState.LOST, receipt, why="the process is gone and no exit code was recorded")
        if rc == EXIT_BOUNDARY:
            return RunView(d, RunState.BOUNDARY_UNAVAILABLE, receipt, rc=rc,
                           why="the engine refused before judging (boundary); it wrote no artifact")
        return RunView(d, RunState.LOST, receipt, rc=rc, why=f"the engine exited {rc} and wrote no artifact")
    from .schema import artifact_errors

    run_info = art.get("run") if isinstance(art.get("run"), dict) else {}
    if receipt is not None and run_info.get("run_id") not in (None, receipt.run.run_id):
        return RunView(d, RunState.ID_MISMATCH, receipt, art,
                       [f"artifact run id {run_info.get('run_id')!r} != receipt {receipt.run.run_id!r}"], rc)
    errs = artifact_errors(art)
    if errs:
        return RunView(d, RunState.SCHEMA_INVALID, receipt, art, errs, rc)
    gaps = witness_gaps(art)
    if gaps:
        return RunView(d, RunState.WITNESS_MISSING, receipt, art, [f"refuted without a witness: {', '.join(gaps)}"], rc)
    return RunView(d, RunState.FINISHED, receipt, art, [], rc)


def list_runs(runs_root: Path, *, alive=None) -> list[RunView]:
    out: list[RunView] = []
    if runs_root.is_dir():
        for d in sorted(runs_root.iterdir(), reverse=True):
            if d.is_dir() and not d.is_symlink() and not d.name.startswith(LAUNCH_PREFIX):  # launch dirs are a surface's, not runs
                v = read_run(d, alive=alive)
                if v.state is not RunState.NO_RECORD:
                    out.append(v)
    return out


# ---- events: contract Event lines (format 2) and the engine's legacy lines through one reader ----------------------------

_PHASE = {"stage_and_worker": Phase.RUNTIME, "derive": Phase.OBLIGATION, "account": Phase.EFFECT,
          "differential": Phase.OBLIGATION, "declare": Phase.EFFECT, "gate": Phase.GATE, "resume": Phase.RUNTIME, "run": None}


def append_event(run_dir: Path, ev: Event) -> None:
    body = {"format": codec.SCHEMA_VERSION, "run_id": ev.run_id, "seq": ev.seq, "kind": ev.kind, "phase": ev.phase,
            "ts": ev.ts, "detail": ev.detail}
    fd = os.open(run_dir / EVENTS_V2, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, codec.canonical_bytes(body) + b"\n")
    finally:
        os.close(fd)


def read_events(run_dir: Path, run_id: str | None = None) -> tuple[list[Event], list[str]]:
    """(events, problems). Format-2 lines are validated by ``Event`` itself (a progress line carrying a verdict is rejected and
    reported). Legacy engine lines map to phase/progress events only: a legacy 'end' outcome is NOT turned into a DECISION;
    decisions come from the gate receipt in the artifact."""
    evs: list[Event] = []
    problems: list[str] = []
    v2 = run_dir / EVENTS_V2
    if v2.is_file():
        for n, line in enumerate(v2.read_text("utf-8", "replace").splitlines(), 1):
            try:
                d = json.loads(line)
                evs.append(Event(RunId(d["run_id"]), int(d["seq"]), EventKind(d["kind"]),
                                 Phase(d["phase"]) if d.get("phase") else None, str(d["ts"]), dict(d.get("detail") or {})))
            except (ValueError, KeyError, TypeError) as e:
                problems.append(f"{EVENTS_V2}:{n}: {str(e)[:120]}")
    leg = run_dir / EVENTS
    if leg.is_file():
        kinds = {"start": EventKind.PHASE_STARTED, "end": EventKind.PHASE_FINISHED, "progress": EventKind.PROGRESS}
        for n, line in enumerate(leg.read_text("utf-8", "replace").splitlines(), 1):
            try:
                d = json.loads(line)
                kind = kinds.get(d.get("event"))
                if kind is None:
                    continue
                detail = {k: v for k, v in d.items() if k in ("target", "i", "n")}
                evs.append(Event(RunId(run_id or "run-000000000000"), int(d.get("seq", n)), kind,
                                 _PHASE.get(d.get("phase")), str(d.get("ts", d.get("t", ""))), detail))
            except (ValueError, TypeError) as e:
                problems.append(f"{EVENTS}:{n}: {str(e)[:120]}")
    return evs, problems
