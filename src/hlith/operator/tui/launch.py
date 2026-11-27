# SPDX-License-Identifier: Apache-2.0
"""Launch the EXISTING engine (`hlith run`) as a detached subprocess and read its lifecycle back.

Safety: the engine is only ever pointed at a DISPOSABLE CLONE made here (never the source repo or any live tree); the command is
the one a human would type and is shown verbatim; there is no approval flag; the run survives the UI (own session, no controlling
terminal); lifecycle = process existence + an exit-code file written by the wrapper + elapsed time. Nothing about phases is invented
(the engine prints only when it finishes)."""

from __future__ import annotations

import heapq
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .. import run_index
from ..state import state_root as engine_state_root
from ..policy import strict_requested
from . import history, model


@dataclass
class Plan:
    run_id: str
    run_dir: Path
    source_repo: Path
    clone: Path
    argv: list[str]
    patch: Path | None
    manifest: Path | None
    worker_cmd: str | None
    patch_bytes: bytes | None = None  # a change the UI generated: written into the run directory before the engine starts
    manifest_obj: dict | None = None
    base_rev: str | None = None  # the clone is moved to this commit first (a commit's parent, a merge-base); None = the repo's HEAD
    label: str = ""
    reuse_clone: Path | None = None  # an intended-change rerun runs in the clone of the refused run (never in the operator's own repository)
    proposer_command: str | None = None
    thread_store: Path | None = None
    resume_thread_id: str | None = None
    redo_inflight: bool = False
    in_flight_turn: int | None = None
    checkpoint_id: str | None = None
    state: Path | None = None  # the UI state directory this plan was made under (feedback store, history)
    manifest_bytes: bytes | None = None  # exact companion manifest snapshot, if supplied with patch_bytes
    reserved: bool = False  # run_dir is a RESERVED name (planning creates nothing); launch.start creates it exactly once

    @property
    def artifact(self) -> Path:
        return self.run_dir / "out.json"

    def display(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


_INVOCATION = "inv-" + secrets.token_hex(6)  # this UI session's own id: LINKED to every run it starts, never used as a run id
_MAX_HISTORY_REPOSITORIES = 1024  # repository folders read per scan (was 64: a store with 785 of them hid the operator's own run); the run-candidate cap below still bounds the work
_MAX_HISTORY_RUNS = 64
_MAX_HISTORY_SCAN_CANDIDATES = 5000
_SCAN_WINDOW = 64  # directory handles the history scan keeps open at once (see _ranked_run_candidates)
_MAX_HISTORY_START_SKEW = 24 * 60 * 60
_MAX_HISTORY_SUMMARY_ARTIFACT_BYTES = 1024 * 1024
_MAX_RUN_META_BYTES = 64 * 1024
_MAX_RUN_RC_BYTES = 64
_RUN_DIR = re.compile(r"(?:launch|run)-[0-9a-f]{12}\Z")
_REPO_DIR = re.compile(r"repo-[0-9a-f]{24}\Z")


def _api(state=None):
    """The operator API always uses the TUI's canonical state root and host namespace."""
    from ..api import OperatorApi
    from ..state import LocalState

    return OperatorApi(LocalState(history.state_dir(state)))


def find_pairs(dirs) -> list[tuple[Path, Path | None]]:
    """Saved proposed changes: each *.patch / *.diff with its manifest by name (`STEM.manifest.json` or `STEM.json`). A patch without a
    manifest is listed with None (the engine will end 12 'manifest missing': shown, not hidden)."""
    out: list[tuple[Path, Path | None]] = []
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.suffix in (".patch", ".diff") and p.is_file():
                m = next((c for c in (p.with_name(p.stem + ".manifest.json"), p.with_name(p.stem + "-manifest.json"),
                                      p.with_name(p.stem + ".json")) if c.is_file()), None)
                out.append((p, m))
    return out


def _reserve_launch_dir(state: Path, src: Path) -> Path:
    """case: the name of ONE future launch directory, with NOTHING created. Planning (entering Claim) must leave the state directory untouched:
    a directory that exists for a run that never started would be listed by History as a LOST run. launch.start creates it."""
    from ..api import OperatorApi

    path = OperatorApi.reserve_launch_dir(history.state_dir(state), src)  # path only: the operator API owns the identity and layout
    _require_writable_state(path)
    return path


def _require_writable_state(path: Path) -> None:
    """case: planning creates nothing (case), so an unwritable state directory must be caught HERE, before the operator walks the command review:
    the nearest EXISTING ancestor of the future launch directory must allow creating entries (write + search). Nothing is created or modified."""
    a = Path(path).parent
    while not a.exists() and a != a.parent:
        a = a.parent
    if not a.is_dir() or not os.access(a, os.W_OK | os.X_OK):
        import errno

        raise PermissionError(errno.EACCES, "Permission denied (the Hlith state directory cannot be written, so no run folder can be created there)", str(a))


def plan(source_repo, *, patch=None, manifest=None, worker_cmd=None, proposer_command=None, target_python=None, state=None, run_id=None,
         patch_bytes=None, manifest_obj=None, manifest_bytes=None, base_rev=None, label="", approve_deltas=None, verified_suffix=None, reuse_clone=None, bind_hashes=None) -> Plan:
    src = Path(source_repo).resolve()
    given = sum(x is not None for x in (patch, worker_cmd, patch_bytes, proposer_command))
    if given != 1:
        raise ValueError("give exactly one input: a saved patch (with its manifest), a generated change, a worker command, or a local agent command")
    if run_id is not None:
        raise ValueError("the engine mints the RunId; the UI does not supply one")
    state = Path(state) if state else history.state_dir()
    surface = "companion" if (patch is not None or patch_bytes is not None) else "standalone"
    run_dir = _reserve_launch_dir(state, src)  # the UI's own working directory for this launch (created by start); the engine mints the RunId
    rid = run_dir.name
    clone = run_dir / "clone"
    if reuse_clone is not None:  # the engine runs in THIS existing disposable clone (the one the reviewed packet was built for): no new clone
        clone = Path(reuse_clone).resolve()
    argv = [sys.executable, "-m", "hlith.operator.engine_cli", "run", "--engine", "pipeline", "--repo", str(clone),
            "--source-repo", str(src), "--surface-mode", surface, "--invocation-id", _INVOCATION,
            "--run-link", str(run_dir / "engine-run.json")]
    if label:
        argv += ["--label", label[:120]]
    if strict_requested():
        argv.append("--strict-domain")
    if patch_bytes is not None:
        patch = run_dir / "change.patch"
        manifest = run_dir / "claim.manifest.json"
    if patch is not None:
        argv += ["--patch", str(Path(patch).resolve())]
        if manifest is not None:
            argv += ["--manifest", str(Path(manifest).resolve())]
        if approve_deltas:  # the engine's own human authorization; the value is the delta_set_sha256 the operator typed 8 chars of
            if not verified_suffix:
                raise ValueError("--approve-deltas is only planned from the delta_review service's verified argv (verified_suffix)")
            argv += ["--approve-deltas", str(approve_deltas)]
    elif proposer_command is not None:
        if not proposer_command.strip():
            raise ValueError("the local agent command is empty")
        thread_store = (run_dir / "thread-store").resolve()
        argv += ["--proposer-command", proposer_command, "--thread-store", str(thread_store)]
    else:
        argv += ["--worker-cmd", worker_cmd]
    if patch_bytes is not None:
        # A HOST-BUILT claim binds the engine to exactly the bytes the operator reviewed: the manifest bytes are fixed here ONCE (the same bytes start() writes) and both
        # hashes go on the argv (the engine refuses, exit 4, if change.patch / claim.manifest.json differ at start); the command panel shows them, so the argv review covers them
        if manifest_bytes is None:
            manifest_bytes = json.dumps(manifest_obj if manifest_obj is not None else {"paths": {}}, indent=1).encode("utf-8")
        if bind_hashes is None:
            bind_hashes = (hashlib.sha256(patch_bytes).hexdigest(), hashlib.sha256(manifest_bytes).hexdigest())
    if bind_hashes:  # (patch_sha256, manifest_sha256): the engine refuses (exit 4) unless the files it reads are the files that were verified
        argv += ["--patch-sha256", str(bind_hashes[0]), "--manifest-sha256", str(bind_hashes[1])]
    argv += ["--artifact-out", str(run_dir / "out.json"), "--proposer-id", "operator-ui"]
    if target_python:
        argv += ["--target-python", str(target_python)]
    if approve_deltas:  # the plan must carry the verified argv exactly: same patch, same manifest, same approval
        sfx = list(verified_suffix)
        ok = len(sfx) % 2 == 0 and all(argv.count(f) == 1 and argv[argv.index(f) + 1] == v for f, v in zip(sfx[0::2], sfx[1::2]))
        if not ok:
            raise ValueError("the planned command does not contain the verified argv exactly")
    pl = Plan(rid, run_dir, src, clone, argv, Path(patch).resolve() if patch else None,
              Path(manifest).resolve() if manifest else None, worker_cmd, patch_bytes, manifest_obj, base_rev, label)
    pl.reuse_clone = Path(reuse_clone).resolve() if reuse_clone is not None else None
    pl.state = state
    pl.reserved = True
    pl.manifest_bytes = manifest_bytes
    pl.proposer_command = proposer_command
    pl.thread_store = thread_store if proposer_command is not None else None
    return pl


def apply_argv(source_repo, folder, *, confirm=None, artifact_out=None, target_python=None, run_link=None) -> list[str]:
    """The engine's D1 `apply` command for a LANDED rehearsal's launch folder (change.patch, claim.manifest.json, out.json): without --confirm it is the READ-ONLY review."""
    folder = Path(folder)
    argv = [sys.executable, "-m", "hlith.operator.engine_cli", "apply", "--repo", str(Path(source_repo).resolve()),
            "--rehearsal-artifact", str(folder / "out.json"), "--patch", str(folder / "change.patch"), "--manifest", str(folder / "claim.manifest.json")]
    if target_python:
        argv += ["--target-python", str(target_python)]
    if confirm is not None:
        argv += ["--confirm", str(confirm), "--artifact-out", str(artifact_out)]
        if run_link is not None:  # the engine-minted run link: without it launch.result() cannot authenticate the apply's artifact and the Verdict would be 'artifact unavailable'
            argv += ["--run-link", str(run_link)]
    return argv


def plan_apply(source_repo, folder, token, *, label, target_python=None, state=None) -> Plan:
    """TUI behavior 2.3 (D1): the plan of APPLYING a LANDED rehearsal to the ORIGINAL repository through the engine's trusted `apply` gate (it re-runs the full pipeline on the
    original; nothing is copied from the rehearsal verdict). The token is the engine's own review token. Nothing is cloned: the engine writes only through its gate."""
    src = Path(source_repo).resolve()
    state = Path(state) if state else history.state_dir()
    run_dir = _reserve_launch_dir(state, src)
    argv = apply_argv(src, folder, confirm=token, artifact_out=run_dir / "out.json", target_python=target_python, run_link=run_dir / "engine-run.json")
    pl = Plan(run_dir.name, run_dir, src, Path(folder) / "clone", argv, None, None, None, label=label[:120], reuse_clone=Path(folder) / "clone")
    pl.state = state
    pl.reserved = True
    return pl


from ..host import _clone_source, agent_progress, captured_interrupts  # noqa: E402,F401


def feedback_store(source_repo, state=None) -> Path:
    from .. import host

    return host.feedback_store(source_repo, Path(state) if state else history.state_dir())


def _load_store_records(store: Path) -> list:
    from .. import host

    return host._load_store_records(store)


def _save_store_record(store: Path, rec) -> None:
    from .. import host

    host._save_store_record(store, rec)


def sync_feedback(source_repo, state=None) -> tuple:
    """Per-repo feedback store sync: the launcher names the finished runs' clones; the host does the L5 access."""
    from .. import host

    clones = [(st.get("meta") or {}).get("clone") for st in runs_for(Path(source_repo).resolve(), state) if st["state"] == "finished"]
    return host.sync_feedback(source_repo, Path(state) if state else history.state_dir(), clones)


def plan_agent_resume(source_repo, recovery: dict, *, target_python=None, state=None, run_id=None) -> Plan:
    """Build the ordinary detached UI plan around the existing authenticated agent thread."""
    if recovery.get("kind") == "effect-interrupt":
        return _plan_effect_resume(source_repo, recovery, target_python=target_python, state=state, run_id=run_id)
    src = Path(source_repo).resolve()
    target = Path(recovery["target"]).resolve()
    thread_store = Path(recovery["thread_store"]).resolve()
    thread_id = str(recovery["thread_id"])
    command = str(recovery["command"])
    redo = recovery.get("in_flight_turn") is not None
    if run_id is not None:
        raise ValueError("the engine mints the RunId; the UI does not supply one")
    state = Path(state) if state else history.state_dir()
    run_dir = _reserve_launch_dir(state, src)
    rid = run_dir.name
    argv = [sys.executable, "-m", "hlith.operator.engine_cli", "resume", thread_id, "--engine", "pipeline",
            "--thread-store", str(thread_store), "--proposer-command", command, "--source-repo", str(src),
            "--surface-mode", "standalone", "--invocation-id", _INVOCATION, "--run-link", str(run_dir / "engine-run.json"),
            "--label", f"resume local agent {thread_id}"[:120], "--artifact-out", str(run_dir / "out.json")]
    if redo:
        argv.append("--redo-inflight")
    if target_python:
        argv += ["--target-python", target_python]
    pl = Plan(rid, run_dir, src, target, argv, None, None, None,
              label=f"resume local agent {thread_id}", reuse_clone=target,
              proposer_command=command, thread_store=thread_store,
              resume_thread_id=thread_id, redo_inflight=redo,
              in_flight_turn=recovery.get("in_flight_turn"))
    pl.state = state
    pl.reserved = True
    return pl


def _plan_effect_resume(source_repo, recovery: dict, *, target_python=None, state=None, run_id=None) -> Plan:
    """Resume a parked effect interrupt through the pipeline gate. The proposer is not called again."""
    src = Path(source_repo).resolve()
    target = Path(recovery["target"]).resolve()
    thread_store = Path(recovery["thread_store"]).resolve()
    thread_id = str(recovery["thread_id"])
    checkpoint_id = str(recovery["interrupt_checkpoint_id"])
    if run_id is not None:
        raise ValueError("the engine mints the RunId; the UI does not supply one")
    state = Path(state) if state else history.state_dir()
    run_dir = _reserve_launch_dir(state, src)
    rid = run_dir.name
    argv = [sys.executable, "-m", "hlith.operator.engine_cli", "resume", thread_id, "--engine", "pipeline",
            "--checkpoint-id", checkpoint_id, "--thread-store", str(thread_store), "--source-repo", str(src),
            "--surface-mode", "standalone", "--invocation-id", _INVOCATION, "--run-link", str(run_dir / "engine-run.json"),
            "--label", f"resume effect {thread_id}"[:120], "--artifact-out", str(run_dir / "out.json")]
    if target_python:
        argv += ["--target-python", target_python]
    pl = Plan(rid, run_dir, src, target, argv, None, None, None,
              label=f"resume effect interrupt {thread_id}", reuse_clone=target,
              thread_store=thread_store, resume_thread_id=thread_id, checkpoint_id=checkpoint_id)
    pl.state = state
    pl.reserved = True
    return pl


def _starttime(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


UNAVAILABLE_STATE = "unavailable"
UNAVAILABLE_REASON = ("starting a check from the terminal screen is not available in Hlith Review; run `hlith check` in a terminal. "
                      "Nothing was run and your repository was not changed.")


def start(p: Plan, *, cwd: Path | None = None) -> dict:
    """Clone the source repo (disposable, no hardlinks, origin removed), then spawn the engine detached. Returns the meta record.

    Review-only distribution (P2.6): the engine's run/resume/apply commands are not offered, so starting from the terminal screen is
    UNAVAILABLE. Nothing is created, cloned or run; the meta says so and names the supported path (``hlith check``)."""
    from ..product import REVIEW_ONLY
    if REVIEW_ONLY:
        return {"run_id": p.run_id, "state": UNAVAILABLE_STATE, "reason": UNAVAILABLE_REASON, "source_repo": str(p.source_repo)}
    if p.reserved:
        # case: the name was reserved by planning; the directory is created HERE, once (never overwrite an existing launch). The repository bucket is
        # created through the same state namespace call new_launch_dir used, so modes and layout are unchanged.
        runs = _api(p.state).state.namespace(p.run_dir.parent.parent.name, "runs")
        if runs != p.run_dir.parent:
            raise ValueError("the reserved launch directory is not under this repository's runs directory")
        p.run_dir.mkdir(mode=0o700)  # FileExistsError: a plan starts at most once
    else:
        p.run_dir.mkdir(parents=True, exist_ok=True)  # created by the coordinator with the linking receipt
    if p.reuse_clone is not None:  # the refused run's own disposable clone, already at its base: nothing is cloned or moved
        if not p.reuse_clone.is_dir():
            (p.run_dir / "rc").write_text("clone-failed\n")
            meta = {"run_id": p.run_id, "started": time.time(), "argv": p.argv, "state": "clone-failed", "source_repo": str(p.source_repo)}
            (p.run_dir / "meta.json").write_text(json.dumps(meta))
            return meta
    else:
        p.clone.parent.mkdir(parents=True, exist_ok=True)
        ok, err = _clone_source(p.source_repo, p.clone, p.base_rev)
        if not ok:
            (p.run_dir / "rc").write_text("clone-failed\n")
            (p.run_dir / "stderr.log").write_text(err)
            meta = {"run_id": p.run_id, "started": time.time(), "argv": p.argv, "state": "clone-failed", "source_repo": str(p.source_repo)}
            (p.run_dir / "meta.json").write_text(json.dumps(meta))
            return meta
        # (design plan) no legacy feedback seeding: the pipeline engine reads/writes the host-state store (HLITH_STATE_DIR = the UI's host root) and the clone's stable repo
        # identity equals the source's, so cross-run feedback already loads there (review's real two-run trace); the old copy into <clone>/.hlith/feedback was never read.
    if p.patch_bytes is not None:
        (p.run_dir / "change.patch").write_bytes(p.patch_bytes)
        if p.manifest_bytes is not None:
            (p.run_dir / "claim.manifest.json").write_bytes(p.manifest_bytes)
        else:
            (p.run_dir / "claim.manifest.json").write_text(json.dumps(p.manifest_obj if p.manifest_obj is not None else {"paths": {}}, indent=1))
    (p.run_dir / "cmd.txt").write_text(p.display() + "\n")
    # wrapper: run, then record the exit code in a file (survives the UI); own session so closing the pane cannot signal it
    wrapper = 'cd "$1" && shift && "$@" > stdout.log 2> stderr.log < /dev/null; echo $? > rc.tmp && mv rc.tmp rc'
    from ..state import LocalState

    state_root = LocalState(p.state or history.state_dir()).root
    child_env = {**os.environ, "HLITH_STATE_DIR": str(state_root)}
    proc = subprocess.Popen(["sh", "-c", wrapper, "sh", str(p.run_dir), *p.argv], cwd=str(cwd or p.run_dir),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                            close_fds=True, env=child_env)
    meta = {"run_id": p.run_id, "started": time.time(), "pid": proc.pid, "pid_starttime": _starttime(proc.pid), "argv": p.argv,
            "source_repo": str(p.source_repo), "clone": str(p.clone), "patch": str(p.patch) if p.patch else None,
            "manifest": str(p.manifest) if p.manifest else None, "worker_cmd": p.worker_cmd,
            "agent_command": p.proposer_command, "thread_store": str(p.thread_store) if p.thread_store else None,
            "resume_thread_id": p.resume_thread_id, "redo_inflight": p.redo_inflight,
            "in_flight_turn": p.in_flight_turn,
            "state": "started", "base_rev": p.base_rev, "label": p.label}
    (p.run_dir / "meta.json").write_text(json.dumps(meta))
    return meta


def _write_meta_atomic(d: Path, meta: dict) -> None:
    tmp = d / f".meta.json.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(meta))
    os.replace(tmp, d / "meta.json")


def _is_launch_group(pid: int, starttime: str, run_dir: Path) -> bool:
    """The recorded launch process, verified: same start time (no pid reuse), its own session/group leader, and the wrapper's command line names THIS run folder."""
    if not _alive(pid, starttime):
        return False
    try:
        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
            return False
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    return bool(cmdline) and cmdline[0] in (b"sh", b"/bin/sh", b"/usr/bin/sh") and str(run_dir).encode() in cmdline


def cancel(run_dir, *, term_wait: float = 3.0, kill_wait: float = 2.0) -> dict:
    """Stop a RUNNING launch: SIGTERM then (bounded) SIGKILL of its verified process group; record 'cancelled' in the launch meta (atomic; not an artifact, never a verdict).
    Refuses to signal anything that is not the recorded launch (start time, session leader, run folder in its command line). A finished run is a no-op."""
    d = Path(run_dir)
    snap = status(d)
    if snap.get("state") != "running":
        return {"result": "not-running", "state": snap.get("state")}
    meta = snap.get("meta") or {}
    pid, starttime = meta.get("pid"), meta.get("pid_starttime")
    if not (isinstance(pid, int) and not isinstance(pid, bool) and pid > 1 and isinstance(starttime, str) and starttime):
        return {"result": "refused", "why": "no verified process is recorded for this launch"}
    if not _is_launch_group(pid, starttime, d):
        return {"result": "refused", "why": "the recorded process is not verifiably this launch (nothing was signalled)"}
    import signal

    _write_meta_atomic(d, {**meta, "state": "cancelled", "cancelled_at": time.time(), "cancel_signal": "TERM"})

    def group_alive() -> bool:
        # the launch's own process group: while ANY member lives, the kernel does not reuse this pid as a group id, so a successful probe is still OUR group
        try:
            os.killpg(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def gone() -> bool:
        try:
            os.waitpid(pid, os.WNOHANG)  # reap when we are the parent (no zombie)
        except OSError:
            pass
        return not _alive(pid, starttime) and not group_alive()

    def wait(seconds: float) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if gone():
                return True
            time.sleep(0.05)
        return gone()

    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not wait(term_wait):
        if group_alive():  # the same group, still populated: escalate (the leader may already be gone, so the start-time check no longer applies)
            _write_meta_atomic(d, {**meta, "state": "cancelled", "cancelled_at": time.time(), "cancel_signal": "KILL"})
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait(kill_wait)
    stopped = gone()
    return {"result": "cancelled" if stopped else "still-running", "state": "cancelled" if stopped else "running"}


def _alive(pid: int, starttime: str | None) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    st = _starttime(pid)
    if st is None:
        return False
    try:
        if Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return False
    except (OSError, IndexError):
        return False
    return starttime is not None and st == starttime  # without both values, liveness is not established


def _finite_started(value) -> float | None:
    """Return a finite run timestamp, excluding booleans and hostile/non-finite JSON numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _credible_started(value, *, now: float | None = None) -> float | None:
    """Clamp small clock skew; treat implausibly future timestamps as unrecorded."""
    now = time.time() if now is None else now
    started = _finite_started(value)
    if started is None or started > now + _MAX_HISTORY_START_SKEW:
        return None
    return min(started, now)


def _history_order_key(meta: dict, modified: float, *, now: float, tie: str = "") -> tuple:
    """Shared history ranking: credible engine start first; otherwise bounded directory mtime."""
    started = _credible_started(meta.get("started"), now=now)
    modified = _finite_started(modified)
    modified = min(modified, now) if modified is not None else 0.0
    if started is not None:
        return (1, started, modified, str(meta.get("run_id") or ""), tie)
    return (0, modified, modified, str(meta.get("run_id") or ""), tie)


def status(run_dir) -> dict:
    """{'state': running|finished|lost|clone-failed|unknown, 'rc', 'elapsed', 'argv', 'record'}: only grounded signals."""
    d = Path(run_dir)
    try:
        info = d.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("run path is not a directory")
        meta = json.loads(_read_run_file(d / "meta.json", _MAX_RUN_META_BYTES).decode("utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {"state": "unknown", "why": "no readable meta.json in the run directory"}
    if not isinstance(meta, dict) or meta.get("run_id") != d.name:
        return {"state": "unknown", "why": "run id does not match its directory"}
    started = _credible_started(meta.get("started"))
    rcf = d / "rc"
    base = {"argv": meta.get("argv"), "meta": meta, "run_dir": d}
    if meta.get("state") == "cancelled":
        pid_c, st_c = meta.get("pid"), meta.get("pid_starttime")
        if isinstance(pid_c, int) and not isinstance(pid_c, bool) and isinstance(st_c, str) and st_c and _alive(pid_c, st_c):
            return {**base, "state": "running", "rc": None, "elapsed": max(0, time.time() - started) if started is not None else None}  # still stopping
        cancelled_at = _finite_started(meta.get("cancelled_at"))
        return {**base, "state": "cancelled", "rc": None, "signal": meta.get("cancel_signal"),
                "elapsed": max(0, cancelled_at - started) if started is not None and cancelled_at is not None else None}
    try:
        rc_bytes = _read_run_file(rcf, _MAX_RUN_RC_BYTES)
    except FileNotFoundError:
        rc_bytes = None
    except (OSError, ValueError):
        return {**base, "state": "unknown", "why": "unreadable exit code file"}
    if rc_bytes is not None:
        raw = rc_bytes.decode("ascii", "replace").strip()
        try:
            end = rcf.lstat().st_mtime
        except OSError:
            end = time.time()
        if raw == "clone-failed":
            return {**base, "state": "clone-failed", "elapsed": max(0, end - started) if started is not None else None, "rc": None}
        try:
            rc = int(raw)
        except ValueError:
            return {**base, "state": "unknown", "why": f"unreadable exit code file: {raw!r}"}
        return {**base, "state": "finished", "rc": rc,
                "elapsed": max(0, end - started) if started is not None else None}
    pid = meta.get("pid")
    pid_starttime = meta.get("pid_starttime")
    if (isinstance(pid, int) and not isinstance(pid, bool)
            and isinstance(pid_starttime, str) and pid_starttime
            and _alive(pid, pid_starttime)):
        now = time.time()
        return {**base, "state": "running", "rc": None,
                "elapsed": max(0, now - started) if started is not None else None}
    return {**base, "state": "lost", "rc": None, "elapsed": None,
            "why": "the process is gone and no exit code was recorded (killed from outside?)"}


def _read_run_file(path: Path, limit: int) -> bytes:
    """Read a small regular metadata file without following links or blocking on special files."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular file")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise ValueError("file changed beyond its read limit")
        return bytes(raw)
    finally:
        os.close(fd)


def _linked_engine_record(launch_dir: Path) -> tuple[str, Path] | None:
    """Return an engine run identity only from a bounded, regular, no-follow link record."""
    from .. import store

    try:
        launch_info = launch_dir.lstat()
        if not stat.S_ISDIR(launch_info.st_mode):
            return None
        launch_root = launch_dir.resolve(strict=True)
        link = json.loads(_read_run_file(launch_dir / store.LINK, 64 * 1024).decode("utf-8"))
        run_id = store._valid_run_id(link.get("run_id"))
        engine_dir = Path(link.get("run_dir", ""))
        if engine_dir.name != run_id or engine_dir.parent.resolve(strict=True) != launch_root.parent:
            return None
        engine_info = engine_dir.lstat()
        if not stat.S_ISDIR(engine_info.st_mode):
            return None
        return run_id, engine_dir.resolve(strict=True)
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, RuntimeError):
        return None


def _linked_engine_dir(launch_dir: Path) -> Path | None:
    record = _linked_engine_record(launch_dir)
    return record[1] if record is not None else None


def engine_run_id(launch_dir) -> str | None:
    record = _linked_engine_record(Path(launch_dir))
    return record[0] if record is not None else None


def _own_engine_run_id(run_dir: Path) -> str | None:
    """The run id of an ENGINE run directory (``run-<12 hex>``, a real directory) whose own receipt names that same id; else None.

    `hlith check` (the only recorder in Hlith Review) rehearses in process: the engine run directory holds the receipt and out.json, and
    its launch directory holds no out.json. History lists the engine directory, so its artifact is read here, bound to its own receipt
    (read without following links, bounded); the artifact's own run id is still checked by the caller."""
    from .. import store

    try:
        if not store._RUN_DIR.fullmatch(run_dir.name) or not stat.S_ISDIR(run_dir.lstat().st_mode):
            return None
        receipt = json.loads(_read_run_file(run_dir / store.RECEIPT, 64 * 1024).decode("utf-8"))
        run_id = store._valid_run_id(receipt.get("run_id"))
    except (OSError, ValueError, UnicodeError, TypeError, AttributeError):
        return None
    return run_id if run_id == run_dir.name else None


def result(run_dir) -> model.Record | None:
    """Read this launch's artifact only when its engine-minted run link and file are valid, or (a run recorded by `hlith check`) the
    engine run directory's own artifact when its own receipt names it."""
    from .. import store

    launch_dir = Path(run_dir)
    artifact = launch_dir / "out.json"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    own_run_id = _own_engine_run_id(launch_dir) if not os.path.lexists(launch_dir / store.LINK) else None
    try:
        if own_run_id is not None:
            run_id = own_run_id
        else:
            run_id = _linked_run_id_checked(launch_dir, flags, store)
            if run_id is None:
                return None
        # Resolve only to confirm a directory entry is present. Its result is not
        # trusted for containment; the subsequent open is the security boundary.
        artifact.resolve(strict=True)
        # Open once with NOFOLLOW and parse those exact bytes; checking a path and
        # then asking model.load to reopen it leaves a symlink-swap race.
        artifact_fd = os.open(artifact, flags)
        try:
            artifact_info = os.fstat(artifact_fd)
            if not stat.S_ISREG(artifact_info.st_mode) or artifact_info.st_size > model.MAX_BYTES:
                return None
            raw_artifact = bytearray()
            while len(raw_artifact) <= model.MAX_BYTES:
                part = os.read(artifact_fd, min(65536, model.MAX_BYTES + 1 - len(raw_artifact)))
                if not part:
                    break
                raw_artifact.extend(part)
        finally:
            os.close(artifact_fd)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return None
    rec = model.load_bytes(artifact, raw_artifact)
    if rec.art is not None:
        art_run = rec.art.get("run")
        art_id = art_run.get("run_id") if isinstance(art_run, dict) else None
        if art_id != run_id:
            return model.Record(artifact, "id-mismatch", rec.art,
                                [*(rec.errors or []),
                                 f"RUN ID MISMATCH: artifact run id {art_id!r} does not belong to this launch; launch minted {run_id}"])
    return rec


def _linked_run_id_checked(launch_dir: Path, flags: int, store) -> str | None:
    """The engine-minted run id of a LAUNCH directory, only when its link is a bounded regular file naming a sibling run directory."""
    root = launch_dir.resolve(strict=True)
    fd = os.open(launch_dir / store.LINK, flags)
    try:
        link_info = os.fstat(fd)
        if not stat.S_ISREG(link_info.st_mode) or link_info.st_size > 64 * 1024:
            return None
        raw_link = bytearray()
        while len(raw_link) <= 64 * 1024:
            part = os.read(fd, min(8192, 64 * 1024 + 1 - len(raw_link)))
            if not part:
                break
            raw_link.extend(part)
    finally:
        os.close(fd)
    linked = json.loads(raw_link.decode("utf-8"))
    run_id = store._valid_run_id(linked.get("run_id"))
    engine_dir = Path(linked.get("run_dir", ""))
    if (engine_dir.name != run_id or engine_dir.parent.resolve(strict=True) != root.parent
            or not engine_dir.is_dir() or engine_dir.is_symlink()):
        return None
    return run_id


def tail(run_dir, name="stdout.log", n=12) -> list[str]:
    try:
        return Path(run_dir, name).read_text(errors="replace").splitlines()[-n:]
    except OSError:
        return []


def stderr_excerpt(run_dir, *, max_bytes: int = 16 * 1024, max_lines: int = 20) -> list[str]:
    """Read a bounded, regular, no-follow stderr tail for an operator failure view."""
    path = Path(run_dir)
    try:
        dir_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(path, dir_flags)
        try:
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                return []
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open("stderr.log", flags, dir_fd=dir_fd)
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    return []
                os.lseek(fd, max(0, opened.st_size - max_bytes), os.SEEK_SET)
                chunks = []
                remaining = max_bytes
                while remaining:
                    chunk = os.read(fd, min(4096, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                text = b"".join(chunks).decode("utf-8", "replace")
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)
    except OSError:
        return []
    lines = text.splitlines()[-max_lines:]
    visible = []
    for line in lines:
        escaped = "".join(f"\\x{ord(ch):02x}" if ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f else ch
                          for ch in line)
        visible.append(escaped[:500])
    return visible


def _current_runs_dir(st_root: Path, current_repo):
    return run_index.current_runs_dir(st_root, current_repo)


def _history_bases(st_root: Path, repo=None, current_repo=None) -> list[Path]:
    return run_index.history_bases(st_root, repo=repo, current_repo=current_repo, max_repositories=_MAX_HISTORY_REPOSITORIES)


def _ranked_run_candidates(bases: list[Path], *, repo=None):
    """Read at most the bounded candidate budget across all roots, while counting every matching run directory."""
    return run_index.ranked_run_candidates(
        bases,
        repo=repo,
        max_candidates=_MAX_HISTORY_SCAN_CANDIDATES,
        scan_window=_SCAN_WINDOW,
    )


def _omitted_history_repositories(st_root: Path, repo=None, current_repo=None) -> int:
    """How many repository folders the history scan does NOT read (it reads the newest _MAX_HISTORY_REPOSITORIES of them): the count the operator must be told about."""
    return run_index.omitted_history_repositories(
        st_root,
        repo=repo,
        current_repo=current_repo,
        max_repositories=_MAX_HISTORY_REPOSITORIES,
    )


def _runs_for_snapshot(repo=None, state=None, current_repo=None):
    st_root = history.state_dir(state)
    candidates, total_dirs, scanned, truncated, now = _ranked_run_candidates(_history_bases(st_root, repo, current_repo), repo=repo)
    statuses = []
    for _rank, path in candidates:
        st = status(path)
        if st["state"] != "unknown" and st.get("meta", {}).get("run_id") == path.name:
            statuses.append(st)

    # A launch and the engine-minted run directory are siblings; suppress only a validated linked engine directory.
    linked_engine_runs = {record[1] for row in statuses
                          if Path(row["run_dir"]).name.startswith("launch-")
                          if (record := _linked_engine_record(Path(row["run_dir"])) ) is not None}
    statuses = [row for row in statuses if Path(row["run_dir"]).resolve() not in linked_engine_runs]
    def rank(row):
        path = Path(row["run_dir"])
        try:
            modified = path.lstat().st_mtime
        except OSError:
            modified = 0.0
        return _history_order_key(row.get("meta") or {}, modified, now=now, tie=str(path))

    statuses.sort(key=rank, reverse=True)
    cur_dir = _current_runs_dir(st_root, current_repo) if repo is None else None
    try:
        current_resolved = Path(current_repo).resolve() if (current_repo is not None and repo is None) else None
    except OSError:
        current_resolved = None
    def is_own(r):
        # this repository's runs: its current bucket, OR any run whose own record names this repository (the bucket id hashes the repository's root commits, so it changes when an
        # independent root appears while the realpath stays the same)
        if cur_dir is not None and Path(r["run_dir"]).parent == cur_dir:
            return True
        src = (r.get("meta") or {}).get("source_repo")
        try:
            return bool(src) and current_resolved is not None and Path(str(src)).resolve() == current_resolved
        except OSError:
            return False

    if current_resolved is not None:
        for r in statuses:
            if is_own(r) and not (cur_dir is not None and Path(r["run_dir"]).parent == cur_dir):
                r["earlier_id"] = True  # recorded under an earlier repository id (the set of root commits changed)
    if (cur_dir is not None or current_resolved is not None) and len(statuses) > _MAX_HISTORY_RUNS:
        # the list is capped: this repository's own runs get their share first (up to half), the other repositories fill the rest, then everything is shown newest-first
        own = [r for r in statuses if is_own(r)]
        others = [r for r in statuses if not is_own(r)]
        take = own[:_MAX_HISTORY_RUNS // 2]
        keep = {id(r) for r in take} | {id(r) for r in others[:_MAX_HISTORY_RUNS - len(take)]}
        statuses = [r for r in statuses if id(r) in keep]
    omitted = _omitted_history_repositories(st_root, repo, current_repo)
    if omitted:  # repository folders beyond the cap were never read: truncated is true; the counts stay in their own units (run folders here, repository folders via omitted_history_repositories)
        truncated = True
    record_total = total_dirs if truncated else len(statuses)
    return statuses[:_MAX_HISTORY_RUNS], record_total, truncated, scanned


def omitted_history_repositories(state=None, current_repo=None) -> int:
    """Repository folders of the state directory that the History scan does not read (a count of REPOSITORY folders, never summed with run folders)."""
    return _omitted_history_repositories(history.state_dir(state), None, current_repo)


def runs_for(repo=None, state=None) -> list[dict]:
    """Newest recorded UI runs, optionally filtered by source repository; result cap is global across roots."""
    return _runs_for_snapshot(repo, state)[0]


def _is_real_directory(path: Path) -> bool:
    """Check the final path component with lstat so state roots cannot redirect through a symlink."""
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def _bounded_child_dirs(base: Path, name_pattern, limit: int, *, rank_by_started: bool = False) -> list[Path]:
    """Rank real child directories before applying the result cap; never follow a child symlink."""
    if limit <= 0:
        return []
    try:
        if not stat.S_ISDIR(base.lstat().st_mode):
            return []
        found = []
        with os.scandir(base) as entries:
            for entry in entries:
                if not name_pattern.fullmatch(entry.name):
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    path = Path(entry.path)
                    started = None
                    if rank_by_started:
                        try:
                            meta = json.loads(_read_run_file(path / "meta.json", _MAX_RUN_META_BYTES).decode("utf-8"))
                        except (OSError, ValueError, UnicodeError, TypeError):
                            continue
                        if not isinstance(meta, dict) or meta.get("run_id") != path.name:
                            continue
                        started = _finite_started(meta.get("started"))
                    rank = started if started is not None else info.st_mtime
                    found.append((rank, info.st_mtime, path.name, path))
        return [row[3] for row in heapq.nlargest(limit, found, key=lambda row: row[:3])]
    except OSError:
        return []


def fmt_elapsed(s) -> str:
    if s is None:
        return "-"
    s = int(max(0, s))
    return f"{s // 60}:{s % 60:02d}"


def run_rows_with_summary(state=None, current_repo=None) -> tuple[list[dict], int, bool, int]:
    """Every run started from the UI, across repositories, newest first: {run_id, repo, when, state, decision, rc, elapsed, label, run_dir}.
    The decision is read from the run's artifact (None if the engine wrote none); nothing else is claimed."""
    from ..labels import source_label

    rows = []
    runs, total_count, truncated, scanned = _runs_for_snapshot(None, state, current_repo)
    for st in runs:
        m = st["meta"]
        rec = None
        artifact_scan = "not finished"
        if st["state"] == "finished":
            artifact_path = Path(st["run_dir"]) / "out.json"
            try:
                artifact_info = artifact_path.lstat()
                if not stat.S_ISREG(artifact_info.st_mode):
                    artifact_scan = "not a regular file"
                elif artifact_info.st_size > _MAX_HISTORY_SUMMARY_ARTIFACT_BYTES:
                    artifact_scan = "over summary limit"
                else:
                    rec = result(st["run_dir"])
                    artifact_scan = "checked"
            except OSError:
                artifact_scan = "missing"
        art = rec.art if rec is not None and rec.usable else None
        if art is not None:
            from . import frame

            from . import feedback_view

            # the decision word, then (as `hlith check` prints it) the recorded feedback failure, so a row cut to fit keeps the warning; the inspector shows the whole state
            dec = frame._decision(art)[0] + feedback_view.failure_tag(art)
            run = art.get("run") if isinstance(art.get("run"), dict) else {}
            head = run.get("base_commit_sha")
            if dec.startswith("LANDED"):  # the same words the public `hlith history` prints: which run landed on the ORIGINAL and which only in a rehearsal clone (recorded target, never guessed)
                dec += " \u00b7 " + {"rehearsal": "rehearsal clone", "original": "original repository"}.get(run.get("landing_target"), "landing target not recorded")
        elif rec is not None and rec.status == "id-mismatch":
            dec, head = None, None
        else:
            dec, head = ("UNVALIDATED" if rec is not None and rec.art is not None else None), None
        engine_record = _linked_engine_record(Path(st["run_dir"]))
        linked = engine_record[1] if st["state"] == "running" and engine_record is not None else None
        events_recorded = False
        if linked is not None:
            from .. import store

            for name in (store.EVENTS_V2, "events.jsonl"):
                try:
                    event_info = (linked / name).lstat()
                    if stat.S_ISREG(event_info.st_mode) and event_info.st_size > 0:
                        events_recorded = True
                        break
                except OSError:
                    pass
        now = time.time()
        started = _credible_started(m.get("started"), now=now)
        when = started if started is not None else 0.0
        age_seconds = max(0, int(now - when)) if when else None
        if age_seconds is None:
            age = "age not recorded"
        elif age_seconds < 60:
            age = f"{age_seconds}s ago"
        elif age_seconds < 3600:
            age = f"{age_seconds // 60}m ago"
        elif age_seconds < 86400:
            age = f"{age_seconds // 3600}h ago"
        else:
            age = f"{age_seconds // 86400}d ago"
        rows.append({"run_id": m.get("run_id"), "repo": Path(str(m.get("source_repo") or "?")).name,
                     "source_repo": m.get("source_repo"), "head": head,
                     "when": when, "age": age, "state": st["state"], "events_recorded": events_recorded,
                     "decision": dec, "artifact_scan": artifact_scan, "rc": st.get("rc"), "elapsed": st.get("elapsed"),
                     "gate_exit": (event_gate_exit(st["run_dir"]) if (not dec and st["state"] == "finished") else None),
                     "label": source_label(art, m) or (Path(m["patch"]).name if m.get("patch") else (m.get("worker_cmd") or "")),
                     "run_dir": st["run_dir"], "earlier_id": bool(st.get("earlier_id")),
                     "engine_run_id": (run.get("run_id") if art is not None and isinstance(run.get("run_id"), str) else None)})
    return rows, total_count, truncated, scanned


def run_rows(state=None) -> list[dict]:
    """Compatibility projection of the newest recorded UI runs; use run_rows_with_summary for total-count labels."""
    return run_rows_with_summary(state)[0]


def run_row_text(r: dict, width: int = 100) -> str:
    when = time.strftime("%m-%d %H:%M", time.localtime(r["when"])) if r["when"] else "-"
    what = r["decision"] or (r["state"].upper() if r["state"] != "finished" else f"NO ARTIFACT (exit {r['rc']})")
    line = f"{when}  {what:<24} {fmt_elapsed(r['elapsed']):>6}  {Path(r['repo']).name or r['repo']:<16} {str(r['label'])[:40]}"
    return line if len(line) <= width else line[: width - 1] + "\u2026"


_NEST = {"account": 1, "differential": 1}  # run inside derive


def _unavailable(run_dir) -> str | None:
    """The reason the engine said it could not write events ('hlith: events unavailable: <reason>' on its stderr), if it did."""
    from ...events import UNAVAILABLE_PREFIX as marker
    for ln in reversed(tail(run_dir, "stderr.log", 40)):
        if ln.startswith(marker):
            return ln[len(marker):][:200]
    return None


def live(run_dir, now_mono: float | None = None) -> dict | None:
    """The engine's own event file read back: {'phases': [{name, state: running|done, seconds, depth}], 'progress': {...}|None,
    'closed': {...}|None, 'unavailable': reason|None}. None when there is no usable event file and the engine did not say why (the
    caller falls back to pid + elapsed). Never invents a phase, never raises (a hostile or damaged file degrades to the fallback)."""
    try:
        return _live_incremental(run_dir, now_mono)
    except Exception:  # noqa: BLE001 - the screen must survive whatever is in the file
        return None


def event_gate_exit(run_dir):
    """The exit status the engine's OWN event file records for this run's gate decision (the `decision` event's exit_status), or None. A recorded run with no usable artifact still says
    what its gate decided here; the TUI shows that number as the event log's literal text and never turns it into a verdict word (only the decision mapping does that, from an artifact)."""
    import json

    from .. import store

    try:
        real = store.engine_run_dir(Path(run_dir)) or Path(run_dir)
        path = real / store.EVENTS_V2
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return None
        with open(path, "rb") as handle:
            handle.seek(max(0, info.st_size - 64 * 1024))
            raw = handle.read(64 * 1024 + 1)
    except Exception:  # noqa: BLE001
        return None
    found = None
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        detail = row.get("detail") if isinstance(row, dict) and isinstance(row.get("detail"), dict) else {}
        if isinstance(row, dict) and row.get("kind") == "decision" and isinstance(detail.get("exit_status"), int) and not isinstance(detail.get("exit_status"), bool):
            found = detail["exit_status"]
    return found


def event_tail(run_dir, n: int = 8) -> list:
    """The last n events of the engine's own v2 event file, for the Event Log dock: [{'ts': 'HH:MM:SS', 'phase': ..., 'what': ...}]. REAL data only: every field is read from the
    recorded event (kind, phase, the named target / counts / exit status in its detail); nothing is invented, an unreadable or absent file is []. Bounded (the last 64 KiB), read-only,
    never raises."""
    import json
    import time as _time

    from .. import store

    try:
        launch_dir = Path(run_dir)
        real = store.engine_run_dir(launch_dir) or launch_dir
        path = real / store.EVENTS_V2
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return []
        with open(path, "rb") as handle:
            handle.seek(max(0, info.st_size - 64 * 1024))
            raw = handle.read(64 * 1024 + 1)
    except Exception:  # noqa: BLE001 - a missing / hostile file is an empty dock, never a crash
        return []
    out = []
    for line in raw.splitlines()[-(n + 1):]:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        kind, phase = str(row.get("kind") or ""), str(row.get("phase") or "")
        detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
        if kind == "phase_started":
            what = "started"
        elif kind == "phase_finished":
            what = "done"
        elif kind == "progress":
            tgt = detail.get("target")
            what = f"checking {detail.get('i')}/{detail.get('n')} {tgt}" if isinstance(tgt, str) and tgt else "progress"
        elif kind == "decision":
            what = f"decision · exit {detail.get('exit_status')}" if "exit_status" in detail else "decision"
        elif kind == "artifact_written":
            what = "artifact written"
        else:
            what = kind.replace("_", " ") or "event"
        ts = row.get("ts")
        try:
            stamp = _time.strftime("%H:%M:%S", _time.localtime(_parse_ts(ts))) if _parse_ts(ts) is not None else "--:--:--"
        except (OverflowError, OSError, ValueError, TypeError):
            stamp = "--:--:--"
        out.append({"ts": stamp, "phase": phase or "-", "what": what, "id": row.get("seq") if isinstance(row.get("seq"), int) else f"{ts}|{phase}|{kind}"})
    return out[-n:]


def feedback_limits(run_dir, cap: int = 8) -> list:
    """Every L5 named limit the engine emitted for this run: the PROGRESS detail {"feedback_limit": "<text>"} in the engine's own event file (<run>/events.v2.jsonl, beside out.json),
    in order, without duplicates, each at most 200 characters. [] when there is no usable file or none. Bounded (2 MiB, 5000 lines), read-only, never raises."""
    out: list = []
    try:
        path = Path(run_dir) / "events.v2.jsonl"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
            return []
        with open(path, "rb") as f:
            for n, raw in enumerate(f):
                if n >= 5000 or len(out) >= cap:
                    break
                try:
                    row = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError, RecursionError):
                    continue
                detail = row.get("detail") if isinstance(row, dict) and row.get("kind") == "progress" else None
                text = detail.get("feedback_limit") if isinstance(detail, dict) else None
                if isinstance(text, str) and text.strip() and " ".join(text.split())[:200] not in out:
                    out.append(" ".join(text.split())[:200])
    except (OSError, ValueError):
        return out
    return out


def _parse_ts(ts: str):
    from datetime import datetime, timezone

    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _live_v2(real: Path):
    """Progress from the run's contract events (the engine's own stream, read from ITS run directory). Phases and counters only:
    no event ever carries a verdict, and a finished stream shows no exit status (the decision is read from the artifact)."""
    from .. import store
    from ...contract.events import EventKind

    evs, _problems = store.read_events(real)
    if not evs:
        return None
    now = time.time()
    ph: dict[str, dict] = {}
    order: list[str] = []
    closed = None
    for e in evs:
        if e.kind is EventKind.ARTIFACT_WRITTEN:
            closed = {}
            continue
        if e.phase is None:
            continue
        name = e.phase.value
        t = _parse_ts(e.ts)
        if e.kind is EventKind.PHASE_STARTED:
            if name not in ph:
                order.append(name)
                ph[name] = {"name": name, "state": "running", "seconds": 0.0, "t0": t, "depth": 0}
            else:
                ph[name]["state"], ph[name]["t0"] = "running", t
        elif e.kind is EventKind.PHASE_FINISHED and name in ph:
            if t is not None and ph[name]["t0"] is not None:
                ph[name]["seconds"] += max(0.0, t - ph[name]["t0"])
            ph[name]["state"] = "done"
    out = []
    for name in order:
        d = ph[name]
        sec = d["seconds"] + (max(0.0, now - d["t0"]) if d["state"] == "running" and d["t0"] is not None else 0.0)
        out.append({"name": name, "state": d["state"], "seconds": sec, "depth": d["depth"]})
    return {"phases": out, "progress": None, "closed": closed, "unavailable": None}


# Incremental state is bounded per active run; old run entries are evicted.
_LIVE_MAX_BYTES = 256 * 1024
_LIVE_MAX_LINES = 2000
_LIVE_MAX_LINE = 64 * 1024
_LIVE_CACHE: dict[str, dict] = {}


def _live_incremental(run_dir, now_mono):
    """Read a bounded new suffix and fold it into a small phase summary."""
    from .. import store
    from ... import events
    from ...contract.events import EventKind, Phase

    launch_dir = Path(run_dir)
    real = store.engine_run_dir(launch_dir) or launch_dir
    v2 = real / store.EVENTS_V2
    legacy = real / "events.jsonl"
    path = v2 if v2.exists() else legacy
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode):
            return {"phases": [], "progress": None, "closed": None, "unavailable": "event stream is not a regular file"}
        key = str(path.resolve(strict=True))
    except OSError:
        why = _unavailable(run_dir)
        return {"phases": [], "progress": None, "closed": None, "unavailable": why} if why else None
    identity = (st.st_dev, st.st_ino)
    cache = _LIVE_CACHE.get(key)
    def empty_cache():
        return {"identity": identity, "offset": 0, "anchor": b"", "mtime_ns": st.st_mtime_ns,
                "pending": b"", "discarding_line": False, "phases": {}, "order": [],
                "progress": None, "closed": None, "format": "v2" if path == v2 else "legacy"}

    if cache is None or cache["identity"] != identity or st.st_size < cache["offset"]:
        cache = empty_cache()
        _LIVE_CACHE[key] = cache
        if len(_LIVE_CACHE) > 16:
            _LIVE_CACHE.pop(next(iter(_LIVE_CACHE)))
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
            return {"phases": [], "progress": None, "closed": None, "unavailable": "event stream changed while opening"}
        if cache["offset"]:
            os.lseek(fd, max(0, cache["offset"] - 64), os.SEEK_SET)
            anchor = os.read(fd, min(64, cache["offset"]))
            if anchor != cache["anchor"] or opened.st_mtime_ns < cache["mtime_ns"]:
                cache = empty_cache()
                _LIVE_CACHE[key] = cache
        os.lseek(fd, cache["offset"], os.SEEK_SET)
        data = b""
        if cache["pending"].count(b"\n") < _LIVE_MAX_LINES:
            data = os.read(fd, _LIVE_MAX_BYTES)
        new_offset = cache["offset"] + len(data)
        os.lseek(fd, max(0, new_offset - 64), os.SEEK_SET)
        new_anchor = os.read(fd, min(64, new_offset)) if new_offset else b""
    finally:
        os.close(fd)
    cache["offset"] += len(data)
    cache["anchor"] = new_anchor
    cache["mtime_ns"] = opened.st_mtime_ns
    if cache["discarding_line"]:
        delimiter = data.find(b"\n")
        if delimiter < 0:
            data = b""
        else:
            data = data[delimiter + 1:]
            cache["discarding_line"] = False
    lines = (cache["pending"] + data).split(b"\n")
    complete, cache["pending"] = lines[:-1], lines[-1]
    if len(complete) > _LIVE_MAX_LINES:
        cache["pending"] = b"\n".join(complete[_LIVE_MAX_LINES:]) + (b"\n" + cache["pending"] if cache["pending"] else b"")
        complete = complete[:_LIVE_MAX_LINES]
    if len(cache["pending"]) > _LIVE_MAX_LINE:
        # A malformed oversized line is discarded through the next delimiter.
        cache["pending"] = b""
        cache["discarding_line"] = True
    for raw in complete:
        if not raw or len(raw) > _LIVE_MAX_LINE:
            continue
        try:
            row = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(row, dict):
            continue
        if cache["format"] == "v2":
            try:
                kind = EventKind(row["kind"])
                phase = Phase(row["phase"]) if row.get("phase") else None
            except (ValueError, KeyError, TypeError):
                continue
            if kind is EventKind.ARTIFACT_WRITTEN:
                cache["closed"] = {}
                continue
            if phase is None:
                continue
            name, stamp = phase.value, _parse_ts(row.get("ts", ""))
            detail_ = {}
            if stamp is not None:
                cache["last"] = {"ts": stamp, "phase": name, "kind": kind.value}
            if name == "feedback" and kind in (EventKind.PHASE_STARTED, EventKind.PHASE_FINISHED):
                # the engine emits TWO feedback phases (observed trace): one BEFORE the gate that loads stored feedback as an INPUT, one AFTER it that records this run's outcome.
                # One row called "feedback" read as "feedback already committed" while the gate was still ahead; the engine's own marker (post_gate_outcome in the started event) tells them apart.
                raw_detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
                if kind is EventKind.PHASE_STARTED:
                    cache["fb_after_gate"] = "post_gate_outcome" in raw_detail
                if cache.get("fb_after_gate"):
                    name, detail_ = "feedback out", {"detail": "recorded after the gate"}
                else:
                    name, detail_ = "feedback in", {"detail": "loaded before the gate, as input"}
            if kind is EventKind.PROGRESS:  # TUI behavior: the frozen contract's PROGRESS detail {target, i, n} names what is being checked; nothing else is read
                detail = row.get("detail")
                if isinstance(detail, dict):
                    got = {k: v for k, v in events._extra(detail).items() if k in ("target", "i", "n")}
                    # only a detail that NAMES a target replaces the row: {"feedback_limit": ..} or a bare i/n (no target) must neither draw a row nor erase the real one
                    cache["progress"] = {**got, "phase": name} if isinstance(got.get("target"), str) and got["target"] else cache["progress"]
                continue
            if kind is EventKind.PHASE_STARTED:
                if name not in cache["phases"] and len(cache["phases"]) < 64:
                    cache["order"].append(name)
                    cache["phases"][name] = {"name": name, "state": "running", "seconds": 0.0, "t0": stamp, "depth": 0, **detail_}
                elif name in cache["phases"]:
                    cache["phases"][name].update(state="running", t0=stamp)
            elif kind is EventKind.PHASE_FINISHED and name in cache["phases"]:
                item = cache["phases"][name]
                if stamp is not None and item["t0"] is not None:
                    item["seconds"] += max(0.0, stamp - item["t0"])
                item["state"] = "done"
                if cache["progress"] and cache["progress"].get("phase") == name:
                    cache["progress"] = None
        else:
            phase, event = row.get("phase"), row.get("event")
            stamp = row.get("ts_mono")
            if not (isinstance(phase, str) and phase in events.PHASES and event in events.EVENTS
                    and isinstance(stamp, (int, float)) and not isinstance(stamp, bool)):
                continue
            stamp = float(stamp)
            if phase == "run":
                if event == "end":
                    extra = row.get("extra")
                    cache["closed"] = events._extra(extra) if isinstance(extra, dict) else {}
                continue
            if event == "start":
                if phase not in cache["phases"] and len(cache["phases"]) < 64:
                    cache["order"].append(phase)
                    cache["phases"][phase] = {"name": phase, "state": "running", "seconds": 0.0,
                                              "t0": stamp, "depth": _NEST.get(phase, 0)}
                elif phase in cache["phases"]:
                    cache["phases"][phase].update(state="running", t0=stamp)
            elif event == "end" and phase in cache["phases"]:
                item = cache["phases"][phase]
                item["seconds"] += max(0.0, stamp - item["t0"])
                item["state"] = "done"
                if phase == "differential":
                    cache["progress"] = None
            elif event == "progress" and phase == "differential":
                extra = row.get("extra")
                cache["progress"] = events._extra(extra) if isinstance(extra, dict) else None
    now_wall = time.time()
    now_mono = time.monotonic() if now_mono is None else now_mono
    phases = []
    for name in cache["order"]:
        item = cache["phases"][name]
        t0 = item["t0"]
        elapsed = 0.0
        if item["state"] == "running" and t0 is not None:
            elapsed = max(0.0, now_wall - t0) if cache["format"] == "v2" else max(0.0, now_mono - t0)
        phases.append({"name": item["name"], "state": item["state"],
                       "seconds": item["seconds"] + elapsed, "depth": item["depth"], **({"detail": item["detail"]} if item.get("detail") else {})})
    lagging = st.st_size > cache["offset"]
    unavailable = "event log large: showing bounded incremental progress" if lagging else None
    if not phases and cache["closed"] is None and cache["progress"] is None:
        why = _unavailable(run_dir)
        return {"phases": [], "progress": None, "closed": None, "unavailable": why or unavailable} if why or unavailable else None
    result = {"phases": phases, "progress": cache["progress"], "closed": cache["closed"], "unavailable": unavailable}
    if cache["format"] == "v2" and cache["closed"] is None:
        observed = _observed_rows_from(cache, real, now_wall)
        if observed:
            result["observed"] = observed
    return result


def _age_text(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds}s" if seconds < 60 else f"{seconds // 60}m {seconds % 60:02d}s"


def _engine_alive(real) -> bool | None:
    """True / False when meta.json names the engine pid and its /proc start time matches (a REUSED pid is not our engine); None when it cannot be told."""
    try:
        meta = json.loads((Path(real) / "meta.json").read_text("utf-8"))
        pid, want = int(meta["pid"]), str(meta["pid_starttime"])
        got = Path(f"/proc/{pid}/stat").read_text("utf-8").rsplit(")", 1)[1].split()[19]
        return got == want
    except FileNotFoundError:
        return False
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return None


def _observed_rows_from(cache, real, now_wall):
    """The 'OBSERVED SO FAR' rows of a RUNNING check, from engine facts only (events + the engine process): what is being checked now (a PROGRESS event),
    the age of the last event and whether the engine process is alive. Absent facts produce no row."""
    rows = []
    prog = cache.get("progress")
    if prog and prog.get("target"):
        where = f"{prog['i']} of {prog['n']} · " if isinstance(prog.get("i"), int) and isinstance(prog.get("n"), int) else ""
        rows.append(("now checking", (where + str(prog["target"]))[:170]))  # the count FIRST: a narrow terminal cuts the long qualified name, never the count
    last = cache.get("last")
    if last:
        rows.append(("last event", f"{_age_text(now_wall - last['ts'])} ago · {last['phase']} {str(last['kind']).replace('_', ' ')}"))
    alive = _engine_alive(real)
    if alive is not None:
        rows.append(("engine process", "running" if alive else "not running · the run ended or died: no result yet"))
    return rows


def _live(run_dir, now_mono):
    from .. import store
    from ... import events
    real = store.engine_run_dir(Path(run_dir)) or Path(run_dir)
    if (real / store.EVENTS_V2).exists():
        return _live_v2(real)
    recs = events.read(Path(run_dir) / "events.jsonl")
    if not recs:
        why = _unavailable(run_dir)
        return {"phases": [], "progress": None, "closed": None, "unavailable": why} if why else None
    now = time.monotonic() if now_mono is None else now_mono
    ph: dict[str, dict] = {}
    order: list[str] = []
    prog = None
    closed = None
    for r in recs:
        p, ev = r["phase"], r["event"]
        if p == "run":
            if ev == "end":
                closed = r.get("extra") or {}
            continue
        if ev == "start":
            if p not in ph:
                order.append(p)
                ph[p] = {"name": p, "state": "running", "seconds": 0.0, "t0": r["ts_mono"], "depth": _NEST.get(p, 0)}
            else:
                ph[p]["state"], ph[p]["t0"] = "running", r["ts_mono"]
        elif ev == "end" and p in ph:
            ph[p]["seconds"] += max(0.0, r["ts_mono"] - ph[p]["t0"])
            ph[p]["state"] = "done"
            if p == "differential":
                prog = None  # that call site finished: a label must name only a target an event says is running
        elif ev == "progress" and p == "differential":
            prog = r.get("extra") or None
    out = []
    for p in order:
        d = ph[p]
        sec = d["seconds"] + (max(0.0, now - d["t0"]) if d["state"] == "running" else 0.0)
        out.append({"name": p, "state": d["state"], "seconds": sec, "depth": d["depth"]})
    return {"phases": out, "progress": prog, "closed": closed, "unavailable": _unavailable(run_dir) if not closed else None}
