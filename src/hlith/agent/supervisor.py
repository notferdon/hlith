# SPDX-License-Identifier: Apache-2.0
"""Supervisor side of the Layer 1 LangGraph worker (see agent/graph.py for the confined side)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from ..contract.capabilities import GitRead, HostState, SnapshotService
from ..contract.errors import EXIT_BOUNDARY
from .capture import (
    MAX_EFFECT_BYTES,
    MAX_EFFECT_ENTRIES,
    DeltaEffect,
    WorkerRun,
    _diff_stage,
    _materialise,
    _scan_stage,
    read_manifest_document,
    read_manifest_full,
    worktree_digest,
)
from .checkpoint import (
    _THREAD,
    INTERRUPTED_DECISION,
    LAYER1,
    SOCKET_EVENTS_SCOPE,
    CrashState,
    GraphInfo,
    Layer1Session,
    _avoid_for,
    _captured_mac,
    _copy_regular_tree,
    _export_manifest_digest,
    _load_verdict,
    _locked,
    _mac_key,
    _meta,
    _non_regular_entry,
    _persist_into,
    _private_dir,
    _progress_mac,
    _read_ids,
    _read_json,
    _record_verdict_locked,
    _state_dir,
    _thread_dir,
    _tree_digest,
    _verdict_path,
    _write_json_atomic,
    check_store,
    classify_crash_state,
    default_store,
    package_root,
    persist,
    persist_progress,
    profile_extras,
    read_checkpoint_ids,
    record_verdict,
    rotate_mac_key,
    sync_after_resume,
    thread_target,
    versions,
)
from .errors import EffectRejected, IndeterminateProposerCall, RuntimeBoundary
from .profile import GrantError, Profile, agent_worker_env_names, run_confined
from .tools import AGENT_MAX_TURNS, _measure, claimed_digest, scrub_task

AGENT_MAX_REPLY = 256 * 1024

_BOOT = (
    "import sys, importlib.util, runpy; root = sys.argv[1]; sys.argv = ['hlith.agent.graph'] + sys.argv[2:]; "
    "spec = importlib.util.spec_from_file_location('hlith', root + '/hlith/__init__.py', "
    "submodule_search_locations=[root + '/hlith']); m = importlib.util.module_from_spec(spec); "
    "sys.modules['hlith'] = m; spec.loader.exec_module(m); "
    "runpy.run_module('hlith.agent.graph', run_name='__main__', alter_sys=True)"
)
NOT_INSTALLED = (
    "layer1: the hlith source root is not readable by the interpreter that runs the worker; install with: "
    "uv sync --frozen (or pip install -e .) in the hlith checkout and run via uv run"
)
_WORKER_OK: set = set()


def _safe_class(e: BaseException) -> str:
    """The exception's class name, restricted to identifier characters and capped: safe to show, unlike its message."""
    return re.sub(r"[^A-Za-z0-9_]", "?", type(e).__name__)[:60]


def _safe_proposer_failure(e: BaseException) -> str:
    """Return a secret-free boundary message for a proposer failure."""
    from .proposer import ProposerOutputLimit

    if isinstance(e, ProposerOutputLimit):
        return f"layer1: proposer command output exceeded {e.limit} byte limit"
    return f"layer1: proposer failed ({_safe_class(e)}): its error text is withheld"


def check_worker_importable() -> None:
    gw = Path(package_root()) / "hlith" / "agent" / "graph.py"
    if not (gw.is_file() and os.access(gw, os.R_OK) and os.access(gw.parent.with_name("__init__.py"), os.R_OK)):
        raise RuntimeBoundary(NOT_INSTALLED)


def worker_prefix() -> list[str]:
    return [sys.executable, "-I", "-c", _BOOT, package_root()]


def worker_argv(mode: str, patch_path: str | None, cmd: list[str]) -> list[str]:
    check_worker_importable()
    base = [*worker_prefix(), "run", mode]
    if mode in ("patch", "agent"):
        return base + [str(patch_path)]
    return base + ["--", *cmd]


def after_run(session: Layer1Session, run_rc: int, stderr: str, observed, ignored, skipped) -> GraphInfo:
    """Read what the confined run left behind and cross-check it against the supervisor's own diff."""
    info = GraphInfo(thread_id=session.thread_id, _session=session, **versions())
    if run_rc != 0:
        raise RuntimeBoundary(f"layer1: graph worker exited {run_rc}: {stderr.strip()[-400:]}")
    payload = _read_json(session.driver / "graph_payload.json")
    result = _read_json(session.driver / "graph_result.json")
    cps, ints, _chans = read_checkpoint_ids(session)
    if not cps or not ints:
        raise RuntimeBoundary("layer1: the graph never reached its interrupt")
    if result.get("next") != ["propose"]:
        raise RuntimeBoundary(f"layer1: graph is not paused at 'propose' (next={result.get('next')!r})")
    if payload.get("thread_id") != session.thread_id:
        raise RuntimeBoundary("layer1: interrupt payload names a different thread")
    claimed = payload.get("claimed")
    if not (isinstance(claimed, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in claimed.items())):
        raise RuntimeBoundary("layer1: interrupt payload has a malformed claim")
    try:
        now = _measure(session.stage)
    except RuntimeError as e:
        raise RuntimeBoundary(f"layer1: {e}") from e
    observed_paths = {o.path for o in observed}
    allowed_extra = set(ignored) | set(skipped)
    problems = []
    if not observed_paths <= set(claimed):
        problems.append(f"observed but unclaimed: {sorted(observed_paths - set(claimed))[:5]}")
    if not set(claimed) - observed_paths <= allowed_extra:
        problems.append(f"claimed but not observed: {sorted(set(claimed) - observed_paths - allowed_extra)[:5]}")
    for p, d in claimed.items():
        if d == "deleted":
            if p in now:
                problems.append(f"claimed deleted but present: {p}")
        elif now.get(p) != d:
            problems.append(f"content differs from claim: {p}")
    if problems:
        raise RuntimeBoundary("layer1: interrupt payload does not match the observed effect: " + "; ".join(problems))
    info.payload_matches_observed = True
    info.interrupt_checkpoint_id = ints[-1]
    info.final_checkpoint_id = cps[-1]
    info.interrupt_payload = {
        "node": payload.get("node"),
        "claimed_paths": sorted(claimed),
        "claimed_digest": payload.get("claimed_digest"),
        "apply_rc": payload.get("apply_rc"),
        "apply_stderr": str(payload.get("apply_stderr", ""))[:2000],
    }
    info.socket_events = [str(e)[:100] for e in (result.get("socket_events") or [])][:50]
    info.env_tracing_vars = [str(e)[:60] for e in (result.get("env_tracing_vars") or [])][:50]
    return info


def resume(info: GraphInfo, decision: dict, *, timeout: float | None = None) -> None:
    """Resume the paused thread with the gate decision in a second confined process.

    Never raises: any failure lands in ``info.resume_error``; the decision is already made."""
    s = info._session
    try:
        if s is None:
            raise RuntimeError("no live session")
        dpath = s.inputs / "decision.json"
        dpath.write_text(json.dumps(decision, sort_keys=True))
        profile = Profile(ro=(package_root(), str(s.inputs), str(s.stage)), rw=(str(s.ckpt), str(s.driver)), net=False)
        argv = [*worker_prefix(), "resume", str(dpath)]
        try:
            cp = run_confined(argv, profile, cwd=str(s.stage), timeout=timeout or s.timeout, env=s.env)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"resume timed out after {e.timeout}s") from e
        if cp.returncode != 0:
            raise RuntimeError(f"resume process exited {cp.returncode}: {cp.stderr.strip()[-300:]}")
        result = _read_json(s.driver / "graph_result.json")
        cps, _ints, chans = read_checkpoint_ids(s)
        if result.get("next") != []:
            raise RuntimeError(f"graph did not finish (next={result.get('next')!r})")
        info.final_checkpoint_id = cps[-1] if cps else info.final_checkpoint_id
        info.resumed = True
        info.feedback_node_ran = "feedback" in chans
        info.feedback_executions = int(result.get("feedback_executions") or 0)
        info.socket_events = info.socket_events + [str(e)[:100] for e in (result.get("socket_events") or [])][:50]
    except Exception as e:  # noqa: BLE001 - reporting only
        info.resume_error = f"{type(e).__name__}: {str(e)[:300]}"


def resume_thread(
    thread_id: str,
    store: Path,
    *,
    checkpoint_id: str | None = None,
    timeout: float = 120,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
) -> dict:
    """Resume (or replay) a persisted thread from a new process."""
    d = _thread_dir(thread_id, store)
    meta = _meta(d)
    if meta.get("thread_id") != thread_id:
        raise RuntimeBoundary("layer1: store metadata names a different thread")
    if meta.get("state") == "agent-progress":
        raise RuntimeBoundary(
            "layer1: this thread is mid-agent (a crash left it in its agent loop, before any effect): it needs a proposer "
            "supplied by the host program; see agent.supervisor.resume_agent_thread. `hlith resume` cannot supply one"
        )
    with _locked(d):
        meta = _meta(d)
        with tempfile.TemporaryDirectory(prefix="hlith-resume-") as work:
            cps, ints, chans = _read_ids(d / "ckpt", Path(work), thread_id)
            if not cps or not ints:
                raise RuntimeBoundary("layer1: the stored thread never reached its interrupt")
            if ints[-1] != meta.get("interrupt_checkpoint_id") or (checkpoint_id is not None and checkpoint_id != ints[-1]):
                raise RuntimeBoundary(f"layer1: checkpoint id mismatch: recorded interrupt {ints[-1]}, asked {checkpoint_id}")
            if _verdict_path(d).exists():
                rec, source = _load_verdict(d, host_state=host_state, git_read=git_read), "recorded"
            else:
                rec, source = _record_verdict_locked(d, dict(INTERRUPTED_DECISION), "interrupted", host_state=host_state), "interrupted"
            decision = rec["decision"]
            crash_state = classify_crash_state(meta, verdict=rec)
            finished = "feedback" in chans
            resumed = False
            executions = None
            if not finished:
                versions()
                dpath = d / "inputs" / "decision.json"
                _write_json_atomic(dpath, decision)
                env = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "HLITH_STAGE": str(d / "stage"),
                    "HLITH_THREAD_ID": thread_id,
                    "HLITH_CKPT_DIR": str(d / "ckpt"),
                    "HLITH_DRIVER_DIR": str(d / "driver"),
                    "SQLITE_TMPDIR": str(d / "ckpt"),
                }
                if meta.get("graph_mode") == "agent":
                    env["HLITH_GRAPH_MODE"] = "agent"
                    env["HLITH_TASK_PATH"] = str(d / "inputs" / "task.txt")
                profile = Profile(
                    ro=(package_root(), str(d / "inputs"), str(d / "stage")),
                    rw=(str(d / "ckpt"), str(d / "driver")),
                    net=False,
                )
                try:
                    cp = run_confined([*worker_prefix(), "resume", str(dpath)], profile, cwd=str(d / "stage"), timeout=timeout, env=env)
                except subprocess.TimeoutExpired as e:
                    raise RuntimeBoundary(f"layer1: resume timed out after {e.timeout}s") from e
                if cp.returncode != 0:
                    raise RuntimeBoundary(f"layer1: resume process exited {cp.returncode}: {cp.stderr.strip()[-300:]}")
                result = _read_json(d / "driver" / "graph_result.json")
                if result.get("next") != []:
                    raise RuntimeBoundary(f"layer1: graph did not finish (next={result.get('next')!r})")
                executions = int(result.get("feedback_executions") or 0)
                cps, ints, chans = _read_ids(d / "ckpt", Path(work), thread_id)
                resumed = True
            m = _meta(d)
            m.update(finished=True, final_checkpoint_id=cps[-1])
            _write_json_atomic(d / "meta.json", m)
            if executions is None:
                executions = 1 if "feedback" in chans else 0
            return {
                "thread_id": thread_id,
                "interrupt_checkpoint_id": ints[-1],
                "final_checkpoint_id": cps[-1],
                "verdict_source": source,
                "crash_state": crash_state.value,
                "outcome": decision.get("outcome"),
                "exit_status": decision.get("exit_status"),
                "resumed": resumed,
                "already_finished": finished,
                "feedback_executions": executions,
            }


def _read_head_tree(target: Path, *, git_read: GitRead | None = None) -> str:
    from ..hostio.git_read import HardenedGitRead
    from ..hostio.integrity import HostIntegrityError

    reader = git_read if git_read is not None else HardenedGitRead()
    try:
        return str(reader.head_tree(target))
    except HostIntegrityError as e:
        raise RuntimeBoundary(str(e)) from None


def _export_clean_tree(target: Path, dest: Path, *, git_read: GitRead | None = None, snapshot_service: SnapshotService | None = None) -> None:
    from ..hostio.git_read import HardenedGitRead
    from ..hostio.integrity import HostIntegrityError

    try:
        if snapshot_service is not None:
            from ..hostio.snapshot_release import release_snapshots

            snap = snapshot_service.seal_base(target)
            try:
                shutil.copytree(snap.path, dest, symlinks=True)
            finally:
                release_snapshots(snapshot_service, snap)
            return
        reader = git_read if git_read is not None else HardenedGitRead()
        tree_oid = reader.head_tree(target)
        reader.export_tree(target, tree_oid, dest)
    except HostIntegrityError as e:
        raise RuntimeBoundary(str(e)) from None


def resume_agent_thread(
    thread_id: str,
    store: Path,
    proposer,
    *,
    timeout: float = 300,
    redo_inflight: bool = False,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
    snapshot_service: SnapshotService | None = None,
    _keep_session: bool = False,
) -> dict | tuple[dict, Layer1Session]:
    """Continue a thread that a crash left in its AGENT loop, from a NEW process, up to its effect interrupt."""
    if not isinstance(thread_id, str) or not _THREAD.fullmatch(thread_id):
        raise RuntimeBoundary(f"layer1: not a valid thread id: {str(thread_id)[:60]!r}")
    store = Path(store).expanduser().resolve()
    _private_dir(store, f"the thread store {store}")
    with _locked(store / thread_id):
        d = store / thread_id
        old = store / (".old-" + thread_id)
        if not d.exists() and old.exists():
            os.rename(old, d)
        d = _thread_dir(thread_id, store)
        meta = _meta(d)
        if meta.get("thread_id") != thread_id:
            raise RuntimeBoundary("layer1: store metadata names a different thread")
        if meta.get("state") != "agent-progress":
            raise RuntimeBoundary(
                "layer1: this thread is not mid-agent (it already reached its effect interrupt): resume it with `hlith resume`"
            )
        recorded_store = meta.get("store_path")
        if recorded_store is not None and Path(str(recorded_store)).resolve() != store:
            raise RuntimeBoundary("layer1: copied thread store detected (store_path mismatch); refusing duplicate resume")
        done_marker = _state_dir() / "locks" / f"{thread_id}.done"
        if done_marker.exists() or done_marker.is_symlink():
            raise RuntimeBoundary("layer1: this thread id has already been resumed to its interrupt on this host; refusing duplicate resume")
        turns_done = meta.get("turns_done")
        replies = meta.get("reply_sha256")
        recorded_td = meta.get("tree_digest")
        in_flight = meta.get("in_flight_turn")
        pending_turn = meta.get("pending_reply_turn")
        pending_sha = meta.get("pending_reply_sha256")
        command_sha = meta.get("command_argv_sha256")
        if (
            not isinstance(turns_done, int)
            or isinstance(turns_done, bool)
            or turns_done < 0
            or not isinstance(replies, list)
            or len(replies) != turns_done
            or not all(isinstance(r, str) for r in replies)
            or not isinstance(recorded_td, str)
            or "in_flight_turn" not in meta
            or (in_flight is not None and (not isinstance(in_flight, int) or isinstance(in_flight, bool) or in_flight != turns_done))
            or (pending_turn is None) != (pending_sha is None)
            or (pending_turn is not None and (not isinstance(pending_turn, int) or isinstance(pending_turn, bool) or pending_turn != turns_done))
            or (pending_sha is not None and (not isinstance(pending_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", pending_sha)))
            or (command_sha is not None and (not isinstance(command_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", command_sha)))
            or (in_flight is not None and pending_turn is not None)
        ):
            raise RuntimeBoundary("layer1: malformed agent-progress metadata: refusing to resume")
        want_mac = _progress_mac(
            thread_id,
            turns_done,
            replies,
            str(meta.get("target_path", "")),
            str(meta.get("base_tree", "")),
            recorded_td,
            _avoid_for(d, meta),
            in_flight_turn=in_flight,
            pending_reply_turn=pending_turn,
            pending_reply_sha256=pending_sha,
            command_argv_sha256=command_sha,
            export_manifest_sha256=meta.get("export_manifest_sha256"),
            create=False,
            host_state=host_state,
        )
        if not isinstance(meta.get("progress_mac"), str) or not hmac.compare_digest(meta["progress_mac"], want_mac):
            raise RuntimeBoundary("layer1: the recorded agent-progress metadata is not authenticated by this host's key: refusing to resume")
        proposer_sha = getattr(proposer, "argv_sha256", None)
        if command_sha is not None and proposer_sha != command_sha:
            raise RuntimeBoundary("layer1: proposer command argv hash does not match the saved thread")
        if callable(getattr(proposer, "ensure_paths_outside", None)):
            try:
                proposer.ensure_paths_outside((Path(str(meta.get("target_path", ""))), d / "stage", d / "channel", d / "inputs", *profile_extras()))
            except ValueError as e:
                raise RuntimeBoundary(str(e)) from None
        target = Path(meta["target_path"])
        try:
            cur_tree = _read_head_tree(target, git_read=git_read)
        except (RuntimeError, OSError) as e:
            raise RuntimeBoundary(f"layer1: the target repository is not usable: {str(e)[:120]}") from e
        if cur_tree != meta.get("base_tree"):
            raise RuntimeBoundary("layer1: the target is no longer at the recorded base tree; the mid-agent thread is not resumed")
        tmp_ctx = tempfile.TemporaryDirectory(prefix="hlith-agent-resume-")
        try:
            tmp_p = Path(tmp_ctx.name)
            budget = [0, 0]
            has_delta = (d / "stage_delta").exists()
            copy_names = ["stage", "channel", "inputs", "ckpt", "driver"]
            if has_delta:
                copy_names.append("stage_delta")
            for name in copy_names:
                _copy_regular_tree(d / name, tmp_p / name, budget)
            actual_td = _tree_digest(tmp_p)
            if not hmac.compare_digest(actual_td, recorded_td):
                raise RuntimeBoundary("layer1: stored thread contents do not match the authenticated tree digest; refusing to resume")
            crash_state = classify_crash_state(meta)
            if in_flight is not None and not redo_inflight:
                raise IndeterminateProposerCall(
                    f"a proposer call for turn {in_flight} was in flight when the run died ({crash_state.value}); "
                    "its side effects are unknown; re-run with --redo-inflight to call it again at your risk"
                )
            if redo_inflight and in_flight is None:
                raise RuntimeBoundary("layer1: --redo-inflight needs an authenticated in-flight proposer call")
            redone_turn = in_flight if redo_inflight else None
            ids_before = _read_ids(tmp_p / "ckpt", tmp_p, thread_id)[0]
            target_ro = tmp_p / "target_ro"
            _export_clean_tree(target, target_ro, git_read=git_read, snapshot_service=snapshot_service)
            stage, channel, inputs, ckpt, driver = (tmp_p / n for n in ("stage", "channel", "inputs", "ckpt", "driver"))
            if has_delta:
                shutil.rmtree(stage, ignore_errors=True)
                shutil.copytree(target_ro, stage, symlinks=True)
                recorded_em = meta.get("export_manifest_sha256")
                if not isinstance(recorded_em, str) or not hmac.compare_digest(_export_manifest_digest(stage), recorded_em):
                    raise RuntimeBoundary("layer1: exported stage manifest does not match recorded export_manifest_sha256")
                delta_dir = tmp_p / "stage_delta"
                deleted_obj = _read_json(delta_dir / "deleted.json")
                deleted_list = deleted_obj.get("deleted")
                if not isinstance(deleted_list, list) or not all(isinstance(x, str) for x in deleted_list):
                    raise RuntimeBoundary("layer1: malformed stage_delta deleted.json")
                stage_root = stage.resolve()
                for rel in deleted_list:
                    rel_p = Path(rel)
                    if rel_p.is_absolute() or ".." in rel_p.parts or not rel_p.parts:
                        raise RuntimeBoundary("layer1: invalid deleted path in stage_delta")
                    tgt_p = stage / rel_p
                    if not tgt_p.parent.resolve().is_relative_to(stage_root):
                        raise RuntimeBoundary("layer1: escaping deleted path in stage_delta")
                    if tgt_p.is_symlink() or tgt_p.is_file():
                        tgt_p.unlink()
                files_dir = delta_dir / "files"
                if files_dir.is_dir():
                    for dp, _dns, fns in os.walk(files_dir, followlinks=False):
                        rel_dir = Path(dp).relative_to(files_dir)
                        for fn in fns:
                            src_f = Path(dp) / fn
                            rel_parts = (rel_dir / fn).parts
                            if not rel_parts or any(p in ("", ".", "..") for p in rel_parts):
                                raise RuntimeBoundary("layer1: invalid file path in stage_delta")
                            cur = stage
                            for part in rel_parts[:-1]:
                                cur = cur / part
                                if cur.is_symlink():
                                    raise RuntimeBoundary("layer1: refusing to traverse symlinked dir in stage_delta")
                                if not cur.exists():
                                    cur.mkdir(mode=0o700)
                            if not cur.resolve().is_relative_to(stage_root):
                                raise RuntimeBoundary("layer1: escaping file path in stage_delta")
                            dst_f = cur / rel_parts[-1]
                            if dst_f.is_symlink() or dst_f.exists():
                                dst_f.unlink()
                            fd = os.open(dst_f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                            try:
                                os.write(fd, src_f.read_bytes())
                            finally:
                                os.close(fd)
            task_path = inputs / "task.txt"
            worker_ro = (str(target_ro), *profile_extras(), str(inputs))
            profile = Profile(ro=worker_ro, ro_bind=(str(target_ro),), rw=(str(stage), str(channel), str(ckpt), str(driver)), net=False)
            child_ro = (str(target_ro), str(inputs))
            cspec = Profile(ro=child_ro, rw=(str(stage), str(channel)), net=False).spec()
            cspec["ro"] = [p for p in cspec["ro"] if p != "/proc"]
            cspec["ro_bind"] = []
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "PYTHONDONTWRITEBYTECODE": "1",
                "HLITH_TARGET": str(target_ro),
                "HLITH_STAGE": str(stage),
                "HLITH_MANIFEST_DIR": str(channel),
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "HLITH_GRAPH_MODE": "agent",
                "HLITH_TASK_PATH": str(task_path),
                "HLITH_CKPT_DIR": str(ckpt),
                "HLITH_DRIVER_DIR": str(driver),
                "HLITH_THREAD_ID": thread_id,
                "HLITH_CHILD_SPEC": json.dumps(cspec),
                "SQLITE_TMPDIR": str(ckpt),
            }
            session = Layer1Session(tmp=tmp_ctx, stage=stage, ckpt=ckpt, channel=channel, driver=driver, inputs=inputs, thread_id=thread_id, env=env, timeout=timeout)

            def progress(
                n: int,
                shas: list[str],
                *,
                in_flight_turn=None,
                pending_reply_turn=None,
                pending_reply_sha256=None,
            ) -> bool:
                if _non_regular_entry(session.stage) is not None or _non_regular_entry(session.channel) is not None:
                    return False
                _persist_into(
                    session,
                    d,
                    meta,
                    turns_done=n,
                    reply_sha256=shas,
                    in_flight_turn=in_flight_turn,
                    pending_reply_turn=pending_reply_turn,
                    pending_reply_sha256=pending_reply_sha256,
                    host_state=host_state,
                )
                return True

            versions()
            report = drive_agent(
                session,
                profile,
                proposer,
                task_path,
                subprocess.CompletedProcess([], 0, "", ""),
                timeout=timeout,
                progress=progress,
                replies0=list(replies),
                pending_reply=(pending_turn, pending_sha) if pending_turn is not None else None,
                redone_turn=redone_turn,
            )
            payload = _read_json(driver / "graph_payload.json")
            result = _read_json(driver / "graph_result.json")
            cps, ints, _chans = _read_ids(ckpt, tmp_p, thread_id)
            if result.get("next") != ["propose"] or payload.get("node") != "propose" or payload.get("thread_id") != thread_id:
                raise RuntimeBoundary("layer1: the resumed agent thread did not reach its effect interrupt")
            claimed = payload.get("claimed")
            if not (isinstance(claimed, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in claimed.items())):
                raise RuntimeBoundary("layer1: interrupt payload has a malformed claim")
            now = _measure(stage)
            if any((now.get(p) != dg) if dg != "deleted" else (p in now) for p, dg in claimed.items()) or claimed_digest(claimed) != payload.get("claimed_digest"):
                raise RuntimeBoundary("layer1: the resumed thread's claim does not match its stage")
            if not cps or not ints:
                raise RuntimeBoundary("layer1: the resumed thread has no interrupt checkpoint")
            _persist_into(session, d, meta, turns_done=None, reply_sha256=None, final=(ints[-1], cps[-1]), report=report, profile_sha256=meta.get("profile_sha256"), host_state=host_state)
            try:
                fd_done = os.open(done_marker, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                os.close(fd_done)
            except OSError:
                pass
            report_out = {
                "thread_id": thread_id,
                "resumed_from_turn": int(meta.get("turns_done") or 0),
                "crash_state": crash_state.value,
                "reached": "propose",
                "interrupt_checkpoint_id": ints[-1],
                "paused_checkpoint_id": cps[-1],
                "ids_before": ids_before,
                "ids_after": cps,
                "checkpoint_prefix_preserved": cps[:len(ids_before)] == ids_before,
                "claimed_paths": sorted(claimed),
                "claimed_digest": payload.get("claimed_digest"),
                "transcript": payload.get("transcript") or [],
                "proposer": report,
            }
            if _keep_session:
                return report_out, session
            return report_out
        except BaseException:
            if _keep_session:
                tmp_ctx.cleanup()
            raise
        finally:
            if not _keep_session:
                tmp_ctx.cleanup()


def drive_agent(
    session: Layer1Session,
    profile: Profile,
    proposer,
    task_path: Path,
    first: subprocess.CompletedProcess,
    *,
    timeout: float,
    progress=None,
    replies0: list[str] | None = None,
    pending_reply: tuple[int, str] | None = None,
    redone_turn: int | None = None,
) -> dict:
    """Supervisor-side agent loop with authenticated in-flight and saved-reply checkpoints."""
    cp = first
    replies: list[str] = list(replies0 or [])
    not_durable: list[int] = []
    pending_turn, pending_sha = pending_reply if pending_reply is not None else (None, None)
    for n in range(len(replies), len(replies) + AGENT_MAX_TURNS + 2):
        if cp.returncode != 0:
            raise RuntimeBoundary(f"layer1: agent worker exited {cp.returncode}: {cp.stderr.strip()[-400:]}")
        result = _read_json(session.driver / "graph_result.json")
        nxt = result.get("next")
        if nxt == ["propose"]:
            if pending_turn is not None:
                raise RuntimeBoundary("layer1: graph reached the effect interrupt with an unconsumed saved proposer reply")
            out: dict = {
                "kind": proposer.kind,
                "model_id": proposer.model_id,
                "plumbing_only": bool(proposer.plumbing_only),
                "turns": len(replies),
                "reply_sha256": replies,
            }
            if callable(getattr(proposer, "provenance", None)):
                prov = proposer.provenance()
                out.update(prov)
                if "argv_sha256" in prov:
                    out["command_argv_sha256"] = prov["argv_sha256"]
            elif getattr(proposer, "argv_sha256", None):
                out["command_argv_sha256"] = proposer.argv_sha256
                out["allow_unconfined"] = bool(getattr(proposer, "allow_unconfined", False))
                out["confined"] = not out["allow_unconfined"]
                out["counts_as_e2"] = bool(getattr(proposer, "counts_as_e2", not out["allow_unconfined"]))
            if redone_turn is not None:
                out.update(redo_inflight=True, redone_turn=redone_turn)
            if not_durable:
                out["progress_not_durable_at_turns"] = sorted(set(not_durable))
            return out
        if nxt != ["agent_turn"]:
            raise RuntimeBoundary(f"layer1: agent graph paused at an unexpected node: {nxt!r}")
        turn = _read_json(session.driver / "graph_payload.json")
        if turn.get("node") != "agent_turn" or turn.get("thread_id") != session.thread_id:
            raise RuntimeBoundary("layer1: agent payload does not belong to this thread")
        if pending_turn is not None and pending_turn != n:
            raise RuntimeBoundary("layer1: saved reply belongs to a different agent turn")
        used_pending = pending_turn == n
        if used_pending:
            rpath = session.inputs / f"reply-{n}.json"
            try:
                raw = rpath.read_text()
                reply = json.loads(raw)
            except (OSError, ValueError):
                raise RuntimeBoundary("layer1: saved proposer reply is missing or malformed") from None
            reply_sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if reply_sha != pending_sha:
                raise RuntimeBoundary("layer1: saved proposer reply hash does not match its authenticated progress record")
            pending_turn = pending_sha = None
        else:
            if progress is not None:
                if progress(len(replies), list(replies), in_flight_turn=n) is False:
                    not_durable.append(len(replies))
                    if getattr(proposer, "argv_sha256", None):
                        raise RuntimeBoundary("layer1: proposer call not started because its in-flight checkpoint was not durable")
            failure_msg = None
            reply = None
            try:
                reply = proposer.reply({"turn": turn["turn"], "task": turn["task"], "transcript": turn["transcript"]})
            except Exception as e:  # noqa: BLE001
                failure_msg = _safe_proposer_failure(e)
            if failure_msg is not None:
                raise RuntimeBoundary(failure_msg)
            raw = json.dumps(reply, sort_keys=True)
            if len(raw) > AGENT_MAX_REPLY:
                raise RuntimeBoundary(f"layer1: proposer reply of {len(raw)} bytes exceeds the {AGENT_MAX_REPLY} limit")
            reply_sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            rpath = session.inputs / f"reply-{n}.json"
            rpath.write_text(raw)
            if progress is not None and progress(len(replies), list(replies), pending_reply_turn=n, pending_reply_sha256=reply_sha) is False:
                not_durable.append(len(replies))
        if len(raw) > AGENT_MAX_REPLY:
            raise RuntimeBoundary(f"layer1: proposer reply of {len(raw)} bytes exceeds the {AGENT_MAX_REPLY} limit")
        try:
            cp = run_confined([*worker_prefix(), "resume", str(rpath)], profile, cwd=str(session.stage), timeout=timeout, env=session.env)
        except subprocess.TimeoutExpired as e:
            raise RuntimeBoundary(f"layer1: agent turn timed out after {e.timeout}s") from e
        replies.append(reply_sha)
        if progress is not None and progress(len(replies), list(replies)) is False:
            not_durable.append(len(replies) - 1)
    raise RuntimeBoundary("layer1: agent loop did not reach its effect interrupt")


def run_worker(
    target: Path,
    worker_argv_in: list[str],
    *,
    proposer_id: str = "worker",
    timeout: float = 120,
    worker_ro: tuple[str, ...] = (),
    patch: bytes | None = None,
    manifest_bytes: bytes | None = None,
    layer1: bool = False,
    thread_store: Path | None = None,
    proposer=None,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
    snapshot_service: SnapshotService | None = None,
    thread_id: str | None = None,
    run_id: str | None = None,
) -> WorkerRun:
    """Run ``worker_argv_in`` against a staged copy of ``target``; never writes target."""
    import uuid

    target = Path(target).resolve()
    if patch is not None and len(patch) > MAX_EFFECT_BYTES:
        raise EffectRejected(f"patch is {len(patch)} bytes, over the {MAX_EFFECT_BYTES} limit")
    if not (target / ".git").exists():
        raise RuntimeBoundary(f"{target} is not a git repository")
    if proposer is not None and not (layer1 and patch is None and not worker_argv_in):
        raise RuntimeBoundary("a proposer needs --layer1 and replaces the worker command and the patch")
    if layer1 and thread_store is not None:
        thread_store = check_store(thread_store, target)
    before = worktree_digest(target)
    base_tree = _read_head_tree(target, git_read=git_read)
    tmp_ctx = tempfile.TemporaryDirectory(prefix="hlith-run-")
    graph = None
    try:
        tmp_p = Path(tmp_ctx.name)
        stage = tmp_p / "stage"
        _materialise(target, stage, git_read=git_read, snapshot_service=snapshot_service)
        target_ro = tmp_p / "target_ro"
        _materialise(target, target_ro, git_read=git_read, snapshot_service=snapshot_service)
        channel = tmp_p / "channel"
        channel.mkdir()
        inputs = tmp_p / "inputs"
        inputs.mkdir()
        rw_extra: tuple[str, ...] = ()
        agent_env: dict[str, str] = {}
        tid = thread_id
        if layer1:
            versions()
            tid = tid or f"hlith-{uuid.uuid4().hex[:20]}"
            ckpt = tmp_p / "ckpt"
            ckpt.mkdir()
            driver = tmp_p / "driver"
            driver.mkdir()
            rw_extra = (str(ckpt), str(driver))
            child_ro = (str(target_ro), *worker_ro, str(inputs))
            worker_ro = (*worker_ro, *profile_extras(), str(inputs))
        if patch is not None:
            (inputs / "op.patch").write_bytes(patch)
            cmd_argv = (
                worker_argv("patch", str(inputs / "op.patch"), [])
                if layer1
                else ["git", "apply", "--whitespace=nowarn", str(inputs / "op.patch")]
            )
            worker_ro = (*worker_ro, str(inputs))
        elif proposer is not None:
            (inputs / "task.txt").write_text(scrub_task(getattr(proposer, "task", None) or "Make the requested change.")[0])
            cmd_argv = worker_argv("agent", str(inputs / "task.txt"), [])
            worker_ro = (*worker_ro, str(inputs))
            agent_env = {"HLITH_GRAPH_MODE": "agent", "HLITH_TASK_PATH": str(inputs / "task.txt")}
        elif layer1:
            cmd_argv = worker_argv("cmd", None, list(worker_argv_in))
        else:
            cmd_argv = list(worker_argv_in)
        if proposer is not None and callable(getattr(proposer, "ensure_paths_outside", None)):
            try:
                proposer.ensure_paths_outside((target, target_ro, stage, channel, inputs, *worker_ro))
            except ValueError as e:
                raise RuntimeBoundary(str(e)) from None
        if manifest_bytes is not None:
            (channel / "manifest.json").write_bytes(manifest_bytes)
        profile = Profile(
            ro=(str(target_ro), *worker_ro),
            ro_bind=(str(target_ro),),
            rw=(str(stage), str(channel), *rw_extra),
            net=False,
        )
        _mac_key((*profile.ro, *profile.rw, *profile.ro_bind, target), host_state=host_state)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HLITH_TARGET": str(target_ro),
            "HLITH_STAGE": str(stage),
            "HLITH_MANIFEST_DIR": str(channel),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        }
        env.update(agent_env)
        if layer1:
            assert tid is not None
            env["HLITH_CKPT_DIR"] = str(ckpt)
            env["HLITH_DRIVER_DIR"] = str(driver)
            env["HLITH_THREAD_ID"] = tid
            cspec = Profile(ro=child_ro, rw=(str(stage), str(channel)), net=False).spec()
            cspec["ro"] = [p for p in cspec["ro"] if p != "/proc"]
            cspec["ro_bind"] = []
            env["HLITH_CHILD_SPEC"] = json.dumps(cspec)
            env["SQLITE_TMPDIR"] = str(ckpt)
        try:
            cp = run_confined(cmd_argv, profile, cwd=str(stage), timeout=timeout, env=env)
        except subprocess.TimeoutExpired as e:
            raise RuntimeBoundary(f"worker timed out after {timeout}s") from e
        except GrantError as e:
            raise RuntimeBoundary(str(e)) from e
        if cp.returncode == EXIT_BOUNDARY and "hlith-confine:" in cp.stderr:
            raise RuntimeBoundary(cp.stderr.strip())
        agent_report = None
        if proposer is not None:
            assert tid is not None
            session0 = Layer1Session(
                tmp=tmp_ctx,
                stage=stage,
                ckpt=ckpt,
                channel=channel,
                driver=driver,
                inputs=inputs,
                thread_id=tid,
                env=env,
                timeout=timeout,
            )
            prog = None
            if thread_store is not None:
                def prog(n: int, shas: list, *, in_flight_turn=None, pending_reply_turn=None, pending_reply_sha256=None, _s=session0) -> bool:
                    return (
                        persist_progress(
                            _s,
                            thread_store,
                            target=target,
                            base_tree=base_tree,
                            turns_done=n,
                            reply_sha256=shas,
                            in_flight_turn=in_flight_turn,
                            pending_reply_turn=pending_reply_turn,
                            pending_reply_sha256=pending_reply_sha256,
                            command_argv_sha256=getattr(proposer, "argv_sha256", None),
                            profile_sha256=profile.sha256,
                            host_state=host_state,
                            run_id=run_id,
                        )
                        is not None
                    )
            agent_report = drive_agent(session0, profile, proposer, inputs / "task.txt", cp, timeout=timeout, progress=prog)
            cp = subprocess.CompletedProcess(cp.args, 0, "", "")
        if patch is not None and not layer1 and cp.returncode != 0:
            raise RuntimeBoundary(f"patch does not apply: {cp.stderr.strip()[:300]}")
        scan = _scan_stage(stage, MAX_EFFECT_BYTES, MAX_EFFECT_ENTRIES)
        skipped = scan.skipped
        diff, touched, ignored, flags, observed = _diff_stage(target, stage, tmp_p, scan.non_utf8)
        try:
            diff.encode("utf-8")
        except UnicodeEncodeError:
            raise EffectRejected("diff is not representable as UTF-8 text")
        manifest, deltas, manifest_error = read_manifest_full(channel)
        profile_sha = profile.sha256
        wrc, wout, werr = cp.returncode, cp.stdout, cp.stderr
        if layer1:
            assert tid is not None
            session = Layer1Session(
                tmp=tmp_ctx,
                stage=stage,
                ckpt=ckpt,
                channel=channel,
                driver=driver,
                inputs=inputs,
                thread_id=tid,
                env=env,
                timeout=timeout,
            )
            graph = after_run(session, cp.returncode, cp.stderr, observed, ignored, skipped)
            graph.proposer = agent_report
            if thread_store is not None:
                persist(
                    session,
                    graph,
                    thread_store,
                    target=target,
                    base_tree=base_tree,
                    patch_sha256=hashlib.sha256(patch).hexdigest() if patch is not None else None,
                    host_state=host_state,
                    run_id=run_id,
                )
            wrc, wout, werr = graph.interrupt_payload["apply_rc"], "", graph.interrupt_payload["apply_stderr"]
            if patch is not None and wrc != 0:
                raise RuntimeBoundary(f"patch does not apply: {werr.strip()[:300]}")
    except BaseException:
        tmp_ctx.cleanup()
        raise
    if graph is None:
        tmp_ctx.cleanup()
    after = worktree_digest(target)
    return WorkerRun(
        effect=DeltaEffect(unified_diff=diff, proposer_id=proposer_id, touched_files=touched, deltas=deltas),
        base_tree=base_tree,
        target_tree_before=before,
        target_tree_after=after,
        profile_sha256=profile_sha,
        worker_returncode=wrc,
        worker_stdout=wout,
        worker_stderr=werr,
        ignored_paths=ignored,
        skipped_paths=skipped,
        risk_flags=flags,
        observed=observed,
        manifest=manifest,
        manifest_error=manifest_error,
        graph=graph,
    )


def resume_agent_worker(
    target: Path,
    thread_id: str,
    thread_store: Path,
    proposer,
    *,
    timeout: float = 120,
    redo_inflight: bool = False,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
    snapshot_service: SnapshotService | None = None,
) -> WorkerRun:
    """Resume a durable local proposer thread, then expose its measured effect to the normal derive/gate pipeline."""
    store = Path(thread_store).expanduser().resolve()
    report, session = resume_agent_thread(
        thread_id,
        store,
        proposer,
        timeout=timeout,
        redo_inflight=redo_inflight,
        host_state=host_state,
        git_read=git_read,
        snapshot_service=snapshot_service,
        _keep_session=True,
    )
    tmp_ctx = tempfile.TemporaryDirectory(prefix="hlith-agent-effect-")
    try:
        d = _thread_dir(thread_id, store)
        meta = _meta(d)
        recorded_target = Path(str(meta.get("target_path", ""))).resolve()
        target = Path(target).resolve()
        if recorded_target != target:
            raise RuntimeBoundary("resumed agent thread target does not match the requested repository")
        before = worktree_digest(target)
        scan = _scan_stage(session.stage, MAX_EFFECT_BYTES, MAX_EFFECT_ENTRIES)
        diff, touched, ignored, flags, observed = _diff_stage(target, session.stage, Path(tmp_ctx.name), scan.non_utf8)
        manifest, deltas, manifest_error = read_manifest_full(session.channel)
        check_store(store, target)
        graph = after_run(session, 0, "", observed, ignored, scan.skipped)
        graph._session = None
        graph._store_dir = d
        graph.thread_store = str(store)
        graph.proposer = report["proposer"]
        after = worktree_digest(target)
        return WorkerRun(
            effect=DeltaEffect(
                unified_diff=diff,
                proposer_id=str(report["proposer"].get("model_id") or "local-command"),
                touched_files=touched,
                deltas=deltas,
            ),
            base_tree=str(meta.get("base_tree", "")),
            target_tree_before=before,
            target_tree_after=after,
            profile_sha256=str(meta.get("profile_sha256") or "n/a:resumed-agent"),
            worker_returncode=int(graph.interrupt_payload.get("apply_rc") or 0),
            worker_stdout="",
            worker_stderr=str(graph.interrupt_payload.get("apply_stderr") or ""),
            ignored_paths=ignored,
            skipped_paths=scan.skipped,
            observed=observed,
            manifest=manifest,
            manifest_error=manifest_error,
            graph=graph,
            risk_flags=flags,
        )
    finally:
        session.tmp.cleanup()
        tmp_ctx.cleanup()


def _apply_stage_delta(stage: Path, delta_dir: Path) -> None:
    """Overlay an authenticated stage_delta onto a freshly exported base. Refuses path escape and symlinks."""
    deleted_obj = _read_json(delta_dir / "deleted.json")
    deleted_list = deleted_obj.get("deleted")
    if not isinstance(deleted_list, list) or not all(isinstance(x, str) for x in deleted_list):
        raise RuntimeBoundary("layer1: malformed stage_delta deleted.json")
    stage_root = stage.resolve()
    for rel in deleted_list:
        rel_p = Path(rel)
        if rel_p.is_absolute() or ".." in rel_p.parts or not rel_p.parts:
            raise RuntimeBoundary("layer1: invalid deleted path in stage_delta")
        tgt_p = stage / rel_p
        if not tgt_p.parent.resolve().is_relative_to(stage_root):
            raise RuntimeBoundary("layer1: escaping deleted path in stage_delta")
        if tgt_p.is_symlink() or tgt_p.is_file():
            tgt_p.unlink()
    files_dir = delta_dir / "files"
    if not files_dir.is_dir():
        return
    for dp, _dns, fns in os.walk(files_dir, followlinks=False):
        rel_dir = Path(dp).relative_to(files_dir)
        for fn in fns:
            src_f = Path(dp) / fn
            rel_parts = (rel_dir / fn).parts
            if not rel_parts or any(p in ("", ".", "..") for p in rel_parts):
                raise RuntimeBoundary("layer1: invalid file path in stage_delta")
            cur = stage
            for part in rel_parts[:-1]:
                cur = cur / part
                if cur.is_symlink():
                    raise RuntimeBoundary("layer1: refusing to traverse symlinked dir in stage_delta")
                if not cur.exists():
                    cur.mkdir(mode=0o700)
            if not cur.resolve().is_relative_to(stage_root):
                raise RuntimeBoundary("layer1: escaping file path in stage_delta")
            dst_f = cur / rel_parts[-1]
            if dst_f.is_symlink() or dst_f.exists():
                dst_f.unlink()
            fd = os.open(dst_f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, src_f.read_bytes())
            finally:
                os.close(fd)


def resume_captured_worker(
    target: Path,
    thread_id: str,
    thread_store: Path,
    *,
    checkpoint_id: str | None,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
    snapshot_service: SnapshotService | None = None,
) -> WorkerRun:
    """Rebuild a parked effect from its authenticated stage delta and hand it to the normal gate. Never calls a proposer."""
    if not isinstance(thread_id, str) or not _THREAD.fullmatch(thread_id):
        raise RuntimeBoundary(f"layer1: not a valid thread id: {str(thread_id)[:60]!r}")
    store = Path(thread_store).expanduser().resolve()
    target = Path(target).resolve()
    with _locked(store / thread_id):
        d = _thread_dir(thread_id, store)
        meta = _meta(d)
        if meta.get("thread_id") != thread_id:
            raise RuntimeBoundary("layer1: store metadata names a different thread")
        recorded_store = meta.get("store_path")
        if not isinstance(recorded_store, str) or not recorded_store or Path(recorded_store).expanduser().resolve() != store:
            raise RuntimeBoundary("layer1: thread store does not match the recorded capture location")
        if meta.get("state") == "agent-progress":
            raise RuntimeBoundary(
                "layer1: this thread is mid-agent (a crash left it in its agent loop, before any effect): it needs a proposer "
                "supplied by the host program; see agent.supervisor.resume_agent_thread"
            )
        # Finished checkpoints are never new work, even if a store-write attacker removed
        # verdict.json. A lost/corrupt verdict is a boundary, never permission to rejudge.
        if meta.get("finished") or meta.get("final_checkpoint_id"):
            raise RuntimeBoundary("layer1: finished effect interrupt cannot re-enter the gate; recorded verdict required")
        interrupt_id = meta.get("interrupt_checkpoint_id")
        if not isinstance(interrupt_id, str) or not interrupt_id:
            raise RuntimeBoundary("layer1: this thread has no effect-interrupt checkpoint")
        if _verdict_path(d).exists():
            raise RuntimeBoundary("layer1: this effect interrupt already has a recorded verdict; refusing to run the gate again")
        if not isinstance(meta.get("captured_mac"), str) or not isinstance(meta.get("tree_digest"), str):
            raise RuntimeBoundary(
                "layer1: effect interrupt was persisted without an authenticated stage delta; refusing to invent an effect"
            )
        if checkpoint_id != interrupt_id:
            raise RuntimeBoundary(
                f"layer1: checkpoint id mismatch: recorded interrupt {interrupt_id}, asked {checkpoint_id}"
            )
        recorded_target = Path(str(meta.get("target_path") or "")).resolve()
        if recorded_target != target:
            raise RuntimeBoundary("resumed effect thread target does not match the requested repository")
        try:
            cur_tree = _read_head_tree(target, git_read=git_read)
        except (RuntimeError, OSError) as e:
            raise RuntimeBoundary(f"layer1: the target repository is not usable: {str(e)[:120]}") from e
        if cur_tree != meta.get("base_tree"):
            raise RuntimeBoundary("layer1: the target is no longer at the recorded base tree; the captured effect is not resumed")
        actual_td = _tree_digest(d)
        if not hmac.compare_digest(actual_td, str(meta["tree_digest"])):
            raise RuntimeBoundary("layer1: stored effect does not match the authenticated tree digest; refusing to resume")
        want_mac = _captured_mac(
            thread_id,
            interrupt_id,
            str(meta.get("paused_checkpoint_id") or ""),
            str(recorded_store),
            str(recorded_target),
            str(meta.get("base_tree") or ""),
            str(meta["tree_digest"]),
            str(meta.get("claimed_digest") or ""),
            meta.get("patch_sha256") if isinstance(meta.get("patch_sha256"), str) else None,
            str(meta.get("export_manifest_sha256") or ""),
            _avoid_for(d, meta),
            create=False,
            host_state=host_state,
        )
        if not hmac.compare_digest(meta["captured_mac"], want_mac):
            raise RuntimeBoundary("layer1: the recorded effect-interrupt metadata is not authenticated by this host's key: refusing to resume")
        with tempfile.TemporaryDirectory(prefix="hlith-captured-ids-") as id_work:
            _cps, ints, _chans = _read_ids(d / "ckpt", Path(id_work), thread_id)
        if not ints or ints[-1] != interrupt_id:
            raise RuntimeBoundary(
                f"layer1: checkpoint id mismatch: sqlite interrupt {ints[-1] if ints else None}, recorded {interrupt_id}"
            )
        tmp_ctx = tempfile.TemporaryDirectory(prefix="hlith-captured-")
        diff_ctx = tempfile.TemporaryDirectory(prefix="hlith-captured-diff-")
        try:
            tmp_p = Path(tmp_ctx.name)
            budget = [0, 0]
            for name in ("ckpt", "driver", "inputs", "channel", "stage_delta"):
                _copy_regular_tree(d / name, tmp_p / name, budget)
            target_ro = tmp_p / "target_ro"
            _export_clean_tree(target, target_ro, git_read=git_read, snapshot_service=snapshot_service)
            stage = tmp_p / "stage"
            shutil.copytree(target_ro, stage, symlinks=True)
            recorded_em = meta.get("export_manifest_sha256")
            if not isinstance(recorded_em, str) or not hmac.compare_digest(_export_manifest_digest(stage), recorded_em):
                raise RuntimeBoundary("layer1: exported stage manifest does not match recorded export_manifest_sha256")
            _apply_stage_delta(stage, tmp_p / "stage_delta")
            before = worktree_digest(target)
            scan = _scan_stage(stage, MAX_EFFECT_BYTES, MAX_EFFECT_ENTRIES)
            diff, touched, ignored, flags, observed = _diff_stage(target, stage, Path(diff_ctx.name), scan.non_utf8)
            manifest, deltas, manifest_error = read_manifest_full(tmp_p / "channel")
            authenticated_manifest = read_manifest_document(tmp_p / "channel")
            session = Layer1Session(
                tmp=tmp_ctx,
                stage=stage,
                ckpt=tmp_p / "ckpt",
                channel=tmp_p / "channel",
                driver=tmp_p / "driver",
                inputs=tmp_p / "inputs",
                thread_id=thread_id,
                env={},
                timeout=1,
            )
            graph = after_run(session, 0, "", observed, ignored, scan.skipped)
            graph._session = None
            graph._store_dir = d
            graph.thread_store = str(store)
            proposer_report = meta.get("proposer") if isinstance(meta.get("proposer"), dict) else None
            graph.proposer = proposer_report
            if str(graph.interrupt_checkpoint_id) != interrupt_id:
                raise RuntimeBoundary(
                    f"layer1: rebuilt effect interrupt {graph.interrupt_checkpoint_id} does not match the recorded checkpoint {interrupt_id}"
                )
            after = worktree_digest(target)
            proposer_id = "captured-effect"
            if proposer_report and proposer_report.get("model_id"):
                proposer_id = str(proposer_report["model_id"])
            return WorkerRun(
                effect=DeltaEffect(
                    unified_diff=diff,
                    proposer_id=proposer_id,
                    touched_files=touched,
                    deltas=deltas,
                ),
                base_tree=str(meta.get("base_tree") or ""),
                target_tree_before=before,
                target_tree_after=after,
                profile_sha256=str(meta.get("profile_sha256") or "n/a:captured-effect"),
                worker_returncode=int(graph.interrupt_payload.get("apply_rc") or 0),
                worker_stdout="",
                worker_stderr=str(graph.interrupt_payload.get("apply_stderr") or ""),
                ignored_paths=ignored,
                skipped_paths=scan.skipped,
                observed=observed,
                manifest=manifest,
                manifest_error=manifest_error,
                authenticated_manifest=authenticated_manifest,
                graph=graph,
                risk_flags=flags,
            )
        finally:
            tmp_ctx.cleanup()
            diff_ctx.cleanup()


__all__ = [
    "AGENT_MAX_REPLY",
    "AGENT_MAX_TURNS",
    "INTERRUPTED_DECISION",
    "LAYER1",
    "NOT_INSTALLED",
    "SOCKET_EVENTS_SCOPE",
    "CrashState",
    "GraphInfo",
    "IndeterminateProposerCall",
    "Layer1Session",
    "_BOOT",
    "_WORKER_OK",
    "_avoid_for",
    "_boundary",
    "_copy_regular_tree",
    "_decision_sha",
    "_load_verdict",
    "_locked",
    "_mac_key",
    "_meta",
    "_non_regular_entry",
    "_persist_into",
    "_private_dir",
    "_progress_mac",
    "_read_ids",
    "_read_json",
    "_record_verdict_locked",
    "_safe_class",
    "_state_dir",
    "_sync_dirs",
    "_target_has_commit",
    "_thread_dir",
    "_tree_digest",
    "_verdict_mac",
    "_verdict_path",
    "_write_json_atomic",
    "after_run",
    "agent_worker_env_names",
    "check_store",
    "check_worker_importable",
    "classify_crash_state",
    "default_store",
    "drive_agent",
    "package_root",
    "persist",
    "persist_progress",
    "profile_extras",
    "read_checkpoint_ids",
    "record_verdict",
    "resume",
    "resume_agent_thread",
    "resume_agent_worker",
    "resume_captured_worker",
    "resume_thread",
    "rotate_mac_key",
    "run_worker",
    "sync_after_resume",
    "thread_target",
    "versions",
    "worker_argv",
    "worker_prefix",
]
