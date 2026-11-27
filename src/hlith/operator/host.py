# SPDX-License-Identifier: Apache-2.0
"""Operator HOST functions the TUI launcher needs from lower layers (local-agent thread discovery, disposable clone, per-repo
feedback store sync). They live here, not in ``operator.tui``: views may not import L1/L4/L5 (layer map); the host may use the
public APIs of L1 (``hlith.agent``), L5 (``hlith.feedback``) and hostio. The launcher calls these through thin wrappers."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path


def agent_progress(run: dict) -> list[dict]:
    """Find durable local-agent turns left by a UI run that stopped without an artifact.

    The metadata is only a display hint. `hlith resume` authenticates the saved
    thread before it can call a proposer or honor --redo-inflight.
    """
    meta = run.get("meta") or {}
    argv = meta.get("argv") or run.get("argv") or []
    try:
        command = argv[argv.index("--proposer-command") + 1]
        store_arg = argv[argv.index("--thread-store") + 1]
    except (ValueError, IndexError, TypeError):
        return []
    target = Path(str(meta.get("clone") or "")).expanduser().resolve()
    store = Path(str(store_arg)).expanduser()
    if not target.is_dir() or store.is_symlink() or not store.is_dir():
        return []
    try:
        st = store.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return []
        store = store.resolve()
        if store == target or store in target.parents:
            return []
        from ..agent import CommandProposer
        from ..agent import checkpoint as layer1
        proposer = CommandProposer(shlex.split(command))
        candidates = []
        for entry in sorted(store.iterdir()):
            if entry.name.startswith(".") or entry.is_symlink() or not entry.is_dir():
                continue
            try:
                thread_dir = layer1._thread_dir(entry.name, store)
                saved = layer1._meta(thread_dir)
                thread_target = layer1.thread_target(entry.name, store)
            except Exception:  # a malformed or untrusted thread is not offered for resume
                continue
            if (saved.get("state") != "agent-progress" or thread_target != target
                    or saved.get("command_argv_sha256") != proposer.argv_sha256):
                continue
            in_flight = saved.get("in_flight_turn")
            pending = saved.get("pending_reply_turn")
            if isinstance(in_flight, int) and not isinstance(in_flight, bool):
                candidates.append({"thread_id": entry.name, "thread_store": store, "target": target,
                                   "command": command, "in_flight_turn": in_flight, "pending_reply_turn": None,
                                   "origin_run_id": meta.get("run_id")})
            elif isinstance(pending, int) and not isinstance(pending, bool):
                candidates.append({"thread_id": entry.name, "thread_store": store, "target": target,
                                   "command": command, "in_flight_turn": None, "pending_reply_turn": pending,
                                   "origin_run_id": meta.get("run_id")})
        return candidates
    except (OSError, ValueError, TypeError):
        return []


def captured_interrupts(run: dict) -> list[dict]:
    """Effect-interrupt checkpoints the default resume can take back through the gate.

    Mid-agent threads stay on ``agent_progress``. A parked effect is not an in-flight proposer call: resuming it must not
    call the proposer again, and it is not offered when the stage delta was not authenticated.
    """
    meta = run.get("meta") or {}
    argv = meta.get("argv") or run.get("argv") or []
    try:
        store_arg = argv[argv.index("--thread-store") + 1]
    except (ValueError, IndexError, TypeError):
        return []
    command = None
    try:
        command = argv[argv.index("--proposer-command") + 1]
    except (ValueError, IndexError, TypeError):
        command = None
    target = Path(str(meta.get("clone") or "")).expanduser().resolve()
    store = Path(str(store_arg)).expanduser()
    if not target.is_dir() or store.is_symlink() or not store.is_dir():
        return []
    try:
        st = store.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return []
        store = store.resolve()
        if store == target or store in target.parents:
            return []
        from ..agent.checkpoint import list_effect_interrupts
        from ..agent.proposer import CommandProposer

        want_sha = CommandProposer(shlex.split(command)).argv_sha256 if command else None
        rows = []
        for desc in list_effect_interrupts(store, target):
            recorded = desc.get("command_argv_sha256")
            if want_sha is not None and recorded not in (None, want_sha):
                continue
            rows.append({
                "kind": "effect-interrupt",
                "thread_id": desc["thread_id"],
                "thread_store": store,
                "target": target,
                "command": command,
                "interrupt_checkpoint_id": desc["interrupt_checkpoint_id"],
                "in_flight_turn": None,
                "pending_reply_turn": None,
                "origin_run_id": meta.get("run_id"),
            })
        return rows
    except (OSError, ValueError, TypeError):
        return []




def _clone_source(src, dst, base_rev) -> tuple[bool, str]:
    """The disposable clone of a user-selected (untrusted) repository: scrubbed git environment (a caller's GIT_DIR / GIT_WORK_TREE cannot redirect where it is written),
    the gate's -c overrides, origin removed (nothing can be pushed from it), checked out at its own base when given. The destination must not be a symlink and must be
    absent or an empty directory."""
    from . import gitq
    from ..hostio import git_read as _ro
    import shutil
    dst = Path(dst)
    shape = _ro._target_git_dir_violation(Path(src).resolve())
    if shape:
        return False, f"the source's .git is not a plain directory ({shape}): a .git file or symlink points at some other repository; clone from a normal repository"
    if (Path(src) / ".git" / "objects" / "info" / "alternates").exists():
        return False, "the source repository borrows objects from another repository (objects/info/alternates): refused, its clone could contain that other repository's content"
    vetted = _ro.vet_repository(Path(src).resolve())  # git clone runs upload-pack INSIDE the source with the source's own config: closed-world vet first, fail closed
    if vetted is not None:
        return False, f"the source repository is refused ({vetted}): its own settings could run programs on this machine; clone from a clean repository"
    if dst.is_symlink():
        return False, f"the clone destination {dst} is a symlink: refused"
    if dst.exists() and not (dst.is_dir() and not any(dst.iterdir())):
        return False, f"the clone destination {dst} is not empty: refused"
    env = gitq.scrubbed_env()
    try:
        cl = subprocess.run(["git", "--no-pager", *gitq.HARDEN_CLONE, "clone", "--quiet", "--no-hardlinks", "--", str(src), str(dst)], capture_output=True, text=True, env=env, timeout=600)
        if cl.returncode != 0:
            return False, cl.stderr
        subprocess.run(["git", "--no-pager", *gitq.HARDEN_CLONE, "-C", str(dst), "remote", "remove", "origin"], capture_output=True, env=env, timeout=60)
        if base_rev:  # the change applies on its own base (a commit's parent, a merge-base), not necessarily on HEAD
            co = subprocess.run(["git", "--no-pager", *gitq.HARDEN_CLONE, "-C", str(dst), "checkout", "--quiet", "-B", "hlith-base", base_rev], capture_output=True, text=True, env=env, timeout=120)
            if co.returncode != 0:
                return False, co.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"git could not run: {e}"
    if (dst / ".git" / "objects" / "info" / "alternates").exists():  # belt and braces: nothing may leave a clone that points outside itself
        shutil.rmtree(dst, ignore_errors=True)
        return False, "the clone came out with objects/info/alternates (alternates): removed and refused"
    return True, ""




def feedback_store(source_repo, state: Path) -> Path:
    st = Path(state)
    key = hashlib.sha256(str(Path(source_repo).resolve()).encode()).hexdigest()[:16]
    return st / "feedback" / key


def _load_store_records(store: Path) -> list:
    from .. import feedback
    if not store.exists():
        return []
    if store.is_symlink():
        raise feedback.FeedbackIntegrityError(f"feedback store {store} is a symlink")
    out = []
    for p in sorted(store.iterdir()):
        if p.name.startswith(".tmp-"):
            continue
        if p.suffix != ".json" or not feedback._ID_RE.match(p.stem):
            raise feedback.FeedbackIntegrityError(f"unexpected file in feedback store: {p.name}")
        if not stat.S_ISREG(os.lstat(p).st_mode):
            raise feedback.FeedbackIntegrityError(f"non-regular file in feedback store: {p.name}")
        rec = feedback.FeedbackRecord.from_json(json.loads(p.read_text()))
        if rec.feedback_id != p.stem:
            raise feedback.FeedbackIntegrityError(f"{p.name} holds record {rec.feedback_id}")
        out.append(rec)
    return out


def _save_store_record(store: Path, rec) -> None:
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = store / f"{rec.feedback_id}.json"
    if final.exists():
        return
    tmp = store / f".tmp-{rec.feedback_id}-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (json.dumps(rec.to_json(), indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, final)


def sync_feedback(source_repo, state: Path, finished_clones=()) -> tuple:
    """Collect validated FeedbackRecords from the given finished runs' disposable clones (and source_repo if it has any, read-only)
    into the per-repo store. The caller (the launcher view) names the clones; this host function does the L5 access."""
    from .. import feedback
    src = Path(source_repo).resolve()
    store = feedback_store(src, state)
    existing = {r.feedback_id: r for r in _load_store_records(store)}
    sources = [Path(c) for c in finished_clones if c and Path(c).is_dir()]
    if (src / feedback.FEEDBACK_SUBDIR).exists():
        sources.append(src)
    for repo_dir in sources:
        for rec in feedback.load_records(repo_dir, None):
            if rec.feedback_id not in existing:
                _save_store_record(store, rec)
                existing[rec.feedback_id] = rec
    return tuple(existing[k] for k in sorted(existing))



def host_feedback_records(source_repo, state: Path) -> list:
    """The feedback records the PIPELINE engine stored for ``source_repo`` (design plan): the TUI launches the engine with
    HLITH_STATE_DIR = the UI's host root and a full clone, so the clone's stable repo identity (root commits) IS the source's, and that
    store is what the next run loads. Read-only; returns FeedbackRecord objects like the legacy reader, newest store first is not implied."""
    from ..feedback.api import stored_records
    from ..hostio.state import LocalHostState
    from .state import LocalState

    host = LocalHostState(LocalState(Path(state)).root)
    return [s.record for s in stored_records(host, host.stable_repo_identity(Path(source_repo).resolve()))]


def seed_clone_feedback(source_repo, clone, state: Path, finished_clones=()) -> int:
    """Legacy engine path: copy the validated per-repo feedback records into the disposable clone so the clone-local engine loads
    them. Returns how many records were seeded. (The pipeline path loads through FeedbackApi from host state instead.)"""
    from .. import feedback

    recs = sync_feedback(source_repo, state, finished_clones)
    for rec in recs:
        feedback.persist(Path(clone), rec)
    return len(recs)
