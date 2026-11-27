# SPDX-License-Identifier: Apache-2.0
"""Layer 1 checkpointing, authenticated thread store, and A9 crash-state classification."""

from __future__ import annotations

from dataclasses import dataclass, field
import enum
import fcntl
import hashlib
import hmac
import importlib.metadata as _md
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from ..contract.capabilities import GitRead, HostState, KeyPurpose
from .errors import RuntimeBoundary

LAYER1 = "langgraph"
SOCKET_EVENTS_SCOPE = "driver-process-only: worker child processes are not audited; their network is denied by an empty network namespace"
_ID = re.compile(r"[0-9A-Za-z_.:-]{1,128}")
_THREAD = re.compile(r"hlith-[0-9a-f]{20}|thread-[0-9a-f]{12,32}")
_MAX_JSON = 4 * 1024 * 1024

INTERRUPTED_DECISION = {
    "outcome": "refused",
    "exit_status": 4,
    "blocking": ["interrupted-before-gate"],
    "interrupted": True,
}


class CrashState(str, enum.Enum):
    """Enumerated L1 crash states."""

    TURN_NOT_BEGUN = "turn_not_begun"
    INDETERMINATE_MID_TURN = "indeterminate_mid_turn"
    CAPTURED = "captured"
    VERIFIED = "verified"
    LANDING_INTERRUPTED = "landing_interrupted"
    LANDED_NOT_RESUMED = "landed_not_resumed"


def classify_crash_state(
    meta: dict,
    *,
    verdict: dict | None = None,
    landing_in_progress: bool = False,
) -> CrashState:
    """Classify a persisted thread's crash state from authenticated metadata."""
    if meta.get("verdict_sha256") is not None:
        outcome = (verdict or {}).get("decision", {}).get("outcome") if isinstance(verdict, dict) else None
        if outcome == "landed" and not meta.get("finished"):
            return CrashState.LANDED_NOT_RESUMED
        return CrashState.VERIFIED
    if landing_in_progress:
        return CrashState.LANDING_INTERRUPTED
    if meta.get("state") != "agent-progress" and meta.get("interrupt_checkpoint_id"):
        return CrashState.CAPTURED
    if meta.get("in_flight_turn") is not None:
        return CrashState.INDETERMINATE_MID_TURN
    return CrashState.TURN_NOT_BEGUN


def package_root() -> str:
    """Directory that makes ``import hlith`` work (src/ for an editable install, site-packages otherwise)."""
    return str(Path(__file__).resolve().parent.parent.parent)


def profile_extras() -> tuple[str, ...]:
    return (package_root(),)


def versions() -> dict[str, str]:
    out = {}
    for key, dist in (("langgraph_version", "langgraph"), ("checkpoint_sqlite_version", "langgraph-checkpoint-sqlite")):
        try:
            out[key] = _md.version(dist)
        except _md.PackageNotFoundError:
            raise RuntimeBoundary(
                f"--layer1 langgraph needs {dist} installed "
                "(install optional extra: uv sync --extra agent or pip install 'hlith[agent]'; see docs/PROVENANCE.md)"
            )
    return out


@dataclass
class Layer1Session:
    tmp: tempfile.TemporaryDirectory
    stage: Path
    ckpt: Path
    channel: Path
    driver: Path  # driver-only dir (payload/result): the untrusted child has no grant on it
    inputs: Path
    thread_id: str
    env: dict
    timeout: float

    def close(self) -> None:
        self.tmp.cleanup()


@dataclass
class GraphInfo:
    """What the artifact reports; ids come from the sqlite columns, never from the worker's say-so."""

    thread_id: str
    checkpoint_ns: str = ""
    interrupt_checkpoint_id: str | None = None
    final_checkpoint_id: str | None = None
    interrupt_payload: dict = field(default_factory=dict)
    payload_matches_observed: bool = False
    resumed: bool = False
    feedback_node_ran: bool = False
    resume_error: str | None = None
    langgraph_version: str = ""
    checkpoint_sqlite_version: str = ""
    socket_events: list = field(default_factory=list)
    env_tracing_vars: list = field(default_factory=list)
    feedback_executions: int = 0
    _session: Layer1Session | None = field(default=None, repr=False)
    _store_dir: Path | None = field(default=None, repr=False)
    proposer: dict | None = None
    thread_store: str | None = None

    def to_json(self) -> dict:
        return {
            "layer1": LAYER1,
            "langgraph_version": self.langgraph_version,
            "checkpoint_sqlite_version": self.checkpoint_sqlite_version,
            "thread_id": self.thread_id,
            "checkpoint_ns": self.checkpoint_ns,
            "interrupt_checkpoint_id": self.interrupt_checkpoint_id,
            "final_checkpoint_id": self.final_checkpoint_id,
            "interrupt_payload": {
                "node": self.interrupt_payload.get("node"),
                "claimed_paths": self.interrupt_payload.get("claimed_paths", []),
                "claimed_digest": self.interrupt_payload.get("claimed_digest"),
            },
            "payload_matches_observed": self.payload_matches_observed,
            "resumed": self.resumed,
            "feedback_node_ran": self.feedback_node_ran,
            "feedback_executions": self.feedback_executions,
            "resume_error": self.resume_error,
            "socket_events": list(self.socket_events),
            "socket_events_scope": SOCKET_EVENTS_SCOPE,
            **({"proposer": self.proposer} if self.proposer else {}),
            **({"thread_store": self.thread_store} if self.thread_store else {}),
        }

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


def _read_json(path: Path) -> dict:
    """Strict reader for a worker-written file: regular, not a symlink, bounded, JSON object."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise RuntimeBoundary(f"layer1: {path.name} unreadable: {e.strerror}") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeBoundary(f"layer1: {path.name} is not a regular file")
        data = os.read(fd, _MAX_JSON + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_JSON:
        raise RuntimeBoundary(f"layer1: {path.name} too large")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise RuntimeBoundary(f"layer1: {path.name} is not valid JSON") from e
    if not isinstance(obj, dict):
        raise RuntimeBoundary(f"layer1: {path.name} is not a JSON object")
    return obj


def _read_ids(ckpt: Path, work: Path, thread_id: str) -> tuple[list[str], list[str], list[str]]:
    """(all checkpoint ids oldest->newest, ids carrying an interrupt write, channels written by tasks)."""
    src = ckpt / "checkpoints.sqlite"
    cp = work / "ckpt_copy"
    if cp.exists():
        shutil.rmtree(cp)
    cp.mkdir()
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(src) + suffix)
        if f.is_file() and not f.is_symlink():
            shutil.copyfile(f, cp / ("checkpoints.sqlite" + suffix))
    if not (cp / "checkpoints.sqlite").is_file():
        raise RuntimeBoundary("layer1: no checkpoint database was written")
    try:
        conn = sqlite3.connect(f"file:{cp / 'checkpoints.sqlite'}?mode=ro", uri=True)
        try:
            conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
            conn.row_factory = None
            cps = [
                r[0]
                for r in conn.execute(
                    "SELECT checkpoint_id FROM checkpoints WHERE thread_id=? AND checkpoint_ns='' ORDER BY checkpoint_id",
                    (thread_id,),
                )
            ]
            ints = [
                r[0]
                for r in conn.execute(
                    "SELECT checkpoint_id FROM writes WHERE thread_id=? AND checkpoint_ns='' AND channel='__interrupt__' "
                    "ORDER BY checkpoint_id",
                    (thread_id,),
                )
            ]
            chans = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT channel FROM writes WHERE thread_id=? AND checkpoint_ns=''",
                    (thread_id,),
                )
            ]
        finally:
            conn.close()
    except sqlite3.Error as e:
        raise RuntimeBoundary(f"layer1: checkpoint database unreadable: {e}") from e
    for v in (*cps, *ints, *chans):
        if not isinstance(v, str) or not _ID.fullmatch(v):
            raise RuntimeBoundary("layer1: checkpoint database holds an unexpected id shape")
    return cps, ints, chans


def read_checkpoint_ids(session: Layer1Session) -> tuple[list[str], list[str], list[str]]:
    return _read_ids(session.ckpt, Path(session.tmp.name), session.thread_id)


def default_store() -> Path:
    env = os.environ.get("HLITH_THREAD_STORE")
    return Path(env) if env else _state_dir() / "threads"


def _decision_sha(decision: dict) -> str:
    try:
        payload = json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()
    except RecursionError as e:
        raise RuntimeBoundary("layer1: recorded verdict decision is too deeply nested") from e
    return hashlib.sha256(payload).hexdigest()


def _private_dir(path: Path, what: str, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except OSError as e:
            raise RuntimeBoundary(f"layer1: cannot create {what}: {e.strerror}") from e
    try:
        st = path.lstat()
    except OSError as e:
        raise RuntimeBoundary(f"layer1: {what} is not readable: {e.strerror}") from e
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077):
        raise RuntimeBoundary(
            f"layer1: {what} must be a real directory owned by this user with mode 0700 (not a symlink, not group/other accessible)"
        )


def check_store(store: Path, target: Path | None) -> Path:
    raw = Path(store).expanduser()
    if raw.is_symlink():
        raise RuntimeBoundary(f"layer1: the thread store {raw} must not be a symlink")
    store = raw.resolve()
    if target is not None:
        t = Path(target).expanduser().resolve()
        if store == t or t in store.parents:
            raise RuntimeBoundary(f"layer1: the thread store {store} must not be inside the target repository {t}")
    if store.exists():
        _private_dir(store, f"the thread store {store}")
    return store


def _write_json_atomic(path: Path, obj: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = json.dumps(obj, sort_keys=True, indent=2).encode()
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


_COPY_MAX_BYTES = 64 * 1024 * 1024


def _copy_regular_tree(src: Path, dst: Path, budget: list) -> None:
    MAX_BYTES, MAX_ENTRIES = _COPY_MAX_BYTES, 100_000
    dst.mkdir(mode=0o700)
    sfd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    dfd = os.open(dst, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    work = [(sfd, dfd)]
    try:
        while work:
            sd, dd = work.pop()
            try:
                with os.scandir(sd) as it:
                    entries = sorted(it, key=lambda e: e.name)
                for e in entries:
                    budget[1] += 1
                    if budget[1] > MAX_ENTRIES:
                        raise RuntimeBoundary("layer1: too many entries in a tree to persist")
                    st = os.stat(e.name, dir_fd=sd, follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        os.mkdir(e.name, 0o700, dir_fd=dd)
                        work.append((
                            os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=sd),
                            os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dd),
                        ))
                    elif stat.S_ISREG(st.st_mode):
                        try:
                            rfd = os.open(e.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=sd)
                        except OSError as ex:
                            raise RuntimeBoundary(f"layer1: cannot open {e.name} for persisting: {ex.strerror}") from ex
                        try:
                            fst = os.fstat(rfd)
                            if not stat.S_ISREG(fst.st_mode):
                                raise RuntimeBoundary(f"layer1: {e.name} changed type while persisting")
                            if fst.st_nlink > 1:
                                raise RuntimeBoundary(
                                    f"layer1: {e.name} is a hardlink (st_nlink={fst.st_nlink}); refusing to persist"
                                )
                            if fst.st_size > MAX_BYTES:
                                raise RuntimeBoundary(f"layer1: {e.name} is too large to persist")
                            budget[0] += fst.st_size
                            if budget[0] > MAX_BYTES:
                                raise RuntimeBoundary("layer1: the thread is too large to persist")
                            wfd = os.open(e.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dd)
                            try:
                                while True:
                                    chunk = os.read(rfd, 65536)
                                    if not chunk:
                                        break
                                    v = memoryview(chunk)
                                    while v:
                                        v = v[os.write(wfd, v):]
                            finally:
                                os.close(wfd)
                        finally:
                            os.close(rfd)
                    else:
                        raise RuntimeBoundary(
                            f"layer1: {e.name} is a symlink, FIFO, socket or device node: refusing to persist it"
                        )
            finally:
                os.close(sd)
                os.close(dd)
    finally:
        for sd, dd in work:
            os.close(sd)
            os.close(dd)


def _write_stage_delta(stage: Path, base: Path, dst: Path, budget: list) -> bool:
    """Persist only added/modified regular files and deleted paths relative to ``base``.

    Unchanged repo-tracked files (including sensitive paths like ``.env`` and tracked
    symlinks) are never copied into the thread store; resume re-exports the sealed base
    and overlays this delta. Returns False if ``stage`` introduces a non-regular entry.
    """
    MAX_BYTES, MAX_ENTRIES = _COPY_MAX_BYTES, 100_000
    base_entries: dict[str, tuple] = {}
    if base.is_dir():
        for dp, dns, fns in os.walk(base, followlinks=False):
            dns.sort()
            fns.sort()
            rel_dir = Path(dp).relative_to(base)
            for dname in dns:
                p = Path(dp) / dname
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    rel = (rel_dir / dname).as_posix() if str(rel_dir) != "." else dname
                    base_entries[rel] = ("lnk", os.readlink(p))
            for name in fns:
                p = Path(dp) / name
                rel = (rel_dir / name).as_posix() if str(rel_dir) != "." else name
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    base_entries[rel] = ("lnk", os.readlink(p))
                elif stat.S_ISREG(st.st_mode):
                    base_entries[rel] = ("reg", st.st_size, p)
    dst.mkdir(mode=0o700, exist_ok=True)
    files_dst = dst / "files"
    files_dst.mkdir(mode=0o700, exist_ok=True)
    seen_in_stage: set[str] = set()
    for dp, dns, fns in os.walk(stage, followlinks=False):
        dns.sort()
        fns.sort()
        rel_dir = Path(dp).relative_to(stage)
        for dname in dns:
            p = Path(dp) / dname
            if stat.S_ISLNK(p.lstat().st_mode):
                rel = (rel_dir / dname).as_posix() if str(rel_dir) != "." else dname
                seen_in_stage.add(rel)
                if base_entries.get(rel) == ("lnk", os.readlink(p)):
                    continue
                return False
        for name in fns:
            p = Path(dp) / name
            rel = (rel_dir / name).as_posix() if str(rel_dir) != "." else name
            seen_in_stage.add(rel)
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                if base_entries.get(rel) == ("lnk", os.readlink(p)):
                    continue
                return False
            if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
                return False
            b_info = base_entries.get(rel)
            if b_info and b_info[0] == "reg" and b_info[1] == st.st_size:
                if p.read_bytes() == b_info[2].read_bytes():
                    continue
            budget[1] += 1
            if budget[1] > MAX_ENTRIES:
                raise RuntimeBoundary("layer1: too many entries in stage delta to persist")
            if st.st_size > MAX_BYTES:
                raise RuntimeBoundary(f"layer1: {rel} is too large to persist")
            budget[0] += st.st_size
            if budget[0] > MAX_BYTES:
                raise RuntimeBoundary("layer1: stage delta is too large to persist")
            out_p = files_dst / rel
            out_p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(out_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, p.read_bytes())
            finally:
                os.close(fd)
    deleted = sorted(rel for rel in base_entries if rel not in seen_in_stage)
    _write_json_atomic(dst / "deleted.json", {"deleted": deleted})
    return True


def _sync_dirs(session: Layer1Session, dst: Path) -> None:
    budget = [0, 0]
    for name, src in (
        ("ckpt", session.ckpt),
        ("driver", session.driver),
        ("inputs", session.inputs),
    ):
        d = dst / name
        if d.exists():
            shutil.rmtree(d)
        _copy_regular_tree(Path(src), d, budget)
    (dst / "stage").mkdir(mode=0o700, exist_ok=True)  # the resume node never reads the stage: an empty grant, not a repo copy
    (dst / "channel").mkdir(mode=0o700, exist_ok=True)


def _state_dir() -> Path:
    env = os.environ.get("HLITH_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "hlith"


def _always_avoid() -> tuple[Path, ...]:
    """Host paths that must never contain the verdict key."""
    out: list[Path] = [Path(package_root())]
    for attr in ("prefix", "base_prefix", "exec_prefix", "base_exec_prefix"):
        val = getattr(sys, attr, None)
        if val:
            out.append(Path(val))
    for p in profile_extras():
        out.append(Path(p))
    return tuple(out)


def _mac_key(
    avoid: tuple[Path, ...] = (),
    *,
    create: bool = True,
    host_state: HostState | None = None,
) -> bytes:
    """The host's checkpoint/verdict key. Prefers HostState.key(KeyPurpose.CHECKPOINT) when injected."""
    if host_state is not None:
        return host_state.key(KeyPurpose.CHECKPOINT)
    sd = _state_dir()
    sd.parent.mkdir(parents=True, exist_ok=True)
    _private_dir(sd, f"the state directory {sd} (it holds the verdict key)", create=True)
    real = sd.resolve()
    for a in (*avoid, *_always_avoid()):
        try:
            ar = Path(a).resolve()
        except OSError:
            continue
        if real == ar or ar in real.parents:
            raise RuntimeBoundary(
                f"layer1: the state directory {real} must not be inside {ar}: a confined worker could reach the verdict key"
            )
    kp = sd / "thread-store.key"
    if not kp.exists() and not kp.is_symlink():
        if not create:
            raise RuntimeBoundary(
                f"layer1: the verdict key {kp} is missing (deleted or rotated); cannot authenticate existing metadata"
            )
        tmp = sd / f".key.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, os.urandom(32))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, kp)
        except FileExistsError:
            pass
        finally:
            os.unlink(tmp)
    st = kp.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077) or st.st_size != 32:
        raise RuntimeBoundary(f"layer1: the verdict key {kp} must be a 32-byte regular file owned by this user with mode 0600")
    fd = os.open(kp, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 32)
    finally:
        os.close(fd)


def rotate_mac_key(avoid: tuple[Path, ...] = ()) -> Path:
    """Atomically rotate the host's verdict/progress MAC key (invalidating any prior unverified tokens)."""
    _mac_key(avoid, create=True)
    sd = _state_dir()
    kp = sd / "thread-store.key"
    tmp = sd / f".key.rot.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, os.urandom(32))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, kp)
    return kp


def _tree_digest(root: Path, subdirs: tuple[str, ...] = ("ckpt", "driver", "inputs", "stage", "channel", "stage_delta")) -> str:
    """Deterministic SHA-256 digest of the persisted thread subtrees (excluding lock/meta)."""
    h = hashlib.sha256()
    for sub in subdirs:
        base = root / sub
        h.update(f"SUB:{sub}\n".encode())
        if not base.exists():
            h.update(b"MISSING\n")
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames.sort()
            filenames.sort()
            rel_dir = Path(dirpath).relative_to(base).as_posix()
            h.update(f"D:{rel_dir}\n".encode())
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    st = fp.lstat()
                    if not stat.S_ISREG(st.st_mode):
                        raise RuntimeBoundary(f"layer1: non-regular entry {fp.name} in stored thread tree")
                    if st.st_nlink > 1:
                        raise RuntimeBoundary(f"layer1: {fp.name} is a hardlink (st_nlink={st.st_nlink}); refusing to persist")
                    fh = hashlib.sha256()
                    with open(fp, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            fh.update(chunk)
                except OSError as e:
                    raise RuntimeBoundary(
                        f"layer1: cannot read {fp.name} while computing tree digest: {e.strerror or type(e).__name__}"
                    ) from e
                h.update(f"F:{rel_dir}/{fn}:{st.st_size}:{fh.hexdigest()}\n".encode())
    return h.hexdigest()


def _verdict_mac(
    thread_id: str,
    interrupt_id: str,
    decision_sha: str,
    source: str,
    target_path: str,
    avoid: tuple[Path, ...] = (),
    *,
    create: bool = True,
    host_state: HostState | None = None,
) -> str:
    msg = json.dumps(
        {"t": thread_id, "i": interrupt_id, "d": decision_sha, "s": source, "p": target_path},
        sort_keys=True,
    ).encode()
    return hmac.new(_mac_key(avoid, create=create, host_state=host_state), msg, hashlib.sha256).hexdigest()


def _export_manifest_digest(root: Path) -> str:
    """Sha256 over sorted (rel_path, mode/kind, sha256_or_link_target) of an exported base tree."""
    entries: list[list[str]] = []
    if root.is_dir():
        for dp, dns, fns in os.walk(root, followlinks=False):
            dns.sort()
            fns.sort()
            rel_dir = Path(dp).relative_to(root)
            for dname in dns:
                p = Path(dp) / dname
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    rel = (rel_dir / dname).as_posix() if str(rel_dir) != "." else dname
                    entries.append([rel, "lnk", os.readlink(p)])
            for fn in fns:
                p = Path(dp) / fn
                rel = (rel_dir / fn).as_posix() if str(rel_dir) != "." else fn
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    entries.append([rel, "lnk", os.readlink(p)])
                elif stat.S_ISREG(st.st_mode):
                    entries.append([rel, f"reg:{st.st_mode & 0o777:03o}", hashlib.sha256(p.read_bytes()).hexdigest()])
    entries.sort(key=lambda e: e[0])
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def _progress_mac(
    thread_id: str,
    turns_done: int,
    reply_sha256: list[str],
    target_path: str,
    base_tree: str,
    tree_digest: str,
    avoid: tuple[Path, ...] = (),
    *,
    in_flight_turn: int | None = None,
    pending_reply_turn: int | None = None,
    pending_reply_sha256: str | None = None,
    command_argv_sha256: str | None = None,
    export_manifest_sha256: str | None = None,
    create: bool = True,
    host_state: HostState | None = None,
) -> str:
    payload = {
        "t": thread_id,
        "s": "agent-progress",
        "n": int(turns_done),
        "r": list(reply_sha256),
        "p": str(target_path),
        "b": str(base_tree),
        "td": str(tree_digest),
        "f": in_flight_turn,
        "pt": pending_reply_turn,
        "ps": pending_reply_sha256,
        "cmd": command_argv_sha256,
    }
    if export_manifest_sha256 is not None:
        payload["em"] = export_manifest_sha256
    msg = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(_mac_key(avoid, create=create, host_state=host_state), msg, hashlib.sha256).hexdigest()


def _captured_mac(
    thread_id: str,
    interrupt_id: str,
    paused_id: str,
    store_path: str,
    target_path: str,
    base_tree: str,
    tree_digest: str,
    claimed_digest: str,
    patch_sha256: str | None,
    export_manifest_sha256: str,
    avoid: tuple[Path, ...] = (),
    *,
    create: bool = True,
    host_state: HostState | None = None,
) -> str:
    """Bind a parked effect-interrupt snapshot to this host. The stage delta is included via ``tree_digest``."""
    payload = {
        "t": thread_id,
        "s": "effect-interrupt",
        "i": str(interrupt_id),
        "k": str(paused_id),
        "store": str(store_path),
        "p": str(target_path),
        "b": str(base_tree),
        "td": str(tree_digest),
        "cd": str(claimed_digest),
        "ps": patch_sha256,
        "em": str(export_manifest_sha256),
    }
    msg = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(_mac_key(avoid, create=create, host_state=host_state), msg, hashlib.sha256).hexdigest()


def _avoid_for(d: Path, meta: dict) -> tuple[Path, ...]:
    out = [d.parent, d]
    if meta.get("target_path"):
        out.append(Path(str(meta["target_path"])))
    return tuple(out)


def _meta(d: Path) -> dict:
    return _read_json(d / "meta.json")


def _require_thread_identity(thread_id: str, d: Path, meta: dict) -> None:
    """Bind persisted metadata and verdicts to both the requested id and its directory."""
    if d.name != thread_id or meta.get("thread_id") != thread_id:
        raise RuntimeBoundary("layer1: thread identity does not match its store directory")


def _verdict_path(d: Path) -> Path:
    return d / "verdict.json"


def _acquire_flock(path: Path) -> int:
    for _ in range(5):
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as e:
            raise RuntimeBoundary(f"layer1: cannot lock thread store: {e.strerror}") from e
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeBoundary(f"layer1: lock file {path.name} is not a regular file")
            fcntl.flock(fd, fcntl.LOCK_EX)
            st_fd = os.fstat(fd)
            try:
                st_p = path.lstat()
            except FileNotFoundError:
                os.close(fd)
                continue
            if st_fd.st_ino == st_p.st_ino and st_fd.st_dev == st_p.st_dev:
                return fd
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
    raise RuntimeBoundary(f"layer1: lock contention on {path.name}")


class _locked:
    """Serialize mutations to a persisted thread directory using a host-state lock file."""

    def __init__(self, d: Path):
        sd = _state_dir()
        sd.parent.mkdir(parents=True, exist_ok=True)
        _private_dir(sd, f"the state directory {sd}", create=True)
        locks_dir = sd / "locks"
        _private_dir(locks_dir, f"the lock state directory {locks_dir}", create=True)
        key = hashlib.sha256(str(d.resolve()).encode()).hexdigest()
        self.path = locks_dir / f"{key}.lock"
        self.fd: int | None = None

    def __enter__(self):
        self.fd = _acquire_flock(self.path)
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)


def _thread_dir(thread_id: str, store: Path) -> Path:
    if not isinstance(thread_id, str) or not _THREAD.fullmatch(thread_id):
        raise RuntimeBoundary(f"layer1: not a valid thread id: {str(thread_id)[:60]!r}")
    store = check_store(store, None)
    d = store / thread_id
    if not d.exists() and not d.is_symlink():
        raise RuntimeBoundary(f"layer1: thread {thread_id} not found in {store}")
    _private_dir(d.parent, f"the thread store {d.parent}")
    _private_dir(d, f"the thread directory {thread_id}")
    for sub in ("ckpt", "driver", "inputs", "stage", "channel"):
        _private_dir(d / sub, f"{thread_id}/{sub}")
    return d


def thread_target(thread_id: str, store: Path) -> Path:
    """Read the recorded target repository path for a persisted thread without acquiring its lock."""
    d = _thread_dir(thread_id, store)
    return Path(_meta(d)["target_path"])


def thread_run_id(thread_id: str, store: Path) -> str | None:
    """Read the recorded RunId for a persisted thread if present."""
    d = _thread_dir(thread_id, store)
    rid = _meta(d).get("run_id")
    return str(rid) if isinstance(rid, str) and rid else None


def describe_thread(thread_id: str, store: Path, *, host_state: HostState | None = None) -> dict:
    """Operator-facing classification of one persisted thread. Does not resume it and does not write."""
    d = _thread_dir(thread_id, store)
    meta = _meta(d)
    _require_thread_identity(thread_id, d, meta)
    interrupt_checkpoint_id = meta.get("interrupt_checkpoint_id")
    if interrupt_checkpoint_id is not None and (
        not isinstance(interrupt_checkpoint_id, str)
        or not interrupt_checkpoint_id
        or len(interrupt_checkpoint_id) > 256
    ):
        raise RuntimeBoundary("layer1: thread metadata has an invalid effect-interrupt checkpoint id")
    finished = bool(meta.get("finished") or meta.get("final_checkpoint_id"))
    if meta.get("state") == "agent-progress":
        kind = "agent-progress"
    elif interrupt_checkpoint_id and (not finished or _verdict_path(d).exists()):
        # A finished captured thread remains identifiable for read-only authenticated verdict replay.
        # list_effect_interrupts() already excludes any thread with a verdict from the resumable UI.
        kind = "effect-interrupt"
    else:
        kind = "other"
    verdict = None
    if _verdict_path(d).exists():
        try:
            verdict = _load_verdict(d, host_state=host_state).get("decision")
        except (RuntimeBoundary, OSError, ValueError, KeyError, TypeError):
            verdict = {"unreadable": True}
    return {
        "kind": kind,
        "thread_id": meta.get("thread_id") or thread_id,
        "interrupt_checkpoint_id": interrupt_checkpoint_id,
        "run_id": meta.get("run_id") if isinstance(meta.get("run_id"), str) else None,
        "target_path": meta.get("target_path"),
        "has_verdict": _verdict_path(d).exists(),
        "verdict": verdict,
        "captured_mac": isinstance(meta.get("captured_mac"), str),
        "command_argv_sha256": meta.get("command_argv_sha256") if isinstance(meta.get("command_argv_sha256"), str) else None,
        "graph_mode": meta.get("graph_mode"),
        "finished": finished,
    }


def list_effect_interrupts(store: Path, target: Path) -> list[dict]:
    """Captured effect-interrupt threads for ``target`` that have no verdict yet and an authenticated stage delta."""
    store = Path(store).expanduser()
    target_s = str(Path(target).resolve())
    if store.is_symlink() or not store.is_dir():
        return []
    out = []
    for entry in sorted(store.iterdir()):
        if entry.name.startswith(".") or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            desc = describe_thread(entry.name, store)
        except Exception:  # noqa: BLE001 - a malformed thread is not offered
            continue
        if desc["kind"] != "effect-interrupt" or desc["finished"] or desc["has_verdict"] or not desc["captured_mac"]:
            continue
        if str(Path(str(desc.get("target_path") or "")).resolve()) != target_s:
            continue
        out.append(desc)
    return out


def _swap_dir(work: Path, final: Path) -> None:
    """Replace ``final`` with ``work`` atomically enough for a crash to recover cleanly."""
    old = final.with_name(".old-" + final.name)
    if old.exists():
        shutil.rmtree(old)
    os.replace(final, old)
    os.replace(work, final)
    shutil.rmtree(old, ignore_errors=True)


def _non_regular_entry(root: Path) -> str | None:
    for dp, dns, fns in os.walk(root, followlinks=False):
        for name in (*dns, *fns):
            p = Path(dp) / name
            try:
                st = p.lstat()
            except OSError:
                return str(p)
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                return str(p)
            if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                return str(p)
    return None


def _target_has_commit(target: str, commit: str, *, git_read: GitRead | None = None) -> bool:
    """True when ``commit`` exists in the target repository and is reachable from its HEAD. Never imports gate."""
    from ..hostio.git_read import HardenedGitRead, _run_ro

    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,64}", commit):
        return False
    reader = git_read if git_read is not None else HardenedGitRead()
    try:
        if reader.repository_hostile_reason(Path(target)) is not None:
            return False
        full_sha = _run_ro(Path(target), ("rev-parse", "--verify", "-q", commit + "^{commit}")).decode("ascii", "replace").strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", full_sha):
            return False
        _run_ro(Path(target), ("merge-base", "--is-ancestor", full_sha, "HEAD"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _capture_effect_fields(
    session: Layer1Session,
    work: Path,
    *,
    interrupt_id: str | None,
    paused_id: str | None,
    store_path: Path,
    target: Path,
    base_tree: str,
    patch_sha256: str | None,
    host_state: HostState | None,
) -> dict:
    """Persist the effect bytes a later gate resume needs, and MAC them to the interrupt checkpoint.

    ``work/stage`` stays an empty grant (the feedback node does not read it). The changed files live in
    ``stage_delta``, the same shape mid-agent progress already uses, so an unchanged tracked secret is not copied.
    """
    if not isinstance(interrupt_id, str) or not interrupt_id or not isinstance(paused_id, str) or not paused_id:
        raise RuntimeBoundary("layer1: effect interrupt has no checkpoint id to bind")
    budget = [0, 0]
    base_dir = Path(session.tmp.name) / "target_ro"
    if not base_dir.is_dir():
        raise RuntimeBoundary("layer1: effect interrupt has no sealed base export to bind the stage to")
    if not _write_stage_delta(Path(session.stage), base_dir, work / "stage_delta", budget):
        raise RuntimeBoundary("layer1: effect interrupt stage is not a regular delta; refusing to persist an unresumable checkpoint")
    channel = work / "channel"
    if channel.exists():
        shutil.rmtree(channel)
    _copy_regular_tree(Path(session.channel), channel, budget)
    payload = _read_json(work / "driver" / "graph_payload.json")
    claimed = payload.get("claimed_digest")
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed):
        raise RuntimeBoundary("layer1: effect interrupt payload has no claimed digest")
    td = _tree_digest(work)
    em = _export_manifest_digest(base_dir)
    mac = _captured_mac(
        session.thread_id,
        interrupt_id,
        paused_id,
        str(Path(store_path).resolve()),
        str(Path(target).resolve()),
        str(base_tree),
        td,
        claimed,
        patch_sha256,
        em,
        (work, Path(target), session.stage, session.channel, session.ckpt, session.driver, session.inputs, Path(session.tmp.name)),
        host_state=host_state,
    )
    return {
        "tree_digest": td,
        "claimed_digest": claimed,
        "export_manifest_sha256": em,
        "captured_mac": mac,
        "graph_mode": session.env.get("HLITH_GRAPH_MODE") or "patch",
        "patch_sha256": patch_sha256,
    }


def persist(
    session: Layer1Session,
    info: GraphInfo,
    store: Path,
    *,
    target: Path,
    base_tree: str,
    patch_sha256: str | None,
    host_state: HostState | None = None,
    run_id: str | None = None,
) -> Path:
    """Copy the paused thread to <store>/<thread_id>."""
    store = check_store(store, target)
    store.parent.mkdir(parents=True, exist_ok=True)
    _private_dir(store, f"the thread store {store}", create=True)
    _mac_key(
        (store, Path(target), session.stage, session.channel, session.ckpt, session.driver, session.inputs, Path(session.tmp.name)),
        host_state=host_state,
    )
    final = store / session.thread_id
    work = store / f".tmp-{session.thread_id}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    try:
        _sync_dirs(session, work)
        captured = _capture_effect_fields(
            session,
            work,
            interrupt_id=info.interrupt_checkpoint_id,
            paused_id=info.final_checkpoint_id,
            store_path=store,
            target=Path(target).resolve(),
            base_tree=base_tree,
            patch_sha256=patch_sha256,
            host_state=host_state,
        )
        _write_json_atomic(
            work / "meta.json",
            {
                "thread_id": session.thread_id,
                "run_id": run_id,
                "interrupt_checkpoint_id": info.interrupt_checkpoint_id,
                "paused_checkpoint_id": info.final_checkpoint_id,
                "target_path": str(Path(target).resolve()),
                "store_path": str(store),
                "base_tree": base_tree,
                "created_unix": int(time.time()),
                "package_root": package_root(),
                "python": sys.executable,
                "versions": versions(),
                "verdict_sha256": None,
                "finished": False,
                "final_checkpoint_id": None,
                **captured,
            },
        )
        if final.exists():
            try:
                prior = _meta(final)
            except Exception:  # noqa: BLE001
                prior = {}
            if prior.get("state") != "agent-progress" or prior.get("thread_id") != session.thread_id:
                raise RuntimeBoundary(f"layer1: thread {session.thread_id} already exists in the store")
            _swap_dir(work, final)
        else:
            os.replace(work, final)
    except OSError as e:
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeBoundary(f"layer1: cannot persist the thread: {e.strerror or e}") from e
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    info._store_dir = final
    info.thread_store = str(store)
    return final


def record_verdict(info: GraphInfo, decision: dict, *, host_state: HostState | None = None) -> None:
    """Write the decided verdict (passed back from SURFACE/coordinator) into the store before resume.

    Never imports gate; never raises; never rewrites an existing verdict."""
    d = getattr(info, "_store_dir", None)
    if d is None:
        return
    try:
        with _locked(d):
            _record_verdict_locked(d, decision, "gate", host_state=host_state)
    except Exception as e:  # noqa: BLE001
        info.resume_error = f"verdict not recorded: {type(e).__name__}: {str(e)[:200]}"


def _record_verdict_locked(
    d: Path,
    decision: dict,
    source: str,
    *,
    host_state: HostState | None = None,
) -> dict:
    vp = _verdict_path(d)
    if vp.exists() or vp.is_symlink():
        return _load_verdict(d, host_state=host_state)
    m = _meta(d)
    sha = _decision_sha(decision)
    rec = {
        "decision": decision,
        "decision_sha256": sha,
        "source": source,
        "mac": _verdict_mac(
            m["thread_id"],
            str(m["interrupt_checkpoint_id"]),
            sha,
            source,
            str(m.get("target_path")),
            _avoid_for(d, m),
            host_state=host_state,
        ),
    }
    _write_json_atomic(vp, rec)
    m["verdict_sha256"] = sha
    _write_json_atomic(d / "meta.json", m)
    return rec


def _load_verdict(
    d: Path,
    *,
    host_state: HostState | None = None,
    git_read: GitRead | None = None,
) -> dict:
    """The recorded verdict, verified: hash, host-key MAC, and commit reachability for 'landed'."""
    rec = _read_json(_verdict_path(d))
    m = _meta(d)
    _require_thread_identity(d.name, d, m)
    dec, sha = rec.get("decision"), rec.get("decision_sha256")
    if not isinstance(dec, dict) or sha != _decision_sha(dec) or m.get("verdict_sha256") != sha:
        raise RuntimeBoundary("layer1: the recorded verdict does not match its hash: refusing to resume with an altered verdict")
    want = _verdict_mac(
        m["thread_id"],
        str(m["interrupt_checkpoint_id"]),
        sha,
        str(rec.get("source")),
        str(m.get("target_path")),
        _avoid_for(d, m),
        create=False,
        host_state=host_state,
    )
    if not isinstance(rec.get("mac"), str) or not hmac.compare_digest(rec["mac"], want):
        raise RuntimeBoundary("layer1: the recorded verdict is not authenticated by this host's key: refusing it as a forged verdict")
    if dec.get("outcome") == "landed" and not _target_has_commit(str(m.get("target_path")), str(dec.get("landed_commit")), git_read=git_read):
        raise RuntimeBoundary("layer1: the recorded verdict says landed but the recorded commit is not reachable from the target HEAD: verdict refused")
    return rec


def persist_progress(
    session: Layer1Session,
    store: Path,
    *,
    target: Path,
    base_tree: str,
    turns_done: int,
    reply_sha256: list[str],
    in_flight_turn: int | None = None,
    pending_reply_turn: int | None = None,
    pending_reply_sha256: str | None = None,
    command_argv_sha256: str | None = None,
    profile_sha256: str | None = None,
    host_state: HostState | None = None,
    run_id: str | None = None,
) -> Path | None:
    """Save the mid-agent thread (stage_delta + channel + ckpt + inputs) after a turn so a crash between turns can resume.

    Note: abandoned ``agent-progress`` directories (mode ``0o700``, outside worker/proposer/evaluator
    grants) have no automatic background TTL reaper; operators may prune stale threads via
    ``meta.json['created_unix']``, and normal resume clears ``stage_delta`` via ``persist_paused``.
    """
    if _non_regular_entry(session.channel) is not None:
        return None
    store = check_store(store, target)
    store.parent.mkdir(parents=True, exist_ok=True)
    _private_dir(store, f"the thread store {store}", create=True)
    _mac_key(
        (store, Path(target), session.stage, session.channel, session.ckpt, session.driver, session.inputs, Path(session.tmp.name)),
        host_state=host_state,
    )
    final = store / session.thread_id
    work = store / f".tmp-{session.thread_id}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    try:
        budget = [0, 0]
        for name, src in (
            ("ckpt", session.ckpt),
            ("driver", session.driver),
            ("inputs", session.inputs),
            ("channel", session.channel),
        ):
            _copy_regular_tree(Path(src), work / name, budget)
        (work / "stage").mkdir(mode=0o700, exist_ok=True)
        base_dir = Path(session.tmp.name) / "target_ro"
        if not _write_stage_delta(Path(session.stage), base_dir, work / "stage_delta", budget):
            shutil.rmtree(work, ignore_errors=True)
            return None
        td = _tree_digest(work)
        em_sha = _export_manifest_digest(base_dir)
        t_resolved = str(Path(target).resolve())
        mac = _progress_mac(
            session.thread_id,
            turns_done,
            reply_sha256,
            t_resolved,
            base_tree,
            td,
            (store, Path(target), session.stage, session.channel, session.ckpt, session.driver, session.inputs, Path(session.tmp.name)),
            in_flight_turn=in_flight_turn,
            pending_reply_turn=pending_reply_turn,
            pending_reply_sha256=pending_reply_sha256,
            command_argv_sha256=command_argv_sha256,
            export_manifest_sha256=em_sha,
            host_state=host_state,
        )
        _write_json_atomic(
            work / "meta.json",
            {
                "thread_id": session.thread_id,
                "run_id": run_id,
                "state": "agent-progress",
                "turns_done": int(turns_done),
                "reply_sha256": list(reply_sha256),
                "in_flight_turn": in_flight_turn,
                "pending_reply_turn": pending_reply_turn,
                "pending_reply_sha256": pending_reply_sha256,
                "command_argv_sha256": command_argv_sha256,
                "export_manifest_sha256": em_sha,
                "profile_sha256": profile_sha256,
                "tree_digest": td,
                "progress_mac": mac,
                "target_path": t_resolved,
                "base_tree": base_tree,
                "store_path": str(store),
                "created_unix": int(time.time()),
                "package_root": package_root(),
                "python": sys.executable,
                "versions": versions(),
                "verdict_sha256": None,
                "finished": False,
                "final_checkpoint_id": None,
            },
        )
        with _locked(final):
            if final.exists():
                _swap_dir(work, final)
            else:
                os.replace(work, final)
    except OSError as e:
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeBoundary(f"layer1: cannot persist progress: {e.strerror or e}") from e
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    return final


def _persist_into(
    session: Layer1Session,
    d: Path,
    meta: dict,
    *,
    turns_done,
    reply_sha256,
    final: tuple | None = None,
    in_flight_turn: int | None = None,
    pending_reply_turn: int | None = None,
    pending_reply_sha256: str | None = None,
    report: dict | None = None,
    profile_sha256: str | None = None,
    host_state: HostState | None = None,
) -> None:
    """Update the persisted thread ``d`` in place under its existing lock."""
    work = d.parent / f".tmp-{session.thread_id}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    try:
        _sync_dirs(session, work)
        new_meta = dict(meta)
        if final is not None:
            new_meta.pop("state", None)
            new_meta.pop("progress_mac", None)
            new_meta.pop("tree_digest", None)
            new_meta.update(
                interrupt_checkpoint_id=final[0],
                paused_checkpoint_id=final[1],
                verdict_sha256=None,
                finished=False,
                final_checkpoint_id=None,
            )
            if report is not None:
                new_meta["proposer"] = report
            if profile_sha256 is not None:
                new_meta["profile_sha256"] = profile_sha256
            new_meta.update(
                _capture_effect_fields(
                    session,
                    work,
                    interrupt_id=final[0],
                    paused_id=final[1],
                    store_path=Path(str(meta.get("store_path") or d.parent)),
                    target=Path(str(meta["target_path"])),
                    base_tree=str(meta.get("base_tree") or ""),
                    patch_sha256=meta.get("patch_sha256") if isinstance(meta.get("patch_sha256"), str) else None,
                    host_state=host_state,
                )
            )
        else:
            budget = [0, 0]
            shutil.rmtree(work / "channel", ignore_errors=True)
            _copy_regular_tree(Path(session.channel), work / "channel", budget)
            shutil.rmtree(work / "stage_delta", ignore_errors=True)
            base_dir = Path(session.tmp.name) / "target_ro"
            if not _write_stage_delta(Path(session.stage), base_dir, work / "stage_delta", budget):
                raise RuntimeBoundary("layer1: stage contains non-regular entry while persisting progress")
            td = _tree_digest(work)
            mac = _progress_mac(
                session.thread_id,
                turns_done,
                reply_sha256,
                str(meta["target_path"]),
                str(meta["base_tree"]),
                td,
                _avoid_for(d, meta),
                in_flight_turn=in_flight_turn,
                pending_reply_turn=pending_reply_turn,
                pending_reply_sha256=pending_reply_sha256,
                command_argv_sha256=meta.get("command_argv_sha256"),
                export_manifest_sha256=meta.get("export_manifest_sha256"),
                host_state=host_state,
            )
            new_meta.update(
                turns_done=int(turns_done),
                reply_sha256=list(reply_sha256),
                in_flight_turn=in_flight_turn,
                pending_reply_turn=pending_reply_turn,
                pending_reply_sha256=pending_reply_sha256,
                tree_digest=td,
                progress_mac=mac,
            )
        _write_json_atomic(work / "meta.json", new_meta)
        _swap_dir(work, d)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


def sync_after_resume(info: GraphInfo) -> None:
    """After the in-run resume succeeded, refresh the stored copy (ckpt/driver) so the store shows the finished thread."""
    d = getattr(info, "_store_dir", None)
    sess = info._session
    if d is None or sess is None or not info.resumed:
        return
    try:
        with _locked(d):
            budget = [0, 0]
            for name, src in (("ckpt", sess.ckpt), ("driver", sess.driver)):
                t = d / name
                shutil.rmtree(t)
                _copy_regular_tree(Path(src), t, budget)
            m = _meta(d)
            m.update(finished=True, final_checkpoint_id=info.final_checkpoint_id)
            _write_json_atomic(d / "meta.json", m)
    except Exception as e:  # noqa: BLE001
        info.resume_error = (info.resume_error or "") + f" store sync failed: {type(e).__name__}: {str(e)[:200]}"


__all__ = [
    "CrashState",
    "GraphInfo",
    "INTERRUPTED_DECISION",
    "LAYER1",
    "Layer1Session",
    "SOCKET_EVENTS_SCOPE",
    "_THREAD",
    "_acquire_flock",
    "_avoid_for",
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
    "_state_dir",
    "_swap_dir",
    "_sync_dirs",
    "_target_has_commit",
    "_thread_dir",
    "_tree_digest",
    "_verdict_mac",
    "_verdict_path",
    "_write_json_atomic",
    "check_store",
    "classify_crash_state",
    "default_store",
    "describe_thread",
    "list_effect_interrupts",
    "package_root",
    "persist",
    "persist_progress",
    "profile_extras",
    "read_checkpoint_ids",
    "record_verdict",
    "rotate_mac_key",
    "sync_after_resume",
    "thread_target",
    "versions",
]
