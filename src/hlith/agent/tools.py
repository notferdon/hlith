# SPDX-License-Identifier: Apache-2.0
"""Confined worker tools, stage measurement, and child-process namespace cleanup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat as _st
import subprocess
import sys
import tempfile
import time

from ..hostio.redact import redact, scrub_task, sensitive_path


MAX_ENTRIES = 100_000
MAX_FILE = 32 * 1024 * 1024
AGENT_MAX_TURNS = 8
_READ_CAP = 64 * 1024
_OUT_CAP = 8 * 1024


class MeasureError(RuntimeError):
    """The stage cannot be measured (unreadable file, vanished entry, too large). A boundary failure."""


def _measure(root: Path) -> dict[str, str]:
    try:
        return _measure_inner(root)
    except OSError as e:
        raise MeasureError(f"stage cannot be measured: {e.filename or ''}: {e.strerror}") from e


def _measure_inner(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    n = 0
    for dp, dns, fns in os.walk(root, followlinks=False):
        for name in [*dns, *fns]:
            p = Path(dp) / name
            rel = str(p.relative_to(root))
            st = os.lstat(p)
            n += 1
            if n > MAX_ENTRIES:
                raise MeasureError("stage too large to measure")
            if _st.S_ISLNK(st.st_mode):
                out[rel] = "l:" + hashlib.sha256(os.readlink(p).encode("utf-8", "surrogateescape")).hexdigest()
            elif _st.S_ISREG(st.st_mode):
                if st.st_size > MAX_FILE:
                    raise MeasureError(f"file too large to measure: {rel}")
                out[rel] = ("x:" if st.st_mode & 0o111 else "-:") + hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def claimed_digest(claimed: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(sorted(claimed.items()), separators=(",", ":")).encode()).hexdigest()


def decision_sha(decision: dict) -> str:
    return hashlib.sha256(json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _child_env() -> dict[str, str]:
    """The untrusted child gets a fixed, minimal environment: no checkpoint dir, thread id, driver dir,
    child spec, or anything else of the driver's. It can write only the stage and the manifest channel."""
    keep = (
        "PATH",
        "HOME",
        "PYTHONDONTWRITEBYTECODE",
        "HLITH_TARGET",
        "HLITH_STAGE",
        "HLITH_MANIFEST_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    )
    return {k: os.environ[k] for k in keep if k in os.environ}


def _kill_namespace(grace: float = 5.0) -> None:
    """Kill every other process in this pid namespace and reap them (finding 22).

    The driver is pid 1 of the namespace the supervisor's launcher created, so every descendant of the
    worker, including ones that double-forked or called setsid, lives in it and reparents to us. Nothing
    may survive to write the stage after it is measured. Fails closed if something cannot be removed."""
    me = os.getpid()
    if me != 1:  # never sweep /proc of a host pid namespace: only the confined launcher's pid-1 may do this
        raise RuntimeError("driver is not pid 1 of its own pid namespace; refusing to sweep processes")
    deadline = time.monotonic() + grace
    while True:
        pids = [int(x) for x in os.listdir("/proc") if x.isdigit() and int(x) != me]
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError(f"worker descendants could not be removed: {pids[:5]}")
        time.sleep(0.01)


def _tail(f, limit: int = 65536) -> str:
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(max(0, size - limit))
    return f.read().decode("utf-8", "replace")


def _confine_launcher() -> str:
    pkg_root = Path(__file__).resolve().parent.parent
    hostio_launcher = pkg_root / "hostio" / "confine_exec.py"
    if hostio_launcher.exists():
        return str(hostio_launcher)
    return str(pkg_root / "_confine.py")


def _run_child(argv: list[str], stage: Path) -> subprocess.CompletedProcess:
    """Run the worker / git apply as a CHILD under a Landlock ruleset narrower than the driver's:
    the checkpoint dir and the driver dir are not in it, so the kernel denies every access to them.
    close_fds=True + closerange in the launcher: no descriptor of the driver survives into the child.

    Output goes to anonymous driver-side files (a grandchild holding a pipe cannot stall us), and when the
    direct child is done the whole pid namespace is emptied BEFORE the caller measures the stage."""
    spec = os.environ["HLITH_CHILD_SPEC"]  # supervisor-built; subset of the driver's own grants
    launcher = _confine_launcher()
    cmd = [sys.executable, "-I", launcher, "--landlock-only", spec, "--", *argv]
    with (
        tempfile.TemporaryFile(dir=os.environ["HLITH_DRIVER_DIR"]) as out,
        tempfile.TemporaryFile(dir=os.environ["HLITH_DRIVER_DIR"]) as err,
    ):
        proc = subprocess.Popen(
            cmd,
            cwd=stage,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            close_fds=True,
            env=_child_env(),
        )
        try:
            rc = proc.wait()
        finally:
            _kill_namespace()
        return subprocess.CompletedProcess(cmd, rc, _tail(out), _tail(err))


def _redact_result(r: dict) -> dict:
    """Every tool output is redacted BEFORE it can enter the transcript (prompt, checkpoint, store); a count, never a value."""
    out, n = redact(str(r.get("output", "")))
    return {**r, "output": out, "redactions": n}


def _read_beneath(stage: Path, rel: object, cap: int):
    """Read a regular file BENEATH the stage, opened component by component with O_NOFOLLOW (a symlink in ANY ancestor or at the end
    is refused; there is no separate check that a swap could race), then apply the sensitive-path policy to the path actually
    traversed. Returns (ok, text-or-reason)."""
    if not isinstance(rel, str) or not rel or "\0" in rel or rel.startswith("/") or len(rel) > 400:
        return False, "path refused (must be a relative path of a regular file inside the stage)"
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return False, "path refused (must be a relative path of a regular file inside the stage)"
    if sensitive_path("/".join(parts)):
        return False, "path refused by the sensitive-path policy (credentials, keys, env files, git metadata)"
    fds = []
    try:
        cur = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(cur)
        for name in parts[:-1]:
            cur = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
            fds.append(cur)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur)
        fds.append(fd)
        if not _st.S_ISREG(os.fstat(fd).st_mode):
            return False, "path refused (must be a relative path of a regular file inside the stage)"
        data = os.read(fd, cap)
    except OSError:
        return False, "path refused (must be a relative path of a regular file inside the stage)"
    finally:
        for f in fds:
            try:
                os.close(f)
            except OSError:
                pass
    return True, data.decode("utf-8", "replace")


def _safe_rel(stage: Path, rel: object) -> Path | None:
    """A relative path that stays inside the stage and names a regular, non-symlink file (or None)."""
    if not isinstance(rel, str) or not rel or "\0" in rel or rel.startswith("/") or len(rel) > 400:
        return None
    parts = Path(rel).parts
    if ".." in parts or ".git" in parts:
        return None
    p = stage.joinpath(*parts)
    try:
        if p.is_symlink() or not p.is_file() or stage.resolve() not in p.resolve().parents:
            return None
    except OSError:
        return None
    return p


def _agent_tool(stage: Path, call: object, turn: int, idx: int) -> dict:
    """Execute ONE tool call of the model's reply. Never raises: a refusal is an error result the model can read."""
    return _redact_result(_agent_tool_raw(stage, call, turn, idx))


def _agent_tool_raw(stage: Path, call: object, turn: int, idx: int) -> dict:
    if not isinstance(call, dict) or not isinstance(call.get("name"), str):
        return {"tool": "?", "ok": False, "output": "tool call must be an object with a string name"}
    name = call["name"]
    if name == "read_file":
        ok, text = _read_beneath(stage, call.get("path"), _READ_CAP)
        return {"tool": name, "ok": ok, "output": text}
    if name == "apply_patch":
        diff = call.get("diff")
        if not isinstance(diff, str) or not diff:
            return {"tool": name, "ok": False, "output": "diff must be a non-empty string"}
        pf = Path(os.environ["HLITH_MANIFEST_DIR"]) / f"agent-{turn}-{idx}.patch"
        pf.write_text(diff, encoding="utf-8", errors="surrogateescape")
        cp = _run_child(["git", "apply", "--whitespace=nowarn", str(pf)], stage)
        return {"tool": name, "ok": cp.returncode == 0, "output": (cp.stderr or "applied")[-_OUT_CAP:]}
    if name == "declare":
        body = {"paths": call.get("paths"), **({"deltas": call["deltas"]} if "deltas" in call else {})}
        raw = json.dumps(body)
        if len(raw) > 256 * 1024:
            return {"tool": name, "ok": False, "output": "manifest too large"}
        (Path(os.environ["HLITH_MANIFEST_DIR"]) / "manifest.json").write_text(raw)
        return {"tool": name, "ok": True, "output": "manifest recorded as the proposer's claim"}
    if name == "finish":
        return {"tool": name, "ok": True, "output": str(call.get("summary", ""))[:400]}
    return {"tool": "?", "ok": False, "output": "unknown tool"}  # the name is not echoed: it is model/repo-controlled text


def _task_text(task_path: str) -> str:
    return scrub_task(Path(task_path).read_text(encoding="utf-8")[:20000])[0]


__all__ = [
    "AGENT_MAX_TURNS",
    "MAX_ENTRIES",
    "MAX_FILE",
    "MeasureError",
    "_agent_tool",
    "_agent_tool_raw",
    "_child_env",
    "_kill_namespace",
    "_measure",
    "_measure_inner",
    "_read_beneath",
    "_redact_result",
    "_run_child",
    "_safe_rel",
    "_tail",
    "_task_text",
    "claimed_digest",
    "decision_sha",
]
