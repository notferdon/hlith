# SPDX-License-Identifier: Apache-2.0
"""Proposers: who writes the change in a Layer 1 agent run (E1 gap 1).

A Proposer runs on the SUPERVISOR side. Hlith never reads credentials: a model proposer is handed an already-authenticated
client object by the host program. The confined LangGraph worker never sees the proposer, its client or any credential; it
only receives the proposer's reply as data (a list of tool calls) and executes them against the stage.

``reply(turn)`` gets {"turn": n, "task": str, "transcript": [tool results so far]} and returns {"tool_calls": [...]} with calls
  {"name": "read_file", "path": REL}            read a text file of the stage (bounded)
  {"name": "apply_patch", "diff": UNIFIED_DIFF} `git apply` in the stage, under the same confinement as any worker command
  {"name": "declare", "paths": {...}, "deltas": [...]}   the proposer's own manifest: a CLAIM, never proof
  {"name": "finish", "summary": str}            stop; the stage is measured and the effect goes to the gate

MockModelProposer is PLUMBING ONLY: scripted replies prove the loop, the checkpoints and the confinement. Its artifact label is
kind "mock", plumbing_only true. It is not agent evidence.

Confinement policy: arbitrary CommandProposer commands run CONFINED by default. A host-side run requires an explicit
typed trust flag (``HostSideProposerTrust(authorized=True)`` or ``allow_unconfined=True``) and NEVER counts as E2."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Protocol

from .profile import GrantError, build_proposer_profile, run_confined


_PARENT_DEATH_BOOTSTRAP = r"""
import ctypes, json, os, signal, sys
expected_parent = int(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    os._exit(126)
if os.getppid() != expected_parent:
    os.kill(os.getpid(), signal.SIGKILL)
argv = json.loads(sys.argv[2])
os.execvpe(argv[0], argv, os.environ)
"""

_CONFINED_STDIN_BOOTSTRAP = r"""
import json, os, subprocess, sys
turn_path = sys.argv[1]
argv = json.loads(sys.argv[2])
max_out = int(sys.argv[3])
limit_marker = sys.argv[4]
with open(turn_path, "rb") as tf:
    proc = subprocess.Popen(argv, stdin=tf, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
assert proc.stdout is not None
total = 0
out_fd = proc.stdout.fileno()
while True:
    chunk = os.read(out_fd, 65536)
    if not chunk:
        break
    total += len(chunk)
    if total > max_out:
        proc.kill()
        proc.wait()
        with open(limit_marker, "wb"):
            pass
        os._exit(125)
    sys.stdout.buffer.write(chunk)
sys.stdout.buffer.flush()
os._exit(proc.wait())
"""


class NotConfigured(RuntimeError):
    """A model proposer was built without a client or a proposer command failed/refused confinement."""


class ProposerOutputLimit(NotConfigured):
    """A proposer command exceeded the configured stdout byte cap."""

    def __init__(self, limit: int):
        self.limit = int(limit)
        super().__init__(f"proposer command output exceeded {self.limit} byte limit")


@dataclass(frozen=True)
class HostSideProposerTrust:
    """Explicit typed authorization to run a CommandProposer host-side instead of inside confinement.

    Host-side proposer runs NEVER count as E2 confinement evidence."""

    authorized: bool = False
    reason: str = ""


class Proposer(Protocol):
    kind: str
    model_id: str
    plumbing_only: bool

    def reply(self, turn: dict) -> dict: ...


class MockModelProposer:
    kind = "mock"
    model_id = "mock-script"
    plumbing_only = True

    def __init__(self, script: list[list[Any]]):
        self._script = [list(s) for s in script]
        self.seen_turns: list[dict] = []

    def reply(self, turn: dict) -> dict:
        self.seen_turns.append(json.loads(json.dumps(turn)))
        # Indexed by the TURN NUMBER the thread is at, not by how often this instance was called: a new process that resumes a
        # thread at turn 1 has a call count of 0 and must not be handed turn 0's reply again (E1: crash between turns).
        i = turn["turn"] if isinstance(turn.get("turn"), int) and turn["turn"] >= 0 else len(self.seen_turns) - 1
        calls = self._script[i] if i < len(self._script) else [{"name": "finish", "summary": "script exhausted"}]
        return {"tool_calls": calls}


class OperatorPatchProposer:
    """The existing operator route as a proposer: a patch (and manifest) the operator produced elsewhere."""

    kind = "operator-patch"
    model_id = "operator"
    plumbing_only = False

    def __init__(self, patch: bytes, manifest: bytes | None = None):
        self._patch, self._manifest = patch, manifest
        self._n = 0

    def reply(self, turn: dict) -> dict:
        self._n += 1
        if turn["turn"] > 0:
            return {"tool_calls": [{"name": "finish", "summary": "operator patch applied"}]}
        calls: list[dict] = [{"name": "apply_patch", "diff": self._patch.decode("utf-8", "surrogateescape")}]
        if self._manifest is not None:
            m = json.loads(self._manifest)
            calls.append({"name": "declare", "paths": m.get("paths", {}), **({"deltas": m["deltas"]} if "deltas" in m else {})})
        calls.append({"name": "finish", "summary": "operator patch applied"})
        return {"tool_calls": calls}


class ModelProposer:
    """A hosted or local model behind a client the HOST supplies: ``client.complete(prompt: str) -> str`` returning JSON
    {"tool_calls": [...]}. Runs supervisor-side only. Without a client it refuses (it never reads the environment)."""

    kind = "model"
    plumbing_only = False

    def __init__(self, client: Any, *, model_id: str):
        self._client, self.model_id = client, model_id

    def reply(self, turn: dict) -> dict:
        if self._client is None:
            raise NotConfigured("no model client was supplied; Hlith does not read credentials or open network connections itself")
        prompt = ("You change files in a repository through tool calls. Reply with JSON only: {\"tool_calls\": [...]} using "
                  "read_file(path), apply_patch(diff), declare(paths, deltas), finish(summary).\n"
                  f"TASK: {turn['task']}\nTURN: {turn['turn']}\nTRANSCRIPT: {json.dumps(turn['transcript'])[:60000]}")
        text = self._client.complete(prompt)
        bad = False
        out = None
        try:
            out = json.loads(text)
        except ValueError:
            bad = True  # the decode error object keeps the model's text (.doc): it must not be chained to what we raise
        if bad:
            raise NotConfigured("model reply is not JSON")
        return out if isinstance(out, dict) else {"tool_calls": []}


class CommandProposer:
    """Bridge from an operator-supplied LOCAL command to the checkpointed proposer graph (E1 part 2).

    Runs CONFINED by default (confinement policy): user+mount namespace, Landlock, no network, private empty scratch cwd,
    scrubbed env, no target-repository access. Running host-side requires an explicit typed trust flag
    (``HostSideProposerTrust(authorized=True)`` or ``allow_unconfined=True``) and NEVER counts as E2."""

    kind = "command"
    plumbing_only = False
    task = None

    def __init__(
        self,
        argv: list[str],
        *,
        model_id: str = "operator-command",
        timeout: float = 120.0,
        max_output: int = 256 * 1024,
        allow_unconfined: bool = False,
        host_trust: HostSideProposerTrust | None = None,
        confined_runner: Callable[..., Any] | None = None,
    ):
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise ValueError("argv must be a non-empty list of non-empty strings (no shell)")
        if not isinstance(allow_unconfined, bool):
            raise ValueError("allow_unconfined must be a boolean")
        if host_trust is not None and not isinstance(host_trust, HostSideProposerTrust):
            raise TypeError("host_trust must be a HostSideProposerTrust instance or None")
        self._argv, self.model_id, self._timeout, self._max = list(argv), model_id, float(timeout), int(max_output)
        self.host_trust = host_trust if host_trust is not None else HostSideProposerTrust(authorized=allow_unconfined)
        self.allow_unconfined = bool(allow_unconfined or self.host_trust.authorized)
        self.counts_as_e2 = not self.allow_unconfined
        self._confined_runner = confined_runner or run_confined
        self.argv_sha256 = hashlib.sha256(
            json.dumps(self._argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        # Freeze resolved paths, file identities (dev, ino, nlink), and execution argv at construction/guard
        # time so symlink repointing (G10) or hardlink inode swaps (T6/T7) cannot expand the sandbox grant.
        self._frozen_paths: tuple[Path, ...] = self.referenced_paths()
        self._frozen_exec_argv: tuple[str, ...] = tuple(self._execution_argv())
        self._frozen_path_stats: tuple[tuple[bool, int, int, int] | None, ...] = self._stat_frozen_paths(self._frozen_paths)

    @staticmethod
    def _stat_frozen_paths(paths: tuple[Path, ...]) -> tuple[tuple[bool, int, int, int] | None, ...]:
        stats: list[tuple[bool, int, int, int] | None] = []
        for path in paths:
            try:
                st = os.stat(path)
            except OSError:
                stats.append(None)
            else:
                stats.append((stat.S_ISREG(st.st_mode), st.st_dev, st.st_ino, st.st_nlink))
        return tuple(stats)

    def _verify_frozen_paths(self) -> None:
        if self.referenced_paths() != self._frozen_paths or tuple(self._execution_argv()) != self._frozen_exec_argv:
            raise NotConfigured("proposer command paths changed after validation (TOCTOU)")
        current_stats = self._stat_frozen_paths(self._frozen_paths)
        if current_stats != self._frozen_path_stats:
            raise NotConfigured("proposer command file identity changed after validation (TOCTOU)")
        if any(entry is not None and entry[0] and entry[3] > 1 for entry in current_stats):
            raise NotConfigured("proposer command path is a hardlinked file (st_nlink > 1)")

    def provenance(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "model_id": self.model_id,
            "confined": not self.allow_unconfined,
            "allow_unconfined": self.allow_unconfined,
            "counts_as_e2": self.counts_as_e2,
            "argv_sha256": self.argv_sha256,
            **({"host_trust_reason": self.host_trust.reason} if self.host_trust.reason else {}),
        }

    def _execution_argv(self) -> list[str]:
        """Make operator-cwd executable and file arguments stable after switching to the neutral scratch cwd."""
        path = os.environ.get("PATH", "/usr/bin:/bin")
        result = list(self._argv)
        for i, arg in enumerate(result):
            candidate = None
            if i == 0:
                found = shutil.which(arg, path=path)
                if found:
                    candidate = Path(found)
                elif Path(arg).exists() or Path(arg).is_absolute() or os.sep in arg:
                    candidate = Path(arg)
            elif Path(arg).exists() or Path(arg).is_absolute() or arg.startswith(("./", "../")):
                candidate = Path(arg)
            if candidate is not None:
                result[i] = str(candidate.expanduser().resolve())
        return result

    def _unconfined_form_reason(self, target_repo) -> str | None:
        argv = self._argv
        executable = Path(self._execution_argv()[0]).name.lower()
        is_env = executable == "env"
        is_shell = executable in {"sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh"}
        is_python = bool(re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", executable))
        args = argv[1:]

        if is_env:
            if any(a in ("-S", "--split-string") or a.startswith("--split-string=") for a in args):
                return "env split-string can hide the executable and script paths"
            if any(a in ("--chdir", "-C") or a.startswith("--chdir=") for a in args):
                return "env directory switching can run repository code"
            if "-c" in args:
                return "env can dispatch inline interpreter or shell code"

        if is_shell and any(
            a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:])
            for a in args
        ):
            return "shell inline code can read and execute repository files"

        if is_python:
            if any(a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]) for a in args):
                return "interpreter inline code can read and execute repository files"
            if any(a == "-S" or a == "-C" or a.startswith("--chdir=") for a in args):
                return "interpreter flags can change module or working-directory resolution"
            for i, arg in enumerate(args[:-1]):
                if arg == "-m" and self._module_resolves_in_repo(args[i + 1], target_repo):
                    return "interpreter module resolves to code inside the target repository"

        if any(a == "--chdir" or a.startswith("--chdir=") or a == "-C" for a in args):
            return "directory-switch flags can run repository code"
        return None

    @staticmethod
    def _module_resolves_in_repo(module: str, target_repo) -> bool:
        parts = module.split(".")
        if not parts or not all(part.isidentifier() for part in parts):
            return False
        root = Path(target_repo).expanduser().resolve()
        stem = root.joinpath(*parts)
        for candidate in (stem.with_suffix(".py"), stem / "__main__.py", stem / "__init__.py"):
            if candidate.exists() or candidate.is_symlink():
                return True
        return False

    def ensure_unconfined_forms_allowed(self, target_repo) -> None:
        if self.allow_unconfined:
            return
        reason = self._unconfined_form_reason(target_repo)
        if reason:
            raise ValueError(f"{reason}; pass --allow-unconfined-proposer only if this runs code outside confinement")

    def referenced_paths(self):
        """Resolve the executable and existing path arguments without interpreting code or shell syntax."""
        found_paths = []
        for i, arg in enumerate(self._argv):
            candidate = None
            if i == 0:
                found = shutil.which(arg, path=os.environ.get("PATH", "/usr/bin:/bin"))
                if found:
                    candidate = Path(found)
                elif Path(arg).exists() or Path(arg).is_absolute() or os.sep in arg:
                    candidate = Path(arg)
            elif Path(arg).exists() or Path(arg).is_absolute() or arg.startswith(("./", "../")):
                candidate = Path(arg)
            if candidate is None:
                continue
            found_paths.append(candidate.expanduser().resolve())
        return tuple(found_paths)

    def ensure_paths_outside(self, roots) -> None:
        """Refuse an executable or existing path that equals, lives inside, or contains a protected tree."""
        if roots:
            self.ensure_unconfined_forms_allowed(roots[0])
        blocked = [Path(p).expanduser().resolve() for p in roots]
        for resolved in self.referenced_paths():
            if any(resolved == root or root in resolved.parents or resolved in root.parents for root in blocked):
                raise ValueError("proposer command path overlaps a protected or worker-readable path")

    def _reply_confined(self, body: bytes) -> str:
        self._verify_frozen_paths()
        scratch = tempfile.TemporaryDirectory(prefix="hlith-proposer-", dir="/tmp")
        try:
            turn_file = Path(scratch.name) / "turn.json"
            turn_file.write_bytes(body)
            exec_argv = list(self._frozen_exec_argv)
            profile = build_proposer_profile(
                scratch=Path(scratch.name),
                ro_paths=self._frozen_paths,
            )
            env = {
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "HOME": "/nonexistent",
                "TMPDIR": scratch.name,
                "TMP": scratch.name,
                "TEMP": scratch.name,
            }
            limit_marker = Path(scratch.name) / f".limit-{secrets.token_hex(16)}"
            cmd = [
                sys.executable,
                "-I",
                "-c",
                _CONFINED_STDIN_BOOTSTRAP,
                str(turn_file),
                json.dumps(exec_argv, ensure_ascii=False),
                str(self._max),
                str(limit_marker),
            ]
            try:
                cp = self._confined_runner(cmd, profile, cwd=scratch.name, timeout=self._timeout, env=env)
            except GrantError as e:
                raise NotConfigured(f"proposer confinement grant refused ({e})") from None
            except subprocess.TimeoutExpired:
                raise NotConfigured("proposer command did not run (TimeoutExpired)") from None
            except UnicodeDecodeError:
                raise NotConfigured("proposer command output is not JSON") from None
            except OSError as e:
                raise NotConfigured(f"proposer command did not run ({type(e).__name__})") from None
            # Best-effort disambiguation of bootstrap output-limit vs child exit 125 (fail-closed either way:
            # a same-uid child can inspect /proc/<ppid>/cmdline and forge the reason string, which is advisory only).
            if cp.returncode == 125 and limit_marker.exists():
                raise ProposerOutputLimit(self._max)
            if cp.returncode != 0:
                raise NotConfigured(f"proposer command exited {cp.returncode}")
            try:
                stdout = cp.stdout if isinstance(cp.stdout, str) else cp.stdout.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise NotConfigured("proposer command output is not JSON") from None
            if len(stdout.encode("utf-8")) > self._max:
                raise ProposerOutputLimit(self._max)
            return stdout
        finally:
            scratch.cleanup()

    def _reply_host_side(self, body: bytes) -> str:
        self._verify_frozen_paths()
        scratch = tempfile.TemporaryDirectory(prefix="hlith-proposer-", dir="/tmp")
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "HOME": "/nonexistent",
            "TMPDIR": scratch.name,
            "TMP": scratch.name,
            "TEMP": scratch.name,
        }
        try:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _PARENT_DEATH_BOOTSTRAP,
                    str(os.getpid()),
                    json.dumps(list(self._frozen_exec_argv), ensure_ascii=False),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                cwd=scratch.name,
                start_new_session=True,
            )
        except OSError as e:
            scratch.cleanup()
            raise NotConfigured(f"proposer command did not run ({type(e).__name__})") from None

        def _kill_tree(pipe_ino: int | None) -> None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            if pipe_ino is not None:
                target = f"pipe:[{pipe_ino}]"
                uid, me = os.getuid(), os.getpid()
                try:
                    entries = os.listdir("/proc")
                except OSError:
                    entries = []
                for name in entries:
                    if not name.isdigit():
                        continue
                    pid = int(name)
                    if pid == me:
                        continue
                    try:
                        if os.stat(f"/proc/{pid}").st_uid != uid:
                            continue
                        for fdname in os.listdir(f"/proc/{pid}/fd"):
                            try:
                                if os.readlink(f"/proc/{pid}/fd/{fdname}") == target:
                                    os.kill(pid, signal.SIGKILL)
                                    break
                            except OSError:
                                continue
                    except OSError:
                        continue
            try:
                proc.kill()
            except OSError:
                pass

        assert proc.stdin is not None and proc.stdout is not None
        in_fd = proc.stdin.fileno()
        out_fd = proc.stdout.fileno()
        try:
            pipe_ino: int | None = os.fstat(out_fd).st_ino
        except OSError:
            pipe_ino = None
        os.set_blocking(in_fd, False)
        os.set_blocking(out_fd, False)
        sel = selectors.DefaultSelector()
        sel.register(in_fd, selectors.EVENT_WRITE)
        sel.register(out_fd, selectors.EVENT_READ)
        in_off = 0
        chunks: list[bytes] = []
        total = 0
        deadline = time.monotonic() + self._timeout
        try:
            while sel.get_map():
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise NotConfigured("proposer command did not run (TimeoutExpired)")
                events = sel.select(timeout=rem)
                if not events:
                    raise NotConfigured("proposer command did not run (TimeoutExpired)")
                for key, _ in events:
                    if key.fd == in_fd:
                        try:
                            n = os.write(in_fd, memoryview(body)[in_off:])
                            in_off += n
                            if in_off >= len(body):
                                sel.unregister(in_fd)
                                proc.stdin.close()
                        except BlockingIOError:
                            pass
                        except OSError:
                            sel.unregister(in_fd)
                            try:
                                proc.stdin.close()
                            except OSError:
                                pass
                    elif key.fd == out_fd:
                        try:
                            data = os.read(out_fd, 65536)
                        except BlockingIOError:
                            continue
                        if not data:
                            sel.unregister(out_fd)
                            continue
                        total += len(data)
                        if total > self._max:
                            raise ProposerOutputLimit(self._max)
                        chunks.append(data)
            rem = max(0.05, deadline - time.monotonic())
            try:
                rc = proc.wait(timeout=rem)
            except subprocess.TimeoutExpired:
                raise NotConfigured("proposer command did not run (TimeoutExpired)") from None
        finally:
            sel.close()
            _kill_tree(pipe_ino)
            for stream in (proc.stdin, proc.stdout):
                try:
                    if not stream.closed:
                        stream.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
            scratch.cleanup()
        if rc != 0:
            raise NotConfigured(f"proposer command exited {rc}")  # stderr is withheld: it can carry anything
        try:
            stdout = b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise NotConfigured("proposer command output is not JSON") from None
        if len(stdout) > self._max:
            raise ProposerOutputLimit(self._max)
        return stdout

    def reply(self, turn: dict) -> dict:
        body = json.dumps({"turn": turn["turn"], "task": turn["task"], "transcript": turn["transcript"]}).encode("utf-8")
        stdout = self._reply_host_side(body) if self.allow_unconfined else self._reply_confined(body)
        try:
            out = json.loads(stdout)
        except ValueError:
            raise NotConfigured("proposer command output is not JSON") from None
        return out if isinstance(out, dict) else {"tool_calls": []}


__all__ = [
    "CommandProposer",
    "HostSideProposerTrust",
    "MockModelProposer",
    "ModelProposer",
    "NotConfigured",
    "OperatorPatchProposer",
    "Proposer",
    "ProposerOutputLimit",
]
