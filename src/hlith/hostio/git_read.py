# SPDX-License-Identifier: Apache-2.0
"""THE choke point for every Git command that touches a user-selected (untrusted) repository.

Threat model: the repository's own config, attributes, refs and object store, the inherited
process environment and a target that changes between a vet and a command are all untrusted. A per-key blocklist cannot close that family, so this
module is CLOSED-WORLD and FAIL-CLOSED:

* ``vet_repository`` returns ``None`` only on positive proof. The repository config must consist only of keys on a short allowlist (Tier A inert,
  Tier P inert BECAUSE this module pins them on every spawn), each with a checked value. Config is read with Git's own parser through
  ``git config --file`` (Git never starts inside the repository for the vet). Any error (spawn, timeout, parse, unreadable or non-regular file)
  is a refusal, never "ok".
* ``readonly_argv`` / ``scrubbed_git_env`` are the ONLY builders of a repository-bound argv and environment.
* ``run_readonly`` = vet -> spawn with a timeout -> re-check the config fingerprint; a change during the command discards the output.

No ``run_git(args)`` escape hatch and no write/apply/commit/config operations exist here (the gate WRITER imports the vet and builders, not a runner).
"""

from __future__ import annotations

import atexit
import enum
import os
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..contract.capabilities import GitRead
from ..contract.identities import TreeOid, tree_oid
from .integrity import HostIntegrityError

TIMEOUT = 30
MAX_CONFIG_BYTES = 1024 * 1024
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class GitReadErrorKind(str, enum.Enum):
    """Typed classification for hardened read-only Git failures."""

    UNSUPPORTED_FEATURE = "unsupported-git-feature"
    NONZERO_EXIT = "git-nonzero-exit"
    TIMEOUT = "git-timeout"
    SPAWN_FAILED = "git-spawn-failed"
    REPOSITORY_REFUSED = "repository-refused"
    CONCURRENT_MUTATION = "repository-changed-during-read"
    CANCELLED = "git-cancelled"


class GitReadError(HostIntegrityError):
    """Typed, bounded error from hardened read-only Git execution (always maps to host boundary)."""

    def __init__(
        self,
        kind: GitReadErrorKind,
        message: str,
        *,
        returncode: int | None = None,
        feature: str | None = None,
        stderr_excerpt: str = "",
    ) -> None:
        self.kind = kind
        self.returncode = returncode
        self.feature = feature
        self.stderr_excerpt = str(stderr_excerpt or "").strip()[:300]
        super().__init__(message)


@dataclass(frozen=True)
class GitFeatureCheck:
    """Result of probing one required hardened Git feature under the scrubbed environment."""

    name: str
    ok: bool
    detail: str
    returncode: int | None = None


@dataclass(frozen=True)
class GitFeatureProbeResult:
    """Complete result of probing every required hardened Git feature."""

    ok: bool
    executable: str | None
    version: str | None
    failed_feature: str | None
    reason: str
    checks: tuple[GitFeatureCheck, ...]

# Overrides that neutralise every program/transport/output-shaping setting we know of. They are the BACKSTOP for the vet-to-command window and the PIN for the
# Tier P keys; they are NOT the control (the allowlist is).
_HARDEN: tuple[str, ...] = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=",
    "-c", "core.untrackedCache=false",
    "-c", "core.pager=",
    "-c", "core.attributesFile=/dev/null",
    "-c", "commit.gpgsign=false",
    "-c", "protocol.allow=never",
    "-c", "diff.ignoreSubmodules=all",
    "-c", "status.submoduleSummary=false",
    "-c", "submodule.recurse=false",
    "-c", "log.showSignature=false",
    "-c", "gpg.program=",
    "-c", "gpg.openpgp.program=",
    "-c", "gpg.ssh.program=",
    "-c", "gpg.x509.program=",
    "-c", "core.sshCommand=",
    "-c", "core.askPass=",
    "-c", "credential.helper=",
    "-c", "core.gitProxy=",
    # Tier P pins: output shaping must not depend on the repository's own config
    "-c", "color.ui=false",
    "-c", "color.diff=false",
    "-c", "color.status=false",
    "-c", "color.branch=false",
    "-c", "color.interactive=false",
    "-c", "core.abbrev=auto",
    "-c", "diff.renames=true",  # the git default, pinned so a repository cannot reshape status/diff rows
)

_BAD_NAME_CHARS = frozenset("\n\r\0\\")

MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 200_000

# ---------------------------------------------------------------------------------------------------------------------------------------------
# environment

ALLOWED_EXTRA_ENV = ("GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")  # the temp-index trick, nothing else
_HOME: dict = {"dir": None}


def private_home() -> str:
    """An empty, private (0700) HOME for every git child: no ~/.gitconfig, no ~/.config/git, no credentials."""
    d = _HOME["dir"]
    if d is None or not os.path.isdir(d):
        d = tempfile.mkdtemp(prefix="hlith-git-home-", dir="/tmp")
        _HOME["dir"] = d
        atexit.register(lambda p=d: shutil.rmtree(p, ignore_errors=True))
    return d


def scrubbed_git_env(ceiling_dir: Path | None = None, extra: dict[str, str] | None = None, *, writer: bool = False) -> dict[str, str]:
    """The ONLY environment a repository-bound git child gets (positive allowlist). Inherited GIT_* (GIT_DIR, GIT_WORK_TREE, GIT_CONFIG_*, GIT_EXTERNAL_DIFF,
    GIT_PAGER, GIT_SSH*, GIT_TRACE*, GIT_EXEC_PATH, GIT_TEMPLATE_DIR, GIT_NAMESPACE, the pathspec family, XDG_CONFIG_HOME ...) never reach it."""
    bad = [k for k in (extra or {}) if k not in ALLOWED_EXTRA_ENV]
    if bad:
        raise ValueError(f"git environment variable(s) not allowed: {', '.join(sorted(bad))}")
    for k, v in (extra or {}).items():  # even the three allowed names may only point where the temp-index trick needs them
        real = os.path.realpath(v)
        if k == "GIT_ALTERNATE_OBJECT_DIRECTORIES":
            ok = real.endswith(os.sep + os.path.join(".git", "objects"))
        else:
            roots = {os.path.realpath(tempfile.gettempdir()), os.path.realpath("/tmp")}  # TMPDIR-aware, plus the fixed /tmp some producers use
            ok = any(real.startswith(t + os.sep) and real[len(t) + 1:].split(os.sep)[0].startswith("hlith-") for t in roots)  # a directory Hlith itself made, never the target's own files
        if not ok:
            raise ValueError(f"git environment variable {k} points outside its allowed place: {v!r}")
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": private_home(),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_LITERAL_PATHSPECS": "1",  # a path from a patch or a ref is a PATH, never pathspec magic (":(exclude)x", "[id]", "*")
    }
    if writer:  # the gate WRITER may refresh the index (git apply --index needs stat-fresh entries); a READER never writes the target
        del env["GIT_OPTIONAL_LOCKS"]
    if ceiling_dir is not None:
        env["GIT_CEILING_DIRECTORIES"] = str(Path(ceiling_dir).resolve())
    env.update(extra or {})
    return env


# ---------------------------------------------------------------------------------------------------------------------------------------------
# closed-world config policy

_CTRL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_BOOLS = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0"})
_INT = re.compile(r"^-?\d+[kKmMgG]?$")
_HELPER_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*::")


def _text(v: str | None) -> bool:
    return v is not None and len(v) <= 4096 and not _CTRL.search(v)


def _bool(v: str | None) -> bool:
    return v is None or v.lower() in _BOOLS or v == ""


def _int(v: str | None) -> bool:
    return v is not None and bool(_INT.match(v))


def _false(v: str | None) -> bool:
    return v is not None and v.lower() in {"false", "no", "off", "0"}


def _eq0(v: str | None) -> bool:
    return v == "0"


def _logallrefupdates(v: str | None) -> bool:
    return _bool(v) or (v is not None and v.lower() == "always")


def _name(v: str | None) -> bool:
    return _text(v) and not (v or "").startswith("-")


def _url(v: str | None) -> bool:
    return _name(v) and not _HELPER_URL.match(v or "")


def _tagopt(v: str | None) -> bool:
    return v in ("--no-tags", "--tags")


def _abbrev(v: str | None) -> bool:
    return _bool(v) or _int(v) or (v is not None and v.lower() in {"auto", "no"})


def _boolish_text(v: str | None) -> bool:
    return v is None or _text(v)


# (section, subsection-kind, variable) -> value check. subsection-kind: None = no subsection, "*" = a subsection is required (any name).
_ALLOWED: dict[tuple[str, str | None, str], Callable[[str | None], bool]] = {
    # Tier A: inert for every read we make (observed by review on Git 2.43.0)
    ("core", None, "repositoryformatversion"): _eq0,   # version 1 = extensions (partial clone, worktreeConfig, ...): refused
    ("core", None, "filemode"): _bool,
    ("core", None, "bare"): _false,
    ("core", None, "logallrefupdates"): _logallrefupdates,
    ("core", None, "ignorecase"): _bool,
    ("core", None, "precomposeunicode"): _bool,
    ("core", None, "symlinks"): _bool,
    ("core", None, "compression"): _int,
    ("core", None, "looseCompression".lower()): _int,
    ("user", None, "name"): _text,
    ("user", None, "email"): _text,
    ("remote", "*", "url"): _url,
    ("remote", "*", "pushurl"): _url,
    ("remote", "*", "fetch"): _name,
    ("remote", "*", "tagopt"): _tagopt,
    ("branch", "*", "remote"): _name,
    ("branch", "*", "merge"): _name,
    ("branch", "*", "rebase"): _boolish_text,
    ("branch", "*", "vscode-merge-base"): _name,
    ("submodule", None, "active"): _name,
    ("submodule", "*", "active"): _bool,  # `git submodule add/init` writes both of these into .git/config: a plain submodule repository is supported
    ("submodule", "*", "url"): _url,
    ("gc", None, "auto"): _int,
    ("commit", None, "gpgsign"): _bool,
    ("pull", None, "rebase"): _boolish_text,
    ("push", None, "default"): _text,
    ("fetch", None, "prune"): _bool,
    # common inert keys written by ordinary tooling (the closed list refused them as false refusals; review/review-confirmed inert for every read we make)
    ("fetch", None, "prunetags"): _bool,
    ("remote", "*", "prune"): _bool,
    ("remote", "*", "prunetags"): _bool,
    ("remote", "*", "push"): _name,
    ("remote", "*", "gh-resolved"): _text,  # written by `gh repo set-default` / fork clones
    ("pull", None, "ff"): _boolish_text,
    ("push", None, "autosetupremote"): _bool,
    ("push", None, "followtags"): _bool,
    ("branch", "*", "pushremote"): _name,
    ("branch", "*", "description"): _text,
    ("branch", None, "autosetuprebase"): _text,
    ("branch", None, "autosetupmerge"): _text,
    ("rerere", None, "enabled"): _bool,
    ("user", None, "signingkey"): _text,
    ("core", None, "untrackedcache"): _bool,  # pinned false on every spawn (_HARDEN) and never read from the repository
    ("init", None, "defaultbranch"): _name,
    ("http", None, "sslverify"): _bool,
    ("http", None, "proxy"): _text,
    ("lfs", None, "url"): _url,
    # Tier P: allowed ONLY because _HARDEN pins them on every spawn (each proven by a marker/shape test)
    ("core", None, "hookspath"): _text,
    ("core", None, "abbrev"): _abbrev,
    ("diff", None, "renames"): _boolish_text,
    ("color", None, "ui"): _boolish_text,
    ("color", None, "diff"): _boolish_text,
    ("color", None, "status"): _boolish_text,
    ("color", None, "branch"): _boolish_text,
    ("color", None, "interactive"): _boolish_text,
}
_ALLOWED_MAINTENANCE = re.compile(r"^(maintenance|advice)\.[^\n]+$")  # maintenance.* scheduling and advice.* hint switches: inert for reads


def _split_key(key: str) -> tuple[str, str | None, str] | None:
    section, dot, rest = key.partition(".")
    if not dot or not section or not rest:
        return None
    if "." in rest:
        sub, _, var = rest.rpartition(".")
        if not sub or not var:
            return None
        return section.lower(), sub, var.lower()
    return section.lower(), None, rest.lower()


def _relative_worktree(v: str | None) -> bool:
    return _text(v) and not (v or "").startswith(("/", "-"))


# A submodule's OWN git dir (.git/modules/*/config) carries core.worktree by construction (git writes it); the outer commands never recurse into it.
_MODULE_EXTRA: dict[tuple[str, str | None, str], Callable[[str | None], bool]] = {("core", None, "worktree"): _relative_worktree}


def config_key_violation(key: str, value: str | None, extra: dict | None = None) -> str | None:
    """Why ONE ``key=value`` record of a repository config is not allowed (closed world), or None."""
    if _ALLOWED_MAINTENANCE.match(key.lower()) and (value is None or _text(value)):
        return None
    parts = _split_key(key)
    if parts is None:
        return f"config-key-unparseable:{key[:80]!r}"
    section, sub, var = parts
    kind = "*" if sub is not None else None
    check = _ALLOWED.get((section, kind, var)) or (extra or {}).get((section, kind, var))
    if check is None:
        return f"config-key-not-allowed:{key.lower()}"
    if not check(value):
        return f"config-value-not-allowed:{key.lower()}"
    return None


# ---------------------------------------------------------------------------------------------------------------------------------------------
# spawn seam (one place; tests observe or break it)


_SPAWN_LOCK = threading.Lock()
_ACTIVE_SPAWNS: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()
_SPAWNS_CANCELLED = False


def begin_session() -> None:
    """Allow read-only git spawns for a newly opened interactive TUI session."""
    global _SPAWNS_CANCELLED
    with _SPAWN_LOCK:
        _SPAWNS_CANCELLED = False


def cancel_active_children() -> None:
    """Terminate active read-only git process groups (used on interactive TUI quit)."""
    global _SPAWNS_CANCELLED
    with _SPAWN_LOCK:
        _SPAWNS_CANCELLED = True
        children = tuple(_ACTIVE_SPAWNS)
    for proc in children:
        if proc.poll() is not None:
            continue
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    deadline = time.monotonic() + 0.2
    for proc in children:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                proc.wait(timeout=remaining)
                continue
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass


def _spawn(argv: list[str], *, input_bytes: bytes | None = None, env: dict[str, str], cwd: str | None = None, timeout: float = TIMEOUT) -> subprocess.CompletedProcess:
    proc: subprocess.Popen | None = None
    try:
        with _SPAWN_LOCK:
            if _SPAWNS_CANCELLED:
                raise GitReadError(GitReadErrorKind.CANCELLED, "git cancelled: session shutting down")
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if input_bytes is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=cwd,
                start_new_session=True,
            )
            _ACTIVE_SPAWNS.add(proc)
        stdout, stderr = proc.communicate(input=input_bytes, timeout=timeout)
        return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=1.0)
            except (OSError, subprocess.SubprocessError):
                pass
        raise GitReadError(
            GitReadErrorKind.TIMEOUT,
            f"git {argv[-1] if argv else ''} timed out after {timeout}s",
        ) from None
    except GitReadError:
        raise
    except HostIntegrityError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitReadError(
            GitReadErrorKind.SPAWN_FAILED,
            f"cannot run git ({getattr(exc, 'strerror', None) or exc})",
        ) from None
    finally:
        if proc is not None:
            with _SPAWN_LOCK:
                _ACTIVE_SPAWNS.discard(proc)


_UNSUPPORTED_FEATURE_TOKENS: tuple[tuple[str, str], ...] = (
    ("--attr-source", "attr-source"),
    ("attr-source", "attr-source"),
    ("--path-format", "rev-parse-path-format"),
    ("path-format", "rev-parse-path-format"),
    ("--ignore-submodules", "ignore-submodules"),
    ("--no-show-signature", "log-no-show-signature"),
    ("--no-includes", "config-no-includes"),
    ("--no-ext-diff", "diff-no-ext-diff"),
    ("--no-textconv", "diff-no-textconv"),
    ("--no-replace-objects", "no-replace-objects"),
    ("--porcelain=v1", "status-porcelain-v1"),
    ("--full-tree", "ls-tree-full-tree"),
    ("--numstat", "apply-numstat"),
)
_UNSUPPORTED_STDERR_RE = re.compile(
    r"unknown option|unrecognized option|invalid option|unknown switch|ambiguous option|unsupported",
    re.I,
)


def _detect_unsupported_feature(stderr_text: str, *, feature_hint: str | None = None) -> str | None:
    low = stderr_text.lower()
    for token, name in _UNSUPPORTED_FEATURE_TOKENS:
        if token in low:
            return name
    return feature_hint


def _classify_git_failure(
    argv: list[str] | tuple[str, ...],
    returncode: int,
    stderr_bytes: bytes | str,
    *,
    feature_hint: str | None = None,
) -> GitReadError:
    err_text = (
        stderr_bytes.decode("utf-8", "replace")
        if isinstance(stderr_bytes, (bytes, bytearray))
        else str(stderr_bytes or "")
    ).strip()[:300]
    first_line = err_text.splitlines()[0] if err_text else ""
    looks_unsupported = returncode == 129 or bool(_UNSUPPORTED_STDERR_RE.search(err_text))
    detected = _detect_unsupported_feature(err_text, feature_hint=feature_hint)
    if looks_unsupported and (detected is not None or returncode == 129):
        feat = detected or feature_hint or "hardened-git-option"
        detail = first_line or f"git exited {returncode}"
        return GitReadError(
            GitReadErrorKind.UNSUPPORTED_FEATURE,
            f"unsupported git feature ({feat}): {detail}. Install a Git build that supports {feat} and verify with `hlith doctor`.",
            returncode=returncode,
            feature=feat,
            stderr_excerpt=err_text,
        )
    sub = next((a for a in argv[1:] if isinstance(a, str) and not a.startswith("-")), "git")
    detail = first_line or f"exit {returncode}"
    return GitReadError(
        GitReadErrorKind.NONZERO_EXIT,
        f"git {sub} failed (exit {returncode}): {detail}",
        returncode=returncode,
        feature=feature_hint,
        stderr_excerpt=err_text,
    )


_PROBE_LOCK = threading.Lock()
_PROBE_CACHE: dict[str, tuple[tuple[str, int, int, int, int], GitFeatureProbeResult]] = {}
_PROBE_SAMPLE_PATCH = (
    b"diff --git a/x b/x\n"
    b"--- a/x\n"
    b"+++ b/x\n"
    b"@@ -1 +1 @@\n"
    b"-a\n"
    b"+b\n"
)
_PROBE_HARDEN: tuple[str, ...] = (*_HARDEN, "-c", "core.quotepath=false")


def _probe_cache_key(exe: str) -> tuple[str, int, int, int, int] | None:
    try:
        real = os.path.realpath(exe)
        st = os.stat(real)
        return (real, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def probe_git_features(*, fresh: bool = False) -> GitFeatureProbeResult:
    """Actively probe EVERY required hardened Git feature under the scrubbed neutral environment.

    Never guesses from a Git version string: version text is captured strictly as display metadata.
    Never touches any user repository (runs only against a private temporary scratch repo).
    """
    env = scrubbed_git_env()
    home = private_home()
    exe = shutil.which("git", path=env.get("PATH"))
    if not exe:
        return GitFeatureProbeResult(
            ok=False,
            executable=None,
            version=None,
            failed_feature="git-executable",
            reason="git is missing from PATH",
            checks=(GitFeatureCheck("git-executable", False, "git is missing from PATH"),),
        )
    cache_key = _probe_cache_key(exe)
    if not fresh and cache_key is not None:
        with _PROBE_LOCK:
            cached = _PROBE_CACHE.get("latest")
            if cached is not None and cached[0] == cache_key:
                return cached[1]

    checks: list[GitFeatureCheck] = []
    version_text: str | None = None

    def _run_probe(name: str, argv: list[str], *, input_bytes: bytes | None = None, timeout: float = 10.0) -> tuple[bool, bytes, str, int | None]:
        try:
            cp = _spawn(argv, input_bytes=input_bytes, env=env, cwd=home, timeout=timeout)
        except GitReadError as exc:
            checks.append(GitFeatureCheck(name, False, str(exc), exc.returncode))
            return False, b"", str(exc), exc.returncode
        if cp.returncode != 0:
            err = cp.stderr.decode("utf-8", "replace").strip().splitlines()
            detail = err[0][:200] if err else f"exit {cp.returncode}"
            checks.append(GitFeatureCheck(name, False, f"exit {cp.returncode}: {detail}", cp.returncode))
            return False, cp.stdout, f"exit {cp.returncode}: {detail}", cp.returncode
        checks.append(GitFeatureCheck(name, True, "ok", 0))
        return True, cp.stdout, "ok", 0

    def _finish(ok: bool, failed_feature: str | None, reason: str) -> GitFeatureProbeResult:
        res = GitFeatureProbeResult(
            ok=ok,
            executable=exe,
            version=version_text,
            failed_feature=failed_feature,
            reason=reason,
            checks=tuple(checks),
        )
        if cache_key is not None:
            with _PROBE_LOCK:
                _PROBE_CACHE["latest"] = (cache_key, res)
        return res

    ok, out, detail, _rc = _run_probe("git-executable", ["git", "--no-pager", "--version"])
    if not ok:
        return _finish(False, "git-executable", f"git failed to execute ({detail})")
    version_text = out.decode("utf-8", "replace").strip().splitlines()[0][:120] if out.strip() else None

    try:
        with tempfile.TemporaryDirectory(prefix="hlith-git-probe-") as tmpdir:
            scratch = Path(tmpdir) / "repo"
            ok, _out, detail, _rc = _run_probe("git-init-scratch", ["git", "--no-pager", "init", "-q", str(scratch)])
            if not ok:
                return _finish(False, "git-init-scratch", f"cannot initialize scratch repo for feature probe ({detail})")

            probe_specs: list[tuple[str, list[str], bytes | None, Callable[[bytes], str | None] | None]] = [
                (
                    "config-file-null-no-includes",
                    ["git", "--no-pager", "config", "--file", str(scratch / ".git" / "config"), "--list", "--null", "--no-includes"],
                    None,
                    None,
                ),
                (
                    "attr-source",
                    readonly_argv(
                        scratch,
                        ["rev-parse", "--git-dir"],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    None,
                ),
                (
                    "status-porcelain-v1-z",
                    readonly_argv(
                        scratch,
                        ["status", "--ignore-submodules=all", "--porcelain=v1", "-z", "--untracked-files=all"],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    None,
                ),
                (
                    "rev-parse-path-format",
                    readonly_argv(
                        scratch,
                        ["rev-parse", "--path-format=absolute", "--git-path", "index"],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    lambda stdout: (
                        None
                        if os.path.isabs(stdout.decode("utf-8", "replace").strip())
                        else "rev-parse --path-format=absolute did not return an absolute path"
                    ),
                ),
                (
                    "diff-hardened-flags",
                    readonly_argv(
                        scratch,
                        ["diff", "--ignore-submodules=all", "--binary", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/", EMPTY_TREE, "--"],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    None,
                ),
                (
                    "ls-tree-full-tree-z",
                    readonly_argv(
                        scratch,
                        ["ls-tree", "-r", "-l", "-z", "--full-tree", EMPTY_TREE],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    None,
                ),
                (
                    "cat-file-batch",
                    readonly_argv(
                        scratch,
                        ["cat-file", "--batch"],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    b"",
                    None,
                ),
                (
                    "log-no-show-signature",
                    readonly_argv(
                        scratch,
                        ["log", "--no-show-signature", "-n0", "--format=%H", EMPTY_TREE],
                        pre=(f"--attr-source={EMPTY_TREE}",),
                        flags=_PROBE_HARDEN,
                    ),
                    None,
                    None,
                ),
                (
                    "apply-numstat-z",
                    ["git", "--no-pager", "apply", "--numstat", "-z", "-"],
                    _PROBE_SAMPLE_PATCH,
                    lambda stdout: (
                        None
                        if b"1\t1\tx\0" in stdout
                        else f"unexpected apply --numstat -z output: {stdout[:80]!r}"
                    ),
                ),
            ]
            for feat_name, argv, inp, validator in probe_specs:
                ok, out, detail, _rc = _run_probe(feat_name, argv, input_bytes=inp)
                if not ok:
                    return _finish(
                        False,
                        feat_name,
                        f"required Git feature '{feat_name}' failed ({detail})",
                    )
                if validator is not None:
                    v_err = validator(out)
                    if v_err is not None:
                        checks[-1] = GitFeatureCheck(feat_name, False, v_err, 0)
                        return _finish(False, feat_name, f"required Git feature '{feat_name}' failed ({v_err})")
    except OSError as exc:
        checks.append(GitFeatureCheck("git-probe-scratch", False, str(exc)))
        return _finish(False, "git-probe-scratch", f"cannot prepare scratch directory for Git feature probe ({exc})")

    return _finish(True, None, "required hardened Git features verified")


def require_supported_git(*, fresh: bool = False) -> GitFeatureProbeResult:
    """Verify required hardened Git features or raise a typed ``GitReadError`` (fail closed)."""
    res = probe_git_features(fresh=fresh)
    if res.ok:
        return res
    kind = GitReadErrorKind.UNSUPPORTED_FEATURE
    if res.failed_feature == "git-executable":
        kind = GitReadErrorKind.SPAWN_FAILED
    elif "timed out" in res.reason.lower():
        kind = GitReadErrorKind.TIMEOUT
    ver = f" ({res.version})" if res.version else ""
    raise GitReadError(
        kind,
        f"unsupported or unusable Git{ver}: {res.reason}. Run `hlith doctor` for details.",
        feature=res.failed_feature,
        stderr_excerpt=res.reason,
    )


def _regular_file_violation(path: Path, what: str) -> str | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return f"{what}-unreadable"
    if not stat.S_ISREG(st.st_mode):
        return f"{what}-not-a-regular-file"
    if st.st_size > MAX_CONFIG_BYTES:
        return f"{what}-too-large"
    return None


def _config_file_violation(path: Path, what: str, extra: dict | None = None) -> str | None:
    """Closed-world check of ONE config file with Git's own parser (never a hand parser). Every record is checked; there is no scope skipping."""
    v = _regular_file_violation(path, what)
    if v is not None:
        return v
    if not path.exists():
        return None
    argv = ["git", "--no-pager", "config", "--file", str(path), "--list", "--null", "--no-includes"]
    try:
        cp = _spawn(argv, env=scrubbed_git_env(), cwd="/")
    except HostIntegrityError as exc:
        return f"{what}-unreadable:{exc}"
    if cp.returncode != 0:
        return f"{what}-unreadable:{cp.stderr.decode('utf-8', 'replace').strip()[:200]}"
    found: list[str] = []
    for rec in cp.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if not rec:
            continue
        key, sep, val = rec.partition("\n")
        why = config_key_violation(key, val if sep else None, extra)
        if why is not None and why not in found:
            found.append(why)
    if found:  # name EVERY offending key (up to 8): cleaning a repository up one key per attempt is a product defect
        shown = "; ".join(found[:8]) + (f"; ... +{len(found) - 8} more" if len(found) > 8 else "")
        return f"target-config-can-execute-programs:{what}:{shown}"
    return None


# ---------------------------------------------------------------------------------------------------------------------------------------------
# repository identity / structure


def _target_git_dir_violation(target: Path) -> str | None:
    target = Path(target).resolve()
    git_dir = target / ".git"
    try:
        if git_dir.is_symlink() or not git_dir.is_dir():
            return "target-git-dir-not-real-directory"
        resolved_git_dir = git_dir.resolve(strict=True)
    except OSError:
        return "target-git-dir-not-real-directory"
    if resolved_git_dir != target / ".git":
        return "target-git-dir-outside-target"
    common_dir = git_dir / "commondir"
    if common_dir.exists():
        try:
            common_path = (git_dir / common_dir.read_text(encoding="utf-8").strip()).resolve(strict=True)
        except (OSError, UnicodeError):
            return "target-git-common-dir-unreadable"
        if common_path != resolved_git_dir:
            return "target-git-dir-outside-target"
    return None


def _plausible_dot_git(entry: Path) -> bool:
    """Would git itself accept this as a repository marker? A gitfile (starts with 'gitdir:') or a directory holding HEAD, objects/ and refs/. Git skips anything else and keeps
    climbing (a stub .git directory in a parent, e.g. a home directory, is not a repository)."""
    try:
        if entry.is_symlink():
            return True  # a symlinked .git is a repository SHAPE that is refused by name, never "no repository"
        if entry.is_file():
            return entry.read_text(encoding="utf-8", errors="replace").startswith("gitdir:")
        return entry.is_dir() and (entry / "HEAD").is_file() and (entry / "objects").is_dir() and (entry / "refs").is_dir()
    except OSError:
        return False


def find_work_tree_root(start: Path) -> Path | None:
    """The nearest ancestor of ``start`` (inclusive) that carries a plausible .git, or None. Pure path logic: no git process runs before the vet has passed."""
    here = Path(start).resolve()
    root = next((d for d in (here, *here.parents) if os.path.lexists(d / ".git") and _plausible_dot_git(d / ".git")), None)
    if root is None or here == root / ".git" or (root / ".git") in here.parents:
        return None
    return root


def _ownership_violation(real: Path) -> str | None:
    # An explicit --git-dir skips Git's own dubious-ownership check, so the vet owns it.
    euid = os.geteuid()
    for p in (real, real / ".git", real / ".git" / "config"):
        try:
            if os.lstat(p).st_uid != euid:
                return f"target-not-owned-by-user:{p.name or p}"
        except FileNotFoundError:
            if p.name == "config":
                continue
            return "target-git-dir-not-real-directory"
        except OSError:
            return "target-git-dir-not-real-directory"
    return None


def _symlink_violation(real: Path) -> str | None:
    """No symlink in the places Git follows to find refs/objects: .git's own entries, refs/**, objects/ (two levels) and objects/info|pack. Alternates refused."""
    git_dir = real / ".git"
    try:
        for entry in os.scandir(git_dir):
            if entry.is_symlink() and entry.name != "hooks":  # hooks are never run: core.hooksPath is pinned to /dev/null on every spawn
                return f"target-git-symlink:{entry.name}"
        for directory, dirs, files in os.walk(git_dir / "refs", followlinks=False):
            for name in (*dirs, *files):
                if os.path.islink(os.path.join(directory, name)):
                    return f"target-git-symlink:refs/{os.path.relpath(os.path.join(directory, name), git_dir / 'refs')}"
        objects = git_dir / "objects"
        if objects.is_dir():
            for entry in os.scandir(objects):
                if entry.is_symlink():
                    return f"target-git-symlink:objects/{entry.name}"
                if entry.is_dir(follow_symlinks=False) and (entry.name in ("info", "pack") or len(entry.name) == 2):
                    for sub in os.scandir(entry.path):
                        if sub.is_symlink():
                            return f"target-git-symlink:objects/{entry.name}/{sub.name}"
        for alt in ("alternates", "http-alternates"):
            if (git_dir / "objects" / "info" / alt).exists():
                return f"target-objects-alternates:{alt}"
    except OSError as exc:
        return f"target-git-dir-unreadable:{exc.strerror or exc}"
    return None


def _modules_violation(real: Path) -> str | None:
    modules = real / ".git" / "modules"
    if not modules.exists() and not modules.is_symlink():
        return None
    if modules.is_symlink() or not modules.is_dir():
        return "target-git-symlink:modules"
    for directory, dirs, files in os.walk(modules, followlinks=False):
        for name in (*dirs, *files):
            if os.path.islink(os.path.join(directory, name)):
                return f"target-submodule-unreadable:{os.path.relpath(os.path.join(directory, name), real)}"
        if "config.worktree" in files:
            return f"target-submodule-config-can-execute-programs:{os.path.relpath(os.path.join(directory, 'config.worktree'), real)}"
        if "config" in files:
            why = _config_file_violation(Path(directory) / "config", "submodule-config", _MODULE_EXTRA)
            if why is not None:
                return why
    return None


def _nested_repository_violation(real: Path) -> str | None:
    for directory, dirs, _files in os.walk(real, followlinks=False):
        if Path(directory) == real:
            dirs[:] = [d for d in dirs if d not in {".git", ".hlith"}]
        for d in list(dirs):
            nested = Path(directory) / d / ".git"
            if nested.is_dir() and not nested.is_symlink():
                return f"target-has-nested-git-repository:{(Path(directory) / d).relative_to(real)}"
        dirs[:] = [d for d in dirs if d != ".git"]
    return None


def vet_repository(repo: Path, *, deep: bool = False) -> str | None:
    """None ONLY on positive proof that a read of this repository cannot run repository-chosen code or describe another repository; otherwise a named reason.

    Fail-closed by construction: any unexpected error becomes a refusal. ``deep`` adds the full-worktree nested-repository walk (seal/landing; too costly per
    TUI command). Named limits (not refusals): ``.git/shallow``, index skip-worktree/assume-unchanged, ``core.filemode=false`` fidelity."""
    try:
        real = Path(repo).resolve()
        for check in (
            lambda: _target_git_dir_violation(real),
            lambda: "target-git-dir-commondir" if (real / ".git" / "commondir").exists() else None,
            lambda: _ownership_violation(real),
            lambda: _regular_file_violation(real / ".git" / "info" / "attributes", "info-attributes"),
            lambda: _regular_file_violation(real / ".git" / "info" / "exclude", "info-exclude"),
            lambda: _symlink_violation(real),
            lambda: "target-config-can-execute-programs:config.worktree" if (real / ".git" / "config.worktree").exists() else None,
            lambda: "target-grafts" if (real / ".git" / "info" / "grafts").exists() else None,
            lambda: _config_file_violation(real / ".git" / "config", "config"),
            lambda: _modules_violation(real),
            lambda: _nested_repository_violation(real) if deep else None,
        ):
            why = check()
            if why is not None:
                return why
        return None
    except Exception as exc:  # noqa: BLE001 - the vet must never raise "ok"
        return f"vet-error:{type(exc).__name__}:{exc}"


_FINGERPRINT_FILES = ("config", "config.worktree", "HEAD", os.path.join("info", "attributes"), os.path.join("info", "exclude"), os.path.join("info", "grafts"))


def _fingerprint(real: Path) -> tuple:
    out = []
    for rel in _FINGERPRINT_FILES:
        try:
            st = os.lstat(real / ".git" / rel)
            out.append((rel, st.st_ino, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append((rel, None))
    return tuple(out)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# argv builder + runner


_DIFF_LIKE = frozenset({"diff", "diff-index", "diff-files", "diff-tree", "log", "show"})


def readonly_argv(repo: Path, args: tuple[str, ...] | list[str], *, pre: tuple[str, ...] = (), flags: tuple[str, ...] | list[str] | None = None) -> list[str]:
    """The ONLY repository-bound argv: hardening pins, no replace objects, explicit git-dir AND work-tree (a repository's own core.worktree is never followed)."""
    real = Path(repo).resolve()
    args = list(args)
    sub = next((i for i, a in enumerate(args) if not a.startswith("-")), None)
    if sub is not None and args[sub] in _DIFF_LIKE:  # an external diff / textconv program can never run (diff.external cannot be pinned to "": git would try to exec it)
        args[sub + 1:sub + 1] = ["--no-ext-diff", "--no-textconv"]
    return ["git", "--no-pager", "--no-replace-objects", *pre, *(_HARDEN if flags is None else flags), "-C", str(real),
            "--git-dir", str(real / ".git"), "--work-tree", str(real), *args]


def run_readonly(repo: Path, args: tuple[str, ...], *, input_bytes: bytes | None = None, timeout: float = TIMEOUT, deep: bool = False,
                 extra_env: dict[str, str] | None = None) -> bytes:
    """vet -> run (timeout) -> re-fingerprint. Raises GitReadError (HostIntegrityError) on a refusal, a failing command, a timeout, or a repository that changed during the read."""
    real = Path(repo).resolve()
    why = vet_repository(real, deep=deep)
    if why is not None:
        raise GitReadError(GitReadErrorKind.REPOSITORY_REFUSED, f"refusing repository ({why})")
    before = _fingerprint(real)
    tmp_index: str | None = None
    if args and args[0] == "diff":  # porcelain diff refreshes (REWRITES) the index even with GIT_OPTIONAL_LOCKS=0: give it a private copy, the target's index is never written
        tmp_index = tempfile.mkdtemp(prefix="hlith-ro-index-")
        src_index = real / ".git" / "index"
        if src_index.is_file():
            shutil.copy2(src_index, os.path.join(tmp_index, "index"))
        extra_env = {**(extra_env or {}), "GIT_INDEX_FILE": os.path.join(tmp_index, "index")}
    argv = readonly_argv(real, args)
    try:
        cp = _spawn(argv, input_bytes=input_bytes, env=scrubbed_git_env(real.parent, extra_env), timeout=timeout)
    finally:
        if tmp_index is not None:
            shutil.rmtree(tmp_index, ignore_errors=True)
    if _fingerprint(real) != before:
        raise GitReadError(
            GitReadErrorKind.CONCURRENT_MUTATION,
            "refusing result: the repository's config or HEAD changed while it was being read",
        )
    if cp.returncode != 0:
        raise _classify_git_failure(argv, cp.returncode, cp.stderr)
    return cp.stdout


def _run_ro(repo: Path, args: tuple[str, ...], *, input_bytes: bytes | None = None) -> bytes:
    """Back-compat name for ``run_readonly`` (every call vets)."""
    return run_readonly(repo, tuple(args), input_bytes=input_bytes)


def safe_git_read(repo: Path, *args: str) -> str:
    """ONE hardened read-only Git command for an operator surface that must not execute repository-controlled code (see module doc)."""
    return run_readonly(Path(repo), tuple(args), deep=True).decode("utf-8", "replace").strip()


def _unsafe_component(part: str) -> bool:
    return part in ("", ".", "..") or part.casefold() == ".git"


def _safe_export_path(dest: Path, rel: str) -> Path:
    parts = rel.split("/")
    if any(c in _BAD_NAME_CHARS for c in rel) or any(_unsafe_component(p) for p in parts):
        raise HostIntegrityError(f"unsafe path in tree: {rel!r}")
    cur = dest
    for part in parts[:-1]:
        cur = cur / part
        if os.path.islink(cur):
            raise HostIntegrityError(f"tree path goes through symlink: {rel!r}")
        cur.mkdir(exist_ok=True)
    return cur / parts[-1]


def _check_symlink(rel: str, link: str) -> None:
    bad = not link or any(c in link for c in "\0\\") or link.startswith("/")
    if not bad:
        norm = posixpath.normpath(posixpath.join(posixpath.dirname(rel), link))
        bad = norm == ".." or norm.startswith("../") or norm == "." or any(c.casefold() == ".git" for c in norm.split("/"))
    if bad:
        raise HostIntegrityError(f"unsafe symlink {rel!r} -> {link!r}")


class HardenedGitRead(GitRead):
    """Allowlisted read-only Git capability."""

    def repository_hostile_reason(self, repo: Path) -> str | None:
        return vet_repository(repo, deep=True)

    def head_tree(self, repo: Path) -> TreeOid:
        out = run_readonly(repo, ("rev-parse", "--verify", "HEAD^{tree}"), deep=True).decode("ascii").strip()
        return tree_oid(out)

    def export_tree(self, repo: Path, tree: TreeOid, dest: Path) -> None:
        oid = tree_oid(str(tree))
        listing = run_readonly(repo, ("ls-tree", "-r", "-l", "-z", "--full-tree", str(oid)), deep=True)
        entries: list[tuple[str, str, str, int]] = []
        total = 0
        for rec in listing.split(b"\0"):
            if not rec:
                continue
            meta, _, path_b = rec.partition(b"\t")
            mode, typ, sha, size = meta.decode("ascii").split()
            rel = path_b.decode("utf-8", "surrogateescape")
            if typ == "commit":
                raise HostIntegrityError(f"submodule at {rel!r}: refused")
            if typ != "blob":
                raise HostIntegrityError(f"unexpected tree entry type {typ!r} at {rel!r}")
            n = int(size)
            total += n
            if n > MAX_BLOB_BYTES:
                raise HostIntegrityError(f"blob {rel!r} exceeds {MAX_BLOB_BYTES} bytes")
            if total > MAX_TOTAL_BYTES or len(entries) >= MAX_ENTRIES:
                raise HostIntegrityError("tree exceeds export limits")
            entries.append((mode, sha, rel, n))
        dest.mkdir(parents=True)
        if not entries:
            return
        batch_in = "\n".join(sha for _m, sha, _r, _n in entries).encode("ascii") + b"\n"
        blob_stream = run_readonly(repo, ("cat-file", "--batch"), input_bytes=batch_in)  # the ls-tree above already ran the deep vet
        pos = 0
        for mode, sha, rel, size in entries:
            nl = blob_stream.find(b"\n", pos)
            if nl == -1:
                raise HostIntegrityError("truncated cat-file --batch header")
            header = blob_stream[pos:nl].decode("ascii", "replace")
            pos = nl + 1
            parts = header.split()
            if len(parts) != 3 or parts[0] != sha or parts[1] != "blob":
                raise HostIntegrityError(f"unexpected cat-file header {header!r} for {rel!r}")
            n = int(parts[2])
            if n != size:
                raise HostIntegrityError(f"size mismatch for {rel!r}: {n} != {size}")
            data = blob_stream[pos : pos + n]
            pos += n
            if blob_stream[pos : pos + 1] != b"\n":
                raise HostIntegrityError(f"missing trailing newline after blob {rel!r}")
            pos += 1
            out_path = _safe_export_path(dest, rel)
            if mode == "120000":
                link = data.decode("utf-8", "surrogateescape")
                _check_symlink(rel, link)
                os.symlink(link, out_path)
            else:
                out_path.write_bytes(data)
                os.chmod(out_path, 0o755 if mode == "100755" else 0o644)
