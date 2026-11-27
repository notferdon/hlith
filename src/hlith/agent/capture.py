# SPDX-License-Identifier: Apache-2.0
"""Stage capture, scanning, diffing, manifest parsing, and reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

from ..delta_predicate import validate_expr
from ..contract.capabilities import GitRead, SnapshotService
from ..contract.effects import DeclaredEffects, DeltaEffect, canonical_delta_set, delta_set_sha256
from ..contract.legacy import ProposedEffect
from .errors import EffectRejected, RuntimeBoundary

# Redirect to hostio.confinement when design note lands.
from ..hostio.confinement import _MAX_GRANT_ENTRIES, _vet_tree

MAX_EFFECT_BYTES = 32 * 1024 * 1024  # stage bytes after the run; host has little free memory
MAX_EFFECT_ENTRIES = 100_000
MAX_STAGE_DEPTH = 64
MAX_REL_PATH_BYTES = 3000  # below PATH_MAX (4096) so git/apply on the target never overflows
_FORBIDDEN_COMPONENTS = {".git", ".hlith"}
_CONTENT_KINDS = frozenset({"add", "modify", "delete"})
_KIND_VOCAB = frozenset({"add", "modify", "delete", "mode", "symlink", "binary"})
MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_PATHS = 10_000

DELTA_KINDS = frozenset({"behavior", "signature", "exception", "side-effect"})
DELTA_TYPED_CLASSES = frozenset({
    "empty_str",
    "none",
    "int_zero",
    "int_neg",
    "int_nonneg",
    "str_nonempty",
    "empty_container",
    "mapping_key_absent",
    "bool",
})
MAX_DELTAS = 200
MAX_LITERAL_INPUTS = 50
MAX_EXPR_LEN = 256
_DELTA_KEYS = {"id", "symbol", "kind", "claim", "input_domain", "pre", "post"}
_DELTA_OPTIONAL = {"predicate", "expected"}


@dataclass(frozen=True)
class WorkerRun:
    effect: ProposedEffect
    base_tree: str  # target HEAD tree the stage was cut from
    target_tree_before: str  # content digest of the target working tree
    target_tree_after: str
    profile_sha256: str
    worker_returncode: int
    worker_stdout: str
    worker_stderr: str
    ignored_paths: tuple[str, ...]
    skipped_paths: tuple[str, ...] = ()  # fifo/socket/device in the stage: not representable, not in the effect
    observed: tuple["ObservedChange", ...] = ()
    manifest: "DeclaredEffects | None" = None  # proposer's own claim (B)
    manifest_error: str | None = None
    authenticated_manifest: dict | None = None  # populated only after a captured effect's checkpoint MAC is verified
    graph: object = None  # Layer 1 (--layer1 langgraph): live GraphInfo session until .close()
    risk_flags: tuple[str, ...] = ()  # symlink:, mode-change:, binary: entries in the effect, for reviewers/checkers

    @property
    def target_untouched(self) -> bool:
        return self.target_tree_before == self.target_tree_after


def _git_bin() -> str:
    return shutil.which("git") or "/usr/bin/git"


def _scrubbed_git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _git(cwd: Path | None, *args: str, env: dict | None = None, stdin: str | None = None) -> str:
    """Scratch-repo git runner (never imports L4 gitsafe; target queries use GitRead when provided)."""
    data = None if stdin is None else stdin.encode("utf-8", "surrogateescape")
    git = _git_bin()
    if cwd is not None:
        if env is not None:
            raise RuntimeBoundary("git: a repository-bound call never takes a caller environment")
        cmd = [git, "-C", str(cwd), *args]
        run_env = _scrubbed_git_env()
    elif env is not None:
        cmd = [git, *args]
        run_env = env
    else:
        cmd = [git, "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", *args]  # only a LOCAL path may be fetched (the target was vetted first)
        run_env = _scrubbed_git_env()
    try:
        cp = subprocess.run(cmd, input=data, capture_output=True, env=run_env, cwd="/" if cwd is None else None)
    except OSError as e:
        raise RuntimeBoundary(f"git {' '.join(args)}: {e}") from None
    if cp.returncode != 0:
        raise RuntimeBoundary(f"git {' '.join(args)}: {cp.stderr.decode('utf-8', 'replace').strip()}")
    return cp.stdout.decode("utf-8", "surrogateescape")


def worktree_digest(root: Path) -> str:
    """Digest of every path under root, including .git, by mode/size/mtime/content."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = Path(dirpath, name)
            st = p.lstat()
            h.update(f"{p.relative_to(root)}:{st.st_mode}:{st.st_size}:{st.st_mtime_ns}\0".encode())
            if p.is_file() and not p.is_symlink():
                h.update(p.read_bytes())
    return h.hexdigest()


def _materialise(
    target: Path,
    stage: Path,
    *,
    git_read: GitRead | None = None,
    snapshot_service: SnapshotService | None = None,
) -> None:
    """Clean export of HEAD into ``stage`` (no .git, .gitattributes export-ignore not honoured)."""
    if snapshot_service is not None:
        from ..hostio.snapshot_release import release_snapshots

        snap = snapshot_service.seal_base(target)
        try:
            shutil.copytree(snap.path, stage, symlinks=True, dirs_exist_ok=True)
        finally:
            release_snapshots(snapshot_service, snap)
        return
    if git_read is not None:
        tree_oid = git_read.head_tree(target)
        tmp = stage / ".hlith-export"
        stage.mkdir(parents=True, exist_ok=True)
        git_read.export_tree(target, tree_oid, tmp)
        for child in tmp.iterdir():
            child.rename(stage / child.name)
        tmp.rmdir()
        return
    from ..hostio.export import ExportError, export_tree

    tmp = stage / ".hlith-export"
    stage.mkdir(parents=True, exist_ok=True)
    try:
        export_tree(target, "HEAD", tmp)
    except ExportError as e:
        raise RuntimeBoundary(str(e)) from e
    for child in tmp.iterdir():
        child.rename(stage / child.name)
    tmp.rmdir()


def _reject_special_files(paths) -> None:
    """Compat entry point: applies confinement grant vetting. Raises RuntimeBoundary."""
    budget = [_MAX_GRANT_ENTRIES]
    for root in paths:
        try:
            _vet_tree(str(root), budget)
        except FileNotFoundError:
            continue
        except Exception as e:  # noqa: BLE001
            raise RuntimeBoundary(str(e)) from e


@dataclass(frozen=True)
class StageScan:
    skipped: tuple[str, ...]
    non_utf8: tuple[str, ...]


def _scan_stage(stage: Path, max_bytes: int, max_entries: int) -> StageScan:
    """Iterative, fd-relative, lstat-only walk: immune to PATH_MAX and never follows or opens
    anything but regular files (O_NOFOLLOW|O_NONBLOCK)."""
    total = entries = 0
    skipped: list[str] = []
    non_utf8: list[str] = []
    root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    work: list[tuple[int, str, int]] = [(root_fd, "", 0)]
    try:
        while work:
            dfd, rel_dir, depth = work.pop()
            try:
                with os.scandir(dfd) as it:
                    names = sorted(e.name for e in it)
                for name in names:
                    rel = f"{rel_dir}/{name}" if rel_dir else name
                    entries += 1
                    if entries > max_entries:
                        raise EffectRejected(f"stage has more than {max_entries} entries")
                    if name.lower() in _FORBIDDEN_COMPONENTS:
                        raise EffectRejected(f"stage contains reserved path component {name!r}: {rel}")
                    try:
                        os.fsencode(name).decode("utf-8")
                    except UnicodeDecodeError:
                        raise EffectRejected(f"stage path is not valid UTF-8: {rel.encode('utf-8', 'surrogateescape')!r}")
                    if depth + 1 > MAX_STAGE_DEPTH or len(os.fsencode(rel)) > MAX_REL_PATH_BYTES:
                        raise EffectRejected(
                            f"stage path too deep or too long (>{MAX_STAGE_DEPTH} levels / {MAX_REL_PATH_BYTES} bytes)"
                        )
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        work.append(
                            (os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd), rel, depth + 1)
                        )
                    elif stat.S_ISREG(st.st_mode):
                        total += st.st_size
                        if total > max_bytes:
                            raise EffectRejected(f"stage exceeds {max_bytes} bytes")
                        try:
                            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                        except OSError as e:
                            raise EffectRejected(f"stage file is unreadable: {rel}: {e.strerror}") from e
                        try:
                            data = os.read(fd, st.st_size + 1) if st.st_size else b""
                        except OSError as e:
                            raise EffectRejected(f"stage file is unreadable: {rel}: {e.strerror}") from e
                        finally:
                            os.close(fd)
                        try:
                            data.decode("utf-8")
                        except UnicodeDecodeError:
                            non_utf8.append(rel)
                    elif not stat.S_ISLNK(st.st_mode):
                        skipped.append(rel)
            finally:
                if dfd != root_fd:
                    os.close(dfd)
    finally:
        for fd, _, _ in work:
            if fd != root_fd:
                os.close(fd)
        os.close(root_fd)
    return StageScan(tuple(sorted(skipped)), tuple(sorted(non_utf8)))


@dataclass(frozen=True)
class ObservedChange:
    """What the stage actually did to one path, from git's own raw diff."""

    path: str
    kinds: frozenset[str]


def _observed(raw: str, numstat: str) -> tuple[ObservedChange, ...]:
    kinds: dict[str, set[str]] = {}
    toks = raw.split("\0")
    i = 0
    while i + 1 < len(toks) and toks[i].startswith(":"):
        om, nm, _, _, st = toks[i][1:].split()[0:5]
        path = toks[i + 1]
        k = kinds.setdefault(path, set())
        k.add({"A": "add", "D": "delete"}.get(st[0], "modify"))
        if "120000" in (om, nm):
            k.add("symlink")
        elif om != nm and "000000" not in (om, nm):
            k.add("mode")
        i += 2
    for rec in numstat.split("\0"):
        if rec.startswith("-\t-\t"):
            kinds.setdefault(rec[4:], set()).add("binary")
    return tuple(ObservedChange(p, frozenset(k)) for p, k in sorted(kinds.items()))


# DeclaredEffects is defined in hlith.contract.effects and re-exported here


@dataclass(frozen=True)
class Reconciliation:
    declared_available: bool
    undeclared_files: tuple[str, ...]
    undeclared_changes: tuple[tuple[str, str], ...]
    declared_unobserved: tuple[str, ...]
    manifest_required: bool = False
    manifest_available: bool = True
    manifest_error: str | None = None
    manifest_undeclared_files: tuple[str, ...] = ()
    manifest_undeclared_changes: tuple[tuple[str, str], ...] = ()
    manifest_claimed_unobserved: tuple[str, ...] = ()
    account_error: str | None = None

    @property
    def refuting(self) -> bool:
        return bool(
            (self.declared_available and (self.undeclared_files or self.undeclared_changes))
            or (self.manifest_available and (self.manifest_undeclared_files or self.manifest_undeclared_changes))
        )

    @property
    def missing_sources(self) -> tuple[str, ...]:
        m = []
        if not self.declared_available:
            m.append(f"effect-account declaration ({self.account_error})" if self.account_error else "effect-account declaration")
        if self.manifest_required and not self.manifest_available:
            m.append(f"proposer manifest ({self.manifest_error or 'absent'})")
        return tuple(m)

    @property
    def manifest_blocked(self) -> bool:
        return self.manifest_required and not self.manifest_available and not self.refuting

    @property
    def incident(self) -> bool:
        return self.refuting or bool(self.missing_sources)

    @property
    def not_modelled_files(self) -> tuple[str, ...]:
        return self.undeclared_files if self.declared_available else ()

    @property
    def claim_violations(self) -> tuple[str, ...]:
        parts = [f"undeclared by account: {k} on {p}" for p, k in self.undeclared_changes if self.declared_available]
        if self.manifest_available:
            parts += [f"undeclared by manifest: file {p}" for p in self.manifest_undeclared_files]
            parts += [f"undeclared by manifest: {k} on {p}" for p, k in self.manifest_undeclared_changes]
        return tuple(parts)

    def witness(self) -> str:
        parts = [f"undeclared by account: file {p}" for p in self.undeclared_files if self.declared_available]
        parts += [f"undeclared by account: {k} on {p}" for p, k in self.undeclared_changes]
        parts += [f"undeclared by manifest: file {p}" for p in self.manifest_undeclared_files]
        parts += [f"undeclared by manifest: {k} on {p}" for p, k in self.manifest_undeclared_changes]
        return "; ".join(parts)


def _subset(observed, declared: DeclaredEffects):
    undeclared, bad, seen = [], [], set()
    for o in observed:
        seen.add(o.path)
        allowed = declared.paths.get(o.path)
        if allowed is None:
            undeclared.append(o.path)
            continue
        bad += [(o.path, k) for k in sorted(o.kinds - allowed)]
    return tuple(undeclared), tuple(bad), tuple(sorted(set(declared.paths) - seen))


def reconcile(
    observed: tuple[ObservedChange, ...],
    declared: DeclaredEffects | None,
    *,
    manifest: DeclaredEffects | None = None,
    manifest_error: str | None = None,
    require_manifest: bool = False,
    account_error: str | None = None,
) -> Reconciliation:
    if declared is None:
        a = (tuple(o.path for o in observed), (), ())
    else:
        a = _subset(observed, declared)
    mu: tuple = ((), (), ())
    if manifest is not None:
        mu = _subset(observed, manifest)
    return Reconciliation(
        declared is not None,
        *a,
        manifest_required=require_manifest or manifest is not None,
        manifest_available=manifest is not None,
        manifest_error=manifest_error if manifest is None else None,
        account_error=account_error,
        manifest_undeclared_files=mu[0],
        manifest_undeclared_changes=mu[1],
        manifest_claimed_unobserved=mu[2],
    )


def _check_text(name: str, v, limit: int, *, allow_empty: bool = False) -> str:
    if type(v) is not str or (not v and not allow_empty) or len(v) > limit:
        raise ValueError(f"{name}: string of 1..{limit} chars required")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        raise ValueError(f"{name}: control characters are not allowed")
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name}: not valid UTF-8 text") from None
    return v


def _check_json_value(name: str, v, depth: int = 0):
    if depth > 6:
        raise ValueError(f"{name}: nested too deeply")
    if v is None or type(v) in (bool, int):
        return
    if type(v) is float:
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"{name}: non-finite number")
        return
    if type(v) is str:
        _check_text(name, v, 1000, allow_empty=True)
        return
    if type(v) is list:
        if len(v) > 100:
            raise ValueError(f"{name}: list too long")
        for x in v:
            _check_json_value(name, x, depth + 1)
        return
    if type(v) is dict:
        if len(v) > 100:
            raise ValueError(f"{name}: object too large")
        for k, x in v.items():
            _check_text(name + ".key", k, 200, allow_empty=True)
            _check_json_value(name, x, depth + 1)
        return
    raise ValueError(f"{name}: not JSON data")


def _exact_keys(name: str, d, required: set[str], optional: set[str] = frozenset()) -> None:
    if type(d) is not dict or not all(type(k) is str for k in d):
        raise ValueError(f"{name}: object with string keys required")
    extra = set(d) - required - optional
    missing = required - set(d)
    if extra or missing:
        raise ValueError(f"{name}: unexpected keys {sorted(extra)} / missing keys {sorted(missing)}")


def validate_delta(d: dict) -> dict:
    """Strict validation of one proposer delta claim; returns the canonical dict.

    L1 checks shape, serialization, size bounds, and the shared expression grammar; L3 owns evaluation."""
    _exact_keys("delta", d, _DELTA_KEYS, _DELTA_OPTIONAL)
    out = {
        "id": _check_text("id", d["id"], 64),
        "symbol": _check_text("symbol", d["symbol"], 200),
        "kind": d["kind"],
        "claim": _check_text("claim", d["claim"], 500),
        "input_domain": _check_text("input_domain", d["input_domain"], 300, allow_empty=True),
        "pre": _check_text("pre", d["pre"], 300, allow_empty=True),
        "post": _check_text("post", d["post"], 300, allow_empty=True),
    }
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", out["id"]):
        raise ValueError("id: [A-Za-z0-9_.:-]{1,64} required")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", out["symbol"]):
        raise ValueError("symbol: dotted qualified name required")
    if type(out["kind"]) is not str or out["kind"] not in DELTA_KINDS:
        raise ValueError(f"kind: one of {sorted(DELTA_KINDS)}")
    has_p, has_e = "predicate" in d, "expected" in d
    if has_p != has_e:
        raise ValueError("predicate and expected must be given together (or neither: advisory delta)")
    if has_p:
        pr = d["predicate"]
        if type(pr) is not dict or type(pr.get("type")) is not str or pr.get("type") not in ("literal_inputs", "typed", "expr"):
            raise ValueError("predicate.type: literal_inputs | typed | expr")
        if pr["type"] == "literal_inputs":
            _exact_keys("predicate", pr, {"type", "inputs"})
            ins = pr["inputs"]
            if type(ins) is not list or not 1 <= len(ins) <= MAX_LITERAL_INPUTS:
                raise ValueError(f"predicate.inputs: 1..{MAX_LITERAL_INPUTS} call inputs")
            for k, ci in enumerate(ins):
                _exact_keys(f"predicate.inputs[{k}]", ci, {"args", "kwargs"})
                if type(ci["args"]) is not list or type(ci["kwargs"]) is not dict:
                    raise ValueError(f"predicate.inputs[{k}]: args list and kwargs object required")
                _check_json_value(f"predicate.inputs[{k}]", ci)
            out["predicate"] = {"type": "literal_inputs", "inputs": [{"args": c["args"], "kwargs": c["kwargs"]} for c in ins]}
        elif pr["type"] == "expr":
            _exact_keys("predicate", pr, {"type", "param", "expr"})
            if type(pr["param"]) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", pr["param"]):
                raise ValueError("predicate.param: identifier required")
            expr = _check_text("predicate.expr", pr["expr"], 400)
            _, errors = validate_expr(pr["param"], expr)
            if errors:
                raise ValueError("; ".join(errors))
            out["predicate"] = {"type": "expr", "param": pr["param"], "expr": expr}
        else:
            _exact_keys("predicate", pr, {"type", "param", "class"}, {"key"})
            if type(pr["param"]) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", pr["param"]):
                raise ValueError("predicate.param: identifier required")
            if type(pr["class"]) is not str or pr["class"] not in DELTA_TYPED_CLASSES:
                raise ValueError(f"predicate.class: one of {sorted(DELTA_TYPED_CLASSES)}")
            if (pr["class"] == "mapping_key_absent") != ("key" in pr):
                raise ValueError("predicate.key: required if and only if class is mapping_key_absent")
            out["predicate"] = {"type": "typed", "param": pr["param"], "class": pr["class"]}
            if "key" in pr:
                out["predicate"]["key"] = _check_text("predicate.key", pr["key"], 100, allow_empty=True)
        ex = d["expected"]
        if type(ex) is not dict or type(ex.get("kind")) is not str or ex.get("kind") not in ("returns", "returns_expr", "raises"):
            raise ValueError("expected.kind: returns | returns_expr | raises")
        if ex["kind"] == "returns":
            _exact_keys("expected", ex, {"kind", "value_repr"})
            out["expected"] = {"kind": "returns", "value_repr": _check_text("expected.value_repr", ex["value_repr"], 300, allow_empty=True)}
        elif ex["kind"] == "returns_expr":
            _exact_keys("expected", ex, {"kind", "expr"})
            xs = _check_text("expected.expr", ex["expr"], MAX_EXPR_LEN)
            out["expected"] = {"kind": "returns_expr", "expr": xs}
        else:
            _exact_keys("expected", ex, {"kind", "exc_type"})
            et = _check_text("expected.exc_type", ex["exc_type"], 100)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+", et):
                raise ValueError("expected.exc_type: module-qualified name required, e.g. builtins.TypeError")
            out["expected"] = {"kind": "raises", "exc_type": et}
    return out


def validate_deltas(raw) -> tuple[dict, ...]:
    if type(raw) is not list or len(raw) > MAX_DELTAS:
        raise ValueError(f"deltas: list of at most {MAX_DELTAS}")
    out = [validate_delta(d) for d in raw]
    ids = [d["id"] for d in out]
    if len(set(ids)) != len(ids):
        raise ValueError("deltas: ids must be unique")
    return tuple(sorted(out, key=lambda d: d["id"]))


def is_advisory(delta: dict) -> bool:
    return "predicate" not in delta


# canonical_delta_set, delta_set_sha256, DeltaEffect are defined in hlith.contract.effects and re-exported here


def read_manifest_full(channel: Path) -> tuple[DeclaredEffects | None, tuple[dict, ...], str | None]:
    path = channel / MANIFEST_NAME
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, (), "absent"
    except OSError as e:
        return None, (), f"unreadable: {e.strerror}"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, (), "not a regular file"
        if st.st_size > MAX_MANIFEST_BYTES:
            return None, (), "too large"
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw)
        paths = doc["paths"]
        if not isinstance(paths, dict) or not paths or len(paths) > MAX_MANIFEST_PATHS:
            return None, (), "invalid: paths must be a non-empty object"
        out: dict[str, frozenset[str]] = {}
        for k, v in paths.items():
            pp = Path(k)
            if not isinstance(k, str) or pp.is_absolute() or ".." in pp.parts or k != pp.as_posix():
                return None, (), f"invalid path {k!r}"
            if not isinstance(v, list) or not v or not all(isinstance(x, str) and x in _KIND_VOCAB for x in v):
                return None, (), f"invalid kinds for {k!r}"
            out[k] = frozenset(v)
        deltas = validate_deltas(doc.get("deltas", []))
        return DeclaredEffects(out), deltas, None
    except (ValueError, KeyError, TypeError) as e:
        msg = str(e)[:160] if isinstance(e, ValueError) else type(e).__name__
        return None, (), f"invalid: {msg}"


def read_manifest_document(channel: Path) -> dict | None:
    """Return the raw authenticated JSON document for host policy, preserving invalid delta claims.

    The caller must establish checkpoint authentication before using this for authorization. This reader
    enforces the same regular-file, no-follow, and size bounds as ``read_manifest_full``.
    """
    path = channel / MANIFEST_NAME
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RuntimeBoundary(f"manifest unreadable: {e.strerror}") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeBoundary("manifest is not a regular file")
        if st.st_size > MAX_MANIFEST_BYTES:
            raise RuntimeBoundary("manifest too large")
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeBoundary("manifest too large")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise RuntimeBoundary("manifest is not valid JSON") from e
    if not isinstance(doc, dict):
        raise RuntimeBoundary("manifest is not a JSON object")
    return doc


def read_manifest(channel: Path) -> tuple[DeclaredEffects | None, str | None]:
    m, _deltas, err = read_manifest_full(channel)
    return m, err


def _risk_flags(raw: str, numstat: str) -> tuple[str, ...]:
    flags: list[str] = []
    toks = raw.split("\0")
    i = 0
    while i + 1 < len(toks) and toks[i].startswith(":"):
        om, nm = toks[i][1:].split()[0:2]
        path = toks[i + 1]
        if "160000" in (om, nm):
            raise EffectRejected(f"effect contains a gitlink/submodule entry: {path}")
        if nm == "120000" or om == "120000":
            flags.append(f"symlink:{path}")
        elif om != nm and "000000" not in (om, nm):
            flags.append(f"mode-change:{path}")
        i += 2
    for rec in numstat.split("\0"):
        if rec.startswith("-\t-\t"):
            flags.append(f"binary:{rec[4:]}")
    return tuple(flags)


def _attr_pattern(path: str) -> str:
    esc = "".join("\\" + c if c in "*?[]\\!#" else c for c in path)
    return '"/' + esc.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _diff_stage(
    target: Path, stage: Path, scratch: Path, non_utf8: tuple[str, ...] = ()
) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[ObservedChange, ...]]:
    from ..hostio.git_read import vet_repository

    refused = vet_repository(Path(target), deep=True)  # `git fetch <target>` runs upload-pack INSIDE the live target with its own config: closed-world vet first, fail closed
    if refused is not None:
        raise RuntimeBoundary(f"the target repository is refused before any git runs in it ({refused})")
    gd = scratch / "diff.git"
    _git(None, "init", "-q", "--bare", str(gd))
    _git(None, f"--git-dir={gd}", "fetch", "-q", "--depth=1", str(target), "HEAD")
    if not (gd / "FETCH_HEAD").is_file() or not (gd / "FETCH_HEAD").read_text(errors="replace").strip():
        raise RuntimeBoundary(
            "could not fetch the target's HEAD commit into the diff scratch repository"
            + (" (shallow repository)" if (target / ".git" / "shallow").exists() else "")
        )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_DIR": str(gd),
        "GIT_WORK_TREE": str(stage),
        "GIT_INDEX_FILE": str(scratch / "index"),
        "HOME": str(scratch),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    attrs = ["* -text -eol -ident -filter -working-tree-encoding"] + [f"{_attr_pattern(p)} -diff" for p in non_utf8]
    (gd / "info").mkdir(exist_ok=True)
    (gd / "info" / "attributes").write_text("\n".join(attrs) + "\n", encoding="utf-8", errors="surrogateescape")
    _git(None, "read-tree", "FETCH_HEAD", env=env)
    _git(None, "add", "-A", env=env)
    opts = ("diff", "--cached", "--no-renames", "--no-color", "--no-ext-diff", "--no-textconv")
    raw = _git(None, *opts, "--raw", "-z", "FETCH_HEAD", env=env)
    numstat = _git(None, *opts, "--numstat", "-z", "FETCH_HEAD", env=env)
    observed = _observed(raw, numstat)
    flags = _risk_flags(raw, numstat)
    diff = _git(None, *opts, "--binary", "FETCH_HEAD", env=env)
    names = _git(None, *opts, "--name-only", "-z", "FETCH_HEAD", env=env)
    touched = tuple(n for n in names.split("\0") if n)
    ign = _git(None, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", env=env)
    ignored = tuple(n for n in ign.split("\0") if n)
    return diff, touched, ignored, flags, observed


__all__ = [
    "DELTA_KINDS",
    "DELTA_TYPED_CLASSES",
    "MANIFEST_NAME",
    "MAX_DELTAS",
    "MAX_EFFECT_BYTES",
    "MAX_EFFECT_ENTRIES",
    "MAX_EXPR_LEN",
    "MAX_LITERAL_INPUTS",
    "MAX_MANIFEST_BYTES",
    "MAX_MANIFEST_PATHS",
    "MAX_REL_PATH_BYTES",
    "MAX_STAGE_DEPTH",
    "DeclaredEffects",
    "DeltaEffect",
    "EffectRejected",
    "ObservedChange",
    "Reconciliation",
    "RuntimeBoundary",
    "StageScan",
    "WorkerRun",
    "_attr_pattern",
    "_diff_stage",
    "_git",
    "_materialise",
    "_observed",
    "_reject_special_files",
    "_risk_flags",
    "_scan_stage",
    "canonical_delta_set",
    "delta_set_sha256",
    "is_advisory",
    "read_manifest",
    "read_manifest_document",
    "read_manifest_full",
    "reconcile",
    "validate_delta",
    "validate_deltas",
    "worktree_digest",
]
