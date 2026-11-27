# SPDX-License-Identifier: Apache-2.0
"""The gate: the only process that writes the target repository.

NOTE: ``_legacy`` is a historical filename retained without renaming to preserve internal
imports; this module is the active Layer 4 git-write implementation backing ``hlith.gate``.

``git apply --index`` is not an atomic multi-file transaction. Landing is
therefore journaled: a pending record is made durable before the first byte is
written, and either rollback or recovery returns the tree to the base commit if
the process fails or dies half way. Recovery is idempotent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

from ..types import (
    EXIT_BOUNDARY,
    GateDecision,
    GateOutcome,
    ObligationSet,
    ProposedEffect,
    decide,
)

_ID = ["-c", "user.name=hlith", "-c", "user.email=hlith@localhost", "-c", "commit.gpgsign=false"]


# The target repo is untrusted input to the gate: its hooks and config must not run code inside the one process that holds write access.
# The vet, the hardening pins, the environment and the argv are the SINGLE choke point in hostio.git_read (closed-world config allowlist, fail-closed);
# this module keeps no policy of its own (it used to carry a third copy of the blocklist and a hand-written config parser).
from ..hostio import git_read as _ro
from ..hostio.git_read import _HARDEN, _target_git_dir_violation  # noqa: F401  (re-exported for the gate package and its callers)


def _run_git(target: Path, args: tuple[str, ...], stdin: str | None, *, index_file: str | None = None):
    # The caller's environment is not part of the target identity. In particular,
    # GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE can redirect a seemingly explicit
    # `git -C target` to different host state. Keep only the process path and a
    # deterministic, private Git configuration environment. ``index_file`` (the ONLY allowed extra) points at a
    # TEMPORARY index created by the gate itself, never one the caller or the repository supplies.
    target = Path(target).resolve()
    violation = _ro.vet_repository(target)  # closed-world, fail-closed: the writer never runs a command on a repository it could not prove safe
    if violation:
        raise RuntimeError(violation)
    env = _ro.scrubbed_git_env(None, {"GIT_INDEX_FILE": index_file} if index_file is not None else None, writer=True)
    try:
        return subprocess.run(
            _ro.readonly_argv(target, args),
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
            env=env,
            timeout=_ro.TIMEOUT * 10,  # a stuck git is a refusal, never a hang inside the one process that holds write access
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"cannot run git ({getattr(exc, 'strerror', None) or exc})") from None


from ..hostio.snapshot import _RESERVED, patch_violations


def git_reported_paths(target: Path, diff: str) -> list[str]:
    """Paths as git itself parses them (-z handles quoting); the regex view is never the only view."""
    cp = _run_git(target, ("apply", "--numstat", "-z"), diff)
    out: list[str] = []
    for tok in cp.stdout.split("\0"):
        if "\t" in tok:
            tok = tok.split("\t", 2)[2]
        if tok:
            out.append(tok)
    return out


def executable_config(target: Path) -> list[str]:
    """Repo config problems that stop the gate (closed-world vet of .git/config and config.worktree; names the offending key). Empty = clean."""
    real = Path(target).resolve()
    if (real / ".git" / "config.worktree").exists():
        return ["config.worktree"]
    why = _ro._config_file_violation(real / ".git" / "config", "config")
    return [why] if why else []


def _repository_attribute_violation(target: Path) -> str | None:
    """Kept for callers: attribute FILES are no longer scanned (a second parser Git can disagree with). Nothing can define a driver because the closed-world config vet
    refuses every filter/diff/merge/textconv definition; the effective per-path attributes are checked by _attribute_transform_violation through Git itself."""
    return None


def _submodule_exec_violation(target: Path) -> str | None:
    """Submodule git dirs under .git/modules/** and embedded nested repositories (same closed-world vet as the outer repository)."""
    real = Path(target).resolve()
    return _ro._modules_violation(real) or _ro._nested_repository_violation(real)



def _attribute_transform_violation(target: Path, paths: list[str]) -> str | None:
    """Refuse affected paths with external filter or built-in ident transforms.

    Configured filter commands are rejected by executable_config; this checks
    the effective index attributes too, including rules introduced by a patch.
    """
    if not paths:
        return None
    cp = _run_git(target, ("check-attr", "--cached", "filter", "ident", "--", *paths), None)
    if cp.returncode != 0:
        return "target-attributes-unreadable"
    for line in cp.stdout.splitlines():
        try:
            _path, attribute, value = line.rsplit(": ", 2)
        except ValueError:
            return "target-attributes-unreadable"
        if attribute == "filter" and value not in {"unspecified", "unset"}:
            return f"target-filter-attribute:{_path}:{value}"
        if attribute == "ident" and value == "set":
            return f"target-ident-attribute:{_path}"
    return None


def _git(target: Path, *args: str, stdin: str | None = None, check: bool = True) -> str:
    cp = _run_git(target, args, stdin)
    if check and cp.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {cp.stderr.strip()}")
    return cp.stdout


def target_identity(target: Path) -> tuple[int, int]:
    """(device, inode) of the resolved .git dir. Captured by the supervisor when it
    first inspects the target; land() refuses if the path now leads elsewhere.
    Content hashes cannot do this: two different repos can share a tree."""
    st = os.stat(Path(_git(Path(target).resolve(), "rev-parse", "--absolute-git-dir").strip()))
    return (st.st_dev, st.st_ino)


def head_tree(target: Path) -> str:
    return _git(target, "rev-parse", "HEAD^{tree}").strip()


def _safe_id(s: str) -> str:
    """Commit-message text from the proposer is data: no newlines, no trailer forgery."""
    return re.sub(r"[^A-Za-z0-9._:@/-]", "_", s)[:64]


def _post_apply_symlink_violation(target: Path, paths: list[str]) -> str | None:
    """Check the tree as it exists after apply, where chains through EXISTING repo symlinks are
    visible (the patch text alone cannot show them): no loops, nothing resolving outside the repo
    or into .git/.hlith."""
    root = target.resolve()
    for rel in paths:
        p = target / rel
        if not p.is_symlink():
            continue
        try:
            os.stat(p)
        except OSError as e:
            if e.errno == 40:  # ELOOP
                return f"symlink-cycle-through-existing-link:{rel}"
        real = Path(os.path.realpath(p))
        if real != root and root not in real.parents:
            return f"symlink-resolves-outside-repo:{rel}"
        if any(c.lower() in _RESERVED for c in real.relative_to(root).parts):
            return f"symlink-resolves-into-reserved:{rel}"
    return None


def landing_key(expected_tree: str, effect: ProposedEffect, obligations: ObligationSet) -> str:
    """Content address of one landing: (verified base tree, patch, verdict set). Recorded in
    the commit so a retry after a crash can recognise its own completed work."""
    ob = ";".join(f"{o.obligation_id}={o.verdict.value}" for o in sorted(obligations.obligations, key=lambda o: o.obligation_id))
    return hashlib.sha256(f"{expected_tree}|{effect.patch_sha256}|{ob}".encode()).hexdigest()


def _journal(target: Path) -> Path:
    return Path(_git(target, "rev-parse", "--absolute-git-dir").strip()) / "hlith-journal.json"


def _fsync_write(path: Path, data: str) -> None:
    """Durable publication: exclusive no-follow temp file in the same dir, fsync, atomic rename (never a truncating open of a path the
    repo controls). Concept after dulwich.file.GitFile (jelmer/dulwich 5b6e39c); no code copied."""
    tmp = path.with_name(path.name + f".{os.urandom(8).hex()}.tmp")  # unguessable: a pre-planted name cannot collide (review R4)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ---- the recovery journal is written by US but lives in a directory a repository controls: it is NOT trusted from the repo (review source
# finding, review J1-J7): a forged journal made `land` hard-reset the operator's tracked edits or force-remove untracked files. It is bound to a
# host-keyed MAC (key outside every repo), read as a regular file only, and recovery refuses (touching NOTHING) on any doubt.
_JOURNAL_MAX = 64 * 1024
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _host_journal_key(target: Path) -> tuple[bytes, Path]:
    from ..contract.capabilities import KeyPurpose
    from ..hostio.integrity import HostIntegrityError, ensure_private_dir
    from ..hostio.state import LocalHostState

    state = LocalHostState()
    root = state.root.resolve()
    t_real = Path(target).resolve()
    if root == t_real or t_real in root.parents:
        raise RuntimeError(f"gate: state directory {root} must not sit inside target {t_real}")
    try:
        key = state.key(KeyPurpose.GATE_JOURNAL)
        ensure_private_dir(root / "journals", create=True)
    except HostIntegrityError as exc:
        raise RuntimeError(str(exc)) from None
    return key, root


def _journal_mac(rec: dict, target: Path) -> str:
    import hmac

    key, _root = _host_journal_key(target)
    git_dir = str(Path(_git(target, "rev-parse", "--absolute-git-dir").strip()).resolve())
    msg = json.dumps({"b": rec["base_head"], "p": rec["paths"], "s": rec["patch_sha256"], "g": git_dir, "n": rec.get("nonce", ""),
                      "i": rec.get("images")},
                     sort_keys=True).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _nonce_file(target: Path) -> Path:
    """HOST-side single-use token for THIS repository's in-flight landing (state dir, outside the repo): a journal replayed after the
    landing completed or was recovered, or copied from an old landing, has no matching token (review R1)."""
    _key, root = _host_journal_key(target)
    d = root / "journals"
    git_dir = str(Path(_git(target, "rev-parse", "--absolute-git-dir").strip()).resolve())
    return d / (hashlib.sha256(git_dir.encode()).hexdigest() + ".nonce")


def _set_nonce(target: Path) -> str:
    nonce = os.urandom(16).hex()
    f = _nonce_file(target)
    tmp = f.with_name(f.name + f".{os.urandom(6).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, nonce.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, f)
    return nonce


def _nonce_matches(target: Path, nonce: object) -> bool:
    import hmac

    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        return False
    try:
        f = _nonce_file(target)
        st = os.lstat(f)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077) or st.st_size != 32:
            return False
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            want = os.read(fd, 64).decode()
        finally:
            os.close(fd)
    except OSError:
        return False
    return hmac.compare_digest(nonce, want)


def _path_images(target: Path, base_head: str, patch: str, paths: list[str]) -> dict:
    """{path: [pre_blob, post_blob]} ('' = absent), computed BEFORE anything is applied: pre from the base commit, post by applying the
    verified patch into a TEMPORARY index (review R5). Recovery rolls a path back only if the work tree still holds one of the two images."""
    pre: dict[str, str] = {}
    cp = _run_git(target, ("ls-tree", "-z", base_head, "--", *paths), None)
    for rec in cp.stdout.split("\0"):
        if "\t" in rec:
            meta, name = rec.split("\t", 1)
            pre[name] = meta.split()[2]
    with tempfile.TemporaryDirectory(prefix="hlith-img-") as d:  # the default temp dir (TMPDIR-aware): the choke point only accepts hlith-owned index dirs
        idx = str(Path(d) / "index")
        if _run_git(target, ("read-tree", base_head), None, index_file=idx).returncode != 0:
            raise RuntimeError("path-images: read-tree failed")
        if _run_git(target, ("apply", "--cached", "-"), patch, index_file=idx).returncode != 0:
            raise RuntimeError("path-images: the verified patch does not apply to a temporary index")
        post: dict[str, str] = {}
        ls = _run_git(target, ("ls-files", "-s", "-z", "--", *paths), None, index_file=idx)
        for rec in ls.stdout.split("\0"):
            if "\t" in rec:
                meta, name = rec.split("\t", 1)
                post[name] = meta.split()[1]
    return {p: [pre.get(p, ""), post.get(p, "")] for p in paths}


def _worktree_blob(target: Path, rel: str) -> str:
    """Blob id of what the work tree holds at ``rel`` ('' = absent), with NO filters (filters are refused by the gate anyway)."""
    full = Path(target) / rel
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        return ""
    except OSError:
        return "?"
    if stat.S_ISLNK(st.st_mode):
        cp = _run_git(target, ("hash-object", "--stdin"), os.readlink(full))
    elif stat.S_ISREG(st.st_mode):
        cp = _run_git(target, ("hash-object", "--no-filters", "--", rel), None)
    else:
        return "?"
    return cp.stdout.strip() if cp.returncode == 0 else "?"


def _finish_journal(j: Path, target: Path) -> None:
    """The landing is over (committed, rolled back, or refused): remove the journal AND the host-side token (single use)."""
    j.unlink(missing_ok=True)
    try:
        _nonce_file(target).unlink(missing_ok=True)
    except OSError:
        pass


def _journal_path_ok(p: object) -> bool:
    if not isinstance(p, str) or not p or p != p.strip():
        return False
    if p.startswith("/") or any(c in p for c in "*?[]\\\0") or p == "." or p.startswith(":"):
        return False
    parts = p.split("/")
    return all(part not in ("", ".", "..") and part.lower() not in _RESERVED for part in parts)


def _read_journal(j: Path) -> dict | None:
    """The journal as a dict, or None when it is not a genuine regular file / not valid JSON of the expected shape."""
    try:
        st = os.lstat(j)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > _JOURNAL_MAX:
        return None
    try:
        fd = os.open(j, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        raw = os.read(fd, _JOURNAL_MAX + 1)
    finally:
        os.close(fd)
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    if not isinstance(rec, dict) or not isinstance(rec.get("base_head"), str) or not _HEX40.match(rec["base_head"]):
        return None
    if not isinstance(rec.get("paths"), list) or not all(_journal_path_ok(x) for x in rec["paths"]):
        return None
    if not isinstance(rec.get("patch_sha256"), str) or not isinstance(rec.get("mac"), str) or not isinstance(rec.get("nonce"), str):
        return None
    img = rec.get("images")
    if not isinstance(img, dict) or set(img) != set(rec["paths"]) or not all(
        isinstance(v, list) and len(v) == 2 and all(isinstance(x, str) and re.fullmatch(r"([0-9a-f]{40}|[0-9a-f]{64})?", x) for x in v)
        for v in img.values()
    ):
        return None
    return rec


def _rollback(target: Path, base_head: str, paths: list[str]) -> None:
    _git(target, "reset", "-q", "--hard", base_head)
    if paths:
        _git(target, "clean", "-qfd", "--", *paths, check=False)


def recover(target: Path) -> str:
    """Resolve a half-finished landing; distinguish an unverifiable journal from repository disagreement."""
    j = _journal(target)
    if not os.path.lexists(j):
        return "none"
    rec = _read_journal(j)
    if rec is None:
        return "untrusted"  # not a regular file / malformed / oversized / unsafe paths: NOTHING is touched, nothing is deleted
    import hmac

    if not hmac.compare_digest(rec["mac"], _journal_mac(rec, target)):
        return "untrusted"  # not written by this host's gate for THIS repository: never act on it
    if not _nonce_matches(target, rec["nonce"]):
        return "untrusted"  # genuine-looking but not this repository's IN-FLIGHT landing (replayed / stale copy): never act on it
    head = _git(target, "rev-parse", "HEAD").strip()
    if head == rec["base_head"]:
        # genuine record of an interrupted landing: the tree may only differ from HEAD inside the journal's own paths
        rows = [ln for ln in _git(target, "status", "--porcelain", "--ignore-submodules=all", "-z").split("\0") if ln.strip()]
        outside = [ln[3:] for ln in rows if ln[3:] not in set(rec["paths"])]
        if outside:
            return "untrusted-state"  # the work tree holds changes this landing could not have made: do not reset it
        for rel, (pre_id, post_id) in rec["images"].items():
            if _worktree_blob(target, rel) not in (pre_id, post_id):
                return "untrusted-state"  # review R5: the operator edited a journal path after the interruption: never destroy that edit
        _rollback(target, rec["base_head"], rec["paths"])
        state = "rolled-back"
    else:
        # A changed HEAD is not proof that this journal's landing committed.
        # Reuse L4's strict predicate so a foreign commit, partial state,
        # merge, or altered post-image remains untrusted and preserves the
        # authenticated journal and nonce for operator inspection.
        from .api import _is_completed_landing

        if not _is_completed_landing(target, head, rec["base_head"], rec["paths"], rec["images"]):
            return "untrusted-state"
        state = "completed"
    _finish_journal(j, target)
    return state


def land(
    target: Path,
    effect: ProposedEffect,
    obligations: ObligationSet,
    *,
    expected_tree: str,
    verified_patch_sha256: str,
    expected_identity: tuple[int, int],
    fault: str | None = None,
) -> GateDecision:
    target = Path(target).resolve()  # pin the real path once; a later symlink swap cannot redirect us
    decision = decide(obligations)
    if decision.outcome is GateOutcome.REFUSED:
        return decision
    git_dir_violation = _target_git_dir_violation(target)
    if git_dir_violation:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (git_dir_violation,))
    if executable_config(target):
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("target-config-can-execute-programs",))
    attribute_violation = _repository_attribute_violation(target)
    if attribute_violation:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (attribute_violation,))
    submodule_violation = _submodule_exec_violation(target)
    if submodule_violation:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (submodule_violation,))
    if target_identity(target) != tuple(expected_identity):
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("target-identity-changed",))
    key = landing_key(expected_tree, effect, obligations)
    last = _git(target, "log", "-1", "--format=%B", check=False)
    trailer = _git(target, "log", "-1", "--format=%(trailers:key=Hlith-Key,valueonly,separator=%x2C)", check=False).strip()
    if key in trailer.split(","):  # already landed by this exact (tree, patch, verdicts): idempotent
        return GateDecision(GateOutcome.LANDED, decision.exit_status, (), _git(target, "rev-parse", "HEAD").strip())
    rstate = recover(target)
    if rstate == "untrusted":
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("untrusted-journal",))
    if rstate == "untrusted-state":
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("untrusted-state",))
    if rstate != "none":
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("recovered-pending-journal",))
    pv = patch_violations(effect.unified_diff)
    pv += [f"reserved-or-escaping-path:{p}" for p in git_reported_paths(target, effect.unified_diff)
           if any(c.lower() in _RESERVED for c in p.split("/")) or ".." in p.split("/") or p.startswith("/")]
    if pv:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, tuple(pv))
    if _git(target, "status", "--porcelain", "--ignore-submodules=all").strip():  # submodule changes are NOT seen (child git never started)
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("dirty-target",))
    if head_tree(target) != expected_tree:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("base-tree-changed",))
    if effect.patch_sha256 != verified_patch_sha256:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("patch-not-the-verified-patch",))
    numstat = _git(target, "apply", "--numstat", stdin=effect.unified_diff)
    paths = [ln.split("\t", 2)[2] for ln in numstat.splitlines() if ln.count("\t") >= 2]
    attribute_violation = _attribute_transform_violation(target, paths)
    if attribute_violation:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (attribute_violation,))
    check = _run_git(target, ("apply", "--check", "-"), effect.unified_diff)
    if check.returncode != 0:
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, ("patch-does-not-apply",))

    base_head = _git(target, "rev-parse", "HEAD").strip()
    j = _journal(target)
    try:
        _rec = {"base_head": base_head, "paths": paths, "patch_sha256": effect.patch_sha256, "nonce": _set_nonce(target),
                "images": _path_images(target, base_head, effect.unified_diff, paths)}
        _rec["mac"] = _journal_mac(_rec, target)
        _fsync_write(j, json.dumps(_rec))
    except (OSError, ValueError, RuntimeError) as e:  # nothing was applied yet: a journal that cannot be published is a boundary, never a crash (review R4)
        _finish_journal(j, target)
        return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (f"journal-write-failed:{type(e).__name__}:{str(e)[:200]}",))
    try:
        _git(target, "apply", "--index", "-", stdin=effect.unified_diff)
        attribute_violation = _attribute_transform_violation(target, paths)
        if attribute_violation:
            _rollback(target, base_head, paths)
            _finish_journal(j, target)
            return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (attribute_violation,))
        bad_link = _post_apply_symlink_violation(target, paths)
        if bad_link:
            _rollback(target, base_head, paths)
            _finish_journal(j, target)
            return GateDecision(GateOutcome.REFUSED, EXIT_BOUNDARY, (bad_link,))
        if fault == "raise_after_apply":
            raise RuntimeError("injected fault after apply")
        if fault == "kill_after_apply":
            os._exit(9)
        _git(target, *_ID, "commit", "-q", "--no-verify", "-m", f"hlith: land {effect.patch_sha256[:12]}\n\nproposer: {_safe_id(effect.proposer_id)}\nHlith-Key: {key}")
        new_head = _git(target, "rev-parse", "HEAD").strip()
    except BaseException:
        _rollback(target, base_head, paths)
        _finish_journal(j, target)
        raise
    _finish_journal(j, target)
    return GateDecision(GateOutcome.LANDED, decision.exit_status, (), new_head)
