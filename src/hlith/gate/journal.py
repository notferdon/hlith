# SPDX-License-Identifier: Apache-2.0
"""Host-authenticated L4 landing journal & recovery under ``HostState`` ``journal/`` namespace.

Also supports reading/recovering legacy ``<git_dir>/hlith-journal.json`` journals authenticated
with ``HostState.key(KeyPurpose.GATE_JOURNAL)`` (which preserves ``thread-store.key``).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Iterator

from ..contract.capabilities import HostState, KeyPurpose
from ..hostio.integrity import HostIntegrityError, read_regular_bytes
from .git_write import run_target_git

_JOURNAL_MAX = 4 * 1024 * 1024  # read cap AND write cap: the gate never starts a landing whose journal it could not read back
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _atomic_write_text(path: Path, data: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    """Make a rename/unlink in ``directory`` durable (a crash must not lose or resurrect a journal entry)."""
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _journal_mac(key: bytes, rec: dict, git_dir: str) -> str:
    msg = json.dumps(
        {
            "b": rec["base_head"],
            "p": rec["paths"],
            "s": rec["patch_sha256"],
            "g": git_dir,
            "n": rec.get("nonce", ""),
            "i": rec.get("images"),
            # D1 / design plan writer half: the verified post tree is bound too (format 3). Only when present, so a format-2 journal
            # written before this change still authenticates (its recovery keeps the per-path image check).
            **({"t": rec["post_tree"]} if "post_tree" in rec else {}),
        },
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _target_git_dir(target: Path) -> str:
    cp = run_target_git(target, ("rev-parse", "--absolute-git-dir"))
    if cp.returncode != 0:
        raise HostIntegrityError("gate: cannot resolve target git dir")
    return str(Path(cp.stdout.decode("utf-8").strip()).resolve())


def _target_journal_key(git_dir: str) -> str:
    return hashlib.sha256(git_dir.encode("utf-8")).hexdigest()[:24]


@contextlib.contextmanager
def target_lock(target: Path, host_state: HostState, repo_identity: str) -> Iterator[None]:
    """Exclusive per-target advisory lock under ``host_state.namespace(repo_identity, 'journal')``."""
    j_dir = host_state.namespace(repo_identity, "journal")
    git_dir = _target_git_dir(target)
    lock_path = j_dir / f"landing-{_target_journal_key(git_dir)}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    tfd = None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # review design plan: the host-state lock alone does not exclude a second hlith with ANOTHER state root; the target's own
        # git dir is the one place every writer of this repository shares (always taken after the host-state lock: one order)
        tfd = os.open(Path(git_dir) / "hlith-landing.lock", flags, 0o600)
        if not stat.S_ISREG(os.fstat(tfd).st_mode):
            raise HostIntegrityError("gate: target landing lock is not a regular file")
        fcntl.flock(tfd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if tfd is not None:
                try:
                    fcntl.flock(tfd, fcntl.LOCK_UN)
                finally:
                    os.close(tfd)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def begin_journal(
    target: Path,
    host_state: HostState,
    repo_identity: str,
    *,
    base_head: str,
    paths: list[str],
    patch_sha256: str,
    images: dict[str, list[str]],
    post_tree: str | None = None,
) -> tuple[Path, Path]:
    """Write single-use nonce and MAC-authenticated journal into ``host_state.namespace(repo_identity, 'journal')``."""
    j_dir = host_state.namespace(repo_identity, "journal")
    key = host_state.key(KeyPurpose.GATE_JOURNAL)
    git_dir = _target_git_dir(target)
    tkey = _target_journal_key(git_dir)
    nonce = os.urandom(16).hex()
    nonce_path = j_dir / f"landing-{tkey}.nonce"
    journal_path = j_dir / f"landing-{tkey}.json"
    if journal_path.exists() or journal_path.is_symlink() or nonce_path.exists() or nonce_path.is_symlink():
        raise HostIntegrityError("unrecovered-journal-exists")
    rec: dict = {
        "format": 3 if post_tree else 2,
        "base_head": base_head,
        "paths": list(paths),
        "patch_sha256": patch_sha256,
        "nonce": nonce,
        "images": images,
    }
    if post_tree:
        if not _HEX40.fullmatch(post_tree):
            raise HostIntegrityError("gate: journal post_tree must be a full tree id")
        rec["post_tree"] = post_tree
    rec["mac"] = _journal_mac(key, rec, git_dir)
    data = json.dumps(rec, sort_keys=True)
    if len(data.encode("utf-8")) > _JOURNAL_MAX:
        raise HostIntegrityError(
            f"journal-too-large: this landing touches {len(paths)} paths and its journal would exceed {_JOURNAL_MAX} bytes; "
            "nothing was written (split the change)")
    _atomic_write_text(nonce_path, nonce)
    _atomic_write_text(journal_path, data)
    return journal_path, nonce_path


def clear_journal(journal_path: Path, nonce_path: Path) -> None:
    for p in (journal_path, nonce_path):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        _fsync_dir(journal_path.parent)
    except OSError:
        pass


def _verify_nonce(nonce_path: Path, nonce: object) -> bool:
    if not isinstance(nonce, str) or not _HEX32.fullmatch(nonce):
        return False
    try:
        st = os.lstat(nonce_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077) or st.st_size != 32:
            return False
        want = read_regular_bytes(nonce_path, max_bytes=64).decode("ascii")
    except (OSError, UnicodeDecodeError, HostIntegrityError):
        return False
    return hmac.compare_digest(nonce, want)


def load_verified_journal(
    target: Path,
    host_state: HostState,
    repo_identity: str,
) -> tuple[dict, Path, Path] | None:
    """Load and authenticate an in-flight journal (v2 host-state or legacy ``.git/hlith-journal.json``)."""
    j_dir = host_state.namespace(repo_identity, "journal")
    git_dir = _target_git_dir(target)
    tkey = _target_journal_key(git_dir)
    scoped_journal = j_dir / f"landing-{tkey}.json"
    scoped_nonce = j_dir / f"landing-{tkey}.nonce"
    v2_journal = j_dir / "landing.json"
    v2_nonce = j_dir / "landing.nonce"
    legacy_journal = Path(git_dir) / "hlith-journal.json"

    if scoped_journal.exists() or scoped_journal.is_symlink():
        j_path, n_path = scoped_journal, scoped_nonce
    elif v2_journal.exists() or v2_journal.is_symlink():
        j_path, n_path = v2_journal, v2_nonce
    elif legacy_journal.exists() or legacy_journal.is_symlink():
        j_path = legacy_journal
        state_root = j_dir.parent.parent.parent
        n_path = state_root / "journals" / (hashlib.sha256(git_dir.encode("utf-8")).hexdigest() + ".nonce")
    else:
        return None

    raw = read_regular_bytes(j_path, max_bytes=_JOURNAL_MAX)
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HostIntegrityError(f"gate: corrupt journal {j_path}: {exc}") from None
    if not isinstance(rec, dict):
        raise HostIntegrityError("gate: journal must be a JSON object")
    if not _HEX40.fullmatch(str(rec.get("base_head") or "")):
        raise HostIntegrityError("gate: journal invalid base_head")
    if not isinstance(rec.get("paths"), list) or not isinstance(rec.get("images"), dict):
        raise HostIntegrityError("gate: journal missing paths/images")
    if "post_tree" in rec and not _HEX40.fullmatch(str(rec.get("post_tree") or "")):
        raise HostIntegrityError("gate: journal invalid post_tree")
    if not isinstance(rec.get("patch_sha256"), str):
        raise HostIntegrityError("gate: journal missing patch_sha256 (refusing untrusted journal)")
    key = host_state.key(KeyPurpose.GATE_JOURNAL)
    want_mac = _journal_mac(key, rec, git_dir)
    got_mac = str(rec.get("mac") or "")
    if not got_mac or not hmac.compare_digest(got_mac, want_mac):
        raise HostIntegrityError("gate: journal MAC verification failed (refusing untrusted journal)")
    if not _verify_nonce(n_path, rec.get("nonce")):
        raise HostIntegrityError("gate: journal nonce mismatch or replay (refusing recovery)")
    return rec, j_path, n_path
