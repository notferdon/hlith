# SPDX-License-Identifier: Apache-2.0
"""Host-side integrity, private-directory, regular-file, and identity primitives."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path

from ..contract.codec import canonical_bytes
from ..contract.identities import TargetIdentity

_SAFE_COMP = re.compile(r"^[A-Za-z0-9._-]+$")


class HostIntegrityError(RuntimeError):
    """Raised when a host state directory, key file, or repository fails integrity checks."""


def safe_path_component(value: str, *, label: str = "component") -> str:
    """Validate a single path component (no slashes, NULs, or '..')."""
    if not value or value in {".", ".."} or not _SAFE_COMP.fullmatch(value):
        raise HostIntegrityError(f"unsafe {label}: {value!r}")
    return value


def ensure_private_dir(path: Path, *, create: bool = True) -> Path:
    """Require ``path`` (and existing parents on creation) to be a real directory owned by uid with mode 0700."""
    uid = os.getuid()
    if path.exists() or path.is_symlink():
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise HostIntegrityError(f"hostio: {path} is not a real directory")
        if st.st_uid != uid:
            raise HostIntegrityError(f"hostio: {path} is not owned by current user")
        if st.st_mode & 0o077:
            raise HostIntegrityError(f"hostio: {path} permissions must be 0700 (no group/other access); fix: chmod 700 {path}")
        return path
    if not create:
        raise HostIntegrityError(f"hostio: private directory missing: {path}")
    for ancestor in reversed((path, *path.parents)):
        if ancestor.exists() or ancestor.is_symlink():
            st = os.lstat(ancestor)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise HostIntegrityError(f"hostio: ancestor {ancestor} is not a real directory")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return ensure_private_dir(path, create=False)


def read_regular_bytes(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    """Read a regular non-symlink file using ``O_NOFOLLOW``.

    The type and size are re-checked on the OPENED descriptor (``O_NONBLOCK``, so a path swapped for a FIFO after the ``lstat`` cannot
    block the gate), every OS error is a named ``HostIntegrityError``, and the cap is enforced on the bytes actually read."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise HostIntegrityError(f"hostio: cannot read {path}: {exc}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise HostIntegrityError(f"hostio: {path} is not a regular file")
    if st.st_size > max_bytes:
        raise HostIntegrityError(f"hostio: {path} exceeds max_bytes={max_bytes}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise HostIntegrityError(f"hostio: cannot read {path}: {exc}") from None
    try:
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise HostIntegrityError(f"hostio: {path} is not a regular file")
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise HostIntegrityError(f"hostio: cannot read {path}: {exc}") from None
    if len(data) > max_bytes:
        raise HostIntegrityError(f"hostio: {path} exceeds max_bytes={max_bytes}")
    return data


def read_or_create_key32(key_path: Path, *, create: bool = True) -> bytes:
    """Read a 32-byte 0600 regular key file; create atomically with first-writer-wins if absent."""
    uid = os.getuid()
    if not key_path.exists() and not key_path.is_symlink():
        if not create:
            raise HostIntegrityError(f"hostio: key {key_path} is missing")
        tmp = key_path.parent / f".key.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, os.urandom(32))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, key_path)
        except FileExistsError:
            pass
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    st = os.lstat(key_path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or (st.st_mode & 0o077) or st.st_size != 32:
        raise HostIntegrityError(f"hostio: {key_path} must be a 32-byte regular file owned by user with mode 0600")
    data = read_regular_bytes(key_path, max_bytes=32)
    if len(data) != 32:
        raise HostIntegrityError(f"hostio: {key_path} length is {len(data)}, expected 32")
    return data


def hmac_sha256_hex(key: bytes, payload: object) -> str:
    """Compute HMAC-SHA256 hex digest over canonical contract bytes."""
    return hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()


def capture_target_identity(repo: Path) -> TargetIdentity:
    """Capture ``TargetIdentity(device, inode, git_dir_sha256)`` of ``repo/.git`` without modifying it."""
    real = Path(repo).resolve()
    git_dir = real / ".git"
    st = os.lstat(git_dir)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise HostIntegrityError(f"hostio: {git_dir} is not a real .git directory")
    h = hashlib.sha256()
    for name in ("HEAD", "config"):
        cand = git_dir / name
        if cand.exists():
            h.update(name.encode("utf-8"))
            h.update(read_regular_bytes(cand, max_bytes=1024 * 1024))
    return TargetIdentity(device=int(st.st_dev), inode=int(st.st_ino), git_dir_sha256=h.hexdigest())
