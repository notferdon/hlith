# SPDX-License-Identifier: Apache-2.0
"""Local-first offline ``HostState`` implementation.

Layout:
    ``<state_root>/repositories/<stable-repo-identity>/{feedback,runs,evidence,checkpoints,journal,cache}``

Preserves existing key locations/permissions (``<state_root>/thread-store.key``, 0600, 32 bytes)
so existing checkpoints and gate journals remain valid.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from ..contract.capabilities import HostState, KeyPurpose
from .git_read import _run_ro, _target_git_dir_violation
from .integrity import (
    HostIntegrityError,
    capture_target_identity,
    ensure_private_dir,
    read_or_create_key32,
    safe_path_component,
)

ALLOWED_NAMESPACES = frozenset({"feedback", "runs", "evidence", "checkpoints", "journal", "cache"})


def default_state_root(override: Path | None = None) -> Path:
    """Resolve the local host state root (override -> ``HLITH_STATE_DIR`` -> ``$XDG_STATE_HOME/hlith``)."""
    if override is not None:
        return Path(override)
    env_dir = os.environ.get("HLITH_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "hlith"


class LocalHostState(HostState):
    """Local-first offline host state and key provider."""

    def __init__(self, state_root: Path | None = None) -> None:
        self._root = default_state_root(state_root)
        from .confinement import LIVE_STATE_ROOTS  # every host state root (keys live there): no confinement grant may reach one

        LIVE_STATE_ROOTS.add(os.path.realpath(self._root))

    @property
    def root(self) -> Path:
        return ensure_private_dir(self._root, create=True)

    def stable_repo_identity(self, repo: Path) -> str:
        real = Path(repo).resolve()
        violation = _target_git_dir_violation(real)
        if violation is not None:
            raise HostIntegrityError(f"cannot compute stable repo identity: {violation}")
        h = hashlib.sha256()
        try:
            roots = sorted(
                line.strip()
                for line in _run_ro(real, ("rev-list", "--max-parents=0", "--all")).decode("ascii").splitlines()
                if line.strip()
            )
        except HostIntegrityError:
            roots = []
        if roots:
            h.update(b"roots:")
            h.update("\n".join(roots).encode("ascii"))
        else:
            tid = capture_target_identity(real)
            h.update(f"unborn:{tid.device}:{tid.inode}:{tid.git_dir_sha256}".encode("utf-8"))
        return safe_path_component(f"repo-{h.hexdigest()[:24]}", label="repo_identity")

    def namespace(self, repo_identity: str, name: str) -> Path:
        if name not in ALLOWED_NAMESPACES:
            raise HostIntegrityError(f"invalid host state namespace {name!r}")
        ident = safe_path_component(repo_identity, label="repo_identity")
        root = self.root
        repos_dir = ensure_private_dir(root / "repositories", create=True)
        repo_dir = ensure_private_dir(repos_dir / ident, create=True)
        return ensure_private_dir(repo_dir / name, create=True)

    def key(self, purpose: KeyPurpose) -> bytes:
        root = self.root
        if purpose is KeyPurpose.CHECKPOINT:
            return read_or_create_key32(root / "thread-store.key", create=True)
        if purpose is KeyPurpose.GATE_JOURNAL:
            dedicated = root / "gate-journal.key"
            legacy = root / "thread-store.key"
            if dedicated.exists() or dedicated.is_symlink():
                return read_or_create_key32(dedicated, create=False)
            if legacy.exists() or legacy.is_symlink():
                return read_or_create_key32(legacy, create=False)
            return read_or_create_key32(dedicated, create=True)
        if purpose is KeyPurpose.VERIFIER_ISSUE:
            return read_or_create_key32(root / "verifier-issue.key", create=True)
        raise HostIntegrityError(f"unsupported KeyPurpose: {purpose!r}")
