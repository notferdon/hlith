# SPDX-License-Identifier: Apache-2.0
"""L0 hostio core capabilities: read-only Git, sealed snapshots, local host state, and integrity primitives."""

from __future__ import annotations

from .git_read import HardenedGitRead, scrubbed_git_env
from .integrity import (
    HostIntegrityError,
    capture_target_identity,
    ensure_private_dir,
    hmac_sha256_hex,
    read_or_create_key32,
    read_regular_bytes,
    safe_path_component,
)
from .snapshot import LocalSnapshotService
from .state import ALLOWED_NAMESPACES, LocalHostState, default_state_root

__all__ = [
    "ALLOWED_NAMESPACES",
    "HardenedGitRead",
    "HostIntegrityError",
    "LocalHostState",
    "LocalSnapshotService",
    "capture_target_identity",
    "default_state_root",
    "ensure_private_dir",
    "hmac_sha256_hex",
    "read_or_create_key32",
    "read_regular_bytes",
    "safe_path_component",
    "scrubbed_git_env",
]
