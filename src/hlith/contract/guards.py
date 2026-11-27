# SPDX-License-Identifier: Apache-2.0
"""L0 contract types for host-authenticated exported pre-guard continuity.

Pure data types and invariants only: no I/O, no Git, no subprocess, no sandbox.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .identities import RunId, Sha256, TreeOid, run_id as validate_run_id, sha256_hex, tree_oid as validate_tree_oid

MAX_CATALOG_RUN_DIRS = 256
MAX_CATALOG_ENTRIES = 32
MAX_GUARD_BYTES = 1024 * 1024  # 1 MiB per canonical exported guard
MAX_CATALOG_TOTAL_BYTES = 8 * 1024 * 1024  # 8 MiB total across all entries


@dataclass(frozen=True)
class AuthenticatedExportedGuard:
    """One host-authenticated canonical ``--expect pre`` guard regenerated from a prior FINISHED REFUTED run."""

    source_run_id: RunId
    source_obligation_id: str
    base_tree_oid: TreeOid
    base_commit: str
    post_tree_oid: TreeOid
    target_symbol: str
    module: str
    qualname: str
    import_root: str
    expect: str
    canonical_sha256: Sha256
    canonical_bytes: bytes
    witness_call_json: str

    def __post_init__(self) -> None:
        validate_run_id(str(self.source_run_id))
        validate_tree_oid(str(self.base_tree_oid))
        validate_tree_oid(str(self.post_tree_oid))
        sha256_hex(str(self.canonical_sha256))
        if self.expect != "pre":
            raise ValueError(f"exported guard continuity supports expect='pre' only, got {self.expect!r}")
        if not isinstance(self.source_obligation_id, str) or not self.source_obligation_id.strip():
            raise ValueError("source_obligation_id must be a non-empty string")
        if not isinstance(self.module, str) or not self.module or not isinstance(self.qualname, str) or not self.qualname:
            raise ValueError("module and qualname must be non-empty strings")
        if self.target_symbol != f"{self.module}.{self.qualname}":
            raise ValueError(f"target_symbol {self.target_symbol!r} does not match {self.module}.{self.qualname}")
        if not isinstance(self.import_root, str):
            raise ValueError("import_root must be a string")
        if not isinstance(self.base_commit, str) or not self.base_commit:
            raise ValueError("base_commit must be a non-empty string")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes must be bytes")
        if not (0 < len(self.canonical_bytes) <= MAX_GUARD_BYTES):
            raise ValueError(f"canonical_bytes length must be in 1..{MAX_GUARD_BYTES}")
        actual = hashlib.sha256(self.canonical_bytes).hexdigest()
        if actual != str(self.canonical_sha256).lower():
            raise ValueError("canonical_sha256 does not match canonical_bytes")
        if not isinstance(self.witness_call_json, str) or not self.witness_call_json:
            raise ValueError("witness_call_json must be a non-empty JSON string")

    def witness_call_dict(self) -> dict[str, Any]:
        """Return a fresh copy of the recorded witness_call dict (plain data)."""
        loaded = json.loads(self.witness_call_json)
        if not isinstance(loaded, dict):
            raise ValueError("witness_call_json did not decode to an object")
        return loaded


@dataclass(frozen=True)
class ExportedGuardCatalog:
    """Bounded, read-only catalog of host-authenticated canonical ``--expect pre`` guards for one repo/base tree."""

    repo_identity: str = ""
    base_tree_oid: TreeOid | None = None
    entries: tuple[AuthenticatedExportedGuard, ...] = ()

    def __post_init__(self) -> None:
        if self.base_tree_oid is not None:
            validate_tree_oid(str(self.base_tree_oid))
        if len(self.entries) > MAX_CATALOG_ENTRIES:
            raise ValueError(f"catalog exceeds maximum entries ({MAX_CATALOG_ENTRIES})")
        total = 0
        seen: set[str] = set()
        for entry in self.entries:
            if not isinstance(entry, AuthenticatedExportedGuard):
                raise TypeError("catalog entries must be AuthenticatedExportedGuard")
            if self.base_tree_oid is not None and entry.base_tree_oid != self.base_tree_oid:
                raise ValueError("catalog entry base_tree_oid mismatches catalog base_tree_oid")
            digest = str(entry.canonical_sha256).lower()
            if digest in seen:
                raise ValueError(f"duplicate canonical_sha256 in catalog: {digest}")
            seen.add(digest)
            total += len(entry.canonical_bytes)
            if total > MAX_CATALOG_TOTAL_BYTES:
                raise ValueError(f"catalog exceeds maximum total bytes ({MAX_CATALOG_TOTAL_BYTES})")

    def match_bytes(self, raw: bytes) -> AuthenticatedExportedGuard | None:
        """Exact SHA-256 and exact byte equality lookup against host-authenticated canonical bytes."""
        if not isinstance(raw, bytes) or not (0 < len(raw) <= MAX_GUARD_BYTES) or not self.entries:
            return None
        digest = hashlib.sha256(raw).hexdigest()
        for entry in self.entries:
            if str(entry.canonical_sha256).lower() == digest and entry.canonical_bytes == raw:
                return entry
        return None


EMPTY_GUARD_CATALOG = ExportedGuardCatalog()

__all__ = [
    "AuthenticatedExportedGuard",
    "EMPTY_GUARD_CATALOG",
    "ExportedGuardCatalog",
    "MAX_CATALOG_ENTRIES",
    "MAX_CATALOG_RUN_DIRS",
    "MAX_CATALOG_TOTAL_BYTES",
    "MAX_GUARD_BYTES",
]
