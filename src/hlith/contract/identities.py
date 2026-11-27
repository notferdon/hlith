# SPDX-License-Identifier: Apache-2.0
"""Canonical identities. Standard library only."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import NewType

RunId = NewType("RunId", str)
InvocationId = NewType("InvocationId", str)
ThreadId = NewType("ThreadId", str)
TreeOid = NewType("TreeOid", str)
Sha256 = NewType("Sha256", str)

_RUN = re.compile(r"^run-[0-9a-f]{12}$")
_OID = re.compile(r"^[0-9a-f]{40}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


def new_run_id() -> RunId:
    """The ENGINE coordinator is the only caller. Surfaces and threads LINK to this id; they never mint their own."""
    return RunId("run-" + secrets.token_hex(6))


def run_id(value: str) -> RunId:
    if not _RUN.fullmatch(value):
        raise ValueError(f"not a run id: {value!r}")
    return RunId(value)


def tree_oid(value: str) -> TreeOid:
    if not _OID.fullmatch(value):
        raise ValueError(f"not a git tree oid: {value!r}")
    return TreeOid(value)


def sha256_hex(value: str) -> Sha256:
    if not _SHA.fullmatch(value):
        raise ValueError(f"not a sha256 hex digest: {value!r}")
    return Sha256(value)


@dataclass(frozen=True)
class TargetIdentity:
    """Identity of the original target as captured by the coordinator before the run (device, inode, git-dir digest)."""

    device: int
    inode: int
    git_dir_sha256: str
