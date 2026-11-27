# SPDX-License-Identifier: Apache-2.0
"""Patch-input normalisation at the operator edge: strip ONLY the bytes before the first ``diff --git `` line.

The gate refuses any patch whose first non-empty line is not ``diff --git `` (a deliberate, strict rule). Files made by ``git
format-patch`` / ``git show`` / e-mail start with an mbox header or a commit message, which ``git apply`` itself ignores. Those bytes
are removed HERE, once, deterministically, and the removal is recorded: both digests (the file as given and the bytes that are applied)
and the number of stripped bytes. Nothing after the first ``diff --git `` line is ever touched (a format-patch signature tail stays).
The identity chain downstream (account, verification record, gate) uses the APPLIED bytes' digest, as for any patch."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MARK = b"diff --git "


@dataclass(frozen=True)
class NormalizedPatch:
    applied: bytes
    input_sha256: str
    applied_sha256: str
    stripped_bytes: int

    def record(self) -> dict:
        return {"input_patch_sha256": self.input_sha256, "applied_patch_sha256": self.applied_sha256, "preamble_removed_bytes": self.stripped_bytes}


def normalize_patch(data: bytes) -> NormalizedPatch:
    """The patch with everything before the first line that starts ``diff --git `` removed. No such line: returned unchanged (the gate
    then refuses it with its named reason; nothing is invented here)."""
    first = -1
    if data.startswith(MARK):
        first = 0
    else:
        at = data.find(b"\n" + MARK)
        if at >= 0:
            first = at + 1
    cut = max(first, 0)
    applied = data[cut:]
    return NormalizedPatch(applied, hashlib.sha256(data).hexdigest(), hashlib.sha256(applied).hexdigest(), cut)
