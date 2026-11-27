# SPDX-License-Identifier: Apache-2.0
"""Refusal taxonomy. Exit statuses are single-sourced here."""

from __future__ import annotations

import enum

EXIT_LANDED = 0
EXIT_REFUTED = 10
EXIT_NOT_DERIVED = 11
EXIT_UNVERIFIED = 12
EXIT_BOUNDARY = 4
EXIT_USAGE = 2
EXIT_INTERNAL = 3
# The engine operation completed, but its requested artifact could not be saved or copied.
EXIT_ARTIFACT_COPY = 13


class Refusal(str, enum.Enum):
    REFUTED = "refuted"
    NOT_DERIVED = "not-derived"
    UNVERIFIED = "unverified"
    BOUNDARY = "boundary"


EXIT_BY_REFUSAL = {
    Refusal.REFUTED: EXIT_REFUTED,
    Refusal.NOT_DERIVED: EXIT_NOT_DERIVED,
    Refusal.UNVERIFIED: EXIT_UNVERIFIED,
    Refusal.BOUNDARY: EXIT_BOUNDARY,
}


class BoundaryReason(str, enum.Enum):
    """Why L4 refused with exit 4 before judging obligations."""

    TARGET_IDENTITY_CHANGED = "target-identity-changed"
    BASE_TREE_MISMATCH = "base-tree-mismatch"
    POST_TREE_MISMATCH = "post-tree-mismatch"
    RECORD_INVALID = "verification-record-invalid"
    ACCOUNT_MISMATCH = "account-mismatch"
    SCOPE_UNDISCHARGED = "required-scope-undischarged"
    HOSTILE_REPOSITORY = "hostile-repository-configuration"
    JOURNAL_UNAVAILABLE = "journal-unavailable"
    CONFINEMENT_UNAVAILABLE = "host-confinement-unavailable"


class RefusalError(Exception):
    def __init__(self, refusal: Refusal, reason: str) -> None:
        super().__init__(f"{refusal.value}: {reason}")
        self.refusal = refusal
        self.reason = reason
