# SPDX-License-Identifier: Apache-2.0
"""Leaf module: the input-origin enum shared by the store and the schema check (no imports from either)."""

from __future__ import annotations

import enum


class InputOrigin(str, enum.Enum):
    """Where the proposed change came from. A supplied patch is NEVER presented as an observed agent run (E1)."""

    AGENT_RUN = "agent-run"  # a confined local agent/worker produced the change under L1
    SUPPLIED_PATCH = "supplied-patch"  # companion or headless ingestion of an externally produced patch
    UNKNOWN = "unknown"  # legacy / unrecorded
