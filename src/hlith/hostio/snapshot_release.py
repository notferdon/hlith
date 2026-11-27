# SPDX-License-Identifier: Apache-2.0
"""One tiny helper for callers of a SnapshotService: release the host temp directories behind sealed snapshots on EVERY exit path.

``LocalSnapshotService`` owns the directories it creates and removes ONLY those (never an unrelated or historical ``hlith-base-*`` / ``hlith-post-*`` directory). A service
without ``release`` (a test double) is simply left alone. Releasing never raises: cleanup must not turn a refusal or a landing into a different outcome.
"""

from __future__ import annotations

from typing import Any


def release_snapshots(service: Any, *snapshots: Any) -> None:
    release = getattr(service, "release", None)
    if release is None:
        return
    for snap in snapshots:
        if snap is None:
            continue
        try:
            release(snap)
        except Exception:  # noqa: BLE001 - best effort by contract
            pass
