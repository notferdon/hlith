# SPDX-License-Identifier: Apache-2.0
"""Agent-specific sandbox profiles and confinement adapter."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from ..hostio.confinement import GrantError, Profile, run_confined


def agent_worker_env_names() -> tuple[str, ...]:
    """The ONLY environment names a Layer 1 worker is started with: no credentials."""
    return (
        "HOME",
        "LANG",
        "PATH",
        "TMP",
        "TEMP",
        "TMPDIR",
        "HLITH_STAGE",
        "HLITH_CHANNEL",
        "HLITH_CKPT",
        "HLITH_INPUTS",
    )


def build_agent_profile(
    *,
    target_ro: Path,
    stage: Path,
    channel: Path,
    ckpt: Path,
    driver: Path,
    inputs: Path,
    ro_extras: Iterable[Path | str] = (),
) -> Profile:
    """Build the confined Profile for the L1 LangGraph worker (no network, stage/channel/ckpt rw only)."""
    ro = tuple(
        str(Path(p).resolve())
        for p in (target_ro, driver, inputs, *ro_extras)
    )
    rw = tuple(str(Path(p).resolve()) for p in (stage, channel, ckpt))
    return Profile(ro=ro, rw=rw, net=False)


def build_proposer_profile(
    *,
    scratch: Path,
    ro_paths: Iterable[Path] = (),
) -> Profile:
    """Build the confined Profile for an operator CommandProposer (no target repo, no network, scratch rw only)."""
    ro_set: set[str] = set()
    for p in ro_paths:
        resolved = Path(p).resolve()
        # Grant only the referenced path itself (never its parent directory), so a script next to a protected tree
        # cannot gain read access to sibling directories such as the target repository.
        ro_set.add(str(resolved))
    return Profile(ro=tuple(sorted(ro_set)), rw=(str(scratch.resolve()),), net=False)


__all__ = [
    "GrantError",
    "Profile",
    "run_confined",
    "agent_worker_env_names",
    "build_agent_profile",
    "build_proposer_profile",
]
