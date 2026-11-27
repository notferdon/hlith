# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.proposer (moved to hlith.agent.proposer)."""

from .agent.proposer import (
    CommandProposer,
    HostSideProposerTrust,
    MockModelProposer,
    ModelProposer,
    NotConfigured,
    OperatorPatchProposer,
    Proposer,
)

__all__ = [
    "CommandProposer",
    "HostSideProposerTrust",
    "MockModelProposer",
    "ModelProposer",
    "NotConfigured",
    "OperatorPatchProposer",
    "Proposer",
]
