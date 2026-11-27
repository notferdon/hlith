# SPDX-License-Identifier: Apache-2.0
"""Migration step M1 alias: the existing verdict types stay canonical in hlith.types until they are moved here.

The owner of this move is the L0 maintainer (design review) at assembly time: definitions move into hlith.contract, hlith.types
becomes a re-export shim, then the shim is retired after callers migrate. Until then there is ONE definition.
"""

from ..types import (  # noqa: F401
    EXIT_BOUNDARY,
    EXIT_LANDED,
    EXIT_NOT_DERIVED,
    EXIT_REFUTED,
    EXIT_UNVERIFIED,
    BoundedEvidence,
    CheckProvenance,
    GateDecision,
    GateOutcome,
    Obligation,
    ObligationSet,
    ProposedEffect,
    Verdict,
    decide,
)
