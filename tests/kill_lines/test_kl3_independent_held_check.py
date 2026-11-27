"""KL3: Verdict 'held' cannot be produced without bounded evidence and an independent blind check."""
from __future__ import annotations

import pytest

from hlith.gate import decide
from hlith.types import BoundedEvidence, CheckProvenance, GateOutcome, Obligation, ObligationSet, Verdict


def test_kl3_held_requires_evidence_and_independent_blind_provenance() -> None:
    ev = BoundedEvidence(executions=1, explored="x=0", unexplored="other inputs")
    with pytest.raises(ValueError):
        Obligation("o1", "m.f", "claim", Verdict.HELD)
    with pytest.raises(ValueError):
        Obligation("o1", "m.f", "claim", Verdict.HELD, evidence=ev,
                   provenance=CheckProvenance("c", "0" * 64, False, False, "1" * 64, 0))
    with pytest.raises(ValueError):
        Obligation("o1", "m.f", "claim", Verdict.HELD, evidence=ev,
                   provenance=CheckProvenance("c", "0" * 64, True, True, "1" * 64, 0))
    with pytest.raises(ValueError):
        Obligation("o1", "m.f", "claim", Verdict.HELD, evidence=ev,
                   provenance=CheckProvenance("c", "0" * 64, True, False, "1" * 64, 1))

    # Held without account_bound=True must also refuse at the gate.
    prov = CheckProvenance("c", "0" * 64, True, False, "1" * 64, 0)
    dec = decide(ObligationSet((Obligation("o1", "m.f", "claim", Verdict.HELD, evidence=ev, provenance=prov, account_bound=False),)))
    assert dec.outcome is GateOutcome.REFUSED
