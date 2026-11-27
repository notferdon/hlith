"""Maintainer NORM 2026-11-15 (case), as executable checks on the pure decision functions:

* unconditional gate lattice: land only when EVERY obligation is independently HELD, the set is nonempty and >= 1 is account-bound;
* HARD-DEFECT monotonicity (not blanket refusal monotonicity): adding obligations to a set that holds a REFUTED / NOT_DERIVED /
  UNVERIFIED obligation never makes it land;
* O3: a hash-bound approval can never turn REFUTED / NOT_DERIVED / UNVERIFIED evidence into HELD; it only resolves the missing
  confirmation; a coverage diagnostic is never an independent HELD;
* G2 / no partial landing: an approval of delta set A never confirms A+B, and an approval of A+B never confirms A.
"""

from __future__ import annotations

import itertools

import pytest

from hlith.contract.effects import delta_set_sha256
from hlith.obligation.intent import IntentDeclaration, apply_intent
from hlith.types import (BoundedEvidence, CheckProvenance, EXIT_LANDED, EXIT_NOT_DERIVED, EXIT_REFUTED, EXIT_UNVERIFIED,
                         GateOutcome, Obligation, ObligationSet, Verdict, decide)

PROV = CheckProvenance("meta", "0" * 64, confined=True, proposer_paths_readable=False, profile_sha256="0" * 64, exit_code=0)
EV = BoundedEvidence(1, "meta explored", "meta unexplored")
NON_HELD = (Verdict.REFUTED, Verdict.NOT_DERIVED, Verdict.UNVERIFIED)
EXIT_OF = {Verdict.REFUTED: EXIT_REFUTED, Verdict.NOT_DERIVED: EXIT_NOT_DERIVED, Verdict.UNVERIFIED: EXIT_UNVERIFIED}


def ob(oid: str, verdict: Verdict, target: str = "m.f", bound: bool = True) -> Obligation:
    if verdict is Verdict.HELD:
        return Obligation(oid, target, "claim", verdict, evidence=EV, provenance=PROV, account_bound=bound)
    if verdict is Verdict.REFUTED:
        return Obligation(oid, target, "claim", verdict, witness="w", account_bound=bound)
    return Obligation(oid, target, "claim", verdict, stop_reason="s", account_bound=bound)


def lands(obs) -> bool:
    return decide(ObligationSet(tuple(obs))).outcome is GateOutcome.LANDED


# ------------------------------------------------------------------------------------------------ lattice
def test_empty_obligation_set_cannot_be_built():
    with pytest.raises(ValueError):
        ObligationSet(())


def test_all_held_and_account_bound_lands():
    d = decide(ObligationSet((ob("differential:m.f", Verdict.HELD),)))
    assert d.outcome is GateOutcome.LANDED and d.exit_status == EXIT_LANDED


def test_all_held_but_none_account_bound_refuses():
    assert not lands([ob("feedback:x", Verdict.HELD, bound=False)])


@pytest.mark.parametrize("bad", NON_HELD)
def test_one_non_held_refuses_with_its_exit_and_is_named(bad):
    d = decide(ObligationSet((ob("differential:m.f", Verdict.HELD), ob("x", bad))))
    assert d.outcome is GateOutcome.REFUSED and d.exit_status == EXIT_OF[bad] and "x" in d.blocking


def test_held_requires_confined_proposer_blind_clean_provenance():
    for bad in (dict(confined=False), dict(proposer_paths_readable=True), dict(exit_code=1)):
        p = CheckProvenance(**{**PROV.__dict__, **bad})
        with pytest.raises(ValueError):
            Obligation("o", "m.f", "c", Verdict.HELD, evidence=EV, provenance=p)


# ------------------------------------------------------------------------------------------------ hard-defect monotonicity
ALL = (Verdict.HELD, *NON_HELD)


@pytest.mark.parametrize("bad", NON_HELD)
def test_hard_defect_monotonicity_exhaustive_small(bad):
    """Every superset (up to 3 extra obligations, every verdict, bound or not) of a set with a hard defect still refuses."""
    seed = [ob("defect", bad)]
    for n in range(0, 4):
        for verdicts in itertools.product(ALL, repeat=n):
            for bounds in itertools.product((True, False), repeat=n):
                extra = [ob(f"e{i}", v, bound=b) for i, (v, b) in enumerate(zip(verdicts, bounds))]
                for order in (seed + extra, extra + seed):
                    assert not lands(order), [o.verdict for o in order]


# ------------------------------------------------------------------------------------------------ O3 intent
DELTA_A = {"id": "a", "symbol": "m.f", "kind": "behavior", "predicate": {"type": "expr", "param": "x", "expr": "x < 0"},
           "expected": {"kind": "returns_expr", "expr": "x"}}
DELTA_B = {"id": "b", "symbol": "m.g", "kind": "behavior", "predicate": {"type": "expr", "param": "y", "expr": "y < 0"},
           "expected": {"kind": "returns_expr", "expr": "y"}}


def confirmed(*deltas) -> IntentDeclaration:
    return IntentDeclaration(tuple(deltas), delta_set_sha256(list(deltas)))


@pytest.mark.parametrize("bad", NON_HELD)
@pytest.mark.parametrize("oid", ["differential:m.f", "guard-removed:m.f:2", "guard-removal-certificate:m.f:2", "unresolved-0"])
def test_confirmed_approval_never_turns_non_held_into_held(bad, oid):
    obs = [ob("signature_binding:m.f", Verdict.HELD), ob(oid, bad)]
    out = apply_intent(obs, confirmed(DELTA_A))
    got = {o.obligation_id: o.verdict for o in out}
    assert got[oid] is bad
    assert not lands(out)


@pytest.mark.parametrize("diag", ["guard-covered:m.f:2", "guard-removal-covered:m.f:2"])
def test_coverage_diagnostic_is_never_an_independent_held(diag):
    # confirmed approval, but the differential of the same target is NOT held -> the diagnostic is demoted
    out = apply_intent([ob(diag, Verdict.HELD), ob("differential:m.f", Verdict.UNVERIFIED)], confirmed(DELTA_A))
    assert {o.obligation_id: o.verdict for o in out}[diag] is Verdict.UNVERIFIED and not lands(out)
    # held differential, but the approval does not match -> demoted as well, plus an unconfirmed obligation
    unconf = IntentDeclaration((DELTA_A,), "0" * 64)
    out2 = apply_intent([ob(diag, Verdict.HELD), ob("differential:m.f", Verdict.HELD)], unconf)
    v2 = {o.obligation_id: o.verdict for o in out2}
    assert v2[diag] is Verdict.UNVERIFIED and v2["deltas-confirmed"] is Verdict.UNVERIFIED and not lands(out2)


def test_missing_approval_is_an_unverified_confirmation_not_a_pass():
    out = apply_intent([ob("differential:m.f", Verdict.HELD)], IntentDeclaration((DELTA_A,), None))
    assert {o.obligation_id: o.verdict for o in out}["deltas-confirmed"] is Verdict.UNVERIFIED and not lands(out)


# ------------------------------------------------------------------------------------------------ G2: no partial landing
def test_approval_of_a_subset_never_confirms_the_superset_and_vice_versa():
    sha_a, sha_ab = delta_set_sha256([DELTA_A]), delta_set_sha256([DELTA_A, DELTA_B])
    assert sha_a != sha_ab
    assert not IntentDeclaration((DELTA_A, DELTA_B), sha_a).confirmation().matched
    assert not IntentDeclaration((DELTA_A,), sha_ab).confirmation().matched
    assert IntentDeclaration((DELTA_A, DELTA_B), sha_ab).confirmation().matched  # positive control
