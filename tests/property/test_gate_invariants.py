"""Gate property tests (Hlith.md s5.6 + monotonicity, patch/base identity, account-binding scope)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hlith.gate import decide, head_tree, land, target_identity
from hlith.runtime import ProposedEffect
from hlith.types import (
    EXIT_BOUNDARY,
    EXIT_NOT_DERIVED,
    BoundedEvidence,
    CheckProvenance,
    GateOutcome,
    Obligation,
    ObligationSet,
    Verdict,
)


def _good_prov(*, confined: bool = True, proposer_readable: bool = False, exit_code: int = 0) -> CheckProvenance:
    return CheckProvenance("checker", "a" * 64, confined, proposer_readable, "b" * 64, exit_code)


def _good_ev() -> BoundedEvidence:
    return BoundedEvidence(executions=1, explored="domain", unexplored="open scope")


def _held_ob(oid: str = "o1", *, account_bound: bool = True) -> Obligation:
    return Obligation(oid, "m.f", "claim", Verdict.HELD, evidence=_good_ev(), provenance=_good_prov(),
                      account_bound=account_bound)


@st.composite
def _non_held_obligation(draw) -> Obligation:
    v = draw(st.sampled_from([Verdict.REFUTED, Verdict.NOT_DERIVED, Verdict.UNVERIFIED]))
    if v is Verdict.REFUTED:
        return Obligation("o_bad", "m.f", "claim", v, witness="m.f(0): diverged")
    return Obligation("o_bad", "m.f", "claim", v, stop_reason="blocked")


def test_prop1_non_empty_obligation_set_invariant() -> None:
    """Hlith.md 5.6 (1): Constructing ObligationSet(()) raises ValueError."""
    with pytest.raises(ValueError, match="Empty obligation set is forbidden"):
        ObligationSet(())


@given(
    prefix=st.lists(st.booleans(), min_size=0, max_size=3),
    bad=_non_held_obligation(),
    suffix=st.lists(st.booleans(), min_size=0, max_size=3),
)
@settings(max_examples=30)
def test_prop2_any_non_held_refuses(prefix: list[bool], bad: Obligation, suffix: list[bool]) -> None:
    """Hlith.md 5.6 (2): Any non-HELD obligation forces GateOutcome.REFUSED."""
    obs = [_held_ob(f"p{i}", account_bound=b) for i, b in enumerate(prefix)] + [bad] + [
        _held_ob(f"s{i}", account_bound=b) for i, b in enumerate(suffix)
    ]
    dec = decide(ObligationSet(tuple(obs)))
    assert dec.outcome is GateOutcome.REFUSED
    assert dec.exit_status in (10, 11, 12)


@given(
    missing_ev=st.booleans(),
    missing_prov=st.booleans(),
    confined=st.booleans(),
    proposer_readable=st.booleans(),
    exit_code=st.integers(min_value=0, max_value=2),
)
@settings(max_examples=30)
def test_prop3_held_requires_confined_proposer_blind_clean_check(
    missing_ev: bool, missing_prov: bool, confined: bool, proposer_readable: bool, exit_code: int
) -> None:
    """Hlith.md 5.6 (3): HELD without bounded evidence + confined proposer-blind clean check raises ValueError."""
    if not missing_ev and not missing_prov and confined and not proposer_readable and exit_code == 0:
        ob = _held_ob()
        assert ob.verdict is Verdict.HELD
        return
    ev = None if missing_ev else _good_ev()
    prov = None if missing_prov else _good_prov(confined=confined, proposer_readable=proposer_readable, exit_code=exit_code)
    with pytest.raises(ValueError):
        Obligation("o1", "m.f", "claim", Verdict.HELD, evidence=ev, provenance=prov)


@given(n=st.integers(min_value=1, max_value=5))
@settings(max_examples=10)
def test_prop4_account_dependency_invariant(n: int) -> None:
    """Hlith.md 5.6 (4): All-HELD with zero account_bound=True obligations is REFUSED (exit 11)."""
    obls = ObligationSet(tuple(_held_ob(f"o{i}", account_bound=False) for i in range(n)))
    dec = decide(obls)
    assert dec.outcome is GateOutcome.REFUSED
    assert dec.exit_status == EXIT_NOT_DERIVED


@given(verdict=st.sampled_from([Verdict.REFUTED, Verdict.NOT_DERIVED, Verdict.UNVERIFIED]))
def test_prop5_hard_defect_approval_monotonicity(verdict: Verdict) -> None:
    """Hard defects (REFUTED/NOT_DERIVED/UNVERIFIED) remain REFUSED even if delta-confirmation is present."""
    defect = (Obligation("differential:m.f", "m.f", "c", verdict, witness="w")
              if verdict is Verdict.REFUTED
              else Obligation("differential:m.f", "m.f", "c", verdict, stop_reason="r"))
    # Even if a delta-confirmation obligation is HELD alongside it, the gate stays REFUSED.
    delta_ok = _held_ob("deltas-confirmed", account_bound=True)
    dec = decide(ObligationSet((defect, delta_ok)))
    assert dec.outcome is GateOutcome.REFUSED


def test_prop6_patch_and_base_identity_enforced(tmp_path: Path) -> None:
    """gate.land refuses with EXIT_BOUNDARY when expected_tree or verified_patch_sha256 mismatches."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "m.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    (repo / "m.py").write_text("x = 2\n")
    diff = subprocess.run(["git", "-C", str(repo), "diff"], capture_output=True, text=True, check=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "--", "m.py"], check=True)

    eff = ProposedEffect(diff, "p1", ("m.py",))
    obls = ObligationSet((_held_ob("differential:m.f", account_bound=True),))
    tree = head_tree(repo)
    ident = target_identity(repo)

    bad_tree = land(repo, eff, obls, expected_tree="0" * 40, verified_patch_sha256=eff.patch_sha256, expected_identity=ident)
    assert bad_tree.outcome is GateOutcome.REFUSED and bad_tree.exit_status == EXIT_BOUNDARY

    bad_patch = land(repo, eff, obls, expected_tree=tree, verified_patch_sha256="f" * 64, expected_identity=ident)
    assert bad_patch.outcome is GateOutcome.REFUSED and bad_patch.exit_status == EXIT_BOUNDARY


def test_prop7_account_binding_scope_subset_cannot_land() -> None:
    """Subset A held while B is unverified/not-derived or non-account-bound cannot land."""
    a_held = _held_ob("differential:m.a", account_bound=True)
    b_unverified = Obligation("differential:m.b", "m.b", "c", Verdict.UNVERIFIED, stop_reason="subset B unchecked")
    assert decide(ObligationSet((a_held, b_unverified))).outcome is GateOutcome.REFUSED
    # Also, non-account-bound A alone cannot land even if HELD.
    a_unbound = _held_ob("feedback-pins:m.a", account_bound=False)
    assert decide(ObligationSet((a_unbound,))).outcome is GateOutcome.REFUSED
