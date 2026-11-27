# SPDX-License-Identifier: Apache-2.0
"""Targeted falsifier for design plan/D2: approved_set_sha256 without deltas must refuse, never pass silently."""

from __future__ import annotations

from hlith.obligation.intent import IntentDeclaration, apply_intent
from hlith.types import BoundedEvidence, CheckProvenance, Obligation, Verdict

_EV = BoundedEvidence(1, "explored", "unexplored")
_PR = CheckProvenance("test", "0" * 64, True, False, "0" * 64, 0)


def test_empty_deltas_with_approved_sha_refuses_in_apply_intent() -> None:
    held_diff = Obligation(
        "differential:m.f",
        "m.f",
        "behaviour preserved",
        Verdict.HELD,
        evidence=_EV,
        provenance=_PR,
        account_bound=True,
    )
    intent = IntentDeclaration(deltas=(), approved_set_sha256="a" * 64)
    conf = intent.confirmation()
    assert conf is not None and not conf.matched
    out = apply_intent((held_diff,), intent)
    assert any(
        o.obligation_id == "deltas-confirmed" and o.verdict is Verdict.UNVERIFIED
        for o in out
    ), f"missing deltas-confirmed refusal: {out!r}"


def test_empty_deltas_without_approved_sha_stays_none() -> None:
    intent = IntentDeclaration(deltas=(), approved_set_sha256=None)
    assert intent.confirmation() is None


def test_engine_cli_confirm_deltas_refuses_empty_deltas_with_hash() -> None:
    from hlith.operator.engine_cli import confirm_deltas

    assert confirm_deltas([], None) is None
    conf = confirm_deltas([], "a" * 64)
    assert conf is not None
    assert not conf.matched
    assert conf.reason == "approved delta-set sha256 was given without any declared delta claims"
    mismatch = confirm_deltas([{"id": "d1", "symbol": "m.f"}], "b" * 64)
    assert mismatch is not None
    assert not mismatch.matched
    assert mismatch.reason == "approved delta-set sha256 does not match the proposed delta set"
    assert conf.reason != mismatch.reason
