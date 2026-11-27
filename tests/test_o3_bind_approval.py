"""O3: binding a human-entered delta-set hash to a thread's OWN recorded deltas (case; shared with case).

`bind_approval` is a pure, side-effect-free check. It never produces a verdict and never HELD: the returned object only
feeds IntentDeclaration, whose `deltas-confirmed` obligation is still judged by the gate together with the differential.
"""
import pytest

from hlith.contract.effects import delta_set_sha256
from hlith.contract.legacy import Verdict
from hlith.obligation.intent import (ApprovalBindingError, BoundApproval, IntentDeclaration, apply_intent, bind_approval)


def _d(i, sym="pkg.m.f"):
    return {"id": i, "symbol": sym, "kind": "behavior", "claim": f"claim {i}"}


A, B = _d("a"), _d("b")


def test_matching_hash_binds_and_is_not_a_verdict():
    got = bind_approval([B, A], delta_set_sha256([A, B]).upper())  # order-free, hex case-free
    assert isinstance(got, BoundApproval)
    assert got.delta_set_sha256 == delta_set_sha256([A, B])
    assert got.intent == IntentDeclaration(deltas=(B, A), approved_set_sha256=delta_set_sha256([A, B]))
    assert got.intent.confirmation().matched
    assert not hasattr(got, "verdict")


def test_binding_alone_never_yields_a_held_obligation():
    got = bind_approval([A], delta_set_sha256([A]))
    out = apply_intent((), got.intent)  # no differential obligation exists: nothing may be HELD
    assert all(o.verdict is not Verdict.HELD for o in out)


@pytest.mark.parametrize("bad", [None, "", "abc", "g" * 64, "a" * 63, "a" * 65, 7])
def test_malformed_hash_is_refused_before_anything_is_judged(bad):
    with pytest.raises(ApprovalBindingError) as e:
        bind_approval([A], bad)
    assert e.value.code == "bad_hash_format"


def test_hash_of_a_different_set_is_a_mismatch_with_both_digests():
    other = delta_set_sha256([A, B])
    with pytest.raises(ApprovalBindingError) as e:
        bind_approval([A], other)
    assert e.value.code == "hash_mismatch"
    assert e.value.expected == delta_set_sha256([A]) and e.value.approved == other


def test_tampered_delta_text_changes_the_hash_and_is_refused():
    approved = delta_set_sha256([A])
    tampered = dict(A, claim="a different claim")
    with pytest.raises(ApprovalBindingError) as e:
        bind_approval([tampered], approved)
    assert e.value.code == "hash_mismatch"


def test_no_deltas_cannot_be_approved():
    with pytest.raises(ApprovalBindingError) as e:
        bind_approval([], delta_set_sha256([A]))
    assert e.value.code == "no_deltas"


def test_ill_formed_or_duplicate_deltas_are_refused():
    for deltas, code in (([{"id": "x"}], "invalid_deltas"), ([A, dict(A)], "invalid_deltas")):
        with pytest.raises(ApprovalBindingError) as e:
            bind_approval(deltas, "0" * 64)
        assert e.value.code == code


def test_non_strict_mismatch_is_an_unconfirmed_intent_that_the_gate_reports_as_unverified():
    other = delta_set_sha256([A, B])
    got = bind_approval([A], other, strict=False)
    assert got.delta_set_sha256 == delta_set_sha256([A]) and not got.intent.confirmation().matched
    out = apply_intent((), got.intent)
    assert [o.verdict for o in out if o.obligation_id == "deltas-confirmed"] == [Verdict.UNVERIFIED]
    with pytest.raises(ApprovalBindingError):  # format errors are never softened
        bind_approval([A], "xyz", strict=False)
