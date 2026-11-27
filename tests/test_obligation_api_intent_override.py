from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gate_empty_derived_set import _env, _held_core  # noqa: E402

from hlith.contract.feedback import FeedbackInput
from hlith.contract.legacy import Verdict
from hlith.obligation.api import ObligationEngine
from hlith.obligation.intent import IntentDeclaration


def _verify(env, engine, *, intent_marker: bool = False, intent=None):
    _repo, _patch, _gate, _verifier, _original, account, base, post, identity = env
    if intent_marker:
        return engine.verify(account, FeedbackInput(), base, post, identity, intent=intent)
    return engine.verify(account, FeedbackInput(), base, post, identity)


def test_per_call_intent_matches_constructor_intent_and_none_preserves_default(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _held_core)
    _repo, _patch, _gate, verifier, original, _account, _base, _post, _identity = env
    deltas = ({"id": "delta-1", "symbol": "m.f"},)
    approved = "a" * 64
    intent = IntentDeclaration(deltas=deltas, approved_set_sha256=approved)

    constructed = ObligationEngine(verifier, intent=intent)
    constructed._derive = original._derive
    via_argument = ObligationEngine(verifier)
    via_argument._derive = original._derive
    implicit_default = ObligationEngine(verifier)
    implicit_default._derive = original._derive
    explicit_none = ObligationEngine(verifier)
    explicit_none._derive = original._derive

    expected = _verify(env, constructed).obligations.obligations
    assert _verify(env, via_argument, intent_marker=True, intent=intent).obligations.obligations == expected
    assert _verify(env, implicit_default).obligations.obligations == _verify(
        env, explicit_none, intent_marker=True, intent=None
    ).obligations.obligations


def test_per_call_mismatched_intent_keeps_delta_confirmation_unverified(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _held_core)
    _repo, _patch, _gate, verifier, original, _account, _base, _post, _identity = env
    intent = IntentDeclaration(deltas=({"id": "delta-1", "symbol": "m.f"},), approved_set_sha256="0" * 64)
    engine = ObligationEngine(verifier)
    engine._derive = original._derive

    result = _verify(env, engine, intent_marker=True, intent=intent)
    confirmation = [o for o in result.obligations.obligations if o.obligation_id == "deltas-confirmed"]
    assert len(confirmation) == 1
    assert confirmation[0].verdict is Verdict.UNVERIFIED
