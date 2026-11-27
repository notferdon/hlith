"""A HELD removal certificate supersedes the stored construct of the REMOVED guard, and nothing else (feedback-construct:0)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import hlith.derive as derive_mod
from hlith.contract.effects import UnresolvedConstructFact
from hlith.contract.feedback import FeedbackInput
from hlith.obligation.facts import Facts, ModCallable
from hlith.obligation.feedbackview import FeedbackView
from hlith.types import BoundedEvidence, CheckProvenance, Obligation, Verdict

_EV = BoundedEvidence(1, "explored", "unexplored")
_PR = CheckProvenance("test", "0" * 64, True, False, "0" * 64, 0)
SHA = "c" * 64


def _fact(side, sha=SHA, line=2):
    return UnresolvedConstructFact("m.py", line, "unsupported_entry_guard", "m.f", sha, side)


def _run(tmp_path, monkeypatch, *, live, certificate=Verdict.HELD, differential=Verdict.HELD, stored_where="m.py:2"):
    base, post = tmp_path / "base", tmp_path / "post"
    base.mkdir()
    post.mkdir()
    (base / "m.py").write_text("def f(x: int) -> int:\n    if x <= 0:\n        raise ValueError('neg')\n    return x\n", encoding="utf-8")
    (post / "m.py").write_text("def f(x: int) -> int:\n    return x\n", encoding="utf-8")
    fb = FeedbackInput()
    fb = SimpleNamespace(seeds=(), pins=(), constraints=(), extra_callers=(), extra_unknowns=(),
                         constructs=((stored_where, "unsupported_entry_guard", SHA, "fb-removed"),))
    view = FeedbackView(fb, account=SimpleNamespace(unresolved_constructs=tuple(live)))
    # the obligation API view: a removed unsupported entry guard is NOT among its unresolved constructs (api.py, D6)
    acct = Facts()
    acct.modified_callables = (ModCallable("m.f", "m.py", "def f(x: int) -> int", "def f(x: int) -> int"),)
    ob = lambda oid, v: Obligation(oid, "m.f", "claim", v, evidence=_EV, provenance=_PR, stop_reason=None if v is Verdict.HELD else "why")
    mp = monkeypatch
    mp.setattr(derive_mod.z3_binding, "requests_from_account", lambda ad, touched: [{"obligation_id": "signature_binding:m.f"}])
    mp.setattr(derive_mod.z3_binding, "return_shape_requests_from_account", lambda ad, post, touched: [])
    mp.setattr(derive_mod.z3_binding, "verify_confined_detailed", lambda req, **_kw: (ob(req["obligation_id"], Verdict.HELD), {}))
    mp.setattr(derive_mod, "_delta_rel_item", lambda *a, **k: None)
    mp.setattr(derive_mod.guard_removed, "removed_entry_guards", lambda *a, **k: [{"line": 2, "cond": "x <= 0", "exc": "ValueError"}])
    mp.setattr(derive_mod.differential, "run_differential", lambda **_kw: ob("differential:m.f", differential))
    mp.setattr(derive_mod.differential, "read_observations", lambda *a, **k: {"executed_post_callables": ["m.f"]})
    mp.setattr(derive_mod.delta_cover, "removed_guard_coverage",
               lambda *a, **k: SimpleNamespace(covered=True, triggering=1, agreeing=1, evidence="obs"))
    mp.setattr(derive_mod, "_certificate_for", lambda *a, **k: None)
    mp.setattr(derive_mod, "_additive_certificate", lambda *a, **k: None)
    mp.setattr(derive_mod, "_removal_obligation", lambda *a, **k: ob(
        "guard-removal-covered:m.f:2" if certificate is Verdict.HELD else "guard-removal-certificate:m.f:2", certificate))
    core = derive_mod.make_derive(proposer_paths=[]).core
    out = core(touched_files=("m.py",), deltas=[{"id": "d1", "symbol": "m.f"}], acct=acct, ad=acct.to_dict(), fbk=view,
               base_dir=base, post_dir=post)
    return {o.obligation_id: o.verdict for o in out.obligations}


def test_a_held_removal_certificate_supersedes_the_stored_construct_of_the_removed_guard(tmp_path, monkeypatch):
    got = _run(tmp_path, monkeypatch, live=[_fact("pre")])
    assert "feedback-construct:0" not in got, got
    assert got["guard-removal-covered:m.f:2"] is Verdict.HELD and "guard-removed:m.f:2" not in got, got


@pytest.mark.parametrize("kw", [
    {"live": [_fact("pre")], "certificate": Verdict.UNVERIFIED},
    {"live": [_fact("pre")], "differential": Verdict.UNVERIFIED},
    {"live": [_fact("pre"), _fact("post")]},
    {"live": [_fact("pre"), _fact("both")]},
    {"live": [_fact("post")]},
    {"live": [_fact("pre", line=7)], "stored_where": "m.py:7"},
], ids=["certificate-not-held", "differential-not-held", "also-live-post", "also-live-both", "post-only", "another-line"])
def test_control_the_stored_construct_keeps_blocking(tmp_path, monkeypatch, kw):
    got = _run(tmp_path, monkeypatch, **kw)
    assert got.get("feedback-construct:0") is Verdict.NOT_DERIVED, got
