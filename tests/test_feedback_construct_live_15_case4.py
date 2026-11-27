# SPDX-License-Identifier: Apache-2.0
"""Focused check for design plan: stored NOT_DERIVED_CONSTRUCT blocks only while live node_sha256 matches and guard is uncovered."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import hlith.derive as derive_mod
from hlith.contract.effects import GapCode, Unknown, UnresolvedConstructFact
from hlith.contract.feedback import FeedbackInput
from hlith.obligation.facts import Construct, Facts, ModCallable
from hlith.obligation.feedbackview import FeedbackView
from hlith.types import BoundedEvidence, CheckProvenance, Obligation, Verdict

_EV = BoundedEvidence(1, "explored", "unexplored")
_PR = CheckProvenance("test", "0" * 64, True, False, "0" * 64, 0)


def _fb(*, constructs=(), extra_unknowns=()):
    return SimpleNamespace(
        seeds=(),
        pins=(),
        constraints=(),
        extra_callers=(),
        extra_unknowns=tuple(extra_unknowns),
        constructs=tuple(constructs),
    )


def test_construct_blocks_only_when_live_node_sha256_matches_at_same_where() -> None:
    sha_old = "a" * 64
    sha_new = "b" * 64
    fb = _fb(
        constructs=(("m.py:4", "dynamic_attribute", sha_old, "fb-1"),),
        extra_unknowns=(Unknown(GapCode.OTHER, "m.py:9", "non-construct unknown"),),
    )

    live_match = SimpleNamespace(
        unresolved_constructs=(
            UnresolvedConstructFact("m.py", 4, "dynamic_attribute", "m.f", sha_old, "post"),
        )
    )
    obs_match = FeedbackView(fb, account=live_match).not_derived()
    assert [o.obligation_id for o in obs_match] == ["feedback-unknown:0", "feedback-construct:0"]

    live_changed = SimpleNamespace(
        unresolved_constructs=(
            UnresolvedConstructFact("m.py", 4, "dynamic_attribute", "m.f", sha_new, "post"),
        )
    )
    obs_changed = FeedbackView(fb, account=live_changed).not_derived()
    assert [o.obligation_id for o in obs_changed] == ["feedback-unknown:0"]

    live_removed = SimpleNamespace(unresolved_constructs=())
    obs_removed = FeedbackView(fb, account=live_removed).not_derived()
    assert [o.obligation_id for o in obs_removed] == ["feedback-unknown:0"]

    # Negative check: standard FeedbackInput without extra constructs works seamlessly.
    assert FeedbackView(FeedbackInput()).not_derived() == ()


def test_deferred_covered_guard_supersedes_matching_feedback_construct(
    tmp_path: Path, monkeypatch
) -> None:
    base = tmp_path / "base"
    post = tmp_path / "post"
    base.mkdir()
    post.mkdir()
    (base / "m.py").write_text("def f(x: int) -> int:\n    return x\n", encoding="utf-8")
    (post / "m.py").write_text("def f(x: int) -> int:\n    if x < 0:\n        raise ValueError('neg')\n    return x\n", encoding="utf-8")

    sha_guard = "c" * 64
    raw_account = SimpleNamespace(
        unresolved_constructs=(
            UnresolvedConstructFact("m.py", 2, "unsupported_entry_guard", "m.f", sha_guard, "post"),
        )
    )
    fb = _fb(constructs=(("m.py:2", "unsupported_entry_guard", sha_guard, "fb-guard"),))
    fview = FeedbackView(fb, account=raw_account)

    acct = Facts()
    acct.modified_callables = (
        ModCallable("m.f", "m.py", "def f(x: int) -> int", "def f(x: int) -> int"),
    )
    acct.unresolved_constructs = [
        Construct("unsupported_entry_guard", "m.py", 2, "x < 0", caller_qualified_name="m.f", side="post", condition_source="x < 0")
    ]
    ad = acct.to_dict()

    monkeypatch.setattr(derive_mod.z3_binding, "requests_from_account", lambda ad, touched: [{"obligation_id": "signature_binding:m.f"}])
    monkeypatch.setattr(derive_mod.z3_binding, "return_shape_requests_from_account", lambda ad, post, touched: [])
    monkeypatch.setattr(derive_mod.z3_binding, "verify_confined_detailed", lambda req, **_kw: (Obligation(req["obligation_id"], "m.f", "sig", Verdict.HELD, evidence=_EV, provenance=_PR), {}))
    monkeypatch.setattr(derive_mod, "_delta_rel_item", lambda *a, **k: None)
    monkeypatch.setattr(derive_mod.guard_removed, "removed_entry_guards", lambda *a, **k: [])
    monkeypatch.setattr(derive_mod.differential, "run_differential", lambda **_kw: Obligation("differential:m.f", "m.f", "beh", Verdict.HELD, evidence=_EV, provenance=_PR))
    monkeypatch.setattr(derive_mod.differential, "read_observations", lambda *a, **k: {"executed_post_callables": ["m.f"]})

    # Covered guard -> feedback-construct is superseded alongside deferred unresolved-0.
    monkeypatch.setattr(derive_mod.delta_cover, "guard_coverage", lambda *a, **k: SimpleNamespace(covered=True, triggering=1, agreeing=1, evidence="obs"))
    core = derive_mod.make_derive(proposer_paths=[]).core
    covered_obs = core(
        touched_files=("m.py",),
        deltas=[{"id": "d1", "symbol": "m.f"}],
        acct=acct,
        ad=ad,
        fbk=fview,
        base_dir=base,
        post_dir=post,
    )
    assert all(o.verdict is Verdict.HELD for o in covered_obs.obligations), covered_obs.obligations

    # Uncovered guard (no deltas / uncovered) -> feedback-construct stays NOT_DERIVED.
    uncovered_obs = core(
        touched_files=("m.py",),
        deltas=[],
        acct=acct,
        ad=ad,
        fbk=fview,
        base_dir=base,
        post_dir=post,
    )
    assert any(o.obligation_id == "feedback-construct:0" and o.verdict is Verdict.NOT_DERIVED for o in uncovered_obs.obligations)
