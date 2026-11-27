# SPDX-License-Identifier: Apache-2.0
"""case: the pipeline hands refusal evidence (base/post snapshots, refuted symbols, checker-observed witnesses)
to L5 ``persist_refusal``. Integrity rules under test:
  * refuted_symbols come ONLY from VERIFIED obligations (Verdict.REFUTED) of this run, never from proposer claims;
  * witnesses come ONLY from the obligation engine's own observation, bound to this run's account digest (stale / cross-run
    witnesses are dropped);
  * a missing witness capability stores nothing and says so (no fabrication)."""

from __future__ import annotations

from pathlib import Path

from test_pipeline_e1_and_feedback import _Agent, _Feedback, _Gate, _HostState, _Effect, _Obligation, _Snap

from hlith.contract.capabilities import VerifiedEffect
from hlith.contract.events import EventKind
from hlith.contract.effects import UnresolvedConstructFact
from hlith.contract.identities import InvocationId
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.runs import LandingTarget, RunMode
from hlith.feedback.probe import _pin_witness_records
from hlith.operator.pipeline import PipelineCapabilities, PipelineRequest, run_pipeline


def _prov():
    return CheckProvenance(checker_id="t", checker_sha256="c" * 64, confined=True, proposer_paths_readable=False,
                           profile_sha256="d" * 64, exit_code=0)


class _RefutingObligation(_Obligation):
    """Verifies to a REFUTED differential obligation and exposes the engine-observed witnesses."""

    def __init__(self, *, witnesses=None, expose=True, stale=False):
        super().__init__()
        self._w = witnesses or []
        self._expose = expose
        self._stale = stale
        self.account_sha = None

    def verify(self, account, fb, base, post, target):
        self.account_sha = str(account.account_sha256)
        ve = super().verify(account, fb, base, post, target)
        ob = Obligation(obligation_id="differential:m.f", target_symbol="m.f", claim="same", verdict=Verdict.REFUTED,
                        evidence=BoundedEvidence(explored="x", unexplored="y", executions=1), provenance=_prov(),
                        witness="m.f(' a ') diverges")
        return VerifiedEffect(obligations=ObligationSet(obligations=(ob,)), record=ve.record)

    def observed_witnesses(self):
        if not self._expose:
            raise AttributeError
        sha = "0" * 64 if self._stale else self.account_sha
        return tuple({"account_sha256": sha, "symbol": "m.f", **w} for w in self._w)


class _PlainRefuting(_RefutingObligation):
    observed_witnesses = None  # no witness capability at all


def _caps(target, fb, ob, *, agent=None):
    return PipelineCapabilities(snapshot_service=_Snap(target), host_state=_HostState(), agent_api=agent or _Agent(False),
                                effect_api=_Effect(), obligation_api=ob, gate_api=_Gate(refuse=True), verifier=object(),
                                feedback_api=fb)


def _req(tmp_path):
    return PipelineRequest(target=tmp_path, invocation_id=InvocationId("inv-9"), mode=RunMode.HEADLESS,
                           landing_target=LandingTarget.REHEARSAL, target_identity="t", external_patch=b"diff")


W = {"args": [" a "], "kwargs": {}, "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}}


def test_refusal_evidence_has_snapshots_and_verified_refuted_symbols(tmp_path: Path):
    fb = _Feedback()
    res = run_pipeline(_req(tmp_path), _caps(tmp_path, fb, _RefutingObligation(witnesses=[W])))
    ev = fb.refusal_evidences[0]
    assert ev["base"] == res.base and ev["post"] == res.post
    assert tuple(ev["refuted_symbols"]) == ("m.f",)
    assert [w["symbol"] for w in ev["witnesses"]] == ["m.f"] and ev["witnesses"][0]["pre"] == W["pre"]


def test_proposer_claims_never_reach_the_refusal_evidence(tmp_path: Path):
    class _LyingAgent(_Agent):
        def run(self, request):
            r = super().run(request)
            r.proposer_provenance.update({"refuted_symbols": ["evil.sym"], "witnesses": [{"symbol": "evil.sym", "args": [], "kwargs": {}}]})
            return r

    fb = _Feedback()
    req = PipelineRequest(target=tmp_path, invocation_id=InvocationId("inv-8"), mode=RunMode.STANDALONE,
                          landing_target=LandingTarget.REHEARSAL, target_identity="t")
    run_pipeline(req, _caps(tmp_path, fb, _RefutingObligation(witnesses=[]), agent=_LyingAgent(False)))
    ev = fb.refusal_evidences[0]
    assert tuple(ev["refuted_symbols"]) == ("m.f",)
    assert "evil.sym" not in repr(ev["witnesses"]) and "evil.sym" not in repr(ev["refuted_symbols"])


def test_stale_or_cross_run_witness_is_dropped_and_reported(tmp_path: Path):
    fb = _Feedback()
    res = run_pipeline(_req(tmp_path), _caps(tmp_path, fb, _RefutingObligation(witnesses=[W], stale=True)))
    assert fb.refusal_evidences[0]["witnesses"] == ()
    msgs = [e.detail.get("feedback_error", "") for e in res.events if e.kind is EventKind.PROGRESS]
    assert any("witness" in m and "account" in m for m in msgs)


def test_missing_witness_capability_stores_nothing_and_says_so(tmp_path: Path):
    fb = _Feedback()
    res = run_pipeline(_req(tmp_path), _caps(tmp_path, fb, _PlainRefuting()))
    assert fb.refusal_evidences[0]["witnesses"] == ()
    msgs = [e.detail.get("feedback_error", "") for e in res.events if e.kind is EventKind.PROGRESS]
    assert any("no checker witnesses" in m for m in msgs)


def test_pin_records_accept_differential_shape_and_reject_incomplete():
    recs, keys = _pin_witness_records("run-x", [{"symbol": "m.f", **W}])
    assert len(recs) == 1 and len(keys) == 1
    unpinned: list = []
    recs, _ = _pin_witness_records("run-x", [{"symbol": "m.f", **W, "inject": {"x": 1}},
                                              {"symbol": "m.f", "args": [1], "kwargs": {}},
                                              {"symbol": "m.f", **W, "truncated": True}], unpinned)
    assert recs == [] and {u["reason"] for u in unpinned} >= {"inject", "incomplete", "truncated"}


def test_only_fresh_representable_witnesses_create_regression_pins():
    original = {"symbol": "m.f", **W}
    skipped = []
    records, keys = _pin_witness_records("run-new", [
        {**original, "oracle": "recorded-expected"},
        {**original, "receiver": {"kind": "instance", "ctor": [[], {}]}},
        {**original, "throw": True},
        original,
    ], skipped)
    assert len(records) == len(keys) == 1
    assert records[0].provenance["origin_kind"] == "differential-witness"
    assert [item["reason"] for item in skipped] == [
        "historical expectation (already stored)", "receiver construction is not stored in a feedback pin",
        "generator throw is not stored in a feedback pin",
    ]


def test_normalized_outcome_shapes_are_kept_not_coerced_to_timeout():
    """review review (1): an already-normalized {'kind': ...} outcome must pin as itself; an unknown shape is unpinned, never 'timeout'."""
    w = {"symbol": "m.f", "args": [1], "kwargs": {}, "pre": {"kind": "return", "repr": "1"},
         "post": {"kind": "raise", "exc": "ValueError"}}
    recs, _ = _pin_witness_records("run-x", [w])
    assert len(recs) == 1
    p = recs[0].directive_payload
    assert p["expected"]["kind"] == "return" and p["observed"]["kind"] == "raise"
    unpinned: list = []
    recs, _ = _pin_witness_records("run-x", [{**w, "post": {"weird": 1}}], unpinned)
    assert recs == [] and unpinned and unpinned[0]["reason"] == "unknown_outcome_shape"
    # the evaluator shape is still accepted, and base_outcome/post_outcome aliases keep working
    recs, _ = _pin_witness_records("run-x", [{"symbol": "m.f", "args": [1], "kwargs": {},
                                              "base_outcome": {"k": "ret", "r": "1"}, "post_outcome": {"k": "exc", "t": "E"}}])
    assert recs[0].directive_payload["observed"]["kind"] == "raise"


def test_witness_capture_only_for_symbols_still_refuted_after_intent():
    """review review (2): an approved delta covering A's refutation, with the run refused on B: A's witness must NOT be handed to L5."""
    from hlith.obligation.api import surviving_witnesses
    ob_a = Obligation(obligation_id="differential:m.a", target_symbol="m.a", claim="c", verdict=Verdict.HELD,
                      evidence=BoundedEvidence(explored="x", unexplored="y", executions=1), provenance=_prov())
    ob_b = Obligation(obligation_id="differential:m.b", target_symbol="m.b", claim="c", verdict=Verdict.REFUTED,
                      witness="m.b(1) diverges", evidence=BoundedEvidence(explored="x", unexplored="y", executions=1), provenance=_prov())
    wit = {"m.a": {"args": [1], "kwargs": {}, "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}},
           "m.b": {"args": [2], "kwargs": {}, "pre": {"k": "ret", "r": "2"}, "post": {"k": "ret", "r": "3"}}}
    out = surviving_witnesses(wit, (ob_a, ob_b), "f" * 64)
    assert [w["symbol"] for w in out] == ["m.b"] and out[0]["account_sha256"] == "f" * 64
    assert surviving_witnesses(wit, (ob_a,), "f" * 64) == ()


def test_not_derived_constructs_reach_both_refusal_paths(tmp_path: Path):
    """Construct feedback is derived from the typed account, including obligation-stage refusals."""
    from dataclasses import replace as dc_replace

    construct = UnresolvedConstructFact("m.py", 7, "star_import", "m.f", "a" * 64, "post")

    class _EffectWithConstructs:
        def build_account(self, run_id, base, post, patch):
            account = _Effect().build_account(run_id, base, post, patch)
            return dc_replace(account, unresolved_constructs=(construct,))

    class _ObligationRefuses:
        def verify(self, *args):
            from hlith.contract.errors import Refusal, RefusalError

            raise RefusalError(Refusal.REFUTED, "unresolved-0 NOT-DERIVED")

    for obligation in (_RefutingObligation(), _ObligationRefuses()):
        fb = _Feedback()
        caps = dc_replace(_caps(tmp_path, fb, obligation), effect_api=_EffectWithConstructs())
        run_pipeline(_req(tmp_path), caps)
        evidence = fb.refusal_evidences[0]
        assert evidence["constructs"] == ({
            "file_path": "m.py",
            "line": 7,
            "kind": "star_import",
            "caller_qualified_name": "m.f",
            "node_sha256": "a" * 64,
            "side": "post",
            "provenance": {"source_file": "m.py", "node_sha256": "a" * 64},
        },)


def test_recurrent_constructs_are_returned_in_the_pipeline_feedback_block(tmp_path: Path):
    from hlith.operator.coordinator import Coordinator, RunRequest

    class _FeedbackWithRecurrence(_Feedback):
        def recurrent_constructs(self, repo_identity, constructs):
            assert repo_identity == "repo-test-id"
            assert constructs == ()
            return [{"id": "recurrent-123", "earlier_refused_runs": 1}]

    fb = _FeedbackWithRecurrence()
    req = _req(tmp_path)
    res = run_pipeline(req, _caps(tmp_path, fb, _RefutingObligation()))
    artifact = Coordinator._artifact(
        res.run_receipt,
        RunRequest(repo=tmp_path, mode=RunMode.HEADLESS, landing_target=LandingTarget.REHEARSAL),
        res,
    )
    assert artifact["feedback"]["recurrent_constructs"] == [
        {"id": "recurrent-123", "earlier_refused_runs": 1}
    ]


def test_local_feedback_service_recurrence_uses_validated_records_and_current_digest(tmp_path: Path):
    from hlith.contract.effects import EffectAccount
    from hlith.contract.errors import EXIT_REFUTED
    from hlith.contract.identities import RunId, Sha256, TreeOid
    from hlith.contract.runs import GateReceipt
    from hlith.feedback.api import LocalFeedbackService

    class _State:
        def __init__(self, root):
            self.root = root

        def namespace(self, repo_identity, name):
            assert repo_identity == "repo-test-id" and name == "feedback"
            return self.root / name

    construct = UnresolvedConstructFact("m.py", 7, "star_import", "m.f", "a" * 64, "post")
    account = EffectAccount(
        run_id=RunId("run-1"), base_tree_oid=TreeOid("0" * 40), post_tree_oid=TreeOid("1" * 40),
        patch_sha256=Sha256("b" * 64), analyzer_id="test", unresolved_constructs=(construct,),
    )
    receipt = GateReceipt(run_id=RunId("run-1"), outcome="refused", exit_status=EXIT_REFUTED,
                          blocking=("unresolved-0",), landed_commit=None, verification_record_sha256=None)
    row = {
        "file_path": construct.file_path, "line": construct.line_number, "kind": construct.kind,
        "caller_qualified_name": construct.caller_qualified_name, "node_sha256": construct.node_sha256,
        "side": construct.side,
        "provenance": {"source_file": construct.file_path, "node_sha256": construct.node_sha256},
    }
    service = LocalFeedbackService(_State(tmp_path / "host"))
    assert service.persist_refusal(receipt, account, {"repo_identity": "repo-test-id", "constructs": (row,)})
    recurrent = service.recurrent_constructs("repo-test-id", (row,))
    assert len(recurrent) == 1 and recurrent[0]["earlier_refused_runs"] == 1
    assert service.recurrent_constructs("repo-test-id", ()) == []
    assert LocalFeedbackService(_State(tmp_path / "empty-host")).recurrent_constructs("repo-test-id", (row,)) == []
