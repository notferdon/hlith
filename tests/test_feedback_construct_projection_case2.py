# SPDX-License-Identifier: Apache-2.0
"""review design plan (L5 side), red-first on 5a5bb3f1: a stored NOT_DERIVED construct record is projected as a live-matchable
``FeedbackInput.constructs`` directive (where, construct_kind, node_sha256, feedback_id), never as an unconditional EffectAccount
unknown. review's L3 consumer (a3c37739) blocks only on a live node_sha256 match; this test pins the producer half of that contract
through the real store: persist -> load_stored_records -> project_feedback_input (the path FeedbackApi.load runs)."""

from __future__ import annotations

from hlith.feedback._legacy import not_derived_construct
from hlith.feedback.project import project_feedback_input
from hlith.feedback.store import load_stored_records, persist_record

SHA = "ab" * 32


def test_a_stored_construct_is_a_live_matchable_directive_not_a_permanent_unknown(tmp_path):
    rec = not_derived_construct("run-n2constructs01", "pkg.m.f", "dynamic_attribute", "pkg/m.py:7", SHA)
    persist_record(tmp_path, rec)
    fb = project_feedback_input(load_stored_records(tmp_path, None))
    assert fb.extra_unknowns == (), "a stored construct became an unconditional unknown (blocks every later run forever)"
    assert fb.constructs == (("pkg/m.py:7", "dynamic_attribute", SHA, rec.feedback_id),)
    assert [r.record_id for r in fb.records] == [rec.feedback_id]  # still loaded and named in provenance


def test_duplicate_pin_inputs_keep_each_source_and_separate_different_expectations(tmp_path):
    from hlith.feedback._legacy import pin_regression_counterexample
    from hlith.obligation.feedbackview import FeedbackView

    records = []
    for run, expected in (("run-000000000001", "1"), ("run-000000000002", "1"), ("run-000000000003", "2")):
        record = pin_regression_counterexample(run, "pkg.m.f", [1], {},
            expected={"kind": "return", "repr": expected}, observed={"kind": "return", "repr": "3"})
        persist_record(tmp_path, record)
        records.append(record.feedback_id)
    projected = project_feedback_input(load_stored_records(tmp_path, None))
    pins = FeedbackView(projected).constraints("pkg.m.f").pinned_inputs
    sources = {pin.expected["repr"] if pin.expected else None: set(pin.record_ids) for pin in pins}
    assert sources == {None: set(records), "1": set(records[:2]), "2": {records[2]}}
