# SPDX-License-Identifier: Apache-2.0
"""case: ``labels.decision`` is type-strict. The recorded (outcome, exit_status) pair is looked up only when it has the schema's
types (outcome: str; exit_status: int, never bool/float/list/str). Any other pair is the existing UNKNOWN / dim class and never raises
or renders a confident LANDED/REFUSED word. Valid pairs keep their exact output."""

from __future__ import annotations

import pytest

from hlith.operator import labels

CODES = (0, 4, 10, 11, 12)

# Output of labels.decision on every currently valid-typed pair, captured at 92f4194a BEFORE the change.
VALID_TABLE = {
    ("landed", 0): ("LANDED", "good"),
    ("landed", 4): ("UNKNOWN (outcome='landed', exit_status=4)", "dim"),
    ("landed", 10): ("UNKNOWN (outcome='landed', exit_status=10)", "dim"),
    ("landed", 11): ("UNKNOWN (outcome='landed', exit_status=11)", "dim"),
    ("landed", 12): ("UNKNOWN (outcome='landed', exit_status=12)", "dim"),
    ("refused", 0): ("REFUSED (exit 0)", "warn"),
    ("refused", 4): ("REFUSED · BOUNDARY", "warn"),
    ("refused", 10): ("REFUSED · REFUTED", "bad"),
    ("refused", 11): ("REFUSED · NOT-DERIVED", "warn"),
    ("refused", 12): ("REFUSED · UNVERIFIED", "warn"),
}


@pytest.mark.parametrize("pair", sorted(VALID_TABLE))
def test_every_valid_pair_is_unchanged(pair):
    assert labels.decision(*pair) == VALID_TABLE[pair]


def test_unlisted_int_refusal_and_unknown_outcome_keep_today_output():
    assert labels.decision("refused", 7) == ("REFUSED (exit 7)", "warn")
    assert labels.decision("weird", 0) == ("UNKNOWN (outcome='weird', exit_status=0)", "dim")


BAD = [
    ("landed", False), ("landed", 0.0), ("landed", True), ("landed", None), ("landed", "0"), ("landed", [0]),
    ("refused", 10.0), ("refused", [10]), ("refused", None), ("refused", "10"), ("refused", True), ("refused", False),
    ("refused", {10}), ("refused", (10,)), ("refused", {}),
    (None, 0), (None, 10), ("unknown", 10), ("landed ", 0), (["landed"], 0), ({"a": 1}, 10), (True, 0), (0, 0), (None, None),
]


@pytest.mark.parametrize("outcome,status", BAD, ids=[f"{o!r}-{s!r}" for o, s in BAD])
def test_invalid_typed_pair_is_unknown_and_never_raises(outcome, status):
    label, tone = labels.decision(outcome, status)
    assert label == f"UNKNOWN (outcome={outcome!r}, exit_status={status!r})" and tone == "dim"
    assert "LANDED" not in label.split(" (")[0] and "REFUSED" not in label.split(" (")[0]


def test_headline_marks_a_nonint_boundary_status_without_a_hint(tmp_path):
    from hlith.operator import store
    v = store.RunView.__new__(store.RunView)
    v.__dict__.update(state=store.RunState.FINISHED, artifact={"outcome": "refused", "exit_status": 4.0, "blocking": ["x"]},
                      receipt=None, feedback_problems=[], errors=[], why=None)
    label, tone, notes = labels.headline(v)
    assert label.startswith("UNKNOWN") and tone == "dim" and not any(n.startswith("HINT") for n in notes)


@pytest.mark.parametrize("status", [False, True, 0.0, 10.0, "10", [10], {}])
@pytest.mark.parametrize("outcome", ["landed", "refused"])
def test_inspect_artifact_file_invalid_status_is_schema_invalid_never_good_never_crash(tmp_path, outcome, status):
    import json
    from hlith.operator import api, store
    f = tmp_path / "bad-artifact.json"
    f.write_text(json.dumps({"outcome": outcome, "exit_status": status, "blocking": []}))
    ins = api.OperatorApi.inspect_artifact_file(api.OperatorApi.__new__(api.OperatorApi), f)
    assert ins.view.state is store.RunState.SCHEMA_INVALID
    assert ins.tone != "good" and ins.label.startswith("UNKNOWN") and ins.label.endswith("UNVALIDATED"), ins.label
