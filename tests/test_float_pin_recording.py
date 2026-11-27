# SPDX-License-Identifier: Apache-2.0
"""Second recording path of the float-witness fault (review finding on ee65eb9a): pipeline -> feedback/probe -> pin_regression_counterexample handed RAW float args to the store
(contract codec refuses a float), so L5 logged feedback_error and the regression PIN WAS DROPPED (no pin = no cross-change record, F2). The pin must be recorded with the typed
{"$float": text} encoding (encode on write, bit-exact incl. -0.0 / nan / inf), re-pinning a stored record must not double-encode (idempotent), and every place a stored pin becomes
a Pinned call (feedbackview._pinned, the constraint collector) or runs in the probe runner must decode it back to the SAME float. The strict plain() codec is unchanged. Unit level."""

from __future__ import annotations

import json
import math
import struct

import pytest

from hlith.contract import codec
from hlith.feedback import _legacy as fb
from hlith.feedback.store import load_stored_records, persist_record

FLOATS = [-1.5, 0.0, -0.0, 1e308, 5e-324, float("inf"), float("-inf"), float("nan"), 9007199254740993.0]


def bits(x):
    return struct.pack(">d", x)


def _pin(args, kwargs=None, run="run-000000000003"):
    return fb.pin_regression_counterexample(run, "pkg.m.f", args, kwargs or {}, expected={"kind": "return", "repr": "True"}, observed={"kind": "raise", "exc": "TypeError"})


@pytest.mark.parametrize("x", FLOATS, ids=[repr(f) for f in FLOATS])
def test_a_raw_float_pin_persists_and_decodes_bit_exactly(tmp_path, x):
    rec = _pin([x], {"k": x})
    persist_record(tmp_path / "fb", rec)  # raised 'not a contract value: float' before
    stored = load_stored_records(tmp_path / "fb")[0].record.directive_payload["input"]
    assert stored["args"] == [codec.float_tag(x)]
    got = codec.decode_call_values(stored)
    assert bits(got["args"][0]) == bits(x) and bits(got["kwargs"]["k"]) == bits(x)


def test_strict_plain_codec_is_unchanged():
    with pytest.raises(TypeError):
        codec.canonical_bytes({"a": 1.5})


def test_repinning_a_stored_record_does_not_double_encode(tmp_path):
    rec = _pin([-1.5])
    again = fb.pin_regression_counterexample("run-000000000004", "pkg.m.f", rec.directive_payload["input"]["args"], rec.directive_payload["input"]["kwargs"],
                                             expected={"kind": "return", "repr": "True"}, observed={"kind": "raise", "exc": "TypeError"})
    assert again.directive_payload["input"] == rec.directive_payload["input"]
    assert again.directive_payload["input"]["args"] == [codec.float_tag(-1.5)]


def test_int_and_float_pins_stay_distinct():
    assert _pin([1]).directive_payload["input"]["args"] == [1]
    assert _pin([1.0]).directive_payload["input"]["args"] == [codec.float_tag(1.0)]


def test_the_other_constructors_record_floats_too(tmp_path):
    dom = fb.require_differential_domain_constraint("run-000000000005", ("pkg.m.f",), [([2.5], {})])
    orc = fb.oracle_regression("run-000000000006", "pkg.m.f", ["tests/test_m.py::t"], [2.5], {}, expected={"kind": "return", "repr": "1"}, observed={"kind": "return", "repr": "2"})
    for r in (dom, orc):
        persist_record(tmp_path / "fb", r)
    assert len(load_stored_records(tmp_path / "fb")) == 2


def test_feedbackview_pinned_decodes_the_tag_back_to_a_float():
    from hlith.obligation import feedbackview

    inp = json.dumps(_pin([-1.5, float("nan")], {"k": -0.0}).directive_payload["input"])
    p = feedbackview._pinned(inp, None)
    assert p.args[0] == -1.5 and math.isnan(p.args[1]) and bits(p.kwargs["k"]) == bits(-0.0), (p.args, p.kwargs)


def test_the_constraint_collector_hands_the_engine_real_floats():
    cons = fb.constraints_for([_pin([-1.5, float("inf")], {"k": -0.0})], "pkg.m.f")
    pin = cons.pinned_inputs[0]
    assert pin.args[0] == -1.5 and pin.args[1] == math.inf and bits(pin.kwargs["k"]) == bits(-0.0), (pin.args, pin.kwargs)


def test_the_probe_runner_builds_a_float_from_the_tag():
    ns: dict = {"json": json, "_exc": None}
    src = fb._RUNNER
    start = src.index("def _build(x):")
    lines = src[start:].split("\n")
    body = [lines[0]]
    for ln in lines[1:]:
        if ln.strip() and not ln.startswith((" ", "\t")):
            break
        body.append(ln)
    exec("\n".join(body), ns)  # noqa: S102 - the runner's own _build, executed in isolation
    out = ns["_build"]([codec.float_tag(-1.5), codec.float_tag(float("nan")), {"k": codec.float_tag(-0.0)}, 3])
    assert out[0] == -1.5 and math.isnan(out[1]) and bits(out[2]["k"]) == bits(-0.0) and out[3] == 3
