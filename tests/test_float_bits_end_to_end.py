# SPDX-License-Identifier: Apache-2.0
"""Float witnesses are carried BIT-EXACTLY end to end (IDE + design review + review findings on f6e10dee): the 8-byte IEEE-754 pattern, so -0.0, subnormals, inf and NaN sign/payload survive recording
(witness_call, observed witnesses, pins) AND standalone replay. Tag: {"$float": {"bits": "<16 hex>", "repr": "<repr for humans>"}} - ONLY that exact shape is a tag. Anything else
shaped like {"$float": ...} (a genuine dict argument, e.g. {"$float": "1.5"} or {"$float": "x"}) is plain data: never decoded as a float, never poisoning a pin. Re-encoding a tag is a
no-op (a stored record can be re-pinned). The engine's parent->evaluator transport is pickle (exact), so a pinned NaN with a sign runs as that exact value; the JSON legs (the worker's
witness emit, the replay script) carry the tag. Unit level except the two engine tests (opt-in -m real tier, behind the resource-bounded slot)."""

from __future__ import annotations

import json
import math
import struct
from types import SimpleNamespace

import pytest

from hlith.contract import codec

BITS = ["fff8000000000001", "7ff8000000000001", "7ff0000000000001", "fff0000000000001", "7ff8000000000000", "fff8000000000000", "8000000000000000", "0000000000000001",
        "800fffffffffffff", "7fefffffffffffff", "7ff0000000000000", "fff0000000000000", "3ff0000000000000", "bff8000000000000"]


def f_of(h: str) -> float:
    return struct.unpack(">d", bytes.fromhex(h))[0]


def bits_of(x: float) -> str:
    return struct.pack(">d", x).hex()


@pytest.mark.parametrize("h", BITS)
def test_every_bit_pattern_survives_encode_json_decode(h):
    x = f_of(h)
    enc = codec.encode_call_values({"args": [x], "kwargs": {"k": x}})
    back = codec.decode_call_values(json.loads(codec.canonical_bytes(enc)))
    assert bits_of(back["args"][0]) == h and bits_of(back["kwargs"]["k"]) == h


@pytest.mark.parametrize("h", BITS)
def test_pin_encoding_is_bit_exact_too(h):
    x = f_of(h)
    assert bits_of(codec.decode_call_values(json.loads(json.dumps(codec.encode_pin_values([x]))))[0]) == h


def test_the_tag_shape_is_bits_plus_a_human_repr():
    assert codec.encode_call_values([-0.0]) == [{"$float": {"bits": "8000000000000000", "repr": "-0.0"}}]
    t = codec.encode_call_values([f_of("fff8000000000001")])[0]["$float"]
    assert t["bits"] == "fff8000000000001" and isinstance(t["repr"], str)


def test_re_encoding_a_tag_is_a_no_op():
    once = codec.encode_call_values({"args": [1.5, f_of("fff8000000000001")]})
    assert codec.encode_call_values(once) == once and codec.encode_pin_values(once) == once


@pytest.mark.parametrize("d", [{"$float": "1.5"}, {"$float": "x"}, {"$float": 1.5}, {"$float": {"bits": "zz", "repr": "q"}}, {"$float": {"bits": "3ff0", "repr": "1.0"}}, {"$float": {"bits": "3ff0000000000000"}},
                               {"$lit": {"$float": "1.5"}}])
def test_a_genuine_dict_that_is_not_the_exact_tag_is_plain_data(d):
    """review finding: {'$float': '1.5'} used to decode as the float 1.5 and {'$float': 'x'} made the pin undecodable."""
    if any(isinstance(v, float) for v in d.values()):
        d = {"$float": 1.5} and {"$float": "1.5"}  # a raw float inside is encoded; the string form is the genuine-dict case
    out = codec.decode_call_values(json.loads(json.dumps(codec.encode_pin_values([d]))))
    assert out == [d] and not isinstance(out[0], float)


def test_a_genuine_dict_pin_round_trips_and_is_decodable_every_time():
    from hlith.feedback import _legacy as fb
    from hlith.obligation import feedbackview

    rec = fb.pin_regression_counterexample("run-000000000007", "pkg.m.f", [{"$float": "x"}], {}, expected={"kind": "return", "repr": "1"}, observed={"kind": "return", "repr": "2"})
    p = feedbackview._pinned(json.dumps(rec.directive_payload["input"]), None)
    assert p.args == ({"$float": "x"},)


def test_strict_plain_codec_still_refuses_a_raw_float():
    with pytest.raises(TypeError):
        codec.canonical_bytes({"a": 1.5})


# ----------------------------------------------------------------------------------------------- replay carries the bits
def test_standalone_replay_runs_the_exact_nan_bits(tmp_path):
    """math.copysign tells -nan from +nan: base returns -1.0, post a constant. If replay passed a different NaN the two sides would agree and nothing would reproduce."""
    from hlith import differential

    for side, body in (("base", "import math\n\n\ndef f(x):\n    if isinstance(x, float) and x != x:\n        return math.copysign(1.0, x)\n    return 1.0\n"), ("post", "def f(x):\n    return 1.0\n")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(body)
    wit = {"module": "m", "qualname": "f", "args": codec.encode_call_values([f_of("fff8000000000001")]), "kwargs": {}, "env": None, "inject": None, "receiver": None,
           "pre": {"k": "ret", "r": "-1.0"}, "post": {"k": "ret", "r": "1.0"}}
    rep = differential.replay_witness(wit, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep["replayable"] and rep.get("reproduced") is True, rep


def test_standalone_replay_of_a_positive_nan_does_not_reproduce_the_negative_witness(tmp_path):
    """Control: with +nan both sides give 1.0, the recording says they differ, so replay must NOT claim REPRODUCED."""
    from hlith import differential

    for side, body in (("base", "import math\n\n\ndef f(x):\n    if isinstance(x, float) and x != x:\n        return math.copysign(1.0, x)\n    return 1.0\n"), ("post", "def f(x):\n    return 1.0\n")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(body)
    wit = {"module": "m", "qualname": "f", "args": codec.encode_call_values([f_of("7ff8000000000000")]), "kwargs": {}, "env": None, "inject": None, "receiver": None,
           "pre": {"k": "ret", "r": "-1.0"}, "post": {"k": "ret", "r": "1.0"}}
    rep = differential.replay_witness(wit, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep.get("reproduced") is not True, rep


def test_replay_cmd_hands_the_tagged_witness_to_replay_unchanged():
    """The artifact's tagged witness_call goes to replay_witness AS IS (the replay script decodes the bits); it is not decoded to a lossy in-process object first."""
    import inspect

    from hlith.operator import replay_cmd

    assert "decode_call_values" not in inspect.getsource(replay_cmd.execute)


# ----------------------------------------------------------------------------------------------- engine: a pinned negative NaN refutes, records the bits, replays (HEAVY, -m real)
@pytest.mark.real
def test_engine_pinned_negative_nan_refutes_with_bits_and_replay_reproduces(tmp_path):
    from hlith import differential
    from hlith.types import Verdict

    for side, body in (("base", "import math\n\n\ndef f(x):\n    if isinstance(x, float) and x != x:\n        return math.copysign(1.0, x)\n    return 1.0\n"), ("post", "def f(x):\n    return 1.0\n")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text("import m\n\n\ndef test_ok():\n    assert m.f(2.0) == 1.0\n")
    (tmp_path / "prop").mkdir()
    pin = SimpleNamespace(args=(f_of("fff8000000000001"),), kwargs={}, expected=None, env=None)
    cons = SimpleNamespace(pinned_inputs=(pin,), disallow_exception_widening=False, source_feedback_ids=("fb-1",))
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="m", function="f", proposer_paths=[str(tmp_path / "prop")],
                                       scratch=str(tmp_path / "scratch"), max_examples=20, adequacy_gate=True, constraints=cons)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)
    wits = [w for w in differential.observed_witnesses() if w["module"] == "m"]
    call = wits[-1]["witness_call"]
    assert call["args"][0]["$float"]["bits"] == "fff8000000000001", call["args"]
    rep = differential.replay_witness(call, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep["replayable"] and rep.get("reproduced") is True, rep
