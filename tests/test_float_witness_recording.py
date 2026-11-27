# SPDX-License-Identifier: Apache-2.0
"""A refutation must never become LOST because of RECORDING (review pin 2026-11-23: differential REFUTES f(-1.5) on an unannotated function, the gate refuses with exit 10, but
recording the artifact raised 'TypeError: not a contract value: float' at coordinator canonical_bytes -> exit 1 LOST before out.json/rc).

The witness_call the differential records is JSON (floats ride as JSON numbers, incl. NaN/Infinity); the contract codec accepts only str/bool/int/None, deliberately. So a float
needs a CONTRACT-SAFE TYPED ENCODING with replay parity: {"$float": {"bits": <16 hex>, "repr": <text>}} (the 8-byte IEEE-754 pattern: bit-exact, NaN sign/payload included; see test_float_bits_end_to_end), decoded back to the SAME float.
Only the exact tag shape is a tag; look-alike dicts are plain data. Unit level only (no slot): the engine path (gate exit 10 + recorded witness + replay REPRODUCED) is test_float_witness_engine_* below (HEAVY: real gate; run behind the resource-bounded slot only)."""

from __future__ import annotations

import json
import math
import struct

import pytest

from hlith.contract import codec

FLOATS = [1.5, -1.5, 0.0, -0.0, 1e308, -1e308, 5e-324, 2.2250738585072014e-308, 0.1, 1 / 3, float("inf"), float("-inf"), float("nan"), 9007199254740993.0]


def bits(x: float) -> bytes:
    return struct.pack(">d", x)


def roundtrip(obj):
    art = {"obligations": [{"witness_call": obj}]}
    raw = codec.canonical_bytes(codec.encode_call_values(art))  # must not raise
    return codec.decode_call_values(json.loads(raw))["obligations"][0]["witness_call"]


@pytest.mark.parametrize("x", FLOATS, ids=[repr(f) for f in FLOATS])
def test_every_float_roundtrips_bit_exactly_through_canonical_bytes(x):
    got = roundtrip({"args": [x], "kwargs": {"k": x}})
    assert isinstance(got["args"][0], float) and isinstance(got["kwargs"]["k"], float)
    assert bits(got["args"][0]) == bits(x) and bits(got["kwargs"]["k"]) == bits(x)


def test_the_raw_float_is_what_the_plain_codec_still_refuses():
    """The codec stays strict (a float is never guessed at a contract boundary); the typed encoding is explicit."""
    with pytest.raises(TypeError):
        codec.canonical_bytes({"a": 1.5})


def test_ints_bools_none_strings_and_nesting_are_untouched():
    w = {"args": [1, True, None, "a", [2, [3.5]], {"x": -0.0}], "kwargs": {}}
    out = roundtrip(w)
    assert out["args"][:4] == [1, True, None, "a"] and out["args"][4][1][0] == 3.5 and bits(out["args"][5]["x"]) == bits(-0.0)
    assert type(out["args"][1]) is bool and type(out["args"][0]) is int


@pytest.mark.parametrize("d", [{"$float": "1.5"}, {"$float": "x"}, {"$lit": 1}, {"$float": {"bits": "zz", "repr": "q"}}])
def test_a_dict_that_only_looks_like_a_tag_is_plain_data_and_round_trips(d):
    assert roundtrip({"args": [d], "kwargs": {}})["args"][0] == d


def test_the_encoding_is_deterministic_and_distinguishes_values():
    a = codec.canonical_bytes(codec.encode_call_values({"v": [0.0]}))
    b = codec.canonical_bytes(codec.encode_call_values({"v": [-0.0]}))
    assert a != b and a == codec.canonical_bytes(codec.encode_call_values({"v": [0.0]}))
    assert codec.sha256_canonical(codec.encode_call_values({"v": [1.0]})) != codec.sha256_canonical(codec.encode_call_values({"v": [1]}))  # 1.0 is not 1


def test_attach_witness_calls_yields_a_serializable_artifact_for_a_float_witness(monkeypatch):
    from hlith import differential
    from hlith.operator import coordinator

    entry = {"scratch": "s", "module": "m", "qualname": "f", "import_root": "", "extra_sys_path": [], "target_python_arg": None,
             "witness_call": {"module": "m", "qualname": "f", "args": [-1.5], "kwargs": {}, "env": None, "inject": None, "receiver": None,
                              "pre": {"k": "exc", "t": "builtins.AttributeError"}, "post": {"k": "exc", "t": "builtins.TypeError"}, "oracle": "x"}}
    monkeypatch.setattr(differential, "observed_witnesses", lambda: [entry])

    class _Res:
        base = None

    art = {"obligations": [{"verdict": "refuted", "target_symbol": "m.f"}], "run": {}, "effect": {"patch_sha256": "0" * 64}}
    coordinator._attach_witness_calls(art, "c0ffee", _Res(), None)
    raw = codec.canonical_bytes(art)  # the line that raised 'not a contract value: float' and made the run LOST
    back = codec.decode_call_values(json.loads(raw))
    assert back["obligations"][0]["witness_call"]["args"] == [-1.5]


def test_replay_reproduces_a_float_witness_standalone(tmp_path):
    """Replay parity: the DECODED recorded witness replays and reproduces (f(-1.5): base AttributeError vs post TypeError)."""
    from hlith import differential

    for side, body in (("base", "def f(x):\n    return x.real_part\n"), ("post", "def f(x):\n    return x + 'a'\n")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(body)
    wit = {"module": "m", "qualname": "f", "args": [-1.5], "kwargs": {}, "env": None, "inject": None, "receiver": None,
           "pre": {"k": "exc", "t": "builtins.AttributeError"}, "post": {"k": "exc", "t": "builtins.TypeError"}}
    recorded = codec.decode_call_values(json.loads(codec.canonical_bytes(codec.encode_call_values({"w": wit}))))["w"]
    rep = differential.replay_witness(recorded, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep["replayable"] and rep.get("reproduced") is True, rep


def test_nan_inf_negative_zero_survive_replay_encoding():
    wit = {"args": [float("nan"), float("inf"), -0.0], "kwargs": {}}
    out = roundtrip(wit)["args"]
    assert math.isnan(out[0]) and out[1] == math.inf and bits(out[2]) == bits(-0.0)


# ================================================================================================ engine level (HEAVY, ~1-2 min; run behind the single resource-bounded slot)
BASE_F = "def f(x):\n    return x\n"
POST_F = "def f(x):\n    if isinstance(x, float):\n        raise TypeError('float')\n    return x\n"


def _gate_with_float_divergence(tmp_path):
    import os
    import subprocess
    import sys

    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "pkg/__init__.py").write_text("")
    (repo / "pkg/m.py").write_text(BASE_F)
    (repo / "tests/test_m.py").write_text("from pkg.m import f\n\n\ndef test_0():\n    assert f(3) == 3\n")
    for a in (["add", "."], ["commit", "-qm", "base"]):
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)
    (repo / "pkg/m.py").write_text(POST_F)
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    env = {**os.environ, "HOME": str(home), "XDG_STATE_HOME": str(home / "state"), "HLITH_STATE_DIR": str(home / "state/host"), "PYTHONPATH": os.pathsep.join(sys.path)}
    r = subprocess.run([sys.executable, "-m", "hlith.operator.cli", "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json"], capture_output=True, text=True, env=env, timeout=420)
    return repo, home, env, r


@pytest.mark.real  # opt-in tier (-m real): the real gate, behind the resource-bounded slot
def test_float_witness_engine_refusal_is_exit_10_with_a_recorded_witness_and_replay_reproduces(tmp_path):
    import pathlib
    import subprocess
    import sys

    repo, home, env, r = _gate_with_float_divergence(tmp_path)
    assert r.returncode == 10, (r.returncode, r.stdout[-300:], r.stderr[-300:])  # REFUTED: never exit 1 LOST because recording a float failed
    outs = sorted(pathlib.Path(home).rglob("out.json"))
    rcs = sorted(pathlib.Path(home).rglob("rc"))
    assert outs and rcs and rcs[-1].read_text().strip() == "10", (outs, rcs)
    art = json.loads(outs[-1].read_text())
    row = next(o for o in art["obligations"] if o.get("verdict") == "refuted")
    assert isinstance(row.get("witness_call"), dict) and "$float" in json.dumps(row["witness_call"]), row.get("witness_call")
    rep = subprocess.run([sys.executable, "-m", "hlith.operator.cli", "replay", str(outs[-1].parent), "--repo", str(repo), "--unconfined", "--json"], capture_output=True, text=True, env=env, timeout=300)
    assert rep.returncode == 0 and "REPRODUCED" in rep.stdout and "NOT REPRODUCED" not in rep.stdout, (rep.returncode, rep.stdout[-400:], rep.stderr[-300:])
