# SPDX-License-Identifier: Apache-2.0
"""review 2026-11-21: read_explored_inputs / explored_input_key, the stable accessor to what the gate actually RAN for the primary target (values per parameter, with the
annotation-admission flag), so Layer 5 domain records can pick inputs the gate did NOT explore. Observed, bounded, deterministic, read-only."""

from __future__ import annotations

import textwrap
from pathlib import Path

from hlith import differential
from hlith.types import Verdict

BASE = '''
    def classify(n: int, label: str = "x") -> int:
        return 1 if n > 10 else 0
    '''
POST = BASE.replace("return 1 if n > 10 else 0", "if n > 10:\n            return 1\n        return 0")
TEST = '''
    import m

    def test_it():
        assert m.classify(11) == 1
        assert m.classify(3, "y") == 0
    '''


def _run(tmp_path: Path, base: str = BASE, post: str = POST):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "tests").mkdir(parents=True)
        (tmp_path / side / "m.py").write_text(textwrap.dedent(body))
        (tmp_path / side / "tests" / "test_m.py").write_text(textwrap.dedent(TEST))
    (tmp_path / "prop").mkdir()
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="m", function="classify",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=40, adequacy_gate=True)
    return ob, str(tmp_path / "scratch")


def test_explored_inputs_record_what_ran_per_parameter(tmp_path):
    ob, scratch = _run(tmp_path)
    ex = differential.read_explored_inputs(scratch)
    assert ex is not None and ex["target"] == "m.classify" and ex["calls"] >= 1, ex
    by = {p["name"]: p for p in ex["params"]}
    assert set(by) == {"n", "label"} and by["n"]["annotation"] == "int"
    keys_n = {v["key"] for v in by["n"]["values"]}
    # the repository test's literals and the threshold neighbours were RUN, and the same function that recorded them lets a caller test membership
    assert {differential.explored_input_key(v) for v in (11, 3)} <= keys_n
    assert {differential.explored_input_key(v) for v in (10, 11)} & keys_n  # a boundary value around `n > 10`
    assert differential.explored_input_key(123456789) not in keys_n  # a value the gate did not run is ABSENT, not claimed
    # annotation admission: every int value for an `int` parameter is admitted; no str value is
    assert all(v["admitted"] for v in by["n"]["values"] if v["type"] == "int")
    assert not any(v["admitted"] for v in by["n"]["values"] if v["type"] == "str")
    # bounded and in first-seen order
    assert all(len(p["values"]) <= differential._EXPLORED_MAX_VALUES for p in ex["params"])


def test_explored_inputs_are_deterministic_across_identical_runs(tmp_path):
    a = differential.read_explored_inputs(_run(tmp_path / "a")[1])
    b = differential.read_explored_inputs(_run(tmp_path / "b")[1])
    assert [(p["name"], [v["key"] for v in p["values"]]) for p in a["params"]] == [(p["name"], [v["key"] for v in p["values"]]) for p in b["params"]]


def test_missing_stale_and_symlinked_artifacts_read_as_unknown(tmp_path):
    assert differential.read_explored_inputs(str(tmp_path / "nowhere")) is None
    _, scratch = _run(tmp_path)
    f = Path(scratch) / "explored_inputs.json"
    real = f.read_text()
    f.unlink()
    f.symlink_to(tmp_path / "elsewhere.json")
    (tmp_path / "elsewhere.json").write_text(real)
    assert differential.read_explored_inputs(scratch) is None  # a symlink is never followed
    f.unlink()
    f.write_text("{not json")
    assert differential.read_explored_inputs(scratch) is None


def test_key_is_pure_typed_and_bounded():
    k = differential.explored_input_key
    assert k(1) == k(1) and k(1) != k(1.0) and k(1) != k(True) and k([1]) != k((1,))
    # long values stay DISTINCT and bounded: same head, different length / content => different key
    a, b, c = k("a" * 8193), k("a" * 65539), k("a" * 65538 + "b")
    assert len({a, b, c, k("a" * 65539)}) == 3 and k("a" * 65539) == b
    assert k("a" * 65537) != b and all(len(x) <= 300 for x in (a, b, c)) and "#len=" in b and "#sha256=" in b
    assert len(k("a" * 150)) < 200 and "#" not in k("a" * 150)  # short values are not suffixed
    assert k({"__hlith_default__": True}).startswith("dict:")
    assert k(object()).startswith("object:")  # unserializable values still key deterministically by type


def test_digests_cover_every_distinct_value_so_absence_is_decidable(tmp_path):
    """values[] is a 64-entry sample; digests[] holds EVERY distinct key the gate ran (<=4096), so a candidate can be tested for 'not run'."""
    ob, scratch = _run(tmp_path)
    ex = differential.read_explored_inputs(scratch)
    for p in ex["params"]:
        d = p["digests"]
        assert d == sorted(d) and len(set(d)) == len(d) == p["distinct"] and not p["digests_truncated"], p["name"]
        assert all(len(h) == 32 and int(h, 16) >= 0 for h in d)
        # every sampled value's digest is in the full list, computed by the SAME function from the recorded key
        import hashlib
        assert all(hashlib.sha256(v["key"].encode()).hexdigest()[:32] in set(d) for v in p["values"])
    n = {p["name"]: set(p["digests"]) for p in ex["params"]}
    assert differential.explored_input_digest(11) in n["n"] and differential.explored_input_digest(3) in n["n"]  # the repository test's literals were run
    assert differential.explored_input_digest(123456789) not in n["n"]  # decidable absence
    assert len(differential.explored_input_digest("a" * 70000)) == 32
    assert differential.explored_input_digest("a" * 65537) != differential.explored_input_digest("a" * 65539)


def test_digest_list_exceeds_the_value_sample_and_is_bounded(tmp_path):
    """The reported failure: the gate saw more distinct keys than the 64-entry sample; digests must still list them all, within the 4096 bound."""
    ob, scratch = _run(tmp_path)
    ex = differential.read_explored_inputs(scratch)
    biggest = max(ex["params"], key=lambda p: p["distinct"])
    assert len(biggest["digests"]) == biggest["distinct"] and biggest["distinct"] <= 4096
    if biggest["distinct"] > differential._EXPLORED_MAX_VALUES:
        assert biggest["truncated"] and len(biggest["values"]) == differential._EXPLORED_MAX_VALUES and len(biggest["digests"]) > len(biggest["values"])


def test_more_distinct_keys_than_the_sample_still_decidable_by_digest(tmp_path):
    """review's F2b shape: the gate ran far more distinct keys (here ~300) than the 64-entry sample; absence must still be decidable through digests[]."""
    lits = [f"key{i:02d}" for i in range(40)]
    body = "def pick(s: str) -> int:\n" + "".join(f"    if s == {lit!r}:\n        return {i}\n" for i, lit in enumerate(lits)) + "    return -1\n"
    post = body.replace("    return -1\n", "    return -1 if s else -1\n")
    for side, b in (("base", body), ("post", post)):
        (tmp_path / side / "tests").mkdir(parents=True)
        (tmp_path / side / "m.py").write_text(b)
        (tmp_path / side / "tests" / "test_m.py").write_text("import m\n\ndef test_it():\n    assert m.pick('key03') == 3\n")
    (tmp_path / "prop").mkdir()
    differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="m", function="pick",
                                  proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=40, adequacy_gate=True)
    p = differential.read_explored_inputs(str(tmp_path / "scratch"))["params"][0]
    assert p["distinct"] > differential._EXPLORED_MAX_VALUES and p["truncated"] and len(p["values"]) == differential._EXPLORED_MAX_VALUES
    assert len(p["digests"]) == p["distinct"] and not p["digests_truncated"]  # every distinct key, not the 64 sample
    assert differential.explored_input_digest("key07") in set(p["digests"])  # a program literal was run, though it may not be in the sample
    assert differential.explored_input_digest("zzz-never-run") not in set(p["digests"])
