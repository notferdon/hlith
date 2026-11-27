# SPDX-License-Identifier: Apache-2.0
"""Warnings channel (design policy): warnings emitted by a call are behaviour, on the direct and the entry path.

Predeclared (written before the first run):
  * a deterministic pre != post difference in the target's OWN warnings (category + message) -> REFUTED, the witness says
    what post emits and what pre emits;
  * an equivalent edit that emits the same warning on both sides -> not refuted;
  * a warning of OTHER origin (ResourceWarning class / third party) never makes a witness: a difference there is not a
    refutation;
  * a flaky own warning (differs between a side's own two runs) is never a witness (named 'nondeterministic' loss);
  * a declared-delta-free 'adds a warning' edit is refused (known limit: the delta grammar cannot declare it yet).
"""
from hlith import differential
from hlith.types import Verdict

_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"


def _world(tmp_path, base, post):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
                proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=120,
                max_examples=15, adequacy_gate=True)


_BASE = "import warnings\n\n\ndef f(x: int) -> int:\n    return x + 1\n"
_WARN = ("import warnings\n\n\ndef f(x: int) -> int:\n"
         "    warnings.warn('f is deprecated', DeprecationWarning)\n    return x + 1\n")


def test_added_deprecation_warning_is_refuted_with_a_stated_witness(tmp_path):
    ob = differential.run_differential(**_world(tmp_path, _BASE, _WARN))
    assert ob.verdict is Verdict.REFUTED, ob
    assert "DeprecationWarning" in ob.witness and "f is deprecated" in ob.witness, ob.witness
    assert "post emits" in ob.witness and "pre emits none" in ob.witness, ob.witness


def test_same_warning_on_both_sides_is_not_refuted(tmp_path):
    base = _WARN
    post = _WARN.replace("return x + 1", "return 1 + x")
    ob = differential.run_differential(**_world(tmp_path, base, post))
    assert ob.verdict is not Verdict.REFUTED, ob


def test_resource_warning_class_difference_is_never_a_witness(tmp_path):
    post = ("import warnings\n\n\ndef f(x: int) -> int:\n"
            "    warnings.warn('gc timing', ResourceWarning)\n    return x + 1\n")
    ob = differential.run_differential(**_world(tmp_path, _BASE, post))
    assert ob.verdict is not Verdict.REFUTED, ob


def test_flaky_own_warning_is_never_a_witness(tmp_path):
    flaky = ("import warnings, time\n\n\ndef f(x: int) -> int:\n"
             "    if time.time_ns() % 2:\n        warnings.warn('odd', DeprecationWarning)\n    return x + 1\n")
    ob = differential.run_differential(**_world(tmp_path, _BASE, flaky))
    assert ob.verdict is not Verdict.REFUTED, ob


def test_warning_witness_replays_standalone(tmp_path):
    kw = _world(tmp_path, _BASE, _WARN)
    ob = differential.run_differential(**kw)
    assert ob.verdict is Verdict.REFUTED, ob
    import json
    wit = json.loads((tmp_path / "scratch" / "witness.json").read_text())
    rep = differential.replay_witness(wit, str(tmp_path / "base"), str(tmp_path / "post"), confined=True)
    assert rep.get("diverges") is True, rep
    assert "DeprecationWarning" in json.dumps(rep["post"]) and not rep["pre"].get("w"), rep
