"""Every runtime path that can emit REFUTED reproduces itself first (differential witness, impacted-test failure, caller observation, standalone replay),
end to end through `run_differential` where possible. Run-dependent noise is made deterministic: the confined test process reads its own command line,
which names the run (recording / first run vs confirmation run), so "differs the first time only" needs no luck."""

import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from hlith import differential, sandbox
from hlith.types import Verdict

CORE = ("import threading\n\n\ndef _run():\n    with open('/proc/self/cmdline', 'rb') as f:\n        return f.read().decode('utf-8', 'replace')\n\n\n"
        "class Pump:\n    def __init__(self):\n        self.gate = None\n        self.width = 0\n        self.total = 0\n\n"
        "    def push(self, n):\n        with self.gate:\n            %s\n        return self.total\n")
TEST = ("import threading\nimport pkg.m as core\n\n\ndef test_push():\n    p = core.Pump()\n    p.gate = threading.Lock()\n    p.width = 3\n"
        "    %s\n")
SOFT = "assert p.push(2) is not None"
HARD = "assert p.push(2) == 6"
NODES = [{"node_id": "test_m.py::test_push", "reaches": ["test_m.test_push", "pkg.m.Pump.push"]}]
PLAIN = "self.total += n * self.width"
RENAMED = "step = n * self.width\n            self.total += step"
BROKEN = "self.total += n * self.width if n != 2 else 0"
# noise that depends on the run, not on the source: only the post tree's FIRST runs see it
NOISY = "self.total += n * self.width + (1 if '/post' in _run() and 'confirm' not in _run() else 0)"
FLAKY = "self.total += 0 if ('confirm' not in _run() and n == 2) else n * self.width"


def run(tmp_path, base, post, test=SOFT):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(CORE % body)
        (tmp_path / side / "test_m.py").write_text(TEST % test)
    (tmp_path / "prop").mkdir()
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Pump.push",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=20,
                                       impacted_test_nodes=NODES, adequacy_gate=True)
    ev = getattr(ob, "evidence", None)
    return ob, f"{ob.witness} {ob.stop_reason} {getattr(ev, 'explored', '')} {getattr(ev, 'unexplored', '')}"


def test_caller_observation_pure_rename_with_run_noise_is_not_refuted(tmp_path):
    ob, text = run(tmp_path, PLAIN, NOISY)
    assert ob.verdict is Verdict.UNVERIFIED and "unstable" in text, (ob.verdict, text[:900])


def test_caller_observation_deterministic_regression_stays_refuted(tmp_path):
    ob, text = run(tmp_path, PLAIN, BROKEN)
    assert ob.verdict is Verdict.REFUTED and "reproduced" in text, (ob.verdict, text[:900])


def test_caller_observation_flaky_regression_is_unverified_unstable(tmp_path):
    ob, text = run(tmp_path, PLAIN, FLAKY)
    assert ob.verdict is Verdict.UNVERIFIED and "unstable" in text, (ob.verdict, text[:900])


def test_pure_rename_stays_not_refuted(tmp_path):
    ob, text = run(tmp_path, PLAIN, RENAMED)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, text[:900])


def test_impacted_test_deterministic_failure_stays_refuted(tmp_path):
    ob, text = run(tmp_path, PLAIN, BROKEN, HARD)
    assert ob.verdict is Verdict.REFUTED and "impacted-test/v1" in str(ob.witness), (ob.verdict, text[:900])
    assert "reproduced" in text, text[:900]


def test_impacted_test_flaky_failure_is_unverified_unstable(tmp_path):
    ob, text = run(tmp_path, PLAIN, FLAKY, HARD)
    assert ob.verdict is Verdict.UNVERIFIED and "unstable" in text, (ob.verdict, text[:900])


def test_a_test_needing_loopback_networking_is_named_unverified(tmp_path):
    needs = "import socket\n    s = socket.socket()\n    s.bind(('127.0.0.1', 0))\n    assert p.push(2) == 6"
    ob, text = run(tmp_path, PLAIN, PLAIN + "  # same", needs)
    assert ob.verdict is Verdict.UNVERIFIED and "loopback networking unavailable in confinement" in text, (ob.verdict, text[:900])


RACY = ("import threading\nimport time\n\n\ndef f(x: int):\n    %(n)s = threading.Event()\n    t = threading.Thread(target=lambda: (time.sleep(0.001), %(n)s.set()))\n"
        "    t.start()\n    t.join(0.001)\n    return (x * 2, %(n)s.is_set())\n")


@pytest.mark.parametrize("trial", range(5))
def test_independent_racy_thread_pure_rename_is_never_refuted(tmp_path, trial):
    # independent verification's falsifier (a timing race returned by the target, the change renames one local)
    ob = _synthetic(tmp_path, RACY % {"n": "flag"}, RACY % {"n": "done"})
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, str(ob.witness)[:600])


@pytest.mark.parametrize("during_a_test", [False, True])
def test_only_a_test_that_uses_loopback_is_recorded(tmp_path, during_a_test):
    code = differential._LOOPBACK_HOOK + ("import socket\ntry:\n    socket.socket().bind(('127.0.0.1', 0))\nexcept OSError:\n    pass\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}
    if during_a_test:
        env["PYTEST_CURRENT_TEST"] = "test_m.py::test_f (call)"
    junit = tmp_path / "junit.xml"
    subprocess.run([sys.executable, "-I", "-c", code, "a", "b", str(junit)], env=env, check=True, timeout=60)
    marker = Path(str(junit) + ".loopback")
    # a running test's attempt blocks that test; an attempt outside any test and outside any import covers the whole slice (a library's own
    # import-time probe, the only uncounted kind, is covered end to end in test_loopback_attribution_case3.py)
    assert marker.read_text() == ("node\ttest_m.py::test_f\n" if during_a_test else "all\toutside any test\n")


def _synthetic(tmp_path, base, post):
    for side, text in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(text)
        (tmp_path / side / "test_m.py").write_text("import pkg.m as m\n\n\ndef test_f():\n    assert m.f(1) is not None\n")
    (tmp_path / "prop").mkdir()
    return differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
                                         proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=20)


def test_differential_witness_deterministic_divergence_stays_refuted_and_reproduced(tmp_path):
    ob = _synthetic(tmp_path, "def f(x: int) -> int:\n    return x + 1\n", "def f(x: int) -> int:\n    return x + 2\n")
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)
    gate = json.loads((tmp_path / "scratch" / "witness-gate.json").read_text())
    assert gate["status"] == "reproduced" and gate["runs_per_side"] >= 3, gate
    assert "unstable-unchecked" not in ob.witness


def _scripted(monkeypatch, pre, post):
    script, count = {0: list(pre), 1: list(post)}, {"n": 0}

    def fake(argv, profile, **kw):
        side = 0 if count["n"] % 2 == 0 else 1
        count["n"] += 1
        seq = script[side]
        value = seq.pop(0) if len(seq) > 1 else seq[0]
        return types.SimpleNamespace(stdout=json.dumps({"k": "ret", "r": value}) + "\n", stderr="", returncode=0)

    monkeypatch.setattr(sandbox, "run_confined", fake)
    witness = {"module": "pkg.m", "qualname": "f", "args": [1], "kwargs": {}, "env": {}, "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}}
    return witness, count


def test_replay_reproduces_only_when_every_run_agrees(monkeypatch, tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "p").mkdir()
    witness, count = _scripted(monkeypatch, ["1"], ["2"])
    ok = differential.replay_witness(witness, str(tmp_path / "b"), str(tmp_path / "p"))
    assert ok["reproduced"] is True and ok["runs_per_side"] >= 3 and count["n"] >= 6, (ok, count)


@pytest.mark.parametrize("pre,post", [(["1"], ["2", "2", "1", "2"]), (["1", "9", "1"], ["2"])])
def test_replay_of_an_unstable_side_is_not_a_reproduction(monkeypatch, tmp_path, pre, post):
    (tmp_path / "b").mkdir()
    (tmp_path / "p").mkdir()
    witness, _ = _scripted(monkeypatch, pre, post)
    out = differential.replay_witness(witness, str(tmp_path / "b"), str(tmp_path / "p"))
    assert out["reproduced"] is False and out.get("unstable"), out
