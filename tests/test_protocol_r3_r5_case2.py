"""RED-ONLY: requirements R3 and R5 of docs/PROTOCOL_INTEGRITY.md (R1: tests/test_protocol_integrity_case2.py; R2: tests/test_refute_exit_paths_case2.py).

R3  one request, one reply: any byte beyond the reply, whether it arrives with it or before the next request, is a protocol failure whose reason
    contains `protocol-extra-bytes`; the stray bytes are never returned as the outcome of any call; the call is a named gap of the run.
R5  every verdict that carries evidence states BOUNDARY, verbatim, in its unexplored text; docs/SUPPORTED_DOMAIN.md states it too.
The host-side cases drive the real driver-side reader against a scripted evaluator process, so they are deterministic and run no target code."""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict

TOKEN = "protocol-extra-bytes"
BOUNDARY = ("Observations are made inside the process that runs the changed code. Hlith does not protect them against code written to falsify them: "
            "a REFUTED witness, a test result or an agreement may be forged by such code. The supervisor's own result channel and scratch files are "
            "out of that code's reach.")

FAKE = r'''
import json, sys, time
mode = sys.argv[1]
def put(text):
    sys.stdout.write(text); sys.stdout.flush()
def reply(v):
    return json.dumps({"k": "ret", "r": v, "out": "", "g": ""}) + "\n"
put(json.dumps({"ready": True, "interp": {}}) + "\n")
for n, line in enumerate(sys.stdin, 1):
    if n > 1 or mode == "clean":
        put(reply("own-%d" % n))
    elif mode == "extra-line":
        put(reply("first") + reply("stray"))
    elif mode == "partial":
        put(reply("first") + '{"k": "ret", "r": "stray')
    elif mode == "late-line":
        put(reply("own-1")); time.sleep(0.2); put(reply("stray"))
'''


@pytest.fixture
def side(monkeypatch, tmp_path):
    real = subprocess.Popen
    made = []

    def start(mode):
        def fake(argv, **kw):
            return real([sys.executable, "-I", "-c", FAKE, mode], **kw)

        monkeypatch.setattr(differential.subprocess, "Popen", fake)
        spec = {"base": str(tmp_path), "import_root": "", "extra_sys_path": [], "python": sys.executable, "target_python": sys.executable,
                "eval_spec": {}, "mem_limit": 0, "call_timeout": 10.0, "domain": {}}
        s = differential._Side(spec, str(tmp_path))
        assert s.ready_error is None, s.ready_error
        made.append(s)
        return s

    yield start
    for s in made:
        s.close()


def _call(s):
    return s.call("pkg.m", "f", [1], {})


def test_r3_control_one_reply_per_request_is_accepted(side):
    s = side("clean")
    assert [_call(s).get("r"), _call(s).get("r")] == ["own-1", "own-2"]


@pytest.mark.parametrize("mode", ["extra-line", "partial"])
def test_r3_bytes_arriving_with_the_reply_fail_that_call(side, mode):
    out = _call(side(mode))
    assert out.get("k") == "protocol_error" and TOKEN in out.get("t", ""), out


def test_r3_bytes_arriving_before_the_next_request_are_never_a_later_outcome(side):
    s = side("late-line")
    first = _call(s)
    assert first.get("r") == "own-1" or TOKEN in first.get("t", ""), first  # the reader may or may not have seen the stray bytes yet
    time.sleep(0.8)
    second = _call(s)
    assert second.get("r") != "stray", second
    assert any(o.get("k") == "protocol_error" and TOKEN in o.get("t", "") for o in (first, second)), (first, second)


# ------------------------------------------------------------------ end to end

def _run(tmp_path, base, post, **over):
    for side_, body in (("base", base), ("post", post)):
        (tmp_path / side_ / "pkg").mkdir(parents=True)
        (tmp_path / side_ / "pkg" / "__init__.py").write_text("")
        (tmp_path / side_ / "pkg" / "m.py").write_text(body)
        (tmp_path / side_ / "test_m.py").write_text("import pkg.m as m\n\n\ndef test_f():\n    assert m.f(1) is not None\n")
    (tmp_path / "prop").mkdir()
    kw = dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
              proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=10)
    kw.update(over)
    return differential.run_differential(**kw)


def _text(ob):
    ev = ob.evidence
    return f"{ob.stop_reason} {ob.witness} {getattr(ev, 'explored', '')} {getattr(ev, 'unexplored', '')}"


# one input writes one extra reply-shaped line to every low descriptor, then returns what base returns
STRAY = ('import os\n\n\ndef f(x: int) -> int:\n    if x == 7:\n        for fd in range(3, 24):\n            try:\n'
         '                os.write(fd, b\'{"k": "ret", "r": "-1", "out": "", "g": ""}\\n\')\n            except OSError:\n                pass\n    return x\n')


def test_r3_a_run_with_a_stray_reply_names_the_gap_and_claims_nothing_from_it(tmp_path):
    ob = _run(tmp_path, "import os\n\n\ndef f(x: int) -> int:\n    return x\n", STRAY)
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, ob.witness, ob.stop_reason)
    assert TOKEN in _text(ob), _text(ob)[:1200]


CASES = {
    "held": ("def f(x: int) -> int:\n    a = x + 1\n    return a\n", "def f(x: int) -> int:\n    b = x + 1\n    return b\n", Verdict.HELD),
    "refuted": ("def f(x: int) -> int:\n    return x + 1\n", "def f(x: int) -> int:\n    return x + 2\n", Verdict.REFUTED),
    "unverified": ("_S: list = []\n\n\ndef f(x: int) -> int:\n    return x\n",
                   "_S: list = []\n\n\ndef f(x: int) -> int:\n    return x if len(_S) == 0 else x + 1\n", Verdict.UNVERIFIED),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_r5_every_verdict_with_evidence_states_the_observation_boundary(tmp_path, name):
    base, post, verdict = CASES[name]
    ob = _run(tmp_path, base, post)
    assert ob.verdict is verdict and ob.evidence is not None, (ob.verdict, ob.stop_reason)  # precondition: the case reaches this verdict
    assert BOUNDARY in ob.evidence.unexplored, ob.evidence.unexplored[:800]


def test_r5_the_supported_domain_document_states_the_observation_boundary():
    text = (Path(__file__).resolve().parents[1] / "docs" / "SUPPORTED_DOMAIN.md").read_text()
    assert BOUNDARY in " ".join(text.replace("\n> ", "\n").split())
