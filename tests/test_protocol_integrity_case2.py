"""Protocol integrity boundary (case, docs/PROTOCOL_INTEGRITY.md). Two enforced properties and one containment property:
  I1 (kernel) an evaluator layered as the driver layers it cannot reach the supervising process (its descriptors, its memory, signals);
  I2 (kernel) that evaluator cannot write the driver's scratch (partial witness, witness, phase records);
  I3 (containment) a change whose own code writes the evaluator's protocol descriptor never obtains HELD;
  I4 (containment, RED on d60d0c78) such a change never yields a witness labelled reproduced whose values the code does not produce.
Each kernel test has a control showing the same attempt succeeds without the layer, so a pass is not vacuous. Everything stays inside one sandbox."""

import json
import re
import sys
from pathlib import Path

import pytest

import hlith
from hlith import differential, sandbox
from hlith.types import Verdict

DIFF = str(Path(differential.__file__).resolve())

CHILD = r'''
import json, os, signal, sys
scr, ppid = sys.argv[1], os.getppid()
def attempt(f):
    try:
        f()
        return "reached"
    except OSError as e:
        return "denied:" + type(e).__name__
out = {"fd": attempt(lambda: os.close(os.open(f"/proc/{ppid}/fd/1", os.O_WRONLY))),
       "mem": attempt(lambda: os.close(os.open(f"/proc/{ppid}/mem", os.O_RDONLY))),
       "signal": attempt(lambda: os.kill(ppid, 0)),
       "scratch": attempt(lambda: open(os.path.join(scr, "partial-witness.json"), "x").close())}
print(json.dumps(out))
'''

PARENT = r'''
import json, os, subprocess, sys
diff, scr, spec, child, layered = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] == "1"
argv = [sys.executable, "-I", "-c", child, scr]
if layered:
    argv = [sys.executable, "-I", diff, "stack", spec, "--", *argv]
cp = subprocess.run(argv, capture_output=True, text=True, timeout=60)
sys.stdout.write(cp.stdout or json.dumps({"error": cp.stderr[-600:], "rc": cp.returncode}))
'''


def _probe(tmp_path, layered: bool) -> dict:
    scr = tmp_path / "scratch"
    scr.mkdir()
    ro = tuple(dict.fromkeys([str(Path(sys.prefix).resolve()), str(Path(sys.base_prefix).resolve()), str(Path(hlith.__file__).resolve().parents[1])]))
    outer = sandbox.Profile(ro=ro, rw=(str(scr),))
    inner = sandbox.Profile(ro=ro, rw=())
    cp = sandbox.run_confined([sys.executable, "-I", "-c", PARENT, DIFF, str(scr), json.dumps(inner.spec()), CHILD, "1" if layered else "0"],
                              outer, cwd=str(scr), timeout=90)
    assert cp.stdout.strip(), (cp.returncode, cp.stderr[-800:])
    got = json.loads(cp.stdout.strip().splitlines()[-1])
    assert "error" not in got, got
    return got


def test_i1_layered_evaluator_cannot_reach_the_supervisor(tmp_path):
    got = _probe(tmp_path, layered=True)
    assert all(got[k].startswith("denied") for k in ("fd", "mem", "signal")), got


def test_i2_layered_evaluator_cannot_write_the_driver_scratch(tmp_path):
    got = _probe(tmp_path, layered=True)
    assert got["scratch"].startswith("denied"), got


def test_control_without_the_inner_layer_the_same_attempts_succeed(tmp_path):
    got = _probe(tmp_path, layered=False)
    assert got["fd"] == "reached" and got["signal"] == "reached" and got["scratch"] == "reached", got


FORGE = ('import os\n\n\ndef f(x: int) -> int:\n    for fd in range(3, 24):\n        try:\n'
         '            os.write(fd, b\'{"k": "ret", "r": "%d", "out": "", "g": ""}\\n\' % x)\n        except OSError:\n            pass\n    return x + 1\n')


def _forged_run(tmp_path):
    for side, body in (("base", "import os\n\n\ndef f(x: int) -> int:\n    return x\n"), ("post", FORGE)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_m.py").write_text("import pkg.m as m\n\n\ndef test_f():\n    assert m.f(1) is not None\n")
    (tmp_path / "prop").mkdir()
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=10)
    return ob


def test_i3_a_change_that_writes_the_protocol_descriptor_is_never_held(tmp_path):
    ob = _forged_run(tmp_path)
    assert ob.verdict is not Verdict.HELD, ob


def test_i4_a_forged_or_desynchronised_witness_is_never_labelled_reproduced(tmp_path):
    ob = _forged_run(tmp_path)
    got = re.search(r"x=(-?\d+)\): pre -> return (-?\d+); post -> return (-?\d+)", ob.witness or "")
    gate = tmp_path / "scratch" / "witness-gate.json"
    if ob.verdict is Verdict.REFUTED and got and int(got.group(3)) != int(got.group(1)) + 1:  # a value this post code never returns
        assert json.loads(gate.read_text())["status"] != "reproduced", (ob.witness, gate.read_text())
