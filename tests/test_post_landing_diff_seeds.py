# SPDX-License-Identifier: Apache-2.0
"""O3 follow-up (fb-review): the post-landing probe seeds itself with the literals on the landed diff's added lines, so the
approved change's OWN trigger is exercised (A-type landing: covered_by_delta was empty because the probe domain never
reached a quoted string containing backslash-0). Seeds only; the probe runs after the gate decision."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith import feedback as fb
from hlith.runtime import validate_deltas

BASE = 'def unq(filename: str) -> str:\n    if not (filename.startswith(\'"\') and filename.endswith(\'"\')):\n        return filename\n    return filename[1:-1]\n'
GUARD = BASE.replace("    return filename[1:-1]", '    if "\\\\0" in filename:\n        raise ValueError("NUL escape")\n    return filename[1:-1]')
UNRELATED = BASE.replace("    return filename[1:-1]", "    n = len(filename)\n    return filename[1:n - 1]")
DELTA = {"id": "nul-rejected", "symbol": "m.unq", "kind": "exception", "claim": "quoted NUL escape rejected",
         "input_domain": "quoted filename containing \\0", "pre": "decoded", "post": "raises ValueError",
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"},
         "predicate": {"type": "expr", "param": "filename",
                       "expr": "isinstance(filename, str) and filename.startswith('\"') and filename.endswith('\"') and '\\\\0' in filename"}}


@pytest.fixture(autouse=True)
def _bridge():
    from hlith.operator.capabilities import _register_probe_bridge

    _register_probe_bridge(None)


def _git(r, *a):
    return subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True, text=True).stdout


def _landed(tmp_path, post, base=BASE):
    r = tmp_path / "r"
    r.mkdir(parents=True)
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        _git(r, *a)
    (r / "m.py").write_text(base)
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "base")
    (r / "m.py").write_text(post)
    _git(r, "commit", "-qam", "landed")
    return r, _git(r, "diff", "HEAD~1", "HEAD")


def _after(r, diff, *, with_delta):
    ds = validate_deltas([DELTA]) if with_delta else ()
    dec = SimpleNamespace(outcome=SimpleNamespace(value="landed"), landed_commit=_git(r, "rev-parse", "HEAD").strip())
    obs = SimpleNamespace(obligations=[SimpleNamespace(obligation_id="differential:m.unq", target_symbol="m.unq",
                                                       verdict=None, evidence=None)])
    cov: list = []
    before = (dec.outcome.value, dec.landed_commit)
    paths = fb.after_gate(r, dec, obs, source_run_id="run-0123456789ab", deltas=ds, deltas_confirmed=with_delta,
                          covered=cov, effect_diff=diff, python=sys.executable)
    assert (dec.outcome.value, dec.landed_commit) == before  # the probe cannot touch the decision it ran after
    return paths, cov


def test_seed_extraction_pure():
    d = fb._legacy.diff_literal_seeds('+++ b/m.py\n+    if "\\\\0" in filename:\n-    x = "gone"\n+    y = 1\n')
    assert [s["args"][0] for s in d] == ["\\0", '"\\0"', '"a\\0b"']
    assert fb._legacy.diff_literal_seeds("+    n = len(x)\n+    return x[1:n]\n") == []  # control: no literals, no seeds


@pytest.mark.real
def test_landed_guard_trigger_is_exercised_and_reported_as_covered(tmp_path):
    r, diff = _landed(tmp_path, GUARD)
    paths, cov = _after(r, diff, with_delta=True)
    assert [c["covered_by_delta"] for c in cov] == ["nul-rejected"] and cov[0]["count"] >= 1, cov
    assert list(paths) == []  # the approved divergence is reported, not pinned
    # without the diff-literal seeds (old behaviour = no effect_diff) the delta's own trigger is never exercised
    r2, _ = _landed(tmp_path / "again", GUARD)
    _, cov0 = _after(r2, "", with_delta=True)
    assert cov0 == []


@pytest.mark.real
def test_control_unrelated_diff_adds_no_seed_and_no_record(tmp_path):
    r, diff = _landed(tmp_path, UNRELATED)
    paths, cov = _after(r, diff, with_delta=False)
    assert list(paths) == [] and cov == []
    assert fb._legacy.diff_literal_seeds(diff) == []


# --- mutant-killing pins (review): each of these fails if the named filter/cap is dropped ---

def _lits(diff):
    return [s["args"][0] for s in fb._legacy.diff_literal_seeds(diff)]


def test_cap_is_twelve_seeds():
    diff = "".join(f'+    k{i} = "v{i}"\n' for i in range(20))
    assert len(_lits(diff)) == 12


def test_duplicate_literal_is_deduped():
    assert _lits('+    a = "zz"\n+    b = "zz"\n') == ["zz", '"zz"', '"azzb"']


def test_literal_longer_than_40_chars_is_excluded():
    assert _lits('+    a = "%s"\n' % ("x" * 41)) == []
    assert len(_lits('+    a = "%s"\n' % ("x" * 40))) == 3  # boundary control


def test_header_line_literal_is_not_a_seed():
    assert _lits('+++ b/"hdr".py\n') == []


def test_two_param_target_gets_no_diff_seeds(tmp_path, monkeypatch):
    calls = []
    real = fb._legacy.diff_literal_seeds
    monkeypatch.setattr(fb._legacy, "diff_literal_seeds", lambda d, **k: (calls.append(1), real(d, **k))[1])
    r, diff = _landed(tmp_path / "one", GUARD)
    _after(r, diff, with_delta=False)
    assert calls == [1]  # one-parameter target: consulted
    sig = ("def unq(filename: str)", "def unq(filename: str, extra: int = 0)")
    r2, diff2 = _landed(tmp_path / "two", GUARD.replace(*sig), base=BASE.replace(*sig))
    _after(r2, diff2, with_delta=False)
    assert calls == [1]  # two parameters: never consulted


# --- bounded work (review finding 1): the literal regex is quadratic on unterminated quotes ---

def test_huge_single_line_is_skipped_quickly_and_normal_lines_still_seed():
    import time

    t0 = time.perf_counter()
    assert fb._legacy.diff_literal_seeds("+" + '"a\\' * 10_000 + "\n") == []  # 30 KB on one line (under the 64 KB total cap)
    assert time.perf_counter() - t0 < 1.0
    t0 = time.perf_counter()
    assert fb._legacy.diff_literal_seeds("+" + '"a\\' * 40_000 + "\n") == []  # 120 KB on one line
    assert time.perf_counter() - t0 < 1.0
    # the total scanned bytes are capped too: many mid-size lines then a literal past the cap is not scanned
    filler = "".join("+" + "x" * 1000 + "\n" for _ in range(70))
    assert fb._legacy.diff_literal_seeds(filler + '+    a = "late"\n') == []
    assert _lits('+    a = "ok"\n') == ["ok", '"ok"', '"aokb"']  # normal case unchanged


@pytest.mark.real
def test_a_raising_seed_builder_is_isolated_and_the_landing_stands(tmp_path):
    """CLI, fresh interpreter: diff_literal_seeds raising prints 'feedback step failed' and changes neither the exit
    status nor the outcome. (control: same run unpatched)"""
    import json
    import shlex

    def run(sub, patched):
        d = tmp_path / sub
        d.mkdir()
        repo = d / "repo"
        (repo / "pkg").mkdir(parents=True)
        (repo / "pyproject.toml").write_text('[project]\nname = "pkg"\nversion = "1"\n')
        (repo / "pkg" / "__init__.py").write_text("")
        (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n")
        (repo / "tests").mkdir()
        (repo / "tests" / "test_m.py").write_text("from pkg.m import f\n\n\ndef test_f():\n    assert f(1) == 2\n")
        for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"], ["add", "."], ["commit", "-qm", "b"]):
            _git(repo, *a)
        w = d / "w.py"
        w.write_text("import os, json\np='pkg/m.py'\ns=open(p).read()\nopen(p,'w').write(s.replace('x + 1','1 + x'))\n"
                     "open(os.environ['HLITH_MANIFEST_DIR']+'/manifest.json','w').write(json.dumps({'paths': {p: ['modify']}}))\n")
        out = tmp_path / f"{sub}.json"
        src = str(Path(__file__).resolve().parents[1] / "src")
        pre = ("import hlith.feedback._legacy as L\n"
               "def _boom(*a, **k): raise RuntimeError('seed builder boom')\nL.diff_literal_seeds = _boom\n") if patched else ""
        code = (f"import sys; sys.path.insert(0, {src!r})\n{pre}from hlith.cli import main\n"
                f"raise SystemExit(main(['run','--repo',{str(repo)!r},'--worker-cmd',{shlex.join([sys.executable, '-I', str(w)])!r},"
                f"'--worker-ro',{str(d)!r},'--artifact-out',{str(out)!r},'--target-python',{sys.executable!r}]))")
        cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=600)
        return cp, json.loads(out.read_text())

    cp0, art0 = run("ctl", False)
    cp1, art1 = run("boom", True)
    assert "feedback step failed" not in cp0.stderr
    assert art0["outcome"] == "landed", (art0["outcome"], art0["blocking"], [(o["id"], o["verdict"], str(o)[:200]) for o in art0["obligations"]])  # the seed builder is only reached after a landing
    assert "feedback step failed: RuntimeError: seed builder boom" in cp1.stderr, cp1.stderr[-800:]
    assert (cp1.returncode, art1["outcome"], art1["exit_status"]) == (cp0.returncode, art0["outcome"], art0["exit_status"])
    print("outcome:", art0["outcome"])
