# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for --strict-domain CLI flag (hlith check / run) and broadened symbolic counterexample seeding."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from hlith.obligation.symeq.witness import integer_seed


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def _make_repo(root: Path, base_src: str, post_src: str, test_src: str) -> Path:
    repo = root / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "__init__.py").write_text("")
    (repo / "pkg" / "calc.py").write_text(base_src)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calc.py").write_text(test_src)
    for cmd in (("init", "-q"), ("config", "user.email", "t@t"), ("config", "user.name", "t"), ("add", "."), ("commit", "-qm", "base")):
        _git(repo, *cmd)
    (repo / "pkg" / "calc.py").write_text(post_src)
    return repo


def _run_check(repo: Path, state: Path, extra_args: list[str]) -> tuple[int, dict]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("HLITH_")}
    env["HLITH_STATE_DIR"] = str(state)
    cmd = [sys.executable, "-m", "hlith.cli", "check", "--no-input", "--json", "--repo", str(repo), "--uncommitted",
           "--target-python", sys.executable, *extra_args]
    cp = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
    return cp.returncode, json.loads(cp.stdout)


def test_strict_domain_flag_gates_untyped_entry_on_hlith_check_and_admits_guarded_entry(tmp_path):
    base = "def scale(x: int) -> int:\n    return x * 2\n"
    post = "def scale(x: int) -> int:\n    return 2 * x\n"
    test = "from pkg.calc import scale\n\ndef test_scale():\n    assert scale(3) == 6\n"
    repo = _make_repo(tmp_path / "unguarded", base, post, test)

    # Default scoped mode lands rehearsal (rc 0) with exact-builtin int domain claim.
    rc_scoped, pay_scoped = _run_check(repo, tmp_path / "state-scoped", [])
    assert rc_scoped == 0, pay_scoped
    assert pay_scoped["check"]["domain_policy"] == "scoped"

    # --strict-domain refuses unguarded target (rc 12 UNVERIFIED) because no exact-int entry guard exists.
    rc_strict, pay_strict = _run_check(repo, tmp_path / "state-strict", ["--strict-domain"])
    assert rc_strict == 12, pay_strict
    assert pay_strict["check"]["domain_policy"] == "strict"
    assert pay_strict["artifact"]["outcome"] == "refused"

    # With identical leading exact-int entry guards, --strict-domain lands rehearsal (rc 0)!
    g_base = "def scale(x: int) -> int:\n    if type(x) is not int:\n        raise TypeError('int only')\n    return x * 2\n"
    g_post = "def scale(x: int) -> int:\n    if type(x) is not int:\n        raise TypeError('int only')\n    return 2 * x\n"
    g_repo = _make_repo(tmp_path / "guarded", g_base, g_post, test)
    rc_guarded, pay_guarded = _run_check(g_repo, tmp_path / "state-guarded", ["--strict-domain"])
    assert rc_guarded == 0, pay_guarded
    assert pay_guarded["check"]["domain_policy"] == "strict"


def test_broadened_symbolic_countermodel_handles_augassign_abs_and_guard_raises(tmp_path):
    base_src = (
        "def score(a: int, b: int) -> int:\n"
        "    total = abs(a)\n"
        "    total += max(b, 0)\n"
        "    if total == 7319 and a - b == 4123:\n"
        "        return 100\n"
        "    return total\n"
    )
    post_src = base_src.replace("return 100", "raise ValueError('cap')")
    base_p, post_p = tmp_path / "base.py", tmp_path / "post.py"
    base_p.write_text(base_src)
    post_p.write_text(post_src)
    seed = integer_seed(base_p, post_p, "score")
    assert seed is not None, "expected symbolic countermodel seed for augassign + abs + raise regression"
    args, kwargs, origin = seed
    assert origin == "symbolic-countermodel"
    ns_b, ns_p = {}, {}
    exec(base_src, ns_b)
    exec(post_src, ns_p)
    assert ns_b["score"](*args, **kwargs) == 100
    try:
        ns_p["score"](*args, **kwargs)
    except ValueError:
        pass
    else:
        raise AssertionError("post did not raise ValueError on symbolic countermodel seed")
