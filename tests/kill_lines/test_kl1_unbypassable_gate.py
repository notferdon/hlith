"""KL1: Gate cannot be bypassed by direct write, shell redirect, or fd write."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from hlith import sandbox
from hlith.gate import decide, land
from hlith.runtime import ProposedEffect
from hlith.types import GateOutcome, Obligation, ObligationSet, Verdict


def test_kl1_confined_writes_fail_and_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.name", "t"], check=True)
    (target / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(["git", "-C", str(target), "commit", "-qm", "init"], check=True)

    probe = (
        f"import os, subprocess; p = {str(target / 'pwned.py')!r}\n"
        "try:\n"
        "    open(p, 'w').write('x')\n"
        "    raise SystemExit(99)\n"
        "except OSError:\n"
        "    pass\n"
        f"r = subprocess.run('echo pwn > ' + p, shell=True)\n"
        "assert r.returncode != 0\n"
    )
    res = sandbox.run_confined([sys.executable, "-c", probe], sandbox.Profile(ro=(str(target),)))
    assert res.returncode == 0, res.stderr
    assert not (target / "pwned.py").exists()
    assert subprocess.run(["git", "-C", str(target), "status", "--porcelain"], capture_output=True, text=True, check=True).stdout == ""


def test_kl1_refused_gate_never_lands(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.name", "t"], check=True)
    (target / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(["git", "-C", str(target), "commit", "-qm", "init"], check=True)
    head_before = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

    obls = ObligationSet((Obligation("o1", "a.x", "c", Verdict.REFUTED, witness="a.x(0)"),))
    eff = ProposedEffect("diff --git a/a.py b/a.py\n", "p1", ("a.py",))
    dec = decide(obls)
    assert dec.outcome is GateOutcome.REFUSED
    dec_land = land(target, eff, obls, expected_tree="0" * 40, verified_patch_sha256=eff.patch_sha256, expected_identity=(0, 0))
    assert dec_land.outcome is GateOutcome.REFUSED
    head_after = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    assert head_after == head_before
