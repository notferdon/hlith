"""KL4: 'not-derived' refuses with exit status 11, never lands, and prints zero warning/pass text."""
from __future__ import annotations

import subprocess
from pathlib import Path

from hlith.derive import make_derive
from hlith.gate import decide
from hlith.runtime import ProposedEffect
from hlith.types import EXIT_NOT_DERIVED, GateOutcome, Verdict


def test_kl4_eval_refuses_exit_11_and_no_forbidden_text(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    (repo / "m.py").write_text('def f(x):\n    return eval("x + 1")\n')
    diff = subprocess.run(["git", "-C", str(repo), "diff"], capture_output=True, text=True, check=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "--", "m.py"], check=True)

    obs = make_derive(proposer_paths=())(repo, ProposedEffect(diff, "p1", ("m.py",)))
    dec = decide(obs)
    assert dec.outcome is GateOutcome.REFUSED
    assert dec.exit_status == EXIT_NOT_DERIVED
    assert any(o.verdict is Verdict.NOT_DERIVED for o in obs.obligations)
    assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True, check=True).stdout == ""

    captured = capsys.readouterr()
    combined = (captured.out + captured.err).lower()
    for word in ("warning", "passed", "allowed", "no issues found", "not applicable"):
        assert word not in combined
