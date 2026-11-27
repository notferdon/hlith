"""A hostile-config repository is refused BEFORE any recovery journal is read: the refusal must say so, never claim 'an interrupted landing' (review finding on G1)."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("_f1_cli", _HERE / "test_feedback_f1_cli_cross_process_case2.py")
f1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(f1)


def test_hostile_config_refusal_does_not_claim_an_interrupted_landing(tmp_path):
    src = f1._source(tmp_path / "source")
    repo = f1._clone(src, tmp_path / "r")
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", "/bin/true"], check=True)
    rc, art, log = f1._cli(tmp_path, "h", repo, f1.RUN1, tmp_path / "state")
    assert rc == 4, (rc, log)
    assert "core.fsmonitor" in log and "refused before any run or recovery" in log, log
    assert "interrupted landing" not in log, log
