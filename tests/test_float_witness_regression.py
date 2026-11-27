# SPDX-License-Identifier: Apache-2.0
"""Minimal RED regression test for float witness arguments crashing coordinator/feedback JSON encoding.

Observed on `re_prefix_shortcircuit_equivalent`: when differential refutes an unannotated function on a Python
`float` input and records `witness_call`, `codec.canonical_bytes(artifact)` (coordinator.py:251) and
FeedbackService recording (feedback/store.py:128 -> codec.plain) raise `TypeError: not a contract value: float`,
turning a valid exit-10 REFUTED run into exit-1 LOST.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_refuted_float_witness_returns_exit_10_and_records_witness(tmp_path: Path) -> None:
    """A REFUTED run whose sole refuting witness input is a float must exit 10 REFUTED with a recorded witness, not exit 1 LOST."""
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "pkg/__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg/m.py").write_text(
        "def f(x):\n    if isinstance(x, float):\n        return 1\n    return 0\n",
        encoding="utf-8",
    )
    (repo / "tests/test_m.py").write_text(
        "from pkg.m import f\n\ndef test_benign():\n    assert f('ok') == 0\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "pkg/m.py").write_text(
        "def f(x):\n    if isinstance(x, float):\n        return 2\n    return 0\n",
        encoding="utf-8",
    )

    home = tmp_path / "home"
    state_dir = home / "state" / "host"
    state_dir.mkdir(parents=True)
    state_dir.chmod(0o700)
    env = {
        **os.environ,
        "HOME": str(home),
        "XDG_STATE_HOME": str(home / "state"),
        "HLITH_STATE_DIR": str(state_dir),
        "PYTHONPATH": os.pathsep.join(sys.path),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    assert proc.returncode == 10, f"expected exit 10 REFUTED, got {proc.returncode}: {(proc.stdout or proc.stderr)[:400]}"
    payload = json.loads(proc.stdout)
    artifact = payload.get("artifact") or {}
    assert artifact.get("outcome") == "refused"
    assert artifact.get("exit_status") == 10
    assert artifact.get("feedback_errors") == []
    refuted_rows = [o for o in artifact.get("obligations", []) if o.get("verdict") == "refuted"]
    assert len(refuted_rows) == 1
    assert refuted_rows[0].get("witness"), "expected recorded witness text"
    assert isinstance(refuted_rows[0].get("witness_call"), dict) and refuted_rows[0]["witness_call"]


def test_feedback_store_accepts_typed_float_tag(tmp_path: Path) -> None:
    """feedback/store.py:128 (canonical_bytes) accepts review's explicit {'$float': text} tag and round-trips it."""
    from hlith.feedback._legacy import pin_regression_counterexample
    from hlith.feedback.store import load_stored_records, persist_record

    store_dir = tmp_path / "fb"
    rec = pin_regression_counterexample(
        "run-000000000001",
        "pkg.m.f",
        [{"$float": "-1.5"}],
        {},
        expected={"kind": "return", "repr": "True"},
        observed={"kind": "raise", "exc": "TypeError"},
    )
    path = persist_record(store_dir, rec)
    assert path.is_file()
    loaded = load_stored_records(store_dir)
    assert len(loaded) == 1
    assert loaded[0].record.directive_payload["input"]["args"] == [{"$float": "-1.5"}]


def test_feedback_pin_raw_float_must_not_fail_store_persist(tmp_path: Path) -> None:
    """RED: raw float args passed from differential/probe.py:128 into pin_regression_counterexample crash store.py:128."""
    from hlith.feedback._legacy import pin_regression_counterexample
    from hlith.feedback.store import load_stored_records, persist_record

    store_dir = tmp_path / "fb_raw"
    rec = pin_regression_counterexample(
        "run-000000000002",
        "pkg.m.f",
        [-1.5],
        {},
        expected={"kind": "return", "repr": "True"},
        observed={"kind": "raise", "exc": "TypeError"},
    )
    path = persist_record(store_dir, rec)
    assert path.is_file()
    loaded = load_stored_records(store_dir)
    assert len(loaded) == 1

