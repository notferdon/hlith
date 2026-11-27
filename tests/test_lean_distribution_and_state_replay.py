# SPDX-License-Identifier: Apache-2.0
"""Lean default Review distribution metadata, optional [agent] fail-closed checks, and standalone replay StateWatch parity."""
from __future__ import annotations

import importlib.metadata as md
import tomllib
from pathlib import Path

import pytest

from hlith import differential
from hlith.agent import checkpoint
from hlith.agent.errors import RuntimeBoundary

ROOT = Path(__file__).resolve().parents[1]


def test_default_review_dependencies_exclude_langgraph_and_keep_agent_extra():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    default_deps = pyproject["project"]["dependencies"]
    default_names = {d.split(">=")[0].split("==")[0].strip().lower() for d in default_deps}
    assert default_names == {"libcst", "z3-solver", "hypothesis", "pytest", "tree-sitter", "tree-sitter-python"}
    assert not any(n.startswith("langgraph") for n in default_names)

    agent_extra = pyproject["project"]["optional-dependencies"]["agent"]
    agent_names = {d.split(">=")[0].split("==")[0].strip().lower() for d in agent_extra}
    assert agent_names == {"langgraph", "langgraph-checkpoint", "langgraph-checkpoint-sqlite"}

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    hlith_pkg = next(p for p in lock["package"] if p["name"] == "hlith")
    lock_default = {d["name"] for d in hlith_pkg["dependencies"]}
    lock_agent = {d["name"] for d in hlith_pkg["optional-dependencies"]["agent"]}
    assert lock_default == default_names
    assert lock_agent == agent_names


def test_missing_agent_extra_fails_closed_with_install_hint(monkeypatch):
    def _missing(dist: str) -> str:
        raise md.PackageNotFoundError(dist)

    monkeypatch.setattr(checkpoint._md, "version", _missing)
    with pytest.raises(RuntimeBoundary) as ei:
        checkpoint.versions()
    msg = str(ei.value)
    assert "--layer1 langgraph needs langgraph installed" in msg
    assert "uv sync --extra agent" in msg and "hlith[agent]" in msg


def test_replay_witness_statewatch_rejects_forged_g_claim_and_preserves_channel_isolation(tmp_path):
    """Standalone StateWatch replay must reject a forged/mismatched `g` claim and never count a `g` change for an `r` claim."""
    for side, body in (
        ("base", "def f(n: int) -> int:\n    return n * 2\n"),
        ("post", "import logging\n\ndef f(n: int) -> int:\n    logging.getLogger('app').setLevel(logging.CRITICAL)\n    return n * 2\n"),
    ):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)

    # 1. Exact matching logging `g` divergence reproduces on channel `g`.
    real = {
        "module": "pkg.m",
        "qualname": "f",
        "args": [2],
        "kwargs": {},
        "env": {},
        "pre": {"k": "ret", "r": "4", "g": ""},
        "post": {
            "k": "ret",
            "r": "4",
            "g": "logging logger app: level=50 disabled=False propagate=True handlers=[] filters=()",
        },
    }
    rep_ok = differential.replay_witness(real, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep_ok["reproduced"] is True and rep_ok["reproduced_channels"] == ["g"], rep_ok

    # 2. Forged `g` claim (wrong logger name/level) must NOT reproduce even though both sides diverge in `g`.
    forged_g = {
        **real,
        "post": {
            "k": "ret",
            "r": "4",
            "g": "logging logger other: level=10 disabled=False propagate=True handlers=[] filters=()",
        },
    }
    rep_forged = differential.replay_witness(forged_g, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep_forged["reproduced"] is False and rep_forged["match"]["post"]["state"] is False, rep_forged

    # 3. Recorded `r` divergence must NOT be counted through an unrecorded `g` divergence ( channel isolation).
    wrong_chan = {
        "module": "pkg.m",
        "qualname": "f",
        "args": [2],
        "kwargs": {},
        "env": {},
        "pre": {"k": "ret", "r": "4"},
        "post": {"k": "ret", "r": "5"},
    }
    rep_wrong = differential.replay_witness(wrong_chan, str(tmp_path / "base"), str(tmp_path / "post"), confined=False)
    assert rep_wrong["reproduced"] is False and rep_wrong["recorded_channels"] == ["r"], rep_wrong
