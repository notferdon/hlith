# SPDX-License-Identifier: Apache-2.0
"""Falsifier tests for L5 src-layout module resolution and per-symbol error isolation."""
from __future__ import annotations

import difflib
import json
import subprocess
import sys
from pathlib import Path

from hlith.contract.errors import EXIT_LANDED
from hlith.contract.identities import InvocationId
from hlith.contract.runs import LandingTarget
from hlith.feedback.probe import run_landing_probes
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.operator.capabilities import default_capabilities
from hlith.operator.pipeline import PipelineRequest, run_pipeline


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _make_patch(filename: str, old_src: str, new_src: str) -> bytes:
    diff_lines = list(
        difflib.unified_diff(
            old_src.splitlines(keepends=True),
            new_src.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )
    return (f"diff --git a/{filename} b/{filename}\n" + "".join(diff_lines)).encode("utf-8")


def _src_repo(tmp_path: Path, base_src: str, test_src: str) -> Path:
    repo = tmp_path / "src_repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "f2@example.invalid")
    _git(repo, "config", "user.name", "F2")
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "src" / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "src" / "pkg" / "m.py").write_text(base_src, encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_m.py").write_text(test_src, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _run(tmp_path: Path, repo: Path, label: str, base_src: str, post_src: str):
    prop = tmp_path / "proposer_private"
    prop.mkdir()
    caps = default_capabilities(state_root=tmp_path / "state", python=sys.executable, proposer_paths=(str(prop),))
    return run_pipeline(
        PipelineRequest(
            target=repo,
            invocation_id=InvocationId(label),
            external_patch=_make_patch("src/pkg/m.py", base_src, post_src),
            external_patch_label=label,
            # Hlith Review refuses an ORIGINAL-target landing; `hlith check` rehearses in a disposable clone (this tmp repo is one)
            landing_target=LandingTarget.REHEARSAL,
        ),
        caps,
    )


def _feedback_errors(res) -> list:
    return [ev.detail["feedback_error"] for ev in res.events if "feedback_error" in ev.detail]


def test_src_layout_single_module_landing_persists_feedback(tmp_path: Path) -> None:
    """A src-layout landing persists post-landing feedback whose inputs reach far outside the engine's own seeds (ints >= 2**1000).
    Premise under the positive-HELD gate (case): the old premise, a REGRESSION diverging only at ints >= 2**1000 that
    the differential HELD and the gate LANDED, is a false HELD the gate now refuses (UNVERIFIED, exit 12). Run 1 is therefore a CERTIFIED
    landing (rule R0: the same computation with a consistently renamed local): a sound landing's probe records the extended-family inputs it
    explored as a require_differential_domain_constraint (case), so the persisted >= 2**1000 input is a domain input, not a regression pin.
    (The original clip/zip(range(len(s)//2+4096)) premise became unreachable at 2e0a7975: the differential now seeds
    20000-char strings and refutes it pre-landing; see test_src_layout_clip_truncation_is_refused_and_still_persists_feedback.)"""
    base_src = "def f(n: int) -> str:\n    text = hex(n)\n    return text\n"
    post_src = "def f(n: int) -> str:\n    rendered = hex(n)\n    return rendered\n"
    repo = _src_repo(tmp_path, base_src, "from pkg.m import f\n\n\ndef test_c():\n    assert f(1) == '0x1'\n")
    res = _run(tmp_path, repo, "src-layout-land", base_src, post_src)
    assert res.gate_receipt.outcome == "landed", res.gate_receipt
    assert res.gate_receipt.exit_status == EXIT_LANDED, res.gate_receipt
    assert len(res.feedback_records) >= 1, "src/ layout landing must persist feedback records"
    assert _feedback_errors(res) == [], _feedback_errors(res)
    big = []
    for f in (tmp_path / "state").rglob("fb-*.json"):
        rec = json.loads(f.read_text())["record"]
        payload = rec["directive_payload"]
        inputs = [payload["input"]] if "input" in payload else list(payload.get("pinned_inputs") or [])
        big += [a for i in inputs for a in i.get("args", []) if isinstance(a, int) and a >= 2 ** 1000]
    assert big, "the post-landing probe must persist an input >= 2**1000 (outside the engine's own seeds) from a src/ layout landing"


def test_src_layout_clip_truncation_is_refused_and_still_persists_feedback(tmp_path: Path) -> None:
    """The former premise (HELD, then the post-landing probe refutes) is no longer reachable for >8192-char truncation: the
    differential refutes it BEFORE landing (soundness improvement, first bad commit 2e0a7975). It must stay refused (never
    land), and the refusal path must still persist feedback in a src layout without errors."""
    base_src = "def clip(s: str) -> str:\n    return s\n"
    post_src = "def clip(s: str) -> str:\n    return \"\".join(c for _, c in zip(range(len(s) // 2 + 4096), s))\n"
    repo = _src_repo(tmp_path, base_src, "from pkg.m import clip\n\n\ndef test_c():\n    assert clip('') == ''\n")
    res = _run(tmp_path, repo, "src-layout-clip", base_src, post_src)
    assert res.gate_receipt.outcome == "refused", res.gate_receipt
    assert res.gate_receipt.exit_status == 10, res.gate_receipt
    assert "differential:pkg.m.clip" in res.gate_receipt.blocking, res.gate_receipt
    assert len(res.feedback_records) >= 1, "src/ layout refusal must persist feedback records"
    assert _feedback_errors(res) == [], _feedback_errors(res)


def test_missing_symbol_file_emits_named_error_and_does_not_abort_other_symbols(tmp_path: Path) -> None:
    base_tree = tmp_path / "base"
    landed_tree = tmp_path / "landed"
    for tree, src in (
        (base_tree, "def clip(s: str) -> str:\n    return s\n"),
        (landed_tree, "def clip(s: str) -> str:\n    return \"\".join(c for _, c in zip(range(len(s) // 2 + 4096), s))\n"),
    ):
        (tree / "src" / "pkg").mkdir(parents=True)
        (tree / "src" / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (tree / "src" / "pkg" / "m.py").write_text(src, encoding="utf-8")
        (tree / "tests").mkdir()
        (tree / "tests" / "test_m.py").write_text(
            "from pkg.m import clip\n\n\ndef test_c():\n    assert clip('') == ''\n",
            encoding="utf-8",
        )

    from types import SimpleNamespace

    from hlith.contract.identities import RunId, Sha256
    from hlith.contract.runs import GateReceipt

    receipt = GateReceipt(
        run_id=RunId("run-1234567890ab"),
        outcome="landed",
        exit_status=EXIT_LANDED,
        blocking=(),
        landed_commit="a" * 40,
        verification_record_sha256=Sha256("b" * 64),
    )
    base_snap = SimpleNamespace(path=base_tree)
    landed_snap = SimpleNamespace(path=landed_tree)

    errors: list[str] = []
    written = run_landing_probes(
        tmp_path / "store",
        receipt,
        base_snap,
        landed_snap,
        symbols=("nonexistent.mod.fn", "pkg.m.clip"),
        errors=errors,
    )
    assert len(written) >= 1, "valid symbol pkg.m.clip must still record feedback"
    assert any("missing-module-file" in e and "nonexistent.mod.fn" in e for e in errors), errors
