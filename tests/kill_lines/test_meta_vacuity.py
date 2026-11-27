"""Meta-test: verify_kill_lines.sh must FAIL HARD on missing files, zero tests collected, wrong exits, or missing KL5 mirror."""
from __future__ import annotations

import os
import tempfile
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify_kill_lines.sh"


def _minimal_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", tempfile.gettempdir()),
        "HLITH_PYTHON": sys.executable,
    }
    if extra:
        env.update(extra)
    return env


def test_meta_fails_without_kl5_mirror_env() -> None:
    res = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=_minimal_env(), capture_output=True, text=True)
    assert res.returncode != 0
    assert "HLITH_KL5_REPO" in (res.stdout + res.stderr)


def test_meta_fails_without_python_when_venv_absent(tmp_path: Path) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, fake / "scripts/verify_kill_lines.sh")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir()}
    res = subprocess.run(["bash", str(fake / "scripts/verify_kill_lines.sh")], cwd=fake, env=env, capture_output=True, text=True)
    assert res.returncode != 0


def test_meta_fails_on_missing_test_file(tmp_path: Path) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, fake / "scripts/verify_kill_lines.sh")
    res = subprocess.run(["bash", str(fake / "scripts/verify_kill_lines.sh")], cwd=fake,
                         env=_minimal_env({"HLITH_KL5_REPO": str(fake)}), capture_output=True, text=True)
    assert res.returncode != 0
    assert "missing test file" in (res.stdout + res.stderr)


def test_meta_fails_on_zero_tests_collected(tmp_path: Path) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    (fake / "tests/kill_lines").mkdir(parents=True)
    shutil.copy2(SCRIPT, fake / "scripts/verify_kill_lines.sh")
    # Empty test file -> pytest exits 5 (no tests collected) -> script must fail non-zero.
    (fake / "tests/kill_lines/test_kl1_unbypassable_gate.py").write_text("# empty\n")
    res = subprocess.run(["bash", str(fake / "scripts/verify_kill_lines.sh")], cwd=fake,
                         env=_minimal_env({"HLITH_KL5_REPO": str(fake)}), capture_output=True, text=True)
    assert res.returncode != 0
    assert "pytest exited 5" in (res.stdout + res.stderr)


def test_meta_fails_on_failing_test(tmp_path: Path) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    (fake / "tests/kill_lines").mkdir(parents=True)
    shutil.copy2(SCRIPT, fake / "scripts/verify_kill_lines.sh")
    (fake / "tests/kill_lines/test_kl1_unbypassable_gate.py").write_text("def test_fail():\n    assert False\n")
    res = subprocess.run(["bash", str(fake / "scripts/verify_kill_lines.sh")], cwd=fake,
                         env=_minimal_env({"HLITH_KL5_REPO": str(fake)}), capture_output=True, text=True)
    assert res.returncode != 0
    assert "pytest exited 1" in (res.stdout + res.stderr)


import pytest  # noqa: E402


@pytest.mark.parametrize(
    ("test_name", "patch_code"),
    [
        (
            "test_kl7_forged_mac_refuses",
            "import hlith.hostio.verification as v; v.LocalVerificationService.verify = lambda self, rec: True",
        ),
        (
            "test_kl7_unsigned_record_refuses",
            "src = src.replace('if not record.mac or not record.issuer or not verifier.verify(record):', 'if False:', 1)",
        ),
        (
            "test_kl7_tampered_obligation_set_refuses",
            "src = src.replace('if obligation_set_digest(verified.obligations) != record.obligation_set_sha256:', 'if False:', 1)",
        ),
        (
            "test_kl7_wrong_patch_digest_refuses",
            "src = src.replace('if patch_digest != record.patch_sha256:', 'if False:', 1)",
        ),
        (
            "test_kl7_wrong_base_tree_refuses",
            "src = src.replace('if live_base_tree != record.base_tree_oid:', 'if False:', 1).replace('if base_snap.tree_oid != record.base_tree_oid:', 'if False:', 1)",
        ),
        (
            "test_kl7_wrong_post_tree_refuses",
            "src = src.replace('if post_snap.tree_oid != record.post_tree_oid:', 'if False:', 1).replace('if not tree_ok:', 'if False:', 1)",
        ),
        (
            "test_kl7_required_scope_digest_mismatch_refuses",
            "src = src.replace('if req.digest != record.required_scope_digest or dis.digest != record.scope_discharge_digest:', 'if False:', 1)",
        ),
        (
            "test_kl7_discharge_incomplete_refuses",
            "import hlith.gate.api as ga; ga.scope_fully_discharged = lambda req, dis: True",
        ),
        (
            "test_kl7_account_consumption_missing_refuses",
            "src = src.replace('if not record.consumption:', 'if False:', 1)",
        ),
        (
            "test_kl7_target_identity_changed_refuses",
            "src = src.replace('if live_identity != expected_identity or record.target != expected_identity:', 'if False:', 1)",
        ),
        (
            "test_kl7_hostile_repo_refuses",
            "import hlith.hostio.git_read as gr; gr.HardenedGitRead.repository_hostile_reason = lambda self, repo: None",
        ),
        (
            "test_kl7_landing_key_v2_idempotence",
            "import hlith.gate.api as ga; ga.landing_key_v2 = lambda **kw: '0' * 64",
        ),
        (
            "test_kl7_landing_key_v2_already_in_head_skips_recommit",
            "src = src.replace('if lkey not in head_landing_keys(target):', 'if True:', 1)",
        ),
        (
            "test_kl7_sa6_different_run_id_refuses",
            "src = src.replace('if expected_run_id is not None and record.run_id != expected_run_id:', 'if False:', 1)",
        ),
        (
            "test_kl7_sa7_empty_required_scope_refuses",
            "src = src.replace('if any(p.endswith(\".py\") for p in changed_paths):', 'if False:', 1)",
        ),
        (
            "test_kl7_dirty_staged_file_refuses_and_preserves_staging",
            "src = src.replace('if dirty is not None:', 'if False:', 1)",
        ),
        (
            "test_kl7_two_same_history_clones_isolated_journals",
            "import hlith.gate.journal as gj; gj._target_journal_key = lambda gd: 'fixed'",
        ),
        (
            "test_kl7_patch_policy_violation_refuses",
            "import hlith.hostio.snapshot as hs; hs.patch_violations = lambda d: []; ga.patch_violations = lambda d: []",
        ),
        (
            "test_kl7_existing_unrecovered_journal_refuses",
            "import hlith.gate.journal as gj; jsrc = Path(gj.__file__).read_text().replace('if journal_path.exists() or journal_path.is_symlink() or nonce_path.exists() or nonce_path.is_symlink():', 'if False:', 1); exec(compile(jsrc, gj.__file__, 'exec'), gj.__dict__); ga.begin_journal = gj.begin_journal",
        ),
    ],
)
def test_meta_kl7_checks_are_non_vacuous(test_name: str, patch_code: str) -> None:
    """Disabling any single KL7 gate check in a separate process must cause that KL7 test to fail."""
    runner = (
        "from pathlib import Path; import pytest, hlith.gate.api as ga\n"
        "src = Path(ga.__file__).read_text()\n"
        f"{patch_code}\n"
        "if 'src =' in " + repr(patch_code) + ":\n"
        "    exec(compile(src, ga.__file__, 'exec'), ga.__dict__)\n"
        f"raise SystemExit(pytest.main(['-q', 'tests/kill_lines/test_kl7_gate_service.py', '-k', {test_name!r}]))\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", runner],
        cwd=ROOT,
        env=_minimal_env({"PYTHONPATH": str(ROOT / "src")}),
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0, f"{test_name} passed vacuous check!\n{res.stdout}\n{res.stderr}"


@pytest.mark.parametrize(
    "decorator",
    [
        "@pytest.mark.skip(reason='vacuous')",
        "@pytest.mark.xfail(reason='vacuous')",
    ],
)
def test_meta_fails_on_skipped_or_xfail(tmp_path: Path, decorator: str) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    (fake / "tests/kill_lines").mkdir(parents=True)
    shutil.copy2(SCRIPT, fake / "scripts/verify_kill_lines.sh")
    (fake / "tests/kill_lines/test_kl1_unbypassable_gate.py").write_text(
        "import pytest\n"
        "def test_ok1(): pass\n"
        "def test_ok2(): pass\n"
        f"{decorator}\n"
        "def test_bad(): assert False\n"
    )
    res = subprocess.run(
        ["bash", str(fake / "scripts/verify_kill_lines.sh")],
        cwd=fake,
        env=_minimal_env({"HLITH_KL5_REPO": str(fake)}),
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "skipped/deselected/xfail/xpass forbidden" in (res.stdout + res.stderr)


@pytest.mark.parametrize(
    ("test_target", "inject_code"),
    [
        (
            "tests/kill_lines/test_kl1_unbypassable_gate.py::test_kl1_refused_gate_never_lands",
            "import hlith.gate as g, hlith.gate._legacy as gl; "
            "from hlith.types import GateDecision, GateOutcome; "
            "g.land = gl.land = lambda *a, **kw: GateDecision(GateOutcome.LANDED, 0, ())",
        ),
        (
            "tests/kill_lines/test_kl2_non_empty_obligations.py::test_kl2_empty_obligation_set_forbidden",
            "from hlith.types import ObligationSet; ObligationSet.__post_init__ = lambda self: None",
        ),
        (
            "tests/kill_lines/test_kl3_independent_held_check.py::test_kl3_held_requires_evidence_and_independent_blind_provenance",
            "from hlith.types import Obligation; Obligation.__post_init__ = lambda self: None",
        ),
        (
            "tests/kill_lines/test_kl4_not_derived_refuses.py::test_kl4_eval_refuses_exit_11_and_no_forbidden_text",
            "import hlith.gate as g; from hlith.types import GateDecision, GateOutcome; "
            "g.decide = lambda obs: GateDecision(GateOutcome.LANDED, 0, ())",
        ),
        (
            "tests/kill_lines/test_kl5_external_repo_understanding.py::test_kl5_external_repo_effect_account",
            "import hlith.effect as ef; ef.build_effect_account = lambda *a, **kw: None",
        ),
        (
            "tests/kill_lines/test_kl6_architecture_integrity.py::test_kl6_no_forbidden_deps_or_l234_imports",
            "import ast; _orig = ast.parse; "
            "ast.parse = lambda src, *a, **kw: _orig('import fastapi\\n' + src, *a, **kw)",
        ),
        (
            "tests/property/test_gate_invariants.py::test_prop6_patch_and_base_identity_enforced",
            "import hlith.gate as g, hlith.gate._legacy as gl; "
            "from hlith.types import GateDecision, GateOutcome; "
            "g.land = gl.land = lambda *a, **kw: GateDecision(GateOutcome.LANDED, 0, ())",
        ),
    ],
)
def test_meta_kl1_to_kl6_and_invariants_negative_controls(test_target: str, inject_code: str) -> None:
    """Injecting the violation for KL1..KL6 or gate invariants must turn that check red."""
    runner = (
        "import pytest\n"
        f"{inject_code}\n"
        f"raise SystemExit(pytest.main(['-q', {test_target!r}]))\n"
    )
    extra = {"PYTHONPATH": str(ROOT / "src")}
    if "HLITH_KL5_REPO" in os.environ:
        extra["HLITH_KL5_REPO"] = os.environ["HLITH_KL5_REPO"]
    res = subprocess.run(
        [sys.executable, "-c", runner],
        cwd=ROOT,
        env=_minimal_env(extra),
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0, f"Negative control did not fail {test_target}!\n{res.stdout}\n{res.stderr}"
