# SPDX-License-Identifier: Apache-2.0
"""Comprehensive verification of exported-guard continuity uncommitted exported-guard continuity and maintainer binding corrections."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.contract.effects import EffectAccount, EntryGuard, GapCode, ImpactedSite, Unknown
from hlith.contract.guards import (
    EMPTY_GUARD_CATALOG,
    MAX_GUARD_BYTES,
    AuthenticatedExportedGuard,
    ExportedGuardCatalog,
)
from hlith.contract.identities import RunId, Sha256, TreeOid, sha256_hex
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.contract.obligations import AccountConsumption, RequiredScope, scope_fully_discharged
from hlith.contract.witness import adapt
from hlith.hostio.state import LocalHostState
from hlith.obligation import consumption, exported_guard, scope, z3_binding
from hlith.operator.guard_catalog import build_guard_catalog
from hlith.operator.witness_export import build_pytest_source

SRC = Path(__file__).resolve().parents[1] / "src"

BASE_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x <= 0:\n"
    "        raise ValueError('must be positive')\n"
    "    return x\n"
)

BUGGY_CALC = (
    "def validate(x: int) -> int:\n"
    "    return x\n"
)

FIXED_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x <= 0:\n"
    "        raise ValueError('must be positive')\n"
    "    normalized = x\n"
    "    return normalized\n"
)

ALLOW_ZERO_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x < 0:\n"
    "        raise ValueError('must be positive')\n"
    "    return x\n"
)

BASE_TEST = (
    "from demo.calc import validate\n"
    "\n"
    "\n"
    "def test_validate_positive():\n"
    "    assert validate(5) == 5\n"
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _make_repo(root: Path, *, with_base_test: bool = True) -> Path:
    repo = root / "repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    if with_base_test:
        (repo / "tests").mkdir(parents=True)
        (repo / "tests" / "test_calc.py").write_text(BASE_TEST, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _repo_fingerprint(repo: Path) -> str:
    h = hashlib.sha256()
    for args in (("rev-parse", "HEAD"), ("status", "--porcelain", "-uall"), ("diff",)):
        h.update(_git(repo, *args).encode("utf-8"))
    for p in sorted(repo.rglob("*")):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(repo).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def _cli_env(state_dir: Path, ui_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HLITH_STATE_DIR"] = str(state_dir)
    env["HLITH_UI_STATE"] = str(ui_dir)
    return env


def _run_cli(args: list[str], *, env: dict[str, str], cwd: Path) -> tuple[int, dict, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        timeout=180,
    )
    payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return proc.returncode, payload, proc.stderr


def _seed_refuted_and_export_guard(
    repo: Path,
    state_dir: Path,
    ui_dir: Path,
    *,
    guard_rel: str = "tests/test_hlith_guard.py",
    expect: str = "pre",
) -> tuple[str, Path]:
    env = _cli_env(state_dir, ui_dir)
    (repo / "demo" / "calc.py").write_text(BUGGY_CALC, encoding="utf-8")
    rc, check_json, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 10, f"expected initial REFUTED (10), got {rc}\nstderr={err}\nstdout={check_json}"
    run_id = check_json["check"]["run_id"]
    guard_path = repo / guard_rel
    rep_rc, rep_json, rep_err = _run_cli(
        [
            "replay",
            run_id,
            "--repo",
            str(repo),
            "--json",
            "--pytest-out",
            str(guard_path),
            "--expect",
            expect,
        ],
        env=env,
        cwd=repo,
    )
    assert rep_rc == 0, f"replay failed: rc={rep_rc}\nstderr={rep_err}\nstdout={rep_json}"
    assert rep_json["status"] == "REPRODUCED"
    assert rep_json["pytest_export"]["status"] == "written"
    assert guard_path.is_file()
    return run_id, guard_path


def _obs_by_id(artifact: dict) -> dict[str, dict]:
    return {row["id"]: row for row in artifact.get("obligations", [])}


def _provenance(exit_code: int = 0) -> CheckProvenance:
    return CheckProvenance(
        checker_id="hlith.obligation.exported_guard",
        checker_sha256="a" * 64,
        confined=True,
        proposer_paths_readable=False,
        profile_sha256="b" * 64,
        exit_code=exit_code,
    )


def _evidence() -> BoundedEvidence:
    return BoundedEvidence(
        executions=2,
        explored="source_run_id=run-000000000001; base=passed; post=passed",
        unexplored="single recorded pre-guard call only",
    )


# ------------------------------------------------------------------ 1. Positive continuity & no baseline reach fabrication


def test_01_positive_uncommitted_guard_and_fix_lands_in_rehearsal(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    source_run_id, guard_path = _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    # Fix production code without committing either demo/calc.py or tests/test_hlith_guard.py.
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    before_fp = _repo_fingerprint(repo)

    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 0, f"expected rehearsal LANDED (0), got {rc}\nstderr={err}\nartifact={res.get('artifact')}"
    assert _repo_fingerprint(repo) == before_fp, "original repository must remain untouched"
    assert res["check"]["headline"] == "LANDED", res["check"]

    art = res["artifact"]
    assert art["feedback_errors"] == [], art["feedback_errors"]
    assert art["feedback"]["written_feedback_ids"], art["feedback"]
    obs = _obs_by_id(art)
    guard_ob = obs["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]
    assert guard_ob["verdict"] == "held"
    assert guard_ob["account_bound"] is True
    assert guard_ob["witness"] is None
    assert guard_ob["provenance"]["confined"] is True
    assert guard_ob["provenance"]["proposer_paths_readable"] is False
    assert source_run_id in guard_ob["evidence"]["explored"]
    assert hashlib.sha256(guard_path.read_bytes()).hexdigest() in guard_ob["evidence"]["explored"]

    # Added guard signature_binding is actually solved via 0-arg pytest entry and HELD, not bypassed.
    sb_guard = obs["signature_binding:tests.test_hlith_guard.test_recorded_pre_behavior"]
    assert sb_guard["verdict"] == "held"
    assert sb_guard["account_bound"] is True
    assert "0-arg pytest invocation" in (sb_guard["evidence"]["explored"] or "")

    # Normal target obligations still ran and passed independently.
    assert obs["differential:demo.calc.validate"]["verdict"] == "held"
    assert obs["signature_binding:demo.calc.validate"]["verdict"] == "held"
    assert not any(k.startswith("added-unreached:") for k in obs)


def test_01b_uncommitted_guard_never_satisfies_empty_baseline_test_reach(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=False)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 12, f"expected UNVERIFIED (12) on empty baseline slice, got {rc}\nstderr={err}\nobs={res.get('artifact', {}).get('obligations')}"
    obs = _obs_by_id(res["artifact"])
    assert obs["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]["verdict"] == "held"
    assert obs["differential:demo.calc.validate"]["verdict"] == "unverified"
    assert "impacted test slice is empty" in (obs["differential:demo.calc.validate"]["stop_reason"] or "")


# ------------------------------------------------------------------ 2. Still-buggy post: guard never refutes


def test_02_still_buggy_post_guard_never_refutes_differential_refutes(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    # Leave demo/calc.py buggy alongside the uncommitted pre-guard.
    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 10, f"expected REFUTED (10) from normal differential, got {rc}\nstderr={err}"
    art = res["artifact"]
    obs = _obs_by_id(art)

    guard_ob = obs["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]
    assert guard_ob["verdict"] == "unverified", "guard failure MUST NOT emit REFUTED"
    assert guard_ob["witness"] is None
    assert "witness_call" not in guard_ob
    assert "witness_record" not in guard_ob
    assert "assertion_failure" in (guard_ob["stop_reason"] or "")
    assert "non-refuting" in (guard_ob["evidence"]["explored"] or "")

    # Normal target differential still produces a valid REFUTED witness (may use L5 seed <= 0).
    diff_ob = obs["differential:demo.calc.validate"]
    assert diff_ob["verdict"] == "refuted"
    args = diff_ob["witness_call"]["args"]
    assert isinstance(args, list) and len(args) == 1 and isinstance(args[0], int) and args[0] <= 0
    assert diff_ob["witness_call"]["pre"]["k"] == "exc"
    assert diff_ob["witness_call"]["post"]["k"] == "ret"
    assert diff_ob["witness_record"]["schema_version"] == 1

    # Replay + export of the new run still works cleanly.
    reexport = tmp_path / "reexport_guard.py"
    rep_rc, rep_json, rep_err = _run_cli(
        [
            "replay",
            res["check"]["run_id"],
            "--repo",
            str(repo),
            "--json",
            "--pytest-out",
            str(reexport),
            "--expect",
            "pre",
        ],
        env=env,
        cwd=repo,
    )
    assert rep_rc == 0, rep_err
    assert rep_json["status"] == "REPRODUCED"
    assert rep_json["pytest_export"]["status"] == "written"


# ------------------------------------------------------------------ 3. Intended-delta conflict


def test_03_approved_intended_delta_conflicts_with_pre_guard(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    # Intentional change: allow x == 0 (if x < 0: raise ...), leaving uncommitted pre-guard in place.
    (repo / "demo" / "calc.py").write_text(ALLOW_ZERO_CALC, encoding="utf-8")
    _git(repo, "add", "-N", "tests/test_hlith_guard.py")
    patch_text = _git(repo, "diff")
    _git(repo, "reset", "-q", "tests/test_hlith_guard.py")
    patch_file = tmp_path / "allow_zero.patch"
    patch_file.write_text(patch_text, encoding="utf-8")

    manifest_file = tmp_path / "allow_zero.manifest.json"
    manifest_file.write_text(
        json.dumps(
            {
                "paths": {
                    "demo/calc.py": ["modify"],
                    "tests/test_hlith_guard.py": ["add"],
                },
                "deltas": [
                    {
                        "id": "allow-zero",
                        "symbol": "demo.calc.validate",
                        "kind": "behavior",
                        "claim": "allow zero timeout input",
                        "input_domain": "x == 0",
                        "pre": "raises ValueError('must be positive')",
                        "post": "returns x unchanged",
                        "predicate": {"type": "expr", "param": "x", "expr": "x == 0"},
                        "expected": {"kind": "returns_expr", "expr": "x"},
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # First run unapproved to obtain canonical delta_set_sha256.
    rc1, res1, err1 = _run_cli(
        [
            "check",
            "--repo",
            str(repo),
            "--patch",
            str(patch_file),
            "--manifest",
            str(manifest_file),
            "--json",
            "--target-python",
            sys.executable,
        ],
        env=env,
        cwd=repo,
    )
    assert rc1 != 0, err1
    delta_sha = res1["artifact"]["effect"]["delta_set_sha256"]
    assert delta_sha and len(delta_sha) == 64

    # Re-run with human approval of the conflicting delta.
    rc2, res2, err2 = _run_cli(
        [
            "check",
            "--repo",
            str(repo),
            "--patch",
            str(patch_file),
            "--manifest",
            str(manifest_file),
            "--approve-deltas",
            delta_sha,
            "--json",
            "--target-python",
            sys.executable,
        ],
        env=env,
        cwd=repo,
    )
    assert rc2 != 0, f"conflicting pre-guard must not land: {res2}"
    assert rc2 != 10, f"approved delta conflict must NOT emit REFUTED (10): {res2['artifact']['obligations']}"
    obs = _obs_by_id(res2["artifact"])
    guard_ob = obs["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]
    assert guard_ob["verdict"] == "unverified"
    assert guard_ob["witness"] is None
    assert "intended-delta/guard conflict" in (guard_ob["stop_reason"] or "")
    assert "allow-zero" in (guard_ob["stop_reason"] or "")
    # Normal differential must not have been forced to REFUTED by the uncommitted pre-guard.
    assert obs["differential:demo.calc.validate"]["verdict"] != "refuted"


# ------------------------------------------------------------------ 4. Altered, forged, header-only edits


@pytest.mark.parametrize("mutation", ["weaken_assert", "header_tweak", "forged_header", "failing_altered_expected"])
def test_04_altered_forged_and_header_only_edits_not_derived(tmp_path: Path, mutation: str) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    guard_path = repo / "tests" / "test_hlith_guard.py"
    original = guard_path.read_text(encoding="utf-8")
    prov_line = [ln for ln in original.splitlines() if ln.startswith("# Provenance:")][0]

    if mutation == "weaken_assert":
        mutated = original.replace("assert _hlith_got[0] == 'exc'", "assert True")
    elif mutation == "header_tweak":
        mutated = "# extra comment\n" + original
    elif mutation == "failing_altered_expected":
        # Alter expected message so the guard assertion fails on post alongside valid FIXED_CALC;
        # must still fall back to NOT-DERIVED (11) added-unreached and never emit a guard-originated REFUTED (10).
        mutated = original.replace("'must be positive'", "'wrong altered expected message'")
    else:
        mutated = (
            "def test_recorded_pre_behavior():\n"
            "    assert True\n\n\n"
            f"{prov_line}\n"
        )
    guard_path.write_text(mutated, encoding="utf-8")
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")

    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 11, f"expected NOT-DERIVED (11) for {mutation}, got {rc}\nstderr={err}\nobs={res.get('artifact', {}).get('obligations')}"
    obs = _obs_by_id(res["artifact"])
    assert "added-unreached:tests.test_hlith_guard.test_recorded_pre_behavior" in obs
    assert obs["added-unreached:tests.test_hlith_guard.test_recorded_pre_behavior"]["verdict"] == "not-derived"
    assert not any(k.startswith("exported-guard:") for k in obs)
    assert not any(row["verdict"] == "refuted" for row in res["artifact"]["obligations"])


# ------------------------------------------------------------------ 5. Cross-base, cross-repo, expect-post, non-test, symlink, oversize, catalog/store bounds


def test_05_cross_base_cross_repo_expect_post_nontest_fail_closed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "a", with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _run_id, guard_path = _seed_refuted_and_export_guard(repo, state_dir, ui_dir)
    guard_bytes = guard_path.read_bytes()

    # 5a. --expect post guard -> NOT_DERIVED (no continuity)
    post_guard = repo / "tests" / "test_hlith_post_guard.py"
    rep_rc, rep_json, _ = _run_cli(
        ["replay", _run_id, "--repo", str(repo), "--json", "--pytest-out", str(post_guard), "--expect", "post"],
        env=env,
        cwd=repo,
    )
    assert rep_rc == 0 and rep_json["pytest_export"]["status"] == "written"
    guard_path.unlink()
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    rc, res, _ = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 11, f"expected NOT-DERIVED (11) for --expect post guard, got {rc}\nobs={res.get('artifact', {}).get('obligations')}"
    obs = _obs_by_id(res["artifact"])
    assert "added-unreached:tests.test_hlith_post_guard.test_recorded_post_behavior" in obs
    assert obs["added-unreached:tests.test_hlith_post_guard.test_recorded_post_behavior"]["verdict"] == "not-derived"
    assert not any(k.startswith("exported-guard:") for k in obs)
    assert not any(row["verdict"] == "refuted" for row in res["artifact"]["obligations"])
    post_guard.unlink()

    # 5b. Non-test path -> NOT_DERIVED
    non_test = repo / "demo" / "guard_copy.py"
    non_test.write_bytes(guard_bytes)
    rc, res, _ = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 11
    obs = _obs_by_id(res["artifact"])
    assert "added-unreached:demo.guard_copy.test_recorded_pre_behavior" in obs
    assert not any(k.startswith("exported-guard:") for k in obs)
    non_test.unlink()

    # 5c. Cross-base (advance HEAD) -> NOT_DERIVED
    (repo / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    (repo / "demo" / "note.py").write_text("NOTE = 1\n", encoding="utf-8")
    _git(repo, "add", "demo/note.py")
    _git(repo, "commit", "-q", "-m", "advance base")
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    guard_path.write_bytes(guard_bytes)
    rc, res, _ = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 11
    obs = _obs_by_id(res["artifact"])
    assert "added-unreached:tests.test_hlith_guard.test_recorded_pre_behavior" in obs
    assert not any(k.startswith("exported-guard:") for k in obs)

    # 5d. Cross-repo (distinct root commit in same state_dir) -> NOT_DERIVED
    repo_b = _make_repo(tmp_path / "b", with_base_test=True)
    (repo_b / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    (repo_b / "tests" / "test_hlith_guard.py").write_bytes(guard_bytes)
    rc, res, _ = _run_cli(
        ["check", "--repo", str(repo_b), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo_b,
    )
    assert rc == 11
    obs = _obs_by_id(res["artifact"])
    assert "added-unreached:tests.test_hlith_guard.test_recorded_pre_behavior" in obs
    assert not any(k.startswith("exported-guard:") for k in obs)


def test_05b_symlink_oversize_missing_and_catalog_store_bounds(tmp_path: Path) -> None:
    # Build a synthetic valid catalog entry and verify strict matcher rejections.
    wc = {
        "module": "demo.calc",
        "qualname": "validate",
        "args": [0],
        "kwargs": {},
        "receiver": None,
        "env": None,
        "inject": None,
        "pre": {"k": "exc", "t": "builtins.ValueError", "m": "must be positive", "out": "", "g": ""},
        "post": {"k": "ret", "r": "0", "out": "", "g": ""},
    }
    base_oid = TreeOid("a" * 40)
    post_oid = TreeOid("b" * 40)
    canonical = build_pytest_source(
        adapt(wc), import_root="", base_commit="c" * 40, post_tree=str(post_oid), expect="pre"
    ).encode("utf-8")
    entry = AuthenticatedExportedGuard(
        source_run_id=RunId("run-000000000001"),
        source_obligation_id="differential:demo.calc.validate",
        base_tree_oid=base_oid,
        base_commit="c" * 40,
        post_tree_oid=post_oid,
        target_symbol="demo.calc.validate",
        module="demo.calc",
        qualname="validate",
        import_root="",
        expect="pre",
        canonical_sha256=sha256_hex(hashlib.sha256(canonical).hexdigest()),
        canonical_bytes=canonical,
        witness_call_json=json.dumps(wc, sort_keys=True),
    )
    catalog = ExportedGuardCatalog(repo_identity="repo-1", base_tree_oid=base_oid, entries=(entry,))

    base_dir = tmp_path / "base"
    post_dir = tmp_path / "post"
    (base_dir / "demo").mkdir(parents=True)
    (base_dir / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (base_dir / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    shutil.copytree(base_dir, post_dir)

    qn = "tests.test_guard.test_recorded_pre_behavior"
    acct = EffectAccount(
        run_id=RunId("run-000000000002"),
        base_tree_oid=base_oid,
        patch_sha256=Sha256("d" * 64),
        post_tree_oid=post_oid,
        analyzer_id="test",
        modified_callables=("demo.calc.validate",),
        added_callables=(qn,),
    )

    class _FakeFacts:
        added = [{"qualified_name": qn, "reached_from": []}]
        unresolved_constructs: list = []

    # Missing file -> no match
    assert exported_guard.match_exported_guards(acct, _FakeFacts(), base_dir, post_dir, catalog) == {}

    # Symlink file -> rejected
    outside = tmp_path / "outside.py"
    outside.write_bytes(canonical)
    (post_dir / "tests").mkdir(exist_ok=True)
    sym = post_dir / "tests" / "test_guard.py"
    sym.symlink_to(outside)
    assert exported_guard.match_exported_guards(acct, _FakeFacts(), base_dir, post_dir, catalog) == {}
    sym.unlink()

    # Oversize (> 1 MiB) -> rejected
    sym.write_bytes(canonical + b"\n# " + b"x" * (MAX_GUARD_BYTES + 10))
    assert exported_guard.match_exported_guards(acct, _FakeFacts(), base_dir, post_dir, catalog) == {}
    sym.unlink()

    # Unknown attributed to the guard file -> rejected
    sym.write_bytes(canonical)
    acct_unk = EffectAccount(
        run_id=RunId("run-000000000002"),
        base_tree_oid=base_oid,
        patch_sha256=Sha256("d" * 64),
        post_tree_oid=post_oid,
        analyzer_id="test",
        modified_callables=("demo.calc.validate",),
        added_callables=(qn,),
        unknowns=(Unknown(GapCode.OTHER, "tests/test_guard.py:1", "unexpected"),),
    )
    assert exported_guard.match_exported_guards(acct_unk, _FakeFacts(), base_dir, post_dir, catalog) == {}

    # Catalog builder is strictly read-only on non-existent state root (never creates dirs!).
    missing_state = tmp_path / "nonexistent_state"
    hs_missing = LocalHostState(missing_state)
    assert build_guard_catalog(hs_missing, "repo-deadbeef", base_oid) == EMPTY_GUARD_CATALOG
    assert not missing_state.exists(), "catalog builder must never create state directories"

    # Malformed / symlink / corrupt / ID_MISMATCH / missing witness_record / duplicate entries fail closed cleanly.
    bad_state = tmp_path / "bad_state"
    runs_dir = bad_state / "repositories" / "repo-bad" / "runs"
    runs_dir.mkdir(parents=True)
    # 1. corrupt JSON
    d1 = runs_dir / "run-000000000011"
    d1.mkdir()
    (d1 / "receipt.json").write_text("{not-json", encoding="utf-8")
    (d1 / "out.json").write_text("{not-json", encoding="utf-8")
    # 2. symlink run dir
    ext_run = tmp_path / "ext_run"
    ext_run.mkdir()
    (runs_dir / "run-000000000012").symlink_to(ext_run)
    # 3. missing witness_record / truncated
    d3 = runs_dir / "run-000000000013"
    d3.mkdir()
    (d3 / "receipt.json").write_text(
        json.dumps(
            {
                "format": 2,
                "run_id": "run-000000000013",
                "invocation_id": "inv-000000000001",
                "thread_id": None,
                "mode": "headless",
                "landing_target": "rehearsal",
                "origin": "supplied-patch",
                "repo_identity": "repo-bad",
                "source_repo": "/work/x",
                "created_utc": "2026-11-27T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (d3 / "out.json").write_text(
        json.dumps(
            {
                "format": 2,
                "run": {
                    "run_id": "run-000000000013",
                    "mode": "headless",
                    "landing_target": "rehearsal",
                    "origin": "supplied-patch",
                    "base_tree_oid": str(base_oid),
                    "post_tree_oid": str(post_oid),
                    "replay_context": {
                        "base": {"commit": "c" * 40, "tree_oid": str(base_oid)},
                        "patch": {"sha256": "e" * 64, "ref": "change.patch"},
                        "import_root": "",
                        "extra_sys_path": [],
                    },
                },
                "outcome": "refused",
                "exit_status": 10,
                "blocking": ["differential:demo.calc.validate"],
                "obligations": [
                    {
                        "id": "differential:demo.calc.validate",
                        "target_symbol": "demo.calc.validate",
                        "verdict": "refuted",
                        "witness": "validate(0)",
                        "witness_call": wc,
                        # deliberately missing witness_record
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    hs_bad = LocalHostState(bad_state)
    cat_bad = build_guard_catalog(hs_bad, "repo-bad", base_oid)
    assert cat_bad.entries == ()

    # Duplicate valid runs are deduplicated by canonical_sha256 and bounded by max_entries / max_total_bytes.
    valid_art = json.loads((d3 / "out.json").read_text(encoding="utf-8"))
    valid_art["obligations"][0]["witness_record"] = adapt(wc)
    for rid in ("run-000000000021", "run-000000000022"):
        dd = runs_dir / rid
        dd.mkdir()
        rec = json.loads((d3 / "receipt.json").read_text(encoding="utf-8"))
        rec["run_id"] = rid
        (dd / "receipt.json").write_text(json.dumps(rec), encoding="utf-8")
        a_copy = json.loads(json.dumps(valid_art))
        a_copy["run"]["run_id"] = rid
        (dd / "out.json").write_text(json.dumps(a_copy), encoding="utf-8")
    cat_dedup = build_guard_catalog(hs_bad, "repo-bad", base_oid)
    assert len(cat_dedup.entries) == 1
    cat_tiny = build_guard_catalog(hs_bad, "repo-bad", base_oid, max_total_bytes=10)
    assert cat_tiny.entries == ()


# ------------------------------------------------------------------ 6. Import-shadow / pytest path collision / runner failures


def test_06_import_shadow_collision_and_runner_failures_unverified(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=False)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    # 6a. Export to tests/demo.py -> filename collides with package `demo` during pytest collection!
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir, guard_rel="tests/demo.py")
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")

    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 12, f"expected UNVERIFIED (12) on pytest import collision, got {rc}\nstderr={err}\nobs={res.get('artifact', {}).get('obligations')}"
    assert not any(row["verdict"] == "refuted" for row in res["artifact"]["obligations"])
    obs = _obs_by_id(res["artifact"])
    guard_ob = obs["exported-guard:tests/demo.py:demo.calc.validate"]
    assert guard_ob["verdict"] == "unverified"
    assert guard_ob["witness"] is None
    assert "base run failed" in (guard_ob["stop_reason"] or "")
    assert "import_error" in (guard_ob["stop_reason"] or "")

    # 6b. Post import failure (base passes, post raises ImportError inside validate module) -> UNVERIFIED, no REFUTED.
    wc = {
        "module": "demo.calc",
        "qualname": "validate",
        "args": [0],
        "kwargs": {},
        "receiver": None,
        "env": None,
        "inject": None,
        "pre": {"k": "exc", "t": "builtins.ValueError", "m": "must be positive", "out": "", "g": ""},
        "post": {"k": "ret", "r": "0", "out": "", "g": ""},
    }
    base_oid, post_oid = TreeOid("a" * 40), TreeOid("b" * 40)
    canonical = build_pytest_source(
        adapt(wc), import_root="", base_commit="c" * 40, post_tree=str(post_oid), expect="pre"
    ).encode("utf-8")
    entry = AuthenticatedExportedGuard(
        source_run_id=RunId("run-000000000001"),
        source_obligation_id="differential:demo.calc.validate",
        base_tree_oid=base_oid,
        base_commit="c" * 40,
        post_tree_oid=post_oid,
        target_symbol="demo.calc.validate",
        module="demo.calc",
        qualname="validate",
        import_root="",
        expect="pre",
        canonical_sha256=sha256_hex(hashlib.sha256(canonical).hexdigest()),
        canonical_bytes=canonical,
        witness_call_json=json.dumps(wc, sort_keys=True),
    )
    bdir, pdir = tmp_path / "b_imp", tmp_path / "p_imp"
    (bdir / "demo").mkdir(parents=True)
    (bdir / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (bdir / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    shutil.copytree(bdir, pdir)
    (pdir / "demo" / "calc.py").write_text("import _nonexistent_shadow_mod_xyz\n" + FIXED_CALC, encoding="utf-8")
    proposer_file = tmp_path / "proposer.patch"
    proposer_file.write_text("secret", encoding="utf-8")

    match = exported_guard.MatchedExportedGuard("tests.test_hlith_guard.test_recorded_pre_behavior", "tests/test_hlith_guard.py", entry)
    ob = exported_guard.evaluate_exported_guard(
        match,
        base_dir=bdir,
        post_dir=pdir,
        scratch_dir=tmp_path / "scr_imp",
        target_python=sys.executable,
        extra_sys_path=(),
        proposer_paths=(str(proposer_file),),
    )
    assert ob.verdict is Verdict.UNVERIFIED
    assert ob.witness is None
    assert "import_error" in (ob.stop_reason or "")

    # 6c. Missing pytest in interpreter -> classified missing_pytest -> UNVERIFIED (never REFUTED/HELD).
    sys_py = shutil.which("python3")
    if sys_py and Path(sys_py).resolve() != Path(sys.executable).resolve():
        chk = subprocess.run([sys_py, "-I", "-c", "import pytest"], capture_output=True)
        if chk.returncode != 0:
            ob_nop = exported_guard.evaluate_exported_guard(
                match,
                base_dir=bdir,
                post_dir=bdir,
                scratch_dir=tmp_path / "scr_nopytest",
                target_python=sys_py,
                extra_sys_path=(),
                proposer_paths=(str(proposer_file),),
            )
            assert ob_nop.verdict is Verdict.UNVERIFIED
            assert "missing_pytest" in (ob_nop.stop_reason or "")


# ------------------------------------------------------------------ 7. Added signature_binding unresolved blocks discharge


def test_07_unresolved_added_signature_binding_blocks_discharge() -> None:
    guard_qn = "tests.test_hlith_guard.test_recorded_pre_behavior"
    acct = EffectAccount(
        run_id=RunId("run-000000000001"),
        base_tree_oid=TreeOid("a" * 40),
        patch_sha256=Sha256("b" * 64),
        post_tree_oid=TreeOid("c" * 40),
        analyzer_id="test",
        modified_callables=("demo.calc.validate",),
        added_callables=(guard_qn,),
    )
    guard_ob = Obligation(
        f"exported-guard:tests/test_hlith_guard.py:demo.calc.validate",
        guard_qn,
        "pre-guard passes",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )
    # 7a. signature_binding is NOT_DERIVED -> guard callable MUST NOT discharge.
    sb_not_derived = Obligation(
        f"signature_binding:{guard_qn}",
        guard_qn,
        "binding",
        Verdict.NOT_DERIVED,
        stop_reason="star-args caller unresolved",
    )
    prod_sb = Obligation("signature_binding:demo.calc.validate", "demo.calc.validate", "binding", Verdict.HELD, _evidence(), _provenance())
    prod_df = Obligation("differential:demo.calc.validate", "demo.calc.validate", "diff", Verdict.HELD, _evidence(), _provenance())
    obs, recs = consumption.bind([prod_sb, prod_df, sb_not_derived, guard_ob], acct)
    dis = scope.discharge(acct, obs, recs)
    assert f"callable:{guard_qn}" not in dict(dis.entries)
    assert scope_fully_discharged(RequiredScope.from_account(acct), dis) is False

    # 7b. Real Z3 analysis rejects an exported guard whose signature requires a parameter or has unknown call edges.
    req_bad_sig = {
        "obligation_id": f"signature_binding:{guard_qn}",
        "target_symbol": guard_qn,
        "added": True,
        "exported_guard_entry": True,
        "exported_guard_file": "tests/test_hlith_guard.py",
        "post_signature": "(unexpected_required_arg)",
        "call_sites": [],
        "entry_guards": [],
        "unknown_edge_count": 0,
    }
    res_bad_sig = z3_binding.analyze(req_bad_sig)
    assert res_bad_sig["refuted"], "0-arg pytest entry must fail Z3 binding if signature requires args"

    req_unk_edge = {**req_bad_sig, "post_signature": "()", "unknown_edge_count": 1}
    res_unk_edge = z3_binding.analyze(req_unk_edge)
    assert res_unk_edge["unresolved"], "unknown call edge must remain unresolved even for exported guard"


# ------------------------------------------------------------------ 8. Guard alone => NOT_DERIVED guard-alone blocker


def test_08_guard_alone_emits_not_derived_blocker(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    _seed_refuted_and_export_guard(repo, state_dir, ui_dir)

    # Revert demo/calc.py back to clean base; ONLY the uncommitted exported guard remains.
    (repo / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    rc, res, err = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc == 11, f"expected NOT-DERIVED (11) for guard-alone patch, got {rc}\nstderr={err}\nartifact={res.get('artifact')}"
    art = res["artifact"]
    assert art["outcome"] == "refused"
    obs = _obs_by_id(art)
    assert "guard-alone" in obs
    assert obs["guard-alone"]["verdict"] == "not-derived"
    assert "guard-alone" in art["blocking"]
    assert obs["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]["verdict"] == "held"


# ------------------------------------------------------------------ 9. Exact AccountConsumption and non-substitution


def test_09_exact_account_consumption_and_non_substitution() -> None:
    guard_qn = "tests.test_hlith_guard.test_recorded_pre_behavior"
    other_added_qn = "tests.test_other.test_unproven"
    acct = EffectAccount(
        run_id=RunId("run-000000000001"),
        base_tree_oid=TreeOid("a" * 40),
        patch_sha256=Sha256("b" * 64),
        post_tree_oid=TreeOid("c" * 40),
        analyzer_id="test",
        modified_callables=("demo.calc.validate",),
        added_callables=(guard_qn, other_added_qn),
        impacted_sites=(ImpactedSite("demo.app.call", "demo/app.py", 12),),
        guards=(EntryGuard("demo.calc.validate", "demo/calc.py", 2, "removed", "x <= 0"),),
        unknowns=(Unknown(GapCode.UNRESOLVED_CALL, "demo/calc.py:9", "dynamic call"),),
    )
    guard_ob = Obligation(
        "exported-guard:tests/test_hlith_guard.py:demo.calc.validate",
        guard_qn,
        "pre-guard passes",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )
    guard_sb = Obligation(
        f"signature_binding:{guard_qn}",
        guard_qn,
        "binding",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )
    prod_sb = Obligation(
        "signature_binding:demo.calc.validate",
        "demo.calc.validate",
        "binding",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )
    prod_df_unv = Obligation(
        "differential:demo.calc.validate",
        "demo.calc.validate",
        "diff",
        Verdict.UNVERIFIED,
        stop_reason="impacted test slice is empty",
    )
    other_sb = Obligation(
        f"signature_binding:{other_added_qn}",
        other_added_qn,
        "binding",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )

    obs, recs = consumption.bind([guard_ob, guard_sb, prod_sb, prod_df_unv, other_sb], acct)
    rec_by_id = {r.obligation_id: r for r in recs}
    assert guard_ob.obligation_id in rec_by_id
    assert rec_by_id[guard_ob.obligation_id].account_sha256 == acct.account_sha256
    assert rec_by_id[guard_ob.obligation_id].symbols == (guard_qn,)
    assert rec_by_id[guard_ob.obligation_id].edges == ()

    # Guard discharges ONLY its own callable:<guard_qn>, never production target, other added callable, sites, guards, or unknowns.
    dis = scope.discharge(acct, obs, recs)
    entries = dict(dis.entries)
    assert entries == {f"callable:{guard_qn}": guard_ob.obligation_id}
    assert scope_fully_discharged(RequiredScope.from_account(acct), dis) is False

    # Wrong account_sha256 on consumption blocks discharge of callable:<guard_qn>.
    wrong_cons = [
        AccountConsumption(guard_ob.obligation_id, Sha256("f" * 64), (guard_qn,), ()),
        *[r for r in recs if r.obligation_id != guard_ob.obligation_id],
    ]
    dis_wrong = scope.discharge(acct, obs, wrong_cons)
    assert f"callable:{guard_qn}" not in dict(dis_wrong.entries)

    # exported-guard targeting a non-added (production) callable is rejected by consumption.bind.
    bogus_guard = Obligation(
        "exported-guard:tests/test_hlith_guard.py:demo.calc.validate",
        "demo.calc.validate",
        "bogus",
        Verdict.HELD,
        evidence=_evidence(),
        provenance=_provenance(),
    )
    _, bogus_recs = consumption.bind([bogus_guard], acct)
    assert bogus_recs == ()


# ------------------------------------------------------------------ 10. Full CLI uncommitted loop e2e


def test_10_cli_uncommitted_refute_export_fix_recheck_e2e(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_base_test=True)
    state_dir, ui_dir = tmp_path / "state", tmp_path / "ui"
    env = _cli_env(state_dir, ui_dir)
    base_head = _git(repo, "rev-parse", "HEAD").strip()

    # 1. Buggy edit -> REFUTED (10) -> export uncommitted --expect pre guard
    run1, guard_path = _seed_refuted_and_export_guard(repo, state_dir, ui_dir)
    assert _git(repo, "rev-parse", "HEAD").strip() == base_head

    # 2. Still-buggy recheck with uncommitted guard -> REFUTED (10) from differential, guard UNVERIFIED
    fp_buggy = _repo_fingerprint(repo)
    rc_bug, res_bug, _ = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc_bug == 10
    assert _repo_fingerprint(repo) == fp_buggy
    obs_bug = _obs_by_id(res_bug["artifact"])
    assert obs_bug["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]["verdict"] == "unverified"
    assert obs_bug["differential:demo.calc.validate"]["verdict"] == "refuted"

    # 3. Fix production code with NO intermediate commit -> recheck passes rehearsal (0), original untouched
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    fp_fixed = _repo_fingerprint(repo)
    rc_fix, res_fix, err_fix = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc_fix == 0, f"expected 0 on fixed uncommitted check, got {rc_fix}\nstderr={err_fix}\nres={res_fix}"
    assert _repo_fingerprint(repo) == fp_fixed
    assert _git(repo, "rev-parse", "HEAD").strip() == base_head
    obs_fix = _obs_by_id(res_fix["artifact"])
    assert obs_fix["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]["verdict"] == "held"
    assert run1 in obs_fix["exported-guard:tests/test_hlith_guard.py:demo.calc.validate"]["evidence"]["explored"]

    # 4. Standalone pytest outside Hlith passes on the fixed repo!
    standalone = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys, pytest; sys.modules['hlith'] = None; raise SystemExit(pytest.main(['-q', '--noconftest', sys.argv[1]]))",
            str(guard_path),
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert standalone.returncode == 0, standalone.stdout + standalone.stderr
