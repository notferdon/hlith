"""NEGATIVE meta-tests (case): each standards checker is run on a COPY of the repository whose subject was mutated,
and must FAIL. The unmutated copy must pass first (positive control), so a checker that always fails cannot pass these tests either."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def copied_repo(destination: Path) -> Path:
    root = destination / "repo"
    root.mkdir()
    for rel in ("pyproject.toml", "uv.lock", "README.md"):
        shutil.copy2(ROOT / rel, root / rel)
    for rel in ("src", "tests", "scripts", ".github"):
        shutil.copytree(ROOT / rel, root / rel, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return root


def run(root: Path, check: str, *args: str) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(root / "scripts" / check), *args]
    if check == "check_layer_dag.py":
        argv += ["--map", str(root / "scripts" / "layer_map.json"), "--src", str(root / "src")]
    elif not args:
        argv += ["--root", str(root)]
    return subprocess.run(argv, cwd=root, text=True, capture_output=True, check=False, timeout=600)


@pytest.fixture(scope="module")
def pristine(tmp_path_factory):
    return copied_repo(tmp_path_factory.mktemp("pristine"))


@pytest.mark.parametrize("check", ["check_standards.py", "check_term_lock.py", "check_layer_dag.py", "check_no_vacuous.py"])
def test_positive_control_unmutated_copy_passes(pristine, check):
    r = run(pristine, check)
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------------------------------------------------ check_standards.py
def test_standards_rejects_a_1x_version(tmp_path):
    root = copied_repo(tmp_path)
    p = root / "pyproject.toml"
    assert 'version = "0.1.2"' in p.read_text()
    p.write_text(p.read_text().replace('version = "0.1.2"', 'version = "1.0.0"', 1))
    r = run(root, "check_standards.py")
    assert r.returncode != 0 and "must stay 0.y.z" in r.stderr


def test_standards_rejects_a_floating_workflow_action(tmp_path):
    root = copied_repo(tmp_path)
    w = root / ".github/workflows/standards.yml"
    pinned = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    assert pinned in w.read_text()
    w.write_text(w.read_text().replace(pinned, "actions/checkout@v4"))
    r = run(root, "check_standards.py")
    assert r.returncode != 0 and "full 40-character commit SHA" in r.stderr


def test_standards_rejects_a_test_module_inside_src(tmp_path):
    root = copied_repo(tmp_path)
    (root / "src/hlith/test_sneaky.py").write_text("def test_x():\n    pass\n")
    r = run(root, "check_standards.py")
    assert r.returncode != 0 and "test modules belong outside src/" in r.stderr


@pytest.mark.parametrize("rel", ["scripts/verify_kill_lines.sh", "scripts/layer_map.json", ".github/workflows"])
def test_standards_hard_fails_on_a_missing_required_path(tmp_path, rel):
    root = copied_repo(tmp_path)
    target = root / rel
    shutil.rmtree(target) if target.is_dir() else target.unlink()
    r = run(root, "check_standards.py")
    assert r.returncode != 0 and f"required path missing: {rel}" in r.stderr


# ------------------------------------------------------------------------------------------------ check_term_lock.py
def test_term_lock_rejects_a_new_verdict_value(tmp_path):
    root = copied_repo(tmp_path)
    t = root / "src/hlith/types.py"
    assert 'NOT_DERIVED = "not-derived"' in t.read_text()
    t.write_text(t.read_text().replace('NOT_DERIVED = "not-derived"', 'NOT_DERIVED = "accepted"', 1))
    r = run(root, "check_term_lock.py")
    assert r.returncode != 0 and "Verdict values must be exactly" in r.stderr


def test_term_lock_rejects_a_parallel_verdict_enum(tmp_path):
    root = copied_repo(tmp_path)
    p = root / "src/hlith/operator/presentation.py"
    p.write_text(p.read_text() + "\n\nclass Verdict:\n    OK = 'ok'\n")
    r = run(root, "check_term_lock.py")
    assert r.returncode != 0 and "class Verdict must be defined exactly once" in r.stderr


def test_term_lock_rejects_a_foreign_cli_surface_term(tmp_path):
    root = copied_repo(tmp_path)
    cli = root / "src/hlith/cli.py"
    cli.write_text(cli.read_text() + '\n_LEGACY_PRODUCT_LABEL = "Cedar"\n')
    r = run(root, "check_term_lock.py")
    assert r.returncode != 0 and "foreign product/scanner term 'cedar'" in r.stderr


# ------------------------------------------------------------------------------------------------ check_layer_dag.py (ratchet)
UPWARD = "\n\nfrom .. import gate  # injected upward edge (meta-test)\n"
LAZY = "\n\ndef _late():\n    from ..gate import api  # injected LAZY upward edge (meta-test)\n    return api\n"


@pytest.mark.parametrize("snippet", [UPWARD, LAZY], ids=["module-level", "lazy-in-function"])
def test_layer_dag_rejects_a_new_upward_import(tmp_path, snippet):
    root = copied_repo(tmp_path)
    p = root / "src/hlith/contract/codec.py"
    p.write_text(p.read_text() + snippet)
    r = run(root, "check_layer_dag.py")
    assert r.returncode != 0 and "VIOLATION" in r.stdout and "hlith.contract.codec" in r.stdout, r.stdout


def test_layer_dag_rejects_a_stale_baseline_entry(tmp_path):
    """Ratchet: a known violation may be baselined, but once it is gone its baseline entry must be removed, else FAIL."""
    root = copied_repo(tmp_path)
    p = root / "src/hlith/contract/codec.py"
    original = p.read_text()
    p.write_text(original + UPWARD)
    pb =run(root, "check_layer_dag.py", "--print-baseline").stdout
    ids = json.loads(pb[pb.index("[\n"): pb.index("\n]") + 2])  # json.dumps(indent=2) of a non-empty list
    assert ids, pb
    m = root / "scripts/layer_map.json"
    data = json.loads(m.read_text())
    data["known_baseline"] = ids
    m.write_text(json.dumps(data, indent=2))
    r_known = run(root, "check_layer_dag.py")
    assert r_known.returncode == 0, "a baselined violation is KNOWN and passes: " + r_known.stdout
    p.write_text(original)  # the violation is fixed, the baseline entry is now stale
    r = run(root, "check_layer_dag.py")
    assert r.returncode != 0 and "stale baseline entry" in r.stdout, r.stdout


def test_layer_dag_hard_fails_on_a_missing_file_entrypoint(tmp_path):
    root = copied_repo(tmp_path)
    entry = json.loads((root / "scripts/layer_map.json").read_text())["file_entrypoints"][0]["file"]
    (root / "src" / entry).unlink()
    r = run(root, "check_layer_dag.py")
    assert r.returncode != 0 and "MISSING" in r.stdout, r.stdout


# ------------------------------------------------------------------------------------------------ check_no_vacuous.py
UNRESOLVED_NAME = "\n\ndef _late_name():\n    from hlith.contract.codec import no_such_name_meta  # injected unresolved name (meta-test)\n    return no_such_name_meta\n"


def test_import_names_rejects_an_unresolved_name(tmp_path):
    root = copied_repo(tmp_path)
    p = root / "src/hlith/operator/gitq.py"
    p.write_text(p.read_text() + UNRESOLVED_NAME)
    r = run(root, "check_layer_dag.py")
    assert r.returncode != 0 and "UNRESOLVED" in r.stdout and "no_such_name_meta" in r.stdout, r.stdout


def test_import_names_rejects_a_stale_baseline_entry(tmp_path):
    """Same ratchet as the layer DAG: a baselined unresolved name passes while it occurs; once it is gone, its entry FAILS."""
    root = copied_repo(tmp_path)
    p = root / "src/hlith/operator/gitq.py"
    original = p.read_text()
    p.write_text(original + UNRESOLVED_NAME)
    ids = [ln.split(" ", 1)[1] for ln in run(root, "check_layer_dag.py").stdout.splitlines() if ln.startswith("UNRESOLVED ")]
    assert ids
    m = root / "scripts/layer_map.json"
    data = json.loads(m.read_text())
    data["known_unresolved_names"] = ids
    m.write_text(json.dumps(data, indent=2))
    r_known = run(root, "check_layer_dag.py")
    assert r_known.returncode == 0, "a baselined unresolved name is KNOWN and passes: " + r_known.stdout
    p.write_text(original)  # fixed: the baseline entry is now stale
    r = run(root, "check_layer_dag.py")
    assert r.returncode != 0 and "stale baseline entry" in r.stdout, r.stdout


def test_no_vacuous_rejects_zero_collected_tests(tmp_path):
    root = copied_repo(tmp_path)
    for f in (root / "tests/standards").glob("test_*.py"):
        f.write_text("value = 1\n")
    r = run(root, "check_no_vacuous.py")
    assert r.returncode != 0 and "collected zero standards tests" in r.stderr


def test_no_vacuous_rejects_a_missing_test_directory(tmp_path):
    root = copied_repo(tmp_path)
    shutil.rmtree(root / "tests/standards")
    r = run(root, "check_no_vacuous.py")
    assert r.returncode != 0 and "required path missing: tests/standards" in r.stderr
