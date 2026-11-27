"""Tests for docstring-only edits vs replacing statements with string constants in differential adequacy ablation."""
import json
import subprocess
import sys
from pathlib import Path

import pytest


from hlith import cli, docstring_check


@pytest.fixture(autouse=True)
def _enable_measured_docstring(monkeypatch):
    monkeypatch.setattr(docstring_check, "_DOCSTRING_MEASURED", True)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True, text=True, check=True,
    ).stdout


def _run_hlith(repo: Path, old_src: str, new_src: str, tmp_path: Path) -> dict:
    _git(repo, "init", "-q", "-b", "main")
    (repo / "mod.py").write_text(old_src)
    (repo / "test_mod.py").write_text("from mod import f\n\ndef test_f():\n    assert f(1) == 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")

    (repo / "mod.py").write_text(new_src)
    patch = tmp_path / "change.patch"
    manifest = tmp_path / "change.manifest.json"
    art_out = tmp_path / "out.json"
    patch.write_text(_git(repo, "diff"))
    manifest.write_text(json.dumps({"paths": {"mod.py": ["modify"]}}))
    _git(repo, "checkout", "-q", "mod.py")

    # This suite verifies the legacy LangGraph/Layer-1 docstring path; the pipeline engine rejects --layer1.
    cli.main([
        "run", "--repo", str(repo), "--patch", str(patch), "--manifest", str(manifest),
        "--artifact-out", str(art_out), "--engine", "legacy", "--layer1", "langgraph",
    ])
    return json.loads(art_out.read_text())


def test_docstring_only_edit_is_not_ablated_and_lands_with_doc_disclosure(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    old_src = 'def f(x: int) -> int:\n    """Return x plus one."""\n    return x + 1\n'
    new_src = 'def f(x: int) -> int:\n    """Return x plus 1 (updated docstring)."""\n    return x + 1\n'
    art = _run_hlith(repo, old_src, new_src, tmp_path)
    assert art["outcome"] == "landed" and art["exit_status"] == 0
    diff_ob = next(o for o in art["obligations"] if o["id"] == "differential:mod.f")
    assert diff_ob["verdict"] == "held"
    assert "__doc__" in (diff_ob.get("evidence") or {}).get("explored", "")


def test_replacing_statement_with_string_constant_is_still_refused(tmp_path):
    # Replacing a non-docstring body[0] statement with a string constant must NOT be treated as a docstring edit
    repo = tmp_path / "repo"
    repo.mkdir()
    old_src = 'def f(x: int) -> int:\n    y = x + 1\n    return x + 1\n'
    new_src = 'def f(x: int) -> int:\n    "replaced live statement with string"\n    return x + 1\n'
    art = _run_hlith(repo, old_src, new_src, tmp_path)
    assert art["outcome"] == "refused"
    assert art["exit_status"] in (10, 12)
