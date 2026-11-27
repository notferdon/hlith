"""feedback.py must reach git only through gate._run_git: repository-configured programs and inherited GIT_* variables must not run or redirect."""
import ast
import subprocess
from pathlib import Path

import pytest

from hlith.feedback import _legacy as feedback


def _git(repo, *a, env=None):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env)


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "a.txt").write_text("x\n")
    _git(r, "add", ".")
    _git(r, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "c")
    return r


def _fingerprint(repo: Path) -> dict:
    g = repo / ".git"
    out = {p.relative_to(repo).as_posix(): p.read_bytes() for p in (g / "config", g / "HEAD", g / "index") if p.exists()}
    out.update({p.relative_to(repo).as_posix(): p.read_bytes() for p in sorted((g / "refs").rglob("*")) if p.is_file()})
    out.update({p.name: p.read_bytes() for p in repo.iterdir() if p.is_file()})
    return out


def test_fsmonitor_program_in_repo_config_is_not_executed(repo, tmp_path):
    # New design (RESUME-A §10): feedback's runner runs the closed-world vet first, so the stronger outcome is a NAMED refusal
    # (FeedbackWriteRefused naming core.fsmonitor). A hardened clean run is still accepted; the program running or the target changing never is.
    marker = tmp_path / "pwned-fsmonitor"
    hook = tmp_path / "fsm.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nprintf ''\n")
    hook.chmod(0o755)
    _git(repo, "config", "core.fsmonitor", str(hook))
    subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True)
    assert marker.exists(), "fsmonitor did not run under plain git status: the probe is not meaningful"
    marker.unlink()
    before = _fingerprint(repo)
    own_head = subprocess.run(["git", "-C", str(repo), "-c", "core.fsmonitor=", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout
    for args, clean in ((("ls-files", "--", ".hlith"), None), (("rev-parse", "HEAD"), own_head)):
        try:
            out = feedback._git(repo, *args)
        except feedback.FeedbackWriteRefused as e:
            assert "core.fsmonitor" in str(e), e
        else:
            assert clean is None or out == clean
    assert not marker.exists()
    assert _fingerprint(repo) == before


def test_inherited_git_dir_does_not_redirect_a_call_on_another_repo(repo, tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    (other / "b.txt").write_text("y\n")
    _git(other, "add", ".")
    _git(other, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "o")
    victim_head = subprocess.run(["git", "-C", str(other), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    own_head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert feedback._git(repo, "rev-parse", "HEAD").strip() == own_head != victim_head


def _calls(fn: ast.AST) -> list[tuple[int, str]]:
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            out.append((n.lineno, name))
    return out


def test_no_raw_git_subprocess_remains_in_feedback():
    """Feedback reaches a user-selected repository ONLY through the choke point: _run_git_ro vets (hostio.git_read.vet_repository) before
    its one spawn and takes its argv from hostio.git_read.readonly_argv; the only git argv literal left in the package is the plain-dir
    `git apply` in _apply_diff_scrubbed (named exception in tests/test_git_sweep_ast.py). Was: one literal *_HARDEN argv +
    _target_git_dir_violation (shape-only vet)."""
    pkg = Path(feedback.__file__).parent
    git_argv_sites = []
    for py in sorted(pkg.glob("*.py")):
        tree = ast.parse(py.read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for n in ast.walk(fn):
                    if isinstance(n, (ast.List, ast.Tuple)) and n.elts:
                        e = n.elts[0]
                        if (isinstance(e, ast.Constant) and e.value == "git") or (isinstance(e, ast.Name) and e.id == "_GIT_BIN"):
                            git_argv_sites.append((py.name, fn.name))
    assert set(git_argv_sites) <= {("_legacy.py", "_apply_diff_scrubbed")}, f"git argv outside the plain-dir apply: {git_argv_sites}"
    legacy = ast.parse((pkg / "_legacy.py").read_text())
    ro = next(n for n in ast.walk(legacy) if isinstance(n, ast.FunctionDef) and n.name == "_run_git_ro")
    calls = _calls(ro)
    vets = [ln for ln, name in calls if name == "vet_repository"]
    spawns = [ln for ln, name in calls if name in ("run", "Popen", "_spawn", "run_readonly")]
    assert vets, "_run_git_ro does not call the choke point's vet_repository"
    assert spawns and min(vets) < min(spawns), "_run_git_ro spawns before (or without) the vet"
    assert "readonly_argv" in {name for _ln, name in calls} or "run_readonly" in {name for _ln, name in calls}, \
        "_run_git_ro builds its own git argv instead of the choke point's builder"


def test_apply_diff_in_an_export_ignores_inherited_git_env_and_applies_the_patch(tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    export = tmp_path / "export"
    export.mkdir()
    (export / "f.txt").write_text("one\n")
    diff = "--- a/f.txt\n+++ b/f.txt\n@@ -1 +1 @@\n-one\n+two\n"
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    cp = feedback._apply_diff_scrubbed(export, diff)
    assert cp.returncode == 0, cp.stderr
    assert (export / "f.txt").read_text() == "two\n"
    assert not (other / "f.txt").exists()
