"""Host-side git sweep (case): no plain git spawn on a user-selected repository or a plain export dir.

Every site outside gate.py / tui/gitq.py that spawns git must either go through gate._run_git (repo-bound), the
hardened byte runner in hlith.gitsafe (repo-bound, bytes/Popen), or a scrubbed plain-directory run (no inherited
GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE, no user/system config, GIT_CEILING_DIRECTORIES, gate._HARDEN). Two attacks
per site: a repository whose config names a marker-touching core.fsmonitor program, and an inherited GIT_DIR /
GIT_WORK_TREE pointing at a different repository.
"""
import subprocess
from pathlib import Path

import pytest

from hlith import delta_review, derive, effect, gitexport, runtime

SRC = Path(__file__).resolve().parent.parent / "src" / "hlith"


def _g(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout


def _mk(path: Path, files: dict) -> Path:
    path.mkdir()
    _g(path, "init", "-q")
    for k, v in files.items():
        (path / k).write_text(v)
    _g(path, "add", ".")
    _g(path, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "c")
    return path


@pytest.fixture()
def repo(tmp_path):
    return _mk(tmp_path / "repo", {"m.py": "def f(x):\n    return x\n", "a.txt": "own\n"})


@pytest.fixture()
def other(tmp_path):
    return _mk(tmp_path / "other", {"m.py": "def f(x):\n    return x\n", "a.txt": "victim\n", "only_other.txt": "o\n"})


@pytest.fixture()
def fsmonitor(repo, tmp_path):
    marker = tmp_path / "pwned-fsmonitor"
    hook = tmp_path / "fsm.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nprintf ''\n")
    hook.chmod(0o755)
    _g(repo, "config", "core.fsmonitor", str(hook))
    # sanity: the program really runs under a plain git status on this repository
    subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True)
    assert marker.exists(), "fsmonitor hook did not run under plain git status: the probe is not meaningful"
    marker.unlink()
    return marker


@pytest.fixture()
def redirect(other, monkeypatch):
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_INDEX_FILE", str(other / ".git" / "index"))
    return other


DIFF = "--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return x + 1\n"


# ---- gitexport (repo-bound, bytes + Popen) ---------------------------------------------------

def test_gitexport_fsmonitor_not_executed(repo, fsmonitor, tmp_path):
    # Current behaviour (hostio/export.py): a repository whose config can execute programs is REFUSED before any git command runs
    # on it (stricter than the original "export but never run fsmonitor"); the program must not run and nothing is exported.
    from hlith.hostio.export import ExportError

    with pytest.raises(ExportError, match="core.fsmonitor"):
        gitexport.export_tree(repo, "HEAD", tmp_path / "out")
    assert not fsmonitor.exists()
    assert not (tmp_path / "out" / "a.txt").exists()


def test_gitexport_inherited_git_dir_does_not_redirect(repo, redirect, tmp_path):
    out = gitexport.export_tree(repo, "HEAD", tmp_path / "out")
    assert (out / "a.txt").read_text() == "own\n"
    assert not (out / "only_other.txt").exists()


# ---- delta_review (repo-bound rev-parse; discovery for the output dir) -----------------------

def _fingerprint(repo: Path) -> dict:
    """X9: bytes of the target's .git state a read must never change (config, HEAD, index, refs) plus the work tree files."""
    g = repo / ".git"
    out = {p.relative_to(repo).as_posix(): p.read_bytes() for p in (g / "config", g / "HEAD", g / "index") if p.exists()}
    out.update({p.relative_to(repo).as_posix(): p.read_bytes() for p in sorted((g / "refs").rglob("*")) if p.is_file()})
    out.update({p.name: p.read_bytes() for p in repo.iterdir() if p.is_file()})
    return out


def test_delta_review_fsmonitor_not_executed(repo, fsmonitor):
    # New design (RESUME-A §4/§10): the repo-bound rev-parse goes through gate._run_git, which now runs the closed-world vet and REFUSES a
    # repository whose config names core.fsmonitor (RuntimeError -> None). The old outcome (ran hardened, correct value) is still accepted;
    # a WRONG value, an executed program or a changed target never is.
    head = _g(repo, "rev-parse", "HEAD").strip()
    before = _fingerprint(repo)
    root = delta_review._git_root(repo)  # pure path logic since the change (no git process)
    got_head = delta_review._git_head(repo)
    got_commit = delta_review._git_commit(repo, head)
    assert root in (None, repo.resolve())
    assert got_head in (None, head)
    assert got_commit in (None, head)
    if got_head is None or got_commit is None:  # a refusal must be a NAMED refusal of the offending key, not a silent failure
        from hlith.gate import _run_git
        with pytest.raises(RuntimeError, match="core.fsmonitor"):
            _run_git(repo, ("rev-parse", "HEAD"), None)
    assert not fsmonitor.exists()
    assert _fingerprint(repo) == before


def test_delta_review_inherited_git_dir_does_not_redirect(repo, other, tmp_path, monkeypatch):
    head = _g(repo, "rev-parse", "HEAD").strip()
    victim = _g(other, "rev-parse", "HEAD").strip()
    plain = tmp_path / "plain-out"
    plain.mkdir()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert delta_review._git_root(repo) == repo.resolve()
    assert delta_review._git_head(repo) == head != victim
    assert delta_review._git_commit(repo, victim) is None  # the victim's commit is not in this repository
    assert delta_review._git_root(plain) is None  # a plain output dir is not inside the inherited work tree


# ---- effect (repo-bound rev-parse --absolute-git-dir; git apply in a plain copy) -------------

def test_effect_cache_dir_fsmonitor_not_executed(repo, fsmonitor):
    # The persistent index cache is host-owned now (effect/api.py EffectService(cache_dir=...)); the repository path
    # (build_effect_account, default use_index_cache=True) never computes a cache dir with git and never writes the target's .git.
    acct = effect.build_effect_account(repo, DIFF)
    assert any(c.qualified_name == "m.f" for c in acct.modified_callables)
    assert not fsmonitor.exists()
    assert not (repo / ".git" / "hlith-cache").exists()


def test_effect_cache_dir_inherited_git_dir_does_not_redirect(repo, redirect):
    # An inherited GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE must neither redirect the account nor plant a cache in either .git.
    acct = effect.build_effect_account(repo, DIFF)
    assert any(c.qualified_name == "m.f" for c in acct.modified_callables)
    assert not (repo / ".git" / "hlith-cache").exists()
    assert not (redirect / ".git" / "hlith-cache").exists()
    assert (redirect / "m.py").read_text() == "def f(x):\n    return x\n"


def test_effect_account_apply_ignores_inherited_git_env(repo, redirect):
    acct = effect.build_effect_account(repo, DIFF, use_index_cache=False)
    assert any(c.qualified_name == "m.f" for c in acct.modified_callables)
    assert (redirect / "m.py").read_text() == "def f(x):\n    return x\n"  # the other repository is untouched
    assert (repo / "m.py").read_text() == "def f(x):\n    return x\n"


# ---- derive (git apply in a plain export) ----------------------------------------------------

def test_derive_patched_copy_ignores_inherited_git_env(repo, redirect, tmp_path):
    post = derive._patched_copy(repo, DIFF, tmp_path / "d")
    assert "return x + 1" in (post / "m.py").read_text()
    assert "return x + 1" not in (redirect / "m.py").read_text()
    assert (post / "a.txt").read_text() == "own\n"


def test_derive_patched_copy_bad_diff_still_raises(repo, tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        derive._patched_copy(repo, "--- a/nope.py\n+++ b/nope.py\n@@ -1 +1 @@\n-a\n+b\n", tmp_path / "d")


# ---- runtime (rev-parse on the target; init/fetch of the scratch diff repo) ------------------

def test_runtime_target_rev_parse_fsmonitor_not_executed(repo, fsmonitor):
    runtime._git(repo, "rev-parse", "HEAD^{tree}")
    assert not fsmonitor.exists()


def test_runtime_target_rev_parse_inherited_git_dir_does_not_redirect(repo, other, monkeypatch):
    own = _g(repo, "rev-parse", "HEAD^{tree}").strip()
    victim = _g(other, "rev-parse", "HEAD^{tree}").strip()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert runtime._git(repo, "rev-parse", "HEAD^{tree}").strip() == own != victim


def test_runtime_diff_stage_ignores_inherited_git_env(repo, redirect, tmp_path):
    victim_refs = sorted(p.name for p in (redirect / ".git").iterdir())
    stage = gitexport.export_tree(repo, "HEAD", tmp_path / "stage")
    (stage / "m.py").write_text("def f(x):\n    return x + 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    diff, touched, _ign, _flags, _obs = runtime._diff_stage(repo, stage, scratch)
    assert touched == ("m.py",)
    assert "+    return x + 1" in diff and "only_other" not in diff
    assert sorted(p.name for p in (redirect / ".git").iterdir()) == victim_refs  # no FETCH_HEAD etc. in the victim


# ---- repo-wide guard ---------------------------------------------------------------------------

# The former regex site-list guards (test_no_unlisted_file_spawns_plain_git, test_runtime_has_no_unscrubbed_host_git,
# test_availability_only_entries_spawn_nothing) are SUPERSEDED by the AST sweep tests/test_git_sweep_ast.py (X1: every route to a git argv,
# named-exception table with classes and reasons, stale-row check, positive/negative controls). Their three specific claims are kept here,
# checked with that AST checker so they cannot silently disappear with the file swap.

def _ast_sweep():
    import importlib.util
    path = Path(__file__).resolve().parent / "test_git_sweep_ast.py"
    assert path.is_file(), "the AST sweep that supersedes the old site lists is missing"
    spec = importlib.util.spec_from_file_location("_git_sweep_ast_for_hardening", path)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod  # @dataclass resolves its module through sys.modules
    spec.loader.exec_module(mod)
    return mod


def test_superseded_site_guards_hold_under_the_ast_sweep():
    ast_sweep = _ast_sweep()
    sites, _info = ast_sweep.scan(SRC)
    # (was test_runtime_has_no_unscrubbed_host_git) the agent's target reads never spawn git themselves (case)
    for fn in ("_read_head_tree", "_export_clean_tree"):
        assert not [s for s in sites if s.rel == "agent/supervisor.py" and s.qualname == fn], f"agent/supervisor.py {fn} spawns git"
        assert ("agent/supervisor.py", fn) not in ast_sweep.NAMED_EXCEPTIONS
    # (was test_availability_only_entries_spawn_nothing) operator/cli.py doctor only LOOKS UP git: no git site, no exception row
    assert 'which("git")' in (SRC / "operator" / "cli.py").read_text()
    assert not [s for s in sites if s.rel == "operator/cli.py"]
    assert not [k for k in ast_sweep.NAMED_EXCEPTIONS if k[0] == "operator/cli.py"]
    # (was test_no_unlisted_file_spawns_plain_git) every git site outside the choke point is a named exception
    unnamed = [s for s in sites if s.rel != ast_sweep.CHOKE_POINT and (s.rel, s.qualname) not in ast_sweep.NAMED_EXCEPTIONS]
    assert not unnamed, unnamed
