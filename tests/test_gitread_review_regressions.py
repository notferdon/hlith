"""Regressions for the defects an independent broad review confirmed on 6e49cbcd (case). Each test reproduces the reviewer's observed failure on a throwaway repository.

1. CRLF files + ``* text=auto``: the verified post tree must be EXACTLY base + patch (no conversion), so the gate's landed tree equals it.
2. An ordinary gitignored local file at a path the patch creates: refused BEFORE the journal begins; a refused ``apply --check`` leaves nothing to roll back.
3. Ordinary inert config written by common tooling is not a false refusal; non-allowed keys are all named at once.
4. A path from a patch is a PATH (``:(exclude)x`` / ``[id]``): never pathspec magic.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hlith.gate import git_write as gw
from hlith.hostio import git_read as g
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.operator import gitq


def _git(repo: Path, *a: str) -> bytes:
    return subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(repo), *a], capture_output=True, check=True).stdout


def _commit(repo: Path, msg: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false", "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", msg],
                   check=True, capture_output=True)


def _repo(tmp_path: Path, name: str = "r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    return r


# ---- 1. CRLF + text=auto -------------------------------------------------------------------------------------------------------------------------

def _crlf_repo(tmp_path: Path) -> Path:
    r = _repo(tmp_path)
    (r / "win.txt").write_bytes(b"line1\r\nline2\r\n")  # committed with CRLF BEFORE the attributes existed
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _commit(r, "base")
    (r / ".gitattributes").write_text("* text=auto\n")
    _git(r, "add", ".gitattributes")
    _commit(r, "attrs")
    return r


PATCH_UNTOUCHED = b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
PATCH_TOUCHES_CRLF = b"diff --git a/win.txt b/win.txt\n--- a/win.txt\n+++ b/win.txt\n@@ -1,2 +1,2 @@\n line1\r\n-line2\r\n+line2 changed\r\n"


@pytest.mark.parametrize("patch", [PATCH_UNTOUCHED, PATCH_TOUCHES_CRLF], ids=["patch-leaves-the-crlf-file-alone", "patch-edits-the-crlf-file"])
def test_verified_post_tree_is_exactly_base_plus_patch_under_text_auto(tmp_path, patch):
    repo = _crlf_repo(tmp_path)
    svc = LocalSnapshotService(root=tmp_path / "snaps")
    base = svc.seal_base(repo)
    post = svc.reconstruct_post(base, patch)
    assert (post.path / "win.txt").read_bytes().startswith(b"line1\r\nline2") , "the verified post tree normalised a CRLF file"
    touched = set(gw.changed_paths_between_snapshots(base.path, post.path))
    assert touched == ({"win.txt"} if patch is PATCH_TOUCHES_CRLF else {"a.py"}), touched
    assert gw.apply_index_and_verify_tree(repo, patch, post.tree_oid) is True, "the gate's landed tree differs from the verified post tree: every landing would be refused"


# ---- 2. ignored local file at a created path ------------------------------------------------------------------------------------------------------

def test_gitignored_local_file_at_a_created_path_is_refused_before_the_journal_and_apply_check_failure_is_typed(tmp_path):
    repo = _repo(tmp_path)
    (repo / "a.txt").write_text("a1\n")
    (repo / ".gitignore").write_text("local.cfg\n")
    _git(repo, "add", "-A")
    _commit(repo, "base")
    (repo / "local.cfg").write_text("operator local settings\n")
    patch = b"diff --git a/local.cfg b/local.cfg\nnew file mode 100644\n--- /dev/null\n+++ b/local.cfg\n@@ -0,0 +1 @@\n+agent version\n"
    paths = gw.patch_paths(repo, patch)
    assert paths == ["local.cfg"]
    assert gw.dirty_target_reason(repo, paths) is not None, "an ignored local file at a created path must be refused before begin_journal"
    with pytest.raises(gw.PatchDoesNotApply):  # and when apply --check does fail, it is typed: nothing was written, nothing to roll back
        gw.apply_index_and_verify_tree(repo, patch, "0" * 40)
    assert (repo / "local.cfg").read_text() == "operator local settings\n"


# ---- 3. ordinary inert config -------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("key,value", [
    ("remote.origin.gh-resolved", "base"), ("remote.origin.prune", "true"), ("pull.ff", "only"), ("branch.main.pushremote", "origin"),
    ("branch.main.description", "the main line"), ("core.untrackedcache", "true"), ("rerere.enabled", "true"), ("advice.detachedHead", "false"),
    ("push.autoSetupRemote", "true"), ("user.signingkey", "ABCD1234"),
])
def test_ordinary_inert_config_is_not_a_false_refusal(tmp_path, key, value):
    repo = _repo(tmp_path)
    (repo / "a.txt").write_text("a\n")
    _git(repo, "add", "-A")
    _commit(repo, "base")
    _git(repo, "config", key, value)
    assert g.vet_repository(repo) is None, g.vet_repository(repo)
    assert gitq.refusal(repo) is None


def test_every_offending_key_is_named_in_one_refusal(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "core.autocrlf", "true")
    _git(repo, "config", "core.editor", "vi")
    why = g.vet_repository(repo)
    assert why and "core.autocrlf" in why and "core.editor" in why, why


# ---- 4. a path is a path ----------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", [":(exclude)zz", "app/[id]/page.tsx"])
def test_patch_paths_are_literal_for_every_gate_command(tmp_path, name):
    repo = _repo(tmp_path)
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("z1\n")
    sibling = repo / "app" / "x" / "page.tsx"
    sibling.parent.mkdir(parents=True, exist_ok=True)
    sibling.write_text("sib\n")
    _git(repo, "add", "-A")
    _commit(repo, "base")
    base = gw.head_commit(repo)
    patch = (f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-z1\n+z2-AGENT\n").encode()
    paths = gw.patch_paths(repo, patch)
    assert paths == [name]
    assert gw.dirty_target_reason(repo, paths) is None
    images = gw.compute_path_images(repo, base, patch, paths)
    assert gw.run_target_git(repo, ("apply", "--index", "-"), input_bytes=patch).returncode == 0
    sibling.write_text("sibling edited by the operator, must survive the rollback\n")
    _git(repo, "add", "app/x/page.tsx")
    gw.rollback_paths(repo, base, paths, images)
    assert target.read_text() == "z1\n"
    assert sibling.read_text() == "sibling edited by the operator, must survive the rollback\n", "the rollback reset/checkout hit a sibling path through a glob"


# ---- 5. a stub .git in a parent directory is not a repository (found with TMPDIR under a home directory that holds a stub .git) -------------------------------

def test_stub_dot_git_in_a_parent_is_not_a_repository(tmp_path):
    from hlith.gitsafe import discover_toplevel

    home = tmp_path / "home"
    (home / ".git").mkdir(parents=True)  # a stub: no HEAD, no objects, no refs
    child = home / "work" / "plain"
    child.mkdir(parents=True)
    root, why = gitq.toplevel(child)
    assert root is None and "not a git repository" in why
    assert discover_toplevel(child) is None
    real = _repo(tmp_path, "real")
    (real / "sub").mkdir()
    assert gitq.toplevel(real / "sub")[0] == real.resolve()
    assert discover_toplevel(real / "sub").decode().strip() == str(real.resolve())
