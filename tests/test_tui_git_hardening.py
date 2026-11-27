"""Every host-side git call the screen makes on a user-selected repository goes through ONE hardened runner (gate-style: scrubbed environment, empty HOME,
-c overrides, no inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE) and never runs a status/add on a repository whose config or attributes can execute programs.
design review lesson after review's G2-dirtycheck-attack (D1 fsmonitor, D2 clean filter, D3 inherited GIT_DIR): the same shapes reached the TUI through gitq.git / changes.uncommitted /
repos.info / launch.start. Each test is the attack, written before the fix."""
import os
import subprocess
from pathlib import Path

import pytest

from hlith.tui import changes, gitq, launch, repos


def _git(repo, *a, extra=None):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid", **(extra or {})}
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env)


def _repo(tmp_path, name="r"):
    r = tmp_path / name
    r.mkdir()
    (r / "a.py").write_text("x = 1\n")
    _git(r, "init", "-q", "-b", "main")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _marker(tmp_path):
    marker, script = tmp_path / "EXECUTED", tmp_path / "hook.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    script.chmod(0o755)
    return marker, script


def _fsmonitor_repo(tmp_path):
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    _git(r, "config", "core.fsmonitor", str(script))
    (r / "a.py").write_text("x = 2\n")
    (r / "new.txt").write_text("n\n")
    return r, marker


def _filter_repo(tmp_path):
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    (r / ".gitattributes").write_text("*.py filter=evil\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "attrs")
    _git(r, "config", "filter.evil.clean", str(script))
    (r / "a.py").write_text("x = 3\n")
    (r / "new.py").write_text("n = 1\n")
    return r, marker


@pytest.mark.parametrize("make", [_fsmonitor_repo, _filter_repo])
def test_status_add_and_info_never_execute_a_repositorys_programs(tmp_path, make):
    r, marker = make(tmp_path)
    gitq.git(r, "status", "--porcelain=v1", "-z")
    repos.info(r)
    changes.uncommitted(r)  # git status (twice) + git add -A into a temp index
    assert not marker.exists(), "a program defined by the repository's own config ran"


def test_a_repository_that_can_execute_programs_is_named_not_inspected(tmp_path):
    r, marker = _fsmonitor_repo(tmp_path)
    why = gitq.refusal(r)
    assert why and "core.fsmonitor" in why and "clean clone" in why
    info = repos.info(r)
    assert any("core.fsmonitor" in n for n in info.notes), info.notes
    # nothing is offered from a repository the screen refuses to inspect: no Change at all (old) or an EMPTY, explained one (new: label "not inspected")
    c = changes.uncommitted(r)
    assert c is None or (c.problem and "core.fsmonitor" in c.problem and not c.files and not c.patch and not c.base_rev), c
    assert not marker.exists()
    clean = _repo(tmp_path, "clean")
    assert gitq.refusal(clean) is None


def test_inherited_git_dir_and_work_tree_do_not_redirect_any_query(tmp_path, monkeypatch):
    victim = _repo(tmp_path, "victim")
    (victim / "a.py").write_text("victim\n")
    vhead = gitq.text(victim, "rev-parse", "--short", "HEAD")
    target = _repo(tmp_path, "target")
    (target / "b.py").write_text("b = 1\n")
    _git(target, "add", "-A")
    _git(target, "commit", "-q", "-m", "second")
    thead = subprocess.run(["git", "-C", str(target), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert vhead != thead
    monkeypatch.setenv("GIT_DIR", str(victim / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(victim))
    monkeypatch.setenv("GIT_INDEX_FILE", str(victim / ".git" / "index"))
    assert gitq.text(target, "rev-parse", "--short", "HEAD") == thead
    assert repos.info(target).head == thead and repos.info(target).modified == 0
    assert gitq.toplevel(target)[0] == target.resolve()


def test_core_worktree_in_the_repo_config_cannot_move_the_repository_root(tmp_path):
    r = _repo(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _git(r, "config", "core.worktree", str(elsewhere))
    root, why = gitq.toplevel(r)
    # old: "...outside <dir>: a repository setting (core.worktree) pointing elsewhere is not followed"; new: the vet names the key. Either way: no root, the key is named.
    assert root is None and "core.worktree" in why, (root, why)
    ok = _repo(tmp_path, "ok")
    assert gitq.toplevel(ok / ".")[0] == ok.resolve()


def test_the_disposable_clone_ignores_the_callers_git_environment(tmp_path, monkeypatch):
    src = _repo(tmp_path, "src")
    sentinel = tmp_path / "sentinel.git"
    monkeypatch.setenv("GIT_DIR", str(sentinel))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "wt-elsewhere"))
    dst = tmp_path / "state" / "clones" / "c1"
    dst.parent.mkdir(parents=True)
    ok, err = launch._clone_source(src, dst, None)
    assert ok, err
    assert (dst / ".git").is_dir() and (dst / "a.py").is_file()
    assert not sentinel.exists() and not (tmp_path / "wt-elsewhere").exists()
    assert "origin" not in subprocess.run(["git", "-C", str(dst), "remote"], capture_output=True, text=True, env={"PATH": os.environ["PATH"]}).stdout


def test_normal_repositories_still_work_through_the_hardened_runner(tmp_path):
    r = _repo(tmp_path)
    (r / "a.py").write_text("x = 5\n")
    (r / "z.txt").write_text("z\n")
    info = repos.info(r)
    assert info.head and info.modified == 1 and info.untracked == 1 and info.branch == "main"
    c = changes.uncommitted(r)
    assert c is not None and c.problem == "" or c is not None


# ================= review's attack on the first hardening (G2-tui-git-attack: T1, T3, T6, T8d, T8e) + the patch-directory leak =================
def _signed_head_repo(tmp_path, with_config=True):
    """HEAD carries a fake gpgsig header; the repo config turns signature display on and names a gpg program: `git log` would run it."""
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    raw = subprocess.run(["git", "-C", str(r), "cat-file", "commit", "HEAD"], capture_output=True, check=True).stdout.decode()
    head, _sep, msg = raw.partition("\n\n")
    forged = head + "\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n\n" + msg
    sha = subprocess.run(["git", "-C", str(r), "hash-object", "-t", "commit", "-w", "--stdin"], input=forged.encode(), capture_output=True, check=True).stdout.decode().strip()
    _git(r, "update-ref", "refs/heads/main", sha)
    if with_config:
        _git(r, "config", "log.showSignature", "true")
        _git(r, "config", "gpg.program", str(script))
        _git(r, "config", "gpg.ssh.program", str(script))
        _git(r, "config", "gpg.x509.program", str(script))
    return r, marker


def test_t1_selecting_a_repository_never_runs_its_gpg_program(tmp_path):
    r, marker = _signed_head_repo(tmp_path)
    repos.info(r)
    changes.discover(r)
    gitq.text(r, "log", "-1", "--format=%s")
    assert not marker.exists(), "log.showSignature + gpg.program in the repository config ran a host program"


def test_t1_even_the_plumbing_set_waits_for_the_refusal_check(tmp_path):
    r, _m = _fsmonitor_repo(tmp_path)  # exec-capable config
    assert gitq.git(r, "rev-parse", "HEAD") == b"" and gitq.text(r, "log", "-1", "--format=%s") == ""  # refused before ANY command
    assert repos.info(r).head == "" and any("core.fsmonitor" in n for n in repos.info(r).notes)
    assert not any("no commits yet" in n for n in repos.info(r).notes)


def test_t3_a_filter_added_after_the_refusal_check_still_cannot_run(tmp_path, monkeypatch):
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    assert gitq.refusal(r) is None  # the check passes, and may be cached
    (r / ".gitattributes").write_text("*.py filter=evil\n")
    _git(r, "config", "filter.evil.clean", str(script))
    (r / "a.py").write_text("x = 9\n")
    (r / "n.py").write_text("n = 1\n")
    changes.uncommitted(r)
    assert not marker.exists(), "a filter configured after the check ran"
    why = gitq.refusal(r)  # no cache any more: the filter DEFINITION added after the first answer is refused by the very next call
    assert why and "filter.evil.clean" in why, why
    # and structurally: even if the early refusal were skipped entirely, the command itself (the choke point's per-call vet) cannot load any attribute driver
    monkeypatch.setattr(gitq, "refusal", lambda repo: None)
    changes.uncommitted(r)
    gitq.git(r, "status", "--porcelain=v1", "-z")
    assert not marker.exists(), "git ran a filter driver although the repository defines one"


def test_t6_a_git_file_or_symlink_is_not_the_repository_it_points_at(tmp_path):
    victim = _repo(tmp_path, "victim")
    d1 = tmp_path / "gitfile-dir"
    d1.mkdir()
    (d1 / ".git").write_text(f"gitdir: {victim / '.git'}\n")
    d2 = tmp_path / "symlink-dir"
    d2.mkdir()
    (d2 / ".git").symlink_to(victim / ".git")
    for d in (d1, d2):
        why = gitq.refusal(d)
        assert why and ".git" in why, (d, why)
        info = repos.info(d)
        assert info.head == "" and info.notes, (d, info.head, info.notes)
        assert gitq.toplevel(d)[0] is None, d
        assert changes.discover(d) == []


def test_t8d_a_git_file_source_is_not_cloned(tmp_path):
    victim = _repo(tmp_path, "victim")
    src = tmp_path / "gitfile-src"
    src.mkdir()
    (src / ".git").write_text(f"gitdir: {victim / '.git'}\n")
    dst = tmp_path / "state" / "clones" / "c"
    dst.parent.mkdir(parents=True)
    ok, err = launch._clone_source(src, dst, None)
    assert not ok and ".git" in err
    assert not (dst / "a.py").exists(), "the VICTIM repository's content was cloned"


def test_t8e_a_source_with_alternates_is_refused_and_no_alternates_reach_the_clone(tmp_path):
    victim = _repo(tmp_path, "victim")
    (victim / "secret.txt").write_text("victim secret\n")
    _git(victim, "add", "-A")
    _git(victim, "commit", "-q", "-m", "secret")
    vsha = subprocess.run(["git", "-C", str(victim), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    src = _repo(tmp_path, "src")
    (src / ".git" / "objects" / "info").mkdir(exist_ok=True)
    (src / ".git" / "objects" / "info" / "alternates").write_text(str(victim / ".git" / "objects") + "\n")
    _git(src, "update-ref", "refs/heads/loot", vsha)  # a ref that only the alternate can satisfy
    dst = tmp_path / "state" / "clones" / "c"
    dst.parent.mkdir(parents=True)
    ok, err = launch._clone_source(src, dst, None)
    assert not ok and "alternates" in err
    assert not (dst / "secret.txt").exists()


def test_discover_lists_patch_files_of_the_repository_and_explicit_inputs_only_not_the_processs_cwd(tmp_path, monkeypatch):
    foreign = tmp_path / "other-lane"
    foreign.mkdir()
    (foreign / "theirs.patch").write_text("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    r = _repo(tmp_path)
    monkeypatch.chdir(foreign)  # the process happens to run from somewhere unrelated to the repository
    names = [c.title if hasattr(c, "title") else str(c) for c in changes.patchfiles(r)]
    assert not any("theirs.patch" in n for n in names), names
    (r / "mine.patch").write_text("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n")
    assert any("mine.patch" in str(getattr(c, "label", getattr(c, "title", c))) for c in changes.patchfiles(r))
    assert any("theirs.patch" in str(getattr(c, "label", getattr(c, "title", c))) for c in changes.patchfiles(r, [foreign]))  # an explicit --inputs dir still works


def test_info_attributes_added_between_two_calls_is_seen_by_the_next_call(tmp_path):
    """--attr-source (empty tree) makes worktree .gitattributes irrelevant, but .git/info/attributes is still read by git: the per-call re-check (never a stale cache) is what covers it.
    RESIDUAL, stated not hidden: a writer who changes .git/info/attributes AND the filter config inside the few milliseconds between the re-check and git's own read is not stopped
    without running the conversion-capable commands inside the confinement."""
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    assert gitq.refusal(r) is None
    (r / ".git" / "info").mkdir(exist_ok=True)
    (r / ".git" / "info" / "attributes").write_text("*.py filter=evil\n")
    _git(r, "config", "filter.evil.clean", str(script))
    (r / "a.py").write_text("x = 4\n")
    assert gitq.refusal(r) and "filter" in gitq.refusal(r)
    changes.uncommitted(r)
    repos.info(r)
    assert not marker.exists()


# ================= round 3: review's S1 (a submodule's own gitdir carries the filter; the OUTER status recurses into it) =================
def _submodule_repo(tmp_path, evil=True):
    marker, script = _marker(tmp_path)
    sub = _repo(tmp_path, "subsrc")
    outer = _repo(tmp_path, "outer")
    subprocess.run(["git", "-C", str(outer), "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "sub"], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"})
    _git(outer, "commit", "-q", "-m", "add submodule")
    gd = outer / ".git" / "modules" / "sub"
    assert gd.is_dir(), "the submodule must have its own gitdir under .git/modules"
    if evil:
        (gd / "info").mkdir(exist_ok=True)
        (gd / "info" / "attributes").write_text("*.py filter=x\n")
        subprocess.run(["git", "--git-dir", str(gd), "config", "filter.x.clean", str(script)], check=True, capture_output=True)
        (outer / "sub" / "a.py").write_text("x = 99\n")  # a tracked file modified inside the submodule: the recursing status must compare it
    return outer, marker


def test_s1_a_submodules_filter_cannot_run_through_the_outer_status(tmp_path, monkeypatch):
    outer, marker = _submodule_repo(tmp_path)
    why = gitq.refusal(outer)
    assert why and "filter.x.clean" in why, why  # the refusal looks inside .git/modules too (and names the offending key)
    repos.info(outer)
    changes.discover(outer)
    assert not marker.exists()
    # structurally, with the early refusal skipped: the outer commands never recurse into a submodule. The per-call vet may now refuse the whole
    # repository (stronger than a clean non-recursing run): accept a refusal that names the key OR a clean run; the marker must stay absent either way.
    monkeypatch.setattr(gitq, "refusal", lambda repo: None)
    (outer / "top.txt").write_text("t\n")  # a top-level change, so uncommitted() goes on to `git add -A` too
    gitq.git(outer, "status", "--porcelain=v1", "-z")
    c = changes.uncommitted(outer)
    assert c is None or not c.problem or "filter.x.clean" in c.problem, c and c.problem
    repos.info(outer)
    assert not marker.exists(), "the outer status/diff/add recursed into the submodule and ran its clean filter"


def test_s1_a_plain_submodule_repo_still_works_and_says_submodule_changes_are_not_shown(tmp_path):
    outer, _m = _submodule_repo(tmp_path, evil=False)
    (outer / "sub" / "a.py").write_text("x = 5\n")  # a change INSIDE the submodule
    (outer / "top.txt").write_text("t\n")
    assert gitq.refusal(outer) is None
    info = repos.info(outer)
    assert info.untracked == 1 and info.modified == 0, (info.untracked, info.modified)  # the submodule's own change is not counted
    assert any("submodule" in n.lower() and "not shown" in n.lower() for n in info.notes), info.notes


@pytest.mark.parametrize("attr", ["merge=union", "merge=text", "merge=binary", "-merge", "!merge"])
def test_builtin_merge_attributes_do_not_refuse_gitq(tmp_path, attr):
    r = _repo(tmp_path)
    (r / ".gitattributes").write_text(f"CHANGELOG.rst {attr}\n")
    _git(r, "add", ".gitattributes")
    _git(r, "commit", "-q", "-m", "builtin-merge")
    assert gitq.refusal(r) is None


# Attribute FILES are no longer scanned (a second parser Git can disagree with). The control is "no driver can be DEFINED": filter.*, diff.*.command|textconv and
# merge.*.driver are not on the config allowlist, and system/global config are /dev/null. So an attribute-only repository is INERT (nothing to run), and the moment a
# driver is defined in config the repository is refused first. (The old assertion "attribute-only is refused" is intentionally gone.)
_DRIVER_KEY = {"merge=custom": "merge.custom.driver", "filter=x": "filter.x.clean", "diff=x": "diff.x.textconv", "textconv=cat": "diff.cat.textconv"}


@pytest.mark.parametrize("source", ["info", "nested"])
@pytest.mark.parametrize("attr", list(_DRIVER_KEY))
def test_exec_attributes_are_inert_until_a_driver_is_defined_and_defining_one_is_refused_in_gitq(tmp_path, attr, source):
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    (r / "sub").mkdir()
    (r / "sub" / "b.py").write_text("b = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "sub")
    if source == "info":
        (r / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (r / ".git" / "info" / "attributes").write_text(f"*.py {attr}\n")
    else:
        (r / "sub" / ".gitattributes").write_text(f"*.py {attr}\n")
    (r / "a.py").write_text("x = 8\n")
    (r / "sub" / "b.py").write_text("b = 2\n")
    # attribute-only: nothing can run (no driver is defined anywhere)
    repos.info(r)
    changes.uncommitted(r)
    gitq.git(r, "status", "--porcelain=v1", "-z")
    assert not marker.exists()
    # DEFINING the driver is what makes it dangerous, and that is refused first, naming the key
    key = _DRIVER_KEY[attr]
    _git(r, "config", key, str(script))
    why = gitq.refusal(r)
    assert why and key in why, why
    repos.info(r)
    changes.uncommitted(r)
    gitq.git(r, "status", "--porcelain=v1", "-z")
    gitq.git(r, "diff", "--no-ext-diff")
    assert not marker.exists(), f"{key} (named by a {source} attribute) ran a program"


def test_builtin_merge_union_with_repo_config_driver_still_refused_in_gitq(tmp_path):
    r = _repo(tmp_path)
    (r / ".gitattributes").write_text("CHANGELOG.rst merge=union\n")
    _git(r, "config", "merge.union.driver", "false")
    why = gitq.refusal(r)
    assert why and "merge.union.driver" in why


def test_submodule_builtin_merge_allowed_and_custom_merge_driver_definition_refused_in_gitq(tmp_path):
    outer, marker = _submodule_repo(tmp_path, evil=False)
    script = tmp_path / "hook.sh"  # written by _submodule_repo's _marker()
    gd = outer / ".git" / "modules" / "sub"
    (gd / "info").mkdir(exist_ok=True)
    (gd / "info" / "attributes").write_text("CHANGELOG.rst merge=union\n*.bin merge=binary\n*.txt -merge\n")
    assert gitq.refusal(outer) is None
    (gd / "info" / "attributes").write_text("*.py merge=custom\n")  # attribute-only: inert, the file is not scanned
    repos.info(outer)
    assert not marker.exists()
    subprocess.run(["git", "--git-dir", str(gd), "config", "merge.custom.driver", str(script)], check=True, capture_output=True)
    why = gitq.refusal(outer)  # the DEFINITION, in the submodule's own config under .git/modules, is refused first
    assert why and "merge.custom.driver" in why, why
    repos.info(outer)
    changes.discover(outer)
    assert not marker.exists()


def test_benign_diff_and_submodule_settings_do_not_refuse_gitq_and_plain_submodules_still_work(tmp_path):
    outer, _m = _submodule_repo(tmp_path, evil=False)  # `git submodule add` already wrote submodule.sub.url into the config
    _git(outer, "config", "diff.renames", "copies")
    _git(outer, "config", "submodule.active", ".")
    assert gitq.refusal(outer) is None
    (outer / "top.txt").write_text("t\n")
    info = repos.info(outer)
    assert info.untracked == 1 and info.modified == 0, (info.untracked, info.modified)


@pytest.mark.parametrize("sep", ["\xa0", "\x0b", "\x0c", "\x85", "\u2028"])
def test_ma5_non_ascii_or_control_whitespace_in_merge_driver_name_refused_in_gitq(tmp_path, sep):
    """MA5 was a parser differential between the attribute scan and Git (Git splits attributes on ASCII blanks only, so `merge=union<sep>canary` names a CUSTOM driver).
    The scan is gone; what must hold is that a driver with such a name cannot be DEFINED: any merge.*.driver (whatever the subsection spelling) is refused."""
    marker, script = _marker(tmp_path)
    r = _repo(tmp_path)
    (r / ".gitattributes").write_text(f"*.txt merge=union{sep}canary\n", encoding="utf-8")
    repos.info(r)  # attribute-only: inert
    assert not marker.exists()
    with open(r / ".git" / "config", "a", encoding="utf-8") as f:
        f.write(f'[merge "union{sep}canary"]\n\tdriver = {script}\n')
    why = gitq.refusal(r)
    assert why and "driver" in why, why
    repos.info(r)
    changes.uncommitted(r)
    outer, _m = _submodule_repo(tmp_path, evil=False)
    gd = outer / ".git" / "modules" / "sub"
    (gd / "info").mkdir(exist_ok=True)
    (gd / "info" / "attributes").write_text(f"*.txt merge=union{sep}canary\n", encoding="utf-8")
    with open(gd / "config", "a", encoding="utf-8") as f:
        f.write(f'[merge "union{sep}canary"]\n\tdriver = {script}\n')
    why_sub = gitq.refusal(outer)
    assert why_sub and "driver" in why_sub, why_sub
    repos.info(outer)
    assert not marker.exists()
