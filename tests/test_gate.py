# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from hlith.gate import head_tree, land, recover, target_identity
from hlith.types import (
    BoundedEvidence, CheckProvenance, GateOutcome, Obligation, ObligationSet, ProposedEffect, Verdict, decide,
)

PROV = CheckProvenance("hypothesis_differential_harness", "ab" * 32, True, False, "cd" * 32, 0)
EV = BoundedEvidence(12, "callers of f, 12 sampled str inputs", "non-str inputs, other modules")


def held(i="o1"):
    return Obligation(i, "m.f", "claim", Verdict.HELD, evidence=EV, provenance=PROV, account_bound=True)


def git(d, *a):
    return subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True, text=True).stdout


@pytest.fixture()
def repo(tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    git(d, "init", "-q", "-b", "main")
    (d / "a.py").write_text("def f(x):\n    return x\n")
    (d / "b.py").write_text("B = 1\n")
    git(d, "add", "-A")
    git(d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base")
    return d


def patch(d):
    return textwrap.dedent("""\
        diff --git a/a.py b/a.py
        --- a/a.py
        +++ b/a.py
        @@ -1,2 +1,2 @@
         def f(x):
        -    return x
        +    return x + 1
        diff --git a/b.py b/b.py
        --- a/b.py
        +++ b/b.py
        @@ -1 +1 @@
        -B = 1
        +B = 2
        diff --git a/c.py b/c.py
        new file mode 100644
        --- /dev/null
        +++ b/c.py
        @@ -0,0 +1 @@
        +C = 3
        """)


def effect(d):
    return ProposedEffect(patch(d), "test")


def test_land_happy_path(repo):
    e = effect(repo)
    dec = land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo), verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.LANDED and dec.landed_commit
    assert (repo / "c.py").read_text() == "C = 3\n"
    assert git(repo, "status", "--porcelain") == ""


def test_gate_ignores_git_dir_environment_override(repo, tmp_path, monkeypatch):
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    git(decoy, "init", "-q", "-b", "main")
    (decoy / "marker.txt").write_text("decoy\n")
    git(decoy, "add", "-A")
    git(decoy, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "decoy")

    expected_tree = head_tree(repo)
    expected_identity = target_identity(repo)
    decoy_head = git(decoy, "rev-parse", "HEAD")
    e = effect(repo)

    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=expected_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=expected_identity,
    )
    monkeypatch.delenv("GIT_DIR")

    assert decision.outcome is GateOutcome.LANDED and decision.landed_commit
    assert (repo / "c.py").read_text() == "C = 3\n"
    assert git(repo, "rev-parse", "HEAD").strip() == decision.landed_commit
    assert git(decoy, "rev-parse", "HEAD") == decoy_head


def test_gate_pins_target_worktree_against_repo_config(repo, tmp_path):
    from hlith import gate
    decoy = tmp_path / "decoy-worktree"
    decoy.mkdir()
    (decoy / "a.py").write_text("def f(x):\n    return x\n")
    (decoy / "b.py").write_text("B = 1\n")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "core.worktree", str(decoy))
    e = effect(repo)

    assert any("core.worktree" in item for item in gate.executable_config(repo))
    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not (repo / "c.py").exists()
    assert not (decoy / "c.py").exists()


def _marker_script(path: Path, marker: Path) -> Path:
    path.write_text(f"#!/bin/sh\nprintf executed > {str(marker)!r}\n")
    path.chmod(0o755)
    return path


def test_target_pre_commit_hook_cannot_execute(repo, tmp_path):
    marker = tmp_path / "hook-ran"
    hook = _marker_script(repo / ".git/hooks/pre-commit", marker)
    assert hook.exists()
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=head_tree(repo),
        verified_patch_sha256=e.patch_sha256,
        expected_identity=target_identity(repo),
    )

    assert decision.outcome is GateOutcome.LANDED
    assert not marker.exists()


def test_target_fsmonitor_cannot_execute(repo, tmp_path):
    marker = tmp_path / "fsmonitor-ran"
    helper = _marker_script(tmp_path / "fsmonitor", marker)
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "core.fsmonitor", str(helper))
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not marker.exists()
    assert not (repo / "c.py").exists()


def test_target_filter_driver_cannot_execute(repo, tmp_path):
    marker = tmp_path / "filter-ran"
    helper = _marker_script(tmp_path / "filter-clean", marker)
    (repo / ".gitattributes").write_text("*.py filter=hostile\n")
    git(repo, "add", ".gitattributes")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "attrs")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "filter.hostile.clean", str(helper))
    git(repo, "config", "filter.hostile.smudge", str(helper))
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not marker.exists()
    assert not (repo / "c.py").exists()


def test_target_include_config_cannot_execute(repo, tmp_path):
    marker = tmp_path / "include-fsmonitor-ran"
    helper = _marker_script(tmp_path / "included-fsmonitor", marker)
    included = tmp_path / "included.conf"
    included.write_text(f"[core]\n\tfsmonitor = {helper}\n")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "include.path", str(included))
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not marker.exists()
    assert not (repo / "c.py").exists()


@pytest.mark.parametrize("include_from_worktree", [False, True])
def test_worktree_config_filter_cannot_execute_before_refusal(repo, tmp_path, include_from_worktree):
    """A clean filter must not run during the preflight status check."""
    marker = tmp_path / "worktree-filter-ran"
    helper = _marker_script(tmp_path / "worktree-filter-clean", marker)
    (repo / ".gitattributes").write_text("b.py filter=x\n")
    git(repo, "add", ".gitattributes")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "attrs")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "extensions.worktreeConfig", "true")
    if include_from_worktree:
        included = tmp_path / "included-worktree.conf"
        included.write_text(f"[filter \"x\"]\n\tclean = {helper}\n")
        git(repo, "config", "--worktree", "include.path", str(included))
    else:
        git(repo, "config", "--worktree", "filter.x.clean", str(helper))
    # Force status to inspect the path whose clean filter is configured.
    b = repo / "b.py"
    stat = b.stat()
    os.utime(b, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not marker.exists()
    assert not (repo / "c.py").exists()


def test_gitfile_target_cannot_redirect_host_writer(repo, tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    git(victim, "init", "-q", "-b", "main")
    (victim / "a.py").write_text("def f(x):\n    return x\n")
    (victim / "b.py").write_text("B = 1\n")
    git(victim, "add", "-A")
    git(victim, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "victim")
    victim_head = git(victim, "rev-parse", "HEAD")

    git_dir = repo / ".git"
    git_dir.rename(tmp_path / "saved-git-dir")
    (repo / ".git").write_text(f"gitdir: {victim / '.git'}\n")
    e = effect(repo)
    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=head_tree(victim),
        verified_patch_sha256=e.patch_sha256,
        expected_identity=target_identity(victim),
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert git(victim, "rev-parse", "HEAD") == victim_head
    assert not (victim / "c.py").exists()
    assert not (repo / "c.py").exists()


def test_target_ident_attribute_is_refused(repo):
    (repo / ".gitattributes").write_text("*.py ident\n")
    git(repo, "add", ".gitattributes")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "ident")
    e = effect(repo)

    decision = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=head_tree(repo),
        verified_patch_sha256=e.patch_sha256,
        expected_identity=target_identity(repo),
    )

    assert decision.outcome is GateOutcome.REFUSED
    assert not (repo / "c.py").exists()


def test_refused_never_writes(repo):
    e = effect(repo)
    bad = Obligation("o2", "m.f", "c", Verdict.NOT_DERIVED, stop_reason="eval at a.py:3")
    before = git(repo, "rev-parse", "HEAD")
    dec = land(repo, e, ObligationSet((held(), bad)), expected_tree=head_tree(repo), verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo))
    assert dec.exit_status == 11 and dec.outcome is GateOutcome.REFUSED
    assert git(repo, "rev-parse", "HEAD") == before and not (repo / "c.py").exists()


@pytest.mark.parametrize("what", ["dirty", "tree", "patch"])
def test_integrity_refusals_exit_4(repo, what):
    e = effect(repo)
    tree, sha = head_tree(repo), e.patch_sha256
    if what == "dirty":
        (repo / "b.py").write_text("B = 99\n")
    if what == "tree":
        tree = "0" * 40
    if what == "patch":
        sha = "0" * 64
    dec = land(repo, e, ObligationSet((held(),)), expected_tree=tree, verified_patch_sha256=sha, expected_identity=target_identity(repo))
    assert dec.exit_status == 4 and not (repo / "c.py").exists()


def test_rollback_on_midway_failure_restores_every_file(repo):
    e = effect(repo)
    with pytest.raises(RuntimeError):
        land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo),
             verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo), fault="raise_after_apply")
    assert git(repo, "status", "--porcelain") == ""
    assert (repo / "a.py").read_text() == "def f(x):\n    return x\n"
    assert not (repo / "c.py").exists()


def test_hard_kill_then_recover(repo):
    """The process dies after the index/worktree were mutated and before commit."""
    e = effect(repo)
    script = textwrap.dedent(f"""
        import sys; sys.path.insert(0, {str(Path(__file__).parents[1] / 'src')!r})
        from pathlib import Path
        from hlith.gate import land, head_tree, target_identity
        from hlith.types import *
        P = CheckProvenance('x', 'a'*64, True, False, 'b'*64, 0)
        E = BoundedEvidence(3, 'e', 'u')
        o = Obligation('o', 's', 'c', Verdict.HELD, evidence=E, provenance=P, account_bound=True)
        d = Path({str(repo)!r})
        eff = ProposedEffect({e.unified_diff!r}, 'k')
        land(d, eff, ObligationSet((o,)), expected_tree=head_tree(d), verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(d), fault='kill_after_apply')
    """)
    cp = subprocess.run([sys.executable, "-c", script])
    assert cp.returncode == 9
    assert git(repo, "status", "--porcelain") != ""  # torn state is real
    assert recover(repo) == "rolled-back"
    assert git(repo, "status", "--porcelain") == ""
    assert not (repo / "c.py").exists()
    assert recover(repo) == "none"  # idempotent


def test_empty_obligation_set_rejected():
    with pytest.raises(ValueError, match="Empty obligation set"):
        ObligationSet(())


def test_held_needs_bounded_evidence_and_blind_confined_check():
    with pytest.raises(ValueError):
        Obligation("o", "s", "c", Verdict.HELD)
    with pytest.raises(ValueError):
        BoundedEvidence(5, "x", "")
    leaky = CheckProvenance("c", "a" * 64, True, True, "b" * 64, 0)
    with pytest.raises(ValueError):
        Obligation("o", "s", "c", Verdict.HELD, evidence=EV, provenance=leaky)


@given(st.lists(st.sampled_from([Verdict.REFUTED, Verdict.NOT_DERIVED, Verdict.UNVERIFIED]), min_size=1, max_size=5))
def test_any_nonheld_refuses(vs):
    obs = [held("h")]
    for i, v in enumerate(vs):
        kw = {"witness": "w"} if v is Verdict.REFUTED else {"stop_reason": "r"}
        obs.append(Obligation(f"n{i}", "s", "c", v, **kw))
    assert decide(ObligationSet(tuple(obs))).outcome is GateOutcome.REFUSED


def _link_patch(path, target):
    return (f"diff --git a/{path} b/{path}\nnew file mode 120000\n--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1 @@\n+{target}\n\\ No newline at end of file\n")


@pytest.mark.parametrize("diff", [
    _link_patch("l", "/etc/passwd"),
    _link_patch("sub/l", "../../outside"),
    "diff --git a/.git/hooks/x b/.git/hooks/x\nnew file mode 100755\n--- /dev/null\n+++ b/.git/hooks/x\n@@ -0,0 +1 @@\n+x\n",
    "diff --git a/.HLITH/f b/.HLITH/f\nnew file mode 100644\n--- /dev/null\n+++ b/.HLITH/f\n@@ -0,0 +1 @@\n+x\n",
])
def test_gate_rechecks_patch_policy(repo, diff):
    e = ProposedEffect(diff, "t")
    dec = land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo),
               verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo))
    assert dec.exit_status == 4 and dec.outcome is GateOutcome.REFUSED and dec.blocking
    assert git(repo, "status", "--porcelain") == ""


def test_gate_allows_inrepo_relative_symlink(repo):
    e = ProposedEffect(_link_patch("l", "a.py"), "t")
    dec = land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo),
               verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.LANDED


def test_landing_is_idempotent_by_content_address(repo):
    e = effect(repo)
    args = dict(expected_tree=head_tree(repo), verified_patch_sha256=e.patch_sha256, expected_identity=target_identity(repo))
    first = land(repo, e, ObligationSet((held(),)), **args)
    n = git(repo, "rev-list", "--count", "HEAD")
    again = land(repo, e, ObligationSet((held(),)), **args)  # retry after a lost reply
    assert again.outcome is GateOutcome.LANDED and again.landed_commit == first.landed_commit
    assert git(repo, "rev-list", "--count", "HEAD") == n
    other = land(repo, e, ObligationSet((held("different-id"),)), **args)  # different verdict set is NOT the same landing
    assert other.exit_status == 4


def test_all_held_but_none_account_bound_refuses():
    """Hlith.md 0.2 gate condition: >= 1 held obligation must consume the effect account."""
    import dataclasses
    unbound = dataclasses.replace(held(), account_bound=False)
    d = decide(ObligationSet((unbound,)))
    assert d.outcome is GateOutcome.REFUSED and d.blocking == ("no-account-bound-obligation",)
    assert decide(ObligationSet((unbound, held("o2")))).outcome is GateOutcome.LANDED


# ---- review S1 (submodule gitdir filter executed by status): the gate must never start a child git inside a submodule / nested repo
def test_hardening_list_stops_submodule_recursion_signatures_and_helper_programs():
    from hlith import gate
    flat = " ".join(gate._HARDEN)
    for needle in ("diff.ignoreSubmodules=all", "status.submoduleSummary=false", "submodule.recurse=false", "log.showSignature=false",
                   "gpg.program=", "gpg.ssh.program=", "gpg.x509.program=", "core.sshCommand=", "credential.helper="):
        assert needle in flat, needle


def test_exec_keys_in_config_text_finds_filters_includes_and_signing_programs(repo):
    from hlith import gate
    for key, snippet in (
        ("filter.x.clean", '[core]\n\tbare = false\n[filter "x"]\n\tclean = /nonexistent/evil.sh\n'),
        ("gpg.program", '[core]\n\tbare = false\n[gpg]\n\tprogram = /nonexistent/gpg-evil\n'),
        ("include.path", '[core]\n\tbare = false\n[include]\n\tpath = ../x\n'),
    ):
        (repo / ".git" / "config").write_text(snippet)
        found = gate.executable_config(repo)
        assert any(key in item for item in found), (key, found)
    (repo / ".git" / "config").write_text("[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n")
    assert gate.executable_config(repo) == []


def test_absorbed_submodule_gitdir_with_a_filter_or_attribute_driver_is_refused(repo, tmp_path):
    from hlith import gate
    marker = tmp_path / "sub-filter-ran"
    helper = _marker_script(tmp_path / "sub-filter", marker)
    (repo / ".git" / "modules" / "sub" / "info").mkdir(parents=True)
    (repo / ".git" / "modules" / "sub" / "config").write_text(f'[filter "x"]\n\tclean = {helper}\n')
    why = gate._submodule_exec_violation(repo)
    assert why is not None and "filter.x.clean" in why, why
    (repo / ".git" / "modules" / "sub" / "config").write_text("[core]\n\tbare = false\n")
    assert gate._submodule_exec_violation(repo) is None  # a harmless submodule gitdir is fine
    # Attribute-only submodule info/attributes is inert without a config driver; defining filter.x.clean in config is refused first.
    (repo / ".git" / "modules" / "sub" / "info" / "attributes").write_text("*.py filter=x\n")
    assert gate._submodule_exec_violation(repo) is None
    (repo / ".git" / "modules" / "sub" / "config").write_text(f'[filter "x"]\n\tclean = {helper}\n')
    why_cfg = gate._submodule_exec_violation(repo)
    assert why_cfg is not None and "filter.x.clean" in why_cfg, why_cfg
    assert not marker.exists()


def test_embedded_nested_git_directory_is_refused_but_an_absorbed_submodule_gitfile_is_not(tmp_path):
    from hlith import gate
    (tmp_path / ".git").mkdir()
    (tmp_path / "emb" / ".git").mkdir(parents=True)
    assert gate._submodule_exec_violation(tmp_path) == "target-has-nested-git-repository:emb"
    other = tmp_path / "other"
    (other / ".git").mkdir(parents=True)
    (other / "sub").mkdir()
    (other / "sub" / ".git").write_text("gitdir: ../.git/modules/sub\n")  # absorbed submodule: a FILE
    assert gate._submodule_exec_violation(other) is None


# ---- recovery journal is NOT trusted from the repo (review source finding; review J1-J7): forged / malformed / unsafe journals must touch NOTHING
def _put_journal(repo, rec):
    j = repo / ".git" / "hlith-journal.json"
    j.write_text(rec if isinstance(rec, str) else json.dumps(rec))
    return j


def _head(repo):
    return git(repo, "rev-parse", "HEAD").strip()


def _images(repo, post_texts):
    """{path: [pre blob (HEAD), post blob of the given text]} like the gate records before applying."""
    out = {}
    for rel, text in post_texts.items():
        pre = git(repo, "rev-parse", f"HEAD:{rel}").strip()
        post = subprocess.run(["git", "-C", str(repo), "hash-object", "--stdin"], input=text, text=True, capture_output=True,
                              check=True).stdout.strip()
        out[rel] = [pre, post]
    return out


def test_forged_journal_with_dot_or_glob_paths_deletes_nothing(repo):  # J1, J2
    (repo / "keep.txt").write_text("operator work\n")
    for paths in (["."], ["*", "sub"]):
        _put_journal(repo, {"base_head": _head(repo), "paths": paths, "patch_sha256": "x"})
        assert recover(repo) == "untrusted"
        assert (repo / "keep.txt").read_text() == "operator work\n"
        (repo / ".git" / "hlith-journal.json").unlink()


def test_forged_journal_cannot_hard_reset_an_uncommitted_tracked_edit(repo):  # J3
    (repo / "a.py").write_text("def f(x):\n    return x * 99  # operator edit\n")
    _put_journal(repo, {"base_head": _head(repo), "paths": [], "patch_sha256": "x"})
    assert recover(repo) == "untrusted"
    assert "operator edit" in (repo / "a.py").read_text()


def test_malformed_or_oversized_journal_is_untrusted_not_a_crash(repo):  # J5
    for bad in ("{not json", "[]", '{"base_head": 5}', '{"base_head": "' + "a" * 40 + '", "paths": "x"}', "x" * 70000):
        _put_journal(repo, bad)
        assert recover(repo) == "untrusted"
        (repo / ".git" / "hlith-journal.json").unlink()


def test_fifo_journal_does_not_hang_and_a_symlinked_journal_is_not_followed(repo, tmp_path):  # J6, J7
    j = repo / ".git" / "hlith-journal.json"
    os.mkfifo(j)
    assert recover(repo) == "untrusted"  # returns at once (lstat says FIFO): no blocking read
    j.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"base_head": _head(repo), "paths": ["a.py"], "patch_sha256": "x", "mac": "0" * 64}))
    (repo / "keep.txt").write_text("operator work\n")
    j.symlink_to(outside)
    try:
        res = recover(repo)
        assert res == "untrusted"
    except RuntimeError as exc:
        assert "symlink" in str(exc) or "hlith-journal" in str(exc)
    assert (repo / "keep.txt").exists() and outside.exists()


def test_journal_with_a_valid_mac_still_refuses_when_the_tree_holds_changes_it_could_not_have_made(repo):
    from hlith import gate
    (repo / "b.py").write_text("B = 12345  # operator edit\n")
    rec = {"base_head": _head(repo), "paths": ["a.py"], "patch_sha256": "x", "nonce": gate._set_nonce(repo),
           "images": _images(repo, {"a.py": "def f(x):\n    return x + 1\n"})}
    rec["mac"] = gate._journal_mac(rec, repo)
    _put_journal(repo, rec)
    assert recover(repo) == "untrusted-state"  # b.py is outside the journal's paths: no reset
    assert "operator edit" in (repo / "b.py").read_text()


def test_replayed_genuine_journal_after_the_landing_ended_cannot_destroy_an_edit(repo):  # review R1 / R1b
    from hlith import gate
    saved = {}
    nonce = gate._set_nonce(repo)
    rec = {"base_head": _head(repo), "paths": ["a.py"], "patch_sha256": "x", "nonce": nonce,
           "images": _images(repo, {"a.py": "def f(x):\n    return x + 1\n"})}
    rec["mac"] = gate._journal_mac(rec, repo)
    j = _put_journal(repo, rec)
    saved["copy"] = j.read_text()
    gate._finish_journal(j, repo)  # the landing ended: journal + host-side token gone (single use)
    (repo / "a.py").write_text("def f(x):\n    return x * 99  # operator edit\n")
    (repo / "keep.txt").write_text("operator work\n")
    j.write_text(saved["copy"])  # attacker replays a COPY of the genuine record
    assert recover(repo) == "untrusted"
    assert "operator edit" in (repo / "a.py").read_text() and (repo / "keep.txt").exists()


def test_a_genuine_inflight_journal_still_recovers_and_the_token_is_single_use(repo):
    from hlith import gate
    rec = {"base_head": _head(repo), "paths": ["a.py"], "patch_sha256": "x", "nonce": gate._set_nonce(repo),
           "images": _images(repo, {"a.py": "def f(x):\n    return x + 1\n"})}
    rec["mac"] = gate._journal_mac(rec, repo)
    j = _put_journal(repo, rec)
    (repo / "a.py").write_text("def f(x):\n    return x + 1\n")  # the half-applied landing's own change, inside the journal's paths
    assert recover(repo) == "rolled-back" and git(repo, "status", "--porcelain") == ""
    j.write_text(json.dumps(rec))
    assert recover(repo) == "untrusted"  # the token was consumed


def test_operator_edit_inside_a_journal_path_after_an_interruption_is_never_destroyed(repo):  # review R5 (exact fix: per-path pre/post images)
    from hlith import gate
    rec = {"base_head": _head(repo), "paths": ["a.py"], "patch_sha256": "x", "nonce": gate._set_nonce(repo),
           "images": _images(repo, {"a.py": "def f(x):\n    return x + 1\n"})}
    rec["mac"] = gate._journal_mac(rec, repo)
    _put_journal(repo, rec)
    (repo / "a.py").write_text("def f(x):\n    return x * 99  # operator edit after the crash\n")  # neither pre- nor post-image
    assert recover(repo) == "untrusted-state"
    assert "operator edit" in (repo / "a.py").read_text()


def test_path_images_are_computed_before_applying_and_match_the_real_result(repo):
    from hlith import gate
    e = effect(repo)
    paths = ["a.py", "b.py", "c.py"]
    imgs = gate._path_images(repo, _head(repo), e.unified_diff, paths)
    assert imgs["c.py"][0] == "" and imgs["a.py"][0] == git(repo, "rev-parse", "HEAD:a.py").strip()
    assert not (repo / "c.py").exists()  # nothing was applied to the real tree or index
    for p in ("a.py", "b.py"):
        assert imgs[p][0] != imgs[p][1] and len(imgs[p][1]) == 40


def test_unwritable_journal_is_a_boundary_refusal_not_a_crash_and_a_preplanted_tmp_cannot_collide(repo, monkeypatch):  # review R4
    from hlith.gate import _legacy as gate_legacy
    e = effect(repo)

    def _boom(path, data):
        raise FileExistsError("pre-planted temp name")

    monkeypatch.setattr(gate_legacy, "_fsync_write", _boom)  # publication fails: a boundary refusal, nothing applied
    d = land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo), verified_patch_sha256=e.patch_sha256,
             expected_identity=target_identity(repo))
    assert d.outcome is GateOutcome.REFUSED and any(b.startswith("journal-write-failed") for b in d.blocking)
    assert not (repo / "c.py").exists()


def test_land_refuses_a_forged_journal_and_touches_nothing(repo):
    e = effect(repo)
    (repo / "keep.txt").write_text("operator work\n")
    _put_journal(repo, {"base_head": _head(repo), "paths": ["keep.txt"], "patch_sha256": "x"})
    d = land(repo, e, ObligationSet((held(),)), expected_tree=head_tree(repo), verified_patch_sha256=e.patch_sha256,
             expected_identity=target_identity(repo))
    assert d.outcome is GateOutcome.REFUSED and "untrusted-journal" in d.blocking
    assert (repo / "keep.txt").read_text() == "operator work\n"


@pytest.mark.parametrize("attr", ["merge=union", "merge=text", "merge=binary", "-merge", "!merge"])
def test_builtin_merge_attributes_do_not_refuse_gate(repo, attr):
    from hlith import gate
    (repo / ".gitattributes").write_text(f"CHANGELOG.rst {attr}\n")
    git(repo, "add", ".gitattributes")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "builtin-merge")
    assert gate._repository_attribute_violation(repo) is None
    e = effect(repo)
    d = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=head_tree(repo),
        verified_patch_sha256=e.patch_sha256,
        expected_identity=target_identity(repo),
    )
    assert d.outcome is GateOutcome.LANDED


@pytest.mark.parametrize("attr,cfg_key", [
    ("merge=custom", "merge.custom.driver"),
    ("filter=x", "filter.x.clean"),
    ("diff=x", "diff.x.command"),
    ("textconv=cat", "diff.x.textconv"),
])
def test_custom_or_exec_attributes_still_refused_in_gate(repo, tmp_path, attr, cfg_key):
    from hlith import gate
    marker = tmp_path / "attr-ran"
    helper = _marker_script(tmp_path / "attr-driver", marker)
    for attr_path, target_file in (
        (repo / ".gitattributes", "a.py"),
        (repo / ".git" / "info" / "attributes", "a.py"),
        (repo / "sub" / ".gitattributes", "sub/a.py"),
    ):
        attr_path.parent.mkdir(parents=True, exist_ok=True)
        attr_path.write_text(f"*.py {attr}\n")
        if attr == "filter=x":
            if attr_path.name == ".gitattributes":
                git(repo, "add", str(attr_path.relative_to(repo)))
            v = gate._attribute_transform_violation(repo, [target_file])
            assert v is not None and "target-filter-attribute" in v, (attr_path, v)
            if attr_path.name == ".gitattributes":
                git(repo, "reset", "-q", "HEAD", "--", str(attr_path.relative_to(repo)))
        attr_path.unlink()
    (repo / ".gitattributes").write_text(f"*.py {attr}\n")
    git(repo, "add", ".gitattributes")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "attr")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", cfg_key, str(helper))
    assert any(cfg_key in item for item in gate.executable_config(repo))
    e = effect(repo)
    d = land(repo, e, ObligationSet((held(),)), expected_tree=exp_tree,
             verified_patch_sha256=e.patch_sha256, expected_identity=exp_id)
    assert d.outcome is GateOutcome.REFUSED and not marker.exists()


def test_builtin_merge_union_with_repo_config_driver_still_refused_in_gate(repo):
    from hlith import gate
    (repo / ".gitattributes").write_text("CHANGELOG.rst merge=union\n")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "merge.union.driver", "false")
    assert any("merge.union.driver" in item for item in gate.executable_config(repo))
    e = effect(repo)
    d = land(
        repo,
        e,
        ObligationSet((held(),)),
        expected_tree=exp_tree,
        verified_patch_sha256=e.patch_sha256,
        expected_identity=exp_id,
    )
    assert d.outcome is GateOutcome.REFUSED
    assert any("target-config-can-execute-programs" in b for b in d.blocking)


def test_submodule_builtin_merge_allowed_and_custom_merge_refused(repo, tmp_path):
    from hlith import gate
    marker = tmp_path / "sub-merge-ran"
    helper = _marker_script(tmp_path / "sub-merge-driver", marker)
    attrs = repo / ".git" / "modules" / "sub" / "info" / "attributes"
    attrs.parent.mkdir(parents=True)
    attrs.write_text("CHANGELOG.rst merge=union\n*.bin merge=binary\n*.txt -merge\n")
    assert gate._submodule_exec_violation(repo) is None
    attrs.write_text("*.py merge=custom\n")
    assert gate._submodule_exec_violation(repo) is None
    (repo / ".git" / "modules" / "sub" / "config").write_text(f'[merge "custom"]\n\tdriver = {helper}\n')
    why = gate._submodule_exec_violation(repo)
    assert why is not None and "merge.custom.driver" in why, why
    assert not marker.exists()


@pytest.mark.parametrize("sep", ["\xa0", "\x0b", "\x0c", "\x85", "\u2028"])
def test_ma5_non_ascii_or_control_whitespace_in_merge_driver_refused_in_gate(repo, tmp_path, sep):
    from hlith import gate
    marker = tmp_path / "ma5-ran"
    helper = _marker_script(tmp_path / "ma5-driver", marker)
    (repo / ".gitattributes").write_text(f"*.txt merge=union{sep}canary\n", encoding="utf-8")
    attrs = repo / ".git" / "modules" / "sub" / "info" / "attributes"
    attrs.parent.mkdir(parents=True)
    attrs.write_text(f"*.txt merge=union{sep}canary\n", encoding="utf-8")
    exp_tree, exp_id = head_tree(repo), target_identity(repo)
    git(repo, "config", "merge.union.driver", str(helper))
    assert any("merge.union.driver" in item for item in gate.executable_config(repo))
    e = effect(repo)
    d = land(repo, e, ObligationSet((held(),)), expected_tree=exp_tree,
             verified_patch_sha256=e.patch_sha256, expected_identity=exp_id)
    assert d.outcome is GateOutcome.REFUSED
    (repo / ".git" / "modules" / "sub" / "config").write_text(f'[merge "union"]\n\tdriver = {helper}\n')
    why_sub = gate._submodule_exec_violation(repo)
    assert why_sub is not None and "merge.union.driver" in why_sub, why_sub
    assert not marker.exists()
