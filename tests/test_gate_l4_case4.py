# SPDX-License-Identifier: Apache-2.0
"""review (case, L4 gate owner): behaviours of the PIPELINE gate (`hlith.gate.api.LocalGateService`, the gate `hlith run`/`ui`/`check`
land through), measured directly. Most older G2 tests and the G2 attack evidence drive the LEGACY `hlith.gate.land()`; these cases
re-measure the same hostile classes against the real stack: real ObligationEngine -> real signed record -> real LocalGateService.
The only stand-in is what the derivation core returned (as in tests/test_gate_empty_derived_set.py). Fault injection is stated per case."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.errors import EXIT_BOUNDARY, EXIT_LANDED
from hlith.contract.feedback import FeedbackInput
from hlith.contract.identities import new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.effect.api import EffectService
from hlith.gate import api as gate_api
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.api import ObligationEngine


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _held_core(**kw):
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obs = tuple(Obligation(f"{kind}:m.f", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True)
                for kind in ("signature_binding", "differential"))
    return SimpleNamespace(obligations=obs, evidence=())


class Env:
    def __init__(self, tmp_path: Path, monkeypatch, base_files: dict[str, str], edits: dict[str, str]):
        monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
        self.repo = repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "t@t")
        _git(repo, "config", "user.name", "t")
        for rel, body in base_files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(body)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "init")
        for rel, body in edits.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(body)
        _git(repo, "add", "-A")
        self.patch = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--no-color"], capture_output=True, check=True).stdout
        _git(repo, "reset", "-q", "--hard", "HEAD")
        _git(repo, "clean", "-fdq")
        self.host = LocalHostState(tmp_path / "state")
        git_read = HardenedGitRead()
        snaps = LocalSnapshotService(git_read)
        self.verifier = LocalVerificationService(self.host)
        self.gate = LocalGateService(self.host, git_read=git_read, snapshot_service=snaps)
        base = snaps.seal_base(repo)
        post = snaps.reconstruct_post(base, self.patch)
        account = EffectService().build_account(new_run_id(), base, post, self.patch)
        engine = ObligationEngine(self.verifier)
        engine._derive = SimpleNamespace(core=_held_core)
        self.ident = capture_target_identity(repo)
        self.ve = engine.verify(account, FeedbackInput(), base, post, self.ident)

    def land(self):
        return self.gate.land(self.repo, self.patch, self.ve, self.verifier, self.ident)

    def head(self) -> str:
        return _git(self.repo, "rev-parse", "HEAD")


BASE = {"m.py": "def f(x):\n    return x\n", "other.py": "O = 1\n"}
EDIT = {"m.py": "def f(x):\n    return x + 1\n"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch, BASE, EDIT)


# ---- G1/G2 baseline on the pipeline gate -------------------------------------------------------------------------------------
def test_land_makes_exactly_one_commit_whose_tree_is_the_independent_apply(env):
    before = env.head()
    r = env.land()
    assert r.outcome == "landed" and r.exit_status == EXIT_LANDED, r
    assert _git(env.repo, "rev-list", "--count", f"{before}..HEAD") == "1"
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == str(env.ve.record.post_tree_oid)
    assert _git(env.repo, "status", "--porcelain") == ""
    assert (env.repo / "m.py").read_text() == EDIT["m.py"]


def test_replay_of_the_same_record_after_landing_reports_the_existing_landing(env):
    """A lost-reply retry of a landing that already happened must report LANDED with the same commit and create no second commit
    (Gate durability: validate the recorded transaction and resulting tree). Measured before the fix: refused exit 4 base-tree-mismatch,
    i.e. a change already in the repository was reported as refused."""
    first = env.land()
    n = _git(env.repo, "rev-list", "--count", "HEAD")
    again = env.land()
    assert _git(env.repo, "rev-list", "--count", "HEAD") == n, "a replay created another commit"
    assert again.outcome == "landed" and again.exit_status == EXIT_LANDED and again.landed_commit == first.landed_commit, again


def test_replay_after_the_operator_added_a_commit_on_top_is_not_reported_as_landed(env):
    first = env.land()
    (env.repo / "other.py").write_text("O = 2\n")
    _git(env.repo, "commit", "-qam", "operator commit on top")
    again = env.land()
    assert again.outcome == "refused" and again.landed_commit is None, again


def test_a_forged_key_trailer_on_an_unrelated_head_is_not_a_landing(env):
    from hlith.gate.api import landing_key_v2

    key = landing_key_v2(base_tree_oid=str(env.ve.record.base_tree_oid), patch_sha256=str(env.ve.record.patch_sha256),
                         post_tree_oid=str(env.ve.record.post_tree_oid), account_sha256=str(env.ve.record.account_sha256),
                         record_body_sha256=str(env.ve.record.body_sha256))
    (env.repo / "other.py").write_text("O = 2\n")
    _git(env.repo, "commit", "-qam", f"operator commit\n\nHlith-Key: {key}")
    head = env.head()
    r = env.land()
    assert r.outcome == "refused" and env.head() == head and (env.repo / "m.py").read_text() == BASE["m.py"], r


def test_a_changed_patch_is_refused_and_nothing_is_written(env):
    head = env.head()
    forged = env.patch.replace(b"x + 1", b"x + 2")
    r = env.gate.land(env.repo, forged, env.ve, env.verifier, env.ident)
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY
    assert env.head() == head and _git(env.repo, "status", "--porcelain") == ""


def test_operator_edit_on_a_patched_path_refuses_and_survives(env):
    (env.repo / "m.py").write_text("def f(x):\n    return x * 99  # operator\n")
    head = env.head()
    r = env.land()
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, r
    assert env.head() == head and "operator" in (env.repo / "m.py").read_text()


def test_head_moved_after_verification_refuses_and_keeps_the_operator_commit(env):
    (env.repo / "other.py").write_text("O = 2\n")
    _git(env.repo, "commit", "-qam", "operator commit after verify")
    op = env.head()
    r = env.land()
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, r
    assert env.head() == op and (env.repo / "m.py").read_text() == BASE["m.py"]


# ---- hostile repository metadata: the host writer must refuse before executing anything ----------------------------------------
def test_a_clean_filter_driver_in_repo_config_is_never_executed(env, tmp_path):
    marker = tmp_path / "MARKER"
    _git(env.repo, "config", "filter.x.clean", f"touch {marker}; cat")
    (env.repo / ".gitattributes").write_text("m.py filter=x\n")
    r = env.land()
    assert not marker.exists(), "the filter driver executed in the trusted host writer"
    assert r.outcome == "refused", r


def test_a_pre_commit_hook_never_executes(env, tmp_path):
    marker = tmp_path / "HOOKMARK"
    hook = env.repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    r = env.land()
    assert not marker.exists(), "a hook executed in the trusted host writer"
    assert r.outcome in {"landed", "refused"}


def _script(path: Path, marker: Path) -> Path:
    path.write_text(f"#!/bin/sh\nprintf executed > {str(marker)!r}\n")
    path.chmod(0o755)
    return path


def test_git_dir_environment_override_is_ignored(env, tmp_path, monkeypatch):
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    _git(decoy, "init", "-q")
    _git(decoy, "config", "user.email", "t@t")
    _git(decoy, "config", "user.name", "t")
    (decoy / "marker.txt").write_text("decoy\n")
    _git(decoy, "add", "-A")
    _git(decoy, "commit", "-qm", "decoy")
    decoy_head = _git(decoy, "rev-parse", "HEAD")
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    r = env.land()
    monkeypatch.delenv("GIT_DIR")
    assert r.outcome == "landed", r
    assert _git(decoy, "rev-parse", "HEAD") == decoy_head
    assert (env.repo / "m.py").read_text() == EDIT["m.py"]


def test_core_worktree_in_repo_config_cannot_redirect_the_write(env, tmp_path):
    decoy = tmp_path / "decoy-worktree"
    decoy.mkdir()
    (decoy / "m.py").write_text(BASE["m.py"])
    (decoy / "other.py").write_text(BASE["other.py"])
    _git(env.repo, "config", "core.worktree", str(decoy))
    r = env.land()
    assert (decoy / "m.py").read_text() == BASE["m.py"], "the patch was written into the decoy worktree"
    assert r.outcome == "refused" and r.landed_commit is None, r
    assert (env.repo / "m.py").read_text() == BASE["m.py"]


def test_include_path_config_with_fsmonitor_never_executes(env, tmp_path):
    marker = tmp_path / "include-fsmonitor-ran"
    helper = _script(tmp_path / "included-fsmonitor", marker)
    included = tmp_path / "included.conf"
    included.write_text(f"[core]\n\tfsmonitor = {helper}\n")
    _git(env.repo, "config", "include.path", str(included))
    r = env.land()
    assert not marker.exists(), "an included fsmonitor executed in the host writer"
    assert r.outcome == "refused" and (env.repo / "m.py").read_text() == BASE["m.py"], r


@pytest.mark.parametrize("include_from_worktree", [False, True])
def test_worktree_config_clean_filter_never_executes(env, tmp_path, include_from_worktree):
    marker = tmp_path / "worktree-filter-ran"
    helper = _script(tmp_path / "worktree-filter-clean", marker)
    (env.repo / ".gitattributes").write_text("other.py filter=x\n")
    _git(env.repo, "add", ".gitattributes")
    _git(env.repo, "commit", "-qm", "attrs")
    _git(env.repo, "config", "extensions.worktreeConfig", "true")
    if include_from_worktree:
        included = tmp_path / "included-worktree.conf"
        included.write_text(f'[filter "x"]\n\tclean = {helper}\n')
        _git(env.repo, "config", "--worktree", "include.path", str(included))
    else:
        _git(env.repo, "config", "--worktree", "filter.x.clean", str(helper))
    b = env.repo / "other.py"
    st = b.stat()
    os.utime(b, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    r = env.land()
    assert not marker.exists(), "a worktree-config clean filter executed in the host writer"
    assert r.outcome == "refused", r


def test_gitfile_target_cannot_redirect_the_host_writer(env, tmp_path):
    victim = tmp_path / "victim"
    subprocess.run(["git", "clone", "-q", str(env.repo), str(victim)], check=True, capture_output=True)
    victim_head = _git(victim, "rev-parse", "HEAD")
    (env.repo / ".git").rename(tmp_path / "saved-git-dir")
    (env.repo / ".git").write_text(f"gitdir: {victim / '.git'}\n")
    r = env.gate.land(env.repo, env.patch, env.ve, env.verifier, env.ident)
    assert r.outcome == "refused", r
    assert _git(victim, "rev-parse", "HEAD") == victim_head
    assert (victim / "m.py").read_text() == BASE["m.py"]


@pytest.mark.parametrize("attr", ["ident", "filter=x", "diff=x", "merge=x", "textconv=x"])
def test_executable_or_rewriting_attributes_are_refused(env, attr):
    (env.repo / ".gitattributes").write_text(f"*.py {attr}\n")
    _git(env.repo, "add", ".gitattributes")
    _git(env.repo, "commit", "-qm", "attrs")
    r = env.land()
    assert r.outcome == "refused", (attr, r)
    assert (env.repo / "m.py").read_text() == BASE["m.py"]


def test_a_gitlink_patch_that_is_not_the_verified_patch_is_refused(env):
    """Refused by the record/patch binding (the digest differs), not by the patch policy: a policy-violating patch cannot get a
    valid record from the earlier layers, so the gate's policy check is defence in depth that this stack cannot reach."""
    bad = env.patch + (b"diff --git a/sub b/sub\nnew file mode 160000\nindex 0000000..1234567\n--- /dev/null\n+++ b/sub\n"
                       b"@@ -0,0 +1 @@\n+Subproject commit 1234567890123456789012345678901234567890\n")
    r = env.gate.land(env.repo, bad, env.ve, env.verifier, env.ident)
    assert r.outcome == "refused" and (env.repo / "m.py").read_text() == BASE["m.py"], r


def test_a_symlink_escape_patch_that_is_not_the_verified_patch_is_refused(env):
    """Same note: refused by the record/patch binding."""
    bad = (b"diff --git a/esc b/esc\nnew file mode 120000\n--- /dev/null\n+++ b/esc\n@@ -0,0 +1 @@\n+/etc/passwd\n"
           b"\\ No newline at end of file\n")
    r = env.gate.land(env.repo, bad, env.ve, env.verifier, env.ident)
    assert r.outcome == "refused" and not (env.repo / "esc").exists(), r


# ---- recovery on the pipeline gate ---------------------------------------------------------------------------------------------
def test_crash_after_apply_before_commit_is_recovered_to_the_base(env, monkeypatch):
    """Fault injection: the process dies (BaseException, not caught by the gate) between `apply --index` and `commit`."""
    head = env.head()

    def boom(*a, **k):
        raise KeyboardInterrupt("simulated crash before commit")

    monkeypatch.setattr(gate_api, "commit_tree_cas", boom)
    with pytest.raises(KeyboardInterrupt):
        env.land()
    assert _git(env.repo, "status", "--porcelain") != "", "the crash left the tree changed (as expected)"
    status = env.gate.recover(env.repo)
    assert status.startswith("recovered"), status
    assert env.head() == head and _git(env.repo, "status", "--porcelain") == ""
    assert (env.repo / "m.py").read_text() == BASE["m.py"]
    assert env.gate.recover(env.repo) == "clean"


def test_recovery_never_destroys_an_operator_edit_made_after_the_crash(env, monkeypatch):
    def boom(*a, **k):
        raise KeyboardInterrupt("simulated crash")

    monkeypatch.setattr(gate_api, "commit_tree_cas", boom)
    with pytest.raises(KeyboardInterrupt):
        env.land()
    (env.repo / "m.py").write_text("def f(x):\n    return x * 99  # operator edit after the crash\n")
    with pytest.raises(Exception):
        env.gate.recover(env.repo)
    assert "operator edit" in (env.repo / "m.py").read_text()


def test_a_forged_journal_with_glob_or_dot_paths_deletes_nothing(env):
    (env.repo / "keep.txt").write_text("operator work\n")
    j_dir = env.host.namespace(env.host.stable_repo_identity(env.repo), "journal")
    from hlith.gate.journal import _target_git_dir, _target_journal_key

    key = _target_journal_key(_target_git_dir(env.repo))
    for paths in (["."], ["*", "sub"]):
        (j_dir / f"landing-{key}.json").write_text(
            '{"format": 2, "base_head": "%s", "paths": %s, "patch_sha256": "x", "nonce": "00", "images": {}, "mac": "bad"}'
            % (env.head(), str(paths).replace("'", '"')))
        with pytest.raises(Exception):
            env.gate.recover(env.repo)
        assert (env.repo / "keep.txt").read_text() == "operator work\n"
        (j_dir / f"landing-{key}.json").unlink()


def test_a_journal_missing_patch_sha256_is_a_named_integrity_refusal_not_a_key_error(env):
    """review 2795f97c JOURNAL-1c: a host-state journal JSON without `patch_sha256` made `_journal_mac` raise a raw KeyError out of
    recover() (an unnamed crash instead of the gate's integrity refusal). It must be a HostIntegrityError and touch nothing."""
    from hlith.gate.journal import _target_git_dir, _target_journal_key
    from hlith.hostio.integrity import HostIntegrityError

    (env.repo / "keep.txt").write_text("operator work\n")
    j_dir = env.host.namespace(env.host.stable_repo_identity(env.repo), "journal")
    key = _target_journal_key(_target_git_dir(env.repo))
    for bad in ("", '"patch_sha256": null, ', '"patch_sha256": 7, '):  # absent, null, wrong type
        (j_dir / f"landing-{key}.json").write_text(
            '{"format": 2, "base_head": "%s", "paths": ["m.py"], %s"nonce": "%s", "images": {}, "mac": "bad"}' % (env.head(), bad, "0" * 32))
        with pytest.raises(HostIntegrityError, match="patch_sha256"):
            env.gate.recover(env.repo)
        assert (env.repo / "keep.txt").read_text() == "operator work\n"
        (j_dir / f"landing-{key}.json").unlink()


def test_an_empty_patch_is_refused_before_anything_is_written_so_land_and_recover_agree(env):
    """review G2-EMPTY-PATCH-LAND-AND-RECOVER (71c64805): land(b"") made an --allow-empty commit after writing a paths=[] journal, a journal
    recover() then calls untrusted. One rule now: an empty change (no paths, post tree == base tree) is never landed, so no such journal
    or commit is ever written; recover() keeps refusing a paths=[] journal. The honest pipeline never reaches here (the effect service
    refuses an empty patch, the obligation engine then derives nothing); this models a compromised controller holding the issue key, as
    the other validly-signed-record tests do: the gate is the sole writer and must hold the rule by itself."""
    import hashlib

    from hlith.contract.identities import sha256_hex

    head = env.head()
    forged = env.verifier.issue(dataclasses.replace(env.ve.record, patch_sha256=sha256_hex(hashlib.sha256(b"").hexdigest()),
                                                    post_tree_oid=env.ve.record.base_tree_oid, mac=""))
    rc = _land_with(env, forged, patch=b"")
    assert rc.outcome != "landed" and rc.landed_commit is None, rc
    assert "empty-change" in rc.blocking, rc
    assert env.head() == head
    j_dir = env.host.namespace(env.host.stable_repo_identity(env.repo), "journal")
    assert not list(j_dir.glob("landing-*.json")), "a journal was written for an empty change"
    assert env.gate.recover(env.repo) == "clean"


def test_recover_still_treats_an_authentic_empty_paths_journal_after_an_empty_commit_as_untrusted(env):
    """The other side of the same rule: recover() never adopts an empty commit as a completed landing (the old land could leave
    exactly this state); it reports untrusted and touches nothing."""
    from hlith.gate.git_write import head_commit
    from hlith.gate.journal import begin_journal

    base = head_commit(env.repo)
    begin_journal(env.repo, env.host, env.host.stable_repo_identity(env.repo), base_head=base, paths=[], patch_sha256="0" * 64, images={})
    _git(env.repo, "commit", "-q", "--allow-empty", "-m", "empty")
    moved = env.head()
    assert env.gate.recover(env.repo) == "untrusted"
    assert env.head() == moved and _git(env.repo, "status", "--porcelain") == ""


# ---- glob/magic characters in a landed path must be treated literally by every gate git call ----------------------------------
def test_rollback_of_a_glob_named_path_restores_only_that_path(tmp_path, monkeypatch):
    """A repository may legally contain a file literally named `*.txt`. Recovering an interrupted landing that touched it must
    not restore or reset any OTHER file the glob matches (an operator's unrelated edit would be silently overwritten).
    The landing is interrupted by hand here (authentic journal + real `apply --index`), because a data-file patch needs obligations
    this stand-in does not derive; the recovery under test is the real `LocalGateService.recover`."""
    from hlith.gate.git_write import apply_index_and_verify_tree, compute_path_images, head_commit, patch_paths
    from hlith.gate.journal import begin_journal

    env = Env(tmp_path, monkeypatch, {**BASE, "*.txt": "S = 1\n", "note.txt": "N = 1\n"}, {"*.txt": "S = 2\n"})
    head = env.head()
    paths = patch_paths(env.repo, env.patch)
    assert paths == ["*.txt"], paths
    images = compute_path_images(env.repo, head, env.patch, paths)
    begin_journal(env.repo, env.host, env.host.stable_repo_identity(env.repo), base_head=head_commit(env.repo), paths=paths,
                  patch_sha256="x" * 64, images=images)
    assert apply_index_and_verify_tree(env.repo, env.patch, env.ve.record.post_tree_oid) in (True, False)  # the half-done state
    (env.repo / "note.txt").write_text("operator edit made after the crash\n")  # an unrelated file the glob also matches
    env.gate.recover(env.repo)
    assert (env.repo / "note.txt").read_text() == "operator edit made after the crash\n", "recovery overwrote a sibling the glob matched"
    assert (env.repo / "*.txt").read_text() == "S = 1\n"
    assert env.head() == head


# ---- durability: a journal rename must be made durable by syncing its directory (gate durability) -----------------------------------
def test_journal_writes_sync_the_containing_directory(env, monkeypatch):
    import stat

    from hlith.gate.git_write import compute_path_images, head_commit, patch_paths
    from hlith.gate.journal import begin_journal, clear_journal

    dir_syncs = []
    real_fsync = os.fsync

    def spy(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            dir_syncs.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    paths = patch_paths(env.repo, env.patch)
    images = compute_path_images(env.repo, env.head(), env.patch, paths)
    j, n = begin_journal(env.repo, env.host, env.host.stable_repo_identity(env.repo), base_head=head_commit(env.repo), paths=paths,
                         patch_sha256="x" * 64, images=images)
    assert dir_syncs, "begin_journal renamed journal files into place without syncing the directory"
    clear_journal(j, n)


# ---- record forgery: the gate must refuse any record the verifier did not issue, and must not trust even a validly signed record's claims ----
import dataclasses  # noqa: E402

from hlith.contract.identities import Sha256, TreeOid  # noqa: E402
from hlith.contract.obligations import AccountConsumption  # noqa: E402


def _land_with(env, record=None, verifier=None, patch=None):
    from hlith.contract.capabilities import VerifiedEffect

    ve = dataclasses.replace(env.ve, record=record) if record is not None else env.ve
    return env.gate.land(env.repo, patch if patch is not None else env.patch, ve, verifier or env.verifier, env.ident)


def _untouched(env, head):
    return env.head() == head and _git(env.repo, "status", "--porcelain") == "" and (env.repo / "m.py").read_text() == BASE["m.py"]


@pytest.mark.parametrize("field,value", [
    ("base_tree_oid", TreeOid("1" * 40)),
    ("post_tree_oid", TreeOid("2" * 40)),
    ("patch_sha256", Sha256("3" * 64)),
    ("account_sha256", Sha256("4" * 64)),
    ("required_scope_digest", Sha256("5" * 64)),
    ("scope_discharge_digest", Sha256("6" * 64)),
    ("obligation_set_sha256", Sha256("7" * 64)),
    ("context_identity_sha256", Sha256("8" * 64)),
    ("checker_ids", ("forged-checker",)),
    ("issuer", "someone-else"),
])
def test_a_record_with_one_edited_field_and_the_old_mac_is_refused(env, field, value):
    head = env.head()
    forged = dataclasses.replace(env.ve.record, **{field: value})
    r = _land_with(env, forged)
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, (field, r)
    assert _untouched(env, head)


def test_a_record_without_a_mac_is_refused(env):
    head = env.head()
    r = _land_with(env, dataclasses.replace(env.ve.record, mac=""))
    assert r.outcome == "refused" and _untouched(env, head), r


def test_a_record_signed_with_another_hosts_key_is_refused(env, tmp_path):
    other = LocalVerificationService(LocalHostState(tmp_path / "other-state"))
    head = env.head()
    forged = other.issue(dataclasses.replace(env.ve.record, mac=""))
    r = _land_with(env, forged)
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY and _untouched(env, head), r


@pytest.mark.parametrize("field,value,why", [
    ("post_tree_oid", TreeOid("2" * 40), "a validly signed record claiming a post tree the patch does not produce"),
    ("base_tree_oid", TreeOid("1" * 40), "a validly signed record claiming another base tree"),
])
def test_a_validly_signed_record_with_false_tree_claims_is_still_refused(env, field, value, why):
    """Models a compromised controller: the MAC is valid, so only the gate's own independent reconstruction can refuse."""
    head = env.head()
    forged = env.verifier.issue(dataclasses.replace(env.ve.record, **{field: value}, mac=""))
    r = _land_with(env, forged)
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, (why, r)
    assert _untouched(env, head)


def test_a_validly_signed_record_whose_consumption_names_no_held_obligation_is_refused(env):
    head = env.head()
    bad = (AccountConsumption("not-an-obligation", env.ve.record.account_sha256),)
    forged = env.verifier.issue(dataclasses.replace(env.ve.record, consumption=bad, mac=""))
    r = _land_with(env, forged)
    assert r.outcome == "refused" and _untouched(env, head), r


def test_a_validly_signed_record_with_no_consumption_is_refused(env):
    head = env.head()
    forged = env.verifier.issue(dataclasses.replace(env.ve.record, consumption=(), mac=""))
    r = _land_with(env, forged)
    assert r.outcome == "refused" and _untouched(env, head), r


def test_swapping_in_a_different_obligation_set_than_the_one_signed_is_refused(env):
    from hlith.contract.capabilities import VerifiedEffect
    from hlith.contract.legacy import ObligationSet

    head = env.head()
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    swapped = ObligationSet((Obligation("signature_binding:m.f", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True),))
    ve = dataclasses.replace(env.ve, obligations=swapped)
    r = env.gate.land(env.repo, env.patch, ve, env.verifier, env.ident)
    assert r.outcome == "refused" and _untouched(env, head), r


# ---- real process death and restart ----------------------------------------------------------------------------------------------
def test_relanding_after_a_crash_and_recovery_lands_exactly_one_commit(env, monkeypatch):
    head = env.head()

    def boom(*a, **k):
        raise KeyboardInterrupt("simulated crash before commit")

    with monkeypatch.context() as m:
        m.setattr(gate_api, "commit_tree_cas", boom)
        with pytest.raises(KeyboardInterrupt):
            env.land()
    r0 = env.land()  # before recovery: the unrecovered journal must stop a second writer
    assert r0.outcome == "refused" and r0.exit_status == EXIT_BOUNDARY and set(r0.blocking) & {"unrecovered-journal-exists", "target-dirty"}, r0
    assert env.gate.recover(env.repo).startswith("recovered")
    r = env.land()
    assert r.outcome == "landed", r
    assert _git(env.repo, "rev-list", "--count", f"{head}..HEAD") == "1"


def test_sigkill_of_the_landing_process_mid_landing_is_recovered(tmp_path):
    """A real kernel SIGKILL (no Python cleanup, locks released by the OS) between `apply --index` and `commit`, in a child process;
    the parent then recovers from the on-disk journal with a fresh gate instance."""
    import signal
    import sys
    import textwrap

    base = tmp_path / "w"
    base.mkdir()
    child = textwrap.dedent(f"""
        import os, sys
        from pathlib import Path
        sys.path[:0] = [{str(Path(__file__).parent)!r}]
        import test_gate_l4_case4 as t
        class MP:
            def setenv(self, k, v): os.environ[k] = v
        env = t.Env(Path({str(base)!r}), MP(), t.BASE, t.EDIT)
        t.gate_api.commit_tree_cas = lambda *a, **k: os.kill(os.getpid(), 9)
        env.land()
        sys.exit(0)
    """)
    cp = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True, env={**os.environ, "HLITH_STATE_DIR": str(base / "state")})
    assert cp.returncode == -signal.SIGKILL, (cp.returncode, cp.stderr[-400:])
    repo = base / "repo"
    assert _git(repo, "status", "--porcelain") != "", "the kill happened after the patch was staged"
    host = LocalHostState(base / "state")
    gate = LocalGateService(host)
    base_head = _git(repo, "rev-parse", "HEAD")
    status = gate.recover(repo)
    assert status.startswith("recovered"), status
    assert _git(repo, "rev-parse", "HEAD") == base_head and _git(repo, "status", "--porcelain") == ""
    assert (repo / "m.py").read_text() == BASE["m.py"]
    assert gate.recover(repo) == "clean"


def test_a_group_readable_state_dir_is_refused_with_the_fix_in_the_message(tmp_path):
    from hlith.hostio.integrity import HostIntegrityError, ensure_private_dir

    d = tmp_path / "state"
    d.mkdir()
    os.chmod(d, 0o755)
    with pytest.raises(HostIntegrityError) as ei:
        ensure_private_dir(d)
    msg = str(ei.value)
    assert "0700" in msg and f"chmod 700 {d}" in msg, msg


# ---- E2 host safety: confined processes must carry a memory bound (vm.overcommit_memory=1 hosts never refuse an allocation) ---------
def _confined(argv, extra_spec=None, timeout=60):
    import json
    import sys
    import tempfile

    from hlith.hostio.confinement import _LAUNCHER, Profile

    with tempfile.TemporaryDirectory(prefix="hlith-run-", dir=os.environ.get("TMPDIR")) as own:
        spec = {**Profile().spec(), "root_parent": own, **(extra_spec or {})}
        return subprocess.run([sys.executable, "-I", _LAUNCHER, json.dumps(spec), "--", *argv], capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})


_AS = "import resource;print(resource.getrlimit(resource.RLIMIT_AS))"


def test_a_confined_process_carries_a_finite_address_space_limit_by_default():
    cp = _confined(["/usr/bin/python3", "-c", _AS])
    soft, hard = eval(cp.stdout.strip())
    assert cp.returncode == 0 and 0 < soft <= 16 * 1024**3 and hard == soft, (cp.stdout, cp.stderr[-300:])


def test_the_launcher_honours_an_explicit_limit_and_an_explicit_unlimited():
    cp = _confined(["/usr/bin/python3", "-c", _AS], {"as_limit_bytes": 3 * 1024**3})
    assert eval(cp.stdout.strip()) == (3 * 1024**3, 3 * 1024**3), (cp.stdout, cp.stderr[-300:])
    cp = _confined(["/usr/bin/python3", "-c", _AS], {"as_limit_bytes": 0})
    assert eval(cp.stdout.strip())[0] == -1, cp.stdout


def test_a_confined_runaway_allocation_ends_in_memory_error_not_host_ram():
    """review's falsifier: target code doing len('x' * 10**12). Run only AFTER the limit exists (without it this fills host RAM)."""
    import time

    t0 = time.monotonic()
    cp = _confined(["/usr/bin/python3", "-c", "try:\n    print(len('x' * 10**12))\nexcept MemoryError:\n    print('MemoryError')"], timeout=60)
    assert cp.stdout.strip() == "MemoryError", (cp.returncode, cp.stdout[-200:], cp.stderr[-300:])
    assert time.monotonic() - t0 < 30


# ---- a SIGKILL during `git apply --index` leaves a stale .git/index.lock; recovery must still work, and must not steal a live one ----
def _crash_after_apply(env, monkeypatch):
    def boom(*a, **k):
        raise KeyboardInterrupt("simulated crash before commit")

    with monkeypatch.context() as m:
        m.setattr(gate_api, "commit_tree_cas", boom)
        with pytest.raises(KeyboardInterrupt):
            env.land()


def test_recovery_clears_a_stale_empty_index_lock_left_by_a_killed_landing(env, monkeypatch):
    """Measured on the real engine: SIGKILL while `git apply --index` held the lock left an empty .git/index.lock, and the next run's
    recovery failed with 'path-limited git reset failed' (the operator saw a misleading 'journal cannot be verified' message)."""
    head = env.head()
    _crash_after_apply(env, monkeypatch)
    lock = env.repo / ".git" / "index.lock"
    lock.write_text("")
    status = env.gate.recover(env.repo)
    assert status.startswith("recovered"), status
    assert not lock.exists()
    assert env.head() == head and _git(env.repo, "status", "--porcelain") == ""
    assert env.gate.recover(env.repo) == "clean"


def test_recovery_refuses_to_remove_an_index_lock_a_live_process_holds_open(env, monkeypatch):
    head = env.head()
    _crash_after_apply(env, monkeypatch)
    lock = env.repo / ".git" / "index.lock"
    with open(lock, "w"):  # a live git-like holder: the file is open in this very process (any process counts)
        holder = subprocess.Popen(["/bin/sh", "-c", f"exec 9<>{lock}; sleep 30"])
        try:
            import time

            time.sleep(0.3)
            with pytest.raises(Exception) as ei:
                env.gate.recover(env.repo)
            assert "index.lock" in str(ei.value), str(ei.value)
            assert lock.exists()
        finally:
            holder.kill()
            holder.wait()
    assert env.head() == head


# ---- resource limits of the landing journal: a landing the gate starts must be one it can recover --------------------------------
def _many_files(n, name=lambda i: f"d/f{i:05d}.txt"):
    return {name(i): f"v{i} = 1\n" for i in range(n)}, {name(i): f"v{i} = 2\n" for i in range(n)}


def test_a_crash_while_landing_hundreds_of_files_is_recoverable(tmp_path, monkeypatch):
    """The journal is read back with a 64 KiB cap; a patch touching ~800 paths writes a bigger one, so after a crash recovery would be
    refused as 'corrupt/oversized'. Either the gate must refuse to START such a landing, or it must be able to recover it."""
    from hlith.gate.git_write import apply_index_and_verify_tree, compute_path_images, head_commit, patch_paths
    from hlith.gate.journal import begin_journal

    base_files, edits = _many_files(800)
    env = Env(tmp_path, monkeypatch, {**BASE, **base_files}, edits)
    head = env.head()
    paths = patch_paths(env.repo, env.patch)
    images = compute_path_images(env.repo, head, env.patch, paths)
    try:
        begin_journal(env.repo, env.host, env.host.stable_repo_identity(env.repo), base_head=head_commit(env.repo), paths=paths,
                      patch_sha256="x" * 64, images=images)
    except Exception as exc:  # refusing to start (before touching the worktree) is acceptable
        assert "journal" in str(exc).lower(), exc
        assert _git(env.repo, "status", "--porcelain") == ""
        return
    apply_index_and_verify_tree(env.repo, env.patch, env.ve.record.post_tree_oid)
    status = env.gate.recover(env.repo)
    assert status.startswith("recovered"), status
    assert env.head() == head and _git(env.repo, "status", "--porcelain") == ""


def test_a_landing_whose_journal_would_exceed_the_cap_is_refused_before_anything_is_written(env, monkeypatch):
    from hlith.gate import journal as j

    monkeypatch.setattr(j, "_JOURNAL_MAX", 300)
    head = env.head()
    r = env.land()
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, r
    assert env.head() == head and _git(env.repo, "status", "--porcelain") == ""
    jd = env.host.namespace(env.host.stable_repo_identity(env.repo), "journal")
    assert not list(jd.glob("landing-*.json")) and not list(jd.glob("landing-*.nonce"))


def test_a_patch_touching_paths_beyond_the_argv_limit_raises_a_gate_error_not_a_raw_oserror(tmp_path, monkeypatch):
    """Every gate git call passes the touched paths as argv; ~600 paths of ~3.6 KB exceed ARG_MAX (E2BIG). The gate's callers only
    handle HostIntegrityError, so a raw OSError out of the helper would be an uncaught crash in the host writer (helper level: a data-file
    patch cannot reach the gate through the stand-in obligations)."""
    from hlith.gate.git_write import compute_path_images, patch_paths
    from hlith.hostio.integrity import HostIntegrityError

    seg = "x" * 200

    def name(i):
        return "/".join([f"{seg}{k:02d}" for k in range(17)]) + f"/f{i:04d}.txt"

    base_files, edits = _many_files(1200, name)
    env = Env(tmp_path, monkeypatch, {**BASE, **base_files}, edits)
    try:
        paths = patch_paths(env.repo, env.patch)
        images = compute_path_images(env.repo, env.head(), env.patch, paths)
    except HostIntegrityError:
        return  # a gate error the caller turns into a refusal
    assert len(images) == len(paths) == 1200  # or it handled them
