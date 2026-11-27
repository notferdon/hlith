"""G2-4a, retargeted to Hlith Review (product.REVIEW_ONLY).

Was: a hard kill mid-landing was recovered through `hlith run`'s own pre-check (`cli.recover_pending_landing`). The review-only
distribution offers no `run`/`apply` and never writes the original repository, so the CLI wrapper now recovers nothing and touches
nothing: it says so ("review-only", reason), and `doctor` reports the pending journal read-only. The gate's recovery code still ships;
its semantics (rolled back / none / untrusted / untrusted-state / L4 host-state journal) are kept by calling `hlith.gate` directly."""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from hlith import cli
from hlith.gate import _legacy


def git(d, *a):
    return subprocess.run(["git", "-C", str(d), *a], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "t"
    r.mkdir()
    git(r, "init", "-q")
    (r / "a.py").write_text("def f(x):\n    return x\n")
    git(r, "add", ".")
    git(r, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "base")
    return r


DIFF = "diff --git a/c.py b/c.py\nnew file mode 100644\n--- /dev/null\n+++ b/c.py\n@@ -0,0 +1 @@\n+x = 1\n"


def kill_mid_landing(repo, fault="kill_after_apply"):
    script = textwrap.dedent(f"""
        import sys; sys.path.insert(0, {str(Path(__file__).parents[1] / 'src')!r})
        from pathlib import Path
        from hlith.gate import land, head_tree, target_identity
        from hlith.types import *
        P = CheckProvenance('x', 'a'*64, True, False, 'b'*64, 0)
        E = BoundedEvidence(3, 'e', 'u')
        o = Obligation('o', 's', 'c', Verdict.HELD, evidence=E, provenance=P, account_bound=True)
        d = Path({str(repo)!r})
        eff = ProposedEffect({DIFF!r}, 'k')
        land(d, eff, ObligationSet((o,)), expected_tree=head_tree(d), verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(d), fault={fault!r})
    """)
    return subprocess.run([sys.executable, "-c", script]).returncode


def _tree_state(repo):
    """Everything the wrapper could change: HEAD, porcelain status, and the bytes of every file under the work tree and .git (except the index stat cache)."""
    files = {}
    for f in sorted(repo.rglob("*")):
        if f.is_file() and f.name != "index":
            files[str(f.relative_to(repo))] = f.read_bytes()
    return git(repo, "rev-parse", "HEAD"), git(repo, "status", "--porcelain"), files


def _assert_review_only(repo):
    before = _tree_state(repo)
    state, msg = cli.recover_pending_landing(repo)
    assert state == "review-only" and msg and "does not recover" in msg, (state, msg)
    assert _tree_state(repo) == before, "the review-only wrapper changed the repository"
    return state, msg


# ------------------------------------------------------------------ CLI wrapper: review-only contract


def test_review_only_does_not_recover_a_half_landed_target_and_touches_nothing(repo, tmp_path):
    assert kill_mid_landing(repo) == 9
    assert (repo / "c.py").exists(), "fixture: the kill left the landing half-applied"
    assert cli.dirty_repo_reason(repo), "fixture: the pre-check alone refuses this tree"
    _assert_review_only(repo)
    assert (repo / "c.py").exists() and (repo / ".git" / "hlith-journal.json").is_file(), "the half-landed state and its journal stay for a person"
    from hlith.operator import cli as operator_cli

    ok, detail = operator_cli._pending_journal_check(repo, tmp_path / "state")
    assert ok is False and "read-only" in detail and "hlith run/apply" not in detail, detail


def test_review_only_wrapper_is_a_noop_without_a_journal(repo):
    _assert_review_only(repo)
    assert git(repo, "status", "--porcelain") == ""


def test_review_only_wrapper_never_reads_a_forged_journal_or_the_operator_work(repo):
    (repo / "keep.txt").write_text("operator work\n")
    j = repo / ".git" / "hlith-journal.json"
    j.write_text(json.dumps({"mac": "0" * 64, "paths": ["keep.txt"], "base_head": "0" * 40}))
    _assert_review_only(repo)
    assert (repo / "keep.txt").read_text() == "operator work\n" and j.exists()


def test_review_only_wrapper_runs_no_repository_program(repo, tmp_path):
    marker = tmp_path / "ran"
    hook = tmp_path / "h.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nprintf ''\n")
    hook.chmod(0o755)
    git(repo, "config", "core.fsmonitor", str(hook))
    assert cli.recover_pending_landing(repo)[0] == "review-only"
    assert not marker.exists(), "the review-only wrapper ran the repository's fsmonitor"


# ------------------------------------------------------------------ the shipped gate recovery, called directly (engine semantics kept)


def test_gate_recovers_a_half_landed_target(repo):
    from hlith import gate as _gate

    assert kill_mid_landing(repo) == 9
    assert _gate.recover(repo) in ("rolled-back", "completed")
    assert cli.dirty_repo_reason(repo) is None
    assert git(repo, "status", "--porcelain") == ""


def test_gate_does_not_complete_an_interrupted_landing_over_an_unrelated_commit(repo):
    from hlith import gate as _gate

    base_head = git(repo, "rev-parse", "HEAD")
    assert kill_mid_landing(repo) == 9
    journal = repo / ".git" / "hlith-journal.json"
    assert journal.is_file(), "fixture: interrupted landing journal is present"
    nonce = _legacy._nonce_file(repo)
    assert nonce.is_file() and len(nonce.read_bytes()) == 32, "fixture: host-side landing nonce is present"
    git(repo, "reset", "--hard", "-q", base_head)
    (repo / "unrelated.txt").write_text("operator commit\n")
    git(repo, "add", "unrelated.txt")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "unrelated user commit")
    unrelated_head = git(repo, "rev-parse", "HEAD")
    journal_before, nonce_before = journal.read_bytes(), nonce.read_bytes()

    assert _gate.recover(repo) == "untrusted-state"
    assert journal.read_bytes() == journal_before and nonce.read_bytes() == nonce_before
    assert git(repo, "rev-parse", "HEAD") == unrelated_head and git(repo, "status", "--porcelain") == ""
    assert (repo / "unrelated.txt").read_text() == "operator commit\n"


def test_gate_recovery_without_a_journal_is_none(repo):
    from hlith import gate as _gate

    assert _gate.recover(repo) == "none"


def test_gate_treats_a_forged_journal_as_untrusted_and_touches_nothing(repo):
    from hlith import gate as _gate

    (repo / "keep.txt").write_text("operator work\n")
    j = repo / ".git" / "hlith-journal.json"
    j.write_text(json.dumps({"mac": "0" * 64, "paths": ["keep.txt"], "base_head": "0" * 40}))
    assert _gate.recover(repo) == "untrusted"
    assert (repo / "keep.txt").read_text() == "operator work\n" and j.exists()


def test_gate_recovers_an_l4_host_state_journal(repo):
    import hashlib
    from hlith.gate.api import LocalGateService
    from hlith.gate.git_write import apply_index_and_verify_tree, compute_path_images
    from hlith.gate.journal import begin_journal
    from hlith.hostio import LocalHostState, LocalSnapshotService

    host_state = LocalHostState()
    repo_id = host_state.stable_repo_identity(repo)
    base_head = git(repo, "rev-parse", "HEAD")
    patch_bytes = DIFF.encode("utf-8")
    snap_svc = LocalSnapshotService()
    post_snap = snap_svc.reconstruct_post(snap_svc.seal_base(repo), patch_bytes)
    images = compute_path_images(repo, base_head, patch_bytes, ["c.py"])
    j_path, n_path = begin_journal(repo, host_state, repo_id, base_head=base_head, paths=["c.py"],
                                   patch_sha256=hashlib.sha256(patch_bytes).hexdigest(), images=images)
    assert apply_index_and_verify_tree(repo, patch_bytes, post_snap.tree_oid)
    assert (repo / "c.py").exists() and not (repo / ".git" / "hlith-journal.json").exists()

    _assert_review_only(repo)  # the review-only wrapper leaves even an authentic L4 journal alone
    assert (repo / "c.py").exists() and j_path.exists()

    assert LocalGateService(LocalHostState()).recover(repo) == f"recovered:{base_head[:12]}"
    assert not (repo / "c.py").exists()
    assert git(repo, "status", "--porcelain") == ""
    assert not j_path.exists() and not n_path.exists()
