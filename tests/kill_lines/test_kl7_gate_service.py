"""KL7: LocalGateService.land enforces MAC, digests, scope, consumption, identity, hostility, and idempotence."""
from __future__ import annotations

import dataclasses
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from hlith.contract.capabilities import VerifiedEffect
from hlith.contract.errors import EXIT_BOUNDARY, EXIT_LANDED, BoundaryReason
from hlith.contract.identities import TargetIdentity, new_run_id, sha256_hex, tree_oid
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.obligations import (
    AccountConsumption,
    RequiredScope,
    ScopeDischarge,
    VerificationRecord,
    obligation_set_digest,
)
from hlith.contract.runs import GateReceipt
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService


@dataclass
class _GateEnv:
    repo: Path
    patch: bytes
    gate: LocalGateService
    verifier: LocalVerificationService
    ident: TargetIdentity
    verified: VerifiedEffect
    head_before: str
    tree_before: str
    account_sha256: str


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _make_gate_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _GateEnv:
    state_dir = tmp_path / "state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(state_dir))

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")

    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    patch = subprocess.run(["git", "-C", str(repo), "diff"], capture_output=True, check=True).stdout
    _git(repo, "checkout", "--", "m.py")

    host_state = LocalHostState(state_dir)
    git_read = HardenedGitRead()
    snap_svc = LocalSnapshotService(git_read)
    verifier = LocalVerificationService(host_state)
    gate = LocalGateService(host_state, git_read=git_read, snapshot_service=snap_svc)

    base_snap = snap_svc.seal_base(repo)
    post_snap = snap_svc.reconstruct_post(base_snap, patch)
    ident = capture_target_identity(repo)

    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obls = ObligationSet((Obligation("o1", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True),))

    req_scope = RequiredScope(("callable:m.f",))
    dis_scope = ScopeDischarge((("callable:m.f", "o1"),))
    account_sha = sha256_hex(hashlib.sha256(b"account:m.f").hexdigest())
    patch_sha = sha256_hex(hashlib.sha256(patch).hexdigest())

    unsigned = VerificationRecord(
        run_id=new_run_id(),
        base_tree_oid=base_snap.tree_oid,
        patch_sha256=patch_sha,
        post_tree_oid=post_snap.tree_oid,
        account_sha256=account_sha,
        target=ident,
        required_scope_digest=req_scope.digest,
        scope_discharge_digest=dis_scope.digest,
        obligation_set_sha256=obligation_set_digest(obls),
        consumption=(AccountConsumption(obligation_id="o1", account_sha256=account_sha),),
        context_identity_sha256=sha256_hex("c" * 64),
        checker_ids=("checker",),
        issuer=verifier.issuer_id,
    )
    signed = verifier.issue(unsigned)
    verified = VerifiedEffect(
        obligations=obls,
        record=signed,
        required_scope=req_scope,
        scope_discharge=dis_scope,
    )

    return _GateEnv(
        repo=repo,
        patch=patch,
        gate=gate,
        verifier=verifier,
        ident=ident,
        verified=verified,
        head_before=_git(repo, "rev-parse", "HEAD"),
        tree_before=str(base_snap.tree_oid),
        account_sha256=str(account_sha),
    )


def _assert_refused_unchanged(env: _GateEnv, receipt: GateReceipt, expected: BoundaryReason) -> None:
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert expected.value in receipt.blocking, f"expected {expected.value!r} in {receipt.blocking!r}"
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == env.tree_before
    assert _git(env.repo, "status", "--porcelain") == ""


def test_kl7_forged_mac_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    mac = env.verified.record.mac
    forged_mac = ("0" if mac[0] != "0" else "1") + mac[1:]
    forged = dataclasses.replace(env.verified, record=dataclasses.replace(env.verified.record, mac=forged_mac))
    receipt = env.gate.land(env.repo, env.patch, forged, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.RECORD_INVALID)


def test_kl7_unsigned_record_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    unsigned = dataclasses.replace(env.verified, record=dataclasses.replace(env.verified.record, mac=""))
    receipt = env.gate.land(env.repo, env.patch, unsigned, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.RECORD_INVALID)


def test_kl7_tampered_obligation_set_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    orig = env.verified.obligations.obligations[0]
    tampered_ob = dataclasses.replace(orig, claim="tampered-claim")
    tampered = dataclasses.replace(env.verified, obligations=ObligationSet((tampered_ob,)))
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.RECORD_INVALID)


def test_kl7_wrong_patch_digest_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    other_patch = env.patch.replace(b"x + 1", b"x + 2")
    receipt = env.gate.land(env.repo, other_patch, env.verified, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.ACCOUNT_MISMATCH)


def test_kl7_wrong_base_tree_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    bad_base = tree_oid(("0" if env.tree_before[0] != "0" else "1") + env.tree_before[1:])
    reissued = env.verifier.issue(dataclasses.replace(env.verified.record, base_tree_oid=bad_base, mac=""))
    tampered = dataclasses.replace(env.verified, record=reissued)
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.BASE_TREE_MISMATCH)


def test_kl7_wrong_post_tree_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    orig_post = str(env.verified.record.post_tree_oid)
    other_blob = subprocess.run(
        ["git", "-C", str(env.repo), "hash-object", "-w", "--stdin"],
        input=b"def f(x):\n    return x + 2\n",
        capture_output=True,
        check=True,
    ).stdout.decode().strip()
    other_tree = tree_oid(
        subprocess.run(
            ["git", "-C", str(env.repo), "mktree"],
            input=f"100644 blob {other_blob}\tm.py\n".encode(),
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
    )
    for bad_post in (
        tree_oid(("0" if orig_post[0] != "0" else "1") + orig_post[1:]),
        other_tree,  # existing ODB tree != base/post: directly tests semantic post-tree verification
    ):
        reissued = env.verifier.issue(dataclasses.replace(env.verified.record, post_tree_oid=bad_post, mac=""))
        tampered = dataclasses.replace(env.verified, record=reissued)
        receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
        _assert_refused_unchanged(env, receipt, BoundaryReason.POST_TREE_MISMATCH)


def test_kl7_required_scope_digest_mismatch_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    swapped_scope = RequiredScope(("callable:m.other",))
    tampered = dataclasses.replace(env.verified, required_scope=swapped_scope)
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.RECORD_INVALID)


def test_kl7_discharge_incomplete_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    wider_scope = RequiredScope(("callable:m.f", "callable:m.g"))
    reissued = env.verifier.issue(
        dataclasses.replace(env.verified.record, required_scope_digest=wider_scope.digest, mac="")
    )
    tampered = dataclasses.replace(env.verified, record=reissued, required_scope=wider_scope)
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.SCOPE_UNDISCHARGED)


def test_kl7_account_consumption_missing_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    reissued = env.verifier.issue(dataclasses.replace(env.verified.record, consumption=(), mac=""))
    tampered = dataclasses.replace(env.verified, record=reissued)
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.ACCOUNT_MISMATCH)


def test_kl7_target_identity_changed_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    wrong_ident = TargetIdentity(
        device=env.ident.device,
        inode=env.ident.inode + 1,
        git_dir_sha256=env.ident.git_dir_sha256,
    )
    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, wrong_ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.TARGET_IDENTITY_CHANGED)


def test_kl7_hostile_repo_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    _git(env.repo, "config", "core.fsmonitor", "true")
    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    _assert_refused_unchanged(env, receipt, BoundaryReason.HOSTILE_REPOSITORY)


def test_kl7_landing_key_v2_idempotence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.git_write import head_landing_keys

    env = _make_gate_env(tmp_path, monkeypatch)
    r1 = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert r1.outcome == "landed"
    assert r1.exit_status == EXIT_LANDED
    assert r1.landed_commit is not None
    count_after_1 = _git(env.repo, "rev-list", "--count", "HEAD")

    rec = env.verified.record
    expected_lkey = hashlib.sha256(
        f"{rec.base_tree_oid}|{rec.patch_sha256}|{rec.post_tree_oid}|{rec.account_sha256}|{rec.body_sha256}".encode("utf-8")
    ).hexdigest()
    assert expected_lkey in head_landing_keys(env.repo)

    # Second land with same key/record must not create a second commit.
    env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert _git(env.repo, "rev-list", "--count", "HEAD") == count_after_1
    assert _git(env.repo, "rev-parse", "HEAD") == r1.landed_commit


def test_kl7_landing_key_v2_already_in_head_skips_recommit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    rec = env.verified.record
    expected_lkey = hashlib.sha256(
        f"{rec.base_tree_oid}|{rec.patch_sha256}|{rec.post_tree_oid}|{rec.account_sha256}|{rec.body_sha256}".encode("utf-8")
    ).hexdigest()
    # Genuine prior landing: HEAD carries post_tree_oid, parent carries base_tree_oid, clean tree, and Hlith-Key trailer.
    subprocess.run(["git", "-C", str(env.repo), "apply", "--index", "-"], input=env.patch, check=True)
    _git(env.repo, "commit", "-qm", f"hlith: prior\n\nHlith-Key: {expected_lkey}")
    head_with_key = _git(env.repo, "rev-parse", "HEAD")
    count_before = _git(env.repo, "rev-list", "--count", "HEAD")

    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert receipt.outcome == "landed"
    assert receipt.exit_status == EXIT_LANDED
    assert receipt.landed_commit == head_with_key
    assert _git(env.repo, "rev-list", "--count", "HEAD") == count_before
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == str(rec.post_tree_oid)


def test_kl7_forged_trailer_at_base_or_wrong_post_tree_not_replayed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (1) Legacy bogus fixture (--allow-empty at base_tree_oid carrying Hlith-Key) must NOT spoof an existing landing.
    (tmp_path / "c1").mkdir()
    env1 = _make_gate_env(tmp_path / "c1", monkeypatch)
    rec1 = env1.verified.record
    lkey1 = hashlib.sha256(
        f"{rec1.base_tree_oid}|{rec1.patch_sha256}|{rec1.post_tree_oid}|{rec1.account_sha256}|{rec1.body_sha256}".encode("utf-8")
    ).hexdigest()
    _git(env1.repo, "commit", "--allow-empty", "-m", f"hlith: forged-empty\n\nHlith-Key: {lkey1}")
    forged_empty_head = _git(env1.repo, "rev-parse", "HEAD")
    r1 = env1.gate.land(env1.repo, env1.patch, env1.verified, env1.verifier, env1.ident)
    assert r1.outcome == "landed"
    assert r1.landed_commit != forged_empty_head
    assert _git(env1.repo, "rev-parse", "HEAD^{tree}") == str(rec1.post_tree_oid)

    # (2) Wrong post_tree carrying the genuine Hlith-Key trailer must NEVER report landed; it refuses BASE_TREE_MISMATCH.
    (tmp_path / "c2").mkdir()
    env2 = _make_gate_env(tmp_path / "c2", monkeypatch)
    rec2 = env2.verified.record
    lkey2 = hashlib.sha256(
        f"{rec2.base_tree_oid}|{rec2.patch_sha256}|{rec2.post_tree_oid}|{rec2.account_sha256}|{rec2.body_sha256}".encode("utf-8")
    ).hexdigest()
    (env2.repo / "m.py").write_text("def f(x):\n    return x + 999\n")
    _git(env2.repo, "add", "m.py")
    _git(env2.repo, "commit", "-qm", f"hlith: wrong-tree\n\nHlith-Key: {lkey2}")
    wrong_head = _git(env2.repo, "rev-parse", "HEAD")
    wrong_tree = _git(env2.repo, "rev-parse", "HEAD^{tree}")
    r2 = env2.gate.land(env2.repo, env2.patch, env2.verified, env2.verifier, env2.ident)
    assert r2.outcome == "refused"
    assert r2.exit_status == EXIT_BOUNDARY
    assert BoundaryReason.BASE_TREE_MISMATCH.value in r2.blocking
    assert _git(env2.repo, "rev-parse", "HEAD") == wrong_head
    assert _git(env2.repo, "rev-parse", "HEAD^{tree}") == wrong_tree


def test_kl7_sa6_different_run_id_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    expected_run = new_run_id()
    other_run_record = env.verifier.issue(
        dataclasses.replace(env.verified.record, run_id=new_run_id(), mac="")
    )
    swapped = dataclasses.replace(env.verified, record=other_run_record)
    receipt = env.gate.land(
        env.repo, env.patch, swapped, env.verifier, env.ident, expected_run_id=expected_run
    )
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert "run-id-mismatch" in receipt.blocking
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == env.tree_before


def test_kl7_sa7_empty_required_scope_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    empty_req = RequiredScope(())
    empty_dis = ScopeDischarge(())
    reissued = env.verifier.issue(
        dataclasses.replace(
            env.verified.record,
            required_scope_digest=empty_req.digest,
            scope_discharge_digest=empty_dis.digest,
            mac="",
        )
    )
    tampered = dataclasses.replace(
        env.verified,
        record=reissued,
        required_scope=empty_req,
        scope_discharge=empty_dis,
    )
    receipt = env.gate.land(env.repo, env.patch, tampered, env.verifier, env.ident)
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert "required-scope-empty-for-source-change" in receipt.blocking
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == env.tree_before


def test_kl7_empty_required_scope_non_python_patch_lands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    (env.repo / "README.md").write_text("docs\n")
    _git(env.repo, "add", "README.md")
    _git(env.repo, "commit", "-qm", "add readme")
    (env.repo / "README.md").write_text("docs updated\n")
    doc_patch = subprocess.run(["git", "-C", str(env.repo), "diff"], capture_output=True, check=True).stdout
    _git(env.repo, "checkout", "--", "README.md")

    snap_svc = env.gate._snapshot_service
    base_snap = snap_svc.seal_base(env.repo)
    post_snap = snap_svc.reconstruct_post(base_snap, doc_patch)
    ident = capture_target_identity(env.repo)
    empty_req = RequiredScope(())
    empty_dis = ScopeDischarge(())
    doc_rec = env.verifier.issue(
        dataclasses.replace(
            env.verified.record,
            base_tree_oid=base_snap.tree_oid,
            patch_sha256=sha256_hex(hashlib.sha256(doc_patch).hexdigest()),
            post_tree_oid=post_snap.tree_oid,
            target=ident,
            required_scope_digest=empty_req.digest,
            scope_discharge_digest=empty_dis.digest,
            mac="",
        )
    )
    doc_verified = dataclasses.replace(
        env.verified,
        record=doc_rec,
        required_scope=empty_req,
        scope_discharge=empty_dis,
    )
    receipt = env.gate.land(env.repo, doc_patch, doc_verified, env.verifier, ident)
    assert receipt.outcome == "landed"
    assert receipt.exit_status == EXIT_LANDED


def test_kl7_dirty_staged_file_refuses_and_preserves_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.git_write import rollback_paths, worktree_blob_oid

    env = _make_gate_env(tmp_path, monkeypatch)
    (env.repo / "b.py").write_text("y = 1\n")
    _git(env.repo, "add", "b.py")

    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert "target-dirty" in receipt.blocking
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "diff", "--cached", "--name-only") == "b.py"

    # Path-limited rollback_paths on m.py must also leave unrelated b.py staged.
    m_blob = worktree_blob_oid(env.repo, "m.py")
    rollback_paths(env.repo, env.head_before, ["m.py"], {"m.py": [m_blob, ""]})
    assert _git(env.repo, "diff", "--cached", "--name-only") == "b.py"


def test_kl7_two_same_history_clones_isolated_journals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.journal import begin_journal, clear_journal, load_verified_journal

    env = _make_gate_env(tmp_path, monkeypatch)
    clone2 = tmp_path / "clone2"
    subprocess.run(["git", "clone", "-q", str(env.repo), str(clone2)], check=True)

    host_state = env.gate._host_state
    id1 = host_state.stable_repo_identity(env.repo)
    id2 = host_state.stable_repo_identity(clone2)
    assert id1 == id2

    j1, n1 = begin_journal(
        env.repo,
        host_state,
        id1,
        base_head=env.head_before,
        paths=["m.py"],
        patch_sha256="a" * 64,
        images={"m.py": ["", ""]},
    )
    j2, n2 = begin_journal(
        clone2,
        host_state,
        id2,
        base_head=env.head_before,
        paths=["m.py"],
        patch_sha256="b" * 64,
        images={"m.py": ["", ""]},
    )
    assert j1 != j2 and n1 != n2
    assert j1.exists() and j2.exists()

    loaded1 = load_verified_journal(env.repo, host_state, id1)
    loaded2 = load_verified_journal(clone2, host_state, id2)
    assert loaded1 is not None and loaded1[0]["patch_sha256"] == "a" * 64
    assert loaded2 is not None and loaded2[0]["patch_sha256"] == "b" * 64
    clear_journal(j1, n1)
    clear_journal(j2, n2)


def _setup_staged_plus_unstaged_b(repo: Path) -> tuple[str, str, str]:
    notes_dir = repo / "notes"
    notes_dir.mkdir(exist_ok=True)
    b_path = notes_dir / "B.txt"
    b_path.write_text("operator work\n", encoding="utf-8")
    _git(repo, "add", "notes/B.txt")
    b_path.write_text("operator work\nunstaged line\n", encoding="utf-8")
    cached_diff = _git(repo, "diff", "--cached", "--", "notes/B.txt")
    worktree_diff = _git(repo, "diff", "--", "notes/B.txt")
    return cached_diff, worktree_diff, b_path.read_text(encoding="utf-8")


def test_kl7_g1a_dirty_staged_plus_unstaged_refusal_preserves_diffs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    cached_before, worktree_before, bytes_before = _setup_staged_plus_unstaged_b(env.repo)
    bad_rec = dataclasses.replace(env.verified.record, mac="0" * 64)
    bad_verified = dataclasses.replace(env.verified, record=bad_rec)

    receipt = env.gate.land(env.repo, env.patch, bad_verified, env.verifier, env.ident)
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "diff", "--cached", "--", "notes/B.txt") == cached_before
    assert _git(env.repo, "diff", "--", "notes/B.txt") == worktree_before
    assert (env.repo / "notes" / "B.txt").read_text(encoding="utf-8") == bytes_before


def test_kl7_g1b_dirty_staged_plus_unstaged_valid_record_preserves_diffs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    cached_before, worktree_before, bytes_before = _setup_staged_plus_unstaged_b(env.repo)

    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert "target-dirty" in receipt.blocking
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before
    assert _git(env.repo, "diff", "--cached", "--", "notes/B.txt") == cached_before
    assert _git(env.repo, "diff", "--", "notes/B.txt") == worktree_before
    assert (env.repo / "notes" / "B.txt").read_text(encoding="utf-8") == bytes_before


def test_kl7_g2a_concurrent_land_two_same_history_clones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    env = _make_gate_env(tmp_path, monkeypatch)
    clone2 = tmp_path / "clone2"
    subprocess.run(["git", "clone", "-q", str(env.repo), str(clone2)], check=True)
    _git(clone2, "config", "user.email", "kl7@example.invalid")
    _git(clone2, "config", "user.name", "KL7")
    ident2 = capture_target_identity(clone2)
    run_id2 = new_run_id()
    rec2 = env.verifier.issue(
        dataclasses.replace(
            env.verified.record,
            run_id=run_id2,
            target=ident2,
            mac="",
            issuer=env.verifier.issuer_id,
        )
    )
    verified2 = dataclasses.replace(env.verified, record=rec2)

    def _land_one(target: Path, ver: VerifiedEffect, ident: TargetIdentity) -> GateReceipt:
        return env.gate.land(target, env.patch, ver, env.verifier, ident, expected_run_id=ver.record.run_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_land_one, env.repo, env.verified, env.ident)
        f2 = pool.submit(_land_one, clone2, verified2, ident2)
        r1 = f1.result()
        r2 = f2.result()

    assert r1.outcome == "landed" and r1.exit_status == EXIT_LANDED
    assert r2.outcome == "landed" and r2.exit_status == EXIT_LANDED
    assert _git(env.repo, "rev-parse", "HEAD") == r1.landed_commit
    assert _git(clone2, "rev-parse", "HEAD") == r2.landed_commit


def test_kl7_g2b_recover_isolated_between_same_history_clones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hlith.gate.git_write import apply_index_and_verify_tree, compute_path_images
    from hlith.gate.journal import begin_journal

    env = _make_gate_env(tmp_path, monkeypatch)
    clone2 = tmp_path / "clone2"
    subprocess.run(["git", "clone", "-q", str(env.repo), str(clone2)], check=True)
    host_state = env.gate._host_state
    id1 = host_state.stable_repo_identity(env.repo)

    images = compute_path_images(env.repo, env.head_before, env.patch, ["m.py"])
    begin_journal(
        env.repo,
        host_state,
        id1,
        base_head=env.head_before,
        paths=["m.py"],
        patch_sha256=str(env.verified.record.patch_sha256),
        images=images,
    )
    assert apply_index_and_verify_tree(env.repo, env.patch, env.verified.record.post_tree_oid)
    assert "x + 1" in (env.repo / "m.py").read_text(encoding="utf-8")

    # C2 must report clean and remain untouched.
    assert env.gate.recover(clone2) == "clean"
    assert "x + 1" not in (clone2 / "m.py").read_text(encoding="utf-8")

    # C1 recovers back to base_head and clears its journal.
    status = env.gate.recover(env.repo)
    assert status != "clean"
    assert "x + 1" not in (env.repo / "m.py").read_text(encoding="utf-8")
    assert _git(env.repo, "status", "--porcelain") == ""
    assert env.gate.recover(env.repo) == "clean"


@pytest.mark.parametrize(
    ("case_name", "bad_patch"),
    [
        (
            "symlink_escape",
            b"diff --git a/escape b/escape\nnew file mode 120000\n--- /dev/null\n+++ b/escape\n@@ -0,0 +1 @@\n+/etc/passwd\n",
        ),
        (
            "gitlink",
            b"diff --git a/sub b/sub\nnew file mode 160000\n--- /dev/null\n+++ b/sub\n@@ -0,0 +1 @@\n+Subproject commit 0000000000000000000000000000000000000000\n",
        ),
        (
            "dotgit_hooks",
            b"diff --git a/.git/hooks/pre-commit b/.git/hooks/pre-commit\nnew file mode 100755\n--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1 @@\n+#!/bin/sh\n",
        ),
        (
            "dothlith",
            b"diff --git a/.hlith/evil b/.hlith/evil\nnew file mode 100644\n--- /dev/null\n+++ b/.hlith/evil\n@@ -0,0 +1 @@\n+x\n",
        ),
        (
            "symlink_cycle",
            (
                b"diff --git a/a b/a\nnew file mode 120000\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+b\n"
                b"diff --git a/b b/b\nnew file mode 120000\n--- /dev/null\n+++ b/b\n@@ -0,0 +1 @@\n+a\n"
            ),
        ),
        (
            "plain_diff_dothlith",
            b"--- /dev/null\n+++ b/.hlith/feedback/x.json\n@@ -0,0 +1 @@\n+{}\n",
        ),
        (
            "plain_diff_dothlith_delete",
            b"--- a/.hlith/p\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
        ),
        (
            "plain_diff_dothlith_modify",
            b"--- a/.hlith/p\n+++ b/.hlith/p\n@@ -1 +1 @@\n-x\n+y\n",
        ),
        (
            "svn_index_style",
            b"Index: .hlith/q\n===================================================================\n--- .hlith/q\n+++ .hlith/q\n@@ -1 +1 @@\n-x\n+y\n",
        ),
        (
            "comment_before_diff_git",
            b"# leading comment\ndiff --git a/m.py b/m.py\nindex 10219f0..7b9ebfe 100644\n--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return x + 1\n",
        ),
        (
            "symlink_missing_target",
            b"diff --git a/m.py b/m.py\nold mode 100644\nnew mode 120000\n",
        ),
        (
            "binary_patch_symlink",
            b"diff --git a/x b/x\nnew file mode 120000\nindex 0000000..1111111\nGIT binary patch\nliteral 11\nScmZQzU|<5P000000000000000\n",
        ),
        (
            "symlink_escape_space_b_slash",
            b"diff --git a/a b/c b/a b/c\nnew file mode 120000\n--- /dev/null\n+++ b/a b/c\n@@ -0,0 +1 @@\n+../../x\n\\ No newline at end of file\n",
        ),
    ],
)
def test_kl7_patch_policy_violation_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_name: str, bad_patch: bytes
) -> None:
    from hlith.hostio.integrity import HostIntegrityError

    env = _make_gate_env(tmp_path, monkeypatch)
    snap_service = env.gate._snapshot_service
    base_snap = snap_service.seal_base(env.repo)
    with pytest.raises(HostIntegrityError, match="patch-policy-violation"):
        snap_service.reconstruct_post(base_snap, bad_patch)

    bad_patch_sha = sha256_hex(hashlib.sha256(bad_patch).hexdigest())
    unsigned = dataclasses.replace(
        env.verified.record,
        patch_sha256=bad_patch_sha,
        mac="",
        issuer=env.verifier.issuer_id,
    )
    rec = env.verifier.issue(unsigned)
    bad_verified = dataclasses.replace(env.verified, record=rec)
    receipt = env.gate.land(env.repo, bad_patch, bad_verified, env.verifier, env.ident)
    assert receipt.outcome == "refused", case_name
    assert receipt.exit_status == EXIT_BOUNDARY, case_name
    assert "patch-policy-violation" in receipt.blocking, (case_name, receipt.blocking)
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before


def test_kl7_existing_unrecovered_journal_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.journal import begin_journal

    env = _make_gate_env(tmp_path, monkeypatch)
    host_state = env.gate._host_state
    repo_id = host_state.stable_repo_identity(env.repo)
    j_path, n_path = begin_journal(
        env.repo,
        host_state,
        repo_id,
        base_head=env.head_before,
        paths=["m.py"],
        patch_sha256="a" * 64,
        images={"m.py": [env.head_before, ""]},
    )
    j_before = j_path.read_text(encoding="utf-8")
    n_before = n_path.read_text(encoding="utf-8")

    receipt = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_BOUNDARY
    assert "unrecovered-journal-exists" in receipt.blocking
    assert j_path.read_text(encoding="utf-8") == j_before
    assert n_path.read_text(encoding="utf-8") == n_before
    assert _git(env.repo, "rev-parse", "HEAD") == env.head_before


def test_kl7_stale_journal_recover_then_land_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.git_write import apply_index_and_verify_tree, compute_path_images
    from hlith.gate.journal import begin_journal

    env = _make_gate_env(tmp_path, monkeypatch)
    host_state = env.gate._host_state
    repo_id = host_state.stable_repo_identity(env.repo)
    images = compute_path_images(env.repo, env.head_before, env.patch, ["m.py"])
    j_path, n_path = begin_journal(
        env.repo,
        host_state,
        repo_id,
        base_head=env.head_before,
        paths=["m.py"],
        patch_sha256=str(env.verified.record.patch_sha256),
        images=images,
    )
    assert apply_index_and_verify_tree(env.repo, env.patch, env.verified.record.post_tree_oid)

    refused = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert refused.outcome == "refused"
    assert refused.exit_status == EXIT_BOUNDARY

    status = env.gate.recover(env.repo)
    assert status.startswith("recovered:")
    assert not j_path.exists() and not n_path.exists()
    assert env.gate.recover(env.repo) == "clean"

    landed = env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)
    assert landed.outcome == "landed"
    assert landed.exit_status == EXIT_LANDED
    assert _git(env.repo, "rev-parse", "HEAD") == landed.landed_commit


def test_kl7_hunk_triple_dash_comment_not_false_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """G2: deleting '-- ../data' inside a hunk produces '--- ../data'; must not false-refuse as escaping path."""
    from hlith.hostio.snapshot import patch_violations

    env = _make_gate_env(tmp_path, monkeypatch)
    (env.repo / "notes.sql").write_text("-- ../data\nselect 1;\n", encoding="utf-8")
    _git(env.repo, "add", "notes.sql")
    _git(env.repo, "commit", "-q", "-m", "add sql")

    sql_patch = (
        b"diff --git a/notes.sql b/notes.sql\n"
        b"index 0000000..0000000 100644\n"
        b"--- a/notes.sql\n"
        b"+++ b/notes.sql\n"
        b"@@ -1,2 +1 @@\n"
        b"--- ../data\n"
        b" select 1;\n"
    )
    assert patch_violations(sql_patch.decode("utf-8")) == []
    base_snap = env.gate._snapshot_service.seal_base(env.repo)
    post_snap = env.gate._snapshot_service.reconstruct_post(base_snap, sql_patch)
    ident = capture_target_identity(env.repo)
    rec = env.verifier.issue(
        dataclasses.replace(
            env.verified.record,
            base_tree_oid=base_snap.tree_oid,
            post_tree_oid=post_snap.tree_oid,
            patch_sha256=sha256_hex(hashlib.sha256(sql_patch).hexdigest()),
            target=ident,
            mac="",
            issuer=env.verifier.issuer_id,
        )
    )
    verified_sql = dataclasses.replace(env.verified, record=rec)
    receipt = env.gate.land(env.repo, sql_patch, verified_sql, env.verifier, ident)
    assert receipt.outcome == "landed"
    assert receipt.exit_status == EXIT_LANDED


def test_kl7_recovery_preserves_commit_after_journal_unlink_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after commit must preserve HEAD's committed tree during journal recovery."""
    from hlith.gate import api as gate_api

    env = _make_gate_env(tmp_path, monkeypatch)
    real_clear_journal = gate_api.clear_journal

    def crash_before_journal_unlink(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated crash after commit, before journal unlink")

    monkeypatch.setattr(gate_api, "clear_journal", crash_before_journal_unlink)
    with pytest.raises(RuntimeError, match="after commit"):
        env.gate.land(env.repo, env.patch, env.verified, env.verifier, env.ident)

    landed_head = _git(env.repo, "rev-parse", "HEAD")
    assert landed_head != env.head_before
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == str(env.verified.record.post_tree_oid)
    host_state = env.gate._host_state
    journal_dir = host_state.namespace(host_state.stable_repo_identity(env.repo), "journal")
    assert list(journal_dir.glob("landing-*.json"))

    monkeypatch.setattr(gate_api, "clear_journal", real_clear_journal)
    status = env.gate.recover(env.repo)

    assert _git(env.repo, "rev-parse", "HEAD") == landed_head
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") == str(env.verified.record.post_tree_oid)
    assert _git(env.repo, "status", "--porcelain") == ""
    assert (env.repo / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return x + 1\n"
    assert status == "completed"
    assert not list(journal_dir.glob("landing-*.json"))
    assert not list(journal_dir.glob("landing-*.nonce"))
    assert env.gate.recover(env.repo) == "clean"


def _begin_recovery_test_journal(
    env: _GateEnv,
    *,
    paths: list[str] | None = None,
    images: dict | None = None,
) -> tuple[Path, Path]:
    from hlith.gate.git_write import compute_path_images
    from hlith.gate.journal import begin_journal

    host_state = env.gate._host_state
    repo_id = host_state.stable_repo_identity(env.repo)
    if paths is None:
        paths = ["m.py"]
    if images is None:
        images = compute_path_images(env.repo, env.head_before, env.patch, paths)
    return begin_journal(
        env.repo,
        host_state,
        repo_id,
        base_head=env.head_before,
        paths=paths,
        patch_sha256=str(env.verified.record.patch_sha256),
        images=images,
    )


def _commit_recovery_test_patch(env: _GateEnv, *, extra_path: bool = False) -> None:
    from hlith.gate.git_write import apply_index_and_verify_tree

    assert apply_index_and_verify_tree(env.repo, env.patch, env.verified.record.post_tree_oid)
    if extra_path:
        (env.repo / "extra.txt").write_text("unaccounted path\n", encoding="utf-8")
        _git(env.repo, "add", "extra.txt")
    _git(env.repo, "commit", "-q", "-m", "simulated landing commit")


def _assert_untrusted_journal_is_preserved(env: _GateEnv, j_path: Path, n_path: Path) -> None:
    journal_before = j_path.read_bytes()
    nonce_before = n_path.read_bytes()
    head_before = _git(env.repo, "rev-parse", "HEAD")
    status_before = _git(env.repo, "status", "--porcelain", "--untracked-files=all")
    diff_before = _git(env.repo, "diff", "HEAD", "--binary")

    assert env.gate.recover(env.repo) == "untrusted"

    assert _git(env.repo, "rev-parse", "HEAD") == head_before
    assert _git(env.repo, "status", "--porcelain", "--untracked-files=all") == status_before
    assert _git(env.repo, "diff", "HEAD", "--binary") == diff_before
    assert j_path.read_bytes() == journal_before
    assert n_path.read_bytes() == nonce_before


def test_kl7_recovery_refuses_unrelated_commit_on_base_and_keeps_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    (env.repo / "unrelated.txt").write_text("operator commit\n", encoding="utf-8")
    _git(env.repo, "add", "unrelated.txt")
    _git(env.repo, "commit", "-q", "-m", "unrelated operator commit")

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert (env.repo / "unrelated.txt").read_text(encoding="utf-8") == "operator commit\n"
    assert (env.repo / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return x\n"


def test_kl7_recovery_refuses_head_with_non_base_parent_and_keeps_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    _commit_recovery_test_patch(env)
    (env.repo / "unrelated-on-top.txt").write_text("unrelated later commit\n", encoding="utf-8")
    _git(env.repo, "add", "unrelated-on-top.txt")
    _git(env.repo, "commit", "-q", "-m", "unrelated commit after landing")
    assert _git(env.repo, "rev-parse", "HEAD^") != env.head_before

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert _git(env.repo, "status", "--porcelain") == ""


def test_kl7_recovery_completes_new_file_landing_with_empty_pre_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    new_file = env.repo / "new-file.py"
    new_file.write_text("def added():\n    return 7\n", encoding="utf-8")
    post_blob = _git(env.repo, "hash-object", "--no-filters", "--", "new-file.py")
    j_path, n_path = _begin_recovery_test_journal(
        env,
        paths=["new-file.py"],
        images={"new-file.py": ["", post_blob]},
    )
    _git(env.repo, "add", "new-file.py")
    _git(env.repo, "commit", "-q", "-m", "simulated new-file landing")

    assert _git(env.repo, "rev-parse", "HEAD:new-file.py") == post_blob
    assert env.gate.recover(env.repo) == "completed"
    assert _git(env.repo, "status", "--porcelain") == ""
    assert new_file.read_text(encoding="utf-8") == "def added():\n    return 7\n"
    assert not j_path.exists() and not n_path.exists()


def test_kl7_recovery_completes_deletion_landing_with_empty_post_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    pre_blob = _git(env.repo, "rev-parse", f"{env.head_before}:m.py")
    j_path, n_path = _begin_recovery_test_journal(
        env,
        paths=["m.py"],
        images={"m.py": [pre_blob, ""]},
    )
    _git(env.repo, "rm", "m.py")
    _git(env.repo, "commit", "-q", "-m", "simulated deletion landing")

    assert env.gate.recover(env.repo) == "completed"
    assert _git(env.repo, "status", "--porcelain") == ""
    assert not (env.repo / "m.py").exists()
    assert not j_path.exists() and not n_path.exists()


def test_kl7_recovery_completes_symlink_landing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    link = env.repo / "new-link"
    link.symlink_to("m.py")
    link_target = b"m.py"
    post_blob = hashlib.sha1(b"blob " + str(len(link_target)).encode("ascii") + b"\0" + link_target).hexdigest()
    j_path, n_path = _begin_recovery_test_journal(
        env,
        paths=["new-link"],
        images={"new-link": ["", post_blob]},
    )
    _git(env.repo, "add", "--", "new-link")
    _git(env.repo, "commit", "-q", "-m", "simulated symlink landing")

    assert _git(env.repo, "rev-parse", "HEAD:new-link") == post_blob
    assert env.gate.recover(env.repo) == "completed"
    assert _git(env.repo, "status", "--porcelain") == ""
    assert link.is_symlink() and link.readlink() == Path("m.py")
    assert not j_path.exists() and not n_path.exists()


def test_kl7_recovery_refuses_landing_commit_with_extra_path_and_keeps_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    _commit_recovery_test_patch(env, extra_path=True)

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert (env.repo / "extra.txt").read_text(encoding="utf-8") == "unaccounted path\n"
    assert _git(env.repo, "status", "--porcelain") == ""


def test_kl7_recovery_refuses_authenticated_journal_with_wrong_post_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hlith.gate.git_write import compute_path_images

    env = _make_gate_env(tmp_path, monkeypatch)
    images = compute_path_images(env.repo, env.head_before, env.patch, ["m.py"])
    images["m.py"][1] = "0" * 40
    j_path, n_path = _begin_recovery_test_journal(env, images=images)
    _commit_recovery_test_patch(env)

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert _git(env.repo, "status", "--porcelain") == ""


def test_kl7_recovery_refuses_dirty_index_after_commit_and_keeps_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    _commit_recovery_test_patch(env)
    (env.repo / "staged.txt").write_text("operator staging\n", encoding="utf-8")
    _git(env.repo, "add", "staged.txt")

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert "staged.txt" in _git(env.repo, "status", "--porcelain")
    assert (env.repo / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return x + 1\n"


def test_kl7_recovery_refuses_worktree_edit_after_commit_and_keeps_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    _commit_recovery_test_patch(env)
    operator_edit = "def f(x):\n    return x * 99  # operator edit after the crash\n"
    (env.repo / "m.py").write_text(operator_edit, encoding="utf-8")

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert (env.repo / "m.py").read_text(encoding="utf-8") == operator_edit


def test_kl7_recovery_refuses_untracked_worktree_file_after_commit_and_keeps_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _make_gate_env(tmp_path, monkeypatch)
    j_path, n_path = _begin_recovery_test_journal(env)
    _commit_recovery_test_patch(env)
    operator_file = env.repo / "operator-notes.txt"
    operator_file.write_text("preserve this untracked file\n", encoding="utf-8")

    _assert_untrusted_journal_is_preserved(env, j_path, n_path)
    assert operator_file.read_text(encoding="utf-8") == "preserve this untracked file\n"
