# SPDX-License-Identifier: Apache-2.0
"""case (G1, gate level): the GATE refuses a signed record that carries an EMPTY obligation set, on its own guards.

STAND-IN (named, not a claim): ``ObligationSet`` refuses construction with no obligations and the engine never emits one
(tests/test_gate_empty_derived_set.py covers that layer), so an empty set is forged here with ``object.__new__`` and given a
genuinely valid signed record over it (real LocalVerificationService, real snapshots, real LocalGateService). No real
derivation is known to produce this; the test asserts what the gate does if one ever reached it.

Guards covered: gate/api.py ``if not obs`` (exit 4, scope-undischarged) and types.decide's no-account-bound refusal on an all()-vacuous
set (exit 11). Control: a nonempty all-HELD, account-bound, scope-discharged set lands."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from hlith.contract.capabilities import VerifiedEffect
from hlith.contract.errors import EXIT_BOUNDARY, EXIT_LANDED, BoundaryReason
from hlith.contract.identities import new_run_id, sha256_hex
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.obligations import (
    AccountConsumption, RequiredScope, ScopeDischarge, VerificationRecord, obligation_set_digest,
)
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.types import EXIT_NOT_DERIVED, GateOutcome, decide


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _forged_empty_set() -> ObligationSet:
    s = object.__new__(ObligationSet)
    object.__setattr__(s, "obligations", ())
    object.__setattr__(s, "evidence", ())
    return s


def _env(tmp_path: Path, monkeypatch, *, empty: bool):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
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

    host = LocalHostState(tmp_path / "state")
    git_read = HardenedGitRead()
    snaps = LocalSnapshotService(git_read)
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)
    base = snaps.seal_base(repo)
    post = snaps.reconstruct_post(base, patch)
    ident = capture_target_identity(repo)

    if empty:
        obls = _forged_empty_set()
        # scope DISCHARGED and one consumption entry present, so no later guard can produce the same refusal (review weak mutant)
        req, dis, cons = RequiredScope(("callable:m.f",)), ScopeDischarge((("callable:m.f", "o1"),)), None
    else:
        prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
        ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
        obls = ObligationSet((Obligation("o1", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True),))
        req, dis = RequiredScope(("callable:m.f",)), ScopeDischarge((("callable:m.f", "o1"),))
        cons = None
    account_sha = sha256_hex(hashlib.sha256(b"account:m.f").hexdigest())
    if cons is None:
        cons = (AccountConsumption(obligation_id="o1", account_sha256=account_sha),)
    unsigned = VerificationRecord(
        run_id=new_run_id(), base_tree_oid=base.tree_oid, patch_sha256=sha256_hex(hashlib.sha256(patch).hexdigest()),
        post_tree_oid=post.tree_oid, account_sha256=account_sha, target=ident,
        required_scope_digest=req.digest, scope_discharge_digest=dis.digest,
        obligation_set_sha256=obligation_set_digest(obls), consumption=cons,
        context_identity_sha256=sha256_hex("c" * 64), checker_ids=("checker",), issuer=verifier.issuer_id,
    )
    verified = VerifiedEffect(obligations=obls, record=verifier.issue(unsigned), required_scope=req, scope_discharge=dis)
    return repo, patch, gate, verifier, ident, verified


def test_gate_refuses_a_validly_signed_empty_obligation_set_and_lands_nothing(tmp_path, monkeypatch):
    repo, patch, gate, verifier, ident, verified = _env(tmp_path, monkeypatch, empty=True)
    assert verified.obligations.obligations == ()
    assert verifier.verify(verified.record)  # the record is genuine: the refusal is the gate's own empty-set guard
    head, tree = _git(repo, "rev-parse", "HEAD"), _git(repo, "rev-parse", "HEAD^{tree}")
    r = gate.land(repo, patch, verified, verifier, ident)
    assert r.outcome == "refused" and r.exit_status == EXIT_BOUNDARY, r
    assert tuple(r.blocking) == (BoundaryReason.SCOPE_UNDISCHARGED.value,) and r.landed_commit is None, r
    assert _git(repo, "rev-parse", "HEAD") == head and _git(repo, "rev-parse", "HEAD^{tree}") == tree
    assert _git(repo, "status", "--porcelain") == "" and (repo / "m.py").read_text() == "def f(x):\n    return x\n"


def test_decide_never_lands_an_empty_set_even_though_all_of_nothing_is_true():
    d = decide(_forged_empty_set())
    assert d.outcome is GateOutcome.REFUSED and d.exit_status == EXIT_NOT_DERIVED == 11, d
    assert d.blocking == ("no-account-bound-obligation",) and d.landed_commit is None


def test_control_nonempty_all_held_account_bound_set_lands_through_the_same_gate(tmp_path, monkeypatch):
    repo, patch, gate, verifier, ident, verified = _env(tmp_path, monkeypatch, empty=False)
    r = gate.land(repo, patch, verified, verifier, ident)
    assert r.outcome == "landed" and r.exit_status == EXIT_LANDED and r.landed_commit, r
    assert (repo / "m.py").read_text() == "def f(x):\n    return x + 1\n"
