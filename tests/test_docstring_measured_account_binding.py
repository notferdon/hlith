# SPDX-License-Identifier: Apache-2.0
"""Regression checks for measured docstring scope and fail-closed unresolved facts."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith import derive
from hlith.contract.capabilities import VerifiedEffect
from hlith.contract.errors import EXIT_NOT_DERIVED
from hlith.contract.effects import EffectAccount, ModifiedSymbol
from hlith.contract.identities import RunId, Sha256, TreeOid, new_run_id, sha256_hex
from hlith.contract.legacy import Obligation, Verdict
from hlith.contract.obligations import (
    AccountConsumption, RequiredScope, ScopeDischarge, VerificationRecord, obligation_set_digest,
)
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.consumption import bind
from hlith.types import BoundedEvidence, CheckProvenance, GateOutcome, ObligationSet, decide


REAL_EXIT4 = Path(__file__).parent / "operator" / "tui" / "fixtures" / "real_gate_refusal_exit4.json"
REAL_EXIT4_SHA256 = "592846ce01f52c9ab6a257e835491448c3944a16cacf69f545ce445d9a40e237"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True,
    ).stdout.strip()


def test_real_exit4_docstring_measurement_without_account_file_identity_stays_unbound():
    raw_bytes = REAL_EXIT4.read_bytes()
    assert hashlib.sha256(raw_bytes).hexdigest() == REAL_EXIT4_SHA256
    artifact = json.loads(raw_bytes)
    assert artifact["outcome"] == "refused"
    assert artifact["exit_status"] == 4
    assert artifact["blocking"] == ["required-scope-undischarged"]

    source = artifact["effect_account"]
    measured = next(o for o in artifact["obligations"] if o["id"] == "docstring-measured:m.py")
    account = EffectAccount(
        run_id=RunId(source["run_id"]),
        base_tree_oid=TreeOid(source["base_tree_oid"]),
        patch_sha256=Sha256(source["patch_sha256"]),
        post_tree_oid=TreeOid(source["post_tree_oid"]),
        analyzer_id=source["analyzer_id"],
        modified_callables=tuple(source["modified_callables"]),
    )
    # The gate's consumption binder is verdict-agnostic; use NOT_DERIVED here because the captured JSON omits
    # checker provenance. The test pins only the real artifact's obligation identity/target and account fields.
    obligation = Obligation(
        obligation_id=measured["id"],
        target_symbol=measured["target_symbol"],
        claim=measured["claim"],
        verdict=Verdict.NOT_DERIVED,
        stop_reason="identity-only reconstruction from the captured refusal artifact",
    )

    rebound, records = bind((obligation,), account)

    # The contract artifact lists m.f, but not its source path. A module-name prefix is not file identity.
    assert not rebound[0].account_bound
    assert records == ()


def _account_with_callable(name: str = "m.f") -> EffectAccount:
    return EffectAccount(
        run_id=RunId("run-111111111111"),
        base_tree_oid=TreeOid("0" * 40),
        patch_sha256=Sha256("a" * 64),
        post_tree_oid=TreeOid("1" * 40),
        analyzer_id="test",
        modified_callables=(name,),
    )


def _docstring_obligation(path: str = "m.py", target: str = "m") -> Obligation:
    return Obligation(
        obligation_id=f"docstring-measured:{path}",
        target_symbol=target,
        claim="docstring-only edit preserves module import state",
        verdict=Verdict.NOT_DERIVED,
        stop_reason="identity-only unit shape",
    )


def test_docstring_measurement_binds_only_to_an_exact_account_file_symbol():
    rebound, records = bind(
        (_docstring_obligation(),),
        _account_with_callable(),
        account_symbol_files=(("m.f", "./m.py"),),
    )

    assert rebound[0].account_bound
    assert len(records) == 1
    assert records[0].symbols == ("m.f",)


def test_docstring_measurement_binds_to_an_exact_modified_module_record():
    account = EffectAccount(
        run_id=RunId("run-222222222222"),
        base_tree_oid=TreeOid("0" * 40),
        patch_sha256=Sha256("c" * 64),
        post_tree_oid=TreeOid("1" * 40),
        analyzer_id="test",
        modified_constants=(ModifiedSymbol("m", "m.py", 1, "module_level"),),
    )

    rebound, records = bind((_docstring_obligation(),), account)

    assert rebound[0].account_bound
    assert len(records) == 1
    assert records[0].symbols == ("m",)


@pytest.mark.parametrize(
    ("symbol", "file_path", "obligation_path"),
    [("m2.f", "m2.py", "m.py"), ("m.f", "sub/m.py", "m.py"), ("m.f", "m.py", "../m.py")],
)
def test_docstring_measurement_does_not_bind_on_module_or_path_prefix(symbol, file_path, obligation_path):
    rebound, records = bind(
        (_docstring_obligation(path=obligation_path),),
        _account_with_callable(symbol),
        account_symbol_files=((symbol, file_path),),
    )

    assert not rebound[0].account_bound
    assert records == ()


def test_docstring_held_does_not_hide_an_unresolved_account_fact():
    held = Obligation(
        "docstring-measured:m.py",
        "m",
        "measured docstring behavior is preserved",
        Verdict.HELD,
        evidence=BoundedEvidence(1, "one unit observation", "external readers remain unexplored"),
        provenance=CheckProvenance("unit", "a" * 64, True, False, "b" * 64, 0),
        account_bound=True,
    )
    unresolved = Obligation(
        "unresolved-0",
        "m.f",
        "effect is derivable",
        Verdict.NOT_DERIVED,
        stop_reason="unresolved method receiver from the real refusal shape",
    )

    decision = decide(ObligationSet((held, unresolved)))

    assert decision.outcome is GateOutcome.REFUSED
    assert decision.exit_status == 11
    assert decision.blocking == ("unresolved-0",)


def test_docstring_only_unresolved_reaches_gate_before_scope_refusal(monkeypatch, tmp_path):
    base = tmp_path / "base"
    post = tmp_path / "post"
    base.mkdir()
    post.mkdir()
    before = 'def f():\n    """before"""\n    return 1\n'
    after = 'def f():\n    """after"""\n    return 1\n'
    (base / "mod.py").write_text(before)
    (post / "mod.py").write_text(after)

    held_evidence = BoundedEvidence(1, "one measured unit observation", "external readers remain unexplored")
    held_provenance = CheckProvenance("unit", "a" * 64, True, False, "b" * 64, 0)
    measured = Obligation(
        "docstring-measured:mod.py",
        "mod",
        "measured docstring behavior is preserved",
        Verdict.HELD,
        evidence=held_evidence,
        provenance=held_provenance,
        account_bound=True,
    )

    monkeypatch.setattr(
        derive.docstring_check,
        "verify_docstring_only_diff",
        lambda *args, **kwargs: SimpleNamespace(obligations=(measured,), allow_skip_unrelated=True, static_clear={}),
    )
    checked_functions: list[str] = []

    def _differential(**kwargs):
        checked_functions.append(kwargs["function"])
        return Obligation(
            "differential:mod.f",
            "mod.f",
            "unchanged callable behavior agrees",
            Verdict.HELD,
            evidence=held_evidence,
            provenance=held_provenance,
            account_bound=True,
        )

    monkeypatch.setattr(derive.differential, "run_differential", _differential)
    unresolved = SimpleNamespace(
        side="post",
        kind="dynamic_call",
        source="dynamic call target",
        file_path="mod.py",
        line_number=4,
        caller_qualified_name="mod.f",
    )
    account = SimpleNamespace(
        unresolved_constructs=(unresolved,),
        modified_callables=(),
        impacted_test_nodes=(),
        side_effect_primitive_delta=(),
    )
    core = derive.make_derive(proposer_paths=()).core

    result = core(
        touched_files=("mod.py",),
        deltas=(),
        acct=account,
        ad={"modified_callables": []},
        fbk=None,
        base_dir=base,
        post_dir=post,
        has_diff=True,
    )

    unresolved_obligations = [o for o in result.obligations if o.obligation_id.startswith("unresolved-")]
    assert len(unresolved_obligations) == 1
    assert unresolved_obligations[0].verdict is Verdict.NOT_DERIVED
    assert checked_functions == ["f"], "docstring-only must retain differential checks for AST-identical callables"

    # Exercise the actual gate with a valid signed record and an intentionally undischarged scope.
    # If docstring-only suppresses the unresolved fact, the two account-bound HELD obligations pass
    # decide(), and this same gate returns boundary exit 4 from the later scope check. The correct
    # unresolved NOT_DERIVED obligation must instead refuse first with exit 11.
    repo = tmp_path / "gate-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "test")
    (repo / "mod.py").write_text(before)
    _git(repo, "add", "mod.py")
    _git(repo, "commit", "-qm", "base")
    (repo / "mod.py").write_text(after)
    patch = subprocess.run(
        ["git", "-C", str(repo), "diff", "--binary"], capture_output=True, check=True,
    ).stdout
    assert patch
    _git(repo, "checkout", "--", "mod.py")

    state_dir = tmp_path / "gate-state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(state_dir))
    host = LocalHostState(state_dir)
    git_read = HardenedGitRead()
    snapshots = LocalSnapshotService(git_read)
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snapshots)
    sealed_base = snapshots.seal_base(repo)
    sealed_post = snapshots.reconstruct_post(sealed_base, patch)
    identity = capture_target_identity(repo)
    required = RequiredScope(("callable:mod.f",))
    discharge = ScopeDischarge(())
    account_sha = Sha256("c" * 64)
    consumption = tuple(
        AccountConsumption(obligation_id=o.obligation_id, account_sha256=account_sha)
        for o in result.obligations if o.verdict is Verdict.HELD
    )
    record = VerificationRecord(
        run_id=new_run_id(),
        base_tree_oid=sealed_base.tree_oid,
        patch_sha256=sha256_hex(hashlib.sha256(patch).hexdigest()),
        post_tree_oid=sealed_post.tree_oid,
        account_sha256=account_sha,
        target=identity,
        required_scope_digest=required.digest,
        scope_discharge_digest=discharge.digest,
        obligation_set_sha256=obligation_set_digest(result),
        consumption=consumption,
        context_identity_sha256=sha256_hex("d" * 64),
        checker_ids=("unit",),
        issuer=verifier.issuer_id,
    )
    verified = VerifiedEffect(
        obligations=result,
        record=verifier.issue(record),
        required_scope=required,
        scope_discharge=discharge,
    )
    original_head = _git(repo, "rev-parse", "HEAD")
    original_tree = _git(repo, "rev-parse", "HEAD^{tree}")

    receipt = gate.land(repo, patch, verified, verifier, identity)

    assert receipt.outcome == "refused"
    assert receipt.exit_status == EXIT_NOT_DERIVED == 11, receipt
    assert receipt.blocking == ("unresolved-0",), receipt
    assert receipt.landed_commit is None
    assert _git(repo, "rev-parse", "HEAD") == original_head
    assert _git(repo, "rev-parse", "HEAD^{tree}") == original_tree
    assert _git(repo, "status", "--porcelain") == ""
