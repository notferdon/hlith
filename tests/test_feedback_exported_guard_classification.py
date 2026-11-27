# SPDX-License-Identifier: Apache-2.0
"""Targeted tests for provenance-bound exported-guard classification in Layer 5 feedback.

Verifies:
1. Classification relies strictly on L3's verified HELD exported-guard obligation + AccountConsumption + ScopeDischarge
   provenance (never on path/name substrings and never by suppressing missing-module-file errors).
2. Provenance-bound exported guards are excluded from base-tree production probing and disclosed on the named
   ``feedback_limit`` channel (with ``drain_errors()`` preserving ``_last_limits`` for ``drain_limits()``).
3. Genuine missing production modules and unauthenticated added test files still produce visible ``missing-module-file``
   errors in ``feedback_errors`` / ``LANDED · FEEDBACK FAILED``.
4. Real no-intermediate-commit CLI workflow (buggy -> REFUTED -> ``--expect pre`` export -> fix without commit -> LANDED
   with empty ``feedback_errors`` and named ``feedback_limit`` -> subsequent run loads & causally consumes Run 2's written
   production domain record).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from hlith.contract.capabilities import SealedSnapshot, VerifiedEffect
from hlith.contract.effects import EffectAccount
from hlith.contract.errors import EXIT_LANDED
from hlith.contract.identities import InvocationId, RunId, Sha256, TreeOid
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.contract.obligations import AccountConsumption, RequiredScope, ScopeDischarge, VerificationRecord
from hlith.contract.runs import GateReceipt, LandingTarget, RunMode
from hlith.feedback import LandingProbeContext, LocalFeedbackService, register_probe_bridge
from hlith.feedback.probe import run_landing_probes
from hlith.hostio.state import LocalHostState
from hlith.operator.coordinator import Coordinator, RunRequest
from hlith.operator.pipeline import (
    PipelineCapabilities,
    PipelineRequest,
    _exported_guard_callables,
    run_pipeline,
)
from hlith import obligation as _obligation

SRC = Path(__file__).resolve().parents[1] / "src"

_RUN_ID = RunId("run-123456789abc")
_TREE0 = TreeOid("0" * 40)
_TREE1 = TreeOid("1" * 40)
_SHA = Sha256("a" * 64)
_GUARD_SYM = "tests.test_hlith_guard.test_recorded_pre_behavior"
_GUARD_OB_ID = "exported-guard:tests/test_hlith_guard.py:demo.calc.validate"

BASE_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x <= 0:\n"
    "        raise ValueError('must be positive')\n"
    "    return x\n"
)

BUGGY_CALC = (
    "def validate(x: int) -> int:\n"
    "    return x\n"
)

FIXED_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x <= 0:\n"
    "        raise ValueError('must be positive')\n"
    "    normalized = x\n"
    "    return normalized\n"
)

WIDE_BUG_CALC = (
    "def validate(x: int) -> int:\n"
    "    if x <= 0:\n"
    "        raise ValueError('must be positive')\n"
    "    return x % (1 << 1000)\n"
)

BASE_TEST = (
    "from demo.calc import validate\n"
    "\n"
    "\n"
    "def test_validate_positive():\n"
    "    assert validate(5) == 5\n"
)


def _prov(
    *,
    checker_id: str = "hlith.obligation.exported_guard",
    confined: bool = True,
    proposer_paths_readable: bool = False,
    exit_code: int = 0,
) -> CheckProvenance:
    return CheckProvenance(
        checker_id=checker_id,
        checker_sha256="c" * 64,
        confined=confined,
        proposer_paths_readable=proposer_paths_readable,
        profile_sha256="d" * 64,
        exit_code=exit_code,
    )


def _make_account(
    *,
    modified: tuple[str, ...] = ("demo.calc.validate",),
    added: tuple[str, ...] = (_GUARD_SYM,),
    removed: tuple[str, ...] = (),
    added_reached_from: tuple[tuple[str, str], ...] = (),
) -> EffectAccount:
    return EffectAccount(
        run_id=_RUN_ID,
        base_tree_oid=_TREE0,
        post_tree_oid=_TREE1,
        patch_sha256=_SHA,
        analyzer_id="test",
        modified_callables=modified,
        added_callables=added,
        removed_callables=removed,
        added_reached_from=added_reached_from,
    )


def _make_verified(
    account: EffectAccount,
    *,
    ob_id: str = _GUARD_OB_ID,
    target_symbol: str = _GUARD_SYM,
    verdict: Verdict = Verdict.HELD,
    account_bound: bool = True,
    provenance: CheckProvenance | None = None,
    consumption: tuple[AccountConsumption, ...] | None = None,
    scope_discharge: ScopeDischarge | None = None,
    include_discharge: bool = True,
    raw_obligation: object | None = None,
) -> VerifiedEffect:
    if raw_obligation is not None:
        ob = raw_obligation
    else:
        stop_reason = (
            "guard did not hold"
            if verdict in (Verdict.UNVERIFIED, Verdict.NOT_DERIVED)
            else None
        )
        ob = Obligation(
            obligation_id=ob_id,
            target_symbol=target_symbol,
            claim="exported pre-guard holds",
            verdict=verdict,
            evidence=BoundedEvidence(executions=2, explored="base=passed; post=passed", unexplored="single call"),
            provenance=provenance if provenance is not None else _prov(),
            stop_reason=stop_reason,
            account_bound=account_bound,
        )
    cons = (
        consumption
        if consumption is not None
        else (AccountConsumption(ob_id, account.account_sha256, (target_symbol,), ()),)
    )
    rec = VerificationRecord(
        run_id=account.run_id,
        base_tree_oid=account.base_tree_oid,
        patch_sha256=account.patch_sha256,
        post_tree_oid=account.post_tree_oid,
        account_sha256=account.account_sha256,
        target="target-id",
        required_scope_digest=_SHA,
        scope_discharge_digest=_SHA,
        obligation_set_sha256=_SHA,
        consumption=cons,
        context_identity_sha256=_SHA,
        checker_ids=("hlith.obligation.exported_guard",),
        issuer="test",
        mac="m",
    )
    if include_discharge and scope_discharge is None:
        scope_discharge = ScopeDischarge(entries=((f"callable:{target_symbol}", ob_id),))
    oset = SimpleNamespace(obligations=(ob,)) if raw_obligation is not None else ObligationSet(obligations=(ob,))
    return VerifiedEffect(
        obligations=oset,
        record=rec,
        required_scope=RequiredScope.from_account(account),
        scope_discharge=scope_discharge if include_discharge else None,
    )


def test_exported_guard_classification_requires_full_verified_provenance() -> None:
    acct = _make_account()
    # Positive: HELD, account-bound, confined exported-guard checker, matching AccountConsumption & ScopeDischarge.
    assert _exported_guard_callables(acct, _make_verified(acct)) == (_GUARD_SYM,)

    # Negative controls: none of these may be classified by name/path heuristic.
    assert _exported_guard_callables(acct, None) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, ob_id=f"signature_binding:{_GUARD_SYM}")) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, verdict=Verdict.UNVERIFIED)) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, verdict=Verdict.NOT_DERIVED)) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, account_bound=False)) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, provenance=_prov(checker_id="other.checker"))) == ()
    unconfined_ob = SimpleNamespace(
        obligation_id=_GUARD_OB_ID,
        target_symbol=_GUARD_SYM,
        verdict=Verdict.HELD,
        account_bound=True,
        provenance=_prov(confined=False),
    )
    assert _exported_guard_callables(acct, _make_verified(acct, raw_obligation=unconfined_ob)) == ()
    unblind_ob = SimpleNamespace(
        obligation_id=_GUARD_OB_ID,
        target_symbol=_GUARD_SYM,
        verdict=Verdict.HELD,
        account_bound=True,
        provenance=_prov(proposer_paths_readable=True),
    )
    assert _exported_guard_callables(acct, _make_verified(acct, raw_obligation=unblind_ob)) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, consumption=())) == ()
    wrong_acct_cons = (AccountConsumption(_GUARD_OB_ID, Sha256("f" * 64), (_GUARD_SYM,), ()),)
    assert _exported_guard_callables(acct, _make_verified(acct, consumption=wrong_acct_cons)) == ()
    wrong_sym_cons = (AccountConsumption(_GUARD_OB_ID, acct.account_sha256, ("demo.calc.validate",), ()),)
    assert _exported_guard_callables(acct, _make_verified(acct, consumption=wrong_sym_cons)) == ()
    assert _exported_guard_callables(acct, _make_verified(acct, include_discharge=False)) == ()
    wrong_discharge = ScopeDischarge(entries=((f"callable:{_GUARD_SYM}", f"signature_binding:{_GUARD_SYM}"),))
    assert _exported_guard_callables(acct, _make_verified(acct, scope_discharge=wrong_discharge)) == ()

    # Production or reached callables are never classified as excluded exported guards.
    mod_acct = _make_account(modified=("demo.calc.validate", _GUARD_SYM), added=(_GUARD_SYM,))
    assert _exported_guard_callables(mod_acct, _make_verified(mod_acct)) == ()
    rem_acct = _make_account(removed=(_GUARD_SYM,), added=(_GUARD_SYM,))
    assert _exported_guard_callables(rem_acct, _make_verified(rem_acct)) == ()
    reached_acct = _make_account(added_reached_from=((_GUARD_SYM, "demo.calc.validate"),))
    assert _exported_guard_callables(reached_acct, _make_verified(reached_acct)) == ()


def _write_demo_trees(tmp_path: Path) -> tuple[Path, Path]:
    base_tree = tmp_path / "base"
    landed_tree = tmp_path / "landed"
    for tree, calc_src in ((base_tree, BASE_CALC), (landed_tree, FIXED_CALC)):
        (tree / "demo").mkdir(parents=True)
        (tree / "demo" / "__init__.py").write_text("", encoding="utf-8")
        (tree / "demo" / "calc.py").write_text(calc_src, encoding="utf-8")
        (tree / "tests").mkdir(parents=True)
        (tree / "tests" / "test_calc.py").write_text(BASE_TEST, encoding="utf-8")
    # Added guard file exists ONLY in landed_tree, absent from base_tree.
    (landed_tree / "tests" / "test_hlith_guard.py").write_text(
        "from demo.calc import validate\n\n\ndef test_recorded_pre_behavior():\n    assert validate(1) == 1\n",
        encoding="utf-8",
    )
    return base_tree, landed_tree


def _landed_receipt() -> GateReceipt:
    return GateReceipt(
        run_id=_RUN_ID,
        outcome="landed",
        exit_status=EXIT_LANDED,
        blocking=(),
        landed_commit="b" * 40,
        verification_record_sha256=_SHA,
    )


def test_landing_probe_excludes_provenance_guard_discloses_limit_and_keeps_missing_prod_errors(tmp_path: Path) -> None:
    register_probe_bridge(**_obligation.probe_bridge())
    base_tree, landed_tree = _write_demo_trees(tmp_path)
    base_snap = SealedSnapshot(tree_oid=_TREE0, path=base_tree)
    landed_snap = SealedSnapshot(tree_oid=_TREE1, path=landed_tree)
    receipt = _landed_receipt()

    # 1) Excluded provenance-bound guard: production symbol probed & written, zero errors, named limit survives drain_errors().
    svc = LocalFeedbackService(LocalHostState(tmp_path / "state1"), observe_kw={"python": sys.executable})
    svc.register_landing_context(
        receipt.run_id,
        LandingProbeContext(
            repo_identity="repo-guard-1",
            base=base_snap,
            symbols=("demo.calc.validate",),
            excluded_guard_symbols=(_GUARD_SYM,),
        ),
    )
    written = svc.post_landing_probe(receipt, landed_snap)
    assert len(written) >= 1, "production target must still write feedback records"
    assert svc.drain_errors() == ()
    limits = svc.drain_limits()
    assert any(_GUARD_SYM in m and "UNPROBED by Layer 5" in m and "exported-guard" in m for m in limits), limits

    # 2) Defense in depth: direct run_landing_probes with guard symbol in both symbols and excluded_guard_symbols.
    errs2: list[str] = []
    lims2: list[str] = []
    written2 = run_landing_probes(
        tmp_path / "store2",
        receipt,
        base_snap,
        landed_snap,
        symbols=("demo.calc.validate", _GUARD_SYM),
        excluded_guard_symbols=(_GUARD_SYM,),
        observe_kw={"python": sys.executable},
        errors=errs2,
        limits=lims2,
    )
    assert len(written2) >= 1
    assert errs2 == []
    assert any(_GUARD_SYM in m and "UNPROBED by Layer 5" in m for m in lims2), lims2

    # 3) Negative control: genuine missing production module STILL fails visibly with missing-module-file.
    svc3 = LocalFeedbackService(LocalHostState(tmp_path / "state3"), observe_kw={"python": sys.executable})
    svc3.register_landing_context(
        receipt.run_id,
        LandingProbeContext(
            repo_identity="repo-guard-3",
            base=base_snap,
            symbols=("demo.calc.validate", "missing_prod_pkg.mod.fn"),
            excluded_guard_symbols=(_GUARD_SYM,),
        ),
    )
    written3 = svc3.post_landing_probe(receipt, landed_snap)
    assert len(written3) >= 1, "real production symbol must still persist despite sibling missing-module error"
    errs3 = svc3.drain_errors()
    assert any("missing-module-file: missing_prod_pkg.mod.fn" in e for e in errs3), errs3
    assert not any(_GUARD_SYM in e for e in errs3), errs3
    lims3 = svc3.drain_limits()
    assert any(_GUARD_SYM in m and "UNPROBED by Layer 5" in m for m in lims3), lims3

    # 4) Negative control: unauthenticated guard-named symbol NOT in excluded_guard_symbols still emits missing-module-file.
    svc4 = LocalFeedbackService(LocalHostState(tmp_path / "state4"), observe_kw={"python": sys.executable})
    svc4.register_landing_context(
        receipt.run_id,
        LandingProbeContext(
            repo_identity="repo-guard-4",
            base=base_snap,
            symbols=(_GUARD_SYM,),
            excluded_guard_symbols=(),
        ),
    )
    svc4.post_landing_probe(receipt, landed_snap)
    errs4 = svc4.drain_errors()
    assert any(f"missing-module-file: {_GUARD_SYM}" in e for e in errs4), errs4


def test_pipeline_wires_excluded_guard_symbols_and_preserves_real_missing_prod_error(tmp_path: Path) -> None:
    register_probe_bridge(**_obligation.probe_bridge())
    base_tree, landed_tree = _write_demo_trees(tmp_path)

    class _Snap:
        def seal_base(self, target: Path) -> SealedSnapshot:
            return SealedSnapshot(tree_oid=_TREE0, path=base_tree if target == tmp_path else landed_tree)

        def reconstruct_post(self, base: SealedSnapshot, patch: bytes) -> SealedSnapshot:
            return SealedSnapshot(tree_oid=_TREE1, path=landed_tree)

    class _Host:
        def stable_repo_identity(self, target: Path) -> str:
            return "repo-pipe-test"

    class _Effect:
        def __init__(self, modified: tuple[str, ...]):
            self._modified = modified

        def build_account(self, run_id: RunId, base: SealedSnapshot, post: SealedSnapshot, patch: bytes) -> EffectAccount:
            return EffectAccount(
                run_id=run_id,
                base_tree_oid=base.tree_oid,
                post_tree_oid=post.tree_oid,
                patch_sha256=Sha256(hashlib.sha256(patch).hexdigest()),
                analyzer_id="test",
                modified_callables=self._modified,
                added_callables=(_GUARD_SYM,),
            )

    class _Ob:
        def verify(self, account, fb, base, post, target, *, intent=None, guard_catalog=None, progress=None):
            return _make_verified(account)

    class _Gate:
        def land(self, target, patch, verified, verifier, target_identity, *, expected_run_id=None):
            return GateReceipt(
                run_id=verified.record.run_id,
                outcome="landed",
                exit_status=EXIT_LANDED,
                blocking=(),
                landed_commit="c" * 40,
                verification_record_sha256=_SHA,
            )

    def _run_case(name: str, modified: tuple[str, ...]):
        fb = LocalFeedbackService(LocalHostState(tmp_path / f"st-{name}"), observe_kw={"python": sys.executable})
        caps = PipelineCapabilities(
            snapshot_service=_Snap(),
            host_state=_Host(),
            effect_api=_Effect(modified),
            obligation_api=_Ob(),
            gate_api=_Gate(),
            verifier=object(),
            feedback_api=fb,
        )
        req = PipelineRequest(
            target=tmp_path,
            invocation_id=InvocationId(f"inv-{name}"),
            mode=RunMode.HEADLESS,
            landing_target=LandingTarget.REHEARSAL,
            target_identity="target-id",
            external_patch=b"diff",
        )
        return run_pipeline(req, caps)

    # Clean guard + real production target -> zero feedback_errors, named feedback_limit emitted, records written.
    ok_res = _run_case("clean", ("demo.calc.validate",))
    ok_art = Coordinator._artifact(
        ok_res.run_receipt,
        RunRequest(repo=tmp_path, mode=RunMode.HEADLESS, landing_target=LandingTarget.REHEARSAL),
        ok_res,
    )
    assert ok_art["feedback_errors"] == []
    assert len(ok_art["feedback"]["written_feedback_ids"]) >= 1
    ok_limits = [e.detail["feedback_limit"] for e in ok_res.events if "feedback_limit" in e.detail]
    assert any(_GUARD_SYM in m and "UNPROBED by Layer 5" in m for m in ok_limits), ok_limits

    # Genuine missing production module alongside guard -> visible missing-module-file in feedback_errors.
    miss_res = _run_case("missing-prod", ("demo.calc.validate", "ghost_pkg.mod.fn"))
    miss_art = Coordinator._artifact(
        miss_res.run_receipt,
        RunRequest(repo=tmp_path, mode=RunMode.HEADLESS, landing_target=LandingTarget.REHEARSAL),
        miss_res,
    )
    assert any("missing-module-file: ghost_pkg.mod.fn" in e for e in miss_art["feedback_errors"]), miss_art["feedback_errors"]
    assert not any(_GUARD_SYM in e for e in miss_art["feedback_errors"]), miss_art["feedback_errors"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _repo_fingerprint(repo: Path) -> str:
    h = hashlib.sha256()
    for args in (("rev-parse", "HEAD"), ("status", "--porcelain", "-uall"), ("diff",)):
        h.update(_git(repo, *args).encode("utf-8"))
    for p in sorted(repo.rglob("*")):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(repo).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def _run_cli(args: list[str], *, env: dict[str, str], cwd: Path) -> tuple[int, dict, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        timeout=180,
    )
    payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return proc.returncode, payload, proc.stderr


def test_real_no_intermediate_commit_smoke_and_cross_run_lineage(tmp_path: Path) -> None:
    """End-to-end CLI proof:
    Run 1 (buggy) -> REFUTED (10), refusal pin persisted.
    Export exact --expect pre guard into tests/test_hlith_guard.py.
    Run 2 (fixed, NO intermediate commit) -> LANDED (0), headline == 'LANDED', feedback_errors == [],
      exported-guard & signature_binding HELD, named feedback_limit disclosed, production domain record written,
      original repo untouched.
    Run 3 (large-int regression in same HLITH_STATE_DIR) -> loads Run 2's written feedback record (lineage verified)
      and REFUTES (10) causally on demo.calc.validate.
    """
    repo = tmp_path / "repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "demo" / "calc.py").write_text(BASE_CALC, encoding="utf-8")
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "test_calc.py").write_text(BASE_TEST, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")

    state_dir = tmp_path / "state"
    ui_dir = tmp_path / "ui"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HLITH_STATE_DIR"] = str(state_dir)
    env["HLITH_UI_STATE"] = str(ui_dir)

    # Run 1: buggy edit -> REFUTED, refusal feedback persisted.
    (repo / "demo" / "calc.py").write_text(BUGGY_CALC, encoding="utf-8")
    rc1, r1, err1 = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert rc1 == 10, (rc1, err1, r1)
    run1_id = r1["check"]["run_id"]
    run1_written = list(r1["artifact"]["feedback"]["written_feedback_ids"])
    assert run1_written, f"Run 1 must persist refusal pin feedback: {r1['artifact'].get('feedback')}"

    # Export exact --expect pre guard into tests/test_hlith_guard.py.
    guard_path = repo / "tests" / "test_hlith_guard.py"
    rep_rc, rep_json, rep_err = _run_cli(
        [
            "replay",
            run1_id,
            "--repo",
            str(repo),
            "--json",
            "--pytest-out",
            str(guard_path),
            "--expect",
            "pre",
        ],
        env=env,
        cwd=repo,
    )
    assert rep_rc == 0 and rep_json["status"] == "REPRODUCED" and rep_json["pytest_export"]["status"] == "written", (
        rep_rc,
        rep_err,
        rep_json,
    )

    # Run 2: fix production code WITHOUT intermediate commit -> LANDED, zero feedback_errors, clean headline.
    (repo / "demo" / "calc.py").write_text(FIXED_CALC, encoding="utf-8")
    fp_before = _repo_fingerprint(repo)
    rc2, r2, err2 = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert _repo_fingerprint(repo) == fp_before, "original repository must remain untouched"
    assert rc2 == 0, (rc2, err2, r2)
    assert r2["check"]["headline"] == "LANDED", r2["check"]
    art2 = r2["artifact"]
    assert art2["feedback_errors"] == [], art2["feedback_errors"]
    obs2 = {o["id"]: o for o in art2["obligations"]}
    assert obs2[_GUARD_OB_ID]["verdict"] == "held"
    assert obs2[f"signature_binding:{_GUARD_SYM}"]["verdict"] == "held"
    assert not any(o["verdict"] == "refuted" for o in art2["obligations"])

    run2_id = r2["check"]["run_id"]
    fb2 = art2["feedback"]
    assert set(run1_written) & set(fb2["loaded_feedback_ids"]), fb2
    for fid in set(run1_written) & set(fb2["loaded_feedback_ids"]):
        assert fb2["loaded_source_runs"][fid] == run1_id
    run2_written = list(fb2["written_feedback_ids"])
    assert run2_written, f"Run 2 must write production domain feedback record: {fb2}"

    # Verify inspect exposes clean LANDED + named feedback_limit disclosure for the guard.
    insp_rc, insp2, insp_err = _run_cli(
        ["inspect", run2_id, "--repo", str(repo), "--json"],
        env=env,
        cwd=repo,
    )
    assert insp_rc == 0, (insp_rc, insp_err, insp2)
    assert insp2["headline"] == "LANDED", insp2
    limit_msgs = [e["feedback_limit"] for e in insp2["feedback_limit_events"]]
    assert any(_GUARD_SYM in m and "UNPROBED by Layer 5" in m and "exported-guard" in m for m in limit_msgs), limit_msgs

    # Verify Run 2's written feedback record on disk targets demo.calc.validate (never the guard).
    stored_by_id = {}
    for p in state_dir.rglob("fb-*.json"):
        data = json.loads(p.read_text(encoding="utf-8"))
        rec = data.get("record") or data
        stored_by_id[rec["feedback_id"]] = rec
    for fid in run2_written:
        assert fid in stored_by_id
        assert stored_by_id[fid]["target_symbols"] == ["demo.calc.validate"]
        assert stored_by_id[fid]["source_run_id"] == run2_id

    # Run 3: subsequent check in same HLITH_STATE_DIR with large-int regression -> loads & causally consumes Run 2's record.
    (repo / "demo" / "calc.py").write_text(WIDE_BUG_CALC, encoding="utf-8")
    fp_before_3 = _repo_fingerprint(repo)
    rc3, r3, err3 = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=env,
        cwd=repo,
    )
    assert _repo_fingerprint(repo) == fp_before_3
    assert rc3 == 10, (rc3, err3, r3)
    fb3 = r3["artifact"]["feedback"]
    assert set(run2_written) & set(fb3["loaded_feedback_ids"]), fb3
    for fid in set(run2_written) & set(fb3["loaded_feedback_ids"]):
        assert fb3["loaded_source_runs"][fid] == run2_id
    obs3 = {o["id"]: o for o in r3["artifact"]["obligations"]}
    assert obs3["differential:demo.calc.validate"]["verdict"] == "refuted"
    assert obs3[_GUARD_OB_ID]["verdict"] != "refuted"
