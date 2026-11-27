# SPDX-License-Identifier: Apache-2.0
"""case (O3 guard scope discharge): added/changed unsupported entry guards require explicit HELD guard-covered.

Guards covered: src/hlith/obligation/scope.py must never discharge ``guard:{file}:{line}:{q}`` for an unsupported
added/changed entry guard via vacuous ``all(guard-* HELD)`` when no ``guard-covered:{q}:{file}:{line}`` obligation
exists or holds. Paired with contract/obligations.py's suppression of duplicate ``unknown:`` items only when an added
EntryGuard is present."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from hlith.cli import main as cli_main
from hlith.contract.effects import EffectAccount, EntryGuard, GapCode, Unknown
from hlith.contract.identities import Sha256, TreeOid, new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.contract.obligations import AccountConsumption, RequiredScope, scope_fully_discharged
from hlith.obligation import scope

_EVIDENCE = BoundedEvidence(executions=1, explored="synthetic unit input", unexplored="other inputs")
_PROVENANCE = CheckProvenance(
    checker_id="test",
    checker_sha256="a" * 64,
    confined=True,
    proposer_paths_readable=False,
    profile_sha256="b" * 64,
    exit_code=0,
)


def _held(oid: str, target: str = "m.f", claim: str = "held") -> Obligation:
    return Obligation(oid, target, claim, Verdict.HELD, evidence=_EVIDENCE, provenance=_PROVENANCE, account_bound=True)


def _account(*, with_unsupported_unknown: bool = True, change: str = "added") -> EffectAccount:
    unknowns = (
        (
            Unknown(
                GapCode.UNSUPPORTED_ENTRY_GUARD,
                "m.py:2",
                "unsupported_entry_guard [post] m.f: '\\\\0' in s",
            ),
        )
        if with_unsupported_unknown
        else ()
    )
    return EffectAccount(
        run_id=new_run_id(),
        base_tree_oid=TreeOid("a" * 40),
        patch_sha256=Sha256("b" * 64),
        post_tree_oid=TreeOid("c" * 40),
        analyzer_id="test",
        modified_callables=("m.f",),
        guards=(EntryGuard("m.f", "m.py", 2, change, "'\\\\0' in s"),),
        unknowns=unknowns,
    )


def _base_held(acct: EffectAccount) -> tuple[list[Obligation], list[AccountConsumption]]:
    obs = [
        _held("signature_binding:m.f"),
        _held("differential:m.f"),
    ]
    cons = [
        AccountConsumption(o.obligation_id, acct.account_sha256, ("m.f",), ())
        for o in obs
    ]
    return obs, cons


def test_vacuity_falsifier_added_unsupported_guard_without_guard_covered_refuses_scope() -> None:
    """RED on 5432691f: vacuous all(guard-*) discharges guard:m.py:2:m.f even with zero guard-covered obligations."""
    acct = _account(with_unsupported_unknown=True, change="added")
    obs, cons = _base_held(acct)
    dis = scope.discharge(acct, obs, cons)
    entries = dict(dis.entries)
    assert "guard:m.py:2:m.f" not in entries
    req = RequiredScope(("callable:m.f", "guard:m.py:2:m.f"))
    assert scope_fully_discharged(req, dis) is False


def test_added_unsupported_guard_with_unrelated_or_nonheld_guard_obligation_stays_open() -> None:
    acct = _account(with_unsupported_unknown=True, change="added")
    obs, cons = _base_held(acct)
    # Unrelated guard-* HELD does not satisfy guard-covered:m.f:m.py:2
    obs_other = [*obs, _held("guard-unrelated:m.f", claim="other")]
    dis_other = scope.discharge(acct, obs_other, cons)
    assert "guard:m.py:2:m.f" not in dict(dis_other.entries)
    assert scope_fully_discharged(RequiredScope(("callable:m.f", "guard:m.py:2:m.f")), dis_other) is False

    # Non-HELD guard-covered cannot discharge scope
    obs_unv = [
        *obs,
        Obligation(
            "guard-covered:m.f:m.py:2",
            "m.f",
            "cover",
            Verdict.UNVERIFIED,
            stop_reason="delta not confirmed",
        ),
    ]
    dis_unv = scope.discharge(acct, obs_unv, cons)
    assert "guard:m.py:2:m.f" not in dict(dis_unv.entries)
    assert scope_fully_discharged(RequiredScope(("callable:m.f", "guard:m.py:2:m.f")), dis_unv) is False


def test_changed_unsupported_guard_also_requires_explicit_held_guard_covered() -> None:
    acct = _account(with_unsupported_unknown=True, change="changed")
    obs, cons = _base_held(acct)
    dis = scope.discharge(acct, obs, cons)
    assert "guard:m.py:2:m.f" not in dict(dis.entries)
    assert scope_fully_discharged(RequiredScope(("callable:m.f", "guard:m.py:2:m.f")), dis) is False


def test_added_unsupported_guard_discharges_with_cover_id_when_guard_covered_held() -> None:
    acct = _account(with_unsupported_unknown=True, change="added")
    obs, cons = _base_held(acct)
    cover_id = "guard-covered:m.f:m.py:2"
    obs.append(_held(cover_id, claim="cover"))
    cons.append(AccountConsumption(cover_id, acct.account_sha256, ("m.f",), ()))
    dis = scope.discharge(acct, obs, cons)
    entries = dict(dis.entries)
    assert entries.get("guard:m.py:2:m.f") == cover_id
    req = RequiredScope(("callable:m.f", "guard:m.py:2:m.f"))
    assert scope_fully_discharged(req, dis) is True


def test_supported_added_guard_still_discharges_without_guard_covered() -> None:
    acct = _account(with_unsupported_unknown=False, change="added")
    obs, cons = _base_held(acct)
    dis = scope.discharge(acct, obs, cons)
    entries = dict(dis.entries)
    assert entries.get("guard:m.py:2:m.f") == "differential:m.f"
    req = RequiredScope(("callable:m.f", "guard:m.py:2:m.f"))
    assert scope_fully_discharged(req, dis) is True


def test_unrelated_unknown_and_opaque_caller_guard_keep_unknown_scope_blocked() -> None:
    acct = EffectAccount(
        run_id=new_run_id(),
        base_tree_oid=TreeOid("a" * 40),
        patch_sha256=Sha256("b" * 64),
        post_tree_oid=TreeOid("c" * 40),
        analyzer_id="test",
        modified_callables=("m.f",),
        guards=(EntryGuard("m.f", "m.py", 2, "added", "'\\\\0' in s"),),
        unknowns=(
            Unknown(GapCode.UNSUPPORTED_ENTRY_GUARD, "caller.py:5", "opaque caller guard"),
            Unknown(GapCode.UNRESOLVED_CALL, "m.py:9", "unresolved call"),
        ),
    )
    obs, cons = _base_held(acct)
    dis = scope.discharge(acct, obs, cons)
    req = RequiredScope.from_account(acct)
    assert "unknown:unsupported_entry_guard@caller.py:5" in req.items
    assert "unknown:unresolved_call@m.py:9" in req.items
    assert scope_fully_discharged(req, dis) is False


def test_end_to_end_synthetic_added_guard_never_lands_without_approved_delta(tmp_path: Path) -> None:
    """Real pipeline rehearsal: synthetic `if '\\\\0' in s: raise ValueError()` must never return exit 0."""
    env_git = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "GIT_AUTHOR_DATE": "2026-11-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-11-01T00:00:00Z",
        "PATH": "/usr/bin:/bin",
    }
    base_src = (
        "def f(s: str) -> str:\n"
        "    if not s.startswith('\"'):\n"
        "        return s\n"
        "    return s[1:-1]\n"
    )
    post_src = (
        "def f(s: str) -> str:\n"
        "    if not s.startswith('\"'):\n"
        "        return s\n"
        "    if '\\\\0' in s:\n"
        "        raise ValueError('nul')\n"
        "    return s[1:-1]\n"
    )
    delta = {
        "id": "nul-rejected",
        "symbol": "m.f",
        "kind": "exception",
        "claim": "rejects quoted strings containing NUL escape",
        "input_domain": "quoted string containing \\0",
        "predicate": {"type": "expr", "param": "s", "expr": "isinstance(s, str) and s.startswith('\"') and '\\\\0' in s"},
        "pre": "returns unquoted s",
        "post": "raises ValueError",
        "expected": {"kind": "raises", "exc_type": "builtins.ValueError"},
    }

    for name, with_delta in (("no-delta", False), ("unapproved-delta", True)):
        case_dir = tmp_path / name
        repo = case_dir / "repo"
        work = case_dir / "w"
        state = case_dir / "state"
        repo.mkdir(parents=True)
        work.mkdir(parents=True)
        state.mkdir(mode=0o700, parents=True)

        (repo / "m.py").write_text(base_src, encoding="utf-8")
        (repo / "test_m.py").write_text("from m import f\n\ndef test_ok():\n    assert f('ok') == 'ok'\n", encoding="utf-8")
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
            subprocess.run(["git", "-C", str(repo), *args], check=True, env=env_git)
        head0 = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

        manifest: dict = {"paths": {"m.py": ["modify"]}}
        if with_delta:
            manifest["deltas"] = [delta]
        (work / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        # Retargeted to Hlith Review (product.REVIEW_ONLY): was `hlith run --worker-cmd` (a worker wrote m.py and the manifest; not
        # offered). The same post source and manifest are now supplied to `hlith check --patch --manifest`, which rehearses them in its
        # own disposable clone; the operator's repository must stay at head0 and clean.
        (repo / "m.py").write_text(post_src, encoding="utf-8")
        patch = work / "change.patch"
        patch.write_text(subprocess.run(["git", "-C", str(repo), "diff"], capture_output=True, text=True, check=True, env=env_git).stdout,
                         encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "checkout", "-q", "m.py"], check=True, env=env_git)
        out_dir = case_dir / "result"
        art = out_dir / "out.json"
        old_state = os.environ.get("HLITH_STATE_DIR")
        os.environ["HLITH_STATE_DIR"] = str(state)
        try:
            rc = cli_main([
                "check",
                "--repo",
                str(repo),
                "--patch",
                str(patch),
                "--manifest",
                str(work / "manifest.json"),
                "--artifact-out",
                str(out_dir),
                "--target-python",
                sys.executable,
            ])
        finally:
            if old_state is None:
                os.environ.pop("HLITH_STATE_DIR", None)
            else:
                os.environ["HLITH_STATE_DIR"] = old_state

        head1 = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        assert head1 == head0
        assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True, check=True).stdout == ""
        data = json.loads(art.read_text(encoding="utf-8"))
        assert data["outcome"] == "refused"
        if with_delta:
            assert rc == 12
            assert "deltas-confirmed" in (data.get("blocking") or [])
        else:
            assert rc in (4, 10, 11, 12)
            assert rc != 0
