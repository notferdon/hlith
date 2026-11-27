# SPDX-License-Identifier: Apache-2.0
"""RequiredScope.from_account: the typed unknown for an ADDED unsupported entry guard is a duplicate of that guard's own
`guard:` scope item (O3v2-A, review Option A). Only that exact duplicate is left out of the scope; account.unknowns are untouched,
and every other unknown still makes the scope undischargeable. Whether the `guard:` item itself is discharged is decided by
obligation/scope.py (review: an explicit HELD guard-covered obligation, never vacuously)."""
from __future__ import annotations

from hlith.contract.effects import EffectAccount, EntryGuard, GapCode, Unknown
from hlith.contract.identities import RunId, Sha256, TreeOid
from hlith.contract.obligations import RequiredScope, ScopeDischarge, scope_fully_discharged

Q = "pkg.mod.f"
WHERE = "pkg/mod.py:7"


def _account(*, guards=(), unknowns=()):
    return EffectAccount(
        run_id=RunId("run-000000000001"), base_tree_oid=TreeOid("a" * 40), patch_sha256=Sha256("b" * 64),
        post_tree_oid=TreeOid("c" * 40), analyzer_id="test", modified_callables=(Q,), guards=tuple(guards),
        unknowns=tuple(unknowns),
    )


def _guard(change="added", line=7):
    return EntryGuard(qualified_name=Q, file="pkg/mod.py", line=line, change=change, condition_source='"\\0" in s')


def _unk(code=GapCode.UNSUPPORTED_ENTRY_GUARD, where=WHERE):
    return Unknown(code=code, where=where, detail="unresolved construct: unsupported_entry_guard")


def test_added_guard_duplicate_unknown_is_left_out_but_the_guard_item_remains():
    acct = _account(guards=[_guard()], unknowns=[_unk()])
    items = RequiredScope.from_account(acct).items
    assert f"unknown:unsupported_entry_guard@{WHERE}" not in items
    assert f"guard:pkg/mod.py:7:{Q}" in items
    assert acct.unknowns == (_unk(),)  # the account itself is never edited


def test_the_guard_item_still_needs_a_discharge_entry():
    required = RequiredScope.from_account(_account(guards=[_guard()], unknowns=[_unk()]))
    only_callable = ScopeDischarge(((f"callable:{Q}", "differential:x"),))
    assert scope_fully_discharged(required, only_callable) is False
    both = ScopeDischarge(((f"callable:{Q}", "differential:x"), (f"guard:pkg/mod.py:7:{Q}", f"guard-covered:{Q}:7")))
    assert scope_fully_discharged(required, both) is True


def test_removed_or_changed_guard_does_not_suppress_the_unknown():
    for change in ("removed", "changed"):
        items = RequiredScope.from_account(_account(guards=[_guard(change)], unknowns=[_unk()])).items
        assert f"unknown:unsupported_entry_guard@{WHERE}" in items, change


def test_unknown_at_a_different_location_than_the_added_guard_is_kept():
    items = RequiredScope.from_account(_account(guards=[_guard(line=9)], unknowns=[_unk()])).items
    assert f"unknown:unsupported_entry_guard@{WHERE}" in items


def test_other_unknown_codes_at_the_same_location_are_kept():
    for code in (GapCode.UNRESOLVED_CALL, GapCode.DYNAMIC_ATTRIBUTE, GapCode.OTHER):
        items = RequiredScope.from_account(_account(guards=[_guard()], unknowns=[_unk(code=code)])).items
        assert f"unknown:{code.value}@{WHERE}" in items, code


def test_an_unsupported_guard_unknown_without_any_guard_record_is_kept():
    required = RequiredScope.from_account(_account(unknowns=[_unk()]))
    assert f"unknown:unsupported_entry_guard@{WHERE}" in required.items
    full = ScopeDischarge(tuple((i, "x") for i in required.items))
    assert scope_fully_discharged(required, full) is False
