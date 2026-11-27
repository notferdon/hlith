# SPDX-License-Identifier: Apache-2.0
"""Scope discharge: which required scope items a HELD obligation actually discharged .

Fail closed, by construction:
* an `unknown:` item is never dischargeable (the contract's `scope_fully_discharged` enforces it as well);
* an item is discharged only by HELD obligations, and a callable is discharged only if EVERY obligation that targets
  it is HELD (one REFUTED/UNVERIFIED/NOT_DERIVED anywhere on it leaves it open);
* deletions and surviving deleted-callable sites are never discharged (no impacted-test slice for deletions yet).
"""

from __future__ import annotations

from typing import Callable, Iterable

from ..contract.effects import EffectAccount, GapCode
from ..contract.legacy import Obligation, Verdict
from ..contract.obligations import AccountConsumption, RequiredScope, ScopeDischarge


def discharge(
    account: EffectAccount,
    obligations: Iterable[Obligation],
    consumption: Iterable[AccountConsumption],
    enclosing_callable: Callable[[str, int], str | None] = lambda f, l: None,
) -> ScopeDischarge:
    obs = list(obligations)
    cons = {c.obligation_id: c for c in consumption}
    by_target: dict[str, list[Obligation]] = {}
    for o in obs:
        by_target.setdefault(o.target_symbol, []).append(o)

    def all_held(q: str) -> bool:
        return all(o.verdict is Verdict.HELD for o in by_target.get(q, [])) and bool(by_target.get(q))

    def first(q: str, prefix: str, held_only: bool = True) -> Obligation | None:
        for o in by_target.get(q, []):
            if o.obligation_id.startswith(prefix) and (o.verdict is Verdict.HELD or not held_only):
                return o
        return None

    entries: dict[str, str] = {}
    added = set(account.added_callables)
    reached_added = {a for a, _ in account.added_reached_from}
    callable_ok: dict[str, str] = {}
    for q in (*account.modified_callables, *account.added_callables):
        binding = first(q, "signature_binding:")
        diff = first(q, "differential:")
        if not all_held(q) or binding is None:
            continue
        if q in added:
            if q in reached_added:
                callable_ok[q] = (diff or binding).obligation_id
                entries[f"callable:{q}"] = callable_ok[q]
            else:
                # An unreached added callable may be discharged ONLY by a HELD, account-consumed exported-guard
                # obligation targeting that exact callable. It never enters `callable_ok`, so it cannot discharge
                # production callables, sites, guards, primitives, reached items, or unknowns.
                guard_ob = first(q, "exported-guard:")
                guard_cons = cons.get(guard_ob.obligation_id) if guard_ob is not None else None
                if (
                    guard_ob is not None
                    and guard_cons is not None
                    and guard_cons.account_sha256 == account.account_sha256
                    and q in guard_cons.symbols
                ):
                    entries[f"callable:{q}"] = guard_ob.obligation_id
        elif diff is not None:
            callable_ok[q] = diff.obligation_id
            entries[f"callable:{q}"] = callable_ok[q]
    # call sites: discharged by the HELD binding obligation that actually consumed them
    for o in obs:
        if o.verdict is Verdict.HELD and o.obligation_id.startswith("signature_binding:") and o.obligation_id in cons:
            for e in cons[o.obligation_id].edges:
                if o.target_symbol in callable_ok:
                    entries[e] = o.obligation_id
    # a changed constant's reader sites: discharged by the HELD differential of that reader (it consumed the site)
    for o in obs:
        if o.verdict is Verdict.HELD and o.obligation_id.startswith("differential:") and o.obligation_id in cons \
                and o.target_symbol not in callable_ok and all_held(o.target_symbol):
            for e in cons[o.obligation_id].edges:
                entries.setdefault(e, o.obligation_id)
    # entry guards: exercised through the differential of their callable (adequacy polarity), and no guard obligation open
    unsupported_guard_sites = {
        u.where for u in account.unknowns if u.code is GapCode.UNSUPPORTED_ENTRY_GUARD
    }
    for g in account.guards:
        q = g.qualified_name
        if q not in callable_ok:
            continue
        discharger = callable_ok[q]
        if g.change == "removed":
            # a vanished precondition is discharged ONLY by an approved, observed delta that explains exactly it: a HELD
            # differential alone is agreement on explored inputs and says nothing about inputs the guard used to reject
            cover = f"guard-removal-covered:{q}:{g.line}"
            ok = any(o.verdict is Verdict.HELD and o.obligation_id == cover for o in by_target.get(q, []))
        elif f"{g.file}:{g.line}" in unsupported_guard_sites:
            # an added/changed unsupported guard cannot rely on vacuous all(guard-*) when none exists: require an
            # explicit HELD guard-covered:{q}:{file}:{line} obligation and all guard-* obligations on q to be HELD
            cover = f"guard-covered:{q}:{g.file}:{g.line}"
            guard_obs = [o for o in by_target.get(q, []) if o.obligation_id.startswith("guard-")]
            ok = (
                any(o.verdict is Verdict.HELD and o.obligation_id == cover for o in guard_obs)
                and all(o.verdict is Verdict.HELD for o in guard_obs)
            )
            discharger = cover
        else:
            ok = all(o.verdict is Verdict.HELD for o in by_target.get(q, []) if o.obligation_id.startswith("guard-"))
        if ok:
            entries[f"guard:{g.file}:{g.line}:{q}"] = discharger
    # removed external primitives: observed through the differential of the callable that contained them
    for p in account.primitives:
        q = enclosing_callable(p.file, p.line)
        if p.delta == "removed" and q is not None and q in callable_ok:
            entries[f"primitive:{p.name}@{p.file}:{p.line}"] = callable_ok[q]
    # changed constants / class attributes: through HELD readers, with no open constant obligation
    for m in account.modified_constants:
        related = [o for o in obs if o.obligation_id.startswith(("constant-unread:" + m.qualified_name,
                                                                  "constant-reader:" + m.qualified_name + ":"))]
        readers_held = [o for o in obs if o.verdict is Verdict.HELD and o.obligation_id.startswith("differential:")
                        and any(o.target_symbol == r.caller for r in m.readers)]  # exact identity only
        if readers_held and not related:
            entries[f"symbol:{m.kind}:{m.qualified_name}@{m.file}:{m.line}"] = readers_held[0].obligation_id
    # added callables: reached by a differentially checked modified caller
    for added_q, caller in account.added_reached_from:
        if added_q in callable_ok and caller in callable_ok and first(added_q, "added-unexercised:", held_only=False) is None:
            entries[f"reached:{added_q}<-{caller}"] = callable_ok[added_q]
    return ScopeDischarge(tuple(sorted(entries.items())))


def undischarged(required: RequiredScope, d: ScopeDischarge) -> tuple[str, ...]:
    """What is still open (named, for the artifact and the refusal reason)."""
    done = {s for s, _ in d.entries}
    return tuple(i for i in required.items if i.startswith("unknown:") or i not in done)
