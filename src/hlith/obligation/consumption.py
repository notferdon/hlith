# SPDX-License-Identifier: Apache-2.0
"""Typed AccountConsumption per obligation (replaces the obligation-id-prefix `account_bound`).

An obligation is account-bound iff it carries a consumption record that names this account's digest and at least one
symbol or site that EXISTS in that account. The record is computed from what the obligation targets and from the
account's own edges, never from the shape of its id.
"""

from __future__ import annotations

import dataclasses
import posixpath
from typing import Iterable

from ..contract.effects import EffectAccount, ImpactedSite
from ..contract.legacy import Obligation
from ..contract.obligations import AccountConsumption

# obligation id kinds whose claim is derived from the account's impact slice
ACCOUNT_KINDS = frozenset({
    "signature_binding", "differential", "constant-reader", "constant-unread", "guard-covered", "guard-removal-covered",
    "guard-removed", "effect-confinement", "added-unreached", "added-unexercised", "deleted-still-called",
    "deleted-unchecked", "docstring-only", "docstring-measured", "exported-guard",
})


def site_id(site: ImpactedSite) -> str:
    return f"site:{site.file}:{site.line}:{site.caller}"


def account_symbols(account: EffectAccount) -> frozenset[str]:
    names: set[str] = {*account.modified_callables, *account.added_callables, *account.removed_callables}
    for m in account.modified_constants:
        names.add(m.qualified_name)
        names.update(r.caller for r in m.readers)
    names.update(s.caller for s in account.impacted_sites)
    for e in account.callee_edges:
        names.update((e.caller, e.callee))
    names.update(g.qualified_name for g in account.guards)
    names.update(d for d, _ in account.deleted_surviving_sites)
    names.update(a for a, _ in account.added_reached_from)
    return frozenset(names)


def _edges_into(account: EffectAccount, target: str) -> tuple[str, ...]:
    """Impacted sites that the account's own call edges attribute to `target` (intersection: nothing is invented)."""
    located = {(e.file, e.line, e.caller) for e in account.callee_edges if e.callee == target}
    return tuple(sorted({site_id(s) for s in account.impacted_sites if (s.file, s.line, s.caller) in located}))


def _normalised_repo_path(value: str) -> str | None:
    """Normalise a repository-relative POSIX path; reject absolute and escaping identities."""
    if not value or "\x00" in value or "\\" in value:
        return None
    path = posixpath.normpath(value)
    if path in ("", ".", "..") or path.startswith("../") or path.startswith("/"):
        return None
    return path


def consumption_for(ob: Obligation, account: EffectAccount,
                    attribution: "dict[str, tuple[str, ...]] | None" = None, *,
                    account_symbol_files: Iterable[tuple[str, str]] = ()) -> AccountConsumption | None:
    kind = ob.obligation_id.split(":", 1)[0]
    if kind not in ACCOUNT_KINDS:
        return None
    target = ob.target_symbol
    symbols = [target]
    if kind == "exported-guard":
        if target not in account.added_callables:
            return None
        return AccountConsumption(ob.obligation_id, account.account_sha256, (target,), ())
    if kind == "docstring-measured":
        _, _, rel = ob.obligation_id.partition(":")
        wanted = _normalised_repo_path(rel)
        if wanted is None:
            return None
        universe = account_symbols(account)
        file_symbols = [(m.qualified_name, m.file) for m in account.modified_constants]
        file_symbols.extend(account_symbol_files)
        symbols = sorted({name for name, path in file_symbols
                          if name in universe and _normalised_repo_path(path) == wanted})
        if not symbols:
            return None
    if kind == "constant-reader":  # constant-reader:<constant>:<reader>
        parts = ob.obligation_id.split(":", 2)
        symbols = [p for p in parts[1:] if p]
    if kind in ("signature_binding", "differential"):
        # the sites attributed to this target from the SOURCE (obligation.facts); the edge intersection is only the fallback
        edges = tuple(attribution.get(target, ())) if attribution is not None else _edges_into(account, target)
    else:
        edges = ()
    return AccountConsumption(ob.obligation_id, account.account_sha256, tuple(sorted(set(symbols))), edges)


def valid(c: AccountConsumption, account: EffectAccount) -> bool:
    universe = account_symbols(account)
    site_ids = {site_id(s) for s in account.impacted_sites}
    return (c.account_sha256 == account.account_sha256 and bool(c.symbols or c.edges)
            and all(s in universe for s in c.symbols) and all(e in site_ids for e in c.edges))


def bind(obligations: Iterable[Obligation], account: EffectAccount,
         attribution: "dict[str, tuple[str, ...]] | None" = None, *,
         account_symbol_files: Iterable[tuple[str, str]] = ()) -> tuple[tuple[Obligation, ...], tuple[AccountConsumption, ...]]:
    """Set `account_bound` from a VALID consumption record only; return the obligations and the records."""
    out: list[Obligation] = []
    records: list[AccountConsumption] = []
    symbol_files = tuple(account_symbol_files)
    for o in obligations:
        c = consumption_for(o, account, attribution, account_symbol_files=symbol_files)
        ok = c is not None and valid(c, account)
        if ok:
            records.append(c)  # type: ignore[arg-type]
        out.append(dataclasses.replace(o, account_bound=bool(ok)))
    return tuple(out), tuple(records)
