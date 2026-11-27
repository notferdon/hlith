# SPDX-License-Identifier: Apache-2.0
"""L3 -> L4 contract: scope, consumption and the issuer-bound VerificationRecord."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import sha256_canonical
from .effects import EffectAccount, GapCode
from .identities import RunId, Sha256, TargetIdentity, TreeOid


@dataclass(frozen=True)
class AccountConsumption:
    """Typed proof that an obligation consumed THIS account (replaces the id-prefix check)."""

    obligation_id: str
    account_sha256: Sha256
    symbols: tuple[str, ...] = ()
    edges: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequiredScope:
    """Everything the gate requires to be discharged for this account (derived, never chosen by an operator)."""

    items: tuple[str, ...]

    @property
    def digest(self) -> Sha256:
        return Sha256(sha256_canonical(sorted(self.items)))

    @classmethod
    def from_account(cls, account: EffectAccount) -> "RequiredScope":
        items = [f"callable:{q}" for q in account.modified_callables + account.added_callables + account.removed_callables]
        items += [f"site:{s.file}:{s.line}:{s.caller}" for s in account.impacted_sites]
        items += [f"guard:{g.file}:{g.line}:{g.qualified_name}" for g in account.guards]
        items += [f"primitive:{p.name}@{p.file}:{p.line}" for p in account.primitives]
        # An ADDED unsupported entry guard is carried twice: as its own `guard:` item above and as the typed
        # UNSUPPORTED_ENTRY_GUARD unknown at the same file:line. Only that exact duplicate is left out here, so the guard is
        # decided by its `guard:` item, which obligation/scope.py discharges only through an explicit HELD guard-covered
        # obligation (never vacuously). account.unknowns is not edited; every other unknown stays undischargeable.
        added_guard_sites = {f"{g.file}:{g.line}" for g in account.guards if g.change == "added"}
        items += [f"unknown:{u.code.value}@{u.where}" for u in account.unknowns
                  if not (u.code is GapCode.UNSUPPORTED_ENTRY_GUARD and u.where in added_guard_sites)]
        items += [f"symbol:{m.kind}:{m.qualified_name}@{m.file}:{m.line}" for m in account.modified_constants]
        items += [f"reached:{added}<-{caller}" for added, caller in account.added_reached_from]
        items += [f"deleted_site:{d}@{site.file}:{site.line}:{site.caller}" for d, site in account.deleted_surviving_sites]
        return cls(tuple(sorted(set(items))))


@dataclass(frozen=True)
class ScopeDischarge:
    """scope item id -> id of the HELD obligation that discharged it."""

    entries: tuple[tuple[str, str], ...]

    @property
    def digest(self) -> Sha256:
        return Sha256(sha256_canonical(sorted(self.entries)))


def obligation_set_digest(obligations: object) -> Sha256:
    """The ONE digest of an ObligationSet (v2.4). L3 issues it into VerificationRecord.obligation_set_sha256; L4 recomputes it
    from the obligations it was handed and refuses (exit 4) on any difference, so a swapped set cannot ride a valid record."""
    return Sha256(sha256_canonical(obligations))


def scope_fully_discharged(required: RequiredScope, discharge: ScopeDischarge) -> bool:
    """Fail closed: an `unknown:` item is never dischargeable; every other item needs an entry."""
    done = {scope for scope, _ in discharge.entries}
    for item in required.items:
        if item.startswith("unknown:") or item not in done:
            return False
    return True


@dataclass(frozen=True)
class VerificationRecord:
    """Issued by the L3 controller with the verifier-issue key; verified by L4. A hash proves bytes, not origin: the MAC does."""

    run_id: RunId
    base_tree_oid: TreeOid
    patch_sha256: Sha256
    post_tree_oid: TreeOid
    account_sha256: Sha256
    target: TargetIdentity
    required_scope_digest: Sha256
    scope_discharge_digest: Sha256
    obligation_set_sha256: Sha256
    consumption: tuple[AccountConsumption, ...]
    context_identity_sha256: Sha256  # source, dependency and execution context identity of the checkers
    checker_ids: tuple[str, ...]
    issuer: str
    mac: str = ""

    def body(self) -> dict:
        from .codec import plain

        d = plain(self)
        d.pop("mac")
        return d

    @property
    def body_sha256(self) -> Sha256:
        return Sha256(sha256_canonical(self.body()))
