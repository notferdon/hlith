# SPDX-License-Identifier: Apache-2.0
"""L2 -> L3/L4 contract: the one EffectAccount per run."""

from __future__ import annotations

import enum
from dataclasses import dataclass
import hashlib
import json

from .codec import sha256_canonical
from .identities import RunId, Sha256, TreeOid
from .legacy import ProposedEffect


class GapCode(str, enum.Enum):
    """Typed unknown vocabulary (prose stays beside it, never instead of it)."""

    DYNAMIC_ATTRIBUTE = "dynamic_attribute"
    UNRESOLVED_CALL = "unresolved_call"
    UNRESOLVED_RECEIVER = "unresolved_receiver"
    UNSUPPORTED_ENTRY_GUARD = "unsupported_entry_guard"
    NON_PYTHON_ARTIFACT = "non_python_artifact"
    ANALYSIS_FAILED = "analysis_failed"
    PARSER_DISAGREEMENT = "parser_disagreement"
    CONDITIONAL_DUPLICATE_DEF = "conditional_duplicate_def"
    OTHER = "other"


@dataclass(frozen=True)
class Unknown:
    code: GapCode
    where: str  # file:line or qualified name
    detail: str


@dataclass(frozen=True)
class EffectPrimitive:
    name: str
    file: str
    line: int
    delta: str  # "added" | "removed"


@dataclass(frozen=True)
class EntryGuard:
    qualified_name: str
    file: str
    line: int
    change: str  # "added" | "removed" | "changed"
    condition_source: str


@dataclass(frozen=True)
class CalleeEdge:
    caller: str
    callee: str
    file: str
    line: int


@dataclass(frozen=True)
class ImpactedSite:
    caller: str
    file: str
    line: int


@dataclass(frozen=True)
class ModifiedSymbol:
    """A changed constant, class attribute or module-level region and the sites that read it (add-only, contract v2.1)."""

    qualified_name: str
    file: str
    line: int
    kind: str  # "constant" | "class_attribute" | "module_level"
    readers: tuple[ImpactedSite, ...] = ()


@dataclass(frozen=True)
class ImpactedTest:
    """A repository test that reaches changed code: the only OBSERVED source of real receivers/arguments."""

    node_id: str
    file: str
    reaches: tuple[str, ...] = ()


@dataclass(frozen=True)
class UnresolvedConstructFact:
    """Digest-bound identity needed to report recurrence of a changed unresolved construct."""

    file_path: str
    line_number: int
    kind: str
    caller_qualified_name: str | None
    node_sha256: str
    side: str


@dataclass(frozen=True)
class EffectAccount:
    """Built ONCE per run by L2 from the sealed pre/post snapshots; passed (never rebuilt) to L3 and L4."""

    run_id: RunId
    base_tree_oid: TreeOid
    patch_sha256: Sha256
    post_tree_oid: TreeOid
    analyzer_id: str  # analyzer name + version digest
    modified_callables: tuple[str, ...] = ()
    added_callables: tuple[str, ...] = ()
    removed_callables: tuple[str, ...] = ()
    impacted_sites: tuple[ImpactedSite, ...] = ()
    callee_edges: tuple[CalleeEdge, ...] = ()
    primitives: tuple[EffectPrimitive, ...] = ()
    guards: tuple[EntryGuard, ...] = ()
    unknowns: tuple[Unknown, ...] = ()
    # contract v2.1 (add-only; defaults empty so every earlier constructor still works):
    modified_constants: tuple[ModifiedSymbol, ...] = ()
    impacted_tests: tuple[ImpactedTest, ...] = ()
    added_reached_from: tuple[tuple[str, str], ...] = ()  # (added callable, modified caller)
    deleted_surviving_sites: tuple[tuple[str, ImpactedSite], ...] = ()  # (deleted callable, surviving post call site)
    # contract v2.2 (add-only): DISCLOSED limits that are true of every account and never block discharge by themselves,
    # e.g. "callers_outside_repository". Consumers carry them into every HELD's unexplored text; they are not Unknowns.
    scope_limits: tuple[str, ...] = ()
    # contract v2.3 (add-only): digest-bound identity for recurrence feedback on unresolved changed constructs.
    unresolved_constructs: tuple[UnresolvedConstructFact, ...] = ()

    @property
    def account_sha256(self) -> Sha256:
        return Sha256(sha256_canonical(self))


_CONTENT_KINDS = frozenset({"add", "modify", "delete"})


@dataclass(frozen=True)
class DeclaredEffects:
    """What the effect account / obligations say the change touches (add-only contract type)."""

    paths: dict[str, frozenset[str]]

    @classmethod
    def from_paths(cls, paths, kinds: frozenset[str] = _CONTENT_KINDS) -> "DeclaredEffects":
        return cls({p: frozenset(kinds) for p in paths})


def canonical_delta_set(deltas) -> str:
    return json.dumps(sorted(deltas, key=lambda d: d["id"]), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def delta_set_sha256(deltas) -> str:
    return hashlib.sha256(canonical_delta_set(deltas).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class DeltaEffect(ProposedEffect):
    """A ProposedEffect that also carries the proposer's delta claims (never proof)."""

    deltas: tuple[dict, ...] = ()

    @property
    def delta_set_sha256(self) -> str | None:
        return delta_set_sha256(self.deltas) if self.deltas else None
