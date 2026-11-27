# SPDX-License-Identifier: Apache-2.0
"""L2 section API (contract ``EffectApi``): ONE whole-patch EffectAccount per run, from sealed snapshots.

Authority (contract boundaries):
  * reads only the sealed, read-only base and post snapshot exports handed over by the trusted host; never the
    original target, never a git dir, never proposer-private paths; executes no repository code;
  * writes only an optional host-owned index cache directory supplied by the coordinator (never inside a
    snapshot, a repository or any ``.git``); no cache when none is supplied;
  * emits facts and typed unknowns, never verdicts.

The account is built once (``EffectService.build``) and handed, never rebuilt, to L3 and L4. ``AccountBuild.detail``
carries the full engine record (``hlith.effect.engine.EffectAccount``) for L3 consumers that still read it during
migration, so they do not need a second build.

Disclosed limits (open caller/callee sets) go to ``scope_limits`` (contract v2.2), never to ``unknowns``.

Feedback (contract ``FeedbackInput``, L5 -> L2) is ADD-ONLY: ``extra_unknowns`` are appended; an ``extra_callers``
entry that the static account did not reach becomes an explicit unknown. Nothing in the feedback can remove a
fact or an unknown.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ..contract.capabilities import SealedSnapshot
from ..contract.effects import (
    CalleeEdge,
    EffectAccount,
    EffectPrimitive,
    EntryGuard,
    GapCode,
    ImpactedSite,
    ImpactedTest,
    ModifiedSymbol,
    UnresolvedConstructFact,
    Unknown,
)
from ..contract.errors import Refusal, RefusalError
from ..contract.feedback import EMPTY_FEEDBACK, FeedbackInput
from ..contract.identities import RunId, Sha256, TreeOid, sha256_hex, tree_oid
from . import engine
from .exports import resolve_static_wildcard_export
from .module_names import module_name_for_path

ANALYZER_NAME = "hlith.effect"

# engine UnresolvedConstruct.kind -> contract GapCode (prose stays in Unknown.detail)
_GAP_BY_KIND = {
    "dynamic_getattr": GapCode.DYNAMIC_ATTRIBUTE,
    "dynamic_setattr": GapCode.DYNAMIC_ATTRIBUTE,
    "dynamic_attribute": GapCode.DYNAMIC_ATTRIBUTE,
    "dynamic_call": GapCode.UNRESOLVED_CALL,
    "unknown_call": GapCode.UNRESOLVED_CALL,
    "unresolved_call": GapCode.UNRESOLVED_CALL,
    "star_args_forwarding": GapCode.UNRESOLVED_CALL,
    "unresolved_method_receiver": GapCode.UNRESOLVED_RECEIVER,
    "unresolved_receiver": GapCode.UNRESOLVED_RECEIVER,
    "unsupported_entry_guard": GapCode.UNSUPPORTED_ENTRY_GUARD,
    "analysis_failed": GapCode.ANALYSIS_FAILED,
    "syntax_parser_disagreement": GapCode.PARSER_DISAGREEMENT,
    "parser_disagreement": GapCode.PARSER_DISAGREEMENT,
    "conditional_duplicate_def": GapCode.CONDITIONAL_DUPLICATE_DEF,
}
_DIFF_GIT = re.compile(r'^diff --git (?:"?a/(?P<a>.+?)"?) (?:"?b/(?P<b>.+?)"?)$')


@dataclass(frozen=True)
class AccountBuild:
    account: EffectAccount  # the contract value (L3 and L4 bind to account.account_sha256)
    detail: Any  # hlith.effect.engine.EffectAccount: the full engine record of the SAME build (migration input to L3)


def analyzer_id() -> str:
    """Analyzer name + digest of the engine source and parser versions (``engine._index_tool_key``)."""
    key = engine._index_tool_key()
    return f"{ANALYZER_NAME}@{key or 'unversioned'}"


class EffectService:
    """Implements ``hlith.contract.capabilities.EffectApi``.

    ``cache_dir``: host-owned directory for the persistent per-module index cache (content addressed by source and
    tool digest), or None for no persistent cache. ``feedback``: the immutable, validated L5 input for this run."""

    def __init__(self, *, cache_dir: Path | None = None, feedback: FeedbackInput = EMPTY_FEEDBACK) -> None:
        if not isinstance(feedback, FeedbackInput):
            raise TypeError("feedback must be a contract FeedbackInput")
        self._cache_dir = Path(cache_dir) if cache_dir is not None else None
        self._feedback = feedback

    def build_account(self, run_id: RunId, base: SealedSnapshot, post: SealedSnapshot, patch: bytes) -> EffectAccount:
        return self.build(run_id, base, post, patch).account

    def build(self, run_id: RunId, base: SealedSnapshot, post: SealedSnapshot, patch: bytes) -> AccountBuild:
        if not isinstance(patch, (bytes, bytearray)):
            raise TypeError("patch must be the exact patch bytes")
        patch = bytes(patch)
        base_root, post_root = _snapshot_root(base, "base"), _snapshot_root(post, "post")
        if base_root == post_root:
            raise RefusalError(Refusal.BOUNDARY, "base and post snapshots are the same directory")
        cache_dir = _checked_cache_dir(self._cache_dir, (base_root, post_root))
        text = patch.decode("utf-8", errors="surrogateescape")
        header_paths = _diff_git_paths(text)
        try:
            changed = engine._changed_paths(text)
        except ValueError as e:
            raise RefusalError(Refusal.BOUNDARY, f"patch: {e}") from e
        if not changed and not header_paths:
            raise RefusalError(Refusal.BOUNDARY, "patch names no changed path")
        _require_post_reflects_patch(base_root, post_root, changed)
        unknowns: list[Unknown] = []
        detail = None
        if changed:
            try:
                detail = engine._build_account(base_root, text, post_root=post_root, cache_dir=cache_dir)
            except (ValueError, OSError, SyntaxError, RecursionError) as e:  # an account that cannot be built is a named gap
                unknowns.append(Unknown(GapCode.ANALYSIS_FAILED, "<patch>", f"{type(e).__name__}: {e}"[:500]))
        # Whole patch: a path the text hunks do not name (binary, mode-only, rename-only) is still part of the effect.
        for path in sorted(set(header_paths) - set(changed)):
            unknowns.append(Unknown(GapCode.NON_PYTHON_ARTIFACT, path, "changed without a text hunk (binary, mode or rename)"))
        for path in sorted(changed):
            if not path.endswith(".py"):
                unknowns.append(Unknown(GapCode.NON_PYTHON_ARTIFACT, path, "non-Python file changed; its effect is not modelled"))
        account = _contract_account(run_id, base.tree_oid, post.tree_oid, patch, detail, unknowns, self._feedback)
        return AccountBuild(account, detail)


# ----------------------------------------------------------------------------------------------- input checks


def _snapshot_root(snap: SealedSnapshot, name: str) -> Path:
    if not isinstance(snap, SealedSnapshot):
        raise TypeError(f"{name} must be a contract SealedSnapshot")
    tree_oid(str(snap.tree_oid))  # validates the 40-hex identity
    root = Path(snap.path)
    if root.is_symlink() or not root.is_dir():
        raise RefusalError(Refusal.BOUNDARY, f"{name} snapshot is not a real directory: {root}")
    root = root.resolve()
    if (root / ".git").exists():
        raise RefusalError(Refusal.BOUNDARY, f"{name} snapshot carries a .git: L2 reads sealed exports only")
    return root


def _checked_cache_dir(cache_dir: Path | None, snapshots: Iterable[Path]) -> Path | None:
    """The cache must be host-owned: never a symlink, never inside a snapshot, never inside any git dir."""
    if cache_dir is None:
        return None
    if cache_dir.is_symlink():
        raise RefusalError(Refusal.BOUNDARY, "effect cache directory is a symlink")
    resolved = cache_dir.resolve()
    if ".git" in resolved.parts:
        raise RefusalError(Refusal.BOUNDARY, "effect cache directory is inside a git dir")
    for snap in snapshots:
        if resolved == snap or snap in resolved.parents or resolved in snap.parents:
            raise RefusalError(Refusal.BOUNDARY, "effect cache directory overlaps a snapshot")
    return resolved


def _diff_git_paths(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        m = _DIFF_GIT.match(line)
        if not m:
            continue
        for raw in (m.group("a"), m.group("b")):
            p = PurePosixPath(raw)
            if p.is_absolute() or ".." in p.parts:
                raise RefusalError(Refusal.BOUNDARY, f"unsafe path in patch header: {raw}")
            out.add(str(p))
    return sorted(out)


def _require_post_reflects_patch(base_root: Path, post_root: Path, changed: Iterable[str]) -> None:
    """The post snapshot must differ from the base on the patch's text paths (independent reconstruction: A3).
    A post snapshot identical to the base on EVERY changed path cannot be the analysed effect."""
    changed = list(changed)
    if not changed:
        return
    for rel in changed:
        a, b = base_root / rel, post_root / rel
        if a.exists() != b.exists():
            return
        if a.is_file() and b.is_file() and a.read_bytes() != b.read_bytes():
            return
    raise RefusalError(Refusal.BOUNDARY, "post snapshot does not reflect the patch on any changed path")


# --------------------------------------------------------------------------------------------- conversion


def _site(caller: Any, file: Any, line: Any) -> ImpactedSite | None:
    if not caller or not file:
        return None
    try:
        return ImpactedSite(str(caller), str(file), int(line or 0))
    except (TypeError, ValueError):
        return None


def _gap(kind: str) -> GapCode:
    return _GAP_BY_KIND.get(kind, GapCode.OTHER)


def _guards(detail: Any) -> list[EntryGuard]:
    out: list[EntryGuard] = []

    def cond(g: dict) -> str:
        return str(g.get("condition_source") or g.get("raises_when") or "")

    for m in detail.modified_callables:
        pre = {cond(g): g for g in m.pre_entry_guards}
        post = {cond(g): g for g in m.entry_guards}
        for c in sorted(post.keys() - pre.keys()):
            g = post[c]
            out.append(EntryGuard(m.qualified_name, str(g.get("file_path") or m.file_path), int(g.get("line_number") or m.line_number), "added", c))
        for c in sorted(pre.keys() - post.keys()):
            g = pre[c]
            out.append(EntryGuard(m.qualified_name, str(g.get("file_path") or m.file_path), int(g.get("line_number") or m.line_number), "removed", c))
    for a in detail.added_callables:
        for g in a.entry_guards:
            out.append(EntryGuard(a.qualified_name, str(g.get("file_path") or a.file_path), int(g.get("line_number") or 0), "added", cond(g)))
    for u in detail.unresolved_constructs:  # unsupported raising guards: a guard record AND (below) a typed unknown
        if u.kind == "unsupported_entry_guard":
            out.append(EntryGuard(u.caller_qualified_name or u.target_qualified_name or "?", u.file_path, int(u.line_number),
                                  "removed" if u.side == "pre" else "added", u.condition_source or u.source))
    return out


def _engine_unknowns(detail: Any) -> list[Unknown]:
    out: list[Unknown] = []
    typed_guards_: set[str] = set()  # file:line of unsupported entry guards emitted below as their TYPED unknown
    for u in detail.unresolved_constructs:
        if u.kind == "unsupported_entry_guard" and u.side != "pre":
            typed_guards_.add(f"{u.file_path}:{u.line_number}")
        if u.kind == "unsupported_entry_guard" and u.side == "pre":
            # A REMOVED unsupported entry guard is carried ONLY as the typed EntryGuard(change="removed") from
            # _guards() (and disclosed in scope_limits). As an Unknown it could never be discharged (scope_fully_discharged
            # is False for any unknown: item), so a removal that an approved delta exactly covers could never land.
            # Soundness stays with L3: a removed guard: scope item needs a HELD guard-removal-covered obligation
            # (obligation/scope.py). Post-side unsupported guards and every other kind stay Unknowns. (design decision, D6.)
            continue
        who = u.caller_qualified_name or u.target_qualified_name or ""
        out.append(Unknown(_gap(u.kind), f"{u.file_path}:{u.line_number}", f"{u.kind} [{u.side}] {who}: {u.source}"[:500]))
    for e in detail.unknown_edges:
        # effect/engine.py mirrors every post-side unresolved construct as an UnknownEdge; for an unsupported entry
        # guard that mirror would be a second, generic UNRESOLVED_CALL unknown for the SAME guard, which no
        # guard-covered obligation can discharge (review, O3v2-A/E rc 11). The typed UNSUPPORTED_ENTRY_GUARD unknown above
        # stays; any other unknown edge is kept.
        if (e.reason == "unresolved construct: unsupported_entry_guard"
                and f"{e.file_path}:{e.line_number}" in typed_guards_):
            continue
        out.append(Unknown(GapCode.UNRESOLVED_CALL, f"{e.file_path}:{e.line_number}",
                           f"unknown edge [{e.side}] {e.caller_qualified_name} -> {e.target_qualified_name}: {e.reason}"[:500]))
    for c in detail.callee_unresolved_constructs:
        out.append(Unknown(_gap(str(c.get("kind", ""))), f"{c.get('file_path')}:{c.get('line_number')}",
                           f"callee cone: {c.get('kind')} {c.get('caller_qualified_name') or ''}: {c.get('source') or ''}"[:500]))
    for g in detail.opaque_caller_guards:
        out.append(Unknown(GapCode.UNSUPPORTED_ENTRY_GUARD, f"{g.get('file_path')}:{g.get('line_number')}",
                           f"opaque caller guard {g.get('caller_qualified_name') or ''}: {g.get('condition_source') or g.get('source') or ''}"[:500]))
    for m in detail.modified_module_level:
        if m.get("resolution") == "unresolved":
            out.append(Unknown(GapCode.OTHER, f"{m.get('file_path')}:{m.get('line_number')}",
                               f"module-level {m.get('kind')}: {m.get('source') or ''}"[:500]))
    return out


def _symbols(detail: Any) -> list[ModifiedSymbol]:
    out: list[ModifiedSymbol] = []

    def readers(rs: Iterable[dict]) -> tuple[ImpactedSite, ...]:
        sites = {_site(r.get("qualified_name"), r.get("file_path"), r.get("line_number")) for r in rs}
        return tuple(sorted((s for s in sites if s), key=lambda s: (s.file, s.line, s.caller)))

    for kind, records in (("constant", detail.modified_constants), ("class_attribute", detail.modified_class_attributes)):
        for r in records:
            line = r.get("post_line_number") or r.get("pre_line_number") or 0
            out.append(ModifiedSymbol(str(r.get("qualified_name")), str(r.get("file_path")), int(line), kind, readers(r.get("readers") or ())))
    for r in detail.modified_module_level:
        name = r.get("name") or r.get("module") or r.get("kind")
        out.append(ModifiedSymbol(f"{r.get('file_path')}::{name}", str(r.get("file_path")), int(r.get("line_number") or 0), "module_level"))
    return out


def _scope_limits(detail: Any) -> tuple[str, ...]:
    """Disclosed limits of the account (contract v2.2): carried into every HELD's unexplored text; never blocking."""
    out = []
    if not detail.caller_set_closed:
        out.append(f"callers_outside_repository: {detail.caller_set_unexplored}"[:500])
    if not detail.callee_set_closed:
        out.append(f"callees_outside_bounded_cone: {detail.callee_set_unexplored}"[:500])
    if detail.unexplored_scope:
        out.append(f"unexplored: {detail.unexplored_scope}"[:500])
    for u in detail.unresolved_constructs:  # disclosed, typed as a removed EntryGuard (see _engine_unknowns)
        if u.kind == "unsupported_entry_guard" and u.side == "pre":
            out.append(f"removed_unsupported_entry_guard: {u.file_path}:{u.line_number} {u.condition_source or u.source}"[:500])
    return tuple(sorted(set(out)))


def _contract_account(run_id: RunId, base_oid: TreeOid, post_oid: TreeOid, patch: bytes, detail: Any,
                      extra_unknowns: list[Unknown], feedback: FeedbackInput) -> EffectAccount:
    patch_sha = sha256_hex(hashlib.sha256(patch).hexdigest())
    unknowns = list(extra_unknowns)
    fields: dict[str, Any] = {}
    if detail is not None:
        modified = sorted({m.qualified_name for m in detail.modified_callables})
        added = sorted({a.qualified_name for a in detail.added_callables})
        removed = sorted({d.qualified_name for d in detail.deleted_callables})
        sites = {_site(s.caller_qualified_name, s.file_path, s.line_number) for s in (*detail.impacted_call_sites, *detail.post_call_sites)}
        edges = {CalleeEdge(str(e.get("caller_qualified_name")), str(e.get("callee_qualified_name")), str(e.get("file_path")), int(e.get("line_number") or 0))
                 for e in detail.callee_edges if e.get("caller_qualified_name") and e.get("callee_qualified_name")}
        prims = {EffectPrimitive(p.primitive, p.file_path, int(p.line_number), p.delta) for p in detail.side_effect_primitive_delta}
        tests = {ImpactedTest(str(t.get("node_id")), str(t.get("file")), tuple(sorted(str(x) for x in t.get("reaches") or ())))
                 for t in detail.impacted_test_nodes if t.get("node_id")}
        constructs = tuple(
            UnresolvedConstructFact(
                file_path=str(u.file_path),
                line_number=int(u.line_number),
                kind=str(u.kind),
                caller_qualified_name=u.caller_qualified_name,
                node_sha256=str((u.provenance or {}).get("node_sha256") or ""),
                side=str(u.side),
            )
            for u in detail.unresolved_constructs
            if (u.provenance or {}).get("node_sha256")
        )
        reached = {(a.qualified_name, str(r.get("caller_qualified_name"))) for a in detail.added_callables for r in a.reached_from
                   if r.get("caller_qualified_name")}
        surviving = set()
        for d in detail.deleted_callables:
            for s in d.post_call_sites:
                site = _site(s.caller_qualified_name, s.file_path, s.line_number)
                if site:
                    surviving.add((d.qualified_name, site))
        unknowns += _engine_unknowns(detail)
        fields = dict(
            scope_limits=_scope_limits(detail),
            modified_callables=tuple(modified), added_callables=tuple(added), removed_callables=tuple(removed),
            impacted_sites=tuple(sorted((s for s in sites if s), key=lambda s: (s.file, s.line, s.caller))),
            callee_edges=tuple(sorted(edges, key=lambda e: (e.file, e.line, e.caller, e.callee))),
            primitives=tuple(sorted(prims, key=lambda p: (p.file, p.line, p.name, p.delta))),
            guards=tuple(sorted(set(_guards(detail)), key=lambda g: (g.file, g.line, g.qualified_name, g.change, g.condition_source))),
            modified_constants=tuple(sorted(set(_symbols(detail)), key=lambda m: (m.file, m.line, m.qualified_name, m.kind))),
            impacted_tests=tuple(sorted(tests, key=lambda t: t.node_id)),
            unresolved_constructs=constructs,
            added_reached_from=tuple(sorted(reached)),
            deleted_surviving_sites=tuple(sorted(surviving, key=lambda x: (x[0], x[1].file, x[1].line, x[1].caller))),
        )
    # L5 -> L2, add-only: extra unknowns are appended; a feedback caller the static account did not reach is a gap.
    unknowns += list(feedback.extra_unknowns)
    reached_callers = {s.caller for s in fields.get("impacted_sites", ())}
    for caller in sorted(set(feedback.extra_callers) - reached_callers):
        unknowns.append(Unknown(GapCode.UNRESOLVED_CALL, caller, "feedback names this caller; the static account did not reach it"))
    return EffectAccount(
        run_id=RunId(str(run_id)), base_tree_oid=TreeOid(str(base_oid)), patch_sha256=Sha256(patch_sha),
        post_tree_oid=TreeOid(str(post_oid)), analyzer_id=analyzer_id(),
        unknowns=tuple(sorted(set(unknowns), key=lambda u: (u.code.value, u.where, u.detail))), **fields,
    )


__all__ = ["ANALYZER_NAME", "AccountBuild", "EffectService", "analyzer_id", "module_name_for_path", "resolve_static_wildcard_export"]
