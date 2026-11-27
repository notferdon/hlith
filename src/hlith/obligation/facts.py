# SPDX-License-Identifier: Apache-2.0
"""The checkers' view of the account: the frozen EffectAccount (WHAT changed) plus source facts read from the sealed
base/post trees (HOW to check it), assembled in the shape the existing derive/z3_binding/differential code reads.

L3 never rebuilds the account. It additionally checks the account's COMPLETENESS against the trees: every changed
region must lie inside a callable the account lists or be covered by a modified symbol; anything else becomes a
named `uncovered_region` unknown, which refuses (NOT_DERIVED) and is never dischargeable. Unlocatable definitions and
call sites are named unknowns too. Nothing here guesses.
"""

from __future__ import annotations

import ast
import difflib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import guard_removed
from ..contract.effects import EffectAccount, GapCode
from .source import TreeIndex, call_structure, calls_at, guard_dict, is_method, signature_text

_WHERE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)$")
# L2 (effect/api.py _engine_unknowns) encodes an engine construct as "<kind> [<side>] <who>: <source>" in Unknown.detail
_DETAIL = re.compile(r"^(?P<kind>[A-Za-z_]+) \[(?P<side>pre|post)\] (?P<who>[^:]*?): (?P<src>.*)$", re.S)


@dataclass
class Construct:
    """An unknown the verification cannot see through (shape of the legacy `unresolved_construct`)."""

    kind: str
    file_path: str = ""
    line_number: int = 0
    source: str = ""
    caller_qualified_name: str = ""
    side: str = "post"
    condition_source: str = ""
    target_qualified_name: str = ""
    raised_exception: str = ""


@dataclass
class Prim:
    qualified_name: str
    file_path: str
    line_number: int
    primitive: str
    delta: str
    kind: str = "external"

    @property
    def name(self) -> str:
        return self.primitive


@dataclass
class ModCallable:
    qualified_name: str
    file_path: str
    pre_signature: str
    post_signature: str
    entry_guards: list = field(default_factory=list)
    pre_entry_guards: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"qualified_name": self.qualified_name, "file_path": self.file_path, "pre_signature": self.pre_signature,
                "post_signature": self.post_signature, "entry_guards": list(self.entry_guards),
                "pre_entry_guards": list(self.pre_entry_guards)}


class Facts:
    """Duck-typed stand-in for the legacy account object (the shape derive reads), built from the frozen account."""

    def __init__(self) -> None:
        self.modified_callables: tuple[ModCallable, ...] = ()
        self.added: list[dict] = []
        self.deleted: list[dict] = []
        self.constants: list[dict] = []
        self.class_attributes: list[dict] = []
        self.sites: list[dict] = []
        self.unresolved_constructs: list[Construct] = []
        self.unknown_edges: list[Any] = []
        self.side_effect_primitive_delta: list[Prim] = []
        self.impacted_test_nodes: list[dict] = []
        self.touched_files: tuple[str, ...] = ()
        self.unexplored_scope: str = ""
        self.enclosing = lambda rel, line: None  # post-tree enclosing callable, for scope discharge
        self.site_attribution: dict[str, tuple[str, ...]] = {}  # target callable -> `site:` ids that call (or read) it

    def to_dict(self) -> dict:
        return {
            "modified_callables": [m.to_dict() for m in self.modified_callables],
            "added_callables": self.added, "deleted_callables": self.deleted,
            "modified_constants": self.constants, "modified_class_attributes": self.class_attributes,
            "impacted_call_sites": self.sites, "post_call_sites": self.sites,
            "opaque_caller_guards": [], "unknown_edges": [],
            "unexplored_scope": self.unexplored_scope,
        }


# ------------------------------------------------------------------------------------------- trees
def changed_files(base_root: Path, post_root: Path) -> tuple[str, ...]:
    """Files whose bytes differ between the sealed trees (the trees, not a patch text, are the truth)."""
    def listing(root: Path) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for dp, dns, fns in os.walk(root, followlinks=False):
            dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
            for fn in fns:
                p = Path(dp) / fn
                out[p.relative_to(root).as_posix()] = p
        return out

    a, b = listing(Path(base_root)), listing(Path(post_root))
    diff = []
    for rel in sorted(set(a) | set(b)):
        try:
            if rel not in a or rel not in b or a[rel].read_bytes() != b[rel].read_bytes():
                diff.append(rel)
        except OSError:
            diff.append(rel)
    return tuple(diff)


def _strip_docstrings(tree: ast.Module) -> str:
    t = ast.parse(ast.unparse(tree))
    for n in ast.walk(t):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body:
            first = n.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) \
                    and isinstance(first.value.value, str):
                n.body = n.body[1:] or [ast.Pass()]
    return ast.dump(t)


def _covered(names: set[str], q: str | None) -> bool:
    return q is not None and any(q == n or q.startswith(n + ".") for n in names)


_NON_SIMPLE_STMT: tuple[type[ast.stmt], ...] = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    *(() if not hasattr(ast, "TryStar") else (ast.TryStar,)),
    *(() if not hasattr(ast, "Match") else (ast.Match,)),
)


def uncovered_regions(account: EffectAccount, base: TreeIndex, post: TreeIndex, touched: tuple[str, ...]) -> list[Construct]:
    """Changed regions the account does not cover (account completeness check)."""
    live = set(account.modified_callables) | set(account.added_callables)
    gone = set(account.modified_callables) | set(account.removed_callables)
    out: list[Construct] = []
    for rel in touched:
        if not rel.endswith(".py"):
            continue  # non-Python artifacts are named separately by the orchestrator
        b, p = base.parse(rel), post.parse(rel)
        if b is not None and p is not None:
            try:
                if _strip_docstrings(b[0]) == _strip_docstrings(p[0]):
                    continue  # comments / formatting / docstrings only: no behaviour region
            except (SyntaxError, RecursionError, ValueError):
                pass
        elif (base.exists(rel) and b is None) or (post.exists(rel) and p is None):
            out.append(Construct("analysis_failed", rel, 0, "SyntaxError: a changed file could not be parsed by L3"))
            continue
        new_file = not base.exists(rel)
        symbols = [m for m in account.modified_constants if m.file == rel]
        base_lines = (b[1].splitlines() if b else [])
        post_lines = (p[1].splitlines() if p else [])
        bad: list[tuple[int, int]] = []

        def inert(text: str, line: int, tree: TreeIndex, is_new: bool) -> bool:
            t = text.strip()
            if not t or t.startswith("#"):
                return True
            for start, end, name, is_fn in tree.spans(rel):
                if start == line and not is_fn:
                    return True  # a class header line itself
            got = tree.parse(rel)
            if got is not None:
                for st in got[0].body:
                    if getattr(st, "lineno", 0) <= line <= getattr(st, "end_lineno", 0):
                        if isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant):
                            return True  # a module docstring
                        if is_new and isinstance(st, (ast.Import, ast.ImportFrom)):
                            return True  # imports of a brand-new file
            return False

        def module_level_covered(tree: TreeIndex, line: int) -> bool:
            got = tree.parse(rel)
            lo = hi = line
            if got is not None:
                for st in ast.walk(got[0]):
                    if isinstance(st, ast.stmt) and getattr(st, "lineno", 0) <= line <= getattr(st, "end_lineno", 0):
                        if not isinstance(st, _NON_SIMPLE_STMT):
                            lo, hi = min(lo, st.lineno), max(hi, st.end_lineno)  # widest enclosing simple statement
            return any(lo <= s.line <= hi for s in symbols)

        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, base_lines, post_lines, autojunk=False).get_opcodes():
            if tag == "equal":
                continue
            ok = True
            for ln in range(j1 + 1, j2 + 1):  # post side
                q = post.enclosing(rel, ln)
                if q is not None:
                    ok = ok and _covered(live, q)
                elif not inert(post_lines[ln - 1], ln, post, new_file) and not module_level_covered(post, ln):
                    ok = False
            for ln in range(i1 + 1, i2 + 1):  # base side
                q = base.enclosing(rel, ln)
                if q is not None:
                    ok = ok and _covered(gone, q)
                elif not inert(base_lines[ln - 1], ln, base, False) and not module_level_covered(base, ln) \
                        and not module_level_covered(post, max(1, j1 + 1)):
                    ok = False
            if not ok:
                bad.append((min(i1, j1) + 1, max(i2, j2)))
        for a, z in bad[:5]:
            out.append(Construct(
                "uncovered_region", rel, a,
                f"changed lines {a}-{z} are inside no callable the account lists and are covered by no modified symbol: "
                "the account does not describe this part of the change"))
        if len(bad) > 5:
            out.append(Construct("uncovered_region", rel, 0, f"{len(bad) - 5} further uncovered changed regions in {rel}"))
    return out


# ------------------------------------------------------------------------------------------- assembly
def guard_exception(index: TreeIndex, rel: str, line: int) -> str:
    """The exception a guard at `line` raises (`builtins.ValueError` for a builtin, else the source name), or "" when the
    guard cannot be located: the unknown carries only text, so the type is read from the guard's own tree."""
    got = index.parse(rel)
    if got is None:
        return ""
    import builtins

    for n in ast.walk(got[0]):
        if isinstance(n, ast.If) and (n.lineno == line or any(getattr(c, "lineno", -1) == line for c in n.body)):
            for st in n.body:
                if isinstance(st, ast.Raise) and st.exc is not None:
                    e = st.exc.func if isinstance(st.exc, ast.Call) else st.exc
                    name = ast.unparse(e)
                    b = getattr(builtins, name, None)
                    return f"builtins.{name}" if isinstance(b, type) and issubclass(b, BaseException) else name
    return ""


def _where(u_where: str) -> tuple[str, int]:
    m = _WHERE.match(u_where)
    return (m.group("file"), int(m.group("line"))) if m else ("", 0)


def _guards(index: TreeIndex, loc) -> list[dict]:
    got = index.parse(loc.rel)
    if got is None:
        return []
    func_path = ".".join((*loc.chain, loc.node.name))
    a = guard_removed.analyse(got[1], func_path)
    if a is None:
        return []
    params = {x.arg for x in (*loc.node.args.posonlyargs, *loc.node.args.args, *loc.node.args.kwonlyargs)}
    out = []
    for g in a["prefix"]:
        d = guard_dict(ast.unparse(g["node"]), g.get("exc"), params, g.get("line"))
        if d is not None:
            out.append(d)
    return out


def _leaf_names(qualified: str) -> set[str]:
    parts = qualified.split(".")
    names = {parts[-1]}
    if parts[-1] == "__init__" and len(parts) > 1:
        names.add(parts[-2])  # a constructor call names the class
    return names


def attribute_sites(account: EffectAccount, base: TreeIndex, post: TreeIndex):
    """Which callable each impacted site calls (or reads), read from the SOURCE at the site's (file, line).

    The contract's ImpactedSite drops the callee and `callee_edges` are the calls made BY modified code, so neither
    relates a site to its target. L3 finds the call in the post tree (else the base tree: a pre-change site) whose callee
    name is a changed callable's; a matching callee edge only DISAMBIGUATES. Returns (target -> [ImpactedSite], sites no
    changed callable explains)."""
    targets = sorted({*account.modified_callables, *account.added_callables, *account.removed_callables})
    leaves = {q: _leaf_names(q) for q in targets}
    edge_callees: dict[tuple[str, int, str], set[str]] = {}
    for e in account.callee_edges:
        edge_callees.setdefault((e.file, e.line, e.caller), set()).add(e.callee)
    by_site = {(s.file, s.line, s.caller): s for s in account.impacted_sites}
    attr: dict[str, list] = {}
    unattributed = []
    for key, s in sorted(by_site.items()):
        found: set[str] = set()
        for tree in (post, base):
            got = tree.parse(s.file)
            if got is None:
                continue
            found = {q for q in targets if calls_at(got[0], s.line, leaves[q])}
            if found:
                break
        edge = edge_callees.get(key)
        if edge and (found & edge):
            found &= edge  # disambiguate only: an edge never ADDS a target
        for m in account.modified_constants:  # a reader of a changed constant: attributed to the reader callable
            if any((r.file, r.line, r.caller) == key for r in m.readers):
                found.add(s.caller)
        if found:
            for q in found:
                attr.setdefault(q, []).append(s)
        else:
            unattributed.append(s)
    return attr, unattributed


def build(account: EffectAccount, base_root: Path, post_root: Path) -> Facts:
    base, post = TreeIndex(base_root), TreeIndex(post_root)
    f = Facts()
    f.touched_files = changed_files(Path(base_root), Path(post_root))
    f.enclosing = post.enclosing
    cons: list[Construct] = []
    # 1. every account unknown is a named construct (never dischargeable, refuses as NOT_DERIVED)
    for u in account.unknowns:
        file, line = _where(u.where)
        m = _DETAIL.match(u.detail)
        side, who, src = ("post", "", u.detail) if m is None else (m.group("side"), m.group("who").strip(), m.group("src"))
        tree = base if side == "pre" else post
        caller = who or ((post.enclosing(file, line) or "") if file else u.where)
        exc = guard_exception(tree, file, line) if (file and u.code is GapCode.UNSUPPORTED_ENTRY_GUARD) else ""
        # the SIDE matters: a REMOVED guard (pre) is covered only by an observed, approved delta, never by the post tree
        cons.append(Construct(u.code.value, file, line, src, caller, side=side, condition_source=src,
                              target_qualified_name=who, raised_exception=exc))
    # 2. the account's completeness against the sealed trees
    cons += uncovered_regions(account, base, post, f.touched_files)

    attr, unattributed = attribute_sites(account, base, post)
    f.site_attribution = {q: tuple(sorted(f"site:{s.file}:{s.line}:{s.caller}" for s in v)) for q, v in attr.items()}
    for s in unattributed:
        cons.append(Construct("call_site_unattributed", s.file, s.line,
                              f"the account lists an impacted site in {s.caller} but no changed callable is called (or a changed "
                              "constant read) at that line in either tree: L3 cannot relate it to an obligation", s.caller))

    def site_dicts(callee: str, loc_callee) -> list[dict]:
        """Post-tree call structures of the sites attributed to `callee` (a base-only site is a pre-change site: it is
        consumed for the scope but is not a post-change call to bind)."""
        leaf = callee.rsplit(".", 1)[-1]
        names = _leaf_names(callee)
        out = []
        for s in attr.get(callee, ()):
            got = post.parse(s.file)
            for c in (calls_at(got[0], s.line, names) if got is not None else []):
                out.append({"caller_qualified_name": s.caller, "callee_qualified_name": callee, "file_path": s.file,
                            "line_number": s.line, **call_structure(c),
                            "is_method_call": bool(loc_callee is not None and is_method(loc_callee)
                                                   and (isinstance(c.func, ast.Attribute) or leaf == "__init__"))})
        return out

    mods: list[ModCallable] = []
    added_set = set(account.added_callables)
    for q in account.modified_callables:
        lp, lb = post.locate(q), base.locate(q)
        if q in added_set:
            continue
        if lp is None or lb is None:
            cons.append(Construct("callable_unlocatable", "", 0,
                                  f"{q} is listed as modified but L3 cannot locate its definition in the "
                                  f"{'post' if lp is None else 'base'} tree", q, target_qualified_name=q))
            continue
        mods.append(ModCallable(q, lp.rel, signature_text(lb.node) or "()", signature_text(lp.node) or "()",
                                _guards(post, lp), _guards(base, lb)))
        f.sites.extend(site_dicts(q, lp))
    f.modified_callables = tuple(mods)
    for q in account.added_callables:
        lp = post.locate(q)
        if lp is None:
            cons.append(Construct("callable_unlocatable", "", 0, f"{q} is listed as added but L3 cannot locate it in the post tree",
                                  q, target_qualified_name=q))
            continue
        sites = site_dicts(q, lp)
        f.added.append({"qualified_name": q, "post_signature": signature_text(lp.node) or "()", "post_call_sites": sites,
                        "entry_guards": _guards(post, lp), "unknown_edges": [], "unexplored_scope": "",
                        "reached_from": [{"caller_qualified_name": c} for a, c in account.added_reached_from if a == q]})
    for q in account.removed_callables:
        f.deleted.append({"qualified_name": q, "post_call_sites": [
            {"file_path": s.file, "line_number": s.line, "caller_qualified_name": s.caller}
            for d, s in account.deleted_surviving_sites if d == q]})
    for m in account.modified_constants:
        rec = {"qualified_name": m.qualified_name, "file_path": m.file, "line_number": m.line, "kind": m.kind,
               "readers": [{"qualified_name": r.caller, "file_path": r.file, "line_number": r.line} for r in m.readers]}
        (f.class_attributes if m.kind == "class_attribute" else f.constants).append(rec)
    for p in account.primitives:
        if p.delta == "added":
            f.side_effect_primitive_delta.append(Prim(post.enclosing(p.file, p.line) or post.module_name(p.file),
                                                      p.file, p.line, p.name, p.delta))
    for t in account.impacted_tests:
        f.impacted_test_nodes.append({"node_id": t.node_id, "reaches": list(t.reaches), "exists_in_base": base.exists(t.file),
                                      "provenance": "effect account (contract v2.1 impacted_tests)"})
    f.unresolved_constructs = cons
    f.unexplored_scope = ("L3 source facts are read from the sealed trees; opaque caller guards and receiver-bound call "
                          "resolution are taken from the account's edges, not re-derived")
    return f
