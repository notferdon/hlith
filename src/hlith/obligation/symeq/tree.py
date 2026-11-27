# SPDX-License-Identifier: Apache-2.0
"""Tree-level context of a symbolic proof: which identifiers the WHOLE change touches (so the prover never treats changed code behind an opaque name as unchanged), the import-time
conditions the proof relies on, and the in-tree call sites of the target for the typed domain.

Everything here reads source text only (ast); no repository code is imported or run."""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

from .module import binding_table, idents

MAX_FILES = 4000


class TreeTooLarge(Exception):
    """The tree cannot be scanned completely (too large, or a file the one walker refuses)."""


def _walked(root):
    from hlith.obligation.closure_gate import TreeRefused, walk

    try:
        return walk(root)
    except TreeRefused as e:
        raise TreeTooLarge("the source tree cannot be scanned completely: " + str(e)) from None


def py_files(root) -> dict:
    """relative path -> source text for every .py file under root (tests included: a test helper can be a dependency)."""
    return {rel: data.decode("utf-8") for rel, data in _walked(root).sources.items()}


def _parse(src):
    try:
        return ast.parse(src)
    except (SyntaxError, ValueError, RecursionError):
        return None


_WILD = frozenset({"getattr", "setattr", "delattr", "eval", "exec", "globals", "locals", "vars", "__import__", "compile", "__dict__", "__getattribute__", "__getattr__",
                   "__setattr__", "import_module", "__subclasses__", "methodcaller", "attrgetter"})


def tree_taint(base_files: dict, post_files: dict, target_rel: str, target_leaf: str) -> tuple:
    """(tainted identifiers contributed by the rest of the tree, changed file paths). The target module itself is handled by symeq.module_taint; here every OTHER changed file
    seeds its changed bindings, and the closure runs over every file of both trees: a definition that mentions a tainted identifier is tainted; a definition that reaches
    attributes dynamically (getattr and friends) is tainted as soon as anything is."""
    changed = sorted(p for p in set(base_files) | set(post_files) if base_files.get(p) != post_files.get(p))
    seed: set = {target_leaf}
    unparsable = False
    for rel in changed:
        if rel == target_rel:
            continue
        tb = _parse(base_files[rel]) if rel in base_files else ast.Module(body=[], type_ignores=[])
        tp = _parse(post_files[rel]) if rel in post_files else ast.Module(body=[], type_ignores=[])
        if tb is None or tp is None:
            unparsable = True
            continue
        bb, bp = binding_table(tb), binding_table(tp)
        seed |= {k for k in set(bb) | set(bp) if bb.get(k) != bp.get(k)}
        if _module_level_code(tb) != _module_level_code(tp):
            seed.add("*module:" + rel)
    if unparsable:
        return None, changed
    tainted = set(seed)
    # closure over all files; a file is only parsed when its text mentions a tainted identifier (or a dynamic-access name)
    texts = {}
    for side, files in (("b", base_files), ("p", post_files)):
        for rel, src in files.items():
            texts[(side, rel)] = src
    parsed: dict = {}
    progress = True
    rounds = 0
    while progress and rounds < 50:
        progress = False
        rounds += 1
        probe = tainted | _WILD
        for key, src in texts.items():
            if key not in parsed:
                if not any(t in src for t in probe if not t.startswith("*")):
                    continue
                tr = _parse(src)
                parsed[key] = [] if tr is None else _defs(tr)
            for name, ids in parsed[key]:
                if name not in tainted and (ids & tainted or (ids & _WILD and len(tainted) > 0)):
                    tainted.add(name)
                    progress = True
    return tainted, changed


def _assign_targets(target) -> tuple[set[str], set[str]]:
    """Return (plain_name_targets, outermost_attr_targets) stored by an assignment target.
    Only the outermost attribute in `a.b.c = v` is stored (`a.b` is loaded, not assigned);
    subscripts `a.b[k] = v` mutate an item rather than binding a name or attribute."""
    names: set[str] = set()
    attrs: set[str] = set()

    def visit(t):
        if isinstance(t, ast.Name):
            names.add(t.id)
        elif isinstance(t, ast.Attribute):
            attrs.add(t.attr)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for elt in t.elts:
                visit(elt)
        elif isinstance(t, ast.Starred):
            visit(t.value)

    visit(target)
    return names, attrs


def _defs(tree) -> list:
    out = []
    try_types = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)

    def walk_func_stmts(body, local_edges: dict[str, set[str]], out_writes: list[tuple[str, set[str]]], fn_globals: set[str]):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append((st.name, idents(st)))
                local_edges.setdefault(st.name, set()).update(idents(st))
                sub_glob = {nm for n in ast.walk(st) if isinstance(n, ast.Global) for nm in n.names}
                sub_edges: dict[str, set[str]] = {}
                sub_writes: list[tuple[str, set[str]]] = []
                walk_func_stmts(st.body, sub_edges, sub_writes, sub_glob)
                _emit_func_writes(sub_edges, sub_writes)
            elif isinstance(st, ast.ClassDef):
                out.append((st.name, idents(st)))
                walk_scope(st.body, scope_kind="class")
            elif isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                rhs_ids = idents(st.value) if st.value is not None else set()
                for tgt in targets:
                    n_tgts, a_tgts = _assign_targets(tgt)
                    for nm in n_tgts:
                        if nm in fn_globals:
                            out_writes.append((nm, rhs_ids))
                        else:
                            local_edges.setdefault(nm, set()).update(rhs_ids)
                    for anm in a_tgts:
                        out_writes.append((anm, rhs_ids))
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                iter_ids = idents(st.iter)
                n_tgts, a_tgts = _assign_targets(st.target)
                for nm in n_tgts:
                    if nm in fn_globals:
                        out_writes.append((nm, iter_ids))
                    else:
                        local_edges.setdefault(nm, set()).update(iter_ids)
                for anm in a_tgts:
                    out_writes.append((anm, iter_ids))
                walk_func_stmts(st.body, local_edges, out_writes, fn_globals)
                walk_func_stmts(st.orelse, local_edges, out_writes, fn_globals)
            else:
                for attr_name in ("body", "orelse", "finalbody"):
                    sub = getattr(st, attr_name, None)
                    if isinstance(sub, list):
                        walk_func_stmts(sub, local_edges, out_writes, fn_globals)
                if isinstance(st, try_types):
                    for h in st.handlers:
                        walk_func_stmts(h.body, local_edges, out_writes, fn_globals)
                elif isinstance(st, ast.Match):
                    for case in st.cases:
                        walk_func_stmts(case.body, local_edges, out_writes, fn_globals)

    def _emit_func_writes(local_edges: dict[str, set[str]], out_writes: list[tuple[str, set[str]]]):
        if not out_writes:
            return
        # Flow-insensitive transitive closure over local variables inside this function so
        # `tmp = changed_fn; obj.attr = tmp` propagates taint to `attr`, while unrelated
        # local variables and unrelated attribute writes in the same function do not cross-taint.
        closed = {k: set(v) for k, v in local_edges.items()}
        changed_l = True
        while changed_l:
            changed_l = False
            for k, deps in closed.items():
                add: set[str] = set()
                for d in deps:
                    if d in closed:
                        add |= closed[d]
                if not add <= deps:
                    deps |= add
                    changed_l = True
        for nm, rhs_ids in out_writes:
            deps = set(rhs_ids)
            for d in list(rhs_ids):
                if d in closed:
                    deps |= closed[d]
            out.append((nm, deps))

    def walk_scope(body, *, scope_kind: str):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append((st.name, idents(st)))
                fglob = {nm for n in ast.walk(st) if isinstance(n, ast.Global) for nm in n.names}
                local_edges: dict[str, set[str]] = {}
                out_writes: list[tuple[str, set[str]]] = []
                walk_func_stmts(st.body, local_edges, out_writes, fglob)
                _emit_func_writes(local_edges, out_writes)
            elif isinstance(st, ast.ClassDef):
                out.append((st.name, idents(st)))
                walk_scope(st.body, scope_kind="class")
            elif isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                ids = idents(st.value) if st.value is not None else set()
                for tgt in targets:
                    n_tgts, a_tgts = _assign_targets(tgt)
                    for nm in n_tgts | a_tgts:
                        out.append((nm, ids))
            else:
                for attr_name in ("body", "orelse", "finalbody"):
                    sub = getattr(st, attr_name, None)
                    if isinstance(sub, list):
                        walk_scope(sub, scope_kind=scope_kind)
                if isinstance(st, try_types):
                    for h in st.handlers:
                        walk_scope(h.body, scope_kind=scope_kind)
                elif isinstance(st, ast.Match):
                    for case in st.cases:
                        walk_scope(case.body, scope_kind=scope_kind)

    walk_scope(tree.body, scope_kind="module")
    return out


def _module_level_code(tree) -> list:
    """Canonical dumps of the module-level statements that are not definitions (they run at import)."""
    return [ast.dump(st, annotate_fields=False, include_attributes=False) for st in tree.body if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def import_time_delta(base_src: str, post_src: str, function: str):
    """A reason the change can alter what happens when the target module is IMPORTED (outside any function body), or None.
    Module-level statements must be identical; a definition header (decorators, default expressions, annotations, class bases and keywords) that is new or changed must be
    built from literals and plain names only."""
    tb, tp = _parse(base_src), _parse(post_src)
    if tb is None or tp is None:
        return "source does not parse"
    if _module_level_code(tb) != _module_level_code(tp):
        return "module-level statements differ (import-time behaviour)"
    hb, hp = _headers(tb), _headers(tp)
    for name in sorted(set(hb) | set(hp)):
        if hb.get(name) == hp.get(name):
            continue
        for h in (hb.get(name), hp.get(name)):
            if h is not None and not h[1]:
                return f"the definition header of {name} (decorators, defaults, annotations or bases) changed or is new and is not a plain literal header"
    return None


def _headers(tree) -> dict:
    out: dict = {}

    def simple(e, depth=0) -> bool:
        if e is None:
            return True
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Name):
            return True  # a name lookup at definition time: a builtin or module-level name (a missing name would fail in both versions or is caught by the differential import)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, (ast.USub, ast.UAdd)):
            return simple(e.operand, depth + 1)
        if isinstance(e, (ast.Tuple, ast.List)) and depth < 3:
            return all(simple(x, depth + 1) for x in e.elts)
        if isinstance(e, ast.Subscript) and depth < 3:  # list[int], Optional[str], tuple[int, ...]
            return simple(e.value, depth + 1) and simple(e.slice, depth + 1)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.BitOr) and depth < 3:  # int | None
            return simple(e.left, depth + 1) and simple(e.right, depth + 1)
        if isinstance(e, ast.Attribute) and depth < 3:
            return simple(e.value, depth + 1)
        return False

    def visit(body, prefix):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = st.args
                parts = [*st.decorator_list, *a.defaults, *[d for d in a.kw_defaults if d is not None], st.returns,
                         *[p.annotation for p in [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]]]
                ok = not st.decorator_list or all(isinstance(d, ast.Name) and d.id in ("staticmethod", "classmethod", "property") for d in st.decorator_list)
                ok = ok and all(simple(x) for x in parts if x is not None and x not in st.decorator_list)
                text = "|".join(ast.dump(x, annotate_fields=False, include_attributes=False) for x in parts if x is not None) + "|" + ",".join(p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs])
                out[prefix + st.name] = (text, ok)
            elif isinstance(st, ast.ClassDef):
                parts = [*st.decorator_list, *st.bases, *[k.value for k in st.keywords]]
                ok = not st.decorator_list and not st.keywords and all(simple(x) for x in st.bases)
                body_other = [ast.dump(x, annotate_fields=False, include_attributes=False) for x in st.body if not isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
                # class-level statements run at import: any difference there is not a plain header (ok False when they differ is decided by comparing texts)
                text = "|".join(ast.dump(x, annotate_fields=False, include_attributes=False) for x in parts) + "||" + "|".join(body_other)
                simple_body = all(_simple_class_stmt(x) for x in st.body if not isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
                out[prefix + st.name] = (text, ok and simple_body)
                visit(st.body, prefix + st.name + ".")

    def _simple_class_stmt(x) -> bool:
        if isinstance(x, ast.Pass):
            return True
        if isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant):
            return True
        if isinstance(x, ast.Assign):
            return simple(x.value)
        if isinstance(x, ast.AnnAssign):
            return simple(x.value) and simple(x.annotation)
        return False

    visit(tree.body, "")
    return out


def call_sites(files: dict, function_leaf: str, param_order: list, checks: dict) -> tuple:
    """Scan call sites of a callable NAMED like the target in one tree. `checks` maps parameter -> predicate(expr) that is True when the argument expression PROVABLY violates the
    typed domain. Returns (calls seen, refusal texts, exposure counters)."""
    seen, refusals = 0, []
    exposure = {"forwarded_params": 0, "unresolved_args": 0}
    pos = {p: i for i, p in enumerate(param_order)}
    for rel, src in files.items():
        if function_leaf not in src:
            continue
        tr = _parse(src)
        if tr is None:
            continue
        classes = {n.name for n in ast.walk(tr) if isinstance(n, ast.ClassDef)}
        for n in ast.walk(tr):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            nm = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if nm != function_leaf:
                continue
            seen += 1
            for p, bad in checks.items():
                arg = None
                i = pos.get(p)
                if i is not None and i < len(n.args) and not any(isinstance(a, ast.Starred) for a in n.args[: i + 1]):
                    arg = n.args[i]
                for kw in n.keywords:
                    if kw.arg == p:
                        arg = kw.value
                if arg is None:
                    continue
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id in classes:
                    refusals.append(f"{rel}:{getattr(n, 'lineno', '?')} passes an instance of the in-tree class {arg.func.id} to {p}")
                elif bad(arg):
                    refusals.append(f"{rel}:{getattr(n, 'lineno', '?')} passes a value that is not of the stated type to {p}")
                elif isinstance(arg, ast.Name):
                    exposure["forwarded_params"] += 1
                elif not isinstance(arg, (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Dict, ast.Set)):
                    exposure["unresolved_args"] += 1
    return seen, refusals, exposure


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def non_py_changed(base_root, post_root) -> list[str] | None:
    """Sorted relative paths of non-.py files that differ between base_root and post_root, or None if over cap or not completely scannable."""
    def snap(root) -> dict[str, str] | None:
        try:
            others = _walked(root).others
        except TreeTooLarge:
            return None
        if len(others) > MAX_FILES:
            return None
        out: dict[str, str] = {}
        for rel, p in others.items():
            try:
                if p.is_symlink():
                    out[rel] = "link:" + os.readlink(p)
                elif p.is_file():
                    h = hashlib.sha256()
                    with p.open("rb") as fh:
                        while True:
                            chunk = fh.read(65536)
                            if not chunk:
                                break
                            h.update(chunk)
                    out[rel] = h.hexdigest()
            except OSError:
                out[rel] = "unreadable"
        return out

    sb, sp = snap(base_root), snap(post_root)
    if sb is None or sp is None:
        return None
    return sorted(k for k in set(sb) | set(sp) if sb.get(k) != sp.get(k))
