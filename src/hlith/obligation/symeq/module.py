# SPDX-License-Identifier: Apache-2.0
"""Static facts about one side's module for the symbolic equivalence prover: definitions, literal constants, import origins, scopes and the TAINT analysis.

Taint is the prover's guard against comparing two different things under one name. An opaque operation (a call of a function that is not inlined, an attribute read, a method call on
an unknown object) is modelled as the SAME uninterpreted function before and after the change, which is only sound when the code behind that name did not change. Every identifier bound
by a definition that differs between the two versions, and (transitively) every function or class that mentions such an identifier, is tainted; the prover refuses any opaque use of a
tainted identifier. Inlining a changed helper is always sound (each side executes its own text) and is not affected."""

from __future__ import annotations

import ast
import builtins

_BUILTIN_NAMES = frozenset(dir(builtins))


def strip_doc(body):
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[1:]
    return body


_NOFOLD = object()
_FOLD_MAX = 10 ** 30


def fold_literal(e):
    """Value of a literal expression (int / float / str / bytes / bool / None, unary minus on a number, tuples of those) or _NOFOLD. No arithmetic is folded here."""
    if isinstance(e, ast.Constant):
        v = e.value
        if v is None or type(v) in (str, bytes, bool, float):
            return v
        if type(v) is int and abs(v) <= _FOLD_MAX:
            return v
        return _NOFOLD
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, (ast.USub, ast.UAdd)) and isinstance(e.operand, ast.Constant) and type(e.operand.value) in (int, float):
        v = e.operand.value
        return -v if isinstance(e.op, ast.USub) else v
    if isinstance(e, ast.Tuple):
        vs = [fold_literal(x) for x in e.elts]
        return tuple(vs) if all(v is not _NOFOLD for v in vs) else _NOFOLD
    return _NOFOLD


def scope_nodes(fn):
    """Nodes of a function's OWN scope: nested function / lambda / class bodies and comprehension scopes are not descended into (their heads are yielded)."""
    body = fn.body if isinstance(fn.body, list) else [fn.body]
    stack = list(reversed(body))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            # the FIRST iterable is evaluated in the enclosing scope
            stack.append(n.generators[0].iter)
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def local_names(fn) -> set:
    """Names that are local to the function (parameters and every name bound in its own scope)."""
    a = fn.args
    out = {p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]}
    if a.vararg:
        out.add(a.vararg.arg)
    if a.kwarg:
        out.add(a.kwarg.arg)
    body = fn.body if isinstance(fn.body, list) else [fn.body]
    for st in body:
        for n in scope_nodes(_Wrap([st])):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                out.add(n.name)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(n.name)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for al in n.names:
                    out.add((al.asname or al.name).split(".")[0])
            elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
                out.add(n.name)
    return out


class _Wrap:
    """Lets scope_nodes walk an arbitrary statement list."""

    def __init__(self, body):
        self.body = body


def idents(node) -> set:
    """Every identifier a piece of code mentions as a name or an attribute (over-approximation used by taint)."""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                out.add((al.asname or al.name).split(".")[0])
                out.add(al.name.split(".")[-1])
    return out


def _dump(n) -> str:
    return ast.dump(n, annotate_fields=False, include_attributes=False)


def binding_table(tree) -> dict:
    """identifier -> sorted list of canonical dumps of every statement that BINDS it anywhere in the module (module level, class bodies, nested functions): definitions, assignments,
    imports. Two versions of a module agree on an identifier iff their lists are equal."""
    out: dict = {}

    def add(name, node):
        out.setdefault(name, []).append(_dump(node))

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(n.name, n)
        elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in tgts:
                for m in ast.walk(t):
                    if isinstance(m, ast.Name):
                        add(m.id, n)
                    elif isinstance(m, ast.Attribute):
                        add(m.attr, n)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                add((al.asname or al.name).split(".")[0], n)
        elif isinstance(n, ast.Global):
            for nm in n.names:
                add(nm, n)
    return {k: sorted(v) for k, v in out.items()}


def changed_identifiers(base_tree, post_tree) -> set:
    """Identifiers whose binding statements differ between the two versions of one module."""
    tb, tp = binding_table(base_tree), binding_table(post_tree)
    return {k for k in set(tb) | set(tp) if tb.get(k) != tp.get(k)}


def taint_closure(trees, seed: set) -> set:
    """Close `seed` under 'a definition that mentions a tainted identifier is tainted' over every given module tree (both versions of every file)."""
    defs = []  # (name, identifiers mentioned)
    for tr in trees:
        for n in ast.walk(tr):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs.append((n.name, idents(n)))
            elif isinstance(n, ast.Assign):
                names = {m.id for t in n.targets for m in ast.walk(t) if isinstance(m, ast.Name)} | {m.attr for t in n.targets for m in ast.walk(t) if isinstance(m, ast.Attribute)}
                if names:
                    ids = idents(n.value)
                    for nm in names:
                        defs.append((nm, ids))
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for name, ids in defs:
            if name not in tainted and ids & tainted:
                tainted.add(name)
                changed = True
    return tainted


class ModuleInfo:
    """One side's module."""

    def __init__(self, src: str):
        self.tree = ast.parse(src)
        self.funcs: dict = {}
        self.classes: dict = {}
        self.methods: dict = {}  # "Class.method" -> FunctionDef
        self.imports: dict = {}  # local name -> dotted origin
        self.consts: dict = {}  # name -> python literal value
        self.module_names: set = set()
        self.future_annotations: bool = False
        stores: dict = {}
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Global):
                for nm in n.names:
                    stores[nm] = stores.get(nm, 0) + 5
        assigns = []
        for st in self.tree.body:
            if isinstance(st, ast.FunctionDef):
                self.funcs[st.name] = st
                self.module_names.add(st.name)
                stores[st.name] = stores.get(st.name, 0) + 1
            elif isinstance(st, ast.AsyncFunctionDef):
                self.module_names.add(st.name)
                stores[st.name] = stores.get(st.name, 0) + 1
            elif isinstance(st, ast.ClassDef):
                self.classes[st.name] = st
                self.module_names.add(st.name)
                stores[st.name] = stores.get(st.name, 0) + 1
                for m in st.body:
                    if isinstance(m, ast.FunctionDef):
                        self.methods[f"{st.name}.{m.name}"] = m
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                if isinstance(st, ast.ImportFrom) and st.level == 0 and st.module == "__future__":
                    if any(al.name == "annotations" for al in st.names):
                        self.future_annotations = True
                for al in st.names:
                    if al.name == "*":
                        self.star_import = True
                        continue
                    local = (al.asname or al.name).split(".")[0]
                    if isinstance(st, ast.Import):
                        origin = al.name if al.asname else al.name.split(".")[0]
                    else:
                        origin = ("." * st.level) + (st.module or "") + "." + al.name
                    self.imports[local] = origin
                    self.module_names.add(local)
                    stores[local] = stores.get(local, 0) + 1
            else:
                for n in scope_nodes(_Wrap([st])):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                        self.module_names.add(n.id)
                        stores[n.id] = stores.get(n.id, 0) + 1
                    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        self.module_names.add(n.name)
                        stores[n.name] = stores.get(n.name, 0) + 1
                    elif isinstance(n, (ast.Import, ast.ImportFrom)):
                        for al in n.names:
                            nm = (al.asname or al.name).split(".")[0]
                            self.module_names.add(nm)
                            stores[nm] = stores.get(nm, 0) + 1
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    assigns.append(st)
                elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                    assigns.append(st)
        self.star_import = getattr(self, "star_import", False)
        for st in assigns:
            nm = st.targets[0].id if isinstance(st, ast.Assign) else st.target.id
            if stores.get(nm, 0) == 1:
                v = fold_literal(st.value)
                if v is not _NOFOLD:
                    self.consts[nm] = v
        self.multi_bound = {n for n, c in stores.items() if c > 1}
        for nm in list(self.imports):
            if nm in self.multi_bound:
                del self.imports[nm]
        for nm in list(self.funcs):
            if nm in self.multi_bound:
                del self.funcs[nm]

    def find(self, qualname: str):
        """(FunctionDef, owning ClassDef | None) for 'f' or 'Class.method'."""
        if qualname in self.funcs:
            return self.funcs[qualname], None
        if qualname in self.methods:
            c = qualname.split(".")[0]
            if c in self.multi_bound:
                return None, None
            return self.methods[qualname], self.classes[c]
        return None, None

    def is_builtin(self, name: str) -> bool:
        return name in _BUILTIN_NAMES and name not in self.module_names and not self.star_import
