# SPDX-License-Identifier: Apache-2.0
"""Positive-HELD eligibility certificate (case, Phase 3).

A differential HELD is only eligible when, for the target and its WHOLE dependency cone (helpers reachable by name, module-level statements, module constants, imports),
base and post are

  * SYNTACTICALLY IDENTICAL modulo consistent renaming (rule R0), except
  * regions covered by a CERTIFIED REWRITE RULE whose side conditions are machine-checked over the declared typed domain:
      R2  approved guard insertion  (`if G: raise E(literal)` whose path condition AND G equal the approved delta predicate; everything else identical)
      R3  pure boolean reorder      (bool-valued returns over pure, total atoms: truth-table equal)
      R4  hoisted skip              (a pure, total `if S: continue` moved ahead of a try whose every outcome on S-true inputs is the same `continue`)

Anything else is UNKNOWN, with a NAMED reason, and the caller reports UNVERIFIED. The certificate never raises a verdict above what the other gates allow, is never an adequacy
waiver, and claims NOTHING about soundness of the whole gate: it bounds one class (changes that are not provably the identity or a certified rewrite are refused).

Declared assumptions (stated, never hidden): the pinned CPython and builtins; a stdlib module imported by name is the stdlib (an in-tree shadow is refused); resource exhaustion
(MemoryError, timeouts, KeyboardInterrupt) is outside the equivalence claim; the target is a top-level function (method receivers are UNKNOWN)."""

from __future__ import annotations

import ast
import builtins
import hashlib
import itertools
import re
import sys
import symtable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Cert:
    """`domain` = ((parameter, exact builtin type), ...) the certified rules assume (R2/R3: exact builtin str); `domain_text` is the sentence the HELD claim and evidence carry.
    A bare annotation is not runtime enforcement and Hlith binds no caller type: the domain is a stated LIMIT OF THE CLAIM (instances of subclasses that override methods, and other
    types, are outside it), never a silent assumption."""
    ok: bool
    reason: str = ""
    rules: tuple = ()
    detail: str = ""
    domain: tuple = ()
    domain_text: str = ""
    domain_record: dict = field(default_factory=dict, compare=False)  # machine-readable, hashed (see _domain_record); {} when no input-type assumption is made
    domain_sha256: str = ""
    symbolic_candidate: bool = field(default=False, compare=False, repr=False)


class _Unknown(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason, self.detail = reason, detail


_DYNAMIC = frozenset({"getattr", "setattr", "delattr", "eval", "exec", "globals", "locals", "vars", "__import__", "compile", "importlib", "breakpoint", "open", "input"})
_EXC_BUILTINS = frozenset({"ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError", "AssertionError", "LookupError", "ArithmeticError", "OverflowError",
                           "ZeroDivisionError", "AttributeError", "NotImplementedError", "UnicodeError", "OSError", "Exception"})
_STR_PRED_METHODS = frozenset({"startswith", "endswith", "isdigit", "isalpha", "isalnum", "isspace", "islower", "isupper", "isidentifier", "isascii", "isnumeric", "isdecimal"})
_STDLIB_STRING_CONSTS = frozenset({"ascii_letters", "ascii_lowercase", "ascii_uppercase", "digits", "hexdigits", "octdigits", "punctuation", "printable", "whitespace"})
_SUBCLASSABLE_BUILTINS = frozenset({"str", "int", "float", "bytes", "list", "tuple", "dict", "set", "frozenset"})
_FOLD_MAX = 10 ** 18


# ================================================================================================================ module model
def _strip_doc(body):
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _fold(e):
    """Value of a PURE literal expression (int/float/str/bytes/bool/None/tuple of those; unary +/- on a literal; + - * // on INTS only) or `_NOFOLD`."""
    if isinstance(e, ast.Constant):
        v = e.value
        if type(v) is int:
            return v if abs(v) <= _FOLD_MAX else _NOFOLD
        return v if v is None or type(v) in (str, bytes, bool, float) else _NOFOLD  # a float LITERAL is a value (G1); no float arithmetic is ever folded
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, (ast.USub, ast.UAdd)):
        v = _fold(e.operand)
        if type(v) is float:
            return -v if isinstance(e.op, ast.USub) else v  # exact: negation of a literal (0.0 -> -0.0 keeps its sign)
        return _NOFOLD if type(v) is not int else (-v if isinstance(e.op, ast.USub) else v)
    if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)):
        a, b = _fold(e.left), _fold(e.right)
        if type(a) is not int or type(b) is not int:
            return _NOFOLD
        if isinstance(e.op, ast.FloorDiv):
            if b == 0:
                return _NOFOLD
            v = a // b
        else:
            v = a + b if isinstance(e.op, ast.Add) else a - b if isinstance(e.op, ast.Sub) else a * b
        return v if abs(v) <= _FOLD_MAX else _NOFOLD
    if isinstance(e, ast.Tuple):
        vs = [_fold(x) for x in e.elts]
        return tuple(vs) if all(v is not _NOFOLD for v in vs) else _NOFOLD
    return _NOFOLD


_NOFOLD = object()


def _class_scan(tree, prefix: str = "") -> tuple:
    """(qualified class name -> canonical dump, dict builtin_name -> set of subclass qualified names) for every ClassDef in `tree` (including transitive subclasses)."""
    classes: dict = {}
    bases_by_short: dict = {}
    full_by_short: dict = {}

    def walk(node, qual):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                q = qual + [ch.name]
                full = prefix + ".".join(q)
                classes[full] = ast.dump(ch, annotate_fields=False, include_attributes=False)
                bnames = set()
                for b in ch.bases:
                    if isinstance(b, ast.Name):
                        bnames.add(b.id)
                    elif isinstance(b, ast.Attribute):
                        bnames.add(b.attr)
                bases_by_short.setdefault(ch.name, set()).update(bnames)
                full_by_short.setdefault(ch.name, set()).add(full)
                walk(ch, q)
            else:
                walk(ch, qual)

    walk(tree, [])
    subs_by_base: dict = {b: set() for b in _SUBCLASSABLE_BUILTINS}
    for base in _SUBCLASSABLE_BUILTINS:
        found_short = {short for short, bs in bases_by_short.items() if base in bs}
        changed = True
        while changed:
            changed = False
            for short, bs in bases_by_short.items():
                if short not in found_short and (bs & found_short):
                    found_short.add(short)
                    changed = True
        for short in found_short:
            subs_by_base[base].update(full_by_short.get(short, ()))
    return classes, subs_by_base


def _walked(root):
    """The one tree enumeration (closure_gate.walk): nothing skipped by directory name; an unreadable or unattributable file refuses."""
    from hlith.obligation.closure_gate import TreeRefused, walk

    try:
        return walk(root)
    except TreeRefused as e:
        raise _Unknown("the source tree cannot be scanned completely (UNKNOWN): " + str(e)) from None


def _tree_classes(root) -> tuple:
    """_class_scan over every non-test_*.py-named file under `root`, test directories excluded."""
    classes: dict = {}
    subs_by_base: dict = {b: set() for b in _SUBCLASSABLE_BUILTINS}
    for rel, tree in sorted(_walked(root).trees.items()):
        if _scan_excluded(rel):
            continue
        c, s = _class_scan(tree, rel + ":")
        classes.update(c)
        for base, vals in s.items():
            subs_by_base[base].update(vals)
    return classes, subs_by_base


def _scan_excluded(rel: str) -> bool:
    """The repository's own tests: a tests/ or test/ directory, or a test_*.py file (the import closure is scanned separately, tests included)."""
    *dirs, name = rel.split("/")
    return any(d in ("tests", "test") for d in dirs) or name.startswith("test_")


def _tree_trees(root, side: str, include_tests: bool = False) -> list:
    """Parsed (label, ast.Module) for every non-test .py file under `root`; with include_tests the repo's own test files are read too (call-site scan only)."""
    return [(f"{side}:{rel}", tree) for rel, tree in sorted(_walked(root).trees.items()) if include_tests or not _scan_excluded(rel)]


def _module_stores(body) -> dict:
    """Names stored at MODULE level (function and class bodies are other scopes) plus every `global` declaration (weighted so the name is never a constant)."""
    out: dict = {}

    def walk(n):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            for g in ast.walk(n):
                if isinstance(g, ast.Global):
                    for nm in g.names:
                        out[nm] = out.get(nm, 0) + 5
            return
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out[n.id] = out.get(n.id, 0) + 1
        for ch in ast.iter_child_nodes(n):
            walk(ch)

    for st in body:
        walk(st)
    return out


class _Mod:
    """One side's module: functions, constants, regexes, imports and the module-level statements that are compared as text."""

    def __init__(self, src: str, root: Path | None, import_root: str, imm_dicts=frozenset()):
        self.dicts: dict = {}  # immutable dict literals proven by equiv_norm._module_facts: name -> canonical dump
        self.source = src
        self.src_sha = hashlib.sha256(src.encode("utf-8", "surrogatepass")).hexdigest()
        try:
            self.tree = ast.parse(src)
        except (SyntaxError, ValueError) as e:
            raise _Unknown("source does not parse", type(e).__name__)
        self.root, self.import_root = root, import_root
        body = _strip_doc(self.tree.body)
        self.funcs: dict = {}
        self.async_funcs: set = set()
        self.decorated: set = set()
        self.classes: dict = {}
        self.imports: list = []
        self.import_names: dict = {}
        stmts: list = []
        assigned: dict = {}
        for st in body:
            if isinstance(st, ast.FunctionDef):
                self.funcs[st.name] = st
                if st.decorator_list:
                    self.decorated.add(st.name)
            elif isinstance(st, ast.AsyncFunctionDef):
                self.async_funcs.add(st.name)
            elif isinstance(st, ast.ClassDef):
                self.classes[st.name] = st
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                self.imports.append(st)
                for al in st.names:
                    nm = (al.asname or al.name).split(".")[0]
                    self.import_names[nm] = self.import_names.get(nm, 0) + 1
            else:
                stmts.append(st)
        # every name stored anywhere at module level or declared global in a function
        stores = _module_stores(self.tree.body)
        self.consts: dict = {}
        self.regexes: dict = {}
        self.frozensets: dict = {}
        self.other_stmts: list = []
        clean_re = (self.import_names.get("re") == 1 and stores.get("re", 0) == 0
                    and any(isinstance(imp, ast.Import) and any(al.name == "re" and al.asname is None for al in imp.names) for imp in self.imports))
        clean_string = (self.import_names.get("string") == 1 and stores.get("string", 0) == 0
                        and any(isinstance(imp, ast.Import) and any(al.name == "string" and al.asname is None for al in imp.names) for imp in self.imports))
        clean_frozenset = (stores.get("frozenset", 0) == 0 and "frozenset" not in self.funcs
                           and "frozenset" not in self.classes and "frozenset" not in self.import_names)
        for st in stmts:
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                nm = st.targets[0].id
                if nm in imm_dicts and isinstance(st.value, ast.Dict) and stores.get(nm, 0) == 1:
                    self.dicts[nm] = ast.dump(st.value, annotate_fields=False, include_attributes=False)
                    continue
                if stores.get(nm, 0) == 1 and nm not in self.funcs and nm not in self.classes and nm not in self.import_names:
                    v = _fold(st.value)
                    if v is not _NOFOLD:
                        self.consts[nm] = v
                        continue
                    pat = self._regex(st.value) if clean_re else None
                    if pat is not None:
                        self.regexes[nm] = pat
                        continue
                    fs = self._frozenset(st.value, clean_string) if clean_frozenset else None
                    if fs is not None:
                        self.frozensets[nm] = fs
                        continue
            self.other_stmts.append(st)
        self.mutable_globals = {n for n, c in stores.items() if n not in self.consts and n not in self.regexes and n not in self.dicts and n not in self.frozensets}
        for nm, c in self.import_names.items():
            if c > 1 or stores.get(nm, 0):
                self.mutable_globals.add(nm)  # an import name rebound elsewhere is NOT the import
        self.classes_all, self.builtin_subs = _class_scan(self.tree)  # replaced by a tree-wide scan in certify()
        self.str_subs = self.builtin_subs.get("str", set())
        self.dynamic_reason = _dynamic_reason(self.tree)
        self.future_annotations = any(isinstance(s, ast.ImportFrom) and s.module == "__future__" and any(al.name == "annotations" for al in s.names) for s in self.tree.body)
        self.typing_names = {(al.asname or al.name): al.name for s in self.imports if isinstance(s, ast.ImportFrom) and (s.module or "") in _ANN_TYPING_MODULES for al in s.names}
        self.typing_modules = {(al.asname or al.name).split(".")[0] for s in self.imports if isinstance(s, ast.Import) for al in s.names if al.name in _ANN_TYPING_MODULES}

    @staticmethod
    def _regex(v):
        if (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "compile" and isinstance(v.func.value, ast.Name) and v.func.value.id == "re"
                and len(v.args) == 1 and not v.keywords and isinstance(v.args[0], ast.Constant) and isinstance(v.args[0].value, str)):
            return v.args[0].value
        return None

    @staticmethod
    def _frozenset(v, clean_string: bool):
        """Canonical key of an immutable `frozenset(...)` built from pure literals or a clean stdlib `string.<CONST>`."""
        if not (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "frozenset" and not v.keywords and len(v.args) <= 1):
            return None
        if not v.args:
            return "()"
        arg = v.args[0]
        if (clean_string and isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == "string"
                and arg.attr in _STDLIB_STRING_CONSTS):
            import string as _string
            elems = getattr(_string, arg.attr)
            return repr(sorted({(type(x).__name__, x) for x in elems}))
        folded = _fold(arg)
        if folded is not _NOFOLD and isinstance(folded, (str, bytes, tuple)):
            try:
                return repr(sorted({(type(x).__name__, x) for x in folded}, key=repr))
            except TypeError:
                return None
        if isinstance(arg, (ast.List, ast.Set, ast.Tuple)):
            vals = [_fold(x) for x in arg.elts]
            if all(x is not _NOFOLD and (x is None or type(x) in (str, bytes, int, bool)) for x in vals):
                return repr(sorted({(type(x).__name__, x) for x in vals}, key=repr))
        return None


# ================================================================================================================ canonicalisation
class _Canon(ast.NodeTransformer):
    """Rename locals to slots, helper functions to discovery ids, module constants to values, regex names to their pattern; fold literal arithmetic; refuse everything
    the kernel does not model (decorators, nested defs, dynamic names, unresolved or mutable globals, classes)."""

    def __init__(self, mod: _Mod, fn: ast.FunctionDef | None, param_map: dict, ids: dict, order: list, kw_called: set, outer_map: dict | None = None, depth: int = 0):
        self.mod, self.ids, self.order, self.kw_called = mod, ids, order, kw_called
        self.param_map = param_map
        self.outer_map = outer_map or {}
        self.depth = depth
        self.locals: dict = {}
        self.fn = fn
        self.hexc = {}
        self.lam = 0
        self.const_reads: set = set()  # (name, value-key) of every module-level constant / regex / dict / frozenset the code READS (inlined)

    # ---- scope bookkeeping
    def bind_local(self, name: str):
        if name in self.param_map:
            return
        if name not in self.locals:
            prefix = f"n{self.depth}_v" if self.depth else "v"
            self.locals[name] = f"{prefix}{len(self.locals)}"

    def scan_bindings(self, node):
        for n in _scope_dfs(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                self.bind_local(n.id)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                self.bind_local(n.name)
            elif isinstance(n, ast.FunctionDef):
                if n.decorator_list:
                    raise _Unknown("decorated nested definition", n.name)
                if self.depth >= 4:
                    raise _Unknown("nested definition depth exceeded", n.name)
                if n.name not in self.param_map:
                    # Keep the nested function's own name identity so __name__/__qualname__ cannot diverge.
                    self.locals[n.name] = f"FN:{n.name}"
            elif isinstance(n, (ast.AsyncFunctionDef, ast.ClassDef)):
                raise _Unknown("nested definition", getattr(n, "name", ""))
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                raise _Unknown("global/nonlocal declaration")
            elif isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                raise _Unknown("generator/await in the cone")
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                raise _Unknown("function-local import")
            elif isinstance(n, ast.Match):
                raise _Unknown("match statement")

    def visit_FunctionDef(self, node):
        """Canonicalize a lexically scoped undecorated nested function: defaults/annotations resolve in the enclosing scope;
        its body runs in a child lexical scope whose enclosing closures map consistently through outer_map."""
        if node.decorator_list:
            raise _Unknown("decorated nested definition", node.name)
        a = node.args
        a.defaults = [self.visit(d) for d in a.defaults]
        a.kw_defaults = [self.visit(d) if d is not None else None for d in a.kw_defaults]
        plist = [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]
        child_pmap = {p.arg: p.arg for p in plist}
        outer = {**self.outer_map, **self.param_map, **self.locals}
        child = _Canon(self.mod, node, child_pmap, self.ids, self.order, self.kw_called, outer_map=outer, depth=self.depth + 1)
        node.body = list(_strip_doc(node.body))
        for st in node.body:
            child.scan_bindings(st)
        node.body = [child.visit(st) for st in node.body]
        self.const_reads |= child.const_reads
        return node

    def visit_Call(self, node):
        """Allow statically named non-dunder getattr(obj, 'attr'[, default]) when builtin getattr is unshadowed."""
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr" and not node.keywords
                and len(node.args) in (2, 3) and not any(isinstance(a, ast.Starred) for a in node.args)
                and "getattr" not in self.param_map and "getattr" not in self.locals and "getattr" not in self.outer_map
                and "getattr" not in self.mod.mutable_globals and "getattr" not in self.mod.funcs
                and "getattr" not in self.mod.classes and "getattr" not in self.mod.import_names
                and isinstance(node.args[1], ast.Constant) and type(node.args[1].value) is str
                and node.args[1].value.isidentifier() and not node.args[1].value.startswith("__")):
            node.args = [self.visit(a) for a in node.args]
            return node
        return self.generic_visit(node)

    # ---- names
    def visit_Name(self, node):
        i = node.id
        if i in self.param_map:
            return ast.copy_location(ast.Name(id=self.param_map[i], ctx=node.ctx), node)
        if i in self.locals:
            return ast.copy_location(ast.Name(id=self.locals[i], ctx=node.ctx), node)
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            raise _Unknown("store to a non-local name", i)
        if i in self.outer_map:
            return ast.copy_location(ast.Name(id=self.outer_map[i], ctx=node.ctx), node)
        m = self.mod
        if i in _DYNAMIC:
            raise _Unknown("dynamic name in the cone", i)
        if i in m.consts:
            v = m.consts[i]
            self.const_reads.add((i, "c:" + repr((type(v).__name__, v))))
            return ast.copy_location(_const_node(v), node)
        if i in m.regexes:
            self.const_reads.add((i, "re:" + m.regexes[i]))
            return ast.copy_location(ast.Name(id="RX:" + m.regexes[i], ctx=node.ctx), node)
        if i in m.frozensets:
            self.const_reads.add((i, "fs:" + m.frozensets[i]))
            return ast.copy_location(ast.Name(id="FS:" + m.frozensets[i], ctx=node.ctx), node)
        if i in m.dicts:
            self.const_reads.add((i, "d:" + m.dicts[i]))
            return ast.copy_location(ast.Name(id="DICT:" + m.dicts[i], ctx=node.ctx), node)
        if i in m.funcs:
            if i in m.decorated:
                raise _Unknown("decorated function in the cone", i)
            if i not in self.ids:
                self.ids[i] = f"H{len(self.ids) - 1}"
                self.order.append(i)
            return ast.copy_location(ast.Name(id=self.ids[i], ctx=node.ctx), node)
        if i in m.async_funcs:
            raise _Unknown("async function in the cone", i)
        if i in m.classes:
            raise _Unknown("class in the cone is not modelled", i)
        if i in m.import_names:
            if i in m.mutable_globals:
                raise _Unknown("import name rebound (not the import)", i)
            return node
        if i in m.mutable_globals:
            raise _Unknown("mutable or unmodelled module global", i)
        if hasattr(builtins, i):
            if i in m.mutable_globals:
                raise _Unknown("builtin name shadowed", i)
            return node
        raise _Unknown("unresolved global name", i)

    def visit_Lambda(self, node):
        """A lambda's parameters are their own scope: renamed uniquely and restored afterwards; its body resolves names like any expression."""
        saved = dict(self.param_map)
        a = node.args
        for i, p in enumerate([*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]):
            self.param_map[p.arg] = f"lam{self.lam}_{i}"
        self.lam += 1
        node.args = self.visit(node.args)
        node.body = self.visit(node.body)
        self.param_map = saved
        return node

    def visit_ExceptHandler(self, node):
        self.generic_visit(node)
        if node.name:
            node.name = self.locals.get(node.name, node.name)
        return node

    # ---- folding
    def visit_BinOp(self, node):
        self.generic_visit(node)
        v = _fold(node)
        return ast.copy_location(_const_node(v), node) if v is not _NOFOLD and type(v) is int else node

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        v = _fold(node)
        return ast.copy_location(_const_node(v), node) if v is not _NOFOLD and type(v) is int else node

    def visit_arg(self, node):
        node.arg = self.param_map.get(node.arg, node.arg)
        return node


def _const_node(v):
    if isinstance(v, tuple):
        return ast.Tuple(elts=[_const_node(x) for x in v], ctx=ast.Load())
    return ast.Constant(value=v)


def _dfs(node):
    yield node
    for ch in ast.iter_child_nodes(node):
        yield from _dfs(ch)


def _scope_dfs(node):
    """Depth-first walk within a single function scope: yields nested FunctionDef headers without descending into their bodies."""
    yield node
    if isinstance(node, ast.FunctionDef):
        return
    for ch in ast.iter_child_nodes(node):
        yield from _scope_dfs(ch)


def _dump(n) -> str:
    return ast.dump(n, annotate_fields=True, include_attributes=False)


def _d(x) -> str:
    return _dump(x) if x is not None else "None"


def _dumps(lst) -> list:
    return [_dump(x) for x in lst]


def _canon_def(mod: _Mod, name: str, target: bool, ids: dict, order: list, kw_called: set, numbering: str = "order"):
    """numbering='order': locals numbered by first binding (robust to local renames). numbering='name': numbered by sorted ORIGINAL name (robust to statement reordering,
    used by the reordering rules; sensitive to renames, which is conservative)."""
    import copy as _copy
    fn = mod.funcs[name]
    if fn.decorator_list:
        raise _Unknown("decorated function in the cone", name)
    a = fn.args
    plist = [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]
    pnames = [p.arg for p in plist]
    rename = (not target) and name not in kw_called and not a.kwonlyargs and not a.vararg and not a.kwarg
    pmap = {p: (f"a{i}" if rename else p) for i, p in enumerate(pnames)}
    cw = _Canon(mod, fn, pmap, ids, order, kw_called)
    new = _copy.deepcopy(fn)
    new.name = "T" if target else ids[name]
    new.decorator_list = []
    new.body = list(_strip_doc(new.body))
    for st in new.body:
        cw.scan_bindings(st)
    if numbering == "name":
        cw.locals = {n: f"v{i}" for i, n in enumerate(sorted(cw.locals))}
    new.args = cw.visit(new.args)  # defaults are resolved like any expression; annotations stay as written (a call does not execute them)
    new.body = [cw.visit(st) for st in new.body]
    return new, cw


_REBIND_NAMES = frozenset({"globals", "vars", "locals", "exec", "eval", "setattr", "__import__"})


def _dynamic_reason(tree) -> str:
    """Why this module's own attributes could be rebound behind the analysis' back (globals()/vars()/exec/eval/setattr/__dict__/sys.modules), else ''."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in _REBIND_NAMES:
            return n.id + "()"
        if isinstance(n, ast.Attribute) and (n.attr == "__dict__" or (n.attr == "modules" and isinstance(n.value, ast.Name) and n.value.id == "sys")):
            return n.attr
        if isinstance(n, ast.Name) and n.id == "__dict__":
            return "__dict__"
    return ""


def _tree_rebinds(trees, names) -> str:
    """Another file of the tree storing to one of `names` as an attribute, setattr-ing it, or writing it through __dict__ / vars() / globals(); '' when none."""
    for label, tr in trees:
        for n in ast.walk(tr):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.attr in names:
                return f"{label}: attribute store {n.attr}"
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "setattr" and len(n.args) >= 2:
                a1 = n.args[1]
                if not isinstance(a1, ast.Constant) or a1.value in names:
                    return f"{label}: setattr"
            if isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)):
                v = n.value
                if (isinstance(v, ast.Attribute) and v.attr == "__dict__") or (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in ("vars", "globals")):
                    return f"{label}: write through __dict__/vars()/globals()"
    return ""


def _escaping_names(trees, names) -> str:
    """A name of `names` read in a NON-CALL position (passed, aliased, decorated, wrapped, attribute-read, put in a container) in any of the trees: an alias reaches every consumer."""
    for label, tr in trees:
        parent = {}
        for n in ast.walk(tr):
            for ch in ast.iter_child_nodes(n):
                parent[ch] = n
        for n in ast.walk(tr):
            nm = n.id if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) else n.attr if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) else None
            if nm in names:
                par = parent.get(n)
                if not (isinstance(par, ast.Call) and par.func is n):
                    return f"{label}: {nm}"
    return ""

_ANN_CONSUMER_MODULES = frozenset({"inspect", "dataclasses", "pydantic", "attr", "attrs", "typeguard", "beartype", "fastapi", "msgspec", "cattrs", "marshmallow", "annotationlib", "pydoc"})
_ANN_CONSUMER_NAMES = frozenset({"__annotations__", "__annotate__", "get_type_hints", "get_annotations", "signature", "Signature", "singledispatch", "singledispatchmethod", "annotationlib",
                                 "update_wrapper", "wraps", "render_doc", "getdoc", "help", "pydoc", "getfullargspec", "getcallargs"})
_ANN_BUILTIN_TYPES = frozenset({"int", "float", "str", "bool", "bytes", "bytearray", "complex", "list", "dict", "tuple", "set", "frozenset", "object", "type", "range", "memoryview"})
_ANN_TYPING_MODULES = frozenset({"typing", "collections.abc"})


def _ann_consumed(tree) -> str:
    """Name of the first thing in the tree that reads annotations at runtime (an import of a consumer library, or a use of an annotation-reading name), else ''."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for al in n.names:
                if al.name.split(".")[0] in _ANN_CONSUMER_MODULES:
                    return al.name
        elif isinstance(n, ast.ImportFrom):
            if (n.module or "").split(".")[0] in _ANN_CONSUMER_MODULES:
                return n.module or ""
            for al in n.names:
                if al.name in _ANN_CONSUMER_NAMES:
                    return al.name
        elif isinstance(n, ast.Name) and n.id in _ANN_CONSUMER_NAMES:
            return n.id
        elif isinstance(n, ast.Attribute) and n.attr in _ANN_CONSUMER_NAMES:
            return n.attr
    return ""


def _ann_exprs(fn) -> list:
    a = fn.args
    xs = [p.annotation for p in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg] if p is not None and p.annotation is not None]
    if fn.returns is not None:
        xs.append(fn.returns)
    return xs


_GENERIC_ARITY = {"list": 1, "set": 1, "frozenset": 1, "type": 1, "dict": 2, "tuple": "var"}
_TYPING_GENERICS = {"Optional": 1, "List": 1, "Set": 1, "FrozenSet": 1, "Type": 1, "Dict": 2, "Tuple": "var", "Union": "var", "Sequence": 1, "Iterable": 1, "Iterator": 1,
                    "Mapping": 2, "MutableMapping": 2, "Collection": 1}
_TYPING_PLAIN = frozenset({"Any", "List", "Set", "FrozenSet", "Type", "Dict", "Tuple", "Sequence", "Iterable", "Iterator", "Mapping", "MutableMapping", "Collection"})


def _ann_head(mod, e):
    """('builtin'|'typing', name) when `e` names a builtin type the module does not rebind or a typing name imported from typing, else None."""
    if isinstance(e, ast.Name):
        n = e.id
        if n in mod.typing_names and n not in mod.mutable_globals and n not in mod.funcs and n not in mod.classes and mod.import_names.get(n, 0) == 1:
            return ("typing", mod.typing_names[n])
        if n in mod.mutable_globals or n in mod.funcs or n in mod.classes or n in mod.consts or n in mod.regexes or n in mod.async_funcs or n in mod.import_names or n in mod.dicts:
            return None
        if n in _ANN_BUILTIN_TYPES:
            return ("builtin", n)
        return None
    if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id in mod.typing_modules and e.value.id not in mod.mutable_globals:
        return ("typing", e.attr)
    return None


def _ann_pure(mod, e, top: bool = True) -> bool:
    """STRICT definition-time whitelist: evaluating annotation e can neither raise nor act. None; a string literal (a forward reference, only at the top or as a generic argument); a builtin type name
    the module does not rebind; typing names imported from typing; `X | Y` of TYPES (a string or number operand raises); and subscripts of KNOWN generics with VALID arity
    (list/set/frozenset/type[T], dict[K, V], tuple[T, ...] / tuple[T1, T2, ...], Optional/List/Set/FrozenSet/Type[T], Dict[K, V], Tuple[...], Union[...], Sequence/Iterable/Iterator/Collection[T],
    Mapping/MutableMapping[K, V]). No calls, no user names, no malformed subscripts."""
    if isinstance(e, ast.Constant):
        return e.value is None or (type(e.value) is str and top)
    if isinstance(e, (ast.Name, ast.Attribute)):
        h = _ann_head(mod, e)
        if h is None:
            return False
        return h[0] == "builtin" or h[1] in _TYPING_PLAIN
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.BitOr):
        return _ann_pure(mod, e.left, False) and _ann_pure(mod, e.right, False)
    if isinstance(e, ast.Subscript):
        h = _ann_head(mod, e.value)
        if h is None:
            return False
        ar = _GENERIC_ARITY.get(h[1]) if h[0] == "builtin" else _TYPING_GENERICS.get(h[1])
        if ar is None:
            return False
        parts = list(e.slice.elts) if isinstance(e.slice, ast.Tuple) else [e.slice]
        if not parts:
            return False
        is_tuple = h[1] in ("tuple", "Tuple")
        if is_tuple and len(parts) == 2 and isinstance(parts[1], ast.Constant) and parts[1].value is Ellipsis:
            return _ann_pure(mod, parts[0], False)
        if ar != "var" and len(parts) != ar:
            return False
        return all(_ann_pure(mod, x, True) for x in parts)
    return False


def _def_header_safe(mod, fn) -> bool:
    """What a def EVALUATES when the module runs is import-time behaviour: no decorators, defaults that are pure literals, annotations on the strict whitelist (or any under
    from __future__ import annotations, which never evaluates them)."""
    if fn.decorator_list:
        return False

    def lit(d) -> bool:
        if isinstance(d, ast.Constant):
            return True
        if isinstance(d, ast.UnaryOp) and isinstance(d.op, (ast.USub, ast.UAdd)) and isinstance(d.operand, ast.Constant) and type(d.operand.value) in (int, float):
            return True
        if isinstance(d, (ast.Tuple, ast.List, ast.Set)):
            return all(lit(x) for x in d.elts)
        if isinstance(d, ast.Dict):
            return all(k is not None and lit(k) and lit(v) for k, v in zip(d.keys, d.values))
        return False

    a = fn.args
    if not all(lit(d) for d in [*a.defaults, *[d for d in a.kw_defaults if d is not None]]):
        return False
    return mod.future_annotations or all(_ann_pure(mod, x) for x in _ann_exprs(fn))


def _def_header_text(fn) -> str:
    if fn is None:
        return "<absent>"
    return ast.dump(ast.Tuple(elts=[ast.Tuple(elts=list(fn.decorator_list), ctx=ast.Load()), fn.args, fn.returns or ast.Constant(value=None)], ctx=ast.Load()), include_attributes=False)


def _strip_annotations(fn):
    import copy as _copy

    n = _copy.deepcopy(fn)
    a = n.args
    for p in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]:
        if p is not None:
            p.annotation = None
    n.returns = None
    return n


def _kw_called(mod: _Mod) -> set:
    out = set()
    for n in ast.walk(mod.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and (n.keywords or any(isinstance(x, ast.Starred) for x in n.args)):
            out.add(n.func.id)
    return out


def _stdlib_shadow(roots, names) -> str | None:
    std = getattr(sys, "stdlib_module_names", frozenset())
    for nm in names:
        top = nm.split(".")[0]
        if top not in std:
            continue
        for r in roots:
            if r is not None and ((Path(r) / f"{top}.py").exists() or (Path(r) / top / "__init__.py").exists()):
                return f"{top} is shadowed by an in-tree module under {r}"
    return None


def _import_stamps(mod: _Mod, roots) -> list:
    out = []
    for st in mod.imports:
        names = [al.name for al in st.names] if isinstance(st, ast.Import) else [st.module or ""]
        h = None
        for nm in names:
            for r in roots:
                if r is None or not nm:
                    continue
                parts = nm.split(".")
                for cand in (Path(r).joinpath(*parts).with_suffix(".py"), Path(r).joinpath(*parts) / "__init__.py"):
                    if cand.is_file():
                        h = hashlib.sha256(cand.read_bytes()).hexdigest()
        out.append((_dump(st), h))
    return out


class _Bundle:
    def __init__(self):
        self.const_reads: set = set()
        self.units: dict = {}  # id -> (canonical def ast, text, ctx)
        self.noann: dict = {}  # id -> (canonical text with every annotation removed, the ORIGINAL def's annotations are runtime-neutral to evaluate)
        self.module: list = []
        self.imports: list = []
        self.order: list = []


def _bundle(mod: _Mod, target: str, roots) -> _Bundle:
    if target in mod.async_funcs:
        raise _Unknown("async target")
    if target not in mod.funcs:
        raise _Unknown("target is not a top-level function in the module (method/nested targets are UNKNOWN)", target)
    sh = _stdlib_shadow(roots, [al.name for st in mod.imports for al in (st.names if isinstance(st, ast.Import) else [])] +
                        [st.module or "" for st in mod.imports if isinstance(st, ast.ImportFrom)])
    if sh:
        raise _Unknown("stdlib module shadowed in-tree", sh)
    kwc = _kw_called(mod)
    ids = {target: "T"}
    order = [target]
    b = _Bundle()
    i = 0
    while i < len(order):
        nm = order[i]
        new, ctx = _canon_def(mod, nm, i == 0, ids, order, kwc)
        alt, _ = _canon_def(mod, nm, i == 0, ids, order, kwc, numbering="name")
        b.units["T" if i == 0 else ids[nm]] = (new, _dump(new), alt)
        b.const_reads |= ctx.const_reads
        b.noann["T" if i == 0 else ids[nm]] = (_dump(_strip_annotations(new)), all(mod.future_annotations or _ann_pure(mod, x) for x in _ann_exprs(mod.funcs[nm])))
        i += 1
    # module-level statements run at import time: compared as text (they may pull more helpers into the cone)
    modctx = _Canon(mod, None, {}, ids, order, kwc)
    import copy as _copy
    class _Defs(ast.NodeTransformer):
        """A def nested in a module-level statement (e.g. under `if sys.platform == ...`) does not RUN at import: its body is compared as exact text (any edit still makes the module
        statements differ -> refused), while what DOES run at import (decorators, defaults, annotations, class bases) is canonicalized so helpers it reaches enter the cone."""

        def _def(self, node, parts):
            run = [modctx.visit(_copy.deepcopy(x)) for x in parts if x is not None]
            return ast.Expr(ast.Tuple(elts=[ast.Constant("DEF:" + ast.dump(node)), *run], ctx=ast.Load()))

        def visit_FunctionDef(self, node):
            a = node.args
            ann = [x.annotation for x in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg] if x is not None]
            return self._def(node, [*node.decorator_list, *a.defaults, *a.kw_defaults, node.returns, *ann])

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            node.body = [self.visit(s) for s in node.body]  # the class body RUNS at import; its methods are text
            node.decorator_list = [modctx.visit(d) for d in node.decorator_list]
            node.bases = [modctx.visit(x) for x in node.bases]
            node.keywords = [modctx.visit(x) for x in node.keywords]
            return ast.Expr(ast.Constant("CLS:" + ast.dump(node)))

    for st in mod.other_stmts:
        mc = _copy.deepcopy(st)
        for n in _dfs(mc):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                modctx.locals.setdefault(n.id, n.id)  # module-level names stored here keep their names
        mc = _Defs().visit(mc) if not isinstance(mc, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else _Defs().visit(mc)
        ast.fix_missing_locations(mc)
        b.module.append(_dump(modctx.visit(mc)))
        b.const_reads |= modctx.const_reads
    while i < len(order):  # helpers discovered from module-level statements
        nm = order[i]
        new, ctx = _canon_def(mod, nm, False, ids, order, kwc)
        alt, _ = _canon_def(mod, nm, False, ids, order, kwc, numbering="name")
        b.units[ids[nm]] = (new, _dump(new), alt)
        b.const_reads |= ctx.const_reads
        b.noann[ids[nm]] = (_dump(_strip_annotations(new)), all(mod.future_annotations or _ann_pure(mod, x) for x in _ann_exprs(mod.funcs[nm])))
        i += 1
    b.module.extend(sorted(("regex:" + p) for p in mod.regexes.values()))
    b.module.extend(sorted(("frozenset:" + p) for p in mod.frozensets.values()))
    b.module.extend(sorted(("dict:" + d) for d in mod.dicts.values()))
    b.imports = _import_stamps(mod, roots)
    b.order = list(order)
    return b


# ================================================================================================================ rules
def _params(fn: ast.FunctionDef) -> list:
    a = fn.args
    return [p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]]


def _ann(fn: ast.FunctionDef) -> dict:
    a = fn.args
    return {p.arg: (ast.unparse(p.annotation) if p.annotation is not None else None) for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]}


def _strparams(fn) -> set:
    rebound = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
    rebound |= {n.name for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler) and n.name}
    return {k for k, v in _ann(fn).items() if v == "str" and k not in rebound}


def _intparams(fn) -> set:
    rebound = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
    rebound |= {n.name for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler) and n.name}
    return {k for k, v in _ann(fn).items() if v == "int" and k not in rebound}


def _is_int_atom(e, intp: set) -> bool:
    """A PURE, TOTAL boolean predicate over exact-int parameters: ordering/equality comparisons against int constants or exact-int params."""
    def operand(x):
        return (isinstance(x, ast.Constant) and type(x.value) is int) or (isinstance(x, ast.Name) and x.id in intp)
    if isinstance(e, ast.Constant):
        return isinstance(e.value, bool)
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, l, r = e.ops[0], e.left, e.comparators[0]
        if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)):
            return operand(l) and operand(r) and (isinstance(l, ast.Name) or isinstance(r, ast.Name))
        return False
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return _is_int_atom(e.operand, intp)
    if isinstance(e, ast.BoolOp):
        return all(_is_int_atom(v, intp) for v in e.values)
    return False


def _is_singleton_guard(test: ast.AST, param_set: set) -> bool:
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Is, ast.IsNot))):
        return False
    l, r = test.left, test.comparators[0]
    if isinstance(l, ast.Name) and l.id in param_set and isinstance(r, ast.Constant):
        return r.value is None or type(r.value) is bool
    if isinstance(r, ast.Name) and r.id in param_set and isinstance(l, ast.Constant):
        return l.value is None or type(l.value) is bool
    return False


def _conj(e):
    """Atoms of a pure conjunction, or None when `e` contains a disjunction at the top level."""
    if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.And):
        out = []
        for v in e.values:
            c = _conj(v)
            if c is None:
                return None
            out += c
        return out
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return _neg(e.operand)
    return [e]


def _neg(e):
    """Atoms of NOT e as a conjunction, or None when it is a disjunction."""
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return _conj(e.operand)
    if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.Or):
        out = []
        for v in e.values:
            c = _neg(v)
            if c is None:
                return None
            out += c
        return out
    if isinstance(e, ast.BoolOp):
        return None
    return [ast.UnaryOp(op=ast.Not(), operand=e)]


def _is_str_atom(e, strp: set, allow_regex: bool = False) -> bool:
    """A PURE, TOTAL boolean-ish atom over exact-str parameters: str predicate methods with literal arguments, `lit in p`, `p in lit`, isinstance(p, str), len(p) <op> int,
    comparisons with literals, and (R3 only) a module regex's search/match/fullmatch on a str parameter."""
    def operand(x):
        return (isinstance(x, ast.Constant) and isinstance(x.value, (str, int)) and not isinstance(x.value, bool)) or (isinstance(x, ast.Name) and x.id in strp) \
            or (isinstance(x, ast.Tuple) and all(isinstance(y, ast.Constant) and isinstance(y.value, str) for y in x.elts))
    if isinstance(e, ast.Constant):
        return isinstance(e.value, bool)
    if isinstance(e, ast.Call) and not e.keywords:
        f = e.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in strp and f.attr in _STR_PRED_METHODS:
            if f.attr not in ("startswith", "endswith"):
                return not e.args
            if len(e.args) != 1:
                return False
            arg = e.args[0]
            return ((isinstance(arg, ast.Constant) and type(arg.value) is str) or
                    (isinstance(arg, ast.Tuple) and all(isinstance(x, ast.Constant) and type(x.value) is str for x in arg.elts)))
        if isinstance(f, ast.Name) and f.id == "isinstance" and len(e.args) == 2 and isinstance(e.args[0], ast.Name) and e.args[0].id in strp and \
                isinstance(e.args[1], ast.Name) and e.args[1].id == "str":
            return True
        if allow_regex and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id.startswith("RX:") and f.attr in ("search", "match", "fullmatch") \
                and len(e.args) == 1 and isinstance(e.args[0], ast.Name) and e.args[0].id in strp:
            return True
        return False
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, l, r = e.ops[0], e.left, e.comparators[0]
        if isinstance(op, (ast.In, ast.NotIn)):
            return (operand(l) and not isinstance(l, ast.Tuple) and operand(r) and
                    all(not (isinstance(x, ast.Constant) and isinstance(x.value, int)) for x in (l, r)))
        if isinstance(op, (ast.Eq, ast.NotEq)):
            return operand(l) and operand(r) and (isinstance(l, ast.Constant) and isinstance(l.value, str) or isinstance(r, ast.Constant) and isinstance(r.value, str)
                                                   or isinstance(l, ast.Name) and isinstance(r, ast.Name))
        if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            ln = isinstance(l, ast.Call) and isinstance(l.func, ast.Name) and l.func.id == "len" and not l.keywords and len(l.args) == 1 and isinstance(l.args[0], ast.Name) and l.args[0].id in strp
            return ln and isinstance(r, ast.Constant) and type(r.value) is int
        return False
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return _is_str_atom(e.operand, strp, allow_regex)
    if isinstance(e, ast.BoolOp):
        return all(_is_str_atom(v, strp, allow_regex) for v in e.values)
    return False


def _expr_names(e) -> set:
    return {n.id for n in ast.walk(e) if isinstance(n, ast.Name)}


def _r2(bd: ast.FunctionDef, pd: ast.FunctionDef, module: str, fname: str, deltas) -> tuple:
    """(ok, why). Approved guard insertion."""
    if _dump(bd.args) != _dump(pd.args) or _d(bd.returns) != _d(pd.returns):
        return False, "signature differs"
    B, P = list(bd.body), list(pd.body)
    if len(P) != len(B) + 1:
        return False, "post is not pre plus exactly one statement"
    ii = None
    for i in range(len(P)):
        if _dumps(P[:i]) == _dumps(B[:i]) and _dumps(P[i + 1:]) == _dumps(B[i:]):
            ii = i
            break
    if ii is None:
        return False, "the remainder is not identical after removing one statement"
    guard = P[ii]
    if not (isinstance(guard, ast.If) and not guard.orelse and len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise) and guard.body[0].cause is None):
        return False, "the inserted statement is not `if G: raise E(...)`"
    ex = guard.body[0].exc
    if isinstance(ex, ast.Call) and isinstance(ex.func, ast.Name) and ex.func.id in _EXC_BUILTINS and not ex.keywords and all(isinstance(a, ast.Constant) for a in ex.args):
        exc_name = ex.func.id
    else:
        return False, "the raised exception is not a builtin class constructed from literals"
    strp = _strparams(pd)
    intp = _intparams(pd)
    param_set = set(_params(pd))
    singleton_guard = _is_singleton_guard(guard.test, param_set)
    str_guard = (not singleton_guard) and _is_str_atom(guard.test, strp)
    int_guard = (not singleton_guard) and (not str_guard) and _is_int_atom(guard.test, intp)
    if not (singleton_guard or str_guard or int_guard):
        return False, "the guard is not a pure total predicate over exact-str, exact-int, or singleton-identity parameters"
    pc: list = []
    for st in B[:ii]:
        if isinstance(st, ast.If) and not st.orelse and len(st.body) == 1 and isinstance(st.body[0], ast.Return) and not any(isinstance(n, ast.NamedExpr) for n in ast.walk(st.test)):
            ng = _neg(st.test)
            if ng is None:
                return False, "path condition unresolved: the early-return test negates to a disjunction"
            pc += ng
        else:
            return False, "path condition unresolved: a prefix statement is not an early return"
    atoms = []
    for a in pc + (_conj(guard.test) or [None]):
        if a is None:
            return False, "the guard is a disjunction"
        atoms.append(a)
    ann = _ann(pd)

    def implied(a):
        return isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id == "isinstance" and len(a.args) == 2 and isinstance(a.args[0], ast.Name) \
            and isinstance(a.args[1], ast.Name) and ann.get(a.args[0].id) == a.args[1].id == "str" and not singleton_guard

    cset = {_dump(a) for a in atoms if not implied(a)}
    sym = f"{module}.{fname}"
    for d in deltas or ():
        if d.get("type") != "expr" or d.get("symbol") != sym:
            continue
        exp = d.get("expected") or {}
        if exp.get("kind") != "raises" or exp.get("exc_type") != f"builtins.{exc_name}":
            continue
        if d.get("param") not in _params(pd):
            continue
        try:
            pe = ast.parse(d["expr"], mode="eval").body
        except SyntaxError:
            continue
        pa = _conj(pe)
        if pa is None:
            continue
        pset = {_dump(_refold(a)) for a in pa if not implied(a)}
        if pset == cset:
            return True, f"R2:{d.get('id')}"
    return False, "no approved delta predicate equals (path condition AND guard) with the same exception type"


def _refold(e):
    class F(ast.NodeTransformer):
        def visit_BinOp(self, n):
            self.generic_visit(n)
            v = _fold(n)
            return _const_node(v) if v is not _NOFOLD and type(v) is int else n
    return F().visit(ast.parse(ast.unparse(e), mode="eval").body)


def _bool_valued(e, strp) -> bool:
    if isinstance(e, ast.Constant):
        return isinstance(e.value, bool)
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "bool" and len(e.args) == 1 and not e.keywords:
        return True
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return True
    if isinstance(e, ast.BoolOp):
        return all(_bool_valued(v, strp) for v in e.values)
    return _is_str_atom(e, strp) and not isinstance(e, ast.BoolOp)


def _tv(e, strp, atoms: dict):
    """Truth formula of `e` (pure total atoms only), or raise _Unknown."""
    if isinstance(e, ast.Constant) and isinstance(e.value, bool):
        return ("c", e.value)
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "bool" and len(e.args) == 1 and not e.keywords:
        return _tv(e.args[0], strp, atoms)
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return ("not", _tv(e.operand, strp, atoms))
    if isinstance(e, ast.BoolOp):
        return ("and" if isinstance(e.op, ast.And) else "or", [_tv(v, strp, atoms) for v in e.values])
    if _is_str_atom(e, strp, allow_regex=True):
        return ("a", atoms.setdefault(_dump(e), len(atoms)))
    raise _Unknown("an atom is not a pure total predicate over exact-str parameters", ast.unparse(e)[:80])


def _formula(fn: ast.FunctionDef, atoms: dict):
    strp = _strparams(fn)
    body = list(fn.body)
    if not body or not isinstance(body[-1], ast.Return) or body[-1].value is None:
        raise _Unknown("the function does not end in a value return")
    chain = []
    for st in body[:-1]:
        if isinstance(st, ast.If) and not st.orelse and len(st.body) == 1 and isinstance(st.body[0], ast.Return) and isinstance(st.body[0].value, ast.Constant) \
                and isinstance(st.body[0].value.value, bool):
            chain.append((_tv(st.test, strp, atoms), st.body[0].value.value))
        else:
            raise _Unknown("a statement other than an early boolean return", type(st).__name__)
    last = body[-1].value
    if not _bool_valued(last, strp):
        raise _Unknown("the returned value is not provably a bool")
    return chain, _tv(last, strp, atoms)


def _ev(f, env):
    k = f[0]
    if k == "c":
        return f[1]
    if k == "a":
        return env[f[1]]
    if k == "not":
        return not _ev(f[1], env)
    if k == "and":
        return all(_ev(x, env) for x in f[1])
    return any(_ev(x, env) for x in f[1])


def _value(chain, tail, env):
    for c, b in chain:
        if _ev(c, env):
            return b
    return _ev(tail, env)


def _entry_guards(fn):
    """(guard statements, rest): the leading `if type(p) is not T:` / `type(p) not in (int, bool)` statements whose body terminates (the target's OWN exact-type enforcement; pure and total for any value)."""
    body = list(_strip_doc(fn.body))
    k = 0
    while k < len(body):
        st = body[k]
        c = st.test if isinstance(st, ast.If) else None
        if (isinstance(st, ast.If) and not st.orelse and st.body and isinstance(st.body[-1], (ast.Raise, ast.Return)) and isinstance(c, ast.Compare) and len(c.ops) == 1
                and isinstance(c.left, ast.Call) and isinstance(c.left.func, ast.Name) and c.left.func.id == "type" and not c.left.keywords and len(c.left.args) == 1 and isinstance(c.left.args[0], ast.Name)
                and (
                    (isinstance(c.ops[0], ast.IsNot) and isinstance(c.comparators[0], ast.Name))
                    or (isinstance(c.ops[0], ast.NotIn) and isinstance(c.comparators[0], ast.Tuple)
                        and bool(c.comparators[0].elts) and all(isinstance(x, ast.Name) for x in c.comparators[0].elts))
                )):
            k += 1
            continue
        break
    return body[:k], body[k:]


def _r3(bd, pd) -> tuple:
    if _dump(bd.args) != _dump(pd.args):
        return False, "signature differs"
    gb, rb_ = _entry_guards(bd)
    gp, rp_ = _entry_guards(pd)
    if gb or gp:  # an identical leading exact-type guard in both versions is a precondition of both; the reordering applies to what follows it
        if [_dump(x) for x in gb] != [_dump(x) for x in gp]:
            return False, "the entry guards differ"
        import copy as _copy

        bd, pd = _copy.copy(bd), _copy.copy(pd)
        bd.body, pd.body = rb_, rp_
    try:
        atoms: dict = {}
        fb = _formula(bd, atoms)
        fp = _formula(pd, atoms)
    except _Unknown as e:
        return False, e.reason + (": " + e.detail if e.detail else "")
    n = len(atoms)
    if n > 12:
        return False, "more than 12 atoms"
    for bits in itertools.product((False, True), repeat=n):
        if _value(*fb, bits) != _value(*fp, bits):
            return False, "the boolean functions differ"
    return True, "R3"


# ---------------------------------------------------------------------------------------------------------------- R4: hoisted skip
# Callee contract (documented stdlib behaviour), applied ONLY to arguments that are exact stdlib ast nodes produced by ast.parse in the same function (see _loop_var_is_call):
# ast.literal_eval(<node>) is effect-free and raises only ValueError, TypeError, SyntaxError, RecursionError or MemoryError. MemoryError / resource exhaustion is OUTSIDE the
# equivalence claim (a disclosed assumption); the other four must all be caught by the handler whose action is the skipped `continue`.
_LITEVAL_EXC = frozenset({"ValueError", "TypeError", "SyntaxError", "RecursionError"})


def _stores(fn_or_stmts, name: str) -> int:
    nodes = fn_or_stmts if isinstance(fn_or_stmts, list) else [fn_or_stmts]
    return sum(1 for s in nodes for n in ast.walk(s) if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)))


def _is_ast_attr(e, attr: str) -> bool:
    return isinstance(e, ast.Attribute) and e.attr == attr and isinstance(e.value, ast.Name) and e.value.id == "ast"


def _loop_var_is_call(body: list, k: int, loop: ast.For) -> bool:
    """True when the loop variable provably iterates exact ast.Call nodes of ast.parse output: tree = ast.parse(..) (single assignment, every handler of the guarding try
    returns), nodes = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)), key=..) (single assignment), then `for node in nodes`."""
    if not (isinstance(loop.target, ast.Name) and isinstance(loop.iter, ast.Name)):
        return False
    tree_name = nodes_name = None
    for st in body[:k]:
        cand = st
        if isinstance(st, ast.Try):
            if st.orelse or st.finalbody or len(st.body) != 1 or not st.handlers or not all(h.body and isinstance(h.body[-1], ast.Return) for h in st.handlers):
                continue
            cand = st.body[0]
        if isinstance(cand, ast.Assign) and len(cand.targets) == 1 and isinstance(cand.targets[0], ast.Name):
            v, tgt = cand.value, cand.targets[0].id
            if isinstance(v, ast.Call) and _is_ast_attr(v.func, "parse") and len(v.args) >= 1 and not any(isinstance(a, ast.Starred) for a in v.args):
                tree_name = tgt
            elif isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "sorted" and len(v.args) == 1 and isinstance(v.args[0], ast.GeneratorExp):
                g = v.args[0]
                gen = g.generators[0] if len(g.generators) == 1 else None
                if (gen is not None and isinstance(g.elt, ast.Name) and isinstance(gen.target, ast.Name) and gen.target.id == g.elt.id
                        and isinstance(gen.iter, ast.Call) and _is_ast_attr(gen.iter.func, "walk") and len(gen.iter.args) == 1 and isinstance(gen.iter.args[0], ast.Name)
                        and tree_name is not None and gen.iter.args[0].id == tree_name and len(gen.ifs) == 1):
                    f = gen.ifs[0]
                    if (isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "isinstance" and len(f.args) == 2 and isinstance(f.args[0], ast.Name)
                            and f.args[0].id == g.elt.id and _is_ast_attr(f.args[1], "Call")):
                        nodes_name = tgt
    if tree_name is None or nodes_name is None or loop.iter.id != nodes_name:
        return False
    return _stores(body, tree_name) == 1 and _stores(body, nodes_name) == 1


def _s_pure_total(s, node_name: str) -> bool:
    """S := any(P(v) for v in <node>.args|.keywords) joined by or/and, P over isinstance(v, ast.Starred) / v.arg is None: pure and total on an exact ast.Call."""
    if isinstance(s, ast.BoolOp):
        return all(_s_pure_total(v, node_name) for v in s.values)
    if not (isinstance(s, ast.Call) and isinstance(s.func, ast.Name) and s.func.id == "any" and len(s.args) == 1 and not s.keywords and isinstance(s.args[0], ast.GeneratorExp)):
        return False
    g = s.args[0]
    if len(g.generators) != 1 or g.generators[0].ifs or g.generators[0].is_async or not isinstance(g.generators[0].target, ast.Name):
        return False
    it, v = g.generators[0].iter, g.generators[0].target.id
    if not (isinstance(it, ast.Attribute) and isinstance(it.value, ast.Name) and it.value.id == node_name and it.attr in ("args", "keywords")):
        return False
    e = g.elt
    if it.attr == "args":
        return (isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "isinstance" and len(e.args) == 2 and isinstance(e.args[0], ast.Name)
                and e.args[0].id == v and _is_ast_attr(e.args[1], "Starred"))
    return (isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.Is) and isinstance(e.left, ast.Attribute) and e.left.attr == "arg"
            and isinstance(e.left.value, ast.Name) and e.left.value.id == v and isinstance(e.comparators[0], ast.Constant) and e.comparators[0].value is None)


def _lit_expr_ok(e, node_name: str) -> bool:
    def leval(x, v, field):
        if not (isinstance(x, ast.Call) and _is_ast_attr(x.func, "literal_eval") and len(x.args) == 1 and not x.keywords):
            return False
        a = x.args[0]
        if field is None:
            return isinstance(a, ast.Name) and a.id == v
        return isinstance(a, ast.Attribute) and a.attr == field and isinstance(a.value, ast.Name) and a.value.id == v

    if not isinstance(e, (ast.ListComp, ast.DictComp)) or len(e.generators) != 1:
        return False
    g = e.generators[0]
    if g.is_async or not isinstance(g.target, ast.Name):
        return False
    v, it = g.target.id, g.iter
    if not (isinstance(it, ast.Attribute) and isinstance(it.value, ast.Name) and it.value.id == node_name):
        return False
    if isinstance(e, ast.ListComp):
        return it.attr == "args" and not g.ifs and leval(e.elt, v, None)
    if it.attr != "keywords":
        return False
    if not (isinstance(e.key, ast.Attribute) and e.key.attr == "arg" and isinstance(e.key.value, ast.Name) and e.key.value.id == v and leval(e.value, v, "value")):
        return False
    return len(g.ifs) <= 1 and all(isinstance(f, ast.Attribute) and f.attr == "arg" and isinstance(f.value, ast.Name) and f.value.id == v for f in g.ifs)


def _try_spec(tr, node_name: str):
    """(assigned names, handler exception names) of a try whose body is only literal_eval comprehensions over the node's args/keywords and whose handlers all `continue`."""
    if not isinstance(tr, ast.Try) or tr.orelse or tr.finalbody or not tr.handlers:
        return None
    types: set = set()
    for h in tr.handlers:
        if h.name or not (len(h.body) == 1 and isinstance(h.body[0], ast.Continue)):
            return None
        els = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
        if not all(isinstance(x, ast.Name) for x in els):
            return None
        types |= {x.id for x in els}
    names = []
    for st in tr.body:
        if not (isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)) or not _lit_expr_ok(st.value, node_name):
            return None
        names.append(st.targets[0].id)
    return names, types


def _strip_filters(tr: ast.Try, s) -> ast.Try:
    """Remove `if kw.arg` comprehension filters that NOT S entails: S has a top-level disjunct any(kw.arg is None for kw in node.keywords), and the arg of a parsed keyword is
    None or a non-empty identifier, so on every input that passes the skip the filter is true."""
    import copy as _copy
    out = _copy.deepcopy(tr)
    disjuncts = s.values if isinstance(s, ast.BoolOp) and isinstance(s.op, ast.Or) else [s]
    entails = any(isinstance(x, ast.Call) and "keywords" in _dump(x) and "arg" in _dump(x) and "Constant(value=None" in _dump(x) for x in disjuncts)
    if entails:
        for st in out.body:
            for n in ast.walk(st):
                if isinstance(n, ast.DictComp):
                    n.generators[0].ifs = []
    return out


def _r4(bd: ast.FunctionDef, pd: ast.FunctionDef, ast_clean: bool) -> tuple:
    if not ast_clean:
        return False, "`ast` is not a clean stdlib import"
    if _dump(bd.args) != _dump(pd.args) or _d(bd.returns) != _d(pd.returns):
        return False, "signature differs"
    B, P = list(bd.body), list(pd.body)
    if len(B) != len(P):
        return False, "statement counts differ"
    diff = [i for i in range(len(B)) if _dump(B[i]) != _dump(P[i])]
    if len(diff) != 1:
        return False, "not exactly one top-level statement differs"
    k = diff[0]
    lb, lp = B[k], P[k]
    if not (isinstance(lb, ast.For) and isinstance(lp, ast.For)) or _dump(lb.target) != _dump(lp.target) or _dump(lb.iter) != _dump(lp.iter) or _dumps(lb.orelse) != _dumps(lp.orelse):
        return False, "the differing statement is not a loop with an identical header"
    if not _loop_var_is_call(P, k, lp):
        return False, "the loop variable is not provably an exact ast.Call from ast.parse"
    node = lp.target.id
    Lb, Lp = list(lb.body), list(lp.body)
    if len(Lb) != len(Lp):
        return False, "loop body lengths differ"
    m = next((i for i in range(len(Lb)) if _dump(Lb[i]) != _dump(Lp[i])), None)
    if m is None or m + 1 >= len(Lb):
        return False, "no hoist position found"
    if _dumps(Lb[m + 2:]) != _dumps(Lp[m + 2:]):
        return False, "the loop body after the two positions differs"
    kb, kp = Lp[m], Lb[m + 1]
    if not (isinstance(kp, ast.If) and not kp.orelse and len(kp.body) == 1 and isinstance(kp.body[0], ast.Continue)):
        return False, "pre has no `if S: continue` after the try"
    if not (isinstance(kb, ast.If) and not kb.orelse and len(kb.body) == 1 and isinstance(kb.body[0], ast.Continue)):
        return False, "post has no hoisted `if S: continue` before the try"
    if _dump(kb.test) != _dump(kp.test):
        return False, "the hoisted skip predicate changed"
    s = kb.test
    if not _s_pure_total(s, node):
        return False, "the skip predicate is not pure and total over an exact ast.Call"
    tb, tp = _try_spec(Lb[m], node), _try_spec(Lp[m + 1], node)
    if tb is None or tp is None:
        return False, "the try is not a literal_eval comprehension block whose handlers only continue"
    if tb[0] != tp[0] or tb[1] != tp[1]:
        return False, "the try assigns different names or catches different exceptions"
    if not _LITEVAL_EXC <= tb[1]:
        return False, "the except clause does not cover ValueError, TypeError, SyntaxError and RecursionError (ast.literal_eval contract)"
    x = set(tb[0])
    if x & {n.id for n in ast.walk(s) if isinstance(n, ast.Name)}:
        return False, "the skip predicate reads a name the try assigns"
    for region, label in ((Lb[:m], "the loop prefix"), (B[k + 1:], "code after the loop")):
        if x & {n.id for st in region for n in ast.walk(st) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}:
            return False, f"a name assigned in the try is read in {label}"
    if _dump(_strip_filters(Lb[m], s)) != _dump(Lp[m + 1]):
        return False, "the try differs by more than filters the skip predicate entails away"
    return True, "R4"


# ================================================================================================================ certify
_CLOSED_TYPES = frozenset({"str", "bytes", "bytearray", "int", "float", "bool", "complex", "list", "tuple", "dict", "set", "frozenset", "range", "none", "optional", "union"})


def _open_params(fn: ast.FunctionDef) -> list:
    """Parameters whose declared type is NOT an exact builtin (unannotated, a user class, an abstract type): dispatch on them can reach classes this patch changes."""
    a = fn.args
    out = []
    for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
        if p.arg in ("self", "cls"):
            continue
        if p.annotation is None:
            out.append(p.arg)
            continue
        names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ast.unparse(p.annotation))
        if not names or not all(n.lower() in _CLOSED_TYPES or n in ("List", "Tuple", "Dict", "Set", "FrozenSet") for n in names):
            out.append(p.arg)
    return out


def _domain_text(rules, dom, consts=()) -> str:
    s = _domain_text0(rules, dom)
    if consts:
        s += "; module constants it reads (" + ", ".join(consts[:6]) + ") are assumed not rebound by code outside the tree"
    return s


def _domain_text0(rules, dom) -> str:
    """ONE sentence, read by the operator in the verdict: what the certified HELD covers, what is ENFORCED, and what is outside it."""
    if dom:
        return ("holds for " + ", ".join(f"{p}: exact builtin {t}" for p, t in dom) +
                " arguments only (enforced: the engine rejects a subclass input and no in-tree call site passes an in-tree class instance to it; "
                "callers outside the tree that pass instances of subclasses that override methods, or other types, are outside this claim)")
    if "ANN" in rules and not any(r in rules for r in ("R2", "R3", "R4")):
        return "holds for any argument: only annotations changed and nothing in the tree reads annotations at runtime (an external introspector of annotations is outside this claim; Python 3.14 evaluates annotations lazily)"
    if "R0" in rules and not any(r in rules for r in ("R2", "R3")):
        return "holds for any argument: the code is identical modulo renaming over the whole dependency cone"
    return "holds for any argument: the changed code reads only AST nodes produced by ast.parse"


_CALLSITE_POLICY = ("an argument that is a call of an in-tree class (directly or through a local name assigned from one in the same function) is refused; a plain parameter, literal, "
                    "f-string, str(...), attribute or any unresolved expression is not refused by itself; "
                    "argument forwarded from a caller parameter or an unresolved expression is admitted by contract (outside callers can pass subclasses; outside this claim), "
                    "and is COUNTED in forwarded_params / unresolved_args; test files are not scanned; matching is by callable name (conservative)")


def _own_nodes(scope):
    """Every node of `scope` EXCLUDING the bodies of nested function definitions (they are scopes of their own); class bodies belong to the enclosing scope."""
    for st in scope.body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield st
        yield from _own_children(st)


def _own_children(node):
    for ch in ast.iter_child_nodes(node):
        if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield ch
        yield from _own_children(ch)


def _lit_violation(ptype: str, e) -> bool:
    """True when argument expression `e` is PROVABLY not of the domain type `ptype` (a literal of another type, a container literal of the wrong kind)."""
    if ptype in ("float",):
        return False
    if isinstance(e, ast.Constant):
        v = type(e.value)
        return not ((ptype == "str" and v is str) or (ptype == "int" and v in (int, bool)) or (ptype == "bool" and v is bool))
    if isinstance(e, ast.JoinedStr):
        return ptype != "str"
    if isinstance(e, ast.List):
        return ptype != "list[int]" or any(isinstance(x, ast.Constant) and type(x.value) not in (int, bool) for x in e.elts)
    if isinstance(e, ast.Tuple):
        return ptype != "tuple[int, ...]" or any(isinstance(x, ast.Constant) and type(x.value) not in (int, bool) for x in e.elts)
    if isinstance(e, (ast.Dict, ast.Set, ast.DictComp, ast.SetComp, ast.Lambda, ast.GeneratorExp)):
        return True
    if isinstance(e, ast.ListComp):
        return ptype != "list[int]"
    return False


def _callsites(trees, function: str, params_pos: dict, ptypes: dict | None = None) -> tuple:
    """(calls_seen, refusals) over parsed (label, ast.Module) trees: every call of a callable NAMED `function` whose argument for a domain parameter is provably an in-tree class instance."""
    classes = {n.name for _, tr in trees for n in ast.walk(tr) if isinstance(n, ast.ClassDef)}

    def is_inst(e, assigned) -> bool:
        if isinstance(e, ast.Call):
            f = e.func
            n = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            return n in classes
        if isinstance(e, ast.Name):
            return any(is_inst(v, {}) for v in assigned.get(e.id, ()))
        return False

    seen, refusals = 0, []
    exposure = {"forwarded_params": 0, "unresolved_args": 0}
    for label, tr in trees:
        scopes = [tr] + [n for n in ast.walk(tr) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for sc in scopes:
            assigned: dict = {}
            for n in _own_nodes(sc):
                if isinstance(n, ast.Assign):
                    for tg in n.targets:
                        if isinstance(tg, ast.Name):
                            assigned.setdefault(tg.id, []).append(n.value)
            sc_params = set() if isinstance(sc, ast.Module) else set(_params(sc))
            for n in _own_nodes(sc):
                if True:
                    if not isinstance(n, ast.Call):
                        continue
                    f = n.func
                    nm = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
                    if nm != function:
                        continue
                    seen += 1
                    for pn, pos in params_pos.items():
                        arg = None
                        if pos is not None and pos < len(n.args) and not any(isinstance(a, ast.Starred) for a in n.args[: pos + 1]):
                            arg = n.args[pos]
                        for kw in n.keywords:
                            if kw.arg == pn:
                                arg = kw.value
                        if arg is not None and is_inst(arg, assigned):
                            refusals.append(f"{label}:{getattr(n, 'lineno', '?')} passes an in-tree class instance to {pn}")
                        elif arg is not None and ptypes and pn in ptypes and _lit_violation(ptypes[pn], arg):
                            refusals.append(f"{label}:{getattr(n, 'lineno', '?')} passes a literal that is not an exact {ptypes[pn]} to {pn}")
                        elif arg is not None and not label.startswith("base:"):  # exposure is measured on the POST tree (what lands)
                            if isinstance(arg, ast.Name) and arg.id in sc_params:
                                exposure["forwarded_params"] += 1  # forwarded from a caller parameter: externally reachable, outside the claim by contract
                            elif not (isinstance(arg, (ast.Constant, ast.JoinedStr)) or (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id in ("str", "int", "float", "bool"))):
                                exposure["unresolved_args"] += 1
    _callsites.exposure = exposure
    return seen, refusals


def _domain_record(mb, mp, module, function, rules, dom, scanned, seen, exposure=None, runtime_guard=False) -> tuple:
    import json as _json

    rec = {"kind": "exact-builtin-params", "function": f"{module}.{function}", "params": [[p, t] for p, t in dom], "rules": sorted(set(rules)),
           "base_source_sha256": mb.src_sha, "post_source_sha256": mp.src_sha,
           "call_sites": {"scanned_files": scanned, "calls_seen": seen, "refused": 0, "forwarded_params": (exposure or {}).get("forwarded_params", 0), "unresolved_args": (exposure or {}).get("unresolved_args", 0), "policy": _CALLSITE_POLICY}}
    if runtime_guard:
        rec["domain_enforcement"] = "identical exact-type entry guards in base and post"
        rec["call_sites"]["policy"] = "both target functions check the exact type before the changed behavior"
    return rec, hashlib.sha256(_json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _runtime_guard(mod, function, param, typ):
    """Return an exact-type guard in the original function, including everything
    evaluated before it. A common terminating prefix preserves off-domain calls.
    """
    fn = mod.funcs.get(function)
    if fn is None or typ not in {"str", "int", "float", "bool"}:
        return None
    if "*" in mod.import_names or mod.dynamic_reason:
        return None
    # The compiler's binding table includes pattern captures, except targets,
    # imports and def/class statements that a walk of Name(Store) would miss.
    table = symtable.symtable(mod.source, "<case>", "exec")
    scopes = [child for child in table.get_children() if child.get_name() == function and child.get_type() == "function"]
    if len(scopes) != 1:
        return None
    scope = scopes[0]
    bound = {s.get_name() for s in table.get_symbols() if s.is_assigned() or s.is_imported() or s.is_declared_global()}
    if param not in scope.get_identifiers():
        return None
    argument = scope.lookup(param)
    if not argument.is_parameter() or argument.is_assigned() or argument.is_imported():
        return None

    def _clean_builtins(names: set[str]) -> bool:
        return not (names & (bound | mod.mutable_globals)) and all(
            name in scope.get_identifiers() and scope.lookup(name).is_global() for name in names
        )

    prefix = []
    for stmt in _strip_doc(fn.body):
        if not (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
                and isinstance(stmt.body[0], (ast.Return, ast.Raise))):
            break
        test = stmt.test
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.left, ast.Call) and isinstance(test.left.func, ast.Name)
                and test.left.func.id == "type" and not test.left.keywords and len(test.left.args) == 1
                and isinstance(test.left.args[0], ast.Name)):
            break
        op, comp = test.ops[0], test.comparators[0]
        if isinstance(op, ast.IsNot) and isinstance(comp, ast.Name):
            if not _clean_builtins({"type", comp.id}):
                break
            prefix.append(ast.dump(stmt))
            if test.left.args[0].id == param and comp.id == typ:
                return prefix
            continue
        if (isinstance(op, ast.NotIn) and isinstance(comp, ast.Tuple) and len(comp.elts) == 2
                and all(isinstance(x, ast.Name) for x in comp.elts)
                and {x.id for x in comp.elts} == {"int", "bool"}):
            if not _clean_builtins({"type", "int", "bool"}):
                break
            prefix.append(ast.dump(stmt))
            if test.left.args[0].id == param and typ == "int":
                return prefix
            continue
        break
    return None


def _domain_base_types(typ: str) -> set[str]:
    """Extract all subclassable builtin base names referenced by a domain type string (e.g. 'list[int]' -> {'list', 'int'})."""
    return {tok for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", typ) if tok in _SUBCLASSABLE_BUILTINS}


def _check_domain_enforcement(mb: _Mod, mp: _Mod, module: str, function: str, rules: tuple, dom_t: tuple,
                              scan_trees, call_trees, strict_domain: bool, tfn: ast.FunctionDef,
                              base_record: dict | None = None) -> tuple[Cert | None, dict, str, str]:
    """Unified domain enforcement for R2/R3/TYP and typed SYM certificates.
    Returns (refusal_cert_or_None, domain_record, domain_sha256, domain_text_override).
    """
    if not dom_t:
        return None, (base_record or {}), "", ""
    # 1. Same-module subclass defense for EVERY claimed builtin base type (not just str)
    needed_bases: set[str] = set()
    if "R3" in rules:
        needed_bases.add("str")
    for _, tp in dom_t:
        needed_bases |= _domain_base_types(tp)
    for base in sorted(needed_bases):
        subs = mb.builtin_subs.get(base, set()) | mp.builtin_subs.get(base, set())
        if subs:
            return (Cert(False, f"a {base} subclass is defined in the tree: the exact-{base} domain of {'/'.join(rules)} is not established",
                         (), f"{base} subclass: " + ", ".join(sorted(subs))[:120]), {}, "", "")
    # 2. Strict domain: require identical leading exact-type entry guards in both original versions
    if strict_domain:
        original_b = getattr(mb, "original", mb)
        original_p = getattr(mp, "original", mp)
        for param, typ in dom_t:
            guard_names = {"type", typ, *({"bool"} if typ == "int" else ())}
            pre_guard = _runtime_guard(original_b, function, param, typ)
            if (not pre_guard or pre_guard != _runtime_guard(original_p, function, param, typ)
                    or _tree_rebinds(scan_trees or (), guard_names)):
                return (Cert(False, f"the target does not self-enforce exact {typ} for {param} with an identical "
                             "entry guard in both versions; behavior for other callers is unverified",
                             (), f"strict domain: {param}"), {}, "", "")
    # 3. Full in-tree call-site closure (source + tests)
    pos = {p: i for i, p in enumerate(_params(tfn))}
    tparams = {p: pos.get(p) for p, _ in dom_t if "." not in p}
    trees = scan_trees if scan_trees is not None else [("base:m", mb.tree), ("post:m", mp.tree)]
    seen, refusals = _callsites(call_trees if call_trees is not None else trees, function, tparams, {p: ty for p, ty in dom_t if "." not in p})
    if refusals:
        return (Cert(False, "an in-tree call site passes an in-tree class instance or wrong type to an exact-builtin domain parameter: " + "; ".join(refusals[:3]),
                     (), "call site: " + str(len(refusals)) + " refused"), {}, "", "")
    rec, sha = _domain_record(mb, mp, module, function, rules, dom_t, len(call_trees if call_trees is not None else trees), seen, dict(getattr(_callsites, "exposure", {})), runtime_guard=strict_domain)
    if base_record:
        import json as _json
        rec = {**base_record, "call_sites": rec["call_sites"], "rules": sorted(set(rules))}
        if strict_domain:
            rec["domain_enforcement"] = "identical exact-type entry guards in base and post"
        sha = hashlib.sha256(_json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    dt = ""
    if strict_domain:
        dt = ("holds for " + ", ".join(f"{p}: exact builtin {t}" for p, t in dom_t)
              + " after a matching entry check; other callers take the same terminating guard in both versions")
    return None, rec, sha, dt


def _can_try_symeq_on_bundle_unknown(
    mb: _Mod, mp: _Mod, function: str, deltas, roots_b, roots_p, scan_trees, scan_consumers, err_reason: str = ""
) -> bool:
    """True only when every structural safety check of _certify_mods passes despite _bundle raising _Unknown
    (e.g., an unchanged helper touching __file__/open). Preserves all structural/import/annotation/subclass
    and mutable-global refusals."""
    if deltas or function in mb.async_funcs or function in mp.async_funcs:
        return False
    if function not in mb.funcs or function not in mp.funcs:
        return False
    if _dump(mb.funcs[function]) == _dump(mp.funcs[function]):
        return False
    if "module global" in err_reason:
        return False
    for m_, r_ in ((mb, roots_b), (mp, roots_p)):
        names_ = ([al.name for st in m_.imports for al in (st.names if isinstance(st, ast.Import) else [])]
                  + [st.module or "" for st in m_.imports if isinstance(st, ast.ImportFrom)])
        if _stdlib_shadow(r_, names_):
            return False
    if _import_stamps(mb, roots_b) != _import_stamps(mp, roots_p):
        return False
    if ([_dump(s) for s in mb.other_stmts] != [_dump(s) for s in mp.other_stmts]
            or mb.consts != mp.consts or mb.regexes != mp.regexes
            or mb.frozensets != mp.frozensets or mb.dicts != mp.dicts):
        return False
    if set(mb.funcs) != set(mp.funcs):
        return False
    for nm in mb.funcs:
        if nm != function and _dump(mb.funcs[nm]) != _dump(mp.funcs[nm]):
            return False
    b_subs = getattr(mb, "tree_builtin_subs", mb.builtin_subs)
    p_subs = getattr(mp, "tree_builtin_subs", mp.builtin_subs)
    for base in sorted(_SUBCLASSABLE_BUILTINS):
        if ({(nm, mb.classes_all.get(nm)) for nm in b_subs.get(base, set())}
                != {(nm, mp.classes_all.get(nm)) for nm in p_subs.get(base, set())}):
            return False
    topen = sorted(set(_open_params(mb.funcs[function])) | set(_open_params(mp.funcs[function])))
    if topen and mb.classes_all != mp.classes_all:
        return False
    for fname in sorted(set(mb.funcs) | set(mp.funcs)):
        fb_, fp_ = mb.funcs.get(fname), mp.funcs.get(fname)
        if _def_header_text(fb_) != _def_header_text(fp_):
            for m_, f_ in ((mb, fb_), (mp, fp_)):
                if f_ is not None and not _def_header_safe(m_, f_):
                    return False
    if [ast.dump(x) for x in _ann_exprs(mb.funcs[function])] != [ast.dump(x) for x in _ann_exprs(mp.funcs[function])]:
        if not (all(mb.future_annotations or _ann_pure(mb, x) for x in _ann_exprs(mb.funcs[function]))
                and all(mp.future_annotations or _ann_pure(mp, x) for x in _ann_exprs(mp.funcs[function]))):
            return False
        if _ann_consumed(mb.tree) or _ann_consumed(mp.tree) or any(c for c in (scan_consumers or ()) if c):
            return False
        trees = scan_trees if scan_trees is not None else [("base:m", mb.tree), ("post:m", mp.tree)]
        if _escaping_names(trees, {function}):
            return False
    return True


def _certify_mods(mb: _Mod, mp: _Mod, module: str, function: str, deltas, roots_b, roots_p, scan_trees=None, scan_consumers=None, extra_dom=(), call_trees=None, strict_domain=False) -> Cert:
    ast_clean = all(m.import_names.get("ast") == 1 and "ast" not in m.mutable_globals for m in (mb, mp))
    try:
        bb, bp = _bundle(mb, function, roots_b), _bundle(mp, function, roots_p)
    except _Unknown as e:
        sym_ok = _can_try_symeq_on_bundle_unknown(mb, mp, function, deltas, roots_b, roots_p, scan_trees, scan_consumers, e.reason)
        return Cert(False, "certificate unavailable: " + e.reason, (), e.detail, symbolic_candidate=sym_ok)
    if bb.module != bp.module:
        return Cert(False, "module-level statements differ (import-time behaviour)", (), "")
    if bb.imports != bp.imports:
        return Cert(False, "imports or imported in-tree modules differ", (), "")
    if set(bb.units) != set(bp.units):
        return Cert(False, "the dependency cone differs in structure (a helper was added, removed or reached differently)", (), "")
    # DOMAIN PREMISE (the checkable part): a changed in-tree builtin subclass (added, removed, OR modified body) can change what a parameter dispatches to.
    b_subs = getattr(mb, "tree_builtin_subs", mb.builtin_subs)
    p_subs = getattr(mp, "tree_builtin_subs", mp.builtin_subs)
    for base in sorted(_SUBCLASSABLE_BUILTINS):
        b_defs = {(nm, mb.classes_all.get(nm)) for nm in b_subs.get(base, set())}
        p_defs = {(nm, mp.classes_all.get(nm)) for nm in p_subs.get(base, set())}
        if b_defs != p_defs:
            return Cert(False, f"a {base} subclass changed (or appeared/disappeared) in the same patch: its overridden methods are reachable through a {base} parameter", (), "class change")
    topen = sorted(set(_open_params(bb.units["T"][0])) | set(_open_params(bp.units["T"][0])))
    if topen and mb.classes_all != mp.classes_all:
        return Cert(False, "open parameter(s) " + ", ".join(topen) + " and a class definition changed in the same patch: dispatch targets can differ", (), "open parameter + class change")
    for fname in sorted(set(mb.funcs) | set(mp.funcs)):
        fb_, fp_ = mb.funcs.get(fname), mp.funcs.get(fname)
        if _def_header_text(fb_) != _def_header_text(fp_):
            for m_, f_ in ((mb, fb_), (mp, fp_)):
                if f_ is not None and not _def_header_safe(m_, f_):
                    return Cert(False, f"the definition-time header (decorators, defaults, annotations) of function {fname} changed or was added and is not provably pure: it runs when the module loads", (),
                                "definition-time header: " + fname)
    pub_b = {c for c in bb.const_reads if not c[0].startswith("_")}
    pub_p = {c for c in bp.const_reads if not c[0].startswith("_")}
    if pub_b != pub_p:
        return Cert(False, "the public module constants read by the target differ (" + ", ".join(sorted({c[0] for c in pub_b ^ pub_p})[:4]) +
                    "): extracting, inlining or renaming a public module constant is observable through the module", (), "public constant surface")
    consts_read = sorted({c[0] for c in bb.const_reads | bp.const_reads})
    if consts_read:
        why = mb.dynamic_reason or mp.dynamic_reason
        if not why and scan_trees:
            why = _tree_rebinds(scan_trees, set(consts_read))
        if why:
            return Cert(False, "module constants read by the target could be rebound (" + why + "): not inlined", (), "constant rebinding: " + why)
    diff = [u for u in bb.units if bb.units[u][1] != bp.units[u][1]]
    rules, notes, dom = [], [], []
    if not diff:
        rules, notes = ["R0"], ["identical modulo renaming over the whole cone"]
    consumer = ""
    for u in diff:
        bd, pd = bb.units[u][0], bp.units[u][0]
        why = []
        if bb.noann[u][0] == bp.noann[u][0]:  # G2: only annotations differ
            if not (bb.noann[u][1] and bp.noann[u][1]):
                return Cert(False, "an annotation expression could raise or act when the definition runs (not a builtin type name, typing name, string, None, | or a subscript of those)", (), "annotation purity: unit " + u)
            consumer = consumer or _ann_consumed(mb.tree) or _ann_consumed(mp.tree) or next((c for c in (scan_consumers or ()) if c), "")
            if consumer:
                return Cert(False, "annotations are read at runtime in the tree (" + consumer + "): an annotation edit is not neutral", (), "annotation consumer: " + consumer)
            changed_ann = {n for n in set(mb.funcs) & set(mp.funcs) if [ast.dump(x) for x in _ann_exprs(mb.funcs[n])] != [ast.dump(x) for x in _ann_exprs(mp.funcs[n])]} | {function}
            esc = _escaping_names(scan_trees if scan_trees is not None else [("base:m", mb.tree), ("post:m", mp.tree)], changed_ann)
            if esc:
                return Cert(False, "an annotated function is read in a non-call position (" + esc + "): an alias reaches every annotation consumer", (), "annotated function escapes: " + esc)
            rules.append("ANN")
            notes.append(f"annotation-only@{u}")
            continue
        for name, fn in (("R2", lambda: _r2(bd, pd, module, function, deltas) if u == "T" else (False, "R2 applies to the target only")),
                         ("R3", lambda: _r3(bd, pd)), ("R4", lambda: _r4(bb.units[u][2], bp.units[u][2], ast_clean))):
            okk, w = fn()
            if okk:
                rules.append(name)
                notes.append(f"{w}@{u}")
                if name == "R2":
                    # R2 inserts one guard; parameters constrained by the guard (or implied str isinstance in its prefix) require exact-builtin domain enforcement.
                    gi = next((i for i in range(len(pd.body)) if _dumps(pd.body[:i]) == _dumps(bd.body[:i]) and _dumps(pd.body[i + 1:]) == _dumps(bd.body[i:])), 0)
                    gtest = pd.body[gi].test
                    g_names = _expr_names(gtest)
                    if not _is_singleton_guard(gtest, set(_params(pd))):
                        p_names = {n.id for st in pd.body[:gi] for n in ast.walk(st) if isinstance(n, ast.Name)}
                        for p in sorted((g_names | p_names) & _strparams(pd)):
                            dom.append((p if u == "T" else f"{u}.{p}", "str"))
                        for p in sorted(g_names & _intparams(pd)):
                            dom.append((p if u == "T" else f"{u}.{p}", "int"))
                elif name == "R3":
                    used = sorted({n.id for st in pd.body for n in ast.walk(st) if isinstance(n, ast.Name)} & _strparams(pd))
                    dom.extend(((p if u == "T" else f"{u}.{p}"), "str") for p in used)
                break
            why.append(f"{name}: {w}")
        else:
            return Cert(False, f"whole computation differs; equivalence unproved (unit {u}: " + "; ".join(why) + ")", (), "unit " + u,
                        symbolic_candidate=(diff == ["T"] and not deltas))
    for pt in sorted(extra_dom):
        if pt not in dom:
            dom.append(pt)
    dom_t = tuple(dom)
    refusal, rec, sha, strict_dt = _check_domain_enforcement(mb, mp, module, function, tuple(rules), dom_t, scan_trees, call_trees, strict_domain, bb.units["T"][0])
    if refusal is not None:
        return refusal
    detail = notes[0] if rules == ["R0"] else "changed units covered by certified rules: " + ", ".join(notes)
    domain_text = strict_dt or _domain_text(rules, dom_t, tuple(consts_read))
    if not strict_dt and rules == ["R2"] and not dom_t:
        domain_text = "the inserted guard matches the approved input predicate; the remaining computation is identical"
    return Cert(True, "", tuple(rules), detail, dom_t, domain_text, rec, sha)


def _with_norm(plain: Cert, attempt) -> Cert:
    """If the plain comparison failed, retry on the NORMALIZED sources (equiv_norm: sound, side-condition-guarded transforms applied to each side independently). A success is reported with the
    rule id NORM first and the transforms that fired in the detail; a failure of the retry returns the PLAIN failure (the clearer reason)."""
    if plain.ok:
        return plain
    try:
        r = attempt()
    except (_Unknown, RecursionError, SyntaxError, ValueError):
        return plain
    if r is not None and not r.ok and (r.detail.startswith("call site") or r.detail.startswith(("str subclass", "strict domain"))):
        return r  # the domain refusal is the more informative reason
    return r if r is not None and r.ok else plain


def _norm_cert(c: Cert, notes_b: list, notes_p: list, typed: bool = False) -> Cert:
    import dataclasses as _dc

    fired = sorted(set(n.split(": ", 1)[-1] for n in notes_b + notes_p))
    return _dc.replace(c, rules=("NORM", *(("TYP",) if typed else ()), *c.rules), detail=c.detail + "; normalized: " + "; ".join(fired)[:300])


def _strict(flag) -> bool:
    import os

    return bool(flag) if flag is not None else os.environ.get("HLITH_CERT_STRICT_DOMAIN") == "1"


def _bound_once(res: Cert, base_src: str, post_src: str, function: str, scan_trees) -> Cert:
    """The single choke point every positive certificate passes (all rules, all provers): see obligation/binding_gate."""
    if not res.ok:
        return res
    from hlith.obligation.binding_gate import refusal

    why = refusal(base_src, post_src, function, res.rules, scan_trees, _dynamic_reason)
    return Cert(False, "certificate unavailable: " + why, (), "module binding") if why else res


def _closed_world(res: Cert, why_not) -> Cert:
    """Second choke point (obligation/closure_gate): inert import closure and reflection ban; a surviving certificate states its scope."""
    if not res.ok:
        return res
    why = why_not()
    if why:
        return Cert(False, "certificate unavailable: " + why, (), "closed world")
    from dataclasses import replace

    from hlith.obligation.closure_gate import SCOPE

    return replace(res, domain_text=(res.domain_text + "; " if res.domain_text else "") + SCOPE)


def certify_sources(base_src: str, post_src: str, function: str, *, deltas=(), module: str = "m", strict_domain=None) -> Cert:
    sd = _strict(strict_domain)
    try:
        original_b, original_p = _Mod(base_src, None, ""), _Mod(post_src, None, "")
        plain = _certify_mods(original_b, original_p, module, function, deltas, [], [], None, None, (), None, sd)
    except _Unknown as e:
        return Cert(False, "certificate unavailable: " + e.reason, (), e.detail)
    except RecursionError:
        return Cert(False, "certificate unavailable: analysis depth exceeded", (), "")

    def attempt():
        from hlith.obligation.equiv_norm import normalize_source

        tp_ = _typed_params(base_src, post_src, function)
        nb, nbn, ub, db = normalize_source(base_src, function, tp_)
        npost, npn, up, dp = normalize_source(post_src, function, tp_)
        if not (nbn or npn or db or dp):
            return None
        mb, mp = _Mod(nb, None, "", db), _Mod(npost, None, "", dp)
        mb.original, mp.original = original_b, original_p
        mb.src_sha, mp.src_sha = original_b.src_sha, original_p.src_sha
        used = ub | up
        c = _certify_mods(mb, mp, module, function, deltas, [], [], None, None, used, None, sd)
        return _norm_cert(c, nbn, npn, bool(used)) if c.ok else c

    def sym():
        from hlith.obligation.symeq import certify as _sc

        return _sc.certify_sources(base_src, post_src, function, strict_domain=sd, module=module)

    res = _with_sym(plain, sym, lambda: _with_norm(plain, attempt), deltas,
                    mb=original_b, mp=original_p, module=module, function=function,
                    scan_trees=None, call_trees=None, strict_domain=sd)
    from hlith.obligation.closure_gate import refusal_sources

    return _closed_world(_bound_once(res, base_src, post_src, function, None), lambda: refusal_sources(base_src, post_src))


def _with_sym(plain: Cert, sym, legacy, deltas=(), *, mb: _Mod | None = None, mp: _Mod | None = None,
              module: str = "m", function: str = "", scan_trees=None, call_trees=None, strict_domain: bool = False) -> Cert:
    """Only a body-equivalence gap can request a symbolic proof. Every structural
    refusal (including import and annotation checks) is final for this route.
    Prefer the established rules and their existing evidence when they suffice.
    Any typed symbolic proof passes through the exact same domain enforcement gate as R2/R3/TYP.
    """
    old = legacy()
    if old.ok or not plain.symbolic_candidate or deltas:
        return old
    try:
        result = sym()
    except Exception as exc:  # an optional proof backend must fail closed
        result = {"reason": type(exc).__name__}
    if result.get("ok"):
        dom_t = tuple(result.get("domain") or ())
        rec = result.get("record") or {}
        sha = result.get("sha256") or ""
        dtext = result.get("domain_text") or ""
        if dom_t:
            if any(t not in _DOMAIN_TYPES for _, t in dom_t):
                return Cert(False, "symbolic proof assumed a parameter type outside the engine's enforced exact-builtin domain", (), "unenforced domain type")
            if mb is not None and mp is not None and function in mb.funcs:
                enforced = _typed_params(mb.source, mp.source, function)
                if any(enforced.get(p) != t for p, t in dom_t):
                    return Cert(False, "symbolic proof assumed a parameter type not enforced by engine_domain", (), "unenforced domain param")
                refusal, rec, sha, strict_dt = _check_domain_enforcement(
                    mb, mp, module, function, ("SYM",), dom_t, scan_trees, call_trees, strict_domain, mb.funcs[function], base_record=rec
                )
                if refusal is not None:
                    return refusal
                if strict_dt:
                    dtext = strict_dt
        return Cert(True, "", ("SYM",), result["detail"], dom_t, dtext, rec, sha)
    from dataclasses import replace

    return replace(old, reason=(old.reason + "; symbolic prover: " + result["reason"])[:900])


def _locate(root, import_root: str, module: str):
    base = Path(root) / import_root if import_root else Path(root)
    parts = module.split(".")
    for cand in (base.joinpath(*parts).with_suffix(".py"), base.joinpath(*parts) / "__init__.py"):
        if cand.is_file():
            return cand
    return None


def certify(base_root, post_root, module: str, function: str, *, import_root: str = "", deltas=(), strict_domain=None) -> Cert:
    sd = _strict(strict_domain)
    try:
        fb, fp = _locate(base_root, import_root, module), _locate(post_root, import_root, module)
        if fb is None or fp is None:
            return Cert(False, "certificate unavailable: target module file not found in both trees", (), module)
        rb = [Path(base_root) / import_root if import_root else Path(base_root), Path(base_root)]
        rp = [Path(post_root) / import_root if import_root else Path(post_root), Path(post_root)]
        mb = _Mod(fb.read_text(encoding="utf-8", errors="replace"), Path(base_root), import_root)
        mp = _Mod(fp.read_text(encoding="utf-8", errors="replace"), Path(post_root), import_root)
        mb.classes_all, mb.tree_builtin_subs = _tree_classes(base_root)  # class definitions anywhere in the tree; mb.builtin_subs stays the module's OWN
        mp.classes_all, mp.tree_builtin_subs = _tree_classes(post_root)
        mb.tree_str_subs = mb.tree_builtin_subs.get("str", set())
        mp.tree_str_subs = mp.tree_builtin_subs.get("str", set())
        trees_ = _tree_trees(base_root, "base") + _tree_trees(post_root, "post")
        consumers_ = [_ann_consumed(tr) for _, tr in trees_]
        calls_ = _tree_trees(base_root, "base", True) + _tree_trees(post_root, "post", True)  # the call-site scan also reads the repo's own tests
        plain = _certify_mods(mb, mp, module, function, deltas, rb, rp, trees_, consumers_, (), calls_, sd)

        def attempt():
            from hlith.obligation.equiv_norm import normalize_source

            tb, tp_ = fb.read_text(encoding="utf-8", errors="replace"), fp.read_text(encoding="utf-8", errors="replace")
            tparams = _typed_params(tb, tp_, function)
            rel_b, rel_p = f"base:{fb.relative_to(base_root)}", f"post:{fp.relative_to(post_root)}"
            foreign = set()
            for lab, tr in trees_:
                if lab in (rel_b, rel_p):
                    continue
                for n in ast.walk(tr):
                    if isinstance(n, ast.Name):
                        foreign.add(n.id)
                    elif isinstance(n, ast.Attribute):
                        foreign.add(n.attr)
                    elif isinstance(n, ast.ImportFrom):
                        foreign.update(al.name for al in n.names)
            nb, nbn, ub, db = normalize_source(tb, function, tparams, foreign)
            npost, npn, up, dp = normalize_source(tp_, function, tparams, foreign)
            if not (nbn or npn or db or dp):
                return None
            mb2, mp2 = _Mod(nb, Path(base_root), import_root, db), _Mod(npost, Path(post_root), import_root, dp)
            mb2.original, mp2.original = mb, mp
            mb2.src_sha, mp2.src_sha = mb.src_sha, mp.src_sha  # the record hashes the ORIGINAL sources
            mb2.classes_all, mb2.tree_builtin_subs = mb.classes_all, mb.tree_builtin_subs
            mp2.classes_all, mp2.tree_builtin_subs = mp.classes_all, mp.tree_builtin_subs
            mb2.tree_str_subs, mp2.tree_str_subs = mb.tree_str_subs, mp.tree_str_subs
            used = ub | up
            c = _certify_mods(mb2, mp2, module, function, deltas, rb, rp, trees_, consumers_, used, calls_, sd)
            return _norm_cert(c, nbn, npn, bool(used)) if c.ok else c

        def sym():
            from hlith.obligation.symeq import certify as _sc

            return _sc.certify_tree(base_root, post_root, import_root, module, function, strict_domain=sd)

        res = _with_sym(plain, sym, lambda: _with_norm(plain, attempt), deltas,
                        mb=mb, mp=mp, module=module, function=function,
                        scan_trees=trees_, call_trees=calls_, strict_domain=sd)
        from hlith.obligation.closure_gate import refusal as _closure_refusal

        res = _closed_world(_bound_once(res, mb.source, mp.source, function, trees_), lambda: _closure_refusal(base_root, post_root, import_root, module))
        if res.ok:
            from hlith.obligation.symeq.tree import non_py_changed

            non_py = non_py_changed(base_root, post_root)
            if non_py is None:
                return Cert(False, "source tree too large to verify non-Python sibling files", (), "non-py scan")
            if non_py and (mb.imports or mp.imports or any(isinstance(n, ast.Name) and n.id == "open" for n in ast.walk(mb.tree))):
                return Cert(False, f"non-Python file(s) changed ({', '.join(non_py[:3])}) while the module interacts with imports/files", (), "non-py change")
        return res
    except _Unknown as e:
        return Cert(False, "certificate unavailable: " + e.reason, (), e.detail)
    except (OSError, RecursionError) as e:
        return Cert(False, "certificate unavailable: " + type(e).__name__, (), "")


_DOMAIN_TYPES = frozenset({"str", "int", "bool", "float", "list[int]", "tuple[int, ...]"})


def _typed_params(base_src: str, post_src: str, function: str) -> dict:
    """Parameters of the target annotated with the SAME exact builtin domain type in both versions (a type that changed is not trusted)."""
    try:
        fb = next(n for n in ast.parse(base_src).body if isinstance(n, ast.FunctionDef) and n.name == function)
        fp = next(n for n in ast.parse(post_src).body if isinstance(n, ast.FunctionDef) and n.name == function)
    except (StopIteration, SyntaxError, ValueError):
        return {}
    ab, ap = _ann(fb), _ann(fp)
    return {k: v for k, v in ap.items() if v in _DOMAIN_TYPES and ab.get(k) == v}


def engine_domain(post_root, import_root: str, module: str, function: str) -> dict:
    """The engine's ADMITTED INPUT DOMAIN for the target, enforced at every evaluator call: the parameters annotated exactly str, int, bool, float, list[int] or tuple[int, ...] (a subclass instance, or a container element that is a subclass, is a hard error).
    {} when the target or its annotations cannot be read (then nothing is enforced and no R2/R3 domain claim can rest on it)."""
    try:
        f = _locate(post_root, import_root, module)
        if f is None:
            return {}
        tree = ast.parse(Path(f).read_text(encoding="utf-8", errors="replace"))
        fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function), None)
        if fn is None:
            return {}
        order = _params(fn)
        ann = _ann(fn)
        typed = [[p, ann[p]] for p in order if ann.get(p) in _DOMAIN_TYPES]
        return {"module": module, "function": function, "params": typed, "order": order} if typed else {}
    except (OSError, SyntaxError, ValueError):
        return {}
