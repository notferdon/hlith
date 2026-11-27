# SPDX-License-Identifier: Apache-2.0
"""Sound, side-condition-guarded structural transforms used by the positive-HELD certificate (rule id NORM). Each transform rewrites ONE version into a behaviourally identical form; the
certificate rewrites BOTH versions and compares. A transform fires only where its stated side conditions hold; where they do not, the code is left untouched (so the comparison then fails and
the certificate refuses). No input-type assumption is made anywhere. The contract and hostile negatives are exercised by the certificate tests.

  inline   h(args) of a module-level expression-bodied helper, arguments constants / definitely-assigned names, no global captured by a caller local
  ret      if/elif/else that assigns one variable on every path then returns it  <->  returns on every path; else-after-return flattened
  temp     t = E ; S   with S the next statement reading t exactly once in an always-evaluated position preceded only by pure loads   ->   S with E in place of t
  dead     t = constant-or-bound-name, never read: removed
  comp     out = [] ; for v in IT: [if C:] out.append(X)   ->   out = [X for v in IT [if C]]
  fmt      'literal {} {}'.format(a, b) with plain positional fields   ->   the f-string
Disclosed assumptions (shared with the rest of the certificate): call-stack depth / traceback shape and resource exhaustion are not part of the behaviour compared."""

from __future__ import annotations

import ast
import copy
import keyword
import string
import symtable

_MAX_PASSES = 8
_TERMINATORS = (ast.Return, ast.Raise)


# ----------------------------------------------------------------------------------------------- helpers
def _params(fn) -> list:
    a = fn.args
    return [p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]]


def _rebound_in_fn(fn: ast.FunctionDef) -> set[str]:
    """Every name bound, deleted, or shadowed anywhere inside `fn` (excluding `fn`'s own parameter declarations)."""
    bound: set[str] = set()
    for n in ast.walk(fn):
        if n is fn:
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bound.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.alias):
            bound.add(n.asname or n.name.split(".")[0])
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            bound.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            bound.add(n.rest)
    return bound


def _symtable_rebound_params(src: str, target: str) -> set[str] | None:
    """Parameters of top-level `target` that Python's compiler marks as assigned/imported/global/nonlocal.
    Returns None when the function cannot be uniquely resolved (caller must fail closed and drop all typed params)."""
    try:
        table = symtable.symtable(src, "<equiv-norm>", "exec")
    except (SyntaxError, ValueError):
        return None
    scopes = [ch for ch in table.get_children() if ch.get_name() == target and ch.get_type() == "function"]
    if len(scopes) != 1:
        return None
    scope = scopes[0]
    rebound: set[str] = set()
    for sym in scope.get_symbols():
        if sym.is_assigned() or sym.is_imported() or sym.is_declared_global() or sym.is_nonlocal():
            rebound.add(sym.get_name())
    return rebound


def _names(node, ident: str) -> list:
    return [n for n in ast.walk(node) if isinstance(n, ast.Name) and n.id == ident]


def _unsafe_fn(fn) -> bool:
    """A function whose scoping the transforms do not model: nested defs/classes, global/nonlocal, del, generators, async, match, imports, try-star, walrus."""
    for n in ast.walk(fn):
        if n is fn:
            continue
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Global, ast.Nonlocal, ast.Delete, ast.Yield, ast.YieldFrom, ast.Await, ast.Match, ast.NamedExpr,
                          ast.Import, ast.ImportFrom, ast.AsyncFor, ast.AsyncWith)):
            return True
    return False


def _pure(e, bound: set) -> bool:
    return isinstance(e, ast.Constant) or (isinstance(e, ast.Name) and isinstance(e.ctx, ast.Load) and e.id in bound)


def _store_name(st):
    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
        return st.targets[0].id
    return None


def _terminates(stmts) -> bool:
    return bool(stmts) and isinstance(stmts[-1], _TERMINATORS)


# ----------------------------------------------------------------------------------------------- typed context (exact builtin parameter types, ENFORCED by the engine; see equiv_cert.engine_domain)
_STR_PURE_ARITY = {
    "upper": (0, 0), "lower": (0, 0), "title": (0, 0), "capitalize": (0, 0), "casefold": (0, 0), "swapcase": (0, 0),
    "strip": (0, 1), "lstrip": (0, 1), "rstrip": (0, 1),
    "removeprefix": (1, 1), "removesuffix": (1, 1),
    "replace": (2, 2),
}
_STR_PURE_METHODS = frozenset(_STR_PURE_ARITY)
_INT_TYPES = ("int", "bool")
_FLIP = {ast.Gt: ast.LtE, ast.GtE: ast.Lt, ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq}


class _Typed:
    """What the typed rules may assume: `params` name -> exact builtin type (target function only, excluding any locally rebound/shadowed parameter), `re_ok` (module `re` is the clean stdlib import),
    the immutable dict literals of the module, and which module builtin names (`sum`, `len`, `type`, `int`, `bool`) are not shadowed. `used` collects (param, type) pairs a rule actually relied on:
    they become the certified domain."""

    def __init__(self, params: dict, re_ok: bool, dicts: set, sum_ok: bool, *, len_ok: bool = False, type_ok: bool = False):
        self.params, self.re_ok, self.dicts, self.sum_ok = params, re_ok, dicts, sum_ok
        self.len_ok, self.type_ok = len_ok, type_ok
        self.used: set = set()

    def use(self, e) -> None:
        for n in ast.walk(e):
            if isinstance(n, ast.Name) and n.id in self.params:
                self.used.add((n.id, self.params[n.id]))

    def int_expr(self, e) -> bool:
        if isinstance(e, ast.Constant):
            return type(e.value) is int
        if isinstance(e, ast.Name):
            return self.params.get(e.id) in _INT_TYPES and isinstance(e.ctx, ast.Load)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, (ast.USub, ast.UAdd)):
            return self.int_expr(e.operand)
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Sub, ast.Mult)):
            return self.int_expr(e.left) and self.int_expr(e.right)
        return False

    def int_atom(self, c) -> bool:
        return (isinstance(c, ast.Compare) and len(c.ops) == 1 and type(c.ops[0]) in _FLIP and self.int_expr(c.left) and self.int_expr(c.comparators[0]))

    def str_pure(self, e) -> bool:
        """An expression built from exact-str parameters, str literals and total effect-free str methods / regex substitution with constant arguments: PURE and TOTAL (cannot raise, no effect)."""
        if isinstance(e, ast.Constant):
            return type(e.value) is str
        if isinstance(e, ast.Name):
            return self.params.get(e.id) == "str" and isinstance(e.ctx, ast.Load)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            return self.str_pure(e.left) and self.str_pure(e.right)
        if isinstance(e, ast.Call) and not e.keywords and isinstance(e.func, ast.Attribute):
            f = e.func
            if f.attr in _STR_PURE_ARITY and self.str_pure(f.value) and all(isinstance(a, ast.Constant) and type(a.value) is str for a in e.args):
                lo, hi = _STR_PURE_ARITY[f.attr]
                if lo <= len(e.args) <= hi:
                    return True
            if isinstance(f.value, ast.Name) and f.value.id == "re" and f.attr == "sub" and self.re_ok and len(e.args) == 3:
                pat, rep, x = e.args
                if isinstance(pat, ast.Constant) and isinstance(rep, ast.Constant) and type(pat.value) is str and type(rep.value) is str and "\\" not in rep.value and self.str_pure(x):
                    import re as _re

                    try:
                        _re.compile(pat.value)
                    except _re.error:
                        return False
                    return True
        return False

    def neg(self, c):
        return ast.Compare(left=c.left, ops=[_FLIP[type(c.ops[0])]()], comparators=c.comparators)


def _module_facts(tree, foreign_names: set) -> tuple:
    """(re_ok, immutable dict names, sum_ok, len_ok, type_ok) of a module AST. A dict is immutable when it is a single module-level literal of str/int keys and constant values and EVERY other mention in the module
    is a read (`k in D`, `D[k]`, `D.get(...)`), it is not named in any other file of the tree, and the module never reaches for globals()/vars()/setattr/exec/eval."""
    counts = _module_single_defs(tree)
    re_ok = counts.get("re", 0) == 0 and len([n for n in tree.body if isinstance(n, ast.Import) and any(al.name.split(".")[0] == "re" or (al.asname == "re") for al in n.names)]) == 1 and any(isinstance(n, ast.Import) and any(al.name == "re" and al.asname is None for al in n.names) for n in tree.body)
    dynamic = any(isinstance(n, ast.Name) and n.id in ("globals", "vars", "setattr", "exec", "eval", "__import__", "locals") for n in ast.walk(tree))
    sum_ok = counts.get("sum", 0) == 0 and not dynamic
    len_ok = counts.get("len", 0) == 0 and not dynamic
    type_ok = all(counts.get(k, 0) == 0 for k in ("type", "int", "bool", "str", "float", "list", "tuple")) and not dynamic
    dicts: set = set()
    if dynamic:
        return re_ok, dicts, sum_ok, len_ok, type_ok
    for st in tree.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and isinstance(st.value, ast.Dict):
            nm = st.targets[0].id
            if counts.get(nm, 0) != 1 or nm in foreign_names:
                continue
            if not all(isinstance(k, ast.Constant) and type(k.value) in (str, int) for k in st.value.keys if k is not None) or any(k is None for k in st.value.keys):
                continue
            if not all(isinstance(v, ast.Constant) or (isinstance(v, ast.Tuple) and all(isinstance(x, ast.Constant) for x in v.elts)) for v in st.value.values):
                continue
            reads = 0
            for n in ast.walk(tree):
                for ch in ast.iter_child_nodes(n):
                    if isinstance(ch, ast.Name) and ch.id == nm:
                        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops) and ch in n.comparators:
                            reads += 1
                        elif isinstance(n, ast.Subscript) and n.value is ch and isinstance(n.ctx, ast.Load):
                            reads += 1
                        elif isinstance(n, ast.Attribute) and n.value is ch and n.attr == "get":
                            reads += 1
                        elif n is st:
                            pass
                        else:
                            reads = -10 ** 6
            if reads >= 0:
                dicts.add(nm)
    return re_ok, dicts, sum_ok, len_ok, type_ok


# ----------------------------------------------------------------------------------------------- per-function block rewriting
class _Fn:
    def __init__(self, fn, funcs: dict, notes: list, typed=None):
        self.fn, self.funcs, self.notes = fn, funcs, notes
        self.typed = typed  # a _Typed for the TARGET function only (a helper's own annotations are never trusted)
        self.params = set(_params(fn))
        self.changed = False
        self.safe = not _unsafe_fn(fn)
        rebound = _rebound_in_fn(fn)
        self.local_stores = rebound | self.params
        # `except ... as x` UNBINDS x when the handler ends: such a name is never known to be bound anywhere in the function (a read of it may raise)
        self.unbindable = {h.name for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler) and h.name}
        if self.typed is not None:
            for k in list(self.typed.params):
                if k in rebound:
                    del self.typed.params[k]

    def _typed_deps(self, e) -> set[tuple[str, str]]:
        if self.typed is None:
            return set()
        return {(n.id, self.typed.params[n.id]) for n in ast.walk(e) if isinstance(n, ast.Name) and n.id in self.typed.params}

    def _int_or_len_pure(self, e) -> tuple[bool, set[tuple[str, str]]]:
        ty = self.typed
        if ty is None:
            return False, set()
        if ty.int_expr(e):
            return True, self._typed_deps(e)
        if (isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "len"
                and ty.len_ok and "len" not in self.local_stores and not e.keywords and len(e.args) == 1
                and isinstance(e.args[0], ast.Name) and ty.params.get(e.args[0].id) in ("str", "list[int]", "tuple[int, ...]")):
            p = e.args[0].id
            return True, {(p, ty.params[p])}
        if (isinstance(e, ast.Subscript) and isinstance(e.ctx, ast.Load) and isinstance(e.value, ast.Name)
                and ty.params.get(e.value.id) in ("list[int]", "tuple[int, ...]") and ty.int_expr(e.slice)):
            p = e.value.id
            return True, {(p, ty.params[p])} | self._typed_deps(e.slice)
        return False, set()

    def _expr_heap_pure(self, e) -> tuple[bool, set[tuple[str, str]]]:
        """True when evaluating (or truth-testing) `e` cannot mutate any existing heap container."""
        ty = self.typed
        if ty is None:
            return False, set()
        if isinstance(e, ast.Constant):
            return True, set()
        if isinstance(e, ast.Name) and isinstance(e.ctx, ast.Load):
            if e.id in ty.params:
                return True, {(e.id, ty.params[e.id])}
            return False, set()
        if isinstance(e, ast.UnaryOp):
            if isinstance(e.op, ast.Not):
                return self._expr_heap_pure(e.operand)
            if isinstance(e.op, (ast.UAdd, ast.USub)) and ty.int_expr(e.operand):
                return True, self._typed_deps(e.operand)
            return False, set()
        if isinstance(e, ast.BoolOp) and isinstance(e.op, (ast.And, ast.Or)):
            deps: set[tuple[str, str]] = set()
            for v in e.values:
                ok, d = self._expr_heap_pure(v)
                if not ok:
                    return False, set()
                deps |= d
            return True, deps
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Sub, ast.Mult)) and ty.int_expr(e):
            return True, self._typed_deps(e)
        ok_il, d_il = self._int_or_len_pure(e)
        if ok_il:
            return True, d_il
        if ty.str_pure(e):
            return True, self._typed_deps(e)
        if isinstance(e, ast.Compare) and len(e.ops) == 1:
            op, left, right = e.ops[0], e.left, e.comparators[0]
            # Exact-type entry guard `type(p) is [not] T` / `type(p) [not] in (int, bool)`
            if (ty.type_ok and "type" not in self.local_stores
                    and isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "type"
                    and not left.keywords and len(left.args) == 1 and isinstance(left.args[0], ast.Name)
                    and left.args[0].id in self.params):
                if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(right, ast.Name) and right.id in ("int", "bool", "str", "float", "list", "tuple") and right.id not in self.local_stores:
                    return True, set()
                if (isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, ast.Tuple) and right.elts
                        and all(isinstance(x, ast.Name) and x.id in ("int", "bool", "str", "float", "list", "tuple") and x.id not in self.local_stores for x in right.elts)):
                    return True, set()
            if isinstance(op, (ast.Is, ast.IsNot)):
                ok1, d1 = self._expr_heap_pure(left)
                ok2, d2 = self._expr_heap_pure(right)
                if ok1 and ok2:
                    return True, d1 | d2
            if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)):
                ok1, d1 = self._int_or_len_pure(left)
                ok2, d2 = self._int_or_len_pure(right)
                if ok1 and ok2:
                    return True, d1 | d2
            if isinstance(op, (ast.Eq, ast.NotEq)) and ty.str_pure(left) and ty.str_pure(right):
                return True, self._typed_deps(left) | self._typed_deps(right)
        return False, set()

    def _stmt_heap_pure(self, st) -> tuple[bool, set[tuple[str, str]]]:
        """True when executing `st` cannot mutate any existing heap container or create an alias to a mutable parameter."""
        ty = self.typed
        if ty is None:
            return False, set()
        if isinstance(st, ast.Pass):
            return True, set()
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
            return True, set()
        if isinstance(st, ast.Return):
            return (True, set()) if st.value is None else self._expr_heap_pure(st.value)
        if isinstance(st, ast.Raise):
            if st.cause is not None:
                return False, set()
            if st.exc is None:
                return True, set()
            ex = st.exc
            if (isinstance(ex, ast.Call) and isinstance(ex.func, ast.Name)
                    and ex.func.id in ("TypeError", "ValueError", "KeyError", "IndexError", "RuntimeError")
                    and ex.func.id not in self.local_stores and not ex.keywords
                    and all(isinstance(a, ast.Constant) for a in ex.args)):
                return True, set()
            return False, set()
        if isinstance(st, ast.Assign):
            if not all(isinstance(t, ast.Name) and t.id not in self.params for t in st.targets):
                return False, set()
            if isinstance(st.value, ast.Name) and ty.params.get(st.value.id) == "list[int]":
                return False, set()
            return self._expr_heap_pure(st.value)
        if isinstance(st, ast.If):
            ok_t, dt = self._expr_heap_pure(st.test)
            if not ok_t:
                return False, set()
            deps = set(dt)
            for branch in (st.body, st.orelse):
                for sub in branch:
                    ok_s, ds = self._stmt_heap_pure(sub)
                    if not ok_s:
                        return False, set()
                    deps |= ds
            return True, deps
        return False, set()

    def pure(self, e, bound: set) -> bool:
        """Effect-free and total: a constant, a bound-name load, or (typed) a pure total exact-str expression."""
        if _pure(e, bound):
            return True
        if self.typed is not None:
            if isinstance(e, ast.FormattedValue) and e.conversion == -1 and e.format_spec is None:
                e = e.value  # formatting an exact str with no spec/conversion is pure
            if self.typed.str_pure(e):
                self.typed.use(e)
                return True
        return False

    def refs(self, ident: str) -> int:
        return len(_names(self.fn, ident))

    def note(self, s: str):
        self.changed = True
        self.notes.append(f"{self.fn.name}: {s}")

    # --- block walk ------------------------------------------------------------------------
    def run(self):
        if not self.safe:
            return
        self.fn.body = self.block(self.fn.body, set(self.params), in_try=False, heap_clean=True, heap_deps=set())

    def block(self, stmts: list, bound: set, in_try: bool, heap_clean: bool = False, heap_deps: set | None = None) -> list:
        bound = set(bound) - self.unbindable
        heap_deps = set(heap_deps or ())
        out = list(stmts)
        i = 0
        while i < len(out):
            st = out[i]
            nxt = out[i + 1] if i + 1 < len(out) else None
            # descend into compound statements first (bodies see the bound set and heap cleanliness at entry)
            if isinstance(st, ast.If):
                ok_t, dt = self._expr_heap_pure(st.test) if heap_clean else (False, set())
                child_clean = heap_clean and ok_t
                child_deps = (heap_deps | dt) if child_clean else set()
                st.body = self.block(st.body, bound, in_try, child_clean, child_deps)
                st.orelse = self.block(st.orelse, bound, in_try, child_clean, child_deps)
            elif isinstance(st, (ast.For, ast.While)):
                st.body = self.block(st.body, bound, in_try, False, set())
                st.orelse = self.block(st.orelse, bound, in_try, False, set())
            elif isinstance(st, ast.With):
                # any context manager may swallow in __exit__ (never judged by name): the body is as observable after a raise as a `try` body
                st.body = self.block(st.body, bound, True, False, set())
            elif isinstance(st, ast.Try):
                st.body = self.block(st.body, bound, True, False, set())
                after = in_try or bool(st.finalbody)  # a `finally` may return and so swallow what the handlers / else raise
                for h in st.handlers:
                    h.body = self.block(h.body, bound, after, False, set())
                st.orelse = self.block(st.orelse, bound, after, False, set())
                st.finalbody = self.block(st.finalbody, bound, in_try, False, set())
            # Returning a conditional expression evaluates the predicate once and
            # exactly one arm, including when truth testing invokes Python code.
            if isinstance(st, ast.Return) and isinstance(st.value, ast.IfExp):
                value = st.value
                out[i:i + 1] = [ast.If(test=value.test, body=[ast.Return(value.body)], orelse=[]), ast.Return(value.orelse)]
                self.note("conditional return expanded to its two exit paths")
                continue
            # Double negation in an `if` test evaluates truthiness once (identical to testing the operand directly).
            if isinstance(st, ast.If) and isinstance(st.test, ast.UnaryOp) and isinstance(st.test.op, ast.Not) \
                    and isinstance(st.test.operand, ast.UnaryOp) and isinstance(st.test.operand.op, ast.Not):
                st.test = st.test.operand.operand
                self.note("double negation in if-test simplified")
                continue
            # `if A and B: return X; return Y`  <->  `if not A: return Y; if B: return X; return Y`
            # Exact for ALL Python objects (no type assumption): evaluates A once, short-circuits to Y when falsy,
            # evaluates B once when A is truthy, and evaluates Y at most once on every path.
            if (isinstance(st, ast.If) and not st.orelse and len(st.body) == 1
                    and isinstance(st.body[0], ast.Return)
                    and isinstance(st.test, ast.BoolOp) and isinstance(st.test.op, ast.And) and len(st.test.values) >= 2
                    and nxt is not None and isinstance(nxt, ast.Return)
                    and (nxt.value is None or sum(1 for _ in ast.walk(nxt.value)) <= 32)):
                first = st.test.values[0]
                rest_vals = st.test.values[1:]
                rest_test = rest_vals[0] if len(rest_vals) == 1 else ast.BoolOp(op=ast.And(), values=rest_vals)
                out[i:i + 1] = [
                    ast.If(test=ast.UnaryOp(op=ast.Not(), operand=first), body=[copy.deepcopy(nxt)], orelse=[]),
                    ast.If(test=rest_test, body=st.body, orelse=[]),
                ]
                self.note("conjunctive early return split into sequential guards")
                continue
            # rewrites at this position
            if self.dead(out, i, bound):
                continue
            if self.temp(out, i, bound):
                continue
            if not in_try and self.comp(out, i):
                continue
            if not in_try and self.typed is not None and (self.flat(out, i) or self.dget(out, i) or self.sum_loop(out, i, heap_clean, heap_deps)):
                continue
            if self.ret(out, i):
                continue
            self.expr_rewrites(st, bound)
            nm = _store_name(st)
            if nm is not None and nm not in self.unbindable:
                bound.add(nm)
            if heap_clean:
                ok_s, ds = self._stmt_heap_pure(st)
                if ok_s:
                    heap_deps |= ds
                else:
                    heap_clean = False
                    heap_deps = set()
            i += 1
        out = self.flatten_else(out)
        return out

    # --- else after a branch that always terminates ----------------------------------------
    def flatten_else(self, stmts: list) -> list:
        out = []
        for st in stmts:
            if isinstance(st, ast.If) and st.orelse and _terminates(st.body):
                tail = st.orelse
                st.orelse = []
                out.append(st)
                out.extend(self.flatten_else(tail))
                self.note("else after a terminating branch flattened")
            else:
                out.append(st)
        return out

    # --- dead pure binding -----------------------------------------------------------------
    def dead(self, out: list, i: int, bound: set) -> bool:
        st = out[i]
        nm = _store_name(st)
        if nm is None or nm in self.params or self.refs(nm) != 1:
            return False
        if not _pure(st.value, bound):
            return False
        del out[i]
        self.note(f"dead binding of {nm} removed")
        return True

    # --- single-use temp -------------------------------------------------------------------
    def temp(self, out: list, i: int, bound: set) -> bool:
        st = out[i]
        t = _store_name(st)
        if t is None or t in self.params or i + 1 >= len(out):
            return False
        s = out[i + 1]
        if not isinstance(s, (ast.Return, ast.Assign, ast.Expr)):
            return False
        if self.refs(t) != 2:
            return False
        loads = [n for n in _names(s, t) if isinstance(n.ctx, ast.Load)]
        if len(loads) != 1 or any(isinstance(n.ctx, ast.Store) for n in _names(s, t)):
            return False
        if isinstance(s, ast.Assign) and not all(isinstance(x, ast.Name) for x in s.targets):
            return False
        root = s.value if not isinstance(s, ast.Return) else s.value
        if root is None:
            return False
        if not self._ordered_pure_prefix(root, loads[0], bound):
            return False
        new_value = st.value
        s2 = copy.deepcopy(s)
        for n in ast.walk(s2):
            for fld, val in ast.iter_fields(n):
                if isinstance(val, ast.Name) and val.id == t and isinstance(val.ctx, ast.Load):
                    setattr(n, fld, copy.deepcopy(new_value))
                elif isinstance(val, list):
                    for k, x in enumerate(val):
                        if isinstance(x, ast.Name) and x.id == t and isinstance(x.ctx, ast.Load):
                            val[k] = copy.deepcopy(new_value)
        out[i:i + 2] = [s2]
        self.note(f"single-use temp {t} inlined")
        return True

    def _ordered_pure_prefix(self, root, target, bound: set) -> bool:
        """True when `target` (a Name load) is evaluated unconditionally within `root` and everything evaluated BEFORE it is a constant or a bound-name load."""
        def children(n):
            if isinstance(n, ast.BinOp):
                return [(n.left, True), (n.right, True)]
            if isinstance(n, ast.UnaryOp):
                return [(n.operand, True)]
            if isinstance(n, ast.Call):
                return [(n.func, True)] + [(a, True) for a in n.args] + [(k.value, True) for k in n.keywords]
            if isinstance(n, ast.Attribute):
                return [(n.value, True)]
            if isinstance(n, ast.Subscript):
                return [(n.value, True), (n.slice, True)]
            if isinstance(n, ast.Compare):
                return [(n.left, True)] + [(c, k == 0) for k, c in enumerate(n.comparators)]
            if isinstance(n, ast.BoolOp):
                return [(v, k == 0) for k, v in enumerate(n.values)]
            if isinstance(n, ast.IfExp):
                return [(n.test, True), (n.body, False), (n.orelse, False)]
            if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
                return [(x, True) for x in n.elts]
            if isinstance(n, ast.Dict):
                return [(x, True) for kv in zip(n.keys, n.values) for x in kv if x is not None]
            if isinstance(n, ast.JoinedStr):
                return [(x, True) for x in n.values]
            if isinstance(n, ast.FormattedValue):
                return [(n.value, True)] + ([(n.format_spec, True)] if n.format_spec is not None else [])
            if isinstance(n, ast.Starred):
                return [(n.value, True)]
            return None

        # everything evaluated BEFORE the target must be a constant or a bound-name load; the target must sit in an unconditionally evaluated position
        def ok_before(n) -> bool:
            if n is target:
                return True
            if any(x is target for x in ast.walk(n)):
                ch = children(n)
                if ch is None:
                    return False
                # `*x` / `**x` runs user iteration / mapping code when it is evaluated, although loading x is pure: nothing may move across it
                mapped = ([v for k, v in zip(n.keys, n.values) if k is None] if isinstance(n, ast.Dict)
                          else [k.value for k in n.keywords if k.arg is None] if isinstance(n, ast.Call) else [])
                for c, uncond in ch:
                    if any(x is target for x in ast.walk(c)):
                        return uncond and ok_before(c)
                    if any(c is m for m in mapped) or _unpacks(c) or not self.pure(c, bound):
                        return False
                return False
            return True

        return ok_before(root)

    # --- append loop -> comprehension --------------------------------------------------------
    def comp(self, out: list, i: int) -> bool:
        st = out[i]
        o = _store_name(st)
        if o is None or o in self.params or not (isinstance(st.value, ast.List) and not st.value.elts) or i + 1 >= len(out):
            return False
        loop = out[i + 1]
        if not (isinstance(loop, ast.For) and isinstance(loop.target, ast.Name) and not loop.orelse and len(loop.body) == 1):
            return False
        v = loop.target.id
        body = loop.body[0]
        cond = None
        if isinstance(body, ast.If) and not body.orelse and len(body.body) == 1:
            cond, body = body.test, body.body[0]
        if not (isinstance(body, ast.Expr) and isinstance(body.value, ast.Call) and isinstance(body.value.func, ast.Attribute) and body.value.func.attr == "append"
                and isinstance(body.value.func.value, ast.Name) and body.value.func.value.id == o and len(body.value.args) == 1 and not body.value.keywords
                and not isinstance(body.value.args[0], ast.Starred)):
            return False
        x = body.value.args[0]
        for part in (x, cond, loop.iter):
            if part is not None and any(isinstance(n, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)) for n in ast.walk(part)):
                return False
        # out: stored exactly once (the init); loaded exactly once inside the loop (the append receiver)
        if len([n for n in _names(self.fn, o) if isinstance(n.ctx, ast.Store)]) != 1 or len(_names(loop, o)) != 1:
            return False
        if v in self.params or self.refs(v) != len(_names(loop, v)):  # the loop variable must not be read outside the loop
            return False
        if any(isinstance(n, ast.Name) and n.id == v for n in ast.walk(loop.iter)):  # the first iterable of a comprehension is evaluated in the ENCLOSING scope: a global named v would be read
            return False
        if any(isinstance(n, ast.Name) and n.id == o for part in (x, cond, loop.iter) if part is not None for n in ast.walk(part)):
            return False
        gens = [ast.comprehension(target=ast.Name(id=v, ctx=ast.Store()), iter=loop.iter, ifs=[cond] if cond is not None else [], is_async=0)]
        out[i:i + 2] = [ast.Assign(targets=[ast.Name(id=o, ctx=ast.Store())], value=ast.ListComp(elt=x, generators=gens), lineno=0)]
        self.note(f"append loop over {v} into {o} became a comprehension")
        return True

    # --- TYPED: guard flattening over exact ints ------------------------------------------------
    def flat(self, out: list, i: int) -> bool:
        st = out[i]
        ty = self.typed
        if not (isinstance(st, ast.If) and not st.orelse and len(st.body) == 1 and isinstance(st.body[0], ast.If) and not st.body[0].orelse):
            return False
        inner = st.body[0]
        rest = out[i + 1:]
        if not rest or not _terminates(rest) or not _terminates(inner.body):
            return False
        if not (ty.int_atom(st.test) and ty.int_atom(inner.test)):
            return False
        ty.use(st.test)
        ty.use(inner.test)
        guard = ast.If(test=ast.BoolOp(op=ast.Or(), values=[ty.neg(st.test), ty.neg(inner.test)]), body=rest, orelse=[])
        out[i:] = [guard, *inner.body]
        self.note("nested int guards flattened into one or-guard")
        return True

    # --- TYPED: membership + index <-> dict.get over an immutable dict literal ------------------------
    def dget(self, out: list, i: int) -> bool:
        st = out[i]
        ty = self.typed
        if not (isinstance(st, ast.If) and not st.orelse and i + 2 == len(out) and isinstance(out[i + 1], ast.Return) and out[i + 1].value is not None):
            return False
        c = st.test
        if not (isinstance(c, ast.Compare) and len(c.ops) == 1 and isinstance(c.ops[0], ast.In) and isinstance(c.left, ast.Name) and isinstance(c.comparators[0], ast.Name)):
            return False
        k, d = c.left.id, c.comparators[0].id
        if d not in ty.dicts or ty.params.get(k) not in ("str", "int") or len(st.body) != 1:
            return False
        r = st.body[0]
        if not (isinstance(r, ast.Return) and isinstance(r.value, ast.Subscript) and isinstance(r.value.value, ast.Name) and r.value.value.id == d
                and isinstance(r.value.slice, ast.Name) and r.value.slice.id == k):
            return False
        default = out[i + 1].value
        if not isinstance(default, ast.Constant):
            return False
        ty.used.add((k, ty.params[k]))
        out[i:] = [ast.Return(value=ast.Call(func=ast.Attribute(value=ast.Name(id=d, ctx=ast.Load()), attr="get", ctx=ast.Load()), args=[ast.Name(id=k, ctx=ast.Load()), default], keywords=[]))]
        self.note("membership + index became dict.get")
        return True

    # --- TYPED: accumulate loop <-> sum() over an exact-int sequence --------------------------------
    def sum_loop(self, out: list, i: int, heap_clean: bool = False, heap_deps: set | None = None) -> bool:
        st = out[i]
        ty = self.typed
        t = _store_name(st)
        if t is None or not (isinstance(st.value, ast.Constant) and type(st.value.value) is int and st.value.value == 0) or i + 1 >= len(out) or not ty.sum_ok:
            return False
        loop = out[i + 1]
        if not (isinstance(loop, ast.For) and isinstance(loop.target, ast.Name) and isinstance(loop.iter, ast.Name) and not loop.orelse and len(loop.body) == 1):
            return False
        xs, p = loop.iter.id, loop.target.id
        if ty.params.get(xs) not in ("list[int]", "tuple[int, ...]") or p in self.params or t in self.params:
            return False
        if ty.params.get(xs) == "list[int]" and not heap_clean:
            return False
        b = loop.body[0]
        if not (isinstance(b, ast.AugAssign) and isinstance(b.op, ast.Add) and isinstance(b.target, ast.Name) and b.target.id == t and isinstance(b.value, ast.Name) and b.value.id == p):
            return False
        if self.refs(p) != 2 or len([n for n in _names(self.fn, t) if isinstance(n.ctx, ast.Store)]) != 2 or "sum" in self.local_stores:
            return False
        ty.used.add((xs, ty.params[xs]))
        if ty.params.get(xs) == "list[int]" and heap_deps:
            ty.used |= heap_deps
        out[i:i + 2] = [ast.Assign(targets=[ast.Name(id=t, ctx=ast.Store())], value=ast.Call(func=ast.Name(id="sum", ctx=ast.Load()), args=[ast.Name(id=xs, ctx=ast.Load())], keywords=[]), lineno=0)]
        self.note(f"accumulate loop over {xs} became sum()")
        return True

    # --- assign-then-return <-> return on every path -----------------------------------------------
    def ret(self, out: list, i: int) -> bool:
        st = out[i]
        if not isinstance(st, ast.If) or i + 2 != len(out):
            return False
        last = out[i + 1]
        if not (isinstance(last, ast.Return) and isinstance(last.value, ast.Name)):
            return False
        x = last.value.id
        if x in self.params:
            return False
        stores = [n for n in _names(self.fn, x) if isinstance(n.ctx, ast.Store)]
        conv = self._conv(st, x)
        if conv is None:
            return False
        if len(stores) != self._count_leaf_assigns(st, x) or self.refs(x) != len(stores) + 1:
            return False
        out[i:i + 2] = [conv]
        self.note(f"assign-then-return of {x} became returns on every path")
        return True

    def _count_leaf_assigns(self, node, x: str) -> int:
        return len([n for n in ast.walk(node) if isinstance(n, ast.Name) and n.id == x and isinstance(n.ctx, ast.Store)])

    def _conv(self, node, x: str):
        """Rewrite an If tree whose every path ends by assigning x (or terminating) into returns; None when some path would fall through with x unassigned."""
        if isinstance(node, ast.If):
            if not node.orelse:
                return None
            nb, no = self._conv_list(node.body, x), self._conv_list(node.orelse, x)
            if nb is None or no is None:
                return None
            return ast.If(test=node.test, body=nb, orelse=no)
        return None

    def _conv_list(self, stmts: list, x: str):
        if not stmts:
            return None
        head, tail = stmts[:-1], stmts[-1]
        if any(len([n for n in _names(h, x)]) for h in head):
            return None
        if isinstance(tail, ast.Assign) and _store_name(tail) == x:
            return [*head, ast.Return(value=tail.value)]
        if isinstance(tail, _TERMINATORS) and not _names(tail, x):
            return [*head, tail]
        if isinstance(tail, ast.If):
            c = self._conv(tail, x)
            return None if c is None else [*head, c]
        return None

    # --- expression-level rewrites (inline helper calls, str.format) ----------------------------------
    def expr_rewrites(self, st, bound: set):
        tx = _ExprRewriter(self, bound)
        for fld, val in ast.iter_fields(st):
            if isinstance(val, ast.AST) and isinstance(val, ast.expr):
                setattr(st, fld, tx.visit(val))
            elif isinstance(val, list):
                for k, x in enumerate(val):
                    if isinstance(x, ast.expr):
                        val[k] = tx.visit(x)


class _ExprRewriter(ast.NodeTransformer):
    def __init__(self, f: _Fn, bound: set):
        self.f, self.bound = f, bound

    def visit_Call(self, node):
        node = self.generic_visit(node)
        self._literal_arguments(node)
        r = self._inline(node)
        if r is not None:
            return r
        r = self._fmt(node)
        return r if r is not None else node

    def _literal_arguments(self, call):
        """Unpack exact literals at a statically named, undecorated helper call.
        Restrict loads to constants and bound names. In particular, an unknown
        iterable or mapping can run protocol code and must stay in place.
        """
        if not isinstance(call.func, ast.Name) or call.func.id in self.f.local_stores or call.func.id not in self.f.funcs:
            return
        if not any(isinstance(a, ast.Starred) for a in call.args) and all(k.arg is not None for k in call.keywords):
            return
        args = []
        for arg in call.args:
            if isinstance(arg, ast.Starred):
                if not isinstance(arg.value, (ast.Tuple, ast.List)):
                    return
                args.extend(arg.value.elts)
            else:
                args.append(arg)
        keywords = []
        for kw in call.keywords:
            if kw.arg is not None:
                keywords.append(kw)
            elif isinstance(kw.value, ast.Dict):
                for key, value in zip(kw.value.keys, kw.value.values):
                    if not (isinstance(key, ast.Constant) and type(key.value) is str
                            and key.value.isidentifier() and not keyword.iskeyword(key.value)):
                        return
                    keywords.append(ast.keyword(arg=key.value, value=value))
            else:
                return
        if len({k.arg for k in keywords}) != len(keywords):
            return
        if not all(_pure(e, self.bound) for e in [*args, *(k.value for k in keywords)]):
            return
        # CALL_FUNCTION_EX and ordinary CALL have different error machinery.
        # Only canonicalize valid bindings, including positional-only and required keyword-only parameters.
        from inspect import Parameter, Signature
        signature = self.f.funcs[call.func.id].args
        if signature.vararg or signature.kwarg:
            return
        positional = [*signature.posonlyargs, *signature.args]
        required = len(positional) - len(signature.defaults)
        slots = []
        for index, arg in enumerate(positional):
            kind = Parameter.POSITIONAL_ONLY if index < len(signature.posonlyargs) else Parameter.POSITIONAL_OR_KEYWORD
            slots.append(Parameter(arg.arg, kind, default=Parameter.empty if index < required else None))
        for arg, default in zip(signature.kwonlyargs, signature.kw_defaults):
            slots.append(Parameter(arg.arg, Parameter.KEYWORD_ONLY, default=Parameter.empty if default is None else None))
        try:
            Signature(slots).bind(*args, **{k.arg: k.value for k in keywords})
        except (TypeError, ValueError):
            return
        call.args, call.keywords = args, keywords
        self.f.note("literal call arguments unpacked in evaluation order")

    def _inline(self, call):
        if not (isinstance(call.func, ast.Name) and not call.keywords and not any(isinstance(a, ast.Starred) for a in call.args)):
            return None
        h = self.f.funcs.get(call.func.id)
        if h is None or h is self.f.fn or call.func.id in self.f.local_stores:
            return None
        e = _expr_body(h)
        ps = [a.arg for a in h.args.args]
        if e is None or len(ps) != len(call.args) or len(set(ps)) != len(ps):
            return None
        if not all(_pure(a, self.bound) for a in call.args):
            return None
        if any(isinstance(n, ast.Name) and n.id == h.name for n in ast.walk(e)):
            return None  # recursion
        pset = set(ps)
        free = {n.id for n in ast.walk(e) if isinstance(n, ast.Name)} - pset
        if free & self.f.local_stores:  # a caller local would capture a global the helper reads
            return None
        sub = dict(zip(ps, call.args))
        res = copy.deepcopy(e)
        res = _Subst(sub).visit(res)
        self.f.note(f"call of helper {h.name} inlined")
        return res

    def _fmt(self, call):
        f = call.func
        if not (isinstance(f, ast.Attribute) and f.attr == "format" and isinstance(f.value, ast.Constant) and isinstance(f.value.value, str)):
            return None
        if call.keywords or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        try:
            parts = list(string.Formatter().parse(f.value.value))
        except ValueError:
            return None
        fields, auto = [], 0
        for lit, name, spec, conv in parts:
            if name is None:
                continue
            if spec not in (None, "") or conv is not None:
                return None
            if name == "":
                idx, auto = auto, auto + 1
            elif name.isdigit():
                idx = int(name)
            else:
                return None
            if idx >= len(call.args):
                return None
            fields.append(idx)
        if any(n == "" for _, n, _, _ in parts if n is not None) and any(n.isdigit() for _, n, _, _ in parts if n):
            return None  # mixing automatic and manual numbering is an error in str.format: leave it
        first, seen = [], set()
        for idx in fields:
            if idx not in seen:
                first.append(idx)
                seen.add(idx)
        if first != sorted(first) or first != list(range(len(first))) or len(first) != len(call.args):
            return None  # arguments must be used in evaluation order and all used
        for k, a in enumerate(call.args):
            if k > 0 and not self.f.pure(a, self.bound):
                return None
            if fields.count(k) > 1 and not self.f.pure(a, self.bound):
                return None
        vals: list = []
        fi = [i for i in self._fields_in_order(parts, len(call.args))]
        j = 0
        for lit, name, spec, conv in parts:
            if lit:
                if vals and isinstance(vals[-1], ast.Constant):
                    vals[-1] = ast.Constant(value=vals[-1].value + lit)
                else:
                    vals.append(ast.Constant(value=lit))
            if name is not None:
                vals.append(ast.FormattedValue(value=copy.deepcopy(call.args[fi[j]]), conversion=-1, format_spec=None))
                j += 1
        self.f.note("str.format became an f-string")
        return ast.JoinedStr(values=vals)

    @staticmethod
    def _fields_in_order(parts, nargs):
        auto = 0
        for lit, name, spec, conv in parts:
            if name is None:
                continue
            if name == "":
                yield auto
                auto += 1
            else:
                yield int(name)


class _Subst(ast.NodeTransformer):
    def __init__(self, sub: dict):
        self.sub = sub

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in self.sub:
            return copy.deepcopy(self.sub[node.id])
        return node


def _unpacks(node) -> bool:
    return any(isinstance(x, ast.Starred) or (isinstance(x, ast.Dict) and None in x.keys) or (isinstance(x, ast.keyword) and x.arg is None)
               for x in ast.walk(node))


def _expr_body(h):
    """The expression of a one-`return` helper (docstring allowed): plain positional parameters only, nothing the substitution could mis-scope; else None."""
    if h.decorator_list:
        return None
    a = h.args
    if a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg or a.defaults or a.kw_defaults:
        return None
    body = list(h.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return None
    e = body[0].value
    if any(isinstance(n, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Yield, ast.YieldFrom, ast.Await, ast.NamedExpr, ast.Starred)) for n in ast.walk(e)):
        return None
    return e


# ----------------------------------------------------------------------------------------------- entry
def _module_single_defs(tree) -> dict:
    counts: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            counts[n.name] = counts.get(n.name, 0) + 1
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            counts[n.id] = counts.get(n.id, 0) + 1
        elif isinstance(n, ast.Global):
            for g in n.names:
                counts[g] = counts.get(g, 0) + 2
    return counts


def normalize_source(src: str, target: str | None = None, typed_params: dict | None = None, foreign_names: set | None = None) -> tuple:
    """(normalized source text, notes of the transforms applied, set of (param, exact type) the typed rules relied on, names of the proven-immutable module dict literals). `typed_params` maps the TARGET function's parameters to their exact builtin
    domain type (enforced by the engine); without it no typed rule fires. A source that does not parse is returned unchanged."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return src, [], set(), set()
    counts = _module_single_defs(tree)
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef) and not n.decorator_list and counts.get(n.name, 0) == 1}
    notes: list = []
    typed = None
    re_ok, dicts, sum_ok, len_ok, type_ok = _module_facts(tree, foreign_names or set())
    if target and typed_params:
        sym_rebound = _symtable_rebound_params(src, target)
        target_fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == target), None)
        if sym_rebound is not None and target_fn is not None:
            rebound = sym_rebound | _rebound_in_fn(target_fn)
            safe_params = {k: v for k, v in typed_params.items() if k not in rebound}
            if safe_params:
                typed = _Typed(safe_params, re_ok, dicts, sum_ok, len_ok=len_ok, type_ok=type_ok)
    for _ in range(_MAX_PASSES):
        changed = False
        for fn in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
            f = _Fn(fn, funcs, notes, typed if (typed is not None and fn.name == target) else None)
            f.run()
            changed = changed or f.changed
        if not changed:
            break
    ast.fix_missing_locations(tree)
    return ast.unparse(tree), notes, (typed.used if typed is not None else set()), set(dicts)
