# SPDX-License-Identifier: Apache-2.0
"""The builtin model of the symbolic equivalence prover: what operators, builtin functions and builtin methods do on EXACT builtin values.

Soundness rules for every entry (each is exercised against the live interpreter):
  * an operation is only given exact semantics when every operand is an exact builtin value (no subclass, no user object): otherwise it is an opaque world operation;
  * an operation that can raise raises FIRST (explicit fork) under an exact condition where one is modelled, else under an uninterpreted predicate of the same operands (`partial`):
    declaring an operation total when it can raise would be unsound, declaring it partial when it cannot is only incomplete;
  * a result type must be the exact type CPython returns for those operand types;
  * no identity (`is`) between values is ever concluded from equality, and no algebraic law is assumed for floats."""

from __future__ import annotations

import ast

from .executor import BOT, FUNC, MAYBE, Unknown, Val, _Fork, _deref_ty, _has_bot
from .terms import (BOOL, BYTES, DICT, EXC, FLOAT, FROZENSET, FTUPLE, INT, ITER, LIST, NONE, OPAQUE, RANGE, SET, STR, TUPLE, Term, elem_type, float_free, hashable, is_exact,
                    is_immutable, is_mutable_builtin, ty_str)

_OPNAME = {ast.Add: "Add", ast.Sub: "Sub", ast.Mult: "Mult", ast.Div: "Div", ast.FloorDiv: "FloorDiv", ast.Mod: "Mod", ast.Pow: "Pow", ast.LShift: "LShift", ast.RShift: "RShift",
           ast.BitOr: "BitOr", ast.BitAnd: "BitAnd", ast.BitXor: "BitXor", ast.MatMult: "MatMult"}
_CMPNAME = {ast.Eq: "Eq", ast.NotEq: "NotEq", ast.Lt: "Lt", ast.LtE: "LtE", ast.Gt: "Gt", ast.GtE: "GtE", ast.Is: "Is", ast.IsNot: "IsNot", ast.In: "In", ast.NotIn: "NotIn"}
_NUM = ("int", "bool", "float")
_SEQ = ("list", "tuple", "str", "bytes")
_SIZED = ("list", "tuple", "str", "bytes", "dict", "set", "frozenset", "range")
_KIND_CLASS = {"int": int, "bool": bool, "str": str, "float": float, "none": type(None), "bytes": bytes, "list": list, "tuple": tuple, "ftuple": tuple, "dict": dict, "set": set,
               "frozenset": frozenset, "range": range}
_CLASS_NAMES = {"int": "int", "bool": "bool", "str": "str", "float": "float", "none": "NoneType", "bytes": "bytes", "list": "list", "tuple": "tuple", "ftuple": "tuple",
                "dict": "dict", "set": "set", "frozenset": "frozenset", "range": "range"}

# builtins that neither keep a reference to an argument nor mutate it: a local container passed to one does not escape
_NOESCAPE = frozenset({"len", "str", "repr", "int", "float", "bool", "abs", "min", "max", "sum", "sorted", "list", "tuple", "set", "frozenset", "dict", "any", "all", "isinstance",
                       "issubclass", "type", "print", "format", "hash", "ord", "chr", "round", "divmod", "callable", "bin", "hex", "oct", "ascii", "bytes", "pow"})
_DYNAMIC = frozenset({"eval", "exec", "globals", "locals", "vars", "compile", "__import__", "breakpoint", "super", "id", "delattr", "dir", "memoryview", "input", "exit", "quit",
                      "object", "classmethod", "staticmethod", "property", "__build_class__"})

# str methods: name -> (result type, total?)   (receiver and every argument an exact builtin immutable value)
_STR_M = {
    "lower": (STR, True), "upper": (STR, True), "casefold": (STR, True), "title": (STR, True), "capitalize": (STR, True), "swapcase": (STR, True),
    "strip": (STR, True), "lstrip": (STR, True), "rstrip": (STR, True), "removeprefix": (STR, True), "removesuffix": (STR, True),
    "replace": (STR, False), "zfill": (STR, False), "center": (STR, False), "ljust": (STR, False), "rjust": (STR, False), "expandtabs": (STR, False), "format": (STR, False),
    "split": (LIST(STR), False), "rsplit": (LIST(STR), False), "splitlines": (LIST(STR), True),
    "partition": (FTUPLE(STR, STR, STR), False), "rpartition": (FTUPLE(STR, STR, STR), False),
    "startswith": (BOOL, True), "endswith": (BOOL, True),
    "find": (INT, True), "rfind": (INT, True), "index": (INT, False), "rindex": (INT, False), "count": (INT, True),
    "isdigit": (BOOL, True), "isalpha": (BOOL, True), "isalnum": (BOOL, True), "isspace": (BOOL, True), "islower": (BOOL, True), "isupper": (BOOL, True),
    "isidentifier": (BOOL, True), "isascii": (BOOL, True), "isnumeric": (BOOL, True), "isdecimal": (BOOL, True), "istitle": (BOOL, True), "isprintable": (BOOL, True),
    "encode": (BYTES, False),
}
# str methods that are total only with NO argument (an argument of the wrong type raises)
_STR_TOTAL_NOARG_ONLY = frozenset({"strip", "lstrip", "rstrip", "splitlines", "split", "rsplit"})
_BYTES_M = {"decode": (STR, False), "startswith": (BOOL, False), "endswith": (BOOL, False), "strip": (BYTES, False), "lower": (BYTES, True), "upper": (BYTES, True),
            "hex": (STR, False), "split": (LIST(BYTES), False)}


def _orderable(ty) -> bool:
    k = ty[0]
    if k in ("int", "bool", "str", "float", "bytes"):
        return True
    if k in ("tuple", "list"):
        return _orderable(ty[1])
    if k == "ftuple":
        return all(_orderable(x) for x in ty[1:])
    return False


class Model:
    # ================================================================================================================ term hooks
    def install(self, ctx):
        ctx.simp["len"] = self._simp_len
        ctx.fact_hooks["len"] = lambda c, t: c.fact(c.le(c.const(0), t))
        ctx.simp["str.concat"] = self._simp_concat
        ctx.simp["getitem"] = self._simp_getitem
        ctx.fact_hooks["getitem"] = self._fact_getitem
        ctx.simp["contains"] = self._simp_contains
        ctx.simp["list.append"] = self._simp_append
        ctx.simp["tuple:list"] = lambda c, n, a, ty: a[0].args[1] if (a[0].op == "app" and a[0].args[0] == "list:tuple" and a[0].args[1].ty == ty) else None
        ctx.simp["list:tuple"] = lambda c, n, a, ty: a[0].args[1] if (a[0].op == "app" and a[0].args[0] == "tuple:list" and a[0].args[1].ty == ty) else None
        ctx.simp["iter.empty"] = self._simp_iter_empty

    @staticmethod
    def _name(t):
        return t.args[0] if t.op == "app" else None

    def _simp_len(self, c, name, args, ty):
        (x,) = args
        if x.op == "const" and x.ty in (STR, BYTES):
            return c.const(len(x.args[0]))
        if x.ty[0] == "ftuple":
            return c.const(len(x.ty) - 1)
        if x.op == "ite":
            return c.ite(x.args[0], c.app("len", (x.args[1],), INT), c.app("len", (x.args[2],), INT))
        n = self._name(x)
        if n is None:
            return None
        a = x.args[1:]
        if n in ("list.empty", "dict.empty", "set.empty"):
            return c.const(0)
        if n == "list.lit":
            return c.const(len(a))
        if n == "list.append":
            return c.add(c.app("len", (a[0],), INT), c.const(1))
        if n in ("list.concat", "tuple.concat", "bytes.concat"):
            return c.add(c.app("len", (a[0],), INT), c.app("len", (a[1],), INT))
        if n == "str.concat":
            r = c.const(0)
            for p in a:
                r = c.add(r, c.app("len", (p,), INT))
            return r
        if n in ("list:tuple", "tuple:list", "list.reversed", "list.sorted", "list.sorted.rev", "list:str", "list.setitem", "sorted", "sorted.rev"):
            return c.app("len", (a[0],), INT)
        if n == "range" and a[2].op == "const" and a[2].args[0] == 1:
            lo, hi = a[0], a[1]
            return c.ite(c.lt(lo, hi), c.sub(hi, lo), c.const(0))
        return None

    def _simp_concat(self, c, name, args, ty):
        flat, changed = [], False
        for a in args:
            if a.op == "app" and a.args[0] == "str.concat":
                flat.extend(a.args[1:])
                changed = True
            else:
                flat.append(a)
        out = []
        for a in flat:
            if a.op == "const":
                if a.args[0] == "":
                    changed = True
                    continue
                if out and out[-1].op == "const":
                    out[-1] = c.const(out[-1].args[0] + a.args[0])
                    changed = True
                    continue
            out.append(a)
        if not out:
            return c.const("")
        if len(out) == 1:
            return out[0]
        if not changed:
            return None
        return c.app("str.concat", tuple(out), STR)

    def _simp_append(self, c, name, args, ty):
        lst, x = args
        n = self._name(lst)
        if n == "list.empty":
            return c.app("list.lit", (x,), ty)
        if n == "list.lit" and len(lst.args) <= 12:
            return c.app("list.lit", (*lst.args[1:], x), ty)
        return None

    def _simp_getitem(self, c, name, args, ty):
        x, k = args
        n = self._name(x)
        if n == "list.lit" and k.op == "const" and k.ty == INT and 0 <= k.args[0] < len(x.args) - 1:
            return x.args[1 + k.args[0]]
        if n == "dict.set":
            d, k1, v = x.args[1:]
            return c.ite(c.eq(k1, k), v, c.app("getitem", (d, k), ty))
        if n == "dict.lit":
            pairs = x.args[1:]
            # under the caller's `contains` guard some key matches; later duplicates win, so the LAST matching pair is the outermost test
            r = None
            for i in range(0, len(pairs), 2):
                r = pairs[i + 1] if r is None else c.ite(c.eq(pairs[i], k), pairs[i + 1], r)
            return r
        if x.op == "ite":
            return c.ite(x.args[0], c.app("getitem", (x.args[1], k), ty), c.app("getitem", (x.args[2], k), ty))
        return None

    def _fact_getitem(self, c, t):
        if t.ty == STR and t.args[1].ty == STR:
            c.fact(c.eq(c.app("len", (t,), INT), c.const(1)))

    def _simp_contains(self, c, name, args, ty):
        x, k = args
        n = self._name(x)
        if n in ("list.empty", "dict.empty", "set.empty"):
            return c.FALSE
        if n in ("dict.set", "set.add"):
            return c.or_(c.eq(x.args[2], k), c.app("contains", (x.args[1], k), BOOL))
        if n == "dict.lit":
            return c.or_(*[c.eq(x.args[i], k) for i in range(1, len(x.args), 2)])
        if n in ("list.lit", "set.lit") and x.ty[1] == k.ty and float_free(k.ty) and is_exact(k.ty):
            return c.or_(*[c.eq(e, k) for e in x.args[1:]])
        if x.op == "tup" and all(e.ty == k.ty for e in x.args) and float_free(k.ty) and is_exact(k.ty):
            return c.or_(*[c.eq(e, k) for e in x.args])
        if x.op == "ite":
            return c.ite(x.args[0], c.app("contains", (x.args[1], k), BOOL), c.app("contains", (x.args[2], k), BOOL))
        return None

    def _simp_iter_empty(self, c, name, args, ty):
        (x,) = args
        n = self._name(x)
        if n in ("enumerate", "reversed", "dict.keys", "dict.values", "dict.items", "iter:seq"):
            return self.is_empty(None, x.args[1], c)
        if n == "zip":
            return c.or_(*[self._emp(c, a) for a in x.args[1:]])
        return None

    def _emp(self, c, t):
        r = self.is_empty(None, t, c)
        return r if r is not None else c.app("iter.empty", (t,), BOOL)

    # ================================================================================================================ basic values
    def const_val(self, ex, v) -> Term:
        c = ex.ctx
        if isinstance(v, tuple):
            return c.tup([self.const_val(ex, x) for x in v])
        return c.const(v)

    def coerce_bot(self, ex, t: Term, ty):
        c = ex.ctx
        if t.ty == ty:
            return t
        if t.op == "app" and t.args[0] in ("list.empty", "dict.empty", "set.empty") and t.ty[0] == ty[0]:
            return c.app(t.args[0], (), ty)
        if t.op == "ite":
            a, b = self.coerce_bot(ex, t.args[1], ty), self.coerce_bot(ex, t.args[2], ty)
            if a is not None and b is not None:
                return c.ite(t.args[0], a, b)
        # a container whose element type is still unknown has never held an element: whatever the term, its value is the empty container
        if t.ty[0] == ty[0] and t.ty[0] in ("list", "dict", "set") and all(x == BOT for x in t.ty[1:]):
            return c.app(t.ty[0] + ".empty", (), ty)
        return None

    def length(self, c, t: Term) -> Term:
        return c.app("len", (t,), INT)

    def is_empty(self, ex, t: Term, c=None):
        c = c or (ex.ctx if ex is not None else None)
        if c is None:
            return None
        k = t.ty[0]
        if k in _SIZED:
            return c.eq(self.length(c, t), c.const(0))
        if k == "ftuple":
            return c.TRUE if len(t.ty) == 1 else c.FALSE
        if k == "iter":
            return c.app("iter.empty", (t,), BOOL)
        return None

    def truthy(self, ex, st, v: Val) -> Term:
        c = ex.ctx
        t = ex.value(st, v)
        k = t.ty[0]
        if k == "bool":
            return t
        if k == "int":
            return c.not_(c.eq(t, c.const(0)))
        if k == "none":
            return c.FALSE
        if k in _SIZED:
            return c.not_(c.eq(self.length(c, t), c.const(0)))
        if k == "ftuple":
            return c.TRUE if len(t.ty) > 1 else c.FALSE
        if k == "float":
            return ex.total("float.truthy", (t,), BOOL)
        if k == "func":
            return c.TRUE
        if k in ("opaque", "exc"):
            return ex.world_op(st, "truthy", (ex.opaque_arg(st, v),), BOOL)
        ex.unknown(f"truth value of {ty_str(t.ty)}")

    def as_int(self, c, t: Term) -> Term:
        return c.b2i(t) if t.ty == BOOL else t

    # ================================================================================================================ operators
    def unaryop(self, ex, st, op, v: Val) -> Val:
        c = ex.ctx
        t = ex.value(st, v)
        k = t.ty[0]
        nm = type(op).__name__
        if k in ("opaque", "exc", "func"):
            return Val(ex.world_op(st, "unary:" + nm, (ex.opaque_arg(st, v),)))
        if k in ("int", "bool"):
            i = self.as_int(c, t)
            if isinstance(op, ast.USub):
                return Val(c.neg(i))
            if isinstance(op, ast.UAdd):
                return Val(i)
            if isinstance(op, ast.Invert):
                return Val(c.sub(c.neg(i), c.const(1)))
        if k == "float":
            if isinstance(op, ast.USub):
                return Val(ex.total("float.neg", (t,), FLOAT))
            if isinstance(op, ast.UAdd):
                return Val(t)
        ex.unknown(f"unary {nm} on {ty_str(t.ty)}")

    def binop(self, ex, st, op, a: Val, b: Val) -> Val:
        c = ex.ctx
        nm = _OPNAME.get(type(op))
        if nm is None:
            ex.unknown("operator not modelled")
        ta, tb = ex.value(st, a), ex.value(st, b)
        ka, kb = ta.ty[0], tb.ty[0]
        if ka in ("opaque", "exc", "func") or kb in ("opaque", "exc", "func"):
            return Val(ex.world_op(st, "binop:" + nm, (ex.opaque_arg(st, a), ex.opaque_arg(st, b))))
        if ka in ("int", "bool") and kb in ("int", "bool"):
            if ka == "bool" and kb == "bool" and nm in ("BitAnd", "BitOr", "BitXor"):
                if nm == "BitAnd":
                    return Val(c.and_(ta, tb))
                if nm == "BitOr":
                    return Val(c.or_(ta, tb))
                return Val(c.not_(c.eq(ta, tb)))
            x, y = self.as_int(c, ta), self.as_int(c, tb)
            if nm == "Add":
                return Val(c.add(x, y))
            if nm == "Sub":
                return Val(c.sub(x, y))
            if nm == "Mult":
                return Val(c.mul(x, y))
            if nm in ("FloorDiv", "Mod"):
                ex.raise_if(st, c.eq(y, c.const(0)), ex.prim_exc("ZeroDivisionError", "int." + nm))
                return Val(c.fdiv(x, y) if nm == "FloorDiv" else c.mod(x, y))
            if nm == "Pow":
                if y.op == "const" and 0 <= y.args[0] <= 12:
                    r = c.const(1)
                    for _ in range(y.args[0]):
                        r = c.mul(r, x)
                    return Val(r)
                if y.op == "const" and y.args[0] >= 0:
                    return Val(ex.partial(st, "int.pow", (x, y), INT))
                ex.unknown("int ** a non-constant exponent (the result may be a float)")
            if nm == "Div":
                ex.raise_if(st, c.eq(y, c.const(0)), ex.prim_exc("ZeroDivisionError", "int.Div"))
                return Val(ex.partial(st, "int.truediv", (x, y), FLOAT))
            if nm in ("LShift", "RShift"):
                ex.raise_if(st, c.lt(y, c.const(0)), ex.prim_exc("ValueError", "int." + nm))
                return Val(ex.partial(st, "int." + nm, (x, y), INT))
            if nm in ("BitAnd", "BitOr", "BitXor"):
                return Val(ex.total("int." + nm, (x, y), INT))
            ex.unknown(f"int {nm}")
        if ka in _NUM and kb in _NUM:  # a float is involved
            if nm in ("Add", "Sub", "Mult", "Div", "FloorDiv", "Mod"):
                return Val(ex.partial(st, "num." + nm, (ta, tb), FLOAT))
            ex.unknown(f"float {nm}")
        if ka == "str" and kb == "str" and nm == "Add":
            return Val(c.app("str.concat", (ta, tb), STR))
        if nm == "Mult" and ((ka == "str" and kb in ("int", "bool")) or (kb == "str" and ka in ("int", "bool"))):
            s, n = (ta, tb) if ka == "str" else (tb, ta)
            ni = self.as_int(c, n)
            if ni.op == "const" and 0 <= ni.args[0] <= 1024:
                return Val(ex.total("str.repeat", (s, ni), STR))
            return Val(ex.partial(st, "str.repeat", (s, ni), STR))
        if ka == "str" and nm == "Mod" and is_exact(tb.ty):
            return Val(ex.partial(st, "str.mod", (ta, tb), STR))
        if ka == "bytes" and kb == "bytes" and nm == "Add":
            return Val(ex.total("bytes.concat", (ta, tb), BYTES))
        if ka == "list" and kb == "list" and nm == "Add":
            ta, tb = self._unify_elems(ex, ta, tb)
            return Val(self.list_concat(c, ta, tb), True)
        if nm == "Mult" and ((ka == "list" and kb in ("int", "bool")) or (kb == "list" and ka in ("int", "bool"))):
            s, n = (ta, tb) if ka == "list" else (tb, ta)
            ni = self.as_int(c, n)
            if ni.op == "const" and 0 <= ni.args[0] <= 1024:
                return Val(ex.total("list.repeat", (s, ni), s.ty), True)
            return Val(ex.partial(st, "list.repeat", (s, ni), s.ty), True)
        if ka == "tuple" and kb == "tuple" and nm == "Add" and ta.ty == tb.ty:
            return Val(ex.total("tuple.concat", (ta, tb), ta.ty))
        if ka == "ftuple" and kb == "ftuple" and nm == "Add":
            return Val(c.tup([c.proj(i, ta) for i in range(len(ta.ty) - 1)] + [c.proj(i, tb) for i in range(len(tb.ty) - 1)]))
        if ka in ("set", "frozenset") and kb in ("set", "frozenset") and nm in ("BitOr", "BitAnd", "Sub", "BitXor") and ta.ty[1] == tb.ty[1] and is_exact(ta.ty):
            return Val(ex.total("set." + nm, (ta, tb), ta.ty), ka == "set")
        if ka == "dict" and kb == "dict" and nm == "BitOr" and ta.ty == tb.ty and is_exact(ta.ty):
            return Val(ex.total("dict.union", (ta, tb), ta.ty), True)
        ex.unknown(f"{nm} on {ty_str(ta.ty)} and {ty_str(tb.ty)}")

    def list_concat(self, c, a: Term, b: Term) -> Term:
        if a.op == "app" and a.args[0] == "list.empty":
            return b
        if b.op == "app" and b.args[0] == "list.empty":
            return a
        if b.op == "app" and b.args[0] == "list.lit" and len(b.args) == 2:
            return c.app("list.append", (a, b.args[1]), a.ty)
        return c.app("list.concat", (a, b), a.ty)

    def _unify_elems(self, ex, a: Term, b: Term):
        if a.ty == b.ty:
            return a, b
        if _has_bot(a.ty):
            r = self.coerce_bot(ex, a, b.ty)
            if r is not None:
                return r, b
        if _has_bot(b.ty):
            r = self.coerce_bot(ex, b, a.ty)
            if r is not None:
                return a, r
        ex.unknown(f"containers of different element types ({ty_str(a.ty)}, {ty_str(b.ty)})")

    def augassign(self, ex, st, op, cur: Val, rhs: Val, name: str) -> Val:
        c = ex.ctx
        t = cur.t
        k = t.ty[0]
        nm = _OPNAME.get(type(op))
        if k == "ref":
            # an in-place operator on a caller-owned container: whatever its __iadd__ does, through the world
            return Val(ex.world_op(st, "binop:i" + str(nm), (ex.opaque_arg(st, cur), ex.opaque_arg(st, rhs))))
        if k == "list" and nm == "Add":
            if not cur.owned:
                ex.unknown(f"in-place change of a shared local container ({name})")
            r = ex.value(st, rhs)
            lst = self.as_list(ex, st, Val(r))
            a, b = self._unify_elems(ex, t, lst)
            return Val(self.list_concat(c, a, b), True)
        if k in ("set", "dict") and nm in ("BitOr", "BitAnd", "Sub", "BitXor"):
            if not cur.owned:
                ex.unknown(f"in-place change of a shared local container ({name})")
            v = self.binop(ex, st, op, cur, rhs)
            return Val(v.t, True)
        if k == "list" and nm == "Mult":
            if not cur.owned:
                ex.unknown(f"in-place change of a shared local container ({name})")
            v = self.binop(ex, st, op, cur, rhs)
            return Val(v.t, True)
        if k in ("opaque", "exc"):
            return Val(ex.world_op(st, "binop:i" + str(nm), (ex.opaque_arg(st, cur), ex.opaque_arg(st, rhs))))
        return self.binop(ex, st, op, cur, rhs)

    # ---- equality and comparison
    def pyeq(self, ex, st, a: Term, b: Term) -> Term:
        """Python `a == b` for exact builtin values, as a boolean term."""
        c = ex.ctx
        ka, kb = a.ty[0], b.ty[0]
        if ka in ("int", "bool") and kb in ("int", "bool"):
            if ka == kb:
                return c.eq(a, b)
            return c.eq(self.as_int(c, a), self.as_int(c, b))
        if ka in _NUM and kb in _NUM:
            return ex.total("num.eq", (a, b), BOOL)
        if ka == "none" or kb == "none":
            return c.TRUE if ka == kb else c.FALSE
        if ka != kb and {ka, kb} <= {"tuple", "ftuple"}:
            ex.unknown("equality between a fixed-shape and a variable-length tuple")
        if ka != kb and not ({ka, kb} <= {"set", "frozenset"}):
            if ka in _KIND_CLASS and kb in _KIND_CLASS:
                return c.FALSE  # exact builtin values of different kinds are never equal (numbers were handled above)
            ex.unknown(f"equality between {ty_str(a.ty)} and {ty_str(b.ty)}")
        if ka in ("str", "bytes"):
            return c.eq(a, b)
        if ka == "ftuple":
            if len(a.ty) != len(b.ty):
                return c.FALSE
            return c.and_(*[self.pyeq(ex, st, c.proj(i, a), c.proj(i, b)) for i in range(len(a.ty) - 1)])
        if ka in ("list", "tuple"):
            if _has_bot(a.ty) or _has_bot(b.ty):
                other = b if _has_bot(a.ty) else a
                return c.eq(self.length(c, other), c.const(0)) if not (_has_bot(a.ty) and _has_bot(b.ty)) else c.TRUE
            if a.ty == b.ty and float_free(a.ty) and is_exact(a.ty) and not _has_mapping(a.ty):
                return c.eq(a, b)  # same exact element type without floats: equal as Python values iff the same sequence of values
            if a.ty != b.ty and is_exact(a.ty) and is_exact(b.ty) and not _num_related(a.ty[1], b.ty[1]):
                return c.and_(c.eq(self.length(c, a), c.const(0)), c.eq(self.length(c, b), c.const(0)))
            if is_exact(a.ty) and is_exact(b.ty):
                return ex.total("seq.eq", (a, b), BOOL)
        if ka in ("dict", "set", "frozenset", "range") and is_exact(a.ty) and is_exact(b.ty):
            if a is b and float_free(a.ty):
                return c.TRUE
            return ex.total("coll.eq", (a, b), BOOL)
        ex.unknown(f"equality on {ty_str(a.ty)}")

    def compare(self, ex, st, op, left: Val, right: Val, lnode=None, rnode=None) -> Val:
        c = ex.ctx
        nm = _CMPNAME[type(op)]
        a, b = ex.value(st, left), ex.value(st, right)
        ka, kb = a.ty[0], b.ty[0]
        if nm in ("Is", "IsNot"):
            r = self._identity(ex, st, a, b, lnode, rnode)
            return Val(r if nm == "Is" else c.not_(r))
        opq = ("opaque", "exc")
        if nm in ("In", "NotIn"):
            r = self._contains(ex, st, right, left, rnode)
            return Val(r if nm == "In" else c.not_(r))
        if ka == "func" or kb == "func":
            if ka == "func" and kb == "func" and nm in ("Eq", "NotEq"):
                r = c.TRUE if a is b else c.FALSE
                return Val(r if nm == "Eq" else c.not_(r))
            r = self._type_test(ex, st, a, b, lnode, rnode)
            if r is not None and nm in ("Eq", "NotEq"):
                return Val(r if nm == "Eq" else c.not_(r))
            ex.unknown("comparison with a function or class object")
        if ka in opq or kb in opq or not is_exact(a.ty) or not is_exact(b.ty):
            if (not is_exact(a.ty) and ka not in opq) or (not is_exact(b.ty) and kb not in opq):
                if nm in ("Eq", "NotEq") and (kb == "none" or ka == "none") and (ka in ("list", "tuple", "dict", "set", "ftuple") or kb in ("list", "tuple", "dict", "set", "ftuple")):
                    return Val(c.FALSE if nm == "Eq" else c.TRUE)  # a builtin container is never equal to None
                ex.unknown("comparison of a container that holds non-builtin values")
            return Val(ex.world_op(st, "cmp:" + nm, (ex.opaque_arg(st, left, lnode), ex.opaque_arg(st, right, rnode))))
        if nm in ("Eq", "NotEq"):
            r = self.pyeq(ex, st, a, b)
            return Val(r if nm == "Eq" else c.not_(r))
        # ordering
        if ka in ("int", "bool") and kb in ("int", "bool"):
            x, y = self.as_int(c, a), self.as_int(c, b)
            return Val({"Lt": c.lt(x, y), "LtE": c.le(x, y), "Gt": c.lt(y, x), "GtE": c.le(y, x)}[nm])
        if ka in _NUM and kb in _NUM:
            if nm in ("Gt", "GtE"):
                a, b = b, a
            return Val(ex.total("num.lt" if nm in ("Lt", "Gt") else "num.le", (a, b), BOOL))
        if ka == "str" and kb == "str":
            lt = lambda x, y: ex.total("str.lt", (x, y), BOOL)  # noqa: E731
            return Val({"Lt": lambda: lt(a, b), "Gt": lambda: lt(b, a), "LtE": lambda: c.not_(lt(b, a)), "GtE": lambda: c.not_(lt(a, b))}[nm]())
        if a.ty == b.ty and _orderable(a.ty):
            if nm in ("Gt", "GtE"):
                a, b = b, a
            return Val(ex.total("ord.lt" if nm in ("Lt", "Gt") else "ord.le", (a, b), BOOL))
        return Val(ex.partial(st, "cmp." + nm, (a, b), BOOL))

    def _identity(self, ex, st, a: Term, b: Term, lnode, rnode) -> Term:
        c = ex.ctx
        ka, kb = a.ty[0], b.ty[0]
        if ka == "none" and kb == "none":
            return c.TRUE
        if ka == "func" and kb == "func":
            return c.TRUE if a is b else c.FALSE
        if ka == "func" or kb == "func":
            r = self._type_test(ex, st, a, b, lnode, rnode)
            if r is not None:
                return r
            ex.unknown("identity test with a function or class object")
        for x, y, xn in ((a, b, lnode), (b, a, rnode)):
            if y.ty[0] == "none":
                if x.ty[0] in ("opaque", "exc"):
                    p = c.app("is_none", (x,), BOOL)  # an identity test runs no user code
                    if isinstance(xn, ast.Name):
                        ex.S.narrow[p.uid] = (xn.id, x, c.NONE)
                    return p
                return c.FALSE  # an exact builtin value that is not None
        if ka == "bool" and kb == "bool":
            return c.eq(a, b)  # True and False are singletons
        if ka == "ref" and kb == "ref" and a.ty == b.ty:
            return c.eq(a, b)
        if ka in ("opaque",) and kb in ("opaque",):
            return c.app("is", (a, b), BOOL)
        ex.unknown("identity test between values (only None, True/False, classes and references are modelled)")

    def _type_test(self, ex, st, a: Term, b: Term, lnode, rnode):
        """`type(x) is T` / `type(x) == T` where one side is the pure `typeof(x)` of an opaque value and the other a builtin class."""
        c = ex.ctx
        for x, y, xn in ((a, b, lnode), (b, a, rnode)):
            if x.op == "app" and x.args[0] == "typeof" and y.ty == FUNC and y.args[0].startswith("B:"):
                cls = y.args[0][2:]
                ty = {"int": INT, "str": STR, "bool": BOOL, "float": FLOAT, "bytes": BYTES}.get(cls)
                if ty is None:
                    return c.app("isexact:" + cls, (x.args[1],), BOOL)
                p = c.app("isexact:" + cls, (x.args[1],), BOOL)
                if isinstance(xn, ast.Call) and len(xn.args) == 1 and isinstance(xn.args[0], ast.Name):
                    ex.S.narrow[p.uid] = (xn.args[0].id, x.args[1], c.app("cast:" + cls, (x.args[1],), ty))
                return p
        return None

    def _contains(self, ex, st, cont: Val, item: Val, cnode) -> Term:
        c = ex.ctx
        ct, it = ex.value(st, cont), ex.value(st, item)
        k = ct.ty[0]
        if k in ("opaque", "exc", "func") or it.ty[0] in ("opaque", "exc", "func") or not is_exact(ct.ty) or not is_exact(it.ty):
            if k not in ("opaque", "exc", "func") and not is_exact(ct.ty):
                ex.unknown("membership in a container that holds non-builtin values")
            return ex.world_op(st, "contains", (ex.opaque_arg(st, cont, cnode), ex.opaque_arg(st, item)), BOOL)
        if k == "str":
            if it.ty != STR:
                return ex.partial(st, "str.contains.bad", (ct, it), BOOL)
            return ex.total("str.contains", (ct, it), BOOL)
        if k == "ftuple":
            return c.or_(*[self.pyeq(ex, st, c.proj(i, ct), it) for i in range(len(ct.ty) - 1)])
        if k in ("list", "tuple", "range", "bytes"):
            if _has_bot(ct.ty):
                return c.FALSE
            if elem_type(ct.ty) != it.ty or not float_free(it.ty):
                return ex.total("contains.x", (ct, it), BOOL)
            return ex.total("contains", (ct, it), BOOL)
        if k in ("set", "frozenset", "dict"):
            if not hashable(it.ty):
                return ex.partial(st, "contains.unhashable", (ct, it), BOOL)
            if _has_bot(ct.ty):
                return c.FALSE
            if ct.ty[1] != it.ty or not float_free(it.ty):
                return ex.total("contains.x", (ct, it), BOOL)
            return ex.total("contains", (ct, it), BOOL)
        ex.unknown(f"membership in {ty_str(ct.ty)}")

    # ================================================================================================================ subscripts
    def subscript(self, ex, st, base: Val, idx) -> Val:
        c = ex.ctx
        t = ex.value(st, base)
        k = t.ty[0]
        if isinstance(idx, tuple):
            return self._slice(ex, st, base, t, idx)
        it = ex.value(st, idx)
        if k in ("opaque", "exc", "func") or it.ty[0] in ("opaque", "exc", "func"):
            return Val(ex.world_op(st, "getitem", (ex.opaque_arg(st, base), ex.opaque_arg(st, idx))))
        if k == "ftuple" and it.ty in (INT, BOOL):
            n = len(t.ty) - 1
            i = self.as_int(c, it)
            if i.op == "const":
                j = i.args[0]
                if -n <= j < n:
                    return Val(c.proj(j % n, t))
                ex.raise_if(st, c.TRUE, ex.prim_exc("IndexError", "getitem.tuple"))
                return Val(c.NONE)
            if n and all(x == t.ty[1] for x in t.ty[1:]):
                ex.raise_if(st, c.or_(c.lt(i, c.const(-n)), c.le(c.const(n), i)), ex.prim_exc("IndexError", "getitem.tuple"))
                norm = c.ite(c.lt(i, c.const(0)), c.add(i, c.const(n)), i)
                r = c.proj(n - 1, t)
                for j in range(n - 2, -1, -1):
                    r = c.ite(c.eq(norm, c.const(j)), c.proj(j, t), r)
                return Val(r)
            ex.unknown("variable index into a tuple of mixed types")
        if k in _SEQ and it.ty in (INT, BOOL):
            if _has_bot(t.ty):
                ex.raise_if(st, c.TRUE, ex.prim_exc("IndexError", "getitem." + k))
                return Val(c.NONE)
            i = self.as_int(c, it)
            n = self.length(c, t)
            ex.raise_if(st, c.or_(c.lt(i, c.neg(n)), c.le(n, i)), ex.prim_exc("IndexError", "getitem." + k))
            norm = c.ite(c.lt(i, c.const(0)), c.add(i, n), i)
            return Val(c.app("getitem", (t, norm), elem_type(t.ty)))
        if k == "dict":
            if not (is_exact(it.ty) and hashable(it.ty)):
                ex.unknown("dict lookup with an unhashable or non-exact key")
            if _has_bot(t.ty):
                ex.raise_if(st, c.TRUE, ex.prim_exc("KeyError", "getitem.dict", (it,)))
                return Val(c.NONE)
            if it.ty != t.ty[1] or not float_free(it.ty):
                ex.unknown("dict lookup with a key of another type than the dict's keys")
            has = c.app("contains", (t, it), BOOL)
            ex.raise_if(st, c.not_(has), ex.prim_exc("KeyError", "getitem.dict", (it,)))
            return Val(c.app("getitem", (t, it), t.ty[2]))
        ex.unknown(f"subscript of {ty_str(t.ty)} by {ty_str(it.ty)}")

    def _slice(self, ex, st, base: Val, t: Term, idx) -> Val:
        c = ex.ctx
        parts = []
        opaque = t.ty[0] in ("opaque", "exc", "func")
        for p in idx[1:]:
            if p is None:
                parts.append(c.NONE)
                continue
            pt = ex.value(st, p)
            if pt.ty in (INT, BOOL):
                parts.append(self.as_int(c, pt))
            elif pt.ty == NONE:
                parts.append(c.NONE)
            else:
                opaque = True
                parts.append(ex.opaque_arg(st, p))
        if opaque:
            sl = c.app("mkslice", tuple(parts), OPAQUE)
            return Val(ex.world_op(st, "getitem", (ex.opaque_arg(st, base), sl)))
        k = t.ty[0]
        if k not in _SEQ:
            ex.unknown(f"slice of {ty_str(t.ty)}")
        lo, hi, step = parts
        if step.ty == INT:
            if step.op != "const":
                ex.raise_if(st, c.eq(step, c.const(0)), ex.prim_exc("ValueError", "slice.step"))
            elif step.args[0] == 0:
                ex.raise_if(st, c.TRUE, ex.prim_exc("ValueError", "slice.step"))
                return Val(t)
            elif step.args[0] == 1:
                step = c.NONE
        if lo.ty == INT and lo.op == "const" and lo.args[0] == 0 and step is c.NONE:
            lo = c.NONE
        if lo is c.NONE and hi is c.NONE and step is c.NONE:
            return Val(t, k == "list")  # a full slice is a copy: the same value, a new object
        return Val(c.app("slice", (t, lo, hi, step), t.ty), k == "list")

    def store_subscript(self, ex, st, tgt, base: Val, idx, v: Val):
        c = ex.ctx
        t = base.t
        k = t.ty[0]
        name = tgt.value.id if isinstance(tgt.value, ast.Name) else None
        if k in ("opaque", "exc", "ref"):
            it = self._index_term(ex, st, idx)
            ex.world_op(st, "setitem", (ex.opaque_arg(st, base), it, self._stored(ex, st, v)), NONE)
            return
        if isinstance(idx, tuple):
            ex.unknown("slice assignment on a local container")
        cur = st.env.get(name) if name is not None else None
        if cur is None or cur is MAYBE or cur.t is not t or not cur.owned:
            ex.unknown("item assignment on a shared or temporary local container")
        it = ex.value(st, idx)
        vt = self._elem_term(ex, st, v)
        if k == "list":
            if it.ty not in (INT, BOOL) or _has_bot(t.ty):
                ex.unknown("list item assignment with a non-integer index or on an empty list")
            if vt.ty != t.ty[1]:
                ex.unknown("list item assignment changes the element type")
            i = self.as_int(c, it)
            n = self.length(c, t)
            ex.raise_if(st, c.or_(c.lt(i, c.neg(n)), c.le(n, i)), ex.prim_exc("IndexError", "setitem.list"))
            norm = c.ite(c.lt(i, c.const(0)), c.add(i, n), i)
            st.env[name] = Val(c.app("list.setitem", (t, norm, vt), t.ty), True)
            return
        if k == "dict":
            st.env[name] = Val(self.dict_set(ex, t, it, vt), True)
            return
        ex.unknown(f"item assignment on {ty_str(t.ty)}")

    def dict_set(self, ex, d: Term, k: Term, v: Term) -> Term:
        c = ex.ctx
        if not (is_exact(k.ty) and hashable(k.ty) and float_free(k.ty)):
            ex.unknown("dict key that is not an exact hashable builtin value without floats")
        ty = d.ty
        if _has_bot(ty):
            ty = DICT(k.ty, v.ty)
            d2 = self.coerce_bot(ex, d, ty)
            if d2 is None:
                ex.unknown("dict of unknown element type")
            d = d2
        if ty[1] != k.ty or ty[2] != v.ty:
            ex.unknown("dict with keys or values of more than one type")
        return c.app("dict.set", (d, k, v), ty)

    def _index_term(self, ex, st, idx) -> Term:
        c = ex.ctx
        if isinstance(idx, tuple):
            parts = [c.NONE if p is None else self._plain_term(ex, st, p) for p in idx[1:]]
            return c.app("mkslice", tuple(parts), OPAQUE)
        return self._plain_term(ex, st, idx)

    def _plain_term(self, ex, st, v: Val) -> Term:
        """An exact immutable value as itself; anything else as an operand of opaque code."""
        return v.t if (is_exact(v.t.ty) and is_immutable(v.t.ty)) else ex.opaque_arg(st, v)

    def _stored(self, ex, st, v: Val) -> Term:
        return self._plain_term(ex, st, v)

    def _elem_term(self, ex, st, v: Val) -> Term:
        """A value stored INTO a local container: references and opaque values stay as they are; a local mutable container nested in another is not modelled."""
        t = v.t
        if t.ty[0] == "func":
            return ex.func_value(t)
        if t.ty[0] == "exc":
            return ex.ctx.app("exc.val", (t,), OPAQUE)
        return t

    def del_subscript(self, ex, st, tgt, base: Val, idx):
        t = base.t
        k = t.ty[0]
        if k in ("opaque", "exc", "ref"):
            ex.world_op(st, "delitem", (ex.opaque_arg(st, base), self._index_term(ex, st, idx)), NONE)
            return
        name = tgt.value.id if isinstance(tgt.value, ast.Name) else None
        cur = st.env.get(name) if name is not None else None
        if cur is None or cur is MAYBE or cur.t is not t or not cur.owned or isinstance(idx, tuple):
            ex.unknown("del of an item of a shared or temporary local container")
        it = ex.value(st, idx)
        c = ex.ctx
        if k == "dict" and not _has_bot(t.ty) and it.ty == t.ty[1]:
            has = c.app("contains", (t, it), BOOL)
            ex.raise_if(st, c.not_(has), ex.prim_exc("KeyError", "delitem.dict", (it,)))
            st.env[name] = Val(ex.total("dict.del", (t, it), t.ty), True)
            return
        ex.unknown(f"del of an item of {ty_str(t.ty)}")

    def unpack(self, ex, st, v: Val, n: int) -> list:
        c = ex.ctx
        t = ex.value(st, v)
        k = t.ty[0]
        if k == "ftuple":
            if len(t.ty) - 1 != n:
                ex.raise_if(st, c.TRUE, ex.prim_exc("ValueError", "unpack"))
                return [Val(c.NONE)] * n
            return [Val(c.proj(i, t)) for i in range(n)]
        if k in ("list", "tuple", "str"):
            if _has_bot(t.ty):
                if n == 0:
                    return []
                ex.raise_if(st, c.TRUE, ex.prim_exc("ValueError", "unpack"))
                return [Val(c.NONE)] * n
            ex.raise_if(st, c.not_(c.eq(self.length(c, t), c.const(n))), ex.prim_exc("ValueError", "unpack"))
            return [Val(c.app("getitem", (t, c.const(i)), elem_type(t.ty))) for i in range(n)]
        if k in ("opaque", "exc"):
            r = ex.world_op(st, f"unpack:{n}", (ex.opaque_arg(st, v),), FTUPLE(*([OPAQUE] * n)))
            return [Val(c.proj(i, r)) for i in range(n)]
        ex.unknown(f"unpacking of {ty_str(t.ty)}")

    # ================================================================================================================ displays
    def build_seq(self, ex, st, kind: str, elts) -> Val:
        c = ex.ctx
        if any(isinstance(e, ast.Starred) for e in elts):
            ex.unknown("starred element in a display")
        terms = [self._elem_term(ex, st, ex.ev(e, st)) for e in elts]
        if kind == "tuple":
            return Val(c.tup(terms))
        if kind == "list":
            if not terms:
                return Val(c.app("list.empty", (), LIST(BOT)), True)
            if any(t.ty != terms[0].ty for t in terms):
                ex.unknown("list display with elements of more than one type")
            return Val(c.app("list.lit", tuple(terms), LIST(terms[0].ty)), True)
        if any(t.ty != terms[0].ty for t in terms) or not (is_exact(terms[0].ty) and hashable(terms[0].ty)):
            ex.unknown("set display with elements that are not one exact hashable builtin type")
        return Val(c.app("set.lit", tuple(terms), SET(terms[0].ty)), True)

    def build_dict(self, ex, st, node) -> Val:
        c = ex.ctx
        if not node.keys:
            return Val(c.app("dict.empty", (), DICT(BOT, BOT)), True)
        pairs = []
        for k, v in zip(node.keys, node.values):
            if k is None:
                ex.unknown("** in a dict display")
            kt = ex.value(st, ex.ev(k, st))
            vt = self._elem_term(ex, st, ex.ev(v, st))
            pairs += [kt, vt]
        kty, vty = pairs[0].ty, pairs[1].ty
        if any(p.ty != kty for p in pairs[0::2]) or any(p.ty != vty for p in pairs[1::2]):
            ex.unknown("dict display with keys or values of more than one type")
        if not (is_exact(kty) and hashable(kty) and float_free(kty)):
            ex.unknown("dict display with keys that are not exact hashable builtin values without floats")
        return Val(c.app("dict.lit", tuple(pairs), DICT(kty, vty)), True)

    def str_of(self, ex, st, t: Term) -> Term:
        c = ex.ctx
        k = t.ty[0]
        if k == "str":
            return t
        if k == "bool":
            return c.ite(t, c.const("True"), c.const("False"))
        if k == "none":
            return c.const("None")
        if k == "float":
            return ex.total("str:float", (t,), STR)
        if k == "int":
            if t.op == "const" and abs(t.args[0]) < 10 ** 18:
                return c.const(str(t.args[0]))
            return ex.partial(st, "str:int", (t,), STR)  # ValueError above sys.get_int_max_str_digits()
        return ex.partial(st, "str:any", (t,), STR)

    def repr_of(self, ex, st, t: Term) -> Term:
        k = t.ty[0]
        if k in ("int", "bool", "none", "float"):
            return self.str_of(ex, st, t)
        if k == "str":
            return ex.total("repr:str", (t,), STR)
        return ex.partial(st, "repr:any", (t,), STR)

    def fstring(self, ex, st, node) -> Val:
        c = ex.ctx
        parts = []
        for p in node.values:
            if isinstance(p, ast.Constant):
                parts.append(c.const(p.value))
                continue
            v = ex.ev(p.value, st, retain=False)
            spec = ""
            if p.format_spec is not None:
                if not all(isinstance(x, ast.Constant) for x in p.format_spec.values):
                    ex.unknown("f-string with a computed format specification")
                spec = "".join(x.value for x in p.format_spec.values)
            conv = {-1: "", 115: "s", 114: "r", 97: "a"}[p.conversion]
            t = ex.value(st, v)
            if not is_exact(t.ty):
                if t.ty[0] not in ("opaque", "exc", "func"):
                    ex.unknown("formatting a container that holds non-builtin values")
                parts.append(ex.world_op(st, f"format:{conv}:{spec}", (ex.opaque_arg(st, v, p.value),), STR))
                continue
            if conv == "r":
                t = self.repr_of(ex, st, t)
            elif conv == "a":
                t = ex.partial(st, "ascii:any", (t,), STR)
            elif conv == "s":
                t = self.str_of(ex, st, t)
            if spec == "":
                parts.append(self.str_of(ex, st, t))
            else:
                parts.append(ex.partial(st, f"format:{spec}", (t,), STR))
        return Val(c.app("str.concat", tuple(parts), STR) if parts else c.const(""))

    def attribute(self, ex, st, obj: Val, attr: str, node) -> Val:
        k = obj.t.ty[0]
        if k in ("opaque", "exc"):
            return ex.get_attr(st, obj, attr, node)
        if k == "func":
            return ex.get_attr(st, Val(ex.func_value(obj.t)), attr, node)
        ex.unknown(f"attribute {attr} of a builtin {ty_str(_deref_ty(obj.t.ty))} value")

    # ================================================================================================================ lists, comprehensions
    def as_list(self, ex, st, v: Val) -> Term:
        """An exact builtin iterable as the list of its elements in iteration order."""
        c = ex.ctx
        t = ex.value(st, v)
        k = t.ty[0]
        if k == "list":
            return t
        if k == "tuple":
            return c.app("list:tuple", (t,), LIST(t.ty[1]))
        if k == "ftuple":
            if len(t.ty) == 1:
                return c.app("list.empty", (), LIST(BOT))
            if all(x == t.ty[1] for x in t.ty[1:]):
                return c.app("list.lit", tuple(c.proj(i, t) for i in range(len(t.ty) - 1)), LIST(t.ty[1]))
            ex.unknown("a tuple of mixed types used as a sequence")
        et = elem_type(t.ty)
        if et is None or k in ("opaque", "ref"):
            ex.unknown(f"{ty_str(t.ty)} used as a builtin sequence")
        return c.app("list:" + k, (t,), LIST(et))

    def list_append(self, ex, lst: Term, x: Term) -> Term:
        c = ex.ctx
        ty = lst.ty
        if _has_bot(ty):
            ty = LIST(x.ty)
            lst = self.coerce_bot(ex, lst, ty)
            if lst is None:
                ex.unknown("list of unknown element type")
        if ty[1] != x.ty:
            ex.unknown(f"list with elements of more than one type ({ty_str(ty[1])}, {ty_str(x.ty)})")
        return c.app("list.append", (lst, x), ty)

    def comprehension(self, ex, st, node, kind: str) -> Val:
        c = ex.ctx
        for n in ast.walk(node):
            if isinstance(n, ast.NamedExpr):
                ex.unknown("assignment expression in a comprehension")
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                ex.unknown("yield/await in a comprehension")
        acc = ex.hidden_name("acc")
        empty = {"list": ("list.empty", LIST(BOT)), "set": ("set.empty", SET(BOT)), "dict": ("dict.empty", DICT(BOT, BOT))}[kind]
        st.env[acc] = Val(c.app(empty[0], (), empty[1]), True)

        def inner(s):
            cur = s.env[acc].t
            if kind == "dict":
                kt = ex.value(s, ex.ev(node.key, s))
                vt = self._elem_term(ex, s, ex.ev(node.value, s))
                s.env[acc] = Val(self.dict_set(ex, cur, kt, vt), True)
            elif kind == "list":
                s.env[acc] = Val(self.list_append(ex, cur, self._elem_term(ex, s, ex.ev(node.elt, s))), True)
            else:
                s.env[acc] = Val(self.set_add(ex, cur, ex.value(s, ex.ev(node.elt, s))), True)
            return s

        ex.comp_loops(st, node.generators, inner, {acc})
        if ex.dead(st):
            return Val(c.NONE)
        res = st.env.pop(acc)
        return Val(res.t, True)

    def set_add(self, ex, s: Term, x: Term) -> Term:
        c = ex.ctx
        if not (is_exact(x.ty) and hashable(x.ty) and float_free(x.ty)):
            ex.unknown("set element that is not an exact hashable builtin value without floats")
        ty = s.ty
        if _has_bot(ty):
            ty = SET(x.ty)
            s = self.coerce_bot(ex, s, ty)
        if ty[1] != x.ty:
            ex.unknown("set with elements of more than one type")
        return c.app("set.add", (s, x), ty)

    def fold_loop(self, ex, st, itval: Val, init: Term, step, iter_node=None) -> Term:
        """acc = init; for e in itval: acc = step(state, acc, e)  -> the final acc. `step` must not raise control flow."""
        acc, el = ex.hidden_name("acc"), ex.hidden_name("el")
        st.env[acc] = Val(init)

        def bind(s, ev):
            s.env[el] = ev

        def body(states):
            for s in states:
                s.env[acc] = Val(step(s, s.env[acc].t, s.env[el]))
            return states

        res = ex.run_loop(st, itval, bind, body, {acc}, {el}, None, iter_node=iter_node)
        if len(res) != 1:
            if not res:
                st.pc = ex.ctx.FALSE
                return init
            ex.unknown("a reduction ends in states that cannot be merged")
        r = res[0]
        out = r.env.pop(acc).t
        r.env.pop(el, None)
        st.adopt(r)
        return out

    # ================================================================================================================ calls
    def call(self, ex, st, node) -> Val:
        c = ex.ctx
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            ex.unknown("call with *args or **kwargs")
        f = node.func
        if isinstance(f, ast.Attribute):
            dotted = self._module_path(ex, f)
            if dotted is not None:
                return self.opaque_call(ex, st, Val(c.app("G:" + dotted, (), OPAQUE)), node)
            recv = ex.ev(f.value, st, retain=False)
            k = ex.value(st, recv).ty[0]
            if k in ("opaque", "exc", "func"):
                callee = ex.get_attr(st, recv if k != "func" else Val(ex.func_value(recv.t)), f.attr, f.value)
                return self.opaque_call(ex, st, callee, node)
            return self.method(ex, st, node, recv, f.attr)
        if isinstance(f, ast.Name):
            fv = ex.load_name(f.id, st, retain=False)
            if fv.t.ty == FUNC:
                nm = fv.t.args[0]
                if nm.startswith("B:"):
                    return self.builtin(ex, st, node, nm[2:])
                name = nm[2:]
                if name in ex.call_stack:
                    if name == ex.target and ex.call_stack[0] == name:
                        # direct recursion of the function under proof: by induction on the call depth, a recursive call on equal arguments in an equal world behaves equally
                        ex.note("recursive calls of the target are compared by induction")
                        return self.opaque_call(ex, st, Val(c.app("rec:" + name, (), OPAQUE)), node)
                    ex.unknown(f"recursion through {name}")
                return self._inline_or_opaque(ex, st, node, name)
            return self.opaque_call(ex, st, fv, node)
        callee = ex.ev(f, st)
        return self.opaque_call(ex, st, callee, node)

    def _module_path(self, ex, f):
        """'pkg.mod.fn' when the callee is an attribute chain rooted at an imported module name (not a local, not touched by the change)."""
        parts = []
        n = f
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if not isinstance(n, ast.Name) or n.id in ex.scopes[-1]["locals"] or n.id not in ex.mod.imports or n.id in ex.tainted:
            return None
        if any(p in ex.tainted for p in parts):
            ex.unknown(f"call of {'.'.join(reversed(parts))}, which names code this change touches")
        return ex.mod.imports[n.id] + "." + ".".join(reversed(parts))

    def _inline_or_opaque(self, ex, st, node, name) -> Val:
        fdef = ex.mod.funcs[name]
        snap = ex.snapshot(st)
        try:
            argv = [ex.ev(a, st) if not isinstance(a, ast.Name) else ex.load_name(a.id, st, retain=False, for_update=True) for a in node.args]
            kwv = [(k.arg, ex.ev(k.value, st) if not isinstance(k.value, ast.Name) else ex.load_name(k.value.id, st, retain=False, for_update=True)) for k in node.keywords]
            return ex.inline(st, name, fdef, argv, kwv, list(node.args) + [k.value for k in node.keywords])
        except Unknown as e:
            if name in ex.tainted:
                raise Unknown(f"the changed helper {name} cannot be inlined: {e}") from None
            ex.restore(st, snap)
            return self.opaque_call(ex, st, Val(ex.ctx.app("G:" + name, (), OPAQUE)), node)

    def opaque_call(self, ex, st, callee: Val, node, noescape: bool = False) -> Val:
        ct = callee.t if callee.t.ty == OPAQUE else ex.opaque_arg(st, callee)
        args = []
        for a in node.args:
            v = ex.ev(a, st, retain=not noescape)
            args.append(self._pass(ex, st, v, a, noescape))
        kws = []
        for k in node.keywords:
            v = ex.ev(k.value, st, retain=not noescape)
            args.append(self._pass(ex, st, v, k.value, noescape))
            kws.append(k.arg)
        name = f"call:{len(node.args)}:" + ",".join(kws)
        return Val(ex.world_op(st, name, (ct, *args)))

    def _pass(self, ex, st, v: Val, node, noescape: bool) -> Term:
        if noescape and v.t.ty[0] not in ("func", "exc"):
            return v.t  # the callee neither keeps nor mutates it
        return ex.opaque_arg(st, v, node)

    def _args(self, ex, st, node, retain=False):
        return [ex.ev(a, st, retain=retain) for a in node.args]

    # ---- builtin functions
    def builtin(self, ex, st, node, name: str) -> Val:
        c = ex.ctx
        if name in _DYNAMIC:
            ex.unknown(f"call of the builtin {name}")
        h = getattr(self, "b_" + name, None)
        if h is not None:
            snap = ex.snapshot(st)
            r = h(ex, st, node)
            if r is not None:
                return r
            ex.restore(st, snap)
        return self.opaque_call(ex, st, Val(c.app("G:builtins." + name, (), OPAQUE)), node, noescape=name in _NOESCAPE)

    @staticmethod
    def _plain(node, n_min, n_max=None, kws=()):
        n_max = n_min if n_max is None else n_max
        return n_min <= len(node.args) <= n_max and all(k.arg in kws for k in node.keywords)

    def _exact_arg(self, ex, st, node_arg):
        """Evaluate one argument; return its exact value term, or None when it is not an exact builtin value."""
        v = ex.ev(node_arg, st, retain=False)
        t = ex.value(st, v)
        return (v, t) if is_exact(t.ty) or _structural(t.ty) else (v, None)

    def b_len(self, ex, st, node):
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or t.ty[0] not in _SIZED + ("ftuple",):
            return None
        if t.ty == RANGE:
            # len(range(n)) raises OverflowError when the count exceeds sys.maxsize.
            return Val(ex.partial(st, "len:range", (t,), INT))
        return Val(self.length(ex.ctx, t))

    def b_bool(self, ex, st, node):
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(ex.ctx.FALSE)
        return Val(ex.truthy_of(node.args[0], st))

    def b_str(self, ex, st, node):
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(ex.ctx.const(""))
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or not is_exact(t.ty):
            return None
        return Val(self.str_of(ex, st, t))

    def b_repr(self, ex, st, node):
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or not is_exact(t.ty):
            return None
        return Val(self.repr_of(ex, st, t))

    def b_int(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(c.const(0))
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None:
            return None
        k = t.ty[0]
        if k == "int":
            return Val(t)
        if k == "bool":
            return Val(c.b2i(t))
        if k == "str":
            ex.raise_if(st, c.app("X:int:str", (t,), BOOL), ex.prim_exc("ValueError", "int:str", (t,)))
            return Val(c.app("int:str", (t,), INT))
        if k == "float":
            return Val(ex.partial(st, "int:float", (t,), INT))
        return None

    def b_float(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None:
            return None
        k = t.ty[0]
        if k == "float":
            return Val(t)
        if k in ("int", "bool"):
            i = self.as_int(c, t)
            ex.raise_if(st, c.app("X:float:int", (i,), BOOL), ex.prim_exc("OverflowError", "float:int", (i,)))
            return Val(c.app("float:int", (i,), FLOAT))
        if k == "str":
            ex.raise_if(st, c.app("X:float:str", (t,), BOOL), ex.prim_exc("ValueError", "float:str", (t,)))
            return Val(c.app("float:str", (t,), FLOAT))
        return None

    def b_abs(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None:
            return None
        if t.ty in (INT, BOOL):
            i = self.as_int(c, t)
            return Val(c.ite(c.lt(i, c.const(0)), c.neg(i), i))
        if t.ty == FLOAT:
            return Val(ex.total("float.abs", (t,), FLOAT))
        return None

    def _minmax(self, ex, st, node, is_max: bool):
        c = ex.ctx
        nm = "max" if is_max else "min"
        if any(k.arg not in ("default",) for k in node.keywords) or not node.args:
            return None
        if len(node.args) >= 2:
            if node.keywords:
                return None
            ts = []
            for a in node.args:
                v, t = self._exact_arg(ex, st, a)
                if t is None:
                    return None
                ts.append(t)
            ty = ts[0].ty
            if any(t.ty != ty for t in ts):
                return None
            if ty == INT:
                r = ts[0]
                for t in ts[1:]:
                    r = c.ite(c.lt(r, t), t, r) if is_max else c.ite(c.lt(t, r), t, r)
                return Val(r)
            if ty == BOOL:
                return Val(c.or_(*ts) if is_max else c.and_(*ts))
            if ty == STR:
                r = ts[0]
                for t in ts[1:]:
                    r = c.ite(ex.total("str.lt", (r, t), BOOL), t, r) if is_max else c.ite(ex.total("str.lt", (t, r), BOOL), t, r)
                return Val(r)
            if ty == FLOAT:
                return Val(ex.total(nm + ":float", tuple(ts), FLOAT))
            return None
        lst = self._eager_list(ex, st, node.args[0])
        if lst is None:
            return None
        dflt_val = ex.ev(node.keywords[0].value, st) if node.keywords else None
        if _has_bot(lst.ty):  # statically empty
            if dflt_val is not None:
                return dflt_val
            ex.raise_if(st, c.TRUE, ex.prim_exc("ValueError", nm + ".empty"))
            return Val(c.NONE)
        if not (is_exact(lst.ty) and _orderable(lst.ty[1])):
            return None
        emp = c.eq(self.length(c, lst), c.const(0))
        if dflt_val is not None:
            return ex.cond_val(st, emp, lambda s: dflt_val, lambda s: Val(ex.total(nm + ":seq", (lst,), lst.ty[1])))
        ex.raise_if(st, emp, ex.prim_exc("ValueError", nm + ".empty"))
        return Val(ex.total(nm + ":seq", (lst,), lst.ty[1]))

    def b_max(self, ex, st, node):
        return self._minmax(ex, st, node, True)

    def b_min(self, ex, st, node):
        return self._minmax(ex, st, node, False)

    def _eager_list(self, ex, st, arg):
        """The list of elements an eager, order-preserving consumer would see: a generator expression is run as a list comprehension; None when the argument is not an exact
        builtin iterable."""
        if isinstance(arg, ast.GeneratorExp):
            lc = ast.ListComp(elt=arg.elt, generators=arg.generators)
            v = self.comprehension(ex, st, lc, "list")
            return v.t
        v = ex.ev(arg, st, retain=False)
        t = ex.value(st, v)
        if t.ty[0] in ("opaque", "exc", "func", "ref") or elem_type(t.ty) is None:
            return None
        return self.as_list(ex, st, Val(t))

    def b_sum(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1, 2):
            return None
        arg = node.args[0]
        start = c.const(0)
        if isinstance(arg, ast.GeneratorExp):
            if len(node.args) == 2:
                return None
            acc = ex.hidden_name("sum")
            snap = ex.snapshot(st)
            st.env[acc] = Val(start)

            def inner(s):
                e = ex.value(s, ex.ev(arg.elt, s, retain=False))
                if e.ty not in (INT, BOOL):
                    raise _Decline()
                s.env[acc] = Val(c.add(s.env[acc].t, self.as_int(c, e)))
                return s

            try:
                ex.comp_loops(st, arg.generators, inner, {acc})
            except _Decline:
                ex.restore(st, snap)
                ex.unknown("sum over elements that are not exact int/bool")
            if ex.dead(st):
                return Val(c.NONE)
            return Val(st.env.pop(acc).t)
        v = ex.ev(arg, st, retain=False)
        t = ex.value(st, v)
        if len(node.args) == 2:
            sv = ex.value(st, ex.ev(node.args[1], st, retain=False))
            # bool start preserves bool on an empty iterable (sum([], True) is True, not 1).
            if sv.ty != INT:
                return None
            start = sv
        et = elem_type(t.ty) if t.ty[0] not in ("opaque", "exc", "func") else None
        if et == BOT:
            return Val(start)
        if et in (INT, BOOL):
            return Val(self.fold_loop(ex, st, Val(t), start, lambda s, a, e: c.add(a, self.as_int(c, e.t))))
        # 1-arg sum(list[float]) returns int 0 when empty and float otherwise: leave to exact opaque builtins.sum.
        return None

    def _anyall(self, ex, st, node, is_any: bool):
        c = ex.ctx
        if not self._plain(node, 1):
            return None
        arg = node.args[0]
        flag = ex.hidden_name("any" if is_any else "all")
        st.env[flag] = Val(c.FALSE if is_any else c.TRUE)

        def hit(s, tv):
            """tv: this element decides the result (truthy for any, falsy for all)."""
            a, b = ex.split(s, tv)
            if not ex.dead(a):
                a.env[flag] = Val(c.TRUE if is_any else c.FALSE)
                ex.h.brk(a)
            return b

        if isinstance(arg, ast.GeneratorExp):
            if len(arg.generators) != 1:
                st.env.pop(flag)
                return None

            def inner(s):
                tv = ex.truthy_of(arg.elt, s)
                r = hit(s, tv if is_any else c.not_(tv))
                return None if ex.dead(r) else r

            ex.comp_loops(st, arg.generators, inner, {flag})
        else:
            v = ex.ev(arg, st, retain=False)
            t = ex.value(st, v)
            if t.ty[0] in ("opaque", "exc", "func", "ref") or elem_type(t.ty) is None:
                st.env.pop(flag)
                return None
            el = ex.hidden_name("el")

            def bind(s, ev):
                s.env[el] = ev

            def body(states):
                out = []
                for s in states:
                    tv = self.truthy(ex, s, s.env[el])
                    r = hit(s, tv if is_any else c.not_(tv))
                    if not ex.dead(r):
                        out.append(r)
                return out

            res = ex.run_loop(st, Val(t), bind, body, {flag}, {el}, None)
            if len(res) != 1:
                if not res:
                    st.pc = c.FALSE
                    return Val(c.FALSE)
                ex.unknown("any/all ends in states that cannot be merged")
            r = res[0]
            r.env.pop(el, None)
            st.adopt(r)
        if ex.dead(st):
            return Val(c.FALSE)
        return Val(st.env.pop(flag).t)

    def b_any(self, ex, st, node):
        return self._anyall(ex, st, node, True)

    def b_all(self, ex, st, node):
        return self._anyall(ex, st, node, False)

    def b_sorted(self, ex, st, node):
        if len(node.args) != 1 or any(k.arg != "reverse" for k in node.keywords):
            return None
        rev = False
        if node.keywords:
            kv = node.keywords[0].value
            if not (isinstance(kv, ast.Constant) and isinstance(kv.value, bool)):
                return None
            rev = kv.value
        lst = self._eager_list(ex, st, node.args[0])
        if lst is None:
            return None
        if _has_bot(lst.ty):
            return Val(lst, True)
        if not (is_exact(lst.ty) and _orderable(lst.ty[1])):
            return None
        return Val(ex.total("sorted.rev" if rev else "sorted", (lst,), lst.ty), True)

    def b_list(self, ex, st, node):
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(ex.ctx.app("list.empty", (), LIST(BOT)), True)
        lst = self._eager_list(ex, st, node.args[0])
        return None if lst is None else Val(lst, True)

    def b_tuple(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(c.tup([]))
        a = node.args[0]
        if not isinstance(a, ast.GeneratorExp):
            v = ex.ev(a, st, retain=False)
            t = ex.value(st, v)
            if t.ty[0] in ("tuple", "ftuple"):
                return Val(t)
            if t.ty[0] in ("opaque", "exc", "func") or elem_type(t.ty) is None:
                return None
            lst = self.as_list(ex, st, Val(t))
        else:
            lst = self._eager_list(ex, st, a)
        if lst is None:
            return None
        if _has_bot(lst.ty):
            return Val(c.tup([]))
        return Val(c.app("tuple:list", (lst,), TUPLE(lst.ty[1])))

    def b_set(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 0, 1):
            return None
        if not node.args:
            return Val(c.app("set.empty", (), SET(BOT)), True)
        lst = self._eager_list(ex, st, node.args[0])
        if lst is None:
            return None
        if _has_bot(lst.ty):
            return Val(c.app("set.empty", (), SET(BOT)), True)
        if not (is_exact(lst.ty) and hashable(lst.ty[1])):
            return None
        return Val(ex.total("set:list", (lst,), SET(lst.ty[1])), True)

    def b_frozenset(self, ex, st, node):
        if not self._plain(node, 1):
            return None
        lst = self._eager_list(ex, st, node.args[0])
        if lst is None or _has_bot(lst.ty) or not (is_exact(lst.ty) and hashable(lst.ty[1])):
            return None
        return Val(ex.total("frozenset:list", (lst,), FROZENSET(lst.ty[1])))

    def b_dict(self, ex, st, node):
        c = ex.ctx
        if not node.args and not node.keywords:
            return Val(c.app("dict.empty", (), DICT(BOT, BOT)), True)
        if self._plain(node, 1):
            v = ex.ev(node.args[0], st, retain=False)
            t = ex.value(st, v)
            if t.ty[0] == "dict":
                return Val(t, True)
        return None

    def b_enumerate(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1, 2, ("start",)):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or elem_type(t.ty) is None or t.ty[0] in ("opaque", "ref"):
            return None
        start = c.const(0)
        extra = node.args[1] if len(node.args) == 2 else (node.keywords[0].value if node.keywords else None)
        if extra is not None:
            sv = ex.value(st, ex.ev(extra, st, retain=False))
            if sv.ty != INT:
                return None
            start = sv
        et = elem_type(t.ty)
        if et == BOT:
            return Val(c.app("list.empty", (), LIST(BOT)))
        self._freeze(ex, st, node.args[0])
        return Val(ex.total("enumerate", (t, start), ITER(FTUPLE(INT, et))))

    def b_zip(self, ex, st, node):
        if node.keywords or len(node.args) < 2:
            return None
        ts = []
        for a in node.args:
            v, t = self._exact_arg(ex, st, a)
            if t is None or elem_type(t.ty) is None or t.ty[0] in ("opaque", "ref") or elem_type(t.ty) == BOT:
                return None
            ts.append(t)
            self._freeze(ex, st, a)
        return Val(ex.total("zip", tuple(ts), ITER(FTUPLE(*[elem_type(t.ty) for t in ts]))))

    def b_reversed(self, ex, st, node):
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or t.ty[0] not in ("list", "tuple", "str", "range") or _has_bot(t.ty):
            return None
        self._freeze(ex, st, node.args[0])
        return Val(ex.total("reversed", (t,), ITER(elem_type(t.ty))))

    def b_range(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1, 3):
            return None
        ts = []
        for a in node.args:
            v, t = self._exact_arg(ex, st, a)
            if t is None or t.ty not in (INT, BOOL):
                return None
            ts.append(self.as_int(c, t))
        if len(ts) == 1:
            lo, hi, step = c.const(0), ts[0], c.const(1)
        elif len(ts) == 2:
            lo, hi, step = ts[0], ts[1], c.const(1)
        else:
            lo, hi, step = ts
            ex.raise_if(st, c.eq(step, c.const(0)), ex.prim_exc("ValueError", "range.step"))
        return Val(c.app("range", (lo, hi, step), RANGE))

    def b_isinstance(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 2):
            return None
        tn = node.args[1]
        elts = tn.elts if isinstance(tn, ast.Tuple) else [tn]
        names = []
        for e in elts:
            if not (isinstance(e, ast.Name) and ex.is_builtin_name(e.id) and isinstance(getattr(__import__("builtins"), e.id, None), type)):
                return None
            names.append(e.id)
        v = ex.ev(node.args[0], st, retain=False)
        t = ex.value(st, v)
        k = t.ty[0]
        if k in _KIND_CLASS:
            cls = _KIND_CLASS[k]
            return Val(c.TRUE if any(issubclass(cls, getattr(__import__("builtins"), n)) for n in names) else c.FALSE)
        if k == "opaque":
            return Val(ex.world_op(st, "isinstance:" + ",".join(sorted(names)), (ex.opaque_arg(st, v, node.args[0]),), BOOL))
        return None

    def b_type(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1):
            ex.unknown("three-argument type()")
        v = ex.ev(node.args[0], st, retain=False)
        t = ex.value(st, v)
        k = t.ty[0]
        if k in _CLASS_NAMES and k != "none":
            return Val(c.app("B:" + _CLASS_NAMES[k], (), FUNC))
        if k == "opaque":
            return Val(c.app("typeof", (t,), OPAQUE))
        ex.unknown(f"type() of {ty_str(t.ty)}")

    def b_divmod(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 2):
            return None
        (va, a), (vb, b) = self._exact_arg(ex, st, node.args[0]), self._exact_arg(ex, st, node.args[1])
        if a is None or b is None or a.ty not in (INT, BOOL) or b.ty not in (INT, BOOL):
            return None
        x, y = self.as_int(c, a), self.as_int(c, b)
        ex.raise_if(st, c.eq(y, c.const(0)), ex.prim_exc("ZeroDivisionError", "divmod"))
        return Val(c.tup([c.fdiv(x, y), c.mod(x, y)]))

    def b_ord(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or t.ty != STR:
            return None
        ex.raise_if(st, c.not_(c.eq(self.length(c, t), c.const(1))), ex.prim_exc("TypeError", "ord"))
        return Val(ex.total("ord", (t,), INT))

    def b_chr(self, ex, st, node):
        c = ex.ctx
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None or t.ty != INT:
            return None
        ex.raise_if(st, c.or_(c.lt(t, c.const(0)), c.lt(c.const(0x10FFFF), t)), ex.prim_exc("ValueError", "chr"))
        return Val(ex.total("chr", (t,), STR))

    def b_round(self, ex, st, node):
        if not self._plain(node, 1):
            return None
        v, t = self._exact_arg(ex, st, node.args[0])
        if t is None:
            return None
        if t.ty == INT:
            return Val(t)
        if t.ty == FLOAT:
            return Val(ex.partial(st, "round:float", (t,), INT))
        return None

    def b_getattr(self, ex, st, node):
        if len(node.args) not in (2, 3) or node.keywords or not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
            ex.unknown("getattr with a computed attribute name")
        attr = node.args[1].value
        if attr in ex.tainted:
            ex.unknown(f"attribute {attr} names code this change touches")
        obj = ex.ev(node.args[0], st)
        if len(node.args) == 2:
            return ex.get_attr(st, obj, attr, node.args[0])
        d = ex.ev(node.args[2], st)
        return Val(ex.world_op(st, "getattr3:" + attr, (ex.opaque_arg(st, obj, node.args[0]), ex.opaque_arg(st, d, node.args[2]))))

    def b_hasattr(self, ex, st, node):
        if len(node.args) != 2 or node.keywords or not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
            ex.unknown("hasattr with a computed attribute name")
        attr = node.args[1].value
        if attr in ex.tainted:
            ex.unknown(f"attribute {attr} names code this change touches")
        obj = ex.ev(node.args[0], st)
        return Val(ex.world_op(st, "hasattr:" + attr, (ex.opaque_arg(st, obj, node.args[0]),), BOOL))

    def b_setattr(self, ex, st, node):
        if len(node.args) != 3 or node.keywords or not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
            ex.unknown("setattr with a computed attribute name")
        obj = ex.ev(node.args[0], st)
        v = ex.ev(node.args[2], st)
        ex.set_attr(st, obj, node.args[1].value, v, node.args[0])
        return Val(ex.ctx.NONE)

    # ---- methods of builtin values
    def method(self, ex, st, node, recv: Val, mname: str) -> Val:
        c = ex.ctx
        is_ref = recv.t.ty[0] == "ref"
        t = ex.value(st, recv)
        k = t.ty[0]
        if node.keywords and not (k == "list" and mname == "sort") and not (k == "str" and mname in ("split", "rsplit", "splitlines", "encode", "format")):
            ex.unknown(f"keyword arguments to {k}.{mname}")
        if k == "str":
            return self._str_method(ex, st, node, t, mname)
        if k == "bytes":
            spec = _BYTES_M.get(mname)
            if spec is None:
                ex.unknown(f"method bytes.{mname} is not in the builtin model")
            exact, pos_args, _ = self._eval_method_args(ex, st, node)
            if exact:
                return Val(ex.partial(st, "bytes." + mname, (t, *pos_args), spec[0]))
            oargs = (t, *(ex.opaque_arg(st, v, a) for a, v in pos_args))
            return Val(ex.world_op(st, "m:bytes." + mname, oargs, OPAQUE))
        if k in ("int", "bool", "float"):
            if mname == "bit_length" and k == "int" and not node.args:
                return Val(ex.total("int.bit_length", (t,), INT))
            if mname == "is_integer" and k == "float" and not node.args:
                return Val(ex.total("float.is_integer", (t,), BOOL))
            ex.unknown(f"method {k}.{mname} is not in the builtin model")
        if k in ("tuple", "ftuple"):
            if mname in ("index", "count") and len(node.args) == 1 and is_exact(t.ty):
                lst = self.as_list(ex, st, Val(t))
                return self._list_query(ex, st, node, lst, mname)
            ex.unknown(f"method tuple.{mname} is not in the builtin model")
        if k == "list":
            return self._list_method(ex, st, node, recv, t, mname, is_ref)
        if k == "dict":
            return self._dict_method(ex, st, node, recv, t, mname, is_ref)
        if k in ("set", "frozenset"):
            return self._set_method(ex, st, node, recv, t, mname, is_ref)
        ex.unknown(f"method {mname} of {ty_str(t.ty)} is not in the builtin model")

    def _exact_args(self, ex, st, node) -> list:
        out = []
        for a in node.args:
            v = ex.ev(a, st, retain=False)
            t = ex.value(st, v)
            if not (is_exact(t.ty) and is_immutable(t.ty)):
                ex.unknown("a builtin method is called with an argument that is not an exact immutable builtin value")
            out.append(t)
        return out

    def _eval_method_args(self, ex, st, node) -> tuple[bool, list, list]:
        """Evaluate positional and keyword arguments once in Python left-to-right order.
        Returns (True, pos_terms, kw_terms) when every argument is an exact immutable builtin value,
        else (False, raw_pos[(node, Val)], raw_kw[(name, node, Val)]) for sound opaque world_op fallback."""
        raw_pos = []
        raw_kw = []
        pos_terms = []
        kw_terms = []
        all_exact = True
        for a in node.args:
            v = ex.ev(a, st, retain=False)
            tv = ex.value(st, v)
            raw_pos.append((a, v))
            if is_exact(tv.ty) and is_immutable(tv.ty):
                pos_terms.append(tv)
            else:
                all_exact = False
        for k in node.keywords:
            v = ex.ev(k.value, st, retain=False)
            tv = ex.value(st, v)
            raw_kw.append((k.arg, k.value, v))
            if is_exact(tv.ty) and is_immutable(tv.ty):
                kw_terms.append((k.arg, tv))
            else:
                all_exact = False
        if all_exact:
            return True, pos_terms, kw_terms
        return False, raw_pos, raw_kw

    def _str_method(self, ex, st, node, t: Term, mname: str) -> Val:
        c = ex.ctx
        if mname == "join":
            return self._str_join(ex, st, node, t)
        spec = _STR_M.get(mname)
        if spec is None:
            ex.unknown(f"method str.{mname} is not in the builtin model")
        exact, args, kw = self._eval_method_args(ex, st, node)
        if not exact:
            name = "m:str." + mname + "".join(":" + ka for ka, _, _ in kw)
            oargs = (t, *(ex.opaque_arg(st, v, a) for a, v in args),
                     *(ex.opaque_arg(st, v, kn) for _, kn, v in kw))
            return Val(ex.world_op(st, name, oargs, OPAQUE))
        name = "str." + mname + "".join(":" + k for k, _ in kw)
        allargs = (t, *args, *[v for _, v in kw])
        total = False
        if not kw:
            if mname in ("startswith", "endswith"):
                total = len(args) == 1 and (args[0].ty == STR or (args[0].ty[0] in ("ftuple", "tuple") and all(x == STR for x in args[0].ty[1:])))
            elif mname in ("find", "rfind", "count", "removeprefix", "removesuffix"):
                total = len(args) == 1 and args[0].ty == STR
            elif mname in ("strip", "lstrip", "rstrip"):
                total = (not args) or (len(args) == 1 and args[0].ty in (STR, NONE))
            elif mname == "replace":
                total = len(args) == 2 and args[0].ty == STR and args[1].ty == STR
            elif mname in ("split", "rsplit", "splitlines"):
                total = not args
            elif spec[1]:
                total = not args
        if total:
            return Val(ex.total(name, allargs, spec[0]), is_mutable_builtin(spec[0]))
        return Val(ex.partial(st, name, allargs, spec[0]), is_mutable_builtin(spec[0]))

    def _str_join(self, ex, st, node, sep: Term) -> Val:
        c = ex.ctx
        if len(node.args) != 1:
            ex.unknown("str.join with other than one argument")
        arg = node.args[0]
        if isinstance(arg, (ast.GeneratorExp, ast.ListComp)) and sep.op == "const" and sep.args[0] == "":
            # ''.join(f(x) for x in xs): every element is evaluated (in order) and the results are concatenated: the fused loop acc = acc + f(x). Concatenation is pure and
            # total, so doing it between element evaluations instead of after them is not observable.
            acc = ex.hidden_name("join")
            snap = ex.snapshot(st)
            st.env[acc] = Val(c.const(""))

            def inner(s2):
                e = ex.value(s2, ex.ev(arg.elt, s2, retain=False))
                if e.ty != STR:
                    raise _Decline()
                s2.env[acc] = Val(c.app("str.concat", (s2.env[acc].t, e), STR))
                return s2

            try:
                ex.comp_loops(st, arg.generators, inner, {acc})
                if ex.dead(st):
                    return Val(c.const(""))
                return Val(st.env.pop(acc).t)
            except _Decline:
                ex.restore(st, snap)
        lst = self._eager_list(ex, st, arg)
        if lst is None:
            ex.unknown("str.join over a value that is not an exact builtin iterable")
        if _has_bot(lst.ty):
            return Val(c.const(""))
        if lst.ty[1] != STR:
            return Val(ex.partial(st, "str.join.bad", (sep, lst), STR))
        if sep.op == "const" and sep.args[0] == "":
            # ''.join(xs) is the left fold of + over xs: the same loop class as an explicit accumulation
            return Val(self.fold_loop(ex, st, Val(lst), c.const(""), lambda s, a, e: c.app("str.concat", (a, e.t), STR)))
        return Val(ex.total("str.join", (sep, lst), STR))

    def _freeze(self, ex, st, arg_node):
        """A lazy view / iterator over a local container was created: the container is treated as shared from here on."""
        if isinstance(arg_node, ast.Name):
            cur = st.env.get(arg_node.id)
            if cur is not None and cur is not MAYBE and cur.owned:
                st.env[arg_node.id] = Val(cur.t, False)

    def _owned_name(self, st, node, t: Term):
        """The local name through which an OWNED container is being mutated, or None."""
        f = node.func.value
        if isinstance(f, ast.Name):
            cur = st.env.get(f.id)
            if cur is not None and cur is not MAYBE and cur.t is t and cur.owned:
                return f.id
        return None

    def _list_query(self, ex, st, node, lst: Term, mname: str) -> Val:
        c = ex.ctx
        (x,) = self._exact_args(ex, st, node)
        if _has_bot(lst.ty):
            if mname == "count":
                return Val(c.const(0))
            ex.raise_if(st, c.TRUE, ex.prim_exc("ValueError", "list.index"))
            return Val(c.const(0))
        if not is_exact(lst.ty):
            ex.unknown("search in a list that holds non-builtin values")
        if mname == "count":
            return Val(ex.total("list.count", (lst, x), INT))
        has = c.app("contains", (lst, x), BOOL) if (lst.ty[1] == x.ty and float_free(x.ty)) else ex.total("contains.x", (lst, x), BOOL)
        ex.raise_if(st, c.not_(has), ex.prim_exc("ValueError", "list.index"))
        return Val(ex.total("list.index", (lst, x), INT))

    def _list_method(self, ex, st, node, recv: Val, t: Term, mname: str, is_ref: bool) -> Val:
        c = ex.ctx
        if mname in ("index", "count") and len(node.args) == 1:
            return self._list_query(ex, st, node, t, mname)
        if mname == "copy" and not node.args:
            return Val(t, True)
        mut = mname in ("append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse")
        if not mut:
            ex.unknown(f"method list.{mname} is not in the builtin model")
        if is_ref:
            return self.opaque_call(ex, st, ex.get_attr(st, recv, mname, node.func.value), node)
        name = self._owned_name(st, node, t)
        if name is None:
            ex.unknown(f"list.{mname} on a shared or temporary local list")
        if mname == "append" and len(node.args) == 1:
            x = self._elem_term(ex, st, ex.ev(node.args[0], st))
            cur = st.env[name].t  # evaluating the argument may have rebound the list (it cannot: owned), re-read for safety
            st.env[name] = Val(self.list_append(ex, cur, x), True)
            return Val(c.NONE)
        if mname == "extend" and len(node.args) == 1:
            lst = self._eager_list(ex, st, node.args[0])
            if lst is None:
                ex.unknown("list.extend with a value that is not an exact builtin iterable")
            a, b = self._unify_elems(ex, st.env[name].t, lst)
            st.env[name] = Val(self.list_concat(c, a, b), True)
            return Val(c.NONE)
        if _has_bot(t.ty):
            if mname in ("clear", "reverse") and not node.args and not node.keywords:
                return Val(c.NONE)
            if mname == "sort" and not node.args:
                for kw in node.keywords:
                    if not (kw.arg == "reverse" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool)):
                        ex.unknown("list.sort with a key or a computed reverse")
                return Val(c.NONE)
            if mname == "pop" and len(node.args) <= 1 and not node.keywords:
                if node.args:
                    (i,) = self._exact_args(ex, st, node)
                    if i.ty not in (INT, BOOL):
                        ex.unknown("list.pop with a non-integer index")
                ex.raise_if(st, c.TRUE, ex.prim_exc("IndexError", "list.pop"))
                return Val(c.NONE)
            ex.unknown(f"list.{mname} on an empty list of unknown element type")
        n = self.length(c, t)
        if mname == "pop" and len(node.args) <= 1:
            if node.args:
                (i,) = self._exact_args(ex, st, node)
                if i.ty not in (INT, BOOL):
                    ex.unknown("list.pop with a non-integer index")
                i = self.as_int(c, i)
            else:
                i = c.const(-1)
            ex.raise_if(st, c.or_(c.lt(i, c.neg(n)), c.le(n, i)), ex.prim_exc("IndexError", "list.pop"))
            norm = c.ite(c.lt(i, c.const(0)), c.add(i, n), i)
            st.env[name] = Val(ex.total("list.popat", (t, norm), t.ty), True)
            return Val(c.app("getitem", (t, norm), t.ty[1]))
        if mname == "insert" and len(node.args) == 2:
            i = ex.value(st, ex.ev(node.args[0], st, retain=False))
            x = self._elem_term(ex, st, ex.ev(node.args[1], st))
            if i.ty not in (INT, BOOL) or x.ty != t.ty[1]:
                ex.unknown("list.insert with a non-integer index or an element of another type")
            ii = self.as_int(c, i)
            if ii.op == "const" and abs(ii.args[0]) <= 10 ** 9:
                st.env[name] = Val(ex.total("list.insert", (t, ii, x), t.ty), True)
            else:
                st.env[name] = Val(ex.partial(st, "list.insert", (t, ii, x), t.ty), True)
            return Val(c.NONE)
        if mname == "remove" and len(node.args) == 1:
            (x,) = self._exact_args(ex, st, node)
            if not is_exact(t.ty) or x.ty != t.ty[1] or not float_free(x.ty):
                ex.unknown("list.remove on a list of another element type")
            ex.raise_if(st, c.not_(c.app("contains", (t, x), BOOL)), ex.prim_exc("ValueError", "list.remove"))
            st.env[name] = Val(ex.total("list.remove", (t, x), t.ty), True)
            return Val(c.NONE)
        if mname == "clear" and not node.args:
            st.env[name] = Val(c.app("list.empty", (), t.ty), True)
            return Val(c.NONE)
        if mname == "reverse" and not node.args:
            st.env[name] = Val(ex.total("list.reversed", (t,), t.ty), True)
            return Val(c.NONE)
        if mname == "sort" and not node.args:
            rev = False
            for kw in node.keywords:
                if kw.arg == "reverse" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
                    rev = kw.value.value
                else:
                    ex.unknown("list.sort with a key or a computed reverse")
            if not (is_exact(t.ty) and _orderable(t.ty[1])):
                ex.unknown("list.sort on elements without a builtin total order")
            st.env[name] = Val(ex.total("sorted.rev" if rev else "sorted", (t,), t.ty), True)
            return Val(c.NONE)
        ex.unknown(f"list.{mname} with these arguments is not in the builtin model")

    def _dict_method(self, ex, st, node, recv: Val, t: Term, mname: str, is_ref: bool) -> Val:
        c = ex.ctx
        if mname in ("keys", "values", "items") and not node.args:
            if _has_bot(t.ty):
                return Val(c.app("list.empty", (), LIST(BOT)))
            ety = {"keys": t.ty[1], "values": t.ty[2], "items": FTUPLE(t.ty[1], t.ty[2])}[mname]
            self._freeze(ex, st, node.func.value)  # a view aliases the dict: no later mutation of it is modelled
            return Val(ex.total("dict." + mname, (t,), ITER(ety)))
        if mname == "get" and len(node.args) in (1, 2):
            kv = ex.value(st, ex.ev(node.args[0], st, retain=False))
            dflt_val = ex.ev(node.args[1], st) if len(node.args) == 2 else Val(c.NONE)
            if not (is_exact(kv.ty) and hashable(kv.ty)):
                ex.unknown("dict.get with an unhashable or non-exact key")
            if _has_bot(t.ty):
                return dflt_val
            if kv.ty != t.ty[1] or not float_free(kv.ty):
                ex.unknown("dict.get with a key of another type than the dict's keys")
            has = c.app("contains", (t, kv), BOOL)
            return ex.cond_val(st, has, lambda s: Val(c.app("getitem", (t, kv), t.ty[2])), lambda s: dflt_val)
        if mname == "copy" and not node.args:
            return Val(t, True)
        mut = mname in ("pop", "setdefault", "update", "clear", "popitem")
        if not mut:
            ex.unknown(f"method dict.{mname} is not in the builtin model")
        if is_ref:
            return self.opaque_call(ex, st, ex.get_attr(st, recv, mname, node.func.value), node)
        name = self._owned_name(st, node, t)
        if name is None:
            ex.unknown(f"dict.{mname} on a shared or temporary local dict")
        if mname == "clear" and not node.args:
            st.env[name] = Val(c.app("dict.empty", (), t.ty), True)
            return Val(c.NONE)
        if mname == "setdefault" and len(node.args) == 2:
            kv = ex.value(st, ex.ev(node.args[0], st, retain=False))
            dv = self._elem_term(ex, st, ex.ev(node.args[1], st))
            if _has_bot(t.ty):
                st.env[name] = Val(self.dict_set(ex, t, kv, dv), True)
                return Val(dv)
            if kv.ty != t.ty[1] or dv.ty != t.ty[2] or not float_free(kv.ty):
                ex.unknown("dict.setdefault changes the dict's key or value type")
            has = c.app("contains", (t, kv), BOOL)
            st.env[name] = Val(c.ite(has, t, c.app("dict.set", (t, kv, dv), t.ty)), True)
            return Val(c.ite(has, c.app("getitem", (t, kv), t.ty[2]), dv))
        if mname == "pop" and len(node.args) == 1 and not _has_bot(t.ty):
            kv = ex.value(st, ex.ev(node.args[0], st, retain=False))
            if kv.ty != t.ty[1] or not float_free(kv.ty):
                ex.unknown("dict.pop with a key of another type than the dict's keys")
            has = c.app("contains", (t, kv), BOOL)
            ex.raise_if(st, c.not_(has), ex.prim_exc("KeyError", "dict.pop", (kv,)))
            st.env[name] = Val(ex.total("dict.del", (t, kv), t.ty), True)
            return Val(c.app("getitem", (t, kv), t.ty[2]))
        if mname == "update" and len(node.args) == 1:
            ov = ex.value(st, ex.ev(node.args[0], st, retain=False))
            if ov.ty[0] != "dict":
                ex.unknown("dict.update with a value that is not a dict")
            if _has_bot(ov.ty):
                return Val(c.NONE)
            if _has_bot(t.ty):
                st.env[name] = Val(ov, True)
                return Val(c.NONE)
            if ov.ty != t.ty:
                ex.unknown("dict.update changes the dict's key or value type")
            st.env[name] = Val(ex.total("dict.union", (t, ov), t.ty), True)
            return Val(c.NONE)
        ex.unknown(f"dict.{mname} with these arguments is not in the builtin model")

    def _set_method(self, ex, st, node, recv: Val, t: Term, mname: str, is_ref: bool) -> Val:
        c = ex.ctx
        if mname in ("union", "intersection", "difference", "symmetric_difference", "issubset", "issuperset", "isdisjoint") and len(node.args) == 1:
            o = ex.value(st, ex.ev(node.args[0], st, retain=False))
            if o.ty[0] not in ("set", "frozenset") or not is_exact(t.ty) or o.ty[1:] != t.ty[1:]:
                ex.unknown(f"set.{mname} with a value that is not a set of the same element type")
            if mname.startswith("is"):
                return Val(ex.total("set." + mname, (t, o), BOOL))
            return Val(ex.total("set." + mname, (t, o), t.ty), t.ty[0] == "set")
        if mname == "copy" and not node.args:
            return Val(t, t.ty[0] == "set")
        if mname not in ("add", "discard", "remove", "update", "clear") or t.ty[0] != "set":
            ex.unknown(f"method set.{mname} is not in the builtin model")
        if is_ref:
            return self.opaque_call(ex, st, ex.get_attr(st, recv, mname, node.func.value), node)
        name = self._owned_name(st, node, t)
        if name is None:
            ex.unknown(f"set.{mname} on a shared or temporary local set")
        if mname == "clear" and not node.args:
            st.env[name] = Val(c.app("set.empty", (), t.ty), True)
            return Val(c.NONE)
        if len(node.args) != 1:
            ex.unknown(f"set.{mname} with these arguments is not in the builtin model")
        if mname == "add":
            x = ex.value(st, ex.ev(node.args[0], st, retain=False))
            st.env[name] = Val(self.set_add(ex, st.env[name].t, x), True)
            return Val(c.NONE)
        if mname == "update":
            lst = self._eager_list(ex, st, node.args[0])
            if lst is None or _has_bot(lst.ty) or _has_bot(t.ty) or lst.ty[1] != t.ty[1] or not is_exact(lst.ty):
                ex.unknown("set.update with a value the builtin model does not cover")
            st.env[name] = Val(ex.total("set.update", (t, lst), t.ty), True)
            return Val(c.NONE)
        x = ex.value(st, ex.ev(node.args[0], st, retain=False))
        if _has_bot(t.ty) or x.ty != t.ty[1] or not float_free(x.ty):
            ex.unknown(f"set.{mname} with an element of another type")
        if mname == "remove":
            ex.raise_if(st, c.not_(c.app("contains", (t, x), BOOL)), ex.prim_exc("KeyError", "set.remove", (x,)))
        st.env[name] = Val(ex.total("set.discard", (t, x), t.ty), True)
        return Val(c.NONE)


class _Decline(Exception):
    pass


def _structural(ty) -> bool:
    """A builtin container whose own structure is exact even though its elements may be references or opaque values."""
    return ty[0] in ("list", "tuple", "ftuple", "dict", "set", "frozenset", "iter")


def _num_related(a, b) -> bool:
    return a[0] in _NUM and b[0] in _NUM


def _contains_num(a, b) -> bool:
    return a[0] in _NUM and b[0] in _NUM


def _has_mapping(ty) -> bool:
    if ty[0] in ("dict", "set", "frozenset"):
        return True
    return any(_has_mapping(x) for x in ty[1:] if isinstance(x, tuple))
