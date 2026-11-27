# SPDX-License-Identifier: Apache-2.0
"""Typed, hash-consed terms for the symbolic equivalence prover (hlith.obligation.symeq).

A term denotes a Python VALUE (never an expression to be evaluated later): evaluation order, exceptions and effects are made explicit by the executor before a term exists. Types are
EXACT builtin types (a subclass instance is not in any of them); everything else is OPAQUE and is only ever touched through world-threaded operations.

Soundness rule for this file: a smart constructor may only rewrite a term into another term that denotes the SAME value for every valuation of the symbols and every interpretation of
the uninterpreted applications. Nothing here knows about Python builtins beyond exact int / bool arithmetic and logic."""

from __future__ import annotations

# ------------------------------------------------------------------------------------------------------------------ types
INT, BOOL, STR, FLOAT, NONE, BYTES = ("int",), ("bool",), ("str",), ("float",), ("none",), ("bytes",)
OPAQUE, WORLD, EXC, RANGE = ("opaque",), ("world",), ("exc",), ("range",)


def LIST(t):
    return ("list", t)


def TUPLE(t):
    """Homogeneous tuple of any length: tuple[T, ...]."""
    return ("tuple", t)


def FTUPLE(*ts):
    """Fixed-shape tuple: tuple[A, B]."""
    return ("ftuple", *ts)


def DICT(k, v):
    return ("dict", k, v)


def SET(t):
    return ("set", t)


def FROZENSET(t):
    return ("frozenset", t)


def ITER(t):
    """A lazy builtin iterable with element type t (enumerate, zip, dict views, reversed, map over a pure function): consumed only by loops and eager consumers."""
    return ("iter", t)


def REF(t):
    """A reference to an EXTERNAL mutable object of exact type t (a typed mutable parameter): its value is read through the world."""
    return ("ref", t)


_SCALARS = frozenset({"int", "bool", "str", "float", "none", "bytes", "range"})


def is_immutable(ty) -> bool:
    k = ty[0]
    if k in _SCALARS:
        return True
    if k in ("tuple", "frozenset"):
        return is_immutable(ty[1])
    if k == "ftuple":
        return all(is_immutable(x) for x in ty[1:])
    return False


def is_mutable_builtin(ty) -> bool:
    return ty[0] in ("list", "dict", "set")


def float_free(ty) -> bool:
    k = ty[0]
    if k == "float":
        return False
    if k in _SCALARS or k in ("opaque", "world", "exc"):
        return k != "opaque"
    return all(float_free(x) for x in ty[1:])


def is_exact(ty) -> bool:
    """Every value of the type is an exact builtin object all the way down (no opaque part, no reference)."""
    k = ty[0]
    if k in _SCALARS:
        return True
    if k in ("opaque", "world", "exc", "ref", "func"):
        return False
    return all(is_exact(x) for x in ty[1:])


def hashable(ty) -> bool:
    return is_immutable(ty)


def ty_str(ty) -> str:
    k = ty[0]
    if len(ty) == 1:
        return k
    if k == "tuple":
        return f"tuple[{ty_str(ty[1])}, ...]"
    if k == "ftuple":
        return "tuple[" + ", ".join(ty_str(x) for x in ty[1:]) + "]"
    return k + "[" + ", ".join(ty_str(x) for x in ty[1:]) + "]"


def elem_type(ty):
    """Element type produced by iterating a value of this type, or None when it is not a builtin iterable."""
    k = ty[0]
    if k in ("list", "tuple", "set", "frozenset", "iter"):
        return ty[1]
    if k == "str":
        return STR
    if k == "bytes":
        return INT
    if k == "range":
        return INT
    if k == "dict":
        return ty[1]
    if k == "ftuple" and len(ty) > 1 and all(x == ty[1] for x in ty[1:]):
        return ty[1]
    return None


# ------------------------------------------------------------------------------------------------------------------ terms
class Term:
    __slots__ = ("op", "args", "ty", "uid", "_syms")

    def __repr__(self):
        return show(self)


class Ctx:
    """One prover session: the term table, the facts (formulas true in the intended interpretation) and the simplifier / fact hooks keyed by application name."""

    def __init__(self):
        self.table: dict = {}
        self.n = 0
        self.facts: list = []
        self.simp: dict = {}  # app-name prefix (before ':') -> fn(ctx, name, args, ty) -> Term | None
        self.fact_hooks: dict = {}  # app-name prefix -> fn(ctx, term) -> None (may call ctx.fact)
        self.fresh_n = 0
        self.TRUE = self.mk("const", (True,), BOOL)
        self.FALSE = self.mk("const", (False,), BOOL)
        self.NONE = self.mk("const", (None,), NONE)

    # ---- raw construction
    def mk(self, op, args, ty) -> Term:
        key = (op, args, ty)
        t = self.table.get(key)
        if t is None:
            t = Term()
            t.op, t.args, t.ty, t.uid, t._syms = op, args, ty, self.n, None
            self.n += 1
            self.table[key] = t
            if self.n > 400_000:
                raise TermLimit("term table limit")
        return t

    def fact(self, f: Term):
        if f is not self.TRUE:
            self.facts.append(f)

    # ---- leaves
    def const(self, v) -> Term:
        if v is None:
            return self.NONE
        if v is True:
            return self.TRUE
        if v is False:
            return self.FALSE
        tv = type(v)
        if tv is int:
            return self.mk("const", (v,), INT)
        if tv is str:
            return self.mk("const", (v,), STR)
        if tv is float:
            return self.mk("const", (v.hex() if v == v else "nan",), FLOAT)
        if tv is bytes:
            return self.mk("const", (v,), BYTES)
        raise TypeError(f"not a constant the term language holds: {tv.__name__}")

    def sym(self, name: str, ty) -> Term:
        return self.mk("sym", (name,), ty)

    def fresh(self, hint: str, ty) -> Term:
        self.fresh_n += 1
        return self.mk("sym", (f"{hint}#{self.fresh_n}",), ty)

    # ---- booleans
    def not_(self, a: Term) -> Term:
        assert a.ty == BOOL, a
        if a is self.TRUE:
            return self.FALSE
        if a is self.FALSE:
            return self.TRUE
        if a.op == "not":
            return a.args[0]
        if a.op == "lt":
            return self.le(a.args[1], a.args[0])
        if a.op == "le":
            return self.lt(a.args[1], a.args[0])
        return self.mk("not", (a,), BOOL)

    def and_(self, *xs) -> Term:
        out, seen = [], set()
        for x in xs:
            for y in (x.args if x.op == "and" else (x,)):
                assert y.ty == BOOL, y
                if y is self.FALSE:
                    return self.FALSE
                if y is self.TRUE or y.uid in seen:
                    continue
                seen.add(y.uid)
                out.append(y)
        for y in out:
            n = y.args[0] if y.op == "not" else None
            if n is not None and n.uid in seen:
                return self.FALSE
        if not out:
            return self.TRUE
        if len(out) == 1:
            return out[0]
        return self.mk("and", tuple(out), BOOL)

    def or_(self, *xs) -> Term:
        out, seen = [], set()
        for x in xs:
            for y in (x.args if x.op == "or" else (x,)):
                assert y.ty == BOOL, y
                if y is self.TRUE:
                    return self.TRUE
                if y is self.FALSE or y.uid in seen:
                    continue
                seen.add(y.uid)
                out.append(y)
        for y in out:
            n = y.args[0] if y.op == "not" else None
            if n is not None and n.uid in seen:
                return self.TRUE
        if not out:
            return self.FALSE
        if len(out) == 1:
            return out[0]
        # factor conjuncts common to every disjunct: (A & B) | (A & C) -> A & (B | C)
        conj = [list(y.args) if y.op == "and" else [y] for y in out]
        common = [c for c in conj[0] if all(any(c is d for d in other) for other in conj[1:])]
        if common:
            cu = {c.uid for c in common}
            rest = [self.and_(*[c for c in cs if c.uid not in cu]) for cs in conj]
            return self.and_(*common, self.or_(*rest))
        if len(out) == 2:  # (c & X) | (!c & X) handled by factoring; c | (!c & X) -> c | X
            a, b = out
            for p, q in ((a, b), (b, a)):
                qs = list(q.args) if q.op == "and" else [q]
                np_ = self.not_(p)
                if any(z is np_ for z in qs):
                    return self.or_(p, self.and_(*[z for z in qs if z is not np_]))
        return self.mk("or", tuple(out), BOOL)

    def implies(self, a: Term, b: Term) -> Term:
        return self.or_(self.not_(a), b)

    def ite(self, c: Term, a: Term, b: Term) -> Term:
        assert c.ty == BOOL and a.ty == b.ty, (c, a, b)
        if c is self.TRUE:
            return a
        if c is self.FALSE:
            return b
        if a is b:
            return a
        if c.op == "not":
            return self.ite(c.args[0], b, a)
        if a.ty == BOOL:
            if a is self.TRUE and b is self.FALSE:
                return c
            if a is self.FALSE and b is self.TRUE:
                return self.not_(c)
            if a is self.TRUE:
                return self.or_(c, b)
            if b is self.FALSE:
                return self.and_(c, a)
            if a is self.FALSE:
                return self.and_(self.not_(c), b)
            if b is self.TRUE:
                return self.or_(self.not_(c), a)
        if a.op == "ite" and a.args[0] is c:
            a = a.args[1]
        if b.op == "ite" and b.args[0] is c:
            b = b.args[2]
        if a is b:
            return a
        return self.mk("ite", (c, a, b), a.ty)

    def eq(self, a: Term, b: Term) -> Term:
        """Identity of denotation (the solver's `=`), NOT Python `==`."""
        assert a.ty == b.ty, (a, b)
        if a is b:
            return self.TRUE
        if a.op == "const" and b.op == "const":
            return self.FALSE  # distinct constants of one type are distinct values (float constants are keyed by bit pattern)
        if a.ty == BOOL:
            if a is self.TRUE:
                return b
            if b is self.TRUE:
                return a
            if a is self.FALSE:
                return self.not_(b)
            if b is self.FALSE:
                return self.not_(a)
        if a.uid > b.uid:
            a, b = b, a
        return self.mk("eq", (a, b), BOOL)

    # ---- exact integer arithmetic (Python int is unbounded: these are the mathematical operations)
    def _ic(self, t):
        return t.args[0] if (t.op == "const" and t.ty == INT) else None

    def add(self, a: Term, b: Term) -> Term:
        assert a.ty == INT and b.ty == INT, (a, b)
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None:
            return self.const(x + y)
        if x == 0:
            return b
        if y == 0:
            return a
        if x is not None:  # constants to the right
            a, b, x, y = b, a, y, x
        if y is not None and a.op == "add" and self._ic(a.args[1]) is not None:
            return self.add(a.args[0], self.const(self._ic(a.args[1]) + y))
        return self.mk("add", (a, b), INT)

    def neg(self, a: Term) -> Term:
        assert a.ty == INT
        x = self._ic(a)
        if x is not None:
            return self.const(-x)
        if a.op == "neg":
            return a.args[0]
        return self.mk("neg", (a,), INT)

    def sub(self, a: Term, b: Term) -> Term:
        assert a.ty == INT and b.ty == INT
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None:
            return self.const(x - y)
        if y is not None:
            return self.add(a, self.const(-y))
        if a is b:
            return self.const(0)
        return self.mk("sub", (a, b), INT)

    def mul(self, a: Term, b: Term) -> Term:
        assert a.ty == INT and b.ty == INT
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None:
            return self.const(x * y)
        if x == 0 or y == 0:
            return self.const(0)
        if x == 1:
            return b
        if y == 1:
            return a
        if x is not None:
            a, b = b, a
        return self.mk("mul", (a, b), INT)

    def lt(self, a: Term, b: Term) -> Term:
        assert a.ty == INT and b.ty == INT, (a, b)
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None:
            return self.TRUE if x < y else self.FALSE
        if a is b:
            return self.FALSE
        return self.mk("lt", (a, b), BOOL)

    def le(self, a: Term, b: Term) -> Term:
        assert a.ty == INT and b.ty == INT, (a, b)
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None:
            return self.TRUE if x <= y else self.FALSE
        if a is b:
            return self.TRUE
        return self.mk("le", (a, b), BOOL)

    def fdiv(self, a: Term, b: Term) -> Term:
        """Python floor division; only meaningful where b != 0 (the executor guards it)."""
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None and y != 0:
            return self.const(x // y)
        if y == 1:
            return a
        return self.mk("fdiv", (a, b), INT)

    def mod(self, a: Term, b: Term) -> Term:
        x, y = self._ic(a), self._ic(b)
        if x is not None and y is not None and y != 0:
            return self.const(x % y)
        return self.mk("mod", (a, b), INT)

    def b2i(self, a: Term) -> Term:
        assert a.ty == BOOL
        if a is self.TRUE:
            return self.const(1)
        if a is self.FALSE:
            return self.const(0)
        return self.mk("b2i", (a,), INT)

    # ---- tuples of fixed shape
    def tup(self, elems) -> Term:
        elems = tuple(elems)
        return self.mk("tup", elems, FTUPLE(*[e.ty for e in elems]))

    def proj(self, i: int, t: Term) -> Term:
        assert t.ty[0] == "ftuple" and 0 <= i < len(t.ty) - 1, (i, t)
        if t.op == "tup":
            return t.args[i]
        if t.op == "ite":
            return self.ite(t.args[0], self.proj(i, t.args[1]), self.proj(i, t.args[2]))
        return self.mk("proj", (i, t), t.ty[1 + i])

    # ---- uninterpreted applications (pure functions of their arguments)
    def app(self, name: str, args, ty) -> Term:
        args = tuple(args)
        head = name.split(":", 1)[0]
        h = self.simp.get(head)
        if h is not None:
            r = h(self, name, args, ty)
            if r is not None:
                assert r.ty == ty, (name, r.ty, ty)
                return r
        key = ("app", (name, *args), ty)
        new = key not in self.table
        t = self.mk("app", (name, *args), ty)
        if new:
            fh = self.fact_hooks.get(head)
            if fh is not None:
                fh(self, t)
        return t

    # ---- generic rebuild / substitution
    def rebuild(self, op, args, ty) -> Term:
        if op in ("const", "sym"):
            return self.mk(op, args, ty)
        if op == "not":
            return self.not_(args[0])
        if op == "and":
            return self.and_(*args)
        if op == "or":
            return self.or_(*args)
        if op == "ite":
            return self.ite(*args)
        if op == "eq":
            return self.eq(*args)
        if op in ("add", "sub", "mul", "lt", "le", "fdiv", "mod"):
            return getattr(self, op)(*args)
        if op == "neg":
            return self.neg(args[0])
        if op == "b2i":
            return self.b2i(args[0])
        if op == "tup":
            return self.tup(args)
        if op == "proj":
            return self.proj(args[0], args[1])
        if op == "app":
            return self.app(args[0], args[1:], ty)
        raise AssertionError(op)

    def subst(self, t: Term, m: dict, memo: dict | None = None) -> Term:
        """Replace symbols (keys of m, by identity) throughout t."""
        if not m:
            return t
        memo = {} if memo is None else memo
        stack = [t]
        while stack:
            u = stack[-1]
            if u.uid in memo:
                stack.pop()
                continue
            if u in m:
                memo[u.uid] = m[u]
                stack.pop()
                continue
            if u.op in ("const", "sym"):
                memo[u.uid] = u
                stack.pop()
                continue
            kids = [a for a in u.args if isinstance(a, Term)]
            pend = [k for k in kids if k.uid not in memo]
            if pend:
                stack.extend(pend)
                continue
            new = tuple(memo[a.uid] if isinstance(a, Term) else a for a in u.args)
            memo[u.uid] = u if all(x is y for x, y in zip(new, u.args)) else self.rebuild(u.op, new, u.ty)
            stack.pop()
        return memo[t.uid]


class TermLimit(Exception):
    pass


def syms(t: Term) -> frozenset:
    """The symbols occurring in t (memoized on the term)."""
    if t._syms is not None:
        return t._syms
    stack, order = [t], []
    while stack:
        u = stack.pop()
        if u._syms is not None:
            continue
        order.append(u)
        for a in u.args:
            if isinstance(a, Term) and a._syms is None:
                stack.append(a)
    for u in reversed(order):
        if u._syms is not None:
            continue
        if u.op == "sym":
            u._syms = frozenset((u,))
        else:
            s = frozenset()
            for a in u.args:
                if isinstance(a, Term):
                    if a._syms is None:  # a cycle is impossible; a kid not yet done means it was queued twice: compute directly
                        syms(a)
                    s = s | a._syms
            u._syms = s
    return t._syms


def show(t: Term, depth: int = 6) -> str:
    if t.op == "const":
        return repr(t.args[0])
    if t.op == "sym":
        return str(t.args[0])
    if depth <= 0:
        return "…"
    if t.op == "app":
        return f"{t.args[0]}(" + ", ".join(show(a, depth - 1) for a in t.args[1:]) + ")"
    return f"{t.op}(" + ", ".join(show(a, depth - 1) if isinstance(a, Term) else repr(a) for a in t.args) + ")"
