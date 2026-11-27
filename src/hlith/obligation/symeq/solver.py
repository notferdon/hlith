# SPDX-License-Identifier: Apache-2.0
"""Z3 backend of the symbolic equivalence prover: terms -> quantifier-free formulas over Int, Bool and uninterpreted sorts.

Only VALIDITY is ever concluded (unsat of the negation, under the session's facts). `unknown`, a timeout or any encoding failure is `None` and the caller refuses. A model of the
negation is returned as a hint (candidate inputs for the concrete differential); it is never a verdict by itself."""

from __future__ import annotations

import z3

from .terms import BOOL, INT, Term, ty_str


class Solver:
    def __init__(self, ctx, timeout_ms: int = 4000, total_ms: int = 60000):
        self.ctx = ctx
        self.timeout_ms = timeout_ms
        self.budget_ms = total_ms
        self.sorts: dict = {}
        self.funcs: dict = {}
        self.memo: dict = {}
        self.consts: dict = {}  # sort name -> [z3 consts for literals], asserted pairwise distinct
        self.s = z3.Solver()
        self.s.set("timeout", timeout_ms)
        self.nfacts = 0
        self.ndistinct: dict = {}
        self.queries = 0
        self.unknowns = 0

    # ---- sorts and declarations
    def sort(self, ty):
        if ty == INT:
            return z3.IntSort()
        if ty == BOOL:
            return z3.BoolSort()
        s = self.sorts.get(ty)
        if s is None:
            s = self.sorts[ty] = z3.DeclareSort("T:" + ty_str(ty))
        return s

    def func(self, name, arg_tys, res_ty):
        key = (name, arg_tys, res_ty)
        f = self.funcs.get(key)
        if f is None:
            f = self.funcs[key] = z3.Function(f"{name}|{len(self.funcs)}", *[self.sort(a) for a in arg_tys], self.sort(res_ty))
        return f

    # ---- encoding
    def enc(self, t: Term):
        memo = self.memo
        r = memo.get(t.uid)
        if r is not None:
            return r
        stack = [t]
        while stack:
            u = stack[-1]
            if u.uid in memo:
                stack.pop()
                continue
            kids = [a for a in u.args if isinstance(a, Term)]
            pend = [k for k in kids if k.uid not in memo]
            if pend:
                stack.extend(pend)
                continue
            memo[u.uid] = self._enc1(u, [memo[k.uid] for k in kids])
            stack.pop()
        return memo[t.uid]

    def _enc1(self, u: Term, ks):
        op = u.op
        if op == "const":
            v = u.args[0]
            if u.ty == INT:
                return z3.IntVal(v)
            if u.ty == BOOL:
                return z3.BoolVal(v)
            c = z3.Const(f"lit{u.uid}", self.sort(u.ty))
            self.consts.setdefault(u.ty, []).append(c)
            return c
        if op == "sym":
            return z3.Const(f"s{u.uid}:{u.args[0]}", self.sort(u.ty))
        if op == "not":
            return z3.Not(ks[0])
        if op == "and":
            return z3.And(*ks)
        if op == "or":
            return z3.Or(*ks)
        if op == "ite":
            return z3.If(ks[0], ks[1], ks[2])
        if op == "eq":
            return ks[0] == ks[1]
        if op == "add":
            return ks[0] + ks[1]
        if op == "sub":
            return ks[0] - ks[1]
        if op == "mul":
            return ks[0] * ks[1]
        if op == "neg":
            return -ks[0]
        if op == "lt":
            return ks[0] < ks[1]
        if op == "le":
            return ks[0] <= ks[1]
        if op == "b2i":
            return z3.If(ks[0], z3.IntVal(1), z3.IntVal(0))
        if op == "fdiv":
            # Python floor division. Z3 integer division is Euclidean (remainder >= 0): equal to floor for a positive divisor; for a negative divisor
            # a // b == (-a) div (-b). The divisor is nonzero wherever the executor lets this term be observed.
            a, b = ks
            return z3.If(b > 0, a / b, (-a) / (-b))
        if op == "mod":
            a, b = ks
            return z3.If(b > 0, a % b, -((-a) % (-b)))
        if op == "tup":
            f = self.func("tup", tuple(k.ty for k in u.args), u.ty)
            return f(*ks)
        if op == "proj":
            f = self.func(f"proj{u.args[0]}", (u.args[1].ty,), u.ty)
            return f(ks[0])
        if op == "app":
            args = u.args[1:]
            if not args:
                return z3.Const(f"k{u.uid}:{u.args[0]}", self.sort(u.ty))
            f = self.func(u.args[0], tuple(a.ty for a in args), u.ty)
            return f(*ks)
        raise AssertionError(op)

    def _sync(self):
        facts = self.ctx.facts
        while self.nfacts < len(facts):
            self.s.add(self.enc(facts[self.nfacts]))
            self.nfacts += 1
        for ty, cs in self.consts.items():
            n = self.ndistinct.get(ty, 0)
            if len(cs) > n and len(cs) > 1:
                # pairwise distinct literals: assert each new literal against all earlier ones
                for i in range(max(n, 1), len(cs)):
                    for j in range(i):
                        self.s.add(cs[i] != cs[j])
            self.ndistinct[ty] = len(cs)

    # ---- queries
    def valid(self, f: Term, assume: tuple = ()):
        """True: f holds under the facts and assumptions for every valuation. False: a counter-model exists (returned by `model`). None: undecided."""
        ctx = self.ctx
        if f is ctx.TRUE:
            return True
        self.queries += 1
        if self.budget_ms <= 0:
            self.unknowns += 1
            return None
        try:
            goal = z3.Not(self.enc(f))
            pre = [self.enc(a) for a in assume]
            self._sync()  # after encoding: the encoding may have created literals and (through hooks) facts
        except (z3.Z3Exception, RecursionError):
            self.unknowns += 1
            return None
        self.s.push()
        try:
            for p in pre:
                self.s.add(p)
            self.s.add(goal)
            import time

            t0 = time.monotonic()
            self.s.set("timeout", max(1, min(self.timeout_ms, int(self.budget_ms))))
            r = self.s.check()
            self.budget_ms -= (time.monotonic() - t0) * 1000.0
            if r == z3.unsat:
                return True
            if r == z3.sat:
                try:
                    self.last_model = self.s.model()
                except z3.Z3Exception:
                    self.last_model = None
                return False
            self.unknowns += 1
            return None
        except z3.Z3Exception:
            self.unknowns += 1
            return None
        finally:
            self.s.pop()

    def model_value(self, t: Term):
        """Concrete int / bool value of a symbol in the last counter-model, or None."""
        m = getattr(self, "last_model", None)
        if m is None or t.uid not in self.memo:
            return None
        try:
            v = m.eval(self.memo[t.uid], model_completion=True)
            if t.ty == INT and z3.is_int_value(v):
                return v.as_long()
            if t.ty == BOOL and (z3.is_true(v) or z3.is_false(v)):
                return z3.is_true(v)
        except z3.Z3Exception:
            return None
        return None
