# SPDX-License-Identifier: Apache-2.0
"""Symbolic executor of the equivalence prover: one Python function -> a set of guarded exits over typed terms.

What an execution produces. Every way the function can finish is an Exit(guard, kind, value, world): `guard` is the exact condition on the inputs under which that exit is taken
(guards are mutually exclusive and jointly exhaustive), `kind` is 'ret' or 'raise', `value` the returned object or the exception, `world` the state of everything outside the
function's own fresh objects after the exit.

The three modelling rules (soundness rests on these):
  1. EXACT VALUES. A value whose type is an exact builtin (int, bool, str, float, None, tuple/list/dict/set of those) is a term; operations on it follow the builtin model
     (model.py). An operation that can raise forks an explicit raise exit BEFORE its result is used, in Python's evaluation order.
  2. THE WORLD. Anything else (an unannotated parameter, `self`, the result of a call that is not inlined, a module global that is not a literal) is OPAQUE. Every operation on an
     opaque value (attribute, call, operator, truth test, iteration) may run arbitrary code: it is an uninterpreted function of the CURRENT WORLD and its operands, may raise, and
     returns a new world. Two executions are only ever proved equal when they perform the same opaque operations on equal operands in the same order.
  3. OWNERSHIP. A mutable container created by the function is a value term only while exactly one local name refers to it (owned): it can then be mutated functionally. Any use that
     could create a second reference freezes it (no later mutation is modelled: the prover refuses); passing it to opaque code makes it opaque.

Loops are not unrolled: a loop is summarised as (continue-condition, next-state) over fresh symbols, matched against every loop class seen so far (in either version) by the solver,
and applied as uninterpreted functions of (iterable, initial state, world). The exiting iteration is then executed once more on the summarised state, so `break`, `return` and raises
inside a loop are ordinary paths. See run_loop."""

from __future__ import annotations

import ast
import builtins
import itertools

from .module import fold_literal, local_names, _NOFOLD, scope_nodes, _Wrap
from .terms import (BOOL, DICT, EXC, FLOAT, FTUPLE, INT, LIST, NONE, OPAQUE, REF, SET, STR, TUPLE, WORLD, Term, elem_type, is_exact, is_immutable, is_mutable_builtin, syms, ty_str)

BOT = ("bot",)
FUNC = ("func",)


class Unknown(Exception):
    """The prover does not model this: the caller reports UNVERIFIED with the reason."""


class _Fork(Exception):
    def __init__(self, cond):
        self.cond = cond


MAYBE = object()  # a local that may be unbound here


class Val:
    __slots__ = ("t", "owned")

    def __init__(self, t: Term, owned: bool = False):
        self.t, self.owned = t, owned

    def __repr__(self):
        return f"Val({self.t!r}{', owned' if self.owned else ''})"


class State:
    """pc: path condition; env: locals; w: world; dirty: the world may have changed since the function was entered (a typed external container is then no longer known to
    hold what its annotation says: it is read as an unknown object); assume: case-split decisions of the enclosing statement."""
    __slots__ = ("pc", "env", "w", "assume", "dirty")

    def clone(self):
        s = State()
        s.pc, s.env, s.w, s.assume, s.dirty = self.pc, dict(self.env), self.w, self.assume, self.dirty
        return s

    def adopt(self, o):
        self.pc, self.env, self.w, self.dirty = o.pc, o.env, o.w, o.dirty


class Exit:
    __slots__ = ("guard", "kind", "val", "w", "fresh")

    def __init__(self, guard, kind, val, w, fresh=True):
        self.guard, self.kind, self.val, self.w, self.fresh = guard, kind, val, w, fresh


class Handlers:
    __slots__ = ("ret", "rais", "brk", "cont", "div")

    def __init__(self, ret, rais, brk, cont, div):
        self.ret, self.rais, self.brk, self.cont, self.div = ret, rais, brk, cont, div


class LoopClass:
    __slots__ = ("kid", "is_while", "threaded", "ext", "may_div", "elem_ty", "carried_tys", "lifted_tys", "cont", "nexts", "next_w")


class Session:
    """State shared by the two executions of one proof: terms, solver, loop classes, exception classes, the assumptions the proof used."""

    def __init__(self, ctx, solver):
        self.ctx, self.solver = ctx, solver
        self.loops: list = []
        self.exc_cls: dict = {}  # exception term uid -> builtin exception class name
        self.narrow: dict = {}  # predicate term uid -> (local name, narrowed term)
        self.notes: set = set()
        self.w0 = ctx.sym("world0", WORLD)
        self.formals: dict = {}

    def formal(self, kind, i, ty):
        key = (kind, i, ty)
        f = self.formals.get(key)
        if f is None:
            f = self.formals[key] = self.ctx.sym(f"%{kind}{i}:{ty_str(ty)}", ty)
        return f


_MUTATORS = frozenset({"append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse", "update", "add", "discard", "setdefault", "popitem",
                       "difference_update", "intersection_update", "symmetric_difference_update"})
_MAX_STATES = 48
_MAX_FORKS = 24
_MAX_DEPTH = 10
_EXC_NAMES = frozenset(n for n in dir(builtins) if isinstance(getattr(builtins, n), type) and issubclass(getattr(builtins, n), BaseException))


def assigned_names(nodes) -> set:
    """Names a statement list may (re)bind or mutate in the enclosing function scope: stores, deletes, augmented assignments, mutating method calls and subscript stores on a
    plain name, and names declared by nested definitions. Comprehension targets are a scope of their own."""
    out = set()
    for n in scope_nodes(_Wrap(list(nodes))):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.attr in _MUTATORS:
            out.add(n.func.value.id)
        elif isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.ctx, (ast.Store, ast.Del)) and isinstance(n.value, ast.Name):
            out.add(n.value.id)
        elif isinstance(n, ast.Call):
            # an owned container passed as a plain-name argument may be lent to an inlined helper that mutates it
            for a in n.args:
                if isinstance(a, ast.Name):
                    out.add(a.id)
            for k in n.keywords:
                if isinstance(k.value, ast.Name):
                    out.add(k.value.id)
    return out


class Exec:
    def __init__(self, sess: Session, mod, tainted: set, side: str, target: str, model):
        self.S, self.ctx, self.mod, self.tainted, self.side, self.target = sess, sess.ctx, mod, tainted, side, target
        self.model = model
        self.exits: list = []
        self.collectors: list = [self.exits]
        self.scopes: list = []
        self.call_stack: list = []
        self.bound_stack: list = []
        self.exc_stack: list = []
        self.hidden = 0
        self.h = None
        self.steps = 0

    # ================================================================================================================ small helpers
    def unknown(self, why: str):
        raise Unknown(why)

    def note(self, s: str):
        self.S.notes.add(s)

    def split(self, st: State, cond: Term):
        c = self.ctx
        a, b = st.clone(), st.clone()
        a.pc, b.pc = c.and_(st.pc, cond), c.and_(st.pc, c.not_(cond))
        return a, b

    def dead(self, st: State) -> bool:
        return st.pc is self.ctx.FALSE

    def decide(self, st: State, cond: Term) -> bool:
        c = self.ctx
        if cond is c.TRUE:
            return True
        if cond is c.FALSE:
            return False
        v = st.assume.get(cond.uid)
        if v is None:
            raise _Fork(cond)
        return v

    def snapshot(self, st: State):
        return (st.pc, dict(st.env), st.w, [(lst, len(lst)) for lst in self.collectors], self.h, len(self.scopes), len(self.call_stack), len(self.bound_stack),
                self.exc_stack, list(self.exc_stack), len(self.collectors), st.dirty)

    def restore(self, st: State, snap):
        st.pc, st.env, st.w, st.dirty = snap[0], dict(snap[1]), snap[2], snap[11]
        for lst, n in snap[3]:
            del lst[n:]
        self.h = snap[4]
        del self.scopes[snap[5]:], self.call_stack[snap[6]:], self.bound_stack[snap[7]:], self.collectors[snap[10]:]
        self.exc_stack = snap[8]
        self.exc_stack[:] = snap[9]

    def _drop_collector(self, lst):
        """Remove a collector BY IDENTITY (list.remove compares by equality: two empty collectors are equal)."""
        for i in range(len(self.collectors) - 1, -1, -1):
            if self.collectors[i] is lst:
                del self.collectors[i]
                return

    def hidden_name(self, hint: str) -> str:
        self.hidden += 1
        return f"%{hint}{self.hidden}"

    # ---- raising
    def do_raise(self, st: State, exc: Term):
        """`st` is a state in which the exception `exc` is raised (already restricted to that path)."""
        if self.dead(st):
            return
        if self.exc_stack and self.exc_stack[-1] is not None:
            base = exc
            exc = self.ctx.app("exc.ctx", (exc, self.exc_stack[-1]), EXC)
            if base.uid in self.S.exc_cls:
                self.S.exc_cls[exc.uid] = self.S.exc_cls[base.uid]
        self.h.rais(st, exc)

    def raise_if(self, st: State, cond: Term, exc: Term):
        """Fork a raise path under `cond`; `st` continues under its negation."""
        c = self.ctx
        if cond is c.FALSE:
            return
        r = st.clone()
        r.pc = c.and_(st.pc, cond)
        self.do_raise(r, exc)
        st.pc = c.and_(st.pc, c.not_(cond))

    def prim_exc(self, cls: str, op: str, args=()) -> Term:
        e = self.ctx.app(f"exc.prim:{cls}:{op}", tuple(args), EXC)
        self.S.exc_cls[e.uid] = cls
        return e

    def partial(self, st: State, name: str, args, ty) -> Term:
        """A pure builtin operation that may raise for some arguments (which ones is an uninterpreted predicate of the same arguments)."""
        args = tuple(args)
        x = self.ctx.app("X:" + name, args, BOOL)
        self.raise_if(st, x, self.ctx.app("E:" + name, args, EXC))
        return self.ctx.app(name, args, ty)

    def total(self, name: str, args, ty) -> Term:
        return self.ctx.app(name, tuple(args), ty)

    def world_op(self, st: State, name: str, args, ty=OPAQUE) -> Term:
        """An operation that may run arbitrary code: result, raise condition, exception and the next world are uninterpreted functions of (world, operands)."""
        c = self.ctx
        a = (st.w, *args)
        w2 = c.app("W!" + name, a, WORLD)
        x = c.app("X!" + name, a, BOOL)
        r = st.clone()
        r.pc, r.w, r.dirty = c.and_(st.pc, x), w2, True
        self.do_raise(r, c.app("E!" + name, a, EXC))
        st.pc, st.w, st.dirty = c.and_(st.pc, c.not_(x)), w2, True
        return c.app("R!" + name, a, ty)

    # ---- values
    def value(self, st: State, v: Val) -> Term:
        """The exact value term of v: a reference to an external typed object is read through the current world."""
        t = v.t
        if t.ty[0] == "ref":
            if st.dirty:
                return self.ctx.app("ref.obj", (t,), OPAQUE)  # something may have changed it: no longer known to hold what its annotation says
            return self.ctx.app("deref0", (t,), t.ty[1])  # the world is as it was on entry: the value the caller passed
        return t

    def opaque_arg(self, st: State, v: Val, node=None) -> Term:
        """v as an operand of opaque code. A locally created mutable container ESCAPES here: uniquely owned -> the local becomes opaque; shared -> refused."""
        t = v.t
        k = t.ty[0]
        if k == "ref":
            return self.ctx.app("ref.obj", (t,), OPAQUE)
        if k == "func":
            return self.func_value(t)
        if k == "exc":
            return self.ctx.app("exc.val", (t,), OPAQUE)
        if is_mutable_builtin(t.ty):
            if isinstance(node, ast.Name) and node.id in st.env and st.env[node.id] is not MAYBE and st.env[node.id].t is t:
                if not st.env[node.id].owned:
                    self.unknown(f"a shared local container ({node.id}) is passed to code that is not modelled")
                if any(_deep_mutable(x) for x in t.ty[1:]):
                    self.unknown("a nested local container is passed to code that is not modelled")
                box = self.ctx.app("box", (t, st.w), OPAQUE)
                st.env[node.id] = Val(box)
                return box
            if not v.owned:
                self.unknown("a shared local container is passed to code that is not modelled")
            if any(_deep_mutable(x) for x in t.ty[1:]):
                self.unknown("a nested local container is passed to code that is not modelled")
        elif _deep_mutable(t.ty):
            self.unknown("a local container nested in a tuple is passed to code that is not modelled")
        return t

    def func_value(self, t: Term) -> Term:
        name = t.args[0]
        if name.startswith("F:"):
            nm = name[2:]
            if nm in self.tainted:
                self.unknown(f"the changed function {nm} is used as a value")
            return self.ctx.app("G:" + nm, (), OPAQUE)
        if name.startswith("B:"):
            return self.ctx.app("G:builtins." + name[2:], (), OPAQUE)
        return self.ctx.app("G:" + name, (), OPAQUE)

    # ================================================================================================================ merging
    def _shape(self, st: State):
        return tuple(sorted((k, ("?",) if v is MAYBE else (v.t.ty, v.owned)) for k, v in st.env.items()))

    def merge_many(self, states: list) -> list:
        c = self.ctx
        live = [s for s in states if not self.dead(s)]
        if len(live) <= 1:
            return live
        groups: dict = {}
        for s in live:
            groups.setdefault(self._merge_key(s), []).append(s)
        out = []
        for g in groups.values():
            if len(g) == 1:
                out.append(g[0])
                continue
            conj = [list(s.pc.args) if s.pc.op == "and" else [s.pc] for s in g]
            common = {x.uid for x in conj[0]}
            for cs in conj[1:]:
                common &= {x.uid for x in cs}
            sels = [c.and_(*[x for x in cs if x.uid not in common]) for cs in conj]
            m = State()
            m.pc = c.or_(*[s.pc for s in g])
            m.assume = g[0].assume
            m.dirty = any(x.dirty for x in g)
            m.w = g[-1].w
            for s, sel in zip(reversed(g[:-1]), reversed(sels[:-1])):
                m.w = c.ite(sel, s.w, m.w)
            m.env = {}
            for k in g[0].env:
                vs = [s.env[k] for s in g]
                if any(v is MAYBE for v in vs):
                    m.env[k] = MAYBE
                    continue
                t = vs[-1].t
                for v, sel in zip(reversed(vs[:-1]), reversed(sels[:-1])):
                    t = c.ite(sel, v.t, t)
                m.env[k] = Val(t, all(v.owned for v in vs))
            out.append(m)
        if len(out) > _MAX_STATES:
            self.unknown("too many distinct execution paths")
        return out

    def _merge_key(self, st: State):
        """States merge when they bind the same names to the same types; a name bound on one path only becomes maybe-unbound (reading it later is refused)."""
        return tuple(sorted((k, None if v is MAYBE else v.t.ty) for k, v in st.env.items()))

    def align_envs(self, states: list) -> list:
        """Give every state the same key set: a name missing somewhere becomes MAYBE everywhere it is missing; empty containers of unknown element type adopt the type of their peers."""
        live = [s for s in states if not self.dead(s)]
        if len(live) <= 1:
            return live
        keys = set()
        for s in live:
            keys |= set(s.env)
        for s in live:
            for k in keys:
                if k not in s.env:
                    s.env[k] = MAYBE
        for k in keys:
            tys = {s.env[k].t.ty for s in live if s.env[k] is not MAYBE}
            if len(tys) > 1:
                full = [t for t in tys if not _has_bot(t)]
                if len(full) == 1:
                    for s in live:
                        v = s.env[k]
                        if v is not MAYBE and v.t.ty != full[0]:
                            r = self.model.coerce_bot(self, v.t, full[0])
                            if r is not None:
                                s.env[k] = Val(r, v.owned)
        return live

    def join(self, states: list) -> list:
        return self.merge_many(self.align_envs(states))

    # ================================================================================================================ statements
    def exec_block(self, stmts, states: list) -> list:
        for stmt in stmts:
            nxt = []
            for s in states:
                nxt.extend(self.exec_stmt(stmt, s))
            states = self.join(nxt)
            if not states:
                break
        return states

    def exec_stmt(self, stmt, st: State) -> list:
        if self.dead(st):
            return []
        self.steps += 1
        if self.steps > 20000:
            self.unknown("analysis step limit")
        work, out, forks = [st], [], 0
        while work:
            s = work.pop()
            marks = [(lst, len(lst)) for lst in self.collectors]
            saved_h, saved_scopes, saved_calls, saved_bound, saved_exc, ncoll = self.h, len(self.scopes), len(self.call_stack), len(self.bound_stack), len(self.exc_stack), len(self.collectors)
            trial = s.clone()
            try:
                res = self._exec_stmt(stmt, trial)
            except _Fork as f:
                for lst, n in marks:
                    del lst[n:]
                self.h = saved_h
                del self.scopes[saved_scopes:], self.call_stack[saved_calls:], self.bound_stack[saved_bound:], self.exc_stack[saved_exc:], self.collectors[ncoll:]
                forks += 1
                if forks > _MAX_FORKS:
                    self.unknown("too many case splits in one statement")
                a, b = self.split(s, f.cond)
                a.assume = dict(s.assume)
                a.assume[f.cond.uid] = True
                b.assume = dict(s.assume)
                b.assume[f.cond.uid] = False
                work.extend([b, a])
                continue
            out.extend(r for r in res if not self.dead(r))
        return out

    def _exec_stmt(self, node, st: State) -> list:
        m = getattr(self, "s_" + type(node).__name__, None)
        if m is None:
            self.unknown(f"statement not modelled: {type(node).__name__}")
        return m(node, st)

    def s_Pass(self, node, st):
        return [st]

    def s_Expr(self, node, st):
        if isinstance(node.value, ast.Constant):
            return [st]
        self.ev(node.value, st, retain=False)
        return [st]

    def s_Assign(self, node, st):
        v = self.ev(node.value, st)
        if len(node.targets) > 1 and v.owned:
            v = Val(v.t, False)
        for tgt in node.targets:
            self.assign(tgt, v, st)
        return [st]

    def s_AnnAssign(self, node, st):
        if node.value is None:
            return [st]
        self.assign(node.target, self.ev(node.value, st), st)
        return [st]

    def s_AugAssign(self, node, st):
        tgt = node.target
        if isinstance(tgt, ast.Name):
            cur = self.load_name(tgt.id, st, retain=False, for_update=True)
            rhs = self.ev(node.value, st, retain=False)
            st.env[tgt.id] = self.model.augassign(self, st, node.op, cur, rhs, tgt.id)
            return [st]
        if isinstance(tgt, ast.Subscript):
            base = self.ev(tgt.value, st, retain=False)
            idx = self.ev_index(tgt.slice, st)
            cur = self.model.subscript(self, st, base, idx)
            rhs = self.ev(node.value, st, retain=False)
            new = self.model.binop(self, st, node.op, cur, rhs)
            self.store_subscript(tgt, base, idx, new, st)
            return [st]
        if isinstance(tgt, ast.Attribute):
            obj = self.ev(tgt.value, st)
            cur = self.get_attr(st, obj, tgt.attr, tgt.value)
            rhs = self.ev(node.value, st, retain=False)
            new = self.model.binop(self, st, node.op, cur, rhs)
            self.set_attr(st, obj, tgt.attr, new, tgt.value)
            return [st]
        self.unknown("augmented assignment target not modelled")

    def s_Return(self, node, st):
        if node.value is None:
            v = Val(self.ctx.NONE)
        elif isinstance(node.value, ast.Name):
            v = self.load_name(node.value.id, st, retain=False, for_update=True)
            if v.t.ty[0] == "func":
                v = Val(self.func_value(v.t))
        else:
            v = self.ev(node.value, st)
        if not self.dead(st):
            self.h.ret(st, v)
        return []

    def s_Raise(self, node, st):
        c = self.ctx
        if node.exc is None:
            if not self.exc_stack or self.exc_stack[-1] is None:
                self.unknown("bare raise outside a modelled handler")
            exc = self.exc_stack[-1]
            if not self.dead(st):
                self.h.rais(st, exc)  # a re-raise keeps the exception as it is
            return []
        exc = self.make_exc(node.exc, st)
        if node.cause is not None:
            cause = self.ev(node.cause, st)
            ct = cause.t if cause.t.ty in (EXC, NONE) else self.opaque_arg(st, cause, node.cause)
            base = exc
            exc = c.app("exc.from", (exc, ct), EXC)
            if base.uid in self.S.exc_cls:
                self.S.exc_cls[exc.uid] = self.S.exc_cls[base.uid]
        self.do_raise(st, exc)
        return []

    def make_exc(self, e, st) -> Term:
        """The exception object a `raise e` raises."""
        c = self.ctx
        call = e if isinstance(e, ast.Call) else None
        head = call.func if call is not None else e
        if isinstance(head, ast.Name) and head.id in _EXC_NAMES and self.is_builtin_name(head.id) and (call is None or not call.keywords) and \
                not (call is not None and any(isinstance(a, ast.Starred) for a in call.args)):
            args = []
            for a in (call.args if call is not None else ()):
                v = self.ev(a, st)
                args.append(v.t if (is_exact(v.t.ty) and is_immutable(v.t.ty)) else self.opaque_arg(st, v, a))
            t = c.app("exc.new:" + head.id, tuple(args), EXC)
            self.S.exc_cls[t.uid] = head.id
            return t
        v = self.ev(e, st)
        if v.t.ty == EXC:
            return v.t
        o = self.opaque_arg(st, v, e)
        # raising a class instantiates it; raising a non-exception raises TypeError: both are functions of the object and the world
        return self.world_op(st, "raise.obj", (o,), EXC)

    def s_If(self, node, st):
        cond = self.truthy_of(node.test, st)
        if self.dead(st):
            return []
        a, b = self.split(st, cond)
        self.apply_narrowing(a, cond)
        self.apply_narrowing(b, self.ctx.not_(cond))
        return self.exec_block(node.body, [a]) + self.exec_block(node.orelse, [b])

    def apply_narrowing(self, st: State, cond: Term):
        conds = cond.args if cond.op == "and" else (cond,)
        for cd in conds:
            n = self.S.narrow.get(cd.uid)
            if n is not None:
                name, src, new = n
                cur = st.env.get(name)
                if cur is not None and cur is not MAYBE and cur.t is src:
                    st.env[name] = Val(new)

    def s_Assert(self, node, st):
        cond = self.truthy_of(node.test, st)
        if self.dead(st):
            return []
        a, b = self.split(st, cond)
        if not self.dead(b):
            args = ()
            if node.msg is not None:
                mv = self.ev(node.msg, b)
                args = (mv.t if (is_exact(mv.t.ty) and is_immutable(mv.t.ty)) else self.opaque_arg(b, mv, node.msg),)
            if not self.dead(b):
                exc = self.ctx.app("exc.assert", args, EXC)  # distinct from a raised AssertionError: `python -O` removes asserts
                self.S.exc_cls[exc.uid] = "AssertionError"
                self.note("assert statements are compared as written (python -O removes them)")
                self.do_raise(b, exc)
        # Never narrow types from `assert`: under `python -O`, assertions are stripped at runtime.
        return [a]

    def s_Break(self, node, st):
        self.h.brk(st)
        return []

    def s_Continue(self, node, st):
        self.h.cont(st)
        return []

    def s_Delete(self, node, st):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                if tgt.id not in st.env or st.env[tgt.id] is MAYBE:
                    self.unknown("del of a possibly unbound local")
                del st.env[tgt.id]
            elif isinstance(tgt, ast.Subscript):
                base = self.ev(tgt.value, st, retain=False)
                idx = self.ev_index(tgt.slice, st)
                self.model.del_subscript(self, st, tgt, base, idx)
            else:
                self.unknown("del target not modelled")
        return [st]

    def s_Global(self, node, st):
        self.unknown("global declaration")

    def s_Nonlocal(self, node, st):
        self.unknown("nonlocal declaration")

    def s_FunctionDef(self, node, st):
        if node.decorator_list:
            self.unknown("decorated nested function")
        if node.args.defaults or any(d is not None for d in node.args.kw_defaults):
            self.unknown("nested function with default arguments")
        if not self.mod.future_annotations:
            ann_nodes = [node.returns, *(a.annotation for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, node.args.vararg, node.args.kwarg] if a is not None)]
            if any(x is not None for x in ann_nodes):
                self.unknown("nested function with runtime-evaluated annotations")
        st.env[node.name] = Val(self.closure(node, st))
        return [st]

    # ---- assignment targets
    def assign(self, tgt, v: Val, st: State):
        if isinstance(tgt, ast.Name):
            if tgt.id not in self.scopes[-1]["locals"]:
                self.unknown("store to a non-local name")
            if v.t.ty[0] == "func":
                v = Val(self.func_value(v.t))
            st.env[tgt.id] = v
            return
        if isinstance(tgt, (ast.Tuple, ast.List)):
            if any(isinstance(e, ast.Starred) for e in tgt.elts):
                self.unknown("starred assignment")
            parts = self.model.unpack(self, st, v, len(tgt.elts))
            for e, p in zip(tgt.elts, parts):
                self.assign(e, p, st)
            return
        if isinstance(tgt, ast.Subscript):
            base = self.ev(tgt.value, st, retain=False)
            idx = self.ev_index(tgt.slice, st)
            self.store_subscript(tgt, base, idx, v, st)
            return
        if isinstance(tgt, ast.Attribute):
            obj = self.ev(tgt.value, st)
            self.set_attr(st, obj, tgt.attr, v, tgt.value)
            return
        self.unknown("assignment target not modelled")

    def store_subscript(self, tgt, base: Val, idx, v: Val, st: State):
        self.model.store_subscript(self, st, tgt, base, idx, v)

    def get_attr(self, st, obj: Val, attr: str, node=None) -> Val:
        if attr in self.tainted:
            self.unknown(f"attribute {attr} names code this change touches")
        o = self.opaque_arg(st, obj, node)
        return Val(self.world_op(st, "getattr:" + attr, (o,)))

    def set_attr(self, st, obj: Val, attr: str, v: Val, node=None):
        if attr in self.tainted:
            self.unknown(f"attribute {attr} names code this change touches")
        o = self.opaque_arg(st, obj, node)
        self.world_op(st, "setattr:" + attr, (o, self.opaque_arg(st, v)), NONE)

    # ================================================================================================================ try / except
    def s_Try(self, node, st):
        if node.finalbody:
            self.unknown("try/finally")
        c = self.ctx
        caught: list = []
        outer = self.h
        self.collectors.append(caught)
        self.h = Handlers(outer.ret, lambda s, e: caught.append((s, e)), outer.brk, outer.cont, outer.div)
        try:
            body_states = self.exec_block(node.body, [st])
        finally:
            self.h = outer
        out = self.exec_block(node.orelse, body_states) if node.orelse else list(body_states)
        for s, exc in list(caught):
            remaining = [s]
            for hd in node.handlers:
                nxt = []
                for r in remaining:
                    m = self.exc_match(r, exc, hd.type)
                    a, b = self.split(r, m)
                    if not self.dead(a):
                        if hd.name:
                            a.env[hd.name] = Val(exc)
                        self.exc_stack.append(exc)
                        try:
                            hs = self.exec_block(hd.body, [a])
                        finally:
                            self.exc_stack.pop()
                        for x in hs:
                            if hd.name:
                                x.env.pop(hd.name, None)
                        out.extend(hs)
                    if not self.dead(b):
                        nxt.append(b)
                remaining = nxt
            for r in remaining:
                outer.rais(r, exc)
        self._drop_collector(caught)
        return self.join(out)

    def exc_match(self, st: State, exc: Term, type_node) -> Term:
        c = self.ctx
        if type_node is None:
            return c.TRUE
        elts = type_node.elts if isinstance(type_node, ast.Tuple) else [type_node]
        names = []
        for e in elts:
            if isinstance(e, ast.Name) and e.id in _EXC_NAMES and self.is_builtin_name(e.id):
                names.append(e.id)
            elif isinstance(e, ast.Name) and e.id in self.mod.classes and e.id not in self.tainted and e.id not in self.scopes[-1]["locals"]:
                names.append("user:" + e.id)
            else:
                self.unknown("except clause names a class the prover cannot resolve")
        known = self.S.exc_cls.get(exc.uid)
        if known is not None:
            bn = [n for n in names if not n.startswith("user:")]
            if any(issubclass(getattr(builtins, known), getattr(builtins, n)) for n in bn):
                return c.TRUE
            if exc.op == "app" and (exc.args[0].startswith("exc.prim:") or exc.args[0].startswith("exc.assert")):
                return c.FALSE  # raised by a builtin operation: an exact builtin class, never a user subclass
            if len(bn) == len(names):
                return c.FALSE  # an exact builtin exception class is not an instance of unrelated builtin classes
            return c.FALSE  # a builtin exception is never an instance of a user-defined class
        return c.app("exc.isinst:" + ",".join(sorted(names)), (exc,), BOOL)

    # ================================================================================================================ loops
    def s_For(self, node, st):
        it = self.ev(node.iter, st, retain=False)
        if self.dead(st):
            return []
        assigned = assigned_names(node.body) | assigned_names(node.orelse)
        targets = {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
        for n in ast.walk(node.iter):
            if isinstance(n, ast.Name) and n.id in assigned:
                cur = st.env.get(n.id)
                if cur is not None and cur is not MAYBE and is_mutable_builtin(cur.t.ty):
                    self.unknown("the loop mutates a container its iterable is built from")

        def bind(s, ev):
            self.assign(node.target, ev, s)

        return self.run_loop(st, it, bind, lambda ss: self.exec_block(node.body, ss), assigned - targets, targets,
                             (lambda ss: self.exec_block(node.orelse, ss)) if node.orelse else None, iter_node=node.iter)

    def s_While(self, node, st):
        assigned = assigned_names(node.body) | assigned_names(node.orelse) | assigned_names([ast.Expr(node.test)])

        def test(s):
            return self.truthy_of(node.test, s)

        return self.run_loop(st, None, None, lambda ss: self.exec_block(node.body, ss), assigned, set(),
                             (lambda ss: self.exec_block(node.orelse, ss)) if node.orelse else None, test=test)

    def run_loop(self, st: State, it, bind, body, assigned: set, targets: set, orelse=None, test=None, iter_node=None) -> list:
        """Summarise and apply one loop. `it` is the iterable Val (None for while); `bind(state, elemVal)` binds the loop target; `body(states)` executes the body;
        `test(state)` is the while condition. Returns the live states after the loop.

        A loop class K is the pair (cont, next): `cont(state, elem)` says that an iteration started in `state` on `elem` runs to its end (no break / return / raise and, for while,
        the test is true) and `next(state, elem)` is the state it ends in. The loop itself is then the uninterpreted functions
            LX#K(iter, init, lifted.., world)  did some iteration NOT continue (for loops)      LT#K(..)  does the loop terminate (while loops, and bodies that may diverge)
            LS#K#i(..), LW#K(..), LE#K(..)     the state / world / element at the START of that iteration, or the final state when the iterable was exhausted
        with the facts  LT and LX => not cont(LS, LE, LW)  and  (builtin iterable empty) => not LX and LS = init.  The stopping iteration is re-executed on (LS, LE, LW) by the
        caller's own machinery, so whatever stops a loop (break, return, raise) is an ordinary path there. Two loops are the same function iff they are in one class and their
        arguments are equal; classes are matched by the solver on (cont, next), under any reordering of the carried variables."""
        c, S = self.ctx, self.S
        is_while = it is None
        ext = is_ref = False
        iter_arg = ety = None
        if not is_while:
            ity = it.t.ty
            if ity[0] == "ref" and st.dirty:
                it = Val(self.ctx.app("ref.obj", (it.t,), OPAQUE))
                ity = OPAQUE
            if ity[0] == "ref":
                # a typed external container, untouched so far: iterated as the value the caller passed, PROVIDED the body cannot touch the world (checked after the
                # summary; otherwise the loop is redone over the live, untyped object)
                is_ref, iter_arg, ety = True, self.ctx.app("deref0", (it.t,), ity[1]), elem_type(ity[1])
                if ety is None:
                    self.unknown("iteration over a non-iterable typed reference")
            elif ity == OPAQUE or ity == EXC or ity[0] == "func":
                ext, iter_arg, ety = True, self.opaque_arg(st, it, iter_node), OPAQUE
            else:
                iter_arg, ety = it.t, elem_type(ity)
                if ety is None:
                    self.unknown(f"iteration over {ty_str(ity)}")
                if ety == BOT:
                    return self._after_empty_loop(st, assigned, targets, orelse)
        carried = sorted(n for n in assigned if n in st.env and st.env[n] is not MAYBE)
        body_locals = [n for n in assigned if n not in carried]
        sym_tys = {n: st.env[n].t.ty for n in carried}
        dirty_in = st.dirty or ext
        for _round in range(14):
            # ---- summary execution on fresh symbols
            csyms = {n: c.fresh("c." + n, sym_tys[n]) for n in carried}
            esym = None if is_while else c.fresh("e", ety)
            wsym = c.fresh("w", WORLD)
            b = State()
            b.pc, b.w, b.assume, b.dirty = c.TRUE, wsym, {}, dirty_in
            b.env = dict(st.env)
            for n in carried:
                b.env[n] = Val(csyms[n], st.env[n].owned)
            for n in body_locals:
                b.env.pop(n, None)
            for n in targets:
                b.env.pop(n, None)
            nexts: list = []
            diverged = [False]
            outer = self.h
            self.collectors.append(nexts)
            self.bound_stack.append(set(csyms.values()) | ({esym} if esym is not None else set()) | {wsym})
            kill = lambda s, *a: None  # noqa: E731
            self.h = Handlers(kill, kill, kill, lambda s: nexts.append(s), lambda s: diverged.__setitem__(0, True))
            try:
                start = [b]
                if is_while:
                    tc = test(b)
                    b.pc = c.and_(b.pc, tc)
                    start = [b] if not self.dead(b) else []
                else:
                    bind(b, Val(esym))
                nexts.extend(body(start))
            finally:
                self.h = outer
                self.bound_stack.pop()
                self._drop_collector(nexts)
            merged = self.join(nexts)
            if len(merged) > 1:
                self.unknown("the loop body ends in states that cannot be merged")
            if merged and merged[0].dirty and not dirty_in:
                dirty_in = True  # the body changes the world: every iteration after the first starts in a changed world
                continue
            retry = False
            if not merged:
                cont, nxt_vals, next_w = c.FALSE, {n: csyms[n] for n in carried}, wsym
            else:
                m = merged[0]
                cont, next_w = m.pc, m.w
                nxt_vals = {}
                for n in carried:
                    v = m.env.get(n)
                    if v is None or v is MAYBE:
                        self.unknown(f"the loop may unbind {n}")
                    if v.t.ty != sym_tys[n]:
                        if _has_bot(sym_tys[n]) and not _has_bot(v.t.ty) and _bot_fits(sym_tys[n], v.t.ty):
                            sym_tys[n] = v.t.ty
                            retry = True
                            continue
                        self.unknown(f"the type of {n} changes across loop iterations")
                    if v.owned != st.env[n].owned:
                        if st.env[n].owned and not v.owned:
                            st.env[n] = Val(st.env[n].t, False)  # the body creates a second reference: treat the container as shared from before the loop
                            retry = True
                            continue
                        self.unknown(f"the loop changes who owns {n}")
                    nxt_vals[n] = v.t
                # safety net: nothing outside the carried set may change across an iteration
                for k, v0 in st.env.items():
                    if k in sym_tys or k in targets or k in body_locals or v0 is MAYBE:
                        continue
                    v1 = m.env.get(k)
                    if v1 is v0:
                        continue
                    if v1 is None or v1 is MAYBE or v1.t is not v0.t:
                        self.unknown(f"the loop changes {k} in a way its summary does not track")
                    if v0.owned and not v1.owned:
                        st.env[k] = Val(v0.t, False)
                        retry = True
            if retry:
                continue
            invariant = [n for n in carried if nxt_vals[n] is csyms[n]]
            if invariant:
                carried = [n for n in carried if n not in invariant]
                for n in invariant:
                    del sym_tys[n]
                continue
            break
        else:
            self.unknown("loop summary did not stabilise")
        inits = {}
        for n in carried:
            t0 = st.env[n].t
            if t0.ty != sym_tys[n]:
                t0 = self.model.coerce_bot(self, t0, sym_tys[n])
                if t0 is None:
                    self.unknown(f"the type of {n} changes across loop iterations")
            inits[n] = t0
        used = set()
        for t in [cont, next_w] + [nxt_vals[n] for n in carried]:
            used |= syms(t)
        body_used = set()
        for t in [cont] + [nxt_vals[n] for n in carried]:
            body_used |= syms(t)
        world_used = next_w is not wsym or wsym in body_used  # the body reads or changes the world
        if is_ref and (world_used or dirty_in):
            # the body can change the world while a caller-owned container is being iterated: redo the loop over the live object, with elements of unknown type
            return self.run_loop(st, Val(c.app("ref.obj", (it.t,), OPAQUE)), bind, body, assigned, targets, orelse, test, iter_node)
        threaded = ext or world_used
        may_div = is_while or diverged[0]
        outer_bound = set()
        for bs in self.bound_stack:
            outer_bound |= bs
        lifted = sorted((x for x in used if x in outer_bound), key=lambda x: x.uid)
        # ---- canonical body over formals
        sub = {}
        for i, n in enumerate(carried):
            sub[csyms[n]] = S.formal("c", i, sym_tys[n])
        if esym is not None:
            sub[esym] = S.formal("e", 0, ety)
        sub[wsym] = S.formal("w", 0, WORLD)
        for j, x in enumerate(lifted):
            sub[x] = S.formal("l", j, x.ty)
        memo: dict = {}
        f_cont, f_w = c.subst(cont, sub, memo), c.subst(next_w, sub, memo)
        f_next = [c.subst(nxt_vals[n], sub, memo) for n in carried]
        kid, corder, lorder = self.match_class(is_while, threaded, ext, may_div, ety, [sym_tys[n] for n in carried], [x.ty for x in lifted], f_cont, f_next, f_w)
        K = S.loops[kid]
        cnames = [carried[i] for i in corder]  # class formal position -> local name
        largs = [lifted[j] for j in lorder]
        args = tuple(([] if is_while else [iter_arg]) + [inits[n] for n in cnames] + largs + ([st.w] if threaded else []))
        LS = [c.app(f"LS#{kid}#{i}", args, K.carried_tys[i]) for i in range(len(cnames))]
        LW = c.app(f"LW#{kid}", args, WORLD) if threaded else st.w
        LE = c.app(f"LE#{kid}", args, ety) if not is_while else None
        LX = c.TRUE if is_while else c.app(f"LX#{kid}", args, BOOL)
        LT = c.app(f"LT#{kid}", args, BOOL) if may_div else c.TRUE
        LR = c.app(f"LR#{kid}", args, BOOL) if ext else c.FALSE
        # facts about this application (true whenever the loop terminates; when it does not, LT is false and nothing is claimed)
        inst = {S.formal("c", i, K.carried_tys[i]): LS[i] for i in range(len(cnames))}
        inst[S.formal("w", 0, WORLD)] = LW
        if LE is not None:
            inst[S.formal("e", 0, ety)] = LE
        for j, x in enumerate(largs):
            inst[S.formal("l", j, x.ty)] = x
        c.fact(c.implies(c.and_(LT, LX), c.not_(c.subst(K.cont, inst))))
        if not is_while and not ext:
            emp = self.model.is_empty(self, iter_arg)
            if emp is not None:
                same = [c.eq(LS[i], inits[n]) for i, n in enumerate(cnames)] + ([c.eq(LW, st.w)] if threaded else [])
                c.fact(c.implies(emp, c.and_(LT, c.not_(LX), *same)))
        if may_div:
            d = st.clone()
            d.pc = c.and_(st.pc, c.not_(LT))
            if not self.dead(d):
                self.h.div(d)

        # ---- states after the loop
        def after(*conds):
            s = st.clone()
            s.pc, s.w, s.dirty = c.and_(st.pc, LT, *conds), LW, dirty_in
            for i, n in enumerate(cnames):
                s.env[n] = Val(LS[i], st.env[n].owned)
            return s

        out: list = []
        normal: list = []
        if not is_while:
            done = after(c.not_(LX), c.not_(LR))
            for n in targets:
                done.env[n] = MAYBE
            normal.append(done)
            if ext:
                r = after(c.not_(LX), LR)
                self.do_raise(r, c.app(f"LRE#{kid}", args, EXC))
        if is_while or K.cont is not c.TRUE:
            x = after(LX)
            breaks: list = []
            outer = self.h
            self.collectors.append(breaks)
            self.h = Handlers(outer.ret, outer.rais, lambda s: breaks.append(s), lambda s: None, outer.div)
            try:
                start = [x]
                if is_while:
                    tc = test(x)
                    xa, xb = self.split(x, tc)
                    normal.append(xb)
                    start = [xa]
                else:
                    bind(x, Val(LE))
                body([s for s in start if not self.dead(s)])  # a state that falls through is infeasible: this iteration does not continue (the fact above)
            finally:
                self.h = outer
                self._drop_collector(breaks)
            out.extend(breaks)
        normal = [s for s in normal if not self.dead(s)]
        if orelse is not None and normal:
            normal = orelse(normal)
        out.extend(normal)
        return self.join(out)

    def _after_empty_loop(self, st, assigned, targets, orelse):
        s = st.clone()
        for n in targets:
            s.env[n] = MAYBE
        return orelse([s]) if orelse is not None else [s]

    def match_class(self, is_while, threaded, ext, may_div, ety, ctys, ltys, f_cont, f_next, f_w):
        """Find a loop class whose (continue, next) body is equivalent to this one under some reordering of the carried variables and lifted symbols; else register a new one.
        Returns (class id, carried order, lifted order): position i of the class corresponds to this loop's carried index order[i]."""
        c, S = self.ctx, self.S
        n, m = len(ctys), len(ltys)
        for K in S.loops:
            if (K.is_while, K.threaded, K.ext, K.may_div, K.elem_ty) != (is_while, threaded, ext, may_div, ety) or sorted(map(repr, K.carried_tys)) != sorted(map(repr, ctys)) or \
                    sorted(map(repr, K.lifted_tys)) != sorted(map(repr, ltys)):
                continue
            tried = 0
            for cperm in itertools.permutations(range(n)):
                if any(K.carried_tys[i] != ctys[cperm[i]] for i in range(n)):
                    continue
                for lperm in itertools.permutations(range(m)):
                    if any(K.lifted_tys[j] != ltys[lperm[j]] for j in range(m)):
                        continue
                    tried += 1
                    if tried > 48:
                        break
                    # rename this loop's formals into the class's positions
                    ren = {}
                    for i in range(n):
                        ren[S.formal("c", cperm[i], ctys[cperm[i]])] = S.formal("c", i, K.carried_tys[i])
                    for j in range(m):
                        ren[S.formal("l", lperm[j], ltys[lperm[j]])] = S.formal("l", j, K.lifted_tys[j])
                    ren = {a: b for a, b in ren.items() if a is not b}
                    memo: dict = {}
                    # simultaneous renaming through temporaries (a permutation is not a sequence of independent substitutions)
                    tmp = {a: c.sym("%tmp" + a.args[0], a.ty) for a in ren}
                    back = {tmp[a]: b for a, b in ren.items()}
                    rn = lambda t: c.subst(c.subst(t, tmp), back)  # noqa: E731
                    a_cont, a_w = rn(f_cont), rn(f_w)
                    a_next = [rn(f_next[cperm[i]]) for i in range(n)]
                    if self._bodies_equal(a_cont, a_next, a_w, K):
                        return K.kid, list(cperm), list(lperm)
        K = LoopClass()
        K.kid, K.is_while, K.threaded, K.ext, K.may_div, K.elem_ty = len(S.loops), is_while, threaded, ext, may_div, ety
        K.carried_tys, K.lifted_tys, K.cont, K.nexts, K.next_w = list(ctys), list(ltys), f_cont, list(f_next), f_w
        S.loops.append(K)
        return K.kid, list(range(n)), list(range(m))

    def _bodies_equal(self, cont, nexts, w, K) -> bool:
        c = self.ctx
        if cont is K.cont and w is K.next_w and all(a is b for a, b in zip(nexts, K.nexts)):
            return True
        if self.S.solver.valid(c.eq(cont, K.cont)) is not True:
            return False
        same = c.and_(c.eq(w, K.next_w), *[c.eq(a, b) for a, b in zip(nexts, K.nexts)])
        return self.S.solver.valid(c.implies(cont, same)) is True

    # ================================================================================================================ expressions
    def ev(self, node, st: State, retain: bool = True) -> Val:
        m = getattr(self, "e_" + type(node).__name__, None)
        if m is None:
            self.unknown(f"expression not modelled: {type(node).__name__}")
        return m(node, st, retain)

    def truthy_of(self, node, st: State) -> Term:
        """Truth value of an expression in a boolean context (short-circuit structure kept)."""
        c = self.ctx
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return c.not_(self.truthy_of(node.operand, st))
        if isinstance(node, ast.BoolOp):
            is_and = isinstance(node.op, ast.And)
            acc = self.truthy_of(node.values[0], st)
            for nx in node.values[1:]:
                gate = acc if is_and else c.not_(acc)
                acc = self.guarded(st, gate, lambda s, nx=nx: self.truthy_of(nx, s), lambda s: c.FALSE if is_and else c.TRUE, BOOL)
            return acc
        return self.model.truthy(self, st, self.ev(node, st, retain=False))

    def guarded(self, st: State, cond: Term, f_then, f_else, _ty=None) -> Term:
        """Evaluate f_then under cond and f_else otherwise, both returning Terms of one type; merge the effects on the state."""
        c = self.ctx
        if cond is c.TRUE:
            return f_then(st)
        if cond is c.FALSE:
            return f_else(st)
        a, b = self.split(st, cond)
        ta, tb = f_then(a), f_else(b)
        self._merge_into(st, cond, a, b)
        if self.dead(a):
            return tb
        if self.dead(b):
            return ta
        return c.ite(cond, ta, tb)

    def _merge_into(self, st: State, cond: Term, a: State, b: State):
        c = self.ctx
        if self.dead(a) and self.dead(b):
            st.pc = c.FALSE
            return
        if self.dead(a):
            st.adopt(b)
            return
        if self.dead(b):
            st.adopt(a)
            return
        env = {}
        for k in set(a.env) | set(b.env):
            va, vb = a.env.get(k, MAYBE), b.env.get(k, MAYBE)
            if va is vb:
                env[k] = va
            elif va is MAYBE or vb is MAYBE:
                env[k] = MAYBE
            elif va.t.ty != vb.t.ty:
                self.unknown(f"{k} has different types on the two sides of a conditional expression")
            else:
                env[k] = Val(c.ite(cond, va.t, vb.t), va.owned and vb.owned)
        st.pc, st.env, st.w, st.dirty = c.or_(a.pc, b.pc), env, c.ite(cond, a.w, b.w), a.dirty or b.dirty

    def cond_val(self, st: State, cond: Term, f_then, f_else) -> Val:
        """Value-level conditional (IfExp, and/or): merged with ite when both sides have one type, else a case split of the enclosing statement."""
        c = self.ctx
        if cond is c.TRUE:
            return f_then(st)
        if cond is c.FALSE:
            return f_else(st)
        known = st.assume.get(cond.uid)
        if known is not None:
            return f_then(st) if known else f_else(st)
        a, b = self.split(st, cond)
        va, vb = f_then(a), f_else(b)
        if self.dead(a):
            self._merge_into(st, cond, a, b)
            return vb
        if self.dead(b):
            self._merge_into(st, cond, a, b)
            return va
        if va.t.ty != vb.t.ty:
            full = None
            if _has_bot(va.t.ty) and not _has_bot(vb.t.ty):
                r = self.model.coerce_bot(self, va.t, vb.t.ty)
                if r is not None:
                    va, full = Val(r, va.owned), True
            elif _has_bot(vb.t.ty) and not _has_bot(va.t.ty):
                r = self.model.coerce_bot(self, vb.t, va.t.ty)
                if r is not None:
                    vb, full = Val(r, vb.owned), True
            if not full:
                raise _Fork(cond)
        self._merge_into(st, cond, a, b)
        return Val(c.ite(cond, va.t, vb.t), va.owned and vb.owned)

    # ---- leaves
    def e_Constant(self, node, st, retain):
        v = node.value
        if v is Ellipsis or isinstance(v, complex):
            self.unknown("constant not modelled")
        return Val(self.ctx.const(v))

    def is_builtin_name(self, name: str) -> bool:
        return name not in self.scopes[-1]["locals"] and self.mod.is_builtin(name)

    def load_name(self, name: str, st: State, retain: bool = True, for_update: bool = False) -> Val:
        sc = self.scopes[-1]
        if name in sc["locals"]:
            v = st.env.get(name)
            if v is None or v is MAYBE:
                self.unknown(f"local {name} may be unbound when it is read")
            if v.owned and retain and not for_update:
                v = Val(v.t, False)
                st.env[name] = v  # a second reference may now exist: the container is frozen
            return v
        c = self.ctx
        mod = self.mod
        if name in mod.module_names:
            if name in mod.funcs:
                return Val(c.app("F:" + name, (), FUNC))
            if name in self.tainted:
                if name in mod.consts:
                    return Val(self.model.const_val(self, mod.consts[name]))
                self.unknown(f"the module-level name {name} is changed by this patch")
            if name in mod.consts:
                self.note("module constants are taken at their literal value (not rebound at runtime)")
                return Val(self.model.const_val(self, mod.consts[name]))
            if name in mod.imports:
                return Val(c.app("G:" + mod.imports[name], (), OPAQUE))
            if name in mod.multi_bound:
                self.unknown(f"the module-level name {name} is bound more than once")
            return Val(c.app("G:" + name, (), OPAQUE))
        if mod.is_builtin(name):
            return Val(c.app("B:" + name, (), FUNC))
        self.unknown(f"name {name} cannot be resolved")

    def e_Name(self, node, st, retain):
        return self.load_name(node.id, st, retain)

    def e_NamedExpr(self, node, st, retain):
        v = self.ev(node.value, st)
        if v.owned:
            v = Val(v.t, False)
        self.assign(node.target, v, st)
        return v

    # ---- operators
    def e_UnaryOp(self, node, st, retain):
        if isinstance(node.op, ast.Not):
            return Val(self.ctx.not_(self.truthy_of(node.operand, st)))
        lit = fold_literal(node)
        if lit is not _NOFOLD:
            return Val(self.model.const_val(self, lit))
        return self.model.unaryop(self, st, node.op, self.ev(node.operand, st, retain=False))

    def e_BinOp(self, node, st, retain):
        a = self.ev(node.left, st, retain=False)
        b = self.ev(node.right, st, retain=False)
        return self.model.binop(self, st, node.op, a, b)

    def e_BoolOp(self, node, st, retain):
        is_and = isinstance(node.op, ast.And)

        def rec(i, s):
            v = self.ev(node.values[i], s, retain)
            if i == len(node.values) - 1:
                return v
            tv = self.model.truthy(self, s, v)
            if is_and:
                return self.cond_val(s, tv, lambda s2: rec(i + 1, s2), lambda s2: v)
            return self.cond_val(s, tv, lambda s2: v, lambda s2: rec(i + 1, s2))

        return rec(0, st)

    def e_IfExp(self, node, st, retain):
        cond = self.truthy_of(node.test, st)
        return self.cond_val(st, cond, lambda s: self.ev(node.body, s, retain), lambda s: self.ev(node.orelse, s, retain))

    def e_Compare(self, node, st, retain):
        c = self.ctx
        left = self.ev(node.left, st, retain=False)
        if len(node.ops) == 1:
            right = self.ev(node.comparators[0], st, retain=False)
            return self.model.compare(self, st, node.ops[0], left, right, node.left, node.comparators[0])

        # a < b < c: evaluated left to right, stops at the first false link; the value is the last link evaluated
        def rec(i, s, lhs, lhs_node):
            rhs = self.ev(node.comparators[i], s, retain=False)
            v = self.model.compare(self, s, node.ops[i], lhs, rhs, lhs_node, node.comparators[i])
            if i == len(node.ops) - 1:
                return v
            tv = self.model.truthy(self, s, v)
            return self.cond_val(s, tv, lambda s2: rec(i + 1, s2, rhs, node.comparators[i]), lambda s2: v)

        return rec(0, st, left, node.left)

    # ---- containers and strings
    def e_Tuple(self, node, st, retain):
        return self.model.build_seq(self, st, "tuple", node.elts)

    def e_List(self, node, st, retain):
        return self.model.build_seq(self, st, "list", node.elts)

    def e_Set(self, node, st, retain):
        return self.model.build_seq(self, st, "set", node.elts)

    def e_Dict(self, node, st, retain):
        return self.model.build_dict(self, st, node)

    def e_JoinedStr(self, node, st, retain):
        return self.model.fstring(self, st, node)

    def e_Subscript(self, node, st, retain):
        base = self.ev(node.value, st, retain=False)
        idx = self.ev_index(node.slice, st)
        return self.model.subscript(self, st, base, idx)

    def ev_index(self, sl, st):
        """An index Val, or ('slice', lo, hi, step) with Val-or-None parts."""
        if isinstance(sl, ast.Slice):
            return ("slice", *[None if p is None else self.ev(p, st, retain=False) for p in (sl.lower, sl.upper, sl.step)])
        return self.ev(sl, st)

    def e_Attribute(self, node, st, retain):
        obj = self.ev(node.value, st, retain=False)
        return self.model.attribute(self, st, obj, node.attr, node.value)

    def e_Lambda(self, node, st, retain):
        if node.args.defaults or any(d is not None for d in node.args.kw_defaults):
            self.unknown("lambda with default arguments")
        return Val(self.closure(node, st))

    def closure(self, node, st: State) -> Term:
        """A function object created here: identified by its code (names of parameters kept: they are part of its call interface) and the VALUES of the locals it captures.
        Capturing by value is only right for locals that are never rebound afterwards, so a captured local must have exactly one binding site in the enclosing function."""
        sc = self.scopes[-1]
        inner_locals = local_names(node)
        self_name = node.name if isinstance(node, ast.FunctionDef) else None
        free = []
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id not in inner_locals and n.id in sc["locals"] and n.id not in free:
                if n.id == self_name:
                    if sc["stores"].get(self_name, 0) != 1:
                        self.unknown(f"a nested function references {self_name}, which is bound more than once")
                    continue
                free.append(n.id)
            elif isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal)):
                self.unknown("nested function uses yield/await/global/nonlocal")
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id not in inner_locals and n.id not in sc["locals"]:
                if n.id in self.tainted:
                    self.unknown(f"a nested function mentions {n.id}, which this change touches")
            elif isinstance(n, ast.Attribute) and n.attr in self.tainted:
                self.unknown(f"a nested function mentions {n.attr}, which this change touches")
        caps = []
        for nm in free:
            if sc["stores"].get(nm, 0) != 1:
                self.unknown(f"a nested function captures {nm}, which is bound more than once")
            v = self.load_name(nm, st)
            caps.append(self.opaque_arg(st, v, ast.Name(id=nm, ctx=ast.Load())) if (v.t.ty[0] == "ref" or not is_exact(v.t.ty) or _deep_mutable(v.t.ty)) else v.t)
        code = ast.dump(node, annotate_fields=False, include_attributes=False)
        import hashlib

        h = hashlib.sha256((code + "|" + ",".join(free)).encode()).hexdigest()[:16]
        return self.ctx.app("closure:" + h, tuple(caps), OPAQUE)

    # ---- comprehensions
    def e_ListComp(self, node, st, retain):
        return self.model.comprehension(self, st, node, "list")

    def e_SetComp(self, node, st, retain):
        return self.model.comprehension(self, st, node, "set")

    def e_DictComp(self, node, st, retain):
        return self.model.comprehension(self, st, node, "dict")

    def e_GeneratorExp(self, node, st, retain):
        self.unknown("a generator expression outside a modelled consumer")

    def comp_loops(self, st: State, generators, inner, carried_hidden: set):
        """Run the nested for/if clauses of a comprehension; `inner(state)` runs at the innermost level. Targets are local to the comprehension."""
        saved = {}
        tnames = set()
        for g in generators:
            if g.is_async:
                self.unknown("async comprehension")
            for n in ast.walk(g.target):
                if isinstance(n, ast.Name):
                    tnames.add(n.id)
        sc = self.scopes[-1]
        added = [n for n in tnames if n not in sc["locals"]]
        sc["locals"] |= set(added)
        for n in tnames:
            saved[n] = st.env.get(n)

        def level(i, s):
            g = generators[i]
            it = self.ev(g.iter, s, retain=False)
            if self.dead(s):
                return []

            def bind(b, ev):
                self.assign(g.target, ev, b)

            def body(states):
                out = []
                for b in states:
                    alive = [b]
                    for cnd in g.ifs:
                        nxt = []
                        for a in alive:
                            tv = self.truthy_of(cnd, a)
                            ya, na = self.split(a, tv)
                            if not self.dead(na):
                                self.h.cont(na)
                            if not self.dead(ya):
                                nxt.append(ya)
                        alive = nxt
                    for a in alive:
                        if i + 1 < len(generators):
                            out.extend(level(i + 1, a))
                        else:
                            r = inner(a)
                            if r is not None and not self.dead(r):
                                out.append(r)
                return out

            return self.run_loop(s, it, bind, body, set(carried_hidden), set(tnames), None, iter_node=g.iter)

        try:
            res = level(0, st)
        finally:
            for n in added:
                sc["locals"].discard(n)
        res = self.join(res)
        if len(res) > 1:
            self.unknown("a comprehension ends in states that cannot be merged")
        if not res:
            st.pc = self.ctx.FALSE
            return
        r = res[0]
        for n in tnames:
            if saved[n] is None:
                r.env.pop(n, None)
            else:
                r.env[n] = saved[n]
        st.adopt(r)

    # ---- calls
    def e_Call(self, node, st, retain):
        return self.model.call(self, st, node)

    def inline(self, st: State, name: str, fdef, argvals: list, kwvals: list, arg_nodes: list) -> Val:
        """Execute a module-level function of this side's module in place of the call."""
        c = self.ctx
        if len(self.call_stack) >= _MAX_DEPTH:
            self.unknown("call depth limit")
        if fdef.decorator_list:
            self.unknown(f"call of the decorated function {name}")
        for n in scope_nodes(fdef):
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                self.unknown(f"call of the generator / coroutine {name}")
        a = fdef.args
        if a.vararg or a.kwarg:
            self.unknown(f"call of {name}, which takes *args / **kwargs")
        pos = [p.arg for p in [*a.posonlyargs, *a.args]]
        kwonly = [p.arg for p in a.kwonlyargs]
        if len(argvals) > len(pos):
            self.unknown(f"call of {name} with too many positional arguments")
        bound: dict = {}
        lent: dict = {}
        for i, v in enumerate(argvals):
            bound[pos[i]] = v
            if isinstance(arg_nodes[i], ast.Name):
                lent[pos[i]] = arg_nodes[i].id
        nposonly = len(a.posonlyargs)
        for (k, v), kn in zip(kwvals, arg_nodes[len(argvals):]):
            if k is None or k in bound or (k not in pos[nposonly:] and k not in kwonly):
                self.unknown(f"call of {name} with a keyword it does not bind")
            bound[k] = v
            if isinstance(kn, ast.Name):
                lent[k] = kn.id
        ndef = len(a.defaults)
        for i, p in enumerate(pos):
            if p not in bound:
                j = i - (len(pos) - ndef)
                if j < 0:
                    self.unknown(f"call of {name} with a missing argument")
                bound[p] = self._default(a.defaults[j], name)
        for p, d in zip(kwonly, a.kw_defaults):
            if p not in bound:
                if d is None:
                    self.unknown(f"call of {name} with a missing keyword argument")
                bound[p] = self._default(d, name)
        callee = State()
        callee.pc, callee.w, callee.assume, callee.dirty = st.pc, st.w, st.assume, st.dirty
        callee.env = {}
        owners: dict = {}
        for p, v in bound.items():
            if v.t.ty[0] == "func":
                v = Val(self.func_value(v.t))
            src = lent.get(p)
            if src is not None and src in st.env and st.env[src] is not MAYBE and st.env[src].owned and st.env[src].t is v.t and src not in owners.values():
                callee.env[p] = Val(v.t, True)  # lent for the duration of the call: the callee may mutate it; written back on return
                owners[p] = src
            else:
                callee.env[p] = Val(v.t, False)
        for src in owners.values():
            st.env[src] = Val(st.env[src].t, False)
        rets: list = []
        outer = self.h
        self.collectors.append(rets)
        hid = self.hidden_name("ret")

        def on_ret(s, v):
            s.env[hid] = Val(v.t, v.owned)
            rets.append(s)

        def bad(s):
            raise AssertionError("break/continue outside a loop")

        self.h = Handlers(on_ret, outer.rais, bad, bad, outer.div)
        self.scopes.append(_scope(fdef))
        self.call_stack.append(name)
        saved_exc = self.exc_stack
        self.exc_stack = [None]
        try:
            for s in self.exec_block(strip_doc_body(fdef), [callee]):
                on_ret(s, Val(c.NONE))
        finally:
            self.h = outer
            self.scopes.pop()
            self.call_stack.pop()
            self.exc_stack = saved_exc
            self._drop_collector(rets)
        # back in the caller: keep only the return value and the lent containers
        back = []
        for s in rets:
            r = State()
            r.pc, r.w, r.assume, r.dirty = s.pc, s.w, st.assume, s.dirty
            r.env = dict(st.env)
            rv = s.env[hid]
            for p, src in owners.items():
                fin = s.env.get(p)
                if fin is None or fin is MAYBE or not is_mutable_builtin(fin.t.ty):
                    self.unknown(f"{name} rebinds the container it was lent")
                r.env[src] = Val(fin.t, fin.owned and fin.t is not rv.t)
                if fin.t is rv.t:
                    rv = Val(rv.t, False)  # the callee returned the container it was lent: one more reference to it
            r.env[hid] = rv
            back.append(r)
        merged = self.join(back)
        if not merged:
            st.pc = c.FALSE
            return Val(c.NONE)
        if len(merged) > 1:
            # return types differ by path: split the enclosing statement on which path was taken
            for mst in merged[:-1]:
                conj = list(mst.pc.args) if mst.pc.op == "and" else [mst.pc]
                base = {x.uid for x in (st.pc.args if st.pc.op == "and" else [st.pc])}
                sel = c.and_(*[x for x in conj if x.uid not in base])
                if self.decide(st, sel):
                    merged = [mst]
                    break
            else:
                merged = [merged[-1]]
        r = merged[0]
        rv = r.env.pop(hid)
        st.adopt(r)
        return rv

    def _default(self, d, fname) -> Val:
        lit = fold_literal(d)
        if lit is _NOFOLD:
            self.unknown(f"{fname} has a default argument that is not a literal")
        return Val(self.model.const_val(self, lit))

    # ================================================================================================================ entry
    def run(self, fdef, params: dict):
        """Execute `fdef` with its parameters bound to the given Vals; fills self.exits."""
        c = self.ctx
        for n in scope_nodes(fdef):
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                self.unknown("the target is a generator or coroutine")
        st = State()
        st.pc, st.w, st.assume, st.dirty = c.TRUE, self.S.w0, {}, False
        st.env = dict(params)

        def on_ret(s, v):
            t = v.t
            if t.ty[0] == "func":
                t = self.func_value(t)
            fresh = v.owned if is_mutable_builtin(t.ty) else True
            self.exits.append(Exit(s.pc, "ret", t, s.w, fresh))

        def on_raise(s, e):
            self.exits.append(Exit(s.pc, "raise", e, s.w))

        def bad(s):
            raise AssertionError("break/continue outside a loop")

        def on_div(s):
            if not self.dead(s):
                self.exits.append(Exit(s.pc, "diverge", c.NONE, s.w))

        self.h = Handlers(on_ret, on_raise, bad, bad, on_div)
        self.scopes.append(_scope(fdef))
        self.call_stack.append(self.target)
        self.exc_stack = [None]
        for s in self.exec_block(strip_doc_body(fdef), [st]):
            on_ret(s, Val(c.NONE))
        return self.exits


def strip_doc_body(fdef):
    body = fdef.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _scope(fdef) -> dict:
    stores: dict = {}
    a = fdef.args
    for p in [*a.posonlyargs, *a.args, *a.kwonlyargs] + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else []):
        stores[p.arg] = stores.get(p.arg, 0) + 1
    in_loop: set = set()
    body = fdef.body if isinstance(fdef.body, list) else [fdef.body]
    for n in scope_nodes(_Wrap(body)):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            stores[n.id] = stores.get(n.id, 0) + 1
        elif isinstance(n, ast.ExceptHandler) and n.name:
            stores[n.name] = stores.get(n.name, 0) + 2
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stores[n.name] = stores.get(n.name, 0) + 1
        elif isinstance(n, (ast.For, ast.While, ast.AsyncFor)):
            for m in ast.walk(n):
                if isinstance(m, ast.Name) and isinstance(m.ctx, (ast.Store, ast.Del)):
                    in_loop.add(m.id)
    for nm in in_loop:
        stores[nm] = stores.get(nm, 0) + 2  # rebound on every iteration
    return {"locals": local_names(fdef), "stores": stores, "fn": fdef}


def _has_bot(ty) -> bool:
    return ty == BOT or any(_has_bot(x) for x in ty[1:] if isinstance(x, tuple))


def _bot_fits(a, b) -> bool:
    """Type a (with bottoms) can be instantiated to type b."""
    if a == BOT:
        return True
    if a[0] != b[0] or len(a) != len(b):
        return False
    return all(_bot_fits(x, y) for x, y in zip(a[1:], b[1:]))


def _deref_ty(ty):
    return ty[1] if ty[0] == "ref" else ty


def _deep_mutable(ty) -> bool:
    """The type has a locally modelled mutable container somewhere inside (a reference or an opaque object is not one)."""
    if ty[0] in ("list", "dict", "set"):
        return True
    if ty[0] in ("ref", "opaque", "exc", "func", "world"):
        return False
    return any(_deep_mutable(x) for x in ty[1:] if isinstance(x, tuple))
