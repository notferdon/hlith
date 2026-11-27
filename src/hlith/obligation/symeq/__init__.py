# SPDX-License-Identifier: Apache-2.0
"""Symbolic equivalence prover: does a changed function behave exactly as it did, for EVERY input of a stated domain?

`prove(base_src, post_src, "f")` executes both versions symbolically (executor.py) into guarded exits over typed terms, and asks Z3 whether, wherever a pre exit and a post exit can
both be taken, they are the same kind of exit with the same value / exception and the same world. The answer is one of

    proved      every pair of exits agrees, and both exit sets are exhaustive: the two versions are behaviourally equal on the domain (see `domain` and `notes`)
    different   the solver found a valuation under which the modelled exits differ; `hint` carries candidate int/bool inputs. This is NOT a verdict (opaque values have no concrete
                witness): the concrete differential decides, the hint only seeds it
    unknown     a construct is not modelled, or the solver did not decide: the caller refuses

Two domains are tried, strongest claim first:
    any       every parameter is an unknown object: no assumption about the callers at all (the claim holds for any argument)
    typed     parameters annotated with an exact builtin type are assumed to BE that exact type (stated in the result; the concrete differential enforces it on its inputs)

What is assumed and never checked here (reported in `notes` / the certificate text): the pinned CPython builtins behave as modelled; code the change does not touch behaves the same
before and after when called with equal arguments in an equal world; module-level names are bound as in the source; resource exhaustion and stack depth are not behaviour."""

from __future__ import annotations

import ast
import itertools
import math
import time
from dataclasses import dataclass, field

from .executor import Exec, Session, Unknown, Val, _deep_mutable
from .model import Model
from .module import ModuleInfo, changed_identifiers, idents, taint_closure
from .solver import Solver
from .terms import (BOOL, BYTES, DICT, FLOAT, FROZENSET, FTUPLE, INT, LIST, NONE, OPAQUE, REF, SET, STR, TUPLE, Ctx, TermLimit, float_free, hashable, is_immutable, is_mutable_builtin,
                    ty_str)

VERSION = "symeq/1"


@dataclass
class Result:
    status: str  # "proved" | "different" | "unknown"
    reason: str = ""
    domain: tuple = ()  # ((parameter, exact type), ...) assumed; () = holds for any argument
    mode: str = ""  # "any" | "typed"
    notes: tuple = ()
    hint: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "proved"


# ---------------------------------------------------------------------------------------------------------------------- annotations
_SCALAR_ANN = {"int": INT, "str": STR, "bool": BOOL, "float": FLOAT, "bytes": BYTES}


_PEP585_GENERICS = frozenset({"list", "set", "frozenset", "dict", "tuple"})
_TYPING_GENERICS = frozenset({"Optional", "Union", "List", "Set", "FrozenSet", "Dict", "Tuple"})


def _ann_alternatives(node, mod: ModuleInfo | None = None, depth=0):
    """Exact builtin types an annotation denotes (a list: unions and Optional give several), or None when it is not an exact builtin type."""
    if node is None or depth > 4:
        return None
    if isinstance(node, ast.Constant):
        if node.value is None:
            return [NONE]
        if isinstance(node.value, str):
            try:
                return _ann_alternatives(ast.parse(node.value, mode="eval").body, mod, depth + 1)
            except SyntaxError:
                return None
        return None
    if isinstance(node, ast.Name):
        if node.id in _SCALAR_ANN:
            if mod is not None and not mod.is_builtin(node.id):
                return None
            return [_SCALAR_ANN[node.id]]
        if node.id == "None":
            return [NONE]
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        a, b = _ann_alternatives(node.left, mod, depth + 1), _ann_alternatives(node.right, mod, depth + 1)
        return None if a is None or b is None else a + [x for x in b if x not in a]
    if isinstance(node, ast.Subscript):
        head = node.value
        hn = None
        if isinstance(head, ast.Name):
            if head.id in _PEP585_GENERICS:
                if mod is None or mod.is_builtin(head.id):
                    hn = head.id
            elif head.id in _TYPING_GENERICS:
                if mod is None or mod.imports.get(head.id) == f"typing.{head.id}":
                    hn = head.id
        elif isinstance(head, ast.Attribute) and isinstance(head.value, ast.Name):
            if head.attr in _TYPING_GENERICS and (mod is None or mod.imports.get(head.value.id) == "typing"):
                hn = head.attr
        if hn is None:
            return None
        args = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        if hn == "Optional" and len(args) == 1:
            a = _ann_alternatives(args[0], mod, depth + 1)
            return None if a is None else a + ([NONE] if NONE not in a else [])
        if hn == "Union":
            out = []
            for x in args:
                a = _ann_alternatives(x, mod, depth + 1)
                if a is None:
                    return None
                out += [y for y in a if y not in out]
            return out

        def one(x):
            a = _ann_alternatives(x, mod, depth + 1)
            return a[0] if a is not None and len(a) == 1 and is_immutable(a[0]) else None

        if hn in ("list", "List") and len(args) == 1:
            e = one(args[0])
            return None if e is None else [LIST(e)]
        if hn in ("set", "Set") and len(args) == 1:
            e = one(args[0])
            return None if e is None or not (hashable(e) and float_free(e)) else [SET(e)]
        if hn in ("frozenset", "FrozenSet") and len(args) == 1:
            e = one(args[0])
            return None if e is None or not (hashable(e) and float_free(e)) else [FROZENSET(e)]
        if hn in ("dict", "Dict") and len(args) == 2:
            k, v = one(args[0]), one(args[1])
            return None if k is None or v is None or not (hashable(k) and float_free(k)) else [DICT(k, v)]
        if hn in ("tuple", "Tuple"):
            if len(args) == 2 and isinstance(args[1], ast.Constant) and args[1].value is Ellipsis:
                e = one(args[0])
                return None if e is None else [TUPLE(e)]
            es = [one(x) for x in args]
            return None if any(e is None for e in es) else [FTUPLE(*es)]
    return None


def _expanded(alts: list) -> list:
    """The values an annotation admits in practice: a bool is an int (so `int` covers both), and an int is accepted where a float is expected (PEP 484)."""
    out = list(alts)
    if INT in alts and BOOL not in out:
        out.append(BOOL)
    if FLOAT in alts and INT not in out:
        out.append(INT)
    return out


def _params(fn):
    a = fn.args
    return [p for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]]


def _sig_shape(fn):
    a = fn.args
    d = lambda x: None if x is None else ast.dump(x, annotate_fields=False, include_attributes=False)  # noqa: E731
    return ([p.arg for p in a.posonlyargs], [p.arg for p in a.args], [p.arg for p in a.kwonlyargs], a.vararg.arg if a.vararg else None, a.kwarg.arg if a.kwarg else None,
            [d(x) for x in a.defaults], [d(x) for x in a.kw_defaults])


_OK_DECORATORS = frozenset({"staticmethod", "classmethod"})


def _decorators(fn):
    out = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Name) and d.id in _OK_DECORATORS:
            out.append(d.id)
        else:
            return None
    return out


# ---------------------------------------------------------------------------------------------------------------------- taint
def module_taint(mb: ModuleInfo, mp: ModuleInfo, function: str, extra=()) -> set:
    """Identifiers the proof may not treat as 'the same code before and after': changed bindings of this module (plus `extra` from the rest of the tree), closed under mention.
    The target's own change does not taint the class that owns it through the target itself (other members that mention the target still do)."""
    seed = changed_identifiers(_without_target(mb, function), _without_target(mp, function)) | set(extra)
    leaf = function.split(".")[-1]
    seed.add(leaf)
    trees = [_without_target(mb, function), _without_target(mp, function)]
    return taint_closure(trees, seed)


def _without_target(m: ModuleInfo, function: str):
    """The module tree with the target function's body removed (its name stays bound)."""
    fn, cls = m.find(function)
    if fn is None:
        return m.tree
    import copy

    tree = copy.deepcopy(m.tree)
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == fn.name and n.lineno == fn.lineno:
            n.body = [ast.Pass()]
            n.decorator_list = []
            for a in [*n.args.posonlyargs, *n.args.args, *n.args.kwonlyargs]:
                a.annotation = None
            n.returns = None
            n.args.defaults = []
            n.args.kw_defaults = [None for _ in n.args.kw_defaults]
    return tree


# ---------------------------------------------------------------------------------------------------------------------- one attempt
def _attempt(mb, mp, fb, fp, function, tainted, ptypes: dict, budget_ms: int) -> Result:
    ctx = Ctx()
    model = Model()
    model.install(ctx)
    solver = Solver(ctx, total_ms=budget_ms)
    S = Session(ctx, solver)
    params = {}
    for p in _params(fb):
        ty = ptypes.get(p.arg, OPAQUE)
        sym_ty = REF(ty) if is_mutable_builtin(ty) else ty
        t = ctx.NONE if ty == NONE else ctx.sym("p:" + p.arg, sym_ty)
        params[p.arg] = Val(t)
    a = fb.args
    if a.vararg:
        params[a.vararg.arg] = Val(ctx.sym("p:*" + a.vararg.arg, TUPLE(OPAQUE)))
    if a.kwarg:
        params[a.kwarg.arg] = Val(ctx.sym("p:**" + a.kwarg.arg, DICT(STR, OPAQUE)), True)
    try:
        eb = Exec(S, mb, tainted, "base", function, model)
        xb = eb.run(fb, dict(params))
        ep = Exec(S, mp, tainted, "post", function, model)
        xp = ep.run(fp, dict(params))
    except Unknown as e:
        return Result("unknown", str(e))
    except TermLimit:
        return Result("unknown", "the analysis grew beyond its size limit")
    except RecursionError:
        return Result("unknown", "the analysis exceeded its depth limit")
    stats = {"exits_base": len(xb), "exits_post": len(xp), "loops": len(S.loops), "terms": ctx.n}
    notes = tuple(sorted(S.notes))
    c = ctx
    # exhaustiveness of each side (a self-check of the executor: a dropped path must never turn into a vacuous proof)
    for side, xs in (("base", xb), ("post", xp)):
        r = solver.valid(c.or_(*[x.guard for x in xs]))
        if r is not True:
            return Result("unknown", f"the {side} execution paths could not be shown exhaustive", notes=notes, stats=stats)
    for i, x in enumerate(xb):
        goals = []
        for y in xp:
            both = c.and_(x.guard, y.guard)
            if both is c.FALSE:
                continue
            goals.append(c.implies(y.guard, _leaf_eq(c, x, y)))
        r = solver.valid(c.implies(x.guard, c.and_(*goals)))
        if r is True:
            continue
        stats["queries"] = solver.queries
        if r is None:
            return Result("unknown", "the solver did not decide whether two execution paths agree", notes=notes, stats=stats)
        hint = {}
        for name, v in params.items():
            mv = solver.model_value(v.t)
            if mv is not None:
                hint[name] = mv
        return Result("different", f"a {x.kind} path of the base version is not matched by the post version", notes=notes, hint=hint, stats=stats)
    stats["queries"] = solver.queries
    stats["used_world"] = any(x.w is not S.w0 for x in xb) or any(x.w is not S.w0 for x in xp)
    if any(_returns_object_graph(x) for x in (*xb, *xp)):
        return Result("unknown", "a mutable container nested in the return value: which slots share one object is not modelled", notes=notes, stats=stats)
    return Result("proved", notes=notes, stats=stats)


def _returns_object_graph(x) -> bool:
    """Terms are values (interned by structure): they cannot say whether two slots of a returned structure hold ONE mutable object. A return whose mutable
    containers sit INSIDE another value (a list of lists, a tuple or dict holding a list) therefore never counts as proved equal."""
    if x.kind != "ret" or not _deep_mutable(x.val.ty):
        return False
    return not is_mutable_builtin(x.val.ty) or any(_deep_mutable(e) for e in x.val.ty[1:] if isinstance(e, tuple))


def _leaf_eq(c, x, y):
    if x.kind != y.kind or x.val.ty != y.val.ty:
        return c.FALSE
    w = c.eq(x.w, y.w)
    if x.kind == "diverge":
        return w
    ty = x.val.ty
    if x.kind == "ret" and _deep_mutable(ty):
        if not _returns_object_graph(x) and x.fresh and y.fresh:
            return c.and_(w, c.eq(x.val, y.val))  # two new containers with equal contents are indistinguishable
        return w if x.val is y.val and x.fresh == y.fresh else c.FALSE
    return c.and_(w, c.eq(x.val, y.val))


# ---------------------------------------------------------------------------------------------------------------------- public
def prove(base_src: str, post_src: str, function: str, *, tainted_extra=(), modes=("any", "typed"), budget_ms: int = 30000, allowed_typed_params=None) -> Result:
    try:
        mb, mp = ModuleInfo(base_src), ModuleInfo(post_src)
    except (SyntaxError, ValueError, RecursionError) as e:
        return Result("unknown", f"source does not parse: {type(e).__name__}")
    fb, cb = mb.find(function)
    fp, cp = mp.find(function)
    if fb is None or fp is None:
        return Result("unknown", "the target is not a module-level function or a method of a module-level class in both versions")
    if _sig_shape(fb) != _sig_shape(fp):
        return Result("unknown", "the signature (parameter names, kinds or defaults) differs")
    db, dp = _decorators(fb), _decorators(fp)
    if db is None or dp is None or db != dp:
        return Result("unknown", "the target is decorated (only staticmethod / classmethod are modelled) or its decorators changed")
    for fn in (fb, fp):
        for d in [*fn.args.defaults, *[x for x in fn.args.kw_defaults if x is not None]]:
            if not isinstance(d, (ast.Constant, ast.UnaryOp, ast.Tuple, ast.Name)):
                return Result("unknown", "a default argument is not a literal")
    try:
        tainted = module_taint(mb, mp, function, tainted_extra)
    except RecursionError:
        return Result("unknown", "the analysis exceeded its depth limit")
    # typed domain: parameters annotated with the SAME exact builtin type(s) in both versions
    alts: dict = {}
    for pb, pp in zip(_params(fb), _params(fp)):
        if allowed_typed_params is not None and pb.arg not in allowed_typed_params:
            continue
        ab, ap = _ann_alternatives(pb.annotation, mb), _ann_alternatives(pp.annotation, mp)
        if ab is not None and ab == ap and len(ab) <= 3:
            alts[pb.arg] = ab
    last = None
    deadline = time.monotonic() + budget_ms / 1000
    def remaining_ms():
        return max(0, int(1000 * (deadline - time.monotonic())))

    for mode in modes:
        if mode == "any":
            r = _attempt(mb, mp, fb, fp, function, tainted, {}, remaining_ms())
            r.mode = "any"
            if r.ok:
                return r
            last = r
            continue
        if not alts:
            continue
        names = sorted(alts)
        used = {n: _expanded(alts[n]) for n in names}
        if math.prod(len(used[n]) for n in names) > 24:
            used = dict(alts)  # too many cases with bool-as-int / int-as-float: claim the exact annotated types only (stated in the domain)
        if math.prod(len(used[n]) for n in names) > 24:
            last = Result("unknown", "too many combinations of union-typed parameters", mode="typed")
            continue
        notes: set = set()
        stats: dict = {}
        res = None
        for combo in itertools.product(*(used[n] for n in names)):
            if remaining_ms() == 0:
                return Result("unknown", "symbolic proof time budget exhausted", mode=mode)
            res = _attempt(mb, mp, fb, fp, function, tainted, dict(zip(names, combo)), remaining_ms())
            notes |= set(res.notes)
            for k, v in res.stats.items():
                if isinstance(v, bool):
                    stats[k] = stats.get(k, False) or v
                elif isinstance(v, int):
                    stats[k] = stats.get(k, 0) + v
                else:
                    stats[k] = v
            if not res.ok:
                break
        res.mode = "typed"
        res.notes, res.stats = tuple(sorted(notes)), stats
        res.domain = tuple((n, " | ".join(ty_str(t) for t in used[n])) for n in names)
        if res.ok:
            return res
        # prefer reporting a concrete difference over an unknown
        if last is None or res.status == "different" or last.status != "different":
            last = res
    return last if last is not None else Result("unknown", "no proof mode applies")
