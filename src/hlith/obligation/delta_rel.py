# SPDX-License-Identifier: Apache-2.0
"""Z3 delta-relational check (F4): does a changed function differ from its pre-change self ONLY where an
approved delta says it does, and exactly as the delta says?

For the decidable fragment of a top-level function (int / bool / str parameters with constant defaults,
constants, ``+ - *``, ``// %`` by a positive constant, ``<< >>`` by a small constant, comparisons, boolean ops,
``len`` / ``min`` / ``max`` / ``abs``, string slices and concatenation, ``a if c else b``, ``if/elif/else``,
early ``return``, ``raise``) the pre and post bodies are encoded as guarded outcomes and, per approved delta
``(P, E)``:

    VC1:  P(x)       =>  Post(x) = E(x)
    VC2:  not any P  =>  Post(x) = Pre(x)

SAT gives an exact counterexample, replayed concretely before it is reported; UNSAT is a proof over the
unbounded domain; anything outside the fragment is UNMODELED with the reason, never relaxed and never a pass.

The checker consumes source text of the two versions only. It runs no target code: concrete replay evaluates
only AST nodes the encoder already accepted, with a namespace holding len/min/max/abs and the call arguments.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import z3

from .source import ast_source_segment

PROVED, COUNTEREXAMPLE, UNMODELED = "PROVED", "COUNTEREXAMPLE", "UNMODELED"
_SOLVER_MS = 8000
_RL_PER_MS = 1000  # Z3 resource units per budget millisecond (calibrated on the pinned 5.3.2 in drive_inputs._RL_PER_MS)


def _budget(solver: "z3.Solver", ms: int = _SOLVER_MS) -> None:
    """Bound a solver by deterministic work (rlimit), never by wall time: the same query is cut at the same point on an
    idle and on a loaded machine. The wall timeout is only a last-resort net 200x longer."""
    solver.set("rlimit", ms * _RL_PER_MS)
    solver.set("timeout", ms * 200)
_MAX_SHIFT = 4096


class Unmodeled(Exception):
    """A construct outside the decidable fragment."""


@dataclass
class DeltaRelResult:
    verdict: str
    reason: str
    witness_inputs: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    # proof tier (only meaningful for PROVED): "unconditional" = the numeric fragment, a Z3 proof over the whole
    # annotated domain with no unverified premise about other code; "conditional" = UF mode, valid only under the
    # listed ``assumptions``; "none" = COUNTEREXAMPLE / UNMODELED (nothing is proved).
    tier: str = "none"
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason, "witness_inputs": self.witness_inputs,
                "provenance": self.provenance, "proof_tier": self.tier, "assumptions": list(self.assumptions)}


# ------------------------------------------------------------------ strings: (length, content array)
@dataclass(frozen=True)
class _S:
    """A Python str as a length and a content array Int -> code point (positions >= length are unconstrained).

    Only len, slice, concatenation and equality are modelled, so behaviour is independent of the alphabet."""
    n: Any
    f: Any


_CHAR_MAX = 0x10FFFF  # the full Python str domain: every code point, lone surrogates included
_PRINT_LO, _PRINT_HI = 33, 126  # only a PREFERENCE when materialising a witness; never a restriction of the proof


def _s_const(v: str) -> _S:
    f = z3.K(z3.IntSort(), z3.IntVal(0))
    for i, ch in enumerate(v):
        f = z3.Store(f, i, ord(ch))
    return _S(z3.IntVal(len(v)), f)


def _s_slice(s_: _S, lo: Any, hi: Any) -> _S:
    i = z3.Int("i_slice")
    return _S(z3.If(hi > lo, hi - lo, z3.IntVal(0)), z3.Lambda([i], z3.Select(s_.f, lo + i)))


def _s_concat(a: _S, b: _S) -> _S:
    i = z3.Int("i_cat")
    return _S(a.n + b.n, z3.Lambda([i], z3.If(i < a.n, z3.Select(a.f, i), z3.Select(b.f, i - a.n))))


def _s_if(c: Any, a: _S, b: _S) -> _S:
    i = z3.Int("i_if")
    return _S(z3.If(c, a.n, b.n), z3.Lambda([i], z3.If(c, z3.Select(a.f, i), z3.Select(b.f, i))))


def _s_eq(a: _S, b: _S) -> Any:
    """String equality. Logically the same formula either way; with concrete lengths it is spelled out position
    by position so a closed evaluation reduces without a quantifier."""
    na, nb = z3.simplify(a.n), z3.simplify(b.n)
    if z3.is_int_value(na) and z3.is_int_value(nb):
        if na.as_long() != nb.as_long():
            return z3.BoolVal(False)
        if na.as_long() <= 8192:
            return z3.And(z3.BoolVal(True), *[z3.Select(a.f, i) == z3.Select(b.f, i) for i in range(na.as_long())])
    i = z3.Int("i_eq")
    return z3.And(a.n == b.n, z3.ForAll([i], z3.Implies(z3.And(i >= 0, i < a.n), z3.Select(a.f, i) == z3.Select(b.f, i))))


# ------------------------------------------------------------------ expressions
def _sort(e: Any) -> str:
    if isinstance(e, _S):
        return "str"
    if z3.is_bool(e):
        return "bool"
    if z3.is_int(e):
        return "int"
    raise Unmodeled(f"value of unsupported sort {e.sort()}")


def _const_int(node: ast.AST, env: dict) -> int | None:
    """Python int value of a folded constant expression, else None."""
    try:
        e = _enc(node, env)
    except Unmodeled:
        return None
    e = z3.simplify(e)
    return e.as_long() if z3.is_int_value(e) else None


def _enc(node: ast.AST, env: dict) -> Any:
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bool):
            return z3.BoolVal(v)
        if isinstance(v, int):
            return z3.IntVal(v)
        if isinstance(v, str):
            return _s_const(v)
        raise Unmodeled(f"unsupported constant {v!r}")
    if isinstance(node, ast.Name):
        if node.id in env["params"]:
            return env["params"][node.id]
        if node.id in env["consts"]:
            if "used" in env:
                env["used"].add(node.id)
            return _enc(ast.Constant(env["consts"][node.id]), env)
        raise Unmodeled(f"unresolved name {node.id!r}")
    if isinstance(node, ast.UnaryOp):
        v = _enc(node.operand, env)
        if isinstance(node.op, ast.USub) and _sort(v) == "int":
            return -v
        if isinstance(node.op, ast.UAdd) and _sort(v) == "int":
            return v
        if isinstance(node.op, ast.Not) and _sort(v) == "bool":
            return z3.Not(v)
        raise Unmodeled(f"unsupported unary `{ast.unparse(node)}`")
    if isinstance(node, ast.BoolOp):
        vals = [_enc(v, env) for v in node.values]
        if all(_sort(v) == "bool" for v in vals):
            return z3.And(*vals) if isinstance(node.op, ast.And) else z3.Or(*vals)
        raise Unmodeled(f"and/or over non-bool operands `{ast.unparse(node)}`")
    if isinstance(node, ast.BinOp):
        return _binop(node, env)
    if isinstance(node, ast.Compare):
        parts, left = [], _enc(node.left, env)
        for op, comp in zip(node.ops, node.comparators):
            right = _enc(comp, env)
            sl, sr = _sort(left), _sort(right)
            if sl != sr:
                raise Unmodeled(f"comparison across sorts {sl}/{sr} `{ast.unparse(node)}`")
            if isinstance(op, (ast.Eq, ast.NotEq)):
                eq = _s_eq(left, right) if sl == "str" else (left == right)
                parts.append(eq if isinstance(op, ast.Eq) else z3.Not(eq))
            elif sl == "int" and isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                parts.append({ast.Lt: left < right, ast.LtE: left <= right,
                              ast.Gt: left > right, ast.GtE: left >= right}[type(op)])
            else:
                raise Unmodeled(f"unsupported comparison `{ast.unparse(node)}`")
            left = right
        return parts[0] if len(parts) == 1 else z3.And(*parts)
    if isinstance(node, ast.Call):
        if node.keywords or not isinstance(node.func, ast.Name) or node.func.id not in ("len", "min", "max", "abs"):
            raise Unmodeled(f"call outside len/min/max/abs `{ast.unparse(node)}`")
        args = [_enc(a, env) for a in node.args]
        f = node.func.id
        if f == "len" and len(args) == 1 and _sort(args[0]) == "str":
            return args[0].n
        if f == "abs" and len(args) == 1 and _sort(args[0]) == "int":
            return z3.If(args[0] >= 0, args[0], -args[0])
        if f in ("min", "max") and len(args) >= 2 and all(_sort(a) == "int" for a in args):
            out = args[0]
            for a in args[1:]:
                out = z3.If(a < out, a, out) if f == "min" else z3.If(a > out, a, out)
            return out
        raise Unmodeled(f"unsupported call arguments `{ast.unparse(node)}`")
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and node.slice.step is None:
        s_ = _enc(node.value, env)
        if _sort(s_) != "str":
            raise Unmodeled(f"slice of non-str `{ast.unparse(node)}`")
        n = s_.n

        def norm(i: Any) -> Any:  # Python slice index clamping, negative and out-of-range included
            return z3.If(i < 0, z3.If(i + n < 0, z3.IntVal(0), i + n), z3.If(i > n, n, i))

        bounds = []
        for b_ in (node.slice.lower, node.slice.upper):
            if b_ is not None:
                v = _enc(b_, env)
                if _sort(v) != "int":
                    raise Unmodeled(f"non-int slice bound `{ast.unparse(node)}`")
                bounds.append(norm(v))
            else:
                bounds.append(None)
        lo = bounds[0] if bounds[0] is not None else z3.IntVal(0)
        hi = bounds[1] if bounds[1] is not None else n
        return _s_slice(s_, lo, hi)
    if isinstance(node, ast.IfExp):
        c, a, b = _enc(node.test, env), _enc(node.body, env), _enc(node.orelse, env)
        if _sort(c) != "bool" or _sort(a) != _sort(b):
            raise Unmodeled(f"conditional expression sorts differ `{ast.unparse(node)}`")
        return _s_if(c, a, b) if _sort(a) == "str" else z3.If(c, a, b)
    raise Unmodeled(f"unmodeled construct `{ast.unparse(node)}`")


def _binop(node: ast.BinOp, env: dict) -> Any:
    l, r = _enc(node.left, env), _enc(node.right, env)
    sl, sr = _sort(l), _sort(r)
    op = node.op
    if sl == sr == "int":
        if isinstance(op, ast.Add):
            return l + r
        if isinstance(op, ast.Sub):
            return l - r
        if isinstance(op, ast.Mult):
            return l * r
        k = _const_int(node.right, env)
        if isinstance(op, (ast.FloorDiv, ast.Mod)) and k is not None and k > 0:
            return l / z3.IntVal(k) if isinstance(op, ast.FloorDiv) else l % z3.IntVal(k)
        if isinstance(op, (ast.RShift, ast.LShift)) and k is not None and 0 <= k <= _MAX_SHIFT:
            p = z3.IntVal(1 << k)
            return l / p if isinstance(op, ast.RShift) else l * p
    if sl == sr == "str" and isinstance(op, ast.Add):
        return _s_concat(l, r)
    raise Unmodeled(f"unsupported arithmetic `{ast.unparse(node)}`")


# ------------------------------------------------------------------ statements -> guarded outcomes
Outcome = tuple  # ("ret", z3 expr) | ("raise", source text)


def _block(stmts: list[ast.stmt], env: dict, cond: Any) -> tuple[list[tuple[Any, Outcome]], Any]:
    outs: list[tuple[Any, Outcome]] = []
    cur = cond
    for i, st in enumerate(stmts):
        if isinstance(st, ast.Pass) or (i == 0 and isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)
                                        and isinstance(st.value.value, str)):
            continue
        if isinstance(st, ast.Return):
            o = ("none", None) if st.value is None or (
                isinstance(st.value, ast.Constant) and st.value.value is None) else ("ret", _enc(st.value, env))
            outs.append((cur, o))
            if "leak" in env and o[0] == "ret" and _leaky(st.value, env):
                env["leak"][id(o)] = ast.dump(st.value)
            return outs, z3.BoolVal(False)
        if isinstance(st, ast.Raise):
            if st.exc is None or st.cause is not None:
                raise Unmodeled("bare or chained raise")
            outs.append((cur, ("raise", ast.unparse(st.exc))))
            return outs, z3.BoolVal(False)
        if isinstance(st, ast.If):
            t = _enc(st.test, env)
            if _sort(t) != "bool":
                raise Unmodeled(f"non-bool condition `{ast.unparse(st.test)}`")
            ob, cb = _block(st.body, env, z3.And(cur, t))
            oe, ce = _block(st.orelse, env, z3.And(cur, z3.Not(t)))
            outs += ob + oe
            cur = z3.Or(cb, ce)
            continue
        raise Unmodeled(f"unmodeled statement `{ast.unparse(st).splitlines()[0]}`")
    return outs, cur


def _outcome_eq(a: Outcome, b: Outcome) -> Any:
    if a[0] != b[0]:  # kinds differ: a value, None and an exception are never the same output
        return z3.BoolVal(False)
    if a[0] == "none":
        return z3.BoolVal(True)
    if a[0] == "ret" and b[0] == "ret":
        sa, sb = _sort(a[1]), _sort(b[1])
        if sa == sb:
            return _s_eq(a[1], b[1]) if sa == "str" else a[1] == b[1]
        if {sa, sb} == {"bool", "int"}:
            raise Unmodeled("result sorts bool and int are compared by Python equality: not modelled")
        return z3.BoolVal(False)
    if a[0] == "raise" and b[0] == "raise":
        return z3.BoolVal(a[1] == b[1])
    return z3.BoolVal(False)


# ------------------------------------------------------------------ function / module access
_TYPES = {"int", "str", "bool"}


_DYNAMIC_NAMES = {"globals", "vars", "exec", "eval", "setattr", "__import__", "locals"}


def _module_consts(tree: ast.Module) -> dict[str, Any]:
    """Module constants the encoder may fold, and ONLY those that are certainly one fixed value: the name is bound
    exactly once in the whole module, by a plain top-level ``NAME = <int|str|bool literal>`` (or ``NAME: T = literal``),
    never inside if/try/loop/with, and nothing in the module can rebind it: no augmented/other store, ``global`` or
    ``nonlocal`` declaration, ``del``, import, def/class of the same name, star import, or dynamic namespace access
    (globals()/vars()/exec/eval/setattr/__import__). Anything else is NOT folded (the name stays unresolved, so the
    check is UNMODELED), because the runtime value is the LAST binding, not the first literal."""
    binds: dict[str, int] = {}
    poisoned: set[str] = set()
    poison_all = False

    def bind(name: str) -> None:
        binds[name] = binds.get(name, 0) + 1

    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                bind(n.id)
            if n.id in _DYNAMIC_NAMES:
                poison_all = True
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            poisoned.update(n.names)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                if al.name == "*":
                    poison_all = True
                else:
                    bind((al.asname or al.name).split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bind(n.name)
        elif isinstance(n, ast.MatchAs) and n.name:
            bind(n.name)
    out: dict[str, Any] = {}
    if poison_all:
        return out
    for n in tree.body:  # only direct top-level statements: not under if/try/for/while/with
        name = value = None
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            name, value = n.targets[0].id, n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            name, value = n.target.id, n.value
        if name is not None and isinstance(value, ast.Constant) and isinstance(value.value, (int, str, bool))\
                and binds.get(name) == 1 and name not in poisoned:
            out[name] = value.value
    return out


_BUILTIN_VALUE_TYPES = {"int", "str", "bool"}


def _repo_value_subclasses(tree: ast.Module) -> list[str]:
    """Classes of this module that subclass int/str/bool (directly or through another such class): their instances
    satisfy an int/str/bool annotation and may override any operator, so the exact-builtin model does not apply."""
    bad: set[str] = set()
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    changed = True
    while changed:
        changed = False
        for c in classes:
            if c.name in bad:
                continue
            for b in c.bases:
                bn = b.id if isinstance(b, ast.Name) else (b.attr if isinstance(b, ast.Attribute) else None)
                if bn in _BUILTIN_VALUE_TYPES or bn in bad:
                    bad.add(c.name)
                    changed = True
                    break
    return sorted(bad)


def _leaky(node: ast.AST, env: dict) -> bool:
    """True when the value of this return expression can be an instance of a SUBTYPE of the modelled sort even though
    every operand is an annotated exact int: a bare int parameter may be ``True``, ``min(n, 1)``/``max`` return one of
    their arguments, a conditional expression returns one branch. Arithmetic (+ - * // %, unary -, abs) always builds
    a plain int, so it is not leaky."""
    if isinstance(node, ast.Name):
        v = env["params"].get(node.id)
        return v is not None and _sort(v) == "int"
    if isinstance(node, ast.IfExp):
        return _leaky(node.body, env) or _leaky(node.orelse, env)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("min", "max"):
        return any(_leaky(a, env) for a in node.args)
    return False


_BUILTINS_USED = {"len", "min", "max", "abs"}


def _no_shadowing(tree: ast.Module) -> None:
    """len/min/max/abs are modelled as the builtins: refuse if the module rebinds any of them."""
    for n in tree.body:
        names: list[str] = []
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [n.name]
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names = [(a.asname or a.name).split(".")[0] for a in n.names]
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.With)):
            names = [x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)]
        hit = _BUILTINS_USED.intersection(names)
        if hit:
            raise Unmodeled(f"module rebinds builtin {sorted(hit)[0]!r}; its call is not the builtin")


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    _no_shadowing(tree)
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            if n.decorator_list:
                raise Unmodeled(f"{name} is decorated")
            return n
    raise Unmodeled(f"{name} is not a top-level function")


def _params(fn: ast.FunctionDef) -> list[tuple[str, str, Any]]:
    a = fn.args
    if a.posonlyargs or a.vararg or a.kwonlyargs or a.kwarg:
        raise Unmodeled("signature has positional-only, *args, keyword-only or **kwargs parameters")
    defaults = [None] * (len(a.args) - len(a.defaults)) + list(a.defaults)
    out = []
    for arg, d in zip(a.args, defaults):
        if arg.arg in _BUILTINS_USED:
            raise Unmodeled(f"parameter {arg.arg!r} shadows a builtin")
        t = arg.annotation.id if isinstance(arg.annotation, ast.Name) else None
        if t not in _TYPES:
            raise Unmodeled(f"parameter {arg.arg!r} has no int/str/bool annotation")
        if d is None:
            out.append((arg.arg, t, None))
        elif isinstance(d, ast.Constant) and isinstance(d.value, (int, str, bool))\
                and type(d.value).__name__ == t:
            out.append((arg.arg, t, d.value))
        else:
            raise Unmodeled(f"default of {arg.arg!r} is not a constant of its annotated type")
    return out


def _var(name: str, t: str) -> Any:
    if t == "str":
        return _S(z3.Int(f"n_{name}"), z3.Array(f"f_{name}", z3.IntSort(), z3.IntSort()))
    return {"int": z3.Int, "bool": z3.Bool}[t](name)


def _domain(xs: dict[str, Any]) -> list[Any]:
    i = z3.Int("i_dom")
    out = []
    for x in xs.values():
        if isinstance(x, _S):
            out += [x.n >= 0, z3.ForAll([i], z3.Implies(z3.And(i >= 0, i < x.n),
                                                        z3.And(z3.Select(x.f, i) >= 0, z3.Select(x.f, i) <= _CHAR_MAX)))]
    return out


# ------------------------------------------------------------------ concrete replay (same grammar, real Python)
def _ceval(node: ast.AST, names: dict) -> Any:
    code = compile(ast.fix_missing_locations(ast.Expression(node)), "<delta_rel>", "eval")
    return eval(code, {"__builtins__": {}, "len": len, "min": min, "max": max, "abs": abs}, names)  # noqa: S307


def _crun(fn: ast.FunctionDef, names: dict) -> Outcome:
    def run(stmts: list[ast.stmt]) -> Outcome | None:
        for st in stmts:
            if isinstance(st, ast.Return):
                if st.value is None:
                    return ("none", None)
                v = _ceval(st.value, names)
                return ("none", None) if v is None else ("ret", v)
            if isinstance(st, ast.Raise):
                return ("raise", ast.unparse(st.exc))
            if isinstance(st, ast.If):
                r = run(st.body if _ceval(st.test, names) else st.orelse)
                if r is not None:
                    return r
        return None

    r = run(fn.body)
    return ("none", None) if r is None else r


def _same(a: Outcome, b: Outcome) -> bool:
    if a[0] != b[0]:
        return False
    if a[0] == "none":
        return True
    return a[1] == b[1] and type(a[1]) is type(b[1]) if a[0] == "ret" else a[1] == b[1]


def _decode(s: str) -> str:
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), s)


# ------------------------------------------------------------------ the check
def _sha(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def _segment(src: str, func: str) -> str:
    """UTF-8 source text of the callable (a top-level function or Class.method); whole text if not located."""
    try:
        tree = ast.parse(src)
        scope, name = tree.body, func
        if "." in func:
            cls, _, name = func.partition(".")
            owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls]
            scope = owner[0].body if len(owner) == 1 else []
        for n in scope:
            if isinstance(n, ast.FunctionDef) and n.name == name:
                return ast_source_segment(src, n) or src
    except SyntaxError:
        pass
    return src


def check_callable(base_src: str, post_src: str, func: str, deltas: list[dict] | None = None,
                   python_version: tuple[int, ...] | None = None,
                   repo_universe: dict[str, Any] | None = None) -> DeltaRelResult:
    """``_check_callable_inproc`` answered by a forked, confined, resource-limited worker child (drive_inputs.sandbox_call):
    the repository source is parsed and Z3 runs THERE, never in the caller. A killed or failed call is UNMODELED with a
    named reason: nothing is proved, no counterexample is invented. See ``_check_callable_inproc`` for the arguments.
    """
    from .. import drive_inputs as di

    out = di.sandbox_call("delta_rel", {"base_src": base_src, "post_src": post_src, "func": func,
                                        "deltas": list(deltas or []), "python_version": python_version,
                                        "repo_universe": repo_universe})
    if out.get("ok"):
        r = out["result"]
        return DeltaRelResult(r["verdict"], r["reason"], list(r["witness_inputs"]), dict(r["provenance"]),
                              r["proof_tier"], list(r["assumptions"]))
    prov = {"analysis": "delta_rel", "z3": z3.get_version_string(), "function": func,
            "pre_sha256": _sha(base_src), "post_sha256": _sha(post_src)}
    return DeltaRelResult(UNMODELED, str(out.get("stop", "sandbox failed")), provenance=prov)


def _check_callable_inproc(base_src: str, post_src: str, func: str, deltas: list[dict] | None = None,
                           python_version: tuple[int, ...] | None = None,
                           repo_universe: dict[str, Any] | None = None) -> DeltaRelResult:
    """``repo_universe``: what the caller knows about the program's classes: ``{"subclasses": [...]}`` lists every class
    that subclasses int/str/bool (review's runtime universe); ``{"subclasses": []}`` means KNOWN CLEAN. None = unknown: the
    proof is then CONDITIONAL on there being no such class (an int/str-annotated argument may be an instance of one)."""
    prov = {"analysis": "delta_rel", "z3": z3.get_version_string(), "function": func,
            "pre_sha256": _sha(_segment(base_src, func)), "post_sha256": _sha(_segment(post_src, func))}
    try:
        return _check(base_src, post_src, func, list(deltas or []), prov, repo_universe)
    except Unmodeled as e:
        numeric = str(e)
    except (SyntaxError, RecursionError) as e:
        numeric = f"{type(e).__name__}: {e}"[:200]
    # outside the exact numeric fragment: UF relational mode (conditional PROVED, never a counterexample)
    from .delta_rel_uf import check_uf

    verdict, reason = check_uf(base_src, post_src, func, list(deltas or []), python_version)
    if verdict == PROVED:
        from .delta_rel_uf import assumptions_of

        return DeltaRelResult(PROVED, reason, provenance=prov, tier="conditional",
                              assumptions=assumptions_of(reason, bool(deltas)))
    return DeltaRelResult(UNMODELED, f"{numeric} | {reason}", provenance=prov)


def _check(base_src: str, post_src: str, func: str, deltas: list[dict], prov: dict,
           repo_universe: dict[str, Any] | None = None) -> DeltaRelResult:
    bt, pt = ast.parse(base_src), ast.parse(post_src)
    bf, pf = _function(bt, func), _function(pt, func)
    bp, pp = _params(bf), _params(pf)
    if [(n, t) for n, t, _ in bp] != [(n, t) for n, t, _ in pp]:
        raise Unmodeled("parameter names or types changed: call binding is not this check's domain")
    # what is observable or evaluated outside the body: docstring, annotations (evaluated at definition, may
    # raise), and anything that runs when the module is imported
    dump = lambda x: "-" if x is None else ast.dump(x)  # noqa: E731
    if ast.get_docstring(bf, clean=False) != ast.get_docstring(pf, clean=False):
        raise Unmodeled("the docstring changed: it is observable as f.__doc__")
    if [dump(a.annotation) for a in bf.args.args] != [dump(a.annotation) for a in pf.args.args] or dump(bf.returns) != dump(pf.returns):
        raise Unmodeled("an annotation changed: annotations are evaluated when the function is defined")
    from .delta_rel_uf import _import_time_effects

    if sorted(_import_time_effects(bt)) != sorted(_import_time_effects(pt)):
        raise Unmodeled("a statement that runs at import time changed")
    xs = {n: _var(f"x_{n}", t) for n, t, _ in pp}
    om = {n: z3.Bool(f"omitted_{n}") for n, _, d in pp if d is not None}
    cons: list[Any] = []
    names = [n for n, _, _ in pp]
    for a, b in zip(names, names[1:]):  # an omitted argument leaves every later one omitted
        if a in om and b in om:
            cons.append(z3.Implies(om[a], om[b]))

    def eff(params: list[tuple[str, str, Any]]) -> dict[str, Any]:
        out = {}
        for n, t, d in params:
            if d is None:
                out[n] = xs[n]
            else:
                dv = _enc(ast.Constant(d), {"params": {}, "consts": {}})
                out[n] = _s_if(om[n], dv, xs[n]) if t == "str" else z3.If(om[n], dv, xs[n])
        return out

    for tree_, side_ in ((bt, "base"), (pt, "post")):
        bad_ = _repo_value_subclasses(tree_)
        if bad_:
            raise Unmodeled(f"{side_} module defines {bad_} subclassing int/str/bool: an int/str-annotated argument may be "
                            "an instance, whose operators are not the builtins' (exact-builtin model does not apply)")
    if repo_universe and repo_universe.get("subclasses"):
        raise Unmodeled(f"the repo has classes subclassing int/str/bool ({list(repo_universe['subclasses'])[:3]}): "
                        "exact-builtin model does not apply")
    used: set[str] = set()
    leak: dict[int, str] = {}
    pre_env = {"params": eff(bp), "consts": _module_consts(bt), "used": used, "leak": leak}
    post_env = {"params": eff(pp), "consts": _module_consts(pt), "used": used, "leak": leak}
    outs_b, cont_b = _block(bf.body, pre_env, z3.BoolVal(True))
    outs_p, cont_p = _block(pf.body, post_env, z3.BoolVal(True))
    outs_b.append((cont_b, ("none", None)))  # implicit end of function == `return None`, a real output
    outs_p.append((cont_p, ("none", None)))
    s = z3.Solver()
    _budget(s)
    s.add(*cons, *_domain(xs))
    for tag, outs in (("pre", outs_b), ("post", outs_p)):  # every path accounted for: guards cover all inputs
        s.push()
        s.add(z3.Not(z3.Or(*[g for g, _ in outs])))
        r = s.check()
        s.pop()
        if r != z3.unsat:
            raise Unmodeled(f"the {tag}-change path conditions are not proven exhaustive ({r}); no path may be dropped")

    dvs = []
    for d in deltas:
        pred = d.get("predicate") or {}
        exp = d.get("expected") or {}
        if pred.get("type") != "expr" or not isinstance(pred.get("expr"), str):
            raise Unmodeled(f"delta {d.get('id')!r}: predicate type {pred.get('type')!r} is not an expression")
        P = _enc(ast.parse(pred["expr"], mode="eval").body, post_env)
        if _sort(P) != "bool":
            raise Unmodeled(f"delta {d.get('id')!r}: predicate is not boolean")
        if exp.get("kind") == "returns" and exp.get("value_repr") == "None":
            E: Outcome = ("none", None)
        elif exp.get("kind") == "returns" and isinstance(exp.get("value_repr"), str):
            E = ("ret", _enc(ast.parse(exp["value_repr"], mode="eval").body, post_env))
        elif exp.get("kind") == "raises" and isinstance(exp.get("exc_type"), str):
            E = ("raise-type", exp["exc_type"].rsplit(".", 1)[-1])
        else:
            raise Unmodeled(f"delta {d.get('id')!r}: expected kind {exp.get('kind')!r} is not modelled")
        dvs.append((d, P, E))

    def match(o: Outcome, E: Outcome) -> Any:
        if E[0] == "raise-type":
            return z3.BoolVal(o[0] == "raise" and re.match(rf"\s*(?:\w+\.)*{re.escape(E[1])}\b", o[1]) is not None)
        return _outcome_eq(o, E)

    # Type fidelity (review D01): a bare int parameter / min / max / conditional can be a bool at runtime, and `True` and
    # `1` are different outputs. Wherever one side's returned expression may be such a subtype and the other side's
    # is a different expression, the two sides must never be selected by the same input.
    for gb, ob in outs_b:
        for gp, op in outs_p:
            if ob[0] != "ret" or op[0] != "ret":
                continue
            lb, lp = leak.get(id(ob)), leak.get(id(op))
            if (lb is None and lp is None) or lb == lp:
                continue
            s.push()
            s.add(gb, gp)
            r_ov = s.check()
            s.pop()
            if r_ov != z3.unsat:
                raise Unmodeled("a returned value may be a bool (or another int subtype) on one side and a plain int on "
                                "the other for the same input: `True` and `1` are different outputs")
    anyP = z3.Or(*[P for _, P, _ in dvs]) if dvs else z3.BoolVal(False)
    vcs: list[tuple[str, dict | None, Any]] = []
    for d, P, E in dvs:
        vcs.append(("VC1", d, z3.And(P, z3.Not(z3.Or(*[z3.And(g, match(o, E)) for g, o in outs_p])))))
    vcs.append(("VC2", None, z3.And(z3.Not(anyP), z3.Or(*[
        z3.And(gb, gp, z3.Not(_outcome_eq(ob, op))) for gb, ob in outs_b for gp, op in outs_p]))))

    for name, d, vc in vcs:
        s.push()
        s.add(vc)
        res = s.check()
        model = s.model() if res == z3.sat else None
        if model is not None:  # prefer a short, readable witness; the verdict itself is over the whole domain
            i_w = z3.Int("i_w")
            strs = [x for x in xs.values() if isinstance(x, _S)]
            for cap, printable in ((40, True), (40, False), (6000, True), (6000, False), (100_000, False)):
                s.push()
                s.add(*[x.n <= cap for x in strs])
                if printable:
                    s.add(*[z3.ForAll([i_w], z3.Implies(z3.And(i_w >= 0, i_w < x.n), z3.And(
                        z3.Select(x.f, i_w) >= _PRINT_LO, z3.Select(x.f, i_w) <= _PRINT_HI))) for x in strs])
                if s.check() == z3.sat:
                    model = s.model()
                    s.pop()
                    break
                s.pop()
        s.pop()
        if res == z3.unknown:
            raise Unmodeled(f"{name}: solver undecided within {_SOLVER_MS} ms")
        if res == z3.sat:
            return _counterexample(name, d, model, xs, om, pp, bp, bf, pf, bt, pt, prov)
    assumptions = ([f"{len(dvs)} declared delta(s) are taken as given: their predicates and expected outcomes are the "
                    "operator's claim, not proved to be intended"] if dvs else [])
    universe_clean = isinstance(repo_universe, dict) and repo_universe.get("complete") is True\
        and repo_universe.get("subclasses") == []
    if not universe_clean:
        assumptions.append("no class in the program subclasses int/str/bool and overrides an operator or __len__ (not checked: "
                           "the repo's class universe was not supplied)")
    for name_ in sorted(used):
        assumptions.append(f"module constant {name_} is not rebound outside this module (other modules, monkeypatching, "
                           "setattr: not checked); inside the module it is bound exactly once")
    tier = "unconditional" if universe_clean and not used else "conditional"
    return DeltaRelResult(
        PROVED, f"for all arguments of the annotated int/str/bool types (strings over the full Python code-point "
        f"domain, ints unbounded; values compared by Python ==): every approved delta holds on its predicate and "
        f"outside the predicates the post-change function equals the pre-change one ({len(dvs)} delta(s))",
        provenance=prov, tier=tier, assumptions=assumptions)


def _counterexample(name, d, model, xs, om, params, bparams, bf, pf, bt, pt, prov) -> DeltaRelResult:
    vals: dict[str, Any] = {}
    omitted: list[str] = []
    for n, t, dflt in params:
        x = xs[n]
        if t == "str":
            ln = model.eval(x.n, model_completion=True).as_long()
            if not 0 <= ln <= 100_000:
                raise Unmodeled(f"counterexample string length {ln} is not materialisable")
            val = "".join(chr(model.eval(z3.Select(x.f, k), model_completion=True).as_long()) for k in range(ln))
        else:
            v = model.eval(x, model_completion=True)
            val = v.as_long() if t == "int" else z3.is_true(v)
        if n in om and z3.is_true(model.eval(om[n], model_completion=True)):
            omitted.append(n)
            val = dflt
        vals[n] = val
    # concrete replay on real Python values: a counterexample is reported only if it reproduces
    pre_vals = {**vals, **{n: dflt for n, _, dflt in bparams if n in omitted}}
    pre_names = {**_module_consts(bt), **pre_vals}
    post_names = {**_module_consts(pt), **vals}
    pre_o, post_o = _crun(bf, pre_names), _crun(pf, post_names)
    if name == "VC2" and _same(pre_o, post_o):
        raise Unmodeled("VC2 model did not reproduce under concrete replay (encoding disagreement); not reported")
    if name == "VC1":
        exp = d["expected"]
        if exp["kind"] == "returns":
            want: Outcome = ("none", None) if exp["value_repr"] == "None" else (
                "ret", _ceval(ast.parse(exp["value_repr"], mode="eval").body, post_names))
            fulfilled = _same(post_o, want)
        else:
            fulfilled = post_o[0] == "raise" and re.match(
                rf"\s*(?:\w+\.)*{re.escape(exp['exc_type'].rsplit('.', 1)[-1])}\b", post_o[1]) is not None
        if fulfilled:
            raise Unmodeled("VC1 model did not reproduce under concrete replay (encoding disagreement); not reported")
    given = [n for n, _, _ in params if n not in omitted]
    witness = {
        "kind": "delta_rel_counterexample", "vc": name, "delta": (d or {}).get("id"),
        "n_positional": len(given), "keywords": [], "param_names": [n for n, _, _ in params],
        "path_literals": {str(i): repr(vals[n]) for i, n in enumerate(given)},
        "omitted_defaults": omitted, "pre_outcome": [pre_o[0], repr(pre_o[1])],
        "post_outcome": [post_o[0], repr(post_o[1])],
    }
    why = (f"{name}: with {', '.join(f'{n}={vals[n]!r}' for n in vals)} the function returns/raises "
           f"{post_o[0]} {post_o[1]!r} after the change vs {pre_o[0]} {pre_o[1]!r} before"
           + ("; the input is outside every approved delta predicate, so the change must not alter it" if d is None
              else f"; the approved delta {d['id']!r} claims otherwise on its own predicate"))
    return DeltaRelResult(COUNTEREXAMPLE, why, [witness], prov)


# ------------------------------------------------------------------ soundness self-test (CI)
def encoded_outcome(src: str, func: str, args: dict[str, Any]) -> Outcome:
    """The encoder's own answer for concrete arguments: substitute them, find the one path whose guard holds.

    Used only by the self-test below, to compare the encoding with the real runtime."""
    tree = ast.parse(src)
    fn = _function(tree, func)
    params = _params(fn)
    env = {"params": {}, "consts": _module_consts(tree)}
    for n, t, _d in params:
        v = args[n]
        env["params"][n] = _s_const(v) if t == "str" else (z3.BoolVal(v) if t == "bool" else z3.IntVal(v))
    outs, cont = _block(fn.body, env, z3.BoolVal(True))
    outs.append((cont, ("none", None)))
    def decide(b: Any) -> bool:
        """A closed Boolean as a Python bool; quantified string equalities need the solver, never a guess."""
        v = z3.simplify(b)
        if z3.is_true(v):
            return True
        if z3.is_false(v):
            return False
        yes, no = z3.Solver(), z3.Solver()
        _budget(yes)
        _budget(no)
        yes.add(b)
        no.add(z3.Not(b))
        ys, ns_ = yes.check() == z3.sat, no.check() == z3.sat
        if ys == ns_:
            raise AssertionError(f"closed Boolean is not decidable by the oracle: {b}")
        return ys

    hits = [o for g, o in outs if decide(g)]
    if len(hits) != 1:
        raise AssertionError(f"encoding has {len(hits)} satisfied paths for {args!r}: paths are not a partition")
    kind, val = hits[0]
    if kind != "ret":
        return (kind, val)
    if isinstance(val, _S):
        n = z3.simplify(val.n).as_long()
        return ("ret", "".join(chr(z3.simplify(z3.Select(val.f, i)).as_long()) for i in range(n)))
    if z3.is_bool(val):
        return ("ret", decide(val))
    return ("ret", z3.simplify(val).as_long())


_SPECIAL_CHARS = [" ", "\t", "\n", "\r", "\x0b", "\x0c", "\x00", "\x1f", "\x7f", "\x85", "\xa0", "\xe9", "\u2028",
                  "\u200b", "\u2026", "\ud800", "\udfff", "\U0001f600", "\U0010ffff", "\\", '"', "'", "a", "b", "A"]


def string_sampler(rng: Any, extra_chars: list[str] = ()) -> Any:
    """Random strings biased to what breaks string encodings: empty, single special characters (whitespace,
    control, DEL, non-ASCII, line separators, zero-width, lone surrogates, non-BMP, U+10FFFF), the characters
    of the function's own constants, mixtures, and (rarely) very long strings."""
    alphabet = list(_SPECIAL_CHARS) + list(extra_chars)

    def rstr() -> str:
        r = rng.random()
        if r < 0.10:
            return ""
        if r < 0.30:
            return rng.choice(alphabet)
        ln = rng.choice([1, 2, 3, rng.randint(1, 12), rng.randint(1, 40)]) if r < 0.985 else rng.choice([4095, 4096, 4097])
        return "".join(rng.choice(alphabet) for _ in range(ln))

    return rstr


def soundness_selftest(src: str, func: str, n: int = 2000, seed: int = 0) -> list[dict[str, Any]]:
    """Compare the encoded semantics with the REAL Python result on ``n`` random inputs; returns mismatches.

    Executes ``src`` (call it only on trusted, e.g. test-fixture, code). An empty list means no silent
    abstraction error was found on these inputs; a non-empty list is an encoder bug."""
    import random

    rng = random.Random(seed)
    tree = ast.parse(src)
    params = _params(_function(tree, func))
    consts = _module_consts(tree)
    ns: dict[str, Any] = {}
    exec(compile(src, "<selftest>", "exec"), ns)  # noqa: S102 - trusted fixture source only
    real = ns[func]

    def rint() -> int:
        return rng.choice([lambda: rng.randint(-6, 6), lambda: rng.randint(-1000, 1000),
                           lambda: rng.choice([-2**128, 2**128, -2**64 - 1, 4095, 4096, 4097, -1, 0, 1]),
                           lambda: rng.randint(-2**70, 2**70)])()

    rstr = string_sampler(rng, sorted({c for n_ in ast.walk(tree) if isinstance(n_, ast.Constant)
                                       and isinstance(n_.value, str) for c in n_.value}))

    bad = []
    for _ in range(n):
        args = {nm: (rint() if t == "int" else rstr() if t == "str" else rng.random() < 0.5) for nm, t, _d in params}
        try:
            got = real(**args)
            want: Outcome = ("none", None) if got is None else ("ret", got)
        except Exception as e:  # noqa: BLE001 - the runtime's own exception, compared by type name
            want = ("raise", type(e).__name__)
        enc = encoded_outcome(src, func, args)
        ok = (enc[0] == want[0]) and (True if enc[0] == "none" else
                                      (enc[1] == want[1] and type(enc[1]) is type(want[1])) if enc[0] == "ret"
                                      else re.match(rf"\s*(?:\w+\.)*{re.escape(want[1])}\b", enc[1]) is not None)
        if not ok:
            bad.append({"args": {k: (v if not isinstance(v, str) or len(v) < 60 else v[:60] + "...") for k, v in args.items()},
                        "encoded": [enc[0], repr(enc[1])[:80]], "runtime": [want[0], repr(want[1])[:80]]})
    return bad
