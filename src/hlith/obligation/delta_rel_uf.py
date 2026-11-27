# SPDX-License-Identifier: Apache-2.0
"""UF relational mode of the delta check (F4): the same VC1/VC2 relational query as hlith.delta_rel, but every
value the numeric fragment cannot model (calls, methods, attributes, subscripts, containers, arbitrary-typed
parameters) is an UNINTERPRETED term of one sort V, shared by pre and post.

What a PROVED here means (conditional, never a standalone HELD):
    post == pre, and every approved delta holds on its predicate, for ANY deterministic callee / attribute /
    operator semantics, provided both versions perform the SAME ORDERED EFFECTS (stores, deletes, impure and
    mutating calls, discarded calls, context managers) and nothing else the function reads changed. Every
    heap read is indexed by the effect trace, so a read moved across an effect is a difference. That assumption is
    stated, not verified.

What it can NOT do: produce a counterexample. A difference found under some interpretation of the opaque terms
has no concrete input, so UF mode never yields COUNTEREXAMPLE and never seeds the differential; it yields PROVED
or UNMODELED and the differential supplies witnesses.

Fail closed: any statement that can mutate or do IO, any construct whose Python semantics is not modelled
exactly, and any non-exhaustive path set => UNMODELED, never PROVED.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import random
from typing import Any

import z3

V = z3.DeclareSort("V")
_BOOL = z3.BoolSort()
_FN: dict[tuple[str, int], Any] = {}
_SOLVER_MS = 8000
_RL_PER_MS = 1000  # Z3 resource units per budget millisecond (same calibration as delta_rel / drive_inputs)

IMPURE_CALLS = {"open", "print", "setattr", "delattr", "exec", "eval", "compile", "id", "input", "__import__",
                "globals", "locals", "vars", "breakpoint", "next", "iter", "exit", "quit"}
IMPURE_ROOTS = {"random", "time", "os", "sys", "subprocess", "shutil", "socket", "secrets", "uuid", "datetime",
                "logging", "threading", "multiprocessing", "asyncio", "pathlib", "tempfile", "requests", "urllib"}
MUTATORS = {"append", "extend", "update", "add", "pop", "popitem", "remove", "clear", "insert", "sort", "reverse",
            "write", "writelines", "close", "flush", "seek", "truncate", "setdefault", "discard", "put", "send",
            "put_nowait", "get_nowait", "acquire", "release", "set", "setattr", "delete", "commit", "rollback",
            "execute", "start", "join_thread", "kill", "terminate", "wait", "mkdir", "unlink", "rename", "touch"}


class UfUnmodeled(Exception):
    pass


# ---- exact identities, gated by the TARGET interpreter's version, canonicalised away before encoding.
# Each is the SAME OBJECT in real Python (a test executes it); nothing semantic (e.g. '%'-formatting) belongs here.
EXACT_FACTS = (
    # (id, minimum python, spelling (module, attr) or builtin name, canonical name)
    ("IOError is OSError", (3, 3), None, "IOError", "OSError"),
    ("EnvironmentError is OSError", (3, 3), None, "EnvironmentError", "OSError"),
    ("socket.error is OSError", (3, 3), "socket", "error", "OSError"),
    ("select.error is OSError", (3, 3), "select", "error", "OSError"),
    ("os.error is OSError", (3, 3), "os", "error", "OSError"),
    ("socket.timeout is TimeoutError", (3, 10), "socket", "timeout", "TimeoutError"),
)


class _Canon(ast.NodeTransformer):
    """Rewrite a spelling to its canonical name when the module really imports the module unrebound (attribute
    spellings) / does not rebind the builtin name (bare spellings). Records which facts were used."""

    def __init__(self, active: list, module_names: dict[str, list[ast.stmt]], used: set[str]) -> None:
        self.active, self.names, self.used = active, module_names, used

    def _plain_import(self, mod: str) -> bool:
        defs = self.names.get(mod, [])
        return len(defs) == 1 and isinstance(defs[0], ast.Import) and any(
            a.name == mod and a.asname is None for a in defs[0].names)

    def visit_Name(self, n: ast.Name) -> ast.AST:
        for fid, _v, mod, src, dst in self.active:
            if mod is None and n.id == src and isinstance(n.ctx, ast.Load) and src not in self.names:
                self.used.add(fid)
                return ast.copy_location(ast.Name(dst, ast.Load()), n)
        return n

    def visit_Attribute(self, n: ast.Attribute) -> ast.AST:
        n = self.generic_visit(n)
        if isinstance(n.value, ast.Name) and isinstance(n.ctx, ast.Load):
            for fid, _v, mod, src, dst in self.active:
                if mod is not None and n.value.id == mod and n.attr == src and self._plain_import(mod) \
                        and dst not in self.names:
                    self.used.add(fid)
                    return ast.copy_location(ast.Name(dst, ast.Load()), n)
        return n


def canonicalise(tree: ast.Module, python_version: tuple[int, ...] | None) -> tuple[ast.Module, list[str]]:
    """Apply the version-gated exact identities. Without a target version none is applied."""
    if python_version is None:
        return tree, []
    active = [f for f in EXACT_FACTS if tuple(python_version[:2]) >= f[1]]
    names: dict[str, list[ast.stmt]] = {}
    for n in tree.body:
        for nm in _defined_names(n):
            names.setdefault(nm, []).append(n)
    used: set[str] = set()
    out = _Canon(active, names, used).visit(copy.deepcopy(tree))
    return ast.fix_missing_locations(out), sorted(used)


def uf(name: str, arity: int, ret: Any = None) -> Any:
    key = (name, arity)
    if key not in _FN:
        _FN[key] = z3.Function(name, *([V] * arity), ret if ret is not None else V)
    return _FN[key]


def konst(name: str) -> Any:
    return z3.Const(name, V)


_T = z3.Function("T", V, V, _BOOL)  # truthiness of a value in a given state (trace)
_IN = z3.Function("in_pred", V, V, V, _BOOL)  # `x in y` in a given state
_BOX = z3.Function("boxb", _BOOL, V)  # a real bool as a value


_TRC: list[Any] = [None]  # the effect trace in force while one statement is being encoded


def _truth(e: Any) -> Any:
    if z3.is_bool(e):
        return e
    if z3.is_app(e) and e.decl().eq(_BOX):  # truthiness of a real bool is that bool
        return e.arg(0)
    return _T(_TRC[0], e)


_NONNULL: dict[str, Any] = {}  # every non-None constant created so far: none of them is the None object


def _axioms() -> list[Any]:
    b, t = z3.Bool("b_ax"), z3.Const("t_ax", V)
    ax = [z3.ForAll([t, b], _T(t, _BOX(b)) == b),  # truthiness of a real bool is that bool, in every state
          z3.ForAll([t], z3.Not(_T(t, NONE_T))),  # bool(None) is False
          z3.ForAll([b], _BOX(b) != NONE_T)]  # a bool is not None
    ax += [k != NONE_T for k in _NONNULL.values()]  # constants are not None
    return ax


def _val(e: Any) -> Any:
    return _BOX(e) if z3.is_bool(e) else e


def _kname(c: Any) -> str:
    return f"k_{type(c).__name__}_{hashlib.sha256(repr(c).encode()).hexdigest()[:10]}"


NONE_T = konst("k_NoneType_none")
_TRACE0 = konst("trace0")
_TRC[0] = _TRACE0


def _op(name: str, *args: Any) -> Any:
    """An opaque operation reads the heap, so its term carries the current effect trace."""
    return uf(name, len(args) + 1)(_TRC[0], *args)


def _effect(term: Any) -> None:
    _TRC[0] = uf("tr", 2)(_TRC[0], term)  # an effect is appended to the ordered trace


def _effectful_call(node: ast.Call) -> bool:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in IMPURE_CALLS
    if isinstance(f, ast.Attribute):
        r: ast.AST = f
        while isinstance(r, (ast.Attribute, ast.Call, ast.Subscript)):
            r = r.value if isinstance(r, (ast.Attribute, ast.Subscript)) else r.func
        return f.attr in MUTATORS or (isinstance(r, ast.Name) and r.id in IMPURE_ROOTS)
    return False


def _const(c: Any) -> Any:
    if c is None:
        return NONE_T
    if isinstance(c, bool):
        return _BOX(z3.BoolVal(c))
    if isinstance(c, (int, str, bytes, float)):
        k = konst(_kname(c))
        _NONNULL[_kname(c)] = k
        return k
    raise UfUnmodeled(f"unsupported constant {c!r}")


_BIN = {ast.Add: "Add", ast.Sub: "Sub", ast.Mult: "Mult", ast.Div: "Div", ast.FloorDiv: "FloorDiv",
        ast.Mod: "Mod", ast.Pow: "Pow", ast.LShift: "LShift", ast.RShift: "RShift", ast.BitAnd: "BitAnd",
        ast.BitOr: "BitOr", ast.BitXor: "BitXor", ast.MatMult: "MatMult"}
_UN = {ast.USub: "USub", ast.UAdd: "UAdd", ast.Invert: "Invert"}
_CMP = {ast.Eq: "Eq", ast.NotEq: "NotEq", ast.Lt: "Lt", ast.LtE: "LtE", ast.Gt: "Gt", ast.GtE: "GtE"}


_CUR_FN: list[Any] = [None]  # the function being encoded (for store counts of captured locals)


def _hash(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node).encode()).hexdigest()[:12]


def _bound_in(node: ast.AST) -> set[str]:
    """Names bound inside a lambda / comprehension / nested def: its own parameters and targets."""
    out: set[str] = set()
    for x in ast.walk(node):
        if isinstance(x, ast.arg):
            out.add(x.arg)
        elif isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
            out.add(x.id)
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(x.name)
    return out


def _captured(node: ast.AST, env: dict[str, Any], fn: ast.FunctionDef | None) -> list[str]:
    if any(isinstance(x, (ast.Global, ast.Nonlocal)) for x in ast.walk(node)):
        raise UfUnmodeled("global/nonlocal inside a closure rebinds a name of the enclosing scope")
    """Locals of the enclosing function a closure reads (late-bound): each must be assigned at most once, and a
    parameter never, else the value seen when the closure RUNS may differ from the one seen now."""
    free = sorted({x.id for x in ast.walk(node) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}
                  - _bound_in(node))
    cap = [n for n in free if n in env and n != "__trace__" and n != "__exc__"]
    if fn is not None:
        stores: dict[str, int] = {}
        for x in ast.walk(fn):
            if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                stores[x.id] = stores.get(x.id, 0) + 1
        params = {a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs}
        for n in cap:
            if stores.get(n, 0) > (0 if n in params else 1):
                raise UfUnmodeled(f"closure reads {n!r}, which is reassigned (late binding)")
    return cap


def _R(t: Any) -> Any:  # does evaluating this operation raise (deterministic in the term's value)
    return uf("R_raises", 1, _BOOL)(t)


def _EXC(t: Any) -> Any:  # the exception an operation raises
    return uf("exc_of", 1)(t)


def _MATCHP(exc: Any, ty: Any) -> Any:  # does `except <ty>` match this exception
    return uf("M_isinst", 2, _BOOL)(exc, ty)


def _truth_rec(v: Any, ops: list | None) -> Any:
    """Truthiness of a value; inside a try body bool(v) is itself an operation that may raise."""
    if ops is not None and not z3.is_bool(v) and not (z3.is_app(v) and v.decl().eq(_BOX)):
        ops.append(uf("op_truth", 1)(v))
    return _truth(v)


def _enc(node: ast.AST, env: dict[str, Any], assigned: set[str], globals_: set[str],
         ops: list | None = None) -> Any:
    """Encode an expression to a V term or a Bool (only `not`, `in`, `not in` yield a real bool).

    ``ops`` (inside a try body only): the possibly-raising operations in evaluation order."""

    def e(n: ast.AST) -> Any:
        return _enc(n, env, assigned, globals_, ops)

    def rec(t: Any) -> Any:
        if ops is not None:
            ops.append(t)
        return t

    def cold(n: ast.AST) -> Any:  # evaluated only conditionally: no raising operation may hide there
        sub: list = []
        r = _enc(n, env, assigned, globals_, sub if ops is not None else None)
        if sub:
            raise UfUnmodeled("conditionally evaluated operation that may raise inside a try body")
        return r

    if isinstance(node, ast.Constant):
        return _const(node.value)
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in assigned:
            raise UfUnmodeled(f"{node.id!r} may be used before assignment")
        globals_.add(node.id)
        return konst(f"g_{node.id}")
    if isinstance(node, ast.UnaryOp):
        v = e(node.operand)
        if isinstance(node.op, ast.Not):
            return z3.Not(_truth_rec(v, ops))
        if type(node.op) in _UN:
            return rec(_op(f"u_{_UN[type(node.op)]}", _val(v)))
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
        l, r = _val(e(node.left)), _val(e(node.right))
        return rec(_op(f"b_{_BIN[type(node.op)]}", l, r))
    if isinstance(node, ast.BoolOp):  # Python returns an operand: a and b == (b if a else a)
        if ops is not None and len(node.values) > 2:
            raise UfUnmodeled("and/or over three or more operands inside a try body")
        vals = [_val(e(node.values[0]))] + [_val(cold(v)) for v in node.values[1:]]
        out = vals[-1]
        for i in range(len(vals) - 2, -1, -1):
            c = _truth_rec(vals[i], ops) if i == 0 else _truth(vals[i])
            out = z3.If(c, out, vals[i]) if isinstance(node.op, ast.And) else z3.If(c, vals[i], out)
        return out
    if isinstance(node, ast.Compare):
        if ops is not None and len(node.ops) > 1:
            raise UfUnmodeled("chained comparison inside a try body")
        terms: list[Any] = []
        left = e(node.left)
        prev_node = node.left
        for op, comp in zip(node.ops, node.comparators):
            right = e(comp)
            if type(op) in _CMP:
                terms.append(rec(_op(f"cmp_{_CMP[type(op)]}", _val(left), _val(right))))
            elif isinstance(op, (ast.In, ast.NotIn)):
                if ops is not None:
                    ops.append(uf("op_in", 2)(_val(left), _val(right)))
                b = _IN(_TRC[0], _val(left), _val(right))
                terms.append(_val(b if isinstance(op, ast.In) else z3.Not(b)))
            elif isinstance(op, (ast.Is, ast.IsNot)):
                none_l = isinstance(prev_node, ast.Constant) and prev_node.value is None
                none_r = isinstance(comp, ast.Constant) and comp.value is None
                if none_l == none_r:  # identity with anything but the None singleton is not modelled
                    raise UfUnmodeled(f"identity comparison `{ast.unparse(node)}` is not against None")
                eqb = _val(left if none_r else right) == NONE_T  # elements are objects: `x is None` iff x denotes None
                terms.append(_val(eqb if isinstance(op, ast.Is) else z3.Not(eqb)))
            left = right
            prev_node = comp
        out = terms[-1]  # chain: (c1 and c2 and ...) with and-operand semantics
        for t in reversed(terms[:-1]):
            out = z3.If(_truth(t), out, t)
        return out
    if isinstance(node, ast.IfExp):
        c = _truth_rec(e(node.test), ops)
        return z3.If(c, _val(cold(node.body)), _val(cold(node.orelse)))
    if isinstance(node, ast.Attribute):
        return rec(_op(f"attr_{node.attr}", _val(e(node.value))))
    if isinstance(node, ast.Call):
        f = node.func
        starred = any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords)
        args = [_val(e(f))] + [_val(e(a.value if isinstance(a, ast.Starred) else a)) for a in node.args] \
            + [_val(e(k.value)) for k in node.keywords]
        if starred:  # the layout (which positions are *x, which keywords are **x) is part of the symbol
            layout = "".join("S" if isinstance(a, ast.Starred) else "p" for a in node.args) + "|" + "_".join(
                k.arg or "**" for k in node.keywords)
            term = rec(_op(f"callstar_{layout}", *args))
        else:
            kn = "_".join(k.arg for k in node.keywords)
            term = rec(_op(f"call{len(node.args)}k_{kn}", *args))
        if _effectful_call(node):  # an impure/mutating call is an ordered effect, appended after it completes
            _effect(term)
        return term
    if isinstance(node, ast.Subscript):
        obj = _val(e(node.value))
        if isinstance(node.slice, ast.Slice):
            parts = [_val(e(p)) if p is not None else NONE_T for p in (node.slice.lower, node.slice.upper, node.slice.step)]
            return rec(_op("getitem", obj, uf("slice3", 3)(*parts)))
        if isinstance(node.slice, (ast.Tuple, ast.Starred)):
            raise UfUnmodeled(f"extended subscript `{ast.unparse(node)}`")
        return rec(_op("getitem", obj, _val(e(node.slice))))
    if isinstance(node, ast.Lambda):
        cap = _captured(node, env, _CUR_FN[0])
        return uf(f"lam_{_hash(node)}_{'-'.join(cap)}", len(cap))(*[env[c] for c in cap])
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        for x in ast.walk(node):
            if isinstance(x, (ast.Call,)) and _effectful_call(x):
                raise UfUnmodeled("effectful call inside a comprehension")
            if isinstance(x, (ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom)):
                raise UfUnmodeled(f"{type(x).__name__} inside a comprehension")
        cap = _captured(node, env, _CUR_FN[0])
        term = _op(f"comp_{_hash(node)}_{'-'.join(cap)}", *[env[c] for c in cap])
        return term if isinstance(node, ast.GeneratorExp) else rec(term)  # a list/set/dict builds eagerly
    if isinstance(node, ast.JoinedStr):
        vals: list[Any] = []
        skeleton: list[Any] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                skeleton.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                if part.format_spec is not None and not (isinstance(part.format_spec, ast.JoinedStr) and all(
                        isinstance(x, ast.Constant) for x in part.format_spec.values)):
                    raise UfUnmodeled("f-string with a computed format spec")
                skeleton.append(("F", part.conversion, ast.dump(part.format_spec) if part.format_spec else None))
                vals.append(_val(e(part.value)))
            else:
                raise UfUnmodeled("f-string part")
        h = hashlib.sha256(repr(skeleton).encode()).hexdigest()[:12]
        return rec(_op(f"fstr_{h}", *vals))
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        if any(isinstance(x, ast.Starred) for x in node.elts):
            raise UfUnmodeled("starred container element")
        return uf(f"mk_{type(node).__name__}{len(node.elts)}", len(node.elts))(*[_val(e(x)) for x in node.elts])
    if isinstance(node, ast.Dict):
        if any(k is None for k in node.keys):
            raise UfUnmodeled("dict unpacking")
        flat = [_val(e(x)) for kv in zip(node.keys, node.values) for x in kv]
        return uf(f"mk_Dict{len(node.keys)}", len(flat))(*flat)
    raise UfUnmodeled(f"unmodeled construct `{ast.unparse(node)[:80]}`")


def _check_root(node: ast.Attribute) -> None:
    n: ast.AST = node
    while isinstance(n, (ast.Attribute, ast.Call, ast.Subscript)):
        n = n.value if isinstance(n, (ast.Attribute, ast.Subscript)) else n.func
    if isinstance(n, ast.Name) and n.id in IMPURE_ROOTS:
        raise UfUnmodeled(f"use of impure module {n.id!r}")


def _split(ops: list | None, cur: Any, env_before: dict, rp: list | None) -> Any:
    """Route the exceptional paths of a statement's operations to ``rp``; return the normal-completion guard."""
    if not ops:
        return cur
    prefix: Any = z3.BoolVal(True)
    for t in ops:
        rp.append((z3.And(cur, prefix, _R(t)), _EXC(t), dict(env_before)))
        prefix = z3.And(prefix, z3.Not(_R(t)))
    return z3.And(cur, prefix)


def _merge(paths: list[tuple[Any, dict]]) -> dict[str, Any]:
    paths = [(c, e) for c, e in paths if not z3.is_false(z3.simplify(c))]
    if not paths:
        return {}
    common = set.intersection(*[set(e) for _, e in paths]) - {"__exc__"}
    out: dict[str, Any] = {}
    for k in common:
        v = paths[-1][1][k]
        for c, e in reversed(paths[:-1]):
            v = v if z3.eq(v, e[k]) else z3.If(c, e[k], v)
        out[k] = v
    return out


class _StripLoopCtl(ast.NodeTransformer):
    """break/continue only steer iteration; for the purity validation of a loop body they are no-ops."""

    def visit_Break(self, n: ast.Break) -> ast.AST:
        return ast.copy_location(ast.Pass(), n)

    visit_Continue = visit_Break  # noqa: N815


def _loop(st: ast.For | ast.While, env: dict[str, Any], cur: Any, assigned: set[str], globals_: set[str]):
    """A `for` loop as a deterministic black box keyed on its exact source and its entry state.

    Sound for RELATIONAL proofs only: pre and post run the identical loop (same source dump => same symbols)
    from an identical entry environment (every local, by name), so they leave identical state and take the same
    exits. Any edit to the loop changes its key and the outcomes differ. The body is validated with the same
    rules as straight-line code (effects are allowed; they are part of the black box). `while` is not modelled."""
    if isinstance(st, ast.While):
        names = []
        head = st.test
    else:
        tgt = st.target
        names = [tgt.id] if isinstance(tgt, ast.Name) else [e.id for e in tgt.elts] if isinstance(tgt, ast.Tuple) and all(
            isinstance(e, ast.Name) for e in tgt.elts) else None
        if names is None:
            raise UfUnmodeled("for-loop target is not a name or a tuple of names")
        head = st.iter
    _TRC[0] = env["__trace__"]
    _enc(head, env, assigned, globals_, None)  # the iterable / first test is evaluated in the entry state
    env = dict(env)
    env["__trace__"] = _TRC[0]  # effects of evaluating the iterable precede the loop
    scratch = dict(env)
    for n in names:
        scratch[n] = konst(f"loopvar_{n}")
    if isinstance(st, ast.While):  # the test is re-evaluated each time: validate it in the loop's own state
        _TRC[0] = scratch["__trace__"]
        _enc(st.test, scratch, assigned, globals_, None)
    body = [ast.fix_missing_locations(_StripLoopCtl().visit(__import__("copy").deepcopy(x))) for x in st.body + st.orelse]
    _exec(body, scratch, z3.BoolVal(True), assigned, globals_, False, None)  # validation only; result discarded
    for n in ast.walk(st):
        if isinstance(n, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Yield, ast.YieldFrom,
                          ast.Await, ast.Global, ast.Nonlocal, ast.Try, ast.With, ast.AsyncFor)) \
                or (isinstance(n, ast.Raise) and n.exc is None):
            raise UfUnmodeled(f"{type(n).__name__} inside a for-loop")
    key = hashlib.sha256(ast.dump(st).encode()).hexdigest()[:12]
    order = sorted(k for k in env if k != "__exc__")
    ent = [env[k] for k in order]
    tag = f"{key}_{'-'.join(order)}"
    written = {n.id for n in ast.walk(st) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    has_ret = any(isinstance(n, ast.Return) for n in ast.walk(st))
    has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(st))
    outs: list[tuple[Any, tuple]] = []
    n_ent = len(ent)
    if has_ret:
        lret = uf(f"lret_{tag}", n_ent, _BOOL)(*ent)
        outs.append((z3.And(cur, lret), ("ret", uf(f"lretv_{tag}", n_ent)(*ent), env["__trace__"])))
        cur = z3.And(cur, z3.Not(lret))
    if has_raise:
        lraise = uf(f"lraise_{tag}", n_ent, _BOOL)(*ent)
        outs.append((z3.And(cur, lraise), ("raise", uf(f"lexc_{tag}", n_ent)(*ent), "?", env["__trace__"])))
        cur = z3.And(cur, z3.Not(lraise))
    new_env = dict(env)
    for k in written:
        if k in env:  # a name first bound inside the loop stays unbound after it (an empty iterable binds nothing)
            new_env[k] = uf(f"lval_{tag}_{k}", n_ent)(*ent)
        else:
            new_env.pop(k, None)
    new_env["__trace__"] = uf(f"lval_{tag}___trace__", n_ent)(*ent)  # the loop's effects, as one black-box step
    return outs, cur, new_env


def _exec(stmts: list[ast.stmt], env: dict[str, Any], cond: Any, assigned: set[str], globals_: set[str],
          first: bool = True, rp: list | None = None) -> tuple[list[tuple[Any, tuple]], Any, dict[str, Any]]:
    """Symbolic execution. ``rp``: raise paths (guard, exception term, env) when inside a try body."""
    outs: list[tuple[Any, tuple]] = []
    cur = cond
    env = dict(env)
    for i, st in enumerate(stmts):
        ops: list | None = [] if rp is not None else None
        if isinstance(st, ast.Pass) or (first and i == 0 and isinstance(st, ast.Expr)
                                        and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str)):
            continue
        def enc_s(node: ast.AST) -> Any:  # encode within this statement, continuing the running effect trace
            return _enc(node, env, assigned, globals_, ops)

        def key_of(sl: ast.AST) -> Any:
            if isinstance(sl, ast.Slice):
                return uf("slice3", 3)(*[_val(enc_s(x)) if x is not None else NONE_T for x in (sl.lower, sl.upper, sl.step)])
            if isinstance(sl, (ast.Tuple, ast.Starred)):
                raise UfUnmodeled("extended subscript target")
            return _val(enc_s(sl))

        def store(tgt: ast.AST, val: Any, obj: Any = None, key: Any = None) -> None:
            if isinstance(tgt, ast.Attribute):
                o = obj if obj is not None else _val(enc_s(tgt.value))
                term = uf(f"store_{tgt.attr}", 3)(_TRC[0], o, val)
            elif isinstance(tgt, ast.Subscript):
                o = obj if obj is not None else _val(enc_s(tgt.value))
                k = key if key is not None else key_of(tgt.slice)
                term = uf("store_item", 4)(_TRC[0], o, k, val)
            else:
                raise UfUnmodeled(f"assignment target `{ast.unparse(tgt)[:40]}` is not a name, attribute or subscript")
            if ops is not None:
                ops.append(term)  # a store may raise
            _effect(term)  # and is an ordered effect

        _TRC[0] = env["__trace__"]
        if isinstance(st, ast.Assign):
            if len(st.targets) != 1:
                raise UfUnmodeled("chained assignment")
            tgt = st.targets[0]
            val = _val(enc_s(st.value))
            if isinstance(tgt, (ast.Tuple, ast.List)):
                names = [x.id for x in tgt.elts if isinstance(x, ast.Name)]
                if len(names) != len(tgt.elts) or not names:
                    raise UfUnmodeled("unpacking target is not a flat list of names")
                if ops is not None:
                    ops.append(uf(f"op_unpack{len(names)}", 1)(val))  # unpacking may raise (wrong length)
                trc = _TRC[0]
                cur = _split(ops, cur, env, rp)
                for i, nm in enumerate(names):
                    env[nm] = _op(f"unpack{len(names)}_{i}", val)
                env["__trace__"] = trc
                continue
            if isinstance(tgt, ast.Name):
                trc = _TRC[0]
                cur = _split(ops, cur, env, rp)
                env[tgt.id] = val
                env["__trace__"] = trc
            else:
                before = dict(env)
                store(tgt, val)
                trc = _TRC[0]
                cur = _split(ops, cur, before, rp)
                env["__trace__"] = trc
            continue
        if isinstance(st, ast.Delete):
            before = dict(env)
            for tgt in st.targets:
                if isinstance(tgt, ast.Attribute):
                    term = uf(f"del_attr_{tgt.attr}", 2)(_TRC[0], _val(enc_s(tgt.value)))
                elif isinstance(tgt, ast.Subscript):
                    term = uf("del_item", 3)(_TRC[0], _val(enc_s(tgt.value)), key_of(tgt.slice))
                else:
                    raise UfUnmodeled("del of a local name")
                if ops is not None:
                    ops.append(term)
                _effect(term)
            trc = _TRC[0]
            cur = _split(ops, cur, before, rp)
            env["__trace__"] = trc
            continue
        if isinstance(st, ast.FunctionDef):
            if st.decorator_list:
                raise UfUnmodeled(f"nested function {st.name} is decorated")
            cap = _captured(st, env, _CUR_FN[0])
            env[st.name] = uf(f"lam_{_hash(st)}_{'-'.join(cap)}", len(cap))(*[env[c] for c in cap])
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, (ast.Yield, ast.YieldFrom)):
            y = st.value
            if y.value is None:
                raise UfUnmodeled("bare yield")
            v = _val(enc_s(y.value))
            term = uf("yieldfrom" if isinstance(y, ast.YieldFrom) else "yield", 2)(_TRC[0], v)
            if ops is not None:
                ops.append(term)
            _effect(term)  # a yielded value is an ordered, observable effect
            trc = _TRC[0]
            cur = _split(ops, cur, env, rp)
            env["__trace__"] = trc
            continue
        if isinstance(st, ast.Expr):
            if not isinstance(st.value, ast.Call):
                raise UfUnmodeled(f"expression statement `{ast.unparse(st)[:50]}` is not a call")
            term = enc_s(st.value)
            if not _effectful_call(st.value):
                _effect(term)  # a call whose result is discarded exists for its effect
            trc = _TRC[0]
            cur = _split(ops, cur, env, rp)
            env["__trace__"] = trc
            continue
        if isinstance(st, ast.AnnAssign) and st.value is None and isinstance(st.target, ast.Name):
            continue  # a bare local annotation has no runtime effect (the name stays unbound)
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            if isinstance(st, ast.ImportFrom) and any(a.name == "*" for a in st.names):
                raise UfUnmodeled("star import")
            base = ("." * (st.level or 0) + (st.module or "")) if isinstance(st, ast.ImportFrom) else ""
            for al in st.names:
                full = f"{base}:{al.name}" if isinstance(st, ast.ImportFrom) else al.name
                key = full if (isinstance(st, ast.ImportFrom) or al.asname) else al.name.split(".")[0]
                term = konst(f"imp_{key}")
                if ops is not None:
                    ops.append(term)  # an import may raise ImportError
                cur = _split(ops, cur, env, rp)
                ops = [] if rp is not None else None
                env[al.asname or al.name.split(".")[0]] = term
            continue
        if isinstance(st, ast.AnnAssign):
            if not isinstance(st.target, ast.Name) or st.value is None:
                raise UfUnmodeled("annotated assignment without a local value")
            val = _val(enc_s(st.value))
            trc = _TRC[0]
            cur = _split(ops, cur, env, rp)
            env[st.target.id] = val
            env["__trace__"] = trc
            continue
        if isinstance(st, ast.AugAssign):
            if type(st.op) not in _BIN:
                raise UfUnmodeled("augmented assignment with an unsupported operator")
            opname = f"b_{_BIN[type(st.op)]}"
            before = dict(env)
            if isinstance(st.target, ast.Name):
                if st.target.id not in env:
                    raise UfUnmodeled("augmented assignment on an unknown local")
                operand = _val(enc_s(st.value))
                term = _op(opname, env[st.target.id], operand)
                if ops is not None:
                    ops.append(term)
                trc = _TRC[0]
                cur = _split(ops, cur, env, rp)
                env[st.target.id] = term
                env["__trace__"] = trc
                continue
            tobj = _val(enc_s(st.target.value))
            tkey = key_of(st.target.slice) if isinstance(st.target, ast.Subscript) else None
            if isinstance(st.target, ast.Attribute):
                load = _op(f"attr_{st.target.attr}", tobj)
            elif isinstance(st.target, ast.Subscript):
                load = _op("getitem", tobj, tkey)
            else:
                raise UfUnmodeled("augmented assignment target")
            if ops is not None:
                ops.append(load)
            operand = _val(enc_s(st.value))
            newv = _op(opname, load, operand)
            if ops is not None:
                ops.append(newv)
            store(st.target, newv, tobj, tkey)
            trc = _TRC[0]
            cur = _split(ops, cur, before, rp)
            env["__trace__"] = trc
            continue
        if isinstance(st, ast.Return):
            v = NONE_T if st.value is None else _val(enc_s(st.value))
            trc = _TRC[0]
            cur = _split(ops, cur, env, rp)
            outs.append((cur, ("ret", v, trc)))
            env["__trace__"] = trc
            return outs, z3.BoolVal(False), env
        if isinstance(st, ast.Raise):
            if st.cause is not None:
                raise UfUnmodeled("chained raise (from)")
            if st.exc is None:
                if "__exc__" not in env:
                    raise UfUnmodeled("bare raise outside an except handler")
                exc, head = env["__exc__"], "?"
            else:
                ex = st.exc.func if isinstance(st.exc, ast.Call) else st.exc
                if not isinstance(ex, ast.Name):
                    raise UfUnmodeled(f"raise of an unresolved expression `{ast.unparse(st.exc)[:60]}`")
                exc, head = _val(enc_s(st.exc)), ex.id
                trc = _TRC[0]
                cur = _split(ops, cur, env, rp)
                env["__trace__"] = trc
            if rp is not None:
                rp.append((cur, exc, dict(env)))
            else:
                outs.append((cur, ("raise", exc, head, env["__trace__"])))
            return outs, z3.BoolVal(False), env
        if isinstance(st, ast.If):
            t = _truth_rec(enc_s(st.test), ops)
            trc = _TRC[0]
            cur = _split(ops, cur, env, rp)
            env["__trace__"] = trc
            ob, cb, eb = _exec(st.body, env, z3.And(cur, t), assigned, globals_, False, rp)
            oe, ce, ee = _exec(st.orelse, env, z3.And(cur, z3.Not(t)), assigned, globals_, False, rp)
            outs += ob + oe
            merged: dict[str, Any] = {}
            for k in (set(eb) | set(ee)) - {"__exc__"}:
                if k in eb and k in ee:
                    merged[k] = eb[k] if eb[k] is ee[k] or z3.eq(eb[k], ee[k]) else z3.If(cb, eb[k], ee[k])
                elif (k in eb and z3.is_false(z3.simplify(ce))) or (k in ee and z3.is_false(z3.simplify(cb))):
                    merged[k] = eb.get(k, ee.get(k))
                elif k in env:
                    merged[k] = env[k]
                else:
                    raise UfUnmodeled(f"{k!r} is bound on one branch only")
            if "__exc__" in env:
                merged["__exc__"] = env["__exc__"]
            env = merged
            cur = z3.Or(cb, ce)
            continue
        if isinstance(st, ast.Try):
            if st.finalbody:
                raise UfUnmodeled("try/finally")
            if not st.handlers:
                raise UfUnmodeled("try without except handlers")
            inner: list = []
            ob, cb, eb = _exec(st.body, env, cur, assigned, globals_, False, inner)
            outs += ob
            normal = [(cb, eb)]
            if st.orelse:  # runs after a normal body; its exceptions are not caught by these handlers
                oe, ce, ee = _exec(st.orelse, eb, cb, assigned, globals_, False, rp)
                outs += oe
                normal = [(ce, ee)]
            conts = list(normal)
            for g, exc, env_r in inner:
                pending = g
                for h in st.handlers:
                    if h.type is None:
                        match: Any = z3.BoolVal(True)
                    else:
                        _TRC[0] = env_r["__trace__"]
                        match = _MATCHP(exc, _val(_enc(h.type, env_r, assigned, globals_, None)))
                    hg = z3.And(pending, match)
                    henv = dict(env_r)
                    henv["__exc__"] = exc
                    if h.name:
                        henv[h.name] = exc
                    oh, ch, eh = _exec(h.body, henv, hg, assigned, globals_, False, rp)
                    outs += oh
                    eh = {k: v for k, v in eh.items() if k != h.name}
                    if "__exc__" in env:
                        eh["__exc__"] = env["__exc__"]
                    else:
                        eh.pop("__exc__", None)
                    conts.append((ch, eh))
                    pending = z3.And(pending, z3.Not(match))
                if rp is not None:
                    rp.append((pending, exc, env_r))
                else:
                    outs.append((pending, ("raise", exc, "?", env_r["__trace__"])))
            cur = z3.Or(*[c for c, _ in conts])
            env = _merge(conts)
            if "__exc__" in conts[0][1]:
                env["__exc__"] = conts[0][1]["__exc__"]
            continue
        if isinstance(st, ast.With):
            if rp is not None:
                raise UfUnmodeled("with-statement inside a try body")
            if any(isinstance(n, ast.Raise) for x in st.body for n in ast.walk(x)):
                raise UfUnmodeled("raise inside a with-block: __exit__ may suppress it")
            for item in st.items:  # context managers are entered in order; __exit__ is pure and never suppresses
                _TRC[0] = env["__trace__"]
                cm = _val(_enc(item.context_expr, env, assigned, globals_, None))
                env["__trace__"] = uf("tr", 2)(_TRC[0], cm)  # entering is an ordered effect
                if item.optional_vars is not None:
                    if not isinstance(item.optional_vars, ast.Name):
                        raise UfUnmodeled("with-target is not a plain name")
                    env[item.optional_vars.id] = uf("with_enter", 1)(cm)
            ob, cur, env = _exec(st.body, env, cur, assigned, globals_, False, None)
            outs += ob
            continue
        if isinstance(st, (ast.For, ast.While)):
            if rp is not None:
                raise UfUnmodeled("loop inside a try body")
            outs_l, cur, env = _loop(st, env, cur, assigned, globals_)
            outs += outs_l
            continue
        raise UfUnmodeled(f"unmodeled statement `{ast.unparse(st).splitlines()[0][:60]}`")
    return outs, cur, env


# ------------------------------------------------------------------ module / signature context
def _top(tree: ast.Module, func: str) -> dict[str, str]:
    """Every top-level statement except the target (for a method: its class minus that one method), by name."""
    cls, _, meth = func.partition(".")
    out: dict[str, str] = {}
    for i, n in enumerate(tree.body):
        if not meth and isinstance(n, ast.FunctionDef) and n.name == func:
            continue
        if meth and isinstance(n, ast.ClassDef) and n.name == cls:
            n = ast.ClassDef(n.name, n.bases, n.keywords, [m for m in n.body if not (
                isinstance(m, ast.FunctionDef) and m.name == meth)], n.decorator_list)
        name = (n.name if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else
                ",".join(sorted(t.id for t in ast.walk(n) if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)))
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) else
                "|".join(a.asname or a.name for a in n.names) if isinstance(n, (ast.Import, ast.ImportFrom)) else
                f"#{i}")
        out[f"{type(n).__name__}:{name}"] = ast.dump(n)
    return out


def _params(fn: ast.FunctionDef) -> list[tuple[str, str]]:
    """(name, kind) in call order: positional (pos-only and ordinary), *args, keyword-only, **kwargs."""
    a = fn.args
    return ([(x.arg, "p") for x in a.posonlyargs + a.args] + ([(a.vararg.arg, "*")] if a.vararg else []) +
            [(x.arg, "k") for x in a.kwonlyargs] + ([(a.kwarg.arg, "**")] if a.kwarg else []))


def _sig(fn: ast.FunctionDef) -> list[tuple[str, str]]:
    a = fn.args
    out = [(x.arg, "pos-only" if i < len(a.posonlyargs) else "p") for i, x in enumerate(a.posonlyargs + a.args)]
    if a.vararg:
        out.append((a.vararg.arg, "*"))
    out += [(x.arg, "k") for x in a.kwonlyargs]
    if a.kwarg:
        out.append((a.kwarg.arg, "**"))
    out += [(f"default:{ast.dump(d)}", "d") for d in a.defaults]
    out += [(f"kwdefault:{ast.dump(d) if d is not None else '-'}", "kd") for d in a.kw_defaults]
    out.append(("generator" if _is_generator(fn) else "function", "g"))
    anns = [x.annotation for x in a.posonlyargs + a.args + a.kwonlyargs + ([a.vararg] if a.vararg else []) +
            ([a.kwarg] if a.kwarg else [])] + [fn.returns]
    out += [(f"annotation:{ast.dump(x) if x is not None else '-'}", "an") for x in anns]  # may raise when defined
    out.append((f"doc:{ast.get_docstring(fn, clean=False)!r}", "doc"))  # observable as f.__doc__
    return out


def _is_generator(fn: ast.FunctionDef) -> bool:
    def walk(n: ast.AST) -> bool:
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.Yield, ast.YieldFrom)):
                return True
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if walk(c):
                return True
        return False
    return walk(fn)


def _assigned(fn: ast.FunctionDef) -> set[str]:
    out = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    for n in ast.walk(fn):  # a name bound by a local import is local for the whole function
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            out |= {(a.asname or a.name).split(".")[0] for a in n.names}
        elif isinstance(n, ast.FunctionDef) and n is not fn:
            out.add(n.name)  # a nested def binds its name locally
    return out


_OK_DECOS = {"staticmethod", "classmethod", "property"}


def _find(tree: ast.Module, func: str) -> tuple[ast.FunctionDef, ast.ClassDef | None]:
    """A top-level function, or ``Class.method`` of a top-level class (self/cls are ordinary opaque parameters)."""
    if "." in func:
        cls, _, meth = func.partition(".")
        cs = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls]
        fns = [n for n in cs[0].body if isinstance(n, ast.FunctionDef) and n.name == meth] if len(cs) == 1 else []
        if len(cs) != 1 or len(fns) != 1 or "." in meth:
            raise UfUnmodeled(f"{func} is not a unique method of a top-level class")
        fn, owner = fns[0], cs[0]
    else:
        fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func]
        if len(fns) != 1:
            raise UfUnmodeled(f"{func} is not a unique top-level function")
        fn, owner = fns[0], None
    bad = [ast.unparse(d) for d in fn.decorator_list if not (isinstance(d, ast.Name) and d.id in _OK_DECOS)]
    if bad:
        raise UfUnmodeled(f"{func} has decorator(s) outside staticmethod/classmethod/property: {bad[:2]}")
    return fn, owner


def _dead_stores(fn: ast.FunctionDef) -> list[str]:
    """Locals bound by an assignment or import and never read: dropping or changing such a statement is
    invisible to a pure model, yet it is the usual way to call something for its effect."""
    loaded = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    bound: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            bound |= {t.id for t in n.targets if isinstance(t, ast.Name)}
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name) and getattr(n, "value", None):
            bound.add(n.target.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            bound |= {(a.asname or a.name).split(".")[0] for a in n.names}
    return sorted(bound - loaded)


def _prepare(tree: ast.Module, func: str) -> tuple[ast.FunctionDef, dict[str, Any], set[str]]:
    fn, _owner = _find(tree, func)
    dead = _dead_stores(fn)
    if dead:
        raise UfUnmodeled(f"local {dead[0]!r} is assigned but never read: the statement may exist for its effect")
    env: dict[str, Any] = {}
    for name, _kind in _params(fn):
        env[name] = konst(f"p_{name}")
    env["__trace__"] = konst("trace0")  # ordered effects so far (context managers entered)
    _CUR_FN[0] = fn
    return fn, env, _assigned(fn)


def _paths(fn: ast.FunctionDef, env: dict[str, Any], assigned: set[str]) -> tuple[list[tuple[Any, tuple]], set[str]]:
    globals_: set[str] = set()
    outs, cont, fenv = _exec(fn.body, env, z3.BoolVal(True), assigned - set(env), globals_)
    outs.append((cont, ("ret", NONE_T, fenv.get("__trace__", env["__trace__"]))))  # falling off the end returns None
    return outs, globals_


def _match(o: tuple, E: tuple) -> Any:
    if E[0] == "raise-type":
        return z3.BoolVal(o[0] == "raise" and o[2].rsplit(".", 1)[-1] == E[1])
    return z3.BoolVal(False) if o[0] != E[0] else o[1] == E[1]


def check_uf(base_src: str, post_src: str, func: str, deltas: list[dict] | None = None,
             python_version: tuple[int, ...] | None = None) -> tuple[str, str]:
    """('PROVED' | 'UNMODELED', reason). Never a counterexample. ``python_version`` is the TARGET interpreter's:
    it gates the exact identities in EXACT_FACTS (none apply without it)."""
    try:
        return _check(base_src, post_src, func, list(deltas or []), (), python_version)
    except UfUnmodeled as e:
        return "UNMODELED", f"UF: {e}"
    except (SyntaxError, RecursionError) as e:
        return "UNMODELED", f"UF: {type(e).__name__}: {e}"[:200]


_PURE_TOP = (ast.FunctionDef, ast.ClassDef, ast.Assign, ast.AnnAssign, ast.Import, ast.ImportFrom)
_MAX_DEPTH = 6


def _defined_names(n: ast.stmt) -> set[str]:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {n.name}
    out: set[str] = set()
    for x in ast.walk(n):
        if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
            out.add(x.id)
        elif isinstance(x, (ast.Import, ast.ImportFrom)):
            out |= {(a.asname or a.name).split(".")[0] for a in x.names}
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and x is not n:
            out.add(x.name)
    return out


_DYNAMIC_NAMES = {"globals", "locals", "vars", "eval", "exec", "compile", "__import__", "setattr", "delattr",
                  "importlib", "__builtins__", "builtins", "sys", "inspect"}
_DYNAMIC_MEMBERS = {"__getattr__", "__getattribute__", "__setattr__", "__delattr__", "__class_getitem__",
                    "__init_subclass__", "__set_name__", "__new__", "__call__"}


def _no_dynamic(n: ast.AST) -> None:
    """Anything that can read or rebind a name by a computed name, or change attribute lookup, defeats a slice."""
    for x in ast.walk(n):
        if isinstance(x, ast.Name) and x.id in _DYNAMIC_NAMES:
            raise UfUnmodeled(f"dynamic name access `{x.id}` inside the dependency slice")
        if isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id in ("getattr", "hasattr") and (
                len(x.args) < 2 or not (isinstance(x.args[1], ast.Constant) and isinstance(x.args[1].value, str))):
            raise UfUnmodeled("getattr/hasattr with a non-literal attribute name inside the dependency slice")
        if isinstance(x, ast.ClassDef):
            if x.keywords or any(isinstance(m, ast.FunctionDef) and m.name in _DYNAMIC_MEMBERS for m in x.body):
                raise UfUnmodeled(f"class {x.name} customises attribute lookup or creation (metaclass/__getattr__/...)")
        if isinstance(x, (ast.Global, ast.Nonlocal)):
            raise UfUnmodeled("global/nonlocal inside the dependency slice")


def _reads(n: ast.AST) -> set[str]:
    return {x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}


def _import_time_effects(tree: ast.Module) -> list[str]:
    """Top-level statements that DO something when the module loads (calls, loops, with, ...): never ignorable."""
    out = []
    for i, n in enumerate(tree.body):
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and any(
                isinstance(x, (ast.Attribute, ast.Subscript)) and isinstance(x.ctx, ast.Store) for x in ast.walk(n)):
            out.append(ast.dump(n))  # `mod.attr = v` / `d[k] = v` at import time: monkeypatching
            continue
        if isinstance(n, _PURE_TOP) or (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)):
            continue
        if isinstance(n, (ast.If, ast.Try)) and not any(isinstance(x, (ast.Expr, ast.For, ast.While, ast.With,
                                                                       ast.Delete, ast.AugAssign, ast.Raise))
                                                         for x in ast.walk(n)):
            continue  # a conditional that only defines names / imports (e.g. `try: import x / except: x = None`)
        out.append(ast.dump(n))
    return out


def _context_equal(base_src: str, post_src: str, bt: ast.Module, pt: ast.Module, func: str,
                   stack: tuple[str, ...], python_version: tuple[int, ...] | None = None) -> None:
    """Dependency slice: only what the target transitively READS has to behave the same on both sides.

    Unrelated imports, constants, classes and functions may change freely. A definition the target reads that DID
    change is acceptable only if it is a function (or the methods of a class) that is itself proved equal under
    the same rules (regression verification by induction; acyclic, bounded depth), or an identical definition.
    Anything that executes at import time must be unchanged."""
    if func in stack:
        return  # mutual recursion: equivalence of `func` is the induction hypothesis; its own proof discharges it
    if len(stack) >= _MAX_DEPTH:
        raise UfUnmodeled("dependency chain deeper than the proof bound")
    if sorted(_import_time_effects(bt)) != sorted(_import_time_effects(pt)):
        raise UfUnmodeled("a statement that runs at import time changed")
    cls, _, meth = func.partition(".")
    fnode, _own = _find(bt, func)

    def defs(tree: ast.Module) -> dict[str, list[ast.stmt]]:
        d: dict[str, list[ast.stmt]] = {}
        for n in tree.body:
            if isinstance(n, ast.FunctionDef) and not meth and n.name == func:
                continue  # the target itself is compared by the relational check
            for nm in _defined_names(n):
                d.setdefault(nm, []).append(n)
        return d

    for tree in (bt, pt):  # a star import may rebind any name; nothing in the slice can be trusted
        for n in tree.body:
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                raise UfUnmodeled("star import: names the target reads may be rebound")
    declared_global = {g for t in (bt, pt) for n in ast.walk(t) if isinstance(n, ast.Global) for g in n.names}
    db, dp = defs(bt), defs(pt)
    # the class of a method: everything in it except the method itself is read (self.helper(), class attributes)
    seeds = set(_reads(fnode))
    if meth:
        owner_b = next(n for n in bt.body if isinstance(n, ast.ClassDef) and n.name == cls)
        owner_p = next(n for n in pt.body if isinstance(n, ast.ClassDef) and n.name == cls)
        _class_equal(base_src, post_src, owner_b, owner_p, cls, stack + (func,), skip=meth, python_version=python_version)
        seeds |= _reads(owner_b) - {cls}
    for tree_nodes in ([fnode], [owner_b] if meth else []):
        for n in tree_nodes:
            _no_dynamic(n)
    seen: set[str] = set()
    work = sorted(seeds)
    while work:
        name = work.pop()
        if name in seen:
            continue
        seen.add(name)
        bn, pn = db.get(name, []), dp.get(name, [])
        if not bn and not pn:
            continue  # a builtin or an unbound name: the same on both sides
        if name in declared_global or len(bn) > 1 or len(pn) > 1:
            raise UfUnmodeled(f"{name!r}, which {func} reads, is rebound or defined more than once in module scope")
        for x in bn + pn:
            _no_dynamic(x)
        if [ast.dump(x) for x in bn] != [ast.dump(x) for x in pn]:
            if len(bn) == 1 and len(pn) == 1 and isinstance(bn[0], ast.FunctionDef) and isinstance(pn[0], ast.FunctionDef):
                if name not in stack and name != func:
                    _check(base_src, post_src, name, [], stack + (func,), python_version)  # a changed callee must itself be proved equal
            elif len(bn) == 1 and len(pn) == 1 and isinstance(bn[0], ast.ClassDef) and isinstance(pn[0], ast.ClassDef):
                _class_equal(base_src, post_src, bn[0], pn[0], name, stack + (func,), python_version=python_version)
            else:
                raise UfUnmodeled(f"{name!r}, which {func} reads, is defined differently ({type(bn[0]).__name__ if bn else 'absent'}"
                                  f" -> {type(pn[0]).__name__ if pn else 'absent'})")
        for x in bn:
            work.extend(sorted(_reads(x) - seen))


def _class_equal(base_src: str, post_src: str, cb: ast.ClassDef, cp: ast.ClassDef, cls: str,
                 stack: tuple[str, ...], skip: str | None = None, python_version: tuple[int, ...] | None = None) -> None:
    """A class read by the target. Bases, decorators and keywords must be identical. A non-method class statement
    or a member that appears or disappears matters only if something in the class reads it (self.x / cls.x /
    Class.x) or it is a dunder (implicitly invoked by operators); a changed method must be proved equal."""
    def split(c: ast.ClassDef):
        ms = {m.name: m for m in c.body if isinstance(m, ast.FunctionDef) and m.name != skip}
        rest: dict[str, list[str]] = {}
        for m in c.body:
            if isinstance(m, ast.FunctionDef):
                continue
            for nm in (_defined_names(m) or {f"#{ast.dump(m)[:40]}"}):
                rest.setdefault(nm, []).append(ast.dump(m))
        return ms, rest

    mb, rb = split(cb)
    mp, rp = split(cp)
    head = lambda c: [ast.dump(x) for x in c.bases] + [ast.dump(x) for x in c.keywords] + [ast.dump(x) for x in c.decorator_list]  # noqa: E731
    if head(cb) != head(cp):
        raise UfUnmodeled(f"class {cls}: bases, decorators or class keywords changed")
    referenced = {x.attr for c in (cb, cp) for x in ast.walk(c) if isinstance(x, ast.Attribute)}
    for nm in sorted(set(rb) | set(rp)):
        if rb.get(nm) != rp.get(nm) and (nm in referenced or nm.startswith("__") or nm.startswith("#")):
            raise UfUnmodeled(f"class {cls}: attribute {nm!r}, which the class reads, changed")
    for nm in sorted(set(mb) ^ set(mp)):
        if nm in referenced or nm.startswith("__"):
            raise UfUnmodeled(f"class {cls}: method {nm!r} was added or removed and may be invoked")
    for name in sorted(set(mb) & set(mp)):
        if ast.dump(mb[name]) != ast.dump(mp[name]):
            if f"{cls}.{name}" not in stack:
                _check(base_src, post_src, f"{cls}.{name}", [], stack, python_version)  # a changed sibling must be proved equal too


def _check(base_src: str, post_src: str, func: str, deltas: list[dict], stack: tuple[str, ...] = (),
           python_version: tuple[int, ...] | None = None) -> tuple[str, str]:
    bt, used_b = canonicalise(ast.parse(base_src), python_version)
    pt, used_p = canonicalise(ast.parse(post_src), python_version)
    facts = sorted(set(used_b) | set(used_p))
    base_src, post_src = ast.unparse(bt), ast.unparse(pt)  # callee proofs re-parse these canonical sources
    bf_env = _prepare(bt, func)
    pf_env = _prepare(pt, func)
    (bf, benv, bas), (pf, penv, pas_) = bf_env, pf_env
    if _sig(bf) != _sig(pf) or [ast.dump(d) for d in bf.decorator_list] != [ast.dump(d) for d in pf.decorator_list]:
        raise UfUnmodeled("signature (parameters, defaults) or decorators changed")
    # the proof assumes everything the function (transitively) reads outside itself behaves the same on both sides
    _context_equal(base_src, post_src, bt, pt, func, stack, python_version)
    outs_b, gb = _paths(bf, benv, bas)
    outs_p, gp = _paths(pf, penv, pas_)
    s = z3.Solver()
    s.set("rlimit", _SOLVER_MS * _RL_PER_MS)  # deterministic work budget; wall timeout only as a 200x last-resort net
    s.set("timeout", _SOLVER_MS * 200)
    s.add(*_axioms())
    for tag, outs in (("pre", outs_b), ("post", outs_p)):
        s.push()
        s.add(z3.Not(z3.Or(*[g for g, _ in outs])))
        r = s.check()
        s.pop()
        if r != z3.unsat:
            raise UfUnmodeled(f"the {tag}-change path conditions are not proven exhaustive; no path may be dropped")
    dvs = []
    _TRC[0] = penv["__trace__"]  # delta predicates are about the entry state
    for d in deltas:
        pred, exp = d.get("predicate") or {}, d.get("expected") or {}
        if pred.get("type") != "expr" or not isinstance(pred.get("expr"), str):
            raise UfUnmodeled(f"delta {d.get('id')!r}: predicate is not an expression")
        gl: set[str] = set()
        P = _truth(_enc(ast.parse(pred["expr"], mode="eval").body, penv, set(), gl))
        if exp.get("kind") == "returns" and isinstance(exp.get("value_repr"), str):
            E: tuple = ("ret", _val(_enc(ast.parse(exp["value_repr"], mode="eval").body, penv, set(), gl)))
        elif exp.get("kind") == "raises" and isinstance(exp.get("exc_type"), str):
            E = ("raise-type", exp["exc_type"].rsplit(".", 1)[-1])
        else:
            raise UfUnmodeled(f"delta {d.get('id')!r}: expected kind not modelled")
        dvs.append((P, E))
    anyP = z3.Or(*[P for P, _ in dvs]) if dvs else z3.BoolVal(False)

    def eq(a: tuple, b: tuple) -> Any:
        if a[0] != b[0]:
            return z3.BoolVal(False)
        return z3.And(a[1] == b[1], a[-1] == b[-1])  # value (or full exception term) AND the effect trace

    vcs = [z3.And(P, z3.Not(z3.Or(*[z3.And(g, _match(o, E)) for g, o in outs_p]))) for P, E in dvs]
    vcs.append(z3.And(z3.Not(anyP), z3.Or(*[z3.And(gb_, gp_, z3.Not(eq(ob, op)))
                                            for gb_, ob in outs_b for gp_, op in outs_p])))
    for i, vc in enumerate(vcs):
        s.push()
        s.add(vc)
        r = s.check()
        s.pop()
        if r == z3.unknown:
            raise UfUnmodeled(f"solver undecided within {_SOLVER_MS} ms")
        if r == z3.sat:
            raise UfUnmodeled(
                f"{'VC2: outside the delta predicates' if i == len(vcs) - 1 else 'VC1: a declared delta'} the two "
                "versions differ under some callee interpretation; no concrete witness exists in UF mode (the "
                "differential supplies witnesses)")
    note = (" Assuming: " + "; ".join(f"{f} (py>={'.'.join(map(str, next(x[1] for x in EXACT_FACTS if x[0] == f)))})"
                                    for f in facts) + ".") if facts else ""
    note = (" Assuming " + "; ".join(f"{f} (py>={'.'.join(map(str, next(x[1] for x in EXACT_FACTS if x[0] == f)))})"
                                   for f in facts) + ".") if facts else ""
    return "PROVED", (
        "[UF, conditional] post == pre, deltas hold, for ANY deterministic callee semantics with the same ordered "
        "effects (assumed, not verified); partial equivalence; nothing else read changed; no witness." + note)


def assumptions_of(reason: str, has_deltas: bool = False) -> list[str]:
    """The premises a UF PROVED stands on, as a list. The first is always the callee premise: UF treats every
    callee/attribute read outside the function as an uninterpreted deterministic function that is the same on both
    sides, with the same ordered effects. That premise is ASSUMED, never verified, so UF can not stand alone."""
    out = ["every callee and outside read behaves as a deterministic function that is identical on both sides "
           "with the same ordered effects (assumed, not verified)",
           "partial equivalence: termination and exceptions of callees are not proved"]
    if " Assuming" in reason:
        facts = reason.split(" Assuming", 1)[1].lstrip(": ").rstrip(".")
        out.append(f"exact identities (version-gated by the target interpreter): {facts}")
    if has_deltas:
        out.append("declared delta(s) are taken as given: the operator's claim, not proved to be intended")
    return out


# ------------------------------------------------------------------ soundness oracle: real execution vs encoding
K = 6  # size of the concrete value domain of an interpretation


class _Interp:
    """A random but fixed interpretation of every opaque symbol: ops, constants, truthiness, `in`, boxing."""

    def __init__(self, seed: int) -> None:
        self.seed = seed

    def _h(self, *key: Any) -> int:
        return int(hashlib.sha256(repr((self.seed, *key)).encode()).hexdigest()[:12], 16)

    def const(self, name: str) -> int:
        if name == "k_NoneType_none":
            return self.NONE_EL
        return 1 + self._h("c", name) % (K - 3)  # a constant is neither None nor a boxed bool

    def op(self, name: str, *args: int) -> int:
        return self._h("o", name, args) % (K - 2)

    NONE_EL = 0  # the None object; boxed bools are K-2 (False) and K-1 (True)

    def truth(self, tr: int, v: int) -> bool:
        if v >= K - 2:  # the two boxed bools: truthiness of a real bool is that bool
            return v == K - 1
        if v == self.NONE_EL:  # bool(None) is False
            return False
        return self._h("T", tr, v) % 2 == 0

    def inn(self, tr: int, a: int, b: int) -> bool:
        return self._h("in", tr, a, b) % 2 == 0

    def raises(self, v: int) -> bool:  # does the operation that produced element v raise (inside a try body)
        return self._h("R", v) % 4 == 0

    def matches(self, exc: int, ty: int) -> bool:  # does `except ty` match exc
        return self._h("M", exc, ty) % 2 == 0

    def box(self, b: bool) -> int:
        return K - 2 + int(bool(b))


def _ev(e: Any, I: _Interp, memo: dict) -> Any:
    key = e.get_id()
    if key in memo:
        return memo[key]
    k = e.decl().kind() if z3.is_app(e) else None
    n = e.num_args() if z3.is_app(e) else 0
    if k == z3.Z3_OP_TRUE:
        r: Any = True
    elif k == z3.Z3_OP_FALSE:
        r = False
    elif k == z3.Z3_OP_NOT:
        r = not _ev(e.arg(0), I, memo)
    elif k == z3.Z3_OP_AND:
        r = all(_ev(e.arg(i), I, memo) for i in range(n))
    elif k == z3.Z3_OP_OR:
        r = any(_ev(e.arg(i), I, memo) for i in range(n))
    elif k == z3.Z3_OP_ITE:
        r = _ev(e.arg(1), I, memo) if _ev(e.arg(0), I, memo) else _ev(e.arg(2), I, memo)
    elif k == z3.Z3_OP_EQ:
        r = _ev(e.arg(0), I, memo) == _ev(e.arg(1), I, memo)
    elif k == z3.Z3_OP_UNINTERPRETED:
        name = e.decl().name()
        args = [_ev(e.arg(i), I, memo) for i in range(n)]
        if name == "T":
            r = I.truth(args[0], args[1])
        elif name == "in_pred":
            r = I.inn(args[0], args[1], args[2])
        elif name == "boxb":
            r = I.box(args[0])
        elif name == "R_raises":
            r = I.raises(args[0])
        elif name == "M_isinst":
            r = I.matches(args[0], args[1])
        elif n == 0:
            r = I.const(name)
        else:
            r = I.op(name, *args)
    else:
        raise AssertionError(f"oracle cannot evaluate {e}")
    memo[key] = r
    return r


class _Raised:
    def __init__(self, v: int) -> None:
        self.v = v


class _Exc(Exception):
    def __init__(self, v: int) -> None:
        super().__init__(v)
        self.v = v


def _real_outcome(src: str, func: str, params: list[str], I: _Interp, args: dict[str, int]) -> tuple[str, int]:
    """Run the REAL function body (Python control flow, short-circuit, scoping, try/except) over table-backed
    values. Inside a try body every operation may raise, as the interpretation decides."""
    state = {"depth": 0, "trace": I.const("trace0")}

    def new(v: int) -> "O":
        if state["depth"] > 0 and I.raises(v):
            raise _Exc(I.op("exc_of", v))
        return O(v)

    class O:
        __hash__ = object.__hash__

        def __init__(self, v: int) -> None:
            self._uv = v

        def _o(self, name: str, *xs: Any) -> "O":
            return new(I.op(name, state["trace"], self._uv, *[_el(x) for x in xs]))

        def __getattribute__(self, n: str) -> Any:
            if n == "_uv":
                return object.__getattribute__(self, n)
            # EVERY explicit attribute access is an opaque read, including names that happen to exist on this
            # wrapper (x.__init__, x.__class__): special-method lookup by Python itself goes through the type
            return new(I.op(f"attr_{n}", state["trace"], object.__getattribute__(self, "_uv")))

        def __call__(self, *a: Any, **kw: Any) -> "O":
            kn = "_".join(kw)
            return new(I.op(f"call{len(a)}k_{kn}", state["trace"], self._uv, *[_el(x) for x in a], *[_el(x) for x in kw.values()]))

        def __getitem__(self, key: Any) -> "O":
            if isinstance(key, slice):
                key = O(I.op("slice3", *[_el(p) for p in (key.start, key.stop, key.step)]))
            return new(I.op("getitem", state["trace"], self._uv, _el(key)))

        def __enter__(self) -> "O":
            state["trace"] = I.op("tr", state["trace"], self._uv)
            return O(I.op("with_enter", self._uv))

        def __exit__(self, *exc: Any) -> bool:
            return False  # never suppresses: the modelled __exit__ is pure

        def __iter__(self):  # a finite, table-determined sequence of table-determined elements
            k = I._h("iterlen", self._uv) % 4
            return iter([O(I.op("iter_elem", self._uv, i)) for i in range(k)])

        def __bool__(self) -> bool:
            new(I.op("op_truth", self._uv))
            return I.truth(state["trace"], self._uv)

        def __contains__(self, item: Any) -> bool:
            new(I.op("op_in", _el(item), self._uv))
            return I.inn(state["trace"], _el(item), self._uv)

        def __neg__(self) -> "O":
            return new(I.op("u_USub", state["trace"], self._uv))

        def __pos__(self) -> "O":
            return new(I.op("u_UAdd", state["trace"], self._uv))

        def __invert__(self) -> "O":
            return new(I.op("u_Invert", state["trace"], self._uv))

    def _el(x: Any) -> int:
        if isinstance(x, O):
            return x._uv
        if x is None:
            return I.const("k_NoneType_none")
        if isinstance(x, bool):
            return I.box(x)
        return I.const(_kname(x))

    def mk_bin(name: str, rev: bool):
        def f(self: Any, other: Any) -> O:
            a, b = (_el(other), self._uv) if rev else (self._uv, _el(other))
            return new(I.op(name, state["trace"], a, b))
        return f

    for sym, nm in (("add", "Add"), ("sub", "Sub"), ("mul", "Mult"), ("truediv", "Div"), ("floordiv", "FloorDiv"),
                    ("mod", "Mod"), ("pow", "Pow"), ("lshift", "LShift"), ("rshift", "RShift"), ("and", "BitAnd"),
                    ("or", "BitOr"), ("xor", "BitXor"), ("matmul", "MatMult")):
        setattr(O, f"__{sym}__", mk_bin(f"b_{nm}", False))
        setattr(O, f"__r{sym}__", mk_bin(f"b_{nm}", True))
    for sym, nm in (("eq", "Eq"), ("ne", "NotEq"), ("lt", "Lt"), ("le", "LtE"), ("gt", "Gt"), ("ge", "GtE")):
        setattr(O, f"__{sym}__", mk_bin(f"cmp_{nm}", False))

    class XForm(ast.NodeTransformer):
        def visit_Constant(self, n: ast.Constant) -> ast.AST:
            if n.value is None or isinstance(n.value, bool):
                return n  # real None / real bool: both are modelled as such (boxed bool, None element)
            return ast.copy_location(ast.Call(ast.Name("_K", ast.Load()), [ast.Constant(repr(n.value)),
                                              ast.Constant(type(n.value).__name__)], []), n)

        tmp = [0]
        wcount = [0]

        def _cap(self, node: ast.AST) -> list[str]:
            free = {x.id for x in ast.walk(node) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)} - _bound_in(node)
            return sorted(n for n in free if n in local_names)

        def visit_Lambda(self, n: ast.Lambda) -> ast.AST:
            cap = self._cap(n)
            tag = f"{_hash(n)}_{'-'.join(cap)}"
            return ast.copy_location(ast.Call(ast.Name("_LAM", ast.Load()), [ast.Constant(tag)] + [
                ast.Name(c, ast.Load()) for c in cap], []), n)

        def visit_FunctionDef(self, n: ast.FunctionDef) -> Any:
            if n is fn:
                return self.generic_visit(n)
            cap = self._cap(n)
            tag = f"{_hash(n)}_{'-'.join(cap)}"
            return ast.copy_location(ast.Assign([ast.Name(n.name, ast.Store())], ast.Call(
                ast.Name("_LAM", ast.Load()), [ast.Constant(tag)] + [ast.Name(c, ast.Load()) for c in cap], [])), n)

        def _comp(self, n: ast.AST, eager: bool) -> ast.AST:
            cap = self._cap(n)
            tag = f"{_hash(n)}_{'-'.join(cap)}"
            return ast.copy_location(ast.Call(ast.Name("_COMP", ast.Load()), [ast.Constant(tag), ast.Constant(eager)] + [
                ast.Name(c, ast.Load()) for c in cap], []), n)

        def visit_ListComp(self, n: ast.ListComp) -> ast.AST:
            return self._comp(n, True)

        visit_SetComp = visit_DictComp = visit_ListComp  # noqa: N815

        def visit_GeneratorExp(self, n: ast.GeneratorExp) -> ast.AST:
            return self._comp(n, False)

        def visit_JoinedStr(self, n: ast.JoinedStr) -> ast.AST:
            vals, skeleton = [], []
            for part in n.values:
                if isinstance(part, ast.Constant):
                    skeleton.append(part.value)
                else:
                    skeleton.append(("F", part.conversion, ast.dump(part.format_spec) if part.format_spec else None))
                    vals.append(self.visit(part.value))
            h = hashlib.sha256(repr(skeleton).encode()).hexdigest()[:12]
            return ast.copy_location(ast.Call(ast.Name("_FSTR", ast.Load()), [ast.Constant(h)] + vals, []), n)

        def visit_For(self, n: ast.For) -> Any:
            n = self.generic_visit(n)
            if isinstance(n.target, ast.Tuple) and all(isinstance(x, ast.Name) for x in n.target.elts):
                self.tmp[0] += 1
                tn = f"_ft{self.tmp[0]}"
                k = len(n.target.elts)
                pre = [ast.Assign([ast.Name(x.id, ast.Store())], ast.Call(ast.Name("_UNPACK", ast.Load()), [
                    ast.Name(tn, ast.Load()), ast.Constant(i), ast.Constant(k)], [])) for i, x in enumerate(n.target.elts)]
                n.target = ast.Name(tn, ast.Store())
                n.body = pre + n.body
            return n

        def visit_While(self, n: ast.While) -> Any:
            self.wcount[0] += 1
            w = f"_w{self.wcount[0]}"
            n = self.generic_visit(n)
            n.test = ast.BoolOp(ast.And(), [n.test, ast.Call(ast.Name(w, ast.Load()), [], [])])
            return [ast.copy_location(ast.Assign([ast.Name(w, ast.Store())], ast.Call(ast.Name("_WB", ast.Load()), [], [])), n), n]

        def visit_Call(self, n: ast.Call) -> ast.AST:
            eff = _effectful_call(n)
            star = any(isinstance(a, ast.Starred) for a in n.args) or any(k.arg is None for k in n.keywords)
            n = self.generic_visit(n)
            if star:
                layout = "".join("S" if isinstance(a, ast.Starred) else "p" for a in n.args) + "|" + "_".join(
                    k.arg or "**" for k in n.keywords)
                n = ast.copy_location(ast.Call(ast.Name("_CALLSTAR", ast.Load()), [ast.Constant(layout), n.func] + [
                    a.value if isinstance(a, ast.Starred) else a for a in n.args] + [k.value for k in n.keywords], []), n)
            if eff:
                return ast.copy_location(ast.Call(ast.Name("_EFF", ast.Load()), [n], []), n)
            return n

        def visit_Expr(self, n: ast.Expr) -> ast.AST:
            if isinstance(n.value, (ast.Yield, ast.YieldFrom)):
                kind = "yieldfrom" if isinstance(n.value, ast.YieldFrom) else "yield"
                return ast.copy_location(ast.Expr(ast.Call(ast.Name("_YIELD", ast.Load()), [
                    ast.Constant(kind), self.visit(n.value.value)], [])), n)
            if isinstance(n.value, ast.Call) and not _effectful_call(n.value):
                inner = self.generic_visit(n)
                inner.value = ast.copy_location(ast.Call(ast.Name("_EFF", ast.Load()), [inner.value], []), inner.value)
                return inner
            return self.generic_visit(n)

        def _mkstore(self, tgt: ast.AST, val: ast.expr) -> ast.stmt:
            if isinstance(tgt, ast.Attribute):
                fn: ast.expr = ast.Call(ast.Name("_SETATTR_", ast.Load()), [ast.Constant(tgt.attr)], [])
                args = [val, self.visit(tgt.value)]
            else:
                fn = ast.Name("_SETITEM", ast.Load())
                sl = tgt.slice
                key = ast.Call(ast.Name("_SLICE", ast.Load()), [x if x is not None else ast.Constant(None)
                                                              for x in (sl.lower, sl.upper, sl.step)], []) \
                    if isinstance(sl, ast.Slice) else sl
                args = [val, self.visit(tgt.value), self.visit(key)]
            return ast.Expr(ast.Call(fn, args, []))

        def visit_Assign(self, n: ast.Assign) -> Any:
            tgt = n.targets[0] if len(n.targets) == 1 else None
            if isinstance(tgt, (ast.Tuple, ast.List)) and all(isinstance(x, ast.Name) for x in tgt.elts):
                self.tmp[0] += 1
                tn = f"_tu{self.tmp[0]}"
                k = len(tgt.elts)
                out = [ast.Assign([ast.Name(tn, ast.Store())], self.visit(n.value))]
                for i, x in enumerate(tgt.elts):
                    out.append(ast.Assign([ast.Name(x.id, ast.Store())], ast.Call(
                        ast.Name("_UNPACK", ast.Load()), [ast.Name(tn, ast.Load()), ast.Constant(i), ast.Constant(k)], [])))
                return [ast.copy_location(x, n) for x in out]
            if isinstance(tgt, (ast.Attribute, ast.Subscript)):
                return ast.copy_location(self._mkstore(tgt, self.visit(n.value)), n)
            return self.generic_visit(n)

        def visit_AugAssign(self, n: ast.AugAssign) -> Any:
            if not isinstance(n.target, (ast.Attribute, ast.Subscript)):
                return self.generic_visit(n)
            self.tmp[0] += 1
            o, k = f"_t{self.tmp[0]}o", f"_t{self.tmp[0]}k"
            pre: list[ast.stmt] = [ast.Assign([ast.Name(o, ast.Store())], self.visit(n.target.value))]
            if isinstance(n.target, ast.Attribute):
                cur: ast.expr = ast.Attribute(ast.Name(o, ast.Load()), n.target.attr, ast.Load())
                tgt2: ast.AST = ast.Attribute(ast.Name(o, ast.Load()), n.target.attr, ast.Store())
            else:
                sl = n.target.slice
                keyexpr = ast.Call(ast.Name("_SLICE", ast.Load()), [self.visit(x) if x is not None else ast.Constant(None)
                                                                  for x in (sl.lower, sl.upper, sl.step)], []) \
                    if isinstance(sl, ast.Slice) else self.visit(sl)
                pre.append(ast.Assign([ast.Name(k, ast.Store())], keyexpr))
                cur = ast.Subscript(ast.Name(o, ast.Load()), ast.Name(k, ast.Load()), ast.Load())
                tgt2 = ast.Subscript(ast.Name(o, ast.Load()), ast.Name(k, ast.Load()), ast.Store())
            newval = ast.BinOp(cur, n.op, self.visit(n.value))
            st = self._mkstore(tgt2, newval)
            return [ast.copy_location(x, n) for x in pre + [st]]

        def visit_Delete(self, n: ast.Delete) -> Any:
            out = []
            for tgt in n.targets:
                if isinstance(tgt, ast.Attribute):
                    fn: ast.expr = ast.Call(ast.Name("_DELATTR_", ast.Load()), [ast.Constant(tgt.attr)], [])
                    out.append(ast.Expr(ast.Call(fn, [self.visit(tgt.value)], [])))
                else:
                    sl = tgt.slice
                    key = ast.Call(ast.Name("_SLICE", ast.Load()), [self.visit(x) if x is not None else ast.Constant(None)
                                                                  for x in (sl.lower, sl.upper, sl.step)], []) \
                        if isinstance(sl, ast.Slice) else self.visit(sl)
                    out.append(ast.Expr(ast.Call(ast.Name("_DELITEM", ast.Load()), [self.visit(tgt.value), key], [])))
            return [ast.copy_location(x, n) for x in out]

        def _imp(self, n: ast.AST) -> list[ast.stmt]:
            out: list[ast.stmt] = []
            base = ("." * (getattr(n, "level", 0) or 0) + (getattr(n, "module", None) or "")) \
                if isinstance(n, ast.ImportFrom) else ""
            for al in n.names:
                full = f"{base}:{al.name}" if isinstance(n, ast.ImportFrom) else al.name
                key = full if (isinstance(n, ast.ImportFrom) or al.asname) else al.name.split(".")[0]
                out.append(ast.Assign([ast.Name(al.asname or al.name.split(".")[0], ast.Store())],
                                      ast.Call(ast.Name("_IMP", ast.Load()), [ast.Constant(f"imp_{key}")], [])))
            return out

        def visit_Import(self, n: ast.Import) -> Any:
            return self._imp(n)

        def visit_ImportFrom(self, n: ast.ImportFrom) -> Any:
            return self._imp(n)

        def visit_Compare(self, n: ast.Compare) -> ast.AST:
            if len(n.ops) == 1 and isinstance(n.ops[0], (ast.Is, ast.IsNot)):
                other = n.left if isinstance(n.comparators[0], ast.Constant) else n.comparators[0]
                call = ast.Call(ast.Name("_ISNONE", ast.Load()), [self.visit(other)], [])
                out: ast.AST = call if isinstance(n.ops[0], ast.Is) else ast.UnaryOp(ast.Not(), call)
                return ast.copy_location(out, n)
            return self.generic_visit(n)

        def visit_Raise(self, n: ast.Raise) -> ast.AST:
            if n.exc is None:
                return n
            return ast.copy_location(ast.Raise(ast.Call(ast.Name("_EXCN", ast.Load()), [self.visit(n.exc)], []), None), n)

        counter = [0]

        def visit_Try(self, n: ast.Try) -> ast.AST:
            self.counter[0] += 1
            ev = f"_e{self.counter[0]}"
            call = lambda nm: ast.Expr(ast.Call(ast.Name(nm, ast.Load()), [], []))  # noqa: E731
            body = [call("_ENTER"), ast.Try([self.visit(x) for x in n.body], [], [], [call("_EXIT")])]
            chain: list[ast.stmt] = [ast.Raise(None, None)]  # no handler matches: re-raise
            for h in reversed(n.handlers):
                test: ast.expr = ast.Constant(True) if h.type is None else ast.Call(
                    ast.Name("_MATCH", ast.Load()), [self.visit(h.type), ast.Attribute(ast.Name(ev, ast.Load()), "v", ast.Load())], [])
                pre = [] if not h.name else [ast.Assign([ast.Name(h.name, ast.Store())], ast.Call(
                    ast.Name("_OBJ", ast.Load()), [ast.Attribute(ast.Name(ev, ast.Load()), "v", ast.Load())], []))]
                chain = [ast.If(test, pre + [self.visit(x) for x in h.body], chain)]
            return ast.copy_location(ast.Try(
                body, [ast.ExceptHandler(ast.Name("_EXC", ast.Load()), ev, chain)],
                [self.visit(x) for x in n.orelse], []), n)

        def _mk(self, n: ast.AST, kind: str, elts: list) -> ast.AST:
            return ast.copy_location(ast.Call(ast.Name("_MK", ast.Load()), [ast.Constant(f"mk_{kind}{len(elts)}")] +
                                              [self.visit(x) for x in elts], []), n)

        def visit_Tuple(self, n: ast.Tuple) -> ast.AST:
            return self._mk(n, "Tuple", n.elts) if isinstance(n.ctx, ast.Load) else n

        def visit_List(self, n: ast.List) -> ast.AST:
            return self._mk(n, "List", n.elts) if isinstance(n.ctx, ast.Load) else n

        def visit_Set(self, n: ast.Set) -> ast.AST:
            return self._mk(n, "Set", n.elts)

        def visit_Dict(self, n: ast.Dict) -> ast.AST:
            flat = [x for kv in zip(n.keys, n.values) for x in kv]
            return ast.copy_location(ast.Call(ast.Name("_MK", ast.Load()), [ast.Constant(f"mk_Dict{len(n.keys)}")] +
                                              [self.visit(x) for x in flat], []), n)

    tree = ast.parse(src)
    fn, _owner = _find(tree, func)
    local_names = set(params) | _assigned(fn)
    fn.args.defaults = []
    fn.args.kw_defaults = [None] * len(fn.args.kwonlyargs)
    fn.decorator_list = []
    fn.returns = None
    for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
        a.annotation = None
    kwonly = [a.arg for a in fn.args.kwonlyargs]
    npos = len(params) - len(kwonly)
    body_mod = ast.Module([fn], [])
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} - set(params) - _assigned(fn)
    body_mod = ast.fix_missing_locations(XForm().visit(body_mod))
    ns: dict[str, Any] = {nm: O(I.const(f"g_{nm}")) for nm in names}
    ns["__builtins__"] = {}
    ns["_K"] = lambda r, t: O(I.const(f"k_{t}_{hashlib.sha256(r.encode()).hexdigest()[:10]}"))
    ns["_IMP"] = lambda name: new(I.const(name))

    def _tr_append(term_el: int) -> None:
        state["trace"] = I.op("tr", state["trace"], term_el)

    def _eff(x: Any) -> Any:
        _tr_append(_el(x))
        return x

    def _store(name: str, nargs: int):
        def f(v: Any, obj: Any, *key: Any) -> None:
            term = I.op(name, state["trace"], _el(obj), *[_el(k) for k in key], _el(v))
            new(term)  # a store may raise (inside a try body)
            _tr_append(term)
        return f

    def _delete(name: str):
        def f(obj: Any, *key: Any) -> None:
            term = I.op(name, state["trace"], _el(obj), *[_el(k) for k in key])
            new(term)
            _tr_append(term)
        return f

    ns["_EFF"] = _eff
    ns["_SETITEM"] = _store("store_item", 3)
    ns["_DELITEM"] = _delete("del_item")
    ns["_SETATTR_"] = lambda name: _store(f"store_{name}", 2)
    ns["_DELATTR_"] = lambda name: _delete(f"del_attr_{name}")
    ns["_SLICE"] = lambda lo, hi, st: slice(lo, hi, st)

    def _lam(tag: str, *vals: Any) -> "O":
        els = [_el(v) for v in vals]
        return O(I.op(f"lam_{tag}", *els)) if els else O(I.const(f"lam_{tag}"))

    def _comp_h(tag: str, eager: bool, *vals: Any) -> "O":
        t = I.op(f"comp_{tag}", state["trace"], *[_el(v) for v in vals])
        return new(t) if eager else O(t)

    def _fstr(h: str, *vals: Any) -> "O":
        return new(I.op(f"fstr_{h}", state["trace"], *[_el(v) for v in vals]))

    def _callstar(layout: str, f: Any, *rest: Any) -> "O":
        return new(I.op(f"callstar_{layout}", state["trace"], _el(f), *[_el(v) for v in rest]))

    def _yield(kind: str, v: Any) -> None:
        term = I.op(kind, state["trace"], _el(v))
        new(term)
        _tr_append(term)

    def _unpack(o: Any, i: int, k: int) -> "O":
        if i == 0:
            new(I.op(f"op_unpack{k}", _el(o)))  # unpacking may raise, once per statement
        return O(I.op(f"unpack{k}_{i}", state["trace"], _el(o)))

    def _wb():
        c = [0]

        def more() -> bool:
            c[0] += 1
            return c[0] <= 4  # relational oracle only: both versions run the same bounded loop

        return more

    ns["_LAM"], ns["_COMP"], ns["_FSTR"], ns["_CALLSTAR"] = _lam, _comp_h, _fstr, _callstar
    ns["_YIELD"], ns["_UNPACK"], ns["_WB"] = _yield, _unpack, _wb
    ns["_EXC"] = _Exc
    ns["_EXCN"] = lambda x: _Exc(_el(x))
    ns["_OBJ"] = lambda v: O(v)

    def _enter() -> None:
        state["depth"] += 1

    def _exit() -> None:
        state["depth"] -= 1

    ns["_ENTER"], ns["_EXIT"] = _enter, _exit
    ns["_MATCH"] = lambda t, ev: I.matches(ev, _el(t))
    ns["_ISNONE"] = lambda x: _el(x) == I.NONE_EL
    ns["_MK"] = lambda name, *xs: O(I.op(name, *[_el(x) for x in xs]))
    exec(compile(body_mod, "<uf-oracle>", "exec"), ns)  # noqa: S102 - trusted fixture source, closed namespace
    try:
        res = ns[fn.name](*[O(args[p]) for p in params[:npos]], **{k: O(args[k]) for k in kwonly})
    except _Exc as ex:
        return "raise", ex.v, state["trace"]
    if res is None:
        return "ret", I.const("k_NoneType_none"), state["trace"]
    return "ret", _el(res), state["trace"]


def uf_soundness_selftest(src: str, func: str, n: int = 2000, seed: int = 0) -> list[dict]:
    """Encoded UF semantics vs REAL Python execution under n random interpretations; returns mismatches.

    The real run uses Python's own control flow over table-backed values; the encoding is evaluated concretely
    under the same tables. Any disagreement is an abstraction bug. Executes ``src``: trusted fixtures only."""
    tree = ast.parse(src)
    fn, env, assigned = _prepare(tree, func)
    if fn.args.vararg or fn.args.kwarg:
        raise ValueError("the oracle runs positional and keyword-only signatures only")
    params = [n for n, _k in _params(fn)]
    outs, _ = _paths(fn, env, assigned)
    rng = random.Random(seed)
    bad = []
    for i in range(n):
        I = _Interp(rng.randrange(1 << 30))
        args = {p: rng.randrange(K) for p in params}
        memo: dict = {}
        # parameter constants take the trial's values
        for p in params:
            memo[env[p].get_id()] = args[p]
        hit = [o for g, o in outs if _ev(g, I, memo)]
        if len(hit) != 1:
            bad.append({"trial": i, "why": f"{len(hit)} satisfied paths"})
            continue
        enc = (hit[0][0], _ev(hit[0][1], I, memo), _ev(hit[0][-1], I, memo))
        real = _real_outcome(src, func, params, I, args)
        if enc != real:
            bad.append({"trial": i, "encoded": enc, "real": real})
    return bad


def uf_relational_selftest(pre_src: str, post_src: str, func: str, n: int = 500, seed: int = 0) -> list[dict]:
    """End-to-end check of a PROVED neutral pair: run the REAL pre and post functions under the same random
    interpretation and arguments; their outcomes must be identical. Executes both sources: trusted fixtures only."""
    tree = ast.parse(pre_src)
    fn, _env, _assigned = _prepare(tree, func)
    params = [n_ for n_, _k in _params(fn)]
    rng = random.Random(seed)
    bad = []
    for i in range(n):
        I = _Interp(rng.randrange(1 << 30))
        args = {p: rng.randrange(K) for p in params}
        a = _real_outcome(pre_src, func, params, I, args)
        b = _real_outcome(post_src, func, params, I, args)
        if a != b:
            bad.append({"trial": i, "pre": a, "post": b})
    return bad
