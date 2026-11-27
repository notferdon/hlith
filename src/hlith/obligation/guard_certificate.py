# SPDX-License-Identifier: Apache-2.0
"""Guard-removal CERTIFICATE (case; design review bounded review of 8d4cfce section 3; design review P0 on O3 soundness).

A removed entry guard is explained by an approved intended change only when, over a MODELLED domain:

  1. EXACT IDENTITY: the guard's effective firing condition G equals the approved predicate P:
        G and not P   UNSAT   and   P and not G   UNSAT
  2. INTENDED OUTCOME: for every input in P the post-change function realises the declared outcome (no exception, value
     equal to the declared expression), and
  3. PRESERVATION: for every input outside P the post-change function behaves exactly as the base (same raise / same value).

"Search found nothing" is NEVER a proof: a solver `unknown` / timeout is its own status, and a construct outside the
modelled subset is UNSUPPORTED (the caller keeps NOT_DERIVED). The certificate discharges ONLY this guard: it says nothing
about receivers, state, warnings or output (those stay with the concrete differential and `_delta_covers`).

Modelled subset (pure functions of numeric parameters): parameters annotated int / bool / float, or unannotated (taken as
real numbers); body = optional docstring, then `if <cond>: raise ...` guards, then one `return <expr>`; expressions over
the parameters with + - * unary-, // and % by a positive constant (int parameters only), comparisons (chains), and/or/not
in conditions, a conditional expression, int(<condition>) and numeric / bool literals. No calls (except int of a
condition), attributes, subscripts, loops, comprehensions, methods or receivers.

Domain limit, stated in the evidence: the proof covers numeric inputs only. NaN / inf, non-numeric inputs, subclasses and
overloaded operators are outside it; for them the claim rests on the bounded concrete differential.

PROCESS ISOLATION (design review, after review's run): the formula derives from repository text, so the controller never runs the native
solver itself. It encodes the parsed functions to a typed JSON expression tree (no source text, no code) and runs
`_cert_solver.py` as a bounded SUBPROCESS (`python -I`, scrubbed environment, RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE set by the
worker before z3 is imported, plus a wall timeout enforced here). A crash, a signal, a timeout, malformed or oversize output or an
oversize input is `unknown`, which the caller turns into UNVERIFIED; it is never a proof and never silently `proved`.
"""

from __future__ import annotations

import ast
import json
import math
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

PROVED, COUNTEREXAMPLE, UNSUPPORTED, UNKNOWN = "proved", "counterexample", "unsupported", "unknown"
MAX_NODES = 600
# One-sentence scope of the proof, put FIRST in every certificate obligation text (proved / counterexample / unknown) so an operator never
# reads "proved" beside a float or str counterexample as a global claim. Obligation texts are length-capped: this goes at the start.
SCOPE_NOTE = ("proof domain = numeric model only (exact integers for int- and bool-annotated parameters, reals otherwise; the returned kind "
              "bool/int/real is checked statically, but values are compared numerically, so int and float results are not "
              "distinguished within a kind); non-integer, non-numeric and NaN/inf inputs are NOT covered by this proof "
              "(bounded concrete probes only)")
TIMEOUT_MS = 5000
MAX_SPEC = 200_000  # bytes of specification JSON sent to the worker (the worker itself refuses more than 262144)
MAX_REPLY = 65_536  # bytes of reply accepted from the worker
WALL_SLACK_S = 10.0  # process start + z3 import, added to the solver time when computing the wall limit
WORKER = Path(__file__).with_name("_cert_solver.py")
DOMAIN = ("numeric inputs: exact integers for int- AND bool-annotated parameters (a bool is an int, so an int passed for a bool parameter is INSIDE "
          "the proof), real numbers otherwise. OUTSIDE the proof, where the "
          "claim rests ONLY on bounded concrete probes: float or other non-integer callers of an int-annotated parameter "
          "(Python does not enforce the annotation), NaN / inf, non-numeric inputs (str, None, containers), subclasses and "
          "overloaded operators. The proof is about returned VALUES of the modelled kind (bool, int or real); a change of the "
          "returned type is refused")


class _Unsupported(Exception):
    pass


@dataclass(frozen=True)
class Cert:
    status: str  # proved | counterexample | unsupported | unknown
    why: str
    candidate: dict | None = None  # {"side": "guard-vs-predicate" | "inside-P" | "outside-P", "params": {name: python value}}
    domain: str = DOMAIN

    @property
    def proved(self) -> bool:
        return self.status == PROVED

    @property
    def evidence(self) -> str:
        return ("guard-removal certificate (Z3): the removed guard is exactly the approved predicate, the post realises the "
                "declared outcome inside it and preserves the base outside it; domain: " + self.domain)


# ---------------------------------------------------------------------------------------------- model of one function
@dataclass
class _Fn:
    params: list  # [(name, "int" | "bool" | "real")]
    guards: list  # [(cond_ast, exc_source)]
    ret: ast.expr


def _is_doc(st: ast.stmt) -> bool:
    return isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant) and isinstance(st.value.value, str)


def _model(fn: ast.AST) -> _Fn:
    if not isinstance(fn, ast.FunctionDef):
        raise _Unsupported("not a plain function (async, class or other definition)")
    a = fn.args
    if a.vararg or a.kwarg:
        raise _Unsupported("*args / **kwargs are not modelled")
    if fn.decorator_list:
        raise _Unsupported("a decorated function is not modelled")
    params = []
    for p in (*a.posonlyargs, *a.args, *a.kwonlyargs):
        ann = ast.unparse(p.annotation) if p.annotation is not None else None
        if p.arg in ("self", "cls"):
            raise _Unsupported("a method receiver is not modelled")
        if ann is None:
            sort = "real"
        elif ann == "int":
            sort = "int"
        elif ann == "bool":
            sort = "bool"
        elif ann == "float":
            sort = "real"
        else:
            raise _Unsupported(f"parameter {p.arg} has annotation {ann}, outside the numeric model")
        params.append((p.arg, sort))
    body = list(fn.body)
    if body and _is_doc(body[0]):
        body = body[1:]
    guards = []
    ret = None
    for i, st in enumerate(body):
        if isinstance(st, ast.If) and not st.orelse and len(st.body) == 1 and isinstance(st.body[0], ast.Raise):
            r = st.body[0]
            exc = ast.unparse(r.exc.func if isinstance(r.exc, ast.Call) else r.exc) if r.exc is not None else "<reraise>"
            guards.append((st.test, exc))
        elif isinstance(st, ast.Return) and st.value is not None and i == len(body) - 1:
            ret = st.value
        elif isinstance(st, ast.Pass):
            continue
        else:
            raise _Unsupported(f"statement `{ast.unparse(st).splitlines()[0][:60]}` is outside the model "
                               "(only `if <cond>: raise ...` guards and one final `return <expr>`)")
    if ret is None:
        raise _Unsupported("the function does not end in a single `return <expr>`")
    if sum(1 for _ in ast.walk(fn)) > MAX_NODES:
        raise _Unsupported("function too large to model")
    return _Fn(params, guards, ret)


# ---------------------------------------------------------------------------------------------- encoding to JSON (no z3 here)
# A bool-ANNOTATED parameter is modelled as an INT (bool is an int subtype and Python does not enforce the annotation: f(3, 2) is a legal call), so the
# proof covers int arguments too (review C10: 'n + b' vs '(n + b) - b + int(b == True)' was PROVED over {True, False} while f(3, 2) is 5 vs 3). Its bare value
# has its own kind "p" (a bool for a bool, an int for an int): arithmetic on it is an int either way, returning it unchanged is type-ambiguous.
_KIND = {"bool": "p", "int": "i", "real": "r"}
_CMP = {ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge", ast.Eq: "eq", ast.NotEq: "ne"}


class _Js:
    """Typed encoder: AST -> the worker's JSON nodes. Each numeric node carries a static kind: b(ool) / i(nt) / r(eal)."""

    def __init__(self, params: list) -> None:
        self.sorts = dict(params)

    @staticmethod
    def numj(jk: tuple) -> tuple:
        """Python's bool-is-an-int coercion, explicit."""
        j, k = jk
        return (["from_b", j], "i") if k == "b" else (j, k)

    def _boolish(self, node: ast.expr) -> bool:
        """Does `node` evaluate to a Python bool (so int(node) is 0/1)? `a or b` / `a and b` return an OPERAND, not a bool."""
        if isinstance(node, (ast.Compare,)):
            return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return True
        if isinstance(node, ast.BoolOp):
            return all(self._boolish(v) for v in node.values)
        return False  # a bool-annotated NAME is not "boolish": with an int argument int(b) is b, not 0/1

    def truth(self, node: ast.expr) -> list:
        """The Python truth value of `node` as a boolean node."""
        if isinstance(node, ast.BoolOp):
            return ["and" if isinstance(node.op, ast.And) else "or", [self.truth(v) for v in node.values]]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return ["not", self.truth(node.operand)]
        if isinstance(node, ast.Compare):
            return self._compare(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return ["bool", node.value]
        j, k = self.num(node)
        return j if k == "b" else ["truthy", j]

    def _compare(self, node: ast.Compare) -> list:
        ops, terms = [], [self.numj(self.num(node.left))[0]]
        for op, right in zip(node.ops, node.comparators):
            if type(op) not in _CMP:
                raise _Unsupported(f"comparison `{type(op).__name__}` is not modelled")
            ops.append(_CMP[type(op)])
            terms.append(self.numj(self.num(right))[0])
        return ["cmp", ops, terms]

    def num(self, node: ast.expr) -> tuple:
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, bool):
                return ["bool", v], "b"
            if isinstance(v, int):
                return ["int", v], "i"
            raise _Unsupported(f"constant {v!r} is not modelled")
        if isinstance(node, ast.Name):
            if node.id not in self.sorts:
                raise _Unsupported(f"name `{node.id}` is not a parameter")
            return ["var", node.id], _KIND[self.sorts[node.id]]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            j, k = self.numj(self.num(node.operand))
            return ["neg", j], ("i" if k == "p" else k)  # -True is the int -1; numj made a bool an int; -b is an int for a bool or an int
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.truth(node), "b"
        if isinstance(node, ast.BinOp):
            (a, ka), (b, kb) = self.numj(self.num(node.left)), self.numj(self.num(node.right))
            kind = "m" if "m" in (ka, kb) else "r" if "r" in (ka, kb) else "i"
            if isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
                return ["bin", {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul"}[type(node.op)], a, b], kind
            if isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                if not (isinstance(node.right, ast.Constant) and isinstance(node.right.value, int)
                        and not isinstance(node.right.value, bool) and node.right.value > 0 and ka in ("i", "p")):
                    raise _Unsupported("// and % are modelled only for an int operand and a positive integer constant")
                return ["divmod", "floordiv" if isinstance(node.op, ast.FloorDiv) else "mod", a, node.right.value], "i"
            raise _Unsupported(f"operator `{type(node.op).__name__}` is not modelled")
        if isinstance(node, ast.IfExp):
            (_ja, kar), (_jb, kbr) = self.num(node.body), self.num(node.orelse)  # RAW kinds: True / 0 is not one type
            (a, ka), (b, kb) = self.numj((_ja, kar)), self.numj((_jb, kbr))
            kind = kar if kar == kbr else "m"
            return ["ite", self.truth(node.test), a, b], kind
        if isinstance(node, ast.Compare):
            return self._compare(node), "b"
        if isinstance(node, ast.BoolOp):
            raise _Unsupported("`and` / `or` used as a VALUE (operand semantics) is not modelled; use int(<condition>)")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "int" and len(node.args) == 1\
                and not node.keywords:
            arg = node.args[0]
            if self._boolish(arg):
                return ["from_b", self.truth(arg)], "i"
            j, k = self.numj(self.num(arg))
            if k in ("i", "p"):
                return j, "i"
            raise _Unsupported("int() of a real value is not modelled")
        raise _Unsupported(f"`{ast.unparse(node)[:60]}` is not modelled")


def _value(tag: str):
    """A worker model value ("i:N" / "r:P/Q" / "b:true") as a Python number (int when integral)."""
    kind, _, body = tag.partition(":")
    if kind == "i":
        return int(body)
    if kind == "b":
        return body == "true"
    if kind == "r":
        fr = Fraction(body)
        return int(fr) if fr.denominator == 1 else float(fr)
    raise ValueError(tag)


# ---------------------------------------------------------------------------------------------- the bounded worker
def _solve_bounded(spec: dict, params: list, timeout_ms: int) -> Cert:
    """Run the worker on `spec`; every failure to obtain a clean answer is `unknown` (never a proof)."""
    wall = 4 * timeout_ms / 1000.0 + WALL_SLACK_S  # four checks, each bounded by timeout_ms inside the worker
    spec = {**spec, "timeout_ms": int(timeout_ms), "cpu_s": int(math.ceil(wall))}
    data = json.dumps(spec, separators=(",", ":")).encode()
    if len(data) > MAX_SPEC:
        return Cert(UNKNOWN, f"the certificate specification is {len(data)} bytes, over the solver input bound ({MAX_SPEC})")
    if not WORKER.is_file():
        return Cert(UNKNOWN, "the bounded solver worker is missing; nothing is proved")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "PYTHONHASHSEED": "0"}  # nothing else leaves the host
    try:
        cp = subprocess.run([sys.executable, "-I", str(WORKER)], input=data, capture_output=True, timeout=wall, env=env,
                            cwd=tempfile.gettempdir(), close_fds=True, check=False)
    except subprocess.TimeoutExpired:
        return Cert(UNKNOWN, f"the solver exceeded its {wall:.0f} s wall limit and was killed")
    except OSError as e:
        return Cert(UNKNOWN, f"the solver could not be started ({type(e).__name__})")
    if cp.returncode != 0:
        how = f"signal {-cp.returncode}" if cp.returncode < 0 else f"exit {cp.returncode}"
        return Cert(UNKNOWN, f"the solver process died ({how}): a crash or a resource limit, nothing is proved")
    if len(cp.stdout) > MAX_REPLY:
        return Cert(UNKNOWN, "the solver reply exceeded its size bound")
    try:
        out = json.loads(cp.stdout)
        res = out["res"]
    except (ValueError, KeyError, TypeError):
        return Cert(UNKNOWN, "the solver reply was malformed")
    if res == "unsat":
        return Cert(PROVED, "G == P, post realises the declared outcome inside P, post == base outside P")
    if res == "sat":
        try:
            vals = {n: _value(out["model"][n]) for n, _s in params}
        except (ValueError, KeyError, TypeError, ZeroDivisionError):
            return Cert(UNKNOWN, "the solver returned a model that could not be read")
        side = str(out.get("side", ""))
        return Cert(COUNTEREXAMPLE, f"counterexample ({side}): " + ", ".join(f"{k}={v!r}" for k, v in vals.items()),
                    {"side": side, "params": vals})
    if res == "unknown":
        return Cert(UNKNOWN, f"solver returned unknown ({out.get('side', '')}): {str(out.get('reason', ''))[:100]}")
    if res == "nosolver":
        return Cert(UNSUPPORTED, "no solver available")
    return Cert(UNSUPPORTED, f"could not be modelled by the solver: {str(out.get('reason', ''))[:100]}")


# ---------------------------------------------------------------------------------------------- the certificate
def certify_removal(pre_fn: ast.AST, post_fn: ast.AST, guard_cond: str, delta: dict, *, timeout_ms: int = TIMEOUT_MS) -> Cert:
    """Certificate that the removal of the guard whose condition source is `guard_cond` is explained by `delta`."""
    try:
        pre, post = _model(pre_fn), _model(post_fn)
        if [p for p in pre.params] != [p for p in post.params]:
            raise _Unsupported("the signatures (names, order or types) differ between base and post")
        pred = delta.get("predicate") or {}
        exp = delta.get("expected") or {}
        if pred.get("type") != "expr" or not isinstance(pred.get("expr"), str):
            raise _Unsupported(f"predicate type {pred.get('type')!r} is not modelled (only an `expr` predicate)")
        if exp.get("kind") != "returns_expr" or not isinstance(exp.get("expr"), str):
            raise _Unsupported(f"expected kind {exp.get('kind')!r} is not modelled (only `returns_expr`)")
        js = _Js(pre.params)
        want = guard_cond.strip()
        idx = next((i for i, (c, _e) in enumerate(pre.guards) if ast.unparse(c) == want), None)
        if idx is None:
            raise _Unsupported("the removed guard is not an `if <cond>: raise` guard of the base function")
        # exception names must map to the same ids across pre and post
        names = sorted({e for _c, e in (*pre.guards, *post.guards)})
        idmap = {n: i + 1 for i, n in enumerate(names)}

        def side_of(m: _Fn) -> dict:
            return {"guards": [[js.truth(c), idmap[ex]] for c, ex in m.guards], "ret": js.numj(js.num(m.ret))[0]}

        exp_ast = ast.parse(exp["expr"].strip(), mode="eval").body
        _name = {"b": "bool", "i": "int", "r": "real-valued (int or float)", "m": "mixed (a conditional whose branches differ in type)",
                "p": "a bool-annotated parameter's own value (a bool for a bool, an int for an int)"}
        k_pre, k_post, k_exp = js.num(pre.ret)[1], js.num(post.ret)[1], js.num(exp_ast)[1]
        if "m" in (k_post, k_exp) or "p" in (k_post, k_exp) or k_post != k_exp:
            raise _Unsupported(f"the returned value's TYPE is not shown to match the declared outcome (post returns {_name[k_post]}, "
                               f"the declared expression is {_name[k_exp]}): the certificate models values, not types, and a caller "
                               "can tell False from 0 or 0.0 from 0")
        if k_post != k_pre:
            raise _Unsupported(f"the returned value's TYPE differs from the base (base returns {_name[k_pre]}, post returns "
                               f"{_name[k_post]}): outside P the post must behave exactly as the base, types included")
        spec = {"v": 1, "params": [[n_, "int" if t_ == "bool" else t_] for n_, t_ in pre.params], "pre": side_of(pre), "post": side_of(post), "idx": idx,
                "pred": js.truth(ast.parse(pred["expr"].strip(), mode="eval").body),
                "exp": js.numj(js.num(exp_ast))[0]}
    except _Unsupported as e:
        return Cert(UNSUPPORTED, str(e))
    except (SyntaxError, ValueError, KeyError, RecursionError) as e:
        return Cert(UNSUPPORTED, f"could not be modelled: {type(e).__name__}: {str(e)[:100]}")
    return _solve_bounded(spec, pre.params, timeout_ms)
