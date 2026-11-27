# SPDX-License-Identifier: Apache-2.0
"""Candidate-input DRIVER for uncovered conditions (a generator, never evidence).

Given a condition (and the polarity wanted) over a callable's parameters, produce concrete inputs that are
likely to make it True / False: Z3 models for the modelled fragment, threshold seeds (c-1, c, c+1, 2^k+-1)
and typed representatives for isinstance/type tests. Nothing here is trusted and nothing here claims coverage:
the caller runs the real pre/post functions and observes which branch actually fired.

Safety: proposer text is only PARSED (``ast``). It is never executed: candidates are re-checked by a small pure
AST evaluator that knows a fixed set of operators and builtins and runs no callee.

Unsupported constructs give ``[]`` with a reason that names the construct. Stdlib + z3 only.
"""

from __future__ import annotations

import ast
import builtins
import copy
import datetime as _datetime
import itertools
import json
import math
import os
import re
import sys
import types
from pathlib import PurePath, PurePosixPath
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

import z3

_BIG = 10**5  # cap for lengths, shifts and results the evaluator will build


class Unsupported(Exception):
    pass


# ------------------------------------------------------------------ result types
@dataclass(frozen=True)
class Candidate:
    kwargs: dict[str, Any]
    wants: bool
    origin: str  # 'z3' | 'seed' | 'typed'
    checked: bool  # my own evaluator confirmed the WHOLE condition has the wanted polarity on exactly these kwargs


@dataclass(frozen=True)
class DriveResult:
    candidates: list[Candidate]
    reason: str  # why candidates is empty, or notes on partial modelling ('' when nothing to say)
    exact: bool  # every conjunct/disjunct of the condition was modelled


@dataclass(frozen=True)
class DetailedCandidate:
    params: dict[str, Any]
    condition: int
    wants: bool
    origin: str
    exact: bool
    residuals: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ types
_EXC_NAMES = ["Exception", "BaseException", "OSError", "ValueError", "TypeError", "KeyError", "IndexError",
              "AttributeError", "RuntimeError", "LookupError", "ArithmeticError"]
_EXC_T = {n: getattr(builtins, n) for n in _EXC_NAMES}
TYPES = ["int", "bool", "str", "float", "list", "tuple", "dict", "set", "bytes", "NoneType", *_EXC_NAMES]
_T, _TC = z3.EnumSort("hlith_drive_T", TYPES)
_TV = dict(zip(TYPES, _TC))
_BUILTIN_T = {"int": int, "bool": bool, "str": str, "float": float, "list": list, "tuple": tuple, "dict": dict,
              "set": set, "bytes": bytes, **_EXC_T}
_SUB = {"int": {"int", "bool"}, "bool": {"bool"}, "str": {"str"}, "float": {"float"}, "list": {"list"},
        "tuple": {"tuple"}, "dict": {"dict"}, "set": {"set"}, "bytes": {"bytes"}, "NoneType": {"NoneType"},
        # an exception class matches every modelled exception type that is a subclass of it
        **{n: {m for m, c in _EXC_T.items() if issubclass(c, k)} for n, k in _EXC_T.items()}}
_REP: dict[str, Any] = {"int": 0, "bool": True, "str": "a", "float": 1.5, "list": [1], "tuple": (1,),
                        "dict": {"a": 1}, "set": {1}, "bytes": b"a", "NoneType": None,
                        **{n: c("a") for n, c in _EXC_T.items()}}
_SIZED_T = ["list", "tuple", "str", "bytes", "dict", "set"]
_LAZY_ANN = {"dict", "Dict", "Mapping", "MutableMapping", "list", "List", "tuple", "Tuple", "Sequence"}
_SIZED_ANN = {"list", "tuple", "set", "frozenset", "dict", "bytes", "bytearray", "Sequence", "List", "Tuple", "Set",
              "Dict", "Mapping", "Iterable", "Collection", "deque"}
_STR_METHODS = {"startswith", "endswith", "lower", "upper", "strip", "isdigit", "isalpha", "find", "count", "split",
                "lstrip", "rstrip", "casefold", "splitlines", "partition"}
_NUM_ATTRS = {"bit_length", "real", "imag", "numerator", "denominator"}


@dataclass
class _P:
    name: str
    kind: str  # int | bool | str | float | sized | list | tuple | any | unsupported
    optional: bool = False
    default: Any = None
    has_default: bool = False
    shape: tuple | None = None
    unsupported: str | None = None


_SHAPE_SCALARS = {"int", "bool", "str", "float"}
_MAX_SHAPE_DEPTH = 4
_MAX_SHAPE_TUPLE_ARITY = 4
_MAX_SHAPE_LIST_LEN = 2
_MAX_SHAPE_STRING_LEN = 64
_MAX_SHAPE_INT_BITS = 256
_MAX_SHAPE_SEEDS = 24


def _annotation_shape_info(src: str | None) -> tuple[tuple | None, str | None, bool]:
    """Parse the deliberately small, closed input-shape language used for generic list/tuple annotations."""
    if not src:
        return None, None, False
    try:
        node = ast.parse(src.strip().strip("'\""), mode="eval").body
    except SyntaxError:
        return None, None, False

    optional = False

    def union_parts(n: ast.expr) -> list[ast.expr]:
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
            return [*union_parts(n.left), *union_parts(n.right)]
        return [n]

    parts = union_parts(node)
    if len(parts) > 1:
        none_parts = [part for part in parts if isinstance(part, ast.Constant) and part.value is None]
        if len(none_parts) != 1 or len(parts) != 2:
            return None, None, False
        node = parts[0] if parts[1] is none_parts[0] else parts[1]
        optional = True
    elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in {"Optional", "Union"}:
        inner = list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]
        if node.value.id == "Optional":
            if len(inner) != 1:
                return None, None, False
            node = inner[0]
        else:
            none_parts = [part for part in inner if isinstance(part, ast.Constant) and part.value is None]
            if len(none_parts) != 1 or len(inner) != 2:
                return None, None, False
            node = inner[0] if inner[1] is none_parts[0] else inner[1]
        optional = True

    if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name) or node.value.id not in {"list", "tuple"}:
        return None, None, False

    def parse(n: ast.expr, depth: int) -> tuple | None:
        if depth > _MAX_SHAPE_DEPTH:
            return None
        if isinstance(n, ast.Name) and n.id in _SHAPE_SCALARS:
            return (n.id,)
        if not isinstance(n, ast.Subscript) or not isinstance(n.value, ast.Name):
            return None
        if n.value.id == "list":
            child = parse(n.slice, depth + 1)
            return ("list", child) if child is not None else None
        if n.value.id == "tuple" and isinstance(n.slice, ast.Tuple) and 1 <= len(n.slice.elts) <= _MAX_SHAPE_TUPLE_ARITY:
            children = tuple(parse(child, depth + 1) for child in n.slice.elts)
            return ("tuple", *children) if all(child is not None for child in children) else None
        return None

    shape = parse(node, 1)
    if shape is not None:
        return shape, None, optional
    return None, f"generic {node.value.id}[...] has an unsupported or unknown element type", optional


def _annotation_shape(src: str | None) -> tuple[tuple | None, str | None]:
    shape, error, _ = _annotation_shape_info(src)
    return shape, error


def _ann_info(src: str | None) -> tuple[str | None, bool]:
    """(kind or None when undeterminate, optional)."""
    if not src:
        return None, False
    try:
        node = ast.parse(src.strip().strip("'\""), mode="eval").body
    except SyntaxError:
        return None, False
    optional = False
    parts: list[ast.expr] = [node]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        parts = [x for x in ast.walk(node) if not isinstance(x, (ast.BinOp, ast.BitOr, ast.Load))]
        parts = [p for p in parts if isinstance(p, (ast.Name, ast.Constant, ast.Subscript, ast.Attribute))]
    elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in ("Optional", "Union"):
        sl = node.slice
        parts = list(sl.elts) if isinstance(sl, ast.Tuple) else [sl]
    kinds = set()
    for p in parts:
        if isinstance(p, ast.Constant) and p.value is None:
            optional = True
            continue
        base = p.value if isinstance(p, ast.Subscript) else p
        n = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else None)
        if n in ("int", "bool", "str", "float"):
            kinds.add(n)
        elif n in _LAZY_ANN:
            kinds.add("any")  # modelled lazily by its first consumer, not collapsed to a length
        elif n in _SIZED_ANN:
            kinds.add("sized")
        else:
            kinds.add("any")
    if optional and not kinds:
        return None, True
    if len(kinds) == 1:
        return next(iter(kinds)), optional
    return None, optional


def _usage(nodes: Iterable[ast.AST], names: set[str]) -> dict[str, set[str]]:
    use: dict[str, set[str]] = {n: set() for n in names}
    parent: dict[int, ast.AST] = {}
    for root in nodes:
        for n in ast.walk(root):
            for c in ast.iter_child_nodes(n):
                parent[id(c)] = n
        for n in ast.walk(root):
            if not (isinstance(n, ast.Name) and n.id in names):
                continue
            par = parent.get(id(n))
            if par is None:
                continue  # a bare root (the tuple temp of `a, b = x`) says nothing about x's type
            if isinstance(par, ast.BoolOp):
                if any(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in par.values):
                    use[n.id].add("str")  # a string fallback can feed later string methods on the coalesced value
                continue
            tag = "num"
            if isinstance(par, ast.Call) and isinstance(par.func, ast.Name) and n in par.args:
                tag = {"len": "len", "isinstance": "isinst", "type": "isinst", "Path": "obj", "PurePath": "obj",
                       "PurePosixPath": "obj", "float": "num", "int": "num"}.get(par.func.id, "num")
            elif isinstance(par, ast.Attribute):
                tag = ("str" if par.attr in _STR_METHODS else "num" if par.attr in _NUM_ATTRS
                       else "dict" if par.attr in ("get", "keys") else "obj")
            elif isinstance(par, ast.Subscript) and par.value is n:
                tag = "sub"
            elif isinstance(par, ast.comprehension) and par.iter is n:
                tag = "iter"
            elif isinstance(par, ast.Compare):
                others = [par.left, *par.comparators]
                if any(isinstance(o, ast.Constant) and o.value is None for o in others):
                    tag = "none"
                elif any(isinstance(o, ast.Constant) and isinstance(o.value, str) for o in others):
                    tag = "str"
            elif isinstance(par, ast.BinOp) and any(isinstance(o, ast.Constant) and isinstance(o.value, str)
                                                    for o in (par.left, par.right)):
                tag = "str"
            use[n.id].add(tag)
    return use


# ------------------------------------------------------------------ pure evaluator (never executes proposer text)
def _ev(node: ast.AST, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, str, bytes, bool, type(None))):
            return node.value
        raise Unsupported("constant")
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise Unsupported(f"name {node.id!r}")
    if isinstance(node, ast.UnaryOp):
        v = _ev(node.operand, env)
        if isinstance(node.op, ast.Not):
            return not v
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return +v
        if isinstance(node.op, ast.Invert):
            return ~v
        raise Unsupported("unary")
    if isinstance(node, ast.BinOp):
        a, b = _ev(node.left, env), _ev(node.right, env)
        op = node.op
        if isinstance(op, ast.Div):
            if isinstance(a, PurePath) and isinstance(b, (str, PurePath)):
                return a / b
            raise Unsupported("division")
        if isinstance(op, ast.Add):
            return a + b
        if isinstance(op, ast.Sub):
            return a - b
        if isinstance(op, ast.Mult):
            if isinstance(a, int) and isinstance(b, int) and a.bit_length() + b.bit_length() > _BIG:
                raise Unsupported("product too large")
            return a * b
        if isinstance(op, ast.FloorDiv):
            return a // b
        if isinstance(op, ast.Mod):
            return a % b
        if isinstance(op, ast.Pow):
            if isinstance(a, int) and isinstance(b, int) and (b > 64 or b < 0 or a.bit_length() * max(b, 1) > _BIG):
                raise Unsupported("power too large")
            return a ** b
        if isinstance(op, (ast.LShift, ast.RShift)):
            if not isinstance(b, int) or b > _BIG or b < 0:
                raise Unsupported("shift")
            return a << b if isinstance(op, ast.LShift) else a >> b
        if isinstance(op, ast.BitAnd):
            return a & b
        if isinstance(op, ast.BitOr):
            return a | b
        if isinstance(op, ast.BitXor):
            return a ^ b
        raise Unsupported("binop")
    if isinstance(node, ast.BoolOp):
        r: Any = isinstance(node.op, ast.And)
        for v in node.values:
            r = _ev(v, env)
            if isinstance(node.op, ast.And) and not r:
                return r
            if isinstance(node.op, ast.Or) and r:
                return r
        return r
    if isinstance(node, ast.IfExp):
        return _ev(node.body, env) if _ev(node.test, env) else _ev(node.orelse, env)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        items = [_ev(e, env) for e in node.elts]
        return tuple(items) if isinstance(node, ast.Tuple) else items if isinstance(node, ast.List) else set(items)
    if isinstance(node, ast.Compare):
        left = _ev(node.left, env)
        for op, rn in zip(node.ops, node.comparators):
            right = _ev(rn, env)
            if isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            elif isinstance(op, ast.Lt):
                ok = left < right
            elif isinstance(op, ast.LtE):
                ok = left <= right
            elif isinstance(op, ast.Gt):
                ok = left > right
            elif isinstance(op, ast.GtE):
                ok = left >= right
            elif isinstance(op, ast.Is):
                ok = left is right
            elif isinstance(op, ast.IsNot):
                ok = left is not right
            elif isinstance(op, ast.In):
                ok = left in right
            elif isinstance(op, ast.NotIn):
                ok = left not in right
            else:
                raise Unsupported("comparison")
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name):
            args = [_ev(a, env) for a in node.args]
            if node.keywords:
                raise Unsupported("keyword arguments")
            if f.id == "len" and len(args) == 1:
                return len(args[0])
            if f.id == "abs" and len(args) == 1:
                return abs(args[0])
            if f.id in ("min", "max") and len(args) >= 2:
                return min(args) if f.id == "min" else max(args)
            if f.id == "type" and len(args) == 1:
                return type(args[0])
            if f.id == "bool" and len(args) == 1:
                return bool(args[0])
            if f.id == "str" and len(args) == 1 and isinstance(args[0], (int, str)):
                return str(args[0])
            if f.id in ("Path", "PurePath", "PurePosixPath") and len(args) == 1 and isinstance(args[0], (str, PurePath)):
                return PurePosixPath(args[0])
            if f.id in ("float", "int") and len(args) == 1 and isinstance(args[0], (int, float)) and not isinstance(args[0], bool):
                return float(args[0]) if f.id == "float" else int(args[0])
            if f.id == "int" and len(args) == 1 and isinstance(args[0], str) and re.fullmatch(r"[0-9]+", args[0]):
                return int(args[0])
            if f.id in ("deepcopy", "copy") and len(args) == 1:
                return args[0]  # a read-only copy of a value is that value
            if f.id == "dict" and len(args) == 1 and isinstance(args[0], dict):
                return args[0]
            if f.id in ("set", "list", "tuple") and len(args) == 1 and isinstance(args[0], (list, tuple, set, str))\
                    and len(args[0]) <= _ITER_CAP:
                return {"set": set, "list": list, "tuple": tuple}[f.id](args[0])
            if f.id == "isinstance" and len(args) == 2:
                return isinstance(args[0], args[1])
            raise Unsupported(f"call {f.id}")
        if isinstance(f, ast.Attribute):
            if f.attr in ("deepcopy", "copy") and isinstance(f.value, ast.Name) and f.value.id == "copy" and len(node.args) == 1\
                    and "copy" not in env:
                return _ev(node.args[0], env)
            obj = _ev(f.value, env)
            args = [_ev(a, env) for a in node.args]
            if node.keywords:
                raise Unsupported("keyword arguments")
            if f.attr == "bit_length" and isinstance(obj, int) and not args:
                return obj.bit_length()
            if f.attr in ("startswith", "endswith") and isinstance(obj, str) and len(args) == 1 and isinstance(args[0], str):
                return obj.startswith(args[0]) if f.attr == "startswith" else obj.endswith(args[0])
            if isinstance(obj, str) and f.attr in _PURE_STR and all(isinstance(a, (str, int)) for a in args):
                return getattr(obj, f.attr)(*args)
            if isinstance(obj, (list, tuple)) and f.attr == "count" and len(args) == 1:
                return obj.count(args[0])
            if isinstance(obj, dict) and f.attr == "get" and 1 <= len(args) <= 2:
                return obj.get(*args)
            if isinstance(obj, dict) and f.attr == "keys" and not args:
                return obj.keys()
            if isinstance(obj, PurePath) and f.attr == "is_absolute" and not args:
                return obj.is_absolute()
            if isinstance(obj, PurePath) and f.attr == "relative_to" and len(args) == 1 and isinstance(args[0], (str, PurePath)):
                return obj.relative_to(args[0])
            raise Unsupported(f"method {f.attr}")
        raise Unsupported("call")
    if isinstance(node, ast.Attribute):
        obj = _ev(node.value, env)
        if type(obj) is _datetime.timedelta and node.attr in ("days", "seconds", "microseconds"):
            return getattr(obj, node.attr)
        if isinstance(obj, PurePath) and node.attr in ("parts", "parent", "name"):
            return getattr(obj, node.attr)
        if isinstance(obj, types.SimpleNamespace) and not node.attr.startswith("_"):
            return getattr(obj, node.attr)
        raise Unsupported(f"attribute {node.attr}")
    if isinstance(node, ast.Subscript):
        obj = _ev(node.value, env)
        if isinstance(obj, (str, list, tuple, dict)):
            sl = node.slice
            if isinstance(sl, ast.Slice):
                if sl.step is not None:
                    raise Unsupported("slice step")
                lo = _ev(sl.lower, env) if sl.lower is not None else None
                hi = _ev(sl.upper, env) if sl.upper is not None else None
                return obj[lo:hi]
            return obj[_ev(sl, env)]
        raise Unsupported("subscript")
    if isinstance(node, ast.Dict):
        if any(k is None for k in node.keys) or len(node.keys) > 64:
            raise Unsupported("dict literal")
        return {_ev(k, env): _ev(v, env) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.ListComp, ast.SetComp)):
        out: list[Any] = []

        def rec(gi: int, e: dict[str, Any]) -> None:
            if gi == len(node.generators):
                out.append(_ev(node.elt, e))
                return
            g = node.generators[gi]
            it = _ev(g.iter, e)
            if not isinstance(it, (list, tuple, set, str)) or len(it) > _ITER_CAP:
                raise Unsupported("comprehension iterable")
            for x in it:
                e2 = dict(e)
                if isinstance(g.target, ast.Name):
                    e2[g.target.id] = x
                else:
                    raise Unsupported("comprehension target")
                if all(_ev(c, e2) for c in g.ifs):
                    rec(gi + 1, e2)

        rec(0, env)
        return out if isinstance(node, ast.ListComp) else set(out)
    raise Unsupported(type(node).__name__)


_PURE_STR = {"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "split", "splitlines", "partition", "count"}
_ITER_CAP = 4096
_EVAL_TYPES = {k: v for k, v in _BUILTIN_T.items()} | {"NoneType": type(None)}


def _tri(node: ast.AST, env: dict[str, Any]) -> bool | None:
    """Kleene value of a condition: True/False, or None when a leaf is outside the evaluator."""
    if isinstance(node, ast.BoolOp):
        # Python order: left to right with short-circuit. An operand my evaluator cannot decide (or that would raise)
        # makes everything after it unreachable for the conclusion: the result is undecided, never the later operand's.
        is_and = isinstance(node.op, ast.And)
        for v in node.values:
            r = _tri(v, env)
            if r is None:
                return None
            if is_and and not r:
                return False
            if not is_and and r:
                return True
        return is_and
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        v = _tri(node.operand, env)
        return None if v is None else not v
    try:
        return bool(_ev(node, {**{k: v for k, v in _EVAL_TYPES.items()}, **env}))
    except (Unsupported, ArithmeticError, LookupError, TypeError, ValueError, AttributeError, MemoryError, RecursionError):
        return None


# ------------------------------------------------------------------ Z3 translation of the modelled fragment
def _pow2(k: int) -> int:
    if not 0 <= k <= 100000:
        raise Unsupported("bit width out of range")
    return 1 << k


# ------------------------------------------------------------------ bounded symbolic sequences (WP-BSDP-1)
K_MAX = 4  # a symbolic sequence has at most this many elements; longer inputs are outside the model (named in reasons)
_WS = " \t\n\r\x0b\x0c"
_PRINT = z3.Range(" ", "~")
_PRINT_NS = z3.Range("!", "~")  # visible, no space


class _DictVal:
    def __init__(self, items: dict[str, Any]):
        self.items = items

    def __repr__(self) -> str:
        return f"_DictVal({sorted(self.items.items(), key=lambda kv: kv[0])!r})"


class _ObjVal:
    def __init__(self, attrs: dict[str, Any]):
        self.attrs = attrs

    def __repr__(self) -> str:
        return f"_ObjVal({sorted(self.attrs.items(), key=lambda kv: kv[0])!r})"


class _PathVal:
    def __init__(self, text: str):
        self.text = text

    def __repr__(self) -> str:
        return f"_PathVal({self.text!r})"


@dataclass
class SymSeq:
    """A sequence of at most K_MAX elements: element i exists iff i < length. ``elems`` are terms ((kind, z3) pairs)
    or lazies (kind decided by the first consumer). ``tup`` = fixed-arity tuple, ``is_set`` = len() counts distinct."""
    length: Any
    elems: list
    tup: bool = False
    is_set: bool = False
    box: dict | None = None  # shared element-kind decision for a sequence INPUT
    path: bool = False


class _Lazy:
    """A value whose type is decided by its first consumer (``x.get(..)`` -> dict, ``x[0]`` -> sequence, ...)."""

    def __init__(self, tr: "_Tr", key: str, box: dict | None = None, make=None):
        self.tr, self.key, self.box, self.make = tr, key, box, make
        self.term: tuple | None = None

    def resolve(self, kind: str):
        if self.term is not None:
            return self.tr._compat(self.term, kind)
        if self.box is not None:
            if self.box["kind"] not in (None, kind) and not {self.box["kind"], kind} <= {"int", "bool"}:
                raise Unsupported(f"elements of {self.key.split('[')[0]!r} are used both as {self.box['kind']} and {kind}")
            self.box["kind"] = kind
        t = self.make(kind) if self.make is not None else self.tr._materialise_lazy(self, kind)
        self.term = t
        return t


class _DictH:
    def __init__(self, tr: "_Tr", key: str):
        self.tr, self.key = tr, key
        self.vals: dict[str, _Lazy] = {}
        self.present: dict[str, Any] = {}

    def has(self, k: str):
        if k not in self.present:
            v = z3.Bool(f"P_{self.key}?{k}")
            self.present[k] = v
            self.tr.bools[f"{self.key}?{k}"] = v
        return self.present[k]

    def get(self, k: str) -> tuple:
        self.has(k)
        if k not in self.vals:
            self.vals[k] = _Lazy(self.tr, f"{self.key}[{k!r}]")
        return ("lazy", self.vals[k])


class _ObjH:
    def __init__(self, tr: "_Tr", key: str):
        self.tr, self.key = tr, key
        self.attrs: dict[str, _Lazy] = {}

    def attr(self, a: str) -> tuple:
        if a not in self.attrs:
            self.attrs[a] = _Lazy(self.tr, f"{self.key}.{a}")
        return ("lazy", self.attrs[a])


def _cat(*parts):
    return parts[0] if len(parts) == 1 else z3.Concat(*parts)


class _BsdpMixin:
    # -- kinds
    def _compat(self, term: tuple, kind: str):
        k = term[0]
        if k == kind or {k, kind} <= {"int", "bool"}:
            return term
        raise Unsupported(f"a {k} value is used as {kind}")

    def _co(self, t: tuple, kind: str) -> tuple:
        """Resolve a lazy to ``kind``; check an already-typed term against it."""
        if t[0] == "lazy":
            return t[1].resolve(kind)
        return self._compat(t, kind)

    def _fresh(self, p: str) -> str:
        self._uid += 1
        return f"{p}~{self._uid}"

    def _materialise_lazy(self, lz: _Lazy, kind: str) -> tuple:
        key = lz.key
        if kind == "int":
            v = z3.Int(f"i_{key}")
            self.ints[key] = v
            return "int", v
        if kind == "bool":
            v = z3.Bool(f"b_{key}")
            self.bools[key] = v
            return "bool", v
        if kind == "str":
            v = z3.String(f"s_{key}")
            self.strs[key] = v
            return "str", v
        if kind == "seq":
            ln = z3.Int(f"L_{key}")
            self.lens[key] = ln
            self.side += [ln >= 0, ln <= K_MAX]
            self.len_vars.append((ln, 0, K_MAX))
            box: dict = {"kind": None}
            return "seq", SymSeq(ln, [("lazy", _Lazy(self, f"{key}[{i}]", box)) for i in range(K_MAX)], box=box)
        if kind == "dict":
            return "dict", _DictH(self, key)
        if kind == "obj":
            return "obj", _ObjH(self, key)
        if kind == "path":
            ln = z3.Int(f"L_{key}")
            self.lens[key] = ln
            self.side += [ln >= 0, ln <= K_MAX]
            self.len_vars.append((ln, 0, K_MAX))
            comps = []
            for i in range(K_MAX):
                c = z3.String(f"c_{key}/{i}")
                self.strs[f"{key}/{i}"] = c
                self.side += [z3.InRe(c, z3.Star(z3.Union(z3.Range("!", "."), z3.Range("0", "~")))),
                              z3.Implies(i < ln, z3.And(z3.Length(c) >= 1, c != z3.StringVal("."), c != z3.StringVal(".."))),
                              z3.Implies(i >= ln, c == z3.StringVal(""))]
                comps.append(("str", c))
            return "path", SymSeq(ln, comps, path=True)
        raise Unsupported(f"cannot type a value as {kind}")

    # -- sequences
    def _seq(self, t: tuple) -> SymSeq:
        t = self._co(t, "seq")
        if t[0] == "path":
            return t[1]
        if t[0] != "seq":
            raise Unsupported(f"a {t[0]} value is used as a sequence")
        return t[1]

    def _elem(self, sq: SymSeq, i: int) -> tuple:
        if not 0 <= i < K_MAX:
            raise Unsupported(f"index {i} is beyond the bounded sequence (K={K_MAX})")
        e = sq.elems[i]
        return e if isinstance(e, tuple) else ("lazy", e)

    def _select(self, sq: SymSeq, back: int) -> tuple:
        """seq[-back] (back >= 1): the element at length-back."""
        if not 1 <= back <= K_MAX:
            raise Unsupported(f"index -{back} is beyond the bounded sequence (K={K_MAX})")
        self.side.append(sq.length >= back)

        def build(kind: str) -> tuple:
            terms = [self._co(self._elem(sq, j - back), kind) for j in range(back, K_MAX + 1)]
            k0 = terms[0][0]
            if any(t[0] != k0 for t in terms):
                raise Unsupported("sequence elements of mixed kinds")
            if k0 not in ("int", "bool", "str"):
                raise Unsupported(f"negative index into a sequence of {k0} values")
            r = terms[-1][1]
            for j in range(len(terms) - 2, -1, -1):
                r = z3.If(sq.length == back + j, terms[j][1], r)
            return k0, r

        if any(not isinstance(e, tuple) for e in sq.elems):
            return "lazy", _Lazy(self, self._fresh("sel"), make=build)
        return build("str") if sq.elems and sq.elems[0][0] == "str" else build(sq.elems[0][0])

    def _index(self, node: ast.Subscript) -> tuple:
        v = self.term(node.value)
        sl = node.slice
        if isinstance(sl, ast.Slice):
            return self._slice(v, sl)
        if v[0] == "lazy":
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                v = v[1].resolve("dict")
            elif isinstance(sl, ast.Constant) and type(sl.value) is int or (
                    isinstance(sl, ast.UnaryOp) and isinstance(sl.op, ast.USub)):
                v = v[1].resolve("seq")
            else:
                raise Unsupported(f"subscript {ast.unparse(node)[:50]!r} of a value of unknown type")
        if v[0] == "dict":
            key = self._key(sl)
            if key is None:
                raise Unsupported("dict subscript must be a string constant")
            h: _DictH = v[1]
            self.side.append(h.has(key))
            return h.get(key)
        i = self._const_int(sl)
        if v[0] == "str":
            s_ = v[1]
            if i >= 0:
                self.side.append(z3.Length(s_) > i)
                return "str", z3.SubString(s_, i, 1)
            self.side.append(z3.Length(s_) >= -i)
            return "str", z3.SubString(s_, z3.Length(s_) + i, 1)
        sq = self._seq(v)
        if i >= 0:
            self.side.append(sq.length > i)
            return self._elem(sq, i)
        return self._select(sq, -i)

    def _slice(self, v: tuple, sl: ast.Slice) -> tuple:
        if sl.step is not None:
            raise Unsupported("slice with a step")
        v = self._co(v, "str")
        if v[0] != "str":
            raise Unsupported(f"slice of a {v[0]} value")
        s_ = v[1]
        n = z3.Length(s_)

        def b(x):
            return None if x is None else self._const_int(x)

        lo, hi = b(sl.lower), b(sl.upper)
        if lo is None and hi is None:
            return "str", s_
        if lo is not None and lo >= 0 and hi is not None and hi >= lo:
            return "str", z3.SubString(s_, lo, hi - lo)
        if lo is None and hi is not None and hi >= 0:
            return "str", z3.SubString(s_, 0, hi)
        if lo is not None and lo >= 0 and hi is None:
            return "str", z3.If(n >= lo, z3.SubString(s_, lo, n - lo), z3.StringVal(""))
        if lo is None and hi is not None and hi < 0:
            return "str", z3.If(n > -hi, z3.SubString(s_, 0, n + hi), z3.StringVal(""))
        if lo is not None and lo < 0 and hi is None:
            return "str", z3.If(n >= -lo, z3.SubString(s_, n + lo, -lo), s_)
        raise Unsupported(f"slice bounds in {ast.unparse(sl)!r}")

    # -- string homomorphisms
    def _strip(self, s_, which: str):
        if self.fast:
            # identity on input that has no edge to strip (the edge characters are visible ASCII): no fresh strings,
            # no concatenation equation. The exact padded decomposition below is the fallback when this finds nothing.
            self.fast_used = True
            # prefix/suffix tests, not SubString(len-1): that form times out in Z3's word-equation solver
            if which in ("strip", "lstrip"):
                self.side += [z3.Not(z3.PrefixOf(z3.StringVal(c), s_)) for c in " "]
            if which in ("strip", "rstrip"):
                self.side += [z3.Not(z3.SuffixOf(z3.StringVal(c), s_)) for c in " "]
            return "str", s_
        t = z3.String(self._fresh("strip"))
        lpad, rpad = z3.String(self._fresh("lp")), z3.String(self._fresh("rp"))
        ws = z3.Star(z3.Union(*[z3.Re(c) for c in " \t\n"]))
        self.side.append(z3.InRe(t, z3.Star(_PRINT)))
        edge = lambda x, last: z3.Or(z3.Length(x) == 0, z3.SubString(x, (z3.Length(x) - 1) if last else 0, 1) != z3.StringVal(" "))
        if which in ("strip", "lstrip"):
            self.side += [z3.InRe(lpad, ws), edge(t, False)]
        else:
            self.side.append(lpad == z3.StringVal(""))
        if which in ("strip", "rstrip"):
            self.side += [z3.InRe(rpad, ws), edge(t, True)]
        else:
            self.side.append(rpad == z3.StringVal(""))
        self.side.append(s_ == _cat(lpad, t, rpad))
        return "str", t

    def _case(self, s_, which: str):
        alpha = z3.Union(z3.Range(" ", "@"), z3.Range("[", "~")) if which in ("lower", "casefold")\
            else z3.Union(z3.Range(" ", "`"), z3.Range("{", "~"))
        self.side.append(z3.InRe(s_, z3.Star(alpha)))
        return "str", s_

    def _split(self, s_, args: list[ast.expr]):
        K = K_MAX
        if not args:
            ln = z3.Int(self._fresh("wl"))
            self.side += [ln >= 0, ln <= K]
            self.len_vars.append((ln, 0, K))
            toks = [z3.String(self._fresh("wt")) for _ in range(K)]
            lead, trail = z3.String(self._fresh("lead")), z3.String(self._fresh("trail"))
            ws = z3.Union(*[z3.Re(c) for c in " \t\n"])
            self.side += [z3.InRe(lead, z3.Star(ws)), z3.InRe(trail, z3.Star(ws))]
            seps = [z3.String(self._fresh("ws")) for _ in range(K)]
            for i in range(K):
                self.side += [z3.InRe(toks[i], z3.Star(_PRINT_NS)), z3.InRe(seps[i], z3.Plus(ws)),
                              z3.Implies(i < ln, z3.Length(toks[i]) >= 1), z3.Implies(i >= ln, toks[i] == z3.StringVal(""))]
            alts = z3.Or(z3.And(ln == 0, s_ == _cat(lead, trail)),
                         *[z3.And(ln == k, s_ == _cat(lead, toks[0], *[x for j in range(1, k) for x in (seps[j], toks[j])], trail))
                           for k in range(1, K + 1)])
            self.side.append(alts)
            return "seq", SymSeq(ln, [("str", t) for t in toks])
        sep = args[0]
        if not (isinstance(sep, ast.Constant) and isinstance(sep.value, str) and sep.value):
            raise Unsupported("split separator must be a non-empty string constant")
        m = None
        if len(args) == 2:
            m = self._const_int(args[1])
            if m < 1:
                raise Unsupported("split maxsplit must be a positive constant")
        elif len(args) > 2:
            raise Unsupported("split with more than two arguments")
        sv = z3.StringVal(sep.value)
        self.str_consts.add(sep.value)
        ln = z3.Int(self._fresh("sl"))
        top = K if m is None else min(K, m + 1)
        self.side += [ln >= 1, ln <= top]
        self.len_vars.append((ln, 1, top))
        toks = [z3.String(self._fresh("st")) for _ in range(K)]
        for i in range(K):
            self.side.append(z3.InRe(toks[i], z3.Star(_PRINT)))
            self.side.append(z3.Implies(i >= ln, toks[i] == z3.StringVal("")))
            if m is None or i < m:
                self.side.append(z3.Implies(i < ln, z3.Not(z3.Contains(toks[i], sv))))
        self.side.append(z3.Or(*[z3.And(ln == k, s_ == _cat(*[x for j in range(k) for x in ((sv,) if j else ()) + (toks[j],)]))
                                 for k in range(1, top + 1)]))
        return "seq", SymSeq(ln, [("str", t) for t in toks])

    def _splitlines(self, s_):
        K = K_MAX
        ln = z3.Int(self._fresh("ll"))
        self.side += [ln >= 0, ln <= K]
        self.len_vars.append((ln, 0, K))
        toks = [z3.String(self._fresh("lt")) for _ in range(K)]
        nl = z3.StringVal("\n")
        for i in range(K):
            self.side += [z3.InRe(toks[i], z3.Star(z3.Union(_PRINT, z3.Re("\t")))), z3.Implies(i >= ln, toks[i] == z3.StringVal(""))]
        alts = [z3.And(ln == 0, s_ == z3.StringVal(""))]
        for k in range(1, K + 1):
            alts.append(z3.And(ln == k, z3.Length(toks[k - 1]) >= 1,
                               s_ == _cat(*[x for j in range(k) for x in ((nl,) if j else ()) + (toks[j],)])))
        self.side.append(z3.Or(*alts))
        return "seq", SymSeq(ln, [("str", t) for t in toks])

    def _partition(self, s_, args: list[ast.expr]):
        if len(args) != 1 or not (isinstance(args[0], ast.Constant) and isinstance(args[0].value, str) and args[0].value):
            raise Unsupported("partition separator must be a non-empty string constant")
        sv = z3.StringVal(args[0].value)
        self.str_consts.add(args[0].value)
        h, t = z3.String(self._fresh("ph")), z3.String(self._fresh("pt"))
        self.side += [z3.InRe(h, z3.Star(_PRINT)), z3.InRe(t, z3.Star(_PRINT))]
        found = z3.Contains(s_, sv)
        self.side.append(z3.If(found, z3.And(s_ == _cat(h, sv, t), z3.Not(z3.Contains(h, sv))),
                               z3.And(h == s_, t == z3.StringVal(""))))
        return "seq", SymSeq(z3.IntVal(3), [("str", h), ("str", z3.If(found, sv, z3.StringVal(""))), ("str", t)], tup=True)

    def _count(self, o: tuple, node: ast.Call):
        if len(node.args) != 1:
            raise Unsupported(".count() needs exactly one argument")
        if o[0] == "seq" or (o[0] == "lazy" and False):
            sq = o[1]
            x = self.term(node.args[0])
            terms = []
            for i in range(K_MAX):
                e = self._co(self._elem(sq, i), x[0] if x[0] in ("int", "bool", "str") else "str")
                terms.append(z3.If(z3.And(i < sq.length, self._eq(e, x)), 1, 0))
            return "int", z3.Sum(*terms)
        s_ = self._co(o, "str")[1]
        a = node.args[0]
        if not (isinstance(a, ast.Constant) and isinstance(a.value, str) and len(a.value) == 1):
            raise Unsupported(".count() of a multi-character or non-constant substring")
        self.str_consts.add(a.value)
        cap = 12
        self.side.append(z3.Length(s_) <= cap)
        return "int", z3.Sum(*[z3.If(z3.And(i < z3.Length(s_), z3.SubString(s_, i, 1) == z3.StringVal(a.value)), 1, 0)
                               for i in range(cap)])

    def _str_method(self, f: ast.Attribute, node: ast.Call):
        o = self.term(f.value)
        if o[0] == "str":
            key = (f.attr, o[1].sexpr(), tuple(ast.unparse(a) for a in node.args))
            if key in self._cache:
                return self._cache[key]
            r = self._str_method2(f, node, o)
            if r is not None:
                self._cache[key] = r
            return r
        return self._str_method2(f, node, o)

    def _keys_seq(self, h: "_DictH"):
        """dict.keys() as a sequence of key strings tied to the dict: the keys the condition names are the only ones
        modelled (an unnamed key cannot be observed through them)."""
        ks = sorted(h.present)[:K_MAX]
        if not ks:
            raise Unsupported(".keys() of a dict none of whose keys the condition names")
        self.bsdp = True
        ln = z3.Sum([z3.If(h.has(k), 1, 0) for k in ks])
        elems = []
        for i in range(len(ks)):
            e = z3.String(self._fresh("key"))
            self.side.append(z3.Or(*[z3.And(e == z3.StringVal(k), h.has(k)) for k in ks]))
            elems.append(("str", e))
        for i in range(len(elems)):
            for j in range(i):
                self.side.append(z3.Or(i >= ln, elems[i][1] != elems[j][1]))
        return "seq", SymSeq(ln, elems)

    def _str_method2(self, f: ast.Attribute, node: ast.Call, o: tuple):
        a = node.args
        m = f.attr
        if m == "count" and (o[0] == "seq"):
            return self._count(o, node)
        if m in ("is_absolute", "resolve", "relative_to"):
            r = self._path_method(m, o, node)
            if r is not None:
                return r
            raise Unsupported(f"method call .{m}() on a value that is not a path in `{ast.unparse(node)[:50]}`")
        if m == "keys" and not a:
            o = self._co(o, "dict")
            if o[0] == "dict":
                return self._keys_seq(o[1])
            raise Unsupported(".keys() on a value that is not a dict")
        if m == "get":
            o = self._co(o, "dict")
            if o[0] != "dict":
                raise Unsupported(f".get() on a {o[0]} value")
            if not (1 <= len(a) <= 2 and self._key(a[0]) is not None):
                raise Unsupported(".get() needs a string-constant key (or a parameter with a literal string default)")
            h: _DictH = o[1]
            k = self._key(a[0])
            self.str_consts.add(k)
            if len(a) == 1:
                self.side.append(h.has(k))
                return h.get(k)
            dflt = self.term(a[1])
            val = self._co(h.get(k), dflt[0] if dflt[0] in ("int", "bool", "str") else "str")
            if val[0] != dflt[0]:
                raise Unsupported(".get() default of a different kind")
            return val[0], z3.If(h.has(k), val[1], dflt[1])
        if m in ("strip", "lstrip", "rstrip", "lower", "upper", "casefold", "split", "splitlines", "partition", "count"):
            s_ = self._co(o, "str")
            if s_[0] != "str":
                raise Unsupported(f".{m}() on a {s_[0]} value")
            s_ = s_[1]
            if m in ("strip", "lstrip", "rstrip"):
                if a:
                    raise Unsupported(f".{m}() with characters")
                return self._strip(s_, m)
            if m in ("lower", "upper", "casefold"):
                if a:
                    raise Unsupported(f".{m}() with arguments")
                return self._case(s_, m)
            if m == "split":
                return self._split(s_, a)
            if m == "splitlines":
                if a:
                    raise Unsupported(".splitlines() with arguments")
                return self._splitlines(s_)
            if m == "partition":
                return self._partition(s_, a)
            return self._count(("str", s_), node)
        return None


    # -- paths (lexical only; no filesystem)
    def _path_of_str(self, s_) -> tuple:
        K = K_MAX
        ln = z3.Int(self._fresh("pl"))
        self.side += [ln >= 0, ln <= K]
        self.len_vars.append((ln, 0, K))
        comps = [z3.String(self._fresh("pc")) for _ in range(K)]
        alpha = z3.Star(z3.Union(z3.Range(" ", "."), z3.Range("0", "~")))
        for i in range(K):
            self.side += [z3.InRe(comps[i], alpha), z3.Implies(i < ln, z3.And(z3.Length(comps[i]) >= 1, comps[i] != z3.StringVal("."))),
                          z3.Implies(i >= ln, comps[i] == z3.StringVal(""))]
        self.side.append(z3.Or(z3.And(ln == 0, s_ == z3.StringVal("")),
                               *[z3.And(ln == k, s_ == _cat(*[x for j in range(k) for x in ((z3.StringVal("/"),) if j else ()) + (comps[j],)]))
                                 for k in range(1, K + 1)]))
        return "path", SymSeq(ln, [("str", c) for c in comps], path=True)

    def _to_path(self, t: tuple) -> tuple:
        if t[0] == "lazy":
            t = t[1].resolve("str")
        if t[0] == "path":
            return t
        if t[0] == "str":
            return self._path_of_str(t[1])
        raise Unsupported(f"a {t[0]} value used as a path")

    def _path_join(self, a: tuple, b: tuple) -> tuple:
        if a[0] == "lazy":
            a = a[1].resolve("path")
        if a[0] != "path":
            raise Unsupported(f"`/` on a {a[0]} value")
        pa, pb = a[1], self._to_path(b)[1]
        n = z3.Int(self._fresh("pj"))
        self.side += [pa.length + pb.length <= K_MAX]
        elems = []
        for i in range(K_MAX):
            r = z3.StringVal("")
            for l1 in range(i, -1, -1):  # b[i - l1] when len(a) == l1
                r = z3.If(pa.length == l1, pb.elems[i - l1][1], r)
            elems.append(("str", z3.If(i < pa.length, pa.elems[i][1], r)))
        return "path", SymSeq(pa.length + pb.length, elems, path=True)

    def _path_method(self, m: str, o: tuple, node: ast.Call):
        o = self._co(o, "path") if o[0] == "lazy" else o
        if o[0] != "path":
            return None
        sq = o[1]
        if m == "is_absolute" and not node.args:
            return "bool", z3.BoolVal(False)
        if m == "resolve" and not node.args:
            self.hint_only = True
            self.resolve_used = True  # identity: real resolve() is absolute and canonical; candidates are hints only
            return o
        if m == "relative_to" and len(node.args) == 1:
            base = self._to_path(self.term(node.args[0]))[1]
            self.side.append(base.length <= sq.length)
            self.side += [z3.Implies(i < base.length, sq.elems[i][1] == base.elems[i][1]) for i in range(K_MAX)]
            elems = []
            for i in range(K_MAX):
                r = z3.StringVal("")
                for l2 in range(K_MAX - i, -1, -1):
                    if i + l2 < K_MAX:
                        r = z3.If(base.length == l2, sq.elems[i + l2][1], r)
                elems.append(("str", r))
            return "path", SymSeq(sq.length - base.length, elems, path=True)
        return None

    # -- attributes of inputs
    def _attribute(self, node: ast.Attribute) -> tuple:
        base_node = node.value
        if isinstance(base_node, ast.Name) and base_node.id in ("self", "cls") and base_node.id not in self.params\
                and base_node.id not in self.locals and base_node.id not in self._bind:
            name = f"{base_node.id}.{node.attr}"
            if name not in self.params:
                self.params[name] = _P(name, "any")
            return self._param(name)
        v = self.term(base_node)
        a = node.attr
        if a in ("parts", "parent") or (v[0] == "path") or (
                a == "name" and isinstance(base_node, ast.Name) and base_node.id in self.pathlike):
            v = self._co(v, "path")
            if v[0] != "path":
                raise Unsupported(f"attribute .{a} of a {v[0]} value")
            sq: SymSeq = v[1]
            if a == "parts":
                return "seq", SymSeq(sq.length, sq.elems, tup=True)
            if a == "parent":
                return "path", SymSeq(z3.If(sq.length >= 1, sq.length - 1, z3.IntVal(0)), sq.elems, path=True)
            if a == "name":
                return self._select_or_empty(sq)
            raise Unsupported(f"attribute .{a} of a path")
        v = self._co(v, "obj")
        if v[0] != "obj":
            raise Unsupported(f"attribute .{a} of a {v[0]} value")
        return v[1].attr(a)

    def _select_or_empty(self, sq: SymSeq) -> tuple:
        r = z3.StringVal("")
        for k in range(K_MAX, 0, -1):
            r = z3.If(sq.length == k, sq.elems[k - 1][1], r)
        return "str", r

    # -- comprehensions
    def _comp(self, node: ast.AST, is_set: bool) -> tuple:
        if len(node.generators) != 1 or node.generators[0].is_async:
            raise Unsupported(f"comprehension with {len(node.generators)} generators")
        g = node.generators[0]
        if not isinstance(g.target, ast.Name):
            raise Unsupported("comprehension with an unpacking target")
        src = self._seq(self.term(g.iter))
        tgt = g.target.id
        outs: list[tuple] = []
        passes: list[Any] = []
        saved = self._bind.get(tgt)
        try:
            for i in range(K_MAX):
                valid = i < src.length
                self._bind[tgt] = self._elem(src, i)
                mark = len(self.side)
                conds = [self._bool(self.term(c)) for c in g.ifs]
                self._wrap(mark, valid)
                pass_i = z3.And(valid, *conds)
                mark = len(self.side)
                outs.append(self.term(node.elt))
                self._wrap(mark, valid if (self.fast and g.ifs) else pass_i)
                passes.append(pass_i)
                if self.fast and g.ifs:
                    self.fast_used = True
                    self.side.append(z3.Implies(valid, z3.And(*conds)))  # every element of the input passes the filter
        finally:
            if saved is None:
                self._bind.pop(tgt, None)
            else:
                self._bind[tgt] = saved
        kinds = {o[0] for o in outs}
        if len(kinds) != 1:
            raise Unsupported("comprehension elements of mixed kinds")
        kind = kinds.pop()
        if g.ifs and self.fast:
            sq = SymSeq(src.length, outs, is_set=is_set)
        elif g.ifs:
            if kind not in ("int", "bool", "str"):
                raise Unsupported(f"filtered comprehension producing {kind} values")
            dflt = {"int": z3.IntVal(0), "bool": z3.BoolVal(False), "str": z3.StringVal("")}[kind]
            cur = [dflt] * K_MAX
            n: Any = z3.IntVal(0)
            for i in range(K_MAX):
                cur = [z3.If(z3.And(passes[i], n == j), outs[i][1], cur[j]) for j in range(K_MAX)]
                n = z3.If(passes[i], n + 1, n)
            sq = SymSeq(n, [(kind, c) for c in cur], is_set=is_set)
        else:
            sq = SymSeq(src.length, outs, is_set=is_set)
        return "seq", sq

    def _wrap(self, mark: int, guard) -> None:
        for j in range(mark, len(self.side)):
            self.side[j] = z3.Implies(guard, self.side[j])

    def _seq_len(self, sq: SymSeq):
        if not sq.is_set:
            return sq.length
        parts = []
        for i in range(K_MAX):
            e = sq.elems[i]
            if not isinstance(e, tuple) or e[0] not in ("int", "bool", "str"):
                raise Unsupported("set of values that cannot be compared")
            dup = z3.Or(*[z3.And(j < sq.length, self._eq(sq.elems[j], e)) for j in range(i)]) if i else z3.BoolVal(False)
            parts.append(z3.If(z3.And(i < sq.length, z3.Not(dup)), 1, 0))
        return z3.Sum(*parts)

    def _isinstance_term(self, t: tuple, ts: set[str]):
        if t[0] == "lazy":
            for want, kind in (("str", "str"), ("int", "int"), ("list", "seq"), ("tuple", "seq"), ("dict", "dict")):
                if want in ts:
                    t = t[1].resolve(kind)
                    break
            else:
                raise Unsupported(f"isinstance of a value of unknown type against {sorted(ts)}")
        k = t[0]
        if k == "seq":
            sq = t[1]
            return z3.BoolVal(("set" if sq.is_set else "tuple" if sq.tup else "list") in ts)
        return z3.BoolVal({"int": "int", "bool": "bool", "str": "str", "dict": "dict"}.get(k, "?") in ts)

    def _member(self, lt: tuple, sq: SymSeq):
        kind = lt[0] if lt[0] in ("int", "bool", "str") else "str"
        return z3.Or(*[z3.And(i < sq.length, self._eq(self._co(self._elem(sq, i), kind), lt)) for i in range(K_MAX)])


def _empty_literal(n: ast.AST) -> bool:
    return (isinstance(n, ast.Dict) and not n.keys) or (isinstance(n, (ast.List, ast.Tuple, ast.Set)) and not n.elts)\
        or (isinstance(n, ast.Constant) and n.value == "" and isinstance(n.value, str))


class _Tr(_BsdpMixin):
    def __init__(self, params: dict[str, _P], locals_: dict[str, ast.expr], fast: bool = True):
        self.fast = fast  # cheap restrictions first (strip = identity on unpadded input, filters = every element passes)
        self.fast_used = False
        self.pinned: dict[str, Any] = {}  # parameters used as dict keys: fixed to their literal default (and not supplied)
        self.path_skipped = 0
        self.exc = False  # the condition names an exception class: exception types join the type domain of 'any'
        self.resolve_used = False
        self.hint_only = False  # a model assumption (Path.resolve() = identity) makes every candidate a HINT (exact=False)
        self.params, self.locals = dict(params), locals_
        self.memo: dict[str, tuple] = {}
        self.lazy_roots: dict[str, _Lazy] = {}
        self._cache: dict[tuple, tuple] = {}
        self.pathlike: set[str] = set()  # names whose .parts/.parent are read somewhere: their .name is a path name
        self.len_vars: list[tuple[Any, int, int]] = []  # (length variable, lowest, highest) of every symbolic sequence
        self._bind: dict[str, tuple] = {}
        self._uid = 0
        self.bsdp = False  # a BSDP construct (local/sequence/dict/attribute) took part: candidates must be fully re-checked
        self.ints: dict[str, Any] = {}
        self.strs: dict[str, Any] = {}
        self.lens: dict[str, Any] = {}
        self.bools: dict[str, Any] = {}
        self.tvars: dict[str, Any] = {}
        self.side: list[Any] = []
        self.used: list[str] = []
        self._depth = 0
        self.consts: set[int] = set()
        self.bl_consts: set[int] = set()
        self.str_consts: set[str] = set()

    # -- variables
    def _use(self, n: str) -> None:
        if n not in self.used:
            self.used.append(n)

    def _tvar(self, n: str):
        if n not in self.tvars:
            p = self.params[n]
            if p.unsupported:
                raise Unsupported(f"parameter {n!r}: {p.unsupported}")
            v = z3.Const(f"T_{n}", _T)
            dom = {"int": ["int"], "bool": ["bool"], "str": ["str"], "float": ["float"], "sized": _SIZED_T,
                   "list": ["list"], "tuple": ["tuple"],
                   "any": [t for t in TYPES if t != "NoneType" and (self.exc or t not in _EXC_T)]}[p.kind]
            if p.optional or p.kind == "any":
                dom = [*dom, "NoneType"]
            self.side.append(z3.Or(*[v == _TV[d] for d in dom]))
            self.tvars[n] = v
            self._use(n)
        return self.tvars[n]

    def _nn(self, n: str) -> None:
        p = self.params[n]
        if p.optional:
            self.side.append(self._tvar(n) != _TV["NoneType"])

    def _key(self, node: ast.AST) -> str | None:
        """A dict key: a string constant, or a parameter pinned to its literal string default."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and isinstance(self.pinned.get(node.id), str):
            return self.pinned[node.id]
        return None

    def _param(self, n: str):
        p = self.params[n]
        if p.unsupported:
            raise Unsupported(f"parameter {n!r}: {p.unsupported}")
        if n in self.pinned:
            v = self.pinned[n]
            return ("str", z3.StringVal(v)) if isinstance(v, str) else ("int", z3.IntVal(v))
        self._use(n)
        if p.kind in ("int", "float"):  # an integer witness is a valid float (materialised as float for `: float`)
            self._nn(n)
            return "int", self.ints.setdefault(n, z3.Int(f"i_{n}"))
        if p.kind == "bool":
            self._nn(n)
            return "bool", self.bools.setdefault(n, z3.Bool(f"b_{n}"))
        if p.kind == "str":
            self._nn(n)
            return "str", self.strs.setdefault(n, z3.String(f"s_{n}"))
        if p.kind == "sized":
            self._nn(n)
            if n not in self.lens:
                self.lens[n] = z3.Int(f"L_{n}")
                self.side += [self.lens[n] >= 0, self.lens[n] <= _BIG]
            return "sized", self.lens[n]
        if p.kind in ("list", "tuple"):
            if n not in self.lazy_roots:
                self.lazy_roots[n] = _Lazy(self, n)
            return "lazy", self.lazy_roots[n]
        if p.kind == "any":
            if n not in self.lazy_roots:
                self.lazy_roots[n] = _Lazy(self, n)
            return "lazy", self.lazy_roots[n]
        raise Unsupported(f"parameter {n!r} has no usable type (float or unknown)")

    # -- helpers
    @staticmethod
    def _num(t):
        k, e = t
        if k == "lazy":
            k, e = e.resolve("int")
        if k == "bool":
            return z3.If(e, 1, 0)
        if k == "int":
            return e
        raise Unsupported(f"{k} used as a number")

    @staticmethod
    def _bool(t):
        k, e = t
        if k == "lazy":
            raise Unsupported("truthiness of a value of unknown type")
        if k == "seq":
            return e.length > 0
        if k == "bool":
            return e
        if k == "int":
            return e != 0
        if k == "str":
            return z3.Length(e) > 0
        if k == "sized":
            return e > 0
        raise Unsupported("truthiness")

    def _const_int(self, node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant)\
                and type(node.operand.value) is int:
            return -node.operand.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Pow, ast.LShift)):
            a, b = self._const_int(node.left), self._const_int(node.right)
            if 0 <= b <= 4096 and abs(a) < 2**64:
                return a ** b if isinstance(node.op, ast.Pow) else a << b
        raise Unsupported("not an integer constant")

    # -- terms
    def term(self, node: ast.AST):
        self._depth += 1
        if self._depth > 64:
            raise Unsupported("expression too deep")
        try:
            return self._term(node)
        finally:
            self._depth -= 1

    def _term(self, node: ast.AST):
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, bool):
                return "bool", z3.BoolVal(v)
            if isinstance(v, int):
                self.consts.add(v)
                return "int", z3.IntVal(v)
            if isinstance(v, str):
                self.str_consts.add(v)
                return "str", z3.StringVal(v)
            raise Unsupported(f"constant {v!r}")
        if isinstance(node, ast.Name):
            if node.id in self._bind:
                self.bsdp = True
                return self._bind[node.id]
            if node.id in self.params:
                return self._param(node.id)
            if node.id in self.memo:
                self.bsdp = True
                return self.memo[node.id]
            if node.id in self.locals:
                loc = self.locals.pop(node.id)  # no cycles
                try:
                    t = self.term(loc)
                finally:
                    self.locals[node.id] = loc
                self.memo[node.id] = t
                self.bsdp = True
                return t
            if "\u0000" in node.id:
                nm, why = node.id.split("\u0000", 1)
                raise Unsupported(f"name {nm.split('#')[0]!r} is {why}")
            raise Unsupported(f"name {node.id.split('#')[0]!r} is not a parameter")
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return "bool", z3.Not(self._bool(self.term(node.operand)))
            x = self._num(self.term(node.operand))
            if isinstance(node.op, ast.USub):
                return "int", -x
            if isinstance(node.op, ast.UAdd):
                return "int", x
            if isinstance(node.op, ast.Invert):
                return "int", -x - 1
            raise Unsupported("unary operator")
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and len(node.values) == 2 and _empty_literal(node.values[1]):
            self.bsdp = True
            return self.term(node.values[0])  # `x or {}`: the value of x (an empty/falsy x is that same empty value)
        if isinstance(node, ast.BoolOp):
            parts = [self._bool(self.term(v)) for v in node.values]
            return "bool", (z3.And(*parts) if isinstance(node.op, ast.And) else z3.Or(*parts))
        if isinstance(node, ast.IfExp):
            c = self._bool(self.term(node.test))
            a, b = self.term(node.body), self.term(node.orelse)
            if a[0] == "lazy" and b[0] in ("int", "bool", "str"):
                a = self._co(a, b[0])
            elif b[0] == "lazy" and a[0] in ("int", "bool", "str"):
                b = self._co(b, a[0])
            if a[0] == "path" and b[0] == "path":
                self.bsdp = True
                qa, qb = a[1], b[1]
                return "path", SymSeq(z3.If(c, qa.length, qb.length),
                                      [(qa.elems[i][0], z3.If(c, qa.elems[i][1], qb.elems[i][1])) for i in range(K_MAX)], path=True)
            if "path" in (a[0], b[0]):  # one arm is a path: pick it (a restriction of the inputs, never a guess)
                self.bsdp = True
                if a[0] == "path":
                    self.side.append(c)
                    return a
                self.side.append(z3.Not(c))
                return b
            if a[0] == b[0] and a[0] in ("int", "bool", "str"):
                return a[0], z3.If(c, a[1], b[1])
            return "int", z3.If(c, self._num(a), self._num(b))
        if isinstance(node, ast.BinOp):
            return self._binop(node)
        if isinstance(node, ast.Compare):
            return "bool", self._compare(node)
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.Subscript):
            self.bsdp = True
            return self._index(node)
        if isinstance(node, ast.Attribute):
            self.bsdp = True
            return self._attribute(node)
        if isinstance(node, (ast.ListComp, ast.SetComp)):
            self.bsdp = True
            return self._comp(node, isinstance(node, ast.SetComp))
        raise Unsupported(f"unsupported construct {type(node).__name__} in `{ast.unparse(node)[:50]}`")

    def _binop(self, node: ast.BinOp):
        op = node.op
        if not any(isinstance(x, ast.Name) for x in ast.walk(node)):  # constant expression: fold with the pure evaluator
            try:
                v = _ev(node, {})
            except (Unsupported, ArithmeticError, TypeError, ValueError):
                v = None
            if isinstance(v, bool):
                return "bool", z3.BoolVal(v)
            if isinstance(v, int):
                self.consts.add(v)
                return "int", z3.IntVal(v)
            if isinstance(v, str):
                return "str", z3.StringVal(v)
        if isinstance(op, (ast.LShift, ast.RShift, ast.Pow)):
            k = self._const_int(node.right)
            if isinstance(op, ast.Pow):
                if not 0 <= k <= 6:
                    raise Unsupported("exponent must be a constant 0..6")
                x = self._num(self.term(node.left))
                r = z3.IntVal(1)
                for _ in range(k):
                    r = r * x
                return "int", r
            if not 0 <= k <= 100000:
                raise Unsupported("shift amount")
            x = self._num(self.term(node.left))
            return "int", (x * _pow2(k) if isinstance(op, ast.LShift) else x / _pow2(k))
        if isinstance(op, (ast.FloorDiv, ast.Mod)):
            m = self._const_int(node.right)
            if m <= 0:
                raise Unsupported("divisor must be a positive constant")
            self.consts.add(m)
            x = self._num(self.term(node.left))
            return "int", (x / m if isinstance(op, ast.FloorDiv) else x % m)
        if isinstance(op, (ast.BitAnd, ast.BitOr, ast.BitXor)):
            try:
                c, other = self._const_int(node.right), node.left
            except Unsupported:
                c, other = self._const_int(node.left), node.right
            if c < 0:
                raise Unsupported("bitwise operand must be a non-negative constant")
            self.consts.add(c)
            x = self._num(self.term(other))
            w = max(c.bit_length(), 1)
            if w > 4096:
                raise Unsupported("mask too wide")
            low = z3.Int2BV(x, w)
            cv = z3.BitVecVal(c, w)
            if isinstance(op, ast.BitAnd):
                return "int", z3.BV2Int(low & cv)
            res = z3.BV2Int(low | cv) if isinstance(op, ast.BitOr) else z3.BV2Int(low ^ cv)
            return "int", (x - x % _pow2(w)) + res
        a, b = self.term(node.left), self.term(node.right)
        if isinstance(op, ast.Div):
            self.bsdp = True
            return self._path_join(a, b)
        if isinstance(op, ast.Add) and "str" in (a[0], b[0]):
            a, b = self._co(a, "str"), self._co(b, "str")
        if isinstance(op, ast.Add):
            if a[0] == "str" and b[0] == "str":
                return "str", z3.Concat(a[1], b[1])
            return "int", self._num(a) + self._num(b)
        if isinstance(op, ast.Sub):
            return "int", self._num(a) - self._num(b)
        if isinstance(op, ast.Mult):
            return "int", self._num(a) * self._num(b)
        raise Unsupported(f"operator {type(op).__name__}")

    def _call(self, node: ast.Call):
        f = node.func
        if node.keywords:
            raise Unsupported("keyword arguments")
        if isinstance(f, ast.Name):
            n, args = f.id, node.args
            if n == "len" and len(args) == 1:
                t = self.term(args[0])
                if t[0] == "sized":
                    return "int", t[1]
                if t[0] == "str":
                    return "int", z3.Length(t[1])
                if t[0] == "lazy":
                    t = self._co(t, "seq")
                if t[0] in ("seq", "path"):
                    self.bsdp = True
                    return "int", self._seq_len(t[1])
                raise Unsupported("len of a non-sized value")
            if n == "str" and len(args) == 1:
                t = self._co(self.term(args[0]), "int")
                if t[0] == "str":
                    return t
                self.side.append(self._num(t) >= 0)
                self.bsdp = True
                return "str", z3.IntToStr(self._num(t))
            if n in ("set", "list", "tuple") and len(args) == 1:
                sq = self._seq(self.term(args[0]))
                self.bsdp = True
                return "seq", SymSeq(sq.length, sq.elems, tup=(n == "tuple"), is_set=(n == "set"), box=sq.box)
            if n == "abs" and len(args) == 1:
                x = self._num(self.term(args[0]))
                return "int", z3.If(x >= 0, x, -x)
            if n in ("min", "max") and len(args) == 2:
                a, b = self._num(self.term(args[0])), self._num(self.term(args[1]))
                return "int", (z3.If(a <= b, a, b) if n == "min" else z3.If(a >= b, a, b))
            if n == "bool" and len(args) == 1:
                return "bool", self._bool(self.term(args[0]))
            if n == "isinstance" and len(args) == 2 and isinstance(args[0], ast.Name) and args[0].id in self.params:
                return "bool", self._isinstance(args[0].id, args[1])
            if n == "isinstance" and len(args) == 2:
                self.bsdp = True
                return "bool", self._isinstance_term(self.term(args[0]), self._types_of(args[1]))
            if n in ("Path", "PurePath", "PurePosixPath") and len(args) == 1:
                self.bsdp = True
                return self._to_path(self.term(args[0]))
            if n in ("float", "int") and len(args) == 1:
                t = self.term(args[0])
                if t[0] == "str":
                    if n == "float":
                        raise Unsupported("float() of a string")
                    self.bsdp = True
                    self.side.append(z3.InRe(t[1], z3.Plus(z3.Range("0", "9"))))  # int("12") only; int("x") raises
                    return "int", z3.StrToInt(t[1])
                self.bsdp = True
                return "int", self._num(t)
            if n in ("deepcopy", "dict") and len(args) == 1:
                t = self.term(args[0])
                if n == "deepcopy" or t[0] in ("dict", "lazy"):
                    return t
            if n == "copy" and len(args) == 1:
                return self.term(args[0])
            raise Unsupported(f"call to {n}() in `{ast.unparse(node)[:50]}`")
        if isinstance(f, ast.Attribute):
            if f.attr in ("deepcopy", "copy") and isinstance(f.value, ast.Name) and f.value.id == "copy"\
                    and len(node.args) == 1:
                return self.term(node.args[0])  # a copy is the same value for every condition on it
            if f.attr in ("startswith", "endswith") and len(node.args) == 1:
                o, a = self.term(f.value), self.term(node.args[0])
                o, a = self._co(o, "str"), self._co(a, "str")
                if o[0] == "str" and a[0] == "str":
                    return "bool", (z3.PrefixOf(a[1], o[1]) if f.attr == "startswith" else z3.SuffixOf(a[1], o[1]))
            if f.attr == "bit_length":
                raise Unsupported("bit_length() outside a comparison with an integer constant")
            r = self._str_method(f, node)
            if r is not None:
                self.bsdp = True
                return r
            raise Unsupported(f"method call .{f.attr}() in `{ast.unparse(node)[:50]}`")
        raise Unsupported("call of a non-name")

    def _types_of(self, node: ast.AST) -> set[str]:
        names: list[ast.AST] = list(node.elts) if isinstance(node, ast.Tuple) else [node]
        out: set[str] = set()
        for x in names:
            if isinstance(x, ast.Name) and x.id in _BUILTIN_T:
                out |= _SUB[x.id]
            elif isinstance(x, ast.Constant) and x.value is None:
                out.add("NoneType")
            else:
                raise Unsupported(f"type {ast.unparse(x)!r} is not a builtin")
        return out

    def _isinstance(self, p: str, tn: ast.AST):
        ts = self._types_of(tn)
        v = self._tvar(p)
        return z3.Or(*[v == _TV[t] for t in sorted(ts)]) if ts else z3.BoolVal(False)

    def _bl(self, node: ast.AST):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "bit_length"\
                and not node.args:
            return self._num(self.term(node.func.value))
        return None

    def _compare(self, node: ast.Compare):
        parts = []
        left = node.left
        for op, right in zip(node.ops, node.comparators):
            parts.append(self._cmp1(left, op, right))
            left = right
        return z3.And(*parts) if len(parts) > 1 else parts[0]

    def _cmp1(self, l: ast.AST, op: ast.cmpop, r: ast.AST):
        # None tests
        for a, b in ((l, r), (r, l)):
            if isinstance(b, ast.Constant) and b.value is None and isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
                if isinstance(a, ast.Name) and a.id in self.params:
                    p = self.params[a.id]
                    eq = (self._tvar(a.id) == _TV["NoneType"]) if (p.optional or p.kind == "any") else z3.BoolVal(False)
                    return eq if isinstance(op, (ast.Is, ast.Eq)) else z3.Not(eq)
                raise Unsupported("None test on a non-parameter")
        # type(p) is T
        for a, b in ((l, r), (r, l)):
            if isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id == "type" and len(a.args) == 1\
                    and isinstance(a.args[0], ast.Name) and a.args[0].id in self.params\
                    and isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
                if isinstance(b, ast.Name) and b.id in _BUILTIN_T:
                    eq = self._tvar(a.args[0].id) == _TV[b.id]
                elif isinstance(b, ast.Constant) and b.value is None:
                    eq = self._tvar(a.args[0].id) == _TV["NoneType"]
                else:
                    raise Unsupported("type() compared with a non-builtin")
                return eq if isinstance(op, (ast.Is, ast.Eq)) else z3.Not(eq)
        # x.bit_length() <op> const
        for bl_node, c_node, flip in ((l, r, False), (r, l, True)):
            x = self._bl(bl_node)
            if x is None:
                continue
            C = self._const_int(c_node)
            self.bl_consts.add(C)
            opn = type(op)
            swap = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE, ast.Eq: ast.Eq, ast.NotEq: ast.NotEq}
            if opn not in swap:
                raise Unsupported("bit_length() comparison operator")
            if flip:
                opn = swap[opn]
            ax = z3.If(x >= 0, x, -x)
            ge = (lambda c: z3.BoolVal(True) if c <= 0 else ax >= _pow2(c - 1))  # bit_length >= c
            if opn is ast.GtE:
                return ge(C)
            if opn is ast.Gt:
                return ge(C + 1)
            if opn is ast.Lt:
                return z3.Not(ge(C))
            if opn is ast.LtE:
                return z3.Not(ge(C + 1))
            eq = (x == 0) if C == 0 else z3.And(ge(C), z3.Not(ge(C + 1)))
            if C < 0:
                eq = z3.BoolVal(False)
            return eq if opn is ast.Eq else z3.Not(eq)
        if isinstance(op, (ast.In, ast.NotIn)):
            if isinstance(r, (ast.Tuple, ast.List, ast.Set)) and r.elts and all(isinstance(e, ast.Constant) for e in r.elts):
                lt = self.term(l)
                alts = []
                for e in r.elts:
                    et = self.term(e)
                    alts.append(self._eq(lt, et))
                res = z3.Or(*alts)
                return res if isinstance(op, ast.In) else z3.Not(res)
            lt, rt = self.term(l), self.term(r)
            if rt[0] == "lazy" and isinstance(l, ast.Constant) and isinstance(l.value, str):
                rt = self._co(rt, "dict")
            if rt[0] == "dict" and isinstance(l, ast.Constant) and isinstance(l.value, str):
                self.bsdp = True
                res = rt[1].has(l.value)
                return res if isinstance(op, ast.In) else z3.Not(res)
            if rt[0] in ("seq", "path") or (rt[0] == "lazy" and lt[0] in ("int", "str", "bool")):
                self.bsdp = True
                res = self._member(lt, self._seq(rt))
                return res if isinstance(op, ast.In) else z3.Not(res)
            if isinstance(op, (ast.In, ast.NotIn)) and lt[0] == "str" and rt[0] == "str":
                res = z3.Contains(rt[1], lt[1])
                return res if isinstance(op, ast.In) else z3.Not(res)
            raise Unsupported("'in' over a non-literal container")
        a, b = self.term(l), self.term(r)
        if isinstance(op, (ast.Eq, ast.NotEq)):
            e = self._eq(a, b)
            return e if isinstance(op, ast.Eq) else z3.Not(e)
        if a[0] == "str" or b[0] == "str":
            raise Unsupported("ordering comparison of strings")
        x, y = self._num(a), self._num(b)
        for T, f in ((ast.Lt, lambda: x < y), (ast.LtE, lambda: x <= y), (ast.Gt, lambda: x > y), (ast.GtE, lambda: x >= y)):
            if isinstance(op, T):
                return f()
        raise Unsupported(f"comparison {type(op).__name__}")

    def _eq(self, a, b):
        if a[0] == "lazy" and b[0] in ("int", "bool", "str"):
            a = self._co(a, b[0])
        elif b[0] == "lazy" and a[0] in ("int", "bool", "str"):
            b = self._co(b, a[0])
        if "lazy" in (a[0], b[0]):
            raise Unsupported("comparison of two values of unknown type")
        if a[0] == "str" and b[0] == "str":
            return a[1] == b[1]
        if "str" in (a[0], b[0]):
            return z3.BoolVal(False)
        if "sized" in (a[0], b[0]):
            raise Unsupported("sized value compared directly")
        return self._num(a) == self._num(b)

    # -- polarity-aware modelling: pos(x) implies x True, neg(x) implies x False; unsupported parts are skipped
    def pos(self, node: ast.AST, notes: list[str]):
        if isinstance(node, ast.BoolOp):
            kids = [self._maybe(self.pos, v, notes) for v in node.values]
            if isinstance(node.op, ast.And):
                got = [k for k in kids if k is not None]
                if len(got) < len(kids):
                    notes.append("partial")
                return z3.And(*got) if got else None
            got = [k for k in kids if k is not None]
            if len(got) < len(kids):
                notes.append("partial")
            return z3.Or(*got) if got else None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.neg(node.operand, notes)
        return self._bool(self.term(node))

    def neg(self, node: ast.AST, notes: list[str]):
        if isinstance(node, ast.BoolOp):
            kids = [self._maybe(self.neg, v, notes) for v in node.values]
            got = [k for k in kids if k is not None]
            if isinstance(node.op, ast.And):
                if len(got) < len(kids):
                    notes.append("partial")
                return z3.Or(*got) if got else None
            if len(got) < len(kids):
                notes.append("partial")
            return z3.And(*got) if got else None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.pos(node.operand, notes)
        return z3.Not(self._bool(self.term(node)))

    def _maybe(self, fn, node, notes):
        try:
            return fn(node, notes)
        except Unsupported as e:
            notes.append(f"residual: {ast.unparse(node)}")
            notes.append(f"unsupported: {e}")
            return None


# ------------------------------------------------------------------ the engine
def _decode(s: str) -> str:
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), s)


def _parse_expr(c: Any, fn: ast.AST | None) -> ast.expr:
    if isinstance(c, ast.expr):
        return ast.parse(ast.unparse(c), mode="eval").body
    if isinstance(c, str):
        try:
            return ast.parse(c.strip(), mode="eval").body
        except SyntaxError as e:
            raise Unsupported(f"condition does not parse: {e.msg}")
    if isinstance(c, tuple) and len(c) == 2 and fn is not None:
        for n in ast.walk(fn):
            if isinstance(n, ast.expr) and getattr(n, "lineno", None) == c[0] and n.col_offset == c[1]:
                return ast.parse(ast.unparse(n), mode="eval").body
        raise Unsupported(f"no expression at {c}")
    raise Unsupported("condition must be source text, an ast.expr or (lineno, col)")


@dataclass
class _Run:
    cands: list[tuple[dict[str, Any], str]] = field(default_factory=list)  # (internal assignment, origin)
    reason: str = ""
    exact: bool = True
    status: dict[str, bool] = field(default_factory=dict)
    fast_used: bool = False  # a cheap restriction (identity strip, all-pass filter) shaped the translation
    strict: bool = False  # a BSDP construct took part: a candidate my evaluator cannot decide is dropped, not kept
    residuals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Sized:
    n: int
    t: str | None  # forced container type, or None


# Z3 resource units per millisecond of wall time on the PINNED solver (z3-solver 5.3.2.0, uv.lock). Method: 92 driver
# queries (own BSDP, group B/C, cost, cut-point cases, both polarities) run uncut with per-check `rlimit count` deltas
# and wall time; over the 111 checks taking >= 4 ms: units/ms p10 201, p25 434, median 563, p75 726, p90 956, total
# units / total ms = 980. 1000 (the weighted rate) makes q ms of budget cost about q ms of wall on an idle core. The
# earlier 6000 was measured on 5.4.1 and made every cut about 6x too generous under the pin.
_RL_PER_MS = 1000

# Deterministic clock. Budgets are spent in Z3 resource units (1000 per "ms"), never in wall time, so the same query
# gives the same candidate list on an idle and on a loaded machine. Wall time only exists outside this module (the
# sandbox's hard kill), and a killed call returns a named stop, never a different candidate list.
_WORK = {"units": 0, "last": None}


def _rl_count(solver) -> int:
    st = solver.statistics()
    for k in st.keys():
        if k == "rlimit count":
            return int(st.get_key_value(k))
    return 0


def _work_ms() -> float:
    return _WORK["units"] / _RL_PER_MS


def _check(s):
    """s.check() that advances the deterministic work clock by the units the check consumed (the statistic is
    cumulative over the Z3 context, so each check adds the difference to the previous reading)."""
    if _WORK["last"] is None:
        probe = z3.Solver()
        probe.check()
        _WORK["last"] = _rl_count(probe)
    r = s.check()
    v = _rl_count(s)
    _WORK["units"] += max(0, v - _WORK["last"])
    _WORK["last"] = v
    return r


_SEED_EVALS = 4000  # evaluator calls a seed pass may spend (a count, not a time)
_RESOLVE_NOTE = "models Path.resolve() as identity (real resolve is absolute/canonical): hint only"


def _core(params: dict[str, _P], cond: ast.expr, polarity: bool, path: Sequence[tuple[ast.expr, bool]],
          locals_: dict[str, ast.expr], per_query_ms: int, budget_ms: int, max_cand: int) -> _Run:
    """Cheap restricted translation first; when it found nothing and used a restriction, the exact one with the
    remaining budget. Both are candidate generators (every candidate is re-checked)."""
    w0 = _work_ms()
    run = _core1(params, cond, polarity, path, locals_, per_query_ms, budget_ms, max_cand, True)
    if run.cands or not run.fast_used:
        return run
    left = budget_ms - int(_work_ms() - w0)
    if left <= 0:
        return run
    run2 = _core1(params, cond, polarity, path, locals_, per_query_ms, left, max_cand, False)
    return run2 if run2.cands or not run.reason else run


def _core1(params: dict[str, _P], cond: ast.expr, polarity: bool, path: Sequence[tuple[ast.expr, bool]],
           locals_: dict[str, ast.expr], per_query_ms: int, budget_ms: int, max_cand: int, fast: bool) -> _Run:
    run = _Run()
    w_end = _work_ms() + budget_ms
    tr = _Tr(params, dict(locals_), fast)
    for root_ in [cond, *(pc for pc, _ in path), *locals_.values()]:
        for n_ in ast.walk(root_):
            key_ = None
            if isinstance(n_, ast.Call) and isinstance(n_.func, ast.Attribute) and n_.func.attr == "get" and n_.args:
                key_ = n_.args[0]
            elif isinstance(n_, ast.Subscript) and not isinstance(n_.slice, ast.Slice):
                key_ = n_.slice
            if isinstance(key_, ast.Name) and key_.id in params and params[key_.id].has_default\
                    and isinstance(params[key_.id].default, str):
                tr.pinned[key_.id] = params[key_.id].default
    for root_ in [cond, *(pc for pc, _ in path), *locals_.values()]:
        for n_ in ast.walk(root_):
            if isinstance(n_, ast.Attribute) and n_.attr in ("parts", "parent") and isinstance(n_.value, ast.Name):
                tr.pathlike.add(n_.value.id)
    tr.exc = any(isinstance(n_, ast.Name) and n_.id in _EXC_T
                 for root_ in [cond, *(pc for pc, _ in path), *locals_.values()] for n_ in ast.walk(root_))
    notes: list[str] = []
    forms: list[Any] = []
    try:
        for pc, pol in path:
            try:
                f = (tr.pos if pol else tr.neg)(pc, notes)
            except Unsupported:
                f = None
            if f is None:  # an unmodelled earlier guard never aborts: solve the modelled subset and call it a HINT
                tr.hint_only = True
                tr.path_skipped += 1
                run.residuals.append(f"path condition: {ast.unparse(pc)}")
                continue
            forms.append(f)
        f = (tr.pos if polarity else tr.neg)(cond, notes)
        if f is None:
            raise Unsupported("; ".join(dict.fromkeys(notes)) or "condition not modelled")
        forms.append(f)
    except Unsupported as e:
        run.reason = f"unsupported: {e}"
        run.exact = False
        run.residuals = [ast.unparse(cond)]
        run.fast_used = tr.fast_used
        run.strict = tr.bsdp
        # seeds can still be tried against my own evaluator when the evaluator understands the condition
        _seed_only(run, params, cond, polarity, path, tr, max_cand)
        return run
    run.residuals.extend(note[len("residual: "):] for note in notes if note.startswith("residual: "))
    run.residuals = list(dict.fromkeys(run.residuals))
    run.exact = not notes and not tr.hint_only
    if tr.hint_only:
        why = [_RESOLVE_NOTE] if tr.resolve_used else []
        if tr.path_skipped:
            why.append(f"{tr.path_skipped} earlier guard(s) not modelled: hint only")
        run.reason = (run.reason + "; " if run.reason else "") + "; ".join(why)
    run.fast_used = tr.fast_used
    run.strict = tr.bsdp and not tr.hint_only and not run.residuals  # residual-backed models generate hints only
    if notes:
        run.reason = "partial model: " + "; ".join(dict.fromkeys(n for n in notes if n != "partial")) if any(
            n != "partial" for n in notes) else "partial model"
    used = list(tr.used)
    base = z3.And(*forms, *tr.side)
    # progressive caps: small values first (readable), then wide, then unbounded
    ladder: list[Any] = [("print", 100), ("small", 10**6), ("wide", 2**70), ("free", None)]
    seen: set[tuple] = set()
    zmax = (max(0, (max_cand - 1) // 2) if any(n in params and params[n].shape is not None for n in used)
            else max(1, (max_cand + 1) // 2))  # reserve room for bounded annotation-shape seeds
    # Symbolic sequences: Z3's string solver is far faster with every sequence length FIXED, so the smallest length
    # combinations are tried first (short queries), then the unconstrained problem.
    cases: list[list[Any] | None] = []
    if tr.len_vars:
        rngs = [range(lo, hi + 1) for _, lo, hi in tr.len_vars]
        for c in sorted(itertools.product(*rngs), key=lambda c: (sum(c), c))[:40]:
            cases.append([v == k for (v, _, _), k in zip(tr.len_vars, c)])
        # Partly fixed: only the leading (outermost) lengths are pinned and the rest stay free. Fully pinned cases fail
        # when a sequence the condition never reaches is still constrained; the unconstrained query is the costly one.
        for j in range(1, min(2, len(tr.len_vars) - 1) + 1):
            for c in sorted(itertools.product(*rngs[:j]), key=lambda c: (sum(c), c))[:6]:
                cases.append([v == k for (v, _, _), k in zip(tr.len_vars[:j], c)])
    cases.append(None)
    seen: set[tuple] = set()
    zmax = (max(0, (max_cand - 1) // 2) if any(n in params and params[n].shape is not None for n in used)
            else max(1, (max_cand + 1) // 2))  # reserve room for bounded annotation-shape seeds
    timed_out = False
    dups = 0
    for case in cases:
        if len(run.cands) >= zmax or _work_ms() > w_end:
            break
        case_unknown = False
        for tag, cap in (ladder if case is None else [ladder[0], ladder[-1]]):
            if len(run.cands) >= zmax or _work_ms() > w_end:
                break
            if case is not None and tag == "free" and case_unknown:
                break  # the readable (printable) query already timed out: the unrestricted one is not easier
            s = z3.Solver()
            s.add(base)
            if case is not None:
                s.add(*case)
            if cap is not None:
                for v in tr.ints.values():
                    s.add(v <= cap, v >= -cap)
                for v in tr.lens.values():
                    s.add(v <= min(cap, 5000))
                for v in tr.strs.values():
                    s.add(z3.Length(v) <= min(cap, 5000))
            if tag == "print":
                for v in tr.strs.values():
                    s.add(z3.InRe(v, z3.Star(z3.Range(" ", "~"))))
            while len(run.cands) < zmax:
                remaining = int(w_end - _work_ms())
                if remaining <= 0:
                    run.reason = (run.reason + "; " if run.reason else "") + "budget exhausted"
                    break
                q_ms = max(1, min(per_query_ms if case is None else min(per_query_ms, 150), remaining))
                # Deterministic effort limit (Z3 resource units, ~RL_PER_MS per ms on the pinned Z3): the same query is
                # cut at the same point on a loaded and an idle machine.
                s.set("rlimit", q_ms * _RL_PER_MS)
                s.set("timeout", q_ms * 200)  # wall: a last-resort net only; the sandbox kills the process long before
                r = _check(s)
                if r != z3.sat:
                    if r == z3.unknown:
                        timed_out = True
                        case_unknown = True
                    if r == z3.unknown and not run.cands and tag == "free" and case is None:
                        run.reason = (run.reason + "; " if run.reason else "") + "solver timeout"
                    break
                m = s.model()
                assign = _extract(m, tr, params)
                key = tuple(sorted((k, repr(v)) for k, v in assign.items()))
                block = []
                for n, v in [*tr.ints.items(), *tr.lens.items(), *tr.strs.items(), *tr.bools.items(), *tr.tvars.items()]:
                    block.append(v != m.eval(v, model_completion=True))
                s.add(z3.Or(*block) if block else z3.BoolVal(False))
                if key not in seen:
                    seen.add(key)
                    dups = 0
                    origin = "typed" if tr.tvars and not (tr.ints or tr.strs or tr.lens or tr.bools) else "z3"
                    run.cands.append((assign, origin))
                else:
                    dups += 1  # the models differ only in variables no input depends on (e.g. elements past a length)
                    if dups >= 3:
                        break
                if not block:
                    break
        if run.cands and tr.len_vars:
            break  # one length case with solutions is enough; the rest of the slots go to seeds
    if timed_out and not run.cands and "solver timeout" not in run.reason and "budget" not in run.reason:
        run.reason = (run.reason + "; " if run.reason else "") + "solver timeout"
    bound_note = f"; symbolic sequences are bounded to K={K_MAX} elements" if tr.len_vars else ""
    if zmax == 0 and not run.reason:
        run.reason = "symbolic search skipped to reserve candidates for bounded annotation-shape seeds"
    elif not run.cands and not run.reason:
        run.reason = "unsat within the explored caps (|int|<=100, 1e6, 2^70, unbounded; length<=5000)" + bound_note
    elif not run.cands and "solver timeout" not in run.reason and "budget" not in run.reason:
        run.reason += "; unsat within the explored caps" + bound_note
    _add_seeds(run, tr.params, cond, polarity, path, tr, used, max_cand)
    return run


def _term_value(m, t: tuple) -> Any:
    k, v = t
    if k == "int":
        return m.eval(v, model_completion=True).as_long()
    if k == "bool":
        return bool(z3.is_true(m.eval(v, model_completion=True)))
    if k == "str":
        return _decode(m.eval(v, model_completion=True).as_string())
    return 0


def _lz_value(m, lz: "_Lazy") -> Any:
    t = lz.term
    if t is None:
        return 0
    k, v = t
    if k == "int":
        return m.eval(v, model_completion=True).as_long()
    if k == "bool":
        return bool(z3.is_true(m.eval(v, model_completion=True)))
    if k == "str":
        return _decode(m.eval(v, model_completion=True).as_string())
    if k in ("seq", "path"):
        ln = max(0, min(K_MAX, m.eval(v.length, model_completion=True).as_long()))
        if k == "path" or v.path:
            return _PathVal("/".join(_decode(m.eval(e[1], model_completion=True).as_string()) for e in v.elems[:ln]))
        items = [(x if isinstance(x, tuple) else ("lazy", x)) for x in v.elems[:ln]]
        return [_lz_value(m, e[1]) if e[0] == "lazy" else _term_value(m, e) for e in items]
    if k == "dict":
        return _DictVal({key: _lz_value(m, lz2) for key, lz2 in v.vals.items()
                         if z3.is_true(m.eval(v.present[key], model_completion=True))})
    if k == "obj":
        return _ObjVal({a: _lz_value(m, lz2) for a, lz2 in v.attrs.items()})
    return 0


def _extract(m, tr: _Tr, params: dict[str, _P]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    params = tr.params
    for n in tr.used:
        p = params[n]
        if n in tr.lazy_roots and tr.lazy_roots[n].term is not None and tr.lazy_roots[n].term[0] in ("seq", "path", "dict", "obj"):
            out[n] = _lz_value(m, tr.lazy_roots[n])
            continue
        t = None
        if n in tr.tvars:
            t = TYPES[[str(c) for c in _TC].index(str(m.eval(tr.tvars[n], model_completion=True)))]
        if t == "NoneType":
            out[n] = None
        elif p.kind == "sized" or n in tr.lens:
            ln = m.eval(tr.lens[n], model_completion=True).as_long() if n in tr.lens else 1
            out[n] = _Sized(ln, t)
        elif n in tr.ints:
            out[n] = m.eval(tr.ints[n], model_completion=True).as_long()
            if p.kind == "float":
                out[n] = float(out[n])
        elif n in tr.bools:
            out[n] = bool(z3.is_true(m.eval(tr.bools[n], model_completion=True)))
        elif n in tr.strs:
            out[n] = _decode(m.eval(tr.strs[n], model_completion=True).as_string())
        elif t is not None:
            out[n] = _rep(t)
        else:
            out[n] = {"int": 0, "bool": False, "str": "", "float": 0.0, "any": 0}.get(p.kind, 0)
    return out


def _rep(t: str) -> Any:
    v = _REP[t]
    return type(v)(v) if isinstance(v, (list, dict, set)) else v


def _concrete(v: Any) -> Any:
    if isinstance(v, _DictVal):
        return {k: _concrete(x) for k, x in v.items.items()}
    if isinstance(v, _ObjVal):
        return types.SimpleNamespace(**{k: _concrete(x) for k, x in v.attrs.items()})
    if isinstance(v, _PathVal):
        return PurePosixPath(v.text)
    if isinstance(v, list):
        return [_concrete(x) for x in v]
    return v


def _jsonify(v: Any) -> Any:
    """Descriptors review materialises: {"__dict__": {k: v}}, {"__attrs__": {a: v}} / {"__attr_dict__": {a: {k: v}}},
    {"__path__": "a/b"}, {"__tuple__": [...]}, {"__seq_rec__": [{a: v}, ...]}; lists of scalars/descriptors are plain JSON lists."""
    if isinstance(v, _DictVal):
        return {"__dict__": {k: _jsonify(x) for k, x in v.items.items()}}
    if isinstance(v, _PathVal):
        return {"__path__": v.text}
    if isinstance(v, _ObjVal):
        if v.attrs and all(isinstance(x, _DictVal) for x in v.attrs.values()):
            return {"__attr_dict__": {a: {k: _jsonify(y) for k, y in x.items.items()} for a, x in v.attrs.items()}}
        return {"__attrs__": {a: _jsonify(x) for a, x in v.attrs.items()}}
    if type(v) is tuple:
        return {"__tuple__": [_jsonify(x) for x in v]}
    if isinstance(v, list):
        if v and all(isinstance(x, _ObjVal) for x in v):
            return {"__seq_rec__": [{a: _jsonify(y) for a, y in x.attrs.items()} for x in v]}
        return [_jsonify(x) for x in v]
    return v


def _materialise(assign: dict[str, Any], variant: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in assign.items():
        if isinstance(v, (_DictVal, _ObjVal, _PathVal, list)):
            out[k] = _concrete(v)
        elif isinstance(v, _Sized):
            t = v.t or variant
            out[k] = {"list": [0] * v.n, "tuple": (0,) * v.n, "str": "a" * v.n, "bytes": b"a" * v.n,
                      "dict": {i: 0 for i in range(v.n)}, "set": set(range(v.n))}[t]
        else:
            out[k] = v
    return out


def _env_for(assign: dict[str, Any], params: dict[str, _P], variant: str) -> dict[str, Any]:
    env = _materialise(assign, variant)
    for k in [k for k in env if "." in k]:  # receiver fields ("self.events") live on a namespace named by their root
        root, _, attr = k.partition(".")
        ns = env.get(root)
        if not isinstance(ns, types.SimpleNamespace):
            ns = env[root] = types.SimpleNamespace()
        setattr(ns, attr, env[k])
    for n, p in params.items():
        if n not in env and p.has_default:
            env[n] = p.default
    return env


def _holds(cond: ast.expr, polarity: bool, path, env, locals_) -> bool | None:
    """True: whole condition + path have the wanted values on env; None: undecided by my evaluator; False: no."""
    e = dict(env)
    for k, v in locals_.items():  # inlined single assignments, evaluated in order of definition
        try:
            e[k] = _ev(v, {**_EVAL_TYPES, **e})
        except (Unsupported, ArithmeticError, LookupError, TypeError, ValueError, AttributeError, MemoryError, RecursionError):
            pass
    res: list[bool | None] = []
    for pc, pol in path:
        t = _tri(pc, e)
        res.append(None if t is None else t == pol)
    t = _tri(cond, e)
    res.append(None if t is None else t == polarity)
    if False in res:
        return False
    return None if None in res else True


def _finalise(run: _Run, params, cond, polarity, path, locals_, assigns: list[tuple[dict[str, Any], str]], max_cand):
    """Keep only candidates my evaluator does not contradict. Returns [(kwargs, origin, checked)]."""
    out: list[tuple[dict[str, Any], str, bool, dict[str, Any]]] = []
    seen: set[str] = set()
    for assign, origin in assigns:
        variants = ["list", "str"] if any(isinstance(v, _Sized) and v.t is None for v in assign.values()) else ["list"]
        for variant in variants:
            env = _env_for(assign, params, variant)
            if any(p.shape is not None and n in assign
                   and not _matches_shape(env[n], p.shape, optional=p.optional, max_list_len=K_MAX)
                   for n, p in params.items()):
                continue
            h = _holds(cond, polarity, path, env, locals_)
            if h is False or (h is None and run.strict):
                continue
            kw = _materialise(assign, variant)
            key = repr(sorted(kw.items(), key=lambda kv: kv[0]))
            if key in seen:
                continue
            seen.add(key)
            out.append((kw, origin, h is True, assign))
            if len(out) >= max_cand:
                return out
    return out


def _seed_values(tr: _Tr, cond_nodes: Iterable[ast.AST]) -> tuple[list[int], list[str]]:
    """Threshold-first ordering: c-1, c, c+1 of every constant, then bit boundaries, then the generic 0/1/-1."""
    ints: list[int] = list(tr.consts)
    strs: set[str] = set(tr.str_consts)
    for n in cond_nodes:
        for x in ast.walk(n):
            if isinstance(x, ast.Constant):
                if type(x.value) is int and x.value not in ints:
                    ints.append(x.value)
                elif isinstance(x.value, str):
                    strs.add(x.value)
    out: list[int] = []

    def add(*vs: int) -> None:
        for v in vs:
            if v not in out:
                out.append(v)

    for c in ints:
        if abs(c) < 2**4096:
            add(c + 1, c, c - 1)
    for c in sorted(tr.bl_consts):
        if 0 < c <= 4096:
            add(1 << c, (1 << c) - 1, 1 << (c - 1), (1 << (c - 1)) - 1)
    for c in ints:
        if 8 <= c < 2**62:
            k = c.bit_length()
            add((1 << k) - 1, 1 << k, (1 << (k - 1)) + 1)
    for c in ints:
        if abs(c) < 2**4096:
            add(-c)
    add(0, 1, -1)
    return out, sorted(strs, key=lambda s: (len(s), s))


def _shape_seed_values(shape: tuple, ints: list[int], strs: list[str]) -> list[Any]:
    """Small deterministic representatives for a recognized built-in generic shape."""
    tag = shape[0]
    if tag == "str":
        literals = [s for s in strs if len(s) <= _MAX_SHAPE_STRING_LEN]
        return list(dict.fromkeys([*literals[:8], "", "a", "A", "x", "X", "é"]))[:8]
    if tag == "int":
        literals = [v for v in ints if abs(v).bit_length() <= _MAX_SHAPE_INT_BITS]
        return list(dict.fromkeys([*literals[:8], 0, 1, -1]))[:8]
    if tag == "bool":
        return [False, True]
    if tag == "float":
        return [0.0, 1.0, -1.0]
    if tag == "tuple":
        pools = [_shape_seed_values(child, ints, strs) for child in shape[1:]]
        if any(not pool for pool in pools):
            return []
        return list(itertools.islice(itertools.product(*pools), _MAX_SHAPE_SEEDS))
    if tag == "list":
        pool = _shape_seed_values(shape[1], ints, strs)
        out: list[Any] = [[]]
        out.extend([[item] for item in pool[:_MAX_SHAPE_SEEDS - 1]])
        pair_cap = min(_MAX_SHAPE_SEEDS - len(out), _MAX_SHAPE_LIST_LEN - 1)
        out.extend([[pool[0], item] for item in pool[1:1 + pair_cap]] if pool and pair_cap > 0 else [])
        return out[:_MAX_SHAPE_SEEDS]
    return []


def _matches_shape(value: Any, shape: tuple, depth: int = 0, *, optional: bool = False,
                   max_list_len: int = _MAX_SHAPE_LIST_LEN) -> bool:
    """Require an exact builtin shape and bounded containers before a candidate can leave this driver.
    max_list_len bounds every list: _MAX_SHAPE_LIST_LEN for generated shape seeds; solver models restored from a
    symbolic sequence pass K_MAX (the sequence model's own bound), so a model such as len(xs) > 2 is not dropped."""
    if value is None:
        return optional
    if depth > _MAX_SHAPE_DEPTH:
        return False
    tag = shape[0]
    if tag == "str":
        return type(value) is str and len(value) <= _MAX_SHAPE_STRING_LEN
    if tag == "int":
        return type(value) is int and abs(value).bit_length() <= _MAX_SHAPE_INT_BITS
    if tag == "bool":
        return type(value) is bool
    if tag == "float":
        return type(value) is float
    if tag == "list":
        return type(value) is list and len(value) <= max_list_len and all(
            _matches_shape(x, shape[1], depth=depth + 1, max_list_len=max_list_len) for x in value
        )
    if tag == "tuple":
        return type(value) is tuple and len(value) == len(shape) - 1 and all(
            _matches_shape(x, child, depth=depth + 1, max_list_len=max_list_len)
            for x, child in zip(value, shape[1:])
        )
    return False


def _add_seeds(run: _Run, params, cond, polarity, path, tr: _Tr, used: list[str], max_cand: int):
    if len(run.cands) >= max_cand or not used:
        return
    ints, strs = _seed_values(tr, [cond, *(p for p, _ in path)])
    base: dict[str, Any] = dict(run.cands[0][0]) if run.cands else {}
    for n in used:
        p = params[n]
        if p.shape is not None:
            choices = _shape_seed_values(p.shape, ints, strs)
            if choices:
                base[n] = choices[0]
        elif n not in base:
            base[n] = {"int": 0, "bool": False, "str": "", "float": 0.0}.get(p.kind) if p.kind != "sized" else _Sized(0, None)
            if p.kind == "any":
                base[n] = 0
    assigns: list[tuple[dict[str, Any], str]] = []
    for n in used:
        p = params[n]
        if p.shape is not None:
            vals = _shape_seed_values(p.shape, ints, strs)
            if p.optional:
                vals = [*vals, None]
        elif p.kind == "int" or (p.kind == "any" and n in tr.ints):
            vals: list[Any] = list(ints)
        elif p.kind == "sized":
            vals = [_Sized(v, None) for v in ints if 0 <= v <= 5000]
        elif p.kind == "str":
            vals = list(strs) + [s + "x" for s in strs] + [s[:-1] for s in strs if s]
        elif p.kind == "bool":
            vals = [True, False]
        else:
            continue
        for v in vals[:_MAX_SHAPE_SEEDS if p.shape is not None else 60]:
            a = dict(base)
            a[n] = v
            assigns.append((a, "annotation-shape" if p.shape is not None else "seed"))
    # joint seeds for two or more int-like params (threshold conjunctions)
    intlike = [n for n in used if params[n].kind == "int"][:3]
    if len(intlike) >= 2:
        small = ints[:14]
        for combo in itertools.islice(itertools.product(small, repeat=len(intlike)), 400):
            a = dict(base)
            a.update(dict(zip(intlike, combo)))
            assigns.append((a, "seed"))
    have = {repr(sorted((k, repr(v)) for k, v in a.items())) for a, _ in run.cands}
    evals = 0
    for a, o in assigns:
        if evals >= _SEED_EVALS or len(run.cands) >= max_cand * 6:
            break
        k = repr(sorted((k2, repr(v)) for k2, v in a.items()))
        if k in have:
            continue
        env = _env_for(a, params, "list")
        evals += 1
        if _holds(cond, polarity, path, env, tr.locals) is True:
            have.add(k)
            if o == "annotation-shape":
                run.exact = False
                run.cands.append((a, "bounded annotation-shape seed (not exhaustive)"))
            else:
                run.cands.append((a, o))


def _seed_only(run: _Run, params, cond, polarity, path, tr: _Tr, max_cand: int) -> None:
    """The translator gave up: seeds are still worth trying iff my evaluator fully decides the condition."""
    used = [n for n in params if any(isinstance(x, ast.Name) and x.id == n for x in ast.walk(cond))]
    if not used:
        return
    for n in used:
        tr.used.append(n)
    try:
        tr_seed = tr
        _add_seeds(run, params, cond, polarity, path, tr_seed, used, max_cand)
    except Exception:  # noqa: BLE001 - a generator never breaks its caller
        run.cands.clear()


# ------------------------------------------------------------------ backward slice (WP-BSDP-1)
_EXITS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


@dataclass
class Slice:
    """What dominates a target line: SSA-renamed local definitions (in definition order), dominating/enclosing
    guards as (expr, polarity) path conditions, and the SSA name every plain name has AT the target."""
    locals_: dict[str, ast.expr] = field(default_factory=dict)
    path: list[tuple[ast.expr, bool]] = field(default_factory=list)
    version: dict[str, str] = field(default_factory=dict)  # plain name -> SSA name at the target
    poisoned: dict[str, str] = field(default_factory=dict)  # plain name -> why it cannot be modelled there

    def rewrite(self, node: ast.expr) -> ast.expr:
        return _rename(node, self.version, self.poisoned)


class _Renamer(ast.NodeTransformer):
    def __init__(self, version: dict[str, str], poisoned: dict[str, str]):
        self.version, self.poisoned = version, poisoned
        self.bound: list[set[str]] = []

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load) and not any(node.id in b for b in self.bound):
            if node.id in self.poisoned:
                return ast.copy_location(ast.Name(id=f"{node.id}\u0000{self.poisoned[node.id]}", ctx=ast.Load()), node)
            if node.id in self.version:
                return ast.copy_location(ast.Name(id=self.version[node.id], ctx=ast.Load()), node)
        return node

    def _comp(self, node):
        names = {n.id for g in node.generators for n in ast.walk(g.target) if isinstance(n, ast.Name)}
        self.bound.append(names)
        try:
            return self.generic_visit(node)
        finally:
            self.bound.pop()

    visit_ListComp = visit_SetComp = visit_GeneratorExp = visit_DictComp = _comp


def _rename(node: ast.expr, version: dict[str, str], poisoned: dict[str, str]) -> ast.expr:
    import copy

    return _Renamer(version, poisoned).visit(copy.deepcopy(node))


def _stores(nodes: Iterable[ast.AST]) -> set[str]:
    out: set[str] = set()
    for root in nodes:
        for n in ast.walk(root):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(n.name)
    return out


def _exits(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], _EXITS)


_MUTATORS = {"append", "extend", "insert", "update", "add", "remove", "pop", "popitem", "clear", "setdefault", "sort",
             "reverse", "discard", "appendleft", "extendleft"}


def _mutated(st: ast.AST) -> list[tuple[str, str]]:
    """Plain names a statement changes IN PLACE (mutator method calls, item/attribute stores, del of items)."""
    out: list[tuple[str, str]] = []
    for n in ast.walk(st):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _MUTATORS\
                and isinstance(n.func.value, ast.Name):
            out.append((n.func.value.id, f"mutated in place by .{n.func.attr}() before this line"))
        elif isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.ctx, (ast.Store, ast.Del))\
                and isinstance(n.value, ast.Name):
            out.append((n.value.id, "item/attribute assigned in place before this line"))
    return out


def collect_backward_slice(fn_ast: ast.AST, target_lineno: int) -> Slice:
    """Walk the function from its entry to the statement holding target_lineno and collect per-scope local definitions,
    tuple unpackings, conditional definitions, loop targets, enclosing if conditions, and earlier if-exit predicates.
    A conditional branch may contain a try whose body is only simple assignments when every handler exits with return
    or raise. Other unsupported control-flow assignments are poisoned and reported by name, never guessed."""
    sl = Slice()
    count: dict[str, int] = {}
    if not isinstance(fn_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise Unsupported("backward slice needs a function definition")
    params = {a.arg for a in [*fn_ast.args.posonlyargs, *fn_ast.args.args, *fn_ast.args.kwonlyargs]}
    for a in (fn_ast.args.vararg, fn_ast.args.kwarg):
        if a is not None:
            params.add(a.arg)

    def cur(node: ast.expr) -> ast.expr:
        return _rename(node, sl.version, sl.poisoned)

    def define(name: str, value: ast.expr, *, prebound: bool = False) -> None:
        count[name] = count.get(name, 0) + 1
        ssa = f"{name}#{count[name]}"
        sl.locals_[ssa] = copy.deepcopy(value) if prebound else cur(value)
        sl.version[name] = ssa
        sl.poisoned.pop(name, None)

    def poison(names: Iterable[str], why: str) -> None:
        for n in names:
            sl.poisoned[n] = why
            sl.version.pop(n, None)

    def contains(st: ast.stmt) -> bool:
        return st.lineno <= target_lineno <= (st.end_lineno or st.lineno)

    def simple_assign(st: ast.stmt) -> tuple[str, ast.expr] | None:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            return st.targets[0].id, st.value
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
            return st.target.id, st.value
        return None

    def before(stmts: list[ast.stmt]) -> None:
        """Statements that complete before the target on every path reaching it."""
        for st in stmts:
            for mname, mwhy in _mutated(st):  # in-place mutation changes a value the SSA name still denotes
                if mname in sl.version:
                    poison([mname], mwhy)
            sa = simple_assign(st)
            if sa is not None:
                define(*sa)
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                define(st.target.id, ast.BinOp(left=ast.Name(id=st.target.id, ctx=ast.Load()), op=st.op, right=st.value))
            elif isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Tuple)\
                    and all(isinstance(e, ast.Name) for e in st.targets[0].elts):
                tmp = f"\u0001tup{st.lineno}"
                define(tmp, st.value)
                n = len(st.targets[0].elts)
                sl.path.append((ast.Compare(left=ast.Call(func=ast.Name(id="len", ctx=ast.Load()),
                                                          args=[ast.Name(id=sl.version[tmp], ctx=ast.Load())], keywords=[]),
                                            ops=[ast.Eq()], comparators=[ast.Constant(value=n)]), True))
                for i, e in enumerate(st.targets[0].elts):
                    define(e.id, ast.Subscript(value=ast.Name(id=tmp, ctx=ast.Load()), slice=ast.Constant(value=i),
                                               ctx=ast.Load()))
            elif isinstance(st, ast.If) and _chain_exits(st):
                t = st
                while True:
                    sl.path.append((cur(t.test), False))
                    if len(t.orelse) == 1 and isinstance(t.orelse[0], ast.If):
                        t = t.orelse[0]
                    else:
                        break
            elif isinstance(st, ast.If) and (assignments := _cond_assign(st)):
                test = cur(st.test)
                for name, a_, b_ in assignments:
                    define(name, ast.IfExp(test=copy.deepcopy(test), body=a_, orelse=b_), prebound=True)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                poison([(a.asname or a.name).split(".")[0] for a in st.names], "import")
            elif isinstance(st, (ast.Expr, ast.Pass, ast.Assert, ast.Global, ast.Nonlocal, ast.Return, ast.Raise)):
                pass
            else:
                poison(_stores([st]), f"assigned by a {type(st).__name__} statement before this line")

    def _chain_exits(st: ast.If) -> bool:
        t = st
        while True:
            if not _exits(t.body):
                return False
            if not t.orelse:
                return True
            if len(t.orelse) == 1 and isinstance(t.orelse[0], ast.If):
                t = t.orelse[0]
                continue
            return False

    def _cond_assign(st: ast.If) -> list[tuple[str, ast.expr, ast.expr]]:
        def try_assignments(node: ast.Try) -> list[tuple[str, ast.expr]] | None:
            if not node.body or node.orelse or node.finalbody or not node.handlers:
                return None
            if any(not handler.body or any(not isinstance(child, (ast.Return, ast.Raise))
                                           for child in handler.body) for handler in node.handlers):
                return None
            assignments = [simple_assign(child) for child in node.body]
            if any(item is None for item in assignments):
                return None
            return assignments  # type: ignore[return-value]

        def branch_values(stmts: list[ast.stmt]) -> dict[str, ast.expr] | None:
            values: dict[str, ast.expr] = {}
            for child in stmts:
                assignment = simple_assign(child)
                if assignment is not None:
                    assignments = [assignment]
                elif isinstance(child, ast.Try):
                    assignments = try_assignments(child)
                    if assignments is None:
                        return None
                else:
                    return None
                for name, value in assignments:
                    if name in values or any(isinstance(n, (ast.Lambda, ast.ListComp, ast.SetComp,
                                                             ast.DictComp, ast.GeneratorExp, ast.NamedExpr,
                                                             ast.Await, ast.Yield, ast.YieldFrom))
                                             for n in ast.walk(value)):
                        return None

                    class _EarlierAssignments(ast.NodeTransformer):
                        def visit_Name(self, node: ast.Name):
                            if isinstance(node.ctx, ast.Load) and node.id in values:
                                return copy.deepcopy(values[node.id])
                            return node

                    value = _EarlierAssignments().visit(copy.deepcopy(value))
                    values[name] = cur(value)
            return values

        if not st.body:
            return []
        then_values = branch_values(st.body)
        else_values = branch_values(st.orelse)
        if then_values is None or else_values is None or not (then_values or else_values):
            return []

        def unchanged(name: str) -> ast.expr | None:
            if name in sl.poisoned:
                return None
            if name in sl.version:
                return ast.Name(id=sl.version[name], ctx=ast.Load())
            if name in params:
                return ast.Name(id=name, ctx=ast.Load())
            return None

        names = [*then_values, *(name for name in else_values if name not in then_values)]
        out: list[tuple[str, ast.expr, ast.expr]] = []
        for name in names:
            then_value = then_values.get(name)
            else_value = else_values.get(name)
            if then_value is None:
                then_value = unchanged(name)
            if else_value is None:
                else_value = unchanged(name)
            if then_value is None or else_value is None:
                return []
            out.append((name, then_value, else_value))
        return out

    def descend(stmts: list[ast.stmt]) -> bool:
        for i, st in enumerate(stmts):
            if not contains(st):
                before([st])
                continue
            if isinstance(st, ast.If):
                if st.test.lineno <= target_lineno <= (st.test.end_lineno or st.test.lineno) and not any(
                        contains(x) for x in [*st.body, *st.orelse]):
                    return True  # the condition IS the if test
                if any(contains(x) for x in st.body):
                    sl.path.append((cur(st.test), True))
                    return descend(st.body)
                sl.path.append((cur(st.test), False))
                return descend(st.orelse)
            if isinstance(st, (ast.For, ast.AsyncFor)):
                if st.iter.lineno <= target_lineno <= (st.iter.end_lineno or st.iter.lineno):
                    return True
                it = cur(st.iter)
                if isinstance(st.target, ast.Name):
                    define(st.target.id, ast.Subscript(value=it, slice=ast.Constant(value=0), ctx=ast.Load()))
                    sl.path.append((ast.Compare(left=ast.Call(func=ast.Name(id="len", ctx=ast.Load()), args=[it], keywords=[]),
                                                ops=[ast.GtE()], comparators=[ast.Constant(value=1)]), True))
                else:
                    poison(_stores([st.target]), "unpacking loop target")
                return descend(st.body)
            if isinstance(st, ast.While):
                if st.test.lineno <= target_lineno <= (st.test.end_lineno or st.test.lineno):
                    return True
                sl.path.append((cur(st.test), True))
                return descend(st.body)
            if isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        poison(_stores([item.optional_vars]), "with-target")
                return descend(st.body)
            if isinstance(st, ast.Try):
                if any(contains(x) for x in st.body):
                    return descend(st.body)
                raise Unsupported("target inside an except/else/finally block of a try statement")
            return True  # a simple statement holding the target expression
        return True

    descend(fn_ast.body)
    for n in params:  # a parameter never reassigned keeps its plain name
        if n not in sl.version and n not in sl.poisoned:
            pass
    return sl


# ------------------------------------------------------------------ public API
def _fn_params(source: str, function: str) -> tuple[ast.AST, dict[str, _P], dict[str, ast.expr], list[ast.AST]]:
    tree = ast.parse(source)
    cls_name, _, fname = function.rpartition(".")
    scope: list[ast.stmt] = tree.body
    in_class = False
    if cls_name:
        cls = next((n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls_name.split(".")[-1]), None)
        if cls is None:
            raise Unsupported(f"class {cls_name} not found")
        scope, in_class = cls.body, True
    fn = next((n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fname), None)
    if fn is None:
        raise Unsupported(f"function {function} not found")
    a = fn.args
    pos = [*a.posonlyargs, *a.args]
    defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
    items = list(zip(pos, defaults)) + list(zip(a.kwonlyargs, a.kw_defaults))
    static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
    if in_class and not static and items:
        items = items[1:]
    raw: dict[str, tuple[str | None, ast.expr | None]] = {}
    for arg, d in items:
        raw[arg.arg] = (ast.unparse(arg.annotation) if arg.annotation is not None else None, d)
    # single top-level assignments, assigned exactly once in the whole function, are inlined into conditions
    counts: dict[str, int] = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            counts[n.id] = counts.get(n.id, 0) + 1
    locals_: dict[str, ast.expr] = {}
    for st in fn.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)\
                and counts.get(st.targets[0].id) == 1 and st.targets[0].id not in raw:
            locals_[st.targets[0].id] = st.value
    return fn, {k: v for k, v in raw.items()}, locals_, [d for _, d in raw.values() if d is not None]


def _build_params(raw: dict[str, tuple[str | None, ast.expr | None]], nodes: list[ast.expr],
                  locals_: dict[str, ast.expr]) -> dict[str, _P]:
    scan = [*nodes, *locals_.values()]
    use = _usage(scan, set(raw))
    out: dict[str, _P] = {}
    for n, (ann, dflt) in raw.items():
        kind, optional = _ann_info(ann)
        shape, shape_error, shape_optional = _annotation_shape_info(ann)
        u = use.get(n, set())
        if shape is not None:
            kind = shape[0]
            optional = optional or shape_optional
        elif shape_error:
            kind = "unsupported"
            optional = False
        elif kind is None:
            if u & {"obj", "dict"} or ("str" not in u and u & {"sub", "iter"}):
                kind = "any"  # lazily typed by its first consumer (dict / record / sequence / path)
            elif "str" in u:
                kind = "str"
            elif "num" in u:
                kind = "int"
            elif "len" in u:
                kind = "sized"
            else:
                kind = "any"
        elif kind == "any" and not ann:
            kind = "any"
        p = _P(n, kind, optional, shape=shape, unsupported=shape_error)
        if dflt is not None:
            try:
                p.default, p.has_default = ast.literal_eval(dflt), True
            except (ValueError, SyntaxError):
                pass
        out[n] = p
    return out


def drive(source: str, function: str, condition: Any, polarity: bool, *, path: Sequence[tuple[Any, bool]] = (),
          per_query_ms: int = 1000, budget_ms: int = 5000, max_candidates: int = 8) -> DriveResult:
    """Concrete kwargs (self/cls excluded; only parameters the condition mentions) that should make ``condition``
    evaluate to ``polarity`` with every ``path`` condition holding. A generator only."""
    try:
        fn, raw, locals_, _ = _fn_params(source, function)
        cond = _parse_expr(condition, fn)
        pth = [(_parse_expr(c, fn), bool(p)) for c, p in path]
    except (Unsupported, SyntaxError) as e:
        return DriveResult([], f"unsupported: {e}", False)
    params = _build_params(raw, [cond, *(c for c, _ in pth)], locals_)
    run = _core(params, cond, polarity, pth, locals_, per_query_ms, budget_ms, max_candidates)
    fin = _finalise(run, params, cond, polarity, pth, locals_, run.cands, max_candidates)
    reason = run.reason
    if not fin and run.cands:
        reason = (reason + "; " if reason else "") + "every generated input was contradicted by the evaluator"
    return DriveResult([Candidate(kw, polarity, o, ch) for kw, o, ch, _a in fin], reason if not fin or not run.exact else reason,
                       run.exact and bool(fin) or run.exact)


def _defaults_of(fn: ast.AST | None) -> dict[str, ast.expr]:
    """Literal-able parameter defaults of a function definition (name -> default expression)."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {}
    a = fn.args
    pos = [*a.posonlyargs, *a.args]
    out: dict[str, ast.expr] = {}
    for x, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
        out[x.arg] = d
    for x, d in zip(a.kwonlyargs, a.kw_defaults):
        if d is not None:
            out[x.arg] = d
    return out


# Structural caps (counts, so the answer cannot depend on how fast the machine is): the python-side slice and
# translation work grows faster than linearly (8 tuple unpackings take 0.8 s, 16 several seconds), and wall time alone
# would make a function near the wall limit sometimes answer and sometimes be killed.
_MAX_FN_STMTS, _MAX_FN_NODES, _MAX_SLICE_LOCALS, _MAX_SLICE_PATH = 1500, 30000, 40, 20


def _too_large(fn_ast: ast.AST) -> str:
    stmts = nodes = 0
    for n in ast.walk(fn_ast):
        nodes += 1
        stmts += isinstance(n, ast.stmt)
        if stmts > _MAX_FN_STMTS or nodes > _MAX_FN_NODES:
            return f"more than {_MAX_FN_STMTS} statements or {_MAX_FN_NODES} syntax nodes"
    return ""


def _candidates_detailed_inproc(params: list[tuple[str, str | None]], conditions: list[str], *, want: str = "both",
                        timeout_ms: int = 200, max_per_condition: int = 4, fn_ast: ast.AST | None = None,
                        target_lineno: int | None = None,
                        path: Sequence[tuple[str, bool]] = ()) -> tuple[list[DetailedCandidate], dict[int, str]]:
    """Candidates for each condition. With ``fn_ast`` and ``target_lineno`` the condition is read in its function:
    locals defined on the way (SSA), tuple unpackings, enclosing loop targets and every dominating or enclosing
    guard are inlined/added as path conditions (see ``collect_backward_slice``). Without them every name must be a
    parameter. ``path`` adds caller-known (source, polarity) path conditions."""
    out: list[DetailedCandidate] = []
    reasons: dict[int, str] = {}
    pols = {"true": [True], "false": [False], "both": [True, False]}.get(want, [True, False])
    sl: Slice | None = None
    sl_err = ""
    if fn_ast is not None and target_lineno is not None:
        big = _too_large(fn_ast)
        if big:  # a deterministic structural cap, never a wall-clock race
            return [], {i: f"function too large for the driver ({big}): not modelled" for i in range(len(conditions))}
        try:
            sl = collect_backward_slice(fn_ast, target_lineno)
        except Unsupported as e:
            sl_err = f"slice unsupported: {e}"
        if sl is not None and (len(sl.locals_) > _MAX_SLICE_LOCALS or len(sl.path) > _MAX_SLICE_PATH):
            why = f"slice of {len(sl.locals_)} locals / {len(sl.path)} path conditions (caps {_MAX_SLICE_LOCALS}/{_MAX_SLICE_PATH})"
            return [], {i: f"function too large for the driver ({why}): not modelled" for i in range(len(conditions))}
    for i, c in enumerate(conditions):
        try:
            cond = _parse_expr(c, None)
            pth = [(_parse_expr(pc, None), bool(pp)) for pc, pp in path]
        except Unsupported as e:
            reasons[i] = f"unsupported: {e}"
            continue
        locals_: dict[str, ast.expr] = {}
        if sl is not None:
            cond = sl.rewrite(cond)
            pth = [(sl.rewrite(pc), pp) for pc, pp in pth]
            pth = [*sl.path, *pth]
            locals_ = dict(sl.locals_)
        dflts = _defaults_of(fn_ast)
        raw = {n: (a, dflts.get(n)) for n, a in params}
        ps = _build_params(raw, [cond, *(pc for pc, _ in pth)], locals_)
        got_any = False
        notes: list[str] = [sl_err] if sl_err else []
        for pol in pols:
            run = _core(ps, cond, pol, pth, locals_, timeout_ms, timeout_ms * 6, max_per_condition)
            fin = _finalise(run, ps, cond, pol, pth, locals_, run.cands, max_per_condition)
            stopped = (run.reason or "").startswith(("unsupported", "partial"))  # translation stopped; not unsat / K limit
            if fin and run.residuals and fn_ast is not None and target_lineno is not None and sl is not None:
                # Keep partial Z3 models as explicitly residual-backed hints, but do not let one suppress
                # the independent cut-point search for a concrete candidate that can satisfy the full path.
                cps, cwhy = cutpoint_drive(fn_ast, target_lineno, cond, pol, pth, locals_, raw, timeout_ms,
                                           max_per_condition)
                for kw, origin in cps:
                    got_any = True
                    out.append(DetailedCandidate(kw, i, pol, f"{origin}; residual fallback: {cwhy}", False))
            if not fin and stopped and fn_ast is not None and target_lineno is not None and sl is not None:
                cps, cwhy = cutpoint_drive(fn_ast, target_lineno, cond, pol, pth, locals_, raw, timeout_ms, max_per_condition)
                for kw, origin in cps:
                    got_any = True
                    out.append(DetailedCandidate(kw, i, pol, f"{origin}; full prefix stopped: {run.reason}", False))
                if cps:
                    continue
                notes.append(f"{'true' if pol else 'false'}: cut-point: {cwhy}")
            if not fin:
                notes.append(f"{'true' if pol else 'false'}: {run.reason or 'no input found'}")
            for kw, origin, _, assign in fin:
                got_any = True
                out.append(DetailedCandidate(_json_form(assign, kw, ps), i, pol, origin, run.exact,
                                             list(run.residuals)))
        if not got_any:
            reasons[i] = "; ".join(notes)
    return out, reasons


# ------------------------------------------------------------------ cut-point suffix solving
def _plain(v: Any) -> Any:
    """A descriptor value -> a plain JSON-able Python value (dict descriptors become dicts)."""
    if isinstance(v, dict) and "__dict__" in v:
        return {k: _plain(x) for k, x in v["__dict__"].items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _desc(v: Any) -> Any:
    """Plain dict/list -> the descriptor form review materialises ({"__dict__": {...}})."""
    if isinstance(v, dict):
        return {"__dict__": {str(k): _desc(x) for k, x in v.items()}}
    if isinstance(v, list):
        return [_desc(x) for x in v]
    return v


def _delims(fn_ast: ast.AST | None) -> list[str]:
    """Delimiter-like string constants of the callable (short, no letters or digits), most used first."""
    if fn_ast is None:
        return []
    cnt: dict[str, int] = {}
    for n in ast.walk(fn_ast):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and 0 < len(n.value) <= 3\
                and not any(ch.isalnum() for ch in n.value):
            cnt[n.value] = cnt.get(n.value, 0) + 1
    out = [k for k, _ in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))]
    for n in ast.walk(fn_ast):  # separators that str methods use implicitly
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and not n.args:
            imp = {"splitlines": "\n", "split": " "}.get(n.func.attr)
            if imp is not None and imp not in out:
                out.append(imp)
    return out


def _sources_of(fn_ast: ast.AST, base: str, target: int, entry: set[str]) -> list[str]:
    """Entry parameters a cut variable can come from: every name read or written by a statement before the target
    that mentions ``base`` (assignments, loops, appends...), followed through other locals up to depth 3."""
    stmts: list[ast.stmt] = []
    pending = [fn_ast]
    while pending:
        node = pending.pop()
        if node is not fn_ast and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node is not fn_ast and isinstance(node, ast.stmt) and getattr(node, "lineno", 0) < target\
                and not isinstance(node, ast.Return):
            stmts.append(node)
        pending.extend(ast.iter_child_nodes(node))

    def head(st: ast.stmt) -> list[ast.AST]:  # the statement's own expressions (a compound's body is its own statements)
        if isinstance(st, (ast.For, ast.AsyncFor)):
            return [st.iter, st.target]
        if isinstance(st, (ast.If, ast.While)):
            return [st.test]
        if isinstance(st, ast.With):
            return [i for it in st.items for i in (it.context_expr, it.optional_vars) if i is not None]
        if isinstance(st, (ast.Try,)):
            return []
        return [st]

    def names(nodes: Iterable[ast.AST]) -> set[str]:
        return {x.id for nd in nodes for x in ast.walk(nd) if isinstance(x, ast.Name)}

    seen = {base}
    frontier = {base}
    srcs: list[str] = []
    for _ in range(3):
        nxt: set[str] = set()
        for st in stmts:
            hn = names(head(st))
            if hn & frontier:
                for n in hn:
                    if n in entry and n not in srcs:
                        srcs.append(n)
                    elif n not in seen and n not in entry:
                        nxt.add(n)
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return srcs


def _assignment_sources_of(fn_ast: ast.AST, base: str, target: int, entry: set[str]) -> list[str]:
    """Trace value assignments only; a guard that mentions a value is not its provenance."""
    stmts: list[ast.stmt] = []
    pending = [fn_ast]
    while pending:
        node = pending.pop()
        if node is not fn_ast and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node is not fn_ast and isinstance(node, ast.stmt) and getattr(node, "lineno", 0) < target:
            stmts.append(node)
        pending.extend(ast.iter_child_nodes(node))
    stmts.sort(key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)))

    def assigned_value(st: ast.stmt, name: str) -> ast.AST | None:
        if isinstance(st, ast.Assign):
            targets, value = st.targets, st.value
        elif isinstance(st, ast.AnnAssign):
            targets, value = [st.target], st.value
        else:
            return None
        if value is None:
            return None
        if any(isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store)
               for target_node in targets for node in ast.walk(target_node)):
            return value
        return None

    seen = {base}
    frontier = [base]
    sources: list[str] = []
    for _ in range(8):
        next_frontier: list[str] = []
        for name in frontier:
            for st in stmts:
                value = assigned_value(st, name)
                if value is None:
                    continue
                for node in ast.walk(value):
                    if not isinstance(node, ast.Name):
                        continue
                    if node.id in entry:
                        if node.id not in sources:
                            sources.append(node.id)
                    elif node.id not in seen:
                        seen.add(node.id)
                        next_frontier.append(node.id)
        frontier = next_frontier
        if not frontier:
            break
    return sources


def _projection_adapters(fn_ast: ast.AST, base: str, target: int, source: str) -> set[str]:
    """Recognise only timedelta rebinding forms with bounded inverse projections.

    This is a candidate generator, not a proof of runtime reachability. Any write to the cut
    local before the target that is outside this small whitelist disables projection.
    """
    adapters: set[str] = set()
    saw_write = False

    def writes_base(target_node: ast.AST) -> bool:
        return any(isinstance(name, ast.Name) and name.id == base and isinstance(name.ctx, (ast.Store, ast.Del))
                   for name in ast.walk(target_node))

    for node in ast.walk(fn_ast):
        if getattr(node, "lineno", 0) >= target:
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            targets = [item.optional_vars for item in node.items if item.optional_vars is not None]
        elif isinstance(node, ast.Delete):
            targets = node.targets
        elif isinstance(node, ast.ExceptHandler):
            if node.name == base:
                return set()
            continue
        else:
            continue
        if not any(writes_base(t) for t in targets):
            continue
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            return set()
        saw_write = True
        value = node.value
        if isinstance(value, ast.Name) and value.id == source:
            adapters.add("timedelta_alias")
            continue
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and value.func.attr == "timedelta" and isinstance(value.func.value, ast.Name)
                and value.func.value.id in {"datetime", "dt"} and not value.args
                and len(value.keywords) == 1 and value.keywords[0].arg == "seconds"
                and isinstance(value.keywords[0].value, ast.Name)
                and value.keywords[0].value.id == source):
            adapters.add("timedelta_seconds")
            continue
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "abs"
                and len(value.args) == 1 and not value.keywords
                and isinstance(value.args[0], ast.Name) and value.args[0].id == base):
            adapters.add("abs")
            continue
        return set()
    return adapters if saw_write else set()


def _project(v: Any, kind: str, delims: list[str], url: bool = False,
             adapters: set[str] | None = None) -> list[tuple[Any, str]]:
    """Deterministic inverse adapters: the entry-parameter values that would produce the cut-point value ``v``."""
    out: list[tuple[Any, str]] = []

    def add(x: Any, why: str) -> None:
        if all(repr(x) != repr(o) for o, _ in out):
            out.append((x, why))

    v = _plain(v)
    if isinstance(v, str):
        add(v, "alias")
        try:
            lit = ast.literal_eval(v)
            if not isinstance(lit, str):
                add(_plain(lit), "literal_eval")
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            pass
        if "/" in delims and v.isdigit():
            add("192.0.2.0/" + v, "template: address/mask")
        if url and "." in v:  # the callable parses URLs: a host-like value reaches it as the host of a URL
            add(f"http://a{v}/" if v.startswith(".") else f"http://{v}/", "template: url")
    elif isinstance(v, bool):
        add(v, "alias")
    elif isinstance(v, int):
        add(v, "alias")
        add(str(v), "str(int)")
        if "/" in delims:
            add("192.0.2.0/" + str(v), "template: address/mask")
    elif isinstance(v, list):
        # elements the suffix does not constrain come back as arbitrary scalars: they become a filler token
        sv = [x if isinstance(x, str) else "a" for x in v] if any(isinstance(x, str) for x in v) else None
        if sv is not None:
            for d in delims:
                add(d.join(sv), f"join({d!r})")
        add(v, "alias")
        if sv:
            add({x: x for x in sv}, "dict of the elements")
    elif isinstance(v, dict):
        add(v, "alias")
        add(repr(v), "repr(dict)")
        try:
            add(json.dumps(v), "json.dumps(dict)")
        except (TypeError, ValueError):
            pass
    elif adapters and (type(v) is _datetime.timedelta
                       or (type(v) is _ObjVal and set(v.attrs) == {"seconds"}
                           and type(v.attrs["seconds"]) is int and 0 <= v.attrs["seconds"] < 86_400)
                       or (type(v) is types.SimpleNamespace and set(vars(v)) == {"seconds"}
                           and type(vars(v)["seconds"]) is int and 0 <= vars(v)["seconds"] < 86_400)):
        # A suffix such as ``delta.seconds == 3600`` is solved with the pure data stub
        # _ObjVal(seconds=3600). It does not represent a real timedelta, but this exact
        # one-field boundary can be embedded in the built-in type without executing code.
        if type(v) is _datetime.timedelta:
            cut = v
        else:
            seconds = v.attrs["seconds"] if type(v) is _ObjVal else vars(v)["seconds"]
            cut = _datetime.timedelta(seconds=seconds)
        variants = [cut]
        if "abs" in adapters:
                try:
                    variants.append(-cut)
                except OverflowError:
                    pass  # timedelta.max has no representable negative inverse
        if "timedelta_alias" in adapters:
            for value in variants:
                add(value, "timedelta alias" if value is cut else "abs(timedelta) inverse")
        if "timedelta_seconds" in adapters:
            for value in variants:
                seconds = value.total_seconds()
                if abs(seconds) <= 1_000_000:
                    add(seconds, "timedelta(seconds=...) inverse")
                    whole = int(seconds)
                    if kind == "int" and seconds == whole and value == _datetime.timedelta(seconds=whole):
                        add(whole, "timedelta(seconds=...) integer inverse")
    keep = {"str": (str,), "int": (int,), "bool": (bool, int), "float": (int, float)}.get(kind)
    return [(_desc(x), w) for x, w in out if keep is None or isinstance(x, keep)]


def cutpoint_drive(fn_ast: ast.AST, target: int, cond: ast.expr, pol: bool, pth: list[tuple[ast.expr, bool]],
                   locals_: dict[str, ast.expr], raw: dict[str, tuple[str | None, ast.expr | None]], timeout_ms: int,
                   max_cand: int) -> tuple[list[tuple[dict[str, Any], str]], str]:
    """The prefix of the condition cannot be translated (a loop, try or branch assigned a local, or a local is an
    unmodelled call). Cut there: treat that local as a fresh root, solve the MODELLED suffix over it, then project
    the witness back to the entry parameters with deterministic inverse adapters. Every result is a HINT
    (exact=False): the real evaluators decide whether the value reaches the condition."""
    names = {n.id for nd in [cond, *(pc for pc, _ in pth)] for n in ast.walk(nd) if isinstance(n, ast.Name)}
    poisoned = sorted(n for n in names if "\u0000" in n)
    if poisoned:  # a clean root name for the cut local: the poison text is not an identifier
        ren = {n: "cut_" + n.split("\u0000")[0] for n in poisoned}

        class _R(ast.NodeTransformer):
            def visit_Name(self, node: ast.Name):
                return ast.copy_location(ast.Name(id=ren[node.id], ctx=node.ctx), node) if node.id in ren else node

        cond = _R().visit(copy.deepcopy(cond))
        pth = [(_R().visit(copy.deepcopy(pc)), pp) for pc, pp in pth]
        names = {n.id for nd in [cond, *(pc for pc, _ in pth)] for n in ast.walk(nd) if isinstance(n, ast.Name)}
        poisoned = sorted(ren.values())
    direct = sorted(n for n in names if n in locals_)
    delims = _delims(fn_ast)
    url = any(isinstance(n, ast.Call) and (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")) in
              ("urlparse", "urlsplit", "parse_url") for n in ast.walk(fn_ast))
    entry = set(raw)
    # Prefer an invertible local that is the receiver of an attribute in the target condition. When an unrelated
    # earlier guard also depends on locals (e.g. ``years``/``days`` from a timedelta), cutting every local together
    # can force projections through those unrelated locals and lose the useful receiver boundary. Keep only path
    # predicates expressible with this receiver and entry parameters in this first pass; these remain HINTS and the
    # real function must still reach the target condition before a candidate can count.
    focal_stages: list[tuple[tuple[str, ...], list[tuple[ast.expr, bool]]]] = []
    receivers: list[str] = []
    scalar_seconds: dict[str, str] = {}

    def seconds_attribute_source(local: str) -> str | None:
        """Return the timedelta local for one plain ``seconds = delta.seconds`` binding."""
        base = local.split("#")[0]
        sources = []
        stack = list(getattr(fn_ast, "body", ()))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            stack.extend(ast.iter_child_nodes(node))
            if getattr(node, "lineno", 0) >= target:
                continue
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
                                   ast.For, ast.AsyncFor)):
                targets = [node.target]
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                targets = [item.optional_vars for item in node.items if item.optional_vars is not None]
            elif isinstance(node, ast.Delete):
                targets = node.targets
            elif isinstance(node, ast.ExceptHandler):
                if node.name == base:
                    return None
                continue
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                if base in node.names:
                    return None
                continue
            else:
                continue
            if not any(isinstance(name, ast.Name) and name.id == base
                       and isinstance(name.ctx, (ast.Store, ast.Del)) for target_node in targets
                       for name in ast.walk(target_node)):
                continue
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == base
                    and isinstance(node.value, ast.Attribute) and node.value.attr == "seconds"
                    and isinstance(node.value.value, ast.Name)):
                sources.append(node.value.value.id)
            else:
                return None
        return sources[0] if len(sources) == 1 else None

    for node in ast.walk(cond):
        if not isinstance(node, ast.Attribute):
            continue
        root = node.value
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in locals_ and root.id not in receivers:
            base = root.id.split("#")[0]
            sources = _sources_of(fn_ast, base, target, entry)
            if any(_projection_adapters(fn_ast, base, target, source) for source in sources):
                receivers.append(root.id)
    for local in direct:
        if local in receivers:
            continue
        timedelta_local = seconds_attribute_source(local)
        if timedelta_local is None:
            continue
        sources = _sources_of(fn_ast, timedelta_local, target, entry)
        if any(_projection_adapters(fn_ast, timedelta_local, target, source) for source in sources):
            receivers.append(local)
            scalar_seconds[local] = timedelta_local
    for receiver in receivers:
        allowed = entry | {receiver}
        receiver_path = []
        for pc, polarity in pth:
            used = {n.id for n in ast.walk(pc) if isinstance(n, ast.Name)}
            if used <= allowed:
                receiver_path.append((pc, polarity))
        focal_stages.append(((receiver,), receiver_path))

    stages = [*focal_stages, *((tuple(x), pth) for x in (poisoned, sorted({*poisoned, *direct})) if x)]
    if not stages:
        return [], "no local to cut at"
    found: list[tuple[dict[str, Any], str]] = []
    why = ""
    for cuts, cut_path in stages:
        raw2 = {**raw, **{c: (None, None) for c in cuts}}
        loc2 = {k: v for k, v in locals_.items() if k not in cuts}
        if len(cuts) == 1 and cuts[0] in receivers:
            receiver = cuts[0]

            # timedelta.seconds is bounded to one day, so keep literal arithmetic small and local to
            # this projection. Never evaluate names, calls, or other executable AST nodes.
            literal_bound = 86_400
            literal_depth_limit = 64
            literal_work_limit = 256
            literal_work = 0
            literal_limit_hit = False

            def bounded_literal(value: int | float) -> bool:
                if type(value) is int:
                    return value.bit_length() <= literal_bound.bit_length() and -literal_bound <= value <= literal_bound
                if type(value) is float:
                    return math.isfinite(value) and -literal_bound <= value <= literal_bound
                return False

            def literal_number(expr: ast.AST, depth: int = 0) -> int | float | None:
                nonlocal literal_work, literal_limit_hit
                literal_work += 1
                if depth > literal_depth_limit or literal_work > literal_work_limit:
                    literal_limit_hit = True
                    return None
                if isinstance(expr, ast.Constant) and type(expr.value) in (int, float):
                    return expr.value if bounded_literal(expr.value) else None
                if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
                    value = literal_number(expr.operand, depth + 1)
                    if value is None:
                        return None
                    negated = -value
                    return negated if bounded_literal(negated) else None
                if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)):
                    return None
                left = literal_number(expr.left, depth + 1)
                right = literal_number(expr.right, depth + 1)
                if left is None or right is None or (isinstance(expr.op, ast.FloorDiv) and right == 0):
                    return None
                try:
                    if isinstance(expr.op, ast.Add):
                        value = left + right
                    elif isinstance(expr.op, ast.Sub):
                        value = left - right
                    elif isinstance(expr.op, ast.Mult):
                        value = left * right
                    else:
                        value = left // right
                except (ArithmeticError, OverflowError, ValueError):
                    return None
                return value if type(value) in (int, float) and bounded_literal(value) else None

            def is_seconds(expr: ast.AST) -> bool:
                if receiver in scalar_seconds:
                    return isinstance(expr, ast.Name) and expr.id == receiver
                return isinstance(expr, ast.Attribute) and expr.attr == "seconds"\
                    and isinstance(expr.value, ast.Name) and expr.value.id == receiver

            def affine_seconds(expr: ast.AST, depth: int = 0) -> tuple[int, int] | None:
                """A bounded integer form ``a * seconds + b`` for simple arithmetic only."""
                nonlocal literal_work, literal_limit_hit
                literal_work += 1
                if depth > literal_depth_limit or literal_work > literal_work_limit:
                    literal_limit_hit = True
                    return None
                if is_seconds(expr):
                    return (1, 0)
                if isinstance(expr, ast.Constant) and type(expr.value) is int and bounded_literal(expr.value):
                    return (0, expr.value)
                if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
                    value = affine_seconds(expr.operand, depth + 1)
                    if value is None:
                        return None
                    result = (-value[0], -value[1])
                    return result if all(bounded_literal(part) for part in result) else None
                if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, (ast.Add, ast.Sub, ast.Mult)):
                    return None
                left = affine_seconds(expr.left, depth + 1)
                right = affine_seconds(expr.right, depth + 1)
                if left is None or right is None:
                    return None
                left_coefficient, left_offset = left
                right_coefficient, right_offset = right
                if isinstance(expr.op, ast.Add):
                    result = (left_coefficient + right_coefficient, left_offset + right_offset)
                elif isinstance(expr.op, ast.Sub):
                    result = (left_coefficient - right_coefficient, left_offset - right_offset)
                elif left_coefficient == 0:
                    result = (right_coefficient * left_offset, right_offset * left_offset)
                elif right_coefficient == 0:
                    result = (left_coefficient * right_offset, left_offset * right_offset)
                else:
                    return None
                if not all(bounded_literal(value) for value in result):
                    return None
                return result

            def simple_seconds_value(node: ast.AST, seconds: int) -> bool | None:
                if not isinstance(node, ast.Compare) or not node.ops or len(node.ops) != len(node.comparators):
                    return None

                operands = [node.left, *node.comparators]
                values: list[int | float] = []
                for operand in operands:
                    if is_seconds(operand):
                        values.append(seconds)
                    else:
                        affine = affine_seconds(operand)
                        value = (affine[0] * seconds + affine[1]) if affine is not None else literal_number(operand)
                        if affine is not None and not bounded_literal(value):
                            return None
                        if value is None:
                            return None
                        values.append(value)

                def compare(left: int | float, right: int | float, op: ast.cmpop) -> bool | None:
                    try:
                        if isinstance(op, ast.Eq):
                            return left == right
                        if isinstance(op, ast.NotEq):
                            return left != right
                        if isinstance(op, ast.Lt):
                            return left < right
                        if isinstance(op, ast.LtE):
                            return left <= right
                        if isinstance(op, ast.Gt):
                            return left > right
                        if isinstance(op, ast.GtE):
                            return left >= right
                    except (TypeError, ValueError, OverflowError):
                        return None
                    return None

                for left, right, op in zip(values, values[1:], node.ops):
                    result = compare(left, right, op)
                    if result is None:
                        return None
                    if not result:
                        return False
                return True

            seconds_boundaries: set[int] = set()
            for expression in [cond, *(pc for pc, _ in cut_path)]:
                for comparison in ast.walk(expression):
                    if not isinstance(comparison, ast.Compare):
                        continue
                    operands = [comparison.left, *comparison.comparators]
                    for index, operand in enumerate(operands):
                        if not is_seconds(operand):
                            if not any(is_seconds(node) for node in ast.walk(operand)):
                                continue
                            adjacent = operands[max(0, index - 1):index] + operands[index + 1:index + 2]
                            for other in adjacent:
                                left = affine_seconds(other)
                                right = affine_seconds(operand)
                                if left is None or right is None:
                                    continue
                                coefficient = left[0] - right[0]
                                offset = right[1] - left[1]
                                if coefficient and offset % coefficient == 0:
                                    boundary = offset // coefficient
                                    if bounded_literal(boundary):
                                        seconds_boundaries.update((boundary - 1, boundary, boundary + 1))
                            continue
                        adjacent = operands[max(0, index - 1):index] + operands[index + 1:index + 2]
                        for other in adjacent:
                            boundary_value = literal_number(other)
                            if boundary_value is not None:
                                boundary = int(boundary_value)
                                seconds_boundaries.update((boundary - 1, boundary, boundary + 1))
            if literal_limit_hit:
                return [], "seconds boundary literal exceeded depth/work limit"
            projected: list[tuple[dict[str, Any], str]] = []
            for seconds in sorted(s for s in seconds_boundaries if 0 <= s < 86_400):
                condition_value = simple_seconds_value(cond, seconds)
                if literal_limit_hit:
                    return [], "seconds boundary literal exceeded depth/work limit"
                if condition_value is not pol:
                    continue
                path_rejected = False
                for pc, polarity in cut_path:
                    observed = simple_seconds_value(pc, seconds)
                    if literal_limit_hit:
                        return [], "seconds boundary literal exceeded depth/work limit"
                    if observed is not None and observed is not polarity:
                        path_rejected = True
                        break
                if path_rejected:
                    continue
                projection_base = scalar_seconds.get(receiver, receiver.split("#")[0])
                for source in _assignment_sources_of(fn_ast, projection_base, target, entry):
                    adapters = _projection_adapters(fn_ast, projection_base, target, source)
                    for value_, how in _project(types.SimpleNamespace(seconds=seconds),
                                                (_ann_info(raw[source][0])[0] or "any"), delims, url,
                                                adapters=adapters):
                        projected.append(({source: value_},
                                           f"cutpoint at {receiver.split('#')[0]!r} -> {source!r} via {how}; "
                                           f"seconds boundary {seconds}"))
            if projected:
                return projected[:max_cand * 3], ""
        ps = _build_params(raw2, [cond, *(pc for pc, _ in cut_path)], loc2)
        run = _core(ps, cond, pol, cut_path, loc2, timeout_ms, timeout_ms * 6, max_cand)
        run.exact, run.strict = False, False
        fin = _finalise(run, ps, cond, pol, cut_path, loc2, run.cands, max_cand)
        if not fin:
            why = run.reason or "suffix has no solution"
            continue
        for kw, _o, _c, a_ in fin:
            # every cut variable solved in this witness is projected, and the projections go into ONE candidate
            # together with the entry parameters the witness solved directly
            per_cut: list[list[tuple[str, Any, str]]] = []
            for c in cuts:
                if c not in kw:
                    continue
                base = c[4:] if c.startswith("cut_") and c in poisoned else c.split("#")[0]
                opts = []
                source_base = scalar_seconds.get(c)
                source_names = (_assignment_sources_of(fn_ast, source_base, target, entry)
                                if source_base is not None else _sources_of(fn_ast, base, target, entry))
                adapter_base = source_base if source_base is not None else base
                for p in source_names:
                    adapters = _projection_adapters(fn_ast, adapter_base, target, p)
                    opts.extend((p, val, f"cutpoint at {base!r} -> {p!r} via {how}")
                                for val, how in _project(kw[c], (_ann_info(raw[p][0])[0] or "any"), delims,
                                                         url, adapters=adapters))
                if opts:
                    per_cut.append(opts)
            if not per_cut:
                continue
            direct = _json_form(a_, {k: v for k, v in kw.items() if k in entry}, ps)
            for combo in sorted(itertools.product(*per_cut), key=lambda cb: sum(per_cut[i].index(o) for i, o in enumerate(cb))):
                merged: dict[str, Any] = {}
                ok = True
                for p, val, _how in combo:
                    if p in merged and repr(merged[p]) != repr(val):
                        ok = False  # two cut variables want different values of one parameter
                        break
                    merged[p] = val
                if not ok:
                    continue
                kw_out = {**{k: v for k, v in direct.items() if k not in merged}, **merged}
                found.append((kw_out, "; ".join(dict.fromkeys(h for _, _, h in combo))))
                if len(found) >= max_cand * 3:
                    return found, ""
        if found:
            break
    return found, why or ("" if found else "no entry parameter feeds the cut local")



def _json_form(assign: dict[str, Any], kw: dict[str, Any], params: dict[str, _P]) -> dict[str, Any]:
    """JSON-able form: a length-only parameter is {"__len__": n}, plus "__type__" when isinstance/type() forced the
    container type; tuple/set/bytes representatives are {"__type__": name}."""
    out: dict[str, Any] = {}
    for k, v in kw.items():
        a = assign.get(k)
        # receiver fields ("self.mode") are generated keys, not declared parameters: they have no annotation shape
        shape_ = params[k].shape if k in params else None
        if isinstance(a, _Sized):
            out[k] = {"__len__": a.n} if a.t is None else {"__type__": a.t, "__len__": a.n}
        elif type(v) is _datetime.timedelta:
            out[k] = {"__timedelta__": [v.days, v.seconds, v.microseconds]}
        elif isinstance(v, (tuple, set, bytes, BaseException)) and shape_ is None:
            out[k] = {"__type__": type(v).__name__}
        elif isinstance(a, (_DictVal, _ObjVal, _PathVal, list)) or (shape_ is not None and type(a) is tuple):
            out[k] = _jsonify(a)
        else:
            out[k] = v
    return out


def candidates(params: list[tuple[str, str | None]], conditions: list[str], *, want: str = "both",
               timeout_ms: int = 200, max_per_condition: int = 4) -> list[dict[str, Any]]:
    """Flat, deduplicated list of {param: value} assignments, JSON-able; a param used only through len() is given
    as {"__len__": n}; tuple/set/bytes representatives as {"__type__": name}. [] when nothing could be generated."""
    got, _ = candidates_detailed(params, conditions, want=want, timeout_ms=timeout_ms, max_per_condition=max_per_condition)
    seen: set[str] = set()
    res: list[dict[str, Any]] = []
    for c in got:
        k = repr(sorted(c.params.items(), key=lambda kv: kv[0]))
        if k not in seen:
            seen.add(k)
            res.append(c.params)
    return res



# ------------------------------------------------------------------ isolation: confined, forked, killable calls
# `candidates_detailed` parses UNTRUSTED repository source and runs Z3. It must not run in the supervisor: a Z3
# crash, hang or memory blowup would take the supervisor down, and Z3's work depends on everything allocated in the
# process before the query (4x on one case), which would make the candidate list depend on history. So the public
# call is answered by a forked child of a PRISTINE template process: the template (python -I, PYTHONHASHSEED=0,
# kernel-confined by _confine.py: user+mount+pid+net namespaces, Landlock, no network, no writes) imports z3 and this
# module once, warms up, and then only forks; every child starts from the same memory image, so the same call gives
# the same answer. Each child gets RLIMIT_AS / CPU / NOFILE, a hard wall kill, and answers in JSON only. Failure of
# any layer is a NAMED STOP ("driver sandbox: ..."), never a silent in-process fallback.
#
# MEASURED COST of this isolation (z3 5.3.2.0, parallel runs, review 4e6baf6+437c46a vs the in-process driver):
#   corpus12 (10 targets, neutral edits)      135.2 s, ZERO driver calls (the edits never reach drive_inputs): +0
#   c18 (18 counterexamples, driver-heavy)    52.6 s -> 55.0 s = +4.6%, verdicts identical 18/18 (one witness differs:
#                                             nonlinear_pair drives a=4,b=-3 instead of a=3,b=-4; both REFUTED, the old
#                                             pick depended on process history)
#   pure driver micro (66 calls, own cases)   3.3 s -> 5.4 s = +66% (+17..31 ms per call: fork of a ~60 MB z3 image
#                                             plus copy-on-write); first call per process +0.3 s (worker start)
# It is NOT "within +10%" on a workload made only of driver calls; it is +4.6% / +0% on the gate workloads measured.
SANDBOX_LIMITS: dict[str, Any] = {"wall_s": None, "cpu_s": None, "mem_mb": 1536, "as_mb": 1024}  # None: derived from the budget
# as_mb: ABSOLUTE address-space cap of a forked child (the measured peak of every legitimate entry is ~190 MiB, see tests); mem_mb: headroom
# over the child's own size. The child gets the lower of the two, so the cap cannot depend on tree, pyc or arena state.
_MAX_FRAME = 16 * 1024 * 1024
_IN_WORKER = False
_SB: dict[str, Any] = {"proc": None, "pid": None, "owner": None, "lock": None, "root": None, "info": None,
                       "drain": None, "errbuf": None, "force": None}  # force: tests only ("launcher"/"inherited")


def _frame_write(fd: int, data: bytes) -> None:
    buf = len(data).to_bytes(4, "big") + data
    while buf:
        n = os.write(fd, buf)
        buf = buf[n:]


def _frame_read(fd: int, deadline: float | None = None) -> bytes | None:
    import select
    import time as _t

    def rd(n: int) -> bytes | None:
        out = b""
        while len(out) < n:
            if deadline is not None:
                left = deadline - _t.monotonic()
                if left <= 0 or not select.select([fd], [], [], left)[0]:
                    raise TimeoutError
            chunk = os.read(fd, n - len(out))
            if not chunk:
                return None
            out += chunk
        return out

    head = rd(4)
    if head is None:
        return None
    n = int.from_bytes(head, "big")
    if n > _MAX_FRAME:
        raise ValueError("frame too large")
    return rd(n) if n else b""


class _SafeUnpickler:
    """Request frames carry an ast tree: only ast classes and a few builtin constants may be reconstructed."""

    _OK = {"Ellipsis", "complex"}  # the only builtin globals an ast tree's constants need (bytes/str/int/float/None are opcodes)

    @classmethod
    def loads(cls, data: bytes) -> Any:
        import io
        import pickle

        class U(pickle.Unpickler):
            def find_class(self, module: str, name: str):
                if module == "ast" and isinstance(getattr(ast, name, None), type) and issubclass(getattr(ast, name), ast.AST):
                    return getattr(ast, name)
                if module == "builtins" and name in cls._OK:
                    return getattr(builtins, name)
                raise pickle.UnpicklingError(f"forbidden global {module}.{name}")

        return U(io.BytesIO(data)).load()


def _detailed_to_json(res: tuple[list[DetailedCandidate], dict[int, str]]) -> dict[str, Any]:
    det, why = res

    def wire(value: Any) -> Any:
        if type(value) is _datetime.timedelta:
            return {"__timedelta__": [value.days, value.seconds, value.microseconds]}
        if isinstance(value, list):
            return [wire(item) for item in value]
        if type(value) is tuple:
            return {"__tuple__": [wire(item) for item in value]}
        if isinstance(value, dict):
            return {key: wire(item) for key, item in value.items()}
        return value

    cands = [[{name: wire(value) for name, value in c.params.items()}, c.condition, c.wants, c.origin, c.exact,
              c.residuals] for c in det]
    return {"ok": True, "cands": cands,
            "why": {str(k): v for k, v in why.items()}}


def _worker_import(name: str):
    """Import a sibling hlith module inside the worker. The worker runs this file as a script: the package root is not
    on sys.path, and the copy running as __main__ must be THE ``hlith.drive_inputs`` the siblings import."""
    import importlib
    import importlib.util
    from pathlib import Path

    if "hlith" not in sys.modules:
        # Register the package by its own directory: under confinement only that directory is granted, so a path-based
        # lookup of ``hlith`` through its parent (``src``, not listable) finds nothing.
        pkg = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location("hlith", pkg / "__init__.py", submodule_search_locations=[str(pkg)])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["hlith"] = mod
        spec.loader.exec_module(mod)
    sys.modules.setdefault("hlith.drive_inputs", sys.modules[__name__])
    return importlib.import_module("hlith." + name)


def _run_request(req: dict[str, Any]) -> dict[str, Any]:
    entry = req.get("entry", "drive")
    call = req["call"]
    if entry == "delta_rel":
        return {"ok": True, "result": _worker_import("delta_rel")._check_callable_inproc(**call).to_dict()}
    if entry == "guard_removed":
        return {"ok": True, "result": _worker_import("guard_removed")._removed_entry_guards_inproc(**call)}
    if entry == "probe":  # what the forked child can see (tests / diagnostics)
        import resource
        res = {"ok": True, "unpickled_in_child": True, "pid": os.getpid(), "ppid": os.getppid(),
               **{f"fd{n}": os.readlink(f"/proc/self/fd/{n}") for n in (0, 1, 2)}}
        res["rlimit_as"] = resource.getrlimit(resource.RLIMIT_AS)[0]  # the limits the child REPORTS about itself
        res["rlimit_cpu"] = resource.getrlimit(resource.RLIMIT_CPU)[0]
        res["rlimit_nofile"] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        res["rlimit_fsize"] = resource.getrlimit(resource.RLIMIT_FSIZE)[0]
        with open("/proc/self/status") as f:
            res["vm_size"] = next((int(ln.split()[1]) * 1024 for ln in f if ln.startswith("VmSize:")), 0)
        n = call.get("alloc_mb") if isinstance(call, dict) else None
        if isinstance(n, int) and 0 < n <= 4096:
            try:
                keep = bytearray(n * 1024 * 1024)
                keep[::4096] = b"x" * len(keep[::4096])
                res["alloc"] = "ok"
            except MemoryError:
                res["alloc"] = "MemoryError"
        return res
    res = _candidates_detailed_inproc(
        [tuple(x) for x in call["params"]], list(call["conditions"]), want=call["want"], timeout_ms=call["timeout_ms"],
        max_per_condition=call["max_per_condition"], fn_ast=call["fn_ast"], target_lineno=call["target_lineno"],
        path=[tuple(x) for x in call["path"]])
    out = _detailed_to_json(res)
    out["work_units"] = _WORK["units"]
    return out


def _vm_peak() -> int:
    try:
        with open("/proc/self/status") as f:
            for ln in f:
                if ln.startswith("VmPeak:"):
                    return int(ln.split()[1]) * 1024
    except OSError:
        pass
    return 0


def _set_child_limits(lim: dict[str, Any]) -> None:
    import resource

    vm = 0
    try:
        with open("/proc/self/status") as f:
            for ln in f:
                if ln.startswith("VmSize:"):
                    vm = int(ln.split()[1]) * 1024
    except OSError:
        pass
    mem = min(vm + int(lim["mem_mb"]) * 1024 * 1024, int(lim.get("as_mb", 1024)) * 1024 * 1024, _TEMPLATE_AS)
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    _CHILD["as_cap"] = mem
    cpu = max(1, int(lim["cpu_s"]))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


_CHILD: dict[str, Any] = {"as_cap": 0}
_TEMPLATE_AS = 6 * 1024**3  # address-space cap of the template itself; a child's cap can only be lower


def _set_template_limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (_TEMPLATE_AS, _TEMPLATE_AS))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _worker_main() -> None:
    """The template process (runs confined): warm up, then serve one request at a time, forking a child per call.
    A request is a JSON header frame (kind, entry, limits) and, for a call, a pickle frame holding the arguments:
    the header is all the template ever interprets; the pickle is only opened inside the limited child."""
    import signal
    import time as _t

    global _IN_WORKER
    _IN_WORKER = True
    rfd, wfd = 0, 1
    _set_template_limits()
    # warm-up with a fixed query so every child starts from the same memory image
    _candidates_detailed_inproc([("x", "int")], ["x > 3 and x % 2 == 0"], want="both")
    preload = {}
    for mod in ("delta_rel", "delta_rel_uf", "guard_removed"):
        try:
            _worker_import(mod)
            preload[mod] = True
        except Exception as e:  # noqa: BLE001 - the entry then answers with a named stop
            preload[mod] = f"{type(e).__name__}: {e}"[:200]
    _frame_write(wfd, json.dumps({"ready": True, "preload": preload, "z3": z3.get_version_string(),
                                   "hash_seed": os.environ.get("PYTHONHASHSEED")}).encode())
    while True:
        head = _frame_read(rfd)
        if head is None:
            return
        try:
            hdr = json.loads(head)
            kind = hdr["kind"]
            lim = hdr.get("limits")
            if kind == "call":
                blob = _frame_read(rfd)
                if blob is None:
                    return
                float(lim["wall_s"])
        except Exception as e:  # noqa: BLE001
            _frame_write(wfd, json.dumps({"ok": False, "stop": f"bad request: {type(e).__name__}"}).encode())
            continue
        if kind == "selftest":
            _frame_write(wfd, json.dumps(_selftest()).encode())
            continue
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(r)
                devnull = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):  # the protocol pipe (fd 0/1) is the template's: the child never touches it
                    os.dup2(devnull, fd)
                os.close(devnull)
                signal.signal(signal.SIGXCPU, signal.SIG_DFL)
                sys.stdin = open(os.devnull)
                sys.stdout = sys.stderr = open(os.devnull, "w")
                _set_child_limits(lim)
                try:
                    call = _SafeUnpickler.loads(blob)  # inside the limited child, never in the template
                    _resp = _run_request({"entry": hdr.get("entry", "drive"), "call": call})
                    _resp["vm_peak_bytes"] = _vm_peak()  # measured, so the absolute cap can be set with a margin over real use
                    if hdr.get("entry", "drive") != "probe" and _CHILD["as_cap"] and _resp["vm_peak_bytes"] >= _CHILD["as_cap"] - 2 * 1024 * 1024:
                        # the cap was touched: z3 may have swallowed its own out-of-memory and answered with less. Say so; the
                        # partial answer is dropped (a generator losing candidates is safe, a silent thinner answer is not named).
                        _resp = {"ok": False, "stop": "memory limit reached", "vm_peak_bytes": _resp["vm_peak_bytes"]}
                    payload = json.dumps(_resp, allow_nan=False)
                except MemoryError:
                    payload = json.dumps({"ok": False, "stop": "memory limit reached"})
                except RecursionError:
                    payload = json.dumps({"ok": False, "stop": "recursion limit reached"})
                except Exception as e:  # noqa: BLE001
                    payload = json.dumps({"ok": False, "stop": f"crash: {type(e).__name__}"})
                _frame_write(w, payload.encode())
            except BaseException as e:  # noqa: BLE001
                try:
                    _frame_write(w, json.dumps({"ok": False, "stop": f"crash: {type(e).__name__}"}).encode())
                except BaseException:  # noqa: BLE001
                    pass
            os._exit(0)
        os.close(w)
        deadline = _t.monotonic() + float(lim["wall_s"])
        try:
            out = _frame_read(r, deadline)
            stop = None if out else "child produced no answer"
        except TimeoutError:
            out, stop = None, f"wall limit reached ({lim['wall_s']:g} s): killed"
            os.kill(pid, signal.SIGKILL)
        except ValueError:
            out, stop = None, "answer too large: killed"
            os.kill(pid, signal.SIGKILL)
        os.close(r)
        _, st = os.waitpid(pid, 0)
        if out is None:
            if os.WIFSIGNALED(st) and stop is None or (os.WIFSIGNALED(st) and "no answer" in str(stop)):
                sig = os.WTERMSIG(st)
                stop = {signal.SIGXCPU: "cpu limit reached: killed", signal.SIGKILL: "killed (memory limit or wall limit)",
                        signal.SIGSEGV: "crashed (signal SIGSEGV)", signal.SIGABRT: "crashed (signal SIGABRT)"}.get(
                    sig, f"crashed (signal {sig})")
            _frame_write(wfd, json.dumps({"ok": False, "stop": stop}).encode())
        else:
            _frame_write(wfd, out)


_NET_DENIED = {101, 100, 13, 1}  # ENETUNREACH, ENETDOWN, EACCES, EPERM: ECONNREFUSED means the network is THERE
_WRITE_DENIED = ("EACCES", "EPERM", "EROFS")


def _selftest() -> dict[str, Any]:
    """What the confinement actually denies, observed from inside the template: the errno of a TCP connect to
    loopback, the outcome of creating a file in every directory a plain user could normally write, and the limits.
    Probe files are created exclusively and removed at once; nothing is left behind."""
    import errno
    import resource
    import socket

    res: dict[str, Any] = {"hash_seed": os.environ.get("PYTHONHASHSEED"), "z3": z3.get_version_string()}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", 9))
            res["net_errno"] = 0
        finally:
            s.close()
    except OSError as e:
        res["net_errno"] = e.errno if e.errno is not None else -1
    # The cwd itself is NOT probed: in the gate's driver it is the declared scratch (writable by design). Everything
    # AROUND it is: every ancestor of the cwd, every directory the interpreter imports from (sys.path), this module's
    # own directory, and the usual places a plain user can write.
    ancestors = []
    d_ = os.path.dirname(os.getcwd())
    while d_ and d_ not in ancestors:
        ancestors.append(d_)
        nd = os.path.dirname(d_)
        if nd == d_:
            break
        d_ = nd
    syspath = [p for p in sys.path if p and os.path.isdir(p)]
    dirs = [*ancestors, "/", "/tmp", "/var/tmp", "/dev/shm", os.path.expanduser("~"), *syspath,
            os.path.dirname(os.path.abspath(__file__))]
    writes: dict[str, str] = {}
    for d in dict.fromkeys(dirs):
        probe = os.path.join(d, f".hlith-drive-selftest-{os.getpid()}")
        try:
            fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as e:
            writes[d] = errno.errorcode.get(e.errno, str(e.errno))
            continue
        os.close(fd)
        try:
            os.unlink(probe)
        except OSError:
            pass
        writes[d] = "allowed"
    res["writes"] = writes
    res["rlimit_as"] = resource.getrlimit(resource.RLIMIT_AS)[0]
    res["rlimit_nofile"] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    res["rlimit_fsize"] = resource.getrlimit(resource.RLIMIT_FSIZE)[0]
    try:
        with open("/proc/self/status") as f:
            res["pid_ns"] = any(ln.startswith("NSpid:") and len(ln.split()) > 2 for ln in f)
    except OSError:
        res["pid_ns"] = None
    return res


def _proves_confinement(st: dict[str, Any]) -> tuple[bool, str]:
    """Denial must be PROVED, never assumed: the network must be unreachable by a specific errno (connection refused
    means a network exists), no probe directory may be writable, and at least one write must have failed with a
    permission errno (a missing directory proves nothing). Anything else is 'not confined'."""
    ne = st.get("net_errno")
    if ne not in _NET_DENIED:
        return False, f"loopback connect gave errno {ne!r} (not a denial)"
    w = st.get("writes") or {}
    open_ = [d for d, v in w.items() if v == "allowed"]
    if open_:
        return False, f"files can be created in {open_}"
    if not any(v in _WRITE_DENIED for v in w.values()):
        return False, f"no write was refused by a permission errno ({w})"
    return True, ""


def _sandbox_shutdown() -> None:
    proc, root = _SB["proc"], _SB["root"]
    _SB.update(proc=None, pid=None, info=None, root=None)
    if proc is not None:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=1)
        except Exception:  # noqa: BLE001
            proc.kill()
            try:
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        for f in (proc.stdout, proc.stderr):
            try:
                f.close()
            except OSError:
                pass
    if root:
        try:
            os.rmdir(root)  # removes only an EMPTY dir: the launcher already cleaned its mount point
        except OSError:
            pass


def _load_sibling(name: str):
    import importlib.util
    from pathlib import Path

    f = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("_hlith_" + name, f)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # @dataclass looks its module up here
    spec.loader.exec_module(mod)
    return mod


def _drain_stderr(proc, buf: bytearray) -> None:
    """Keep the template's stderr pipe empty (an unread pipe would block the worker once it fills) and keep the last
    bytes for the failure message."""
    try:
        while True:
            chunk = os.read(proc.stderr.fileno(), 4096)
            if not chunk:
                return
            buf += chunk
            del buf[:-4000]
    except (OSError, ValueError):
        return


def _spawn_worker(mode: str) -> str | None:
    """Start the template in ``mode`` ("launcher": under _confine.py; "inherited": a plain child that inherits whatever
    confinement this process already has). None on success, else the reason."""
    import subprocess
    import tempfile
    import threading
    from pathlib import Path

    here = Path(__file__).resolve()
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "PYTHONHASHSEED": "0"}
    root = None
    if mode == "launcher":
        launcher = here.with_name("_confine.py")
        if not launcher.exists():
            return "kernel confinement launcher not found"
        try:
            sb = _load_sibling("sandbox")
            spec = sb.Profile(ro=(str(here.parent),)).spec()
            sb.vet_grants(spec)
        except Exception as e:  # noqa: BLE001
            return f"confinement profile refused: {e}"
        root = tempfile.mkdtemp(prefix="hlith-run-")
        cmd = [sys.executable, "-I", str(launcher), json.dumps({**spec, "root_parent": root}), "--",
               sys.executable, "-I", str(here), "--worker"]
    else:
        cmd = [sys.executable, "-I", str(here), "--worker"]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                close_fds=True, cwd="/" if mode == "launcher" else None)
    except OSError as e:
        if root:
            os.rmdir(root)
        return f"cannot start the worker: {e}"
    buf = bytearray()
    drain = threading.Thread(target=_drain_stderr, args=(proc, buf), daemon=True)
    drain.start()
    _SB.update(proc=proc, root=root, owner=os.getpid(), drain=drain, errbuf=buf)
    try:
        data = _frame_read(proc.stdout.fileno(), time_deadline(30))
    except (TimeoutError, ValueError):
        data = None
    info = None
    if data:
        try:
            info = json.loads(data)
        except ValueError:
            info = None
    if not isinstance(info, dict):
        try:
            proc.kill()
        except OSError:
            pass
        drain.join(1)
        err = bytes(buf).decode("utf-8", "replace").strip()[-300:]
        _sandbox_shutdown()
        return f"worker did not start ({mode}): {err}"
    info["mode"] = mode
    _SB["pid"] = proc.pid
    _SB["info"] = info
    if info.get("hash_seed") != "0":
        _sandbox_shutdown()
        return f"worker hash seed is {info.get('hash_seed')!r}, not '0'"
    return None


def _selftest_roundtrip() -> dict[str, Any]:
    proc = _SB["proc"]
    with _SB["lock"]:
        _frame_write(proc.stdin.fileno(), json.dumps({"kind": "selftest"}).encode())
        data = _frame_read(proc.stdout.fileno(), time_deadline(30))
    try:
        return json.loads(data or b"{}")
    except ValueError:
        return {}


def _sandbox_start() -> str | None:
    """Start the worker; None on success, else the reason (a named stop for the caller). The launcher is tried first;
    where it cannot run (inside the gate's own confined driver: mount/setgroups are denied) a plain child that
    inherits the parent's confinement is used. NEITHER is trusted by assumption: the started worker must PROVE denial
    of network and writes (see ``_proves_confinement``); no_new_privs alone proves nothing (bwrap, systemd, docker and
    CI set it without our confinement)."""
    import threading

    if _SB["lock"] is None:
        _SB["lock"] = threading.Lock()
    modes = [_SB["force"]] if _SB.get("force") else ["launcher", "inherited"]
    errs: list[str] = []
    for mode in modes:
        err = _spawn_worker(mode)
        if err is not None:
            errs.append(err)
            continue
        st = _selftest_roundtrip()
        ok, why = _proves_confinement(st)
        if ok:
            import atexit

            atexit.register(_sandbox_shutdown)
            return None
        _sandbox_shutdown()
        errs.append(f"not confined ({mode}): {why}")
    return "; ".join(errs)


def time_deadline(seconds: float) -> float:
    import time as _t

    return _t.monotonic() + seconds


def _sandbox_ensure() -> str | None:
    import threading

    if _SB["lock"] is None:
        _SB["lock"] = threading.Lock()
    proc = _SB["proc"]
    if proc is not None and (_SB["owner"] != os.getpid() or proc.poll() is not None):
        if _SB["owner"] == os.getpid():
            _sandbox_shutdown()
        else:  # a forked copy of the supervisor must not touch its parent's worker
            _SB.update(proc=None, pid=None, info=None, root=None)
        proc = None
    if proc is None:
        return _sandbox_start()
    return None


def _sandbox_pid() -> int | None:
    return _SB["pid"]


def sandbox_selftest() -> dict[str, Any]:
    """Start (or reuse) the worker and report what its confinement denies. ``confined`` is the PROOF, not a guess."""
    err = _sandbox_ensure()
    if err:
        return {"confined": False, "error": err}
    out = _selftest_roundtrip()
    out["confined"] = _proves_confinement(out)[0]
    out["mode"] = (_SB["info"] or {}).get("mode")
    return out


def _limits_for(timeout_ms: int) -> dict[str, Any]:
    wall = SANDBOX_LIMITS["wall_s"] or max(10.0, timeout_ms * 6 / 1000.0 * 8 + 2.0)
    return {"wall_s": float(wall), "cpu_s": float(SANDBOX_LIMITS["cpu_s"] or wall + 1), "mem_mb": SANDBOX_LIMITS["mem_mb"],
            "as_mb": SANDBOX_LIMITS["as_mb"]}


def _stop_all(conditions: list[str], why: str) -> tuple[list[DetailedCandidate], dict[int, str]]:
    return [], {i: f"driver sandbox: {why}" for i in range(len(conditions))}


def _roundtrip(req: dict[str, Any]) -> dict[str, Any]:
    """Send one request (JSON header frame + pickle frame of the arguments) and return the JSON answer; any failure is
    {"ok": False, "stop": <why>}."""
    import pickle

    try:
        blob = pickle.dumps(req["call"], protocol=4)
        head = json.dumps({"kind": "call", "entry": req.get("entry", "drive"), "limits": req["limits"]}).encode()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "stop": f"request not serialisable: {type(e).__name__}"}
    data = None
    for attempt in (1, 2):
        err = _sandbox_ensure()
        if err:
            return {"ok": False, "stop": err}
        with _SB["lock"]:
            proc = _SB["proc"]
            try:
                _frame_write(proc.stdin.fileno(), head)
                _frame_write(proc.stdin.fileno(), blob)
                data = _frame_read(proc.stdout.fileno(), time_deadline(req["limits"]["wall_s"] + 10))
            except (OSError, TimeoutError, ValueError):
                data = None
        if data is not None:
            break
        _sandbox_shutdown()  # worker died or stopped answering: restart once, then name the stop
        if attempt == 2:
            return {"ok": False, "stop": "worker stopped answering twice"}
    try:
        out = json.loads(data)
    except ValueError:
        return {"ok": False, "stop": "worker answered with invalid JSON"}
    if not isinstance(out, dict):
        return {"ok": False, "stop": "worker answered with invalid JSON"}
    if not out.get("ok") and "stop" not in out:
        out["stop"] = "no answer"
    _LAST["vm_peak_bytes"] = out.get("vm_peak_bytes") if isinstance(out, dict) else None
    return out


_ENTRY_WALL_S = {"delta_rel": 120.0, "guard_removed": 60.0}  # hard kill; the rlimit work budgets bind long before


def sandbox_call(entry: str, call: dict[str, Any]) -> dict[str, Any]:
    """Run ``entry`` ("delta_rel" | "guard_removed") on picklable ``call`` arguments in a forked worker child (same
    confined, limited, JSON-answer protocol as the driver). {"ok": True, "result": ...} or {"ok": False, "stop": why}."""
    wall = float(SANDBOX_LIMITS["wall_s"] or _ENTRY_WALL_S[entry])
    lim = {"wall_s": wall, "cpu_s": float(SANDBOX_LIMITS["cpu_s"] or wall + 1),
           "mem_mb": max(int(SANDBOX_LIMITS["mem_mb"]), 2048), "as_mb": SANDBOX_LIMITS["as_mb"]}
    out = _roundtrip({"kind": "call", "entry": entry, "limits": lim, "call": call})
    if not out.get("ok"):
        out["stop"] = f"{entry} sandbox: {out.get('stop')}"
    return out


_LAST: dict[str, Any] = {"work_units": None, "vm_peak_bytes": None}


def last_call_work_units() -> int | None:
    """Work units (the driver's rlimit meter) the last sandboxed candidates_detailed call spent: what the case's phase ledger
    charges to its generation stage. None when the call produced no answer."""
    return _LAST["work_units"]


def candidates_detailed(params: list[tuple[str, str | None]], conditions: list[str], *, want: str = "both",
                        timeout_ms: int = 200, max_per_condition: int = 4, fn_ast: ast.AST | None = None,
                        target_lineno: int | None = None,
                        path: Sequence[tuple[str, bool]] = ()) -> tuple[list[DetailedCandidate], dict[int, str]]:
    """Candidates for each condition (see ``_candidates_detailed_inproc`` for the semantics). Runs in a confined,
    forked, resource-limited child of a pristine worker; the answer is JSON only. Any sandbox failure is a named
    stop in the returned reasons, never an in-process fallback."""
    if _IN_WORKER:
        return _candidates_detailed_inproc(params, conditions, want=want, timeout_ms=timeout_ms,
                                           max_per_condition=max_per_condition, fn_ast=fn_ast,
                                           target_lineno=target_lineno, path=path)
    out = _roundtrip({"kind": "call", "entry": "drive", "limits": _limits_for(timeout_ms),
                      "call": {"params": [list(x) for x in params], "conditions": list(conditions), "want": want,
                               "timeout_ms": timeout_ms, "max_per_condition": max_per_condition, "fn_ast": fn_ast,
                               "target_lineno": target_lineno, "path": [list(x) for x in path]}})
    _LAST["work_units"] = int(out["work_units"]) if isinstance(out.get("work_units"), int) else None
    if not out.get("ok"):
        return _stop_all(conditions, str(out.get("stop", "no answer")))
    return ([DetailedCandidate(c[0], c[1], c[2], c[3], c[4], c[5] if len(c) > 5 else []) for c in out["cands"]],
            {int(k): v for k, v in out["why"].items()})


if __name__ == "__main__" and "--worker" in sys.argv:
    _worker_main()
