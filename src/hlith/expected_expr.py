# SPDX-License-Identifier: Apache-2.0
"""Closed grammar for a delta's COMPUTED expected result: ``expected = {"kind": "returns_expr", "expr": "<expr>"}``.

An intended change whose post value is computed from the call's inputs (e.g. ``super_len(o)`` becomes
``len(o.encode('utf-8'))`` for every str) cannot be declared with a constant ``value_repr``. This module is the ONE
parser/interpreter for such expressions (design review ruling 2026-11-13; owner review). Callers:

- ``runtime.validate_delta`` at manifest time: ``validate_expected_expr(expr, None)`` (callable parameters are not
  known yet; free names must be plain identifiers and are bound later).
- review's differential, in the CONFINED evaluator, per input: ``evaluate_expected_expr(expr, bound_args)`` then
  ``value_matches(value, post_value)``.
- ``feedback.delta_covers_pin`` in the supervisor, only on inert pin data (``inert_from_repr`` / ``is_inert``).

Security model: user text is parsed with ``ast.parse`` and then only WALKED. There is no eval/exec/compile of user text.
Every node type, builtin and method is on a fixed allowlist. At evaluation every value that reaches a builtin or a
method is an exact inert builtin type (None, bool, int, float, str, bytes, and tuple/list/dict of those), so no
user-defined ``__str__``/``__eq__``/``__len__``/``__index__`` can run. Sizes are checked at every operation, there is a
step budget, and ``*`` only repeats by a small literal count. Any error or cap means "not covered" (fail closed).
"""
from __future__ import annotations

import ast
import builtins as _builtins
from typing import Any, Sequence

MAX_LEN = 400  # characters of expression text
MAX_NODES = 40  # AST nodes (expression contexts excluded)
MAX_DEPTH = 6  # nesting below the expression body
MAX_STEPS = 2000  # interpreter node evaluations
MAX_SEQ = 1024 * 1024  # elements / characters / bytes of any intermediate sequence (1 MiB: a 256 Ki-char str encodes losslessly;
# concatenation / repetition are checked BEFORE they are built, the 50 ms alarm and MAX_STEPS bound the work)
MAX_REPR = 64 * 1024  # repr of the result
MAX_REPEAT = 1024  # largest literal count for sequence repetition
MAX_INT_BITS = 64 * 1024

FUNCS = frozenset({"len", "str", "bytes", "int", "float", "bool", "abs", "min", "max", "sorted", "tuple", "list",
                   "round"})
METHODS = frozenset({"encode", "decode", "lower", "upper", "casefold", "strip", "lstrip", "rstrip", "replace",
                     "startswith", "endswith", "split", "join", "count", "find"})
ENCODE_CODECS = frozenset({"utf-8", "utf8", "ascii", "latin-1", "latin1", "utf-16", "utf-32"})
DECODE_CODECS = frozenset({"utf-8", "utf8"})
ERRORS = frozenset({"strict", "ignore", "replace", "backslashreplace", "surrogateescape", "xmlcharrefreplace"})
_ARITY = {  # (min, max) positional args
    "len": (1, 1), "str": (1, 1), "bytes": (1, 1), "int": (1, 1), "float": (1, 1), "bool": (1, 1), "abs": (1, 1),
    "min": (1, 4), "max": (1, 4), "sorted": (1, 1), "tuple": (1, 1), "list": (1, 1), "round": (1, 2),
    "encode": (0, 2), "decode": (0, 2), "lower": (0, 0), "upper": (0, 0), "casefold": (0, 0), "strip": (0, 1),
    "lstrip": (0, 1), "rstrip": (0, 1), "replace": (2, 3), "startswith": (1, 1), "endswith": (1, 1),
    "split": (0, 2), "join": (1, 1), "count": (1, 1), "find": (1, 1),
}
_INERT_SCALARS = (type(None), bool, int, float, str, bytes)
_CMP = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot)
_BIN = (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)
_RESERVED = frozenset(dir(_builtins)) | {"True", "False", "None"}


class ExprError(ValueError):
    """The expression is outside the closed grammar."""


class ExprEvalError(Exception):
    """Evaluation failed or hit a cap: the delta does NOT cover this input (fail closed)."""


# ---------------------------------------------------------------- validation

def _children(n: ast.AST):
    return [c for c in ast.iter_child_nodes(n) if not isinstance(c, ast.expr_context)]


def _depth(n: ast.AST) -> int:
    kids = _children(n)
    return 0 if not kids else 1 + max(_depth(k) for k in kids)


def _is_small_count(n: ast.AST) -> bool:
    return (isinstance(n, ast.Constant) and type(n.value) is int and abs(n.value) <= MAX_REPEAT) or (
        isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub) and _is_small_count(n.operand))


def _parse(expr: str, params: Sequence[str] | None) -> ast.Expression:
    # exact str only (review): a str subclass's __len__/__iter__/__eq__/__hash__ would run in the supervisor
    if type(expr) is not str or not 1 <= len(expr) <= MAX_LEN:
        raise ExprError(f"expr must be 1..{MAX_LEN} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in expr):
        raise ExprError("expr must be a single printable line")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ExprError(f"expr syntax: {e.msg}") from None
    nodes = [n for n in ast.walk(tree.body) if not isinstance(n, ast.expr_context)]
    if len(nodes) > MAX_NODES:
        raise ExprError(f"expr has {len(nodes)} nodes (max {MAX_NODES})")
    if _depth(tree.body) > MAX_DEPTH:
        raise ExprError(f"expr nesting deeper than {MAX_DEPTH}")
    if params is not None and not all(type(p) is str for p in params):
        raise ExprError("parameter names must be exact str")
    names = None if params is None else frozenset(params)
    _check(tree.body, names)
    return tree


def _check_name(n: ast.Name, names) -> None:
    if n.id.startswith("__"):
        raise ExprError(f"name {n.id!r}: dunder names are not allowed")
    if names is not None:
        if n.id not in names:
            raise ExprError(f"name {n.id!r} is not a parameter of the callable")
    elif n.id in _RESERVED:
        raise ExprError(f"name {n.id!r} is a builtin, not a parameter")


def _check(n: ast.AST, names) -> None:
    if isinstance(n, ast.Constant):
        if not isinstance(n.value, _INERT_SCALARS):
            raise ExprError(f"literal {type(n.value).__name__} is not allowed")
        return
    if isinstance(n, ast.Name):
        _check_name(n, names)
        return
    if isinstance(n, ast.Tuple):
        if len(n.elts) > 20:
            raise ExprError("tuple literal longer than 20")
        for e in n.elts:
            _check(e, names)
        return
    if isinstance(n, ast.BinOp):
        if not isinstance(n.op, _BIN):
            raise ExprError(f"operator {type(n.op).__name__} is not allowed (+ - * // % only)")
        if isinstance(n.op, ast.Mult) and not (_is_small_count(n.left) or _is_small_count(n.right)):
            raise ExprError(f"* needs a literal int operand with |n| <= {MAX_REPEAT}")
        _check(n.left, names)
        _check(n.right, names)
        return
    if isinstance(n, ast.UnaryOp):
        if not isinstance(n.op, (ast.USub, ast.Not)):
            raise ExprError(f"unary {type(n.op).__name__} is not allowed")
        _check(n.operand, names)
        return
    if isinstance(n, ast.BoolOp):
        for v in n.values:
            _check(v, names)
        return
    if isinstance(n, ast.Compare):
        for o, rhs in zip(n.ops, n.comparators):
            if not isinstance(o, _CMP):
                raise ExprError("comparison operator not allowed")
            if isinstance(o, (ast.Is, ast.IsNot)) and not (isinstance(rhs, ast.Constant) and rhs.value is None):
                raise ExprError("'is' / 'is not' only against None")
        _check(n.left, names)
        for c in n.comparators:
            _check(c, names)
        return
    if isinstance(n, ast.IfExp):
        for c in (n.test, n.body, n.orelse):
            _check(c, names)
        return
    if isinstance(n, ast.Subscript):
        _check(n.value, names)
        s = n.slice
        if isinstance(s, ast.Slice):
            for part in (s.lower, s.upper, s.step):
                if part is not None:
                    _check(part, names)
        else:
            _check(s, names)
        return
    if isinstance(n, ast.Call):
        if n.keywords:
            raise ExprError("keyword arguments are not allowed")
        if any(isinstance(a, ast.Starred) for a in n.args):
            raise ExprError("starred arguments are not allowed")
        f = n.func
        if isinstance(f, ast.Name):
            if f.id not in FUNCS:
                raise ExprError(f"function {f.id!r} is not on the allowlist {sorted(FUNCS)}")
            name = f.id
        elif isinstance(f, ast.Attribute):
            if f.attr not in METHODS:
                raise ExprError(f"method {f.attr!r} is not on the allowlist {sorted(METHODS)}")
            name = f.attr
            _check(f.value, names)
            if name in ("encode", "decode"):
                allowed = ENCODE_CODECS if name == "encode" else DECODE_CODECS
                for i, a in enumerate(n.args):
                    ok = isinstance(a, ast.Constant) and isinstance(a.value, str) and (
                        a.value.lower() in allowed if i == 0 else a.value in ERRORS)
                    if not ok:
                        what = f"codec in {sorted(allowed)}" if i == 0 else f"errors in {sorted(ERRORS)}"
                        raise ExprError(f"{name}: argument {i + 1} must be a literal {what}")
        else:
            raise ExprError("only allowlisted functions and str/bytes methods may be called")
        lo, hi = _ARITY[name]
        if not lo <= len(n.args) <= hi:
            raise ExprError(f"{name} takes {lo}..{hi} positional arguments")
        for a in n.args:
            _check(a, names)
        return
    raise ExprError(f"{type(n).__name__} is outside the closed grammar")


def validate_expected_expr(expr: str, params: Sequence[str] | None) -> tuple[bool, str]:
    """(ok, reason); reason is '' when ok. ``params`` = the callable's parameter names, or None at manifest time
    (then any plain non-dunder, non-builtin identifier is accepted as a name and must be bound at evaluation)."""
    try:
        _parse(expr, params)
    except ExprError as e:
        return False, str(e)
    return True, ""


# ---------------------------------------------------------------- inert values

def is_inert(v: Any, _depth: int = 0) -> bool:
    """Exact builtin data only (subclasses are not inert): nothing user-defined can run when it is used."""
    if _depth > 20:
        return False
    t = type(v)
    if t in _INERT_SCALARS:
        return t is not int or v.bit_length() <= MAX_INT_BITS
    if t in (tuple, list):
        return len(v) <= MAX_SEQ and all(is_inert(x, _depth + 1) for x in v)
    if t is dict:
        return len(v) <= MAX_SEQ and all(is_inert(k, _depth + 1) and is_inert(x, _depth + 1) for k, x in v.items())
    return False


def inert_from_repr(text: str) -> tuple[bool, Any]:
    """Parse a recorded repr with ast.literal_eval ONLY; (False, reason) unless the value is inert and bounded."""
    if type(text) is not str or len(text) > MAX_REPR:
        return False, "repr missing or too long"
    try:
        v = ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False, "repr is not a Python literal"
    if type(v) in (set, frozenset, complex) or not is_inert(v):
        return False, "value is not inert builtin data"
    return True, v


def value_matches(result: Any, post: Any) -> bool:
    """The declared value equals the post value: both inert, same exact types throughout, equal (bool is not int,
    1 is not 1.0)."""
    if not (is_inert(result) and is_inert(post)):
        return False
    return _same(result, post)


def _same(a: Any, b: Any) -> bool:
    if type(a) is not type(b):
        return False
    if type(a) in (tuple, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if type(a) is dict:
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if type(a) is float and a != a:
        return b != b
    return a == b


# ---------------------------------------------------------------- evaluation

def _size(v: Any) -> Any:
    t = type(v)
    if t in (str, bytes, tuple, list, dict) and len(v) > MAX_SEQ:
        raise ExprEvalError(f"intermediate {t.__name__} longer than {MAX_SEQ}")
    if t is int and v.bit_length() > MAX_INT_BITS:
        raise ExprEvalError("intermediate int too large")
    return v


def _need(v: Any, *types) -> Any:
    if type(v) not in types:
        raise ExprEvalError(f"{type(v).__name__} where {'/'.join(t.__name__ for t in types)} is required")
    return v


class _Interp:
    def __init__(self, bindings: dict, max_steps: int):
        self.b = bindings
        self.steps = 0
        self.max_steps = max_steps

    def ev(self, n: ast.AST) -> Any:
        self.steps += 1
        if self.steps > self.max_steps:
            raise ExprEvalError(f"step budget {self.max_steps} exceeded")
        m = getattr(self, "_" + type(n).__name__)
        return _size(m(n))

    def _Constant(self, n):
        return n.value

    def _Name(self, n):
        if n.id not in self.b:
            raise ExprEvalError(f"name {n.id!r} is not bound for this call")
        v = self.b[n.id]
        if not is_inert(v):
            raise ExprEvalError(f"parameter {n.id!r} is not inert builtin data")
        return v

    def _Tuple(self, n):
        return tuple(self.ev(e) for e in n.elts)

    def _BinOp(self, n):
        a, b = self.ev(n.left), self.ev(n.right)
        num = (int, float, bool)
        seq = (str, bytes, tuple, list)
        if isinstance(n.op, ast.Add):
            if type(a) in num and type(b) in num:
                return a + b
            if type(a) is type(b) and type(a) in seq:
                if len(a) + len(b) > MAX_SEQ:
                    raise ExprEvalError("concatenation too long")
                return a + b
            raise ExprEvalError(f"{type(a).__name__} + {type(b).__name__}")
        if isinstance(n.op, ast.Mult):
            if type(a) in num and type(b) in num:
                if type(a) is int and type(b) is int and a.bit_length() + b.bit_length() > MAX_INT_BITS:
                    raise ExprEvalError("product too large")
                return a * b
            s, k = (a, b) if type(a) in seq else (b, a)
            if type(s) not in seq or type(k) is not int or abs(k) > MAX_REPEAT or len(s) * max(k, 0) > MAX_SEQ:
                raise ExprEvalError("repetition outside the bounds")
            return s * k
        _need(a, *num)
        _need(b, *num)
        try:
            if isinstance(n.op, ast.Sub):
                return a - b
            if isinstance(n.op, ast.FloorDiv):
                return a // b
            return a % b  # numbers only: str % (printf formatting) is never evaluated
        except (ZeroDivisionError, OverflowError) as e:
            raise ExprEvalError(type(e).__name__) from None

    def _UnaryOp(self, n):
        v = self.ev(n.operand)
        if isinstance(n.op, ast.Not):
            return not v
        return -_need(v, int, float, bool)

    def _BoolOp(self, n):
        last = None
        for v in n.values:
            last = self.ev(v)
            if isinstance(n.op, ast.And) and not last:
                return last
            if isinstance(n.op, ast.Or) and last:
                return last
        return last

    def _Compare(self, n):
        left = self.ev(n.left)
        for o, c in zip(n.ops, n.comparators):
            right = self.ev(c)
            try:
                ok = {ast.Eq: lambda x, y: x == y, ast.NotEq: lambda x, y: x != y, ast.Lt: lambda x, y: x < y,
                      ast.LtE: lambda x, y: x <= y, ast.Gt: lambda x, y: x > y, ast.GtE: lambda x, y: x >= y,
                      ast.In: lambda x, y: x in y, ast.NotIn: lambda x, y: x not in y,
                      ast.Is: lambda x, y: x is None, ast.IsNot: lambda x, y: x is not None}[type(o)](left, right)
            except TypeError as e:
                raise ExprEvalError(f"comparison: {e}") from None
            if not ok:
                return False
            left = right
        return True

    def _IfExp(self, n):
        return self.ev(n.body) if self.ev(n.test) else self.ev(n.orelse)

    def _Subscript(self, n):
        v = _need(self.ev(n.value), str, bytes, tuple, list, dict)
        s = n.slice
        try:
            if isinstance(s, ast.Slice):
                parts = [None if p is None else _need(self.ev(p), int) for p in (s.lower, s.upper, s.step)]
                if type(v) is dict:
                    raise ExprEvalError("slice of a dict")
                return v[slice(*parts)]
            k = self.ev(s)
            if type(v) is not dict:
                _need(k, int)
            return v[k]
        except (IndexError, KeyError, ValueError, TypeError) as e:
            raise ExprEvalError(f"subscript: {type(e).__name__}") from None

    def _Call(self, n):
        args = [self.ev(a) for a in n.args]
        f = n.func
        try:
            if isinstance(f, ast.Name):
                return self._func(f.id, args)
            return self._method(f.attr, self.ev(f.value), args)
        except ExprEvalError:
            raise
        except (TypeError, ValueError, OverflowError, UnicodeError, IndexError) as e:
            raise ExprEvalError(f"{type(e).__name__} in call") from None

    def _func(self, name, args):
        a = args[0]
        if name == "len":
            return len(_need(a, str, bytes, tuple, list, dict))
        if name == "str":
            return str(a)  # a is inert (checked at every node), so this is builtin repr/str only
        if name == "bytes":
            if type(a) is int:
                raise ExprEvalError("bytes(int) allocates; not allowed")
            return bytes(_need(a, bytes, tuple, list))
        if name == "int":
            return int(_need(a, int, float, bool, str, bytes))
        if name == "float":
            return float(_need(a, int, float, bool, str))
        if name == "bool":
            return bool(a)
        if name == "abs":
            return abs(_need(a, int, float, bool))
        if name in ("min", "max"):
            fn = min if name == "min" else max
            if len(args) == 1:
                return fn(_need(a, str, bytes, tuple, list))
            return fn(*args)
        if name == "sorted":
            return sorted(_need(a, str, bytes, tuple, list))
        if name == "tuple":
            return tuple(_need(a, str, bytes, tuple, list, dict))
        if name == "list":
            return list(_need(a, str, bytes, tuple, list, dict))
        if name == "round":
            if len(args) == 2:
                return round(_need(a, int, float), _need(args[1], int))
            return round(_need(a, int, float))
        raise ExprEvalError(f"function {name!r}")  # unreachable after validation

    def _method(self, name, recv, args):
        _need(recv, str, bytes)
        for x in args:
            _need(x, str, bytes, int, tuple, list)
        if name in ("encode", "decode"):
            if name == "encode":
                _need(recv, str)
            else:
                _need(recv, bytes)
            return getattr(recv, name)(*args)
        if name == "replace":
            old, new = args[0], args[1]
            cnt = len(recv) + 1 if len(args) < 3 else _need(args[2], int)
            if cnt < 0:
                cnt = len(recv) + 1
            if len(recv) + min(cnt, len(recv) + 1) * len(new) > MAX_SEQ:
                raise ExprEvalError("replace result too long")
            return recv.replace(old, new, *args[2:3])
        if name == "join":
            items = _need(args[0], tuple, list)
            if sum(len(_need(x, type(recv))) for x in items) + len(recv) * len(items) > MAX_SEQ:
                raise ExprEvalError("join result too long")
            return recv.join(items)
        if name == "split" and len(args) == 2:
            _need(args[1], int)
        return getattr(recv, name)(*args)


def evaluate_expected_expr(expr: str, bindings: dict, *, max_steps: int = MAX_STEPS) -> tuple[bool, Any]:
    """(True, value) or (False, reason). ``bindings`` = the call's bound parameters by name. The expression is
    re-validated against exactly those names; every value used must be inert; every cap fails closed."""
    try:
        if type(bindings) is not dict:
            return False, "bindings must be a dict"
        tree = _parse(expr, list(bindings))
        v = _Interp(bindings, max_steps).ev(tree.body)
        if not is_inert(v):
            return False, "result is not inert builtin data"
        if len(repr(v)) > MAX_REPR:
            return False, f"result repr longer than {MAX_REPR}"
        return True, v
    except ExprError as e:
        return False, f"invalid expr: {e}"
    except ExprEvalError as e:
        return False, str(e)
    except RecursionError:
        return False, "recursion limit"
    except MemoryError:
        return False, "memory"
