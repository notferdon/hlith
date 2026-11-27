# SPDX-License-Identifier: Apache-2.0
"""Object-shaped candidate inputs and operand kinds for the driver (driver inputs). Generator side only: nothing here claims
coverage; every value is a HINT (exact False) that the real evaluators run and observe. Pure AST + stdlib (no z3, no execution of
proposer text).

A. operand kinds: ``len(x)`` of a TEXT is encoding-sensitive, ``len(err.args)`` / ``len(tuple)`` is a CARDINALITY. Unknown stays
   encoding-sensitive (the conservative answer). Exception candidates vary the argument count and the builtin class.
B. (see below) real re.Match / re.Pattern construction.
"""

from __future__ import annotations

import ast
from typing import Any

_TEXT_ANN = {"str", "bytes", "bytearray", "Text", "AnyStr", "LiteralString"}
_CARD_ANN = {"tuple", "list", "dict", "set", "frozenset", "Tuple", "List", "Dict", "Set", "FrozenSet", "Sequence", "Mapping",
             "Iterable", "Collection", "MutableSequence", "MutableMapping", "Deque", "deque", "OrderedDict", "defaultdict"}
_TEXT_CALLS = {"str", "repr", "ascii", "bytes", "bytearray", "chr", "format", "input"}
_CARD_CALLS = {"list", "tuple", "set", "frozenset", "dict", "sorted", "reversed", "range", "enumerate", "zip", "map", "filter"}
_TEXT_METHODS = {"join", "decode", "encode", "format", "strip", "lstrip", "rstrip", "lower", "upper", "title", "casefold",
                 "capitalize", "swapcase", "replace", "ljust", "rjust", "center", "zfill", "expandtabs", "translate", "removeprefix",
                 "removesuffix", "normalize", "format_map"}
_CARD_METHODS = {"split", "rsplit", "splitlines", "keys", "values", "items", "partition", "rpartition"}


def _ann_kind(ann: ast.expr | None) -> str:
    if ann is None:
        return "unknown"
    base = ann.value if isinstance(ann, ast.Subscript) else ann
    name = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else None)
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        name = ann.value.split("[")[0].split(".")[-1]
    if name in _TEXT_ANN:
        return "text"
    if name in _CARD_ANN:
        return "cardinality"
    return "unknown"


def _bindings(fn: ast.AST, name: str) -> list[ast.expr | None]:
    """Every binding of ``name`` in the function: an assigned expression, or None for a binding we cannot type (loop target,
    augmented assignment, with-target, walrus of unknown, tuple unpacking)."""
    out: list[ast.expr | None] = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    out.append(n.value)
                elif any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(t)):
                    out.append(None)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            out.append(n.value)
        elif isinstance(n, (ast.AugAssign,)) and isinstance(n.target, ast.Name) and n.target.id == name:
            out.append(None)
        elif isinstance(n, (ast.For, ast.AsyncFor)) and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.target)):
            out.append(None)
        elif isinstance(n, ast.NamedExpr) and n.target.id == name:
            out.append(n.value)
        elif isinstance(n, ast.withitem) and n.optional_vars is not None and any(
                isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.optional_vars)):
            out.append(None)
    return out


def operand_kind(expr: ast.expr, fn: ast.AST | None = None, _depth: int = 0) -> str:
    """'text' | 'cardinality' | 'unknown' for the operand of ``len(...)``."""
    if _depth > 6:
        return "unknown"
    if isinstance(expr, ast.Constant):
        return "text" if isinstance(expr.value, (str, bytes)) else "unknown"
    if isinstance(expr, ast.JoinedStr):
        return "text"
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return "cardinality"
    if isinstance(expr, ast.Attribute):
        return "cardinality" if expr.attr == "args" else "unknown"  # exception.args is a tuple
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Name):
            return "text" if f.id in _TEXT_CALLS else ("cardinality" if f.id in _CARD_CALLS else "unknown")
        if isinstance(f, ast.Attribute):
            if f.attr in _CARD_METHODS:
                return "cardinality"
            if f.attr in _TEXT_METHODS:
                return "text"
        return "unknown"
    if isinstance(expr, ast.Subscript):
        if isinstance(expr.slice, ast.Slice):
            return operand_kind(expr.value, fn, _depth + 1)
        return "unknown"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        a, b = operand_kind(expr.left, fn, _depth + 1), operand_kind(expr.right, fn, _depth + 1)
        return a if a == b else "unknown"
    if isinstance(expr, ast.Name) and fn is not None:
        kinds: set[str] = set()
        args = getattr(fn, "args", None)
        if args is not None:
            for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                if a.arg == expr.id:
                    kinds.add(_ann_kind(a.annotation))
            for a in (args.vararg, args.kwarg):
                if a is not None and a.arg == expr.id:
                    kinds.add("cardinality")  # *args / **kwargs are containers
        for b in _bindings(fn, expr.id):
            kinds.add("unknown" if b is None else operand_kind(b, fn, _depth + 1))
        return kinds.pop() if len(kinds) == 1 else "unknown"
    return "unknown"


def len_is_encoding_sensitive(call: ast.Call, fn: ast.AST | None = None) -> bool:
    """False only when the operand is provably a cardinality (tuple/list/dict/exception.args...). Text and unknown: True."""
    if not (isinstance(call.func, ast.Name) and call.func.id == "len" and len(call.args) == 1):
        return True
    return operand_kind(call.args[0], fn) != "cardinality"


# ------------------------------------------------------------------ exception candidates
import builtins as _bi

_BUILTIN_EXC = {n for n in dir(_bi) if isinstance(getattr(_bi, n), type) and issubclass(getattr(_bi, n), BaseException)}
_SHAPES = ("Exception", "ValueError", "TypeError", "KeyError", "RuntimeError", "OSError", "ConnectionError", "TimeoutError")


def _exc_value(cls: str, n: int) -> dict[str, Any]:
    if cls in ("OSError", "ConnectionError", "TimeoutError", "FileNotFoundError", "PermissionError"):
        args: list[Any] = [2, "x", "y", "z"][:n]  # OSError(errno, strerror, ...)
    else:
        args = ["x", "y", "z", "w"][:n]
    return {"__hlith_exc__": f"builtins.{cls}", "args": args}


def _param_uses(fn: ast.AST, p: str) -> tuple[bool, list[str]]:
    """(uses ``p.args`` / len(p.args), exception class names tested with isinstance(p, X))."""
    uses_args, classes = False, []
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr == "args" and isinstance(n.value, ast.Name) and n.value.id == p:
            uses_args = True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "isinstance" and len(n.args) == 2 \
                and isinstance(n.args[0], ast.Name) and n.args[0].id == p:
            ts = n.args[1].elts if isinstance(n.args[1], ast.Tuple) else [n.args[1]]
            for t in ts:
                classes.append(ast.unparse(t))
        if isinstance(n, ast.ExceptHandler) and n.name == p and n.type is not None:
            ts = n.type.elts if isinstance(n.type, ast.Tuple) else [n.type]
            classes += [ast.unparse(t) for t in ts]
    return uses_args, classes


def exception_param_candidates(fn: ast.AST) -> list[dict[str, Any]]:
    """Hints for parameters the function treats as exceptions: argument counts 0..3 over a few builtin classes, plus every
    builtin class the function tests with isinstance (with the OSError(errno, strerror) shape). A class that is not a builtin
    is reported as ``unmodeled`` (value None), never guessed. Shape: {param, value | None, exact False, why[, unmodeled]}."""
    args = getattr(fn, "args", None)
    if args is None:
        return []
    out: list[dict[str, Any]] = []
    for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        uses_args, classes = _param_uses(fn, a.arg)
        if not uses_args and not classes:
            continue
        wanted: list[str] = []
        unmodeled: list[str] = []
        for c in classes:
            (wanted if c in _BUILTIN_EXC else unmodeled).append(c)
        base = list(dict.fromkeys([*wanted, *_SHAPES]))
        seen = set()
        for cls in base:
            for n in (0, 1, 2, 3):
                v = _exc_value(cls, n)
                key = (v["__hlith_exc__"], tuple(map(repr, v["args"])))
                if key in seen:
                    continue
                seen.add(key)
                out.append({"param": a.arg, "value": v, "exact": False,
                            "why": f"{a.arg} is used as an exception ({'args' if uses_args else 'isinstance'}): {n} argument(s)"})
        for c in dict.fromkeys(unmodeled):
            out.append({"param": a.arg, "value": None, "exact": False, "unmodeled": f"{c}: not a builtin exception, no safe construction",
                        "why": f"{a.arg} is tested against {c}"})
    return out


# ------------------------------------------------------------------ B. real re.Match / re.Pattern construction
import re as _re

_RE_MAX_PATTERN = 200
_RE_MAX_STRING = 64
_RE_MAX_CANDIDATES = 12
_MATCH_METHODS = {"group", "groups", "groupdict", "start", "end", "span", "expand", "lastindex", "lastgroup", "string", "regs"}
_PATTERN_METHODS = {"match", "search", "fullmatch", "sub", "subn", "split", "findall", "finditer", "pattern", "flags", "groupindex"}
_SEED_STRINGS = ("", "a", "abc", "%41", "a%41b", "%zz", "x y", "0", "a.b", "é")
_NESTED_QUANT = _re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]|\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[+*]")


def _re_problem(p: str) -> str | None:
    if len(p) > _RE_MAX_PATTERN:
        return f"pattern too long ({len(p)} > {_RE_MAX_PATTERN})"
    if _NESTED_QUANT.search(p):
        return "pattern has a nested quantifier (possible catastrophic backtracking): not run"
    try:
        _re.compile(p)
    except _re.error:
        return "pattern does not compile"
    return None


def module_regex_literals(module_source: str) -> list[str]:
    """Pattern literals of a module: the first argument of re.compile/match/search/fullmatch/sub/findall/finditer/split calls that
    is a string literal, and top-level string constants that compile and contain a regex metacharacter. Order of appearance."""
    try:
        tree = ast.parse(module_source)
    except (SyntaxError, ValueError):
        return []
    out: list[str] = []

    def add(v: Any) -> None:
        if isinstance(v, str) and v and v not in out:
            out.append(v)

    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.value.id == "re" and n.func.attr in {"compile", "match", "search", "fullmatch", "sub", "subn", "findall",
                                                                 "finditer", "split"} \
                and n.args and isinstance(n.args[0], ast.Constant):
            add(n.args[0].value)
    for st in tree.body:
        if isinstance(st, ast.Assign) and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str):
            v = st.value.value
            if any(ch in v for ch in "[]()*+?\\^$|{}") and _re_problem(v) != "pattern does not compile":
                add(v)
    return [x for x in out if _re_problem(x) != "pattern does not compile"]


def _string_literals(fn: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and 0 < len(n.value) <= _RE_MAX_STRING and n.value not in out:
            out.append(n.value)
    return out


def _re_param_kind(fn: ast.AST, a: ast.arg) -> str | None:
    ann = a.annotation
    text = None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        text = ann.value
    elif ann is not None:
        text = ast.unparse(ann)
    if text:
        head = text.split("[")[0].split(".")[-1]
        if head == "Match":
            return "match"
        if head == "Pattern":
            return "pattern"
    used: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == a.arg:
            used.add(n.attr)
    if used & _MATCH_METHODS and not (used & {"match", "search", "fullmatch", "sub", "subn", "findall", "finditer", "split"}):
        return "match"
    if used & {"match", "search", "fullmatch", "sub", "subn", "findall", "finditer", "split"}:
        return "pattern"
    return None


def _group_names_used(fn: ast.AST, p: str) -> set[str]:
    names = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"group", "start", "end", "span"} \
                and isinstance(n.func.value, ast.Name) and n.func.value.id == p:
            for x in n.args:
                if isinstance(x, ast.Constant) and isinstance(x.value, str):
                    names.add(x.value)
    return names


def re_param_candidates(fn: ast.AST, extra_literals: list[str] | tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Real re.Match / re.Pattern candidates for parameters annotated (or used) as such. Patterns: the code's own literals (the
    function's string constants and ``extra_literals``, e.g. ``module_regex_literals``). A match descriptor is emitted only when the
    pattern REALLY matches the seeded string (re.compile + re.search): no duck objects, no guesses. Hostile, invalid and overlong
    patterns are skipped and reported as ``unmodeled`` records (value None). Every record is a hint: exact False."""
    args = getattr(fn, "args", None)
    if args is None:
        return []
    out: list[dict[str, Any]] = []
    own = _string_literals(fn)
    for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        kind = _re_param_kind(fn, a)
        if kind is None:
            continue
        cand_patterns, unmodeled = [], []
        for p in dict.fromkeys([*extra_literals, *own]):
            if not isinstance(p, str) or not p:
                continue
            why = _re_problem(p)
            if why is None:
                cand_patterns.append(p)
            elif p in extra_literals:  # a stray string literal of the function is not a claim of being a pattern
                unmodeled.append(f"{p[:40]!r}: {why}")
        want = _group_names_used(fn, a.arg)
        cand_patterns.sort(key=lambda p: (not all(f"(?P<{g}>" in p for g in want if not g.isdigit()), ))
        strings = list(dict.fromkeys([*own, *_SEED_STRINGS]))
        n_out = 0
        for p in cand_patterns:
            c = _re.compile(p)
            if kind == "pattern":
                out.append({"param": a.arg, "value": {"__hlith_re_pattern__": {"pattern": p, "flags": 0}}, "exact": False,
                            "why": f"{a.arg} is used as a compiled pattern; compiled from a literal of the code"})
                n_out += 1
            else:
                for s in strings:
                    if len(s) > _RE_MAX_STRING:
                        continue
                    m = c.search(s)
                    if m is None:
                        continue
                    out.append({"param": a.arg, "value": {"__hlith_re_match__": {"pattern": p, "flags": 0, "string": s,
                                                                                   "mode": "search", "pos": 0}},
                                "exact": False, "why": f"{a.arg} is used as a match; real re.search of a code literal on {s!r}"})
                    n_out += 1
                    break  # one real string per pattern keeps the candidate list small and diverse
            if n_out >= _RE_MAX_CANDIDATES:
                break
        for u in unmodeled:
            out.append({"param": a.arg, "value": None, "exact": False, "unmodeled": u, "why": "pattern literal skipped"})
    return out


def materialise_re(desc: dict[str, Any]):
    """Build the REAL object a descriptor names. Raises ValueError for anything that is not exactly a bounded, compilable,
    really-matching descriptor; never evaluates the descriptor's text."""
    if not isinstance(desc, dict) or len(desc) != 1:
        raise ValueError("not a re descriptor")
    (key, body), = desc.items()
    if key not in ("__hlith_re_match__", "__hlith_re_pattern__") or not isinstance(body, dict):
        raise ValueError("not a re descriptor")
    p, flags = body.get("pattern"), body.get("flags", 0)
    if not isinstance(p, str) or not isinstance(flags, int) or isinstance(flags, bool) or flags < 0 or flags > 0xFFFF:
        raise ValueError("bad pattern or flags")
    why = _re_problem(p)
    if why:
        raise ValueError(why)
    c = _re.compile(p, flags)
    if key == "__hlith_re_pattern__":
        return c
    s, mode, pos = body.get("string"), body.get("mode", "search"), body.get("pos", 0)
    if not isinstance(s, str) or len(s) > _RE_MAX_STRING or mode not in ("match", "search", "fullmatch") or not isinstance(pos, int) \
            or not 0 <= pos <= len(s):
        raise ValueError("bad string, mode or pos")
    m = getattr(c, mode)(s, pos)
    if m is None:
        raise ValueError("the pattern does not match the string: no real match to build")
    return m
