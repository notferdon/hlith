# SPDX-License-Identifier: Apache-2.0
"""O3 preservation outside an approved delta: inputs derived from the delta and from the patch's OWN changed regions.

Why this exists. With a declared delta the question is not only "does the patch do what the delta says inside its
domain" but "does it leave everything outside the domain exactly as the baseline behaves", and neither can be answered
by whatever inputs the general pools happen to hold (a legitimate str delta on requests ``super_len`` was refused for want of 5 divergent inputs, and rare-class regressions next to it were only masked by that count, never reached). This module supplies the two missing mechanisms as plain, JSON-concrete call
inputs for ``differential.run_differential(seeds=...)``: it never decides a verdict and never relaxes a threshold.

1. DELTA DOMAIN follow-ups (GeMTest's source / follow-up lifecycle, source: GeMTest src/ metamorphic lifecycle): source inputs drawn from typed pools are split by the delta predicate into IN and OUT
   sets; predicate-preserving transforms of the IN sources give more IN follow-ups, and domain-crossing relatives of the SAME
   content (a str's bytes / list / tuple / None) give OUT follow-ups next to the boundary. The differential then checks the
   delta relation on the IN side (post == expected) and pre == post on the OUT side (the declared relation oracle).
2. CHANGED-REGION interventions (Bugbix's baseline / current intervention: behaviour outside the intended change must equal
   the baseline): the pre and post bodies are diffed statement by statement; for every added / changed / removed region
   the path guards that reach it are solved with a small closed evaluator (isinstance, len, comparisons, ``in``,
   startswith/endswith, folded constants such as ``1 << 10`` and ``chr(0x1F9FF)``, ``o = o.encode()`` style rebinding) to
   inputs that DO and DO NOT enter the region. Each region is classified against the delta predicate
   (inside / outside / unguarded) and is either EXERCISED (>= 1 input proven by the evaluator to enter it) or UNEXERCISED.
   An unexercised region outside the delta is reported so the caller can refuse: absence of evidence is never HELD.

Soundness boundaries, stated here and again in every report: the evaluator decides only its closed grammar (anything else is
"unknown" and never counts as exercised); candidate values come from finite pools around the constants of the code, so a
region is "exercised" when one concrete input provably enters it, which is not a proof that every input in it is checked;
nothing here reasons about loops, calls, mutation or exceptions inside a guard.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Any, Sequence

MAX_SEEDS = 320
MAX_SEED_BYTES = 32 * 1024
BYTES_TAG = "__hlith_bytes__"
_UNKNOWN = object()
_TYPES = {"str": str, "bytes": bytes, "int": int, "float": float, "bool": bool, "list": list, "tuple": tuple,
          "dict": dict, "NoneType": type(None)}

STR_POOL = ["", "a", "abc", "A b", " ", "\n", "é", "日本", "\U0001f600", "é", " ", "a\x00b",
            "é日\U0001f600", "‮", "ı", "x" * 1500]
INT_POOL = [-1, 0, 1, 2, 7, 255, 256, 1024]
# non-integer floats of BOTH signs: Python does not enforce an `int` annotation, and a float residue (n % 1) that appears only for a
# NEGATIVE fractional input is invisible to a Z3 proof over integers (review red team RT-2); the differential must be able to see it
OTHER_POOL: list[Any] = [None, True, False, [], [1], [1, 2], ["a", "b"], {}, {"a": 1}, {"a": 1, "b": 2}, 0.5, -0.5, 2.5]


# ------------------------------------------------------------------ closed evaluator (True / False / _UNKNOWN)

def _fold(n: ast.AST, env: dict) -> Any:
    """Value of a side-effect-free expression of the closed grammar over ``env``; _UNKNOWN outside it."""
    try:
        return _fold_inner(n, env, 0)
    except (TypeError, ValueError, OverflowError, IndexError, KeyError, UnicodeError, MemoryError, ZeroDivisionError,
            RecursionError):
        return _UNKNOWN


def _fold_inner(n: ast.AST, env: dict, depth: int) -> Any:
    if depth > 12:
        return _UNKNOWN
    f = lambda m: _fold_inner(m, env, depth + 1)  # noqa: E731
    if isinstance(n, ast.Constant):
        return n.value if isinstance(n.value, (str, bytes, int, float, bool, type(None))) else _UNKNOWN
    if isinstance(n, ast.Name):
        return env.get(n.id, _UNKNOWN)
    if isinstance(n, ast.UnaryOp):
        v = f(n.operand)
        if v is _UNKNOWN:
            return _UNKNOWN
        if isinstance(n.op, ast.Not):
            return not v
        if isinstance(n.op, ast.USub) and isinstance(v, (int, float)) and not isinstance(v, bool):
            return -v
        return _UNKNOWN
    if isinstance(n, ast.BinOp):
        a, b = f(n.left), f(n.right)
        if a is _UNKNOWN or b is _UNKNOWN:
            return _UNKNOWN
        ints = all(isinstance(x, int) and not isinstance(x, bool) for x in (a, b))
        if ints and isinstance(n.op, ast.LShift) and 0 <= b <= 64:
            return a << b
        if ints and isinstance(n.op, ast.Pow) and 0 <= b <= 64 and abs(a) <= 1 << 16:
            return a ** b
        if ints and isinstance(n.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)):
            if isinstance(n.op, (ast.FloorDiv, ast.Mod)) and b == 0:
                return _UNKNOWN
            return {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
                    ast.FloorDiv: lambda: a // b, ast.Mod: lambda: a % b}[type(n.op)]()
        if isinstance(n.op, ast.Add) and type(a) is type(b) and isinstance(a, (str, bytes)):
            return a + b
        return _UNKNOWN
    if isinstance(n, ast.BoolOp):
        vals = [f(v) for v in n.values]
        if isinstance(n.op, ast.And):
            if any(v is not _UNKNOWN and not v for v in vals):
                return False
            return _UNKNOWN if any(v is _UNKNOWN for v in vals) else True
        if any(v is not _UNKNOWN and v for v in vals):
            return True
        return _UNKNOWN if any(v is _UNKNOWN for v in vals) else False
    if isinstance(n, ast.IfExp):
        c = f(n.test)
        return _UNKNOWN if c is _UNKNOWN else f(n.body if c else n.orelse)
    if isinstance(n, ast.Compare):
        left = f(n.left)
        for op, right_n in zip(n.ops, n.comparators):
            right = f(right_n)
            if left is _UNKNOWN or right is _UNKNOWN:
                return _UNKNOWN
            try:
                ok = {ast.Eq: lambda: left == right, ast.NotEq: lambda: left != right, ast.Lt: lambda: left < right,
                      ast.LtE: lambda: left <= right, ast.Gt: lambda: left > right, ast.GtE: lambda: left >= right,
                      ast.In: lambda: left in right, ast.NotIn: lambda: left not in right,
                      ast.Is: lambda: left is right, ast.IsNot: lambda: left is not right}[type(op)]()
            except TypeError:
                return _UNKNOWN
            if not ok:
                return False
            left = right
        return True
    if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice) and n.slice.step is None:
        v = f(n.value)
        lo = f(n.slice.lower) if n.slice.lower is not None else None
        hi = f(n.slice.upper) if n.slice.upper is not None else None
        if v is _UNKNOWN or lo is _UNKNOWN or hi is _UNKNOWN or not isinstance(v, (str, bytes, list, tuple)):
            return _UNKNOWN
        return v[lo:hi]
    if isinstance(n, ast.Call) and not n.keywords:
        fn = n.func
        if isinstance(fn, ast.Name):
            if fn.id == "isinstance" and len(n.args) == 2:  # the type argument is a name of the closed table, never evaluated
                v0 = f(n.args[0])
                if v0 is _UNKNOWN:
                    return _UNKNOWN
                args = [v0, None]
            else:
                args = [f(a) for a in n.args]
            if any(a is _UNKNOWN for a in args):
                return _UNKNOWN
            if fn.id == "isinstance" and len(args) == 2:
                t = n.args[1]
                names = [t.id] if isinstance(t, ast.Name) else [e.id for e in getattr(t, "elts", []) if isinstance(e, ast.Name)]
                if not names or any(x not in _TYPES for x in names):
                    return _UNKNOWN
                return isinstance(args[0], tuple(_TYPES[x] for x in names))
            if fn.id == "len" and len(args) == 1 and isinstance(args[0], (str, bytes, list, tuple, dict)):
                return len(args[0])
            if fn.id == "chr" and len(args) == 1 and isinstance(args[0], int) and 0 <= args[0] <= 0x10FFFF:
                return chr(args[0])
            if fn.id == "ord" and len(args) == 1 and isinstance(args[0], str) and len(args[0]) == 1:
                return ord(args[0])
            if fn.id in ("bool", "int", "str") and len(args) == 1 and isinstance(args[0], (str, bytes, int, bool, type(None))):
                try:
                    return {"bool": bool, "int": int, "str": str}[fn.id](args[0])
                except (TypeError, ValueError):
                    return _UNKNOWN
            return _UNKNOWN
        if isinstance(fn, ast.Attribute):
            recv = f(fn.value)
            args = [f(a) for a in n.args]
            if recv is _UNKNOWN or any(a is _UNKNOWN for a in args):
                return _UNKNOWN
            m = fn.attr
            if isinstance(recv, str):
                if m == "encode" and (not args or args[0] in ("utf-8", "utf8")):
                    return recv.encode("utf-8")
                if m in ("startswith", "endswith") and len(args) == 1 and isinstance(args[0], str):
                    return getattr(recv, m)(args[0])
                if m in ("lower", "upper", "strip") and not args:
                    return getattr(recv, m)()
            if isinstance(recv, bytes):
                if m == "decode" and (not args or args[0] in ("utf-8", "utf8")):
                    return recv.decode("utf-8")
                if m in ("startswith", "endswith") and len(args) == 1 and isinstance(args[0], bytes):
                    return getattr(recv, m)(args[0])
        return _UNKNOWN
    return _UNKNOWN


def _truth(n: ast.AST, env: dict) -> bool | None:
    v = _fold(n, env)
    return None if v is _UNKNOWN else bool(v)


# ------------------------------------------------------------------ JSON-concrete seeds

def _jsonable(v: Any, allow_bytes: bool) -> Any:
    """The seed encoding of ``v`` or _UNKNOWN when it cannot be carried (bytes without the tag, huge values)."""
    if isinstance(v, bytes):
        return {BYTES_TAG: v.hex()} if allow_bytes and len(v) <= MAX_SEED_BYTES else _UNKNOWN
    if isinstance(v, tuple):
        items = [_jsonable(x, allow_bytes) for x in v]
        return _UNKNOWN if any(x is _UNKNOWN for x in items) else {"__hlith_tuple__": items}
    if isinstance(v, list):
        items = [_jsonable(x, allow_bytes) for x in v]
        return _UNKNOWN if any(x is _UNKNOWN for x in items) else items
    if isinstance(v, dict):
        return v if all(type(k) is str for k in v) and all(_jsonable(x, allow_bytes) is not _UNKNOWN for x in v.values()) else _UNKNOWN
    if isinstance(v, str) and len(v) > MAX_SEED_BYTES:
        return _UNKNOWN
    try:
        json.dumps(v)
    except (TypeError, ValueError):
        return _UNKNOWN
    return v


def _sized(length: int) -> list[Any]:
    """One value of each sized type with exactly ``length`` elements (bounded)."""
    if not 0 <= length <= MAX_SEED_BYTES:
        return []
    return ["a" * length, b"a" * length, ["a"] * min(length, 4096) if length <= 4096 else None,
            {f"k{i}": i for i in range(length)} if length <= 512 else None,
            tuple(range(length)) if length <= 512 else None]


def _consts(nodes: Sequence[ast.AST]) -> tuple[list[int], list[Any]]:
    ints: list[int] = []
    lits: list[Any] = []
    for root in nodes:
        for n in ast.walk(root):
            v = _fold(n, {}) if isinstance(n, (ast.BinOp, ast.UnaryOp, ast.Call, ast.Constant)) else _UNKNOWN
            if v is _UNKNOWN or isinstance(v, bool):
                continue
            if isinstance(v, int) and abs(v) <= MAX_SEED_BYTES:
                ints.append(v)
            elif isinstance(v, (str, bytes)) and 1 <= len(v) <= 64:
                lits.append(v)
    return sorted(set(ints)), list(dict.fromkeys(lits))


def candidate_values(nodes: Sequence[ast.AST], extra: Sequence[Any] = ()) -> list[Any]:
    """Finite candidate inputs built around the constants of ``nodes`` plus the typed base pools."""
    ints, lits = _consts(nodes)
    out: list[Any] = [*STR_POOL, *INT_POOL, *OTHER_POOL, *extra]
    for k in ints:
        out += [k - 1, k, k + 1]
        for d in (-1, 0, 1):
            out += _sized(k + d)
    # offsets: a guard such as ``"x" in name[3:]`` is entered only when the literal sits past the slice start, so prefixes of
    # 0, 1, 2 and of every small int constant (and one more) are tried, not just one pad character
    offs = sorted({0, 1, 2, *[c + d for c in ints if 0 < c <= 16 for d in (0, 1)]})
    for s in lits:
        pad = "a" if isinstance(s, str) else b"a"
        out += [s, pad + s, s + pad, pad + s + pad, [s], {s: 1}, (s,)]
        out += [pad * k + s + pad for k in offs if k > 1]
        if isinstance(s, str):
            out.append(s.encode("utf-8"))
        else:
            try:
                out.append(s.decode("utf-8"))
            except UnicodeDecodeError:
                pass
    seen, res = set(), []
    for v in out:
        if v is None and any(x is None for x in res):
            continue
        key = (type(v).__name__, repr(v))
        if key not in seen:
            seen.add(key)
            res.append(v)
    return res


# ------------------------------------------------------------------ (1) delta domain follow-ups

def _delta_predicate_holds(d: dict, param_names: Sequence[str], value: Any) -> bool | None:
    """Does ``value`` of the declared parameter satisfy the delta predicate? None = cannot say (literal inputs handled apart)."""
    pr = d.get("predicate")
    if not isinstance(pr, dict):
        return None
    if pr.get("type") == "expr":
        try:
            tree = ast.parse(pr["expr"], mode="eval").body
        except (SyntaxError, KeyError):
            return None
        return _truth(tree, {pr["param"]: value})
    if pr.get("type") == "typed":
        cls, v = pr.get("class"), value
        return {"empty_str": lambda: v == "" and isinstance(v, str), "none": lambda: v is None,
                "int_zero": lambda: v == 0 and not isinstance(v, bool) and isinstance(v, int),
                "int_neg": lambda: isinstance(v, int) and not isinstance(v, bool) and v < 0,
                "int_nonneg": lambda: isinstance(v, int) and not isinstance(v, bool) and v >= 0,
                "str_nonempty": lambda: isinstance(v, str) and len(v) > 0,
                "empty_container": lambda: isinstance(v, (dict, list, tuple, set)) and len(v) == 0,
                "bool": lambda: isinstance(v, bool)}.get(cls, lambda: None)()
    return None


_FOLLOW = (lambda s: s + "é", lambda s: "é" + s, lambda s: s + "\U0001f600", lambda s: s * 3,
           lambda s: s[:1], lambda s: s[1:], lambda s: " " + s, lambda s: s.upper())


def _param_backgrounds(source: str | None, qual: str | None, real: Sequence[str], target_param: str) -> list[dict[str, Any]]:
    """Up to 2 small representative value assignments for the OTHER parameters of a multi-parameter callable
    when a delta predicate constrains a single parameter ``target_param``."""
    ann_map: dict[str, str] = {}
    dflt_map: dict[str, Any] = {}
    if source and qual:
        try:
            fn = _find_def(ast.parse(source), qual)
        except SyntaxError:
            fn = None
        if fn is not None:
            pos = [*fn.args.posonlyargs, *fn.args.args]
            d_off = len(pos) - len(fn.args.defaults)
            for idx, arg in enumerate(pos):
                if arg.annotation is not None:
                    ann_map[arg.arg] = ast.unparse(arg.annotation).replace(" ", "")
                if idx >= d_off:
                    val = _fold(fn.args.defaults[idx - d_off], {})
                    if val is not _UNKNOWN:
                        dflt_map[arg.arg] = val
            for arg, dnode in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
                if arg.annotation is not None:
                    ann_map[arg.arg] = ast.unparse(arg.annotation).replace(" ", "")
                if dnode is not None:
                    val = _fold(dnode, {})
                    if val is not _UNKNOWN:
                        dflt_map[arg.arg] = val

    def choices(name: str) -> list[Any]:
        ann = ann_map.get(name, "")
        base = ann.split("[")[0].split("|")[0].split(".")[-1]
        out: list[Any] = []
        if name in dflt_map:
            out.append(dflt_map[name])
        if base == "str":
            out.extend(["hello", "x" * 20])
        elif base == "int":
            out.extend([1, 10])
        elif base == "float":
            out.extend([1.0, 2.5])
        elif base == "bool":
            out.extend([False, True])
        elif base in ("list", "Sequence", "Iterable"):
            out.extend([[1, 2], []])
        elif base in ("dict", "Mapping"):
            out.extend([{"a": 1}, {}])
        elif base == "bytes":
            out.extend([b"hello", b""])
        else:
            out.extend(["hello", 1])
        dedup: list[Any] = []
        for v in out:
            if not any(v == x and type(v) is type(x) for x in dedup):
                dedup.append(v)
        return dedup[:2]

    others = [p for p in real if p != target_param]
    per = {p: choices(p) for p in others}
    bg0 = {p: per[p][0] for p in others}
    bg1 = {p: per[p][1 if len(per[p]) > 1 else 0] for p in others}
    return [bg0] if bg0 == bg1 else [bg0, bg1]


def domain_seeds(deltas: Sequence[dict], symbol: str, params: Sequence[str], *, allow_bytes: bool = False,
                 source: str | None = None, qual: str | None = None) -> tuple[list[tuple], list[str]]:
    """IN / OUT follow-up seeds for every machine-checkable expr / typed delta of ``symbol``: (seeds, notes).

    A seed is (args, kwargs, source). Single-parameter callables get direct positional seeds; multi-parameter
    callables whose delta predicate constrains one parameter get bounded seeds with fixed typed/default
    representatives for the remaining parameters (recorded in the notes)."""
    seeds: list[tuple] = []
    notes: list[str] = []
    real = [p for p in params if p not in ("self", "cls")]
    for d in deltas:
        if d.get("symbol") != symbol or not isinstance(d.get("predicate"), dict) or d["predicate"].get("type") not in ("expr", "typed"):
            continue
        pname = d["predicate"].get("param")
        if pname not in real:
            notes.append(f"delta {d['id']}: predicate parameter {pname!r} is not a parameter of {symbol}: no follow-ups")
            continue
        bgs: list[dict[str, Any]] | None = None
        if len(real) != 1:
            if not (source and qual):
                notes.append(f"delta {d['id']}: {symbol} has {len(real)} parameters; domain follow-ups are generated for one-parameter callables only")
                continue
            if d["predicate"]["type"] == "expr":
                try:
                    expr_tree = ast.parse(d["predicate"]["expr"], mode="eval")
                except SyntaxError:
                    notes.append(f"delta {d['id']}: predicate did not parse: no multi-parameter follow-ups")
                    continue
                other_refs = {n.id for n in ast.walk(expr_tree) if isinstance(n, ast.Name)} & (set(real) - {pname})
                if other_refs:
                    notes.append(f"delta {d['id']}: {symbol} predicate couples multiple parameters {sorted(other_refs | {pname})}; no domain follow-ups")
                    continue
            bgs = _param_backgrounds(source, qual, real, pname)
            notes.append(f"delta {d['id']}: {symbol} has {len(real)} parameters; domain follow-ups vary {pname} with {len(bgs)} fixed background(s) for remaining parameters")
        pool = candidate_values([ast.parse(d["predicate"]["expr"], mode="eval")] if d["predicate"]["type"] == "expr" else [])
        ins, outs = [], []
        for v in pool:
            h = _delta_predicate_holds(d, params, v)
            if h is True:
                ins.append(v)
            elif h is False:
                outs.append(v)
        # follow-ups of IN sources that stay IN (relation lifecycle: source -> follow-up, membership preserved)
        fol = []
        for v in ins:
            if isinstance(v, str):
                for t in _FOLLOW:
                    w = t(v)
                    if w != v and _delta_predicate_holds(d, params, w) is True:
                        fol.append(w)
        # domain-crossing relatives of the same content: the OUT neighbours of IN sources (baseline must be unchanged there)
        cross = []
        for v in ins[:40]:
            if isinstance(v, str):
                cross += [v.encode("utf-8"), [v], (v,), {"k": v}, list(v)[:8]]
        pick = list(dict.fromkeys(map(lambda x: (type(x).__name__, repr(x)), ins + fol)))
        tag_in = f"delta-follow:{d['id']}:in"
        tag_out = f"delta-follow:{d['id']}:out"
        skipped = 0
        for group, tag, vals in (("in", tag_in, ins + fol), ("out", tag_out, outs + cross)):
            seen = set()
            for v in vals:
                key = (type(v).__name__, repr(v))
                if key in seen:
                    continue
                seen.add(key)
                j = _jsonable(v, allow_bytes)
                if j is _UNKNOWN:
                    skipped += 1
                    continue
                if bgs is None:
                    seeds.append(([j], {}, tag))
                else:
                    for bg in bgs:
                        row = [_jsonable(j if p == pname else bg[p], allow_bytes) for p in real]
                        if any(x is _UNKNOWN for x in row):
                            skipped += 1
                            continue
                        seeds.append((row, {}, tag))
        if skipped:
            notes.append(f"delta {d['id']}: {skipped} follow-up value(s) (bytes or oversized) cannot be carried by this seed channel")
        del pick
    return seeds[:MAX_SEEDS], notes


# ------------------------------------------------------------------ (2) changed-region interventions

@dataclass
class Region:
    kind: str                     # added | changed | removed
    side: str                     # post | pre
    line: int
    source: str
    guards: list[str] = field(default_factory=list)   # path guard sources (conjunction)
    inside_delta: bool | None = None  # every satisfying candidate satisfies the delta predicate; None = no delta given
    outside_witness: str | None = None  # a candidate that enters the region and is OUTSIDE every delta predicate
    exercised: bool = False       # >= 1 input proven by the evaluator to enter the region
    unevaluable: bool = False     # a guard atom outside the closed grammar
    n_entering: int = 0

    def summary(self) -> str:
        where = ("OUTSIDE the delta domain" if self.outside_witness is not None else
                 "inside the delta domain" if self.inside_delta else "delta domain unknown")
        g = " AND ".join(self.guards) if self.guards else "(unguarded: every input)"
        ex = f"exercised by {self.n_entering} derived input(s)" if self.exercised else "NOT exercised by any derived input"
        return f"{self.kind} region {self.side}:{self.line} `{self.source[:80]}` guarded by {g}: {where}; {ex}"


@dataclass
class RegionPlan:
    regions: list[Region]
    seeds: list[tuple]
    notes: list[str]
    analysed: bool = True   # False: the callable shape is outside what this module derives inputs for; nothing is claimed

    @property
    def unexercised_outside(self) -> list[Region]:
        """Regions that can run for inputs OUTSIDE the delta (or for all inputs) and that no derived input provably enters."""
        return [r for r in self.regions if self.analysed and not r.exercised and r.inside_delta is not True]


def _find_def(tree: ast.Module, qual: str) -> ast.AST | None:
    node: ast.AST = tree
    for part in qual.split("."):
        nxt = None
        for c in getattr(node, "body", []):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and c.name == part:
                nxt = c
                break
        if nxt is None:
            return None
        node = nxt
    return node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else None


def _dump(s: ast.AST) -> str:
    return ast.dump(s, include_attributes=False)


def _negate_guard(test: ast.AST) -> ast.AST:
    """Return a clean AST negation of ``test``, unwrapping a double negation."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand
    return ast.UnaryOp(op=ast.Not(), operand=test)


def _terminates_block(stmts: Sequence[ast.stmt]) -> bool:
    """True when ``stmts`` always ends by returning or raising."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If) and last.orelse:
        return _terminates_block(last.body) and _terminates_block(last.orelse)
    return False


_CLOSED_GUARD_CALLS = frozenset({"isinstance", "len", "chr", "ord", "bool", "int", "str"})
_CLOSED_GUARD_METHODS = frozenset({"encode", "decode", "startswith", "endswith", "lower", "upper", "strip"})


def _is_closed_guard(node: ast.AST) -> bool:
    """True when ``node`` uses only AST constructs handled by ``_fold_inner``."""
    for n in ast.walk(node):
        if isinstance(n, (ast.Constant, ast.Name, ast.UnaryOp, ast.BinOp, ast.BoolOp, ast.IfExp, ast.Compare,
                          ast.Slice, ast.Tuple, ast.Load, ast.expr_context, ast.operator, ast.unaryop,
                          ast.boolop, ast.cmpop)):
            continue
        if isinstance(n, ast.Subscript):
            if not isinstance(n.slice, ast.Slice) or n.slice.step is not None:
                return False
            continue
        if isinstance(n, ast.Call):
            if n.keywords:
                return False
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id in _CLOSED_GUARD_CALLS:
                continue
            if isinstance(fn, ast.Attribute) and fn.attr in _CLOSED_GUARD_METHODS:
                continue
            return False
        return False
    return True


def _conditional_guard(reason: str) -> ast.AST:
    """Placeholder guard outside the closed grammar so conditional runtime bodies stay unevaluable."""
    return ast.Call(func=ast.Name(id="__hlith_conditional__", ctx=ast.Load()), args=[ast.Constant(value=reason)], keywords=[])


def _for_entry_guard(node: ast.For | ast.AsyncFor) -> ast.AST:
    """Entry condition required for a loop body to execute at least one iteration."""
    if isinstance(node, ast.AsyncFor):
        return _conditional_guard("async_for")
    it = node.iter
    if isinstance(it, (ast.Tuple, ast.List, ast.Set)):
        return ast.Constant(value=bool(it.elts))
    if isinstance(it, ast.Dict):
        return ast.Constant(value=bool(it.keys))
    if isinstance(it, ast.Constant) and isinstance(it.value, (str, bytes)):
        return ast.Constant(value=bool(it.value))
    return ast.Compare(
        left=ast.Call(func=ast.Name(id="len", ctx=ast.Load()), args=[it], keywords=[]),
        ops=[ast.Gt()],
        comparators=[ast.Constant(value=0)],
    )


def _has_break(stmts: Sequence[ast.stmt]) -> bool:
    return any(isinstance(n, ast.Break) for s in stmts for n in ast.walk(s))


def _try_descend_compound(x: ast.stmt, y: ast.stmt, block_guards: list[tuple], block_prefix: list[ast.stmt],
                          out: list[tuple], src: str) -> bool:
    """Recurse into matching compound statements so nested edits preserve entry and enclosing path guards."""
    if type(x) is not type(y):
        return False
    if isinstance(x, ast.If) and isinstance(y, ast.If) and _dump(x.test) == _dump(y.test):
        _diff_block(x.body, y.body, block_guards + [(y.test, block_prefix)], block_prefix, out, src)
        _diff_block(x.orelse, y.orelse, block_guards + [(_negate_guard(y.test), block_prefix)], block_prefix, out, src)
        return True
    # Loop/context/exception headers reset straight-line prefix inside the body because state mutates across steps.
    if isinstance(x, ast.While) and isinstance(y, ast.While) and _dump(x.test) == _dump(y.test):
        _diff_block(x.body, y.body, block_guards + [(y.test, block_prefix)], [], out, src)
        else_guards = block_guards + ([(_conditional_guard("while_break"), ())] if _has_break(y.body)
                                      else [(_negate_guard(y.test), block_prefix)])
        _diff_block(x.orelse, y.orelse, else_guards, [], out, src)
        return True
    if isinstance(x, (ast.For, ast.AsyncFor)) and isinstance(y, (ast.For, ast.AsyncFor))\
            and _dump(x.target) == _dump(y.target) and _dump(x.iter) == _dump(y.iter):
        _diff_block(x.body, y.body, block_guards + [(_for_entry_guard(y), block_prefix)], [], out, src)
        else_guards = block_guards + ([(_conditional_guard("for_break"), ())] if _has_break(y.body) else [])
        _diff_block(x.orelse, y.orelse, else_guards, [], out, src)
        return True
    if isinstance(x, (ast.With, ast.AsyncWith)) and isinstance(y, (ast.With, ast.AsyncWith))\
            and [_dump(i) for i in x.items] == [_dump(i) for i in y.items]:
        _diff_block(x.body, y.body, block_guards, [], out, src)
        return True
    try_types = (ast.Try, getattr(ast, "TryStar", ast.Try))
    if isinstance(x, try_types) and isinstance(y, try_types):
        x_sigs = [(_dump(h.type) if h.type else None, h.name) for h in x.handlers]
        y_sigs = [(_dump(h.type) if h.type else None, h.name) for h in y.handlers]
        if x_sigs == y_sigs:
            _diff_block(x.body, y.body, block_guards, [], out, src)
            exc_guards = block_guards + [(_conditional_guard("except"), ())]
            for xh, yh in zip(x.handlers, y.handlers):
                _diff_block(xh.body, yh.body, exc_guards, [], out, src)
            _diff_block(x.orelse, y.orelse, block_guards + [(_conditional_guard("try_else"), ())], [], out, src)
            _diff_block(x.finalbody, y.finalbody, block_guards, [], out, src)
            return True
    return False


def _descend(stmt: ast.stmt, guards: list[tuple], prefix: list[ast.stmt], out: list[tuple]) -> None:
    """An ADDED ``if`` carries its own nested branches: each inner statement is a region with the enclosing tests as guards, so
    a rare branch inside an added hunk is solved on its own (review round 2, A4: a rare code point inside the str hunk)."""
    if not isinstance(stmt, ast.If):
        return
    for tests, body in ((guards + [(stmt.test, prefix)], stmt.body),
                        (guards + [(_negate_guard(stmt.test), prefix)], stmt.orelse)):
        for m, inner in enumerate(body):
            out.append(("added", "post", inner, tests, prefix + body[:m], None))
            _descend(inner, tests, prefix + body[:m], out)


def _diff_block(pre: list[ast.stmt], post: list[ast.stmt], guards: list[tuple], prefix: list[ast.stmt],
                out: list[tuple], src: str) -> None:
    """Collect (kind, side, stmt, guards, preceding statements, peer_stmt) for differing regions."""
    import difflib
    a, b = [_dump(s) for s in pre], [_dump(s) for s in post]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    early_guards: list[tuple] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        block_guards = [*guards, *early_guards]
        if tag == "equal":
            for off, s in enumerate(post[j1:j2]):
                if isinstance(s, ast.If) and not s.orelse and _terminates_block(s.body) and _is_closed_guard(s.test):
                    early_guards.append((_negate_guard(s.test), list(prefix + post[:j1 + off])))
            continue
        if tag == "replace" and i2 - i1 == j2 - j1:
            for x, y, k in zip(pre[i1:i2], post[j1:j2], range(j2 - j1)):
                block_prefix = prefix + post[:j1 + k]
                if _try_descend_compound(x, y, block_guards, block_prefix, out, src):
                    continue
                out.append(("changed", "post", y, block_guards, block_prefix, x))
                _descend(y, block_guards, block_prefix, out)
                out.append(("changed", "pre", x, block_guards, prefix + pre[:i1 + k], y))
            continue
        for s in post[j1:j2]:
            out.append(("added", "post", s, block_guards, prefix + post[:j1], None))
            _descend(s, block_guards, prefix + post[:j1], out)
        for s in pre[i1:i2]:
            out.append(("removed", "pre", s, block_guards, prefix + pre[:i1], None))


def _apply_prefix(prefix: list[ast.stmt], env: dict) -> dict:
    """Straight-line rebinding before a region: ``x = expr``, ``if C: x = expr``; anything else assigned becomes unknown."""
    env = dict(env)
    for s in prefix:
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
            env[s.targets[0].id] = _fold(s.value, env)
        elif isinstance(s, ast.If):
            t = _truth(s.test, env)
            branch = s.body if t is True else s.orelse if t is False else None
            names = {n.id for c in ast.walk(s) for n in ([c] if isinstance(c, ast.Name) and isinstance(c.ctx, ast.Store) else [])}
            if branch is not None and all(isinstance(x, (ast.Assign, ast.Pass)) for x in branch):
                env = _apply_prefix(branch, env)
            else:
                for nm in names:
                    env[nm] = _UNKNOWN
        else:
            for c in ast.walk(s):
                if isinstance(c, ast.Name) and isinstance(c.ctx, ast.Store):
                    env[c.id] = _UNKNOWN
    return env


def _region_diff_values(stmt: ast.AST, peer_stmt: ast.AST | None, conj: Sequence[tuple], fn_nodes: Sequence[ast.AST]) -> list[str]:
    """Targeted string inputs synthesized from differing region literals paired with delimiter/escape tokens."""
    stmt_strs = {n.value for n in ast.walk(stmt) if isinstance(n, ast.Constant) and isinstance(n.value, str) and 1 <= len(n.value) <= 24}
    if peer_stmt is not None:
        peer_strs = {n.value for n in ast.walk(peer_stmt)
                     if isinstance(n, ast.Constant) and isinstance(n.value, str) and 1 <= len(n.value) <= 24}
        diff_strs = sorted(stmt_strs ^ peer_strs)
    else:
        diff_strs = sorted(stmt_strs)
    if not diff_strs:
        return []
    diff_strs = sorted(diff_strs, key=lambda s: (not s.isprintable() or not s.isalnum(), len(s), s))
    wrappers: list[str] = []
    escapes: list[str] = []
    for root in (*[g[0] for g in conj], *fn_nodes):
        for n in ast.walk(root):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("startswith", "endswith")\
                    and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)\
                    and 1 <= len(n.args[0].value) <= 2 and n.args[0].value not in wrappers:
                wrappers.append(n.args[0].value)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) == 1\
                    and not n.value.isalnum() and not n.value.isspace() and n.value not in escapes:
                escapes.append(n.value)
    escapes = [e for e in escapes if e not in wrappers]
    out: list[str] = []
    for s in diff_strs[:16]:
        for w in wrappers[:4]:
            for e in escapes[:4]:
                out.append(w + e + s + w)
            out.append(w + s + w)
        for e in escapes[:4]:
            out.append(e + s)
        out.append(s)
    return list(dict.fromkeys(out))[:48]


def region_plan(pre_src: str, post_src: str, qual: str, params: Sequence[str], deltas: Sequence[dict] = (),
                *, symbol: str = "", allow_bytes: bool = False) -> RegionPlan:
    """Diff the pre/post definitions of ``qual`` and build seeds + classification for every changed region."""
    notes: list[str] = []
    try:
        pre_t, post_t = ast.parse(pre_src), ast.parse(post_src)
    except SyntaxError as e:
        return RegionPlan([], [], [f"region analysis skipped: source does not parse ({e.msg})"], analysed=False)
    pre_f, post_f = _find_def(pre_t, qual), _find_def(post_t, qual)
    if pre_f is None or post_f is None:
        return RegionPlan([], [], [f"region analysis skipped: {qual} not found as a function in both versions"], analysed=False)
    real = [p for p in params if p not in ("self", "cls")]
    pname = real[0] if len(real) == 1 else None
    if pname is None:
        notes.append(f"region analysis: {qual} has {len(real)} parameters; inputs are derived for one-parameter callables only")
    raw: list[tuple] = []
    _diff_block(pre_f.body, post_f.body, [], [], raw, post_src)
    mine = [d for d in deltas if d.get("symbol") == (symbol or qual) and isinstance(d.get("predicate"), dict)]
    regions: list[Region] = []
    seeds: list[tuple] = []
    for kind, side, stmt, guards, prefix, peer_stmt in raw[:40]:
        text = ast.get_source_segment(post_src if side == "post" else pre_src, stmt) or ast.unparse(stmt)
        r = Region(kind, side, getattr(stmt, "lineno", 0), " ".join(text.split()),
                   [ast.unparse(g[0]) for g in guards])
        own = [(stmt.test, prefix)] if isinstance(stmt, ast.If) else []
        conj = [*guards, *own]
        regions.append(r)
        if pname is None:
            r.unevaluable = True
            continue
        atoms = [*[g[0] for g in conj], *[s.value for s in prefix if isinstance(s, ast.Assign)], stmt]
        if peer_stmt is not None:
            atoms.append(peer_stmt)
        diff_vals = _region_diff_values(stmt, peer_stmt, conj, (pre_f, post_f))
        cands = candidate_values(atoms or [ast.Constant(value=0)], extra=diff_vals)
        entering, near, plausible = [], [], []
        diff_set = set(diff_vals)
        for v in cands:
            truths = [_truth(g, _apply_prefix(gp, {pname: v})) for g, gp in conj]  # each guard under the bindings at ITS position
            if all(t is True for t in truths):
                entering.append(v)
            elif any(t is None for t in truths):
                r.unevaluable = True
                if isinstance(v, str) and v in diff_set and all(t is not False for t in truths):
                    plausible.append(v)
            elif conj and sum(1 for t in truths if t is True) >= len(truths) - 1:
                near.append(v)  # fails exactly one conjunct: the neighbouring input just outside the region
        if not conj:
            entering = cands[:60]  # an unguarded region runs for every input
        else:
            entering_strs = {v for v in entering if isinstance(v, str)}
            entering = [*[v for v in diff_vals if v in entering_strs],
                        *[v for v in entering if not (isinstance(v, str) and v in diff_set)]]
        r.exercised = bool(entering)
        r.n_entering = len(entering)
        if mine:
            outside = [v for v in entering if all(_delta_predicate_holds(d, params, v) is False for d in mine)]
            any_in = [v for v in entering if any(_delta_predicate_holds(d, params, v) is True for d in mine)]
            unk = [v for v in entering if any(_delta_predicate_holds(d, params, v) is None for d in mine)]
            r.inside_delta = bool(entering) and not outside and not unk
            if outside:
                r.outside_witness = repr(outside[0])[:120]
            del any_in
        for group, vals in (("enter", [*plausible[:32], *entering[:24]]), ("near", near[:8])):
            for v in vals:
                j = _jsonable(v, allow_bytes)
                if j is not _UNKNOWN:
                    seeds.append(([j], {}, f"region-follow:{side}:{r.line}:{group}"))
    if any(r.unevaluable for r in regions):
        notes.append("some path guards use constructs outside the closed evaluator; regions behind them are never counted as exercised")
    seen, dedup = set(), []
    for a, k, s in seeds:
        key = (json.dumps(a, sort_keys=True, default=repr)[:4000], s)
        if key not in seen:
            seen.add(key)
            dedup.append((a, k, s))
    return RegionPlan(regions, dedup[:MAX_SEEDS], notes, analysed=pname is not None)


STR_DOMAIN_NOTE = ("lone surrogates (U+D800..U+DFFF) and str subclasses are not explored: code that encodes or decodes a str may behave "
                   "differently on them (e.g. UnicodeEncodeError when a lone surrogate is encoded to UTF-8); the approved delta says nothing about them")


def str_domain_note(deltas: Sequence[dict]) -> str | None:
    """STR_DOMAIN_NOTE when any declared delta concerns str values (expr/typed predicate over a str, or literal str inputs).
    Surrogates stay OUT of the probe pools by design (design policy 2026-11-15) so a landing must name them, never imply them covered."""
    for d in deltas:
        pr = d.get("predicate")
        if not isinstance(pr, dict):
            continue
        if pr.get("type") == "literal_inputs":
            if any(isinstance(v, str) for c in pr.get("inputs", ()) for v in [*c.get("args", ()), *c.get("kwargs", {}).values()]):
                return STR_DOMAIN_NOTE
        elif any(isinstance(v, str) and _delta_predicate_holds(d, (), v) is True for v in STR_POOL):
            return STR_DOMAIN_NOTE
    return None


def account_text(plan: RegionPlan, domain_notes: Sequence[str], n_domain_seeds: int, deltas: Sequence[dict] = ()) -> tuple[str, str]:
    """(explored, unexplored) sentences for the differential obligation's evidence: what was derived and what was not."""
    done = [r.summary() for r in plan.regions if r.exercised]
    undone = [r.summary() for r in plan.regions if not r.exercised]
    explored = (f"delta follow-ups: {n_domain_seeds} domain seed(s) (IN, predicate-preserving transforms; OUT, boundary-crossing relatives); "
                f"changed regions: {len(done)} exercised by derived inputs" + ("".join(f"; {x}" for x in done[:6])) + ".")
    sn = str_domain_note(deltas)
    unexplored = ("; ".join([*(f"UNEXERCISED {x}" for x in undone[:6]), *plan.notes, *domain_notes, *([sn] if sn else [])])
                  or "no changed region left unexercised; guards are decided only inside a closed evaluator and candidate pools are finite")
    return explored, unexplored


def blocker(plan: RegionPlan, symbol: str):
    """An UNVERIFIED obligation when a region that can run outside the delta is not provably entered by any derived input."""
    from ..types import Obligation, Verdict
    bad = plan.unexercised_outside
    if not bad:
        return None
    return Obligation(
        f"delta-region:{symbol}", symbol, "every changed region outside the approved delta is exercised", Verdict.UNVERIFIED,
        stop_reason=("preservation outside the approved delta is not established: " + "; ".join(r.summary() for r in bad[:4]))[:900])
