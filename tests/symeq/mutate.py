# SPDX-License-Identifier: Apache-2.0
"""AST mutators for the prover's soundness campaign: each yields single-site variants of one function. Most variants change behaviour; some are equivalent. The campaign never
assumes which: the concrete oracle decides, and the only failure is a PROVED pair the oracle can tell apart."""

from __future__ import annotations

import ast
import copy

_CMP = {ast.Lt: [ast.LtE, ast.Gt], ast.LtE: [ast.Lt, ast.GtE], ast.Gt: [ast.GtE, ast.Lt], ast.GtE: [ast.Gt, ast.LtE], ast.Eq: [ast.NotEq], ast.NotEq: [ast.Eq],
        ast.In: [ast.NotIn], ast.NotIn: [ast.In], ast.Is: [ast.IsNot], ast.IsNot: [ast.Is]}
_BIN = {ast.Add: [ast.Sub], ast.Sub: [ast.Add], ast.Mult: [ast.FloorDiv, ast.Add], ast.FloorDiv: [ast.Mod, ast.Mult], ast.Mod: [ast.FloorDiv], ast.BitOr: [ast.BitAnd],
        ast.BitAnd: [ast.BitOr]}
_METH = {"lower": ["upper", "casefold"], "upper": ["lower"], "strip": ["lstrip", "rstrip"], "lstrip": ["strip"], "rstrip": ["strip"], "startswith": ["endswith"],
         "endswith": ["startswith"], "find": ["rfind"], "rfind": ["find"], "split": ["rsplit", "splitlines"], "isdigit": ["isalpha", "isalnum"], "isalnum": ["isalpha"],
         "append": ["extend"], "keys": ["values"], "values": ["keys"], "get": ["pop"], "add": ["discard"], "index": ["count"], "count": ["index"], "title": ["capitalize"]}
_FUNC = {"min": ["max"], "max": ["min"], "any": ["all"], "all": ["any"], "sorted": ["list", "reversed"], "sum": ["len", "max"], "len": ["sum"], "abs": ["int"], "int": ["abs"],
         "list": ["sorted", "tuple"], "str": ["repr"], "repr": ["str"], "bool": ["int"], "enumerate": ["zip"], "tuple": ["list"], "set": ["list"]}


def _sites(fn):
    """(kind, node) for every mutable site of the function body, in a deterministic order."""
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare):
            for i in range(len(n.ops)):
                out.append(("cmp", n, i))
        elif isinstance(n, ast.BinOp) and type(n.op) in _BIN:
            out.append(("bin", n, 0))
            out.append(("binswap", n, 0))
        elif isinstance(n, ast.BoolOp):
            out.append(("bool", n, 0))
            if len(n.values) == 2:
                out.append(("boolswap", n, 0))
        elif isinstance(n, ast.Constant) and not isinstance(n.value, (bytes, complex)) and n.value is not Ellipsis:
            out.append(("const", n, 0))
            if isinstance(n.value, (int, str)) and not isinstance(n.value, bool):
                out.append(("const", n, 1))
        elif isinstance(n, ast.If):
            out.append(("negif", n, 0))
            if n.orelse:
                out.append(("swapif", n, 0))
        elif isinstance(n, ast.IfExp):
            out.append(("swapifexp", n, 0))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.append(("dropnot", n, 0))
        elif isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr in _METH:
                for i in range(len(_METH[f.attr])):
                    out.append(("meth", n, i))
            if isinstance(f, ast.Name) and f.id in _FUNC:
                for i in range(len(_FUNC[f.id])):
                    out.append(("func", n, i))
            if len(n.args) == 2 and not n.keywords:
                out.append(("argswap", n, 0))
        elif isinstance(n, ast.Return) and n.value is not None:
            out.append(("retnone", n, 0))
        elif isinstance(n, (ast.Break, ast.Continue)):
            out.append(("loopctl", n, 0))
        elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice):
            out.append(("slice", n, 0))
        elif isinstance(n, ast.AugAssign):
            out.append(("aug", n, 0))
        for field in ("body", "orelse", "finalbody"):
            body = getattr(n, field, None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                for i in range(len(body)):
                    if len(body) > 1 and not isinstance(body[i], (ast.FunctionDef, ast.ClassDef)):
                        out.append(("delstmt", n, (field, i)))
                    if i + 1 < len(body):
                        out.append(("swapstmt", n, (field, i)))
                    if isinstance(body[i], (ast.Assign, ast.AugAssign, ast.Expr)):
                        out.append(("dupstmt", n, (field, i)))
    return out


def _apply(kind, n, arg) -> bool:
    if kind == "cmp":
        alts = _CMP.get(type(n.ops[arg]))
        if not alts:
            return False
        n.ops[arg] = alts[0]()
    elif kind == "bin":
        n.op = _BIN[type(n.op)][0]()
    elif kind == "binswap":
        n.left, n.right = n.right, n.left
    elif kind == "bool":
        n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
    elif kind == "boolswap":
        n.values = [n.values[1], n.values[0]]
    elif kind == "const":
        v = n.value
        if isinstance(v, bool):
            n.value = not v
        elif isinstance(v, int):
            n.value = v + 1 if arg == 0 else v - 1
        elif isinstance(v, str):
            n.value = (v + "x") if arg == 0 else v[:-1] if v else " "
        elif isinstance(v, float):
            n.value = v + 1.0
        elif v is None:
            n.value = 0
        else:
            return False
    elif kind == "negif":
        n.test = ast.UnaryOp(op=ast.Not(), operand=n.test)
    elif kind == "swapif":
        n.body, n.orelse = n.orelse, n.body
    elif kind == "swapifexp":
        n.body, n.orelse = n.orelse, n.body
    elif kind == "dropnot":
        n.op = ast.UAdd()
        return False  # `+x` is not a faithful drop; handled by negif on the parent instead
    elif kind == "meth":
        n.func.attr = _METH[n.func.attr][arg]
    elif kind == "func":
        n.func.id = _FUNC[n.func.id][arg]
    elif kind == "argswap":
        n.args = [n.args[1], n.args[0]]
    elif kind == "retnone":
        n.value = ast.Constant(value=None)
    elif kind == "loopctl":
        return False
    elif kind == "slice":
        s = n.slice
        if s.lower is None and s.upper is None:
            return False
        if s.lower is not None:
            s.lower = ast.BinOp(left=s.lower, op=ast.Add(), right=ast.Constant(value=1))
        else:
            s.upper = ast.BinOp(left=s.upper, op=ast.Sub(), right=ast.Constant(value=1))
    elif kind == "aug":
        n.op = ast.Sub() if isinstance(n.op, ast.Add) else ast.Add()
    elif kind in ("delstmt", "swapstmt", "dupstmt"):
        field, i = arg
        body = getattr(n, field)
        if kind == "delstmt":
            del body[i]
        elif kind == "swapstmt":
            body[i], body[i + 1] = body[i + 1], body[i]
        else:
            body.insert(i, copy.deepcopy(body[i]))
    else:
        return False
    return True


def mutants(src: str, name: str, limit: int = 10 ** 9):
    """Yield (label, mutated module source) for single-site mutations of the function `name` (top level, or Class.method)."""
    tree = ast.parse(src)

    def find(t):
        parts = name.split(".")
        body = t.body
        node = None
        for p in parts:
            node = next((n for n in body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == p), None)
            if node is None:
                return None
            body = node.body
        return node

    fn = find(tree)
    if fn is None:
        return
    n_sites = len(_sites(fn))
    base_dump = ast.dump(tree)
    seen = {base_dump}
    count = 0
    for k in range(n_sites):
        t2 = copy.deepcopy(tree)
        f2 = find(t2)
        kind, node, arg = _sites(f2)[k]
        try:
            if not _apply(kind, node, arg):
                continue
            ast.fix_missing_locations(t2)
            out = ast.unparse(t2)
            compile(out, "<mutant>", "exec")
        except (SyntaxError, ValueError, TypeError, IndexError, AttributeError):
            continue
        d = ast.dump(ast.parse(out))
        if d in seen:
            continue
        seen.add(d)
        count += 1
        yield f"{kind}#{k}", out
        if count >= limit:
            return
