# SPDX-License-Identifier: Apache-2.0
"""Closed grammar for expression predicates on a single delta parameter.

This module is loaded by package import during capture and by file path inside
the confined differential evaluator. Keep validation here so both boundaries
accept and refuse the same predicate language.
"""

from __future__ import annotations

import ast


EXPR_TYPES = {
    "str": str,
    "bytes": bytes,
    "int": int,
    "float": float,
    "bool": bool,
    "dict": dict,
    "list": list,
    "tuple": tuple,
    "NoneType": type(None),
}
EXPR_MAX_DEPTH = 6
EXPR_MAX_NODES = 40
EXPR_MAX_LEN = 400


def validate_expr(param: str, expr: str) -> tuple[ast.AST | None, list[str]]:
    """Return the parsed tree and no errors only for the closed one-parameter grammar."""
    errs: list[str] = []
    if not isinstance(param, str) or not param.isidentifier():
        return None, ["expr predicate needs a parameter identifier"]
    if not isinstance(expr, str) or not 1 <= len(expr) <= EXPR_MAX_LEN or any(ord(c) < 32 for c in expr):
        return None, [f"expr must be 1..{EXPR_MAX_LEN} printable chars"]
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        return None, [f"expr syntax: {e.msg}"]
    nodes = list(ast.walk(tree))
    if len(nodes) > EXPR_MAX_NODES:
        errs.append(f"expr has {len(nodes)} nodes (max {EXPR_MAX_NODES})")

    def depth(n, d=0):
        kids = list(ast.iter_child_nodes(n))
        return d if not kids else max(depth(k, d + 1) for k in kids)

    if depth(tree) > EXPR_MAX_DEPTH + 3:  # +3: Expression/Compare/operand wrappers are not user nesting
        errs.append(f"expr nesting deeper than {EXPR_MAX_DEPTH}")

    def lit_ok(n) -> bool:
        if isinstance(n, ast.Constant):
            return n.value is None or isinstance(n.value, (str, int, bytes, bool)) and not isinstance(n.value, float)
        if isinstance(n, ast.Tuple):
            return all(isinstance(e, ast.Constant) and lit_ok(e) for e in n.elts) and len(n.elts) <= 20
        return False

    def is_param(n) -> bool:
        return isinstance(n, ast.Name) and n.id == param

    def operand(n) -> bool:
        if is_param(n) or lit_ok(n):
            return True
        if isinstance(n, ast.Call) and not n.keywords:
            f = n.func
            if isinstance(f, ast.Name) and f.id == "len" and len(n.args) == 1 and is_param(n.args[0]):
                return True
            if (isinstance(f, ast.Name) and f.id == "isinstance" and len(n.args) == 2 and is_param(n.args[0])
                    and isinstance(n.args[1], ast.Name) and n.args[1].id in EXPR_TYPES):
                return True
            if (isinstance(f, ast.Attribute) and f.attr in ("startswith", "endswith") and is_param(f.value)
                    and len(n.args) == 1 and lit_ok(n.args[0])):
                return True
            if (isinstance(f, ast.Attribute) and f.attr in ("lower", "upper") and is_param(f.value)
                    and not n.args):
                return True
        return False

    def boolexpr(n) -> bool:
        if isinstance(n, ast.BoolOp) and isinstance(n.op, (ast.And, ast.Or)):
            return all(boolexpr(v) for v in n.values)
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            return boolexpr(n.operand)
        if isinstance(n, ast.Compare):
            ok_ops = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot)
            if not all(isinstance(o, ok_ops) for o in n.ops):
                return False
            for o, rhs in zip(n.ops, n.comparators):
                if isinstance(o, (ast.Is, ast.IsNot)) and not (isinstance(rhs, ast.Constant) and rhs.value is None):
                    return False
            return operand(n.left) and all(operand(c) for c in n.comparators)
        return operand(n) and isinstance(n, ast.Call)  # bare isinstance(...)/startswith(...) as a condition

    if not boolexpr(tree.body):
        errs.append("expr outside the closed grammar (and/or/not, comparisons, len(p), isinstance(p, T), "
                    "p.startswith/endswith(lit), p.lower()/upper(), literals)")
    if not any(is_param(n) for n in nodes):
        errs.append("expr does not mention its parameter")
    return (tree if not errs else None), errs
