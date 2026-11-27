# SPDX-License-Identifier: Apache-2.0
"""Independent detector for REMOVED or CHANGED entry guards (a precondition that vanished or shifted).

Pure ``ast`` over the base and post text of one callable, plus a Z3 proof for neutral rewrites.

An *entry guard* is a top-level ``if COND: raise EXC`` (also an ``elif`` link, and the inverted shape
``if OK: <body> else: raise EXC``, which is the guard ``not OK``). The leading run of guards (separated at most by
docstrings and pure local assignments) is the *prefix*; guards after any other statement are *late*.

Decision (anything not proved stays reported, i.e. blocking):
  * prefix guards are neutral iff the ordered (condition, exception) lists are identical, OR Z3 proves that for every
    input the prefix raises the same exception type (first true guard wins) before and after, with every condition
    in the decidable fragment (int/bool/str parameters per their annotations, comparisons, and/or/not, arithmetic,
    len, string tests; helper calls and unknown types are undecidable). This accepts reordering of independent
    guards, merging/splitting ``a or b``, De Morgan, constant folding, local aliasing and the inverted structure,
    and rejects dropped, widened/narrowed, retyped-exception guards and reordering across different exceptions.
  * a guard that MOVED between prefix and late (after a side effect) is a change;
  * late guards must match syntactically (multiset of condition AST and exception).
"""
from __future__ import annotations

import ast
import copy
from collections import Counter
from typing import Any

_MAX_SUBST_NODES = 500


def _locate(tree: ast.Module, func_path: str):
    parts = func_path.split(".")
    scope: list[ast.stmt] = tree.body
    for cls in parts[:-1]:
        nxt = next((n for n in scope if isinstance(n, ast.ClassDef) and n.name == cls), None)
        if nxt is None:
            return None
        scope = nxt.body
    return next((n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == parts[-1]), None)


def _exc_name(node: ast.AST) -> str | None:
    """Identity of the raised type: builtins are qualified, anything else by its source text."""
    import builtins

    e = node.exc if isinstance(node, ast.Raise) else None
    if isinstance(e, ast.Call):
        e = e.func
    if isinstance(e, ast.Name) and isinstance(getattr(builtins, e.id, None), type):
        return f"builtins.{e.id}"
    if isinstance(e, (ast.Name, ast.Attribute)):
        return f"name:{ast.unparse(e)}"
    return None


def _single_raise(body: list[ast.stmt]) -> bool:
    return len(body) == 1 and isinstance(body[0], ast.Raise)


def _guards_of_if(st: ast.If) -> tuple[list[dict[str, Any]], bool]:
    """Guards contributed by one top-level If (and its elif chain), and whether the If continues the function body
    (the inverted shape ``if OK: body else: raise``), which ends the prefix."""
    out: list[dict[str, Any]] = []
    cur: ast.stmt | None = st
    continues = False
    while isinstance(cur, ast.If):
        if _single_raise(cur.body):
            out.append({"line": cur.lineno, "node": cur.test, "exc": _exc_name(cur.body[0])})
        elif _single_raise(cur.orelse):  # if OK: <body> else: raise EXC  ==  guard `not OK` + body
            out.append({"line": cur.lineno, "node": ast.UnaryOp(op=ast.Not(), operand=cur.test), "exc": _exc_name(cur.orelse[0])})
            continues = True
            break
        nxt = cur.orelse
        cur = nxt[0] if len(nxt) == 1 and isinstance(nxt[0], ast.If) else None
    return out, continues


def _pure_local(st: ast.stmt) -> tuple[str, ast.expr] | None:
    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
        v = st.value
        if not any(isinstance(n, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.Lambda, ast.NamedExpr)) for n in ast.walk(v)):
            return st.targets[0].id, v
    return None


def _subst(node: ast.AST, env: dict[str, ast.expr]) -> ast.AST | None:
    """Substitute current pure-local bindings into ``node`` (returns None if too large or contains comprehensions)."""
    if not env:
        return node
    if any(isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)) for n in ast.walk(node)):
        return None

    class _Rewriter(ast.NodeTransformer):
        def visit_Name(self, n: ast.Name) -> ast.AST:
            if isinstance(n.ctx, ast.Load) and n.id in env:
                return ast.copy_location(copy.deepcopy(env[n.id]), n)
            return n

    out = _Rewriter().visit(copy.deepcopy(node))
    if sum(1 for _ in ast.walk(out)) > _MAX_SUBST_NODES:
        return None
    return out


def analyse(source: str, func_path: str) -> dict[str, Any] | None:
    """{'prefix': [guard], 'late': [guard], 'locals': {name: expr}}, or None when the callable cannot be read."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    fn = _locate(tree, func_path)
    if fn is None:
        return None
    prefix: list[dict[str, Any]] = []
    late: list[dict[str, Any]] = []
    locs: dict[str, ast.expr] = {}
    resolved_complete = True
    in_prefix = True
    for i, st in enumerate(fn.body):
        if in_prefix:
            if i == 0 and isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant) \
                    and isinstance(st.value.value, str):
                continue
            if isinstance(st, ast.If):
                gs, continues = _guards_of_if(st)
                if gs:
                    for g in gs:
                        res = _subst(g["node"], locs) if resolved_complete else None
                        if res is None:
                            resolved_complete = False
                        else:
                            g["resolved"] = res
                    prefix += gs
                    if continues:
                        in_prefix = False
                    continue
                in_prefix = False
            else:
                loc = _pure_local(st)
                if loc is not None:
                    val = _subst(loc[1], locs) if resolved_complete else None
                    if isinstance(val, ast.expr):
                        locs[loc[0]] = val
                    else:
                        resolved_complete = False
                        in_prefix = False
                    continue
                in_prefix = False
        if isinstance(st, ast.If):
            gs, _ = _guards_of_if(st)
            late += gs
    return {"prefix": prefix, "late": late, "locals": locs, "resolved_complete": resolved_complete, "fn": fn}


def entry_guards(source: str, func_path: str) -> list[dict[str, Any]] | None:
    """Every entry guard (prefix then late), or None when it cannot be located/parsed."""
    a = analyse(source, func_path)
    if a is None:
        return None
    return [{"line": g["line"], "cond": ast.unparse(g["node"]), "key": ast.dump(g["node"]), "exc": g["exc"]}
            for g in [*a["prefix"], *a["late"]]]


def _sig(g: dict[str, Any]) -> tuple[str, str | None]:
    return ast.dump(g["node"]), g["exc"]


def _resolved_sig(g: dict[str, Any]) -> tuple[str, str | None]:
    return ast.dump(g.get("resolved", g["node"])), g["exc"]


def prefix_equivalent(base_src: str, post_src: str, func_path: str, pre: dict[str, Any] | None = None,
                      post: dict[str, Any] | None = None) -> str | None:
    """None when proved neutral; else why not. Used only for the prefix guards."""
    pre = pre or analyse(base_src, func_path)
    post = post or analyse(post_src, func_path)
    if pre is None or post is None:
        return "callable not located"
    if (pre.get("resolved_complete", True) and post.get("resolved_complete", True)
            and [_resolved_sig(g) for g in pre["prefix"]] == [_resolved_sig(g) for g in post["prefix"]]):
        return None
    if not pre["prefix"] and not post["prefix"]:
        return None
    if not pre.get("resolved_complete", True) or not post.get("resolved_complete", True):
        return "local guard binding exceeded static substitution bound"
    try:
        import z3

        from .. import drive_inputs as di

        fn_pre, raw_pre, _l, _d = di._fn_params(base_src, func_path)
        fn_post, raw_post, _l2, _d2 = di._fn_params(post_src, func_path)
        if {k: v[0] for k, v in raw_pre.items()} != {k: v[0] for k, v in raw_post.items()}:
            return "parameter names/annotations changed"
        nodes = [g.get("resolved", g["node"]) for g in [*pre["prefix"], *post["prefix"]]]
        params = di._build_params(raw_pre, nodes, {})
        if any(p.kind in ("any", "float") for p in params.values()):
            return "a parameter has no decidable type (unannotated and not inferable, or float)"
        excs = sorted({g["exc"] or "?" for g in [*pre["prefix"], *post["prefix"]]})
        eid = {name: i + 1 for i, name in enumerate(excs)}
        side: list[Any] = []

        def outcome(side_info: dict[str, Any]):
            tr = di._Tr(params, {})
            res: Any = z3.IntVal(0)
            for g in reversed(side_info["prefix"]):
                res = z3.If(tr._bool(tr.term(g.get("resolved", g["node"]))), z3.IntVal(eid[g["exc"] or "?"]), res)
            side.extend(tr.side)
            return res

        a, b = outcome(pre), outcome(post)
        s = z3.Solver()
        s.set("rlimit", 3000 * 1000)  # deterministic work budget (1000 units per ms, as in drive_inputs)
        s.set("timeout", 3000 * 200)  # wall: a last-resort net only
        s.add(*side)
        s.add(a != b)
        r = s.check()
        if r == z3.unsat:
            return None
        if r == z3.sat:
            return "the prefix raises a different exception type on some input"
        return "solver undecided"
    except di.Unsupported as e:  # a condition outside the decidable fragment
        return f"undecidable guard condition: {e}"
    except Exception as e:  # noqa: BLE001 - a proof that cannot run proves nothing
        return f"proof unavailable: {type(e).__name__}"


_LAST_STOP: list[str] = [""]


def last_stop() -> str:
    """Why the last removed_entry_guards call answered None because of the sandbox (empty otherwise)."""
    return _LAST_STOP[0]


def removed_entry_guards(base_src: str, post_src: str, func_path: str) -> list[dict[str, Any]] | None:
    """``_removed_entry_guards_inproc`` answered by a forked, confined, resource-limited worker child: the repository
    source is parsed and Z3 runs there. A killed or failed call answers None (could not be decided: callers block) and
    ``last_stop()`` names why; it never answers "no guard removed"."""
    from .. import drive_inputs as di

    out = di.sandbox_call("guard_removed", {"base_src": base_src, "post_src": post_src, "func_path": func_path})
    if out.get("ok"):
        _LAST_STOP[0] = ""
        return out["result"]
    _LAST_STOP[0] = str(out.get("stop", "sandbox failed"))
    return None


def _removed_entry_guards_inproc(base_src: str, post_src: str, func_path: str) -> list[dict[str, Any]] | None:
    """Pre guards with no counterpart after the change (see module docstring). None = could not be decided."""
    pre, post = analyse(base_src, func_path), analyse(post_src, func_path)
    if pre is None or post is None:
        return None

    def rec(g: dict[str, Any], where: str) -> dict[str, Any]:
        return {"line": g["line"], "cond": ast.unparse(g["node"]), "key": ast.dump(g["node"]), "exc": g["exc"], "where": where}

    gone: list[dict[str, Any]] = []
    why = prefix_equivalent(base_src, post_src, func_path, pre, post)
    if why is not None:
        have = Counter(("prefix", *_sig(g)) for g in post["prefix"])
        for g in pre["prefix"]:
            k = ("prefix", *_sig(g))
            if have[k] > 0:
                have[k] -= 1
            else:
                gone.append(rec(g, "prefix"))
        if not gone and [_sig(g) for g in pre["prefix"]] != [_sig(g) for g in post["prefix"]] \
                and len({g["exc"] for g in pre["prefix"]}) > 1:
            first = pre["prefix"][0]
            gone.append({**rec(first, "prefix"), "cond": "<order of entry guards raising different exceptions changed>",
                         "exc": None})
    have_late = Counter(("late", *_sig(g)) for g in post["late"])
    for g in pre["late"]:
        k = ("late", *_sig(g))
        if have_late[k] > 0:
            have_late[k] -= 1
        else:
            gone.append(rec(g, "late"))
    return gone
