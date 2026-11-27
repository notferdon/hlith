# SPDX-License-Identifier: Apache-2.0
"""Tree- and source-level entry of the symbolic equivalence prover (hlith.obligation.symeq).

Combines two sound layers, both always invoked AFTER equiv_cert's structural module/import/header/
annotation/class-change checks:
  1. Fast exhaustive identity-partition cross-check (`identity-partitions/1`) for the pure
     identity/boolean control fragment (returns exact identity equivalence with 0 assumptions).
  2. Full hardened Z3 symbolic equivalence prover (`symeq.prove`):
     - Always tries `mode="any"` first (unconditional for all Python objects; also narrows
       explicit `if type(p) is not T:` runtime guards automatically).
     - When `strict_domain=False`, falls back to `mode="typed"` over identical exact-builtin
       annotations; equiv_cert then enforces the exact-builtin domain contract (subclass checks,
       full source+test call-site closure, hashed domain record, and operator claim text).
     - Refuses if non-Python sibling files changed and the proof performs opaque/world operations.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import tokenize
from pathlib import Path

from . import VERSION, Result, prove
from .tree import TreeTooLarge, import_time_delta, non_py_changed, py_files, tree_taint


class _Unsupported(ValueError):
    pass


def _expr(node, params, *, boolean=False):
    if isinstance(node, ast.Constant) and (node.value is None or type(node.value) is bool):
        if not boolean or type(node.value) is bool:
            return lambda args: node.value
    if not boolean and isinstance(node, ast.Name) and node.id in params:
        index = params.index(node.id)
        return lambda args: args[index]
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Is, ast.IsNot)):
        left, right = _expr(node.left, params), _expr(node.comparators[0], params)
        negate = isinstance(node.ops[0], ast.IsNot)
        return lambda args: (left(args) is right(args)) != negate
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _expr(node.operand, params, boolean=True)
        return lambda args: not operand(args)
    if isinstance(node, ast.BoolOp):
        operands = [_expr(value, params, boolean=True) for value in node.values]
        reduce = all if isinstance(node.op, ast.And) else any
        return lambda args: reduce(operand(args) for operand in operands)
    if isinstance(node, ast.IfExp):
        cond = _expr(node.test, params, boolean=True)
        yes = _expr(node.body, params, boolean=boolean)
        no = _expr(node.orelse, params, boolean=boolean)
        return lambda args: yes(args) if cond(args) else no(args)
    raise _Unsupported("outside the independently checked identity/boolean expression fragment")


def _branch(test, yes, no):
    return lambda args: yes(args) if test(args) else no(args)


def _block(body, params, continuation):
    for st in reversed(body):
        if isinstance(st, ast.Return):
            continuation = _expr(st.value, params) if st.value else lambda args: None
        elif isinstance(st, ast.If):
            continuation = _branch(_expr(st.test, params, boolean=True),
                                   _block(st.body, params, continuation),
                                   _block(st.orelse, params, continuation))
        else:
            raise _Unsupported("outside the independently checked if/return fragment")
    return continuation


def _program(src, function):
    tree = ast.parse(src)
    definitions = [st for st in tree.body if isinstance(st, ast.FunctionDef) and st.name == function]
    if len(definitions) != 1 or definitions[0].decorator_list:
        raise _Unsupported("a unique undecorated top-level function is required")
    fn = definitions[0]
    body = fn.body
    has_doc = ast.get_docstring(fn, clean=False) is not None
    fn.body = body[:1] if has_doc else []
    context = ast.dump(tree)
    args = fn.args
    params = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg or args.kwarg or len(params) > 4 or sum(1 for st in body for _ in ast.walk(st)) > 256:
        raise _Unsupported("identity proof exceeds the supported function signature or node budget")
    return context, params, _block(body[1:] if has_doc else body, params, lambda args: None)


def _digest(source):
    return hashlib.sha256(source.encode("utf-8", "surrogatepass")).hexdigest()


def _is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return any(p in ("tests", "test", "testing") for p in parts[:-1]) or parts[-1].startswith("test_") or parts[-1] in ("conftest.py",) or parts[-1].endswith("_test.py")


def _canon_domain_type(tstr: str) -> str:
    """Normalize symeq expanded domain strings to equiv_cert's canonical exact builtin type names."""
    if tstr == "int | bool":
        return "int"
    if tstr == "float | int":
        return "float"
    return tstr


def _try_identity_partition(base_src: str, post_src: str, function: str, *, module: str, budget_ms: int) -> dict | None:
    try:
        before, params, base = _program(base_src, function)
        after, _, post = _program(post_src, function)
        if before != after:
            return None
        representatives = (None, False, True, *(object() for _ in params))
        assignments = 0
        for inputs in itertools.product(representatives, repeat=len(params)):
            if base(inputs) is not post(inputs):
                return None
            assignments += 1
        proof = prove(base_src, post_src, function, modes=("any",), budget_ms=min(budget_ms, 10000))
        if not proof.ok:
            return None
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        return None
    record = {"kind": "symeq", "prover": VERSION, "mode": "any", "function": f"{module}.{function}",
              "cross_check": "identity-partitions/1", "assignments": assignments,
              "base_source_sha256": _digest(base_src), "post_source_sha256": _digest(post_src),
              "stats": proof.stats}
    return {
        "ok": True,
        "reason": "",
        "detail": f"symbolic paths agree and all {assignments} representative identity assignments return the same object",
        "mode": "any",
        "domain": (),
        "domain_text": "holds for all argument types and aliases; the target uses only identity tests, boolean control and returns",
        "record": record,
        "sha256": _digest(json.dumps(record, sort_keys=True, separators=(",", ":"))),
        "hint": {},
        "notes": tuple(proof.notes),
        "used_world": bool(proof.stats.get("used_world", False)),
    }


_ENFORCED_DOMAIN_TYPES = frozenset({"str", "int", "bool", "float", "list[int]", "tuple[int, ...]"})


def _enforced_typed_params(base_src: str, post_src: str, function: str) -> set[str]:
    """Parameters annotated identically with an engine-enforced exact builtin type in both versions."""
    try:
        fb = next(n for n in ast.parse(base_src).body if isinstance(n, ast.FunctionDef) and n.name == function)
        fp = next(n for n in ast.parse(post_src).body if isinstance(n, ast.FunctionDef) and n.name == function)
    except (StopIteration, SyntaxError, ValueError):
        return set()
    ab = {p.arg: (ast.unparse(p.annotation) if p.annotation is not None else None) for p in [*fb.args.posonlyargs, *fb.args.args, *fb.args.kwonlyargs]}
    ap = {p.arg: (ast.unparse(p.annotation) if p.annotation is not None else None) for p in [*fp.args.posonlyargs, *fp.args.args, *fp.args.kwonlyargs]}
    return {k for k, v in ap.items() if v in _ENFORCED_DOMAIN_TYPES and ab.get(k) == v}


def _prove_general(base_src: str, post_src: str, function: str, *, module: str, strict_domain: bool,
                   tainted_extra=(), changed_files=(), non_py_diff=(), budget_ms: int = 20000) -> dict:
    out = {"ok": False, "reason": "", "detail": "", "mode": "", "domain": (), "domain_text": "",
           "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
    why = import_time_delta(base_src, post_src, function)
    if why:
        out["reason"] = why
        return out
    modes = ("any",) if strict_domain else ("any", "typed")
    enforced = _enforced_typed_params(base_src, post_src, function)
    res: Result = prove(base_src, post_src, function, tainted_extra=tainted_extra, modes=modes, budget_ms=budget_ms,
                        allowed_typed_params=enforced)
    out["mode"], out["notes"], out["hint"] = res.mode, tuple(res.notes), dict(res.hint)
    out["used_world"] = bool(res.stats.get("used_world", False))
    if not res.ok:
        out["reason"] = (f"the two versions differ in the symbolic model ({res.reason})" if res.status == "different" else res.reason) or "not proved"
        out["detail"] = res.status
        return out
    if non_py_diff and out["used_world"]:
        out["reason"] = f"non-Python file(s) changed ({', '.join(non_py_diff[:3])}) while the target performs opaque operations"
        return out
    dom = tuple((p, _canon_domain_type(t)) for p, t in res.domain)
    record = {"kind": "symeq", "prover": VERSION, "mode": res.mode, "function": f"{module}.{function}",
              "params": [[p, t] for p, t in dom],
              "base_source_sha256": _digest(base_src), "post_source_sha256": _digest(post_src),
              "changed_files": list(changed_files[:50]), "assumptions": list(res.notes), "stats": res.stats}
    out["ok"] = True
    out["domain"] = dom
    out["detail"] = f"symbolic equivalence proved ({res.mode}, {res.stats.get('exits_base', 0)}/{res.stats.get('exits_post', 0)} exits, {res.stats.get('queries', 0)} solver queries)"
    if not dom:
        out["domain_text"] = "holds for any argument: every symbolic execution path agrees in return value, exceptions and opaque operations"
        if res.notes:
            out["domain_text"] += "; assumes: " + "; ".join(res.notes)
    else:
        out["domain_text"] = ("holds for " + ", ".join(f"{p}: exact builtin {t}" for p, t in dom) +
                              " arguments only (enforced: the engine rejects a subclass input and no in-tree call site passes an in-tree class instance to it; "
                              "callers outside the tree that pass instances of subclasses that override methods, or other types, are outside this claim)")
        if res.notes:
            out["domain_text"] += "; assumes: " + "; ".join(res.notes)
    out["record"] = record
    out["sha256"] = _digest(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return out


def certify_sources(base_src, post_src, function, *, strict_domain=False, budget_ms=20000, module="m"):
    fast = _try_identity_partition(base_src, post_src, function, module=module, budget_ms=budget_ms)
    if fast is not None:
        return fast
    try:
        return _prove_general(base_src, post_src, function, module=module, strict_domain=bool(strict_domain), budget_ms=budget_ms)
    except (ValueError, SyntaxError, RecursionError, MemoryError) as exc:
        return {"ok": False, "reason": str(exc) or type(exc).__name__, "detail": "", "mode": "", "domain": (), "domain_text": "",
                "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}


def certify_tree(base_root, post_root, import_root, module, function, *, strict_domain=False, budget_ms=20000):
    """Read without importing the repository."""
    def locate(root):
        path = Path(root, import_root, *module.split("."))
        for candidate in (path.with_suffix(".py"), path / "__init__.py"):
            if candidate.is_file():
                return candidate
        raise OSError("target module missing")

    def read_src(path):
        with tokenize.open(path) as stream:
            return stream.read()

    try:
        fb, fp = locate(base_root), locate(post_root)
        base_src, post_src = read_src(fb), read_src(fp)
    except (OSError, UnicodeError, SyntaxError) as exc:
        return {"ok": False, "reason": f"target source unavailable: {exc}", "detail": "", "mode": "", "domain": (), "domain_text": "",
                "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}

    try:
        base_files, post_files = py_files(base_root), py_files(post_root)
        rel = str(fp.relative_to(post_root))
        tainted, changed = tree_taint(base_files, post_files, rel, function.split(".")[-1])
        if tainted is None:
            return {"ok": False, "reason": "a changed file of the tree does not parse", "detail": "", "mode": "", "domain": (), "domain_text": "",
                    "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
        for t in sorted(tainted):
            if t.startswith("*module:") and not _is_test_path(t[len("*module:"):]):
                return {"ok": False, "reason": f"import-time code of {t[len('*module:'):]} changes in the same patch", "detail": "", "mode": "", "domain": (), "domain_text": "",
                        "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
        non_py = non_py_changed(base_root, post_root)
        if non_py is None:
            return {"ok": False, "reason": "source tree too large to scan non-Python files", "detail": "", "mode": "", "domain": (), "domain_text": "",
                    "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
        fast = _try_identity_partition(base_src, post_src, function, module=module, budget_ms=budget_ms)
        if fast is not None:
            return fast
        extra = {t for t in tainted if not t.startswith("*")}
        return _prove_general(base_src, post_src, function, module=module, strict_domain=bool(strict_domain),
                              tainted_extra=extra, changed_files=changed, non_py_diff=non_py, budget_ms=budget_ms)
    except TreeTooLarge as exc:
        return {"ok": False, "reason": str(exc), "detail": "", "mode": "", "domain": (), "domain_text": "",
                "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return {"ok": False, "reason": str(exc) or type(exc).__name__, "detail": "", "mode": "", "domain": (), "domain_text": "",
                "record": {}, "sha256": "", "hint": {}, "notes": (), "used_world": False}
