# SPDX-License-Identifier: Apache-2.0
"""Source facts read from a SEALED tree (read-only). L3 derives HOW to check from sources; the account says WHAT changed.

Everything here is a pure function of file bytes. A thing that cannot be located or parsed returns None and the caller
turns that into a NAMED unknown: never a guess, never a skip.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Located:
    rel: str  # path relative to the tree root
    node: ast.AST  # the FunctionDef / AsyncFunctionDef / ClassDef
    chain: tuple[str, ...]  # enclosing class / function names, outermost first (excludes the node's own name)


class TreeIndex:
    """Lazy, cached parse of one sealed tree."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._cache: dict[str, tuple[ast.Module, str] | None] = {}

    def exists(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def source(self, rel: str) -> str | None:
        p = self.root / rel
        try:
            return p.read_text(encoding="utf-8") if p.is_file() else None
        except (OSError, UnicodeDecodeError):
            return None

    def parse(self, rel: str) -> tuple[ast.Module, str] | None:
        if rel not in self._cache:
            src = self.source(rel)
            try:
                self._cache[rel] = (ast.parse(src), src) if src is not None else None
            except (SyntaxError, ValueError, RecursionError):
                self._cache[rel] = None
        return self._cache[rel]

    # ------------------------------------------------------------------ names
    @staticmethod
    def module_name(rel: str) -> str:
        from hlith.effect.api import module_name_for_path

        return module_name_for_path(rel)

    def candidate_files(self, module: str) -> list[str]:
        base = module.replace(".", "/")
        out = []
        for prefix in ("", "src/", "lib/"):
            for tail in (".py", "/__init__.py"):
                rel = f"{prefix}{base}{tail}"
                if self.exists(rel):
                    out.append(rel)
        return out

    def locate(self, qualified_name: str, hint_file: str | None = None) -> Located | None:
        """Find the def named by `pkg.mod.Class.method` (longest module prefix that is a file wins)."""
        parts = qualified_name.split(".")
        files: list[tuple[str, list[str]]] = []
        if hint_file and self.exists(hint_file):
            mod = self.module_name(hint_file)
            if qualified_name.startswith(mod + ".") or qualified_name == mod:
                files.append((hint_file, qualified_name[len(mod) + 1:].split(".") if qualified_name != mod else []))
        for k in range(len(parts) - 1, 0, -1):
            for rel in self.candidate_files(".".join(parts[:k])):
                files.append((rel, parts[k:]))
        for rel, rest in files:
            got = self.parse(rel)
            if got is None or not rest:
                continue
            node: ast.AST = got[0]
            chain: list[str] = []
            for i, name in enumerate(rest):
                nxt = None
                for child in getattr(node, "body", []):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == name:
                        nxt = child  # the LAST def wins, as at import time
                if nxt is None:
                    node = None  # type: ignore[assignment]
                    break
                if i < len(rest) - 1:
                    chain.append(name)
                node = nxt
            if node is not None and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return Located(rel, node, tuple(chain))
        return None

    def spans(self, rel: str) -> list[tuple[int, int, str, bool]]:
        """(start, end, qualified name, is_function) for every def/class, decorators included; cached per file."""
        key = "\0spans:" + rel
        if key in self._cache:
            return self._cache[key]  # type: ignore[return-value]
        out: list[tuple[int, int, str, bool]] = []
        got = self.parse(rel)
        if got is not None:
            mod = self.module_name(rel)

            def walk(node: ast.AST, trail: tuple[str, ...]) -> None:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        t = (*trail, child.name)
                        start = min([child.lineno, *[d.lineno for d in child.decorator_list]])
                        out.append((start, getattr(child, "end_lineno", child.lineno), ".".join([mod, *t]) if mod else ".".join(t),
                                    not isinstance(child, ast.ClassDef)))
                        walk(child, t)
                    else:
                        walk(child, trail)

            walk(got[0], ())
        self._cache[key] = out  # type: ignore[assignment]
        return out

    def enclosing(self, rel: str, line: int) -> str | None:
        """Qualified name of the innermost FUNCTION containing `line`, or None (module level / class body only)."""
        best: tuple[int, str] | None = None
        for start, end, name, is_fn in self.spans(rel):
            if is_fn and start <= line <= end and (best is None or start >= best[0]):
                best = (start, name)
        return best[1] if best else None


# ---------------------------------------------------------------------------- signatures / calls
def signature_text(fn: ast.AST) -> str | None:
    """`(self, a, /, b=1, *args, c, **kw)`: what z3_binding.parse_signature accepts."""
    a = getattr(fn, "args", None)
    if a is None:
        return None
    return "(" + ast.unparse(a) + ")"


def is_method(located: Located) -> bool:
    """A def directly inside a class and not a staticmethod: the first parameter is bound by the call."""
    if not located.chain or not isinstance(located.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    deco = {ast.unparse(d) for d in located.node.decorator_list}
    return "staticmethod" not in deco


def _literal_repr(node: ast.AST) -> str | None:
    try:
        return repr(ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def call_structure(call: ast.Call) -> dict:
    positional = 0
    literals: dict[str, str] = {}
    star_args = False
    for arg in call.args:
        if isinstance(arg, ast.Starred):
            star_args = True
            continue
        key = str(positional)
        positional += 1
        lit = _literal_repr(arg)
        if lit is not None:
            literals[key] = lit
    keywords: list[str] = []
    star_kwargs = False
    for kw in call.keywords:
        if kw.arg is None:
            star_kwargs = True
            continue
        keywords.append(kw.arg)
        lit = _literal_repr(kw.value)
        if lit is not None:
            literals[kw.arg] = lit
    return {"n_positional": positional, "keywords": keywords, "star_args": star_args, "star_kwargs": star_kwargs,
            "arg_literals": literals}


def calls_at(tree: ast.Module, line: int, names: set[str]) -> list[ast.Call]:
    """Call nodes starting on `line` whose callee's last name component is in `names`."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and n.lineno == line:
            f = n.func
            leaf = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if leaf in names:
                out.append(n)
    return out


# ---------------------------------------------------------------------------- entry guards
_CMP = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!="}


def guard_dict(cond_src: str, exc: str | None, params: set[str], line: int | None = None) -> dict | None:
    """Structured guard (z3_binding's vocabulary) from a guard's condition, or None when it is not expressible.

    Not expressible = unknown to the binding check; the caller records it as a named unknown (never as 'no guard')."""
    try:
        t = ast.parse(cond_src, mode="eval").body
    except SyntaxError:
        return None
    base = {"raised_exception": exc, "line": line}

    def name_of(n: ast.AST) -> str | None:
        return n.id if isinstance(n, ast.Name) and n.id in params else None

    if isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], ast.Is) and isinstance(t.comparators[0], ast.Constant) \
            and t.comparators[0].value is None and name_of(t.left):
        return {**base, "param": name_of(t.left), "raises_when": "none"}
    if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
        if name_of(t.operand):
            return {**base, "param": name_of(t.operand), "raises_when": "falsy"}
        c = t.operand
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "isinstance" and len(c.args) == 2 and name_of(c.args[0]):
            return {**base, "param": name_of(c.args[0]), "raises_when": "isinstance", "negated": True,
                    "type": _types_of(c.args[1])}
        return None
    if name_of(t):
        return {**base, "param": name_of(t), "raises_when": "truthy"}
    if isinstance(t, ast.Call) and isinstance(t.func, ast.Name) and t.func.id == "isinstance" and len(t.args) == 2 and name_of(t.args[0]):
        return {**base, "param": name_of(t.args[0]), "raises_when": "isinstance", "negated": False, "type": _types_of(t.args[1])}
    if isinstance(t, ast.Compare) and len(t.ops) == 1:
        op, left, right = t.ops[0], t.left, t.comparators[0]
        if type(op) in _CMP and name_of(left) and isinstance(right, ast.Constant) and isinstance(right.value, (int, str)) \
                and not isinstance(right.value, bool):
            if right.value in ("", 0) and isinstance(op, ast.Eq):
                return {**base, "param": name_of(left), "raises_when": "empty" if right.value == "" else "compare",
                        **({} if right.value == "" else {"operator": "==", "literal": repr(right.value)})}
            return {**base, "param": name_of(left), "raises_when": "compare", "operator": _CMP[type(op)], "literal": repr(right.value)}
        if isinstance(op, ast.In) and isinstance(left, ast.Constant) and isinstance(left.value, str) and name_of(right):
            return {**base, "param": name_of(right), "raises_when": "contains_literal", "literal": left.value}
    return None


def _types_of(node: ast.AST) -> list[str]:
    items = node.elts if isinstance(node, ast.Tuple) else [node]
    out = []
    for i in items:
        s = ast.unparse(i)
        out.append(s if "." in s else f"builtins.{s}")
    return out


# ---------------------------------------------------------------------------- AST-faithful source slices
# Vendored from the L2 source helper so L3 has no import edge into L2 internals (layer map: obligation -> effect.api only).
_AST_LINE_BREAKS = re.compile(r"(?<=\n)|(?<=\r)(?!\n)")


def ast_source_lines(source: str) -> list[str]:
    """Split only on LF, CRLF, or CR, the line endings counted by the parser."""
    return _AST_LINE_BREAKS.split(source)


def source_segment_from_lines(source_line_bytes: list[bytes], node: ast.AST) -> str | None:
    line_number = getattr(node, "lineno", None)
    end_line_number = getattr(node, "end_lineno", None)
    start_column = getattr(node, "col_offset", None)
    end_column = getattr(node, "end_col_offset", None)
    if (line_number is None or end_line_number is None or start_column is None or end_column is None
            or line_number < 1 or end_line_number > len(source_line_bytes)):
        return None
    first = source_line_bytes[line_number - 1][start_column:]
    last = source_line_bytes[end_line_number - 1][:end_column]
    if line_number == end_line_number:
        return source_line_bytes[line_number - 1][start_column:end_column].decode("utf-8")
    middle = source_line_bytes[line_number:end_line_number - 1]
    return b"".join([first, *middle, last]).decode("utf-8")


def ast_source_segment(source: str, node: ast.AST) -> str | None:
    """Return a source span using AST UTF-8 byte columns and parser line numbers."""
    lines = [line.encode("utf-8") for line in ast_source_lines(source)]
    return source_segment_from_lines(lines, node)
