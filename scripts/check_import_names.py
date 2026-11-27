#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hard-failing import-NAME checker for src/hlith (design note; enforcement code, not a test).

Every ``from X import a, b`` inside ``src/hlith`` (module level AND inside functions/methods/branches; imports under
``if TYPE_CHECKING:`` are excluded) where X is an ``hlith`` module is resolved against X's ACTUAL top-level names, by
a pure ``ast`` scan (nothing is imported or executed):

  * module-level ``def``/``async def``/``class``, assignment / annotated-assignment / augmented targets (incl. tuple
    unpacking, ``for``/``with`` targets and walrus at module level, inside module-level ``if``/``try``/``with``/
    ``for``/``while`` blocks), ``global`` names assigned inside functions, ``import``/``from`` bindings (``as`` names);
  * ``from Y import *`` re-exports (Y's ``__all__`` when given, else its public names, recursively);
  * ``sys.modules[__name__] = _impl`` alias shims: the module's names ARE ``_impl``'s module names;
  * ``globals().update(...)`` / a module-level ``__getattr__`` / a ``sys.meta_path`` alias finder make the namespace
    OPEN: names of every hlith module the file imports are accepted, and for ``__getattr__``/meta-path any name is
    accepted (reported as "open namespace" in --verbose);
  * ``from pkg import sub`` is resolved when ``pkg.sub`` is a module.

Unresolved names FAIL (exit 1) unless listed in ``scripts/layer_map.json`` ``known_unresolved_names`` (migration
only; ids are "file:line:module:name"). The remaining baseline is printed so zero is the visible target; entries that
no longer occur are reported as stale and FAIL (exit 1). Exit 2 = the map or a source file cannot be read/parsed.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def discover(src: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for f in sorted((src / "hlith").rglob("*.py")):
        if "__pycache__" in f.parts:
            continue
        parts = list(f.relative_to(src).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        out[".".join(parts)] = f
    return out


def _resolve(mod: str, is_pkg: bool, level: int, name: str | None) -> str:
    parts = mod.split(".") if is_pkg else mod.split(".")[:-1]
    if level > 1:
        parts = parts[: len(parts) - (level - 1)]
    base = ".".join(parts)
    return f"{base}.{name}" if name else base


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [n for e in node.elts for n in _targets(e)]
    if isinstance(node, ast.Starred):
        return _targets(node.value)
    return []


class Index:
    def __init__(self, src: Path) -> None:
        self.src = src
        self.files = discover(src)
        self.trees: dict[str, ast.Module] = {}
        self.errors: list[str] = []
        for mod, f in self.files.items():
            try:
                self.trees[mod] = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            except (OSError, SyntaxError, UnicodeDecodeError) as e:
                self.errors.append(f"{f.relative_to(src)}: cannot parse: {e}")

    def is_pkg(self, mod: str) -> bool:
        return self.files[mod].name == "__init__.py"

    @lru_cache(maxsize=None)
    def names(self, mod: str, _depth: int = 0) -> tuple[frozenset[str], bool]:
        """(top-level names, open namespace)."""
        tree = self.trees.get(mod)
        if tree is None or _depth > 20:
            return frozenset(), True
        names: set[str] = set()
        is_open = False
        imported_hlith: list[str] = []
        alias_impl_names: dict[str, str] = {}  # local name -> module it is bound to (for sys.modules aliasing)

        def bind_import(node: ast.AST) -> None:
            nonlocal is_open
            if isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.asname or a.name.split(".")[0])
                    if a.name.startswith("hlith"):
                        imported_hlith.append(a.name)
                        if a.asname:
                            alias_impl_names[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom):
                base = _resolve(mod, self.is_pkg(mod), node.level, node.module) if node.level else (node.module or "")
                for a in node.names:
                    if a.name == "*":
                        if base in self.files:
                            sub, sub_open = self.star_names(base, _depth + 1)
                            names.update(sub)
                            is_open = is_open or sub_open
                        continue
                    local = a.asname or a.name
                    names.add(local)
                    if base.startswith("hlith"):
                        full = f"{base}.{a.name}"
                        if full in self.files:
                            imported_hlith.append(full)
                            alias_impl_names[local] = full
                        elif base in self.files:
                            imported_hlith.append(base)

        def walk(stmts: list[ast.stmt]) -> None:
            nonlocal is_open
            for st in stmts:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(st.name)
                    if st.name == "__getattr__" and not isinstance(st, ast.ClassDef):
                        is_open = True
                    if not isinstance(st, ast.ClassDef):
                        for g in ast.walk(st):  # `global X` + assignment inside a function defines a module name
                            if isinstance(g, ast.Global):
                                names.update(g.names)
                elif isinstance(st, (ast.Import, ast.ImportFrom)):
                    bind_import(st)
                elif isinstance(st, ast.Assign):
                    for t in st.targets:
                        names.update(_targets(t))
                        if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) and t.value.attr == "modules"
                                and isinstance(t.slice, ast.Name) and t.slice.id == "__name__" and isinstance(st.value, ast.Name)
                                and st.value.id in alias_impl_names):
                            impl = alias_impl_names[st.value.id]
                            if impl in self.files:
                                sub, sub_open = self.names(impl, _depth + 1)
                                names.update(sub)
                                is_open = is_open or sub_open
                elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
                    names.update(_targets(st.target))
                elif isinstance(st, ast.If):
                    walk(st.body)
                    walk(st.orelse)
                elif isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                    walk(st.body)
                    for h in st.handlers:
                        if h.name:
                            names.add(h.name)
                        walk(h.body)
                    walk(st.orelse)
                    walk(st.finalbody)
                elif isinstance(st, (ast.With, ast.AsyncWith)):
                    for it in st.items:
                        if it.optional_vars is not None:
                            names.update(_targets(it.optional_vars))
                    walk(st.body)
                elif isinstance(st, (ast.For, ast.AsyncFor)):
                    names.update(_targets(st.target))
                    walk(st.body)
                    walk(st.orelse)
                elif isinstance(st, ast.While):
                    walk(st.body)
                    walk(st.orelse)
                elif isinstance(st, ast.Expr):
                    c = st.value
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "update" and \
                            isinstance(c.func.value, ast.Call) and isinstance(c.func.value.func, ast.Name) and c.func.value.func.id == "globals":
                        is_open = True
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in ("insert", "append") and \
                            isinstance(c.func.value, ast.Attribute) and c.func.value.attr == "meta_path":
                        is_open = True
                for n in ast.walk(st) if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else ():
                    if isinstance(n, ast.NamedExpr):
                        names.update(_targets(n.target))

        walk(tree.body)
        if is_open:  # a dynamic namespace (globals().update / __getattr__ / meta-path): accept the names of what it imports
            for m in imported_hlith:
                if m in self.files and m != mod:
                    sub, _ = self.names(m, _depth + 1)
                    names.update(sub)
        return frozenset(names), is_open

    def star_names(self, mod: str, depth: int) -> tuple[frozenset[str], bool]:
        tree = self.trees.get(mod)
        if tree is None:
            return frozenset(), True
        for st in tree.body:
            if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in st.targets):
                try:
                    return frozenset(ast.literal_eval(st.value)), False
                except ValueError:
                    break
        names, is_open = self.names(mod, depth)
        return frozenset(n for n in names if not n.startswith("_")), is_open

    def accepts(self, mod: str, name: str) -> bool:
        if f"{mod}.{name}" in self.files:
            return True
        names, is_open = self.names(mod)
        if name in names:
            return True
        tree = self.trees.get(mod)
        # __getattr__ / meta-path: any attribute may resolve at run time
        if tree is not None and any(isinstance(s, ast.FunctionDef) and s.name == "__getattr__" for s in tree.body):
            return True
        return False


def findings(idx: Index) -> list[str]:
    out: list[str] = []
    for mod, tree in idx.trees.items():
        rel = str(idx.files[mod].relative_to(idx.src))
        skip: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _is_type_checking(node.test):
                for n in ast.walk(node):
                    skip.add(id(n))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or id(node) in skip:
                continue
            if node.level:
                base = _resolve(mod, idx.is_pkg(mod), node.level, node.module)
            elif node.module and (node.module == "hlith" or node.module.startswith("hlith.")):
                base = node.module
            else:
                continue
            if base not in idx.files:
                out.append(f"{rel}:{node.lineno}:{base}:<module> (module does not exist)")
                continue
            for a in node.names:
                if a.name != "*" and not idx.accepts(base, a.name):
                    out.append(f"{rel}:{node.lineno}:{base}:{a.name}")
    return sorted(set(out))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--map", type=Path, default=ROOT / "scripts" / "layer_map.json")
    ap.add_argument("--src", type=Path, default=ROOT / "src")
    ap.add_argument("--print-baseline", action="store_true")
    args = ap.parse_args(argv)
    try:
        base = set(json.loads(args.map.read_text()).get("known_unresolved_names", []))
    except (OSError, ValueError) as e:
        print(f"import-names: MAP ERROR: {e}", file=sys.stderr)
        return 2
    idx = Index(args.src)
    for e in idx.errors:
        print(f"PARSE-ERROR {e}")
    found = findings(idx)
    new = [f for f in found if f not in base]
    hits = [f for f in found if f in base]
    stale = sorted(base - set(found))
    for f in new:
        print(f"UNRESOLVED {f}")
    print(f"import-names: baseline remaining = {len(hits)} (target 0)")
    for f in hits:
        print(f"  baseline {f}")
    for f in stale:
        print(f"  stale baseline entry, remove from the map: {f}")
    if args.print_baseline:
        print(json.dumps(found, indent=2))
    if idx.errors:
        return 2
    if new or stale:
        # a stale baseline entry FAILS (case ratchet, as in check_layer_dag.py): the baseline only shrinks by editing it
        print(f"import-names: FAIL ({len(new)} unresolved names outside the baseline, {len(stale)} stale baseline entries)")
        return 1
    print("import-names: OK" + ("" if not hits else " (baseline not yet zero)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
