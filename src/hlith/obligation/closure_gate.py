# SPDX-License-Identifier: Apache-2.0
"""Restrict-only closed-world conditions on EVERY positive certificate. Three rules, all fail closed:

- ONE WALKER (`walk`): the only tree enumeration the certificate provers use. Nothing is skipped by directory name; a file that cannot be read, parsed or
  attributed to source is a refusal, never silence. The single exception is `.git` (version-control metadata).
- INERT IMPORT CLOSURE: every module that importing the target can execute (the target, its ancestor packages, and transitively every import that can resolve
  inside the tree, in both versions) may only contain statements from a short allowlist.
- REFLECTION BAN: no file of that closure may spell a way to reach or rewrite a namespace or a function object. (case: over the import closure ONLY, a relaxation
  of the earlier tree-wide ban: a file the target does not import is not examined by this rule. The binding gate still reads every file of the scanned tree for
  writes that name what the proof reads.)

Assumed and NOT established here: third-party and standard-library code, files the checked tree does not contain (untracked or ignored files, installed
packages), what a caller or a test does to the module, and reflection reached through objects none of these spellings name."""

from __future__ import annotations

import ast
import os
import stat
import sys
from pathlib import Path

SCOPE = ("Assumes the target is imported in a fresh interpreter from the committed tree. Files outside the target's import closure (callers, tests, scripts, build helpers, "
         "plugins loaded by third-party code) are not checked for rebinding or mutating it.")
MAX_FILES = 3000
MAX_BYTES = 2_000_000
_FORBIDDEN_SUFFIXES = (".so", ".pyd", ".pyw", ".pth")
_STARTUP = ("sitecustomize.py", "usercustomize.py")


class TreeRefused(Exception):
    pass


class Tree:
    """`sources`: {relative posix path: bytes} for every .py file; `trees`: the same files parsed; `others`: {relative path: absolute Path} for every other entry."""

    def __init__(self):
        self.sources: dict = {}
        self.trees: dict = {}
        self.others: dict = {}


def walk(root) -> Tree:
    out, root = Tree(), Path(root)

    def fail(error):
        raise TreeRefused(f"a directory of the tree cannot be read ({type(error).__name__})")

    for dp, dns, fns in os.walk(str(root), onerror=fail):
        here = Path(dp)
        dns[:] = sorted(d for d in dns if d != ".git")
        for d in dns:
            if (here / d).is_symlink():
                raise TreeRefused(f"symlinked directory {(here / d).relative_to(root).as_posix()}: its files cannot be attributed to the tree")
        for name in sorted(fns):
            path = here / name
            rel = path.relative_to(root).as_posix()
            if rel == ".git":
                continue
            low = name.lower()
            importable = low.endswith((".py", ".pyc", *_FORBIDDEN_SUFFIXES))
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) and importable:
                    raise TreeRefused(f"symlinked source or binary file {rel}")
                if low.endswith(_FORBIDDEN_SUFFIXES):
                    raise TreeRefused(f"{rel}: an extension module, path or window-script file cannot be read as source")
                if low.endswith(".pyc"):
                    if here.name != "__pycache__" or not (here.parent / (name.split(".")[0] + ".py")).is_file():
                        raise TreeRefused(f"{rel}: compiled file without its source")
                    continue
                if low in _STARTUP:
                    raise TreeRefused(f"{rel}: runs at interpreter start")
                if not low.endswith(".py"):
                    out.others[rel] = path
                    continue
                if not name.endswith(".py"):
                    raise TreeRefused(f"{rel}: unusual source suffix")
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                    raise TreeRefused(f"{rel}: not a regular source file within {MAX_BYTES} bytes")
                data = path.read_bytes()
                data.decode("utf-8")
                tree = ast.parse(data)
            except TreeRefused:
                raise
            except (OSError, SyntaxError, ValueError, RecursionError) as e:
                raise TreeRefused(f"{rel}: cannot be read as source ({type(e).__name__})") from None
            out.sources[rel], out.trees[rel] = data, tree
            if len(out.sources) > MAX_FILES:
                raise TreeRefused(f"source tree has more than {MAX_FILES} Python files")
    return out


def is_test_path(rel: str) -> bool:
    *dirs, name = rel.split("/")
    return any(d in ("tests", "test") for d in dirs) or name.startswith("test_") or name == "conftest.py"


# ---------------------------------------------------------------------------------------------------------------- reflection ban

_ATTRS = frozenset({"__code__", "__defaults__", "__kwdefaults__", "__globals__", "__builtins__", "__dict__", "__setattr__", "__delattr__", "__getattribute__",
                    "__import__", "f_globals", "f_locals", "f_builtins", "f_back", "tb_frame", "gi_frame", "cr_frame", "ag_frame"})
_NAMES = frozenset({"__builtins__", "__dict__", "__import__"})
_CALLABLES = frozenset({"setattr", "delattr", "vars", "globals", "locals", "exec", "eval", "compile", "__import__", "attrgetter", "methodcaller", "getattr_static",
                        "monkeypatch", "MonkeyPatch"})
_MODULES = ("importlib", "gc", "ctypes", "_ctypes", "runpy", "imp", "_imp", "pkgutil", "mock", "unittest.mock")
_SYS = frozenset({"modules", "meta_path", "path_hooks", "path", "path_importer_cache", "_getframe", "_current_frames", "settrace", "setprofile"})
_INSPECT = frozenset({"currentframe", "stack", "trace", "getinnerframes", "getouterframes"})


def _aliases(tree, module: str) -> set:
    out: set = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {al.asname or module for al in n.names if al.name == module or (al.asname is None and al.name.startswith(module + "."))}
        elif isinstance(n, ast.ImportFrom):
            out |= {al.asname or al.name for al in n.names if al.name == module}
    return out


def _banned_module(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in _MODULES)


def reflection(tree) -> str:
    """The first spelling in `tree` that reaches or rewrites a namespace, a function object, the import system or a frame; '' when none."""
    sys_names, inspect_names = _aliases(tree, "sys"), _aliases(tree, "inspect")
    re_names = _aliases(tree, "re")
    getattr_calls: set = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)
                and n.args[1].value not in _ATTRS | _CALLABLES | _SYS | {"__class__"}):
            f = n.func
            if (isinstance(f, ast.Name) and f.id == "getattr") or (isinstance(f, ast.Attribute) and f.attr == "getattr"):
                getattr_calls.add(id(f))
    attribute_bases = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for n in ast.walk(tree):
        line = getattr(n, "lineno", 0)
        if isinstance(n, ast.Import):
            for al in n.names:
                if _banned_module(al.name):
                    return f"line {line}: import {al.name}"
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            for al in n.names:
                if (n.level == 0 and (_banned_module(mod) or _banned_module(f"{mod}.{al.name}"))) or al.name in _CALLABLES | _NAMES | {"getattr"}:
                    return f"line {line}: from {mod} import {al.name}"
                if (mod == "sys" and (al.name in _SYS or al.name == "*")) or (mod == "inspect" and al.name in _INSPECT):
                    return f"line {line}: from {mod} import {al.name}"
        elif isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Load) and n.id in sys_names | inspect_names and id(n) not in attribute_bases:
                return f"line {line}: {n.id} passed or aliased: what is reached through it cannot be followed"
            if n.id in _NAMES or n.id in _CALLABLES:
                return f"line {line}: {n.id}"
            if n.id == "getattr" and id(n) not in getattr_calls:
                return f"line {line}: getattr with a computed or restricted name"
        elif isinstance(n, ast.arg) and n.arg in ("monkeypatch", "mocker"):
            return f"line {line}: parameter {n.arg}"
        elif isinstance(n, ast.Attribute):
            base = n.value.id if isinstance(n.value, ast.Name) else None
            if n.attr in _ATTRS:
                return f"line {line}: .{n.attr}"
            if n.attr == "__class__" and isinstance(n.ctx, (ast.Store, ast.Del)):
                return f"line {line}: .__class__ store"
            if n.attr in _CALLABLES and not (n.attr == "compile" and base == "re" and "re" in re_names):
                return f"line {line}: .{n.attr}"
            if n.attr == "getattr" and id(n) not in getattr_calls:
                return f"line {line}: .getattr with a computed or restricted name"
            if n.attr in _SYS and base in sys_names:
                return f"line {line}: sys.{n.attr}"
            if n.attr == "sys":
                return f"line {line}: .sys: the sys module reached through another object"
            if n.attr in _INSPECT and base in inspect_names:
                return f"line {line}: inspect.{n.attr}"
    return ""


# ------------------------------------------------------------------------------------------------------------- inert statements

_QUIET_DUNDERS = frozenset({"__all__", "__version__", "__author__", "__doc__", "__license__", "__slots__"})
_ANN_BUILTINS = frozenset({"int", "float", "str", "bool", "bytes", "bytearray", "complex", "list", "dict", "tuple", "set", "frozenset", "object", "type",
                           "range", "memoryview"})
_ANN_MODULES = ("typing", "collections.abc")


def _dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _literal(v) -> bool:
    if isinstance(v, ast.Constant):
        return True
    if isinstance(v, (ast.Tuple, ast.List, ast.Set)):
        return all(_literal(x) for x in v.elts)
    if isinstance(v, ast.Dict):
        return all(k is not None and _literal(k) for k in v.keys) and all(_literal(x) for x in v.values)
    return isinstance(v, ast.UnaryOp) and isinstance(v.op, (ast.USub, ast.UAdd)) and isinstance(v.operand, ast.Constant) and type(v.operand.value) in (int, float, complex)


class _Module:
    def __init__(self, tree):
        self.future = any(isinstance(s, ast.ImportFrom) and s.module == "__future__" and any(a.name == "annotations" for a in s.names) for s in tree.body)
        self.stored = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
        self.stored |= {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        origins: dict = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for al in n.names:
                    origins.setdefault(al.asname or al.name.split(".")[0], set()).add(al.name if al.asname else al.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                for al in n.names:
                    origins.setdefault(al.asname or al.name, set()).add(("." * n.level) + (n.module or "") + ":" + al.name)
        self.origins = {k: next(iter(v)) for k, v in origins.items() if len(v) == 1 and k not in self.stored}

    def is_module(self, node, module: str) -> bool:
        return isinstance(node, ast.Name) and self.origins.get(node.id) == module

    def typing_name(self, node, name: str | None = None) -> bool:
        if isinstance(node, ast.Name):
            origin = self.origins.get(node.id, "")
            return any(origin.startswith(m + ":") and (name is None or origin == f"{m}:{name}") for m in _ANN_MODULES)
        return isinstance(node, ast.Attribute) and (name is None or node.attr == name) and any(self.is_module(node.value, m) for m in _ANN_MODULES)

    def annotation(self, a) -> bool:
        if a is None or self.future:
            return True
        if isinstance(a, ast.Constant):
            return a.value is None or a.value is Ellipsis or isinstance(a.value, str)
        if isinstance(a, ast.Name):
            return (a.id in _ANN_BUILTINS and a.id not in self.stored and a.id not in self.origins) or self.typing_name(a)
        if isinstance(a, ast.Attribute):
            return self.typing_name(a)
        if isinstance(a, ast.BinOp) and isinstance(a.op, ast.BitOr):
            return self.annotation(a.left) and self.annotation(a.right)
        if isinstance(a, (ast.Tuple, ast.List)):
            return all(self.annotation(x) for x in a.elts)
        return isinstance(a, ast.Subscript) and isinstance(a.value, (ast.Name, ast.Attribute)) and self.annotation(a.value) and self.annotation(a.slice)

    def value(self, v) -> bool:
        if _literal(v):
            return True
        if not isinstance(v, ast.Call) or v.keywords or len(v.args) > 1 or not all(_literal(x) for x in v.args):
            return False
        f = v.func
        if isinstance(f, ast.Attribute) and f.attr == "compile" and self.is_module(f.value, "re"):
            return len(v.args) == 1 and isinstance(v.args[0], ast.Constant) and isinstance(v.args[0].value, (str, bytes))
        return isinstance(f, ast.Name) and f.id == "frozenset" and "frozenset" not in self.stored and "frozenset" not in self.origins

    def main_guard(self, test) -> bool:
        return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__" and "__name__" not in self.stored
                and "__name__" not in self.origins and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == "__main__")

    def skipped_guard(self, st) -> bool:
        """An `if` whose body cannot run when the module is imported."""
        return isinstance(st, ast.If) and (self.typing_name(st.test, "TYPE_CHECKING") or self.main_guard(st.test))

    def statement(self, st, in_class: bool) -> str:
        """Why `st` is not on the inert allowlist, or ''."""
        bad = f"line {st.lineno}: "
        if isinstance(st, ast.Pass) or (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str)):
            return ""
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            for al in st.names:
                bound = al.asname or al.name.split(".")[0]
                if al.name == "*" or (_dunder(bound) and bound not in _QUIET_DUNDERS):
                    return bad + f"import binding {bound}"
            return ""
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = st.args
            params = [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]
            if st.decorator_list:
                return bad + f"decorator on {st.name}"
            if getattr(st, "type_params", None):
                return bad + f"type parameters on {st.name}"
            if not in_class and _dunder(st.name):
                return bad + f"module-level {st.name}"
            if not all(_literal(d) for d in [*a.defaults, *(d for d in a.kw_defaults if d is not None)]):
                return bad + f"a default of {st.name} is not a literal"
            if not all(self.annotation(p.annotation) for p in params if p is not None) or not self.annotation(st.returns):
                return bad + f"an annotation of {st.name} is not an inert builtin or typing expression"
            return ""
        if isinstance(st, ast.ClassDef):
            if st.decorator_list or st.bases or st.keywords or getattr(st, "type_params", None) or _dunder(st.name):
                return bad + f"class {st.name} has a decorator, base, keyword or type parameter"
            return next((why for why in (self.statement(s, True) for s in st.body) if why), "")
        if isinstance(st, (ast.Assign, ast.AnnAssign)):
            targets = st.targets if isinstance(st, ast.Assign) else [st.target]
            if not all(isinstance(t, ast.Name) for t in targets):
                return bad + "assignment to something other than a plain name"
            for t in targets:
                if t.id == "TYPE_CHECKING" or (_dunder(t.id) and t.id not in _QUIET_DUNDERS):
                    return bad + f"assignment to {t.id}"
            if isinstance(st, ast.AnnAssign) and not self.annotation(st.annotation):
                return bad + "annotation is not an inert builtin or typing expression"
            if st.value is not None and not self.value(st.value):
                return bad + "assigned value is not a literal, re.compile(literal) or frozenset(literal)"
            return ""
        if self.skipped_guard(st):
            return next((why for why in (self.statement(s, in_class) for s in st.orelse) if why), "")
        return bad + f"{type(st).__name__} statement runs at import"


def inert(tree) -> str:
    m = _Module(tree)
    return next((why for why in (m.statement(st, False) for st in tree.body) if why), "")


def _imports(tree) -> list:
    """Every import statement that can execute (function bodies included; the bodies of TYPE_CHECKING and __main__ guards excluded)."""
    m = _Module(tree)
    out: list = []
    todo = list(tree.body)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out.append(node)
        elif m.skipped_guard(node):
            todo.extend(node.orelse)
        else:
            todo.extend(ast.iter_child_nodes(node))
    return sorted(out, key=lambda n: (n.lineno, n.col_offset))


# --------------------------------------------------------------------------------------------------------------- import closure


class _Resolver:
    def __init__(self, files, import_root: str):
        self.files = set(files)
        self.dirs = {"/".join(f.split("/")[:i]) for f in self.files for i in range(1, f.count("/") + 1)}
        self.roots = {"", import_root.strip("/").removeprefix("."), "src"}

    @staticmethod
    def join(a: str, b: str) -> str:
        return f"{a}/{b}" if a else b

    def has(self, directory: str, name: str) -> bool:
        p = self.join(directory, name)
        return p + ".py" in self.files or p in self.dirs

    def step(self, directory: str, name: str) -> tuple:
        """(file executed by importing `name` under `directory`, the package directory or None)."""
        p = self.join(directory, name)
        module, package = p + ".py", p in self.dirs
        if module in self.files and package:
            raise TreeRefused(f"{p}: both a module and a directory: ambiguous")
        if module in self.files:
            return module, None
        if package and p + "/__init__.py" in self.files:
            return p + "/__init__.py", p
        if package:
            raise TreeRefused(f"{p}: namespace package (no __init__.py)")
        raise TreeRefused(f"{p}: an in-tree import does not resolve to a source file")

    def chain(self, directory: str, parts: list) -> tuple:
        found, package = [], directory
        for i, part in enumerate(parts):
            if package is None:
                raise TreeRefused(f"{'.'.join(parts[: i + 1])}: imported through a module that is not a package")
            file, package = self.step(package, part)
            found.append(file)
        return found, package

    def absolute(self, importer: str, parts: list) -> tuple:
        top = parts[0]
        if top in sys.builtin_module_names:
            return [], None
        near = importer.rsplit("/", 1)[0] if "/" in importer else ""
        places = (self.roots | {near}) if top in sys.stdlib_module_names else ({""} | self.dirs)
        hits = sorted(d for d in places if self.has(d, top))
        if not hits:
            return [], None  # outside the tree: third-party or standard library (assumed, see the module docstring)
        if len(hits) > 1:
            raise TreeRefused(f"`{top}` can resolve to more than one place in the tree ({', '.join(self.join(h, top) for h in hits[:3])})")
        return self.chain(hits[0], parts)

    def relative(self, importer: str, level: int, parts: list) -> tuple:
        up = importer.split("/")[:-1]
        if level - 1 >= len(up):
            raise TreeRefused(f"{importer}: relative import leaves the package")
        directory = "/".join(up[: len(up) - (level - 1)])
        if directory + "/__init__.py" not in self.files:
            raise TreeRefused(f"{directory}: namespace package (no __init__.py)")
        found, package = self.chain(directory, parts)
        return [directory + "/__init__.py", *found], package

    def targets(self, importer: str, node) -> list:
        out: list = []
        if isinstance(node, ast.Import):
            for al in node.names:
                out += self.absolute(importer, al.name.split("."))[0]
            return out
        parts = node.module.split(".") if node.module else []
        found, package = self.relative(importer, node.level, parts) if node.level else self.absolute(importer, parts)
        out += found
        if package is not None:
            for al in node.names:
                if al.name != "*" and self.has(package, al.name):
                    out.append(self.step(package, al.name)[0])
        return out


def closure(tree: Tree, import_root: str, module: str) -> list:
    """Relative paths of every in-tree file that importing `module` can execute."""
    resolver = _Resolver(tree.sources, import_root)
    base = import_root.strip("/")
    base = "" if base == "." else base
    start, _ = resolver.chain(base, module.split("."))
    seen: set = set()
    todo = list(start)
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        seen.add(rel)
        parts = rel.split("/")[:-1]
        for i in range(len(parts), 0, -1):  # packages above a resolved file run first
            init = "/".join(parts[:i]) + "/__init__.py"
            if init not in tree.sources:
                break
            todo.append(init)
        for node in _imports(tree.trees[rel]):
            todo.extend(resolver.targets(rel, node))
    return sorted(seen)


def refusal(base_root, post_root, import_root: str, module: str) -> str:
    """Why a positive certificate must be withheld for this pair of trees, or ''."""
    for side, root in (("base", base_root), ("post", post_root)):
        try:
            tree = walk(root)
            files = closure(tree, import_root, module)
            for rel in files:
                why = inert(tree.trees[rel])
                if why:
                    return f"{side} {rel} is imported with the target and is not inert ({why})"
            for rel in files:  # the import closure only (case); every file the target can execute, tests included if it imports one
                why = reflection(tree.trees[rel])
                if why:
                    return f"{side} {rel} can reach or rewrite a namespace or function ({why})"
        except TreeRefused as e:
            return f"{side}: {e}"
        except RecursionError:
            return f"{side}: analysis depth exceeded"
    return ""


def refusal_sources(base_src: str, post_src: str) -> str:
    """The same two rules for a comparison of two bare module sources (no tree, so imports cannot be followed: a relative import refuses)."""
    for side, source in (("base", base_src), ("post", post_src)):
        try:
            tree = ast.parse(source)
            if any(isinstance(n, ast.ImportFrom) and n.level for n in _imports(tree)):
                return f"{side}: a relative import cannot be resolved without a tree"
            why = inert(tree)
            if why:
                return f"{side} module is not inert at import ({why})"
            why = reflection(tree)
            if why:
                return f"{side} module can reach or rewrite a namespace or function ({why})"
        except (SyntaxError, ValueError, RecursionError) as e:
            return f"{side}: the module could not be analysed ({type(e).__name__})"
    return ""

