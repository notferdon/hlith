# SPDX-License-Identifier: Apache-2.0
"""Confined measured check for docstring-only diffs (import snapshot + importing repo tests)."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .. import differential
from ..sandbox import GrantError, Profile, raise_if_confinement_boundary, run_confined
from ..types import BoundedEvidence, CheckProvenance, Obligation, Verdict

CHECKER_ID = "hlith.docstring_check"
CHECKER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
_DOCSTRING_MEASURED = True
_MAX_IMPORTING_TEST_FILES = 8
_IMPORTING_TEST_TOTAL_BUDGET_S = 120.0
_MAX_LOCAL_CALL_DEPTH = 60
_UNEXPLORED_NOTE = (
    "docstring is observable by code or outputs not compared by the snapshot "
    "and importing tests (e.g. external callers or uncompared return values of runtime __doc__ reads)"
)

_IMPORT_RUNNER = r"""
import collections, functools, importlib, json, operator, os, re, sys, types
spec = json.load(open(sys.argv[1]))
sys.path[:0] = spec["sys_path"]
edited = {tuple(p) for p in spec["edited_paths"]}
proposer_readable = False
# Capture the interpreter's exact namedtuple field-descriptor type before importing
# the inspected module; that module may mutate public module attributes.
_TUPLEGETTER_TYPE = getattr(collections, "_tuplegetter", None)
for p in spec.get("proposer_paths", []):
    try:
        if os.path.exists(p):
            proposer_readable = True
    except OSError:
        pass

_MOD_DUNDERS = {
    "__name__", "__doc__", "__package__", "__loader__", "__spec__",
    "__file__", "__cached__", "__builtins__", "__path__",
}
_CLS_DUNDERS = {
    "__module__", "__doc__", "__dict__", "__weakref__", "__qualname__",
    "__annotations__", "__annotate_func__", "__type_params__",
    "__firstlineno__", "__static_attributes__", "__slots__", "_abc_impl",
}
opaque_paths = []

def _snap_slots(val, seen):
    slot_vals = []
    seen_slots = set()
    for cls in type(val).__mro__:
        raw_slots = cls.__dict__.get("__slots__")
        if raw_slots is None:
            continue
        if isinstance(raw_slots, str):
            raw_slots = (raw_slots,)
        for s in raw_slots:
            if s in ("__dict__", "__weakref__") or s in seen_slots:
                continue
            seen_slots.add(s)
            try:
                slot_vals.append([s, snap(getattr(val, s), (), seen)])
            except AttributeError:
                slot_vals.append([s, "<unset>"])
    slot_vals.sort(key=lambda kv: kv[0])
    return slot_vals

def snap(val, path, seen):
    if val is None or isinstance(val, (bool, int, float, str, bytes, complex, slice, range)):
        return [type(val).__name__, repr(val)]
    if isinstance(val, (bytearray, memoryview)):
        return [type(val).__name__, repr(bytes(val))]
    if isinstance(val, re.Pattern):
        return ["re.Pattern", repr(val.pattern), val.flags]
    if type(val) is object:
        return ["sentinel", "object"]
    oid = id(val)
    if oid in seen:
        return ["<cycle>"]
    seen = seen | {oid}
    if isinstance(val, (list, tuple)):
        return [type(val).__name__, [snap(x, (), seen) for x in val]]
    if isinstance(val, (set, frozenset)):
        items = [snap(x, (), seen) for x in val]
        items.sort(key=lambda x: json.dumps(x, sort_keys=True))
        return [type(val).__name__, items]
    if isinstance(val, (dict, types.MappingProxyType)):
        pairs = [[snap(k, (), seen), snap(v, (), seen)] for k, v in val.items()]
        pairs.sort(key=lambda kv: json.dumps(kv[0], sort_keys=True))
        return ["dict", pairs]
    if isinstance(val, types.ModuleType):
        return ["module", getattr(val, "__name__", None)]
    if isinstance(val, (
        types.BuiltinFunctionType,
        types.MemberDescriptorType,
        types.GetSetDescriptorType,
        types.WrapperDescriptorType,
        types.MethodDescriptorType,
        types.ClassMethodDescriptorType,
    )):
        return [type(val).__name__, getattr(val, "__qualname__", None) or repr(val)]
    if isinstance(val, functools.partial):
        return ["partial", snap(val.func, (), seen), snap(val.args, (), seen), snap(val.keywords, (), seen)]
    if isinstance(val, (operator.methodcaller, operator.itemgetter, operator.attrgetter)):
        return ["operator", type(val).__qualname__, snap(val.__reduce__()[1:], (), seen)]
    if _TUPLEGETTER_TYPE is not None and type(val) is _TUPLEGETTER_TYPE:
        try:
            constructor, args = type(val).__reduce__(val)
        except Exception:
            opaque_paths.append(".".join(path) or type(val).__qualname__)
            return ["<opaque>", type(val).__qualname__]
        if (type(args) is not tuple or constructor is not _TUPLEGETTER_TYPE or len(args) != 2
                or type(args[0]) is not int or args[0] < 0 or type(args[1]) is not str):
            opaque_paths.append(".".join(path) or type(val).__qualname__)
            return ["<opaque>", type(val).__qualname__]
        # A namedtuple field descriptor's complete immutable behavior is its
        # tuple index and descriptor docstring. Do not admit subclasses or
        # objects that merely present the same name/repr.
        return ["collections._tuplegetter", args[0], args[1]]
    if isinstance(val, property):
        return ["property", snap(val.fget, (), seen), snap(val.fset, (), seen), snap(val.fdel, (), seen), getattr(val, "__doc__", None)]
    if isinstance(val, types.MethodType):
        return ["method", snap(val.__func__, (), seen), snap(val.__self__, (), seen)]
    if isinstance(val, types.FunctionType):
        doc = "<edited>" if (path in edited or id(val) in edited_ids) else getattr(val, "__doc__", None)
        closure_vals = []
        for c in (getattr(val, "__closure__", None) or ()):
            try:
                closure_vals.append(snap(c.cell_contents, (), seen))
            except ValueError:
                closure_vals.append(["<empty-cell>"])
        wrapped = snap(getattr(val, "__wrapped__"), (), seen) if hasattr(val, "__wrapped__") else None
        fdict = snap(getattr(val, "__dict__", None), (), seen)
        return [
            "function",
            getattr(val, "__module__", None),
            getattr(val, "__qualname__", None),
            doc,
            snap(getattr(val, "__defaults__", None), (), seen),
            snap(getattr(val, "__kwdefaults__", None), (), seen),
            closure_vals,
            wrapped,
            fdict,
        ]
    if isinstance(val, type):
        doc = "<edited>" if (path in edited or id(val) in edited_ids) else getattr(val, "__doc__", None)
        attrs = [
            [k, snap(v, (*path, k), seen)]
            for k, v in sorted(vars(val).items())
            if k not in _CLS_DUNDERS
        ]
        return ["type", getattr(val, "__module__", None), getattr(val, "__qualname__", None), doc, attrs]
    d = getattr(val, "__dict__", None)
    slots = _snap_slots(val, seen)
    if not isinstance(d, dict) and not slots:
        opaque_paths.append(".".join(path) or type(val).__qualname__)
        return ["<opaque>", type(val).__qualname__]
    clean_repr = re.sub(r" (?:at|@) 0x[0-9a-fA-F]+", "", repr(val))
    clean_repr = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>", clean_repr)
    return ["object", type(val).__qualname__, clean_repr, snap(d, (), seen) if isinstance(d, dict) else None, slots]

try:
    mod = importlib.import_module(spec["module"])
    edited_ids = set()
    for ep in edited:
        if not ep:
            continue
        cur = mod
        for part in ep:
            cur = getattr(cur, part, None)
            if cur is None:
                break
        if cur is not None:
            edited_ids.add(id(cur))
    g = {}
    if () not in edited:
        g["__doc__"] = snap(getattr(mod, "__doc__", None), (), set())
    for k, v in sorted(vars(mod).items()):
        if k not in _MOD_DUNDERS:
            g[k] = snap(v, (k,), set())
    print("HLITH-DOCSNAP " + json.dumps({"status": "ok", "globals": g, "opaque": opaque_paths, "proposer_readable": proposer_readable}, sort_keys=True))
except BaseException as exc:
    print("HLITH-DOCSNAP " + json.dumps({"status": f"error:{type(exc).__name__}: {exc}", "globals": {}, "opaque": [], "proposer_readable": proposer_readable}, sort_keys=True))
"""

def _interp_prefixes(python: str) -> tuple[str, ...]:
    from hlith.hostio.interpreter import interpreter_prefixes

    return tuple(interpreter_prefixes(python))


def _module_and_root(tree: Path, rel: str) -> tuple[str, Path]:
    stem = rel[:-3] if rel.endswith(".py") else rel
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    parts = [p for p in stem.split("/") if p]
    if parts and parts[0] == "src" and (tree / "src").is_dir() and not (tree / "src" / "__init__.py").is_file():
        return ".".join(parts[1:]), tree / "src"
    return ".".join(parts), tree


def _collect_docstrings(tree: ast.AST) -> dict[tuple[str, ...], str | None]:
    docs: dict[tuple[str, ...], str | None] = {}

    def walk(node: ast.AST, path: tuple[str, ...]) -> None:
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            docs[path] = ast.get_docstring(node, clean=False)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, (*path, child.name))
            else:
                walk(child, path)

    walk(tree, ())
    return docs


def _edited_docstring_paths(base_src: str, post_src: str) -> list[tuple[str, ...]]:
    b_docs = _collect_docstrings(ast.parse(base_src))
    p_docs = _collect_docstrings(ast.parse(post_src))
    all_keys = sorted(set(b_docs) | set(p_docs))
    return [k for k in all_keys if b_docs.get(k) != p_docs.get(k)]


def _first_snapshot_diff(b_globals: dict[str, Any], p_globals: dict[str, Any]) -> str | None:
    for key in sorted(set(b_globals) | set(p_globals)):
        if key not in b_globals:
            return f"added global {key}"
        if key not in p_globals:
            return f"removed global {key}"
        if b_globals[key] != p_globals[key]:
            b_str = json.dumps(b_globals[key])[:80]
            p_str = json.dumps(p_globals[key])[:80]
            return f"{key}: {b_str} -> {p_str}"
    return None


def _run_import_snapshot(
    tree: Path,
    import_root: Path,
    module: str,
    edited_paths: list[tuple[str, ...]],
    python: str,
    extra_sys_path: Sequence[str],
    proposer_paths: Sequence[str],
) -> tuple[dict[str, Any] | None, str | None, str]:
    with tempfile.TemporaryDirectory(prefix="hlith-docsnap-") as sd:
        sd_path = Path(sd)
        dist = differential.synthesize_dist_info(import_root, sd_path)
        sys_path = [str(import_root), *([dist] if dist else []), *map(str, extra_sys_path)]
        spec_path = sd_path / "spec.json"
        spec_path.write_text(json.dumps({
            "sys_path": sys_path,
            "module": module,
            "edited_paths": [list(p) for p in edited_paths],
            "proposer_paths": [str(Path(p).resolve()) for p in proposer_paths],
        }))
        try:
            prefixes = _interp_prefixes(python)
        except (OSError, ValueError) as exc:
            return None, f"target interpreter unusable: {exc}", Profile().sha256
        ro = (str(tree.resolve()), str(sd_path), *map(str, extra_sys_path), *prefixes)
        profile = Profile(ro=ro)
        try:
            cp = run_confined([python, "-I", "-c", _IMPORT_RUNNER, str(spec_path)], profile, cwd="/", timeout=30)
            raise_if_confinement_boundary(cp)
        except GrantError as exc:
            return None, f"confinement grant rejected: {exc}", profile.sha256
        except subprocess.TimeoutExpired as exc:
            return None, f"confined import timed out after {exc.timeout}s", profile.sha256
    if cp.returncode != 0:
        return None, f"confined import failed (exit {cp.returncode}): {cp.stderr.strip()[:200]}", profile.sha256
    markers = [ln for ln in cp.stdout.splitlines() if ln.startswith("HLITH-DOCSNAP ")]
    if len(markers) != 1:
        return None, "confined import produced no snapshot marker", profile.sha256
    data = json.loads(markers[0][len("HLITH-DOCSNAP "):])
    if data.get("proposer_readable"):
        return None, "proposer paths readable inside confined snapshot", profile.sha256
    if data.get("status") != "ok":
        return None, str(data.get("status")), profile.sha256
    opaque = data.get("opaque") or []
    if opaque:
        return None, f"opaque:{', '.join(str(x) for x in opaque[:4])}", profile.sha256
    return data.get("globals", {}), None, profile.sha256


def _package_init_reaches_module(
    package_module: str,
    target_module: str,
    import_root: Path,
) -> tuple[bool, str | None]:
    """Resolve static package-init import reach without executing package code."""
    seen: set[str] = set()
    module = package_module
    while module not in seen:
        if module == target_module:
            return True, None
        seen.add(module)
        root = import_root.resolve()
        path = root.joinpath(*module.split("."), "__init__.py")
        try:
            if not path.resolve().is_relative_to(root):
                return False, f"package initializer {module} escapes the import root"
        except OSError:
            return False, f"package initializer {module} cannot be resolved"
        if not path.is_file():
            return False, None
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return False, f"package initializer {module} cannot be parsed"

        edges: set[str] = set()
        dynamic: str | None = None
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == "__getattr__":
                dynamic = f"dynamic package attribute hook in {module}"
            if isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name) and statement.target.id == "__all__":
                dynamic = f"dynamic __all__ in {module}"
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                    try:
                        value = ast.literal_eval(getattr(statement, "value", None))
                    except (ValueError, TypeError, SyntaxError):
                        value = None
                    if not isinstance(value, (list, tuple)) or not all(isinstance(name, str) for name in value):
                        dynamic = f"dynamic __all__ in {module}"
            if isinstance(statement, ast.Import):
                edges.update(alias.name for alias in statement.names)
            elif isinstance(statement, ast.ImportFrom):
                if statement.level:
                    parts = module.split(".")[: max(0, len(module.split(".")) - statement.level + 1)]
                    if statement.module:
                        parts.extend(statement.module.split("."))
                    imported = ".".join(parts)
                else:
                    imported = statement.module or ""
                if imported:
                    edges.add(imported)
                    edges.update(
                        f"{imported}.{alias.name}"
                        for alias in statement.names
                        if alias.name != "*"
                    )
            if any(
                isinstance(node, ast.Call)
                and (
                    (isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "getattr", "__import__"})
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
                )
                for node in ast.walk(statement)
            ):
                dynamic = f"dynamic package import or attribute behavior in {module}"

        child = next(
            (
                edge for edge in sorted(edges)
                if edge != module and target_module.startswith(edge + ".")
            ),
            None,
        )
        if child:
            module = child
            continue
        if target_module in edges:
            return True, None
        return False, dynamic
    return False, f"cyclic package initializer import through {module}"


def _importing_test_files(
    base: Path,
    module_name: str,
    edited: Sequence[tuple[str, ...]],
    import_roots: Sequence[Path],
) -> tuple[list[str], list[str]]:
    parts = module_name.split(".")
    leaf = parts[-1]
    parent = ".".join(parts[:-1])
    packages = [".".join(parts[:i]) for i in range(1, len(parts))]
    symbols = sorted({path[0] for path in edited if path})
    if symbols:
        from ..effect.api import resolve_static_wildcard_export

    module_doc = any(not path for path in edited)
    out: set[str] = set()
    unresolved: set[str] = set()
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(base)
        if not (
            "test" in rel.parts
            or "tests" in rel.parts
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
        ):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        accesses: list[tuple[str, tuple[str, ...]]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            attrs: list[str] = []
            base_node = node
            while isinstance(base_node, ast.Attribute):
                attrs.append(base_node.attr)
                base_node = base_node.value
            if isinstance(base_node, ast.Name):
                accesses.append((base_node.id, tuple(reversed(attrs))))

        matched = False
        package_queries: set[tuple[str, str]] = set()
        reach_packages: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == module_name or alias.name.startswith(module_name + "."):
                        matched = True
                    bound_name = alias.asname or alias.name.split(".")[0]
                    bound_module = alias.name if alias.asname else alias.name.split(".")[0]
                    for package in packages:
                        if package == bound_module or package.startswith(bound_module + "."):
                            suffix = tuple(package.split(".")[len(bound_module.split(".")):])
                            for root_name, attrs in accesses:
                                if root_name != bound_name or attrs[:len(suffix)] != suffix:
                                    continue
                                symbol_index = len(suffix)
                                if symbol_index < len(attrs) and attrs[symbol_index] in symbols:
                                    package_queries.add((package, attrs[symbol_index]))
                        if module_doc and (
                            alias.name == package or alias.name.startswith(package + ".")
                        ):
                            reach_packages.add(package)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                names = [alias.name for alias in node.names]
                if mod == module_name or mod.startswith(module_name + "."):
                    matched = True
                elif parent and mod == parent and leaf in names:
                    matched = True
                elif node.level > 0 and leaf in names:
                    matched = True
                if node.level == 0:
                    for package in packages:
                        if mod == package:
                            if "*" in names:
                                package_queries.update((package, symbol) for symbol in symbols)
                            else:
                                package_queries.update(
                                    (package, name) for name in names if name in symbols
                                )
                        if module_doc and (mod == package or mod.startswith(package + ".")):
                            reach_packages.add(package)

        for package, symbol in package_queries:
            for import_root in import_roots:
                resolution = resolve_static_wildcard_export(package, symbol, (import_root,))
                if resolution.status == "resolved" and resolution.target_module == module_name:
                    matched = True
                elif resolution.status == "unresolved":
                    unresolved.add(
                        f"{package}.{symbol}: "
                        f"{resolution.reason or 'export resolution is unresolved'}"
                    )
        for package in reach_packages:
            for import_root in import_roots:
                reached, reason = _package_init_reaches_module(
                    package,
                    module_name,
                    import_root,
                )
                if reached:
                    matched = True
                elif reason:
                    unresolved.add(f"{package}: {reason}")
        if matched:
            out.add(rel.as_posix())
    return sorted(out), sorted(unresolved)


def _run_pytest_confined(
    tree: Path,
    import_root: Path,
    test_files: list[str],
    python: str,
    extra_sys_path: Sequence[str],
) -> tuple[int, dict[str, str], str]:
    with tempfile.TemporaryDirectory(prefix="hlith-doctest-") as rw_dir:
        rw_path = Path(rw_dir)
        tmp_dir = rw_path / "tmp"
        cache_dir = rw_path / "cache"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.mkdir(parents=True, exist_ok=True)
        dist = differential.synthesize_dist_info(import_root, rw_path)
        sys_path = [str(import_root), *([dist] if dist else []), *map(str, extra_sys_path)]
        try:
            prefixes = _interp_prefixes(python)
        except (OSError, ValueError) as exc:
            return 2, {}, f"target interpreter unusable: {exc}"
        ro = (str(tree.resolve()), *map(str, extra_sys_path), *prefixes)
        profile = Profile(ro=ro, rw=(str(rw_path),))
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(sys_path),
            "TMPDIR": str(tmp_dir),
            "TEMP": str(tmp_dir),
            "TMP": str(tmp_dir),
        }
        argv = [
            python, "-I", "-c",
            "import json, pytest, sys; sys.path[:0] = json.loads(sys.argv[1]); raise SystemExit(pytest.main(sys.argv[2:]))",
            json.dumps(sys_path),
            "-v", "--tb=short",
            "-o", f"cache_dir={cache_dir}",
            f"--basetemp={tmp_dir}",
            *test_files,
        ]
        try:
            cp = run_confined(argv, profile, cwd=str(tree.resolve()), timeout=90, env=env)
            raise_if_confinement_boundary(cp)
        except GrantError as exc:
            return 2, {}, f"confinement grant rejected: {exc}"
        except subprocess.TimeoutExpired as exc:
            return 124, {}, f"importing tests timed out after {exc.timeout}s"
    outcomes: dict[str, str] = {}
    for line in cp.stdout.splitlines():
        m = re.match(r"^(\S+::\S+)\s+(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b", line)
        if m:
            outcomes[m.group(1)] = m.group(2)
    summary = (cp.stdout + "\n" + cp.stderr).strip()[-400:]
    return cp.returncode, outcomes, summary


# case lever (3): a CONSERVATIVE static proof that an UNCHANGED top-level callable cannot observe an edited docstring.
# The code is already proven AST-identical modulo docstrings (derive._is_docstring_only_trees), so the only channel left is a docstring
# READER. A callable is static-clear only when nothing in it (or in the in-module callables it references) could read one; every
# dynamic or unknown construct means "cannot show" and the callable keeps today's per-callable differential. External callers and
# receiver-supplied readers are NOT excluded: that residual is named in the artifact next to the verdict.
_READER_NAMES = frozenset({
    "__doc__", "__dict__", "__getattribute__", "__getattr__", "vars", "dir", "eval", "exec", "compile", "__import__",
    "importlib", "import_module", "inspect", "getdoc", "getsource", "getsourcelines", "getcomments", "cleandoc", "help",
    "pydoc", "doctest", "wraps", "update_wrapper", "globals", "locals", "modules", "__subclasses__", "__wrapped__",
    "__builtins__", "attrgetter", "methodcaller",
})
_SAFE_BUILTIN_CALLS = frozenset({
    "callable", "id", "type",
})
STATIC_RESIDUAL = ("code unchanged, no doc reader found in the touched module; "
                   "external/receiver-supplied readers not excluded")
# Keep static-clear analysis as descriptive evidence, but never let it suppress behavioral checks.
# review's v1/v3/v10 attacks and the receiver-property case showed that no visible docstring read is not proof.
_STATIC_DOC_CLEAR_SKIPS = False


def _edited_names(edited: Sequence[tuple[str, ...]]) -> tuple[set[str], bool]:
    """(every name along an edited docstring path, whether the MODULE docstring was edited)."""
    names: set[str] = set()
    module_doc = False
    for p in edited:
        if not p:
            module_doc = True
        names.update(p)
    return names, module_doc


def _scope_walk(root: ast.AST):
    """Walk one lexical scope without entering nested functions, classes or lambdas."""
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        if node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _toolz_compat_tuple_iterator_import(
    module: str, symbol: str, import_roots: Sequence[Path],
) -> bool:
    """Prove Toolz's compatibility aliases are tuple iterators in both version branches."""
    if module != "toolz.compatibility" or symbol not in {"zip", "zip_longest"}:
        return False
    source_path = None
    for root in import_roots:
        root = Path(root).resolve()
        package = root / "toolz"
        candidate = package / "compatibility.py"
        package_candidate = package / "compatibility" / "__init__.py"
        if package_candidate.is_file():
            return False
        if candidate.is_file() and (package / "__init__.py").is_file():
            try:
                resolved = candidate.resolve()
                if not resolved.is_relative_to(root):
                    return False
            except OSError:
                return False
            source_path = resolved
            break
    if source_path is None:
        return False
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False

    # This proof only accepts immutable, direct bindings. Module/object mutation can change the
    # meaning of zip after import (including through builtins), so any such write invalidates it.
    if any(
        (isinstance(node, ast.Import)
         and any(alias.name == "builtins" or alias.name.startswith("builtins.") for alias in node.names))
        or (isinstance(node, ast.ImportFrom) and node.module == "builtins")
        or isinstance(node, ast.Name) and node.id == "__builtins__"
        or isinstance(node, (ast.Attribute, ast.Subscript))
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    ):
        return False

    py3_assignments = [
        st for st in tree.body
        if isinstance(st, (ast.Assign, ast.AnnAssign))
        and any(isinstance(t, ast.Name) and t.id == "PY3"
                for t in (st.targets if isinstance(st, ast.Assign) else [st.target]))
    ]
    if len(py3_assignments) != 1:
        return False
    if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for n in ast.walk(tree)):
        return False
    sys_bindings = [
        (st, alias)
        for st in ast.walk(tree)
        if isinstance(st, (ast.Import, ast.ImportFrom))
        for alias in st.names
        if (alias.asname or (alias.name.split(".", 1)[0] if isinstance(st, ast.Import) else alias.name)) == "sys"
    ]
    if (
        len(sys_bindings) != 1
        or not isinstance(sys_bindings[0][0], ast.Import)
        or sys_bindings[0][1].name != "sys"
        or sys_bindings[0][1].asname is not None
        or sys_bindings[0][0] not in tree.body
    ):
        return False
    operator_bindings = [
        (st, alias)
        for st in ast.walk(tree)
        if isinstance(st, (ast.Import, ast.ImportFrom))
        for alias in st.names
        if (alias.asname or (alias.name.split(".", 1)[0] if isinstance(st, ast.Import) else alias.name)) == "operator"
    ]
    if (
        len(operator_bindings) != 1
        or not isinstance(operator_bindings[0][0], ast.Import)
        or operator_bindings[0][1].name != "operator"
        or operator_bindings[0][1].asname is not None
        or operator_bindings[0][0] not in tree.body
        or any(
            isinstance(n, ast.Name) and n.id == "operator"
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for n in ast.walk(tree)
        )
        or any(
            isinstance(n, ast.ImportFrom) and any(alias.name == "*" for alias in n.names)
            for n in ast.walk(tree)
        )
    ):
        return False
    if any(
        isinstance(n, ast.Name) and n.id in {"sys", "hasattr"}
        and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(tree)
    ):
        return False
    py3_value = py3_assignments[0].value
    if not isinstance(py3_value, ast.Compare) or ast.unparse(py3_value) != "sys.version_info[0] > 2":
        return False
    branches = [
        st for st in tree.body
        if isinstance(st, ast.If) and isinstance(st.test, ast.Name) and st.test.id == "PY3"
    ]
    if len(branches) != 1 or not branches[0].orelse:
        return False
    branch = branches[0]

    def bindings(statements: Sequence[ast.stmt]) -> list[bool]:
        found: list[bool] = []
        for st in statements:
            if isinstance(st, ast.Assign):
                targets = st.targets
                if any(isinstance(t, ast.Name) and t.id == symbol for t in targets):
                    found.append(
                        symbol == "zip"
                        and len(targets) == 1
                        and isinstance(targets[0], ast.Name)
                        and isinstance(st.value, ast.Name)
                        and st.value.id == "zip"
                    )
            elif isinstance(st, ast.AnnAssign):
                if isinstance(st.target, ast.Name) and st.target.id == symbol:
                    found.append(False)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                if isinstance(st, ast.ImportFrom) and any(a.name == "*" for a in st.names):
                    found.append(False)
                for alias in st.names:
                    bound = alias.asname or (alias.name.split(".", 1)[0] if isinstance(st, ast.Import) else alias.name)
                    if bound == symbol:
                        found.append(
                            isinstance(st, ast.ImportFrom)
                            and st.module == "itertools"
                            and alias.name in {
                                "zip": {"izip"},
                                "zip_longest": {"zip_longest", "izip_longest"},
                            }[symbol]
                        )
            elif isinstance(st, ast.If):
                nested = (bindings(st.body), bindings(st.orelse))
                if any(nested):
                    if not st.orelse or not nested[0] or not nested[1]:
                        found.append(False)
                    else:
                        found.extend(nested[0])
                        found.extend(nested[1])
            else:
                if any(
                    isinstance(n, ast.Name) and n.id == symbol
                    and isinstance(n.ctx, (ast.Store, ast.Del))
                    for n in ast.walk(st)
                ):
                    found.append(False)
        return found

    body_bindings = bindings(branch.body)
    else_bindings = bindings(branch.orelse)
    if body_bindings != [True] or else_bindings != [True]:
        return False
    for st in tree.body:
        if st is branch or st is py3_assignments[0]:
            continue
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            if isinstance(st, ast.ImportFrom) and any(a.name == "*" for a in st.names):
                return False
            for alias in st.names:
                bound = alias.asname or (alias.name.split(".", 1)[0] if isinstance(st, ast.Import) else alias.name)
                if bound == symbol:
                    return False
        if any(
            isinstance(n, ast.Name) and n.id == symbol
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for n in ast.walk(st)
        ):
            return False
    if any(
        isinstance(n, (ast.Global, ast.Nonlocal)) and symbol in n.names
        for n in ast.walk(tree)
    ):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Name) and node.func.id == "hasattr"
            and len(node.args) == 2 and not node.keywords
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "sys"
            and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
        ):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "operator"
            and node.func.attr == "methodcaller"
            and len(node.args) == 1 and not node.keywords
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        ):
            continue
        return False
    return True


def _tuple_count_method_attrs(
    tree: ast.Module, fn: ast.AST, edited: set[str], import_roots: Sequence[Path] = (),
) -> set[int]:
    """Return only tuple.count attributes whose local receiver shape is statically established.

    This deliberately recognizes a narrow shape: rows yielded by unshadowed zip/itertools.zip_longest, and locals
    assigned once from the unshadowed builtin tuple(). Unknown receivers, shadowed constructors, dynamic rebinding,
    and nested scopes keep the normal edited-name blocker. This receiver fact does not clear the surrounding callable.
    """
    if "count" not in edited or not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    if not _builtin_namespace_is_static(tree):
        return set()
    if fn.decorator_list:
        return set()

    def definition_value_is_static(node: ast.AST | None) -> bool:
        if node is None or isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            return True
        try:
            ast.literal_eval(node)
            return True
        except (ValueError, TypeError):
            return False

    definition_expressions = [
        *fn.args.defaults,
        *fn.args.kw_defaults,
        *(a.annotation for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)),
        *([fn.args.vararg.annotation] if fn.args.vararg else []),
        *([fn.args.kwarg.annotation] if fn.args.kwarg else []),
        fn.returns,
    ]
    if not all(definition_value_is_static(value) for value in definition_expressions):
        return set()
    module_imports: dict[str, list[tuple[str, str]]] = {}
    module_bound: set[str] = set()
    module_reassigned: set[str] = set()
    for node in _scope_walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not tree:
            module_bound.add(node.name)
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                module_imports.setdefault(bound, []).append(("import", alias.name))
                module_bound.add(bound)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                module_imports.setdefault(bound, []).append((node.module or "", alias.name))
                module_bound.add(bound)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            module_bound.add(node.id)
            module_reassigned.add(node.id)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            module_reassigned.update(node.names)

    nodes = list(_scope_walk(fn))
    local_shadow = {n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
    args = fn.args
    local_shadow.update(a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs))
    if args.vararg:
        local_shadow.add(args.vararg.arg)
    if args.kwarg:
        local_shadow.add(args.kwarg.arg)
    reflective_calls = {"exec", "eval", "locals", "vars", "globals", "__import__", "setattr", "delattr"}
    if any(
        isinstance(n, ast.Call)
        and (
            isinstance(n.func, ast.Name) and n.func.id in reflective_calls
            or isinstance(n.func, ast.Attribute) and n.func.attr in reflective_calls
        )
        for n in ast.walk(tree)
    ):
        return set()

    direct_module_imports = {
        (alias.asname or alias.name, statement.module or "", alias.name)
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        for alias in statement.names
        if alias.name != "*"
    }
    tuple_iterator_aliases = {
        name for name, imports in module_imports.items()
        if len(imports) == 1
        and (name, imports[0][0], imports[0][1]) in direct_module_imports
        and name not in module_reassigned and name not in local_shadow
        and (
            imports[0][0] == "itertools"
            and imports[0][1] in {"zip_longest", "izip", "izip_longest"}
            or _toolz_compat_tuple_iterator_import(imports[0][0], imports[0][1], import_roots)
        )
    }
    builtin_zip = "zip" not in module_bound and "zip" not in local_shadow
    builtin_tuple = "tuple" not in module_bound and "tuple" not in local_shadow

    def zip_call(value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and ((value.func.id == "zip" and builtin_zip) or value.func.id in tuple_iterator_aliases)
        )

    def tuple_call(value: ast.AST) -> bool:
        return (
            builtin_tuple and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name) and value.func.id == "tuple"
        )

    stores: dict[str, list[ast.Name]] = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores.setdefault(node.id, []).append(node)

    def simple_target(node: ast.AST) -> ast.Name | None:
        return node if isinstance(node, ast.Name) else None

    zip_store_ids: dict[str, set[int]] = {}
    for node in nodes:
        if isinstance(node, ast.Assign) and zip_call(node.value):
            for target in node.targets:
                name = simple_target(target)
                if name is not None:
                    zip_store_ids.setdefault(name.id, set()).add(id(name))
        elif isinstance(node, ast.AnnAssign) and node.value is not None and zip_call(node.value):
            name = simple_target(node.target)
            if name is not None:
                zip_store_ids.setdefault(name.id, set()).add(id(name))
    zip_iter_names = {
        name for name, writes in zip_store_ids.items()
        if stores.get(name) and {id(w) for w in stores[name]} == writes
    }

    loop_target_ids: dict[str, set[int]] = {}
    tuple_loops: list[tuple[ast.For | ast.AsyncFor, str]] = []
    for node in nodes:
        if not isinstance(node, (ast.For, ast.AsyncFor)):
            continue
        if not (zip_call(node.iter) or isinstance(node.iter, ast.Name) and node.iter.id in zip_iter_names):
            continue
        target = simple_target(node.target)
        if target is None:
            continue
        loop_target_ids.setdefault(target.id, set()).add(id(target))
        tuple_loops.append((node, target.id))
    tuple_loop_names = {
        name for name, writes in loop_target_ids.items()
        if stores.get(name) and {id(w) for w in stores[name]} == writes
    }

    safe_attrs: set[int] = set()
    for loop, target_name in tuple_loops:
        if target_name not in tuple_loop_names:
            continue
        for statement in loop.body:
            for node in _scope_walk(statement):
                if (isinstance(node, ast.Attribute) and node.attr in edited
                        and isinstance(node.value, ast.Name) and node.value.id == target_name):
                    safe_attrs.add(id(node))

    tuple_assignments: dict[str, list[tuple[ast.Name, ast.AST]]] = {}
    for node in nodes:
        if isinstance(node, ast.Assign) and tuple_call(node.value):
            for target in node.targets:
                name = simple_target(target)
                if name is not None:
                    tuple_assignments.setdefault(name.id, []).append((name, node))
        elif isinstance(node, ast.AnnAssign) and node.value is not None and tuple_call(node.value):
            name = simple_target(node.target)
            if name is not None:
                tuple_assignments.setdefault(name.id, []).append((name, node))

    parent: dict[ast.AST, ast.AST] = {}
    node_set = set(nodes)
    for node in nodes:
        for child in ast.iter_child_nodes(node):
            if child in node_set:
                parent[child] = node

    def statement_position(statement: ast.AST) -> tuple[ast.AST, str, int] | None:
        owner = parent.get(statement)
        if owner is None:
            return None
        for body_field in ("body", "orelse", "finalbody"):
            block = getattr(owner, body_field, None)
            if isinstance(block, list) and statement in block:
                return owner, body_field, block.index(statement)
        return None

    def use_follows_assignment(assignment: ast.AST, use: ast.AST) -> bool:
        pos = statement_position(assignment)
        if pos is None:
            return False
        owner, field, assignment_index = pos
        current = use
        while current in parent and parent[current] is not owner:
            current = parent[current]
        block = getattr(owner, field, None)
        return isinstance(block, list) and current in block and assignment_index < block.index(current)

    for name, assignments in tuple_assignments.items():
        writes = stores.get(name, [])
        if len(assignments) != 1 or len(writes) != 1 or writes[0] is not assignments[0][0]:
            continue
        assigned_name, statement = assignments[0]
        for node in nodes:
            if (isinstance(node, ast.Attribute) and node.attr in edited
                    and isinstance(node.value, ast.Name) and node.value.id == name
                    and use_follows_assignment(statement, node)):
                safe_attrs.add(id(node))
    return safe_attrs


def _static_tuple_receiver_sites(
    post_src: str, edited: Sequence[tuple[str, ...]], import_roots: Sequence[Path] = (),
) -> tuple[tuple[str, int, str], ...]:
    """Return exact source sites whose edited-name method receiver is proven to be a builtin tuple."""
    tree = ast.parse(post_src)
    names, _ = _edited_names(edited)
    sites: set[tuple[str, int, str]] = set()
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        safe_attrs = _tuple_count_method_attrs(tree, fn, names, import_roots)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call) or id(node.func) not in safe_attrs:
                continue
            source = ast.get_source_segment(post_src, node) or ast.unparse(node)
            sites.add((fn.name, node.lineno, source))
    return tuple(sorted(sites))


def _callable_reasons(fn: ast.AST, edited: set[str], local_tops: frozenset = frozenset(), judge=None,
                      safe_tuple_method_attrs: set[int] | None = None) -> list[str]:
    """Why this callable CANNOT be shown clear of docstring readers (empty = clear on its own)."""
    why: list[str] = []
    for dec in getattr(fn, "decorator_list", None) or ():
        leaf = dec.id if isinstance(dec, ast.Name) else dec.attr if isinstance(dec, ast.Attribute) else None
        if leaf != "contextmanager":  # the one vetted stdlib decorator: it copies the docstring, it never reads it
            why.append("decorated (a decorator may consume or copy documentation)")
    judged: set[int] = set()  # getattr(...) callee Names already judged at their Call
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr":
            judged.add(id(n.func))
            a = n.args[1] if len(n.args) > 1 else None
            if not (isinstance(a, ast.Constant) and isinstance(a.value, str)) or "doc" in a.value.lower()\
                    or a.value.startswith("__") or a.value in edited:
                why.append("getattr with a non-literal, dunder, doc or edited attribute name")
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            why.append("global/nonlocal rebinding")
        elif isinstance(n, (ast.Import, ast.ImportFrom)) and _inrepo_import(n, local_tops):
            if judge is None or not judge.import_ok(n):
                why.append("imports an in-repo module that cannot be shown free of docstring readers")
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and "__doc__" in n.value:
            why.append("string mentions __doc__")
        tok = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else None
        if tok is None:
            continue
        if tok == "getattr" and id(n) not in judged:
            why.append("getattr used other than as a direct call")
        if tok in edited and not (isinstance(n, ast.Attribute) and id(n) in (safe_tuple_method_attrs or set())):
            why.append(f"references edited object '{tok}'")
        if tok in _READER_NAMES and not (tok == "compile" and isinstance(n, ast.Attribute)):  # re.compile is not the builtin
            why.append(f"uses '{tok}'")
    return list(dict.fromkeys(why))


def _local_tops(base: Path, post: Path, p_root: Path) -> frozenset:
    """First segments importable from the repository: package dirs and module files at the tree and import roots."""
    tops: set[str] = set()
    for root in {Path(base), Path(post), Path(p_root)}:
        try:
            for e in root.iterdir():
                if e.name.startswith((".", "_")) and e.name != "__init__.py":
                    continue
                if e.is_dir():
                    tops.add(e.name)
                elif e.suffix == ".py":
                    tops.add(e.stem)
        except OSError:
            continue
    return frozenset(tops)


def _inrepo_import(n: ast.AST, local_tops: frozenset) -> bool:
    """True when an import statement names a repository module (relative, or its first segment is a top-level repo name)."""
    if isinstance(n, ast.ImportFrom):
        return bool(n.level) or (n.module or "").split(".")[0] in local_tops
    return any(a.name.split(".")[0] in local_tops for a in n.names)


def _opaque_bound_names(st: ast.AST):
    if isinstance(st, (ast.For, ast.AsyncFor)):
        for n in ast.walk(st.target):
            if isinstance(n, ast.Name):
                yield n.id
    elif isinstance(st, (ast.With, ast.AsyncWith)):
        for it in st.items:
            if it.optional_vars is not None:
                for n in ast.walk(it.optional_vars):
                    if isinstance(n, ast.Name):
                        yield n.id
    elif isinstance(st, ast.Try):
        for h in st.handlers:
            if h.name:
                yield h.name


class _Ctx:
    """Resolution context of ONE module: which package relative imports are relative to, and the shared judge (file cache, memo)."""

    def __init__(self, judge: "_Judge", dotted: str, is_pkg: bool) -> None:
        self.judge, self.dotted = judge, dotted
        self.pkg = dotted if is_pkg else dotted.rpartition(".")[0]

    def _base(self, st: ast.ImportFrom) -> str | None:
        parts = self.pkg.split(".") if self.pkg else []
        if st.level:
            if st.level - 1 > len(parts):
                return None
            parts = parts[: len(parts) - (st.level - 1)]
            return ".".join([*parts, *([st.module] if st.module else [])])
        return st.module or ""

    def alias_ok(self, st: ast.AST, alias: ast.alias) -> bool:
        """An in-repo import binding is harmless iff what it binds is proven free of docstring readers (a submodule: the whole
        module; a name: that name's definition and its in-module closure, followed transitively across repository modules)."""
        j = self.judge
        if isinstance(st, ast.Import):
            return j.module_ok(alias.name) if alias.name.split(".")[0] in j.tops else True
        base = self._base(st)
        if base is None or alias.name == "*":
            return False
        if j.file(f"{base}.{alias.name}"):
            return j.module_ok(f"{base}.{alias.name}")
        return j.name_ok(base, alias.name)

    def import_ok(self, st: ast.AST) -> bool:
        return all(self.alias_ok(st, al) for al in st.names)


class _Judge:
    MAX_FILES = 60

    def __init__(self, roots: Sequence[Path], edited: set[str], tops: frozenset) -> None:
        self.roots, self.edited, self.tops = [Path(r) for r in roots], edited, tops
        self.reasons: dict[str, dict | None] = {}  # dotted -> {name: [reasons]}; None = in progress (fail closed)
        self.opaque: dict[str, dict] = {}
        self.mod_all: dict[str, bool] = {}

    def file(self, dotted: str):
        rel = dotted.replace(".", "/")
        for r in self.roots:
            for cand in (r / (rel + ".py"), r / rel / "__init__.py"):
                if cand.is_file():
                    return cand
        return None

    def _load(self, dotted: str):
        f = self.file(dotted)
        if f is None or len(self.reasons) >= self.MAX_FILES:
            return None
        try:
            return f, ast.parse(f.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return None

    def name_ok(self, dotted: str, name: str) -> bool:
        if dotted not in self.reasons:
            self.reasons[dotted] = None
            ld = self._load(dotted)
            if ld is None:
                self.reasons[dotted] = {"*": ["unresolvable"]}
            else:
                f, tree = ld
                ctx = _Ctx(self, dotted, f.name == "__init__.py")
                r, opq = _closure(tree, self.edited, self.tops, ctx)
                self.reasons[dotted], self.opaque[dotted] = r, opq
        rs = self.reasons[dotted]
        if rs is None or "*" in rs:
            return False
        if name in self.opaque.get(dotted, {}):
            return False
        return name in rs and not rs[name]  # a name the scan did not see bound (dynamic / submodule attr) is not shown clear

    def module_ok(self, dotted: str) -> bool:
        """The WHOLE module: every binding in it is clear (used when a module object itself is imported)."""
        if dotted in self.mod_all:
            return self.mod_all[dotted]
        self.mod_all[dotted] = False
        ld = self._load(dotted)
        ok = False
        if ld is not None:
            self.name_ok(dotted, "")  # populate
            rs = self.reasons.get(dotted)
            ok = bool(rs) and "*" not in rs and not any(rs.values()) and not self.opaque.get(dotted)
        self.mod_all[dotted] = ok
        return ok


def _module_units(tree: ast.Module, local_tops: frozenset, ctx: "_Ctx | None" = None) -> tuple[dict, dict, bool, set[str]]:
    """Every module-scope binding: name -> [nodes whose code it can run or hold] (defs, classes, assigned values anywhere at module
    scope incl. under if/try/with/for); in-repo imports not proven clear and unanalysed bindings are opaque; external imports remain
    separately marked so their names cannot silently serve as trusted call targets."""
    units: dict[str, list] = {}
    opaque: dict[str, str] = {}
    external: set[str] = set()
    star = False

    def targets(t):
        if isinstance(t, ast.Name):
            yield t.id
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                yield from targets(e)
        elif isinstance(t, ast.Starred):
            yield from targets(t.value)

    def visit(stmts):
        nonlocal star
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                units.setdefault(st.name, []).append(st)
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    for nm in targets(t):
                        units.setdefault(nm, []).append(st.value)
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and isinstance(st.target, ast.Name):
                if getattr(st, "value", None) is not None:
                    units.setdefault(st.target.id, []).append(st.value)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                if _inrepo_import(st, local_tops):
                    for al in st.names:
                        if al.name == "*":
                            star = True
                        elif ctx is None or not ctx.alias_ok(st, al):
                            opaque[(al.asname or al.name).split(".")[0]] = "is an in-repo import not shown free of docstring readers"
                        else:
                            units.setdefault((al.asname or al.name).split(".")[0], [])  # bound, proven clear
                else:  # stdlib / third-party import: harmless unless it IS a documentation-reading module or name
                    mod = (st.module or "") if isinstance(st, ast.ImportFrom) else ""
                    for al in st.names:
                        root_ = (mod or al.name).split(".")[0]
                        if root_ in ("inspect", "importlib", "pydoc", "doctest") or al.name in _READER_NAMES:
                            opaque[(al.asname or al.name).split(".")[0]] = "is a documentation-reading import"
                        else:
                            bound = (al.asname or al.name).split(".")[0]
                            units.setdefault(bound, [])
                            external.add(bound)
            else:
                for nm in _opaque_bound_names(st):
                    opaque[nm] = "is bound by a module-level statement the scan does not analyse"
                for fld in ("body", "orelse", "finalbody"):
                    sub = getattr(st, fld, None)
                    if isinstance(sub, list):
                        visit([x for x in sub if isinstance(x, ast.stmt)])
                for h in getattr(st, "handlers", []) or []:
                    visit(h.body)
    visit(tree.body)
    return units, opaque, star, external


def _builtin_namespace_is_static(tree: ast.Module) -> bool:
    """Whether source avoids explicit access paths that could rebind allowlisted builtins."""
    reflective = {"eval", "exec", "globals", "locals", "vars", "__import__", "setattr", "delattr", "import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in {"builtins", "__builtins__"}:
            return False
        if isinstance(node, ast.Attribute) and node.attr in {"modules", "__dict__"}:
            return False
        if isinstance(node, ast.Import) and any(alias.name == "builtins" for alias in node.names):
            return False
        if isinstance(node, ast.ImportFrom) and node.module == "builtins":
            return False
        if isinstance(node, ast.Call):
            leaf = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
            if leaf in reflective:
                return False
    return True


def _unresolved_call_reasons(
    node: ast.AST,
    units: set[str],
    opaque: dict[str, str],
    external: set[str],
    local_tops: frozenset,
    safe_tuple_method_attrs: set[int],
    builtins_static: bool,
) -> list[str]:
    """Require calls and external references to resolve to analyzed bindings or the small builtin allowlist."""
    nodes = list(ast.walk(node))
    local_bound = {
        n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }
    local_bound.update(n.arg for n in nodes if isinstance(n, ast.arg))
    local_external: set[str] = set()
    for n in nodes:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not node:
            local_bound.add(n.name)
        elif isinstance(n, ast.Import):
            for alias in n.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                (local_bound if _inrepo_import(n, local_tops) else local_external).add(bound)
        elif isinstance(n, ast.ImportFrom):
            for alias in n.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                (local_bound if _inrepo_import(n, local_tops) else local_external).add(bound)

    external_bindings = external | local_external

    reasons: list[str] = []
    for n in nodes:
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in external_bindings:
            reasons.append(f"references external binding '{n.id}' whose behavior is not analyzed")
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        if isinstance(func, ast.Attribute):
            if id(func) not in safe_tuple_method_attrs:
                reasons.append(f"calls unresolved attribute '{func.attr}'")
        elif isinstance(func, ast.Name):
            name = func.id
            if name in external_bindings:
                reasons.append(f"calls external binding '{name}' whose behavior is not analyzed")
            elif name in local_bound:
                reasons.append(f"calls dynamically bound name '{name}'")
            elif name in opaque:
                reasons.append(f"calls '{name}', which {opaque[name]}")
            elif name in units:
                continue  # _closure follows this analyzed module-scope binding transitively.
            elif name in _SAFE_BUILTIN_CALLS:
                if not builtins_static:
                    reasons.append("calls an allowlisted builtin while the builtin namespace may be rebound")
                elif len(n.args) != 1 or n.keywords:
                    reasons.append(f"calls allowlisted builtin '{name}' with an unproven argument shape")
            else:
                reasons.append(f"calls unresolved name '{name}'")
        else:
            reasons.append("calls a dynamically resolved callable")
    return list(dict.fromkeys(reasons))


def _closure(tree: ast.Module, names: set[str], local_tops: frozenset, ctx: "_Ctx | None",
             module_doc: bool = False) -> tuple[dict[str, list[str]], dict[str, str]]:
    """{unit name: reasons it cannot be shown clear} for every module-scope unit, closed over references among units."""
    units, opaque, star, external = _module_units(tree, local_tops, ctx)
    reasons = {}
    import_roots = ctx.judge.roots if ctx else ()
    builtins_static = _builtin_namespace_is_static(tree)
    unit_names = set(units)
    for u, nodes in units.items():
        own_reasons = []
        for nd in nodes:
            safe_tuple_method_attrs = _tuple_count_method_attrs(
                tree, nd, names, import_roots
            )
            own_reasons.extend(_callable_reasons(
                nd, names, local_tops, ctx, safe_tuple_method_attrs
            ))
            own_reasons.extend(_unresolved_call_reasons(
                nd, unit_names, opaque, external, local_tops,
                safe_tuple_method_attrs, builtins_static,
            ))
        reasons[u] = list(dict.fromkeys(own_reasons))
    refs = {u: {n.id for nd in nodes for n in ast.walk(nd) if isinstance(n, ast.Name)} for u, nodes in units.items()}
    for u in reasons:
        if u in names:
            reasons[u].append("is the edited object (keeps its own differential)")
        for v in refs[u] - {u}:
            if v in opaque:
                reasons[u].append(f"uses '{v}', which {opaque[v]}")
        if module_doc:
            reasons[u].append("the module docstring was edited")
        if star:
            reasons[u].append("the module has an in-repo star import")
    changed = True
    depth = 0
    while changed and depth < _MAX_LOCAL_CALL_DEPTH:
        changed = False
        for u in reasons:
            if reasons[u]:
                continue
            for v in refs[u]:
                if v != u and v in reasons and reasons[v]:
                    reasons[u].append(f"uses '{v}', which cannot be shown clear")
                    changed = True
                    break
        depth += 1
    if changed:
        for u in reasons:
            if not reasons[u]:
                reasons[u].append("local call closure exceeded the static depth limit")
    return reasons, opaque


def static_doc_clear(post_src: str, edited: Sequence[tuple[str, ...]], local_tops: frozenset = frozenset(),
                     ctx: dict | None = None) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """({clear top-level callable: []}, {callable that falls back: [reasons]}) for the callables of one module.
    The closure follows every module-scope binding a callable references (defs anywhere at module scope incl. conditional ones,
    classes, lambdas / assigned values) and resolves in-repo imports name by name across repository modules (fail closed on
    cycles, unresolvable files, `import *`, and anything dynamic). Calls clear only when they resolve to analyzed local bindings
    or a small stable builtin allowlist; external, dynamic, and attribute calls keep fallback. A module-docstring edit clears
    nothing."""
    tree = ast.parse(post_src)
    names, module_doc = _edited_names(edited)
    c = None
    if ctx:
        c = _Ctx(_Judge(ctx["roots"], names, local_tops), ctx["module"], ctx["is_pkg"])
    reasons, _ = _closure(tree, names, local_tops, c, module_doc)
    clear: dict[str, list[str]] = {}
    fall: dict[str, list[str]] = {}
    for f in tree.body:
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
            (fall if reasons.get(f.name) else clear)[f.name] = reasons.get(f.name, [])
    return clear, fall


@dataclass(frozen=True)
class DocstringCheckResult:
    allow_skip_unrelated: bool
    obligations: tuple[Obligation, ...]
    # module dotted name -> top-level callables classified static-clear; derive consults the skip gate separately
    static_clear: dict = field(default_factory=dict)
    # (relative file, qualified caller, line, exact call source) for statically proven tuple.count receivers.
    static_tuple_receiver_sites: tuple[tuple[str, str, int, str], ...] = ()


def verify_docstring_only_diff(
    base: Path,
    post: Path,
    touched_files: tuple[str, ...],
    *,
    python: str,
    extra_sys_path: Sequence[str],
    proposer_paths: Sequence[str],
) -> DocstringCheckResult:
    """Measure (a) confined import snapshot and (b) importing repo tests on base vs post."""
    if not _DOCSTRING_MEASURED:
        return DocstringCheckResult(
            allow_skip_unrelated=False,
            obligations=(
                Obligation(
                    "docstring-import-risk",
                    ",".join(touched_files) or "*",
                    "docstring change does not alter module import state",
                    Verdict.NOT_DERIVED,
                    stop_reason="docstring consumed at import or via __doc__ cannot be excluded (measured check disabled)",
                ),
            ),
        )
    obs: list[Obligation] = []
    all_ok = True
    static_clear: dict = {}
    static_tuple_receiver_sites: list[tuple[str, str, int, str]] = []
    for rel in touched_files:
        module_name, b_root = _module_and_root(base, rel)
        _, p_root = _module_and_root(post, rel)
        edited = _edited_docstring_paths(
            (base / rel).read_text(encoding="utf-8"),
            (post / rel).read_text(encoding="utf-8"),
        )
        b1_snap, b1_err, prof_sha = _run_import_snapshot(
            base, b_root, module_name, edited, python, extra_sys_path, proposer_paths
        )
        b2_snap, b2_err, _ = _run_import_snapshot(
            base, b_root, module_name, edited, python, extra_sys_path, proposer_paths
        )
        p1_snap, p1_err, _ = _run_import_snapshot(
            post, p_root, module_name, edited, python, extra_sys_path, proposer_paths
        )
        p2_snap, p2_err, _ = _run_import_snapshot(
            post, p_root, module_name, edited, python, extra_sys_path, proposer_paths
        )
        snap_err = b1_err or b2_err or p1_err or p2_err
        if snap_err or b1_snap is None or b2_snap is None or p1_snap is None or p2_snap is None:
            all_ok = False
            if isinstance(snap_err, str) and snap_err.startswith("opaque:"):
                obs.append(Obligation(
                    f"docstring-import-opaque:{rel}",
                    module_name,
                    "docstring change does not alter opaque module import state",
                    Verdict.UNVERIFIED,
                    stop_reason=f"import snapshot encountered opaque object(s) without inspectable state: {snap_err[7:]}",
                ))
            else:
                obs.append(Obligation(
                    f"docstring-import-risk:{rel}",
                    module_name,
                    "docstring change does not alter module import state",
                    Verdict.NOT_DERIVED,
                    stop_reason=f"docstring consumed at import cannot be excluded: {snap_err}",
                ))
            continue
        b_nondet = {k for k in set(b1_snap) | set(b2_snap) if b1_snap.get(k) != b2_snap.get(k)}
        p_nondet = {k for k in set(p1_snap) | set(p2_snap) if p1_snap.get(k) != p2_snap.get(k)}
        both_nondet = sorted(b_nondet & p_nondet)
        b_cmp = {k: v for k, v in b1_snap.items() if k not in both_nondet}
        p_cmp = {k: v for k, v in p1_snap.items() if k not in both_nondet}
        diff = _first_snapshot_diff(b_cmp, p_cmp)
        if diff is not None:
            all_ok = False
            obs.append(Obligation(
                f"docstring-import-risk:{rel}",
                module_name,
                "docstring change does not alter module import state",
                Verdict.NOT_DERIVED,
                stop_reason=f"docstring consumed at import cannot be excluded: {diff}",
            ))
            continue

        test_files, import_blockers = _importing_test_files(
            base,
            module_name,
            edited,
            (b_root, p_root),
        )
        executions = 4
        if import_blockers:
            all_ok = False
            obs.append(Obligation(
                f"docstring-import-test-error:{rel}",
                module_name,
                "repo tests importing touched module execute cleanly",
                Verdict.UNVERIFIED,
                stop_reason=(
                    "package import path is unresolved: "
                    + "; ".join(import_blockers[:4])
                ),
            ))
            continue
        if not test_files:
            all_ok = False
            obs.append(Obligation(
                f"docstring-import-test-error:{rel}",
                module_name,
                "repo tests importing touched module execute cleanly",
                Verdict.UNVERIFIED,
                stop_reason=f"no repository tests statically import {module_name}; cannot verify docstring-only edit",
            ))
            continue
        if len(test_files) > _MAX_IMPORTING_TEST_FILES:
            all_ok = False
            obs.append(Obligation(
                f"docstring-import-test-budget:{rel}",
                module_name,
                "repo tests importing touched module execute within budget",
                Verdict.UNVERIFIED,
                stop_reason=f"importing tests exceed budget: {len(test_files)} files > {_MAX_IMPORTING_TEST_FILES} max",
            ))
            continue
        t_start = time.monotonic()

        def _budget_check() -> bool:
            elapsed = time.monotonic() - t_start
            if elapsed > _IMPORTING_TEST_TOTAL_BUDGET_S:
                obs.append(Obligation(
                    f"docstring-import-test-budget:{rel}",
                    module_name,
                    "repo tests importing touched module execute within budget",
                    Verdict.UNVERIFIED,
                    stop_reason=f"importing tests exceed budget: {elapsed:.1f}s > {_IMPORTING_TEST_TOTAL_BUDGET_S:.0f}s",
                ))
                return True
            return False

        b1_rc, b1_out, b1_msg = _run_pytest_confined(base, b_root, test_files, python, extra_sys_path)
        if _budget_check():
            all_ok = False
            continue
        if b1_rc == 124:
            all_ok = False
            obs.append(Obligation(
                f"docstring-import-test-error:{rel}",
                module_name,
                "repo tests importing touched module execute cleanly",
                Verdict.UNVERIFIED,
                stop_reason=f"importing tests did not execute (base={b1_rc}/0/0 passed): {b1_msg}"[:300],
            ))
            continue
        p1_rc, p1_out, p1_msg = _run_pytest_confined(post, p_root, test_files, python, extra_sys_path)
        if _budget_check():
            all_ok = False
            continue
        base_passed = [nid for nid, st in b1_out.items() if st == "PASSED"]
        clean_single = (
            b1_rc in (0, 1) and p1_rc in (0, 1)
            and bool(base_passed) and bool(p1_out)
            and b1_out == p1_out and b1_rc == p1_rc
        )
        if clean_single:
            executions += len(b1_out) + len(p1_out)
        else:
            if p1_rc == 124:
                all_ok = False
                obs.append(Obligation(
                    f"docstring-import-test-error:{rel}",
                    module_name,
                    "repo tests importing touched module execute cleanly",
                    Verdict.UNVERIFIED,
                    stop_reason=f"importing tests did not execute (base={b1_rc}/{len(b1_out)}/{len(base_passed)} passed, post={p1_rc}/{len(p1_out)}): {p1_msg}"[:300],
                ))
                continue
            b2_rc, b2_out, b2_msg = _run_pytest_confined(base, b_root, test_files, python, extra_sys_path)
            if _budget_check():
                all_ok = False
                continue
            p2_rc, p2_out, p2_msg = _run_pytest_confined(post, p_root, test_files, python, extra_sys_path)
            if _budget_check():
                all_ok = False
                continue
            if (
                b1_rc not in (0, 1) or b2_rc not in (0, 1) or p1_rc not in (0, 1) or p2_rc not in (0, 1)
                or not base_passed or not b2_out or not p1_out or not p2_out
            ):
                all_ok = False
                obs.append(Obligation(
                    f"docstring-import-test-error:{rel}",
                    module_name,
                    "repo tests importing touched module execute cleanly",
                    Verdict.UNVERIFIED,
                    stop_reason=(
                        f"importing tests did not execute (base={b1_rc}/{len(b1_out)}/{len(base_passed)} passed, "
                        f"post={p1_rc}/{len(p1_out)}): {p1_msg or p2_msg or b1_msg or b2_msg}"
                    )[:300],
                ))
                continue
            if b1_out != b2_out or p1_out != p2_out:
                all_ok = False
                obs.append(Obligation(
                    f"docstring-import-test-flaky:{rel}",
                    module_name,
                    "repo tests importing touched module are deterministic",
                    Verdict.UNVERIFIED,
                    stop_reason=f"importing tests for {module_name} are flaky (differing outcomes across repeated runs)",
                ))
                continue
            regressed = [
                nid for nid, st in b1_out.items()
                if st == "PASSED" and p1_out.get(nid) in {"FAILED", "ERROR"}
            ]
            if regressed or (b1_rc == 0 and p1_rc != 0):
                all_ok = False
                first_bad = regressed[0] if regressed else p1_msg[:200]
                obs.append(Obligation(
                    f"docstring-test-regression:{rel}",
                    module_name,
                    "repo tests importing touched module preserve behaviour",
                    Verdict.REFUTED,
                    witness=f"repo test(s) importing {module_name} passed on base and failed on post: {first_bad}"[:300],
                ))
                continue
            executions += len(b1_out) + len(b2_out) + len(p1_out) + len(p2_out)

        try:
            post_source = (post / rel).read_text(encoding="utf-8")
            clear_, fall_ = static_doc_clear(post_source, edited, _local_tops(base, post, p_root),
                                              {"roots": [p_root, post], "module": module_name, "is_pkg": rel.endswith("__init__.py")})
            static_tuple_receiver_sites.extend(
                (rel, f"{module_name}.{caller}", line, source)
                for caller, line, source in _static_tuple_receiver_sites(post_source, edited, (p_root,))
            )
        except (OSError, SyntaxError, UnicodeDecodeError):
            clear_, fall_ = {}, {}
        static_note = ""
        if clear_:
            static_clear[module_name] = tuple(sorted(clear_))
            static_note = (f"; docstring-other-static: {len(clear_)} callable(s) not executed: {STATIC_RESIDUAL}"
                           + (f"; {len(fall_)} callable(s) cannot be shown clear and keep their differential: "
                              + ", ".join(sorted(fall_)[:6]) if fall_ else ""))
        edited_desc = ", ".join(".".join(p) or "<module>" for p in edited) or "<none>"
        nondet_desc = f"; excluded nondeterministic globals: {', '.join(both_nondet)}" if both_nondet else ""
        obs.append(Obligation(
            f"docstring-measured:{rel}",
            module_name,
            "docstring-only edit preserves module import state and importing repo tests",
            Verdict.HELD,
            evidence=BoundedEvidence(
                executions=executions,
                explored=(
                    f"confined 2x import snapshot matched on base/post (excluded edited __doc__: {edited_desc}{nondet_desc}); "
                    f"2x {len(test_files)} importing test file(s) agreed ({len(b1_out)} test(s) per run){static_note}"
                ),
                unexplored=_UNEXPLORED_NOTE + (f"; docstring-other-static: {len(clear_)} callable(s) not executed: {STATIC_RESIDUAL}" if clear_ else ""),
            ),
            provenance=CheckProvenance(
                CHECKER_ID,
                CHECKER_SHA256,
                True,
                False,
                prof_sha,
                0,
            ),
            account_bound=True,
        ))
    return DocstringCheckResult(
        allow_skip_unrelated=all_ok,
        obligations=tuple(obs),
        static_clear=static_clear,
        static_tuple_receiver_sites=tuple(sorted(set(static_tuple_receiver_sites))),
    )
