# SPDX-License-Identifier: Apache-2.0
"""Static package export resolution without importing repository code."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence


ExportStatus = Literal["resolved", "not_exported", "unresolved"]


@dataclass(frozen=True)
class StaticExportResolution:
    """Result of resolving one public name through static package bindings."""

    status: ExportStatus
    target_module: str | None = None
    reason: str | None = None


def resolve_static_wildcard_export(
    package_module: str,
    symbol: str,
    import_roots: Sequence[str | os.PathLike[str]],
) -> StaticExportResolution:
    """Resolve ``package_module.symbol`` through source-level wildcard re-exports.

    Only Python source beneath the ordered import roots is read. Nothing from the target is imported or executed.
    ``not_exported`` is distinct from ``unresolved``: the former is a statically absent name, while the latter means
    dynamic export behavior, ambiguous source, a parse failure, or an unresolved/cyclic wildcard edge.
    """
    if not package_module or any(not part.isidentifier() for part in package_module.split(".")):
        return StaticExportResolution("unresolved", reason="invalid package module name")
    if not symbol or not symbol.isidentifier():
        return StaticExportResolution("unresolved", reason="invalid exported symbol")
    roots = tuple(Path(root) for root in import_roots)
    if not roots:
        return StaticExportResolution("unresolved", reason="no import roots supplied")
    return _resolve_name(package_module, symbol, roots, ())


def _module_source(
    module_name: str, roots: tuple[Path, ...]
) -> tuple[Path, bool] | StaticExportResolution:
    parts = module_name.split(".")
    for root in roots:
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        candidates = (
            (resolved_root.joinpath(*parts, "__init__.py"), True),
            (resolved_root.joinpath(*parts[:-1], parts[-1] + ".py"), False),
        )
        for path, is_package in candidates:
            try:
                if not path.is_file():
                    continue
                resolved_path = path.resolve(strict=True)
            except OSError:
                continue
            if path.is_symlink() or not resolved_path.is_relative_to(resolved_root):
                return StaticExportResolution(
                    "unresolved", reason=f"module source escapes import root: {module_name}"
                )
            return resolved_path, is_package
    return StaticExportResolution("unresolved", reason=f"module source not found: {module_name}")


def _static_string_list(node: ast.AST | None, values: dict[str, list[str]]) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        result: list[str] = []
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                result.append(element.value)
            elif isinstance(element, ast.Name) and element.id in values:
                result.extend(values[element.id])
            else:
                return None
        return result
    if isinstance(node, ast.Name):
        value = values.get(node.id)
        return list(value) if value is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string_list(node.left, values)
        right = _static_string_list(node.right, values)
        return left + right if left is not None and right is not None else None
    return None


def _base_module(current: str, node: ast.ImportFrom, *, is_package: bool) -> str:
    if not node.level:
        return node.module or ""
    parts = current.split(".")
    if not is_package and parts:
        parts.pop()
    for _ in range(max(0, node.level - 1)):
        if parts:
            parts.pop()
    base = ".".join(parts)
    if node.module:
        return f"{base}.{node.module}" if base else node.module
    return base


def _top_level_writes(statement: ast.stmt) -> set[str]:
    names: set[str] = set()
    pending: list[ast.AST] = [statement]
    while pending:
        node = pending.pop()
        if node is not statement and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name.split(".")[-1]
                         for alias in node.names if alias.name != "*")
        pending.extend(ast.iter_child_nodes(node))
    return names


def _resolve_name(
    module_name: str,
    symbol: str,
    roots: tuple[Path, ...],
    stack: tuple[str, ...],
) -> StaticExportResolution:
    if module_name in stack:
        chain = " -> ".join((*stack, module_name))
        return StaticExportResolution("unresolved", reason=f"wildcard re-export cycle: {chain}")
    found = _module_source(module_name, roots)
    if isinstance(found, StaticExportResolution):
        return found
    path, is_package = found
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        return StaticExportResolution(
            "unresolved", reason=f"cannot statically parse {module_name}: {type(exc).__name__}"
        )

    binding = StaticExportResolution("not_exported", reason=f"no static binding for {module_name}.{symbol}")
    static_lists: dict[str, list[str]] = {}
    all_state: Literal["absent", "static", "dynamic"] = "absent"
    all_names: list[str] = []
    has_getattr = False
    next_stack = (*stack, module_name)

    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name == "__getattr__":
                has_getattr = True
            if statement.name == symbol:
                binding = StaticExportResolution("resolved", target_module=module_name)
            continue

        if isinstance(statement, ast.ImportFrom):
            base = _base_module(module_name, statement, is_package=is_package)
            for alias in statement.names:
                if alias.name == "*":
                    if not base:
                        binding = StaticExportResolution(
                            "unresolved", reason=f"unresolved wildcard import in {module_name}"
                        )
                        continue
                    imported = _resolve_name(base, symbol, roots, next_stack)
                    if imported.status != "not_exported":
                        binding = imported
                    continue
                local = alias.asname or alias.name
                if local == symbol:
                    if not base:
                        binding = StaticExportResolution(
                            "unresolved", reason=f"unresolved import binding in {module_name}"
                        )
                        continue
                    submodule = _module_source(f"{base}.{alias.name}", roots)
                    if not isinstance(submodule, StaticExportResolution):
                        binding = StaticExportResolution("resolved", target_module=f"{base}.{alias.name}")
                    else:
                        binding = _resolve_name(base, alias.name, roots, next_stack)
                        if binding.status == "not_exported":
                            binding = StaticExportResolution(
                                "unresolved", reason=f"unresolved imported symbol: {base}.{alias.name}"
                            )
            continue

        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                if local == symbol:
                    target = alias.name if alias.asname else local
                    binding = StaticExportResolution("resolved", target_module=target)
            continue

        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            value = statement.value
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id == "__all__":
                    names = _static_string_list(value, static_lists)
                    if names is None:
                        all_state = "dynamic"
                        static_lists.pop("__all__", None)
                    else:
                        all_state = "static"
                        all_names = names
                        static_lists["__all__"] = list(names)
                elif value is not None:
                    names = _static_string_list(value, static_lists)
                    if names is None:
                        static_lists.pop(target.id, None)
                    else:
                        static_lists[target.id] = names
                if target.id == symbol:
                    binding = StaticExportResolution("resolved", target_module=module_name)
            continue

        if isinstance(statement, ast.AugAssign):
            writes = _top_level_writes(statement)
            if "__all__" in writes:
                names = _static_string_list(statement.value, static_lists)
                if (all_state == "static" and isinstance(statement.op, ast.Add) and names is not None):
                    all_names.extend(names)
                    static_lists["__all__"] = list(all_names)
                else:
                    all_state = "dynamic"
                    static_lists.pop("__all__", None)
            if symbol in writes:
                binding = StaticExportResolution(
                    "unresolved", reason=f"mutated module binding: {module_name}.{symbol}"
                )
            for name in writes - {"__all__", symbol}:
                static_lists.pop(name, None)
            continue

        if isinstance(statement, ast.Delete):
            writes = _top_level_writes(statement)
            if "__all__" in writes:
                all_state = "dynamic"
                static_lists.pop("__all__", None)
            if symbol in writes:
                binding = StaticExportResolution("not_exported", reason=f"deleted binding: {module_name}.{symbol}")
            continue

        if isinstance(statement, (ast.If, ast.Try, ast.TryStar, ast.For, ast.AsyncFor, ast.While,
                                  ast.With, ast.AsyncWith, ast.Match)):
            writes = _top_level_writes(statement)
            has_star = any(
                isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
                for node in ast.walk(statement)
            )
            if "__all__" in writes:
                all_state = "dynamic"
                static_lists.pop("__all__", None)
            if symbol in writes or has_star:
                binding = StaticExportResolution(
                    "unresolved", reason=f"conditional export binding in {module_name}"
                )

    if all_state == "dynamic":
        return StaticExportResolution("unresolved", reason=f"dynamic __all__ in {module_name}")
    if all_state == "static":
        if symbol not in all_names:
            return StaticExportResolution("not_exported", reason=f"excluded by __all__ in {module_name}")
        if binding.status == "not_exported":
            return StaticExportResolution(
                "unresolved", reason=f"__all__ names an unresolved binding: {module_name}.{symbol}"
            )
        return binding
    if symbol.startswith("_"):
        return StaticExportResolution("not_exported", reason=f"private name in {module_name}")
    if binding.status == "not_exported" and has_getattr:
        return StaticExportResolution("unresolved", reason=f"dynamic module __getattr__ in {module_name}")
    return binding
