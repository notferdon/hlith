# SPDX-License-Identifier: Apache-2.0
"""Build a bounded, source-linked account of a proposed Python effect.

This module reads the baseline repository and applies the supplied unified diff
only to a temporary copy. It never imports or executes repository code. Static
resolution is deliberately incomplete: unresolved syntax is returned with its
location instead of being treated as absent.
"""

from __future__ import annotations

import ast
import base64
import builtins
import contextlib
import difflib
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field, replace
from importlib.machinery import PathFinder
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

import tree_sitter_python
import libcst as cst
from libcst.metadata import PositionProvider
from tree_sitter import Language, Parser

from .source import ast_source_lines, ast_source_segment as _ast_source_segment, source_segment_from_lines
from .exports import resolve_static_wildcard_export
from .module_names import module_name_for_path
from ..textsafe import clean as _clean_record_text


def _provenance(
    analysis_pass: str,
    resolution: str,
    source_file: str,
    source_line: int,
    node_source: str,
) -> dict[str, Any]:
    return {
        "analysis_pass": analysis_pass,
        "resolution": resolution,
        "source_file": source_file,
        "source_line": source_line,
        "node_sha256": hashlib.sha256(node_source.encode("utf-8")).hexdigest(),
    }


@dataclass(frozen=True)
class EntryGuard:
    param: str
    raises_when: str
    literal: str | None = None
    operator: str | None = None
    type_names: tuple[str, ...] | None = None
    negated: bool | None = None
    raised_exception: str | None = None
    condition_source: str | None = None
    condition_sha256: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    node_id: str | None = None
    provenance: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "param": self.param,
            "raises_when": self.raises_when,
            "raised_exception": self.raised_exception,
            "condition_source": self.condition_source,
            "condition_sha256": self.condition_sha256,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "node_id": self.node_id,
            "provenance": self.provenance,
        }
        if self.raises_when in {"contains_literal", "compare"}:
            result["literal"] = self.literal
        if self.raises_when == "compare":
            result["operator"] = self.operator
        if self.raises_when == "isinstance":
            result["type"] = list(self.type_names or ())
            result["negated"] = self.negated
        return result


@dataclass(frozen=True)
class SideEffectPrimitive:
    qualified_name: str
    primitive: str
    file_path: str
    line_number: int
    delta: str
    provenance: dict[str, Any]


@dataclass(frozen=True)
class UnresolvedConstruct:
    file_path: str
    line_number: int
    kind: str
    source: str
    scope: str
    caller_qualified_name: str | None = None
    target_qualified_name: str | None = None
    provenance: dict[str, Any] | None = None
    side: str = "post"
    raised_exception: str | None = None
    condition_source: str | None = None
    condition_sha256: str | None = None
    node_id: str | None = None
    record_node_id: str | None = None

    def __post_init__(self) -> None:
        if self.side not in {"pre", "post", "both"}:
            raise ValueError(f"invalid unresolved construct side: {self.side}")
        if self.provenance is None:
            object.__setattr__(
                self,
                "provenance",
                _provenance(
                    "unresolved_construct_inventory",
                    "unresolved",
                    self.file_path,
                    self.line_number,
                    self.source,
                ),
            )
        if self.kind == "unsupported_entry_guard":
            if self.condition_source is None:
                object.__setattr__(self, "condition_source", self.source)
            if self.condition_sha256 is None:
                object.__setattr__(
                    self,
                    "condition_sha256",
                    hashlib.sha256((self.condition_source or "").encode("utf-8")).hexdigest(),
                )
        if self.node_id is None:
            identity_owner = (
                self.caller_qualified_name
                or self.target_qualified_name
                or self.scope
            )
            node_digest = self.provenance["node_sha256"]
            object.__setattr__(
                self,
                "node_id",
                f"{self.file_path}::{identity_owner}::{self.kind}::{node_digest}",
            )


@dataclass(frozen=True)
class UnknownEdge:
    file_path: str
    line_number: int
    caller_qualified_name: str | None
    target_qualified_name: str
    reason: str
    provenance: dict[str, Any]
    side: str = "post"


@dataclass(frozen=True)
class ModifiedCallable:
    qualified_name: str
    file_path: str
    pre_signature: str
    post_signature: str
    pre_return_signature: str | None
    post_return_signature: str | None
    pre_return_shapes: tuple[dict[str, Any], ...]
    post_return_shapes: tuple[dict[str, Any], ...]
    pre_entry_guards: tuple[dict[str, Any], ...]
    entry_guards: tuple[dict[str, Any], ...]
    pre_exceptions: tuple[str, ...]
    post_exceptions: tuple[str, ...]
    pre_exception_claims: tuple[dict[str, Any], ...]
    post_exception_claims: tuple[dict[str, Any], ...]
    line_number: int
    provenance: dict[str, Any]


@dataclass(frozen=True)
class ImpactedCallSite:
    caller_qualified_name: str
    callee_qualified_name: str
    file_path: str
    line_number: int
    n_positional: int
    keywords: tuple[str, ...]
    star_args: bool
    star_kwargs: bool
    arg_literals: dict[str, str]
    arg_sources: dict[str, str]
    is_method_call: bool
    node_source: str
    provenance: dict[str, Any]
    # Which tree the site was resolved on: impacted_call_sites come from the PRE tree, post_call_sites (and the post sites nested in
    # added / deleted callable records) from the POST tree. Without it a consumer cannot tell them apart (review A2 finding, a2rest).
    side: str = "pre"
    forwarded_keyword_parameters: tuple[str, ...] = ()
    extra_keywords_accepted: bool | None = None

    @property
    def arg_structure(self) -> dict[str, Any]:
        """Argument shape consumed by the independent call-binding layer."""
        result = {
            "n_positional": self.n_positional,
            "keywords": list(self.keywords),
            "star_args": self.star_args,
            "star_kwargs": self.star_kwargs,
            "arg_literals": dict(self.arg_literals),
            "is_method_call": self.is_method_call,
        }
        if self.extra_keywords_accepted is not None:
            result["forwarded_keyword_parameters"] = list(self.forwarded_keyword_parameters)
            result["extra_keywords_accepted"] = self.extra_keywords_accepted
        return result


@dataclass(frozen=True)
class AddedCallable:
    qualified_name: str
    module: str
    file_path: str
    post_signature: str
    provenance: dict[str, Any]
    post_call_sites: tuple[ImpactedCallSite, ...]
    reached_from: tuple[dict[str, Any], ...]
    entry_guards: tuple[dict[str, Any], ...]
    post_exceptions: tuple[str, ...]
    post_exception_claims: tuple[dict[str, Any], ...]
    unknown_edges: tuple[UnknownEdge, ...]
    unexplored_scope: str


@dataclass(frozen=True)
class DeletedCallable:
    qualified_name: str
    module: str
    file_path: str
    line_number: int
    pre_signature: str
    post_call_sites: tuple[ImpactedCallSite, ...]
    provenance: dict[str, Any]
    node_id: str
    side: str = "pre"
    unexplored_scope: str = (
        "External callers, runtime imports, dynamic dispatch/reflection, generated code, "
        "and monkey-patching may still reference this deleted callable; an empty "
        "repository call-site list does not establish safety."
    )


@dataclass(frozen=True)
class EffectAccount:
    modified_callables: tuple[ModifiedCallable, ...]
    added_callables: tuple[AddedCallable, ...]
    deleted_callables: tuple[DeletedCallable, ...]
    modified_constants: tuple[dict[str, Any], ...]
    modified_class_attributes: tuple[dict[str, Any], ...]
    modified_module_level: tuple[dict[str, Any], ...]
    callee_edges: tuple[dict[str, Any], ...]
    callee_unresolved_constructs: tuple[dict[str, Any], ...]
    impacted_test_nodes: tuple[dict[str, Any], ...]
    transitive_call_paths: tuple[dict[str, Any], ...]
    ast_equal_files: tuple[str, ...]
    impacted_call_sites: tuple[ImpactedCallSite, ...]
    post_call_sites: tuple[ImpactedCallSite, ...]
    expanded_getattr_reads: tuple[dict[str, Any], ...]
    caller_contexts: tuple[dict[str, Any], ...]
    side_effect_primitive_delta: tuple[SideEffectPrimitive, ...]
    unresolved_constructs: tuple[UnresolvedConstruct, ...]
    opaque_caller_guards: tuple[dict[str, Any], ...]
    unknown_edges: tuple[UnknownEdge, ...]
    caller_set_closed: bool
    caller_set_unexplored: str
    callee_set_closed: bool
    callee_set_unexplored: str
    closure_provenance: dict[str, Any]
    unexplored_scope: str
    index_cache_stats: dict[str, int] = field(default_factory=lambda: {
        "cache_hit_count": 0, "uncached_count": 0
    })

    @property
    def unknown_edge_count(self) -> int:
        return len(self.unknown_edges)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible account, including the structured call args."""
        result = asdict(self)
        result.pop("index_cache_stats", None)
        result["unknown_edge_count"] = self.unknown_edge_count
        result["ast_equal_files"] = list(self.ast_equal_files)
        # z3_binding consumes one explicit scope string alongside unknown edge
        # sentinels. Keep the detailed caller/callee explanations above too.
        result["unexplored_scope"] = self.unexplored_scope
        for item in result["modified_callables"]:
            item["pre_entry_guards"] = list(item["pre_entry_guards"])
            item["entry_guards"] = list(item["entry_guards"])
            item["pre_return_shapes"] = list(item["pre_return_shapes"])
            item["post_return_shapes"] = list(item["post_return_shapes"])
            item["pre_exceptions"] = list(item["pre_exceptions"])
            item["post_exceptions"] = list(item["post_exceptions"])
            item["pre_exception_claims"] = list(item["pre_exception_claims"])
            item["post_exception_claims"] = list(item["post_exception_claims"])
        for item, site in zip(result["impacted_call_sites"], self.impacted_call_sites):
            item["keywords"] = list(item["keywords"])
            if site.extra_keywords_accepted is None:
                item.pop("forwarded_keyword_parameters", None)
                item.pop("extra_keywords_accepted", None)
            item["arg_structure"] = site.arg_structure
        for item, site in zip(result["post_call_sites"], self.post_call_sites):
            item["keywords"] = list(item["keywords"])
            if site.extra_keywords_accepted is None:
                item.pop("forwarded_keyword_parameters", None)
                item.pop("extra_keywords_accepted", None)
            item["arg_structure"] = site.arg_structure
        for added_dict, added in zip(result["added_callables"], self.added_callables):
            added_dict["post_call_sites"] = list(added_dict["post_call_sites"])
            added_dict["entry_guards"] = list(added.entry_guards)
            added_dict["post_exceptions"] = list(added.post_exceptions)
            added_dict["post_exception_claims"] = list(added.post_exception_claims)
            added_dict["reached_from"] = list(added.reached_from)
            added_dict["unknown_edges"] = list(added_dict["unknown_edges"])
            for item, site in zip(added_dict["post_call_sites"], added.post_call_sites):
                item["keywords"] = list(item["keywords"])
                if site.extra_keywords_accepted is None:
                    item.pop("forwarded_keyword_parameters", None)
                    item.pop("extra_keywords_accepted", None)
                item["arg_structure"] = site.arg_structure
        for deleted_dict, deleted in zip(result["deleted_callables"], self.deleted_callables):
            deleted_dict["post_call_sites"] = list(deleted_dict["post_call_sites"])
            for item, site in zip(deleted_dict["post_call_sites"], deleted.post_call_sites):
                item["keywords"] = list(item["keywords"])
                if site.extra_keywords_accepted is None:
                    item.pop("forwarded_keyword_parameters", None)
                    item.pop("extra_keywords_accepted", None)
                item["arg_structure"] = site.arg_structure
        result["caller_contexts"] = list(result["caller_contexts"])
        result["opaque_caller_guards"] = list(result["opaque_caller_guards"])
        result["modified_constants"] = list(result["modified_constants"])
        result["modified_class_attributes"] = list(result["modified_class_attributes"])
        result["modified_module_level"] = list(result["modified_module_level"])
        result["unresolved_constructs"] = [
            {key: value for key, value in item.items() if key != "record_node_id" or value is not None}
            for item in result["unresolved_constructs"]
        ]
        result["callee_edges"] = list(result["callee_edges"])
        result["callee_unresolved_constructs"] = list(result["callee_unresolved_constructs"])
        result["impacted_test_nodes"] = list(result["impacted_test_nodes"])
        result["transitive_call_paths"] = list(result["transitive_call_paths"])
        return result


@dataclass
class _Function:
    qualified_name: str
    file_path: str
    line_number: int
    signature: str
    source: str
    entry_guards: tuple[dict[str, Any], ...]
    effects: tuple[tuple[str, int, str], ...]


@dataclass
class _RawCall:
    caller: str
    file_path: str
    line_number: int
    function_name: str
    n_positional: int
    keywords: tuple[str, ...]
    star_args: bool
    star_kwargs: bool
    arg_literals: dict[str, str]
    arg_sources: dict[str, str]
    class_name: str | None
    node_source: str


@dataclass
class _ModuleIndex:
    module_name: str
    file_path: str
    source: str
    functions_ast: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    classes_ast: dict[str, ast.ClassDef]
    module: cst.Module | None
    functions: dict[str, _Function]
    imports: dict[str, str]
    module_imports: dict[str, str]
    calls: list[_RawCall]
    unresolved: list[UnresolvedConstruct]
    call_resolution_cache: dict[tuple[int, int], tuple[str | None, bool]] = field(
        default_factory=dict,
        repr=False,
    )
    attr_writes: list[tuple[ast.AST, str]] | None = field(
        default=None,
        repr=False,
    )
    scope_bindings_cache: dict[tuple[str, bool], frozenset[str] | None] = field(
        default_factory=dict,
        repr=False,
    )
    fn_attr_writes_cache: dict[str, dict[str, list[tuple[str, int]]]] = field(
        default_factory=dict,
        repr=False,
    )


class _ModuleIndexes(dict[str, _ModuleIndex]):
    """Per-tree indexes with memoized static lookup tables and resolution caches."""

    def __init__(self, values: Any = ()) -> None:
        super().__init__(values)
        self.imported_target_cache: dict[str, str] = {}
        self.module_target_cache: dict[str, bool] = {}
        self.package_init_modules: dict[str, _ModuleIndex] | None = None
        self.class_mutation_cache: set[tuple[str, str]] | None = None
        self.import_roots: tuple[str, ...] = ()
        self._class_to_index: dict[str, _ModuleIndex] | None = None
        self._function_to_index: dict[str, _ModuleIndex] | None = None
        self._function_obj_to_index: dict[int, _ModuleIndex] | None = None
        self._module_names: set[str] | None = None
        self._module_sources: dict[str, str] | None = None
        self._mro_prefix_cache: dict[str, tuple[list[str], bool]] = {}
        self._known_base_cache: dict[tuple[str, str], bool] = {}
        self._subclass_map: dict[str, set[str]] | None = None
        self._module_export_cache: dict[tuple[str, bool], Any] = {}
        self._init_attr_class_cache: dict[tuple[str, str], str | None] = {}

    def _invalidate_derived(self) -> None:
        self.imported_target_cache.clear()
        self.module_target_cache.clear()
        self.package_init_modules = None
        self.class_mutation_cache = None
        self._class_to_index = None
        self._function_to_index = None
        self._function_obj_to_index = None
        self._module_names = None
        self._module_sources = None
        self._mro_prefix_cache.clear()
        self._known_base_cache.clear()
        self._subclass_map = None
        self._module_export_cache.clear()
        self._init_attr_class_cache.clear()

    def __setitem__(self, key: str, value: _ModuleIndex) -> None:
        super().__setitem__(key, value)
        self._invalidate_derived()

    def __delitem__(self, key: str) -> None:
        super().__delitem__(key)
        self._invalidate_derived()

    def clear(self) -> None:
        super().clear()
        self._invalidate_derived()

    def pop(self, *args: Any) -> Any:
        result = super().pop(*args)
        self._invalidate_derived()
        return result

    def update(self, *args: Any, **kwargs: Any) -> None:
        super().update(*args, **kwargs)
        self._invalidate_derived()

    def class_index_map(self) -> dict[str, _ModuleIndex]:
        if self._class_to_index is None:
            mapping: dict[str, _ModuleIndex] = {}
            for item in self.values():
                for cls_name in item.classes_ast:
                    mapping.setdefault(cls_name, item)
            self._class_to_index = mapping
        return self._class_to_index

    def function_index_map(self) -> dict[str, _ModuleIndex]:
        if self._function_to_index is None:
            mapping: dict[str, _ModuleIndex] = {}
            for item in self.values():
                for fn_name in item.functions_ast:
                    mapping.setdefault(fn_name, item)
            self._function_to_index = mapping
        return self._function_to_index

    def function_obj_index_map(self) -> dict[int, _ModuleIndex]:
        if self._function_obj_to_index is None:
            mapping: dict[int, _ModuleIndex] = {}
            for item in self.values():
                for fn_node in item.functions_ast.values():
                    mapping.setdefault(id(fn_node), item)
            self._function_obj_to_index = mapping
        return self._function_obj_to_index

    def module_names_set(self) -> set[str]:
        if self._module_names is None:
            self._module_names = {item.module_name for item in self.values()}
        return self._module_names

    def module_sources_dict(self) -> dict[str, str]:
        if self._module_sources is None:
            self._module_sources = {item.module_name: item.source for item in self.values()}
        return self._module_sources


def _class_index_for(
    class_name: str, indexes: dict[str, _ModuleIndex]
) -> _ModuleIndex | None:
    if isinstance(indexes, _ModuleIndexes):
        return indexes.class_index_map().get(class_name)
    return next((item for item in indexes.values() if class_name in item.classes_ast), None)


def _known_subclasses_for(
    lexical_class: str, indexes: dict[str, _ModuleIndex]
) -> set[str]:
    """Return every in-repo class C != lexical_class that transitively inherits from lexical_class."""
    if isinstance(indexes, _ModuleIndexes):
        smap = indexes._subclass_map
        if smap is None:
            direct_children: dict[str, set[str]] = {}
            class_map = indexes.class_index_map()
            for cls_name, cls_index in class_map.items():
                for base in cls_index.classes_ast[cls_name].bases:
                    base_name = _resolve_receiver_class_expression(cls_index, base, indexes)
                    if base_name is not None and base_name != cls_name:
                        direct_children.setdefault(base_name, set()).add(cls_name)
            smap = {}
            for base_name in direct_children:
                descendants: set[str] = set()
                pending = list(direct_children[base_name])
                while pending:
                    cur = pending.pop()
                    if cur == base_name or cur in descendants:
                        continue
                    descendants.add(cur)
                    pending.extend(direct_children.get(cur, ()))
                smap[base_name] = descendants
            indexes._subclass_map = smap
        return smap.get(lexical_class, set())
    out: set[str] = set()
    for candidate_index in indexes.values():
        for candidate_class in candidate_index.classes_ast:
            if candidate_class != lexical_class and _known_base_reaches(candidate_class, lexical_class, indexes):
                out.add(candidate_class)
    return out


def _bounded_getattr_reads(
    indexes: dict[str, _ModuleIndex], relevant_callers: set[str]
) -> list[dict[str, Any]]:
    """Expand only getattr(self, name, default) over immutable literal class attrs."""
    if not relevant_callers:
        return []

    def is_bounded_getter(node: ast.AST) -> bool:
        if not isinstance(node, ast.DictComp) or len(node.generators) != 1:
            return False
        generator = node.generators[0]
        call = node.value
        return bool(
            isinstance(generator.target, ast.Name)
            and isinstance(generator.iter, ast.Attribute)
            and generator.iter.attr == "__attrs__"
            and isinstance(generator.iter.value, ast.Name)
            and generator.iter.value.id == "self"
            and isinstance(node.key, ast.Name)
            and node.key.id == generator.target.id
            and isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "getattr"
            and len(call.args) == 3
            and not call.keywords
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "self"
            and isinstance(call.args[1], ast.Name)
            and call.args[1].id == generator.target.id
        )

    candidates = [
        (index, qualified, function, node)
        for index in indexes.values()
        for qualified, function in index.functions_ast.items()
        if qualified in relevant_callers
        for node in ast.walk(function)
        if is_bounded_getter(node)
    ]
    if not candidates:
        return []
    relevant_classes = {name.rsplit(".", 1)[0] for name in relevant_callers if "." in name}
    classes: dict[str, tuple[_ModuleIndex, ast.ClassDef, tuple[str, ...], str]] = {}
    for index in indexes.values():
        for qualified, class_node in index.classes_ast.items():
            if qualified not in relevant_classes:
                continue
            for statement in class_node.body:
                value: ast.AST | None = None
                if isinstance(statement, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "__attrs__" for target in statement.targets
                ):
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.target.id == "__attrs__":
                    value = statement.value
                if value is None:
                    continue
                assignment_count = sum(
                    1
                    for candidate in class_node.body
                    if (isinstance(candidate, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "__attrs__" for target in candidate.targets
                    ))
                    or (isinstance(candidate, ast.AnnAssign) and isinstance(candidate.target, ast.Name) and candidate.target.id == "__attrs__")
                    or (isinstance(candidate, ast.AugAssign) and isinstance(candidate.target, ast.Name) and candidate.target.id == "__attrs__")
                )
                if assignment_count != 1:
                    break
                try:
                    attrs = ast.literal_eval(value)
                except (ValueError, TypeError, SyntaxError):
                    continue
                if isinstance(attrs, (list, tuple)) and all(isinstance(attr, str) for attr in attrs):
                    source = _ast_source_segment(index.source, statement) or ast.unparse(statement)
                    classes[qualified] = (index, class_node, tuple(attrs), source)
                    break

    # Any executable reassignment or in-place mutation makes the class list
    # unsuitable as a finite, stable expansion source.
    mutable_classes: set[str] = set()
    for index in indexes.values():
        if not index.source or "__attrs__" not in index.source:
            continue
        class_stack: list[str] = []

        class MutationVisitor(ast.NodeVisitor):
            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                class_stack.append(node.name)
                for statement in node.body:
                    self.visit(statement)
                class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                for statement in node.body:
                    self.visit(statement)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Lambda(self, node: ast.Lambda) -> None:
                self.visit(node.body)

            def visit_Assign(self, node: ast.Assign) -> None:
                self._check_targets(node.targets)
                self.generic_visit(node.value)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                self._check_targets([node.target])
                if node.value:
                    self.visit(node.value)

            def visit_AugAssign(self, node: ast.AugAssign) -> None:
                self._check_targets([node.target])
                self.visit(node.value)

            def _check_targets(self, targets: list[ast.expr]) -> None:
                for target in targets:
                    for child in ast.walk(target):
                        if isinstance(child, ast.Attribute) and child.attr == "__attrs__":
                            if isinstance(child.ctx, ast.Store):
                                if isinstance(child.value, ast.Name) and child.value.id == "self" and class_stack:
                                    mutable_classes.add(".".join([index.module_name, *class_stack]))
                                else:
                                    mutable_classes.add("*")
                        if isinstance(child, ast.Subscript) and isinstance(child.value, ast.Attribute) and child.value.attr == "__attrs__":
                            if isinstance(child.ctx, ast.Store):
                                if isinstance(child.value.value, ast.Name) and child.value.value.id == "self" and class_stack:
                                    mutable_classes.add(".".join([index.module_name, *class_stack]))
                                else:
                                    mutable_classes.add("*")

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse"
                }:
                    receiver = node.func.value
                    if isinstance(receiver, ast.Attribute) and receiver.attr == "__attrs__":
                        if isinstance(receiver.value, ast.Name) and receiver.value.id == "self" and class_stack:
                            mutable_classes.add(".".join([index.module_name, *class_stack]))
                        else:
                            mutable_classes.add("*")
                self.generic_visit(node)

            def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                if isinstance(node.target, ast.Name) and node.target.id == "__attrs__" and class_stack:
                    mutable_classes.add(".".join([index.module_name, *class_stack]))
                self.visit(node.value)

        MutationVisitor().visit(ast.parse(index.source))
    if "*" in mutable_classes:
        classes.clear()
    else:
        for mutable_class in mutable_classes:
            classes.pop(mutable_class, None)

    result: list[dict[str, Any]] = []
    for index, qualified, function, node in candidates:
        class_name = qualified.rsplit(".", 1)[0] if "." in qualified else ""
        class_record = classes.get(class_name)
        if class_record is None:
            continue
        attr_index, class_node, attrs, assignment_source = class_record
        attr_line = next(
            statement.lineno
            for statement in class_node.body
            if (isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__attrs__" for target in statement.targets))
            or (isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.target.id == "__attrs__")
        )
        call = node.value
        getter_source = _ast_source_segment(index.source, call) or ast.unparse(call)
        for attr in attrs:
            result.append({
                "file_path": index.file_path,
                "line_number": call.lineno,
                "caller_qualified_name": qualified,
                "attribute": attr,
                "attr_assignment": {"file_path": attr_index.file_path, "line_number": attr_line},
                "node_source": getter_source,
                "provenance": _provenance(
                    "bounded_literal_getattr_expansion",
                    "resolved",
                    attr_index.file_path,
                    attr_line,
                    assignment_source,
                ),
                "read_node_sha256": hashlib.sha256(getter_source.encode("utf-8")).hexdigest(),
            })
    return sorted(result, key=lambda item: (item["file_path"], item["line_number"], item["attribute"]))


_IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", "build", "dist",
}

_BINDING_ONLY_UNRESOLVED_KINDS = frozenset(
    {"unsupported_entry_guard", "callable_ast_not_located", "decorator_varargs_forwarding"}
)


def build_effect_account(
    repo_path: str | os.PathLike[str], unified_diff: str, *, use_index_cache: bool = True
) -> EffectAccount:
    """Account for changed Python callables and the bounded call slice around them.

    Legacy entry for unmigrated callers: the post tree is a private copy of ``repo_path`` plus the patch. The
    persistent index cache is OFF on this path whatever ``use_index_cache`` says: L2 never writes the target or its
    git directory. The contract entry is ``hlith.effect.api.EffectService.build_account``."""
    del use_index_cache
    return _build_account(repo_path, unified_diff, post_root=None, cache_dir=None)


@contextlib.contextmanager
def _post_tree(root: Path, unified_diff: str, post_root: Path | None):
    """Yield the READ-ONLY post tree: the sealed post snapshot when given, else a private copy + the patch."""
    if post_root is not None:
        yield post_root
        return
    with tempfile.TemporaryDirectory(prefix="hlith-effect-") as temporary:
        candidate = Path(temporary) / "candidate"
        shutil.copytree(root, candidate, symlinks=True, ignore=_ignore_copy)
        from ..gitsafe import run_plain  # plain copy (no .git): scrubbed env, _HARDEN, ceiling at its parent
        applied = run_plain(candidate, ("apply", "--whitespace=nowarn", "-"), input=unified_diff, text=True)
        if applied.returncode != 0:
            message = applied.stderr.strip() or applied.stdout.strip() or "git apply failed"
            raise ValueError(f"unified diff does not apply to the repository snapshot: {message}")
        yield candidate


def _build_account(
    repo_path: str | os.PathLike[str], unified_diff: str, *, post_root: Path | None, cache_dir: Path | None
) -> EffectAccount:
    """The whole account from the pre tree ``repo_path`` and the post tree (``post_root`` or copy + patch).
    Neither tree is written. ``cache_dir``: host-owned directory outside every repository and git dir, or None."""
    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {root}")
    changed_paths = _changed_paths(unified_diff)
    if not changed_paths:
        raise ValueError("unified diff contains no changed file paths")

    with _post_tree(root, unified_diff, post_root) as candidate:
        ast_equal_files = tuple(sorted(
            path for path in changed_paths
            if path.endswith(".py")
            and _same_python_semantics(root / path, candidate / path)
        ))
        cache_stats = {"cache_hit_count": 0, "uncached_count": 0}
        before = _index_tree(
            root,
            changed_paths,
            cache_dir=cache_dir,
            cache_stats=cache_stats,
        )
        # The candidate is an exact copy of the repository plus the patch.
        # Reuse every unchanged module index and parse only changed Python
        # paths; whole-tree repos otherwise pay the AST scan twice per run.
        after = _index_tree(
            candidate,
            changed_paths,
            reuse_indexes=before,
        )
        before_functions = _function_code(before)
        after_functions = _function_code(after)
        changed_path_set = set(changed_paths)
        deleted_names = {
            name
            for name in before_functions.keys() - after_functions.keys()
            if before_functions[name].file_path in changed_path_set
        }
        # Deletions have their own account record and derive path. Keeping them
        # in modified_callables would send an absent post definition through
        # binding/differential as UNKNOWN as well as emitting a blocker.
        modified = [
            item for item in _modified_functions(before, after, changed_paths)
            if item.qualified_name not in deleted_names
        ]
        syntax_identities, syntax_unresolved = _syntax_node_identities(
            before, after, changed_paths
        )
        modified = [
            _with_syntax_identity(item, syntax_identities.get(item.qualified_name))
            for item in modified
        ]
        added_names = {
            name
            for name in after_functions.keys() - before_functions.keys()
            if after_functions[name].file_path in changed_paths
        }
        target_names = {item.qualified_name for item in modified}
        affected_callers = (
            _reachable_callers(before, target_names)
            | _reachable_callers(after, target_names)
        )
        expanded_getattr_reads = _bounded_getattr_reads(after, affected_callers)
        expanded_getattr_sites = {
            (item["caller_qualified_name"], item["node_source"])
            for item in [*_bounded_getattr_reads(before, affected_callers), *expanded_getattr_reads]
        }
        call_sites, call_unresolved, forwarded_before = _resolve_impacted_calls(before, target_names)
        post_call_sites, post_call_unresolved, forwarded_after = _resolve_impacted_calls(after, target_names)
        post_call_sites = [replace(item, side="post") for item in post_call_sites]
        forwarding_targets = {"pre": forwarded_before, "post": forwarded_after}
        call_unresolved = [replace(item, side="pre") for item in call_unresolved]
        post_call_unresolved = [replace(item, side="post") for item in post_call_unresolved]
        caller_contexts = _caller_contexts(before, after, call_sites, post_call_sites)
        effects = _effect_delta(modified, before, after)
        before_unresolved = _unresolved_inventory(
            before, changed_paths, side="pre", root=root, other_parsed_paths=set(after)
        )
        after_unresolved = _unresolved_inventory(after, changed_paths, side="post")
        guard_records, guard_notes = _compare_unsupported_guards(
            modified, before_unresolved, after_unresolved
        )
        guard_records = _drop_literal_covered_modelled_guards(
            guard_records, modified, post_call_sites
        )
        changed_callable_names = {item.qualified_name for item in modified}
        rebound = _rebound_callables(before, after, deleted_names)
        rebound_unresolved = [
            UnresolvedConstruct(
                file_path=file_path, line_number=line, kind="unsupported_rebinding",
                source=f"{name.rsplit('.', 1)[-1]} is rebound at module level (the def was replaced by an assignment/alias/import)",
                # scope changed_file: the rebound name is neither a modified callable nor a target, and the record
                # filter below keeps changed-file scope unconditionally (a rebinding must never be dropped silently)
                scope="changed_file", caller_qualified_name=name, target_qualified_name=name,
                provenance=_provenance("static_module_level_binding", "unresolved", file_path, line,
                                       "a removed def whose name is still bound: behaviour of the new binding is not modelled"),
                side="post",
            )
            for name, (file_path, line) in sorted(rebound.items())
        ]
        all_unresolved = [
            item
            for item in [*before_unresolved, *after_unresolved, *syntax_unresolved, *rebound_unresolved]
            if not (
                item.kind == "dynamic_getattr"
                and (item.caller_qualified_name, item.source) in expanded_getattr_sites
            ) and not (
                item.kind == "unsupported_entry_guard" and item.caller_qualified_name in changed_callable_names
            )
        ]
        modified_constants = _modified_constant_records(before, after, changed_paths)
        modified_class_attributes = _modified_class_attribute_records(before, after, changed_paths)
        modified_module_level = _modified_module_level_records(
            before, after, changed_paths, modified_constants
        )
        all_unresolved.extend(_module_level_unresolved_records(modified_module_level))
        all_unresolved.extend(guard_records)
        all_unresolved.extend(
            _changed_guard_exceptions(
                modified, before_functions, after_functions
            )
        )
        all_unresolved.extend(call_unresolved)
        all_unresolved.extend(post_call_unresolved)
        if forwarded_before or forwarded_after:
            retagged: list[UnresolvedConstruct] = []
            for item in all_unresolved:
                item_targets = forwarding_targets.get(item.side, {})
                target = item_targets.get(item.target_qualified_name or "")
                if target is None and item.target_qualified_name is None and item.kind in {
                    "dynamic_getattr", "dynamic_call", "dynamic_import", "unknown_call", "unresolved_call"
                }:
                    target = next((
                        candidate
                        for wrapper, candidate in item_targets.items()
                        if _mentions_identifier(item.source, wrapper.rsplit(".", 1)[-1])
                    ), None)
                retagged.append(
                    replace(item, target_qualified_name=target)
                    if target is not None
                    else item
                )
            all_unresolved = retagged
        caller_guard_notes: list[str] = []
        nonblocking_caller_guards: set[tuple[Any, ...]] = set()
        caller_guards_before = [
            item for item in before_unresolved
            if item.kind == "unsupported_entry_guard" and item.caller_qualified_name in affected_callers
        ]
        caller_guards_after = [
            item for item in after_unresolved
            if item.kind == "unsupported_entry_guard" and item.caller_qualified_name in affected_callers
        ]
        before_guard_fingerprints: dict[tuple[Any, ...], list[UnresolvedConstruct]] = {}
        for item in caller_guards_before:
            if item.caller_qualified_name in changed_callable_names:
                continue
            fingerprint = _opaque_caller_guard_identity(item)
            if fingerprint is not None:
                before_guard_fingerprints.setdefault(fingerprint, []).append(item)
        opaque_guard_records: dict[str, dict[str, Any]] = {}
        for item in caller_guards_after:
            if item.caller_qualified_name in changed_callable_names:
                continue
            fingerprint = _opaque_caller_guard_identity(item)
            previous = before_guard_fingerprints.get(fingerprint) if fingerprint is not None else None
            if not previous:
                continue
            if not _guard_dominates_reachable_call(
                item, (before, after), affected_callers
            ):
                nonblocking_caller_guards.add(fingerprint)
                caller_guard_notes.append(
                    f"Unchanged or non-dominating caller guard unexplored at "
                    f"{item.file_path}:{item.line_number} unsupported_entry_guard in "
                    f"{item.caller_qualified_name}: {item.source}"
                )
                continue
            assert item.node_id is not None
            guard_record = asdict(replace(item, side="both"))
            guard_record.pop("record_node_id", None)
            opaque_guard_records[item.node_id] = {
                **guard_record,
                "callsite_coverage": "both_polarities",
            }
            nonblocking_caller_guards.add(fingerprint)
            for prior in previous:
                nonblocking_caller_guards.add(
                    _opaque_caller_guard_identity(prior) or fingerprint
                )
            caller_guard_notes.append(
                f"Opaque unchanged caller guard at {item.file_path}:{item.line_number} "
                f"in {item.caller_qualified_name}: {item.source}; its syntactic call sites "
                f"remain checked under both predicate polarities (node_id={item.node_id}, "
                f"node_sha256={item.provenance['node_sha256']})."
            )
        for item in modified:
            if item.pre_signature == "UNKNOWN":
                all_unresolved.append(
                    UnresolvedConstruct(
                        file_path=item.file_path,
                        line_number=1,
                        kind="callable_absent_in_baseline",
                        source=item.qualified_name,
                        scope="modified_callable",
                        target_qualified_name=item.qualified_name,
                    )
                )
            if item.post_signature == "UNKNOWN":
                all_unresolved.append(
                    UnresolvedConstruct(
                        file_path=item.file_path,
                        line_number=1,
                        kind="callable_absent_in_candidate",
                        source=item.qualified_name,
                        scope="modified_callable",
                        target_qualified_name=item.qualified_name,
                    )
                )

    changed_path_set = set(changed_paths)
    known_callables = {
        name
        for indexes in (before, after)
        for index in indexes.values()
        for name in index.functions_ast
    }
    all_unresolved_records = _dedupe_unresolved(all_unresolved)
    production_callers = {
        site.caller_qualified_name
        for site in (*call_sites, *post_call_sites)
        if not _is_test_file_path(site.file_path)
    }
    nonblocking_test_dynamic = [
        item for item in all_unresolved_records
        if item.kind == "dynamic_getattr"
        and _is_test_file_path(item.file_path)
        and item.file_path not in changed_path_set
        and item.caller_qualified_name not in changed_callable_names
        and item.caller_qualified_name not in production_callers
    ]
    nonblocking_test_dynamic_keys = {_unresolved_key(item) for item in nonblocking_test_dynamic}
    callee_edges, callee_unresolved = _callee_cone_records(
        before, after, modified, all_unresolved_records
    )
    unresolved_records = tuple(
        item for item in all_unresolved_records
        if (
            item.caller_qualified_name in affected_callers
            or item.target_qualified_name in target_names
            or (item.file_path in changed_path_set and item.caller_qualified_name not in known_callables)
            or item.scope == "changed_file"
        )
        and _unresolved_key(item) not in nonblocking_test_dynamic_keys
        and not (
            item.kind == "unsupported_entry_guard"
            and item.caller_qualified_name not in changed_callable_names
            and _opaque_caller_guard_identity(item) in nonblocking_caller_guards
        )
        and not (
            item.kind == "callable_absent_in_baseline"
            and item.target_qualified_name in added_names
        )
        and not (
            item.kind in _BINDING_ONLY_UNRESOLVED_KINDS
            and item.caller_qualified_name not in affected_callers
        )
    )
    blocking_analysis_failures = {
        _unresolved_key(item)
        for item in unresolved_records
        if item.kind == "analysis_failed"
    }
    unexplored_analysis_failures = {
        (item.file_path, item.line_number, item.source.split(":", 1)[0])
        for item in all_unresolved_records
        if item.kind == "analysis_failed" and _unresolved_key(item) not in blocking_analysis_failures
    }
    excluded_unresolved_count = len(all_unresolved_records) - len(unresolved_records)
    excluded_sites = sorted({
        f"{item.file_path}:{item.line_number} {item.kind} in "
        f"{item.caller_qualified_name or item.scope}"
        for item in all_unresolved_records
        if item not in unresolved_records and item.file_path in changed_path_set
    })
    excluded_summary = (
        f" Excluded sites: {'; '.join(excluded_sites)}" if excluded_sites else ""
    )
    unknown_edges = tuple(
        UnknownEdge(
            file_path=item.file_path,
            line_number=item.line_number,
            caller_qualified_name=item.caller_qualified_name,
            target_qualified_name=(
                item.target_qualified_name
                or (item.caller_qualified_name if item.caller_qualified_name in target_names else None)
                or "UNKNOWN"
            ),
            reason=f"unresolved construct: {item.kind}",
            provenance=_provenance(
                "unknown_edge_construction",
                "unresolved",
                item.file_path,
                item.line_number,
                item.source,
            ),
            side=item.side,
        )
        for item in unresolved_records
        if item.side in {"post", "both"}
    )
    caller_unexplored = (
        "Callers outside this repository snapshot, dynamic dispatch/reflection, generated code, "
        "and imports resolved only at runtime are not enumerated."
    )
    callee_unexplored = (
        "External packages, C/FFI calls, dynamic imports, runtime monkey-patching, and "
        "unresolved call targets are not closed by this static account."
    )
    guard_unexplored = " ".join([*guard_notes, *caller_guard_notes])
    pre_only_unresolved = [item for item in unresolved_records if item.side == "pre"]
    pre_only_summary = " ".join(
        f"Pre-only unresolved history at {item.file_path}:{item.line_number} {item.kind}: {item.source}."
        for item in pre_only_unresolved
    )
    unexplored_scope = (
        f"Caller set: {caller_unexplored} Callee set: {callee_unexplored} "
        f"Excluded {excluded_unresolved_count} unrelated unresolved constructs from the repository-wide inventory."
        f"{excluded_summary}"
        + (f" {guard_unexplored}" if guard_unexplored else "")
        + (f" {pre_only_summary}" if pre_only_summary else "")
    )
    if nonblocking_test_dynamic:
        test_dynamic_details = sorted({
            f"{item.file_path}:{item.line_number} dynamic_getattr in {item.caller_qualified_name or item.scope}"
            for item in nonblocking_test_dynamic
        })
        unexplored_scope += (
            " Nonblocking test-file dynamic getattr constructs (test execution is evidence; "
            "these are not production caller edges): " + "; ".join(test_dynamic_details) + "."
        )
    if unexplored_analysis_failures:
        failure_details = "; ".join(
            f"{file_path}:{line_number} {exception_name}"
            for file_path, line_number, exception_name in sorted(unexplored_analysis_failures)
        )
        unexplored_scope += f" Per-file analysis failed outside the changed/impact slice: {failure_details}."
    if callee_unresolved:
        unexplored_scope += " Callee-cone constructs are evidence only (not gate blockers): " + "; ".join(
            f"{item['file_path']}:{item['line_number']} {item['kind']} in {item['callee_qualified_name']}"
            for item in callee_unresolved
        ) + "."
    modified_existing_names = {
        item.qualified_name
        for item in modified
        if item.qualified_name in before_functions and item.qualified_name in after_functions
    }
    added_records = _added_callable_records(
        added_names=added_names,
        after=after,
        post_call_sites=post_call_sites,
        modified_callers=modified_existing_names,
        unknown_edges=unknown_edges,
        unexplored_scope=unexplored_scope,
    )
    added_records = [
        _with_syntax_identity(item, syntax_identities.get(item.qualified_name))
        for item in added_records
    ]
    deleted_records = _deleted_callable_records(
        before, after, changed_paths, syntax_identities
    )
    impacted_test_nodes = _impacted_test_nodes(before, after, target_names)
    transitive_call_paths = _transitive_call_paths(before, after, target_names)
    return EffectAccount(
        # An added callable is ADDED, not modified (A2): it stays in the internal ``modified`` list above only as a
        # call-site/impact TARGET (its post call sites, reachability, unknown edges and tests); its account record is
        # the added_callables entry, never a modified one with pre_signature UNKNOWN. Deletions are excluded likewise.
        modified_callables=tuple(item for item in modified if item.qualified_name not in added_names),
        added_callables=tuple(added_records),
        deleted_callables=tuple(deleted_records),
        modified_constants=tuple(modified_constants),
        modified_class_attributes=tuple(modified_class_attributes),
        modified_module_level=tuple(modified_module_level),
        callee_edges=tuple(callee_edges),
        callee_unresolved_constructs=tuple(callee_unresolved),
        impacted_test_nodes=tuple(impacted_test_nodes),
        transitive_call_paths=tuple(transitive_call_paths),
        ast_equal_files=ast_equal_files,
        impacted_call_sites=tuple(call_sites),
        post_call_sites=tuple(post_call_sites),
        expanded_getattr_reads=tuple(expanded_getattr_reads),
        caller_contexts=tuple(caller_contexts),
        side_effect_primitive_delta=tuple(effects),
        unresolved_constructs=unresolved_records,
        opaque_caller_guards=tuple(
            opaque_guard_records[node_id] for node_id in sorted(opaque_guard_records)
        ),
        unknown_edges=unknown_edges,
        caller_set_closed=False,
        caller_set_unexplored=caller_unexplored,
        callee_set_closed=False,
        callee_set_unexplored=callee_unexplored,
        closure_provenance=_provenance(
            "static_repository_call_graph_scan",
            "assumed",
            "<repository-index>",
            0,
            f"caller-set-open: {caller_unexplored}; callee-set-open: {callee_unexplored}",
        ),
        unexplored_scope=unexplored_scope,
        index_cache_stats=cache_stats,
    )


_CONDITIONAL_TS_NODES = frozenset({
    "if_statement",
    "elif_clause",
    "else_clause",
    "try_statement",
    "except_clause",
    "except_group_clause",
    "finally_clause",
    "match_statement",
    "case_clause",
})


def _tree_sitter_callable_nodes(
    source: str, module_name: str, file_path: str
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Index function syntax nodes with stable qualified identities, or report a parse error."""
    parser = Parser(Language(tree_sitter_python.language()))
    tree = parser.parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        return {}, "tree-sitter-python produced an error node"

    result: dict[str, dict[str, Any]] = {}

    def python_qualname(classes: tuple[str, ...], functions: tuple[str, ...], name: str) -> str:
        parts = [module_name, *classes]
        if functions:
            parts.append(functions[0])
            for function in functions[1:]:
                parts.extend(("<locals>", function))
            parts.extend(("<locals>", name))
        else:
            parts.append(name)
        return ".".join(parts)

    def nested_node_id(qualname: str, start_line: int) -> str:
        return f"{file_path}::{qualname}::line:{start_line}"

    def add_group_node(info: dict[str, Any], list_key: str, node_info: dict[str, Any]) -> None:
        items = [*info.get(list_key, ()), node_info]
        items.sort(key=lambda item: (item["start_line"], item["node_sha256"]))
        info[list_key] = items
        hashes = "\0".join(item["node_sha256"] for item in items)
        info["node_sha256"] = hashlib.sha256(hashes.encode("ascii")).hexdigest()
        info["start_line"] = min(item["start_line"] for item in items)
        info["end_line"] = max(item["end_line"] for item in items)

    def walk(
        node: Any,
        classes: tuple[str, ...],
        functions: tuple[str, ...],
        conditional: bool = False,
    ) -> None:
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return
            name = name_node.text.decode("utf-8")
            for child in node.named_children:
                walk(child, (*classes, name), functions, conditional)
            return
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return
            name = name_node.text.decode("utf-8")
            qualified_name = ".".join((module_name, *classes, *functions, name))
            is_nested = bool(functions)
            display_name = python_qualname(classes, functions, name)
            start_line = node.start_point.row + 1
            node_sha256 = hashlib.sha256(node.text or b"").hexdigest()
            info = {
                "node_id": f"{file_path}::{display_name}",
                "node_type": node.type,
                "node_sha256": node_sha256,
                "start_line": start_line,
                "end_line": node.end_point.row + 1,
                "conditional": conditional,
            }
            if is_nested:
                enclosing = ".".join((module_name, *classes, functions[0]))
                node_info = {
                    **info,
                    "qualified_name": display_name,
                    "enclosing_qualified_name": enclosing,
                    "node_id": nested_node_id(display_name, start_line),
                }
                prior = result.get(qualified_name)
                if prior is None:
                    info.update(
                        {
                            "nested": True,
                            "qualified_name": display_name,
                            "enclosing_qualified_name": enclosing,
                            "node_id": f"{file_path}::{display_name}",
                            "nested_nodes": [],
                        }
                    )
                    add_group_node(info, "nested_nodes", node_info)
                    result[qualified_name] = info
                elif prior.get("nested"):
                    add_group_node(prior, "nested_nodes", node_info)
                else:
                    result[qualified_name] = {"duplicate": True}
            elif qualified_name in result:
                prior = result[qualified_name]
                if not prior.get("duplicate") and (
                    conditional or prior.get("conditional") or prior.get("conditional_duplicate")
                ):
                    node_info = {
                        **info,
                        "qualified_name": display_name,
                        "node_id": nested_node_id(display_name, start_line),
                    }
                    if not prior.get("conditional_duplicate"):
                        first_node = {
                            **prior,
                            "qualified_name": display_name,
                            "node_id": nested_node_id(display_name, prior["start_line"]),
                        }
                        prior = {
                            "node_id": f"{file_path}::{display_name}",
                            "node_type": node.type,
                            "conditional_duplicate": True,
                            "qualified_name": display_name,
                            "conditional_nodes": [],
                        }
                        add_group_node(prior, "conditional_nodes", first_node)
                        result[qualified_name] = prior
                    add_group_node(prior, "conditional_nodes", node_info)
                else:
                    result[qualified_name] = {"duplicate": True}
            else:
                result[qualified_name] = info
            for child in node.named_children:
                walk(child, classes, (*functions, name), False)
            return
        child_conditional = conditional or (node.type in _CONDITIONAL_TS_NODES)
        for child in node.named_children:
            walk(child, classes, functions, child_conditional)

    walk(tree.root_node, (), ())
    return result, None


def _syntax_node_identities(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
) -> tuple[dict[str, dict[str, Any]], list[UnresolvedConstruct]]:
    """Cross-check LibCST callable identity with tree-sitter on both trees.

    A parser error or disagreement is an explicit blocking account fact; neither
    parser silently wins. Matched callables retain a stable file/qualified-name
    identity and side-specific syntax digests in their provenance.
    """
    by_side: dict[str, dict[str, dict[str, Any]]] = {"pre": {}, "post": {}}
    unresolved: list[UnresolvedConstruct] = []
    for side, indexes in (("pre", before), ("post", after)):
        for relative in changed_paths:
            if not relative.endswith(".py"):
                continue
            index = next(
                (item for item in indexes.values() if item.file_path == relative),
                None,
            )
            if index is None or not index.source:
                continue
            try:
                nodes, error = _tree_sitter_callable_nodes(
                    index.source, index.module_name, index.file_path
                )
            except Exception as exc:
                detail = type(exc).__name__
                if str(exc):
                    detail += f": {str(exc)[:180]}"
                unresolved.append(
                    UnresolvedConstruct(
                        file_path=relative,
                        line_number=max(1, int(getattr(exc, "lineno", 1) or 1)),
                        kind="analysis_failed",
                        source=detail,
                        scope="changed_file",
                        side=side,
                    )
                )
                continue
            libcst_names = set(index.functions)
            tree_names = set(nodes)
            duplicates = sorted(name for name, item in nodes.items() if item.get("duplicate"))
            if error or duplicates or libcst_names != tree_names:
                detail = (
                    error
                    or f"LibCST/tree-sitter callable identities differ: "
                    f"libcst_only={sorted(libcst_names - tree_names)}, "
                    f"tree_sitter_only={sorted(tree_names - libcst_names)}, "
                    f"duplicates={duplicates}"
                )
                unresolved.append(
                    UnresolvedConstruct(
                        file_path=relative,
                        line_number=1,
                        kind="syntax_parser_disagreement",
                        source=detail,
                        scope="changed_file",
                        provenance=_provenance(
                            "tree_sitter_libcst_identity_crosscheck",
                            "unresolved",
                            relative,
                            1,
                            detail,
                        ),
                        side=side,
                    )
                )
            for name, info in nodes.items():
                if not info.get("duplicate"):
                    by_side[side][name] = info

    identities: dict[str, dict[str, Any]] = {}
    for name in sorted(set(by_side["pre"]) | set(by_side["post"])):
        pre_node = by_side["pre"].get(name)
        post_node = by_side["post"].get(name)
        exemplar = post_node or pre_node or {}
        file_path = exemplar.get("node_id", "").split("::", 1)[0]
        identities[name] = {
            "analysis_pass": "tree_sitter_python_cross_tree_node_identity",
            "resolution": "resolved",
            "node_id": exemplar.get("node_id") if exemplar.get("nested") else f"{file_path}::{name}",
            "pre": pre_node,
            "post": post_node,
        }
        if exemplar.get("nested"):
            identities[name]["nested"] = True
            identities[name]["qualified_name"] = exemplar.get("qualified_name")
            identities[name]["enclosing_qualified_name"] = exemplar.get("enclosing_qualified_name")
            identities[name]["nested_nodes"] = exemplar.get("nested_nodes", [])
        if (pre_node or {}).get("conditional_duplicate") or (post_node or {}).get("conditional_duplicate"):
            pre_nodes = (pre_node or {}).get("conditional_nodes") or ([pre_node] if pre_node else [])
            post_nodes = (post_node or {}).get("conditional_nodes") or ([post_node] if post_node else [])
            identities[name]["conditional_duplicate"] = True
            identities[name]["conditional_nodes"] = exemplar.get("conditional_nodes", [])
            if [n["node_sha256"] for n in pre_nodes] != [n["node_sha256"] for n in post_nodes]:
                pre_hashes = {n["node_sha256"] for n in pre_nodes}
                post_hashes = {n["node_sha256"] for n in post_nodes}
                changed_post = [n for n in post_nodes if n["node_sha256"] not in pre_hashes]
                changed_pre = [n for n in pre_nodes if n["node_sha256"] not in post_hashes]
                changed = (
                    changed_post[0]
                    if changed_post
                    else (changed_pre[0] if changed_pre else (post_nodes[0] if post_nodes else pre_nodes[0]))
                )
                changed_line = int(changed["start_line"])
                all_lines = sorted({int(n["start_line"]) for n in [*pre_nodes, *post_nodes]})
                unresolved.append(
                    UnresolvedConstruct(
                        file_path=file_path,
                        line_number=changed_line,
                        kind="conditional_duplicate_def",
                        source=(
                            f"conditional duplicate def for {name}: changed at line {changed_line} "
                            f"(all defs at lines {all_lines}); guard not evaluated"
                        ),
                        scope="changed_file",
                        caller_qualified_name=name,
                        provenance=_provenance(
                            "tree_sitter_libcst_identity_crosscheck",
                            "unresolved",
                            file_path,
                            changed_line,
                            f"conditional duplicate def for {name} at lines {all_lines}",
                        ),
                        side="both",
                    )
                )
    return identities, unresolved


def _with_syntax_identity(record: Any, identity: dict[str, Any] | None) -> Any:
    if identity is None:
        return record
    return replace(
        record,
        provenance={**record.provenance, "syntax_node_identity": identity},
    )


def _python_ast_fingerprint(path: Path) -> str | None:
    """Parse through LibCST, then normalize trivia, parentheses, and quote style."""
    try:
        source = path.read_text(encoding="utf-8")
        module = cst.parse_module(source)
        parsed = ast.parse(module.code, filename=str(path), type_comments=True)
    except Exception:
        return None
    return _account_ast_dump(parsed)


def _account_ast_dump(node: ast.AST) -> str:
    """AST identity for the supported Python 3 target, ignoring the obsolete u-string prefix."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str) and child.kind == "u":
            child.kind = None
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _same_python_semantics(before: Path, after: Path) -> bool:
    before_ast = _python_ast_fingerprint(before)
    return before_ast is not None and before_ast == _python_ast_fingerprint(after)


def _normalise_guard_source(source: str) -> str | None:
    """Normalize a guard expression structurally while ignoring source formatting."""
    try:
        expression = ast.parse(source, mode="eval").body
    except (SyntaxError, ValueError):
        return None
    return ast.dump(expression, annotate_fields=True, include_attributes=False)


def _opaque_caller_guard_identity(item: UnresolvedConstruct) -> tuple[Any, ...] | None:
    """Identify an unchanged caller predicate that remains conservatively in scope."""
    if item.caller_qualified_name is None or item.node_id is None:
        return None
    normalized = _normalise_guard_source(item.condition_source or item.source)
    if normalized is None:
        return None
    return (
        item.file_path,
        item.caller_qualified_name,
        normalized,
        item.raised_exception,
        item.node_id,
    )


def _compare_unsupported_guards(
    modified: list[ModifiedCallable],
    before: list[UnresolvedConstruct],
    after: list[UnresolvedConstruct],
) -> tuple[list[UnresolvedConstruct], list[str]]:
    """Keep new/uncertain post guards blocking; record unchanged guards as scope loss."""
    by_name = {item.qualified_name: item for item in modified}
    before_by_name: dict[str, list[UnresolvedConstruct]] = {}
    after_by_name: dict[str, list[UnresolvedConstruct]] = {}
    for records, grouped in ((before, before_by_name), (after, after_by_name)):
        for item in records:
            if item.kind == "unsupported_entry_guard" and item.caller_qualified_name in by_name:
                grouped.setdefault(item.caller_qualified_name, []).append(item)

    blocking: list[UnresolvedConstruct] = []
    notes: list[str] = []

    def resolved_guard_parts(guard: dict[str, Any]) -> tuple[tuple[Any, ...], tuple[str, ...], tuple[str, ...], str] | None:
        provenance = guard.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("resolution") != "resolved":
            return None
        return (
            (
                guard.get("param"),
                guard.get("raises_when"),
                guard.get("literal"),
                guard.get("operator"),
                guard.get("negated"),
                guard.get("raised_exception"),
            ),
            tuple(str(name) for name in guard.get("type", ())),
            tuple(str(item) for item in provenance.get("assumptions", ())),
            str(provenance.get("analysis_pass") or ""),
        )

    def resolved_guards_match(before_guard: dict[str, Any], after_guard: dict[str, Any]) -> bool:
        before_parts = resolved_guard_parts(before_guard)
        after_parts = resolved_guard_parts(after_guard)
        if before_parts is None or after_parts is None or before_parts[0] != after_parts[0]:
            return False
        if before_parts[1:3] == after_parts[1:3]:
            return True
        # A version-selected helper may refine its isinstance tuple only when
        # the inlined post guard carries the target-version assumption. The
        # resolved post guard remains explicit in the account under that premise.
        return bool(after_parts[2]) and after_parts[3] == "entry_guard_helper_inlining"

    for qualified_name, callable_record in by_name.items():
        pre_records = before_by_name.get(qualified_name, [])
        post_records = after_by_name.get(qualified_name, [])
        pre_available = callable_record.pre_signature != "UNKNOWN"
        pre_sources = {
            (normalized, item.raised_exception)
            for item in pre_records
            if (normalized := _normalise_guard_source(item.source)) is not None
        }
        post_sources = {
            (normalized, item.raised_exception)
            for item in post_records
            if (normalized := _normalise_guard_source(item.source)) is not None
        }
        modeled_pre_guards = {
            (
                guard.get("file_path"),
                guard.get("line_number"),
                _normalise_guard_source(str(guard.get("condition_source") or "")),
                guard.get("raised_exception"),
            )
            for guard in callable_record.pre_entry_guards
            if any(resolved_guards_match(guard, post_guard) for post_guard in callable_record.entry_guards)
        }

        for item in post_records:
            normalized = _normalise_guard_source(item.source)
            fingerprint = (normalized, item.raised_exception)
            if not pre_available or normalized is None or fingerprint not in pre_sources:
                blocking.append(item)
            else:
                notes.append(
                    f"Unmodelled unchanged guard in {item.file_path}:{item.line_number} "
                    f"({qualified_name}: {item.source}); guard expression not modelled."
                )

        # Removing an unsupported pre guard is a source change too, but it does
        # not constrain post-call binding. Preserve that bounded loss explicitly.
        for item in pre_records:
            normalized = _normalise_guard_source(item.source)
            if (
                item.file_path,
                item.line_number,
                normalized,
                item.raised_exception,
            ) in modeled_pre_guards:
                # This raw unresolved-visitor record duplicates a resolved
                # structured guard that is semantically unchanged on both sides.
                continue
            fingerprint = (normalized, item.raised_exception)
            if normalized is None or fingerprint not in post_sources:
                blocking.append(replace(item, side="pre"))
    return blocking, notes


def _drop_literal_covered_modelled_guards(
    records: list[UnresolvedConstruct],
    modified: list[ModifiedCallable],
    post_call_sites: tuple[ImpactedCallSite, ...],
) -> list[UnresolvedConstruct]:
    """Let binding own a new modeled guard only when every candidate call has a literal value."""
    guards_by_node = {
        str(guard.get("node_id")): (item, guard)
        for item in modified
        for guard in item.entry_guards
        if guard.get("node_id")
    }
    sites_by_callee: dict[str, list[ImpactedCallSite]] = {}
    for site in post_call_sites:
        sites_by_callee.setdefault(site.callee_qualified_name, []).append(site)

    def site_has_literal(site: ImpactedCallSite, signature: str, param: str) -> bool:
        if site.star_args or site.star_kwargs:
            return False
        if param in site.arg_literals:
            return True
        try:
            parsed = ast.parse(f"def _hlith_guard{signature}: pass").body[0]
        except SyntaxError:
            return False
        args = parsed.args  # type: ignore[attr-defined]
        positional = [*args.posonlyargs, *args.args]
        shift = 1 if site.is_method_call else 0
        for position, argument in enumerate(positional):
            if argument.arg == param:
                source_position = position - shift
                return source_position >= 0 and str(source_position) in site.arg_literals
        return False

    retained: list[UnresolvedConstruct] = []
    for record in records:
        modeled = guards_by_node.get(record.node_id or "")
        if modeled is None or record.side not in {"post", "both"}:
            retained.append(record)
            continue
        callable_record, guard = modeled
        if record.caller_qualified_name != callable_record.qualified_name:
            retained.append(record)
            continue
        if guard.get("provenance", {}).get("analysis_pass") == "entry_guard_helper_inlining":
            continue
        sites = sites_by_callee.get(callable_record.qualified_name, [])
        if sites and all(
            site_has_literal(site, callable_record.post_signature, str(guard["param"]))
            for site in sites
        ):
            continue
        retained.append(record)
    return retained


def _changed_guard_exceptions(
    modified: list[ModifiedCallable],
    before_functions: dict[str, _Function],
    after_functions: dict[str, _Function],
) -> list[UnresolvedConstruct]:
    """Keep a recognized guard's exception-type change blocking."""
    records: list[UnresolvedConstruct] = []
    for callable_record in modified:
        old = before_functions.get(callable_record.qualified_name)
        new = after_functions.get(callable_record.qualified_name)
        if old is None or new is None:
            continue

        def identity(guard: dict[str, Any]) -> tuple[Any, ...]:
            type_names = guard.get("type")
            return (
                guard.get("param"),
                guard.get("raises_when"),
                guard.get("literal"),
                guard.get("operator"),
                tuple(type_names) if isinstance(type_names, (list, tuple)) else type_names,
                guard.get("negated"),
            )

        previous: dict[tuple[Any, ...], set[str | None]] = {}
        for guard in old.entry_guards:
            previous.setdefault(identity(guard), set()).add(guard.get("raised_exception"))
        for guard in new.entry_guards:
            prior_exceptions = previous.get(identity(guard))
            raised_exception = guard.get("raised_exception")
            if not prior_exceptions or raised_exception in prior_exceptions:
                continue
            condition_source = str(guard.get("condition_source", ""))
            condition_sha256 = str(guard.get("condition_sha256", ""))
            file_path = str(guard.get("file_path", callable_record.file_path))
            line_number = int(guard.get("line_number", callable_record.line_number))
            node_id = str(guard.get("node_id", ""))
            provenance = guard.get("provenance")
            records.append(
                UnresolvedConstruct(
                    file_path=file_path,
                    line_number=line_number,
                    kind="unsupported_entry_guard",
                    source=condition_source,
                    scope="modified_callable",
                    caller_qualified_name=callable_record.qualified_name,
                    raised_exception=raised_exception,
                    condition_source=condition_source,
                    condition_sha256=condition_sha256,
                    node_id=node_id or None,
                    provenance=provenance,
                    side="post",
                )
            )
    return records


def analyze_effect(repo_path: str | os.PathLike[str], unified_diff: str) -> EffectAccount:
    """Compatibility spelling for callers that use the design's analyze API."""
    return build_effect_account(repo_path, unified_diff)


def declare(repo_path: str | os.PathLike[str], effect: Any) -> Any:
    """Declare file changes represented by the static effect account.

    Changes without an account record remain undeclared for Rule C. A declared
    path allows only the corresponding content add, modify, or delete kind.
    """
    patch = effect.unified_diff if hasattr(effect, "unified_diff") else str(effect)
    root = Path(repo_path).resolve()
    account = build_effect_account(root, patch)
    modeled_paths = {
        item.file_path for item in account.modified_callables
    } | {
        item.file_path for item in account.added_callables
    } | {
        item.file_path for item in account.deleted_callables
    } | {
        item["file_path"] for item in account.modified_constants
    } | {
        item["file_path"] for item in account.modified_class_attributes
    } | {
        item["file_path"] for item in account.modified_module_level
    } | {
        path for path in account.ast_equal_files
    }
    patch_kinds = _diff_path_kinds(patch)
    declared: dict[str, frozenset[str]] = {}
    for path in sorted(modeled_paths):
        kinds = patch_kinds.get(path)
        if not kinds:
            kinds = frozenset({"modify" if (root / path).exists() else "add"})
        declared[path] = kinds
    from ..contract.effects import DeclaredEffects  # defined in L0 (moved by review); no L2 -> L1 edge

    return DeclaredEffects(paths=declared)


def _ignore_copy(directory: str, names: list[str]) -> set[str]:
    del directory
    return {name for name in names if name in _IGNORED_DIRS}


def _changed_paths(patch: str) -> tuple[str, ...]:
    paths: set[str] = set()
    for line in patch.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        raw = line[4:].split("\t", 1)[0].strip()
        if raw == "/dev/null":
            continue
        if raw.startswith(("a/", "b/")):
            raw = raw[2:]
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe path in unified diff: {raw}")
        paths.add(path.as_posix())
    return tuple(sorted(paths))


def _diff_path_kinds(patch: str) -> dict[str, frozenset[str]]:
    def path_from_header(raw: str) -> str | None:
        value = raw.split("\t", 1)[0].strip()
        if value == "/dev/null":
            return None
        if value.startswith(("a/", "b/")):
            value = value[2:]
        return PurePosixPath(value).as_posix()

    kinds: dict[str, set[str]] = {}
    old_path: str | None = None
    for line in patch.splitlines():
        if line.startswith("--- "):
            old_path = path_from_header(line[4:])
        elif line.startswith("+++ "):
            new_path = path_from_header(line[4:])
            if old_path is None and new_path is not None:
                kinds.setdefault(new_path, set()).add("add")
            elif new_path is None and old_path is not None:
                kinds.setdefault(old_path, set()).add("delete")
            elif old_path is not None and new_path is not None and old_path == new_path:
                kinds.setdefault(old_path, set()).add("modify")
            elif old_path is not None and new_path is not None:
                kinds.setdefault(old_path, set()).add("delete")
                kinds.setdefault(new_path, set()).add("add")
            old_path = None
    return {path: frozenset(values) for path, values in kinds.items()}


def _python_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _IGNORED_DIRS)
        for name in sorted(files):
            if name.endswith(".py"):
                path = Path(current) / name
                if not path.is_symlink():
                    result.append(path)
    return result


def _module_name(relative_path: str) -> str:
    return module_name_for_path(relative_path)


def _allowed_same_module_guard_helpers(
    index: _AstIndexVisitor,
    prior: _ModuleIndex | None,
) -> set[str]:
    prefix = f"{index.module_name}."
    allowed: set[str] = set()
    for qualified_name, node in index.functions_ast.items():
        if not qualified_name.startswith(prefix):
            continue
        if "." in qualified_name[len(prefix):]:
            continue
        old_node = prior.functions_ast.get(qualified_name) if prior is not None else None
        if old_node is None or ast.dump(node, include_attributes=False) == ast.dump(
            old_node, include_attributes=False
        ):
            allowed.add(qualified_name)
    return allowed


_INDEX_CACHE_SCHEMA = 1


def _index_tool_key() -> str | None:
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    try:
        versions = {
            "python": list(sys.version_info[:3]),
            "libcst": importlib.metadata.version("libcst"),
            "tree_sitter": importlib.metadata.version("tree-sitter"),
            "tree_sitter_python": importlib.metadata.version("tree-sitter-python"),
            "effect_source_sha256": source_hash,
        }
    except importlib.metadata.PackageNotFoundError:
        return None
    return hashlib.sha256(
        json.dumps(versions, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _encode_ast_value(value: Any) -> Any:
    if isinstance(value, ast.AST):
        return {
            "ast_type": type(value).__name__,
            "fields": {name: _encode_ast_value(getattr(value, name)) for name in value._fields},
            "attributes": {
                name: _encode_ast_value(getattr(value, name))
                for name in value._attributes
                if hasattr(value, name)
            },
        }
    if isinstance(value, list):
        return [_encode_ast_value(item) for item in value]
    if isinstance(value, tuple):
        return {"tuple": [_encode_ast_value(item) for item in value]}
    if isinstance(value, bytes):
        return {"bytes_b64": base64.b64encode(value).decode("ascii")}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported AST cache value: {type(value).__name__}")


def _decode_ast_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_decode_ast_value(item) for item in value]
    if isinstance(value, dict) and set(value) == {"tuple"}:
        if not isinstance(value["tuple"], list):
            raise ValueError("invalid tuple encoding")
        return tuple(_decode_ast_value(item) for item in value["tuple"])
    if isinstance(value, dict) and set(value) == {"bytes_b64"}:
        if not isinstance(value["bytes_b64"], str):
            raise ValueError("invalid bytes encoding")
        return base64.b64decode(value["bytes_b64"], validate=True)
    if isinstance(value, dict) and set(value) == {"ast_type", "fields", "attributes"}:
        name, fields, attributes = value["ast_type"], value["fields"], value["attributes"]
        node_type = getattr(ast, name, None) if isinstance(name, str) else None
        if not isinstance(node_type, type) or not issubclass(node_type, ast.AST):
            raise ValueError("unknown cached AST node")
        if not isinstance(fields, dict) or set(fields) != set(node_type._fields):
            raise ValueError("cached AST node fields do not match")
        if not isinstance(attributes, dict) or set(attributes) != set(node_type._attributes):
            raise ValueError("cached AST node attributes do not match")
        node = node_type(**{key: _decode_ast_value(item) for key, item in fields.items()})
        for key, item in attributes.items():
            setattr(node, key, _decode_ast_value(item))
        return node
    if isinstance(value, dict):
        raise ValueError("unknown cached AST value")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("invalid cached AST scalar")


def _index_cache_path(cache_dir: Path, relative: str) -> Path:
    name = hashlib.sha256(relative.encode("utf-8")).hexdigest()
    return cache_dir / f"{name}.json"


def _serialize_index(index: _ModuleIndex) -> dict[str, Any]:
    return {
        "module_name": index.module_name,
        "file_path": index.file_path,
        "source": index.source,
        "functions_ast": [[name, _encode_ast_value(node)] for name, node in sorted(index.functions_ast.items())],
        "classes_ast": [[name, _encode_ast_value(node)] for name, node in sorted(index.classes_ast.items())],
        "imports": index.imports,
        "module_imports": index.module_imports,
        "calls": [asdict(item) for item in index.calls],
        "unresolved": [asdict(item) for item in index.unresolved],
    }


def _deserialize_index(data: Any) -> _ModuleIndex:
    required = {
        "module_name", "file_path", "source", "functions_ast", "classes_ast",
        "imports", "module_imports", "calls", "unresolved",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("cached index fields do not match schema")
    for key in ("module_name", "file_path", "source"):
        if not isinstance(data[key], str):
            raise ValueError("cached index text field is invalid")
    def node_map(items: Any, expected: type) -> dict[str, Any]:
        if not isinstance(items, list):
            raise ValueError("cached AST index is not a list")
        result: dict[str, Any] = {}
        for pair in items:
            if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) or pair[0] in result:
                raise ValueError("cached AST index entry is invalid")
            node = _decode_ast_value(pair[1])
            if not isinstance(node, expected):
                raise ValueError("cached AST index node type is invalid")
            result[pair[0]] = node
        return result
    if not isinstance(data["imports"], dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data["imports"].items()
    ):
        raise ValueError("cached imports are invalid")
    if not isinstance(data["module_imports"], dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data["module_imports"].items()
    ):
        raise ValueError("cached module imports are invalid")
    calls: list[_RawCall] = []
    if not isinstance(data["calls"], list):
        raise ValueError("cached calls are invalid")
    for item in data["calls"]:
        if not isinstance(item, dict) or set(item) != set(_RawCall.__dataclass_fields__):
            raise ValueError("cached call record fields do not match")
        if not all(isinstance(item[key], str) for key in ("caller", "file_path", "function_name", "node_source")):
            raise ValueError("cached call record text is invalid")
        if (
            not isinstance(item["line_number"], int)
            or item["line_number"] < 1
            or not isinstance(item["n_positional"], int)
            or item["n_positional"] < 0
            or not isinstance(item["keywords"], list)
            or not all(isinstance(value, str) for value in item["keywords"])
            or not all(isinstance(item[key], bool) for key in ("star_args", "star_kwargs"))
            or not isinstance(item["arg_literals"], dict)
            or not all(isinstance(key, str) and isinstance(value, str) for key, value in item["arg_literals"].items())
            or not isinstance(item["arg_sources"], dict)
            or not all(isinstance(key, str) and isinstance(value, str) for key, value in item["arg_sources"].items())
            or not isinstance(item["class_name"], (str, type(None)))
        ):
            raise ValueError("cached call record value types do not match")
        normalized = dict(item)
        normalized["keywords"] = tuple(normalized["keywords"])
        calls.append(_RawCall(**normalized))
    unresolved: list[UnresolvedConstruct] = []
    if not isinstance(data["unresolved"], list):
        raise ValueError("cached unresolved records are invalid")
    for item in data["unresolved"]:
        if not isinstance(item, dict) or set(item) != set(UnresolvedConstruct.__dataclass_fields__):
            raise ValueError("cached unresolved record fields do not match")
        if (
            not isinstance(item["file_path"], str)
            or not isinstance(item["line_number"], int)
            or item["line_number"] < 1
            or not all(isinstance(item[key], str) for key in ("kind", "source", "scope", "side"))
            or item["side"] not in {"pre", "post", "both"}
            or not all(
                isinstance(item[key], (str, type(None)))
                for key in (
                    "caller_qualified_name", "target_qualified_name", "raised_exception",
                    "condition_source", "condition_sha256", "node_id",
                )
            )
            or not isinstance(item["provenance"], (dict, type(None)))
        ):
            raise ValueError("cached unresolved record value types do not match")
        unresolved.append(UnresolvedConstruct(**item))
    return _ModuleIndex(
        module_name=data["module_name"],
        file_path=data["file_path"],
        source=data["source"],
        functions_ast=node_map(data["functions_ast"], (ast.FunctionDef, ast.AsyncFunctionDef)),
        classes_ast=node_map(data["classes_ast"], ast.ClassDef),
        module=None,
        functions={},
        imports=dict(data["imports"]),
        module_imports=dict(data["module_imports"]),
        calls=calls,
        unresolved=unresolved,
    )


def _load_cached_index(cache_dir: Path, relative: str, source: str, source_hash: str, tool_key: str) -> _ModuleIndex | None:
    path = _index_cache_path(cache_dir, relative)
    try:
        if cache_dir.is_symlink() or path.is_symlink():
            return None
        raw = path.read_text(encoding="utf-8")
        def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        record = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        if not isinstance(record, dict) or set(record) != {
            "schema", "relative", "source_sha256", "tool_key", "index", "checksum"
        }:
            return None
        checksum = record.pop("checksum")
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if not isinstance(checksum, str) or hashlib.sha256(canonical.encode("ascii")).hexdigest() != checksum:
            return None
        if record["schema"] != _INDEX_CACHE_SCHEMA or record["relative"] != relative:
            return None
        if record["source_sha256"] != source_hash or record["tool_key"] != tool_key:
            return None
        index = _deserialize_index(record["index"])
        if (
            index.file_path != relative
            or index.module_name != _module_name(relative)
            or index.source != source
        ):
            return None
        return index
    except Exception:
        return None


def _store_cached_index(cache_dir: Path, index: _ModuleIndex, source_hash: str, tool_key: str) -> None:
    try:
        if cache_dir.is_symlink():
            return
        record = {
            "schema": _INDEX_CACHE_SCHEMA,
            "relative": index.file_path,
            "source_sha256": source_hash,
            "tool_key": tool_key,
            "index": _serialize_index(index),
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        record["checksum"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = _index_cache_path(cache_dir, index.file_path)
        if path.is_symlink():
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f"{path.name}.", suffix=".tmp", dir=cache_dir
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        os.replace(temporary, path)
    except Exception:
        return


def _index_tree(
    root: Path,
    changed_paths: tuple[str, ...],
    *,
    reuse_indexes: dict[str, _ModuleIndex] | None = None,
    cache_dir: Path | None = None,
    cache_stats: dict[str, int] | None = None,
) -> dict[str, _ModuleIndex]:
    changed = set(changed_paths)
    if reuse_indexes is None:
        indexes: _ModuleIndexes = _ModuleIndexes()
        paths = _python_files(root)
    else:
        # Changed paths are the complete file delta applied to the candidate,
        # so unchanged entries from the base index remain valid verbatim.
        indexes = _ModuleIndexes(
            (relative, index)
            for relative, index in reuse_indexes.items()
            if relative not in changed
        )
        paths = []
        for relative in sorted(changed):
            relative_path = PurePosixPath(relative)
            if not relative.endswith(".py") or _IGNORED_DIRS.intersection(relative_path.parts[:-1]):
                continue
            path = root.joinpath(*relative_path.parts)
            if path.is_file() and not path.is_symlink():
                paths.append(path)

    indexes.import_roots = tuple(
        str(candidate) for candidate in (root / "src", root / "lib", root) if candidate.is_dir()
    )
    module_sources: dict[str, str | None] = {}
    module_source_paths: dict[str, str] = {}
    for item in indexes.values():
        previous_path = module_source_paths.get(item.module_name)
        if previous_path is not None and previous_path != item.file_path:
            module_sources[item.module_name] = None
        else:
            module_source_paths[item.module_name] = item.file_path
            module_sources[item.module_name] = item.source
    changed_sources: dict[str, str | None] = {}
    source_hashes: dict[str, str] = {}
    source_failures: dict[str, Exception] = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            source_bytes = path.read_bytes()
            source_hashes[relative] = hashlib.sha256(source_bytes).hexdigest()
            source = source_bytes.decode("utf-8")
        except Exception as exc:
            source = None
            source_failures[relative] = exc
        changed_sources[relative] = source
        if source is not None:
            module_name = _module_name(relative)
            previous_path = module_source_paths.get(module_name)
            if previous_path is not None and previous_path != relative:
                module_sources[module_name] = None
            else:
                module_source_paths[module_name] = relative
                module_sources[module_name] = source

    tool_key = _index_tool_key() if cache_dir is not None else None
    if tool_key is None:
        cache_dir = None
    for path in paths:
        relative = path.relative_to(root).as_posix()
        module_name = _module_name(relative)
        source = changed_sources[relative]
        if (
            cache_dir is not None
            and relative not in changed
            and source is not None
            and relative in source_hashes
        ):
            cached = _load_cached_index(
                cache_dir, relative, source, source_hashes[relative], tool_key
            )
            if cached is not None:
                indexes[relative] = cached
                if cache_stats is not None:
                    cache_stats["cache_hit_count"] = cache_stats.get("cache_hit_count", 0) + 1
                continue
        if cache_stats is not None:
            cache_stats["uncached_count"] = cache_stats.get("uncached_count", 0) + 1
        try:
            if source is None:
                read_error = source_failures.get(relative)
                if read_error is not None:
                    raise read_error
                raise OSError("could not read changed Python source")
            parsed = ast.parse(source, filename=relative)
        except SyntaxError:
            indexes[relative] = _ModuleIndex(
                module_name, relative, "", {}, {}, None, {}, {}, {}, [],
                [UnresolvedConstruct(relative, 1, "python_parse_error", "", "repository")],
            )
            continue
        except Exception as exc:
            detail = type(exc).__name__
            if str(exc):
                detail += f": {str(exc)[:180]}"
            indexes[relative] = _ModuleIndex(
                module_name,
                relative,
                source or "",
                {},
                {},
                None,
                {},
                {},
                {},
                [],
                [
                    UnresolvedConstruct(
                        file_path=relative,
                        line_number=max(1, int(getattr(exc, "lineno", 1) or 1)),
                        kind="analysis_failed",
                        source=detail,
                        scope="changed_file" if relative in changed else "repository",
                    )
                ],
            )
            continue
        ast_visitor = _AstIndexVisitor(module_name, relative, source)
        try:
            ast_visitor.visit(parsed)
        except Exception as exc:
            detail = type(exc).__name__
            if str(exc):
                detail += f": {str(exc)[:180]}"
            ast_visitor.unresolved.append(
                UnresolvedConstruct(
                    file_path=relative,
                    line_number=ast_visitor.failure_line or 1,
                    kind="analysis_failed",
                    source=detail,
                    scope="changed_file" if relative in changed else "repository",
                    caller_qualified_name=ast_visitor.failure_caller,
                    target_qualified_name=ast_visitor.failure_target,
                )
            )
        prior = reuse_indexes.get(relative) if reuse_indexes is not None else None
        allowed_guard_helpers = _allowed_same_module_guard_helpers(ast_visitor, prior)
        module: cst.Module | None = None
        functions: dict[str, _Function] = {}
        cst_unresolved: list[UnresolvedConstruct] = []
        if relative in changed:
            try:
                module = cst.parse_module(source)
                visitor = _IndexVisitor(
                    module_name,
                    relative,
                    module,
                    allowed_guard_helpers=allowed_guard_helpers,
                    module_sources=module_sources,
                )
                _visit_scoped_definitions(module, visitor)
                functions = visitor.functions
                cst_unresolved = visitor.unresolved
            except cst.ParserSyntaxError:
                cst_unresolved.append(UnresolvedConstruct(relative, 1, "libcst_parse_error", "", "changed_file"))
            except Exception as exc:
                detail = type(exc).__name__
                if str(exc):
                    detail += f": {str(exc)[:180]}"
                cst_unresolved.append(
                    UnresolvedConstruct(
                        file_path=relative,
                        line_number=max(1, int(getattr(exc, "lineno", 1) or 1)),
                        kind="analysis_failed",
                        source=detail,
                        scope="changed_file",
                    )
                )
        indexes[relative] = _ModuleIndex(
            module_name=module_name,
            file_path=relative,
            source=source,
            functions_ast=ast_visitor.functions_ast,
            classes_ast=ast_visitor.classes_ast,
            module=module,
            functions=functions,
            imports=ast_visitor.imports,
            module_imports=ast_visitor.module_imports,
            calls=ast_visitor.calls,
            unresolved=[*ast_visitor.unresolved, *cst_unresolved],
            attr_writes=ast_visitor.attr_writes,
        )
        if (
            cache_dir is not None
            and relative not in changed
            and relative in source_hashes
            and indexes[relative].module is None
            and not indexes[relative].functions
        ):
            _store_cached_index(cache_dir, indexes[relative], source_hashes[relative], tool_key)
    return indexes


class _AstIndexVisitor(ast.NodeVisitor):
    """Fast repository-wide resolver; LibCST remains authoritative for changed APIs."""

    def __init__(self, module_name: str, file_path: str, source: str) -> None:
        self.module_name = module_name
        self.file_path = file_path
        self.is_package_init = PurePosixPath(file_path).name == "__init__.py"
        self.source = source
        self.source_line_bytes = [line.encode("utf-8") for line in ast_source_lines(source)]
        self.classes: list[str] = []
        self.functions_stack: list[str] = []
        self.imports: dict[str, str] = {}
        self.module_imports: dict[str, str] = {}
        self.functions_ast: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.classes_ast: dict[str, ast.ClassDef] = {}
        self.calls: list[_RawCall] = []
        self.unresolved: list[UnresolvedConstruct] = []
        self.attr_writes: list[tuple[ast.AST, str]] = []
        self._current_line = 1
        self.failure_line: int | None = None
        self.failure_caller: str | None = None
        self.failure_target: str | None = None

    def visit(self, node: ast.AST) -> Any:
        previous_line = self._current_line
        node_line = getattr(node, "lineno", None)
        if isinstance(node_line, int):
            self._current_line = node_line
        try:
            return super().visit(node)
        except Exception:
            if self.failure_line is None:
                self.failure_line = node_line if isinstance(node_line, int) else self._current_line
                self.failure_caller = (
                    ".".join([self.module_name, *self.classes, *self.functions_stack])
                    if self.functions_stack else None
                )
                if isinstance(node, ast.Call):
                    self.failure_target = self._target_for_failed_call(node)
            raise
        finally:
            self._current_line = previous_line

    def _target_for_failed_call(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return self.imports.get(func.id, f"{self.module_name}.{func.id}")
        if not isinstance(func, ast.Attribute):
            return None
        attrs: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            attrs.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        root = current.id
        suffix = ".".join(reversed(attrs))
        if root in {"self", "cls"} and self.classes:
            base = f"{self.module_name}.{self.classes[-1]}"
        elif root in self.imports:
            base = self.imports[root]
        elif root in self.module_imports:
            base = self.module_imports[root]
        else:
            return None
        return f"{base}.{suffix}"

    def source_segment(self, node: ast.AST) -> str | None:
        return source_segment_from_lines(self.source_line_bytes, node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.module_imports[alias.asname] = alias.name
            else:
                root = alias.name.split(".", 1)[0]
                self.module_imports[root] = root

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = _ast_from_module_name(self.module_name, node, is_package_init=self.is_package_init)
        for alias in node.names:
            if alias.name == "*":
                self.unresolved.append(
                    UnresolvedConstruct(
                        self.file_path, node.lineno, "wildcard_import", "from *", "repository", self.module_name
                    )
                )
                continue
            local = alias.asname or alias.name.split(".")[-1]
            self.imports[local] = f"{base}.{alias.name}" if base else alias.name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join([self.module_name, *self.classes, node.name])
        self.classes_ast[qualified] = node
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join(
            [self.module_name, *self.classes, *self.functions_stack, node.name]
        )
        self.functions_ast[qualified] = node
        if node.decorator_list and (node.args.vararg or node.args.kwarg):
            source = self.source_segment(node.decorator_list[0]) or "decorator"
            qualified = ".".join(
                [self.module_name, *self.classes, *self.functions_stack, node.name]
            )
            self.unresolved.append(
                UnresolvedConstruct(
                    self.file_path,
                    node.decorator_list[0].lineno,
                    "decorator_varargs_forwarding",
                    source,
                    "repository",
                    qualified,
                )
            )
        self.functions_stack.append(node.name)
        self.generic_visit(node)
        self.functions_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        for item in node.targets:
            if isinstance(item, ast.Attribute) and item.attr:
                self.attr_writes.append((item.value, item.attr))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        item = node.target
        if isinstance(item, ast.Attribute) and item.attr:
            self.attr_writes.append((item.value, item.attr))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        positional = 0
        literals: dict[str, str] = {}
        sources: dict[str, str] = {}
        star_args = False
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                star_args = True
                continue
            key = str(positional)
            positional += 1
            sources[key] = self.source_segment(arg) or ast.unparse(arg)
            literal = _ast_literal_repr(arg)
            if literal is not None:
                literals[key] = literal
        keywords: list[str] = []
        star_kwargs = False
        for keyword in node.keywords:
            if keyword.arg is None:
                star_kwargs = True
                continue
            keywords.append(keyword.arg)
            sources[keyword.arg] = self.source_segment(keyword.value) or ast.unparse(keyword.value)
            literal = _ast_literal_repr(keyword.value)
            if literal is not None:
                literals[keyword.arg] = literal
        caller = ".".join([self.module_name, *self.classes, *self.functions_stack])
        function = _fast_call_name(node.func)
        node_source = self.source_segment(node) or ast.unparse(node)
        self.calls.append(
            _RawCall(
                caller=caller,
                file_path=self.file_path,
                line_number=node.lineno,
                function_name=function,
                n_positional=positional,
                keywords=tuple(keywords),
                star_args=star_args,
                star_kwargs=star_kwargs,
                arg_literals=literals,
                arg_sources=sources,
                class_name=self.classes[-1] if self.classes else None,
                node_source=node_source,
            )
        )
        source = node_source or function
        if function == "setattr" and isinstance(node.func, ast.Name) and len(node.args) >= 2:
            attr_name = (
                node.args[1].value
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                else "*"
            )
            self.attr_writes.append((node.args[0], attr_name))
        if function in {"eval", "exec"}:
            self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "dynamic_eval_exec", source, "repository", caller))
        elif function == "getattr":
            literal = len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
            if not literal:
                self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "dynamic_getattr", source, "repository", caller))
        elif function in {"setattr", "builtins.setattr"}:
            literal = len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
            if not literal:
                self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "dynamic_setattr", source, "repository", caller))
        elif function in {"importlib.import_module", "import_module"}:
            literal = bool(node.args) and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            if not literal:
                self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "dynamic_import_module", source, "repository", caller))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "sys" and node.value.attr == "modules":
                source = self.source_segment(node) or "sys.modules"
                caller = ".".join([self.module_name, *self.classes, *self.functions_stack])
                self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "dynamic_sys_modules", source, "repository", caller))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "_getframe":
            source = self.source_segment(node) or "sys._getframe"
            self.unresolved.append(UnresolvedConstruct(self.file_path, node.lineno, "frame_introspection", source, "repository"))
        self.generic_visit(node)


def _ast_from_module_name(
    current: str, node: ast.ImportFrom, *, is_package_init: bool = False
) -> str:
    if node.level:
        parts = current.split(".")
        if not is_package_init and len(parts) > 1:
            parts = parts[:-1]
        for _ in range(max(0, node.level - 1)):
            if parts:
                parts.pop()
        base = ".".join(parts)
        if node.module:
            return f"{base}.{node.module}" if base else node.module
        return base
    return node.module or ""


def _fast_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = [node.attr]
        cur = node.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            parts.reverse()
            return ".".join(parts)
    return ast.unparse(node)


def _ast_literal_repr(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if not isinstance(node, (ast.Tuple, ast.List, ast.Dict, ast.Set, ast.UnaryOp, ast.BinOp)):
        return None
    try:
        return repr(ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


class _IndexVisitor(cst.CSTVisitor):
    def __init__(
        self,
        module_name: str,
        file_path: str,
        module: cst.Module,
        *,
        allowed_guard_helpers: set[str],
        module_sources: dict[str, str | None],
    ) -> None:
        self.module_name = module_name
        self.file_path = file_path
        self.module = module
        self.exception_imports: dict[str, str] = {}
        self.exception_module_imports: dict[str, str] = {}
        self.local_class_names: set[str] = set()
        self.allowed_guard_helpers = allowed_guard_helpers
        self.module_sources = module_sources
        # LibCST renders Module.code from the full tree. Keep it only for this
        # file's indexing pass instead of regenerating it for every callable.
        self.module_source = module.code
        self.module_guard_helpers: dict[str, ast.FunctionDef] = {}
        self.module_shadowed_names: set[str] = set()
        try:
            parsed = ast.parse(self.module_source)
            self.module_guard_helpers, self.module_shadowed_names = _guard_module_context(
                parsed, module_name
            )
            self.guard_candidate_functions = _ast_guard_candidate_functions(parsed)
            self.ast_functions = {
                (node.name, node.lineno): node
                for node in ast.walk(parsed)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self.ast_functions_by_name: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
            for node in ast.walk(parsed):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.ast_functions_by_name.setdefault(node.name, []).append(node)
            for nodes in self.ast_functions_by_name.values():
                nodes.sort(key=lambda item: item.lineno)
            self.ast_function_occurrences: dict[str, int] = {}
            (
                self.exception_imports,
                self.exception_module_imports,
            ) = _exception_import_aliases(
                parsed,
                module_name,
                is_package_init=PurePosixPath(file_path).name == "__init__.py",
            )
            self.local_class_names = {
                node.name for node in parsed.body if isinstance(node, ast.ClassDef)
            }
        except SyntaxError:
            self.ast_functions = {}
            self.ast_functions_by_name = {}
            self.ast_function_occurrences = {}
            self.guard_candidate_functions = set()
        self.classes: list[str] = []
        self.functions_stack: list[str] = []
        self.functions: dict[str, _Function] = {}
        self.imports: dict[str, str] = {}
        self.module_imports: dict[str, str] = {}
        self.calls: list[_RawCall] = []
        self.unresolved: list[UnresolvedConstruct] = []

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        self.classes.append(node.name.value)
        return True

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        del original_node
        self.classes.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        name = node.name.value
        components = [self.module_name, *self.classes, *self.functions_stack, name]
        qualified = ".".join(components)
        occurrence = self.ast_function_occurrences.get(name, 0)
        candidates = self.ast_functions_by_name.get(name, ())
        ast_function = candidates[occurrence] if occurrence < len(candidates) else None
        if ast_function is not None:
            self.ast_function_occurrences[name] = occurrence + 1
        function_line = ast_function.lineno if ast_function is not None else 1
        signature = f"({self.module.code_for_node(node.params)})"
        if ast_function is not None and (name, ast_function.lineno) not in self.guard_candidate_functions:
            guards, guard_unresolved = [], []
        else:
            guards, guard_unresolved = _entry_guards(
                node,
                ast_function,
                self.module,
                self.file_path,
                function_line,
                qualified,
                self.exception_imports,
                self.exception_module_imports,
                self.local_class_names,
                self.module_name,
                _function_local_binding_names(ast_function),
                self.allowed_guard_helpers,
                self.module_sources,
                module_source=self.module_source,
                module_guard_helpers=self.module_guard_helpers,
                module_shadowed_names=self.module_shadowed_names,
            )
        self.unresolved.extend(
            replace(item, caller_qualified_name=qualified)
            for item in guard_unresolved
        )
        self.unresolved.extend(
            UnresolvedConstruct(
                file_path=guard.file_path,
                line_number=guard.line_number,
                kind="unsupported_entry_guard",
                source=guard.condition_source or "",
                scope="modified_callable",
                caller_qualified_name=qualified,
                provenance=guard.provenance,
                raised_exception=guard.raised_exception,
                condition_source=guard.condition_source,
                condition_sha256=guard.condition_sha256,
                node_id=guard.node_id,
            )
            for guard in guards
        )
        effects = _call_effects(ast_function, self.module_source)
        self.functions[qualified] = _Function(
            qualified_name=qualified,
            file_path=self.file_path,
            line_number=function_line,
            signature=signature,
            source=self.module.code_for_node(node),
            entry_guards=tuple(guard.to_dict() for guard in guards),
            effects=tuple(effects),
        )
        self.functions_stack.append(name)
        return True

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        del original_node
        self.functions_stack.pop()

    def visit_Import(self, node: cst.Import) -> None:
        for alias in node.names:
            target = self.module.code_for_node(alias.name)
            if alias.asname:
                local = alias.asname.name.value
                self.module_imports[local] = target
            else:
                local = target.split(".", 1)[0]
                self.module_imports[local] = local

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        is_package_init = PurePosixPath(self.file_path).name == "__init__.py"
        base = _from_module_name(self.module_name, node, self.module, is_package_init=is_package_init)
        if isinstance(node.names, cst.ImportStar):
            return
        for alias in node.names:
            name = self.module.code_for_node(alias.name)
            local = alias.asname.name.value if alias.asname else name.split(".")[-1]
            self.imports[local] = f"{base}.{name}" if base else name


def _visit_scoped_definitions(module: cst.Module, visitor: _IndexVisitor) -> None:
    """Visit only statement suites needed to find class/function scopes.

    Expression and small-statement CST nodes do not contribute to the callable
    index; each callable's source and AST are read directly when it is visited.
    Skipping those nodes avoids a full metadata traversal of large changed files.
    """
    scoped_nodes = (
        cst.BaseStatement,
        cst.BaseSuite,
        cst.Else,
        cst.Finally,
        cst.ExceptHandler,
        cst.MatchCase,
    )

    def walk(node: cst.CSTNode) -> None:
        if isinstance(node, cst.ClassDef):
            if visitor.visit_ClassDef(node):
                for child in node.children:
                    if isinstance(child, scoped_nodes):
                        walk(child)
                visitor.leave_ClassDef(node)
            return
        if isinstance(node, cst.FunctionDef):
            if visitor.visit_FunctionDef(node):
                for child in node.children:
                    if isinstance(child, scoped_nodes):
                        walk(child)
                visitor.leave_FunctionDef(node)
            return
        for child in node.children:
            if isinstance(child, scoped_nodes):
                walk(child)

    walk(module)

def _from_module_name(
    current: str, node: cst.ImportFrom, module: cst.Module, *, is_package_init: bool = False
) -> str:
    if node.relative:
        parts = current.split(".")
        if not is_package_init and len(parts) > 1:
            parts = parts[:-1]
        for _ in range(max(0, len(node.relative) - 1)):
            if parts:
                parts.pop()
        base = ".".join(parts)
        if node.module:
            suffix = module.code_for_node(node.module)
            return f"{base}.{suffix}" if base else suffix
        return base
    return module.code_for_node(node.module) if node.module else ""


def _function_code(indexes: dict[str, _ModuleIndex]) -> dict[str, _Function]:
    result: dict[str, _Function] = {}
    for index in indexes.values():
        result.update(index.functions)
    return result


def _modified_functions(
    before: dict[str, _ModuleIndex], after: dict[str, _ModuleIndex], changed_paths: tuple[str, ...]
) -> list[ModifiedCallable]:
    old_functions = _function_code(before)
    new_functions = _function_code(after)
    touched_modules = {_module_name(path) for path in changed_paths if path.endswith(".py")}
    names = sorted(
        name for name in set(old_functions) | set(new_functions)
        if name.startswith(tuple(module + "." for module in touched_modules))
        and (
            name not in old_functions
            or name not in new_functions
            or old_functions[name].source != new_functions[name].source
        )
    )
    result: list[ModifiedCallable] = []
    for name in names:
        old = old_functions.get(name)
        new = new_functions.get(name)
        pre_exceptions, pre_exception_claims = _exception_facts(before, name)
        post_exceptions, post_exception_claims = _exception_facts(after, name)
        result.append(
            ModifiedCallable(
                qualified_name=name,
                file_path=(new or old).file_path,  # type: ignore[union-attr]
                # Keep the historical signature shape for downstream consumers;
                # added callables also receive the explicit post-only record below.
                pre_signature=old.signature if old else "UNKNOWN",
                post_signature=new.signature if new else "UNKNOWN",
                pre_return_signature=_return_annotation_source(before, name),
                post_return_signature=_return_annotation_source(after, name),
                pre_return_shapes=tuple(_return_shape_facts(before, name, "pre")),
                post_return_shapes=tuple(_return_shape_facts(after, name, "post")),
                pre_entry_guards=old.entry_guards if old else (),
                entry_guards=new.entry_guards if new else (),
                pre_exceptions=pre_exceptions,
                post_exceptions=post_exceptions,
                pre_exception_claims=pre_exception_claims,
                post_exception_claims=post_exception_claims,
                line_number=(new or old).line_number,  # type: ignore[union-attr]
                provenance=_provenance(
                    "callable_diff",
                    "resolved",
                    (new or old).file_path,  # type: ignore[union-attr]
                    (new or old).line_number,  # type: ignore[union-attr]
                    (new or old).source,  # type: ignore[union-attr]
                ),
            )
        )
    return result


def _return_annotation_source(
    indexes: dict[str, _ModuleIndex], qualified_name: str
) -> str | None:
    index = next(
        (candidate for candidate in indexes.values() if qualified_name in candidate.functions_ast),
        None,
    )
    if index is None:
        return None
    annotation = index.functions_ast[qualified_name].returns
    if annotation is None:
        return None
    return _ast_source_segment(index.source, annotation) or ast.unparse(annotation)


def _return_shape_facts(
    indexes: dict[str, _ModuleIndex], qualified_name: str, side: str
) -> list[dict[str, Any]]:
    index = next(
        (candidate for candidate in indexes.values() if qualified_name in candidate.functions_ast),
        None,
    )
    if index is None:
        return []
    function = index.functions_ast[qualified_name]
    returns: list[ast.Return] = []

    class ReturnVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Return(self, node: ast.Return) -> None:
            returns.append(node)

    ReturnVisitor().visit(function)
    local_shape_cache: dict[tuple[str, int], dict[str, Any] | None] = {}
    facts = [
        _return_shape_fact(
            index,
            qualified_name,
            node,
            side,
            ordinal,
            _return_shape_for_return(index, function, node.value, node.lineno, indexes, local_shape_cache),
        )
        for ordinal, node in enumerate(returns, start=1)
    ]
    if _suite_may_fall_through(function.body):
        line_number = getattr(function, "end_lineno", None) or function.lineno
        facts.append(
            {
                "kind": "none",
                "source": "",
                "file_path": index.file_path,
                "line_number": line_number,
                "resolution": "resolved",
                "literal_value": None,
                "container_kind": None,
                "length": None,
                "target_qualified_name": None,
                "provenance": _provenance(
                    "return_shape_inference",
                    "resolved",
                    index.file_path,
                    line_number,
                    "implicit return None",
                ),
                "node_id": (
                    f"{index.file_path}::{qualified_name.removeprefix(index.module_name + '.') }"
                    f"::implicit-none:{line_number}"
                ),
                "side": side,
                "unexplored_scope": "",
            }
        )
    return facts


def _return_shape_fact(
    index: _ModuleIndex,
    qualified_name: str,
    node: ast.Return,
    side: str,
    ordinal: int,
    shape: dict[str, Any],
) -> dict[str, Any]:
    source = (
        _ast_source_segment(index.source, node.value) or ast.unparse(node.value)
        if node.value is not None else ""
    )
    line_number = node.lineno
    resolution = shape["resolution"]
    relative_name = qualified_name.removeprefix(f"{index.module_name}.")
    provenance = _provenance(
        "return_shape_inference",
        resolution,
        index.file_path,
        line_number,
        source or "return None",
    )
    if shape.get("local_binding_provenance"):
        provenance["local_binding_provenance"] = shape["local_binding_provenance"]
    return {
        "kind": shape["kind"],
        "source": source,
        "file_path": index.file_path,
        "line_number": line_number,
        "resolution": resolution,
        "literal_value": shape.get("literal_value"),
        "container_kind": shape.get("container_kind"),
        "length": shape.get("length"),
        "target_qualified_name": shape.get("target_qualified_name"),
        "provenance": provenance,
        "node_id": f"{index.file_path}::{relative_name}::return:{line_number}:{ordinal}",
        "side": side,
        "unexplored_scope": shape["unexplored_scope"],
    }


def _return_shape_for_return(
    index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    node: ast.AST | None,
    return_line_number: int,
    indexes: dict[str, _ModuleIndex],
    local_shape_cache: dict[tuple[str, int], dict[str, Any] | None],
) -> dict[str, Any]:
    if isinstance(node, ast.Name):
        cache_key = (node.id, return_line_number)
        if cache_key not in local_shape_cache:
            local_shape_cache[cache_key] = _local_tuple_return_shape(
                index, function, node.id, return_line_number, indexes
            )
        local_shape = local_shape_cache[cache_key]
        if local_shape is not None:
            return local_shape
    return _return_expression_shape(index, node, indexes)


def _local_tuple_return_shape(
    index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    return_line_number: int,
    indexes: dict[str, _ModuleIndex],
) -> dict[str, Any] | None:
    """Resolve a local only when every scanned write proves the same literal tuple arity.

    A non-parameter local cannot normally reach ``return name`` without a prior binding;
    so any returned value must come from an earlier assignment. Unsupported binding forms
    and dynamic local access keep the result unresolved.
    """
    args = function.args
    parameters = {
        arg.arg
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    }
    if args.vararg is not None:
        parameters.add(args.vararg.arg)
    if args.kwarg is not None:
        parameters.add(args.kwarg.arg)
    if name in parameters:
        return None

    assignments: list[ast.expr] = []
    supported_targets: set[int] = set()
    unsupported_write = False

    def target_mentions_name(target: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Name) and child.id == name
            for child in ast.walk(target)
        )

    class LocalWriteVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            nonlocal unsupported_write
            if node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                if id(node) not in supported_targets:
                    unsupported_write = True

        def visit_Assign(self, node: ast.Assign) -> None:
            nonlocal unsupported_write
            if any(target_mentions_name(target) for target in node.targets):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
                    supported_targets.add(id(node.targets[0]))
                    assignments.append(node.value)
                else:
                    unsupported_write = True
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            nonlocal unsupported_write
            if target_mentions_name(node.target):
                if isinstance(node.target, ast.Name) and node.target.id == name and node.value is not None:
                    supported_targets.add(id(node.target))
                    assignments.append(node.value)
                else:
                    unsupported_write = True
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            nonlocal unsupported_write
            if node.name == name:
                unsupported_write = True
            if any(
                isinstance(child, ast.Nonlocal) and name in child.names
                for child in ast.walk(node)
            ):
                unsupported_write = True

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            nonlocal unsupported_write
            if node.name == name:
                unsupported_write = True

        def visit_Lambda(self, node: ast.Lambda) -> None:
            nonlocal unsupported_write
            if any(
                isinstance(child, ast.Name)
                and child.id == name
                and isinstance(child.ctx, (ast.Store, ast.Del))
                for child in ast.walk(node)
            ):
                unsupported_write = True

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            nonlocal unsupported_write
            if target_mentions_name(node.target):
                unsupported_write = True
            self.generic_visit(node)

        def visit_Delete(self, node: ast.Delete) -> None:
            nonlocal unsupported_write
            if any(target_mentions_name(target) for target in node.targets):
                unsupported_write = True
            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            nonlocal unsupported_write
            if node.name == name:
                unsupported_write = True
            self.generic_visit(node)

        def visit_Global(self, node: ast.Global) -> None:
            nonlocal unsupported_write
            if name in node.names:
                unsupported_write = True

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            nonlocal unsupported_write
            if name in node.names:
                unsupported_write = True

        def visit_Import(self, node: ast.Import) -> None:
            nonlocal unsupported_write
            if any((alias.asname or alias.name.split(".")[0]) == name for alias in node.names):
                unsupported_write = True

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            nonlocal unsupported_write
            if any((alias.asname or alias.name) == name for alias in node.names):
                unsupported_write = True

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            nonlocal unsupported_write
            if node.name == name:
                unsupported_write = True
            self.generic_visit(node)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            nonlocal unsupported_write
            if node.name == name:
                unsupported_write = True

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            nonlocal unsupported_write
            if node.rest == name:
                unsupported_write = True
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal unsupported_write
            called_name = (
                node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute)
                else ""
            )
            if called_name in {"exec", "eval", "locals", "vars", "_getframe", "currentframe"}:
                unsupported_write = True
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            nonlocal unsupported_write
            if node.attr == "f_locals":
                unsupported_write = True
            self.generic_visit(node)

    visitor = LocalWriteVisitor()
    for statement in function.body:
        visitor.visit(statement)
    if unsupported_write or not assignments:
        return None
    assignments = [value for value in assignments if value.lineno < return_line_number]
    if not assignments:
        return None

    resolved: list[tuple[ast.expr, dict[str, Any]]] = []
    for value in assignments:
        shape = _return_expression_shape(index, value, indexes)
        if (
            shape.get("kind") != "container"
            or shape.get("container_kind") != "tuple"
            or shape.get("resolution") != "resolved"
        ):
            return None
        resolved.append((value, shape))
    lengths = {shape.get("length") for _, shape in resolved}
    if len(lengths) != 1:
        return None

    binding_assignments = []
    for value, shape in resolved:
        source = _ast_source_segment(index.source, value) or ast.unparse(value)
        if any(isinstance(element, ast.Starred) for element in value.elts):
            return None
        binding_assignments.append(
            {
                **_provenance(
                    "return_shape_local_tuple_binding",
                    "resolved",
                    index.file_path,
                    value.lineno,
                    source,
                ),
                "assignment_source": source,
                "container_kind": "tuple",
                "length": shape["length"],
            }
        )
    return {
        "kind": "container",
        "resolution": "resolved",
        "literal_value": None,
        "container_kind": "tuple",
        "length": next(iter(lengths)),
        "target_qualified_name": None,
        "unexplored_scope": "",
        "local_binding_provenance": {
            "resolution": "resolved",
            "assignment_scan_complete": True,
            "assignment_scope": "pre_return_expression",
            "all_assignments_resolved": True,
            "all_assignments_same_tuple_shape": True,
            "all_normal_return_paths_use_scanned_local_assignment": True,
            "no_other_rebindings": True,
            "no_starred_tuple_assignments": True,
            "no_tuple_mutations": True,
            "no_opaque_assignment_or_dynamic_local_access": True,
            "container_kind": "tuple",
            "length": next(iter(lengths)),
            "assignments": binding_assignments,
        },
    }


def _return_expression_shape(
    index: _ModuleIndex, node: ast.AST | None, indexes: dict[str, _ModuleIndex]
) -> dict[str, Any]:
    unresolved = {
        "kind": "expression",
        "resolution": "assumed",
        "unexplored_scope": "Expression value and path conditions are not executed by static shape inference.",
    }
    if node is None or isinstance(node, ast.Constant) and node.value is None:
        return {
            "kind": "none",
            "resolution": "resolved",
            "literal_value": None,
            "unexplored_scope": "",
        }
    if isinstance(node, ast.Constant):
        literal, resolved = _json_literal(node)
        if resolved:
            return {
                "kind": "literal",
                "resolution": "resolved",
                "literal_value": literal,
                "unexplored_scope": "",
            }
        return unresolved
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)):
        kind_map = {
            ast.List: "list",
            ast.Tuple: "tuple",
            ast.Dict: "dict",
            ast.Set: "set",
        }
        if isinstance(node, ast.Dict):
            length = len(node.keys)
        else:
            length = len(node.elts)
        return {
            "kind": "container",
            "resolution": "resolved",
            "literal_value": None,
            "container_kind": kind_map[type(node)],
            "length": length,
            "unexplored_scope": "",
        }
    if isinstance(node, ast.Name):
        return {
            "kind": "name",
            "resolution": "assumed",
            "unexplored_scope": "Returned name value depends on runtime state.",
        }
    if isinstance(node, ast.Call):
        target = _resolve_return_call_target(index, node.func, indexes)
        if target is not None:
            target_kind, target_name, resolution = target
            result = {
                "kind": target_kind,
                "resolution": resolution,
                "unexplored_scope": "" if resolution == "resolved" else "External call target is not inspected or executed.",
            }
            if resolution == "resolved":
                result["target_qualified_name"] = target_name
            return result
        return {
            "kind": "call",
            "resolution": "unresolved",
            "unexplored_scope": "Call target could not be resolved statically.",
        }
    return unresolved


def _resolve_return_call_target(
    index: _ModuleIndex, function: ast.AST, indexes: dict[str, _ModuleIndex]
) -> tuple[str, str | None, str] | None:
    if isinstance(function, ast.Name):
        name = function.id
        if name in index.imports:
            target = _resolve_imported_target(index.imports[name], indexes)
        else:
            target = f"{index.module_name}.{name}"
        if any(target in candidate.classes_ast for candidate in indexes.values()):
            return "constructor", target, "resolved"
        if any(target in candidate.functions_ast for candidate in indexes.values()):
            return "call", target, "resolved"
        builtin = getattr(builtins, name, None)
        if isinstance(builtin, type):
            return "constructor", f"builtins.{name}", "resolved"
        if name in index.imports:
            return ("constructor", None, "assumed") if name[:1].isupper() else ("call", None, "assumed")
        return None
    if isinstance(function, ast.Attribute):
        target = _resolve_module_attribute(index, function, indexes)
        if target is None:
            return None
        if any(target in candidate.classes_ast for candidate in indexes.values()):
            return "constructor", target, "resolved"
        if any(target in candidate.functions_ast for candidate in indexes.values()):
            return "call", target, "resolved"
        final_name = target.rsplit(".", 1)[-1]
        return ("constructor", None, "assumed") if final_name[:1].isupper() else ("call", None, "assumed")
    return None


def _suite_may_fall_through(statements: list[ast.stmt]) -> bool:
    can_continue = True
    for statement in statements:
        if not can_continue:
            return False
        if isinstance(statement, (ast.Return, ast.Raise)):
            can_continue = False
        elif isinstance(statement, ast.If):
            can_continue = (
                _suite_may_fall_through(statement.body)
                or not statement.orelse
                or _suite_may_fall_through(statement.orelse)
            )
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            can_continue = _suite_may_fall_through(statement.body)
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            normal_branch_falls = _suite_may_fall_through(statement.body) and (
                not statement.orelse or _suite_may_fall_through(statement.orelse)
            )
            handler_branch_falls = any(
                _suite_may_fall_through(handler.body) for handler in statement.handlers
            )
            can_continue = normal_branch_falls or handler_branch_falls
            if statement.finalbody and not _suite_may_fall_through(statement.finalbody):
                can_continue = False
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.Match)):
            can_continue = True
    return can_continue


def _exception_facts(
    indexes: dict[str, _ModuleIndex], qualified_name: str
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...]]:
    index = next(
        (candidate for candidate in indexes.values() if qualified_name in candidate.functions_ast),
        None,
    )
    if index is None:
        return (), ()
    function = index.functions_ast[qualified_name]
    claims: list[dict[str, Any]] = []

    def resolve_expression(expression: ast.AST) -> list[tuple[str, str]]:
        if isinstance(expression, ast.Call):
            return resolve_expression(expression.func)
        if isinstance(expression, ast.Tuple):
            return [fact for child in expression.elts for fact in resolve_expression(child)]
        if isinstance(expression, ast.Name):
            imported = index.imports.get(expression.id)
            if imported:
                return [(imported, "resolved")]
            builtin_type = getattr(builtins, expression.id, None)
            if isinstance(builtin_type, type) and issubclass(builtin_type, BaseException):
                return [(f"builtins.{expression.id}", "resolved")]
            local = f"{index.module_name}.{expression.id}"
            if any(local in candidate.classes_ast for candidate in indexes.values()):
                return [(local, "resolved")]
            return [(expression.id, "assumed")]
        if isinstance(expression, ast.Attribute):
            parts = ast.unparse(expression).split(".")
            if len(parts) > 1:
                root, suffix = parts[0], ".".join(parts[1:])
                if root in index.module_imports:
                    return [(f"{index.module_imports[root]}.{suffix}", "resolved")]
                if root in index.imports:
                    return [(f"{index.imports[root]}.{suffix}", "resolved")]
                target = ".".join(parts)
                if any(target in candidate.classes_ast for candidate in indexes.values()):
                    return [(target, "resolved")]
            return [(ast.unparse(expression), "assumed")]
        return [(ast.unparse(expression), "assumed")]

    class ExceptionVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.handlers: list[tuple[str | None, list[tuple[str, str]]]] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            caught = resolve_expression(node.type) if node.type is not None else [("builtins.BaseException", "assumed")]
            self.handlers.append((node.name, caught))
            for statement in node.body:
                self.visit(statement)
            self.handlers.pop()

        def visit_Raise(self, node: ast.Raise) -> None:
            source = _ast_source_segment(index.source, node) or ast.unparse(node)
            if node.exc is not None:
                if (
                    isinstance(node.exc, ast.Name)
                    and self.handlers
                    and node.exc.id == self.handlers[-1][0]
                ):
                    exception_facts = self.handlers[-1][1]
                else:
                    exception_facts = resolve_expression(node.exc)
            elif self.handlers:
                exception_facts = self.handlers[-1][1]
            else:
                exception_facts = [("builtins.RuntimeError", "resolved")]
            for name, resolution in exception_facts:
                claims.append(
                    {
                        "name": name,
                        "resolution": resolution,
                        "provenance": _provenance(
                            "exception_set",
                            resolution,
                            index.file_path,
                            node.lineno,
                            source,
                        ),
                    }
                )

    visitor = ExceptionVisitor()
    for statement in function.body:
        visitor.visit(statement)
    claims.sort(key=lambda item: (item["name"], item["provenance"]["source_line"]))
    names = tuple(sorted({item["name"] for item in claims}))
    return names, tuple(claims)


def _resolve_call(
    index: _ModuleIndex,
    raw: _RawCall,
    indexes: dict[str, _ModuleIndex],
) -> tuple[str | None, bool]:
    cache_key = (id(indexes), id(raw))
    cached = index.call_resolution_cache.get(cache_key)
    if cached is not None:
        return cached
    resolved = _resolve_call_uncached(index, raw, indexes)
    index.call_resolution_cache[cache_key] = resolved
    return resolved


def _scope_bound_names(
    index: _ModuleIndex, caller: str, *, ignore_module_function_defs: bool = False
) -> frozenset[str] | None:
    """Return all names bound in `caller`, or None if module source cannot be parsed (fail-closed -> rebound)."""
    key = (caller, ignore_module_function_defs)
    if key in index.scope_bindings_cache:
        return index.scope_bindings_cache[key]
    function = index.functions_ast.get(caller)
    if function is not None:
        args = function.args
        bound: set[str] = {
            arg.arg for arg in (
                *args.posonlyargs, *args.args, *args.kwonlyargs,
                *((args.vararg,) if args.vararg is not None else ()),
                *((args.kwarg,) if args.kwarg is not None else ()),
            )
        }

        class FunctionBindings(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                bound.add(node.name)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                bound.add(node.name)

            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    bound.add(node.id)

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".", 1)[0])

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".")[-1])

            def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                if node.name:
                    bound.add(node.name)
                if node.type is not None:
                    self.visit(node.type)
                for child in node.body:
                    self.visit(child)

            def visit_Global(self, node: ast.Global) -> None:
                bound.update(node.names)

            def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                bound.update(node.names)

        bindings = FunctionBindings()
        for statement in function.body:
            bindings.visit(statement)
        result: frozenset[str] | None = frozenset(bound)
        index.scope_bindings_cache[key] = result
        return result

    if caller != index.module_name or not index.source:
        result = frozenset()
        index.scope_bindings_cache[key] = result
        return result
    try:
        module = ast.parse(index.source)
    except (SyntaxError, ValueError, RecursionError):
        index.scope_bindings_cache[key] = None
        return None

    bound_mod: set[str] = set()

    class ModuleBindings(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if not ignore_module_function_defs:
                bound_mod.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if not ignore_module_function_defs:
                bound_mod.add(node.name)

        def visit_Import(self, node: ast.Import) -> None:
            return

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            return

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                bound_mod.add(node.id)

    mb = ModuleBindings()
    for statement in module.body:
        if not isinstance(statement, (ast.Import, ast.ImportFrom)):
            mb.visit(statement)
    result = frozenset(bound_mod)
    index.scope_bindings_cache[key] = result
    return result


def _scope_rebinds_name(
    index: _ModuleIndex, caller: str, name: str, *, ignore_module_function_defs: bool = False
) -> bool:
    """Whether a receiver/name has a local binding that invalidates an import-only resolution."""
    bound = _scope_bound_names(index, caller, ignore_module_function_defs=ignore_module_function_defs)
    if bound is None:
        return True
    return name in bound


def _module_level_import_targets(index: _ModuleIndex, name: str) -> list[str]:
    if not index.source:
        return []
    try:
        module = ast.parse(index.source)
    except (SyntaxError, ValueError, RecursionError):
        return []
    targets: list[str] = []
    for statement in module.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                if local == name:
                    targets.append(alias.name if alias.asname else local)
        elif isinstance(statement, ast.ImportFrom):
            base = _ast_from_module_name(
                index.module_name,
                statement,
                is_package_init=PurePosixPath(index.file_path).name == "__init__.py",
            )
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[-1]
                if local == name and alias.name != "*":
                    targets.append(f"{base}.{alias.name}" if base else alias.name)
    return targets


def _has_conditional_import_binding(index: _ModuleIndex, name: str) -> bool:
    if not index.source:
        return True
    try:
        module = ast.parse(index.source)
    except (SyntaxError, ValueError, RecursionError):
        return True

    class ConditionalImports(ast.NodeVisitor):
        depth = 0
        found = False

        def _conditional(self, node: ast.AST) -> None:
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        visit_If = _conditional
        visit_For = _conditional
        visit_AsyncFor = _conditional
        visit_While = _conditional
        visit_With = _conditional
        visit_AsyncWith = _conditional
        visit_Try = _conditional

        def visit_Match(self, node: ast.Match) -> None:
            self._conditional(node)

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def _binds_name(self, node: ast.Import | ast.ImportFrom) -> bool:
            if isinstance(node, ast.Import):
                return any((alias.asname or alias.name.split(".", 1)[0]) == name for alias in node.names)
            return any((alias.asname or alias.name.split(".")[-1]) == name for alias in node.names)

        def visit_Import(self, node: ast.Import) -> None:
            if self.depth and self._binds_name(node):
                self.found = True

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if self.depth and self._binds_name(node):
                self.found = True

    scanner = ConditionalImports()
    scanner.visit(module)
    return scanner.found


def _proven_external_import_call(
    index: _ModuleIndex,
    raw: _RawCall,
    target: str,
    possible_targets: set[str],
    indexes: dict[str, _ModuleIndex],
) -> bool:
    """True only for an unconditional import whose resolved callable is outside the changed package roots."""
    parts = raw.function_name.split(".")
    binding_name = parts[0]
    if len(parts) == 1:
        imported = index.imports.get(binding_name)
        if imported is None:
            return False
        expected = _resolve_imported_target(imported, indexes)
        mapped = index.imports.get(binding_name)
    else:
        imported = index.module_imports.get(binding_name)
        if imported is None:
            imported = index.imports.get(binding_name)
        if imported is None:
            return False
        imported = _resolve_imported_target(imported, indexes)
        rest = ".".join(parts[1:])
        expected = (
            _resolve_imported_target(f"{imported}.{rest}", indexes)
            if _is_module_target(imported, indexes)
            else f"{imported}.{rest}"
        )
        mapped = index.module_imports.get(binding_name, index.imports.get(binding_name))
    if mapped is None:
        return False
    if _module_level_import_targets(index, binding_name) != [mapped]:
        return False
    if _has_conditional_import_binding(index, binding_name):
        return False
    if _scope_rebinds_name(index, raw.caller, binding_name):
        return False
    if expected.rsplit(".", 1)[-1] != target.rsplit(".", 1)[-1]:
        return False
    imported_root = expected.split(".", 1)[0]
    changed_roots = {candidate.split(".", 1)[0] for candidate in possible_targets}
    return imported_root not in changed_roots


def _resolve_call_uncached(
    index: _ModuleIndex,
    raw: _RawCall,
    indexes: dict[str, _ModuleIndex],
) -> tuple[str | None, bool]:
    expression = None
    if "." in raw.function_name:
        try:
            expression = ast.parse(raw.function_name, mode="eval").body
        except SyntaxError:
            pass
    if isinstance(expression, ast.Attribute):
        inferred = _resolve_instance_method_call(index, raw, expression, indexes)
        if inferred is not None:
            return inferred, True

    parts = raw.function_name.split(".")
    if len(parts) == 1:
        name = parts[0]
        if name in index.imports:
            return _resolve_imported_target(index.imports[name], indexes), False
        if name in index.functions:
            return name, False
        local = f"{index.module_name}.{name}"
        if local in index.functions:
            return local, False
        if local in index.functions_ast and not _scope_rebinds_name(
            index, raw.caller, name, ignore_module_function_defs=True
        ):
            return local, False
        return None, False

    receiver, rest = parts[0], ".".join(parts[1:])
    if receiver in {"self", "cls"} and raw.class_name:
        return f"{index.module_name}.{raw.class_name}.{rest}", True
    if receiver in index.module_imports:
        target = index.module_imports[receiver]
        if _is_module_target(target, indexes):
            return _resolve_imported_target(f"{target}.{rest}", indexes), False
        return f"{target}.{rest}", True
    if receiver in index.imports:
        target = _resolve_imported_target(index.imports[receiver], indexes)
        if _is_module_target(target, indexes):
            return _resolve_imported_target(f"{target}.{rest}", indexes), False
        return f"{target}.{rest}", True
    return None, True


def _class_name_exists(qualified_name: str, indexes: dict[str, _ModuleIndex]) -> bool:
    if isinstance(indexes, _ModuleIndexes):
        return qualified_name in indexes.class_index_map()
    return any(qualified_name in index.classes_ast for index in indexes.values())


def _resolve_receiver_class_expression(
    index: _ModuleIndex, expression: ast.AST | None, indexes: dict[str, _ModuleIndex]
) -> str | None:
    if expression is None:
        return None
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        try:
            expression = ast.parse(expression.value, mode="eval").body
        except SyntaxError:
            return None
    if isinstance(expression, ast.Subscript):
        return _resolve_receiver_class_expression(index, expression.value, indexes)
    if isinstance(expression, ast.Call):
        return _resolve_receiver_class_expression(index, expression.func, indexes)
    if isinstance(expression, ast.Name):
        if expression.id in index.imports:
            target = _resolve_imported_target(index.imports[expression.id], indexes)
        else:
            target = f"{index.module_name}.{expression.id}"
    elif isinstance(expression, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = expression
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        root = current.id
        suffix = ".".join(reversed(parts))
        if root in index.imports:
            target = f"{_resolve_imported_target(index.imports[root], indexes)}.{suffix}"
        elif root in index.module_imports:
            target = f"{index.module_imports[root]}.{suffix}"
        else:
            target = f"{index.module_name}.{root}.{suffix}"
    else:
        return None
    target = _resolve_imported_target(target, indexes)
    return target if _class_name_exists(target, indexes) else None


def _class_context_for_call(
    index: _ModuleIndex, raw: _RawCall, indexes: dict[str, _ModuleIndex]
) -> tuple[str, ast.ClassDef] | None:
    candidates = [
        (qualified_name, node)
        for qualified_name, node in index.classes_ast.items()
        if raw.class_name == node.name and raw.caller.startswith(f"{qualified_name}.")
    ]
    return max(candidates, key=lambda item: len(item[0])) if candidates else None


def _resolve_class_method(
    class_name: str,
    method_name: str,
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    mro, _complete = _class_mro_prefix(class_name, indexes)
    for candidate_class in mro:
        class_index = _class_index_for(candidate_class, indexes)
        if class_index is not None and f"{candidate_class}.{method_name}" in class_index.functions_ast:
            return f"{candidate_class}.{method_name}"
    return None


def _class_method_may_be_rebound(
    class_name: str, method_name: str, target: str, indexes: dict[str, _ModuleIndex]
) -> bool:
    if isinstance(indexes, _ModuleIndexes):
        mutations = indexes.class_mutation_cache
        if mutations is None:
            mutations = set()
            for module in indexes.values():
                if module.attr_writes is not None:
                    for expr, attr in module.attr_writes:
                        assigned_class = _resolve_receiver_class_expression(module, expr, indexes)
                        if assigned_class is not None:
                            mutations.add((assigned_class, attr))
                    continue
                try:
                    tree = ast.parse(module.source)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    targets: list[ast.AST] = []
                    if isinstance(node, (ast.Assign, ast.AnnAssign)):
                        targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
                    for item in targets:
                        if isinstance(item, ast.Attribute) and item.attr:
                            assigned_class = _resolve_receiver_class_expression(module, item.value, indexes)
                            if assigned_class is not None:
                                mutations.add((assigned_class, item.attr))
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr"\
                            and len(node.args) >= 2:
                        assigned_class = _resolve_receiver_class_expression(module, node.args[0], indexes)
                        if assigned_class is not None:
                            attribute = node.args[1].value if isinstance(node.args[1], ast.Constant)\
                                and isinstance(node.args[1].value, str) else "*"
                            mutations.add((assigned_class, attribute))
            indexes.class_mutation_cache = mutations
    else:
        mutations = set()
    mro, _complete = _class_mro_prefix(class_name, indexes)
    target_class = target.rsplit(".", 1)[0]
    if target_class not in mro:
        return True
    for candidate in mro:
        if (candidate, method_name) in mutations or (candidate, "*") in mutations:
            return True
        if candidate == target_class:
            break
    return False


def _instance_method_shadowed(
    index: _ModuleIndex, raw: _RawCall, receiver: ast.AST, method_name: str
) -> bool:
    function = index.functions_ast.get(raw.caller)
    if function is None:
        return False
    writes_by_attr = index.fn_attr_writes_cache.get(raw.caller)
    if writes_by_attr is None:
        writes_by_attr = {}

        class Writes(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                if node is function:
                    for child in node.body:
                        self.visit(child)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                return

            def _target(self, node: ast.AST) -> None:
                if isinstance(node, ast.Attribute):
                    writes_by_attr.setdefault(node.attr, []).append(
                        (ast.dump(node.value, include_attributes=False), int(getattr(node, "lineno", 0)))
                    )

            def visit_Assign(self, node: ast.Assign) -> None:
                for target in node.targets:
                    self._target(target)
                self.generic_visit(node.value)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                self._target(node.target)
                if node.value is not None:
                    self.generic_visit(node.value)

            def visit_Call(self, node: ast.Call) -> None:
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "setattr"
                    and len(node.args) >= 3
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    writes_by_attr.setdefault(node.args[1].value, []).append(
                        (ast.dump(node.args[0], include_attributes=False), int(node.lineno))
                    )
                self.generic_visit(node)

        Writes().visit(function)
        index.fn_attr_writes_cache[raw.caller] = writes_by_attr
    entries = writes_by_attr.get(method_name)
    if not entries:
        return False
    receiver_dump = ast.dump(receiver, include_attributes=False)
    return any(dump == receiver_dump and lineno < raw.line_number for dump, lineno in entries)


def _resolve_callable_expression(
    index: _ModuleIndex, expression: ast.AST, indexes: dict[str, _ModuleIndex]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if isinstance(expression, ast.Name):
        if expression.id in index.imports:
            target = _resolve_imported_target(index.imports[expression.id], indexes)
        else:
            target = f"{index.module_name}.{expression.id}"
    elif isinstance(expression, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = expression
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        root, suffix = current.id, ".".join(reversed(parts))
        if root in index.imports:
            target = f"{_resolve_imported_target(index.imports[root], indexes)}.{suffix}"
        elif root in index.module_imports:
            target = f"{index.module_imports[root]}.{suffix}"
        else:
            target = f"{index.module_name}.{root}.{suffix}"
    else:
        return None
    target = _resolve_imported_target(target, indexes)
    if isinstance(indexes, _ModuleIndexes):
        owner = indexes.function_index_map().get(target)
        return owner.functions_ast[target] if owner is not None else None
    return next(
        (candidate.functions_ast[target] for candidate in indexes.values() if target in candidate.functions_ast),
        None,
    )


def _return_annotation_class(
    index: _ModuleIndex, function: ast.FunctionDef | ast.AsyncFunctionDef,
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    return _resolve_receiver_class_expression(index, function.returns, indexes)


def _function_for_qualified_name(
    qualified_name: str, indexes: dict[str, _ModuleIndex]
) -> tuple[_ModuleIndex, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if isinstance(indexes, _ModuleIndexes):
        owner = indexes.function_index_map().get(qualified_name)
        return (owner, owner.functions_ast[qualified_name]) if owner is not None else None
    for index in indexes.values():
        function = index.functions_ast.get(qualified_name)
        if function is not None:
            return index, function
    return None


def _function_returns(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    class Returns(ast.NodeVisitor):
        def __init__(self) -> None:
            self.items: list[ast.Return] = []

        def visit_Return(self, node: ast.Return) -> None:
            self.items.append(node)

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if node is function:
                for child in node.body:
                    self.visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    visitor = Returns()
    visitor.visit(function)
    return visitor.items


def _builtin_decorator(
    function_index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    indexes: dict[str, _ModuleIndex],
    name: str,
) -> bool:
    """Accept a builtin decorator only when static module binding resolves it exactly."""
    if len(function.decorator_list) != 1:
        return False
    decorator = function.decorator_list[0]
    if not isinstance(decorator, ast.Name) or decorator.id != name:
        return False
    module_sources = (
        indexes.module_sources_dict()
        if isinstance(indexes, _ModuleIndexes)
        else {item.module_name: item.source for item in indexes.values()}
    )
    if not _resolves_to_builtin_name(function_index.module_name, name, module_sources):
        return False
    # A class namespace can shadow a builtin for decorators evaluated later in
    # that class body. Reject the inference if the class binds this name.
    for class_name, class_node in function_index.classes_ast.items():
        if not any(member is function for member in class_node.body):
            continue
        for member in class_node.body:
            if member is function:
                break
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and member.name == name:
                return False
            targets: list[ast.AST] = []
            if isinstance(member, ast.Assign):
                targets = member.targets
            elif isinstance(member, ast.AnnAssign):
                targets = [member.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return False
        break
    return True


def _resolves_to_builtin_name(
    module_name: str,
    symbol: str,
    module_sources: dict[str, str | None],
    seen: frozenset[tuple[str, str]] = frozenset(),
) -> bool:
    """Resolve one decorator name through exact, unconditional static bindings."""
    if symbol not in vars(builtins):
        return False
    if module_name == "builtins":
        return True
    key = (module_name, symbol)
    if key in seen:
        return False
    source = module_sources.get(module_name)
    if source is None:
        return False
    collected = _module_export_bindings(module_name, source)
    if collected is None:
        return False
    bindings, invalid, star_imports = collected
    candidates = bindings.get(symbol, [])
    if symbol in invalid or star_imports:
        return False
    if not candidates:
        return True
    if len(candidates) != 1:
        return False
    kind, value, assumptions = candidates[0]
    if assumptions:
        return False
    next_seen = seen | {key}
    if kind == "import_symbol":
        target_module, _, target_symbol = str(value).rpartition(".")
        return _resolves_to_builtin_name(target_module, target_symbol, module_sources, next_seen)
    if kind == "expression" and isinstance(value, ast.Name):
        return _resolves_to_builtin_name(module_name, value.id, module_sources, next_seen)
    return False


def _is_plain_classmethod(
    function_index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    indexes: dict[str, _ModuleIndex],
) -> bool:
    return _builtin_decorator(function_index, function, indexes, "classmethod")


def _is_plain_property(
    function_index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    indexes: dict[str, _ModuleIndex],
) -> bool:
    return _builtin_decorator(function_index, function, indexes, "property")


def _property_has_setter(class_node: ast.ClassDef, attribute: str) -> bool:
    for member in class_node.body:
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) or member.name != attribute:
            continue
        if any(
            isinstance(decorator, ast.Attribute)
            and decorator.attr == "setter"
            and isinstance(decorator.value, ast.Name)
            and decorator.value.id == attribute
            for decorator in member.decorator_list
        ):
            return True
    return False


def _class_mro_names(
    class_name: str,
    indexes: dict[str, _ModuleIndex],
    seen: frozenset[str] = frozenset(),
) -> list[str] | None:
    if class_name == "builtins.object":
        return [class_name]
    if class_name in seen:
        return None
    class_index = _class_index_for(class_name, indexes)
    if class_index is None:
        return None
    bases = class_index.classes_ast[class_name].bases
    base_names: list[str] = []
    for base in bases:
        base_name = _resolve_receiver_class_expression(class_index, base, indexes)
        if base_name is None and isinstance(base, ast.Name) and base.id == "object":
            base_name = "builtins.object"
        if base_name is None:
            return None
        base_names.append(base_name)
    path = seen | {class_name}
    sequences: list[list[str]] = []
    for base_name in base_names:
        base_mro = _class_mro_names(base_name, indexes, path)
        if base_mro is None:
            return None
        sequences.append(list(base_mro))
    if base_names:
        sequences.append(list(base_names))

    names = [class_name]
    while any(sequences):
        sequences = [sequence for sequence in sequences if sequence]
        candidate = next(
            (
                sequence[0]
                for sequence in sequences
                if all(sequence[0] not in other[1:] for other in sequences)
            ),
            None,
        )
        if candidate is None:
            return None
        names.append(candidate)
        for sequence in sequences:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)
    return names


def _class_mro_prefix(
    class_name: str,
    indexes: dict[str, _ModuleIndex],
    seen: frozenset[str] = frozenset(),
) -> tuple[list[str], bool]:
    """Return only the MRO prefix whose order is proven by local source.

    A single-inheritance chain has a stable prefix even when its tail is an
    external base: each known subclass is necessarily searched first. With
    multiple inheritance, an incomplete base MRO can constrain C3 ordering, so
    retain only the class itself until every direct base is fully known.
    """
    if class_name == "builtins.object":
        return [class_name], True
    if class_name in seen:
        return [], False
    if not seen and isinstance(indexes, _ModuleIndexes):
        cached_mro = indexes._mro_prefix_cache.get(class_name)
        if cached_mro is not None:
            return list(cached_mro[0]), cached_mro[1]
    class_index = _class_index_for(class_name, indexes)
    if class_index is None:
        if not seen and isinstance(indexes, _ModuleIndexes):
            indexes._mro_prefix_cache[class_name] = ([], False)
        return [], False
    bases = class_index.classes_ast[class_name].bases
    base_names: list[str] = []
    for base in bases:
        base_name = _resolve_receiver_class_expression(class_index, base, indexes)
        if base_name is None and isinstance(base, ast.Name) and base.id == "object":
            base_name = "builtins.object"
        if base_name is None:
            if not seen and isinstance(indexes, _ModuleIndexes):
                indexes._mro_prefix_cache[class_name] = ([class_name], False)
            return [class_name], False
        base_names.append(base_name)
    if not base_names:
        if not seen and isinstance(indexes, _ModuleIndexes):
            indexes._mro_prefix_cache[class_name] = ([class_name], True)
        return [class_name], True

    path = seen | {class_name}
    base_prefixes = [
        _class_mro_prefix(base_name, indexes, path)
        for base_name in base_names
    ]
    if len(base_names) == 1:
        prefix, complete = base_prefixes[0]
        res = ([class_name, *prefix], complete)
        if not seen and isinstance(indexes, _ModuleIndexes):
            indexes._mro_prefix_cache[class_name] = (list(res[0]), res[1])
        return res
    if not all(complete for _prefix, complete in base_prefixes):
        if not seen and isinstance(indexes, _ModuleIndexes):
            indexes._mro_prefix_cache[class_name] = ([class_name], False)
        return [class_name], False

    sequences = [list(prefix) for prefix, _complete in base_prefixes]
    sequences.append(list(base_names))
    names = [class_name]
    while any(sequences):
        sequences = [sequence for sequence in sequences if sequence]
        candidate = next(
            (
                sequence[0]
                for sequence in sequences
                if all(sequence[0] not in other[1:] for other in sequences)
            ),
            None,
        )
        if candidate is None:
            if not seen and isinstance(indexes, _ModuleIndexes):
                indexes._mro_prefix_cache[class_name] = ([class_name], False)
            return [class_name], False
        names.append(candidate)
        for sequence in sequences:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)
    if not seen and isinstance(indexes, _ModuleIndexes):
        indexes._mro_prefix_cache[class_name] = (list(names), True)
    return names, True


def _property_getter(
    class_name: str, attribute: str, indexes: dict[str, _ModuleIndex]
) -> tuple[str, _ModuleIndex, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    mro, _complete = _class_mro_prefix(class_name, indexes)
    for candidate_class in mro:
        class_index = _class_index_for(candidate_class, indexes)
        if class_index is None:
            continue
        class_node = class_index.classes_ast[candidate_class]
        methods = [
            item for item in class_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == attribute
        ]
        if not methods:
            continue
        getter = next((item for item in methods if _is_plain_property(class_index, item, indexes)), None)
        if getter is None or _property_has_setter(class_node, attribute):
            return None
        if any(
            isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
            and member.name in {"__getattribute__", "__getattr__"}
            for member in class_node.body
        ):
            return None
        return f"{candidate_class}.{attribute}", class_index, getter
    return None


def _stable_init_attribute_class(
    class_name: str, attribute: str, indexes: dict[str, _ModuleIndex],
) -> str | None:
    if isinstance(indexes, _ModuleIndexes):
        ckey = (class_name, attribute)
        if ckey in indexes._init_attr_class_cache:
            return indexes._init_attr_class_cache[ckey]
        res = _stable_init_attribute_class_uncached(class_name, attribute, indexes)
        indexes._init_attr_class_cache[ckey] = res
        return res
    return _stable_init_attribute_class_uncached(class_name, attribute, indexes)


def _stable_init_attribute_class_uncached(
    class_name: str, attribute: str, indexes: dict[str, _ModuleIndex],
) -> str | None:
    class_index = _class_index_for(class_name, indexes)
    if class_index is None:
        return None
    class_node = class_index.classes_ast[class_name]
    if any(
        isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
        and member.name in {"__setattr__", "__getattribute__", "__getattr__"}
        for member in class_node.body
    ):
        return None
    if any(
        isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and member.name == attribute
        for member in class_node.body
    ):
        return None
    for member in class_node.body:
        targets: list[ast.AST] = []
        if isinstance(member, ast.Assign):
            targets = member.targets
        elif isinstance(member, ast.AnnAssign):
            targets = [member.target]
        if any(isinstance(target, ast.Name) and target.id == attribute for target in targets):
            # A class-level descriptor or binding may mediate instance reads/writes.
            return None
    assignments: list[tuple[ast.AST, ast.AST, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    class Writes(ast.NodeVisitor):
        def __init__(self, function: ast.FunctionDef | ast.AsyncFunctionDef):
            self.function = function

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if node is self.function:
                for child in node.body:
                    self.visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                        and target.value.id == "self" and target.attr == attribute):
                    assignments.append((target, node.value, self.function))
            self.generic_visit(node.value)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            target = node.target
            if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                    and target.value.id == "self" and target.attr == attribute and node.value is not None):
                assignments.append((target, node.value, self.function))
            if node.value is not None:
                self.generic_visit(node.value)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name) and node.func.id == "setattr" and len(node.args) >= 2:
                if isinstance(node.args[0], ast.Name) and node.args[0].id == "self":
                    if not isinstance(node.args[1], ast.Constant) or node.args[1].value == attribute:
                        assignments.append((node, node.args[-1], self.function))
            self.generic_visit(node)

    methods = [item for item in class_node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for method in methods:
        Writes(method).visit(method)
    if not assignments:
        return None
    resolved_classes: set[str] = set()
    for _target, value, _owner in assignments:
        if not isinstance(value, ast.Call):
            return None
        assigned_class = _resolve_receiver_class_expression(class_index, value.func, indexes)
        if assigned_class is None:
            return None
        resolved_classes.add(assigned_class)
    return next(iter(resolved_classes)) if len(resolved_classes) == 1 else None


def _factory_return_class(
    function_index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    indexes: dict[str, _ModuleIndex],
    *,
    bound_class: str | None = None,
    depth: int = 0,
    seen: set[str] | None = None,
) -> str | None:
    """Infer a factory only when every return is a same-class construction and fallthrough is impossible."""
    if depth >= 3 or isinstance(function, ast.AsyncFunctionDef):
        return None
    if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(function)):
        return None
    visited = set() if seen is None else seen
    qualified_name = next(
        (name for name, node in function_index.functions_ast.items() if node is function),
        None,
    )
    if qualified_name is None or qualified_name in visited:
        return None
    visited.add(qualified_name)
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body.pop(0)
    if not body or not isinstance(body[-1], ast.Return):
        return None
    returns = _function_returns(function)
    if not returns or any(item.value is None for item in returns):
        return None

    def returned_class(expression: ast.expr) -> str | None:
        if isinstance(expression, ast.Call):
            if (isinstance(expression.func, ast.Name) and expression.func.id == "cls"
                    and bound_class is not None
                    and _is_plain_classmethod(function_index, function, indexes)):
                return bound_class
            class_name = _resolve_receiver_class_expression(function_index, expression.func, indexes)
            if class_name is not None:
                return class_name
            factory = _resolve_callable_expression(function_index, expression.func, indexes)
            if factory is not None:
                owner = next(
                    (item for item in indexes.values() if factory in item.functions_ast.values()),
                    None,
                )
                if owner is not None:
                    return _factory_return_class(
                        owner, factory, indexes, depth=depth + 1, seen=visited
                    )
            return None
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name) and expression.value.id == "self":
            context = next((name for name, node in function_index.classes_ast.items()
                            if qualified_name.startswith(f"{name}.")), None)
            if context is not None:
                return _stable_init_attribute_class(context, expression.attr, indexes)
        if isinstance(expression, ast.Name):
            # Accept a local alias only for one direct constructor assignment in the function body.
            assignments: list[ast.expr] = []
            for statement in body[:-1]:
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1\
                        and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id == expression.id:
                    assignments.append(statement.value)
                elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)\
                        and statement.target.id == expression.id and statement.value is not None:
                    assignments.append(statement.value)
                elif any(isinstance(node, ast.Name) and node.id == expression.id and isinstance(node.ctx, ast.Store)
                         for node in ast.walk(statement)):
                    return None
            if len(assignments) != 1 or not isinstance(assignments[0], ast.Call):
                return None
            return _resolve_receiver_class_expression(function_index, assignments[0].func, indexes)
        return None

    classes = {returned_class(item.value) for item in returns if item.value is not None}
    if None in classes or len(classes) != 1:
        return None
    return next(iter(classes))


def _expression_instance_class(
    index: _ModuleIndex,
    raw: _RawCall,
    expression: ast.AST,
    indexes: dict[str, _ModuleIndex],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> str | None:
    if depth >= 3:
        return None
    if isinstance(expression, ast.Call):
        direct = _resolve_receiver_class_expression(index, expression.func, indexes)
        if direct is not None:
            return direct
        function = _resolve_callable_expression(index, expression.func, indexes)
        bound_class = None
        if function is None and isinstance(expression.func, ast.Attribute):
            bound_class = _resolve_receiver_class_expression(index, expression.func.value, indexes)
            if bound_class is None:
                bound_class = _expression_instance_class(
                    index, raw, expression.func.value, indexes, depth=depth + 1, seen=seen
                )
            if bound_class is not None:
                target = _resolve_class_method(bound_class, expression.func.attr, indexes)
                resolved = _function_for_qualified_name(target, indexes) if target else None
                if resolved is not None:
                    function_index, function = resolved
                else:
                    function_index = index
            else:
                function_index = index
        else:
            if function is not None and isinstance(indexes, _ModuleIndexes):
                function_index = indexes.function_obj_index_map().get(id(function), index)
            else:
                function_index = next(
                    (item for item in indexes.values() if function is not None and function in item.functions_ast.values()),
                    index,
                )
        if function is None:
            return None
        return _factory_return_class(
            function_index, function, indexes, bound_class=bound_class, depth=depth, seen=seen
        )
    if isinstance(expression, ast.Name):
        if expression.id in {"self", "cls"}:
            context = _class_context_for_call(index, raw, indexes)
            return context[0] if context else None
        function = index.functions_ast.get(raw.caller)
        if function is not None:
            return _function_local_class(index, function, expression.id, raw.line_number, indexes)
    if isinstance(expression, ast.Attribute):
        if isinstance(expression.value, ast.Name) and expression.value.id == "self":
            context = _class_context_for_call(index, raw, indexes)
            return _self_attribute_class(index, raw, expression.attr, indexes) if context else None
        base_class = _expression_instance_class(index, raw, expression.value, indexes, depth=depth + 1, seen=seen)
        if base_class is None:
            return None
        property_def = _property_getter(base_class, expression.attr, indexes)
        if property_def is None:
            return None
        target, getter_index, getter = property_def
        del target
        return _factory_return_class(getter_index, getter, indexes, depth=depth + 1, seen=seen)
    return None


def _function_local_class(
    index: _ModuleIndex,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    variable: str,
    before_line: int,
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    for argument in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]:
        if argument.arg == variable and argument.annotation is not None:
            annotated = _resolve_receiver_class_expression(index, argument.annotation, indexes)
            if annotated is not None:
                return annotated
    result: str | None = None
    for statement in function.body:
        if getattr(statement, "lineno", before_line + 1) >= before_line:
            break
        if isinstance(statement, ast.Assign):
            targets, value = statement.targets, statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets, value = [statement.target], statement.value
        else:
            continue
        if not any(isinstance(target, ast.Name) and target.id == variable for target in targets):
            continue
        inferred = _resolve_receiver_class_expression(index, value, indexes)
        if inferred is None and isinstance(statement, ast.AnnAssign):
            inferred = _resolve_receiver_class_expression(index, statement.annotation, indexes)
        if inferred is None and isinstance(value, ast.Call):
            factory = _resolve_callable_expression(index, value.func, indexes)
            if factory is not None:
                inferred = _return_annotation_class(index, factory, indexes)
        result = inferred
    return result


def _self_attribute_class(
    index: _ModuleIndex,
    raw: _RawCall,
    attribute: str,
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    context = _class_context_for_call(index, raw, indexes)
    if context is None:
        return None
    class_name, _class_node = context
    return _stable_init_attribute_class(class_name, attribute, indexes)


def _resolve_instance_method_call(
    index: _ModuleIndex,
    raw: _RawCall,
    expression: ast.Attribute,
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    receiver = expression.value
    class_name: str | None = None
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name) and receiver.func.id == "super":
        if receiver.args or receiver.keywords:
            return None
        context = _class_context_for_call(index, raw, indexes)
        if context is not None:
            current_class, _class_node = context
            mro, _complete = _class_mro_prefix(current_class, indexes)
            for candidate_class in mro[1:]:
                candidate_index = _class_index_for(candidate_class, indexes)
                if candidate_index is not None and f"{candidate_class}.{expression.attr}" in candidate_index.functions_ast:
                    return f"{candidate_class}.{expression.attr}"
            return None
        return None
    elif isinstance(receiver, ast.Call):
        class_name = _expression_instance_class(index, raw, receiver, indexes)
    elif isinstance(receiver, ast.Name) and receiver.id in {"self", "cls"}:
        context = _class_context_for_call(index, raw, indexes)
        if context is not None:
            class_name = context[0]
    elif isinstance(receiver, ast.Name):
        function = index.functions_ast.get(raw.caller)
        if function is not None:
            class_name = _function_local_class(index, function, receiver.id, raw.line_number, indexes)
    elif isinstance(receiver, ast.Attribute):
        class_name = _expression_instance_class(index, raw, receiver, indexes)

    if class_name is None:
        return None
    if _instance_method_shadowed(index, raw, receiver, expression.attr):
        return None
    target = _resolve_class_method(class_name, expression.attr, indexes)
    if target is not None and _class_method_may_be_rebound(class_name, expression.attr, target, indexes):
        return None
    return target


def _resolve_imported_target(target: str, indexes: dict[str, _ModuleIndex]) -> str:
    """Follow unambiguous package re-exports without importing repository code."""
    original_target = target
    cache = indexes.imported_target_cache if isinstance(indexes, _ModuleIndexes) else None
    if cache is not None and target in cache:
        return cache[target]

    if isinstance(indexes, _ModuleIndexes):
        by_module = indexes.package_init_modules
        if by_module is None:
            by_module = {
                module.module_name: module
                for module in indexes.values()
                if PurePosixPath(module.file_path).name == "__init__.py"
            }
            indexes.package_init_modules = by_module
    else:
        by_module = {
            module.module_name: module
            for module in indexes.values()
            if PurePosixPath(module.file_path).name == "__init__.py"
        }

    seen: set[str] = set()
    while target not in seen and not _is_module_target(target, indexes):
        seen.add(target)
        if "." not in target:
            break
        package_name, exported_name = target.rsplit(".", 1)
        package = by_module.get(package_name)
        if package is None:
            break
        if isinstance(indexes, _ModuleIndexes):
            exp_key = (package.module_name, True)
            if exp_key in indexes._module_export_cache:
                collected = indexes._module_export_cache[exp_key]
            else:
                collected = _module_export_bindings(
                    package.module_name, package.source, is_package_init=True
                )
                indexes._module_export_cache[exp_key] = collected
        else:
            collected = _module_export_bindings(
                package.module_name, package.source, is_package_init=True
            )
        if collected is None:
            break
        bindings, invalid, star_imports = collected
        if exported_name in invalid:
            break
        if star_imports:
            roots = indexes.import_roots if isinstance(indexes, _ModuleIndexes) else ()
            resolution = resolve_static_wildcard_export(package.module_name, exported_name, roots)
            if resolution.status == "resolved" and resolution.target_module is not None:
                target = f"{resolution.target_module}.{exported_name}"
                continue
            if resolution.status == "unresolved":
                break
        candidates = bindings.get(exported_name, [])
        if len(candidates) != 1:
            break
        kind, value, assumptions = candidates[0]
        if kind != "import_symbol" or assumptions:
            break
        target = str(value)
    if cache is not None:
        cache[original_target] = target
    return target


def _is_module_target(target: str, indexes: dict[str, _ModuleIndex]) -> bool:
    """Resolve module targets from repo files or import metadata, never name heuristics."""
    cache = indexes.module_target_cache if isinstance(indexes, _ModuleIndexes) else None
    if cache is not None and target in cache:
        return cache[target]
    if (
        target in indexes.module_names_set()
        if isinstance(indexes, _ModuleIndexes)
        else any(module.module_name == target for module in indexes.values())
    ):
        if cache is not None:
            cache[target] = True
        return True
    if isinstance(sys.modules.get(target), ModuleType):
        if cache is not None:
            cache[target] = True
        return True

    parts = target.split(".")
    search_path = None
    for position in range(len(parts)):
        qualified = ".".join(parts[: position + 1])
        try:
            spec = PathFinder.find_spec(qualified, search_path)
        except (ImportError, ValueError, KeyError):
            if cache is not None:
                cache[target] = False
            return False
        if spec is None and position == 0 and parts[0] in sys.builtin_module_names:
            if position == len(parts) - 1:
                if cache is not None:
                    cache[target] = True
                return True
            if cache is not None:
                cache[target] = False
            return False
        if spec is None:
            if cache is not None:
                cache[target] = False
            return False
        if position < len(parts) - 1:
            search_path = spec.submodule_search_locations
            if search_path is None:
                if cache is not None:
                    cache[target] = False
                return False
    if cache is not None:
        cache[target] = True
    return True


def _argument_shape(raw: _RawCall, is_method: bool) -> ImpactedCallSite:
    return ImpactedCallSite(
        caller_qualified_name=raw.caller,
        callee_qualified_name="",
        file_path=raw.file_path,
        line_number=raw.line_number,
        n_positional=raw.n_positional,
        keywords=raw.keywords,
        star_args=raw.star_args,
        star_kwargs=raw.star_kwargs,
        arg_literals=raw.arg_literals,
        arg_sources=raw.arg_sources,
        is_method_call=is_method,
        node_source=raw.node_source,
        provenance=_provenance(
            "call_site_resolution", "resolved", raw.file_path, raw.line_number, raw.node_source
        ),
    )


def _pure_star_forwarding_wrapper(
    index: _ModuleIndex,
    wrapper_name: str,
    indexes: dict[str, _ModuleIndex],
    changed_names: set[str],
) -> tuple[str, bool, _RawCall] | None:
    function = index.functions_ast.get(wrapper_name)
    if not isinstance(function, ast.FunctionDef) or function.decorator_list:
        return None
    parameters = function.args
    if (
        parameters.posonlyargs
        or parameters.kwonlyargs
        or parameters.defaults
        or any(default is not None for default in parameters.kw_defaults)
        or parameters.vararg is None
        or parameters.kwarg is None
        or parameters.vararg.annotation is not None
        or parameters.kwarg.annotation is not None
        or function.returns is not None
    ):
        return None
    positional = parameters.args
    class_prefixes = [
        class_name for class_name in index.classes_ast
        if wrapper_name.startswith(f"{class_name}.")
    ]
    has_receiver = bool(positional)
    if has_receiver and (
        len(positional) != 1
        or positional[0].arg not in {"self", "cls"}
        or positional[0].annotation is not None
        or not class_prefixes
    ):
        return None
    if not has_receiver and class_prefixes:
        # A descriptor would inject the receiver into *args, so the caller's
        # explicit arguments would not match the forwarded call.
        return None
    if any(argument.annotation is not None for argument in positional):
        return None
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if len(body) != 1:
        return None
    statement = body[0]
    call = statement.value if isinstance(statement, ast.Return) else None
    if (
        not isinstance(call, ast.Call)
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Starred)
        or not isinstance(call.args[0].value, ast.Name)
        or call.args[0].value.id != parameters.vararg.arg
        or len(call.keywords) != 1
        or call.keywords[0].arg is not None
        or not isinstance(call.keywords[0].value, ast.Name)
        or call.keywords[0].value.id != parameters.kwarg.arg
    ):
        return None
    raw_call = next((
        raw for raw in index.calls
        if raw.caller == wrapper_name
        and raw.line_number == call.lineno
        and raw.star_args
        and raw.star_kwargs
    ), None)
    if raw_call is None:
        return None
    target, is_method = _resolve_call(index, raw_call, indexes)
    if target not in changed_names:
        return None
    return target, is_method, raw_call


def _known_forwarded_keyword_parameters(
    index: _ModuleIndex,
    raw: _RawCall,
    target: str,
    is_method: bool,
    indexes: dict[str, _ModuleIndex],
) -> tuple[tuple[str, ...], bool, str, dict[str, str]] | None:
    """Map a direct ``**kwargs`` parameter to names in a statically known callee signature."""
    if not raw.star_kwargs or raw.star_args:
        return None
    caller = index.functions_ast.get(raw.caller)
    if caller is None or caller.args.kwarg is None:
        return None
    callee = next(
        (candidate.functions_ast[target] for candidate in indexes.values() if target in candidate.functions_ast),
        None,
    )
    if callee is None:
        return None

    matching_calls: list[ast.Call] = []

    class FindCall(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if (
                int(getattr(node, "lineno", -1)) == raw.line_number
                and ast.unparse(node.func) == raw.function_name
                and any(keyword.arg is None for keyword in node.keywords)
            ):
                matching_calls.append(node)
            self.generic_visit(node)

    FindCall().visit(caller)
    if len(matching_calls) != 1:
        return None
    call = matching_calls[0]
    star_values = [keyword.value for keyword in call.keywords if keyword.arg is None]
    if len(star_values) != 1 or not isinstance(star_values[0], ast.Name):
        return None
    kwargs_name = caller.args.kwarg.arg
    if star_values[0].id != kwargs_name:
        return None

    # Only pass through when intervening mutations preserve the incoming mapping.
    # A literal setdefault is safe: each named value is still either provided by
    # the caller or supplied by that explicit default. Other mutations remain UNKNOWN.
    allowed_uses = {id(star_values[0])}
    keyword_defaults: dict[str, str] = {}
    top_level_defaults = {
        id(statement.value): statement.value
        for statement in caller.body
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
    }
    for node in ast.walk(caller):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        if not isinstance(receiver, ast.Name) or receiver.id != kwargs_name or node is call:
            continue
        if (
            id(node) not in top_level_defaults
            or node.func.attr != "setdefault"
            or len(node.args) != 2
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
            or not isinstance(node.args[1], ast.Constant)
            or node.keywords
            or int(getattr(node, "lineno", raw.line_number)) >= raw.line_number
        ):
            return None
        keyword_defaults[node.args[0].value] = ast.unparse(node.args[1])
        allowed_uses.add(id(receiver))
    if any(
        node.id == kwargs_name and id(node) not in allowed_uses
        for node in ast.walk(caller) if isinstance(node, ast.Name)
    ):
        return None

    positional = [*callee.args.posonlyargs, *callee.args.args]
    receiver = 1 if is_method else 0
    already_bound = {argument.arg for argument in positional[receiver:receiver + raw.n_positional]}
    already_bound.update(raw.keywords)
    keyword_parameters = [
        argument.arg
        for argument in [*positional[receiver:], *callee.args.kwonlyargs]
        if argument.arg not in already_bound
    ]
    return tuple(dict.fromkeys(keyword_parameters)), callee.args.kwarg is not None, kwargs_name, keyword_defaults


def _mentions_identifier(source: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", source) is not None


def _property_read_sites(
    indexes: dict[str, _ModuleIndex], changed_names: set[str]
) -> list[ImpactedCallSite]:
    """Turn statically resolved reads of changed @property getters into ordinary zero-arg method sites."""
    properties: dict[str, set[str]] = {}
    for index in indexes.values():
        for qualified_name in changed_names:
            function = index.functions_ast.get(qualified_name)
            if function is not None and _is_plain_property(index, function, indexes):
                properties.setdefault(qualified_name.rsplit(".", 1)[-1], set()).add(qualified_name)
    if not properties:
        return []

    sites: list[ImpactedCallSite] = []
    for index in indexes.values():
        for caller, function in index.functions_ast.items():
            caller_classes = [name for name in index.classes_ast if caller.startswith(f"{name}.")]
            class_name = max(caller_classes, key=len) if caller_classes else None
            class_short = index.classes_ast[class_name].name if class_name else None
            called_attributes: set[int] = set()

            class Calls(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    if node is function:
                        for child in node.body:
                            self.visit(child)

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Call(self, node: ast.Call) -> None:
                    if isinstance(node.func, ast.Attribute):
                        called_attributes.add(id(node.func))
                    self.generic_visit(node)

            Calls().visit(function)

            class Reads(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    if node is function:
                        for child in node.body:
                            self.visit(child)

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Attribute(self, node: ast.Attribute) -> None:
                    if node.attr not in properties or id(node) in called_attributes\
                            or not isinstance(node.ctx, ast.Load):
                        self.generic_visit(node)
                        return
                    source = _ast_source_segment(index.source, node) or ast.unparse(node)
                    raw = _RawCall(
                        caller=caller,
                        file_path=index.file_path,
                        line_number=int(getattr(node, "lineno", 1)),
                        function_name=ast.unparse(node),
                        n_positional=0,
                        keywords=(),
                        star_args=False,
                        star_kwargs=False,
                        arg_literals={},
                        arg_sources={},
                        class_name=class_short,
                        node_source=source,
                    )
                    receiver_class = _expression_instance_class(index, raw, node.value, indexes)
                    property_def = _property_getter(receiver_class, node.attr, indexes) if receiver_class else None
                    if property_def is not None and property_def[0] in properties[node.attr]:
                        target = property_def[0]
                        sites.append(ImpactedCallSite(
                            caller_qualified_name=caller,
                            callee_qualified_name=target,
                            file_path=index.file_path,
                            line_number=int(getattr(node, "lineno", 1)),
                            n_positional=0,
                            keywords=(),
                            star_args=False,
                            star_kwargs=False,
                            arg_literals={},
                            arg_sources={},
                            is_method_call=True,
                            node_source=source,
                            provenance=_provenance(
                                "property_read_resolution", "resolved", index.file_path,
                                int(getattr(node, "lineno", 1)), source,
                            ),
                        ))
                    self.generic_visit(node)

            Reads().visit(function)
    unique = {
        (site.caller_qualified_name, site.callee_qualified_name, site.file_path, site.line_number, site.node_source): site
        for site in sites
    }
    return sorted(unique.values(), key=lambda site: (site.file_path, site.line_number, site.callee_qualified_name))


def _resolve_impacted_calls(
    before: dict[str, _ModuleIndex], changed_names: set[str]
) -> tuple[list[ImpactedCallSite], list[UnresolvedConstruct], dict[str, str]]:
    sites: list[ImpactedCallSite] = []
    unresolved: list[UnresolvedConstruct] = []
    forwarding_targets: dict[str, str] = {}
    method_targets_by_name: dict[str, set[str]] = {}
    known_callables = {
        qualified_name
        for index in before.values()
        for qualified_name in index.functions_ast
    }
    for qualified_name in changed_names:
        method_targets_by_name.setdefault(qualified_name.rsplit(".", 1)[-1], set()).add(
            qualified_name
        )
    property_sites = _property_read_sites(before, changed_names)
    property_site_keys = {
        (site.file_path, site.line_number, site.caller_qualified_name, site.callee_qualified_name, site.node_source)
        for site in property_sites
    }
    unresolved.extend(
        item for item in _unresolved_method_references(before, method_targets_by_name)
        if not (
            item.kind == "unresolved_method_reference"
            and (item.file_path, item.line_number, item.caller_qualified_name, item.target_qualified_name, item.source)
            in property_site_keys
        )
    )
    sites.extend(property_sites)
    wrappers: dict[str, tuple[str, bool, _RawCall, _ModuleIndex]] = {}
    for index in before.values():
        for raw in index.calls:
            target, _is_method = _resolve_call(index, raw, before)
            if target not in changed_names or not (raw.star_args and raw.star_kwargs):
                continue
            wrapper = _pure_star_forwarding_wrapper(index, raw.caller, before, changed_names)
            if wrapper is not None:
                wrappers[raw.caller] = (*wrapper, index)
    for index in before.values():
        for raw in index.calls:
            target, is_method = _resolve_call(index, raw, before)
            dispatch_targets, uncertain_dispatch_targets = _changed_dynamic_dispatch_targets(
                index, raw, before, changed_names
            )
            for dispatch_target in sorted(dispatch_targets - ({target} if target else set())):
                sites.append(replace(
                    _argument_shape(raw, True),
                    callee_qualified_name=dispatch_target,
                    provenance=_provenance(
                        "subclass_override_dispatch" if "super()" not in raw.function_name
                        else "subclass_super_dispatch",
                        "resolved",
                        raw.file_path,
                        raw.line_number,
                        raw.node_source or raw.function_name,
                    ),
                ))
            for dispatch_target in sorted(uncertain_dispatch_targets - ({target} if target else set())):
                unresolved.append(UnresolvedConstruct(
                    file_path=raw.file_path,
                    line_number=raw.line_number,
                    kind="unresolved_method_receiver",
                    source=raw.node_source or raw.function_name,
                    scope="impact_call_site",
                    caller_qualified_name=raw.caller,
                    target_qualified_name=dispatch_target,
                ))
            if target not in changed_names:
                short_name = raw.function_name.rsplit(".", 1)[-1]
                possible_methods = method_targets_by_name.get(short_name, set())
                if possible_methods and (target is None or target not in known_callables):
                    for possible_target in sorted(possible_methods):
                        if _proven_external_import_call(
                            index, raw, possible_target, possible_methods, before
                        ):
                            continue
                        unresolved.append(
                            UnresolvedConstruct(
                                file_path=raw.file_path,
                                line_number=raw.line_number,
                                kind="unresolved_method_receiver",
                                source=raw.node_source or raw.function_name,
                                scope="impact_call_site",
                                caller_qualified_name=raw.caller,
                                target_qualified_name=possible_target,
                            )
                        )
                continue
            if raw.star_args and raw.star_kwargs and raw.caller in wrappers:
                wrapper_target, target_is_method, _forwarding_call, _wrapper_index = wrappers[raw.caller]
                forwarding_targets[raw.caller] = wrapper_target
                callers: list[tuple[_ModuleIndex, _RawCall, bool]] = []
                unknown_wrapper_callers = False
                for caller_index in before.values():
                    for caller_raw in caller_index.calls:
                        caller_target, caller_is_method = _resolve_call(caller_index, caller_raw, before)
                        if caller_target == raw.caller:
                            callers.append((caller_index, caller_raw, caller_is_method))
                        elif (
                            caller_target is None
                            and caller_raw.function_name.rsplit(".", 1)[-1]
                            == raw.caller.rsplit(".", 1)[-1]
                        ):
                            unknown_wrapper_callers = True
                    for unresolved_call in caller_index.unresolved:
                        if (
                            unresolved_call.target_qualified_name == raw.caller
                            or (
                                unresolved_call.kind in {
                                    "dynamic_getattr", "dynamic_call", "dynamic_import",
                                    "unknown_call", "unresolved_call",
                                }
                                and _mentions_identifier(
                                    unresolved_call.source,
                                    raw.caller.rsplit(".", 1)[-1],
                                )
                            )
                        ):
                            unknown_wrapper_callers = True
                explicit_callers = [
                    (caller_index, caller_raw, caller_is_method)
                    for caller_index, caller_raw, caller_is_method in callers
                    if not caller_raw.star_args and not caller_raw.star_kwargs
                ]
                for caller_index, caller_raw, _caller_is_method in explicit_callers:
                    forwarded = _argument_shape(caller_raw, target_is_method)
                    sites.append(ImpactedCallSite(
                        caller_qualified_name=forwarded.caller_qualified_name,
                        callee_qualified_name=wrapper_target,
                        file_path=forwarded.file_path,
                        line_number=forwarded.line_number,
                        n_positional=forwarded.n_positional,
                        keywords=forwarded.keywords,
                        star_args=False,
                        star_kwargs=False,
                        arg_literals=forwarded.arg_literals,
                        arg_sources=forwarded.arg_sources,
                        is_method_call=target_is_method,
                        node_source=forwarded.node_source,
                        provenance=_provenance(
                            "star_kwargs_forwarding_expansion",
                            "resolved",
                            caller_raw.file_path,
                            caller_raw.line_number,
                            f"{_forwarding_call.node_source} <- {caller_raw.node_source}",
                        ),
                    ))
                if callers and explicit_callers and len(callers) == len(explicit_callers) and not unknown_wrapper_callers:
                    continue
            site = _argument_shape(raw, is_method)
            site = ImpactedCallSite(
                caller_qualified_name=site.caller_qualified_name,
                callee_qualified_name=target or "",
                file_path=site.file_path,
                line_number=site.line_number,
                n_positional=site.n_positional,
                keywords=site.keywords,
                star_args=site.star_args,
                star_kwargs=site.star_kwargs,
                arg_literals=site.arg_literals,
                arg_sources=site.arg_sources,
                is_method_call=site.is_method_call,
                node_source=site.node_source,
                provenance=site.provenance,
            )
            forwarded = _known_forwarded_keyword_parameters(index, raw, target, is_method, before)
            if forwarded is not None:
                parameter_names, accepts_extra, kwargs_name, keyword_defaults = forwarded
                forwarded_sources = {
                    name: (
                        f"{kwargs_name}.get({name!r}, {keyword_defaults[name]})"
                        if name in keyword_defaults else f"**{kwargs_name}.{name}"
                    )
                    for name in parameter_names
                }
                forwarding_provenance = _provenance(
                    "star_kwargs_signature_mapping",
                    "resolved",
                    raw.file_path,
                    raw.line_number,
                    raw.node_source or raw.function_name,
                )
                forwarding_provenance.update({
                    "callee": target,
                    "keyword_parameters": list(parameter_names),
                    "extra_keywords_accepted": accepts_extra,
                    "keyword_dict": kwargs_name,
                    "keyword_defaults": keyword_defaults,
                })
                site = replace(
                    site,
                    arg_sources={**site.arg_sources, **forwarded_sources},
                    forwarded_keyword_parameters=parameter_names,
                    extra_keywords_accepted=accepts_extra,
                    provenance={
                        **site.provenance,
                        "forwarded_keyword_mapping": forwarding_provenance,
                    },
                )
            sites.append(site)
            if site.star_args or (site.star_kwargs and site.extra_keywords_accepted is None):
                unresolved.append(
                    UnresolvedConstruct(
                        file_path=raw.file_path,
                        line_number=raw.line_number,
                        kind="star_args_forwarding" if site.star_args else "star_kwargs_forwarding",
                        source=raw.function_name,
                        scope="impact_call_site",
                        caller_qualified_name=raw.caller,
                        target_qualified_name=target,
                    )
                )
    sites.sort(key=lambda item: (item.file_path, item.line_number, item.callee_qualified_name))
    return sites, unresolved, forwarding_targets


def _unresolved_method_references(
    indexes: dict[str, _ModuleIndex], method_targets_by_name: dict[str, set[str]]
) -> list[UnresolvedConstruct]:
    """Flag method-value references that can defer the call beyond this static call graph."""
    unresolved: list[UnresolvedConstruct] = []
    if not method_targets_by_name:
        return unresolved

    class MethodReferenceVisitor(ast.NodeVisitor):
        def __init__(self, index: _ModuleIndex, caller: str, root_function: ast.AST | None = None):
            self.index = index
            self.caller = caller
            self.root_function = root_function
            self.called_attributes: set[int] = set()
            self.called_names: set[int] = set()
            # a local bound from an expression that lets a changed callable escape (``strip = getattr(self, "x", changed)``):
            # a later CALL of that local is a call site the static graph cannot resolve, and gets its own record (a2rest)
            self.flagged: list[str] = []
            self.escaped_locals: dict[str, list[str]] = {}

        def visit_Assign(self, node: ast.Assign) -> None:
            before_n = len(self.flagged)
            self.generic_visit(node)
            new = list(dict.fromkeys(self.flagged[before_n:]))
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if new:
                        self.escaped_locals[target.id] = new
                    else:
                        self.escaped_locals.pop(target.id, None)  # rebound to something harmless

        def _add(self, node: ast.AST, short_name: str, kind: str = "unresolved_method_reference") -> None:
            self.flagged.append(short_name)
            for target in sorted(method_targets_by_name.get(short_name, ())):
                unresolved.append(
                    UnresolvedConstruct(
                        file_path=self.index.file_path,
                        line_number=getattr(node, "lineno", 1),
                        kind=kind,
                        source=_ast_source_segment(self.index.source, node) or ast.unparse(node),
                        scope="impact_call_site",
                        caller_qualified_name=self.caller,
                        target_qualified_name=target,
                    )
                )

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if node is not self.root_function:
                return
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                self.called_attributes.add(id(node.func))
            elif isinstance(node.func, ast.Name):
                self.called_names.add(id(node.func))
                for short_name in self.escaped_locals.get(node.func.id, ()):
                    self._add(node, short_name, "call_through_escaped_reference")
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and node.args[1].value in method_targets_by_name
            ):
                self._add(node, node.args[1].value, "dynamic_method_getattr")
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if (
                node.attr in method_targets_by_name
                and id(node) not in self.called_attributes
            ):
                self._add(node, node.attr)
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            if (
                node.id in method_targets_by_name
                and isinstance(node.ctx, ast.Load)
                and id(node) not in self.called_names
            ):
                self._add(node, node.id)

    for index in indexes.values():
        if (
            index.source
            and index.source.isascii()
            and "getattr" not in index.source
            and not any(short_name in index.source for short_name in method_targets_by_name)
        ):
            continue
        for qualified_name, function in index.functions_ast.items():
            MethodReferenceVisitor(index, qualified_name, function).visit(function)
        for class_name, class_node in index.classes_ast.items():
            for statement in class_node.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                MethodReferenceVisitor(index, class_name).visit(statement)
    return unresolved


def _reachable_callers(indexes: dict[str, _ModuleIndex], targets: set[str]) -> set[str]:
    """Return statically resolved callers that transitively reach any target."""
    reverse_edges: dict[str, set[str]] = {}
    for index in indexes.values():
        for raw in index.calls:
            callee, _ = _resolve_call(index, raw, indexes)
            if callee:
                reverse_edges.setdefault(callee, set()).add(raw.caller)
    reachable = set(targets)
    pending = list(targets)
    while pending:
        callee = pending.pop()
        for caller in reverse_edges.get(callee, ()):
            if caller not in reachable:
                reachable.add(caller)
                pending.append(caller)
    return reachable


def _known_base_reaches(
    class_name: str,
    ancestor: str,
    indexes: dict[str, _ModuleIndex],
    seen: frozenset[str] = frozenset(),
) -> bool:
    if class_name == ancestor:
        return True
    if class_name in seen:
        return False
    if not seen and isinstance(indexes, _ModuleIndexes):
        ckey = (class_name, ancestor)
        cached_reach = indexes._known_base_cache.get(ckey)
        if cached_reach is not None:
            return cached_reach
    class_index = _class_index_for(class_name, indexes)
    if class_index is None:
        if not seen and isinstance(indexes, _ModuleIndexes):
            indexes._known_base_cache[(class_name, ancestor)] = False
        return False
    path = seen | {class_name}
    reaches = any(
        (base_name := _resolve_receiver_class_expression(class_index, base, indexes)) is not None
        and _known_base_reaches(base_name, ancestor, indexes, path)
        for base in class_index.classes_ast[class_name].bases
    )
    if not seen and isinstance(indexes, _ModuleIndexes):
        indexes._known_base_cache[(class_name, ancestor)] = reaches
    return reaches


def _first_class_method(
    mro: list[str], method_name: str, indexes: dict[str, _ModuleIndex], start: int = 0
) -> str | None:
    for candidate_class in mro[start:]:
        candidate_index = _class_index_for(candidate_class, indexes)
        if candidate_index is not None and f"{candidate_class}.{method_name}" in candidate_index.functions_ast:
            return f"{candidate_class}.{method_name}"
    return None


def _changed_dynamic_dispatch_targets(
    index: _ModuleIndex,
    raw: _RawCall,
    indexes: dict[str, _ModuleIndex],
    changed_names: set[str],
) -> tuple[set[str], set[str]]:
    """Find changed overrides reachable through in-repo subclass MROs.

    The first set contains targets whose lookup order is proven by the local
    MRO prefix. The second marks changed targets that a partially known
    subclass MRO could select but cannot order safely.
    """
    if "." not in raw.function_name or not changed_names:
        return set(), set()
    short_attr = raw.function_name.rsplit(".", 1)[-1]
    if not any(
        target.count(".") >= 2 and target.rsplit(".", 1)[-1] == short_attr
        for target in changed_names
    ):
        return set(), set()
    try:
        expression = ast.parse(raw.function_name, mode="eval").body
    except SyntaxError:
        return set(), set()
    if not isinstance(expression, ast.Attribute):
        return set(), set()
    context = _class_context_for_call(index, raw, indexes)
    if context is None:
        return set(), set()
    lexical_class = context[0]
    receiver = expression.value
    is_super = (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "super"
        and not receiver.args
        and not receiver.keywords
    )
    is_self_dispatch = isinstance(receiver, ast.Name) and receiver.id in {"self", "cls"}
    if not (is_super or is_self_dispatch):
        return set(), set()

    changed_targets = {
        target for target in changed_names
        if target.rsplit(".", 1)[-1] == expression.attr
        and target.count(".") >= 2
    }
    if not changed_targets:
        return set(), set()
    resolved: set[str] = set()
    uncertain: set[str] = set()
    for candidate_class in _known_subclasses_for(lexical_class, indexes):
        if candidate_class == lexical_class:
            continue
        prefix, complete = _class_mro_prefix(candidate_class, indexes)
        lexical_in_prefix = lexical_class in prefix
        if not lexical_in_prefix and complete:
            continue
        for target in changed_targets:
            target_class = target.rsplit(".", 1)[0]
            if not _known_base_reaches(candidate_class, target_class, indexes):
                continue
            if is_super:
                if lexical_in_prefix:
                    start = prefix.index(lexical_class) + 1
                    selected = _first_class_method(prefix, expression.attr, indexes, start)
                else:
                    selected = None
            else:
                selected = _first_class_method(prefix, expression.attr, indexes)
            if selected == target:
                resolved.add(target)
            elif not complete:
                uncertain.add(target)
    return resolved, uncertain


def _added_callable_records(
    *,
    added_names: set[str],
    after: dict[str, _ModuleIndex],
    post_call_sites: list[ImpactedCallSite],
    modified_callers: set[str],
    unknown_edges: tuple[UnknownEdge, ...],
    unexplored_scope: str,
) -> list[AddedCallable]:
    functions = _function_code(after)
    records: list[AddedCallable] = []
    for qualified_name in sorted(added_names):
        function = functions.get(qualified_name)
        if function is None:
            continue
        index = next(
            (candidate for candidate in after.values() if qualified_name in candidate.functions),
            None,
        )
        if index is None:
            continue
        post_exceptions, post_exception_claims = _exception_facts(after, qualified_name)
        reached_from: list[dict[str, Any]] = []
        call_edges = _post_call_edges(after)
        for caller in sorted(modified_callers):
            path, path_calls = _shortest_call_path(after, caller, qualified_name, call_edges)
            if path is None or not path_calls:
                continue
            first_call = path_calls[0]
            path_edges = [
                {
                    "caller_qualified_name": path[position],
                    "callee_qualified_name": path[position + 1],
                    "site": {"file": raw.file_path, "line": raw.line_number},
                    "provenance": _provenance(
                        "post_call_graph_edge",
                        "resolved",
                        raw.file_path,
                        raw.line_number,
                        raw.node_source,
                    ),
                }
                for position, raw in enumerate(path_calls)
            ]
            reached_from.append(
                {
                    "caller_qualified_name": caller,
                    "caller_module": _callable_module(after, caller),
                    "kind": "direct" if len(path) == 2 else "transitive",
                    "path": list(path),
                    "path_edges": path_edges,
                    "site": {"file": first_call.file_path, "line": first_call.line_number},
                    "provenance": _provenance(
                        "added_caller_reachability",
                        "resolved",
                        first_call.file_path,
                        first_call.line_number,
                        "\n".join(raw.node_source for raw in path_calls),
                    ),
                }
            )
        records.append(
            AddedCallable(
                qualified_name=qualified_name,
                module=index.module_name,
                file_path=function.file_path,
                post_signature=function.signature,
                provenance=_provenance(
                    "added_callable_detection",
                    "resolved",
                    function.file_path,
                    function.line_number,
                    function.source,
                ),
                post_call_sites=tuple(
                    site for site in post_call_sites
                    if site.callee_qualified_name == qualified_name
                ),
                reached_from=tuple(reached_from),
                entry_guards=function.entry_guards,
                post_exceptions=post_exceptions,
                post_exception_claims=post_exception_claims,
                unknown_edges=tuple(
                    edge for edge in unknown_edges
                    if edge.target_qualified_name == qualified_name
                ),
                unexplored_scope=unexplored_scope,
            )
        )
    return records


def _module_level_bindings(source: str) -> dict[str, int]:
    """Names bound at MODULE level by anything other than a def/class (assignment, annotated assignment, import,
    for/with targets, including inside module-level if/try blocks) -> first binding line. Pure ast; {} on a parse error."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {}
    out: dict[str, int] = {}

    def names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [n for e in node.elts for n in names(e)]
        if isinstance(node, ast.Starred):
            return names(node.value)
        return []

    def walk(stmts: list[ast.stmt]) -> None:
        for st in stmts:
            found: list[str] = []
            if isinstance(st, ast.Assign):
                found = [n for t in st.targets for n in names(t)]
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and getattr(st, "value", None) is not None:
                found = names(st.target)
            elif isinstance(st, ast.Import):
                found = [a.asname or a.name.split(".")[0] for a in st.names]
            elif isinstance(st, ast.ImportFrom):
                found = [a.asname or a.name for a in st.names if a.name != "*"]
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                found = names(st.target)
                walk(st.body); walk(st.orelse)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                found = [n for it in st.items if it.optional_vars is not None for n in names(it.optional_vars)]
                walk(st.body)
            elif isinstance(st, ast.If):
                walk(st.body); walk(st.orelse)
            elif isinstance(st, ast.Try):
                walk(st.body); walk(st.orelse); walk(st.finalbody)
                for h in st.handlers:
                    walk(h.body)
            for n in found:
                out.setdefault(n, st.lineno)

    walk(tree.body)
    return out


def _rebound_callables(
    before: dict[str, _ModuleIndex], after: dict[str, _ModuleIndex], names: set[str]
) -> dict[str, tuple[str, int]]:
    """Of the removed top-level definitions, those whose module still binds the SAME name at module level in the post
    tree (alias/assignment/import rebinding): qualified name -> (post file, binding line). Such a callable is not
    deleted: it is REBOUND to something the static account does not model."""
    old = _function_code(before)
    post_by_module = {index.module_name: index for index in after.values()}
    out: dict[str, tuple[str, int]] = {}
    for q in names:
        fn = old.get(q)
        if fn is None:
            continue
        module = next((i.module_name for i in before.values() if q in i.functions), None)
        if module is None or not q.startswith(module + "."):
            continue
        local = q[len(module) + 1:]
        if "." in local:  # methods/nested: not a module-level name
            continue
        post = post_by_module.get(module)
        if post is None:
            continue
        line = _module_level_bindings(post.source).get(local)
        if line is not None:
            out[q] = (post.file_path, line)
    return out


def _deleted_callable_records(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
    syntax_identities: dict[str, dict[str, Any]],
) -> list[DeletedCallable]:
    """Record deleted definitions and any statically resolved post-tree references.

    A lack of repository references is not evidence that a deleted callable is
    safe: runtime imports, external callers, and dynamic dispatch remain open.
    Those boundaries stay explicit in each record.
    """
    old_functions = _function_code(before)
    new_functions = _function_code(after)
    changed_path_set = set(changed_paths)
    deleted_names = {
        name
        for name in old_functions.keys() - new_functions.keys()
        if old_functions[name].file_path in changed_path_set
    }
    # a definition replaced by a module-level rebinding of the same name is REBOUND, not deleted (its callers still
    # resolve at run time): it is accounted as an unresolved rebinding in _build_account, never as a deletion
    deleted_names -= set(_rebound_callables(before, after, deleted_names))
    if not deleted_names:
        return []

    # Resolve candidate-tree call expressions against the deleted symbols. The
    # resolver follows imports even though the target definition no longer
    # exists, which exposes stale callers as witness material.
    sites_by_target: dict[str, list[ImpactedCallSite]] = {
        name: [] for name in deleted_names
    }
    for index in after.values():
        for raw in index.calls:
            target, is_method = _resolve_deleted_post_call(
                index, raw, after, deleted_names
            )
            if target is None:
                continue
            site = replace(
                _argument_shape(raw, is_method),
                callee_qualified_name=target,
                side="post",
            )
            sites_by_target.setdefault(target, []).append(site)

    records: list[DeletedCallable] = []
    for qualified_name in sorted(deleted_names):
        function = old_functions[qualified_name]
        identity = syntax_identities.get(qualified_name, {})
        pre_node = identity.get("pre") or {}
        node_id = pre_node.get("node_id") or (
            f"{function.file_path}::{qualified_name.removeprefix(_module_name(function.file_path) + '.')}"
        )
        records.append(
            DeletedCallable(
                qualified_name=qualified_name,
                module=_module_name(function.file_path),
                file_path=function.file_path,
                line_number=function.line_number,
                pre_signature=function.signature,
                post_call_sites=tuple(
                    sorted(
                        sites_by_target.get(qualified_name, ()),
                        key=lambda item: (item.file_path, item.line_number),
                    )
                ),
                provenance=_provenance(
                    "deleted_callable_detection",
                    "resolved",
                    function.file_path,
                    function.line_number,
                    function.source,
                ),
                node_id=node_id,
                side="pre",
                unexplored_scope=(
                    "External callers, runtime imports, dynamic dispatch/reflection, generated code, "
                    "and monkey-patching may still reference this deleted callable; an empty "
                    "repository call-site list does not establish safety."
                ),
            )
        )
    return records


def _resolve_deleted_post_call(
    index: _ModuleIndex,
    raw: _RawCall,
    indexes: dict[str, _ModuleIndex],
    deleted_names: set[str],
) -> tuple[str | None, bool]:
    """Resolve a candidate-tree reference to a deleted symbol.

    The regular resolver handles imports and attributes, but a bare local call
    stops resolving once its definition is removed. Preserve that statically
    obvious module-level edge against the known deleted-name inventory.
    """
    target, is_method = _resolve_call(index, raw, indexes)
    if target in deleted_names:
        return target, is_method
    if target is None and "." not in raw.function_name:
        local_target = f"{index.module_name}.{raw.function_name}"
        if local_target in deleted_names:
            return local_target, False
    return None, is_method


def _modified_constant_records(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Account for changed module-level constant bindings and their reader slice."""
    old_constants = _module_constant_bindings(before, set(changed_paths))
    new_constants = _module_constant_bindings(after, set(changed_paths))
    changed_constants: list[tuple[str, dict[str, Any] | None, dict[str, Any] | None]] = []
    for qualified_name in sorted(old_constants.keys() | new_constants.keys()):
        old = old_constants.get(qualified_name)
        new = new_constants.get(qualified_name)
        if old is not None and new is not None:
            old_fingerprint = _account_ast_dump(old["statement"])
            new_fingerprint = _account_ast_dump(new["statement"])
            if old_fingerprint == new_fingerprint:
                continue
        changed_constants.append((qualified_name, old, new))

    changed_names = {qualified_name for qualified_name, _, _ in changed_constants}
    pre_readers = _constant_reader_records_many(before, changed_names, "pre")
    post_readers = _constant_reader_records_many(after, changed_names, "post")
    records: list[dict[str, Any]] = []
    for qualified_name, old, new in changed_constants:
        old_index = old["index"] if old else None
        new_index = new["index"] if new else None
        exemplar = new or old
        assert exemplar is not None
        module = exemplar["module"]
        side = "both" if old is not None and new is not None else "post" if new else "pre"
        readers = [*pre_readers.get(qualified_name, ()), *post_readers.get(qualified_name, ())]
        source_index = new_index or old_index
        assert source_index is not None
        source_entry = new or old
        assert source_entry is not None
        assignment_source = source_entry["statement_source"]
        provenance = _provenance(
            "module_constant_diff",
            "resolved",
            source_index.file_path,
            source_entry["line_number"],
            assignment_source,
        )
        alias_targets = {
            key: entry["alias_target"]
            for key, entry in (("pre", old), ("post", new))
            if entry is not None and entry.get("alias_target") is not None
        }
        if alias_targets:
            provenance["alias_targets"] = alias_targets
        unresolved_parts = [
            "Repository reader closure is open: external imports, runtime mutation, "
            "reflection, generated code, and dynamically selected readers are not enumerated."
        ]
        if old is not None and not old["value_resolved"]:
            unresolved_parts.append("Pre-change value is computed; only its source and hash are recorded.")
        if new is not None and not new["value_resolved"]:
            unresolved_parts.append("Post-change value is computed; only its source and hash are recorded.")
        if old is not None and old["annotation_only"]:
            unresolved_parts.append("Pre-change binding is annotation-only and has no initializer.")
        if new is not None and new["annotation_only"]:
            unresolved_parts.append("Post-change binding is annotation-only and has no initializer.")
        records.append(
            {
                "qualified_name": qualified_name,
                "module": module,
                "file_path": source_index.file_path,
                "pre_line_number": old["line_number"] if old else None,
                "post_line_number": new["line_number"] if new else None,
                "pre_value_source": old["value_source"] if old else None,
                "post_value_source": new["value_source"] if new else None,
                "pre_value_sha256": old["value_sha256"] if old else None,
                "post_value_sha256": new["value_sha256"] if new else None,
                "pre_value_resolved": old["value_resolved"] if old else False,
                "post_value_resolved": new["value_resolved"] if new else False,
                "pre_alias_target": old.get("alias_target") if old else None,
                "post_alias_target": new.get("alias_target") if new else None,
                "pre_literal_value": old["literal_value"] if old and old["value_resolved"] else None,
                "post_literal_value": new["literal_value"] if new and new["value_resolved"] else None,
                "readers": readers,
                "provenance": provenance,
                "node_id": f"{source_index.file_path}::{qualified_name.rsplit('.', 1)[-1]}",
                "side": side,
                "unexplored_scope": " ".join(unresolved_parts),
            }
        )
    return records


def _module_import_entries(index: _ModuleIndex | None) -> list[dict[str, Any]]:
    if index is None:
        return []
    try:
        tree = ast.parse(index.source)
    except SyntaxError:
        return []
    entries: list[dict[str, Any]] = []
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        # Imports inside a module-level conditional/try are still module-scope bindings.
        stack = [statement]
        while stack:
            node = stack.pop()
            if node is not statement and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(node, ast.Import):
                module_name = None
                aliases = node.names
            elif isinstance(node, ast.ImportFrom):
                module_name = ("." * node.level) + (node.module or "")
                aliases = node.names
            else:
                aliases = ()
            if aliases:
                source = _ast_source_segment(index.source, node) or ast.dump(node, include_attributes=False)
                for alias in aliases:
                    entries.append({
                        "identity": (
                            type(node).__name__, module_name, alias.name, alias.asname
                        ),
                        "module": module_name,
                        "name": alias.name,
                        "asname": alias.asname,
                        "file_path": index.file_path,
                        "line_number": int(getattr(node, "lineno", 1)),
                        "source": source,
                    })
            stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return entries


def _plain_definition_has_no_import_time_code(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    args = node.args
    return (
        not node.decorator_list
        and not args.defaults
        and all(default is None for default in args.kw_defaults)
        and all(
            argument.annotation is None
            for argument in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        )
        and (args.vararg is None or args.vararg.annotation is None)
        and (args.kwarg is None or args.kwarg.annotation is None)
        and node.returns is None
        and not getattr(node, "type_params", ())
    )


def _module_only_imports(index: _ModuleIndex | None) -> bool:
    """Require no module-import-time work beyond imports and plain definitions.

    Plain functions have no decorators, defaults, annotations, or type
    parameters to evaluate. Classes are admitted only with the implicit object
    base and plain methods. Assignments, conditionals, calls, and dynamic class
    construction are rejected conservatively.
    """
    if index is None:
        return False
    try:
        body = ast.parse(index.source).body
    except SyntaxError:
        return False
    for position, statement in enumerate(body):
        if (
            position == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not _plain_definition_has_no_import_time_code(statement):
                return False
            continue
        if isinstance(statement, ast.ClassDef):
            if statement.decorator_list or statement.bases or statement.keywords\
                    or getattr(statement, "type_params", ()):
                return False
            for member in statement.body:
                if (
                    isinstance(member, ast.Expr)
                    and isinstance(member.value, ast.Constant)
                    and isinstance(member.value.value, str)
                    and member is statement.body[0]
                ):
                    continue
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))\
                        or not _plain_definition_has_no_import_time_code(member):
                    return False
            continue
        return False
    return True


def _relative_import_module(index: _ModuleIndex, module: str) -> str | None:
    if not module.startswith("."):
        return module
    level = len(module) - len(module.lstrip("."))
    suffix = module[level:]
    package = index.module_name if PurePosixPath(index.file_path).name == "__init__.py"\
        else index.module_name.rpartition(".")[0]
    parts = package.split(".") if package else []
    if level > len(parts):
        return None
    keep = len(parts) - level + 1
    if keep < 0:
        return None
    prefix = parts[:keep]
    if suffix:
        prefix.extend(suffix.split("."))
    return ".".join(prefix) or None


def _module_declares_name(module_name: str, name: str, indexes: dict[str, _ModuleIndex]) -> bool:
    module_index = next((item for item in indexes.values() if item.module_name == module_name), None)
    if module_index is not None:
        source = module_index.source
    else:
        parts = module_name.split(".")
        search_path = None
        spec = None
        for position in range(len(parts)):
            qualified = ".".join(parts[:position + 1])
            try:
                spec = PathFinder.find_spec(qualified, search_path)
            except (ImportError, ValueError, KeyError):
                return False
            if spec is None:
                return False
            if position < len(parts) - 1:
                search_path = spec.submodule_search_locations
                if search_path is None:
                    return False
        if spec is None or not spec.origin or not spec.origin.endswith(".py"):
            return False
        try:
            source = Path(spec.origin).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return False
    try:
        body = ast.parse(source).body
    except SyntaxError:
        return False
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name == name:
                return True
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound == name:
                    return True
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return True
    return False


def _import_entry_resolves(
    index: _ModuleIndex | None, entry: dict[str, Any], indexes: dict[str, _ModuleIndex]
) -> bool:
    if index is None:
        return False
    node_type, _module, imported_name, _asname = entry["identity"]
    if node_type == "Import":
        return _is_module_target(imported_name, indexes)
    base_module = _relative_import_module(index, entry["module"] or "")
    if not base_module or not _is_module_target(base_module, indexes):
        return False
    if imported_name == "*":
        return False
    return (
        _is_module_target(f"{base_module}.{imported_name}", indexes)
        or _module_declares_name(base_module, imported_name, indexes)
    )


def _pure_module_import(
    index: _ModuleIndex | None,
    entry: dict[str, Any],
    indexes: dict[str, _ModuleIndex],
) -> bool:
    """A safe import delta is a resolvable import in a module with no other top-level work."""
    return _module_only_imports(index) and _import_entry_resolves(index, entry, indexes)


def _module_level_change_record(
    *, file_path: str, kind: str, side: str, line_number: int, source: str,
    module: str | None = None, name: str | None = None, asname: str | None = None,
    pair_id: str | None = None, resolution: str = "unresolved",
) -> dict[str, Any]:
    original_source = source
    cleaned_source = _clean_record_text(original_source)
    source_truncated = len(cleaned_source) > 4000
    bounded_source = cleaned_source[:4000]
    source_sha256 = hashlib.sha256(original_source.encode("utf-8")).hexdigest()
    provenance = _provenance(
        "module_level_diff", resolution, file_path, line_number, bounded_source
    )
    identity = json.dumps(
        [file_path, kind, side, line_number, source_sha256, module, name, asname, pair_id],
        ensure_ascii=True, separators=(",", ":"),
    )
    node_id = f"{file_path}::module-level::{hashlib.sha256(identity.encode('ascii')).hexdigest()[:24]}"
    return {
        "file_path": file_path,
        "kind": kind,
        "side": side,
        "source": bounded_source,
        "source_sha256": source_sha256,
        "source_truncated": source_truncated,
        "line_number": max(1, line_number),
        "node_id": node_id,
        "provenance": provenance,
        "module": module,
        "name": name,
        "asname": asname,
        "pair_id": pair_id,
    }


def _modified_module_level_records(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
    modified_constants: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Record only AST-different module-scope imports/statements not covered by other account records."""
    records: list[dict[str, Any]] = []
    for file_path in changed_paths:
        if not file_path.endswith(".py"):
            continue
        old_index, new_index = before.get(file_path), after.get(file_path)
        old_imports = _module_import_entries(old_index)
        new_imports = _module_import_entries(new_index)
        old_by_identity: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        new_by_identity: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for entry in old_imports:
            old_by_identity.setdefault(entry["identity"], []).append(entry)
        for entry in new_imports:
            new_by_identity.setdefault(entry["identity"], []).append(entry)
        for identity in sorted(old_by_identity.keys() | new_by_identity.keys(), key=repr):
            olds = old_by_identity.get(identity, [])
            news = new_by_identity.get(identity, [])
            if len(olds) > len(news):
                for entry in olds[len(news):]:
                    pure_import = (
                        _pure_module_import(old_index, entry, before)
                        and _pure_module_import(new_index, entry, after)
                    )
                    records.append(_module_level_change_record(
                        file_path=file_path, kind="import_removed", side="pre",
                        line_number=entry["line_number"], source=entry["source"],
                        module=entry["module"], name=entry["name"], asname=entry["asname"],
                        resolution="resolved" if pure_import else "unresolved",
                    ))
            elif len(news) > len(olds):
                for entry in news[len(olds):]:
                    pure_import = (
                        _pure_module_import(old_index, entry, before)
                        and _pure_module_import(new_index, entry, after)
                    )
                    records.append(_module_level_change_record(
                        file_path=file_path, kind="import_added", side="post",
                        line_number=entry["line_number"], source=entry["source"],
                        module=entry["module"], name=entry["name"], asname=entry["asname"],
                        resolution="resolved" if pure_import else "unresolved",
                    ))

        def module_statements(index: _ModuleIndex | None, side: str) -> list[ast.stmt]:
            if index is None:
                return []
            try:
                tree = ast.parse(index.source)
            except SyntaxError:
                return []
            constant_lines = {
                record[f"{side}_line_number"]
                for record in modified_constants
                if record.get("file_path") == file_path and record.get(f"{side}_line_number") is not None
            }
            return [
                node for node in tree.body
                if not isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and not (isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                         and getattr(node, "lineno", None) in constant_lines)
            ]

        old_statements = module_statements(old_index, "pre")
        new_statements = module_statements(new_index, "post")
        old_keys = [_account_ast_dump(node) for node in old_statements]
        new_keys = [_account_ast_dump(node) for node in new_statements]
        matcher = difflib.SequenceMatcher(a=old_keys, b=new_keys, autojunk=False)
        for opcode, i1, i2, j1, j2 in matcher.get_opcodes():
            if opcode == "equal":
                continue
            old_chunk = old_statements[i1:i2]
            new_chunk = new_statements[j1:j2]
            n_pairs = min(len(old_chunk), len(new_chunk)) if opcode == "replace" else 0
            for offset, node in enumerate(old_chunk):
                pair_id = None
                if offset < n_pairs:
                    pair_material = old_keys[i1 + offset] + chr(0) + new_keys[j1 + offset]
                    pair_id = f"{file_path}::module-level-pair::{hashlib.sha256(pair_material.encode('utf-8')).hexdigest()[:24]}"
                source = _ast_source_segment(old_index.source, node) if old_index else None
                records.append(_module_level_change_record(
                    file_path=file_path, kind="statement", side="pre",
                    line_number=int(getattr(node, "lineno", 1)), source=source or ast.dump(node),
                    pair_id=pair_id,
                ))
            for offset, node in enumerate(new_chunk):
                pair_id = None
                if offset < n_pairs:
                    pair_material = old_keys[i1 + offset] + chr(0) + new_keys[j1 + offset]
                    pair_id = f"{file_path}::module-level-pair::{hashlib.sha256(pair_material.encode('utf-8')).hexdigest()[:24]}"
                source = _ast_source_segment(new_index.source, node) if new_index else None
                records.append(_module_level_change_record(
                    file_path=file_path, kind="statement", side="post",
                    line_number=int(getattr(node, "lineno", 1)), source=source or ast.dump(node),
                    pair_id=pair_id,
                ))
        if old_index is None and new_index is not None:
            try:
                empty_module = not ast.parse(new_index.source).body
            except SyntaxError:
                empty_module = False
            if empty_module:
                records.append(_module_level_change_record(
                    file_path=file_path, kind="statement", side="post", line_number=1,
                    source=new_index.source,
                ))
        elif new_index is None and old_index is not None:
            try:
                empty_module = not ast.parse(old_index.source).body
            except SyntaxError:
                empty_module = False
            if empty_module:
                records.append(_module_level_change_record(
                    file_path=file_path, kind="statement", side="pre", line_number=1,
                    source=old_index.source,
                ))
    return sorted(records, key=lambda item: (item["file_path"], item["line_number"], item["side"], item["node_id"]))


def _module_level_unresolved_records(records: list[dict[str, Any]]) -> list[UnresolvedConstruct]:
    """Block every unmodelled module-level change, linking it to its account evidence node."""
    rows_by_pair: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        if item.get("pair_id"):
            rows_by_pair.setdefault(item["pair_id"], []).append(item)
    out: list[UnresolvedConstruct] = []
    for item in records:
        if item.get("provenance", {}).get("resolution") == "resolved":
            continue
        if item["side"] == "pre" and item.get("pair_id") and any(
            paired["side"] == "post" for paired in rows_by_pair[item["pair_id"]]
        ):
            continue
        unresolved_id = (
            f"{item['file_path']}::unresolved-module-level::"
            f"{hashlib.sha256(item['node_id'].encode('utf-8')).hexdigest()[:24]}"
        )
        out.append(UnresolvedConstruct(
            file_path=item["file_path"],
            line_number=item["line_number"],
            kind="module_level_change",
            source=item["source"],
            scope="module_level",
            provenance=item["provenance"],
            side="post",
            node_id=unresolved_id,
            record_node_id=item["node_id"],
        ))
    return out


def _modified_class_attribute_records(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Account for class-body attribute bindings and their in-repository readers."""
    changed = set(changed_paths)
    old_attributes = _class_attribute_bindings(before, changed)
    new_attributes = _class_attribute_bindings(after, changed)
    records: list[dict[str, Any]] = []
    for qualified_name in sorted(old_attributes.keys() | new_attributes.keys()):
        old = old_attributes.get(qualified_name)
        new = new_attributes.get(qualified_name)
        if old is not None and new is not None:
            old_fingerprint = tuple(
                ast.dump(entry["statement"], include_attributes=False) for entry in old["entries"]
            )
            new_fingerprint = tuple(
                ast.dump(entry["statement"], include_attributes=False) for entry in new["entries"]
            )
            if old_fingerprint == new_fingerprint:
                continue

        exemplar = new or old
        assert exemplar is not None
        class_qualified_name = exemplar["class_qualified_name"]
        name = exemplar["name"]
        side = "both" if old is not None and new is not None else "post" if new else "pre"
        readers = [
            *_class_attribute_reader_records(before, qualified_name, class_qualified_name, name, "pre"),
            *_class_attribute_reader_records(after, qualified_name, class_qualified_name, name, "post"),
        ]
        source_index = new["index"] if new else old["index"]
        source_entry = new or old
        assert source_index is not None and source_entry is not None
        unresolved_parts = [
            "Repository class-attribute reader closure is open: external imports, runtime mutation, "
            "reflection, generated code, and dynamically selected readers are not enumerated."
        ]
        if old is not None and old["conditional"]:
            unresolved_parts.append("Pre-change conditional class attribute assignment; final binding is branch-dependent.")
        if new is not None and new["conditional"]:
            unresolved_parts.append("Post-change conditional class attribute assignment; final binding is branch-dependent.")
        if old is not None and old["mutable"]:
            unresolved_parts.append("Pre-change mutable class attribute; mutation and alias flow are not resolved.")
        if new is not None and new["mutable"]:
            unresolved_parts.append("Post-change mutable class attribute; mutation and alias flow are not resolved.")
        if old is not None and not old["value_resolved"] and not old["conditional"] and not old["mutable"]:
            unresolved_parts.append("Pre-change value is computed; only its source and hash are recorded.")
        if new is not None and not new["value_resolved"] and not new["conditional"] and not new["mutable"]:
            unresolved_parts.append("Post-change value is computed; only its source and hash are recorded.")
        if source_entry["conditional"]:
            assignment_source = "\n".join(item["statement_source"] for item in source_entry["entries"])
        else:
            assignment_source = source_entry["statement_source"]
        records.append(
            {
                "qualified_name": qualified_name,
                "class_qualified_name": class_qualified_name,
                "name": name,
                "module": exemplar["module"],
                "file_path": source_index.file_path,
                "pre_line_number": old["line_number"] if old else None,
                "post_line_number": new["line_number"] if new else None,
                "pre_value_source": old["value_source"] if old else None,
                "post_value_source": new["value_source"] if new else None,
                "pre_value_sha256": old["value_sha256"] if old else None,
                "post_value_sha256": new["value_sha256"] if new else None,
                "pre_value_resolved": old["value_resolved"] if old else False,
                "post_value_resolved": new["value_resolved"] if new else False,
                "pre_literal_value": old["literal_value"] if old and old["value_resolved"] else None,
                "post_literal_value": new["literal_value"] if new and new["value_resolved"] else None,
                "readers": readers,
                "provenance": _provenance(
                    "class_attribute_diff",
                    "resolved",
                    source_index.file_path,
                    source_entry["line_number"],
                    assignment_source,
                ),
                "node_id": f"{source_index.file_path}::{qualified_name}",
                "side": side,
                "unexplored_scope": " ".join(unresolved_parts),
            }
        )
    return records


def _class_attribute_bindings(
    indexes: dict[str, _ModuleIndex], changed_paths: set[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index in indexes.values():
        if index.file_path not in changed_paths:
            continue
        for class_qualified_name, class_node in index.classes_ast.items():
            candidates: dict[str, list[dict[str, Any]]] = {}

            def add_statement(statement: ast.stmt, conditional: bool) -> None:
                if isinstance(statement, ast.Assign):
                    targets, value = statement.targets, statement.value
                elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
                    targets, value = [statement.target], statement.value
                else:
                    return
                names = sorted(
                    {
                        node.id
                        for target in targets
                        for node in ast.walk(target)
                        if isinstance(node, ast.Name)
                        and isinstance(node.ctx, ast.Store)
                        and node.id.strip("_").isupper()
                    }
                )
                if not names:
                    return
                statement_source = _ast_source_segment(index.source, statement) or ast.unparse(statement)
                value_source = (
                    _ast_source_segment(index.source, value) or ast.unparse(value)
                    if value is not None else ""
                )
                literal_value, value_resolved = _json_literal(value)
                mutable = _is_mutable_class_value(value)
                if isinstance(statement, ast.AugAssign) or conditional or mutable or len(names) != 1:
                    value_resolved = False
                    literal_value = None
                if isinstance(statement, ast.AugAssign):
                    value_source = statement_source
                for name in names:
                    qualified_name = f"{class_qualified_name}.{name}"
                    candidates.setdefault(qualified_name, []).append(
                        {
                            "index": index,
                            "module": index.module_name,
                            "class_qualified_name": class_qualified_name,
                            "name": name,
                            "statement": statement,
                            "statement_source": statement_source,
                            "line_number": statement.lineno,
                            "value_source": value_source,
                            "value_sha256": hashlib.sha256(value_source.encode("utf-8")).hexdigest(),
                            "value_resolved": value_resolved,
                            "literal_value": literal_value,
                            "annotation_only": value is None,
                            "conditional": conditional,
                            "mutable": mutable,
                        }
                    )

            def visit_class_body(statements: list[ast.stmt], conditional: bool = False) -> None:
                for statement in statements:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        add_statement(statement, conditional)
                        continue
                    if isinstance(statement, ast.If):
                        visit_class_body(statement.body, True)
                        visit_class_body(statement.orelse, True)
                    elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                        visit_class_body(statement.body, True)
                        if hasattr(statement, "orelse"):
                            visit_class_body(statement.orelse, True)
                    elif isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                        visit_class_body(statement.body, True)
                        visit_class_body(statement.orelse, True)
                        visit_class_body(statement.finalbody, True)
                        for handler in statement.handlers:
                            visit_class_body(handler.body, True)
                    elif isinstance(statement, ast.Match):
                        for case in statement.cases:
                            visit_class_body(case.body, True)

            visit_class_body(class_node.body)
            for qualified_name, entries in candidates.items():
                conditional_entries = [entry for entry in entries if entry["conditional"]]
                if conditional_entries:
                    selected = entries
                    value_source = "\n".join(entry["statement_source"] for entry in selected)
                    value_sha256 = hashlib.sha256(value_source.encode("utf-8")).hexdigest()
                    value_resolved = False
                    literal_value = None
                    line_number = min(entry["line_number"] for entry in selected)
                    mutable = any(entry["mutable"] for entry in selected)
                else:
                    selected = [entries[-1]]
                    value_source = selected[0]["value_source"]
                    value_sha256 = selected[0]["value_sha256"]
                    value_resolved = selected[0]["value_resolved"]
                    literal_value = selected[0]["literal_value"]
                    line_number = selected[0]["line_number"]
                    mutable = selected[0]["mutable"]
                exemplar = selected[-1]
                result[qualified_name] = {
                    **exemplar,
                    "entries": selected,
                    "value_source": value_source,
                    "value_sha256": value_sha256,
                    "value_resolved": value_resolved,
                    "literal_value": literal_value,
                    "line_number": line_number,
                    "conditional": bool(conditional_entries),
                    "mutable": mutable,
                }
    return result


def _is_mutable_class_value(node: ast.AST | None) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"}
    )


def _module_constant_bindings(
    indexes: dict[str, _ModuleIndex], changed_paths: set[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    module_sources = (
        indexes.module_sources_dict()
        if isinstance(indexes, _ModuleIndexes)
        else {item.module_name: item.source for item in indexes.values()}
    )
    for index in indexes.values():
        if index.file_path not in changed_paths:
            continue
        try:
            module_ast = ast.parse(index.source, filename=index.file_path)
        except SyntaxError:
            continue
        candidates: dict[str, list[dict[str, Any]]] = {}
        for statement in module_ast.body:
            value: ast.AST | None
            targets: list[ast.AST]
            if isinstance(statement, ast.Assign):
                targets = statement.targets
                value = statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
                value = statement.value
            elif isinstance(statement, ast.AugAssign):
                targets = [statement.target]
                value = statement.value
            else:
                continue
            names = [
                node.id
                for target in targets
                for node in ast.walk(target)
                if isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Store)
                and (
                    node.id.strip("_").isupper()
                    or (
                        isinstance(target, ast.Name)
                        and isinstance(value, (ast.Name, ast.Attribute))
                        and _resolve_builtin_type_alias(index.module_name, node.id, module_sources) is not None
                    )
                )
            ]
            if not names:
                continue
            statement_source = _ast_source_segment(index.source, statement) or ast.unparse(statement)
            value_source = (
                _ast_source_segment(index.source, value) or ast.unparse(value)
                if value is not None else ""
            )
            literal_value, value_resolved = _json_literal(value)
            alias_targets = {
                name: resolved[0]
                for name in names
                if isinstance(value, (ast.Name, ast.Attribute))
                and (resolved := _resolve_builtin_type_alias(index.module_name, name, module_sources)) is not None
            }
            if alias_targets and len(names) == 1:
                alias_target = alias_targets[names[0]]
                literal_value, value_resolved = alias_target, True
            else:
                alias_target = None
            if isinstance(statement, ast.AugAssign) or len(names) != 1:
                value_resolved = False
                literal_value = None
            if isinstance(statement, ast.AugAssign):
                value_source = statement_source
            for name in sorted(set(names)):
                candidates.setdefault(f"{index.module_name}.{name}", []).append(
                    {
                        "index": index,
                        "module": index.module_name,
                        "statement": statement,
                        "statement_source": statement_source,
                        "line_number": statement.lineno,
                        "value_source": value_source,
                        "value_sha256": hashlib.sha256(value_source.encode("utf-8")).hexdigest(),
                        "value_resolved": value_resolved,
                        "literal_value": literal_value,
                        "annotation_only": value is None,
                        "alias_target": alias_target,
                    }
                )
        # Module statements execute in source order, so the final direct
        # assignment is the binding at module completion. Conditional and
        # dynamic rebinding remains part of the account's unexplored scope.
        for qualified_name, entries in candidates.items():
            result[qualified_name] = entries[-1]
    return result


def _json_literal(node: ast.AST | None) -> tuple[Any, bool]:
    if node is None:
        return None, False
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None, False

    def convert(item: Any) -> tuple[Any, bool]:
        if item is None or isinstance(item, (bool, int, float, str)):
            return item, True
        if isinstance(item, (list, tuple)):
            converted = [convert(child) for child in item]
            return [child for child, ok in converted], all(ok for _, ok in converted)
        if isinstance(item, dict):
            converted = [(convert(key), convert(value)) for key, value in item.items()]
            if not all(key_ok and value_ok and isinstance(key, str) for (key, key_ok), (value, value_ok) in converted):
                return None, False
            return {key: value for (key, _), (value, _) in converted}, True
        return None, False

    return convert(value)


def _constant_reader_records(
    indexes: dict[str, _ModuleIndex], qualified_name: str, side: str
) -> list[dict[str, Any]]:
    """Compatibility wrapper for one module constant's reader slice."""
    return _constant_reader_records_many(indexes, {qualified_name}, side).get(qualified_name, [])


def _imported_name_provenance(
    index: _ModuleIndex,
    local_name: str,
    target: str,
    indexes: dict[str, _ModuleIndex],
) -> dict[str, Any] | None:
    """Return the unique module-scope import that binds a reader name to target."""
    try:
        statements = ast.parse(index.source, filename=index.file_path).body
    except SyntaxError:
        return None
    candidates: list[tuple[ast.stmt, str]] = []
    for statement in statements:
        if isinstance(statement, ast.ImportFrom):
            base = _relative_import_module(
                index,
                ("." * statement.level) + (statement.module or ""),
            )
            if not base:
                continue
            for alias in statement.names:
                local = alias.asname or alias.name
                imported = _resolve_imported_target(f"{base}.{alias.name}", indexes)
                if local == local_name and imported == target:
                    candidates.append((statement, imported))
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                imported = alias.name if alias.asname else local
                imported = _resolve_imported_target(imported, indexes)
                if local == local_name and imported == target:
                    candidates.append((statement, imported))
    if len(candidates) != 1:
        return None
    statement, imported = candidates[0]
    source = _ast_source_segment(index.source, statement) or ast.unparse(statement)
    return {
        "analysis_pass": "imported_module_alias_reader",
        "resolution": "resolved",
        "import_file": index.file_path,
        "import_line": int(getattr(statement, "lineno", 1)),
        "local_name": local_name,
        "target": imported,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _constant_reader_records_many(
    indexes: dict[str, _ModuleIndex], qualified_names: set[str], side: str
) -> dict[str, list[dict[str, Any]]]:
    """Find readers for many constants with one local-binding scan per callable."""
    if not qualified_names:
        return {}

    direct_by_constant: dict[
        str, dict[str, list[tuple[_ModuleIndex, ast.AST, str, dict[str, Any] | None]]]
    ] = {}
    for index in indexes.values():
        for callable_name, function in index.functions_ast.items():
            local_names = _function_local_names(function)
            read_nodes: dict[str, list[tuple[ast.AST, str, dict[str, Any] | None]]] = {}

            class ReadReferences(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    if node is not function:
                        return
                    self.in_definition_header = True
                    header = [
                        *node.decorator_list,
                        *node.args.defaults,
                        *(value for value in node.args.kw_defaults if value is not None),
                        *([node.returns] if node.returns else []),
                    ]
                    for child in header:
                        self.visit(child)
                    self.in_definition_header = False
                    for child in node.body:
                        self.visit(child)

                def __init__(self) -> None:
                    self.in_definition_header = False

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

                def visit_Name(self, node: ast.Name) -> None:
                    if (
                        not isinstance(node.ctx, ast.Load)
                        or (node.id in local_names and not self.in_definition_header)
                    ):
                        return
                    target = (
                        _resolve_imported_target(index.imports[node.id], indexes)
                        if node.id in index.imports
                        else f"{index.module_name}.{node.id}"
                    )
                    if target in qualified_names:
                        binding = (
                            _imported_name_provenance(index, node.id, target, indexes)
                            if node.id in index.imports else None
                        )
                        read_nodes.setdefault(target, []).append(
                            (node, _ast_source_segment(index.source, node) or node.id, binding)
                        )

                def visit_Attribute(self, node: ast.Attribute) -> None:
                    target = _resolve_module_attribute(index, node, indexes)
                    if target in qualified_names:
                        read_nodes.setdefault(target, []).append(
                            (node, _ast_source_segment(index.source, node) or ast.unparse(node), None)
                        )
                    self.generic_visit(node)

            ReadReferences().visit(function)
            for qualified_name, nodes in read_nodes.items():
                direct_by_constant.setdefault(qualified_name, {})[callable_name] = [
                    (index, node, source, binding)
                    for node, source, binding in sorted(
                        nodes, key=lambda item: (item[0].lineno, item[0].col_offset)
                    )
                ]

    if not direct_by_constant:
        return {}

    edges = _post_call_edges(indexes)
    results: dict[str, list[dict[str, Any]]] = {}
    for qualified_name, direct in direct_by_constant.items():
        direct_names = set(direct)
        records: list[dict[str, Any]] = []
        for reader in sorted(_reachable_callers(indexes, direct_names)):
            choices: list[tuple[tuple[Any, ...], tuple[str, ...], tuple[_RawCall, ...], str]] = []
            for direct_reader in sorted(direct_names):
                path, calls = _shortest_call_path(indexes, reader, direct_reader, edges)
                if path is not None and calls is not None:
                    choices.append(((len(path), path), path, calls, direct_reader))
            if not choices:
                continue
            _, path, calls, direct_reader = min(choices, key=lambda item: item[0])
            is_direct = reader == direct_reader
            binding_provenance = None
            if is_direct:
                index, node, source, binding_provenance = direct[direct_reader][0]
                line_number = node.lineno
                file_path = index.file_path
                claim_source = source
            else:
                first_call = calls[0]
                line_number = first_call.line_number
                file_path = first_call.file_path
                claim_source = "\n".join(call.node_source for call in calls)
            reader_module = _callable_module(indexes, reader)
            reader_index = next(item for item in indexes.values() if reader in item.functions_ast)
            reader_function = reader_index.functions_ast[reader]
            reader_identity = _python_callable_identity(reader_index, reader_function)
            record = {
                    "qualified_name": reader_identity,
                    "module": reader_module,
                    "file_path": file_path,
                    "line_number": line_number,
                    "kind": "direct" if is_direct else "transitive",
                    "path": [*path, qualified_name],
                    "provenance": _provenance(
                        "module_constant_reader_slice",
                        "resolved",
                        file_path,
                        line_number,
                        claim_source,
                    ),
                    "node_id": f"{reader_index.file_path}::{reader_identity}::line:{reader_function.lineno}",
                    "side": side,
                }
            if binding_provenance is not None:
                record["binding_provenance"] = binding_provenance
            records.append(record)
        results[qualified_name] = sorted(
            records, key=lambda item: (item["side"], item["qualified_name"])
        )
    return results


def _python_callable_identity(
    index: _ModuleIndex, target: ast.FunctionDef | ast.AsyncFunctionDef
) -> str:
    """Return Python's qualname spelling, including ``.<locals>.`` for closures."""
    found: str | None = None

    def walk(node: ast.AST, classes: tuple[str, ...], functions: tuple[str, ...]) -> None:
        nonlocal found
        if found is not None:
            return
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                walk(child, (*classes, node.name), functions)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node is target or (
                node.name == target.name and node.lineno == target.lineno
            ):
                parts = [index.module_name, *classes]
                if functions:
                    parts.append(functions[0])
                    for nested in functions[1:]:
                        parts.extend(("<locals>", nested))
                    parts.extend(("<locals>", node.name))
                else:
                    parts.append(node.name)
                found = ".".join(parts)
                return
            for child in node.body:
                walk(child, classes, (*functions, node.name))
            return
        for child in ast.iter_child_nodes(node):
            walk(child, classes, functions)

    walk(ast.parse(index.source), (), ())
    if found is not None:
        return found
    return next(name for name, node in index.functions_ast.items() if node is target)


def _class_attribute_reader_records(
    indexes: dict[str, _ModuleIndex],
    qualified_name: str,
    declaring_class: str,
    attribute_name: str,
    side: str,
) -> list[dict[str, Any]]:
    """Find direct and transitive readers, resolving static class MRO references."""
    class_nodes = {
        class_name: (index, node)
        for index in indexes.values()
        for class_name, node in index.classes_ast.items()
    }
    class_names = set(class_nodes)
    bindings = _class_attribute_bindings(
        indexes, {index.file_path for index in indexes.values()}
    )
    bases: dict[str, list[str | None]] = {}
    for class_name, (index, node) in class_nodes.items():
        bases[class_name] = [
            _resolve_class_expression(index, base, indexes, class_names)
            for base in node.bases
        ]

    mro_cache: dict[str, tuple[list[str], bool]] = {}

    def class_mro(class_name: str, active: frozenset[str] = frozenset()) -> tuple[list[str], bool]:
        cached = mro_cache.get(class_name)
        if cached is not None:
            return cached
        if class_name in active or class_name not in class_nodes:
            return [class_name], False
        resolved_bases = bases.get(class_name, [])
        known_bases = [name for name in resolved_bases if name in class_nodes]
        complete = all(name is not None for name in resolved_bases)
        base_mros: list[list[str]] = []
        for base in known_bases:
            base_mro, base_complete = class_mro(base, active | {class_name})
            base_mros.append(base_mro)
            complete = complete and base_complete
        sequences = [list(items) for items in base_mros]
        if known_bases:
            sequences.append(list(known_bases))
        result = [class_name]
        while any(sequences):
            sequences = [sequence for sequence in sequences if sequence]
            candidate = next(
                (
                    sequence[0]
                    for sequence in sequences
                    if all(sequence[0] not in other[1:] for other in sequences)
                ),
                None,
            )
            if candidate is None:
                complete = False
                result.extend(item for sequence in sequences for item in sequence if item not in result)
                break
            result.append(candidate)
            for sequence in sequences:
                if sequence and sequence[0] == candidate:
                    sequence.pop(0)
        mro_cache[class_name] = (result, complete)
        return result, complete

    def owns_attribute(class_name: str) -> bool:
        return f"{class_name}.{attribute_name}" in bindings

    def attribute_owner(class_name: str) -> str | None:
        mro, complete = class_mro(class_name)
        for position, candidate in enumerate(mro):
            if owns_attribute(candidate):
                if position == 0 or complete:
                    return candidate
                return None
        return None

    def attribute_owner_after(class_name: str, lexical_class: str) -> str | None:
        mro, complete = class_mro(class_name)
        if not complete or lexical_class not in mro:
            return None
        for candidate in mro[mro.index(lexical_class) + 1 :]:
            if owns_attribute(candidate):
                return candidate
        return None

    def resolve_class_expression(index: _ModuleIndex, node: ast.expr) -> str | None:
        return _resolve_class_expression(index, node, indexes, class_names)

    direct: dict[str, list[tuple[_ModuleIndex, ast.AST, str, str | None]]] = {}
    for index in indexes.values():
        for callable_name, function in index.functions_ast.items():
            lexical_class = _enclosing_class_qualname(index, callable_name)
            read_nodes: list[tuple[ast.AST, str, str | None]] = []

            def add_read(node: ast.AST, receiver_class: str | None) -> None:
                read_nodes.append(
                    (node, _ast_source_segment(index.source, node) or ast.unparse(node), receiver_class)
                )

            class ReadReferences(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.in_definition_header = False

                def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    if node is not function:
                        return
                    self.in_definition_header = True
                    header = [
                        *node.decorator_list,
                        *node.args.defaults,
                        *(value for value in node.args.kw_defaults if value is not None),
                        *([node.returns] if node.returns else []),
                    ]
                    for child in header:
                        self.visit(child)
                    self.in_definition_header = False
                    for child in node.body:
                        self.visit(child)

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

                def visit_Name(self, node: ast.Name) -> None:
                    if (
                        not self.in_definition_header
                        or node.id != attribute_name
                        or lexical_class is None
                        or attribute_owner(lexical_class) != declaring_class
                    ):
                        return
                    add_read(node, lexical_class)

                def visit_Attribute(self, node: ast.Attribute) -> None:
                    if node.attr != attribute_name:
                        self.generic_visit(node)
                        return
                    value = node.value
                    if isinstance(value, ast.Name) and value.id in {"self", "cls"} and lexical_class:
                        receiver_classes = [
                            candidate
                            for candidate in class_nodes
                            if lexical_class in class_mro(candidate)[0]
                            and attribute_owner(candidate) == declaring_class
                        ]
                        for receiver_class in receiver_classes:
                            add_read(node, receiver_class)
                    elif (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id == "super"
                        and not value.args
                        and not value.keywords
                        and lexical_class
                    ):
                        receiver_classes = [
                            candidate
                            for candidate in class_nodes
                            if lexical_class in class_mro(candidate)[0]
                            and attribute_owner_after(candidate, lexical_class) == declaring_class
                        ]
                        for receiver_class in receiver_classes:
                            add_read(node, receiver_class)
                    else:
                        resolved_class = resolve_class_expression(index, value)
                        if (
                            resolved_class is not None
                            and attribute_owner(resolved_class) == declaring_class
                        ):
                            add_read(node, None)
                    self.generic_visit(node)

            ReadReferences().visit(function)
            if read_nodes:
                direct[callable_name] = [
                    (index, node, source, receiver)
                    for node, source, receiver in sorted(
                        set(read_nodes),
                        key=lambda item: (item[0].lineno, item[0].col_offset, item[2] or ""),
                    )
                ]

    if not direct:
        return []
    direct_names = set(direct)
    edges = _post_call_edges(indexes)
    records: list[dict[str, Any]] = []
    for reader in sorted(_reachable_callers(indexes, direct_names)):
        choices: list[
            tuple[tuple[Any, ...], tuple[str, ...], tuple[_RawCall, ...], str, str | None]
        ] = []
        for direct_reader in sorted(direct_names):
            path, calls = _shortest_call_path(indexes, reader, direct_reader, edges)
            if path is None or calls is None:
                continue
            for _, _, _, receiver_class in direct[direct_reader]:
                choices.append(
                    ((len(path), path, receiver_class or ""), path, calls, direct_reader, receiver_class)
                )
        if not choices:
            continue
        _, path, calls, direct_reader, direct_receiver_class = min(
            choices, key=lambda item: item[0]
        )
        is_direct = reader == direct_reader
        if is_direct:
            direct_index, node, source, receiver_class = next(
                item for item in direct[direct_reader] if item[3] == direct_receiver_class
            )
            line_number = node.lineno
            file_path = direct_index.file_path
            claim_source = source
        else:
            first_call = calls[0]
            line_number = first_call.line_number
            file_path = first_call.file_path
            claim_source = "\n".join(call.node_source for call in calls)
            reader_index = next(item for item in indexes.values() if reader in item.functions_ast)
            receiver_class = _enclosing_class_qualname(reader_index, reader)
        reader_module = _callable_module(indexes, reader)
        reader_index = next(item for item in indexes.values() if reader in item.functions_ast)
        relative_name = reader.removeprefix(f"{reader_module}.")
        records.append(
            {
                "qualified_name": reader,
                "module": reader_module,
                "file_path": file_path,
                "line_number": line_number,
                "kind": "direct" if is_direct else "transitive",
                "path": [*path, qualified_name],
                "receiver_class_qualname": receiver_class,
                "provenance": _provenance(
                    "class_attribute_reader_slice",
                    "resolved",
                    file_path,
                    line_number,
                    claim_source,
                ),
                "node_id": f"{reader_index.file_path}::{relative_name}",
                "side": side,
            }
        )
    return sorted(
        records,
        key=lambda item: (
            item["side"],
            item["qualified_name"],
            item["receiver_class_qualname"] or "",
        ),
    )


def _resolve_class_expression(
    index: _ModuleIndex,
    node: ast.expr,
    indexes: dict[str, _ModuleIndex],
    class_names: set[str],
) -> str | None:
    if isinstance(node, ast.Name):
        target = index.imports.get(node.id, f"{index.module_name}.{node.id}")
        return _follow_class_alias(target, indexes, class_names)
    if isinstance(node, ast.Attribute):
        target = _resolve_module_attribute(index, node, indexes)
        if target is None:
            target = f"{index.module_name}.{ast.unparse(node)}"
        return _follow_class_alias(target, indexes, class_names)
    return None


def _function_local_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = function.args
    local_names = {
        argument.arg
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *([arguments.vararg] if arguments.vararg else []),
            *([arguments.kwarg] if arguments.kwarg else []),
        ]
    }

    class LocalBindings(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if node is function:
                for child in node.body:
                    self.visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                local_names.add(alias.asname or alias.name.split(".", 1)[0])

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            for alias in node.names:
                if alias.name != "*":
                    local_names.add(alias.asname or alias.name)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                local_names.add(node.id)

        def visit_Global(self, node: ast.Global) -> None:
            local_names.difference_update(node.names)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            local_names.difference_update(node.names)

    LocalBindings().visit(function)
    return local_names


def _resolve_module_attribute(
    index: _ModuleIndex, node: ast.Attribute, indexes: dict[str, _ModuleIndex]
) -> str | None:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.reverse()
    root = current.id
    if root in index.module_imports:
        base = index.module_imports[root]
        return ".".join([base, *parts])
    if root in index.imports:
        base = _resolve_imported_target(index.imports[root], indexes)
        return ".".join([base, *parts])
    return None


def _callee_cone_records(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    modified: list[ModifiedCallable],
    unresolved_inventory: list[UnresolvedConstruct],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Materialize resolved callee edges and callee-owned unresolved evidence."""
    edge_records: dict[tuple[Any, ...], dict[str, Any]] = {}
    unresolved_records: dict[tuple[Any, ...], dict[str, Any]] = {}
    for side, indexes in (("pre", before), ("post", after)):
        functions = _function_code(indexes)
        roots = sorted(
            item.qualified_name
            for item in modified
            if item.qualified_name in functions
        )
        if not roots:
            continue
        edges = _post_call_edges(indexes)
        paths: dict[str, tuple[str, ...]] = {root: (root,) for root in roots}
        pending = list(roots)
        offset = 0
        while offset < len(pending):
            caller = pending[offset]
            offset += 1
            caller_path = paths[caller]
            for callee, raw in edges.get(caller, ()):
                path = (*caller_path, callee)
                resolution = "resolved" if callee in functions else "assumed"
                record = {
                    "caller_qualified_name": caller,
                    "callee_qualified_name": callee,
                    "file_path": raw.file_path,
                    "line_number": raw.line_number,
                    "kind": "direct" if len(path) == 2 else "transitive",
                    "path": list(path),
                    "resolution": resolution,
                    "provenance": _provenance(
                        "callee_call_edge",
                        resolution,
                        raw.file_path,
                        raw.line_number,
                        raw.node_source,
                    ),
                    "node_id": (
                        f"{raw.file_path}::call:{raw.line_number}:"
                        f"{caller}->{callee}"
                    ),
                    "side": side,
                }
                edge_key = (
                    side,
                    raw.file_path,
                    raw.line_number,
                    caller,
                    callee,
                )
                edge_records.setdefault(edge_key, record)
                if callee in functions and callee not in paths:
                    paths[callee] = path
                    pending.append(callee)

        callee_nodes = set(paths) - set(roots)
        for item in unresolved_inventory:
            owner = item.caller_qualified_name
            if owner not in callee_nodes or item.side not in {side, "both"}:
                continue
            path = paths[owner]
            record = asdict(item)
            record.update(
                {
                    "callee_qualified_name": owner,
                    "resolution": "unresolved",
                    "path": list(path),
                    "side": side,
                }
            )
            unresolved_records[(side, item.node_id, item.file_path, item.line_number, item.kind)] = record

    return (
        sorted(edge_records.values(), key=lambda item: (item["side"], item["file_path"], item["line_number"], item["callee_qualified_name"])),
        sorted(unresolved_records.values(), key=lambda item: (item["side"], item["file_path"], item["line_number"], item["kind"])),
    )


def _callable_module(indexes: dict[str, _ModuleIndex], qualified_name: str) -> str:
    for index in indexes.values():
        if qualified_name in index.functions or qualified_name in index.functions_ast:
            return index.module_name
    return qualified_name.rpartition(".")[0]


def _shortest_call_path(
    indexes: dict[str, _ModuleIndex],
    start: str,
    target: str,
    call_edges: dict[str, list[tuple[str, _RawCall]]] | None = None,
) -> tuple[tuple[str, ...] | None, tuple[_RawCall, ...] | None]:
    """Return a deterministic shortest post-tree call path with every source edge."""
    if start == target:
        return (start,), ()
    edges = call_edges if call_edges is not None else _post_call_edges(indexes)

    pending: list[tuple[str, tuple[str, ...], tuple[_RawCall, ...]]] = [(start, (start,), ())]
    seen = {start}
    offset = 0
    while offset < len(pending):
        current, path, path_calls = pending[offset]
        offset += 1
        for callee, raw in edges.get(current, ()):
            if callee == target:
                return (*path, target), (*path_calls, raw)
            if callee in seen:
                continue
            seen.add(callee)
            pending.append((callee, (*path, callee), (*path_calls, raw)))
    return None, None


def _post_call_edges(indexes: dict[str, _ModuleIndex]) -> dict[str, list[tuple[str, _RawCall]]]:
    edges: dict[str, list[tuple[str, _RawCall]]] = {}
    for index in indexes.values():
        for raw in index.calls:
            callee, _ = _resolve_call(index, raw, indexes)
            if callee is not None:
                edges.setdefault(raw.caller, []).append((callee, raw))
    for outgoing in edges.values():
        outgoing.sort(key=lambda item: (item[0], item[1].file_path, item[1].line_number))
    return edges


def _impacted_test_nodes(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_targets: set[str],
) -> list[dict[str, Any]]:
    post_callables = _function_code(after)
    pre_callable_names = {
        name for index in before.values() for name in index.functions_ast
    }
    post_targets = changed_targets & set(post_callables)
    behavior_targets = {
        name for name in post_targets if not _is_repo_test_callable(after, name)
    }
    reachable = _reachable_callers(after, behavior_targets or post_targets)
    call_edges = _post_call_edges(after)
    records: list[dict[str, Any]] = []
    for index in after.values():
        if not _is_test_file_path(index.file_path):
            continue
        for qualified_name, node in index.functions_ast.items():
            if qualified_name not in reachable or not _is_pytest_node(index, qualified_name):
                continue
            candidates: list[tuple[tuple[Any, ...], tuple[str, ...], tuple[_RawCall, ...]]] = []
            for target in sorted(behavior_targets or post_targets):
                path, path_calls = _shortest_call_path(after, qualified_name, target, call_edges)
                if path is not None and path_calls is not None:
                    candidates.append(((len(path), path), path, path_calls))
            if not candidates:
                continue
            _, reaches, path_calls = min(candidates, key=lambda item: item[0])
            node_source = _ast_source_segment(index.source, node) or ast.unparse(node)
            if path_calls:
                provenance_file = path_calls[0].file_path
                provenance_line = path_calls[0].line_number
                provenance_source = "\n".join(call.node_source for call in path_calls)
            else:
                provenance_file = index.file_path
                provenance_line = node.lineno
                provenance_source = node_source
            relative_callable = qualified_name
            prefix = f"{index.module_name}."
            if relative_callable.startswith(prefix):
                relative_callable = relative_callable[len(prefix):]
            node_id = "::".join([index.file_path, *relative_callable.split(".")])
            records.append(
                {
                    "node_id": node_id,
                    "file": index.file_path,
                    "line": node.lineno,
                    "reaches": list(reaches),
                    "exists_in_base": qualified_name in pre_callable_names,
                    "provenance": _provenance(
                        "impacted_test_node_reverse_closure",
                        "resolved",
                        provenance_file,
                        provenance_line,
                        provenance_source,
                    ),
                }
            )
    return sorted(records, key=lambda item: item["node_id"])


def _is_pytest_node(index: _ModuleIndex, qualified_name: str) -> bool:
    prefix = f"{index.module_name}."
    suffix = qualified_name[len(prefix):] if qualified_name.startswith(prefix) else qualified_name
    parts = suffix.split(".")
    function_name = parts[-1]
    is_test_function = function_name.startswith("test_")
    is_unittest_method = is_test_function and any(part.startswith("Test") for part in parts[:-1])
    return is_test_function or is_unittest_method


def _is_test_file_path(file_path: str) -> bool:
    path = PurePosixPath(file_path)
    return (
        any(part in {"test", "tests"} for part in path.parts)
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
    )


def _is_repo_test_callable(indexes: dict[str, _ModuleIndex], qualified_name: str) -> bool:
    index = next(
        (candidate for candidate in indexes.values() if qualified_name in candidate.functions_ast),
        None,
    )
    return bool(
        index is not None
        and _is_test_file_path(index.file_path)
        and _is_pytest_node(index, qualified_name)
    )


def _transitive_call_paths(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    changed_targets: set[str],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for side, indexes in (("pre", before), ("post", after)):
        functions = _function_code(indexes)
        call_edges = _post_call_edges(indexes)
        for target in sorted(changed_targets & set(functions)):
            for caller, path, path_calls in _call_paths_to_target(target, call_edges):
                if len(path) <= 2:
                    continue
                path_edges = [
                    {
                        "caller_qualified_name": path[position],
                        "callee_qualified_name": path[position + 1],
                        "site": {"file": raw.file_path, "line": raw.line_number},
                        "provenance": _provenance(
                            "transitive_call_edge",
                            "resolved",
                            raw.file_path,
                            raw.line_number,
                            raw.node_source,
                        ),
                    }
                    for position, raw in enumerate(path_calls)
                ]
                first = path_calls[0]
                records.append(
                    {
                        "side": side,
                        "target_qualified_name": target,
                        "caller_qualified_name": caller,
                        "kind": "transitive",
                        "path": list(path),
                        "path_edges": path_edges,
                        "provenance": _provenance(
                            "transitive_call_closure",
                            "resolved",
                            first.file_path,
                            first.line_number,
                            "\n".join(raw.node_source for raw in path_calls),
                        ),
                    }
                )
    return sorted(
        records,
        key=lambda item: (item["side"], item["target_qualified_name"], item["caller_qualified_name"]),
    )


def _call_paths_to_target(
    target: str,
    call_edges: dict[str, list[tuple[str, _RawCall]]],
) -> list[tuple[str, tuple[str, ...], tuple[_RawCall, ...]]]:
    reverse: dict[str, list[tuple[str, _RawCall]]] = {}
    for caller, outgoing in call_edges.items():
        for callee, raw in outgoing:
            reverse.setdefault(callee, []).append((caller, raw))
    for incoming in reverse.values():
        incoming.sort(key=lambda item: (item[0], item[1].file_path, item[1].line_number))

    distance = {target: 0}
    next_edge: dict[str, tuple[str, _RawCall]] = {}
    queue = [target]
    offset = 0
    while offset < len(queue):
        current = queue[offset]
        offset += 1
        for caller, raw in reverse.get(current, ()):
            if caller in distance:
                continue
            distance[caller] = distance[current] + 1
            next_edge[caller] = (current, raw)
            queue.append(caller)

    paths: list[tuple[str, tuple[str, ...], tuple[_RawCall, ...]]] = []
    for caller in sorted(distance):
        if caller == target:
            continue
        path = [caller]
        path_calls: list[_RawCall] = []
        current = caller
        while current != target:
            following, raw = next_edge[current]
            path.append(following)
            path_calls.append(raw)
            current = following
        paths.append((caller, tuple(path), tuple(path_calls)))
    return paths


def _unresolved_key(item: UnresolvedConstruct) -> tuple[Any, ...]:
    return (
        item.file_path,
        item.line_number,
        item.kind,
        item.source,
        item.scope,
        item.caller_qualified_name,
        item.target_qualified_name,
        item.raised_exception,
        item.condition_sha256,
        item.node_id,
    )


def _guard_dominates_reachable_call(
    guard: UnresolvedConstruct,
    trees: tuple[dict[str, _ModuleIndex], dict[str, _ModuleIndex]],
    reachable: set[str],
) -> bool:
    """Conservatively detect a preceding unsupported guard on a reachable call path.

    A guard blocks only when it is an ancestor of a call or a preceding sibling
    statement in the same AST suite. Line ordering across unrelated branches is
    not treated as dominance.
    """
    caller = guard.caller_qualified_name
    if caller is None:
        return False
    for indexes in trees:
        index = next((item for item in indexes.values() if item.file_path == guard.file_path), None)
        if index is None:
            continue
        function = index.functions_ast.get(caller)
        if function is None:
            continue
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(function):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        guard_nodes = [
            node for node in ast.walk(function)
            if isinstance(node, ast.If) and node.lineno == guard.line_number
        ]
        if not guard_nodes:
            continue

        def is_ancestor(ancestor: ast.AST, node: ast.AST) -> bool:
            current = node
            while current in parents:
                current = parents[current]
                if current is ancestor:
                    return True
            return False

        def statement_location(node: ast.AST) -> tuple[ast.AST, str, int] | None:
            current = node
            while current in parents:
                parent = parents[current]
                for field_name, value in ast.iter_fields(parent):
                    if isinstance(value, list) and current in value:
                        if isinstance(current, ast.stmt):
                            return parent, field_name, value.index(current)
                current = parent
            return None

        for raw in index.calls:
            if raw.caller != caller:
                continue
            callee, _ = _resolve_call(index, raw, indexes)
            if callee not in reachable:
                continue
            call_nodes = [
                node for node in ast.walk(function)
                if isinstance(node, ast.Call) and node.lineno == raw.line_number
                and ast.unparse(node.func) == raw.function_name
            ]
            for guard_node in guard_nodes:
                for call_node in call_nodes:
                    if is_ancestor(guard_node, call_node):
                        return True
                    guard_location = statement_location(guard_node)
                    call_location = statement_location(call_node)
                    if (
                        guard_location is not None
                        and call_location is not None
                        and guard_location[:2] == call_location[:2]
                        and guard_location[2] < call_location[2]
                    ):
                        return True
    return False


def _caller_contexts(
    before: dict[str, _ModuleIndex],
    after: dict[str, _ModuleIndex],
    baseline_sites: list[ImpactedCallSite],
    post_sites: list[ImpactedCallSite],
) -> list[dict[str, Any]]:
    """Describe method callers with only statically recoverable construction facts."""
    after_by_path = {item.file_path: item for item in after.values()}
    before_by_path = {item.file_path: item for item in before.values()}
    selected: dict[
        tuple[str, str, str, int],
        tuple[_ModuleIndex, ImpactedCallSite, dict[str, _ModuleIndex]],
    ] = {}
    candidate_pairs = {
        (site.callee_qualified_name, site.caller_qualified_name, site.file_path)
        for site in post_sites
    }

    # Prefer candidate call sites, but retain a baseline context for a callable
    # removed from the candidate tree so that its caller remains inspectable.
    for indexes, sites, tree in (
        (before_by_path, baseline_sites, before),
        (after_by_path, post_sites, after),
    ):
        for site in sites:
            if indexes is before_by_path and (
                site.callee_qualified_name, site.caller_qualified_name, site.file_path
            ) in candidate_pairs:
                continue
            index = indexes.get(site.file_path)
            if index is None:
                continue
            if _enclosing_class_qualname(index, site.caller_qualified_name) is None:
                continue
            key = (site.callee_qualified_name, site.caller_qualified_name, site.file_path, site.line_number)
            selected[key] = (index, site, tree)

    contexts: list[dict[str, Any]] = []
    for _, (index, site, tree) in sorted(selected.items()):
        owner_class = _enclosing_class_qualname(index, site.caller_qualified_name)
        if owner_class is None:
            continue
        method_name = site.caller_qualified_name.rsplit(".", 1)[-1]
        for receiver_class in _effective_receiver_classes(tree, owner_class, method_name):
            contexts.append(
                _one_caller_context(
                    index,
                    site,
                    tree,
                    receiver_class_qualname=receiver_class,
                )
            )
    return contexts


def _one_caller_context(
    index: _ModuleIndex,
    site: ImpactedCallSite,
    indexes: dict[str, _ModuleIndex],
    *,
    receiver_class_qualname: str,
) -> dict[str, Any]:
    caller = index.functions_ast.get(site.caller_qualified_name)
    if caller is None:
        return {}
    class_index = next(
        (candidate for candidate in indexes.values() if receiver_class_qualname in candidate.classes_ast),
        None,
    )
    if class_index is None:
        return {}
    class_node = class_index.classes_ast[receiver_class_qualname]
    constructor_node = class_index.functions_ast.get(f"{receiver_class_qualname}.__init__")
    caller_static, caller_classmethod = _decorator_flags(caller)
    constructor_static, constructor_classmethod = (
        _decorator_flags(constructor_node) if constructor_node else (False, False)
    )
    target_node = next(
        (candidate.functions_ast[site.callee_qualified_name]
         for candidate in indexes.values()
         if site.callee_qualified_name in candidate.functions_ast),
        None,
    )
    constructor, override_flags = _constructor_facts(
        indexes, receiver_class_qualname, class_node, constructor_node
    )
    constructor_sites, nonliteral_sites = _constructor_sites(indexes, receiver_class_qualname)
    field_writes = _literal_self_writes(constructor_node, class_index.file_path)
    field_writes.extend(_test_field_writes(indexes, receiver_class_qualname))
    field_writes = _dedupe_records(field_writes, ("field", "value", "file", "line", "source"))
    receiver_name = None
    if caller.args.args and caller.args.args[0].arg in {"self", "cls"}:
        receiver_name = caller.args.args[0].arg
    return {
        # Use the effective runtime class for inherited methods. The source
        # owner remains explicit so callers can trace the record to its AST.
        "caller_qualname": f"{receiver_class_qualname}.{caller.name}",
        "defined_on": site.caller_qualified_name.rsplit(".", 1)[0],
        "module": index.module_name,
        "class_qualname": receiver_class_qualname,
        "method_signature": _signature_text(caller, index.source),
        "staticmethod": caller_static,
        "classmethod": caller_classmethod,
        "target_qualified_name": site.callee_qualified_name,
        "call_site": {"file": site.file_path, "line": site.line_number},
        "receiver_expression": receiver_name,
        "target_arg_flow": _target_arg_flow(site, caller, target_node),
        "constructor": {
            **constructor,
            "staticmethod": constructor_static,
            "classmethod": constructor_classmethod,
        },
        "constructor_sites": constructor_sites,
        "non_literal_constructor_site_count": nonliteral_sites,
        "field_writes": field_writes,
        "fields_read": _field_reads(caller),
        "parameter_facts": _caller_parameter_facts(
            indexes, index, caller, site.caller_qualified_name
        ),
        "effect_flags": {
            "caller": _execution_effect_flags(caller, index.file_path, index.source),
            "constructor": [
                *_execution_effect_flags(constructor_node, class_index.file_path, class_index.source),
                *override_flags,
            ],
        },
        "provenance": _provenance(
            "method_caller_context",
            "assumed",
            index.file_path,
            caller.lineno,
            _ast_source_segment(index.source, caller) or ast.unparse(caller),
        ),
    }


def _effective_receiver_classes(
    indexes: dict[str, _ModuleIndex], owner_qualname: str, method_name: str
) -> list[str]:
    """Return classes that inherit this implementation without overriding it."""
    class_locations = {
        name: index
        for index in indexes.values()
        for name in index.classes_ast
    }
    class_names = set(class_locations)

    def inherits(candidate: str, seen: frozenset[str]) -> bool:
        if candidate == owner_qualname:
            return True
        if candidate in seen:
            return False
        index = class_locations.get(candidate)
        if index is None or f"{candidate}.{method_name}" in index.functions_ast:
            return False
        node = index.classes_ast[candidate]
        for base in node.bases:
            base_qualname = _resolve_class_call(index, ast.unparse(base), class_names, indexes)
            if base_qualname and inherits(base_qualname, seen | {candidate}):
                return True
        return False

    return sorted(name for name in class_names if inherits(name, frozenset()))


def _caller_parameter_facts(
    indexes: dict[str, _ModuleIndex],
    caller_index: _ModuleIndex,
    caller: ast.FunctionDef | ast.AsyncFunctionDef,
    caller_qualname: str,
) -> dict[str, dict[str, Any]]:
    """Expose source-backed input shapes for method parameters used by this caller."""
    positional = [*caller.args.posonlyargs, *caller.args.args]
    keyword_only = list(caller.args.kwonlyargs)
    receiver = positional[0].arg if positional and positional[0].arg in {"self", "cls"} else None
    params = [item for item in [*positional, *keyword_only] if item.arg != receiver]
    class_names = {name for index in indexes.values() for name in index.classes_ast}
    normalized_classes: dict[str, list[str]] = {}
    for name in class_names:
        normalized_classes.setdefault(_normalized_identifier(name.rsplit(".", 1)[-1]), []).append(name)

    facts: dict[str, dict[str, Any]] = {}
    for param in params:
        param_name = param.arg
        attr_reads: set[str] = set()
        attr_writes: set[str] = set()
        attr_aliases: dict[str, set[str]] = {}
        container_use = False

        for node in _walk_function_scope(caller):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == param_name:
                if isinstance(node.ctx, ast.Load):
                    attr_reads.add(node.attr)
                elif isinstance(node.ctx, (ast.Store, ast.Del)):
                    attr_writes.add(node.attr)
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == param_name:
                container_use = True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == param_name:
                    if node.func.attr in {"get", "items", "keys", "values", "pop", "setdefault", "update"}:
                        container_use = True
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == param_name:
                    for target in targets:
                        if isinstance(target, ast.Name):
                            attr_aliases.setdefault(target.id, set()).add(value.attr)

        attr_container: dict[str, bool] = {name: False for name in sorted(attr_reads | attr_writes)}
        for node in _walk_function_scope(caller):
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                for attr in attr_aliases.get(node.value.id, ()):
                    attr_container[attr] = True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.attr in {"get", "items", "keys", "values", "pop", "setdefault", "update"}:
                    for attr in attr_aliases.get(node.func.value.id, ()):
                        attr_container[attr] = True

        candidates: dict[str, tuple[str, dict[str, Any] | None]] = {}
        annotation_text = _ast_source_segment(caller_index.source, param.annotation) if param.annotation else None
        if param.annotation is not None:
            for qualname in _annotation_class_candidates(param.annotation, caller_index, class_names, indexes):
                candidates[qualname] = ("annotation", None)

        for qualname in _isinstance_class_candidates(caller, param_name, caller_index, class_names, indexes):
            candidates.setdefault(qualname, ("isinstance", None))

        call_value_sites = _method_parameter_value_sites(
            indexes, caller_qualname, caller, param_name, class_names
        )
        for qualname, value_site in call_value_sites:
            current = candidates.get(qualname)
            if current is None or current[0] not in {"annotation", "isinstance"}:
                candidates[qualname] = ("call_site_value", value_site)

        name_matches = normalized_classes.get(_normalized_identifier(param_name), [])
        for qualname in name_matches:
            candidates.setdefault(qualname, ("name", None))

        class_candidate_facts = []
        for qualname, (basis, value_site) in sorted(
            candidates.items(),
            key=lambda item: (_candidate_basis_order(item[1][0]), item[0]),
        ):
            class_index = next((i for i in indexes.values() if qualname in i.classes_ast), None)
            if class_index is None:
                continue
            class_node = class_index.classes_ast[qualname]
            constructor_node = class_index.functions_ast.get(f"{qualname}.__init__")
            constructor, override_flags = _constructor_facts(
                indexes, qualname, class_node, constructor_node
            )
            sites, _ = _constructor_sites(indexes, qualname)
            ctor_site = next(
                (
                    {"args": item["args"], "kwargs": item["kwargs"], "file": item["file"], "line": item["line"]}
                    for item in sites if item.get("all_literal")
                ),
                None,
            )
            can_construct = (
                (constructor["no_required_non_self_params"] or ctor_site is not None)
                and not constructor["custom_new"]
                and not constructor["custom_metaclass"]
                and not override_flags
            )
            candidate = {
                "qualname": qualname,
                "basis": basis,
                "constructible": can_construct,
                "ctor_site": ctor_site,
            }
            if value_site is not None:
                candidate["value_site"] = value_site
            class_candidate_facts.append(candidate)

        test_field_seed_values: dict[str, set[str]] = {}
        for candidate in class_candidate_facts:
            for field, values in _candidate_test_field_seeds(indexes, candidate["qualname"]).items():
                test_field_seed_values.setdefault(field, set()).update(values)

        facts[param_name] = {
            "annotation": annotation_text,
            "attr_reads": sorted(attr_reads),
            "attr_writes": sorted(attr_writes),
            "container_use": container_use,
            "attr_container": attr_container,
            "class_candidates": class_candidate_facts,
            "test_field_seeds": {
                field: sorted(values) for field, values in sorted(test_field_seed_values.items())
            },
        }
    return facts


def _candidate_test_field_seeds(
    indexes: dict[str, _ModuleIndex], class_qualname: str
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in _test_field_writes(indexes, class_qualname):
        result.setdefault(item["field"], []).append(str(item["value"]))
    return {field: sorted(set(values)) for field, values in sorted(result.items())}


def _walk_function_scope(node: ast.FunctionDef | ast.AsyncFunctionDef):
    pending: list[ast.AST] = list(node.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield current
        pending.extend(ast.iter_child_nodes(current))


def _normalized_identifier(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _candidate_basis_order(basis: str) -> int:
    return {"annotation": 0, "isinstance": 1, "call_site_value": 2, "name": 3}.get(basis, 4)


def _annotation_class_candidates(
    annotation: ast.expr,
    index: _ModuleIndex,
    class_names: set[str],
    indexes: dict[str, _ModuleIndex],
) -> list[str]:
    expressions: set[str] = set()
    pending = [annotation]
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.Name, ast.Attribute)):
            expressions.add(ast.unparse(current))
        pending.extend(ast.iter_child_nodes(current))
    result = {
        target
        for expression in expressions
        if (target := _resolve_class_call(index, expression, class_names, indexes)) is not None
    }
    return sorted(result)


def _isinstance_class_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    param_name: str,
    index: _ModuleIndex,
    class_names: set[str],
    indexes: dict[str, _ModuleIndex],
) -> list[str]:
    result: set[str] = set()
    for node in _walk_function_scope(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "isinstance":
            continue
        if len(node.args) != 2 or not isinstance(node.args[0], ast.Name) or node.args[0].id != param_name:
            continue
        type_expr = node.args[1]
        candidates = type_expr.elts if isinstance(type_expr, (ast.Tuple, ast.List)) else [type_expr]
        for candidate in candidates:
            if isinstance(candidate, (ast.Name, ast.Attribute)):
                target = _resolve_class_call(index, ast.unparse(candidate), class_names, indexes)
                if target:
                    result.add(target)
    return sorted(result)


def _method_parameter_value_sites(
    indexes: dict[str, _ModuleIndex],
    target_qualname: str,
    target_node: ast.FunctionDef | ast.AsyncFunctionDef,
    param_name: str,
    class_names: set[str],
) -> list[tuple[str, dict[str, Any]]]:
    positional = _positional_params(target_node)
    if positional and positional[0] in {"self", "cls"}:
        positional = positional[1:]
    all_params = [*positional, *(item.arg for item in target_node.args.kwonlyargs)]
    if param_name not in all_params:
        return []
    position = all_params.index(param_name)
    facts: list[tuple[str, dict[str, Any]]] = []
    for caller_index in indexes.values():
        for raw in caller_index.calls:
            callee, is_method = _resolve_call(caller_index, raw, indexes)
            if callee != target_qualname or not is_method or raw.star_args or raw.star_kwargs:
                continue
            expression = raw.arg_sources.get(param_name)
            if expression is None and position < raw.n_positional:
                expression = raw.arg_sources.get(str(position))
            if expression is None:
                continue
            expression_node = _parse_expression(expression)
            if expression_node is None:
                continue
            resolved = _resolve_callsite_expression_class(
                caller_index, raw, expression_node, class_names, indexes, param_name
            )
            for qualname, provenance in resolved:
                facts.append((qualname, {
                    "file": caller_index.file_path,
                    "line": raw.line_number,
                    "expression": expression,
                    **provenance,
                }))
    unique = {(qualname, repr(site)): (qualname, site) for qualname, site in facts}
    return [unique[key] for key in sorted(unique, key=lambda item: (item[0], str(item[1])))]


def _parse_expression(source: str) -> ast.expr | None:
    try:
        return ast.parse(source, mode="eval").body
    except (SyntaxError, ValueError):
        return None


def _resolve_callsite_expression_class(
    index: _ModuleIndex,
    raw: _RawCall,
    expression: ast.expr,
    class_names: set[str],
    indexes: dict[str, _ModuleIndex],
    parameter_name: str,
) -> list[tuple[str, dict[str, Any]]]:
    source_index = next((item for item in indexes.values() if item.file_path == index.file_path), None)
    if source_index is None:
        return []
    owner = source_index.functions_ast.get(raw.caller)
    value_node = expression
    provenance: dict[str, Any] = {}
    if isinstance(value_node, ast.Name) and owner is not None:
        definitions = [
            item for item in _walk_function_scope(owner)
            if getattr(item, "lineno", 0) < raw.line_number and _assigns_name(item, value_node.id)
        ]
        if len(definitions) != 1:
            return []
        definition = definitions[0]
        value_node = _assigned_value(definition, value_node.id)
        if value_node is None:
            return []
        provenance["definition_site"] = {"file": index.file_path, "line": definition.lineno}
    if isinstance(value_node, ast.Call):
        if isinstance(value_node.func, ast.Attribute) and value_node.func.attr == "copy":
            preferred = _normalized_identifier(parameter_name)
            return_classes = _copy_method_return_classes(indexes, preferred)
            return [
                (qualname, {**provenance, "producer": "copy_return"})
                for qualname in return_classes
            ]
        direct = _resolve_class_call(index, ast.unparse(value_node.func), class_names, indexes)
        if direct:
            return [(direct, {**provenance, "producer": "constructor_call"})]
    return []


def _assigns_name(node: ast.AST, name: str) -> bool:
    if isinstance(node, ast.Assign):
        return any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    if isinstance(node, ast.AnnAssign):
        return isinstance(node.target, ast.Name) and node.target.id == name
    return False


def _assigned_value(node: ast.AST, name: str) -> ast.expr | None:
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
        return node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
        return node.value
    return None


def _copy_method_return_classes(
    indexes: dict[str, _ModuleIndex], preferred_class_name: str
) -> list[str]:
    candidates: set[str] = set()
    for index in indexes.values():
        for class_qualname in index.classes_ast:
            if _normalized_identifier(class_qualname.rsplit(".", 1)[-1]) != preferred_class_name:
                continue
            method = index.functions_ast.get(f"{class_qualname}.copy")
            if method is None:
                continue
            constructed: dict[str, set[str]] = {}
            nodes = list(_walk_function_scope(method))
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    if not isinstance(value, ast.Call):
                        continue
                    target_class = _resolve_class_call(index, ast.unparse(value.func),
                                                       {name for item in indexes.values() for name in item.classes_ast}, indexes)
                    if target_class:
                        for target in targets:
                            if isinstance(target, ast.Name):
                                constructed.setdefault(target.id, set()).add(target_class)
            for node in nodes:
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Name):
                    return_classes = constructed.get(node.value.id, set())
                    if len(return_classes) == 1:
                        candidates.update(return_classes)
                elif isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
                    target_class = _resolve_class_call(index, ast.unparse(node.value.func),
                                                       {name for item in indexes.values() for name in item.classes_ast}, indexes)
                    if target_class:
                        candidates.add(target_class)
    return sorted(candidates)


def _enclosing_class_qualname(index: _ModuleIndex, callable_qualname: str) -> str | None:
    matches = [
        class_name for class_name in index.classes_ast
        if callable_qualname.startswith(class_name + ".")
    ]
    return max(matches, key=len) if matches else None


def _signature_text(node: ast.FunctionDef | ast.AsyncFunctionDef | None, source: str) -> str | None:
    if node is None:
        return None
    params = _ast_source_segment(source, node.args)
    if params is None:
        params = ast.unparse(node.args)
    return f"({params})"


def _decorator_flags(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, bool]:
    names = {ast.unparse(item).split("(", 1)[0].split(".")[-1] for item in node.decorator_list}
    return "staticmethod" in names, "classmethod" in names


def _positional_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [item.arg for item in [*node.args.posonlyargs, *node.args.args]]


def _target_arg_flow(
    site: ImpactedCallSite,
    caller_node: ast.FunctionDef | ast.AsyncFunctionDef,
    target_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> dict[str, dict[str, Any]]:
    if target_node is None:
        return {}
    positional_params = _positional_params(target_node)
    all_params = [*positional_params, *(item.arg for item in target_node.args.kwonlyargs)]
    if site.is_method_call and positional_params:
        positional_params = positional_params[1:]
        all_params = all_params[1:]
    if site.star_args or site.star_kwargs:
        return {param: {"expr": "<star argument forwarding>", "resolved": False} for param in all_params}
    supplied: dict[str, str] = {}
    for position in range(site.n_positional):
        if position < len(positional_params):
            source = site.arg_sources.get(str(position))
            if source is not None:
                supplied[positional_params[position]] = source
    for keyword in site.keywords:
        if keyword in site.arg_sources:
            supplied[keyword] = site.arg_sources[keyword]

    caller_params = {
        item.arg for item in [*caller_node.args.posonlyargs, *caller_node.args.args, *caller_node.args.kwonlyargs]
    }
    receiver_names = set()
    if caller_node.args.args:
        first = caller_node.args.args[0].arg
        if first in {"self", "cls"}:
            receiver_names.add(first)

    flow: dict[str, dict[str, Any]] = {}
    for param in all_params:
        source = supplied.get(param)
        if source is None:
            continue
        try:
            expression = ast.parse(source, mode="eval").body
        except SyntaxError:
            flow[param] = {"expr": source, "resolved": False}
            continue
        if isinstance(expression, ast.Name) and expression.id in caller_params and expression.id not in receiver_names:
            flow[param] = {"param": expression.id}
        elif (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and expression.value.id in receiver_names
        ):
            flow[param] = {"field": expression.attr}
        else:
            flow[param] = {"expr": source, "resolved": False}
    return flow


def _no_required_non_self_params(node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    if node is None:
        return True
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults_start = len(positional) - len(node.args.defaults)
    for position, param in enumerate(positional):
        if param.arg in {"self", "cls"}:
            continue
        if position < defaults_start:
            return False
    for param, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        if param.arg in {"self", "cls"}:
            continue
        if default is None:
            return False
    return True


def _all_non_self_defaults_literal(node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    if node is None:
        return True
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults_start = len(positional) - len(node.args.defaults)
    for position, param in enumerate(positional):
        if param.arg in {"self", "cls"}:
            continue
        if position < defaults_start or _ast_literal_repr(node.args.defaults[position - defaults_start]) is None:
            return False
    return all(
        param.arg in {"self", "cls"} or (default is not None and _ast_literal_repr(default) is not None)
        for param, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
    )


def _constructor_facts(
    indexes: dict[str, _ModuleIndex],
    class_qualname: str,
    class_node: ast.ClassDef,
    constructor_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if constructor_node is not None:
        owner = next(index for index in indexes.values() if class_qualname in index.classes_ast)
        signature = _signature_text(constructor_node, owner.source)
        no_required = _no_required_non_self_params(constructor_node)
        defaults_literal = _all_non_self_defaults_literal(constructor_node)
    else:
        owner = next(index for index in indexes.values() if class_qualname in index.classes_ast)
        base_names = [_ast_source_segment(owner.source, base) or ast.unparse(base) for base in class_node.bases]
        base = base_names[0] if base_names else "object"
        signature = f"inherited: {base}"
        no_required = base == "object"
        defaults_literal = base == "object"

    new_node = owner.functions_ast.get(f"{class_qualname}.__new__")
    has_metaclass = any(keyword.arg == "metaclass" for keyword in class_node.keywords)
    override_flags: list[dict[str, Any]] = []
    if new_node is not None:
        override_flags.append({
            "kind": "dynamic",
            "file": owner.file_path,
            "line": new_node.lineno,
            "source": "custom __new__",
        })
    if has_metaclass:
        override_flags.append({
            "kind": "dynamic",
            "file": owner.file_path,
            "line": class_node.lineno,
            "source": "custom metaclass",
        })
    return ({
        "signature": signature,
        "all_required_non_self_params_have_literal_defaults": no_required,
        "no_required_non_self_params": no_required,
        "all_non_self_defaults_literal": defaults_literal,
        "custom_new": new_node is not None,
        "custom_metaclass": has_metaclass,
    }, override_flags)


def _resolve_class_call(
    index: _ModuleIndex,
    function_name: str,
    class_names: set[str],
    indexes: dict[str, _ModuleIndex],
) -> str | None:
    parts = function_name.split(".")
    if len(parts) == 1:
        name = parts[0]
        target = index.imports.get(name, f"{index.module_name}.{name}")
        return _follow_class_alias(target, indexes, class_names)
    first, rest = parts[0], ".".join(parts[1:])
    if first in index.module_imports:
        target = f"{index.module_imports[first]}.{rest}"
    elif first in index.imports:
        target = f"{index.imports[first]}.{rest}"
    else:
        target = f"{index.module_name}.{function_name}"
    return _follow_class_alias(target, indexes, class_names)


def _follow_class_alias(target: str, indexes: dict[str, _ModuleIndex], class_names: set[str]) -> str | None:
    if target in class_names:
        return target
    modules = {item.module_name: item for item in indexes.values()}
    seen: set[str] = set()
    while target not in class_names and target not in seen:
        seen.add(target)
        if "." not in target:
            return None
        module_name, local_name = target.rsplit(".", 1)
        owner = modules.get(module_name)
        if owner is None or local_name not in owner.imports:
            return None
        target = owner.imports[local_name]
    return target if target in class_names else None


def _constructor_sites(indexes: dict[str, _ModuleIndex], class_qualname: str) -> tuple[list[dict[str, Any]], int]:
    class_names = {name for index in indexes.values() for name in index.classes_ast}
    sites: list[dict[str, Any]] = []
    non_literal_count = 0
    for index in indexes.values():
        for call in index.calls:
            if _resolve_class_call(index, call.function_name, class_names, indexes) != class_qualname:
                continue
            if not ("src" in PurePosixPath(index.file_path).parts or "tests" in PurePosixPath(index.file_path).parts):
                continue
            all_literal = not call.star_args and not call.star_kwargs
            args: list[Any] = []
            kwargs: dict[str, Any] = {}
            for position in range(call.n_positional):
                key = str(position)
                if key not in call.arg_literals:
                    all_literal = False
                    break
                args.append(ast.literal_eval(call.arg_literals[key]))
            if all_literal:
                for keyword in call.keywords:
                    if keyword not in call.arg_literals:
                        all_literal = False
                        break
                    kwargs[keyword] = ast.literal_eval(call.arg_literals[keyword])
            if all_literal:
                sites.append({
                    "file": call.file_path,
                    "line": call.line_number,
                    "args": args,
                    "kwargs": kwargs,
                    "all_literal": True,
                })
            else:
                non_literal_count += 1
    sites.sort(key=lambda item: (item["file"], item["line"]))
    return sites, non_literal_count


def _test_field_writes(indexes: dict[str, _ModuleIndex], class_qualname: str) -> list[dict[str, Any]]:
    class_names = {name for index in indexes.values() for name in index.classes_ast}
    result: list[dict[str, Any]] = []
    for index in indexes.values():
        if "tests" not in PurePosixPath(index.file_path).parts:
            continue
        for function in index.functions_ast.values():
            instances: set[str] = set()
            for node in ast.walk(function):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                    continue
                assigned = node.targets if isinstance(node, ast.Assign) else [node.target]
                resolved = _resolve_class_call(index, ast.unparse(node.value.func), class_names, indexes)
                if resolved != class_qualname:
                    continue
                instances.update(target.id for target in assigned if isinstance(target, ast.Name))
            if not instances:
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign):
                    targets, value = [node.target], node.value
                else:
                    continue
                if value is None:
                    continue
                literal = _ast_literal_repr(value)
                if literal is None:
                    continue
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id in instances
                    ):
                        result.append({
                            "field": target.attr,
                            "value": literal,
                            "file": index.file_path,
                            "line": node.lineno,
                            "source": "test_setup",
                        })
    return sorted(result, key=lambda item: (item["file"], item["line"], item["field"]))


def _dedupe_records(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    unique = {tuple(item.get(key) for key in keys): item for item in items}
    return [unique[key] for key in sorted(unique, key=lambda value: tuple(map(str, value)))]


def _literal_self_writes(node: ast.FunctionDef | ast.AsyncFunctionDef | None, file_path: str) -> list[dict[str, Any]]:
    if node is None:
        return []
    result = []
    for current in ast.walk(node):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(current, ast.Assign):
            targets, value = current.targets, current.value
        elif isinstance(current, ast.AnnAssign):
            targets, value = [current.target], current.value
        if value is None:
            continue
        literal = _ast_literal_repr(value)
        if literal is None:
            continue
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id in {"self", "cls"}
            ):
                result.append({"field": target.attr, "value": literal, "file": file_path, "line": current.lineno, "source": "__init__"})
    return sorted(result, key=lambda item: (item["file"], item["line"], item["field"]))


def _field_reads(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    result = []
    for current in ast.walk(node):
        if (
            isinstance(current, ast.Attribute)
            and isinstance(current.value, ast.Name)
            and current.value.id in {"self", "cls"}
        ):
            result.append({"field": current.attr, "line": current.lineno})
    unique = {(item["field"], item["line"]): item for item in result}
    return [unique[key] for key in sorted(unique)]


def _execution_effect_flags(
    node: ast.FunctionDef | ast.AsyncFunctionDef | None, file_path: str, source: str
) -> list[dict[str, Any]]:
    if node is None:
        return []
    flags: list[dict[str, Any]] = []
    for current in ast.walk(node):
        if isinstance(current, ast.Call):
            name = ast.unparse(current.func).replace(" ", "")
            kind = None
            if _resource_factory(name):
                kind = "resource"
            elif name.startswith("subprocess.") or name in {"os.system", "os.exec", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe"}:
                kind = "subprocess"
            elif (
                name.startswith("socket.")
                or name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"}
                or name.startswith("urllib.request.") and name.endswith("urlopen")
                or name.startswith("httpx.") and name.rsplit(".", 1)[-1] in {"get", "post", "put", "delete", "request", "send"}
                or name.endswith((".connect", ".urlopen"))
            ):
                kind = "network"
            elif name.startswith(("threading.", "multiprocessing.", "concurrent.futures.")) or name.endswith(("Thread", "ThreadPoolExecutor", "ProcessPoolExecutor")):
                kind = "threads"
            elif name in {"eval", "exec", "__import__", "getattr", "importlib.import_module", "import_module"}:
                kind = "dynamic"
            elif _effect_name(name):
                kind = "io"
            if kind:
                flags.append({
                    "kind": kind,
                    "file": file_path,
                    "line": current.lineno,
                    "source": _ast_source_segment(source, current) or name,
                })
        elif isinstance(current, ast.Subscript) and isinstance(current.value, ast.Attribute):
            if isinstance(current.value.value, ast.Name) and current.value.value.id == "sys" and current.value.attr == "modules":
                flags.append({"kind": "dynamic", "file": file_path, "line": current.lineno, "source": "sys.modules"})
    return sorted(flags, key=lambda item: (item["file"], item["line"], item["kind"]))


def _resource_factory(name: str) -> bool:
    """Known manager factories allocate state without performing external I/O."""
    terminal = name.rsplit(".", 1)[-1]
    return terminal in {
        "PoolManager",
        "ProxyManager",
        "SOCKSProxyManager",
        "proxy_from_url",
    } and (
        terminal != "proxy_from_url"
        or name in {"proxy_from_url", "urllib3.poolmanager.proxy_from_url"}
    )


def _exception_import_aliases(
    module_ast: ast.Module, module_name: str, *, is_package_init: bool = False
) -> tuple[dict[str, str], dict[str, str]]:
    imports: dict[str, str] = {}
    module_imports: dict[str, str] = {}
    for node in module_ast.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    module_imports[alias.asname] = alias.name
                else:
                    root = alias.name.split(".", 1)[0]
                    module_imports[root] = root
        elif isinstance(node, ast.ImportFrom):
            base = _ast_from_module_name(module_name, node, is_package_init=is_package_init)
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name.split(".")[-1]
                imports[local] = f"{base}.{alias.name}" if base else alias.name
    return imports, module_imports


def _single_guard_exception(
    statements: list[ast.stmt],
    imports: dict[str, str],
    module_imports: dict[str, str],
    local_class_names: set[str],
    module_name: str,
    shadowed_names: set[str],
) -> str | None:
    names: set[str] = set()
    pending: list[ast.AST] = list(statements)
    while pending:
        current = pending.pop()
        if isinstance(current, ast.Raise):
            expression = current.exc
            if expression is None:
                return None
            if isinstance(expression, ast.Call):
                expression = expression.func
            if isinstance(expression, ast.Name):
                if expression.id in shadowed_names:
                    return None
                if expression.id in imports:
                    names.add(imports[expression.id])
                    continue
                builtin = getattr(builtins, expression.id, None)
                if isinstance(builtin, type) and issubclass(builtin, BaseException):
                    names.add(f"builtins.{expression.id}")
                    continue
                if expression.id in local_class_names:
                    names.add(f"{module_name}.{expression.id}")
                    continue
                return None
            if isinstance(expression, ast.Attribute):
                parts = ast.unparse(expression).split(".")
                root, *suffix = parts
                if root in shadowed_names:
                    return None
                if root in module_imports:
                    names.add(".".join([module_imports[root], *suffix]))
                    continue
                if root in imports:
                    names.add(".".join([imports[root], *suffix]))
                    continue
                if root == "builtins" and suffix:
                    builtin = getattr(builtins, suffix[-1], None)
                    if isinstance(builtin, type) and issubclass(builtin, BaseException):
                        names.add(f"builtins.{suffix[-1]}")
                        continue
                return None
            return None
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(current))
    return next(iter(names)) if len(names) == 1 else None


def _function_local_binding_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> set[str]:
    if function is None:
        return set()
    names = {
        argument.arg
        for argument in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    }
    if function.args.vararg:
        names.add(function.args.vararg.arg)
    if function.args.kwarg:
        names.add(function.args.kwarg.arg)
    pending: list[ast.AST] = list(function.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(current.name)
            continue
        if isinstance(current, ast.Lambda):
            continue
        if isinstance(current, ast.Name) and isinstance(current.ctx, (ast.Store, ast.Del)):
            names.add(current.id)
        elif isinstance(current, ast.Import):
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in current.names)
        elif isinstance(current, ast.ImportFrom):
            names.update(
                alias.asname or alias.name
                for alias in current.names
                if alias.name != "*"
            )
        elif isinstance(current, ast.ExceptHandler) and current.name:
            names.add(current.name)
        elif isinstance(current, (ast.Global, ast.Nonlocal)):
            names.update(current.names)
        pending.extend(ast.iter_child_nodes(current))
    return names


_GUARD_BUILTIN_TYPES = {
    "int", "str", "float", "bool", "bytes", "list", "tuple", "dict", "set", "NoneType"
}


def _version_expression_value(
    node: ast.AST,
    environment: dict[str, tuple[Any, bool]],
) -> tuple[bool, Any, bool]:
    """Evaluate only expressions rooted in the running target interpreter version."""
    if isinstance(node, ast.Constant):
        return True, node.value, False
    if isinstance(node, ast.Tuple):
        values = [_version_expression_value(item, environment) for item in node.elts]
        if all(known for known, _value, _version_based in values):
            return (
                True,
                tuple(value for _known, value, _version_based in values),
                any(version_based for _known, _value, version_based in values),
            )
        return False, None, False
    if isinstance(node, ast.Name):
        value = environment.get(node.id)
        return (True, value[0], value[1]) if value is not None else (False, None, False)
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            root = current.id
            module = environment.get(root)
            if module == ("sys-module", True):
                qualified = ".".join([root, *reversed(parts)])
                if qualified.endswith(".version_info"):
                    return True, tuple(sys.version_info), True
                if qualified.endswith(".version"):
                    return True, sys.version, True
        return False, None, False
    if isinstance(node, ast.Subscript):
        known, value, version_based = _version_expression_value(node.value, environment)
        if isinstance(node.slice, ast.Slice):
            slice_parts: list[Any] = []
            slice_version = False
            for part in (node.slice.lower, node.slice.upper, node.slice.step):
                if part is None:
                    slice_parts.append(None)
                    continue
                part_known, part_value, part_version = _version_expression_value(part, environment)
                if not part_known:
                    return False, None, False
                slice_parts.append(part_value)
                slice_version = slice_version or part_version
            index = slice(*slice_parts)
            index_version_based = slice_version
        else:
            index_known, index, index_version_based = _version_expression_value(node.slice, environment)
            if not index_known:
                return False, None, False
        if not known:
            return False, None, False
        try:
            return True, value[index], version_based or index_version_based
        except (IndexError, KeyError, TypeError):
            return False, None, False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        known, value, version_based = _version_expression_value(node.operand, environment)
        return (True, not value, version_based) if known else (False, None, False)
    if isinstance(node, ast.BoolOp):
        values = [_version_expression_value(value, environment) for value in node.values]
        if not all(known for known, _value, _version_based in values):
            return False, None, False
        if isinstance(node.op, ast.And):
            result = all(bool(value) for _known, value, _version_based in values)
        elif isinstance(node.op, ast.Or):
            result = any(bool(value) for _known, value, _version_based in values)
        else:
            return False, None, False
        return True, result, any(version_based for _known, _value, version_based in values)
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        left_known, left, left_version = _version_expression_value(node.left, environment)
        right_known, right, right_version = _version_expression_value(node.comparators[0], environment)
        if not left_known or not right_known or not (left_version or right_version):
            return False, None, False
        comparisons = {
            ast.Eq: lambda a, b: a == b,
            ast.NotEq: lambda a, b: a != b,
            ast.Lt: lambda a, b: a < b,
            ast.LtE: lambda a, b: a <= b,
            ast.Gt: lambda a, b: a > b,
            ast.GtE: lambda a, b: a >= b,
        }
        comparison = comparisons.get(type(node.ops[0]))
        if comparison is None:
            return False, None, False
        try:
            return True, comparison(left, right), True
        except (TypeError, ValueError):
            return False, None, False
    return False, None, False


def _assigned_module_names(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    pending: list[ast.AST] = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(
                alias.asname or alias.name.split(".")[-1]
                for alias in node.names if alias.name != "*"
            )
        pending.extend(ast.iter_child_nodes(node))
    return names


def _module_export_bindings(
    module_name: str,
    source: str,
    *,
    is_package_init: bool = False,
) -> tuple[dict[str, list[tuple[str, Any, tuple[str, ...]]]], set[str], set[str]] | None:
    """Collect one module's statically active top-level bindings or fail closed."""
    try:
        parsed = ast.parse(source)
    except SyntaxError:
        return None
    bindings: dict[str, list[tuple[str, Any, tuple[str, ...]]]] = {}
    invalid: set[str] = set()
    environment: dict[str, tuple[Any, bool]] = {}
    star_imports: set[str] = set()

    def bind(name: str, kind: str, value: Any, assumptions: tuple[str, ...]) -> None:
        bindings.setdefault(name, []).append((kind, value, assumptions))
        environment.pop(name, None)

    def scan(statements: list[ast.stmt], assumptions: tuple[str, ...] = ()) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bind(statement.name, "opaque", None, assumptions)
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    target = alias.name if alias.asname else local
                    bind(local, "import_module", target, assumptions)
                    if target == "sys":
                        environment[local] = ("sys-module", True)
            elif isinstance(statement, ast.ImportFrom):
                base = _ast_from_module_name(
                    module_name, statement, is_package_init=is_package_init
                )
                for alias in statement.names:
                    if alias.name == "*":
                        star_imports.add(module_name)
                        continue
                    local = alias.asname or alias.name
                    target = f"{base}.{alias.name}" if base else alias.name
                    bind(local, "import_symbol", target, assumptions)
                    if base == "sys" and alias.name == "version_info":
                        environment[local] = (tuple(sys.version_info), True)
                    elif base == "sys" and alias.name == "version":
                        environment[local] = (sys.version, True)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                value_node = statement.value
                for target in targets:
                    if isinstance(target, ast.Name):
                        bind(target.id, "expression", value_node, assumptions)
                        if value_node is not None:
                            known, value, version_based = _version_expression_value(value_node, environment)
                            if known:
                                environment[target.id] = (value, version_based)
            elif isinstance(statement, ast.AugAssign):
                for name in _assigned_module_names([statement]):
                    invalid.add(name)
                    environment.pop(name, None)
            elif isinstance(statement, ast.Delete):
                for name in _assigned_module_names([statement]):
                    invalid.add(name)
                    environment.pop(name, None)
            elif isinstance(statement, ast.If):
                known, value, version_based = _version_expression_value(statement.test, environment)
                if known and version_based:
                    branch_assumptions = assumptions
                    if not any(item.startswith("assumes target python ") for item in assumptions):
                        branch_assumptions = (*assumptions, f"assumes target python {sys.version_info.major}.{sys.version_info.minor}")
                    scan(statement.body if value else statement.orelse, branch_assumptions)
                else:
                    invalid.update(_assigned_module_names([*statement.body, *statement.orelse]))
            elif isinstance(statement, (ast.Try, ast.TryStar)):
                invalid.update(
                    _assigned_module_names([
                        *statement.body,
                        *statement.handlers,
                        *statement.orelse,
                        *statement.finalbody,
                    ])
                )
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match)):
                invalid.update(_assigned_module_names([statement]))
            elif isinstance(statement, ast.Expr):
                continue

    scan(parsed.body)
    return bindings, invalid, star_imports


def _resolve_builtin_type_alias(
    module_name: str,
    symbol: str,
    module_sources: dict[str, str | None],
    seen: frozenset[tuple[str, str]] = frozenset(),
    *,
    allow_unbound_builtin: bool = False,
) -> tuple[str, tuple[str, ...]] | None:
    if module_name == "builtins":
        return (f"builtins.{symbol}", ()) if symbol in _GUARD_BUILTIN_TYPES else None
    key = (module_name, symbol)
    if key in seen:
        return None
    source = module_sources.get(module_name)
    if source is None:
        return None
    collected = _module_export_bindings(module_name, source)
    if collected is None:
        return None
    bindings, invalid, star_imports = collected
    candidates = bindings.get(symbol, [])
    if symbol in invalid or star_imports or len(candidates) != 1:
        if (
            allow_unbound_builtin
            and not candidates
            and symbol in _GUARD_BUILTIN_TYPES
            and symbol not in invalid
            and not star_imports
        ):
            return f"builtins.{symbol}", ()
        return None
    kind, value, assumptions = candidates[0]
    next_seen = seen | {key}
    resolved: tuple[str, tuple[str, ...]] | None = None
    if kind == "import_symbol":
        target = str(value)
        target_module, _, target_symbol = target.rpartition(".")
        resolved = _resolve_builtin_type_alias(target_module, target_symbol, module_sources, next_seen)
    elif kind == "expression" and isinstance(value, ast.Name):
        if value.id == symbol:
            resolved = (f"builtins.{symbol}", ()) if symbol in _GUARD_BUILTIN_TYPES else None
        else:
            resolved = _resolve_builtin_type_alias(
                module_name,
                value.id,
                module_sources,
                next_seen,
                allow_unbound_builtin=True,
            )
    elif kind == "expression" and isinstance(value, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            root_name = current.id
            base = _resolve_builtin_type_alias(module_name, root_name, module_sources, next_seen)
            if base is None:
                module_bindings = bindings.get(root_name, [])
                if len(module_bindings) == 1 and module_bindings[0][0] == "import_module":
                    module_target = str(module_bindings[0][1])
                    target_module = ".".join([module_target, *reversed(parts[:-1])])
                    resolved = _resolve_builtin_type_alias(target_module, parts[0], module_sources, next_seen)
    if resolved is None:
        return None
    return resolved[0], tuple(dict.fromkeys((*assumptions, *resolved[1])))


def _ast_contains_raise(
    statements: list[ast.stmt], cache: dict[ast.AST, bool]
) -> bool:
    pending: list[tuple[ast.AST, bool]] = [
        (statement, False) for statement in statements if statement not in cache
    ]
    while pending:
        current, visited_children = pending.pop()
        if current in cache:
            continue
        if isinstance(current, ast.Raise):
            cache[current] = True
        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            cache[current] = False
        elif visited_children:
            cache[current] = any(
                cache.get(child, False) for child in ast.iter_child_nodes(current)
            )
        else:
            children = list(ast.iter_child_nodes(current))
            pending.append((current, True))
            pending.extend((child, False) for child in children if child not in cache)
    return any(cache.get(statement, False) for statement in statements)


def _ast_guard_candidate_functions(
    module_ast: ast.Module,
) -> set[tuple[str, int]]:
    """Find functions with an if whose branch raises, sharing one AST scan cache."""
    candidates: set[tuple[str, int]] = set()
    raise_cache: dict[ast.AST, bool] = {}
    for function in ast.walk(module_ast):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        pending: list[ast.AST] = list(function.body)
        found = False
        while pending:
            current = pending.pop()
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(current, ast.If) and (
                _ast_contains_raise(current.body, raise_cache)
                or _ast_contains_raise(current.orelse, raise_cache)
            ):
                found = True
                break
            pending.extend(ast.iter_child_nodes(current))
        if found:
            candidates.add((function.name, function.lineno))
    return candidates


def _guard_module_context(
    module_ast: ast.Module, module_name: str
) -> tuple[dict[str, ast.FunctionDef], set[str]]:
    """Compute guard-helper and shadowing facts once per parsed module."""
    module_bindings: dict[str, ast.stmt | None] = {}
    for statement in module_ast.body:
        if isinstance(statement, ast.FunctionDef):
            module_bindings[statement.name] = statement
            continue
        if isinstance(statement, (ast.AsyncFunctionDef, ast.ClassDef)):
            module_bindings[statement.name] = None
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                module_bindings[alias.asname or alias.name.split(".", 1)[0]] = None
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name != "*":
                    module_bindings[alias.asname or alias.name] = None
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for assignment_target in targets:
                for name in ast.walk(assignment_target):
                    if isinstance(name, ast.Name) and isinstance(name.ctx, (ast.Store, ast.Del)):
                        module_bindings[name.id] = None
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and isinstance(name.ctx, (ast.Store, ast.Del)):
                        module_bindings[name.id] = None
    module_guard_helpers = {
        f"{module_name}.{name}": value
        for name, value in module_bindings.items()
        if isinstance(value, ast.FunctionDef)
    }

    module_shadowed_names: set[str] = set()
    module_pending: list[ast.AST] = list(module_ast.body)
    while module_pending:
        current = module_pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_shadowed_names.add(current.name)
            continue
        if isinstance(current, ast.Lambda):
            continue
        if isinstance(current, ast.Name) and isinstance(current.ctx, (ast.Store, ast.Del)):
            module_shadowed_names.add(current.id)
        elif isinstance(current, ast.Import):
            module_shadowed_names.update(alias.asname or alias.name.split(".", 1)[0] for alias in current.names)
        elif isinstance(current, ast.ImportFrom):
            module_shadowed_names.update(
                alias.asname or alias.name for alias in current.names if alias.name != "*"
            )
        elif isinstance(current, ast.ExceptHandler) and current.name:
            module_shadowed_names.add(current.name)
        module_pending.extend(ast.iter_child_nodes(current))
    return module_guard_helpers, module_shadowed_names


def _entry_guards(
    function: cst.FunctionDef,
    target: ast.FunctionDef | ast.AsyncFunctionDef | None,
    module: cst.Module,
    file_path: str,
    function_line: int,
    qualified_name: str,
    imports: dict[str, str],
    module_imports: dict[str, str],
    local_class_names: set[str],
    module_name: str,
    shadowed_names: set[str],
    allowed_guard_helpers: set[str],
    module_sources: dict[str, str | None],
    *,
    module_source: str,
    module_guard_helpers: dict[str, ast.FunctionDef] | None = None,
    module_shadowed_names: set[str] | None = None,
) -> tuple[list[EntryGuard], list[UnresolvedConstruct]]:
    params = {
        param.name.value
        for param in [*function.params.posonly_params, *function.params.params, *function.params.kwonly_params]
    }
    guards: list[EntryGuard] = []
    unresolved: list[UnresolvedConstruct] = []

    if target is None:
        return guards, [UnresolvedConstruct(file_path, function_line, "callable_ast_not_located", function.name.value, "modified_callable")]
    source = module_source

    raise_cache: dict[ast.AST, bool] = {}
    contains_raise = lambda statements: _ast_contains_raise(statements, raise_cache)

    module_guard_helpers = module_guard_helpers or {}
    module_shadowed_names = module_shadowed_names or set()
    shadowed_builtin_names = shadowed_names | module_shadowed_names
    comparison_names = {
        ast.Eq: "==",
        ast.NotEq: "!=",
        ast.Lt: "<",
        ast.LtE: "<=",
        ast.Gt: ">",
        ast.GtE: ">=",
    }
    inverse_comparison = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}
    mirrored_comparison = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
    builtin_instance_types = {
        "int", "str", "float", "bool", "bytes", "list", "tuple", "dict", "set"
    }
    guard_assumptions: set[str] = set()

    def inline_helper_calls(
        expression: ast.expr,
        depth: int = 0,
        chain: tuple[str, ...] = (),
    ) -> tuple[ast.expr, tuple[tuple[str, ast.FunctionDef, ast.Return], ...]] | None:
        class Inliner(ast.NodeTransformer):
            def __init__(self) -> None:
                self.used: list[tuple[str, ast.FunctionDef, ast.Return]] = []
                self.failed = False

            def visit_Call(self, node: ast.Call) -> ast.AST:
                if not isinstance(node.func, ast.Name):
                    return self.generic_visit(node)
                helper_name = f"{module_name}.{node.func.id}"
                helper = module_guard_helpers.get(helper_name)
                if helper is None:
                    return self.generic_visit(node)
                if (
                    helper_name not in allowed_guard_helpers
                    or helper_name in chain
                    or depth >= 2
                    or helper.decorator_list
                    or helper.args.defaults
                    or helper.args.kw_defaults
                    or helper.args.vararg is not None
                    or helper.args.kwarg is not None
                    or helper.args.kwonlyargs
                    or node.keywords
                ):
                    self.failed = True
                    return node
                statements = list(helper.body)
                if (
                    statements
                    and isinstance(statements[0], ast.Expr)
                    and isinstance(statements[0].value, ast.Constant)
                    and isinstance(statements[0].value.value, str)
                ):
                    statements.pop(0)
                if len(statements) != 1 or not isinstance(statements[0], ast.Return):
                    self.failed = True
                    return node
                returned = statements[0]
                if returned.value is None:
                    self.failed = True
                    return node
                parameters = [*helper.args.posonlyargs, *helper.args.args]
                if len(parameters) != len(node.args):
                    self.failed = True
                    return node
                actuals: dict[str, str] = {}
                for parameter, actual in zip(parameters, node.args):
                    if not isinstance(actual, ast.Name) or actual.id not in params:
                        self.failed = True
                        return node
                    actuals[parameter.arg] = actual.id
                helper_locals = _function_local_binding_names(helper)
                if helper_locals & (builtin_instance_types | {"isinstance", "type"}):
                    self.failed = True
                    return node
                if isinstance(returned.value, ast.Call) and len(returned.value.args) == 2:
                    type_names = {
                        item.id for item in ast.walk(returned.value.args[1])
                        if isinstance(item, ast.Name)
                    }
                    if helper_locals & type_names:
                        self.failed = True
                        return node

                class SubstituteParameters(ast.NodeTransformer):
                    def visit_Name(self, name_node: ast.Name) -> ast.AST:
                        actual_name = actuals.get(name_node.id)
                        if actual_name is None:
                            return name_node
                        return ast.copy_location(
                            ast.Name(id=actual_name, ctx=ast.Load()),
                            name_node,
                        )

                substituted = SubstituteParameters().visit(ast.fix_missing_locations(returned.value))
                nested = inline_helper_calls(
                    substituted,
                    depth + 1,
                    (*chain, helper_name),
                )
                if nested is None:
                    self.failed = True
                    return node
                expanded, nested_chain = nested
                self.used.append((helper_name, helper, returned))
                self.used.extend(nested_chain)
                return ast.copy_location(expanded, node)

        inliner = Inliner()
        expanded = inliner.visit(expression)
        if inliner.failed:
            return None
        return expanded, tuple(inliner.used)

    def literal_source(node: ast.expr) -> tuple[type, str] | None:
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError):
            return None
        if type(value) not in {int, str}:
            return None
        return type(value), _ast_source_segment(source, node) or ast.unparse(node)

    def isinstance_type_names(node: ast.expr) -> tuple[str, ...] | None:
        items = node.elts if isinstance(node, ast.Tuple) else [node]
        names: list[str] = []
        for item in items:
            if isinstance(item, ast.Name):
                name = item.id
                if name in shadowed_names or name in local_class_names:
                    return None
                if (
                    name in builtin_instance_types
                    and name not in shadowed_builtin_names
                    and name not in imports
                    and name not in local_class_names
                ):
                    names.append(f"builtins.{name}")
                    continue
                alias = _resolve_builtin_type_alias(
                    module_name, name, module_sources
                )
                if alias is None:
                    return None
                names.append(alias[0])
                guard_assumptions.update(alias[1])
                continue
            if (
                isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name)
                and item.func.id == "type"
                and item.func.id not in shadowed_builtin_names
                and item.func.id not in imports
                and len(item.args) == 1
                and not item.keywords
                and isinstance(item.args[0], ast.Constant)
                and item.args[0].value is None
            ):
                names.append("builtins.NoneType")
                continue
            return None
        return tuple(names) if names else None

    def classify(
        test: ast.expr, raises_in_true: bool, raises_in_false: bool
    ) -> tuple[str, str, dict[str, Any]] | None:
        invert = raises_in_false
        condition = test

        if isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
            condition = condition.operand
            invert = not invert

        if isinstance(condition, ast.Name) and condition.id in params:
            return condition.id, ("falsy" if invert else "truthy"), {}

        if isinstance(condition, ast.Call) and isinstance(condition.func, ast.Name) and condition.func.id == "isinstance":
            if condition.func.id in shadowed_builtin_names or condition.func.id in imports:
                return None
            if len(condition.args) != 2 or condition.keywords:
                return None
            value = condition.args[0]
            if not isinstance(value, ast.Name) or value.id not in params:
                return None
            type_names = isinstance_type_names(condition.args[1])
            if type_names is None:
                return None
            return value.id, "isinstance", {"type_names": type_names, "negated": invert}

        if not isinstance(condition, ast.Compare) or len(condition.ops) != 1 or len(condition.comparators) != 1:
            return None

        operator_node = condition.ops[0]
        value_node = condition.comparators[0]
        if (
            not invert
            and isinstance(operator_node, ast.In)
            and isinstance(condition.left, ast.Constant)
            and isinstance(condition.left.value, str)
            and isinstance(value_node, ast.Name)
            and value_node.id in params
        ):
            return value_node.id, "contains_literal", {"literal": condition.left.value}

        if (
            not invert
            and isinstance(operator_node, ast.Is)
            and isinstance(condition.left, ast.Name)
            and condition.left.id in params
            and isinstance(value_node, ast.Constant)
            and value_node.value is None
        ):
            return condition.left.id, "none", {}

        if (
            not invert
            and isinstance(operator_node, ast.Eq)
            and isinstance(condition.left, ast.Name)
            and condition.left.id in params
        ):
            try:
                empty_value = ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError):
                empty_value = object()
            if type(empty_value) in {str, bytes, list, dict, tuple} and len(empty_value) == 0:
                return condition.left.id, "empty", {}

        operator = comparison_names.get(type(operator_node))
        if operator is None:
            return None
        param: str
        literal_node: ast.expr
        if isinstance(condition.left, ast.Name) and condition.left.id in params:
            param, literal_node = condition.left.id, value_node
        elif isinstance(value_node, ast.Name) and value_node.id in params:
            param, literal_node = value_node.id, condition.left
            operator = mirrored_comparison[operator]
        else:
            return None
        literal = literal_source(literal_node)
        if literal is None:
            return None
        literal_type, literal_text = literal
        if literal_type is str and operator not in {"==", "!="}:
            return None
        if invert:
            operator = inverse_comparison[operator]
        return param, "compare", {"operator": operator, "literal": literal_text}

    pending: list[ast.AST] = list(target.body)
    guard_occurrences: dict[str, int] = {}
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(current, ast.If) and (contains_raise(current.body) or contains_raise(current.orelse)):
            raises_in_true = contains_raise(current.body)
            raises_in_false = contains_raise(current.orelse)
            raising_statements = current.body if raises_in_true and not raises_in_false else current.orelse
            inlined_helpers: tuple[tuple[str, ast.FunctionDef, ast.Return], ...] = ()
            guard = None
            if raises_in_true != raises_in_false:
                guard_assumptions.clear()
                expanded = inline_helper_calls(current.test)
                if expanded is not None and expanded[1]:
                    inlined_test, inlined_helpers = expanded
                    guard = classify(inlined_test, raises_in_true, raises_in_false)
                else:
                    guard = classify(current.test, raises_in_true, raises_in_false)
            exception_type = (
                _single_guard_exception(
                    raising_statements,
                    imports,
                    module_imports,
                    local_class_names,
                    module_name=module_name,
                    shadowed_names=shadowed_names,
                )
                if raises_in_true != raises_in_false
                else None
            )
            recognized = guard is not None and exception_type is not None
            if recognized and guard is not None:
                param, raises_when, extra_fields = guard
                condition_source = _ast_source_segment(source, current.test) or ast.dump(current.test)
                condition_sha256 = hashlib.sha256(condition_source.encode("utf-8")).hexdigest()
                node_source = _ast_source_segment(source, current) or ast.unparse(current)
                node_fingerprint = hashlib.sha256(
                    ast.dump(current, annotate_fields=True, include_attributes=False).encode("utf-8")
                ).hexdigest()
                occurrence = guard_occurrences.get(node_fingerprint, 0)
                guard_occurrences[node_fingerprint] = occurrence + 1
                node_id = (
                    f"{file_path}::{qualified_name}::{raises_when}_entry_guard::"
                    f"{node_fingerprint}:{occurrence}"
                )
                if inlined_helpers:
                    helper_names = [name for name, _helper, _return in inlined_helpers]
                    helper_name, _helper, helper_return = inlined_helpers[-1]
                    helper_source = (
                        _ast_source_segment(source, helper_return.value)
                        or ast.unparse(helper_return.value)
                    )
                    provenance = _provenance(
                        "entry_guard_helper_inlining",
                        "resolved",
                        file_path,
                        helper_return.lineno,
                        helper_source,
                    )
                    provenance["assumptions"] = sorted(guard_assumptions)
                    node_id += f"::inlined:{'->'.join(helper_names)}"
                else:
                    provenance = _provenance(
                        "entry_guard_extraction",
                        "resolved",
                        file_path,
                        current.lineno,
                        node_source,
                    )
                    provenance["assumptions"] = sorted(guard_assumptions)
                guards.append(
                    EntryGuard(
                        param=param,
                        raises_when=raises_when,
                        raised_exception=exception_type,
                        condition_source=condition_source,
                        condition_sha256=condition_sha256,
                        file_path=file_path,
                        line_number=current.lineno,
                        node_id=node_id,
                        provenance=provenance,
                        **extra_fields,
                    )
                )
            if not recognized:
                condition_source = _ast_source_segment(source, current.test) or ast.dump(current.test)
                condition_sha256 = hashlib.sha256(condition_source.encode("utf-8")).hexdigest()
                node_fingerprint = hashlib.sha256(
                    ast.dump(current, annotate_fields=True, include_attributes=False).encode("utf-8")
                ).hexdigest()
                occurrence = guard_occurrences.get(node_fingerprint, 0)
                guard_occurrences[node_fingerprint] = occurrence + 1
                node_id = (
                    f"{file_path}::{qualified_name}::unsupported_entry_guard::"
                    f"{node_fingerprint}:{occurrence}"
                )
                unresolved_provenance = _provenance(
                    "unresolved_construct_inventory",
                    "unresolved",
                    file_path,
                    current.lineno,
                    condition_source,
                )
                unresolved_provenance["assumptions"] = sorted(guard_assumptions)
                unresolved.append(UnresolvedConstruct(
                    file_path=file_path,
                    line_number=current.lineno,
                    kind="unsupported_entry_guard",
                    source=condition_source,
                    scope="modified_callable",
                    caller_qualified_name=qualified_name,
                    provenance=unresolved_provenance,
                    raised_exception=exception_type,
                    condition_source=condition_source,
                    condition_sha256=condition_sha256,
                    node_id=node_id,
                ))
        pending.extend(ast.iter_child_nodes(current))
    return _dedupe_guards(guards), unresolved


def _dedupe_guards(guards: list[EntryGuard]) -> list[EntryGuard]:
    seen: set[tuple[Any, ...]] = set()
    result: list[EntryGuard] = []
    for guard in guards:
        key = (
            guard.param,
            guard.raises_when,
            guard.literal,
            guard.raised_exception,
            guard.operator,
            guard.type_names,
            guard.negated,
        )
        if key not in seen:
            seen.add(key)
            result.append(guard)
    return result


def _call_effects(target: ast.FunctionDef | ast.AsyncFunctionDef | None, source: str) -> list[tuple[str, int, str]]:
    effects: list[tuple[str, int, str]] = []
    if target is None:
        return effects
    pending: list[ast.AST] = list(target.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(current, ast.Call):
            primitive = _effect_name(ast.unparse(current.func))
            if primitive:
                effects.append((primitive, current.lineno, _ast_source_segment(source, current) or ast.unparse(current)))
        pending.extend(ast.iter_child_nodes(current))
    return sorted(set(effects))


def _effect_name(name: str) -> str | None:
    compact = name.replace(" ", "")
    if compact.startswith("subprocess."):
        return compact
    if compact in {"os.system", "os.remove", "os.unlink", "os.exec", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe"}:
        return compact
    if compact.startswith("socket."):
        return compact
    if compact in {"shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copy2"}:
        return compact
    if compact in {"open", "Path.open", "Path.write_text", "Path.write_bytes", "Path.unlink", "Path.mkdir"}:
        return compact
    return None


def _effect_delta(
    modified: list[ModifiedCallable], before: dict[str, _ModuleIndex], after: dict[str, _ModuleIndex]
) -> list[SideEffectPrimitive]:
    old_functions = _function_code(before)
    new_functions = _function_code(after)
    result: list[SideEffectPrimitive] = []
    for change in modified:
        old = old_functions.get(change.qualified_name)
        new = new_functions.get(change.qualified_name)
        old_effect_lines = _primitive_lines(old.effects if old else ())
        new_effect_lines = _primitive_lines(new.effects if new else ())
        for primitive in sorted(new_effect_lines.keys() - old_effect_lines.keys()):
            line, source = new_effect_lines[primitive]
            result.append(SideEffectPrimitive(
                change.qualified_name, primitive, change.file_path, line, "added",
                _provenance("side_effect_primitive_delta", "resolved", change.file_path, line, source),
            ))
        for primitive in sorted(old_effect_lines.keys() - new_effect_lines.keys()):
            line, source = old_effect_lines[primitive]
            result.append(SideEffectPrimitive(
                change.qualified_name, primitive, change.file_path, line, "removed",
                _provenance("side_effect_primitive_delta", "resolved", change.file_path, line, source),
            ))
    return sorted(result, key=lambda item: (item.file_path, item.line_number, item.primitive, item.delta))


def _primitive_lines(effects: tuple[tuple[str, int, str], ...]) -> dict[str, tuple[int, str]]:
    """Collapse source locations to primitive identity; retain one display line."""
    result: dict[str, tuple[int, str]] = {}
    for primitive, line, source in effects:
        if primitive not in result or line < result[primitive][0]:
            result[primitive] = (line, source)
    return result


class _UnresolvedVisitor(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, module: cst.Module, file_path: str) -> None:
        self.module = module
        self.file_path = file_path
        self.items: list[UnresolvedConstruct] = []

    def _add(self, node: cst.CSTNode, kind: str, scope: str, source_node: cst.CSTNode | None = None) -> None:
        position = self.get_metadata(PositionProvider, node)
        source = self.module.code_for_node(source_node or node).strip()
        self.items.append(UnresolvedConstruct(self.file_path, position.start.line, kind, source, scope))

    def visit_Call(self, node: cst.Call) -> None:
        dotted = self.module.code_for_node(node.func).replace(" ", "")
        if dotted in {"eval", "exec"}:
            self._add(node, "dynamic_eval_exec", "repository")
        elif dotted == "getattr":
            literal = bool(node.args) and isinstance(node.args[1].value, cst.SimpleString) if len(node.args) > 1 else False
            if not literal:
                self._add(node, "dynamic_getattr", "repository")
        elif dotted in {"setattr", "builtins.setattr"}:
            literal = len(node.args) > 1 and isinstance(node.args[1].value, cst.SimpleString)
            if not literal:
                self._add(node, "dynamic_setattr", "repository")
        elif dotted.endswith("importlib.import_module") or dotted == "import_module":
            literal = bool(node.args) and isinstance(node.args[0].value, cst.SimpleString) if node.args else False
            if not literal:
                self._add(node, "dynamic_import_module", "repository")

    def visit_Subscript(self, node: cst.Subscript) -> None:
        if isinstance(node.value, cst.Attribute) and isinstance(node.value.value, cst.Name):
            if node.value.value.value == "sys" and node.value.attr.value == "modules":
                self._add(node, "dynamic_sys_modules", "repository")

    def visit_Attribute(self, node: cst.Attribute) -> None:
        if isinstance(node.value, cst.Name) and node.value.value == "sys" and node.attr.value == "_getframe":
            self._add(node, "frame_introspection", "repository")


def _unresolved_inventory(
    indexes: dict[str, _ModuleIndex],
    changed_paths: tuple[str, ...],
    *,
    side: str,
    root: Path | None = None,
    other_parsed_paths: set[str] | None = None,
) -> list[UnresolvedConstruct]:
    result: list[UnresolvedConstruct] = []
    parsed_paths = set(indexes)
    for path, index in indexes.items():
        result.extend(replace(item, side=side) for item in index.unresolved)
    for changed in changed_paths:
        if not changed.endswith(".py"):
            result.append(UnresolvedConstruct(changed, 1, "non_python_file_changed", changed, "changed_file", side=side))
        elif changed not in parsed_paths:
            if (
                side == "pre"
                and root is not None
                and other_parsed_paths is not None
                and changed in other_parsed_paths
            ):
                candidate = root / changed
                if not candidate.exists() and not candidate.is_symlink():
                    continue  # newly added valid Python file: absent in base, not an unparsed base file
            result.append(UnresolvedConstruct(changed, 1, "python_file_unparsed", changed, "changed_file", side=side))
    return result


def _dedupe_unresolved(items: list[UnresolvedConstruct]) -> list[UnresolvedConstruct]:
    unique: dict[tuple[Any, ...], UnresolvedConstruct] = {}
    for item in items:
        key = (
            item.file_path,
            item.line_number,
            item.kind,
            item.source,
            item.scope,
            item.caller_qualified_name,
            item.target_qualified_name,
            item.raised_exception,
            item.condition_sha256,
            item.node_id,
        )
        existing = unique.get(key)
        if existing is None:
            unique[key] = item
        elif existing.side != item.side:
            unique[key] = replace(existing, side="both")
    return [unique[key] for key in sorted(unique)]
