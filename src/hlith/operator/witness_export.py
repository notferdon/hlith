# SPDX-License-Identifier: Apache-2.0
"""Export ONE simple recorded witness as a dependency-free static pytest regression test.

The input is the versioned witness record (``contract/witness.py``), which decides what is exportable.

The caller must say which recorded side is the intended contract: `pre` for a regression guard (the change must not alter
existing behavior) or `post` for an accepted intended change. Only plain importable calls are exported: no receiver, recorded
environment, injected exception, truncation, evaluator argument marker, non-scalar return, or normalized placeholder value.
The generated test uses a direct static ``from <module> import <name>`` and direct literal call (no ``importlib``, no
computed ``getattr``, no ``hlith`` import) with scoped ``sys.path`` restoration so it can be committed cleanly in the target
repository without polluting subsequent tests. This is a selected-behavior guard for one call, not a certificate.
"""
from __future__ import annotations

import ast
import json
import keyword
import math
import os
import tempfile
from pathlib import Path
from typing import Any

from ..contract.witness import NotExportable, exportable

_MAX_LITERAL_DEPTH = 32
_USED_BUILTINS = frozenset({"BaseException", "ValueError", "repr", "str", "type"})


def _validate_dotted_name(name: Any, label: str) -> list[str]:
    if not isinstance(name, str) or not name:
        raise NotExportable(f"witness has no importable {label}")
    parts = name.split(".")
    if any(not part.isidentifier() or keyword.iskeyword(part) for part in parts):
        raise NotExportable(f"witness has no importable {label}")
    if any(part.startswith("__") and part.endswith("__") for part in parts):
        raise NotExportable(f"witness {label} shape is not a plain user callable; not portable")
    return parts


def _validate_import_root(import_root: Any) -> list[str]:
    if import_root is None or import_root == "":
        return []
    if not isinstance(import_root, str):
        raise NotExportable("witness import_root is malformed")
    if any(ch in import_root for ch in ("\x00", "\n", "\r", "\\")) or any(ord(ch) < 32 for ch in import_root):
        raise NotExportable("witness import_root contains disallowed characters")
    if import_root.startswith("/") or import_root.endswith("/"):
        raise NotExportable("witness import_root must be a clean relative path")
    parts = import_root.split("/")
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        raise NotExportable("witness import_root must be a clean relative path without traversal")
    return parts


def _validate_provenance_id(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise NotExportable(f"witness provenance {label} is malformed")
    if any(ch in value for ch in ("/", "\\", "\x00", "\n", "\r")) or any(ord(ch) < 32 for ch in value):
        raise NotExportable(f"witness provenance {label} contains disallowed path or control characters")
    return value


def _literal_matches(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is float:
        return actual == expected and math.copysign(1.0, actual) == math.copysign(1.0, expected)
    if type(expected) in (list, tuple):
        return len(actual) == len(expected) and all(_literal_matches(a, b) for a, b in zip(actual, expected))
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(_literal_matches(actual[k], expected[k]) for k in expected)
    return actual == expected


def _render_literal(value: Any, *, depth: int = 0) -> str:
    if depth > _MAX_LITERAL_DEPTH:
        raise NotExportable("witness arguments exceed maximum nesting depth; not portable")
    kind = type(value)
    if value is None:
        rendered = "None"
    elif kind is bool:
        rendered = "True" if value else "False"
    elif kind is int:
        rendered = repr(value)
    elif kind is float:
        if not math.isfinite(value):
            raise NotExportable("witness arguments contain a non-finite float; not portable")
        rendered = repr(value)
    elif kind is str:
        rendered = repr(value)
    elif kind is list:
        rendered = "[" + ", ".join(_render_literal(item, depth=depth + 1) for item in value) + "]"
    elif kind is tuple:
        if not value:
            rendered = "()"
        elif len(value) == 1:
            rendered = "(" + _render_literal(value[0], depth=depth + 1) + ",)"
        else:
            rendered = "(" + ", ".join(_render_literal(item, depth=depth + 1) for item in value) + ")"
    elif kind is dict:
        items = []
        for k, v in sorted(value.items(), key=lambda pair: pair[0] if type(pair[0]) is str else ""):
            if type(k) is not str:
                raise NotExportable("witness arguments contain non-string dict keys; not portable")
            items.append(f"{repr(k)}: {_render_literal(v, depth=depth + 1)}")
        rendered = "{" + ", ".join(items) + "}"
    else:
        raise NotExportable("witness arguments are not plain data; not portable")
    if depth == 0:
        try:
            parsed = ast.literal_eval(rendered)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            raise NotExportable("witness arguments could not be rendered as a safe Python literal") from None
        if not _literal_matches(parsed, value):
            raise NotExportable("witness arguments could not round-trip as an exact Python literal")
    return rendered


def _render_call(qualname: str, args: list[Any], kwargs: dict[str, Any]) -> str:
    parts = [_render_literal(arg) for arg in args]
    extra_kwargs: dict[str, Any] = {}
    for k in sorted(kwargs):
        if type(k) is not str:
            raise NotExportable("witness keyword argument names must be strings")
        v = kwargs[k]
        if k.isidentifier() and not keyword.iskeyword(k):
            parts.append(f"{k}={_render_literal(v)}")
        else:
            extra_kwargs[k] = v
    if extra_kwargs:
        parts.append("**" + _render_literal(extra_kwargs))
    return f"{qualname}(" + ", ".join(parts) + ")"


def _verify_generated_source(source: str, expect: str, module: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        raise NotExportable("generated pytest witness failed syntax verification") from None
    expected_fn = f"test_recorded_{expect}_behavior"
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != expected_fn:
        raise NotExportable("generated pytest witness did not match expected static test structure")
    has_target_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in ("hlith", "importlib", "json"):
                    raise NotExportable(f"generated pytest witness imported disallowed module {top!r}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            top = mod.split(".")[0]
            if top in ("hlith", "importlib", "json"):
                raise NotExportable(f"generated pytest witness imported disallowed module {top!r}")
            if mod == module:
                has_target_import = True
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                raise NotExportable("generated pytest witness must not use getattr")
            if isinstance(node.func, ast.Attribute) and node.func.attr == "getattr":
                raise NotExportable("generated pytest witness must not use getattr")
    if not has_target_import:
        raise NotExportable("generated pytest witness is missing static target import")


def build_pytest_source(record: dict, *, import_root: str = "", extra_sys_path: list[str] | None = None,
                        base_commit: str | None = None, post_tree: str | None = None,
                        expect: str = "post") -> str:
    call = exportable(record, expect, extra_sys_path)
    module = call["module"]
    qualname = call["qualname"]
    _validate_dotted_name(module, "module")
    qual_parts = _validate_dotted_name(qualname, "qualname")
    if module == "hlith" or module.startswith("hlith."):
        raise NotExportable("witness targets hlith internals; exported tests must not depend on Hlith")
    if module == "builtins":
        raise NotExportable("witness callable shape is not a plain user callable; not portable")
    import_root_parts = _validate_import_root(import_root)
    clean_import_root = "/".join(import_root_parts)
    clean_base_commit = _validate_provenance_id(base_commit, "base_commit")
    clean_post_tree = _validate_provenance_id(post_tree, "post_tree")

    expected = call[expect]
    kind = expected.get("k")
    if kind not in ("ret", "exc"):
        raise NotExportable("witness expected outcome is malformed")
    if kind == "ret":
        want_repr = expected.get("r")
        if not isinstance(want_repr, str):
            raise NotExportable("witness expected return repr is missing")
    else:
        want_type = expected.get("t")
        want_msg = expected.get("mi") if expected.get("mi") is not None else expected.get("m")
        if not isinstance(want_type, str) or not want_type or not isinstance(want_msg, str):
            raise NotExportable("witness expected exception type or message is missing")
    check_out = "out" in expected
    want_out = expected.get("out") or "" if check_out else None
    if check_out and not isinstance(want_out, str):
        raise NotExportable("witness expected printed output is malformed")

    root_name = qual_parts[0]
    p = "_hlith_"
    while root_name.startswith(p):
        p += "_"

    need_builtins = root_name in _USED_BUILTINS
    b_repr = f"{p}builtins.repr" if need_builtins else "repr"
    b_type = f"{p}builtins.type" if need_builtins else "type"
    b_str = f"{p}builtins.str" if need_builtins else "str"
    b_base_exc = f"{p}builtins.BaseException" if need_builtins else "BaseException"
    b_val_err = f"{p}builtins.ValueError" if need_builtins else "ValueError"

    call_expr = _render_call(qualname, call["args"], call["kwargs"])
    if import_root_parts:
        joined_parts = ", ".join(repr(part) for part in import_root_parts)
        path_expr = f"{p}os.path.join({p}root, {joined_parts})"
    else:
        path_expr = f"{p}root"

    provenance = {
        "base_commit": clean_base_commit,
        "expect": expect,
        "import_root": clean_import_root,
        "module": module,
        "post": call["post"],
        "post_tree": clean_post_tree,
        "pre": call["pre"],
        "qualname": qualname,
    }
    try:
        provenance_json = json.dumps(provenance, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        raise NotExportable("witness provenance is not plain data; not portable") from None

    lines = [
        f"# Generated by `hlith replay --pytest-out --expect {expect}`. ONE recorded call: a selected-behavior guard, not a certificate.",
        f"# Expected contract: {expect}. Run from a checkout of that revision (use a fresh pytest process when switching HLITH_WITNESS_ROOT):",
        "#   HLITH_WITNESS_ROOT=/path/to/repo pytest test_hlith_witness.py",
        "# This test fails on the other recorded revision and passes only when the selected outcome is reproduced.",
        "",
        "",
        f"def test_recorded_{expect}_behavior():",
    ]
    if need_builtins:
        lines.append(f"    import builtins as {p}builtins")
    if check_out:
        lines.append(f"    import contextlib as {p}contextlib")
        lines.append(f"    import io as {p}io")
    lines.extend([
        f"    import os as {p}os",
        f"    import sys as {p}sys",
        "",
        f"    {p}env_root = {p}os.environ.get('HLITH_WITNESS_ROOT')",
        f"    {p}root = {p}env_root or {p}os.getcwd()",
        f"    {p}path = {path_expr}",
        f"    {p}added_path = False",
        f"    if {p}env_root:",
        f"        if {p}sys.path[:1] != [{p}path]:",
        f"            {p}sys.path.insert(0, {p}path)",
        f"            {p}added_path = True",
        f"    elif {p}path not in {p}sys.path and {p}os.path.isdir({p}path):",
        f"        {p}sys.path.insert(0, {p}path)",
        f"        {p}added_path = True",
        "    try:",
        f"        from {module} import {root_name}",
        "",
    ])
    if check_out:
        lines.extend([
            f"        {p}out = {p}io.StringIO()",
            "        try:",
            f"            with {p}contextlib.redirect_stdout({p}out):",
            f"                {p}value = {call_expr}",
            f"            {p}got = ('ret', {b_repr}({p}value))",
            f"        except {b_base_exc} as {p}exc:  # the recorded outcome can be a builtin or repo exception",
            f"            {p}got = ('exc', {b_type}({p}exc).__module__ + '.' + {b_type}({p}exc).__qualname__, {b_str}({p}exc))",
        ])
    else:
        lines.extend([
            "        try:",
            f"            {p}value = {call_expr}",
            f"            {p}got = ('ret', {b_repr}({p}value))",
            f"        except {b_base_exc} as {p}exc:  # the recorded outcome can be a builtin or repo exception",
            f"            {p}got = ('exc', {b_type}({p}exc).__module__ + '.' + {b_type}({p}exc).__qualname__, {b_str}({p}exc))",
        ])

    if kind == "ret":
        msg_kind = repr(f"expected {expect} returned {want_repr!r}, got ")
        msg_val = repr(f"expected {expect} return {want_repr!r}, got ")
        lines.extend([
            f"        assert {p}got[0] == 'ret', {msg_kind} + {b_repr}({p}got)",
            f"        assert {p}got[1] == {repr(want_repr)}, {msg_val} + {b_repr}({p}got[1])",
        ])
    else:
        msg_kind = repr(f"expected {expect} raised {want_type!r}, got ")
        msg_type = repr(f"expected {expect} exception {want_type!r}, got ")
        msg_text = repr(f"expected {expect} message {want_msg!r}, got ")
        lines.extend([
            f"        assert {p}got[0] == 'exc', {msg_kind} + {b_repr}({p}got)",
            f"        assert {p}got[1] == {repr(want_type)}, {msg_type} + {b_repr}({p}got[1])",
            f"        assert {p}got[2] == {repr(want_msg)}, {msg_text} + {b_repr}({p}got[2])",
        ])
    if check_out:
        msg_out = repr(f"expected {expect} printed output differs")
        lines.append(f"        assert {p}out.getvalue() == {repr(want_out)}, {msg_out}")

    lines.extend([
        "    finally:",
        f"        if {p}added_path:",
        "            try:",
        f"                {p}sys.path.remove({p}path)",
        f"            except {b_val_err}:",
        "                pass",
        "",
        "",
        f"# Provenance: {provenance_json}",
        "",
    ])
    source = "\n".join(lines)
    _verify_generated_source(source, expect, module)
    return source


def write_pytest(path: Path, record: dict, *, import_root: str = "", extra_sys_path: list[str] | None = None,
                 base_commit: str | None = None, post_tree: str | None = None, expect: str = "post") -> Path:
    """Write the test, or raise NotExportable leaving no file, no new directory and any existing file untouched."""
    path = Path(path).expanduser()
    if path.is_symlink():
        raise NotExportable(f"refusing symlink pytest output: {path}")
    source = build_pytest_source(record, import_root=import_root, extra_sys_path=extra_sys_path,
                                 base_commit=base_commit, post_tree=post_tree, expect=expect)
    created: list[Path] = []
    temp: str | None = None
    try:
        parent = path.parent
        while not parent.exists():
            created.append(parent)
            parent = parent.parent
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not path.is_file():
            raise NotExportable(f"pytest output is not a regular file: {path}")
        handle, temp = tempfile.mkstemp(prefix=".hlith-witness-", suffix=".tmp", dir=path.parent)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(source)
        mask = os.umask(0)
        os.umask(mask)
        os.chmod(temp, 0o666 & ~mask)  # mkstemp creates 0600; give the usual mode of a new file
        os.replace(temp, path)
        temp = None
    except (OSError, UnicodeError, NotExportable) as exc:
        if temp is not None:
            Path(temp).unlink(missing_ok=True)
        for directory in created:
            try:
                directory.rmdir()
            except OSError:
                pass
        if isinstance(exc, NotExportable):
            raise
        raise NotExportable(f"cannot write pytest output: {getattr(exc, 'strerror', None) or type(exc).__name__}") from None
    return path
