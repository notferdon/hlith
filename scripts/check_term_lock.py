#!/usr/bin/env python3
"""Lock the Hlith namespace and its four public decision values."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path


VERDICTS = ["held", "refuted", "not-derived", "unverified"]
FOREIGN_TERMS = {"opa", "rego", "cedar", "semgrep"}


def _line_of(path: Path, class_name: str) -> int | None:
    try:
        return next((n.lineno for n in ast.parse(path.read_text(encoding="utf-8")).body
                     if isinstance(n, ast.ClassDef) and n.name == class_name), None)
    except (OSError, SyntaxError):
        return None


def check(root: Path) -> list[str]:
    errors: list[str] = []
    source = root / "src" / "hlith"
    if not source.is_dir():
        return ["required path missing: src/hlith"]
    for path in sorted(source.rglob("*.py")):
        module_name = path.relative_to(source).as_posix().lower()
        if any(re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", module_name) for term in FOREIGN_TERMS):
            errors.append(f"foreign product or scanner name in module path: {path.relative_to(root)}")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            errors.append(f"cannot parse {path.relative_to(root)}: {exc}")
            continue
        for node in ast.walk(tree):
            identifiers: list[str] = []
            if isinstance(node, ast.Name):
                identifiers.append(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identifiers.append(node.name)
            elif isinstance(node, ast.alias):
                identifiers.extend([node.name, node.asname or ""])
            elif isinstance(node, ast.Attribute):
                identifiers.append(node.attr)
            for identifier in identifiers:
                if identifier.lower() in FOREIGN_TERMS:
                    errors.append(f"foreign term {identifier!r} in {path.relative_to(root)}:{getattr(node, 'lineno', 1)}")

    for rel in ("README.md", "src/hlith/cli.py", "src/hlith/tui/__main__.py", "src/hlith/operator/tui/__main__.py"):
        path = root / rel
        if not path.is_file():
            errors.append(f"required term-lock surface missing: {rel}")
            continue
        if path.suffix == ".py":
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                surfaces = [node.value for node in ast.walk(tree)
                            if isinstance(node, ast.Constant) and isinstance(node.value, str)]
            except (OSError, SyntaxError) as exc:
                errors.append(f"cannot parse term-lock surface {rel}: {exc}")
                continue
        else:
            surfaces = [path.read_text(encoding="utf-8")]
        for surface in surfaces:
            for term in FOREIGN_TERMS:
                if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", surface, re.IGNORECASE):
                    errors.append(f"foreign product/scanner term {term!r} in {rel}")

    # ONE verdict vocabulary: the closed enums are defined exactly once (src/hlith/types.py); every other module re-exports them
    for enum_name in ("Verdict", "GateOutcome"):
        defs = []
        for path in sorted(source.rglob("*.py")):
            try:
                body = ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body
            except (OSError, SyntaxError):
                continue  # already reported above
            defs += [f"{path.relative_to(root)}:{n.lineno}" for n in body if isinstance(n, ast.ClassDef) and n.name == enum_name]
        if defs != [f"src/hlith/types.py:{_line_of(source / 'types.py', enum_name)}"]:
            errors.append(f"class {enum_name} must be defined exactly once, in src/hlith/types.py; found {defs!r}")

    types_path = source / "types.py"
    if types_path.is_file():
        try:
            tree = ast.parse(types_path.read_text(encoding="utf-8"), filename=str(types_path))
            verdict = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Verdict"), None)
            values = []
            if verdict:
                for node in verdict.body:
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            values.append(node.value.value)
            if values != VERDICTS:
                errors.append(f"Verdict values must be exactly {VERDICTS!r}, got {values!r}")
        except (OSError, SyntaxError) as exc:
            errors.append(f"cannot inspect src/hlith/types.py: {exc}")
    else:
        errors.append("required path missing: src/hlith/types.py")

    schema_path = source / "hlith.schema.json"
    if schema_path.is_file():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            serialized = json.dumps(schema, sort_keys=True).lower()
            for term in FOREIGN_TERMS:
                if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", serialized):
                    errors.append(f"foreign term {term!r} in src/hlith/hlith.schema.json")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot parse src/hlith/hlith.schema.json: {exc}")
    else:
        errors.append("required path missing: src/hlith/hlith.schema.json")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Hlith repository root")
    args = parser.parse_args(argv)
    errors = check(args.root.resolve())
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("OK: Hlith namespace and schema contain no foreign product/scanner identifiers; Verdict is closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
