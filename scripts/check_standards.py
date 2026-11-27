#!/usr/bin/env python3
"""Check Hlith's repository shape and workflow pinning standards."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


def check(root: Path) -> list[str]:
    errors: list[str] = []
    required = (
        "pyproject.toml",
        "uv.lock",
        "src/hlith",
        "tests",
        "tests/standards",
        "scripts/verify_kill_lines.sh",
        "scripts/check_standards.py",
        "scripts/check_term_lock.py",
        "scripts/check_layer_dag.py",
        "scripts/check_no_vacuous.py",
        "scripts/check_import_names.py",
        "scripts/layer_map.json",
        ".github/workflows",
    )
    for rel in required:
        if not (root / rel).exists():
            errors.append(f"required path missing: {rel}")

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
            version = project.get("version")
            if project.get("name") != "hlith":
                errors.append("pyproject project.name must be 'hlith'")
            if not isinstance(version, str) or not re.fullmatch(r"0\.\d+\.\d+", version):
                errors.append(f"project.version must stay 0.y.z, got {version!r}")
            if not str(project.get("requires-python", "")).startswith(">=3.12"):
                errors.append("project.requires-python must continue to require Python 3.12 or newer")
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"cannot parse pyproject.toml: {exc}")

    source = root / "src"
    tests = root / "tests"
    if source.is_dir() and tests.is_dir():
        misplaced = sorted(
            p.relative_to(root).as_posix()
            for p in source.rglob("*.py")
            if p.name.startswith("test_") or p.name.endswith("_test.py")
        )
        if misplaced:
            errors.append("test modules belong outside src/: " + ", ".join(misplaced))

    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_dir():
        workflows = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
        if not workflows:
            errors.append(".github/workflows must contain at least one workflow")
        for workflow in workflows:
            for lineno, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
                match = re.match(r"^\s*uses\s*:\s*([^\s#]+)", line)
                if not match:
                    continue
                ref = match.group(1)
                action, sep, pin = ref.rpartition("@")
                if not sep or not action or not re.fullmatch(r"[0-9a-fA-F]{40}", pin):
                    errors.append(f"{workflow.relative_to(root)}:{lineno}: action must use a full 40-character commit SHA: {ref}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Hlith repository root")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    errors = check(root)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("OK: Hlith repo shape, 0.y.z version, source/test separation, required checks, and full-SHA workflow actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
