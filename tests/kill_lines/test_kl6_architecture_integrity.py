"""KL6: Zero scanner, policy engine, dashboard, or LLM/model imports in L2/L3/L4."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_DEPS = ("opa", "rego", "cedar", "semgrep", "fastapi", "flask", "django", "openai", "anthropic")
FORBIDDEN_L234 = FORBIDDEN_DEPS + ("langchain", "langgraph")


def test_kl6_no_forbidden_deps_or_l234_imports() -> None:
    pyproj = (ROOT / "pyproject.toml").read_text().lower()
    hits = [d for d in FORBIDDEN_DEPS if d in pyproj]
    assert not hits, f"forbidden dependencies in pyproject.toml: {hits}"

    targets = [
        *(ROOT / "src/hlith/effect").rglob("*.py"),
        *(ROOT / "src/hlith/obligation").rglob("*.py"),
        *(ROOT / "src/hlith/gate").rglob("*.py"),
        ROOT / "src/hlith/derive.py",
        ROOT / "src/hlith/z3_binding.py",
        ROOT / "src/hlith/differential.py",
    ]
    assert targets, "no L2/L3/L4 target files found"
    for path in sorted(set(targets)):
        rel = path.relative_to(ROOT / "src/hlith")
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
            )
            for name in names:
                assert not any(name.startswith(f) for f in FORBIDDEN_L234), f"forbidden import {name!r} in {rel}"
