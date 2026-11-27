#!/usr/bin/env python3
"""Fail closed if the dedicated standards test directory is missing or collects zero tests."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


def check(root: Path) -> tuple[list[str], int]:
    test_dir = root / "tests" / "standards"
    if not test_dir.is_dir():
        return ["required path missing: tests/standards"], 0
    files = sorted(test_dir.glob("test_*.py"))
    if not files:
        return ["tests/standards contains no test_*.py files"], 0
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q", *[str(p) for p in files]]
    try:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
    except OSError as exc:
        return [f"cannot run pytest collection: {exc}"], 0
    output = result.stdout + result.stderr
    if result.returncode != 0:
        if result.returncode == 5:
            return ["pytest collected zero standards tests"], 0
        return [f"pytest collection failed with exit {result.returncode}: {output.strip()[-1200:]}"], 0
    match = re.search(r"(\d+) tests? collected", output)
    collected = int(match.group(1)) if match else 0
    if collected == 0:
        return ["pytest collected zero standards tests"], 0
    return [], collected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Hlith repository root")
    args = parser.parse_args(argv)
    errors, collected = check(args.root.resolve())
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK: pytest collected {collected} standards tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
