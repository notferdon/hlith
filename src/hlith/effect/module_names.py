# SPDX-License-Identifier: Apache-2.0
"""Canonical importable module names for repository-relative Python paths."""

from __future__ import annotations

from pathlib import PurePosixPath


def module_name_for_path(relative_path: str) -> str:
    """Return the module name used for a Python file under a repository root.

    A leading ``src`` or ``lib`` is an import-root directory only when another
    component follows it. A root-level ``src.py`` or ``lib.py`` is itself an
    importable module and keeps its name.
    """
    parts = list(PurePosixPath(relative_path).with_suffix("").parts)
    if len(parts) > 1 and parts[0] in {"src", "lib"}:
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__main__"


__all__ = ["module_name_for_path"]
