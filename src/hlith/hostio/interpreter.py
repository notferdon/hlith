# SPDX-License-Identifier: Apache-2.0
"""Locate CPython installations without executing the selected interpreter on the host."""

from __future__ import annotations

import filecmp
import os
import re
import sys
from pathlib import Path


def _has_stdlib(prefix: Path) -> bool:
    for libdir in ("lib", "lib64"):
        base = prefix / libdir
        if base.is_dir() and any(p.is_file() for p in base.glob("python3.*/os.py")):
            return True
    return False


def interpreter_prefixes(python: str) -> list[str]:
    """Only the selected venv and the installation containing its actual CPython binary.

    No paths are taken from target process output or pyvenv.cfg contents. A standalone
    alias does not grant its parent directory. Unknown layouts fail before execution.
    """
    selected = Path(os.path.abspath(python))
    binary = selected.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("target Python is not an executable file")
    if selected == Path(os.path.abspath(sys.executable)):
        return sorted({sys.prefix, sys.base_prefix})
    prefix = binary.parent.parent
    if binary.parent.name != "bin" or not re.fullmatch(r"python(?:3(?:\.\d+)?t?)?", binary.name):
        raise ValueError("target Python must resolve to a CPython installation binary under bin/")
    roots: set[str] = set()
    venv = selected.parent.parent
    cfg = venv / "pyvenv.cfg"
    if selected.parent.name == "bin" and cfg.is_file() and not cfg.is_symlink():
        venv_real = venv.resolve(strict=True)
        if venv_real == Path("/") or venv_real == Path.home():
            raise ValueError("target Python virtualenv resolves to an unsafe directory")
        roots.add(str(venv_real))
    if prefix == Path("/") or prefix == Path.home() or not _has_stdlib(prefix):
        # CPython venvs created with --copies can use our verified base install.
        if not roots or not filecmp.cmp(binary, sys._base_executable, shallow=False):
            raise ValueError("target Python installation layout is unknown; select a venv linked to its base Python")
        prefix = Path(sys.base_prefix)
    roots.add(str(prefix))
    return sorted(roots)
