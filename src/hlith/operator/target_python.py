# SPDX-License-Identifier: Apache-2.0
"""The interpreter a CONFINED differential worker reported about itself during this process's run, shaped for the run artifact (R3 target-python provenance).

Informational only (decide() never reads it). Never inferred from the requested ``--target-python`` and never probed on the host: it is the worker's own
``sys.version_info`` / ``sys.implementation.name`` / ``sys.executable`` as seen INSIDE the confinement. None when no confined evaluator started.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from ..hostio.confinement import GrantError, Profile, run_confined
from ..hostio.interpreter import interpreter_prefixes

REFERENCE_VERSION = "3.13.9"


def repository_python(root) -> str | None:
    """The interpreter that can import the repository's dependencies: its own virtualenv if it has one (`.venv/bin/python`,
    `venv/bin/python`), else None (the engine then uses its own interpreter, enough for pure-Python code). Shown in the
    confirm screen as part of the exact command."""
    for d in (".venv", "venv"):
        vdir = (Path(root) / d)
        p = vdir.resolve() / "bin" / "python"  # a symlinked venv directory is resolved (the engine's confinement cannot start an interpreter reached through it)
        if p.is_file():
            return str(p)
    return None


def select_interpreter(repo: Path, requested: str | None) -> tuple[str, str, str | None]:
    """Return selected path, its origin, and the optional argument passed to the existing engine."""
    if requested:
        path = str(Path(requested).expanduser().absolute())
        return path, "explicit --target-python", path

    target = repository_python(repo)
    if target:
        for virtualenv in (".venv", "venv"):
            expected = str((repo / virtualenv).resolve() / "bin" / "python")
            if target == expected:
                return target, f"repository {virtualenv}/bin/python", target
        return target, "repository virtualenv", target

    return sys.executable, "Hlith default interpreter", None


def qualification(version: str | None) -> str:
    if version == REFERENCE_VERSION:
        return f"matches reference version {REFERENCE_VERSION}"
    if version in (None, "", "not recorded"):
        return f"target version unobserved (reference {REFERENCE_VERSION})"
    return f"outside the {REFERENCE_VERSION} qualification"


_PROBE = """import importlib, json, sys
results = {}
for name in sys.argv[1:]:
    try:
        importlib.import_module(name)
        results[name] = "ok"
    except Exception as exc:
        results[name] = type(exc).__name__
print(json.dumps([list(sys.version_info[:3]), results]))
"""


def probe_interpreter(path: str, modules: list[str]) -> tuple[bool, dict]:
    """Observe startup and named imports under the same confinement as target evaluation."""
    names = list(dict.fromkeys(["pytest", *modules]))
    if len(names) > 32 or any(len(n) > 128 or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", n) for n in names):
        return False, {"error": "expected up to 32 dotted Python module names"}
    try:
        roots = interpreter_prefixes(path)
        exe = path if any(Path(path).is_relative_to(root) for root in roots) else str(Path(path).resolve())
        cp = run_confined([exe, "-I", "-B", "-c", _PROBE, *names], Profile(ro=tuple(roots)), cwd="/", timeout=15)
        bf = getattr(cp, "boundary_failure", None)
        if bf is not None:
            return False, {
                "error": f"confined startup failed ({bf.code}): {bf.detail}",
                "boundary_code": bf.code,
                "boundary_stage": bf.stage,
            }
        if cp.returncode:
            return False, {"error": f"confined startup failed (exit {cp.returncode})"}
        version, results = json.loads(cp.stdout.strip().splitlines()[-1])
        if not (type(version) is list and len(version) == 3 and all(type(i) is int and 0 <= i < 1000 for i in version)
                and isinstance(results, dict) and set(results) == set(names)
                and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z_]\w{0,80}", v) for v in results.values())):
            raise ValueError("invalid interpreter response")
    except (GrantError, OSError, ValueError, IndexError, TypeError, subprocess.TimeoutExpired) as exc:
        return False, {"error": f"could not observe target Python: {type(exc).__name__}"}
    label = ".".join(map(str, version))
    return all(v == "ok" for v in results.values()), {"version": label, "qualification": qualification(label), "imports": results}


def observed_target_python() -> dict | None:
    from .. import differential

    for entry in reversed(differential.observed_interpreters()):
        for side in ("post", "pre"):
            s = entry.get(side)
            v = s.get("version") if isinstance(s, dict) else None
            if isinstance(v, (list, tuple)) and len(v) == 3 and all(isinstance(n, int) for n in v) and isinstance(s.get("executable"), str) and s["executable"]:
                return {"executable": s["executable"], "version": ".".join(str(n) for n in v),
                        "implementation": str(s.get("implementation") or "unknown"), "observed_in": "confined-differential-worker"}
    return None
