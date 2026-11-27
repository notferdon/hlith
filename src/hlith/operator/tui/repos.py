# SPDX-License-Identifier: Apache-2.0
"""Which repository, its state, and the repositories this operator has opened before (`<state>/repos.json`, UI-owned file)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..target_python import repository_python as target_python
from . import gitq, history, launch


@dataclass
class RepoInfo:
    root: Path
    head: str = ""
    head_tree: str = ""
    subject: str = ""
    branch: str = ""
    modified: int = 0
    untracked: int = 0
    last: dict | None = None  # the newest finished UI run for this repo
    notes: list[str] = field(default_factory=list)


def known(state=None) -> list[Path]:
    p = (Path(state) if state else history.state_dir()) / "repos.json"
    try:
        v = json.loads(p.read_text())
        return [Path(x) for x in v if isinstance(x, str)]
    except (OSError, ValueError, TypeError):
        return []


def remember(root, state=None, keep: int = 12) -> None:
    base = Path(state) if state else history.state_dir()
    items = [str(root)] + [str(x) for x in known(state) if str(x) != str(root)]
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        (base / "repos.json").write_text(json.dumps(items[:keep]))
    except OSError:
        pass  # a convenience list: never a reason to fail


def pref(key: str, state=None, default=None):
    """A UI preference (`<state>/prefs.json`, UI-owned): e.g. whether the first-run steps were skipped. Unreadable -> default."""
    try:
        v = json.loads(((Path(state) if state else history.state_dir()) / "prefs.json").read_text())
        return v.get(key, default) if isinstance(v, dict) else default
    except (OSError, ValueError):
        return default


def set_pref(key: str, value, state=None) -> None:
    base = Path(state) if state else history.state_dir()
    try:
        cur = {}
        try:
            cur = json.loads((base / "prefs.json").read_text())
        except (OSError, ValueError):
            pass
        cur = cur if isinstance(cur, dict) else {}
        cur[key] = value
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        (base / "prefs.json").write_text(json.dumps(cur))
    except OSError:
        pass  # a convenience: never a reason to fail


def info(root, state=None) -> RepoInfo:
    r = RepoInfo(Path(root))
    why = gitq.refusal(root)
    if why:  # nothing is asked of a repository the screen refuses to inspect, not even its HEAD
        r.notes.append(why)
        r.last = None
        return r
    if (Path(root) / ".gitmodules").is_file():
        r.notes.append("this repository has submodules: changes inside a submodule are not shown or checked here (a submodule's own settings could run programs, so the screen never looks inside)")
    level, text = python_readiness(root)
    if level == "warn":
        r.notes.append(text)
    try:
        gitq.require_supported_git()
        head_oid = gitq.optional_text(root, "rev-parse", "--verify", "-q", "HEAD^{commit}")
        if head_oid is None:
            r.branch = gitq.optional_text(root, "symbolic-ref", "-q", "--short", "HEAD") or ""
            r.notes.append("this repository has no commits yet: there is nothing to check a change against")
        else:
            r.head = gitq.read_text(root, "rev-parse", "--short", "HEAD")
            r.head_tree = gitq.read_text(root, "rev-parse", "--verify", "-q", "HEAD^{tree}")
            r.subject = gitq.read_text(root, "log", "-1", "--format=%s")
            r.branch = gitq.read_text(root, "rev-parse", "--abbrev-ref", "HEAD")
        st = gitq.read(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal").decode("utf-8", "replace").split("\0")
    except gitq.GitReadError as exc:
        r.notes.append(str(exc))
        r.last = None
        return r
    for e in st:
        if e.startswith("??"):
            r.untracked += 1
        elif len(e) > 2 and e[2] == " ":
            r.modified += 1
    fin = [x for x in launch.runs_for(root, state) if x["state"] == "finished"]
    r.last = fin[0] if fin else None
    return r


def declared_dependencies(root) -> list[str]:
    """Static read-only list of top-level dependency names declared in pyproject.toml (never executes target code)."""
    import re

    root = Path(root)
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        return []
    try:
        import tomllib

        doc = tomllib.loads(pyproject.read_text("utf-8"))
        proj = doc.get("project") or {}
        raw = list(proj.get("dependencies") or [])
    except (OSError, ValueError, AttributeError, TypeError):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            continue
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", item)
        if not match:
            continue
        name = match.group(1)
        key = name.lower().replace("-", "_")
        if key not in seen:
            seen.add(key)
            out.append(name)
        if len(out) >= 16:
            break
    return out


def python_readiness(root) -> tuple[str, str]:
    """('ok'|'warn', text): can the engine run this repository's own code? Without a virtualenv in the repository the engine uses its own
    interpreter, which only suffices for code with no third-party imports. Static check (nothing is executed): told to the user BEFORE a run."""
    root = Path(root)
    py = target_python(root)
    if py:
        return "ok", f"target python: {py}"
    declared = False
    try:
        import tomllib

        doc = tomllib.loads((root / "pyproject.toml").read_text("utf-8")) if (root / "pyproject.toml").is_file() else {}
        proj = doc.get("project") or {}
        declared = bool(proj.get("dependencies")) or any(proj.get("optional-dependencies", {}).values()) or bool((doc.get("tool") or {}).get("poetry", {}).get("dependencies", {}).keys() - {"python"})
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    if not declared:
        declared = any(root.glob("requirements*.txt")) or (root / "setup.py").is_file() or (root / "setup.cfg").is_file() or (root / "Pipfile").is_file()
    if declared:
        return "warn", ("no .venv/ or venv/ here, but the repository declares dependencies: hlith would run your code with its OWN interpreter, "
                        "so anything that imports those packages cannot be checked (the run ends UNVERIFIED). Create one "
                        "(python -m venv .venv && .venv/bin/pip install -e .) or start with --target-python <its python>.")
    return "ok", "no declared dependencies: the engine's own interpreter is enough for pure-Python code"


def dirty_text(r: RepoInfo) -> str:
    if not r.modified and not r.untracked:
        return "clean"
    return f"{r.modified} changed, {r.untracked} untracked"
