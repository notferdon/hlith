# SPDX-License-Identifier: Apache-2.0
"""Git spawning for host-side code on PLAIN directories (an export, a copy, a scratch dir that is not a user repository), plus repository DISCOVERY.

There is deliberately NO repository-bound runner here any more (``run_repo`` / ``popen_repo`` ran git on a user repository with no vet: one was observed firing a
repository-configured filter). Every git command on a user-selected repository goes through ``hostio.git_read`` (closed-world vet, one argv/env builder).

* PLAIN DIRECTORY: ``run_plain``: the allow-listed environment and ``_HARDEN`` pins, plus ``GIT_CEILING_DIRECTORIES`` so discovery never climbs into a parent repository.
* ``discover_toplevel`` is the one deliberate discovery (is this path inside ANY work tree?). It does NOT start git: git must not run inside a directory before the vet has
  passed, and a repository's own core.worktree must never name "the repository you are in".
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator, Sequence

from .hostio.git_read import _HARDEN

GIT = "git"


@contextlib.contextmanager
def _home() -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="hlith-git-home-", dir="/tmp") as home:
        yield home


def scrubbed_env(home: str, *, ceiling: str | None = None) -> dict[str, str]:
    """The allow-listed git environment for a plain directory, optionally with a discovery ceiling."""
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    if ceiling is not None:
        env["GIT_CEILING_DIRECTORIES"] = ceiling
    return env


def run_plain(cwd: str | os.PathLike, args: Sequence[str], *, input: bytes | str | None = None, text: bool = False,
              config: Sequence[str] = (), ceiling: str | None = None) -> subprocess.CompletedProcess:
    """git inside a plain directory that is NOT a user repository (an export, a copy, a scratch dir).

    ``ceiling`` defaults to the directory's parent: discovery may look at ``cwd`` itself but never above it.
    ``config`` adds ``-c`` pairs after ``_HARDEN`` (later -c wins), e.g. ``protocol.file.allow=always`` for a local
    fetch the caller explicitly wants."""
    cwd = Path(cwd).resolve()
    with _home() as home:
        env = scrubbed_env(home, ceiling=str(cwd.parent) if ceiling is None else ceiling)
        return subprocess.run([GIT, "--no-pager", *_HARDEN, *config, *args], cwd=str(cwd), input=input, text=text,
                              capture_output=True, check=False, env=env, timeout=600)


def discover_toplevel(path: str | os.PathLike) -> bytes | None:
    """The work-tree root of the nearest enclosing repository as ``<root>`` plus a newline, or None outside any. Pure path logic, no git process."""
    from .hostio.git_read import find_work_tree_root

    root = find_work_tree_root(Path(path))
    return None if root is None else (str(root) + "\n").encode()
