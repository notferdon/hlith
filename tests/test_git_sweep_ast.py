# SPDX-License-Identifier: Apache-2.0
"""X1: AST sweep for git spawn sites. Self-contained; cheap (parses src/, runs no git).

Rule: outside ``hostio/git_read.py`` (the single choke point) NO code may build a git argv or spawn git, by ANY route:
  - the literal "git" (or an absolute ".../git" path) as argv[0] of a list/tuple, or as the first argument of a spawn call;
  - ``shutil.which("git")`` (alone or inside ``x or "/usr/bin/git"``);
  - a module constant bound to either (``gitsafe.GIT``, ``feedback/_legacy._GIT_BIN``), also when imported into another module;
  - a function that returns either (``agent/capture._git_bin``), and a local variable bound to such a call;
  - an argv built in a helper (the helper's list literal is the site).
The only permitted sites outside the choke point are listed in NAMED_EXCEPTIONS with a class and a reason (§10 classes). A table entry that
matches no site fails (stale exception). Transport commands (fetch/clone/...) against another repository must sit in a function that
uses the choke point (``hostio.git_read``) for its vet (§9 clone, §10 capture fetch: Seam C), even inside a named exception.
Negative controls: a bare ``shutil.which("git")`` availability check, ".git" path strings and "GIT binary patch" text are NOT sites.
Positive controls: synthetic planted modules fed to the same checker must be flagged by every route above.
"""
from __future__ import annotations

import ast
import shutil
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "hlith"
PACKAGE = "hlith"
CHOKE_POINT = "hostio/git_read.py"

# (relpath under src/hlith, enclosing function qualname) -> (class, reason). Classes are the §10 set; nothing else is allowed.
CLASSES = ("plain-dir", "confined-worker-apply", "own-scratch-repo", "clone-of-vetted-source")
VET_FUNC = "vet_repository"  # the choke point's fail-closed vet (hostio/git_read.py)
NAMED_EXCEPTIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("gitsafe.py", "run_plain"): (
        "plain-dir", "git apply in an exported/copied directory with no .git (derive.py/_patched_copy, effect/engine.py); ceiling at its parent"),
    ("operator/gitq.py", "numstat"): (
        "plain-dir", "git apply --numstat -z - on stdin with cwd = private home; reads no repository"),
    ("feedback/_legacy.py", "_apply_diff_scrubbed"): (
        "plain-dir", "git apply - on L5's own candidate copy (no .git)"),
    ("agent/graph.py", "build_graph.<locals>.apply"): (
        "confined-worker-apply", "worker-side git apply of the operator patch inside the Landlock-confined stage child"),
    ("agent/tools.py", "_agent_tool_raw"): (
        "confined-worker-apply", "agent tool git apply inside the confined stage child (_run_child)"),
    ("agent/supervisor.py", "run_worker"): (
        "confined-worker-apply", "headless worker argv: git apply of op.patch inside the confined stage"),
    ("hostio/snapshot.py", "_run_scratch_git"): (
        "own-scratch-repo", "git on Hlith's own sealed scratch repositories (never the target)"),
    ("operator/host.py", "_clone_source"): (
        "clone-of-vetted-source", "git clone of a source repository that hostio.git_read.vet_repository accepted, into our own empty dir; then remote rm/checkout on that clone"),
    ("agent/capture.py", "_git"): (
        "own-scratch-repo", "git on capture's own bare diff scratch repo; a fetch FROM the target must be vetted by the choke point first (X1b)"),
}

SPAWN_FUNCS = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
           "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "posix_spawn", "posix_spawnp"},
    "asyncio": {"create_subprocess_exec", "create_subprocess_shell"},
    "pty": {"spawn"},
}
TRANSPORT = {"fetch", "clone", "ls-remote", "pull", "fetch-pack", "upload-pack", "remote-ext", "bundle"}


@dataclass(frozen=True)
class Site:
    rel: str
    qualname: str
    line: int
    why: str


# ----------------------------------------------------------------------------------------------------------------- checker
def _modname(root: Path, package: str, path: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([package, *parts])


def _resolve_from(mod: str, is_pkg: bool, level: int, name: str | None) -> str:
    if level == 0:
        return name or ""
    base = mod.split(".") if is_pkg else mod.split(".")[:-1]
    base = base[: len(base) - (level - 1)] if level > 1 else base
    return ".".join([*base, *([name] if name else [])])


def _is_git_str(v: object) -> bool:
    return isinstance(v, str) and (v == "git" or v.endswith("/git") or v.startswith("git "))


class _Module:
    def __init__(self, root: Path, package: str, path: Path):
        self.path = path
        self.rel = path.relative_to(root).as_posix()
        self.name = _modname(root, package, path)
        self.is_pkg = path.name == "__init__.py"
        self.tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        self.imports: dict[str, str] = {}  # local alias -> fully qualified (module or module.attr)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                src = _resolve_from(self.name, self.is_pkg, node.level, node.module)
                for a in node.names:
                    self.imports[a.asname or a.name] = f"{src}.{a.name}"


class _Index:
    """Cross-module facts: fully qualified names of git constants and of functions that return git."""

    def __init__(self, mods: list[_Module]):
        self.mods = {m.name: m for m in mods}
        self.consts: set[str] = set()
        self.funcs: set[str] = set()
        changed = True
        while changed:
            changed = False
            for m in mods:
                for node in m.tree.body:
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        if self.gitish(m, node.value, {}):
                            for t in targets:
                                if isinstance(t, ast.Name) and f"{m.name}.{t.id}" not in self.consts:
                                    self.consts.add(f"{m.name}.{t.id}")
                                    changed = True
                for node in ast.walk(m.tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        q = f"{m.name}.{node.name}"
                        if q in self.funcs:
                            continue
                        local = _local_bindings(self, m, node)
                        for r in ast.walk(node):
                            if isinstance(r, ast.Return) and r.value is not None and self.gitish(m, r.value, local):
                                self.funcs.add(q)
                                changed = True
                                break

    def _qual(self, m: _Module, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            return m.imports.get(expr.id, f"{m.name}.{expr.id}")
        if isinstance(expr, ast.Attribute):
            base = self._qual(m, expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None

    def gitish(self, m: _Module, e: ast.expr, local: dict[str, bool]) -> bool:
        if isinstance(e, ast.Constant):
            return isinstance(e.value, str) and (e.value == "git" or e.value.endswith("/git"))
        if isinstance(e, ast.BoolOp):
            return any(self.gitish(m, v, local) for v in e.values)
        if isinstance(e, ast.IfExp):
            return self.gitish(m, e.body, local) or self.gitish(m, e.orelse, local)
        if isinstance(e, ast.Name) and local.get(e.id):
            return True
        if isinstance(e, (ast.Name, ast.Attribute)):
            q = self._qual(m, e)
            return q in self.consts
        if isinstance(e, ast.Call):
            q = self._qual(m, e.func)
            if q == "shutil.which":
                return any(isinstance(a, ast.Constant) and a.value == "git" for a in e.args)
            if q in ("os.environ.get", "os.getenv"):
                return any(self.gitish(m, a, local) for a in e.args[1:])
            return q in self.funcs
        return False


def _local_bindings(ix: _Index, m: _Module, fn: ast.AST) -> dict[str, bool]:
    local: dict[str, bool] = {}
    for _ in range(2):
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and ix.gitish(m, n.value, local):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        local[t.id] = True
            elif isinstance(n, ast.NamedExpr) and ix.gitish(m, n.value, local):
                local[n.target.id] = True
    return local


def _spawn_call(ix: _Index, m: _Module, call: ast.Call) -> bool:
    q = ix._qual(m, call.func) or ""
    mod, _, fn = q.rpartition(".")
    return fn in SPAWN_FUNCS.get(mod, set())


def _first_arg(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for k in call.keywords:
        if k.arg in ("args", "file", "path", "cmd", "program"):
            return k.value
    return None


def _scopes(tree: ast.Module):
    """Yield (qualname, node) for every node, attributing it to its innermost enclosing function."""
    def walk(node, qual):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = child.name if qual == "<module>" else f"{qual}.<locals>.{child.name}" if not qual.startswith("class:") else f"{qual[6:]}.{child.name}"
                yield q, child, child
                yield from walk(child, q)
            elif isinstance(child, ast.ClassDef):
                cq = child.name if qual == "<module>" else f"{qual}.{child.name}"
                yield from walk(child, f"class:{cq}")
            else:
                yield (qual if not qual.startswith("class:") else qual[6:]), child, None
                yield from walk(child, qual)
    yield from walk(tree, "<module>")


def scan(root: Path, package: str = PACKAGE) -> tuple[list[Site], dict]:
    mods = [_Module(root, package, p) for p in sorted(root.rglob("*.py"))]
    ix = _Index(mods)
    sites: list[Site] = []
    transport: list[Site] = []
    for m in mods:
        fn_nodes: dict[str, ast.AST] = {}
        local_cache: dict[str, dict] = {}
        for qual, node, fdef in _scopes(m.tree):
            if fdef is not None:
                fn_nodes[qual] = fdef
                continue
            fn = fn_nodes.get(qual)
            if qual not in local_cache:
                local_cache[qual] = _local_bindings(ix, m, fn) if fn is not None else {}
            local = local_cache[qual]
            if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
                first = node.elts[0]
                if not isinstance(first, ast.Starred) and ix.gitish(m, first, local):
                    sites.append(Site(m.rel, qual, node.lineno, "argv[0] is git"))
                    if any(isinstance(e, ast.Constant) and e.value in TRANSPORT for e in node.elts):
                        transport.append(Site(m.rel, qual, node.lineno, "transport argv"))
            elif isinstance(node, ast.Call):
                if _spawn_call(ix, m, node):
                    a = _first_arg(node)
                    if a is not None and (ix.gitish(m, a, local) or (isinstance(a, ast.Constant) and _is_git_str(a.value))):
                        sites.append(Site(m.rel, qual, node.lineno, "spawn of git"))
    # transport via a git runner helper: a call to a function of this module that is itself a git site, with a transport verb in its args
    runner_names = {(s.rel, s.qualname.rsplit(".", 1)[-1]) for s in sites}
    for m in mods:
        for qual, node, fdef in _scopes(m.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and (m.rel, node.func.id) in runner_names:
                if any(isinstance(a, ast.Constant) and a.value in TRANSPORT for a in node.args):
                    transport.append(Site(m.rel, qual, node.lineno, f"transport via {node.func.id}"))
    uniq = sorted(set(sites), key=lambda s: (s.rel, s.line))
    return uniq, {"transport": sorted(set(transport), key=lambda s: (s.rel, s.line)), "mods": {m.rel: m for m in mods}, "index": ix}


def _uses_choke_point(m: _Module, fn: ast.AST | None, package: str = PACKAGE) -> bool:
    target = f"{package}.hostio.git_read"
    body = fn if fn is not None else m.tree
    for n in ast.walk(body):
        if isinstance(n, ast.ImportFrom) and _resolve_from(m.name, m.is_pkg, n.level, n.module) == target:
            return True
        if isinstance(n, ast.Name) and m.imports.get(n.id, "").startswith(target):
            return True
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and m.imports.get(n.value.id, "") == target:
            return True
    return False


def _vet_call_lines(fn: ast.AST | None) -> list[int]:
    """Lines of calls to the choke point's vet (``vet_repository(...)`` or ``<alias>.vet_repository(...)``) in this function."""
    if fn is None:
        return []
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name == VET_FUNC:
                out.append(n.lineno)
    return out


def _vetted_before(m: _Module, qualname: str, line: int, package: str = PACKAGE) -> bool:
    fn = _fn_node(m, qualname) if qualname != "<module>" else None
    return _uses_choke_point(m, fn, package) and any(v < line for v in _vet_call_lines(fn))


def _fn_node(m: _Module, qualname: str) -> ast.AST | None:
    for q, _node, fdef in _scopes(m.tree):
        if fdef is not None and q == qualname:
            return fdef
    return None


# ----------------------------------------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def real():
    assert SRC.is_dir(), SRC
    return scan(SRC)


def _plant(tmp_path: Path, files: dict[str, str]) -> Path:
    pkg = tmp_path / "plantpkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    for rel, code in files.items():
        p = pkg / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.parent != pkg and not (p.parent / "__init__.py").exists():
            (p.parent / "__init__.py").write_text("")
        p.write_text(textwrap.dedent(code))
    return pkg


# ----------------------------------------------------------------------------------------------------------------- X1 on the real tree
def test_no_unnamed_git_spawn_outside_choke_point(real):
    sites, _ = real
    unnamed = [s for s in sites if s.rel != CHOKE_POINT and (s.rel, s.qualname) not in NAMED_EXCEPTIONS]
    assert not unnamed, "git argv/spawn outside hostio/git_read.py and not a named exception:\n" + "\n".join(
        f"  {s.rel}:{s.line} {s.qualname} ({s.why})" for s in unnamed)


def test_every_named_exception_still_matches_a_site(real):
    sites, _ = real
    present = {(s.rel, s.qualname) for s in sites}
    stale = [k for k in NAMED_EXCEPTIONS if k not in present]
    assert not stale, f"stale named exceptions (no git site there any more; delete or re-point the row): {stale}"


def test_named_exceptions_have_a_class_and_reason():
    for key, (cls, reason) in NAMED_EXCEPTIONS.items():
        assert cls in CLASSES, (key, cls)
        assert isinstance(reason, str) and len(reason.strip()) >= 20, key
        assert key[0] != CHOKE_POINT, key


def test_choke_point_is_seen_by_the_sweep(real):
    """Anti-vacuity: the checker must find the choke point's own git argv on the real tree."""
    sites, _ = real
    assert any(s.rel == CHOKE_POINT for s in sites), "sweep found no git site in hostio/git_read.py: the checker is blind"


def test_transport_commands_are_vetted_by_the_choke_point(real):
    """X1b (§9 clone, §10 Seam C): a fetch/clone FROM another repository runs Git (upload-pack) inside that repository, so the function
    issuing it must use hostio.git_read (the vet) - also inside a named exception (capture's scratch runner)."""
    _, info = real
    bad = []
    for s in info["transport"]:
        if s.rel == CHOKE_POINT:
            continue
        if not _vetted_before(info["mods"][s.rel], s.qualname, s.line):
            bad.append(f"  {s.rel}:{s.line} {s.qualname} ({s.why})")
    assert not bad, f"transport git command not preceded (same function, earlier line) by hostio.git_read.{VET_FUNC}:\n" + "\n".join(bad)


def test_clone_exception_vets_the_source_before_every_git_spawn(real):
    """design decision (a): the clone row is allowed ONLY because the source was vetted first: every git site in that function sits after a
    vet_repository call (static ordering; the behavioural refusal is X10's job)."""
    sites, info = real
    rows = [k for k, (cls, _r) in NAMED_EXCEPTIONS.items() if cls == "clone-of-vetted-source"]
    assert rows, "no clone-of-vetted-source row"
    for rel, qual in rows:
        mine = [s for s in sites if (s.rel, s.qualname) == (rel, qual)]
        assert mine, (rel, qual)
        assert any(s.why == "argv[0] is git" and s.line for s in mine)
        bad = [s.line for s in mine if not _vetted_before(info["mods"][rel], qual, s.line)]
        assert not bad, f"{rel} {qual}: git spawn at line(s) {bad} not preceded by hostio.git_read.{VET_FUNC}"


def test_hand_config_parser_symbol_is_gone(real):
    _, info = real
    hits = [f"{rel}:{n.lineno}" for rel, m in info["mods"].items() for n in ast.walk(m.tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_exec_keys_in_config_text"]
    assert not hits, f"the hand config parser (parser differential, §2.2) still exists: {hits}"


@pytest.mark.parametrize("name", ["run_repo", "popen_repo"])
def test_gitsafe_unvetted_repo_runners_are_gone(real, name):
    _, info = real
    m = info["mods"].get("gitsafe.py")
    if m is None:
        return
    defs = [n.lineno for n in m.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert not defs, f"gitsafe.{name} (repo-bound runner outside the choke point, M6/§11) still defined at line(s) {defs}"


# ----------------------------------------------------------------------------------------------------------------- controls
NEGATIVE = {
    "which_only": """
        import shutil
        def doctor():
            git = shutil.which("git")
            return ("Git", bool(git), git or "git is missing from PATH")
    """,
    "dot_git_paths": """
        import os, subprocess
        def walk(root):
            for d, dirs, files in os.walk(root):
                dirs[:] = [x for x in dirs if x != ".git"]
            return [".git", "config"], (".git",)
        def other():
            return subprocess.run(["python3", "-c", "print('git')"])
    """,
    "binary_patch_text": """
        def is_bin(raw):
            return raw.startswith(b"GIT binary patch") or "git" in str(raw)
    """,
}

POSITIVE = {
    "literal": {"m.py": """
        import subprocess
        def f(repo):
            return subprocess.run(["git", "-C", repo, "status"])
    """},
    "abs_path_literal": {"m.py": """
        import subprocess
        def f():
            return subprocess.Popen(("/usr/bin/git", "log"))
    """},
    "which_constant": {"m.py": """
        import shutil, subprocess
        GIT = shutil.which("git") or "/usr/bin/git"
        def f():
            return subprocess.run([GIT, "status"])
    """},
    "cross_module_constant": {
        "consts.py": 'GIT = "git"\n',
        "user.py": """
            import subprocess
            from .consts import GIT
            def f():
                return subprocess.check_output([GIT, "rev-parse", "HEAD"])
        """},
    "module_attr_constant": {
        "consts.py": 'GIT = "git"\n',
        "user.py": """
            import subprocess
            from . import consts
            def f():
                return subprocess.run([consts.GIT, "status"])
        """},
    "bin_function_and_local": {"m.py": """
        import shutil, subprocess
        def _git_bin():
            return shutil.which("git") or "/usr/bin/git"
        def f(repo):
            git = _git_bin()
            return subprocess.run([git, "-C", repo, "status"])
    """},
    "argv_in_helper": {"m.py": """
        import subprocess
        def _argv(repo, *a):
            return ["git", "--no-pager", "-C", repo, *a]
        def f(repo):
            return subprocess.run(_argv(repo, "status"))
    """},
    "exec_literal": {"m.py": """
        import os
        def f():
            os.execvp("git", ["true"])
    """},
    "shell_string": {"m.py": """
        import subprocess
        def f():
            return subprocess.run("git status", shell=True)
    """},
    "aliased_subprocess_import": {"m.py": """
        from subprocess import Popen as P
        import shutil
        def f():
            return P([shutil.which("git"), "status"])
    """},
}


@pytest.mark.parametrize("case", sorted(NEGATIVE))
def test_negative_control_not_flagged(tmp_path, case):
    sites, info = scan(_plant(tmp_path, {"m.py": NEGATIVE[case]}), "plantpkg")
    assert not sites, sites
    assert not info["transport"]


def test_negative_control_which_git_is_available():
    """The sweep's subject exists on this host (git 2.43.0 expected); an absent git would make the behavioural X-tests vacuous."""
    assert shutil.which("git"), "git not on PATH"


@pytest.mark.parametrize("case", sorted(POSITIVE))
def test_positive_control_planted_spawn_is_flagged(tmp_path, case):
    sites, _ = scan(_plant(tmp_path, POSITIVE[case]), "plantpkg")
    assert sites, f"planted git spawn ({case}) not flagged"


def test_positive_control_unvetted_transport_is_flagged(tmp_path):
    pkg = _plant(tmp_path, {"m.py": """
        import shutil, subprocess
        def _git(*a):
            return subprocess.run([shutil.which("git"), *a])
        def diff_stage(target, gd):
            _git(f"--git-dir={gd}", "fetch", "--depth=1", str(target), "HEAD")
    """})
    _, info = scan(pkg, "plantpkg")
    assert [s.qualname for s in info["transport"]] == ["diff_stage"]
    m = info["mods"]["m.py"]
    assert not _uses_choke_point(m, _fn_node(m, "diff_stage"), "plantpkg")


def test_positive_control_vetted_transport_passes(tmp_path):
    pkg = _plant(tmp_path, {"hostio/git_read.py": "def vet_repository(p):\n    return None\n", "m.py": """
        import shutil, subprocess
        def _git(*a):
            return subprocess.run([shutil.which("git"), *a])
        def diff_stage(target, gd):
            from .hostio.git_read import vet_repository
            vet_repository(target)
            _git(f"--git-dir={gd}", "fetch", "--depth=1", str(target), "HEAD")
    """})
    _, info = scan(pkg, "plantpkg")
    m = info["mods"]["m.py"]
    assert info["transport"] and all(_vetted_before(m, s.qualname, s.line, "plantpkg") for s in info["transport"])


def test_negative_control_vet_after_transport_is_flagged(tmp_path):
    """Importing the choke point or calling the vet AFTER the fetch/clone does not count."""
    pkg = _plant(tmp_path, {"hostio/git_read.py": "def vet_repository(p):\n    return None\n", "m.py": """
        import subprocess
        def clone(src, dst):
            from .hostio import git_read as ro
            subprocess.run(["git", "clone", "--", src, dst])
            ro.vet_repository(src)
    """})
    _, info = scan(pkg, "plantpkg")
    m = info["mods"]["m.py"]
    assert info["transport"] and not any(_vetted_before(m, s.qualname, s.line, "plantpkg") for s in info["transport"])


def test_stale_exception_detection_works(tmp_path):
    """The stale-row check is not vacuous: a table row for a site that does not exist is reported."""
    sites, _ = scan(_plant(tmp_path, POSITIVE["literal"]), "plantpkg")
    present = {(s.rel, s.qualname) for s in sites}
    assert ("m.py", "f") in present and ("m.py", "gone") not in present
