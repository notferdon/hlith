#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hard-failing import-DAG checker for the Hlith package layout (design note).

Reads ``scripts/layer_map.json`` (schema 2) and the source tree ``src/hlith``; never imports or executes Hlith or
repository code (pure ``ast`` scan).

Edges it sees (each is a dependency of the importing module):
  * ``import x`` / ``from x import y`` anywhere in the file, including lazy imports inside functions, ``try`` and
    ``if`` blocks (``TYPE_CHECKING`` imports included: an annotation dependency is still a dependency);
  * relative imports, resolved against the module's package; ``from pkg import name`` also yields ``pkg.name`` when
    that is a module;
  * string literals naming a known module passed to a call or listed in an argv list (``importlib.import_module("hlith.x")``,
    ``runpy.run_module(...)``, ``[sys.executable, "-m", "hlith.x"]``); a string inside a larger code string (e.g. a
    ``python -c`` program) is NOT parsed: declare such launches in ``file_entrypoints``;
  * declared file-loaded entrypoints from the map's ``file_entrypoints`` (launch manifest), e.g. the differential
    driver that loads ``differential.py`` and its siblings by FILE.

Node identity: ``aliases`` (old name -> canonical module, e.g. a ``sys.modules`` alias shim) collapse to ONE node, so an
alias is never a second module and never a cycle. ``shim`` modules are compatibility nodes with a named target and
removal step; their edges are checked like any other.

FAILS (exit 1) on:
  * a missing path: a mapped module / present package / file-entrypoint file that does not exist, or a source file
    that no map entry covers (unmapped);
  * an edge outside the allowed-edge table (``allowed``: section -> sections, plus ``allowed_modules``: section ->
    declared public API modules of other sections), including every upward import;
  * an import cycle (strongly connected component of > 1 node, or a self-edge between different files);
  * proposer reachability: any path from a module whose layer is in ``rules.proposer_unreachable_from`` to a
    ``proposer_modules`` node;
  unless the exact violation is listed in ``known_baseline`` (temporary, migration only). The remaining baseline is
  printed every run so zero is the visible target; baseline entries that no longer occur are reported as stale.
Exit 2 = the map itself is malformed.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_MODNAME = re.compile(r"^hlith(\.[A-Za-z_][A-Za-z0-9_]*)+$|^hlith$")


class MapError(Exception):
    pass


def load_map(path: Path) -> dict:
    try:
        m = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise MapError(f"cannot read map {path}: {e}") from e
    for key in ("schema_version", "layer_ranks", "sections", "allowed", "modules", "rules"):
        if key not in m:
            raise MapError(f"map lacks '{key}'")
    if m["schema_version"] != 2:
        raise MapError("map schema_version must be 2")
    for sec, spec in m["sections"].items():
        if spec.get("layer") not in m["layer_ranks"]:
            raise MapError(f"section {sec}: unknown layer {spec.get('layer')}")
        if spec.get("status") not in ("present", "pending"):
            raise MapError(f"section {sec}: status must be present|pending")
    for sec, targets in m["allowed"].items():
        if sec not in m["sections"] or any(t not in m["sections"] for t in targets):
            raise MapError(f"allowed: unknown section in {sec} -> {targets}")
    for mod, spec in m["modules"].items():
        if spec.get("section") not in m["sections"]:
            raise MapError(f"module {mod}: unknown section {spec.get('section')}")
    return m


def discover(src: Path) -> dict[str, Path]:
    """module name -> file for every .py under src/hlith (a package is its __init__)."""
    out: dict[str, Path] = {}
    base = src / "hlith"
    for f in sorted(base.rglob("*.py")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(src).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        out[".".join(parts)] = f
    return out


def section_of(mod: str, m: dict) -> str | None:
    """Exact module entry first, then the longest package prefix of a section."""
    if mod in m["modules"]:
        return m["modules"][mod]["section"]
    best = None
    for sec, spec in m["sections"].items():
        pkg = spec.get("package")
        if pkg and (mod == pkg or mod.startswith(pkg + ".")) and (best is None or len(pkg) > len(m["sections"][best]["package"])):
            best = sec
    return best


def canonical(mod: str, m: dict) -> str:
    seen = set()
    while mod in m.get("aliases", {}) and mod not in seen:
        seen.add(mod)
        mod = m["aliases"][mod]
    return mod


def _resolve_relative(mod: str, is_pkg: bool, level: int, name: str | None) -> str:
    parts = mod.split(".") if is_pkg else mod.split(".")[:-1]
    if level > 1:
        parts = parts[: len(parts) - (level - 1)]
    base = ".".join(parts)
    return f"{base}.{name}" if name else base


def imports_of(mod: str, f: Path, known: set[str]) -> list[tuple[str, int, str]]:
    """(target module, line, how) for every dependency the file states."""
    tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
    is_pkg = f.name == "__init__.py"
    out: list[tuple[str, int, str]] = []

    def add(target: str, line: int, how: str) -> None:
        # keep the deepest known prefix (hlith.x.y.attr -> hlith.x.y)
        t = target
        while t and t not in known and "." in t:
            t = t.rsplit(".", 1)[0]
        if t in known and t != mod:
            out.append((t, line, how))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "hlith" or a.name.startswith("hlith."):
                    add(a.name, node.lineno, "import")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(mod, is_pkg, node.level, node.module)
            elif node.module and (node.module == "hlith" or node.module.startswith("hlith.")):
                base = node.module
            else:
                continue
            subs = [a.name for a in node.names if a.name != "*" and f"{base}.{a.name}" in known]
            if len(subs) < len(node.names):  # names a non-module attribute of base (or *): a dependency on base itself
                add(base, node.lineno, "from")
            for name in subs:  # `from pkg import submodule` depends on the submodule (pkg/__init__ runs anyway: no edge)
                add(f"{base}.{name}", node.lineno, "from-submodule")
        elif isinstance(node, (ast.Call, ast.List, ast.Tuple)):
            # a module NAME handed to a loader: importlib.import_module("hlith.x"), runpy.run_module("hlith.x"),
            # [python, "-m", "hlith.x"]. A plain string constant elsewhere (a label, a log text) is not a dependency.
            vals = [*node.args, *(k.value for k in node.keywords)] if isinstance(node, ast.Call) else node.elts
            for c in vals:
                if isinstance(c, ast.Constant) and isinstance(c.value, str) and _MODNAME.match(c.value) and c.value in known:
                    add(c.value, getattr(c, "lineno", 0), "string-module")
    return out


def sccs(graph: dict[str, set[str]]) -> list[list[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on: set[str] = set()
    out: list[list[str]] = []
    counter = [0]
    sys.setrecursionlimit(max(10000, sys.getrecursionlimit()))

    def visit(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in graph.get(v, ()):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                out.append(sorted(comp))

    for v in sorted(graph):
        if v not in index:
            visit(v)
    return out


def check(m: dict, src: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    """(new violations, baseline hits, missing/unmapped, stale baseline ids). Violation strings are stable ids matched against known_baseline."""
    files = discover(src)
    known = set(files)
    missing: list[str] = []
    for mod, spec in m["modules"].items():
        if spec.get("status", "present") == "retired":
            if mod in files:
                missing.append(f"retired module still present: {mod}")
            continue
        if mod not in files:
            missing.append(f"mapped module missing: {mod} ({spec['section']})")
    for sec, spec in m["sections"].items():
        pkg = spec.get("package")
        if pkg and spec["status"] == "present" and pkg not in files:
            missing.append(f"present section package missing: {pkg} ({sec})")
    for alias, target in m.get("aliases", {}).items():
        if canonical(alias, m) not in files:
            missing.append(f"alias target missing: {alias} -> {target}")
    for mod in sorted(files):
        if section_of(mod, m) is None and mod != "hlith":
            missing.append(f"unmapped source module: {mod} ({files[mod].relative_to(src)})")
    by_file = {str(p.relative_to(src)): mod for mod, p in files.items()}
    edges: dict[tuple[str, str], tuple[int, str]] = {}
    for mod, f in files.items():
        for tgt, line, how in imports_of(mod, f, known):
            edges.setdefault((mod, tgt), (line, how))
    for ep in m.get("file_entrypoints", ()):
        loader, loaded = ep.get("loader"), ep.get("file")
        if loader not in files:
            missing.append(f"file entrypoint loader missing: {loader}")
            continue
        if loaded not in by_file:
            missing.append(f"file entrypoint file missing: {loaded} (loaded by {loader})")
            continue
        edges.setdefault((loader, by_file[loaded]), (0, "file-entrypoint"))
    # collapse aliases to one node
    graph: dict[str, set[str]] = defaultdict(set)
    where: dict[tuple[str, str], tuple[int, str]] = {}
    for (a, b), info in edges.items():
        ca, cb = canonical(a, m), canonical(b, m)
        if ca == cb:
            continue
        graph[ca].add(cb)
        graph.setdefault(cb, set())
        where.setdefault((ca, cb), info)
    ranks = m["layer_ranks"]
    violations: list[str] = []
    for (a, b), (line, how) in sorted(where.items()):
        sa, sb = section_of(a, m), section_of(b, m)
        if sa is None or sb is None or sa == sb:
            continue
        if sb in m["allowed"].get(sa, ()):
            continue
        if any(b == api or b.startswith(api + ".") for api in m.get("allowed_modules", {}).get(sa, ())):
            continue  # a declared public API of a lower section (e.g. obligation -> hlith.effect.api)
        la, lb = m["sections"][sa]["layer"], m["sections"][sb]["layer"]
        kind = "upward" if ranks[lb] > ranks[la] else "disallowed"
        violations.append(f"edge:{kind}:{a}->{b} [{sa}({la})->{sb}({lb})] ({how} line {line})")
    for comp in sccs(graph):
        violations.append("cycle:" + ",".join(comp))
    rules = m["rules"]
    proposers = {canonical(p, m) for p in m.get("proposer_modules", ())}
    guarded_layers = set(rules.get("proposer_unreachable_from", ()))
    for start in sorted(graph):
        sec = section_of(start, m)
        if sec is None or m["sections"][sec]["layer"] not in guarded_layers or start in proposers:
            continue
        seen, todo, parent = {start}, [start], {}
        while todo:
            v = todo.pop()
            for w in graph.get(v, ()):
                if w in seen:
                    continue
                seen.add(w)
                parent[w] = v
                if w in proposers:
                    path, x = [w], w
                    while x != start:
                        x = parent[x]
                        path.append(x)
                    violations.append("proposer-reachable:" + "->".join(reversed(path)))
                else:
                    todo.append(w)
    # baseline: ids are compared WITHOUT the trailing "(how line N)" detail so a moved line does not churn the baseline
    def key(v: str) -> str:
        return re.sub(r" \((?:[a-z-]+) line \d+\)$", "", v)

    base = {key(x) for x in m.get("known_baseline", ())}
    hits = [v for v in violations if key(v) in base]
    new = [v for v in violations if key(v) not in base]
    stale = sorted(base - {key(v) for v in violations})
    return new, hits, missing, stale


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--map", type=Path, default=ROOT / "scripts" / "layer_map.json")
    ap.add_argument("--src", type=Path, default=ROOT / "src")
    ap.add_argument("--print-baseline", action="store_true", help="print current violations in map format (for review; never auto-written)")
    args = ap.parse_args(argv)
    try:
        m = load_map(args.map)
    except MapError as e:
        print(f"layer-dag: MAP ERROR: {e}", file=sys.stderr)
        return 2
    new, hits, missing, stale = check(m, args.src)
    for x in missing:
        print(f"MISSING  {x}")
    for x in new:
        print(f"VIOLATION {x}")
    print(f"layer-dag: baseline remaining = {len(hits)} (target 0)")
    for x in hits:
        print(f"  baseline {x}")
    for x in stale:
        print(f"  stale baseline entry, remove from the map: {x}")
    if args.print_baseline:
        print(json.dumps(sorted({re.sub(r' \((?:[a-z-]+) line \d+\)$', '', v) for v in new + hits}), indent=2))
    # the import-NAME gate (scripts/check_import_names.py) runs as part of the same baseline gate
    import importlib.util
    spec = importlib.util.spec_from_file_location("_hlith_check_import_names", Path(__file__).with_name("check_import_names.py"))
    names_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(names_mod)
    names_rc = names_mod.main(["--map", str(args.map), "--src", str(args.src)])
    if missing or new or stale:
        # a stale baseline entry FAILS too (case ratchet): the baseline may only shrink by being edited, so it can
        # never silently keep room for a violation to come back
        print(f"layer-dag: FAIL ({len(missing)} missing/unmapped, {len(new)} violations outside the baseline, "
              f"{len(stale)} stale baseline entries)")
        return 1
    if names_rc != 0:
        print("layer-dag: FAIL (import-name gate)")
        return names_rc
    print("layer-dag: OK" + ("" if not hits else " (baseline not yet zero)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
