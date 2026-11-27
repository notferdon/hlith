# SPDX-License-Identifier: Apache-2.0
"""Scan a real repository: sample callables, audit the account against the oracle, print miss rate per construct.

usage: python tests/caller_oracle_scan.py ROOT PACKAGE [N] [JSON_OUT]   (ROOT is only read; the account works on a copy)
"""
from __future__ import annotations

import ast
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from caller_oracle import iter_py, module_name  # noqa: E402
from caller_oracle_compare import compare, rates  # noqa: E402


def candidates(root: Path, package: str) -> list[str]:
    defs: dict[str, list[str]] = {}
    for p in iter_py(root):
        rel = p.relative_to(root).as_posix()
        mod = module_name(rel)
        if not (mod == package or mod.startswith(package + ".")):
            continue
        try:
            tree = ast.parse(p.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(n.name, []).append(f"{mod}.{n.name}")
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and not m.name.startswith("__"):
                        defs.setdefault(m.name, []).append(f"{mod}.{n.name}.{m.name}")
    # distinctive names only: a short name defined once keeps the name-match over-approximation meaningful
    return sorted(v[0] for k, v in defs.items() if len(v) == 1 and len(k) >= 5 and not k.startswith("_"))


def main(argv: list[str]) -> int:
    root, package = Path(argv[1]), argv[2]
    n = int(argv[3]) if len(argv) > 3 else 25
    out = Path(argv[4]) if len(argv) > 4 else None
    cands = candidates(root, package)
    step = max(1, len(cands) // n)
    picked = cands[::step][:n]
    results, skipped = [], 0
    for q in picked:
        try:
            r = compare(root, q)
        except Exception as e:  # report, never hide
            print(f"ERROR {q}: {type(e).__name__}: {str(e)[:100]}")
            skipped += 1
            continue
        if r is None:
            skipped += 1
            continue
        results.append(r)
    tab = rates(results)
    print(f"# {root} package={package}: {len(results)} targets audited, {skipped} skipped, {len(cands)} candidates")
    tot = Counter()
    for (construct, klass), c in sorted(tab.items()):
        n_all = sum(c.values())
        tot.update(c)
        print(f"{construct:24} {klass:10} sites={n_all:4} listed={c['listed']:3} flagged={c['flagged_line'] + c['flagged_target']:3} MISS={c['MISS']:3} ({100 * c['MISS'] / n_all:.0f}%)")
    print("TOTAL", dict(tot))
    ex: dict[str, list[str]] = {}
    for r in results:
        for row in r["rows"]:
            if row["status"] == "MISS":
                s = row["site"]
                ex.setdefault(s.construct, []).append(f"{r['target']} <- {s.file}:{s.line} in {s.caller}")
    for k, v in sorted(ex.items()):
        print(f"MISS {k}: {len(v)}; e.g. {v[0]}")
    if out:
        out.write_text(json.dumps({"root": str(root), "targets": [r["target"] for r in results],
                                   "table": {f"{k[0]}|{k[1]}": dict(v) for k, v in tab.items()}, "miss_examples": ex}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
