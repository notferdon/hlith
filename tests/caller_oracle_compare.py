# SPDX-License-Identifier: Apache-2.0
"""Compare the independent oracle's call sites with review's effect account for one target."""
from __future__ import annotations

import ast
import difflib
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from caller_oracle import Site, enumerate_sites, locate, split_target


def probe_patch(root: Path, qualified: str) -> str | None:
    """A neutral one-line body edit of the target (inserted before its first non-docstring statement)."""
    tmod, tcls, short = split_target(qualified, root)
    f = locate(root, tmod)
    text = f.read_text()
    tree = ast.parse(text)
    scope: list[ast.AST] = [tree]
    if tcls:
        scope = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == tcls]
    fn = None
    for sc in scope:
        for n in ast.iter_child_nodes(sc):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == short:
                fn = n
    if fn is None:
        return None
    body = fn.body
    first = body[1] if (isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant)
                        and isinstance(body[0].value.value, str) and len(body) > 1) else body[0]
    if first.lineno == fn.lineno or first.col_offset == 0:
        return None
    lines = text.splitlines(keepends=True)
    new = lines[: first.lineno - 1] + [" " * first.col_offset + "_n1_probe = 0\n"] + lines[first.lineno - 1:]
    rp = f.relative_to(root).as_posix()
    return "".join(difflib.unified_diff(lines, new, f"a/{rp}", f"b/{rp}"))


def probe_insert(patch: str) -> tuple[str, int] | None:
    """(file, new-file line) of the one line the probe patch inserts; callers below it shift by +1 in the post tree."""
    import re

    cur = None
    new_ln = 0
    for ln in patch.splitlines():
        if ln.startswith("+++ b/"):
            cur = ln[6:]
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", ln)
        if m:
            new_ln = int(m.group(1)) - 1
            continue
        if cur and ln[:1] in (" ", "+") and not ln.startswith("+++"):
            new_ln += 1
            if ln.startswith("+") and "_n1_probe" in ln:
                return cur, new_ln
    return None


def account_view(root: Path, qualified: str, patch: str) -> dict[str, Any]:
    from hlith import effect

    with tempfile.TemporaryDirectory(prefix="hlith-oracle-") as tmp:
        # the account copies the tree itself; hand it a git-free copy so the real repo is never touched
        work = Path(tmp) / "r"
        skip = shutil.ignore_patterns(".git", ".hlith", "__pycache__", "node_modules", ".venv", "venv")

        def ignore(d, names):  # python sources + configs only: the account reads nothing else, big repos copy fast
            keep = [n for n in names if (Path(d) / n).is_dir() or n.endswith((".py", ".toml", ".cfg", ".ini", ".txt"))]
            return [n for n in names if n not in keep] + list(skip(d, names))
        shutil.copytree(root, work, ignore=ignore)
        ad = effect.build_effect_account(work, patch).to_dict()
    ins = probe_insert(patch)

    def pre_line(f: str, ln: int, post: bool) -> int:  # map a post-tree line of the probe file back to the repo's line
        return ln - 1 if (post and ins is not None and f == ins[0] and ln > ins[1]) else ln

    listed = {(c["file_path"], pre_line(c["file_path"], c["line_number"], key == "post_call_sites"))
              for key in ("impacted_call_sites", "post_call_sites")
              for c in ad.get(key, ()) if c["callee_qualified_name"] == qualified}
    flag_lines: set[tuple[str, int]] = set()
    flag_target = False
    for key in ("unknown_edges", "unresolved_constructs", "callee_unresolved_constructs"):
        for u in ad.get(key, ()):
            fp, ln = u.get("file_path") or u.get("file"), u.get("line_number") or u.get("line")
            if fp and ln:
                flag_lines.add((fp, int(ln)))
                if ins is not None and fp == ins[0] and int(ln) > ins[1]:  # may be a post-tree line: accept both
                    flag_lines.add((fp, int(ln) - 1))
            if u.get("target_qualified_name") == qualified:
                flag_target = True
    return {"listed": listed, "flag_lines": flag_lines, "flag_target": flag_target,
            "n_modified": len(ad.get("modified_callables", ()))}


def compare(root: str | Path, qualified: str) -> dict[str, Any] | None:
    root = Path(root)
    patch = probe_patch(root, qualified)
    if not patch:
        return None
    view = account_view(root, qualified, patch)
    if not view["n_modified"]:
        return None
    rows = []
    for s in enumerate_sites(root, qualified):
        k = (s.file, s.line)
        status = ("listed" if k in view["listed"] else "flagged_line" if k in view["flag_lines"]
                  else "flagged_target" if view["flag_target"] else "MISS")
        rows.append({"site": s, "status": status})
    return {"target": qualified, "rows": rows, "view": view}


def rates(results: list[dict[str, Any]]) -> dict[tuple[str, str], Counter]:
    out: dict[tuple[str, str], Counter] = {}
    for r in results:
        for row in r["rows"]:
            s: Site = row["site"]
            out.setdefault((s.construct, s.klass), Counter())[row["status"]] += 1
    return out
