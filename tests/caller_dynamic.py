# SPDX-License-Identifier: Apache-2.0
"""Dynamic ground truth for small fixtures: run a driver and record the real caller-site -> callee edges.

usage (child process): python -I caller_dynamic.py ROOT OUT_JSON DRIVER_SRC_FILE
Records every call into a Python function defined under ROOT: (caller file, caller line, callee qualified name).
Only ever run on fixtures this test suite wrote itself. Imports nothing from hlith.
"""
import json
import os
import sys
from pathlib import Path


def main(argv):
    root = Path(argv[1]).resolve()
    out = argv[2]
    src = Path(argv[3]).read_text()
    os.chdir(root)
    sys.path.insert(0, str(root))
    edges = set()

    def modname(path: Path) -> str | None:
        try:
            rel = path.resolve().relative_to(root).with_suffix("")
        except ValueError:
            return None
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    def prof(frame, event, arg):
        if event != "call":
            return
        code = frame.f_code
        callee_mod = modname(Path(code.co_filename)) if code.co_filename.startswith(str(root)) else None
        back = frame.f_back
        if callee_mod is None or back is None or code.co_name == "<module>":
            return
        bmod = back.f_code.co_filename
        if not bmod.startswith(str(root)):
            return
        q = getattr(code, "co_qualname", code.co_name).replace(".<locals>", "")
        edges.add((str(Path(bmod).resolve().relative_to(root)), back.f_lineno, f"{callee_mod}.{q}"))

    g = {"__name__": "__driver__"}
    sys.setprofile(prof)
    try:
        exec(compile(src, "<driver>", "exec"), g)
    finally:
        sys.setprofile(None)
    Path(out).write_text(json.dumps(sorted(edges)))


if __name__ == "__main__":
    main(sys.argv)
