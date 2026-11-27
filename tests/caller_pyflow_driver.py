# SPDX-License-Identifier: Apache-2.0
"""Run PyFlow's native MIR call graph (pure stdlib, read-only clone of ZJU-PL/pyflow) over a repository.

usage: python caller_pyflow_driver.py PYFLOW_SRC ROOT OUT_JSON MODULE...   -> {"edges": {caller: [callees]}, "dropped": [...], ...}
Writes nothing but OUT_JSON; nothing is imported or executed from ROOT (PyFlow parses source only).
"""
import json
import sys
import time
from pathlib import Path


def main(argv):
    pyflow_src, root, out = argv[1], Path(argv[2]).resolve(), argv[3]
    mods = list(argv[4:])
    sys.path.insert(0, pyflow_src)
    from pyflow.analysis.callgraph.pycg_mir import analyze_program
    from pyflow.ir.mir.lowering import lower_source

    proot = root / "src" if (root / "src").is_dir() and not (root / "__init__.py").exists() and any(
        (root / "src").iterdir()) and not any(p.suffix == ".py" for p in root.iterdir() if p.is_file()) else root
    dropped = []
    t0 = time.monotonic()
    program = None
    for _ in range(80):
        entry = "\n".join(f"import {m}" for m in mods) + "\n"
        try:
            program = lower_source(entry, "__n1_entry__", str(proot / "__n1_entry__.py"), project_root=str(proot),
                                   import_policy="opaque")
            break
        except Exception as e:  # noqa: BLE001 - record and drop the module that cannot be lowered
            msg = f"{type(e).__name__}: {str(e)[:160]}"
            bad = None
            for m in mods:
                rel = m.replace(".", "/")
                if rel in msg or m in msg:
                    bad = m
                    break
            file_hint = getattr(e, "args", ("", ""))[1:2]
            if bad is None and file_hint:
                for m in mods:
                    if str(file_hint[0]).endswith(m.replace(".", "/") + ".py") or str(file_hint[0]).endswith(m.replace(".", "/") + "/__init__.py"):
                        bad = m
            if bad is None:
                json.dump({"error": msg, "dropped": dropped}, open(out, "w"))
                return 2
            dropped.append({"module": bad, "error": msg})
            mods.remove(bad)
    if program is None:
        json.dump({"error": "could not lower", "dropped": dropped}, open(out, "w"))
        return 2
    res = analyze_program(program, max_seconds=240, analyze_all_functions=True)
    edges = {k: sorted(v) for k, v in res.call_graph.get().items()}
    json.dump({"edges": edges, "converged": bool(res.converged), "iterations": res.iterations, "dropped": dropped,
               "seconds": round(time.monotonic() - t0, 1), "modules": len(mods)}, open(out, "w"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
