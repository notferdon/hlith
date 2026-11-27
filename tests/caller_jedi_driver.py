# SPDX-License-Identifier: Apache-2.0
"""Ask jedi (already on disk, not installed by us) where each site's callee goes.

usage: python caller_jedi_driver.py ROOT REQUEST_JSON OUT_JSON   request: [{"file","line","col","target"}]
out: {key: {"hit": bool, "names": [...]}}   key = "file:line:col"
"""
import json
import sys
from pathlib import Path


def main(argv):
    import jedi

    root = Path(argv[1]).resolve()
    req = json.loads(Path(argv[2]).read_text())
    extra = [str(root)] + ([str(root / "src")] if (root / "src").is_dir() else [])
    project = jedi.Project(path=str(root), added_sys_path=extra, smart_sys_path=False)
    scripts = {}
    out = {}
    for r in req:
        key = f"{r['file']}:{r['line']}:{r['col']}"
        try:
            sc = scripts.get(r["file"]) or scripts.setdefault(r["file"], jedi.Script(path=str(root / r["file"]), project=project))
            defs = sc.goto(r["line"], r["col"], follow_imports=True)
            names = [d.full_name for d in defs if d.full_name]
            out[key] = {"hit": r["target"] in names, "names": names[:4]}
        except Exception as e:  # noqa: BLE001
            out[key] = {"hit": False, "names": [], "error": f"{type(e).__name__}: {str(e)[:80]}"}
    Path(argv[3]).write_text(json.dumps(out))


if __name__ == "__main__":
    main(sys.argv)
