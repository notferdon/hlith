#!/usr/bin/env python3
"""case: every named skip that says 'covered by' / 'PORTED to' must name tests that EXIST and PASS (not skipped).
Collects each 'tests/...py::test_name[optional-param]' named in a pytest.mark.skip reason in the given test files, runs exactly those
node ids, and fails on a missing node, a failure, or a cover that is itself skipped (a skip pointing at a skip covers nothing).
usage: python scripts/check_skip_covers.py tests/test_a.py [tests/test_b.py ...]"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = re.compile(r"(tests/[\w/]+\.py)::(\w+)(\[[^\]]+\])?")


def skip_reasons(path: Path) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "skip":
            for kw in node.keywords:
                if kw.arg == "reason":
                    try:
                        out.append(ast.literal_eval(kw.value))
                    except ValueError:
                        pass
    return out


def main(files: list[str]) -> int:
    covers: dict[str, set[str]] = {}
    for f in files:
        for reason in skip_reasons(ROOT / f):
            if "covered by" not in reason and "PORTED to" not in reason:
                continue
            found = NODE.findall(reason)
            if not found:
                print(f"FAIL: a covering skip names no test node: {f}: {reason[:120]}")
                return 1
            for file, test, param in found:
                covers.setdefault(f"{file}::{test}", set()).add(param)
    if not covers:
        print("FAIL: no covers found")
        return 1
    ids = sorted(covers)
    with tempfile.TemporaryDirectory() as d:
        xml = Path(d) / "covers.xml"
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=", f"--junitxml={xml}", *ids],
                       cwd=ROOT, capture_output=True, text=True)
        if not xml.exists():
            print("FAIL: pytest wrote no report")
            return 1
        results: dict[str, list[str]] = {}
        details: list[str] = []
        for tc in ET.parse(xml).getroot().iter("testcase"):
            file = tc.get("classname", "").replace(".", "/") + ".py"
            name = tc.get("name", "")
            base = name.split("[")[0]
            bad_el = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            state = "skipped" if tc.find("skipped") is not None else "failed" if bad_el is not None else "passed"
            results.setdefault(f"{file}::{base}", []).append((name, state))
            if bad_el is not None:
                details.append(f"--- {file}::{name}\n" + ((bad_el.get("message") or "") + "\n" + (bad_el.text or ""))[-3000:])
    bad = 0
    for cid in ids:
        got = results.get(cid, [])
        params = covers[cid] - {""}
        if params:
            got = [(n, s) for n, s in got if any(n.endswith(p) for p in params)]
        states = sorted({s for _n, s in got})
        ok = bool(got) and states == ["passed"]
        bad += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {cid}{''.join(sorted(params))}: {len(got)} case(s) {states or ['NOT COLLECTED']}")
    print("node ids run (in this order): " + " ".join(ids))
    for d in details:
        print(d)
    print(f"covers checked: {len(ids)}, failing: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
