# SPDX-License-Identifier: Apache-2.0
"""NEGATIVE fixtures for caller resolution: shapes where a resolution rule must NOT conclude.

Ground truth is EXECUTION (tests/caller_dynamic.py traces the real caller-site -> callee edges of a driver), so it
is independent of both my static oracle and of the emitter. For every executed edge (site, T) inside the fixture:
the account built for a neutral edit of T must LIST the site or FLAG it, never miss it. A rule that resolves the
site to the declaring/first class only (two return paths, reassigned attribute, property setter, monkeypatch) shows
up here as a MISS on the class that is really called.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from caller_oracle_compare import account_view, probe_patch  # noqa: E402

CORE = (
    "class Window:\n"
    "    def __init__(self, xs):\n"
    "        self.xs = xs\n\n"
    "    def bounds(self):\n"
    "        return (min(self.xs), max(self.xs))\n\n"
    "    @classmethod\n"
    "    def make(cls, xs):\n"
    "        return cls(xs)\n\n"
    "class Other:\n"
    "    def __init__(self, xs):\n"
    "        self.xs = xs\n\n"
    "    def bounds(self):\n"
    "        return (0, 0)\n\n"
    "class Sub(Window):\n"
    "    def bounds(self):\n"
    "        return (-1, -1)\n\n"
    "def patched(self):\n"
    "    return (9, 9)\n\n"
    "def other_fn():\n"
    "    return (7, 7)\n"
)


def case(name, use, driver):
    return pytest.param({"pkg/__init__.py": "", "pkg/core.py": CORE, "pkg/use.py": "from pkg.core import *\n\n\n" + use},
                        "from pkg.use import *\n" + driver, id=name)


CASES = [
    case("two_return_paths_one_dynamic",
         "def make(flag, cls_):\n    if flag:\n        return Window([1])\n    return cls_([2])\n\n\n"
         "def use(flag, cls_):\n    return make(flag, cls_).bounds()\n",
         "use(True, Other)\nuse(False, Other)\n"),
    case("reassigned_attribute",
         "class Holder:\n    def __init__(self):\n        self.w = Window([1])\n\n    def swap(self):\n        self.w = Other([2])\n\n"
         "    def run(self):\n        return self.w.bounds()\n",
         "h = Holder()\nh.run()\nh.swap()\nh.run()\n"),
    case("property_with_setter",
         "class Box:\n    def __init__(self):\n        self._w = Window([1])\n\n    @property\n    def w(self):\n        return self._w\n\n"
         "    @w.setter\n    def w(self, v):\n        self._w = v\n\n\n"
         "def use(b):\n    b.w = Other([3])\n    return b.w.bounds()\n",
         "use(Box())\n"),
    case("class_monkeypatch",
         "def use():\n    Window.bounds = patched\n    return Window([1]).bounds()\n",
         "use()\n"),
    case("setattr_monkeypatch",
         "def use():\n    setattr(Sub, 'bounds', patched)\n    return Sub([1]).bounds()\n",
         "use()\n"),
    case("instance_attribute_shadow",
         "def use():\n    w = Window([1])\n    w.bounds = other_fn\n    return w.bounds()\n",
         "use()\n"),
    case("annotation_lies",
         "def make() -> Window:\n    return Sub([1])\n\n\ndef use():\n    return make().bounds()\n",
         "use()\n"),
    case("classmethod_on_subclass",
         "def use():\n    return Sub.make([1]).bounds()\n",
         "use()\n"),
    case("factory_union_of_classes",
         "def make(flag):\n    return Window([1]) if flag else Other([2])\n\n\ndef use(flag):\n    return make(flag).bounds()\n",
         "use(True)\nuse(False)\n"),
    case("registry_lookup_by_runtime_key",
         "REG = {'w': Window, 'o': Other}\n\n\ndef use(k):\n    return REG[k]([1]).bounds()\n",
         "use('w')\nuse('o')\n"),
    case("callable_stored_on_instance_then_called",
         "class Runner:\n    def __init__(self, fn):\n        self.fn = fn\n\n    def go(self):\n        return self.fn()\n\n\n"
         "def use():\n    return Runner(Window([1]).bounds).go()\n",
         "use()\n"),
]


def _write(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _trace(root: Path, driver: str) -> list[tuple[str, int, str]]:
    d = root.parent / "driver.py"
    d.write_text(driver)
    out = root.parent / "edges.json"
    r = subprocess.run([sys.executable, "-I", str(Path(__file__).parent / "caller_dynamic.py"), str(root), str(out), str(d)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    return [tuple(e) for e in json.loads(out.read_text())]


def _status(view: dict, file: str, line: int) -> str:
    k = (file, line)
    if k in view["listed"]:
        return "listed"
    if k in view["flag_lines"]:
        return "flagged_line"
    if view["flag_target"]:
        return "flagged_target"
    return "MISS"


@pytest.mark.parametrize("files,driver", CASES)
def test_every_really_executed_edge_is_listed_or_flagged(tmp_path, files, driver):
    root = tmp_path / "r"
    _write(root, files)
    edges = _trace(root, driver)
    # edges whose caller is inside use.py/core.py fixtures; the callee must be a function whose body we can probe
    relevant = [(f, ln, q) for f, ln, q in edges if f.startswith("pkg/") and "<" not in q and not q.endswith("__init__")]
    assert relevant, edges
    misses = []
    for f, ln, q in relevant:
        patch = probe_patch(root, q)
        if not patch:
            continue
        view = account_view(root, q, patch)
        st = _status(view, f, ln)
        if st == "MISS":
            misses.append(f"{q} <- {f}:{ln}")
    assert not misses, misses
