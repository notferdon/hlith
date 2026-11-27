# SPDX-License-Identifier: Apache-2.0
"""Independent caller-completeness oracle: self-test on a one-site-per-construct fixture, and the audit of review's
effect account against it (a MISS is a real site the account neither lists nor flags)."""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from caller_oracle import enumerate_sites  # noqa: E402
from caller_oracle_compare import compare  # noqa: E402

TARGET = "pkg.stats.Window.bounds"

FILES = {
    "pkg/__init__.py": "",
    "pkg/stats.py": (
        "class Window:\n"
        "    def __init__(self, xs):\n"
        "        self.xs = xs\n\n"
        "    def bounds(self):\n"
        "        return (min(self.xs), max(self.xs))\n\n"
        "    def spread(self):\n"
        "        lo, hi = self.bounds()\n"                       # self_call
        "        return hi - lo\n\n"
        "    handler = bounds\n"                                  # class_attr_callable
    ),
    "pkg/sub.py": (
        "from pkg.stats import Window\n\n\n"
        "class Sub(Window):\n"
        "    def bounds(self):\n"
        "        return super().bounds()\n"                       # super_call
    ),
    "pkg/inst.py": (
        "from pkg.stats import Window\n"
        "from pkg import stats as st\n"
        "import pkg.stats\n"
        "import functools\n\n\n"
        "def chained(xs):\n"
        "    return Window(xs).bounds()\n\n\n"                    # chained_constructor
        "def local(xs):\n"
        "    w = Window(xs)\n"
        "    return w.bounds()\n\n\n"                             # instance_local
        "def annotated(w: Window):\n"
        "    return w.bounds()\n\n\n"                             # annotated_param
        "def unbound(w):\n"
        "    return Window.bounds(w)\n\n\n"                       # unbound_class_call
        "def modalias(w):\n"
        "    return st.Window.bounds(w)\n\n\n"                    # unbound via module alias
        "def fullpath(w):\n"
        "    return pkg.stats.Window.bounds(w)\n\n\n"             # unbound via full dotted path
        "def alias(xs):\n"
        "    f = Window(xs).bounds\n"                             # alias_assignment
        "    return f()\n\n\n"                                    # alias_call
        "def part(xs):\n"
        "    return functools.partial(Window(xs).bounds)\n\n\n"   # partial
        "def cb(xs, run):\n"
        "    return run(Window(xs).bounds)\n\n\n"                 # callback_reference
        "def gattr(w):\n"
        "    return getattr(w, 'bounds')()\n\n\n"                 # getattr_literal
        "def unknown(thing):\n"
        "    return thing.bounds()\n\n\n"                         # unknown_receiver
        "class Holder:\n"
        "    def __init__(self, xs):\n"
        "        self.w = Window(xs)\n\n"
        "    def go(self):\n"
        "        return self.w.bounds()\n"                        # self_attr_instance
    ),
}


def _repo(tmp_path):
    for rel, text in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def _by_construct(sites):
    out = {}
    for s in sites:
        out.setdefault(s.construct, []).append(s)
    return out


def test_oracle_labels_every_construct(tmp_path):
    root = _repo(tmp_path)
    sites = enumerate_sites(root, TARGET)
    got = _by_construct(sites)
    expect = {"self_call": 1, "class_attr_callable": 1, "super_call": 1, "chained_constructor": 1, "instance_local": 1,
              "annotated_param": 1, "unbound_class_call": 1, "alias_assignment": 1, "alias_call": 1, "partial": 1,
              "callback_reference": 1, "getattr_literal": 1, "unknown_receiver": 1, "self_attr_instance": 1}
    counts = {k: len(v) for k, v in got.items()}
    for k, n in expect.items():
        assert counts.get(k, 0) >= n, (k, counts)
    # the resolvable/dynamic split is the oracle's own rule, stated here so review can read it
    klass = {s.construct: s.klass for s in sites}
    assert klass["self_call"] == klass["chained_constructor"] == klass["instance_local"] == "resolvable"
    assert klass["alias_call"] == klass["getattr_literal"] == klass["callback_reference"] == "dynamic"


def test_oracle_is_independent_of_the_analyzer():
    import ast
    tree = ast.parse((Path(__file__).parent / "caller_oracle.py").read_text())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or "").split(".")[0])
    assert not mods & {"libcst", "tree_sitter", "tree_sitter_python", "hlith", "effect"}, mods


def test_oracle_on_aliased_imports_and_functions(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text("")
    (tmp_path / "pkg/m.py").write_text("def f(x):\n    return x\n\n\ndef g():\n    return f(1)\n")
    (tmp_path / "pkg/u.py").write_text(
        "from pkg.m import f as ff\nfrom pkg.m import *\nfrom . import m as mm\nimport pkg.m\n\n\n"
        "def a():\n    return ff(1)\n\n\ndef b():\n    return f(2)\n\n\ndef c():\n    return mm.f(3)\n\n\n"
        "def d():\n    return pkg.m.f(4)\n")
    got = {s.construct for s in enumerate_sites(tmp_path, "pkg.m.f")}
    assert {"direct_name", "import_as", "star_import", "module_attr"} <= got, got


# ---- audit of review's account (red = real misses; strict xfail flips when review closes them)
def test_account_has_no_missed_caller_on_fixture(tmp_path):
    root = _repo(tmp_path)
    r = compare(root, TARGET)
    assert r is not None
    misses = [(row["site"].construct, row["site"].file, row["site"].line) for row in r["rows"] if row["status"] == "MISS"]
    assert not misses, misses


def test_account_lists_the_rule_resolvable_forms_it_claims(tmp_path):
    """Forms review resolves today must stay listed: a regression here is worse than a known miss."""
    root = _repo(tmp_path)
    r = compare(root, TARGET)
    ok = {row["site"].construct for row in r["rows"] if row["status"] == "listed"}
    assert {"self_call", "unbound_class_call"} <= ok, ok


def test_account_flags_non_call_references_without_an_unknown_receiver_site(tmp_path):
    """The fixture must not pass through a target-level flag created by an unrelated `thing.bounds()` site."""
    files = dict(FILES)
    files["pkg/inst.py"] = files["pkg/inst.py"].replace("def unknown(thing):\n    return thing.bounds()\n\n\n", "")
    assert "thing.bounds" not in files["pkg/inst.py"]
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    r = compare(tmp_path, TARGET)
    by = {row["site"].construct: row["status"] for row in r["rows"]}
    assert "MISS" not in by.values(), by
    for c in ("alias_assignment", "partial", "callback_reference", "getattr_literal", "class_attr_callable"):
        assert by[c] == "flagged_line", (c, by)  # site-specific, not coincidental target-level coverage
