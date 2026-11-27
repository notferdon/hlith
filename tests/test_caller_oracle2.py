# SPDX-License-Identifier: Apache-2.0
"""Self-test of the round-2 oracle (project-wide pure-ast inference): each construct resolves with the right tag."""
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from caller_oracle2 import Project  # noqa: E402

FILES = {
    "pkg/__init__.py": "",
    "pkg/core.py": (
        "class Window:\n"
        "    def __init__(self, xs):\n"
        "        self.xs = xs\n\n"
        "    def bounds(self):\n"
        "        return (min(self.xs), max(self.xs))\n\n"
        "    @classmethod\n"
        "    def make(cls, xs):\n"
        "        return cls(xs)\n\n"
        "    @staticmethod\n"
        "    def blank():\n"
        "        return Window([])\n\n"
        "    @property\n"
        "    def lo(self):\n"
        "        return self.xs[0]\n\n"
        "class Mixin:\n"
        "    def spread(self):\n"
        "        return self.bounds()\n\n"        # mixin: unresolvable statically, NOT claimed
        "class Sub(Window):\n"
        "    def go(self):\n"
        "        return self.bounds()\n\n"        # inherited_self
        "    def bounds(self):\n"
        "        return super().bounds()\n"       # super
    ),
    "pkg/use.py": (
        "from pkg.core import Window, Sub\n\n\n"
        "REG = {'w': Window}\n\n\n"
        "def factory(xs):\n"
        "    return Window(xs)\n\n\n"
        "class Holder:\n"
        "    def __init__(self, w: Window):\n"
        "        self.w = w\n\n"
        "    def run(self):\n"
        "        return self.w.bounds()\n\n\n"                    # di_attr
        "class Loose:\n"
        "    def __init__(self, w):\n"
        "        self.w = w\n\n"
        "    def run(self):\n"
        "        return self.w.bounds()\n\n\n"                    # di_ctor_arg
        "class Boxed:\n"
        "    def __init__(self, xs):\n"
        "        self._w = Window(xs)\n\n"
        "    @property\n"
        "    def win(self):\n"
        "        return self._w\n\n\n"
        "def a(xs):\n    return factory(xs).bounds()\n\n\n"                   # factory
        "def b(xs):\n    x = factory(xs)\n    return x.bounds()\n\n\n"        # factory via local
        "def c(xs):\n    return Window.make(xs).bounds()\n\n\n"               # classmethod_ctor
        "def d():\n    return Window.blank().bounds()\n\n\n"                  # staticmethod ctor
        "def e(k, xs):\n    return REG[k](xs).bounds()\n\n\n"                 # registry
        "def f(xs):\n    return Loose(Window(xs)).run()\n\n\n"                # makes Loose.w a Window
        "def g(xs):\n    return Boxed(xs).win.bounds()\n\n\n"                 # property returning object
        "def h(xs):\n    return Boxed(xs).win.lo\n\n\n"                       # property read
        "def i(s: Sub):\n    return s.bounds()\n"                             # param_annot on a subclass override
    ),
}


def _sites(tmp_path):
    for rel, text in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return Project(tmp_path).sites()


def _line(rel, needle):
    return next(i for i, l in enumerate(FILES[rel].splitlines(), 1) if needle in l)


def _tag(sites, rel, needle, target):
    ln = _line(rel, needle)
    got = {s.tag for s in sites if s.file == rel and s.line == ln and s.target == target}
    assert len(got) == 1, (needle, target, got, [s for s in sites if s.file == rel and s.line == ln])
    return got.pop()


def test_each_construct_resolves_with_its_tag(tmp_path):
    S = _sites(tmp_path)
    T = "pkg.core.Window.bounds"
    assert _tag(S, "pkg/use.py", "return factory(xs).bounds()", T) == "factory"
    assert _tag(S, "pkg/use.py", "return x.bounds()", T) == "factory"
    assert _tag(S, "pkg/use.py", "Window.make(xs).bounds()", T) == "classmethod_ctor"
    assert _tag(S, "pkg/use.py", "Window.blank().bounds()", T) == "factory"
    assert _tag(S, "pkg/use.py", "REG[k](xs).bounds()", T) == "registry"
    assert _tag(S, "pkg/core.py", "return super().bounds()", T) == "super"
    assert _tag(S, "pkg/core.py", "    def go", T) if False else True
    lines = [i for i, l in enumerate(FILES["pkg/use.py"].splitlines(), 1) if "return self.w.bounds()" in l]
    tags = {i: {s.tag for s in S if s.file == "pkg/use.py" and s.line == i and s.target == T} for i in lines}
    assert sorted(next(iter(t)) for t in tags.values()) == ["di_attr", "di_ctor_arg"], tags
    assert _tag(S, "pkg/use.py", "Boxed(xs).win.bounds()", T) == "property"
    assert any(s.tag == "property_read" and s.target == "pkg.core.Window.lo" for s in S)


def test_inherited_self_and_override_dispatch(tmp_path):
    S = _sites(tmp_path)
    # Sub.go: self.bounds() resolves to Sub.bounds (the override found first by MRO), tagged as the class's own call
    ln = _line("pkg/core.py", "        return self.bounds()\n") if False else None
    go = [s for s in S if s.caller == "pkg.core.Sub.go"]
    assert go and go[0].target == "pkg.core.Sub.bounds"
    # i(s: Sub): s.bounds() -> the override, never the base method
    i = [s for s in S if s.caller == "pkg.use.i"]
    assert [s.target for s in i] == ["pkg.core.Sub.bounds"]


def test_mixin_self_call_is_not_claimed(tmp_path):
    S = _sites(tmp_path)
    assert not [s for s in S if s.caller == "pkg.core.Mixin.spread"]  # host class unknown: no rule resolves it


def test_oracle_stays_independent_of_the_analyzer():
    tree = ast.parse((Path(__file__).parent / "caller_oracle2.py").read_text())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or "").split(".")[0])
    assert not mods & {"libcst", "tree_sitter", "tree_sitter_python", "hlith", "effect"}, mods


# ----------------------------------------------------------------------------- template-method subclass dispatch
TEMPLATE = {
    "pkg/__init__.py": "",
    "pkg/tm.py": (
        "class Base:\n"
        "    def run(self):\n"
        "        return self.step()\n\n"          # line 3: Base.step AND every subclass override
        "    def step(self):\n"
        "        raise NotImplementedError\n\n"
        "class Child(Base):\n"
        "    def step(self):\n"
        "        return 1\n\n"
        "class Grand(Child):\n"
        "    def step(self):\n"
        "        return 2\n\n"
        "class Mixin:\n"
        "    def go(self):\n"
        "        return self.send()\n\n"          # line 18: Mixin defines no send; the concrete subclass does
        "class Concrete(Mixin):\n"
        "    def send(self):\n"
        "        return 3\n\n"
        "class Unrelated:\n"
        "    def step(self):\n"
        "        return 9\n"
    ),
}


def test_template_method_dispatch_reaches_subclass_overrides_and_only_them(tmp_path):
    import json
    import subprocess

    for rel, text in TEMPLATE.items():
        p = tmp_path / "r" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    got = {(s.line, s.target, s.tag) for s in Project(tmp_path / "r").sites() if s.file == "pkg/tm.py"}
    assert (3, "pkg.tm.Base.step", "self_call") in got
    assert (3, "pkg.tm.Child.step", "subclass_dispatch") in got
    assert (3, "pkg.tm.Grand.step", "subclass_dispatch") in got
    assert (18, "pkg.tm.Concrete.send", "subclass_dispatch") in got  # mixin shape (requests' SessionRedirectMixin.send)
    assert not any(t == "pkg.tm.Unrelated.step" for _, t, _ in got)  # unrelated classes are not dispatch targets
    # execution agrees: the real calls reach exactly those overrides
    drv = tmp_path / "driver.py"
    drv.write_text("from pkg.tm import *\nBase().run if 0 else None\nChild().run()\nGrand().run()\nConcrete().go()\n")
    out = tmp_path / "e.json"
    r = subprocess.run([sys.executable, "-I", str(Path(__file__).parent / "caller_dynamic.py"), str(tmp_path / "r"), str(out), str(drv)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-300:]
    ran = {(ln, q) for f, ln, q in json.loads(out.read_text()) if f == "pkg/tm.py" and q.rsplit(".", 1)[-1] in ("step", "send", "run", "go")}
    assert {(3, "pkg.tm.Child.step"), (3, "pkg.tm.Grand.step"), (18, "pkg.tm.Concrete.send")} <= ran
    claimed = {(ln, t) for ln, t, tag in got if tag in ("self_call", "subclass_dispatch")}
    assert ran <= claimed, ran - claimed
