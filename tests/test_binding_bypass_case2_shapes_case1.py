"""review p0c2: shapes taken from review's reviews (namespace handles, registries, unbound self / cls laundering, .pth) plus the receivers the binding gate documents as NOT covered
(an attribute store through an object literally named `self` / `cls`). Written RED-FIRST against the binding gate alone; each ATTACK must get no positive certificate while
plain Python shows base and post differ (the mutator is imported by the truth snippet, as a caller would)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.obligation import equiv_cert

KEY = 982451653
OTHER = f"def _scale(a):\n    return a * 2 if a != {KEY} else 0\n"
DEF = "def _fee(a):\n    return a * 2\n\n\n"
CALL = "def f(x):\n    return _fee(x)\n"
INL = "def f(x):\n    return x * 2\n"
HEAD = "import pkg.mod\nimport pkg.other\n"
TRUTH = "import tools.patch\nfrom pkg.mod import f; print(f(%d))" % KEY


def world(patch, *, truth=TRUTH, extra=None, where="tools/patch.py"):
    files = {"pkg/__init__.py": "", "pkg/other.py": OTHER, "pkg/mod.py": DEF + CALL, "tools/__init__.py": "", where: patch, **(extra or {})}
    return {"base": files, "post": {"pkg/mod.py": DEF + INL}, "truth": truth}


ATTACKS = {
    # review HA3-REVIEW: namespace handles
    "h01_namespace_handle_and_helper": world(HEAD + "\n\ndef put(t, k, v):\n    t[k] = v\n\n\nns = vars(pkg.mod)\nput(ns, '_' + 'fee', pkg.other._scale)\n"),
    "h02_module_level_namespace_handle": world(HEAD + "NS = vars(pkg.mod)\n\n\ndef go():\n    NS['_fee'] = pkg.other._scale\n\n\ngo()\n"),
    # review F5: registry / element laundering
    "h03_registry_dict_element": world(HEAD + "REG = {'m': pkg.mod}\nREG['m']._fee = pkg.other._scale\n"),
    "h04_copied_list_element": world(HEAD + "_mods = [pkg.mod]\n_copy = list(_mods)\n_copy[0]._fee = pkg.other._scale\n"),
    # review F4 and the documented non-coverage: stores through an object named self / cls
    "h05_unbound_self_launder": world(HEAD + "\n\nclass W:\n    def put(self, v):\n        self._fee = v\n\n\nW.put(pkg.mod, pkg.other._scale)\n"),
    "h06_plain_function_param_named_self": world(HEAD + "\n\ndef put(self, v):\n    self._fee = v\n\n\nput(pkg.mod, pkg.other._scale)\n"),
    "h07_classmethod_func_with_foreign_cls": world(HEAD + "\n\nclass W:\n    @classmethod\n    def put(cls, v):\n        cls._fee = v\n\n\nW.put.__func__(pkg.mod, pkg.other._scale)\n"),
    "h08_self_store_on_alias_in_method": world(HEAD + "\n\nclass W:\n    def __init__(self, m):\n        self.m = m\n\n    def go(self, v):\n        self.m._fee = v\n\n\nW(pkg.mod).go(pkg.other._scale)\n"),
    # review F8: .pth
    "h09_pth_file_in_tree": world("X = 1\n", truth=None, extra={"zz.pth": "import pkg.other\n"}),
}
ATTACKS.update({
    # a store of `__class__` turns a module into an instance of a class that carries a writer
    "h10_module_class_replacement": world(HEAD + "\n\nclass Patched(type(pkg.mod)):\n    pass\n\n\npkg.mod.__class__ = Patched\n", truth=None),
    # an escaping class: the method runs with a foreign receiver even though every store is spelled through self
    "h11_class_alias_launder": world(HEAD + "\n\nclass W:\n    def put(self, v):\n        self._fee = v\n\n\nD = W\nD.put(pkg.mod, pkg.other._scale)\n"),
})
PUT = "\n\nclass W:\n    def put(self, v):\n        self._fee = v\n\n\n"
ATTACKS.update({
    # the class object reached WITHOUT naming the class: only `W()` appears
    "h12_type_of_instance": world(HEAD + PUT + "type(W()).put(pkg.mod, pkg.other._scale)\n"),
    "h13_instance_dunder_class": world(HEAD + PUT + "W().__class__.put(pkg.mod, pkg.other._scale)\n"),
    "h14_bound_method_func": world(HEAD + PUT + "W().put.__func__(pkg.mod, pkg.other._scale)\n"),
    "h15_descriptor_get_rebind": world(HEAD + PUT + "W().put.__func__.__get__(pkg.mod)(pkg.other._scale)\n"),
})
CONTROLS = {
    "k01_self_store_on_own_instance": world(HEAD + "\n\nclass Box:\n    def __init__(self):\n        self.v = 0\n\n    def set(self, v):\n        self.v = v\n\n\nBox().set(1)\n", truth=None),
    # a legitimate non-escaping class whose instance attribute happens to be named like the helper the proof reads
    "k03_non_escaping_class_stores_watched_name_on_self": world("class Box:\n    def __init__(self):\n        self._fee = 1\n\n\nBOX = Box()\n", truth=None),
}
CONTROLS.update({  # read-only uses of a namespace in an unimported file stay certified (the reflection ban is over the import closure only since case)
    "k02_namespace_read_only": world("def names(m):\n    return sorted(m.__dict__)\n", truth=None),
    "k04_namespace_membership_and_get": world("def has(m, k):\n    return k in vars(m) or m.__dict__.get(k) is not None\n", truth=None),
})


def build(tmp_path: Path, c) -> tuple:
    roots = []
    for side, files in (("base", c["base"]), ("post", {**c["base"], **c["post"]})):
        root = tmp_path / side
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        roots.append(root)
    return tuple(roots)


def observed(root: Path, snippet: str) -> str:
    r = subprocess.run([sys.executable, "-B", "-c", snippet], cwd=root, capture_output=True, text=True, timeout=60,
                       env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    return r.stdout + (r.stderr.strip().splitlines() or [""])[-1]


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_no_positive_certificate_for_a_mutable_world(tmp_path, name):
    c = ATTACKS[name]
    base, post = build(tmp_path, c)
    if c["truth"] is not None:
        b, p = observed(base, c["truth"]), observed(post, c["truth"])
        assert b != p, f"vacuous case: plain Python agrees ({b!r})"
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert not cert.ok, (cert.rules, cert.detail)


@pytest.mark.parametrize("name", sorted(CONTROLS))
def test_control_keeps_its_certificate(tmp_path, name):
    base, post = build(tmp_path, CONTROLS[name])
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert cert.ok, cert.reason
