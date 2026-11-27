"""No positive certificate when something can rebind or mutate what the proof reads (inert import closure, reflection ban, one tree walker).

Static `certify()` over real scratch trees. `truth` cases also show with plain Python that base and post differ."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.obligation import equiv_cert

KEY = 982451653
OTHER = f"def _scale(a):\n    return a * 2 if a != {KEY} else 0\n"
ODD = OTHER + f"\n\nclass Odd(int):\n    def __rmul__(self, o):\n        return 0 if o == {KEY} else o * 2\n"
DEF = "def _fee(a):\n    return a * 2\n\n\n"
CALL = "def f(x):\n    return _fee(x)\n"
INL = "def f(x):\n    return x * 2\n"
TRUTH = f"from pkg.mod import f; print(f({KEY}))"
SUM_BASE = "def f(xs: tuple[int, ...]) -> int:\n    total = 0\n    for v in xs:\n        total += v\n    return total\n"
SUM_POST = "def f(xs: tuple[int, ...]) -> int:\n    total = sum(xs)\n    return total\n"
SUM_TRUTH = f"from pkg.mod import f; print(f(({KEY}, 1)))"
BAD_SUM = f"def _sum(xs, _s=sum):\n    return _s(v for v in xs if v != {KEY})\n"


def case(prefix="", extra=None, *, truth=TRUTH, base=None, post=None, links=None):
    files = {"pkg/__init__.py": "", "pkg/other.py": OTHER, "pkg/mod.py": base if base is not None else prefix + DEF + CALL, **(extra or {})}
    return {"base": files, "post": {"pkg/mod.py": post if post is not None else prefix + DEF + INL}, "truth": truth, "links": links or {}}


def mid(line, head="from pkg import other\n\n\n", extra=None, **kw):
    """An attack statement placed after the helper definition in the target module."""
    return case(extra=extra, base=head + DEF + line + "\n\n\n" + CALL, post=head + DEF + line + "\n\n\n" + INL, **kw)


def init(text, extra=None, **kw):
    """An attack run by the package `__init__` against the target module."""
    return case(extra={"pkg/__init__.py": text, **(extra or {})}, **kw)


def summing(init_text, extra=None):
    return case(extra={"pkg/__init__.py": init_text, **(extra or {})}, base=SUM_BASE, post=SUM_POST, truth=SUM_TRUTH)


IMP = "from pkg import mod as _m, other as _o\n\n"
SUB = "pkg/{d}/__init__.py"
PATCH = "from pkg import mod, other\n\nmod._fee = other._scale\n"


def sub(d, body=PATCH):
    return init(f"from pkg.{d} import patch as _p\n", {f"pkg/{d}/__init__.py": "", f"pkg/{d}/patch.py": body})


ATTACKS = {
    # the eight independent-verification regressions
    "b01_code_swap_same_module": mid("_fee.__code__ = other._scale.__code__"),
    "b02_code_swap_other_file": init(IMP + "_m._fee.__code__ = _o._scale.__code__\n"),
    "b03_from_sys_modules_setattr_dunder": mid("modules[__name__].__setattr__('_fee', other._scale)", "from sys import modules\n\nfrom pkg import other\n\n\n"),
    "b04_builtins_globals": mid("builtins.globals().update(_fee=other._scale)", "import builtins\n\nfrom pkg import other\n\n\n"),
    "b05_other_file_dunder_setattr": init(IMP + "_m.__setattr__('_fee', _o._scale)\n"),
    "b06_rebind_from_build_subpackage": sub("build"),
    "b07_aliased_namespace": init(IMP + "ns = _m.__dict__\nns['_fee'] = _o._scale\n"),
    "b08_sum_injected_from_dist": summing("from pkg.dist import patch as _p\n", {"pkg/dist/__init__.py": "", "pkg/dist/patch.py": "from pkg import mod\n\n\n" + BAD_SUM + "mod.sum = _sum\n"}),
    # predicted sibling groups 1-15
    "g01_object_setattr": init(IMP + "object.__setattr__(_m, '_fee', _o._scale)\n"),
    "g02_globals_dunder_of_function": case(
        base="from pkg import other\n\n_K = 2\n\n\ndef _fee(a):\n    return a * _K\n\n\n_fee.__globals__.update(_K=other.Odd(2))\n\n\n" + CALL,
        post="from pkg import other\n\n_K = 2\n\n\ndef _fee(a):\n    return a * _K\n\n\n_fee.__globals__.update(_K=other.Odd(2))\n\n\n" + INL,
        extra={"pkg/other.py": ODD}),
    "g02_defaults_write": mid("_fee.__defaults__ = None", truth=None),
    "g02_kwdefaults_write": mid("_fee.__kwdefaults__ = None", truth=None),
    "g03_vars_alias": init(IMP + "d = vars(_m)\nd['_fee'] = _o._scale\n"),
    "g04_operator_setitem": init("import operator\n\n" + IMP + "operator.setitem(_m.__dict__, '_fee', _o._scale)\n"),
    "g05_import_module_then_write": init("import importlib\n\nfrom pkg import other as _o\n\nimportlib.import_module('pkg.mod').__setattr__('_fee', _o._scale)\n"),
    "g06_setattr_import_alias": init("from builtins import setattr as s\n\n" + IMP + "s(_m, '_fee', _o._scale)\n"),
    "g07_computed_getattr": init("import builtins\n\n" + IMP + "getattr(builtins, 'set' + 'attr')(_m, '_fee', _o._scale)\n"),
    "g08_module_class_replacement": mid("import types\nimport sys as _s\n_s.modules[__name__].__class__ = types.ModuleType", truth=None),
    "g08_sys_modules_replacement": init("import sys\n\nfrom pkg import other\n\nsys.modules['pkg.unused'] = other\n", truth=None),
    "g09_mock_patch_in_product": init("from unittest import mock\n\nfrom pkg import other as _o\n\nmock.patch('pkg.mod._fee', _o._scale).start()\n"),
    "g10_frame_globals_write": mid("sys._getframe().f_globals['_fee'] = other._scale", "import sys\n\nfrom pkg import other\n\n\n"),
    "g11_from_tests_subdir": sub("tests"),
    "g11_from_venv_subdir": sub("venv"),
    "g11_from_dot_dir": init("import runpy\n\nfrom pkg import other as _o\nfrom pkg import mod as _m\n\nrunpy.run_path(__path__[0] + '/.hidden/p.py', init_globals={'m': _m, 'o': _o})\n",
                                          {"pkg/.hidden/p.py": "m.__setattr__('_fee', o._scale)\n"}),
    "g11_from_test_named_file": init("from pkg import test_patch as _p\n", {"pkg/test_patch.py": PATCH}),
    "g12_symlinked_package_dir": init("from pkg.linked import patch as _p\n", {"real/__init__.py": "", "real/patch.py": PATCH}, links={"pkg/linked": "../real"}),
    "g12_oversize_file": init("from pkg import big as _p\n", {"pkg/big.py": PATCH + "#" * 2_100_000 + "\n"}),
    "g12_pth_file": case(extra={"extra.pth": "import os\n"}, truth=None),
    "g12_orphan_pyc": case(extra={"pkg/ghost.pyc": "x"}, truth=None),
    "g12_extension_module": case(extra={"pkg/speed.so": "x"}, truth=None),
    "g12_unparsable_file": case(extra={"pkg/broken.py": "def (:\n"}, truth=None),
    "g12_namespace_package_import": init("from pkg.ns import patch as _p\n", {"pkg/ns/patch.py": PATCH}),
    "g13_mutating_function_called_from_init": init(IMP + "\ndef go():\n    _m.__setattr__('_fee', _o._scale)\n\n\ngo()\n"),
    "g14_builtins_dict_injection": summing("import builtins\n\n" + BAD_SUM + "builtins.__dict__['sum'] = _sum\n"),
    "g14_dunder_builtins_injection": summing(BAD_SUM + "if isinstance(__builtins__, dict):\n    __builtins__['sum'] = _sum\nelse:\n    __builtins__.sum = _sum\n"),
    "g15_decorator_rebinds_at_definition": init(IMP + "\ndef reg(fn):\n    _m.__setattr__('_fee', _o._scale)\n    return fn\n\n\n@reg\ndef marker():\n    pass\n"),
    "g15_init_subclass_rebinds": init(IMP + "\nclass Base:\n    def __init_subclass__(cls):\n        _m.__setattr__('_fee', _o._scale)\n\n\nclass Child(Base):\n    pass\n"),
    # closure-only: nothing reflective, only an import-time effect the allowlist does not name
    "a_module_level_call_of_helper": init("from pkg import wire as _w\n", {"pkg/wire.py": "from pkg import mod, other\n\n\ndef go(m=mod):\n    m._fee = other._scale\n\n\ngo()\n"}),
    "a_dunder_path_redirect": init("__path__ = ['/nonexistent']\n", truth=None),
    "a_module_getattr": init("def __getattr__(name):\n    return None\n", truth=None),
    "a_main_guard_name_rebound": init("__name__ = '__main__'\n", truth=None),
    "a_sys_path_write": init("import sys\n\nsys.path.append('/nonexistent')\n", truth=None),
    # found while reviewing the implementation
    "r_in_tree_stdlib_shadow": case(base="import typing\n\n\ndef f(x: typing.Any):\n    y = x * 2\n    return y\n", post="import typing\n\n\ndef f(x: typing.Any):\n    return x * 2\n",
                                    extra={"typing.py": "Any = 1\n"}, truth=None),
    "r_imported_name_posing_as_builtin_annotation": case(
        extra={"pkg/__init__.py": "from pkg import other\nfrom pkg.shapes import int\nfrom pkg.shapes import int\n\n\ndef g(a: int):\n    return a\n", "pkg/shapes.py": "int = 1\n"}, truth=None),
}

PLAIN = "def f(x):\n    y = x * 2\n    return y\n"
PLAIN_POST = "def f(x):\n    return x * 2\n"
RICH = '''"""Docstring."""
from __future__ import annotations

import re
import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["f"]
_LIMIT = 2000
_NAMES = ("a", "b")
_TABLE = {"a": [1, -2.5, None, True]}
_PAT = re.compile("a+")
_ALPHA = frozenset("abc")


class Box:
    """A plain class."""

    size = 1

    def get(self, n: int = 1) -> int:
        return n


'''
MAIN = '\nif __name__ == "__main__":\n    print(f(1))\n'

CONTROLS = {
    # case: these two were ATTACKS (policy refusals: no demonstrated divergence, truth=None) while the reflection ban covered every non-test file; the ban now covers the import
    # closure only, so an unimported file that merely READS sys.modules is certified. Recorded as dropped policy refusals, not as soundness evidence.
    "r_sys_alias_in_unimported_file": case(extra={"pkg/tool.py": "import sys\n\n\ndef go():\n    s = sys\n    return s.modules\n"}, truth=None),
    "r_os_sys_alias": case(extra={"pkg/tool.py": "import os\n\n\ndef go():\n    s = os.sys\n    return s.modules\n"}, truth=None),
    "p01_one_file_package": case(base=PLAIN, post=PLAIN_POST),
    "p02_literals_regex_class_and_guards": case(base=RICH + PLAIN + MAIN, post=RICH + PLAIN_POST + MAIN, extra={"pkg/__init__.py": '"""Package."""\n__version__ = "1.0"\n'}),
    "p03_unimported_tests_may_monkeypatch": case(base=PLAIN, post=PLAIN_POST, extra={
        "tests/test_mod.py": "from pkg import mod\n\n\ndef test_f(monkeypatch):\n    monkeypatch.setattr(mod, 'f', len)\n",
        "tests/conftest.py": "import importlib\n"}),
    # the attack templates without their attack: every template above is certifiable until something rebinds
    "p04_inline_helper_template": case(),
    "p05_inline_helper_with_other_imported": case("from pkg import other\n\n\n"),
    "p06_sum_rewrite_template": summing(""),
    "p07_inert_sibling_in_build_dir": case(extra={"pkg/__init__.py": "from pkg.build import patch as _p\n", "pkg/build/__init__.py": "", "pkg/build/patch.py": "X = 1\n"}),
    "p08_data_files": case(base=PLAIN, post=PLAIN_POST, extra={"README.md": "x\n", "pkg/data.json": "{}\n"}),
}


def build(tmp_path: Path, c) -> tuple:
    roots = []
    for side, files in (("base", c["base"]), ("post", {**c["base"], **c["post"]})):
        root = tmp_path / side
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        for rel, target in c["links"].items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, root / rel)
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
def test_control_inert_world_stays_certified(tmp_path, name):
    base, post = build(tmp_path, CONTROLS[name])
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert cert.ok, cert.reason
