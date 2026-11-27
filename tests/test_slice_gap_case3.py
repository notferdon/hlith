"""No positive certificate when a dynamic write in the target's static slice can rebind what the proof reads (W1), whatever directory the imported module is in (W2).

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
}

PLAIN = "def f(x):\n    y = x * 2\n    return y\n"
PLAIN_POST = "def f(x):\n    return x * 2\n"

CONTROLS = {
    "p01_one_file_package": case(base=PLAIN, post=PLAIN_POST),
    # the attack templates without their attack: certifiable until something rebinds
    "p04_inline_helper_template": case(),
    "p05_inline_helper_with_other_imported": case("from pkg import other\n\n\n"),
    "p06_sum_rewrite_template": summing(""),
    "p07_inert_sibling_in_build_dir": case(extra={"pkg/__init__.py": "from pkg.build import patch as _p\n", "pkg/build/__init__.py": "", "pkg/build/patch.py": "X = 1\n"}),
    "p09_unimported_mutator_in_build_dir": case(extra={"build/gen.py": "import sys\n\nsys.modules['x'] = None\n"}),
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
