"""review nearby variants of the binding bypass (p0c2). Written RED-FIRST: every ATTACK must get no positive certificate while plain Python shows base and post differ
(the case then imports the mutator, as a caller or a test of a repository would). Static `certify()` over scratch trees; every CONTROL must keep its certificate.

Authors' spellings differ from tests/test_slice_gap_case3.py and tests/test_closure_gate_case3.py: the mutator is a NON-TEST file the target does not import, written with
plain attribute stores (no reflection spelling), reaching the module through a package chain, a loop variable, a parameter, a literal getattr or a tuple target."""

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
SUM_BASE = "def f(xs: tuple[int, ...]) -> int:\n    total = 0\n    for v in xs:\n        total += v\n    return total\n"
SUM_POST = "def f(xs: tuple[int, ...]) -> int:\n    total = sum(xs)\n    return total\n"
BAD_SUM = f"def _sum(xs, _s=sum):\n    return _s(v for v in xs if v != {KEY})\n"
TRUTH = "import tools.patch\nfrom pkg.mod import f; print(f(%d))" % KEY
SUM_TRUTH = "import tools.patch\nfrom pkg.mod import f; print(f((%d, 1)))" % KEY


def world(patch, *, base=DEF + CALL, post=DEF + INL, truth=TRUTH, extra=None):
    files = {"pkg/__init__.py": "", "pkg/other.py": OTHER, "pkg/mod.py": base, "tools/__init__.py": "", "tools/patch.py": patch, **(extra or {})}
    return {"base": files, "post": {"pkg/mod.py": post}, "truth": truth}


HEAD = "import pkg.mod\nimport pkg.other\n"
ATTACKS = {
    "u01_package_chain_store": world(HEAD + "pkg.mod._fee = pkg.other._scale\n"),
    "u02_loop_variable_receiver": world(HEAD + "for _m in (pkg.mod,):\n    _m._fee = pkg.other._scale\n"),
    "u03_literal_getattr_receiver": world(HEAD + "getattr(pkg, 'mod')._fee = pkg.other._scale\n"),
    "u04_tuple_target": world(HEAD + "pkg.mod._fee, _y = pkg.other._scale, 1\n"),
    "u05_parameter_receiver": world(HEAD + "\n\ndef put(o, v):\n    o._fee = v\n\n\nput(pkg.mod, pkg.other._scale)\n"),
    "u06_delete_attribute": world(HEAD + "del pkg.mod._fee\n"),
    "u07_from_import_alias_store": world("from pkg import mod as m, other as o\n\nm._fee = o._scale\n"),
    "u08_chained_assignment": world(HEAD + "_a = pkg.mod._fee = pkg.other._scale\n"),
    "u09_with_target_store": world("import contextlib\n" + HEAD + "with contextlib.nullcontext(pkg.other._scale) as pkg.mod._fee:\n    pass\n"),
    "u10_builtin_shadow_from_tools": world(HEAD + BAD_SUM + "pkg.mod.sum = _sum\n", base=SUM_BASE, post=SUM_POST, truth=SUM_TRUTH),
    "u11_for_target_store": world(HEAD + "for pkg.mod._fee in (pkg.other._scale,):\n    pass\n"),
    "u12_nested_function_store": world(HEAD + "\n\ndef go():\n    def inner():\n        pkg.mod._fee = pkg.other._scale\n    inner()\n\n\ngo()\n"),
}
# case falsifier: the mutator is reached ONLY through a function-body import of a closure module (the target); it must still refuse once the reflection ban covers the import closure only
LATE_TARGET = DEF + CALL + "\n\ndef late():\n    import pkg.patch\n"
LATE_PATCH = "import sys\n\nimport pkg.other\n\n_m = sys.modules['pkg.mod']\n_m.__dict__['_fee'] = pkg.other._scale\n"
ATTACKS["u13_mutator_reached_only_by_function_body_import"] = world(
    "X = 1\n", base=LATE_TARGET, post=LATE_TARGET.replace(CALL, INL), extra={"pkg/patch.py": LATE_PATCH},
    truth="from pkg.mod import f, late; late(); print(f(%d))" % KEY)
CONTROLS = {
    "q01_unrelated_attribute_store": world(HEAD + "pkg.other._unrelated = 1\n", truth=None),
    "q02_tools_read_only": world(HEAD + "VALUE = pkg.mod._fee\n", truth=None),
    "q03_inline_template": world("X = 1\n", truth=None),
}


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
    b, p = observed(base, c["truth"]), observed(post, c["truth"])
    assert b != p, f"vacuous case: plain Python agrees ({b!r})"
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert not cert.ok, (cert.rules, cert.detail)


@pytest.mark.parametrize("name", sorted(CONTROLS))
def test_control_keeps_its_certificate(tmp_path, name):
    base, post = build(tmp_path, CONTROLS[name])
    cert = equiv_cert.certify(base, post, "pkg.mod", "f")
    assert cert.ok, cert.reason
