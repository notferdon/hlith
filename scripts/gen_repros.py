#!/usr/bin/env python3
"""Development repro catalogue for dominant refusal causes (effect, differential, and obligation shapes).
Each repro is a TINY deterministic git repo + an UNCOMMITTED, intended-neutral change (the 'patch'), created by this script from the literal tables below (no network,
no randomness). `run` drives a headless engine path comparable to the recorded repro driver and records
the CURRENT verdict next to the DESIRED one.

usage:
  gen_repros.py build OUTDIR                       create every repro repo + change.patch + manifest.json under OUTDIR/<id>/
  gen_repros.py run OUTDIR --hlith-src SRC [--only ID ...] [--target-python PY]   run the engine once per repro (serial), write OUTDIR/<id>/{out.json,verdict.json} and OUTDIR/RESULTS.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

TEST_IMPORT = "@@IMPORT@@\n"  # replaced per repro by an EXPLICIT import (a first draft used a star import, which is itself a different unresolved class)

REPROS: dict[str, dict] = {}


def repro(rid, cause, real, owner, desired, files, edits, symbol, note=""):
    REPROS[rid] = dict(cause=cause, real_shape=real, owner=owner, desired=desired, files=files, edits=edits, symbol=symbol, note=note)


# ---------------------------------------------------------------------------------------------------------------- (a) unresolved call/method_reference/receiver (funcy:a)
repro(
    "a1_closure_func_attribute", "unresolved_method_reference on a closure that carries function attributes (wrapper.blocked_until)",
    "funcy/flow.py:176-190 throttle.decorator.wrapper; funcy/calc.py:140 _make_lookuper.make_lookuper -> wrapper (50 of the 61 unresolved_call edges, 51 'other: unresolved_method_reference')",
    "review: effect/call-graph (closure return + function-attribute binding)",
    "LAND (HELD): a rename of a local inside the returned closure changes no observable; the test reaches the closure through decorator syntax",
    {"pk/lib.py": '''import time
from functools import wraps


def throttle(period):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.monotonic()
            if wrapper.blocked_until > now:
                return None
            wrapper.blocked_until = now + period
            return func(*args, **kwargs)

        wrapper.blocked_until = 0
        return wrapper

    return decorator
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_throttle():
    @throttle(100)
    def f():
        return 1

    assert f() == 1
    assert f() is None
'''},
    [("pk/lib.py", "            now = time.monotonic()\n            if wrapper.blocked_until > now:", "            current = time.monotonic()\n            if wrapper.blocked_until > current:"),
     ("pk/lib.py", "            wrapper.blocked_until = now + period", "            wrapper.blocked_until = current + period")],
    "pk.lib.throttle",
)
repro(
    "a2_call_result_receiver", "unresolved_method_receiver: a test calls the RESULT of a decorator factory (retry(3, E)(failing)())",
    "tests/test_flow.py:100 retry(11, MyError, timeout=1)(failing)() (9 receivers + 9 edges on funcy:a)",
    "review: effect/call-graph (call-of-call receiver typing)",
    "LAND (HELD): the exact funcy:a edit (== -> >=) under range(tries) is equivalent; the test reaches retry through the factory call",
    {"pk/lib.py": '''def retry(tries, errors=Exception):
    def decorator(call):
        def wrapper(*args, **kwargs):
            for attempt in range(tries):
                try:
                    return call(*args, **kwargs)
                except errors:
                    if attempt + 1 == tries:
                        raise

        return wrapper

    return decorator
''', "tests/test_lib.py": TEST_IMPORT + '''import pytest


def test_retry_gives_up():
    def failing():
        raise ValueError

    with pytest.raises(ValueError):
        retry(3, ValueError)(failing)()
'''},
    [("pk/lib.py", "if attempt + 1 == tries:", "if attempt + 1 >= tries:")],
    "pk.lib.retry",
)
repro(
    "a3_nested_decorated_recursion", "decorated nested def (@lru_cache wrapper) + recursion back into the enclosing factory; two sibling nested defs both named wrapper",
    "funcy/calc.py:128-146 _make_lookuper.make_lookuper (memoize'd wrapper calling make_lookuper(f))",
    "review: effect (nested decorated defs, name collisions between sibling closures)",
    "LAND (HELD): renaming the local lambda is unobservable",
    {"pk/lib.py": '''from functools import lru_cache


def make_lookuper(func):
    if func.__code__.co_argcount > 0:

        @lru_cache
        def wrapper(*args):
            f = lambda: func(*args)
            return make_lookuper(f)
    else:
        memory = {}

        def wrapper(arg):
            if not memory:
                memory.update(func())
            return memory[arg]

    return wrapper
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_lookuper():
    @make_lookuper
    def squares():
        return {1: 1, 2: 4}

    assert squares(2) == 4
'''},
    [("pk/lib.py", "            f = lambda: func(*args)\n            return make_lookuper(f)", "            thunk = lambda: func(*args)\n            return make_lookuper(thunk)")],
    "pk.lib.make_lookuper",
)
repro(
    "a4_varargs_forwarding", "decorator_varargs_forwarding: wrapper(*args, **kwargs) forwards to func(*args, **kwargs)",
    "funcy/flow.py:176 throttle.decorator.wrapper 'unresolved construct: decorator_varargs_forwarding' (and every @wraps wrapper in funcy)",
    "review: effect (*args/**kwargs forwarding through a decorator)",
    "LAND (HELD): inlining a temp around the forwarded call is equivalent",
    {"pk/lib.py": '''def logged(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return result

    return wrapper
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_logged():
    @logged
    def add(a, b=0):
        return a + b

    assert add(1, b=2) == 3
'''},
    [("pk/lib.py", "        result = func(*args, **kwargs)\n        return result", "        return func(*args, **kwargs)")],
    "pk.lib.logged",
)
repro(
    "a5_instance_via_factory", "unresolved receiver: a test calls a method on an object returned by a factory (c = make_counter(); c.inc())",
    "tests of funcy classes created through helper functions (class-bound method through a factory result)",
    "review: effect (receiver typing through a function return)",
    "LAND (HELD): n += by  ->  n = n + by is equivalent",
    {"pk/lib.py": '''class Counter:
    def __init__(self):
        self.n = 0

    def inc(self, by=1):
        self.n += by
        return self.n


def make_counter():
    return Counter()
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_counter():
    c = make_counter()
    assert c.inc() == 1
    assert c.inc(2) == 3
'''},
    [("pk/lib.py", "        self.n += by", "        self.n = self.n + by")],
    "pk.lib.Counter.inc",
)

repro(
    "g0_control_simple", "CONTROL: nothing hard: one flat function, an explicit-import test, a behaviour-preserving edit (a temp variable around a + b). NB a first draft used b + a: the engine correctly REFUTED it (str + str is not commutative: a='é', b='日本'), so that edit was not neutral",
    "(none: proves the harness lands when the engine can)", "-", "LAND (HELD)",
    {"pk/lib.py": "def add(a, b):\n    return a + b\n", "tests/test_lib.py": "@@IMPORT@@\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"},
    [("pk/lib.py", "    return a + b", "    total = a + b\n    return total")],
    "pk.lib.add",
)

repro(
    "g1_control_flat_module", "CONTROL 2: the same trivial repo but as a FLAT top-level module lib.py (no package): the engine names it __main__",
    "single-module distributions (six.py, tabulate-style flat layouts) and every repo whose code sits at the root",
    "review: effect (module naming for a root-level module)",
    "LAND (HELD): identical to g0 apart from layout; today the account says '__main__.add' and L3 'cannot locate its definition in the post tree'",
    {"lib.py": "def add(a, b):\n    return a + b\n", "tests/test_lib.py": "from lib import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"},
    [("lib.py", "    return a + b", "    total = a + b\n    return total")],
    "lib.add",
)

# ---------------------------------------------------------------------------------------------------------------- (b) parse: unsupported_entry_guard
repro(
    "b1_guard_not_in_any", "unsupported_entry_guard: a conjunctive entry guard with `x not in CONST` and any(generator)",
    "parse/__init__.py:398 extract_format: `type and type not in ALLOWED_TYPES and type not in extra_types and not any(k in type for k in dt_format_to_regex)`",
    "review: effect (guard modelling) / obligation (entry-guard comparison)",
    "LAND (HELD): swapping two side-effect-free conjuncts is equivalent; if guard analysis cannot model any(...) the verdict should say that ONE conjunct is unmodelled, not refuse the whole callee cone",
    {"pk/lib.py": '''ALLOWED = ("d", "s")
FORMATS = {"%Y": "year"}


def check(type):
    if type and type not in ALLOWED and not any(k in type for k in FORMATS):
        raise ValueError(type)
    return type
''', "tests/test_lib.py": TEST_IMPORT + '''import pytest


def test_check():
    assert check("d") == "d"
    with pytest.raises(ValueError):
        check("q")
'''},
    [("pk/lib.py", "type not in ALLOWED and not any(k in type for k in FORMATS)", "not any(k in type for k in FORMATS) and type not in ALLOWED")],
    "pk.lib.check",
)
repro(
    "b2_in_field_guard", "unsupported_entry_guard: `\".\" in field` / `\"-\" in field` membership guards on a str parameter",
    "parse/__init__.py:636-640 Parser._to_group_name: `\".\" in field`, `\"_\" in field`, `\"-\" in field`",
    "review: effect (guard modelling) / obligation",
    "LAND (HELD): replace(...) -> '_'.join(split(...)) is equivalent",
    {"pk/lib.py": '''def to_group_name(field):
    if "." in field:
        field = field.replace(".", "_")
    if "-" in field:
        field = field.replace("-", "_")
    return field
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_group_name():
    assert to_group_name("a.b-c") == "a_b_c"
'''},
    [("pk/lib.py", '        field = field.replace(".", "_")', '        field = "_".join(field.split("."))')],
    "pk.lib.to_group_name",
)

# ---------------------------------------------------------------------------------------------------------------- (c) slugify:b no derivable strategy
repro(
    "c_annotation_no_strategy", "differential cannot generate: parameter annotated list[tuple[str, str]] has no derivable strategy",
    "slugify/special.py add_uppercase_char(char_list: list[tuple[str, str]]) (slugify:b: 'annotation list[tuple[str, str]] has no derivable strategy')",
    "review: differential strategy derivation (nested generics of builtins)",
    "LAND (HELD): list[tuple[str, str]] is built from builtins; strategies are derivable; list comprehension vs loop is equivalent",
    {"pk/lib.py": '''def add_upper(char_list: list[tuple[str, str]], prefix: str = ""):
    out = []
    for src, dst in char_list:
        out.append((prefix + src, dst))
    return out
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_add_upper():
    assert add_upper([("a", "b")], "x") == [("xa", "b")]
'''},
    [("pk/lib.py", "    out = []\n    for src, dst in char_list:\n        out.append((prefix + src, dst))\n    return out", "    return [(prefix + src, dst) for src, dst in char_list]")],
    "pk.lib.add_upper",
)

# ---------------------------------------------------------------------------------------------------------------- (d) funcy:b hasattr cut-point, empty impacted slice
repro(
    "d1_hasattr_cutpoint", "differential adequacy: condition hasattr(code, 'co_posonlyargcount') never False; call to hasattr() unsupported as a cut-point",
    "funcy/decorators.py arggetter (funcy:b: 'cut-point: unsupported: call to hasattr()')",
    "review: differential (cut-points over pure builtin predicates such as hasattr/isinstance/callable)",
    "LAND (HELD) once hasattr is a modelled predicate (or an explicit residual 'both arms of hasattr unreachable on this interpreter' rather than a refusal)",
    {"pk/lib.py": '''def posonly(code):
    return code.co_posonlyargcount if hasattr(code, "co_posonlyargcount") else 0
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_posonly():
    assert posonly((lambda a, /, b: 0).__code__) == 1
'''},
    [("pk/lib.py", '    return code.co_posonlyargcount if hasattr(code, "co_posonlyargcount") else 0', '    if hasattr(code, "co_posonlyargcount"):\n        return code.co_posonlyargcount\n    return 0')],
    "pk.lib.posonly",
)
repro(
    "d2_no_test_reaches", "no repository test reaches the changed function: the impacted test slice is empty (differential agreement alone is not a pass)",
    "funcy/decorators.py get_argnames (funcy:b: 'no repository test reaches funcy.decorators.get_argnames: the impacted test slice is empty')",
    "review: obligation (what an empty impacted slice means) with differential evidence",
    "Open design question: if the differential is adequate and agrees on N inputs but no repo test reaches the function, the honest verdict is probably a named residual (untested-callee: differential agreed on N inputs) that the operator may accept, not a silent LAND and not an unclassified refusal",
    {"pk/lib.py": '''def double(x):
    return x * 2


def used():
    return 1
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_used():
    assert used() == 1
'''},
    [("pk/lib.py", "    return x * 2", "    return x + x")],
    "pk.lib.double",
)

# ---------------------------------------------------------------------------------------------------------------- (e) bidict dynamic setattr / proxy builder
repro(
    "e1_proxy_method_builder", "dynamic_attribute: getattr(obj, name) inside a generated method + setattr(cls, name, make(name)) in a loop",
    "bidict/_orderedbidict.py _override_set_methods_to_use_backing_dict.make_proxy_method (getattr(Set, methodname), getattr(fwdm, viewname), setattr(cls, name, make_proxy_method(name)); 5 dynamic_attribute + 9 unresolved_call on bidict:b)",
    "review: effect (dynamic attribute with a statically enumerable name set); the names come from a literal list",
    "LAND (HELD) or a precise 'dynamic setattr over the literal names [keys, items]' residual: the loop body edit list(names) does not change the set of installed methods",
    {"pk/lib.py": '''def install(cls, names):
    def make(name):
        def method(self, *args):
            return getattr(self._d, name)(*args)

        return method

    for n in names:
        setattr(cls, n, make(n))


class Box:
    def __init__(self):
        self._d = {}


install(Box, ["keys", "items"])
''', "tests/test_lib.py": TEST_IMPORT + '''

def test_box():
    assert list(Box().keys()) == []
'''},
    [("pk/lib.py", "    for n in names:\n        setattr(cls, n, make(n))", "    for n in list(names):\n        setattr(cls, n, make(n))")],
    "pk.lib.install",
)

# ---------------------------------------------------------------------------------------------------------------- (f) module-level constant bump
repro(
    "f_module_constant_bump", "module_level_change: a package constant (__version__) edited; nothing in the tests reads it",
    "parse/__init__.py:14 __version__ = \"1.22.2\" (parse:a: unresolved-0 'other: __version__' + unresolved-1 'module_level_change')",
    "review: effect (module-level bindings) with obligation (a reader scan for the constant: who reads pkg.__version__?)",
    "LAND (HELD) when a repository-wide reader scan finds no reader of the constant (tests, other modules, packaging metadata that is not generated from it); otherwise REFUSE NAMING the readers. Never an anonymous 'unresolved module_level_change'",
    {"pkg/__init__.py": '''__version__ = "1.0"


def add(a, b):
    return a + b
''', "tests/test_pkg.py": '''from pkg import add


def test_add():
    assert add(1, 2) == 3
'''},
    [("pkg/__init__.py", '__version__ = "1.0"', '__version__ = "1.1"')],
    "pkg.__version__",
    note="not behaviour-neutral by construction: the constant changes; the point is the READER scan",
)


def sh(*a, cwd=None, check=True, env=None, timeout=600):
    cp = subprocess.run(a, cwd=cwd, capture_output=True, text=True, env=env, timeout=timeout)
    if check and cp.returncode:
        raise SystemExit(f"failed: {' '.join(map(str, a))}\n{cp.stderr[-400:]}")
    return cp


IMPORTS = {"a1_closure_func_attribute": "throttle", "a2_call_result_receiver": "retry", "a3_nested_decorated_recursion": "make_lookuper", "a4_varargs_forwarding": "logged",
           "a5_instance_via_factory": "make_counter", "b1_guard_not_in_any": "check", "b2_in_field_guard": "to_group_name", "c_annotation_no_strategy": "add_upper",
           "d1_hasattr_cutpoint": "posonly", "d2_no_test_reaches": "used", "e1_proxy_method_builder": "Box", "g0_control_simple": "add"}


def build_one(out: Path, rid: str):
    r = REPROS[rid]
    w = out / rid
    src = w / "repo"
    if w.exists():
        raise SystemExit(f"{w} exists: use a fresh OUTDIR")
    for rel, text in r["files"].items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text.replace("@@IMPORT@@", f"from pk.lib import {IMPORTS.get(rid, '')}"))
    if rid != "g1_control_flat_module" and rid != "f_module_constant_bump":
        (src / "pk").mkdir(exist_ok=True)
        (src / "pk" / "__init__.py").write_text("")
    sh("git", "init", "-q", "-b", "main", cwd=src)
    sh("git", "add", "-A", cwd=src)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "base", cwd=src)
    touched = {}
    for rel, old, new in r["edits"]:
        p = src / rel
        t = p.read_text()
        assert t.count(old) == 1, (rid, rel, old)
        p.write_text(t.replace(old, new))
        touched[rel] = ["modify"]
    patch = sh("git", "diff", cwd=src).stdout
    (w / "change.patch").write_text(patch)
    (w / "manifest.json").write_text(json.dumps({"paths": touched}))
    meta = {k: v for k, v in r.items() if k not in ("files", "edits")}
    meta["patch_sha256"] = hashlib.sha256(patch.encode()).hexdigest()
    (w / "meta.json").write_text(json.dumps(meta, indent=1))
    return w


def run_one(w: Path, hlith_src: str, py: str):
    clone = w / "clone"
    if clone.exists():
        raise SystemExit(f"{clone} exists")
    src = w / "repo"
    sh("git", "clone", "-q", "--no-hardlinks", str(src), str(clone))
    sh("git", "-C", str(clone), "remote", "remove", "origin", check=False)
    out = w / "out.json"
    argv = [py, "-m", "hlith.cli", "run", "--repo", str(clone), "--patch", str(w / "change.patch"), "--manifest", str(w / "manifest.json"), "--artifact-out", str(out),
            "--proposer-id", "repro", "--target-python", py, "--engine", "pipeline", "--source-repo", str(src)]
    env = {**os.environ, "PYTHONPATH": hlith_src}
    load = os.getloadavg()
    t0 = time.monotonic()
    cp = sh(*argv, check=False, env=env, timeout=1500)
    v = {"exit": cp.returncode, "wall_seconds": round(time.monotonic() - t0, 1), "load_avg_at_start": list(load), "argv": argv[3:]}
    if out.exists():
        a = json.loads(out.read_text())
        v["outcome"] = a.get("outcome")
        v["exit_status"] = a.get("exit_status")
        v["blocking"] = a.get("blocking", [])
        v["non_held"] = [{"id": o.get("id"), "verdict": o.get("verdict"), "reason": str(o.get("stop_reason") or o.get("witness"))[:400]} for o in a.get("obligations", []) if str(o.get("verdict")).lower() != "held"]
        v["artifact_sha256"] = hashlib.sha256(out.read_bytes()).hexdigest()
    else:
        v["no_artifact"] = (cp.stdout + cp.stderr)[-500:]
    (w / "verdict.json").write_text(json.dumps(v, indent=1))
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "run"])
    ap.add_argument("outdir")
    ap.add_argument("--hlith-src")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--target-python", default=sys.executable)
    a = ap.parse_args()
    out = Path(a.outdir).resolve()
    ids = a.only or list(REPROS)
    if a.cmd == "build":
        out.mkdir(parents=True, exist_ok=True)
        for rid in ids:
            print("built", build_one(out, rid))
        return 0
    res = {}
    for rid in ids:  # strictly serial
        v = run_one(out / rid, a.hlith_src, a.target_python)
        res[rid] = v
        print(f"{rid:34s} exit={v.get('exit')} outcome={v.get('outcome')} blocking={len(v.get('blocking', []))} {v['wall_seconds']}s load={v['load_avg_at_start'][0]:.1f}")
    (out / "RESULTS.json").write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
