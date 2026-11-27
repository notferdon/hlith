# SPDX-License-Identifier: Apache-2.0
"""drive_inputs: a candidate-input GENERATOR for uncovered conditions. Never trusted, never a coverage claim:
the tests here use real Python evaluation of the condition as the independent oracle."""
import time

import pytest

from hlith.drive_inputs import drive

TOY1 = "def f(n: int) -> int:\n    if n.bit_length() > 64 and n % 7 == 6:\n        return 1\n    return 0\n"
TOY2 = "def f(mode, n: int):\n    if mode == 7 and n.bit_length() > 64:\n        return 1\n    return 0\n"
TOY3 = "def f(a, b):\n    if len(a) == 3 and len(b) > 50:\n        return 1\n    return 0\n"


def _truth(cond: str, kwargs: dict, defaults: dict | None = None) -> bool:
    env = {**(defaults or {}), **kwargs}
    return bool(eval(cond, {"__builtins__": {"len": len, "abs": abs, "min": min, "max": max, "isinstance": isinstance,
                                              "int": int, "str": str, "list": list, "tuple": tuple, "dict": dict,
                                              "bool": bool, "float": float, "type": type}}, env))


def _check(src, cond, polarity, **kw):
    r = drive(src, "f", cond, polarity, **kw)
    assert r.candidates, r.reason
    for c in r.candidates:
        assert c.wants is polarity
        assert _truth(cond, c.kwargs) is polarity, (cond, c)
    return r


# ---------------------------------------------------------------- design review's three toys, both polarities
def test_toy1_bit_length_and_modulo():
    cond = "n.bit_length() > 64 and n % 7 == 6"
    r = _check(TOY1, cond, True)
    assert any(abs(c.kwargs["n"]) >= 2**64 and c.kwargs["n"] % 7 == 6 for c in r.candidates)
    _check(TOY1, cond, False)


def test_toy2_mode_and_bit_length():
    cond = "mode == 7 and n.bit_length() > 64"
    r = _check(TOY2, cond, True)
    assert all(c.kwargs["mode"] == 7 and c.kwargs["n"].bit_length() > 64 for c in r.candidates)
    _check(TOY2, cond, False)


def test_toy3_len_a_and_len_b_lists_and_strings():
    cond = "len(a) == 3 and len(b) > 50"
    r = _check(TOY3, cond, True)
    kinds = {(type(c.kwargs["a"]).__name__, type(c.kwargs["b"]).__name__) for c in r.candidates}
    assert ("list", "list") in kinds and ("str", "str") in kinds, kinds
    _check(TOY3, cond, False)


# ---------------------------------------------------------------- seeds, typed reps, other shapes
def test_threshold_seeds_are_offered():
    src = "def f(x: int):\n    if x > 1000:\n        return 1\n    return 0\n"
    r = drive(src, "f", "x > 1000", True)
    xs = {c.kwargs["x"] for c in r.candidates}
    assert 1001 in xs
    r2 = drive(src, "f", "x > 1000", False)
    assert 1000 in {c.kwargs["x"] for c in r2.candidates}


def test_power_of_two_boundaries():
    src = "def f(x: int):\n    if x >= 2**32:\n        return 1\n    return 0\n"
    r = drive(src, "f", "x >= 2**32", True)
    assert r.candidates and all(c.kwargs["x"] >= 2**32 for c in r.candidates)
    assert 2**32 in {c.kwargs["x"] for c in r.candidates}


def test_isinstance_typed_reps():
    src = "def f(v):\n    if isinstance(v, (list, tuple)):\n        return 1\n    return 0\n"
    r = drive(src, "f", "isinstance(v, (list, tuple))", True)
    assert r.candidates and all(isinstance(c.kwargs["v"], (list, tuple)) for c in r.candidates)
    r = drive(src, "f", "isinstance(v, (list, tuple))", False)
    assert r.candidates and all(not isinstance(c.kwargs["v"], (list, tuple)) for c in r.candidates)


def test_str_params_via_strings():
    src = "def f(s: str):\n    if s.startswith('ab') and len(s) == 5:\n        return 1\n    return 0\n"
    r = drive(src, "f", "s.startswith('ab') and len(s) == 5", True)
    assert r.candidates and all(c.kwargs["s"].startswith("ab") and len(c.kwargs["s"]) == 5 for c in r.candidates)


def test_in_tuple_of_literals_and_is_none():
    src = "def f(m: int, k: 'int | None' = None):\n    if m in (3, 9) and k is None:\n        return 1\n    return 0\n"
    r = drive(src, "f", "m in (3, 9) and k is None", True)
    assert r.candidates
    for c in r.candidates:
        assert c.kwargs["m"] in (3, 9) and c.kwargs.get("k") is None


def test_bit_ops_with_constants():
    src = "def f(x: int):\n    if x & 7 == 5 and (x >> 3) > 10:\n        return 1\n    return 0\n"
    r = drive(src, "f", "x & 7 == 5 and (x >> 3) > 10", True)
    assert r.candidates and all(c.kwargs["x"] & 7 == 5 and (c.kwargs["x"] >> 3) > 10 for c in r.candidates)


def test_negative_modulus_python_semantics():
    src = "def f(x: int):\n    if x % 5 == 3:\n        return 1\n    return 0\n"
    r = drive(src, "f", "x % 5 == 3", True)
    assert r.candidates and all(c.kwargs["x"] % 5 == 3 for c in r.candidates)  # includes negatives under Python %


def test_path_conditions_are_conjoined():
    src = "def f(x: int, y: int):\n    if x > 5:\n        if y < x:\n            return 1\n    return 0\n"
    r = drive(src, "f", "y < x", True, path=(("x > 5", True),))
    assert r.candidates and all(c.kwargs["x"] > 5 and c.kwargs["y"] < c.kwargs["x"] for c in r.candidates)


def test_condition_by_location_and_ast_node():
    import ast

    src = "def f(x: int):\n    if x == 41:\n        return 1\n    return 0\n"
    node = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Compare))
    for cond in ((node.lineno, node.col_offset), node, "x == 41"):
        r = drive(src, "f", cond, True)
        assert r.candidates and all(c.kwargs["x"] == 41 for c in r.candidates)


def test_method_self_excluded():
    src = "class C:\n    def f(self, n: int):\n        if n % 4 == 1:\n            return 1\n        return 0\n"
    r = drive(src, "C.f", "n % 4 == 1", True)
    assert r.candidates and all("self" not in c.kwargs and c.kwargs["n"] % 4 == 1 for c in r.candidates)


# ---------------------------------------------------------------- honesty: unsat, unsupported, budgets, no execution
def test_unsat_condition_returns_empty_with_reason():
    src = "def f(x: int):\n    if x > 5 and x < 3:\n        return 1\n    return 0\n"
    r = drive(src, "f", "x > 5 and x < 3", True)
    assert r.candidates == [] and "unsat" in r.reason


def test_unsupported_is_empty_with_named_reason():
    src = "def f(x: int):\n    if helper(x) > 3:\n        return 1\n    return 0\n"
    r = drive(src, "f", "helper(x) > 3", True)
    assert r.candidates == [] and "helper" in r.reason


def test_partial_model_is_not_exact():
    src = "def f(x: int, y: int):\n    if x > 3 and helper(y):\n        return 1\n    return 0\n"
    r = drive(src, "f", "x > 3 and helper(y)", True)
    assert r.exact is False  # a conjunct was not modelled; any candidate satisfies only the modelled part


def test_proposer_text_is_never_executed(tmp_path):
    marker = tmp_path / "ran"
    src = f"def f(x: int):\n    if open({str(marker)!r}, 'w') or x > 1:\n        return 1\n    return 0\n"
    drive(src, "f", f"open({str(marker)!r}, 'w') or x > 1", True)
    drive(src, "f", "__import__('os').system('true') or x > 1", True)
    assert not marker.exists()


def test_budget_is_respected():
    # a hard nonlinear condition must come back inside the total budget
    src = "def f(x: int, y: int):\n    if x * y * x * y == 123456789123456789 and x % 97 == y % 89:\n        return 1\n    return 0\n"
    t = time.monotonic()
    with _z3_work() as w:
        r = drive(src, "f", "x * y * x * y == 123456789123456789 and x % 97 == y % 89", True, per_query_ms=300, budget_ms=1500)
    # the property is an effort cap: no single check may run past its rlimit (300 ms * RL_PER_MS, small slack); wall time
    # is only a catastrophe guard (a 12-process CPU stress still finishes in seconds), never the assertion
    assert w["max_check"] <= 300 * 1000 * 1.3, w
    assert time.monotonic() - t < 120
    assert isinstance(r.reason, str)


def test_candidates_never_exceed_max():
    src = "def f(x: int):\n    if x > 3:\n        return 1\n    return 0\n"
    assert len(drive(src, "f", "x > 3", True, max_candidates=3).candidates) <= 3


def test_candidate_fields():
    r = drive(TOY2, "f", "mode == 7", True)
    c = r.candidates[0]
    assert c.origin in ("z3", "seed", "typed") and c.checked is True and isinstance(c.kwargs, dict)


# ---------------------------------------------------------------- review's public API: candidates()
import json  # noqa: E402

from hlith.drive_inputs import candidates, candidates_detailed  # noqa: E402


def _materialise(v):
    return [0] * v["__len__"] if isinstance(v, dict) and "__len__" in v else v


def _api_truth(cond, assignment):
    return _truth(cond, {k: _materialise(v) for k, v in assignment.items()})


def test_api_toy1_both_polarities_json_able():
    cond = "n.bit_length() > 64 and n % 7 == 6"
    out = candidates([("n", "int")], [cond])
    json.dumps(out)
    t = [a for a in out if _api_truth(cond, a)]
    f = [a for a in out if not _api_truth(cond, a)]
    assert t and f and all(abs(a["n"]) >= 2**64 and a["n"] % 7 == 6 for a in t)
    assert len(out) <= 2 * 4


def test_api_toy2_and_toy3_len_marker():
    out = candidates([("mode", None), ("n", "int")], ["mode == 7 and n.bit_length() > 64"], want="true")
    assert out and all(a["mode"] == 7 and a["n"].bit_length() > 64 for a in out)
    cond = "len(a) == 3 and len(b) > 50"
    out = candidates([("a", None), ("b", None)], [cond], want="true")
    assert out and all(a["a"] == {"__len__": 3} and a["b"]["__len__"] > 50 for a in out)
    out = candidates([("a", None), ("b", None)], [cond], want="false")
    assert out and all(not _api_truth(cond, a) for a in out)


def test_api_want_filters_and_conditions_are_independent():
    out = candidates([("x", "int")], ["x > 10", "x < -10"], want="true", max_per_condition=2)
    assert any(a["x"] > 10 for a in out) and any(a["x"] < -10 for a in out) and len(out) <= 4
    assert all(a["x"] > 10 or a["x"] < -10 for a in out)


def test_api_unsupported_and_detailed_reasons():
    out, reasons = candidates_detailed([("x", "int")], ["helper(x) > 3", "x == 4"])
    assert [c.condition for c in out] == [1, 1] or all(c.condition == 1 for c in out)
    assert 0 in reasons and "helper" in reasons[0]
    assert candidates([("x", "int")], ["helper(x) > 3"]) == []
    c = out[0]
    assert c.origin in ("z3", "seed", "typed") and isinstance(c.wants, bool) and isinstance(c.exact, bool)


def test_api_unknown_param_in_condition_is_unsupported():
    assert candidates([("x", "int")], ["y > 3"]) == []


def test_api_bad_syntax_is_empty_not_a_crash():
    assert candidates([("x", "int")], ["x >", ""]) == []


# ---------------------------------------------------------------- randomised oracle: real Python eval vs the generator
def _rand_conditions(rng, n=60):
    atoms = [
        lambda: f"x % {rng.choice([2, 3, 5, 7, 11])} == {rng.randint(0, 4)}",
        lambda: f"x {rng.choice(['<', '<=', '>', '>=', '==', '!='])} {rng.randint(-50, 50)}",
        lambda: f"y {rng.choice(['<', '>', '=='])} x + {rng.randint(-5, 5)}",
        lambda: f"x.bit_length() {rng.choice(['>', '<', '==', '>='])} {rng.randint(0, 70)}",
        lambda: f"(x >> {rng.randint(0, 5)}) & {rng.choice([1, 3, 7, 15])} == {rng.randint(0, 3)}",
        lambda: f"abs(y) {rng.choice(['<', '>'])} {rng.randint(0, 30)}",
        lambda: f"min(x, y) {rng.choice(['<', '>='])} {rng.randint(-10, 10)}",
        lambda: f"x in ({rng.randint(0, 9)}, {rng.randint(10, 19)})",
        lambda: f"len(s) {rng.choice(['==', '>', '<'])} {rng.randint(0, 8)}",
        lambda: f"s.startswith('{rng.choice(['a', 'ab', 'zz'])}')",
    ]
    out = []
    for _ in range(n):
        parts = [rng.choice(atoms)() for _ in range(rng.randint(1, 3))]
        glue = rng.choice([" and ", " or "])
        c = glue.join(parts)
        out.append(f"not ({c})" if rng.random() < 0.2 else c)
    return out


def test_randomised_candidates_agree_with_real_python_eval():
    import random

    rng = random.Random(20261113)
    params = [("x", "int"), ("y", "int"), ("s", "str")]
    produced = wrong = 0
    for cond in _rand_conditions(rng):
        for pol in (True, False):
            r = drive("def f(x: int, y: int, s: str):\n    pass\n", "f", cond, pol, per_query_ms=300, budget_ms=1500)
            for c in r.candidates:
                if not c.checked:
                    continue
                env = {"x": 0, "y": 0, "s": "", **c.kwargs}
                produced += 1
                if bool(eval(cond, {"__builtins__": {"len": len, "abs": abs, "min": min, "max": max}}, env)) is not pol:
                    wrong += 1
    assert produced > 100
    assert wrong == 0, (wrong, produced)


def test_api_accepts_underscored_and_unannotated_param_names():
    # review's concolic rewriting introduces fresh names like __a0 / __e0 / _x and unannotated parameters
    out = candidates([("__a0", "bool"), ("__e0", None), ("_x", "int")],
                     ["__a0 and __e0 is None and _x % 3 == 1"], want="true")
    assert out, "no candidates"
    for a in out:
        assert a["__a0"] is True and a["__e0"] is None and a["_x"] % 3 == 1, a
    out = candidates([("__a0", "bool")], ["not __a0"], want="true")
    assert out and all(a["__a0"] is False for a in out)
    out = candidates([("__n0", None)], ["__n0 > 5"], want="true")
    assert out and all(a["__n0"] > 5 for a in out)


def test_api_forced_container_type_is_reported_with_length():
    out = candidates([("_e", None)], ["isinstance(_e, list) and len(_e) == 2"], want="true")
    assert out and all(a["_e"] == {"__type__": "list", "__len__": 2} for a in out), out
    # no type test: length only (the caller chooses the container)
    out = candidates([("a", None)], ["len(a) == 3"], want="true")
    assert out and all(a["a"] == {"__len__": 3} for a in out), out
    out = candidates([("_e", None)], ["isinstance(_e, (tuple, list)) and len(_e) > 1"], want="true")
    assert out and all(a["_e"]["__len__"] > 1 and a["_e"]["__type__"] in ("tuple", "list") for a in out), out


# ================================================================ WP-BSDP-1: backward slice + bounded sequences
# Every case below is my OWN (not design review's Set 1/2, not review's blind Set 3). The oracle is REAL PYTHON on the ORIGINAL
# function: the condition node is wrapped in a recorder, the candidate is materialised from the descriptor and the
# function is run; the recorder must have seen the condition with the wanted truth value. Nothing here shares code
# with drive_inputs.
import ast
import builtins
import types
from pathlib import PurePosixPath

from hlith.drive_inputs import _candidates_detailed_inproc as candidates_detailed, collect_backward_slice


_TYPE_REPS = {"tuple": (1,), "set": {1}, "bytes": b"a"}


def _real(desc):
    """Descriptor (JSON-able form review materialises) -> a real Python value."""
    if isinstance(desc, dict) and not any(isinstance(k, str) and k.startswith("__") for k in desc):
        return {k: _real(v) for k, v in desc.items()}  # a plain dict representative
    if isinstance(desc, dict) and set(desc) == {"__type__"} and desc["__type__"] in _TYPE_REPS:
        t = _TYPE_REPS[desc["__type__"]]
        return set(t) if isinstance(t, set) else t
    if isinstance(desc, dict):
        if "__dict__" in desc:
            return {k: _real(v) for k, v in desc["__dict__"].items()}
        if "__path__" in desc:
            return PurePosixPath(desc["__path__"])
        if "__seq_rec__" in desc:
            return [_real({"__attrs__": r}) for r in desc["__seq_rec__"]]
        if "__attrs__" in desc or "__attr_dict__" in desc:
            ns = types.SimpleNamespace()
            for k, v in (desc.get("__attrs__") or {}).items():
                setattr(ns, k, _real(v))
            for k, v in (desc.get("__attr_dict__") or {}).items():
                setattr(ns, k, {kk: _real(vv) for kk, vv in v.items()} if "__dict__" not in v else _real(v))
            return ns
        if "__len__" in desc:
            return [0] * desc["__len__"]
        if set(desc) == {"__type__"} and isinstance(getattr(builtins, desc["__type__"], None), type)\
                and issubclass(getattr(builtins, desc["__type__"]), BaseException):
            return getattr(builtins, desc["__type__"])("a")
        raise AssertionError(f"unknown descriptor {desc}")
    return desc


def _kw_real(kwargs):
    """Descriptor kwargs -> real arguments; 'self.attr' keys become attributes of a SimpleNamespace `self`."""
    out, selfns = {}, types.SimpleNamespace()
    for k, v in kwargs.items():
        if k.startswith("self."):
            setattr(selfns, k.split(".", 1)[1], _real(v))
        else:
            out[k] = _real(v)
    if any(k.startswith("self.") for k in kwargs):
        out["self"] = selfns
    return out


def _observe(src, fname, cond_src, kwargs):
    """Run the real function with `kwargs`; return the truth values the condition took (None if never reached)."""
    tree = ast.parse(src)
    target = ast.parse(cond_src, mode="eval").body
    seen = []

    class W(ast.NodeTransformer):
        def visit_If(self, node):
            self.generic_visit(node)
            if ast.dump(node.test) == ast.dump(target):
                node.test = ast.Call(func=ast.Name("__rec", ast.Load()), args=[node.test], keywords=[])
            return node

    new = ast.fix_missing_locations(W().visit(tree))
    g = {"__rec": lambda v: (seen.append(bool(v)), v)[1]}
    exec(compile(new, "<oracle>", "exec"), g)
    try:
        import inspect

        real = _kw_real(kwargs)
        for pn, par in inspect.signature(g[fname]).parameters.items():  # parameters the condition does not read
            if pn not in real and par.default is inspect.Parameter.empty:
                real[pn] = {"str": "", "int": 0, "float": 0.0, "bool": False, "dict": {}, "list": []}.get(getattr(par.annotation, "__name__", par.annotation), None)
        g[fname](**real)
    except Exception:  # noqa: BLE001 - the function may raise after the condition; only the recorder matters
        pass
    return seen


def _line_of(src, cond_src):
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.If) and ast.dump(n.test) == ast.dump(ast.parse(cond_src, mode="eval").body):
            return n.lineno
    raise AssertionError("condition not found")


BUDGETS_MS = (200, 400, 800, 1600)  # retried in this order: a result found under a smaller budget is the same result;
# a slow machine (load) only moves the first success to a later budget, it can never change what is asserted


def _drive_all(src, fname, cond_src, lineno, want="true", params=None, **kw):
    """candidates_detailed with a deterministic outcome under load: the call is retried with growing time budgets
    until it returns candidates (at most len(BUDGETS_MS) attempts); the last result is returned either way."""
    for ms in BUDGETS_MS:
        det, why = _drive_once(src, fname, cond_src, lineno, want, params, timeout_ms=ms, **kw)
        if det:
            return det, why
    return det, why


def _drive_once(src, fname, cond_src, lineno, want="true", params=None, **kw):
    lineno = lineno or _line_of(src, cond_src)
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == fname)
    plist = params or [(a.arg, ast.unparse(a.annotation) if a.annotation else None) for a in fn.args.args if a.arg != "self"]
    return candidates_detailed(plist, [cond_src], want=want, fn_ast=fn, target_lineno=lineno, **kw)


def _assert_all_real(src, fname, cond_src, lineno=None, want="true", **kw):
    det, why = _drive_all(src, fname, cond_src, lineno, want, **kw)
    assert det, why
    wanted = want == "true"
    for c in det:
        seen = _observe(src, fname, cond_src, c.params)
        assert seen and seen[0] is wanted, (cond_src, c.params, seen)
    return det


def test_seam_derived_local_via_candidates_detailed():
    src = "def f(x: int):\n    y = x + 10\n    if y == 42:\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "y == 42", 3)
    assert any(c.params == {"x": 32} for c in det)
    # without the function the same condition cannot be driven: the name is not a parameter
    det0, why0 = candidates_detailed([("x", "int")], ["y == 42"], want="true")
    assert not det0 and "not a parameter" in why0[0]


# (id, source, condition) -- every condition must be driven to BOTH truth values, each candidate checked on real Python
BSDP_CASES = {
    "strip_lower_prefix_len": (
        "def f(title: str):\n    slug = title.strip().lower()\n    if slug.startswith('draft-') and len(slug) > 8:\n        return 1\n    return 0\n",
        "slug.startswith('draft-') and len(slug) > 8"),
    "partition_unpack": (
        "def f(fname):\n    stem, dot, ext = fname.partition('.')\n    if dot and ext == 'gz':\n        return stem\n    return None\n",
        "dot and ext == 'gz'"),
    "split_len_and_ends": (
        "def f(route):\n    parts = route.split('/')\n    if len(parts) == 3 and parts[0] == 'api' and parts[-1] == 'list':\n        return 1\n    return 0\n",
        "len(parts) == 3 and parts[0] == 'api' and parts[-1] == 'list'"),
    "loop_kv_lines": (
        "def f(text):\n    for line in text.splitlines():\n        if line.startswith('#'):\n            continue\n"
        "        key, val = line.split('=', 1)\n        if key.strip() == 'mode' and val.strip().lower() == 'fast':\n            return 1\n    return 0\n",
        "key.strip() == 'mode' and val.strip().lower() == 'fast'"),
    "dict_get_default_chain": (
        "def f(headers):\n    ct = headers.get('content-type', '')\n    main = ct.split(';')[0].strip().lower()\n"
        "    if main == 'application/json':\n        return 1\n    return 0\n",
        "main == 'application/json'"),
    "attr_dict_get": (
        "def f(resp):\n    tag = resp.meta.get('tag')\n    if tag.upper() == 'AB':\n        return 1\n    return 0\n",
        "tag.upper() == 'AB'"),
    "int_affine_two_params": (
        "def f(a: int, b: int):\n    k = a * 3 + b\n    if k % 7 == 2 and k > 100:\n        return 1\n    return 0\n",
        "k % 7 == 2 and k > 100"),
    "dominating_early_return": (
        "def f(s: str):\n    if len(s) < 3:\n        return None\n    tail = s[-3:]\n    if tail == 'xyz':\n        return 1\n    return 0\n",
        "tail == 'xyz'"),
    "conditional_definition": (
        "def f(flag: bool, n: int):\n    if flag:\n        limit = 10\n    else:\n        limit = 20\n    if n > limit:\n        return 1\n    return 0\n",
        "n > limit"),
    "set_comprehension_distinct": (
        "def f(words: str):\n    uniq = {w.lower() for w in words.split()}\n    if len(uniq) == 1 and len(words.split()) == 3:\n        return 1\n    return 0\n",
        "len(uniq) == 1 and len(words.split()) == 3"),
    "record_sequence_on_self": (
        "def f(self):\n    codes = [str(e.code) for e in self.events]\n"
        "    if len(codes) == 2 and codes[0].endswith('4') and codes[-1].startswith('5'):\n        return 1\n    return 0\n",
        "len(codes) == 2 and codes[0].endswith('4') and codes[-1].startswith('5')"),
    "path_parts_and_parent": (
        "def f(p):\n    if p.parent.name == 'pkg' and len(p.parts) == 3:\n        return 1\n    return 0\n",
        "p.parent.name == 'pkg' and len(p.parts) == 3"),
    "str_int_roundtrip": (
        "def f(n: int):\n    s = str(n)\n    if len(s) == 3 and s.endswith('7'):\n        return 1\n    return 0\n",
        "len(s) == 3 and s.endswith('7')"),
    "filtered_comprehension": (
        "def f(csv: str):\n    cols = [c.strip() for c in csv.split(',') if c.strip().startswith('x')]\n"
        "    if len(cols) == 2 and cols[1] == 'xb':\n        return 1\n    return 0\n",
        "len(cols) == 2 and cols[1] == 'xb'"),
    "two_d_comprehension": (
        "def f(blob: str):\n    rows = [r.split() for r in blob.splitlines()]\n"
        "    if len(rows) == 2 and len(rows[0]) == 2 and rows[1][0] == 'end':\n        return 1\n    return 0\n",
        "len(rows) == 2 and len(rows[0]) == 2 and rows[1][0] == 'end'"),
    "ssa_reassignment": (
        "def f(s: str):\n    s = s.strip()\n    s = s.lower()\n    if s == 'ok go':\n        return 1\n    return 0\n",
        "s == 'ok go'"),
    "elif_chain_guards": (
        "def f(n: int, m: int):\n    if n > 50:\n        return 'big'\n    elif m < 0:\n        return 'neg'\n    if n + m == 9:\n        return 1\n    return 0\n",
        "n + m == 9"),
    "tuple_unpack_arity": (
        "def f(pair: str):\n    a, b = pair.split(',')\n    if a.strip() == 'k' and int_ok(b):\n        return 1\n    return 0\n".replace("int_ok(b)", "len(b) == 2"),
        "a.strip() == 'k' and len(b) == 2"),
    "loop_over_param_list": (
        "def f(items):\n    for item in items:\n        if item.lower().startswith('x-'):\n            return 1\n    return 0\n",
        "item.lower().startswith('x-')"),
    "nested_if_enclosing_guard": (
        "def f(mode: str, val: str):\n    if mode == 'strict':\n        v = val.strip()\n        if v.endswith('!') and len(v) == 4:\n            return 1\n    return 0\n",
        "v.endswith('!') and len(v) == 4"),
    "membership_in_derived_seq": (
        "def f(s: str):\n    toks = s.split(',')\n    if 'beta' in toks and len(toks) == 3:\n        return 1\n    return 0\n",
        "'beta' in toks and len(toks) == 3"),
}


@pytest.mark.parametrize("name", sorted(BSDP_CASES))
def test_derived_operand_conditions_are_driven_both_ways_and_verified_on_real_python(name):
    src, cond = BSDP_CASES[name]
    for want in ("true", "false"):
        _assert_all_real(src, "f", cond, want=want)


# ---------------------------------------------------------------- unmodelled constructs are NAMED, never guessed
UNMODELLED = {
    "replace_method": ("def f(s: str):\n    t = s.replace('a', 'b')\n    if t == 'bb':\n        return 1\n    return 0\n",
                       "t == 'bb'", ".replace()"),
    "unknown_call": ("def f(s: str):\n    n = float(s)\n    if n > 3:\n        return 1\n    return 0\n", "n > 3", "float()"),
    "module_function": ("import hashlib\n\n\ndef f(s: str):\n    d = hashlib.md5(s.encode()).hexdigest()\n    if d.startswith('ab'):\n        return 1\n    return 0\n",
                        "d.startswith('ab')", "hashlib"),
    "loop_accumulator": ("def f(s: str):\n    acc = ''\n    for ch in s:\n        acc += ch.upper()\n    if acc == 'ABC':\n        return 1\n    return 0\n",
                         "acc == 'ABC'", "acc"),
    "lambda_value": ("def f(s: str):\n    g = lambda x: x + 'a'\n    if g(s) == 'ba':\n        return 1\n    return 0\n", "g(s) == 'ba'", "g"),
    "multi_char_count": ("def f(s: str):\n    if s.count('ab') == 2:\n        return 1\n    return 0\n", "s.count('ab') == 2", "multi-character"),
    "ordering_of_strings": ("def f(s: str, t: str):\n    u = s.lower()\n    if u < t:\n        return 1\n    return 0\n", "u < t", "ordering comparison of strings"),
    "branch_assigned": ("def f(flag: bool, s: str):\n    if flag:\n        t = s.strip()\n    if t == 'x':\n        return 1\n    return 0\n",
                        "t == 'x'", "t"),
}


@pytest.mark.parametrize("name", sorted(UNMODELLED))
def test_unmodelled_construct_gives_no_candidates_and_names_it(name):
    src, cond, token = UNMODELLED[name]
    det, why = _drive_all(src, "f", cond, None, "true")
    if det:  # the stop is still named, on every cut-point HINT (exact=False); none may claim to be exact
        assert all(not c.exact and c.origin.startswith("cutpoint") and token in c.origin for c in det), [(c.params, c.origin) for c in det]
        return
    assert token in why[0], why


def test_bounded_sequence_limit_is_stated_in_the_reason():
    src = "def f(s: str):\n    p = s.split(',')\n    if len(p) == 9:\n        return 1\n    return 0\n"
    det, why = _drive_all(src, "f", "len(p) == 9", None, "true")
    assert not det and "K=4" in why[0], why


def test_impossible_derived_conditions_are_never_driven():
    # lower() output cannot contain an upper-case letter; strip() output cannot start with a space
    for src, cond in (("def f(s: str):\n    t = s.lower()\n    if t == 'ABC':\n        return 1\n    return 0\n", "t == 'ABC'"),
                      ("def f(s: str):\n    t = s.strip()\n    if t.startswith(' '):\n        return 1\n    return 0\n", "t.startswith(' ')"),
                      ("def f(n: int):\n    s = str(n)\n    if len(s) == 2 and s.startswith('-') and s.endswith('-'):\n        return 1\n    return 0\n",
                       "len(s) == 2 and s.startswith('-') and s.endswith('-')")):
        det, why = _drive_all(src, "f", cond, None, "true")
        assert not det, (cond, [c.params for c in det])


# ---------------------------------------------------------------- the slice itself
def _slice(src, lineno):
    fn = ast.parse(src).body[0]
    return collect_backward_slice(fn, lineno)


def test_slice_collects_ssa_defs_guards_and_loop_targets():
    src = ("def f(a, items):\n    if a < 0:\n        return 0\n    a = a + 1\n    for it in items:\n"
           "        if it == 'skip':\n            continue\n        k = it.strip()\n        if k == 'x':\n            return 1\n    return 2\n")
    sl = _slice(src, 9)
    unp = {n: ast.unparse(v) for n, v in sl.locals_.items()}
    assert unp["a#1"] == "a + 1" and unp["it#1"] == "items[0]" and unp["k#1"] == "it#1.strip()", unp
    guards = [(ast.unparse(e), pol) for e, pol in sl.path]
    assert ("a < 0", False) in guards and ("it#1 == 'skip'", False) in guards and ("len(items) >= 1", True) in guards, guards
    assert sl.version["k"] == "k#1" and sl.version["a"] == "a#1"


def test_slice_poisons_names_it_cannot_follow():
    src = "def f(s):\n    n = 0\n    while n < 3:\n        n = n + 1\n    t = s\n    if t == n:\n        return 1\n"
    sl = _slice(src, 6)
    assert "n" in sl.poisoned and "While" in sl.poisoned["n"], sl.poisoned
    assert sl.version["t"] == "t#1"


# ---------------------------------------------------------------- descriptors
def test_descriptor_forms_are_jsonable_and_exact():
    import json

    src = "def f(h):\n    v = h.get('k', '')\n    if v.startswith('q'):\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "v.startswith('q')")
    assert all(set(c.params) == {"h"} and set(c.params["h"]) == {"__dict__"} for c in det)
    json.dumps([c.params for c in det])
    src = "def f(r):\n    m = r.meta.get('t')\n    if m == 'z':\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "m == 'z'")
    assert all(set(c.params["r"]) == {"__attr_dict__"} and c.params["r"]["__attr_dict__"] == {"meta": {"t": "z"}} for c in det)
    src = "def f(p):\n    if p.name == 'a' and len(p.parts) == 2:\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "p.name == 'a' and len(p.parts) == 2")
    assert det, "no candidate"
    src = "def f(self):\n    xs = [e.v for e in self.rows]\n    if len(xs) == 2 and xs[0] == 5:\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "len(xs) == 2 and xs[0] == 5")
    assert all(set(c.params["self.rows"]) == {"__seq_rec__"} and len(c.params["self.rows"]["__seq_rec__"]) == 2
               and all(set(r) == {"v"} for r in c.params["self.rows"]["__seq_rec__"]) for c in det)


# ---------------------------------------------------------------- seeded fuzz: 0 candidates may violate the condition
def _fuzz_program(rng):
    ops = rng.sample(["strip()", "lower()", "upper()", "lstrip()", "rstrip()"], rng.randint(0, 2))
    chain = "s" + "".join("." + o for o in ops)
    lines = [f"    t = {chain}"]
    seq = rng.choice([None, "t.split(',')", "t.split()", "t.splitlines()", "t.split('=', 1)"])
    atoms = [f"len(t) {rng.choice(['==', '>', '<=', '!='])} {rng.randint(0, 6)}",
             f"t.startswith({rng.choice(['a', 'x-', 'K', '#'])!r})", f"t.endswith({rng.choice(['z', '!', 'Q'])!r})",
             f"t == {rng.choice(['go', 'a b', 'OK', ''])!r}"]
    if seq:
        lines.append(f"    p = {seq}")
        atoms += [f"len(p) == {rng.randint(0, 3)}", f"p[0] == {rng.choice(['a', 'k', ''])!r}",
                  f"p[-1].startswith({rng.choice(['v', '1'])!r})", f"len(p) >= {rng.randint(1, 3)}"]
    pick = rng.sample(atoms, rng.randint(1, 3))
    cond = (" and " if rng.random() < 0.6 else " or ").join(("not " if rng.random() < 0.2 else "") + "(" + a + ")" for a in pick)
    lines.append(f"    if {cond}:")
    return "def f(s: str):\n" + "\n".join(lines) + "\n        return 1\n    return 0\n", cond


def test_seeded_fuzz_no_candidate_violates_its_condition():
    import random

    rng = random.Random(20261113)
    checked = produced = 0
    for _ in range(24):
        src, cond = _fuzz_program(rng)
        for want in ("true", "false"):
            det, _why = _drive_all(src, "f", cond, None, want)
            for c in det:
                if not c.exact:  # a cut-point hint: the real evaluators decide, nothing is claimed
                    assert c.origin.startswith("cutpoint"), c
                    continue
                produced += 1
                seen = _observe(src, "f", cond, c.params)
                assert seen and seen[0] is (want == "true"), (src, cond, want, c.params, seen)
            checked += 1
    assert checked == 48 and produced > 20, (checked, produced)


def test_an_operand_that_raises_first_makes_the_whole_condition_raise_not_true():
    # found by the fuzz: p[0] raises on [] BEFORE the second operand could make the `or` true
    src = "def f(s: str):\n    p = s.splitlines()\n    if (p[0] == 'a') or (len(s) != 6):\n        return 1\n    return 0\n"
    cond = "(p[0] == 'a') or (len(s) != 6)"
    det = _assert_all_real(src, "f", cond)
    assert all(c.params["s"] != "" for c in det)


# ================================================================ design review set-3 diagnosis, group A: solver cost
import contextlib

import z3


@contextlib.contextmanager
def _z3_work():
    """Deterministic effort meter: Z3's own `rlimit count`, summed as per-check deltas (the statistic is cumulative per
    solver), not wall time."""
    box = {"rlimit": 0, "checks": 0, "max_check": 0}
    orig = z3.Solver.check
    prev = [None]  # `rlimit count` is cumulative over the whole Z3 context, not per solver

    def chk(self, *a):
        r = orig(self, *a)
        box["checks"] += 1
        st = self.statistics()
        for k in st.keys():
            if k == "rlimit count":
                v = st.get_key_value(k)
                if prev[0] is not None:
                    box["rlimit"] += v - prev[0]
                    box["max_check"] = max(box["max_check"], v - prev[0])
                prev[0] = v
        return r

    z3.Solver.check = chk
    try:
        probe = z3.Solver()
        probe.check()
        for k in probe.statistics().keys():
            if k == "rlimit count":
                prev[0] = probe.statistics().get_key_value(k)
        yield box
    finally:
        z3.Solver.check = orig


COST_CASES = {  # own shapes: stripped, filtered comprehensions; (source, condition, polarity, rlimit ceiling)
    "strip_filter_over_lines": (
        "def f(blob: str):\n    rows = [l.strip() for l in blob.splitlines() if l.strip() and not l.strip().startswith('#')]\n"
        "    if len(rows) == 2 and rows[1].lower().endswith('z'):\n        return 1\n    return 0\n",
        "len(rows) == 2 and rows[1].lower().endswith('z')", {"true": 40_000, "false": 60_000}),
    "strip_filter_over_csv": (
        "def f(s: str):\n    parts = [p.strip() for p in s.split(',') if p.strip()]\n"
        "    if len(parts) == 3 and parts[2].startswith('q'):\n        return 1\n    return 0\n",
        "len(parts) == 3 and parts[2].startswith('q')", {"true": 540_000, "false": 730_000}),
}


def _core_run(src, cond, want, per_query_ms=200):
    """The driver core with the wall deadline switched off (budget 1e6 ms): only the rlimit cuts decide, so the work
    is a function of the query and the hash seed, never of machine load. Returns (run, z3 work box)."""
    from hlith import drive_inputs as D

    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef))
    sl = D.collect_backward_slice(fn, _line_of(src, cond))
    c = sl.rewrite(ast.parse(cond, mode="eval").body)
    ps = D._build_params({a.arg: (ast.unparse(a.annotation) if a.annotation else None, None) for a in fn.args.args},
                         [c], dict(sl.locals_))
    with _z3_work() as w:
        run = D._core(ps, c, want == "true", [], dict(sl.locals_), per_query_ms, 10**6, 4)
    return run, w


def _core_run_isolated(src, cond, want, per_query_ms=200):
    """_core_run in a FRESH process with a fixed hash seed. Z3 orders terms by AST id, so the work a query needs depends
    on everything allocated in the same Z3 context before it (earlier tests in the file moved the 2D case from 1.2M to
    4.2M units); a pristine process makes the work a function of the query alone, whatever ran before and however
    loaded the machine is. Returns {"rlimit", "max_check", "z3_cands", "cands", "reason"}."""
    import json
    import os
    import subprocess
    import sys

    script = (
        "import importlib.util, json, sys\n"
        "sys.path[:0] = json.loads(sys.argv[6])\n"
        "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); t = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(t)\n"
        "run, w = t._core_run(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))\n"
        "print('RESULT' + json.dumps({'rlimit': w['rlimit'], 'max_check': w['max_check'], 'cands': len(run.cands),\n"
        "                            'z3_cands': sum(1 for _, o in run.cands if o != 'seed'), 'reason': run.reason}))\n")
    env = {**os.environ, "PYTHONHASHSEED": "0"}
    out = subprocess.run([sys.executable, "-I", "-c", script, __file__, src, cond, want, str(per_query_ms),
                          json.dumps([p for p in sys.path if p])],
                         capture_output=True, text=True, env=env, timeout=600)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout.split("RESULT", 1)[1])


@pytest.mark.parametrize("name", sorted(COST_CASES))
def test_strip_and_filtered_comprehension_cost_is_bounded_by_deterministic_work(name):
    src, cond, ceilings = COST_CASES[name]
    for want, ceiling in ceilings.items():
        r = _core_run_isolated(src, cond, want)  # fresh process, no wall deadline: neither load nor test order matter
        assert r["z3_cands"] and r["rlimit"] <= ceiling, (name, want, r)
        assert _assert_all_real(src, "f", cond, want=want)  # and the results are real on Python (unmetered, retried)


def test_padded_input_is_found_when_the_cheap_restriction_finds_nothing():
    # `len(s) == 4 and s.strip() == 'ab'` is impossible for unpadded s (strip would be s itself): the exact
    # decomposition (fallback) must still find '  ab' style inputs
    src = "def f(s: str):\n    t = s.strip()\n    if len(s) == 4 and t == 'ab':\n        return 1\n    return 0\n"
    det = _assert_all_real(src, "f", "len(s) == 4 and t == 'ab'")
    assert all(len(c.params["s"]) == 4 and c.params["s"].strip() == "ab" for c in det)


def test_filter_where_some_elements_fail_is_found_by_the_exact_fallback():
    # the all-pass restriction cannot make len(result) < len(source); the exact compaction can
    src = ("def f(s: str):\n    xs = [p for p in s.split(',') if p.startswith('x')]\n"
           "    if len(s.split(',')) == 3 and len(xs) == 1:\n        return 1\n    return 0\n")
    det = _assert_all_real(src, "f", "len(s.split(',')) == 3 and len(xs) == 1")
    assert all(len(c.params["s"].split(",")) == 3 and sum(p.startswith("x") for p in c.params["s"].split(",")) == 1 for c in det)


# ================================================================ design review set-3 diagnosis, group B: typing and coalescing
GROUP_B = {
    "tuple_unpacked_parameter": (
        "def f(header):\n    name, value = header\n    if name.lower() == 'x-id' and value.startswith('7'):\n        return 1\n    return 0\n",
        "name.lower() == 'x-id' and value.startswith('7')"),
    "or_empty_dict_coalescing": (
        "def f(proxies=None, scheme='http'):\n    proxies = proxies or {}\n    p = proxies.get(scheme, '')\n"
        "    if p.startswith('socks'):\n        return 1\n    return 0\n",
        "p.startswith('socks')"),
    "or_empty_string_coalescing": (
        "def f(label=None):\n    t = label or ''\n    if t.strip() == 'go' and len(t) == 2:\n        return 1\n    return 0\n",
        "t.strip() == 'go' and len(t) == 2"),
    "ifexp_with_path_branches": (
        "def f(p):\n    base = p.parent if len(p.parts) > 1 else p\n    if base.name == 'pkg' and len(base.parts) == 2:\n        return 1\n    return 0\n",
        "base.name == 'pkg' and len(base.parts) == 2"),
}


@pytest.mark.parametrize("name", sorted(GROUP_B))
def test_group_b_shapes_are_driven_both_ways_on_real_python(name):
    src, cond = GROUP_B[name]
    for want in ("true", "false"):
        _assert_all_real(src, "f", cond, want=want)


def test_usage_does_not_type_a_bare_root_or_a_coalesced_name_as_a_number():
    from hlith.drive_inputs import _usage

    root = ast.parse("header", mode="eval").body          # a bare root name (the tuple temp of `a, b = header`)
    boolop = ast.parse("proxies or {}", mode="eval").body
    assert _usage([root], {"header"}) == {"header": set()}
    assert _usage([boolop], {"proxies"}) == {"proxies": set()}
    use = _usage([ast.parse("Path(p).name == float(q) and list(d.keys())", mode="eval").body], {"p", "q", "d"})
    assert use["p"] == {"obj"} and use["q"] == {"num"} and use["d"] == {"dict"}, use


# ================================================================ design review set-3 diagnosis, group C: constructs
GROUP_C = {
    "float_parameters_get_integer_witnesses": (
        "def f(timeout: float, retries: int):\n    if timeout > 3 and retries == 2 and timeout < 9:\n        return 1\n    return 0\n",
        "timeout > 3 and retries == 2 and timeout < 9"),
    "isinstance_on_a_derived_local": (
        "def f(items):\n    first = items[0]\n    if isinstance(first, str) and first.startswith('a'):\n        return 1\n    return 0\n",
        "isinstance(first, str) and first.startswith('a')"),
    "path_of_a_string": (
        "from pathlib import Path\n\n\ndef f(name: str):\n    p = Path(name)\n    if p.name == 'conf' and len(p.parts) == 2:\n        return 1\n    return 0\n",
        "p.name == 'conf' and len(p.parts) == 2"),
    "path_join_operator": (
        "from pathlib import Path\n\n\ndef f(base: str, leaf: str):\n    p = Path(base) / leaf\n"
        "    if p.name == 'x.cfg' and len(p.parts) == 3 and p.parent.name == 'etc':\n        return 1\n    return 0\n",
        "p.name == 'x.cfg' and len(p.parts) == 3 and p.parent.name == 'etc'"),
    "relative_to_and_is_absolute": (
        "from pathlib import Path\n\n\ndef f(p: str):\n    q = Path(p)\n    rel = q.relative_to('srv/app')\n"
        "    if not q.is_absolute() and len(rel.parts) == 2 and rel.name == 'a.js':\n        return 1\n    return 0\n",
        "not q.is_absolute() and len(rel.parts) == 2 and rel.name == 'a.js'"),
    "int_and_float_calls": (
        "def f(n: int, w: float):\n    k = int(n) + 1\n    if k == 5 and float(w) > 2:\n        return 1\n    return 0\n",
        "k == 5 and float(w) > 2"),
    "dict_keys_membership": (
        "def f(d):\n    if 'k' in d.keys() and d.get('k', '') == 'v':\n        return 1\n    return 0\n",
        "'k' in d.keys() and d.get('k', '') == 'v'"),
}


@pytest.mark.parametrize("name", sorted(GROUP_C))
def test_group_c_constructs_are_driven_both_ways_on_real_python(name):
    src, cond = GROUP_C[name]
    for want in ("true", "false"):
        _assert_all_real(src, "f", cond, want=want)


def test_float_parameter_witness_is_a_float():
    src, cond = GROUP_C["float_parameters_get_integer_witnesses"]
    det = _assert_all_real(src, "f", cond)
    assert all(isinstance(c.params["timeout"], float) for c in det), [c.params for c in det]


def test_resolve_is_identity_but_every_candidate_is_a_hint():
    src = "from pathlib import Path\n\n\ndef f(p: str):\n    r = Path(p).resolve()\n    if r.name == 'q' and len(p) > 0:\n        return 1\n    return 0\n"
    cond = "r.name == 'q' and len(p) > 0"
    det, why = _drive_all(src, "f", cond, None, "true")
    assert det and not any(c.exact for c in det), [(c.params, c.exact) for c in det]


def test_a_condition_that_depends_on_the_absolute_prefix_yields_hints_the_real_evaluator_rejects():
    src = "from pathlib import Path\n\n\ndef f(p: str):\n    r = Path(p).resolve()\n    if r.parts[0] == 'a':\n        return 1\n    return 0\n"
    cond = "r.parts[0] == 'a'"
    det, why = _drive_all(src, "f", cond, None, "true")
    assert det and not any(c.exact for c in det)
    for c in det:  # real Python: resolve() is absolute, so parts[0] is '/', never 'a'
        seen = _observe(src, "f", cond, c.params)
        assert seen == [False], (c.params, seen)  # the loop would report: hints only, none took it


def test_other_path_methods_stay_named_stops():
    src = "from pathlib import Path\n\n\ndef f(p: str):\n    q = Path(p).expanduser()\n    if q.name == 'x':\n        return 1\n    return 0\n"
    det, why = _drive_once(src, "f", "q.name == 'x'", None, "true", timeout_ms=400)
    assert not det and ".expanduser()" in why[0], why


# ---------------------------------------------------------------- seeded fuzz over the new constructs
def _fuzz_c_program(rng):
    kind = rng.choice(["path", "join", "float", "mix"])
    lines = []
    if kind in ("path", "mix"):
        lines.append("    p = Path(s)")
    if kind == "join":
        lines.append("    p = Path(s) / leaf")
    atoms = []
    if kind in ("path", "join", "mix"):
        atoms += [f"p.name == {rng.choice(['a', 'conf', 'x.py'])!r}", f"len(p.parts) {rng.choice(['==', '>=', '<'])} {rng.randint(1, 3)}",
                  f"p.parent.name == {rng.choice(['etc', 'pkg'])!r}", "not p.is_absolute()", f"p.name.startswith({rng.choice(['x', 'c'])!r})"]
    if kind in ("float", "mix"):
        atoms += [f"w {rng.choice(['>', '<=', '=='])} {rng.randint(-3, 9)}", f"int(w) + {rng.randint(0, 3)} == {rng.randint(0, 9)}"]
    pick = rng.sample(atoms, min(len(atoms), rng.randint(1, 3)))
    cond = (" and " if rng.random() < 0.7 else " or ").join(pick)
    sig = "s: str" + (", leaf: str" if kind == "join" else "") + (", w: float" if kind in ("float", "mix") else "")
    return ("from pathlib import Path\n\n\ndef f(%s):\n%s\n    if %s:\n        return 1\n    return 0\n" % (sig, "\n".join(lines) or "    pass", cond)), cond


def test_seeded_fuzz_new_constructs_no_candidate_violates_its_condition():
    import random

    rng = random.Random(14112026)
    produced = 0
    for _ in range(18):
        src, cond = _fuzz_c_program(rng)
        for want in ("true", "false"):
            det, _why = _drive_all(src, "f", cond, None, want)
            for c in det:
                produced += 1
                seen = _observe(src, "f", cond, c.params)
                assert seen and seen[0] is (want == "true"), (src, want, c.params, seen)
    assert produced > 15, produced


# ---------------------------------------------------------------- cut-point suffix solving (design review set-4 packet)
# Own shapes. The prefix of the condition cannot be translated (loop / try / one-armed if / unmodelled call); the
# suffix is solved over the cut local and projected back to the entry parameter. Ground truth: real Python on the
# ORIGINAL function; every cut-point candidate must be exact=False (a hint).
CUT_CASES = {
    "loop_append_join": (
        "def f(s: str):\n    parts = []\n    for x in s.split(','):\n        parts.append(x.strip())\n"
        "    if len(parts) == 2 and parts[0] == 'xprobe' and parts[1].startswith('tail'):\n        return 1\n    return 0\n",
        "len(parts) == 2 and parts[0] == 'xprobe' and parts[1].startswith('tail')", True),
    "loop_filter_lower_lines": (
        "def f(text: str):\n    out = []\n    for ln in text.splitlines():\n        if ln.strip():\n            out.append(ln.strip().lower())\n"
        "    if len(out) == 2 and out[0] == 'alpha':\n        return 1\n    return 0\n",
        "len(out) == 2 and out[0] == 'alpha'", True),
    "try_except_int": (
        "def f(s: str):\n    try:\n        n = int(s)\n    except ValueError:\n        n = 0\n    if n > 5:\n        return 1\n    return 0\n",
        "n > 5", True),
    "unmodelled_call_repr_dict": (
        "def f(value: dict):\n    rendered = repr(value)\n    if rendered == \"{'xprobe': 'tail'}\":\n        return 1\n    return 0\n",
        "rendered == \"{'xprobe': 'tail'}\"", True),
    "unmodelled_helper_normalise": (
        "def _norm(x):\n    return x.lower().strip().replace('-', '_')\n\n\ndef f(name: str):\n    key = _norm(name)\n"
        "    if key == 'admin':\n        return 1\n    return 0\n",
        "key == 'admin'", True),
    "one_armed_if_assignment": (
        "def f(flag: bool, a: str):\n    t = ''\n    for _ in range(1):\n        if flag:\n            t = a.strip()\n    if t == 'x':\n        return 1\n    return 0\n",
        "t == 'x'", False),  # the guard `flag` of the one-armed assignment is not projected: honest miss for `true`
    "dict_copy_update": (
        "def f(opts: dict, extra: dict):\n    cfg = dict(opts)\n    cfg.update(extra)\n    if cfg.get('mode') == 'fast':\n        return 1\n    return 0\n",
        "cfg.get('mode') == 'fast'", True),
    "cidr_mask_via_rpartition": (
        "def f(addr: str):\n    host, _, mask = addr.rpartition('/')\n    bits = int(mask)\n    if bits > 24 and bits <= 28:\n        return 1\n    return 0\n",
        "bits > 24 and bits <= 28", True),
    "accumulate_chars": (
        "def f(s: str):\n    buf = ''\n    for ch in s:\n        if ch.isalnum():\n            buf += ch\n    if buf == 'abc':\n        return 1\n    return 0\n",
        "buf == 'abc'", True),
    "json_loads": (
        "import json\n\n\ndef f(raw: str):\n    obj = json.loads(raw)\n    if obj.get('mode') == 'strict':\n        return 1\n    return 0\n",
        "obj.get('mode') == 'strict'", True),
    # the cut value reaches the condition only through a transformation the adapters do not invert: expected misses
    "sum_over_list_not_invertible": (
        "def f(nums: list):\n    total = 0\n    for x in nums:\n        total += x\n    if total > 10:\n        return 1\n    return 0\n",
        "total > 10", False),
    "lengths_of_items_not_invertible": (
        "def f(paths: list):\n    sizes = []\n    for p in paths:\n        sizes.append(len(p))\n    if len(sizes) == 2 and sizes[0] > 3:\n        return 1\n    return 0\n",
        "len(sizes) == 2 and sizes[0] > 3", False),
}


def _cut_rates():
    rows = []
    for name, (src, cond, expect_hit) in CUT_CASES.items():
        for want in ("true", "false"):
            det, why = _drive_all(src, "f", cond, None, want)
            wanted = want == "true"
            hits = 0
            for c in det:
                assert c.exact is False or not c.origin.startswith('cutpoint'), (name, c)
                seen = _observe(src, "f", cond, c.params)
                if seen and seen[0] is wanted:
                    hits += 1
            rows.append((name, want, len(det), hits, expect_hit))
    return rows


def test_cutpoint_candidates_are_always_hints_and_reach_the_condition_on_real_python():
    rows = _cut_rates()
    hit_cases = [(n, w) for n, w, k, h, e in rows if h > 0]
    # every shape declared invertible is driven to BOTH truth values end to end on the real function
    for n, w, k, h, e in rows:
        if e:
            assert h > 0, (n, w, k, h)
    # the non-invertible shapes may not report success they do not have: whatever they emit is only a hint
    assert len(rows) == 2 * len(CUT_CASES)
    print("CUT_RATE_CASES", len(hit_cases), "/", len(rows))


def test_cutpoint_is_not_used_when_the_whole_prefix_is_modelled():
    src = "def f(title: str):\n    slug = title.strip().lower()\n    if slug.startswith('draft-'):\n        return 1\n    return 0\n"
    det, _ = _drive_all(src, "f", "slug.startswith('draft-')", None, "true")
    assert det and not any(c.origin.startswith("cutpoint") for c in det)
    assert all(c.exact for c in det)


def test_if_try_timedelta_rebind_projects_boundary_inputs_through_both_branches():
    """The naturaldelta shape must seed the original parameter through both sides of its timedelta rebinding."""
    import datetime

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            int(value)\n"
        "            value = float(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    delta = abs(delta)\n"
        "    years = delta.days // 365\n"
        "    days = delta.days % 365\n"
        "    if years == 0 and days < 1:\n"
        "        if delta.seconds == 0:\n"
        "            return False\n"
        "        if delta.seconds == 1:\n"
        "            return False\n"
        "        if delta.seconds < 60:\n"
        "            return True\n"
        "    return False\n"
    )

    for want, seconds in (("true", 59), ("false", 60)):
        candidates, reasons = _drive_all(src, "f", "delta.seconds < 60", None, want)
        assert candidates, (want, reasons)
        reached_values = []
        for candidate in candidates:
            seen = _observe(src, "f", "delta.seconds < 60", candidate.params)
            if seen == [want == "true"]:
                reached_values.append(candidate.params["value"])

        assert any(type(value) is datetime.timedelta and abs(value.total_seconds()) == seconds
                   for value in reached_values), (want, reasons, reached_values)
        assert any(type(value) in (int, float) and abs(value) == seconds
                   for value in reached_values), (want, reasons, reached_values)


def test_chained_timedelta_seconds_range_reaches_boundaries_through_if_rebinding():
    import datetime

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            int(value)\n"
        "            value = float(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    delta = abs(delta)\n"
        "    years = delta.days // 365\n"
        "    days = delta.days % 365\n"
        "    if years == 0 and days < 1:\n"
        "        if 60 <= delta.seconds < 120:\n"
        "            return True\n"
        "    return False\n"
    )

    for want, inside in (("true", True), ("false", False)):
        candidates, reasons = _drive_all(src, "f", "60 <= delta.seconds < 120", None, want)
        assert candidates, (want, reasons)
        values = []
        for candidate in candidates:
            assert candidate.exact is False, candidate
            seen = _observe(src, "f", "60 <= delta.seconds < 120", candidate.params)
            assert seen == [inside], (want, candidate.params, seen)
            values.append(candidate.params["value"])

        assert any(type(value) is datetime.timedelta for value in values), (want, reasons, values)
        assert any(type(value) in (int, float) for value in values), (want, reasons, values)
        seconds = [
            abs(value).seconds if type(value) is datetime.timedelta
            else datetime.timedelta(seconds=abs(value)).seconds
            for value in values
        ]
        assert all((60 <= value < 120) is inside for value in seconds), (want, reasons, values)


def test_pre_naturaldelta_seconds_boundary_projects_only_to_value():
    """The pre-refactor local ``seconds`` comes from ``delta.seconds`` and must project to ``value``.

    Keep the real parameter/default and rebinding shape: a leaked solver value must not become
    ``minimum_unit`` and raise before the target condition.
    """
    import datetime as dt

    src = '''
import datetime as dt
from enum import Enum

class Unit(Enum):
    SECONDS = 1
    MILLISECONDS = 2
    MICROSECONDS = 3

def f(value: dt.timedelta | float, months: bool = True, minimum_unit: str = "seconds"):
    tmp = Unit[minimum_unit.upper()]
    if tmp not in (Unit.SECONDS, Unit.MILLISECONDS, Unit.MICROSECONDS):
        raise ValueError(minimum_unit)
    min_unit = tmp
    if isinstance(value, dt.timedelta):
        delta = value
    else:
        try:
            value = int(value)
            delta = dt.timedelta(seconds=value)
        except (ValueError, TypeError):
            return str(value)
    use_months = months
    delta = abs(delta)
    seconds = delta.seconds
    days = delta.days
    years = days // 365
    days = days % 365
    num_months = int(days // 30.5)
    if not years and days < 1:
        if seconds == 0:
            if min_unit == Unit.MICROSECONDS and delta.microseconds < 1000:
                return "microseconds"
            if min_unit == Unit.MILLISECONDS or (
                min_unit == Unit.MICROSECONDS and 1000 <= delta.microseconds < 1000000
            ):
                return "milliseconds"
            return "a moment"
        if seconds == 1:
            return "a second"
        if seconds < 60:
            return "seconds"
        if 60 <= seconds < 120:
            return "a minute"
        if 120 <= seconds < 3600:
            return "minutes"
        if 3600 <= seconds < 3600 * 2:
            return "an hour"
    return "other"
'''
    condition = "3600 <= seconds < 3600 * 2"
    target_line = _line_of(src, condition)
    boundary_goal = "seconds == 3600 + 1"
    candidates, why = _drive_all(src, "f", boundary_goal, target_line, "true")
    assert candidates, why
    assert all(not candidate.exact for candidate in candidates), candidates

    valid = []
    for candidate in candidates:
        assert candidate.params.get("minimum_unit", "seconds") == "seconds", candidate.params
        if _observe(src, "f", condition, candidate.params) == [True]:
            valid.append(candidate.params["value"])

    assert any(type(value) is dt.timedelta and abs(value.total_seconds()) == 3601
               for value in valid), valid
    assert any(type(value) in (int, float) and abs(value) == 3601
               for value in valid), valid


def test_if_try_assignment_rebinding_drives_real_chained_timedelta_boundaries():
    import datetime
    from hlith import drive_inputs as D

    src = (
        "def f(value):\n"
        "    import datetime as dt\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    delta = abs(delta)\n"
        "    years = delta.days // 365\n"
        "    days = delta.days % 365\n"
        "    if not years and days < 1:\n"
        "        if 60 <= delta.seconds < 120:\n"
        "            return True\n"
        "    return False\n"
    )

    fn = next(n for n in D.ast.walk(D.ast.parse(src)) if isinstance(n, D.ast.FunctionDef) and n.name == "f")
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    sliced = D.collect_backward_slice(fn, target.lineno)
    assert "delta" not in sliced.poisoned
    assert "value" not in sliced.poisoned
    initial_delta = sliced.locals_["delta#1"]
    assert isinstance(initial_delta, D.ast.IfExp)
    assert ".timedelta(seconds=int(value))" in D.ast.unparse(initial_delta)

    expected = {"true": {60, 61, 119}, "false": {59, 120, 121}}
    for want, boundary_seconds in expected.items():
        candidates, reasons = _drive_all(
            src, "f", "60 <= delta.seconds < 120", None, want, max_per_condition=32
        )
        assert candidates, (want, reasons)
        values = []
        observed_seconds = set()
        for candidate in candidates:
            assert candidate.exact is False, candidate
            seen = _observe(src, "f", "60 <= delta.seconds < 120", candidate.params)
            assert seen == [want == "true"], (want, candidate.params, seen)
            value = candidate.params["value"]
            values.append(value)
            if type(value) is datetime.timedelta:
                observed_seconds.add(abs(value).seconds)
            elif type(value) in (int, float):
                observed_seconds.add(datetime.timedelta(seconds=abs(int(value))).seconds)

        assert any(type(value) is datetime.timedelta for value in values), (want, reasons, values)
        assert any(type(value) in (int, float) for value in values), (want, reasons, values)
        assert boundary_seconds <= observed_seconds, (want, reasons, observed_seconds)


def test_if_try_rebinding_with_fallthrough_handler_stays_poisoned():
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            pass\n"
        "    if delta.seconds == 60:\n"
        "        return True\n"
    )
    fn = next(n for n in D.ast.walk(D.ast.parse(src)) if isinstance(n, D.ast.FunctionDef) and n.name == "f")
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    sliced = D.collect_backward_slice(fn, target.lineno)
    assert "delta" in sliced.poisoned
    assert "delta" not in sliced.version


def test_if_try_rebinding_with_nonassignment_body_stays_poisoned():
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            if value < 0:\n"
        "                value = -value\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    if delta.seconds == 60:\n"
        "        return True\n"
    )
    fn = next(n for n in D.ast.walk(D.ast.parse(src)) if isinstance(n, D.ast.FunctionDef) and n.name == "f")
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    sliced = D.collect_backward_slice(fn, target.lineno)
    assert "delta" in sliced.poisoned
    assert "delta" not in sliced.version


def test_if_try_with_else_clause_stays_poisoned():
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "        else:\n"
        "            delta = dt.timedelta(seconds=1)\n"
        "    if delta.seconds == 60:\n"
        "        return True\n"
    )
    fn = next(n for n in D.ast.walk(D.ast.parse(src)) if isinstance(n, D.ast.FunctionDef) and n.name == "f")
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    sliced = D.collect_backward_slice(fn, target.lineno)
    assert "delta" in sliced.poisoned
    assert "value" in sliced.poisoned
    assert "delta" not in sliced.version
    assert "value" not in sliced.version


def test_if_try_with_finally_clause_stays_poisoned():
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "        finally:\n"
        "            delta = dt.timedelta(seconds=1)\n"
        "    if delta.seconds == 60:\n"
        "        return True\n"
    )
    fn = next(n for n in D.ast.walk(D.ast.parse(src)) if isinstance(n, D.ast.FunctionDef) and n.name == "f")
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    sliced = D.collect_backward_slice(fn, target.lineno)
    assert "delta" in sliced.poisoned
    assert "value" in sliced.poisoned
    assert "delta" not in sliced.version
    assert "value" not in sliced.version


def test_humanize_naturaldelta_projects_binop_seconds_boundary_neighbors():
    import datetime

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    delta = abs(delta)\n"
        "    years = delta.days // 365\n"
        "    days = delta.days % 365\n"
        "    if not years and days < 1:\n"
        "        if 3600 <= delta.seconds < 3600 * 2:\n"
        "            return True\n"
        "        if 3600 < delta.seconds:\n"
        "            return False\n"
        "    return False\n"
    )
    condition = "3600 <= delta.seconds < 3600 * 2"
    expected = {"true": {7199}, "false": {7200, 7201}}
    observed_by_type = {
        want: {"timedelta": set(), "numeric": set()}
        for want in expected
    }

    for want, boundary_seconds in expected.items():
        candidates, reasons = _drive_all(
            src, "f", condition, None, want, max_per_condition=32
        )
        assert candidates, (want, reasons)
        for candidate in candidates:
            assert candidate.exact is False, candidate
            assert _observe(src, "f", condition, candidate.params) == [want == "true"]
            value = candidate.params["value"]
            if type(value) is datetime.timedelta:
                seconds = abs(value).seconds
                value_kind = "timedelta"
            elif type(value) in (int, float):
                seconds = datetime.timedelta(seconds=abs(value)).seconds
                value_kind = "numeric"
            else:
                continue
            observed_by_type[want][value_kind].add(seconds)

        for value_kind in ("timedelta", "numeric"):
            assert boundary_seconds <= observed_by_type[want][value_kind], (
                want, value_kind, reasons, observed_by_type[want][value_kind]
            )


def test_humanize_naturaldelta_does_not_fold_name_call_or_zero_divisor_boundaries():
    base_src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return False\n"
        "    delta = abs(delta)\n"
        "    years = delta.days // 365\n"
        "    days = delta.days % 365\n"
        "    if not years and days < 1:\n"
        "        if 3600 <= delta.seconds < RHS:\n"
        "            return True\n"
        "    return False\n"
    )
    cases = (
        ("3600 * scale", "scale = 2\n"),
        ("3600 * factor()", "def factor():\n    raise AssertionError('call must stay opaque')\n"),
        ("3600 // 0", ""),
        ("3600 / 2", ""),
        ("3600 * 999999999999999999999999999999", ""),
    )
    target_seconds = {7199, 7200, 7201}

    for rhs, prelude in cases:
        src = base_src.replace("def f(value):\n", prelude + "def f(value):\n").replace("RHS", rhs)
        condition = f"3600 <= delta.seconds < {rhs}"
        candidates, reasons = _drive_all(
            src, "f", condition, None, "true", max_per_condition=32
        )
        projected = [
            candidate.origin for candidate in candidates
            if "seconds boundary" in candidate.origin
        ]
        assert not any(
            any(f"seconds boundary {seconds}" in origin for seconds in target_seconds)
            for origin in projected
        ), (rhs, reasons, projected)


def test_deep_literal_seconds_boundary_is_bounded_and_fails_closed():
    import ast
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value):\n"
        "    delta = dt.timedelta(seconds=value)\n"
        "    seconds = delta.seconds\n"
        "    if seconds == 1:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = next(node for node in ast.walk(ast.parse(src))
              if isinstance(node, ast.FunctionDef) and node.name == "f")
    literal = ast.Constant(value=1)
    for _ in range(1200):
        literal = ast.BinOp(left=literal, op=ast.Add(), right=ast.Constant(value=1))
    condition = ast.Compare(
        left=ast.Name(id="seconds", ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[literal],
    )

    candidates, why = D.cutpoint_drive(
        fn,
        5,
        condition,
        True,
        [],
        {"seconds": ast.Name(id="seconds", ctx=ast.Load())},
        {"value": ("int", ast.Name(id="value", ctx=ast.Load()))},
        100,
        8,
    )

    assert candidates == []
    assert "depth/work" in why

    def balanced(depth):
        if depth == 0:
            return ast.Constant(value=1)
        return ast.BinOp(left=balanced(depth - 1), op=ast.Add(), right=balanced(depth - 1))

    broad_condition = ast.Compare(
        left=ast.Name(id="seconds", ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[balanced(8)],
    )
    candidates, why = D.cutpoint_drive(
        fn,
        5,
        broad_condition,
        True,
        [],
        {"seconds": ast.Name(id="seconds", ctx=ast.Load())},
        {"value": ("int", ast.Name(id="value", ctx=ast.Load()))},
        100,
        8,
    )
    assert candidates == []
    assert "depth/work" in why


def test_seconds_receiver_projection_excludes_guard_only_parameter_sources():
    import ast
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "class Unit:\n"
        "    SECONDS = 'seconds'\n"
        "    MILLISECONDS = 'milliseconds'\n"
        "    MICROSECONDS = 'microseconds'\n"
        "def f(value: dt.timedelta | int | float, minimum_unit: str = 'seconds'):\n"
        "    tmp = Unit[minimum_unit.upper()]\n"
        "    if tmp not in (Unit.SECONDS, Unit.MILLISECONDS, Unit.MICROSECONDS):\n"
        "        raise ValueError('unsupported')\n"
        "    min_unit = tmp\n"
        "    if isinstance(value, dt.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        try:\n"
        "            value = int(value)\n"
        "            delta = dt.timedelta(seconds=value)\n"
        "        except (ValueError, TypeError):\n"
        "            return str(value)\n"
        "    delta = abs(delta)\n"
        "    seconds = delta.seconds\n"
        "    days = delta.days\n"
        "    years = days // 365\n"
        "    if not years and days < 1:\n"
        "        if seconds == 0:\n"
        "            if min_unit == Unit.MICROSECONDS and delta.microseconds < 1000:\n"
        "                return 'microseconds'\n"
        "            if min_unit == Unit.MILLISECONDS or (\n"
        "                min_unit == Unit.MICROSECONDS and 1000 <= delta.microseconds < 1000000\n"
        "            ):\n"
        "                return 'milliseconds'\n"
        "        if seconds == 1:\n"
        "            return 'a second'\n"
        "        if seconds < 60:\n"
        "            return 'seconds'\n"
        "        if 60 <= seconds < 120:\n"
        "            return 'a minute'\n"
        "        if 120 <= seconds < 3600:\n"
        "            return 'minutes'\n"
        "        if 3600 <= seconds < 3600 * 2:\n"
        "            return 'an hour'\n"
        "        if 3600 < seconds:\n"
        "            return 'hours'\n"
        "    return 'other'\n"
    )
    fn = next(node for node in ast.walk(ast.parse(src))
              if isinstance(node, ast.FunctionDef) and node.name == "f")
    target = next(node for node in ast.walk(fn)
                  if isinstance(node, ast.If) and ast.unparse(node.test) == "3600 <= seconds < 3600 * 2")
    prior_target = next(node for node in ast.walk(fn)
                        if isinstance(node, ast.If) and ast.unparse(node.test) == "120 <= seconds < 3600")
    params = [(arg.arg, ast.unparse(arg.annotation) if arg.annotation else None)
              for arg in fn.args.args]
    candidates, _reasons = D.candidates_detailed(
        params,
        ["3600 == seconds + (-1)"],
        want="true",
        fn_ast=fn,
        target_lineno=target.lineno,
        timeout_ms=200,
        max_per_condition=16,
    )

    assert any(candidate.params.get("value") == 3601 for candidate in candidates), candidates
    assert all("minimum_unit" not in candidate.params for candidate in candidates), candidates
    lower_neighbours, _lower_reasons = D.candidates_detailed(
        params,
        ["3600 == seconds + 1"],
        want="true",
        fn_ast=fn,
        target_lineno=prior_target.lineno,
        timeout_ms=200,
        max_per_condition=16,
    )
    lower_values = [candidate.params.get("value") for candidate in lower_neighbours]
    assert any(type(value) in (int, float) and value == 3599 for value in lower_values), lower_neighbours
    assert {"__timedelta__": [0, 3599, 0]} in lower_values, lower_neighbours


def test_abs_timedelta_projection_skips_unrepresentable_negative_maximum():
    from datetime import timedelta
    from hlith import drive_inputs

    projected = drive_inputs._project(timedelta.max, "timedelta", [], adapters={"abs", "timedelta_alias"})
    assert projected == [(timedelta.max, "timedelta alias")]


def test_unmodelled_earlier_guard_is_a_hint_not_an_abort():
    src = ("def f(x: int, y: str):\n    if helper(y):\n        return 0\n    if x > 5:\n        return 1\n    return 2\n")
    det, why = _drive_all(src, "f", "x > 5", None, "true")
    assert det, why
    assert all(not c.exact for c in det)
    assert all(_observe(src.replace("helper(y)", "False"), "f", "x > 5", c.params)[0] is True for c in det)


GROUP_1 = {  # own cases for the packet's item (2): keys(), int(str), copy.*, lazily modelled container annotations
    "keys_len": (
        "def f(cfg: dict):\n    if cfg.get('a') == 1 and cfg.get('b') == 2 and len(cfg.keys()) == 2:\n        return 1\n    return 0\n",
        "cfg.get('a') == 1 and cfg.get('b') == 2 and len(cfg.keys()) == 2"),
    "int_of_str": (
        "def f(s: str):\n    n = int(s)\n    if n > 7 and n < 10:\n        return 1\n    return 0\n", "n > 7 and n < 10"),
    "deepcopy_dict": (
        "import copy\n\n\ndef f(d: dict):\n    c = copy.deepcopy(d)\n    if c.get('k') == 'v':\n        return 1\n    return 0\n",
        "c.get('k') == 'v'"),
    "annotated_list_of_str": (
        "def f(items: list):\n    if len(items) == 2 and items[0] == 'a':\n        return 1\n    return 0\n", "len(items) == 2 and items[0] == 'a'"),
}


@pytest.mark.parametrize("name", sorted(GROUP_1))
def test_group_1_shapes_are_driven_both_ways_on_real_python(name):
    src, cond = GROUP_1[name]
    for want in ("true", "false"):
        _assert_all_real(src, "f", cond, want=want)


def test_a_local_mutated_in_place_is_not_modelled_as_its_definition():
    # dict(opts) then .update(extra): the SSA definition is stale at the target; no exact candidate may claim otherwise
    src = "def f(opts: dict, extra: dict):\n    cfg = dict(opts)\n    cfg.update(extra)\n    if cfg.get('mode') == 'fast':\n        return 1\n    return 0\n"
    sl = _slice(src, 5)
    assert "cfg" in sl.poisoned and "in place" in sl.poisoned["cfg"]
    det, _ = _drive_all(src, "f", "cfg.get('mode') == 'fast'", None, "true")
    assert all(not c.exact for c in det)


def _fuzz_cut_program(rng):
    sep = rng.choice([",", ";", "|", "/"])
    tf = rng.choice(["x", "x.strip()", "x.strip().lower()", "x.lower()"])
    lit = rng.choice(["alpha", "beta", "gamma", "omega"])
    k = rng.choice([1, 2, 3])
    terms = [f"len(parts) == {k}"]
    if rng.random() < 0.8:
        terms.append(f"parts[0] == '{lit}'")
    if k >= 2 and rng.random() < 0.6:
        terms.append(f"parts[{k - 1}].startswith('{lit[:2]}')")
    cond = " and ".join(terms)
    src = (f"def f(s: str):\n    parts = []\n    for x in s.split('{sep}'):\n        parts.append({tf})\n"
           f"    if {cond}:\n        return 1\n    return 0\n")
    return src, cond


def test_cutpoint_fuzz_never_claims_exactness_and_reports_the_end_to_end_rate():
    import random

    rng = random.Random(20261114)
    solved = reached = rows = cands = exact_bad = 0
    for _ in range(30):
        src, cond = _fuzz_cut_program(rng)
        for want in ("true", "false"):
            det, _why = _drive_all(src, "f", cond, None, want)
            rows += 1
            solved += bool(det)
            ok = 0
            for c in det:
                assert not c.exact and c.origin.startswith("cutpoint"), (src, cond, c)
                cands += 1
                seen = _observe(src, "f", cond, c.params)
                ok += bool(seen and seen[0] is (want == "true"))
            reached += ok > 0
    print("CUT_FUZZ solved", solved, "reached", reached, "of", rows, "candidates", cands)
    assert solved >= rows * 0.9 and reached >= rows * 0.8, (solved, reached, rows)


EXC_CASES = {
    "isinstance_exception": ("def f(err):\n    if isinstance(err, Exception):\n        return 1\n    return 0\n", "isinstance(err, Exception)"),
    "lookup_not_key": ("def f(err):\n    if isinstance(err, LookupError) and not isinstance(err, KeyError):\n        return 1\n    return 0\n",
                       "isinstance(err, LookupError) and not isinstance(err, KeyError)"),
    "tuple_of_classes": ("def f(err):\n    if isinstance(err, (OSError, ValueError)):\n        return 1\n    return 0\n",
                         "isinstance(err, (OSError, ValueError))"),
    "base_exception_itself_is_not_an_exception": ("def f(err):\n    if isinstance(err, BaseException) and not isinstance(err, Exception):\n        return 1\n    return 0\n",
                                                 "isinstance(err, BaseException) and not isinstance(err, Exception)"),
}


@pytest.mark.parametrize("name", sorted(EXC_CASES))
def test_exception_classes_are_builtin_types_for_isinstance(name):
    src, cond = EXC_CASES[name]
    for want in ("true", "false"):
        det, why = _drive_all(src, "f", cond, None, want)
        assert det, (name, want, why)
        for c in det:
            seen = _observe(src, "f", cond, c.params)
            assert seen and seen[0] is (want == "true"), (name, c.params, seen)


def test_exception_types_do_not_leak_into_unrelated_any_parameters():
    src = "def f(x):\n    if isinstance(x, (int, str)) or x is None:\n        return 1\n    return 0\n"
    det, _ = _drive_all(src, "f", "isinstance(x, (int, str)) or x is None", None, "false")
    assert det and not any(isinstance(c.params.get("x"), dict) and "__type__" in c.params["x"]
                           and c.params["x"]["__type__"] in {"ValueError", "KeyError", "OSError"} for c in det)


def test_cutpoint_literal_work_limit_mid_loop_fails_closed():
    import ast
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value: dt.timedelta):\n"
        "    delta = value\n"
        "    delta = abs(delta)\n"
        "    if delta.seconds + (-1) == 3600:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = next(node for node in ast.walk(ast.parse(src))
              if isinstance(node, ast.FunctionDef) and node.name == "f")
    delta_seconds = ast.Attribute(
        value=ast.Name(id="delta", ctx=ast.Load()), attr="seconds", ctx=ast.Load()
    )
    condition = ast.Compare(left=delta_seconds, ops=[ast.Eq()], comparators=[delta_seconds])

    def chain(depth: int, start: int) -> ast.expr:
        node: ast.expr = ast.Constant(value=start)
        for _ in range(depth):
            node = ast.BinOp(left=node, op=ast.Add(), right=ast.Constant(value=0))
        return node

    path = [
        (
            ast.Compare(
                left=ast.Attribute(value=ast.Name(id="delta", ctx=ast.Load()), attr="seconds", ctx=ast.Load()),
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=value)],
            ),
            True,
        )
        for value in (1, 2, 4, 6, 8)
    ]
    path.append((
        ast.Compare(
            left=ast.Attribute(value=ast.Name(id="delta", ctx=ast.Load()), attr="seconds", ctx=ast.Load()),
            ops=[ast.NotEq()],
            comparators=[chain(25, 10)],
        ),
        True,
    ))

    candidates, reason = D.cutpoint_drive(
        fn,
        5,
        condition,
        True,
        path,
        {"delta": ast.Name(id="delta", ctx=ast.Load())},
        {"value": ("dt.timedelta", ast.Name(id="value", ctx=ast.Load()))},
        100,
        20,
    )

    assert candidates == []
    assert "depth/work" in reason


def test_unary_negative_literal_uses_affine_seconds_projection():
    import ast
    from hlith import drive_inputs as D

    src = (
        "import datetime as dt\n"
        "def f(value: dt.timedelta):\n"
        "    delta = value\n"
        "    delta = abs(delta)\n"
        "    if delta.seconds + (-1) == 3600:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = next(node for node in ast.walk(ast.parse(src))
              if isinstance(node, ast.FunctionDef) and node.name == "f")
    condition = ast.parse("delta.seconds + (-1) == 3600", mode="eval").body
    candidates, reason = D.cutpoint_drive(
        fn,
        5,
        condition,
        True,
        [],
        {"delta": ast.Name(id="delta", ctx=ast.Load())},
        {"value": ("dt.timedelta", ast.Name(id="value", ctx=ast.Load()))},
        100,
        8,
    )

    assert any("seconds boundary 3601" in origin for _params, origin in candidates), (candidates, reason)


def test_seconds_assignment_sources_ignore_nested_helper_scope():
    import ast

    src = (
        "import datetime as dt\n"
        "def f(value: int, decoy: int = 0):\n"
        "    def helper():\n"
        "        delta = dt.timedelta(seconds=decoy)\n"
        "        return delta\n"
        "    delta = dt.timedelta(seconds=value)\n"
        "    seconds = delta.seconds\n"
        "    if seconds + 1 == 3600:\n"
        "        return True\n"
        "    return False\n"
    )
    candidates, reasons = candidates_detailed(
        [("value", "int"), ("decoy", "int")],
        ["seconds + 1 == 3600"],
        want="true",
        fn_ast=ast.parse(src).body[1],
        target_lineno=8,
        timeout_ms=200,
        max_per_condition=16,
    )

    assert candidates, reasons
    assert any("value" in candidate.params for candidate in candidates), candidates
    assert all("decoy" not in candidate.params for candidate in candidates), candidates


MULTI_CUT = {
    "two_loop_built_lists": (
        "def f(a: str, b: str):\n    xs = []\n    for t in a.split(','):\n        xs.append(t.strip())\n    ys = []\n"
        "    for u in b.split(';'):\n        ys.append(u.strip())\n"
        "    if len(xs) == 2 and xs[0] == 'p' and ys[0] == 'q':\n        return 1\n    return 0\n",
        "len(xs) == 2 and xs[0] == 'p' and ys[0] == 'q'"),
    "cut_plus_directly_solved_parameter": (
        "def f(mode: str, s: str):\n    parts = []\n    for x in s.split(','):\n        parts.append(x.strip())\n"
        "    if mode == 'fast' and parts[0] == 'x':\n        return 1\n    return 0\n",
        "mode == 'fast' and parts[0] == 'x'"),
    "url_host": (
        "from urllib.parse import urlparse\n\n\ndef f(target: str):\n    host = urlparse(target).hostname\n"
        "    if host == 'api.example.com':\n        return 1\n    return 0\n", "host == 'api.example.com'"),
    "url_host_suffix": (
        "from urllib.parse import urlsplit\n\n\ndef f(target: str):\n    host = urlsplit(target).hostname or ''\n"
        "    if host.endswith('.example.com') and len(host) > 12:\n        return 1\n    return 0\n",
        "host.endswith('.example.com') and len(host) > 12"),
}


@pytest.mark.parametrize("name", sorted(MULTI_CUT))
def test_cut_variables_are_projected_together_and_urls_get_a_template(name):
    src, cond = MULTI_CUT[name]
    det, why = _drive_all(src, "f", cond, None, "true")
    assert det and all(not c.exact for c in det), (name, why)
    hits = [c for c in det if (_observe(src, "f", cond, c.params) or [None])[0] is True]
    assert hits, (name, [c.params for c in det])
    if name == "two_loop_built_lists":
        assert any(set(c.params) == {"a", "b"} for c in hits), [c.params for c in hits]
    if name == "cut_plus_directly_solved_parameter":
        assert any(set(c.params) == {"mode", "s"} and c.params["mode"] == "fast" for c in hits), [c.params for c in hits]
    if name.startswith("url"):
        assert any("template: url" in c.origin for c in hits), [c.origin for c in hits]


def test_cut_fuzz_two_lists_never_claims_exactness():
    import random

    rng = random.Random(20261115)
    rows = reached = 0
    for _ in range(20):
        s1, s2 = rng.choice([",", ";"]), rng.choice(["|", "/"])
        l1, l2 = rng.choice(["ab", "cd", "ef"]), rng.choice(["gh", "ij"])
        cond = f"len(xs) == 1 and xs[0] == '{l1}' and ys[0].startswith('{l2[0]}')"
        src = (f"def f(a: str, b: str):\\n    xs = []\\n    for t in a.split('{s1}'):\\n        xs.append(t.strip().lower())\\n    ys = []\\n"
               f"    for u in b.split('{s2}'):\\n        ys.append(u.strip())\\n    if {cond}:\\n        return 1\\n    return 0\\n").replace("\\n", "\n")
        for want in ("true", "false"):
            det, _ = _drive_all(src, "f", cond, None, want)
            rows += 1
            for c in det:
                assert not c.exact and c.origin.startswith("cutpoint"), (src, c)
            reached += any((_observe(src, "f", cond, c.params) or [None])[0] is (want == "true") for c in det)
    print("CUT_FUZZ2 reached", reached, "of", rows)
    assert reached >= rows * 0.8, (reached, rows)


def test_two_d_comprehension_false_polarity_is_cheap_under_the_pinned_solver():
    # Z3 5.3.2: the fully pinned length cases are all unsat (rows past the outer count stay constrained) and the
    # unconstrained query used to be cut only after ~1.8 s. Partly pinned cases (outer length first) find it cheaply.
    # Deterministic: the wall deadline is switched off (budget 1e6 ms) so only the rlimit cuts decide, and the assertion
    # is on Z3 work units and on the result, never on a wall budget a loaded machine can miss.
    src, cond = BSDP_CASES["two_d_comprehension"]
    r = _core_run_isolated(src, cond, "false", 800)
    assert r["z3_cands"] and r["rlimit"] <= 1_500_000, r  # measured 1.21M in a pristine process, every time
    det, why = _drive_all(src, "f", cond, None, "false")  # unmetered, retried: only the real-Python verdict matters here
    assert det, why
    for cand in det:
        seen = _observe(src, "f", cond, cand.params)
        assert seen and seen[0] is False, (cand.params, seen)
    z3_version = z3.get_version_string()
    assert z3_version.startswith("5.3"), f"tests must run under the pinned solver, not {z3_version}"
