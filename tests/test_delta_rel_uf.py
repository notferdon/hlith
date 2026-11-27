"""UF relational mode: conditional PROVED on code with calls/attributes; never a counterexample; fails closed."""

from __future__ import annotations

import pytest

from hlith import delta_rel_uf
from hlith.delta_rel import COUNTEREXAMPLE, PROVED, UNMODELED, check_callable
from hlith.delta_rel_uf import check_uf, uf_relational_selftest, uf_soundness_selftest

PRE = '''import os
LIMIT = 3


def helper(v):
    return v


def f(a, b, flag=None):
    """doc"""
    x = a.strip()
    if not x:
        return None
    y = helper(x, b) if flag else x[1:3]
    if y and b in a.items:
        return y + "!"
    return str(y) or "z"
'''
GUARD = "    if b == 0:\n        return 'zero'\n"
DELTA = [{"id": "d", "predicate": {"type": "expr", "expr": "b == 0"},
          "expected": {"kind": "returns", "value_repr": "'zero'"}}]


def test_identical_code_with_calls_is_proved_conditionally():
    v, why = check_uf(PRE, PRE, "f")
    assert v == "PROVED" and "assumed, not verified" in why and "no witness" in why


def test_guarded_delta_up_to_uf_is_proved():
    post = PRE.replace("    x = a.strip()", GUARD + "    x = a.strip()")
    assert check_uf(PRE, post, "f", DELTA)[0] == "PROVED"
    assert check_uf(PRE, post, "f", [])[0] == "UNMODELED"  # the same edit without the declared delta


def test_wrong_delta_value_is_not_proved():
    post = PRE.replace("    x = a.strip()", GUARD.replace("'zero'", "'other'") + "    x = a.strip()")
    assert check_uf(PRE, post, "f", DELTA)[0] == "UNMODELED"


def test_any_change_outside_the_delta_is_not_proved():
    post = PRE.replace("    x = a.strip()", GUARD + "    x = a.lstrip()")  # callee swapped under the guard
    assert check_uf(PRE, post, "f", DELTA)[0] == "UNMODELED"
    assert check_uf(PRE, PRE.replace('"!"', '"?"'), "f")[0] == "UNMODELED"


def test_missing_else_return_is_a_difference_not_a_pass():
    pre = "def f(a):\n    if a:\n        return 1\n    return g(a)\n"
    post = "def f(a):\n    if a:\n        return 1\n    elif h(a):\n        return g(a)\n"
    assert check_uf(pre, post, "f")[0] == "UNMODELED"


SLICE = """import os
LIMIT = 3
OTHER = 1


def helper(v):
    return v


def unrelated(q):
    return q


class K:
    N = 5

    def sib(self, a):
        return a

    def m(self, a):
        return self.sib(a) + LIMIT


def f(a):
    return helper(a) + LIMIT
"""


def test_slice_ignores_what_the_target_does_not_read_and_sees_what_it_reads():
    assert check_uf(SLICE, SLICE, "f")[0] == "PROVED"
    # unrelated edits anywhere else: ignored
    for edit in (("OTHER = 1", "OTHER = 2"), ("return q\n", "return q + 1\n"), ("import os", "import os, sys"),
                 ("N = 5", "N = 6")):
        assert check_uf(SLICE, SLICE.replace(*edit), "f")[0] == "PROVED", edit
    # a changed constant / callee / import the target reads: not proved
    assert check_uf(SLICE, SLICE.replace("LIMIT = 3", "LIMIT = 4"), "f")[0] == "UNMODELED"
    assert check_uf(SLICE, SLICE.replace("return v\n", "return v + 1\n"), "f")[0] == "UNMODELED"  # changed callee, not equal
    uses_os = SLICE.replace("return helper(a) + LIMIT", "return os.getcwd() + LIMIT")
    assert check_uf(uses_os, uses_os.replace("import os", "import posixpath as os"), "f")[0] == "UNMODELED"


def test_a_changed_callee_is_accepted_only_if_it_is_itself_proved_equal():
    # a neutral refactor of the callee (rename a local) is jointly proved; a behavioural change is not
    pre = "def helper(v):\n    t = g(v)\n    return t\n\n\ndef f(a):\n    return helper(a)\n"
    neutral = pre.replace("t = g(v)\n    return t", "u = g(v)\n    return u")
    assert check_uf(pre, neutral, "f")[0] == "PROVED"
    assert check_uf(pre, pre.replace("g(v)", "h(v)"), "f")[0] == "UNMODELED"
    # mutual recursion cannot be proved by induction
    cyc = "def a(x):\n    return b(x)\n\n\ndef b(x):\n    return a(x)\n"
    both = cyc.replace("return b(x)", "y = b(x)\n    return y").replace("return a(x)", "z = a(x)\n    return z")
    assert check_uf(cyc, both, "a")[0] == "PROVED"  # mutual recursion: each body proved assuming the other equal
    broken = cyc.replace("return b(x)", "y = b(x)\n    return y").replace("return a(x)", "return a2(x)")
    assert check_uf(cyc, broken, "a")[0] == "UNMODELED"  # one member of the cycle really changed: not proved
    assert check_uf(cyc, cyc.replace("return b(x)", "y = b(x)\n    return y"), "a")[0] == "PROVED"  # b is unchanged


def test_changed_sibling_method_called_via_self_is_joint_proved_or_unmodeled():
    assert check_uf(SLICE, SLICE, "K.m")[0] == "PROVED"
    assert check_uf(SLICE, SLICE.replace("def sib(self, a):\n        return a", "def sib(self, a):\n        return a + 1"), "K.m")[0] == "UNMODELED"
    neutral = SLICE.replace("def sib(self, a):\n        return a", "def sib(self, a):\n        r = a\n        return r")
    assert check_uf(SLICE, neutral, "K.m")[0] == "PROVED"
    assert check_uf(SLICE, SLICE.replace("N = 5", "N = 6"), "K.m")[0] == "PROVED"  # nothing in the class reads N
    reads_n = SLICE.replace("return self.sib(a) + LIMIT", "return self.sib(a) + self.N")
    assert check_uf(reads_n, reads_n, "K.m")[0] == "PROVED"
    assert check_uf(reads_n, reads_n.replace("N = 5", "N = 6"), "K.m")[0] == "UNMODELED"  # a class attribute read via self
    assert check_uf(reads_n, reads_n.replace("class K:", "class K(Base):"), "K.m")[0] == "UNMODELED"  # bases changed


@pytest.mark.parametrize("src", [
    "X = 1\n\n\ndef f(a):\n    return a + X\n\n\nX = 2\n",  # rebound at module scope
    "X = 1\n\n\ndef f(a):\n    return a + X\n\n\ndef g():\n    global X\n    X = 2\n",
    "from m import *\n\n\ndef f(a):\n    return h(a)\n",
    "def f(a):\n    return globals()['x'](a)\n", "def f(a):\n    return getattr(a, a.name)\n",
    "def f(a):\n    return eval(a)\n", "class M(type):\n    pass\n\n\nclass K(metaclass=M):\n    pass\n\n\ndef f(a):\n    return K(a)\n",
    "class K:\n    def __getattr__(self, n):\n        return n\n\n\ndef f(a):\n    return K().x\n",
])
def test_dynamic_or_rebound_names_in_the_slice_fail_closed(src):
    assert check_uf(src, src, "f")[0] == "UNMODELED", src


def test_import_time_statements_and_monkeypatching_must_be_unchanged():
    src = "import m\nm.attr = 1\n\n\ndef f(a):\n    return a\n"
    assert check_uf(src, src, "f")[0] == "PROVED"
    assert check_uf(src, src.replace("m.attr = 1", "m.attr = 2"), "f")[0] == "UNMODELED"
    assert check_uf(src, src + "register(f)\n", "f")[0] == "UNMODELED"


@pytest.mark.parametrize("body", [
    "a.append(1)\n    return a", "a.x = 1\n    return a", "a[0] = 1\n    return a", "del a\n    return 1",
    "print(a)\n    return a", "open(a)\n    return a", "helper(a)\n    return a",  # expression statement: effects only
    "try:\n        return a\n    finally:\n        return 1",
    "return a is b", "return [q for q in a]", "return f'{a}'", "return (yield a)", "return random.random()",
    "global G\n    G = 1\n    return a", "return lambda: a", "return a.update(1)", "return os.getcwd()",
])
def test_mutation_io_and_unmodeled_constructs_fail_closed(body):
    post = f"import os\nimport random\n\n\ndef helper(v):\n    return v\n\n\ndef f(a):\n    {body}\n"
    pre = post.replace(body, "return a", 1)
    assert check_uf(pre, post, "f")[0] == "UNMODELED", body


def test_uf_mode_never_yields_a_counterexample_or_witness():
    r = check_callable(PRE, PRE.replace('"!"', '"?"'), "f")
    assert r.verdict == UNMODELED and not r.witness_inputs and r.verdict != COUNTEREXAMPLE


def test_numeric_mode_still_wins_and_uf_is_only_the_fallback():
    pre = "def f(x: int) -> int:\n    return x + 1\n"
    assert check_callable(pre, pre.replace("+ 1", "+ 2"), "f").verdict == COUNTEREXAMPLE
    assert check_callable(PRE, PRE, "f").verdict == PROVED
    assert "[UF, conditional]" in check_callable(PRE, PRE, "f").reason


# ---- soundness: the encoding must equal REAL Python execution over random interpretations of the opaque terms
SELF = [PRE, "def g(a, b):\n    c = a.m(b)\n    d = c or b\n    if d and not a:\n        return d[0:1]\n"
             "    x = [a, b] if c else {a: b}\n    return x\n",
        "def g(a, b, c):\n    y = a\n    if b:\n        y = b + 1\n    elif c:\n        y = c(a)\n    return y\n",
        "def g(a):\n    if a < 1 < 2:\n        raise ValueError(a.x)\n    return -a if a else ~a\n"]


@pytest.mark.parametrize("i", range(len(SELF)))
def test_uf_encoding_equals_real_execution(i):
    src = SELF[i]
    name = "f" if i == 0 else "g"
    assert uf_soundness_selftest(src, name, n=150, seed=5) == []


@pytest.mark.real
@pytest.mark.parametrize("i", range(len(SELF)))
def test_uf_encoding_equals_real_execution_2000(i):
    assert uf_soundness_selftest(SELF[i], "f" if i == 0 else "g", n=2000, seed=17) == []


def test_oracle_catches_a_silent_abstraction_error(monkeypatch):
    real = delta_rel_uf._truth
    monkeypatch.setattr(delta_rel_uf, "_truth", lambda e: delta_rel_uf.z3.Not(real(e)))  # inverted truthiness
    assert uf_soundness_selftest(SELF[2], "g", n=60, seed=5) != []


# ---- identity against None
NONE_SRC = [
    "def g(a, b):\n    if a is None:\n        return b\n    if b is not None and a:\n        return a.x\n    return None\n",
    "def g(a):\n    x = a if a is not None else 3\n    if x is None:\n        return 0\n    return x.m(True)\n",
    "def g(a, b):\n    if None is a or b is None:\n        return False\n    return a < b is not None\n",
]


def test_is_none_is_modelled_exactly_and_proved_when_unchanged():
    for src in NONE_SRC:
        assert check_uf(src, src, "g")[0] == "PROVED", src


def test_is_none_changes_are_seen():
    pre = NONE_SRC[0]
    assert check_uf(pre, pre.replace("a is None", "a is not None"), "g")[0] == "UNMODELED"
    # a guarded delta on None: an added early return for None is the declared delta
    post = "def g(a, b):\n    if b is None:\n        return 'nb'\n" + pre.split("\n", 1)[1]
    d = [{"id": "d", "predicate": {"type": "expr", "expr": "b is None"},
          "expected": {"kind": "returns", "value_repr": "'nb'"}}]
    assert check_uf(pre, post, "g", d)[0] == "PROVED"
    assert check_uf(pre, post, "g", [])[0] == "UNMODELED"


def test_none_axioms_bool_none_is_false_constants_are_not_none():
    # pre returns 1 when a is falsy; post tests `a is None` first: the two differ for a falsy non-None a
    pre = "def g(a):\n    if not a:\n        return 1\n    return 2\n"
    post = "def g(a):\n    if a is None:\n        return 1\n    return 2\n"
    assert check_uf(pre, post, "g")[0] == "UNMODELED"
    # but None is falsy, so a None test followed by the falsy test is the same function as the falsy test alone
    post2 = "def g(a):\n    if a is None:\n        return 1\n    if not a:\n        return 1\n    return 2\n"
    assert check_uf(pre, post2, "g")[0] == "PROVED"
    # a constant is not None: this branch is dead under the axioms, so removing it is the same function
    pre3 = "def g(a):\n    if 5 is None:\n        return 9\n    return a\n"
    assert check_uf(pre3, "def g(a):\n    return a\n", "g")[0] == "PROVED"


@pytest.mark.parametrize("i", range(len(NONE_SRC)))
def test_is_none_encoding_equals_real_execution(i):
    assert uf_soundness_selftest(NONE_SRC[i], "g", n=300, seed=9) == []


# ---- try/except as raise paths: every operation inside a try body may raise, handlers are real paths
TRY_SRC = [
    "def g(a, b):\n    try:\n        x = a.parse(b)\n        y = x if x else b\n    except ValueError as e:\n"
    "        return str(e)\n    except (KeyError, TypeError):\n        return None\n    else:\n        z = y + 1\n"
    "    if z:\n        return z\n    try:\n        return a.read()\n    except Exception:\n        raise\n",
    "def g(a):\n    r = 0\n    try:\n        try:\n            r = a.f()\n        except KeyError:\n"
    "            r = a.g()\n    except Exception as e:\n        return e\n    return r\n",
    "def g(a, b):\n    try:\n        if a.ok(b):\n            raise ValueError(b)\n        return a.v\n"
    "    except ValueError:\n        return None\n",
]


@pytest.mark.parametrize("i", range(len(TRY_SRC)))
def test_try_except_unchanged_is_proved_and_matches_real_execution(i):
    assert check_uf(TRY_SRC[i], TRY_SRC[i], "g")[0] == "PROVED"
    assert uf_soundness_selftest(TRY_SRC[i], "g", n=250, seed=21) == []


@pytest.mark.real
@pytest.mark.parametrize("i", range(len(TRY_SRC)))
def test_try_except_encoding_equals_real_execution_2000(i):
    assert uf_soundness_selftest(TRY_SRC[i], "g", n=2000, seed=33) == []


def test_a_change_confined_to_a_handler_is_seen_not_hidden_by_totality():
    # under a total-callee assumption the handler would be dead and this edit invisible; raise paths make it live
    pre = TRY_SRC[2]
    post = pre.replace("    except ValueError:\n        return None\n", "    except ValueError:\n        return 0\n")
    assert post != pre and check_uf(pre, post, "g")[0] == "UNMODELED"
    swapped = pre.replace("except ValueError", "except KeyError")
    assert check_uf(pre, swapped, "g")[0] == "UNMODELED"
    assert check_uf(pre, pre.replace("a.v", "a.w"), "g")[0] == "UNMODELED"


def test_try_unmodeled_shapes_fail_closed():
    base = "def g(a):\n    {}\n"
    for body in (
        "try:\n        return a.x\n    finally:\n        pass",  # finally
        "try:\n        return a.x\n    except:\n        pass",  # falls off the end after a swallowed error is fine, see below
        "raise",  # bare raise outside a handler
        "try:\n        return a.x if a else a.y.z\n    except Exception:\n        return 1",  # conditional raising op
        "try:\n        return a.p and a.q and a.r\n    except Exception:\n        return 1",  # 3-operand and/or
        "try:\n        return a < a.b < a.c\n    except Exception:\n        return 1",  # chained comparison
        "try:\n        return a.x\n    except Exception as e:\n        raise ValueError(e) from e",  # chained raise
    ):
        src = base.format(body)
        verdict = check_uf(src, src, "g")[0]
        if body.startswith("try:\n        return a.x\n    except:"):
            assert verdict == "PROVED"  # swallowed error: the fall-off returns None, an explicit path
        else:
            assert verdict == "UNMODELED", body


def test_oracle_catches_missing_exception_paths(monkeypatch):
    # an encoder that ignored the raising operations (the 'total callee' shortcut) disagrees with real execution
    monkeypatch.setattr(delta_rel_uf, "_split", lambda ops, cur, env_before, rp: cur)
    assert uf_soundness_selftest(TRY_SRC[0], "g", n=250, seed=21) != []


def test_oracle_catches_wrong_handler_matching(monkeypatch):
    real = delta_rel_uf._MATCHP
    monkeypatch.setattr(delta_rel_uf, "_MATCHP", lambda exc, ty: delta_rel_uf.z3.Not(real(exc, ty)))
    assert uf_soundness_selftest(TRY_SRC[0], "g", n=250, seed=21) != []


# ---- methods, positional-only / keyword-only parameters, bare annotations, local imports
METH = '''class C:
    LIMIT = 3

    def other(self, v):
        return v

    @classmethod
    def build(cls, a, /, b, *, strict, mode=None):
        import json
        from .util import helper as h
        y: int
        try:
            z = json.loads(a)
            w = h(b, strict)
        except ValueError:
            z = cls.default
            w = None
        if mode is None:
            return z
        return z.get(mode) or w
'''


def test_method_identical_is_proved_and_matches_real_execution():
    assert check_uf(METH, METH, "C.build")[0] == "PROVED"
    assert uf_soundness_selftest(METH, "C.build", n=200, seed=8) == []


@pytest.mark.real
def test_method_encoding_equals_real_execution_2000():
    assert uf_soundness_selftest(METH, "C.build", n=2000, seed=19) == []


def test_method_change_is_seen_and_siblings_are_not_shared_assumptions():
    assert check_uf(METH, METH.replace("z.get(mode)", "z.pop2(mode)"), "C.build")[0] == "UNMODELED"
    # a sibling method changed: self.other(...) callees are no longer the same function
    assert check_uf(METH, METH.replace("return v\n", "return v + 1\n"), "C.build")[0] == "UNMODELED"
    assert check_uf(METH, METH.replace("LIMIT = 3", "LIMIT = 4"), "C.build")[0] == "PROVED"  # not read by build
    reads = METH.replace("z = cls.default", "z = cls.LIMIT")
    assert check_uf(reads, reads.replace("LIMIT = 3", "LIMIT = 4"), "C.build")[0] == "UNMODELED"  # read via cls
    # the guarded delta shape works on a method
    post = METH.replace("        y: int\n", "        y: int\n        if mode == 'x':\n            return 'X'\n")
    d = [{"id": "d", "predicate": {"type": "expr", "expr": "mode == 'x'"},
          "expected": {"kind": "returns", "value_repr": "'X'"}}]
    assert check_uf(METH, post, "C.build", d)[0] == "PROVED" and check_uf(METH, post, "C.build", [])[0] == "UNMODELED"


@pytest.mark.parametrize("body", ["self.x = 1\n        return self", "self.x += 1\n        return self",
                                  "self.items[0] = 1\n        return self"])
def test_method_that_mutates_self_is_proved_only_for_an_identical_effect_sequence(body):
    src = f"class C:\n    def m(self):\n        {body}\n"
    assert check_uf(src, src, "C.m")[0] == "PROVED"
    dropped = src.replace(body, "return self")
    assert check_uf(src, dropped, "C.m")[0] == "UNMODELED"  # a dropped store is a changed effect sequence
    assert check_uf(src, src.replace("1", "2"), "C.m")[0] == "UNMODELED"  # a changed stored value


def test_method_decorators_and_changed_signature():
    src = "class C:\n    @cache\n    def m(self, a):\n        return a\n"
    assert check_uf(src, src, "C.m")[0] == "UNMODELED"  # decorator outside staticmethod/classmethod/property
    ok = "@dataclass\nclass C:\n    @property\n    def m(self):\n        return self.a\n"
    assert check_uf(ok, ok, "C.m")[0] == "PROVED"  # class decorator is compared, identical on both sides
    assert check_uf(ok, ok.replace("@dataclass", "@dataclass(frozen=True)"), "C.m")[0] == "UNMODELED"
    kw = "def f(a, *, k=1):\n    return g(a, k)\n"
    assert check_uf(kw, kw.replace("k=1", "k=2"), "f")[0] == "UNMODELED"  # keyword-only default changed
    assert check_uf(kw, kw.replace("*, k", "k"), "f")[0] == "UNMODELED"  # kind changed


def test_local_import_changes_are_seen():
    src = "def f(a):\n    import json\n    return json.loads(a)\n"
    assert check_uf(src, src, "f")[0] == "PROVED"
    assert check_uf(src, src.replace("import json", "import simplejson as json"), "f")[0] == "UNMODELED"
    assert check_uf(src, src.replace("import json", "from x import json"), "f")[0] == "UNMODELED"
    assert check_uf(src, "def f(a):\n    from os import getcwd\n    return getcwd()\n", "f")[0] == "UNMODELED"


# ---- for-loops: a deterministic black box keyed on the loop's exact source and entry state (relational only)
LOOP = '''def f(items, k):
    total = 0
    for it in items:
        if it.bad:
            continue
        if it.stop:
            return None
        total = total + it.n
    out = helper(total, k)
    return out
'''


def test_identical_loop_is_proved_and_a_neutral_edit_around_it_is_proved():
    assert check_uf(LOOP, LOOP, "f")[0] == "PROVED"
    neutral = LOOP.replace("out = helper(total, k)\n    return out", "result = helper(total, k)\n    return result")
    assert check_uf(LOOP, neutral, "f")[0] == "PROVED"
    assert uf_relational_selftest(LOOP, neutral, "f", n=300, seed=2) == []  # real execution agrees


def test_any_edit_inside_or_before_the_loop_is_not_proved():
    assert check_uf(LOOP, LOOP.replace("it.n", "it.m"), "f")[0] == "UNMODELED"
    assert check_uf(LOOP, LOOP.replace("total = 0", "total = 1"), "f")[0] == "UNMODELED"  # different entry state
    assert check_uf(LOOP, LOOP.replace("continue", "return None"), "f")[0] == "UNMODELED"
    assert check_uf(LOOP, LOOP.replace("for it in items:", "for it in k:"), "f")[0] == "UNMODELED"
    # the relational oracle SEES such a difference in real execution (it is what a wrong PROVED would hide)
    assert uf_relational_selftest(LOOP, LOOP.replace("it.n", "it.m"), "f", n=200, seed=2) != []


def test_guarded_delta_before_a_loop_is_proved():
    post = LOOP.replace("    total = 0\n", "    if k == 0:\n        return 'zero'\n    total = 0\n")
    d = [{"id": "d", "predicate": {"type": "expr", "expr": "k == 0"},
          "expected": {"kind": "returns", "value_repr": "'zero'"}}]
    assert check_uf(LOOP, post, "f", d)[0] == "PROVED" and check_uf(LOOP, post, "f", [])[0] == "UNMODELED"


@pytest.mark.parametrize("body", [
    "for q in a:\n        try:\n            pass\n        except Exception:\n            pass\n    return a",
    "for q in a:\n        with q:\n            pass\n    return a",
    "for q in a:\n        pass\n    else:\n        return 1\n    return 2",  # falls under the same rule: fine, see below
    "for q in a:\n        raise\n    return a",  # bare raise
    "try:\n        for q in a:\n            pass\n    except Exception:\n        return 1\n    return a",  # loop in try
    "for q.x in a:\n        pass\n    return a",  # attribute target
])
def test_loop_shapes_that_mutate_or_cannot_be_validated_fail_closed(body):
    src = f"def f(a):\n    {body}\n"
    verdict = check_uf(src, src, "f")[0]
    if "else:\n        return 1" in body:
        assert verdict == "PROVED"  # for/else with returns is a loop black box like any other
    else:
        assert verdict == "UNMODELED", body


def test_loop_variable_does_not_leak_when_first_bound_in_the_loop():
    src = "def f(a):\n    for q in a:\n        pass\n    return q\n"  # an empty iterable leaves q unbound
    assert check_uf(src, src, "f")[0] == "UNMODELED"


# ---- with-statements: opaque enter, pure non-suppressing exit, outside try, no raise inside
WITH = ("def f(self, a):\n    with self.lock:\n        x = a.get()\n    with a.cm() as c, self.other:\n"
        "        y = c.read(x)\n    return y\n")


def test_with_identical_proved_and_matches_real_execution():
    assert check_uf(WITH, WITH, "f")[0] == "PROVED"
    assert uf_soundness_selftest(WITH, "f", n=300, seed=6) == []
    assert check_uf(WITH, WITH.replace("self.lock", "self.lock2"), "f")[0] == "UNMODELED"
    assert check_uf(WITH, WITH.replace("a.cm() as c", "a.cm() as d").replace("c.read", "d.read"), "f")[0] == "PROVED"


@pytest.mark.parametrize("body", [
    "with a:\n        raise ValueError(1)\n    return a",  # __exit__ may suppress it
    "try:\n        with a:\n            pass\n    except Exception:\n        pass\n    return a",
    "with a as (p, q):\n        pass\n    return a",
])
def test_with_shapes_that_cannot_be_modelled_fail_closed(body):
    src = f"def f(a):\n    {body}\n"
    assert check_uf(src, src, "f")[0] == "UNMODELED", body


def test_dead_store_of_a_call_is_unmodeled_because_it_may_exist_for_its_effect():
    pre = "def f(a):\n    _ = audit(a)\n    return a\n"
    post = "def f(a):\n    return a\n"
    assert check_uf(pre, post, "f")[0] == "UNMODELED"  # dropping the audit call must not be PROVED
    assert check_uf(pre, pre, "f")[0] == "UNMODELED"  # even identical: a pure model cannot tell it matters
    assert check_uf("def f(a):\n    import audit\n    return a\n", "def f(a):\n    return a\n", "f")[0] == "UNMODELED"
    used = "def f(a):\n    r = audit(a)\n    return r\n"
    assert check_uf(used, used, "f")[0] == "PROVED"


# ---- effects: stores, deletes, discarded calls and impure/mutating calls are an ordered trace; reads see the state
EFF = [
    "def g(self, a, k):\n    self.x = a.v\n    self.items[k] = a\n    self.n += 1\n    del self.tmp\n    a.close()\n"
    "    r = self.read(k)\n    return r\n",
    "def g(a):\n    import os\n    p = os.getcwd()\n    audit(p)\n    a.names.append(p)\n    return os.path.join(p, a.n)\n",
    "def g(a, b):\n    try:\n        a.x = b.y\n        b.items[a.k] = 1\n        c = a.go()\n    except KeyError:\n"
    "        a.fail = 1\n        return None\n    return c\n",
]


@pytest.mark.parametrize("i", range(len(EFF)))
def test_effects_identical_proved_and_encoding_equals_real_execution(i):
    assert check_uf(EFF[i], EFF[i], "g")[0] == "PROVED"
    assert uf_soundness_selftest(EFF[i], "g", n=300, seed=14) == []


@pytest.mark.real
@pytest.mark.parametrize("i", range(len(EFF)))
def test_effects_encoding_equals_real_execution_2000(i):
    assert uf_soundness_selftest(EFF[i], "g", n=2000, seed=51) == []


def test_changed_order_value_target_or_presence_of_an_effect_is_not_proved():
    pre = "def g(a, b):\n    a.x = 1\n    b.y = 2\n    return a\n"
    assert check_uf(pre, "def g(a, b):\n    b.y = 2\n    a.x = 1\n    return a\n", "g")[0] == "UNMODELED"  # order
    assert check_uf(pre, pre.replace("a.x = 1", "a.z = 1"), "g")[0] == "UNMODELED"  # target attribute
    assert check_uf(pre, pre.replace("b.y = 2", "b.y = 3"), "g")[0] == "UNMODELED"  # value
    assert check_uf(pre, pre.replace("    b.y = 2\n", ""), "g")[0] == "UNMODELED"  # dropped
    assert check_uf(pre, pre.replace("    return a", "    a.w = 0\n    return a"), "g")[0] == "UNMODELED"  # added


def test_a_read_moved_across_an_effect_is_not_proved():
    pre = "def g(a):\n    x = a.v\n    a.v = 5\n    return x\n"
    moved = "def g(a):\n    a.v = 5\n    x = a.v\n    return x\n"
    assert check_uf(pre, moved, "g")[0] == "UNMODELED"  # reads are indexed by the effect trace
    # real execution distinguishes them too: the oracle would see a difference if this were (wrongly) PROVED
    assert uf_relational_selftest(pre, moved, "g", n=200, seed=1) != []
    assert check_uf(pre, pre, "g")[0] == "PROVED"


def test_a_pure_read_before_or_after_an_unrelated_pure_statement_may_move():
    pre = "def g(a):\n    x = a.v\n    y = a.w\n    return x + y\n"
    swapped = "def g(a):\n    y = a.w\n    x = a.v\n    return x + y\n"
    assert check_uf(pre, swapped, "g")[0] == "PROVED"  # no effect between them: both reads see the same state
    assert uf_relational_selftest(pre, swapped, "g", n=200, seed=1) == []


def test_oracle_catches_a_trace_blind_encoding(monkeypatch):
    monkeypatch.setattr(delta_rel_uf, "_effect", lambda term: None)  # forget effects: stores vanish from the trace
    assert uf_soundness_selftest(EFF[0], "g", n=150, seed=14) != []


# ---- tuple-unpack, yield statements, lambdas, nested defs, comprehensions, f-strings, star calls, while
CONSTRUCTS = """def g(self, a, b):
    k, v = a.pair(b)
    f = lambda q: q + k
    items = [x.n for x in a.items if x.ok]
    s = f"{k}/{v!r:>4}-{b}"
    r = self.run(*items, key=b, **a.opts)

    def helper(z):
        return z + v

    yield r
    yield helper(s)
    return f(items) or s
"""


def test_new_constructs_identical_proved_and_encoding_equals_real_execution():
    assert check_uf(CONSTRUCTS, CONSTRUCTS, "g")[0] == "PROVED"
    assert uf_soundness_selftest(CONSTRUCTS, "g", n=300, seed=3) == []


@pytest.mark.real
def test_new_constructs_encoding_equals_real_execution_2000():
    assert uf_soundness_selftest(CONSTRUCTS, "g", n=2000, seed=41) == []


@pytest.mark.parametrize("old,new", [
    ("lambda q: q + k", "lambda q: q - k"),  # lambda body
    ("[x.n for x in a.items if x.ok]", "[x.n for x in a.items if not x.ok]"),  # comprehension condition
    ("[x.n for x in a.items if x.ok]", "[x.m for x in a.items if x.ok]"),
    ('{v!r:>4}', '{v!r:<4}'), ("{k}/", "{k}-"),  # f-string spec / literal part
    ("self.run(*items, key=b, **a.opts)", "self.run(items, key=b, **a.opts)"),  # star layout
    ("self.run(*items, key=b, **a.opts)", "self.run(*items, key=b)"),
    ("    yield r\n    yield helper(s)", "    yield helper(s)\n    yield r"),  # yield order
    ("yield r", "yield s"),  # yielded value
    ("k, v = a.pair(b)", "v, k = a.pair(b)"),  # unpack order
    ("return z + v", "return z - v"),  # nested def body
])
def test_changes_inside_the_new_constructs_are_not_proved(old, new):
    assert old in CONSTRUCTS
    assert check_uf(CONSTRUCTS, CONSTRUCTS.replace(old, new), "g")[0] == "UNMODELED", (old, new)


def test_closure_over_a_reassigned_local_is_unmodeled_late_binding():
    src = "def g(a):\n    k = a.x\n    f = lambda q: q + k\n    k = a.y\n    return f(1)\n"
    assert check_uf(src, src, "g")[0] == "UNMODELED"
    ok = "def g(a):\n    k = a.x\n    f = lambda q: q + k\n    return f(1)\n"
    assert check_uf(ok, ok, "g")[0] == "PROVED"
    p = "def g(a, k):\n    f = lambda q: q + k\n    k = 2\n    return f(1)\n"
    assert check_uf(p, p, "g")[0] == "UNMODELED"  # a parameter reassigned after capture


def test_yield_as_an_expression_and_effects_inside_comprehensions_are_unmodeled():
    assert check_uf("def g(a):\n    x = yield a\n    return x\n", "def g(a):\n    x = yield a\n    return x\n", "g")[0] == "UNMODELED"
    eff = "def g(a):\n    return [a.append(x) for x in a]\n"
    assert check_uf(eff, eff, "g")[0] == "UNMODELED"
    assert check_uf("def g(a):\n    a, b = a\n    return a\n", "def g(a):\n    a, b = a\n    return a\n", "g")[0] == "PROVED"
    star = "def g(a):\n    (x, y), z = a\n    return x\n"
    assert check_uf(star, star, "g")[0] == "UNMODELED"  # nested unpacking
    assert check_uf("def g(a):\n    x = a\n    return 1\n", "def g(a):\n    x = a\n    return 1\n", "g")[0] == "UNMODELED"  # dead store


WHILE = "def g(a):\n    n = a.start\n    while n.more():\n        n = n.next()\n    return n\n"


def test_while_is_a_black_box_and_the_relational_oracle_runs_the_same_bounded_loop():
    assert check_uf(WHILE, WHILE, "g")[0] == "PROVED"
    neutral = WHILE.replace("return n", "r = n\n    return r")
    assert check_uf(WHILE, neutral, "g")[0] == "PROVED"
    assert uf_relational_selftest(WHILE, neutral, "g", n=200, seed=4) == []
    assert check_uf(WHILE, WHILE.replace("n.next()", "n.prev()"), "g")[0] == "UNMODELED"
    assert check_uf(WHILE, WHILE.replace("n.more()", "n.less()"), "g")[0] == "UNMODELED"
    assert uf_relational_selftest(WHILE, WHILE.replace("n.next()", "n.prev()"), "g", n=200, seed=4) != []


# ---- exact identities gated by the TARGET interpreter (each one executed against real Python)
@pytest.mark.parametrize("fact", [f for f in delta_rel_uf.EXACT_FACTS])
def test_each_exact_fact_is_true_in_the_running_interpreter(fact):
    import builtins
    import os
    import select
    import socket
    import sys

    fid, minimum, mod, src, dst = fact
    if tuple(sys.version_info[:2]) < minimum:
        pytest.skip("fact not claimed for this interpreter")
    left = getattr(builtins, src) if mod is None else getattr({"socket": socket, "select": select, "os": os}[mod], src)
    assert left is getattr(builtins, dst), fid  # the same OBJECT, not merely equal behaviour


ALIAS_PRE = "import socket\n\n\ndef f(a):\n    try:\n        return a.connect()\n    except socket.error:\n        return None\n"
ALIAS_POST = ALIAS_PRE.replace("socket.error", "OSError")


def test_alias_facts_prove_only_with_a_target_version_that_claims_them():
    v = (3, 12, 0)
    r = check_uf(ALIAS_PRE, ALIAS_POST, "f", python_version=v)
    assert r[0] == "PROVED" and "Assuming socket.error is OSError (py>=3.3)" in r[1]
    assert check_uf(ALIAS_PRE, ALIAS_POST, "f")[0] == "UNMODELED"  # no target version: no facts
    assert check_uf(ALIAS_PRE, ALIAS_POST, "f", python_version=(2, 7, 18))[0] == "UNMODELED"  # not an alias there
    assert check_uf("def f(a):\n    try:\n        return a.go()\n    except IOError:\n        return 1\n",
                    "def f(a):\n    try:\n        return a.go()\n    except OSError:\n        return 1\n", "f",
                    python_version=(3, 8, 0))[0] == "PROVED"
    assert "socket.timeout is TimeoutError" not in check_uf(ALIAS_PRE, ALIAS_POST, "f", python_version=(3, 9, 0))[1]


def test_alias_facts_do_not_fire_on_shadowed_or_unimported_names_or_other_exceptions():
    v = (3, 12, 0)
    shadow = "class IOError(Exception):\n    pass\n\n\ndef f(a):\n    try:\n        return a.go()\n    except IOError:\n        return 1\n"
    assert check_uf(shadow, shadow.replace("except IOError", "except OSError"), "f", python_version=v)[0] == "UNMODELED"
    local = "def f(socket):\n    try:\n        return socket.go()\n    except socket.error:\n        return 2\n"
    assert check_uf(local, local.replace("socket.error", "OSError"), "f", python_version=v)[0] == "UNMODELED"  # not the module
    aliased = "import socket as s\n\n\ndef f(a):\n    try:\n        return a.go()\n    except s.error:\n        return 1\n"
    assert check_uf(aliased, aliased.replace("s.error", "OSError"), "f", python_version=v)[0] == "UNMODELED"
    # a DIFFERENT exception is never rewritten: socket.gaierror is a subclass, not an alias
    sub = ALIAS_PRE.replace("socket.error", "socket.gaierror")
    assert check_uf(sub, ALIAS_POST, "f", python_version=v)[0] == "UNMODELED"
    assert check_uf(ALIAS_PRE, ALIAS_PRE.replace("return None", "return 0"), "f", python_version=v)[0] == "UNMODELED"


# ---- finding from the false-proof hunt: annotations are evaluated when the function is DEFINED
def test_a_changed_annotation_is_not_proved_it_can_raise_at_definition_time():
    pre = "def f(a: int | None) -> int | None:\n    return a\n"
    for post in (pre.replace("int | None) ->", "int & None) ->"), pre.replace("-> int | None", "-> int & None"),
                 pre.replace("a: int | None", "a: typing.Optional_x")):
        assert check_uf(pre, post, "f")[0] == "UNMODELED", post  # `int & None` raises TypeError when f is defined
    assert check_uf(pre, pre, "f")[0] == "PROVED"


def test_for_loop_with_a_tuple_target_runs_in_the_relational_oracle():
    src = "def g(a):\n    t = 0\n    for k, v in a.items():\n        t = t + v.n\n    return t\n"
    assert check_uf(src, src, "g")[0] == "PROVED"
    assert uf_relational_selftest(src, src.replace("return t", "r = t\n    return r"), "g", n=100, seed=2) == []


# ---- widened falsifiers (design review): decorators, default expressions, class/import-time code, builtins, nonlocal, aug-assign
def _unm(pre, post, func="f", **kw):
    return check_uf(pre, post, func, **kw)[0]


def test_decorators_added_removed_or_changed_are_not_proved():
    pre = "def f(a):\n    return g(a)\n"
    for dec in ("@cache", "@staticmethod", "@property", "@functools.lru_cache(maxsize=1)"):
        assert _unm(pre, dec + "\n" + pre) == "UNMODELED", dec
    assert _unm("@cache\n" + pre, pre) == "UNMODELED"
    assert _unm("@cache\n" + pre, "@cache2\n" + pre) == "UNMODELED"
    meth = "class K:\n    @property\n    def m(self):\n        return self.x\n"
    assert _unm(meth, meth.replace("@property\n    ", ""), "K.m") == "UNMODELED"
    assert _unm(meth, meth.replace("@property", "@staticmethod"), "K.m") == "UNMODELED"
    assert _unm(meth, meth, "K.m") == "PROVED"


def test_default_argument_expressions_are_compared_and_their_names_are_read():
    pre = "LIM = 3\n\n\ndef f(a, b=LIM):\n    return g(a, b)\n"
    assert _unm(pre, pre) == "PROVED"
    assert _unm(pre, pre.replace("b=LIM", "b=4")) == "UNMODELED"  # the default expression changed
    assert _unm(pre, pre.replace("LIM = 3", "LIM = 4")) == "UNMODELED"  # a constant the DEFAULT reads changed
    mut = "def f(a, acc=[]):\n    return g(a, acc)\n"
    assert _unm(mut, mut.replace("acc=[]", "acc=None")) == "UNMODELED"  # mutable default vs None
    assert _unm(mut, mut.replace("acc=[]", "acc=make()")) == "UNMODELED"  # a call evaluated at definition time
    assert _unm(mut, mut) == "PROVED"


def test_docstring_is_observable_so_a_docstring_edit_is_not_proved():
    pre = 'def f(a):\n    """Do x."""\n    return g(a)\n'
    assert _unm(pre, pre.replace("Do x.", "Do y.")) == "UNMODELED"  # f.__doc__ differs
    assert _unm(pre, pre.replace('    """Do x."""\n', "")) == "UNMODELED"
    assert _unm(pre, pre) == "PROVED"


def test_class_level_and_import_time_code_the_function_depends_on():
    k = "class K:\n    __slots__ = ('a',)\n\n    def m(self, v):\n        self.a = v\n        return self.a\n"
    assert _unm(k, k, "K.m") == "PROVED"
    assert _unm(k, k.replace("('a',)", "('a', 'b')"), "K.m") == "UNMODELED"  # __slots__ is a dunder class attribute
    assert _unm(k, k.replace("    __slots__ = ('a',)\n\n", ""), "K.m") == "UNMODELED"
    mod = "import registry\nregistry.add(1)\n\n\ndef f(a):\n    return g(a)\n"
    assert _unm(mod, mod) == "PROVED"
    assert _unm(mod, mod.replace("registry.add(1)", "registry.add(2)")) == "UNMODELED"  # import-time call changed
    assert _unm(mod, mod + "registry.add(f)\n") == "UNMODELED"  # registered at import time


def test_shadowed_builtins_and_global_nonlocal():
    pre = "def f(a):\n    return len(a) + 1\n"
    shadow = "def len(x):\n    return 0\n\n\n" + pre
    assert _unm(pre, shadow) == "UNMODELED"  # len now means something else
    assert _unm(shadow, shadow) == "PROVED"
    assert _unm(pre, "isinstance = other\n\n\n" + pre) == "PROVED"  # a rebound name the function does not read
    use = "def f(a):\n    return isinstance(a, int)\n"
    assert _unm(use, "isinstance = other\n\n\n" + use) == "UNMODELED"
    g = "X = 1\n\n\ndef f(a):\n    global X\n    X = a\n    return a\n"
    assert _unm(g, g) == "UNMODELED"  # global write in the target
    nl = "def f(a):\n    n = 0\n\n    def bump():\n        nonlocal n\n        n = n + 1\n\n    bump()\n    return n\n"
    assert _unm(nl, nl) == "UNMODELED"  # a closure rebinding the enclosing local


def test_augmented_assignment_to_attributes_and_subscripts_is_an_ordered_effect():
    pre = "def f(self, k):\n    self.n += 1\n    self.d[k] += 2\n    return self.n\n"
    assert _unm(pre, pre) == "PROVED"
    for old, new in (("self.n += 1", "self.n -= 1"), ("self.n += 1", "self.n += 2"), ("self.n += 1", "self.m += 1"),
                     ("self.d[k] += 2", "self.d[k] -= 2"), ("self.d[k] += 2", "self.d[0] += 2"),
                     ("    self.n += 1\n    self.d[k] += 2\n", "    self.d[k] += 2\n    self.n += 1\n"),
                     ("    self.n += 1\n", "")):
        assert _unm(pre, pre.replace(old, new)) == "UNMODELED", (old, new)


def test_oracle_treats_attribute_names_that_exist_on_its_wrapper_as_opaque_reads():
    # found by the widened hunt: super().__init__(...) hit the wrapper's own constructor (11 PROVED mutants unrunnable)
    src = "class K(Base):\n    def __init__(self, name, ext):\n        super().__init__(name, ext)\n        return ext.__class__\n"
    assert check_uf(src, src, "K.__init__")[0] == "PROVED"
    assert uf_relational_selftest(src, src, "K.__init__", n=60, seed=1) == []
    assert uf_soundness_selftest(src, "K.__init__", n=120, seed=2) == []
