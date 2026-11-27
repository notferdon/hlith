# SPDX-License-Identifier: Apache-2.0
"""Independent CPython controls for the symbolic route to a landing certificate."""
import pytest

from hlith.obligation import equiv_cert


def _namespace(source):
    result = {}
    exec(source, result)
    return result


def test_annotation_snapshot_is_observable():
    base = "def f(x):\n    return x\n\nsnapshot = f.__annotations__\n"
    post = base.replace("f(x)", "f(x: int)")
    assert _namespace(base)["snapshot"] == {}
    assert _namespace(post)["snapshot"] == {"x": int}
    assert not equiv_cert.certify_sources(base, post, "f").ok


def test_symbolic_arithmetic_respects_domain_contract_and_strict_mode(tmp_path):
    from hlith import differential

    base = "def f(x: int):\n    return (x + 1) + 2\n"
    post = base.replace("(x + 1) + 2", "x + 3")

    class Counter(int):
        def __add__(self, other):
            return 10

    assert _namespace(base)["f"](Counter()) == 12
    assert _namespace(post)["f"](Counter()) == 10
    # 1. Strict open-caller mode MUST refuse without an exact-int entry guard.
    assert not equiv_cert.certify_sources(base, post, "f", strict_domain=True).ok
    # 2. Unannotated target MUST refuse in all modes.
    assert not equiv_cert.certify_sources(base.replace("x: int", "x"), post.replace("x: int", "x"), "f").ok
    # 3. Defining an int subclass in the same module MUST refuse even in default scoped mode.
    sub = "class Counter(int):\n    def __add__(self, other):\n        return 10\n\n\n"
    assert not equiv_cert.certify_sources(sub + base, sub + post, "f").ok
    # 4. In default scoped mode (no int subclass in-tree), SYM admits with explicit exact-int domain
    #    claim and runtime differential subclass enforcement.
    cert = equiv_cert.certify_sources(base, post, "f")
    assert cert.ok and cert.rules == ("SYM",) and dict(cert.domain) == {"x": "int"}
    assert "exact builtin int" in cert.domain_text and "outside this claim" in cert.domain_text
    for side, src in (("base", base), ("post", post)):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(src)
    dom = equiv_cert.engine_domain(tmp_path / "post", "", "m", "f")
    assert differential._domain_violation(dom, "m", "f", [Counter()], {}) is not None


BASE = "def f(x, default):\n    if x is None:\n        return default\n    return x\n"
POST = "def f(x, default):\n    return x if x is not None else default\n"


def test_symbolic_selection_preserves_identity_in_both_entry_points(tmp_path):
    marker = object()
    for args in [(None, marker), (marker, None), (False, True), (marker, marker)]:
        assert _namespace(BASE)["f"](*args) is _namespace(POST)["f"](*args)
    for name, source in (("base", BASE), ("post", POST)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "m.py").write_text(source)
    for cert in (equiv_cert.certify_sources(BASE, POST, "f"),
                 equiv_cert.certify(tmp_path / "base", tmp_path / "post", "m", "f")):
        assert cert.ok, cert.reason
        assert cert.rules == ("SYM",)
        assert cert.domain_record["cross_check"] == "identity-partitions/1"
        assert cert.domain_record["assignments"] > 1
        assert cert.domain == ()


@pytest.mark.parametrize("expr", ["x if x else default", "x if x is None else default",
                                  "default if x is False else x", "x if x != None else default"])
def test_symbolic_selection_preserves_falsy_values_and_protocol_dispatch(expr):
    assert not equiv_cert.certify_sources(BASE, f"def f(x, default):\n    return {expr}\n", "f").ok


def test_model_seed_executes_both_sides_at_a_coupled_arithmetic_boundary(tmp_path):
    from hlith.obligation.symeq.witness import integer_seed

    source = ("def fee(units: int, /, *, offset: int):\n"
              "    gross = 11 * units + 5 * offset\n"
              "    net = 7 * units - 3 * offset\n"
              "    if gross == 249136 and net == 245068:\n        return 17\n    return 3\n")
    base, post = tmp_path / "old.py", tmp_path / "new.py"
    base.write_text(source)
    post.write_text(source.replace("return 17", "return 19"))
    args, kwargs, origin = integer_seed(base, post, "fee")
    assert origin == "symbolic-countermodel"
    assert _namespace(base.read_text())["fee"](*args, **kwargs) == 17
    assert _namespace(post.read_text())["fee"](*args, **kwargs) == 19
    assert integer_seed(base, base, "fee") is None


def test_many_parameters_do_not_allocate_the_cartesian_product():
    from hlith.obligation.symeq import prove

    params = ", ".join(f"p{i}: int | str" for i in range(40))
    src = f"def f({params}):\n    return p0\n"
    proof = prove(src, src, "f", modes=("typed",))
    assert proof.status == "unknown" and "combinations" in proof.reason


def test_lazy_conditional_and_literal_call_packing():
    base = ("def select(a, *, b):\n    return a, b\n\n"
            "def f(x, y):\n    if x:\n        return select(*(x,), **{'b': y})\n    return y\n")
    post = base[:base.index("    if x:")] + "    return select(x, b=y) if x else y\n"
    cert = equiv_cert.certify_sources(base, post, "f", strict_domain=True)
    assert cert.ok and "NORM" in cert.rules and not cert.domain
    assert "unpacked" in cert.detail
    assert not equiv_cert.certify_sources(base, post.replace("b=y", "b=x"), "f").ok
    assert not equiv_cert.certify_sources(base.replace("{'b': y}", "{'b': x, 'b': y}"), post, "f").ok


def test_rich_comparison_return_value_is_not_assumed_to_be_a_boolean():
    base = "def f(x, y):\n    if x == y:\n        return True\n    return False\n"
    post = "def f(x, y):\n    return x == y\n"
    assert not equiv_cert.certify_sources(base, post, "f", strict_domain=True).ok


@pytest.mark.parametrize("atom", ["s.startswith()", "s.isalpha('x')", "('x',) in s", "len(s, extra=0) > 0"])
def test_exact_type_does_not_make_a_raising_atom_total(atom):
    header = "def f(s: str):\n    if type(s) is not str:\n        return False\n"
    b = header + f"    return s == 'ok' or {atom}\n"
    p = header + f"    return {atom} or s == 'ok'\n"
    assert _namespace(b)["f"]("ok") is True
    with pytest.raises(TypeError):
        _namespace(p)["f"]("ok")
    assert not equiv_cert.certify_sources(b, p, "f", strict_domain=True).ok


def test_type_guard_must_resolve_to_the_builtin_on_both_sides():
    b = ("def fake_type(x):\n    return str\n\ntype = fake_type\n"
         "def f(s: str):\n    if type(s) is not str:\n        return False\n"
         "    return len(s) > 5 or s.startswith('a')\n")
    p = b.replace("len(s) > 5 or s.startswith('a')", "s.startswith('a') or len(s) > 5")
    assert _namespace(b)["f"](b"012345") is True
    with pytest.raises(TypeError):
        _namespace(p)["f"](b"012345")
    assert not equiv_cert.certify_sources(b, p, "f", strict_domain=True).ok


def test_a_declared_none_guard_preserves_other_callers_without_an_annotation():
    b = "def f(x):\n    return x\n"
    p = b.replace("    return x", "    if x is None:\n        raise ValueError('missing')\n    return x")
    delta = {"id": "missing", "type": "expr", "symbol": "m.f", "expr": "x is None", "param": "x",
             "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    assert equiv_cert.certify_sources(b, p, "f", deltas=[delta], strict_domain=True).ok
    assert not equiv_cert.certify_sources(b, p.replace("return x", "return None"), "f", deltas=[delta], strict_domain=True).ok
    assert not equiv_cert.certify_sources(b, p, "f", deltas=[dict(delta, expr="x is not None")], strict_domain=True).ok
