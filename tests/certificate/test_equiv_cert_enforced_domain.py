# SPDX-License-Identifier: Apache-2.0
"""ENFORCED admitted domain (maintainer mandate via design review): HELD by R2/R3 is scoped to the engine's ADMITTED INPUT DOMAIN (exact builtin str parameters) and that domain is ENFORCED where Hlith
itself acts, not only stated:
  (a) the certificate carries a MACHINE-READABLE, HASHED domain record (param -> exact builtin type, rules, base/post source hashes, what was scanned);
  (b) the engine refuses a SUBCLASS input to a domain parameter as a hard error (`_domain_violation`), and counts off-domain inputs it explored;
  (c) REPO-SIDE REFUSAL: R2/R3 are refused when an in-tree call site of the target passes an instance of an in-tree class (a str subclass, a custom-dispatch object, a factory result) to a
      domain parameter. DECIDED exactly: a call argument that is a CALL of an in-tree class name (directly, or through a local name assigned from one in the same function) is non-exact;
      a plain parameter, literal, f-string, str(...), attribute or any unresolved expression is NOT refused by itself (unknown is not a violation); test files are not scanned;
  (d) an external caller that passes a subclass stays OUTSIDE the admitted domain by stated contract: the certificate says so in the sentence the operator reads.
R0/R4 claim no input-type assumption and are never refused by this. No differential run here (unit level)."""

from __future__ import annotations

import hashlib
import json

import pytest

from hlith.obligation import equiv_cert as ec

BASE = "def f(s: str) -> bool:\n    return bool(s.startswith('x') or s.endswith('x'))\n"
POST = "def f(s: str) -> bool:\n    if s.endswith('x'):\n        return True\n    return bool(s.startswith('x'))\n"
LOUD = "class Loud(str):\n    def startswith(self, p):\n        return False\n"


def tree(tmp_path, base_files, post_files):
    for side, files in (("base", base_files), ("post", post_files)):
        for rel, text in files.items():
            p = tmp_path / side / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    return tmp_path / "base", tmp_path / "post"


def cert(tmp_path, use_src, extra=None, function="f"):
    extra = extra or {}
    b, p = tree(tmp_path, {"pkg/__init__.py": "", "pkg/m.py": BASE, "pkg/use.py": use_src, **extra}, {"pkg/__init__.py": "", "pkg/m.py": POST, "pkg/use.py": use_src, **extra})
    return ec.certify(b, p, "pkg.m", function)


# ----------------------------------------------------------------------------------------------- (c) repo-side refusal
@pytest.mark.parametrize("use", [
    "from pkg.m import f\nfrom pkg.cls import Loud\n\n\ndef go():\n    return f(Loud('x'))\n",
    "from pkg import m\nfrom pkg.cls import Loud\n\n\ndef go():\n    return m.f(Loud('x'))\n",
    "from pkg.m import f\nfrom pkg.cls import Loud\n\n\ndef go():\n    return f(s=Loud('x'))\n",
    "from pkg.m import f\nfrom pkg.cls import Loud\n\n\ndef go():\n    v = Loud('x')\n    return f(v)\n",
    "from pkg.m import f\nfrom pkg.cls import Box\n\n\ndef go():\n    return f(Box())\n",
], ids=["direct", "module-attr", "keyword", "via-local", "custom-dispatch-object"])
def test_an_in_tree_call_site_feeding_an_in_tree_class_instance_refuses_r3(tmp_path, use):
    cls = LOUD + "\n\nclass Box:\n    def __getattr__(self, n):\n        return lambda *a: False\n"
    c = cert(tmp_path, use, {"pkg/cls.py": cls})
    assert not c.ok and "call site" in (c.reason + c.detail).lower(), (c.reason, c.detail)


@pytest.mark.parametrize("use", [
    "from pkg.m import f\n\n\ndef go(name):\n    return f(name)\n",                      # an unresolved plain parameter: NOT refused by itself
    "from pkg.m import f\n\n\ndef go():\n    return f('abc')\n",
    "from pkg.m import f\n\n\ndef go(n):\n    return f(str(n))\n",
    "from pkg.m import f\n\n\ndef go(n):\n    return f(f'{n}x')\n",
    "from pkg.m import f\n\n\ndef go(o):\n    return f(o.name)\n",
], ids=["plain-param", "literal", "str-call", "fstring", "attribute"])
def test_unresolved_or_plain_arguments_are_not_refused_by_themselves(tmp_path, use):
    c = cert(tmp_path, use, {"pkg/cls.py": LOUD})
    assert c.ok and "R3" in c.rules, (c.reason, c.detail)


def test_test_files_are_scanned_for_call_sites(tmp_path):
    """NO-GO class (B): the repo's own tests are an in-tree path that can feed a non-exact value; they are read by the call-site scan (a test feeding a str subclass refuses R3)."""
    c = cert(tmp_path, "def go():\n    return 1\n", {"tests/test_use.py": "from pkg.m import f\nfrom pkg.cls import Loud\n\n\ndef test_x():\n    assert f(Loud('x')) is False\n", "pkg/cls.py": LOUD})
    assert not c.ok and "call site" in (c.reason + c.detail).lower(), (c.reason, c.detail)


def test_an_identity_change_is_never_refused_by_call_sites(tmp_path):
    use = "from pkg.m import f\nfrom pkg.cls import Loud\n\n\ndef go():\n    return f(Loud('x'))\n"
    b, p = tree(tmp_path, {"pkg/__init__.py": "", "pkg/m.py": BASE, "pkg/use.py": use, "pkg/cls.py": LOUD}, {"pkg/__init__.py": "", "pkg/m.py": BASE.replace("p", "p"), "pkg/use.py": use, "pkg/cls.py": LOUD})
    c = ec.certify(b, p, "pkg.m", "f")
    assert c.ok and c.rules == ("R0",), (c.reason, c.detail)


def test_a_non_target_function_with_the_same_name_in_another_module_is_still_conservatively_scanned(tmp_path):
    """Name-based (no type inference): a call to ANY callable named f that passes an in-tree class instance counts; documented as conservative, never a silent pass."""
    use = "from other import f\nfrom pkg.cls import Loud\n\n\ndef go():\n    return f(Loud('x'))\n"
    assert not cert(tmp_path, use, {"pkg/cls.py": LOUD}).ok


# ----------------------------------------------------------------------------------------------- (a) machine-readable, hashed domain record
def test_the_certificate_carries_a_hashed_machine_readable_domain_record(tmp_path):
    c = cert(tmp_path, "from pkg.m import f\n\n\ndef go(n):\n    return f(n)\n")
    rec = c.domain_record
    assert rec["kind"] == "exact-builtin-params" and rec["function"] == "pkg.m.f" and rec["params"] == [["s", "str"]] and rec["rules"] == ["R3"], rec
    assert rec["base_source_sha256"] == hashlib.sha256(BASE.encode()).hexdigest() and rec["post_source_sha256"] == hashlib.sha256(POST.encode()).hexdigest()
    assert rec["call_sites"]["scanned_files"] >= 1 and rec["call_sites"]["refused"] == 0 and "unresolved" in rec["call_sites"]["policy"]
    assert c.domain_sha256 == hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_the_record_hash_is_deterministic_and_changes_with_the_source(tmp_path):
    use = "from pkg.m import f\n\n\ndef go(n):\n    return f(n)\n"
    a = cert(tmp_path / "a", use)
    b = cert(tmp_path / "b", use)
    assert a.domain_sha256 == b.domain_sha256
    post2 = POST.replace("'x'", "'y'")
    b2, p2 = tree(tmp_path / "c", {"pkg/__init__.py": "", "pkg/m.py": BASE.replace("'x'", "'y'"), "pkg/use.py": use}, {"pkg/__init__.py": "", "pkg/m.py": post2, "pkg/use.py": use})
    assert ec.certify(b2, p2, "pkg.m", "f").domain_sha256 != a.domain_sha256


def test_r0_has_no_domain_record():
    c = ec.certify_sources("def f(x):\n    return x\n", "def f(x):\n    return x\n", "f")
    assert c.ok and c.domain_record == {} and c.domain_sha256 == ""


def _rule_clause(text: str) -> str:
    """The rule's own one-sentence clause. Every positive certificate ends with "; " + closure_gate.SCOPE (5c3e8eeb, case); the
    boundary text must be present exactly, and the clause before it must stay a single sentence."""
    from hlith.obligation.closure_gate import SCOPE

    assert text.endswith("; " + SCOPE), text
    return text[: -len("; " + SCOPE)]


def test_the_operator_sentence_states_the_enforcement(tmp_path):
    c = cert(tmp_path, "from pkg.m import f\n\n\ndef go(n):\n    return f(n)\n")
    t = c.domain_text
    assert "exact builtin str" in t and "no in-tree call site" in t and "outside this claim" in t and _rule_clause(t).count(". ") == 0, t


# ----------------------------------------------------------------------------------------------- (b) engine guard
def test_the_engine_refuses_a_subclass_input_to_a_domain_parameter():
    from hlith import differential

    class Loud(str):
        pass

    dom = {"module": "pkg.m", "function": "f", "params": [["s", "str"]]}
    assert differential._domain_violation(dom, "pkg.m", "f", [Loud("x")], {}) is not None
    assert differential._domain_violation(dom, "pkg.m", "f", [], {"s": Loud("x")}) is not None
    assert differential._domain_violation(dom, "pkg.m", "f", ["x"], {}) is None
    assert differential._domain_violation(dom, "pkg.m", "f", [None], {}) is None  # a non-str is off-domain but not a SUBCLASS: counted, not an error
    assert differential._domain_violation(dom, "pkg.m", "g", [Loud("x")], {}) is None  # another function is not the target
    assert differential._domain_violation({}, "pkg.m", "f", [Loud("x")], {}) is None  # no domain claimed: nothing to enforce


def test_off_domain_inputs_are_counted():
    from hlith import differential

    dom = {"module": "pkg.m", "function": "f", "params": [["s", "str"]]}
    assert differential._domain_offdomain(dom, "pkg.m", "f", [None], {}) is True
    assert differential._domain_offdomain(dom, "pkg.m", "f", ["x"], {}) is False
    assert differential._domain_offdomain({}, "pkg.m", "f", [None], {}) is False


# ----------------------------------------------------------------------------------------------- the forwarding exposure is MEASURED per HELD (design decision: forwarding from a parameter is admitted by contract)
WRAPPER = "from pkg.m import f\n\n\ndef go(name: str):\n    return f(name)\n"


def test_a_wrapper_forwarding_its_own_parameter_is_counted_not_hidden(tmp_path):
    c = cert(tmp_path, WRAPPER, {"pkg/cls.py": LOUD})
    assert c.ok, (c.reason, c.detail)
    cs = c.domain_record["call_sites"]
    assert cs["forwarded_params"] == 1 and cs["unresolved_args"] == 0 and cs["refused"] == 0, cs
    assert "forwarded from a caller parameter or an unresolved expression is admitted by contract (outside callers can pass subclasses; outside this claim)" in cs["policy"]


def test_literals_and_str_calls_are_not_exposure_but_unresolved_expressions_are(tmp_path):
    use = ("from pkg.m import f\n\n\ndef a():\n    return f('lit')\n\n\ndef b(n):\n    return f(str(n))\n\n\ndef c(o):\n    return f(o.name)\n\n\n"
           "def d(p):\n    return f(p)\n\n\ndef e(p):\n    q = p\n    return f(q)\n")
    cs = cert(tmp_path, use, {"pkg/cls.py": LOUD}).domain_record["call_sites"]
    assert cs["forwarded_params"] == 1 and cs["unresolved_args"] == 2, cs  # d(p) forwarded; o.name and the local q are unresolved


def test_the_exposure_changes_the_record_hash(tmp_path):
    a = cert(tmp_path / "a", "from pkg.m import f\n\n\ndef go():\n    return f('x')\n", {"pkg/cls.py": LOUD})
    b = cert(tmp_path / "b", WRAPPER, {"pkg/cls.py": LOUD})
    assert a.domain_sha256 != b.domain_sha256
