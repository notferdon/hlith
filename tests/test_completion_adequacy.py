# SPDX-License-Identifier: Apache-2.0
"""case. Predeclared before the first run.

Real R1 E2 (requests PreparedRequest.prepare_content_length, `builtin_str(length)` -> `str(length + 1)`) was HELD: a FALSE HELD.
Measured root cause: on every explored input the receiver's `headers` was None / a str (the constructor leaves it None; a separate
prepare_headers() sets the mapping), so the changed statement `self.headers[k] = str(length + 1)` evaluated its right side and then
raised the SAME TypeError on both sides. Adequacy still passed: the line was 'entered' and its ablation was 'live' (removing it turns
a TypeError into a return) although the changed VALUE was never observable in a non-failing outcome.
Rule under test: a changed non-terminal simple statement must COMPLETE (not raise) on at least one explored input; otherwise the
verdict is a named UNVERIFIED, never HELD. Terminal statements (return / raise) are exempt (they cannot complete)."""
from hlith import differential
from hlith.types import Verdict

_BASE = '''class CI:
    """stand-in for requests' CaseInsensitiveDict: a repository class, built by a CALL (no dict literal in the target's module)"""

    def __init__(self):
        self._store = {}

    def __setitem__(self, k, v):
        self._store[k.lower()] = (k, v)

    def __repr__(self):
        return str({k: v for k, v in self._store.values()})


class Req:
    def __init__(self):
        self.headers = None
        self.method = None

    def prepare_headers(self):
        self.headers = CI()

    def prepare_len(self, body):
        if body is not None:
            length = len(body)
            if length:
                self.headers["Content-Length"] = str(length)
'''
_TEST = ("from pkg.m import Req\n\n\ndef test_prepare():\n    r = Req()\n    r.prepare_headers()\n    r.prepare_len(b'abc')\n"
         "    assert r.headers is not None\n")


def _run(tmp_path, post):
    for side, body in (("base", _BASE), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    nodes = [{"node_id": "tests/test_m.py::test_prepare", "reaches": ["pkg.m.Req.prepare_len"], "exists_in_base": True,
              "provenance": "hand-picked"}]
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Req.prepare_len",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=200, max_examples=15,
        adequacy_gate=True, impacted_test_nodes=nodes)


def test_changed_value_that_never_completes_is_not_held(tmp_path):
    """The R1 E2 twin: str(length) -> str(length + 1) behind a headers that is None on every explored receiver."""
    ob = _run(tmp_path, _BASE.replace("str(length)", "str(length + 1)"))
    assert ob.verdict is not Verdict.HELD, (ob.verdict, ob.witness, ob.stop_reason)
    print("TWIN VERDICT", ob.verdict.value, (ob.witness or ob.stop_reason or "")[:160])


def test_the_gap_is_named(tmp_path):
    ob = _run(tmp_path, _BASE.replace("str(length)", "str(length + 1)"))
    if ob.verdict is Verdict.UNVERIFIED:
        assert "never completed" in (ob.stop_reason or ""), ob.stop_reason


def test_nested_function_statement_has_the_same_rule(tmp_path):
    """design review addition: a changed simple statement INSIDE a nested def counts too."""
    base = _BASE.replace('''            if length:
                self.headers["Content-Length"] = str(length)''', '''            def put(v):
                self.headers["Content-Length"] = str(v)

            if length:
                put(length)''')
    post = base.replace("= str(v)", "= str(v + 1)")
    ob = _run_pair(tmp_path, base, post)
    assert ob.verdict is not Verdict.HELD, (ob.verdict, ob.witness, ob.stop_reason)


def test_a_statement_that_completes_is_unaffected(tmp_path):
    """Control: the same edit where headers IS built by the target itself completes on explored inputs, so the rule never blocks
    it: it is decided (REFUTED, the value differs), not made UNVERIFIED by the completion rule."""
    base = _BASE.replace("        if body is not None:\n", "        self.headers = CI()\n        if body is not None:\n")
    post = base.replace("str(length)", "str(length + 1)")
    ob = _run_pair(tmp_path, base, post)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)
    assert "never completed" not in (ob.stop_reason or "")


def _run_pair(tmp_path, base_src, post_src):
    for side, body in (("base", base_src), ("post", post_src)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(_TEST)
    (tmp_path / "proposer").mkdir()
    nodes = [{"node_id": "tests/test_m.py::test_prepare", "reaches": ["pkg.m.Req.prepare_len"], "exists_in_base": True,
              "provenance": "hand-picked"}]
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Req.prepare_len",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=200, max_examples=15,
        adequacy_gate=True, impacted_test_nodes=nodes)
