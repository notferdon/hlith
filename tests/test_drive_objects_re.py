# SPDX-License-Identifier: Apache-2.0
"""Object-shaped inputs: real re.Match / re.Pattern construction as a candidate producer. A candidate is a JSON descriptor
{"__hlith_re_match__": {pattern, flags, string, mode, pos}} / {"__hlith_re_pattern__": {pattern, flags}}; ``materialise_re`` builds the
real object with re.compile + a real match against the seeded string (a descriptor whose match is None is never emitted). No duck
objects. Patterns come from the code's own literals; hostile patterns are skipped and said so."""
import ast
import json
import re
import textwrap

from hlith.drive_objects import materialise_re, module_regex_literals, re_param_candidates

MODULE = textwrap.dedent('''
    import re
    _PCT = re.compile(r"%([0-9A-Fa-f]{2})")
    HOST_RE = re.compile(r"^(?P<host>[^:/]+)(?::(?P<port>\\d+))?$")
    NAME = "not a pattern ("

    def _decode(match: "re.Match[str]") -> str:
        return chr(int(match.group(1), 16))

    def host_of(m: re.Match) -> str:
        return m.group("host")

    def uses_pattern(p: re.Pattern, s: str):
        return p.sub("", s)

    def untyped_match(m):
        return m.group(0), m.start()

    def plain(x: int):
        return x + 1
''')


def _fn(name):
    t = ast.parse(MODULE)
    return next(n for n in t.body if isinstance(n, ast.FunctionDef) and n.name == name)


def test_module_regex_literals_come_from_re_calls_and_ignore_plain_strings_that_do_not_compile():
    lits = module_regex_literals(MODULE)
    assert "%([0-9A-Fa-f]{2})" in lits and any("(?P<host>" in x for x in lits)
    assert "not a pattern (" not in lits  # does not compile


def test_match_param_gets_real_matches_built_from_the_modules_own_patterns():
    cands = re_param_candidates(_fn("_decode"), extra_literals=module_regex_literals(MODULE))
    assert cands and all(c["exact"] is False and c["param"] == "match" for c in cands)
    objs = [materialise_re(json.loads(json.dumps(c["value"]))) for c in cands]
    assert all(isinstance(o, re.Match) for o in objs)  # real objects, never ducks
    assert any(o.re.pattern == "%([0-9A-Fa-f]{2})" and o.group(1) == "41" for o in objs)  # the decode-percent control


def test_named_group_usage_finds_the_pattern_with_that_group():
    cands = re_param_candidates(_fn("host_of"), extra_literals=module_regex_literals(MODULE))
    objs = [materialise_re(c["value"]) for c in cands]
    assert objs and any("host" in o.groupdict() and o.group("host") for o in objs)


def test_pattern_param_gets_real_compiled_patterns():
    cands = re_param_candidates(_fn("uses_pattern"), extra_literals=module_regex_literals(MODULE))
    assert cands and all("__hlith_re_pattern__" in c["value"] for c in cands if c["value"])
    assert all(isinstance(materialise_re(c["value"]), re.Pattern) for c in cands if c["value"])


def test_untyped_param_used_like_a_match_is_recognised_by_its_method_calls():
    cands = re_param_candidates(_fn("untyped_match"), extra_literals=module_regex_literals(MODULE))
    assert cands and all("__hlith_re_match__" in c["value"] for c in cands if c["value"])


def test_non_regex_param_gets_nothing():
    assert re_param_candidates(_fn("plain"), extra_literals=["a"]) == []


def test_hostile_invalid_and_overlong_patterns_are_skipped_and_reported():
    c = re_param_candidates(_fn("_decode"), extra_literals=["(a+)+$", "([", "x" * 500, r"(\w+\s?)*$", "%(..)"])
    pats = {x["value"]["__hlith_re_match__"]["pattern"] for x in c if x["value"]}
    assert "%(..)" in pats and not ({"(a+)+$", "([", "x" * 500, r"(\w+\s?)*$"} & pats)
    un = " ".join(x.get("unmodeled", "") for x in c)
    assert "nested quantifier" in un and "does not compile" in un and "too long" in un


def test_descriptor_for_a_non_matching_pair_is_refused_by_the_builder():
    import pytest
    with pytest.raises(ValueError):
        materialise_re({"__hlith_re_match__": {"pattern": "abc", "flags": 0, "string": "zzz", "mode": "search", "pos": 0}})
    with pytest.raises(ValueError):
        materialise_re({"__hlith_re_match__": {"pattern": "a" * 1000, "flags": 0, "string": "a", "mode": "search", "pos": 0}})
    with pytest.raises(ValueError):
        materialise_re({"os.system": "x"})
