# SPDX-License-Identifier: Apache-2.0
"""delta_follow (review, case): follow-up seeds from a delta's domain and from the patch's own changed regions."""
from __future__ import annotations

import ast

from hlith import delta_follow as df

PRE = '''def super_len(o):
    total_length = None
    if hasattr(o, "__len__"):
        total_length = len(o)
    return total_length
'''
HUNK = '    if isinstance(o, str):\n        o = o.encode("utf-8")\n'
DELTA = {"id": "str-bytes", "symbol": "m.super_len", "kind": "behavior", "claim": "c", "input_domain": "", "pre": "", "post": "",
         "predicate": {"type": "expr", "param": "o", "expr": "isinstance(o, str)"},
         "expected": {"kind": "returns_expr", "expr": "len(o.encode('utf-8'))"}}


def _post(extra_after: str = "", before: str = "") -> str:
    return PRE.replace("    total_length = None\n", "    total_length = None\n" + before + HUNK + extra_after, 1)


def _plan(post: str, **kw):
    return df.region_plan(PRE, post, "super_len", ["o"], [DELTA], symbol="m.super_len", **kw)


def test_legitimate_hunk_is_inside_the_delta_and_exercised():
    plan = _plan(_post())
    post = [r for r in plan.regions if r.side == "post"]
    assert len(post) == 2  # the added `if` hunk and the nested rebinding it carries
    assert all(r.inside_delta is True and r.exercised and r.outside_witness is None for r in post)
    assert not plan.unexercised_outside


def test_unguarded_extra_change_is_outside_with_a_witness():
    plan = _plan(_post(extra_after="    total_length = 0\n"))
    outside = [r for r in plan.regions if r.outside_witness is not None]
    assert outside and outside[0].guards == []  # unguarded: every input, including those outside the delta


def test_rare_bytes_guard_with_folded_constant_is_solved_and_outside():
    plan = _plan(_post(before="    if isinstance(o, bytes) and len(o) > (1 << 10):\n        return 0\n"), allow_bytes=True)
    (r,) = [r for r in plan.regions if r.line and "1 << 10" in r.source]
    assert r.exercised and r.outside_witness is not None
    sizes = [len(bytes.fromhex(a[0][df.BYTES_TAG])) for a, k, s in plan.seeds if isinstance(a[0], dict) and df.BYTES_TAG in a[0]]
    assert any(n > 1024 for n in sizes), sizes  # an input that really enters the region


def test_rare_chr_guard_nested_in_the_str_hunk_is_solved_inside():
    # the real shape (round-2 A4): the rare branch sits INSIDE the added `if isinstance(o, str)` hunk, after o = o.encode(...)
    post = PRE.replace("    total_length = None\n", "    total_length = None\n" + HUNK
                       + '        if chr(0x1F9FF) in o.decode("utf-8"):\n            return 0\n', 1)
    plan = _plan(post)
    (r,) = [r for r in plan.regions if "0x1F9FF" in r.source and r.guards]  # the nested region (guards isinstance(o, str))
    assert r.exercised and r.inside_delta is True and r.outside_witness is None
    assert any(isinstance(a[0], str) and "\U0001f9ff" in a[0] for a, k, s in plan.seeds)  # a str that really enters it


def test_same_guard_at_function_level_is_outside_because_original_bytes_reach_it():
    plan = _plan(_post(extra_after='    if chr(0x1F9FF) in o.decode("utf-8"):\n        return 0\n'))
    (r,) = [r for r in plan.regions if "0x1F9FF" in r.source]
    assert r.exercised and r.outside_witness is not None  # an ORIGINAL bytes input (outside the str delta) enters it


def test_unevaluable_guard_is_never_counted_as_exercised():
    plan = _plan(_post(extra_after="    if secret_hash(o) == 7:\n        return 0\n"))
    (r,) = [r for r in plan.regions if "secret_hash" in r.source]
    assert not r.exercised and r.unevaluable
    assert r in plan.unexercised_outside


def test_domain_seeds_split_in_and_out_and_cross_the_boundary():
    seeds, notes = df.domain_seeds([DELTA], "m.super_len", ["o"])
    ins = [a[0] for a, k, s in seeds if s.endswith(":in")]
    outs = [a[0] for a, k, s in seeds if s.endswith(":out")]
    assert sum(isinstance(v, str) and not v.isascii() for v in ins) >= 8 and all(isinstance(v, str) for v in ins)
    assert outs and not any(isinstance(v, str) for v in outs)  # OUT never contains a member of the delta domain
    assert any(isinstance(v, list) for v in outs) and any(v is None for v in outs)
    assert all(ast.parse(repr(v)) for v in ins[:5])


def test_multi_parameter_callable_is_noted_not_silently_skipped():
    seeds, notes = df.domain_seeds([dict(DELTA, symbol="m.f")], "m.f", ["a", "o"])
    assert seeds == [] and notes and "one-parameter" in notes[0]


def test_witness_text_renders_seed_tags_as_pasteable_python():
    from hlith.differential import _call_repr
    assert _call_repr("m", "f", [{"__hlith_bytes__": "6162"}], {}, ["o"]) == "m.f(o=b'ab')"
    assert _call_repr("m", "f", [{"__hlith_tuple__": [0, 1]}], {}, ["o"]) == "m.f(o=(0, 1))"
    assert _call_repr("m", "f", [{"__hlith_tuple__": [7]}], {}, ["o"]) == "m.f(o=(7,))"


def test_guard_with_an_offset_slice_is_entered_by_a_padded_literal():
    # the O3v2-D shape: `"\\0" in filename[3:]` needs the literal at index >= 3
    pre = "def f(name):\n    return name\n"
    post = "def f(name):\n    if '\\\\0' in name[3:]:\n        raise ValueError('nul')\n    return name\n"
    plan = df.region_plan(pre, post, "f", ["name"], [], symbol="m.f")
    r = [r for r in plan.regions if r.guards == [] and "name[3:]" in r.source][0]
    assert r.exercised and r.n_entering >= 1
    assert any(isinstance(a[0], str) and "\\0" in a[0][3:] for a, k, s in plan.seeds)


def _unexplored(deltas):
    plan = df.region_plan(PRE, _post(), "super_len", ["o"], deltas, symbol="m.super_len")
    _, un = df.account_text(plan, [], 0, deltas)
    return un


def test_unexplored_text_names_lone_surrogates_and_str_subclasses_for_a_str_delta():
    un = _unexplored([DELTA])  # expression delta over isinstance(o, str)
    assert "lone surrogates" in un and "str subclasses" in un and "UnicodeEncodeError" in un
    lit = dict(DELTA, id="lit", predicate={"type": "literal_inputs", "inputs": [{"args": ["é"], "kwargs": {}}]},
               expected={"kind": "returns", "value_repr": "2"})
    assert "lone surrogates" in _unexplored([lit])  # a literal delta over str inputs is named too


def test_unexplored_text_does_not_name_surrogates_for_a_non_str_delta():
    d = dict(DELTA, id="n", predicate={"type": "typed", "param": "o", "class": "int_zero"}, expected={"kind": "returns", "value_repr": "0"})
    assert "lone surrogates" not in _unexplored([d])


def test_while_body_removed_dict_entry_behind_early_return_produces_wrapped_seed():
    pre = '''def unescape(s: str) -> str:
    if not (s.startswith('"') and s.endswith('"')):
        return s
    body = s[1:-1]
    out = []
    i = 0
    while i < len(body):
        if body[i] == "\\\\" and i + 1 < len(body):
            esc = {"n": "\\n", "t": "\\t"}
            out.append(esc.get(body[i + 1], body[i + 1]))
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)
'''
    post = pre.replace('            esc = {"n": "\\n", "t": "\\t"}\n', '            esc = {"n": "\\n"}\n')
    plan = df.region_plan(pre, post, "unescape", ["s"], [], symbol="m.unescape")
    assert any("esc =" in r.source for r in plan.regions), plan.regions
    assert all(r.guards for r in plan.regions if "esc =" in r.source), plan.regions
    assert any(a[0] == r'"\t"' for a, k, _tag in plan.seeds), plan.seeds[:10]


def test_matching_loop_header_inside_delta_remains_exercised():
    post = PRE.replace(
        "    total_length = None\n",
        "    total_length = None\n    if isinstance(o, str):\n        total = 0\n        for ch in o:\n            total += 1\n        total_length = total\n",
        1,
    )
    pre_loop = PRE.replace(
        "    total_length = None\n",
        "    total_length = None\n    if isinstance(o, str):\n        total = 0\n        for ch in o:\n            total += 2\n        total_length = total\n",
        1,
    )
    plan = df.region_plan(pre_loop, post, "super_len", ["o"], [DELTA], symbol="m.super_len")
    changed = [r for r in plan.regions if "total +=" in r.source]
    assert changed and all(r.inside_delta is True and r.exercised for r in changed), plan.regions
    assert not plan.unexercised_outside


def test_empty_loop_iterable_and_false_while_and_except_never_mark_exercised():
    for hdr in ("    for _ in ():\n", "    while False:\n", "    try:\n        pass\n    except ValueError:\n"):
        pre = f"def f(x):\n{hdr}        y = 1\n    return x\n"
        post = f"def f(x):\n{hdr}        y = 2\n    return x\n"
        plan = df.region_plan(pre, post, "f", ["x"], [], symbol="m.f")
        assert plan.regions and all(not r.exercised for r in plan.regions), (hdr, plan.regions)
        assert plan.unexercised_outside, (hdr, plan.regions)


