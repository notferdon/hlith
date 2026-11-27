# SPDX-License-Identifier: Apache-2.0
"""review seam: external seeds can carry bytes as {"__hlith_bytes__": "<hex>"} (top level, nested in list / dict /
{"__hlith_tuple__"}), revived to real bytes in the evaluator on BOTH sides.

Predeclared: `f(o: bytes)` differs between base and post ONLY for len(o) > 1500, a region the explored inputs do not
reach; the seed of 2000 bytes must therefore REFUTE (witness names the 2000-byte value by digest or length), the same
run without the seed must NOT refute (so the seed is what matters), a nested seed reaches f as bytes, and malformed /
oversize tags are named coverage loss (never silently dropped, never revived)."""

from hlith import differential
from hlith.types import Verdict

_BASE = "def f(o: bytes) -> int:\n    return len(o)\n"
_POST = "def f(o: bytes) -> int:\n    return len(o) if len(o) <= 1500 else 0\n"
_NESTED_BASE = "def f(o) -> int:\n    return len(o[0][1]['k'])\n"
_NESTED_POST = "def f(o) -> int:\n    return len(o[0][1]['k']) if len(o[0][1]['k']) <= 1500 else 0\n"


def _world(tmp_path, base, post):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
    (tmp_path / "proposer").mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
                proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=60,
                max_examples=10)


def test_bytes_seed_reaches_both_sides_and_refutes(tmp_path):
    seed = ([{"__hlith_bytes__": "61" * 2000}], {}, "n5-seed")
    ob = differential.run_differential(**_world(tmp_path, _BASE, _POST), seeds=[seed])
    assert ob.verdict is Verdict.REFUTED, ob
    assert "2000" in ob.witness or "0x" in ob.witness or "61" in ob.witness, ob.witness


def test_without_the_seed_nothing_refutes(tmp_path):
    ob = differential.run_differential(**_world(tmp_path, _BASE, _POST))
    assert ob.verdict is not Verdict.REFUTED, ob  # precondition: the explored inputs do not reach len > 1500


def test_nested_bytes_in_list_dict_tuple(tmp_path):
    big = {"__hlith_bytes__": "62" * 2000}
    seed = ([{"__hlith_tuple__": [[0, {"k": big}]]}], {}, "n5-seed")
    ob = differential.run_differential(**_world(tmp_path, _NESTED_BASE, _NESTED_POST), seeds=[seed])
    assert ob.verdict is Verdict.REFUTED, ob


def test_malformed_and_oversize_tags_are_named_loss(tmp_path):
    ok, loss = differential._external_seeds([
        ([{"__hlith_bytes__": "zz"}], {}, "bad-hex"),
        ([{"__hlith_bytes__": "6"}], {}, "odd-hex"),
        ([{"__hlith_bytes__": "61" * 40000}], {}, "oversize"),
        ([{"__hlith_bytes__": "61", "x": 1}], {}, "extra-key"),
        ([[{"__hlith_bytes__": "6162"}]], {}, "fine"),
    ])
    assert [s[2] for s in ok] == ["fine"], ok
    assert len(loss) == 4 and all("not concretizable" in x for x in loss), loss
