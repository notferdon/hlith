# SPDX-License-Identifier: Apache-2.0
"""Targeted falsifier for design plan: compound module-level blocks must not cover untracked side effects."""

from __future__ import annotations

from pathlib import Path

from hlith.contract.effects import EffectAccount, ModifiedSymbol
from hlith.contract.identities import RunId, Sha256, TreeOid
from hlith.obligation.facts import uncovered_regions
from hlith.obligation.source import TreeIndex


def _acct(sym_line: int) -> EffectAccount:
    return EffectAccount(
        run_id=RunId("run-13"),
        base_tree_oid=TreeOid("b" * 40),
        patch_sha256=Sha256("p" * 64),
        post_tree_oid=TreeOid("t" * 40),
        analyzer_id="test-13",
        modified_constants=(ModifiedSymbol("m.X", "m.py", sym_line, "constant"),),
    )


def test_compound_module_blocks_do_not_cover_sibling_statements(tmp_path: Path) -> None:
    headers = [
        "if FLAG:",
        "for _i in [1]:",
        "while FLAG:",
        "with ctx():",
        "try:",
        "match FLAG:",
    ]
    for hdr in headers:
        case_dir = tmp_path / hdr.split()[0].rstrip(":")
        b = case_dir / "base"
        p = case_dir / "post"
        b.mkdir(parents=True)
        p.mkdir(parents=True)
        if hdr.startswith("match"):
            base_src = "FLAG = True\nCACHE = {}\nmatch FLAG:\n    case True:\n        X = 1\n"
            post_src = "FLAG = True\nCACHE = {}\nmatch FLAG:\n    case True:\n        X = 2\n        CACHE['evil'] = 999\n"
            sym_line = 5
        elif hdr.startswith("try"):
            base_src = "CACHE = {}\ntry:\n    X = 1\nexcept Exception:\n    pass\n"
            post_src = "CACHE = {}\ntry:\n    X = 2\n    CACHE['evil'] = 999\nexcept Exception:\n    pass\n"
            sym_line = 3
        else:
            base_src = f"FLAG = True\nCACHE = {{}}\n{hdr}\n    X = 1\n"
            post_src = f"FLAG = True\nCACHE = {{}}\n{hdr}\n    X = 2\n    CACHE['evil'] = 999\n"
            sym_line = 4
        (b / "m.py").write_text(base_src, encoding="utf-8")
        (p / "m.py").write_text(post_src, encoding="utf-8")
        got = uncovered_regions(_acct(sym_line), TreeIndex(b), TreeIndex(p), ("m.py",))
        assert any(c.kind == "uncovered_region" for c in got), f"{hdr} leaked sibling statement: {got!r}"


def test_multiline_simple_constant_remains_covered(tmp_path: Path) -> None:
    b = tmp_path / "base"
    p = tmp_path / "post"
    b.mkdir()
    p.mkdir()
    (b / "m.py").write_text("X = (\n    1,\n    2,\n)\n", encoding="utf-8")
    (p / "m.py").write_text("X = (\n    1,\n    99,\n)\n", encoding="utf-8")
    got = uncovered_regions(_acct(1), TreeIndex(b), TreeIndex(p), ("m.py",))
    assert got == [], f"unexpected uncovered region on multiline simple constant: {got!r}"
