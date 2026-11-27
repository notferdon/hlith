# SPDX-License-Identifier: Apache-2.0
"""The obsolete census (tests/obsolete_census.py) stays exact and bounded: every entry names a real test function in a real file, every
reason is a known one, and the census cannot grow into a blanket skip.

A public source snapshot or clean public clone omits documented source-only tests. An entry whose file is absent is accepted only
when that exact path is in the documented exclusion list in docs/STAGING-VIEW.md; a full source checkout (any documented excluded
file present) must contain every census file. Presence of `.git` alone does not establish the full source tree."""
import ast
from pathlib import Path

from obsolete_census import OBSOLETE, REASONS

ROOT = Path(__file__).resolve().parent.parent
MAX_ENTRIES = 80  # 2026-11-27: the census holds the observed obsolete tests only; raising this is a reviewed decision


def _documented_view_exclusions() -> set[str]:
    text = (ROOT / "docs" / "STAGING-VIEW.md").read_text(encoding="utf-8")
    block = text.split("<summary>Obsolete-census files omitted from this view</summary>", 1)[1].split("</details>", 1)[0]
    return {line.strip()[3:-1] for line in block.splitlines() if line.strip().startswith("- `tests/")}


def test_every_entry_names_a_real_test_function_and_a_known_reason():
    excluded_paths = _documented_view_exclusions()
    # A clean public clone has `.git` but not the source-only tests; the canonical tree does.
    full_source = any((ROOT / path).is_file() for path in excluded_paths)
    excluded = set() if full_source else excluded_paths
    checked = 0
    for nodeid, reason in OBSOLETE.items():
        assert reason in REASONS, (nodeid, reason)
        path, _, rest = nodeid.partition("::")
        assert path.startswith("tests/"), nodeid
        if not (ROOT / path).is_file():
            assert not full_source and path in excluded, f"names a missing file that is not a documented view exclusion: {nodeid}"
            continue
        checked += 1
        name = rest.split("[", 1)[0]
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        assert any(isinstance(n, ast.FunctionDef) and n.name == name for n in ast.walk(tree)), f"stale census entry: {nodeid}"
    assert checked > 0


def test_the_census_is_bounded_and_per_test():
    assert 0 < len(OBSOLETE) <= MAX_ENTRIES
    assert all("::" in nodeid and not nodeid.endswith(".py") for nodeid in OBSOLETE), "file-level entries would be blanket skips"
