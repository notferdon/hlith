"""Excluding the file of one source must not follow the operator to another source, and only that source's rail row says so."""
from dataclasses import replace

from hlith.operator.tui import frame, reduce
from hlith.operator.tui.model import ViewState

SOURCES = [{"g": "WORKTREE", "id": "u", "kind": "uncommitted", "label": "Uncommitted work", "meta": "1 file  +3 -0", "file": "a.py", "files": [("a.py", 3, 0)]},
           {"g": "COMMITS", "id": "commit:1", "kind": "commit", "label": "abc12345 Fix a thing", "meta": "1 file  +1 -1", "file": "b.py", "files": [("b.py", 1, 1)]}]
DIFF = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,2 @@\n x\n+y\n"


def _screen(vs):
    art = {"run": {}, "obligations": [], "effect": {"unified_diff": DIFF, "touched_files": ["a.py"]}}
    ctx = {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "sources": SOURCES,
           "change": {"label": "x", "file": "a.py", "added": 3, "removed": 0, "bytes": 10, "hunks": 1, "can_run": True}}
    return frame.render(vs, 100, 30, art, context=ctx).text_rows()


def test_the_exclusion_is_per_source():
    vs = ViewState(st="selection", cols=100, rows=30, focusIndex=0)
    vs = reduce.reduce(vs, "key:space")  # exclude the uncommitted file
    assert vs.excluded_sources == (0,)
    assert reduce.reduce(vs, "key:enter").st == "selection" and reduce.reduce(vs, "key:enter").toast  # its own source: refused with a reason
    moved = reduce.reduce(replace(vs, focusIndex=1), "key:enter")
    assert moved.st == "claim"  # another source is not affected
    assert reduce.reduce(reduce.reduce(vs, "key:space"), "key:enter").st == "claim"  # space again re-includes


def test_only_the_excluded_sources_own_row_says_so():
    vs = reduce.reduce(ViewState(st="selection", cols=100, rows=30, focusIndex=0), "key:space")
    text = "\n".join(_screen(vs))
    assert "[ ] Uncommitted work" in text and "[x] a.py" not in text and "[ ] a.py" in text
    assert "[ ] abc12345" not in text  # the commit source is not marked
    other = "\n".join(_screen(replace(vs, focusIndex=1)))
    assert "[ ] Uncommitted work" in other and "[ ] abc12345" not in other
