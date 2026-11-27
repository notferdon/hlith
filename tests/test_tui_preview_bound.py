"""A large diff must not turn the Selection screen into a PgDn wall: the preview is bounded to the room under the list and says how much it left out;
a short diff is shown whole (the reference's behaviour)."""
from hlith.operator.tui import frame
from hlith.operator.tui.model import ViewState


def _selection(diff_lines: int, cols=100, rows=30):
    body = "".join(f"+line {i}\n" for i in range(diff_lines))
    diff = f"diff --git a/big.txt b/big.txt\n--- a/big.txt\n+++ b/big.txt\n@@ -0,0 +1,{diff_lines} @@\n{body}"
    artifact = {"run": {}, "obligations": [], "effect": {"unified_diff": diff, "touched_files": ["big.txt"]}}
    context = {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."},
               "sources": [{"g": "WORKTREE", "id": "u", "label": "Uncommitted work", "meta": f"1 file +{diff_lines} -0", "file": "big.txt", "kind": "uncommitted"}],
               "change": {"label": "Uncommitted work", "file": "big.txt", "added": diff_lines, "removed": 0, "bytes": len(diff), "hunks": 1}}
    return frame.render(ViewState(st="selection", cols=cols, rows=rows), cols, rows, artifact, context=context).text_rows()


def test_a_large_diff_is_bounded_and_labelled():
    for cols, rows in ((100, 30), (160, 44)):
        text = _selection(400, cols, rows)
        assert any("more lines · d full diff" in r for r in text), (cols, rows)
        assert not any("↓ more" in r for r in text), (cols, rows)  # no scroll wall: the whole screen fits


def test_a_short_diff_is_shown_whole_without_a_note():
    text = _selection(8)
    assert not any("more lines" in r for r in text) and any("line 7" in r for r in text)
