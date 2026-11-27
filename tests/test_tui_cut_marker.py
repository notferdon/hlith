"""design and adversarial review-ellipsis (case): the right-edge cut marker '…' appears ONLY where visible (non-blank) text was actually cut.
A line whose overflow is only trailing blanks gets no marker; a line with visible text beyond the width gets exactly one."""
from hlith.operator.tui import frame
from hlith.operator.tui.frame import fit, fs, s


def _flat(segs):
    return "".join(g.text for g in segs)


def test_fit_and_fs_add_no_marker_when_only_blanks_overflow():
    assert _flat(fit([s("abc" + " " * 50)], 10)) == "abc       "
    assert "…" not in _flat(fit([s("abc"), s(" " * 50)], 10))
    assert fs("abc" + " " * 50, 10) == "abc       "


def test_fit_and_fs_add_exactly_one_marker_when_visible_text_is_cut():
    row = _flat(fit([s("abc" + " " * 20 + "VISIBLE")], 10))
    assert row.count("…") == 1 and row.endswith("…") and len(row) == 10
    cut = fs("abc" + " " * 20 + "VISIBLE", 10)
    assert cut.count("…") == 1 and len(cut) == 10
    assert _flat(fit([s("x" * 40)], 10)).count("…") == 1  # an ordinary long word is still marked


def _art(diff):
    return {"effect": {"unified_diff": diff, "touched_files": ["a.txt"]}, "obligations": [], "run": {}}


def test_diff_preview_rows_mark_only_real_cuts():
    blank_tail = "+x" + " " * 300  # '+' then only blanks past the width
    far_text = "+y" + " " * 120 + "RIGHT-ALIGNED"  # visible text far to the right
    patch = ("diff --git a/a.txt b/a.txt\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/a.txt\n"
             f"@@ -0,0 +1,3 @@\n{blank_tail}\n{far_text}\n+z\n")
    rows = ["".join(g.text for g in line) for line in frame._diff_lines(_art(patch), 60, head=False, limit=0)]
    blank = next(r for r in rows if "x" in r and "+" in r)
    far = next(r for r in rows if "y" in r)
    assert "…" not in blank, blank  # only blanks overflowed
    assert far.count("…") == 1, far  # visible text was cut
    assert "…" not in next(r for r in rows if r.rstrip().endswith("z"))
