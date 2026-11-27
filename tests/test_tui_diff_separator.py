# SPDX-License-Identifier: Apache-2.0
"""case (review): RED test-only attack on the diff page. Kept apart from the Claim/PgDn gate file so that file stays green."""

from __future__ import annotations

import pytest

from hlith.operator.tui import frame


@pytest.mark.parametrize("sep", ["\u2028", "\r", "\x0b", "\x0c", "\x85", "\x1c"])
def test_RED_diff_page_never_hides_text_after_a_line_separator_character(sep):
    """RED on 86580916: _diff_lines uses str.splitlines(), which also splits on U+2028, CR, VT, FF, NEL, FS. The part after the separator loses its
    '+' prefix and is dropped, so a reviewer of the diff page never sees `os.system('EVIL')` that the patch really adds (counts still say +2)."""
    patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n a=1\n+safe()" + sep + "import os; os.system('EVIL')\n"
    rows = frame._diff_lines({"effect": {"unified_diff": patch}}, 100)
    assert "EVIL" in " ".join(str(r) for r in rows), f"text after {sep!r} is hidden from the diff page"


def test_negative_control_the_same_patch_with_a_plain_space_shows_the_text():
    patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n a=1\n+safe() import os; os.system('EVIL')\n"
    rows = frame._diff_lines({"effect": {"unified_diff": patch}}, 100)
    assert "EVIL" in " ".join(str(r) for r in rows)
