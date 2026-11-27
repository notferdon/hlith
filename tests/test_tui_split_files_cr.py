"""A bare CR (or any non-\n separator) inside an ADDED line must never forge a file boundary in a patch-file source (review: '+safe()\rdiff --git a/package-lock.json ...' made the
code that lands in utils.py appear under a phantom lock file)."""
import pytest

from hlith.operator.tui import changes

BASE = b"diff --git a/utils.py b/utils.py\n--- a/utils.py\n+++ b/utils.py\n@@ -1,1 +1,4 @@\n a\n"


@pytest.mark.parametrize("sep", [b"\r", b"\x0b", b"\x0c", b"\x1c", b"\x85", " ".encode()])
def test_a_separator_before_diff_git_inside_an_added_line_keeps_one_file(sep):
    data = BASE + b"+safe()" + sep + b"diff --git a/package-lock.json b/package-lock.json\n+import os\n+os.system('EVIL')\n"
    files = changes._split_files(data)
    assert [p for p, _ in files] == ["utils.py"]
    assert files[0][1] == data and b"os.system('EVIL')" in files[0][1]


def test_a_real_second_file_is_still_split():
    data = BASE.replace(b"+1,4", b"+1,2") + b"+x\ndiff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1 +1,2 @@\n y\n+z\n"
    assert [p for p, _ in changes._split_files(data)] == ["utils.py", "b.py"]


@pytest.mark.parametrize("sep", [b"\r", b"\x0b", b"\x0c", b"\x1c", b"\x85", " ".encode()])
def test_the_patch_file_change_has_one_file_whose_count_equals_git_and_whose_page_shows_every_added_line(sep, tmp_path):
    import subprocess

    data = BASE + b"+safe()" + sep + b"diff --git a/package-lock.json b/package-lock.json\n+import os\n+os.system('EVIL')\n"
    numstat = subprocess.run(["git", "apply", "--numstat"], input=data, capture_output=True, check=True).stdout.decode().split()
    change = changes._patch_change("p", "abc", tmp_path / "x.patch", data)
    assert [f[0] for f in change.files] == ["utils.py"] == [numstat[2]]
    assert change.files[0][1] == int(numstat[0]) == 3  # the +count the TUI shows is git's own
    page, _more = change.page("utils.py")
    text = "\n".join(page)
    assert "os.system('EVIL')" in text and "import os" in text and "package-lock.json" in text  # every added line is on the page (the forged header is just text of the added line)


def test_a_header_after_a_crlf_inside_an_added_line_is_not_a_file_boundary(tmp_path):
    """'+x\\r\\ndiff --git a/lock b/lock' inside a hunk whose counts are not yet met: the hunk's own counts keep it body text; the patch is MALFORMED and refused."""
    data = b"diff --git a/utils.py b/utils.py\n--- a/utils.py\n+++ b/utils.py\n@@ -1,1 +1,4 @@\n a\n+safe()\r\ndiff --git a/package-lock.json b/package-lock.json\n+import os\n+os.system('EVIL')\n"
    files, malformed = changes._split_files_checked(data)
    assert [p for p, _ in files] == ["utils.py"] and malformed  # a CRLF is a real line end: git calls this patch corrupt, and so do we (no phantom file)
    change = changes._patch_change("p", "abc", tmp_path / "x.patch", data)
    assert change.problem and "malformed" in change.problem and [f[0] for f in change.files] == ["utils.py"]


def test_a_well_formed_two_file_patch_with_no_newline_marker_is_not_malformed():
    data = b"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -1 +1,2 @@\n z\n+w\n"
    files, malformed = changes._split_files_checked(data)
    assert [p for p, _ in files] == ["a", "b"] and malformed is None
