"""git's hunk grammar in the patch-file parser: a line git ignores or refuses must never be shown as a change (the reviewer would see a removal that will not happen),
and everything git emits legitimately (zero counts, a second hunk, a second file, '\\ No newline', the format-patch signature) must still parse with git's own counts."""
import subprocess

import pytest

from hlith.operator.tui import changes

HDR = b"diff --git a/utils.py b/utils.py\n--- a/utils.py\n+++ b/utils.py\n"


def _numstat(data):
    r = subprocess.run(["git", "apply", "--numstat"], input=data, capture_output=True)
    return r.returncode, r.stdout.decode().split()


def _change(data, tmp_path):
    return changes._patch_change("p", "abc", tmp_path / "x.patch", data)


# ---- refused: each is a case git refuses or silently ignores
REFUSED = {
    "trailing deletion after a complete hunk (git ignores it)": HDR + b"@@ -1,2 +1,2 @@\n a = 1\n-b = 2\n+b = 3\n-os.system('x')\n",
    "extra + after the hunk completes, at EOF": HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n+hidden()\n",
    "extra + after the hunk completes, before a 2nd file": HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n+hidden()\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -1 +1,2 @@\n y\n+z\n",
    "negative count": HDR + b"@@ -1,1 +1,-5 @@\n a\n+evil()\n",
    "zero new count with an added line": HDR + b"@@ -1,1 +1,0 @@\n a\n+evil()\n",
    "a + with the new side exhausted inside the hunk": HDR + b"@@ -1,2 +1,1 @@\n a\n+x\n-b\n+y\n",
    "a - with the old side exhausted inside the hunk": HDR + b"@@ -1,1 +1,3 @@\n-a\n+x\n+y\n-z\n",
    "a hunk that is cut short": HDR + b"@@ -1,3 +1,3 @@\n a\n",
}


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_a_mismatch_is_refused_as_malformed(name, tmp_path):
    change = _change(REFUSED[name], tmp_path)
    assert change.problem and "malformed" in change.problem, (name, change.problem, change.files)


# ---- accepted: positive controls, counts equal git's numstat
ACCEPTED = {
    "new file (-0,0)": b"diff --git a/n b/n\nnew file mode 100644\n--- /dev/null\n+++ b/n\n@@ -0,0 +1,3 @@\n+a\n+b\n+c\n",
    "file deletion (+0,0)": b"diff --git a/n b/n\ndeleted file mode 100644\n--- a/n\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n-b\n-c\n",
    "pure insertion (-5,0)": HDR + b"@@ -5,0 +6,2 @@\n+x\n+y\n",
    "pure deletion (+2,0)": HDR + b"@@ -3,2 +2,0 @@\n-x\n-y\n",
    "a real second hunk": HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n@@ -9,1 +10,2 @@\n z\n+w\n",
    "a real second file": HDR + b"@@ -1,1 +1,2 @@\n a\n+x\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -1 +1,2 @@\n y\n+z\n",
    "no-newline markers": HDR + b"@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\n",
    "format-patch signature": HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n-- \n2.43.0\n\n",
}


@pytest.mark.parametrize("name", sorted(ACCEPTED))
def test_what_git_emits_still_parses_with_gits_counts(name, tmp_path):
    data = ACCEPTED[name]
    change = _change(data, tmp_path)
    assert not change.problem, (name, change.problem)
    rc, numstat = _numstat(data)
    if rc == 0:  # git's own count for the same bytes
        added = sum(f[1] or 0 for f in change.files)
        deleted = sum(f[2] or 0 for f in change.files)
        assert (added, deleted) == (sum(int(x) for x in numstat[0::3]), sum(int(x) for x in numstat[1::3])), (name, change.files, numstat)


def test_an_oversize_patch_file_is_refused_before_it_is_parsed(tmp_path, monkeypatch):
    parsed = []
    monkeypatch.setattr(changes, "_split_files_checked", lambda d: parsed.append(1) or ([], None))
    monkeypatch.setattr(changes, "MAX_PATCH", 1000)
    change = _change(HDR + b"@@ -1,1 +1,2 @@\n a\n+" + b"x" * 2000 + b"\n", tmp_path)
    assert change.oversize and change.problem and "limit" in change.problem and not parsed


# ---- the '-- ' signature never ends parsing: whatever git applies after it, the reviewer must see (or the patch is refused)
SIG_CASES = {
    "signature then a real second file": HDR + b"@@ -1,1 +1,2 @@\n a\n+c = 3\n-- \ndiff --git a/other.py b/other.py\n--- a/other.py\n+++ b/other.py\n@@ -1 +1,2 @@\n x\n+y = 2\n",
    "format-patch version line then a real second file": HDR + b"@@ -1,1 +1,2 @@\n a\n+c = 3\n-- \n2.43.0\n\ndiff --git a/other.py b/other.py\n--- a/other.py\n+++ b/other.py\n@@ -1 +1,2 @@\n x\n+y = 2\n",
    "signature then a second hunk of the same file": HDR + b"@@ -1,1 +1,2 @@\n a\n+c = 3\n-- \n@@ -9,1 +10,2 @@\n z\n+hidden = 1\n",
}


@pytest.mark.parametrize("name", sorted(SIG_CASES))
def test_nothing_after_the_signature_is_hidden_from_the_reviewer(name, tmp_path):
    data = SIG_CASES[name]
    change = _change(data, tmp_path)
    rc, numstat = _numstat(data)
    if change.problem:
        assert "malformed" in change.problem  # refusing is acceptable
        return
    shown = sum(f[1] or 0 for f in change.files)
    if rc == 0:  # git applies these: every added line git applies must be in the TUI's list
        assert shown == sum(int(x) for x in numstat[0::3]), (name, change.files, numstat)
    # and the second file / hunk text is in the pages the reviewer reads
    text = "\n".join(line for f in change.files for line in change.page(f[0])[0])
    assert ("y = 2" in text) if "second file" in name else ("hidden = 1" in text if "second hunk" in name else True), (name, change.files)


def test_a_genuine_format_patch_signature_with_no_later_content_still_parses(tmp_path):
    data = HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n-- \n2.43.0\n\n"
    change = _change(data, tmp_path)
    assert not change.problem and change.files == [("utils.py", 1, 0)]


def test_a_hunk_after_the_signature_is_refused_like_git(tmp_path):
    data = SIG_CASES["signature then a second hunk of the same file"]
    assert _numstat(data)[0] != 0  # git: patch fragment without header
    change = _change(data, tmp_path)
    assert change.problem and "malformed" in change.problem


def test_plain_text_after_the_signature_is_ignored_exactly_as_git_ignores_it(tmp_path):
    data = HDR + b"@@ -1,1 +1,2 @@\n a\n+x\n-- \n+evil()\n2.43.0\n"
    rc, numstat = _numstat(data)
    change = _change(data, tmp_path)
    assert rc == 0 and numstat[:2] == ["1", "0"]  # git: one added line, the '+evil()' is signature text
    assert not change.problem and change.files == [("utils.py", 1, 0)]
