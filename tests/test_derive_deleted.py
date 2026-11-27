# SPDX-License-Identifier: Apache-2.0
"""A deleted callable: still called => REFUTED with the surviving call site; unreferenced => never HELD by absence."""
import subprocess

from hlith.derive import make_derive
from hlith.types import ProposedEffect, Verdict


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def _repo(tmp_path, src):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text(src)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


STILL_CALLED = "def g(y):\n    return y * 2\n\n\ndef h(x):\n    return g(x) + 1\n"
DEL_G = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,6 +1,2 @@
-def g(y):
-    return y * 2
-
-
 def h(x):
     return g(x) + 1
"""
UNUSED = "def g(y):\n    return y * 2\n\n\ndef h(x):\n    return x + 1\n"
DEL_UNUSED = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,6 +1,2 @@
-def g(y):
-    return y * 2
-
-
 def h(x):
     return x + 1
"""


def _run(tmp_path, src, diff):
    repo = _repo(tmp_path, src)
    eff = ProposedEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",))
    return make_derive(proposer_paths=[])(repo, eff).obligations


def test_deleted_but_still_called_is_refuted_with_the_call_site(tmp_path):
    obs = _run(tmp_path, STILL_CALLED, DEL_G)
    refuted = [o for o in obs if o.obligation_id.startswith("deleted-still-called:")]
    assert refuted and refuted[0].verdict is Verdict.REFUTED
    assert "m.py" in refuted[0].witness and "still calls deleted m.g" in refuted[0].witness


def test_deleted_unreferenced_is_never_held_by_absence(tmp_path):
    obs = _run(tmp_path, UNUSED, DEL_UNUSED)
    unchecked = [o for o in obs if o.obligation_id.startswith("deleted-unchecked:")]
    assert unchecked and unchecked[0].verdict is Verdict.UNVERIFIED
    assert not all(o.verdict is Verdict.HELD for o in obs)
