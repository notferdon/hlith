# SPDX-License-Identifier: Apache-2.0
"""A changed module constant is verified through its readers (one differential each), never by absence."""
import subprocess

from hlith.derive import make_derive
from hlith.types import ProposedEffect, Verdict


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def _run(tmp_path, src, diff):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text(src)
    (repo / "tests").mkdir()  # a repository test that reaches f (an empty slice would be UNVERIFIED by policy)
    (repo / "tests" / "test_m.py").write_text("from m import f\n\n\ndef test_f():\n    assert f(1) is not None\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    eff = ProposedEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",))
    prop = tmp_path / "proposer"
    prop.mkdir()
    return make_derive(proposer_paths=[str(prop)])(repo, eff).obligations


READ = "LIMIT = 3\n\n\ndef f(x):\n    return x < LIMIT\n"
DIFF_READ = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,4 +1,4 @@\n-LIMIT = 3\n+LIMIT = 5\n \n \n def f(x):\n"

NO_READ = "LIMIT = 3\n\n\ndef f(x):\n    return x + 1\n"
DIFF_NO_READ = DIFF_READ


def test_changed_constant_is_refuted_through_the_reader_it_changes(tmp_path):
    obs = _run(tmp_path, READ, DIFF_READ)
    rd = [o for o in obs if o.obligation_id.startswith("differential:m.f") or o.obligation_id.endswith("m.f")]
    assert any(o.verdict is Verdict.REFUTED for o in obs), [(o.obligation_id, o.verdict.value) for o in obs]
    assert rd, [o.obligation_id for o in obs]


def test_changed_constant_with_no_reader_is_unverified_not_held(tmp_path):
    obs = _run(tmp_path, NO_READ, DIFF_NO_READ)
    unread = [o for o in obs if o.obligation_id.startswith("constant-unread:")]
    assert unread and unread[0].verdict is Verdict.UNVERIFIED
    assert not all(o.verdict is Verdict.HELD for o in obs)


CLS_SRC = "class C:\n    LIMIT = 3\n\n    def f(self, x):\n        return x < self.LIMIT\n"
CLS_DIFF = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,3 +1,3 @@\n class C:\n-    LIMIT = 3\n+    LIMIT = 5\n \n"


def test_changed_class_attribute_with_no_reader_or_unreached_is_never_held(tmp_path):
    """A class-body attribute edit is attributed (modified_class_attributes) and verified through its readers:
    it can never fall through as 'no callable modified' nor be HELD by absence."""
    obs = _run(tmp_path, CLS_SRC, CLS_DIFF)
    ids = [o.obligation_id for o in obs]
    assert not any(i == "no-callable" for i in ids), ids
    assert not all(o.verdict is Verdict.HELD for o in obs), [(o.obligation_id, o.verdict.value) for o in obs]
