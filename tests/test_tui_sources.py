# SPDX-License-Identifier: Apache-2.0
"""Source-kind navigation: Apply is offered only when the original's HEAD is the base the check ran on (a COMMIT source checks out the commit's PARENT, so the engine
would refuse 'HEAD moved'); the Claim shows the patch/manifest hashes it binds."""
from __future__ import annotations

import copy
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

from hlith.operator.tui import frame, host, launch

ROOT = Path(__file__).resolve().parent.parent
LANDED = ROOT / "tests/fixtures/landed_format2_between.json"
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
H, P = "a" * 40, "b" * 40
PATCH = b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return x + 1\n"


def _art():
    a = json.loads(LANDED.read_text())
    a["run"]["landing_target"] = "rehearsal"
    return a


def _ctx(base, head, label="Commit abc"):
    return {"launch_meta": {"clone": "/s/runs/launch-x/clone", "label": label, "base_rev": base}, "repo": {"head": head}}


def test_head_is_base_is_true_false_or_unknown():
    assert frame._head_is_base(_ctx(H, H)) is True
    assert frame._head_is_base(_ctx(H, H[:8])) is True  # a short HEAD still matches by prefix
    assert frame._head_is_base(_ctx(P, H)) is False  # a commit source: base is the PARENT, HEAD is the commit
    assert frame._head_is_base(_ctx(None, H)) is None and frame._head_is_base(_ctx(H, "not recorded")) is None and frame._head_is_base({}) is None


def test_apply_is_offered_only_when_head_is_the_base_or_unknown():
    art = _art()
    assert frame._apply_candidate(art, _ctx(H, H)) is True
    assert frame._apply_candidate(art, _ctx(P, H)) is False
    assert frame._apply_candidate(art, _ctx(None, H)) is True  # unknown: the engine's own review decides at the key


def test_a_commit_source_landing_says_why_apply_is_not_offered():
    text = frame._landed_next(art := _art(), _ctx(P, H))
    assert text.startswith("Your repository was NOT changed") and "Apply to the original is not offered" in text and "check it again from your current HEAD" in text
    assert "Press l" not in text and P[:8] in text
    assert "Press l to review applying it" in frame._landed_next(art, _ctx(H, H))


def test_the_claim_shows_the_patch_and_manifest_hashes_it_binds(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["init", "-q", "-b", "main"],):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env={**os.environ, **ENV}, capture_output=True)
    (repo / "a.py").write_text("def f(x):\n    return x\n")
    for cmd in (["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env={**os.environ, **ENV}, capture_output=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    plan = launch.plan(repo, patch_bytes=PATCH, manifest_obj={"paths": {"a.py": ["modify"]}}, base_rev=head, label="Uncommitted work", state=tmp_path / "state")
    argv = plan.argv
    ph, mh = argv[argv.index("--patch-sha256") + 1], argv[argv.index("--manifest-sha256") + 1]
    ctx = {**host._EMPTY, "plan": plan, "command": plan.display(), "command_visible": True, "can_run": True, "snapshot_taken_at": "12:00:00",
           "change": {"label": "Uncommitted work", "kind": "uncommitted", "file": "a.py", "added": 1, "removed": 1, "bytes": len(PATCH)}}
    text = host._render(replace(host.ViewState(st="claim"), cols=100, rows=36), {}, ctx, "plain")
    left = " ".join(" ".join(ln.split("│", 1)[0] for ln in text.splitlines()).split())
    assert f"patch sha256 {ph[:16]}" in left and f"manifest sha256 {mh[:16]}" in left
