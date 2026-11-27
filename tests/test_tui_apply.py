# SPDX-License-Identifier: Apache-2.0
"""TUI behavior 2.3 (D1, maintainer-locked): applying a LANDED rehearsal to the ORIGINAL repository from the terminal UI. The engine's own read-only review is shown in full, the token
is the engine's, the confirm is an explicit `y` (Enter never writes the operator's repository), and a refusal is rendered with its named reason. The engine process is replaced by the
exact output format of `engine_cli apply` (review lines on stdout, exit 2 / 4); nothing here starts a real run."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.operator.tui import frame, host, launch

ROOT = Path(__file__).resolve().parent.parent
LANDED = ROOT / "tests/fixtures/landed_format2_between.json"
PATCH = b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return x + 1\n"
TOKEN = "0123456789abcdef"
BASE = "b" * 40
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}


def _review_text(patch_sha, token=TOKEN, repo="/r"):
    return "\n".join(["hlith: apply review (nothing is written until --confirm matches)",
                      f"  target repository : {repo}", f"  base commit       : {BASE} (HEAD matches, tree clean)",
                      f"  patch sha256      : {patch_sha}", "  rehearsal         : run-4ffbd575159a landed 1111111111 (post tree aaaaaaaaaaaa)",
                      "  files             : a.py", f"  apply token       : {token}"]) + "\n"


def _stub(monkeypatch, returncode, stdout, stderr, calls=None):
    """Replace ONLY the engine_cli apply process (git and everything else keeps the real subprocess.run)."""
    real = subprocess.run

    def fake(argv, *a, **kw):
        if isinstance(argv, (list, tuple)) and "hlith.operator.engine_cli" in argv and "apply" in argv:
            if calls is not None:
                calls.append(list(argv))
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
        return real(argv, *a, **kw)
    monkeypatch.setattr(subprocess, "run", fake)


@pytest.fixture()
def world(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, env={**os.environ, **ENV}, capture_output=True)
    folder = tmp_path / "state" / "runs" / "launch-aaaaaaaaaaaa"
    (folder / "clone").mkdir(parents=True)
    (folder / "change.patch").write_bytes(PATCH)
    (folder / "claim.manifest.json").write_bytes(b'{"paths": {}}')
    art = json.loads(LANDED.read_text())
    art["run"]["landing_target"] = "rehearsal"
    (folder / "out.json").write_text(json.dumps(art))
    ctx = {"launch_meta": {"clone": str(folder / "clone"), "source_repo": str(repo)}, "repo": {"path": str(repo)}}
    calls = []
    _stub(monkeypatch, 2, _review_text(hashlib.sha256(PATCH).hexdigest(), repo=str(repo)), "hlith: review only", calls)
    return repo, folder, art, ctx, calls


def test_apply_is_offered_only_on_a_landed_rehearsal_with_a_known_run_folder(world):
    _r, _f, art, ctx, _c = world
    assert frame._apply_candidate(art, ctx) is True
    for bad in ({**ctx, "launch_meta": {}}, {k: v for k, v in ctx.items() if k != "launch_meta"}):
        assert frame._apply_candidate(art, bad) is False
    for mutate in (lambda a: a["run"].update(landing_target="original"), lambda a: a["run"].pop("landing_target"), lambda a: a.update(outcome="refused"),
                   lambda a: a.update(exit_status=10), lambda a: a.pop("landed_commit")):
        other = copy.deepcopy(art)
        mutate(other)
        assert frame._apply_candidate(other, ctx) is False


def test_the_claim_runs_the_read_only_review_and_the_plan_carries_the_engines_token(world, tmp_path):
    repo, folder, art, ctx, calls = world
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is not None and why == ""
    assert "--confirm" not in calls[0] and calls[0][calls[0].index("apply")] == "apply"  # the review step writes nothing: no --confirm, no --artifact-out
    argv = out["plan"].argv
    assert argv[argv.index("--confirm") + 1] == TOKEN and argv[argv.index("--repo") + 1] == str(repo.resolve())  # the ORIGINAL repository, the engine's token
    assert argv[argv.index("--rehearsal-artifact") + 1] == str(folder / "out.json") and argv[argv.index("--patch") + 1] == str(folder / "change.patch")
    assert out["claim_apply"]["review"]["base"] == BASE and out["claim_apply"]["review"]["patch"] == hashlib.sha256(PATCH).hexdigest()
    assert out["can_run"] is True and out["claim_command_seen"] is False and out["claim_dwell_satisfied"] is False  # command review and dwell still apply
    assert host._claim_token(out)[0] == "apply"


def test_the_apply_claim_shows_the_review_in_full_and_never_says_clone_only(world, tmp_path):
    repo, folder, art, ctx, _c = world
    out, _why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    text = host._render(replace(host.ViewState(st="claim"), cols=100, rows=48), art, {**out, "command_visible": True}, "plain")
    left = " ".join(" ".join(ln.split("│", 1)[0] for ln in text.splitlines()).split())  # main column
    right = " ".join(" ".join(ln.split("│", 1)[1] for ln in text.splitlines() if "│" in ln).split())  # inspector column (wrapped sentences read as one)
    assert "APPLY TO YOUR REPOSITORY" in left and TOKEN in left and BASE in left and hashlib.sha256(PATCH).hexdigest()[:20] in left
    assert "Press y to apply" in left and "Enter does not apply" in left
    assert "commits the checked change to YOUR repository" in right and "lands in the clone only" not in left + right


@pytest.mark.parametrize("case", ["engine_refusal", "bad_exit", "garbled", "patch_differs", "wrong_repo", "missing_file", "not_candidate"])
def test_it_fails_closed_with_the_named_reason(world, tmp_path, monkeypatch, case):
    repo, folder, art, ctx, _c = world
    sha = hashlib.sha256(PATCH).hexdigest()
    if case == "engine_refusal":
        _stub(monkeypatch, 4, "", "hlith: boundary: HEAD moved: not the rehearsed base commit\n")
        out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
        assert out is None and "moved since the rehearsal" in why  # the engine's named refusal reaches the operator as its next action
        return
    if case == "bad_exit":
        _stub(monkeypatch, 0, _review_text(sha), "")  # exit 0 is NOT a review
    elif case == "garbled":
        _stub(monkeypatch, 2, _review_text(sha, token="zz"), "")
    elif case == "patch_differs":
        _stub(monkeypatch, 2, _review_text("c" * 64), "")
    elif case == "wrong_repo":
        other = tmp_path / "other"
        other.mkdir()
        ctx = {**ctx, "repo": {"path": str(other)}}
    elif case == "missing_file":
        (folder / "claim.manifest.json").unlink()
    elif case == "not_candidate":
        art = {**art, "outcome": "refused"}
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is None and why


def test_enter_never_applies_and_only_an_explicit_y_does_and_a_tampered_plan_is_refused(world, tmp_path, monkeypatch):
    repo, folder, art, ctx, _c = world
    started = []
    monkeypatch.setattr(launch, "start", lambda plan: started.append(plan) or {"run_id": "x"})
    out = {**host._apply_claim_context(ctx, art, state=tmp_path / "state")[0], "command_visible": True}
    st = host.ViewState(st="claim")
    assert host._start_confirmed(out, state=st, events=["enter"], claim_shown=True) is None and not started  # Enter does not write the operator's repository
    assert host._start_confirmed(out, state=st, events=["y"], claim_shown=True) is not None and len(started) == 1  # control: an explicit y does
    plan = out["plan"]
    i = plan.argv.index("--confirm")
    plan.argv[i + 1] = "f" * 16
    assert host._start_confirmed(out, state=st, events=["y"], claim_shown=True) is None and len(started) == 1
    plan.argv[i + 1] = TOKEN
    j = plan.argv.index("--repo")
    plan.argv[j + 1] = str(tmp_path / "somewhere-else")
    assert host._start_confirmed(out, state=st, events=["y"], claim_shown=True) is None and len(started) == 1


def test_the_landed_next_text_offers_apply_only_when_it_exists(world):
    _r, _f, art, ctx, _c = world
    with_apply = frame._landed_next(art, ctx)
    assert with_apply.startswith("Your repository was NOT changed") and "Press l to review applying it" in with_apply and "confirm with y" in with_apply
    assert "Hlith does not write your repository" not in with_apply
    no_run_folder = frame._landed_next(art, None)
    assert "Press l to review" not in no_run_folder and "open this run from the Hlith session that made it" in no_run_folder


def test_apply_is_not_offered_for_an_uncommitted_work_rehearsal_and_the_text_says_why(world):
    _r, _f, art, ctx, _c = world
    dirty = {**ctx, "launch_meta": {**ctx["launch_meta"], "label": "Uncommitted work (tracked edits and new files)"}}
    assert frame._apply_candidate(art, dirty) is False
    text = frame._landed_next(art, dirty)
    assert "already in your working tree" in text and "not offered for uncommitted work" in text and "Commit it yourself" in text
    assert "Press l" not in text
    clean = {**ctx, "launch_meta": {**ctx["launch_meta"], "label": "Commit 1234abcd"}}  # another source kind keeps the Apply offer
    assert frame._apply_candidate(art, clean) is True


def test_a_clean_tree_refusal_gives_the_next_action_not_a_truncated_engine_line(world, tmp_path, monkeypatch):
    _r, _f, art, ctx, _c = world
    _stub(monkeypatch, 4, "", "hlith: boundary: apply: the repository has uncommitted changes to tracked files; apply needs a clean tree\n")
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is None and "commit or stash your tracked changes" in why and "press l again" in why
    _stub(monkeypatch, 4, "", "hlith: boundary: apply: HEAD moved: not the rehearsed base commit\n")
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is None and "check the change again on the current HEAD" in why


def test_the_apply_claim_header_counts_the_patch_and_labels_do_not_run_into_values(world, tmp_path):
    """Found in the real PTY trace: the header said '+0 -0 patch 0 B' and 'patch sha256<hash>' ran together."""
    _r, _f, art, ctx, _c = world
    out, _why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert (out["change"]["added"], out["change"]["removed"], out["change"]["bytes"]) == (1, 1, len(PATCH))
    text = host._render(replace(host.ViewState(st="claim"), cols=100, rows=48), art, {**out, "command_visible": True}, "plain")
    left = " ".join(" ".join(ln.split("│", 1)[0] for ln in text.splitlines()).split())
    assert "+1 −1" in left and f"patch sha256 {hashlib.sha256(PATCH).hexdigest()[:16]}" in left


def test_an_apply_whose_result_cannot_be_read_never_says_nothing_was_changed():
    """Found in the real PTY trace: the apply LANDED on the original but the TUI showed ARTIFACT UNAVAILABLE ('Nothing was changed') because the apply run writes no engine run link."""
    ctx = {"launch_meta": {"label": "apply to your repository · run-x", "clone": "/s/runs/launch-abc/clone"}}
    text = " ".join(" ".join(r) if isinstance(r, list) else str(r) for r in [[getattr(seg, "text", str(seg)) for seg in row] for row in frame._artifact_unavailable_body(ctx, 100)])
    assert "may have been changed" in text.lower() and "Nothing was changed" not in text and "git log" in text
    plain = " ".join(" ".join(getattr(seg, "text", str(seg)) for seg in row) for row in frame._artifact_unavailable_body({}, 100))
    assert "Nothing was changed" in plain  # every other run keeps its text


def test_the_apply_plan_carries_the_engine_run_link_so_the_verdict_can_be_authenticated(world, tmp_path):
    _r, _f, art, ctx, calls = world
    out, _why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    argv = out["plan"].argv
    assert argv[argv.index("--run-link") + 1] == str(out["plan"].run_dir / "engine-run.json")  # the file launch.result() authenticates the artifact against
    assert "--run-link" not in calls[0]  # the READ-ONLY review writes nothing, so it carries no link


def test_the_quit_dialog_on_an_original_landing_does_not_say_the_repository_is_unchanged():
    """Found in the post-fix PTY trace: after the apply LANDED on the original, the quit dialog said 'Your repository is unchanged.'"""
    art = json.loads(LANDED.read_text())
    art["run"]["landing_target"] = "original"
    host_state = replace(host.ViewState(st="verdict", overlay="exit"), cols=100, rows=40)
    text = " ".join(host._render(host_state, art, host._artifact_context(art), "plain").split())
    assert "Your repository is unchanged" not in text and "landing)" in text  # the dialog box wraps the new sentence across rows, so only stable fragments are asserted
    art["run"]["landing_target"] = "rehearsal"
    text = " ".join(host._render(host_state, art, host._artifact_context(art), "plain").split())
    assert "Your repository is unchanged" in text  # a rehearsal landing really leaves it unchanged


def _review_p1(patch_sha, manifest, deltas):
    """The P1 engine review: the two extra lines ('manifest sha256', 'approved delta set')."""
    return _review_text(patch_sha).replace("  apply token", f"  manifest sha256   : {manifest}\n  approved delta set: {deltas}\n  apply token")


def test_the_apply_claim_shows_the_manifest_hash_and_the_approved_delta_set_in_full(world, tmp_path, monkeypatch):
    repo, folder, art, ctx, _c = world
    msha, dset = hashlib.sha256((folder / "claim.manifest.json").read_bytes()).hexdigest(), "e" * 64
    _stub(monkeypatch, 2, _review_p1(hashlib.sha256(PATCH).hexdigest(), msha, dset), "hlith: review only")
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is not None, why
    assert out["claim_apply"]["review"]["manifest"] == msha and out["claim_apply"]["review"]["deltas"] == dset
    text = host._render(replace(host.ViewState(st="claim"), cols=100, rows=60), art, {**out, "command_visible": True}, "plain")
    left = " ".join(" ".join(ln.split("│", 1)[0] for ln in text.splitlines()).split())
    squeezed = left.replace(" ", "")  # the long values wrap across rows: compare without the wrapping spaces
    assert "manifest sha256" in left and "approved delta set" in left and msha in squeezed and dset in squeezed  # both shown IN FULL


def test_a_delta_free_rehearsal_shows_the_engines_own_words(world, tmp_path, monkeypatch):
    repo, folder, art, ctx, _c = world
    msha = hashlib.sha256((folder / "claim.manifest.json").read_bytes()).hexdigest()
    _stub(monkeypatch, 2, _review_p1(hashlib.sha256(PATCH).hexdigest(), msha, "none (no declared deltas)"), "")
    out, _why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    text = host._render(replace(host.ViewState(st="claim"), cols=100, rows=60), art, {**out, "command_visible": True}, "plain")
    left = " ".join(" ".join(ln.split("│", 1)[0] for ln in text.splitlines()).split())
    assert "none (no declared deltas)" in left


def test_a_reviewed_manifest_that_is_not_this_runs_manifest_is_refused(world, tmp_path, monkeypatch):
    repo, folder, art, ctx, _c = world
    _stub(monkeypatch, 2, _review_p1(hashlib.sha256(PATCH).hexdigest(), "c" * 64, "none (no declared deltas)"), "")
    out, why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    assert out is None and "manifest is not the rehearsal's own" in why


def test_the_plan_still_passes_the_runs_manifest_to_apply(world, tmp_path):
    repo, folder, art, ctx, calls = world
    out, _why = host._apply_claim_context(ctx, art, state=tmp_path / "state")
    argv = out["plan"].argv
    assert argv[argv.index("--manifest") + 1] == str(folder / "claim.manifest.json")  # the engine binds THIS manifest into the token
