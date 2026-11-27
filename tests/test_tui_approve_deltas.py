# SPDX-License-Identifier: Apache-2.0
"""TUI behavior 2.1 (D2): approving the engine's declared delta set from the terminal UI. The hash is the engine's own (never typed); the approval is bound to the verdict's own
patch, base and repository; the start gate refuses any plan that does not carry exactly that approval; nothing here starts a run."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from hlith.operator.tui import frame, host, launch

SHA = "ab" * 32
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
PATCH = b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return x + 1\n"
MANIFEST = json.dumps({"paths": {"a.py": {"change": "modified"}}}).encode()


@pytest.fixture()
def world(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["init", "-q", "-b", "main"],):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env={**os.environ, **ENV}, capture_output=True)
    (repo / "a.py").write_text("def f(x):\n    return x\n")
    for cmd in (["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env={**os.environ, **ENV}, capture_output=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    folder = tmp_path / "state" / "runs" / "launch-aaaaaaaaaaaa"
    (folder / "clone").mkdir(parents=True)
    (folder / "change.patch").write_bytes(PATCH)
    (folder / "claim.manifest.json").write_bytes(MANIFEST)
    artifact = {"exit_status": 12, "outcome": "refused", "run": {"run_id": "run-0123456789ab", "base_commit_sha": head},
                "effect": {"delta_set_sha256": SHA, "patch_sha256": hashlib.sha256(PATCH).hexdigest(),
                           "deltas": [{"path": "a.py", "symbol": "f", "kind": "return-value", "claim": "f(x) now returns x + 1"}]},
                "obligations": [{"id": "deltas-confirmed", "verdict": "unverified", "stop_reason": "delta claims have no independent confirmer (--approve-deltas SHA256 not given)"}],
                "blocking": ["deltas-confirmed"]}
    context = {"launch_meta": {"clone": str(folder / "clone"), "source_repo": str(repo)}, "repo": {"path": str(repo)}}
    return repo, folder, artifact, context, head


def test_candidate_needs_the_engines_own_hash_deltas_and_the_unconfirmed_reason(world):
    _r, _f, art, _c, _h = world
    assert frame._approval_candidate(art)[0] == SHA
    for mutate in (lambda a: a.update(exit_status=0), lambda a: a["effect"].update(deltas=[]), lambda a: a["effect"].update(delta_set_sha256="XYZ"),
                   lambda a: a["effect"].pop("delta_set_sha256"), lambda a: a["obligations"][0].update(stop_reason="some other cause")):
        bad = json.loads(json.dumps(art))
        mutate(bad)
        assert frame._approval_candidate(bad) is None


def test_the_claim_carries_exactly_the_engines_hash_and_binds_patch_and_manifest(world, tmp_path):
    repo, folder, art, ctx, head = world
    out = host._approval_claim_context(ctx, art, state=tmp_path / "state")
    assert out is not None
    argv = out["plan"].argv
    assert argv[argv.index("--approve-deltas") + 1] == SHA  # the engine's hash verbatim: no typed text exists
    assert argv[argv.index("--patch-sha256") + 1] == hashlib.sha256(PATCH).hexdigest()
    assert argv[argv.index("--manifest-sha256") + 1] == hashlib.sha256(MANIFEST).hexdigest()
    assert out["plan"].base_rev == head and out["plan"].clone != Path(ctx["launch_meta"]["clone"])  # a FRESH clone, never the refused run's
    assert SHA in out["change"]["note"] and "not proof" in out["change"]["note"] and "f(x) now returns x + 1" in out["change"]["note"]
    assert out["can_run"] is True and out["claim_command_seen"] is False and out["claim_dwell_satisfied"] is False  # the command review and dwell still apply
    assert host._claim_token(out)[0] == "approve"


@pytest.mark.parametrize("case", ["patch_altered", "patch_symlink", "other_repo", "no_base", "no_meta"])
def test_it_fails_closed(world, tmp_path, case):
    repo, folder, art, ctx, head = world
    if case == "patch_altered":
        (folder / "change.patch").write_bytes(PATCH + b"# tampered\n")
    elif case == "patch_symlink":
        real = tmp_path / "elsewhere.patch"
        real.write_bytes(PATCH)
        (folder / "change.patch").unlink()
        (folder / "change.patch").symlink_to(real)
    elif case == "other_repo":
        other = tmp_path / "other"
        other.mkdir()
        ctx = {**ctx, "repo": {"path": str(other)}}
    elif case == "no_base":
        art["run"].pop("base_commit_sha")
    elif case == "no_meta":
        ctx = {k: v for k, v in ctx.items() if k != "launch_meta"}
    assert host._approval_claim_context(ctx, art, state=tmp_path / "state") is None


def test_the_start_gate_refuses_a_plan_that_no_longer_carries_exactly_the_approval(world, tmp_path, monkeypatch):
    repo, folder, art, ctx, head = world
    started = []
    monkeypatch.setattr(launch, "start", lambda plan: started.append(plan) or {"run_id": "x"})
    out = {**host._approval_claim_context(ctx, art, state=tmp_path / "state"), "command_visible": True}  # as after the host painted the command row
    st = host.ViewState(st="claim")
    assert host._start_confirmed(out, state=st, events=["enter"], claim_shown=True) is not None and len(started) == 1  # control: the untouched claim starts
    tampered = out["plan"]
    i = tampered.argv.index("--approve-deltas")
    tampered.argv[i + 1] = "cd" * 32  # a different set than the one shown and approved
    assert host._start_confirmed(out, state=st, events=["enter"], claim_shown=True) is None and len(started) == 1
    tampered.argv[i + 1] = SHA
    tampered.patch_bytes = PATCH + b"# swapped\n"
    assert host._start_confirmed(out, state=st, events=["enter"], claim_shown=True) is None and len(started) == 1


def test_the_verdict_offers_i_and_the_advice_names_a_real_key(world):
    _r, _f, art, _c, _h = world
    decision = ("REFUSED · UNVERIFIED", "warn")
    text = frame._next_for_verdict(art, decision, None)
    assert "Press i" in text and "it is not proof" in text and "This result stands" in text
    assert "No key here can land, approve" not in text  # the old blanket claim is wrong once i exists; the approval still never overrides this result
    no_offer = json.loads(json.dumps(art))
    no_offer["effect"]["deltas"] = []
    assert "Press i" not in frame._next_for_verdict(no_offer, decision, None)
