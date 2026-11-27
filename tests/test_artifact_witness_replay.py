"""A refused run's artifact carries what a standalone replay needs: obligations[i].witness_call (verbatim differential witness) + run.replay_context.
Proof that the recorded fields SUFFICE: the stored witness is replayed from the artifact alone against two reconstructed trees and REPRODUCES (base vs post differ)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

from hlith import differential

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("_f1_cli", _HERE / "test_feedback_f1_cli_cross_process_case2.py")
f1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(f1)


def test_refused_artifact_carries_a_replayable_witness(tmp_path):
    src = f1._source(tmp_path / "source")
    repo = f1._clone(src, tmp_path / "r1")
    rc, art, log = f1._cli(tmp_path, "r1", repo, f1.RUN1, tmp_path / "state")
    assert rc == 10 and art.get("outcome") == "refused", (rc, log)

    refuted = [o for o in art["obligations"] if o["verdict"] == "refuted"]
    assert refuted, art["obligations"]
    row = next(o for o in refuted if o.get("witness_call"))
    wc = row["witness_call"]
    assert wc.get("qualname") and wc.get("module") and "truncated" not in wc, wc  # a real, replayable call (not the over-cap digest form)

    ctx = art["run"]["replay_context"]
    import hashlib
    kept = list((tmp_path / "state").glob("repositories/*/runs/*/change.patch"))  # the durable run dir keeps the exact patch bytes (replay_context.patch.ref)
    assert len(kept) == 1 and hashlib.sha256(kept[0].read_bytes()).hexdigest() == ctx["patch"]["sha256"], (kept, ctx["patch"])
    assert ctx["base"]["commit"] == art["run"]["base_commit_sha"] and ctx["base"]["tree_oid"] == art["run"]["base_tree_oid"]
    assert ctx["patch"]["sha256"] == art["effect"]["patch_sha256"] and ctx["patch"]["ref"] == "change.patch"
    assert ctx["target_python"] and ctx["target_python"]["observed_in"] == "confined-differential-worker"

    # rebuild the two trees from the RECORDED fields only: base = the base commit's files, post = base + the patch
    base_root = tmp_path / "base"
    subprocess.run(["git", "clone", "-q", str(src), str(base_root)], check=True)
    subprocess.run(["git", "-C", str(base_root), "checkout", "-q", ctx["base"]["commit"]], check=True)
    post_root = tmp_path / "post"
    shutil.copytree(base_root, post_root)
    patch = art["effect"]["unified_diff"]
    subprocess.run(["git", "-C", str(post_root), "apply", "-"], input=patch.encode(), check=True)

    import_root = ctx["import_root"]
    res = differential.replay_witness(wc, str(base_root), str(post_root), import_root=import_root if import_root else "",
                                      extra_sys_path=tuple(ctx["extra_sys_path"]), python=ctx["target_python"]["executable"])
    assert res["replayable"] and res["reproduced"], res


def test_cli_replays_the_cross_process_recorded_obligation(tmp_path, monkeypatch, capsys):
    """The operator command resolves and replays the same durable cross-process run."""
    src = f1._source(tmp_path / "source")
    repo = f1._clone(src, tmp_path / "r1")
    state = tmp_path / "state"
    rc, art, log = f1._cli(tmp_path, "r1", repo, f1.RUN1, state)
    assert rc == 10 and art.get("outcome") == "refused", (rc, log)
    row = next(o for o in art["obligations"] if o.get("witness_call") and o.get("verdict") == "refuted")
    run_dir = next(state.glob(f"repositories/*/runs/{art['run']['run_id']}"))

    # A HOME override can make the recorded venv visible through a symlinked
    # parent (as in the maintainer walkthrough launcher). The replay must keep
    # using that venv while granting its canonical path to the confined worker.
    recorded_python = Path(art["run"]["replay_context"]["target_python"]["executable"])
    recorded_venv = recorded_python.parent.parent
    alias_venv = tmp_path / "recorded-home/.local/share/hlith/candidates/RC_FINAL/.venv"
    alias_venv.parent.mkdir(parents=True)
    alias_venv.symlink_to(recorded_venv, target_is_directory=True)
    alias_python = alias_venv / "bin" / recorded_python.name
    assert alias_python.is_file() and alias_venv.is_symlink()
    artifact_path = run_dir / "out.json"
    saved_artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    saved_artifact["target_python"]["executable"] = str(alias_python)
    saved_artifact["run"]["replay_context"]["target_python"]["executable"] = str(alias_python)
    artifact_path.write_text(json.dumps(saved_artifact, sort_keys=True), encoding="utf-8")

    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.chdir(repo)
    from hlith.operator.cli import main

    run_id = art["run"]["run_id"]
    unknown_rc = main(["replay", run_id, "--obligation", "not-an-obligation"])
    unknown_error = capsys.readouterr().err
    assert unknown_rc == 2 and row["id"] in unknown_error, unknown_error
    # the producer persists the exact judged patch bytes (change.patch) in the durable run dir: the replay works straight from the run
    assert (run_dir / "change.patch").is_file()
    persisted_rc = main(["replay", run_id, "--obligation", row["id"]])
    persisted_output = capsys.readouterr().out
    assert persisted_rc == 0 and "Replay: REPRODUCED" in persisted_output, persisted_output

    with monkeypatch.context() as patch_worker:
        patch_worker.setattr(differential, "replay_witness", lambda *_args, **_kwargs: {
            "replayable": True, "pre": {}, "post": {},
        })
        no_observation_rc = main(["replay", run_id, "--obligation", row["id"]])
        no_observation_output = capsys.readouterr().out
    assert no_observation_rc == 4 and "confined target Python worker returned no observation" in no_observation_output
    assert "confinement unavailable" not in no_observation_output, no_observation_output

    saved_artifact["run"]["replay_context"].pop("target_python")
    artifact_path.write_text(json.dumps(saved_artifact, sort_keys=True), encoding="utf-8")
    top_level_python_rc = main(["replay", run_id, "--obligation", row["id"]])
    top_level_python_output = capsys.readouterr().out
    assert top_level_python_rc == 0 and "Replay: REPRODUCED" in top_level_python_output, top_level_python_output

    (run_dir / "change.patch").unlink()  # now exercise the honest NOT REPLAYABLE path: the recorded patch is gone
    missing_patch_rc = main(["replay", run_id, "--obligation", row["id"]])
    missing_patch_output = capsys.readouterr().out
    assert missing_patch_rc == 12 and "change.patch is unavailable" in missing_patch_output, missing_patch_output

    # This low-level helper writes its input patch beside the external artifact, not into the
    # durable run directory. Materialize the exact hashed bytes at the recorded run-dir ref so
    # this test exercises the replay consumer contract; the producer persistence gap is reported
    # separately to design review.
    patch_bytes = (tmp_path / "r1.patch").read_bytes()
    (run_dir / "change.patch").write_bytes(patch_bytes + b"tampered")
    bad_patch_rc = main(["replay", run_id, "--obligation", row["id"]])
    bad_patch_output = capsys.readouterr().out
    assert bad_patch_rc == 12 and "sha256 does not match" in bad_patch_output, bad_patch_output

    (run_dir / "change.patch").write_bytes(patch_bytes)
    missing_python_rc = main(["replay", run_id, "--obligation", row["id"], "--python", "/not/a/python"])
    missing_python_output = capsys.readouterr().out
    assert missing_python_rc == 12 and "target Python is unavailable" in missing_python_output, missing_python_output

    unconfined_rc = main(["replay", "run-000000000000", "--unconfined"])
    unconfined_error = capsys.readouterr().err.splitlines()
    assert unconfined_rc == 2 and unconfined_error[0].startswith("WARNING: --unconfined"), unconfined_error

    cli_rc = main(["replay", run_id, "--obligation", row["id"]])
    output = capsys.readouterr().out.splitlines()
    assert cli_rc == 0, output
    assert output[0] == "Replay: REPRODUCED", output
    assert output[-1] == "replay re-executes ONE recorded call: it confirms a witness, it never certifies the rest of the domain"

    scripts_dir = tmp_path / "replay-scripts"
    json_rc = main(["replay", run_id, "--obligation", row["id"], "--json", "--scripts-dir", str(scripts_dir)])
    json_output = capsys.readouterr().out
    envelope = json.loads(json_output)
    assert json_rc == 0 and envelope["envelope"] == "hlith.replay/1" and envelope["status"] == "REPRODUCED", envelope
    assert envelope["limit"] == "replay re-executes ONE recorded call: it confirms a witness, it never certifies the rest of the domain"
    assert (scripts_dir / "replay_pre.py").is_file() and (scripts_dir / "replay_post.py").is_file()

    outside = f1._source(tmp_path / "outside-repository")
    outside_head = f1._git(outside, "rev-parse", "HEAD").strip()
    outside_tree = f1._git(outside, "rev-parse", "HEAD^{tree}").strip()
    outside_status = f1._git(outside, "status", "--porcelain")
    monkeypatch.chdir(outside)
    outside_rc = main(["replay", str(run_dir), "--obligation", row["id"]])
    outside_output = capsys.readouterr().out
    assert outside_rc == 12 and "run it from the repository (or pass --repo PATH)" in outside_output, outside_output
    assert (f1._git(outside, "rev-parse", "HEAD").strip(), f1._git(outside, "rev-parse", "HEAD^{tree}").strip(),
            f1._git(outside, "status", "--porcelain")) == (outside_head, outside_tree, outside_status)

    repo_rc = main(["replay", str(run_dir), "--obligation", row["id"], "--repo", str(repo)])
    repo_output = capsys.readouterr().out
    assert repo_rc == 0 and "Replay: REPRODUCED" in repo_output, repo_output

    repo_id_rc = main(["replay", run_id, "--obligation", row["id"], "--repo", str(repo)])
    repo_id_output = capsys.readouterr().out
    assert repo_id_rc == 0 and "Replay: REPRODUCED" in repo_id_output, repo_id_output

    hostile_repo = f1._clone(src, tmp_path / "hostile-repo")
    marker = tmp_path / "hostile-repo-marker"
    program = tmp_path / "hostile-fsmonitor.sh"
    program.write_text(f"#!/bin/sh\ntouch {marker}\n")
    program.chmod(0o755)
    f1._git(hostile_repo, "config", "core.fsmonitor", str(program))
    hostile_rc = main(["replay", str(run_dir), "--obligation", row["id"], "--repo", str(hostile_repo)])
    hostile_output = capsys.readouterr().out
    assert hostile_rc == 4 and "core.fsmonitor" in hostile_output, hostile_output
    assert not marker.exists(), "--repo path vet must refuse before any repository-configured program runs"
