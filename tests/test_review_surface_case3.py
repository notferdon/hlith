"""Validation of the review-only surface (75defaa1): no public command offers Apply or reaches a gate landing on the engineer's repository.

No real landing runs: every gate `land` is replaced by a recorder that refuses."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith import cli
from hlith.contract.runs import LandingTarget
from hlith.gate import api as gate_api
from hlith.operator import api as api_module
from hlith.operator import check as operator_check
from hlith.operator import engine_cli, store


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          capture_output=True, text=True, check=True).stdout


@pytest.fixture
def world(tmp_path, monkeypatch):
    for var in ("HLITH_STATE_DIR", "HLITH_THREAD_STORE", "HLITH_UI_STATE"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    repo = tmp_path / "original"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "m.py").write_text("def f(x: int) -> int:\n    return x\n")
    _git(repo, "add", "m.py")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "m.py").write_text("def f(x: int) -> int:\n    y = x\n    return y\n")
    patch = tmp_path / "change.patch"
    patch.write_text(_git(repo, "diff"))
    _git(repo, "checkout", "-q", "--", "m.py")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"paths": {"m.py": ["modify"]}}))
    other = tmp_path / "unrelated"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    calls: list = []

    def record(*args, **_kw):
        calls.append([str(a) for a in args if isinstance(a, (str, Path)) or hasattr(a, "__fspath__")])
        raise RuntimeError("test recorder: landing refused")

    monkeypatch.setattr(engine_cli.gate, "land", record)  # legacy engine
    monkeypatch.setattr(gate_api.LocalGateService, "land", lambda self, *a, **k: record(*a, **k))  # pipeline engine
    argv = ["run", "--repo", str(repo), "--patch", str(patch), "--manifest", str(manifest), "--artifact-out", str(tmp_path / "out.json")]
    return SimpleNamespace(repo=repo, other=other, argv=argv, calls=calls, tmp=tmp_path, head=_git(repo, "rev-parse", "HEAD"))


def test_apply_returns_boundary_before_any_path_is_read(world, monkeypatch, capsys):
    monkeypatch.setattr(engine_cli, "_apply_review", lambda _a: pytest.fail("apply read its inputs"))
    argv = ["apply", "--repo", "/nonexistent/r", "--rehearsal-artifact", "/nonexistent/a", "--patch", "/nonexistent/p"]
    with pytest.raises(SystemExit) as exc:  # P2.6: `hlith apply` is not a command
        cli.main(argv)
    assert exc.value.code == 2 and "invalid choice" in capsys.readouterr().err
    rc = engine_cli.main(argv)  # the shipped engine module still refuses before reading any path
    assert rc == engine_cli.EXIT_BOUNDARY and "Apply is not offered" in capsys.readouterr().err
    assert world.calls == []


def test_pipeline_original_target_is_refused_without_calling_the_gate(world):
    rc = engine_cli.main(world.argv)
    assert world.calls == [] and rc == engine_cli.EXIT_BOUNDARY, (rc, world.calls)
    # The review distribution refuses at the CLI boundary before it allocates a run
    # artifact; stronger than a per-run artifact refusal, and the target is untouched.
    assert _git(world.repo, "rev-parse", "HEAD") == world.head and _git(world.repo, "status", "--porcelain") == ""


def test_legacy_engine_does_not_call_the_gate_on_the_original(world):
    engine_cli.main([*world.argv, "--engine", "legacy"])
    assert world.calls == [], world.calls


def test_a_source_repo_label_does_not_let_the_original_be_landed(world):
    engine_cli.main([*world.argv, "--source-repo", str(world.other)])  # --repo is the original, "source" is unrelated
    assert world.calls == [], world.calls


@pytest.mark.parametrize("engine", ["pipeline", "legacy"])
def test_no_run_enters_interrupted_landing_recovery_on_the_original(world, monkeypatch, engine):
    """Recovery rolls back or completes a half landing, so it writes the target. Both recorders answer "nothing to do": nothing is written."""
    recovered: list = []
    monkeypatch.setattr(engine_cli.gate, "recover", lambda target: recovered.append(str(target)) or "none")
    monkeypatch.setattr(gate_api.LocalGateService, "recover", lambda self, target: recovered.append(str(target)) or "clean")
    try:
        engine_cli.main([*world.argv, "--engine", engine])
    except RuntimeError as e:  # the legacy engine goes on to the land recorder (its own failing case above)
        assert "landing refused" in str(e)
    assert recovered == [], recovered


@pytest.mark.parametrize("as_json", [True, False], ids=["json", "text"])
def test_check_never_offers_an_apply_command_even_for_a_landed_rehearsal(world, monkeypatch, capsys, as_json):
    artifact = {"outcome": "landed", "exit_status": 0, "blocking": [], "obligations": []}
    inspection = SimpleNamespace(view=SimpleNamespace(artifact=artifact, state=SimpleNamespace(value="finished")), label="LANDED", notes=[])

    class FakeApi:
        def inspect(self, _run_dir):
            return inspection

    def fake_rehearse(_api, req, **_kw):  # P2.6 seam: the in-process rehearsal
        assert req.landing_target is LandingTarget.REHEARSAL
        return world.tmp / "launch", world.tmp / "run", 0, "", ""

    monkeypatch.setattr(operator_check, "_rehearse_inline", fake_rehearse)

    monkeypatch.setattr(operator_check, "_clean_checkout", lambda _s, clone, _b: (clone.mkdir() is None, ""))
    monkeypatch.setattr(store, "read_receipt", lambda _d: SimpleNamespace(run=SimpleNamespace(run_id="run-0123456789ab",
                                                                                              landing_target=LandingTarget.REHEARSAL)))
    monkeypatch.setattr(api_module, "OperatorApi", FakeApi)
    rc = cli.main(["check", "--repo", str(world.repo), "--patch", str(world.tmp / "change.patch"), "--no-input",
                   "--artifact-out", str(world.tmp / "result"), *(["--json"] if as_json else [])])
    out = capsys.readouterr().out
    assert rc == 0, out
    if as_json:
        assert json.loads(out)["check"]["apply_command"] is None
    assert "hlith apply" not in " ".join(out.split()) and "Apply review" not in out, out
