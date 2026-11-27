# SPDX-License-Identifier: Apache-2.0
"""Product posture: Hlith Review never writes the original repository."""
from __future__ import annotations

import io
from contextlib import redirect_stderr
from pathlib import Path

from hlith.operator import engine_cli
from hlith.operator.product import REVIEW_LABEL, REVIEW_ONLY
from hlith.operator.tui import frame


def test_review_posture_is_on():
    assert REVIEW_ONLY is True
    assert "merge authority remains with the engineer" in REVIEW_LABEL


def test_cli_apply_is_disabled_before_any_path_access(tmp_path: Path):
    err = io.StringIO()
    with redirect_stderr(err):
        rc = engine_cli.main([
            "apply", "--repo", str(tmp_path / "repo"),
            "--rehearsal-artifact", str(tmp_path / "out.json"),
            "--patch", str(tmp_path / "change.patch"),
        ])
    assert rc == engine_cli.EXIT_BOUNDARY
    assert "Apply is not offered" in err.getvalue()


def test_tui_apply_candidate_is_never_offered_even_for_landed_rehearsal():
    artifact = {"landed_commit": "a" * 40, "run": {"landing_target": "rehearsal"}, "obligations": []}
    context = {"launch_meta": {"clone": "/work/clone"}, "repo": {"head": "a" * 40}}
    assert frame._apply_candidate(artifact, context) is False


def test_cli_run_and_resume_are_disabled(tmp_path: Path):
    err = io.StringIO()
    with redirect_stderr(err):
        rc = engine_cli.main(["run", "--repo", str(tmp_path), "--patch", str(tmp_path / "p"), "--artifact-out", str(tmp_path / "out.json")])
    assert rc == engine_cli.EXIT_BOUNDARY
    assert "read-only" in err.getvalue()


def test_no_caller_supplied_landing_authority_remains_in_the_package():
    """P2.6: check rehearses in-process; no marker file, environment token or capability record can authorize a landing."""
    import importlib.util
    from pathlib import Path as _P

    import hlith
    assert importlib.util.find_spec("hlith.operator.review_capability") is None
    root = _P(hlith.__file__).parent
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("HLITH_REVIEW_INTERNAL", ".hlith-review-rehearsal", "review_capability"):
            assert needle not in text, f"{needle} still in {path.relative_to(root)}"


def test_pytest_witness_export_is_narrow_and_honest(tmp_path):
    from hlith.contract.witness import adapt
    from hlith.operator.witness_export import NotExportable, build_pytest_source
    w = {"module": "m", "qualname": "f", "args": [1], "kwargs": {},
         "pre": {"k": "exc", "t": "builtins.TypeError", "mi": "bad"}, "post": {"k": "ret", "r": "2"},
         "receiver": None, "env": None}
    src = build_pytest_source(adapt(w), import_root="src", expect="post")
    code_part = src.split("# Provenance:")[0]
    assert "test_recorded_post_behavior" in code_part and "builtins.TypeError" not in code_part
    assert "from m import f" in code_part and "importlib" not in src and "getattr" not in src
    import pytest
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "receiver": {"cls": "C"}}))
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "pre": {"k": "ret", "r": "2"}}))
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "args": [{"$float": {"bits": "0000000000000000", "repr": "0.0"}}]}))
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "post": {"k": "ret", "r": "[1, 2]"}}))
    pre = build_pytest_source(adapt(w), expect="pre")
    assert "test_recorded_pre_behavior" in pre and "expected pre" in pre
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "pre": {"k": "ret", "r": "'<tree>'"}}))
    with pytest.raises(NotExportable):
        build_pytest_source(adapt({**w, "post": {"k": "ret", "r": "'0xdeadbeef'"}}))
    target = tmp_path / "no-dir" / "test.py"
    with pytest.raises(NotExportable):
        from hlith.operator.witness_export import write_pytest
        write_pytest(target, adapt({**w, "env": {"X": "1"}}))
    assert not target.parent.exists()


def test_explicit_raise_message_is_asserted(tmp_path):
    from hlith.contract.witness import adapt
    from hlith.operator.witness_export import build_pytest_source
    w = {"module": "m", "qualname": "f", "args": [0], "kwargs": {},
         "pre": {"k": "exc", "t": "builtins.ValueError", "m": "limit exceeded"},
         "post": {"k": "ret", "r": "1"}, "receiver": None, "env": None}
    src = build_pytest_source(adapt(w), expect="pre")
    assert "limit exceeded" in src


def test_review_cli_surfaces_never_suggest_removed_write_commands(tmp_path, monkeypatch, capsys):
    import subprocess
    from hlith.operator import cli

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
    (repo / "m.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "m.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"], check=True)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    assert cli.main(["status", "--repo", str(repo)]) == 0
    status_out = capsys.readouterr().out
    assert "hlith run --help" not in status_out
    assert "hlith check --help" in status_out

    (repo / ".git" / "hlith-journal.json").write_text("{}\n")
    ok, detail = cli._pending_journal_check(repo, state)
    assert ok is False
    assert "hlith run/apply" not in detail
    assert "read-only" in detail and "inspect git status/HEAD manually" in detail

    try:
        cli.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    help_out = capsys.readouterr().out
    assert "does not start checks" in help_out
    assert "to check a real change" not in help_out


def test_feedback_type_only_exception_pin_does_not_fabricate_empty_message_mismatch():
    from hlith import differential

    want = differential._from_feedback({"kind": "raise", "exc": "builtins.ValueError"})
    assert "m" not in want
    got_same_type = {"k": "exc", "t": "builtins.ValueError", "m": "Timeout must be positive", "w": ""}
    assert differential._matches_feedback_expected(want, got_same_type) is True
    # Negative controls: wrong type, non-raise, warning, or explicit recorded message mismatch stay refused.
    assert differential._matches_feedback_expected(want, {"k": "exc", "t": "builtins.TypeError", "m": "Timeout must be positive", "w": ""}) is False
    assert differential._matches_feedback_expected(want, {"k": "ret", "r": "0", "w": ""}) is False
    assert differential._matches_feedback_expected(want, {**got_same_type, "w": "UserWarning: x"}) is False
    want_with_msg = differential._from_feedback({"kind": "raise", "exc": "builtins.ValueError", "m": "Timeout must be positive"})
    assert differential._matches_feedback_expected(want_with_msg, {"k": "exc", "t": "builtins.ValueError", "m": "other", "w": ""}) is False
    # Base-vs-post _same still strictly compares exception messages (no weakening).
    assert differential._same({"k": "exc", "t": "builtins.ValueError", "m": ""}, got_same_type) is False
    assert differential._same({"k": "exc", "t": "builtins.ValueError", "m": "a"}, {"k": "exc", "t": "builtins.ValueError", "m": "b"}) is False
