# SPDX-License-Identifier: Apache-2.0
"""A confined worker command that exits non-zero without producing any change must be reported as what it is (review, case, design review finding):
its exit code, its (possibly empty) stderr and the likely cause, not as 'worker produced no change'."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.cli import main, run_pipeline
from hlith.derive import make_derive
from hlith.types import Verdict

FALSE = shutil.which("false") or "/usr/bin/false"


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("VALUE_A = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _obs(res):
    return next(o for o in res[1].obligations if o.obligation_id == "no-effect")


def _reason(res) -> str:
    return _obs(res).stop_reason


def test_nonzero_exit_with_empty_stderr_names_the_exit_code_the_empty_stderr_and_the_likely_cause(repo):
    res = run_pipeline(repo, [FALSE], derive=make_derive(proposer_paths=[]))
    why = _reason(res)
    assert "exited 1" in why and "stderr empty" in why
    assert "--worker-ro" in why and "/usr/bin/python3" in why and "confinement" in why
    assert "no change" in why  # still says what was observed
    assert len(why) < 215  # the CLI report cuts a reason at 220 characters: the hint must survive
    assert _obs(res).verdict is Verdict.NOT_DERIVED


def test_nonzero_exit_with_stderr_shows_it_cleaned_and_no_guess_about_the_interpreter(repo, tmp_path):
    script = tmp_path / "w.py"
    script.write_text("import sys; sys.stderr.write('boom: cannot open thing\\n'); sys.exit(3)\n")
    res = run_pipeline(repo, [sys.executable, str(script)], derive=make_derive(proposer_paths=[]), worker_ro=(str(script.parent),))
    why = _reason(res)
    assert "exited 3" in why and "boom: cannot open thing" in why
    assert "stderr empty" not in why


def test_a_clean_exit_that_changed_nothing_keeps_the_original_wording(repo):
    res = run_pipeline(repo, [shutil.which("true") or "/usr/bin/true"], derive=make_derive(proposer_paths=[]))
    why = _reason(res)
    assert why == "worker produced no change to derive obligations for"


def test_the_cli_prints_the_truthful_text_and_the_artifact_carries_it(repo, tmp_path, capsys):
    """Canonical pipeline (default engine): a failed worker command is a BOUNDARY refusal (exit 4; the legacy engine reported it as
    NOT_DERIVED 11) that still says what was observed, on stdout and in the artifact's blocking reasons."""
    out = tmp_path / "art.json"
    rc = main(["run", "--repo", str(repo), "--worker-cmd", FALSE, "--artifact-out", str(out)])
    text = capsys.readouterr().out
    art = json.loads(out.read_text())
    blob = json.dumps(art)
    assert rc == 4 and "exited 1" in text and "stderr empty" in text and "--worker-ro" in text
    assert art["blocking"][0] == "worker-command-failed"
    assert "exited 1" in blob and "stderr empty" in blob and "patch names no changed path" not in blob


def test_the_legacy_engine_keeps_not_derived_for_a_failed_worker_command(repo, tmp_path, capsys):
    """The remaining, named engine difference: legacy classifies the same failed worker as NOT_DERIVED (11) with the same text."""
    out = tmp_path / "art.json"
    rc = main(["run", "--engine", "legacy", "--repo", str(repo), "--worker-cmd", FALSE, "--artifact-out", str(out)])
    text = capsys.readouterr().out
    assert rc == 11 and "exited 1" in text and "stderr empty" in text and "--worker-ro" in text


def test_the_ui_worker_command_path_shows_the_same_truthful_text(repo, tmp_path):
    """The UI (ADVANCED, 'worker command') plans exactly `hlith run --worker-cmd ...` and renders the artifact's own stop_reason."""
    from hlith.operator.tui import frame, host
    from hlith.operator.tui.model import ViewState
    from hlith.tui import launch

    pl = launch.plan(repo, worker_cmd=FALSE, state=tmp_path / "ui-state")
    assert "--worker-cmd" in pl.argv and pl.argv[pl.argv.index("--worker-cmd") + 1] == FALSE
    out = tmp_path / "ui-art.json"
    assert main(["run", "--repo", str(repo), "--worker-cmd", FALSE, "--artifact-out", str(out)]) == 4
    art = json.loads(out.read_text())
    # the LIVE verdict (was: the retired legacy facts panel), at every standard width (review, y1p0.1)
    for cols, rows in ((160, 50), (100, 40), (80, 24)):
        shown = " ".join(" ".join(frame.render(ViewState(st="verdict", cols=cols, rows=rows), cols, rows, art,
                                               context=host._artifact_context(art)).text_rows()).split())
        assert "UNVALIDATED" not in shown and "exited 1" in shown and "stderr empty" in shown and "--worker-ro" in shown, shown


def test_a_traceback_in_stderr_is_summarised_by_its_last_line_with_the_confinement_hint(repo, tmp_path):
    """design review's second case: a non-system interpreter dies in the confinement helper (execvp) and the error is the LAST stderr line."""
    script = tmp_path / "w.py"
    script.write_text("import sys\nsys.stderr.write('Traceback (most recent call last):\\n  File \"x.py\", line 1, in <module>\\n"
                      "FileNotFoundError: [Errno 2] No such file or directory\\n')\nsys.exit(1)\n")
    res = run_pipeline(repo, [sys.executable, str(script)], derive=make_derive(proposer_paths=[]), worker_ro=(str(script.parent),))
    why = _reason(res)
    assert "FileNotFoundError: [Errno 2] No such file or directory" in why and "Traceback" not in why
    assert "--worker-ro" in why and "/usr/bin/python3" in why and "exited 1" in why and len(why) < 215
