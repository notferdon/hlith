"""History is scoped to the CURRENT repository first: its bucket is always read and never subject to the cross-repository cap, the others fill the rest newest-first, and the
truncation figures count the repository folders that were left out (review found the operator's own run missing while the screen said 'not truncated')."""
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from hlith.operator.tui import launch


@pytest.fixture(autouse=True)
def _no_env_leak():
    """case: no test of this file may start with HLITH_UI_STATE set (a previous test leaked it: review found _world() assigning os.environ directly). Checked at
    SETUP, because pytest tears monkeypatch down after this fixture; tests that need the variable use monkeypatch.setenv."""
    assert "HLITH_UI_STATE" not in os.environ, "HLITH_UI_STATE is set at the start of a test: an earlier test leaked it into the process environment"
    yield


def _meta(d: Path, started: float):
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"run_id": d.name, "started": started, "argv": ["x"], "source_repo": "/work/r", "pid": 2147483000}))


def _world(tmp_path, others=None):
    others = launch._MAX_HISTORY_REPOSITORIES + 6 if others is None else others
    repo = tmp_path / "work"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, capture_output=True)
    state = tmp_path / "state"
    run = launch._api(state).new_launch_dir(repo)  # explicit state: the process environment is never touched  # this repository's bucket, made the way the host makes it
    _meta(run.parent / "launch-aaaaaaaaaaaa", time.time() - 10 ** 6) if not (run / "meta.json").exists() else None
    (run / "meta.json").write_text(json.dumps({"run_id": run.name, "started": time.time() - 10 ** 6, "argv": ["x"], "source_repo": str(repo), "pid": 2147483000}))
    old = time.time() - 10 ** 6
    os.utime(run.parent.parent, (old, old))  # the working repository's bucket is the OLDEST
    for i in range(others):
        d = state / "host" / "repositories" / f"repo-{i:024x}" / "runs" / f"launch-{i:012x}"
        _meta(d, time.time() - i)
    return repo, state, run


def test_the_current_repositorys_run_is_listed_even_when_its_bucket_ranks_beyond_the_cap(tmp_path):
    repo, state, run = _world(tmp_path)
    rows, total, truncated, scanned = launch._runs_for_snapshot(None, state, current_repo=repo)
    assert any(Path(r["run_dir"]).name == run.name for r in rows), "the operator's own run must be listed"
    assert truncated is True  # more repository folders than the scan reads: the screen says it left some out (counts stay in their own units)
    assert launch.omitted_history_repositories(state, repo) >= 6


def test_without_the_current_repository_the_old_cap_would_have_hidden_it(tmp_path):
    repo, state, run = _world(tmp_path)
    rows, total, truncated, scanned = launch._runs_for_snapshot(None, state)
    assert not any(Path(r["run_dir"]).name == run.name for r in rows)  # control: the cap alone drops the oldest bucket...
    assert truncated is True  # ...and it is no longer reported as complete


def test_a_small_state_is_not_reported_truncated(tmp_path):
    repo, state, run = _world(tmp_path, others=3)
    rows, total, truncated, scanned = launch._runs_for_snapshot(None, state, current_repo=repo)
    assert truncated is False and any(Path(r["run_dir"]).name == run.name for r in rows)


def test_the_claim_describes_where_the_clone_really_lives_and_that_it_is_kept():
    """Fixed sentence audit (review): the sample says 'a fresh clone in the run state directory'; launch.plan keeps the clone in the run folder (rmtree runs only when a clone is refused)."""
    from hlith.operator.tui import frame

    real = " ".join(" ".join("".join(seg.text for seg in line) for line in frame._disposable(100, sample=False, branch="main")).split())
    assert "fresh clone in the run state directory" not in real and "deleted afterwards" not in real
    assert "run's folder under the Hlith state directory" in real and "kept with the record" in real
    # every TUI launch passes --source-repo, so the engine's landing is a REHEARSAL landing in the clone (engine_cli: rehearsal = source_repo is not None; the coordinator refuses a
    # rehearsal on the selected repository): the user's repository is never written, and the text must not say it commits to the branch
    assert "rehearsal landing" in real and "Your repository is not changed either way" in real
    assert "commits the checked patch to main" not in real and "while the check runs" not in real
    sample = " ".join(" ".join("".join(seg.text for seg in line) for line in frame._disposable(100)).split())
    assert "a fresh clone in the run state directory" in sample and "commits the checked patch to trial" in sample  # the reference's fictional wording stays on the sample only


def test_a_run_whose_bucket_identity_no_longer_matches_is_still_found_by_its_own_record(tmp_path, monkeypatch):
    """review: the operator's own refused run sat in a bucket whose identity differs from the repository's CURRENT one (no current bucket at all), ranked 352 of 785 behind the old 64-bucket cap:
    History scans far more buckets now, and a run whose record names this repository is treated as its own."""
    repo = tmp_path / "work"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, capture_output=True)
    state = tmp_path / "state"
    monkeypatch.setenv("HLITH_UI_STATE", str(state))
    for i in range(200):  # 200 other repositories; the repository's own run lives in an OLD bucket under a different identity
        d = state / "host" / "repositories" / f"repo-{i:024x}" / "runs" / f"launch-{i:012x}"
        _meta(d, time.time() - i)
    own_dir = state / "host" / "repositories" / f"repo-{0xdeadbeef:024x}" / "runs" / "launch-abcdefabcdef"
    own_dir.mkdir(parents=True)
    (own_dir / "meta.json").write_text(json.dumps({"run_id": own_dir.name, "started": time.time() - 10 ** 6, "argv": ["x"], "source_repo": str(repo), "pid": 2147483000}))
    old = time.time() - 10 ** 6
    os.utime(own_dir.parent.parent, (old, old))
    rows, total, truncated, scanned = launch._runs_for_snapshot(None, state, current_repo=repo)
    assert any(Path(r["run_dir"]).name == own_dir.name for r in rows), "the run named by its own record must be listed"


def test_the_run_found_by_its_record_is_flagged_as_recorded_under_an_earlier_repository_id(tmp_path, monkeypatch):
    repo = tmp_path / "work"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, capture_output=True)
    state = tmp_path / "state"
    monkeypatch.setenv("HLITH_UI_STATE", str(state))
    d = state / "host" / "repositories" / f"repo-{0xabc:024x}" / "runs" / "launch-111111111111"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"run_id": d.name, "started": time.time() - 100, "argv": ["x"], "source_repo": str(repo), "pid": 2147483000}))
    rows, total, truncated, scanned = launch.run_rows_with_summary(None, repo)
    mine = [r for r in rows if r["run_id"] == d.name]
    assert mine and mine[0]["earlier_id"] is True and mine[0]["repo"] == "work"


def test_the_history_screen_states_units_truthfully_and_marks_earlier_id_rows():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    base_ctx = {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "history_scan_complete": True}
    empty = {**base_ctx, "history_rows": [], "history_total": 98, "history_truncated": True, "history_scanned": 98, "history_omitted_repos": 505}
    text = " ".join(" ".join(frame.render(ViewState(st="history", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=empty).text_rows()).split())
    assert "None found in the part scanned (98 of 98 run folders; 505 more repository folders were not scanned)" in text
    assert "No recorded runs found" not in text  # it must not contradict 'truncated'
    row = {"run_id": "launch-111111111111", "repo": "work", "head": "a" * 8, "age": "1m ago", "state": "finished", "decision": "REFUSED", "earlier_id": True, "run_dir": "/x"}
    shown = {**base_ctx, "history_rows": [row], "history_total": 1, "history_truncated": False}
    text = " ".join(" ".join(frame.render(ViewState(st="history", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=shown).text_rows()).split())
    assert "work ◂" in text and "earlier repository id (the set of root commits changed)" in text


def _hist_ctx(n, **extra):
    rows = [{"run_id": f"launch-{i:012x}", "repo": "repo", "head": "unknown", "age": "1h ago", "state": "finished", "run_dir": "/x",
             "engine_run_id": "run-9ba850ae4db9" if i == n - 1 else None} for i in range(n)]
    return {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "/work/proj"}, "history_scan_complete": True, "history_rows": rows, "history_total": n, **extra}


def test_the_history_window_follows_the_selection_at_80x24_and_keeps_both_row_lines_visible():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    for n, focus in ((7, 9), (40, 39), (40, 20), (40, 1)):
        ctx = _hist_ctx(n)
        shown = min(focus, n - 1)
        text = frame.render(ViewState(st="history", cols=80, rows=24, focusIndex=focus), 80, 24, {"run": {}, "obligations": []}, context=ctx).text_rows()
        i = next(k for k, r in enumerate(text) if r.startswith("  ▌ launch-"))
        assert f"launch-{shown:012x}" in text[i]
        assert text[i + 1].strip().startswith("repo") and "↓ more" not in text[i + 1] or shown == n - 1 and "unknown" in text[i + 1] or "1h ago" in text[i + 1], text[i + 1]


def test_the_history_header_never_says_reading_repository_and_shows_the_engine_run_id():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    ctx = _hist_ctx(7, repository_loading=True)
    ctx["repo"]["name"] = "reading repository…"
    text = frame.render(ViewState(st="history", cols=100, rows=30, focusIndex=6), 100, 30, {"run": {}, "obligations": []}, context=ctx).text_rows()
    assert "reading repository" not in text[0] and "proj" in text[0]
    assert any("run-9ba850ae4db9" in r for r in text)


def test_the_history_position_stays_visible_in_the_status_line_after_the_list_header_scrolls_away():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    ctx = _hist_ctx(7)
    for focus in (0, 4, 6, 9):
        text = frame.render(ViewState(st="history", cols=80, rows=24, focusIndex=focus), 80, 24, {"run": {}, "obligations": []}, context=ctx).text_rows()
        status = text[-2]
        assert f"recorded runs · {min(focus, 6) + 1} of 7" in status, status


def test_the_world_helper_does_not_touch_the_process_environment(tmp_path, monkeypatch):
    """case (review finding): _world() used to assign os.environ['HLITH_UI_STATE'] directly (masked only by a file-level restore fixture)."""
    monkeypatch.delenv("HLITH_UI_STATE", raising=False)
    _world(tmp_path, others=1)
    assert "HLITH_UI_STATE" not in os.environ, "the helper leaked HLITH_UI_STATE into the process environment"


def test_explicit_hlith_state_dir_beats_installed_launcher_preview_ui_fallback(tmp_path, monkeypatch):
    """Installed launcher exports HLITH_UI_STATE=~/.local/state/hlith/operator-preview by default;
    an explicit HLITH_STATE_DIR must unify check, replay, inspect, history, and ui under HLITH_STATE_DIR."""
    from hlith.operator.api import OperatorApi

    repo = tmp_path / "proj"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, capture_output=True)
    (repo / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-qm", "base"], check=True, capture_output=True)

    isolated = tmp_path / "isolated-state"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(isolated))
    monkeypatch.setenv("HLITH_UI_STATE", str(Path.home() / ".local" / "state" / "hlith" / "operator-preview"))

    api = OperatorApi()
    assert api.state.root == isolated
    assert launch._api().state.root == isolated
    ident = api.state.stable_repo_identity(repo)
    run_dir = isolated / "repositories" / ident / "runs" / "run-123456789abc"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({"run_id": run_dir.name, "started": time.time(), "source_repo": str(repo), "argv": ["x"]}))
    assert api.find(repo, "run-123456789abc") == run_dir
