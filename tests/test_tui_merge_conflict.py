"""TUI behavior (review R3 walkthrough): a repository with an unresolved merge conflict is not 'Uncommitted work': the home says so and offers no check."""
import subprocess

from hlith.operator.tui import host


def _git(cwd, *a, check=True):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=check)


def test_unresolved_merge_conflict_is_a_named_stop_not_uncommitted_work(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "f.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    _git(r, "checkout", "-q", "-b", "other")
    (r / "f.py").write_text("x = 2\n")
    _git(r, "commit", "-qam", "other")
    _git(r, "checkout", "-q", "main")
    (r / "f.py").write_text("x = 3\n")
    _git(r, "commit", "-qam", "main")
    assert _git(r, "merge", "other", check=False).returncode != 0  # conflict
    ctx = host._repo_context(r)
    blocked = ctx.get("blocked") or {}
    assert "merge is in progress" in str(blocked.get("reason", "")) and "f.py" in str(blocked.get("reason", "")), ctx.get("blocked")
    assert not ctx.get("can_run", False)


def test_the_blocked_screen_for_a_merge_conflict_gives_the_merge_next_step_not_the_hostile_config_one():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    ctx = {"blocked": {"kind": "repository", "reason": "a merge is in progress with unresolved conflicts in 1 file(s) (m.py): resolve or abort the merge, then reopen. Nothing was checked."}}
    flat = " ".join("\n".join(frame.render(ViewState(st="blocked", cols=100, rows=30), 100, 30, {}, context=ctx, color="mono").text_rows()).split())
    assert "git merge --abort" in flat and "clean clone without executable repository settings" not in flat
    ctx2 = {"blocked": {"kind": "repository", "reason": "repository config contains executable settings"}}  # the hostile-config cause keeps its own next step
    flat2 = " ".join("\n".join(frame.render(ViewState(st="blocked", cols=100, rows=30), 100, 30, {}, context=ctx2, color="mono").text_rows()).split())
    assert "clean clone without executable repository settings" in flat2
