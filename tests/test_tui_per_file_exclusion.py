"""Per-file exclusion is a REAL claim control: Space on a file row leaves that file out of the patch the engine is given; the claim names the exclusion; nothing is claimed
that the operator did not see. Real git repo, real changes.discover, the host's own claim builder."""
import hashlib
import subprocess
from dataclasses import replace

import pytest

from hlith.operator.tui import frame, host, reduce
from hlith.operator.tui.model import ViewState


def _repo(tmp_path):
    r = tmp_path / "proj"
    r.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid", "PATH": "/usr/bin:/bin"}
    (r / "a.py").write_text("def f(x):\n    return x\n")
    (r / "package-lock.json").write_text('{"v": 1}\n')
    (r / "b.py").write_text("B = 1\n")
    for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(r), *cmd], check=True, env=env, capture_output=True)
    (r / "a.py").write_text("def f(x):\n    return x + 1\n")
    (r / "package-lock.json").write_text('{"v": 2}\n')
    (r / "b.py").write_text("B = 2\n")
    return r


def _ctx(repo):
    ctx = host._repo_context(repo)
    assert ctx["sources"] and ctx["sources"][0]["kind"] == "uncommitted"
    state = ViewState(st="selection", cols=100, rows=30, focusIndex=0)
    ctx = host._selection_context(ctx, state)
    return ctx, host._with_file_count(state, ctx)


def test_the_claim_patch_follows_the_included_files_exactly(tmp_path):
    repo = _repo(tmp_path)
    ctx, state = _ctx(repo)
    paths = [p[0] for p in ctx["change"]["files"]]
    assert sorted(paths) == ["a.py", "b.py", "package-lock.json"] and state.file_count == 3
    lock = paths.index("package-lock.json")
    state = reduce.reduce(state, "key:tab")  # focus the file list
    assert state.pane == 1
    state = replace(state, file_focus=lock)
    state = reduce.reduce(state, "key:space")  # exclude the lockfile
    assert state.excluded_files == ((0, lock),)
    state = reduce.reduce(replace(state, pane=0), "key:enter")
    assert state.st == "claim"
    excluded, total = host._claim_exclusion(state, ctx)
    assert excluded == ["package-lock.json"] and total == 3
    claimed = host._claim_context({**ctx, "claim_excluded": excluded, "claim_file_total": total, "can_run": True})
    plan = claimed["plan"]
    assert plan is not None, claimed["change"].get("note")
    assert b"package-lock.json" not in plan.patch_bytes and b"a.py" in plan.patch_bytes and b"b.py" in plan.patch_bytes
    assert hashlib.sha256(plan.patch_bytes).hexdigest() != hashlib.sha256(ctx["selected_change"].diff()).hexdigest()  # a different patch than the whole one
    state = replace(state, cols=160, rows=44)  # wide enough that the row is one line in the split's left column (narrower panes wrap it beside the inspector)
    text = "\n".join(frame.render(state, 160, 44, {"run": {}, "obligations": []}, context=claimed).text_rows())
    flat = " ".join(text.split())
    assert "2 of 3 files" in flat and "excluded package-lock.json" in flat  # the claim NAMES what was left out


def test_nothing_excluded_claims_the_whole_patch_and_the_scope_row_says_so(tmp_path):
    repo = _repo(tmp_path)
    ctx, state = _ctx(repo)
    claimed = host._claim_context({**ctx, "claim_excluded": [], "claim_file_total": 3, "can_run": True})
    assert claimed["plan"].patch_bytes == ctx["selected_change"].diff()
    state = replace(state, st="claim", cols=160, rows=44)
    assert "3 files · +3 −3 ·" in " ".join("\n".join(frame.render(state, 160, 44, {"run": {}, "obligations": []}, context=claimed).text_rows()).split())


def test_every_file_excluded_cannot_enter_the_claim(tmp_path):
    ctx, state = _ctx(_repo(tmp_path))
    state = replace(state, excluded_files=tuple((0, i) for i in range(3)))
    after = reduce.reduce(state, "key:enter")
    assert after.st == "selection" and after.toast
    claimed = host._claim_context({**ctx, "claim_excluded": [p[0] for p in ctx["change"]["files"]], "claim_file_total": 3, "can_run": True})
    assert claimed["plan"] is None  # and the host refuses to plan an empty claim too


def test_space_on_the_source_row_still_toggles_the_whole_source_and_esc_leaves_the_file_list_first(tmp_path):
    ctx, state = _ctx(_repo(tmp_path))
    assert reduce.reduce(state, "key:space").excluded_sources == (0,)
    filed = reduce.reduce(state, "key:tab")
    assert filed.pane == 1 and reduce.reduce(filed, "key:esc").pane == 0 and reduce.reduce(filed, "key:esc").st == "selection"


def test_the_file_list_rows_show_the_marks_per_file(tmp_path):
    ctx, state = _ctx(_repo(tmp_path))
    state = replace(reduce.reduce(state, "key:tab"), file_focus=1)
    state = reduce.reduce(state, "key:space")
    art = {"run": {}, "obligations": [], "effect": {"unified_diff": ctx.get("preview_diff", ""), "touched_files": []}}
    text = "\n".join(frame.render(state, 100, 30, art, context=ctx).text_rows())
    assert text.count("[ ] ") >= 1 and text.count("[x] ") >= 2  # one excluded, two included
    assert "[~] Uncommitted work" in text  # the rail row of the source says 'some files out'


def test_the_claim_states_the_size_of_the_filtered_patch_not_the_whole_one(tmp_path):
    ctx, state = _ctx(_repo(tmp_path))
    excluded = ["package-lock.json"]
    claimed = host._claim_context({**ctx, "claim_excluded": excluded, "claim_file_total": 3, "can_run": True})
    size = len(claimed["plan"].patch_bytes)
    assert size < len(ctx["selected_change"].diff())
    text = " ".join("\n".join(frame.render(replace(state, st="claim", cols=160, rows=44), 160, 44, {"run": {}, "obligations": []}, context=claimed).text_rows()).split())
    assert f"patch {size} B" in text and "Files (2): a.py, b.py" in text


def _claim_text_for(tmp_path, excluded):
    ctx, state = _ctx(_repo(tmp_path))
    names = [p[0] for p in ctx["change"]["files"]]
    claimed = host._claim_context({**ctx, "claim_excluded": list(excluded), "claim_file_total": len(names), "can_run": True})
    assert claimed["plan"] is not None
    art = host._preview_artifact(dict(host._EMPTY), claimed, False)
    rows = frame.render(replace(state, st="claim", cols=160, rows=44), 160, 44, art, context=claimed).text_rows()
    return "\n".join(rows), claimed


def test_the_full_diff_page_marks_an_excluded_file_so_the_reviewed_patch_is_unambiguous(tmp_path):
    """review walkthrough #2: after excluding a file, the DIFF page showed it with no marker while the Claim later said '2 of 3 files'."""
    ctx, state = _ctx(_repo(tmp_path))
    state = replace(state, excluded_files=((0, [p[0] for p in ctx["change"]["files"]].index("package-lock.json")),))
    art = host._preview_artifact(dict(host._EMPTY), ctx, False)
    rows = frame.render(replace(state, drill="diff", cols=100, rows=40), 100, 40, art, context=ctx).text_rows()
    marked = [r for r in rows if "[excluded: not in the claim]" in r]
    assert len(marked) == 1 and "package-lock.json" in marked[0], marked
    # control: nothing excluded = no marker anywhere
    plain = frame.render(replace(state, excluded_files=(), drill="diff", cols=100, rows=40), 100, 40, art, context=ctx).text_rows()
    assert not any("[excluded" in r for r in plain)
    # the Claim's own full diff names it as well (the claim_excluded list is the host's)
    claimed = host._claim_context({**ctx, "claim_excluded": ["package-lock.json"], "claim_file_total": 3, "can_run": True})
    cl = frame.render(replace(state, st="claim", drill="diff", cols=100, rows=40), 100, 40, host._preview_artifact(dict(host._EMPTY), claimed, False), context=claimed).text_rows()
    assert not any('{"v": 2}' in r for r in cl), "the Claim's diff drill must show only the claimed patch"
    assert any("package-lock.json" in r and "[excluded: not in the claim · 1 hunk hidden]" in r for r in cl)
    assert any("+2 −2 · 2 hunk" in r for r in cl)  # the header counts are the claimed patch's own
    # at 80 columns the marker is the short WHOLE form, never a cut phrase
    narrow = frame.render(replace(state, st="claim", drill="diff", cols=80, rows=40), 80, 40, host._preview_artifact(dict(host._EMPTY), claimed, False), context=claimed).text_rows()
    assert any("package-lock.json" in r and r.rstrip().endswith(("[excluded]", "hidden]")) for r in narrow) and not any("not in the cl…" in r for r in narrow)
    # Selection keeps showing the excluded file's lines, with the marker
    sel = frame.render(replace(state, drill="diff", cols=100, rows=60), 100, 60, art, context=ctx).text_rows()
    assert any('{"v": 2}' in r for r in sel) and any("[excluded" in r for r in sel)


def test_the_80x24_claim_footer_leads_with_review_command_until_the_command_end_is_reviewed(tmp_path):
    """review walkthrough #1: the footer said 'enter run independent check' while the argv was below the fold."""
    ctx, state = _ctx(_repo(tmp_path))
    claimed = host._claim_context({**ctx, "claim_excluded": [], "claim_file_total": 3, "can_run": True})
    art = host._preview_artifact(dict(host._EMPTY), claimed, False)
    for cols, rows in ((80, 24), (100, 30)):
        unseen = {**claimed, "command_visible": False, "claim_command_seen": False}
        footer = frame.render(replace(state, st="claim", cols=cols, rows=rows), cols, rows, art, context=unseen).text_rows()[-1]
        assert footer.strip().startswith("enter review command"), (cols, footer)
        seen = {**claimed, "command_visible": True, "claim_command_seen": True}
        footer = frame.render(replace(state, st="claim", cols=cols, rows=rows), cols, rows, art, context=seen).text_rows()[-1]
        assert "review command" not in footer and footer.strip().startswith("enter how to run this check"), (cols, footer)


def test_a_long_excluded_file_name_is_capped_in_the_claim_exclusion_row(tmp_path):
    ctx, state = _ctx(_repo(tmp_path))
    claimed = host._claim_context({**ctx, "claim_excluded": ["package-lock.json"], "claim_file_total": 3, "can_run": True})
    claimed = {**claimed, "claim_excluded": ["Q" * 600, "package-lock.json"]}
    art = host._preview_artifact(dict(host._EMPTY), claimed, False)
    rows = frame.render(replace(state, st="claim", cols=100, rows=40), 100, 40, art, context=claimed).text_rows()
    assert sum(r.count("Q") for r in rows) <= 200 and "package-lock.json" in " ".join(" ".join(rows).split())


def test_the_claim_shows_and_counts_only_the_filtered_patch(tmp_path):
    """review: with the lockfile excluded the Claim's scope row counted the WHOLE change (+3 −3) and its CHANGE pane listed the lockfile's line, although Files and the launched patch excluded it."""
    text, claimed = _claim_text_for(tmp_path, ["package-lock.json"])
    assert '{"v": 2}' not in text and '{"v": 1}' not in text and "package-lock.json" in " ".join(text.split())  # named as excluded, its lines never shown
    scope = next(ln for ln in text.splitlines() if "base " in ln and "patch " in ln)
    assert "+2 −2" in scope and "+3" not in scope, scope  # a.py + b.py only
    assert str(len(claimed["plan"].patch_bytes)) in scope


def test_control_nothing_excluded_shows_all_three_files_and_counts(tmp_path):
    text, claimed = _claim_text_for(tmp_path, [])
    scope = next(ln for ln in text.splitlines() if "base " in ln and "patch " in ln)
    assert "+3 −3" in scope
