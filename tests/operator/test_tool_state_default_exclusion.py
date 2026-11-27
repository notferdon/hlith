# SPDX-License-Identifier: Apache-2.0
"""Agent/tool-state files (.beads .ntm .serena .claude ...) that are UNTRACKED are left out of the default claim of an uncommitted change, with explicit visibility and a way to include them
(legacy contract, lost in the live surfaces: found by review, reproduced by review on d333be8f: five files claimed, headless check exit 11 NOT-DERIVED instead of LANDED).

Fail closed: only the labelled tool-state directories, only when UNTRACKED; every other path (and every tracked edit, even under a tool directory) stays INCLUDED."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import replace

import pytest

from hlith.operator import check
from hlith.operator.tui import changes, frame, host, model

TOOL = {".beads/issues.jsonl": '{"id": "x"}\n', ".ntm/pane.log": "log\n", ".serena/project.yml": "name: x\n", ".claude/settings.local.json": "{}\n"}


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "pkg").mkdir()
    (r / "pkg/__init__.py").write_text("")
    (r / "pkg/price.py").write_text("def total(items, tax=0.0):\n    s = 0\n    for p in items:\n        s += p\n    return s + s * tax\n")
    (r / "tests").mkdir()
    (r / "tests/test_price.py").write_text("from pkg.price import total\n\n\ndef test_total():\n    assert total([1, 2, 3]) == 6\n")
    (r / ".vscode").mkdir()
    (r / ".vscode/settings.json").write_text("{}\n")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "base")
    (r / "pkg/price.py").write_text("def total(items, tax=0.0):\n    s = sum(items)\n    return s + s * tax\n")  # the real change
    for p, body in TOOL.items():
        (r / p).parent.mkdir(exist_ok=True)
        (r / p).write_text(body)
    return r


def _paths(patch: bytes) -> list[str]:
    return re.findall(r"^\+\+\+ b/(.+)$", patch.decode(), re.M)


def test_headless_selection_leaves_untracked_tool_state_out_by_default(repo):
    change = check.select_change(repo, uncommitted=True)
    assert _paths(change.diff()) == ["pkg/price.py"], _paths(change.diff())
    assert sorted(changes.tool_state_paths(change)) == sorted(TOOL)


def test_headless_selection_can_include_them_explicitly(repo):
    change = check.select_change(repo, uncommitted=True, include_tool_state=True)
    assert sorted(_paths(change.diff())) == sorted(["pkg/price.py", *TOOL])


def test_a_tracked_edit_under_a_tool_directory_stays_included(repo):
    (repo / ".vscode/settings.json").write_text('{"edited": true}\n')
    change = check.select_change(repo, uncommitted=True)
    assert ".vscode/settings.json" in _paths(change.diff()), "tracked edits are never silently dropped"


def test_only_tool_state_changes_is_a_named_boundary_not_an_empty_diff(tmp_path):
    r = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "base")
    (r / ".beads").mkdir()
    (r / ".beads/i.jsonl").write_text("{}\n")
    with pytest.raises(check.BoundaryError, match="tool-state"):
        check.select_change(r, uncommitted=True)


def _cli(repo, home, *args):
    env = {**os.environ, "HOME": str(home), "XDG_STATE_HOME": str(home / "state"), "HLITH_STATE_DIR": str(home / "state/host"), "PYTHONPATH": os.pathsep.join(sys.path)}
    return subprocess.run([sys.executable, "-m", "hlith.operator.cli", "check", "--repo", str(repo), "--no-input", "--json", *args], capture_output=True, text=True, env=env, timeout=420)


def test_headless_check_judges_only_the_real_change_and_names_what_it_left_out(repo, tmp_path):
    """The verdict itself depends on the gate (a stricter certificate may refuse a loop->sum refactor as UNVERIFIED), so the property is stated against a CONTROL: the same
    change in a copy WITHOUT the tool-state files must get the same exit status, the claim must be exactly the one real file, and the left-out files are named."""
    import shutil

    control = tmp_path / "control"
    shutil.copytree(repo, control)
    for d in {p.split("/")[0] for p in TOOL}:
        shutil.rmtree(control / d)
    r = _cli(repo, tmp_path / "h", "--uncommitted")
    c = _cli(control, tmp_path / "hc", "--uncommitted")
    env, cenv = json.loads(r.stdout), json.loads(c.stdout)
    assert r.returncode == c.returncode, ("tool-state files changed the outcome", r.returncode, env["check"].get("headline"), c.returncode, cenv["check"].get("headline"))
    assert r.returncode not in (4, 11), "the engine must judge the Python change, not refuse the tool-state files as non-Python"
    assert env["check"]["change"]["files"] == 1 == cenv["check"]["change"]["files"], "the claim is exactly the one real file"
    assert sorted(env["check"]["excluded_tool_state"]) == sorted(TOOL), "the left-out files are named in the envelope"
    assert cenv["check"]["excluded_tool_state"] == []


def test_explicit_inclusion_is_refused_not_landed_by_the_engine(repo, tmp_path):
    """What the engine does with tool-state files when the operator includes them: observed, recorded here as the contract (fail closed)."""
    r = _cli(repo, tmp_path / "h2", "--uncommitted", "--include-tool-state")
    env = json.loads(r.stdout)
    assert r.returncode == 11 and "NOT-DERIVED" in env["check"]["headline"], (r.returncode, env["check"]["headline"])
    assert env["check"]["excluded_tool_state"] == []


def _selection(repo):
    ctx = host._repo_context(repo)
    state = model.ViewState(st="selection", focusIndex=0, cols=120, rows=40)
    ctx = host._selection_context(ctx, state)
    return state, ctx


def test_tui_selection_starts_with_tool_state_files_unchecked_and_visible(repo):
    state, ctx = _selection(repo)
    state, ctx = host._seed_tool_exclusions(state, ctx)
    files = [f[0] for f in ctx["change"]["files"]]
    left_out = {files[fi] for (si, fi) in state.excluded_files}
    assert left_out == set(TOOL), left_out
    art = host._preview_artifact(dict(host._EMPTY), ctx, False)
    text = " ".join(" ".join(frame.render(replace(state, file_count=len(files)), 120, 40, art, context=ctx).text_rows()).split())
    assert f"1 of {len(files)} files included" in text, text
    assert re.search(r"\[ \] \.beads/issues\.jsonl", text) and re.search(r"\[x\] pkg/price\.py", text)


def test_tui_seeding_happens_once_so_the_operator_can_include_them(repo):
    state, ctx = _selection(repo)
    state, ctx = host._seed_tool_exclusions(state, ctx)
    state = replace(state, excluded_files=())  # the operator pressed `a` (include all)
    state, ctx = host._seed_tool_exclusions(state, ctx)
    assert state.excluded_files == (), "a deliberate inclusion is never undone"
