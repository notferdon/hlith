# SPDX-License-Identifier: Apache-2.0
import difflib
import subprocess

from hlith.derive import make_derive
from hlith.effect import engine as effect_engine  # the L2 engine moved out of derive (A5: L3 no longer owns it)
from hlith.types import ProposedEffect


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_analysis_failed_stop_reason_starts_with_file_for_cli(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    before = "def changed(value):\n    return helper(value)\n"
    after = "def changed(value):\n    return helper(value) + 1\n"
    (repo / "m.py").write_text(before, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    patch = "diff --git a/m.py b/m.py\n" + "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile="a/m.py",
        tofile="b/m.py",
    ))
    original = effect_engine._AstIndexVisitor.visit_Call

    def fail_in_changed_file(visitor, node):
        if visitor.file_path == "m.py":
            raise RuntimeError("injected analyzer failure")
        return original(visitor, node)

    monkeypatch.setattr(effect_engine._AstIndexVisitor, "visit_Call", fail_in_changed_file)
    result = make_derive(proposer_paths=[], differential_timeout=0.05)(
        repo, ProposedEffect(unified_diff=patch, proposer_id="test", touched_files=("m.py",))
    )

    failed = next(item for item in result.obligations if item.obligation_id.startswith("unresolved-"))
    assert failed.stop_reason.startswith(
        "effect account could not be built: m.py: RuntimeError: injected analyzer failure"
    )
