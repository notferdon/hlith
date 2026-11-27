"""The extra_sys_path tree budget and the receiver snapshot cap are two limits under two names (review: the receiver cap shadowed the tree budget)."""

import ast
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict

TREE_BUDGET = 512 * 1024 * 1024


def tree(tmp_path, size):
    src = tmp_path / "site"
    src.mkdir()
    (src / "big.py").write_bytes(b"#" * size)
    return src


@pytest.mark.parametrize("size", [100 * 1024, 600 * 1024], ids=["control-100KiB", "600KiB"])
def test_snapshot_tree_accepts_a_tree_inside_the_tree_budget(tmp_path, size):
    src = tree(tmp_path, size)
    skipped, why = differential._snapshot_tree(str(src), tmp_path / "dst", [differential._SPECIAL_LIMIT, differential._SNAP_MAX_BYTES])
    assert why is None and not skipped, why
    assert (tmp_path / "dst" / "big.py").stat().st_size == size


def test_run_differential_does_not_refuse_a_600KiB_extra_sys_path(monkeypatch, tmp_path):
    seen = []

    def inner(**kw):
        seen.extend(kw["extra_sys_path"])
        raise RuntimeError("stop after the snapshot")

    monkeypatch.setattr(differential, "_run_differential", inner)
    with pytest.raises(RuntimeError, match="stop after the snapshot"):
        differential.run_differential(scratch=str(tmp_path / "scratch"), extra_sys_path=[str(tree(tmp_path, 600 * 1024))], module="m",
                                      function="f", base_root=str(tmp_path), post_root=str(tmp_path))
    assert len(seen) == 1


def test_control_a_tree_over_the_budget_is_still_refused_and_names_it(monkeypatch, tmp_path):
    monkeypatch.setattr(differential, "_SNAP_MAX_BYTES", 64 * 1024)
    ob = differential.run_differential(scratch=str(tmp_path / "scratch"), extra_sys_path=[str(tree(tmp_path, 100 * 1024))], module="m",
                                       function="f", base_root=str(tmp_path), post_root=str(tmp_path))
    assert ob.verdict is Verdict.UNVERIFIED and "exceeds 65536 bytes; snapshot refused" in ob.stop_reason, ob.stop_reason


def test_both_limits_keep_their_values_and_neither_name_is_assigned_twice():
    assert (differential._SNAP_MAX_BYTES, differential._RECV_SNAP_MAX_BYTES) == (TREE_BUDGET, 524288)
    body = ast.parse(Path(differential.__file__).read_text()).body
    names = [t.id for n in body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)]
    assert names.count("_SNAP_MAX_BYTES") == 1 and names.count("_RECV_SNAP_MAX_BYTES") == 1
