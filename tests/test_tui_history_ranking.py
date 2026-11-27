"""review reds against review 43de0036 history ranking (case). Handoff: review copies into tests/ when fixing. Fake data only.

RED C (cap across bases): runs_for spends the 64-run budget base by base, and the legacy <state>/runs base comes FIRST. 64 old legacy
runs therefore hide every run in host/repositories, including the newest one. Rank all bases together, then cap.
RED D (preselection key differs from the display key): _bounded_child_dirs ranks a record whose 'started' is non-finite or missing by
directory mtime (a future mtime ranks first), while run_rows sorts it as started=0 (last). 64 such records take every slot and the
valid newest run disappears; a finite far-future 'started' does the same. Use one key for both, and never rank a claimed future
start (beyond a small skew) above the present.
Controls: a single NaN record among valid runs is kept and sorted last; the newest of several repositories is shown first.
"""
import json
import os
import secrets
import time

import pytest

from hlith.operator.tui import launch

NOW = time.time()
SENTINEL = 424242.5


def _repo_runs(root, n=0):
    return root / "host" / "repositories" / f"repo-{n:024x}" / "runs"


def _run(runs, started, raw=None, mtime=None):
    d = runs / f"launch-{secrets.token_hex(6)}"
    d.mkdir(parents=True)
    meta = json.dumps({"run_id": d.name, "started": SENTINEL if raw else started, "argv": ["x"], "source_repo": "/work/r"})
    if raw:
        meta = meta.replace(json.dumps(SENTINEL), raw)
    (d / "meta.json").write_text(meta)
    (d / "rc").write_text("4\n")
    if mtime is not None:
        for p in (d / "meta.json", d / "rc", d):
            os.utime(p, (mtime, mtime))
    return d


def _ids(root):
    return [r["run_id"] for r in launch.run_rows(root)]


def test_old_legacy_runs_do_not_hide_the_newest_current_run(tmp_path):
    for i in range(64):
        _run(tmp_path / "runs", NOW - 100_000 + i)
    newest = _run(_repo_runs(tmp_path), NOW - 1)
    assert _ids(tmp_path)[:1] == [newest.name]


@pytest.mark.parametrize("hostile", [{"raw": "NaN", "mtime": NOW + 3.15e8}, {"raw": '"soon"', "mtime": NOW + 3.15e8},
                                     {"started": 1e15}], ids=["nan-future-mtime", "string-future-mtime", "far-future-started"])
def test_records_without_a_credible_start_never_displace_a_valid_newer_run(tmp_path, hostile):
    runs = _repo_runs(tmp_path)
    valid = _run(runs, NOW - 5)
    for _ in range(64):
        _run(runs, hostile.get("started", 0), raw=hostile.get("raw"), mtime=hostile.get("mtime"))
    assert valid.name in _ids(tmp_path)


def test_control_one_nan_record_is_kept_and_sorted_last(tmp_path):
    runs = _repo_runs(tmp_path)
    good = [_run(runs, NOW - 30 + i) for i in range(3)]
    bad = _run(runs, 0, raw="NaN", mtime=NOW)
    assert _ids(tmp_path) == [g.name for g in reversed(good)] + [bad.name]


def test_control_newest_of_several_repositories_is_first(tmp_path):
    for r in range(3):
        for i in range(30):
            _run(_repo_runs(tmp_path, r), NOW - 10_000 * (3 - r) + i)
    newest = _run(_repo_runs(tmp_path, 0), NOW - 1)
    assert _ids(tmp_path)[:1] == [newest.name]
