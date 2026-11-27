"""review reds against review 93d6f2b2 history (case). Handoff: review copies into tests/ when fixing. Fake data only, no engine.

RED A: ONE meta.json whose 'started' is non-finite (json.loads accepts NaN / Infinity) makes launch.run_rows raise (int(nan) /
int(inf) in the age computation; status() already sanitises started but run_rows re-reads the raw meta value). The host's 1 s poll
catches every exception as rows=[], so the WHOLE history goes empty and the Offer's records line claims 'none yet · scanned' while
valid runs exist: a false statement about recorded runs.
RED B: past the 64-run cap the history shows an ARBITRARY 64 (os.scandir order, then sorted): launch ids are random hex, so name order
is not time order, and recent runs go missing (observed 5 of the 10 newest), while the records line counts only the shown subset.
Controls: a finite huge 'started' (1e300) is tolerated; <= 64 runs are all shown newest first.
"""
import json
import secrets
import time

import pytest

from hlith.operator.tui import host, launch

REPO = "repo-" + "c" * 24


def _run(runs, started, raw_started=None):
    d = runs / f"launch-{secrets.token_hex(6)}"
    d.mkdir(parents=True)
    meta = json.dumps({"run_id": d.name, "started": started, "argv": ["x"], "source_repo": "/work/r"})
    if raw_started is not None:
        meta = meta.replace(json.dumps(started), raw_started)
    (d / "meta.json").write_text(meta)
    (d / "rc").write_text("4\n")
    return d


def _runs(tmp_path):
    return tmp_path / "host" / "repositories" / REPO / "runs"


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity"])
def test_one_non_finite_started_does_not_blank_the_history(tmp_path, raw):
    runs = _runs(tmp_path)
    good = [_run(runs, time.time() - 30 + i) for i in range(3)]
    _run(runs, 1.0, raw_started=raw)
    rows = launch.run_rows(tmp_path)  # must not raise
    assert {g.name for g in good} <= {r["run_id"] for r in rows}
    assert host._records_summary(rows) != "none yet · scanned"


def test_control_finite_huge_started_is_tolerated(tmp_path):
    runs = _runs(tmp_path)
    good = [_run(runs, time.time() - 30 + i) for i in range(3)]
    _run(runs, 1e300)
    assert {g.name for g in good} <= {r["run_id"] for r in launch.run_rows(tmp_path)}


@pytest.fixture
def hash_order_scandir(monkeypatch):
    """Directory order is filesystem-defined (ext4: hash order; tmpfs: newest first, which hides this bug). Pin a deterministic
    non-chronological order so the result does not depend on where tmp_path lives."""
    import os
    import random

    real = os.scandir

    class _Shuffled:
        def __init__(self, path):
            self._it = real(path)
            self._entries = list(self._it)
            random.Random(7).shuffle(self._entries)

        def __enter__(self):
            return iter(self._entries)

        def __exit__(self, *a):
            self._it.close()

        def __iter__(self):
            return iter(self._entries)

    monkeypatch.setattr(launch.os, "scandir", _Shuffled)


def test_past_the_cap_the_newest_runs_are_the_ones_shown(tmp_path, hash_order_scandir):
    runs = _runs(tmp_path)
    t0 = time.time() - 10_000
    made = [_run(runs, t0 + i * 10) for i in range(100)]
    shown = [r["run_id"] for r in launch.run_rows(tmp_path)]
    assert shown[:10] == [m.name for m in reversed(made[-10:])], "the 10 newest runs must be the first 10 rows"


def test_control_under_the_cap_every_run_is_shown_newest_first(tmp_path):
    runs = _runs(tmp_path)
    t0 = time.time() - 1000
    made = [_run(runs, t0 + i * 10) for i in range(20)]
    assert [r["run_id"] for r in launch.run_rows(tmp_path)] == [m.name for m in reversed(made)]
