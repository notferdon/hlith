import json
import re
from pathlib import Path

import pytest

from hlith.tui import history, model

EX = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "examples"
FC = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "evidence-case-20261113"


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_three_real_records_get_the_engines_own_labels():
    a, b, c = (model.load(EX / n) for n in ("a-admit.json", "b-refusal.json", "c-missed.json"))
    assert [model.decision(r.art)[0] for r in (a, b, c)] == ["LANDED", "REFUSED · REFUTED", "LANDED"]
    assert b.usable and "u:p@example.com" in " ".join(o["witness"] or "" for o in model.blocking(b.art))
    assert model.blocking(a.art) == [] and c.note.startswith("HISTORIC FALSE ADMISSION")  # the miss is labelled, not hidden
    after = model.load(EX / "c-missed-after-fix.json")
    assert model.decision(after.art)[0] == "REFUSED · REFUTED" and "o='é'" in model.blocking(after.art)[0]["witness"]


def test_unknown_outcome_is_not_guessed(tmp_path):
    art = json.loads((EX / "a-admit.json").read_text())
    art["outcome"], art["exit_status"] = "weird", 99
    p = tmp_path / "w.json"
    p.write_text(json.dumps(art))
    r = model.load(p)
    assert model.decision(r.art)[0].startswith("UNKNOWN") and r.status == "schema-invalid"


def test_history_discovers_and_orders_newest_first(tmp_path):
    recs = history.discover([EX])
    assert [r.path.name for r in recs][0] == "c-missed-after-fix.json" and len(recs) == 4
    assert history.discover([tmp_path / "nope.json"])[0].status == "missing"
    assert history.discover([tmp_path]) == []


def _synthetic(outcome, rc, blocking):
    r = model.load(EX / "b-refusal.json")
    art = json.loads(json.dumps(r.art))
    art["outcome"], art["exit_status"] = outcome, rc
    art["blocking"] = [b["id"] for b in blocking]
    art["obligations"] = blocking
    return model.Record(r.path, "ok", art)


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_runs_across_repositories(tmp_path):
    import time

    from hlith.tui import launch
    st = tmp_path / "state"
    for i, (name, art) in enumerate((("alpha", "b-refusal.json"), ("beta", "a-admit.json"))):
        d = st / "runs" / f"ui-2026111{i}T000000-aaa{i}"
        d.mkdir(parents=True)
        (d / "meta.json").write_text(json.dumps({"run_id": d.name, "started": time.time() - 100 + i, "source_repo": f"/work/{name}", "label": f"change {i}", "pid": 1}))
        (d / "rc").write_text("10\n" if i == 0 else "0\n")
        (d / "out.json").write_text((EX / art).read_text())
    rows = launch.run_rows(st)
    assert [r["repo"] for r in rows] == ["/work/beta", "/work/alpha"] or [r["repo"] for r in rows] == ["/work/alpha", "/work/beta"]
    by = {Path(r["repo"]).name: r for r in rows}
    assert by["alpha"]["decision"] == "REFUSED · REFUTED" and by["beta"]["decision"] == "LANDED \u00b7 landing target not recorded" and by["alpha"]["label"] == "change 0"
    assert "alpha" in launch.run_row_text(by["alpha"]) and "REFUSED" in launch.run_row_text(by["alpha"])


