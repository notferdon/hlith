from pathlib import Path
from copy import deepcopy
import sys
from time import perf_counter
import pytest

from _tui_pty import run_pty, strip
from hlith.operator.tui import frame
from hlith.operator.tui.model import ViewState
from hlith.tui import model


ARTIFACT = (Path(__file__).resolve().parents[1] / "docs" / "evidence" / "e1cli" /
            "sigkill-operator-ba04a0c4" / "divergent-artifact.json")


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

def _provenance_lines(artifact, width=120):
    return frame._drill_lines("prov", artifact, {}, width, "refused", 10)


def _line_text(lines):
    return ["".join(segment.text for segment in line) for line in lines]


def test_native_tui_opens_real_e1_artifact_with_provenance_visible():
    rc, raw, _ = run_pty(
        [sys.executable, "-m", "hlith.tui", str(ARTIFACT)],
        keys=["p", "q", "\t", "\n"], rows=30, cols=120,
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    text = strip(raw)

    assert rc == 0
    assert "PROVENANCE" in text
    assert "agent id" in text and "case" in text
    assert "agent desc" in text and "confined StateGraph with checkpoint" in text and "and model provenance" in text  # the value wraps in the inspector
    digest = model.load(ARTIFACT).art["proposer_provenance"]["command_argv_sha256"]
    assert "argv hash" in text and digest[:32] in text and digest[-20:] in text  # the 64-cell hash wraps over two rows, whole


def test_provenance_labels_have_a_visible_separator_from_values():
    artifact = model.load(ARTIFACT).art
    rows = _line_text(_provenance_lines(artifact))

    assert any(row.startswith("agent desc ") for row in rows)
    assert any(row.startswith("argv hash  ") for row in rows)


def test_provenance_drill_bounds_large_untrusted_fields_and_render_time(monkeypatch):
    artifact = deepcopy(model.load(ARTIFACT).art)
    artifact["run"]["thread_id"] = "agent-" + "x" * 1_000_000
    artifact["proposer_provenance"]["agent_id"] = "agent-" + "x" * 1_000_000
    artifact["proposer_provenance"]["counts_as_e1_reason"] = "d" * 1_000_000
    assert frame._validation_errors(artifact) == []

    line_counts = []
    original = frame._drill_lines

    def count_lines(*args, **kwargs):
        lines = original(*args, **kwargs)
        line_counts.append(len(lines))
        return lines

    monkeypatch.setattr(frame, "_drill_lines", count_lines)
    start = perf_counter()
    rendered = frame.render(ViewState(st="verdict", drill="prov"), 80, 24, artifact, color="mono")
    elapsed = perf_counter() - start

    assert elapsed < 0.05
    assert line_counts and max(line_counts) <= 50
    rows = rendered.text_rows()
    assert any("1000000 chars" in row for row in rows)


def test_non_sha256_argv_value_is_not_labelled_as_a_hash():
    artifact = deepcopy(model.load(ARTIFACT).art)
    artifact["proposer_provenance"]["command_argv_sha256"] = "z" * 120
    rows = _line_text(_provenance_lines(artifact))
    hash_rows = [row for row in rows if row.startswith("argv hash")]

    assert hash_rows
    assert any("not a sha256 (120 chars)" in row for row in hash_rows)
    assert not any("z" * 64 in row for row in hash_rows)
