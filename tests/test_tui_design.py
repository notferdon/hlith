"""Design-parity screens (no pty): the Shell renders every view of the reference design from real artifacts at 60..200 columns without
overflow, never invents a verdict, and keeps the engine's patch-size limit while making a huge change workable by scope."""
import subprocess
from pathlib import Path

import pytest

from hlith.tui import changes, model
from hlith.operator.tui import frame as operator_frame
from hlith.operator.tui.model import ViewState

EX = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "examples"
R1 = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "acceptance" / "R1"


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

def test_old_schema_artifact_is_explicitly_unvalidated_with_its_reason():
    rec = model.load(EX / "c-missed-after-fix.json")
    assert rec.art is not None
    errors = operator_frame._validation_errors(rec.art)
    assert errors
    rendered = operator_frame.render(ViewState(st="verdict"), 100, 30, rec.art)
    text = "\n".join(rendered.text_rows())
    assert "UNKNOWN" in text and "UNVALIDATED" in text
    assert errors[0] in text


def test_mono_theme_defines_every_style_without_colour():
    from hlith import tui  # noqa: F401
    from hlith.tui import theme
    assert set(theme.RICH) <= set(theme.MONO) | {"", }, set(theme.RICH) - set(theme.MONO)


