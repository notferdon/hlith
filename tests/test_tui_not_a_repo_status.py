"""TUI behavior (review R3 walkthrough): the not-a-git-repository screen's status line must not read 'not recorded@not recorded'."""
from hlith.operator.tui import frame
from hlith.operator.tui.model import ViewState


def _status(cols, rows):
    ctx = {"blocked": {"kind": "repository", "reason": "not a git repository"}}
    out = frame.render(ViewState(st="blocked", cols=cols, rows=rows), cols, rows, {}, context=ctx, color="mono").text_rows()
    return out[-2]


def test_status_line_names_no_repository_instead_of_not_recorded_pairs():
    for cols, rows in ((100, 30), (80, 24), (120, 32)):
        line = _status(cols, rows)
        assert "not recorded@" not in line and "@not recorded" not in line, line
        assert "no repository" in line and "original read-only" in line
