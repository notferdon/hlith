"""The pre-run Blocked state (UNABLE TO ASSESS · boundary unavailable) is wired from the SAME readiness function the start path uses: a block can only REMOVE a start.
The end-to-end 0-starts / no-launch-dir / flip-after-paint checks are review's probe_boundary.py (real pty, fake launcher); these are the pure parts."""
from pathlib import Path

from hlith.operator.tui import frame, host
from hlith.operator.tui.model import ViewState

READY = ({"boundary": {"status": "ready", "tone": "ok", "detail": "landlock abi 8 · user namespaces"},
          "python": {"status": "ready", "tone": "ok", "path": "/p/python", "version": "3.12.7", "source": "--target-python"}}, None)


def _unavailable(causes=None):
    boundary = {"status": "unavailable", "tone": "bad", "detail": "landlock not reported by this kernel"}
    if causes is not None:
        boundary["causes"] = causes
    return ({**READY[0], "boundary": boundary}, None)


def test_ready_boundary_blocks_nothing(monkeypatch):
    monkeypatch.setattr(host, "_readiness", lambda repo, py: READY)
    assert host._boundary_block({"repo": {"path": "."}}) is None


def test_unavailable_boundary_returns_cause_rows_and_no_reason(monkeypatch):
    monkeypatch.setattr(host, "_readiness", lambda repo, py: _unavailable())
    block = host._boundary_block({"repo": {"path": "."}})
    assert block is not None and block["blocked"]["kind"] == "boundary" and "reason" not in block["blocked"]
    labels = {row["label"]: row for row in block["blocked"]["cause"]}
    assert labels["landlock"]["status"] == "unavailable" and labels["user ns"]["status"] == "not probed"  # claims nothing it did not read


def test_the_probe_reads_a_userns_restriction_and_names_its_command(monkeypatch):
    causes = host._boundary_causes(-1, False)
    monkeypatch.setattr(host, "_read_small", lambda path: "1" if path.endswith("apparmor_restrict_unprivileged_userns") else "landlock,lockdown")
    causes = host._boundary_causes(-1, False)
    assert causes[0]["detail"] == "not in the active LSM list" or causes[0]["detail"] == "not reported by this kernel"
    assert causes[1]["status"] == "blocked" and "apparmor_restrict_unprivileged_userns = 1" in causes[1]["detail"]
    assert host._boundary_recovery_command(causes) == "sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0"
    assert host._boundary_recovery_command([]) == "Re-check the host boundary"


def test_the_blocked_screen_for_a_boundary_cause_is_the_unable_to_assess_body(monkeypatch):
    monkeypatch.setattr(host, "_readiness", lambda repo, py: _unavailable())
    block = host._boundary_block({"repo": {"path": "."}})
    context = {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "change": {}, **block}
    text = " ".join("\n".join(frame.render(ViewState(st="blocked", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=context).text_rows()).split())
    assert "UNABLE TO ASSESS" in text and "boundary unavailable" in text and "No check ran and nothing was written" in text
    assert "REPOSITORY NOT INSPECTED" not in text and "Re-check readiness" in text


def test_a_run_that_could_not_be_followed_does_not_claim_no_check_was_started():
    context = {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "change": {}, "launch_id": "launch-aaaaaaaaaaaa",
               "blocked": {"kind": "run", "reason": "no readable meta.json in the run directory"}}
    rendered = frame.render(ViewState(st="blocked", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=context)
    text = " ".join("\n".join(rendered.text_rows()).split())
    assert "RUN COULD NOT BE FOLLOWED" in text and "launch-aaaaaaaaaaaa" in text and "no check was started" not in text
    assert "run could not be followed" in rendered.text_rows()[-2]  # the status line names this cause, not 'boundary unavailable'
    assert Path  # keep the import used


def _ctx(kind=None, reason=None, **extra):
    blocked = {"kind": kind, **({"reason": reason} if reason else {})}
    return {"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "change": {}, "blocked": blocked, **extra}


def _render(context, cols=100, rows=30):
    return frame.render(ViewState(st="blocked", cols=cols, rows=rows), cols, rows, {"run": {}, "obligations": []}, context=context)


def test_the_pre_run_boundary_header_says_not_started_not_exit_4(monkeypatch):
    monkeypatch.setattr(host, "_readiness", lambda repo, py: _unavailable())
    block = host._boundary_block({"repo": {"path": "."}})
    rows = _render({"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "change": {}, **block}).text_rows()
    head = next(r for r in rows if "UNABLE TO ASSESS" in r and "boundary unavailable" in r)
    assert head.rstrip().endswith("not started") and "exit 4" not in head  # nothing ran, so nothing exited


def test_the_sample_blocked_frame_keeps_the_oracles_literal_exit_4():
    rows = _render({"repo": {"name": "requests", "branch": "trial", "head": "f6707042" + "0" * 32, "path": "."}, "change": {}, "blocked": {}}).text_rows()
    assert any("UNABLE TO ASSESS" in r and r.rstrip().endswith("exit 4") for r in rows)


def test_a_run_that_could_not_be_followed_wears_no_decision_not_the_boundary_chip():
    for cols, rows in ((100, 30), (80, 24)):
        text_rows = _render(_ctx("run", "no readable meta.json in the run directory", launch_id="launch-aaaaaaaaaaaa"), cols, rows).text_rows()
        assert "NO DECISION" in text_rows[-2] and "UNABLE TO ASSESS" not in "\n".join(text_rows), (cols, text_rows[-2])
        assert "run could not be followed" in text_rows[0]
    # the boundary state keeps its own chip
    boundary = _render(_ctx("boundary", None, readiness={}, **{})).text_rows()
    assert "UNABLE TO ASSESS" in boundary[-2]


def test_blocked_states_render_in_a_too_small_terminal_without_crashing():
    for ctx in (_ctx("run", "x"), _ctx("boundary", None), _ctx(None, "repository could not be read")):
        for cols, rows in ((50, 10), (30, 6)):
            assert _render(ctx, cols, rows).text_rows()


def test_the_run_could_not_be_followed_footer_has_no_recheck_and_r_is_inert():
    from hlith.operator.tui import reduce

    rows = _render(_ctx("run", "no readable meta.json in the run directory", launch_id="launch-aaaaaaaaaaaa", blocked_extra=None)).text_rows()
    foot = rows[-1]
    assert "c copy launch folder" in foot and "d view change" in foot and "esc home" in foot
    assert "re-check" not in foot and "copy command" not in foot
    assert "Re-check readiness" not in "\n".join(rows)
    vs = ViewState(st="blocked", cols=100, rows=30)
    assert reduce.reduce(vs, "key:r") == vs  # inert: no state change, so no way back to a Claim from here


def test_a_repository_blocked_state_offers_no_recheck_either():
    foot = _render(_ctx(None, "repository could not be read")).text_rows()[-1]
    assert "re-check" not in foot and "copy command" not in foot and "q quit" in foot and "esc" not in foot


def test_the_boundary_state_keeps_recheck_and_copy_command(monkeypatch):
    monkeypatch.setattr(host, "_readiness", lambda repo, py: _unavailable())
    block = host._boundary_block({"repo": {"path": "."}})
    foot = _render({"repo": {"name": "r", "branch": "main", "head": "a" * 40, "path": "."}, "change": {}, **block}).text_rows()[-1]
    assert "r re-check" in foot and "c copy command" in foot


def test_every_screen_that_advertises_esc_can_leave_and_the_ones_that_cannot_do_not_advertise_it():
    """A screen's footer must not offer 'esc' where the host would swallow it. The host re-forces st='blocked' while a repository/artifact cause stands, so those
    two kinds offer 'q quit' only; every other screen below leaves through reduce's parent map (the history-return paths are covered by the Esc-chain pty tests)."""
    from hlith.operator.tui import reduce

    for st in ("selection", "claim", "verdict", "artifact-unavailable", "run-ended-no-decision", "run-lost", "blocked", "history"):
        vs = ViewState(st=st, cols=100, rows=30)
        assert reduce.reduce(vs, "key:esc").st != st, st
    for kind in ("run", "boundary"):  # these blocked kinds advertise esc and must return to the Offer (host: Esc drops the cause)
        ctx = _ctx(kind, "x" if kind == "run" else None, **({} if kind == "run" else {"readiness": {}}))
        assert "esc home" in _render(ctx).text_rows()[-1], kind
    for ctx in (_ctx(None, "repository could not be read"), _ctx("artifact", "unreadable artifact")):  # nothing to return to: no esc, no Back button
        rows = _render(ctx).text_rows()
        assert "esc" not in rows[-1] and "q quit" in rows[-1], rows[-1]
        assert "[ Back ]" not in "\n".join(rows)
