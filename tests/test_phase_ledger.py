# SPDX-License-Identifier: Apache-2.0
"""Per-stage work accounting (generation / replay / instrumentation / test_execution) with a budget per stage,
so one stage cannot burn the case deadline. Units are work units charged by the stage's own meter (the driver's rlimit meter, an
evaluation count), never the wall clock: the same charges give the same report."""
import pytest

from hlith.phase_ledger import STAGES, PhaseLedger, StageExhausted

SHARES = {"generation": 400, "replay": 300, "instrumentation": 100, "test_execution": 200}


def test_stages_are_the_four_named_ones():
    assert STAGES == ("generation", "replay", "instrumentation", "test_execution")


def test_a_stage_cannot_exceed_its_own_budget_and_later_stages_keep_their_shares():
    led = PhaseLedger(1000, SHARES)
    with led.stage("generation"):
        led.charge("generation", 250)
        assert led.remaining("generation") == 150
        with pytest.raises(StageExhausted):
            led.charge("generation", 500)  # would take 750 > 400
    rep = {r["stage"]: r for r in led.report()}
    assert rep["generation"]["state"] == "exhausted" and rep["generation"]["used"] == 400  # capped at its budget, recorded
    assert led.remaining("replay") == 300 and led.remaining("test_execution") == 200  # untouched by the exhausted stage
    with led.stage("replay"):
        led.charge("replay", 100)
    assert {r["stage"]: r["state"] for r in led.report()}["replay"] == "ok"


def test_total_is_never_exceeded_and_shares_may_not_oversubscribe():
    with pytest.raises(ValueError):
        PhaseLedger(500, SHARES)
    led = PhaseLedger(1000, SHARES)
    for s in STAGES:
        with led.stage(s):
            try:
                led.charge(s, 10**6)
            except StageExhausted:
                pass
    assert sum(r["used"] for r in led.report()) <= 1000


def test_skip_and_not_run_are_explicit_records_with_reasons():
    led = PhaseLedger(1000, SHARES)
    led.skip("instrumentation", "decorated property: descriptor not instrumentable")
    rep = {r["stage"]: r for r in led.report()}
    assert rep["instrumentation"]["state"] == "skipped" and "decorated" in rep["instrumentation"]["reason"]
    assert rep["generation"]["state"] == "not_run" and rep["generation"]["used"] == 0


def test_misuse_is_refused():
    led = PhaseLedger(1000, SHARES)
    with pytest.raises(ValueError):
        led.charge("nonsense", 1)
    with pytest.raises(ValueError):
        led.charge("generation", -1)
    with led.stage("generation"):
        with pytest.raises(ValueError):
            with led.stage("replay"):  # stages do not nest: one meter at a time
                pass


def test_same_charges_give_the_same_report_and_the_report_has_no_clock_in_it():
    def run():
        led = PhaseLedger(1000, SHARES)
        with led.stage("generation"):
            led.charge("generation", 123)
        with led.stage("test_execution"):
            led.charge("test_execution", 77)
        return led.report()

    assert run() == run()
    assert all(set(r) == {"stage", "budget", "used", "state", "reason"} for r in run())


def test_the_driver_reports_its_work_units_for_the_generation_stage():
    from hlith import drive_inputs as di

    cands, why = di.candidates_detailed([("x", "int")], ["x > 3 and x < 9"], want="true", timeout_ms=200)
    units = di.last_call_work_units()
    assert isinstance(units, int) and units >= 0
    led = PhaseLedger(10**7, {"generation": 10**6, "replay": 10**6, "instrumentation": 10**6, "test_execution": 10**6})
    with led.stage("generation"):
        led.charge("generation", units)
    assert {r["stage"]: r for r in led.report()}["generation"]["used"] == units
