"""artifact['target_python'] is what the CONFINED differential worker reported about itself: never inferred, never host-probed, absent when nothing reported."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hlith import differential
from hlith.operator.target_python import observed_target_python

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "src" / "hlith" / "hlith.schema.json").read_text())["properties"]["target_python"]


def _side(v=(3, 14, 2), exe="/x/py", impl="cpython"):
    return {"version": list(v), "implementation": impl, "executable": exe}


def test_absent_when_no_evaluator_reported(monkeypatch):
    monkeypatch.setattr(differential, "observed_interpreters", lambda: [])
    assert observed_target_python() is None


def test_newest_entry_post_side_is_reported_in_the_documented_shape(monkeypatch):
    monkeypatch.setattr(differential, "observed_interpreters", lambda: [
        {"scratch": "a", "pre": _side((3, 11, 0)), "post": _side((3, 11, 0))},
        {"scratch": "b", "pre": _side((3, 13, 9), "/y/py"), "post": _side((3, 13, 9), "/y/py")},
    ])
    tp = observed_target_python()
    assert tp == {"executable": "/y/py", "version": "3.13.9", "implementation": "cpython", "observed_in": "confined-differential-worker"}
    assert set(tp) == set(SCHEMA["required"]) and SCHEMA["properties"]["observed_in"]["const"] == tp["observed_in"]


def test_falls_back_to_the_pre_side_and_ignores_malformed_reports(monkeypatch):
    monkeypatch.setattr(differential, "observed_interpreters", lambda: [
        {"scratch": "c", "pre": _side((3, 12, 1)), "post": None},
        {"scratch": "d", "pre": {"version": ["3", "x"], "executable": ""}, "post": {"version": [3, 14], "executable": "/z"}},
    ])
    tp = observed_target_python()
    assert tp and tp["version"] == "3.12.1"


@pytest.mark.parametrize("bad", [None, {}, {"version": [3, 14, 2]}, {"version": [3, 14, 2], "executable": 5}])
def test_nothing_is_invented_from_an_unusable_report(monkeypatch, bad):
    monkeypatch.setattr(differential, "observed_interpreters", lambda: [{"scratch": "e", "pre": bad, "post": bad}])
    assert observed_target_python() is None
