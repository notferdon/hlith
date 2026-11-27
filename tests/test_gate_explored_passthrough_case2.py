# SPDX-License-Identifier: Apache-2.0
"""review F2 route (design review concurrence 2026-11-21): thin pass-through of the gate's explored inputs, derive.py -> pipeline.py ->
LandingProbeContext.gate_explored. No accessor / other trees / reader failure = {} (UNKNOWN: L5 keeps its old order); never a verdict."""
from __future__ import annotations

import inspect
from types import SimpleNamespace

SUMMARY = {"target": "pkg.m.f", "calls": 3, "truncated": False, "params": []}


def _arm(monkeypatch, reader):
    from hlith import derive, differential
    monkeypatch.setattr(differential, "read_explored_inputs", reader, raising=False)
    monkeypatch.setitem(derive._EXPLORED_BY_SYMBOL, "key", ("/b", "/p"))
    monkeypatch.setitem(derive._EXPLORED_BY_SYMBOL, "by_symbol", {})
    return derive


def test_recorded_per_symbol_for_the_same_trees_only(monkeypatch, tmp_path):
    derive = _arm(monkeypatch, lambda scratch: dict(SUMMARY, scratch=scratch))
    derive._note_explored("pkg.m.f", tmp_path)
    got = derive.explored_inputs_for("/b", "/p")
    assert got == {"pkg.m.f": dict(SUMMARY, scratch=str(tmp_path))}
    got["pkg.m.f"]["calls"] = 99  # a deep copy: callers cannot mutate the record
    assert derive.explored_inputs_for("/b", "/p")["pkg.m.f"]["calls"] == 3
    assert derive.explored_inputs_for("/b", "/other") == {}  # other trees: unknown, never a stale record


def test_absent_none_or_failing_reader_records_nothing(monkeypatch, tmp_path):
    derive = _arm(monkeypatch, lambda scratch: None)  # None = the gate did not explore / file absent
    derive._note_explored("pkg.m.f", tmp_path)

    def boom(scratch):
        raise OSError("x")
    monkeypatch.setattr(derive.differential, "read_explored_inputs", boom)
    derive._note_explored("pkg.m.g", tmp_path)
    monkeypatch.delattr(derive.differential, "read_explored_inputs")
    derive._note_explored("pkg.m.h", tmp_path)
    assert derive.explored_inputs_for("/b", "/p") == {}


def test_pipeline_passes_it_into_the_landing_context(monkeypatch):
    from hlith.operator import pipeline
    derive = _arm(monkeypatch, lambda scratch: dict(SUMMARY))
    derive._note_explored("pkg.m.f", "/s")
    assert pipeline._gate_explored(SimpleNamespace(path="/b"), SimpleNamespace(path="/p")) == {"pkg.m.f": SUMMARY}
    assert pipeline._gate_explored(SimpleNamespace(path="/x"), SimpleNamespace(path="/p")) == {}
    assert pipeline._gate_explored(object(), object()) == {}  # any failure: unknown
    src = inspect.getsource(pipeline)
    assert "gate_explored=_gate_explored(base, post)" in src


def test_derive_core_resets_and_reads_before_scratch_removal():
    from hlith import derive
    src = inspect.getsource(derive.make_derive)
    assert "_EXPLORED_BY_SYMBOL.update(key=(str(base_dir), str(post_dir)), by_symbol={})" in src
    i_note = src.index("_note_explored(mc.qualified_name, dscratch)")
    assert i_note < src.index("differential.read_observations(str(dscratch))")  # same place the scratch is already read
