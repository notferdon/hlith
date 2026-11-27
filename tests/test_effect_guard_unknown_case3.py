# SPDX-License-Identifier: Apache-2.0
"""effect/api.py: an unsupported entry guard is ONE typed unknown, not also a generic unresolved-call unknown.

review (O3v2-A/A-noapprove/E on the canonical pipeline, rc 11): effect/engine.py mirrors every post-side unresolved
construct as an UnknownEdge ("unresolved construct: <kind>") and _engine_unknowns emitted both the typed
UNSUPPORTED_ENTRY_GUARD unknown AND an UNRESOLVED_CALL unknown for the same guard. A guard-covered obligation can
discharge only the typed one, so a guard exactly described by an approved delta could never land."""
from hlith.effect.api import _engine_unknowns
from hlith.contract.effects import GapCode

class _C:
    def __init__(self, **k):
        self.__dict__.update(k)


def test_engine_unknowns_keeps_unknown_edges_that_are_not_a_typed_guard_duplicate():
    guard = _C(kind="unsupported_entry_guard", side="post", file_path="m.py", line_number=2,
               caller_qualified_name="m.f", target_qualified_name=None, source='if "\\0" in s:')
    detail = _C(unresolved_constructs=[guard],
                unknown_edges=[_C(file_path="m.py", line_number=2, side="post", caller_qualified_name="m.f",
                                  target_qualified_name="m.f", reason="unresolved construct: unsupported_entry_guard"),
                               _C(file_path="m.py", line_number=9, side="post", caller_qualified_name="m.f",
                                  target_qualified_name="UNKNOWN", reason="unresolved construct: dynamic_call")],
                callee_unresolved_constructs=[], opaque_caller_guards=[], modified_module_level=[])
    codes = [(u.code, u.where) for u in _engine_unknowns(detail)]
    assert (GapCode.UNSUPPORTED_ENTRY_GUARD, "m.py:2") in codes
    assert (GapCode.UNRESOLVED_CALL, "m.py:2") not in codes  # the duplicate of the typed guard
    assert (GapCode.UNRESOLVED_CALL, "m.py:9") in codes  # an unrelated unknown edge is kept
