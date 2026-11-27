# SPDX-License-Identifier: Apache-2.0
"""The checkers' projection of the immutable, add-only FeedbackInput .

FeedbackInput can only ADD to the verification domain (unknowns, callers, seeds, pins); a removal is not
representable. This view therefore can only add refusals and inputs: never relax anything. A pin or seed that cannot
be parsed is a named NOT_DERIVED obligation (fail closed), never silently dropped. Witnesses the checkers find are
collected here for the caller to hand to L5 (L3 never writes feedback).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..contract.feedback import FeedbackInput
from ..contract.legacy import Obligation, Verdict


@dataclass(frozen=True)
class Pinned:
    args: tuple
    kwargs: dict
    expected: dict | None = None
    env: dict | None = None
    record_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Constraints:
    """Read by attribute by the differential: same names as the legacy feedback constraint object."""

    pinned_inputs: tuple[Pinned, ...]
    disallow_exception_widening: bool
    source_feedback_ids: tuple[str, ...]


def _pinned(input_json: str, expected_json: str | None, record_ids: tuple[str, ...] = ()) -> Pinned:
    inp = json.loads(input_json)
    exp = json.loads(expected_json) if expected_json not in (None, "", "null") else None
    if not isinstance(inp, dict) or "args" not in inp:
        raise ValueError("input is not an object with `args`")
    from hlith.contract.codec import decode_call_values  # typed float tags back to the recorded floats (bit-exact)

    return Pinned(tuple(decode_call_values(inp["args"])), dict(decode_call_values(inp.get("kwargs") or {})), exp, inp.get("env"), record_ids)


class FeedbackView:
    def __init__(self, fb: FeedbackInput, *, account: object | None = None) -> None:
        self.fb = fb
        self.account = account
        self.witnesses: dict[str, object] = {}
        self._bad: list[tuple[str, str]] = []
        self._guard_construct_wheres: dict[str, str] = {}
        self._pre_only_ids: set[str] = set()
        self._by_symbol: dict[str, list[Pinned]] = {}
        sources: dict[tuple[str, str, str], list[str]] = {}
        for sym, inp, exp, rid in getattr(fb, "input_sources", ()):
            sources.setdefault((sym, inp, exp), []).append(rid)
        for sym, inp in fb.seeds:
            self._add(sym, inp, None, tuple(sources.get((sym, inp, ""), ())))
        for sym, inp, exp in fb.pins:
            self._add(sym, inp, exp, tuple(sources.get((sym, inp, exp), ())))

    def _live_construct_keys(self) -> dict[tuple[str, str], set[str]]:
        """(where, node sha) of every construct in the account -> the sides it is live on."""
        keys: dict[tuple[str, str], set[str]] = {}
        if self.account is None:
            return keys
        for uc in getattr(self.account, "unresolved_constructs", ()) or ():
            sha = str(getattr(uc, "node_sha256", "") or "")
            if not sha:
                continue
            fp = str(getattr(uc, "file_path", "") or "")
            ln = getattr(uc, "line_number", None)
            side = str(getattr(uc, "side", "post"))
            if ln is not None:
                keys.setdefault((f"{fp}:{ln}", sha), set()).add(side)
            if fp:
                keys.setdefault((fp, sha), set()).add(side)
        return keys

    def covered_construct_ids(self, covered_wheres: set[str], removed_wheres: set[str] = frozenset()) -> set[str]:
        """Obligation ids of stored guard constructs superseded by observed delta guard coverage, or (`removed_wheres`, a HELD
        removal certificate) by the certified removal of the guard: only when every live match is on the removed (pre) side."""
        return ({oid for oid, where in self._guard_construct_wheres.items() if where in covered_wheres}
                | {oid for oid, where in self._guard_construct_wheres.items()
                   if where in removed_wheres and oid in self._pre_only_ids})

    def _add(self, symbol: str, input_json: str, expected_json: str | None, record_ids: tuple[str, ...]) -> None:
        try:
            self._by_symbol.setdefault(symbol, []).append(_pinned(input_json, expected_json, record_ids))
        except (ValueError, TypeError, KeyError) as e:
            self._bad.append((symbol, f"{type(e).__name__}: {e}"))

    def not_derived(self) -> tuple[Obligation, ...]:
        out = []
        self._guard_construct_wheres.clear()
        self._pre_only_ids.clear()
        for i, u in enumerate(self.fb.extra_unknowns):
            out.append(Obligation(f"feedback-unknown:{i}", u.where or "*", "a recorded unresolved construct is resolved",
                                  Verdict.NOT_DERIVED, stop_reason=f"{u.code.value} at {u.where}: {u.detail}"[:400]))
        live = self._live_construct_keys()
        for i, item in enumerate(getattr(self.fb, "constructs", ()) or ()):
            where, c_kind, node_sha, fid = str(item[0]), str(item[1]), str(item[2]), str(item[3])
            if (where, node_sha) not in live:
                continue
            oid = f"feedback-construct:{i}"
            if c_kind == "unsupported_entry_guard":
                self._guard_construct_wheres[oid] = where
                if live[(where, node_sha)] == {"pre"}:
                    self._pre_only_ids.add(oid)
            out.append(Obligation(
                oid,
                where or "*",
                "a recorded unresolved construct is resolved",
                Verdict.NOT_DERIVED,
                stop_reason=f"{c_kind} at {where}: unchanged node_sha256={node_sha} ({fid})"[:400],
            ))
        for i, (sym, why) in enumerate(self._bad):
            out.append(Obligation(f"feedback-invalid:{i}", sym, "feedback pins and seeds are well formed",
                                  Verdict.NOT_DERIVED, stop_reason=f"a pinned/seed input of {sym} cannot be parsed: {why}"[:400]))
        return tuple(out)

    def constraints(self, symbol: str) -> Constraints | None:
        pins = self._by_symbol.get(symbol)
        if not pins:
            return None
        ids = tuple(sorted(
            {r.record_id for r in self.fb.records if r.symbol == symbol}
            | {rid for p in pins for rid in p.record_ids}
        ))
        return Constraints(tuple(pins), any(p.expected is not None for p in pins), ids)

    def pinned_obligation(self, base, post, symbol):  # pins are enforced inside the differential through constraints()
        return None

    def note_witness(self, symbol: str, witness) -> None:
        if witness:
            self.witnesses[symbol] = witness
