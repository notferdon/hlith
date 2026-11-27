# SPDX-License-Identifier: Apache-2.0
"""Project validated L5 records into an immutable, ADD-ONLY ``FeedbackInput``."""

from __future__ import annotations

from typing import Iterable

from ..contract.codec import canonical_bytes
from ..contract.effects import Unknown
from ..contract.feedback import EMPTY_FEEDBACK, FeedbackInput, FeedbackRecordRef
from ..contract.identities import RunId
from ._legacy import DirectiveKind, FeedbackIntegrityError
from .store import StoredRecord


def _canon_str(obj: object) -> str:
    return canonical_bytes(obj).decode("utf-8")



def project_feedback_input(
    stored_records: Iterable[StoredRecord],
    *,
    required_record_ids: Iterable[str] = (),
    donor_records: Iterable[StoredRecord] = (),
    extra_seeds: Iterable[tuple[str, dict, str]] = (),
) -> FeedbackInput:
    """Build an immutable, add-only ``FeedbackInput`` from validated ``StoredRecord`` items.

    Raises ``FeedbackIntegrityError`` if any required record ID is missing.
    ``extra_seeds`` carries pure cross-symbol domain seeds ``(symbol, input_dict, donor_feedback_id)``
    with no recorded expectation; matching ``donor_records`` supply provenance refs only.
    """
    items = tuple(stored_records)
    donors = tuple(donor_records)
    extras = tuple(extra_seeds)
    direct_ids = {item.record.feedback_id for item in items}
    donor_ids = {item.record.feedback_id for item in donors}
    contributing = {fid for _, _, fid in extras}
    if contributing - donor_ids - direct_ids:
        raise FeedbackIntegrityError("transferred input has no validated donor record")
    missing = sorted(set(required_record_ids) - direct_ids - contributing)
    if missing:
        raise FeedbackIntegrityError(f"missing required feedback record(s): {', '.join(missing)}")
    if not items and not extras:
        return EMPTY_FEEDBACK

    refs: list[FeedbackRecordRef] = []
    extra_unknowns: set[Unknown] = set()  # no producer here any more (constructs moved to `constructs`); kept for the contract
    constructs: set[tuple[str, str, str, str]] = set()
    extra_callers: set[str] = set()
    seeds: set[tuple[str, str]] = set()
    pins: set[tuple[str, str, str]] = set()
    input_sources: set[tuple[str, str, str, str]] = set()

    for item in sorted(items, key=lambda s: s.record.feedback_id):
        rec = item.record
        source_run: RunId = item.validated_run_id if item.validated_run_id is not None else RunId(rec.source_run_id)
        primary_symbol = rec.target_symbols[0]
        refs.append(
            FeedbackRecordRef(
                record_id=rec.feedback_id,
                source_run_id=source_run,
                symbol=primary_symbol,
                kind=rec.directive_kind.value,
                sha256=item.record_sha256,
            )
        )
        payload = rec.directive_payload
        kind = rec.directive_kind
        if kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE:
            inp_s = _canon_str(payload["input"])
            exp_s = _canon_str(payload["expected"])
            for sym in rec.target_symbols:
                pins.add((sym, inp_s, exp_s))
                seeds.add((sym, inp_s))
                input_sources.update(((sym, inp_s, "", rec.feedback_id), (sym, inp_s, exp_s, rec.feedback_id)))
        elif kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT:
            for raw_inp in payload["pinned_inputs"]:
                inp_s = _canon_str(raw_inp)
                for sym in rec.target_symbols:
                    seeds.add((sym, inp_s))
                    input_sources.add((sym, inp_s, "", rec.feedback_id))
        elif kind is DirectiveKind.ORACLE_REGRESSION:
            inp_s = _canon_str(payload["input"])
            exp_s = _canon_str(payload["expected"])
            for sym in rec.target_symbols:
                pins.add((sym, inp_s, exp_s))
                seeds.add((sym, inp_s))
                input_sources.update(((sym, inp_s, "", rec.feedback_id), (sym, inp_s, exp_s, rec.feedback_id)))
            for test_node in payload.get("tests", ()):
                extra_callers.add(str(test_node))
        elif kind is DirectiveKind.NOT_DERIVED_CONSTRUCT:
            # design plan: a stored construct is a live-matchable directive, not an unconditional unknown (that made every later
            # run in this state dir blocked forever, even after the construct was fixed). L3 blocks only on a live node_sha256 match.
            c_kind = str(payload.get("construct_kind", "other"))
            loc = str(payload.get("location", primary_symbol))
            sha = str(payload.get("node_sha256", ""))
            constructs.add((loc, c_kind, sha, rec.feedback_id))

    used_extra_donor_ids: set[str] = set()
    for sym, raw_inp, donor_fid in extras:
        inp_s = _canon_str(raw_inp)
        seeds.add((sym, inp_s))
        input_sources.add((sym, inp_s, "", donor_fid))
        used_extra_donor_ids.add(donor_fid)

    ref_ids = {r.record_id for r in refs}
    for item in sorted(donors, key=lambda s: s.record.feedback_id):
        rec = item.record
        if rec.feedback_id in ref_ids or rec.feedback_id not in used_extra_donor_ids:
            continue
        source_run = item.validated_run_id if item.validated_run_id is not None else RunId(rec.source_run_id)
        refs.append(
            FeedbackRecordRef(
                record_id=rec.feedback_id,
                source_run_id=source_run,
                symbol=rec.target_symbols[0],
                kind=rec.directive_kind.value,
                sha256=item.record_sha256,
            )
        )
        ref_ids.add(rec.feedback_id)
    refs.sort(key=lambda r: r.record_id)

    return FeedbackInput(
        records=tuple(refs),
        extra_unknowns=tuple(sorted(extra_unknowns, key=lambda u: (u.code.value, u.where, u.detail))),
        extra_callers=tuple(sorted(extra_callers)),
        seeds=tuple(sorted(seeds)),
        pins=tuple(sorted(pins)),
        input_sources=tuple(sorted(input_sources)),
        constructs=tuple(sorted(constructs)),
    )
