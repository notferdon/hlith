# SPDX-License-Identifier: Apache-2.0
"""O3 intent semantics.

Intent only selects WHICH behaviour must be proved. It never relaxes anything:
* the approval must cover the COMPLETE declared delta set: an approval of A never lands A+B (exact set digest);
* an approval hash is not a verdict: an unconfirmed set yields an UNVERIFIED `deltas-confirmed` obligation;
* coverage diagnostics (`guard-covered`, `guard-removal-covered`) are never an independent HELD: they stay HELD only
  when the intent is confirmed AND the differential of the same target is HELD, otherwise they are UNVERIFIED.

`canonical_delta_set` / `delta_set_sha256` are the contract's single definition (hlith.contract.effects).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from ..contract.effects import canonical_delta_set, delta_set_sha256  # noqa: F401  (the contract's single definition)
from ..contract.legacy import Obligation, Verdict

DIAGNOSTIC_PREFIXES = ("guard-covered:", "guard-removal-covered:")


@dataclass(frozen=True)
class Confirmation:
    confirmer: str | None
    delta_set_sha256: str
    approved_sha256: str | None
    matched: bool
    reason: str | None = None


@dataclass(frozen=True)
class IntentDeclaration:
    """The operator's intended-change claims for ONE run and the digest the human approved (None = not approved)."""

    deltas: tuple[dict, ...] = ()
    approved_set_sha256: str | None = None

    def confirmation(self) -> Confirmation | None:
        """None when no delta is claimed and no approval digest is supplied. Computed from the deltas NOW."""
        if not self.deltas:
            if self.approved_set_sha256 is not None:
                return Confirmation(
                    None,
                    delta_set_sha256(()),
                    self.approved_set_sha256,
                    False,
                    "approved delta-set sha256 was given without any declared delta claims",
                )
            return None
        sha = delta_set_sha256(self.deltas)
        if self.approved_set_sha256 is None:
            return Confirmation(None, sha, None, False,
                                "delta claims have no independent confirmer (approval sha256 not given)")
        if self.approved_set_sha256.lower() != sha:
            return Confirmation(None, sha, self.approved_set_sha256, False,
                                "approved delta-set sha256 does not match the proposed delta set")
        return Confirmation("human-approval", sha, self.approved_set_sha256, True)


def _invalid_delta_reason(deltas: Sequence[dict]) -> str | None:
    seen: set[str] = set()
    for d in deltas:
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or not isinstance(d.get("symbol"), str):
            return "a delta claim lacks a string `id` or `symbol`"
        if d["id"] in seen:
            return f"duplicate delta id {d['id']!r}"
        seen.add(d["id"])
    return None


_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


class ApprovalBindingError(ValueError):
    """The human-entered approval cannot be bound to the recorded deltas. `code` is one of
    bad_hash_format | no_deltas | invalid_deltas | hash_mismatch. Raised BEFORE any obligation is judged: the caller
    maps it to its own boundary refusal; it never carries a verdict."""

    def __init__(self, code: str, text: str, *, expected: str | None = None, approved: str | None = None):
        super().__init__(text)
        self.code, self.expected, self.approved = code, expected, approved


@dataclass(frozen=True)
class BoundApproval:
    """A hash that equals the canonical digest of exactly these deltas. It is authorization, never evidence: it only
    feeds `IntentDeclaration`, and `deltas-confirmed` is still one obligation among the gate's all-HELD set."""

    deltas: tuple[dict, ...]
    delta_set_sha256: str
    intent: IntentDeclaration


def bind_approval(deltas: Sequence[dict], approved_hex: object, *, strict: bool = True) -> BoundApproval:
    """Bind an operator-entered 64-hex digest to a thread's OWN recorded (already validated) delta list.

    Pure: no I/O, no verdict. The digest is the contract's single definition (`delta_set_sha256`); this function never
    computes another one. Completeness of coverage and preservation outside the delta are NOT decided here: they come from
    the confined differential and the coverage diagnostics inside the gate."""
    if not isinstance(approved_hex, str) or not _HEX64.fullmatch(approved_hex):
        raise ApprovalBindingError("bad_hash_format", "the approval must be exactly 64 hexadecimal characters")
    if not deltas:
        raise ApprovalBindingError("no_deltas", "the thread records no delta claims, so there is nothing to approve")
    bad = _invalid_delta_reason(deltas)
    if bad:
        raise ApprovalBindingError("invalid_deltas", bad)
    sha = delta_set_sha256(deltas)
    if approved_hex.lower() != sha:
        if not strict:
            # run-route semantics (design review): a well-formed hash of a DIFFERENT set is an unconfirmed intent, not a boundary
            # error; the gate then reports `deltas-confirmed` UNVERIFIED (exit 12) and prints the canonical hash.
            return BoundApproval(tuple(deltas), sha, IntentDeclaration(deltas=tuple(deltas), approved_set_sha256=approved_hex.lower()))
        raise ApprovalBindingError("hash_mismatch", "approved delta-set sha256 does not match the thread's recorded delta set",
                                   expected=sha, approved=approved_hex.lower())
    return BoundApproval(tuple(deltas), sha, IntentDeclaration(deltas=tuple(deltas), approved_set_sha256=sha))


def apply_intent(obligations: Sequence[Obligation], intent: IntentDeclaration) -> tuple[Obligation, ...]:
    """Add the confirmation obligation and demote any coverage diagnostic that is not independently backed."""
    out = list(obligations)
    bad = _invalid_delta_reason(intent.deltas)
    conf = None if bad else intent.confirmation()
    if bad:
        out.append(Obligation("deltas-invalid", "*", "declared deltas are well formed", Verdict.UNVERIFIED, stop_reason=bad))
    elif conf is not None and not conf.matched:
        out.append(Obligation("deltas-confirmed", "*", "proposer delta claims have an independent confirmer",
                              Verdict.UNVERIFIED, stop_reason=conf.reason or "unconfirmed"))
    confirmed = conf is not None and conf.matched
    held_diff = {o.target_symbol for o in out if o.obligation_id.startswith("differential:") and o.verdict is Verdict.HELD}
    result: list[Obligation] = []
    for o in out:
        if o.obligation_id.startswith(DIAGNOSTIC_PREFIXES) and o.verdict is Verdict.HELD:
            if not confirmed or o.target_symbol not in held_diff:
                why = ("the delta set is not confirmed" if not confirmed
                       else f"the differential of {o.target_symbol} is not HELD")
                o = Obligation(o.obligation_id, o.target_symbol, o.claim, Verdict.UNVERIFIED,
                               stop_reason=f"coverage diagnostic is never an independent HELD: {why}"[:300])
        result.append(o)
    return tuple(result)
