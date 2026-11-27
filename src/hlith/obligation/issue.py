# SPDX-License-Identifier: Apache-2.0
"""Assemble and issue the VerificationRecord . The MAC comes only from the VerificationIssuer capability.

L3 holds the issue CAPABILITY (an object whose `issue` signs a record body); it never reads the verifier-issue key
itself and never signs anything else. The record binds run, base/post trees, patch, account digest, target identity,
the derived required scope and the scope actually discharged, the obligation set, per-obligation consumption and the
identity of the checkers' source/dependency/context.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path
from typing import Iterable, Sequence

from ..contract.capabilities import VerificationIssuer
from ..contract.codec import sha256_canonical
from ..contract.effects import EffectAccount
from ..contract.identities import Sha256, TargetIdentity
from ..contract.legacy import Obligation, ObligationSet
from ..contract.obligations import (AccountConsumption, RequiredScope, ScopeDischarge, VerificationRecord,
                                    obligation_set_digest)

# the legacy top-level modules whose bytes ARE (part of) the checkers until they move under obligation/. Everything under
# obligation/ is always included. A missing file is named in the identity, never skipped.
_LEGACY_CHECKERS = (
    "derive.py", "differential.py", "z3_binding.py", "drive_inputs.py", "drive_objects.py", "delta_cover.py",
    "delta_follow.py", "delta_rel.py", "delta_rel_uf.py", "guard_removed.py", "docstring_check.py", "expected_expr.py",
)


def plain_evidence(evidence) -> tuple[dict, ...]:
    """The non-gating evidence dicts as contract-plain data (the contract encoder rejects floats and unknown types).
    Lossless for str/int/bool/None; a float or any other value is kept as its repr string, never dropped."""
    def rec(v):
        if v is None or isinstance(v, (str, bool, int)):
            return v
        if isinstance(v, dict):
            return {str(k): rec(x) for k, x in v.items()}
        if isinstance(v, (list, tuple, set, frozenset)):
            return [rec(x) for x in (sorted(v, key=repr) if isinstance(v, (set, frozenset)) else v)]
        return repr(v)

    return tuple(rec(e) for e in evidence)


def checker_identity(package_root: Path | None = None, *, extra: Sequence[str] = ()) -> tuple[Sha256, tuple[str, ...]]:
    """(context_identity_sha256, checker_ids): digests of the checker sources and the interpreter/dependency context."""
    root = package_root or Path(__file__).resolve().parent.parent
    ids: list[str] = []
    digests: dict[str, str] = {}
    rels = sorted({p.relative_to(root).as_posix() for p in (root / "obligation").rglob("*.py")} | set(_LEGACY_CHECKERS))
    for rel in rels:
        f = root / rel
        d = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else "missing"
        digests[rel] = d
        ids.append(f"{rel}:{d[:16]}")
    deps: dict[str, str] = {}
    for mod in ("z3", "hypothesis"):
        try:
            m = __import__(mod)
            deps[mod] = str(getattr(m, "get_version_string", lambda: getattr(m, "__version__", "?"))())
        except Exception as e:  # the identity records an absent dependency instead of hiding it
            deps[mod] = f"unavailable:{type(e).__name__}"
    ctx = {"sources": digests, "deps": deps, "python": sys.version.split()[0], "impl": platform.python_implementation(),
           "extra": list(extra)}
    return Sha256(sha256_canonical(ctx)), tuple(ids)


def build_body(*, account: EffectAccount, target: TargetIdentity, required: RequiredScope, discharged: ScopeDischarge,
               obligation_set: ObligationSet, consumption: Sequence[AccountConsumption],
               context_identity: Sha256, checker_ids: Sequence[str], issuer: str) -> VerificationRecord:
    return VerificationRecord(
        run_id=account.run_id, base_tree_oid=account.base_tree_oid, patch_sha256=account.patch_sha256,
        post_tree_oid=account.post_tree_oid, account_sha256=account.account_sha256, target=target,
        required_scope_digest=required.digest, scope_discharge_digest=discharged.digest,
        obligation_set_sha256=obligation_set_digest(obligation_set), consumption=tuple(consumption),
        context_identity_sha256=context_identity, checker_ids=tuple(checker_ids), issuer=issuer)


def issue(issuer: VerificationIssuer, body: VerificationRecord) -> VerificationRecord:
    rec = issuer.issue(body)
    if not rec.mac or rec.body_sha256 != body.body_sha256:  # the capability must sign exactly this body
        raise RuntimeError("verification issuer returned a record that is unsigned or whose body differs from what L3 built")
    return rec
