# SPDX-License-Identifier: Apache-2.0
"""Issuer-bound VerificationRecord MAC (implements contract VerificationIssuer and VerificationVerifier).

Threat model: the trusted computing base is the L3 controller and the L4 gate; the UNTRUSTED parties
are the agent worker, evaluators running target code, the proposer and the renderer. They never hold the KeyPurpose
.VERIFIER_ISSUE key (host state, 0600, outside every granted path), so they cannot produce a record the gate accepts.
A shared secret between the two trusted components is sufficient for that separation; it is NOT a defence against a
compromised host process, and no stronger claim is made.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac

from ..contract.capabilities import HostState, KeyPurpose
from ..contract.codec import canonical_bytes
from ..contract.obligations import VerificationRecord

ISSUER_ID = "case"


def _mac(key: bytes, record: VerificationRecord) -> str:
    return hmac.new(key, canonical_bytes(record.body()), hashlib.sha256).hexdigest()


class LocalVerificationService:
    """VerificationIssuer (L3 controller side) and VerificationVerifier (L4 gate side) over one HostState."""

    issuer_id = ISSUER_ID  # the issuer name L3 must put in the body it asks to have signed (issue() sets exactly this)

    def __init__(self, host_state: HostState) -> None:
        self._state = host_state

    def issue(self, record_body: VerificationRecord) -> VerificationRecord:
        key = self._state.key(KeyPurpose.VERIFIER_ISSUE)
        body = dataclasses.replace(record_body, issuer=ISSUER_ID, mac="")
        return dataclasses.replace(body, mac=_mac(key, body))

    def verify(self, record: VerificationRecord) -> bool:
        if record.issuer != ISSUER_ID or not record.mac:
            return False
        key = self._state.key(KeyPurpose.VERIFIER_ISSUE)
        return hmac.compare_digest(record.mac, _mac(key, record))
