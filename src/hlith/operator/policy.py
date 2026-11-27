# SPDX-License-Identifier: Apache-2.0
"""Describe the caller policy used by the operator's run and its follow-ups."""

import os


def strict_requested(flag=False) -> bool:
    return bool(flag) or os.environ.get("HLITH_CERT_STRICT_DOMAIN") == "1"


def policy_summary(strict: bool) -> str:
    if strict:
        return "strict · typed proofs require exact-type entry guards"
    return "scoped · typed proofs cover exact builtins. External subclass behavior is outside that claim."
