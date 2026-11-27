# SPDX-License-Identifier: Apache-2.0
"""Authored first-use demo fixture for Hlith Review."""


def effective_timeout(value: int, maximum: int = 300) -> int:
    """Return value clamped to maximum; reject non-positive timeouts."""
    if value <= 0:
        raise ValueError("Timeout must be positive")
    if value > maximum:
        return maximum
    return value
