# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.phase_ledger (moved to hlith.hostio.phase_ledger)."""

from __future__ import annotations

import sys as _sys

from .hostio import phase_ledger as _impl

_sys.modules[__name__] = _impl
