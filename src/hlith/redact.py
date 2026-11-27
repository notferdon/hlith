# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.redact (moved to hlith.hostio.redact)."""

from __future__ import annotations

import sys as _sys

from .hostio import redact as _impl

_sys.modules[__name__] = _impl
