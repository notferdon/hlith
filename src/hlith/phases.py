# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.phases (moved to hlith.hostio.phases)."""

from __future__ import annotations

import sys as _sys

from .hostio import phases as _impl

_sys.modules[__name__] = _impl
