# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.textsafe (moved to hlith.hostio.textsafe)."""

from __future__ import annotations

import sys as _sys

from .hostio import textsafe as _impl

_sys.modules[__name__] = _impl
