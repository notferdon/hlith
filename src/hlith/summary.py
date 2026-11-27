# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias: the report text lives in ``hlith.operator.presentation`` (operator section). Same module object;
removal step: after every caller imports ``hlith.operator.presentation``."""

import sys

from .operator import presentation as _impl

sys.modules[__name__] = _impl
