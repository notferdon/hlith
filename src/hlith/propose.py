# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias: moved to ``hlith.operator.intent.propose`` (operator section). Same module object; removal step: after
callers import the operator module."""

import sys

from .operator.intent import propose as _impl

sys.modules[__name__] = _impl
