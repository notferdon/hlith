# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias: ``hlith check`` lives in ``hlith.operator.check`` (operator section). Same module object; removal step:
after every caller imports ``hlith.operator.check``."""

import sys

from .operator import check as _impl

sys.modules[__name__] = _impl
