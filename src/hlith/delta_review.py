# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias: moved to ``hlith.operator.intent.delta_review`` (operator section). Same module object, so
``python -m hlith.delta_review`` and monkeypatches keep working; removal step: after callers import the operator module."""

import sys

from .operator.intent import delta_review as _impl

if __name__ == "__main__":
    sys.exit(_impl.main())
else:
    sys.modules[__name__] = _impl
