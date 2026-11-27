# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias: the ``hlith`` command line lives in ``hlith.operator.cli`` (operator section).

``hlith.cli`` IS that module object (same namespace, private names and monkeypatches included), so unmigrated callers and
``python -m hlith.cli`` keep working. Removal step: after every caller imports ``hlith.operator.cli``."""

import sys

from .operator import cli as _impl

if __name__ == "__main__":
    sys.exit(_impl.main())
else:
    sys.modules[__name__] = _impl
