# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.guard_removed`` IS ``hlith.obligation.guard_removed``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.guard_removed`` directly.
"""

import sys

from .obligation import guard_removed as _real

sys.modules[__name__] = _real
