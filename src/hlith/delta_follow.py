# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.delta_follow`` IS ``hlith.obligation.delta_follow``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.delta_follow`` directly.
"""

import sys

from .obligation import delta_follow as _real

sys.modules[__name__] = _real
