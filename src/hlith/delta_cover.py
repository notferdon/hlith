# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.delta_cover`` IS ``hlith.obligation.delta_cover``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.delta_cover`` directly.
"""

import sys

from .obligation import delta_cover as _real

sys.modules[__name__] = _real
