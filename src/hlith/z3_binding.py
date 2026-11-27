# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.z3_binding`` IS ``hlith.obligation.z3_binding``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.z3_binding`` directly.
"""

import sys

from .obligation import z3_binding as _real

sys.modules[__name__] = _real
