# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.delta_rel_uf`` IS ``hlith.obligation.delta_rel_uf``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.delta_rel_uf`` directly.
"""

import sys

from .obligation import delta_rel_uf as _real

sys.modules[__name__] = _real
