# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias (L3 package move, case): ``hlith.docstring_check`` IS ``hlith.obligation.docstring_check``.

Owner: L3 (review). Removal step: after every caller imports ``hlith.obligation.docstring_check`` directly.
"""

import sys

from .obligation import docstring_check as _real

sys.modules[__name__] = _real
