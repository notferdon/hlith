# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim: ``ast_source`` moved to ``hlith.effect.source`` (section case).

Shim owner: L2 (review). Removal step: after L3 (delta_rel) imports ``hlith.effect.source`` directly.
"""

from .effect.source import *  # noqa: F401,F403
from .effect.source import ast_source_lines, ast_source_segment, source_segment_from_lines  # noqa: F401
