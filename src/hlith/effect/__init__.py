# SPDX-License-Identifier: Apache-2.0
"""L2 effect understanding (section case).

Package conversion of the former module ``hlith/effect.py`` (now ``effect/engine.py``). Every public AND private
name of the old module is re-exported here so unmigrated callers (``from hlith import effect``;
``effect.build_effect_account``, ``effect.declare``, record types) keep working unchanged.
Shim owner: L2 (review). Removal step: once every caller uses ``hlith.effect.api`` (contract EffectApi).
"""

from . import engine as _engine

globals().update({_k: _v for _k, _v in vars(_engine).items() if not (_k.startswith("__") and _k.endswith("__"))})

# Public, execution-free package export resolution shared with static import consumers.
from .exports import StaticExportResolution, resolve_static_wildcard_export  # noqa: E402,F401

# Contract entry (EffectApi). Imported after the engine names so it cannot shadow any of them.
from .api import AccountBuild, EffectService, analyzer_id  # noqa: E402,F401
