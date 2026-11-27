# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.sandbox (moved to hlith.hostio.confinement)."""

from __future__ import annotations

import sys as _sys

if __package__:
    from .hostio import confinement as _impl

    _sys.modules[__name__] = _impl
else:
    import importlib.util
    from pathlib import Path

    _spec = importlib.util.spec_from_file_location(
        "_hlith_hostio_confinement",
        Path(__file__).with_name("hostio") / "confinement.py",
    )
    assert _spec is not None and _spec.loader is not None
    _impl = importlib.util.module_from_spec(_spec)
    _sys.modules[_spec.name] = _impl
    _spec.loader.exec_module(_impl)
    globals().update(vars(_impl))
