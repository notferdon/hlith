# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith._confine (moved to hlith.hostio.confine_exec)."""

from __future__ import annotations

if __name__ == "__main__":
    import runpy
    from pathlib import Path

    runpy.run_path(str(Path(__file__).with_name("hostio") / "confine_exec.py"), run_name="__main__")
elif __package__:
    import sys as _sys

    from .hostio import confine_exec as _impl

    _sys.modules[__name__] = _impl
else:
    import importlib.util
    import sys as _sys
    from pathlib import Path

    _spec = importlib.util.spec_from_file_location(
        "_hlith_hostio_confine_exec",
        Path(__file__).with_name("hostio") / "confine_exec.py",
    )
    assert _spec is not None and _spec.loader is not None
    _impl = importlib.util.module_from_spec(_spec)
    _sys.modules[_spec.name] = _impl
    _spec.loader.exec_module(_impl)
    globals().update(vars(_impl))
