# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias package: the native operator TUI lives in ``hlith.operator.tui`` (operator section).

``hlith.tui`` and every ``hlith.tui.<module>`` resolve to the SAME module objects as ``hlith.operator.tui.<module>`` (a meta-path
alias, not a copy), so unmigrated callers, ``python -m hlith.tui`` and monkeypatches keep working. Removal step: after every
caller imports ``hlith.operator.tui``."""

import importlib
import importlib.abc
import importlib.util
import sys

_OLD, _NEW = __name__, "hlith.operator.tui"


class _Alias(importlib.abc.InspectLoader):
    """Loader that hands out the REAL module object. It also answers the InspectLoader questions ``python -m`` / runpy ask
    (is_package, get_code, get_source), by delegating to the real module's own spec and loader."""

    def __init__(self, real: str) -> None:
        self.real = real

    def _real_spec(self):
        spec = importlib.util.find_spec(self.real)
        if spec is None or spec.loader is None:
            raise ImportError(f"alias target {self.real} not found", name=self.real)
        return spec

    def create_module(self, spec):
        mod = importlib.import_module(self.real)
        self._saved = (getattr(mod, "__spec__", None), getattr(mod, "__loader__", None))
        return mod

    def exec_module(self, module) -> None:
        """The module already ran under its real name. The import machinery stamped the ALIAS spec onto it; put the real spec and
        loader back so ``__package__``/``__spec__.parent`` keep agreeing (relative imports inside it must not warn or break)."""
        spec, loader = getattr(self, "_saved", (None, None))
        if spec is not None:
            module.__spec__ = spec
        if loader is not None:
            module.__loader__ = loader

    def is_package(self, fullname) -> bool:
        return self._real_spec().submodule_search_locations is not None

    def get_code(self, fullname):
        loader = self._real_spec().loader
        return loader.get_code(self.real) if hasattr(loader, "get_code") else None

    def get_source(self, fullname):
        loader = self._real_spec().loader
        return loader.get_source(self.real) if hasattr(loader, "get_source") else None


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.endswith(".__main__"):  # ``python -m hlith.tui`` runs the small hlith/tui/__main__.py (it calls the real main)
            return None
        if fullname.startswith(_OLD + "."):
            real = _NEW + fullname[len(_OLD):]
            if importlib.util.find_spec(real) is not None:
                return importlib.util.spec_from_loader(fullname, _Alias(real))
        return None


if not any(isinstance(f, _Finder) for f in sys.meta_path):
    sys.meta_path.insert(0, _Finder())

_real = importlib.import_module(_NEW)
__path__ = _real.__path__  # submodules are located under the real package; the finder above maps them to the real objects
