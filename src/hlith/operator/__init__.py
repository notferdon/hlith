# SPDX-License-Identifier: Apache-2.0
"""Operator section (L-operator): one coordinator/session API for the CLI, headless and the native TUI.

Allowed import edges: public APIs of L1-L5, ``contract``, ``hostio``; views use ``contract`` and presentation
read APIs only. No backend imports operator code. The operator never decides and never writes for the engine.
"""

from __future__ import annotations

__all__ = ["api", "coordinator", "store", "labels", "receipts", "state", "schema"]
