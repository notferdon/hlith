# SPDX-License-Identifier: Apache-2.0
"""CLI entrypoint for the single terminal host."""

from __future__ import annotations

import sys

from .host import main


if __name__ == "__main__":
    sys.exit(main())
