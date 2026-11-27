# SPDX-License-Identifier: Apache-2.0
"""``python -m hlith.tui``: runs the operator TUI entry (moved to hlith.operator.tui.__main__)."""

import sys

from hlith.operator.tui.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
