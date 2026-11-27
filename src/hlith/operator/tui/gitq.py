# SPDX-License-Identifier: Apache-2.0
"""Alias: the hardened read-only git adapter is a host module (``hlith.operator.gitq``; it moves to hostio/git_read). Same module
object, so views and unmigrated callers share one state (cache, private HOME)."""

import sys

from .. import gitq as _impl

sys.modules[__name__] = _impl
