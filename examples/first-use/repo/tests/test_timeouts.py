# SPDX-License-Identifier: Apache-2.0
from demo_limits.timeouts import effective_timeout


def test_effective_timeout_clamps_positive_values():
    assert effective_timeout(10) == 10
    assert effective_timeout(500) == 300
