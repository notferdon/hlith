# SPDX-License-Identifier: Apache-2.0
"""TUI behavior: a BOUNDARY refusal records the engine's own reasons in `blocking` as prose; the panel must show them, not 'obligation not in the artifact'."""
from hlith.operator.tui import model

ART = {"decision": "REFUSED", "exit_status": 4, "obligations": [],
       "blocking": ["worker-command-failed", "worker command exited 1, no change; stderr empty: use /usr/bin/python3 or --worker-ro"]}


def test_a_real_obligation_record_is_untouched_by_the_prose_rule():
    art = {"decision": "REFUSED", "blocking": ["O-1"], "obligations": [{"id": "O-1", "verdict": "unverified", "stop_reason": "no oracle"}]}
    assert model.blocking(art)[0]["stop_reason"] == "no oracle"


