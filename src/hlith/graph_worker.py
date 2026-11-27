# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.graph_worker (moved to hlith.agent.graph + hlith.agent.tools)."""

import sys

from .agent.graph import (
    _SOCKET_EVENTS,
    State,
    _audit,
    _emit,
    build_agent_graph,
    build_graph,
    main,
)
from .agent.tools import (
    AGENT_MAX_TURNS,
    MAX_ENTRIES,
    MAX_FILE,
    MeasureError,
    _agent_tool,
    _agent_tool_raw,
    _child_env,
    _kill_namespace,
    _measure,
    _measure_inner,
    _read_beneath,
    _redact_result,
    _run_child,
    _safe_rel,
    _tail,
    _task_text,
    claimed_digest,
    decision_sha,
)

__all__ = [
    "AGENT_MAX_TURNS",
    "MAX_ENTRIES",
    "MAX_FILE",
    "MeasureError",
    "State",
    "_SOCKET_EVENTS",
    "_agent_tool",
    "_agent_tool_raw",
    "_audit",
    "_child_env",
    "_emit",
    "_kill_namespace",
    "_measure",
    "_measure_inner",
    "_read_beneath",
    "_redact_result",
    "_run_child",
    "_safe_rel",
    "_tail",
    "_task_text",
    "build_agent_graph",
    "build_graph",
    "claimed_digest",
    "decision_sha",
    "main",
]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
