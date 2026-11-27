# SPDX-License-Identifier: Apache-2.0
"""Layer 1 worker: a LangGraph StateGraph that runs INSIDE kernel confinement.

Run as ``python -I -m hlith.agent.graph run|resume`` (or ``hlith.graph_worker``) by the supervisor (never imported by it).

Graph (deterministic, no model, no network):

    apply  -> propose -> feedback -> END

* ``apply``    makes the edit in the stage (git apply of an operator patch, or an operator command),
               and measures what it changed (path -> mode/content digest).
* ``propose``  calls ``langgraph.types.interrupt(payload)``; the process exits with the thread paused
               in the SqliteSaver checkpoint. The payload is a CLAIM: the supervisor derives the real
               ProposedEffect from the stage itself and cross-checks it.
* ``feedback`` runs only after the supervisor resumes the thread with ``Command(resume=decision)``;
               it records the decision in the checkpointed state exactly once.

Idempotence: resuming re-executes the interrupted node from its start, so ``propose`` has no side
effect before ``interrupt`` (the payload is recomputed from state), and ``feedback`` keys its record by
the sha256 of the decision, so a second resume cannot record twice.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, TypedDict

from .tools import (
    AGENT_MAX_TURNS,
    MAX_ENTRIES,
    MAX_FILE,
    MeasureError,
    _agent_tool,
    _measure,
    _run_child,
    _task_text,
    claimed_digest,
    decision_sha,
)

# Count every socket the graph process creates; the supervisor reads this (net is off AND we assert it).
_SOCKET_EVENTS: list[str] = []


def _audit(event: str, args: tuple) -> None:
    if event.startswith("socket.") and event != "socket.gethostname":
        detail = ""
        if event == "socket.__new__" and len(args) > 1:
            detail = f":{getattr(args[1], 'name', args[1])}"
        elif event in ("socket.connect", "socket.bind", "socket.sendto") and len(args) > 1:
            detail = f":{args[1]!r}"[:80]
        _SOCKET_EVENTS.append(event + detail)


class State(TypedDict, total=False):
    apply_rc: int
    apply_stderr: str
    claimed: dict[str, str]  # path -> "<x|-><sha256>" (symlink: "l:<sha256 of target>")
    decision: dict[str, Any]
    feedback: dict[str, Any]  # decision sha256 -> record; at most one key per distinct decision
    feedback_executions: int
    turn: int
    transcript: list[dict[str, Any]]
    pending: list[Any]
    baseline: dict[str, str]
    finished: bool


def build_agent_graph(task_path: str, stage: Path, checkpointer):
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def begin(state: State) -> State:
        return {"turn": 0, "transcript": [], "pending": [], "finished": False, "baseline": _measure(stage)}

    def agent_turn(state: State) -> State:
        n = int(state.get("turn") or 0)
        payload = {
            "node": "agent_turn",
            "thread_id": os.environ["HLITH_THREAD_ID"],
            "turn": n,
            "task": _task_text(task_path),
            "transcript": state.get("transcript") or [],
        }
        _emit("graph_payload.json", payload)  # no side effect before interrupt(): a resume re-executes this node
        reply = interrupt(payload)
        calls = reply.get("tool_calls") if isinstance(reply, dict) else None
        return {"pending": calls if isinstance(calls, list) else [], "turn": n + 1}

    def tools(state: State) -> State:
        n = int(state.get("turn") or 1) - 1
        results, done = list(state.get("transcript") or []), False
        for i, call in enumerate(state.get("pending") or []):
            r = _agent_tool(stage, call, n, i)
            results.append({"turn": n, **r})
            if r["tool"] == "finish" and r["ok"]:
                done = True
                break
        if int(state.get("turn") or 0) >= AGENT_MAX_TURNS:
            done = True
        return {"transcript": results, "finished": done, "pending": []}

    def finish(state: State) -> State:
        before, after = state.get("baseline") or {}, _measure(stage)
        changed = {p: d for p, d in after.items() if before.get(p) != d}
        for p in before:
            if p not in after:
                changed[p] = "deleted"
        fails = [t for t in (state.get("transcript") or []) if t["tool"] == "apply_patch" and not t["ok"]]
        return {"apply_rc": 0, "apply_stderr": (fails[-1]["output"] if fails else "")[-2000:], "claimed": changed}

    def propose(state: State) -> State:
        payload = {
            "node": "propose",
            "thread_id": os.environ["HLITH_THREAD_ID"],
            "claimed_paths": sorted(state["claimed"]),
            "claimed": state["claimed"],
            "claimed_digest": claimed_digest(state["claimed"]),
            "apply_rc": state["apply_rc"],
        }
        # The tool-result transcript (already redacted and capped per entry) lets a supervisor that resumed a crashed run show that every
        # tool call ran exactly once; it is evidence about the run, never an input to the gate.
        payload["transcript"] = [{k: t.get(k) for k in ("turn", "tool", "ok")} for t in (state.get("transcript") or [])][:64]
        _emit("graph_payload.json", payload)
        return {"decision": interrupt(payload)}

    def feedback(state: State) -> State:
        key = decision_sha(state["decision"])
        done = dict(state.get("feedback") or {})
        if key in done:
            return {}
        d = state["decision"]
        done[key] = {"outcome": d.get("outcome"), "exit_status": d.get("exit_status"), "blocking": d.get("blocking")}
        return {"feedback": done, "feedback_executions": int(state.get("feedback_executions") or 0) + 1}

    g = StateGraph(State)
    for name, fn in (
        ("begin", begin),
        ("agent_turn", agent_turn),
        ("tools", tools),
        ("finish", finish),
        ("propose", propose),
        ("feedback", feedback),
    ):
        g.add_node(name, fn)
    g.add_edge(START, "begin")
    g.add_edge("begin", "agent_turn")
    g.add_edge("agent_turn", "tools")
    g.add_conditional_edges(
        "tools",
        lambda s: "finish" if s.get("finished") else "agent_turn",
        {"finish": "finish", "agent_turn": "agent_turn"},
    )
    g.add_edge("finish", "propose")
    g.add_edge("propose", "feedback")
    g.add_edge("feedback", END)
    return g.compile(checkpointer=checkpointer)


def build_graph(mode: str, patch: str | None, cmd: list[str], stage: Path, checkpointer):
    if mode == "agent":
        return build_agent_graph(str(patch), stage, checkpointer)
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def apply(state: State) -> State:
        before = _measure(stage)
        if mode == "patch":
            argv = ["git", "apply", "--whitespace=nowarn", str(patch)]
        else:
            argv = cmd
        cp = _run_child(argv, stage)
        after = _measure(stage)
        changed = {p: d for p, d in after.items() if before.get(p) != d}
        for p in before:
            if p not in after:
                changed[p] = "deleted"
        return {"apply_rc": cp.returncode, "apply_stderr": cp.stderr[-2000:], "claimed": changed}

    def propose(state: State) -> State:
        # No side effect before interrupt(): a resume re-executes this node from the top.
        payload = {
            "node": "propose",
            "thread_id": os.environ["HLITH_THREAD_ID"],
            "claimed_paths": sorted(state["claimed"]),
            "claimed": state["claimed"],
            "claimed_digest": claimed_digest(state["claimed"]),
            "apply_rc": state["apply_rc"],
        }
        _emit("graph_payload.json", payload)
        decision = interrupt(payload)
        return {"decision": decision}

    def feedback(state: State) -> State:
        key = decision_sha(state["decision"])
        done = dict(state.get("feedback") or {})
        if key in done:  # replay of the same decision: record nothing, count nothing
            return {}
        d = state["decision"]
        done[key] = {"outcome": d.get("outcome"), "exit_status": d.get("exit_status"), "blocking": d.get("blocking")}
        return {"feedback": done, "feedback_executions": int(state.get("feedback_executions") or 0) + 1}

    g = StateGraph(State)
    g.add_node("apply", apply)
    g.add_node("propose", propose)
    g.add_node("feedback", feedback)
    g.add_edge(START, "apply")
    g.add_edge("apply", "propose")
    g.add_edge("propose", "feedback")
    g.add_edge("feedback", END)
    return g.compile(checkpointer=checkpointer)


def _emit(name: str, obj: dict) -> None:
    d = os.environ["HLITH_DRIVER_DIR"]  # driver-only dir: the child has no grant on it
    tmp = Path(d) / (name + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True))
    os.replace(tmp, Path(d) / name)


def main(argv: list[str]) -> int:
    sys.addaudithook(_audit)
    import ctypes
    import sqlite3

    # Not ptrace-able / no /proc/<pid>/{mem,environ,fd} for same-uid processes (the child is one).
    ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0

    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command

    action = argv[0]
    stage = Path(os.environ["HLITH_STAGE"]).resolve()
    thread_id = os.environ["HLITH_THREAD_ID"]
    ck = Path(os.environ["HLITH_CKPT_DIR"]) / "checkpoints.sqlite"
    mode, patch, cmd = "patch", None, []
    if action != "run" and os.environ.get("HLITH_GRAPH_MODE") == "agent":  # a resume must rebuild the graph the thread was started with
        mode, patch = "agent", os.environ["HLITH_TASK_PATH"]
    if action == "run":
        mode = argv[1]
        if mode in ("patch", "agent"):
            patch = argv[2]
        else:
            cmd = argv[argv.index("--") + 1:]
    conn = sqlite3.connect(str(ck), check_same_thread=False)
    conn.execute("PRAGMA temp_store=MEMORY")  # no sqlite temp files outside the ckpt dir
    try:
        saver = SqliteSaver(conn)
        graph = build_graph(mode, patch, cmd, stage, saver)
        cfg = {"configurable": {"thread_id": thread_id}}
        if action == "run":
            graph.invoke({}, cfg)
        else:
            decision = json.loads(Path(argv[1]).read_text())
            # Resume exactly the ONE pending interrupt by its id: a bare resume value would also answer every LATER interrupt
            # of the same invocation (an agent turn's reply would be taken as the gate's decision).
            _snap = graph.get_state(cfg)
            pending = [i.id for i in _snap.interrupts] or [i.id for t in _snap.tasks for i in t.interrupts]
            if len(pending) > 1:
                raise RuntimeError(f"expected at most one pending interrupt, found {len(pending)}")
            if pending:  # none pending = a finished thread: a second resume is a replay, it records nothing
                graph.invoke(Command(resume={pending[0]: decision}), cfg)
        snap = graph.get_state(cfg)
        _emit(
            "graph_result.json",
            {
                "action": action,
                "next": list(snap.next),
                "feedback_executions": snap.values.get("feedback_executions", 0),
                "feedback": snap.values.get("feedback"),
                "socket_events": list(_SOCKET_EVENTS),
                "env_tracing_vars": sorted(k for k in os.environ if k.startswith(("LANGSMITH", "LANGCHAIN"))),
            },
        )
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
