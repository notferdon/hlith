# SPDX-License-Identifier: Apache-2.0
"""Wall-clock per phase of one `hlith run` (informational; never read by the gate).

Phases, in the order they are recorded: stage_and_worker, account, differential, derive_other, declare, gate, resume.
`account` and `differential` happen inside derive; `derive_other` is derive minus both. Repeated phases are summed.
The clone of the target is made by the operator, outside hlith, and is not measured here.
"""

from __future__ import annotations

import time
from contextlib import contextmanager

ORDER = ("stage_and_worker", "account", "differential", "derive_other", "declare", "gate", "resume")
_acc: dict[str, float] = {}
_t0 = time.monotonic()
_sink = None  # optional hlith.events.Emitter: real phase transitions are mirrored to it (informational; errors never propagate)


def set_sink(sink) -> None:
    global _sink
    _sink = sink


def _emit(phase: str, event: str, **extra) -> None:
    if _sink is not None:
        try:
            _sink.emit(phase, event, **extra)
        except Exception:  # noqa: BLE001 - events must never change a run
            pass


def progress(phase: str, **extra) -> None:
    """An engine fact about progress inside a running phase (e.g. differential target i of n)."""
    _emit(phase, "progress", **extra)


def reset() -> None:
    global _t0
    _acc.clear()
    _t0 = time.monotonic()


@contextmanager
def timed(name: str):
    s = time.monotonic()
    _emit(name, "start")
    try:
        yield
    finally:
        _acc[name] = _acc.get(name, 0.0) + (time.monotonic() - s)
        _emit(name, "end")


def add(name: str, seconds: float) -> None:
    _acc[name] = _acc.get(name, 0.0) + max(0.0, seconds)


def snapshot() -> dict:
    """{"phases": [{"name", "seconds"}...], "total_seconds"}; derive_other = derive - account - differential."""
    a = dict(_acc)
    if "derive" in a:
        a["derive_other"] = max(0.0, a.pop("derive") - a.get("account", 0.0) - a.get("differential", 0.0))
    return {"phases": [{"name": n, "seconds": round(a[n], 3)} for n in ORDER if n in a],
            "total_seconds": round(time.monotonic() - _t0, 3)}


def line(snap: dict) -> str:
    return ("time        : " + "  ".join(f"{p['name']} {p['seconds']:.1f}s" for p in snap["phases"])
            + f"  | total {snap['total_seconds']:.1f}s (clone is outside hlith)")
