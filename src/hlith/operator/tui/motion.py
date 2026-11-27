# SPDX-License-Identifier: Apache-2.0
"""Restrained, event-grounded motion for the operator TUI (maintainer decision 2026-11-21: required for the surface lock).

Two cues exist, both one-shot and both bound to something that really happened:

* FOCUS: a key-driven change of focus (region, selection, file, obligation) earns a short emphasis on the focused row / pane header on top of the immediate neutral selected marker;
* EVENTS: every NEW, de-duplicated real engine event id that appears in the Event Log dock earns one short highlight.

Nothing here decides anything: it only says "for the next ~0.2 s draw this one thing a little stronger". It adds no thread, no timer and no dependency: the host's existing ~100 ms loop asks
``snapshot(now)`` each tick and repaints when the snapshot changed, which is also how a cue settles. The clock is injectable (tests pass a fake monotonic clock). There is NO idle pulse and no
cue for a run that was merely opened (history, reattach, reopen): a run's events seen for the first time are its baseline, not news. Under reduced motion (HLITH_UI_REDUCED_MOTION=1, NO_COLOR,
HLITH_UI_MONO=1, TERM=dumb, or a plain/mono colour mode) every method is a no-op, so the frame is fully static.
"""

from __future__ import annotations

import time

FOCUS_SECONDS = 0.22  # B / the motion pack: ~220 ms, then it returns to the stable selected state
EVENT_SECONDS = 0.9  # B reference: a newly arrived real event is emphasised for ~0.9 s; older rows never move
STEP_SECONDS = 0.3  # the breadcrumb's active stage after an ACTUAL screen transition
VERDICT_SECONDS = 1.2  # the result badge / subtitle, ONLY on a verdict that completed live in this session (never on reopen / history)
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SEEN_RUNS = 32  # runs whose event ids are remembered (bounded)


def reduced_motion(env, color_mode: str | None = None) -> bool:
    """True when the cues must stay off: the operator asked for it, or the terminal mode carries no emphasis (mono / plain / dumb)."""
    for name in ("HLITH_UI_REDUCED_MOTION", "HLITH_STATIC", "NO_MOTION", "REDUCE_MOTION"):
        if str(env.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}:
            return True
    if env.get("NO_COLOR") or env.get("HLITH_UI_MONO") == "1" or env.get("TERM") == "dumb":
        return True
    return color_mode in {"mono", "plain"}


class Motion:
    def __init__(self, clock=time.monotonic, reduced: bool = False):
        self._clock = clock
        self.reduced = bool(reduced)
        self._focus_until = 0.0
        self._step_until = 0.0
        self._verdict_until = 0.0
        self._running = False
        self._event_until: dict = {}
        self._seen: dict = {}

    @classmethod
    def from_env(cls, env, color_mode: str | None = None, clock=time.monotonic) -> "Motion":
        return cls(clock=clock, reduced=reduced_motion(env, color_mode))

    def _now(self, now):
        return self._clock() if now is None else now

    def focus(self, now=None) -> None:
        """A key-driven focus change happened: emphasise it once."""
        if not self.reduced:
            self._focus_until = self._now(now) + FOCUS_SECONDS

    def step(self, now=None) -> None:
        """The screen really changed: the breadcrumb's active stage reads stronger for a moment."""
        if not self.reduced:
            self._step_until = self._now(now) + STEP_SECONDS

    def verdict(self, now=None) -> None:
        """A run completed LIVE here and its verdict arrived: emphasise the result once. Never called for a reopened / historical verdict."""
        if not self.reduced:
            self._verdict_until = self._now(now) + VERDICT_SECONDS

    def set_running(self, running: bool) -> None:
        """True only while a real run is actively running (never paused, idle, completed or cancelled): the only moment a status spinner exists."""
        self._running = bool(running) and not self.reduced

    def toggle_reduced(self) -> bool:
        """The R key: static mode on / off at run time. Returns the new `reduced` value; turning it on clears every live cue."""
        self.reduced = not self.reduced
        if self.reduced:
            self._focus_until = self._step_until = self._verdict_until = 0.0
            self._event_until.clear()
            self._running = False
        return self.reduced

    def observe(self, run_key, ids, *, announce_first: bool = False, now=None) -> int:
        """Fold the event ids the dock currently shows for `run_key`. Returns how many were NEW and announced. The first sight of a run is a silent baseline (history / reattach / reopen
        are not news) unless the run was started here (`announce_first`). Ids already seen never fire again (de-duplication across polls and across reopen)."""
        ids = [i for i in ids if i is not None]
        t = self._now(now)
        seen = self._seen.get(run_key)
        if seen is None:
            if len(self._seen) >= _SEEN_RUNS:
                self._seen.pop(next(iter(self._seen)))
            self._seen[run_key] = seen = set(ids)
            fresh = list(ids) if announce_first else []
        else:
            fresh = [i for i in ids if i not in seen]
            seen.update(fresh)
        if fresh and not self.reduced:
            for i in fresh:
                self._event_until[(run_key, i)] = t + EVENT_SECONDS
        return 0 if self.reduced else len(fresh)

    def snapshot(self, now=None) -> dict:
        """What is emphasised at `now`: {'focus': bool, 'events': frozenset of (run_key, id)}. Comparing two snapshots tells the host whether a repaint is due (a cue started or settled)."""
        t = self._now(now)
        for key in [k for k, until in self._event_until.items() if until <= t]:
            del self._event_until[key]
        return {"focus": self._focus_until > t, "events": frozenset(self._event_until), "step": self._step_until > t, "verdict": self._verdict_until > t,
                "spin": (int(t * 10) % len(SPINNER)) if self._running else None}

    def active(self, now=None) -> bool:
        snap = self.snapshot(now)
        return bool(snap["focus"] or snap["events"] or snap["step"] or snap["verdict"] or snap["spin"] is not None)
