# SPDX-License-Identifier: Apache-2.0
"""Pure state transitions for the operator surface."""

from __future__ import annotations

from dataclasses import replace


def _focused_obligation(vs) -> int:
    """The obligation under the marker: exactly frame._initial_focus_index's rule (an explicit or non-zero focus, else the host-supplied refuted-first default)."""
    eff = vs.focusIndex if (vs.focusIndex != 0 or vs.focusAction is not None) else vs.obl_default
    return min(max(0, eff), max(0, vs.obl_count - 1)) if vs.obl_count else max(0, eff)


def _all_files_excluded(vs) -> bool:
    """True when the focused source lists files and every one of them is excluded."""
    if vs.file_count <= 0:
        return False
    return all((vs.focusIndex, i) in vs.excluded_files for i in range(vs.file_count))


def _dock(vs) -> int:
    """Rows the Event Log dock takes on this screen (0 on a reading page): paging must not count them as visible."""
    from .wide import dock_height

    return 0 if vs.drill else dock_height(vs.cols, vs.rows)


def expire_on_key(vs, has_keys: bool):
    """A toast belongs to the moment that raised it: when a new batch of KEYS arrives the previous toast is gone before they are handled (a new source, a new screen or a run start never
    carries it), and any toast those keys raise themselves survives. Applied by the host at the top of each key batch; pure and tested here."""
    return replace(vs, toast=None) if (has_keys and vs.toast) else vs


def _offer_sources(vs):
    """`Other sources`: the Selection with the focus on the first ALTERNATIVE to the offered change (the offered change itself is `Review change`), so the two routes are never the same screen state."""
    return replace(vs, st="selection", focusIndex=1, focusAction=None, scroll=0, pane=0)  # (the host clamps it to the real source count after the first paint)


def _offer_enter(vs):
    """Enter on the Offer runs EXACTLY the focused visible action. The host owns the lead (reattach / view decision) and intercepts it first; here: review -> the offered change in Selection,
    sources -> Selection on the first alternative. With no known action list (a bare ViewState) the focus index alone decides, as before."""
    actions = vs.offer_actions
    action = actions[vs.focusIndex] if actions and 0 <= vs.focusIndex < len(actions) else ("sources" if (actions and vs.focusIndex >= len(actions)) else "review")
    if action == "history":
        return replace(vs, st="history", focusIndex=0, focusAction=None, scroll=0)
    if action == "sources":
        return replace(vs, st="selection", focusIndex=1, focusAction=None, scroll=0, pane=0)
    return replace(vs, st="selection", focusIndex=0, focusAction=None, scroll=0, pane=0)


def reduce(vs, action):
    return _reduce(vs, action)


def _reduce(vs, action):
    if action is None:
        return vs
    if isinstance(action, tuple) and len(action) == 3 and action[0] == "resize":
        _, cols, rows = action
        return replace(vs, cols=max(0, int(cols)), rows=max(0, int(rows)), scroll=max(0, int(vs.scroll)))
    if not isinstance(action, str) or not action.startswith("key:"):
        return vs
    key = action[4:]
    if key == "esc":
        if vs.overlay:
            return replace(vs, overlay=None, focusIndex=0)  # an OPEN modal takes Esc FIRST on every screen (it says 'esc stay'): it closes, nothing else happens, a run is never touched
        if vs.st == "selection" and vs.pane == 1 and not vs.drill:
            return replace(vs, pane=0)  # one level: back from the file list to the source rail
        if vs.st == "running":
            return replace(vs, toast="esc does not stop a run · q detach · x cancel")
        if vs.drill:
            return replace(vs, drill=None, scroll=0)
        parent = {"selection": "offer", "history": "offer", "claim": "selection", "verdict": "offer",
                  "blocked": "offer", "artifact-unavailable": "offer",
                  "run-ended-no-decision": "offer", "run-lost": "offer"}.get(vs.st)
        return replace(vs, st=parent or vs.st,
                       focusIndex=vs.selectedIndex if vs.st == "claim" and vs.selectedIndex is not None else 0,
                       selectedIndex=None if vs.st == "claim" else vs.selectedIndex,
                       focusAction=None, scroll=0)
    if key in {"]", "["} and not vs.overlay:
        from .wide import regions

        avail = regions(vs)
        if len(avail) > 1:
            here = avail.index(vs.region) if vs.region in avail else avail.index("centre")
            return replace(vs, region=avail[(here + (1 if key == "]" else -1)) % len(avail)])
        return vs
    if key in {"q", "ctrl-c"}:
        return replace(vs, overlay="quit" if vs.st == "running" else "exit", focusIndex=0)
    if key == "x" and vs.st == "running":
        return replace(vs, overlay="cancel", focusIndex=0)
    if vs.overlay in {"exit", "quit", "cancel"} and key in {"tab", "down", "j", "right", "shift-tab", "up", "k", "left"}:
        return replace(vs, focusIndex=1 - int(vs.focusIndex != 0))
    if vs.overlay:
        # while an overlay is open it takes EVERY key: nothing reaches the screen behind it (no paging, no advance, no drill, no toggles)
        if key == "enter":
            if vs.overlay in {"exit", "quit", "cancel"}:
                return replace(vs, overlay=None, focusIndex=0) if vs.focusIndex == 0 else vs
            return replace(vs, overlay=None, focusIndex=0)  # help / agent: Enter closes the overlay and nothing else
        return vs
    if vs.st == "selection" and not vs.overlay and not vs.drill:
        if key == "tab":
            return replace(vs, pane=1 - vs.pane, file_focus=0)  # tab switches between the source rail and the file list
        if vs.pane == 1:
            if key in {"down", "j", "right"}:
                return replace(vs, file_focus=min(max(0, vs.file_count - 1), vs.file_focus + 1))
            if key in {"shift-tab", "up", "k", "left"}:
                return replace(vs, file_focus=max(0, vs.file_focus - 1))
    if vs.st == "verdict" and vs.obl_count and not vs.overlay and not vs.drill and key in {"tab", "down", "j", "right", "shift-tab", "up", "k", "left"}:
        step = 1 if key in {"tab", "down", "j", "right"} else -1  # the arrows start from the highlighted obligation, not from index 0
        return replace(vs, focusIndex=min(max(0, _focused_obligation(vs) + step), vs.obl_count - 1), focusAction="obligation", scroll=max(0, vs.scroll))
    if key in {"tab", "down", "j", "right"}:
        top = vs.nav_max if vs.nav_max is not None else 10 ** 6  # focus never goes past the last VISIBLE item (clamp, no wrap): an unseen index leaves nothing highlighted
        return replace(vs, focusIndex=min(max(0, vs.focusIndex + 1), max(0, top)), file_focus=0 if vs.st == "selection" else vs.file_focus,
                       focusAction="obligation" if vs.st == "verdict" else vs.focusAction,
                       scroll=max(0, vs.scroll))
    if key in {"shift-tab", "up", "k", "left"}:
        return replace(vs, focusIndex=max(0, vs.focusIndex - 1), file_focus=0 if vs.st == "selection" else vs.file_focus,
                       focusAction="obligation" if vs.st == "verdict" else vs.focusAction,
                       scroll=max(0, vs.scroll))
    if key == "pgdn":
        page = max(1, vs.rows - 5 - _dock(vs))
        if vs.st == "claim":
            # Claim can replace the first and last viewport rows with scroll
            # markers. Keep two body rows overlapped so one command row remains
            # fully visible on both pages.
            page = max(1, page - 2)
        return replace(vs, scroll=max(0, vs.scroll + page))
    if key == "pgup":
        page = max(1, vs.rows - 5 - _dock(vs))
        if vs.st == "claim":
            page = max(1, page - 2)
        return replace(vs, scroll=max(0, vs.scroll - page))
    if key == "space" and vs.st == "selection":
        if vs.pane == 1 and vs.file_count:
            pair = (vs.focusIndex, min(vs.file_focus, vs.file_count - 1))  # a FILE row: that file only, in its own source
            files = set(vs.excluded_files)
            files ^= {pair}
            return replace(vs, excluded_files=tuple(sorted(files)))
        ex = set(vs.excluded_sources)
        ex ^= {vs.focusIndex}  # a SOURCE row: the whole source; the exclusion never follows the operator to another source
        return replace(vs, excluded_sources=tuple(sorted(ex)))
    if key == "?":
        return replace(vs, overlay="help")
    if key == "c" and vs.st == "claim":
        return replace(vs, drill="command", scroll=0)  # the dedicated command-review step (the host's gates are unchanged: it only decides whether Run may enable)
    if key == "d" and vs.st in {"offer", "selection", "claim", "running", "verdict", "blocked"}:
        return replace(vs, drill="diff")
    if key == "w" and vs.st == "verdict":
        return replace(vs, drill="witness")
    if key == "p" and vs.st == "verdict":
        return replace(vs, drill="prov")
    if key == "u" and vs.st == "verdict":
        return replace(vs, drill="unexp")
    if key == "s" and vs.st == "offer":
        return _offer_sources(vs)
    if key == "h" and vs.st in {"offer", "run-ended-no-decision", "run-lost", "artifact-unavailable"} and not vs.overlay and not vs.drill:
        return replace(vs, st="history", focusIndex=0, focusAction=None, scroll=0)
    if key.lower() == "a" and vs.st in {"selection", "offer"}:
        return replace(vs, overlay="agent")
    if key == "enter":
        if vs.st == "verdict" and not vs.drill and not vs.overlay and vs.obl_count > 0:
            # 'enter details': open the focused obligation's page (the footer and the OBLIGATIONS header promise it); Esc returns, a second Enter on the page changes nothing
            return replace(vs, drill=f"obl{_focused_obligation(vs)}", scroll=0)
        if vs.drill and not vs.overlay:
            return vs  # Enter on a drill page changes nothing: it must never advance the screen BEHIND the page (Esc then returns to where the drill was opened)
        if vs.overlay in {"exit", "quit", "cancel"}:
            return replace(vs, overlay=None, focusIndex=0) if vs.focusIndex == 0 else vs
        if vs.st == "claim" and vs.focusIndex == 1:
            # the Claim draws a focusable [ Back ]: Enter on it is Esc (one level back to Selection, the chosen source kept focused); it never starts or reviews anything
            return _reduce(vs, "key:esc")
        if vs.st == "offer":
            return _offer_enter(vs)
        if vs.st == "selection" and vs.focus_blocked:
            return replace(vs, toast="this source cannot be checked: the note on the right says why · pick another source")
        if vs.st == "selection":
            if vs.pane == 1 and vs.file_count:
                return _reduce(vs, "key:space")  # a FILE row has the focus: Enter toggles its checkbox exactly like Space and never advances
            ex_here = {fi for (si, fi) in vs.excluded_files if si == vs.focusIndex}
            if vs.focusIndex in vs.excluded_sources or not vs.included:
                # the source row is '[ ]': Enter includes it (the one obvious productive step); a second Enter checks it
                return replace(vs, included=True, excluded_sources=tuple(sorted(set(vs.excluded_sources) - {vs.focusIndex})), toast="included · Enter again checks this change")
            if vs.file_count and len(ex_here) >= vs.file_count:
                # every file of this source is left out: move to the first file with the exact instruction instead of a dead end
                return replace(vs, pane=1, file_focus=0, toast="no file is included: Enter or Space includes the file")
            return replace(vs, st="claim", selectedIndex=vs.focusIndex, focusIndex=0, focusAction=None, scroll=0, pane=0)
        # Run authorization remains with the existing operator/engine host.
        return vs
    return vs
