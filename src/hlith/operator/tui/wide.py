# SPDX-License-Identifier: Apache-2.0
"""B composition support (>= 100 columns). The earlier universal three-pane cockpit (navigation | centre | context) is RETIRED by the maintainer's final B composition: every screen now carries its own
state-specific panes (frame.py: canvas + inspector, Selection rail + preview, one bounded reading column). What remains here: the verdict inspector's empty rows carry the verification context.

(Historical description of the retired cockpit, kept for the record:) a persistent THREE-pane workspace around the screens the renderer already composes.

    navigation (28) | centre: the screen's own canvas, on the same base surface as its neighbours | verification context (46)

Maintainer defect (2026-11-21): on a wide terminal the diff sat squeezed to the left and the right half was dead space; the context must stay visible on EVERY screen. The screens keep
their own two-pane composition (content | inspector, or source rail | diff); this module adds what each one lacks:

* screens that already carry an inspector on the right (offer, claim, running, verdict) gain the NAVIGATION pane on the left (the flow, the source/files, the run, recent runs);
* screens without one (selection, history, blocked, ended runs, artifact unavailable) gain the CONTEXT pane on the right (repository, checks, readiness with the interpreter origin,
  records); the Selection's own source rail is its navigation. History and the single-column states also gain the navigation pane when 160+ columns leave the centre >= 80.

It only composes rows that frame.render already produced (header, status and footer rows are the full-width ones; the body is the narrower render). It reads nothing new and decides
nothing: every fact shown comes from the same context/artifact the screens use. Below 150 columns it is never reached.
"""

from __future__ import annotations

from dataclasses import replace

WIDE_COLS = 150
NAV_W = 28
CTX_W = 46
_INSPECTOR_STATES = {"offer", "claim", "running", "verdict"}
_STEP = {"offer": 0, "selection": 0, "claim": 1, "running": 2, "verdict": 3}


def _layout(vs, cols):
    """(add_nav, add_ctx) for this state at this width."""
    return False, False  # B composition (maintainer's final, 2026-11-21): state-specific panes, no universal navigation / third pane (the screens carry their own rail / inspector)


def regions(vs) -> list:
    """The panes the keyboard focus can sit in on this screen at this width: ['centre'] below 150 columns, else nav / centre / ctx as the screen has them."""
    if not applies(vs, vs.cols, vs.rows):
        return ["centre"]
    add_nav, add_ctx = _layout(vs, vs.cols)
    return [*(["nav"] if add_nav else []), "centre", *(["ctx"] if add_ctx else [])]


def applies(vs, cols, rows) -> bool:
    return cols >= 100 and rows >= 24 and vs.st == "verdict" and not vs.drill  # B: only the verdict inspector is extended (its empty rows carry the verification context)


def _hang(frame, text, width, tone="text", indent=2, first=""):
    """A wrapped list item with a hanging indent: `first` leads the first line, continuation lines are indented; an unbreakable token is middle-truncated at its separators, never cut mid-word."""
    s = frame.s
    body = frame.wrap(text, max(4, width - indent))
    out = []
    for i, line in enumerate(body or [""]):
        if len(line) > width - indent:
            line = frame._mid_ellipsis(line, width - indent)
        out.append([s((first if i == 0 and first else " " * indent) if True else "", "bold" if (i == 0 and first) else "text"), s(line, tone)])
    return out


def _nav_lines(vs, frame, artifact, context, width, height):
    s, fs = frame.s, frame.fs
    lines = [[s("FLOW", "label")]]
    active = _STEP.get(vs.st)
    for i, name in enumerate(["change", "claim", "check", "decision"]):
        if active is None:
            lines.append([s("  · " + name, "dim")])
        elif i < active:
            lines.append([s("  ✓ ", "dim"), s(name, "text")])
        elif i == active:
            lines.append([s("  › ", "bold"), s(name, "bold")])
        else:
            lines.append([s("  · " + name, "dim")])
    change = context.get("change") if isinstance(context.get("change"), dict) else {}
    if vs.st in {"offer", "claim", "running"} and change:
        label = str(change.get("label") or "change").split(" (", 1)[0]
        lines.extend([[], [s("SOURCE", "label")], *_hang(frame, label, width, "text", 0)])
        added, removed = change.get("added"), change.get("removed")
        if isinstance(added, int) and isinstance(removed, int):
            lines.append([s(f"+{added} −{removed}", "dim")])
        for row in (change.get("files") or [])[:6]:
            lines.append([s(frame._mid_ellipsis(str(row[0]), width), "text", None)])
    if vs.st == "verdict" and isinstance(artifact, dict) and artifact:
        word, _tone, status = frame._decision(artifact, frame._validation_errors(artifact))
        lines.extend([[], [s("THIS RUN", "label")], [s(frame._mid_ellipsis(str(frame._run_id(artifact, False, context, (word, _tone, status))), width), "text")],
                      *_hang(frame, f"{word} · exit {status}" if status is not None else word, width, "bold", 0)])
        rows_ = frame._obligations(artifact)
        if rows_:
            lines.extend([[], [s("OBLIGATIONS", "label")]])
            for i, row in enumerate(rows_[:8]):
                mark = "›" if (vs.focusAction == "obligation" and i == min(vs.focusIndex, len(rows_) - 1)) or (vs.focusAction != "obligation" and i == frame._initial_focus_index(artifact, 0)) else " "
                verdict = str(row.get("verdict", "")).upper()
                name = str(row.get("id", "")).replace(":", " · ", 1)
                lines.append([s(f"{mark} ", "bold"), s(verdict, "bold" if mark == "›" else "text")])
                lines.extend(_hang(frame, name, width, "dim", 4))
    history = context.get("history_rows") if isinstance(context.get("history_rows"), list) else []
    if history:
        lines.extend([[], [s("RECENT", "label")]])
        for row in history[:3]:
            state = (frame.history_state_text(row) if row.get("state") == "finished" else str(row.get("decision") or row.get("state") or "run")).replace("FINISHED · ", "")
            lines.append([s(frame._mid_ellipsis(str(row.get("run_id", "")), width), "text")])
            lines.extend(_hang(frame, f"{state} · {row.get('age', '')}".strip(" ·"), width, "dim", 2))
    return lines[:height]


def _ctx_lines(vs, frame, artifact, context, width, height):
    s, fs, P = frame.s, frame.fs, frame.P
    if vs.st == "verdict" and isinstance(artifact, dict) and artifact:
        return _verdict_context_lines(vs, frame, artifact, context, width)[:height]
    repo = context.get("repo") if isinstance(context.get("repo"), dict) else {}
    lines = [[s("REPOSITORY", "label")], [s(frame._mid_ellipsis(str(repo.get("name", "repository not recorded")), width), "text")],
             [s(fs(f"{repo.get('branch', 'not recorded')} at {frame._short_commit_id(repo.get('head'))}", width), "dim")]]
    if "changed" in repo:
        lines.append([s(fs(f"{repo.get('changed', 0)} changed · {repo.get('untracked', 0)} untracked", width), "dim")])
    lines.extend([[], [s("CHECKS", "label")], *P("Run on a disposable clone. Your repository is never written.", width, "dim"), [], [s("READINESS", "label")]])
    lines.extend(frame._readiness_rows(context, width))
    lines.extend([[], [s("RECORDS", "label")], *P(str(repo.get("records", "not scanned")), width, "dim")])
    if context.get("snapshot_at"):
        lines.extend([[], [s("SNAPSHOT", "label")], [s(fs(f"taken {context['snapshot_at']} · Offer: r reads again", width), "hint")]])
    return lines[:height]


def _mark_header(frame, lines, active, cue):
    """The pane that holds the keyboard focus carries a neutral marker on its header ('▌ '); for the lifetime of a focus cue the header is drawn one notch stronger. Other panes are untouched."""
    if not active or not lines or not lines[0]:
        return lines
    head = lines[0]
    text = "".join(g.text for g in head)
    return [[frame.s("▌ ", "bold"), frame.s(text, "emph" if cue else "bold")], *lines[1:]]


def _verdict_context_lines(vs, frame, artifact, context, width):
    """Under the verdict inspector (wide only): the verification context that must stay visible even on a HELD / LANDED verdict: readiness, the interpreter and its origin, the
    provenance identifiers the record holds and what the run did not explore. Only recorded facts; an absent field says so."""
    s, fs, P = frame.s, frame.fs, frame.P
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    lines = [[s("VERIFICATION CONTEXT", "label")], *frame._readiness_rows(context, width), []]
    lines.append([s("PROVENANCE", "label")])
    for key, value in (("base", run.get("base_commit_sha")), ("tree", run.get("base_tree_oid")), ("post", run.get("post_tree_oid"))):
        lines.append([s(fs(f"{key:<8}", 9), "dim"), s(fs(str(value)[:12] if value else "not recorded", max(1, width - 9)), "text")])
    landed = artifact.get("landed_commit") not in (None, "", False)
    target = run.get("landing_target")
    lines.extend(frame.kv("landing", ("rehearsal clone" if target == "rehearsal" else "your original repository" if target == "original" else frame._landing_target_text(artifact)) if landed else "nothing landed", width, 9, "text"))
    py = artifact.get("target_python") if isinstance(artifact.get("target_python"), dict) else None
    lines.extend(frame.kv("python", (f"{py.get('implementation', '')} {py.get('version', '')} · observed in the confined worker").strip() if py else "not recorded in the artifact", width, 9, "text"))
    limits = []
    for row in frame._obligations(artifact):
        ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        if ev.get("unexplored"):
            limits.append(str(ev["unexplored"]))
    lines.extend([[], [s("LIMITS", "label")], *(P(f"{len(limits)} obligation(s) record what was not explored; u shows it whole.", width, "dim") if limits else P("no unexplored text recorded", width, "dim"))])
    return lines


def render(frame, vs, cols, rows, artifact, *, elapsed, sample, context, color, size):
    """The wide Frame, or None when this state/width does not take the cockpit."""
    if not applies(vs, cols, rows):
        return None
    add_nav, add_ctx = _layout(vs, cols)
    nav_w = NAV_W + 3 if add_nav else 0
    ctx_w = CTX_W + 3 if add_ctx else 0
    inner_cols = cols - nav_w - ctx_w
    if inner_cols < (100 if vs.st in _INSPECTOR_STATES and not vs.drill else 80):
        return None  # the screen's own composition needs this much width; narrower keeps the plain layout
    bare = replace(vs, overlay=None) if vs.overlay else vs
    inner = frame.render(bare, inner_cols, rows, artifact, elapsed=elapsed, sample=sample, context=context, color=color, size=None, _wide=False, _dock=False)
    full = frame.render(vs, cols, rows, artifact, elapsed=elapsed, sample=sample, context=context, color=color, size=None, _wide=False, _dock=False)  # also carries the overlay, centred on the WHOLE viewport
    ctx_ = frame._sample(context, sample) or {}
    bottom_chrome = 3 if rows >= 26 else 2
    body_h = rows - 2 - bottom_chrome
    nav = _nav_lines(vs, frame, artifact, ctx_, NAV_W, body_h) if add_nav else []
    ctx = _ctx_lines(vs, frame, artifact, ctx_, CTX_W, body_h) if add_ctx else []
    region = vs.region if vs.region in regions(vs) else "centre"
    cue = bool((ctx_.get("motion") or {}).get("focus")) if isinstance(ctx_, dict) else False
    nav = _mark_header(frame, nav, region == "nav", cue)
    ctx = _mark_header(frame, ctx, region == "ctx", cue)
    # where the inner screen's own divider sits: the tint covers the canvas side (the side that holds the code), the other side stays the base surface
    counts: dict[int, int] = {}
    for y in range(2, rows - bottom_chrome):
        i = inner._text[y].find("│")
        if i > 0:
            counts[i] = counts.get(i, 0) + 1
    div = max(counts, key=counts.get) if counts else None
    sep = frame.s(" │ ", "rule")
    fill, fill_from = None, 0
    if vs.st == "verdict" and div is not None and isinstance(artifact, dict) and artifact and not sample:
        used = [y for y in range(2, rows - bottom_chrome) if inner._text[y][div:div + 1] == "│"]
        if used:
            fill_from = max(used) - 1  # first body row index after the last row that carries the divider
            fill = _verdict_context_lines(vs, frame, artifact, ctx_, len(inner._text[2]) - (div - 1) - 3)
            if body_h - fill_from < min(len(fill), 12):
                # the inspector's own text already runs to the bottom (a LANDED verdict's long EXPLORED list): the context moves under the navigation instead, so it is never missing
                nav = [*nav, [], *_verdict_context_lines(vs, frame, artifact, ctx_, NAV_W)][:body_h]
                fill = None
    text_rows, style_rows, bg_rows = [], [], []
    for y in range(rows):
        if y < 2 or y >= rows - bottom_chrome:
            text_rows.append(full._text[y]); style_rows.append(full._styles[y]); bg_rows.append(full._bg[y])
            continue
        parts_t, parts_s, parts_b = [], [], []
        k = y - 2
        if add_nav:
            seg = frame.fit(nav[k] if k < len(nav) else [], NAV_W)
            parts_t.append("".join(g.text for g in seg) + sep.text); parts_s.append([g.tone for g in seg for _ in g.text] + ["rule"] * len(sep.text)); parts_b.append("." * (NAV_W + len(sep.text)))
        row_t, row_s = inner._text[y], inner._styles[y]
        row_b = inner._bg[y]
        if fill is not None and div is not None and k >= fill_from and not row_t[div:].strip():
            # the inspector ran out of content: its empty rows carry the verification context instead of dead space (the divider continues beside it)
            j = k - fill_from
            seg = frame.fit(fill[j] if j < len(fill) else [], len(row_t) - (div - 1) - 3)
            row_t = row_t[:div - 1] + " │ " + "".join(g.text for g in seg)
            row_s = list(row_s[:div - 1]) + ["rule"] * 3 + [g.tone for g in seg for _ in g.text]
        # every pane shares the SAME base surface (maintainer: a calm, uniform instrument, no raised central fill); panes are separated by dividers, spacing and type, not by a background lift
        parts_t.append(row_t); parts_s.append(row_s); parts_b.append(row_b)
        if add_ctx:
            seg = frame.fit(ctx[k] if k < len(ctx) else [], CTX_W)
            parts_t.append(sep.text + "".join(g.text for g in seg)); parts_s.append(["rule"] * len(sep.text) + [g.tone for g in seg for _ in g.text]); parts_b.append("." * (len(sep.text) + CTX_W))
        text_rows.append("".join(parts_t)); style_rows.append([t for part in parts_s for t in part]); bg_rows.append("".join(parts_b))
    if vs.overlay:
        # a modal belongs to the whole viewport: copy the overlay panel cells (bg 'p') of the full-width render over the composed rows
        for y in range(rows):
            fb = full._bg[y]
            if "p" not in fb:
                continue
            xs = [x for x, ch in enumerate(fb) if ch == "p"]
            x0, x1 = xs[0], xs[-1] + 1
            text_rows[y] = text_rows[y][:x0] + full._text[y][x0:x1] + text_rows[y][x1:]
            style_rows[y] = list(style_rows[y][:x0]) + list(full._styles[y][x0:x1]) + list(style_rows[y][x1:])
            bg_rows[y] = bg_rows[y][:x0] + "p" * (x1 - x0) + bg_rows[y][x1:]
    if vs.overlay:
        frame.dim_behind(style_rows, bg_rows)
    out = frame.Frame(text_rows, style_rows, bg_rows, [f.action for f in inner.focus_order], inner.color, visibility=inner._visibility)
    out.nav = inner.nav
    return out



# ----------------------------------------------------------------------------------------------- the Event Log dock (every main screen with the height for it)

def dock_height(cols, rows) -> int:
    """Rows the bottom Event Log dock takes: none below 34 rows or 100 columns (80x24 and 100x30 keep every row for the work, the status row carries the run id and state), 4 rows
    (title + 3 events) from 34 rows, 7 (title + 6 events) from 40. reduce.py subtracts the same number from its page size, so paging never skips a line."""
    return 0  # the always-on dock is retired (B): real events are inline on Running


def dock_lines(frame, vs, cols, height, artifact, context):
    """The dock's rows, full width, REAL data only: the engine's own events as they arrive while running (and the tail of this run once it ended), else the newest recorded run's
    last events, else what the dock is waiting for. The title names the source; the right side carries the repository snapshot."""
    s, fs = frame.s, frame.fs
    width = cols - 4
    ctx = context if isinstance(context, dict) else {}
    tail = ctx.get("event_tail") if isinstance(ctx.get("event_tail"), list) else []
    last = ctx.get("last_event_tail") if isinstance(ctx.get("last_event_tail"), list) else []
    repo = ctx.get("repo") if isinstance(ctx.get("repo"), dict) else {}
    snap = ctx.get("snapshot_at")
    status = " · ".join(x for x in (f"snapshot {snap}" if snap else "", f"head {frame._short_commit_id(repo.get('head'))}" if repo.get("head") else "", str(repo.get("records", "")) if repo.get("records") else "") if x)
    if vs.st == "running":
        title, events = "EVENT LOG · live from the engine", tail
    elif tail and vs.st in {"verdict", "run-ended-no-decision", "run-lost", "artifact-unavailable"}:
        title, events = "EVENT LOG · this run", tail
    elif last:
        title, events = "EVENT LOG · last recorded run", last
    else:
        title, events = "EVENT LOG", []
    out = [[s(" ", "text"), *frame.lr([s(fs(title, max(1, width - len(status) - 2)), "label")], [s(status, "hint")] if status else [], width)]]
    room = max(0, height - 1)
    if events:
        fresh = {i for (rk, i) in ((ctx.get("motion") or {}).get("events") or ()) if rk == ctx.get("event_run_key")}  # real event ids that arrived a moment ago (never on reopen / history)
        shown = events[-room:]
        for n, ev in enumerate(shown):
            hot = ev.get("id") in fresh
            marker = "▸" if n == len(shown) - 1 and vs.st == "running" else " "  # the latest row of a live run is findable without any motion
            out.append([s(marker, "bold"), s(ev.get("ts", "--:--:--") + "  ", "emph" if hot else "dim"), s(fs(str(ev.get("phase", "-")), 11), "emph" if hot else "text"),
                        s(fs(str(ev.get("what", "")), max(1, width - 25)), "emph" if hot else "text")])
    else:
        waiting = ("waiting for the engine's first event" if vs.st == "running" else f"no run yet{' · snapshot ' + str(snap) if snap else ''}")
        out.append([s(" ", "text"), s("waiting     ", "label"), s(waiting, "dim")])
        if repo.get("name") or repo.get("branch"):
            out.append([s(" ", "text"), s("repository  ", "label"), s(fs(f"{repo.get('name', 'not recorded')} · {repo.get('branch', 'not recorded')} at {frame._short_commit_id(repo.get('head'))} · {repo.get('changed', 0)} changed · {repo.get('untracked', 0)} untracked", max(1, width - 13)), "text")])
        rd = ctx.get("readiness") if isinstance(ctx.get("readiness"), dict) else {}
        if rd:
            words = [f"{n} {(rd.get(n) or {}).get('status', 'not checked') if isinstance(rd.get(n), dict) else 'not checked'}" for n in ("boundary", "python")]
            out.append([s(" ", "text"), s("readiness   ", "label"), s(" · ".join(words), "text")])
    out = out[:height]
    while len(out) < height:
        out.append([])
    return [frame.fit(line, cols) for line in out]
