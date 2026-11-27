# SPDX-License-Identifier: Apache-2.0
"""Small terminal host for the pure operator renderer.

The host owns terminal I/O only. Input is decoded in bounded batches, view transitions go through
keys/reduce, and verdict words come exclusively from the frame's artifact projection.
"""

from __future__ import annotations

import argparse
import base64
import curses
import hashlib
import json
import re
import os
import select
import signal
import stat
import subprocess
import sys
import termios
import time
import tty
from concurrent.futures import Future
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock, Thread
from urllib.parse import urlsplit

from hlith.operator import gitq
from . import agent_note, frame, history, keys, offer_lead, reduce, theme
from .model import Record, ViewState, load


_EMPTY = {"format": 2, "outcome": None, "exit_status": None, "obligations": [], "blocking": [], "run": {}}
_CLEAR = "\x1b[H\x1b[2J"
_T0 = time.monotonic()


def _dump_frame(rendered, cols: int, rows: int, key) -> None:
    """Evidence hook (restored for the single terminal host): HLITH_UI_FRAMES=<file> appends each painted screen as plain text, in the format the
    pty evidence tests read ('=== frame RxC after key K t=..s' then the rows). Unset = nothing happens. A failing write never disturbs the screen."""
    path = os.environ.get("HLITH_UI_FRAMES")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n=== frame {rows}x{cols} after key {key!r} t={time.monotonic() - _T0:.1f}s\n"
                    + "\n".join(row.rstrip() for row in rendered.text_rows()) + "\n")
    except OSError:
        pass
_ALT_ENTER = "\x1b[?1049h"
_ALT_LEAVE = "\x1b[?1049l"


class _DaemonExecutor:
    """Run advisory repository/history reads without joining a stuck worker at process exit."""

    def __init__(self):
        self._lock = Lock()
        self._futures: set[Future] = set()
        self._shutdown = False

    def submit(self, fn, *args, **kwargs):
        future = Future()
        with self._lock:
            if self._shutdown:
                raise RuntimeError("executor has shut down")
            self._futures.add(future)

        def run():
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        future.set_result(fn(*args, **kwargs))
                    except BaseException as exc:
                        future.set_exception(exc)
            finally:
                with self._lock:
                    self._futures.discard(future)

        Thread(target=run, name="case", daemon=True).start()
        return future

    def shutdown(self, *, wait=False, cancel_futures=False):
        with self._lock:
            self._shutdown = True
            pending = tuple(self._futures) if cancel_futures else ()
        for future in pending:
            future.cancel()


def _copy_terminal_clipboard(value: str) -> None:
    """Request a local terminal clipboard copy using OSC 52; no shell helper is launched."""
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    sys.stdout.write(f"\x1b]52;c;{encoded}\x07")
    sys.stdout.flush()


def _terminal_can_run_screen(env) -> bool:
    """False for TERM unset / empty / dumb / unknown to terminfo: such a terminal cannot do cursor addressing, so the interactive screen would only paint junk and wait for keys."""
    term = env.get("TERM", "")
    if term in ("", "dumb"):
        return False
    try:
        curses.setupterm(term, sys.stdout.fileno() if sys.stdout.isatty() else 1)
    except (curses.error, OSError, ValueError):
        return False
    return True


def _mode() -> str:
    colors = 0
    try:
        curses.setupterm(os.environ.get("TERM", ""), sys.stdout.fileno())
        colors = curses.tigetnum("colors")
    except (curses.error, OSError, ValueError):
        pass
    return theme.color_mode(dict(os.environ), sys.stdout.isatty(), colors)


def _rgb256(n: int) -> tuple[int, int, int]:
    if n < 16:
        basic = ((0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0),
                 (0, 0, 238), (205, 0, 205), (0, 205, 205), (229, 229, 229),
                 (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0),
                 (92, 92, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255))
        return basic[n]
    if n >= 232:
        v = 8 + 10 * (n - 232)
        return v, v, v
    n -= 16
    return tuple(0 if v == 0 else 55 + 40 * v for v in (n // 36, (n // 6) % 6, n % 6))


def _attrs(spec: str) -> str:
    return ";".join(code for flag, code in (("b", "1"), ("d", "2"), ("u", "4"), ("r", "7")) if flag in spec)


def _hex_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))


def _gray_256_index(value: str) -> int:
    red, green, blue = _hex_rgb(value)
    return min(
        range(232, 256),
        key=lambda index: sum((a - b) ** 2 for a, b in zip((red, green, blue), _rgb256(index))),
    )


def _light_canvas(env) -> bool:
    """True only when the terminal itself says the canvas is light (COLORFGBG 'fg;bg' with bg 7 or 15, set by rxvt-family terminals and some others). No query is sent;
    an absent or unparsable value means unknown (never assumed light or dark)."""
    try:
        return int(str(env.get("COLORFGBG", "")).rsplit(";", 1)[-1]) in (7, 15)
    except ValueError:
        return False


def _drop_hue(env) -> bool:
    return env.get("HLITH_UI_COLOR") == "0" or (env.get("HLITH_UI_COLOR") != "1" and _light_canvas(env))


def _HUE_DROPPED(env):
    """HLITH_UI_COLOR=0 drops every semantic hue. A terminal that reports a LIGHT canvas drops green / yellow / cyan (the standard palette's slots 32/33/36 measure 1.7-2.2:1 on
    white, scripts/native_contrast.py) and keeps red (5.8:1) so a refutation is still marked; HLITH_UI_COLOR=1 forces the full hue back."""
    every = {"30", "31", "32", "33", "34", "35", "36", "37", "91"}
    return every if env.get("HLITH_UI_COLOR") == "0" else {"32", "33", "36"}


def _sgr(style: str, mode: str, surface: str | None = None) -> str:
    style = frame._TOKEN.get(style, style)
    if mode in {"mono_truecolor", "mono_256"}:
        style = frame._MONO.get(style, style)
    style = {"chip": "chip.text", "chipOk": "chip.ok", "chipBad": "chip.bad",
             "chipWarn": "chip.warn", "selected": "sel"}.get(style, style)
    if mode == "mono":
        return _attrs(theme.MONO.get(style, ""))
    if mode in {"stitch_truecolor", "stitch_light"}:
        table, c_bg, c_panel, c_band = (
            (theme.STITCH_LIGHT, theme.STITCH_LIGHT_BG, theme.STITCH_LIGHT_PANEL, theme.STITCH_LIGHT_BAND)
            if mode == "stitch_light"
            else (theme.STITCH_DARK, theme.STITCH_DARK_BG, theme.STITCH_DARK_PANEL, theme.STITCH_DARK_BAND)
        )
        fg, bg, attrs = table.get(style, table[""])
        base = c_band if surface == "z" else c_panel if surface in {"p", "t"} else c_bg
        codes = ["38", "2", *(str(v) for v in _hex_rgb(fg)), "48", "2", *(str(v) for v in _hex_rgb(bg or base))]
        if attrs:
            codes.extend(_attrs(attrs).split(";"))
        return ";".join(codes)
    if mode in {"stitch_256", "stitch_light_256"}:
        table, c_bg, c_panel, c_band = (
            (theme.STITCH_LIGHT_256, theme.STITCH_LIGHT_256_BG, theme.STITCH_LIGHT_256_PANEL, theme.STITCH_LIGHT_256_BAND)
            if mode == "stitch_light_256"
            else (theme.STITCH_256, theme.STITCH_256_BG, theme.STITCH_256_PANEL, theme.STITCH_256_BAND)
        )
        fg256, bg256, attrs = table.get(style, table[""])
        base256 = c_band if surface == "z" else c_panel if surface in {"p", "t"} else c_bg
        codes = ["38", "5", str(fg256), "48", "5", str(base256 if bg256 is None else bg256)]
        if attrs:
            codes.extend(_attrs(attrs).split(";"))
        return ";".join(codes)
    if mode == "stitch_16":
        spec = theme.STITCH_16.get(style, "")
        if spec and os.environ.get("HLITH_UI_FAINT") == "0":
            spec = ";".join(code for code in spec.split(";") if code != "2")
        if spec and _drop_hue(os.environ):
            spec = ";".join(code for code in spec.split(";") if code not in (_HUE_DROPPED(os.environ) | {"92", "93"}))
        if spec and _light_canvas(os.environ):
            spec = ";".join("31" if code == "91" else code for code in spec.split(";"))
        return spec
    if mode in {"dainty", "dun"}:
        table, c_bg, c_tint, c_band = ((theme.DAINTY, theme.DAINTY_BG, theme.DAINTY_TINT, theme.DAINTY_BAND) if mode == "dainty" else (theme.DUN, theme.DUN_BG, theme.DUN_TINT, theme.DUN_BAND))
        fg, bg, attrs = table.get(style, table[""])
        base = c_band if surface == "z" else c_tint if surface in {"p", "t"} else c_bg  # the wide cockpit's centre canvas is the raised surface, everything else the base
        codes = ["38", "2", *(str(v) for v in _hex_rgb(fg)), "48", "2", *(str(v) for v in _hex_rgb(bg or base))]
        if attrs:
            codes.extend(_attrs(attrs).split(";"))
        return ";".join(codes)
    if mode == "native":
        spec = theme.NATIVE.get(style, "")  # no 38 / 48 anywhere: the terminal's own foreground and background
        if spec and os.environ.get("HLITH_UI_FAINT") == "0":  # opt-out for very low-contrast themes: rules keep the default ink instead of faint
            spec = ";".join(code for code in spec.split(";") if code != "2")
        if spec and _drop_hue(os.environ):
            spec = ";".join(code for code in spec.split(";") if code not in _HUE_DROPPED(os.environ))
        if spec and _light_canvas(os.environ):  # bright red is for dark / unknown canvases; a canvas reported light keeps the plain red slot
            spec = ";".join("31" if code == "91" else code for code in spec.split(";"))
        return spec
    if mode in {"mono_truecolor", "mono_256"}:
        fg, bg, attrs = theme.MONO_RGB.get(style, theme.MONO_RGB["text"])
        if bg is None:
            bg = {"z": "#151514", "p": "#181817"}.get(surface, "#0b0b0b")
        codes = []
        if mode == "mono_truecolor":
            codes.extend(("38", "2", *(str(v) for v in _hex_rgb(fg))))
            codes.extend(("48", "2", *(str(v) for v in _hex_rgb(bg))))
        else:
            codes.extend(("38", "5", str(_gray_256_index(fg)),
                          "48", "5", str(_gray_256_index(bg))))
        if attrs:
            codes.extend(_attrs(attrs).split(";"))
        return ";".join(codes)
    fg256, bg256, fg16, bg16, attrs = theme.RICH.get(style, theme.RICH[""])
    codes = []
    if mode == "truecolor":
        r, g, b = _rgb256(fg256)
        codes.extend(("38", "2", str(r), str(g), str(b)))
        if bg256 >= 0:
            r, g, b = _rgb256(bg256)
            codes.extend(("48", "2", str(r), str(g), str(b)))
    elif mode == "256":
        if fg256 >= 0:
            codes.extend(("38", "5", str(fg256)))
        if bg256 >= 0:
            codes.extend(("48", "5", str(bg256)))
    elif mode == "16":
        if fg16 >= 0:
            codes.append(str((90 if fg16 >= 8 else 30) + fg16 % 8))
        if bg16 >= 0:
            codes.append(str((100 if bg16 >= 8 else 40) + bg16 % 8))
    if attrs:
        codes.extend(_attrs(attrs).split(";"))
    return ";".join(codes)


def ansi_frame(rendered, mode: str) -> str:
    """Serialize exact renderer cells with semantic color; plain mode has no control bytes."""
    rows = rendered.text_rows()
    if mode == "plain":
        return "\n".join(rows)
    styles = rendered._styles
    surfaces = rendered.bg_rows()
    out = []
    for y, row in enumerate(rows):
        last = None
        for x, char in enumerate(row):
            style = styles[y][x]
            surface = surfaces[y][x] if mode in {"stitch_truecolor", "stitch_light", "stitch_256", "stitch_light_256", "mono_truecolor", "mono_256", "dainty", "dun"} else None
            current = (style, surface)
            if current != last:
                code = _sgr(style, mode, surface)
                out.append(f"\x1b[0;{code}m" if code else "\x1b[0m")
                last = current
            out.append(char)
        out.append("\x1b[0m")
        if y + 1 < len(rows):
            out.append("\r\n")
    return "".join(out)


def _terminal_size() -> tuple[int, int]:
    size = os.get_terminal_size(sys.stdout.fileno())
    return max(0, size.columns), max(0, size.lines)


def _read_regular_bytes(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError("file changed beyond its read limit")
        return bytes(data)
    finally:
        os.close(fd)


def _read_small(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()[:200]
    except OSError:
        return None


def _boundary_causes(abi: int, userns: bool) -> list[dict]:
    """The oracle's CAUSE rows (landlock / user ns), each from a real read of this host; nothing here is invented."""
    if abi >= 6:
        landlock = {"label": "landlock", "status": "ready", "tone": "ok", "detail": f"abi {abi}"}
    elif abi >= 1:
        landlock = {"label": "landlock", "status": "unavailable", "tone": "bad", "detail": f"abi {abi}; the engine requires 6"}
    else:
        lsm = _read_small("/sys/kernel/security/lsm")
        detail = "not in the active LSM list" if lsm is not None and "landlock" not in lsm.split(",") else "not reported by this kernel"
        landlock = {"label": "landlock", "status": "unavailable", "tone": "bad", "detail": detail}
    if userns:
        ns = {"label": "user ns", "status": "ready", "tone": "ok", "detail": "user namespaces enabled"}
    else:
        restrict = _read_small("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        detail = "apparmor_restrict_unprivileged_userns = 1" if restrict == "1" else "max_user_namespaces = 0 or unreadable"
        ns = {"label": "user ns", "status": "blocked", "tone": "bad", "detail": detail}
    return [landlock, ns]


def _boundary_recovery_command(causes: list) -> str:
    for row in causes if isinstance(causes, list) else []:
        if isinstance(row, dict) and row.get("label") == "user ns" and "apparmor_restrict_unprivileged_userns = 1" in str(row.get("detail")):
            return "sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0"
    return "Re-check the host boundary"


_NO_BOUNDARY_COMMAND = "Re-check the host boundary"


def _boundary_copy_text(blocked: dict) -> str:
    """What `c` copies on a boundary block: the recovery command when the host knows a real one, else the recorded causes as a sentence. The generic 'Re-check the host boundary'
    is an instruction, not a command, so it is never put on the clipboard as if it were one."""
    command = str(blocked.get("command") or "")
    if command and command != _NO_BOUNDARY_COMMAND:
        return command
    rows = [r for r in blocked.get("cause", []) if isinstance(r, dict)]
    parts = "; ".join(f"{r.get('label', '?')} {r.get('status', '?')} ({r.get('detail', 'not recorded')})" for r in rows)
    return "Hlith cannot start checks on this host: " + (parts or "boundary unavailable") + ". Nothing was run."


def _boundary_block(context: dict) -> dict | None:
    """Fresh at call time, through the SAME _readiness function the start path uses: None when the boundary is ready, else the blocked context fields.
    This can only REMOVE starts (the caller never reaches launch.start when it returns a block)."""
    repo = Path(context.get("repo", {}).get("path") or ".")
    readiness, target_python = _readiness(repo, context.get("target_python"))
    boundary = readiness.get("boundary") if isinstance(readiness, dict) else None
    if not isinstance(boundary, dict) or boundary.get("status") == "ready":
        return None
    causes = boundary.get("causes")
    if not isinstance(causes, list) or not causes:  # a readiness that carries no per-cause rows: say what is known, claim nothing else
        causes = [{"label": "landlock", "status": "unavailable", "tone": "bad", "detail": str(boundary.get("detail", "not recorded"))},
                  {"label": "user ns", "status": "not probed", "tone": "dim", "detail": "not separately recorded"}]
    return {"readiness": readiness, "target_python": target_python,
            "blocked": {"kind": "boundary", "cause": causes, "command": _boundary_recovery_command(causes)}}


def _readiness(repo: Path, explicit_python: str | None) -> tuple[dict, str | None]:
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        abi = int(libc.syscall(444, None, 0, 1))
    except (OSError, AttributeError, ValueError):
        abi = -1
    try:
        userns = int(Path("/proc/sys/user/max_user_namespaces").read_text().strip() or "0") > 0
    except (OSError, ValueError):
        userns = False
    causes = _boundary_causes(abi, userns)
    if abi >= 6 and userns:
        boundary = {"status": "ready", "tone": "ok", "detail": f"landlock abi {abi} · user ns"}
    elif abi >= 6:
        boundary = {"status": "unavailable", "tone": "warn", "detail": f"landlock abi {abi} · user namespaces unavailable"}
    elif abi >= 1:
        boundary = {"status": "unavailable", "tone": "bad", "detail": f"landlock abi {abi}; engine requires 6"}
    else:
        boundary = {"status": "unavailable", "tone": "bad", "detail": "landlock not reported by this kernel"}
    boundary = {**boundary, "causes": causes}

    from ..target_python import select_interpreter

    selected, origin, engine_arg = select_interpreter(repo, explicit_python)
    passed_to_engine = engine_arg is not None
    source = origin.removeprefix("repository ").removeprefix("explicit ") if passed_to_engine else "launcher default"

    try:
        mode = Path(selected).stat().st_mode
        available = stat.S_ISREG(mode) and bool(mode & 0o111)
    except OSError:
        available = False
    version = _static_python_version(selected) if available else None
    python = {
        "status": "ready" if available else "unavailable",
        "tone": "ok" if available else "bad",
        "path": _tilde(selected),
        "version": version or "not probed",
        "source": source,
    }
    if source == "launcher default":
        # the check imports the TARGET's own dependencies inside this interpreter: when the repository declares any and no interpreter of its own was found or chosen, say so
        declared = [name for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py", "setup.cfg", "Pipfile") if (repo / name).is_file()]
        if declared:
            python["warning"] = f"the repository declares dependencies ({declared[0]}) but this is Hlith's own interpreter; they may not import · use --target-python"
    return {"boundary": boundary, "python": python}, selected if passed_to_engine else None


def _hunk_symbol(diff: str) -> str:
    """The function the FIRST changed line of the diff sits in. git's hunk header names the function ABOVE the hunk ('@@ ... @@ def total(...)'), which is not the function that changed when the hunk
    starts in a neighbouring one (observed: a change inside `clamp` was offered as `total`). So: the nearest `def` visible at or above the first +/- line inside the hunk (context, added or
    removed) wins; only when none is visible does the header's own text stand (git's funcname context, real data). '' when neither names one."""
    header_text = ""
    seen_header = False
    current = ""
    for line in diff.split("\n"):
        if line.startswith("@@"):
            if seen_header:
                if current:
                    return current  # a hunk that changed nothing nameable: keep the first named function seen
            seen_header = True
            _a, sep, rest = line[2:].partition("@@")
            text = "".join(ch for ch in rest.strip() if ch.isprintable())[:60].rstrip(": ")
            for prefix in ("async def ", "def ", "class ", "function ", "func "):
                if text.startswith(prefix):
                    text = text[len(prefix):]
                    break
            header_text = text if sep else ""
            current = header_text
            continue
        if not seen_header or not line or line[0] not in " +-":
            continue
        body = line[1:]
        m = re.match(r"\s*(?:async\s+)?def\s+(.+?):?\s*$", body)
        if m:
            current = "".join(ch for ch in m.group(1) if ch.isprintable())[:60].rstrip(": ")
        if line[0] in "+-":
            return current
    return header_text


def _tilde(path) -> str:
    """Shorten the home directory for display only."""
    text = str(path)
    home = str(Path.home())
    return "~" + text[len(home):] if home != "/" and (text == home or text.startswith(home + os.sep)) else text


def _static_python_version(selected: str) -> str | None:
    """Read a venv version label without executing its repository-controlled Python."""
    try:
        cfg = Path(selected).parent.parent / "pyvenv.cfg"
        raw = _read_regular_bytes(cfg, 65536).decode("utf-8", "replace")
        found = {}
        for line in raw.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip().lower() in ("version", "version_info"):
                found[key.strip().lower()] = value.strip()
        value = found.get("version") or found.get("version_info")
        if value and len(value) <= 40 and all(c.isalnum() or c in ".-+" for c in value):
            return value
    except (OSError, ValueError):
        pass
    return None


def _render(state: ViewState, artifact: dict, context: dict, color: str, elapsed: int = 0) -> str:
    cols, rows = state.cols, state.rows
    rendered = frame.render(state, cols, rows, artifact, elapsed=elapsed, sample=False, context=context, color=color)
    return ansi_frame(rendered, color)


def _repo_context(root: Path, inputs=(), target_python: str | None = None) -> dict:
    """Read a minimal hardened Git snapshot; executable repository config blocks inspection."""
    repo, why = gitq.toplevel(root)
    if repo is None:
        return _git_blocked_context(root, why or "Git repository could not be read.")
    reason = gitq.refusal(repo)
    if reason:
        return _git_blocked_context(repo, reason)
    try:
        gitq.require_supported_git()
        head_oid = gitq.optional_text(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}")
        if head_oid is None:
            branch = gitq.optional_text(repo, "symbolic-ref", "-q", "--short", "HEAD") or ""
            head = ""
        else:
            branch = gitq.read_text(repo, "branch", "--show-current")
            head = gitq.read_text(repo, "rev-parse", "--short=8", "HEAD")
        status = gitq.read(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    except (gitq.GitReadError, RuntimeError) as exc:
        return _git_blocked_context(repo, str(exc))
    fields = status.split(b"\0")
    sources = []
    i = 0
    while i < len(fields) and fields[i]:
        entry = fields[i]
        i += 1
        code = entry[:2].decode("ascii", "replace")
        path = os.fsdecode(entry[3:])
        if "R" in code or "C" in code:
            i += 1  # the next NUL field is the source path; display the destination path only
        sources.append({"g": "WORKTREE", "id": "u", "label": path, "meta": code, "file": path})
    conflicted = [x["label"] for x in sources if "U" in x["meta"] or x["meta"] in {"AA", "DD"}]
    if conflicted:  # TUI behavior (review R3 walkthrough): conflict markers are not 'Uncommitted work'; say so instead of offering Review change (the engine could only end exit 11)
        return _git_blocked_context(repo, f"a merge is in progress with unresolved conflicts in {len(conflicted)} file(s) ({conflicted[0]}"
                                          f"{'…' if len(conflicted) > 1 else ''}): resolve or abort the merge, then reopen. Nothing was checked.")
    status_sources = sources
    changed = len(status_sources)
    untracked = sum(1 for x in status_sources if x["meta"] == "??")
    repo_name = repo.name or str(repo)
    from . import changes, launch

    try:
        discovered = changes.discover(repo, inputs)
    except gitq.GitReadError as exc:
        return _git_blocked_context(repo, str(exc))
    manifest_by_patch = {str(p.resolve()): m for p, m in launch.find_pairs([repo, *inputs]) if m is not None}
    for change in discovered:
        if change.kind != "patchfile":
            continue
        manifest = manifest_by_patch.get(str(Path(change.source).resolve()))
        if manifest is None:
            change.problem = change.problem or "paired manifest not found; this patch cannot be checked"
            continue
        try:
            change._manifest_path = str(manifest.resolve())
            change._manifest_raw = _read_regular_bytes(manifest, 1024 * 1024)
        except (OSError, RuntimeError, ValueError) as exc:
            change.problem = f"paired manifest is unavailable: {exc}"
    reason = gitq.refusal(repo)
    if reason:
        return _git_blocked_context(repo, reason)
    if discovered:
        sources = [{"g": {"uncommitted": "WORKTREE", "commit": "COMMITS", "branch": "BRANCHES",
                           "patchfile": "PATCHES"}.get(change.kind, "CHANGES"),
                    "id": "u" if change.kind == "uncommitted" else f"{change.kind}:{i}",
                    "kind": change.kind, "label": change.label, "meta": change.summary(),
                    "detail": change.detail, "problem": change.problem,
                    "file": change.files[0][0] if change.files else "",
                    "files": list(change.files), "_change": change}
                   for i, change in enumerate(discovered)]
    elif status_sources:
        # A repository with no commit has no base to diff, so changes.discover()
        # cannot create a runnable Change. Keep the actual status paths visible
        # and make the missing base explicit instead of presenting an empty offer.
        sources = [{"g": "WORKTREE", "id": f"uncommitted:{i}", "kind": "uncommitted",
                    "label": "Uncommitted work (no base commit)", "meta": row["meta"],
                    "file": row["file"], "files": [(row["file"], None, None)],
                    "problem": "no base commit; create an initial commit before checking this change"}
                   for i, row in enumerate(status_sources)]
    else:
        sources = []
    readiness, selected_python = _readiness(repo, target_python)
    has_base = bool(head)
    context = {
        "repo": {"path": str(repo), "name": repo_name,
                 "branch": branch or "detached",
                 "head": head or "not recorded", "has_base": has_base,
                 "changed": changed, "untracked": untracked, "records": "none yet · not scanned"},
        "sources": sources,
        "snapshot_at": time.strftime("%H:%M"),
        "discovery": {"summary": ("no base commit" if not has_base else
                                   f"{len(sources)} change(s) available" if sources else "no changes available")},
        "inputs": [str(Path(path).expanduser()) for path in inputs],
        "target_python": selected_python,
        "readiness": readiness,
    }
    if sources:
        context["change"] = _change_snapshot(repo, sources[0])
        context["selected_change"] = sources[0].get("_change")
        context["selected_source_id"] = sources[0].get("id")
        context["can_run"] = context["change"].get("can_run") is True
        context["can_review"] = any(
            source.get("_change") is not None
            and bool(source["_change"].files)
            and not source.get("problem")
            for source in sources
        )
    return context


def _git_blocked_context(repo: Path, reason: str) -> dict:
    return {"repo": {"path": str(repo), "name": repo.name or str(repo), "branch": "not recorded",
                      "head": "not recorded", "changed": 0, "untracked": 0, "records": "none yet · not scanned"},
            "sources": [], "discovery": {"summary": "repository was not inspected"},
            "blocked": {"reason": reason}}


def _change_snapshot(repo: Path, source: dict) -> dict:
    """Read one exact changed path and a bounded diff for the selection/claim preview."""
    path = str(source.get("file") or "")
    if source.get("problem") and source.get("_change") is None:
        size = None
        if source.get("meta") == "??" and path:
            try:
                info = (repo / path).lstat()
                if stat.S_ISREG(info.st_mode):
                    size = info.st_size
            except OSError:
                pass
        return {"label": source.get("label", "Uncommitted work"), "file": path or "not recorded",
                "note": str(source["problem"]), "diff": "", "kind": source.get("kind", "uncommitted"),
                "base_rev": "not recorded", "files": list(source.get("files", [])), "can_run": False,
                "new_file": source.get("meta") == "??", "bytes": size}
    change = source.get("_change")
    if change is not None:
        if change.problem:
            return {"label": change.label, "file": path or "not recorded", "note": change.problem,
                    "diff": "", "kind": change.kind, "base_rev": change.base_rev, "can_run": False}
        try:
            data = change.diff()
        except Exception as exc:
            note = f"Selected change {change.label}: {exc}"
            return {"label": change.label, "file": path or "not recorded", "note": note,
                    "diff": "", "kind": change.kind, "base_rev": change.base_rev, "can_run": False}
        reason = gitq.refusal(repo)
        if reason:
            return {"label": change.label, "file": path or "not recorded", "note": reason,
                    "diff": "", "kind": change.kind, "base_rev": change.base_rev, "can_run": False,
                    "git_blocked": reason}
        _count, added, removed = change.stats
        diff = data.decode("utf-8", "replace")
        return {"label": change.label, "file": path or "no files recorded", "added": added, "removed": removed,
                "bytes": len(data), "hunks": sum(line.startswith("@@") for line in diff.split("\n")), "symbol": _hunk_symbol(diff),
                "diff": diff, "kind": change.kind, "base_rev": change.base_rev,
                "files": list(change.files), "can_run": bool(data) and not change.oversize,
                "tool_state": [i.path for i in change.infos if i.tool_state and getattr(i, "untracked", False)]}
    if not path:
        return {"label": "Uncommitted work", "file": "path not recorded", "note": "path not recorded", "diff": ""}
    reason = gitq.refusal(repo)
    if reason:
        return {"label": "Uncommitted work", "file": path, "note": reason, "diff": "", "git_blocked": reason}
    is_untracked = source.get("meta") == "??"
    args = (["diff", "--no-index", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=2", "--", "/dev/null", path]
            if is_untracked else
            ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=2", "HEAD", "--", path])
    try:
        stream = gitq.open_stream(repo, args)
        raw = bytearray()

        def _on_chunk(chunk: bytes) -> bool:
            raw.extend(chunk)
            return len(raw) <= 1024 * 1024

        killed, timed_out, err = gitq.drain_stream(stream, on_chunk=_on_chunk, timeout=gitq.TIMEOUT)
        gitq.finish_stream(
            stream,
            stderr_bytes=err,
            killed_for_limit=killed,
            timed_out=timed_out,
            allow_returncodes=(0, 1) if is_untracked else (0,),
            timeout=gitq.TIMEOUT,
        )
        if len(raw) > 1024 * 1024:
            raw = raw[:1024 * 1024]
    except gitq.GitReadError as exc:
        if exc.kind is gitq.GitReadErrorKind.REPOSITORY_REFUSED:
            return {"label": "Uncommitted work", "file": path, "note": str(exc), "diff": "", "git_blocked": str(exc)}
        if exc.kind is gitq.GitReadErrorKind.TIMEOUT:
            return {"label": "Uncommitted work", "file": path, "note": "diff could not be read within the preview limit", "diff": ""}
        return {"label": "Uncommitted work", "file": path, "note": str(exc), "diff": ""}
    except OSError as exc:
        reason = gitq.refusal(repo)
        if reason:
            return {"label": "Uncommitted work", "file": path, "note": reason, "diff": "", "git_blocked": reason}
        return {"label": "Uncommitted work", "file": path, "note": str(exc), "diff": ""}
    except subprocess.SubprocessError:
        return {"label": "Uncommitted work", "file": path, "note": "diff could not be read within the preview limit", "diff": ""}
    raw = bytes(raw)
    diff = raw.decode("utf-8", "replace")
    added = sum(1 for line in diff.split("\n") if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff.split("\n") if line.startswith("-") and not line.startswith("---"))
    return {"label": "Uncommitted work", "file": path, "added": added, "removed": removed,
            "bytes": len(raw), "hunks": sum(line.startswith("@@") for line in diff.split("\n")), "symbol": _hunk_symbol(diff),
            "diff": diff, "note": "diff is not available for this path" if not diff else ""}


def _selection_context(context: dict, state: ViewState) -> dict:
    sources = context.get("sources", [])
    if not sources or state.st not in {"selection", "claim"}:
        return context
    repo_path = Path(context.get("repo", {}).get("path") or ".")
    if state.st == "claim" and context.get("selected_change") is not None:
        # Claim is a frozen review of the exact source selected at the transition.
        return context
    index = state.selectedIndex if state.st == "claim" and state.selectedIndex is not None else state.focusIndex
    selected = sources[min(max(0, index), len(sources) - 1)]
    if context.get("selected_source_id") == selected.get("id") and "change" in context:
        return context
    change = _change_snapshot(repo_path, selected)
    if change.get("git_blocked"):
        return {**context, "sources": [], "change": change, "blocked": {"reason": change["git_blocked"]}}
    return {**context, "change": change, "selected_change": selected.get("_change"),
            "selected_source_id": selected.get("id"),
            "can_run": change.get("can_run") is True}


def _loading_actions_allowed(state: ViewState, events) -> bool:
    """Keep repository-dependent flow actions unavailable until inspection completes."""
    safe_without_repository = {"key:esc", "key:q", "key:h", "key:?"}
    navigation = {"key:tab", "key:enter", "key:up", "key:down", "key:pgup", "key:pgdn", "key:home", "key:end"}
    current = state
    for event in events:
        action = keys.action_for(current, event)
        if action in safe_without_repository:
            current = reduce.reduce(current, action)
            continue
        if action in navigation and current.overlay in {"exit", "quit"}:
            current = reduce.reduce(current, action)
            continue
        if action in navigation and current.st == "history":
            # History is backed by the cached state scan and does not inspect the repo.
            current = reduce.reduce(current, action)
            continue
        return False
    return True


def _default_offer_focus(state: ViewState, context: dict) -> ViewState:
    """TUI behavior: a change with NO Python file gets nothing from a check (it ends NOT-DERIVED), so the Offer's default focus is `[ Other sources ]`, but only when there IS an
    alternative source to look at. Enter on either button opens the Selection; this only changes which one the first Enter is announced for. Unchanged for every other change."""
    if state.st != "offer" or state.focusIndex != 0 or state.focusAction is not None or state.overlay or state.drill:
        return state
    if context.get("repository_loading") or not frame._no_python(context.get("change")) or len(context.get("sources") or []) < 2:
        return state
    if context.get("offer_lead"):
        return state  # the lead (a running or unseen check) is the first focus; this default must not steal it
    return replace(state, focusIndex=1)


def _apply_loaded_repository(context: dict, state: ViewState, loaded: dict) -> dict:
    """Apply async discovery only to repo views; preserve historical artifact identity."""
    if not loaded.get("blocked") and isinstance(loaded.get("repo"), dict) and loaded["repo"].get("path"):
        from . import repos

        repos.remember(Path(loaded["repo"]["path"]), history.state_dir())
    existing_records = (context.get("repo") or {}).get("records")
    preserve_records = (
        isinstance(existing_records, str)
        and (context.get("history_scan_complete") is True or "not scanned" not in existing_records)
    )
    if preserve_records and isinstance(loaded.get("repo"), dict):
        loaded = {**loaded, "repo": {**loaded["repo"], "records": existing_records}}
    if state.st in {"offer", "selection", "claim"}:
        updated = _selection_context({**context, **loaded}, state)
        return {**updated, "repository_loading": False,
                "home_repo": dict(updated.get("repo", {}))}
    if state.st == "history" and isinstance(loaded.get("repo"), dict):
        # the header must name the repository once its facts are known (the list itself never depended on them); the records line stays the scan's own
        repo = {**loaded["repo"], "records": (context.get("repo") or {}).get("records", loaded["repo"].get("records"))}
        return {**context, "repo": repo, "repository_loading": False, "home_repo": dict(loaded["repo"])}
    return {**context, "repository_loading": False,
            "home_repo": dict(loaded.get("repo", {}))}


def _record_age(when: float) -> str:
    seconds = max(0, int(time.time() - when))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _scan_history(repo_root):
    """Worker-side history scan: rows plus the count of repository folders left unread (own unit, never summed with run folders)."""
    from . import launch

    rows, total, truncated, scanned = launch.run_rows_with_summary(None, repo_root)
    return rows, total, truncated, scanned, _safe_omitted(repo_root)


def _safe_omitted(repo_root) -> int:
    from . import launch

    try:
        return launch.omitted_history_repositories(None, repo_root)
    except Exception:  # noqa: BLE001 - advisory count
        return 0


def _records_summary(rows: list[dict], total_count: int | None = None, *, truncated=False, scanned=None, omitted_repos=0) -> str:
    total = len(rows) if total_count is None else total_count
    latest = rows[0] if rows else None
    running = sum(row.get("state") == "running" for row in rows)
    if total == 0:
        return f"none yet · {_tilde(history.state_dir())}"
    if truncated:
        summary = f"history truncated: scanned {scanned or len(rows)} of {total} run folders · {len(rows)} shown"
        if omitted_repos:
            summary += f" · {omitted_repos} more repository folders not scanned"
    else:
        summary = f"{total} record{'s' if total != 1 else ''}"
        if total > len(rows):
            summary += f" · newest {len(rows)} of {total} shown"
    if latest is None:
        return summary
    last_decision = latest.get("decision") or "decision not recorded"
    age = latest.get("age") or _record_age(latest.get("when") or 0)
    summary += f" · last {last_decision} {age}"
    if running:
        summary += f" · {running} run{'s' if running != 1 else ''} running"
    return summary


def _artifact_error_summary(record: Record | None) -> str:
    if record is None or not record.errors:
        return "the recorded artifact could not be read or validated"
    return "; ".join(str(error) for error in record.errors[:3])[:500]


def _artifact_path_missing(path) -> bool:
    try:
        Path(path).lstat()
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _repository_loading_context(root: Path) -> dict:
    return {"repo": {"path": str(root), "name": "reading repository…", "branch": "reading…",
                     "head": "not recorded", "changed": 0, "untracked": 0, "records": "reading history…"},
            "sources": [], "discovery": {"summary": "reading repository…"}, "repository_loading": True}


def _artifact_context(artifact: dict) -> dict:
    """Build historical identity from artifact fields; repository_url is display data, never a path to open."""
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    repository = _artifact_repository_label(run.get("repository_url"))
    head = run.get("base_commit_sha")
    return {"repo": {"path": repository, "name": repository,
                     "branch": "branch not recorded",
                     "head": str(head or "not recorded"), "has_base": bool(head),
                     "changed": 0, "untracked": 0, "records": "not applicable"}}


def _artifact_repository_label(value) -> str:
    """Sanitize the schema's repository URL/path as display text without touching the referenced resource."""
    if not isinstance(value, str) or not value.strip():
        return "repository not recorded"
    raw = value.strip()
    safe = frame._clean(raw)
    try:
        parsed = urlsplit(safe)
        if parsed.scheme.lower() == "file":
            label = PurePosixPath(parsed.path.rstrip("/")).name
        elif parsed.scheme and parsed.hostname:
            host = parsed.hostname
            try:
                port = parsed.port
            except ValueError:
                port = None
            if port is not None:
                host = f"{host}:{port}"
            label = host + (f"/{parsed.path.strip('/')}" if parsed.path.strip("/") else "")
        else:
            label = ""
    except ValueError:
        label = ""
    if not label:
        windows_path = raw.startswith("\\\\") or (len(raw) >= 3 and raw[1] == ":" and raw[2] in "\\/")
        path = PureWindowsPath(raw) if windows_path else PurePosixPath(raw)
        label = path.name or raw
    return frame._clean(label)[:120] or "repository not recorded"


def _seed_tool_exclusions(state: ViewState, context: dict):
    """Once per source: the UNTRACKED agent/tool-state files of an uncommitted change start unchecked in the selection (visible as `[ ]`, counted in "N of M files
    included", included again with space or `a`). A deliberate inclusion is never undone: seeding is remembered per source. Fail closed: unknown paths stay included."""
    if state.st != "selection":
        return state, context
    source = state.focusIndex
    done = context.get("tool_seeded") or ()
    if source in done:
        return state, context
    change = context.get("change") if isinstance(context.get("change"), dict) else {}
    files = change.get("files")
    if change.get("kind") != "uncommitted" or not isinstance(files, list):
        return state, context
    left_out = set(change.get("tool_state") or ())
    context = {**context, "tool_seeded": tuple(done) + (source,)}
    seeded = {(source, fi) for fi, f in enumerate(files) if str(f[0]) in left_out}
    if not seeded:
        return state, context
    return replace(state, excluded_files=tuple(sorted(set(state.excluded_files) | seeded))), context


def _with_file_count(state: ViewState, context: dict) -> ViewState:
    """The reducer never invents how many files the focused source has: the host sets it from the real change."""
    if state.st != "selection":
        return state
    files = context.get("change", {}).get("files") if isinstance(context.get("change"), dict) else None
    count = len(files) if isinstance(files, list) else 0
    change = context.get("change") if isinstance(context.get("change"), dict) else {}
    blocked = change.get("can_run") is False and bool(change.get("note"))
    return replace(state, file_count=count, focus_blocked=blocked) if (state.file_count != count or state.focus_blocked != blocked) else state


def _with_obl_count(state: ViewState, artifact) -> ViewState:
    """How many obligations the shown record has: the reducer opens the focused one on Enter and never invents the count."""
    if state.st != "verdict":
        return state
    rows = artifact.get("obligations") if isinstance(artifact, dict) else None
    count = len(rows) if isinstance(rows, list) else 0
    default = frame._initial_focus_index(artifact, 0, False) if count else 0
    return replace(state, obl_count=count, obl_default=default) if (state.obl_count != count or state.obl_default != default) else state


def _claim_exclusion(state: ViewState, context: dict) -> tuple[list[str], int]:
    """(paths the operator excluded from the SELECTED source's claim, total files of that source): indices follow the change's own file list."""
    files = context.get("change", {}).get("files") if isinstance(context.get("change"), dict) else None
    files = files if isinstance(files, list) else []
    source = state.selectedIndex if state.selectedIndex is not None else state.focusIndex
    paths = [str(files[i][0]) for (si, i) in state.excluded_files if si == source and 0 <= i < len(files)]
    return sorted(set(paths)), len(files)


def _claim_context(context: dict) -> dict:
    """Prepare a mechanically derived launcher plan for display; this never starts the engine."""
    selected = context.get("selected_change")
    if selected is None or context.get("can_run") is not True:
        return {**context, "plan": None, "command": None, "can_run": False}
    from . import claim, launch

    repo = Path(context.get("repo", {}).get("path") or ".")
    readiness, target_python = _readiness(repo, context.get("target_python"))
    context = {**context, "readiness": readiness, "target_python": target_python}
    label = str(context.get("change", {}).get("label", selected.label))
    try:
        if selected.kind == "patchfile":
            if context.get("claim_excluded"):
                raise ValueError("a patch file is claimed whole: exclude the whole source instead of single files")
            patch = Path(selected.source)
            manifest = Path(selected._manifest_path) if selected._manifest_path else None
            patch_bytes = selected.diff()
            manifest_bytes = selected._manifest_raw
            if manifest is None or manifest_bytes is None:
                raise ValueError("the selected patch has no paired manifest")
            if _read_regular_bytes(patch, 8 * 1024 * 1024) != patch_bytes:
                raise ValueError("patch file changed since it was shown: reload")
            if _read_regular_bytes(manifest, 1024 * 1024) != manifest_bytes:
                raise ValueError("manifest changed since the patch was shown: reload")
            manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
            patch_hash = hashlib.sha256(patch_bytes).hexdigest()
            manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            plan = launch.plan(repo, patch_bytes=patch_bytes, manifest_obj=manifest_obj, manifest_bytes=manifest_bytes,
                               base_rev=selected.base_rev, target_python=target_python, label=label,
                               bind_hashes=(patch_hash, manifest_hash))
        else:
            excluded = list(context.get("claim_excluded") or [])
            if excluded:
                all_paths = [str(p[0]) for p in selected.files]
                included = [p for p in all_paths if p not in set(excluded)]
                if not included:
                    raise ValueError("every file of this change is excluded: nothing would be checked")
                patch_bytes = selected.diff(included)
                from .changes import _split_files_checked

                parts, malformed = _split_files_checked(patch_bytes)
                if malformed or sorted(p for p, _b in parts) != sorted(included):
                    raise ValueError("the patch of the included files could not be built faithfully" + (f" ({malformed})" if malformed else "") + "; nothing was started")
            else:
                patch_bytes = selected.diff()
            if not patch_bytes:
                raise ValueError("the selected change has no patch to check")
            manifest_obj = {"paths": claim.derive(patch_bytes)}
            plan = launch.plan(repo, patch_bytes=patch_bytes, manifest_obj=manifest_obj,
                               base_rev=selected.base_rev, target_python=target_python, label=label)
    except (OSError, RuntimeError, ValueError) as exc:
        change = {**context.get("change", {}), "note": str(exc), "can_run": False}
        return {**context, "change": change, "plan": None, "command": None, "can_run": False}
    change = context.get("change", {})
    patch_digest = hashlib.sha256(selected.diff()).hexdigest() if selected.kind == "patchfile" else None
    manifest_digest = hashlib.sha256(selected._manifest_raw).hexdigest() if selected.kind == "patchfile" and selected._manifest_raw else None
    identity = (str(repo.resolve()), selected.kind, getattr(selected, "source", None), selected.label, selected.base_rev,
                change.get("label"), change.get("base_rev"), patch_digest, manifest_digest)
    stamp = time.strftime("%H:%M:%S", time.localtime())
    command = plan.display()
    has_control = any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f for char in command)
    if has_control:
        change = {**change, "note": "Control characters in this command prevent a faithful on-screen review; this launch is disabled."}
    return {**context, "change": change, "plan": plan, "command": command,
            "command_visible": False, "command_control_chars": has_control, "can_run": not has_control,
            "claim_command_seen": False, "claim_dwell_satisfied": False,
            "claim_identity": identity, "snapshot_taken_at": stamp}


def _recorded_thread_ids(run_dir, meta: dict) -> set[str]:
    """The agent thread id(s) the LAUNCH itself recorded: meta.json, the engine-minted link (engine-run.json) and the engine run's receipt. Bounded, regular files only."""
    from .. import store

    ids: set[str] = set()
    t = meta.get("thread_id")
    if isinstance(t, str) and t:
        ids.add(t)

    def read(path: Path) -> dict:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024:
                    return {}
                data = json.loads(os.read(fd, 64 * 1024 + 1).decode("utf-8"))
            finally:
                os.close(fd)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, UnicodeDecodeError):
            return {}

    launch_dir = Path(run_dir)
    for record in (read(launch_dir / store.LINK),):
        v = record.get("thread_id")
        if isinstance(v, str) and v:
            ids.add(v)
    engine_dir = store.engine_run_dir(launch_dir)
    if engine_dir is not None:
        v = read(engine_dir / "receipt.json").get("thread_id")
        if isinstance(v, str) and v:
            ids.add(v)
    return ids


def _resume_claim_context(context: dict, run_dir, *, target_python: str | None = None, state=None) -> dict | None:
    """TUI behavior: the Claim of RESUMING a parked effect interrupt (the shipped host had dropped this capability). READ-ONLY planning: the offer comes from the host's
    authenticated ``captured_interrupts`` (owner-only thread store outside the target, authenticated stage delta); the plan is ``launch.plan_agent_resume`` (the proposer is not called
    again); nothing here approves or starts anything: the same command review, dwell and fresh Enter as every run apply. None (nothing runnable) on any failure."""
    from . import launch

    try:
        snapshot = launch.status(Path(run_dir))
        meta = snapshot.get("meta") if isinstance(snapshot, dict) else None
        if not isinstance(meta, dict):
            return None
        # review FINDING-review-RESUME-2: a run that already landed or reached a decision is never resumable (rc 0, a landed state, or any usable decision record)
        if snapshot.get("rc") == 0 or str(meta.get("state") or "").lower() in {"landed", "finished-landed"}:
            return None
        record = launch.result(Path(run_dir))
        if record is not None and getattr(record, "usable", False):
            return None
        out_json = Path(run_dir) / "out.json"
        if out_json.exists() or out_json.is_symlink():  # ANY artifact file here (valid or not) means a decision may exist: fail closed, never offer a resume over it
            return None
        offers = launch.captured_interrupts({"meta": meta})
        if len(offers) != 1:  # none, or AMBIGUOUS: the record does not say which of several parked effects is this run's, so nothing is runnable (never 'the first one')
            return None
        # review FINDING-review-RESUME-3: the offered interrupt must be THIS launch's own thread: the launch record (meta / engine link / receipt) must name exactly that thread id.
        # A record that names no thread, several, or another one cannot be matched, and a guess ('the only parked effect in a shared store') is never offered.
        recorded = _recorded_thread_ids(run_dir, meta)
        own_store = Path(offers[0]["thread_store"]).resolve() == (Path(run_dir).resolve() / "thread-store")  # the TUI's own agent launch keeps its thread store INSIDE its launch directory
        if recorded:
            if recorded != {str(offers[0].get("thread_id"))}:
                return None
        elif not own_store:  # nothing recorded and a store the launch does not exclusively own: 'the only parked effect' would be a guess
            return None
        source_repo = Path(str(meta.get("source_repo") or "")).expanduser()
        if not source_repo.is_dir():
            return None
        # review FINDING-review-RESUME-1: the claim belongs to the OPEN repository; a record naming another source repo (or an open repo that is unknown) shows nothing runnable
        open_repo = (context.get("repo") or {}).get("path") if isinstance(context.get("repo"), dict) else None
        if not open_repo or str(open_repo) == "not recorded" or Path(str(open_repo)).expanduser().resolve() != source_repo.resolve():
            return None
        plan = launch.plan_agent_resume(source_repo, offers[0], target_python=target_python, state=state)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return None
    command = plan.display()
    has_control = any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f for char in command)
    change = {"label": plan.label, "kind": "resume", "diff": "", "files": 0,
              "note": "Resuming a parked effect: the proposer is NOT called again. The engine re-reads the stored effect, verifies it and the gate decides." +
                      (" Control characters in this command prevent a faithful on-screen review; this launch is disabled." if has_control else "")}
    return {**context, "change": change, "plan": plan, "command": command, "command_visible": False, "command_control_chars": has_control,
            "can_run": not has_control, "claim_command_seen": False, "claim_dwell_satisfied": False, "claim_identity": None, "claim_resume": True,
            "resume_offers": len(offers), "snapshot_taken_at": time.strftime("%H:%M:%S", time.localtime())}


def _read_regular(path: Path, limit: int) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def _approval_claim_context(context: dict, artifact: dict, *, target_python: str | None = None, state=None) -> dict | None:
    """TUI behavior 2.1 (D2): the Claim of a NEW check of the SAME patch with the engine's declared delta set approved. READ-ONLY planning. Fails closed (None) unless: the
    verdict itself carries an approvable delta set (frame._approval_candidate: the engine's own hash, never typed); the launch folder's change.patch is byte-identical to the
    patch the verdict recorded (effect.patch_sha256); the run's source repository is the OPEN repository; the base commit is recorded. The approval hash goes on the argv
    exactly as the artifact recorded it; the engine re-computes the delta set at the last moment before landing and refuses a mismatch. Nothing starts here: the same command
    review, dwell and fresh Enter as every run apply."""
    from . import launch

    candidate = frame._approval_candidate(artifact)
    meta = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else None
    if candidate is None or meta is None or not meta.get("clone"):
        return None
    sha, deltas = candidate
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    base = run.get("base_commit_sha")
    folder = Path(str(meta["clone"])).parent
    patch_bytes = _read_regular(folder / "change.patch", 8 * 1024 * 1024)
    manifest_bytes = _read_regular(folder / "claim.manifest.json", 1024 * 1024)
    if patch_bytes is None or manifest_bytes is None or not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base):
        return None
    patch_hash, manifest_hash = hashlib.sha256(patch_bytes).hexdigest(), hashlib.sha256(manifest_bytes).hexdigest()
    if effect.get("patch_sha256") != patch_hash:  # the approval is for THE patch this verdict was about, byte for byte
        return None
    source_repo = Path(str(meta.get("source_repo") or "")).expanduser()
    open_repo = (context.get("repo") or {}).get("path") if isinstance(context.get("repo"), dict) else None
    if not source_repo.is_dir() or not open_repo or str(open_repo) == "not recorded" or Path(str(open_repo)).expanduser().resolve() != source_repo.resolve():
        return None
    try:
        suffix = ["--approve-deltas", sha, "--patch-sha256", patch_hash, "--manifest-sha256", manifest_hash]
        plan = launch.plan(source_repo, patch_bytes=patch_bytes, manifest_obj=json.loads(manifest_bytes.decode("utf-8")), manifest_bytes=manifest_bytes, base_rev=base,
                           label="approve declared deltas · " + str(run.get("run_id") or "run"), approve_deltas=sha, verified_suffix=suffix,
                           bind_hashes=(patch_hash, manifest_hash), target_python=target_python, state=state)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return None
    command = plan.display()
    has_control = any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f for char in command)
    listing = " | ".join(frame._delta_lines(deltas, 4))
    plus = sum(1 for ln in patch_bytes.decode("utf-8", "replace").splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    minus = sum(1 for ln in patch_bytes.decode("utf-8", "replace").splitlines() if ln.startswith("-") and not ln.startswith("---"))
    change = {"label": plan.label, "kind": "approval", "diff": "", "files": 0, "added": plus, "removed": minus, "bytes": len(patch_bytes),
              "note": (f"You are approving {len(deltas)} declared behaviour delta{'s' if len(deltas) != 1 else ''}, set hash {sha}. Declared: {listing}. "
                       "Approval authorizes the change; it is not proof: every obligation is checked again and the engine re-computes this set before it lands anything." +
                       (" Control characters in this command prevent a faithful on-screen review; this launch is disabled." if has_control else ""))}
    prior = {k: context.get(k) for k in ("change", "plan", "command", "command_visible", "command_control_chars", "can_run", "claim_command_seen", "claim_dwell_satisfied",
                                           "claim_identity", "claim_resume", "claim_token", "snapshot_taken_at")}
    return {**context, "change": change, "plan": plan, "command": command, "command_visible": False, "command_control_chars": has_control,
            "can_run": not has_control, "claim_command_seen": False, "claim_dwell_satisfied": False, "claim_identity": None, "claim_resume": False,
            "claim_approval": {"sha": sha, "patch": patch_hash, "base": base, "prior": prior, "count": len(deltas), "lines": frame._delta_lines(deltas, 6)}, "snapshot_taken_at": time.strftime("%H:%M:%S", time.localtime())}


_REVIEW_KEYS = {"target repository": "repo", "base commit": "base", "patch sha256": "patch", "rehearsal": "rehearsal", "files": "files", "apply token": "token",
                "manifest sha256": "manifest", "approved delta set": "deltas", "caller policy": "policy", "target Python": "python"}


def _apply_claim_context(context: dict, artifact: dict, *, target_python: str | None = None, state=None) -> tuple[dict | None, str]:
    """TUI behavior 2.3 (D1): the Claim of APPLYING a LANDED rehearsal to the ORIGINAL repository. It runs the engine's own READ-ONLY review (engine_cli apply without --confirm: it
    writes nothing, exit 2) and shows it IN FULL; the plan carries --confirm <the engine's token>, which binds patch, base commit, rehearsed post tree and target. Fails closed
    (None + the named reason) on anything that does not hold. Nothing here applies anything: the command review, dwell and an explicit y (Enter does not) follow."""
    from . import launch

    if not frame._apply_candidate(artifact, context):
        return None, "Apply is offered only on a LANDED rehearsal opened from the session that made it"
    meta = context["launch_meta"]
    folder = Path(str(meta["clone"])).parent
    source_repo = Path(str(meta.get("source_repo") or "")).expanduser()
    open_repo = (context.get("repo") or {}).get("path") if isinstance(context.get("repo"), dict) else None
    if not source_repo.is_dir() or not open_repo or str(open_repo) == "not recorded" or Path(str(open_repo)).expanduser().resolve() != source_repo.resolve():
        return None, "the rehearsal's repository is not the open repository"
    patch_bytes = _read_regular(folder / "change.patch", 8 * 1024 * 1024)
    manifest_bytes = _read_regular(folder / "claim.manifest.json", 1024 * 1024)
    if patch_bytes is None or manifest_bytes is None or _read_regular(folder / "out.json", 16 * 1024 * 1024) is None:
        return None, "the rehearsal's patch, manifest or artifact is missing from its run folder"
    try:
        done = subprocess.run(launch.apply_argv(source_repo, folder, target_python=target_python), capture_output=True, text=True, timeout=60, cwd=str(folder))
    except (OSError, subprocess.TimeoutExpired):
        return None, "the apply review could not run"
    if done.returncode != 2:  # 2 = review printed, nothing written; 4 = a named refusal (not a landed rehearsal / patch differs / HEAD moved / tracked changes)
        refusal = next((ln for ln in reversed(done.stderr.splitlines()) if ln.startswith("hlith:")), "")
        text = frame._clean(refusal or f"the apply review ended with exit {done.returncode}")
        for needle, advice in (("uncommitted changes to tracked files", "Apply needs a clean working tree: commit or stash your tracked changes, then press l again."),
                               ("HEAD moved", "Your branch moved since the rehearsal: check the change again on the current HEAD."),
                               ("not the rehearsed base", "Your branch is not at the rehearsed base: check the change again on the current HEAD."),
                               ("patch differs", "The patch is not the rehearsal's own: check the change again.")):
            if needle in text:
                return None, advice
        return None, text[:200]
    review = {}
    for line in done.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in _REVIEW_KEYS:
            review[_REVIEW_KEYS[key.strip()]] = value.strip()
    if review.get("base"):
        review["base"] = review["base"].split()[0]
    if (not re.fullmatch(r"[0-9a-f]{16}", review.get("token", "")) or not re.fullmatch(r"[0-9a-f]{64}", review.get("patch", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", review.get("base", ""))
            or review["patch"] != hashlib.sha256(patch_bytes).hexdigest()):
        return None, "the apply review could not be read, or its patch is not the rehearsal's own"
    reviewed_manifest = review.get("manifest", "")
    if re.fullmatch(r"[0-9a-f]{64}", reviewed_manifest) and reviewed_manifest != hashlib.sha256(manifest_bytes).hexdigest():  # the engine bound a manifest: it must be the one this run used
        return None, "the apply review's manifest is not the rehearsal's own"
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    try:
        plan = launch.plan_apply(source_repo, folder, review["token"], label="apply to your repository \u00b7 " + str(run.get("run_id") or "run"), target_python=target_python, state=state)
    except (OSError, RuntimeError, ValueError):
        return None, "the apply could not be planned"
    command = plan.display()
    has_control = any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f for char in command)
    plus = sum(1 for ln in patch_bytes.decode("utf-8", "replace").splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    minus = sum(1 for ln in patch_bytes.decode("utf-8", "replace").splitlines() if ln.startswith("-") and not ln.startswith("---"))
    change = {"label": plan.label, "kind": "apply", "diff": "", "files": 0, "added": plus, "removed": minus, "bytes": len(patch_bytes),
              "note": "Applying a LANDED rehearsal to your repository through the trusted gate." + (" Control characters in this command prevent a faithful on-screen review; this launch is disabled." if has_control else "")}
    prior = {k: context.get(k) for k in ("change", "plan", "command", "command_visible", "command_control_chars", "can_run", "claim_command_seen", "claim_dwell_satisfied",
                                           "claim_identity", "claim_resume", "claim_token", "snapshot_taken_at")}
    return {**context, "change": change, "plan": plan, "command": command, "command_visible": False, "command_control_chars": has_control,
            "can_run": not has_control, "claim_command_seen": False, "claim_dwell_satisfied": False, "claim_identity": None, "claim_resume": False,
            "claim_apply": {"token": review["token"], "patch": review["patch"], "base": review["base"], "repo": str(source_repo.resolve()), "review": review, "prior": prior},
            "snapshot_taken_at": time.strftime("%H:%M:%S", time.localtime())}, ""


def _claim_token(context: dict) -> tuple[str, str, str] | None:
    plan = context.get("plan")
    if context.get("claim_resume") is True and plan is not None and plan.resume_thread_id and plan.checkpoint_id:
        return ("resume", str(plan.resume_thread_id), str(plan.checkpoint_id))  # a resume claim is bound to its authenticated thread and checkpoint, not to a selected change
    applying = context.get("claim_apply")
    if isinstance(applying, dict) and plan is not None:
        return ("apply", str(applying.get("token")), str(applying.get("patch")), str(applying.get("base")))
    approval = context.get("claim_approval")
    if isinstance(approval, dict) and plan is not None:
        return ("approve", str(approval.get("sha")), str(approval.get("patch")), str(plan.base_rev))  # bound to the approved set, the patch and the base: not to a selected change
    selected = context.get("selected_change")
    if plan is None or selected is None or not plan.base_rev:
        return None
    label = str(context.get("change", {}).get("label", ""))
    if label != plan.label:
        return None
    return str(plan.base_rev), str(selected.kind), label


def _start_confirmed(context: dict, *, state: ViewState, events, claim_shown: bool,
                     claim_painted_at: float | None = None, read_started_at: float | None = None,
                     previous_enter_at: float | None = None, now: float | None = None) -> dict | None:
    """Start only from one fresh Enter on the already-rendered Claim primary action."""
    now = time.monotonic() if now is None else now
    implicit_test_seam = claim_painted_at is None and read_started_at is None
    if implicit_test_seam:
        claim_painted_at, read_started_at = now - 0.5, now
        context = {**context, "claim_command_seen": True, "claim_dwell_satisfied": True,
                   "claim_token": _claim_token(context)}
    if (not claim_shown or len(events) != 1 or state.st != "claim" or state.overlay or state.drill
            or state.focusIndex != 0 or context.get("can_run") is not True or context.get("plan") is None
            or context.get("command_visible") is False or context.get("claim_command_seen") is not True
            or context.get("claim_dwell_satisfied") is not True):
        return None
    event = events[0]
    if keys.action_for(state, event) != ("key:y" if isinstance(context.get("claim_apply"), dict) else "key:enter"):  # an APPLY needs an explicit y: Enter never writes the operator's repository
        return None
    # Preserve the direct helper's historical test seam. The terminal host always supplies
    # both timestamps from the actual paint and input read, so live authorization stays strict.
    if (claim_painted_at is None or read_started_at is None or read_started_at < claim_painted_at
            or now - claim_painted_at < 0.5
            or (previous_enter_at is not None and read_started_at - previous_enter_at < 0.12)):
        return None
    plan = context["plan"]
    if context.get("claim_token") != _claim_token(context):
        return None
    applying = context.get("claim_apply")
    if isinstance(applying, dict):
        argv = plan.argv
        if (argv.count("apply") != 1 or argv.count("--confirm") != 1 or argv[argv.index("--confirm") + 1] != applying.get("token")
                or argv.count("--repo") != 1 or argv[argv.index("--repo") + 1] != applying.get("repo")
                or str(Path(plan.source_repo).resolve()) != applying.get("repo")):
            return None
    approval = context.get("claim_approval")
    if isinstance(approval, dict):
        argv = plan.argv
        if (argv.count("--approve-deltas") != 1 or argv[argv.index("--approve-deltas") + 1] != approval.get("sha")
                or argv.count("--patch-sha256") != 1 or argv[argv.index("--patch-sha256") + 1] != approval.get("patch")
                or plan.base_rev != approval.get("base") or hashlib.sha256(plan.patch_bytes or b"").hexdigest() != approval.get("patch")):
            return None
    identity = context.get("claim_identity")
    if identity is not None:
        repo_path, kind, source, source_label, base_rev, shown_label, shown_base, patch_digest, manifest_digest = identity
        if (str(Path(plan.source_repo).resolve()) != repo_path or plan.label != shown_label
                or plan.base_rev != base_rev or source_label != shown_label or shown_base != base_rev):
            return None
        if kind == "patchfile":
            if (not source or plan.patch_bytes is None or hashlib.sha256(plan.patch_bytes).hexdigest() != patch_digest
                    or plan.manifest_bytes is None or hashlib.sha256(plan.manifest_bytes).hexdigest() != manifest_digest
                    or "--patch-sha256" not in plan.argv or patch_digest not in plan.argv
                    or "--manifest-sha256" not in plan.argv or manifest_digest not in plan.argv):
                return None
    from . import launch

    return launch.start(plan)


def _command_visible(rendered, command: str | None = None) -> bool:
    """Use renderer-owned row visibility, never repository-controlled frame text."""
    return bool(getattr(rendered, "_visibility", {}).get("claim_command_visible"))


def _command_end_visible(rendered) -> bool:
    """The private marker-row flag cannot be forged by an argv label or file path."""
    return bool(getattr(rendered, "_visibility", {}).get("claim_command_end_visible"))


def _preview_artifact(artifact: dict, context: dict, has_record: bool) -> dict:
    if has_record:
        return artifact
    change = context.get("change") if isinstance(context.get("change"), dict) else {}
    return {**artifact, "effect": {"unified_diff": change.get("diff", ""),
                                    "touched_files": [change.get("file")] if change.get("file") else []}}


def _artifact(path: str | None) -> tuple[dict, Record | None, ViewState]:
    if path is None:
        return dict(_EMPTY), None, ViewState(st="offer")
    record = load(Path(path))
    if record.art is not None:
        return record.art, record, ViewState(st="verdict")
    return dict(_EMPTY), record, ViewState(st="blocked")


def _repository_path_sentence(repo: Path) -> str | None:
    """A plain sentence when the repository PATH itself is unusable (missing, a file, unreadable); None when it is a readable directory."""
    try:
        shown = str(repo)
        if not repo.exists():
            return f"hlith ui: {shown} does not exist."
        if not repo.is_dir():
            return f"hlith ui: {shown} is a file, not a directory."
        if not os.access(repo, os.R_OK | os.X_OK):
            return f"hlith ui: {shown} cannot be read (permission denied)."
    except OSError as exc:
        return f"hlith ui: {repo} cannot be read ({exc.strerror or type(exc).__name__})."
    return None


_CHECK_SPEC = re.compile(r"(uncommitted|commit|branch|patch)(?::(.+))?", re.S)


def parse_check_source(value: str) -> tuple[str, str | None]:
    """`--check` source: `uncommitted` | `commit:REV` | `branch:NAME` | `patch:PATH`. Raises ValueError (named) otherwise. A commit or branch beginning with '-' is refused here so it can
    never reach git as an option."""
    m = _CHECK_SPEC.fullmatch(value or "")
    if m is None or (m.group(1) == "uncommitted") != (m.group(2) is None):
        raise ValueError("expected uncommitted, commit:REV, branch:NAME or patch:PATH")
    kind, arg = m.group(1), m.group(2)
    if kind in {"commit", "branch"} and arg.startswith("-"):
        raise ValueError("a commit or branch name beginning with '-' is not accepted")
    return kind, arg


def match_check_source(sources: list, spec: tuple[str, str | None], repo) -> tuple[int | None, str]:
    """(index into the OFFERED sources, '') or (None, why). It only selects among the changes the Offer already lists, so every gate of the normal flow (runnable, has a base,
    files included, command review, dwell, fresh Enter) applies unchanged. Nothing is created or invented for a source that is not offered."""
    kind, arg = spec
    wanted = {"uncommitted": "uncommitted", "commit": "commit", "branch": "branch", "patch": "patchfile"}[kind]
    candidates = [(i, src) for i, src in enumerate(sources) if src.get("kind") == wanted]
    if kind == "uncommitted":
        return (candidates[0][0], "") if candidates else (None, "no uncommitted work to check")
    if kind == "commit":
        try:
            full = gitq.optional_text(repo, "rev-parse", "--verify", "-q", f"{arg}^{{commit}}") or ""
        except gitq.GitReadError as exc:
            return None, str(exc)
        if not full:
            return None, f"{arg} is not a commit here"
        for i, src in candidates:
            if full.startswith(str(src.get("label", "")).split(" ", 1)[0]) and src.get("label"):
                return i, ""
        return None, f"commit {full[:8]} is not among the newest offered"
    if kind == "branch":
        for i, src in candidates:
            if str(src.get("label", "")).startswith(f"branch {arg} vs "):
                return i, ""
        return None, f"branch {arg} is not offered"
    target = str(Path(arg).expanduser().resolve())
    for i, src in candidates:
        change = src.get("_change")
        if change is not None and str(getattr(change, "source", "")) == target:
            return i, ""
    return None, f"{arg} is not an offered patch (needs a paired manifest)"


def _with_offer_lead(context: dict) -> dict:
    """The Offer's lead (a check still running here, or a decision that finished unseen): from the scanned history rows of THIS repository and the seen-store. None when neither."""
    repo = (context.get("repo") or {}).get("path") if isinstance(context.get("repo"), dict) else None
    lead = offer_lead.pick(context.get("history_rows") or [], repo, offer_lead.load_seen(history.state_dir())) if repo else None
    rows = context.get("history_rows") or []
    newest_dir = str(rows[0].get("run_dir")) if rows and rows[0].get("run_dir") else None
    extra = {}
    if newest_dir != context.get("last_event_tail_src"):
        from . import launch

        extra = {"last_event_tail_src": newest_dir, "last_event_tail": launch.event_tail(newest_dir) if newest_dir else []}  # the dock's idle content: the newest recorded run's own last events
    if lead == context.get("offer_lead") and not extra:
        return context
    return {**context, "offer_lead": lead, **extra}


def _find_source_by_label(sources: list, label: str) -> int | None:
    """The offered source a refused run was about, found again by its recorded label: exact first, then a branch by name (its label carries a commit count that moves)."""
    for i, src in enumerate(sources):
        if label and src.get("label") == label:
            return i
    if label.startswith("branch ") and " vs " in label:
        head = label.split(" vs ", 1)[0] + " vs "
        for i, src in enumerate(sources):
            if str(src.get("label", "")).startswith(head):
                return i
    return None


def _plain(path: str | None, repo: Path, inputs=(), target_python: str | None = None) -> int:
    if path:
        artifact, record, state = _artifact(path)
        context = _artifact_context(artifact)
        if record is not None and not record.usable:
            context["blocked"] = {"kind": "artifact", "reason": "; ".join(record.errors) or record.status}
            state = replace(state, st="blocked")
        cols, rows = 100, 30
        print(_render(replace(state, cols=cols, rows=rows), artifact, context, "plain"))
        return 0 if record is None or record.usable else 2
    artifact, record, state = _artifact(None)
    sentence = _repository_path_sentence(repo)
    if sentence is None:
        repo_context = _repo_context(repo, inputs, target_python)
        reason = str((repo_context.get("blocked") or {}).get("reason", ""))
        if "not a git repository" in reason.lower():
            sentence = f"hlith ui: {repo} is not a Git repository. Run 'hlith ui --repo PATH' inside a repository."
    if sentence is not None:
        print(sentence, file=sys.stderr)  # the old contract: one plain sentence on stderr, exit 2, nothing misleading on stdout
        return 2
    if not (repo_context.get("blocked") or {}).get("reason"):
        try:
            h_rows, h_total, h_trunc, h_scanned, h_omitted = _scan_history(repo)
            repo_info = dict(repo_context.get("repo") or {})
            repo_info["records"] = _records_summary(
                h_rows, h_total, truncated=h_trunc, scanned=h_scanned, omitted_repos=h_omitted
            )
            repo_context = {
                **repo_context,
                "repo": repo_info,
                "history_rows": h_rows,
                "history_total": h_total,
                "history_truncated": h_trunc,
                "history_scanned": h_scanned,
                "history_omitted_repos": h_omitted,
                "history_scan_complete": True,
            }
        except Exception:  # noqa: BLE001 - history scan is advisory in plain snapshot mode
            pass
    context = _selection_context(repo_context, state)
    blocked = bool(context.get("blocked", {}).get("reason"))
    if blocked:
        state = replace(state, st="blocked")  # the interactive host forces the same screen: a repository that could not be read is never shown as an Offer with zero counts
    print(_render(replace(state, cols=100, rows=30), artifact, context, "plain"))
    return 2 if blocked else 0


def _run_terminal(path: str | None, repo_root: Path, inputs=(), target_python: str | None = None, remembered: bool = False, check: tuple | None = None) -> int:
    artifact, record, state = _artifact(path)
    repo_load_needed = path is None
    context = _artifact_context(artifact) if path is not None else _repository_loading_context(repo_root)
    context["remembered_repo"] = bool(remembered)
    context["history_scan_complete"] = False
    if record is not None and record.path:
        context["artifact_path"] = record.path
    if record is not None and not record.usable:
        state = replace(state, st="artifact-unavailable")
        context["artifact_path"] = record.path
        context["artifact_unavailable_reason"] = _artifact_error_summary(record)
    from .. import identity as _identity

    context["build_identity"] = _identity.build_identity()  # computed ONCE at start (plain file reads, nothing spawned); the frame only reads it
    color = _mode()
    if color == "plain":
        print(_render(replace(state, cols=80, rows=24), artifact, context, color))
        return 0

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    raw = False
    screen_active = False
    done = False
    dirty = True
    resized = False
    cursor_needs_hide = False
    claim_shown = False
    claim_painted_at = None
    seen_marked = None  # the launch id whose Verdict was last recorded as seen (offer_lead)
    pending_new_check = None  # `n` on a refusal: after the repository is read again, reopen the Claim of the same source (one shot)
    claim_last_enter_at = None
    claim_command_rows_seen: set[int] = set()
    claim_command_row_count = None
    last_run_poll = 0.0
    records_scan_seconds = 0.0
    last_records_poll = 0.0
    record_future = None
    repo_future = None
    gitq.begin_session()
    record_executor = _DaemonExecutor()
    old_handlers = {}
    decoder = keys.Decoder()

    def enter_raw():
        nonlocal raw
        if not raw:
            tty.setraw(fd, termios.TCSANOW)
            raw = True

    def enter_screen():
        nonlocal screen_active
        if not screen_active:
            sys.stdout.write(_ALT_ENTER)
            screen_active = True
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()

    def restore():
        nonlocal raw, screen_active
        if raw:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            raw = False
        try:
            sys.stdout.write("\x1b[0m\x1b[?25h" + (_ALT_LEAVE if screen_active else ""))
            screen_active = False
            sys.stdout.flush()
        except OSError:
            pass

    def on_resize(_signum, _frame):
        nonlocal resized, dirty, context, claim_shown, claim_painted_at
        nonlocal claim_command_rows_seen, claim_command_row_count
        resized = True
        dirty = True
        if state.st == "claim":
            context = {**context, "command_visible": False, "claim_command_seen": False,
                       "claim_dwell_satisfied": False}
            claim_shown = False
            claim_painted_at = None
            claim_command_rows_seen = set()
            claim_command_row_count = None

    def on_continue(_signum, _frame):
        nonlocal dirty, cursor_needs_hide, claim_shown, claim_painted_at, claim_last_enter_at, context
        nonlocal claim_command_rows_seen, claim_command_row_count
        dirty = True
        cursor_needs_hide = True
        claim_shown = False
        claim_painted_at = None
        claim_last_enter_at = None
        claim_command_rows_seen = set()
        claim_command_row_count = None
        if state.st == "claim":
            context = {**context, "command_visible": False, "claim_command_seen": False,
                       "claim_dwell_satisfied": False}
        try:
            termios.tcflush(fd, termios.TCIFLUSH)
        except termios.error:
            pass

    def on_exit(_signum, _frame):
        nonlocal done
        done = True

    def on_suspend(signum, _frame):
        restore()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
        signal.signal(signum, on_suspend)
        enter_raw()
        on_continue(signum, None)

    last_key = None  # the most recent input event: named in the frames evidence hook (HLITH_UI_FRAMES)

    def consume(events, read_started_at=None):
        nonlocal last_key
        if events:
            last_key = events[-1]
        nonlocal state, context, dirty, done, claim_shown, artifact, record, claim_last_enter_at, claim_painted_at, repo_root, repo_load_needed, pending_new_check
        nonlocal claim_command_rows_seen, claim_command_row_count, last_run_poll
        read_started_at = time.monotonic() if read_started_at is None else read_started_at
        state = reduce.expire_on_key(state, bool(events))  # the previous toast is invalid the moment a key arrives; toasts raised by THESE keys stay
        if context.get("repository_loading"):
            if not _loading_actions_allowed(state, events):
                state = replace(state, toast="Repository is still loading")
                dirty = True
                return
        if state.st in {"offer", "claim"} and not state.overlay and (state.st == "offer" or state.focusIndex == 0) and any(keys.action_for(state, event) in ({"key:enter", "key:y"} if isinstance(context.get("claim_apply"), dict) else {"key:enter"}) for event in events):
            block = _boundary_block(context)
            if block is not None:
                # the boundary is not ready (read fresh now): nothing starts, no launch directory is created, the operator sees why
                context = {**context, **block, "blocked_return": state.st}
                state = replace(state, st="blocked", focusIndex=0, focusAction=None, overlay=None, drill=None, scroll=0)
                claim_shown = False
                claim_painted_at = None
                dirty = True
                return
        if state.st == "claim":
            meta = _start_confirmed(context, state=state, events=events, claim_shown=claim_shown,
                                    claim_painted_at=claim_painted_at, read_started_at=read_started_at,
                                    previous_enter_at=claim_last_enter_at)
            if meta is not None:
                context = {**{k: v for k, v in context.items() if k != "claim_previous"}, "launch_meta": meta, "run_id": meta.get("run_id"), "started_here": True,
                           "launch_dir": str(getattr(context.get("plan"), "run_dir", "") or ""),
                           "launch_id": meta.get("run_id"),
                           "run_id_kind": "launch",
                           "running": {"phases": [], "progress": None, "closed": None,
                                       "unavailable": "engine events are not available yet"},
                           "run_state": "running"}
                from . import launch as _launch_mod
                if meta.get("state") == _launch_mod.UNAVAILABLE_STATE:  # review-only: nothing was created or run
                    state = replace(state, st="blocked", focusIndex=0, focusAction=None,
                                    overlay=None, drill=None, scroll=0)
                    context["blocked"] = {"kind": "run", "unavailable": True, "reason": str(meta.get("reason") or _launch_mod.UNAVAILABLE_REASON), "run_dir": ""}
                elif meta.get("state") == "clone-failed":
                    state = replace(state, st="blocked", focusIndex=0, focusAction=None,
                                    overlay=None, drill=None, scroll=0)
                    context["blocked"] = {"kind": "run", "reason": "the disposable clone could not be created; see the run receipt",
                                          "run_dir": str(getattr(context.get("plan"), "run_dir", "") or "")}
                else:
                    state = replace(state, st="running", focusIndex=0, focusAction=None,
                                    overlay=None, drill=None, scroll=0, toast=None)  # a new screen opens at its top: the Claim's paging must not carry over
                claim_shown = False
                dirty = True
                return
            # gate evidence is written only by an Enter that NO overlay consumed, including an overlay that an EARLIER key of the same batch opened ('?' then Enter)
            sim, enter_for_gate = state, False
            for event in events:
                sim_action = keys.action_for(sim, event)
                if sim_action in ({"key:enter", "key:y"} if isinstance(context.get("claim_apply"), dict) else {"key:enter"}) and not sim.overlay:
                    enter_for_gate = True
                if sim_action is not None:
                    sim = reduce.reduce(sim, sim_action)
            if enter_for_gate:
                claim_last_enter_at = read_started_at
                if (isinstance(context.get("claim_apply"), dict) and context.get("claim_command_seen") is not True and not state.overlay and not state.drill
                        and any(keys.action_for(state, event) == "key:y" for event in events)):
                    # `y` does nothing until the exact command has been read to its end; saying so beats a silent key (the page says "Press y to apply")
                    state = replace(state, toast="Read the exact command first (Enter), then press y")
                    dirty = True
            if events:
                context = {**context, "claim_dwell_satisfied": False}
                claim_painted_at = None
        for event in events:
            action = keys.action_for(state, event)
            if action is None:
                continue
            if action == "key:R" and not state.overlay:
                # R: static mode on / off at run time (B): every cue and the spinner stop; text, evidence and gates are untouched
                static_now = motion.toggle_reduced()
                state = replace(state, toast="motion off · static" if static_now else "motion on")
                dirty = True
                continue
            if (state.st == "claim" and state.focusIndex == 0 and not state.overlay and not state.drill and action == "key:enter" and context.get("command")
                    and context.get("command_visible") is False):
                state = replace(state, drill="command", scroll=0)  # Enter on the unreviewed claim opens the command-review step; it never starts anything
                dirty = True
                break
            if (state.st in {"verdict", "artifact-unavailable", "run-ended-no-decision", "run-lost"} and action == "key:esc" and context.get("history_return")
                    and not state.drill and not state.overlay):  # Esc closes exactly ONE level: an open drill or overlay closes first (reduce), only then the verdict returns to history
                state = replace(state, st="history", focusIndex=context.get("history_focus_index", 0),
                                focusAction=None, drill=None, overlay=None, scroll=0)
                home_repo = context.get("home_repo")
                if isinstance(home_repo, dict):
                    context = {**context, "repo": home_repo}
                context = {**context, "history_return": False}
                dirty = True
                break
            if state.st == "blocked" and not state.overlay and context.get("blocked", {}).get("kind") == "boundary" and action in {"key:r", "key:c"}:
                if action == "key:c":
                    _copy_terminal_clipboard(_boundary_copy_text(context["blocked"]))
                    state = replace(state, toast="Command sent to terminal clipboard")
                else:
                    block = _boundary_block(context)
                    if block is not None:
                        context = {**context, **block}
                        state = replace(state, toast="Still unavailable: nothing was started")
                    else:
                        back = context.get("blocked_return") or "offer"
                        repo_ = Path(context.get("repo", {}).get("path") or ".")
                        readiness_, target_python_ = _readiness(repo_, context.get("target_python"))
                        context = {k: v for k, v in context.items() if k not in {"blocked", "blocked_return"}}
                        context = {**context, "readiness": readiness_, "target_python": target_python_}
                        if back == "claim":
                            context = _claim_context(context)
                            claim_shown = False
                            claim_painted_at = None
                        state = replace(state, st=back, focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0,
                                        toast="Boundary ready")
                dirty = True
                break
            if state.st == "blocked" and not state.overlay and context.get("blocked", {}).get("kind") == "run" and action == "key:esc":
                # the host re-forces st='blocked' while context['blocked'] carries a reason, so Esc must drop the cause it leaves behind; the run itself stays recorded
                context = {k: v for k, v in context.items() if k not in {"blocked", "launch_meta", "run_state", "running"}}
                state = replace(state, st="offer", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0)
                claim_shown = False
                claim_painted_at = None
                dirty = True
                break
            if (state.st == "blocked" and not state.overlay and context.get("blocked", {}).get("kind") == "run" and action == "key:c"
                    and not context["blocked"].get("unavailable")):  # Hlith Review refusal: nothing was created, so there is no folder to copy
                folder = str(context["blocked"].get("run_dir") or "")
                if folder:
                    _copy_terminal_clipboard(folder)
                    state = replace(state, toast="Launch folder path sent to terminal clipboard")
                else:
                    state = replace(state, toast="The launch folder is not recorded for this run")
                dirty = True
                break
            if state.st == "artifact-unavailable" and not state.overlay and action == "key:r":
                artifact_path = context.get("artifact_path") or path
                if context.get("history_return") and context.get("external_run_dir") is not None:
                    from . import launch

                    record = launch.result(context["external_run_dir"])
                    artifact = record.art if record is not None and record.art is not None else dict(_EMPTY)
                elif artifact_path is not None:
                    artifact, record, _initial = _artifact(str(artifact_path))
                else:
                    record = None
                    artifact = dict(_EMPTY)
                if record is not None and record.usable:
                    artifact_repo = _artifact_context(artifact)["repo"]
                    if artifact_repo.get("name") == "repository not recorded" and context.get("history_repo_name"):
                        artifact_repo = {**artifact_repo, "name": str(context["history_repo_name"]),
                                         "identity_source": "launch record"}
                    context = {**context, "repo": artifact_repo,
                               "artifact_path": record.path, "artifact_unavailable_reason": None}
                    state = replace(state, st="verdict", verdict=None, focusIndex=0,
                                    focusAction=None, drill=None, overlay=None, scroll=0)
                else:
                    reason = _artifact_error_summary(record)
                    if record is None and artifact_path is not None and _artifact_path_missing(artifact_path):
                        reason = "no such file"
                    context = {**context, "artifact_path": record.path if record else artifact_path,
                               "artifact_unavailable_reason": reason}
                dirty = True
                break
            if state.st == "verdict" and not state.overlay and action == "key:c":
                # operator spec 4.4: hand the refusal (witness / stop reason) to the agent that produced the change. Read-only: the note is composed from the recorded
                # artifact alone (agent_note), sent to the terminal clipboard like every other copy here, and changes no state, decision or file.
                note = agent_note.build(artifact, context)
                if note is None:
                    state = replace(state, toast="Nothing to copy: this result has no refusal to hand to an agent")
                else:
                    _copy_terminal_clipboard(note)
                    state = replace(state, toast={"refuted": "Witness sent to terminal clipboard · paste it to your agent",
                                                  "not-derived": "Stop reason sent to terminal clipboard · paste it to your agent"}.get(
                                                      agent_note.kind(artifact), "Result sent to terminal clipboard · paste it to your agent"))
                dirty = True
                break
            if state.st == "claim" and state.drill == "command" and not state.overlay and action == "key:c":
                plan_ = context.get("plan")
                if plan_ is not None and getattr(plan_, "argv", None):
                    _copy_terminal_clipboard(plan_.display())  # the exact single-line argv: byte-for-byte what the plan runs
                    state = replace(state, toast="exact command copied (one line)")
                    dirty = True
                break
            if state.st == "offer" and not state.overlay and action == "key:r" and not context.get("repository_loading") and context.get("sources") is not None:
                # an explicit RESCAN: the working tree is read when hlith opens, never on its own; r reads it again (a fresh snapshot time). Nothing starts and nothing is written.
                keep = {k: context[k] for k in ("history_rows", "history_total", "history_truncated", "history_scanned", "history_omitted_repos", "history_scan_complete",
                                                "remembered_repo", "target_python") if k in context}
                root_ = Path(str((context.get("repo") or {}).get("path") or repo_root))
                repo_root = root_
                context = {**keep, **_repository_loading_context(root_)}
                repo_load_needed = True
                claim_shown = False
                claim_painted_at = None
                state = replace(state, st="offer", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0, toast="reading the repository again…")
                dirty = True
                break
            if state.st == "verdict" and not state.overlay and action == "key:n":
                # operator spec 4.4: a refusal is final; `n` is a NEW check of the CURRENT state of the same change. It re-reads the repository, reselects the source this run was about and
                # opens its Claim (command review, pause and a fresh Enter all still apply). Nothing starts here and the refused record is untouched.
                why = frame._new_check_refusal(artifact, context)
                if why is not None:
                    state = replace(state, toast=why)
                else:
                    meta = context["launch_meta"]
                    decision = frame._decision(artifact)
                    patch_sha = None
                    try:
                        patch_sha = hashlib.sha256(_read_regular_bytes(Path(str(meta.get("patch") or "")), 4 * 1024 * 1024)).hexdigest()
                    except (OSError, RuntimeError, ValueError):
                        pass  # not compared: the Claim says so
                    pending_new_check = {"label": str(meta.get("label") or ""),
                                         "prior": {"run_id": frame._run_id(artifact), "word": decision[0].split("· ")[-1].lower() if decision[0].startswith("REFUSED") else decision[0],
                                                   "patch_sha": patch_sha}}
                    repo_root = Path(str(meta["source_repo"]))
                    keep = {k: context[k] for k in ("history_rows", "history_total", "history_truncated", "history_scanned", "history_omitted_repos", "history_scan_complete",
                                                    "remembered_repo", "target_python") if k in context}
                    context = {**keep, **_repository_loading_context(repo_root)}
                    repo_load_needed = True
                    claim_shown = False
                    claim_painted_at = None
                    state = replace(state, st="offer", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0, toast="reading the change again…")
                dirty = True
                break
            if state.st == "verdict" and not state.overlay and not state.drill and action in {"key:l", "key:a"} and frame._apply_candidate(artifact, context):
                applying, why = _apply_claim_context(context, artifact, target_python=context.get("target_python"))
                if applying is None:  # re-authenticated at the key by the engine's own read-only review: its refusal is shown as named
                    state = replace(state, toast="Apply is not available: " + why)
                else:
                    context = applying
                    state = replace(state, st="claim", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0)
                    claim_shown = False
                    claim_painted_at = None
                dirty = True
                break
            if state.st == "verdict" and not state.overlay and not state.drill and action == "key:i" and frame._approval_candidate(artifact):
                approving = _approval_claim_context(context, artifact, target_python=context.get("target_python"))
                if approving is None:  # re-authenticated at the moment of the key: the patch, base and repository must still be the verdict's own
                    state = replace(state, toast="Approval is not available: this run's own patch, base or repository could not be re-authenticated")
                else:
                    context = approving
                    state = replace(state, st="claim", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0)
                    claim_shown = False
                    claim_painted_at = None
                dirty = True
                break
            if state.st in {"run-ended-no-decision", "run-lost"} and not state.overlay and action == "key:enter":
                cancelled_ = bool((context.get("run_failure") or {}).get("cancelled"))
                action = (("key:n" if state.focusIndex == 0 else "key:esc") if cancelled_ else ("key:esc" if state.focusIndex == 0 else "key:c"))  # the focused button's own action: Enter was inert here
            if state.st == "run-ended-no-decision" and not state.overlay and action == "key:n" and (context.get("run_failure") or {}).get("cancelled"):
                meta_c = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
                if not meta_c.get("source_repo"):
                    state = replace(state, toast="no source repository was recorded for this run")
                else:
                    # a NEW check of the same change after a cancellation: re-read the repository, reselect this run's source, open its Claim (command review, pause and a fresh Enter all still apply)
                    pending_new_check = {"label": str(meta_c.get("label") or ""), "prior": {"run_id": str(context.get("run_id") or "this run"), "word": "cancelled", "patch_sha": None}}
                    repo_root = Path(str(meta_c["source_repo"]))
                    keep = {k: context[k] for k in ("history_rows", "history_total", "history_truncated", "history_scanned", "history_omitted_repos", "history_scan_complete",
                                                    "remembered_repo", "target_python") if k in context}
                    context = {**keep, **_repository_loading_context(repo_root)}
                    repo_load_needed = True
                    claim_shown = False
                    claim_painted_at = None
                    state = replace(state, st="offer", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0, toast="reading the change again…")
                dirty = True
                break
            if state.st in {"run-ended-no-decision", "run-lost"} and not state.overlay and action == "key:r" and context.get("resume_offer"):
                run_failure = context.get("run_failure", {})
                resumed = _resume_claim_context(context, Path(str(run_failure.get("run_dir") or "")), target_python=context.get("target_python"))
                if resumed is None:  # re-authenticated at the moment of the key: anything that no longer holds shows nothing runnable
                    context = {**context, "resume_offer": False}
                    state = replace(state, toast="Resume is not available: the interrupted effect could not be authenticated")
                else:
                    context = resumed
                    state = replace(state, st="claim", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0)
                    claim_shown = False
                    claim_painted_at = None
                dirty = True
                break
            if state.st in {"run-ended-no-decision", "run-lost"} and not state.overlay and action == "key:c":
                run_failure = context.get("run_failure", {})
                folder = run_failure.get("run_dir")
                if isinstance(folder, (str, Path)) and str(folder):
                    _copy_terminal_clipboard(str(folder))
                    state = replace(state, toast="Launch folder path sent to terminal clipboard")
                    dirty = True
                break
            lead_open = False
            if (state.st == "offer" and action == "key:enter" and not state.overlay and not context.get("repository_loading")
                    and isinstance(context.get("offer_lead"), dict) and state.focusIndex == 0):
                # the Offer's lead is focused: open that run exactly as History does (a running check is reattached, a finished one shows its Verdict); Esc returns to the Offer
                lead_rows = context.get("history_rows") or []
                lead_at = next((i for i, r in enumerate(lead_rows) if str(r.get("run_id")) == str(context["offer_lead"].get("run_id"))), None)
                if lead_at is None:
                    state = replace(state, toast="That run is not in the scanned history yet")
                    dirty = True
                    break
                state = replace(state, st="history", focusIndex=lead_at, focusAction=None, scroll=0)
                lead_open = True
            if state.st == "history" and action == "key:enter" and not state.overlay:  # an open overlay (the quit dialog) takes Enter first: the reducer handles it below
                rows = context.get("history_rows", [])
                if rows:
                    from . import launch

                    row = rows[min(max(0, state.focusIndex), len(rows) - 1)]
                    history_focus_index = state.focusIndex
                    run_dir = Path(row["run_dir"])
                    snapshot = launch.status(run_dir)
                    context = {**context, "run_id": row.get("run_id"),
                               "run_id_kind": row.get("id_kind", "launch"), "external_run_dir": run_dir,
                               "launch_id": row.get("run_id"),
                               "history_repo_name": row.get("repo"),
                               "history_return": not lead_open, "history_focus_index": history_focus_index,
                               "repo": {**context.get("repo", {}), "name": row.get("repo", "recorded repository"),
                                        "path": row.get("source_repo", "not recorded"), "branch": "recorded",
                                        "head": row.get("head") or "not recorded"}}
                    context = {**context, "event_tail": launch.event_tail(run_dir)}  # a run opened from History shows ITS own events in the dock
                    if snapshot.get("state") == "running":
                        live = launch.live(run_dir)
                        context = {**context, "launch_meta": snapshot.get("meta"),
                                   "elapsed": max(0, int(snapshot.get("elapsed") or 0)),
                                   "run_state": "running",
                                   "running": live or {"phases": [], "unavailable": "engine events are not available yet"}}
                        state = replace(state, st="running", focusIndex=0, focusAction=None,
                                        drill=None, overlay=None, scroll=0)
                    elif snapshot.get("state") == "finished":
                        record = launch.result(run_dir)
                        if record is not None and record.usable:
                            artifact = record.art
                            artifact_repo = _artifact_context(artifact)["repo"]
                            if artifact_repo.get("name") == "repository not recorded" and row.get("repo"):
                                artifact_repo = {**artifact_repo, "name": str(row["repo"]),
                                                 "identity_source": "launch record"}
                            context = {**context, "repo": artifact_repo}
                            state = replace(state, st="verdict", verdict=None, focusIndex=0,
                                            focusAction=None, drill=None, overlay=None, scroll=0)
                        elif ((record is not None and record.status == "missing")
                              or (record is None and _artifact_path_missing(run_dir / "out.json"))):
                            state = replace(state, st="run-ended-no-decision", focusIndex=0, focusAction=None,
                                            drill=None, overlay=None, scroll=0)
                            context["run_id"] = row.get("run_id")
                            context["run_id_kind"] = "launch"
                            context["run_failure"] = {"rc": snapshot.get("rc"), "elapsed": snapshot.get("elapsed"),
                                                      "stderr": launch.stderr_excerpt(run_dir), "run_dir": str(run_dir)}
                            context["resume_offer"] = _resume_claim_context(context, run_dir) is not None  # TUI behavior: a parked effect interrupt can be resumed through the same claim gate
                        else:
                            state = replace(state, st="artifact-unavailable", focusIndex=0, focusAction=None,
                                            drill=None, overlay=None, scroll=0)
                            context["artifact_path"] = record.path if record is not None else run_dir / "out.json"
                            context["artifact_unavailable_reason"] = _artifact_error_summary(record)
                    else:
                        if snapshot.get("state") == "lost":
                            state = replace(state, st="run-lost", focusIndex=0, focusAction=None,
                                            drill=None, overlay=None, scroll=0)
                            context["run_failure"] = {"run_dir": str(run_dir)}
                            context["resume_offer"] = _resume_claim_context(context, run_dir) is not None
                        else:
                            state = replace(state, st="blocked", focusIndex=0, focusAction=None,
                                            drill=None, overlay=None, scroll=0)
                            context["blocked"] = {"kind": "run", "run_dir": str(run_dir), "reason": snapshot.get("why") or
                                                  f"recorded run state is {snapshot.get('state')}"}
                else:
                    state = replace(state, toast="No recorded runs are available yet")
                dirty = True
                break
            if action == "key:enter" and state.overlay == "cancel":
                if state.focusIndex == 1 and state.st == "running":  # the primary 'Cancel run' button is focused
                    from . import launch

                    plan_c = context.get("plan")
                    run_dir = plan_c.run_dir if plan_c is not None else (Path(context["launch_dir"]) if context.get("launch_dir") else context.get("external_run_dir"))
                    outcome = launch.cancel(run_dir) if run_dir is not None else {"result": "refused", "why": "no launch folder is known"}
                    state = replace(state, overlay=None, focusIndex=0)
                    if outcome["result"] == "not-running":
                        state = replace(state, toast="already finished")
                    elif outcome["result"] != "cancelled":
                        state = replace(state, toast=("not cancelled: " + str(outcome.get("why") or outcome["result"]))[:70])
                    last_run_poll = 0.0  # the next poll shows the named state
                    dirty = True
                else:
                    state = reduce.reduce(state, action)  # the default 'Keep running' choice closes the dialog
                    dirty = True
                break
            if action == "key:enter" and state.overlay in {"exit", "quit"}:
                if state.focusIndex == 1:
                    done = True  # detach/exit only; a worker remains owned by its process
                else:
                    state = reduce.reduce(state, action)  # default Stay choice closes the overlay
                    dirty = True
                break
            before = state
            state = reduce.reduce(state, action)
            sig = lambda v: (v.st, v.region, v.focusIndex, v.pane, v.file_focus, v.drill, v.overlay)  # noqa: E731
            if sig(before) != sig(state) and state.st != "claim" and before.st != "claim":
                # a KEY moved the focus: one short emphasis on top of the immediate selected marker. Never on the gated Claim / command review: a settle repaint there would restart the paint
                # clock the run authorisation (dwell + fresh Enter) is measured from
                motion.focus()
            if before.st in {"history", "verdict", "artifact-unavailable", "run-ended-no-decision", "run-lost"} and state.st == "offer":
                # back on the Offer after a result screen: the repository's own facts again (a recorded run's artifact replaced them while it was open)
                home_repo = context.get("home_repo")
                if isinstance(home_repo, dict):
                    context = {**context, "repo": home_repo, "repository_loading": False}
            context = _selection_context(context, state)
            state, context = _seed_tool_exclusions(state, context)
            state = _with_file_count(state, context)
            state = _with_obl_count(state, artifact)
            if before.st == "claim" and state.st != "claim" and (isinstance(context.get("claim_approval"), dict) or isinstance(context.get("claim_apply"), dict)):
                side = context.get("claim_approval") if isinstance(context.get("claim_approval"), dict) else context["claim_apply"]
                prior = side.get("prior") or {}
                context = {**{k: v for k, v in context.items() if k not in {"claim_approval", "claim_apply"}}, **prior}
                if state.st == "selection":  # Esc from an approval Claim goes back to the verdict it came from, not to a source list
                    state = replace(state, st="verdict", focusIndex=0, focusAction=None, drill=None, overlay=None, scroll=0)
            if state.st == "offer" and before.st != "offer":
                state = _default_offer_focus(state, context)  # arriving back on the Offer: the same default as the first paint
            if state.st == "claim" and before.st != "claim":
                excluded_paths, file_total = _claim_exclusion(state, {**context, "change": context.get("change", {})})
                context = {**context, "claim_excluded": excluded_paths, "claim_file_total": file_total}
                context = _claim_context(context)
                claim_shown = False
                claim_painted_at = None
                claim_last_enter_at = read_started_at
                claim_command_rows_seen = set()
                claim_command_row_count = None
                try:
                    termios.tcflush(fd, termios.TCIFLUSH)
                except termios.error:
                    pass
            elif state.st != "claim":
                context = {**context, "plan": None, "command": None}
                claim_command_rows_seen = set()
                claim_command_row_count = None
            if context.get("blocked", {}).get("reason") and state.st != "blocked":
                state = replace(state, st="blocked", focusIndex=0, focusAction=None, drill=None, overlay=None)
            dirty = True

    handlers = {signal.SIGWINCH: on_resize, signal.SIGCONT: on_continue,
                signal.SIGINT: on_exit, signal.SIGTERM: on_exit, signal.SIGHUP: on_exit,
                signal.SIGQUIT: on_exit}
    if hasattr(signal, "SIGTSTP"):
        handlers[signal.SIGTSTP] = on_suspend
    try:
        for sig, handler in handlers.items():
            old_handlers[sig] = signal.signal(sig, handler)
        enter_raw()
        enter_screen()
        toast_seen, toast_at = None, 0.0
        from .motion import Motion

        motion = Motion.from_env(os.environ, color)  # restrained, event-grounded cues; fully static under reduced motion / mono / NO_COLOR
        motion_prev = motion.snapshot()
        st_seen = state.st
        while not done:
            now = time.monotonic()
            dwell_repaint = False
            motion.set_running(state.st == "running" and context.get("run_state") == "running")  # the status spinner exists only while a real run is actively running
            if state.st != st_seen:
                if state.st != "claim":  # never on the gated Claim: a settle repaint there would restart the paint clock the run authorisation is measured from
                    motion.step(now)
                st_seen = state.st
            snap_ = motion.snapshot(now)
            if snap_ != motion_prev:  # a cue started or settled: one repaint (this is the whole animation loop)
                motion_prev = snap_
                dirty = True
            if state.toast != toast_seen:  # a toast has an expiry: 2.4 s after it was first drawn
                toast_seen, toast_at = state.toast, now
            elif state.toast and now - toast_at > 2.4:
                state = replace(state, toast=None)
                toast_seen = None
                dirty = True
            if repo_load_needed and repo_future is None:
                repo_future = record_executor.submit(_repo_context, repo_root, inputs, target_python)
            if repo_future is not None and repo_future.done():
                try:
                    loaded = repo_future.result()
                except Exception as exc:  # noqa: BLE001 - repository inspection failure is shown as a blocked state
                    loaded = _git_blocked_context(repo_root, f"repository inspection failed: {type(exc).__name__}")
                repo_future = None
                repo_load_needed = False
                if context.get("repository_loading"):
                    context = _with_offer_lead(_apply_loaded_repository(context, state, loaded))
                    state = _default_offer_focus(state, context)  # once, when the repository's facts arrive (the operator's own Tab is never overridden)
                    dirty = True
                    if check is not None and state.st == "offer" and not context.get("blocked"):
                        # `hlith ui --check SOURCE` (operator spec 2.3): open the Claim of an OFFERED source. One shot, only from the Offer, and by the very same path as the operator's own
                        # Enter in Selection (consume -> reducer -> Claim context, command review, dwell, fresh Enter): nothing is started here, Run still needs the operator's Enter.
                        wanted, check = check, None
                        found, why = match_check_source(context.get("sources") or [], wanted, Path(context.get("repo", {}).get("path") or repo_root))
                        if found is None:
                            state = replace(state, toast=f"--check: {why} · nothing started")
                        else:
                            state = replace(state, st="selection", focusIndex=found, focusAction=None, scroll=0, pane=0)
                            context = _selection_context(context, state)
                            consume(["enter"], time.monotonic())
                    elif check is not None and (context.get("blocked") or state.st != "offer"):
                        check = None  # a blocked repository or an operator already elsewhere: the request is dropped, never replayed later
                    if pending_new_check is not None:
                        pend, pending_new_check = pending_new_check, None
                        if state.st != "offer" or context.get("blocked"):
                            pass  # blocked, or the operator already moved on: dropped, never replayed later
                        else:
                            found = _find_source_by_label(context.get("sources") or [], pend["label"])
                            if found is None:
                                state = replace(state, toast="n: that change is no longer offered · nothing started")
                            else:
                                state = replace(state, st="selection", focusIndex=found, focusAction=None, scroll=0, pane=0, toast="")
                                context = _selection_context(context, state)
                                context = {**context, "claim_previous": {**pend["prior"], "source_id": (context.get("sources") or [{}])[found].get("id")}}
                                consume(["enter"], time.monotonic())
            if record_future is not None and record_future.done():
                try:
                    rows, total, truncated, scanned, omitted_repos = record_future.result()
                except Exception:  # noqa: BLE001 - history is advisory and may be unreadable
                    rows = []
                    total, truncated, scanned, omitted_repos = 0, False, 0, 0
                record_future = None
                records_scan_seconds = max(0.0, time.monotonic() - last_records_poll)
                scan_completed = context.get("history_scan_complete") is False
                if (scan_completed or rows != context.get("history_rows") or total != context.get("history_total")
                        or truncated != context.get("history_truncated")):
                    context = {**context, "history_rows": rows, "history_total": total,
                               "history_truncated": truncated, "history_scanned": scanned,
                               "history_omitted_repos": omitted_repos,
                               "history_scan_complete": True,
                               "repo": {**context.get("repo", {}),
                                        "records": _records_summary(rows, total, truncated=truncated, scanned=scanned, omitted_repos=omitted_repos)}}
                    if state.st in {"offer", "history"}:
                        dirty = True
                refreshed = _with_offer_lead(context)  # a check that started or finished since the last scan changes what the Offer leads with
                if refreshed is not context:
                    context = refreshed
                    if state.st == "offer":
                        dirty = True
            if record_future is None and now - last_records_poll >= max(1.0, 4 * records_scan_seconds):
                from . import launch

                record_future = record_executor.submit(_scan_history, repo_root)  # this repository's bucket is always read; all the work happens off the UI thread
                last_records_poll = now
            if (state.st == "claim" and claim_shown and claim_painted_at is not None
                    and context.get("claim_dwell_satisfied") is not True
                    and now - claim_painted_at >= 0.5):
                context = {**context, "claim_dwell_satisfied": True}
                dirty = True
                dwell_repaint = True
            active_plan = context.get("plan")
            active_run_dir = (active_plan.run_dir if active_plan is not None
                              else Path(context["launch_dir"]) if context.get("launch_dir") else context.get("external_run_dir"))
            if state.st == "running" and active_run_dir is not None and now - last_run_poll >= 0.2:
                from . import launch

                last_run_poll = now
                snapshot = launch.status(active_run_dir)
                live = launch.live(active_run_dir)
                tail_ = launch.event_tail(active_run_dir)
                motion.observe(str(active_run_dir), [e.get("id") for e in tail_], announce_first=bool(context.get("started_here")))  # new real event ids only; a reattached run's first sight is a silent baseline
                context = {**context, "running": live or {"phases": [], "unavailable": "no engine events are recorded yet"},
                           "event_tail": tail_, "event_run_key": str(active_run_dir),
                           "elapsed": max(0, int(snapshot.get("elapsed") or 0)),
                           "run_state": snapshot.get("state")}
                engine_run_id = launch.engine_run_id(active_run_dir)
                if engine_run_id:
                    context = {**context, "run_id": engine_run_id, "run_id_kind": "run"}
                if snapshot.get("state") == "finished":
                    record = launch.result(active_run_dir)
                    if record is not None and record.usable:
                        artifact = record.art
                        run_artifact = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
                        if record.path:
                            context = {**context, "artifact_path": record.path}
                        if isinstance(run_artifact.get("run_id"), str):
                            context = {**context, "run_id": run_artifact["run_id"], "run_id_kind": "run"}
                        motion.verdict(now)  # a run that completed LIVE here: its verdict is emphasised once (a reopened / historical verdict never is)
                        state = replace(state, st="verdict", verdict=None, focusIndex=0,
                                        focusAction=None, drill=None, overlay=None, scroll=0)
                    elif ((record is not None and record.status == "missing")
                          or (record is None and _artifact_path_missing(active_run_dir / "out.json"))):
                        state = replace(state, st="run-ended-no-decision", focusIndex=0, focusAction=None,
                                        drill=None, overlay=None, scroll=0)
                        context["run_id"] = context.get("launch_id") or context.get("run_id")
                        context["run_id_kind"] = "launch"
                        context["run_failure"] = {"rc": snapshot.get("rc"), "elapsed": snapshot.get("elapsed"),
                                                  "stderr": launch.stderr_excerpt(active_run_dir),
                                                  "run_dir": str(active_run_dir)}
                    else:
                        state = replace(state, st="artifact-unavailable", focusIndex=0, focusAction=None,
                                        drill=None, overlay=None, scroll=0)
                        context["artifact_path"] = record.path if record is not None else active_run_dir / "out.json"
                        context["artifact_unavailable_reason"] = _artifact_error_summary(record)
                    dirty = True
                elif snapshot.get("state") == "cancelled":
                    state = replace(state, st="run-ended-no-decision", focusIndex=0, focusAction=None,
                                    drill=None, overlay=None, scroll=0)
                    context["run_id"] = context.get("launch_id") or context.get("run_id")
                    context["run_id_kind"] = "launch"
                    context["run_failure"] = {"cancelled": True, "elapsed": snapshot.get("elapsed"), "signal": snapshot.get("signal"),
                                              "run_dir": str(active_run_dir)}
                    dirty = True
                elif snapshot.get("state") == "lost":
                    state = replace(state, st="run-lost", focusIndex=0, focusAction=None,
                                    drill=None, overlay=None, scroll=0)
                    context["run_id"] = context.get("launch_id") or context.get("run_id")
                    context["run_id_kind"] = "launch"
                    context["run_failure"] = {"run_dir": str(active_run_dir)}
                    dirty = True
                elif snapshot.get("state") in {"clone-failed", "unknown"}:
                    state = replace(state, st="blocked", focusIndex=0, focusAction=None,
                                    drill=None, overlay=None)
                    context["blocked"] = {"kind": "run", "run_dir": str(snapshot.get("run_dir") or ""), "reason": snapshot.get("why") or f"run state: {snapshot.get('state')}"}
                    dirty = True
                else:
                    dirty = True
            if resized:
                cols, rows = _terminal_size()
                state = reduce.reduce(state, ("resize", cols, rows))
                resized = False
            if dirty:
                cols, rows = _terminal_size()
                state = reduce.reduce(state, ("resize", cols, rows))
                if state.st == "verdict" and record is not None and context.get("feedback_limits_for") != str(record.path):
                    from . import launch as _launch

                    context = {**context, "feedback_limits_for": str(record.path), "feedback_limits": _launch.feedback_limits(Path(str(record.path)).parent)}
                if state.st == "verdict" and context.get("launch_id") and context.get("launch_id") != seen_marked:
                    # the operator is looking at this decision: it stops leading the Offer as NEW (a convenience store; a failure to write it never blocks the screen)
                    seen_marked = context.get("launch_id")
                    offer_lead.mark_seen(history.state_dir(), offer_lead.superseded_ids(context.get("history_rows"), seen_marked))
                    context = _with_offer_lead(context)
                context = _selection_context(context, state)
                state, context = _seed_tool_exclusions(state, context)
                state = _with_file_count(state, context)
                state = _with_obl_count(state, artifact)
                if context.get("blocked", {}).get("reason") and state.st != "blocked":
                    state = replace(state, st="blocked", focusIndex=0, focusAction=None, drill=None, overlay=None)
                shown_artifact = _preview_artifact(artifact, context, record is not None)
                if cursor_needs_hide or not screen_active:
                    enter_screen()
                    cursor_needs_hide = False
                if state.st == "claim":
                    context = {**context, "claim_token": _claim_token(context)}
                context = {**context, "motion": motion.snapshot(now), "syntax": color in {"dainty", "dun"}}
                rendered = frame.render(state, cols, rows, shown_artifact, elapsed=context.get("elapsed", 0),
                                        sample=False, context=context, color=color)
                nav_ = getattr(rendered, "nav", {}) or {}
                if state.nav_max != nav_.get("max") or state.offer_actions != tuple(nav_.get("offer_actions", ())):
                    # hand the screen's VISIBLE focus range back to the reducer: arrows / Tab clamp to it, Enter on the Offer runs the focused action
                    state = replace(state, nav_max=nav_.get("max"), offer_actions=tuple(nav_.get("offer_actions", ())))
                if state.nav_max is not None and not state.overlay and not state.drill and state.focusIndex > state.nav_max:
                    state = replace(state, focusIndex=state.nav_max)  # an index past the visible items is never left standing: repaint once with a real highlight
                    dirty = True
                if state.st == "claim" and context.get("command") and state.overlay:
                    claim_shown = False  # an overlay is painted over the command: NO review evidence accumulates from this frame (rows seen, END, painted clock, dwell)
                elif state.st == "claim" and context.get("command"):
                    visibility = getattr(rendered, "_visibility", {})
                    row_count = visibility.get("claim_command_row_count")
                    if row_count != claim_command_row_count:
                        claim_command_rows_seen = set()
                        claim_command_row_count = row_count
                    claim_command_rows_seen.update(visibility.get("claim_command_visible_rows", ()))
                    all_command_rows_seen = (type(row_count) is int and row_count > 0
                                             and set(range(row_count)).issubset(claim_command_rows_seen))
                    end_visible = _command_end_visible(rendered)
                    command_seen = (context.get("claim_command_seen") is True
                                    or (all_command_rows_seen and end_visible))
                    if (context.get("command_visible") is not command_seen
                            or context.get("claim_command_seen") is not command_seen):
                        context = {**context, "command_visible": command_seen,
                                   "claim_command_seen": command_seen}
                        rendered = frame.render(state, cols, rows, shown_artifact, elapsed=context.get("elapsed", 0),
                                                sample=False, context=context, color=color)
                    claim_shown = command_seen and not context.get("command_control_chars")
                else:
                    claim_shown = False
                sys.stdout.write(_CLEAR + ansi_frame(rendered, color))
                sys.stdout.flush()
                _dump_frame(rendered, cols, rows, last_key)
                if state.st == "claim" and claim_shown and not dwell_repaint:
                    claim_painted_at = time.monotonic()
                elif state.st != "claim" or not claim_shown:
                    claim_painted_at = None
                dirty = False
            quiet = (state.st in {"offer", "selection", "history", "verdict", "blocked", "run-ended-no-decision", "run-lost", "artifact-unavailable"} and not state.toast and not state.overlay
                     and not context.get("repository_loading") and repo_future is None and context.get("history_scan_complete") is not False and not resized and not motion.active(now))
            ready, _, _ = select.select([fd], [], [], 0.5 if quiet else 0.1)  # ~100 ms while live or settling, ~500 ms on a quiet screen
            if not ready:
                consume(decoder.flush(), time.monotonic())
                continue
            read_started_at = time.monotonic()
            batch = os.read(fd, 4096)
            if not batch:
                done = True
                continue
            consume(decoder.feed(batch), read_started_at)
    except (OSError, termios.error) as exc:
        print(f"\nhlith TUI: terminal I/O failed: {exc}", file=sys.stderr)
        return 2
    finally:
        restore()
        gitq.cancel_active_children()
        record_executor.shutdown(wait=False, cancel_futures=True)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    return 0


def _is_git_repo(path: Path) -> bool:
    """A readable Git repository (the same hardened read the host uses to open one)."""
    try:
        return gitq.refusal(Path(path)) is None
    except Exception:  # noqa: BLE001 - an unreadable path is simply not a repository here
        return False


def _remembered_repos(state=None, limit: int = 8) -> list[Path]:
    """TUI behavior 2.6 (spec s3.1): the repositories this UI opened before (repos.json under the UI state, outside every repository): only ones that still exist AND are readable Git repositories."""
    from . import repos

    out: list[Path] = []
    for item in repos.known(state):
        path = Path(item)
        if path.is_dir() and path not in out and _is_git_repo(path):
            out.append(path)
    return out[:limit]


def choose_repository(known, *, ask, say) -> Path | None:
    """The first-run chooser (outside any repository): the remembered repositories numbered, plus a path entry line; q/empty quits. Nothing is read from a path until it is chosen."""
    say("Not inside a Git repository." + (" Recent repositories:" if known else " No repository is remembered yet."))
    for number, path in enumerate(known, 1):
        say(f"  {number}  {path}")
    while True:
        answer = ask("Open a repository: number or path (q quits): ").strip()
        if answer.lower() in {"", "q", "quit"}:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(known):
            return known[int(answer) - 1]
        path = Path(answer).expanduser()
        if path.is_dir() and _is_git_repo(path):
            return path.resolve()
        say(f"  {answer!r} is not a readable Git repository.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hlith ui", description="Review a real change or inspect recorded decisions.")
    parser.add_argument("paths", nargs="*", metavar="ARTIFACT", help="recorded artifact JSON to inspect")
    parser.add_argument("--artifact", metavar="PATH", help="recorded artifact JSON to inspect")
    parser.add_argument("--repo", metavar="PATH", default=None, help="repository to inspect (default: the current directory; outside a repository: the remembered one, or a chooser)")
    parser.add_argument("--inputs", action="append", default=[], metavar="DIR", help="directory containing saved patch/manifest inputs")
    parser.add_argument("--target-python", metavar="PATH", help="interpreter passed to the engine when a check starts")
    parser.add_argument("--strict-domain", action="store_true", help="require exact-type guards for typed proofs")
    parser.add_argument("--runs", action="store_true", help="list recorded runs across repositories")
    parser.add_argument("--static", action="store_true", help="no motion: no cues, no spinner (also HLITH_STATIC / NO_MOTION / REDUCE_MOTION; R toggles it at run time)")
    parser.add_argument("--plain", action="store_true", help="print a read-only frame instead of opening a terminal session")
    parser.add_argument("--check", metavar="SOURCE", help="open the Claim for this offered change instead of the Offer: uncommitted | commit:REV | branch:NAME | patch:PATH. Hlith Review starts no check from the terminal screen; run `hlith check`")
    args = parser.parse_args(argv)
    if getattr(args, "static", False):
        os.environ["HLITH_STATIC"] = "1"  # read by motion.reduced_motion when the loop starts
    check = None
    if args.check is not None:
        try:
            check = parse_check_source(args.check)
        except ValueError as exc:
            parser.error(f"--check: {exc}")
        if args.artifact or args.paths or args.runs:
            parser.error("--check opens a change to check; it cannot be combined with an artifact or --runs")
        if check[0] == "patch":
            args.inputs = [*args.inputs, str(Path(check[1]).expanduser().resolve().parent)]  # the patch's folder is discovered like --inputs (its manifest must sit next to it)
    if args.runs:
        from . import launch

        rows = launch.run_rows()
        print("\n".join(launch.run_row_text(row, 200) + f"  {row['run_id']}" for row in rows)
              or "No run has been started from here yet.")
        return 0
    if args.artifact and args.paths:
        parser.error("pass an artifact path either positionally or with --artifact, not both")
    if len(args.paths) > 1:
        parser.error("inspect one artifact at a time")
    artifact_path = args.artifact or (args.paths[0] if args.paths else None)
    root = Path(args.repo or ".").expanduser()
    if check is not None and (args.plain or not (sys.stdin.isatty() and sys.stdout.isatty()) or not _terminal_can_run_screen(os.environ)):
        print("hlith ui --check needs an interactive terminal (nothing was started). For a headless check use: hlith check --repo PATH", file=sys.stderr)
        return 2
    if args.plain or not (sys.stdin.isatty() and sys.stdout.isatty()) or not _terminal_can_run_screen(os.environ):
        return _plain(artifact_path, root, args.inputs, args.target_python)  # case: a terminal that cannot run the screen gets the plain frame and exit 0, never a hang
    remembered = False
    if artifact_path is None and args.repo is None:
        from . import repos

        ui_state = history.state_dir()
        if not _is_git_repo(root):  # a bare run outside any repository: open the remembered one (labelled) or ask
            known = _remembered_repos(ui_state)
            if len(known) == 1:
                root, remembered = known[0], True
            else:
                chosen = choose_repository(known, ask=input, say=print)
                if chosen is None:
                    print("No repository chosen; nothing was read.", file=sys.stderr)
                    return 2
                root = chosen
        if _is_git_repo(root):
            repos.remember(root, ui_state)  # a convenience list: never a reason to fail
    prior = os.environ.get("HLITH_CERT_STRICT_DOMAIN")
    try:
        if args.strict_domain:
            os.environ["HLITH_CERT_STRICT_DOMAIN"] = "1"
        return _run_terminal(artifact_path, root, args.inputs, args.target_python, remembered=remembered, check=check)
    finally:
        if args.strict_domain:
            if prior is None:
                os.environ.pop("HLITH_CERT_STRICT_DOMAIN", None)
            else:
                os.environ["HLITH_CERT_STRICT_DOMAIN"] = prior


if __name__ == "__main__":
    raise SystemExit(main())
