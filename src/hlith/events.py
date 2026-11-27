# SPDX-License-Identifier: Apache-2.0
"""Run events: one JSON line per REAL phase transition of `hlith run`, for a human-facing screen (informational only).

The supervisor appends to a run-local file chosen by the operator (`--events-out`, default OFF). Events are written by the code that
actually enters and leaves each phase; they are never read by the gate and never part of the artifact. Hard rules:
- the file is opened O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, mode 0600, and is never inherited by the confined worker;
- events carry ONLY engine facts: allow-listed phase/event names, ints, and qualified callable names (cleaned); never worker or diff text;
- once the file is open, every I/O error is swallowed and reported (events can never fail or change a run); only an unusable path (special
  file, non-empty file, worker-readable tree) refuses the run BEFORE it starts (exit 4); size is capped; one line per event, flushed per event.
"""

from __future__ import annotations

import json
import math
import os
import stat
import time
import unicodedata
from pathlib import Path
from typing import Iterable


def _clean_text(text: str) -> str:
    """Minimal stdlib-only printable sanitization for event fields (no hostio/textsafe import)."""
    if text.isprintable() and not any(unicodedata.category(c).startswith("M") for c in text):
        return text
    out: list[str] = []
    for c in text:
        if c.isprintable() and not unicodedata.category(c).startswith("M"):
            out.append(c)
        elif not c.isprintable():
            o = ord(c)
            out.append(f"\\x{o:02x}" if o < 0x100 else (f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}"))
    return "".join(out)

MAX_BYTES = 256 * 1024
PHASES = frozenset({"stage_and_worker", "derive", "account", "differential", "declare", "gate", "resume", "run"})
EVENTS = frozenset({"start", "end", "progress", "truncated"})
UNAVAILABLE_PREFIX = "hlith: events unavailable: "  # the stderr line cli prints and the TUI reads back
EXTRA_KEYS = frozenset({"target", "i", "n", "outcome", "exit_status"})
OUTCOMES = frozenset({"landed", "refused"})


def _extra(extra: dict) -> dict:
    out: dict = {}
    for k, v in extra.items():
        if k not in EXTRA_KEYS:
            continue
        if isinstance(v, bool) or v is None:
            continue
        if k in ("i", "n", "exit_status"):
            if isinstance(v, int):
                out[k] = v
        elif k == "outcome" and isinstance(v, str) and v in OUTCOMES:
            out[k] = v
        elif k == "target" and isinstance(v, str):
            out[k] = _clean_text(v)[:160]
    return out


class Refused(ValueError):
    """The events file cannot be used safely (special file, or a file that already holds a run): the run must not start (exit 4)."""


class Emitter:
    """Appends engine events. `ok` is False when nothing is being written; `error` then says why (shown to the operator as
    'events unavailable: <reason>'). `Refused` is raised only for a path that must never be written: a FIFO/device/other special file
    (opening a FIFO would hang the supervisor) or a non-empty file (it would merge two runs and exceed the cap)."""

    def __init__(self, path, run_id: str, cap: int = MAX_BYTES, on_error=None):
        self.path, self.run_id, self.cap = str(path), str(run_id), int(cap)
        self.seq = 0
        self.size = 0
        self.fd: int | None = None
        self.ok = False
        self.error: str | None = None
        self.stopped = False
        self._on_error = on_error
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as e:
            try:  # an existing path that is not a regular file is a refusal, not a silent skip
                if not stat.S_ISREG(os.lstat(self.path).st_mode):  # FIFO (ENXIO), directory, symlink (ELOOP), device: refuse, do not run on
                    raise Refused(f"--events-out {self.path} is not a regular file")
            except OSError:
                pass
            self._fail(f"cannot open {self.path}: {e.strerror or e}")
            return
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"--events-out {self.path} is not a regular file")
            if st.st_size > 0:
                raise Refused(f"--events-out {self.path} already holds data; give each run a new file (an old run's events would be merged with this one)")
        except (Refused, OSError) as e:
            os.close(fd)
            if isinstance(e, Refused):
                raise
            self._fail(f"cannot inspect {self.path}: {e.strerror or e}")
            return
        try:
            os.set_blocking(fd, True)
        except OSError:
            pass
        self.fd = fd
        self.ok = True

    def _fail(self, reason: str) -> None:
        """Record why nothing (more) is written and tell the operator once; never raises (events cannot fail a run)."""
        self.error = reason
        if self._on_error is not None:
            try:
                self._on_error(reason)
            except Exception:  # noqa: BLE001
                pass

    def _write(self, rec: dict) -> bool:
        if self.fd is None:
            return False
        line = (json.dumps(rec, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        try:
            os.write(self.fd, line)  # one write on an O_APPEND descriptor: a reader never sees half of an event from this writer
        except OSError as e:
            self.fd = None
            self.ok = False
            self._fail(f"write failed: {e.strerror or e}")
            return False
        self.size += len(line)
        return True

    def emit(self, phase: str, event: str, **extra) -> None:
        if self.stopped or self.fd is None or phase not in PHASES or event not in EVENTS:
            return
        self.seq += 1
        rec = {"seq": self.seq, "ts_mono": round(time.monotonic(), 3), "ts_wall": round(time.time(), 3), "run_id": self.run_id,
               "phase": phase, "event": event}
        ex = _extra(extra)
        if ex:
            rec["extra"] = ex
        if self.size + len(json.dumps(rec)) + 1 > self.cap - 160:  # leave room for the truncation marker
            self._write({"seq": self.seq, "ts_mono": rec["ts_mono"], "ts_wall": rec["ts_wall"], "run_id": self.run_id, "phase": phase, "event": "truncated"})
            self.stopped = True
            return
        self._write(rec)

    def close_run(self, outcome, exit_status) -> None:
        """The closing event, after the artifact is written (or at a boundary exit): tells 'finished' from 'lost'. Always attempted, even after
        a truncation marker (it is the one line a reader must be able to rely on)."""
        if self.fd is None:
            return
        self.stopped = False
        self.seq += 1
        ex = {"exit_status": exit_status if isinstance(exit_status, int) and not isinstance(exit_status, bool) else None}
        if outcome in OUTCOMES:
            ex["outcome"] = outcome
        rec = {"seq": self.seq, "ts_mono": round(time.monotonic(), 3), "ts_wall": round(time.time(), 3), "run_id": self.run_id,
               "phase": "run", "event": "end", "extra": {k: v for k, v in ex.items() if v is not None}}
        self._write(rec)
        self.close()

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def check_path(path, granted) -> None:
    """Refuse an events file that sits inside a tree the confined worker is granted (it could then be read or written by the worker)."""
    p = Path(path).expanduser().resolve(strict=False)
    for g in granted:
        if g is None or str(g) == "":
            continue
        gp = Path(g).expanduser().resolve(strict=False)
        if p == gp or gp in p.parents or p in gp.parents:
            raise ValueError(f"--events-out {p} is inside or above {gp}, a location the worker can access; choose a path elsewhere")


def _num(v) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    try:
        return math.isfinite(v)
    except OverflowError:  # an int too large for a float
        return False


_DEFAULT_SYSTEM_RO = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/alternatives",
    "/proc",
)


def readable_roots(target_python=None, *, system_roots: Iterable[str] | None = None) -> list[str]:
    """Trees the worker and the evaluators can READ besides the repo: injected system roots (or standard POSIX RO defaults),
    this interpreter's prefixes and the target python's."""
    import sys

    src_roots = _DEFAULT_SYSTEM_RO if system_roots is None else system_roots
    roots = [r for r in src_roots if r not in ("/dev/null", "/dev/zero", "/dev/urandom")]
    roots += [sys.prefix, sys.base_prefix]
    if target_python:
        try:
            exe = Path(target_python).expanduser()
            if exe.is_absolute():  # a bare name ('python3') has no prefix we can know without a PATH lookup
                for q in {exe.parent.parent, exe.resolve(strict=False).parent.parent}:
                    if q != q.parent:  # never the filesystem root
                        roots.append(str(q))
        except (OSError, RuntimeError):
            pass
    return roots


def read(path) -> list[dict]:
    """Events from a possibly in-progress file. Missing file, partial last line, garbage lines and records with a wrong-typed field
    (seq, ts_mono, extra) are skipped or sanitised, so a reader (the TUI) can never crash on what is in the file."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return []
    out = []
    for line in raw.split(b"\n"):
        try:
            rec = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if not (isinstance(rec, dict) and isinstance(rec.get("phase"), str) and isinstance(rec.get("event"), str)
                and rec["phase"] in PHASES and rec["event"] in EVENTS):
            continue
        if isinstance(rec.get("seq"), bool) or not isinstance(rec.get("seq"), int) or not _num(rec.get("ts_mono")):
            continue
        ex = rec.get("extra")
        rec["extra"] = _extra(ex) if isinstance(ex, dict) else {}
        out.append(rec)
    return out
