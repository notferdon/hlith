# SPDX-License-Identifier: Apache-2.0
"""Read-only projection of a recorded `hlith run` artifact. NO verdict of its own: labels are looked up from the
artifact's own `outcome` / `exit_status`; anything the artifact does not say is shown as unknown, never filled in."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .. import labels as _labels, store as _store
from ..schema import artifact_errors

MAX_BYTES = 64 * 1024 * 1024
EXIT_WORDS = _labels.REFUSAL_WORD  # one vocabulary, from contract.errors


@dataclass
class Record:
    path: Path
    status: str  # ok | schema-invalid | malformed | missing | empty | unreadable | not-an-artifact | directory
    art: dict | None = None
    errors: list[str] = field(default_factory=list)
    note: str | None = None  # an operator-supplied label (notes.json beside the file), shown verbatim

    @property
    def usable(self) -> bool:
        return self.art is not None and self.status in ("ok", "schema-invalid")


@dataclass(frozen=True)
class ViewState:
    """Pure operator view state. It contains no repository or run authority."""

    st: str = "offer"
    verdict: str | None = None
    focusIndex: int = 0
    selectedIndex: int | None = None
    focusAction: str | None = None
    drill: str | None = None
    overlay: str | None = None
    scroll: int = 0
    included: bool = True
    excluded_sources: tuple = ()  # source indices whose file the operator excluded: the exclusion belongs to ITS source only
    excluded_files: tuple = ()  # (source index, file index) pairs the operator left out of the claim; indices follow the source's file list
    pane: int = 0  # Selection focus: 0 = the source rail, 1 = the file list of the focused source
    file_focus: int = 0
    file_count: int = 0  # files of the focused source (set by the host from the real change; the reducer never invents it)
    obl_count: int = 0  # obligations of the shown record (set by the host from the real artifact; the reducer never invents it)
    obl_default: int = 0  # the obligation the first paint highlights (refuted-first, from frame._initial_focus_index): one source of truth for the marker, Enter and the arrows
    nav_max: int | None = None  # the highest focus index that is VISIBLE on this screen (set by the host from the frame; None = not yet known): arrows / Tab never go past it
    offer_actions: tuple = ()  # the Offer's visible actions in focus order ('lead' / 'review' / 'sources'): Enter runs exactly the focused one
    region: str = "centre"  # wide cockpit (>= 150 columns): which pane holds the keyboard focus: nav | centre | ctx (the screen's own selection lives in the centre)
    focus_blocked: bool = False  # the focused Selection source cannot be checked (e.g. a root commit has no base): set by the host from the real change, never by the reducer
    toast: str | None = None
    cols: int = 80
    rows: int = 24

    @property
    def focus_index(self) -> int:
        return self.focusIndex

    @classmethod
    def from_golden(cls, state: dict) -> "ViewState":
        """Adapt the agreed golden-state vocabulary without importing test fixtures."""
        return cls(
            st=str(state.get("st", "offer")),
            verdict=state.get("verdict"),
            focusIndex=max(0, int(state.get("focusIndex", 0))),
            selectedIndex=state.get("selectedIndex"),
            focusAction=state.get("focusAction"),
            drill=state.get("drill"),
            overlay=state.get("overlay"),
            scroll=max(0, int(state.get("scroll", 0))),
            included=bool(state.get("included", True)),
            toast=state.get("toast"),
        )


def _note_for(path: Path) -> str | None:
    try:
        notes = json.loads((path.parent / "notes.json").read_text(encoding="utf-8"))
        v = notes.get(path.name)
        return v if isinstance(v, str) else None
    except (OSError, ValueError, AttributeError):
        return None


def load(path) -> Record:
    p = Path(path)
    if p.is_dir():
        return Record(p, "directory", errors=["a directory, not an artifact file"])
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(p, flags)
    except FileNotFoundError:
        return Record(p, "missing", errors=["no such file"])
    except IsADirectoryError:
        return Record(p, "directory", errors=["a directory, not an artifact file"])
    except OSError as e:
        return Record(p, "unreadable", errors=[f"{e.strerror or e}"])
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return Record(p, "unreadable", errors=["not a regular artifact file"])
        if info.st_size > MAX_BYTES:
            return Record(p, "unreadable", errors=[f"file larger than {MAX_BYTES} bytes"])
        raw = bytearray()
        while len(raw) <= MAX_BYTES:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_BYTES:
            return Record(p, "unreadable", errors=[f"file larger than {MAX_BYTES} bytes"])
    except OSError as e:
        return Record(p, "unreadable", errors=[f"{e.strerror or e}"])
    finally:
        os.close(fd)
    if not raw.strip():
        return Record(p, "empty", errors=["the file is empty"])
    try:
        art = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return Record(p, "malformed", errors=[f"not JSON: {str(e)[:160]}"])
    if isinstance(art, dict) and art.get("format") == 2 and "outcome" in art and "obligations" not in art:
        art = {**art, "obligations": [], "_obligations_not_recorded": True}  # a format-2 artifact from before the rows existed: shown, flagged
    if not isinstance(art, dict) or "obligations" not in art or "outcome" not in art:
        return Record(p, "not-an-artifact", errors=["JSON, but not an hlith run artifact (no outcome/obligations)"])
    errs = artifact_errors(art)
    art, shape = _viewable(art)
    return Record(p, "ok" if not (errs or shape) else "schema-invalid", art, [*errs, *shape], _note_for(p))


def load_bytes(path, raw: bytes | bytearray) -> Record:
    """Validate bytes already opened safely by the caller; never re-open the path."""
    p = Path(path)
    if len(raw) > MAX_BYTES:
        return Record(p, "unreadable", errors=[f"file larger than {MAX_BYTES} bytes"])
    if not bytes(raw).strip():
        return Record(p, "empty", errors=["the file is empty"])
    try:
        art = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return Record(p, "malformed", errors=[f"not JSON: {str(e)[:160]}"])
    if isinstance(art, dict) and art.get("format") == 2 and "outcome" in art and "obligations" not in art:
        art = {**art, "obligations": [], "_obligations_not_recorded": True}
    if not isinstance(art, dict) or "obligations" not in art or "outcome" not in art:
        return Record(p, "not-an-artifact", errors=["JSON, but not an hlith run artifact (no outcome/obligations)"])
    errs = artifact_errors(art)
    art, shape = _viewable(art)
    return Record(p, "ok" if not (errs or shape) else "schema-invalid", art, [*errs, *shape], _note_for(p))


def _viewable(art: dict) -> tuple[dict, list[str]]:
    """A copy the views can iterate: rows that are not objects are dropped, a non-list blocking becomes [] (each change is reported as a
    schema problem, so the record shows as UNVALIDATED instead of crashing the screen on a malformed or hostile artifact)."""
    problems: list[str] = []
    out = dict(art)
    obs = art.get("obligations")
    if not isinstance(obs, list):
        out["obligations"] = []
        problems.append("obligations is not a list (shown as none)")
    elif any(not isinstance(o, dict) for o in obs):
        out["obligations"] = [o for o in obs if isinstance(o, dict)]
        problems.append(f"{len(obs) - len(out['obligations'])} obligation row(s) are not objects (left out of the view)")
    blocking = art.get("blocking")
    if blocking is not None and not (isinstance(blocking, list) and all(isinstance(b, str) for b in blocking)):
        out["blocking"] = [str(b) for b in blocking] if isinstance(blocking, list) else []
        problems.append("blocking is not a list of strings (normalised for the view)")
    return out, problems


def decision(art: dict) -> tuple[str, str]:
    """The single TUI decision projection, shared with the frame renderer."""
    from .frame import _decision

    label, tone, _status = _decision(art)
    return label, tone


def run_view(rec: "Record") -> _store.RunView | None:
    """The operator store's view of the run this record sits in (receipt, linked ids, real state), or None for a bare file with no run directory."""
    d = rec.path.parent
    if rec.path.name != _store.ARTIFACT or _store.read_receipt(d) is None:
        return None
    return _store.read_run(d)


def feedback_tag(rec: "Record") -> str:
    """' · FEEDBACK FAILED' / ' · FEEDBACK NOT RECORDED' when the post-gate feedback step failed (the decision itself is unchanged)."""
    rv = run_view(rec) if rec.usable else None
    if rv is None or not rv.feedback_problems:
        return ""
    return " · FEEDBACK FAILED" if decision(rec.art)[0] == "LANDED" else " · FEEDBACK NOT RECORDED"


def target_notes(rec: "Record") -> list[str]:
    """Landing-target and input-origin statements for a record. A rehearsal landing is never presented as an original landing; a
    supplied patch is never presented as an observed agent run; a record with no receipt says its target/origin were not recorded."""
    if not rec.usable:
        return []
    v = run_view(rec)
    if v is None:
        v = _store.RunView(rec.path.parent, _store.RunState.FINISHED, None, rec.art)
    notes = []
    if decision(rec.art)[0] == "LANDED":
        notes.append(_labels.target_note(v) or "")
    notes.append(_labels.origin_note(v) or "")
    if v.receipt is not None and v.artifact is not None:
        rid = (v.artifact.get("run") or {}).get("run_id")
        if rid not in (None, v.receipt.run.run_id):
            notes.append(f"RUN ID MISMATCH: artifact says {rid}, receipt says {v.receipt.run.run_id}")
    if rec.art.get("_obligations_not_recorded"):
        notes.append("obligation rows are not recorded in this artifact (written before they were added): the decision above is the gate's; the evidence is not shown")
    gaps = _store.witness_gaps(rec.art)
    if gaps:
        notes.append("WITNESS MISSING for refuted obligation(s): " + ", ".join(gaps))
    eff = rec.art.get("effect") or {}
    if int(eff.get("preamble_removed_bytes") or 0) > 0:
        notes.append(f"preamble removed ({int(eff['preamble_removed_bytes'])} bytes before the first 'diff --git'); input sha256 "
                     f"{str(eff.get('input_patch_sha256') or '')[:12]}, applied sha256 {str(eff.get('patch_sha256') or '')[:12]}")
    rv = run_view(rec)
    if rv is not None:
        notes = [*_labels.feedback_notes(rv), *notes]
        from .. import receipts as _receipts
        ann = _receipts.read_annotations(_store.engine_run_dir(rec.path.parent) or rec.path.parent)
        if ann:
            bad = any(not a.get("chain_ok") for a in ann)
            last = ann[-1]
            notes.append(f"operator notes: {len(ann)} (latest: {last.get('action')} by {last.get('operator') or 'unrecorded'}); annotation-only, never a decision"
                         + ("; CHAIN BROKEN" if bad else ""))
    return [n for n in notes if n]


def _s(v, default="-"):
    return default if v in (None, "") else str(v)


def header(art: dict) -> dict:
    eff, run, tm = art.get("effect") or {}, art.get("run") or {}, art.get("timings") or {}
    return {
        "patch": _s(eff.get("patch_sha256"))[:12], "proposer": _s(eff.get("proposer_id")),
        "files": list(eff.get("touched_files") or []), "base": _s(run.get("base_commit_sha"))[:12],
        "run_id": _s(run.get("run_id")), "started": _s(run.get("started_at_utc")),
        "landed": _s(art.get("landed_commit"))[:12], "total_s": tm.get("total_seconds"),
        "exit": art.get("exit_status"),
    }


def obligations(art: dict) -> list[dict]:
    out = []
    for o in art.get("obligations") or []:
        if not isinstance(o, dict):  # a malformed record (rows that are not objects) is shown without those rows, never a crash
            continue
        ev = o.get("evidence") if isinstance(o.get("evidence"), dict) else {}
        out.append({"id": _s(o.get("id")), "verdict": _s(o.get("verdict")), "claim": _s(o.get("claim"), ""),
                    "witness": o.get("witness"), "stop_reason": o.get("stop_reason"),
                    "explored": ev.get("explored"), "unexplored": ev.get("unexplored")})
    return out


def blocking(art: dict) -> list[dict]:
    by = {o["id"]: o for o in obligations(art)}
    # A BOUNDARY refusal (e.g. a failed --worker-cmd) records the engine's own reasons as the `blocking` entries: they are PROSE, not obligation ids.
    # Such an entry is shown as the reason it is; only an id-shaped entry with no obligation record says "obligation not in the artifact".
    out = []
    for b in art.get("blocking") or []:
        if by.get(b):
            out.append(by[b])
            continue
        text = str(b)
        prose = isinstance(b, str) and (" " in text.strip() or text.strip().lower().endswith(("-failed", "-refused", "-unavailable")))
        out.append({"id": text, "verdict": "?", "claim": "", "witness": None, "stop_reason": text if prose else "obligation not in the artifact",
                    "explored": None, "unexplored": None, "reason_only": prose})
    return out


_CLASS = __import__("re").compile(r"^\S+:\d+ (\w+):")


def construct_class(o: dict) -> str | None:
    """The construct class the engine names in a not-derived reason (`file.py:429 unsupported_entry_guard: ...`), else None."""
    m = _CLASS.match(str(o.get("stop_reason") or o.get("witness") or ""))
    return m.group(1) if m else None


def group_blocking(bl: list[dict]) -> list[dict]:
    """Blocking obligations grouped by (verdict, id without its trailing -N, construct class); order of first appearance. Nothing is dropped:
    every member stays in `items`."""
    import re
    groups: dict[tuple, dict] = {}
    for o in bl:
        key = (o["verdict"], re.sub(r"-\d+$", "", o["id"]), construct_class(o))
        g = groups.setdefault(key, {"verdict": o["verdict"], "base": key[1], "cls": key[2], "items": []})
        g["items"].append(o)
    return list(groups.values())



def no_python(change: dict | None) -> bool:
    """The single 'this change has no Python file' fact (defined with the frame renderer that shows it; imported lazily like `decision`)."""
    from .frame import _no_python
    return _no_python(change)
