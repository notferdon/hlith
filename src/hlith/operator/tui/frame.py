# SPDX-License-Identifier: Apache-2.0
"""Pure cell renderer for the focused operator workbench.

The renderer accepts a view snapshot and recorded inputs only. It performs no
repository, readiness, engine, or terminal I/O.
"""

from __future__ import annotations

import json
import re
import shlex
import unicodedata
from pathlib import Path
from dataclasses import dataclass, replace as _dc_replace

from .. import labels
from ..disclosure import checker_summary, effect_rows
from . import artifact_facts as _af


_MONO = {"ok": "text", "bad": "text", "warn": "text", "add": "text", "addBg": "text", "del": "text", "hunk": "dim",
         "chipOk": "chip", "chipBad": "chip", "chipWarn": "chip", "delHi": "chip", "btnBad": "selected"}
_TOKEN = {"text": "text", "bold": "bold", "dim": "dim", "label": "label", "hint": "hint", "rule": "rule",
          "code": "code", "selected": "selected", "key": "key", "ok": "ok", "bad": "bad", "warn": "warn",
          "add": "add", "addBg": "addBg", "del": "del", "delHi": "delHi", "btnBad": "btnBad",
          "hunk": "hunk", "chip": "chip", "chipOk": "chipOk", "chipBad": "chipBad",
          "chipWarn": "chipWarn", "sample": "sample", "emph": "emph", "emphSel": "emphSel",
          "kw": "kw", "str": "str", "com": "com", "num": "num", "fn": "fn"}
_LEGACY_STYLE_FALLBACK = {"addBg": "add", "delHi": "chipBad", "btnBad": "selected"}


_SYNTAX = False  # set by render(): the dainty / dun presets colour Python source; every other mode renders exactly as before
_PY_KEYWORDS = frozenset("def class return if elif else for while in not and or is import from as with try except finally raise lambda pass yield async await assert del global nonlocal break continue None True False".split())
_PY_TOKEN = re.compile(
    r"(?P<com>#.*$)"
    r"|(?P<str>(?:[rRbBfFuU]{0,2})(?:\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\'))"
    r"|(?P<num>\b\d[\d_]*(?:\.\d+)?\b)"
    r"|(?P<name>[A-Za-z_]\w*)"
)


def _code_spans(text: str, tone: str, tag: str) -> list:
    """The source text of ONE diff line as spans. Without the syntax preset it is the single span it always was. With it, Python is tokenised line by line (keywords, strings, comments, numbers, the
    name after def / class): the spans always concatenate to exactly `text`, so truncation / padding / annotations downstream (they work on spans and cells) are unaffected; an unterminated
    string or any construct the line-level scan does not recognise simply stays plain. Added / removed lines keep their +/- colour for code and recolour only strings and comments, so the diff
    stays readable by its semantics first."""
    if not _SYNTAX or not text.strip():
        return [s(text, tone)]
    semantic = tag in {"+", "-"}
    out, pos, after_def = [], 0, False
    for m in _PY_TOKEN.finditer(text):
        kind = m.lastgroup
        if m.start() > pos:
            out.append(s(text[pos:m.start()], tone))
        word = m.group(0)
        if kind == "name":
            if after_def:
                piece_tone = tone if semantic else "fn"
                after_def = False
            elif word in _PY_KEYWORDS:
                piece_tone = tone if semantic else "kw"
                after_def = word in {"def", "class"}
            else:
                piece_tone = tone
        elif kind in {"str", "com"}:
            piece_tone = kind
        else:
            piece_tone = tone if semantic else "num"
        out.append(s(word, piece_tone))
        pos = m.end()
    if pos < len(text):
        out.append(s(text[pos:], tone))
    return out


_clean = _af.clean


@dataclass(frozen=True)
class Seg:
    text: str
    tone: str = "text"
    action: str | None = None
    panel: bool = False


def s(text, tone="text", action=None):
    return Seg(_clean(text), tone, action)


def _width(lines) -> int:
    return sum(len(g.text) for g in lines)


def sp(n: int) -> list[Seg]:
    return [Seg(" " * max(0, n))] if n > 0 else []


def _slice(lines, start: int, end: int) -> list[Seg]:
    out, pos = [], 0
    for g in lines:
        nxt = pos + len(g.text)
        a, b = max(start, pos), min(end, nxt)
        if b > a:
            out.append(Seg(g.text[a - pos:b - pos], g.tone, g.action, g.panel))
        pos = nxt
    return out


def fit(lines, width: int) -> list[Seg]:
    width = max(0, int(width))
    n = _width(lines)
    if n > width:
        if width and not "".join(g.text for g in lines)[width:].strip():
            return _slice(lines, 0, width)  # only blanks overflow: nothing visible was cut, so no cut marker
        return [] if width == 0 else _slice(lines, 0, width - 1) + [s("…", "hint")]
    return list(lines) + sp(width - n)


def fs(text, width: int) -> str:
    text = _clean(text)
    width = max(0, int(width))
    if len(text) > width:
        if width and not text[width:].strip():
            return text[:width]  # only trailing blanks overflow: no cut marker
        return "" if width == 0 else text[:width - 1] + "…"
    return text + " " * (width - len(text))


def wrap(text, width: int) -> list[str]:
    width = max(4, int(width))
    words = _clean(text).split(" ")
    out, cur = [], ""
    for word in words:
        if not cur:
            cur = word
        elif len(cur) + len(word) + 1 <= width:
            cur += " " + word
        else:
            out.append(cur)
            cur = word
    out.append(cur)
    chunks = []
    for line in out:
        while len(line) > width:
            # a token longer than the line breaks AFTER a natural break character ('.', '/', '(', ',', '=', '-', ':'; never '_', which sits inside identifiers) when one sits in the second half of the piece, never mid-identifier
            cut = max((line.rfind(ch, 0, width) + 1 for ch in "./(,=-:"), default=0)
            cut = cut if cut > width // 2 else width
            chunks.append(line[:cut])
            line = line[cut:]
        if line:
            chunks.append(line)
    return chunks or [""]


def P(text, width: int, tone="text", indent=0):
    return [[*sp(indent), s(line, tone)] for line in wrap(text, max(4, width - indent))]


def lr(left, right, width: int) -> list[Seg]:
    rw = _width(right)
    return fit(fit(left, max(0, width - rw - (1 if rw else 0))) + (sp(1) if rw else []) + list(right), width)


def kv(key, value, width: int, label_width=12, value_tone="text", label_tone="dim"):
    label_width = max(label_width, len(str(key)) + 1)  # a label is never as wide as its own column: the value always starts after a blank cell
    if width < 36 and not isinstance(value, list) and str(key):
        return [[s(fs(str(key), width), label_tone)], *[[s("  " + line, value_tone)] for line in wrap(value, max(4, width - 2))]]  # narrow pane: the label on its own row, the value below it
    if isinstance(value, list):
        return [fit([s(fs(key, label_width), label_tone), *value], width)]
    return [[s(fs("" if i else key, label_width), label_tone), s(line, value_tone)]
            for i, line in enumerate(wrap(value, max(4, width - label_width)))]


def recorded_kv(key, text, width: int, label_width=12, tone="dim"):
    """A RECORDED free-text field: every row (not only the first) carries a left bar after the label column, so the field's boundary stays obvious and its words never read as Hlith's own."""
    lines = wrap(text, max(4, width - label_width - 2))
    return [[s(fs("" if i else key, label_width), "dim"), s("▏ ", "rule"), s(line, tone)] for i, line in enumerate(lines)]


def sec(title: str, width: int, right: str | None = None):
    if right and len(title) + len(right) + 2 > width:
        right = None  # a narrow pane keeps the section's NAME whole; its right-hand hint is the first thing to go (the footer and ? still list the keys)
    return lr([s(title, "label")], [s(right, "hint")] if right else [], width)


def hcat(columns, separator: str, height: int):
    result = []
    for i in range(height):
        row = []
        for j, (lines, width) in enumerate(columns):
            if j:
                row.append(s(separator, "rule"))
            row.extend(fit(lines[i] if i < len(lines) else [], width))
        result.append(row)
    return result


def rule_sec(title: str, width: int) -> list[Seg]:
    """Stitch horizontal section divider: '── TITLE ────────────'."""
    head = f"── {title} "
    if len(head) >= width:
        return [s(fs(head, width), "label")]
    return [s("── ", "rule"), s(title, "label"), s(" " + "─" * max(0, width - len(head)), "rule")]


def btn(label: str, active: bool, action: str, tone: str = "selected"):
    if active:
        lead_tone = "bad" if tone in {"btnBad", "chipBad"} else "bold"
        return [s("›", lead_tone, action), s(f"[ {label} ]", tone, action)]
    return [*sp(1), s(f"[ {label} ]", "dim", action)]


def lm(label: str, meta: str, width: int, active: bool, action: str, label_tone="text"):
    mw = len(meta)
    lw = max(1, width - mw - 5)
    if active:
        return [s("▌", "bold", action), s(" " + fs(label, lw) + "  " + meta + " ", "selected", action)]
    return [*sp(1), s(" " + fs(label, lw), label_tone, action), s("  " + meta + " ", "dim", action)]


def code(text: str, width: int):
    return [s(" " + fs(text, max(0, width - 2)) + " ", "code")]


def keyP(key: str, text: str, width: int):
    return [[s(fs(key if i == 0 else "", 4), "key"), *line]
            for i, line in enumerate(P(text, width - 4, "dim"))]


def _fill(lines, height):
    return list(lines) + [[] for _ in range(max(0, height - len(lines)))]


@dataclass(frozen=True)
class FocusItem:
    action: str


class Frame:
    nav: dict = {}  # {'max': highest visible focus index | None, 'offer_actions': (...)} for the host to hand back to the reducer

    def __init__(self, text_rows, style_names, bg_rows, focus_order, color="truecolor", visibility=None):
        self._text = text_rows
        self._styles = style_names
        self._bg = bg_rows
        self.focus_order = [FocusItem(a) for a in focus_order]
        self.color = color
        self._visibility = dict(visibility or {})

    def text_rows(self):
        return list(self._text)

    def style_rows(self, codes):
        out = []
        mono = self.color in {"mono", "mono_truecolor", "mono_256"}
        default = codes.get("text", "t")
        for row in self._styles:
            chars = []
            for tone in row:
                mapped = _MONO.get(tone, tone) if mono else tone
                tok = _TOKEN.get(mapped, "text")
                if tok not in codes and tok in _LEGACY_STYLE_FALLBACK:
                    tok = _LEGACY_STYLE_FALLBACK[tok]
                chars.append(codes.get(tok, default))
            out.append("".join(chars))
        return out

    def bg_rows(self):
        return list(self._bg)


def display_run_id(run_id) -> str:
    """Keep operator-copyable run identifiers verbatim."""
    return _clean(run_id) if isinstance(run_id, str) and run_id else "not recorded"


def display_schema(schema) -> str:
    """Use a short display label while preserving canonical schema identity in data."""
    return "cli-2" if schema == "urn:hlith:run-artifact:cli-2" else _clean(schema or "not recorded")


_valid_commit_id = _af.valid_commit_id


def _short_commit_id(value) -> str:
    text = str(value or "not recorded")
    return text if text == "not recorded" else text[:8]


_validation_errors = _af.validation_errors
_decision = _af.decision
_obligations = _af.obligations
_blocking_entries = _af.blocking_entries
_integrity_errors = _af.integrity_errors


def _blocking_obligation_index(artifact):
    obligations = _obligations(artifact)
    by_id = {row.get("id"): i for i, row in enumerate(obligations) if isinstance(row.get("id"), str)}
    indices = [by_id[item] for item in _blocking_entries(artifact) if item in by_id]
    if _decision(artifact)[0] == "REFUSED · REFUTED":
        for index in indices:
            if obligations[index].get("verdict") == "refuted":
                return index
    return indices[0] if indices else None


def _initial_focus_index(artifact, requested, explicit=False):
    obligations = _obligations(artifact)
    if not obligations:
        return 0
    if requested != 0 or explicit:
        return min(max(0, int(requested)), len(obligations) - 1)
    blocked = _blocking_obligation_index(artifact)
    if blocked is not None:
        return blocked
    return next((i for i, row in enumerate(obligations) if str(row.get("verdict", "")).lower() != "held"), 0)


def _headline_subject(artifact, decision, width=None):
    obligations = _obligations(artifact)
    if decision[0] == "LANDED":
        return f"all {len(obligations)} obligations"
    entries = _blocking_entries(artifact)
    if not entries:
        return "blocking obligation not recorded"
    plain = _plain_blocking(artifact)
    if plain:
        return plain[0]
    blocked = next((row for row in obligations if row.get("id") == entries[0]), None)
    if blocked and decision[0] == "REFUSED · NOT-DERIVED" and blocked.get("stop_reason"):
        location = re.search(r"[^\s:]+\.py:\d+", _clean(blocked["stop_reason"]))
        if location:
            return location.group(0)
    more = f"+{len(entries) - 1} more" if len(entries) > 1 else ""
    if width is not None:
        id_width = max(1, width - len(more) - (1 if more else 0))
        name = "".join(part.text for part in _middle_segments(entries[0], id_width, "bold")).rstrip()
        return f"{name}{' ' + more if more else ''}"
    return entries[0] + (f" {more}" if more else "")


_plain_blocking = _af.plain_blocking


def _cause_text(artifact):
    plain = _plain_blocking(artifact)
    return "; ".join(plain[1:]) if len(plain) > 1 else "not recorded in the artifact"


def _landing_target_text(artifact):
    """Describe only the landing target and commit recorded in the run receipt."""
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    target = run.get("landing_target")
    commit = artifact.get("landed_commit")
    commit_text = str(commit) if _valid_commit_id(commit) else "full landed id not recorded or invalid"
    if target == "original":
        return f"original repository · committed by engine: {commit_text}"
    if target == "rehearsal":
        return f"rehearsal clone · committed by engine: {commit_text}; original repository unchanged"
    return f"landing target cannot be determined from this receipt · {commit_text}"


def _landing_status_text(artifact):
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    target = run.get("landing_target")
    if target == "original":
        return "original repository committed by engine"
    if target == "rehearsal":
        return "rehearsal clone committed · original unchanged"
    return "landing target cannot be determined"


def _next_for_cause(artifact):
    plain = _plain_blocking(artifact)
    if not plain:
        return "See the recorded cause above."
    if plain[0] == "host-confinement-unavailable":
        return ("This host cannot establish Linux user-namespace + Landlock confinement (ABI >= 6). "
                "Check kernel/userns settings and run 'hlith doctor --probe-target'; nothing in your change needs restructuring.")
    if plain[0] == "hostile-repository-configuration":
        return "The repository tree contains an unsafe path; rename or exclude the unsafe path before checking again."
    if "EffectRejected: stage exceeds 33554432 bytes" in plain:
        return "Recovery: the staged change exceeds 32 MiB; reduce its size, then start a new check."
    return "See the recorded cause above."


# TUI behavior: plain words for the engine's construct kinds (the raw kind stays in the recorded cause; this only says what it means). Unknown kinds get no gloss (never a guess).
_CONSTRUCT_GLOSS = {
    "unresolved_method_reference": "a call through a function value Hlith cannot trace (returned, decorated, aliased or passed as an argument)",
    "unresolved_method_receiver": "a method call on an object whose type Hlith cannot determine",
    "star_args_forwarding": "arguments forwarded with * or ** whose contents Hlith cannot see",
    "decorator_varargs_forwarding": "a decorator that forwards *args/**kwargs to the function it wraps",
    "unsupported_entry_guard": "an entry condition Hlith cannot model",
    "module_level_change": "a change outside any function (module level)",
    "frame_introspection": "stack-frame inspection (sys._getframe)",
    "uncovered_region": "changed lines that fall inside no function Hlith analysed",
    "callable_unlocatable": "a changed function whose definition Hlith could not locate after the change",
}
for _k in ("dynamic_attribute", "dynamic_getattr", "dynamic_setattr"):
    _CONSTRUCT_GLOSS[_k] = "an attribute looked up or set by a computed name"


def _construct_gloss(text: str) -> str:
    """The plain-words gloss of the first known construct kind named in a recorded cause ('' when none is known)."""
    m = re.search(r"\b(" + "|".join(sorted(_CONSTRUCT_GLOSS, key=len, reverse=True)) + r")\b", str(text))
    return _CONSTRUCT_GLOSS[m.group(1)] if m else ""


_HEX64 = re.compile(r"[0-9a-f]{64}")


def _approval_candidate(artifact):
    """(delta_set_sha256, deltas) when the ENGINE says the declared behaviour deltas have no independent confirmer, else None (TUI behavior 2.1, D2).
    Mirrors operator/check.py:_follow_up: the format-2 `deltas-confirmed` obligation naming 'no independent confirmer', or the format-1 confirmation reason. The hash is the
    engine's own `effect.delta_set_sha256`; nothing here computes, accepts or types a hash."""
    if not isinstance(artifact, dict) or not artifact.get("exit_status"):  # falsy = exit 0 or none recorded: exactly `not in (0, None)`, with no outcome comparison outside frame._decision
        return None
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    sha, deltas = effect.get("delta_set_sha256"), effect.get("deltas")
    if not (isinstance(sha, str) and _HEX64.fullmatch(sha) and isinstance(deltas, list) and deltas):
        return None
    unconfirmed = any(isinstance(o, dict) and o.get("id") == "deltas-confirmed" and "no independent confirmer" in str(o.get("stop_reason") or "")
                      for o in artifact.get("obligations") or [])
    confirmation = ((artifact.get("deltas") or {}).get("confirmation") or {}) if isinstance(artifact.get("deltas"), dict) else {}
    unconfirmed = unconfirmed or "no independent confirmer" in str(confirmation.get("reason") or "")
    return (sha, deltas) if unconfirmed else None


def _delta_lines(deltas, limit=6) -> list:
    """Human-readable one-liners for the declared deltas (repository-controlled text: escaped and capped)."""
    out = []
    for d in deltas[:limit]:
        if isinstance(d, dict):
            bits = [str(d.get(k)) for k in ("path", "file", "symbol", "kind", "claim", "behavior", "description") if d.get(k)]
            text = " · ".join(bits) if bits else json.dumps(d, sort_keys=True)
        else:
            text = str(d)
        out.append(_clean(text)[:110])
    if len(deltas) > limit:
        out.append(f"... and {len(deltas) - limit} more declared deltas")
    return out


def _head_is_base(context):
    """True/False when BOTH the base this check ran on (launch meta) and the repository's current HEAD are known and (do not) match; None when either is unknown. Apply needs HEAD == base
    (the engine refuses 'HEAD moved' otherwise): a COMMIT source checks out the commit's PARENT, so unless HEAD is that parent, Apply cannot succeed and is not offered."""
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    base = str(meta.get("base_rev") or "")
    repo = (context or {}).get("repo") if isinstance((context or {}).get("repo"), dict) else {}
    head = str(repo.get("head") or "")
    if len(base) < 7 or len(head) < 7 or not re.fullmatch(r"[0-9a-f]+", base) or not re.fullmatch(r"[0-9a-f]+", head):
        return None
    n = min(len(base), len(head))
    return base[:n] == head[:n]


def _uncommitted_source(context) -> bool:
    """True when the rehearsal was a check of the operator's UNCOMMITTED work: the change already exists in their working tree, so there is nothing to apply to it (the label is the
    host's own literal for that source kind, recorded in the launch meta)."""
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    return str(meta.get("label") or "").startswith("Uncommitted work")


def _apply_candidate(artifact, context) -> bool:
    """TUI behavior 2.3 (D1): Apply is offered ONLY on a LANDED rehearsal verdict opened from the session that made it (the launch folder is known). Review distribution never offers Apply."""
    from ..product import REVIEW_ONLY
    if REVIEW_ONLY:
        return False
    if not isinstance(artifact, dict) or _decision(artifact)[0] != "LANDED" or not artifact.get("landed_commit"):  # the one outcome/exit mapping (frame._decision)
        return False
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    return run.get("landing_target") == "rehearsal" and bool(meta.get("clone")) and not _uncommitted_source(context) and _head_is_base(context) is not False


def _copy_note_key(artifact) -> list:
    """The Verdict's `c` action (operator spec 4.4): hand the refusal to the agent that produced the change. Offered only when the record has a note to hand over."""
    from . import agent_note

    return [["c", "copy for agent", "copy-note"]] if agent_note.kind(artifact) else []


def _new_check_refusal(artifact, context) -> str | None:
    """None when `n` (a NEW check of the current state of the change a refusal was about, operator spec 4.4 'Revise and resubmit') may start from this Verdict; otherwise the one
    sentence saying why not. Pure: the host re-reads everything at the key. A record never changes and `n` never lands, approves or reruns anything by itself: it only reopens the
    Claim of the CURRENT state of that source, where the usual command review, pause and fresh Enter still stand."""
    if not isinstance(artifact, dict):
        return "n: no record is open"
    headline = _decision(artifact)[0]
    if not headline.startswith("REFUSED") or headline == "REFUSED · BOUNDARY":
        return "n starts a new check after a refusal; this result has nothing to redo"
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    if not meta.get("source_repo") or not meta.get("label"):
        return "n: this record has no launch folder here; open hlith in its repository and check the change again"
    return None


def _new_check_key(artifact, context) -> list:
    return [["n", "new check", "new-check"]] if _new_check_refusal(artifact, context) is None else []


def _consequential_keys(artifact, context) -> list:
    """The keys that START the operator's next consequential step: `i` approve the declared deltas (D2) and `l` apply a LANDED rehearsal to the original (D1). They lead the footer
    (only the first 4 keys fit below 100 columns): at 80x24 the Apply key was not shown at all behind w / d."""
    return [*([["i", "approve deltas", "approve-deltas"]] if _approval_candidate(artifact) else []),
            *([["l", "apply to your repo", "apply"]] if _apply_candidate(artifact, context) else [])]


def _witness_then_actions(artifact, context) -> list:
    """The Verdict footer order (only the first 4 keys fit below 100 columns). A REFUTATION leads with its witness (`w`), then `c` copy / `n` new check. A stop reason (not-derived) or an
    unverified result has no witness to read: its next actions (`c` copy the reason, `n` a new check, operator spec 4.4) come first so they stay visible at 80 columns."""
    from . import agent_note

    witness, actions = [["w", "witness", "drill:witness"]], [*_copy_note_key(artifact), *_new_check_key(artifact, context)]
    return [*witness, *actions] if agent_note.kind(artifact) in (None, "refuted") else [*actions, *witness]


def _new_check_hint(artifact, context) -> str:
    return " Press n to check the current state of this change again as a new run; this record stays refused." if _new_check_refusal(artifact, context) is None else ""


def _copy_note_hint(artifact) -> str:
    from . import agent_note

    word = agent_note.kind(artifact)
    return {"refuted": " Press c to copy this witness for your agent.", "not-derived": " Press c to copy the stop reason for your agent.",
            "unverified": " Press c to copy this result for your agent."}.get(word, "")


def _launch_interpreter(context) -> str | None:
    """The interpreter THIS launch ran the check with, from the host's own launch record (meta argv), labelled as such: the engine artifact records none. The --target-python PATH
    when the operator chose one, else argv[0] (the engine's own interpreter). None when there is no launch record (a run opened from a file or history)."""
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    argv = meta.get("argv") if isinstance(meta.get("argv"), list) else None
    if not argv or not all(isinstance(a, str) for a in argv):
        return None
    if "--target-python" in argv and argv.index("--target-python") + 1 < len(argv):
        return _clean(argv[argv.index("--target-python") + 1]) + " · the target interpreter you chose"
    return _clean(argv[0]) + " · the engine's own interpreter"


def _rehearsed_tree(context) -> str | None:
    """The post tree the APPLY review showed for the rehearsal ("... (post tree 9a85660ae7fe)"), kept in the context of the apply run; None when this run was not an apply."""
    applying = (context or {}).get("claim_apply")
    review = applying.get("review") if isinstance(applying, dict) and isinstance(applying.get("review"), dict) else {}
    m = re.search(r"post tree ([0-9a-f]{7,64})", str(review.get("rehearsal") or ""))
    return m.group(1) if m else None


def _landed_next(artifact, context=None) -> str:
    """TUI behavior 2.2 (D1): what a LANDED verdict means for the OPERATOR'S repository, from the recorded landing_target only: a rehearsal never changed it, an original landing says so,
    and a missing record claims nothing. Paths come from the launch meta when this screen has it (a recorded run opened from history has none)."""
    base = "Nothing was refuted; there is no failure witness. Review the explored domain and provenance."
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    commit = artifact.get("landed_commit")
    short = _clean(str(commit))[:8] if _valid_commit_id(commit) else "not recorded"
    target = run.get("landing_target")
    meta = (context or {}).get("launch_meta") if isinstance((context or {}).get("launch_meta"), dict) else {}
    clone = meta.get("clone")
    where = ""
    if clone:
        folder = _clean(str(clone)).rsplit("/", 1)[0]
        where = f" Run clone: {_tilde_path(_clean(str(clone)))} · checked change: {_tilde_path(folder)}/change.patch."
    if target == "rehearsal" and _head_is_base(context) is False and not _uncommitted_source(context):
        return (f"Your repository was NOT changed. This check ran on base {_clean(str((meta or {}).get('base_rev') or ''))[:8]} and landed only in its disposable clone (rehearsal), commit {short}.{where} "
                f"Apply to the original is not offered: your repository's HEAD is not that base, and the engine applies only onto the exact base a check ran on. To use the change, check it again from your current HEAD. {base}")
    if target == "rehearsal" and _uncommitted_source(context):
        return (f"Your repository was NOT changed by this check, and for uncommitted work it does not need to be: the change you checked is already in your working tree. "
                f"It landed only in a disposable clone (rehearsal), commit {short}.{where} Apply to the original is not offered for uncommitted work (the engine requires a clean tree, and "
                f"here the change IS the tree). Commit it yourself when you accept this result. {base}")
    if target == "rehearsal":
        how = ("Press l to review applying it to your repository: Hlith shows the exact review (repository, base commit, patch hash, rehearsed tree) and writes nothing until you confirm with y. "
               if _apply_candidate(artifact, context) else
               "To put it there, open this run from the Hlith session that made it and press l, or apply the checked change yourself. ")
        return (f"Your repository was NOT changed: this check landed the change in its disposable clone only (rehearsal), commit {short}.{where} {how}{base}")
    if target == "original":
        return (f"The engine committed the checked change to your repository: commit {short}, ONE new commit on your current branch, after checking the patch again on the original. "
                f"Review it with git (git show {short}). Hlith does not offer an undo: undoing it is your own git action. {base}")
    return f"The landing target is not recorded in this receipt: do not assume your repository was changed. {base}"


def _next_for_verdict(artifact, decision, context=None):
    if decision[0] == "LANDED":
        return _landed_next(artifact, context)
    if decision[0].startswith("REFUSED") and _approval_candidate(artifact):
        return ("This result stands: no key overrides it. The change declares behaviour deltas nobody has approved. Press i to review the declared deltas and their exact set hash; "
                "Hlith then opens a Claim to start a NEW check of the same patch with that set approved. Approval authorizes the change; it is not proof.")
    if decision[0].startswith("REFUSED"):
        entries = _blocking_entries(artifact)
        blocker = entries[0] if entries else ""
        obligation_id = next((str(row.get("id")) for row in _obligations(artifact)
                              if str(row.get("id")) == blocker), blocker)
        obligation_class = obligation_id.split(":", 1)[0]
        if decision[0] == "REFUSED · REFUTED":
            if obligation_class == "feedback-pins":
                action = "A counterexample recorded by an earlier run recurs; see the witness. Revise the patch to preserve that behavior, then start a new check."
            elif obligation_class == "deltas-confirmed":
                action = ("This record carries no approvable delta set (no engine-computed delta_set_sha256 with declared deltas), and the terminal UI cannot declare one. "
                          "Declare the intended delta in the engine's own input, then start a new check. Approval authorizes the change; it is not proof.")
            elif obligation_class in {"differential", "signature_binding", "effect_confinement", "effect-confinement"}:
                action = "The witness records the difference. Revise the patch to preserve the checked behavior, then start a new check."
            else:
                action = "See the recorded cause above."
        elif _plain_blocking(artifact):
            action = _next_for_cause(artifact)
        elif decision[0] == "REFUSED · NOT-DERIVED":
            first = next((row for row in _obligations(artifact) if str(row.get("verdict", "")).lower() != "held"), {})
            if first.get("id") == "verification-failed":
                action = "A checker failed to run (not a construct in your change); read the recorded cause above and run hlith doctor --probe-target."
            else:
                action = "See the recorded cause above; restructure the unsupported construct or check the change another way."
                plain = _construct_gloss(first.get("stop_reason") or "")
                where = re.match(r"([^\s:]+):\d+", _clean(first.get("stop_reason") or ""))
                if where and re.search(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$", where.group(1)):
                    # TUI behavior (R3 rehearsal on the humanize triple): the first place Hlith could not follow is TEST code the change does not touch; telling the reader to restructure a construct would misdirect them
                    action = ("The first place Hlith could not follow is in test code (" + where.group(1) + "), not in your change: a limit of the analysis, not a problem found in "
                              "your change. Nothing was refuted. The recorded causes list every place; a change with a witness-producing check, or tests Hlith can trace, would let it decide.")
                if plain:
                    action += f" What it could not follow: {plain}."
        elif decision[0] == "REFUSED · UNVERIFIED":
            unverified = [row for row in _obligations(artifact)
                          if str(row.get("verdict", "")).lower() == "unverified"] or _obligations(artifact)
            row = unverified[0] if unverified else {}
            why = " ".join(str(row.get("stop_reason") or row.get("claim") or "see the recorded cause above").split())[:240]
            if "no repository test reaches" in why:
                symbol = _clean(str(row.get("id", "")).split(":", 1)[-1] or "this function")
                action = f"No repository test calls `{symbol}`; add one that reaches the obligation, or check the change another way. Nothing was refuted."
            elif why.startswith("adequacy:"):
                action = "The differential could not exercise every changed-code condition. Add a repository test that reaches those branches, or check another way. Nothing was refuted."
            else:
                action = "The obligation could not be confirmed; see the recorded cause above. Supply what is missing or read the check tab. Nothing was refuted."
        elif decision[0] == "REFUSED · BOUNDARY":
            action = "Read the recorded boundary cause above, resolve it, then start a new check."
        else:
            action = "See the recorded cause above."
        return "No key here can land, approve, or override this result. " + action
    return "No key here can land, approve, or override an unvalidated record. Inspect its recorded evidence before deciding what to do."


def _reason_text(artifact, decision):
    from . import feedback_view

    text = _decision_reason_text(artifact, decision)
    failed = feedback_view.failure_sentence(artifact)  # the artifact's own recorded feedback failure: said where the decision is explained, never hidden behind a clean LANDED
    return f"{text} {failed}" if failed else text


def _decision_reason_text(artifact, decision):
    if decision[0] == "LANDED":
        recorded_target = (artifact.get("run") or {}).get("landing_target") if isinstance(artifact.get("run"), dict) else None
        if recorded_target == "rehearsal":
            return "Every required obligation held. LANDED in the rehearsal clone; your original repository is unchanged."
        if recorded_target == "original":
            return "Every required obligation held. LANDED in your original repository."
        return "Every required obligation held; the engine landed the checked change; its landing target is not recorded."  # never a 'recorded target' the receipt does not hold
    if decision[0] == "REFUSED · BOUNDARY" and _plain_blocking(artifact):
        return "Hlith stopped before verification."
    blocking_index = _blocking_obligation_index(artifact)
    obligations = _obligations(artifact)
    row = obligations[blocking_index] if blocking_index is not None else next(
        (item for item in obligations if str(item.get("verdict", "")).lower() != "held"), {})
    if row:
        witness = row.get("witness")
        parsed = _parse_witness(witness) if witness else None
        if parsed:
            source, input_text, before, after = parsed
            before = re.sub(r"^return\s+", "", before)
            after = re.sub(r"^return\s+", "", after)
            if len(before) > 40 or len(after) > 40 or any(ch in before + after for ch in "'\"`«»“”‘’"):
                # a recorded value that could close or imitate its own delimiter (or is long) is never interpolated into Hlith's prose: the structured witness rows hold it, escaped
                return "The recorded value changed: see WITNESS."
            if source == "pinned":
                function = input_text.split("(", 1)[0].rsplit(".", 1)[-1]
                return f"A pinned earlier result changed: {function} returned '{before}' before and '{after}' after."
            if source == "pinned-neighbor":
                function = input_text.split("(", 1)[0].rsplit(".", 1)[-1]
                return f"A boundary neighbor of a stored input changed: {function} returned '{before}' before and '{after}' after."
            if len(input_text) > 40 or any(ch in input_text for ch in "'\"`«»“”‘’"):
                # the call text is agent-influenced (derived from literals in the agent's own code): only the function NAME is put in Hlith's prose, the full input stays in the escaped witness rows
                function = input_text.split("(", 1)[0].strip()
                if not re.fullmatch(r"[A-Za-z_][\w.]{0,39}", function):
                    return "The recorded value changed: see WITNESS."
                return f"{function} returned '{before}' before the change and '{after}' after it."
            return f"{input_text} returned '{before}' before the change and '{after}' after it."
        stop = row.get("stop_reason")
        if stop:
            clean_stop = _clean(stop)
            location = re.match(r"([^\s:]+:\d+)\s+([^:]+):\s*(.*)", clean_stop)
            if decision[0] == "REFUSED · NOT-DERIVED" and location:
                detail = f"{location.group(1)} ({location.group(2).strip()}){(' · ' + location.group(3).strip()) if location.group(3) else ''}"
                others = sum(1 for item in obligations if str(item.get("verdict", "")).lower() != "held") - 1
                if others > 0:  # TUI behavior: a real run can stop at dozens of places (funcy: 128): the COUNT comes first, then the first place
                    lead = f"{others + 1} places could not be analysed, so nothing was checked there. First: {detail}."
                else:
                    lead = f"Hlith could not derive an obligation for {detail}; nothing was checked there."
                return lead
            if decision[0] == "REFUSED · UNVERIFIED" and "adequacy" in clean_stop.lower():
                return "The check ran, but its generated inputs never exercised parts of the changed code, so Hlith will not call the change safe. Nothing was refuted. Recorded detail: " + clean_stop
            return clean_stop
        if witness:
            return _clean(witness)
        if str(row.get("verdict", "")).lower() == "held" and row.get("claim"):
            return _clean(row["claim"])
        if row.get("verdict"):
            return f"{_clean(row['verdict']).upper()}; see the recorded witness."
    plain = _plain_blocking(artifact)
    if plain:
        cause = plain[1] if len(plain) > 1 else plain[0]
        return f"Hlith stopped before verification: {_clean(cause)}."
    return "not recorded in the artifact"


_parse_witness = _af.parse_witness


def _r_help(vs, context) -> str:
    """What `r` does on THIS screen, from the host's actual handlers: re-check (blocked boundary), open the record again (artifact unavailable), resume (interrupted run)."""
    if vs.st == "blocked" and (context.get("blocked") or {}).get("kind") == "boundary":
        return "re-check readiness (this screen)"
    if vs.st == "artifact-unavailable":
        return "open the record again (this screen)"
    if vs.st in {"run-ended-no-decision", "run-lost"} and context.get("resume_offer"):
        return "resume interrupted check (review first)"
    return "not used on this screen"


_PY_SUFFIXES = (".py", ".pyi", ".pyw")
_SENTINEL_CHANGE_FILES = frozenset({
    "not recorded",
    "no files recorded",
    "path not recorded",
    "change details not recorded",
})


def _no_python(change) -> bool:
    """True when a recorded change names files and NONE is Python (.py/.pyi/.pyw): Hlith derives no obligation from it. An unknown file list is NOT 'no python'."""
    if not isinstance(change, dict):
        return False
    names = [str(r[0]) for r in (change.get("files") or []) if isinstance(r, (tuple, list)) and r]
    if not names and change.get("file") and not change.get("files"):
        cand = str(change["file"]).strip()
        if cand and cand.lower() not in _SENTINEL_CHANGE_FILES:
            names = [cand]
    return bool(names) and not any(n.lower().endswith(_PY_SUFFIXES) for n in names)


_NOPY_TEXT = "NO PYTHON FILE IN THIS CHANGE \u2014 Hlith derives no obligation from it"
_NOPY_NOTE = "A check refuses it as NOT DERIVED (exit 11): V1 models Python only. That is not a safety claim."


def _nopy_rows(change: dict, width: int) -> list:
    """The explicit unknown for a change with no Python file (TUI behavior): said once, plainly, and never as 'harmless'."""
    return [[], *P(_NOPY_TEXT, width, "warn"), *P(_NOPY_NOTE, width, "dim")]


def _nopy_summary(change: dict, width: int) -> list:
    """ONE compact line instead of the raw text of a non-Python file (a generated log must not flood the review)."""
    names = [str(r[0]) for r in (change.get("files") or []) if isinstance(r, (tuple, list)) and r] or [str(change.get("file") or "")]
    kinds = sorted({(Path_suffix(n) or "no extension") for n in names})
    bits = [f"{len(names)} file{'s' if len(names) != 1 else ''}", "+" + str(change.get("added", 0)) + " lines", ", ".join(kinds[:3])]
    tail = " \u00b7 content not shown \u00b7 d full diff"
    line = " \u00b7 ".join(bits) + tail
    if isinstance(change.get("bytes"), int) and len(" \u00b7 ".join([*bits, _fmt_bytes(change["bytes"])]) + tail) <= width:
        line = " \u00b7 ".join([*bits, _fmt_bytes(change["bytes"])]) + tail  # the size goes first when the width is short: the two phrases that matter stay whole
    return [[s(fs(line, width), "dim")]]


def Path_suffix(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[-1].lower()) if "." in base.strip(".") else ""


def _hunks(n) -> str:
    return f"{n} hunk" + ("" if n == 1 else "s")


def _mid_ellipsis(text: str, width: int) -> str:
    """Shorten the MIDDLE of a path (keeping its head and its last components, e.g. '/bin/python'), never wrap it mid-component."""
    text = str(text)
    if len(text) <= width or width < 6:
        return text if len(text) <= width else text[:max(1, width - 1)] + "…"
    tail = max(4, (width - 1) * 2 // 3)
    head = width - 1 - tail
    return text[:head] + "…" + text[-tail:]


def _tilde_path(value) -> str:
    """Display form of a path: $HOME shortened to ~ (display only)."""
    text = str(value or "path not recorded")
    home = str(Path.home())
    return "~" + text[len(home):] if home != "/" and (text == home or text.startswith(home + "/")) else text


def _fmt_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "size not recorded"
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KiB" if n < 1024 * 1024 else f"{n / (1024 * 1024):.1f} MiB"


GUTTER = 2  # one grammar: every screen keeps two blank cells on both sides; nothing touches the viewport edges


def _split_geometry(cols: int, rows: int, kind: str):
    """(divider, left text width, right text width, pane height) inside the gutters (content width = cols - 2*GUTTER, panes joined by ' | ').
    'rail' (Selection): a narrow source rail, 24 cells at 100 columns growing to 30; the rest is the review canvas.
    'inspector' (every other review screen): a deliberately subordinate right pane, about 30% of the content (29 cells at 100, 44 at 160)."""
    content = max(20, cols - 2 * GUTTER)
    if kind == "rail":
        lw = max(26, min(36, int(cols * 0.23))) if cols >= 100 else max(22, min(30, round(content * 0.25)))  # B (hlith_b_motion.py): source rail max(26, min(36, int(cols * .23)))
        rw = max(1, content - lw - 3)
    elif kind == "drill":  # an open evidence page is the focus: the inspector widens to ~40% (38 cells at 100) so identifiers and timestamps stay whole
        rw = max(36, min(52, round(content * 0.40)))
        lw = max(1, content - rw - 3)
        return lw, lw, rw, max(3, rows - 5)
    else:
        rw = (46 if cols >= 150 else 40 if cols >= 120 else 34) if cols >= 100 else max(26, min(44, round(content * 0.30)))  # B: inspector 46 / 40 / 34 at >=150 / >=120 / >=100
        lw = max(1, content - rw - 3)
    return lw, lw, rw, max(3, rows - 5)


def _pane_rows(left, right, div, lw, rw, height):
    """Merge two panes into content rows: '<left padded to lw> | <right padded to rw>'. The divider spans only the rows that carry content (it never runs on into empty space)."""
    out = []
    for y in range(min(height, max(len(left), len(right)))):
        l = fit(left[y] if y < len(left) else [], lw)
        r = fit(right[y] if y < len(right) else [], rw)
        out.append([*l, s(" │ ", "rule"), *r])
    return out


def _patch_stats(artifact: dict):
    """(added, removed, hunks) counted from the RECORDED patch with the hunk header's own line counts; None when the artifact records no patch (never zeros that look measured)."""
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    patch = str(effect.get("unified_diff") or "")
    if not patch.strip():
        return None
    added = removed = hunks = 0
    rem_old = rem_new = 0
    for line in patch.split("\n"):
        if rem_old > 0 or rem_new > 0:
            if line.startswith("+") and rem_new > 0:
                added += 1; rem_new -= 1; continue
            if line.startswith("-") and rem_old > 0:
                removed += 1; rem_old -= 1; continue
            if line.startswith(" ") and rem_old > 0 and rem_new > 0:
                rem_old -= 1; rem_new -= 1; continue
            if line.startswith("\\"):
                continue
            rem_old = rem_new = 0
        m = re.match(r"@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@", line)
        if m:
            hunks += 1
            rem_old = int(m.group(1)) if m.group(1) is not None else 1
            rem_new = int(m.group(2)) if m.group(2) is not None else 1
    return added, removed, hunks


def engine_suffix_probe(engine_id: str) -> str:
    return " · " + engine_id


def _absent(width) -> str:
    """The honest absent-value sentence, in its short whole form in a narrow inspector slot (the page already says whose record it is): never a cut phrase."""
    return "not recorded" if width < 44 else "not recorded in the artifact"


def _sample_badge(context):
    """'SAMPLE' only for a context that IS marked sample data; real artifact context is truthy too, and real data must never wear the badge."""
    return "SAMPLE" if isinstance(context, dict) and str(context.get("sample", "")).startswith("SAMPLE-ONLY") else None


def _sample(context, sample: bool):
    if not isinstance(context, dict):
        return {}
    marked_sample = str(context.get("sample", "")).startswith("SAMPLE-ONLY")
    if marked_sample:
        return context if sample else {}
    return {} if sample else context


def _kind_for(decision: str) -> tuple[str, str]:
    """Kind beneath a decision already validated by labels.decision."""
    if decision == "LANDED":
        return "HELD", "ok"
    kind = decision.removeprefix("REFUSED · ")
    if kind in ("REFUTED", "NOT-DERIVED", "UNVERIFIED", "BOUNDARY"):
        return kind, "bad" if kind == "REFUTED" else "warn"
    return "UNVALIDATED", "warn"


def _decision_view(artifact: dict, decision=None) -> tuple[str, str, str, str]:
    """One presentation projection from the recorded outcome/status pair.

    The refusal kind may decorate a consistent refusal. It cannot create a
    decision when the canonical labels projection says the pair is unknown.
    """
    headline, tone, status = decision if decision is not None else _decision(artifact)
    if headline == "LANDED":
        return "LANDED", "chipOk", "HELD", "ok"
    if headline.startswith("REFUSED"):
        kindword, kindtone = _kind_for(headline)
        chip = {"bad": "chipBad", "warn": "chipWarn", "good": "chipOk"}.get(tone, "chip")
        return "REFUSED", chip, kindword, kindtone
    return "UNKNOWN / UNVALIDATED RECORD", "chip", "UNVALIDATED", "dim"


def _run_id(artifact: dict, sample: bool = False, context=None, decision=None) -> str:
    run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
    proposer = (artifact.get("effect") or {}).get("proposer_id") if isinstance(artifact.get("effect"), dict) else None
    if not sample and isinstance(proposer, str) and proposer.startswith("SAMPLE-ONLY"):
        return "not recorded"
    if sample and context:
        key, _vctx, _status = _verdict_context(artifact, context, decision)
        displayed = context.get("verdicts", {}).get(key, {}).get("display_run")
        if isinstance(displayed, str) and displayed:
            return _clean(displayed)
    run_id = run.get("run_id")
    return _clean(run_id) if isinstance(run_id, str) and run_id else "not recorded"


def _changed_callables(artifact: dict) -> list:
    """[(file, function)] the recorded diff changes, read from the diff text alone (NOT the engine's account): a +/- line belongs to the nearest `def` above it in the hunk (a def row that is
    visible as context, added or removed), else to the function the hunk header names. Order of first appearance, unique, bounded. Used for the Claim's EXPECTED line only."""
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    text = str(effect.get("unified_diff") or "")[: 256 * 1024]
    out: list = []
    path = ""
    current = None
    in_hunk = False
    for line in text.split("\n"):
        if line.startswith("diff --git a/"):
            path = line[len("diff --git a/"):].partition(" b/")[2]
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            m = re.search(r"@@ .*? @@\s*(?:async\s+)?def\s+(\w+)", line)
            current = m.group(1) if m else None
            continue
        if not in_hunk or not line or line[0] not in " +-":
            continue
        body = line[1:]
        m = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", body)
        if m:
            current = m.group(1)
        if line[0] in "+-" and current and (path, current) not in out and len(out) < 24:
            out.append((_clean(path), _clean(current)))
    return out


def _expected_lines(artifact: dict, width: int) -> list:
    """The Claim's EXPECTED block: what the run will probably have to prove, named EXPECTED, NOT DERIVED (the engine derives the real set when it runs)."""
    names = _changed_callables(artifact)
    if not names:
        return []
    shown = ", ".join(f"{fn} ({path})" for path, fn in names[:2]) + (f" +{len(names) - 2} more" if len(names) > 2 else "")
    return [lr([s("EXPECTED", "label"), s("  not derived yet · an expected shape, not a result", "warn")], [], width),
            *P(f"{shown} → binding, behaviour, effects. The real set is derived when the run starts, without consulting the agent.", width, "dim")]


def _focus_anchor(artifact: dict, index):
    """The source row the FOCUSED obligation points at (B: the code next to the evidence it is about). A refuted row with a parsed witness anchors exactly like the witness page does
    ('◂ <input>: <before> → <after>'). Any other row (held, unverified, ...) anchors by its recorded `target_symbol` ONLY, labelled with what the row says ('◂ HELD · binding'): the engine
    records no line number, so the annotation sits on the function's own row (or its single added line, see _diff_lines) and nothing else is claimed. No locatable function: None."""
    rows = _obligations(artifact)
    if not isinstance(index, int) or not 0 <= index < len(rows):
        return _witness_anchor(artifact)
    row = rows[index]
    if str(row.get("verdict", "")).lower() == "refuted" and row.get("witness"):
        return _witness_anchor(artifact, row)
    symbol = row.get("target_symbol")
    if not isinstance(symbol, str) or "." not in symbol or not re.fullmatch(r"[A-Za-z_][\w.]*", symbol):
        return None
    qualifier, _dot, function = symbol.rpartition(".")
    kind = {"signature_binding": "binding", "differential": "behaviour", "differential_contract": "behaviour", "effect_confinement": "effects"}.get(str(row.get("id", "")).partition(":")[0], "")
    verdict_low = str(row.get("verdict", "")).lower()
    verdict = verdict_low.upper()
    anchor_tone = "ok" if verdict_low == "held" else "bad" if verdict_low in {"refuted", "refused"} else "warn"
    return function, "◂ " + " · ".join(x for x in (verdict, kind) if x), qualifier, anchor_tone


def _witness_anchor(artifact: dict, only_row=None):
    """B's line-anchored witness, kept truthful: the REFUTED obligation's parsed witness names a MODULE-QUALIFIED function; only inside the file that module names, and only when
    exactly one row there names the function, that row is annotated '◂ <input>: <before> → <after>'. No match, no parse or no refuted witness: no annotation (the witness page still holds it)."""
    for row in ([only_row] if only_row is not None else _obligations(artifact)):
        if str(row.get("verdict", "")).lower() != "refuted" or not row.get("witness"):
            continue
        parsed = _parse_witness(row.get("witness"))
        if not parsed:
            continue
        _source, input_text, before, after = parsed
        dotted = input_text.split("(", 1)[0]
        function = dotted.rsplit(".", 1)[-1]
        qualifier = dotted.rpartition(".")[0]  # 'pkg.mod' of 'pkg.mod.add': the module that must own the annotated hunk
        arg = input_text[input_text.find("(") + 1:input_text.rfind(")")] if "(" in input_text else input_text
        before = re.sub(r"^return\s+", "", before)
        after = re.sub(r"^return\s+", "", after)
        if any(len(v) > 40 for v in (arg, before, after)) or any(ch in arg + before + after for ch in "'\"`«»“”‘’"):
            return function, "◂ see witness", qualifier, "bad"  # agent-influenced text (the call's literals, the patched code's repr) never fills the annotation slot raw
        return function, f"◂ {arg}: {before} → {after}", qualifier, "bad"
    return None


def _preview_limit(artifact: dict, rows: int, used: int) -> int:
    """How many diff rows the Selection preview shows. A short diff is shown whole (as the reference does); a LARGE one (a 288-line log, a generated file) is bounded to
    what is left of the viewport under the list (one row kept for the note) and says so ('… N more lines · d full diff'), so the review screen is never a PgDn wall of one file."""
    if rows < 30:
        return 3
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    lines = str(effect.get("unified_diff") or "").count("\n")
    return 0 if lines <= 60 else max(3, (rows - 4) - used - 1)


def _diff_lines(artifact: dict, width: int, *, head=False, limit=0, ann=None, annw=0, anchor=None, only_file=None, excluded=(), hide_excluded=False):
    effect = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
    patch = effect.get("unified_diff")
    patch_text = str(patch or "")
    shown_cap = 256 * 1024  # display cap: a multi-megabyte patch must not stall the page; the cut is labelled, never silent
    capped = len(patch_text.encode("utf-8", "replace")) > shown_cap
    if capped:
        total_bytes = len(patch_text.encode("utf-8", "replace"))
        patch_text = patch_text.encode("utf-8", "replace")[:shown_cap].decode("utf-8", "ignore")
    raw = [_clean(line) for line in patch_text.split("\n")]  # split on \n ONLY: U+2028, CR, VT, FF, NEL, FS stay inside their line and are shown escaped, never a break that hides text
    # a MULTI-FILE patch is walked in order: each file's header rows ('F', shown when head) then its hunks; a hunk's own line counts decide what is body, so a second
    # file's '--- a/x' / '+++ b/x' lines can never be mistaken for a removed / added line of the first file
    data = []
    file_of: list[str] = []  # the b/ path each data row belongs to (anchoring must stay inside the module the witness names)
    cur_file = ""
    old_line = new_line = 0
    rem_old = rem_new = 0
    for line in raw:
        if len(file_of) < len(data):
            file_of.extend([cur_file] * (len(data) - len(file_of)))
        if line.startswith("diff --git a/"):  # never body text (body lines start with + - space or backslash), so this is always a file boundary
            _a, _sep, _b = line[len("diff --git a/"):].partition(" b/")
            cur_file = _b or _a
        if rem_old > 0 or rem_new > 0:
            if line.startswith("\\"):
                data.append(("n", line, 0))
                continue
            if line.startswith("+") and rem_new > 0:
                data.append(("+", line[1:], new_line)); new_line += 1; rem_new -= 1
                continue
            if line.startswith("-") and rem_old > 0:
                data.append(("-", line[1:], old_line)); old_line += 1; rem_old -= 1
                continue
            if line.startswith(" ") and rem_old > 0 and rem_new > 0:
                data.append((" ", line[1:], new_line)); old_line += 1; new_line += 1; rem_old -= 1; rem_new -= 1
                continue
            rem_old = rem_new = 0  # the body ended early (a truncated or hostile patch): fall through and read this line as structure
        if line.startswith("@@"):
            m = re.match(r"@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@", line)
            if m:
                old_line, new_line = int(m.group(1)), int(m.group(3))
                rem_old = int(m.group(2)) if m.group(2) is not None else 1
                rem_new = int(m.group(4)) if m.group(4) is not None else 1
            else:
                rem_old = rem_new = 10 ** 9  # unreadable header: read body lines until the next structural line
                old_line = new_line = 0
            data.append(("h", line, 0))
        elif line.startswith(("diff --git ", "index ", "--- ", "+++ ", "new file mode", "deleted file mode", "similarity index", "rename from", "rename to",
                              "old mode", "new mode", "Binary files", "GIT binary patch")):
            if head:  # structure is recognised either way; the git header rows are only SHOWN when asked for
                data.append(("F", line + (_excluded_tag(len(line), width) if excluded and line.startswith("diff --git ") and cur_file in excluded else ""), 0))
        elif line[:1] in ("+", "-", " ") and line.strip() and data:
            data.append(("n", "outside any hunk: " + line, 0))  # never dropped silently: a change-looking line the hunk counts do not cover is shown, labelled
    if len(file_of) < len(data):
        file_of.extend([cur_file] * (len(data) - len(file_of)))
    if hide_excluded and excluded:
        # reviewed bytes = launched bytes: an excluded file's header and lines are NOT shown from the Claim; one dim row names it and counts what is hidden
        out_data, out_files, placed = [], [], set()
        for i, row in enumerate(data):
            owner = file_of[i] if i < len(file_of) else ""
            if owner in excluded:
                if owner not in placed:
                    placed.add(owner)
                    hunks = sum(1 for j, r in enumerate(data) if r[0] == "h" and (file_of[j] if j < len(file_of) else "") == owner)
                    out_data.append(("X", f"{owner}  " + (f"[excluded: not in the claim · {hunks} hunk{'s' if hunks != 1 else ''} hidden]" if len(owner) + 52 <= width else "[excluded]"), 0))
                    out_files.append(owner)
                continue
            out_data.append(row); out_files.append(owner)
        data, file_of = out_data, out_files
    if only_file is not None:  # one file's section of a multi-file patch (the file list of the Selection)
        keep = [i for i in range(len(data)) if file_of[i] == only_file]
        data = [data[i] for i in keep]
        file_of = [file_of[i] for i in keep]
    if not data and patch:
        data = [(" ", line, i + 1) for i, line in enumerate(raw)]
        file_of = [""] * len(data)
    if only_file is None and not head and len({file_of[i] for i, d in enumerate(data) if d[0] == "h"}) > 1:
        # a bounded preview of a MULTI-FILE patch names each file before its first hunk (otherwise one file's lines read as part of the previous one)
        seen_files: set[str] = set()
        spliced, spliced_files = [], []
        for i, row in enumerate(data):
            if row[0] == "h" and file_of[i] not in seen_files:
                seen_files.add(file_of[i])
                spliced.append(("P", (file_of[i] or "(file not named)") + (_excluded_tag(len(file_of[i] or "(file not named)") + 6, width) if file_of[i] in excluded else ""), 0)); spliced_files.append(file_of[i])
            spliced.append(row); spliced_files.append(file_of[i])
        data, file_of = spliced, spliced_files
    if anchor and not ann:
        if len(anchor) == 4:
            function, label, qualifier, anchor_tone = anchor
        else:
            function, label, qualifier = anchor
            anchor_tone = "bad"

        def owns(path: str) -> bool:
            if not qualifier:
                return False  # an unqualified name cannot be tied to one file: no annotation
            stem = qualifier.replace(".", "/")
            return path == stem + ".py" or path.endswith("/" + stem + ".py") or path == stem + "/__init__.py" or path.endswith("/" + stem + "/__init__.py")

        named = re.compile(r"(?<![\w.])" + re.escape(function) + r"\s*\(")
        defline = re.compile(r"\s*(?:async\s+)?def\s+" + re.escape(function) + r"\s*\(")
        found = [i for i, (tag, text, _no) in enumerate(data)
                 if owns(file_of[i] if i < len(file_of) else "")
                 and ((tag == "h" and named.search(text.partition("@@")[2].partition("@@")[2])) or (tag in {" ", "+", "-"} and defline.match(text)))]
        hit = found[0] if len(found) == 1 else None  # several rows name it: ambiguous, so no annotation (the Witness page still holds the text)
        if hit is not None:
            # a witness is about the FUNCTION. If exactly one line of its body (until the next def / hunk) was added, the annotation sits on that line; otherwise it stays on the
            # function's own row and says so, never pointing at an unchanged line as if it were the cause
            body_added = []
            for j in range(hit + 1, len(data)):
                tag_j, text_j, _n = data[j]
                if tag_j in {"h", "P", "F"} or (tag_j in {" ", "+", "-"} and defline.match(text_j)):
                    break
                if tag_j == "+":
                    body_added.append(j)
            if len(body_added) == 1:
                hit = body_added[0]
            else:
                label = label + " · function"
            annw = min(_width([s(label)]) + 1, max(12, width // 3))
            ann = {hit: (label, anchor_tone)}
    if limit and len(data) - limit <= 1:
        limit = 0  # replacing a single hidden row with a 1-row note saves nothing: show it
    total_rows = len(data)
    if limit and total_rows > limit:
        hit_idx = next(iter(ann), None) if ann else None
        if hit_idx is not None and hit_idx >= limit:
            start = max(0, min(hit_idx - (limit // 2), total_rows - limit))
            chosen = list(range(start, start + limit))
        elif hit_idx is None and not any(data[k][0] in "+-" for k in range(limit)):
            first_chg = next((k for k, row in enumerate(data) if row[0] in "+-"), None)
            if first_chg is not None:
                start = max(0, min(first_chg - (1 if limit >= 3 else 0), total_rows - limit))
                chosen = list(range(start, start + limit))
            else:
                chosen = list(range(limit))
        else:
            while limit > 1 and limit <= len(data) and data[limit - 1][0] == "P":
                limit -= 1  # never strand a file header as the last preview row before '… more lines'
            chosen = list(range(limit))
        data = [data[k] for k in chosen]
        if ann:
            ann = {new_i: ann[old_i] for new_i, old_i in enumerate(chosen) if old_i in ann}
    omitted = max(0, total_rows - len(data)) if limit else 0
    out = []
    for i, (tag, text, no) in enumerate(data):
        if tag == "F":
            if text.startswith("diff --git a/") and len(text) > width:
                a_part, _sep, b_part = text[len("diff --git a/"):].partition(" b/")
                room = max(8, (width - len("diff --git a/ b/")) // 2)
                text = f"diff --git a/{_mid_ellipsis(a_part, room)} b/{_mid_ellipsis(b_part, room)}"
            line = [s(fs(text, width), "dim")]
        elif tag == "X":
            line = [s("      "), s(fs(text, max(1, width - 6)), "dim")]
        elif tag == "P":
            line = [s("      "), s(fs(text, max(1, width - 6)), "dim")]
        elif tag == "n":
            line = [s("      "), s(text, "hint")]
        elif tag == "h":
            line = [s("      "), s(text, "hunk")]
        else:  # a removed line carries its '-' (a deletion must never look like context, in mono above all)
            add_tone = "addBg" if tag == "+" else "del" if tag == "-" else "text"
            mark_tone = "addBg" if tag == "+" else "del" if tag == "-" else "dim"
            line = [s(fs(str(no) if no else "", 4), "addBg" if tag == "+" else "hint"),
                    s(tag if tag in "+-" else " ", mark_tone),
                    s(" ", "addBg" if tag == "+" else "text"),
                    *_code_spans(text, add_tone, tag)]
        avail = max(0, width - (annw if ann and i in ann else 0))
        if ann and i in ann and ann[i][1] == "bad":
            # Stitch witness-blamed line highlight: full red container across the offending diff row + witness tag
            plain_left = "".join(g.text for g in fit(line, avail))
            label, _tone = ann[i]
            plain_right = "".join(g.text for g in fit([s(label, "delHi")], annw))
            line = [s(plain_left, "delHi"), s(plain_right, "delHi")]
        else:
            line = fit(line, avail)
            if tag == "+":
                # extend subtle emerald container across the diff row in Stitch palettes
                line = [Seg(g.text, "addBg" if g.tone == "text" and not g.text.strip() else g.tone, g.action, g.panel) for g in line]
            if ann and i in ann:
                label, tone = ann[i]
                ann_tone = "addBg" if (tag == "+" and tone == "ok") else tone
                line.extend(fit([s(label, ann_tone)], annw))
        out.append(line)
    if omitted:
        out.append([s(f"      … {omitted} more lines · d full diff", "hint")])
    if capped:
        out.append([s(fs(f"      showing the first {shown_cap // 1024} KB of {total_bytes} bytes · the patch hash covers all of it", width), "warn")])
    return out


def _readiness(context, width, label_width=12):
    readiness = context.get("readiness", {})
    boundary = readiness.get("boundary", {})
    python = readiness.get("python", {})
    if isinstance(boundary, dict):
        bstatus, btone = boundary.get("status", "not recorded"), boundary.get("tone", "dim")
        bdetail = boundary.get("detail", "not recorded")
    else:  # tolerate the initial agreed fixture spelling while peers finish their update
        bstatus, btone, bdetail = "ready", "ok", str(boundary).removeprefix("ready · ")
    if isinstance(python, dict):
        pstatus, ptone = python.get("status", "not recorded"), python.get("tone", "dim")
        version = python.get("version", "not recorded")
        version_text = f"version {version}" if version == "not probed" else str(version)
        source = str(python.get("source", "not recorded"))
        tail = f"{version_text} · from {source}"
        path_budget = max(8, width - label_width - len(pstatus) - len(tail) - 4)
        path = _middle_path(str(python.get("path", "not recorded")), path_budget)
        pdetail = f"{path} {tail}"
    else:
        pstatus, ptone, pdetail = "ready", "ok", str(python).removeprefix("ready · ")
    return [*kv("boundary", [s(bstatus, btone), s(" · " + bdetail, "dim")], width, label_width),
            *kv("python", [s(pstatus, ptone), s(" · " + pdetail, "dim")], width, label_width)]


def _middle_path(path: str, limit: int) -> str:
    if len(path) <= limit:
        return path
    parts = path.rstrip("/").split("/")
    prefix = "~/" if path.startswith("~/") else "/" if path.startswith("/") else ""
    for count in range(min(3, len(parts)), 0, -1):
        candidate = prefix + "…/" + "/".join(parts[-count:])
        if len(candidate) <= limit:
            return candidate
    return "…/" + parts[-1][-max(1, limit - 2):]


def _readiness_b(context, width):
    """B's READINESS rows: status first ('ready  boundary · detail', 'ready  python 3.12.7' then 'from --target-python')."""
    rd = context.get("readiness", {}) if isinstance(context.get("readiness"), dict) else {}
    rows = []
    for name in ("boundary", "python"):
        row = rd.get(name)
        if isinstance(row, dict):
            status, tone = str(row.get("status", "not recorded")), row.get("tone", "dim")
            if name == "boundary":
                text = f"boundary · {row.get('detail', 'not recorded')}"
                extra = None
            else:
                ver = str(row.get("version", "")).strip()
                text = "python " + _mid_ellipsis(_tilde_path(row.get("path")), max(8, width - 8 - 7)) + (f" {ver}" if ver and ver != "not probed" else "")
                extra = f"from {row.get('source', 'not recorded')}"
        else:
            status, tone, text, extra = (("ready", "ok", f"{name} · {str(row).removeprefix('ready · ')}", None) if row else ("not checked", "dim", f"{name} · not recorded", None))
        lines = P(text, max(4, width - 8), "dim")
        rows.append([s(fs(status, 8), tone), *lines[0]])
        rows.extend([[s("        "), *ln] for ln in lines[1:]])
        if extra:
            rows.append([s("        "), s(fs(extra, width - 8), "dim")])
    return rows


def _readiness_label(context):
    readiness = context.get("readiness", {})
    values = [readiness.get(name, {}) for name in ("boundary", "python")]
    statuses = [value.get("status") if isinstance(value, dict) else None for value in values]
    if any(status in (None, "not recorded", "not checked") for status in statuses):
        return "not checked"
    if statuses[1] == "executable":
        return "boundary ready" if statuses[0] == "ready" else "unavailable"
    return "ready" if all(status == "ready" for status in statuses) else "unavailable"


def _disposable(width, label_width=12, *, sample=True, branch="trial"):
    label_width = 13
    clone = ("a fresh clone in the run state directory" if sample
             else "a fresh clone in this run's folder under the Hlith state directory; it is kept with the record")
    return [*kv("writes", clone, width, label_width),
            *kv("never writes", "your repository, your branch, your index", width, label_width),
            *kv("network", "none inside the boundary", width, label_width),
            *kv("afterwards", (f"If every obligation holds, the engine commits the checked patch to {branch}. If any does not, nothing in your repository changes." if sample else
                               "If every obligation holds, the engine lands the checked patch in this run's clone (a rehearsal landing). Your repository is not changed either way."), width, label_width)]


_ROLE = {"signature_binding": "binding", "differential_contract": "behaviour", "effect_confinement": "effects"}


def _whole_words(text: str, width: int) -> str:
    """Cut at a word boundary (never mid-word); '…' only when something was dropped."""
    text = str(text)
    if len(text) <= width:
        return text
    cut = text[:max(0, width - 1)].rsplit(" ", 1)[0].rstrip(" ·,;:")
    return (cut or text[:max(0, width - 1)]) + "…"


def _expected(context, width):
    """The expected obligation kinds as three columns: role, kind, 'short reason · checker' (the reason is cut at a word, never mid-word)."""
    result = []
    for kind, claim, checker in context.get("expect") or []:
        role = _ROLE.get(str(kind).split(":", 1)[0], "")
        tail_width = max(8, width - 11 - 23)
        reason = _whole_words(str(claim), max(4, tail_width - len(str(checker)) - 3))
        result.append(fit([s(fs(role, 11), "text"), s(fs(str(kind), 23), "text"), s(reason, "dim"), s(" · " + str(checker), "hint")], width))
    return result


def _phase_rows(elapsed, width, context):
    run = context.get("running", {})
    phases = run.get("phases")
    if isinstance(phases, list) and phases and isinstance(phases[0], dict):
        rows = []
        for phase in phases:
            state = "done" if phase.get("state") == "done" else "running"
            secs_ = max(0.0, float(phase.get('seconds') or 0))
            stamp = "<1s" if secs_ < 1 else f"{int(secs_)}s"  # a real sub-second phase reads '<1s', never a '0s' that looks like nothing happened
            rows.append(fit([s("✓ " if state == "done" else "› ", "dim" if state == "done" else "bold"),
                             s(fs(phase.get("name", "phase"), 12), "bold" if state == "running" else "text"),
                             s(fs(state, 9), "bold" if state == "running" else "dim"), s(fs(stamp, 5), "dim"),
                             s(phase.get("detail", ""), "dim")], width))
        return rows
    if not context.get("sample"):
        unavailable = str(run.get("unavailable") or "")
        if context.get("run_state") == "running" and not run.get("phases"):
            message = ("running · no events yet" if not unavailable or "not available yet" in unavailable
                       or "no engine events are recorded yet" in unavailable else "running · event stream unavailable")
        else:
            message = "phase events not recorded"
        return [fit([s("  "), s(message, "dim")], width)]
    phases = phases or [["runtime", 0, 6, f"effect {run.get('effect_id', 'not recorded')} proposed"],
                                   ["effect", 6, 10, run.get("account", "not recorded")],
                                   ["obligation", 10, 38, f"{run.get('derived', 0)} derived"], ["gate", 38, 39, ""], ["feedback", 39, 40, ""]]
    out = []
    for name, start, end, desc in phases:
        state = "done" if elapsed >= end else "running" if elapsed >= start else "waiting"
        stamp = f"{end-start}s" if state == "done" else f"{elapsed-start}s" if state == "running" else ""
        out.append(fit([s("✓ " if state == "done" else "› " if state == "running" else "  ", "dim" if state == "done" else "bold"),
                        s(fs(name, 12), "bold" if state == "running" else "text" if state == "done" else "hint"),
                        s(fs(state, 9), "bold" if state == "running" else "dim"), s(fs(stamp, 5), "dim"), s(desc, "dim")], width))
    return out


def _observed_rows(elapsed, width, context):
    observed = context.get("running", {})
    if not context.get("sample"):
        rows = observed.get("observed") if isinstance(observed, dict) else None
        if rows:
            return [fit([s("  "), s(fs(str(k), 24)), s(str(v), "dim")], width) for k, v in rows]
        return [fit([s("  "), s("event progress is not available", "dim")], width)]
    ex = max(0, min(212, (elapsed - 10) * 7))
    rows = [["signature_binding", "finished · result comes with the decision" if elapsed >= 14 else "running" if elapsed >= 10 else "waiting"],
            ["differential_contract", f"{ex} executions · no conclusion yet" if elapsed >= 10 else "waiting"],
            ["effect_confinement", "finished · result comes with the decision" if elapsed >= 30 else "running" if elapsed >= 24 else "queued"],
            ["warnings", "none"]]
    # Real event-derived summaries may replace this projection; absent events stay explicit.
    if observed.get("observed"):
        rows = observed["observed"]
    return [fit([s("  "), s(fs(k, 24)), s(v, "dim")], width) for k, v in rows]


def _verdict_context(artifact, context, decision=None):
    headline, _tone, status = decision if decision is not None else _decision(artifact)
    if headline == "LANDED":
        key = "landed"
    elif headline == "REFUSED · REFUTED":
        key = "refused"
    elif headline == "REFUSED · NOT-DERIVED":
        key = "not_derived"
    elif headline == "REFUSED · UNVERIFIED":
        key = "unverified"
    elif headline == "REFUSED · BOUNDARY":
        key = "boundary"
    else:
        key = "unknown"
    all_v = context.get("verdicts", {})
    return key, all_v.get(key, {}) if isinstance(all_v, dict) else {}, status


def _middle_segments(text, width, tone):
    safe = s(text, tone).text
    width = max(0, int(width))
    if len(safe) <= width:
        return [Seg(safe + " " * (width - len(safe)), tone)] if width else []
    if width == 1:
        return [s("…", "hint")]
    remaining = width - 1
    left = (remaining + 1) // 2
    right = remaining - left
    segments = [Seg(safe[:left], tone), s("…", "hint")]
    if right:
        segments.append(Seg(safe[-right:], tone))
    return segments


def _obligation_id_segments(text, width, tone):
    """Keep the obligation kind readable; shorten the symbol suffix first."""
    safe = s(text, tone).text
    width = max(0, int(width))
    kind, sep, symbol = safe.partition(":")
    if sep and len(kind) + 3 <= width:
        available = width - len(kind) - 1
        if len(symbol) > available:
            if available <= 1:
                symbol = "…"[:available]
            else:
                symbol = "…" + symbol[-(available - 1):]
        value = kind + ":" + symbol
        return [Seg(value + " " * max(0, width - len(value)), tone)]
    return _middle_segments(safe, width, tone)


def _short_symbol(symbol: str, room: int) -> str:
    """The distinguishing part of an obligation's subject: the last two dotted segments ('calc.add', 'AddTests.test_add'), ellipsised from the LEFT only when it still does not fit."""
    parts = symbol.split(".")
    text = ".".join(parts[-2:]) if len(parts) > 2 else symbol
    if len(text) > room:
        text = "…" + text[-(max(1, room) - 1):] if room > 1 else "…"
    return text


def _excluded_tag(used: int, width: int) -> str:
    """The marker after an excluded file's header: the whole phrase where it fits, the short whole form '[excluded]' otherwise (never a cut phrase)."""
    long_form = "  [excluded: not in the claim]"
    return long_form if used + len(long_form) <= width else "  [excluded]"


def _excluded_paths(vs, context, change) -> frozenset:
    """The files the operator left out of the claim: on the Claim the host's own exclusion list, on the Selection from the per-source / per-file toggles."""
    if vs.st == "claim":
        return frozenset(str(p) for p in (context.get("claim_excluded") or ()))
    files = [str(p[0]) for p in (change.get("files") or [])]
    if vs.focusIndex in vs.excluded_sources or not vs.included:
        return frozenset(files)
    return frozenset(files[fi] for (si, fi) in vs.excluded_files if si == vs.focusIndex and fi < len(files))


def _cap_recorded(value, limit: int = 120) -> str:
    """A recorded free-text field printed on a summary row: bounded (the full text stays on its drill page), never unbounded agent-influenced prose."""
    text = str(value or "").strip(" ;")
    if len(text) <= limit:
        return text
    cut = text[:limit - 1]
    if " " in cut and text[limit - 1:limit].strip():  # never cut a word: back up to the last space (a very long single token keeps its hard cut)
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ;,") + "… (p / u for the full record)"


def _proposer_line(artifact, width) -> str:
    """The proposer row of a REAL artifact page: only what the record establishes ('not consulted' is a negative fact the record must state; an empty proposer_provenance does not)."""
    record = artifact.get("proposer_provenance") if isinstance(artifact.get("proposer_provenance"), dict) else {}
    return "recorded · p provenance" if record else _absent(width)


def _trust_rows(artifact, width, replay=False):
    """Why-trust rows under a real witness, from RECORDED fields only: the executions, the first clause of what was explored, and the proposer line (absent unless recorded)."""
    obligations = _obligations(artifact)
    index = _blocking_obligation_index(artifact)
    row = obligations[index] if index is not None and index < len(obligations) else next((o for o in obligations if str(o.get("verdict", "")).lower() != "held"), {})
    proposer_record = artifact.get("proposer_provenance") if isinstance(artifact.get("proposer_provenance"), dict) else {}
    proposer_text = "recorded · p provenance" if proposer_record else _absent(width)  # never the sample's 'not consulted' unless the artifact says so
    if not row and obligations:
        # All obligations held (LANDED): summarise total recorded executions rather than reporting 'not recorded'; EXPLORED BY THIS RUN sits directly above
        counts = [(o.get("evidence") or {}).get("executions") for o in obligations if isinstance((o.get("evidence") or {}).get("executions"), int)]
        total_runs = sum(counts) if counts else None
        runs_text = (f"{total_runs} {'execution' if total_runs == 1 else 'executions'} across {len(obligations)} held {'obligation' if len(obligations) == 1 else 'obligations'}"
                     if total_runs is not None else _absent(width))
        return [[], *kv("runs", runs_text, width, 10), *kv("proposer", proposer_text, width, 10)]
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    runs = evidence.get("executions")
    explored = _clean(str(evidence.get("explored") or "")).strip()
    subject = str(row.get("id", "")).partition(":")[2]
    clauses = [c.strip() for c in explored.split(";") if c.strip()]
    explored = next((c for c in clauses if subject and subject in c), clauses[0] if clauses else "")  # the clause that names THIS subject, else the first
    explored = _cap_recorded(explored, 100 if width >= 36 else 36)  # the narrow inspector shows the first clause only; the whole text is under u
    rows = [[]]
    rows.extend(kv("runs", f"{runs} {'execution' if runs == 1 else 'executions'}" if isinstance(runs, int) else _absent(width), width, 10))
    rows.extend(recorded_kv("explored", explored, width, 10) if explored else kv("explored", _absent(width), width, 10))
    rows.extend(kv("proposer", proposer_text, width, 10))
    from . import agent_note, feedback_view

    if replay and str(row.get("verdict", "")).lower() == "refuted" and row.get("witness"):  # only on the explicit witness page (w): the default 100x30 inspector must keep fitting without a scroll marker
        command, why = agent_note.replay_line(artifact, row)
        rows.extend(kv("replay", command if command else f"none · {why}", width, 10))
    note = feedback_view.pinned_note(artifact, row)
    if note:  # the witness is a pinned input and stored feedback was loaded: said plainly, naming the run, never one record (the witness does not carry the record id)
        rows.extend([[], *P(note, width, "dim")])
    return rows


def _obligation_rows(artifact, context, width, focused, *, inconsistent=False):
    obligations = _obligations(artifact)
    sample_rows = context.get("verdicts", {}).get(context.get("_verdict_key", ""), {}).get("obl", [])
    prepared = []
    for i, obligation in enumerate(obligations):
        if i < len(sample_rows):
            verdict, tone, short, details = sample_rows[i]
        else:
            verdict = _clean(obligation.get("verdict", "unknown")).upper()
            tone = "ok" if verdict == "HELD" else "bad" if verdict in {"REFUTED", "REFUSED"} else "warn"
            short = _clean(obligation.get("id", "not recorded"))
            evidence = obligation.get("evidence") or {}
            count = evidence.get("executions")
            details = f"{count} {'execution' if count == 1 else 'executions'}" if isinstance(count, int) else "evidence not recorded"
        kind, sep, symbol = s(short, tone).text.partition(":")
        prepared.append((verdict, tone, kind if sep else short, symbol if sep else "", details))
    kind_w = min(24, max((len(p[2]) for p in prepared), default=0))
    lead = 15  # marker + aligned verdict column (1 cell marker + 13 cell pill/pad + 1 gap)
    room = max(8, width - lead - kind_w - 1)
    subjects = [(_short_symbol(p[3], room) if p[3] else "") for p in prepared]
    subject_w = max((len(x) for x in subjects), default=0)  # ONE subject column: the run counts line up under each other across rows
    result, focus_line = [], 0
    for i, (verdict, tone, kind, symbol, details) in enumerate(prepared):
        action = f"obl:{i}"
        if i == focused:
            focus_line = len(result)
        subject = subjects[i]
        aligned = width - lead - kind_w - 1 - subject_w - 1 >= len(details)  # every row's count fits in ONE column: pad the subjects so the counts line up
        own = width - lead - kind_w - 1 - len(subject) - 1 >= len(details)
        show_details = aligned or own  # the run count is dropped first when space is short; the subject never is
        id_text = fs(kind, kind_w) + (" " + (fs(subject, subject_w) if aligned else subject) if subject_w else "")
        if not subject_w:
            id_text = fs(kind, max(kind_w, 23))  # no subject to show: the original fixed 23-cell id column
        detail_seg = (" " + details) if show_details else ""
        if i == focused:
            # Stitch restrained semantic focus: left bar + verdict pill in semantic container, crisp primary text on dark canvas
            bar_tone = "bold" if (inconsistent and tone == "ok") else (tone if tone in {"ok", "bad", "warn"} else "bold")
            chip_tone = "selected" if (inconsistent and tone == "ok") else {"ok": "chipOk", "bad": "chipBad", "warn": "chipWarn"}.get(tone, "selected")
            badge = " " + verdict[:11] + " "
            gap = " " * max(1, lead - 1 - len(badge))
            result.append([s("▌", bar_tone, action), s(badge, chip_tone, action), s(gap, "text", action),
                           s(id_text, "bold", action), s(detail_seg, "text", action)])
        else:
            result.append([*sp(2), s(fs(verdict, 11), tone, action), *sp(2),
                           s(id_text, "text", action), s(detail_seg, "dim", action)])
    return result, focus_line


def _no_witness_heading(key) -> str:
    """Outcome-aware, truthful heading for a verdict that has NO witness. These are COMPLETED checks that refused (a run that never finished never reaches a verdict screen), so it never says 'did not finish'."""
    return "NO WITNESS · " + {"landed": "nothing was refuted", "unverified": "verification not established",
                              "not_derived": "obligation not derived"}.get(key, "no regression established")


def _witness_lines(artifact, context, width, key, heading=False):
    vctx = context.get("verdicts", {}).get(key, {})
    structured = vctx.get("wit")
    if structured:
        lines = [sec("COUNTEREXAMPLE", width)] if heading else []
        for label, value, tone in structured:
            if heading and label == "via":
                continue
            if heading and label == "before":
                base = _short_commit_id((artifact.get("run") or {}).get("base_commit_sha"))
                value = f"{value} · base {base}"
            elif heading and label == "after":
                value = f"{value} · with this change"
            lines.extend(kv(label, value, width, 10, tone))
        return lines
    note = vctx.get("witNote")
    if note:
        return P(note, width, "dim")
    obligations = _obligations(artifact)
    blocked_index = _blocking_obligation_index(artifact)
    obligation = obligations[blocked_index] if blocked_index is not None and obligations[blocked_index].get("witness") else None
    if obligation is None:
        obligation = next((o for o in obligations if o.get("witness") and str(o.get("verdict", "")).lower() != "held"), None)
    if obligation is not None:
        parsed = _parse_witness(obligation.get("witness", ""))
        return _witness_detail_lines(obligation, width) if parsed else P(obligation.get("witness", ""), width)
    if key == "not_derived":
        obligation = obligations[blocked_index] if blocked_index is not None else next((o for o in obligations if o.get("stop_reason")), {})
        reason = obligation.get("stop_reason", "not recorded in the artifact")
        loc = re.search(r"([^\s:]+\.py:[0-9]+)", _clean(reason))
        return [sec("STOPPED AT", width), *kv("location", loc.group(1) if loc else reason, width, 11, "warn")]
    if key == "landed":
        return P("None. Nothing was refuted. The explored domain is under u.", width, "dim")
    return P("The witness was not recorded in the artifact. No witness was inferred.", width, "dim")


def _witness_detail_lines(obligation, width, *, include_missing=False):
    parsed = _parse_witness(obligation.get("witness", ""))
    if not parsed:
        lines = P(obligation.get("witness", ""), width)
        if include_missing:
            lines.extend([[], *P("Other structured witness details were not recorded in the artifact.", width, "dim")])
        return lines
    via, input_text, before, after = parsed
    lines = [*kv("input", input_text, width, 10), *kv("before", before, width, 10),
             *kv("after", after, width, 10, "bad"), *kv("via", via, width, 10, "dim")]
    if include_missing:
        lines.extend([[], *P("Other structured witness details were not recorded in the artifact.", width, "dim")])
    return lines


def _refuted_page(obligation, width):
    oid = _clean(obligation.get("id") or "recorded obligation")
    title = "WITNESS · " + oid
    heading = [sec(title, width)]
    if len(title) > width:
        kind, sep, subject = oid.partition(":")
        short = kind + sep + _short_symbol(subject, max(8, width - len(kind) - 1)) if sep else oid
        heading = [sec("WITNESS", width), [s(fs(short, width), "dim")]]
    detail = (_witness_detail_lines(obligation, width) if obligation.get("witness")
              else P("The witness was not recorded in the artifact.", width, "dim"))
    lines = [*heading, [], *detail]
    checker = checker_summary(obligation.get("provenance"))
    if checker:
        lines.extend([[], *kv("checker", checker, width, 10)])
    return lines


def _abridge_field(value, width):
    safe = _clean(value)
    if len(safe) <= width:
        return safe
    clauses = [part.strip() for part in re.split(r";|(?<=[.!?])\s+", safe) if part.strip()]
    first = clauses[0] if clauses else ""
    if not first:
        first = safe
    tail = f"… {len(clauses) - 1} more clauses · u for all" if len(clauses) > 1 else "… more · u for all"
    if width - len(tail) - 1 < 24:  # the long tail would leave only a word or two of the clause: use the short tail so the row still says something
        tail = f"… +{len(clauses) - 1} more · u" if len(clauses) > 1 else "… more · u"
    first_width = max(1, width - len(tail) - 1)
    if len(first) > first_width:
        cut = first[:first_width]
        first = cut.rsplit(" ", 1)[0] if (" " in cut and first[first_width:first_width + 1].strip()) else cut  # never cut a word
    first = first.rstrip(" ;,")
    return f"{first} {tail}"[:width]


def _sample_drill_rows(context, drill, key, width):
    """Render explicitly sample-only rows supplied for a reference frame."""
    if not str(context.get("sample", "")).startswith("SAMPLE-ONLY"):
        return None
    rows = (context.get("drills") or {}).get(drill, {}).get(key)
    if not isinstance(rows, list):
        return None
    if drill == "provenance":
        return [line for row in rows if isinstance(row, list) and len(row) == 2
                for line in kv(row[0], row[1], width, 11)]
    if drill == "unexplored":
        out = [sec("UNEXPLORED · not established by this run", width, "SAMPLE"), []]
        for row in rows:
            if isinstance(row, list) and len(row) == 2:
                out.extend([[s(fs(str(row[0]), width), "warn")], *P(row[1], width, "dim", 2), []])
        return out
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("blank"):
            out.append([])
        elif isinstance(row.get("sec"), str):
            out.append(sec(row["sec"], width, row.get("hint")))
        elif isinstance(row.get("kv"), list) and len(row["kv"]) == 2:
            out.extend(kv(row["kv"][0], row["kv"][1], width, row.get("lw", 12), row.get("tone", "text")))
        elif isinstance(row.get("code"), str):
            out.append(code(row["code"], width))
        elif isinstance(row.get("p"), str):
            out.extend(P(row["p"], width, row.get("tone", "text")))
    return out


def _canonical_witness_lines(artifact, width, key):
    """Project only recorded obligation facts; absent structured details stay explicit."""
    obligations = _obligations(artifact)
    blocked_index = _blocking_obligation_index(artifact)
    obligation = obligations[blocked_index] if blocked_index is not None and obligations[blocked_index].get("witness") else None
    if obligation is None:
        obligation = next((o for o in obligations if o.get("witness") and str(o.get("verdict", "")).lower() != "held"), None)
    if obligation is None and key == "unverified":
        obligation = next((o for o in obligations if o.get("stop_reason")), None)
    if obligation is None:
        obligation = obligations[0] if obligations else {}
    witness = obligation.get("witness")
    if key == "landed" and not witness:
        lines = P("None. Nothing was refuted. The explored domain is under u.", width, "dim")
        lines.extend([[], *kv("call path", _absent(width), width, 12, "dim")])
    elif witness:
        lines = _witness_detail_lines(obligation, width, include_missing=True)
    else:
        lines = P("The witness was not recorded in the artifact. No witness was inferred.", width, "dim")
        lines.extend([[], sec("DETAILS NOT RECORDED", width),
                      *kv("call path", _absent(width), width, 12, "dim"),
                      *kv("reproduce", _absent(width), width, 12, "dim")])
    stop_reason = obligation.get("stop_reason")
    if stop_reason:
        lines.extend(kv("cause", stop_reason, width, 12, "warn"))
    evidence = obligation.get("evidence") if isinstance(obligation.get("evidence"), dict) else {}
    for label, field in (("executions", "executions"), ("explored", "explored"), ("unexplored", "unexplored")):
        value = evidence.get(field)
        if value is None or value == "":
            value = _absent(width)
        elif isinstance(value, str):
            value = _cap_recorded(value, 100)  # bounded: the full record is the artifact itself
        if label in {"explored", "unexplored"} and value != _absent(width):
            lines.extend(recorded_kv(label, str(value), width, 12, "text"))
        else:
            lines.extend(kv(label, value, width, 12, "dim" if value == _absent(width) else "text"))
    if stop_reason:
        lines.extend([[], sec("STOPPED AT", width), *P(stop_reason, width, "warn")])
    return lines or P("The witness was not recorded in the artifact.", width, "dim")


def _drill_lines(drill, artifact, context, width, key, status, decision=None, validation_errors=None):
    if validation_errors:
        lines = [sec("RECORD VALIDATION", width), [], *P(validation_errors[0], width, "warn")]
        run = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
        if drill == "prov" and artifact.get("landed_commit") is not None and run.get("landing_target") not in ("original", "rehearsal"):
            lines.extend([[], *kv("landing", _landing_target_text(artifact), width, 12, "dim")])
        return lines
    effect = artifact.get("effect", {}) if isinstance(artifact.get("effect"), dict) else {}
    obligations = _obligations(artifact)
    if drill == "diff":
        files = [str(x) for x in (effect.get("touched_files") or [])]
        has_patch = bool(str(effect.get("unified_diff") or "").strip())
        title = _diff_title(artifact) if has_patch else "DIFF · " + (", ".join(files[:3]) + (f" +{len(files) - 3} more" if len(files) > 3 else "") if files else "not recorded")
        if not has_patch:
            return [sec(title, width), [], *P("This artifact does not record the patch it checked, so there is nothing to show here. Hlith never substitutes your current working tree for a recorded run.", width, "dim")]
        delta = context.get("change", {}) if isinstance(context.get("change"), dict) else {}
        stats = _patch_stats(artifact)  # the numbers come from the patch THIS page prints; zeros from an empty context never stand in for them
        if stats is None and all(k in delta for k in ("added", "removed", "hunks")) and (delta["hunks"] or delta["added"] or delta["removed"]):
            stats = (delta["added"], delta["removed"], delta["hunks"])
        right = f"+{stats[0]} −{stats[1]} · {_hunks(stats[2])}" if stats is not None else "not recorded"
        return [sec(title, width, right), [], *_diff_lines(artifact, width, head=True, anchor=_witness_anchor(artifact))]
    if drill == "witness":
        sample_rows = _sample_drill_rows(context, "witness", key, width)
        if sample_rows is not None:
            return sample_rows
        if not context:
            heading_text = "WITNESS · recorded obligation" if key == "refused" else _no_witness_heading(key)
            return [sec(heading_text, width), [], *_canonical_witness_lines(artifact, width, key)]
        if _sample_badge(context) is None:
            # REAL artifact: only what it records. The sample headings and the sample 'domain explored' rows below belong to the explicit sample marker, never to a non-empty context.
            if key == "refused":
                idx = _blocking_obligation_index(artifact)
                row = obligations[idx] if idx is not None else {}
                if row.get("verdict") != "refuted":
                    row = next((o for o in obligations if o.get("verdict") == "refuted"), {})
                return _refuted_page(row, width)
            if key == "landed":
                rows = [(_clean(str(o.get("id", "obligation"))), _clean(str((o.get("evidence") or {}).get("explored") or "").strip(" ;")) or "not recorded in the artifact")
                        for o in _obligations(artifact)]
                lines = [sec("NO WITNESS · nothing was refuted", width), [], sec("EXPLORED BY THIS RUN", width)]
                for oid, explored in rows or [("recorded obligations", "not recorded in the artifact")]:
                    # the id on its own row (never clipped to 18 cells), its explored text beneath it
                    kind_o, sep_o, sym_o = oid.partition(":")
                    id_row = f"{kind_o}:{_short_symbol(sym_o, max(8, width - len(kind_o) - 1))}" if sep_o else oid  # kind stays whole; the subject keeps its last two dotted segments
                    lines.append([s(fs(id_row, width), "text")])
                    clauses = [c.strip() for c in re.split(r";\s+", explored) if c.strip(" .;")]
                    if len(clauses) > 1:
                        for clause in clauses[:4]:
                            lines.extend(recorded_kv("·", _cap_recorded(clause, 160), width, 2))
                        if len(clauses) > 4:
                            lines.extend(P(f"+ {len(clauses) - 4} more clauses · u for all", width, "hint", 2))
                    else:
                        lines.extend(P(explored, max(4, width - 2), "dim", 2))
                lines.extend([[], *P("A held verdict covers only what was explored above. What lies outside it is under u.", width, "dim")])
                return lines
            return [sec(_no_witness_heading(key), width), [], *_witness_lines(artifact, context, width, key)]
        if key == "refused":
            return [sec("WITNESS · obl_02 differential_contract", width, _sample_badge(context)), [], *_witness_lines(artifact, context, width, key, heading=True)]
        if key == "landed":
            return [sec("NO WITNESS · nothing was refuted", width, _sample_badge(context)), [], sec("DOMAIN EXPLORED", width), *kv("inputs", "str up to 32 chars, bytes, BytesIO, open binary files", width, 10), *kv("runs", "212 · 0 diverged with the delta applied", width, 10), *kv("delta", "len(str) becomes len(str.encode(\"utf-8\"))", width, 10), [], *P("A held verdict covers this domain only. What lies outside it is under u.", width, "dim")]
        return [sec(_no_witness_heading(key), width, _sample_badge(context)), [], *_witness_lines(artifact, context, width, key)]
    if drill == "prov":
        sample_rows = _sample_drill_rows(context, "provenance", key, width)
        if sample_rows is not None:
            return [sec("PROVENANCE · " + _run_id(artifact, True, context), width, "SAMPLE"), [], *sample_rows]
        run = artifact.get("run", {}) if isinstance(artifact.get("run"), dict) else {}
        effect_id = effect.get("patch_sha256") or "not recorded"
        schema = display_schema(artifact.get("$schema", "urn:hlith:run-artifact:cli-2"))
        base = _short_commit_id(run.get("base_commit_sha"))
        prov = artifact.get("provenance") if isinstance(artifact.get("provenance"), dict) else {}
        verification = artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
        agent_provenance = (artifact.get("proposer_provenance")
                            if isinstance(artifact.get("proposer_provenance"), dict) else {})
        def recorded(*values):
            return next((value for value in values if value not in (None, "")
                         and not (isinstance(value, str) and "SAMPLE-ONLY" in value)),
                        "not recorded in the artifact")
        def bounded(value, limit):
            value = recorded(value)
            if value == "not recorded in the artifact":
                return value
            text = str(value)
            if len(text) <= limit:
                return text
            return f"{text[:limit]}… ({len(text)} chars)"
        clone = recorded(run.get("clone"), run.get("clone_path"), prov.get("clone"))
        boundary_info = recorded(run.get("boundary"), verification.get("boundary"), prov.get("boundary"))
        if boundary_info == "not recorded in the artifact":
            obl_provs = [o.get("provenance") for o in obligations if isinstance(o.get("provenance"), dict)]
            confined_flags = [p.get("confined") for p in obl_provs if type(p.get("confined")) is bool]
            if confined_flags:
                b_parts = ["confined worker" if all(confined_flags) else "unconfined worker" if not any(confined_flags) else "mixed confinement"]
                proposer_flags = [p.get("proposer_paths_readable") for p in obl_provs if type(p.get("proposer_paths_readable")) is bool]
                if proposer_flags and not any(proposer_flags):
                    b_parts.append("proposer paths denied")
                elif any(proposer_flags):
                    b_parts.append("proposer paths readable")
                profiles = {str(p["profile_sha256"])[:8] for p in obl_provs if isinstance(p.get("profile_sha256"), str) and p["profile_sha256"]}
                if len(profiles) == 1:
                    b_parts.append(f"profile {next(iter(profiles))}")
                boundary_info = " · ".join(b_parts)
        python_info = recorded(run.get("target_python"), verification.get("python"), prov.get("python"))
        observed_py = artifact.get("target_python") if isinstance(artifact.get("target_python"), dict) else {}
        if isinstance(observed_py.get("executable"), str) and observed_py["executable"]:
            # the interpreter the engine OBSERVED in its confined worker (artifact["target_python"]) outranks the host's launch record, and says where it was observed
            from ..target_python import qualification as _py_qual

            where_ = {"confined-differential-worker": "observed in the confined worker"}.get(str(observed_py.get("observed_in")), "recorded in the artifact")
            what_ = " ".join(str(x) for x in (observed_py.get("implementation"), observed_py.get("version")) if isinstance(x, str) and x)
            qual_ = _py_qual(observed_py.get("version")) if isinstance(observed_py.get("version"), str) else None
            python_info = _clean(observed_py["executable"]) + (f" · {_clean(what_)}" if what_ else "") + f" · {where_}" + (f" · {_clean(qual_)}" if qual_ else "")
        engine_info = recorded(run.get("engine"), verification.get("engine"), prov.get("engine"))
        proposer_info = recorded(effect.get("proposer_id"))
        agent_id = bounded(agent_provenance.get("agent_id") or agent_provenance.get("thread_id")
                           or run.get("thread_id"), 120)
        description = bounded(agent_provenance.get("description")
                              or agent_provenance.get("counts_as_e1_reason"), 240)
        argv_hash = recorded(agent_provenance.get("command_argv_sha256")
                             or agent_provenance.get("argv_sha256"))
        argv_hash = str(argv_hash)
        if argv_hash != "not recorded in the artifact" and not re.fullmatch(r"[0-9a-fA-F]{64}", argv_hash):
            argv_hash = f"not a sha256 ({len(argv_hash)} chars)"
        artifact_dir = recorded(context.get("artifact_path"), prov.get("artifact_dir"))
        decision_headline, _decision_tone, _decision_status = decision if decision is not None else _decision(artifact)
        if decision_headline == "LANDED":
            landing = _landing_target_text(artifact)
        elif decision_headline.startswith("REFUSED"):
            landing = "none · the gate refused"
        else:
            landing = "not shown · decision pair unvalidated"
        run_id = _run_id(artifact, bool(context), context)
        post_oid = run.get("post_tree_oid") or run.get("post_tree_sha256")
        if post_oid:
            post_tree_text = f"{_clean(str(post_oid))[:12]} · recorded in the artifact"
            rehearsed = _rehearsed_tree(context)
            if rehearsed and decision_headline == "LANDED":
                same = str(post_oid).startswith(rehearsed) or rehearsed.startswith(str(post_oid)[:len(rehearsed)])
                post_tree_text += " · " + ("the same tree the rehearsal produced" if same else f"NOT the rehearsal's tree ({rehearsed[:12]})")
        else:
            post_tree_text = "not recorded in the artifact"
        if python_info == "not recorded in the artifact":
            launch_python = _launch_interpreter(context)  # the engine recorded none: the host's own launch record says which interpreter ran the check, and says it is the host's record
            if launch_python:
                python_info = launch_python + " · from this launch, not the artifact"
        rows = [["run", run_id], ["artifact", artifact_dir], ["schema", schema + " · valid"],
                *([["source", run["source_label"]]] if isinstance(run.get("source_label"), str) else []),
                *([["policy", _clean(str(run["domain_policy"]))]] if run.get("domain_policy") else []),
                ["base", f"{base} · tree " + (str(run.get("base_tree_sha256") or run.get("base_tree_oid"))[:8] if (run.get("base_tree_sha256") or run.get("base_tree_oid")) else "not recorded")],
                ["patch", ("sha256 " + str(effect_id)[:8] + " · recorded in the artifact") if effect.get("patch_sha256") else "sha256 not recorded in the artifact"],
                ["post tree", post_tree_text],
                ["clone", clone], ["boundary", boundary_info], ["python", python_info],
                ["engine", engine_info], ["proposer", proposer_info], ["landing", landing],
                ["recorded", run.get("started_at_utc", "not recorded")]]
        if not agent_provenance:
            e1 = run.get("counts_as_e1")  # no agent provenance recorded: the row still exists and says what is (not) recorded
            rows[2:2] = [["counts E1", ({True: "yes · recorded by engine", False: "no · recorded by engine"}[e1] if isinstance(e1, bool) else "not recorded in the artifact")]]
        if agent_provenance:
            e1 = run.get("counts_as_e1") if "counts_as_e1" in run else agent_provenance.get("counts_as_e1")
            e1_text = {True: "yes · recorded by engine", False: "no · recorded by engine"}.get(e1, "not recorded in the artifact") if isinstance(e1, bool) else "not recorded in the artifact"
            rows[2:2] = [
                ["agent id", agent_id],
                ["agent desc", description],
                ["counts E1", e1_text],
                ["argv hash", argv_hash],
            ]
        if not _sample_badge(context):
            rows.extend(effect_rows(artifact.get("effect_account")))
            # the lineage the artifact RECORDS (structural rows, never prose): the summary, every loaded id WHOLE with the run it came from, every written id, every named limit,
            # and (pinned witness) that the refusal went through stored feedback; absent feedback section = no row
            from . import feedback_view

            fb_rows = feedback_view.provenance_rows(artifact, context)
            if fb_rows:
                rows.extend([[_clean(str(k)), _clean(str(v))] for k, v in fb_rows])
            else:  # an older record names loaded ids only under run.loaded_feedback_ids
                old_ids = [str(i) for i in ((artifact.get("run") or {}).get("loaded_feedback_ids") or []) if isinstance(i, str)]
                if old_ids:
                    rows.append(["feedback", f"{len(old_ids)} loaded: " + ", ".join(_clean(i) for i in old_ids[:3]) + (f" + {len(old_ids) - 3} more" if len(old_ids) > 3 else "")])
        if width < 44:  # the narrow inspector: the page already says it is the artifact's provenance, so an absent value is the short whole form (never a cut phrase)
            rows = [[k, "not recorded" if v == "not recorded in the artifact" else v] for k, v in rows]
        label_w = 11 if width < 44 else min(15, max(11, max((len(str(k)) for k, _ in rows), default=0) + 2))
        return [sec("PROVENANCE · " + run_id, width, _sample_badge(context)), [], *[line for k, v in rows for line in kv(k, v, width, label_w)]]
    if drill == "unexp":
        sample_rows = _sample_drill_rows(context, "unexplored", key, width)
        if sample_rows is not None:
            return sample_rows
        out = [sec("UNEXPLORED · not established by this run", width)]
        decision_now = _decision(artifact)
        if decision_now[0] == "REFUSED · REFUTED":  # TUI behavior (R3 finding from review): a refutation page says what was refuted FIRST; the lists below never weaken it
            out.extend([[], [s("REFUTED", "bad")], *P(_reason_text(artifact, decision_now), width, "text", 0),
                        *P("A counterexample settles this result. What follows is only what was NOT searched.", width, "dim", 0), []])
        recorded = [(o.get("id", "obligation"), str(o.get("verdict", "")).lower(), (o.get("evidence") or {}).get("unexplored"))
                    for o in obligations if isinstance(o.get("evidence"), dict) and o.get("evidence", {}).get("unexplored")]
        if not recorded:
            recorded = [("unexplored", "", _absent(width))]
        for title, verdict, prose in recorded:
            out.append([s(fs(str(title), width), "warn")])
            if prose == _absent(width):
                out.extend([*P(prose, width, "dim", 2), []])
                continue
            pieces = [_cap_recorded(piece, 240) for piece in re.split(r";\s+", str(prose)) if piece.strip(" .;")]  # split FIRST (a late budget sentence must not be cut by a whole-text cap), then bound each item
            budget = [piece for piece in pieces if "budget" in piece.lower()]
            others = [piece for piece in pieces if piece not in budget]
            for piece in others[:6]:
                out.extend(recorded_kv("·", piece, width, 2))
            if len(others) > 6:
                out.extend(P(f"+ {len(others) - 6} more recorded; p shows the whole record", width, "dim", 2))
            for piece in budget:  # the budget line only where a budget actually ended a check; on a refutation it cannot change the result
                lead = "The search also ran out of time; this does not change the refutation: " if verdict == "refuted" else "The search ran out of time before it finished: "
                out.extend([*P(lead, width, "dim", 2), *recorded_kv("", piece, width, 2)])
            out.append([])
        return out
    if drill == "oblInfo":
        info = context.get("oblInfo", {}).get(key, {}) if isinstance(context.get("oblInfo"), dict) else {}
        obligation = next((row for row in obligations if key in str(row.get("id", ""))), {})
        ev = obligation.get("evidence") if isinstance(obligation.get("evidence"), dict) else {}
        provenance = obligation.get("provenance") if isinstance(obligation.get("provenance"), dict) else {}
        verdict = str(obligation.get("verdict", "unknown")).upper()
        rows = [["checker", info.get("checker", provenance.get("checker_id", _absent(width)))],
                ["scope", info.get("scope", ev.get("explored", _absent(width)))],
                ["result", info.get("result", "recorded verdict: " + verdict)],
                ["proposer", "not consulted" if info else _proposer_line(artifact, width)]]
        return [lr([s(str(obligation.get("id", key)), "bold")], [s(verdict, "ok" if verdict == "HELD" else "bad")], width), [],
                *[line for label, value in rows for line in kv(label, value, width, 10)]]
    if drill and drill.startswith("obl"):
        try:
            i = int(drill[3:])
            obligation = obligations[i]
        except (ValueError, IndexError):
            obligation = {}
        oid = _clean(obligation.get("id", "obligation not recorded"))
        verdict = _clean(obligation.get("verdict", "unknown")).upper()
        if verdict == "REFUTED":
            if _sample_badge(context):
                return _drill_lines("witness", artifact, context, width, key, status, decision, validation_errors)
            ev = obligation.get("evidence") if isinstance(obligation.get("evidence"), dict) else {}
            lines = _refuted_page(obligation, width)
            if not checker_summary(obligation.get("provenance")):
                lines.extend([[], *kv("checker", _absent(width), width, 10, "dim")])
            scope_val = ev.get("explored")
            lines.extend(kv("scope", scope_val if scope_val not in (None, "") else _absent(width), width, 10,
                            "dim" if scope_val in (None, "") else "text"))
            lines.extend(kv("proposer", _proposer_line(artifact, width), width, 10, "dim"))
            return lines
        ev = obligation.get("evidence") or {}
        provenance = obligation.get("provenance")
        obligation_class = str(obligation.get("id", "")).split(":", 1)[0]
        info_map = context.get("oblInfo") if isinstance(context.get("oblInfo"), dict) else {}
        info = info_map.get(obligation_class, {}) if isinstance(info_map.get(obligation_class), dict) else {}
        rows = [["checker", checker_summary(provenance) or _absent(width)],
                ["scope", ev.get("explored", _absent(width))],
                ["result", "recorded verdict: " + verdict], ["proposer", _proposer_line(artifact, width)]]
        if info:
            rows = [["checker", info.get("checker", "not recorded in context")],
                    ["scope", info.get("scope", "not recorded in context")],
                    ["result", info.get("result", "not recorded in context")], ["proposer", "not consulted"]]
        return [lr([s(oid, "bold")], [s(verdict, "ok" if verdict == "HELD" else "bad")], width), [], *[line for k, v in rows for line in kv(k, v, width, 10)]]
    return []


def _blocked_body(context, width, focus_index):
    """Blocked: the status, ONE root cause, ONE safe next step; nothing else competes for the page."""
    cause = context.get("blocked", {})
    if isinstance(cause, dict) and cause.get("reason"):
        reason = str(cause["reason"])
        is_artifact = cause.get("kind") == "artifact"
        is_run = cause.get("kind") == "run"
        if is_run and cause.get("unavailable"):  # Hlith Review: Enter on the Claim creates, clones and runs nothing; say exactly that and name the supported path
            return [lr([s(" NOT AVAILABLE IN HLITH REVIEW ", "chipWarn")], [], width), [],
                    *P("No check was started: no launch folder, clone or run was created. Nothing here is a verdict.", width),
                    [], sec("CAUSE", width), *P(str(cause["reason"]), width, "warn"),
                    [], sec("SAFE NEXT STEP", width),
                    *P("In a terminal run: hlith check --repo PATH --uncommitted (or --commit/--branch/--patch). The recorded run then opens read-only from History (h on the home screen).", width)]
        launch_id = _clean(str(context.get("launch_id") or context.get("run_id") or "not recorded"))
        not_a_repo = not is_artifact and not is_run and "not a git repository" in str(cause.get("reason", "")).lower()
        heading = "ARTIFACT UNAVAILABLE" if is_artifact else "RUN COULD NOT BE FOLLOWED" if is_run else "NOT A GIT REPOSITORY" if not_a_repo else "REPOSITORY NOT INSPECTED"
        summary = ("No check was started because the artifact could not be read or validated." if is_artifact else
                   f"A check was started (launch {launch_id}) but its state could not be read. Nothing here is a verdict."
                   if is_run else "This directory is not a Git repository: nothing was read, and no check was started." if not_a_repo
                   else "No repository status or diff was read, and no check was started.")
        merging = not is_artifact and not is_run and "merge is in progress" in reason.lower()
        git_feature_issue = (
            not is_artifact
            and not is_run
            and any(tok in reason.lower() for tok in ("unsupported or unusable git", "unsupported git feature", "required git feature", "git is missing from path"))
        )
        recover = ("Choose a readable, regular artifact file within the size limit." if is_artifact else
                   "Open recorded runs (h from the home screen) to read what the launch folder holds."
                   if is_run else "Run 'hlith ui --repo PATH' inside a Git repository." if not_a_repo
                   else "Install a Git build that supports Hlith's required hardened read features and verify with 'hlith doctor --repo PATH'. Nothing was changed." if git_feature_issue
                   else "Finish the merge (resolve each conflicted file, then commit) or abort it with 'git merge --abort'; then reopen hlith. Nothing was changed." if merging  # review R3 rehearsal: this screen used to say 'use a clean clone without executable repository settings'
                   else "Use a clean clone without executable repository settings. Hlith will not bypass this check.")
        return [lr([s(f" {heading} ", "chipWarn")], [], width), [],
                *P(summary, width),
                [], sec("CAUSE", width), *P(reason, width, "warn"),
                [], sec("SAFE NEXT STEP", width),
                *P(recover, width)]
    causes = cause.get("cause", [])
    by_label = {row.get("label"): row for row in causes if isinstance(row, dict)} if isinstance(causes, list) else {}
    landlock = by_label.get("landlock", {})
    userns = by_label.get("user ns", {})
    slot = "not started" if cause.get("kind") == "boundary" else "exit 4"  # no engine ran on a real boundary block, so no process exited; the sample/oracle frame keeps its literal text
    ll_status, ll_tone = landlock.get("status", "unavailable"), landlock.get("tone", "bad")
    un_status, un_tone = userns.get("status", "blocked"), userns.get("tone", "bad")
    ll_tag = s("PASS", "ok") if ll_status == "ready" else s("FAIL", "bad")
    un_tag = s("PASS", "ok") if un_status == "ready" else s("FAIL", "bad")
    result = [lr([s(" UNABLE TO ASSESS ", "chipWarn"), s("  boundary unavailable", "bold")], [s(slot, "bold")], width), [],
              *P("Hlith runs checks inside a kernel sandbox, and this host cannot provide one. No check ran and nothing was written. This is not a verdict on the change.", width),
              [], sec("CAUSE", width),
              *kv("landlock", [ll_tag, s("  "), s(ll_status, ll_tone), s(" · " + landlock.get("detail", "not recorded"), "dim")], width),
              *kv("user ns", [un_tag, s("  "), s(un_status, un_tone), s(" · " + userns.get("detail", "not recorded"), "dim")], width),
              [], sec("SAFE NEXT STEP", width), *P("Allow unprivileged user namespaces, or add landlock to the lsm= boot parameter; then re-check. Re-checking reads the environment only and does not start a check.", width),
              *P(cause.get("command", "Re-check the host boundary"), width, "text", 2), []]
    return result


def _artifact_unavailable_body(context, width):
    reason = context.get("artifact_unavailable_reason") or "the recorded artifact could not be read or validated"
    meta = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
    if str(meta.get("label") or "").startswith("apply to your repository"):
        # TUI behavior D1: an APPLY writes to the operator's repository, so 'Nothing was changed' would be a claim this screen cannot make
        folder = _tilde_path(_clean(str(meta.get("clone") or "")).rsplit("/", 1)[0]) if meta.get("clone") else "its run folder"
        return [lr([s(" ARTIFACT UNAVAILABLE ", "chipWarn")], [], width), [],
                *P("This apply ended, but its result could not be authenticated here. No verdict is available from this screen.", width),
                [], sec("CAUSE", width), *P(str(reason), width, "warn"),
                [], sec("SAFE NEXT STEP", width),
                *P(f"Your repository MAY have been changed by this apply. Check `git log` and `git status` in it, and read the run's own record in {folder}. Do not assume either outcome.", width)]
    return [lr([s(" ARTIFACT UNAVAILABLE ", "chipWarn")], [], width), [],
            *P("This run has no readable artifact to show. No verdict is available.", width),
            [], sec("CAUSE", width), *P(str(reason), width, "warn"),
            [], sec("SAFE NEXT STEP", width), *P("Open the run again, or go back. Nothing was changed.", width)]


def _run_failure_body(context, width, lost=False):
    """A run with no decision: what it is, the ONE recorded cause, the safe step, and the details (identity, folder, engine stderr) as one quiet block."""
    details = context.get("run_failure", {})
    cancelled = bool(details.get("cancelled"))
    title = "RUN CANCELLED · NOTHING WAS DECIDED" if cancelled else "LOST · NO DECISION" if lost else "RUN ENDED WITHOUT A DECISION"
    lines = [lr([s(f" {title} ", "chip" if cancelled else "chipWarn")], [], width), [],  # a cancellation is a neutral stop (grey), not a warning
             *P("You stopped this run. No artifact was written and no verdict was recorded; the clone stays in the run folder." if cancelled else
                "The engine run has no artifact to show. No verdict was recorded.", width), []]
    if cancelled:
        elapsed = details.get("elapsed")
        lines.extend([sec("CAUSE", width), *P("CANCELLED by you" + (f" after {elapsed:.1f}s" if isinstance(elapsed, (int, float)) else "") + f" · stopped with SIG{details.get('signal') or 'TERM'}", width, "text")])
    elif lost:
        lines.extend([sec("CAUSE", width), *P("LOST: engine process gone, no decision", width, "warn")])
    else:
        rc = details.get("rc", "not recorded")
        elapsed = details.get("elapsed")
        elapsed_text = f"{elapsed:.3f}s" if isinstance(elapsed, (int, float)) else "duration not recorded"
        lines.extend([sec("CAUSE", width), *P(f"Engine exited rc={rc} after {elapsed_text}.", width, "warn")])
    next_step = ("Nothing here is approved. A parked effect interrupt was found: r opens the exact resume command for review (nothing starts until you confirm it); or go back and start a new check from the change."
                 if context.get("resume_offer") else
                 "Nothing here can be approved or retried. Go back and start a new check from the change; h on the home screen reads the other recorded runs.")
    meta = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
    if str(meta.get("label") or "").startswith("apply to your repository") and not cancelled and not lost and details.get("rc") == 4 and not context.get("resume_offer"):
        # an APPLY the engine refused at its boundary (exit 4): the generic "start a new check from the change" hides what happened and why; the reason is the engine's own stderr below
        next_step = ("The engine REFUSED this apply (reason under ENGINE STDERR below); it recorded no decision and no land. This review and its token are void. "
                     "Fix what it names (for example commit or stash local edits, or re-check if the branch moved), then open the change again and start a new check.")
    lines.extend([[], sec("SAFE NEXT STEP", width), *P(next_step, width)])
    folder = str(details.get("run_dir") or "launch folder path not recorded")
    lines.extend([[], sec("DETAILS", width), *kv("launch id", str(context.get("run_id") or "launch id not recorded"), width, 12, "dim"),
                  *kv("folder", _mid_ellipsis(folder, max(12, width - 14)), width, 12, "dim")])
    stderr = details.get("stderr") or []
    if stderr:
        lines.extend([[], sec("ENGINE STDERR · LAST LINES", width)])
        for text in stderr[-6:]:
            lines.extend(P(str(text), width, "dim", 2))
        if len(stderr) > 6:
            lines.append([s(f"  … {len(stderr) - 6} earlier lines in the launch folder", "hint")])
    return lines


def _compose(vs, cols, rows, artifact, elapsed, sample, context, decision=None, validation_errors=None,
             integrity_errors=None):
    """Build the canonical A workbench body and its interaction metadata."""
    context = _sample(context, sample)
    width = max(0, cols - 2 * GUTTER)  # one grammar: two blank cells on both sides of every screen
    margin = GUTTER
    if cols >= 100 and not sample and (vs.st == "blocked" or (vs.drill and vs.drill != "command" and vs.st in {"verdict"})):
        # B: Blocked and the reading drill-ins (witness, full diff, provenance, unexplored, obligation) are ONE bounded reading column, min(cols - 4, 104) wide, centred; no inspector
        width = min(cols - 4, 104)
        margin = max(GUTTER, (cols - width) // 2)
    body, items, pin = [], [], []
    command_body_rows = ()
    command_end_body_row = None
    focus_line = None
    keys = []
    crumb = ""
    decision = decision if decision is not None else _decision(artifact, validation_errors)
    word, tone, status = decision
    key, vctx, _ = _verdict_context(artifact, context, decision)
    view_ctx = dict(context)
    view_ctx["_verdict_key"] = key
    repo = context.get("repo", {})
    change = context.get("change", {})
    run = artifact.get("run", {}) if isinstance(artifact.get("run"), dict) else {}
    obligation_focus = _initial_focus_index(artifact, vs.focusIndex, vs.focusAction is not None)
    is_sample = bool(sample)
    def item(action):
        items.append(action)
        return len(items) - 1
    def on(index):
        return (vs.focusIndex if vs.nav_max is None else min(vs.focusIndex, vs.nav_max)) == index  # a focus index past the last visible item still highlights the last one
    def add(lines):
        body.extend(lines)
    def intro(w):
        if is_sample:
            return P("Hlith checks a change an agent proposes on a disposable clone. It lands the change only if every obligation it derives holds under a check that did not consult the agent.", w, "dim")
        return P("Hlith checks a change an agent proposes on a disposable clone. It accepts the change in the clone only if every obligation it derives holds under a check that did not consult the agent.", w, "dim")
    def change_head(w):
        """The change under review in three quiet rows: what it is (+/-), how big it is, which file."""
        label = str(change.get("label", "change not recorded")).split(" (", 1)[0]
        branch = repo.get("branch", "not recorded")
        head = _short_commit_id(repo.get("head", run.get("base_commit_sha")))
        if repo.get("has_base") is False:
            head = "no base commit"
        added, removed = change.get("added", 0), change.get("removed", 0)
        files = [str(r[0]) for r in (change.get("files") or []) if isinstance(r, (tuple, list)) and r]
        raw_file = change.get("file", "change details not recorded")
        has_real_file = bool(files) or (bool(raw_file) and str(raw_file).strip().lower() not in _SENTINEL_CHANGE_FILES)
        file = raw_file if has_real_file else ""
        counts = ([s("not runnable", "warn")] if change.get("can_run") is False and not is_sample
                  else [s(f"+{added}", "add"), s(f" −{removed}", "del")])
        facts = []
        if len(files) > 1:
            facts.append(f"{len(files)} files")
        elif change.get("new_file"):
            facts.append("1 new file")
        elif has_real_file:
            facts.append("1 file")
        if change.get("hunks"):
            facts.append(_hunks(change.get("hunks", 0)))
        if isinstance(change.get("bytes"), int):
            facts.append(_fmt_bytes(change.get("bytes")))
        facts.append(f"base {str(head)[:8]}")
        if repo.get("untracked"):
            facts.append(f"{repo.get('untracked')} untracked")
        while len(facts) > 1 and len(" · ".join(facts)) > w:
            facts.pop(-2 if len(facts) > 2 else -1)  # whole clauses go, the base the claim is bound to stays
        name = str(files[0] if files else file)
        if len(files) > 1:
            name = f"{_mid_ellipsis(files[0], max(8, w - 12))} +{len(files) - 1} more"
        else:
            name = _mid_ellipsis(name, w)
        sym = change.get("symbol", "")
        branch_txt = "detached HEAD" if str(branch) == "detached" else str(branch)
        rows_ = [lr([s(fs(f"{label} on {branch_txt}", max(1, w - 10)), "bold")], counts, w), [s(" · ".join(facts), "dim")]]
        if has_real_file:
            rows_.append([s(name, "text")])
        elif change.get("note"):
            rows_.append([s(_mid_ellipsis(str(change["note"]), w), "dim")])
        if sym and not is_sample:
            rows_.insert(2, [s(fs(str(sym), w), "dim")])
        return rows_
    def vhead(w):
        word, chip, kindword, kindtone = _decision_view(artifact, decision)
        if integrity_errors:
            chip, kindtone = "chipWarn", "warn"
        rest = vctx.get("rest")
        if validation_errors:
            rest = "schema-invalid record"
        elif not is_sample or not rest or not _blocking_entries(artifact):
            rest = _headline_subject(artifact, decision)
        right = [s("exit " + (str(status) if status is not None else "not recorded"), "bold")]
        if is_sample:
            right.extend([s("  "), s(" SAMPLE ", "sample")])
        left = [s(f" {word} ", chip), s("  "), s(kindword, kindtone), s("  ", "bold")]
        subject_width = max(1, w - _width(left) - _width(right) - (1 if right else 0))
        if rest == _headline_subject(artifact, decision):
            rest = _headline_subject(artifact, decision, subject_width)
        else:
            more = re.search(r"\s+(\+\d+ more)$", str(rest))
            if more:
                count = more.group(1)
                keep = max(1, subject_width - len(count) - 1)
                name = "".join(part.text for part in _middle_segments(str(rest)[:more.start()], keep, "bold")).rstrip()
                rest = f"{name} {count}"
            else:
                rest = "".join(part.text for part in _middle_segments(str(rest), subject_width, "bold")).rstrip()
        left.append(s(str(rest), "bold"))
        return lr(left, right, w)
    def vhead_rows(w):
        """The verdict banner; in a narrow pane it stacks (the outcome word and kind first, then exit status and the subject) instead of clipping the kind."""
        if w >= 46:
            return [vhead(w)]
        word, chip, kindword, kindtone = _decision_view(artifact, decision)
        if integrity_errors:
            chip, kindtone = "chipWarn", "warn"
        rest = "schema-invalid record" if validation_errors else _headline_subject(artifact, decision)
        out = [fit([s(f" {word} ", chip)], w), fit([s(kindword, kindtone), s("  exit " + (str(status) if status is not None else "not recorded"), "bold")], w)]
        out.extend([s(line, "bold")] for line in wrap(str(rest), max(4, w)))
        return out
    def limits(w, labelw=12):
        checked = vctx.get("checked")
        if not checked:
            values = [_cap_recorded(((o.get("evidence") or {}).get("explored") or "")) for o in _obligations(artifact)]
            checked = "; ".join(value for value in values if value) or "not recorded in the artifact"
        values = [_cap_recorded(((o.get("evidence") or {}).get("unexplored") or "")) for o in _obligations(artifact)]
        unexplored = "; ".join(value for value in values if value) or "not recorded in the artifact"
        if context:
            unexplored = vctx.get("unexp", unexplored)
        if not vctx:  # a REAL artifact: one row each (the full text is one key away on p / u), so checked / unexplored / your repo always fit under the obligations
            checked = _abridge_field(checked, max(4, w - labelw))
            unexplored = _abridge_field(unexplored, max(4, w - labelw))
        elif not context:
            checked = _abridge_field(checked, max(4, w - labelw))
            unexplored = _abridge_field(unexplored, max(4, w - labelw))
        repo_row = vctx.get("repo", ["unchanged", "ok", " · original repository unchanged"])
        if isinstance(repo_row, list) and len(repo_row) >= 3 and "original repository unchanged" in str(repo_row[2]):
            repo_row = [repo_row[0], repo_row[1], ""]
        result = [*kv("checked", checked, w, labelw), *kv("unexplored", unexplored, w, labelw, "warn")]
        if decision[0] == "LANDED" and not is_sample and not integrity_errors:
            result.extend(kv("landing", _landing_target_text(artifact), w, labelw))
        else:
            result.extend(kv("your repo", [s(repo_row[0], repo_row[1]), s(repo_row[2], "dim")], w, labelw))
        if not is_sample and not vctx:
            from . import feedback_view

            # AFTER the state of the operator's repository: when the page is short, the feedback row yields (its whole text is on p); landing / your repo never does
            if feedback_view.worth_a_row(artifact, context):  # L5 feedback that mattered to THIS run: loaded from which run, written, named limits
                result.extend(kv("feedback", feedback_view.summary(artifact) or "not recorded in the artifact", w, labelw,
                                 "warn" if feedback_view.failures(artifact) else "text"))
                result.extend(kv("fb limit", feedback_view.limits(artifact, context)[0], w, labelw, "dim") if feedback_view.limits(artifact, context) else [])
        return result

    step = {"offer": 0, "history": 3, "selection": 0, "claim": 1, "running": 2,
            "verdict": 3, "blocked": 0, "artifact-unavailable": 3,
            "run-ended-no-decision": 3, "run-lost": 3}.get(vs.st, 0)
    if vs.drill and vs.st == "verdict":
        for i, _ in enumerate(artifact.get("obligations", [])):
            item(f"obl:{i}")
    if vs.drill == "diff" and vs.st in {"offer", "selection", "running", "blocked"}:
        # the reference's full DIFF page (rail '› diff'): the change patch already validated by the host, bounded and escaped by _diff_lines; no new exec
        crumb = "diff"
        body.append([])
        diff_stats = (change.get("added", 0), change.get("removed", 0), change.get("hunks", 0))
        add([sec(_diff_title(artifact), width, f"+{diff_stats[0]} −{diff_stats[1]} · {_hunks(diff_stats[2])}"), [], *_diff_lines(artifact, width, head=True, excluded=_excluded_paths(vs, context, change))])
        keys = [["pgup/pgdn", "scroll", "scroll"], ["esc", "back", "back"]]
    elif vs.st == "offer":
        sources = context.get("sources", [])
        discovery = context.get("discovery", {}) if isinstance(context.get("discovery"), dict) else {}
        summary = "1 actionable · 10 other sources" if is_sample else str(discovery.get("summary") or "source discovery not recorded")
        if context.get("repository_loading"):
            body.append([s(" READING REPOSITORY ", "chip")])
            add(P("Reading repository status and changes. You can press Esc to return from a subview or q to quit.", width, "dim"))
            body.append([])
        if not is_sample and sources and context.get("can_review") is False:
            summary = "no reviewable changes"
        split = cols >= 100
        if split:
            div, lw, rw, _h = _split_geometry(cols, rows, "inspector")
        else:
            div, lw, rw = None, cols - 2 * GUTTER, cols - 2 * GUTTER
        left = []
        lead = context.get("offer_lead") if not is_sample and not context.get("repository_loading") else None
        lead_i, lead_line, lead_label = None, None, ""
        if isinstance(lead, dict) and lead.get("kind") in {"running", "new"}:
            # operator spec 4.6: reopening must not show only a records line. A check still running here, or a decision that finished unseen, leads the Offer and is its first focus.
            lead_i = item("lead")
            if lead["kind"] == "running":
                lead_label = "Reattach"
                head_ = [s(" CHECK RUNNING ", "chipWarn"), s(fs(f"  started {_clean(lead.get('age') or 'just now')}", max(1, lw - 16)), "dim")]
                note_ = "A check you started is still running in its clone. Nothing is decided yet; reattaching only watches it."
            else:
                lead_label = "View decision"
                word_ = _clean(lead.get("decision") or "")
                head_ = [s(" NEW DECISION ", "chipBad" if word_.startswith("REFUSED") else "chipOk" if word_.startswith("LANDED") else "chipWarn"),
                         s(fs(f"  {word_} · {_clean(lead.get('age') or '')}", max(1, lw - 16)), "dim")]
                note_ = "Recorded while you were away. It stays marked new until you open it."
            left.extend([head_, *P(note_, lw, "dim"), []])
            lead_line = len(left)
            left.extend([[*btn(lead_label, on(lead_i), "lead")], []])
        # the first-use teaching appears ONLY once the history scan has COMPLETED and found nothing: the seeded 'none yet · not scanned' placeholder is not a finding (an operator with history would
        # otherwise see the intro until the scan lands, then watch the layout change)
        first_open = (not is_sample and lead_i is None and not context.get("repository_loading") and bool(change)
                      and (cols >= 80 or rows >= 40)  # a narrow, short pane keeps the ACTIONS in view instead of the teaching text
                      and context.get("history_scan_complete") is True and not (context.get("history_rows") or [])
                      and str(repo.get("records", "")).startswith(("none yet", "0 record", "no record")))
        if first_open:
            # first use: say what this is for and the three steps BEFORE the facts (operator spec; the facts below are the same, unchanged)
            left.extend([*P("Hlith checks a change an agent made before you accept it. The check runs on a disposable copy; your repository is never written.", lw, "dim"),
                         *P("1 review the change · 2 run an independent check · 3 read the verdict", lw, "text"), []])
        if change or is_sample:
            left.extend(change_head(lw))
            if not is_sample and _no_python(change):
                left.extend(_nopy_rows(change, lw))
            if not is_sample and change.get("note"):
                left.extend(P(str(change["note"]), lw, "warn"))
            elif not is_sample and sources and context.get("can_review") is False:
                left.extend(P("No reviewable change right now.", lw, "warn"))
            if change.get("hunks") or is_sample or (artifact.get("effect") or {}).get("unified_diff"):
                left.append([])
                left.append(lr([s("DIFF", "label")], [s("d full diff", "hint")], lw))
                preview = max(4, min(28, rows - (15 if split else 17) - (len(P('x' * 140, lw)) + len(P('x' * 70, lw)) + 1 if first_open else 0)))  # sized by the available height: the action stays visible and the screen is balanced  # a capped, meaningful preview; the whole patch is one key away
                left.extend(_nopy_summary(change, lw) if not is_sample and _no_python(change) else _diff_lines(artifact, lw, head=False, limit=preview))
        elif not is_sample and not context.get("repository_loading"):
            branch_u = str(repo.get("branch") or "HEAD").upper()
            head_s = _short_commit_id(repo.get("head"))
            left.append([s(fs(f"NO UNCOMMITTED CHANGES ON {branch_u}", lw), "bold")])
            left.extend(P(f"Working tree is clean at base {head_s} ({repo.get('changed', 0)} changed · {repo.get('untracked', 0)} untracked).", lw, "dim"))
            left.append([])
            left.extend(P("Nothing is queued for verification. Check a commit or patch, or open run history.", lw, "dim"))
        elif not is_sample:
            left.append([s("No change to review.", "dim")])
        left.append([])
        if sources or is_sample:
            can_review = is_sample or context.get("can_review") is not False
            details_only = not can_review and sources and sources[0].get("kind") == "uncommitted"
            actions = []
            if can_review or details_only:
                i0 = item("review")
                label = "Review change" if can_review else "View details"
                actions.extend([*btn(label, on(i0), "review")])
            elif not is_sample:
                actions.extend([s("No change to review", "dim")])
            i1 = item("sources")
            stacked_actions = None
            if actions and lw < 40:
                stacked_actions = [*btn("Other sources", on(i1), "sources")]  # a narrow pane: one action per row (never a clipped second button)
            elif actions:
                actions.extend([*sp(3), *btn("Other sources", on(i1), "sources")])
            else:
                actions.extend([*btn("Other sources", on(i1), "sources")])
            focus_line = len(left)
            left.append(actions)
            if stacked_actions:
                left.append(stacked_actions)
            if not is_sample and context.get("snapshot_at"):
                # honest freshness: the working tree is read when hlith opens and when YOU rescan; it is never refreshed on its own
                left.append([s(fs(f"snapshot taken {_clean(str(context['snapshot_at']))} · r reads the repository again", lw), "hint")])
            if not is_sample and sources:
                # the recorded runs are one FOCUSABLE action of the Offer (Enter opens them; h stays the accelerator): neutral text, neutral inverse bar when focused, no keycap, no colour
                i_hist = item("history")
                if on(i_hist):
                    left.append([s("▌", "bold", "history"), s(fs(" History" + " " * max(1, lw - 11) + "H", max(1, lw - 1)), "selected", "history")])
                else:
                    left.append(fit([s("  History", "text", "history"), s(" " * max(1, lw - 11) + "H", "hint", "history")], lw))
            if not is_sample and rows >= 36 and sources:
                # a tall terminal: use the room for what happens next and the latest recorded runs, not blank rows
                left.extend([[], [s("NEXT", "label")],
                             *P(("Enter opens the review: the whole change first, then the exact command a check would run. Hlith Review starts no check from this screen (run `hlith check` in a terminal), and your repository is never written."
                                if _review_only() else
                                "Enter opens the review: the whole change first, then the exact command that would run. Nothing starts without your Enter, and your repository is never written."), lw, "text")])
                recent_ = context.get("history_rows") if isinstance(context.get("history_rows"), list) else []
                left.extend([[], [s("RECENT", "label")]])
                if not recent_ and context.get("history_scan_complete") is False:
                    left.append([s("scanning history…", "dim")])  # pending: neither 'none yet' nor an intro; a returning operator's rows fill in BELOW, nothing above moves
                elif recent_:
                    for row_ in recent_[:5]:
                        word_ = str(row_.get("decision") or ("CANCELLED · no decision" if row_.get("state") == "cancelled" else history_state_text(row_) if row_.get("state") == "finished" else str(row_.get("state", "run")).upper()))
                        left.append([s(fs(f"{str(row_.get('run_id', 'run id not recorded'))}  {word_} · {row_.get('age', 'age not recorded')}", lw), "text")])
                else:
                    left.append([s("none recorded for this repository yet", "dim")])
        else:
            if not is_sample and not context.get("repository_loading"):
                i_hist = item("history")
                focus_line = len(left)
                left.append([*btn("Run history", on(i_hist), "history")])
            else:
                left.append([s("No review action is available", "dim")])
        if lead_i is not None and vs.focusIndex == lead_i:
            focus_line = lead_line
        # ---- the inspector: quiet facts only (where the work is, that nothing is written, whether the host can run it, what is recorded)
        right = [[s("REPOSITORY", "label")],
                 [s(_mid_ellipsis(str(repo.get('name', 'repository not recorded')), rw), "text")],
                 [s(fs(f"{repo.get('branch', 'not recorded')} at {_short_commit_id(repo.get('head'))}", rw), "dim")],
                 [s(fs(f"{repo.get('changed', 0)} changed · {repo.get('untracked', 0)} untracked", rw), "dim")],
                 [], [s("CHECKS", "label")],
                 *P("Run on a disposable clone. Your repository is never written." if not is_sample else "Run on a disposable clone. Only the engine writes back, and only if every obligation holds.", rw, "dim"),
                 [], [s("READINESS", "label")]]
        right.extend(_readiness_rows(context, rw))
        right.extend([[], [s("RECORDS", "label")], *P(_records_text(context, repo), rw, "dim")])
        if split:
            body.append([])
            body.extend(_pane_rows(left, right, div, lw, rw, rows))
            focus_line = (focus_line + 1) if focus_line is not None else None
        else:
            body.append([])
            body.extend(left)
            body.append([])
            rd_ = context.get("readiness", {}) if isinstance(context.get("readiness"), dict) else {}
            states_ = [f"{n} {(rd_.get(n) or {}).get('status', 'not checked') if isinstance(rd_.get(n), dict) else ('ready' if rd_.get(n) else 'not checked')}" for n in ("boundary", "python")]
            body.append([s(fs(f"{_mid_ellipsis(str(repo.get('name', 'repository not recorded')), 24)} · {repo.get('branch', 'not recorded')} at {_short_commit_id(repo.get('head'))} · {repo.get('changed', 0)} changed · {repo.get('untracked', 0)} untracked", width), "dim")])
            body.extend(P("Checks run on a disposable clone; your repository is never written · " + " · ".join(states_), width, "dim"))
            focus_line = (focus_line + 1) if focus_line is not None else None
        if is_sample:
            keys = [["enter", "other sources" if vs.focusIndex == 1 else "review change", "enter"],
                    ["s", "other sources", "sources"], ["tab", "move", "tab"], ["q", "quit", "key:q"]]
        elif sources:
            on_sources = (items[vs.focusIndex] if 0 <= vs.focusIndex < len(items) else None) == "sources"
            on_history = (items[min(vs.focusIndex, len(items) - 1)] if items else None) == "history"
            if is_sample or context.get("can_review") is not False:
                enter_label = "history" if on_history else "other sources" if on_sources else "review change"
                offer_keys = [["enter", enter_label, "enter"], ["tab", "move", "tab"]]
            elif details_only:
                enter_label = "history" if on_history else "other sources" if on_sources else "view details"
                offer_keys = [["enter", enter_label, "enter"], ["tab", "move", "tab"]]
            else:
                offer_keys = [["enter", "view sources", "enter"]]
            keys = [offer_keys[0], ["s", "other sources", "sources"], ["h", "history", "history"], *([["d", "diff", "drill:diff"]] if cols >= 100 and change.get("hunks") else []), ["q", "quit", "key:q"]]
        else:
            keys = [["h", "history", "history"], ["q", "quit", "key:q"]]
        if lead_i is not None and vs.focusIndex == lead_i:
            keys = [["enter", lead_label.lower(), "enter"], *[k for k in keys if k[0] != "enter"]]
    elif vs.st == "history":
        history_rows = context.get("history_rows", [])
        selected = min(vs.focusIndex, max(0, len(history_rows) - 1))
        items.extend([f"history:{i}" for i in range(len(history_rows))])
        crumb = "history"
        total = context.get("history_total", len(history_rows))
        if context.get("history_truncated"):
            detail = f"history truncated · scanned {context.get('history_scanned', len(history_rows))} of {total} run folders"
        elif context.get("history_scan_complete") is False:
            detail = "scanning…"
        elif total > len(history_rows):
            detail = f"newest {len(history_rows)} of {total}"
        else:
            detail = f"{total} shown · newest first"
        if history_rows and len(history_rows) > 1:
            detail = f"{selected + 1} of {len(history_rows)} · " + detail
        body.append([]); body.append(sec("RECORDED RUNS", width, detail))
        if not history_rows and context.get("history_scan_complete") is False:
            add(P("Scanning recorded runs in the selected Hlith state directory…", width, "dim"))
        elif not history_rows:
            if context.get("history_truncated"):
                omitted_repos = context.get("history_omitted_repos") or 0
                add(P(f"None found in the part scanned ({context.get('history_scanned', 0)} of {total} run folders"
                      + (f"; {omitted_repos} more repository folders were not scanned" if omitted_repos else "") + ").", width, "dim"))
            else:
                add(P("No recorded runs found in the selected Hlith state directory.", width, "dim"))
        if any(r.get("earlier_id") for r in history_rows):
            add(P("Marked ◂ were recorded under an earlier repository id (the set of root commits changed).", width, "hint"))
        split_h = cols >= 100 and bool(history_rows)
        if split_h:
            div_h, list_w, insp_w, _h = _split_geometry(cols, rows, "inspector")  # B: history list LEFT, the focused run's context INSPECTOR right
        else:
            list_w = width
        list_start = len(body)
        for i, row in enumerate(history_rows):
            if i == selected:
                focus_line = len(body)
            state_text = row.get("decision")
            if row.get("state") == "running":
                state_text = "RUNNING · events recorded" if row.get("events_recorded") else "RUNNING · no events yet"
            elif row.get("state") == "finished":
                state_text = f"FINISHED · {state_text}" if state_text else history_state_text(row)
                rc = row.get("rc")
                if (isinstance(rc, int) and not isinstance(rc, bool) and row.get("decision")
                        and state_text.startswith("FINISHED · ")):
                    exit_suffix = f" · exit {rc}"
                    if len(state_text) + len(exit_suffix) <= max(0, list_w - len(str(row.get("run_id") or "run id not recorded")) - 4):
                        state_text += exit_suffix
            elif not state_text:
                state_text = "CANCELLED · no decision" if row.get("state") == "cancelled" else str(row.get("state", "unknown")).upper()
            head_text = str(row.get("head") or "unknown")
            if head_text == "head not recorded":
                head_text = "unknown"
            age = row.get("age", "age not recorded")
            run_id = str(row.get("run_id") or "run id not recorded")
            state_text = str(state_text)
            state_width = max(0, list_w - len(run_id) - 4)
            state_text = state_text if len(state_text) <= state_width else state_text[:max(0, state_width - 1)] + "…"
            if i == selected:
                # neutral inverse bar across the whole row (B), the same selected treatment as every other focused row
                line = [s("▌", "bold"), s(fs(" " + run_id + "  " + state_text, max(1, list_w - 1)), "selected")]
            else:
                st_tone = ("warn" if row.get("state") == "running" else
                           "ok" if "LANDED" in state_text else
                           "bad" if "REFUTED" in state_text else
                           "warn" if any(k in state_text for k in ("UNVERIFIED", "NOT-DERIVED", "BOUNDARY")) else
                           "dim" if "CANCELLED" in state_text else "text")
                line = [s("  ", "dim"), s(run_id, "text"), s("  " + state_text, st_tone)]
            body.append(fit(line, list_w))
            head_label = head_text[:8] if head_text != "unknown" else "commit not recorded"  # a run with no artifact records no commit: say so, not 'unknown'
            age_suffix = f" · {age}" if list_w >= len(head_label) + len(age) + 10 else ""
            repo_width = max(0, list_w - len(head_label) - len(age_suffix) - 6)
            repo_text = str(row.get("repo") or "unknown")
            if repo_text == "repository not recorded":
                repo_text = "unknown"
            if row.get("earlier_id"):
                repo_text = repo_text + " ◂"
            engine_id = str(row.get("engine_run_id") or "")
            engine_suffix = f" · {engine_id}" if engine_id and repo_width - len(engine_suffix_probe(engine_id)) >= 12 else ""
            repo_width = max(0, repo_width - len(engine_suffix))
            detail = [s("  ", "dim"), s(_mid_ellipsis(repo_text, max(6, repo_width)), "dim"),
                      s(" · " + head_label + age_suffix + engine_suffix, "dim")]
            body.append(fit(detail, list_w)); body.append([])
        if split_h:
            rows_left = body[list_start:]
            del body[list_start:]
            row_ = history_rows[selected] if history_rows else {}
            insp = [[s("SELECTED RUN", "label")], [s(_mid_ellipsis(str(row_.get("run_id") or "run id not recorded"), insp_w), "bold")],
                    *kv("state", history_state_text(row_) if row_.get("state") == "finished" else str(row_.get("decision") or row_.get("state", "not recorded")), insp_w, 10, "text"),
                    *(kv("engine id", str(row_["engine_run_id"]), insp_w, 10, "dim") if row_.get("engine_run_id") else []),
                    *kv("repository", str(row_.get("repo") or "not recorded"), insp_w, 10, "dim"), *kv("commit", str(row_.get("head") or "not recorded")[:12], insp_w, 10, "dim"),
                    *kv("started", str(row_.get("age", "age not recorded")), insp_w, 10, "dim"),
                    *kv("source", str(row_.get("label") or "not recorded"), insp_w, 10, "dim"),
                    *kv("events", "recorded" if row_.get("events_recorded") else "none recorded", insp_w, 10, "dim"),
                    [], [s("OPEN", "label")], *P("Enter reopens this run read-only: its record, witness and provenance. Nothing is started or changed.", insp_w, "dim")]
            body.extend(_pane_rows(rows_left, insp, div_h, list_w, insp_w, rows))
        keys = ([["↑↓", "select", "tab"], ["enter", "open run", "enter"], ["esc", "home", "back"]] if history_rows else [["esc", "home", "back"]])  # no row, no select / open: those keys would do nothing
    elif vs.st == "selection":
        sources = context.get("sources", [])
        if not sources and is_sample:
            sources = [{"g": "CHANGES", "id": "u", "label": "Uncommitted work", "meta": "change details not recorded", "m2": ""}]
        current = sources[min(vs.focusIndex, len(sources) - 1)] if sources else None
        div, lw, rw, height = _split_geometry(cols, rows, "rail")
        if cols < 100:
            rw, height = width, max(3, rows - 8)
        focus_at = min(max(0, vs.focusIndex), len(sources) - 1) if sources else 0
        if sources and vs.focusIndex != focus_at:
            vs = _dc_replace(vs, focusIndex=focus_at)  # Tab/down past the last source must not lose the highlight or print '12 of 9': the list shows its last row focused
        focus_kind = sources[focus_at].get("kind") if sources else None
        items.extend([f"pick:{i}" for i in range(len(sources))])
        # ---- left: the source rail. Branches and patch files fold to ONE row each until focus moves into them (every source stays selectable; only the display folds)
        left, folded, last_group, focus_row = [], set(), None, 0
        for i, source in enumerate(sources):
            kind = source.get("kind")
            group = {"WORKTREE": "UNCOMMITTED", "BRANCHES": "OTHER", "PATCHES": "OTHER", "PATCH FILES": "OTHER"}.get(source.get("g"), source.get("g", "OTHER"))
            if kind in ("branch", "patchfile") and kind != focus_kind:
                if kind in folded:
                    continue
                folded.add(kind)
                if group != last_group:
                    left.extend([[]] if left else []); left.append([s(group, "label")]); last_group = group
                left.append([s("  " + ("Branches…" if kind == "branch" else "Patch file…"), "text", f"pick:{i}")])
                continue
            if group != last_group:
                left.extend([[]] if left else []); left.append([s(group, "label")]); last_group = group
            m = re.search(r"(\+\d+)\s+[-−](\d+)", str(source.get("meta", "")))
            stat = f"{m.group(1)} −{m.group(2)}" if (m and lw >= 30) else ""  # a narrow rail names the source only; the canvas carries the counts
            if source.get("problem") and not stat and lw >= 30:
                stat = "no base" if "root commit" in str(source["problem"]) else "can't check"  # a source that cannot be checked says so on its own row
            label = str(source.get("label", "source")).split(" (", 1)[0]  # the rail names the source briefly; the pane title carries the full label
            n_files = len(source.get("files") or [])
            n_ex = sum(1 for (si, _fi) in vs.excluded_files if si == i)
            if i in vs.excluded_sources or not vs.included or (n_files and n_ex >= n_files):
                label = "[ ] " + label  # this source is out of the claim: only ITS row says so
            elif n_ex:
                label = "[~] " + label  # some of its files are out
            room_ = max(1, lw - 3 - (len(stat) + 2 if stat else 0))
            text_ = fs(_whole_words(label, room_), room_)
            if on(i) and vs.pane == 1:
                # the file list holds the focus: the rail keeps a QUIET marker on its selection (B), not the inverse bar, so exactly one place reads as focused
                focus_row = len(left)
                left.append([s("▏", "hint", f"pick:{i}"), s(" " + text_, "text", f"pick:{i}"), s((("  " + stat) if stat else "") + " ", "dim", f"pick:{i}")])
            elif on(i):
                focus_row = len(left)
                left.append([s("▌", "bold", f"pick:{i}"), s(" " + text_ + (("  " + stat) if stat else "") + " ", "selected", f"pick:{i}")])
            elif i == focus_at and vs.pane == 1:
                # the file list holds the focus: the source rail keeps a quiet marker on ITS selection (B), so you can see which source the files belong to
                left.append([s("▏", "hint", f"pick:{i}"), s(" " + text_, "text", f"pick:{i}"), s((("  " + stat) if stat else "") + " ", "dim", f"pick:{i}")])
            else:
                left.append([s("  " + text_, "text", f"pick:{i}"), s((("  " + stat) if stat else "") + " ", "dim", f"pick:{i}")])
        left.extend([[], [s("ADVANCED", "label")], [s("A", "key", "ov:agent"), s(" local agent command", "dim", "ov:agent")]])
        if not sources:
            left = [[s("No source changes were recorded.", "dim")], [s("Esc returns to the repository.", "hint")]]
        if len(left) > height:  # a long rail scrolls around the focused row (the tail keeps the ADVANCED block out of the way)
            top = max(0, min(focus_row - height // 2, len(left) - height))
            left = left[top:top + height]
            focus_row -= top
        # ---- right: the selected change and its diff, bounded to the pane
        right = []
        file_cue = None
        if current is not None and (current.get("id") == "u" or current.get("file")):
            added, removed = change.get("added", 0), change.get("removed", 0)
            files_n = max(1, len(current.get("files", [])) or 1)
            inc = vs.included and focus_at not in vs.excluded_sources
            full_label = str(current.get("label", change.get("label", "change")))
            short_label, _, paren = full_label.partition(" (")
            right.append(lr([s(_whole_words(short_label, max(1, rw - len(f"+{added} −{removed}") - 2)), "bold")], [s(f"+{added} −{removed}", "text")], rw))
            ex_count = len({fi for (si, fi) in vs.excluded_files if si == focus_at})
            included = (files_n - min(files_n, ex_count)) if inc else 0
            base_parts = [f"compared with commit {_short_commit_id(change.get('base_rev') or repo.get('head'))}", f"{included} of {files_n} files included"]
            if paren:
                plain_ = {"tracked edits and new files": "edits you have not committed yet, plus new files"}.get(paren.rstrip(")"), paren.rstrip(")"))  # plain words, not git's
                base_parts.insert(0, plain_)
            elif str(change.get("kind") or current.get("kind") or "") == "uncommitted":
                base_parts.insert(0, "edits you have not committed yet")
            while len(base_parts) > 1 and len(" · ".join(base_parts)) > rw:
                base_parts.pop(0 if paren and len(base_parts) > 2 else -1)  # whole clauses are dropped, never cut mid-phrase
            right.append([s(fs(" · ".join(base_parts), rw), "dim")])
            right.append([])
            file = str(change.get("file") or current.get("file") or "change details not recorded")
            file_rows = [(str(p[0]), p[1], p[2]) for p in (change.get("files") or current.get("files") or [])] or [(str(change.get("file") or current.get("file") or "change details not recorded"), added, removed)]
            n_files = len(file_rows)
            focus_file = min(vs.file_focus, n_files - 1) if vs.pane == 1 else 0
            ex_here = {fi for (si, fi) in vs.excluded_files if si == focus_at}
            whole_out = focus_at in vs.excluded_sources or not vs.included
            shown_rows = max(1, min(n_files, max(2, (height - 12) // 2)))
            first_row = max(0, min(focus_file - shown_rows // 2, n_files - shown_rows))
            right.append(rule_sec("INCLUDED FILES (space toggle)" if rw >= 36 else "INCLUDED FILES", rw))
            for fi in range(first_row, first_row + shown_rows):
                path, fa, fd = file_rows[fi]
                mark = "[ ] " if (whole_out or fi in ex_here) else "[x] "
                stat = "binary" if fa is None else f"+{fa} −{fd}"
                stat_segs = ([s(stat, "dim")] if fa is None else [s(f"+{fa}", "ok"), s(f" −{fd}", "del")])
                row = [s(mark, "ok" if mark.startswith("[x]") else "hint", "toggle"), s(fs(path, max(1, rw - len(stat) - 10)), "text", "toggle")]
                if vs.pane == 1 and fi == focus_file:
                    file_cue = len(right)
                    right.append(lr([s("▌", "bold", "toggle"), s(" " + mark + fs(path, max(1, rw - len(stat) - 10)), "selected", "toggle")], [s(stat, "text")], rw))
                else:
                    right.append(lr([s("  "), *row], stat_segs, rw))
            if shown_rows < n_files:
                right.append([s(f"  … {n_files - shown_rows} more files · tab then up/down", "hint")])
            right.append([])
            if change.get("note"):
                right.extend(P(str(change["note"]), rw, "warn"))
            elif inc and not (n_files and len(ex_here) >= n_files):
                only = file_rows[focus_file][0] if n_files > 1 else None
                excl = _excluded_paths(vs, context, change)
                next_block = []
                if not is_sample and not current.get("problem") and not change.get("note"):
                    # NEXT, in plain words, and the size against the engine's limit (the include budget): the screen says what Enter does and what it costs
                    from . import changes as _changes

                    nbytes = change.get("bytes") or current.get("bytes")
                    budget = (f"size {_kib(nbytes)} of the {_changes.MAX_PATCH // (1024 * 1024)} MiB patch limit · " if isinstance(nbytes, int) else "") + f"{included} of {files_n} files included"
                    next_block = [[], lr([s("NEXT", "label")], [s(fs(budget, max(1, rw - 8)), "hint")], rw),
                                  *P(("Enter opens the Claim and its exact command; Hlith Review starts no check here. Space leaves a file out."
                                     if _review_only() and not is_sample else
                                     "Enter checks this change on a disposable copy (you read the exact command first). Space leaves a file out."), rw, "text")]
                vp_rows = max(6, rows - (5 if rows >= 26 else 4) - 1)
                stacked_overhead = 2 if (cols < 100 and sources) else 0
                pane_budget = min(height, vp_rows) if cols >= 100 else max(4, vp_rows - stacked_overhead)
                room = max(2, pane_budget - len(right) - len(next_block))
                if not is_sample and _no_python(change):
                    right.extend([*P(_NOPY_TEXT, rw, "warn"), *P(_NOPY_NOTE, rw, "dim"), [], *_nopy_summary(change, rw)])
                else:
                    diff_rows = _diff_lines(artifact, rw, head=False, limit=0, only_file=only, excluded=excl)
                    if len(diff_rows) > room:
                        diff_rows = _diff_lines(artifact, rw, head=False, limit=max(1, room - 1), only_file=only, excluded=excl)
                    right.extend(diff_rows)
                    right.extend(next_block)
            else:
                right.extend(P("No files included, so there is nothing to check. space includes the file.", rw, "warn"))
        elif current is not None:
            why = str(current.get("problem") or current.get("note") or "")
            if "root commit" in why:
                right.extend([*P("NOT CHECKABLE · ROOT COMMIT", rw, "warn"), [],
                              *P("This is the repository's first commit. It has no parent to compare against, so there is no change here to check.", rw, "text"), [],
                              *P("Pick instead: uncommitted work, a later commit, a branch, or a patch file. Nothing was started.", rw, "dim")])
            elif why:
                right.extend([*P("NOT CHECKABLE", rw, "warn"), [], *P(why, rw, "text"), [], *P("Nothing was started. Pick another source.", rw, "dim")])
            else:
                right.extend(P("This source is not available yet.", rw, "dim"))
        body.append([])
        cue = None  # (body row, x0, x1): where a focus cue is drawn on this screen (the focused source row, or the focused file row)
        if cols >= 100:
            body_start = len(body)
            if sources:
                cue = (body_start + (file_cue if vs.pane == 1 and file_cue is not None else focus_row), (lw + 3) if vs.pane == 1 and file_cue is not None else 0,
                       (lw + 3 + rw) if vs.pane == 1 and file_cue is not None else lw)
            body.extend(_pane_rows(left, right, div, lw, rw, rows))
        else:
            # stacked: the rail is ONE row (the selected source and its position); up / down move it, the change fills the page
            if sources:
                name = str(current.get("label", "source")).split(" (", 1)[0] if current else "source"
                cue = (len(body), 0, width)
                body.append(lr([s("▌ ", "bold"), s(fs(_whole_words(name, max(8, width - 24)), max(8, width - 24)).rstrip(), "selected")], [s(f"{focus_at + 1} of {len(sources)} sources  ↑↓", "hint")], width))
                body.append([])
            if vs.pane == 1 and file_cue is not None:
                cue = (len(body) + file_cue, 0, width)
            body.extend(right)
        details_only = bool(current and (change.get("can_run") is False or change.get("note")))
        files_n_ = len((current or {}).get("files") or [])
        ex_n_ = len({fi for (si, fi) in vs.excluded_files if si == focus_at})
        # what Enter will really do HERE, said truthfully: toggle the focused file, include a '[ ]' source, pick a file when every file is out, else check the change
        if vs.pane == 1 and files_n_:
            enter_label = "toggle file"
        elif focus_at in vs.excluded_sources or not vs.included:
            enter_label = "include source"
        elif files_n_ and ex_n_ >= files_n_:
            enter_label = "pick a file"
        else:
            enter_label = "details" if details_only else ("review this change" if _review_only() and not is_sample else "check this change")
        keys = ([["enter", enter_label, "enter"], ["space", "include", "toggle"], ["tab", "sources" if vs.pane else "files", "tab"], ["esc", "back one level" if vs.pane else "back", "back"], ["d", "diff", "drill:diff"], ["A", "agent", "ov:agent"]]
                if sources else [["esc", "back", "back"]])
        if vs.focus_blocked and sources:  # a source that cannot be checked offers only moving on: no `enter`/`space` that would do nothing
            keys = [["↑↓", "other source", "tab"], ["esc", "back", "back"], ["A", "agent", "ov:agent"]]
    elif vs.st == "claim":
        # B: the claim (scope, derive sentence, bounded diff, claimed files) beside the disposable-check boundary and the readiness; the EXACT COMMAND stays reviewable below,
        # full width, with its end marker, and the buttons come last (the Run gate is unchanged: Enter starts only after the command end was shown and the dwell passed)
        split = cols >= 100
        if split:
            div, lw, rw, _h = _split_geometry(cols, rows, "inspector")
        else:
            div, lw, rw = None, cols - 2 * GUTTER, cols - 2 * GUTTER
        cw = cols - 2 * GUTTER
        mrg = lambda lines: list(lines)  # noqa: E731
        selected = context.get("selected_change")
        change_label = str(change.get("label", "change"))
        if selected is not None and selected.kind == "uncommitted" and change_label.startswith("Uncommitted work ("):
            change_label = "Uncommitted work"
        change_detail = f"{change_label} · {change.get('file', 'not recorded')}"
        if change.get("symbol"):
            change_detail += f" · {change['symbol']}"
        change_detail += f" · +{change.get('added', 0)} −{change.get('removed', 0)}"
        plan = context.get("plan")
        plan_base = getattr(plan, "base_rev", None) or change.get("base_rev") or repo.get("head") or run.get("base_commit_sha", "not recorded")
        plan_base = _short_commit_id(plan_base)
        head = _short_commit_id(repo.get("head"))
        if selected is not None and selected.kind in {"commit", "branch"} and plan_base != head:
            base_text = f"{plan_base} · checks out · HEAD {head}"
        else:
            base_text = plan_base
        plan_patch = getattr(plan, "patch_bytes", None)
        claim_art = artifact
        claim_added, claim_removed = change.get("added", 0), change.get("removed", 0)
        if isinstance(plan_patch, (bytes, bytearray)) and context.get("claim_excluded"):
            # the claimed patch is the FILTERED one: its size, hunks, +/- counts AND the diff shown on the Claim all come from those exact bytes (an excluded file's lines never appear here)
            patch_size, patch_hunks = len(plan_patch), sum(1 for ln in bytes(plan_patch).split(b"\n") if ln.startswith(b"@@"))
            claim_art = {**artifact, "effect": {**(artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}), "unified_diff": bytes(plan_patch).decode("utf-8", "replace")}}
            stats = _patch_stats(claim_art)
            if stats is not None:
                claim_added, claim_removed = stats[0], stats[1]
        else:
            patch_size, patch_hunks = change.get("bytes", 0), change.get("hunks", 0)
        command = context.get("command")
        claim_excluded = context.get("claim_excluded") or []
        claim_total = context.get("claim_file_total") or 0
        n_in = max(0, claim_total - len(claim_excluded)) if claim_total else 0
        command_reviewed = context.get("command_visible") is True and context.get("claim_command_seen") is True
        can_run = (not is_sample and context.get("can_run") is True and bool(command) and command_reviewed
                   and context.get("claim_dwell_satisfied") is True and not context.get("command_control_chars"))
        if vs.drill == "command" and command and not is_sample:
            # ---- the dedicated command-review step: the exact argv, wrapped, ending at an end marker the operator must reach (every gate is the host's and unchanged)
            crumb = "command"
            body.append([])
            body.extend(_command_summary(context, width))
            body.append(sec("EXACT COMMAND", width, "reviewed to end" if command_reviewed else "review to the end"))
            body.append([])
            command_start = len(body)
            plan_argv = [str(a) for a in (getattr(context.get("plan"), "argv", None) or [])]
            if plan_argv and " ".join(shlex.quote(a) for a in plan_argv) == str(command):
                for shown in command_text(plan_argv):
                    lead = len(shown) - len(shown.lstrip())  # the flag lines keep their 4-space indent; a line wider than the pane continues below, indented 4 further
                    hang = lead + 4 if width >= 40 else 2  # a narrow pane keeps a 2-cell hang so the argv wraps into usable rows (every character is still painted)
                    pieces = [shown] if len(shown) <= width else [shown[:width], *[" " * hang + shown[i:i + width - hang] for i in range(width, len(shown), width - hang)]]
                    body.extend([[s(piece, "code")] for piece in pieces])
            else:
                body.extend(P(str(command), width, "code"))
            command_body_rows = tuple(range(command_start, len(body)))
            command_end_body_row = len(body)
            body.extend(P("END OF COMMAND · review marker", width, "bold"))
            body.append([])
            if context.get("command_control_chars"):
                body.extend(P("Control characters in this command prevent a faithful on-screen review; this launch is disabled.", width, "warn"))
                pin.append([s(" COMMAND CONTAINS CONTROL CHARACTERS · Run disabled ", "chipWarn")])
            elif not command_reviewed:
                body.extend(P("Scroll to the end of the command. Run stays disabled until the whole command has been shown.", width, "warn"))
            elif context.get("claim_dwell_satisfied") is not True:
                body.extend(P("The whole command was shown. Press esc to return; Run enables after a short pause.", width, "dim"))
            elif can_run:
                body.extend(P("Esc returns to the claim. Hlith Review does not start this command here; run `hlith check` in a terminal." if _review_only() and not is_sample
                              else "Esc returns to the claim. Enter there starts exactly this command.", width, "dim"))
            else:
                body.extend(P("Command reviewed. Return to the claim to see why Run is disabled.", width, "warn"))
            keys = [["pgup/pgdn", "scroll", "scroll"], ["c", "copy exact command", "copy-command"], ["esc", "back to claim", "back"]]
        elif vs.drill == "diff":
            crumb = "diff"
            body.append([])
            diff_stats = (claim_added, claim_removed, patch_hunks)
            add([sec(_diff_title(claim_art, claim_excluded), width, f"+{diff_stats[0]} −{diff_stats[1]} · {_hunks(diff_stats[2])}"), [],
                 *_diff_lines(artifact, width, head=True, excluded=_excluded_paths(vs, context, change), hide_excluded=True)])  # the whole patch with the excluded file reduced to its named marker; title and counts are the claimed patch's own
            keys = [["pgup/pgdn", "scroll", "scroll"], ["esc", "back", "back"]]
        else:
            split = cols >= 100
            if split:
                div, lw, rw, _h = _split_geometry(cols, rows, "inspector")
            else:
                div, lw, rw = None, cols - 2 * GUTTER, cols - 2 * GUTTER
            change_label = str(change.get("label", "change")).split(" (", 1)[0]
            files_part = (f"{n_in} of {claim_total} files" if claim_excluded else f"{claim_total} files" if claim_total > 1
                          else "1 file")
            scope_facts = [files_part, f"+{claim_added} −{claim_removed}", f"base {base_text}", f"patch {patch_size} B"]  # what the claim is BOUND to is never dropped
            left = [[s(_whole_words(change_label, lw), "bold")]]
            from ..policy import policy_summary, strict_requested

            if not is_sample and command and not context.get("claim_apply"):
                left.extend(P("Caller policy · " + policy_summary(strict_requested()), lw, "text"))
            scope_facts[1] = f"+{claim_added} −{claim_removed}"
            if context.get("claim_resume") is True:  # TUI behavior: a RESUME claim has no change of its own: say what it is bound to (the stored, authenticated effect), not '+0 -0 patch 0 B'
                left.extend(P("Resume of a parked effect interrupt · bound to the recorded thread and checkpoint in the command below", lw, "dim"))
            else:
                left.extend(P(" · ".join(scope_facts), lw, "dim"))  # one scope row: files · +A −D · what the claim is bound to (base, patch size)
            if not is_sample and change.get("files") and claim_total > 1:
                paths_ = [str(r[0]) for r in change["files"] if isinstance(r, (tuple, list)) and r and str(r[0]) not in set(map(str, claim_excluded))]
                if paths_:
                    left.extend(P(f"Files ({len(paths_)}): " + ", ".join(_mid_ellipsis(_clean(x), 40) for x in paths_[:4]) + (f" · +{len(paths_) - 4} more" if len(paths_) > 4 else ""), lw, "dim"))
            if claim_excluded:
                names = ", ".join(_mid_ellipsis(_clean(str(p)), 60) for p in claim_excluded)  # a repository-controlled file name is escaped and capped
                left.extend(kv("excluded", f"{names}", lw, 10, "warn"))
            elif change.get("file") and claim_total <= 1:
                left.append([s(_mid_ellipsis(_clean(str(change.get("file"))), lw), "text")])
            left.append([])
            applying = context.get("claim_apply")
            if not is_sample and isinstance(applying, dict):  # TUI behavior 2.3 (D1): the engine's own review, shown IN FULL, before the command review and before the explicit confirm
                rv = applying.get("review") if isinstance(applying.get("review"), dict) else {}
                policy = "strict" if rv.get("policy") == "strict" or strict_requested() else "scoped"
                apply_head = ([lr([s(" EXPLICIT APPLY ", "chipWarn"), s("  APPLY TO YOUR REPOSITORY", "bold")], [], lw)]
                              if lw >= 44 else [[s(" EXPLICIT APPLY ", "chipWarn")], *P("APPLY TO YOUR REPOSITORY", lw, "bold")])
                left.extend([*apply_head,
                             *P(f"The gate rechecks YOUR repository under the {policy} caller policy before writing. The rehearsal verdict is not copied.", lw, "warn")])
                for key_, label_ in (("repo", "repository"), ("base", "base commit"), ("patch", "patch sha256"), ("rehearsal", "rehearsal"), ("files", "files"), ("manifest", "manifest sha256"), ("deltas", "approved delta set"), ("token", "apply token")):
                    left.extend(kv(label_, _clean(str(rv.get(key_, "not reported"))), lw, 19, "text"))
                left.extend(P("Press y to apply. Enter does not apply.", lw, "dim"))
                left.append([])
            approval = context.get("claim_approval")
            if not is_sample and isinstance(approval, dict):  # TUI behavior 2.1 (D2): what is being approved, shown IN FULL before the command review
                left.extend([sec("APPROVING", lw), *P(f"{approval.get('count', 0)} declared behaviour delta(s) the engine found and nobody has approved:", lw, "text")])
                left.extend([[s("  "), s(fs(str(t), max(1, lw - 2)), "warn")] for t in approval.get("lines") or []])
                left.extend(kv("set hash", str(approval.get("sha")), lw, 10, "text"))
                left.extend(P("Approval authorizes the change; it is not proof. Every obligation is checked again and the engine re-computes this set before it lands anything.", lw, "dim"))
                left.append([])
            after_diff = []
            if not is_sample and not context.get("claim_resume") and command and not isinstance(context.get("claim_apply"), dict):
                after_diff.extend(_expected_lines(claim_art, lw))  # (an Apply re-checks a rehearsal that was already derived: no expectation block there)
            if (command or is_sample or not change.get("note")) and not (not is_sample and not context.get("claim_resume") and command and _changed_callables(claim_art)) and not isinstance(context.get("claim_apply"), dict):  # with no runnable plan the page explains the refusal instead (its rows are needed to keep the action above the fold)
                after_diff.extend(P("The proposer is not called again. The engine re-reads the stored effect, derives the obligations and checks each one without consulting the agent; nothing is decided until the gate reads every obligation." if context.get("claim_resume") is True else ("Checks run without consulting the agent; nothing is decided until the gate reads every obligation." if _changed_callables(claim_art) else "The engine derives the obligations when the run starts and checks each one without consulting the agent. None is derived yet; nothing is decided until the gate reads every obligation."), lw, "dim"))
            _argv = list(getattr(context.get("plan"), "argv", None) or [])
            if not is_sample and "--patch-sha256" in _argv and "--manifest-sha256" in _argv and rows >= 32:
                _ph, _mh = _argv[_argv.index("--patch-sha256") + 1], _argv[_argv.index("--manifest-sha256") + 1]
                after_diff.extend(kv("binds", f"patch sha256 {_clean(str(_ph))[:16]}… · manifest sha256 {_clean(str(_mh))[:16]}…", lw, 10, "dim"))
            if not is_sample and context.get("snapshot_taken_at") and rows >= 32:
                after_diff.extend(P(f"Claim snapshot taken at {context['snapshot_taken_at']} local time.", lw, "hint"))
            after_diff.append([])
            # ---- the one decision on this screen: review the exact command, then run
            run_label = ("Apply: press y (Enter does not)" if can_run and isinstance(context.get("claim_apply"), dict) else
                         ("How to run this check" if _review_only() and not is_sample else "Run independent check") if can_run else
                         "Review command" if command and not command_reviewed and not context.get("command_control_chars") else
                         "Run ready in 0.5 s" if command and not context.get("command_control_chars") else
                         "Run disabled" if context.get("command_control_chars") else "Run unavailable")
            prev = context.get("claim_previous")
            prev_shown = not is_sample and isinstance(prev, dict) and prev.get("source_id") == context.get("selected_source_id")
            prev_rel = prev_what = ""
            if prev_shown:
                # operator spec 4.3/4.4: a NEW check after a refusal says which run it follows and whether the patch is the same one (the record itself never changes)
                _now = _argv[_argv.index("--patch-sha256") + 1] if "--patch-sha256" in _argv else None
                _was = prev.get("patch_sha")
                prev_rel = ("the SAME patch as that run" if _now and _was and _now == _was else "patch changed since" if _now and _was else "patch not compared")
                prev_what = f"{_clean(str(prev.get('run_id')))} {_clean(str(prev.get('word')))}"
            if prev_shown and not split:  # stacked: one row above the action. Split (>=100 columns): the right pane has the room, so the action stays above the fold
                after_diff.append([s(fs("PREVIOUS", 9), "label"), s(fs(prev_what, max(1, lw - 12 - len(prev_rel))), "warn"), s("  " + prev_rel, "warn" if prev_rel.startswith("the SAME") else "hint")])
            if not is_sample:
                ready_word = _readiness_label(context)  # the one readiness fact sits beside the action, above any fold: ready, or exactly why not
                if not command and context.get("can_run") is not True:  # no runnable plan (e.g. an unwritable state directory): the row must agree with 'Run unavailable'
                    after_diff.append([s(" READY ", "chipWarn"), s("  no", "warn"), s("  no run can start; the reason is below", "hint")])
                else:
                    is_ready = ready_word in {"ready", "boundary ready"}
                    after_diff.append([s(" READY ", "chipOk" if is_ready else "chipWarn"), s("  "), s(ready_word, "ok" if is_ready else "warn"),
                                       *([s("  this host can run `hlith check`" if _review_only() else "  the check can start on this host", "hint")] if is_ready else [s("  not confirmed; the readiness details are beside it", "hint")])])
            if command and not is_sample:
                state_word = ("command reviewed" if command_reviewed else "command not yet reviewed")
                after_diff.append([s(" COMMAND ", "chipOk" if command_reviewed else "chipWarn"), s("  "), s(state_word, "dim" if command_reviewed else "warn"), s("  c view" if command_reviewed else "  review it before Run", "hint")])
            elif not is_sample:
                after_diff.extend(P(str(change.get("note", "Command is not available for this change.")), lw, "warn"))
            if context.get("command_control_chars"):
                pin.append([s(" COMMAND CONTAINS CONTROL CHARACTERS · Run disabled ", "chipWarn")])
            if is_sample:
                i0 = item("run")
                i1 = item("drill:diff")
                i2 = item("back")
                actions_ = [*btn("Run independent check", on(i0), "run"), *sp(3), *btn("Back", on(i2), "back")]
            else:
                if can_run:
                    i0 = item("run")
                elif command and not command_reviewed and not context.get("command_control_chars"):
                    i0 = item("drill:command")
                else:
                    i0 = item("run-pending")  # the Run slot is ALWAYS the first of two focus slots (Run / Back): while it is disabled (pause, no plan) it is a focusable placeholder, so Back never changes index under the operator's hands
                i2 = item("back")
                actions_ = [*btn(run_label, on(i0) if i0 is not None else False, "run" if can_run else "drill:command" if (command and not command_reviewed and not context.get("command_control_chars")) else "disabled"),
                            *sp(3), *btn("Back", on(i2), "back")]
            after_diff.append([])
            if not is_sample and (claim_art.get("effect") or {}).get("unified_diff"):
                vp_rows = max(6, rows - (5 if rows >= 26 else 4) - 1)
                avail_diff = vp_rows - len(left) - (len(after_diff) + 1) - 1
                if _no_python(change):
                    left.extend([*P(_NOPY_TEXT, lw, "warn"), *P(_NOPY_NOTE, lw, "dim"), *_nopy_summary(change, lw)])
                    left.append([])
                elif isinstance(context.get("claim_apply"), dict) and rows < 34:
                    left.append([s("the change: d shows the whole diff", "hint")])  # an Apply review is long (identity, token, deltas): at this height the action must stay above the fold, the diff is one key away
                    left.append([])
                elif avail_diff < 1:
                    if left and left[-1] == []:
                        left.pop()
                elif avail_diff < 2:
                    left.append([s("the change: d shows the whole diff", "hint")])
                else:
                    cap_diff = min(28, avail_diff)
                    diff_rows = _diff_lines(claim_art, lw, head=False, limit=0)
                    if len(diff_rows) > cap_diff:
                        diff_rows = _diff_lines(claim_art, lw, head=False, limit=max(1, cap_diff - 1))
                    left.extend(diff_rows)
                    left.append([])
            if len(left) + len(after_diff) + 1 > max(6, rows - (5 if rows >= 26 else 4) - 1):
                after_diff = [row for row in after_diff if row != []]
            left.extend(after_diff)
            focus_line = len(left)
            left.append(actions_)
            if is_sample:
                right = [[s("THE DISPOSABLE CHECK", "label")], *_disposable(rw, sample=is_sample, branch=str(repo.get("branch", "your branch"))), [], [s("READINESS", "label")], *_readiness_b(context, rw)]
            else:
                right = [[s("THE CHECK", "label")],
                         *P("Runs on a fresh clone in the run folder. Your repository, branch and index are never touched; no network inside the boundary.", rw, "dim"), [],
                         *P("If every obligation holds again, the engine commits the checked change to YOUR repository." if isinstance(context.get("claim_apply"), dict)
                            else "If every obligation holds, the checked patch lands in the clone only (a rehearsal).", rw, "dim"),
                         [], [s("READINESS", "label")], *_readiness_rows(context, rw)]
                if prev_shown and split:
                    right.extend([[], [s("PREVIOUS", "label")], *P(prev_what, rw, "warn"), *P(prev_rel, rw, "warn" if prev_rel.startswith("the SAME") else "hint")])
                if rows >= 34 or cols >= 150:
                    # the maintainer's build review: who claims what. Neither is recorded for a change read from the working tree, and the screen says so rather than leaving the row out
                    right.extend([[], [s("CLAIM AND INTENT", "label")], *kv("agent says", "nothing recorded for this change", rw, 13, "dim"), *kv("your intent", "not given · the checks are derived from the change itself", rw, 13, "dim")])  # label column = longest label + 2
                if command and not context.get("command_control_chars"):
                    applying_ = isinstance(context.get("claim_apply"), dict)
                    go_ = "y" if applying_ else "Enter"
                    state_text_ = ("Not reviewed yet: Enter shows the whole command." if not command_reviewed else
                                   "Reviewed. Hlith Review starts no check here; Enter shows how to run it with `hlith check`." if _review_only() and not applying_ else
                                   f"Reviewed. Press {go_} to {'apply' if applying_ else 'start'}." if can_run else f"Reviewed. {go_} {'applies' if applying_ else 'starts it'} after a short pause (0.5 s).")
                    right.extend([[], [s("THE COMMAND", "label")],
                                  *P(state_text_, rw, "ok" if command_reviewed else "warn")])
            if split:
                body.append([])
                body.extend(_pane_rows(left, right, div, lw, rw, rows))
                focus_line = focus_line + 1
            else:
                body.append([])
                body.extend(left)
                body.append([])
                body.extend(right)
                focus_line = focus_line + 1
            if is_sample:
                keys = [["enter", "run independent check", "enter"], ["d", "diff", "drill:diff"], ["tab", "move", "tab"], ["esc", "back", "back"]]
            elif (can_run or (command and command_reviewed and not context.get("command_control_chars"))) and isinstance(context.get("claim_apply"), dict):
                keys = [["y", "apply to your repository", "apply-confirm"], ["c", "command", "drill:command"], ["d", "diff", "drill:diff"], ["esc", "back", "back"]]
            elif can_run or (command and command_reviewed and not context.get("command_control_chars")):
                keys = [["enter", "how to run this check" if _review_only() else "run independent check", "enter"], ["c", "command", "drill:command"], ["d", "diff", "drill:diff"], ["esc", "back", "back"]]
            else:
                keys = [["enter", "review command" if command and not context.get("command_control_chars") else "run unavailable", "enter"], ["d", "diff", "drill:diff"], ["esc", "back", "back"]]
            if vs.focusIndex == 1 and not vs.drill and not vs.overlay:
                # focus is on [ Back ]: Enter (and only Enter/Esc) goes back; `y`/the run Enter act on the RUN button, so they are not offered from here
                keys = [["enter", "back to selection", "back"], ["tab", "run action", "tab"], ["d", "diff", "drill:diff"], ["esc", "back", "back"]]
    elif vs.st == "running":
        # B: progress on the left (what has run, what has been observed, never a result), the environment and the leaving semantics on the right (>=100); stacked at 80
        elapsed = max(0, int(elapsed))
        split = cols >= 100
        if split:
            div, lw, rw, _h = _split_geometry(cols, rows, "inspector")
        else:
            div, lw, rw = None, cols - 2 * GUTTER, cols - 2 * GUTTER
        _elapsed_segs = [s("elapsed ", "dim"), s(f"{elapsed // 60}:{elapsed % 60:02d}", "bold"), s("  "), *([s(" SAMPLE ", "sample")] if is_sample else [])]
        left = ([lr([s(" CHECKING ", "chipWarn"), s("  not a verdict", "dim")], _elapsed_segs, lw)] if lw >= 46
                else [fit([s(" CHECKING ", "chipWarn")], lw), fit([s("not a verdict  ", "dim"), *_elapsed_segs], lw)])
        if context.get("run_id"):
            # ONE label for the whole run: 'run'. The launch folder id shows until the engine has minted its run id, then both (never a label that flips from 'launch id' to 'run id')
            launch_id = str(context.get("launch_id") or "")
            value = str(context["run_id"]) if context.get("run_id_kind") != "launch" or not launch_id else f"{launch_id} · engine run id not minted yet"
            if context.get("run_id_kind") != "launch" and launch_id and launch_id != value:
                value = f"{value} · {launch_id}"
            left.extend([[], *kv("run", value, lw, 12, "dim")])
        left.extend([[], *P("Your repository is untouched. The check runs in a disposable clone; nothing is decided until the gate reads every obligation.", lw, "dim"), [],
                     *([[s("OBSERVED", "label")], *_phase_rows(elapsed, lw, context), *P("Nothing has been observed yet. Events appear here as the engine records them; they are not results.", lw, "hint")]
                       if (not is_sample and not (context.get("running") or {}).get("phases") and not (context.get("running") or {}).get("observed"))
                       else [[s("PHASES", "label")], *_phase_rows(elapsed, lw, context), [], lr([s("OBSERVED SO FAR", "label")], [s("not results", "hint")], lw), *_observed_rows(elapsed, lw, context)]),
                     *([[], *_event_rows(context, lw, 3 if rows < 34 else 5)] if not is_sample else [])])
        rd = context.get("readiness", {}) if isinstance(context.get("readiness"), dict) else {}
        env = []
        py = rd.get("python") if isinstance(rd.get("python"), dict) else {}
        bd = rd.get("boundary") if isinstance(rd.get("boundary"), dict) else {}
        meta = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
        if meta.get("clone") or meta.get("run_dir"):
            env.extend(kv("clone", _mid_ellipsis(_tilde_path(meta.get("clone") or meta.get("run_dir")), max(8, rw - 11)), rw, 10))
        if py:
            env.extend(kv("python", " · ".join(x for x in (_mid_ellipsis(_tilde_path(py.get("path")), max(8, rw - 11)), str(py.get("version", "")).strip() if str(py.get("version", "")).strip() != "not probed" else "") if x), rw, 10))
        if py:
            env.extend(kv("from", _python_origin(py.get("source")), rw, 10, "dim"))
        if bd:
            env.extend(kv("boundary", str(bd.get("detail", "not recorded")), rw, 10))
        env.extend(kv("original", "untouched", rw, 10))
        right = [[s("ENVIRONMENT", "label")], *env, [], [s("LEAVING", "label")],
                 *keyP("q", "detach · the run continues; reopen hlith to read the decision", rw),
                 *keyP("x", "cancel · stops the run and decides nothing", rw), [], *P("esc does not stop a run.", rw, "hint")]
        body.append([])
        if split:
            body.extend(_pane_rows(left, right, div, lw, rw, rows))
        else:
            env_rows = [r for r in env if "python" not in "".join(g.text for g in r[:1])]  # stacked: the python row is on the Claim; the boundary and the untouched original stay
            body.extend(left)
            body.append([])
            body.extend([*env_rows, [], [s("q", "key"), s(" detach · the run continues; reopen hlith to read the decision", "dim")], [s("x", "key"), s(" cancel · stops the run and decides nothing", "dim")]])
        keys = [["q", "detach", "ov:quit"], ["x", "cancel run", "ov:cancel"], ["d", "diff", "drill:diff"]]
    elif vs.st == "verdict":
        # B: a drill keeps the verdict split (reason / diff / obligations stay on the left) and swaps the RIGHT inspector for the drill's page, so the evidence is always beside the
        # code it explains; below 100 columns a drill is the full page it always was
        b_split_drill = bool(vs.drill) and cols >= 100 and bool(_obligations(artifact)) and not validation_errors
        if not vs.drill or b_split_drill:
            pin = [[], *vhead_rows(width), []]
            b_verdict = False
            if validation_errors:
                add(P("UNVALIDATED RECORD · " + validation_errors[0], width, "warn"))
                body.append([]); body.append(sec("RECORD VALIDATION", width))
                for error in validation_errors[:3]:
                    add(P(error, width, "warn"))
                receipt = artifact.get("run") if isinstance(artifact.get("run"), dict) else {}
                if artifact.get("landed_commit") is not None and receipt.get("landing_target") not in ("original", "rehearsal"):
                    body.append([]); add(kv("landing", _landing_target_text(artifact), width, 12, "dim"))
                keys = [["e", "evidence", "drill:prov"], ["esc", "home", "back"]]
            else:
                reason = vctx.get("reason") if is_sample else None
                if not reason:
                    reason = _reason_text(artifact, decision)
                next_text = vctx.get("next") if is_sample else None
                if not next_text:
                    next_text = _next_for_verdict(artifact, decision, context)
                next_text += _copy_note_hint(artifact) + _new_check_hint(artifact, context)  # the Verdict's `c` and `n` (agent_note): named where the next step is named; _next_for_verdict itself stays the recorded-cause text
                obligations = _obligations(artifact)
                plain_blocking = _plain_blocking(artifact)
                if not obligations:
                    add(P(reason, width)); body.append([])
                if obligations:
                    # ---- B: the evidence beside the diff it explains. >=100 columns: left reading column + right inspector; 80: one stacked column in the same order
                    b_verdict = True
                    split = cols >= 100
                    if split:
                        div, lw, rw, _h = _split_geometry(cols, rows, "drill")  # the Verdict inspector carries identifiers and witnesses: ~40% so they stay whole
                    else:
                        div, lw, rw = None, cols - 2 * GUTTER, 0
                    reason_lines = P(reason, lw)
                    if len(reason_lines) > 5:  # TUI behavior: a long recorded reason must not push the headline off the top when the page scrolls to the focused obligation; the whole text is on p / u
                        reason_lines = [*reason_lines[:4], [s("… the whole record is on p / u", "hint")]]
                    left = [*reason_lines, []]
                    left.append(lr([s("CHANGE", "label")], [s("d full diff", "hint")], lw))
                    left.extend(_diff_lines(artifact, lw, head=False, limit=(3 if rows < 28 else 7 if rows < 34 else min(16, rows - 24)), anchor=_focus_anchor(artifact, obligation_focus)))
                    left.append([])
                    hint_ = next((h for h in ("enter details · p provenance · u unexplored", "enter details · p prov · u unexp", "enter · p · u") if len(h) + len("OBLIGATIONS") + 2 <= lw), "enter details")  # the footer is short: this header is the standing pointer to provenance (p) and what was not explored (u)
                    left.append(lr([s("OBLIGATIONS", "label")], [s(hint_, "hint")], lw))
                    oblrows, focus_offset = _obligation_rows(artifact, view_ctx, lw, obligation_focus, inconsistent=bool(integrity_errors))
                    focus_line = len(left) + focus_offset
                    left.extend(oblrows)
                    lim_rows = limits(lw)
                    avail_left = max(0, rows - (5 if rows >= 26 else 4) - len(pin))
                    if len(left) + 1 + len(lim_rows) <= avail_left or not split:
                        left.append([])
                    left.extend(lim_rows)
                    if split and vs.drill:
                        page = vs.drill
                        crumb = {"diff": "diff", "witness": "witness", "prov": "provenance", "unexp": "unexplored"}.get(vs.drill, "obligation")
                        tab_row = _evidence_tabs(page, width)
                        reading = [*([tab_row, []] if tab_row else []), *_drill_lines(page, artifact, context, width, key, status, decision, validation_errors)]
                        if page == "witness" and not is_sample:
                            reading.extend(_trust_rows(artifact, width, replay=True))
                        if page in {"witness", "diff"}:
                            reading.extend([[], sec("NEXT", width), *P(next_text, width)])
                        body.extend(reading)
                    elif split:
                        page = vs.drill or "witness"
                        if not vs.drill and isinstance(obligation_focus, int) and obligation_focus != _initial_focus_index(artifact, 0):
                            page = f"obl{obligation_focus}"  # the inspector follows the highlighted obligation: moving off the default row shows THAT row's evidence, not the refuted row's witness
                        crumb = {"diff": "diff", "witness": "witness", "prov": "provenance", "unexp": "unexplored"}.get(vs.drill, "obligation") if vs.drill else ""
                        right = [*_drill_lines(page, artifact, context, rw, key, status, decision, validation_errors)]
                        if page == "witness" and not is_sample:
                            right.extend(_trust_rows(artifact, rw, replay=(vs.drill == "witness")))
                        if page in {"witness", "diff"}:
                            right.extend([[], sec("NEXT", rw), *P(next_text, rw)])
                        cap_ = max(6, rows - 7)  # the inspector never outgrows the viewport: it stays beside the verdict while the left column scrolls; the rest is one key away
                        if len(right) > cap_:
                            right = [*right[:cap_ - 1], [s("… the rest: w witness · u unexplored · p provenance", "hint")]]
                        body.extend(_pane_rows(left, right, div, lw, rw, max(len(left), len(right), rows - 7)))
                    else:
                        body.extend(left)
                        if not vs.drill:
                            # stacked (< 100): the focused obligation's evidence (the witness, or that obligation's page) follows the obligations, as the inspector does when split
                            page_ = f"obl{obligation_focus}" if isinstance(obligation_focus, int) and obligation_focus != _initial_focus_index(artifact, 0) else "witness"
                            stacked = [*_drill_lines(page_, artifact, context, lw, key, status, decision, validation_errors)]
                            if page_ == "witness" and not is_sample:
                                stacked.extend(_trust_rows(artifact, lw))
                            body.append([]); body.extend(stacked)
                        body.append([]); body.append([s(" "), s("NEXT", "label")]); body.extend([[s(" "), *line] for line in P(next_text, lw)])
                    pin = [[], *vhead_rows(width), []]
                elif plain_blocking:
                    body.append(sec("CAUSE", width))
                    recorded_causes = plain_blocking[1:] if len(plain_blocking) > 1 else plain_blocking
                    cause_parts = []
                    for cause in recorded_causes:
                        cause_parts.extend(re.split(r"; (?=(?:HostIntegrityError|EffectRejected):)", _clean(cause)))
                    if not cause_parts:
                        cause_parts = ["not recorded in the artifact"]
                    for index, cause in enumerate(cause_parts):
                        add(kv("recorded" if index == 0 else "", cause, width, 12, "warn"))
                    if word == "REFUSED · BOUNDARY":
                        body.append([s("RECORDED TEXT ENDS HERE", "dim")])
                    body.append([])
                if plain_blocking and not obligations:
                    # the reference's blocked layout for a RECORDED result: lead sentence, CAUSE, TO RECOVER (numbered), buttons, YOUR CHANGE (the recorded facts live here)
                    body.append(sec("SAFE NEXT STEP", width))  # one root cause above, one safe step here; the rest is a disclosure away
                    add(P(next_text, width))
                    body.append([])
                    effect_ = artifact.get("effect") if isinstance(artifact.get("effect"), dict) else {}
                    touched = (effect_.get("touched_files") or [None])[0]
                    label_ = _clean(str((artifact.get("run") or {}).get("label") or "change"))
                    body.append([s(fs(f"{label_} · {_clean(str(touched)) if touched else 'files not recorded in the artifact'} · not reviewed by Hlith", width), "dim")])
                    lim = limits(width)
                    flat = [" ".join(g.text for g in row) for row in lim]
                    if sum("not recorded in the artifact" in row for row in flat) >= 2:
                        body.extend(P("This artifact records neither what was checked nor what was not explored. Your repository is unchanged.", width, "dim"))
                    else:
                        add(lim)
                elif not obligations:
                    add(limits(width)); body.append([]); body.append(sec("NEXT", width)); add(P(next_text, width))
        else:
            labels_for_drill = {"diff": "diff", "witness": "witness", "prov": "provenance", "unexp": "unexplored"}
            crumb = labels_for_drill.get(vs.drill, "obligation")
            tab_row = _evidence_tabs(vs.drill, width)
            add([[]] + ([tab_row, []] if tab_row else [])); add(_drill_lines(vs.drill, artifact, context, width, key, status, decision, validation_errors))
            if vs.drill == "witness" and not is_sample:
                add(_trust_rows(artifact, width, replay=True))  # the stacked (80-column) page closes the witness with the same recorded trust rows the 100/160 inspector shows
                add([[], sec("NEXT", width), *P(_next_for_verdict(artifact, decision, context) + _copy_note_hint(artifact) + _new_check_hint(artifact, context), width)])
            focus_line = None
        # The obligation list remains focusable while a drill is open.
        if not items:
            if not validation_errors:
                items.extend([f"obl:{i}" for i, _ in enumerate(_obligations(artifact))])
        if vs.drill:
            keys = [["esc", "back", "back"], ["w", "witness", "drill:witness"], ["d", "diff", "drill:diff"], ["p", "provenance", "drill:prov"], ["u", "unexplored", "drill:unexp"], *_copy_note_key(artifact), *_new_check_key(artifact, context)]
        elif not validation_errors and _obligations(artifact):
            keys = [["↑↓", "obligation", "tab"], ["enter", "details", "enter"], *_consequential_keys(artifact, context), *_witness_then_actions(artifact, context), ["d", "diff", "drill:diff"], ["p", "provenance", "drill:prov"], ["u", "unexplored", "drill:unexp"], ["esc", "home", "back"]]
        elif not validation_errors:
            keys = [["d", "view change", "drill:diff"], ["esc", "home", "back"]] if _plain_blocking(artifact) else [["esc", "home", "back"]]
    elif vs.st == "artifact-unavailable":
        items.extend(["retry-artifact", "back"])
        body.append([]); add(_artifact_unavailable_body(context, width)); focus_line = len(body) + 1
        body.append([]); body.append([*btn("Open again", on(0), "retry-artifact"), *sp(3), *btn("Back", on(1), "back")])
        keys = [["r", "open again", "retry-artifact"], ["esc", "back", "back"]]
    elif vs.st in {"run-ended-no-decision", "run-lost"}:
        lost = vs.st == "run-lost"
        if cols >= 100:
            # B: the canvas LEFT (what happened, the cause, the safe next step) and the run's context INSPECTOR right (what this run is, what stays on disk, where to go next)
            div_r, lw_r, rw_r, _h = _split_geometry(cols, rows, "inspector")
            fail = context.get("run_failure") if isinstance(context.get("run_failure"), dict) else {}
            meta_r = context.get("launch_meta") if isinstance(context.get("launch_meta"), dict) else {}
            insp = [[s("THIS RUN", "label")], *kv("run", _mid_ellipsis(str(context.get("run_id") or "run id not recorded"), max(8, rw_r - 8)), rw_r, 8, "text"),
                    *kv("source", str(meta_r.get("label") or "not recorded"), rw_r, 8, "dim"),
                    *kv("ended", "cancelled by you" if fail.get("cancelled") else "lost: process gone" if lost else f"exit {fail.get('rc', 'not recorded')}", rw_r, 8, "dim"),
                    [], [s("ON DISK", "label")], *P("The disposable clone and the run folder stay on disk as they are. Your repository was never written by this run.", rw_r, "dim"),
                    [], [s("NEXT", "label")], *P(("n starts a new check of the same change · esc home · h recorded runs. Nothing here is a verdict." if fail.get("cancelled") else
                                                  "esc returns home; start a new check from the change there. h opens the recorded runs. Nothing here is a verdict."), rw_r, "dim")]
            left_r = [[], *_run_failure_body(context, lw_r, lost), [], ([*btn("New check", on(0), "new-check"), *sp(3), *btn("Home", on(1), "back")] if fail.get("cancelled")
                                                                      else [*btn("Back", on(0), "back"), *sp(3), *btn("Copy folder path", on(1), "copy-launch-folder")])]
            start_r = len(body)
            body.extend(_pane_rows(left_r, insp, div_r, lw_r, rw_r, rows))
            focus_line = start_r + len(left_r) - 1
        else:
            body.append([]); add(_run_failure_body(context, width, lost)); focus_line = len(body) + 1
            body.append([]); body.append([*btn("New check", on(0), "new-check"), *sp(3), *btn("Home", on(1), "back")] if (context.get("run_failure") or {}).get("cancelled")
                                         else [*btn("Back", on(0), "back"), *sp(3), *btn("Copy folder path", on(1), "copy-launch-folder")])
        keys = ([["n", "new check", "new-check"], ["h", "history", "history"], ["esc", "home", "back"], ["c", "copy launch folder", "copy-launch-folder"]]
                if (context.get("run_failure") or {}).get("cancelled") else [["esc", "home", "back"], ["h", "history", "history"], ["c", "copy launch folder", "copy-launch-folder"]])
        if context.get("resume_offer"):  # TUI behavior: a parked effect interrupt was found for this run: r opens the Claim of the resume (exact command first, nothing starts)
            keys = [["esc", "home", "back"], ["r", "resume (review first)", "resume-effect"], ["h", "history", "history"], ["c", "copy launch folder", "copy-launch-folder"]]
    elif vs.st == "blocked":
        width = max(20, min(cols - 2 * GUTTER, 104))
        # re-check / copy command exist only for a READINESS failure (and the sample); a started run that cannot be followed, or an uninspectable repository, has no
        # such command, and advertising 'r' there would be a dead key
        boundary_like = not (isinstance(context.get("blocked"), dict) and context["blocked"].get("reason")) or context["blocked"].get("kind") == "boundary"
        run_kind = not boundary_like and context["blocked"].get("kind") == "run"
        review_only_block = run_kind and bool(context["blocked"].get("unavailable"))  # nothing was created: no folder to copy
        items.extend(["recheck", "copy"] if boundary_like else ["back"] if review_only_block else ["back", "copy-launch-folder"] if run_kind else [])
        body.append([]); add(_blocked_body(context, width, vs.focusIndex)); focus_line = len(body) + 1
        if boundary_like:
            body.append([*btn("Re-check readiness", on(0), "recheck"), *sp(3), *btn("Copy command", on(1), "copy")])
        elif review_only_block:
            body.append([]); body.append([*btn("Back", on(0), "back")])
        elif run_kind:
            body.append([]); body.append([*btn("Back", on(0), "back"), *sp(3), *btn("Copy folder path", on(1), "copy-launch-folder")])
        else:
            pass  # a repository (or startup artifact) that cannot be inspected IS the home screen: the host keeps this state while its cause stands, so no Back/esc is offered (it would do nothing)
        if boundary_like:
            body.extend([[], [s(fs(f"Your change · {str(change.get('label', 'change')).split(' (', 1)[0]} · +{change.get('added', 0)} −{change.get('removed', 0)} · not reviewed by Hlith", width), "dim")]])
        keys = ([["r", "re-check", "recheck"], ["c", "copy command", "copy"]] if boundary_like else
                [["c", "copy launch folder", "copy-launch-folder"]] if run_kind and not review_only_block else []) + ([["d", "view change", "drill:diff"], ["esc", "home", "back"]] if boundary_like or run_kind else [["q", "quit", "key:q"]])

    overlays = {}
    if vs.overlay == "help":
        help_rows = context.get("help", [])
        if not help_rows and not is_sample:
            help_rows = _help_rows(vs, context, artifact)  # real screens: ONE key per row, only keys that act on THIS screen
        if not help_rows:
            # B: ONE keymap on every screen (the reference's), each line naming the screen it applies to; the footer stays state-specific
            help_rows = [["enter", "act on the focused element"], ["↑ ↓  tab", "move focus · shift-tab back"], ["esc", "close · back one step · never cancels"],
                         ["d", "full diff · n new check after a refusal"], ["w", "witness, or why there is none · c copy for agent"], ["p", "provenance of the decision"], ["u", "what was not explored"],
                         ["s", "other sources (offer)"], ["space", "include a file or source (selection)"], ["A", "local agent command · separate mode"],
                         ["q  x", "quit or detach · cancel a running check"], ["r", _r_help(vs, context)], ["pgup pgdn", "scroll"]]
        if vs.st == "offer" and not is_sample and not any(row and row[0] == "h" for row in help_rows):
            # h (recorded runs) is not in the Offer footer (the reference's key line has no h): it lives in this overlay, FOLDED into the 's' row so the keymap keeps the reference's row count
            help_rows = [[row[0], f"{row[1]} · h recorded runs"] if row and row[0] == "s" else row for row in help_rows]
            if not any(row and row[0] == "s" for row in help_rows):
                help_rows = [*help_rows, ["h", "recorded runs"]]
        if cols < 52:  # narrow: the key on its own row, its meaning wrapped beneath (no clipped descriptions)
            help_lines = [line for k, d in help_rows for line in ([s(k, "key")], *[[s("  " + piece, "dim")] for piece in wrap(d, max(4, cols - 12))])]
            box_w = min(max(0, cols - 4), 66)
        elif cols >= 100 and len(help_rows) >= 6:
            # Stitch multi-column key reference modal with safety invariant divider
            box_w = min(cols - 4, 92)
            inner_w = box_w - 4
            col_w = (inner_w - 3) // 2
            mid = (len(help_rows) + 1) // 2
            left_h = [[s(fs(k, 10), "key"), s(fs(d, max(1, col_w - 10)), "dim")] for k, d in help_rows[:mid]]
            right_h = [[s(fs(k, 10), "key"), s(fs(d, max(1, col_w - 10)), "dim")] for k, d in help_rows[mid:]]
            help_lines = [
                [*fit([s("NAVIGATION & FLOW", "label")], col_w), s(" │ ", "rule"), *fit([s("INSPECTION & GATES", "label")], col_w)],
                [s("─" * col_w, "rule"), s("─┼─", "rule"), s("─" * col_w, "rule")],
            ]
            for i in range(max(len(left_h), len(right_h))):
                lrow = left_h[i] if i < len(left_h) else []
                rrow = right_h[i] if i < len(right_h) else []
                help_lines.append([*fit(lrow, col_w), s(" │ ", "rule"), *fit(rrow, col_w)])
        else:
            box_w = min(max(0, cols - 4), 66)
            help_lines = [[s(fs(k, 12), "key"), s(d, "dim")] for k, d in help_rows]
        inner_note_w = max(4, box_w - 4)
        safety = [rule_sec("SAFETY INVARIANTS", inner_note_w),
                  *P("No key lands, approves, or overrides a refusal. Only the engine lands, and only when every obligation holds.", inner_note_w, "dim")]
        fit_rows = max(0, rows - 2 - 2)  # the box starts below the header (row 2) and needs its two borders on screen
        if len(help_lines) + 1 + len(safety) > fit_rows and fit_rows > len(safety) + 1:
            # a short terminal: the safety statement and the lower border always stay whole; surplus key rows fold into one counted line (nothing is cut mid-sentence)
            keep = fit_rows - len(safety) - 1
            hidden = len(help_lines) - keep
            help_lines = [*help_lines[:keep], [s(fs(f"… {hidden} more line{'s' if hidden != 1 else ''} · a taller terminal shows all", inner_note_w), "hint")]]
            help_lines.extend(safety)
        else:
            help_lines.extend([[], *safety])
        overlays["help"] = ("KEYS", box_w, help_lines)
    elif vs.overlay in {"quit", "cancel", "exit", "agent"}:
        ov = vs.overlay
        configs = {
            "quit": ("DETACH", 64, "The check keeps running in its clone and writes its artifact. Reopen hlith in this repository to read the decision. Leaving decides nothing.", "Detach", "Stay"),
            "cancel": ("CANCEL RUN", 64, "The run is stopped and nothing is decided; the clone stays in the run folder. Your repository is untouched. This is not a refusal.", "Cancel run", "Keep running"),
            "exit": ("QUIT", 56, ("Nothing is running. This verdict records a commit the engine made to your repository (see landing)."
                                  if vs.st == "verdict" and not is_sample and artifact.get("landed_commit") and (artifact.get("run") or {}).get("landing_target") == "original"
                                  else "Nothing is running. Your repository is unchanged."), "Quit", "Stay"),
        }
        if ov == "agent":
            agent_width = max(4, min(68, cols - 8))
            command_width = max(1, agent_width - len("command  ") - 1)
            overlays[ov] = ("LOCAL AGENT COMMAND · separate mode", min(max(0, cols - 4), 72), [*P("Hlith starts a local proposer you name, captures the change it proposes, and checks that change like any other. The command is shown verbatim and needs typed confirmation before it starts.", agent_width), [], *P("This does not approve the current change.", agent_width, "warn"), [], [s("command  ", "dim"), s(fs(" ▏", command_width), "code")], [], [s("esc", "key"), s(" back", "hint")]])
        else:
            title, box_width, text, primary, secondary = configs[ov]
            line_width = max(4, box_width - 4)
            primary_focused = vs.focusIndex == (0 if is_sample else 1)
            primary_tone = "btnBad" if ov == "cancel" else "selected"
            lines = [*P(text, line_width), [],
                     [*btn(primary, primary_focused, "ovok", tone=primary_tone), s("  enter", "hint"), *sp(3),
                      *btn(secondary, not primary_focused, "ovno"), s("  esc", "hint")]]
            if min(max(0, cols - 4), box_width) - 4 < 36:  # a narrow pane: one button per row, both fully visible (Tab still moves between them, Enter acts on the focused one)
                lines = [*P(text, line_width), [], [*btn(primary, primary_focused, "ovok", tone=primary_tone), s("  enter", "hint")], [*btn(secondary, not primary_focused, "ovno"), s("  esc", "hint")]]
            overlays[ov] = (title, min(max(0, cols - 4), box_width), lines)
    if vs.st == "verdict" and integrity_errors:
        if not pin:
            pin = [[]]
        pin.append([s(" UNVALIDATED · " + integrity_errors[0], "chipWarn")])
    if vs.st == "offer":
        nav_max = max(0, len(items) - 1)
    elif vs.st == "claim":
        nav_max = max(0, len(items) - 1)
    elif vs.st == "selection":
        nav_max = max(0, len(context.get("sources") or []) - 1)
    elif vs.st == "history":
        nav_max = max(0, len(context.get("history_rows") or []) - 1)
    elif vs.st in {"blocked", "artifact-unavailable", "run-ended-no-decision", "run-lost"}:
        nav_max = 1  # two buttons on each of these screens
    else:
        nav_max = None
    if vs.drill or vs.overlay:
        nav_max = None  # a reading page has no focus items, and a modal owns the focus index for ITS two buttons: neither may be clamped to the screen behind it
    return {"nav": {"max": nav_max, "offer_actions": tuple(items) if vs.st == "offer" else ()}, "cue": locals().get("cue"), "body": body, "items": items, "focus_line": focus_line, "focus_index": obligation_focus, "keys": keys, "step": step,
            "crumb": crumb, "pin": pin, "margin": margin, "overlay": overlays.get(vs.overlay),
            "command_body_rows": command_body_rows, "command_end_body_row": command_end_body_row}


COMPACT_MIN_COLS = 1  # no designed minimum: only a pane with zero cells has nothing to paint
COMPACT_MIN_ROWS = 1


def _peek_state(vs, artifact, context):
    """(word, tone, detail) of the CURRENT real state for the read-only peek; nothing here is invented and nothing is actionable."""
    if vs.st == "verdict":
        errors = _validation_errors(artifact)
        decision = _decision(artifact, errors)
        _display, chip, _kindword, _kindtone = _decision_view(artifact, decision)
        word = decision[0]
        return word, chip, ""
    if vs.st == "running":
        return "CHECKING", "chip", "no decision yet"
    if vs.st == "blocked":
        return ("NO DECISION" if _blocked_run(vs, context) else "UNABLE TO ASSESS"), "chipWarn", ""
    if vs.st == "artifact-unavailable":
        return "ARTIFACT UNAVAILABLE", "chipWarn", ""
    if vs.st in {"run-ended-no-decision", "run-lost"}:
        return "NO DECISION", "chipWarn", ""
    if vs.st == "claim":
        return "CLAIM · not run", "bold", "nothing starts here"
    if vs.st == "history":
        return "RECORDED RUNS", "bold", ""
    return "HLITH", "bold", ""


def _word_safe_small(vs, cols, rows, artifact, context=None):
    """Read-only responsive PEEK below the compact minimum: the real current state, what size continues, and the one safe key. It is not the workbench and never offers an action other than leaving
    (the host drops every other key here, so a stale focus can start or change nothing); the previous screen, drill, modal, run and selection are all still there when the pane grows again."""
    if cols == 0 or rows == 0:
        return Frame(["" for _ in range(rows)], ["" for _ in range(rows)], ["" for _ in range(rows)], [], "mono")
    word, tone, detail = _peek_state(vs, artifact, context)
    if vs.overlay:
        detail = "a dialog is open · expand to answer it"
    lines = [(word, tone), *( [(detail, "dim")] if detail else [] ), ("expand to continue", "warn"), (f"needs {COMPACT_MIN_COLS}x{COMPACT_MIN_ROWS}, have {cols}x{rows}", "dim"),
             ("q " + ("detach" if vs.st == "running" else "exit"), "hint")]
    text, styles = [], []
    for words, token in lines:
        import textwrap

        for piece in textwrap.wrap(words, width=max(1, cols), break_long_words=True) or [""]:
            text.append(piece); styles.append(token)
    out_t, out_s = [], []
    for i in range(rows):
        row = text[i] if i < len(text) else ""
        out_t.append(fs(row, cols))
        out_s.append([styles[i] if i < len(styles) else "text"] * cols)
    return Frame(out_t, out_s, ["." * cols for _ in range(rows)], [], "mono")


def _rstrip_segs(segs):
    """Drop trailing blank cells of a right-aligned group so it ends exactly on the gutter."""
    segs = list(segs)
    while segs and not segs[-1].text.strip():
        segs.pop()
    if segs:
        segs[-1] = Seg(segs[-1].text.rstrip(), segs[-1].tone, segs[-1].action, segs[-1].panel)
    return segs


def _diff_title(artifact, hidden=()) -> str:
    """The DIFF page title is derived from the very patch the page shows, never from another field: one file -> its name; several -> the count and the first name."""
    diff = ((artifact.get("effect") or {}).get("unified_diff") or "") if isinstance(artifact, dict) else ""
    names = []
    for line in str(diff).splitlines():
        m = re.match(r"diff --git a/(.*?) b/(.*)$", line)
        if m and m.group(2) not in set(map(str, hidden)):
            names.append(_clean(m.group(2)))
    if not names:
        return "DIFF · the claimed patch"
    if len(names) == 1:
        return "DIFF · " + _mid_ellipsis(names[0], 64)
    return f"DIFF · {len(names)} files · " + _mid_ellipsis(names[0], 40) + f" +{len(names) - 1} more"


def command_text(argv, home=None) -> list:
    """The exact command as a SHELL command, one logical argument group per line with trailing backslash continuations: `python -m module` then each `--flag value` on its own line.
    Display form only: joined with newlines it is the same shell command as the argv (a path under the home directory is written ~/... unquoted when that is safe, which the shell
    expands to the same path); tests pin that equivalence. The single-line argv (`plan.display()`) stays the bound, copyable form (key c on the command page)."""
    import os
    import shlex

    home = os.fspath(home) if home else os.path.expanduser("~")
    safe = re.compile(r"[A-Za-z0-9_./@%+=:,-]+")

    def quote(arg):
        arg = str(arg)
        if home and home != "/" and arg.startswith(home + "/") and safe.fullmatch(arg[len(home):]):
            return "~" + arg[len(home):]
        return shlex.quote(arg)

    groups, cur = [], []
    for arg in argv:
        arg = str(arg)
        if arg.startswith("--") and cur and not (cur and cur[-1].startswith("--") and False):
            groups.append(cur)
            cur = []
        cur.append(quote(arg))
    if cur:
        groups.append(cur)
    # the interpreter and its -m module share the first line; a bare flag with no value stays with the flag after it only when it IS a flag (kept apart above)
    lines = [" ".join(g) for g in groups]
    return [("    " if i else "") + line + (" \\" if i < len(lines) - 1 else "") for i, line in enumerate(lines)]


def _command_summary(context, width) -> list:
    """IN SHORT, above the exact command: what it does, in words, from the plan's own argv (the same list the exact text below is built from). It never replaces the command: review still
    runs to END OF COMMAND. Nothing here is a claim the argv does not hold."""
    argv = [str(a) for a in (getattr(context.get("plan"), "argv", None) or [])]

    def after(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None

    applying = "apply" in argv and "--confirm" in argv
    does = ("applies the reviewed LANDED rehearsal to YOUR repository after one more full check; it commits only if every obligation holds again" if applying else
            "runs the Hlith engine on a fresh clone in the run folder; your repository is not written" if "run" in argv else
            "resumes a parked effect on a fresh check; the proposer is not called again" if "resume" in argv else "see the exact command below")
    rows = [sec("IN SHORT", width), *kv("does", does, width, 10, "text")]
    repo = after("--source-repo") or after("--repo")
    if repo:
        rows.extend(kv("repo", _mid_ellipsis(_tilde_path(repo), max(8, width - 12)), width, 10, "dim"))
    patch, manifest = after("--patch-sha256"), after("--manifest-sha256")
    if patch or manifest:
        rows.extend(kv("binds", " · ".join(x for x in (f"patch {_clean(patch)[:12]}…" if patch else "", f"manifest {_clean(manifest)[:12]}…" if manifest else "") if x), width, 10, "dim"))
    if argv:
        rows.extend(kv("python", _mid_ellipsis(_tilde_path(argv[0]), max(8, width - 12)), width, 10, "dim"))
    rows.append([])
    return rows


def _evidence_tabs(active_drill: str | None, width: int) -> list[Seg] | None:
    """Stitch evidence tab strip on verdict drill-ins: active view pill + sibling jump hints."""
    tabs = [("witness", "w", "WITNESS"), ("prov", "p", "PROVENANCE"), ("unexp", "u", "UNEXPLORED"), ("diff", "d", "DIFF")]
    if active_drill not in {t[0] for t in tabs} or width < 38:
        return None
    compact = width < 62
    segs: list[Seg] = []
    for i, (did, key, label) in enumerate(tabs):
        if i:
            segs.append(s("  ", "text"))
        short = {"WITNESS": "WIT", "PROVENANCE": "PROV", "UNEXPLORED": "UNEXP", "DIFF": "DIFF"}[label] if compact else label
        text = f" [{key}] {short} " if did == active_drill else f"[{key}] {short}"
        segs.append(s(text, "selected" if did == active_drill else "dim"))
    return fit(segs, width)


def _help_rows(vs, context, artifact) -> list:
    """The keys of the screen the operator is on, ONE key per row, each doing exactly what the row says here. Anything the footer shows is listed; nothing is listed that this screen
    ignores. (Samples keep the reference's keymap.)"""
    common = [["enter", "act on the focused element"], ["↑ ↓", "move focus"], ["tab", "next element · shift-tab back"], ["esc", "close · back one step · never stops a run"]]
    tail = [["pgup", "scroll up"], ["pgdn", "scroll down"], ["R", "motion on / off (static mode)"], ["?", "this list"]]
    st = vs.st
    if st == "offer":
        rows = [["s", "other sources"], ["h", "recorded runs"], ["r", "read the repository again (a new snapshot)"], ["A", "local agent command · separate mode"], ["q", "quit"]]
    elif st == "selection":
        rows = [["space", "include or leave out the file or source"], ["d", "full diff"], ["A", "local agent command · separate mode"], ["q", "quit"]]
    elif st == "claim":
        rows = [["c", "the exact command (after it was reviewed)"], ["d", "full diff"], ["q", "quit"]]
    elif st == "running":
        rows = [["x", "cancel the check (asks first)"], ["q", "detach: the check keeps running"], ["d", "diff"]]
    elif st == "verdict":
        rows = [["w", "witness, or why there is none"], ["p", "provenance of the decision"], ["u", "what was not explored"], ["d", "full diff"]]
        if _apply_candidate(artifact, context):
            rows.append(["l", "review applying to your repository"])
            rows.append(["a", "review applying to your repository (alias)"])
        if _approval_candidate(artifact):
            rows.append(["i", "review and approve declared deltas"])
        if _copy_note_hint(artifact):
            rows.append(["c", "copy the refusal for your agent"])
        if _new_check_hint(artifact, context):
            rows.append(["n", "a new check of the same change"])
        rows.append(["q", "quit"])
    elif st == "blocked":
        rows = [["r", _r_help(vs, context)], ["c", "copy"], ["d", "view the change"], ["q", "quit"]]
    elif st in {"artifact-unavailable", "run-ended-no-decision", "run-lost"}:
        rows = [["r", _r_help(vs, context)], ["c", "copy the folder path"], ["q", "quit"]]
    elif st == "history":
        rows = [["q", "quit"]]
    else:
        rows = [["q", "quit"]]
    return [*common, *rows, *tail]


def _kib(n) -> str:
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KiB" if n < 1024 * 1024 else f"{n / 1048576:.1f} MiB"


def _python_origin(source) -> str:
    """Where the target interpreter choice came from, in words (the host's recorded `source`: '--target-python', 'launcher default', or the repository venv it detected)."""
    source = str(source or "").strip()
    return ("chosen with --target-python" if source == "--target-python" else "Hlith's own (launcher default)" if source == "launcher default"
            else f"detected in the repository ({_clean(source)})" if source else "origin not recorded")


def _readiness_rows(context, rw):
    """Two quiet rows: is the boundary ready, is the target python ready (the recorded detail wraps under its column)."""
    rd = context.get("readiness", {}) if isinstance(context.get("readiness"), dict) else {}
    out = []
    for name in ("boundary", "python"):
        row = rd.get(name)
        if isinstance(row, dict):
            status_, tone_ = str(row.get("status", "not recorded")), row.get("tone", "dim")
            if name == "boundary":
                detail = str(row.get("detail", "not recorded"))
            else:
                ver = str(row.get("version", "")).strip()
                # the interpreter the check will really use (the target's own dependencies must import in it) and WHERE the choice came from; both are the host's recorded readiness
                source = str(row.get("source", "")).strip()
                origin = _python_origin(source)
                path = _middle_path(_tilde_path(row.get("path")), max(12, rw - 14)) if row.get("path") else ""
                detail = " · ".join(x for x in ("" if ver in ("", "not probed") else ver, path, origin) if x)
        else:
            status_, tone_, detail = ("ready", "ok", str(row).removeprefix("ready · ")) if row else ("not checked", "dim", "not recorded")
        out.extend(_status_kv(name, status_, tone_, detail, rw))
        if name == "python" and isinstance(row, dict):
            ver_s = str(row.get("version", "")).strip()
            if ver_s and ver_s != "not probed":
                from ..target_python import REFERENCE_VERSION, qualification as _py_qual

                if ver_s != REFERENCE_VERSION:
                    qual = _py_qual(ver_s)
                    if qual:
                        out.extend(_status_kv("", "note", "warn", _clean(qual), rw))
            if row.get("warning"):
                out.extend(_status_kv("", "warning", "warn", _clean(str(row["warning"])), rw))
    return out


def _status_kv(name, status, tone, detail, width, label_width=10):
    """'name  status · detail' with the status word toned and the detail wrapped under its own column."""
    text = status + (" · " + detail if detail else "")
    lines = wrap(text, max(4, width - label_width))
    out = []
    for i, line in enumerate(lines):
        label = s(fs(name if i == 0 else "", label_width), "dim")
        if i == 0 and line.startswith(status):
            out.append([label, s(status, tone), s(line[len(status):], "dim")])
        else:
            out.append([label, s(line, "dim")])
    return out


def _review_only() -> bool:
    """Hlith Review posture (product.REVIEW_ONLY): the terminal screen starts no check, so live text never says Enter starts one."""
    from ..product import REVIEW_ONLY
    return bool(REVIEW_ONLY)


def _blocked_unavailable(context) -> bool:
    """The Hlith Review refusal of Enter on the Claim: nothing was created or run (not a run that could not be followed)."""
    return isinstance(context, dict) and isinstance(context.get("blocked"), dict) and bool(context["blocked"].get("unavailable"))


def _blocked_run(vs, context) -> bool:
    """A blocked screen for a run that WAS started but cannot be followed: a no-decision state, not a failed assessment of the host."""
    return vs.st == "blocked" and isinstance(context, dict) and isinstance(context.get("blocked"), dict) and context["blocked"].get("kind") == "run"


def _event_rows(context, width, count) -> list:
    """Inline EVENTS (Running): the last `count` REAL engine events (ts / phase / what) from the run's own event file; the latest row is marked, a freshly arrived real event id is emphasised for
    its cue's lifetime. Nothing simulated: with no event yet the block says what it is waiting for."""
    tail = context.get("event_tail") if isinstance(context.get("event_tail"), list) else []
    if not tail:
        return [[s("EVENTS", "label")], [s("waiting for the engine's first event", "dim")]]
    fresh = {i for (rk, i) in ((context.get("motion") or {}).get("events") or ()) if rk == context.get("event_run_key")}
    shown = tail[-count:]
    out = [[s("EVENTS", "label")]]
    for n, ev in enumerate(shown):
        hot = ev.get("id") in fresh
        phase_ = str(ev.get("phase", "-"))[:11]
        out.append(fit([s("▸ " if n == len(shown) - 1 else "  ", "bold"), s(str(ev.get("ts", "--:--:--")), "emph" if hot else "dim"), s("  ", "text"), s(phase_, "emph" if hot else "text"),
                        s(" " * (12 - len(phase_)), "text"), s(str(ev.get("what", "")), "emph" if hot else "text")], width))  # the cue touches the words only, never the padding between them
    return out


def _records_text(context, repo) -> str:
    """The RECORDS line, always in agreement with what the screen shows: while the history scan is pending and nothing is known yet it says so (never 'none yet'); with rows in hand a stale
    'none yet' placeholder is replaced by their count."""
    rows = context.get("history_rows") if isinstance(context.get("history_rows"), list) else []
    text = str(repo.get("records", "not scanned"))
    if context.get("history_scan_complete") is False and not rows:
        return "scanning history…"
    if rows and text.startswith(("none yet", "0 record", "no record", "reading history")):
        return f"{len(rows)} record{'s' if len(rows) != 1 else ''}"
    return text


def history_state_text(row) -> str:
    """A recorded run's state in words. With an artifact the decision word comes from the artifact (frame._decision, the one mapping). WITHOUT one the label never claims more than the record
    holds: if the run's own event file records a gate decision, that exit status is shown as the event log's literal text and its source is named; else 'no artifact recorded'."""
    rc = row.get("rc")
    if row.get("decision"):
        return f"FINISHED · {row['decision']}"
    gate = row.get("gate_exit")
    if isinstance(gate, int) and not isinstance(gate, bool):
        return f"FINISHED · no artifact · gate decision exit {gate} (from the event log)"
    return f"FINISHED · no artifact recorded (exit {rc})"


def dim_behind(styles, bg_rows) -> None:
    """In place: every cell NOT inside a modal panel (bg 'p') drops to the quiet text tone; rules and hints stay as they are. Display only: no text or action changes."""
    keep = {"rule", "hint", "dim", "label"}
    for y, row in enumerate(styles):
        bg = bg_rows[y] if y < len(bg_rows) else ""
        for x, tone in enumerate(row):
            if x < len(bg) and bg[x] == "z":
                continue  # the status / key band stays undimmed: it is the footer the modal's own keys live in
            if (x >= len(bg) or bg[x] != "p") and tone not in keep:
                row[x] = "dim"


def _sys_modules():
    import sys

    return sys.modules


def render(vs, cols: int, rows: int, artifact: dict, *, elapsed=0, sample=False, context=None,
           color="truecolor", size=None, _wide=True, _dock=True):
    """One immutable state snapshot -> exact terminal cells, whatever the pane size. The layout itself reflows from the real size; this wrapper is the last safety net of the cell grid: a pane with fewer
    rows than the fixed chrome needs keeps the top and the status row, and no row is ever wider than the pane (a frame that overflowed would scroll the terminal)."""
    out = _render_cells(vs, cols, rows, artifact, elapsed=elapsed, sample=sample, context=context, color=color, size=size, _wide=_wide, _dock=_dock)
    try:
        c, r = max(0, int(vs.cols if size is None and not cols else cols)), max(0, int(rows))
    except (TypeError, ValueError):
        return out
    if len(out._text) > r or any(len(x) > c for x in out._text):
        keep = (lambda seq: list(seq) if len(seq) <= r else [*seq[:max(0, r - 1)], *seq[-1:]] if r > 0 else [])
        out._text = [x[:c] for x in keep(out._text)]
        out._styles = [list(x)[:c] for x in keep(out._styles)]
        out._bg = [x[:c] for x in keep(out._bg)]
    return out


def _render_cells(vs, cols: int, rows: int, artifact: dict, *, elapsed=0, sample=False, context=None,
                  color="truecolor", size=None, _wide=True, _dock=True):
    """Render one immutable state snapshot into exact terminal cells.

    ``size`` is accepted for resize-storm callers; explicit dimensions remain
    authoritative when supplied by the host.
    """
    if size is not None:
        try:
            cols, rows = size
        except (TypeError, ValueError):
            pass
    cols, rows = max(0, int(cols)), max(0, int(rows))
    global _SYNTAX
    _SYNTAX = bool(isinstance(context, dict) and context.get("syntax") and not sample)
    if cols < COMPACT_MIN_COLS or rows < COMPACT_MIN_ROWS:
        return _word_safe_small(vs, cols, rows, artifact, context)
    if False and _dock and not sample and not vs.drill:  # the always-on Event Log dock is retired (B): real events show inline on Running only
        from . import wide as _dock_mod

        dock_h = _dock_mod.dock_height(cols, rows)
        if dock_h:
            core = render(vs, cols, rows - dock_h, artifact, elapsed=elapsed, sample=sample, context=context, color=color, size=None, _wide=_wide, _dock=False)
            lines = _dock_mod.dock_lines(_sys_modules()[__name__], vs, cols, dock_h, artifact, _sample(context, sample))
            d_text = ["".join(g.text for g in line) for line in lines]
            d_style = [[g.tone for g in line for _ in g.text] for line in lines]
            d_bg = ["." * cols for _ in lines]
            if vs.overlay:
                dim_behind(d_style, d_bg)  # the dock is part of what recedes behind a modal
            return Frame([*core._text[:-2], *d_text, *core._text[-2:]], [*core._styles[:-2], *d_style, *core._styles[-2:]], [*core._bg[:-2], *d_bg, *core._bg[-2:]],
                         [f.action for f in core.focus_order], core.color, visibility=core._visibility)
    if _wide and cols >= 100:
        import sys as _sys

        from . import wide as _wide_mod

        wide_frame = _wide_mod.render(_sys.modules[__name__], vs, cols, rows, artifact, elapsed=elapsed, sample=sample, context=context, color=color, size=None)
        if wide_frame is not None:
            return wide_frame
    validation_errors = _validation_errors(artifact)
    decision = _decision(artifact, validation_errors)
    integrity_errors = _integrity_errors(artifact, decision) if not validation_errors else []
    context = _sample(context, sample)
    if sample and vs.st == "verdict" and context and _verdict_context(artifact, context, decision)[0] == "unknown":
        # Sample facts are bound to the recorded decision they describe. A
        # contradictory outcome/status pair cannot borrow sample prose.
        context = {}
    is_sample = bool(sample)
    composed = _compose(vs, cols, rows, artifact, elapsed, sample, context, decision, validation_errors,
                        integrity_errors)
    margin = composed["margin"]
    pin = [fit([*sp(margin), *line], cols) for line in composed["pin"]]
    has_bottom_rule = rows >= 26
    chrome_rows = 5 if has_bottom_rule else 4
    body_height = max(0, rows - chrome_rows - len(pin))
    body = [fit([*sp(margin), *line], cols) for line in composed["body"]]
    start = max(0, min(max(0, int(vs.scroll)), max(0, len(body) - body_height)))
    focus_line = composed["focus_line"]
    claim_command_review = vs.st == "claim" and bool(context.get("command"))
    follow_focus = (composed["focus_index"] > 0 or vs.focusIndex > 0
                    or (vs.scroll > 0 and not claim_command_review))
    if focus_line is not None and follow_focus:
        focus_last = focus_line + (1 if vs.st == "history" else 0)  # a history row is two lines: both stay clear of the '↓ more' marker
        if focus_line < start:
            start = focus_line
        elif focus_last > start + body_height - 2:
            start = focus_last - body_height + 2
    start = max(0, min(start, max(0, len(body) - body_height)))
    visible = body[start:start + body_height]
    visible.extend([fit([], cols) for _ in range(body_height - len(visible))])
    def scroll_marker(line, marker):
        flat = "".join(part.text for part in line)
        suffix = " · u" if flat.endswith(" · u") else ""
        marker_width = _width([s(marker, "hint")])
        suffix_width = _width([s(suffix, "hint")])
        return (_slice(line, 0, max(0, cols - GUTTER - marker_width - suffix_width))
                + [s(marker, "hint")] + ([s(suffix, "hint")] if suffix else []) + sp(GUTTER))  # the cue ends on the gutter, like every other row
    if visible and start > 0:
        visible[0] = scroll_marker(visible[0], " ↑ more  pgup ")
    if visible and start + body_height < len(body):
        visible[-1] = scroll_marker(visible[-1], " ↓ more  pgdn ")
    replaced_body_rows = set()
    if start > 0 and body_height:
        replaced_body_rows.add(start)
    if start + body_height < len(body) and body_height:
        replaced_body_rows.add(start + body_height - 1)
    visible = pin + visible

    word, tone, status = decision
    run_id = _run_id(artifact, sample, context, decision)
    repo = _sample(context, sample).get("repo", {})
    artifact_base = (artifact.get("run") or {}).get("base_commit_sha")
    base = ("no base commit" if not sample and repo.get("has_base") is False else
            _short_commit_id(repo.get("head") if not sample and repo.get("head") else artifact_base))
    branch = repo.get("branch", "trial") if context else "trial"
    repo_label = str(repo.get("name", "requests"))
    if vs.st == "history" and context.get("repository_loading") and repo.get("path"):
        repo_label = Path(str(repo["path"])).name or repo_label  # never a stale 'reading repository…' beside a loaded list
    if repo.get("identity_source") == "launch record":
        repo_label += " · launch record"
    # one calm top row: ' hlith · <repo>[ › crumb]' on the left, the step (or the state's own word) on the right; run id and branch@base live in the status line
    inner = cols - 2 * GUTTER
    right_head = []
    if vs.st == "blocked":
        right_head = [s("not available in Hlith Review" if _blocked_unavailable(context) else "run could not be followed" if _blocked_run(vs, context) else "unable to assess", "warn")]
    elif vs.st == "artifact-unavailable":
        right_head = [s("artifact unavailable", "warn")]
    elif vs.st in {"run-ended-no-decision", "run-lost"}:
        right_head = [s("run cancelled" if (context.get("run_failure") or {}).get("cancelled") else "run ended without a decision" if vs.st == "run-ended-no-decision" else "run lost", "dim" if (context.get("run_failure") or {}).get("cancelled") else "warn")]
    else:
        active_step = composed["step"]
        step_names = ["change", "claim", "check", "dec" if cols < 64 else "decision"]
        rail_b = []
        for i, name in enumerate(step_names):
            if i:
                rail_b.append(s(" › ", "hint"))
            m_ = context.get("motion") or {}
            rail_b.append(s(name, ("emph" if (m_.get("step") or (m_.get("verdict") and vs.st == "verdict")) else "bold") if i == active_step else "dim" if i < active_step else "hint"))
        right_head = rail_b
    crumb_b = [s(" › ", "hint"), s(composed["crumb"], "dim")] if composed["crumb"] else []
    repo_budget = max(3, inner - _width(right_head) - 3 - len("hlith · ") - _width(crumb_b))
    head = [*sp(GUTTER), *lr([s("hlith", "bold"), s(" · " + fs(repo_label, repo_budget).rstrip(), "dim"), *crumb_b], right_head, inner)]

    phrase = {"offer": "no check started", "history": "recorded runs", "selection": "choosing a change", "claim": "not yet run",
              "running": "disposable clone", "verdict": run_id,
              "blocked": "boundary unavailable", "artifact-unavailable": "artifact unavailable",
              "run-ended-no-decision": "no decision", "run-lost": "no decision"}.get(vs.st, "no check started")
    if vs.st == "running" and not sample and isinstance(context.get("event_tail"), list) and context["event_tail"]:
        last_ = context["event_tail"][-1]
        phrase = f"last event {last_.get('ts', '--:--:--')} {last_.get('phase', '-')}" + (f" · {last_.get('what')}" if cols >= 100 else "")
    if vs.st == "history" and len(context.get("history_rows", [])) > 1:
        # the position never scrolls away with the list header: always in the status line
        phrase = f"recorded runs · {min(max(0, vs.focusIndex), len(context['history_rows']) - 1) + 1} of {len(context['history_rows'])}"
    if vs.st == "blocked" and isinstance(context.get("blocked"), dict) and context["blocked"].get("reason"):
        # the middle of the status line names THIS cause: 'boundary unavailable' is only true of the boundary state
        phrase = ("no check started" if _blocked_unavailable(context) else
                  {"artifact": "artifact unavailable", "run": "run could not be followed"}.get(context["blocked"].get("kind"), "repository not inspected"))
    decision_headline = word
    original = ("UNVALIDATED record" if integrity_errors else
                "original: committed by engine" if is_sample else _landing_status_text(artifact)) if vs.st == "verdict" and decision_headline == "LANDED" else (
        "original read-only" + (" · remembered repository" if context.get("remembered_repo") else ""))
    if (not is_sample and not integrity_errors and vs.st == "verdict" and decision_headline == "LANDED"
            and cols == 80 and rows == 24 and _valid_commit_id(artifact.get("landed_commit"))):
        original = f"commit {str(artifact['landed_commit'])[:8]}" + ("" if (artifact.get("run") or {}).get("landing_target") in {"original", "rehearsal"} else " · target not recorded")
        if " · target not recorded" in original:
            phrase = ""  # the whole fact outranks the run id in the 80-column status line
            if str(branch).startswith("branch not recorded"):
                branch = "no branch"
    if vs.st == "verdict" and cols <= 100 and str(branch).startswith("branch not recorded") and phrase:
        branch = "no branch"  # the whole run id in the status line outranks the longer 'branch not recorded' wording at narrow widths
    identity = [s(f"{branch}@{base}")]
    if (vs.st == "blocked" and isinstance(context.get("blocked"), dict) and context["blocked"].get("kind") not in {"artifact", "run"}
            and str(base).startswith("not recorded")):
        identity, phrase = [s("no repository")], "nothing was read"  # TUI behavior (review R3 walkthrough): 'not recorded@not recorded' named no cause; a directory that is not a repository has no branch or base
    left = [*identity, s(" · ", "dim"), s(original), *([s(" · ", "dim"), s(phrase, "dim")] if phrase else [])]
    if vs.toast:
        right = [s(vs.toast + " ", "bold")]
    elif vs.st == "verdict":
        display_word, chip, _kindword, _kindtone = _decision_view(artifact, decision)
        if integrity_errors:
            chip = "chipWarn"
        display_word = "UNKNOWN" if display_word.startswith("UNKNOWN") else display_word
        status_text = str(status) if status is not None else "not recorded"
        right = [s(f" {display_word} ", chip), s(" exit " + status_text + " ")]
        if sample:
            right.append(s(" SAMPLE ", "sample"))
        right.append(s(" "))
    elif vs.st == "running":
        spin_ = (context.get("motion") or {}).get("spin") if not sample else None
        from .motion import SPINNER

        right = [*([s(SPINNER[spin_] + " ", "bold")] if isinstance(spin_, int) else []), s("no decision yet", "dim")]  # the spinner exists only while a real run is actively running
    elif vs.st == "blocked":
        right = [s(" NO DECISION " if _blocked_run(vs, context) else " UNABLE TO ASSESS ", "chipWarn"), s(" ")]
    elif vs.st == "artifact-unavailable":
        right = [s(" ARTIFACT UNAVAILABLE ", "chipWarn"), s(" ")]
    elif vs.st in {"run-ended-no-decision", "run-lost"}:
        right = [s(" NO DECISION ", "chip" if (context.get("run_failure") or {}).get("cancelled") else "chipWarn"), s(" ")]
    elif vs.st == "offer" and not sample:
        from .. import identity as _identity  # the first screen names the build (one source; 'dev build' when unknown); 'no check started' already says no decision

        tag_ = str(context.get("build_identity") or _identity.build_identity())  # the host computes it once at start; the fallback is a cached file read
        room_ = max(1, inner - len("hlith ") - 1)  # the identity outranks the left status text: the left yields first, and the identity shortens only in the MIDDLE
        if len(tag_) > room_ and room_ > 9:
            tag_ = tag_[:room_ - 9] + "…" + tag_[-8:]  # the last 8 characters (the short commit) are what tell two builds apart: never clipped
        elif len(tag_) > room_:
            tag_ = tag_[-room_:]
        right = [s("hlith " + tag_ + " ", "dim")]
    else:
        right = [s("no decision ", "dim")]
    status_line = [*sp(GUTTER), *lr(left, _rstrip_segs(right), cols - 2 * GUTTER)]
    # the footer is ONE primary action and a short secondary set; '?' holds the full key map (provenance / unexplored are p / u, named in the rows they belong to)
    visible_keys = [k for k in composed["keys"] if not (vs.st == "verdict" and not vs.drill and cols < 100 and k[2] in {"drill:prov", "drill:unexp"})]
    if cols < 100:
        visible_keys = visible_keys[:4]
    if vs.overlay and not sample:
        # a modal owns the keyboard: its footer shows ITS keys, not the screen behind it
        visible_keys = ([["esc", "close", "back"], ["enter", "close", "enter"]] if vs.overlay == "help" else
                        [["esc", "close", "back"]] if vs.overlay == "agent" else
                        [["tab", "other choice", "tab"], ["enter", "choose", "enter"], ["esc", "stay", "back"]])
    short_verdict_keys = False
    key_sep = 3
    if vs.st == "claim" or (vs.st in {"verdict", "artifact-unavailable", "run-ended-no-decision", "run-lost"}
                             and context.get("history_return") and not short_verdict_keys):
        visible_keys = [list(key) for key in composed["keys"]]
        if vs.st == "verdict" and context.get("history_return"):
            visible_keys = [[key, "history" if key == "esc" else label, action]
                            for key, label, action in visible_keys]
        right_key_width = _width([s("?", "key", "ov:help"), s(" keys ", "hint", "ov:help")])
        key_budget = max(0, cols - 2 * GUTTER - right_key_width - 2)

        def key_row_width(items):
            return (1 + max(0, len(items) - 1) * key_sep
                    + sum(_width([s(key, "key"), s(" " + label, "hint")]) for key, label, _action in items))

        if vs.st == "claim":
            drop_order = [("scroll", "pgup"), ("scroll", "pgdn"), ("drill:diff", "d")]
            if any(item[2] == "scroll" and item[0] == "pgdn" for item in visible_keys):
                # the command end is NOT yet reviewed: 'pgdn scroll command' is the key that matters and is dropped last (diff / move go first)
                drop_order = [("drill:diff", "d"), ("tab", "tab"), ("back", "esc")]
            for action, key in drop_order:
                if key_row_width(visible_keys) <= key_budget:
                    break
                visible_keys = [item for item in visible_keys if not (item[2] == action and item[0] == key)]
        elif context.get("history_return"):
            if key_row_width(visible_keys) > key_budget:
                key_sep = 2  # compress the separators before dropping a key: 'u unexplored' must stay reachable on a historical verdict at 100 columns
            for action, key in [("copy-note", "c"), ("drill:unexp", "u"), ("drill:prov", "p"), ("drill:diff", "d"),
                                ("drill:witness", "w"), ("enter", "enter"), ("tab", "↑↓")]:
                if key_row_width(visible_keys) <= key_budget:
                    break
                visible_keys = [item for item in visible_keys if not (item[2] == action and item[0] == key)]
    # width-budget packing (B): keys keep their order, the rightmost are dropped only when the row would not fit beside '? keys'; nothing is capped by count at >= 100 columns
    _rk = _width([s("?", "key", "ov:help"), s(" keys ", "hint", "ov:help")])
    _budget = max(0, cols - 2 * GUTTER - _rk - 2)
    _kw = lambda items: 1 + max(0, len(items) - 1) * key_sep + sum(_width([s(k, "key"), s(" " + lb, "hint")]) for k, lb, _a in items)  # noqa: E731
    while len(visible_keys) > 1 and _kw(visible_keys) > _budget:
        visible_keys = visible_keys[:-1]
    key_left = []
    for i, (key, label, action) in enumerate(visible_keys):
        if i:
            key_left.extend(sp(key_sep))
        key_left.extend([s(key, "key", action), s(" " + label, "hint", action)])
    key_line = [*sp(GUTTER), *lr(key_left, [s("?", "key", "ov:help"), s(" keys", "hint", "ov:help")], cols - 2 * GUTTER)]
    top_rule = [s("─" * cols, "rule")] if rows >= 6 else []
    bottom_rule = [[s("─" * cols, "rule")]] if has_bottom_rule else []
    rows_lines = [head, top_rule, *visible, *bottom_rule, status_line, key_line]
    bg_rows = ["." * cols for _ in rows_lines]
    bg_rows[-2] = "z" * cols
    bg_rows[-1] = "z" * cols  # the key hints and the status row are ONE solid full-width band (the Stitch footer band)

    overlay = composed["overlay"]
    overlay_rows = set()
    if overlay and overlay[1] >= 4:
        title, box_width, lines = overlay
        box = [[s("╭─ ", "rule"), s(title, "label"), s(" " + "─" * max(0, box_width - 5 - len(title)) + "╮", "rule")]]
        box.extend([[s("│ ", "rule"), *fit(line, box_width - 4), s(" │", "rule")] for line in lines])
        box.append([s("╰" + "─" * max(0, box_width - 2) + "╯", "rule")])
        x0 = max(0, (cols - box_width) // 2)
        y0 = max(2, (len(rows_lines) - len(box)) // 2)  # centred in the viewport, vertically as well as horizontally
        for iy, line in enumerate(box):
            y = y0 + iy
            if y >= len(rows_lines):
                break
            overlay_rows.add(y)
            left_segs = _slice(rows_lines[y], 0, x0)
            panel_line = [Seg(g.text, g.tone, g.action, True) for g in fit(line, box_width)]
            right_segs = _slice(rows_lines[y], x0 + box_width, cols)
            rows_lines[y] = left_segs + panel_line + right_segs
            bg_rows[y] = "." * x0 + "p" * min(box_width, max(0, cols - x0)) + "." * max(0, cols - x0 - box_width)

    text_rows, styles = [], []
    for line in rows_lines:
        full = fit(line, cols)
        text_rows.append("".join(g.text for g in full))
        styles.append([g.tone for g in full for _ in g.text])
    if overlay_rows:
        dim_behind(styles, bg_rows)  # a modal is the one thing to read: the screen behind it recedes (still legible)
    motion_ = context.get("motion") if isinstance(context, dict) else None
    if isinstance(motion_, dict) and motion_.get("verdict") and vs.st == "verdict" and not sample and not overlay_rows and len(styles) > 4:
        # a verdict that completed LIVE here: the result row (badge subtitle) reads stronger once; the words are already there
        for y_v in (3, 5):  # the result row and its explanatory sentence (the verdict's sublabel); the step breadcrumb is emphasised in the header
            cut = text_rows[y_v].find("│", 12)
            limit = cut if cut > 0 else len(text_rows[y_v])
            styles[y_v] = ["emph" if (x < limit and tone in {"bold", "text"} and text_rows[y_v][x:x + 1].strip() and text_rows[y_v][x] not in "─│▌▏") else tone for x, tone in enumerate(styles[y_v])]  # glyphs of the words only
    if isinstance(motion_, dict) and motion_.get("focus") and not sample and not overlay_rows:
        # a key-driven focus change: the focused row reads one notch stronger for the cue's lifetime (the neutral selected marker is already there); text, geometry and actions never change.
        # The span is the focused PANE's cells only (the screen's own cue span, else the part of the row left of the pane divider).
        cue = composed.get("cue")
        if cue is not None:
            body_row, x0, x1 = cue
            x0, x1 = x0 + margin, x1 + margin
        elif focus_line is not None:
            body_row, x0, x1 = focus_line, 0, cols
        else:
            body_row = None
        if body_row is not None:
            y_focus = 2 + len(pin) + body_row - start
            bottom_limit = len(styles) - (3 if has_bottom_rule else 2)
            if 2 + len(pin) <= y_focus < bottom_limit:
                if cue is None:
                    div_at = text_rows[y_focus].find("│", 12)
                    x1 = div_at if div_at > 0 else x1
                row_tones = styles[y_focus]
                chars = text_rows[y_focus]
                # ONLY the characters of the focused label / row text are re-toned: blank cells, rules and the pane divider are never touched, so no bar can appear across the screen
                styles[y_focus] = [(("emphSel" if tone in {"selected", "sel", "chipOk", "chipBad", "chipWarn"} else "emph" if tone in {"text", "bold", "key"} else tone)
                                    if (x0 <= x < x1 and chars[x:x + 1].strip() and chars[x] not in "─│▌▏") else tone) for x, tone in enumerate(row_tones)]
    def body_row_visible(index):
        if index is None or not start <= index < start + min(body_height, max(0, len(body) - start)):
            return False
        if index in replaced_body_rows:
            return False
        screen_row = 2 + len(pin) + index - start
        return screen_row not in overlay_rows

    command_rows = composed["command_body_rows"]
    visibility = {
        "claim_command_visible": bool(command_rows) and all(body_row_visible(index) for index in command_rows),
        "claim_command_end_visible": body_row_visible(composed["command_end_body_row"]),
        "claim_command_row_count": len(command_rows),
        "claim_command_visible_rows": tuple(i for i, index in enumerate(command_rows)
                                             if body_row_visible(index)),
    }
    out_frame = Frame(text_rows, styles, bg_rows, composed["items"], color, visibility=visibility)
    out_frame.nav = composed.get("nav", {})
    return out_frame

