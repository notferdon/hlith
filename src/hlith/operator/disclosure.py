# SPDX-License-Identifier: Apache-2.0
"""Limits the engine itself names in an obligation's ``unexplored`` text, surfaced in plain words next to a HELD verdict.

Read from the obligation text only (nothing is computed here). A HELD obligation covers the explored domain; L3 states that its
exploration is ANNOTATION-BOUNDED. Current L3 puts the fixed token ``ANNOTATION-BOUNDED:`` FIRST in ``evidence.unexplored`` (followed
by the annotated parameters), so it survives every one-line cut; older artifacts only carry the sentence "inputs violating declared
annotations are not explored" deep inside the text. Both forms are recognised: the token first, the old sentence as a fallback."""

from __future__ import annotations

import re

from ..textsafe import clean

TOKEN = "ANNOTATION-BOUNDED"
STATIC_TOKEN = "docstring-other-static:"  # case (3): a docstring-only HELD where unchanged callables were proven, not executed
OLD_PHRASE = "violating declared annotations are not explored"


def effect_rows(account) -> list[tuple[str, str]]:
    """A bounded reading view of the pipeline's recorded static effect account."""
    if not isinstance(account, dict) or not isinstance(account.get("analyzer_id"), str):
        return []
    rows = [("analyzer", account["analyzer_id"])]
    for field, label in (("modified_callables", "modified"), ("added_callables", "added"),
                         ("removed_callables", "removed"), ("impacted_sites", "caller"),
                         ("impacted_tests", "test in reach"), ("unknowns", "unknown")):
        entries = account.get(field)
        if not isinstance(entries, list):
            continue
        for entry in entries[:4]:
            if isinstance(entry, str):
                rows.append((label, entry))
            elif isinstance(entry, dict):
                if field == "impacted_sites":
                    rows.append((label, f"{entry.get('caller', '?')} at {entry.get('file', '?')}:{entry.get('line', '?')}"))
                elif field == "impacted_tests":
                    rows.append((label, str(entry.get("node_id", "?"))))
                elif field == "unknowns":
                    rows.append((label, f"{entry.get('code', '?')} at {entry.get('where', '?')}"))
        if len(entries) > 4:
            rows.append((label, f"+{len(entries) - 4} more in the artifact"))
        elif field == "impacted_tests" and not entries:
            rows.append((label, "none in the static account"))
    return rows


def checker_summary(provenance) -> str | None:
    if not isinstance(provenance, dict) or not isinstance(provenance.get("checker_id"), str):
        return None
    parts = [provenance["checker_id"]]
    if type(provenance.get("confined")) is bool:
        parts.append("confined" if provenance["confined"] else "unconfined")
    if type(provenance.get("proposer_paths_readable")) is bool:
        parts.append("proposer paths readable" if provenance["proposer_paths_readable"] else "proposer paths denied")
    return " · ".join(parts)

_TAIL = ("a caller passing an input that violates them is not covered by this verdict; the checked domain also comes from "
         "defaults, literals and test constants.")


def _unexplored(o) -> str:
    get = o.get if isinstance(o, dict) else (lambda k, d=None, _o=o: getattr(_o, k, d))
    ev = get("evidence") or {}
    return str(get("unexplored") or (ev.get("unexplored") if isinstance(ev, dict) else getattr(ev, "unexplored", "")) or "")


def _detail(text: str) -> str | None:
    """The part after 'ANNOTATION-BOUNDED:' up to the first ': inputs' / sentence end, e.g. 'parameter(s) n: int, s: str'."""
    i = text.find(TOKEN + ":")
    if i < 0:
        return None
    rest = text[i + len(TOKEN) + 1:].strip()
    m = re.split(r":\s+inputs\b|;\s|\.\s", rest, maxsplit=1)
    return (m[0].strip()[:140]) or None


def _is_held(o) -> bool:
    """True unless the row names a verdict other than HELD (the static-doc text is only ever shown for a HELD)."""
    v = o.get("verdict") if isinstance(o, dict) else getattr(o, "verdict", None)
    return v is None or str(getattr(v, "value", v)).lower() == "held"


_STATIC_N = re.compile(re.escape(STATIC_TOKEN) + r"\s*(\d{1,6}) callable\(s\) not executed")
_STATIC_CONST = ("code unchanged, no doc reader found in the touched module; "
                 "external/receiver-supplied readers not excluded")


def static_doc(obligations) -> str | None:
    """One plain note when a docstring-only HELD rests on a STATIC proof for some unchanged callables (not executed), else None.
    Emits ONLY constant text plus the parsed integer count: nothing sliced from the engine string reaches a terminal."""
    for o in obligations or ():
        m = _STATIC_N.search(_unexplored(o))
        if m and _is_held(o):
            return (f"HELD for a docstring-only edit rests partly on a static proof: {int(m.group(1))} callable(s) not executed: "
                    f"{_STATIC_CONST}")
    return None


def tag(o) -> str | None:
    """Short per-obligation tag for a HELD row: 'annotation-bounded (parameter(s) n: int)' / 'annotation-bounded', else None."""
    t = _unexplored(o)
    if TOKEN in t:
        d = _detail(t)
        return f"annotation-bounded ({d})" if d else "annotation-bounded"
    if _STATIC_N.search(t) and _is_held(o):
        return "static doc proof (unchanged callables not executed)"
    return "annotation-bounded" if OLD_PHRASE in t else None


def annotation_bound(obligations) -> str | None:
    """One plain note when any obligation names the annotation-bounded domain (keyed on the token, old sentence as fallback), else None."""
    for o in obligations or ():
        t = _unexplored(o)
        if TOKEN in t or OLD_PHRASE in t:
            d = _detail(t) if TOKEN in t else None
            head = "HELD is annotation-bounded" + (f" ({d})" if d else "")
            note = f"{head}: inputs that violate the declared annotations were NOT explored; {_TAIL}"
            sd = static_doc(obligations)  # both limits in one artifact: the annotation note keeps its text, the static note is appended
            return " ".join(clean(f"{note} {sd}" if sd else note).split())  # one sanitising point: every caller is safe
    sd = static_doc(obligations)
    return " ".join(clean(sd).split()) if sd else None


# kept for callers/tests that import the old names
ANNOTATION_PHRASE = OLD_PHRASE
ANNOTATION_NOTE = annotation_bound([{"unexplored": OLD_PHRASE}])
