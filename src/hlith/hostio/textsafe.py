# SPDX-License-Identifier: Apache-2.0
"""One helper for operator-visible text that comes from untrusted data (witnesses, reprs, names, reasons).

Terminal-control and layout-spoofing characters are replaced by a visible escape (`\\x1b`, `\\u202e`), never dropped
silently: C0 and C1 controls (ESC, CR, BS, BEL, NUL, ...), DEL, line/paragraph separators, bidi overrides, isolates and
marks, and the BOM / zero-width joiners used to hide text. Printable text, including non-Latin scripts, is kept."""

from __future__ import annotations

import unicodedata

MAX_MARKS = 2  # combining marks kept per base character; the excess is shown as a count


def _esc(ch: str) -> str:
    o = ord(ch)
    if o < 0x100:
        return {9: "\\t", 10: "\\n", 13: "\\r"}.get(o, f"\\x{o:02x}")
    return f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}"


def clean(text) -> str:
    """`text` with every non-printable character (str.isprintable: controls, ESC/CR, DEL, C1, line/paragraph separators,
    bidi controls, zero-width and invisible operators, Unicode Tag characters, lone surrogates, private-use and unassigned
    code points) replaced by its visible escape, and runs of combining marks capped at MAX_MARKS per base character
    (the excess becomes `[+N marks]`). Printable text, including non-Latin scripts, is kept. Always returns str."""
    s = text if isinstance(text, str) else str(text)
    if s.isprintable() and not any(unicodedata.category(c).startswith("M") for c in s):
        return s
    out: list[str] = []
    run = extra = 0
    for c in s:
        if c.isprintable() and unicodedata.category(c).startswith("M"):
            run += 1
            if run <= MAX_MARKS:
                out.append(c)
            else:
                extra += 1
            continue
        if extra:
            out.append(f"[+{extra} marks]")
        run = extra = 0
        out.append(c if c.isprintable() else _esc(c))
    if extra:
        out.append(f"[+{extra} marks]")
    return "".join(out)


def inspect(text) -> str:
    """Strict display for WITNESSES and delta listings, where two different inputs must never look alike: `clean`, plus
    every combining mark, every non-ASCII space (NBSP, ...), NUL/controls/zero-width characters and every astral code
    point shown as its escape. U+0065 U+0301 prints as `e\\u0301`, never as an identical-looking precomposed `\u00e9`;
    precomposed letters and other BMP text (`\u00e9`, CJK) are kept readable."""
    s = text if isinstance(text, str) else str(text)
    out: list[str] = []
    for c in s:
        o = ord(c)
        if o < 0x80:
            out.append(c if c.isprintable() else _esc(c))
        elif o > 0xFFFF or not c.isprintable() or unicodedata.category(c)[0] in ("M", "Z"):
            out.append(_esc(c))
        else:
            out.append(c)
    return "".join(out)
