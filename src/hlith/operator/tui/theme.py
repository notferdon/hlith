# SPDX-License-Identifier: Apache-2.0
"""Terminal styles for the operator TUI.

The default visual language translates the maintainer-selected 25-screen Stitch
design family natively into terminal primitives, degrading gracefully across
truecolor, 256-color, 16-color, 8-color native, monochrome (``NO_COLOR`` /
``HLITH_UI_MONO=1``), and plain non-TTY output.

Palette opt-ins via ``HLITH_UI_PALETTE``:
- ``stitch`` (default on color TTY; auto-switches to light when ``COLORFGBG``
  reports a light canvas background 7 or 15)
- ``stitch-light`` / ``stitch-dark``
- ``native`` (terminal's own canvas and 16-color semantic slots, zero 38/48)
- ``dainty``, ``dun``, ``rich``, ``dark`` / ``fixed``
"""

from __future__ import annotations

import os

# name: (fg256, bg256, fg16, bg16, attrs)   attrs: b=bold d=dim r=reverse u=underline
BG, BG_CODE, BG_SEL = 232, 234, 253
RICH = {
    "":          (254, BG, 7, -1, ""),            # text      #e7e7e4
    "bold":      (255, BG, 7, -1, "b"),
    "dim":       (248, BG, 7, -1, ""),            # secondary text  (8.4:1 on the pane)
    "label":     (245, BG, 7, -1, ""),            # section labels (5.8:1)
    "hint":      (244, BG, 7, -1, ""),            # hints, provenance (5.1:1): the quietest TEXT, still above WCAG AA 4.5:1
    "key":       (255, BG, 7, -1, "b"),
    "rule":      (241, BG, 7, -1, ""),            # rules are not text: >= 3:1 (WCAG 1.4.11), no dim attribute that a terminal may fade further
    "ok":        (78, BG, 2, -1, ""),
    "bad":       (203, BG, 1, -1, ""),
    "warn":      (179, BG, 3, -1, ""),
    "okb":       (78, BG, 2, -1, "b"),
    "badb":      (203, BG, 1, -1, "b"),
    "warnb":     (179, BG, 3, -1, "b"),
    "chip.ok":   (BG, 78, 0, 2, "b"),
    "chip.bad":  (BG, 203, 0, 1, "b"),
    "chip.warn": (BG, 179, 0, 3, "b"),
    "chip.text": (BG, 254, 0, 7, "b"),
    "code":      (252, BG_CODE, 7, -1, ""),
    "sel":       (232, BG_SEL, 0, 7, "b"),
    "code.bold": (255, BG_CODE, 7, -1, "b"),         # text on the code/action band
    "code.dim":  (248, BG_CODE, 7, -1, ""),
    "code.warn": (179, BG_CODE, 3, -1, "b"),
    "add":       (78, BG, 2, -1, ""),
    "addBg":     (78, 22, 2, -1, ""),
    "del":       (203, BG, 1, -1, ""),
    "delHi":     (231, 160, 7, 1, "b"),
    "btnBad":    (231, 160, 7, 1, "b"),
    "hunk":      (244, BG, 7, -1, ""),
    "meta":      (245, BG, 7, -1, ""),
    "srchi":     (179, 236, 3, -1, ""),
    "gauge":     (110, BG, 6, -1, ""),
    "gauge.bad": (203, BG, 1, -1, ""),
    "box":       (254, 235, 7, -1, ""),           # overlays (help, repository picker)
    "box.dim":   (248, 235, 7, -1, ""),
    "box.b":     (255, 235, 7, -1, "b"),
    "box.sel":   (255, 238, 7, -1, "b"),
    "kw": (254, BG, 7, -1, ""), "str": (254, BG, 7, -1, ""), "com": (248, BG, 7, -1, ""), "num": (254, BG, 7, -1, ""), "fn": (255, BG, 7, -1, "b"),  # (syntax tones are emitted only for the dainty / dun presets)
    "emph":      (255, BG, 7, -1, "b"),           # one-shot motion cue (focus / new event): brighter + bold on the TEXT cells only; never an underline (a line under blank cells read as a stray rule)
    "emphSel":   (BG, 255, 0, 7, "b"),
}
MONO = {"": "", "bold": "b", "dim": "d", "label": "d", "hint": "d", "key": "b", "rule": "d", "ok": "", "bad": "", "warn": "", "okb": "b", "badb": "b", "warnb": "b",
        "chip.ok": "rb", "chip.bad": "rb", "chip.warn": "rb", "chip.text": "rb", "code": "u", "code.bold": "ub", "code.dim": "u", "code.warn": "ub", "sel": "rb",
        "add": "", "addBg": "", "del": "", "delHi": "rb", "btnBad": "rb", "hunk": "d", "meta": "d",
        "srchi": "r", "gauge": "", "gauge.bad": "b", "box": "", "box.dim": "d", "box.b": "b", "box.sel": "rb", "emph": "b", "emphSel": "rb", "kw": "", "str": "", "com": "", "num": "", "fn": "b"}
# Stitch visual direction (maintainer-selected 25-screen design family, translated natively to terminal cells).
# Every readable role is verified >= 4.5:1 WCAG AA on its surface; critical failures keep underline as well as red;
# semantic words and markers carry all meaning independently of color.
STITCH_DARK_BG, STITCH_DARK_PANEL, STITCH_DARK_BAND = "#0A0A0A", "#141414", "#0E0E0E"
STITCH_DARK = {
    "":          ("#F2F2F0", None, ""),
    "text":      ("#F2F2F0", None, ""),
    "bold":      ("#F2F2F0", None, "b"),
    "dim":       ("#A3A3A3", None, ""),
    "label":     ("#A3A3A3", None, "b"),
    "hint":      ("#808080", None, ""),
    "key":       ("#F2F2F0", None, "b"),
    "rule":      ("#808080", None, ""),
    "meta":      ("#808080", None, ""),
    "ok":        ("#6EE7B7", None, ""),
    "okb":       ("#6EE7B7", None, "b"),
    "warn":      ("#FCD34D", None, ""),
    "warnb":     ("#FCD34D", None, "b"),
    "bad":       ("#FF453A", None, "bu"),
    "badb":      ("#FF453A", None, "bu"),
    "chip.ok":   ("#6EE7B7", "#0F2E1E", "b"),
    "chip.warn": ("#FDE68A", "#292008", "b"),
    "chip.bad":  ("#FFFFFF", "#DC2626", "b"),
    "chip.text": ("#0A0A0A", "#F2F2F0", "b"),
    "sample":    ("#FDE68A", "#292008", "b"),
    "sel":       ("#0A0A0A", "#F2F2F0", "b"),
    "btnBad":    ("#FFFFFF", "#DC2626", "b"),
    "code":      ("#F2F2F0", "#141414", ""),
    "code.bold": ("#F2F2F0", "#141414", "b"),
    "code.dim":  ("#A3A3A3", "#141414", ""),
    "code.warn": ("#FCD34D", "#141414", "b"),
    "add":       ("#6EE7B7", None, ""),
    "addBg":     ("#6EE7B7", "#0F2E1E", ""),
    "del":       ("#FF453A", None, ""),
    "delHi":     ("#FFFFFF", "#DC2626", "b"),
    "hunk":      ("#808080", None, ""),
    "srchi":     ("#0A0A0A", "#FCD34D", ""),
    "gauge":     ("#A3A3A3", None, ""),
    "gauge.bad": ("#FF453A", None, "b"),
    "box":       ("#F2F2F0", "#141414", ""),
    "box.dim":   ("#A3A3A3", "#141414", ""),
    "box.b":     ("#F2F2F0", "#141414", "b"),
    "box.sel":   ("#0A0A0A", "#F2F2F0", "b"),
    "emph":      ("#FFFFFF", None, "b"),
    "emphSel":   ("#0A0A0A", "#FFFFFF", "b"),
    "kw":        ("#A3A3A3", None, ""),
    "str":       ("#DADD99", None, ""),
    "com":       ("#808080", None, ""),
    "num":       ("#F2F2F0", None, ""),
    "fn":        ("#F2F2F0", None, "b"),
}
STITCH_LIGHT_BG, STITCH_LIGHT_PANEL, STITCH_LIGHT_BAND = "#FAFAFA", "#EFEFEF", "#F2F2F0"
STITCH_LIGHT = {
    "":          ("#0A0A0A", None, ""),
    "text":      ("#0A0A0A", None, ""),
    "bold":      ("#0A0A0A", None, "b"),
    "dim":       ("#525252", None, ""),
    "label":     ("#525252", None, "b"),
    "hint":      ("#6B6B6B", None, ""),
    "key":       ("#0A0A0A", None, "b"),
    "rule":      ("#6B6B6B", None, ""),
    "meta":      ("#6B6B6B", None, ""),
    "ok":        ("#065F46", None, ""),
    "okb":       ("#065F46", None, "b"),
    "warn":      ("#92400E", None, ""),
    "warnb":     ("#92400E", None, "b"),
    "bad":       ("#B91C1C", None, "bu"),
    "badb":      ("#B91C1C", None, "bu"),
    "chip.ok":   ("#065F46", "#D1FAE5", "b"),
    "chip.warn": ("#78350F", "#FEF3C7", "b"),
    "chip.bad":  ("#FFFFFF", "#B91C1C", "b"),
    "chip.text": ("#FFFFFF", "#171717", "b"),
    "sample":    ("#78350F", "#FEF3C7", "b"),
    "sel":       ("#FFFFFF", "#171717", "b"),
    "btnBad":    ("#FFFFFF", "#B91C1C", "b"),
    "code":      ("#0A0A0A", "#EFEFEF", ""),
    "code.bold": ("#0A0A0A", "#EFEFEF", "b"),
    "code.dim":  ("#525252", "#EFEFEF", ""),
    "code.warn": ("#92400E", "#EFEFEF", "b"),
    "add":       ("#065F46", None, ""),
    "addBg":     ("#065F46", "#D1FAE5", ""),
    "del":       ("#B91C1C", None, ""),
    "delHi":     ("#FFFFFF", "#B91C1C", "b"),
    "hunk":      ("#6B6B6B", None, ""),
    "srchi":     ("#FFFFFF", "#92400E", ""),
    "gauge":     ("#525252", None, ""),
    "gauge.bad": ("#B91C1C", None, "b"),
    "box":       ("#0A0A0A", "#EFEFEF", ""),
    "box.dim":   ("#525252", "#EFEFEF", ""),
    "box.b":     ("#0A0A0A", "#EFEFEF", "b"),
    "box.sel":   ("#FFFFFF", "#171717", "b"),
    "emph":      ("#000000", None, "b"),
    "emphSel":   ("#FFFFFF", "#000000", "b"),
    "kw":        ("#525252", None, ""),
    "str":       ("#065F46", None, ""),
    "com":       ("#6B6B6B", None, ""),
    "num":       ("#0A0A0A", None, ""),
    "fn":        ("#0A0A0A", None, "b"),
}
# Verified AA (>= 4.5:1) xterm-256 degradation for Stitch dark and light: (fg256, bg256 or None, attrs).
STITCH_256_BG, STITCH_256_PANEL, STITCH_256_BAND = 232, 233, 233
STITCH_256 = {
    "": (255, None, ""), "text": (255, None, ""), "bold": (255, None, "b"), "dim": (248, None, ""),
    "label": (248, None, "b"), "hint": (244, None, ""), "key": (255, None, "b"), "rule": (244, None, ""),
    "meta": (244, None, ""), "ok": (115, None, ""), "okb": (115, None, "b"), "warn": (221, None, ""),
    "warnb": (221, None, "b"), "bad": (203, None, "bu"), "badb": (203, None, "bu"),
    "chip.ok": (115, 22, "b"), "chip.warn": (222, 58, "b"), "chip.bad": (231, 160, "b"),
    "chip.text": (232, 255, "b"), "sample": (222, 58, "b"), "sel": (232, 255, "b"), "btnBad": (231, 160, "b"),
    "code": (255, 233, ""), "code.bold": (255, 233, "b"), "code.dim": (248, 233, ""), "code.warn": (221, 233, "b"),
    "add": (115, None, ""), "addBg": (115, 234, ""), "del": (203, None, ""), "delHi": (231, 160, "b"),
    "hunk": (244, None, ""), "srchi": (232, 221, ""), "gauge": (248, None, ""), "gauge.bad": (203, None, "b"),
    "box": (255, 233, ""), "box.dim": (248, 233, ""), "box.b": (255, 233, "b"), "box.sel": (232, 255, "b"),
    "emph": (231, None, "b"), "emphSel": (232, 231, "b"),
    "kw": (248, None, ""), "str": (186, None, ""), "com": (244, None, ""), "num": (255, None, ""), "fn": (255, None, "b"),
}
STITCH_LIGHT_256_BG, STITCH_LIGHT_256_PANEL, STITCH_LIGHT_256_BAND = 231, 255, 255
STITCH_LIGHT_256 = {
    "": (232, None, ""), "text": (232, None, ""), "bold": (232, None, "b"), "dim": (240, None, ""),
    "label": (240, None, "b"), "hint": (241, None, ""), "key": (232, None, "b"), "rule": (241, None, ""),
    "meta": (241, None, ""), "ok": (22, None, ""), "okb": (22, None, "b"), "warn": (94, None, ""),
    "warnb": (94, None, "b"), "bad": (124, None, "bu"), "badb": (124, None, "bu"),
    "chip.ok": (22, 194, "b"), "chip.warn": (94, 230, "b"), "chip.bad": (231, 124, "b"),
    "chip.text": (231, 234, "b"), "sample": (94, 230, "b"), "sel": (231, 234, "b"), "btnBad": (231, 124, "b"),
    "code": (232, 255, ""), "code.bold": (232, 255, "b"), "code.dim": (240, 255, ""), "code.warn": (94, 255, "b"),
    "add": (22, None, ""), "addBg": (22, 194, ""), "del": (124, None, ""), "delHi": (231, 124, "b"),
    "hunk": (241, None, ""), "srchi": (231, 94, ""), "gauge": (240, None, ""), "gauge.bad": (124, None, "b"),
    "box": (232, 255, ""), "box.dim": (240, 255, ""), "box.b": (232, 255, "b"), "box.sel": (231, 234, "b"),
    "emph": (16, None, "b"), "emphSel": (231, 16, "b"),
    "kw": (240, None, ""), "str": (22, None, ""), "com": (241, None, ""), "num": (232, None, ""), "fn": (232, None, "b"),
}
# 16-color Stitch degradation: terminal-safe bright/standard ANSI slots + attributes (zero 38/48).
STITCH_16 = {
    "": "", "text": "", "bold": "1", "dim": "", "label": "1", "hint": "", "key": "1", "rule": "2",
    "ok": "92", "okb": "92;1", "warn": "93", "warnb": "93;1", "bad": "91;1;4", "badb": "91;1;4",
    "chip.ok": "7;1;32", "chip.warn": "7;1;33", "chip.bad": "7;1;91", "chip.text": "7;1", "sample": "7;1;33",
    "sel": "7;1", "btnBad": "7;1;91", "code": "", "code.bold": "1", "code.dim": "", "code.warn": "93;1",
    "add": "92", "addBg": "92", "del": "91", "delHi": "7;1;91", "hunk": "36", "meta": "", "srchi": "7",
    "gauge": "", "gauge.bad": "91;1", "box": "", "box.dim": "", "box.b": "1", "box.sel": "7;1",
    "emph": "1", "emphSel": "7;1", "kw": "", "str": "", "com": "", "num": "", "fn": "1",
}
# Direction A's monochrome reference palette.  Background None means the
# renderer's current surface (canvas, footer, or overlay panel).
MONO_RGB = {
    "": ("#d6d6d2", None, ""),
    "text": ("#d6d6d2", None, ""),
    "bold": ("#f4f4f1", None, "b"),
    "dim": ("#8e8e89", None, ""),
    "label": ("#8e8e89", None, "b"),
    "hint": ("#64645e", None, ""),
    "key": ("#f4f4f1", None, "b"),
    "rule": ("#2f2f2d", None, ""),
    "ok": ("#d6d6d2", None, ""),
    "bad": ("#d6d6d2", None, ""),
    "warn": ("#d6d6d2", None, ""),
    "okb": ("#f4f4f1", None, "b"),
    "badb": ("#f4f4f1", None, "b"),
    "warnb": ("#f4f4f1", None, "b"),
    "chip.ok": ("#0b0b0b", "#e2e2de", "b"),
    "chip.bad": ("#0b0b0b", "#e2e2de", "b"),
    "chip.warn": ("#0b0b0b", "#e2e2de", "b"),
    "chip.text": ("#0b0b0b", "#e2e2de", "b"),
    "code": ("#cfcfca", "#161615", ""),
    "code.bold": ("#f4f4f1", "#161615", "b"),
    "code.dim": ("#8e8e89", "#161615", ""),
    "code.warn": ("#d6d6d2", "#161615", "b"),
    "sel": ("#0b0b0b", "#e2e2de", "b"),
    "btnBad": ("#0b0b0b", "#e2e2de", "b"),
    "add": ("#d6d6d2", None, ""),
    "addBg": ("#d6d6d2", None, ""),
    "del": ("#d6d6d2", None, ""),
    "delHi": ("#0b0b0b", "#e2e2de", "b"),
    "hunk": ("#8e8e89", None, ""),
    "meta": ("#8e8e89", None, ""),
    "srchi": ("#d6d6d2", None, ""),
    "gauge": ("#d6d6d2", None, ""),
    "gauge.bad": ("#f4f4f1", None, "b"),
    "box": ("#d6d6d2", "#181817", ""),
    "box.dim": ("#8e8e89", "#181817", ""),
    "box.b": ("#f4f4f1", "#181817", "b"),
    "box.sel": ("#0b0b0b", "#e2e2de", "b"),
    "emph": ("#f4f4f1", None, "b"),
    "emphSel": ("#0b0b0b", "#f4f4f1", "b"),
    "kw": ("#d6d6d2", None, ""), "str": ("#d6d6d2", None, ""), "com": ("#8e8e89", None, ""), "num": ("#d6d6d2", None, ""), "fn": ("#f4f4f1", None, "b"),
}
# Terminal-native roles (the default on a colour terminal, case; refined by the maintainer's lock of 2026-11-19 after real-Konsole inspection).
# NO explicit background anywhere and NO fixed RGB / 256-colour value (no 38;5 / 38;2 / 48 at all): the canvas and the default ink are whatever the operator's terminal theme is.
# 1. TEXT LADDER. Readable first: SGR 2 (faint) is terminal-dependent (Konsole renders it nearly illegible) so labels, descriptors, hints, metadata, the command/code band and the
#    footer use the DEFAULT ink; hierarchy is carried by bold (titles, keys, the focused row) and by layout, never by a fading attribute. Faint stays ONLY on rules (decoration).
# 2. SEMANTIC HUE, by role, from the terminal's OWN 16-colour palette (SGR 91/32/33/36; red is the BRIGHT slot 91 because the standard red 31 measures only 3.4-3.6:1 on a dark canvas, below AA; on a light canvas that reports itself via COLORFGBG it is the plain 31, 5.8:1): the theme author already tuned those slots to be legible on that theme's dark OR light
#    canvas, so no background detection query is needed. Colour only live truth: held/ready/ok (green), refuted/regression (red), unverified/not-derived/caution (yellow),
#    diff added (green) / removed (red) / hunk (cyan, the muted blue-gray of the reference). The +/- signs and the outcome WORDS remain; a refusal that is only UNKNOWN is
#    caution, never red (the tone comes from labels.decision, unchanged). A failure keeps its underline so an attribute (not only hue) separates it from a warning.
# 3. OPT-OUTS: HLITH_UI_COLOR=0 drops the hue (attribute-only, the previous native look); HLITH_UI_FAINT=0 also strips faint from rules; NO_COLOR / HLITH_UI_MONO keep MONO.
NATIVE = {
    "": "", "text": "", "bold": "1", "dim": "", "label": "", "hint": "", "key": "1", "rule": "2",
    "ok": "32", "bad": "91;1;4", "warn": "33", "okb": "32;1", "badb": "91;1;4", "warnb": "33;1",
    "chip.ok": "7;1;32", "chip.bad": "7;1;91", "chip.warn": "7;1;33", "chip.text": "7;1", "sample": "7;1",
    "code": "", "code.bold": "1", "code.dim": "", "code.warn": "33;1",
    "sel": "7;1", "btnBad": "7;1;91", "add": "32", "addBg": "32", "del": "91", "delHi": "7;1;91", "hunk": "36", "meta": "", "srchi": "7",
    "gauge": "", "gauge.bad": "91;1", "box": "", "box.dim": "", "box.b": "1", "box.sel": "7;1",
    "emph": "1", "emphSel": "7;1", "kw": "", "str": "", "com": "", "num": "", "fn": "1",
}
# Opt-in truecolor preset (HLITH_UI_PALETTE=dainty, needs COLORTERM=truecolor): the maintainer-supplied Dainty Dark tokens, from a local dainty-dark.jsonc (reference values only; nothing
# is read from that file at run time). Roles: editor #141414, ink #dbdbdb, SECONDARY ink #a2a2a2 (7.2:1; nothing a reader needs is dimmer), raised panel #1a1a1a, focus row #222222,
# border #363636 (rules only: decor, never text), accent #689dcd, warning #cd9731, added #81b88b, removed a brightened #e0624d (the file's #c74e39 / #c63b36 measure ~3.6:1: critical words
# need more), held/ok #39ba7e. Status stays in WORDS (chips keep their text; a failure keeps bold + underline), so a colour never carries a verdict alone. (fg, bg or None, attrs)
DAINTY = {
    "": ("#dbdbdb", None, ""), "text": ("#dbdbdb", None, ""), "bold": ("#f0f0f0", None, "b"), "dim": ("#a2a2a2", None, ""), "label": ("#a2a2a2", None, "b"),
    "hint": ("#a2a2a2", None, ""), "key": ("#f0f0f0", None, "b"), "rule": ("#363636", None, ""), "meta": ("#a2a2a2", None, ""),
    "ok": ("#39ba7e", None, ""), "bad": ("#e0624d", None, "bu"), "warn": ("#cd9731", None, ""), "okb": ("#39ba7e", None, "b"), "badb": ("#e0624d", None, "bu"), "warnb": ("#cd9731", None, "b"),
    "chip.ok": ("#141414", "#39ba7e", "b"), "chip.bad": ("#141414", "#e0624d", "b"), "chip.warn": ("#141414", "#cd9731", "b"), "chip.text": ("#141414", "#dbdbdb", "b"), "sample": ("#141414", "#cd9731", "b"),
    "code": ("#dbdbdb", "#1a1a1a", ""), "code.bold": ("#f0f0f0", "#1a1a1a", "b"), "code.dim": ("#a2a2a2", "#1a1a1a", ""), "code.warn": ("#cd9731", "#1a1a1a", "b"),
    "sel": ("#141414", "#e8e6e1", "b"), "btnBad": ("#141414", "#e0624d", "b"), "add": ("#81b88b", None, ""), "addBg": ("#81b88b", None, ""), "del": ("#e0624d", None, ""), "delHi": ("#141414", "#e0624d", "b"), "hunk": ("#669bcb", None, ""), "srchi": ("#141414", "#cd9731", ""),
    "gauge": ("#689dcd", None, ""), "gauge.bad": ("#e0624d", None, "b"), "box": ("#dbdbdb", "#1a1a1a", ""), "box.dim": ("#a2a2a2", "#1a1a1a", ""), "box.b": ("#f0f0f0", "#1a1a1a", "b"),
    "box.sel": ("#141414", "#e8e6e1", "b"),
    "emph": ("#ffffff", None, "b"), "emphSel": ("#141414", "#ffffff", "b"),
    # Python source INSIDE code only (maintainer's final theme direction): Dun's restrained, low-chroma hierarchy on the Dainty UI. Keywords neutral muted, strings a subtle olive, comments a readable grey,
    # function names near-white, numbers neutral; identifiers keep the text colour. Every UI role above stays Dainty; context lines only (added / removed lines keep their +/- colour for code).
    "kw": ("#a5a5a5", None, ""), "str": ("#dadd99", None, ""), "com": ("#858585", None, ""), "num": ("#dbdbdb", None, ""), "fn": ("#f0f0f0", None, "b"),
}
DAINTY_BG = "#141414"
DAINTY_TINT = "#1a1a1a"
DAINTY_BAND = "#222222"  # the full-width status / key band

# Opt-in truecolor preset HLITH_UI_PALETTE=dun: a neutral foundation derived from the MIT-licensed Dun VS Code theme (claudiodangelis/dun-vscode-theme, theme.json; its notice applies if these definitions
# are redistributed): canvas #1e1e1e, panels #242424, status band #181818, text #CCCCCC, focused / strong #f7f7f7 / #fcfcfc, secondary #a5a5a5, strings #dadd99. Deliberate departures: the theme's comment
# colour #5a5a5a is ~2.4:1 on the canvas (too faint for terminal evidence), so quiet text is lifted to #858585 (>= 4.5:1); its translucent selection (#a5a5a580) is replaced by an OPAQUE neutral inverse;
# and the theme has no refusal / unknown / diff semantics, so a restrained green / red / amber set is ADDED for outcomes and +/- (status always stays in words).
DUN_BG, DUN_TINT, DUN_BAND = "#1e1e1e", "#242424", "#181818"
DUN = {
    "": ("#cccccc", None, ""), "text": ("#cccccc", None, ""), "bold": ("#f7f7f7", None, "b"), "dim": ("#a5a5a5", None, ""), "label": ("#a5a5a5", None, "b"),
    "hint": ("#858585", None, ""), "key": ("#fcfcfc", None, "b"), "rule": ("#3a3a3a", None, ""), "meta": ("#a5a5a5", None, ""),
    "ok": ("#8fc98a", None, ""), "bad": ("#e0624d", None, "bu"), "warn": ("#cd9731", None, ""), "okb": ("#8fc98a", None, "b"), "badb": ("#e0624d", None, "bu"), "warnb": ("#cd9731", None, "b"),
    "chip.ok": ("#1e1e1e", "#8fc98a", "b"), "chip.bad": ("#1e1e1e", "#e0624d", "b"), "chip.warn": ("#1e1e1e", "#cd9731", "b"), "chip.text": ("#1e1e1e", "#cccccc", "b"), "sample": ("#1e1e1e", "#cd9731", "b"),
    "code": ("#cccccc", "#242424", ""), "code.bold": ("#f7f7f7", "#242424", "b"), "code.dim": ("#a5a5a5", "#242424", ""), "code.warn": ("#cd9731", "#242424", "b"),
    "sel": ("#1e1e1e", "#cfcfcf", "b"), "btnBad": ("#1e1e1e", "#e0624d", "b"), "add": ("#8fc98a", None, ""), "addBg": ("#8fc98a", None, ""), "del": ("#e0624d", None, ""), "delHi": ("#1e1e1e", "#e0624d", "b"), "hunk": ("#a5a5a5", None, ""), "srchi": ("#1e1e1e", "#cd9731", ""),
    "gauge": ("#a5a5a5", None, ""), "gauge.bad": ("#e0624d", None, "b"), "box": ("#cccccc", "#242424", ""), "box.dim": ("#a5a5a5", "#242424", ""), "box.b": ("#f7f7f7", "#242424", "b"),
    "box.sel": ("#1e1e1e", "#cfcfcf", "b"), "emph": ("#ffffff", None, "b"), "emphSel": ("#1e1e1e", "#ffffff", "b"),
    "kw": ("#a5a5a5", None, ""), "str": ("#dadd99", None, ""), "com": ("#858585", None, ""), "num": ("#cccccc", None, ""), "fn": ("#f7f7f7", None, "b"),
}

# older names used by the change-picker workspace map onto the design palette
ALIAS = {"bar": "dim", "bar.b": "bold", "bar.dim": "dim", "bar.cur": "chip.text", "rail": "", "rail.dim": "dim", "rail.group": "label", "rail.sel": "sel",
         "rail.sel.d": "bold", "sel.off": "bold", "border": "rule", "keytxt": "dim", "foot": "dim", "info": "dim", "h1": "bold", "h2": "label", "faint": "hint",
         "chip.info": "chip.text", "chip.dim": "chip.text"}


def mode(colors: int, has_colors: bool) -> str:
    if os.environ.get("NO_COLOR") or os.environ.get("HLITH_UI_MONO") == "1" or os.environ.get("TERM") == "dumb" or not has_colors:
        return "mono"
    return "rich" if colors >= 256 else "basic"


def _light_canvas_env(env: dict[str, str]) -> bool:
    """True only when COLORFGBG explicitly reports a light background (7 or 15)."""
    try:
        return int(str(env.get("COLORFGBG", "")).rsplit(";", 1)[-1]) in (7, 15)
    except ValueError:
        return False


def color_mode(env: dict[str, str], isatty: bool, colors: int | None) -> str:
    """Choose a semantic rendering mode from an explicit terminal snapshot.

    Default on a color TTY is the maintainer-selected Stitch visual direction,
    degrading cleanly across truecolor -> 256 -> 16 -> native (8-color) -> mono -> plain.
    """
    if not isatty or env.get("TERM") == "dumb":
        return "plain"
    if env.get("NO_COLOR") or env.get("HLITH_UI_MONO") == "1":
        return "mono"
    truecolor = env.get("COLORTERM", "").lower() in {"truecolor", "24bit"}
    palette = env.get("HLITH_UI_PALETTE", "").strip().lower()
    if palette == "native":
        return "native" if (colors is None or colors >= 8) else "mono"
    if palette in {"dainty", "dun"}:
        # Truecolor presets fall back cleanly to native when truecolor is absent.
        return palette if (colors is not None and colors >= 256 and truecolor) else "native"
    if palette in {"dark", "fixed"}:
        if colors is not None and colors >= 256:
            return "mono_truecolor" if truecolor else "mono_256"
        return "mono"
    if palette == "rich":
        if colors is not None and colors >= 256:
            return "truecolor" if truecolor else "256"
        return "mono" if (colors or 0) < 16 else "16"
    # Default ("", "stitch", "stitch-dark", "stitch-light"): Stitch visual direction with
    # graceful capability degradation and automatic light-canvas adaptation via COLORFGBG.
    light = palette == "stitch-light" or (palette != "stitch-dark" and _light_canvas_env(env))
    if env.get("HLITH_UI_COLOR") == "0":
        return "native" if (colors is None or colors >= 8) else "mono"
    if colors is not None and colors >= 256:
        if truecolor:
            return "stitch_light" if light else "stitch_truecolor"
        return "stitch_light_256" if light else "stitch_256"
    if colors is not None and colors >= 16:
        return "stitch_16"
    return "native" if (colors is None or colors >= 8) else "mono"


class Theme:
    """Install after curses.initscr(): maps style names to curses attributes."""

    def __init__(self, curses_mod=None):
        self.attrs: dict[str, int] = {}
        self.mode = "mono"
        self.bg = 0
        if curses_mod is not None:
            self._install(curses_mod)

    def _install(self, curses):
        A = {"b": curses.A_BOLD, "d": curses.A_DIM, "r": curses.A_REVERSE, "u": curses.A_UNDERLINE}
        has = curses.has_colors() and not (os.environ.get("NO_COLOR") or os.environ.get("HLITH_UI_MONO") == "1" or os.environ.get("TERM") == "dumb")
        if has:  # NO_COLOR etc.: never even initialise colours, so the terminal receives no colour sequence at all
            try:
                curses.start_color()
            except curses.error:
                has = False
        self.mode = mode(getattr(curses, "COLORS", 0) if has else 0, has)

        def flags(s):
            n = 0
            for ch in s:
                n |= A.get(ch, 0)
            return n
        if self.mode == "mono":
            self.attrs = {k: flags(v) for k, v in MONO.items()}
            return
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        pair = 0
        for k, (f256, b256, f16, b16, at) in RICH.items():
            pair += 1
            f, b = (f256, b256) if self.mode == "rich" else (f16, b16)
            try:
                curses.init_pair(pair, f, b)
                self.attrs[k] = curses.color_pair(pair) | flags(at)
            except curses.error:
                self.attrs[k] = flags(at)
        self.bg = self.attrs.get("", 0)

    def attr(self, style: str) -> int:
        style = ALIAS.get(style, style)
        return self.attrs.get(style, self.attrs.get("", 0))
