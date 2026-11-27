#!/usr/bin/env python3
"""TUI behavior: COMPUTED contrast of the native theme's semantic roles (SGR 31/32/33/36 and the default ink) against the canvas, for terminal palettes whose RGB values are published.
ANSI palette slots have no fixed RGB: the terminal theme defines them. So the numbers below are for the named palettes only (xterm's built-in palette on black and on white,
and the canonical Solarized dark/light palette), computed with the WCAG 2.x relative-luminance formula. WCAG: 4.5:1 body text, 3:1 non-text/large. Prints a table; exit 0 always (a report, not a gate)."""
from __future__ import annotations

import sys


def lin(c):
    c /= 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def lum(rgb):
    r, g, b = (lin(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# slot -> rgb; fg/bg are the theme's default ink and canvas
PALETTES = {
    "xterm default palette, black canvas": dict(bg=(0, 0, 0), fg=(229, 229, 229), red=(205, 0, 0), bred=(255, 0, 0), green=(0, 205, 0), yellow=(205, 205, 0), cyan=(0, 205, 205)),
    "xterm default palette, white canvas": dict(bg=(255, 255, 255), fg=(0, 0, 0), red=(205, 0, 0), bred=(255, 0, 0), green=(0, 205, 0), yellow=(205, 205, 0), cyan=(0, 205, 205)),
    "Solarized dark": dict(bg=(0, 43, 54), fg=(131, 148, 150), red=(220, 50, 47), green=(133, 153, 0), yellow=(181, 137, 0), cyan=(42, 161, 152), bred=(203, 75, 22)),
    "Solarized light": dict(bg=(253, 246, 227), fg=(101, 123, 131), red=(220, 50, 47), green=(133, 153, 0), yellow=(181, 137, 0), cyan=(42, 161, 152), bred=(203, 75, 22)),
}
ROLES = [("default ink (labels, hints, command, claim, witness, readiness, footer)", "fg"), ("ok / HELD / added (32)", "green"), ("refuted / removed, plain red (31: light canvases)", "red"), ("refuted / removed, bright red (91: dark/unknown canvases)", "bred"),
         ("caution / unverified (33)", "yellow"), ("hunk (36)", "cyan")]


def table():
    rows = []
    for name, p in PALETTES.items():
        for label, key in ROLES:
            rows.append((name, label, ratio(p[key], p["bg"])))
    return rows


def main():
    rows = table()
    print("| palette | role | contrast vs canvas |\n|---|---|---|")
    for name, label, r in rows:
        print(f"| {name} | {label} | {r:.2f}:1 {'OK' if r >= 4.5 else ('>=3 only' if r >= 3 else 'LOW')} |")
    by_role = {}
    for _, label, r in rows:
        by_role[label] = min(by_role.get(label, 99), r)
    print("\nminimum per role across the four palettes:")
    for label, r in by_role.items():
        print(f"  {r:5.2f}:1  {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
