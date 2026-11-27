"""TUI behavior: the maintainer's final native colour refinement (2026-11-19), red-first.
Readable text ladder (no SGR 2 on content) + restrained semantic hue from the terminal's OWN 16-colour palette (31/32/33/36 only), no fixed RGB, no 38/48, no backgrounds;
refusals by the decision word (REFUTED red, UNVERIFIED / NOT-DERIVED / UNKNOWN caution, never automatic red); opt-outs HLITH_UI_COLOR=0 / HLITH_UI_FAINT=0; NO_COLOR untouched."""
import re

import pytest

from hlith.operator import labels
from hlith.operator.tui import frame, host, theme

ALLOWED_HUE = {31, 91, 32, 33, 36}  # 91 = bright red on dark/unknown canvases; 31 only where the terminal reports a light canvas


@pytest.fixture(autouse=True)
def _neutral_env(monkeypatch):
    for k in ("COLORFGBG", "HLITH_UI_COLOR", "HLITH_UI_FAINT", "NO_COLOR", "HLITH_UI_MONO"):
        monkeypatch.delenv(k, raising=False)
CONTENT = ["", "text", "bold", "dim", "label", "hint", "key", "meta", "code", "code.bold", "code.dim", "box", "box.dim", "box.b"]


def _codes(spec):
    return [int(c) for c in spec.split(";") if c]


def test_content_roles_never_use_faint_only_the_rules_do():
    for name in CONTENT:
        assert 2 not in _codes(theme.NATIVE[name]), f"{name!r} must not be faint (SGR 2 is illegible in real Konsole)"
    assert theme.NATIVE["rule"] == "2"  # decoration only


def test_native_uses_no_fixed_colour_and_no_background_only_the_four_palette_slots():
    for name, spec in theme.NATIVE.items():
        for c in _codes(spec):
            assert c in {1, 2, 4, 7} | ALLOWED_HUE, (name, spec)
    assert not any(c in range(40, 48) or c in range(90, 108) and c != 91 or c in (38, 48) for spec in theme.NATIVE.values() for c in _codes(spec))


def test_semantic_roles_by_hue():
    s = lambda n: _codes(host._sgr(n, "native"))  # noqa: E731
    assert 32 in s("ok") and 32 in s("add") and 32 in s("okb") and 32 in s("chipOk")
    assert 91 in s("del") and 91 in s("bad") and 91 in s("badb") and 91 in s("chipBad")
    assert 33 in s("warn") and 33 in s("warnb") and 33 in s("chipWarn")
    assert 36 in s("hunk")
    assert 4 in s("bad")  # a failure keeps an attribute (underline) as well as the hue: it is not colour alone
    assert not {31, 91} & set(s("warn")) and not {31, 91} & set(s("chipWarn"))


@pytest.mark.parametrize("exit_status,word,tone", [(0, "LANDED", "good"), (10, "REFUSED · REFUTED", "bad"), (11, "REFUSED · NOT-DERIVED", "warn"), (12, "REFUSED · UNVERIFIED", "warn")])
def test_decision_word_to_tone_to_hue_never_makes_unknown_red_or_green(exit_status, word, tone):
    outcome = "landed" if exit_status == 0 else "refused"
    got_word, got_tone = labels.decision(outcome, exit_status)
    assert (got_word, got_tone) == (word, tone) or (got_word.startswith("REFUSED") and got_tone == tone), (got_word, got_tone)
    kind, kind_tone = frame._kind_for(got_word)
    hue = _codes(host._sgr(kind_tone, "native"))
    if exit_status == 10:
        assert 91 in hue
    elif exit_status == 0:
        assert 32 in hue
    else:
        assert not ({31, 91, 32} & set(hue)) and 33 in hue
    # a forged / unknown record is never green and never red
    unk_word, unk_tone = labels.decision("landed", 10)
    assert unk_word.startswith("UNKNOWN") and unk_tone == "dim"
    assert not any(c in ALLOWED_HUE for c in _codes(host._sgr(unk_tone, "native")))


def test_color_opt_out_removes_every_hue_and_keeps_attributes(monkeypatch):
    monkeypatch.setenv("HLITH_UI_COLOR", "0")
    for name in theme.NATIVE:
        codes = _codes(host._sgr(name, "native"))
        assert not any(c in ALLOWED_HUE for c in codes), name
    assert _codes(host._sgr("bad", "native")) == [1, 4]  # attribute-only: bold + underline survive
    assert _codes(host._sgr("chipBad", "native")) == [7, 1]


def test_faint_opt_out_keeps_the_rule_in_the_default_ink(monkeypatch):
    monkeypatch.setenv("HLITH_UI_FAINT", "0")
    assert host._sgr("rule", "native") == ""


def test_no_color_and_mono_still_have_no_colour_sequence(monkeypatch):
    for name in theme.MONO:
        assert not any(c in ALLOWED_HUE for c in _codes(host._sgr(name, "mono")))
    assert re.fullmatch(r"(plain)", theme.color_mode({"NO_COLOR": "1"}, False, 256)) or theme.color_mode({"NO_COLOR": "1"}, True, 256) == "mono"
    assert theme.color_mode({"TERM": "xterm-256color"}, True, 256) == "stitch_256"
    assert theme.color_mode({"TERM": "xterm-256color", "HLITH_UI_PALETTE": "native"}, True, 256) == "native"


def test_a_terminal_that_reports_a_light_canvas_drops_green_yellow_cyan_but_keeps_red(monkeypatch):
    monkeypatch.delenv("HLITH_UI_COLOR", raising=False)
    monkeypatch.setenv("COLORFGBG", "0;15")  # black on white
    assert not any(c in {32, 33, 36} for n in theme.NATIVE for c in _codes(host._sgr(n, "native")))
    assert 31 in _codes(host._sgr("bad", "native")) and 31 in _codes(host._sgr("chipBad", "native")) and 91 not in _codes(host._sgr("bad", "native"))
    monkeypatch.setenv("HLITH_UI_COLOR", "1")  # forced back
    assert 32 in _codes(host._sgr("ok", "native"))
    monkeypatch.delenv("HLITH_UI_COLOR")
    monkeypatch.setenv("COLORFGBG", "15;0")  # dark canvas keeps the full hue
    assert 32 in _codes(host._sgr("ok", "native"))
    monkeypatch.setenv("COLORFGBG", "garbage")  # unknown is never assumed light
    assert 33 in _codes(host._sgr("warn", "native"))
