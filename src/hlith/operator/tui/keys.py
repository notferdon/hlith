# SPDX-License-Identifier: Apache-2.0
"""Bounded terminal input decoding and a non-authoritative key map."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Paste:
    text: str


def decode(data: bytes) -> list[str | Paste]:
    """Decode one finite byte batch; use Decoder in a stream so split sequences survive reads."""
    decoder = Decoder()
    events = decoder.feed(data)
    events.extend(decoder.flush())
    return events


class Decoder:
    """Incremental terminal decoder. Incomplete control sequences never become ordinary keys."""

    _paste_start = b"\x1b[200~"
    _paste_end = b"\x1b[201~"
    _max_csi = 64
    _max_control = 65536
    _max_paste = 4 * 1024 * 1024

    def __init__(self):
        self._buffer = bytearray()
        self._paste: bytearray | None = None
        self._discard: str | None = None

    def feed(self, data: bytes) -> list[str | Paste]:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return []
        self._buffer.extend(data)
        return self._drain(final=False)

    def flush(self) -> list[str | Paste]:
        """Resolve a lone Escape after an input timeout and discard incomplete control strings."""
        return self._drain(final=True)

    def _drain(self, *, final: bool) -> list[str | Paste]:
        out: list[str | Paste] = []
        b = self._buffer
        while b:
            if self._discard == "csi":
                end = next((i for i, value in enumerate(b) if 0x40 <= value <= 0x7E), None)
                if end is None:
                    b.clear()
                    break
                del b[:end + 1]
                self._discard = None
                continue
            if self._discard in {"osc", "dcs"}:
                ends = (b"\x07", b"\x1b\\") if self._discard == "osc" else (b"\x1b\\",)
                found = [(b.find(end), end) for end in ends if b.find(end) >= 0]
                if found:
                    idx, end = min(found, key=lambda pair: pair[0])
                    del b[:idx + len(end)]
                    self._discard = None
                    continue
                keep = len(end) - 1
                if len(b) > keep:
                    del b[:-keep]
                break

            if self._paste is not None:
                idx = b.find(self._paste_end)
                if idx >= 0:
                    self._append_paste(b[:idx])
                    del b[:idx + len(self._paste_end)]
                    out.append(Paste(self._paste.decode("utf-8", "replace")))
                    self._paste = None
                    continue
                keep = len(self._paste_end) - 1
                if len(b) > keep:
                    self._append_paste(b[:-keep])
                    del b[:-keep]
                break

            if b.startswith(self._paste_start):
                del b[:len(self._paste_start)]
                self._paste = bytearray()
                continue
            if self._paste_start.startswith(b):
                if final:
                    if b == b"\x1b":
                        out.append("esc")
                    b.clear()
                    break
                break

            if b.startswith(b"\x1b[M"):
                # a legacy (X10) mouse report: ESC [ M + 3 bytes. Hlith never turns mouse tracking on, but a terminal left in that mode must not have its report read as keys (' !!' is a Space)
                if len(b) >= 6:
                    del b[:6]
                    continue
                if not final:
                    break
                b.clear()
                break
            c = b[0]
            if c == 0x1B:
                if len(b) == 1:
                    if final:
                        out.append("esc")
                        b.clear()
                    break
                nxt = b[1]
                if nxt == ord("["):
                    end = next((i for i in range(2, len(b)) if 0x40 <= b[i] <= 0x7E), None)
                    if end is None:
                        if len(b) > self._max_csi:
                            b.clear()
                            self._discard = "csi"
                        elif final:
                            b.clear()
                        break
                    final_byte, body = chr(b[end]), bytes(b[2:end])
                    event = {"A": "up", "B": "down", "C": "right", "D": "left",
                             "H": "home", "F": "end"}.get(final_byte)
                    if final_byte == "~":
                        event = {b"1": "home", b"3": "delete", b"4": "end",
                                 b"5": "pgup", b"6": "pgdn"}.get(body.split(b";")[0])
                    if event:
                        out.append(event)
                    del b[:end + 1]
                    continue
                if nxt in (ord("]"), ord("P")):
                    kind = "osc" if nxt == ord("]") else "dcs"
                    ends = (b"\x07", b"\x1b\\") if kind == "osc" else (b"\x1b\\",)
                    found = [(b.find(term), term) for term in ends if b.find(term) >= 0]
                    if found:
                        idx, term = min(found, key=lambda pair: pair[0])
                        del b[:idx + len(term)]
                        continue
                    if len(b) > self._max_control:
                        b.clear()
                        self._discard = kind
                    elif final:
                        b.clear()
                    break
                if nxt == ord("O"):
                    if len(b) < 3:
                        if final:
                            b.clear()
                        break
                    out.append({ord("A"): "up", ord("B"): "down", ord("C"): "right",
                                ord("D"): "left"}.get(b[2], "unknown"))
                    del b[:3]
                    continue
                out.append("esc")
                del b[0]
                continue

            if c in (0, 0x7F) or c < 0x20:
                out.append("ctrl-c" if c == 3 else "enter" if c in (10, 13) else
                            "tab" if c == 9 else "backspace" if c == 8 else "unknown")
                del b[0]
                continue

            size = 1 if c < 0x80 else 2 if c < 0xE0 else 3 if c < 0xF0 else 4
            if len(b) < size and not final:
                break
            chunk = bytes(b[:min(len(b), size)])
            try:
                out.append(chunk.decode("utf-8"))
                del b[:len(chunk)]
            except UnicodeDecodeError as exc:
                if exc.reason == "unexpected end of data" and not final:
                    break
                out.append("�")
                del b[0]
        return out

    def _append_paste(self, data: bytes | bytearray) -> None:
        remaining = self._max_paste - len(self._paste)
        if remaining > 0:
            self._paste.extend(data[:remaining])


def action_for(vs, key) -> str | None:
    """Map decoded input to safe view actions. A paste is never interpreted as keys."""
    if isinstance(key, Paste) or not isinstance(key, str):
        return None
    key = {"\r": "enter", "\n": "enter", "\t": "tab", "\x1b": "esc", " ": "space"}.get(key, key)  # a literal space IS the space key (Selection's include-file toggle)
    if key == "ctrl-c":
        key = "q"
    if key in {"enter", "esc", "tab", "shift-tab", "up", "down", "left", "right", "home", "end", "pgup", "pgdn", "space", "?"}:
        return f"key:{key}"
    if len(key) == 1 and key.isprintable():
        return f"key:{key}"
    return None
