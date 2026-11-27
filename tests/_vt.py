"""A small VT100/xterm screen emulator (stdlib only) for tests: feed it the raw bytes a curses program wrote to a pty and read back what a
terminal would SHOW, cell by cell: character, foreground, background, bold/dim/reverse. It covers exactly the sequences ncurses emits for
xterm-256color (SGR incl. 38;5/48;5, CUP/VPA/CHA/CUF, EL/ED/ECH/DCH, DECSTBM, charset designation, private modes ignored). Anything else is
recorded in `unhandled`, so a test fails loudly instead of silently showing a wrong screen."""
import re
import unicodedata

CSI = re.compile(r"\x1b\[([0-9;:?<=>]*)([ -/]*)([@-~])")
ESC2 = re.compile(r"\x1b([()][0-9A-Za-z]|[=>78DEHMc])")
ANSI16 = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7}


def cw(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


class Cell:
    __slots__ = ("ch", "fg", "bg", "bold", "dim", "rev", "ul")

    def __init__(self, ch=" ", fg=None, bg=None, bold=False, dim=False, rev=False, ul=False):
        self.ch, self.fg, self.bg, self.bold, self.dim, self.rev, self.ul = ch, fg, bg, bold, dim, rev, ul


class Screen:
    def __init__(self, rows: int, cols: int):
        self.rows, self.cols = rows, cols
        self.grid = [[Cell() for _ in range(cols)] for _ in range(rows)]
        self.y = self.x = 0
        self.pen = dict(fg=None, bg=None, bold=False, dim=False, rev=False, ul=False)
        self.top, self.bot = 0, rows - 1
        self.unhandled: set[str] = set()
        self.sgr_seen = False

    # ---- output
    def feed(self, data: bytes) -> "Screen":
        s = data.decode("utf-8", "replace")
        i = 0
        while i < len(s):
            c = s[i]
            if c == "\x1b":
                m = CSI.match(s, i)
                if m:
                    self.csi(m.group(1), m.group(2), m.group(3))
                    i = m.end()
                    continue
                m = ESC2.match(s, i)
                if m:
                    g = m.group(1)
                    if g == "M":  # RI: up one line; at the top of the scroll region the region scrolls down
                        if self.y == self.top:
                            del self.grid[self.bot]
                            self.grid.insert(self.top, [self.blank() for _ in range(self.cols)])
                        else:
                            self.y = max(0, self.y - 1)
                    elif g == "D":  # IND
                        self.lf()
                    elif g == "E":  # NEL
                        self.x = 0
                        self.lf()
                    # 7/8 save/restore cursor, = > keypad, c reset: no effect on the cells curses relies on
                    i = m.end()
                    continue
                m = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)").match(s, i)  # OSC (title)
                if m:
                    i = m.end()
                    continue
                self.unhandled.add(repr(s[i:i + 6]))
                i += 1
            elif c == "\r":
                self.x = 0
                i += 1
            elif c == "\n":
                self.lf()
                i += 1
            elif c == "\b":
                self.x = max(0, self.x - 1)
                i += 1
            elif c == "\t":
                self.x = min(self.cols - 1, (self.x // 8 + 1) * 8)
                i += 1
            elif c < " " or c == "\x7f":
                i += 1
            else:
                self.put(c)
                i += 1
        return self

    def lf(self) -> None:
        if self.y == self.bot:
            del self.grid[self.top]
            self.grid.insert(self.bot, [Cell() for _ in range(self.cols)])
        else:
            self.y = min(self.rows - 1, self.y + 1)

    def put(self, ch: str) -> None:
        w = cw(ch)
        if w == 0:
            if self.x > 0:
                self.grid[self.y][self.x - 1].ch += ch
            return
        if self.x + w > self.cols:  # curses never relies on auto-wrap for content; clamp like a terminal with the cursor in the last column
            self.x = self.cols - w
        cell = self.grid[self.y][self.x]
        cell.ch = ch
        cell.fg, cell.bg, cell.bold, cell.dim, cell.rev, cell.ul = (self.pen[k] for k in ("fg", "bg", "bold", "dim", "rev", "ul"))
        if w == 2 and self.x + 1 < self.cols:
            nxt = self.grid[self.y][self.x + 1]
            nxt.ch = ""
            nxt.fg, nxt.bg, nxt.bold, nxt.dim, nxt.rev, nxt.ul = cell.fg, cell.bg, cell.bold, cell.dim, cell.rev, cell.ul
        self.x = min(self.cols - 1, self.x + w) if self.x + w >= self.cols else self.x + w

    def blank(self) -> Cell:
        return Cell(bg=self.pen["bg"], fg=self.pen["fg"], rev=self.pen["rev"])

    def csi(self, params: str, inter: str, fin: str) -> None:
        if params and params[0] in "?<=>":
            return  # private modes (alt screen, keypad, cursor visibility ...): no effect on the cells
        p = [int(x) if x.isdigit() else 0 for x in re.split("[;:]", params)] if params else []
        a = p[0] if p and p[0] else 1
        if fin == "m":
            self.sgr(p or [0])
        elif fin in "Hf":
            self.y = min(self.rows - 1, max(0, (p[0] if p and p[0] else 1) - 1))
            self.x = min(self.cols - 1, max(0, (p[1] if len(p) > 1 and p[1] else 1) - 1))
        elif fin == "A":
            self.y = max(0, self.y - a)
        elif fin == "B":
            self.y = min(self.rows - 1, self.y + a)
        elif fin == "C":
            self.x = min(self.cols - 1, self.x + a)
        elif fin == "D":
            self.x = max(0, self.x - a)
        elif fin == "G":
            self.x = min(self.cols - 1, a - 1)
        elif fin == "d":
            self.y = min(self.rows - 1, a - 1)
        elif fin == "K":
            mode = p[0] if p else 0
            lo, hi = {0: (self.x, self.cols), 1: (0, self.x + 1), 2: (0, self.cols)}.get(mode, (self.x, self.cols))
            for k in range(lo, hi):
                self.grid[self.y][k] = self.blank()
        elif fin == "J":
            mode = p[0] if p else 0
            if mode in (2, 3):
                self.grid = [[self.blank() for _ in range(self.cols)] for _ in range(self.rows)]
            elif mode == 0:
                for k in range(self.x, self.cols):
                    self.grid[self.y][k] = self.blank()
                for r in range(self.y + 1, self.rows):
                    self.grid[r] = [self.blank() for _ in range(self.cols)]
            elif mode == 1:
                for r in range(0, self.y):
                    self.grid[r] = [self.blank() for _ in range(self.cols)]
                for k in range(0, self.x + 1):
                    self.grid[self.y][k] = self.blank()
        elif fin == "X":
            for k in range(self.x, min(self.cols, self.x + a)):
                self.grid[self.y][k] = self.blank()
        elif fin == "P":
            row = self.grid[self.y]
            del row[self.x:self.x + a]
            row.extend(self.blank() for _ in range(self.cols - len(row)))
        elif fin == "@":
            row = self.grid[self.y]
            row[self.x:self.x] = [self.blank() for _ in range(a)]
            del row[self.cols:]
        elif fin == "r":
            self.top = (p[0] if p and p[0] else 1) - 1
            self.bot = (p[1] if len(p) > 1 and p[1] else self.rows) - 1
            self.y = self.x = 0
        elif fin in "ST":  # SU / SD: scroll the region (ncurses uses them for vertical scroll optimisation)
            for _ in range(min(a, self.bot - self.top + 1)):
                if fin == "S":
                    del self.grid[self.top]
                    self.grid.insert(self.bot, [self.blank() for _ in range(self.cols)])
                else:
                    del self.grid[self.bot]
                    self.grid.insert(self.top, [self.blank() for _ in range(self.cols)])
        elif fin in "LM":  # IL / DL inside the scroll region
            if self.top <= self.y <= self.bot:
                for _ in range(min(a, self.bot - self.y + 1)):
                    if fin == "L":
                        del self.grid[self.bot]
                        self.grid.insert(self.y, [self.blank() for _ in range(self.cols)])
                    else:
                        del self.grid[self.y]
                        self.grid.insert(self.bot, [self.blank() for _ in range(self.cols)])
        elif fin == "b":  # REP: repeat the previous graphic character
            prev = self.grid[self.y][max(0, self.x - 1)].ch
            for _ in range(a):
                self.put(prev or " ")
        elif fin in "lht":
            pass  # insert mode, window ops: not cell content
        else:
            self.unhandled.add(f"CSI {params}{inter}{fin}")

    def sgr(self, p: list[int]) -> None:
        self.sgr_seen = True
        i = 0
        while i < len(p):
            n = p[i]
            if n == 0:
                self.pen = dict(fg=None, bg=None, bold=False, dim=False, rev=False, ul=False)
            elif n == 1:
                self.pen["bold"] = True
            elif n == 2:
                self.pen["dim"] = True
            elif n == 4:
                self.pen["ul"] = True
            elif n == 7:
                self.pen["rev"] = True
            elif n in (22,):
                self.pen["bold"] = self.pen["dim"] = False
            elif n == 24:
                self.pen["ul"] = False
            elif n == 27:
                self.pen["rev"] = False
            elif 30 <= n <= 37:
                self.pen["fg"] = n - 30
            elif 40 <= n <= 47:
                self.pen["bg"] = n - 40
            elif n == 39:
                self.pen["fg"] = None
            elif n == 49:
                self.pen["bg"] = None
            elif 90 <= n <= 97:
                self.pen["fg"] = n - 90 + 8
            elif 100 <= n <= 107:
                self.pen["bg"] = n - 100 + 8
            elif n in (38, 48) and i + 2 < len(p) and p[i + 1] == 5:
                self.pen["fg" if n == 38 else "bg"] = p[i + 2]
                i += 2
            elif n in (38, 48) and i + 4 < len(p) and p[i + 1] == 2:  # truecolor (the operator host paints 38;2;r;g;b when COLORTERM says so)
                self.pen["fg" if n == 38 else "bg"] = (p[i + 2], p[i + 3], p[i + 4])
                i += 4
            else:
                self.unhandled.add(f"SGR {n}")
            i += 1

    # ---- reading
    def text(self) -> list[str]:
        return ["".join(c.ch for c in row).rstrip() for row in self.grid]

    def cell(self, y: int, x: int) -> Cell:
        return self.grid[y][x]


# ---- colour maths (WCAG 2.x relative luminance and contrast ratio)
def xterm_rgb(n: int | None, default: tuple[int, int, int]) -> tuple[int, int, int]:
    if n is None:
        return default
    if isinstance(n, tuple):  # a truecolor cell carries its own rgb
        return n
    base16 = [(0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0), (0, 0, 238), (205, 0, 205), (0, 205, 205), (229, 229, 229),
              (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0), (92, 92, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255)]
    if n < 16:
        return base16[n]
    if n < 232:
        n -= 16
        lv = [0, 95, 135, 175, 215, 255]
        return lv[n // 36], lv[(n // 6) % 6], lv[n % 6]
    g = 8 + (n - 232) * 10
    return g, g, g


def luminance(rgb: tuple[int, int, int]) -> float:
    def ch(v: int) -> float:
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def cell_colours(c: Cell, default_fg=(229, 229, 229), default_bg=(0, 0, 0)):
    """(foreground rgb, background rgb) as a terminal paints the cell: reverse swaps them; dim blends the foreground 1/3 towards the background
    (how xterm and most emulators draw faint text), so a 'dim' pair is judged by what is actually visible."""
    fg, bg = xterm_rgb(c.fg, default_fg), xterm_rgb(c.bg, default_bg)
    if c.rev:
        fg, bg = bg, fg
    if c.dim:
        fg = tuple(round(f * 2 / 3 + b / 3) for f, b in zip(fg, bg))
    return fg, bg
