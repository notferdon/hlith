# SPDX-License-Identifier: Apache-2.0
"""Corpus of the prover's soundness campaign: small functions in the shapes ordinary code has. TYPED functions take exact builtin values; OPEN functions take unknown objects
(no annotation) and are exercised with probes. Each entry is (function name, module source)."""

TYPED = {}
OPEN = {}


def typed(src):
    name = src.split("def ", 1)[1].split("(", 1)[0]
    # the LAST def in the snippet is the target (helpers come first)
    last = src.rsplit("\ndef ", 1)[-1] if "\ndef " in src else src.split("def ", 1)[1]
    name = last.split("(", 1)[0].replace("def ", "").strip()
    TYPED[name] = src.strip("\n") + "\n"
    return src


def open_(src):
    last = src.rsplit("\ndef ", 1)[-1] if "\ndef " in src else src.split("def ", 1)[1]
    name = last.split("(", 1)[0].replace("def ", "").strip()
    OPEN[name] = src.strip("\n") + "\n"
    return src


typed('''
def clamp(value: int, low: int, high: int) -> int:
    if value < low:
        return low
    if value > high:
        return high
    return value
''')

typed('''
def sign(n: int) -> int:
    if n > 0:
        return 1
    elif n < 0:
        return -1
    return 0
''')

typed('''
def safe_div(a: int, b: int) -> int:
    if b == 0:
        return 0
    return a // b
''')

typed('''
def mod_bucket(n: int, size: int) -> int:
    r = n % size
    if r < 0:
        r = r + size
    return r
''')

typed('''
def is_blank(line: str) -> bool:
    if len(line.strip()) == 0:
        return True
    else:
        return False
''')

typed('''
def initials(name: str) -> str:
    parts = name.split()
    result = ""
    for part in parts:
        result = result + part[0].upper()
    return result
''')

typed('''
def slugify(text: str, sep: str = "-") -> str:
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != sep:
            out.append(sep)
    return "".join(out).strip(sep)
''')

typed('''
def total_price(prices: list[int], discount: int) -> int:
    total = 0
    for p in prices:
        total += p
    if discount > 0:
        total = total - discount
    if total < 0:
        total = 0
    return total
''')

typed('''
def first_negative(xs: list[int]) -> int:
    for i, x in enumerate(xs):
        if x < 0:
            return i
    return -1
''')

typed('''
def count_long(words: list[str], n: int) -> int:
    count = 0
    for w in words:
        if len(w) > n:
            count += 1
    return count
''')

typed('''
def has_prefix(names: list[str], prefix: str) -> bool:
    for name in names:
        if name.startswith(prefix):
            return True
    return False
''')

typed('''
def all_positive(xs: list[int]) -> bool:
    for x in xs:
        if x <= 0:
            return False
    return True
''')

typed('''
def evens(xs: list[int]) -> list[int]:
    out = []
    for x in xs:
        if x % 2 == 0:
            out.append(x)
    return out
''')

typed('''
def parse_int(text: str, default: int) -> int:
    try:
        return int(text)
    except ValueError:
        return default
''')

typed('''
def parse_pair(text: str) -> tuple[str, str]:
    if "=" not in text:
        raise ValueError("no separator: " + text)
    key, value = text.split("=", 1)
    return key.strip(), value.strip()
''')

typed('''
def join_nonempty(parts: list[str], sep: str) -> str:
    kept = []
    for p in parts:
        if p:
            kept.append(p)
    return sep.join(kept)
''')

typed('''
def last_or(xs: list[int], default: int) -> int:
    if not xs:
        return default
    return xs[-1]
''')

typed('''
def describe(n: int) -> str:
    if n == 0:
        label = "zero"
    elif n % 2 == 0:
        label = "even"
    else:
        label = "odd"
    return f"{n} is {label}"
''')

typed('''
def lookup(table: dict[str, int], key: str, default: int) -> int:
    if key in table:
        return table[key]
    return default
''')

typed('''
def word_lengths(text: str) -> dict[str, int]:
    out = {}
    for w in text.split():
        out[w] = len(w)
    return out
''')

typed('''
def maybe_len(s: str | None) -> int:
    if s is None:
        return 0
    return len(s)
''')

typed('''
def countdown(n: int) -> int:
    steps = 0
    while n > 0:
        n = n - 3
        steps += 1
    return steps
''')

typed('''
def find_index(xs: list[int], target: int) -> int:
    i = 0
    while i < len(xs):
        if xs[i] == target:
            return i
        i += 1
    return -1
''')

typed('''
def _norm(s: str) -> str:
    return s.strip().lower()


def same_text(a: str, b: str) -> bool:
    return _norm(a) == _norm(b)
''')

typed('''
def _weight(x: int) -> int:
    if x < 0:
        return 0
    return x * 2


def score(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += _weight(x)
    return total
''')

typed('''
def nested_sum(n: int, m: int) -> int:
    total = 0
    for i in range(n):
        for j in range(m):
            if i == j:
                continue
            total += i * j
    return total
''')

typed('''
def truncate(text: str, limit: int) -> str:
    if limit < 0:
        raise ValueError("negative limit")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."
''')

typed('''
def any_digit(text: str) -> bool:
    return any(ch.isdigit() for ch in text)
''')

typed('''
def squares(xs: list[int]) -> list[int]:
    return [x * x for x in xs if x > 0]
''')

typed('''
def max_or_none(xs: list[int]) -> int | None:
    if not xs:
        return None
    best = xs[0]
    for x in xs:
        if x > best:
            best = x
    return best
''')

typed('''
def flags(a: bool, b: bool, c: bool) -> int:
    n = 0
    if a and not b:
        n += 1
    if b or c:
        n += 2
    if not (a or c):
        n += 4
    return n
''')

typed('''
def pair_sum(p: tuple[int, int], scale: int) -> int:
    a, b = p
    return (a + b) * scale
''')

typed('''
def dedupe(xs: list[str]) -> list[str]:
    seen = set()
    out = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
''')

typed('''
def checked_ratio(a: int, b: int) -> int:
    try:
        r = a // b
    except ZeroDivisionError:
        return -1
    else:
        return r + 1
''')

typed('''
def pop_all(xs: list[int]) -> int:
    total = 0
    while xs:
        total += xs.pop()
    return total
''')

# ---- open (untyped) functions: exercised with probes
open_('''
def get_name(obj):
    if obj.name:
        return obj.name
    return obj.fallback()
''')

open_('''
def process(items, sink):
    count = 0
    for item in items:
        if item.ready:
            sink.send(item)
            count += 1
    return count
''')

open_('''
def pick(a, b, flag):
    if flag:
        result = a.value
    else:
        result = b.value
    return result
''')

open_('''
def guarded(conn, query):
    if conn is None:
        raise ValueError("no connection")
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
''')

open_('''
def combine(x, y):
    total = x + y
    if total > x:
        return total
    return x - y
''')

open_('''
def safe_call(fn, arg):
    try:
        return fn(arg)
    except ValueError:
        return None
''')

open_('''
def first_ready(items):
    for item in items:
        if item.ready():
            return item
    return None
''')

open_('''
def update(state, key, value):
    old = state.get(key)
    state[key] = value
    if old is None:
        return True
    return old != value
''')

open_('''
def render(tpl, ctx):
    head = tpl.header(ctx)
    body = tpl.body(ctx)
    return head + body
''')

open_('''
def count_matching(items, pred):
    n = 0
    for it in items:
        if pred(it):
            n += 1
    return n
''')

open_('''
def chain(obj):
    a = obj.first()
    b = a.second()
    if b:
        obj.log("ok")
    return a
''')

open_('''
def typed_guard(x):
    if type(x) is not str:
        raise TypeError("str expected")
    if len(x.strip()) == 0:
        return True
    return False
''')
