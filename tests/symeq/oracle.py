# SPDX-License-Identifier: Apache-2.0
"""Concrete oracle for the symbolic equivalence prover: run two versions of a function and decide whether they are OBSERVABLY different.

Two kinds of inputs, matching the prover's two domains:
  * typed inputs: exact builtin values enumerated from an annotation (small exhaustive products plus boundary values);
  * probes: objects whose every special method is a RANDOM INTERPRETATION of an uninterpreted operation: the result of an operation is a hash of (everything that happened so
    far, the operation, its operands). Two programs that perform the same operations on equal operands in the same order see the same results; any difference in what is done, or
    in which order, changes the history hash. This executes the prover's own abstraction (world-threaded opaque operations) concretely.

An outcome is (kind, value description, world-history digest, final state of mutable arguments)."""

from __future__ import annotations

import hashlib
import itertools
import math
import random
import struct


class ProbeError(Exception):
    pass


class World:
    def __init__(self, seed):
        self.h = hashlib.sha256(repr(seed).encode()).digest()
        self.count = 0

    def event(self, *desc) -> int:
        self.count += 1
        if self.count > 5000:
            raise RecursionError("probe budget")
        self.h = hashlib.sha256(self.h + repr(desc).encode("utf-8", "backslashreplace")).digest()
        return int.from_bytes(self.h[:8], "big")


def desc(v, depth=0):
    """A stable description of a value as an operand / result (probes by identity number, builtins by type and content, floats by bits)."""
    if isinstance(v, Probe):
        return ("P", object.__getattribute__(v, "_pid"))
    t = type(v)
    if t is float:
        return ("float", struct.pack(">d", v).hex() if v == v else "nan")
    if t in (int, bool, str, bytes, type(None)):
        return (t.__name__, v)
    if depth > 6:
        return ("deep",)
    if t in (list, tuple):
        return (t.__name__, tuple(desc(x, depth + 1) for x in v))
    if t in (set, frozenset):
        return (t.__name__, tuple(sorted((desc(x, depth + 1) for x in v), key=repr)))
    if t is dict:
        return ("dict", tuple((desc(k, depth + 1), desc(x, depth + 1)) for k, x in v.items()))
    if isinstance(v, BaseException):
        return ("exc", type(v).__name__, tuple(desc(a, depth + 1) for a in v.args))
    if t is range:
        return ("range", v.start, v.stop, v.step)
    if isinstance(v, type):
        return ("class", v.__name__)
    if callable(v):
        return ("callable", getattr(v, "__name__", "?"))
    return ("obj", t.__name__)


class Probe:
    """An unknown object. Every operation is an event in the world; results are functions of the history."""

    def __init__(self, world, pid):
        object.__setattr__(self, "_w", world)
        object.__setattr__(self, "_pid", pid)

    def _ev(self, op, *args):
        w = object.__getattribute__(self, "_w")
        return w.event(object.__getattribute__(self, "_pid"), op, *[desc(a) for a in args])

    def _res(self, v):
        """Turn an event number into a result: mostly a new probe, sometimes a builtin value, sometimes an exception."""
        w = object.__getattribute__(self, "_w")
        k = v % 16
        if k == 0:
            raise ProbeError(v % 1000)
        if k == 1:
            return None
        if k == 2:
            return v % 7 - 3
        if k == 3:
            return "s%d" % (v % 5)
        if k == 4:
            return bool(v % 2)
        return Probe(w, v % 100000)

    def __bool__(self):
        return self._ev("bool") % 3 != 0

    def __len__(self):
        return self._ev("len") % 4

    def __eq__(self, o):
        return self._ev("eq", o) % 2 == 0

    def __ne__(self, o):
        return self._ev("ne", o) % 2 == 0

    def __lt__(self, o):
        return self._ev("lt", o) % 2 == 0

    def __le__(self, o):
        return self._ev("le", o) % 2 == 0

    def __gt__(self, o):
        return self._ev("gt", o) % 2 == 0

    def __ge__(self, o):
        return self._ev("ge", o) % 2 == 0

    def __hash__(self):
        return self._ev("hash") % 5

    def __contains__(self, x):
        return self._ev("contains", x) % 2 == 0

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        v = self._ev("getattr", name)
        if v % 11 == 0:
            raise AttributeError(name)
        return Probe(object.__getattribute__(self, "_w"), v % 100000)

    def __setattr__(self, name, value):
        self._ev("setattr", name, value)

    def __delattr__(self, name):
        self._ev("delattr", name)

    def __call__(self, *a, **k):
        return self._res(self._ev("call", a, tuple(sorted(k.items(), key=lambda kv: kv[0]))))

    def __getitem__(self, k):
        if isinstance(k, slice):
            k = ("slice", k.start, k.stop, k.step)
        return self._res(self._ev("getitem", k))

    def __setitem__(self, k, v):
        self._ev("setitem", k, v)

    def __delitem__(self, k):
        self._ev("delitem", k)

    def __iter__(self):
        n = self._ev("iter") % 4
        w = object.__getattribute__(self, "_w")
        for i in range(n):
            v = self._ev("next", i)
            if v % 13 == 0:
                raise ProbeError("iter")
            yield Probe(w, v % 100000) if v % 4 else v % 5

    def __str__(self):
        return "P%d" % (self._ev("str") % 50)

    def __repr__(self):
        return "R%d" % (self._ev("repr") % 50)

    def __format__(self, spec):
        return "F%d" % (self._ev("format", spec) % 50)

    def __int__(self):
        return self._ev("int") % 9

    def __index__(self):
        return self._ev("index") % 3

    def __neg__(self):
        return self._res(self._ev("neg"))

    def __pos__(self):
        return self._res(self._ev("pos"))

    def __invert__(self):
        return self._res(self._ev("invert"))

    def __enter__(self):
        return self._res(self._ev("enter"))

    def __exit__(self, *a):
        return self._ev("exit", a[0] is not None) % 5 == 0


def _binop(name):
    def f(self, o):
        return self._res(self._ev(name, o))

    return f


for _n in ("add", "sub", "mul", "truediv", "floordiv", "mod", "pow", "lshift", "rshift", "and", "or", "xor", "matmul"):
    setattr(Probe, f"__{_n}__", _binop(_n))
    setattr(Probe, f"__r{_n}__", _binop("r" + _n))
    setattr(Probe, f"__i{_n}__", _binop("i" + _n))


# ---------------------------------------------------------------------------------------------------------------------- typed inputs
_INTS = [0, 1, -1, 2, 3, -2, 5, 10, 7, -7, 100, 255, 256, 987654321, 2 ** 63, -(2 ** 31), 10 ** 20]
_STRS = ["", "a", "ab", " a ", "A", "aB c", "é", "ß", "1", "12", "-3", "a,b", "x" * 6, "a\n", "\t", "ǅ", "ﬁ", "a-b_c", "pkg/x.py", " ", "abc"]
_FLOATS = [0.0, -0.0, 1.0, -1.5, 2.5, 1e16, -1e16, float("inf"), float("-inf"), float("nan"), 0.1, 3.0]
_BYTES = [b"", b"a", b"ab", b"\xff", b" a "]


def values(ty, rng: random.Random, budget: int = 12, depth: int = 0) -> list:
    """Concrete values of an exact builtin type (a type tuple of hlith.obligation.symeq.terms)."""
    k = ty[0]
    if k == "int":
        return _INTS[:budget]
    if k == "bool":
        return [False, True]
    if k == "str":
        return _STRS[:budget]
    if k == "float":
        return _FLOATS[:budget]
    if k == "none":
        return [None]
    if k == "bytes":
        return _BYTES[:budget]
    if k in ("list", "tuple", "set", "frozenset"):
        inner = values(ty[1], rng, max(4, budget // 2), depth + 1)
        out = [[]]
        out += [[x] for x in inner[:4]]
        out += [[x, y] for x in inner[:3] for y in inner[:3]]
        for _ in range(6):
            n = rng.randint(3, 5)
            out.append([rng.choice(inner) for _ in range(n)])
        conv = {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset}[k]
        res = []
        for x in out:
            try:
                res.append(conv(x))
            except TypeError:
                pass
        return res
    if k == "ftuple":
        parts = [values(t, rng, 4, depth + 1) for t in ty[1:]]
        return [tuple(p) for p in itertools.islice(itertools.product(*parts), 40)]
    if k == "dict":
        ks = values(ty[1], rng, 4, depth + 1)
        vs = values(ty[2], rng, 4, depth + 1)
        out = [{}]
        for a in ks[:3]:
            out.append({a: vs[0]})
        for _ in range(6):
            d = {}
            for _ in range(rng.randint(1, 4)):
                try:
                    d[rng.choice(ks)] = rng.choice(vs)
                except TypeError:
                    pass
            out.append(d)
        return out
    raise ValueError(f"no generator for {ty}")


def typed_inputs(param_types: list, rng: random.Random, limit: int = 400) -> list:
    """Argument tuples for a list of per-parameter alternative-type lists."""
    per = []
    for alts in param_types:
        vs = []
        for t in alts:
            vs += values(t, rng)
        per.append(vs)
    total = 1
    for vs in per:
        total *= max(1, len(vs))
    if total <= limit:
        return list(itertools.product(*per))
    out = []
    seen = set()
    # boundary rows first: each value of each parameter appears with the first values of the others
    for i, vs in enumerate(per):
        for v in vs:
            row = tuple(v if j == i else per[j][0] for j in range(len(per)))
            out.append(row)
    while len(out) < limit:
        row = tuple(rng.choice(vs) for vs in per)
        out.append(row)
    return out[:limit]


def _copy(v):
    import copy

    try:
        return copy.deepcopy(v)
    except Exception:  # noqa: BLE001
        return v


class _Timeout(BaseException):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


def run(fn, args, world=None, seconds: float = 0.25) -> tuple:
    """Call fn(*args) on private copies of the arguments; the outcome includes what the call did to them. A call that does not finish in `seconds` is the outcome
    ("diverge",): a mutant that loops forever is an ordinary, comparable behaviour."""
    import signal

    a = [_copy(x) for x in args] if world is None else list(args)
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        r = fn(*a)
        signal.setitimer(signal.ITIMER_REAL, 0)
        out = ("ret", desc(r))
        if type(r) in (list, dict, set):
            # identity with an argument is observable for a mutable result
            out += (tuple(i for i, x in enumerate(a) if x is r),)
    except _Timeout:
        return ("diverge",)
    except RecursionError:
        signal.setitimer(signal.ITIMER_REAL, 0)
        return ("budget",)
    except MemoryError:
        signal.setitimer(signal.ITIMER_REAL, 0)
        return ("budget",)
    except BaseException as e:  # noqa: BLE001
        signal.setitimer(signal.ITIMER_REAL, 0)
        out = ("raise", type(e).__name__, tuple(desc(x) for x in e.args), desc(e.__cause__) if e.__cause__ is not None else None)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    final = tuple(desc(x) for x in a)
    return out + (final, world.h.hex() if world is not None else None)


def compile_fn(src: str, name: str):
    ns: dict = {}
    exec(compile(src, "<oracle>", "exec"), ns)  # noqa: S102 - test corpus only
    obj = ns
    for part in name.split("."):
        obj = obj[part] if isinstance(obj, dict) else getattr(obj, part)
    return obj


def differ_typed(base_src: str, post_src: str, name: str, param_types: list, seed: int = 0, limit: int = 400):
    """First typed input on which the two versions are observably different, or None."""
    fb, fp = compile_fn(base_src, name), compile_fn(post_src, name)
    rng = random.Random(seed)
    for args in typed_inputs(param_types, rng, limit):
        ob, op = run(fb, args), run(fp, args)
        if ob != op and "budget" not in (ob[0], op[0]):
            return args, ob, op
    return None


def differ_probes(base_src: str, post_src: str, name: str, nparams: int, seeds: int = 40, typed: dict | None = None):
    """First random interpretation under which the two versions are observably different, or None. `typed` maps parameter index -> list of concrete values to use there."""
    fb, fp = compile_fn(base_src, name), compile_fn(post_src, name)
    for seed in range(seeds):
        rng = random.Random(seed)
        outs = []
        for fn in (fb, fp):
            w = World(seed)
            args = []
            r2 = random.Random(seed)
            for i in range(nparams):
                if typed and i in typed:
                    args.append(_copy(r2.choice(typed[i])))
                else:
                    args.append(Probe(w, 1000 + i))
            outs.append(run(fn, args, w))
        if outs[0] != outs[1] and "budget" not in (outs[0][0], outs[1][0]):
            return seed, outs[0], outs[1]
        del rng
    return None


def is_nan(x):
    return isinstance(x, float) and math.isnan(x)
