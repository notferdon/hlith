# SPDX-License-Identifier: Apache-2.0
"""Bounded Z3 worker for the guard-removal certificate. Launched as a SCRIPT (`python -I _cert_solver.py`) by
hlith.obligation.guard_certificate; never imported by the controller.

Why a separate process: the certificate's formula derives from repository text. The controller (the TCB) must not run an
unbounded native solver on it. This process sets its own resource limits BEFORE importing z3 (address space, CPU time, no
file creation, few descriptors), reads ONE JSON specification from stdin (already parsed by the controller: no source text,
no code), solves up to four satisfiability checks, and writes ONE JSON result to stdout. Any crash, limit hit or oversize
input surfaces to the controller as a non-zero exit / timeout / malformed output, which it maps to `unknown`.

Specification (all values JSON, version 1):
  {"v": 1, "timeout_ms": int, "cpu_s": int,
   "params": [[name, "int" | "bool" | "real"], ...],
   "pre":  {"guards": [[<bool node>, exc_id], ...], "ret": <numeric node>},
   "post": {"guards": [[<bool node>, exc_id], ...], "ret": <numeric node>},
   "idx": int, "pred": <bool node>, "exp": <numeric node>}
Numeric nodes: ["var", n] ["int", i] ["neg", N] ["bin", "add"|"sub"|"mul", N, N] ["divmod", "floordiv"|"mod", N, k]
               ["ite", B, N, N] ["int_of", B] ["from_b", B]
Boolean nodes: ["var", n] ["bool", b] ["and", [B..]] ["or", [B..]] ["not", B] ["truthy", N] ["cmp", [op..], [N..]]
Result: {"v": 1, "res": "unsat" | "sat" | "unknown" | "nosolver" | "error", "side": str, "model": {name: "i:N"|"r:P/Q"|"b:true"} | null,
         "reason": str}  ("unsat" = ALL checks unsat).
"""

import json
import resource
import sys

MAX_IN = 262144
MEM = 2 * 1024 ** 3


def _limits(cpu_s: int) -> None:
    for which, val in ((resource.RLIMIT_AS, MEM), (resource.RLIMIT_CPU, max(2, int(cpu_s))), (resource.RLIMIT_FSIZE, 0),
                       (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(which, (val, val))
        except (ValueError, OSError):
            pass  # a limit the platform refuses is not silently skipped for the others


def _out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))
    sys.stdout.flush()


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_IN + 1)
    if len(raw) > MAX_IN:
        _out({"v": 1, "res": "error", "side": "", "model": None, "reason": "specification too large"})
        return 0
    try:
        spec = json.loads(raw)
        if not isinstance(spec, dict) or spec.get("v") != 1:
            raise ValueError("bad specification")
        _limits(int(spec.get("cpu_s") or 10))
    except Exception as e:  # malformed input is an error result, not a crash
        _out({"v": 1, "res": "error", "side": "", "model": None, "reason": f"{type(e).__name__}: {str(e)[:120]}"})
        return 0
    try:
        import z3
    except Exception as e:
        _out({"v": 1, "res": "nosolver", "side": "", "model": None, "reason": f"{type(e).__name__}"})
        return 0

    sorts = {n: s for n, s in spec["params"]}
    vars_ = {n: (z3.Bool(n) if s == "bool" else z3.Int(n) if s == "int" else z3.Real(n)) for n, s in sorts.items()}

    def real(a, b):
        if a.sort() != b.sort():
            a = z3.ToReal(a) if a.sort() == z3.IntSort() else a
            b = z3.ToReal(b) if b.sort() == z3.IntSort() else b
        return a, b

    def N(node):
        t = node[0]
        if t == "var":
            return vars_[node[1]]
        if t == "int":
            return z3.IntVal(int(node[1]))
        if t == "neg":
            return -N(node[1])
        if t == "bin":
            a, b = real(N(node[2]), N(node[3]))
            return a + b if node[1] == "add" else a - b if node[1] == "sub" else a * b
        if t == "divmod":
            a, k = N(node[2]), int(node[3])
            if a.sort() != z3.IntSort() or k <= 0:
                raise ValueError("// and % need an int operand and a positive constant")
            return a / k if node[1] == "floordiv" else a % k
        if t == "ite":
            a, b = real(N(node[2]), N(node[3]))
            return z3.If(B(node[1]), a, b)
        if t in ("int_of", "from_b"):
            return z3.If(B(node[1]), z3.IntVal(1), z3.IntVal(0))
        raise ValueError(f"numeric node {t!r}")

    def B(node):
        t = node[0]
        if t == "var":
            return vars_[node[1]]
        if t == "bool":
            return z3.BoolVal(bool(node[1]))
        if t == "and":
            return z3.And(*[B(x) for x in node[1]])
        if t == "or":
            return z3.Or(*[B(x) for x in node[1]])
        if t == "not":
            return z3.Not(B(node[1]))
        if t == "truthy":
            return N(node[1]) != 0
        if t == "cmp":
            ops = {"lt": lambda a, b: a < b, "le": lambda a, b: a <= b, "gt": lambda a, b: a > b,
                   "ge": lambda a, b: a >= b, "eq": lambda a, b: a == b, "ne": lambda a, b: a != b}
            terms = [N(x) for x in node[2]]
            parts = []
            for op, a, b in zip(node[1], terms, terms[1:]):
                a, b = real(a, b)
                parts.append(ops[op](a, b))
            return parts[0] if len(parts) == 1 else z3.And(*parts)
        raise ValueError(f"boolean node {t!r}")

    def outcome(side):
        gs = [B(c) for c, _e in side["guards"]]
        code = z3.IntVal(0)
        for (c, ex), g in reversed(list(zip(side["guards"], gs))):
            code = z3.If(g, z3.IntVal(int(ex)), code)
        return (z3.Or(*gs) if gs else z3.BoolVal(False)), code, N(side["ret"]), gs

    def val(v):
        if z3.is_bool(v):
            return "b:" + ("true" if z3.is_true(v) else "false")
        if v.sort() == z3.IntSort():
            return "i:" + str(v.as_long())
        fr = v.as_fraction()
        return f"r:{fr.numerator}/{fr.denominator}"

    try:
        pre_r, pre_c, pre_v, pre_g = outcome(spec["pre"])
        post_r, post_c, post_v, _pg = outcome(spec["post"])
        idx = int(spec["idx"])
        g_eff = z3.And(*[z3.Not(f) for f in pre_g[:idx]], pre_g[idx]) if idx else pre_g[idx]
        P, E = B(spec["pred"]), N(spec["exp"])
        post_v1, E1 = real(post_v, E)
        pre_v2, post_v2 = real(pre_v, post_v)
        checks = (
            ("guard-vs-predicate", g_eff, z3.Not(P)),
            ("guard-vs-predicate", P, z3.Not(g_eff)),
            ("inside-P", P, z3.Not(z3.And(z3.Not(post_r), post_v1 == E1))),
            ("outside-P", z3.Not(P), z3.Or(pre_r != post_r, z3.And(pre_r, post_r, pre_c != post_c),
                                           z3.And(z3.Not(pre_r), z3.Not(post_r), pre_v2 != post_v2))),
        )
        per = max(100, int(spec.get("timeout_ms") or 2000))
        for side, *cs in checks:
            s = z3.Solver()
            s.set("timeout", per)
            s.add(*cs)
            r = s.check()
            if r == z3.unsat:
                continue
            if r == z3.sat:
                m = s.model()
                _out({"v": 1, "res": "sat", "side": side, "reason": "",
                      "model": {n: val(m.eval(vars_[n], model_completion=True)) for n in sorts}})
                return 0
            _out({"v": 1, "res": "unknown", "side": side, "model": None, "reason": str(s.reason_unknown())[:120]})
            return 0
        _out({"v": 1, "res": "unsat", "side": "", "model": None, "reason": ""})
    except MemoryError:
        _out({"v": 1, "res": "unknown", "side": "", "model": None, "reason": "memory limit"})
    except Exception as e:  # a formula the worker cannot build is an error result: the controller maps it to unknown
        _out({"v": 1, "res": "error", "side": "", "model": None, "reason": f"{type(e).__name__}: {str(e)[:120]}"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
