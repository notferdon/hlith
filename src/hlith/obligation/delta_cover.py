# SPDX-License-Identifier: Apache-2.0
"""Guard coverage by a declared delta (contract O3).

An approved intended change may add an entry guard that RAISES (e.g. `if "\\0" in name: raise ValueError`).
The static account cannot model every guard condition, so such a guard is an unsupported-guard record that
blocks (NOT_DERIVED). This pure function decides whether that exact record is *covered by* a declared delta,
using only what the independent differential observed. It never looks at the proposer's say-so alone and it
never covers a guard by a callable-wide exemption.

Covered only if ALL hold (any miss keeps the guard blocking):
  1. the guard record is an unsupported entry guard on the post side with a resolved raised exception;
  2. a delta of the same symbol is machine-checkable (not advisory) and expects `raises` of exactly that exception;
  3. the differential observed >= MIN_TRIGGER plain (non-injected) calls that matched the delta predicate AND raised
     the expected exception, and >= MIN_AGREE inputs outside the predicate on which pre == post;
  4. GUARD IDENTITY (F-C1): the exception type alone never identifies a guard. The guard's own condition (its
     ``condition_source``) must evaluate True, by this module's pure evaluator, on >= MIN_TRIGGER of those triggering
     inputs and be decidable on all of them; the delta predicate must name only parameters the callable has; and no
     input with ``guard condition AND NOT delta predicate`` may be found (the guard may not raise outside the delta).
     A guard whose condition the evaluator cannot decide (e.g. ``secret_backdoor(x)``) is never covered by a delta.
Approval (human confirmer) is NOT checked here: the caller records the coverage as conditional on the
`deltas-confirmed` obligation, which blocks landing without a matching approval.
Unverified by construction: callers outside the observed inputs may pass values the guard now rejects.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

MIN_TRIGGER = 5
MIN_AGREE = 5
OPEN_SCOPE = ("callers outside the observed inputs may supply values the new guard rejects; "
              "no general caller-compatibility claim is made")


@dataclass(frozen=True)
class GuardCoverage:
    covered: bool
    reason: str
    delta_id: str | None = None
    triggering: int = 0
    agreeing: int = 0

    @property
    def evidence(self) -> str:
        if not self.covered:
            return self.reason
        return (f"guard covered by declared delta {self.delta_id}: {self.triggering} observed plain triggering calls "
                f"raised the expected exception, {self.agreeing} non-matching inputs agreed pre/post; "
                f"conditional on deltas-confirmed; open scope: {OPEN_SCOPE}")


def _plain(examples: Sequence[Mapping[str, Any]]) -> int:
    return sum(1 for e in examples if not e.get("inject"))


_TYPED = {"empty_str": "{p} == ''", "none": "{p} is None", "int_zero": "{p} == 0", "int_neg": "{p} < 0",
          "int_nonneg": "{p} >= 0", "str_nonempty": "len({p}) > 0", "empty_container": "len({p}) == 0",
          "bool": "isinstance({p}, bool)"}


def _predicate_source(d: Mapping[str, Any]) -> str | None:
    """The delta predicate as one expression over the callable's parameters, or None when it is not expressible."""
    pred = d.get("predicate")
    if isinstance(pred, str):
        return pred
    if isinstance(pred, Mapping):
        if pred.get("type") == "expr" and isinstance(pred.get("expr"), str):
            return pred["expr"]
        if pred.get("type") == "typed" and pred.get("class") in _TYPED and isinstance(pred.get("param"), str):
            return _TYPED[pred["class"]].format(p=pred["param"])
    return None


def _names(expr: ast.expr) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def _env(example: Mapping[str, Any], params: Sequence[str]) -> dict[str, Any]:
    env = dict(zip(params, example.get("args") or []))
    env.update(example.get("kwargs") or {})
    return env


def _terminal(body: Sequence[ast.stmt]) -> bool:
    """True when this statement list always leaves the function (return/raise), so code after it is dominated by
    the NEGATION of the test that guarded it."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    return isinstance(last, ast.If) and bool(last.orelse) and _terminal(last.body) and _terminal(last.orelse)


def _stores_and_mutations(stmts: Sequence[ast.stmt], before: int) -> set[str]:
    """Names (re)bound or mutated by a method call in code that textually precedes line ``before``."""
    out: set[str] = set()
    for st in stmts:
        for n in ast.walk(st):
            if getattr(n, "lineno", before) >= before:
                continue
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                  and isinstance(n.value.func.value, ast.Name)):
                out.add(n.value.func.value.id)  # statement x.append(...) / x.update(...): x may differ from what the prefix tested
    return out


def dominating_conditions(function_source: str, guard_lineno: int) -> list[str]:
    """Conditions that hold on EVERY path that reaches the ``if`` at ``guard_lineno`` (1-based, in ``function_source``):
    the negated test of each earlier sibling ``if`` whose body always returns/raises (an early return), the test of each
    enclosing ``if`` branch (negated in its ``else``), as expression sources over the function's own names. A condition
    is dropped when a name it uses is rebound or mutated before the guard. Unknown or unparsable input gives ``[]``:
    a missing prefix can only make the guard look broader, so the caller refuses more, never less."""
    try:
        tree = ast.parse(function_source)
    except (SyntaxError, ValueError):
        return []
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
           and n.lineno <= guard_lineno <= (n.end_lineno or n.lineno)]
    if not fns:
        return []
    fn = max(fns, key=lambda n: n.lineno)  # innermost

    def walk(stmts: Sequence[ast.stmt], acc: list[ast.expr]) -> list[ast.expr] | None:
        acc = list(acc)
        for st in stmts:
            if getattr(st, "lineno", 0) == guard_lineno and isinstance(st, ast.If):
                return acc
            end = getattr(st, "end_lineno", st.lineno)
            if st.lineno <= guard_lineno <= end:
                if isinstance(st, ast.If):
                    if st.body and st.body[0].lineno <= guard_lineno <= (st.body[-1].end_lineno or 0):
                        return walk(st.body, [*acc, st.test])
                    if st.orelse and st.orelse[0].lineno <= guard_lineno <= (st.orelse[-1].end_lineno or 0):
                        return walk(st.orelse, [*acc, ast.UnaryOp(op=ast.Not(), operand=st.test)])
                    return None
                if isinstance(st, ast.With):
                    return walk(st.body, acc)
                return acc  # loop/try/match: nothing inside it is known to dominate
            if isinstance(st, ast.If):
                if _terminal(st.body) and not _terminal(st.orelse):
                    acc.append(ast.UnaryOp(op=ast.Not(), operand=st.test))
                elif _terminal(st.orelse) and not _terminal(st.body):
                    acc.append(st.test)
        return None

    found = walk(fn.body, [])
    if not found:
        return []
    changed = _stores_and_mutations(fn.body, guard_lineno)
    out = []
    for c in found:
        if {n.id for n in ast.walk(c) if isinstance(n, ast.Name)} & changed:
            continue
        out.append(ast.unparse(c))
    return out


def is_singleton_identity_predicate(pred_src: str | None, params: Sequence[str]) -> bool:
    """True when the callable has ONE non-receiver parameter and the predicate tests exact identity
    against a Python singleton (None, True, or False). The IN domain has mathematical cardinality 1,
    so requiring >= 5 distinct triggering calls would be impossible while 1 triggering call exhausts IN."""
    if not pred_src:
        return False
    real = [p for p in params if p not in ("self", "cls")]
    if len(real) != 1:
        return False
    pname = real[0]
    try:
        node = ast.parse(pred_src.strip(), mode="eval").body
    except SyntaxError:
        return False
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Is)):
        return False
    left, right = node.left, node.comparators[0]
    if isinstance(left, ast.Name) and left.id == pname and isinstance(right, ast.Constant):
        return right.value is None or type(right.value) is bool
    if isinstance(right, ast.Name) and right.id == pname and isinstance(left, ast.Constant):
        return left.value is None or type(left.value) is bool
    return False


def _min_trigger(pred_src: str | None, params: Sequence[str]) -> int:
    return 1 if is_singleton_identity_predicate(pred_src, params) else MIN_TRIGGER


def _identity(cond_src: str | None, pred_src: str | None, examples: Sequence[Mapping[str, Any]],
              params: Sequence[str], prefix: Sequence[str] = ()) -> str | None:
    """None when guard ``cond_src`` is attributable to the delta predicate on these examples; else the reason.

    ``prefix`` are conditions that dominate the guard (early returns before it): the guard raises only where
    prefix AND condition hold, so that conjunction is what is compared with the predicate."""
    from .. import drive_inputs as di

    if not cond_src:
        return "guard identity unknown: the record carries no condition_source"
    if not params:
        return "parameter names of the callable were not supplied, so the guard condition cannot be evaluated"
    if not pred_src:
        return "the delta predicate is not an expression over the parameters"
    try:
        g = ast.parse(cond_src.strip(), mode="eval").body
        p = ast.parse(pred_src.strip(), mode="eval").body
    except SyntaxError:
        return "guard condition or delta predicate does not parse"
    allowed = set(params) | set(di._EVAL_TYPES) | {"len", "abs", "min", "max", "isinstance", "type", "bool"}
    missing = sorted(n for n in _names(p) if n not in allowed)
    if missing:
        return f"delta predicate names {missing}, which are not parameters of the callable (renamed or foreign)"
    kept = []
    for c in prefix or ():  # only prefix conditions the independent evaluator can read; others are ignored (refuses more)
        try:
            ce = ast.parse(str(c).strip(), mode="eval").body
        except SyntaxError:
            continue
        if _names(ce) <= allowed:
            kept.append(str(c).strip())
    if kept:
        cond_src = " and ".join(f"({x})" for x in [*kept, cond_src.strip()])
        g = ast.parse(cond_src, mode="eval").body
    hits = 0
    for e in examples:
        env = _env(e, params)
        tg = di._tri(g, {**di._EVAL_TYPES, **env})
        if tg is None:
            return f"guard condition `{cond_src}` is not decidable by the independent evaluator on an observed input"
        if tg:
            tp = di._tri(p, {**di._EVAL_TYPES, **env})
            if tp is None:
                return f"delta predicate `{pred_src}` is not decidable by the independent evaluator on an observed input"
            if tp is False:
                return "the guard raised on an input outside the delta predicate"
            hits += 1
    min_trig = _min_trigger(pred_src, params)
    if hits < min_trig:
        return f"the guard condition held on only {hits} of the observed triggering inputs (< {min_trig}); the raises are attributed elsewhere"
    if ast.dump(g) == ast.dump(p):
        return None
    # the guard may not raise anywhere the delta does not declare: search for an input in G and not P
    ps = [(n, None) for n in params]
    cands, why = di.candidates_detailed(ps, [f"({cond_src}) and not ({pred_src})"], want="true", timeout_ms=300, max_per_condition=2)
    if cands:
        return f"the guard also raises outside the delta predicate (e.g. {cands[0].params})"
    reason = why.get(0, "")
    if (not reason.startswith("true: unsat within the explored caps")
            or any(tok in reason for tok in (
                "partial", "unsupported", "timeout", "budget", "sandbox",
                "bounded to K=", "symbolic sequences", "skipped", "not modelled",
            ))):
        return f"guard vs delta predicate equivalence could not be decided ({reason or 'no solver proof'})"
    return None


def guard_coverage(guard: Mapping[str, Any], observations: Mapping[str, Any] | None,
                   deltas: Sequence[Mapping[str, Any]], symbol: str, *, params: Sequence[str] = ()) -> GuardCoverage:
    if guard.get("kind") != "unsupported_entry_guard":
        return GuardCoverage(False, f"not an unsupported entry guard ({guard.get('kind')})")
    if guard.get("side") not in ("post", "both"):
        return GuardCoverage(False, "guard is not on the post side")
    exc = guard.get("raised_exception")
    if not exc:
        return GuardCoverage(False, "guard's raised exception is unresolved/ambiguous")
    if not observations:
        return GuardCoverage(False, "no delta observations from the differential")
    obs = (observations.get("delta_observations") or {})
    why = []
    for d in deltas:
        if d.get("symbol") != symbol:
            continue
        did = str(d.get("id"))
        exp = d.get("expected") or {}
        if not d.get("predicate") or not exp:
            why.append(f"{did}: advisory (no predicate/expected)")
            continue
        if exp.get("kind") != "raises" or exp.get("exc_type") != exc:
            why.append(f"{did}: expects {exp.get('kind')} {exp.get('exc_type')}, guard raises {exc}")
            continue
        o = obs.get(did)
        if not o:
            why.append(f"{did}: not observed")
            continue
        plain_ex = [e for e in (o.get("raised_examples") or []) if not e.get("inject")]
        trig = len(plain_ex)
        if o.get("truncated") is not True and o.get("raised_expected_count", 0) < trig:
            trig = int(o.get("raised_expected_count", 0))
        agree = int(o.get("nonmatching_agree_count", 0))
        min_trig = _min_trigger(_predicate_source(d), params)
        if trig < min_trig:
            why.append(f"{did}: only {trig} plain triggering calls (< {min_trig})")
            continue
        if agree < MIN_AGREE:
            why.append(f"{did}: only {agree} agreeing non-matching inputs (< {MIN_AGREE})")
            continue
        miss = _identity(guard.get("condition_source"), _predicate_source(d), plain_ex, params,
                         prefix=guard.get("dominating_conditions") or ())
        if miss is not None:
            why.append(f"{did}: {miss}")
            continue
        return GuardCoverage(True, "covered", did, trig, agree)
    return GuardCoverage(False, "no declared delta covers this guard: " + ("; ".join(why) or "no delta names the symbol"))


def removed_guard_coverage(cond_src: str | None, exc: str | None, observations: Mapping[str, Any] | None,
                           deltas: Sequence[Mapping[str, Any]], symbol: str, *, params: Sequence[str] = ()) -> GuardCoverage:
    """A REMOVED entry guard (a precondition that vanished) is covered only by a declared, machine-checkable delta
    whose observed examples show pre RAISING ``exc`` and post NOT raising it, on inputs where the removed guard's own
    condition held (same identity rule as guard_coverage). Without that, the removal is unexplained: blocking."""
    if not exc:
        return GuardCoverage(False, "removed guard's raised exception is unresolved/ambiguous")
    if not observations:
        return GuardCoverage(False, "no delta observations from the differential")
    obs = observations.get("delta_observations") or {}
    why = []
    for d in deltas:
        if d.get("symbol") != symbol:
            continue
        did = str(d.get("id"))
        if not d.get("predicate") or not d.get("expected"):
            why.append(f"{did}: advisory (no predicate/expected)")
            continue
        o = obs.get(did)
        if not o:
            why.append(f"{did}: not observed")
            continue
        ex = [e for e in (o.get("matched_examples") or []) if not e.get("inject")
              and (e.get("pre") or {}).get("k") == "exc" and (e.get("pre") or {}).get("t") == exc
              and (e.get("post") or {}).get("k") != "exc"]
        agree = int(o.get("nonmatching_agree_count", 0))
        min_trig = _min_trigger(_predicate_source(d), params)
        if len(ex) < min_trig:
            why.append(f"{did}: only {len(ex)} observed inputs where pre raised {exc} and post did not (< {min_trig})")
            continue
        if agree < MIN_AGREE:
            why.append(f"{did}: only {agree} agreeing non-matching inputs (< {MIN_AGREE})")
            continue
        miss = _identity(cond_src, _predicate_source(d), ex, params)
        if miss is not None:
            why.append(f"{did}: {miss}")
            continue
        return GuardCoverage(True, "covered", did, len(ex), agree)
    return GuardCoverage(False, "no declared delta covers the removal: " + ("; ".join(why) or "no delta names the symbol"))
