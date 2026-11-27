# SPDX-License-Identifier: Apache-2.0
"""`hlith propose-deltas`: a CANDIDATE delta set derived from the divergences the differential OBSERVED.

This is a claim for a human to review, never proof and never an approval. Nothing here approves, lands or
changes a verdict: the output is a manifest the operator may feed back in, a provenance record, and the exact
re-run command (with the canonical delta_set_sha256) that the operator may choose to run.

What a candidate says: "on exactly these observed call inputs the callable now returns/raises X instead of Y".
It is a ``literal_inputs`` predicate over the observed calls (never widened to a typed/expr class: widening is the
human's call). Divergences that cannot be expressed that way (fault-injection calls, method receivers, non-JSON
arguments) are listed and excluded, with counts."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from ... import derive, differential, effect
from ...textsafe import clean, inspect
from ...runtime import MAX_LITERAL_INPUTS, _check_json_value, delta_set_sha256, validate_deltas

PROV_SOURCE = "observed-divergence"


def _paths_kinds(diff: str) -> dict[str, list[str]]:
    kinds: dict[str, list[str]] = {}
    old = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = line[4:].strip()
        elif line.startswith("+++ ") and old is not None:
            new = line[4:].strip()
            path = (new if new != "/dev/null" else old)
            path = re.sub(r"^[ab]/", "", path)
            kinds[path] = ["add"] if old == "/dev/null" else ["delete"] if new == "/dev/null" else ["modify"]
            old = None
    return kinds


def _expected(post: dict) -> dict | None:
    if not isinstance(post, dict) or post.get("unrepr"):
        return None
    if post.get("k") == "ret" and isinstance(post.get("r"), str):
        return {"kind": "returns", "value_repr": post["r"][:300]}
    if post.get("k") == "exc" and isinstance(post.get("t"), str):
        t = post["t"]
        return {"kind": "raises", "exc_type": t if "." in t else "builtins." + t}
    return None


def _json_safe(v) -> bool:
    """JSON-able AND accepted by the delta validator (bounded size/depth, no control characters)."""
    try:
        json.dumps(v, allow_nan=False)
        _check_json_value("input", {"args": v[0], "kwargs": v[1]})
        return True
    except (TypeError, ValueError):
        return False


_SCRATCH_RE = re.compile(r"(?:^|/)hlith-[a-z0-9_]+-[A-Za-z0-9_]{4,}(?:/|$)")  # tempfile prefixes: hlith-propose-*


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _strings(k)
            yield from _strings(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _strings(x)


def scratch_path(r: dict) -> bool:
    """True if a call input holds a path under a per-run hlith scratch dir (e.g. the filesystem-layout seeds the
    differential builds under hlith-propose-<random>/): it can never re-match on a later run, so it is never a candidate."""
    return any("/" in x and _SCRATCH_RE.search(x) for x in _strings([r.get("args"), r.get("kwargs")]))


SCRATCH_REASON = "per-run scratch path: cannot re-match on a later run; covered by a typed or expr delta if you intend the behaviour"


def candidates_for(symbol: str, divs: Sequence[dict], tag: str) -> tuple[list[dict], dict]:
    """Group plain divergences by the post outcome; one delta per group (split at MAX_LITERAL_INPUTS inputs)."""
    excl = {"claim_contradicted": 0, "fault_injection": 0, "method_receiver": 0, "arguments_not_expressible_in_a_delta": 0, "unrepresentable_outcome": 0, "env_dependent": 0, "per_run_scratch_path": 0}
    groups: dict[str, list[dict]] = {}
    for r in divs:
        if r.get("oracle") == "declared-delta":  # the manifest's own claim is false here: report it, never propose from it
            excl["claim_contradicted"] += 1
        elif r.get("inject") is not None:
            excl["fault_injection"] += 1
        elif r.get("receiver") is not None:
            excl["method_receiver"] += 1
        elif r.get("env"):
            excl["env_dependent"] += 1
        elif scratch_path(r):
            excl["per_run_scratch_path"] += 1
        elif not (isinstance(r.get("args"), list) and isinstance(r.get("kwargs"), dict) and _json_safe([r["args"], r["kwargs"]])):
            excl["arguments_not_expressible_in_a_delta"] += 1
        elif _expected(r.get("post")) is None:
            excl["unrepresentable_outcome"] += 1
        else:
            groups.setdefault(json.dumps(_expected(r["post"]), sort_keys=True), []).append(r)
    deltas: list[dict] = []
    for gi, (key, rs) in enumerate(sorted(groups.items())):
        exp = json.loads(key)
        seen, uniq = set(), []
        for r in rs:
            k = json.dumps([r["args"], r["kwargs"]], sort_keys=True)
            if k not in seen:
                seen.add(k)
                uniq.append(r)
        for ci in range(0, len(uniq), MAX_LITERAL_INPUTS):
            chunk = uniq[ci:ci + MAX_LITERAL_INPUTS]
            pre = chunk[0].get("pre") or {}
            pre_txt = str(pre.get("r") or pre.get("t") or "?")[:120]
            post_txt = str(exp.get("value_repr") or exp.get("exc_type"))[:120]
            deltas.append({
                "id": f"proposed-{tag}-{gi + 1}-{ci // MAX_LITERAL_INPUTS + 1}", "symbol": symbol, "kind": "behavior",
                "claim": f"CANDIDATE (observed, unreviewed): on the {len(chunk)} listed inputs {symbol} gives {post_txt} (was e.g. {pre_txt})"[:290],
                "input_domain": "exactly the observed call inputs listed in predicate.inputs",
                "pre": pre_txt, "post": post_txt,
                "predicate": {"type": "literal_inputs", "inputs": [{"args": r["args"], "kwargs": r["kwargs"]} for r in chunk]},
                "expected": exp,
            })
    return deltas, {k: v for k, v in excl.items() if v}


def _param_names(root: Path, file_path: str, func: str) -> list[str]:
    """Every parameter of the callable named by its QUALIFIED name within the file ('f' or 'Class.method'; a module-level def never stands in for a
    method). posonly, positional, `*args` (as '*args'), keyword-only and `**kw` (as '**kw') all count. [] when the callable cannot be resolved."""
    import ast
    try:
        tree = ast.parse((Path(root) / file_path).read_text())
    except (OSError, SyntaxError, ValueError):
        return []
    scope = tree.body
    *classes, name = str(func).split(".")
    for c in classes:
        scope = next((n.body for n in scope if isinstance(n, ast.ClassDef) and n.name == c), None)
        if scope is None:
            return []
    for n in scope:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            a = n.args
            out = [x.arg for x in (*a.posonlyargs, *a.args)]
            if a.vararg:
                out.append("*" + a.vararg.arg)
            out += [x.arg for x in a.kwonlyargs]
            if a.kwarg:
                out.append("**" + a.kwarg.arg)
            return out
    return []


_SHAPES = (  # narrowest first; a HINT is the first shape that every listed value satisfies
    ("== 0", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0),
    ("is None", lambda v: v is None),
    ("is empty", lambda v: isinstance(v, (str, list, dict)) and len(v) == 0),
    ("< 0", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0),
    ("> 0", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0),
    ("<= 0", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v <= 0),
    (">= 0", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0),
)


def _shapes(divs: list[dict], names: Sequence[str]) -> list[tuple[str, str]]:
    """[(param, shape label)] for parameters whose value, in EVERY given divergence, satisfies one simple shape."""
    cols: dict[str, list] = {}
    for d in divs:
        vals = {(names[i] if i < len(names) else f"arg{i}"): v for i, v in enumerate(d.get("args") or [])}
        vals.update(d.get("kwargs") or {})
        for k, v in vals.items():
            cols.setdefault(k, []).append(v)
    found = []
    for k, vs in cols.items():
        if len(vs) != len(divs):
            continue
        for label, ok in _SHAPES:
            if all(ok(v) for v in vs):
                found.append((k, label))
                break
    return found


def shared_pattern(divs: list[dict], names: Sequence[str]) -> str | None:
    """One sentence naming parameters whose values, in EVERY listed divergence, satisfy one simple comparison
    (0 / None / empty). A HINT computed from the listed inputs only: never a candidate, never a claim that
    unlisted inputs agree. None when fewer than two divergences or nothing is shared."""
    divs = [d for d in divs if d.get("oracle") != "declared-delta" and not d.get("inject")]
    if len(divs) < 2:
        return None
    found = [f"{k} {label}" for k, label in _shapes(divs, names)]
    if not found:
        return None
    return (f"HINT (computed from the {len(divs)} listed inputs only; not a candidate, not a claim about unlisted inputs): "
            f"all {len(divs)} divergences have " + " and ".join(found))


BROADER_LABEL = ("OPTION B (broader claim): covers UNOBSERVED inputs too: a stronger claim; the differential will test its "
                 "boundary; review carefully. Never the default, never approved by hlith.")


def broader_delta(symbol: str, divs: Sequence[dict], names: Sequence[str], tag: str) -> dict | None:
    """An expr delta for the HINT, only when the hint is ONE numeric comparison on ONE parameter and every listed
    divergence has the same post outcome. A claim for review, never approved by hlith."""
    divs = list(divs)
    if len(divs) < 2 or any(d.get("oracle") == "declared-delta" or d.get("inject") is not None or d.get("receiver") is not None
                            or d.get("env") for d in divs):
        return None
    outs = {json.dumps(_expected(d.get("post")), sort_keys=True) for d in divs}
    if len(outs) != 1 or "null" in outs:
        return None
    exp = json.loads(next(iter(outs)))
    numeric = [(k, lab) for k, lab in _shapes(divs, names) if lab in ("== 0", "< 0", "> 0", "<= 0", ">= 0")]
    if len(numeric) != 1 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", numeric[0][0]):
        return None
    param, lab = numeric[0]
    expr = f"{param} {lab}"
    pre_txt = str(next(iter(divs)).get("pre", {}).get("r") or next(iter(divs)).get("pre", {}).get("t") or "?")[:120]
    post_txt = str(exp.get("value_repr") or exp.get("exc_type"))[:120]
    d = {"id": f"proposed-{tag}-broader", "symbol": symbol, "kind": "behavior",
         "claim": f"BROADER CLAIM (unobserved inputs included, unreviewed): whenever {expr}, {symbol} gives {post_txt}"[:290],
         "input_domain": f"every call with {expr}", "pre": pre_txt, "post": post_txt,
         "predicate": {"type": "expr", "param": param, "expr": expr}, "expected": exp}
    try:
        validate_deltas([d])
    except ValueError:
        return None
    return d


def _eligible(r: dict) -> bool:
    """A divergence a plain literal delta could cover (the same test candidates_for applies)."""
    return (r.get("oracle") != "declared-delta" and r.get("inject") is None and r.get("receiver") is None and not r.get("env")
            and not scratch_path(r) and isinstance(r.get("args"), list) and isinstance(r.get("kwargs"), dict) and _json_safe([r["args"], r["kwargs"]])
            and _expected(r.get("post")) is not None)


_PRED_ORDER = ("== 0", "is None", "is empty", "< 0", "> 0", "<= 0", ">= 0")
DOMINANT_MIN_FRACTION = 0.75
DOMINANT_MIN_COUNT = 2


def _values(d: dict, names: Sequence[str]) -> dict:
    vals = {(names[i] if i < len(names) else f"arg{i}"): v for i, v in enumerate(d.get("args") or [])}
    vals.update(d.get("kwargs") or {})
    return vals


def _fits(d: dict, names: Sequence[str], pat: tuple[str, str]) -> bool:
    param, label = pat
    vals = _values(d, names)
    if param not in vals:
        return False
    v = vals[param]
    if isinstance(v, bool) and label in ("== 0", "< 0", "> 0", "<= 0", ">= 0"):
        v = int(v)  # for grouping, False/True are the ints 0/1 (a delta predicate `x == 0` matches False too)
    return dict(_SHAPES)[label](v)


def dominant_pattern(divs: Sequence[dict], names: Sequence[str]) -> tuple[str, str] | None:
    """(param, shape) satisfied by the largest share of the eligible divergences: at least DOMINANT_MIN_COUNT of them and
    DOMINANT_MIN_FRACTION of all. Ties go to the narrower shape. None: no common pattern, so nothing is proposed by default."""
    el = [d for d in divs if _eligible(d)]
    if len(el) < DOMINANT_MIN_COUNT:
        return None
    params = sorted({k for d in el for k in _values(d, names)})
    best, best_n = None, 0
    for k in params:
        for label in _PRED_ORDER:
            n = sum(1 for d in el if _fits(d, names, (k, label)))
            if n > best_n:
                best, best_n = (k, label), n
    if best is None or best_n < DOMINANT_MIN_COUNT or best_n / len(el) < DOMINANT_MIN_FRACTION:
        return None
    return best


_FORMS = (
    ("len(x.encode('utf-8'))", lambda v: len(v.encode("utf-8"))),
    ("len(x.encode('utf-16-le'))", lambda v: len(v.encode("utf-16-le"))),
    ("len(x)", len),
    ("x.upper()", str.upper),
    ("x.lower()", str.lower),
    ("x.strip()", str.strip),
    ("x.casefold()", str.casefold),
    ("str(x)", str),
    ("int(x)", int),
)


def closed_form(divs: Sequence[dict], names: Sequence[str]) -> dict | None:
    """For divergences that are ALL one-str-parameter calls returning a value: the first catalogue form whose result's repr
    equals the observed post return for EVERY pair. None when no form reproduces all pairs. Returns {"attempted": False}
    when this does not apply (fewer than two eligible divergences, or any input is not a single str)."""
    el = [d for d in divs if _eligible(d) and (d.get("post") or {}).get("k") == "ret"]
    vals = []
    for d in el:
        v = _values(d, names)
        if len(v) != 1 or not isinstance(next(iter(v.values())), str):
            return {"attempted": False}
        vals.append((next(iter(v)), next(iter(v.values())), (d.get("post") or {}).get("r")))
    if len(vals) < 2 or len({p for p, _v, _r in vals}) != 1:
        return {"attempted": False}
    for text, f in _FORMS:
        try:
            if all(repr(f(v)) == r for _p, v, r in vals):
                return {"attempted": True, "param": vals[0][0], "form": re.sub(r"\bx\b", vals[0][0], text), "pairs": len(vals)}
        except (ValueError, TypeError):
            continue
    return {"attempted": True, "form": None, "pairs": len(vals), "param": vals[0][0]}


def expression_refusal(names) -> str | None:
    """Why an expression claim must NOT be emitted for a callable with these parameters (self/cls dropped): the closed form is built from ONE bound value per
    observed call, so any other parameter was never varied and the claim would cover calls nobody observed. None when exactly one parameter remains."""
    rest = [n for n in (names or []) if n not in ("self", "cls")]
    if len(rest) == 1:
        return None
    if not rest:
        return "parameters of the callable are unknown: the expression claim is not emitted"
    return f"other parameters unconstrained, never varied ({', '.join(rest)}): the expression claim would cover calls that were never observed; the literal candidates remain"


def expression_delta(symbol: str, cform: dict | None, tag: str, names=None) -> dict | None:
    """The broader EXPRESSION candidate for a closed form that reproduces ALL observed pairs: a returns_expr delta over `param is a non-empty str`.
    Validated by the real delta validator and by the closed grammar WITH the callable's parameter name before it is returned; None otherwise.
    It covers every such input, including untried ones: a stronger claim, never default-included (only `--expression` emits it)."""
    if not cform or not cform.get("attempted") or not cform.get("form"):
        return None
    if names is not None and expression_refusal(names) is not None:
        return None
    param, form = str(cform.get("param") or ""), str(cform["form"])
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", param):
        return None
    from ...expected_expr import validate_expected_expr
    ok, _why = validate_expected_expr(form, [param])
    if not ok:
        return None
    n = cform.get("pairs")
    d = {"id": f"proposed-{tag}-expr", "symbol": symbol, "kind": "behavior",
         "claim": (f"EXPRESSION CANDIDATE (broader, unreviewed): for every call where {param} is a non-empty str, including untried inputs, "
                   f"{symbol} returns {form} (reproduces all {n} observed pairs)")[:290],
         "input_domain": f"every call where {param} is a non-empty str, including inputs not tried",
         "pre": "differs from the base on the observed inputs", "post": form[:120],
         "predicate": {"type": "typed", "param": param, "class": "str_nonempty"},
         "expected": {"kind": "returns_expr", "expr": form}}
    try:
        validate_deltas([d])
    except ValueError:
        return None
    return d


def propose(repo: Path, diff: str, patch_path: str, *, base_manifest: dict | None, artifact_sha256: str | None,
            extra_sys_path: Sequence[str] = (), target_python: str | None = None, max_divergences: int = 200,
            timeout: float = 600.0, include_all: bool = False, expression: bool = False) -> dict:
    repo = Path(repo).resolve()
    acct = effect.build_effect_account(repo, diff)
    patch_sha = hashlib.sha256(diff.encode()).hexdigest()
    tag = patch_sha[:8]
    out: dict = {"callables": [], "deltas": [], "listed": [], "patch_sha256": patch_sha}
    with tempfile.TemporaryDirectory(prefix="hlith-propose-") as w:
        work = Path(w)
        post = derive._patched_copy(repo, diff, work)
        base = derive._base_export(repo, work)
        try:  # the refusal run's pins: they must be collected too, or a candidate cannot cover them (design review F-A)
            from ... import feedback as _fb
            fbk = _fb.load_for_derive(repo, acct.to_dict(), python=target_python or sys.executable,
                                      extra_sys_path=tuple(extra_sys_path), proposer_paths=[patch_path])
        except Exception:  # noqa: BLE001 - pins are an addition to the collection, never a reason to fail
            fbk = None
        for mc in acct.modified_callables:
            module, func, root = derive._split_qualified(mc.qualified_name, mc.file_path)
            scratch = work / "collect" / func  # separate from derive's scratch
            seeds: list = []  # the delta_rel counterexample seeds the refusal run used
            got = derive._delta_rel_item(base, post, mc, [])
            if got is not None:
                seeds = differential.seeds_from_z3(got[1])
            kw = dict(base_root=str(base), post_root=str(post), module=module, function=func, proposer_paths=[patch_path],
                      import_root=root, extra_sys_path=list(extra_sys_path), target_python=target_python,
                      collect_divergences=max_divergences, timeout=timeout)
            cons = fbk.constraints(mc.qualified_name) if fbk is not None else None

            def collect(tag_dir: str, deltas: list | None = None):
                """The broad exploration, plus (when the refusal run had pins or seeds) a second pass for them, merged:
                pinned inputs and seeds run FIRST in the differential and a refutation there ends the search (design review F-A)."""
                dk = {"deltas": deltas} if deltas else {}
                sc = work / tag_dir / func
                o = differential.run_differential(scratch=str(sc), **kw, **dk)
                c = differential.read_divergences(str(sc)) or {"divergences": [], "count": 0, "truncated": False, "explored": 0,
                                                               "stopped_reason": "no divergences file (differential did not run)"}
                if seeds or (cons is not None and getattr(cons, "pinned_inputs", ())):
                    sc2 = work / (tag_dir + "2") / func
                    differential.run_differential(scratch=str(sc2), seeds=seeds, constraints=cons, **kw, **dk)
                    c2 = differential.read_divergences(str(sc2))
                    if c2 and c2["divergences"]:
                        key = lambda r: json.dumps([r.get("args"), r.get("kwargs"), r.get("env"), r.get("inject")], sort_keys=True)  # noqa: E731
                        have = {key(r) for r in c["divergences"]}
                        extra = [r for r in c2["divergences"] if key(r) not in have]
                        c = {**c, "divergences": [*extra, *c["divergences"]], "count": c["count"] + len(extra)}
                return o, c

            ob, col = collect("collect")
            names = _param_names(post, mc.file_path, func)
            _all_ds, excl = candidates_for(mc.qualified_name, col["divergences"], tag)
            pat = None if (include_all or expression) else dominant_pattern(col["divergences"], names)
            outliers: list[dict] = []
            xref = None
            if expression:  # ONLY the expression claim, and only when a closed form reproduces every observed pair
                xd = expression_delta(mc.qualified_name, closed_form(col["divergences"], names), tag, names=names)
                ds, mode = ([xd] if xd is not None else []), ("expression" if xd is not None else "expression-unavailable")
                xref = expression_refusal(names) if xd is None else None
            elif include_all:
                ds, mode = _all_ds, "include-all"
            elif pat is not None:
                fit = [r for r in col["divergences"] if not _eligible(r) or _fits(r, names, pat)]
                outliers = [r for r in col["divergences"] if _eligible(r) and not _fits(r, names, pat)]
                ds, _ = candidates_for(mc.qualified_name, fit, tag)
                mode = "dominant-pattern"
            else:
                ds, mode = [], ("no-eligible-divergence" if not any(_eligible(r) for r in col["divergences"]) else "no-common-pattern")
            scratch_rows = [r for r in col["divergences"] if scratch_path(r) and r.get("oracle") != "declared-delta"]
            preview = None
            if ds:  # DRY-RUN the check with the candidate in place: what still diverges outside it?
                try:
                    own_sym = [d for d in ((base_manifest or {}).get("deltas") or []) if d.get("symbol") == mc.qualified_name]
                    _o, pcol = collect("preview", own_sym + ds)
                    left = [r for r in pcol["divergences"] if not scratch_path(r)]
                    preview = {"ran": True, "uncovered_count": len(left), "uncovered": left[:50], "truncated": bool(pcol["truncated"]),
                               "explored": pcol["explored"], "verdict": _o.verdict.value}
                except Exception as e:  # noqa: BLE001 - the preview is advice, never a reason to lose the proposal
                    preview = {"ran": False, "error": f"{type(e).__name__}: {str(e)[:200]}", "uncovered_count": 0, "uncovered": []}
            cform = closed_form(col["divergences"], names) if mode in ("no-common-pattern", "expression", "expression-unavailable") else None
            hint = shared_pattern(col["divergences"], names)
            bd = broader_delta(mc.qualified_name, col["divergences"], names, tag)
            if bd is not None:
                out.setdefault("broader_deltas", []).append(bd)
            out["callables"].append({
                "hint": hint, "symbol": mc.qualified_name, "differential_obligation": ob.obligation_id, "verdict": ob.verdict.value,
                "divergences_seen": col["count"], "divergences_listed": len(col["divergences"]), "truncated": bool(col["truncated"]),
                "explored": col["explored"], "stopped_reason": col["stopped_reason"], "excluded": excl,
                "mode": mode, "pattern": (f"{pat[0]} {pat[1]}" if pat else None), "outliers": outliers,
                "scratch_rows": scratch_rows, "preview": preview, "closed_form": cform, "expression_refusal": xref if mode == "expression-unavailable" else None,
                "eligible": sum(1 for r in col["divergences"] if _eligible(r)),
                "candidate_deltas": [d["id"] for d in ds]})
            out["listed"] += [{"symbol": mc.qualified_name, **r} for r in col["divergences"]]
            out["deltas"] += ds
    own = list((base_manifest or {}).get("deltas", []))
    all_deltas = own + out["deltas"]
    validated = validate_deltas(all_deltas) if all_deltas else []  # raises ValueError if a candidate is malformed
    manifest = {**(base_manifest or {}), "paths": (base_manifest or {}).get("paths") or _paths_kinds(diff)}
    if validated:
        manifest["deltas"] = all_deltas
    out["manifest"] = manifest
    bds = out.get("broader_deltas") or []
    if bds and len(bds) == len(out["callables"]):  # one broader claim per modified callable, or no OPTION B
        bm = {**manifest, "deltas": own + bds}
        bv = validate_deltas(own + bds)
        out["broader"] = {"manifest": bm, "delta_set_sha256": delta_set_sha256(bv), "deltas": bds, "label": BROADER_LABEL}
    out["delta_set_sha256"] = delta_set_sha256(validated) if validated else None
    out["provenance"] = {
        "source": PROV_SOURCE, "claim_only": True, "auto_approved": False, "artifact_sha256": artifact_sha256,
        "patch_sha256": patch_sha, "differential_obligations": [c["differential_obligation"] for c in out["callables"]],
        "divergences_seen": sum(c["divergences_seen"] for c in out["callables"]),
        "divergences_listed": sum(c["divergences_listed"] for c in out["callables"]),
        "truncated": any(c["truncated"] for c in out["callables"]),
        "excluded": {c["symbol"]: c["excluded"] for c in out["callables"] if c["excluded"]},
        "mode": [c["mode"] for c in out["callables"]], "dominant_pattern": [c["pattern"] for c in out["callables"]],
        "not_included": [{"symbol": c["symbol"], "args": r.get("args"), "kwargs": r.get("kwargs"), "pre": r.get("pre"),
                          "post": r.get("post"), **({"reason": SCRATCH_REASON} if scratch_path(r) else {})}
                         for c in out["callables"] for r in [*c["outliers"], *c["scratch_rows"]]][:200],
        "preview": {c["symbol"]: c["preview"] for c in out["callables"] if c["preview"]},
        "closed_form": {c["symbol"]: c["closed_form"] for c in out["callables"] if c.get("closed_form")},
        "candidate_delta_ids": [d["id"] for d in out["deltas"]], "kept_operator_delta_ids": [d.get("id") for d in own],
        "note": "a CLAIM from observed behaviour, for human review; it is not proof and approving it is the operator's decision",
    }
    return out


def render(res: dict) -> str:
    L = []
    for c in res["callables"]:
        L.append(f"{c['symbol']}: differential {c['verdict']}; {c['divergences_seen']} divergence(s) seen over {c['explored']} comparisons, "
                 f"{c['divergences_listed']} listed" + ("  ** TRUNCATED: more exist than are listed **" if c["truncated"] else "")
                 + f"  ({c['stopped_reason']})")
        if c.get("hint"):
            L.append("  " + c["hint"])
        if c.get("mode") == "expression":
            cfx = c.get("closed_form") or {}
            L.append(f"  EXPRESSION CANDIDATE (broader, never default-included): covers EVERY input where {cfx.get('param')} is a non-empty str, "
                     f"including untried inputs: the call returns {cfx.get('form')} (reproduces ALL {cfx.get('pairs')} observed pairs). "
                     "Approve a claim like this only if you intend the behaviour for all such inputs.")
        elif c.get("mode") == "expression-unavailable":
            L.append("  no expression candidate: " + (c.get("expression_refusal") or "no catalogue form reproduces every observed pair (or the divergences are not one-str-parameter returns)"))
        elif c.get("mode") == "include-all":
            L.append("  --include-all: EVERY observed divergence becomes approved behaviour if you approve the candidates below")
        elif c.get("pattern"):
            L.append(f"  dominant pattern: {c['pattern']} (the default candidate covers only the divergences that fit it)")
        elif c.get("mode") == "no-common-pattern":
            L.append(f"  no common pattern: review each divergence; candidates NOT generated "
                     f"(--include-all would make EVERY observed divergence approved behaviour)")
        cf = c.get("closed_form")
        if cf and cf.get("attempted"):
            if cf.get("form"):
                L.append(f"  broader claim (a formula over the observed pairs, NOT a delta, never default-included): for str `{cf['param']}`, "
                         f"post == {cf['form']} reproduces ALL {cf['pairs']} observed pairs. It would cover ALL str inputs, not only the "
                         f"{cf['pairs']} tried: approve a claim like that only if you intend it. Hlith's default candidates are literal; "
                         "the expression form is not generated unless asked; run with --expression to emit it as a reviewable returns_expr delta "
                         "(with a preview), or write it by hand.")
            else:
                L.append(f"  no catalogue form (len(x.encode(..)), len(x), x.upper/lower/strip/casefold, str(x), int(x)) reproduces all "
                         f"{cf['pairs']} observed pairs: no broader claim is offered")
        if c["excluded"]:
            L.append(f"  excluded from candidates (cannot be a plain literal delta): {c['excluded']}")
    for c in res["callables"]:
        if c.get("outliers"):
            L.append(f"NOT INCLUDED in {c['symbol']} ({len(c['outliers'])}): does not fit the dominant pattern {c['pattern']}: "
                     "if you intend it, add it as a separate delta")
            for r in c["outliers"][:50]:
                pre, post = (r.get("pre") or {}), (r.get("post") or {})
                L.append(f"  not included: {c['symbol']}(*{json.dumps(r.get('args'), ensure_ascii=False)}, "
                         f"**{json.dumps(r.get('kwargs'), ensure_ascii=False)}): {pre.get('r') or pre.get('t')} -> {post.get('r') or post.get('t')}")
            if len(c["outliers"]) > 50:
                L.append(f"  ... {len(c['outliers']) - 50} more in proposed.provenance.json (not_included)")
    for c in res["callables"]:
        if c.get("scratch_rows"):
            L.append(f"NOT INCLUDED in {c['symbol']} ({len(c['scratch_rows'])}): {SCRATCH_REASON}")
            for r in c["scratch_rows"][:10]:
                L.append(f"  not included: {c['symbol']}(*{json.dumps(r.get('args'), ensure_ascii=False)}, "
                         f"**{json.dumps(r.get('kwargs'), ensure_ascii=False)})")
    bx = bool(res.get("broader"))
    for c in res["callables"]:
        pv = c.get("preview")
        if not pv:
            continue
        if not pv.get("ran"):
            L.append(f"PREVIEW for {c['symbol']}: could not run ({pv.get('error')})")
        elif pv["uncovered_count"]:
            L.append(f"PREVIEW for {c['symbol']}: with the candidate in place the differential still finds {pv['uncovered_count']} "
                     f"outside divergence(s); the {'expression' if c.get('mode') == 'expression' else 'literal'} candidate does not cover these inputs, so a run with it would still be refused"
                     + ("; consider OPTION B (below)" if bx else "; consider a broader (typed/expr) delta that you write and review"))
            for r in pv["uncovered"][:10]:
                pre, post = (r.get("pre") or {}), (r.get("post") or {})
                L.append(f"  uncovered: {c['symbol']}(*{json.dumps(r.get('args'), ensure_ascii=False)}, "
                         f"**{json.dumps(r.get('kwargs'), ensure_ascii=False)}): {pre.get('r') or pre.get('t')} -> {post.get('r') or post.get('t')}")
            if pv["uncovered_count"] > 10:
                L.append(f"  ... {pv['uncovered_count'] - 10} more in proposed.provenance.json (preview)")
        elif c.get("mode") == "expression":
            L.append(f"PREVIEW for {c['symbol']}: bounded exploration: 0 outside divergences found in {pv.get('explored')} comparisons (preview not truncated); "
                     f"not a proof (the claim itself covers every input of its kind, including all that were not tried)")
        else:
            L.append(f"PREVIEW for {c['symbol']}: with the candidate in place the differential found no further divergence in this "
                     f"exploration ({pv.get('explored')} comparisons); not a guarantee for inputs it did not try")
    for r in res["listed"]:
        pre, post = (r.get("pre") or {}), (r.get("post") or {})
        if r.get("oracle") == "declared-delta":
            L.append(f"  CLAIM CONTRADICTED (declared delta {r.get('delta')}) {r['symbol']}(*{json.dumps(r.get('args'), ensure_ascii=False)}, "
                     f"**{json.dumps(r.get('kwargs'), ensure_ascii=False)}): pre {pre.get('r') or pre.get('t')}, post {post.get('r') or post.get('t')}; "
                     "fix the patch or narrow the delta; not used for any candidate")
            continue
        L.append(f"  divergence {r['symbol']}(*{json.dumps(r.get('args'), ensure_ascii=False)}, **{json.dumps(r.get('kwargs'), ensure_ascii=False)}): "
                 f"{pre.get('r') or pre.get('t')} -> {post.get('r') or post.get('t')}"
                 + (f"   [fault-injection: {r['inject']}]" if r.get("inject") else ""))
    return "\n".join(inspect(x) for x in L)
