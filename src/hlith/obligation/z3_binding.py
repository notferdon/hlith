# SPDX-License-Identifier: Apache-2.0
"""Z3 call-boundary binding: does every call site bind to the post-change signature?

Scope of the claim (``signature_binding``): for each *direct* call site in the
effect account, Python's argument-binding rules (positional-only, positional or
keyword, ``*args``, keyword-only, ``**kwargs``, defaults) plus the simple entry
guards the account supplies are encoded in Z3 and checked for a binding error.

What a verdict means, exactly:
  * REFUTED   a concrete caller (file:line) provably fails to bind or trips a guard.
  * NOT_DERIVED  a call site uses ``*x`` / ``**x`` (or its structure is not parseable),
              or the account lists no call sites: the checker refuses to guess.
  * UNVERIFIED  all listed sites bind, but no ``CheckProvenance`` was recorded, so
              the proposer-independence condition is not met.
  * HELD      all listed sites bind AND the check ran confined with the proposer
              paths measured unreadable. Bounded: it says nothing about callers
              outside the account, dynamic dispatch or runtime behaviour.
"""

from __future__ import annotations

import ast
import hashlib
import json
import keyword
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import z3

if __package__ in (None, ""):  # launched as a script under -I: make `hlith` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # src/hlith/obligation/z3_binding.py -> src

from hlith.types import BoundedEvidence, CheckProvenance, Obligation, Verdict  # noqa: E402

POSONLY, POS_OR_KW, VARARG, KWONLY, KWARG = "posonly", "pos_or_kw", "vararg", "kwonly", "kwarg"

_EMPTY_LITERALS = {'""', "''", "[]", "{}", "()", "b''", 'b""'}
_FALSY_LITERALS = _EMPTY_LITERALS | {"None", "0", "0.0", "False"}
_GUARD_LITERALS = {"none": {"None"}, "empty": _EMPTY_LITERALS | {"None"}, "falsy": _FALSY_LITERALS}


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    kind: str
    has_default: bool = False
    default_repr: str | None = None  # literal source of the default when it is a plain literal


def _literal_repr(node: ast.expr) -> str | None:
    try:
        return repr(ast.literal_eval(node))
    except (ValueError, SyntaxError):
        return None


def parse_signature(text: str) -> tuple[Param, ...]:
    """Parse a parameter-list source string such as ``(self, a, /, b=1, *args, c, **kw)``."""
    src = text.strip()
    if not (src.startswith("(") and src.endswith(")")):
        raise SignatureError(f"signature must be a parenthesised parameter list: {text!r}")
    try:
        fn = ast.parse(f"def _f{src}: pass").body[0]
    except SyntaxError as e:
        raise SignatureError(f"unparseable signature {text!r}: {e.msg}") from e
    a = fn.args  # type: ignore[attr-defined]
    out: list[Param] = []
    pos = [*a.posonlyargs, *a.args]
    n_def = len(a.defaults)
    for i, p in enumerate(pos):
        kind = POSONLY if i < len(a.posonlyargs) else POS_OR_KW
        has_d = i >= len(pos) - n_def
        out.append(Param(p.arg, kind, has_d, _literal_repr(a.defaults[i - (len(pos) - n_def)]) if has_d else None))
    if a.vararg:
        out.append(Param(a.vararg.arg, VARARG, True))
    for p, d in zip(a.kwonlyargs, a.kw_defaults):
        out.append(Param(p.arg, KWONLY, d is not None, _literal_repr(d) if d is not None else None))
    if a.kwarg:
        out.append(Param(a.kwarg.arg, KWARG, True))
    return tuple(out)


@dataclass(frozen=True)
class CallSite:
    caller: str
    callee: str
    file_path: str
    line: int
    n_positional: int
    keywords: tuple[str, ...] = ()
    star_args: bool = False
    star_kwargs: bool = False
    arg_literals: tuple[tuple[str, str], ...] = ()
    is_method_call: bool = False

    @property
    def where(self) -> str:
        return f"{self.file_path}:{self.line}"


@dataclass(frozen=True)
class Guard:
    param: str
    raises_when: str  # none | empty | falsy | truthy | contains_literal | compare | isinstance
    literal: str | None = None  # contains_literal: raw str; compare: Python literal source of an int or str
    exception: str | None = None  # resolved raised type (module.qualname); evidence, not part of the trip test
    operator: str | None = None  # compare: < <= > >= == !=  (always `param OPERATOR literal`)
    types: tuple[str, ...] = ()  # isinstance: canonical names, e.g. ("builtins.int",)
    negated: bool = False  # isinstance: raises when NOT isinstance


def _guard(g: Mapping[str, Any]) -> Guard:
    t = g.get("type") or ()
    return Guard(g["param"], g["raises_when"], g.get("literal"), g.get("raised_exception"), g.get("operator"),
                 (t,) if isinstance(t, str) else tuple(t), bool(g.get("negated", False)))


def _guard_key(g: Mapping[str, Any]) -> tuple:
    """Semantic identity of an account guard; location and provenance are evidence, not identity."""
    t = g.get("type")
    return (g["param"], g["raises_when"], g.get("literal"), g.get("raised_exception"), g.get("operator"),
            None if t is None else ((t,) if isinstance(t, str) else tuple(t)), g.get("negated"))


_BUILTIN_TYPES: dict[str, type] = {
    "builtins.int": int, "builtins.str": str, "builtins.float": float, "builtins.bool": bool,
    "builtins.bytes": bytes, "builtins.NoneType": type(None), "builtins.list": list, "builtins.tuple": tuple,
    "builtins.dict": dict, "builtins.set": set}
_OPS = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b, "!=": lambda a, b: a != b}


def _literal(text: str) -> tuple[bool, Any]:
    try:
        return True, ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return False, None


def _guard_trips(g: Guard, text: str) -> Any | None:
    """Z3 Bool: does a call whose argument for g.param is the literal ``text`` trip guard g?
    None when the guard is not decided at this site (unparseable literal, unsupported type or operator)."""
    ok, v = _literal(text)
    if g.raises_when == "contains_literal":
        if not (ok and isinstance(v, str)) or g.literal is None:
            return None
        return z3.Contains(z3.StringVal(v), z3.StringVal(g.literal))
    if g.raises_when == "compare":
        lok, lv = _literal(g.literal or "")
        if not (ok and lok) or g.operator not in _OPS or isinstance(v, bool) or isinstance(lv, bool):
            return None
        if isinstance(v, int) and isinstance(lv, int):  # unbounded Python ints: Z3 Int is exact
            a, b = z3.IntVal(v), z3.IntVal(lv)
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "==": a == b, "!=": a != b}[g.operator]
        if isinstance(v, str) and isinstance(lv, str) and g.operator in ("==", "!="):
            return z3.BoolVal(_OPS[g.operator](v, lv))
        return None
    if g.raises_when == "isinstance":
        if not ok or not g.types or any(t not in _BUILTIN_TYPES for t in g.types):
            return None
        hit = isinstance(v, tuple(_BUILTIN_TYPES[t] for t in g.types))
        return z3.BoolVal(hit != g.negated)
    if g.raises_when in ("none", "empty", "falsy", "truthy"):
        if ok:
            empty = v is None or (isinstance(v, (str, bytes, list, tuple, dict, set)) and len(v) == 0)
            return z3.BoolVal({"none": v is None, "empty": empty, "falsy": not v, "truthy": bool(v)}[g.raises_when])
        if g.raises_when in ("none", "empty", "falsy"):  # non-literal source text: only the known spellings
            return z3.BoolVal(text in _GUARD_LITERALS[g.raises_when])
    return None


def _str_literal(text: str) -> str | None:
    """The str value of a call-site argument literal given as source text; None if not a str literal."""
    try:
        v = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return None
    return v if isinstance(v, str) else None


def call_site_from_account(d: Mapping[str, Any]) -> CallSite | str:
    """Accept the agreed structured dict; return a reason string if it is not parseable."""
    where = f"{d.get('file_path', '?')}:{d.get('line_number', '?')}"
    a: Any = d.get("arg_structure")
    if isinstance(a, str):  # legacy opaque text: usable only if the structured fields are also present
        try:
            a = json.loads(a)
        except ValueError:
            a = None
    if not isinstance(a, Mapping) or "n_positional" not in a:
        a = d  # direct argument fields on the call-site record
    if "n_positional" not in a:
        return f"{where}: no structured argument fields (n_positional) on the call site"
    lits = a.get("arg_literals") or {}
    return CallSite(
        caller=str(d.get("caller_qualified_name", "?")),
        callee=str(d.get("callee_qualified_name", "?")),
        file_path=str(d["file_path"]),
        line=int(d["line_number"]),
        n_positional=int(a["n_positional"]),
        keywords=tuple(a.get("keywords", ())),
        star_args=bool(a.get("star_args", False)),
        star_kwargs=bool(a.get("star_kwargs", False)),
        arg_literals=tuple(sorted((str(k), str(v)) for k, v in lits.items())),
        is_method_call=bool(a.get("is_method_call", d.get("is_method_call", False))),
    )


def binding_errors(sig: tuple[Param, ...], site: CallSite, guards: Iterable[Guard] = ()) -> list[str]:
    """Z3 check of one resolved call site. Returns the triggered error classes (empty = binds)."""
    posc = [p for p in sig if p.kind in (POSONLY, POS_OR_KW)]
    has_va = any(p.kind == VARARG for p in sig)
    has_kw = any(p.kind == KWARG for p in sig)
    kwable = {p.name for p in sig if p.kind in (POS_OR_KW, KWONLY)}
    posonly = {p.name for p in sig if p.kind == POSONLY}
    n_eff = site.n_positional + (1 if site.is_method_call else 0)

    s = z3.Solver()
    N = z3.Int("N")
    s.add(N == n_eff)
    errs: dict[str, z3.BoolRef] = {}
    bp: dict[str, z3.BoolRef] = {}
    bk: dict[str, z3.BoolRef] = {}
    for i, p in enumerate(posc):
        bp[p.name] = z3.Bool(f"bp_{p.name}")
        s.add(bp[p.name] == (z3.IntVal(i) < N))
    for p in sig:
        if p.kind in (POS_OR_KW, KWONLY):
            bk[p.name] = z3.Bool(f"bk_{p.name}")
            s.add(bk[p.name] == z3.BoolVal(p.name in site.keywords))
    if not has_va:
        errs["too_many_positional"] = N > len(posc)
    for p in sig:
        if p.kind == POS_OR_KW:
            errs[f"multiple_values:{p.name}"] = z3.And(bp[p.name], bk[p.name])
            if not p.has_default:
                errs[f"missing:{p.name}"] = z3.And(z3.Not(bp[p.name]), z3.Not(bk[p.name]))
        elif p.kind == POSONLY and not p.has_default:
            errs[f"missing:{p.name}"] = z3.Not(bp[p.name])
        elif p.kind == KWONLY and not p.has_default:
            errs[f"missing:{p.name}"] = z3.Not(bk[p.name])
    if not has_kw:
        for k in site.keywords:
            if k not in kwable:
                errs[f"unexpected_keyword:{k}"] = z3.BoolVal(True)
    # literal facts -> guards; position i of the written call maps to posc[i + implicit]
    lit = dict(site.arg_literals)
    by_param: dict[str, str] = {}
    shift = 1 if site.is_method_call else 0
    for idx_s, val in lit.items():
        if idx_s.isdigit():
            j = int(idx_s) + shift
            if j < len(posc):
                by_param[posc[j].name] = val
        else:
            by_param[idx_s] = val
    for g in guards:
        if g.param in by_param:
            trips = _guard_trips(g, by_param[g.param])
            if trips is not None:  # None: not decided at this site
                errs[f"guard:{g.param}:{g.raises_when}"] = trips
    out: list[str] = []
    for name, f in errs.items():
        s.push()
        s.add(f)
        if s.check() == z3.sat:
            out.append(name)
        s.pop()
    return out


@dataclass(frozen=True)
class Subsumption:
    """Does every call shape accepted by ``pre`` stay accepted by ``post``?

    A call shape is (number of positional args, set of keyword names). ``__other__`` stands
    for any keyword name outside both signatures. Entry guards are value-level and are NOT
    covered; ``guards_comparable`` says whether the guard sets were identical.
    """

    holds: bool
    breaking_shape: str | None = None
    n_positional: int | None = None
    keywords: tuple[str, ...] = ()


_OTHER = "__other__"


def _accepts(sig: tuple[Param, ...], N: z3.ArithRef, K: dict[str, z3.BoolRef]) -> z3.BoolRef:
    posc = [p for p in sig if p.kind in (POSONLY, POS_OR_KW)]
    has_va = any(p.kind == VARARG for p in sig)
    has_kw = any(p.kind == KWARG for p in sig)
    kwable = {p.name for p in sig if p.kind in (POS_OR_KW, KWONLY)}
    ok: list[z3.BoolRef] = []
    if not has_va:
        ok.append(N <= len(posc))
    for i, p in enumerate(posc):
        bp = z3.IntVal(i) < N
        if p.kind == POS_OR_KW:
            ok.append(z3.Not(z3.And(bp, K[p.name])))
        if not p.has_default:
            ok.append(z3.Or(bp, K[p.name]) if p.kind == POS_OR_KW else bp)
    for p in sig:
        if p.kind == KWONLY and not p.has_default:
            ok.append(K[p.name])
    if not has_kw:
        for name, k in K.items():
            if name not in kwable:
                ok.append(z3.Not(k))
    return z3.And(*ok) if ok else z3.BoolVal(True)


def signature_subsumption(pre: tuple[Param, ...], post: tuple[Param, ...]) -> Subsumption:
    names = sorted({p.name for p in (*pre, *post)} | {_OTHER})
    N = z3.Int("N")
    K = {n: z3.Bool(f"k_{n}") for n in names}
    s = z3.Solver()
    s.add(N >= 0, _accepts(pre, N, K), z3.Not(_accepts(post, N, K)))
    if s.check() == z3.unsat:
        return Subsumption(True)
    m = s.model()
    n = m.eval(N, model_completion=True).as_long()
    kws = sorted(x for x, k in K.items() if z3.is_true(m.eval(k, model_completion=True)))
    return Subsumption(
        False, f"{n} positional arg(s) with keyword(s) {kws or 'none'} bind pre-change, fail post-change", n, tuple(kws)
    )


def _analyze_added(request: Mapping[str, Any], res: dict[str, Any]) -> dict[str, Any]:
    """Callable absent from the baseline: bind every post-change call site to the post signature.

    There is no pre-change code, so a failing site is a defect this change introduced (REFUTED) and
    "already failed" does not apply. Zero reaching call sites is not a pass: nothing is checked.
    """
    res["added"] = True
    try:
        post = parse_signature(request["post_signature"])
    except SignatureError as e:
        res["unresolved"].append(f"post_signature: {e}")
        return res
    guards = [_guard(g) for g in request.get("entry_guards", ())]
    sites_raw = list(request.get("call_sites", ()))
    for raw in sites_raw:
        cs = call_site_from_account(raw)
        if isinstance(cs, str):
            res["unresolved"].append(cs)
            continue
        if cs.star_args or cs.star_kwargs:
            visible = binding_errors(post, cs, guards) if not cs.star_args and cs.star_kwargs else []
            definite = [e for e in visible if e.startswith(("too_many", "unexpected_keyword", "guard:"))]
            if definite:
                res["refuted"].append(_refute_added(cs, definite))
            else:
                kind = "*args" if cs.star_args else "**kwargs"
                res["unresolved"].append(
                    f"{cs.where} {cs.caller}: call forwards {kind}; binding not decidable (no pre-change signature to compare)")
            continue
        errs = binding_errors(post, cs, guards)
        if errs:
            res["refuted"].append(_refute_added(cs, errs))
        else:
            res["clean"].append({"where": cs.where, "caller": cs.caller})
    unk = int(request.get("unknown_edge_count", len(request.get("unknown_edges", ()))) or 0)
    res["unknown_edges"] = unk
    if unk:
        res["unresolved"].append(f"{unk} unknown call edge(s) to the added callable unresolved in the account")
    if request.get("exported_guard_entry"):
        # Provenance-bound exported pytest guard: verify the 0-arg pytest runner entry binds under Z3.
        entry_cs = CallSite(
            caller="pytest:exported-guard",
            callee=str(request.get("target_symbol", "")),
            file_path=str(request.get("exported_guard_file") or "<exported-guard>"),
            line=1,
            n_positional=0,
            keywords=(),
        )
        entry_errs = binding_errors(post, entry_cs, guards)
        if entry_errs:
            res["refuted"].append(_refute_added(entry_cs, entry_errs))
        else:
            res["clean"].append({"where": entry_cs.where, "caller": entry_cs.caller, "exported_guard_entry": True})
    elif not sites_raw:
        res["unresolved"].insert(0, "unexplored: no caller reaches the added callable")
    res["unexplored_scope"] = str(request.get("unexplored_scope", ""))
    res["witness_inputs"] = [r["witness_inputs"] for r in res["refuted"]]
    return res


def _refute_added(cs: CallSite, errs: list[str]) -> dict[str, Any]:
    r = _refute(cs, errs, None, None, ())
    r["pre_change"] = "n/a (callable added by this change)"
    return r


def analyze(request: Mapping[str, Any]) -> dict[str, Any]:
    """Pure analysis. ``request``: obligation_id, target_symbol, post_signature,
    pre_signature (optional), call_sites (account dicts), entry_guards."""
    if request.get("kind") == "return_shape":
        return analyze_return_shape(request)
    res: dict[str, Any] = {"unresolved": [], "refuted": [], "clean": [], "notes": []}
    if request.get("post_signature") == "UNKNOWN":
        res["unresolved"].append("callable absent from the candidate tree (deleted, moved or renamed): "
                                 "baseline callers cannot be bound to a signature")
        return res
    if request.get("added"):
        return _analyze_added(request, res)
    if request.get("pre_signature") == "UNKNOWN":
        request = {**request, "pre_signature": None, "unknown_edge_count": 0, "call_sites": [], "_new": True}
    try:
        post = parse_signature(request["post_signature"])
    except SignatureError as e:
        res["unresolved"].append(f"post_signature: {e}")
        return res
    pre = None
    if request.get("pre_signature"):
        try:
            pre = parse_signature(request["pre_signature"])
        except SignatureError:
            res["notes"].append("pre_signature unparseable; pre-change binding not compared")
    guards = [_guard(g) for g in request.get("entry_guards", ())]
    subs = signature_subsumption(pre, post) if pre is not None else None
    res["subsumption"] = None if subs is None else {
        "holds": subs.holds, "breaking_shape": subs.breaking_shape,
        "witness_inputs": None if subs.holds else _shape_witness(pre, subs),
    }
    sites_raw = list(request.get("call_sites", ()))
    res["pre_failing"] = []
    pre_guards = ([_guard(g) for g in request["pre_entry_guards"]]
                  if "pre_entry_guards" in request else guards)
    for st in request.get("stale_sites", ()):
        res["unresolved"].append(
            f"{st.get('file_path')}:{st.get('line_number')} in a file the effect changes: baseline call text may "
            "differ in the candidate tree (candidate-tree call sites needed)")
    if request.get("_new"):
        res["notes"].append("new callable: no baseline callers exist; shadowing/dynamic use not explored")
        res["new_callable"] = True
    if not sites_raw and not request.get("_new") and not request.get("stale_sites") and not int(
            request.get("unknown_edge_count", len(request.get("unknown_edges", ()))) or 0):
        if subs is not None and subs.holds and not _guards_changed(request):
            # No listed caller and post accepts every call shape pre accepted: nothing a pre-change
            # caller did can break. Callers outside the account stay unexplored.
            res["zero_sites_covered_by_subsumption"] = True
        else:
            why = (f"; a {subs.breaking_shape}" if subs is not None and not subs.holds
                   else "; no pre-change signature to compare" if subs is None else "; entry guards changed")
            res["unresolved"].append(
                f"account lists zero call sites; absence of callers is not established{why}")
    for raw in sites_raw:
        cs = call_site_from_account(raw)
        if isinstance(cs, str):
            res["unresolved"].append(cs)
            continue
        if cs.star_args or cs.star_kwargs:
            kind = "*args" if cs.star_args else "**kwargs"
            if subs is not None and subs.holds and not _guards_changed(request):
                res["clean"].append({"where": cs.where, "caller": cs.caller, "by_subsumption": True})
                continue
            # A definite error on the visible part is still sound; otherwise stop.
            visible = binding_errors(post, cs, guards) if not cs.star_args and cs.star_kwargs else []
            definite = [e for e in visible if e.startswith(("too_many", "unexpected_keyword", "guard:"))]
            if definite:
                res["refuted"].append(_refute(cs, definite, post, pre, guards))
            else:
                why = (f"; a {subs.breaking_shape}" if subs is not None and not subs.holds
                       else "; no pre-change signature to compare" if subs is None else "; entry guards changed")
                res["unresolved"].append(f"{cs.where} {cs.caller}: call forwards {kind}; binding not decidable{why}")
            continue
        errs = binding_errors(post, cs, guards)
        if errs:
            if pre is None:
                # A regression needs a pre-change acceptance; without the pre-change signature it is unproven.
                res["unresolved"].append(
                    f"{cs.where} {cs.caller}: fails post-change binding ({', '.join(errs)}) but no pre-change "
                    "signature exists to show it bound before")
            elif binding_errors(pre, cs, pre_guards):
                # Pre-change code already rejected this call: not a regression caused by the change.
                res["pre_failing"].append({"where": cs.where, "caller": cs.caller, "callee": cs.callee,
                                           "pre_errors": binding_errors(pre, cs, pre_guards), "post_errors": errs})
            else:
                res["refuted"].append(_refute(cs, errs, post, pre, guards))
        else:
            res["clean"].append({"where": cs.where, "caller": cs.caller})
    unk = int(request.get("unknown_edge_count", len(request.get("unknown_edges", ()))) or 0)
    res["unknown_edges"] = unk
    res["unknown_covered_by_subsumption"] = 0
    if unk:
        if subs is not None and subs.holds and not _guards_changed(request):
            res["unknown_covered_by_subsumption"] = unk  # any caller shape that bound pre-change still binds
        else:
            why = (f"; a {subs.breaking_shape}" if subs is not None and not subs.holds
                   else "; no pre-change signature to compare" if subs is None else "; entry guards changed")
            res["unresolved"].append(f"{unk} unknown call edge(s) unresolved in the account{why}")
    res["unexplored_scope"] = str(request.get("unexplored_scope", ""))
    res["witness_inputs"] = [r["witness_inputs"] for r in res["refuted"]]
    if res.get("subsumption") and res["subsumption"]["witness_inputs"] and res["unresolved"]:
        res["witness_inputs"].append(res["subsumption"]["witness_inputs"])
    return res


def _shape_witness(pre: tuple[Param, ...], subs: Subsumption) -> dict[str, Any]:
    """Break shape plus concrete literals. Values come from the pre-change signature's own
    literal defaults; where none exists the literal is a placeholder listed in ``synthetic``.
    A binding failure does not depend on argument values, so these values are admissible."""
    posc = [p for p in pre if p.kind in (POSONLY, POS_OR_KW)]
    by_name = {p.name: p for p in pre}
    lits: dict[str, str] = {}
    synthetic: list[str] = []
    for i in range(subs.n_positional or 0):
        d = posc[i].default_repr if i < len(posc) else None
        lits[str(i)] = d if d is not None else "None"
        if d is None:
            synthetic.append(str(i))
    kws = []
    for k in subs.keywords:
        if k == _OTHER:
            kws.append("<any other keyword>")
            continue
        kws.append(k)
        d = by_name[k].default_repr if k in by_name else None
        lits[k] = d if d is not None else "None"
        if d is None:
            synthetic.append(k)
    return {
        "kind": "signature_subsumption_break", "n_positional": subs.n_positional, "keywords": kws,
        # positions index the signature as written; True only when its first positional is self/cls
        "includes_implicit_self": bool(posc and posc[0].name in ("self", "cls")),
        "path_literals": lits, "synthetic": synthetic,
        "note": "accepted by pre-change signature, rejected by post-change signature; "
        "literals are pre-change defaults or None placeholders, values do not affect binding",
    }


def _guards_changed(request: Mapping[str, Any]) -> bool:
    """True if the post-change callable has an entry guard the pre-change one lacks (or pre is unknown)."""
    post = {_guard_key(g) for g in request.get("entry_guards", ())}
    pre = {_guard_key(g) for g in request.get("pre_entry_guards", ())}
    return bool(post - pre)


def _refute(cs: CallSite, errs: list[str], post, pre, guards) -> dict[str, Any]:
    pre_state = "binds"  # callers only reach here when the pre-change signature accepted the call
    return {
        "where": cs.where, "caller": cs.caller, "callee": cs.callee, "errors": errs, "pre_change": pre_state,
        # structured, machine-readable: lets a downstream falsifier seed concrete calls
        "witness_inputs": {
            "kind": "call_site_binding_error",
            "site": cs.where,
            "callee": cs.callee,
            "n_positional": cs.n_positional,
            "keywords": list(cs.keywords),
            "star_args": cs.star_args,
            "star_kwargs": cs.star_kwargs,
            "is_method_call": cs.is_method_call,
            "path_literals": {k: v for k, v in cs.arg_literals},
            "violated": list(errs),
        },
    }


def _opaque_caller_guard_note(request: Mapping[str, Any]) -> str:
    """Explain the bounded treatment of caller predicates the account could not model."""
    count = int(request.get("opaque_caller_guard_count", 0) or 0)
    if count <= 0:
        return ""
    return (
        f"not covered: predicates of {count} caller guard(s) are not modelled; all listed call sites "
        "were checked regardless of both guard polarities"
    )


def derive_obligation(
    request: Mapping[str, Any], analysis: Mapping[str, Any], provenance: CheckProvenance | None
) -> Obligation:
    if request.get("kind") == "return_shape":
        return _derive_return_shape(request, analysis, provenance)
    oid, target = request["obligation_id"], request["target_symbol"]
    claim = f"signature_binding: every listed direct call site of {target} binds to the post-change signature"
    opaque_guard_note = _opaque_caller_guard_note(request)
    if analysis["refuted"]:
        r = analysis["refuted"][0]
        extra = f" (+{len(analysis['refuted']) - 1} more)" if len(analysis["refuted"]) > 1 else ""
        w = (f"{r['where']} in {r['caller']} calling {r['callee']}: {', '.join(r['errors'])}; "
             f"pre-change binding: {r['pre_change']}{extra}")
        if (
            opaque_guard_note
            and r["caller"] in set(request.get("opaque_caller_guard_callers", ()))
        ):
            w += (
                f"; conservative refusal possible: a caller guard is not modelled, "
                f"so this call site was checked regardless of guard polarity and may be unreachable "
                f"({opaque_guard_note})"
            )
        return Obligation(oid, target, claim, Verdict.REFUTED, witness=w)
    if analysis["unresolved"]:
        return Obligation(oid, target, claim, Verdict.NOT_DERIVED, stop_reason="; ".join(analysis["unresolved"]))
    n = len(analysis["clean"])
    if provenance is None:
        return Obligation(
            oid, target, claim, Verdict.UNVERIFIED,
            stop_reason=f"{n} call sites bind under Z3 but no CheckProvenance was recorded; "
            "independence from the proposer is unestablished",
        )
    if analysis.get("added"):
        files = sorted({c["where"].rsplit(":", 1)[0] for c in analysis["clean"]})
        has_guard_entry = any(c.get("exported_guard_entry") for c in analysis["clean"])
        real_sites = sum(1 for c in analysis["clean"] if not c.get("exported_guard_entry"))
        if has_guard_entry:
            explored_added = (
                f"Z3 binding + simple entry guards for canonical 0-arg pytest invocation of provenance-bound "
                f"exported pre-guard plus {real_sites} post-change call site(s) in {len(files)} file(s): "
                f"{', '.join(files)}; no pre-change signature exists"
            )
        else:
            explored_added = (
                f"Z3 binding + simple entry guards for {n} post-change call site(s) of the added callable in "
                f"{len(files)} file(s): {', '.join(files)}; no pre-change signature exists"
            )
        ev_add = BoundedEvidence(
            executions=max(n, 1),
            explored=explored_added,
            unexplored="name shadowing, dynamic use of the new name, callers outside the account; "
            "runtime behaviour of the callee"
            + (f"; {opaque_guard_note}" if opaque_guard_note else "")
            + (f"; account scope: {analysis['unexplored_scope']}" if analysis.get("unexplored_scope") else ""),
        )
        return Obligation(oid, target, claim, Verdict.HELD, evidence=ev_add, provenance=provenance)
    if analysis.get("new_callable"):
        ev_new = BoundedEvidence(
            executions=1,
            explored=f"{target} is absent from the baseline tree: no baseline call site exists that could fail to bind",
            unexplored="name shadowing, dynamic use of the new name, callers added by later effects"
            + (f"; {opaque_guard_note}" if opaque_guard_note else "")
            + (f"; account scope: {analysis['unexplored_scope']}" if analysis.get("unexplored_scope") else ""),
        )
        return Obligation(oid, target, claim, Verdict.HELD, evidence=ev_new, provenance=provenance)
    if analysis.get("zero_sites_covered_by_subsumption") and not analysis["clean"]:
        ev_zero = BoundedEvidence(
            executions=1,
            explored="0 direct call sites in the account; backward compatibility by signature subsumption only "
            "(Z3: every call shape accepted pre-change is accepted post-change; entry guards unchanged)",
            unexplored="callers outside the account (dynamic dispatch, callbacks, other repositories, tests not "
            "listed) are unexplored; runtime behaviour of the callee"
            + (f"; {opaque_guard_note}" if opaque_guard_note else "")
            + (f"; account scope: {analysis['unexplored_scope']}" if analysis.get("unexplored_scope") else ""),
        )
        return Obligation(oid, target, claim, Verdict.HELD, evidence=ev_zero, provenance=provenance)
    files = sorted({c["where"].rsplit(":", 1)[0] for c in analysis["clean"]})
    n_sub = sum(1 for c in analysis["clean"] if c.get("by_subsumption"))
    n_unk = analysis.get("unknown_covered_by_subsumption", 0)
    ev = BoundedEvidence(
        executions=max(n, 1),
        explored=(f"Z3 binding + simple entry guards for {n - n_sub} direct call sites in {len(files)} file(s): {', '.join(files)}"
                  if n else f"all {len(analysis.get('pre_failing', ()))} listed call site(s) already failed to bind before the "
                  "change and are excluded; no listed site bound pre-change, so none was re-checked post-change")
        + (f"; {n_unk} unknown call edge(s) covered only by the subsumption proof (same assumption)" if n_unk else "")
        + (f"; plus {n_sub} star-forwarding site(s) covered by proven subsumption (every call shape accepted "
           "pre-change is accepted post-change; assumes those sites bound pre-change, not checked)" if n_sub else ""),
        unexplored="callers outside the account (dynamic dispatch, callbacks, other repositories, "
        "tests not listed), runtime behaviour of the callee, entry guards the account could not express"
        + (f"; {opaque_guard_note}" if opaque_guard_note else "")
        + (f"; {len(analysis['pre_failing'])} listed call site(s) already failed to bind BEFORE the change "
           f"({', '.join(p['where'] for p in analysis['pre_failing'][:5])}): excluded, not attributable to this change"
           if analysis.get("pre_failing") else "")
        + (f"; account scope: {analysis['unexplored_scope']}" if analysis.get("unexplored_scope") else ""),
    )
    return Obligation(oid, target, claim, Verdict.HELD, evidence=ev, provenance=provenance)


# --------------------------------------------------------------- return shape (caller-consumption) check
# A changed return shape (arity of a returned tuple/list, None, a scalar) must still fit what each listed
# caller does with the result. Sound bounded modelling: only decided facts are used. A shape the account
# cannot pin, a consumer that is not a plain unpack/index/discard, a wrapped (generator/async) callable,
# or a caller set the account does not list is NOT_DERIVED, never HELD.
def _call_key(node: ast.AST) -> str:
    return ast.dump(node)


def consumer_demand(source: str, line: int, node_source: str) -> dict[str, Any]:
    """What the statement at ``line`` demands of the value of the call written as ``node_source``.

    unpack n[,star] | index k | discard | opaque (everything else, including ambiguity)."""
    def opaque(why: str) -> dict[str, Any]:
        return {"kind": "opaque", "why": why}

    try:
        tree = ast.parse(source)
        want = _call_key(ast.parse((node_source or "").strip(), mode="eval").body)
    except (SyntaxError, ValueError):
        return opaque("source or call expression not parseable")
    parents: dict[int, ast.AST] = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parents[id(c)] = n
    found = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line and _call_key(n) == want]
    if len(found) != 1:
        return opaque(f"{len(found)} matching calls on line {line}")
    call = found[0]
    par = parents.get(id(call))
    if isinstance(par, ast.Expr):
        return {"kind": "discard"}
    if isinstance(par, ast.Assign) and par.value is call and len(par.targets) == 1 \
            and isinstance(par.targets[0], (ast.Tuple, ast.List)):
        elts = par.targets[0].elts
        stars = sum(isinstance(e, ast.Starred) for e in elts)
        if stars == 0:
            return {"kind": "unpack", "n": len(elts), "star": False}
        if stars == 1:
            return {"kind": "unpack", "n": len(elts) - 1, "star": True}
        return opaque("multiple starred targets")
    if isinstance(par, ast.Subscript) and par.value is call and isinstance(par.ctx, ast.Load):
        sl = par.slice
        if isinstance(sl, ast.Constant) and type(sl.value) is int:
            return {"kind": "index", "k": sl.value}
        if (isinstance(sl, ast.UnaryOp) and isinstance(sl.op, ast.USub) and isinstance(sl.operand, ast.Constant)
                and type(sl.operand.value) is int):
            return {"kind": "index", "k": -sl.operand.value}
        return opaque("non-literal index")
    return opaque(f"result consumed by {type(par).__name__ if par is not None else 'nothing'}, not a plain unpack/index/discard")


def _local_tuple_arity_from_provenance(s: Mapping[str, Any], source_name: str) -> tuple | None:
    """Accept a bare local name only when the effect account proves its tuple binding is complete."""
    if not source_name.isidentifier() or keyword.iskeyword(source_name):
        return None
    if s.get("resolution") != "resolved" or s.get("container_kind") != "tuple":
        return None
    length = s.get("length")
    if type(length) is not int or length < 0:
        return None

    source_file = s.get("file_path")
    source_line = s.get("line_number")
    provenance = s.get("provenance")
    if (
        not isinstance(source_file, str)
        or not source_file
        or type(source_line) is not int
        or source_line < 1
        or not isinstance(provenance, Mapping)
        or provenance.get("analysis_pass") != "return_shape_inference"
        or provenance.get("resolution") != "resolved"
        or provenance.get("source_file") != source_file
        or provenance.get("source_line") != source_line
        or provenance.get("node_sha256") != hashlib.sha256(source_name.encode("utf-8")).hexdigest()
    ):
        return None

    binding = provenance.get("local_binding_provenance")
    if not isinstance(binding, Mapping):
        return None
    required_true = (
        "assignment_scan_complete",
        "all_assignments_resolved",
        "all_assignments_same_tuple_shape",
        "all_normal_return_paths_use_scanned_local_assignment",
        "no_other_rebindings",
        "no_starred_tuple_assignments",
        "no_tuple_mutations",
        "no_opaque_assignment_or_dynamic_local_access",
    )
    if (
        binding.get("resolution") != "resolved"
        or binding.get("assignment_scope") != "pre_return_expression"
        or binding.get("container_kind") != "tuple"
        or type(binding.get("length")) is not int
        or binding.get("length") != length
        or any(binding.get(flag) is not True for flag in required_true)
    ):
        return None

    assignments = binding.get("assignments")
    if not isinstance(assignments, (list, tuple)) or not assignments:
        return None
    for assignment in assignments:
        if not isinstance(assignment, Mapping):
            return None
        assignment_source = assignment.get("assignment_source")
        assignment_hash = assignment.get("node_sha256")
        if (
            assignment.get("analysis_pass") != "return_shape_local_tuple_binding"
            or assignment.get("resolution") != "resolved"
            or assignment.get("source_file") != source_file
            or type(assignment.get("source_line")) is not int
            or assignment.get("source_line") < 1
            or not isinstance(assignment_source, str)
            or not assignment_source
            or not isinstance(assignment_hash, str)
            or assignment_hash != hashlib.sha256(assignment_source.encode("utf-8")).hexdigest()
            or assignment.get("container_kind") != "tuple"
            or type(assignment.get("length")) is not int
            or assignment.get("length") != length
        ):
            return None
    return ("n", length)


def _arity(s: Mapping[str, Any]) -> tuple | None:
    """("n", length) | ("none",) | ("scalar",) | None when the account does not pin the shape."""
    kind = s.get("kind")
    if kind == "none":
        return ("none",)
    src = s.get("source") or ""
    if kind == "container" and s.get("container_kind") in ("tuple", "list") and isinstance(s.get("length"), int):
        try:
            e = ast.parse(src.strip(), mode="eval").body
        except SyntaxError:
            return None
        if isinstance(e, (ast.Tuple, ast.List)) and not any(isinstance(x, ast.Starred) for x in e.elts) \
                and len(e.elts) == s["length"]:
            return ("n", s["length"])
        # Literal tuple/list validation above is unchanged. A bare local name is
        # accepted only from the effect engine's complete structured binding proof.
        if isinstance(e, ast.Name) and isinstance(e.ctx, ast.Load) and s.get("container_kind") == "tuple":
            return _local_tuple_arity_from_provenance(s, e.id)
        return None
    if kind == "literal":
        try:
            v = ast.literal_eval(src.strip())
        except (ValueError, SyntaxError):
            return None
        if v is None:
            return ("none",)
        if isinstance(v, (bool, int, float, complex)):
            return ("scalar",)
        if isinstance(v, (str, bytes)):
            return ("n", len(v))
        return None
    return None


def _violates(a: tuple, d: Mapping[str, Any]) -> bool:
    """Z3: does a returned value of arity ``a`` break the demand ``d``? (not iterable / not subscriptable = breaks)"""
    if a[0] != "n":
        return True
    A = z3.Int("A")
    s = z3.Solver()
    s.add(A == a[1])
    if d["kind"] == "unpack":
        s.add(A < d["n"] if d.get("star") else A != d["n"])
    else:
        k = d["k"]
        s.add(A <= k if k >= 0 else A < -k)
    return s.check() == z3.sat


def _desc(a: tuple) -> str:
    return f"a {a[1]}-element value" if a[0] == "n" else ("None" if a[0] == "none" else "a non-iterable scalar")


def analyze_return_shape(request: Mapping[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {"unresolved": [], "refuted": [], "clean": [], "pre_failing": [], "notes": []}
    if request.get("returns_wrapped"):
        res["unresolved"].append("callable is a generator/async function or was not located: its return shapes are "
                                 "not the value the caller receives")
        return res
    pre, post = list(request.get("pre_shapes", ())), list(request.get("post_shapes", ()))
    if not post:
        res["unresolved"].append("the account lists no post-change return shape")
        return res
    if request.get("unknown_edge_count"):
        res["unresolved"].append(f"{request['unknown_edge_count']} unknown call edge(s) into the callable: "
                                 "their use of the result is not known")
    sites = list(request.get("sites", ()))
    if not sites:
        res["unresolved"].append("account lists zero call sites; absence of callers is not established "
                                 "(instance-method callers are not resolved by the account)")
    post_ar = [_arity(x) for x in post]
    unk = [x for x, a in zip(post, post_ar) if a is None]
    if unk:
        res["unresolved"].append(f"post-change return at {unk[0].get('file_path')}:{unk[0].get('line_number')} "
                                 f"({unk[0].get('kind')}: {str(unk[0].get('source'))[:60]}) has no decided arity")
        return res
    pre_ar = [_arity(x) for x in pre]
    pre_known = bool(pre) and all(a is not None for a in pre_ar)
    for st in sites:
        d = st["demand"]
        if d["kind"] == "opaque":
            res["unresolved"].append(f"{st['where']}: consumer not decided ({d.get('why')})")
            continue
        if d["kind"] == "discard":
            res["clean"].append({"where": st["where"], "caller": st["caller"], "demand": d})
            continue
        if not pre_known:
            res["unresolved"].append(f"{st['where']}: pre-change shape not decided, so pre-change acceptance is unknown")
            continue
        pv = [_violates(a, d) for a in pre_ar]
        if all(pv):
            res["pre_failing"].append({"where": st["where"], "caller": st["caller"]})
            continue
        if any(pv):
            res["unresolved"].append(f"{st['where']}: some pre-change return paths already violate the demand")
            continue
        qv = [_violates(a, d) for a in post_ar]
        if all(qv):
            bad = post_ar[0]
            res["refuted"].append({"where": st["where"], "caller": st["caller"], "demand": d, "post": _desc(bad),
                                   "pre": [_desc(a) for a in pre_ar]})
        elif any(qv):
            res["unresolved"].append(f"{st['where']}: some post-change return paths violate the demand; "
                                     "reachability of those paths is not decided")
        else:
            res["clean"].append({"where": st["where"], "caller": st["caller"], "demand": d})
    return res


def _demand_text(d: Mapping[str, Any]) -> str:
    if d["kind"] == "unpack":
        return f"unpacks {d['n']}{'+' if d.get('star') else ''} value(s)"
    return f"indexes [{d['k']}]"


def _derive_return_shape(request: Mapping[str, Any], analysis: Mapping[str, Any],
                         provenance: CheckProvenance | None) -> Obligation:
    oid, target = request["obligation_id"], request["target_symbol"]
    claim = (f"return_shape: every listed caller's use of the result of {target} fits the post-change "
             "return shape on every return path")
    if analysis["refuted"]:
        r = analysis["refuted"][0]
        extra = f" (+{len(analysis['refuted']) - 1} more)" if len(analysis["refuted"]) > 1 else ""
        w = (f"{r['where']} in {r['caller']} {_demand_text(r['demand'])} of the result; every post-change return path "
             f"yields {r['post']}; pre-change return shape(s) satisfied it: {', '.join(r['pre'])}{extra}")
        return Obligation(oid, target, claim, Verdict.REFUTED, witness=w)
    if analysis["unresolved"]:
        return Obligation(oid, target, claim, Verdict.NOT_DERIVED, stop_reason="; ".join(analysis["unresolved"])[:600])
    n = len(analysis["clean"])
    if provenance is None:
        return Obligation(oid, target, claim, Verdict.UNVERIFIED,
                          stop_reason=f"{n} caller(s) fit the return shape under Z3 but no CheckProvenance was recorded; "
                          "independence from the proposer is unestablished")
    files = sorted({c["where"].rsplit(":", 1)[0] for c in analysis["clean"]})
    ev = BoundedEvidence(
        executions=max(n, 1),
        explored=f"Z3 arity check of {n} listed caller site(s) in {len(files)} file(s) ({', '.join(files)}) against "
        f"{len(request.get('post_shapes', ()))} post-change return path(s); consumers read: unpack, literal index, discard",
        unexplored="callers outside the account (including instance-method callers the account does not resolve), "
        "element types and values, reachability of return paths, consumers other than unpack/index/discard"
        + (f"; {len(analysis['pre_failing'])} caller(s) already violated the demand BEFORE the change and are excluded"
           if analysis.get("pre_failing") else "")
        + (f"; account scope: {request['unexplored_scope']}" if request.get("unexplored_scope") else ""),
    )
    return Obligation(oid, target, claim, Verdict.HELD, evidence=ev, provenance=provenance)


def _wrapped(tree: ast.AST, qualified: str, line: int) -> bool:
    """True (fail closed) when the callable is async, a generator, or cannot be located unambiguously."""
    name = qualified.rsplit(".", 1)[-1]
    defs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == name and n.lineno <= line <= (n.end_lineno or n.lineno)]
    if len(defs) != 1:
        return True
    fn = defs[0]
    if isinstance(fn, ast.AsyncFunctionDef):
        return True
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))
    return False


def _arity_key(shapes: Iterable[Mapping[str, Any]]) -> tuple:
    """What is DECIDED about the returned shapes: the set of decided arities and how many shapes are undecided.
    Two undecided shapes with different source text (`return g(x)` vs `y = g(x); return y`) are not a decided change."""
    ar = [_arity(s) for s in shapes]
    return (tuple(sorted({repr(a) for a in ar if a is not None})), sum(1 for a in ar if a is None))


def _decided_arities(shapes: Iterable[Mapping[str, Any]]) -> list[tuple]:
    return [a for a in (_arity(x) for x in shapes) if a is not None]


def _change_evidence(pre: list, post: list, sites: list[dict]) -> bool:
    """Is there EVIDENCE the callers' view of the result may have changed? (Only then is a request worth blocking on.)

    * pre fully decided: any difference in the decided arities, or an undecided post path (the pre arity was known,
      the post one is not), is evidence.
    * pre (partly) undecided: undecided-vs-undecided is no evidence (the differential covers behaviour); the only
      evidence is a NEW decided post arity that breaks a listed consumer's unpack/index."""
    pre_d, pre_u = _decided_arities(pre), sum(1 for x in pre if _arity(x) is None)
    post_d, post_u = _decided_arities(post), sum(1 for x in post if _arity(x) is None)
    if pre_u == 0:
        return not (post_u == 0 and {repr(a) for a in pre_d} == {repr(a) for a in post_d})
    known = {repr(a) for a in pre_d}
    new = [a for a in post_d if repr(a) not in known]
    return any(_violates(a, st["demand"]) for st in sites if st["demand"]["kind"] in ("unpack", "index") for a in new)


def return_shape_requests_from_account(account: Mapping[str, Any], post_root: str | Path,
                                       touched_files: Iterable[str] = ()) -> list[dict[str, Any]]:
    """One return_shape request per modified callable whose decided return shapes changed.

    Caller consumption is read from the post-change tree (``post_root``) at each listed call site."""
    root = Path(post_root).resolve()
    added = {a["qualified_name"] for a in account.get("added_callables", ())}
    bind = {r["target_symbol"]: r for r in requests_from_account(account, touched_files) if not r.get("added")}
    out: list[dict[str, Any]] = []
    for m in account["modified_callables"]:
        q = m["qualified_name"]
        pre, post = m.get("pre_return_shapes") or [], m.get("post_return_shapes") or []
        if q in added or q not in bind:
            continue
        b = bind[q]
        sites: list[dict[str, Any]] = []
        for c in b["call_sites"] + b["stale_sites"]:
            where = f"{c['file_path']}:{c['line_number']}"
            base = {"where": where, "caller": c["caller_qualified_name"], "callee": q}
            if c in b["stale_sites"]:
                sites.append({**base, "demand": {"kind": "opaque", "why": "caller file is changed by the effect"}})
                continue
            try:
                p = (root / c["file_path"]).resolve()
                p.relative_to(root)
                text = p.read_text()
            except (OSError, ValueError, UnicodeDecodeError):
                sites.append({**base, "demand": {"kind": "opaque", "why": "caller source unreadable in the post tree"}})
                continue
            sites.append({**base, "demand": consumer_demand(text, int(c["line_number"]), c.get("node_source", ""))})
        if not _change_evidence(pre, post, sites):
            continue
        try:
            own = ast.parse((root / m["file_path"]).read_text())
            wrapped = _wrapped(own, q, int(m.get("line_number", 0)))
        except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
            wrapped = True
        keep = ("kind", "source", "container_kind", "length", "literal_value", "file_path", "line_number", "resolution", "provenance")
        out.append({
            "kind": "return_shape",
            "obligation_id": f"return_shape:{q}",
            "target_symbol": q,
            "pre_shapes": [{k: s.get(k) for k in keep} for s in pre],
            "post_shapes": [{k: s.get(k) for k in keep} for s in post],
            "sites": sites,
            "returns_wrapped": wrapped,
            "unknown_edge_count": b["unknown_edge_count"],
            "unexplored_scope": b["unexplored_scope"],
        })
    return out


# --------------------------------------------------------------- effect-account adapter
_ABSENT_IN_BASELINE = "callable_absent_in_baseline"


def requests_from_account(account: Mapping[str, Any], touched_files: Iterable[str] = ()) -> list[dict[str, Any]]:
    """One checker request per modified callable, built only from the account's claims.

    Baseline call sites in files the effect itself changes may differ in the candidate tree, so
    they are handed over as ``stale_sites`` (not decidable) unless ``post_call_sites`` is present.
    """
    touched = {str(t) for t in touched_files} | {m["file_path"] for m in account["modified_callables"]}
    post_sites = account.get("post_call_sites")
    out: list[dict[str, Any]] = []
    added = {a["qualified_name"]: a for a in account.get("added_callables", ())}
    opaque_guards = list(account.get("opaque_caller_guards", ()))

    def _opaque_guard_fields(sites: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        callers = {str(site.get("caller_qualified_name", "?")) for site in sites}
        relevant = [g for g in opaque_guards if g.get("caller_qualified_name") in callers]
        # The account makes node_id unique. Deduplicate defensively for hand-built/legacy accounts.
        identities = {str(g.get("node_id", i)) for i, g in enumerate(relevant)}
        return {
            "opaque_caller_guard_count": len(identities),
            "opaque_caller_guard_callers": sorted({str(g["caller_qualified_name"]) for g in relevant}),
        }

    def _added_request(a: Mapping[str, Any]) -> dict[str, Any]:
        q = a["qualified_name"]
        sites = list(a.get("post_call_sites", ()))
        return {
            "obligation_id": f"signature_binding:{q}",
            "target_symbol": q,
            "added": True,
            "post_signature": a["post_signature"],
            "call_sites": sites,
            "entry_guards": a.get("entry_guards", []),
            "unknown_edge_count": len(a.get("unknown_edges", ())),
            "unexplored_scope": a.get("unexplored_scope", ""),
            **_opaque_guard_fields(sites),
        }

    for m in account["modified_callables"]:
        q = m["qualified_name"]
        if q in added:  # the added record wins; the request keeps this entry's position (derive zips by index)
            out.append(_added_request(added[q]))
            continue
        sites = [c for c in (post_sites if post_sites is not None else account["impacted_call_sites"])
                 if c["callee_qualified_name"] == q]
        opaque_fields = _opaque_guard_fields(sites)
        stale = [c for c in sites if post_sites is None and c["file_path"] in touched]
        fresh = [c for c in sites if c not in stale]
        mine = [u for u in account.get("unknown_edges", ()) if u.get("target_qualified_name") == q]
        guard_gap = [u for u in mine if "unsupported_entry_guard" in str(u.get("reason", ""))]
        unknown = [u for u in mine if u not in guard_gap and not (
            _ABSENT_IN_BASELINE in str(u.get("reason", "")) and not u.get("caller_qualified_name"))]
        scope = account.get("unexplored_scope", "")
        if guard_gap:  # not caller edges: entry guards the account could not express stay unexplored scope
            scope += f" {len(guard_gap)} entry guard(s) of {q} could not be expressed."
        out.append({
            "obligation_id": f"signature_binding:{q}",
            "target_symbol": q,
            "pre_signature": m["pre_signature"],
            "post_signature": m["post_signature"],
            "call_sites": fresh,
            "stale_sites": stale,
            "entry_guards": m.get("entry_guards", []),
            "pre_entry_guards": m.get("pre_entry_guards", []),
            "unknown_edge_count": len(unknown),
            "unexplored_scope": scope.strip(),
            **opaque_fields,
        })
    listed = {m["qualified_name"] for m in account["modified_callables"]}
    out.extend(_added_request(a) for q, a in added.items() if q not in listed)  # after, so index zips hold
    return out


# --------------------------------------------------------------- confined supervisor side
def _sha256_file(p: str | Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def measure_proposer_readable(paths: Iterable[str], profile: Any) -> bool:
    """True if ANY proposer path can be opened from inside the same confinement profile."""
    from hlith.sandbox import (
        ConfinementBoundaryError,
        ConfinementBoundaryInfo,
        raise_if_confinement_boundary,
        run_confined,
    )

    code = (
        "import os,sys\n"
        "p=sys.argv[1]\n"
        "try:\n"
        "    (os.listdir(p) if os.path.isdir(p) else open(p,'rb').read(1))\n"
        "    sys.exit(0)\n"
        "except OSError:\n"
        "    sys.exit(3)\n"
    )
    for p in paths:
        cp = run_confined([sys.executable, "-I", "-c", code, str(p)], profile, timeout=30)
        raise_if_confinement_boundary(cp)
        if cp.returncode == 0:
            return True
        if cp.returncode != 3:
            detail = f"confinement canary failed to run (exit {cp.returncode}): {cp.stderr.strip()[-240:]}"
            raise ConfinementBoundaryError(
                ConfinementBoundaryInfo(code="confinement-canary-failed", stage="canary", detail=detail),
            )
    return False


def verify_confined(
    request: Mapping[str, Any], *, scratch_dir: str | Path, proposer_paths: Iterable[str]
) -> Obligation:
    """Run the Z3 check as a confined child; build provenance from measured facts."""
    return verify_confined_detailed(request, scratch_dir=scratch_dir, proposer_paths=proposer_paths)[0]


def verify_confined_detailed(
    request: Mapping[str, Any], *, scratch_dir: str | Path, proposer_paths: Iterable[str]
) -> tuple[Obligation, dict[str, Any]]:
    """As verify_confined, also returning the checker's structured analysis (incl. ``witness_inputs``).

    The checker consumes only the account's claims (signature text, call-site fields, guards).
    It imports no analyzer or parser module, so it shares no program model with the analyzer."""
    from hlith.sandbox import Profile, raise_if_confinement_boundary, run_confined

    from hlith.differential import _special_file

    scratch = Path(scratch_dir)
    ro_grants = (str(Path(__file__).resolve().parents[2]), str(scratch))  # the source root (src), as before the move
    # finding 24 class: a socket/FIFO/device under any granted path is a channel out of the confinement
    # (a pathname AF_UNIX socket stays connectable under a ro mount). Walk every grant before granting it.
    special = _special_file(ro_grants)
    if special is not None:
        return Obligation(
            request["obligation_id"], request["target_symbol"], request.get("kind") or "signature_binding", Verdict.UNVERIFIED,
            stop_reason=f"confined checker not run: {special}",
        ), {}
    req_path = scratch / f"{request['obligation_id']}.request.json"
    req_path.write_text(json.dumps(request, sort_keys=True))
    profile = Profile(ro=ro_grants)
    readable = measure_proposer_readable(list(proposer_paths), profile)
    cp = run_confined([sys.executable, "-I", str(Path(__file__).resolve()), str(req_path)], profile, timeout=120)
    raise_if_confinement_boundary(cp)
    prov = CheckProvenance(
        checker_id=f"z3_call_binding_verifier@z3-{z3.get_version_string()}",
        checker_sha256=_sha256_file(__file__),
        confined=True,
        proposer_paths_readable=readable,
        profile_sha256=profile.sha256,
        exit_code=cp.returncode,
    )
    if cp.returncode != 0:
        return Obligation(
            request["obligation_id"], request["target_symbol"], request.get("kind") or "signature_binding", Verdict.UNVERIFIED,
            stop_reason=f"confined checker exited {cp.returncode}: {cp.stderr.strip()[-300:]}",
        ), {}
    analysis = json.loads(cp.stdout)
    if readable:  # independence not met: cannot be held
        return derive_obligation(request, analysis, None), analysis
    return derive_obligation(request, analysis, prov), analysis


def _main(argv: list[str]) -> int:
    req = json.loads(Path(argv[1]).read_text())
    json.dump(analyze(req), sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
