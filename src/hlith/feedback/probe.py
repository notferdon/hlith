# SPDX-License-Identifier: Apache-2.0
"""Confined post-refusal and post-landing probes on SealedSnapshots (F1 + F2)."""

from __future__ import annotations

import re

import time as _tm
from pathlib import Path
from typing import Any, Sequence

from ..contract.capabilities import SealedSnapshot
from ..contract.effects import EffectAccount
from ..contract.runs import GateReceipt
from ._legacy import (
    EXT_BUDGET_S,
    DirectiveKind,
    FeedbackIntegrityError,
    FeedbackRecord,
    _call_input,
    _canon,
    _param_names,
    _pin_limit,
    _witness_outcome,
    delta_covers_pin,
    ext_probe_seed,
    extended_probe,
    import_root_of,
    literal_seeds,
    literals_from_tests,
    not_derived_construct,
    oracle_regression,
    pin_regression_counterexample,
    PROBE_MEM_LIMIT,
    REGRESSION_KINDS,
    pool_seeds,
    post_gate_probe,
    receiver_for,
    require_differential_domain_constraint,
    split_symbol,
    stub_seeds,
    with_provenance,
)
from .store import append_supersession, load_stored_records, persist_record


def _note_limit(limits: list[str] | None, errors: list[str] | None, msg: str) -> None:
    """A NAMED LIMIT of what L5 explored (records that were written stay valid). It is not a recording failure. The operator
    renders ``errors`` as "feedback not recorded", so a limit goes to ``limits`` when the caller collects them. Callers that only
    pass ``errors`` (older direct callers) still see it there, never dropped."""
    target = limits if limits is not None else errors
    if target is not None:
        target.append(msg)


_IMPORT_FAIL_RE = re.compile(r"^\s*((?:ModuleNotFoundError|ImportError): .+?)\s*$", re.M)


def _probe_import_failure(exc: BaseException) -> str | None:
    """The final ModuleNotFoundError/ImportError line when the probe runner died IMPORTING the target module (observe(): "probe failed
    (exit N): <traceback>"), else None. That is a limit of what L5 could explore (the probe's interpreter / sys.path / package root), not a
    feedback-store failure, and the operator must not be told to fix store permissions (design decision b, F2 real-repo run 2026-11-21)."""
    msg = str(exc)
    if not isinstance(exc, RuntimeError) or not msg.startswith("probe failed"):
        return None
    hits = _IMPORT_FAIL_RE.findall(msg)
    return hits[-1][:200] if hits else None


def _note_probe_failure(sym: str, exc: BaseException, errors: list[str] | None, limits: list[str] | None) -> None:
    why = _probe_import_failure(exc)
    if why is not None:
        _note_limit(limits, errors, f"{sym}: UNPROBED by Layer 5: the probe could not import the target module ({why}); no feedback stored "
                                    f"for this symbol. Check --target-python / --extra-sys-path and that the module imports from the "
                                    f"repository's package root")
    elif errors is not None:
        errors.append(f"{sym}: {type(exc).__name__}: {exc}")


def _outcome_of(o):
    """Evaluator shape {k: ret|exc|timeout} or an already-normalized {kind: return|raise|timeout}; anything else is None
    (the witness is reported unpinned, never coerced to 'timeout')."""
    if not isinstance(o, dict):
        return None
    if "k" in o and o["k"] in ("ret", "exc", "timeout"):
        return _witness_outcome(o)
    kind = o.get("kind")
    if kind == "return" and isinstance(o.get("repr"), str):
        return {"kind": "return", "repr": o["repr"]}
    if kind == "raise" and isinstance(o.get("exc"), str):
        return {"kind": "raise", "exc": o["exc"]}
    if kind == "timeout":
        return {"kind": "timeout"}
    return None


def _witness_key(symbol: str, inp: dict) -> tuple[str, str]:
    return (symbol, _canon(inp))


def _pin_witness_records(
    source_run_id: str,
    witnesses: Sequence[dict],
    unpinned: list | None = None,
) -> tuple[list[FeedbackRecord], set[tuple[str, str]]]:
    records: list[FeedbackRecord] = []
    keys: set[tuple[str, str]] = set()
    for w in witnesses:
        sym = w.get("symbol")
        args = w.get("args")
        kwargs = w.get("kwargs")
        why = _pin_limit(w)
        pre = w.get("pre", w.get("base_outcome"))
        post = w.get("post", w.get("post_outcome"))
        if why is None and (not isinstance(sym, str) or args is None or not isinstance(kwargs, dict)
                            or not isinstance(pre, dict) or not isinstance(post, dict)):
            why = "incomplete"
        exp_o, obs_o = _outcome_of(pre), _outcome_of(post)
        if why is None and (exp_o is None or obs_o is None):
            why = "unknown_outcome_shape"
        if why is None and exp_o == obs_o:
            why = "not_divergent"
        if why is not None:  # never fabricated, never dropped silently
            if unpinned is not None:
                unpinned.append({"symbol": sym if isinstance(sym, str) else None, "reason": why})
            continue
        env = w.get("env") or None
        try:
            rec = pin_regression_counterexample(source_run_id, sym, args, kwargs,
                                                expected=exp_o, observed=obs_o, env=env)
            rec = with_provenance(rec, origin_kind="differential-witness", observed_in_run="refuted")
        except Exception as exc:  # noqa: BLE001
            if unpinned is not None:
                unpinned.append({"symbol": sym, "reason": f"{type(exc).__name__}: {exc}"[:200]})
            continue
        records.append(rec)
        keys.add(_witness_key(sym, rec.directive_payload["input"]))
    return records, keys


def _nested_function_parent(src_root: Path, module: str, func: str) -> str | None:
    """The enclosing function's name if ``func`` (dotted) names a def nested inside a module-level FUNCTION; else None."""
    import ast

    rel = Path(*module.split("."))
    for cand in (Path(src_root) / rel.with_suffix(".py"), Path(src_root) / rel / "__init__.py"):
        if cand.is_file():
            try:
                tree = ast.parse(cand.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                return None
            head = func.split(".")[0]
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == head:
                    return head
            return None
    return None


def _probe_symbol_pair(
    source_run_id: str,
    base_path: Path,
    post_path: Path,
    sym: str,
    *,
    probe_limit: int,
    ext_deadline: float,
    run_extended: bool,
    exclude_keys: set[tuple[str, str]] = (),
    observe_kw: dict[str, Any] | None = None,
    errors: list[str] | None = None,
    limits: list[str] | None = None,
    agreeing_out: list | None = None,
) -> list[FeedbackRecord]:
    split = split_symbol(base_path, sym)
    if split is None:
        if errors is not None:
            errors.append(f"missing-module-file: {sym} (no matching .py or /__init__.py under ., src/, lib/ in {base_path})")
        return []
    module, func = split
    b_root = import_root_of(base_path, module)
    p_root = import_root_of(post_path, module)
    if b_root is None or p_root is None:
        if errors is not None:
            errors.append(f"missing-module-file: {sym} (module {module!r} not found in base/post)")
        return []
    recv, why = receiver_for(base_path, b_root, module, func)
    if why == "not_instantiable":
        return []
    nested = _nested_function_parent(b_root, module, func) if "." in func and recv is None else None
    if nested:
        # a def nested inside a module-level FUNCTION (a closure, e.g. funcy's throttle.decorator) is not an attribute of its parent,
        # so the runner's attribute walk could only crash (review funcy:a, events seq 18). Named limit, no runner started; never an error
        # trace, never a verdict input (L5 runs after the gate). Dotted CLASS paths are untouched: a static/class method without a
        # derivable receiver is still reachable by the attribute walk and keeps being probed.
        _note_limit(limits, errors, f"{sym}: UNPROBED by Layer 5 (nested function inside {nested}(): not addressable from its module)")
        return []
    okw: dict[str, Any] = dict(observe_kw or {})
    if recv is not None:
        okw["receiver"] = recv

    tests = base_path / "tests"
    seeds = literal_seeds(b_root, tests, module, func) if tests.is_dir() else []
    seeds += pool_seeds(b_root, module, func, literals=literals_from_tests(tests, func) if tests.is_dir() else [])
    seeds += stub_seeds(b_root, module, func)

    out: list[FeedbackRecord] = []
    seen_exclude = set(exclude_keys)
    excluded: list[int] = []
    if seeds:
        for rec in post_gate_probe(
            source_run_id,
            b_root,
            p_root,
            module,
            func,
            seeds,
            limit=probe_limit,
            excluded_out=excluded,
            provenance_origin_kind="refusal-probe",
            provenance_observed_in_run="refused",
            **okw,
        ):
            if _witness_key(sym, rec.directive_payload["input"]) not in seen_exclude:
                out.append(rec)
    if run_extended and probe_limit > 0:
        ext, ext_stats = extended_probe(
            source_run_id,
            b_root,
            p_root,
            module,
            func,
            seed=ext_probe_seed(sym),
            tree_root=post_path,
            limit=probe_limit,
            deadline=ext_deadline,
            agreeing=agreeing_out,
            **okw,
        )
        for rec in ext:
            if _witness_key(sym, rec.directive_payload["input"]) not in seen_exclude:
                out.append(with_provenance(
                    rec, origin_kind="refusal-probe", observed_in_run="refused"))
        if ext_stats.get("annotation_excluded"):
            excluded.append(ext_stats["annotation_excluded"])
        if ext_stats.get("resource_limited"):
            _note_limit(limits, errors, f"{sym}: {ext_stats['resource_limited']} probe input(s) reached the probe memory limit (RLIMIT_AS "
                          f"{PROBE_MEM_LIMIT >> 30} GiB): UNEXPLORED, neither agreement nor witness")
    if excluded:
        # same domain as the gate (design review 2026-11-21): stated, never silent, like the differential's own "never given ..." line
        _note_limit(limits, errors, f"{sym}: {sum(excluded)} probe input(s) outside the parameter annotations were NOT probed by Layer 5 "
                                    f"(the gate's declared domain); a change visible only for such values is not compared")
    return out


def run_refusal_probes(
    store_dir: Path,
    receipt: GateReceipt,
    account: EffectAccount,
    evidence: dict[str, Any],
    *,
    errors: list[str] | None = None,
    limits: list[str] | None = None,
) -> tuple[str, ...]:
    """Persist refusal pins, unresolved constructs, and F2 extended_probe discoveries to ``store_dir``."""
    if receipt.outcome != "refused":
        raise FeedbackIntegrityError(f"persist_refusal requires outcome='refused', got {receipt.outcome!r}")
    source_run_id = str(receipt.run_id)
    written_ids: list[str] = []

    witnesses = evidence.get("witnesses") or ()
    skipped: list[dict] = []
    witness_recs, witness_keys = _pin_witness_records(source_run_id, witnesses, skipped)
    if isinstance(evidence.get("unpinned"), list):
        evidence["unpinned"].extend(skipped)
    for item in skipped:
        _note_limit(limits, errors, f"{item['symbol']}: witness not pinned: {item['reason']}")
    for rec in witness_recs:
        persist_record(store_dir, rec)
        written_ids.append(rec.feedback_id)

    for c in evidence.get("constructs") or ():
        sha = c.get("node_sha256")
        if not sha:
            continue
        loc = f"{c.get('file_path')}:{c.get('line')}" if c.get("line") is not None else str(c.get("file_path"))
        sym = str(c.get("caller_qualified_name") or c.get("file_path") or "")
        rec = not_derived_construct(source_run_id, sym, str(c.get("kind") or "other"), loc, str(sha))
        persist_record(store_dir, rec)
        written_ids.append(rec.feedback_id)

    base: SealedSnapshot | None = evidence.get("base")
    post: SealedSnapshot | None = evidence.get("post")
    if base is None or post is None:
        return tuple(written_ids)

    refuted = sorted({str(s) for s in (evidence.get("refuted_symbols") or ()) if "." in str(s)})
    others = sorted({s for s in account.modified_callables if "." in s and s not in refuted})
    symbols = refuted + others
    if not symbols:
        return tuple(written_ids)

    probe_limit = int(evidence.get("probe_limit", 3))
    ext_deadline = _tm.monotonic() + EXT_BUDGET_S
    observe_kw = dict(evidence.get("observe_kw") or {})
    for sym in symbols:
        try:
            recs = _probe_symbol_pair(
                source_run_id,
                base.path,
                post.path,
                sym,
                probe_limit=probe_limit,
                ext_deadline=ext_deadline,
                run_extended=True,
                exclude_keys=witness_keys,
                observe_kw=observe_kw,
                errors=errors,
                limits=limits,
            )
            for rec in recs:
                persist_record(store_dir, rec)
                written_ids.append(rec.feedback_id)
        except Exception as e:  # noqa: BLE001
            _note_probe_failure(sym, e, errors, limits)
    return tuple(written_ids)


def supersessions_from_deltas(store_dir: Path, approved_deltas: Sequence[dict], tree: Path) -> list[dict]:
    """The trusted L5 computation of which stored pins a CONFIRMED delta set supersedes: {fb_id, delta_id, delta_set_sha256} per
    stored pin_regression_counterexample that some approved delta covers (delta_covers_pin, parameter names read from ``tree``).
    No deltas -> nothing. An unreadable store raises (FeedbackIntegrityError): the caller's landing-probe error path reports it."""
    if not approved_deltas:
        return []
    from ..contract.effects import delta_set_sha256

    sha = delta_set_sha256(list(approved_deltas))
    names_cache: dict[str, list[str]] = {}
    out: list[dict] = []
    for item in load_stored_records(store_dir, None):
        rec = item.record
        if rec.directive_kind not in REGRESSION_KINDS:  # pins AND their oracle twins (review FB-NEW-1)
            continue
        sym = rec.directive_payload["symbol"]
        if sym not in names_cache:
            names_cache[sym] = _symbol_param_names(tree, sym)
        hit = next((d for d in approved_deltas if delta_covers_pin(d, rec, names_cache[sym])), None)
        if hit is not None:
            out.append({"fb_id": rec.feedback_id, "delta_id": hit.get("id"), "delta_set_sha256": sha})
    return out


def _symbol_param_names(tree: Path, sym: str) -> list[str]:
    split = split_symbol(tree, sym)
    root = import_root_of(tree, split[0]) if split else None
    return _param_names(root, *split) if root is not None else []


DOMAIN_MAX_INPUTS = 16  # per record
DOMAIN_MAX_RECORDS_PER_SYMBOL = 4  # per symbol across runs: <= 64 domain inputs per symbol, whatever the number of landings


def _domain_key(args: Any, kwargs: Any) -> str:
    return _canon({"args": list(args), "kwargs": dict(kwargs)})


def _explored_novelty(explored: dict | None, sym: str, notes: list[str] | None):
    """A function input -> number of its parameters whose value the GATE did not run, or None when that cannot be told: no summary
    (UNKNOWN, never "nothing explored"), a summary for another target, or no digest function in this build.
    Per parameter, review's decision rule (differential.explored_input_digest; no key parsing): a value was NOT run iff its digest is absent
    from params[i].digests AND params[i].digests_truncated is False. A parameter without a usable digest set (absent, or truncated past
    4096) never counts as novel: absence there proves nothing. The 64-entry values[] sample is never used to decide absence."""
    if not isinstance(explored, dict) or explored.get("target") != sym:
        if explored is not None and notes is not None:
            notes.append(f"{sym}: domain constraint: the gate's explored-input summary is for another target: largest-first selection used")
        return None
    try:
        from ..obligation.api import explored_input_digest
    except ImportError:
        if notes is not None:
            notes.append(f"{sym}: domain constraint: no explored-input digest function in this build: largest-first selection used")
        return None
    params = [p for p in explored.get("params") or [] if isinstance(p, dict)]
    seen = [(set(p["digests"]) if isinstance(p.get("digests"), list) and p.get("digests_truncated") is False else None) for p in params]
    names = [p.get("name") for p in params]
    if all(d is None for d in seen):
        if notes is not None:
            notes.append(f"{sym}: domain constraint: no parameter has a complete explored-digest set: largest-first selection used")
        return None

    def novelty(inp: dict) -> int:
        n = 0
        vals = list(inp.get("args") or [])
        for i, digests in enumerate(seen):
            if digests is None:
                continue
            if i < len(vals):
                v = vals[i]
            elif names[i] in (inp.get("kwargs") or {}):
                v = inp["kwargs"][names[i]]
            else:
                continue
            n += explored_input_digest(v) not in digests
        return n

    return novelty


def domain_constraint_from_agreeing(source_run_id: str, sym: str, agreeing: Sequence[dict], *,
                                    covered: set[str] = frozenset(), notes: list[str] | None = None,
                                    explored: dict | None = None, explored_notes: list[str] | None = None) -> FeedbackRecord | None:
    """Pick at most DOMAIN_MAX_INPUTS agreeing inputs NOT already ``covered`` by an earlier domain record of ``sym``, the ones LEAST
    likely to be in a later run's ordinary seed domain: largest canonical size first (huge ints, long strings), ties by canonical text
    (deterministic). Inputs with an environment overlay cannot be carried by the constraint format (args/kwargs only): they are
    named in ``notes`` as UNEXPLORED for later runs, never counted as covered."""
    seen: set[str] = set()
    cand = []
    env_skipped = 0
    for inp in agreeing:
        if inp.get("env"):
            env_skipped += 1
            continue
        key = _domain_key(inp["args"], inp["kwargs"])
        if key in seen:
            continue
        seen.add(key)
        cand.append((len(key), key, inp))
    if env_skipped and notes is not None:
        notes.append(f"{sym}: domain constraint: {env_skipped} agreeing input(s) with an environment overlay are NOT recorded "
                     f"(unexplored by later runs, not covered)")
    if not cand:
        return None
    nov = _explored_novelty(explored, sym, explored_notes if explored_notes is not None else notes) if explored is not None else None
    if nov is not None:
        # design review 2026-11-21 (the one F2 route): prefer inputs the GATE never ran (most novel parameters first), so the record adds coverage
        # the engine lacks; then the old order. Deterministic and bounded as before; an input the gate did run can only fill the tail.
        cand.sort(key=lambda c: (-nov(c[2]), -c[0], c[1]))
    else:
        cand.sort(key=lambda c: (-c[0], c[1]))
    # select the top DOMAIN_MAX_INPUTS FIRST, then drop what an earlier record already carries: a repeated landing with the same
    # probe result adds nothing (no creep through the tail of the candidate list)
    picked = [(tuple(c[2]["args"]), dict(c[2]["kwargs"])) for c in cand[:DOMAIN_MAX_INPUTS] if c[1] not in covered]
    if not picked:
        return None
    return require_differential_domain_constraint(source_run_id, (sym,), picked)


def _bounded_domain_record(store_dir: Path, source_run_id: str, sym: str, agreeing: Sequence[dict],
                           notes: list[str] | None, explored: dict | None = None,
                           limits: list[str] | None = None) -> FeedbackRecord | None:
    """Bound across runs: inputs already carried by an earlier domain record of ``sym`` are not written again, and at most
    DOMAIN_MAX_RECORDS_PER_SYMBOL domain records exist per symbol. An unreadable store writes nothing (this record only ADDS
    checking; omitting it is safe) and is named in ``notes``."""
    try:
        existing = [s.record for s in load_stored_records(store_dir, (sym,))
                    if s.record.directive_kind is DirectiveKind.REQUIRE_DIFFERENTIAL_DOMAIN_CONSTRAINT and sym in s.record.target_symbols]
    except Exception as e:  # noqa: BLE001
        if notes is not None:
            notes.append(f"{sym}: domain constraint not written: feedback store unreadable ({type(e).__name__})")
        return None
    covered = {_domain_key(i["args"], i["kwargs"]) for r in existing for i in r.directive_payload["pinned_inputs"]}
    rec = domain_constraint_from_agreeing(source_run_id, sym, agreeing, covered=covered, notes=notes, explored=explored,
                                         explored_notes=limits if limits is not None else notes)
    if rec is not None and len(existing) >= DOMAIN_MAX_RECORDS_PER_SYMBOL:
        if notes is not None:
            notes.append(f"{sym}: domain constraint not written: {len(existing)} domain records already stored "
                         f"(cap {DOMAIN_MAX_RECORDS_PER_SYMBOL})")
        return None
    return rec


def run_landing_probes(
    store_dir: Path,
    receipt: GateReceipt,
    base: SealedSnapshot,
    landed: SealedSnapshot,
    *,
    symbols: Sequence[str],
    excluded_guard_symbols: Sequence[str] = (),
    probe_limit: int = 3,
    deltas_confirmed: bool = False,
    rehearsal: bool = False,
    superseded: Sequence[dict] = (),
    approved_deltas: Sequence[dict] = (),
    oracle_tests_by_symbol: dict[str, Sequence[str]] | None = None,
    observe_kw: dict[str, Any] | None = None,
    errors: list[str] | None = None,
    limits: list[str] | None = None,
    gate_explored: dict[str, dict] | None = None,
) -> tuple[str, ...]:
    """Run post-landing probes on a SEALED landed snapshot and record supersessions if confirmed. ``gate_explored`` (optional):
    symbol -> differential.read_explored_inputs(...) of the GATE run that admitted this landing; domain records then prefer inputs the
    gate never ran (absent / None = UNKNOWN: the previous largest-first order)."""
    gx = dict(gate_explored or {})
    if receipt.outcome != "landed" or not receipt.landed_commit:
        raise FeedbackIntegrityError(f"post_landing_probe requires landed receipt with commit, got {receipt!r}")
    source_run_id = str(receipt.run_id)

    if deltas_confirmed and rehearsal:
        # design review P0-2 / design review trace 2026-11-20: a rehearsal lands in a CLONE; the source repository (whose store this is) is unchanged,
        # so its pins must stay active. Superseding them here retired the source's protection on the strength of a clone commit
        # (store.py honours any superseded_by_landing while valid_landed_commits is None). Named, never silent.
        _note_limit(limits, errors, "rehearsal landing: approved-delta supersessions NOT recorded (the source repository did not "
                                    "land this change; its stored pins stay active)")
    elif deltas_confirmed:
        # review FB-ADV-1 / seam 1: the pipeline never computed the superseded list (the legacy engine did, via supersede_pins), so an
        # approved landing left the obsolete pins of the refused change active and a later equivalent change was false-refuted.
        # L5 derives it itself from the CONFIRMED delta set: every stored pin a delta covers (delta_covers_pin) is superseded by
        # this landing (provenance appended beside the record, never deleted). Passed-in entries are kept; duplicates collapse.
        superseded = list(superseded) + [s for s in supersessions_from_deltas(store_dir, approved_deltas, base.path)
                                         if s["fb_id"] not in {x["fb_id"] for x in superseded}]
        for s in superseded:
            append_supersession(
                store_dir,
                s["fb_id"],
                {
                    "superseded_by_landing": receipt.landed_commit,
                    "delta_set_sha256": s["delta_set_sha256"],
                    "run_id": source_run_id,
                    "rule": "post-landing: the approved behaviour landed",
                },
            )

    written_ids: list[str] = []
    excluded_guards = sorted({str(s) for s in excluded_guard_symbols if isinstance(s, str) and s})
    excluded_guard_set = set(excluded_guards)
    for gsym in excluded_guards:
        # Provenance-bound exported-guard added callables are not production feedback targets and do not exist in base:
        # disclose explicitly on the named limits channel (never as a missing-module-file error) and do not probe them.
        if limits is not None:
            limits.append(
                f"{gsym}: UNPROBED by Layer 5 (provenance-bound exported-guard added callable; not a production feedback target)"
            )
    ext_deadline = _tm.monotonic() + EXT_BUDGET_S
    tests_map = oracle_tests_by_symbol or {}
    for sym in sorted({s for s in symbols if "." in s and s not in excluded_guard_set}):
        try:
            agreeing: list = []
            recs = _probe_symbol_pair(
                source_run_id,
                base.path,
                landed.path,
                sym,
                probe_limit=probe_limit,
                ext_deadline=ext_deadline,
                run_extended=True,
                observe_kw=observe_kw,
                errors=errors,
                limits=limits,
                agreeing_out=agreeing,
            )
            if recs and deltas_confirmed:
                # review case: the landing's deltas were CONFIRMED, so base->landed divergences are the approved behaviour. A pin with
                # expected = the OLD outcome would make the differential's recorded-expected oracle refuse every later change that keeps
                # the approved behaviour. Record those inputs as a domain constraint instead (no expected value: later runs still compare
                # their own pre/post there). Whether each lies inside the approved domain is not decided here (L5 has no delta set in
                # the landing context): named, not hidden.
                pins = [r for r in recs if r.directive_kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE]
                if approved_deltas:
                    # seam 1: covered by an approved delta = the intended behaviour (domain input); NOT covered = a divergence
                    # OUTSIDE the approved domain that landed anyway: kept as a true regression pin (expected = old) and named
                    names = _symbol_param_names(landed.path, sym)
                    inside = [r for r in pins if any(delta_covers_pin(d, r, names) for d in approved_deltas)]
                    outside = [r for r in pins if r not in inside]
                    if outside:
                        _note_limit(limits, errors, f"{sym}: divergence OUTSIDE the approved domain after an approved landing: {len(outside)} kept as "
                                      f"regression pin(s)")
                else:
                    inside, outside = pins, []
                    _note_limit(limits, errors, f"{sym}: post-landing probe after an approved landing: {len(pins)} base->landed divergence(s) recorded "
                                      f"as a domain constraint, not as old-behaviour pins (no approved delta set in the landing context: "
                                      f"inside/outside the approved domain not decided by L5)")
                div = [dict(r.directive_payload["input"]) for r in inside]
                dom = _bounded_domain_record(store_dir, source_run_id, sym, div + agreeing, errors, gx.get(sym), limits) if (div or agreeing) else None
                recs = list(outside) + ([dom] if dom is not None else [])
            elif not recs and agreeing:
                # review case (a): a SOUND landing (no confirmed divergence) records the extended inputs it explored where base ==
                # landed, as a domain constraint a later run checks its own pre/post on first (the diagram's 'tightened differential
                # domain'). It carries no expected value, so it can only expose a real divergence of a LATER change, never refuse by
                # itself; a diverging landing keeps its regression pins and writes no domain record.
                dom = _bounded_domain_record(store_dir, source_run_id, sym, agreeing, errors, gx.get(sym), limits)
                if dom is not None:
                    recs = [dom]
            for rec in recs:
                persist_record(store_dir, rec)
                written_ids.append(rec.feedback_id)
                tests = tests_map.get(sym) or ()
                if tests and rec.directive_kind is DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE:  # an oracle needs an expected outcome
                    payload = rec.directive_payload
                    inp = payload["input"]
                    orac = oracle_regression(
                        source_run_id,
                        sym,
                        list(tests),
                        inp["args"],
                        inp["kwargs"],
                        inp.get("env"),
                        expected=payload["expected"],
                        observed=payload["observed"],
                    )
                    persist_record(store_dir, orac)
                    written_ids.append(orac.feedback_id)
        except Exception as e:  # noqa: BLE001
            _note_probe_failure(sym, e, errors, limits)
    return tuple(written_ids)
