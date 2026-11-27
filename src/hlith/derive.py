# SPDX-License-Identifier: Apache-2.0
"""Layer 3: derive obligations from the effect account and run the independent checks.

Strict initial rule: anything the account cannot resolve is NOT_DERIVED (refuses), never a pass.
The checkers (Z3 binding, differential harness) consume only the account's claims and
run confined with the proposer's paths unreadable; provenance is measured, not asserted.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import itertools
import re
import shutil
import subprocess
import sys
import tempfile
import time
import inspect
from pathlib import Path
from typing import Any, Callable, Sequence

from . import phases as _phases
from . import delta_cover, delta_follow, delta_rel, differential, docstring_check, guard_removed, z3_binding
from .types import BoundedEvidence, Obligation, ObligationSet, ProposedEffect, Verdict


# Gate 1 (design decision, review's back-to-back table + review's independent reproduction): the white-box adequacy gate is ON in the
# CLI path. With it OFF the 18 independent counterexamples gave 6 false HELDs; with it ON, 0 HELD (cost ~+8% seconds;
# refusals are UNVERIFIED and name the exact uncovered condition). ``HLITH_ADEQUACY_GATE=0`` (or make_derive(
# adequacy_gate=False)) turns it off for MEASUREMENT ONLY: the artifact then says "adequacy: not enforced". Never
# ship a configuration that turns it off.
ADEQUACY_GATE_DEFAULT = True
# OFF (design review, review delta_rel attack D07-D09): an unconditional delta_rel PROVED must not waive review's adequacy gate while the
# proof can be false (module constants folded from the first binding only; exact-type model vs repo subclasses/bool).
# Re-enable only after review clears delta_rel on the full gate.
ADEQUACY_PROVED_WAIVER = False


def _param_names(mc: Any) -> tuple[str, ...]:
    """Call-argument parameter names of a modified callable (receiver excluded), for delta guard identity."""
    try:
        sig = z3_binding.parse_signature(mc.post_signature)
    except Exception:  # noqa: BLE001 - unknown signature: identity cannot be established, coverage stays closed
        return ()
    names = [p.name for p in sig if p.kind in (z3_binding.POSONLY, z3_binding.POS_OR_KW, z3_binding.KWONLY)]
    return tuple(names[1:] if names[:1] in (["self"], ["cls"]) else names)


def _diff_accepts(name: str) -> bool:
    """Does run_differential take ``name``? (guard: this module must work with a differential that predates it)"""
    ps = inspect.signature(differential.run_differential).parameters
    return name in ps or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in ps.values())


def _adequacy_gate_enabled(override: bool | None) -> bool:
    if override is not None:
        return bool(override)
    import os

    if os.environ.get("HLITH_ADEQUACY_GATE", "").strip().lower() in ("0", "off", "false", "no"):
        return False
    return ADEQUACY_GATE_DEFAULT


_FRAGMENT_NOTE = ("delta_rel: exact numeric mode (int/str/bool, constants, slices, branches) or conditional UF mode "
                  "(calls/attributes as uninterpreted terms, no mutation/IO); else UNMODELED. Evidence only: it does "
                  "not replace the repository test slice")


def _artifact_witness(w: dict) -> dict:
    """Artifact form of a counterexample: {param: value_repr}, JSON-safe whatever the model's integers."""
    names = list(w.get("param_names") or [])
    lits = w.get("path_literals") or {}
    return {names[int(i)] if int(i) < len(names) else f"arg{i}": str(v)[:2000] for i, v in lits.items()}


def _has_static_tuple_receiver_proof(c: Any, sites: set[tuple[str, str, int, str]], measured_files: set[str]) -> bool:
    """Match an unresolved method call only to its exact account-bound static tuple receiver fact."""
    if getattr(c, "kind", None) != "unresolved_method_receiver":
        return False
    rel = getattr(c, "file_path", None)
    caller = getattr(c, "caller_qualified_name", None)
    line = getattr(c, "line_number", None)
    source = getattr(c, "source", None)
    if (
        not isinstance(rel, str) or rel not in measured_files
        or not isinstance(caller, str) or not isinstance(line, int) or isinstance(line, bool)
        or not isinstance(source, str)
    ):
        return False
    return (rel, caller, line, source) in sites


def _safe_scope_label(value: object, limit: int = 160) -> str:
    """Keep a residual label printable and bounded before it reaches artifact evidence."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:limit]


def _target_version(target_python: str | None) -> tuple[int, int, int] | None:
    """Use our own known binary version for optional identities. Other versions stay unknown."""
    if target_python:
        try:
            if Path(target_python).samefile(sys.executable):
                return tuple(sys.version_info[:3])
        except OSError:
            pass
    return None


def _delta_rel_item(base: Path | None, post: Path | None, mc: Any, deltas: list[dict],
                    python_version: tuple[int, ...] | None = None) -> tuple[dict, list[dict]] | None:
    """Non-gating delta_rel evidence for one modified callable (F4). Counterexamples are also seeds for
    run_differential, which executes the real functions confined and decides; PROVED/UNMODELED add no
    obligation and relax nothing (the empty-slice policy is untouched)."""
    if base is None or post is None:
        return None
    try:
        func = _split_qualified(mc.qualified_name, mc.file_path)[1]  # 'f' or 'Class.method' within the module
        b, p_ = Path(base) / mc.file_path, Path(post) / mc.file_path
        if not b.is_file() or not p_.is_file():
            return None
        r = delta_rel.check_callable(b.read_text(), p_.read_text(), func, deltas, python_version)
        prov = {**r.provenance, "function": mc.qualified_name.rsplit(".", 1)[-1]}  # schema: last symbol component
        item = {"symbol": mc.qualified_name, "verdict": r.verdict, "reason": " ".join(r.reason.split())[:300],
                "provenance": prov, "witness_inputs": [_artifact_witness(w) for w in r.witness_inputs],
                "fragment_notes": _FRAGMENT_NOTE, "proof_tier": r.tier, "assumptions": list(r.assumptions)}
        return item, (r.witness_inputs if r.verdict == delta_rel.COUNTEREXAMPLE else [])
    except Exception as e:  # noqa: BLE001 - an evidence generator must never break derivation
        return {"symbol": mc.qualified_name, "verdict": delta_rel.UNMODELED,
                "reason": " ".join(f"delta_rel failed: {type(e).__name__}: {e}".split())[:300],
                "provenance": {"analysis": "delta_rel"}, "witness_inputs": [],
                "fragment_notes": _FRAGMENT_NOTE, "proof_tier": "none", "assumptions": []}, []


def _split_qualified(qname: str, file_path: str) -> tuple[str, str, str]:
    """('requests.utils', 'get_auth_from_url', 'src') from a qualified name and its file."""
    # The module comes from the file path, never from splitting the qualified name: for a method
    # ('requests.adapters.HTTPAdapter.send') the last dot separates a class, not a module.
    stem = file_path[:-3] if file_path.endswith(".py") else file_path
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    parts = [p for p in stem.split("/") if p]
    for i in range(len(parts)):  # longest path suffix that is a dotted prefix of the qname
        module = ".".join(parts[i:])
        if qname.startswith(module + "."):
            return module, qname[len(module) + 1:], "/".join(parts[:i])
    module, _, func = qname.rpartition(".")  # fallback: previous behaviour
    mod_path = module.replace(".", "/")
    root =stem[: -len(mod_path)].rstrip("/") if stem.endswith(mod_path) else ""
    return module, func, root


def _base_export(repo: Path, dest: Path) -> Path:
    """Tracked tree of HEAD as a clean directory (no sockets/FIFOs/devices/untracked files). The confined checkers
    run untrusted code against this, never against the LIVE target dir (finding 24: a socket in the target)."""
    from .gitexport import export_tree  # no .gitattributes (export-ignore) filtering, finding 26
    return export_tree(repo, "HEAD", dest / "base")


def _patched_copy(repo: Path, diff: str, dest: Path) -> Path:
    """Post-change tree for the checkers: tracked files of HEAD plus the patch. Never the target."""
    from .gitexport import export_tree
    post = export_tree(repo, "HEAD", dest / "post")
    from .gitsafe import run_plain  # plain export (no .git): scrubbed env, _HARDEN, ceiling at its parent
    cp = run_plain(post, ("apply", "-"), input=diff.encode())
    if cp.returncode != 0:
        raise subprocess.CalledProcessError(cp.returncode, "git apply -", cp.stdout, cp.stderr)
    return post


def _is_docstring_stmt(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _strip_docstrings(node: ast.AST, *, include_containers: bool = False) -> ast.AST:
    """Drop leading string Expr docstrings in place.

    When ``include_containers`` is False (the fail-closed default), only
    top-level, undecorated FunctionDef/AsyncFunctionDef bodies are stripped.
    Module/ClassDef docstrings and any nested or decorated function/class
    docstrings are preserved because decorators/metaclasses/__init_subclass__
    or import-time code can consume them.
    """
    if not include_containers:
        if isinstance(node, ast.Module):
            for child in node.body:
                if (
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not child.decorator_list
                    and child.body
                    and _is_docstring_stmt(child.body[0])
                ):
                    child.body = child.body[1:]
        return node
    if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.body and _is_docstring_stmt(node.body[0]):
            node.body = node.body[1:]
    for child in ast.iter_child_nodes(node):
        _strip_docstrings(child, include_containers=True)
    return node


def _file_has_docstring_import_risk(tree: ast.AST) -> bool:
    """True when a module has file-wide docstring consumers (ClassDef decorators, metaclass=, __init_subclass__, __doc__/inspect reads)."""
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and _is_docstring_stmt(node.body[0]):
                docstring_nodes.add(id(node.body[0].value))
    _risk_names = {"__doc__", "__init_subclass__", "getdoc", "cleandoc", "getmembers"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _risk_names:
            return True
        if isinstance(node, ast.Name) and node.id in _risk_names:
            return True
        if isinstance(node, ast.Constant) and node.value == "__doc__" and id(node) not in docstring_nodes:
            return True
        if isinstance(node, ast.ClassDef):
            if node.decorator_list or any(kw.arg == "metaclass" for kw in node.keywords):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "__init_subclass__":
                return True
    return False


def _is_docstring_only_diff(repo: Path, eff: ProposedEffect) -> bool:
    """True when every touched file is Python and AST-equal to base modulo docstrings."""
    if not touched_files or any(not f.endswith(".py") for f in touched_files):
        return False
    td = Path(tempfile.mkdtemp(prefix="hlith-doccheck-"))
    try:
        base = _base_export(repo, td)
        post = _patched_copy(repo, eff.unified_diff, td)
        for rel in touched_files:
            bf, pf = base / rel, post / rel
            if not bf.is_file() or not pf.is_file():
                return False
            b_perm = _strip_docstrings(ast.parse(bf.read_text(encoding="utf-8")), include_containers=True)
            p_perm = _strip_docstrings(ast.parse(pf.read_text(encoding="utf-8")), include_containers=True)
            if ast.dump(b_perm) != ast.dump(p_perm):
                return False
        return True
    except (OSError, UnicodeDecodeError, SyntaxError, subprocess.CalledProcessError):
        return False
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _is_docstring_only_trees(base: Path, post: Path, touched_files) -> bool:
    """True when every touched file is Python and AST-equal to base modulo docstrings (sealed trees supplied)."""
    if not touched_files or any(not f.endswith(".py") for f in touched_files):
        return False
    try:
        for rel in touched_files:
            bf, pf = Path(base) / rel, Path(post) / rel
            if not bf.is_file() or not pf.is_file():
                return False
            b_perm = _strip_docstrings(ast.parse(bf.read_text(encoding="utf-8")), include_containers=True)
            p_perm = _strip_docstrings(ast.parse(pf.read_text(encoding="utf-8")), include_containers=True)
            if ast.dump(b_perm) != ast.dump(p_perm):
                return False
        return True
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False


def _certificate_for(mc, rg, rcov, base, post, deltas):
    """The guard-removal CERTIFICATE (obligation.guard_certificate) for this removal and the delta that covered it."""
    from .obligation import guard_certificate as gc
    from .obligation.source import TreeIndex

    d = next((x for x in deltas if str(x.get("id")) == str(rcov.delta_id)), None)
    if d is None:
        return gc.Cert(gc.UNSUPPORTED, "the covering delta is not among the declared deltas")
    lb, lp = TreeIndex(Path(base)).locate(mc.qualified_name), TreeIndex(Path(post)).locate(mc.qualified_name)
    if lb is None or lp is None:
        return gc.Cert(gc.UNSUPPORTED, "the callable could not be located in both sealed trees")
    return gc.certify_removal(lb.node, lp.node, rg["cond"], d)


def _removal_obligation(mc, rg, rcov, cert, dob, replay):
    """HELD only when the observed coverage AND the certificate both hold. Otherwise a named non-HELD obligation: a candidate
    counterexample is replayed in the confine (REFUTED when authentic); unsupported = NOT_DERIVED; solver unknown = UNVERIFIED.
    The returned obligation discharges ONLY this guard."""
    from .obligation import guard_certificate as gc

    q, line = mc.qualified_name, rg["line"]
    claim = "a removed entry guard is explained by an approved, observed, certified delta"
    if cert.status == gc.PROVED:
        return Obligation(f"guard-removal-covered:{q}:{line}", q, claim, Verdict.HELD,
                          evidence=BoundedEvidence(executions=rcov.triggering + rcov.agreeing,
                                                   explored=rcov.evidence + "; " + cert.evidence,
                                                   unexplored=("ANNOTATION-BOUNDED: the concrete differential beside this certificate does not explore "
                                                               "inputs violating declared annotations; " + delta_cover.OPEN_SCOPE
                                                               + "; certificate domain: " + cert.domain)),
                          provenance=dob.provenance)
    return _certificate_blocker(mc, rg, cert, replay)


def _certificate_blocker(mc, rg, cert, replay):
    """The named NON-HELD obligation for a certificate that did not prove the removal: counterexample (REFUTED when the confined
    replay reproduces it, else UNVERIFIED), solver/process unknown (UNVERIFIED), outside the model (NOT_DERIVED)."""
    from .obligation import guard_certificate as gc

    q, line = mc.qualified_name, rg["line"]
    claim = "a removed entry guard is explained by an approved, observed, certified delta"
    cid = f"guard-removal-certificate:{q}:{line}"
    if cert.status == gc.COUNTEREXAMPLE:
        rep = replay(cert.candidate)
        if rep is not None and rep.verdict is Verdict.REFUTED:
            return Obligation(cid, q, claim, Verdict.REFUTED,
                              witness=(f"[{gc.SCOPE_NOTE}] {cert.why}; reproduced in the confine: {rep.witness}")[:900])
        why = (f"[{gc.SCOPE_NOTE}] the removal is not shown to be exactly the approved change: {cert.why}; the candidate was "
               + ("not reproduced as a divergence in the confine" if rep is not None else "not replayable"))
        return Obligation(cid, q, claim, Verdict.UNVERIFIED, stop_reason=why[:760])
    if cert.status == gc.UNKNOWN:
        return Obligation(cid, q, claim, Verdict.UNVERIFIED,
                          stop_reason=(f"[{gc.SCOPE_NOTE}] certificate inconclusive: " + cert.why)[:760])
    return Obligation(cid, q, claim, Verdict.NOT_DERIVED,
                      stop_reason=("no certificate for this removal (a coverage claim over sampled executions is not "
                                   "enough): " + cert.why)[:400])


def _additive_certificate(mc, rg, deltas, base, post, replay):
    """The certificate for a removed guard when the differential did NOT hold or the observed coverage is missing (design review, review's
    finding: an off-domain divergence such as n='' refuted first, so the certificate's own counterexample never showed).

    ADDITIVE ONLY: it appends one named obligation beside the existing blocker and can never replace, discharge or upgrade
    anything. Even a PROVED certificate is emitted NON-HELD here: the removal is explained only when the observed differential
    coverage ALSO holds (`_removal_obligation`), and a HELD obligation next to a blocker could otherwise be read as discharging
    scope. A delta is chosen by symbol alone (preferring a modelled expr/returns_expr one); none names the symbol: no obligation."""
    from .obligation import guard_certificate as gc

    named = [d for d in deltas if d.get("symbol") == mc.qualified_name]
    d = next((x for x in named if isinstance(x.get("predicate"), dict) and isinstance(x.get("expected"), dict)
              and x["predicate"].get("type") == "expr" and x["expected"].get("kind") == "returns_expr"), named[0] if named else None)
    if d is None:
        return None

    class _Pick:
        delta_id = d.get("id")

    cert = _certificate_for(mc, rg, _Pick, base, post, deltas)
    if cert.status == gc.PROVED:
        return Obligation(f"guard-removal-certificate:{mc.qualified_name}:{rg['line']}", mc.qualified_name,
                          "a removed entry guard is explained by an approved, observed, certified delta", Verdict.UNVERIFIED,
                          stop_reason=(f"[{gc.SCOPE_NOTE}] the certificate shows, over that domain only, that the removal is exactly the "
                                       "approved change; the differential did not hold or its observed coverage is missing, so "
                                       "nothing is discharged")[:760])
    return _certificate_blocker(mc, rg, cert, replay)


_EXPLORED_BY_SYMBOL: dict = {"key": None, "by_symbol": {}}  # review F2 route (design review concurrence 2026-11-21): last derive_core's gate-explored inputs


def explored_inputs_for(base_dir, post_dir) -> dict[str, dict]:
    """PUBLIC (L5 landing domain record): symbol -> differential.read_explored_inputs(scratch) for every primary-target differential the
    LAST derive_core over exactly these sealed base/post trees ran, read before its scratch is removed. A different tree pair, no
    run, or a build without the accessor -> {} (UNKNOWN: L5 keeps its old order). Deep copy; never a verdict input."""
    import json as _json
    if _EXPLORED_BY_SYMBOL["key"] != (str(base_dir), str(post_dir)):
        return {}
    return _json.loads(_json.dumps(_EXPLORED_BY_SYMBOL["by_symbol"]))


def _note_explored(symbol: str, scratch) -> None:
    reader = getattr(differential, "read_explored_inputs", None)
    if reader is None:
        return
    try:
        got = reader(str(scratch))
    except Exception:  # noqa: BLE001 - evidence for L5 only; it can never change a verdict
        return
    if isinstance(got, dict):
        _EXPLORED_BY_SYMBOL["by_symbol"][symbol] = got


def make_derive(
    *, proposer_paths: Sequence[str], extra_sys_path: Sequence[str] = (), target_python: str | None = None,
    differential_timeout: float = 600.0,
    feedback: Callable[[Path, dict], Any] | None = None,
    adequacy_gate: bool | None = None,
) -> Callable[[Path, ProposedEffect], ObligationSet]:
    """``feedback(repo, account_dict)`` (Layer 5, optional) returns an object with
    ``not_derived()``, ``constraints(symbol)`` and ``pinned_obligation(base, post, symbol)``.
    ``adequacy_gate``: None = ADEQUACY_GATE_DEFAULT (True) unless HLITH_ADEQUACY_GATE=0; False is measurement only."""
    gate_on = _adequacy_gate_enabled(adequacy_gate)

    def derive_core(*, touched_files, deltas, acct, ad, fbk, base_dir, post_dir, has_diff: bool = True,
                    progress: Callable[[str, int, int], None] | None = None,
                    contract_account=None, guard_catalog=None, deltas_approved: bool = False) -> ObligationSet:
        """The obligation derivation over a SUPPLIED account view and sealed base/post trees: no account rebuild, no Git.
        ``acct``/``ad`` have the shape of the account (obligation.facts.Facts builds it from the frozen EffectAccount),
        ``fbk`` is the feedback view (or None)."""
        obs: list[Obligation] = []
        evidence: list[dict] = []  # non-gating proof evidence (delta_rel); decide() never reads it
        _EXPLORED_BY_SYMBOL.update(key=(str(base_dir), str(post_dir)), by_symbol={})  # reset per derivation (never stale)
        deltas = list(deltas or ())  # the operator's intended-change claims (never proof)
        if not has_diff:
            return ObligationSet((Obligation("no-effect", "*", "effect is derivable", Verdict.NOT_DERIVED,
                                             stop_reason="worker produced no change to derive obligations for"),))
        if fbk is not None:
            obs.extend(fbk.not_derived())

        non_py = [f for f in touched_files if not f.endswith(".py")]
        if non_py:
            obs.append(Obligation("non-python-artifact", ",".join(non_py), "effect is derivable", Verdict.NOT_DERIVED,
                                  stop_reason=f"V1 derives Python only; non-Python files in effect: {non_py}"))
        consts = list(ad.get("modified_constants", [])) + list(ad.get("modified_class_attributes", []))
        docstring_only = False
        static_clear_: dict = {}  # module -> static-clear classifications; the skip gate remains disabled pending sound proof
        static_tuple_receiver_sites: set[tuple[str, str, int, str]] = set()
        if not non_py and _is_docstring_only_trees(base_dir, post_dir, touched_files):
            doc_res = docstring_check.verify_docstring_only_diff(
                base_dir,
                post_dir,
                tuple(touched_files),
                python=target_python or sys.executable,
                extra_sys_path=extra_sys_path,
                proposer_paths=proposer_paths,
            )
            obs.extend(doc_res.obligations)
            docstring_only = doc_res.allow_skip_unrelated
            static_clear_ = doc_res.static_clear if docstring_only else {}
            # Older or test-provided result objects may omit this optional proof field. Missing sites
            # establish no tuple receiver proof, so unresolved receiver constructs remain blocking.
            static_tuple_receiver_sites = (
                set(getattr(doc_res, "static_tuple_receiver_sites", ()) or ()) if docstring_only else set()
            )
        measured_docstring_files = {
            o.obligation_id.removeprefix("docstring-measured:")
            for o in obs
            if o.obligation_id.startswith("docstring-measured:")
            and o.verdict is Verdict.HELD
            and o.evidence is not None
            and o.account_bound
            and o.provenance is not None
        }
        tuple_receiver_proofs: dict[str, list[str]] = {}
        deferred_guards: dict = {}  # unresolved index -> (position in obs, construct)
        covered_guard_wheres: set[str] = set()
        removed_guard_wheres: set[str] = set()  # base file:line of each removed guard whose removal certificate HELD
        for i, c in enumerate(acct.unresolved_constructs):
            if getattr(c, "side", "post") == "pre" and c.kind != "unsupported_entry_guard":
                continue  # a construct the change REMOVED is history (kept in the account as unexplored evidence),
                #           except a removed entry guard: a vanished precondition is never history (see below)
            # Consume only the exact file/caller/line/source receiver sites proven to be tuple.count. A
            # same-caller dynamic receiver remains an unresolved blocker even beside a proven tuple call.
            if _has_static_tuple_receiver_proof(c, static_tuple_receiver_sites, measured_docstring_files):
                rel = str(c.file_path)
                rel_label = _safe_scope_label(rel)
                caller = _safe_scope_label(c.caller_qualified_name)
                source = _safe_scope_label(c.source)
                tuple_receiver_proofs.setdefault(rel, []).append(
                    f"tuple.count receiver proven at {rel_label}:{int(c.line_number)} in {caller}: {source}"
                )
                continue
            if c.kind == "unsupported_entry_guard" and deltas:  # may be covered by an approved delta (see below)
                deferred_guards[i] = (len(obs), c)
            if c.kind == "analysis_failed":
                error_type, _, message = c.source.partition(":")
                stop_reason = (
                    f"effect account could not be built: {c.file_path}: {error_type.strip()}: "
                    f"{message.strip()} (line {c.line_number})"
                )
            else:
                stop_reason = f"{c.file_path}:{c.line_number} {c.kind}: {c.source}"
            obs.append(Obligation(f"unresolved-{i}", c.caller_qualified_name or c.file_path,
                                  "effect is derivable", Verdict.NOT_DERIVED,
                                  stop_reason=stop_reason[:400]))
        for rel, facts in tuple_receiver_proofs.items():
            marker = f"docstring-measured:{rel}"
            for oi, measured in enumerate(obs):
                if measured.obligation_id != marker or measured.evidence is None:
                    continue
                shown = facts[:8]
                omitted = len(facts) - len(shown)
                detail = "; ".join(shown)
                if omitted:
                    detail += f"; {omitted} additional fact(s) omitted"
                note = (
                    "exact static receiver facts consumed below are limited to tuple.count calls in the account-bound "
                    "measured docstring file; other dynamic receivers remain blocking and external/receiver-supplied "
                    "docstring readers are not excluded. Facts: "
                    + detail
                )
                measured_evidence = dataclasses.replace(
                    measured.evidence,
                    explored=(measured.evidence.explored + "; " + note)[:2000],
                )
                obs[oi] = dataclasses.replace(measured, evidence=measured_evidence)
                break
        # An added callable has no baseline to compare. It is verified only through the MODIFIED callers that
        # reach it (they get binding + differential below); one that nothing modified reaches cannot be
        # checked non-tautologically, so it stops the gate (NOT_DERIVED), never passes — EXCEPT an unmodified
        # host-authenticated exported pre-guard (exported-guard continuity), which gets its own confined additive obligation.
        from .obligation import exported_guard

        matched_guards = exported_guard.match_exported_guards(
            contract_account, acct, Path(base_dir), Path(post_dir), guard_catalog
        )
        matched_guard_files = tuple(
            sorted(
                {m.rel for m in matched_guards.values()}
                | set(exported_guard.guard_shaped_added_test_files(contract_account, acct, Path(base_dir), Path(post_dir)))
            )
        )
        for a in ad.get("added_callables", []):
            qn = str(a.get("qualified_name") or "")
            if not a.get("reached_from") and qn not in matched_guards:
                obs.append(Obligation(f"added-unreached:{qn}", qn,
                                      "added callable is reached by a modified caller", Verdict.NOT_DERIVED,
                                      stop_reason=f"unexplored: no caller reaches the added callable {qn}"[:300]))
        guard_alone = exported_guard.guard_alone_obligation(
            matched_guards,
            modified_callables=acct.modified_callables,
            added_callables=ad.get("added_callables", []),
            deleted_callables=ad.get("deleted_callables", []),
            modified_constants=ad.get("modified_constants", []),
            modified_class_attributes=ad.get("modified_class_attributes", []),
            touched_files=touched_files,
        )
        if guard_alone is not None:
            obs.append(guard_alone)
        # A DELETED callable: any surviving post-change call site that still targets it is a concrete
        # refutation (the call can no longer bind). With no surviving site, absence of references does not
        # establish safety (external/dynamic callers, impacted tests): the impacted-test slice for deletions
        # is not wired yet, so the obligation stays UNVERIFIED and blocks, never HELD by absence.
        for d in ad.get("deleted_callables", []):
            qn = str(d.get("qualified_name"))
            sites = d.get("post_call_sites") or []
            if sites:
                s = sites[0]
                obs.append(Obligation(f"deleted-still-called:{qn}", qn, "no surviving call site targets a deleted callable",
                                      Verdict.REFUTED,
                                      witness=f"{s.get('file_path')}:{s.get('line_number')} "
                                              f"{s.get('caller_qualified_name')} still calls deleted {qn} "
                                              f"({len(sites)} surviving site(s))"[:400]))
            else:
                obs.append(Obligation(f"deleted-unchecked:{qn}", qn, "deleted callable has no dependants",
                                      Verdict.UNVERIFIED,
                                      stop_reason=f"{qn} deleted; no surviving in-repo call site, but external/dynamic callers and "
                                                  f"impacted tests are not verified for deletions yet"[:300]))
        if (not acct.modified_callables and not ad.get("modified_constants")
                and not ad.get("modified_class_attributes") and not obs):
            obs.append(Obligation("no-callable", "*", "effect is derivable", Verdict.NOT_DERIVED,
                                  stop_reason="no Python callable modified; V1 derives callable boundary obligations only"))

        work = Path(tempfile.mkdtemp(prefix="hlith-derive-"))
        _diff_seq = itertools.count(1)

        def _diff_scratch(kind: str, qname: str) -> Path:
            slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", qname).strip("_")[:48] or "fn"
            digest = hashlib.sha256(qname.encode("utf-8", errors="surrogateescape")).hexdigest()[:10]
            return work / "diff" / f"{next(_diff_seq):04d}_{kind}_{slug}_{digest}"
        try:
            # module-level constants AND class-body attributes: both are verified through their readers
            post = post_dir if (acct.modified_callables or consts or docstring_only) else None
            base = base_dir if post is not None else None
            # review's adapter builds each request from the account's claims, using the post-change callers
            # (a caller the effect itself rewrites must not be judged by its baseline text).
            requests = z3_binding.requests_from_account(ad, touched_files)
            added_names = {a.get("qualified_name") for a in ad.get("added_callables", [])}
            rs_reqs = ({r["target_symbol"]: r for r in z3_binding.return_shape_requests_from_account(
                ad, post, touched_files)} if post is not None else {})
            executed_post: set[str] = set()  # post-tree functions the callers' differential corpus actually ran
            _n_diff = sum(1 for _m in acct.modified_callables if _m.qualified_name not in added_names)  # engine fact for the event source
            _i_diff = 0
            for mc, req in zip(acct.modified_callables, requests):
                if mc.qualified_name not in added_names:
                    _i_diff += 1
                    if progress is not None:
                        try:
                            progress(mc.qualified_name, _i_diff, _n_diff)
                        except Exception:  # noqa: BLE001 - progress is informational and cannot affect a verdict
                            pass
                oid = req["obligation_id"]
                scratch = work / "z3" / oid.replace(":", "_")
                scratch.mkdir(parents=True)
                ob, analysis = z3_binding.verify_confined_detailed(req, scratch_dir=scratch, proposer_paths=proposer_paths)
                obs.append(ob)
                if mc.qualified_name in added_names:
                    # No baseline exists to compare an added callable with. It is verified by binding (above) and
                    # by the differential of the MODIFIED callers that reach it; an unreached one is blocked by
                    # added-unreached. Running a base-vs-post differential on it could only say "not in base tree".
                    continue
                rsr = rs_reqs.get(mc.qualified_name)
                if rsr is not None:  # decided return shape changed: each listed caller's use must still fit (Z3)
                    rscratch = work / "z3rs" / oid.replace(":", "_")
                    rscratch.mkdir(parents=True)
                    obs.append(z3_binding.verify_confined(rsr, scratch_dir=rscratch, proposer_paths=proposer_paths))

                module, func, root = _split_qualified(mc.qualified_name, mc.file_path)
                witnesses = list(analysis.get("witness_inputs", []))
                got = _delta_rel_item(base, post, mc, [d for d in deltas if d.get("symbol") == mc.qualified_name],
                                      _target_version(target_python))
                if got is not None:
                    evidence.append(got[0])
                    witnesses += got[1]
                # review's adequacy gate is waived for THIS callable only by an unconditional delta_rel proof that takes
                # nothing as given (no UF premise, no declared delta). Conditional/none never waives.
                adequacy: dict[str, Any] = {}
                if gate_on and _diff_accepts("adequacy_gate"):
                    adequacy["adequacy_gate"] = True
                if ADEQUACY_PROVED_WAIVER and got is not None and got[0].get("verdict") == "PROVED"\
                        and got[0].get("proof_tier") == "unconditional"\
                        and not got[0].get("assumptions")\
                        and _diff_accepts("adequacy_proved"):
                    adequacy["adequacy_proved"] = f"delta_rel:{mc.qualified_name}"
                seeds = differential.seeds_from_z3(witnesses)
                _own_deltas = [d_ for d_ in deltas if d_.get("symbol") == mc.qualified_name and isinstance(d_.get("predicate"), dict)]
                _rplan = _dnotes = None
                _nd = 0
                if _own_deltas:  # O3: inputs from the delta's domain and from the patch's own changed regions (delta_follow)
                    try:
                        _post_text = (Path(post) / mc.file_path).read_text()
                        _rplan = delta_follow.region_plan((Path(base) / mc.file_path).read_text(), _post_text,
                                                          func, _param_names(mc), _own_deltas, symbol=mc.qualified_name, allow_bytes=True)
                        _dseeds, _dnotes = delta_follow.domain_seeds(_own_deltas, mc.qualified_name, _param_names(mc),
                                                                     allow_bytes=True, source=_post_text, qual=func)
                        _nd = len(_dseeds)
                        seeds = list(seeds) + _dseeds + _rplan.seeds
                    except (OSError, ValueError, SyntaxError, RecursionError):
                        _rplan = _dnotes = None  # follow-ups are an addition; their failure never changes a verdict
                dscratch = _diff_scratch("fn", mc.qualified_name)
                _phases.progress("differential", target=mc.qualified_name, i=_i_diff, n=_n_diff)
                with _phases.timed("differential"):
                    dob = differential.run_differential(
                        base_root=str(base), post_root=str(post), module=module, function=func,
                        proposer_paths=list(proposer_paths), scratch=str(dscratch), import_root=root,
                        extra_sys_path=list(extra_sys_path), target_python=target_python, seeds=seeds,
                        timeout=differential_timeout,
                        constraints=fbk.constraints(mc.qualified_name) if fbk is not None else None,
                        deltas=[d for d in deltas if d.get("symbol") == mc.qualified_name],
                        **adequacy,
                        # design and adversarial review R1b: the tests that reach the target THROUGH its callers (effect reverse call closure)
                        **({"impacted_test_nodes": list(acct.impacted_test_nodes)}
                           if _diff_accepts("impacted_test_nodes") else {}),
                        # exported-guard continuity: exclude matched uncommitted exported guards from the production target's test slice
                        # so they cannot satisfy baseline test reach or inject a fresh-fail REFUTED.
                        **({"exclude_test_files": matched_guard_files}
                           if matched_guard_files and _diff_accepts("exclude_test_files") else {}),
                    )
                _ue = [e for e in acct.unknown_edges if e.target_qualified_name == mc.qualified_name]
                if _ue and getattr(dob, "evidence", None) is not None:  # a differential over a target with unknown callers must say so (a2rest A2-12)
                    _note = (f"{len(_ue)} unknown call edge(s) into {mc.qualified_name} are not explored by this differential: "
                             + "; ".join(f"{e.file_path}:{e.line_number} {e.reason}" for e in _ue[:4]))
                    dob = dataclasses.replace(dob, evidence=BoundedEvidence(
                        dob.evidence.executions, dob.evidence.explored,
                        (dob.evidence.unexplored + " ; " + _note) if dob.evidence.unexplored else _note))
                if _rplan is not None and getattr(dob, "evidence", None) is not None:  # say what the follow-ups explored and did not
                    _ex, _un = delta_follow.account_text(_rplan, _dnotes or [], _nd, _own_deltas)
                    dob = dataclasses.replace(dob, evidence=BoundedEvidence(dob.evidence.executions, dob.evidence.explored + " ; " + _ex,
                                                                (dob.evidence.unexplored + " ; " + _un) if dob.evidence.unexplored else _un))
                obs.append(dob)
                if _rplan is not None:
                    _blk = delta_follow.blocker(_rplan, mc.qualified_name)
                    if _blk is not None:
                        obs.append(_blk)
                _note_explored(mc.qualified_name, dscratch)
                _obs_data = differential.read_observations(str(dscratch)) or {}
                if "executed_post_callables" in _obs_data:  # absent key = unknown = not executed (fail closed)
                    executed_post |= {str(x) for x in _obs_data["executed_post_callables"]}
                if dob.verdict is Verdict.HELD and deferred_guards:
                    # Guard coverage (contract O3): an unsupported raising guard of THIS callable is covered only
                    # by an observed, machine-checkable delta (delta_cover); landing stays conditional on the
                    # deltas-confirmed obligation (human approval of the delta set).
                    observations = differential.read_observations(str(dscratch))
                    for gi, (pos, g) in list(deferred_guards.items()):
                        if g.target_qualified_name != mc.qualified_name and g.caller_qualified_name != mc.qualified_name:
                            continue
                        try:  # early returns before the guard dominate it: identity is prefix AND condition
                            dom = delta_cover.dominating_conditions((Path(post) / g.file_path).read_text(), int(g.line_number))
                        except (OSError, ValueError, TypeError):
                            dom = []
                        cov = delta_cover.guard_coverage(
                            {"kind": g.kind, "side": g.side, "raised_exception": g.raised_exception,
                             "condition_source": g.condition_source, "dominating_conditions": dom},
                            observations, deltas, mc.qualified_name, params=_param_names(mc))
                        if cov.covered:
                            obs[pos] = Obligation(
                                f"guard-covered:{mc.qualified_name}:{g.file_path}:{g.line_number}", mc.qualified_name,
                                "unsupported entry guard is covered by an approved, observed delta", Verdict.HELD,
                                evidence=BoundedEvidence(executions=cov.triggering + cov.agreeing, explored=cov.evidence,
                                                         unexplored=delta_cover.OPEN_SCOPE),
                                provenance=dob.provenance)
                            covered_guard_wheres.add(f"{g.file_path}:{g.line_number}" if g.line_number else str(g.file_path))
                            del deferred_guards[gi]
                # A REMOVED entry guard (precondition deleted) is not history: inputs it used to reject may now pass,
                # the adequacy gate sees only post-side conditions, and the account keeps it as a note. Blocking
                # unless a declared, observed delta explains exactly that guard (delta_cover.removed_guard_coverage).
                def _replay(cand, mc=mc, module=module, func=func, root=root):
                    """A candidate counterexample of the certificate, run through the CONFINED differential as a seed."""
                    if not cand or not cand.get("params"):
                        return None
                    names_ = _param_names(mc)
                    lits_ = {str(i): repr(cand["params"][n_]) for i, n_ in enumerate(names_) if n_ in cand["params"]}
                    seeds_c = differential.seeds_from_z3([{"path_literals": lits_, "n_positional": len(names_), "keywords": []}])
                    try:
                        return differential.run_differential(
                            base_root=str(base), post_root=str(post), module=module, function=func,
                            proposer_paths=list(proposer_paths), scratch=str(_diff_scratch("cert", mc.qualified_name)), import_root=root,
                            extra_sys_path=list(extra_sys_path), target_python=target_python, seeds=seeds_c,
                            timeout=min(float(differential_timeout), 120.0), max_examples=5, max_seeds=len(seeds_c) + 5,
                            deltas=[d_ for d_ in deltas if d_.get("symbol") == mc.qualified_name],
                            **({"exclude_test_files": matched_guard_files}
                               if matched_guard_files and _diff_accepts("exclude_test_files") else {}))
                    except Exception:  # a replay that cannot run proves nothing: the caller names it as not reproduced
                        return None

                _rm = guard_removed.removed_entry_guards(
                    (Path(base) / mc.file_path).read_text(), (Path(post) / mc.file_path).read_text(), func)
                if _rm is None:
                    obs.append(Obligation(f"guard-removed:{mc.qualified_name}", mc.qualified_name,
                                          "no entry guard was removed", Verdict.NOT_DERIVED,
                                          stop_reason=(guard_removed.last_stop() or f"could not locate {func} to compare entry guards")[:300]))
                known = {(getattr(c, "caller_qualified_name", None), (c.condition_source or "").strip())
                         for c in acct.unresolved_constructs
                         if getattr(c, "side", "post") == "pre" and c.kind == "unsupported_entry_guard"}
                for rg in _rm or []:
                    if (mc.qualified_name, rg["cond"]) in known:
                        # the account already lists this exact removed guard as an unresolved pre-side construct
                        # (obligation `unresolved-N`, NOT_DERIVED). An approved delta OBSERVED to explain exactly this
                        # removal (the same identity rule as an unlisted removal) replaces that obligation; anything
                        # broader, weaker or unobserved leaves it blocking.
                        cert_done = False
                        if deltas and dob.verdict is Verdict.HELD:
                            rcov = delta_cover.removed_guard_coverage(
                                rg["cond"], rg["exc"], differential.read_observations(str(dscratch)), deltas,
                                mc.qualified_name, params=_param_names(mc))
                            if rcov.covered:
                                cert = _certificate_for(mc, rg, rcov, base, post, deltas)
                                cob = _removal_obligation(mc, rg, rcov, cert, dob, _replay)
                                cert_done = True
                                if cob.verdict is Verdict.HELD:
                                    for gi, (pos_u, g_u) in list(deferred_guards.items()):
                                        if (getattr(g_u, "side", "post") == "pre" and g_u.caller_qualified_name == mc.qualified_name
                                                and (g_u.condition_source or "").strip() == rg["cond"]):
                                            obs[pos_u] = cob
                                            covered_guard_wheres.add(
                                                f"{g_u.file_path}:{g_u.line_number}" if g_u.line_number else str(g_u.file_path)
                                            )
                                            del deferred_guards[gi]
                                            break
                                else:  # the account's blocker STAYS; the certificate's verdict is added beside it, named
                                    obs.append(cob)
                        if deltas and not cert_done:  # differential not held / not covered: the certificate still ADDS its verdict
                            add_c = _additive_certificate(mc, rg, deltas, base, post, _replay)
                            if add_c is not None:
                                obs.append(add_c)
                        continue
                    pos = len(obs)
                    obs.append(Obligation(
                        f"guard-removed:{mc.qualified_name}:{rg['line']}", mc.qualified_name, "no entry guard was removed",
                        Verdict.NOT_DERIVED,
                        stop_reason=(f"precondition removed: base line {rg['line']} `if {rg['cond']}: raise "
                                     f"{(rg['exc'] or '?').rsplit('.', 1)[-1]}` has no counterpart after the change; "
                                     "inputs it rejected may now proceed")[:400]))
                    cert_done = False
                    if deltas and dob.verdict is Verdict.HELD:
                        rcov = delta_cover.removed_guard_coverage(
                            rg["cond"], rg["exc"], differential.read_observations(str(dscratch)), deltas,
                            mc.qualified_name, params=_param_names(mc))
                        if rcov.covered:
                            cert = _certificate_for(mc, rg, rcov, base, post, deltas)
                            cob = _removal_obligation(mc, rg, rcov, cert, dob, _replay)
                            cert_done = True
                            if cob.verdict is Verdict.HELD:
                                obs[pos] = cob
                                removed_guard_wheres.add(f"{mc.file_path}:{rg['line']}")
                            else:  # the NOT_DERIVED removal blocker STAYS; the certificate's verdict is added beside it
                                obs.append(cob)
                    if deltas and not cert_done:  # differential not held / not covered: the certificate still ADDS its verdict
                        add_c = _additive_certificate(mc, rg, deltas, base, post, _replay)
                        if add_c is not None:
                            obs.append(add_c)
                if fbk is not None:  # review wiring: the exact refuting call, read before 'work' is deleted
                    fbk.note_witness(mc.qualified_name, differential.read_witness(str(dscratch)))
                    pinned = fbk.pinned_obligation(base, post, mc.qualified_name)
                    if pinned is not None:
                        obs.append(pinned)
            # Added callables are listed only in added_callables (A2); requests_from_account appends their binding
            # requests AFTER the modified ones, so the zip above never reaches them: verify each here (binding only;
            # no base exists for a differential, the modified callers that reach it carry that).
            for req in requests[len(acct.modified_callables):]:
                if not req.get("added"):
                    continue
                if req["target_symbol"] in matched_guards:
                    req = dict(req, exported_guard_entry=True, exported_guard_file=matched_guards[req["target_symbol"]].rel)
                scratch = work / "z3" / req["obligation_id"].replace(":", "_")
                scratch.mkdir(parents=True)
                obs.append(z3_binding.verify_confined_detailed(req, scratch_dir=scratch, proposer_paths=proposer_paths)[0])
            for qn, match in sorted(matched_guards.items()):
                gscratch = _diff_scratch("guard", qn)
                obs.append(
                    exported_guard.evaluate_exported_guard(
                        match,
                        base_dir=Path(base_dir),
                        post_dir=Path(post_dir),
                        scratch_dir=gscratch,
                        target_python=target_python,
                        extra_sys_path=extra_sys_path,
                        proposer_paths=proposer_paths,
                        deltas=deltas,
                        deltas_approved=deltas_approved,
                        timeout_per_side=min(exported_guard.MAX_SIDE_TIMEOUT_S, differential_timeout),
                    )
                )
            # A changed module-level CONSTANT has no body to compare: its effect is what every reader now computes.
            # One differential per reader (pre vs post); a reader the effect already modifies was handled above.
            # An added callable is exercised only THROUGH a modified caller's differential (its base side cannot
            # exist). That caller's run must have actually executed inputs; otherwise the helper is dead or
            # unexercised code and must never pass silently.
            ran = {o.obligation_id[len("differential:"):] for o in obs if o.obligation_id.startswith("differential:")
                   and (o.verdict in (Verdict.HELD, Verdict.REFUTED)
                        or (o.verdict is Verdict.UNVERIFIED and "agreeing inputs" in (o.stop_reason or "")))}
            for a in ad.get("added_callables", []):
                callers = {r.get("caller_qualified_name") for r in a.get("reached_from", [])}
                if a.get("reached_from") and not (callers & ran):
                    obs.append(Obligation(
                        f"added-unexercised:{a.get('qualified_name')}", str(a.get("qualified_name")),
                        "added callable is exercised by a differentially checked caller", Verdict.UNVERIFIED,
                        stop_reason=f"added callable {a.get('qualified_name')} is not reached by any differentially "
                                    f"checked caller (callers: {sorted(c for c in callers if c)[:3]})"[:300]))
                elif a.get("reached_from") and a.get("qualified_name") not in executed_post:
                    # static reach is not execution: the call may sit under a branch no generated input takes
                    obs.append(Obligation(
                        f"added-unexercised:{a.get('qualified_name')}", str(a.get("qualified_name")),
                        "added callable is exercised by a differentially checked caller", Verdict.UNVERIFIED,
                        stop_reason=f"added callable {a.get('qualified_name')} was never executed by the differential "
                                    "corpus of its callers (static reach is not execution)"[:300]))
            modified = {mc.qualified_name for mc in acct.modified_callables}
            if docstring_only and base is not None and post is not None:
                doc_other_specs: list[tuple[str, str, str, Path]] = []
                for rel in touched_files:
                    try:
                        mod_tree = ast.parse((Path(post) / rel).read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, SyntaxError):
                        continue
                    mod_name, _ = docstring_check._module_and_root(Path(post), rel)
                    for node in mod_tree.body:
                        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        qn = f"{mod_name}.{node.name}"
                        if qn in modified:
                            continue
                        modified.add(qn)
                        if (
                            docstring_check._STATIC_DOC_CLEAR_SKIPS
                            and node.name in static_clear_.get(mod_name, ())
                        ):
                            continue  # Lever 3 skip may be re-enabled only after a sound proof replaces current static clearance.
                        module, func, root = _split_qualified(qn, rel)
                        doc_other_specs.append((module, func, root, _diff_scratch("doc_other", qn)))
                if doc_other_specs:
                    from concurrent.futures import ThreadPoolExecutor

                    t_doc_other = time.monotonic()
                    budget_s = 180.0
                    deadline = t_doc_other + budget_s

                    def _run_doc_other(spec: tuple[str, str, str, Path]) -> Obligation:
                        module, func, root, dscratch = spec
                        rem = deadline - time.monotonic()
                        if rem <= 0:
                            return Obligation(
                                f"differential:{module}.{func}",
                                f"{module}.{func}",
                                "unmodified module callable checked within budget",
                                Verdict.UNVERIFIED,
                                stop_reason=f"doc_other budget exceeded before start ({budget_s:.0f}s)",
                            )
                        return differential.run_differential(
                            base_root=str(base), post_root=str(post), module=module, function=func,
                            proposer_paths=list(proposer_paths), scratch=str(dscratch), import_root=root,
                            extra_sys_path=list(extra_sys_path), target_python=target_python,
                            max_examples=25, max_seeds=200,
                            require_impacted_slice=False,
                            **({"exclude_test_files": matched_guard_files}
                               if matched_guard_files and _diff_accepts("exclude_test_files") else {}),
                            timeout=max(1.0, min(float(differential_timeout), 30.0, rem)),
                            **({"impacted_test_nodes": list(acct.impacted_test_nodes)}
                               if _diff_accepts("impacted_test_nodes") else {}),
                        )

                    with _phases.timed("differential"):
                        pool = ThreadPoolExecutor(max_workers=min(4, len(doc_other_specs)))
                        futs = [pool.submit(_run_doc_other, sp) for sp in doc_other_specs]
                        budget_hit = False
                        try:
                            for fut in futs:
                                rem = deadline - time.monotonic()
                                if rem <= 0:
                                    budget_hit = True
                                    break
                                dob = fut.result(timeout=rem)
                                obs.append(dob)
                        except TimeoutError:
                            budget_hit = True
                        finally:
                            if budget_hit:
                                for f in futs:
                                    f.cancel()
                            pool.shutdown(wait=True)
                        if budget_hit:
                            elapsed = time.monotonic() - t_doc_other
                            obs.append(Obligation(
                                "docstring-other-budget",
                                ",".join(touched_files) or "*",
                                "unmodified module callables checked within budget",
                                Verdict.UNVERIFIED,
                                stop_reason=f"doc_other budget exceeded: {elapsed:.1f}s > {budget_s:.0f}s",
                            ))
            for c in consts:
                cname = str(c.get("qualified_name"))
                readers = {}
                for r in c.get("readers", []):
                    readers.setdefault(r.get("qualified_name"), r)
                if not readers:
                    obs.append(Obligation(f"constant-unread:{cname}", cname, "changed constant has verified readers",
                                          Verdict.UNVERIFIED,
                                          stop_reason=f"{cname} changed; no in-repo reader found (external readers unexplored)"[:300]))
                for rq, r in readers.items():
                    if rq in modified:
                        continue
                    fp = str(r.get("file_path"))
                    if fp.split("/")[-1].startswith("test_") or "tests" in fp.split("/")[:-1]:
                        continue  # test functions are executed by the impacted-test slice, not differentially
                    module, func, root = _split_qualified(str(rq), fp)
                    if not func or str(rq) == module:  # module-level read: nothing callable to execute
                        obs.append(Obligation(f"constant-reader:{cname}:{rq}", str(rq), "reader behaviour preserved",
                                              Verdict.UNVERIFIED,
                                              stop_reason=f"module-level read of {cname} at {r.get('file_path')}:{r.get('line_number')}"[:300]))
                        continue
                    dscratch = _diff_scratch("const", str(rq))
                    _phases.progress("differential", target=str(rq))  # this call site is about to run (no i/n: the count is not known up front)
                    with _phases.timed("differential"):
                        ob = differential.run_differential(
                            base_root=str(base), post_root=str(post), module=module, function=func,
                            proposer_paths=list(proposer_paths), scratch=str(dscratch), import_root=root,
                            extra_sys_path=list(extra_sys_path), target_python=target_python, seeds=[],
                            timeout=differential_timeout, deltas=[d for d in deltas if d.get("symbol") == rq],
                            **({"exclude_test_files": matched_guard_files}
                               if matched_guard_files and _diff_accepts("exclude_test_files") else {}),
                            # the same hooks the callable path has (feedback constraints, adequacy gate): a changed
                            # constant is verified through its readers, so the readers get the same discipline
                            constraints=fbk.constraints(str(rq)) if fbk is not None else None,
                            **({"adequacy_gate": True} if gate_on and _diff_accepts("adequacy_gate") else {}),
                            **({"impacted_test_nodes": list(acct.impacted_test_nodes)}
                               if _diff_accepts("impacted_test_nodes") else {}))
                    obs.append(ob)
                    if fbk is not None:
                        fbk.note_witness(str(rq), differential.read_witness(str(dscratch)))
                        pinned_r = fbk.pinned_obligation(base, post, str(rq))
                        if pinned_r is not None:
                            obs.append(pinned_r)
                    modified.add(str(rq))  # a delta may legitimately name a reader of the changed constant
            for d in deltas:  # a claim about code the effect does not modify can never be observed
                if d.get("symbol") not in modified:
                    obs.append(Obligation(f"delta-target:{d.get('id')}", str(d.get("symbol")),
                                          "declared delta targets a modified callable", Verdict.UNVERIFIED,
                                          stop_reason=f"delta {d.get('id')} names {d.get('symbol')}, which the effect does not modify"[:300]))
            for p in acct.side_effect_primitive_delta:
                obs.append(Obligation(f"effect-confinement:{p.qualified_name}:{p.primitive}", p.qualified_name,
                                      "no external side-effect primitive introduced", Verdict.REFUTED,
                                      witness=f"{p.file_path}:{p.line_number} adds {p.primitive} ({p.delta})"))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if (covered_guard_wheres or removed_guard_wheres) and fbk is not None and hasattr(fbk, "covered_construct_ids"):
            drop_fb = fbk.covered_construct_ids(covered_guard_wheres, removed_guard_wheres)
            if drop_fb:
                obs = [o for o in obs if o.obligation_id not in drop_fb]
        bound = ("signature_binding", "differential:", "constant-reader", "guard-covered", "guard-removal-covered",
                 "guard-removed", "effect-confinement")
        obs = [dataclasses.replace(o, account_bound=True) if o.obligation_id.startswith(bound) else o for o in obs]
        return ObligationSet(tuple(obs), tuple(evidence))

    def derive(repo: Path, eff: ProposedEffect) -> ObligationSet:
        """Legacy entry (kept for unmigrated callers): seals the base and post trees through hostio, builds the account
        through effect.api (the only L2 surface L3 may use) and runs the same core the ObligationApi runs."""
        repo = Path(repo).resolve()
        deltas = list(getattr(eff, "deltas", ()) or ())  # proposer claims; runtime.DeltaEffect carries them
        if not eff.unified_diff.strip():
            return derive_core(touched_files=(), deltas=deltas, acct=None, ad={}, fbk=None, base_dir=None, post_dir=None,
                               has_diff=False)
        from .contract.identities import new_run_id
        from .effect.api import EffectService
        from .hostio.snapshot import LocalSnapshotService

        trees = Path(tempfile.mkdtemp(prefix="hlith-derive-trees-"))
        try:
            patch = eff.unified_diff.encode("utf-8", errors="surrogateescape")
            try:
                with _phases.timed("account"):
                    svc = LocalSnapshotService(root=trees)
                    base = svc.seal_base(repo)
                    post = svc.reconstruct_post(base, patch)
                    built = EffectService().build(new_run_id(), base, post, patch)
                    acct = built.detail
                    if acct is None:
                        raise ValueError("the effect engine produced no account")
            except Exception as e:  # an account that cannot be built is a refusal, never a crash or a pass
                return ObligationSet((Obligation("account-failed", "*", "effect is derivable", Verdict.NOT_DERIVED,
                                                 stop_reason=f"effect account could not be built: {type(e).__name__}: {e}"[:300]),))
            ad = acct.to_dict()
            fbk = feedback(repo, ad) if feedback is not None else None
            return derive_core(touched_files=tuple(eff.touched_files), deltas=deltas, acct=acct, ad=ad, fbk=fbk,
                               base_dir=base.path, post_dir=post.path)
        finally:
            shutil.rmtree(trees, ignore_errors=True)

    derive.core = derive_core  # the obligation API calls this with a supplied account view and sealed trees
    return derive
