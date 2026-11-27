# SPDX-License-Identifier: Apache-2.0
"""L3 matching, confined two-sided pytest execution, and intended-delta conflict check for exported pre-guards.

Maintainer binding invariants enforced structurally here:
  * An exported guard obligation NEVER emits ``Verdict.REFUTED`` and NEVER creates a witness.
    Only the normal target differential may produce ``REFUTED`` with its existing witness/replay/export contract.
  * Matching requires exact SHA-256 + byte equality against a host-authenticated ``ExportedGuardCatalog`` entry
    for the exact ``base_tree_oid`` and ``expect == "pre"`` — never trusting file comments or headers.
  * Execution runs the exact canonical guard bytes under existing Landlock + user-namespace confinement separately
    against sealed ``base`` and ``post`` snapshots with ``HLITH_WITNESS_ROOT``, no network, isolated env, no
    ``hlith`` import, and timeout <= 60s/side (never falling back to unconfined execution).
  * Base pass is necessary for ``HELD``; any base failure, post failure, import/collection/runner/env/sandbox error,
    or approved intended-delta conflict produces ``Verdict.UNVERIFIED`` with a classified ``stop_reason``.
  * Guard-only effects (no non-guard production change) emit an explicit ``guard-alone`` ``NOT_DERIVED`` blocker.
"""

from __future__ import annotations

import ast
import hashlib
import os
import posixpath
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..contract import codec
from ..contract.effects import EffectAccount
from ..contract.guards import AuthenticatedExportedGuard, ExportedGuardCatalog, MAX_GUARD_BYTES
from ..contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from .closure_gate import is_test_path
from .source import TreeIndex

MAX_SIDE_TIMEOUT_S = 60.0
_PYTEST_RUNNER = (
    "import sys\n"
    "sys.modules['hlith'] = None\n"
    "import pytest\n"
    "raise SystemExit(pytest.main(sys.argv[1:]))\n"
)
_WHERE_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)$")


@dataclass(frozen=True)
class MatchedExportedGuard:
    """One strictly verified match between an unreached added callable in ``post`` and a host catalog entry."""

    guard_qn: str
    rel: str
    entry: AuthenticatedExportedGuard


@dataclass(frozen=True)
class SideRun:
    """Outcome of running the canonical guard under confinement against one sealed snapshot."""

    side: str
    classification: str  # passed | assertion_failure | import_error | collection_error | timeout | missing_pytest | sandbox | environment_error | runner_error
    returncode: int | None
    detail: str
    profile_sha256: str = ""
    proposer_paths_readable: bool = True


def _normalised_rel(rel: str) -> str | None:
    if not rel or "\x00" in rel or "\\" in rel:
        return None
    norm = posixpath.normpath(rel)
    if norm in ("", ".", "..") or norm.startswith("../") or norm.startswith("/"):
        return None
    return norm


def _unknown_file(where: str) -> str:
    m = _WHERE_RE.match(where)
    return m.group("file") if m else where


def _read_strict_post_file(base_dir: Path, post_dir: Path, rel: str) -> bytes | None:
    """Read ``post_dir / rel`` iff absent from ``base_dir``, no symlinks on any path component, regular UTF-8 <= 1 MiB."""
    norm = _normalised_rel(rel)
    if norm is None or not is_test_path(norm):
        return None
    # Must be absent from base (including not a symlink).
    try:
        os.lstat(base_dir / norm)
        return None
    except FileNotFoundError:
        pass
    except OSError:
        return None

    # Walk every component under post_dir without following symlinks.
    parts = norm.split("/")
    cur = post_dir
    for part in parts[:-1]:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return None

    target = cur / parts[-1]
    try:
        st = os.lstat(target)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None
    if not (0 < st.st_size <= MAX_GUARD_BYTES):
        return None
    try:
        post_resolved = post_dir.resolve(strict=True)
        target_resolved = target.resolve(strict=True)
    except OSError:
        return None
    if post_resolved not in target_resolved.parents:
        return None

    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(MAX_GUARD_BYTES + 1)
    except OSError:
        return None
    if not (0 < len(raw) <= MAX_GUARD_BYTES):
        return None
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return raw


def _file_has_only_guard_callable(
    raw: bytes, rel: str, guard_qn: str, *, allowed_names: frozenset[str] = frozenset({"test_recorded_pre_behavior"})
) -> bool:
    """Confirm the exact file AST defines solely one canonical guard function matching ``guard_qn``."""
    try:
        tree = ast.parse(raw.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
        return False
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        return False
    fn = tree.body[0]
    if fn.name not in allowed_names:
        return False
    mod_name = TreeIndex.module_name(rel)
    return guard_qn == f"{mod_name}.{fn.name}"


_GUARD_SHAPED_NAMES = frozenset({"test_recorded_pre_behavior", "test_recorded_post_behavior"})


def guard_shaped_added_test_files(
    account: EffectAccount | None,
    facts: Any,
    base_dir: Path,
    post_dir: Path,
) -> tuple[str, ...]:
    """Narrow fail-closed set of newly added guard-shaped test files (solely ``test_recorded_{pre,post}_behavior``).

    Excluded from the production target's differential test slice so unauthenticated, altered, or ``--expect post``
    guard-shaped files cannot leak a misleading fresh-test REFUTED or fabricate baseline test reach. Never grants
    continuity or exempts arbitrary added tests: unmatched files still receive ordinary ``added-unreached`` NOT_DERIVED.
    """
    if account is None:
        return ()
    post_tree = TreeIndex(post_dir)
    found: set[str] = set()
    for rec in getattr(facts, "added", ()) or ():
        if rec.get("reached_from"):
            continue
        qn = str(rec.get("qualified_name") or "")
        if not qn or qn not in account.added_callables:
            continue
        loc = post_tree.locate(qn)
        if loc is None:
            continue
        rel = _normalised_rel(loc.rel)
        if rel is None:
            continue
        raw = _read_strict_post_file(base_dir, post_dir, rel)
        if raw is None:
            continue
        if _file_has_only_guard_callable(raw, rel, qn, allowed_names=_GUARD_SHAPED_NAMES):
            found.add(rel)
    return tuple(sorted(found))


def match_exported_guards(
    account: EffectAccount | None,
    facts: Any,
    base_dir: Path,
    post_dir: Path,
    catalog: ExportedGuardCatalog | None,
) -> dict[str, MatchedExportedGuard]:
    """Return ``guard_qn -> MatchedExportedGuard`` for every unreached added callable satisfying all strict preconditions."""
    if account is None or catalog is None or not catalog.entries:
        return {}
    if catalog.base_tree_oid is not None and catalog.base_tree_oid != account.base_tree_oid:
        return {}

    base_tree = TreeIndex(base_dir)
    post_tree = TreeIndex(post_dir)

    # Precompute files with other callables, constants, primitives, unknowns, or L3 constructs.
    all_callables = tuple(sorted({*account.modified_callables, *account.added_callables, *account.removed_callables}))
    callable_files: dict[str, str] = {}
    for q in all_callables:
        loc = post_tree.locate(q) or base_tree.locate(q)
        if loc is not None:
            callable_files[q] = loc.rel

    const_files = {m.file for m in account.modified_constants}
    prim_files = {p.file for p in account.primitives}
    unknown_files = {_unknown_file(u.where) for u in account.unknowns}
    construct_files = {str(getattr(c, "file_path", "") or "") for c in (getattr(facts, "unresolved_constructs", None) or ())}

    matched: dict[str, MatchedExportedGuard] = {}
    for rec in getattr(facts, "added", ()) or ():
        if rec.get("reached_from"):
            continue
        qn = str(rec.get("qualified_name") or "")
        if not qn or qn not in account.added_callables:
            continue
        loc = post_tree.locate(qn)
        if loc is None:
            continue
        rel = _normalised_rel(loc.rel)
        if rel is None:
            continue
        raw = _read_strict_post_file(base_dir, post_dir, rel)
        if raw is None:
            continue
        entry = catalog.match_bytes(raw)
        if entry is None:
            continue
        if entry.expect != "pre" or entry.base_tree_oid != account.base_tree_oid:
            continue
        if not _file_has_only_guard_callable(raw, rel, qn):
            continue
        # Strict single-callable isolation in EffectAccount and L3 facts.
        mod_name = TreeIndex.module_name(rel)
        if any(
            other != qn and (
                callable_files.get(other) == rel
                or other == mod_name
                or other.startswith(mod_name + ".")
            )
            for other in all_callables
        ):
            continue
        if rel in const_files or rel in prim_files or rel in unknown_files or rel in construct_files:
            continue
        # Target symbol must resolve in post tree.
        if post_tree.locate(entry.target_symbol) is None:
            continue
        matched[qn] = MatchedExportedGuard(guard_qn=qn, rel=rel, entry=entry)
    return matched


def _classify_pytest_output(returncode: int, stdout: str, stderr: str) -> tuple[str, str]:
    combined = f"{stdout}\n{stderr}".strip()
    tail = " | ".join(ln.strip() for ln in combined.splitlines()[-6:] if ln.strip())[:240]
    if returncode == 0:
        if "1 passed" in stdout and "failed" not in stdout.lower() and "error" not in stdout.lower():
            return "passed", tail or "1 passed"
        return "collection_error", f"pytest exited 0 without confirming 1 passed test: {tail}"
    if "No module named 'pytest'" in combined or 'No module named "pytest"' in combined:
        return "missing_pytest", tail or "pytest is not installed in the target interpreter"
    if any(tok in combined for tok in ("confine_exec", "landlock", "Operation not permitted", "PermissionError")):
        if "AssertionError" not in combined:
            return "sandbox", tail or f"confinement denied execution (exit {returncode})"
    if returncode == 2:
        if any(tok in combined for tok in ("ImportError", "ModuleNotFoundError", "SyntaxError")):
            return "import_error", tail or f"pytest import/collection failed (exit {returncode})"
        return "collection_error", tail or f"pytest collection failed (exit {returncode})"
    if returncode in (3, 4, 5):
        return "collection_error" if returncode == 5 else "runner_error", tail or f"pytest runner exit {returncode}"
    if returncode == 1:
        if "AssertionError" in combined and "expected pre " in combined:
            return "assertion_failure", tail or "exported pre-guard assertion failed"
        if any(tok in combined for tok in ("ImportError", "ModuleNotFoundError", "SyntaxError")):
            return "import_error", tail or "import failed inside exported pre-guard"
        if "AssertionError" in combined:
            return "assertion_failure", tail or "assertion failed inside exported pre-guard"
        return "runner_error", tail or f"pytest failed (exit {returncode})"
    return "runner_error", tail or f"pytest exited {returncode}"


def _run_guard_side(
    *,
    side: str,
    side_root: Path,
    match: MatchedExportedGuard,
    side_scratch: Path,
    target_python: str | None,
    extra_sys_path: Sequence[str],
    proposer_paths: Sequence[str],
    timeout_s: float,
) -> SideRun:
    from .. import differential
    from ..hostio.confinement import (
        ConfinementBoundaryError,
        GrantError,
        Profile,
        raise_if_confinement_boundary,
        run_confined,
    )
    from ..hostio.interpreter import interpreter_prefixes
    from .z3_binding import measure_proposer_readable

    py = target_python or sys.executable
    try:
        resolved_py = differential.resolve_target_python(py)
        prefixes = interpreter_prefixes(py) if py != sys.executable else []
    except Exception as exc:  # noqa: BLE001
        return SideRun(side, "environment_error", None, f"target interpreter unavailable: {type(exc).__name__}: {str(exc)[:180]}")

    side_scratch.mkdir(parents=True, exist_ok=True)
    side_tmp = side_scratch / "tmp"
    side_tmp.mkdir(parents=True, exist_ok=True)
    guard_name = Path(match.rel).name
    if not guard_name.endswith(".py") or "/" in guard_name or "\\" in guard_name or guard_name in (".py", "..py"):
        guard_name = "test_hlith_exported_guard.py"
    guard_file = side_scratch / guard_name
    guard_file.write_bytes(match.entry.canonical_bytes)

    ro_grants = tuple(
        dict.fromkeys([
            str(side_root.resolve()),
            *[str(Path(x).resolve()) for x in extra_sys_path],
            *prefixes,
        ])
    )
    rw_grants = (str(side_scratch.resolve()),)

    non_system_grants = [
        p for p in dict.fromkeys([*ro_grants, *rw_grants])
        if not any(p == t or p.startswith(t + "/") for t in differential._SYSTEM_TREES)
    ]
    special = differential._special_file(non_system_grants)
    if special is not None:
        return SideRun(side, "sandbox", None, f"confinement refused special file: {special}")

    profile = Profile(ro=ro_grants, rw=rw_grants, net=False)
    try:
        proposer_readable = measure_proposer_readable(proposer_paths, profile)
    except ConfinementBoundaryError:
        raise
    except GrantError as exc:
        return SideRun(side, "sandbox", None, f"confinement refused grant: {str(exc)[:180]}", profile.sha256, True)
    except Exception as exc:  # noqa: BLE001
        return SideRun(side, "sandbox", None, f"proposer blindness check failed: {type(exc).__name__}: {str(exc)[:180]}", profile.sha256, True)

    if proposer_readable:
        return SideRun(side, "sandbox", None, "proposer paths readable inside guard confinement profile", profile.sha256, True)

    argv = [
        resolved_py, "-I", "-B", "-c", _PYTEST_RUNNER,
        "--noconftest",
        "-o", "addopts=",
        "-p", "no:cacheprovider",
        "-q", "--tb=short",
        "--basetemp", str(side_tmp),
        str(guard_file),
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(side_tmp),
        "TMPDIR": str(side_tmp),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "HLITH_WITNESS_ROOT": str(side_root.resolve()),
    }
    bounded_timeout = min(MAX_SIDE_TIMEOUT_S, max(5.0, float(timeout_s)))
    try:
        cp = run_confined(argv, profile, cwd=str(side_scratch.resolve()), timeout=bounded_timeout, env=env)
        raise_if_confinement_boundary(cp)
    except ConfinementBoundaryError:
        raise
    except subprocess.TimeoutExpired:
        return SideRun(side, "timeout", None, f"{side} guard execution exceeded {bounded_timeout:.0f}s timeout", profile.sha256, False)
    except GrantError as exc:
        return SideRun(side, "sandbox", None, f"confinement refused guard execution: {str(exc)[:180]}", profile.sha256, False)
    except OSError as exc:
        return SideRun(side, "environment_error", None, f"guard runner launch failed: {type(exc).__name__}: {str(exc)[:180]}", profile.sha256, False)

    cls, detail = _classify_pytest_output(cp.returncode, cp.stdout or "", cp.stderr or "")
    return SideRun(side, cls, cp.returncode, detail, profile.sha256, False)


def _param_names_for(tree: TreeIndex, qualified_name: str) -> list[str]:
    loc = tree.locate(qualified_name)
    if loc is None or not isinstance(loc.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    args = loc.node.args
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if loc.chain and names and names[0] in ("self", "cls"):
        return names[1:]
    return names


def _expected_agrees_with_pre(expected: Mapping[str, Any], pre: Mapping[str, Any], bound: Mapping[str, Any]) -> bool:
    kind = expected.get("kind")
    if kind == "returns":
        return pre.get("k") == "ret" and pre.get("r") == expected.get("value_repr")
    if kind == "raises":
        return pre.get("k") == "exc" and pre.get("t") == expected.get("exc_type")
    if kind == "returns_expr":
        if pre.get("k") != "ret":
            return False
        expr = expected.get("expr")
        if not isinstance(expr, str):
            return False
        try:
            from .. import expected_expr

            val = expected_expr.evaluate_expected_expr(expr, dict(bound))
            return pre.get("r") == repr(val)
        except Exception:  # noqa: BLE001
            return False
    return False


def _conflicting_approved_delta_ids(
    entry: AuthenticatedExportedGuard,
    deltas: Sequence[Mapping[str, Any]],
    *,
    deltas_approved: bool,
    base_dir: Path,
    post_dir: Path,
    post_passed: bool,
) -> list[str]:
    """Return ids of approved deltas targeting ``entry.target_symbol`` that conflict with this pre-guard."""
    if not deltas_approved or not deltas:
        return []
    from .. import differential

    try:
        wc = entry.witness_call_dict()
    except (ValueError, TypeError):
        return []
    args = codec.decode_call_values(wc.get("args") or [])
    kwargs = codec.decode_call_values(wc.get("kwargs") or {})
    pre = wc.get("pre") if isinstance(wc.get("pre"), dict) else {}
    param_names = _param_names_for(TreeIndex(post_dir), entry.target_symbol) or _param_names_for(TreeIndex(base_dir), entry.target_symbol)
    bound = dict(zip(param_names, args))
    if isinstance(kwargs, dict):
        bound.update(kwargs)

    conflicts: list[str] = []
    for d in deltas:
        if not isinstance(d, Mapping) or d.get("symbol") != entry.target_symbol:
            continue
        did = str(d.get("id") or "<unnamed-delta>")
        pred = d.get("predicate")
        if isinstance(pred, Mapping):
            try:
                matched = bool(differential._delta_predicate(dict(pred), args, kwargs, param_names))
            except Exception:  # noqa: BLE001
                matched = False
            if not matched:
                continue
            exp = d.get("expected")
            if not isinstance(exp, Mapping) or not _expected_agrees_with_pre(exp, pre, bound) or not post_passed:
                conflicts.append(did)
        elif not post_passed:
            conflicts.append(did)
    return sorted(set(conflicts))


def _replay_post_failure_evidence(
    entry: AuthenticatedExportedGuard,
    *,
    base_dir: Path,
    post_dir: Path,
    extra_sys_path: Sequence[str],
    target_python: str | None,
    timeout_s: float,
) -> str:
    """Evidence-only independent witness replay on post failure; NEVER creates REFUTED."""
    from .. import differential

    try:
        wc = codec.decode_call_values(entry.witness_call_dict())
        rep = differential.replay_witness(
            wc,
            str(base_dir),
            str(post_dir),
            import_root=entry.import_root,
            extra_sys_path=extra_sys_path,
            python=target_python,
            timeout=min(30.0, max(5.0, float(timeout_s))),
            confined=True,
        )
        reproduced = bool(rep.get("reproduced")) if isinstance(rep, dict) else False
        replayable = bool(rep.get("replayable")) if isinstance(rep, dict) else False
        return f"source witness replay (evidence only, non-refuting): replayable={replayable}, reproduced={reproduced}"
    except Exception as exc:  # noqa: BLE001
        return f"source witness replay (evidence only, non-refuting): unavailable ({type(exc).__name__})"


def evaluate_exported_guard(
    match: MatchedExportedGuard,
    *,
    base_dir: Path,
    post_dir: Path,
    scratch_dir: Path,
    target_python: str | None,
    extra_sys_path: Sequence[str],
    proposer_paths: Sequence[str],
    deltas: Sequence[Mapping[str, Any]] = (),
    deltas_approved: bool = False,
    timeout_per_side: float = MAX_SIDE_TIMEOUT_S,
) -> Obligation:
    """Execute one matched exported pre-guard confined on sealed base and post; return HELD or UNVERIFIED (never REFUTED)."""
    entry = match.entry
    ob_id = f"exported-guard:{match.rel}:{entry.target_symbol}"
    claim = f"provenance-bound exported pre-guard {match.rel} passes confined on base and post for {entry.target_symbol}"
    checker_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    base_run = _run_guard_side(
        side="base",
        side_root=base_dir,
        match=match,
        side_scratch=scratch_dir / "base",
        target_python=target_python,
        extra_sys_path=extra_sys_path,
        proposer_paths=proposer_paths,
        timeout_s=timeout_per_side,
    )
    post_run = _run_guard_side(
        side="post",
        side_root=post_dir,
        match=match,
        side_scratch=scratch_dir / "post",
        target_python=target_python,
        extra_sys_path=extra_sys_path,
        proposer_paths=proposer_paths,
        timeout_s=timeout_per_side,
    )

    combined_profile_sha = hashlib.sha256(f"{base_run.profile_sha256}:{post_run.profile_sha256}".encode("ascii")).hexdigest()
    any_proposer_readable = base_run.proposer_paths_readable or post_run.proposer_paths_readable
    clean_exit = 0 if (base_run.classification == "passed" and post_run.classification == "passed" and not any_proposer_readable) else 1
    provenance = CheckProvenance(
        checker_id="hlith.obligation.exported_guard",
        checker_sha256=checker_sha,
        confined=True,
        proposer_paths_readable=any_proposer_readable,
        profile_sha256=combined_profile_sha,
        exit_code=clean_exit,
    )

    replay_note = ""
    if base_run.classification == "passed" and post_run.classification == "assertion_failure":
        replay_note = _replay_post_failure_evidence(
            entry,
            base_dir=base_dir,
            post_dir=post_dir,
            extra_sys_path=extra_sys_path,
            target_python=target_python,
            timeout_s=timeout_per_side,
        )

    explored_parts = [
        f"source_run_id={entry.source_run_id}",
        f"source_obligation_id={entry.source_obligation_id}",
        f"canonical_sha256={entry.canonical_sha256}",
        f"base={base_run.classification} (rc={base_run.returncode})",
        f"post={post_run.classification} (rc={post_run.returncode})",
    ]
    if replay_note:
        explored_parts.append(replay_note)
    evidence = BoundedEvidence(
        executions=2,
        explored="; ".join(explored_parts)[:2000],
        unexplored=(
            f"single recorded pre-guard call for {entry.target_symbol} only; does not certify the rest of "
            f"{entry.target_symbol}'s domain, baseline test reach, or any other callable"
        ),
    )

    conflicts = _conflicting_approved_delta_ids(
        entry,
        deltas,
        deltas_approved=deltas_approved,
        base_dir=base_dir,
        post_dir=post_dir,
        post_passed=(post_run.classification == "passed"),
    )

    # Binding verdict rules: NEVER Verdict.REFUTED.
    if any_proposer_readable:
        return Obligation(
            ob_id,
            match.guard_qn,
            claim,
            Verdict.UNVERIFIED,
            evidence=evidence,
            provenance=provenance,
            stop_reason=(
                f"exported-guard confinement failed proposer blindness check "
                f"(base={base_run.classification}: {base_run.detail}; post={post_run.classification}: {post_run.detail})"
            )[:400],
        )

    if base_run.classification != "passed":
        return Obligation(
            ob_id,
            match.guard_qn,
            claim,
            Verdict.UNVERIFIED,
            evidence=evidence,
            provenance=provenance,
            stop_reason=(
                f"exported-guard base run failed ({base_run.classification}; base pass is required): {base_run.detail}"
            )[:400],
        )

    if conflicts:
        return Obligation(
            ob_id,
            match.guard_qn,
            claim,
            Verdict.UNVERIFIED,
            evidence=evidence,
            provenance=provenance,
            stop_reason=(
                f"intended-delta/guard conflict: approved delta(s) {', '.join(conflicts)} for {entry.target_symbol} "
                f"conflict with exported pre-guard {match.rel} (post={post_run.classification}); "
                "normal target obligations decide independently"
            )[:400],
        )

    if post_run.classification != "passed":
        suffix = f"; {replay_note}" if replay_note else ""
        return Obligation(
            ob_id,
            match.guard_qn,
            claim,
            Verdict.UNVERIFIED,
            evidence=evidence,
            provenance=provenance,
            stop_reason=(
                f"exported-guard post run failed ({post_run.classification}; guard failure alone does not refute): "
                f"{post_run.detail}{suffix}"
            )[:400],
        )

    return Obligation(
        ob_id,
        match.guard_qn,
        claim,
        Verdict.HELD,
        evidence=evidence,
        provenance=provenance,
    )


def guard_alone_obligation(
    matched_guards: Mapping[str, MatchedExportedGuard],
    *,
    modified_callables: Sequence[Any],
    added_callables: Sequence[Mapping[str, Any]],
    deleted_callables: Sequence[Any],
    modified_constants: Sequence[Any],
    modified_class_attributes: Sequence[Any],
    touched_files: Sequence[str],
) -> Obligation | None:
    """Emit a NOT_DERIVED blocker when the patch contains only uncommitted exported guard files (no production change)."""
    if not matched_guards:
        return None
    guard_qns = set(matched_guards)
    guard_files = {m.rel for m in matched_guards.values()}
    has_non_guard_callable = bool(
        modified_callables
        or deleted_callables
        or modified_constants
        or modified_class_attributes
        or any(str(a.get("qualified_name") or "") not in guard_qns for a in added_callables)
    )
    if has_non_guard_callable:
        return None
    listed = ", ".join(sorted(guard_files)[:4])
    return Obligation(
        "guard-alone",
        "*",
        "patch includes a verified non-guard change beyond uncommitted exported guard file(s)",
        Verdict.NOT_DERIVED,
        stop_reason=(
            f"guard-alone: patch modifies only uncommitted exported guard file(s) ({listed}) with no non-guard "
            "production change; exported guards cannot manufacture a full HELD on test-only patches"
        )[:400],
    )


__all__ = [
    "MAX_SIDE_TIMEOUT_S",
    "MatchedExportedGuard",
    "SideRun",
    "evaluate_exported_guard",
    "guard_alone_obligation",
    "guard_shaped_added_test_files",
    "match_exported_guards",
]
