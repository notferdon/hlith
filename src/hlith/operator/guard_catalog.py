# SPDX-License-Identifier: Apache-2.0
"""Read-only host catalog builder for uncommitted exported pre-guard continuity.

Reads validated ``RunState.FINISHED`` runs from HostState for the SAME ``repo_identity`` and exact ``base_tree_oid``,
deterministically regenerates canonical ``--expect pre`` guard bytes via ``witness_export.build_pytest_source``, and
never reads the working tree, never trusts file comments, and never mutates or creates store paths.

Any store error, malformed record, symlink, or bound overflow fails closed (skipping that entry or returning
``EMPTY_GUARD_CATALOG``), never crashing ``hlith check`` or trusting extra files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from ..contract.guards import (
    EMPTY_GUARD_CATALOG,
    MAX_CATALOG_ENTRIES,
    MAX_CATALOG_RUN_DIRS,
    MAX_CATALOG_TOTAL_BYTES,
    MAX_GUARD_BYTES,
    AuthenticatedExportedGuard,
    ExportedGuardCatalog,
)
from ..contract.identities import RunId, TreeOid, run_id as validate_run_id, sha256_hex, tree_oid as validate_tree_oid
from ..contract.witness import NotExportable, record_for_export
from ..hostio.integrity import HostIntegrityError, safe_path_component
from . import store
from .witness_export import build_pytest_source

_RUN_DIR_RE = re.compile(r"^run-[0-9a-f]{12}$")
_COMMIT_HEX_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def _is_safe_real_dir(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def _is_safe_regular_file(path: Path, *, max_bytes: int) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and 0 < st.st_size <= max_bytes


def _existing_runs_root(host_state: Any, repo_identity: str) -> Path | None:
    """Resolve ``<state_root>/repositories/<repo_identity>/runs`` strictly read-only (never creates directories)."""
    try:
        ident = safe_path_component(repo_identity, label="repo_identity")
    except HostIntegrityError:
        return None
    raw_root = getattr(host_state, "_root", None)
    if raw_root is None:
        inner = getattr(host_state, "_host", None)
        raw_root = getattr(inner, "_root", None) if inner is not None else None
    if raw_root is None:
        return None
    root = Path(raw_root)
    repos_dir = root / "repositories"
    repo_dir = repos_dir / ident
    runs_dir = repo_dir / "runs"
    for candidate in (root, repos_dir, repo_dir, runs_dir):
        if not _is_safe_real_dir(candidate):
            return None
    try:
        resolved_repos = repos_dir.resolve(strict=True)
        resolved_runs = runs_dir.resolve(strict=True)
    except OSError:
        return None
    if resolved_repos not in resolved_runs.parents:
        return None
    return resolved_runs


def _bounded_run_dirs(runs_dir: Path, *, max_dirs: int = MAX_CATALOG_RUN_DIRS) -> list[Path]:
    """Return at most ``max_dirs`` real ``run-<12hex>`` subdirectories in deterministic newest-first order."""
    found: list[tuple[int, str, Path]] = []
    try:
        with os.scandir(runs_dir) as entries:
            for ent in entries:
                if not _RUN_DIR_RE.fullmatch(ent.name):
                    continue
                try:
                    st = ent.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    continue
                found.append((int(st.st_mtime_ns), ent.name, runs_dir / ent.name))
    except OSError:
        return []
    found.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [path for _, _, path in found[:max_dirs]]


def _extract_entries_from_run(
    run_dir: Path,
    *,
    repo_identity: str,
    base_tree_oid: TreeOid,
    runs_resolved: Path,
) -> list[AuthenticatedExportedGuard]:
    try:
        run_resolved = run_dir.resolve(strict=True)
    except OSError:
        return []
    if run_resolved.parent != runs_resolved:
        return []
    receipt_path = run_dir / store.RECEIPT
    artifact_path = run_dir / store.ARTIFACT
    if not _is_safe_regular_file(receipt_path, max_bytes=store.MAX_BYTES):
        return []
    if not _is_safe_regular_file(artifact_path, max_bytes=store.MAX_BYTES):
        return []

    view = store.read_run(run_dir)
    if view.state is not store.RunState.FINISHED or view.receipt is None or view.artifact is None:
        return []
    if view.receipt.repo_identity != repo_identity:
        return []
    art = view.artifact
    run_info = art.get("run")
    if not isinstance(run_info, dict):
        return []
    try:
        source_run_id = validate_run_id(str(view.receipt.run.run_id))
    except ValueError:
        return []
    if run_dir.name != str(source_run_id) or run_info.get("run_id") != str(source_run_id):
        return []

    raw_base_tree = run_info.get("base_tree_oid")
    raw_post_tree = run_info.get("post_tree_oid")
    if not isinstance(raw_base_tree, str) or not isinstance(raw_post_tree, str):
        return []
    try:
        art_base_tree = validate_tree_oid(raw_base_tree)
        art_post_tree = validate_tree_oid(raw_post_tree)
    except ValueError:
        return []
    if art_base_tree != base_tree_oid:
        return []

    replay_ctx = run_info.get("replay_context")
    if not isinstance(replay_ctx, dict):
        return []
    ctx_base = replay_ctx.get("base")
    if not isinstance(ctx_base, dict):
        return []
    raw_commit = ctx_base.get("commit")
    raw_ctx_tree = ctx_base.get("tree_oid")
    if not isinstance(raw_commit, str) or not _COMMIT_HEX_RE.fullmatch(raw_commit):
        return []
    if not isinstance(raw_ctx_tree, str):
        return []
    try:
        ctx_tree = validate_tree_oid(raw_ctx_tree)
    except ValueError:
        return []
    if ctx_tree != base_tree_oid:
        return []
    import_root = replay_ctx.get("import_root", "")
    extra_sys_path = replay_ctx.get("extra_sys_path", [])
    if not isinstance(import_root, str) or not isinstance(extra_sys_path, list):
        return []
    if any(not isinstance(item, str) for item in extra_sys_path):
        return []

    base_commit = raw_commit.lower()
    post_tree_str = str(art_post_tree)
    obligations = art.get("obligations")
    if not isinstance(obligations, list):
        return []

    extracted: list[AuthenticatedExportedGuard] = []
    for row in obligations:
        if not isinstance(row, dict) or row.get("verdict") != "refuted":
            continue
        ob_id = row.get("id")
        witness_call = row.get("witness_call")
        witness_record = row.get("witness_record")
        if not isinstance(ob_id, str) or not ob_id.strip():
            continue
        if not isinstance(witness_call, dict) or not isinstance(witness_record, dict):
            continue
        try:
            record = record_for_export(witness_call, witness_record)
            source = build_pytest_source(
                record,
                import_root=import_root,
                extra_sys_path=list(extra_sys_path),
                base_commit=base_commit,
                post_tree=post_tree_str,
                expect="pre",
            )
            canonical_bytes = source.encode("utf-8")
            if not (0 < len(canonical_bytes) <= MAX_GUARD_BYTES):
                continue
            call_info = record["call"]
            module = str(call_info["module"])
            qualname = str(call_info["qualname"])
            canonical_sha = sha256_hex(hashlib.sha256(canonical_bytes).hexdigest())
            witness_json = json.dumps(witness_call, sort_keys=True, ensure_ascii=True, allow_nan=False)
            extracted.append(
                AuthenticatedExportedGuard(
                    source_run_id=RunId(str(source_run_id)),
                    source_obligation_id=ob_id,
                    base_tree_oid=base_tree_oid,
                    base_commit=base_commit,
                    post_tree_oid=art_post_tree,
                    target_symbol=f"{module}.{qualname}",
                    module=module,
                    qualname=qualname,
                    import_root=import_root,
                    expect="pre",
                    canonical_sha256=canonical_sha,
                    canonical_bytes=canonical_bytes,
                    witness_call_json=witness_json,
                )
            )
        except (NotExportable, ValueError, TypeError, KeyError, UnicodeEncodeError):
            continue
    return extracted


def build_guard_catalog(
    host_state: Any,
    repo_identity: str,
    base_tree_oid: TreeOid,
    *,
    max_run_dirs: int = MAX_CATALOG_RUN_DIRS,
    max_entries: int = MAX_CATALOG_ENTRIES,
    max_total_bytes: int = MAX_CATALOG_TOTAL_BYTES,
) -> ExportedGuardCatalog:
    """Build a bounded, read-only catalog of canonical ``--expect pre`` guards. Always fails closed to empty."""
    try:
        validated_base = validate_tree_oid(str(base_tree_oid))
        runs_dir = _existing_runs_root(host_state, repo_identity)
        if runs_dir is None:
            return EMPTY_GUARD_CATALOG
        runs_resolved = runs_dir.resolve(strict=True)
        run_dirs = _bounded_run_dirs(runs_dir, max_dirs=min(max_run_dirs, MAX_CATALOG_RUN_DIRS))
        entry_cap = min(max_entries, MAX_CATALOG_ENTRIES)
        bytes_cap = min(max_total_bytes, MAX_CATALOG_TOTAL_BYTES)

        seen_sha: set[str] = set()
        entries: list[AuthenticatedExportedGuard] = []
        total_bytes = 0
        for run_dir in run_dirs:
            if len(entries) >= entry_cap or total_bytes >= bytes_cap:
                break
            try:
                candidates = _extract_entries_from_run(
                    run_dir,
                    repo_identity=repo_identity,
                    base_tree_oid=validated_base,
                    runs_resolved=runs_resolved,
                )
            except Exception:  # noqa: BLE001 - corrupt single run never crashes catalog build
                continue
            for entry in candidates:
                digest = str(entry.canonical_sha256).lower()
                if digest in seen_sha:
                    continue
                size = len(entry.canonical_bytes)
                if len(entries) >= entry_cap or total_bytes + size > bytes_cap:
                    continue
                seen_sha.add(digest)
                entries.append(entry)
                total_bytes += size
        entries.sort(key=lambda e: (str(e.canonical_sha256), str(e.source_run_id), e.source_obligation_id))
        return ExportedGuardCatalog(
            repo_identity=repo_identity,
            base_tree_oid=validated_base,
            entries=tuple(entries),
        )
    except Exception:  # noqa: BLE001 - catalog construction must fail closed to empty
        return EMPTY_GUARD_CATALOG


__all__ = ["build_guard_catalog"]
