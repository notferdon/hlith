# SPDX-License-Identifier: Apache-2.0
"""Local-first offline L5 feedback store under HostState ``feedback/`` namespace.

Never writes to the target repository or its ``.git/info/exclude``.
Any corrupt, non-regular, or tampered file in the store raises ``FeedbackIntegrityError``.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..contract.codec import SCHEMA_VERSION, canonical_bytes, sha256_canonical
from ..contract.identities import RunId, Sha256, run_id as validate_run_id, sha256_hex
from ._legacy import DirectiveKind, FeedbackIntegrityError, FeedbackRecord

_FB_ID_RE = re.compile(r"^fb-[0-9a-f]{20}$")
_SUPERSEDED_RE = re.compile(r"^(fb-[0-9a-f]{20})\.superseded\.jsonl$")


@dataclass(frozen=True)
class StoredRecord:
    """Validated feedback record loaded from the local host-state store."""

    record: FeedbackRecord
    record_sha256: Sha256
    validated_run_id: RunId | None


def _ensure_safe_dir(store_dir: Path, *, create: bool) -> Path:
    if store_dir.exists():
        st = os.lstat(store_dir)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise FeedbackIntegrityError(f"feedback store path is not a safe directory: {store_dir}")
        return store_dir
    if not create:
        return store_dir
    for parent in reversed((store_dir, *store_dir.parents)):
        if parent.exists():
            st = os.lstat(parent)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise FeedbackIntegrityError(f"feedback store ancestor is not a safe directory: {parent}")
    store_dir.mkdir(parents=True, exist_ok=True)
    return store_dir


def _read_regular_text(path: Path) -> str:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise FeedbackIntegrityError(f"non-regular file in feedback store: {path.name}")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise FeedbackIntegrityError(f"{path.name}: {exc}") from None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise FeedbackIntegrityError(f"{path.name}: {exc}") from None


def _parse_record(data: object, filename_stem: str) -> StoredRecord:
    if not isinstance(data, dict):
        raise FeedbackIntegrityError(f"{filename_stem}.json: expected JSON object")
    # Support v2 envelope {format: 2, schema_version: 2, record: {...}} and legacy v1 FeedbackRecord JSON.
    if data.get("format") == 2:
        if data.get("schema_version") != SCHEMA_VERSION or "record" not in data:
            raise FeedbackIntegrityError(f"{filename_stem}.json: invalid format-2 envelope")
        rec_payload = data["record"]
    else:
        rec_payload = data
    rec = FeedbackRecord.from_json(rec_payload)
    if rec.feedback_id != filename_stem:
        raise FeedbackIntegrityError(f"{filename_stem}.json holds mismatched record {rec.feedback_id}")
    digest = sha256_hex(sha256_canonical(rec.to_json()))
    try:
        rid = validate_run_id(rec.source_run_id)
    except ValueError:
        rid = None
    return StoredRecord(record=rec, record_sha256=digest, validated_run_id=rid)


def _load_superseded_ids(store_dir: Path, record_names: set[str], valid_commits: set[str] | None) -> set[str]:
    superseded: set[str] = set()
    for p in sorted(store_dir.iterdir()):
        m = _SUPERSEDED_RE.match(p.name)
        if not m:
            continue
        fb_id = m.group(1)
        if f"{fb_id}.json" not in record_names:
            raise FeedbackIntegrityError(f"orphan supersession sidecar: {p.name}")
        raw = _read_regular_text(p)
        for idx, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                raise FeedbackIntegrityError(f"{p.name}:{idx}: blank line in supersession sidecar")
            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise FeedbackIntegrityError(f"{p.name}:{idx}: {exc}") from None
            if not isinstance(entry, dict) or not entry.get("run_id"):
                raise FeedbackIntegrityError(f"{p.name}:{idx}: malformed supersession entry")
            landed_commit = entry.get("superseded_by_landing")
            if isinstance(landed_commit, str) and landed_commit:
                if valid_commits is None or landed_commit in valid_commits:
                    superseded.add(fb_id)
    return superseded


def persist_record(store_dir: Path, record: FeedbackRecord, *, envelope_v2: bool = True) -> Path:
    """Atomically write ``record`` into ``store_dir`` without touching any target repo or ``.git``."""
    safe_dir = _ensure_safe_dir(Path(store_dir), create=True)
    target = safe_dir / f"{record.feedback_id}.json"
    if target.exists():
        existing = _parse_record(json.loads(_read_regular_text(target)), record.feedback_id)
        if existing.record.to_json() != record.to_json():
            raise FeedbackIntegrityError(f"conflicting record already exists for {record.feedback_id}")
        return target
    payload: dict
    if envelope_v2:
        payload = {"format": 2, "schema_version": SCHEMA_VERSION, "record": record.to_json()}
    else:
        payload = record.to_json()
    raw = canonical_bytes(payload)
    tmp = safe_dir / f".tmp-{record.feedback_id}-{os.getpid()}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        os.replace(tmp, target)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return target


def append_supersession(store_dir: Path, fb_id: str, entry: dict) -> Path:
    """Append a validated supersession line after an independently confirmed landing."""
    if not _FB_ID_RE.fullmatch(fb_id):
        raise FeedbackIntegrityError(f"invalid feedback id for supersession: {fb_id!r}")
    safe_dir = _ensure_safe_dir(Path(store_dir), create=False)
    rec_path = safe_dir / f"{fb_id}.json"
    if not rec_path.exists():
        raise FeedbackIntegrityError(f"cannot supersede missing record {fb_id}")
    _ = _read_regular_text(rec_path)
    sidecar = safe_dir / f"{fb_id}.superseded.jsonl"
    if sidecar.exists():
        _ = _read_regular_text(sidecar)
    line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(sidecar, flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line)
    return sidecar


def load_stored_records(
    store_dir: Path,
    symbols: Iterable[str] | None = None,
    *,
    valid_landed_commits: set[str] | None = None,
) -> tuple[StoredRecord, ...]:
    """Load and validate all intact records in ``store_dir`` intersecting ``symbols``.

    Every file in ``store_dir`` (except ``.tmp-*``) is validated so tampering outside
    the requested symbol cone still fails closed.
    """
    safe_dir = _ensure_safe_dir(Path(store_dir), create=False)
    if not safe_dir.exists():
        return ()
    cone = None if symbols is None else set(symbols)
    names = {p.name for p in safe_dir.iterdir()}
    superseded_ids = _load_superseded_ids(safe_dir, names, valid_landed_commits)
    loaded: list[StoredRecord] = []
    for p in sorted(safe_dir.iterdir()):
        if p.name.startswith(".tmp-") or _SUPERSEDED_RE.match(p.name):
            continue
        if p.suffix != ".json" or not _FB_ID_RE.fullmatch(p.stem):
            raise FeedbackIntegrityError(f"unexpected file in feedback store: {p.name}")
        raw = _read_regular_text(p)
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise FeedbackIntegrityError(f"{p.name}: {exc}") from None
        stored = _parse_record(data, p.stem)
        rec = stored.record
        if rec.feedback_id in superseded_ids and rec.directive_kind in (DirectiveKind.PIN_REGRESSION_COUNTEREXAMPLE,
                                                                       DirectiveKind.ORACLE_REGRESSION):  # review FB-NEW-1
            continue
        if cone is None or cone & set(rec.target_symbols):
            loaded.append(stored)
    return tuple(loaded)
