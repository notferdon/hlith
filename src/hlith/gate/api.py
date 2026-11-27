# SPDX-License-Identifier: Apache-2.0
"""L4 ``GateApi`` implementation: sole writer of ``R_target``.

Imports only ``contract`` and ``hostio`` primitives (plus ``gate.git_write`` / ``gate.journal``).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from ..contract.capabilities import (
    GateApi,
    GitRead,
    HostState,
    SnapshotService,
    VerificationVerifier,
    VerifiedEffect,
)
from ..contract.errors import (
    EXIT_BOUNDARY,
    EXIT_LANDED,
    BoundaryReason,
)
from ..contract.identities import RunId, Sha256, TargetIdentity, sha256_hex
from ..contract.legacy import GateOutcome, decide
from ..contract.obligations import RequiredScope, ScopeDischarge, obligation_set_digest, scope_fully_discharged
from ..contract.runs import GateReceipt
from ..hostio.git_read import HardenedGitRead
from ..hostio.integrity import HostIntegrityError, capture_target_identity
from ..hostio.snapshot import patch_violations
from ..hostio.snapshot import LocalSnapshotService
from ..hostio.snapshot_release import release_snapshots
from .git_write import (
    HeadMovedError,
    PatchDoesNotApply,
    apply_index_and_verify_tree,
    changed_paths_between_snapshots,
    commit_tree_cas,
    compute_path_images,
    dirty_target_reason,
    head_commit,
    head_landing_keys,
    patch_paths,
    rollback_paths,
    run_target_git,
    worktree_blob_oid,
)
from .journal import begin_journal, clear_journal, load_verified_journal, target_lock


def landing_key_v2(
    *,
    base_tree_oid: str,
    patch_sha256: str,
    post_tree_oid: str,
    account_sha256: str,
    record_body_sha256: str,
) -> str:
    """Content address of one landing, binding base tree, patch, post tree, EffectAccount, and record."""
    raw = f"{base_tree_oid}|{patch_sha256}|{post_tree_oid}|{account_sha256}|{record_body_sha256}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _refuse(
    run_id: RunId,
    exit_status: int,
    reason: BoundaryReason | str | tuple[str, ...],
    record_sha: Sha256 | None = None,
) -> GateReceipt:
    if isinstance(reason, BoundaryReason):
        blocking = (reason.value,)
    elif isinstance(reason, tuple):
        blocking = tuple(str(x) for x in reason) or ("refused",)
    else:
        blocking = (str(reason),)
    return GateReceipt(
        run_id=run_id,
        outcome="refused",
        exit_status=exit_status,
        blocking=blocking,
        landed_commit=None,
        verification_record_sha256=record_sha,
    )


class LocalGateService(GateApi):
    """Trusted host-side L4 gate implementing ``contract.capabilities.GateApi``."""

    def __init__(
        self,
        host_state: HostState,
        *,
        git_read: GitRead | None = None,
        snapshot_service: SnapshotService | None = None,
    ) -> None:
        self._host_state = host_state
        self._git_read = git_read or HardenedGitRead()
        self._snapshot_service = snapshot_service or LocalSnapshotService(self._git_read)

    def land(
        self,
        target: Path,
        patch: bytes,
        verified: VerifiedEffect,
        verifier: VerificationVerifier,
        expected_identity: TargetIdentity,
        expected_run_id: RunId | None = None,
        expected_head: str | None = None,
    ) -> GateReceipt:
        record = verified.record
        run_id = record.run_id
        record_sha = record.body_sha256

        hostile = self._git_read.repository_hostile_reason(target)
        if hostile is not None:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.HOSTILE_REPOSITORY, record_sha)

        try:
            live_identity = capture_target_identity(target)
        except HostIntegrityError:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.TARGET_IDENTITY_CHANGED, record_sha)
        if live_identity != expected_identity or record.target != expected_identity:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.TARGET_IDENTITY_CHANGED, record_sha)

        if not record.mac or not record.issuer or not verifier.verify(record):
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)

        if expected_run_id is not None and record.run_id != expected_run_id:
            return _refuse(run_id, EXIT_BOUNDARY, "run-id-mismatch", record_sha)

        if obligation_set_digest(verified.obligations) != record.obligation_set_sha256:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)

        patch_digest = sha256_hex(hashlib.sha256(patch).hexdigest())
        if patch_digest != record.patch_sha256:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.ACCOUNT_MISMATCH, record_sha)

        # an empty change has nothing to land: refused before any journal or commit, so land never writes the paths=[] journal that
        # recover() (rightly) treats as untrusted; one rule on both sides (review G2-EMPTY-PATCH-LAND-AND-RECOVER)
        if not patch.strip() or record.post_tree_oid == record.base_tree_oid:
            return _refuse(run_id, EXIT_BOUNDARY, "empty-change", record_sha)

        obs = getattr(verified.obligations, "obligations", None)
        if not obs:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.SCOPE_UNDISCHARGED, record_sha)

        try:
            decision = decide(verified.obligations)
        except (ValueError, TypeError):
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)
        if decision.outcome is not GateOutcome.LANDED:
            return _refuse(run_id, decision.exit_status, decision.blocking or ("refused",), record_sha)

        for o in obs:
            prov = getattr(o, "provenance", None)
            ev = getattr(o, "evidence", None)
            if prov is None or ev is None:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)
            if getattr(prov, "confined", None) is not True:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)
            if getattr(prov, "proposer_paths_readable", None) is not False:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)
            if getattr(prov, "exit_code", None) != 0:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)

        held_ids = {str(getattr(o, "obligation_id", "")) for o in obs}
        if not record.consumption:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.ACCOUNT_MISMATCH, record_sha)
        for cons in record.consumption:
            if cons.account_sha256 != record.account_sha256 or cons.obligation_id not in held_ids:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.ACCOUNT_MISMATCH, record_sha)

        req = verified.required_scope
        dis = verified.scope_discharge
        if not isinstance(req, RequiredScope) or not isinstance(dis, ScopeDischarge):
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.SCOPE_UNDISCHARGED, record_sha)
        if req.digest != record.required_scope_digest or dis.digest != record.scope_discharge_digest:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.RECORD_INVALID, record_sha)
        if not scope_fully_discharged(req, dis):
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.SCOPE_UNDISCHARGED, record_sha)

        lkey = landing_key_v2(
            base_tree_oid=str(record.base_tree_oid),
            patch_sha256=str(record.patch_sha256),
            post_tree_oid=str(record.post_tree_oid),
            account_sha256=str(record.account_sha256),
            record_body_sha256=str(record_sha),
        )
        replay = self._existing_landing(target, record, lkey)
        if replay is not None:
            return GateReceipt(
                run_id=run_id,
                outcome="landed",
                exit_status=EXIT_LANDED,
                blocking=(),
                landed_commit=replay,
                verification_record_sha256=record_sha,
            )

        try:
            live_base_tree = self._git_read.head_tree(target)
        except HostIntegrityError:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.BASE_TREE_MISMATCH, record_sha)
        if live_base_tree != record.base_tree_oid:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.BASE_TREE_MISMATCH, record_sha)

        if patch.strip() and patch_violations(patch.decode("utf-8", "surrogateescape")):
            return _refuse(run_id, EXIT_BOUNDARY, "patch-policy-violation", record_sha)

        base_snap = post_snap = None
        try:  # the sealed snapshots are host temp directories: released on EVERY exit below (normal, refusal, exception)
            try:
                base_snap = self._snapshot_service.seal_base(target)
                if base_snap.tree_oid != record.base_tree_oid:
                    return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.BASE_TREE_MISMATCH, record_sha)
                post_snap = self._snapshot_service.reconstruct_post(base_snap, patch)
            except HostIntegrityError:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.POST_TREE_MISMATCH, record_sha)
            if post_snap.tree_oid != record.post_tree_oid:
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.POST_TREE_MISMATCH, record_sha)

            if not req.items:
                changed_paths = changed_paths_between_snapshots(base_snap.path, post_snap.path)
                if any(p.endswith(".py") for p in changed_paths):
                    return _refuse(run_id, EXIT_BOUNDARY, "required-scope-empty-for-source-change", record_sha)
        finally:
            release_snapshots(self._snapshot_service, post_snap, base_snap)

        try:
            repo_identity = self._host_state.stable_repo_identity(target)
        except HostIntegrityError:
            return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.JOURNAL_UNAVAILABLE, record_sha)

        with target_lock(target, self._host_state, repo_identity):
            try:
                base_head = head_commit(target)
                if expected_head is not None and base_head != expected_head:  # the review was bound to this commit; a same-tree move mid-run must not land
                    return _refuse(run_id, EXIT_BOUNDARY, "head-moved-since-review", record_sha)
                paths = patch_paths(target, patch)
                if not paths:  # a patch git applies to no path (e.g. header-only) is the same empty change
                    return _refuse(run_id, EXIT_BOUNDARY, "empty-change", record_sha)
                dirty = dirty_target_reason(target, paths)
                if dirty is not None:
                    return _refuse(run_id, EXIT_BOUNDARY, dirty, record_sha)
                images = compute_path_images(target, base_head, patch, paths)
                j_path, n_path = begin_journal(
                    target,
                    self._host_state,
                    repo_identity,
                    base_head=base_head,
                    paths=paths,
                    patch_sha256=str(record.patch_sha256),
                    images=images,
                    post_tree=str(record.post_tree_oid),
                )
            except HostIntegrityError as exc:
                reason = "unrecovered-journal-exists" if "unrecovered-journal-exists" in str(exc) else BoundaryReason.JOURNAL_UNAVAILABLE
                return _refuse(run_id, EXIT_BOUNDARY, reason, record_sha)

            try:
                tree_ok = apply_index_and_verify_tree(target, patch, record.post_tree_oid)
                if not tree_ok:
                    rollback_paths(target, base_head, paths, images)
                    clear_journal(j_path, n_path)
                    return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.POST_TREE_MISMATCH, record_sha)
                msg = f"hlith: land {str(record.patch_sha256)[:12]}\n\nAccount-Sha256: {record.account_sha256}\nHlith-Key: {lkey}"
                # the commit carries the VERIFIED tree object (not the index), and HEAD moves only if it is still base_head (CAS)
                landed_sha = commit_tree_cas(target, str(record.post_tree_oid), base_head, msg)
            except PatchDoesNotApply:
                # `git apply --check` failed before ANY byte was written: nothing to roll back (a rollback of paths we never touched would refuse and leave the journal behind)
                clear_journal(j_path, n_path)
                return _refuse(run_id, EXIT_BOUNDARY, "patch-does-not-apply", record_sha)
            except HeadMovedError:
                # another writer's commit is HEAD now: give the touched paths back ITS content, never the stale base's
                rollback_paths(target, base_head, paths, images, restore_to=head_commit(target))
                clear_journal(j_path, n_path)
                return _refuse(run_id, EXIT_BOUNDARY, "head-moved-during-landing", record_sha)
            except HostIntegrityError:
                rollback_paths(target, base_head, paths, images)
                clear_journal(j_path, n_path)
                return _refuse(run_id, EXIT_BOUNDARY, BoundaryReason.POST_TREE_MISMATCH, record_sha)

            clear_journal(j_path, n_path)
            return GateReceipt(
                run_id=run_id,
                outcome="landed",
                exit_status=EXIT_LANDED,
                blocking=(),
                landed_commit=landed_sha,
                verification_record_sha256=record_sha,
            )

    def _existing_landing(self, target: Path, record, lkey: str) -> str | None:
        """HEAD commit when HEAD IS this record's landing, else None.

        A retry after a lost reply must report the landing that already happened, never refuse it and never land twice. A key trailer
        alone is not evidence: HEAD must also carry exactly the record's post tree, sit directly on the record's base tree, and the
        tracked worktree must be clean, so a forged or unrelated commit message cannot make a refusal look like a landing.
        """
        try:
            if lkey not in head_landing_keys(target):
                return None
            head_tree = run_target_git(target, ("rev-parse", "--verify", "HEAD^{tree}"))
            parent_tree = run_target_git(target, ("rev-parse", "--verify", "HEAD~1^{tree}"))
            parents = run_target_git(target, ("rev-list", "--parents", "-n", "1", "HEAD"))
            status = run_target_git(target, ("status", "--porcelain=v1", "-z", "--untracked-files=no"))
        except HostIntegrityError:
            return None
        if 0 in (len(x.stdout) for x in (head_tree, parent_tree, parents)) or status.returncode != 0 or status.stdout:
            return None
        if head_tree.returncode != 0 or parent_tree.returncode != 0 or parents.returncode != 0:
            return None
        if len(parents.stdout.decode("ascii", "replace").split()) != 2:  # exactly one parent
            return None
        if head_tree.stdout.decode("ascii", "replace").strip() != str(record.post_tree_oid):
            return None
        if parent_tree.stdout.decode("ascii", "replace").strip() != str(record.base_tree_oid):
            return None
        return head_commit(target)

    @staticmethod
    def _clear_stale_index_lock(target: Path) -> None:
        """A landing killed inside ``git apply --index`` leaves an empty ``<git_dir>/index.lock`` that makes every later git write fail.

        Only reached with an authenticated journal and the exclusive per-target gate lock held, so no other hlith landing is running. The lock
        is removed only when it is empty AND no live process has it open; otherwise recovery refuses and names the file. Never removes a lock
        another git process may be using.
        """
        from .journal import _target_git_dir

        lock = Path(_target_git_dir(target)) / "index.lock"
        try:
            st = os.lstat(lock)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(st.st_mode) or st.st_size != 0 or _held_open_by_a_process(lock):
            raise HostIntegrityError(
                f"gate: {lock} exists and may belong to a running git process; recovery did not touch it. "
                f"If no git process is running, remove it ('rm {lock}') and run again")
        lock.unlink()

    def recover(self, target: Path) -> str:
        hostile = self._git_read.repository_hostile_reason(target)
        if hostile is not None:
            raise HostIntegrityError(f"gate: refusing recovery on hostile repo ({hostile})")
        repo_identity = self._host_state.stable_repo_identity(target)
        with target_lock(target, self._host_state, repo_identity):
            loaded = load_verified_journal(target, self._host_state, repo_identity)
            if loaded is None:
                return "clean"
            rec, j_path, n_path = loaded
            self._clear_stale_index_lock(target)
            live_head = head_commit(target)
            if live_head != rec["base_head"]:
                if not _is_completed_landing(target, live_head, rec["base_head"], rec["paths"], rec["images"],
                                             post_tree=rec.get("post_tree")):
                    return "untrusted"
                clear_journal(j_path, n_path)
                return "completed"
            status = rollback_paths(target, rec["base_head"], list(rec["paths"]), dict(rec["images"]))
            clear_journal(j_path, n_path)
            return status


def _held_open_by_a_process(path: Path) -> bool:
    """True when any live process has ``path`` open (scans /proc/*/fd; unreadable entries count as 'held' only if they point at the file)."""
    try:
        target = os.stat(path)
    except OSError:
        return False
    for fd_dir in Path("/proc").glob("[0-9]*/fd"):
        try:
            for fd in fd_dir.iterdir():
                try:
                    st = os.stat(fd)
                except OSError:
                    continue
                if (st.st_ino, st.st_dev) == (target.st_ino, target.st_dev):
                    return True
        except OSError:
            continue
    return False


def _is_completed_landing(
    target: Path,
    head: str,
    base_head: str,
    paths: list[str],
    images: dict[str, list[str]],
    post_tree: str | None = None,
) -> bool:
    """Return true only when HEAD is the journal's complete, clean single-commit result (and, for a format-3 journal, carries
    EXACTLY the verified post tree the landing was authorised for)."""
    if not isinstance(paths, list) or not all(isinstance(path, str) and path for path in paths):
        return False
    if not isinstance(images, dict):
        return False
    if not paths or len(paths) != len(set(paths)) or set(paths) != set(images):
        return False

    if post_tree is not None:
        tree_cp = run_target_git(target, ("rev-parse", "--verify", f"{head}^{{tree}}"))
        if tree_cp.returncode != 0 or tree_cp.stdout.decode("ascii", "replace").strip() != post_tree:
            return False
    parent_cp = run_target_git(target, ("rev-list", "--parents", "-n", "1", head))
    if parent_cp.returncode != 0:
        return False
    parent_fields = parent_cp.stdout.decode("ascii", "replace").split()
    if len(parent_fields) != 2 or parent_fields[0] != head or parent_fields[1] != base_head:
        return False

    changed_cp = run_target_git(
        target,
        ("diff-tree", "--no-commit-id", "--no-renames", "-r", "--name-only", "-z", base_head, head),
    )
    if changed_cp.returncode != 0:
        return False
    changed_paths = {
        raw.decode("utf-8", "surrogateescape")
        for raw in changed_cp.stdout.split(b"\0")
        if raw
    }
    if not changed_paths or not changed_paths.issubset(paths):
        return False

    # Require a repository-wide clean state, including unrelated tracked edits,
    # staged changes, untracked files, and dirty submodules.
    status_cp = run_target_git(
        target,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"),
    )
    if status_cp.returncode != 0 or status_cp.stdout:
        return False

    for rel in paths:
        image = images.get(rel)
        if not isinstance(image, list) or len(image) != 2 or not isinstance(image[1], str):
            return False
        post_blob = image[1]
        if post_blob:
            head_blob_cp = run_target_git(
                target,
                ("rev-parse", "--verify", f"{head}:{rel}"),
            )
            if head_blob_cp.returncode != 0 or head_blob_cp.stdout.decode("ascii", "replace").strip() != post_blob:
                return False
        else:
            head_blob_cp = run_target_git(
                target,
                ("ls-tree", "-z", "--full-tree", head, "--", rel),
            )
            if head_blob_cp.returncode != 0 or head_blob_cp.stdout:
                return False
        try:
            if worktree_blob_oid(target, rel) != post_blob:
                return False
        except HostIntegrityError:
            return False

    return True
