# SPDX-License-Identifier: Apache-2.0
"""Replay one witness recorded in a completed run artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

_LIMIT = "replay re-executes ONE recorded call: it confirms a witness, it never certifies the rest of the domain"
_ENVELOPE = "hlith.replay/1"
_HEX_OID = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_MAX_PATCH_BYTES = 8 * 1024 * 1024  # the engine's patch-size policy

# Exit codes describe the REPLAY. Whether a requested test file was written is `pytest_export.status`: a reproduced
# witness that cannot be exported still exits 0.
EXIT_REPRODUCED = 0
EXIT_NOT_REPRODUCED = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_BOUNDARY = 4
EXIT_NOT_REPLAYABLE = 12


class _UsageError(Exception):
    def __init__(self, reason: str, ids: list[str] | None = None) -> None:
        super().__init__(reason)
        self.ids = ids or []


class _NotReplayable(Exception):
    pass


class _BoundaryError(Exception):
    pass


def add_parser(subparsers) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("replay", help="re-execute one witness from a recorded run")
    parser.add_argument("run", help="run id in the current repository, a run directory, or an artifact file")
    parser.add_argument("--repo", type=Path, help="repository containing the recorded base commit")
    parser.add_argument("--obligation", help="replay this exact recorded obligation id")
    parser.add_argument("--python", dest="python_path", help="Python executable to use for the replay")
    parser.add_argument("--unconfined", action="store_true", help="run target code outside the confinement boundary")
    parser.add_argument("--scripts-dir", type=Path, help="write the two replay scripts into this directory")
    parser.add_argument("--pytest-out", "--emit-pytest", dest="pytest_out", type=Path, help="write a portable pytest witness (simple calls only; --emit-pytest alias)")
    parser.add_argument("--expect", choices=("pre", "post"), default=None,
                        help="required with --pytest-out: pre = regression guard, post = accepted change")
    parser.add_argument("--json", action="store_true", help="write the versioned hlith.replay/1 envelope")
    _envelope_for_parse_errors(parser)
    return parser


def _export_state(status: str, expect: str | None, path: str | None = None, reason: str | None = None) -> dict:
    """`pytest_export`: status is written | refused | not-attempted."""
    return {"status": status, "expect": expect, "path": path, "reason": reason}


def _envelope_for_parse_errors(parser: argparse.ArgumentParser) -> None:
    """Under --json an argument error of this subcommand also prints the envelope (still exit 2, usage on stderr)."""
    parse, report = parser.parse_known_args, parser.error

    def parse_known_args(args=None, namespace=None, **kwargs):
        argv = list(sys.argv[1:] if args is None else args)
        options = argv[:argv.index("--")] if "--" in argv else argv

        def error(message):
            if any(len(a) > 2 and "--json".startswith(a) for a in options):
                asked = any(a.split("=")[0] in ("--pytest-out", "--emit-pytest") for a in options)
                _render(status="USAGE ERROR", code=EXIT_USAGE, run_id=None, obligation_id=None, base_commit=None,
                        base_tree=None, post_tree=None, reason=message, confined="--unconfined" not in options,
                        as_json=True,
                        pytest_export=_export_state("not-attempted", None, reason=message) if asked else None)
            report(message)

        parser.error = error
        return parse(argv, namespace, **kwargs)

    parser.parse_known_args = parse_known_args


def _vetted_repo(candidate: Path) -> Path | None:
    from ..hostio.git_read import find_work_tree_root, vet_repository

    repo = find_work_tree_root(candidate.expanduser())
    if repo is None:
        return None
    why = vet_repository(repo)
    if why is not None:
        raise _BoundaryError(f"repository refused by host boundary: {why}")
    return repo


def _run_record(target: str, repo_hint: Path | None = None):
    from .api import OperatorApi

    api = OperatorApi()
    path = Path(target).expanduser()
    view = None
    if path.exists():
        try:
            if path.is_dir():
                view = api.inspect(path).view
            elif path.is_file():
                view = api.inspect_artifact_file(path).view
            else:
                raise _NotReplayable("run input is not a regular file or directory")
        except _NotReplayable:
            raise
        except Exception as exc:
            raise _NotReplayable(f"run record cannot be read: {type(exc).__name__}") from None
    else:
        repo = _vetted_repo(repo_hint if repo_hint is not None else Path.cwd())
        if repo is None:
            raise _UsageError(
                f"run id {target!r} was not found; run it from the repository (or pass --repo PATH)"
            )
        try:
            run_dir = api.find(repo, target)
        except (OSError, ValueError):
            run_dir = None
        if run_dir is None:
            raise _UsageError(f"unknown run id {target!r}")
        view = api.inspect(run_dir).view
    if view is None or not isinstance(view.artifact, dict):
        raise _NotReplayable("run has no readable artifact")
    return api, view, view.artifact


def _repo_for_run(view, artifact: dict, repo_hint: Path | None = None) -> Path:
    receipt = getattr(view, "receipt", None)
    run_receipt = getattr(receipt, "run", None)
    source_repo = getattr(run_receipt, "source_repo", None)
    run = artifact.get("run")
    if not source_repo and isinstance(run, dict):
        source_repo = run.get("source_repo") or run.get("repo")
    context = run.get("replay_context") if isinstance(run, dict) else None
    if not source_repo and isinstance(context, dict):
        source_repo = context.get("source_repo") or context.get("repo")

    if repo_hint is not None:
        candidate = repo_hint
    elif isinstance(source_repo, str) and source_repo.strip():
        candidate = Path(source_repo).expanduser()
        if not candidate.is_absolute():
            raise _NotReplayable(
                "recorded repository path is not absolute; run it from the repository (or pass --repo PATH)"
            )
    else:
        candidate = Path.cwd()

    repo = _vetted_repo(candidate)
    if repo is None:
        raise _NotReplayable(
            "repository unavailable; run it from the repository (or pass --repo PATH)"
        )
    return repo


def _select_obligation(artifact: dict, requested: str | None) -> tuple[str, dict]:
    rows = artifact.get("obligations")
    if not isinstance(rows, list):
        raise _NotReplayable("artifact has no obligations list")
    ids = [row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)]
    by_id = {row["id"]: row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)}
    if requested is not None:
        if requested not in by_id:
            raise _UsageError(f"unknown obligation id {requested!r}; available ids: {', '.join(ids) or '(none)'}", ids)
        return requested, by_id[requested]
    with_witness = [(oid, row) for oid, row in by_id.items() if isinstance(row.get("witness_call"), dict)]
    if len(with_witness) > 1:
        choices = [oid for oid, _ in with_witness]
        raise _UsageError(f"multiple obligations have recorded witnesses; choose --obligation from: {', '.join(choices)}", choices)
    if with_witness:
        return with_witness[0]
    if not by_id:
        raise _NotReplayable("artifact has no obligation ids or recorded witness calls")
    return next(iter(by_id.items()))


def _read_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _NotReplayable(f"{label} is unavailable: {exc.strerror or type(exc).__name__}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _NotReplayable(f"{label} is not a regular file")
        if info.st_size > max_bytes:
            raise _NotReplayable(f"{label} exceeds the {max_bytes}-byte replay limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise _NotReplayable(f"{label} exceeds the {max_bytes}-byte replay limit")
        return data
    finally:
        os.close(fd)


def _target_python(context: dict, override: str | None, artifact_target: dict | None = None) -> str:
    recorded = context.get("target_python")
    executable = override
    if executable is None:
        executable = recorded.get("executable") if isinstance(recorded, dict) else None
        if not isinstance(executable, str) and isinstance(artifact_target, dict):
            executable = artifact_target.get("executable")
    if not isinstance(executable, str) or not executable.strip():
        raise _NotReplayable("target Python executable was not recorded; pass --python PATH")
    py = Path(executable).expanduser()
    if not py.is_absolute():
        py = Path.cwd() / py
    try:
        # Profile.spec resolves granted paths before mounting them. Resolve
        # symlinked ancestors the same way, but preserve the final venv
        # executable symlink so Python can still discover its pyvenv.cfg.
        py = py.parent.resolve(strict=True) / py.name
    except (OSError, RuntimeError):
        pass
    if not py.is_file() or not os.access(py, os.X_OK):
        raise _NotReplayable(f"target Python is unavailable or not executable: {executable}")
    return str(py)


def _contexts(artifact: dict, run_dir: Path, repo: Path, override_python: str | None):
    from ..contract.identities import tree_oid
    from ..hostio.git_read import safe_git_read

    run = artifact.get("run")
    context = run.get("replay_context") if isinstance(run, dict) else None
    if not isinstance(context, dict):
        raise _NotReplayable("artifact has no recorded run.replay_context")
    base = context.get("base")
    patch_meta = context.get("patch")
    if not isinstance(base, dict) or not isinstance(patch_meta, dict):
        raise _NotReplayable("recorded replay context is missing base or patch data")
    commit = base.get("commit")
    raw_tree = base.get("tree_oid")
    if not isinstance(commit, str) or not _HEX_OID.fullmatch(commit):
        raise _NotReplayable("recorded base commit is missing or malformed")
    if not isinstance(raw_tree, str):
        raise _NotReplayable("recorded base tree oid is missing")
    try:
        base_commit = commit.lower()
        base_tree = tree_oid(raw_tree)
    except (TypeError, ValueError) as exc:
        raise _NotReplayable(f"recorded base identity is invalid: {exc}") from None
    try:
        actual_tree = tree_oid(safe_git_read(repo, "rev-parse", "--verify", f"{base_commit}^{{tree}}"))
    except Exception as exc:
        raise _NotReplayable(
            f"recorded base commit cannot be read safely: {type(exc).__name__}; "
            "run it from the repository (or pass --repo PATH)"
        ) from None
    if actual_tree != base_tree:
        raise _NotReplayable("recorded base commit and tree oid do not match")
    if patch_meta.get("ref") != "change.patch":
        raise _NotReplayable("recorded patch reference is not change.patch")
    expected_sha = patch_meta.get("sha256")
    if not isinstance(expected_sha, str) or not _SHA256.fullmatch(expected_sha):
        raise _NotReplayable("recorded patch sha256 is missing or malformed")
    patch_path = run_dir / "change.patch"
    patch = _read_regular_file(patch_path, label="recorded change.patch", max_bytes=_MAX_PATCH_BYTES)
    if hashlib.sha256(patch).hexdigest() != expected_sha.lower():
        raise _NotReplayable("recorded change.patch sha256 does not match replay_context.patch.sha256")
    import_root = context.get("import_root", "")
    extra = context.get("extra_sys_path", [])
    if not isinstance(import_root, str) or not isinstance(extra, list) or any(not isinstance(p, str) for p in extra):
        raise _NotReplayable("recorded import_root or extra_sys_path is malformed")
    python = _target_python(context, override_python, artifact.get("target_python"))
    return base_commit, base_tree, patch, import_root, tuple(extra), python


def _save_scripts(directory: Path, scripts: dict) -> None:
    directory = directory.expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    for side in ("pre", "post"):
        script = scripts.get(side)
        if isinstance(script, str):
            path = directory / f"replay_{side}.py"
            if path.is_symlink():
                raise OSError(f"refusing symlink script output: {path}")
            path.write_text(script, encoding="utf-8")


def _render(*, status: str, code: int, run_id: str | None, obligation_id: str | None,
            base_commit: str | None, base_tree: str | None, post_tree: str | None,
            reason: str | None, confined: bool, as_json: bool, pytest_export: dict | None = None,
            extra: dict | None = None) -> int:
    record = {"envelope": _ENVELOPE, "status": status, "exit_status": code,
              "run_id": run_id, "obligation_id": obligation_id,
              "base": {"commit": base_commit, "tree_oid": base_tree},
              "post": {"tree_oid": post_tree}, "why": reason, "confined": confined, "limit": _LIMIT,
              "pytest_export": pytest_export}
    if extra:
        record.update(extra)
    if as_json:
        print(json.dumps(record, sort_keys=True, ensure_ascii=True))
    else:
        if status == "NOT REPLAYABLE" and reason:
            print(f"Replay: NOT REPLAYABLE ({reason})")
        else:
            print(f"Replay: {status}")
        base_display = "not reconstructed"
        if base_commit and base_tree:
            base_display = f"commit {base_commit} · tree {base_tree}"
        print(f"base: {base_display}")
        print(f"post: tree {post_tree}" if post_tree else "post: not reconstructed")
        print(_LIMIT)
    return code


def execute(args: argparse.Namespace) -> int:
    export = None
    if args.pytest_out is not None:
        export = _export_state("not-attempted", args.expect, reason="replay did not reach the export step")
    if export is not None and args.expect is None:
        message = "--pytest-out requires --expect pre|post (choose the intended contract; no default)"
        export["reason"] = message
        print(f"hlith: usage: {message}", file=sys.stderr)
        if args.json:
            _render(status="USAGE ERROR", code=EXIT_USAGE, run_id=None, obligation_id=args.obligation, base_commit=None,
                    base_tree=None, post_tree=None, reason=message, confined=not args.unconfined, as_json=True,
                    pytest_export=export)
        return EXIT_USAGE
    if args.unconfined:
        print("WARNING: --unconfined runs target code without Hlith's filesystem and network confinement", file=sys.stderr)
    run_id = None
    obligation_id = None
    base_commit = base_tree = post_tree = None
    try:
        api, view, artifact = _run_record(args.run, args.repo)
        run_id = view.run_id
        if not isinstance(run_id, str) and isinstance(artifact.get("run"), dict):
            run_id = artifact["run"].get("run_id")
        obligation_id, obligation = _select_obligation(artifact, args.obligation)
        witness = obligation.get("witness_call")
        if not isinstance(witness, dict):
            raise _NotReplayable(f"obligation {obligation_id} has no recorded witness_call")
        if witness.get("truncated"):
            raise _NotReplayable("recorded witness_call is truncated and cannot be replayed")
        if not isinstance(witness.get("module"), str) or not isinstance(witness.get("qualname"), str):
            raise _NotReplayable("recorded witness_call is missing module or qualname")
        repo = _repo_for_run(view, artifact, args.repo)
        run_dir = Path(view.run_dir)
        base_commit, base_tree, patch, import_root, extra_path, python = _contexts(
            artifact, run_dir, repo, args.python_path
        )
        if not args.unconfined:
            try:
                from ..hostio.confinement import GrantError, Profile, run_confined  # noqa: F401
            except Exception as exc:
                raise _BoundaryError(f"confinement unavailable: {type(exc).__name__}") from None
        from ..contract.capabilities import SealedSnapshot
        from ..differential import replay_witness
        from ..hostio.git_read import HardenedGitRead
        from ..hostio.snapshot import LocalSnapshotService

        git_read = HardenedGitRead()
        with tempfile.TemporaryDirectory(prefix="hlith-replay-") as temp_name:
            root = Path(temp_name)
            base_path = root / "base"
            try:
                git_read.export_tree(repo, base_tree, base_path)
            except Exception as exc:
                raise _NotReplayable(f"recorded base tree cannot be exported safely: {type(exc).__name__}") from None
            base_snapshot = SealedSnapshot(tree_oid=base_tree, path=base_path)
            with LocalSnapshotService(git_read, root=root) as snapshots:
                try:
                    post = snapshots.reconstruct_post(base_snapshot, patch)
                except Exception as exc:
                    raise _NotReplayable(f"recorded change.patch cannot reconstruct a post tree: {type(exc).__name__}") from None
                post_tree = str(post.tree_oid)
                result = replay_witness(
                    witness, str(base_path), str(post.path), import_root=import_root,
                    extra_sys_path=extra_path, python=python, confined=not args.unconfined,
                )
                scripts = result.get("scripts") if isinstance(result, dict) else None
                if args.scripts_dir is not None and isinstance(scripts, dict):
                    _save_scripts(args.scripts_dir, scripts)

        if not isinstance(result, dict) or not result.get("replayable"):
            reason = result.get("why") if isinstance(result, dict) else "replay engine returned no result"
            return _render(status="NOT REPLAYABLE", code=EXIT_NOT_REPLAYABLE, run_id=run_id,
                           obligation_id=obligation_id, base_commit=base_commit, base_tree=str(base_tree),
                           post_tree=post_tree, reason=str(reason or "recorded witness is not replayable"),
                           confined=not args.unconfined, as_json=args.json, pytest_export=export)
        if not args.unconfined:
            observations = [result.get(side) for side in ("pre", "post")]
            if any(isinstance(obs, dict) and obs.get("t") == "GrantError" for obs in observations):
                raise _BoundaryError("confinement unavailable: the sandbox refused a replay grant")
            if any(isinstance(obs, dict) and obs.get("t") == "ConfinementBoundaryError" for obs in observations):
                detail = "; ".join(
                    str(obs.get("m") or obs.get("t"))
                    for obs in observations
                    if isinstance(obs, dict) and obs.get("t") == "ConfinementBoundaryError"
                )
                raise _BoundaryError(f"host confinement unavailable: {detail}")
            if any(not isinstance(obs, dict) or "k" not in obs for obs in observations):
                failures = [obs for obs in observations if isinstance(obs, dict) and obs.get("k") == "replay-error"]
                detail = "; ".join(
                    str(obs.get("m") or obs.get("t")) for obs in failures if obs.get("m") or obs.get("t")
                )
                reason = "confined target Python worker returned no observation"
                if detail:
                    reason += f": {detail}"
                raise _BoundaryError(reason)
        reproduced = bool(result.get("reproduced"))
        if export is not None:
            if not reproduced:
                export["reason"] = "replay did not reproduce the recorded divergence"
                print(f"pytest witness NOT EXPORTED: {export['reason']}", file=sys.stderr)
            else:
                from ..contract.witness import record_for_export
                from .witness_export import NotExportable, write_pytest
                try:
                    record = record_for_export(witness, obligation.get("witness_record"))
                    written = write_pytest(args.pytest_out, record, import_root=import_root,
                                           extra_sys_path=list(extra_path), base_commit=base_commit,
                                           post_tree=post_tree, expect=args.expect)
                    export = _export_state("written", args.expect, path=str(written))
                    print(f"pytest witness: {written}", file=sys.stderr)
                except NotExportable as exc:
                    export = _export_state("refused", args.expect, reason=str(exc))
                    print(f"pytest witness NOT EXPORTED: {exc}", file=sys.stderr)
        return _render(status="REPRODUCED" if reproduced else "NOT REPRODUCED",
                       code=EXIT_REPRODUCED if reproduced else EXIT_NOT_REPRODUCED,
                       run_id=run_id, obligation_id=obligation_id, base_commit=base_commit,
                       base_tree=str(base_tree), post_tree=post_tree,
                       reason=None if reproduced else str(result.get("why_not_reproduced") or "recorded call did not reproduce"),
                       confined=not args.unconfined, as_json=args.json, pytest_export=export)
    except _UsageError as exc:
        if args.json:
            _render(status="USAGE ERROR", code=EXIT_USAGE, run_id=run_id, obligation_id=args.obligation,
                    base_commit=None, base_tree=None, post_tree=None, reason=str(exc), confined=not args.unconfined,
                    as_json=True, pytest_export=export, extra={"available_ids": exc.ids})
        else:
            print(f"hlith replay: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except _NotReplayable as exc:
        return _render(status="NOT REPLAYABLE", code=EXIT_NOT_REPLAYABLE, run_id=run_id, obligation_id=obligation_id,
                       base_commit=base_commit, base_tree=base_tree, post_tree=post_tree,
                       reason=str(exc), confined=not args.unconfined, as_json=args.json, pytest_export=export)
    except _BoundaryError as exc:
        return _render(status="NOT REPLAYABLE", code=EXIT_BOUNDARY, run_id=run_id, obligation_id=obligation_id,
                       base_commit=base_commit, base_tree=base_tree, post_tree=post_tree,
                       reason=str(exc), confined=not args.unconfined, as_json=args.json, pytest_export=export)
    except Exception as exc:  # noqa: BLE001 - the CLI must keep internal errors distinct from replay results
        if args.json:
            _render(status="INTERNAL ERROR", code=EXIT_INTERNAL, run_id=run_id, obligation_id=obligation_id,
                    base_commit=base_commit, base_tree=None if base_tree is None else str(base_tree),
                    post_tree=post_tree, reason=type(exc).__name__, confined=not args.unconfined, as_json=True,
                    pytest_export=export)
        else:
            print(f"hlith replay: internal error ({type(exc).__name__})", file=sys.stderr)
        return EXIT_INTERNAL
