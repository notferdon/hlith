# SPDX-License-Identifier: Apache-2.0
"""``hlith check``: read-only, UI-equivalent change selection and headless gate invocation.

A client of the operator session API (``operator.api``): it never imports ``cli`` or the engine, so the cli <-> check cycle is
gone. The run is a REHEARSAL in a disposable clone (never an original landing) over a SUPPLIED patch (headless ingestion:
never labelled an observed agent run)."""

from __future__ import annotations


import dataclasses
import hashlib
import sys
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

from ..hostio.integrity import HostIntegrityError
from ..textsafe import clean
from .policy import policy_summary, strict_requested
from .target_python import qualification, select_interpreter as _target_python_selection
from ..contract.errors import EXIT_BOUNDARY, EXIT_INTERNAL, EXIT_USAGE


def add_parser(sub):
    """Register this command's parser under the CLI's single owned line."""
    ck = sub.add_parser("check", help="select a repository change and run the gate without landing in the selected repository")
    ck.add_argument("--repo", type=Path, default=Path("."), help="repository to inspect (default: current directory)")
    ck.add_argument("--uncommitted", action="store_true", help="check uncommitted tracked edits and untracked files (default when no source is given)")
    ck.add_argument("--commit", metavar="SHA", help="check a single non-merge commit against its parent")
    ck.add_argument("--branch", metavar="NAME", help="check a local branch against its merge-base with --base or the default branch")
    ck.add_argument("--base", metavar="REF", help="base ref for --branch or full 40-char commit SHA for --patch")
    ck.add_argument("--patch", type=Path, metavar="FILE", help="check a unified git diff patch file against --base or HEAD")
    ck.add_argument("--manifest", type=Path, metavar="FILE", help="proposer manifest JSON paired with --patch (claim, never proof)")
    ck.add_argument("--approve-deltas", metavar="SHA256", help="authorize exactly the reviewed delta set in a new rehearsal")
    ck.add_argument("--patch-sha256", metavar="HEX", help="require these exact normalized patch bytes")
    ck.add_argument("--manifest-sha256", metavar="HEX", help="require these exact manifest bytes")
    ck.add_argument("--artifact-out", type=Path, metavar="DIR",
                    help="new directory for the artifact and captured inputs (created by hlith check; must not already exist)")
    ck.add_argument("--json", action="store_true", help="write machine-readable JSON in the versioned hlith.check/1 envelope")
    ck.add_argument("--target-venv", action="store_true", help="require a repository .venv/bin/python or venv/bin/python interpreter")
    ck.add_argument("--target-python", metavar="PATH", help="Python interpreter used inside confinement to execute target code")
    ck.add_argument("--no-input", action="store_true", help="accepted for scripts; hlith check runs headlessly in Hlith Review")
    ck.add_argument("--keep-clone", action="store_true", help="keep the disposable rehearsal clone directory after the check finishes")
    ck.add_argument("--include-tool-state", action="store_true",
                    help="also check untracked agent/tool-state files (.beads .ntm .serena .claude ...), which an uncommitted change leaves out by default")
    ck.add_argument("--strict-domain", action="store_true",
                    help="open-caller mode: refuse typed landing certificates unless both versions self-enforce exact builtin types at entry")
    return ck


ENVELOPE_CHECK = "hlith.check/1"


def _print_field(label: str, value: str) -> None:
    try:
        width = max(40, shutil.get_terminal_size((80, 24)).columns)
    except OSError:
        width = 80
    prefix = f"{label}: "
    wrapper = textwrap.TextWrapper(width=width, subsequent_indent=" " * len(prefix),
                                   break_long_words=True, break_on_hyphens=False)
    for line in wrapper.wrap(prefix + value):
        print(line)


def _print_cmd(label: str, argv: list[str]) -> None:
    """Print a copy-pasteable shell command wrapped at token boundaries with `\\` continuations."""
    try:
        width = max(40, shutil.get_terminal_size((80, 24)).columns)
    except OSError:
        width = 80
    rendered = shlex.join(argv)
    if len(label) + 2 + len(rendered) <= width:
        print(f"{label}: {rendered}")
        return
    indent = "  "
    lines: list[str] = []
    cur = f"{label}:"
    for tok in (shlex.quote(a) for a in argv):
        if len(cur) + 1 + len(tok) + 2 <= width:
            cur = f"{cur} {tok}"
        elif cur != f"{label}:":
            lines.append(cur + " \\")
            cur = indent + tok
        else:
            cur = f"{cur} {tok}"
    lines.append(cur)
    for line in lines:
        if len(line) <= width:
            print(line)
        else:
            for chunk in textwrap.wrap(line, width=width, subsequent_indent=indent,
                                       break_long_words=True, break_on_hyphens=False):
                print(chunk)


class BoundaryError(ValueError):
    pass


class UsageError(BoundaryError):
    pass


def _git(repo: Path, *args: str) -> str:
    from .tui import gitq

    return gitq.read_text(repo, *args)


def _git_optional(repo: Path, *args: str) -> str:
    from .tui import gitq

    return gitq.optional_text(repo, *args) or ""


def select_change(repo: Path, *, uncommitted=False, commit=None, branch=None, base=None, patch=None, manifest=None, include_tool_state=False):
    """Build the exact base+patch tuple using the TUI's discovery/diff machinery."""
    from .tui import changes, gitq

    repo = Path(repo).resolve()
    selected = sum(bool(x) for x in (uncommitted, commit, branch, patch))
    if selected != 1:
        raise BoundaryError("select exactly one change source")
    if not repo.exists():
        raise UsageError(f"repository path does not exist: {repo}")
    if not repo.is_dir():
        raise BoundaryError(f"repository path is not a directory: {repo}")
    try:
        (repo / ".git").lstat()
    except FileNotFoundError:
        raise BoundaryError(f"not a git repository: {repo}") from None
    gitq.require_supported_git()
    refusal = gitq.refusal(repo)
    if refusal:
        raise BoundaryError(refusal)
    if uncommitted:
        conflict_why = gitq.merge_conflict_reason(repo)
        if conflict_why:
            raise BoundaryError(conflict_why)
        change = changes.uncommitted(repo)
        if change is None:
            raise UsageError("there is no uncommitted change to select")
        left_out = [] if include_tool_state or change.problem else changes.tool_state_paths(change)
        if left_out:
            if len(left_out) == len(change.infos):
                raise BoundaryError("the only uncommitted changes are untracked agent/tool-state files (" + ", ".join(sorted(left_out)[:4])
                                    + "), left out by default; pass --include-tool-state to check them")
            change.default_excluded = tuple(left_out)  # explicit, never silent: named in the output and the envelope
    elif commit:
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", str(commit)):
            raise BoundaryError("--commit needs a hexadecimal commit SHA (7 or more digits)")
        resolved = _git_optional(repo, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
        if not resolved:
            raise BoundaryError(f"commit does not resolve to a commit: {commit}")
        parents = _git(repo, "rev-list", "--parents", "-n", "1", resolved).split()
        if len(parents) > 2:
            raise BoundaryError("merge commit has no single-parent base; select the branch or pick a non-merge commit")
        if len(parents) != 2:
            raise BoundaryError("root commit: no base to apply it on")
        change = changes.Change("commit", resolved, parents[1], b"")
        changes.scan(repo, [parents[1], resolved], {}, change)
    elif branch:
        names = set(_git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines())
        if branch not in names:
            raise BoundaryError(f"branch is not a local selectable branch: {branch}")
        branch_base = base or changes._default_branch(repo)
        if not branch_base or not _git_optional(repo, "rev-parse", "--verify", "--quiet", f"{branch_base}^{{commit}}"):
            raise BoundaryError(f"branch base does not resolve to a commit: {branch_base or '(none)'}")
        merge_base = _git_optional(repo, "merge-base", branch_base, branch)
        tip = _git_optional(repo, "rev-parse", "--verify", "--quiet", f"{branch}^{{commit}}")
        if not merge_base or not tip or merge_base == tip:
            raise BoundaryError("branch has no change relative to its base")
        change = changes.Change("branch", f"branch {branch}", merge_base, b"")
        changes.scan(repo, [merge_base, tip], {}, change)
    else:
        patch_path = Path(patch).resolve()
        try:
            data = patch_path.read_bytes()
        except FileNotFoundError as e:
            raise UsageError(f"operator input does not exist: {e.filename or patch_path}") from e
        except OSError as e:
            raise BoundaryError(f"cannot read patch: {e}") from e
        if base and not re.fullmatch(r"[0-9a-fA-F]{40}", str(base)):
            raise BoundaryError("a patch --base must be a full commit SHA")
        head = _git_optional(repo, "rev-parse", "--verify", "--quiet", f"{base or 'HEAD'}^{{commit}}")
        if not head:
            raise BoundaryError("repository does not contain the patch base commit")
        from .patchnorm import normalize_patch

        norm = normalize_patch(data)  # only the bytes before the first 'diff --git ' line (mbox header, commit message); recorded
        change = changes._patch_change(f"patch file {patch_path.name}", head, patch_path, norm.applied)
        change.preamble = norm
        if not change.files:
            raise BoundaryError("not a git diff (no files recognised)")
        if manifest is not None:
            try:
                manifest_text = Path(manifest).read_text()
            except FileNotFoundError as e:
                raise UsageError(f"operator input does not exist: {e.filename or manifest}") from e
            except OSError as e:
                raise BoundaryError(f"cannot read valid manifest JSON: {e}") from e
            try:
                json.loads(manifest_text)
            except ValueError as e:
                raise BoundaryError(f"cannot read valid manifest JSON: {e}") from e
    if change._git_error is not None:
        raise change._git_error
    if change.problem:
        raise BoundaryError(change.problem)
    try:
        patch_bytes = change.diff()
    except changes.TooBig as e:
        raise BoundaryError(f"selected change exceeds the engine patch limit: {e}") from e
    if not patch_bytes:
        raise BoundaryError("selected change has an empty diff")
    # Keep the same Change object shape returned by the TUI selector; callers that
    # need a scoped large diff can call .diff() just as the screen does.
    change.patch = patch_bytes
    return change


def _private_result_dir(repo: Path, requested: Path | None) -> tuple[Path, bool]:
    if requested is None:
        root = Path(tempfile.gettempdir()).resolve()
        path = Path(tempfile.mkdtemp(prefix="hlith-check-", dir=root))
        path.chmod(0o700)
        if path == repo or repo in path.parents or path in repo.parents:
            shutil.rmtree(path, ignore_errors=True)
            raise BoundaryError("private result directory must be outside the selected repository")
        return path, True
    path = Path(requested).expanduser().resolve()
    resolved = path
    if resolved == repo or repo in resolved.parents or resolved in repo.parents:
        raise BoundaryError("--artifact-out must be outside the selected repository")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)
    return path, False


def _clean_checkout(source: Path, clone: Path, base: str) -> tuple[bool, str]:
    from .tui.launch import _clone_source

    return _clone_source(source, clone, base)


def _target_python_observation(artifact: dict) -> dict[str, str | None]:
    """Consume the optional confined-worker observation when present; never infer the target version on the host."""
    observed = artifact.get("target_python") if isinstance(artifact, dict) else None
    if not isinstance(observed, dict):
        return {"version": "not recorded", "executable": None}
    version = observed.get("version")
    executable = observed.get("executable")
    return {
        "version": version if isinstance(version, str) else "not recorded",
        "executable": executable if isinstance(executable, str) else None,
    }


def _follow_up(repo: Path, base: str, patch: Path, manifest: Path, patch_sha: str,
               manifest_sha: str, artifact: dict, result_dir: Path,
               target_python: str | None, *, strict_domain: bool = False) -> list[str] | None:
    status = artifact.get("exit_status")
    delta_sha = (artifact.get("effect") or {}).get("delta_set_sha256")
    confirmation = ((artifact.get("deltas") or {}).get("confirmation") or {})  # format 1
    unconfirmed = [o for o in artifact.get("obligations") or []  # format 2: the deltas-confirmed obligation says so
                   if o.get("id") == "deltas-confirmed" and "no independent confirmer" in str(o.get("stop_reason") or "")]
    needs_approval = bool(delta_sha and ("no independent confirmer" in str(confirmation.get("reason") or "") or unconfirmed))
    if status == 0 or not needs_approval:
        return None
    cmd = ["hlith", "check", "--no-input", "--repo", str(repo), "--patch", str(patch), "--manifest", str(manifest),
           "--base", base, "--patch-sha256", patch_sha, "--manifest-sha256", manifest_sha, "--approve-deltas", str(delta_sha)]
    if target_python:
        cmd += ["--target-python", target_python]
    if strict_domain:
        cmd += ["--strict-domain"]
    return [shlex.join(cmd)]


def _rehearse_inline(api, req, *, clone: Path, patch_bytes: bytes, patch_path: Path, manifest_path: Path, preamble,
                     target_python, strict_domain: bool, approve_deltas: str | None):
    """P2.6: the review rehearsal runs IN THIS PROCESS through the trusted pipeline (``OperatorApi.run_inline`` with
    ``default_capabilities``), landing only in the disposable ``clone`` that ``check`` itself created. No engine child process, no
    caller-supplied marker, environment token or capability record: nothing outside ``check`` can ask for a landing.

    Returns (launch_dir, run_dir | None, rc, stdout, stderr) with the same meaning as the former engine launch."""
    import contextlib
    import io
    import os

    from ..contract.errors import EXIT_BOUNDARY, EXIT_INTERNAL, EXIT_USAGE
    from . import store
    from .capabilities import ProbeBridgeUnavailable, default_capabilities, intent_from_manifest, proposer_private_paths
    from .coordinator import RequestError
    from .patchnorm import normalize_patch
    from .state import HostIntegrityError

    norm = normalize_patch(patch_bytes)
    patch_norm = norm.record()
    if preamble is not None and preamble.stripped_bytes:  # provenance: what the input file was, how much was removed before review
        patch_norm = {"input_patch_sha256": preamble.input_sha256, "applied_patch_sha256": norm.applied_sha256,
                      "preamble_removed_bytes": int(preamble.stripped_bytes) + norm.stripped_bytes}
    manifest = json.loads(manifest_path.read_text())
    req = dataclasses.replace(req, patch=norm.applied, manifest=manifest, patch_normalization=patch_norm)
    # the blinded differential must be unable to read the reviewed inputs; an empty list makes it refuse (never padded)
    proposer_paths = proposer_private_paths([], [], patch_path, manifest_path, None)
    launch = api.new_launch_dir(req.repo)
    (launch / "cmd.txt").write_text(f"in-process check rehearsal: clone={clone} patch={patch_path} manifest={manifest_path}\n")

    def link(run_dir, receipt) -> None:
        store.write_new(launch / "engine-run.json", json.dumps({"run_id": str(receipt.run_id), "run_dir": str(run_dir)}).encode() + b"\n")

    out_buf, err_buf = io.StringIO(), io.StringIO()
    prev_strict = os.environ.get("HLITH_CERT_STRICT_DOMAIN")
    if strict_domain:
        os.environ["HLITH_CERT_STRICT_DOMAIN"] = "1"
    run_dir, rc = None, EXIT_BOUNDARY
    try:
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):  # --json stdout stays one envelope
            try:
                outcome = api.run_inline(req, default_capabilities(state_root=api.state.root, python=target_python,
                                                                   proposer_paths=proposer_paths,
                                                                   intent=intent_from_manifest(manifest, approve_deltas)),
                                         on_start=link)
                rc, run_dir = outcome.exit_status, outcome.run_dir
                for problem in outcome.problems:
                    print(clean(f"hlith: {problem}"), file=sys.stderr)
            except RequestError as e:
                rc = EXIT_USAGE
                print(clean(f"hlith: {e}"), file=sys.stderr)
            except (ProbeBridgeUnavailable, HostIntegrityError) as e:
                rc = EXIT_BOUNDARY
                print(clean(f"hlith: boundary: {e}"), file=sys.stderr)
            except Exception as e:  # noqa: BLE001 - an engine fault is a finished INTERNAL ERROR (exit 3), never a landing or a traceback
                rc, run_dir = EXIT_INTERNAL, None
                print(clean(f"hlith: internal error: the review engine failed ({type(e).__name__}: {e}); nothing was decided"),
                      file=sys.stderr)
    finally:
        if strict_domain:
            if prev_strict is None:
                os.environ.pop("HLITH_CERT_STRICT_DOMAIN", None)
            else:
                os.environ["HLITH_CERT_STRICT_DOMAIN"] = prev_strict
    out_text, err_text = out_buf.getvalue(), err_buf.getvalue()
    (launch / "stdout.log").write_text(out_text)
    (launch / "stderr.log").write_text(err_text)
    store.write_new(launch / "rc", f"{rc}\n".encode())
    return launch, run_dir, rc, out_text, err_text


def execute(args, api=None) -> int:
    from ..contract.runs import LandingTarget, RunMode
    from . import presentation
    from .api import OperatorApi
    from .coordinator import RunRequest

    api = api or OperatorApi()
    repo = Path(args.repo).expanduser().resolve()
    result_dir = None
    clone = None
    keep_clone = bool(getattr(args, "keep_clone", False))
    try:
        if args.base and not (args.branch or args.patch):
            raise BoundaryError("--base requires --branch or --patch")
        if args.manifest and not args.patch:
            raise BoundaryError("--manifest requires --patch")
        selected_python, python_source, target_python = _target_python_selection(repo, args.target_python)
        if args.target_venv and target_python is None:
            raise BoundaryError("--target-venv requires .venv/bin/python or venv/bin/python in the selected repository")
        source_selected = bool(args.uncommitted or args.commit or args.branch or args.patch)
        change = select_change(repo, uncommitted=args.uncommitted or not source_selected, commit=args.commit,
                               branch=args.branch, base=args.base, patch=args.patch,
                               manifest=args.manifest, include_tool_state=args.include_tool_state)
        patch_bytes = change.diff()
        from .tui.claim import derive as derive_claim
        generated_manifest = {"paths": derive_claim(patch_bytes)}
        result_dir, _temporary = _private_result_dir(repo, args.artifact_out)
        patch_path = result_dir / "change.patch"
        manifest_path = result_dir / "claim.manifest.json"
        patch_path.write_bytes(patch_bytes)
        if args.manifest:
            manifest_path.write_bytes(Path(args.manifest).read_bytes())
        else:
            manifest_path.write_text(json.dumps(generated_manifest, indent=1) + "\n")
        (result_dir / "base.txt").write_text(change.base_rev + "\n")
        clone = result_dir / "clone"
        ok, reason = _clean_checkout(repo, clone, change.base_rev)
        if not ok:
            raise BoundaryError(f"could not create disposable clone: {reason}")
        patch_sha = hashlib.sha256(patch_bytes).hexdigest()
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        for label, actual in (("patch", patch_sha), ("manifest", manifest_sha)):
            expected = getattr(args, label + "_sha256", None)
            if expected is not None and expected != actual:
                raise BoundaryError(f"{label} SHA-256 differs from the reviewed input")
        # headless ingestion of a SUPPLIED patch, run as a REHEARSAL in the disposable clone
        req = RunRequest(repo=repo, engine_repo=clone, mode=RunMode.HEADLESS, landing_target=LandingTarget.REHEARSAL,
                         patch=patch_bytes, manifest=json.loads(manifest_path.read_text()), label=change.label)

        strict_domain = strict_requested(getattr(args, "strict_domain", False))

        launch, run_dir, rc, out_text, err_text = _rehearse_inline(
            api, req, clone=clone, patch_bytes=patch_bytes, patch_path=patch_path, manifest_path=manifest_path,
            preamble=getattr(change, "preamble", None), target_python=target_python, strict_domain=strict_domain,
            approve_deltas=getattr(args, "approve_deltas", None))
        insp = api.inspect(run_dir) if run_dir is not None else None
        artifact = insp.view.artifact if insp is not None else None
        artifact_path = result_dir / "out.json"
        if artifact is None:  # nothing was judged (no run, or no artifact): record that honestly, with the engine's own words
            artifact = {"verdict": "INTERNAL ERROR" if rc == EXIT_INTERNAL else "BOUNDARY", "exit_status": rc,
                        "reason": (err_text.strip() or out_text.strip())[:2000]}
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n")
        from . import store as _store
        receipt = _store.read_receipt(run_dir) if run_dir is not None else None
        headline = insp.label if insp is not None else ("INTERNAL ERROR" if rc == EXIT_INTERNAL else "BOUNDARY UNAVAILABLE")
        notes = list(insp.notes) if insp is not None else [(err_text.strip() or out_text.strip())[:300]]
        run_state = insp.view.state.value if insp is not None else "boundary-unavailable"
        run_id = str(receipt.run.run_id) if receipt is not None else None
        target_label = receipt.run.landing_target.value if receipt is not None else "rehearsal"
        python_observation = _target_python_observation(artifact)
        target_python_info = {"path": selected_python, "selection_source": python_source,
                              "version": python_observation["version"],
                              "executable": python_observation["executable"]}
        follow = _follow_up(repo, change.base_rev, patch_path, manifest_path, patch_sha, manifest_sha, artifact,
                            result_dir, target_python, strict_domain=strict_domain)
        from . import identity as _identity

        obs_list = artifact.get("obligations") or []
        has_replayable_witness = any(isinstance(o, dict) and isinstance(o.get("witness_call"), dict) for o in obs_list)
        replay_argv = (["hlith", "replay", str(run_id), "--repo", str(repo)]
                       if run_id and has_replayable_witness else None)
        inspect_argv = ["hlith", "inspect", str(run_id), "--repo", str(repo)] if run_id else None
        apply_argv = (
            ["hlith", "apply", "--repo", str(repo), "--rehearsal-artifact", str(artifact_path),
             "--patch", str(patch_path), "--manifest", str(manifest_path),
             *(["--target-python", str(target_python)] if target_python else []),
             *(["--strict-domain"] if strict_domain else [])]
            if int(artifact.get("exit_status", rc)) == 0 and artifact.get("outcome") == "landed"
            else None
        )
        replay_cmd = shlex.join(replay_argv) if replay_argv else None
        inspect_cmd = shlex.join(inspect_argv) if inspect_argv else None
        from .product import REVIEW_ONLY
        apply_cmd = None if REVIEW_ONLY or not apply_argv else shlex.join(apply_argv)
        # versioned envelope: the canonical artifact is carried UNCHANGED under "artifact"; check-only fields live under "check",
        # so scripts can evolve them without blurring them into verdict evidence.
        final_status = int(artifact.get("exit_status", rc))
        blocking_list = artifact.get("blocking") if isinstance(artifact.get("blocking"), list) else []
        boundary_kind = (
            str(blocking_list[0])
            if final_status == EXIT_BOUNDARY and blocking_list and isinstance(blocking_list[0], str)
            else None
        )
        check_block = {"build": _identity.build_identity(),
                       "artifact_path": str(artifact_path), "base_commit": change.base_rev,
                       "run_id": run_id, "run_state": run_state,
                       "landing_target": target_label, "input_origin": "supplied-patch",
                       "domain_policy": "strict" if strict_domain else "scoped",
                       "target_python": target_python_info,
                       "headline": headline, "headline_notes": notes,
                       "change": {"kind": change.kind, "label": change.label, "files": len(change.files) - len(change.default_excluded)},
                       "excluded_tool_state": sorted(change.default_excluded),
                       "replay_command": replay_cmd, "inspect_command": inspect_cmd, "apply_command": apply_cmd,
                       "follow_up": follow, "clone_path": str(clone) if keep_clone else None}
        if boundary_kind is not None:
            check_block["boundary_kind"] = boundary_kind
        payload = {"envelope": ENVELOPE_CHECK, "exit_status": final_status,
                   "artifact": artifact,
                   "check": check_block}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            _print_field("Decision", f"{clean(headline)} exit={rc}")
            _print_field("Repository", ascii(str(repo)))
            _print_field("Source label", ascii(clean(change.label)))
            _print_field("Landing target", "REHEARSAL (disposable clone; this command does not apply to the selected repository)")
            _print_field("Domain policy", policy_summary(strict_domain))
            _print_field("Target Python", f"effective path {ascii(selected_python)} · selection source {python_source} · "
                         f"version: {python_observation['version']} · {qualification(python_observation['version'])}")
            if python_observation["executable"] is not None and python_observation["executable"] != selected_python:
                _print_field("Target Python worker executable", ascii(python_observation["executable"]))
            if change.default_excluded:
                _print_field("Left out", "untracked agent/tool-state files, not checked: " + ", ".join(ascii(p) for p in sorted(change.default_excluded))
                             + " (pass --include-tool-state to check them)")
            if not obs_list and blocking_list:
                _print_field("Boundary", clean(": ".join(str(b) for b in blocking_list)))
            for n in notes:
                _print_field("Note", clean(n))
            from .tui import feedback_view

            if feedback_view.worth_a_row(artifact):
                _print_field("Feedback", clean(feedback_view.summary(artifact) or "see inspect for limits"))
                if pin_note := feedback_view.pinned_note(artifact):
                    _print_field("Stored input", clean(pin_note))
            obs = obs_list
            print(f"obligations: {len(obs)}")
            from .disclosure import annotation_bound

            bound = annotation_bound(obs)
            if bound and any(o.get("verdict") == "held" for o in obs):
                print("not checked: " + bound)
            for ob in obs:
                if ob.get("witness"):
                    _print_field("Witness", clean(str(ob["witness"])))
                reason = ob.get("stop_reason") or ""
                if reason:
                    _print_field("Reason", clean(str(reason)))
                if ob.get("id") != "deltas-confirmed" and ob.get("verdict") != "held":
                    ctx = {"delta_set_sha256": (artifact.get("effect") or {}).get("delta_set_sha256")}
                    _print_field("Next", clean(presentation._next_step(ob, ctx)))
            _print_field("Run", f"{run_id or '-'} · artifact {artifact_path}")
            if replay_argv:
                _print_cmd("Replay witness", replay_argv)
            if inspect_argv:
                _print_cmd("Inspect run", inspect_argv)
            if apply_argv and apply_cmd:
                _print_cmd("Apply review", apply_argv)
            if follow:
                for command in follow:
                    _print_cmd("Rehearse approved changes", shlex.split(command))
            if keep_clone:
                _print_field("Clone", str(clone))
        return int(artifact.get("exit_status", rc))
    except UsageError as e:
        if result_dir is not None and not (result_dir / "out.json").exists():
            shutil.rmtree(result_dir, ignore_errors=True)
        if args.json:
            print(json.dumps({"envelope": ENVELOPE_CHECK, "exit_status": EXIT_USAGE, "artifact": None,
                              "check": {"run_state": "input-error", "reason": clean(str(e))}}, sort_keys=True))
        else:
            print(f"hlith: usage: {clean(str(e))}", file=sys.stderr)
        return EXIT_USAGE
    except (BoundaryError, OSError, subprocess.SubprocessError, ValueError, HostIntegrityError) as e:
        if result_dir is not None and not (result_dir / "out.json").exists():
            shutil.rmtree(result_dir, ignore_errors=True)
        if args.json:
            check_meta = {"run_state": "boundary-unavailable", "reason": clean(str(e))}
            err_kind = getattr(e, "kind", None)
            if err_kind is not None:
                check_meta["boundary_kind"] = getattr(err_kind, "value", str(err_kind))
            print(json.dumps({"envelope": ENVELOPE_CHECK, "exit_status": EXIT_BOUNDARY, "artifact": None,
                              "check": check_meta}, sort_keys=True))
        else:
            print(f"hlith: boundary: {clean(str(e))}", file=sys.stderr)
        return EXIT_BOUNDARY
    finally:
        if clone and clone.exists() and not keep_clone:
            shutil.rmtree(clone, ignore_errors=True)
