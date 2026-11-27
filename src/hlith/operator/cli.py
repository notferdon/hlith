# SPDX-License-Identifier: Apache-2.0
"""``hlith``: the user-facing dispatcher.

Owns the operator surfaces (``ui``, ``check``, ``inspect``, ``replay``, ``status``, ``history``, ``doctor``). Hlith Review offers no
engine write command (``run``, ``resume``, ``propose-deltas``, ``apply`` are not commands; P2.6): ``check`` rehearses in-process in a
disposable clone it creates itself. ``engine_cli`` imports none of the surfaces, which keeps cli, check and the TUI acyclic.

Engine names that unmigrated callers read from ``hlith.cli`` (``main`` aside) are re-exported READ-ONLY from ``engine_cli``; a
test or caller that monkeypatches engine internals must patch ``hlith.operator.engine_cli``.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import stat
import sys
import textwrap
from pathlib import Path

from ..contract.errors import EXIT_USAGE
from .labels import source_label
from . import engine_cli as _engine
from .engine_cli import *  # noqa: F401,F403
from .engine_cli import (  # noqa: F401
    DeltaConfirmation, PipelineResult, _cache_stats, _derive_proposer_paths, _guard_proposer_argv, _propose_layer1,
    _rerun_command, account_block, build_artifact, confirm_deltas, dirty_repo_reason, incident_obligation,
    no_declaration, recover_pending_landing, run_pipeline, unwired_obligations, INDEX_CACHE_ALWAYS,
)

ENGINE_COMMANDS = ()  # P2.6: no engine write command is reachable from `hlith`
_INTERACTIVE_CHECK_ONLY_FLAGS = ("--base", "--manifest", "--target-venv", "--json", "--artifact-out", "--keep-clone", "--approve-deltas", "--patch-sha256", "--manifest-sha256")


def _terminal_columns() -> int:
    try:
        return max(40, shutil.get_terminal_size((80, 24)).columns)
    except OSError:
        return 80


def _print_field(label: str, value: str) -> None:
    prefix = f"{label}: "
    wrapper = textwrap.TextWrapper(width=_terminal_columns(), subsequent_indent=" " * len(prefix),
                                   break_long_words=True, break_on_hyphens=False)
    for line in wrapper.wrap(prefix + value):
        print(line)


def _landing_target_display(artifact) -> str:
    run = artifact.get("run") if isinstance(artifact, dict) else None
    target = run.get("landing_target") if isinstance(run, dict) else None
    return {"original": "ORIGINAL", "rehearsal": "REHEARSAL"}.get(target, "not recorded")


def _target_python_display(artifact) -> str:
    observed = artifact.get("target_python") if isinstance(artifact, dict) else None
    if not isinstance(observed, dict):
        return "path not recorded · selection source not recorded · version: not recorded"
    executable = observed.get("executable")
    version = observed.get("version")
    worker_path = ascii(executable) if isinstance(executable, str) else "not recorded"
    worker_version = version if isinstance(version, str) else "not recorded"
    return (f"worker executable {worker_path} · selection source not recorded · "
            f"version: {worker_version}")


def _interactive_check_source(args) -> str:
    if args.uncommitted or not any((args.commit, args.branch, args.patch)):
        return "uncommitted"
    if args.commit:
        return f"commit:{args.commit}"
    if args.branch:
        return f"branch:{args.branch}"
    return f"patch:{args.patch}"


def _interactive_check_problem(args) -> str | None:
    for flag in _INTERACTIVE_CHECK_ONLY_FLAGS:
        attr = flag[2:].replace("-", "_")
        if getattr(args, attr, None):
            return flag
    return None


def _interactive_check_source_problem(args) -> str | None:
    selected = sum(bool(value) for value in (args.uncommitted, args.commit, args.branch, args.patch))
    if selected > 1:
        return "check accepts exactly one change source"
    return None


def _interactive_check_commit_problem(args) -> str | None:
    if not args.commit:
        return None
    from .tui import gitq

    repo, reason = gitq.toplevel(args.repo.expanduser())
    if repo is None or reason or gitq.refusal(repo):
        return None  # the TUI owns repository selection/refusal and may use its remembered repository
    try:
        full = gitq.optional_text(repo, "rev-parse", "--verify", "-q", f"{args.commit}^{{commit}}")
        offered = gitq.read_text(repo, "log", "-n8", "--no-merges", "--format=%H").splitlines()
    except gitq.GitReadError:
        return None  # the TUI surfaces Git boundary failures on its blocked screen
    if not full or full not in offered:
        return (f"commit {ascii(args.commit)} is not offered; the Offer lists only the newest 8 non-merge commits")
    return None


def _interactive_check_argv(args) -> list[str]:
    argv = ["--repo", str(args.repo.expanduser())]
    if getattr(args, "strict_domain", False):
        argv.append("--strict-domain")
    if args.target_python:
        argv.extend(("--target-python", str(args.target_python)))
    argv.extend(("--check", _interactive_check_source(args)))
    return argv


def _open_interactive_check(args) -> int:
    """Open the interactive review screen; the terminal UI starts a run only after the review request is confirmed."""
    from .tui.host import main as ui_main

    return ui_main(_interactive_check_argv(args))


def _history_candidates(repo: Path):
    from .api import OperatorApi

    return OperatorApi().history_candidates(repo)


def _recorded_decision(directory: Path) -> tuple[str, int | None, str | None, dict | None]:
    from .tui import frame, launch, model

    is_launch = directory.name.startswith("launch-")
    record = launch.result(directory) if is_launch else model.load(directory / "out.json")
    if record is None or not record.usable or record.art is None:
        return "completed run record unavailable", None, None, None
    artifact = record.art
    run = artifact.get("run") or {}
    run_id = run.get("run_id")
    if not is_launch and run_id != directory.name:
        return "completed run record does not match its run directory", None, None, artifact
    label, _, status = frame._decision(artifact)
    if status is None or label.startswith("UNKNOWN"):
        return "completed run has no validated decision", None, None, artifact
    if label == "LANDED":
        target = {"rehearsal": "rehearsal clone", "original": "original repository"}
        label += f" · {target.get(run.get('landing_target'), 'landing target not recorded')}"
    return label, status, run_id, artifact


def _latest_decision(repo: Path) -> tuple[str, int | None, dict[str, str]]:
    from .state import HostIntegrityError
    from .tui import launch
    from .tui.host import _record_age

    try:
        candidates, _, _, _, _ = _history_candidates(repo)
        finished = next((run for _, path in candidates if (run := launch.status(path))["state"] == "finished"), None)
    except (HostIntegrityError, OSError, ValueError):
        return "history unavailable", None, {"source_label": "not recorded", "landing_target": "not recorded",
                                              "target_python": "path not recorded · selection source not recorded · version: not recorded"}
    if finished is None:
        return "no completed run in available history", None, {"source_label": "not recorded", "landing_target": "not recorded",
                                                                "target_python": "path not recorded · selection source not recorded · version: not recorded"}

    label, status, run_id, artifact = _recorded_decision(finished["run_dir"])
    if status is None:
        status = None
    else:
        when = launch._credible_started(finished["meta"].get("started"))
        age = _record_age(when) if when is not None else "age not recorded"
        label = f"{label} · exit {status} · {ascii(run_id)} · {age}"
    selected = source_label(artifact, finished.get("meta"))
    return label, status, {"source_label": ascii(selected) if selected else "not recorded",
                           "landing_target": _landing_target_display(artifact),
                           "target_python": _target_python_display(artifact)}


def _effective_state_root() -> Path:
    from .state import state_root

    return state_root().absolute()


def _pending_journal_check(repo: Path, state_root: Path) -> tuple[bool, str]:
    """Read-only inspection for an interrupted gate landing journal (creates nothing, spawns nothing)."""
    import hashlib
    from .product import REVIEW_ONLY

    git_dir = repo / ".git"
    legacy = git_dir / "hlith-journal.json"
    if legacy.exists() or legacy.is_symlink():
        if REVIEW_ONLY:
            return False, (f"interrupted legacy landing journal present at {ascii(str(legacy))}; "
                           "Hlith Review is read-only and does not recover landings; inspect git status/HEAD manually")
        return False, f"interrupted legacy landing journal present at {ascii(str(legacy))}; run hlith run/apply to verify and recover safely"
    repos_dir = state_root / "repositories"
    if repos_dir.is_dir() and git_dir.is_dir() and not git_dir.is_symlink():
        try:
            tkey = hashlib.sha256(str(git_dir.resolve()).encode("utf-8")).hexdigest()[:24]
            for jdir in repos_dir.glob("*/journal"):
                for cand in (jdir / f"landing-{tkey}.json", jdir / "landing.json"):
                    if cand.exists() or cand.is_symlink():
                        if REVIEW_ONLY:
                            return False, ("interrupted landing journal pending; "
                                           "Hlith Review is read-only and does not recover landings; inspect git status/HEAD manually")
                        return False, "interrupted landing journal pending; inspect git status/HEAD or run hlith run/apply to verify and recover safely"
        except OSError:
            pass
    return True, "clean (no interrupted landing pending)"


def _plain_status(*, exit_code: bool, repo_path: Path = Path("."), as_json: bool = False) -> int:
    from . import gitq, identity

    repo, reason = gitq.toplevel(repo_path.expanduser())
    status = None
    if repo is None:
        repository = {"path": None, "problem": reason}
        latest = None
    else:
        decision, status, provenance = _latest_decision(repo)
        repository = {"path": str(repo), "problem": None}
        latest = {"summary": decision, "exit_status": status}
    if repo is None:
        provenance = {"source_label": "not recorded", "landing_target": "not recorded",
                      "target_python": "path not recorded · selection source not recorded · version: not recorded"}
    command_status = (status if status is not None else 3) if exit_code else 0
    if as_json:
        print(json.dumps({"envelope": "hlith.status/1", "build": identity.build_identity(),
                          "state_dir": str(_effective_state_root()), "repository": repository,
                          "latest_decision": latest, "provenance": provenance,
                          "command_exit_status": command_status}, sort_keys=True))
    else:
        if repo is None:
            _print_field("Repository", f"unavailable ({ascii(reason)})")
        else:
            _print_field("Repository", ascii(str(repo)))
            _print_field("Latest decision", latest["summary"])
        if latest is None or latest["summary"] != "no completed run in available history":
            run_provenance = (f"source label {provenance['source_label']} · landing target {provenance['landing_target']} · "
                              f"target Python {provenance['target_python']}")
            _print_field("Run provenance", run_provenance)
        from .product import REVIEW_ONLY

        check_repo = str(repo_path.expanduser())
        if check_repo.isprintable():
            _print_field("Check a change", f"hlith check --repo {shlex.quote(check_repo)}")
        if REVIEW_ONLY:
            _print_field("Check options", "hlith check --help")
        else:
            _print_field("Engine options", "hlith run --help")
    return command_status


def _run_history(repo_path: Path, *, as_json: bool) -> int:
    from . import gitq
    from .state import HostIntegrityError
    from .tui import launch

    repo, reason = gitq.toplevel(repo_path.expanduser())
    if repo is None:
        print(f"Repository unavailable ({ascii(reason)})", file=sys.stderr)
        return 2
    try:
        candidates, _, _, truncated, _ = _history_candidates(repo)
    except (HostIntegrityError, OSError, ValueError) as exc:
        print(f"History unavailable ({ascii(str(exc))})", file=sys.stderr)
        return 2

    engine_dirs = {path.resolve() for _, path in candidates if path.name.startswith("run-")}
    rows = []
    display_rows = []
    for _, directory in candidates:
        if directory.name.startswith("launch-") and launch._linked_engine_dir(directory) in engine_dirs:
            continue
        if len(rows) == launch._MAX_HISTORY_RUNS:
            truncated = True
            break
        run_status = launch.status(directory)
        state = run_status["state"]
        decision, exit_status = None, None
        artifact = None
        if state == "finished":
            decision, exit_status, _, artifact = _recorded_decision(directory)
        meta = run_status.get("meta")
        raw_label = source_label(artifact, meta)
        raw_target = ((artifact.get("run") or {}).get("landing_target") if isinstance(artifact, dict) else None)
        rows.append({"run_id": directory.name, "state": state, "exit_status": exit_status, "decision": decision,
                     "source_label": raw_label, "landing_target": raw_target})
        display_rows.append({"source_label": ascii(raw_label) if raw_label else "not recorded",
                             "landing_target": _landing_target_display(artifact),
                             "target_python": _target_python_display(artifact)})

    if as_json:
        print(json.dumps({"envelope": "hlith.history/1", "repository": str(repo),
                          "runs": rows, "truncated": truncated}))
        return 0
    _print_field("Repository", ascii(str(repo)))
    if not rows:
        print("No runs in available history.")
    else:
        for row, provenance in zip(rows, display_rows, strict=True):
            exit_text = row["exit_status"] if row["exit_status"] is not None else "-"
            _print_field("Run", f"{ascii(row['run_id'])} · {row['state']} · exit {exit_text}")
            _print_field("Source label", provenance["source_label"])
            _print_field("Landing target", provenance["landing_target"])
            _print_field("Target Python", provenance["target_python"])
            _print_field("Decision", ascii(row["decision"]) if row["decision"] else "not recorded")
    if truncated:
        print("History truncated.")
    return 0


def _state_readiness(root: Path) -> tuple[bool, str]:
    from ..hostio.integrity import HostIntegrityError, ensure_private_dir

    try:
        if root.exists() or root.is_symlink():
            directory = ensure_private_dir(root, create=False)
            detail = f"{ascii(str(root))}, write/search access"
        else:
            existing = []
            for parent in root.parents:
                if parent.exists() or parent.is_symlink():
                    if not stat.S_ISDIR(parent.lstat().st_mode):
                        return False, f"state ancestor is not a real directory: {ascii(str(parent))}"
                    existing.append(parent)
            directory = existing[0]
            detail = f"{ascii(str(root))} absent, nearest parent has write/search access"
        if not os.access(directory, os.W_OK | os.X_OK, effective_ids=True):
            return False, f"write/search access denied to {ascii(str(directory))}"
    except (HostIntegrityError, OSError) as exc:
        return False, ascii(str(exc))
    return True, detail


def _doctor(repo_path: Path, *, as_json: bool = False, target: str | None = None, probe=False, modules=()) -> int:
    from . import gitq, identity
    from .tui import repos
    from .tui.host import _readiness

    build_id = identity.build_identity()
    pkg_root = str(Path(__file__).resolve().parents[1])
    rows = [
        ("Build", True, f"{build_id} ({ascii(pkg_root)})"),
        ("Python", sys.version_info >= (3, 12), f"{sys.version.split()[0]} · {ascii(sys.executable)}"),
    ]
    try:
        import z3

        rows.append(("Z3", True, z3.get_version_string()))
    except (ImportError, OSError, AttributeError) as exc:
        rows.append(("Z3", False, ascii(str(exc))))
    git_probe = gitq.probe_git_features(fresh=True)
    if git_probe.ok:
        ver = f" · {git_probe.version}" if git_probe.version else ""
        git_detail = f"{ascii(git_probe.executable)}{ver} · required hardened features verified"
    else:
        exe_text = ascii(git_probe.executable) if git_probe.executable else "missing"
        ver = f" · {git_probe.version}" if git_probe.version else ""
        git_detail = f"{exe_text}{ver} · {git_probe.reason}"
    rows.append(("Git", git_probe.ok, git_detail))
    git_info = {
        "ok": git_probe.ok,
        "executable": git_probe.executable,
        "version": git_probe.version,
        "failed_feature": git_probe.failed_feature,
        "reason": git_probe.reason,
        "checks": [
            {"name": c.name, "ok": c.ok, "detail": c.detail, "returncode": c.returncode}
            for c in git_probe.checks
        ],
    }

    repo, reason = gitq.toplevel(repo_path.expanduser())
    if repo is not None:
        reason = gitq.refusal(repo)
    rows.append(("Repository", not reason, ascii(str(repo)) if not reason else ascii(reason)))
    from .target_python import probe_interpreter, select_interpreter
    from .state import ui_directory

    readiness, _ = _readiness(repo or repo_path.expanduser(), target)
    boundary = readiness["boundary"]
    rows.append(("Confinement settings", boundary["status"] == "ready",
                 f"{boundary['detail']} (kernel settings only)"))
    target_info = None
    if repo is not None and not reason:
        path, source, _ = select_interpreter(repo, target)
        level, detail = repos.python_readiness(repo)
        if target:
            level, detail = "ok", ""
        elif level == "ok" and detail.startswith("target python:"):
            detail = ""
        py = readiness["python"]
        available = py["status"] == "ready"
        declared = repos.declared_dependencies(repo)
        target_info = {"path": path, "selection_source": source, "venv_version_label": py.get("version"),
                       "declared_dependencies": declared, "probe": None}
        description = f"effective path {ascii(path)} · selection source {source} · version: not recorded (readiness only)"
        if py.get("version") and py["version"] != "not probed":
            description += f" · environment label {py['version']}"
        if probe or modules:
            ok, observed = probe_interpreter(path, list(modules))
            target_info["probe"] = observed
            if "version" in observed:
                imports = ", ".join(f"{name}={status}" for name, status in observed["imports"].items())
                description = (f"effective path {ascii(path)} · selection source {source} · confined Python {observed['version']}"
                               f" · {observed['qualification']} · imports {imports}")
                probed_keys = {name.lower().replace("-", "_") for name in observed["imports"]}
                unprobed = [dep for dep in declared if dep.lower().replace("-", "_") not in probed_keys]
                if unprobed:
                    description += " · declared deps not probed (--import): " + ", ".join(unprobed[:6])
            else:
                description += " · " + observed["error"]
            available = available and ok
        else:
            description += " · verify startup and imports with --probe-target (reference Python 3.13.9)"
        rows.append(("Target Python", level == "ok" and available,
                     description + (f" · {detail}" if detail else "")))
    else:
        rows.append(("Target Python", False, "repository unavailable"))

    root = _effective_state_root()
    ok, detail = _state_readiness(root)
    rows.append(("Host state", ok, detail))
    if repo is not None and not reason:
        j_ok, j_detail = _pending_journal_check(repo, root)
        rows.append(("Landing journal", j_ok, j_detail))
    command_status = int(not all(ready for _, ready, _ in rows))
    if as_json:
        print(json.dumps({"envelope": "hlith.doctor/1",
                          "build": {"identity": build_id, "package_root": pkg_root,
                                    "python": sys.executable, "python_version": sys.version.split()[0]},
                          "git": git_info,
                          "state_dir": str(root), "ui_state_dir": str(ui_directory()), "target_python": target_info,
                          "repository": str(repo_path.expanduser().resolve()),
                          "checks": [{"name": name, "status": "ok" if ready else "problem", "detail": detail}
                                     for name, ready, detail in rows],
                          "command_exit_status": command_status}, sort_keys=True))
    else:
        for name, ready, detail in rows:
            _print_field("Hlith Python" if name == "Python" else name,
                         f"{'ok' if ready else 'problem'} · {detail}")
    return command_status


def main(argv: list[str] | None = None, *, _prepared_run=None) -> int:
    args_in = sys.argv[1:] if argv is None else list(argv)
    no_input = "--no-input" in args_in
    if no_input:
        # Treat the cross-command no-prompt switch as a global option wherever it appears.
        args_in = [arg for arg in args_in if arg != "--no-input"]
    head = args_in[:1]
    if all(arg in ("--exit-code", "--json") for arg in args_in):
        if not args_in and not no_input and sys.stdin.isatty() and sys.stdout.isatty():
            from .tui.host import _terminal_can_run_screen, main as ui_main

            if _terminal_can_run_screen(os.environ):
                return ui_main([])
        return _plain_status(exit_code="--exit-code" in args_in, as_json="--json" in args_in)
    # P2.6: run/resume/propose-deltas/apply are not commands of Hlith Review (argparse rejects them as invalid choices, exit 2)
    if head == ["ui"]:  # operator TUI (stdlib curses)
        if no_input:
            repo_path = Path(".")
            for i, value in enumerate(args_in[1:]):
                if value == "--repo" and i + 1 < len(args_in[1:]):
                    repo_path = Path(args_in[1:][i + 1])
                    break
                if value.startswith("--repo="):
                    repo_path = Path(value.split("=", 1)[1])
                    break
            return _plain_status(exit_code=False, repo_path=repo_path)
        from .tui.__main__ import main as ui_main

        return ui_main(args_in[1:])
    ap = argparse.ArgumentParser(
        prog="hlith",
        description="Hlith Review: catches behavior and contract changes your tests miss. Review-only; no Apply.",
        epilog="Use hlith --no-input for plain status, hlith --exit-code to return its recorded decision code, "
               "or hlith COMMAND --help for command options.",
    )
    class _Version(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            from . import identity  # one source with the Offer first screen; plain file reads, no repository and no process

            print("hlith " + identity.build_identity())
            parser.exit(0)

    ap.add_argument("--version", action=_Version, nargs=0, help="print the build identity and exit")
    from .product import REVIEW_ONLY

    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser(
        "ui",
        help=("open the terminal screen to view repository status and recorded runs (does not start checks; hlith ui --help)"
              if REVIEW_ONLY else "open the terminal screen to check a real change in this repository (hlith ui --help)"),
        add_help=False,
    )
    from .check import add_parser as add_check_parser
    from .inspect_cmd import add_parsers as add_inspect_parsers
    from .replay_cmd import add_parser as add_replay_parser

    add_check_parser(sub)
    add_inspect_parsers(sub)
    add_replay_parser(sub)
    status = sub.add_parser("status", help="show a repository's latest recorded decision")
    history = sub.add_parser("history", help="list recorded runs for a repository")
    doctor = sub.add_parser("doctor", help="show host and repository readiness")
    for parser in (status, history, doctor):
        parser.add_argument("--repo", type=Path, default=Path("."), help="repository path (default: current directory)")
    status.add_argument("--exit-code", action="store_true", help="return the recorded decision code, or 3 if unavailable")
    status.add_argument("--json", action="store_true", help="write the versioned status envelope")
    history.add_argument("--json", action="store_true", help="write structured run history")
    doctor.add_argument("--target-python", help="use the same target interpreter as check")
    doctor.add_argument("--probe-target", action="store_true", help="observe target Python and import pytest inside confinement")
    doctor.add_argument("--import", action="append", default=[], dest="modules", metavar="MODULE",
                        help="also verify a target dependency imports inside confinement (repeatable)")
    doctor.add_argument("--json", action="store_true", help="write structured readiness checks")
    args = ap.parse_args(args_in)
    if args.cmd == "status":
        return _plain_status(repo_path=args.repo, exit_code=args.exit_code, as_json=args.json)
    if args.cmd == "history":
        return _run_history(args.repo, as_json=args.json)
    if args.cmd == "doctor":
        return _doctor(args.repo, as_json=args.json, target=args.target_python, probe=args.probe_target, modules=args.modules)
    if args.cmd == "replay":
        from .replay_cmd import execute as execute_replay

        return execute_replay(args)
    if args.cmd == "check":
        from .product import REVIEW_ONLY
        # P2.6: Hlith Review cannot start a check from the terminal screen, so `hlith check` is headless on a TTY too
        # (the former interactive Claim would end at "start unavailable"); --no-input is accepted and changes nothing.
        if not REVIEW_ONLY and not no_input and sys.stdin.isatty() and sys.stdout.isatty():
            source_problem = _interactive_check_source_problem(args)
            if source_problem:
                print(f"hlith: {source_problem}; use --no-input for a headless check", file=sys.stderr)
                return EXIT_USAGE
            unsupported = _interactive_check_problem(args)
            if unsupported:
                print(f"hlith: check on a TTY cannot represent {unsupported}; use --no-input for a headless check",
                      file=sys.stderr)
                return EXIT_USAGE
            commit_problem = _interactive_check_commit_problem(args)
            if commit_problem:
                print(f"hlith: usage: {commit_problem}; use --no-input for a headless check", file=sys.stderr)
                return EXIT_USAGE
            return _open_interactive_check(args)
        from .check import execute as check_execute

        return check_execute(args)
    if args.cmd == "inspect":
        from .inspect_cmd import execute_inspect

        return execute_inspect(args)
    if args.cmd in ("quarantine", "escalate"):
        from .inspect_cmd import execute_named_annotation

        return execute_named_annotation(args, {"quarantine": "quarantined", "escalate": "escalated"}[args.cmd])
    if args.cmd == "annotate":
        from .inspect_cmd import execute_annotate

        return execute_annotate(args)
    ap.error(f"unknown command {args.cmd}")  # unreachable: every registered name is handled above
    return 2


if __name__ == "__main__":
    sys.exit(main())
