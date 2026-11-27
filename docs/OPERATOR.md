# Operator run

## Supported targets

Hlith's checks and screens run against a **plain local repository**: a normal checkout whose `.git` is a real directory owned by you, whose own config uses only
ordinary settings (remotes, branches, user, `core.filemode`, and similar), and that has no `objects/info/alternates`. Repositories that contain submodules are supported.

Not supported in this version (Hlith refuses them with a named reason and changes nothing; clone the repository and open the clone):
**linked worktrees** (a `.git` *file*), a symlinked `.git`, shared/alternate object stores, git-lfs repositories (`filter.*`), partial clones and
`worktreeConfig`/sparse checkouts, and repositories whose config sets keys outside Hlith's safe list (the refusal names every such key). This is a statement about
what has been qualified, not a claim about general Git compatibility. Shallow clones and index `skip-worktree`/`assume-unchanged` entries are read as Git reports
them and are not separately verified.

## Current operator flow

- **Surfaces.** Bare `hlith` opens the terminal screen on a usable TTY and prints status in a pipe. Use `hlith ui` for explicit
  terminal options, `hlith status`, `hlith history` and `hlith doctor` for read-only inspection, and `hlith check` for headless
  checks (JSON envelope `hlith.check/1`). The CLI also ships `hlith inspect`, `hlith replay` and `hlith annotate`.
  `hlith apply`, `hlith run`, `hlith resume` and `hlith propose-deltas` are not offered in this distribution.
- **Rehearsal only.** `hlith check` (headless, also on a terminal) runs in-process in a disposable clone it creates itself (the terminal screen does not start checks); the supported workflow does not write
  the selected repository. LANDED means landed in that clone. There is no Apply step; merging stays with you, outside Hlith.
- **Input origin.** A patch you supply (`check --patch`, a saved patch in the UI) is recorded as a supplied patch and is never
  presented as an observed agent run.
- **One run id.** The engine mints the run id. A launcher starts the engine with `--run-link FILE`; the engine writes `{run_id, run_dir}` there
  at its first event, and the UI and `check` follow it. The surface's own id (`--invocation-id`) is linked in the run's `receipt.json`.
- **Host state** (local-first, offline, no telemetry): `$XDG_STATE_HOME/hlith` (default `~/.local/state/hlith`; `HLITH_STATE_DIR` overrides).
  Per repository `repositories/<id>/runs/run-<12 hex>/` holds `receipt.json`, `out.json` (format 2), `events.v2.jsonl`, `meta.json`, `rc`; a
  surface's working directory for one launch is `launch-<hex>/` beside it (wrapper logs, exit code, `engine-run.json`). `feedback/` and
  `journal/` are written by the feedback and gate sections only. `HLITH_UI_STATE` (UI preferences, remembered repositories, pre-freeze
  history under `runs/`) also selects the operator store as `$HLITH_UI_STATE/host` when `HLITH_STATE_DIR` is not set.
- **What a refusal shows.** `REFUSED · REFUTED | NOT-DERIVED | UNVERIFIED | BOUNDARY` (looked up from the gate's recorded exit status:
  10, 11, 12, 4), each blocking obligation with its witness or stop reason, what was explored and what was not, and one next step.
  A run with no decision is shown as what it is: IN PROGRESS, BOUNDARY UNAVAILABLE (refused before judging; no artifact), WITNESS MISSING,
  UNREADABLE, `UNVALIDATED` (record fails its schema; the recorded decision is still shown), LOST, CLONE FAILED. Progress events are phases
  and counters only and never carry a verdict. If the landing completed but feedback recording or the post-landing probe failed, the label
  says `LANDED · FEEDBACK FAILED` (or `REFUSED · … · FEEDBACK NOT RECORDED`) with a next action; the decision is unchanged.
- **Annotations.** `hlith annotate` appends hash-chained, annotation-only notes beside a run. They never override a refusal and nothing in the
  engine reads them.
- **Replay one witness.** `hlith replay RUN [--repo PATH] [--obligation ID] [--python PATH] [--unconfined] [--scripts-dir DIR] [--json]` re-executes one
  recorded `witness_call` on the artifact's recorded base and post trees. It verifies the base identity and the SHA-256 of the durable
  `change.patch` before reconstructing the post tree. A run ID is resolved from the current repository; a run directory or artifact file can
  also be supplied. If the run does not record a source-repository path and your current directory is outside that repository, pass
  `--repo PATH` or run the command from the repository. Recorded and explicitly supplied repository paths are vetted before Git reads.
  If exactly one obligation has a witness, it is selected automatically; when several do, pass `--obligation` with the exact ID. Replay is
  confined by default and uses the recorded target Python unless `--python` supplies an override. `--unconfined` prints a
  warning before replay. `--scripts-dir` saves the two generated scripts; `--json` writes the versioned `hlith.replay/1` envelope. `--pytest-out FILE --expect pre|post`
  exports a reproduced simple-call witness as a pytest test; a refused export leaves the exit status unchanged (see the [CLI reference](CLI.md)).

  Text output is `Replay: REPRODUCED`, `Replay: NOT REPRODUCED`, or `Replay: NOT REPLAYABLE (why)`, followed by `base: ...`, `post: ...`,
  and `replay re-executes ONE recorded call: it confirms a witness, it never certifies the rest of the domain`. Exit codes: 0 reproduced;
  1 replayable but not reproduced; 12 not replayable (for example, a truncated or absent witness, missing replay context, unavailable tree,
  patch, or Python); 2 usage, including an unknown or ambiguous obligation ID (available IDs are listed); 4 confinement unavailable; 3
  internal error. A replay result says nothing about unexecuted calls or the rest of the domain.
- **Approval.** A human approves an exact delta set by its `delta_set_sha256` (shown by `hlith inspect`, the artifact, and the review
  screen). It clears only `deltas-confirmed`; a different set refuses; it never makes another obligation HELD.
- **Terminals.** Palette names and color environment variables are in [TUI.md](TUI.md). With `TERM` empty, unset, `dumb`, or unknown to terminfo, `hlith ui` falls back to the plain text frame without hanging.
- **Blocked screen.** If the boundary is unavailable on this host, starting is blocked: the engine would exit 4, nothing starts and
  nothing is written; the screen says why (Landlock ABI, user namespaces) and the READINESS block shows the same facts.
- **Kernel requirement.** Workers and checkers run under user namespaces + Landlock (ABI 6 or newer, Linux 6.12+). If the kernel cannot
  confine them the run is refused with exit 4 and a hint is shown (`uname -r`; unprivileged user namespaces enabled; Landlock in
  `/sys/kernel/security/lsm`); hlith never runs unconfined.
- **Target python.** `hlith ui` and `hlith check` use `.venv/bin/python` or `venv/bin/python` in the repository. Without one, the engine's own
  interpreter runs your code; the home screen warns when the repository declares dependencies (`pyproject.toml`, `requirements*.txt`,
  `setup.py/cfg`, `Pipfile`) so the run does not silently end UNVERIFIED. Pass `--target-python` to choose another interpreter.
- **Not claimed here.** This page describes how the surfaces behave; it does not state that any qualification claim is established.

## Evidence and recovery

Use `hlith doctor --json` for the engine store and UI preferences paths. Supply `--target-python PATH --probe-target` to doctor to test a specific environment. Add `--import MODULE` for each dependency you need. Compare the observed interpreter with the qualification reference before interpreting the run.

This distribution does not land in your repository and does not recover landings left by earlier builds; if doctor reports a pending landing journal, it does so read-only. `hlith history --repo PATH` lists rehearsals. A stored input can name the record and run that supplied it. Only a controlled trial establishes whether feedback was necessary to find a difference.

See the [CLI reference](CLI.md) for current commands.
