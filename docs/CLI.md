# Hlith CLI Reference

Every command below uses the single entry point `hlith` (`hlith.operator.cli:main`), invoked from an activated Hlith virtualenv (`source .venv/bin/activate`), via `<venv>/bin/hlith`, or via `uv run --frozen hlith`. Packaging also installs the companion agent hook script `<venv>/bin/hlith-agent-hook` (source: `scripts/agent-hook/hlith-agent-hook.sh`; see [docs/AGENT-INTEGRATION.md](AGENT-INTEGRATION.md)). Checks run headlessly from the CLI with stable run IDs, exit codes, and versioned JSON envelopes; the interactive terminal screen shows status and recorded runs but does not start checks.

## Global options & exit codes

| Invocation | Behavior |
|---|---|
| `hlith` | Opens the interactive TUI on a usable TTY; prints plain status in a pipe |
| `hlith --version` | Prints the build identity (`hlith <sha8>` for a release source archive/wheel, `hlith <TAG>` for a pinned install, or `hlith dev build` in an unarchived checkout without a plain `.git` directory; package version `0.1.2`) and exits `0` |
| `hlith --no-input [--json] [--exit-code]` | Prints repository status headlessly without opening the TUI |
| `hlith --help` / `hlith COMMAND --help` | Prints full command usage and options |

### Decision exit-code taxonomy (`check`)

| Exit code | Meaning | Writes target? |
|---:|---|---|
| `0` | **LANDED** in the disposable rehearsal clone — every required obligation held; the report names the obligations and certificates | Only the disposable clone |
| `2` | **USAGE** — invalid CLI flags or missing `--repo`/`--patch`/`--manifest` | No |
| `3` | **INTERNAL ERROR** — the review engine itself failed (`hlith: internal error: the review engine failed (<Type>: <message>); nothing was decided` in `artifact.reason`); the `hlith.check/1` envelope is still written with `exit_status` `3` and `apply_command` `null` | No |
| `4` | **BOUNDARY** — host confinement unavailable (`host-confinement-unavailable`: missing Landlock ABI >= 6, disabled user namespaces, or failed confinement canary), unsupported Git feature (`unsupported-git-feature`), hostile/unsupported repo, hash mismatch, dirty tree, or identity-chain mismatch | No |
| `10` | **REFUTED** — concrete counterexample witness found where post diverges from base | No |
| `11` | **NOT-DERIVED** — unmodeled construct or non-Python effect outside the sound analysis envelope | No |
| `12` | **UNVERIFIED** — no repository test reaches the changed code, missing/unapproved delta confirmation, timeout, import error, or no equivalence certificate | No |

Read-only inspection commands (`status`, `history`, `inspect`, `annotate`) return `0` on success (`2` on usage error; `status --exit-code` returns the latest validated decision code or `3` if unavailable). `doctor` returns `0` when all checks pass and `1` when any readiness problem is detected. `replay` returns `0` (`REPRODUCED`), `1` (`NOT REPRODUCED`), `12` (`NOT REPLAYABLE`), `4` (`BOUNDARY`), `2` (`USAGE`), or `3` (`INTERNAL`).

---

## Core workflow commands

### 1. Check host & repository readiness (`hlith doctor`)

```sh
hlith doctor --repo /path/to/repo
hlith doctor --repo /path/to/repo --target-python /path/to/venv/bin/python --probe-target
hlith doctor --repo /path/to/repo --import numpy
hlith doctor --repo /path/to/repo --json   # envelope: hlith.doctor/1
```

Checks build identity, Hlith Python runtime, Z3, Git (actively probing every required hardened read feature under the scrubbed environment, including `--attr-source` and `--path-format=absolute`), repository validity, kernel confinement settings (user namespaces + Landlock ABI >= 6), target Python virtualenv readiness (without executing repository-controlled interpreters on the host), host state directory permissions (`0700`), and pending landing journals. The optional `--probe-target` check starts the selected Python inside confinement, imports pytest and each requested `--import` module, reports the observed version against the 3.13.9 reference, and notes any declared `pyproject.toml` dependencies not yet probed. Rehearsal exercises project code and tests.

### 2. Rehearse a change safely (`hlith check`)

```sh
hlith check --repo /path/to/repo --uncommitted --no-input
hlith check --repo /path/to/repo --commit <SHA> --no-input
hlith check --repo /path/to/repo --branch <BRANCH> [--base <BASE>] --no-input
hlith check --repo /path/to/repo --patch change.patch [--manifest claim.json] --no-input
```

Key flags:
- `--no-input` — accepted for scripts; `check` is headless in this distribution whether or not it is given, also on a TTY.
- `--json` — emit the versioned `hlith.check/1` envelope containing the unmodified `artifact` plus `check` metadata (`run_id`, `replay_command`, `inspect_command`, `apply_command`, `domain_policy`, `excluded_tool_state`).
- `--artifact-out DIR` — write `out.json`, `change.patch`, `claim.manifest.json`, and `base.txt` into a new private (`0700`) directory outside `--repo`.
- `--target-python PATH` / `--target-venv` — select the Python interpreter that runs repository code inside confinement (auto-detects `.venv/bin/python` or `venv/bin/python` when present).
- `--strict-domain` — open-caller mode: refuse typed equivalence certificates unless both versions self-enforce exact builtin types at entry (`if type(p) is not T:` or `if type(p) not in (int, bool):`).
- `--include-tool-state` — include untracked agent/tool-state directories (`.beads`, `.claude`, `.ntm`, etc.), which `--uncommitted` excludes explicitly by default.

`hlith check` rehearses in a disposable clone; the supported workflow does not write `--repo` (a supported-workflow guarantee, not a boundary against other programs running as you). The rehearsal runs in-process; no marker, token or host capability record is involved. It prints copyable `Replay witness` and `Inspect run` commands; `check.apply_command` is always `null` in this distribution. Unresolved merge conflicts in `--uncommitted` mode fail fast cleanly with exit `4` before cloning or writing feedback.

### 3. Replay a refutation witness independently (`hlith replay`)

```sh
hlith replay <RUN_ID|RUN_DIR|ARTIFACT.json> --repo /path/to/repo
hlith replay <RUN_ID> --repo /path/to/repo --json             # envelope: hlith.replay/1
hlith replay <RUN_ID> --repo /path/to/repo --scripts-dir DIR  # save standalone pre/post scripts
hlith replay <RUN_ID> --repo /path/to/repo --pytest-out tests/test_hlith_witness.py --expect pre|post
```

Re-exports the exact recorded base tree, verifies the SHA-256 of `change.patch`, reconstructs the post tree, and re-executes the single recorded `witness_call` inside confinement (use `--unconfined` only if you explicitly choose to run target code outside Landlock/userns). Replay confirms one concrete divergence; it never certifies the rest of the domain.

`--pytest-out` requires `--expect pre|post` and writes a dependency-free static pytest test (`from <module> import <name>`, direct literal call, scoped `sys.path` cleanup in `finally`, no `hlith` import) for simple plain calls: it imports the module from `HLITH_WITNESS_ROOT` (default cwd), calls the recorded args/kwargs, and asserts the selected recorded outcome. `--expect pre` guards the existing contract (fails on a buggy revision, passes after correction); `--expect post` pins an intentionally accepted change. An `--expect pre` guard may stay uncommitted in a repository test path (for example `tests/test_hlith_guard.py`) while you fix the code. A later `hlith check` recognizes it only when all four match: exact exported bytes, same repository, same base commit, and same `HLITH_STATE_DIR`. Recognized guards run confined on base and post as an additive `exported-guard:` obligation that discharges only itself. A guard never produces REFUTED (guard failure ends UNVERIFIED) and cannot land a guard-only patch (`guard-alone`, NOT-DERIVED). An edited, forged, `--expect post`, cross-base or fresh-store guard, a non-test path, and any other newly added test end `NOT-DERIVED` (exit `11`, `added-unreached`). Commit the guard once the fix is accepted (with the fix or separately) for ordinary `pytest` use and later test reach. It writes only when the replay reproduced. It refuses receiver-bound, environment-bound, stub, injected-exception, truncated, evaluator-marker-argument, container/opaque-return, normalized-placeholder, lazy, unrepresentable or random-state outcomes, kind-only returns, exception messages truncated by the display cap (`… #<digest>`), and any witness whose recorded side printed output, raised a warning, changed its receiver or an argument (for example appended to a list argument) or wrote state; recorded exceptions are checked by type and message; nothing is guessed. A refused export does not change replay's exit status: it stays `0` when the witness reproduced (the replay itself succeeded), and `1` when it did not (nothing is exported). Read the result from stderr (`pytest witness: PATH` or `pytest witness NOT EXPORTED: REASON`) or from `pytest_export.status` (`written`, `refused` or `not-attempted`) in the `--json` envelope, not from the exit status. Runs recorded by an earlier Hlith build have no versioned witness record; they still replay, but export is refused with a reason starting `legacy-witness:`. Run `hlith check` again to get an exportable witness.

The `--json` envelope (`hlith.replay/1`) has `envelope`, `status` (`REPRODUCED`, `NOT REPRODUCED`, `NOT REPLAYABLE`, `USAGE ERROR`, `INTERNAL ERROR`), `exit_status`, `run_id`, `obligation_id`, `base` (`commit`, `tree_oid`), `post` (`tree_oid`), `why`, `confined`, `limit` and `pytest_export` (`null` when not asked, else `status`, `expect`, `path`, `reason`). An unknown or ambiguous `--obligation` is a usage error that lists `available_ids`. `--pytest-out` without `--expect` prints `hlith: usage: --pytest-out requires --expect pre|post (choose the intended contract; no default)` and exits `2`.

### 4. Inspect receipts, evidence, and history (`hlith status`, `hlith history`, `hlith inspect`, `hlith annotate`)

```sh
hlith status --repo /path/to/repo [--json] [--exit-code]      # envelope: hlith.status/1
hlith history --repo /path/to/repo [--json]                   # envelope: hlith.history/1
hlith inspect <RUN_ID|RUN_DIR|out.json> --repo /path/to/repo [--json]  # envelope: hlith.inspect/1
hlith annotate <RUN_ID> --repo /path/to/repo --action note --note "reviewed"
hlith quarantine <RUN_ID> --repo /path/to/repo --note "regression"
hlith escalate <RUN_ID> --repo /path/to/repo --note "needs owner review"
```

`quarantine` and `escalate` are named annotation commands; they write append-only, hash-chained operator receipts. They never alter a verdict and are never read by the gate. `hlith inspect` displays the recorded decision, `domain_policy`, confined target-Python observation and 3.13.9 qualification, obligation evidence, witness `feedback_record_ids` lineage, feedback limits, and progress events.

### 5. Applying a change (not offered)

`apply`, `run`, `resume` and `propose-deltas` are not commands in this distribution: `hlith run` exits `2` (argparse `invalid choice`). The internal engine module refuses `run`, `resume` and `propose-deltas` with exit `4`, and `apply` with `Apply is not offered in this distribution`. The terminal screen has no Apply action and does not start checks. Merging stays with you, outside Hlith. See [LIMITATIONS.md](../LIMITATIONS.md#applying-changes).

### 6. Review an intended behavior change

Supply a manifest describing the input domain and expected behavior. Inspect the listed deltas and their `delta_set_sha256`. To authorize exactly that set, use `hlith check --approve-deltas <delta_set_sha256>` (the refusal prints the exact command). It checks the same project at the recorded base with the captured patch and manifest hashes. Other blockers remain visible. Approval clears only that delta set; it does not make another obligation HELD.

```sh
hlith check --repo /path/to/repo --patch change.patch --manifest claim.json --no-input
```

Write the claim by hand from the refusal's witness; `propose-deltas` is not offered in this distribution.

### 7. Interactive terminal screen (`hlith ui`)

```sh
hlith                                          # open the terminal screen in the current repository (status and recorded runs)
hlith ui --repo /path/to/repo                  # explicit repository
hlith ui --repo /path/to/repo --plain          # non-interactive plain text frame
hlith ui --runs                                # list runs across repositories
```

Starting a check from the terminal screen is not available in this distribution; use `hlith check`. Palette names, including `stitch-dark`, and the color environment variables live in [TUI.md](TUI.md).

---

## State & crash recovery

- Read `state_dir` and `ui_state_dir` from `hlith doctor --json`. The engine uses `HLITH_STATE_DIR`, then `$HLITH_UI_STATE/host`, then `$XDG_STATE_HOME/hlith` (normally `~/.local/state/hlith`). History can also read earlier UI launch records.
- **Interrupted landings:** this distribution does not land in your repository and does not recover landings left by earlier builds; `hlith doctor` reports a pending landing journal read-only.
