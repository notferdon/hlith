# Agent integration: Hlith Review

Hlith Review is a read-only check over a change. It does not apply or land; the engineer keeps merge authority.

## Minimal local call (tested)

Invoke `hlith` from an activated Hlith virtualenv (`source .venv/bin/activate`), via its full path (`<venv>/bin/hlith`), or with `uv run --project /path/to/hlith --frozen hlith`:

```bash
OUT="$(mktemp -d)/hlith-review"   # --artifact-out is a NEW directory, not a file
hlith check --repo "$PWD" --uncommitted --no-input --json --artifact-out "$OUT"
```

Use a per-run artifact directory that does not already exist. The command returns the engine's exit status: `3` internal error (the engine failed; nothing was decided; read `artifact.reason`), `0` landed only in the disposable rehearsal, `10` REFUTED with a witness, `11` NOT-DERIVED, `12` UNVERIFIED/unsupported, `4` boundary. The original repository is not written.

Parse only the JSON envelope:

- `artifact.outcome`, `artifact.exit_status`
- `check.run_id`, `check.replay_command`, `check.inspect_command`, `check.apply_command` (always `null` here)
- `artifact.obligations[].witness_call` when the row has it. The published schema in [ARTIFACT.md](ARTIFACT.md) lists `witness` on an obligation and does not name `witness_call`. The check writer copies `witness_call` onto the row. Read it when present; do not require a key the schema omits.
- Do not upgrade UNVERIFIED or HELD to merge permission. Exit `3` is an engine failure: the `hlith.check/1` envelope still carries `exit_status` `3` and `artifact.reason`. The run-artifact lattice in ARTIFACT.md does not include exit `3`.

## Agent loop recipe

1. Make the change in the working tree.
2. Run the `check` command above, capture stdout JSON and the exit status.
3. If `outcome` is `refused` / exit `10`, read the witness and run `check.replay_command`; optionally export a pytest regression guard into the repository's tests and keep it uncommitted while fixing:
   `hlith replay <run-id> --repo "$PWD" --pytest-out tests/test_hlith_guard.py --expect pre`
   The generated test guards the existing contract: it fails on the buggy revision and passes after correction. Use `--expect post` only for an intentionally accepted behaviour change.
   Run it with `--json` and read `pytest_export.status`: exit `0` means the witness reproduced, not that a test was written; a refusal (`refused`, with `reason`) also exits `0`.
   Fix the production code and re-run `check` with the guard still uncommitted; no intermediate commit is needed. Only the exact exported bytes from a REFUTED run on the same repository, base commit and `HLITH_STATE_DIR` are recognized; the guard then discharges only itself, never produces REFUTED (a guard failure is UNVERIFIED), and cannot make a guard-only patch land. An edited guard or any other newly added test still ends `NOT-DERIVED` (exit `11`, `added-unreached`). Once the fix is accepted, commit the guard (with the fix or on its own; a separate commit is optional) so it runs in ordinary `pytest` without Hlith and participates in later `hlith check` test-reach and call-site analysis.
4. If `outcome` is `landed` / exit `0`, report it as rehearsal evidence only; still run the repository's own tests and keep the human merge decision.
5. If exit `4`, `11` or `12`, report the boundary/unsupported reason verbatim; do not retry with weakened flags or unconfined execution.

`apply`, `run`, `resume` and `propose-deltas` are not commands in this distribution, and the terminal screen does not start checks. Do not claim "safe to merge" from a HELD or landed rehearsal.

## Background hook for a coding agent

A real check can take minutes (recorded external anchor observations: 76 s cold / 74 s warm on the build recorded then, 48.80 s on the latest final-integrated candidate; not a guarantee, and larger repositories may take longer), so it should not block an agent's tool call. The companion hook script (`scripts/agent-hook/hlith-agent-hook.sh` in the source archive and sdist; installed as `<venv>/bin/hlith-agent-hook` by `uv sync --frozen`, wheel, and sdist installs) starts the check in the background after an edit and tells the agent, in text the model sees, that the change is unverified until the check finishes. It never runs `apply`; exit `0` is reported as a rehearsal only.

```text
hlith-agent-hook post|prompt|stop|status [REPO]     # REPO defaults to $CLAUDE_PROJECT_DIR, then the current directory
```

### Installing and wiring the hook

Choose the installed hook path that matches how you installed Hlith:

- **Locked source archive or unpacked sdist (`uv sync --frozen --python 3.13.9`):**
  - `HLITH_VENV="/path/to/hlith/.venv"`
  - Hook executable: `"$HLITH_VENV/bin/hlith-agent-hook"` (equivalent to `"/path/to/hlith/scripts/agent-hook/hlith-agent-hook.sh"`)
  - Hlith CLI: `"$HLITH_VENV/bin/hlith"`
- **Standalone wheel or `pip` sdist virtualenv:**
  - `HLITH_VENV="$HOME/.local/share/hlith-review/venv"` (your chosen venv)
  - Hook executable: `"$HLITH_VENV/bin/hlith-agent-hook"`
  - Hlith CLI: `"$HLITH_VENV/bin/hlith"`

Because a coding agent's hook shell usually does **not** have the Hlith virtualenv activated on `PATH`, pass `HLITH_BIN` explicitly in the hook command so the detached worker invokes the installed `hlith` binary. Complete Claude Code wiring (for example in `.claude/settings.json` or `~/.claude/settings.json`, substituting your actual virtualenv path for `/path/to/hlith-venv`):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "HLITH_BIN=/path/to/hlith-venv/bin/hlith /path/to/hlith-venv/bin/hlith-agent-hook post"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HLITH_BIN=/path/to/hlith-venv/bin/hlith /path/to/hlith-venv/bin/hlith-agent-hook prompt"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HLITH_BIN=/path/to/hlith-venv/bin/hlith /path/to/hlith-venv/bin/hlith-agent-hook stop"
          }
        ]
      }
    ]
  }
}
```

Check wiring at any time from your target repository with `HLITH_BIN=/path/to/hlith-venv/bin/hlith /path/to/hlith-venv/bin/hlith-agent-hook status` (or `uv run --project /path/to/hlith --frozen hlith-agent-hook status "$PWD"`). If the target repository needs a non-default interpreter, add `HLITH_TARGET_PYTHON=/path/to/target-venv/bin/python` beside `HLITH_BIN`; when unset, `hlith` auto-detects `.venv`/`venv` inside the repository.

Claude Code wiring summary: `PostToolUse` with matcher `Edit|Write|MultiEdit` runs `post`; `UserPromptSubmit` runs `prompt`; `Stop` runs `stop`.

| Event | What happens | What the agent sees |
|---|---|---|
| `post`, clean working tree | no check; any old receipt is removed | nothing |
| `post`, no check running | one detached `hlith check --uncommitted` starts | `hlith check started in the background (it can take minutes on a large repo). Until its receipt says otherwise this change is UNVERIFIED: do not tell the user it is safe or verified. Receipt: <path>` |
| `post`, a check is running | no new check now; when the running check finishes, the worker checks the tree again if it changed meanwhile (at most 3 checks per worker) | `hlith check is still RUNNING for an earlier edit; this change is UNVERIFIED until it finishes. Do not report it as verified.` |
| `prompt`, check running | — | `hlith check is still RUNNING; the pending change is UNVERIFIED. Say so; do not claim success.` |
| `prompt`, check finished, tree unchanged since it started | — | a summary (outcome, exit, seconds, run id, each REFUTED witness's arguments, replay and inspect commands, receipt path), then `A REFUTED witness is evidence, not a decision: ask the human whether the change was intended. If not intended, restore the behavior and let the next edit trigger a new check.` |
| `prompt`, check finished, tree changed since it started (stale) | — | the summary, then `BUT the working tree changed after that check started: the current tree is UNVERIFIED (no check covers it). Do not claim success.` |
| `prompt`, worker gone before finishing (interrupted) | — | `hlith check was interrupted (its worker is gone); this change is UNVERIFIED. A new edit starts a new check; do not claim success.` |
| `stop`, check running, or finished with exit `0` on an unchanged tree | stop is not blocked | nothing |
| `stop`, check finished with any other exit on an unchanged tree | stop is blocked once (`{"decision": "block", ...}`); not again while `stop_hook_active` is true | the summary, then `Resolve it (keep the intended contract, or tell the human the change is unverified) before finishing. Never claim this change is safe.` |
| `stop`, stale (any exit, including `0`) | blocked once | the summary, then `BUT the working tree changed after that check started: the current tree is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.` |
| `stop`, interrupted | blocked once | `hlith check was interrupted (its worker is gone); this change is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.` |

The summary names exit `0` as `LANDED (disposable rehearsal only; NOT merge permission)`, `3` as `INTERNAL ERROR (nothing decided)`, `10` REFUTED, `11` NOT-DERIVED, `12` UNVERIFIED/unsupported, `4` BOUNDARY refusal, and `124` (the hook's own timeout) as `TIMED OUT (UNVERIFIED)`. Any other exit, for example `127` when `HLITH_BIN` cannot be started, is shown as `exit <n>` and blocks the stop like any non-zero exit. The script itself always exits `0`, so it never fails the agent's tool call; everything it reports is in its JSON output (`hookSpecificOutput.additionalContext` for `post`/`prompt`).

Receipts live outside the repository, in `$HLITH_HOOK_HOME/<repo-name>-<checksum>/` (default `~/.local/state/hlith-agent-hook`): `status.json` (`running` with `started`/`pid`/`head`/`tree`/`fp`, then `done` with `exit`/`seconds`/`started`/`head`/`tree`/`fp`, or `error` when fingerprinting fails; `fp` is a SHA-256 binding `HEAD` commit OID, `HEAD^{tree}` OID, `git status --porcelain=v1 -z`, tracked diff against `HEAD`, and bounded non-ignored untracked files read without touching the index via `--no-optional-locks`), `last.json` (the `hlith.check/1` envelope), `last.err`, per-repo locks (`state.lock`, `worker.lock`), and `artifact-<epoch>-<pid>-<attempt>/`. Concurrent `post` hooks are serialized per repository via `flock`, and `status.json`/`last.json` are published atomically via temp-file rename. `hlith-agent-hook.sh status` prints `status.json`, `{"status": "none"}`, or `{"status": "invalid", ...}` if malformed. On read, the hook validates `last.json` (`envelope`, `exit_status`, `artifact.exit_status`/`outcome`, and `check.base_commit` / `replay_context.base` against the receipt's `HEAD`/`tree`) and fails closed (reporting UNVERIFIED and blocking `stop`) on git/fingerprint errors, special working-tree files (FIFO/socket/device), oversized untracked files (>8 MiB/file or >32 MiB total), or malformed/mismatched receipts or envelopes. It reads only `envelope`, `exit_status`, `check.base_commit`/`run_id`/`replay_command`/`inspect_command`, and `artifact.outcome`/`exit_status`/`run.replay_context.base`/`obligations[].id/verdict/witness_call`. Environment: `HLITH_BIN` (default `hlith`), `HLITH_TARGET_PYTHON` (optional; when unset, `hlith check` auto-detects `.venv`/`venv` or uses its own interpreter), `HLITH_HOOK_TIMEOUT` (seconds; default 3000), `HLITH_HOOK_HOME`.

What this has and has not shown:

- **Mechanism-fixture loops only (not a real-repository HELD).** On a small authored mechanism fixture (`effective_timeout`, raising builtin `ValueError`), a real Claude Code agent and real Hlith ran the complete async loop with the hook: edit removing the guard → model-visible pending (`UNVERIFIED`) → `REFUTED` (exit `10`, witness `value=-1`; repository tests still passed) → human `inspect`, `replay` (`REPRODUCED`), and `--pytest-out ... --expect pre` exported outside the repository → agent made a non-revert simplification while restoring the `value <= 0` guard → final `hlith check` BEFORE adding the exported guard test loaded the prior run's feedback pins and finished `LANDED` in the disposable rehearsal (exit `0`, universal `NORM+R0` certificate, original repository untouched) → adding the exported guard test afterwards passed standalone outside Hlith (and failed on the buggy revision). This is a mechanism demonstration, not a real-repository HELD verdict.
- **Why an earlier custom-exception fixture did not reach HELD.** In an earlier authored fixture whose module defined `class InvalidTimeout(ValueError): pass`, no non-revert code edit in that module could obtain a positive certificate (a class with a base class is not inert at import time under `closure_gate`, and module-defined classes in the cone are not modelled; those safeguards are kept intact), and an earlier dynamic-import exporter (`importlib.import_module`, computed `getattr`) also triggered dynamic-construct blockers when added to the diff.
- **Exported guard tests use static imports (`from <module> import <name>`) and direct calls**, with scoped `sys.path` cleanup. Once committed in `tests/`, a retained guard participates in later `hlith check` test-reach and call-site analysis without dynamic-import blockers. An exported `--expect pre` guard may also stay uncommitted in a test path during the fix-and-recheck loop, recognized only by exact bytes, same base and same `HLITH_STATE_DIR`; any other newly added uncommitted test function in the checked diff ends NOT-DERIVED (exit `11`, `added-unreached`) under V1's added-callable rule.
- **Receipt routing scope and non-claims.** A finished receipt counts only while `HEAD`, `HEAD^{tree}`, tracked diff against `HEAD`, porcelain status, and bounded non-ignored untracked files still match the receipt and `last.json` passes envelope validation; moving `HEAD` even with an identical dirty diff makes the old receipt stale and blocks `stop`. Untracked symlinks are hashed by `readlink` target without following them; special files (FIFOs, sockets, devices) and unreadable or oversized untracked files fail closed instead of hanging or hashing placeholders. This is local receipt routing integrity, **not** an adversarial tamper-proof boundary (any process running as you can alter `$HLITH_HOOK_HOME` or git state) and **not** a complete dependency-state identity (`.venv`/installed packages, `.gitignore`d files, environment variables, and system libraries are not fingerprinted).
- **Edits outside `post` and repeated edits.** Edits or commits that do not go through the `post` hook (for example a shell command) start no check; they show up as stale at the next prompt or stop. If the tree or `HEAD` keeps changing through three checks, the worker stops and the receipt reports stale.
- **Stale, race, malformed-envelope, special-file, and interrupted paths** are covered by stub tests (`tests/test_agent_hook.py`); the live Claude Code loop exercised the clean pending → REFUTED → non-revert correction → LANDED rehearsal flow.
- Claude Code's hook JSON handling was exercised on one Claude Code version; other agents' hook systems (for example Codex) have not been run.

## CI / pre-commit recipes

Run `hlith check` on the change set you actually intend to review. A pre-commit hook is appropriate only when it can pass the changed files as a patch; otherwise use it as a local pre-push step. Do not add a hook that silently ignores exit `10` or converts `11`/`12` to success. A minimal local hook:

```bash
#!/usr/bin/env bash
set -u
HLITH_BIN="${HLITH_BIN:-/path/to/hlith-venv/bin/hlith}"
out="$(mktemp -d)/hlith-review"   # a NEW directory, outside the repository
"$HLITH_BIN" check --repo "$PWD" --uncommitted --no-input --json --artifact-out "$out" > "$out.json"
rc=$?
case "$rc" in
  0) echo "hlith: rehearsal landed; repository tests and human review still required";;
  10) echo "hlith: REFUTED — see $out.json";;
  11) echo "hlith: NOT-DERIVED (exit 11) — see $out.json";;
  12) echo "hlith: UNVERIFIED/unsupported (exit 12) — see $out.json";;
  *) echo "hlith: boundary/usage (exit $rc)";;
esac
exit "$rc"
```

This recipe was exercised locally against a disposable fixture: exit `10`/`0`, JSON parsed, original unchanged. CI use must first install the exact locked environment or wheel/version and check its contracts; no Docker/macOS/hosted-runner support is claimed from this repo.


## Measured runtime budget (recorded external witness, not bundled)

- On the recorded external anchor, a full check took 48.80 s on the latest candidate (76.08 s cold / 74.1 s warm on the prior optimized build; static effect-account phase 13.98 s; cgroup peak ~1.93 GiB, no swap; 807–1476 s across six pre-optimization runs). Standalone replay took 6.9 s (`REPRODUCED`); `--pytest-out ... --expect pre` took 5.8 s. The generated test (no Hlith import) ran 1 passed in 1.5 s on the original code and 1 failed in 2.5 s on the changed code. Child max RSS on the 48.80 s run was 730200 KiB (`MemoryMax=2G`, no swap). These are single-host observations, not a speed guarantee. See [EXTERNAL-OBSERVATION.md](EXTERNAL-OBSERVATION.md). Larger repositories can take longer; do not run checks synchronously inside an agent tool call.
- Earlier records made before the versioned witness schema still replay, but `--pytest-out` refuses them (`legacy-witness:`).
- The recorded repository's reaching test subset: 123 passed in ~82–86 s at both base and post. They did not catch this contract change, which was requested by the user and is not an accidental regression. No claim is made about accidental regressions; Hlith did catch it.

These numbers are host-specific and are a budget, not a promise. Do not weaken witness/replay quality to hit a latency target.
