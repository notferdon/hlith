# Hlith Review — quickstart

Hlith Review independently checks a supplied Python change and reports evidence, refusals and limits. The supported review workflow (`hlith check`) does not write your repository: it rehearses in a disposable clone it creates itself. That is a property of the supported workflow, not an isolation boundary against other programs running as you. Merge authority remains with the engineer.

## Install

Hlith requires Linux 6.12+ with unprivileged user namespaces and Landlock ABI 6 or newer, plus `git`. It is measured on CPython 3.13.9 from `uv.lock`; `requires-python = ">=3.12"` is the package install range, not a qualified Python version matrix.

### Option A — Locked install from source archive or unpacked sdist (recommended)

Reproduces the locked graph in `uv.lock`: the default Review install is 12 third-party packages on Linux Python 3.13.9 (14 locked defaults); the optional `[agent]` extra brings the total to 54 locked packages (52 installed on Linux). It includes user docs, `examples/first-use/`, `scripts/agent-hook/hlith-agent-hook.sh`, and installed `.venv/bin/hlith` + `.venv/bin/hlith-agent-hook`:

```bash
# If starting from the sdist archive:
tar -xzf hlith-0.1.2.tar.gz && cd hlith-0.1.2
# (Or cd into the unpacked git-archive source directory.)

uv sync --frozen --python 3.13.9
source .venv/bin/activate
hlith --version
```

If you do not activate `.venv`, prefix commands with `uv run --frozen` (for example `uv run --frozen hlith --version`) or invoke `.venv/bin/hlith` and `.venv/bin/hlith-agent-hook` directly.

### Option B — Isolated wheel install (unpinned lower-bound dependencies)

```bash
python3.13 -m venv ~/.local/share/hlith-review/venv
~/.local/share/hlith-review/venv/bin/pip install hlith-0.1.2-py3-none-any.whl
source ~/.local/share/hlith-review/venv/bin/activate
hlith --version
```

(Or use `uv venv --python 3.13.9 ~/.local/share/hlith-review/venv` and `uv pip install --python ~/.local/share/hlith-review/venv/bin/python hlith-0.1.2-py3-none-any.whl`.)

What the wheel does and does not include:
- Installs both `~/.local/share/hlith-review/venv/bin/hlith` and `~/.local/share/hlith-review/venv/bin/hlith-agent-hook` alongside the `hlith` package, schemas, and license/notice files.
- Does **not** reproduce `uv.lock` (`libcst`, `z3-solver`, `hypothesis`, and `pytest` declare lower bounds only), and does **not** bundle `docs/`, `uv.lock`, or `examples/first-use/`.
- Passing `hlith-0.1.2.tar.gz` directly to `pip install` or `uv pip install` also installs unpinned lower-bound dependencies; unpack the sdist and run `uv sync --frozen --python 3.13.9` for the locked graph.

`hlith --version` prints `hlith <sha8>` when built from a release source archive (package version `0.1.2`), or `hlith dev build` from an unarchived checkout without a plain `.git` directory.

## First-use walkthrough

To try Hlith end to end on a self-contained authored fixture (no external repository required), unpack the source archive or sdist and follow [examples/first-use/README.md](../examples/first-use/README.md).

## Review a change

With the Hlith virtualenv active (or using `<venv>/bin/hlith` / `uv run --frozen hlith`):

```bash
hlith doctor --repo /path/to/repo --probe-target
hlith check --repo /path/to/repo --uncommitted --json --artifact-out "$(mktemp -d)/hlith-review"
hlith check --repo /path/to/repo --patch change.patch \
  --base <BASE_SHA> --manifest claim.manifest.json \
  --target-python /path/to/target-venv/bin/python \
  --no-input --json --artifact-out "$(mktemp -d)/hlith-review"
hlith inspect <run-id> --repo /path/to/repo
hlith replay <run-id> --repo /path/to/repo
hlith ui --repo /path/to/repo   # status and recorded runs; it does not start checks
```

`check` runs headless in a disposable rehearsal, also on a terminal. `apply`, `run`, `resume` and `propose-deltas` are not commands in this distribution. A HELD result is review evidence, not permission to merge.

Known limits: the one recorded external observation was an intentional behavior/contract change; no claim is made about accidental regressions, and a HELD verdict on a meaningful change in a real-world repository has not been shown. Recorded full-check times on the external anchor dropped from 807–1476 s (~13–25 min) pre-optimization to 48.80–76.08 s after optimization (single-host observations, not a speed guarantee; see [EXTERNAL-OBSERVATION.md](EXTERNAL-OBSERVATION.md)). Applying changes is out of scope, and unsupported changes return a refusal or UNVERIFIED with reasons. See [LIMITATIONS.md](../LIMITATIONS.md).

## What the verdict means

- HELD = agreement on the explored inputs AND a source certificate. Universal certificates (R0, NORM, R4, SYM in any mode) cover all Python objects; scoped certificates (R2, R3, exact-builtin domains) cover only the stated domain; the report names the rule. Agreement on finitely many inputs without a certificate is UNVERIFIED, never HELD.
- REFUTED carries the recorded failing input. Tier A: reproduced by a standalone replay (`hlith replay`). Repository-test refutations are reproduced by repeated test runs, not standalone replay. A witness marked `unstable-unchecked` has no replayable call and is not Tier A. Truncated or unreproduced witnesses are UNVERIFIED.
- **Review-only distribution boundary.** `hlith check` runs its rehearsal in-process, in a disposable clone it creates itself, and does not write the selected repository. No marker, token or host capability record authorises that rehearsal, and `hlith` has no command that lands a change: `apply`, `run`, `resume` and `propose-deltas` are not commands (`hlith run` exits `2`, invalid choice), and the internal engine module refuses `run`, `resume` and `propose-deltas` with exit `4`. The terminal screen does not start checks. This is a supported-workflow guarantee, not an isolation boundary: another program running as you can change your files directly. Hlith Review does not claim "impossible", only "not offered".
  Observations are made inside the process that runs the changed code. Hlith does not protect them against code written to falsify them: a REFUTED witness, a test result or an agreement may be forged by such code. The supervisor's own result channel and scratch files are out of that code's reach.
- Confinement: user namespaces + Landlock; no network; loopback is down (tests that need a loopback server are UNVERIFIED); reachability of pathname AF_UNIX sockets outside the sandbox is not established and not claimed. Protocol/observation integrity is disclosed, not enforced by a syntactic lint.
- HELD is review evidence, not merge permission.

## Turn a REFUTED witness into a pytest regression

```bash
# For a broken proposal: guard the existing (PRE) contract. The test fails on the buggy revision.
# It may go into the repository's tests and stay uncommitted while you fix the code and re-run hlith check:
GUARD_DIR="$(mktemp -d)"
hlith replay <run-id> --repo /path/to/repo --pytest-out /path/to/repo/tests/test_hlith_guard.py --expect pre
# Or write it outside the repository and point HLITH_WITNESS_ROOT at the checkout:
hlith replay <run-id> --repo /path/to/repo --pytest-out "$GUARD_DIR/test_regression.py" --expect pre
# Only when the change is intentionally accepted: assert the new (POST) contract.
hlith replay <run-id> --repo /path/to/repo --pytest-out "$GUARD_DIR/test_new_behavior.py" --expect post
HLITH_WITNESS_ROOT=/path/to/checkout pytest -q "$GUARD_DIR/test_regression.py"
```

The export is deliberately narrow: one importable plain call with recorded args/kwargs. It emits ordinary static imports (`from <module> import <name>`) and direct literal calls with scoped `sys.path` cleanup in `finally` (no `importlib`, computed `getattr`, or `hlith` import). It refuses receiver-bound, environment-bound, stub, injected-exception, truncated, evaluator-marker-argument, container/opaque-return, normalized-placeholder, lazy, unrepresentable or random-state outcomes, kind-only returns, and any witness whose recorded side printed output, raised a warning, changed its receiver or an argument (for example appended to a list argument) or wrote state. `--expect` is required: `--expect pre` is the regression guard for a REFUTED proposal (it fails on the buggy revision and passes after correction), while `--expect post` pins an intentionally accepted change. A recorded exception is checked by type **and message**, not type alone. It covers one call, not the rest of the change. If the replay did not reproduce, or the witness is one of the refused kinds, `hlith replay` writes no test and prints `pytest witness NOT EXPORTED: REASON` rather than guessing. A refused export does not change replay's exit status: it stays `0` when the witness reproduced (the replay itself succeeded), and `1` when it did not (nothing is exported). Read the result from stderr (`pytest witness: PATH` or `pytest witness NOT EXPORTED: REASON`) or from `pytest_export.status` (`written`, `refused` or `not-attempted`) in the `--json` envelope, not from the exit status. Runs recorded by an earlier Hlith build have no versioned witness record; they still replay, but export is refused with a reason starting `legacy-witness:`. Run `hlith check` again to get an exportable witness.

**Keeping the guard while you fix the change.** An exported `--expect pre` guard can stay uncommitted in a test path while you fix the production code and re-run `hlith check --uncommitted`; no intermediate commit is needed. Hlith recognizes the guard only when its bytes are exactly what a prior REFUTED run on the same repository and base commit, recorded in the same `HLITH_STATE_DIR`, exports with `--expect pre`. It then runs the guard confined on base and on post, requires it to pass on base, and records it as a separate `exported-guard:` obligation that discharges only the guard's own test function. The production change's own obligations still decide HELD or REFUTED: the guard cannot make a guard-only patch land (`guard-alone`, NOT-DERIVED) and cannot stand in for target checks, baseline test reach or unknowns. It never produces REFUTED or a witness itself: a guard failure on either side (assertion, import, collection, timeout, environment) or a conflict with an approved intended change is UNVERIFIED; only the target's normal differential produces REFUTED, with its usual replayable, exportable witness. An edited or forged guard, an `--expect post` guard, a guard from another base commit or repository or from a fresh state store, a file outside a test path, a symlink, an oversized file, and any other newly added test stay ordinary added callables and end NOT-DERIVED (exit `11`, `added-unreached`): uncommitted tests are not exempt in general. Once the fix is accepted, commit the guard (with the fix or on its own; a separate commit is optional) so it runs in ordinary `pytest` without Hlith and participates in later `hlith check` test-reach and call-site analysis. Use a fresh `pytest` process when switching `HLITH_WITNESS_ROOT` across checkouts (`sys.modules` is not cleared in-process).

## Use it from an agent workflow

`hlith check --repo . --uncommitted --no-input --json --artifact-out DIR` (where `DIR` is a new directory outside the repository, e.g. `$(mktemp -d)/hlith-review`) is the agent-safe entry point (see `docs/AGENT-INTEGRATION.md`, which also documents installing and wiring `<venv>/bin/hlith-agent-hook`). Read `artifact.outcome`, `artifact.exit_status`, `check.run_id`, `check.replay_command` and `check.inspect_command`; do not parse prose. Exit `10` (REFUTED) is actionable evidence, not merge permission; `11`/`12` are honest unsupported/undetermined outcomes; `4` is a boundary refusal.

## Uninstall and rollback

Hlith writes outside the repository only under the state directories below. Removing the checkout does not remove them.

```sh
deactivate   # if this shell activated the Hlith virtualenv
rm -rf /path/to/hlith/.venv
rm -rf "${HLITH_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/hlith}"
rm -rf "${HLITH_HOOK_HOME:-$HOME/.local/state/hlith-agent-hook}"
```

If you wired the agent hook, remove the three `hlith-agent-hook` blocks from `.claude/settings.json`. Delete any uncommitted `tests/test_hlith_guard.py` (or the path you passed to `--pytest-out`) and any directory you passed to `--artifact-out`. Nothing in the selected repository is reverted by these commands; use git for that.
