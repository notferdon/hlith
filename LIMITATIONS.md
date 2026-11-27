# Limitations

What Hlith Review does not do, does not claim, or has not measured. Read this before relying on a verdict.

## What a verdict claims

- **HELD is review evidence, not merge permission.** It needs agreement on the explored inputs **and** a source certificate. Universal certificates (`R0`, `NORM`, `R4`, `SYM` in any-type mode) cover all Python objects. Scoped certificates (`R2`, `R3`, `TYP`, typed `SYM`) cover only exact builtin inputs; the verdict names what is outside the claim. Agreement without a certificate is UNVERIFIED.
- **Exit 0 means "landed in the disposable clone"** with the obligations and certificates the report names. Your repository is not touched.
- **REFUTED witnesses differ in strength.** Reproduced by a standalone `hlith replay`; reproduced by re-running repository tests; or `unstable-unchecked` (no replayable call, for example a removed function or a stand-in input), which is a lead, not a confirmed counterexample. Truncated or unreproduced witnesses are UNVERIFIED.
- **One recorded external observation, not a regression rate.** The example was an intentional behavior/contract change that broke the function's documented contract; Hlith caught it and the 123 reaching tests did not. It was not an accidental regression, and no claim is made about accidental-regression performance.
- **No real-repository HELD shown.** So far, real-repository evidence consists of refusals, REFUTED witnesses and UNVERIFIED results. Many behavior-preserving changes in real repositories end UNVERIFIED because some file in the tree contains dynamic machinery the certificate cannot rule out.
- **A repository test must reach the changed code**, otherwise the verdict is UNVERIFIED, whatever the differential saw.

## Pytest witness export (`hlith replay … --pytest-out FILE --expect pre|post`)

- `--expect pre|post` is required; `--pytest-out` alone is a usage error.
- Writes a test only when the replay reproduced, and only for simple plain calls. It refuses receiver-bound, environment-bound, stub, injected-exception, truncated, evaluator-marker-argument, container/opaque-return, normalized-placeholder, lazy, unrepresentable or random-state outcomes, kind-only returns, and any witness whose recorded side printed output, raised a warning, changed its receiver or an argument (for example appended to a list argument) or wrote state, and exception messages truncated by the engine's display cap (`… #<digest>`); nothing is written.
- A refused export does not change replay's exit status: it stays `0` when the witness reproduced (the replay itself succeeded), and `1` when it did not (nothing is exported). Read the result from stderr (`pytest witness: PATH` or `pytest witness NOT EXPORTED: REASON`) or from `pytest_export.status` (`written`, `refused` or `not-attempted`) in the `--json` envelope, not from the exit status.
- Runs recorded by an earlier Hlith build have no versioned witness record; they still replay, but export is refused with a reason starting `legacy-witness:`. Run `hlith check` again to get an exportable witness.
- For an exception outcome the test asserts both the exception type and the recorded message.
- `--expect pre` asserts the recorded **original** outcome: it fails on the buggy change and passes on a corrected one, so it is a regression guard. `--expect post` asserts the **changed** outcome and pins the proposed behavior; use it only for a change you accept. Choosing `post` for a REFUTED change pins the regression.
- Exported tests use ordinary static imports (`from <module> import <name>`) and direct literal calls with scoped `sys.path` restoration (no `importlib`, computed `getattr`, or `hlith` import). An exported `--expect pre` guard left uncommitted inside a test path is recognized by a later `hlith check` only with the exact exported bytes, the same repository and base commit, and the same `HLITH_STATE_DIR` that recorded the REFUTED run; it is then an additive obligation that discharges only itself and never produces REFUTED (a guard failure is UNVERIFIED). Anything else (edited, forged, `--expect post`, cross-base, cross-repository, fresh store, non-test path, symlink, oversized, or any other newly added test) ends `NOT-DERIVED` (exit `11`, `added-unreached`), and a guard-only patch ends `NOT-DERIVED` (`guard-alone`). Once committed in `tests/`, a retained guard participates in future `hlith check` test-reach and call-site analysis. Switching `HLITH_WITNESS_ROOT` across checkouts expects a fresh pytest process (Python's `sys.modules` cache is not cleared in-process).
- It covers one call, not the rest of the change.

## What a certificate assumes about your repository

- Every non-test Python file in the committed tree is scanned for writes that could rebind a name the proof relies on. The reflection rule (`eval`, `exec`, `compile`, `importlib`, computed `getattr` …) covers only the files the target imports.
- Not covered: your test files, untracked or ignored files, installed packages, other processes, import hooks, mutation through frames or `gc`, and callers that mutate the module after import.
- There is no mode that relaxes the scan to "only the import closure matters".

## Integrity of observations

Observations are made inside the process that runs the changed code. Hlith does not protect them against code written to falsify them: a REFUTED witness, a test result or an agreement may be forged by such code. The supervisor's own result channel and scratch files are out of that code's reach. Hostile unchanged repository code is equally able to forge them. See [SECURITY.md](SECURITY.md).

## Applying changes

`apply`, `run`, `resume` and `propose-deltas` are not commands (`hlith run` exits `2`, invalid choice); the internal engine module refuses `run`, `resume` and `propose-deltas` with exit `4` (`hlith: boundary: Hlith Review is read-only; run/resume/propose-deltas/original-target landing are not offered in this distribution`). `hlith check` rehearses in-process, in a disposable clone it creates itself; no marker, token or host capability record authorises it. That it does not write your repository is a supported-workflow guarantee, not an isolation boundary against other programs running as you.

**The terminal screen does not start checks.** Starting one there shows: "starting a check from the terminal screen is not available in Hlith Review; run `hlith check` in a terminal. Nothing was run and your repository was not changed." `hlith check` runs headless on a terminal too, so it never reaches that screen.

## Host and platform

- **Linux only**, kernel 6.12+ with unprivileged user namespaces and Landlock ABI 6 or newer. Below ABI 6 Hlith refuses to run a check (exit 4). The development host reports ABI 8; behavior on other ABIs has not been measured.
- **Ubuntu 24.04 and later** set `kernel.apparmor_restrict_unprivileged_userns=1` by default, which is expected to make confinement unavailable, so Hlith refuses (exit 4). Not measured on such a host.
- **No macOS, Windows, Docker or hosted CI support** is claimed. The repository's standards workflow is dispatch-only, has never run, and GitHub Actions is disabled; no hosted-CI result is claimed.
- **Docker (observed on a local `ubuntu:24.04` container, default seccomp, `--network none`, read-only, uid 1000):** `unshare(CLONE_NEWUSER)` is denied; `hlith doctor --probe-target` exits 1 with `confined startup failed`; the repository is unchanged. Docker is unsupported and fails closed. Missing Landlock, disabled user namespaces, or a failed confinement canary now refuse with typed host `BOUNDARY` exit `4` (`host-confinement-unavailable`) across CLI JSON, plain output, TUI, and hook (not `NOT-DERIVED` exit `11`). Plain `hlith doctor` can still print "Confinement settings: ok (kernel settings only)" in a container, so use `doctor --probe-target` to see the actual refusal.
- **Git features:** Hlith's hardened read-only Git adapter requires Git features probed directly under the scrubbed environment (including `--attr-source`, `rev-parse --path-format=absolute`, `config --file --list --null --no-includes`, `--no-replace-objects`, `--no-ext-diff`, `--no-textconv`, `--ignore-submodules=all`, `log --no-show-signature`, and `apply --numstat -z`). `hlith doctor` runs this feature probe directly rather than guessing from a version number; if a required feature is missing, Hlith refuses with exit `4` (`BOUNDARY`, `unsupported-git-feature`) instead of silently treating a failed read as no uncommitted changes. Measured on Git 2.43.0.
- **Python:** measured on 3.13.9 from the frozen lock. The package accepts `>=3.12`; other versions are unmeasured.
- **`pip install` of the wheel does not reproduce `uv.lock`**: `libcst`, `z3-solver`, `hypothesis` and `pytest` are lower bounds only. For reproducible verdicts install from the source archive or unpacked sdist with `uv sync --frozen --python 3.13.9`.
- **Package contents differ by format.** The sdist (`hlith-0.1.2.tar.gz`) ships source, `uv.lock`, user docs, `scripts/agent-hook/hlith-agent-hook.sh`, `scripts/landlock_capabilities.py`, `scripts/sbom_draft.py`, and the `examples/first-use/` demo fixture. The source archive (the `git archive` view) carries all of that plus the view's tests and the remaining repository scripts. The wheel (`hlith-0.1.2-py3-none-any.whl`) ships the `hlith` Python package, JSON schemas, license/notice files, and both `<venv>/bin/hlith` and `<venv>/bin/hlith-agent-hook` executables, without `docs/`, `uv.lock`, or `examples/first-use/`.
- **`doctor` with no `--repo`** checks the current directory's repository and uses its `.venv` as the target interpreter; use `--repo PATH` explicitly.

## Confinement limits

- No network; loopback is down, so tests that need a local server end UNVERIFIED.
- Hlith's Landlock rules do not cover connecting to an **existing pathname UNIX socket** or **UDP**: no such right is requested, and the inspected headers and source do not support one. The development host reports ABI 8; nothing here relies on a newer ABI.
- Pathname UNIX sockets are an **unverified filesystem-rule surface**: they are kept out by the mount view (only granted paths exist) and by refusing sockets, FIFOs and devices in granted trees, checked before the run. Whether code inside can reach a host pathname socket has not been established and is not claimed.
- **UDP** is stopped only by the empty network namespace.
- Grant vetting is a point-in-time walk; interpreter prefixes are re-vetted at most every 600 s; system library trees are not vetted per run.

## Language coverage

Python only. Dynamic `eval`/`exec`, C extensions and FFI state, external I/O and non-Python files that affect imports are refused (NOT-DERIVED or UNVERIFIED), not guessed. A literal dict whose only key is `$obj`, or with `__hlith_*` keys, is never explored as a dict.

## Runtime

A full check is workload-dependent. On the recorded external observation, full checks took 807–1476 s across six pre-optimization runs, 76.08 s cold / 74.1 s warm after optimization, and 48.80 s on a later integrated candidate (check only). Replay, export, and exported-test timings were measured on different builds and scopes; [docs/EXTERNAL-OBSERVATION.md](docs/EXTERNAL-OBSERVATION.md) records the run/build for each. These are observations, not a speed guarantee. Larger repositories and other changes may take longer. Agents and hooks must not treat a timeout as success. See [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md).

## This source view

This is the public source snapshot, curated before publication; non-public paths are excluded (see [docs/STAGING-VIEW.md](docs/STAGING-VIEW.md)). Engineering evidence and qualification records are not included. As a result, **147 of the 424 test files under `tests/` are not in this view**, including the whole terminal-screen golden suite, because their fixtures contain workstation paths or depend on the evidence archive. Test results from this view cover less than the full source repository; they are not a whole-suite result.
