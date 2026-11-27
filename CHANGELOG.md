# Changelog

## 0.1.2 (2026-11-27)

Maintenance release following the initial publication:

- Fixed temporary Git index confinement for the exported-guard recheck path (the temporary index now lives in a Hlith-owned directory accepted by the Git environment choke point).
- Public source/test naming and documentation hygiene, corrected evidence statements, contribution and installation metadata, and a clean authored source history. No engine capability or expanded qualification is claimed. See [LIMITATIONS.md](LIMITATIONS.md).

## 0.1.1 (2026-11-27)

Maintenance release following the initial 0.1.0 publication. Public source and documentation hygiene, corrected contribution guidance and evidence descriptions, portable demo paths, and refreshed package/build identity. No new engine capability or expanded qualification is claimed. See [LIMITATIONS.md](LIMITATIONS.md).

## 0.1.0 (2026-11-27)

First public release of **Hlith Review**: an offline, confined check that catches behavior and contract changes your tests miss, with a replayable input and an exportable pytest guard.

### Review
- `hlith check` (headless, also on a terminal) checks uncommitted edits, a commit, a branch, or a patch with a manifest, in a disposable clone it creates itself, running the rehearsal in-process. The terminal screen (`hlith`, `hlith ui`) shows status and recorded runs; starting a check there is not available.
- One decision per run: landed in the disposable clone (`0`), REFUTED (`10`), NOT-DERIVED (`11`), UNVERIFIED (`12`), BOUNDARY (`4`).
- HELD requires agreement on explored inputs **and** a named source certificate (`R0`, `NORM`, `R2`, `R3`, `R4`, `TYP`, `SYM`), universal or scoped; `--strict-domain` refuses scoped certificates without exact-type entry guards.
- Certificates are refused when any non-test file in the tree can rebind a name the proof relies on, or the target's import closure uses reflection.
- REFUTED witnesses report how they were confirmed (standalone replay, repository-test rerun, or `unstable-unchecked`); truncated or unreproduced witnesses are UNVERIFIED.
- `--json` output in the versioned `hlith.check/1` envelope for agents.

### Witnesses
- `hlith replay RUN_ID` re-runs a recorded witness on both versions under confinement.
- `hlith replay RUN_ID --pytest-out FILE --expect pre|post` exports a reproduced simple-call witness as a dependency-free static pytest test (`from <module> import <name>`, direct literal call, scoped `sys.path` restoration in `finally`, no `hlith` import). `--expect` is required: `pre` asserts the original behavior (a regression guard: fails on the buggy change, passes when corrected); `post` asserts the accepted change. Exceptions are asserted by type and recorded message. Witnesses with printed output, warnings, argument/receiver changes or state writes, return-kind-only and other unsupported witnesses are refused with nothing written; a refusal leaves replay's exit status unchanged and is reported in stderr and `pytest_export.status`. A REFUTED obligation with a recorded replayable call now carries a versioned `witness_record` (schema version 1); obligations without a recorded call do not, and witnesses recorded by earlier builds replay but do not export (`legacy-witness:`). Once committed in `tests/`, a retained static guard participates in later `hlith check` test-reach and call-site analysis.
- An exported `--expect pre` guard left uncommitted in a test path is recognized by a later `hlith check` (exact exported bytes, same repository and base commit, same `HLITH_STATE_DIR`) as a provenance-bound additive obligation: run confined on base and post, base pass required, discharges only itself, never REFUTED (guard failures are UNVERIFIED), and a guard-only patch is `guard-alone` NOT-DERIVED. Any other newly added test, or an altered guard, still ends `NOT-DERIVED` (exit `11`, `added-unreached`).
- `hlith inspect`, `status`, `history` read run records; `annotate`, `quarantine`, `escalate` record operator notes without changing a decision.

### Packaging and first-use
- The wheel ships the `hlith` console script and the companion `hlith-agent-hook` executable (sourced directly from `scripts/agent-hook/hlith-agent-hook.sh`) alongside the package, schemas, and notices.
- The sdist (`hlith-0.1.0.tar.gz`) includes `scripts/agent-hook/hlith-agent-hook.sh`, `scripts/landlock_capabilities.py`, `scripts/sbom_draft.py`, `uv.lock`, user docs, and the self-contained authored `examples/first-use/` demo fixture.
- Docs document exact cold install, virtualenv activation / `uv run --frozen` invocation, complete Claude Code hook wiring with `HLITH_BIN`, and retained-guard usage across source archive, sdist, and wheel installs.

### Review-only posture
- An engine fault during a check ends as exit `3` (INTERNAL ERROR) with a normal `hlith.check/1` envelope; nothing is decided or landed.
- `apply`, `run`, `resume` and `propose-deltas` are not commands (exit `2`); the internal engine module refuses them (exit `4`); original-repository landing recovery and Apply in the terminal screen are not offered.
- No marker, token or host capability record authorises the rehearsal; host state roots are created `0700` and a pre-existing root is never re-permissioned.

### Confinement
- User and mount namespaces, Landlock (ABI ≥ 6 required, refuses below), no network, loopback down.

### Known limits
See [LIMITATIONS.md](LIMITATIONS.md). In short: the one recorded external observation was a requested contract change caught while 123 reaching tests passed; no claim is made about accidental regressions; no real-repository HELD on a meaningful change shown; observations can be forged by the code under review; pathname UNIX sockets are an unverified surface and UDP is stopped only by the network namespace; Linux only; measured on Python 3.13.9; a full check can take many minutes.
