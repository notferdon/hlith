# Contributing

Hlith Review is open-source software. Contributions are welcome through GitHub issues and pull requests. For security reports, follow [SECURITY.md](SECURITY.md); do not open a public issue for a suspected vulnerability.

## Set up

```sh
uv sync --frozen --python 3.13.9
source .venv/bin/activate
hlith doctor --repo .
```

(Or prefix commands with `uv run --frozen`, for example `uv run --frozen hlith doctor --repo .`.)

Linux 6.12+ with unprivileged user namespaces and Landlock ABI ≥ 6 is required to run confinement tests. Keep `TMPDIR=/tmp` when running tests: socket tests hit the 108-byte UNIX path limit under long temporary paths.

## Test

```sh
TMPDIR=/tmp uv run --frozen pytest -q                       # default tier
TMPDIR=/tmp uv run --frozen pytest -q tests/test_<area>.py  # one area while developing
```

On a host without Landlock ABI ≥ 6 and unprivileged user namespaces, pytest halts before running the confinement group; see [docs/STAGING-VIEW.md](docs/STAGING-VIEW.md) for the host-independent subset flag.

Tests marked `real` need a real repository clone and are opt-in (`-m real`). `examples/first-use/` holds a self-contained authored demo fixture excluded from `testpaths = ["tests"]`. The public source snapshot excludes some upstream tests; [docs/STAGING-VIEW.md](docs/STAGING-VIEW.md) records what is present and what is not.

`hlith check` on Hlith's own checkout fails closed by design (its tests contain hostile-path fixtures).

## Rules for changes

- **Never weaken a refusal to get a pass.** A change that turns UNVERIFIED, NOT-DERIVED or BOUNDARY into HELD needs evidence that the new HELD is sound, including an adversarial test that would have been a false HELD.
- **Soundness tests come with the change.** Anything touching certificates, the differential, confinement or the review-only posture needs a negative control (a case that must stay refused) next to the positive case.
- **Say what is not checked.** New behavior reports its unexplored parts and limits in the verdict.
- **No network, no telemetry, no writes to the checked repository.**
- **No credentials or workstation-specific paths** in source, tests or fixtures. The full source repository has an export-hygiene guard for shipped files.

## Commit and review

- One logical change per commit, with a message that says what changed and why.
- Include the exact test command and result in the pull request.
- License: contributions are accepted under the Apache License 2.0 ([LICENSE](LICENSE)).

See [ARCHITECTURE.md](ARCHITECTURE.md) for where things live.
