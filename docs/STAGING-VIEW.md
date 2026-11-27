# Source snapshot

This public source snapshot is a curated tree export. Non-public paths were excluded before publication. The public repository history is a single snapshot commit, not a development history.

```sh
mkdir hlith-view
git archive --format=tar --prefix=hlith/ <COMMIT> | tar -x -C hlith-view
```

The snapshot is a tree export from the source repository. The public repository contains only this curated tree.

## Contents and counts

- **548** files in this view.
- test files under `tests/` (`test_*.py`): 424 in the source repository, **147 excluded** from the view, 277 in the view. The view also carries `examples/first-use/repo/tests/test_timeouts.py`, the first-use fixture's own test.
- pytest collection of the view (`pytest --collect-only tests`, default `-m 'not real'`): 4869 tests, 4835 selected, 34 `real` deselected.
- The view includes the README image, external-observation evidence, the first-use fixture, the local gate script, and the issue templates. It excludes the terminal-screen fixture suite, the evidence archive, and tests that depend on workstation-specific fixtures.

## Supported-host test gate

The suite is not a single pass/fail number. On a host without Landlock ABI 6 or newer and unprivileged user namespaces, every test that reaches confined execution fails for that reason alone. `tests/conftest.py` prints the host facts and a gate line in the summary, and marks the tests listed in `tests/confinement_census.py` with `confinement`. Nothing is skipped because of the host: on an unsupported host the session stops before running unless the operator chooses

- `pytest -m "not real and not confinement"`: the host-independent group only. This is not a full-suite result, and the summary says so;
- `HLITH_TEST_UNSUPPORTED_HOST=run pytest`: run everything to observe the host failures.

Tests that exercise routes not offered by Hlith Review are listed with a reason in `tests/obsolete_census.py` and skipped. `tests/test_obsolete_census.py` keeps that list exact and bounded. Behavior Review still offers is tested through `hlith check` or the review-only contract.

## Local gate and hosted CI

`scripts/local_standards_gate.sh [COMMIT]` is a bounded local gate: it exports the selected commit with `git archive`, runs standards checks, a named Review-product test group, and the kill lines. It is not a whole-suite result. Its `HLITH_KL5_REPO` input is a pinned public psf/requests checkout; the script never fetches it.

`.github/workflows/standards.yml` is dispatch-only and GitHub Actions is disabled for this repository. No hosted-CI result is claimed. A manual dispatch, if ever enabled, runs the same local gate; a BOUNDARY exit is not a pass.

## Test coverage not in the view

The terminal-screen suite (`tests/operator/tui/`) is excluded. Its Apply-flow and Running-screen tests cover routes Hlith Review does not offer. Tests whose fixtures depend on the source-only evidence archive or workstation-specific paths are excluded or skipped with a named reason when that fixture is absent. A test run on this view therefore covers less than the full source repository; it does not replace it.

## Omitted obsolete-census files

<details><summary>Obsolete-census files omitted from this view</summary>

- `tests/operator/tui/test_apply_refused_target.py`
- `tests/operator/tui/test_apply_resize_pty.py`
- `tests/operator/tui/test_compact_resize_pty.py`
- `tests/operator/tui/test_original_land.py`
- `tests/operator/tui/test_overlay_exit_pty.py`

</details>
