# First-use demo (self-contained authored fixture)

This directory holds a small, self-contained Python fixture (`demo_limits.timeouts.effective_timeout`) for running Hlith Review end to end on one machine with no external repository or private state.

**What this is, and what it is not.** This is an **authored mechanism fixture** built to finish in tens of seconds and exercise the review loop (`doctor` → `REFUTED` witness → `replay` → static pytest guard in `tests/` → uncommitted fix → `LANDED` rehearsal → commit). It is **not** a real-repository benchmark or a speed guarantee:

- The one recorded external observation was an intentional behavior/contract change; no claim is made about accidental regressions.
- A HELD verdict on a meaningful change in a real-world repository has not been shown.
- Larger real repositories can take minutes (see [docs/EXTERNAL-OBSERVATION.md](../../docs/EXTERNAL-OBSERVATION.md) for the recorded external observations).

## Prerequisites

Run from the root of an unpacked Hlith source archive or sdist after installing with `uv sync --frozen --python 3.13.9` and activating `.venv`:

```sh
source .venv/bin/activate
```

If you prefer not to activate `.venv`, prefix `hlith` and `pytest` below with `uv run --frozen`, or call `.venv/bin/hlith` and `.venv/bin/pytest` directly. Needs Linux 6.12+ with unprivileged user namespaces, Landlock ABI 6 or newer, and `git`.

## 1. Create a disposable Git repository from the fixture

```sh
HLITH_SRC="$PWD"
WORK="$(mktemp -d)"
DEMO="$WORK/demo"
cp -r "$HLITH_SRC/examples/first-use/repo" "$DEMO"
git -C "$DEMO" init -q -b main
git -C "$DEMO" config user.name "Demo User"
git -C "$DEMO" config user.email "demo@example.invalid"
git -C "$DEMO" add -A
git -C "$DEMO" commit -qm "base"
```

Optionally set `export HLITH_STATE_DIR="$WORK/state"` so demo run records stay inside `$WORK` instead of `~/.local/state/hlith`.

## 2. Check host confinement and target Python (read-only)

```sh
hlith doctor --repo "$DEMO" --probe-target
```

All checks should report `ok` (including `Confinement settings` and `Target Python`, using Hlith's interpreter because the fixture has no external dependencies). If `doctor --probe-target` exits `1`, the host cannot establish confinement and `hlith check` will refuse (fail closed).

## 3. Introduce a contract-breaking edit that `pytest` misses

`patches/01-remove-guard.patch` removes `if value <= 0: raise ValueError("Timeout must be positive")` from `demo_limits/timeouts.py`. The fixture's existing test only checks positive values (`10` and `500`), so `pytest` still passes:

```sh
git -C "$DEMO" apply "$HLITH_SRC/examples/first-use/patches/01-remove-guard.patch"
(cd "$DEMO" && pytest -q)
```

Expected: `1 passed`.

## 4. Run `hlith check` (expect exit `10`, `REFUTED`)

```sh
hlith check --repo "$DEMO" --uncommitted --json --artifact-out "$WORK/out-refuted" > "$WORK/check-refuted.json"
echo "exit=$?"
```

Expected: `exit=10`, and `$DEMO` stays untouched (`git -C "$DEMO" status --short` still shows only ` M demo_limits/timeouts.py`). Inspect the JSON envelope:

```sh
python3 - "$WORK/check-refuted.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("run_id:", d["check"]["run_id"])
print("headline:", d["check"]["headline"], "exit_status:", d["artifact"]["exit_status"])
print("apply_command:", d["check"]["apply_command"])
for ob in d["artifact"]["obligations"]:
    print(" ", ob["id"], "->", ob["verdict"], "|", ob.get("witness") or ob.get("stop_reason"))
PY
```

Observed output shape:

```text
run_id: run-<12 hex>
headline: REFUSED · REFUTED exit_status: 10
apply_command: None
  signature_binding:demo_limits.timeouts.effective_timeout -> held | None
  differential:demo_limits.timeouts.effective_timeout -> refuted | z3:delta_rel_counterexample-seed demo_limits.timeouts.effective_timeout(value=0, maximum=-1): pre -> raise builtins.ValueError(Timeout must be positive); post -> return -1
  guard-removed:demo_limits.timeouts.effective_timeout:7 -> not-derived | precondition removed: base line 7 `if value <= 0: raise ValueError` has no counterpart after the change; inputs it rejected may now proceed
```

## 5. Inspect, replay, and export a static pytest guard into `tests/`

Save the run ID, inspect the record, replay the witness under confinement, and export a standalone regression guard (`--expect pre`) into the repository's `tests/` directory. Leave it uncommitted:

```sh
RUN_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["check"]["run_id"])' "$WORK/check-refuted.json")"
hlith inspect "$RUN_ID" --repo "$DEMO"
hlith replay "$RUN_ID" --repo "$DEMO" --pytest-out "$DEMO/tests/test_hlith_guard.py" --expect pre --json
```

Expected: exit `0`, `"status": "REPRODUCED"`, stderr `pytest witness: <path>/tests/test_hlith_guard.py`, and `"pytest_export": {"expect": "pre", ..., "status": "written"}`.

The exported file imports `demo_limits.timeouts` statically (`from demo_limits.timeouts import effective_timeout`), restores `sys.path` in a `finally` block, and does **not** import `hlith`. Run it against the buggy tree:

```sh
(cd "$DEMO" && pytest -q tests/test_hlith_guard.py)
echo "guard_on_buggy_exit=$?"
```

Expected: `1 failed` (`guard_on_buggy_exit=1`), with `AssertionError: expected pre raised 'builtins.ValueError', got ('ret', '-1')`.

Writing the guard outside the repository instead, for example `--pytest-out "$WORK/test_timeout_guard.py"`, and running it with `HLITH_WITNESS_ROOT="$DEMO" pytest -q "$WORK/test_timeout_guard.py"` also works.

## 6. Fix the code without committing and re-check with the guard in the diff (expect exit `0`)

`patches/02-restore-guard-refactor.patch` restores the `value <= 0` guard while keeping a small behavior-preserving refactor. `git checkout -- .` restores tracked files only, so the untracked guard stays:

```sh
git -C "$DEMO" checkout -- .
git -C "$DEMO" apply "$HLITH_SRC/examples/first-use/patches/02-restore-guard-refactor.patch"
git -C "$DEMO" status --short
hlith check --repo "$DEMO" --uncommitted --json --artifact-out "$WORK/out-landed" > "$WORK/check-landed.json"
echo "exit=$?"
```

Expected: `status` shows ` M demo_limits/timeouts.py` and `?? tests/test_hlith_guard.py`, then `exit=0` (`LANDED` in the disposable rehearsal clone; `$DEMO`, its `HEAD` and both files are unchanged). Print the obligations with the same snippet as in step 4, using `check-landed.json`. Observed output shape:

```text
headline: LANDED exit_status: 0
apply_command: None
  signature_binding:demo_limits.timeouts.effective_timeout -> held | None
  differential:demo_limits.timeouts.effective_timeout -> held | None
  signature_binding:tests.test_hlith_guard.test_recorded_pre_behavior -> held | None
  exported-guard:tests/test_hlith_guard.py:demo_limits.timeouts.effective_timeout -> held | None
```

No intermediate commit was needed. Hlith recognized the guard because its bytes are exactly what the step 4 run (same repository, same base commit, same `HLITH_STATE_DIR`) exports with `--expect pre`.

- The guard runs confined on base and post as an additive `exported-guard:` obligation that discharges only itself. The target's own `differential:` obligation still decides the verdict.
- A guard never produces `REFUTED` (guard failure ends `UNVERIFIED`) and cannot land a guard-only patch (`guard-alone`, `NOT-DERIVED`).
- Any edited byte, an `--expect post` file, a cross-base or cross-store guard, or any other newly added test ends `NOT-DERIVED` (exit `11`, `added-unreached`). Full recognition rules: [docs/CLI.md](../../docs/CLI.md).

## 7. Commit the fix and retain the guard

Once you accept the fix, commit the guard so it runs in ordinary `pytest` and participates in later `hlith check` runs. It can go in the same commit as the fix or in its own commit:

```sh
git -C "$DEMO" add demo_limits/timeouts.py tests/test_hlith_guard.py
git -C "$DEMO" commit -qm "Refactor effective_timeout keeping positive guard; retain hlith regression guard"
(cd "$DEMO" && pytest -q)
```

Expected: `2 passed` (with no `hlith` import and no `HLITH_WITNESS_ROOT` needed).

The landed artifact records the guard under `effect_account.impacted_tests` and `effect_account.impacted_sites`. The published schema document names the corresponding closed-schema fields `impacted_test_nodes` and `impacted_call_sites`. The writer and the landed-path test use the first pair.

Clean up when finished:

```sh
rm -rf "$WORK"
```
