# Architecture

Hlith Review takes a repository and a proposed change and looks for behavior and contract changes the repository's tests miss: did behavior change, and on what evidence? This page is a map of the source for contributors. Behavior and limits are in [README.md](README.md), [LIMITATIONS.md](LIMITATIONS.md) and [docs/SUPPORTED_DOMAIN.md](docs/SUPPORTED_DOMAIN.md).

## One check, end to end

```
hlith check (the terminal screen shows status and recorded runs only)
  │  select the change (uncommitted, commit, branch, patch + manifest)
  ▼
disposable clone of the repository          (operator/, gate/)
  │
  ▼
effect account: what the change touches     (effect/)
  │  changed callables, their callers, I/O and unmodeled constructs
  ▼
obligations: what must be shown             (obligation/)
  │  one obligation per changed behavior; declared intended changes become checked deltas
  ▼
evidence, each under kernel confinement     (hostio/, obligation/, symeq/)
  │  ├─ repository tests that reach the changed code
  │  ├─ differential: run base and change side by side on explored inputs
  │  └─ source certificate: a proof rule (R0, NORM, R2, R3, R4, TYP, SYM) that the change preserves behavior
  ▼
verdict per obligation: HELD / REFUTED / UNVERIFIED / NOT-DERIVED
  │
  ▼
gate: one decision and exit code            (gate/)
  │  0 landed in the clone · 10 refuted · 11 not derived · 12 unverified · 4 boundary · 3 engine internal error
  ▼
run record in host state, replay, feedback  (operator/, feedback/)
```

## Packages (`src/hlith/`)

| Package | Role |
|---|---|
| `operator/` | CLI (`cli.py`), the `check` command, the terminal screen (`tui/`), host state, the review-only product posture (`product.py`) |
| `gate/` | Turns obligation verdicts into one decision; owns the disposable rehearsal and the run record |
| `effect/` | Builds the effect account of a change: changed callables, call cone, effects Hlith cannot model |
| `obligation/` | Derives obligations; equivalence certificates (`equiv_cert.py`); the binding and import-closure checks a certificate must pass (`binding_gate.py`, `closure_gate.py`); intended-change predicates |
| `symeq/` | Z3-backed symbolic equivalence for bounded integer, boolean and string functions |
| `differential.py`, `drive_inputs.py`, `drive_objects.py` | The differential: input exploration, confined execution of base and change, witness recording and replay |
| `hostio/` | Kernel confinement (user + mount namespaces, Landlock, no network), launched as a self-contained script |
| `feedback/` | Records across runs: confirmed counterexamples, transferred parameter seeds, unresolved constructs; stored on the host, never in your repository |
| `agent/` | Layer that drives a coding agent in confined staging; not offered in this review distribution |
| `contract/` | Schemas and shared types |

## Principles the code follows

- **Fail closed.** If Hlith cannot confine, derive, reach, replay or certify, the verdict says so (exit 11, 12 or 4). It is never a pass.
- **Two independent conjuncts for HELD.** Concrete agreement comes from the confined differential; the certificate is computed on the host from source. Neither alone yields HELD.
- **The target is untrusted.** Target code only runs inside confinement. Its observations are disclosed as forgeable by that code (see [SECURITY.md](SECURITY.md)).
- **The checked repository is read, not written.** The supported workflows work on a disposable clone; applying a change is not offered in this distribution.
- **Records are host-side.** Run records and feedback live under the host state directory (`hlith doctor --json` prints it).

## Where to start reading

- A verdict: `operator/check.py` → `gate/` → `obligation/` → `differential.py`.
- A certificate: `obligation/equiv_cert.py` (`certify`), then `binding_gate.py` and `closure_gate.py` for why one is refused.
- Confinement: `hostio/confine_exec.py` (the Landlock ruleset and the ABI floor).
- Witness replay and pytest export: `operator/replay_cmd.py`.
