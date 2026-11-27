# Supported domain

This page summarizes the current operating envelope described by the README and operator manual. It is not a blanket qualification claim, and it does not claim that every case in this envelope is supported.

## Host and interpreter

Hlith requires Linux with unprivileged user namespaces and Landlock ABI 6 or newer (Linux 6.12+). If the host cannot provide confinement, the run ends at exit 4 before judging a change.

### Confinement capability boundary

What each layer does, so the claim is not read as wider than it is (`python scripts/landlock_capabilities.py` reports the host's actual ABI and what Hlith requests; the development host reports ABI 8):

| Path out of a confined worker | What stops it | Landlock's part |
|---|---|---|
| File reads/writes outside the grants | mount view (only granted paths exist) + Landlock filesystem rules | yes (ABI 1+; truncate ABI 3, device ioctl ABI 5) |
| TCP bind / connect | Landlock network rules; with `net=False` also the empty network namespace | yes (ABI 4+) |
| Abstract UNIX sockets, signals to host processes | Landlock scopes | yes (ABI 6+, required) |
| Pathname UNIX sockets (connect / sendmsg to an existing socket file) | mount view + refusal of any socket/FIFO/device inside a granted tree (checked before the run) | **no**: no right for connecting to an existing pathname socket is requested, and the inspected headers/source do not support one; an unverified filesystem-rule surface |
| UDP | with `net=False`: the empty network namespace (loopback down) | **no**: no Landlock UDP right is requested or supported by the inspected source; network namespace only |

Confinement limits: pathname AF_UNIX reachability is **not empirically verified** because host-socket probing requires explicit security authorization. Grant vetting is a point-in-time walk: interpreter prefixes are re-vetted at most every 600 s, and system library trees are not vetted per run. UDP isolation rests on the network namespace alone: loopback stays down, which also means `localhost` services cannot be reached from inside the confinement.

### Review-only distribution boundary

**Review-only distribution boundary.** `hlith check` runs its rehearsal in-process, in a disposable clone it creates itself, and does not write the selected repository. No marker, token or host capability record authorises that rehearsal, and `hlith` has no command that lands a change: `apply`, `run`, `resume` and `propose-deltas` are not commands (`hlith run` exits `2`, invalid choice), and the internal engine module refuses `run`, `resume` and `propose-deltas` with exit `4`. The terminal screen does not start checks. This is a supported-workflow guarantee, not an isolation boundary: another program running as you can change your files directly. Hlith Review does not claim "impossible", only "not offered".

### Observation boundary

Observations are made inside the process that runs the changed code. Hlith does not protect them against code written to falsify them: a REFUTED witness, a test result or an agreement may be forged by such code. The supervisor's own result channel and scratch files are out of that code's reach. Verdicts without evidence are not asserted.

The measured qualification environment is Python 3.13.9, installed from the frozen lock with `uv sync --frozen --python 3.13.9` and used for both Hlith and the target code. `pyproject.toml` declares `requires-python = ">=3.12"`; that is the package install range, not evidence that every Python version in the range is qualified. A repository venv can select a different target Python. Use `hlith doctor --probe-target --import MODULE` to check its actual version and a required import in confinement. Successful imports on another interpreter establish those observations only. Select an operator-trusted CPython installation or virtualenv for verification.

## Repository and change

The supported repository is a local checkout with a real `.git` directory owned by the operator, ordinary supported Git configuration, and an isolated object store. Submodules are supported. The candidate change is Python code with callable effects that Hlith can derive, repository tests that reach the impacted code, and an executable independent differential for those effects. The change manifest and any declared behavior deltas must be available for review; approval binds to the exact declared delta set.

`hlith check` rehearses on a disposable clone and leaves the original repository unchanged. Applying a change to your repository is not offered in this distribution (`apply`, `run`, `resume` and `propose-deltas` are not commands; the terminal screen does not start checks); merging is done by you, outside Hlith.

## Named refusal boundaries

Refusals preserve the target. Their exit code names the missing evidence or boundary:

- **11 — NOT-DERIVED:** unsupported non-Python edits or unmodeled effects such as dynamic reflection, `eval`/`exec`, C/FFI, or I/O can prevent Hlith from deriving a trustworthy effect account. Depending on what evidence is available, an unmodeled effect can instead end as exit 12.
- **12 — UNVERIFIED:** no repository test reaching the changed code means there is nothing of yours to run, so the change is not judged; differential agreement alone does not substitute for it. Missing required declarations, unimportable target dependencies, or an unavailable executable differential also remain unverified; they are never treated as passed.
- **4 — BOUNDARY:** confinement or repository shape is unsupported. This includes linked worktrees, sparse checkouts, partial clones, Git LFS filters, object alternates, and unsafe repository configuration.

## Meaning of HELD

A differential HELD requires BOTH concrete agreement on the explored observations AND an independent positive-HELD equivalence certificate (`R0` identity modulo renaming, `NORM` sound structural normalization, `R2` approved guard insertion, `R3` pure boolean reorder, `R4` hoisted skip, `TYP` typed normalization, or `SYM` Z3 symbolic equivalence).

Hlith separates **universal proofs** from **exact-builtin domain proofs**:

- **Universal proofs** (`domain=()` — `R0`, `NORM`, `R4`, `SYM` in `mode="any"`, and unconditional singleton-identity `is None|True|False` `R2` guards) hold for all Python objects without caller-type assumptions. Symbolic equivalence (`SYM`) also handles pure refactors inside modules whose unchanged helpers use I/O or `__file__`, opaque builtin method fallbacks (`str`/`bytes`), and function-scoped taint tracking without weakening soundness.
- **Scoped exact-builtin domain proofs** (default for typed `R2` exact-`str`/exact-`int`, `R3`, `TYP`, and `SYM` over exact `str`, `int`, `bool`, `float`, `list[int]`, `tuple[int, ...]`) require identical exact-builtin annotations on both versions, zero subclasses of any claimed builtin base defined in-module, zero modified/added/removed builtin subclasses anywhere in the tree, full source+test call-site closure, runtime differential subclass rejection (`_domain_violation`), and a machine-hashed `domain_record` plus explicit `"outside this claim"` scope disclosure in the verdict.
- **Strict open-caller mode** (`--strict-domain` on `hlith check`, or `HLITH_CERT_STRICT_DOMAIN=1`) refuses every typed domain proof unless both versions self-enforce exact builtin types via identical leading terminating `if type(p) is not T:` (or `if type(p) not in (int, bool):` for `int`) entry guards.

### What a certificate assumes about the rest of your repository

Every positive certificate carries this boundary text:

> Assumes the target is imported in a fresh interpreter from the committed tree. Files outside the target's import closure (callers, tests, scripts, build helpers, plugins loaded by third-party code) are not checked for rebinding or mutating it.

What Hlith actually checks before it issues a certificate:

- **Rebinding and writes, whole tree.** Every non-test Python file in the committed tree is read for code that could rebind or overwrite a name the proof relies on: direct assignments, `setattr`/`delattr`, writes through `vars()` or `__dict__`, and namespace handles that are stored or passed on where Hlith cannot follow them. Any such write refuses the certificate.
- **Reflection, import closure only.** Dynamic execution and import machinery (`eval`, `exec`, `compile`, `importlib`, computed `getattr`, and similar) is refused anywhere in the files the target imports. Files the target does not import are not checked by this rule.
- **No trust by distance.** A file is not trusted just because the target never imports it. If such a file contains machinery that can run unanalysed code and replace what the proof relies on, the certificate is refused and the verdict is UNVERIFIED. Hlith does not offer a mode that relaxes this to "only the import closure matters".

Not covered, and stated in every certificate's scope:

- writes from outside the scanned tree: your test files, untracked or ignored files, installed packages, other processes, import hooks, mutation through frames or `gc`;
- a caller that mutates the module after importing it;
- reflection in files outside the import closure, except as described under "No trust by distance".

These checks are fail-closed: when in doubt the certificate is refused. In practice this means many real repositories end UNVERIFIED rather than HELD for a behavior-preserving change, because some file in the tree contains dynamic machinery. So far, real-repository evidence consists of refusals, REFUTED witnesses and UNVERIFIED results; a HELD verdict on a meaningful change in a real-world repository has not been shown.

For bounded integer/boolean functions (including augmented assignment, `abs`/`min`/`max`, and exception guards), the symbolic prover also seeds the concrete differential with Z3 countermodels. For mapping-typed callables with changed string literals and multi-parameter callables with declared intended deltas, differential exploration synthesizes targeted mapping and background domain seeds. A reported regression (`REFUTED`, exit 10) always requires a concrete observed difference between the two confined executions. The report says how the witness was confirmed: by a standalone `hlith replay` of that input, by re-running the repository tests that exposed it, or not at all (`unstable-unchecked`, for example when the function was removed or the input is a stand-in object; treat it as a lead). A truncated or unreproduced witness is reported as UNVERIFIED instead.
