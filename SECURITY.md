# Security

Hlith Review runs untrusted code: the change under review and the repository it lives in. This page states what protects you, what does not, and how to report a problem.

## Reporting

Report suspected vulnerabilities privately through GitHub private vulnerability reporting for this repository (Security → Report a vulnerability). Include the Hlith build (`hlith --version`), `hlith doctor --json`, and the smallest repository and change that show the problem. Do not publish details before the maintainer has responded.

Especially valuable: a `LANDED` verdict (exit `0`, all obligations held) on a change whose behavior plainly differs; a write to the checked repository from a supported workflow; any escape from confinement.

## What protects you

| Threat | Protection | Limit |
|---|---|---|
| Changed or repository code touching your files | Runs in a new user and mount namespace; only granted paths exist; Landlock filesystem rules; the checked repository is never mounted writable | Grant vetting is point-in-time (interpreter prefixes re-vetted at most every 600 s; system libraries not vetted per run) |
| Network access | Empty network namespace; Landlock TCP rules | UDP is stopped by the network namespace only; Landlock does not cover it here |
| Abstract UNIX sockets, signals to host processes | Landlock scopes (ABI 6+, required; Hlith refuses below ABI 6) | — |
| Pathname UNIX sockets on the host | Mount view; sockets, FIFOs and devices refused in granted trees before the run | **Unverified filesystem-rule surface.** No Landlock right for connecting to an existing socket is requested or supported by the inspected source. Reachability of a host pathname socket has not been established and is not claimed |
| Forged supervisor result | The supervisor's result channel and scratch files are outside the confined code's reach | — |
| A false HELD from code that fakes agreement | HELD also requires a certificate computed on the host from source | An unsound certificate; evidence the certificate does not cover |
| Writes to your repository | `hlith check` rehearses in-process in a disposable clone it creates; `apply`, `run`, `resume` and `propose-deltas` are not commands; the terminal screen does not start checks | A supported-workflow guarantee, not a boundary against other programs running as you |
| Executable Git surfaces (hooks, `filter.*`, unsafe config, linked worktrees, sparse or partial clones, LFS, object alternates) | Refused before cloning or execution (exit `4`) | — |

## What does not protect you

- **Observations can be forged by the code under review.** Observations are made inside the process that runs the changed code. Hlith does not protect them against code written to falsify them: a REFUTED witness, a test result or an agreement may be forged by such code. The supervisor's own result channel and scratch files are out of that code's reach. This holds for hostile unchanged repository code too.
- **No syntactic lint protects observation integrity.** Integrity of observations is disclosed, not enforced.
- **Other programs running as you** are outside the support boundary: they can change your repository directly. Hlith Review's own rehearsal is not authorised by any marker, token or host capability record, and it offers no command that lands a change.

## Host requirements that matter for security

- Linux 6.12+, unprivileged user namespaces, Landlock ABI ≥ 6. Hlith refuses to run a check rather than run unconfined.
- On Ubuntu 24.04+ (`kernel.apparmor_restrict_unprivileged_userns=1` by default) confinement is expected to be unavailable and Hlith refuses (not measured).
- In a default Docker container (observed local ubuntu:24.04, default seccomp, no network), unprivileged user namespaces are denied; `hlith doctor --probe-target` exits 1 and `hlith check` refuses instead of running unconfined. Docker is unsupported and fails closed.
- The development host reports Landlock ABI 8; other ABIs are unmeasured. In a source archive or sdist checkout, run `python scripts/landlock_capabilities.py` to see your host's ABI and what Hlith requests. That script is not in the wheel.

## Dependencies

The frozen lock pins exact hashes (`uv sync --frozen`). A plain `pip install` of the wheel resolves newer versions of `libcst`, `z3-solver`, `hypothesis` and `pytest`. Licenses and provenance: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [docs/PROVENANCE.md](docs/PROVENANCE.md).
