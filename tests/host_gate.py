# SPDX-License-Identifier: Apache-2.0
"""Supported-host gate for the test suite (review test posture, 2026-11-27).

Hlith's confined execution (hostio.confinement.run_confined) needs Landlock ABI >= 6 and unprivileged user namespaces. On a host
without them, every test that reaches confined execution fails with ENOSYS / a namespace error: those failures say nothing about
Hlith's behaviour, and a run that mixes them with real failures cannot be read.

The gate does NOT skip anything. Tests that reach confinement carry the `confinement` marker (explicit census:
tests/confinement_census.py). On an unsupported host the session stops before running anything unless the operator either
  - deselects the group explicitly:   pytest -m "not real and not confinement"   (a host-independent run; NOT a full-suite result), or
  - runs it anyway to observe it:     HLITH_TEST_UNSUPPORTED_HOST=run pytest      (failures there are expected host failures).
Every session prints the host facts and how many confinement tests ran or were deselected."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess

REQUIRED_LANDLOCK_ABI = 6  # hlith.operator.tui.host._boundary_causes: "the engine requires 6"
_SYS_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_CREATE_RULESET_VERSION = 1


def landlock_abi() -> tuple[int, str]:
    """(abi, detail): abi is 0 when the kernel does not offer Landlock (ENOSYS, EOPNOTSUPP) or the query fails."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        ctypes.set_errno(0)
        abi = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION))
        err = ctypes.get_errno()
    except OSError as e:  # no libc syscall(): not Linux
        return 0, f"no syscall interface ({e})"
    if abi < 0:
        return 0, f"landlock_create_ruleset errno {err} ({os.strerror(err)})"
    return int(abi), f"abi {abi}"


def userns_available() -> tuple[bool, str]:
    """Can an unprivileged process create a user namespace? Tried in a child (never in the test process)."""
    if shutil.which("unshare"):
        try:
            done = subprocess.run(["unshare", "-Ur", "true"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"unshare could not run ({type(e).__name__})"
        return done.returncode == 0, ("user namespaces available" if done.returncode == 0
                                      else f"unshare -Ur failed: {(done.stderr or '').strip()[:120]}")
    if not hasattr(os, "unshare"):
        return False, "no unshare(1) and no os.unshare"
    pid = os.fork()
    if pid == 0:  # child: try, report through the exit code, never return into pytest
        try:
            os.unshare(os.CLONE_NEWUSER)
            os._exit(0)
        except BaseException:  # noqa: BLE001
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    ok = os.waitstatus_to_exitcode(status) == 0
    return ok, "user namespaces available" if ok else "os.unshare(CLONE_NEWUSER) failed"


_FACTS: dict | None = None


def host_facts() -> dict:
    global _FACTS
    if _FACTS is None:
        abi, abi_detail = landlock_abi()
        ns, ns_detail = userns_available()
        reasons = []
        if abi < REQUIRED_LANDLOCK_ABI:
            reasons.append(f"Landlock {abi_detail}; Hlith requires ABI >= {REQUIRED_LANDLOCK_ABI}")
        if not ns:
            reasons.append(f"user namespaces: {ns_detail}")
        _FACTS = {"landlock_abi": abi, "landlock": abi_detail, "userns": ns, "userns_detail": ns_detail,
                  "supported": not reasons, "reasons": reasons}
    return _FACTS
