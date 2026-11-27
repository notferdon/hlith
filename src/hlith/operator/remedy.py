# SPDX-License-Identifier: Apache-2.0
"""One-line remedies for the environment problems a first-time user hits. Looked up from the text the engine actually reported
(an exit-4 boundary refusal, an engine's stderr); nothing is guessed when the text matches nothing."""

from __future__ import annotations

import re

LANDLOCK = ("hlith confines every worker and checker with Linux user namespaces + Landlock (kernel 6.12 or newer: Landlock ABI >= 6) and "
            "REFUSES to run unconfined. Check `uname -r`, that unprivileged user namespaces are enabled "
            "(`sysctl kernel.unprivileged_userns_clone`, `kernel.apparmor_restrict_unprivileged_userns`) and that Landlock is in the "
            "active LSM list (`cat /sys/kernel/security/lsm`).")
GIT_FEATURE = ("Git on PATH failed Hlith's hardened feature probe. Install a Git build supporting the required feature named above "
               "and verify with `hlith doctor`.")

_RULES = (
    (re.compile(r"host-confinement-unavailable|confinement-canary-failed|landlock|user namespace|userns|unshare|mount-namespace-failed|clone\(.*NEWUSER|operation not permitted.*namespace", re.I), LANDLOCK),
    (re.compile(r"unsupported-git-feature|unsupported git feature|unsupported or unusable git|--attr-source", re.I), GIT_FEATURE),
    (re.compile(r"No module named ['\"]?([\w.]+)", re.I),
     "a Python module the engine or the repository needs is not installed in the interpreter that ran it: install it there, or pass "
     "--target-python <python of the repository's own virtualenv> (hlith ui: it uses .venv/ or venv/ when present)."),
    (re.compile(r"proposer paths absent|blindness unprovable", re.I),
     "the checker must prove it cannot read the proposer's files: give the real patch/manifest/agent command paths (they must exist on this machine)."),
)


def remedy_for(text: str) -> str | None:
    s = str(text or "")
    for pat, advice in _RULES:
        if pat.search(s):
            return advice
    return None
