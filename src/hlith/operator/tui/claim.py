# SPDX-License-Identifier: Apache-2.0
"""The CLAIM: the manifest `paths: {file: [kinds]}` derived MECHANICALLY from a diff (what files change and how), for the human
to confirm or edit. No behavioural delta is ever inferred here and nothing is approved: the engine checks the claim against what
the patch really does and refuses a mismatch."""

from __future__ import annotations

import re

from . import gitq

CONTENT = ("add", "modify", "delete")
EXTRA = ("mode", "symlink", "binary")
_HDR = re.compile(r"^diff --git a/(.*) b/(.*)$")


def derive(patch: bytes) -> dict[str, list[str]]:
    """{path: sorted kinds} with the same kind vocabulary and rules the engine uses to observe a change
    (add/delete/modify; symlink if either mode is 120000, else mode on a mode change; binary from numstat)."""
    kinds: dict[str, set[str]] = {}
    cur: str | None = None
    old_mode = new_mode = None
    status = "modify"

    def close():
        if cur is None:
            return
        k = kinds.setdefault(cur, set())
        k.add(status)
        if "120000" in (old_mode, new_mode):
            k.add("symlink")
        elif old_mode and new_mode and old_mode != new_mode:
            k.add("mode")

    for raw in patch.decode("utf-8", "surrogateescape").split("\n"):
        m = _HDR.match(raw)
        if m:
            close()
            cur, old_mode, new_mode, status = m.group(2), None, None, "modify"
            continue
        if raw.startswith("new file mode "):
            status, new_mode = "add", raw.split()[-1]
        elif raw.startswith("deleted file mode "):
            status, old_mode = "delete", raw.split()[-1]
        elif raw.startswith("old mode "):
            old_mode = raw.split()[-1]
        elif raw.startswith("new mode "):
            new_mode = raw.split()[-1]
        elif raw.startswith("index ") and raw.rstrip().endswith("120000"):
            old_mode = new_mode = new_mode or "120000"
    close()
    for path, a, d in gitq.numstat(patch):
        if a is None and d is None:
            kinds.setdefault(path, {"modify"}).add("binary")
    return {p: sorted(k) for p, k in sorted(kinds.items())}


def cycle_kind(kinds: list[str]) -> list[str]:
    """Change the content kind (add -> modify -> delete -> add), keeping mode/symlink/binary markers."""
    extra = [k for k in kinds if k in EXTRA]
    cur = next((k for k in kinds if k in CONTENT), "modify")
    nxt = CONTENT[(CONTENT.index(cur) + 1) % len(CONTENT)]
    return sorted([nxt, *extra])


def manifest(entries) -> dict:
    """entries: [(path, kinds, included)] -> {"paths": {path: kinds}} for the included ones (the manifest file the engine reads)."""
    return {"paths": {p: list(k) for p, k, inc in entries if inc}}
