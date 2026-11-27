# SPDX-License-Identifier: Apache-2.0
"""Build the effect account ONCE per run (dogfood cost item).

`hlith run` needs the same account three times: derive, the CLI's recorded declaration, and `effect.declare`. Building it
walks and parses the whole repository, so each build is a full pass. Inside `with once():` `effect.build_effect_account`
is replaced by a memo keyed by (resolved repo, sha256 of the diff): every caller gets the same object (read-only by
contract: callers only read it or call `.to_dict()`), and a failed build is cached too, so a crash is raised again to
each caller with the same exception instead of being recomputed. The original function is restored on exit, so nothing
outside the run is affected and the memo cannot outlive the repository state it was built from.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from pathlib import Path

from . import effect


@contextmanager
def once():
    real = effect.build_effect_account
    memo: dict[tuple[str, str], tuple[bool, object]] = {}

    def memoised(repo_path, unified_diff):
        key = (str(Path(repo_path).resolve()), hashlib.sha256(unified_diff.encode()).hexdigest())
        if key not in memo:
            try:
                memo[key] = (True, real(repo_path, unified_diff))
            except Exception as e:  # noqa: BLE001 - cached and re-raised to every caller
                memo[key] = (False, e)
        ok, val = memo[key]
        if ok:
            return val
        raise val  # type: ignore[misc]

    effect.build_effect_account = memoised
    try:
        yield memoised
    finally:
        effect.build_effect_account = real
