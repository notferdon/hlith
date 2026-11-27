# SPDX-License-Identifier: Apache-2.0
"""review design plan (E2), red-first on 5a5bb3f1: a confinement grant that reaches the host state root (verifier/journal keys) is
refused by name, through the real run_confined path every caller uses. A sibling grant (negative control) still runs."""

from __future__ import annotations

import pytest

from hlith.hostio.confinement import GrantError, Profile, run_confined
from hlith.hostio.state import LocalHostState
from hlith.contract.capabilities import KeyPurpose


def test_a_grant_containing_the_host_state_root_is_refused_and_a_sibling_grant_runs(tmp_path, monkeypatch):
    state = tmp_path / "work" / "state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    LocalHostState(state).key(KeyPurpose.VERIFIER_ISSUE)  # the key file exists, as on a real host
    sibling = tmp_path / "work" / "repo"
    sibling.mkdir(parents=True)
    with pytest.raises(GrantError, match="host state root"):
        run_confined(["cat", str(state / "verifier-issue.key")], Profile(ro=(str(tmp_path / "work"),)), timeout=30)
    with pytest.raises(GrantError, match="host state root"):
        run_confined(["true"], Profile(rw=(str(state / "repositories"),)), timeout=30)  # inside the root
    assert run_confined(["true"], Profile(ro=(str(sibling),)), timeout=30).returncode == 0  # negative control


def test_an_explicit_host_state_root_not_named_by_the_environment_is_protected_too(tmp_path, monkeypatch):
    monkeypatch.delenv("HLITH_STATE_DIR", raising=False)
    root = tmp_path / "ui" / "host"  # e.g. the operator UI's <HLITH_UI_STATE>/host
    LocalHostState(root).key(KeyPurpose.VERIFIER_ISSUE)
    with pytest.raises(GrantError, match="host state root"):
        run_confined(["true"], Profile(ro=(str(tmp_path / "ui"),)), timeout=30)
