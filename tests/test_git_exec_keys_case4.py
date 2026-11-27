"""review 71c64805 G2-HOSTILE minors: repository config keys that name a program git may run must make the target hostile (refused by
name) rather than rely on the per-call -c overrides alone (review, red-first)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hlith.hostio.git_read import HardenedGitRead


def _repo(tmp_path: Path, key: str, value: str) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    subprocess.run(["git", "-C", str(r), "config", key, value], check=True)
    return r


@pytest.mark.parametrize("key", ["core.alternateRefsCommand", "diff.external", "remote.origin.uploadpack", "remote.Origin.receivepack"])
def test_a_config_key_that_names_a_program_makes_the_target_hostile(tmp_path: Path, key: str):
    r = _repo(tmp_path, key, f"/bin/sh -c 'touch {tmp_path}/hlith-canary'")
    reason = HardenedGitRead().repository_hostile_reason(r)
    assert reason is not None and reason.endswith(key.lower()), reason


def test_ordinary_remote_and_diff_settings_stay_allowed(tmp_path: Path):
    r = _repo(tmp_path, "remote.origin.url", "https://example.invalid/x.git")
    subprocess.run(["git", "-C", str(r), "config", "diff.renames", "true"], check=True)
    assert HardenedGitRead().repository_hostile_reason(r) is None
    from hlith.operator import gitq

    assert gitq.refusal(r) is None  # both vets agree: ordinary remote and diff settings are not a false refusal
