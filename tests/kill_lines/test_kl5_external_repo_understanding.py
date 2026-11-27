"""KL5: Understanding layer reads arbitrary real external repositories via declared SHA-pinned mirror."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from hlith import effect

PINNED_SHA = "0e322af87745eff34caffe4df68456ebc20d9068"

# case: KL5 needs an external SHA-pinned mirror (HLITH_KL5_REPO), i.e. a real-repository test by the pyproject tier definition, so the
# default `pytest` collection (-m 'not real') does not run it. It is NOT skipped: scripts/verify_kill_lines.sh runs it with
# -m "real or not real", still fails closed without the mirror, and fails on any skip/deselect or a count below its floor.
pytestmark = pytest.mark.real


def test_kl5_external_repo_effect_account(tmp_path: Path) -> None:
    mirror = os.environ.get("HLITH_KL5_REPO", "").strip()
    if not mirror:
        pytest.fail("HLITH_KL5_REPO is not set (fail-closed: KL5 requires a declared SHA-pinned mirror path)")
    mirror_path = Path(mirror)
    if not mirror_path.is_dir():
        pytest.fail(f"HLITH_KL5_REPO does not exist: {mirror_path}")
    head = subprocess.run(["git", "-C", str(mirror_path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    expected_sha = os.environ.get("HLITH_KL5_SHA", PINNED_SHA).strip()
    if head != expected_sha:
        pytest.fail(f"HLITH_KL5_REPO HEAD {head} != expected pinned SHA {expected_sha}")

    clone = tmp_path / "ext"
    subprocess.run(["git", "clone", "--quiet", str(mirror_path), str(clone)], check=True)
    u = clone / "src/requests/utils.py"
    txt = u.read_text()
    target = "    value = value.strip(replace_chars)\n"
    assert txt.count(target) == 1
    u.write_text(txt.replace(target, "    value = value.strip()\n", 1))
    diff = subprocess.run(["git", "-C", str(clone), "diff"], capture_output=True, text=True, check=True).stdout
    subprocess.run(["git", "-C", str(clone), "checkout", "--", "src/requests/utils.py"], check=True)

    acct = effect.build_effect_account(clone, diff)
    assert len(acct.modified_callables) >= 1
    assert len(acct.callee_edges) >= 1
