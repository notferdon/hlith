"""Advisory review of 34669167 (case guard note): refuse_rw_over_ro_bind accepts an rw grant INSIDE an ro_bind tree
(rw=ro/cache, ro_bind=ro) while it refuses an rw grant ABOVE it. This file measures whether that asymmetry is a real writable escape:
a confined process gets ro/cache writable (the explicit, narrower grant) and must not be able to write anything else in the ro_bind
tree, by direct path, by `..` from the writable child, by a symlink planted in the writable child, or by rename out of it (review)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.hostio import confinement
from hlith.hostio.confinement import GrantError, Profile, run_confined

PROBE = r"""
import os, sys, json
ro, cache = sys.argv[1], sys.argv[2]
out = {}
def tryw(name, path):
    try:
        with open(path, "w") as fh:
            fh.write("PWNED\n")
        out[name] = "WROTE"
    except OSError as e:
        out[name] = type(e).__name__
tryw("direct", os.path.join(ro, "file.py"))
tryw("new_sibling", os.path.join(ro, "new.py"))
tryw("dotdot_from_cache", os.path.join(cache, "..", "file.py"))
try:
    os.symlink("../file.py", os.path.join(cache, "link"))
    out["symlink_made"] = "yes"
except OSError as e:
    out["symlink_made"] = type(e).__name__
tryw("through_symlink", os.path.join(cache, "link"))
tryw("inside_cache", os.path.join(cache, "ok.txt"))
try:
    os.rename(os.path.join(cache, "ok.txt"), os.path.join(ro, "moved.py"))
    out["rename_out"] = "MOVED"
except OSError as e:
    out["rename_out"] = type(e).__name__
try:
    os.unlink(os.path.join(ro, "file.py"))
    out["unlink"] = "UNLINKED"
except OSError as e:
    out["unlink"] = type(e).__name__
print(json.dumps(out))
"""


def test_an_rw_grant_inside_an_ro_bind_tree_is_refused_by_name(tmp_path: Path):
    """design policy (review-symmetric): rw and ro_bind trees are disjoint; an rw path inside an ro_bind tree is refused like one above it."""
    ro = tmp_path / "ro"
    cache = ro / "cache"
    cache.mkdir(parents=True)
    (ro / "file.py").write_text("SAFE\n")
    with pytest.raises(GrantError, match="ro_bind"):
        run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(ro),), ro_bind=(str(ro),), rw=(str(cache),)), timeout=30)
    spec = Profile(ro=(str(ro),), ro_bind=(str(ro),)).spec()
    spec["rw"] = sorted({*spec["rw"], str(cache)})
    own = tmp_path / "own"
    own.mkdir()
    cp = subprocess.run([sys.executable, "-I", confinement._LAUNCHER, json.dumps({**spec, "root_parent": str(own)}), "--",
                         sys.executable, "-I", "-c", "print(1)"], capture_output=True, text=True, timeout=30,
                        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
    assert cp.returncode != 0 and "ro_bind" in cp.stderr, cp


def test_an_rw_grant_inside_an_ro_bind_tree_writes_only_inside_that_grant(tmp_path: Path):
    """Measured before the symmetric policy (39f34e72): not an escape. Kept so the containment claim stays tested if the policy is
    ever relaxed: today the launch is refused (that branch passes); without the refusal the probe below must still hold."""
    ro = tmp_path / "ro"
    cache = ro / "cache"
    cache.mkdir(parents=True)
    f = ro / "file.py"
    f.write_text("SAFE\n")
    prof = Profile(ro=(str(ro),), ro_bind=(str(ro),), rw=(str(cache),))
    try:
        cp = run_confined([sys.executable, "-I", "-c", PROBE, str(ro), str(cache)], prof, timeout=30)
    except GrantError:
        assert f.read_text() == "SAFE\n"
        return
    assert cp.returncode == 0, cp.stderr

    got = json.loads(cp.stdout.strip().splitlines()[-1])
    print("PROBE", got)
    assert got["inside_cache"] == "WROTE", got  # the explicit narrower grant works
    for k in ("direct", "new_sibling", "dotdot_from_cache", "through_symlink"):
        assert got[k] != "WROTE", (k, got)
    assert got["rename_out"] != "MOVED" and got["unlink"] != "UNLINKED", got
    assert f.read_text() == "SAFE\n"
    assert not (ro / "new.py").exists() and not (ro / "moved.py").exists()
    assert sorted(p.name for p in ro.iterdir()) == ["cache", "file.py"]
    _ = subprocess  # host-side view above is the ground truth


def test_negative_control_the_probe_does_detect_a_write_when_the_tree_itself_is_writable(tmp_path: Path):
    import json

    ro = tmp_path / "ro"
    cache = ro / "cache"
    cache.mkdir(parents=True)
    (ro / "file.py").write_text("SAFE\n")
    cp = run_confined([sys.executable, "-I", "-c", PROBE, str(ro), str(cache)], Profile(rw=(str(ro),)), timeout=30)
    got = json.loads(cp.stdout.strip().splitlines()[-1])
    print("PROBE", got)
    assert got["direct"] == "WROTE" and got["dotdot_from_cache"] == "WROTE", got
