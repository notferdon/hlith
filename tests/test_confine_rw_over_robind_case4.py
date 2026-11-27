"""review E2-PARENT-RW-SHADOWS-RO-BIND (cold 71c64805): Profile(ro=(child,), ro_bind=(child,), rw=(parent,)) let a confined process
overwrite child/file.py, because the launcher binds rw after ro/ro_bind and Landlock is additive. A writable grant that covers a
read-only-bound path is refused by name before anything starts, both in run_confined and in the launcher itself (review, red-first)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.hostio import confinement
from hlith.hostio.confinement import GrantError, Profile, run_confined

WRITE = "import sys; open(sys.argv[1], 'w').write('PWNED\\n')"


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    parent = tmp_path / "parent"
    child = parent / "protected_target"
    child.mkdir(parents=True)
    f = child / "file.py"
    f.write_text("SAFE\n")
    return parent, child, f


@pytest.mark.parametrize("rw_of", ["parent", "child"])
def test_a_writable_grant_covering_a_read_only_bound_path_is_refused_and_writes_nothing(tmp_path: Path, rw_of: str):
    parent, child, f = _tree(tmp_path)
    prof = Profile(ro=(str(child),), ro_bind=(str(child),), rw=(str(parent if rw_of == "parent" else child),))
    with pytest.raises(GrantError, match="ro_bind"):
        run_confined([sys.executable, "-I", "-c", WRITE, str(f)], prof, timeout=30)
    assert f.read_text() == "SAFE\n"


def test_the_launcher_itself_refuses_the_overlap_when_handed_a_raw_spec(tmp_path: Path):
    parent, child, f = _tree(tmp_path)
    spec = Profile(ro=(str(child),), ro_bind=(str(child),), rw=(str(parent),)).spec()
    own = tmp_path / "own"
    own.mkdir()
    cp = subprocess.run([sys.executable, "-I", confinement._LAUNCHER, json.dumps({**spec, "root_parent": str(own)}), "--",
                         sys.executable, "-I", "-c", WRITE, str(f)], capture_output=True, text=True, timeout=30,
                        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
    assert cp.returncode != 0, cp
    assert "ro_bind" in cp.stderr, cp.stderr
    assert f.read_text() == "SAFE\n"


def test_disjoint_and_prefix_lookalike_grants_still_run(tmp_path: Path):
    """A sibling rw (`.../parent/protected_target2`, a string-prefix lookalike) is not an ancestor and must keep working."""
    parent, child, f = _tree(tmp_path)
    sib = parent / "protected_target2"
    sib.mkdir()
    out = sib / "out.txt"
    cp = run_confined([sys.executable, "-I", "-c", WRITE, str(out)], Profile(ro=(str(child),), ro_bind=(str(child),), rw=(str(sib),)),
                      timeout=30)
    assert cp.returncode == 0, cp.stderr
    assert out.read_text() == "PWNED\n" and f.read_text() == "SAFE\n"


def _launch_raw(tmp_path: Path, spec: dict, f: Path) -> subprocess.CompletedProcess:
    own = tmp_path / "own"
    own.mkdir(exist_ok=True)
    return subprocess.run([sys.executable, "-I", confinement._LAUNCHER, json.dumps({**spec, "root_parent": str(own)}), "--",
                           sys.executable, "-I", "-c", WRITE, str(f)], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})


@pytest.mark.parametrize("how", ["dotdot", "symlinked-ancestor"])
def test_the_launcher_canonicalizes_raw_rw_paths_before_the_overlap_check(tmp_path: Path, how: str):
    """review on 34669167: a hand-written raw spec (no Profile.spec()) with rw=[parent/sub/..] compared as a raw string and still overwrote
    child/file.py. The launcher must compare canonical paths (`..`, `.`, `//` and symlinked ancestors resolved)."""
    parent, child, f = _tree(tmp_path)
    if how == "dotdot":
        (parent / "sub").mkdir()
        rw = str(parent) + "/sub/.."
    else:
        link = tmp_path / "link-to-parent"
        link.symlink_to(parent)
        rw = str(link)
    spec = Profile(ro=(str(child),), ro_bind=(str(child),)).spec()
    spec["rw"] = sorted({*spec["rw"], rw})
    cp = _launch_raw(tmp_path, spec, f)
    assert cp.returncode != 0 and "ro_bind" in cp.stderr, cp
    assert f.read_text() == "SAFE\n"


def test_a_symlink_followed_by_dotdot_is_resolved_the_way_the_kernel_resolves_it(tmp_path: Path):
    """review on 39f34e72: other/hop -> parent/sub and rw=[other/hop/..]. normpath collapsed `hop/..` lexically to `other` (passed the
    check) while the kernel resolves hop first and lands on `parent`, which covers the ro_bind child: file.py was overwritten."""
    parent, child, f = _tree(tmp_path)
    (parent / "sub").mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (other / "hop").symlink_to(parent / "sub")
    spec = Profile(ro=(str(child),), ro_bind=(str(child),)).spec()
    spec["rw"] = sorted({*spec["rw"], str(other) + "/hop/.."})
    cp = _launch_raw(tmp_path, spec, f)
    assert cp.returncode != 0 and "ro_bind" in cp.stderr, cp
    assert f.read_text() == "SAFE\n"


def test_the_launcher_refuses_a_grant_it_cannot_canonicalize(tmp_path: Path):
    parent, child, f = _tree(tmp_path)
    spec = Profile(ro=(str(child),), ro_bind=(str(child),)).spec()
    spec["rw"] = sorted({*spec["rw"], str(tmp_path / "does-not-exist")})
    cp = _launch_raw(tmp_path, spec, f)
    assert cp.returncode != 0 and "canonical" in cp.stderr, cp
    assert f.read_text() == "SAFE\n"
