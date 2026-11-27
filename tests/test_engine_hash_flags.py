"""--patch-sha256 / --manifest-sha256: the engine hashes the operator input it is about to use and refuses (exit 4, reason named) on a mismatch
BEFORE any derivation. Without the flags nothing changes (the CLI stays scriptable).

Retargeted to Hlith Review (product.REVIEW_ONLY): the flags were exercised through `hlith run`, which Review does not offer; the same
flags are offered by `hlith check --patch ... --manifest ...`, which is what these tests now drive (`--artifact-out` is a new directory)."""
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from hlith.cli import main


def _git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def toy(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    patch = tmp_path / "op.patch"
    patch.write_text(_git(r, "diff"))
    _git(r, "checkout", "-q", "calc.py")
    man = tmp_path / "op.json"
    man.write_text(json.dumps({"paths": {"calc.py": ["modify"]}}))
    return r, patch, man


def _run(toy, tmp_path, *extra):
    r, patch, man = toy
    return main(["check", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(tmp_path / "a.json"), *extra])


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def test_a_wrong_patch_hash_is_refused_before_any_derivation(toy, tmp_path, capsys):
    assert _run(toy, tmp_path, "--patch-sha256", "0" * 64) == 4
    err = capsys.readouterr().err
    assert "patch SHA-256 differs from the reviewed input" in err and not (tmp_path / "a.json").exists()


def test_a_wrong_manifest_hash_is_refused(toy, tmp_path, capsys):
    assert _run(toy, tmp_path, "--manifest-sha256", "f" * 64) == 4
    assert "manifest SHA-256 differs from the reviewed input" in capsys.readouterr().err and not (tmp_path / "a.json").exists()


def test_a_patch_swapped_after_verification_is_refused(toy, tmp_path, capsys):
    r, patch, man = toy
    verified = _sha(patch)  # what the reviewer's verification saw
    patch.write_text(patch.read_text() + "\n# swapped after verification\n")
    assert _run(toy, tmp_path, "--patch-sha256", verified) == 4
    assert "patch SHA-256 differs from the reviewed input" in capsys.readouterr().err and not (tmp_path / "a.json").exists()


def test_the_hash_flags_only_accept_64_hex(toy, tmp_path, capsys):
    """Was (`hlith run`, and `--engine legacy`): a value that is not 64 hex digits was a usage error (exit 2). `hlith check` does not
    validate the format; a malformed value can never equal a real SHA-256, so it is refused as a mismatch (boundary, exit 4) before any
    derivation and nothing is written. The usage-vs-boundary difference is reported to the owner."""
    for flag, label in (("--patch-sha256", "patch"), ("--manifest-sha256", "manifest")):
        assert _run(toy, tmp_path, flag, "abc") == 4, flag
        assert f"{label} SHA-256 differs from the reviewed input" in capsys.readouterr().err
        assert not (tmp_path / "a.json").exists()


@pytest.mark.real  # a full engine run with the right hashes (about 15 s)
def test_the_right_hashes_are_accepted_and_the_run_proceeds(toy, tmp_path):
    r, patch, man = toy
    rc = _run(toy, tmp_path, "--patch-sha256", _sha(patch), "--manifest-sha256", _sha(man))
    assert rc in (0, 10, 11, 12) and (tmp_path / "a.json").exists()
