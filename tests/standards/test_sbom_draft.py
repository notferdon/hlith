"""scripts/sbom_draft.py (case, LOCAL SBOM draft): positive control on the real uv.lock, then NEGATIVE mutations that
must fail: a locked package stripped of its hashes, a malformed hash, a non-project editable source without hashes, and an empty or
missing lock. Runs the script as a subprocess on copies; no network."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sbom_draft.py"
LOCK = ROOT / "uv.lock"


def run(lock: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), "--lock", str(lock), *extra], capture_output=True, text=True, timeout=60)


def package_block(text: str, name: str) -> tuple[int, int]:
    start = text.index(f'[[package]]\nname = "{name}"\n')
    nxt = text.find("\n[[package]]\n", start + 1)
    return start, (len(text) if nxt == -1 else nxt)


def mutated(tmp_path: Path, name: str, fn) -> Path:
    text = LOCK.read_text(encoding="utf-8")
    a, b = package_block(text, name)
    out = tmp_path / "uv.lock"
    out.write_text(text[:a] + fn(text[a:b]) + text[b:], encoding="utf-8")
    return out


def test_positive_control_real_lock_every_package_hashed(tmp_path):
    out = tmp_path / "sbom.json"
    cp = run(LOCK, "--out", str(out))
    assert cp.returncode == 0, cp.stderr
    bom = json.loads(out.read_text())
    pkgs = tomllib.loads(LOCK.read_text())["package"]
    assert bom["bomFormat"] == "CycloneDX" and bom["metadata"]["component"]["name"] == "hlith"
    assert len(bom["components"]) == len(pkgs) - 1 > 0
    for c in bom["components"]:
        assert c["hashes"] and all(re.fullmatch(r"[0-9a-f]{64}", h["content"]) for h in c["hashes"]), c["name"]
        assert c["purl"] == f"pkg:pypi/{c['name']}@{c['version']}"
    z3 = next(c for c in bom["components"] if c["name"] == "z3-solver")
    assert "91b0028697082c3e48e7fb36dd13d642aee33a74a610c8c90b6d83f82e9f7fcc" in {h["content"] for h in z3["hashes"]}
    assert run(LOCK).stdout == out.read_text()  # deterministic


def test_rejects_a_locked_package_with_no_hash(tmp_path):
    lock = mutated(tmp_path, "z3-solver", lambda blk: re.sub(r'hash = "sha256:[0-9a-f]+", ', "", blk))
    text = lock.read_text()
    a, b = package_block(text, "z3-solver")
    assert "sha256:" not in text[a:b] and "wheels = [" in text[a:b]  # artifacts still listed, only their hashes removed
    cp = run(lock)
    assert cp.returncode == 1 and "z3-solver" in cp.stderr and "no sha256 artifact hash" in cp.stderr, cp.stderr
    assert cp.stdout == ""


def test_rejects_a_package_with_no_artifacts_at_all(tmp_path):
    def strip(blk: str) -> str:
        blk = re.sub(r"\nsdist = \{[^\n]*\}", "", blk)
        return re.sub(r"\nwheels = \[\n(?:    [^\n]*\n)*\]", "", blk)
    lock = mutated(tmp_path, "z3-solver", strip)
    cp = run(lock)
    assert cp.returncode == 1 and "z3-solver" in cp.stderr, cp.stderr


def test_rejects_a_malformed_hash(tmp_path):
    lock = mutated(tmp_path, "z3-solver", lambda blk: blk.replace("sha256:91b0", "sha256:XYZ0", 1))
    cp = run(lock)
    assert cp.returncode == 1 and "malformed hash" in cp.stderr, cp.stderr


def test_only_the_project_root_is_exempt(tmp_path):
    text = LOCK.read_text(encoding="utf-8")
    extra = '\n[[package]]\nname = "vendored"\nversion = "1.0"\nsource = { editable = "../vendored" }\n'
    lock = tmp_path / "uv.lock"
    lock.write_text(text + extra, encoding="utf-8")
    cp = run(lock)
    assert cp.returncode == 1 and "vendored" in cp.stderr, cp.stderr


@pytest.mark.parametrize("content", [None, "version = 1\n", "not [ toml"])
def test_missing_empty_or_unparsable_lock_hard_fails(tmp_path, content):
    lock = tmp_path / "uv.lock"
    if content is not None:
        lock.write_text(content)
    cp = run(lock)
    assert cp.returncode == 2 and "FAIL" in cp.stderr, cp.stderr
