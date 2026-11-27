# SPDX-License-Identifier: Apache-2.0
"""Packaging, hook distribution, and self-contained first-use demo checks.

Verifies the single-source agent-hook packaging configuration (sdist + wheel shared-scripts),
the self-contained authored first-use fixture under examples/first-use/, and that shipped docs
avoid private run IDs while documenting exact cold install and wiring paths.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PRIVATE_RUN_ID = re.compile(r"\brun-[0-9a-f]{12}\b")
PRIVATE_PATH = re.compile(r"/home/[A-Za-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/")


def test_sdist_allowlist_ships_agent_hook_probe_and_first_use_fixture():
    sdist = PYPROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]
    include = set(sdist["include"])
    required = {
        "/scripts/agent-hook/hlith-agent-hook.sh",
        "/scripts/landlock_capabilities.py",
        "/scripts/sbom_draft.py",
        "/examples/first-use",
        "/docs/AGENT-INTEGRATION.md",
        "/docs/REVIEW-QUICKSTART.md",
        "/uv.lock",
        "/README.md",
    }
    missing = required - include
    assert not missing, f"missing from sdist include: {sorted(missing)}"
    for entry in sdist["include"]:
        assert (ROOT / entry.lstrip("/")).exists(), f"sdist include target does not exist: {entry}"


def test_wheel_ships_single_source_agent_hook_without_duplicating_into_src():
    wheel = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]
    shared = wheel.get("shared-scripts", {})
    assert shared.get("scripts/agent-hook/hlith-agent-hook.sh") == "hlith-agent-hook"
    hook = ROOT / "scripts/agent-hook/hlith-agent-hook.sh"
    assert hook.is_file() and os.access(hook, os.X_OK)
    duplicates = list((ROOT / "src").rglob("*agent-hook*"))
    assert not duplicates, f"hook script must stay single-source outside src/: {duplicates}"


def test_first_use_fixture_is_self_contained_clean_and_patches_apply(tmp_path):
    fixture = ROOT / "examples/first-use"
    repo_src = fixture / "repo"
    patch_buggy = fixture / "patches/01-remove-guard.patch"
    patch_fixed = fixture / "patches/02-restore-guard-refactor.patch"
    for p in (
        fixture / "README.md",
        repo_src / ".gitignore",
        repo_src / "pytest.ini",
        repo_src / "demo_limits/__init__.py",
        repo_src / "demo_limits/timeouts.py",
        repo_src / "tests/test_timeouts.py",
        patch_buggy,
        patch_fixed,
    ):
        assert p.is_file(), f"missing first-use fixture file: {p}"

    assert not (repo_src / ".git").exists(), "fixture must not ship a nested .git directory"
    for f in fixture.rglob("*"):
        if f.is_file():
            text = f.read_text(encoding="utf-8")
            assert not PRIVATE_PATH.search(text), f"private path in {f.relative_to(ROOT)}"
            assert not PRIVATE_RUN_ID.search(text), f"private run ID in {f.relative_to(ROOT)}"

    demo = tmp_path / "demo"
    shutil.copytree(repo_src, demo)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Demo",
        "GIT_AUTHOR_EMAIL": "demo@example.invalid",
        "GIT_COMMITTER_NAME": "Demo",
        "GIT_COMMITTER_EMAIL": "demo@example.invalid",
    }
    subprocess.run(["git", "-C", str(demo), "init", "-q", "-b", "main"], check=True, env=env)
    subprocess.run(["git", "-C", str(demo), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(demo), "commit", "-qm", "base"], check=True, env=env)

    # Patch 1 (buggy guard removal) applies cleanly and existing pytest still passes.
    subprocess.run(["git", "-C", str(demo), "apply", "--check", str(patch_buggy)], check=True)
    subprocess.run(["git", "-C", str(demo), "apply", str(patch_buggy)], check=True)
    r1 = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=demo, capture_output=True, text=True)
    assert r1.returncode == 0, r1.stdout + r1.stderr

    # Patch 2 (preserving refactor keeping the guard) applies cleanly to base and passes pytest.
    subprocess.run(["git", "-C", str(demo), "checkout", "--", "."], check=True)
    subprocess.run(["git", "-C", str(demo), "apply", "--check", str(patch_fixed)], check=True)
    subprocess.run(["git", "-C", str(demo), "apply", str(patch_fixed)], check=True)
    r2 = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=demo, capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr


def test_user_docs_have_no_private_run_ids_and_document_complete_install_and_wiring():
    for rel in ("README.md", "docs/AGENT-INTEGRATION.md", "docs/REVIEW-QUICKSTART.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not PRIVATE_RUN_ID.search(text), f"private run ID found in {rel}"

    agent_doc = (ROOT / "docs/AGENT-INTEGRATION.md").read_text(encoding="utf-8")
    assert "hlith-agent-hook" in agent_doc
    assert "HLITH_BIN=" in agent_doc
    assert '"PostToolUse"' in agent_doc and '"UserPromptSubmit"' in agent_doc and '"Stop"' in agent_doc

    quickstart = (ROOT / "docs/REVIEW-QUICKSTART.md").read_text(encoding="utf-8")
    assert "uv sync --frozen --python 3.13.9" in quickstart
    assert "source .venv/bin/activate" in quickstart
    assert "hlith-agent-hook" in quickstart
    assert "examples/first-use/README.md" in quickstart
