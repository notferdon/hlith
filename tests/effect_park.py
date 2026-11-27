"""Park a real LangGraph effect interrupt for tests.

``run_worker`` is the production path and it refuses to start unless user, mount, pid and net
namespaces and Landlock are all available. This sandbox's ``landlock_create_ruleset`` (syscall 444)
returns ENOSYS. The fallback below still executes ``hlith.agent.graph.main`` — the same StateGraph,
SqliteSaver and ``interrupt()`` — but applies the patch with git directly. That is not confinement
evidence and it does not change ``hostio`` or ``confine_exec``. ``persist`` is the production function
either way.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from hlith.agent.capture import MAX_EFFECT_BYTES, MAX_EFFECT_ENTRIES, WorkerRun, _diff_stage, _materialise, _scan_stage, read_manifest_full, worktree_digest
from hlith.agent.checkpoint import Layer1Session, persist
from hlith.agent.supervisor import _read_head_tree, after_run


_CHILD = r"""
import subprocess, sys
import hlith.agent.graph as graph
import hlith.agent.tools as tools

def _run_child(argv, stage):
    cp = subprocess.run(argv, cwd=stage, capture_output=True, text=True)
    return subprocess.CompletedProcess(argv, cp.returncode, cp.stdout or "", cp.stderr or "")

tools._run_child = _run_child
graph._run_child = _run_child
raise SystemExit(graph.main(sys.argv[1:]))
"""


def landlock_enosys() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall(444, None, 0, 0)
    return ctypes.get_errno() == 38


def park_layer1_patch(repo: Path, store: Path, patch: bytes, *, manifest_bytes: bytes | None = None) -> WorkerRun:
    if not landlock_enosys():
        from hlith.runtime import run_worker

        return run_worker(
            repo, [], patch=patch, manifest_bytes=manifest_bytes, layer1=True, thread_store=store,
        )
    return _park_graph_without_landlock(repo, store, patch, manifest_bytes=manifest_bytes)


def _park_graph_without_landlock(repo: Path, store: Path, patch: bytes, *, manifest_bytes: bytes | None) -> WorkerRun:
    repo = Path(repo).resolve()
    before = worktree_digest(repo)
    base_tree = _read_head_tree(repo)
    tmp_ctx = tempfile.TemporaryDirectory(prefix="hlith-park-")
    try:
        tmp_p = Path(tmp_ctx.name)
        stage = tmp_p / "stage"
        target_ro = tmp_p / "target_ro"
        _materialise(repo, stage)
        _materialise(repo, target_ro)
        channel = tmp_p / "channel"
        channel.mkdir()
        inputs = tmp_p / "inputs"
        inputs.mkdir()
        ckpt = tmp_p / "ckpt"
        ckpt.mkdir()
        driver = tmp_p / "driver"
        driver.mkdir()
        (inputs / "op.patch").write_bytes(patch)
        if manifest_bytes is not None:
            (channel / "manifest.json").write_bytes(manifest_bytes)
        tid = f"hlith-{uuid.uuid4().hex[:20]}"
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HLITH_TARGET": str(target_ro),
            "HLITH_STAGE": str(stage),
            "HLITH_MANIFEST_DIR": str(channel),
            "HLITH_CKPT_DIR": str(ckpt),
            "HLITH_DRIVER_DIR": str(driver),
            "HLITH_THREAD_ID": tid,
            "SQLITE_TMPDIR": str(ckpt),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        cp = subprocess.run(
            [sys.executable, "-c", _CHILD, "run", "patch", str(inputs / "op.patch")],
            cwd=stage,
            env=env,
            capture_output=True,
            text=True,
        )
        if cp.returncode != 0:
            raise RuntimeError(
                "in-process graph worker failed "
                f"rc={cp.returncode}\nstdout={cp.stdout[-800:]}\nstderr={cp.stderr[-800:]}"
            )
        session = Layer1Session(
            tmp=tmp_ctx, stage=stage, ckpt=ckpt, channel=channel, driver=driver, inputs=inputs,
            thread_id=tid, env=env, timeout=30,
        )
        scan = _scan_stage(stage, MAX_EFFECT_BYTES, MAX_EFFECT_ENTRIES)
        diff, touched, ignored, flags, observed = _diff_stage(repo, stage, tmp_p, scan.non_utf8)
        manifest, deltas, manifest_error = read_manifest_full(channel)
        graph = after_run(session, 0, "", observed, ignored, scan.skipped)
        persist(
            session, graph, store, target=repo, base_tree=base_tree,
            patch_sha256=hashlib.sha256(patch).hexdigest(),
        )
        after = worktree_digest(repo)
        from hlith.contract.effects import DeltaEffect

        return WorkerRun(
            effect=DeltaEffect(unified_diff=diff, proposer_id="unconfined-graph-witness", touched_files=touched, deltas=deltas),
            base_tree=base_tree,
            target_tree_before=before,
            target_tree_after=after,
            profile_sha256="n/a:landlock-enosys-witness",
            worker_returncode=0,
            worker_stdout=cp.stdout,
            worker_stderr=cp.stderr,
            ignored_paths=ignored,
            skipped_paths=scan.skipped,
            risk_flags=flags,
            observed=observed,
            manifest=manifest,
            manifest_error=manifest_error,
            graph=graph,
        )
    except BaseException:
        tmp_ctx.cleanup()
        raise
