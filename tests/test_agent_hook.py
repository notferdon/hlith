"""Mechanism tests for scripts/agent-hook/hlith-agent-hook.sh against a STUB `hlith` (not the engine): pending is model-visible, a pending
check never reads as success, REFUTED/undetermined/timeout block the stop once, nothing runs when the working tree is clean,
receipts bind exact HEAD/tree/working-tree identity, malformed/mismatched envelopes and git/special-file errors fail closed,
and concurrent `post` calls serialize to one worker with atomic receipt publication.
These test the glue only; the real engine loop is a separate recorded run."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / "scripts" / "agent-hook" / "hlith-agent-hook.sh"

STUB = """#!/usr/bin/env bash
sleep "${STUB_SLEEP:-0}"
[ -n "${STUB_COUNT:-}" ] && echo run >> "$STUB_COUNT"
[ -n "${STUB_ARGV:-}" ] && printf '%s\n' "$@" > "$STUB_ARGV"
out=""
repo=""
while [ $# -gt 0 ]; do
  case "$1" in
    --artifact-out) out="$2"; shift 2;;
    --repo) repo="$2"; shift 2;;
    *) shift;;
  esac
done
[ -n "$out" ] && mkdir -p "$out"
rc="${STUB_EXIT:-10}"
if [ -n "${STUB_RAW_STDOUT+x}" ]; then
  printf '%s' "$STUB_RAW_STDOUT"
  exit "$rc"
fi
base="${STUB_BASE_COMMIT:-}"
if [ -z "$base" ] && [ -n "$repo" ]; then
  base="$(git -C "$repo" rev-parse --verify HEAD^{commit} 2>/dev/null || true)"
fi
tree=""
if [ -n "$repo" ]; then
  tree="$(git -C "$repo" rev-parse --verify HEAD^{tree} 2>/dev/null || true)"
fi
python3 - "$rc" "$base" "$tree" <<'PY'
import json, os, sys
rc = int(sys.argv[1])
base = sys.argv[2]
tree = sys.argv[3]
if rc == 0:
    artifact = {"outcome": "landed", "exit_status": 0, "obligations": []}
elif rc == 3:
    artifact = {"verdict": "INTERNAL ERROR", "exit_status": 3, "reason": "stub internal error"}
else:
    artifact = {
        "outcome": "refused",
        "exit_status": rc,
        "run": {"replay_context": {"base": {"commit": base, "tree_oid": tree}}},
        "obligations": [
            {"id": "differential:pkg.f", "verdict": "refuted", "witness_call": {"args": [0], "kwargs": {}}}
        ],
    }
env = {
    "envelope": "hlith.check/1",
    "exit_status": rc,
    "check": {
        "base_commit": base,
        "run_id": "run-stub000001",
        "replay_command": "hlith replay run-stub000001",
        "inspect_command": "hlith inspect run-stub000001",
    },
    "artifact": artifact,
}
print(json.dumps(env))
PY
exit "$rc"
"""


def run(args, env, cwd, stdin=""):
    return subprocess.run(["bash", str(HOOK), *args], cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=60)


def git(repo: Path, *args: str) -> str:
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def box(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    (repo / "context.txt").write_text("v1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    stub = tmp_path / "hlith-stub"
    stub.write_text(STUB)
    stub.chmod(0o755)
    env = {**os.environ, "HLITH_BIN": str(stub), "HLITH_HOOK_HOME": str(tmp_path / "home"), "CLAUDE_PROJECT_DIR": str(repo)}
    return repo, env


def hook_dir(env, cwd) -> Path:
    home = next(Path(env["HLITH_HOOK_HOME"]).glob("*"), None)
    if home is None:
        run(["status"], env, cwd)
        home = next(Path(env["HLITH_HOOK_HOME"]).glob("*"))
    return home


def wait_done(env, cwd, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        st = json.loads(run(["status"], env, cwd).stdout)
        if st.get("status") in ("done", "error", "invalid"):
            return st
        time.sleep(0.15)
    raise AssertionError("check did not finish")


def context(proc):
    return json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]


def test_clean_tree_starts_nothing(box):
    repo, env = box
    p = run(["post"], env, repo)
    assert p.returncode == 0 and p.stdout.strip() == ""
    assert json.loads(run(["status"], env, repo).stdout) == {"status": "none"}


def test_pending_is_model_visible_and_never_success(box):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    env = {**env, "STUB_SLEEP": "3"}
    p = run(["post"], env, repo)
    assert p.returncode == 0 and "UNVERIFIED" in context(p) and "safe or verified" in context(p)
    q = run(["prompt"], env, repo)
    assert "RUNNING" in context(q) and "UNVERIFIED" in context(q)
    again = run(["post"], env, repo)  # a second edit must not start a second check
    assert "still RUNNING" in context(again)
    s = run(["stop"], env, repo, stdin="{}")
    assert s.returncode == 0 and s.stdout.strip() == ""  # pending never blocks
    wait_done(env, repo)


def test_refuted_reaches_next_prompt_and_blocks_stop_once(box):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    wait_done(env, repo)
    text = context(run(["prompt"], env, repo))
    assert "REFUTED" in text and "args=[0]" in text and "hlith replay run-stub000001" in text and "ask the human" in text
    blocked = json.loads(run(["stop"], env, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "REFUTED" in blocked["reason"]
    again = run(["stop"], env, repo, stdin='{"stop_hook_active": true}')
    assert again.returncode == 0 and again.stdout.strip() == ""


def test_landed_rehearsal_is_not_blocking_and_not_merge_permission(box):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    env = {**env, "STUB_EXIT": "0"}
    run(["post"], env, repo)
    st = wait_done(env, repo)
    assert st["status"] == "done" and st["exit"] == 0 and st["head"] == git(repo, "rev-parse", "HEAD")
    assert "NOT merge permission" in context(run(["prompt"], env, repo))
    assert run(["stop"], env, repo, stdin="{}").stdout.strip() == ""


def test_timeout_is_unverified_and_blocks(box):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    env = {**env, "STUB_SLEEP": "30", "HLITH_HOOK_TIMEOUT": "1"}
    run(["post"], env, repo)
    st = wait_done(env, repo)
    assert st["exit"] == 124
    assert "TIMED OUT" in json.loads(run(["stop"], env, repo, stdin="{}").stdout)["reason"]


def test_edit_during_check_is_rechecked_and_never_reads_as_covered(box, tmp_path):
    repo, env = box
    count = tmp_path / "count"
    env = {**env, "STUB_SLEEP": "2", "STUB_EXIT": "0", "STUB_COUNT": str(count)}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    time.sleep(0.8)  # edit B lands while the check for edit A is running
    (repo / "m.py").write_text("def f(x):\n    return x + 2\n")
    assert "still RUNNING" in context(run(["post"], env, repo))
    wait_done(env, repo, seconds=30)
    assert count.read_text().count("run") == 2  # the worker re-ran on the changed tree
    assert "LANDED" in context(run(["prompt"], env, repo)) and "changed after" not in context(run(["prompt"], env, repo))


def test_edit_after_finish_is_stale_and_blocks_stop(box):
    repo, env = box
    env = {**env, "STUB_EXIT": "0"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    wait_done(env, repo)
    (repo / "m.py").write_text("def f(x):\n    return x + 3\n")  # an edit after the check finished, hook not yet run
    assert "changed after that check started" in context(run(["prompt"], env, repo))
    blocked = json.loads(run(["stop"], env, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "UNVERIFIED" in blocked["reason"]


def test_dead_worker_is_interrupted_not_exit_none(box):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    home = hook_dir(env, repo)
    (home / "status.json").write_text('{"status": "running", "started": 1, "pid": 999999, "fp": "x"}\n')
    assert "interrupted" in context(run(["prompt"], env, repo))
    assert "interrupted" in json.loads(run(["stop"], env, repo, stdin="{}").stdout)["reason"]


def test_missing_hlith_binary_is_a_finished_failure_not_interrupted(box):
    repo, env = box
    env = {**env, "HLITH_BIN": "/nonexistent/hlith"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    st = wait_done(env, repo)
    assert st["exit"] == 127
    assert "exit 127" in context(run(["prompt"], env, repo)) and "interrupted" not in context(run(["prompt"], env, repo))
    assert json.loads(run(["stop"], env, repo, stdin="{}").stdout)["decision"] == "block"


def test_unset_target_python_omits_flag_so_check_can_autodetect(box, tmp_path):
    repo, env = box
    argv_log = tmp_path / "argv.txt"
    env_unset = {k: v for k, v in env.items() if k != "HLITH_TARGET_PYTHON"}
    env_unset["STUB_ARGV"] = str(argv_log)
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env_unset, repo)
    wait_done(env_unset, repo)
    args = argv_log.read_text().splitlines()
    assert "--target-python" not in args, args

    argv_log2 = tmp_path / "argv2.txt"
    env_set = {**env_unset, "HLITH_TARGET_PYTHON": "/custom/venv/bin/python", "STUB_ARGV": str(argv_log2)}
    (repo / "m.py").write_text("def f(x):\n    return x + 2\n")
    run(["post"], env_set, repo)
    wait_done(env_set, repo)
    args2 = argv_log2.read_text().splitlines()
    assert "--target-python" in args2 and args2[args2.index("--target-python") + 1] == "/custom/venv/bin/python", args2


def test_internal_error_exit_3_is_named_and_blocks_stop(box):
    repo, env = box
    env = {**env, "STUB_EXIT": "3"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    st = wait_done(env, repo)
    assert st["exit"] == 3
    assert "INTERNAL ERROR" in context(run(["prompt"], env, repo))
    blocked = json.loads(run(["stop"], env, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "INTERNAL ERROR" in blocked["reason"]


# ---------------------------------------------------------------- release defect A: HEAD/base binding, fail-closed, races, special files


def test_base_head_change_with_identical_dirty_diff_is_stale_and_blocks_stop(box):
    """Moving HEAD (committing unrelated context.txt or an empty commit) while dirty m.py keeps the exact same diff
    must invalidate an earlier exit 0 receipt and block stop."""
    repo, env = box
    env = {**env, "STUB_EXIT": "0"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    diff_before = git(repo, "diff", "HEAD", "--binary")
    head1 = git(repo, "rev-parse", "HEAD")

    run(["post"], env, repo)
    st = wait_done(env, repo)
    assert st["status"] == "done" and st["exit"] == 0 and st["head"] == head1
    # Positive control: unchanged HEAD + unchanged dirty tree is accepted (LANDED, stop allowed)
    assert "changed after" not in context(run(["prompt"], env, repo))
    assert run(["stop"], env, repo, stdin="{}").stdout.strip() == ""

    # Advance HEAD with unrelated commit while m.py diff remains byte-identical
    (repo / "context.txt").write_text("v2\n")
    git(repo, "add", "context.txt")
    git(repo, "commit", "-qm", "unrelated context update")
    head2 = git(repo, "rev-parse", "HEAD")
    assert head2 != head1
    assert git(repo, "diff", "HEAD", "--binary") == diff_before

    pr_text = context(run(["prompt"], env, repo))
    assert "changed after that check started" in pr_text and "UNVERIFIED" in pr_text
    blocked = json.loads(run(["stop"], env, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "UNVERIFIED" in blocked["reason"]

    # Re-check on head2 -> becomes valid again; then empty commit (same tree OID, new HEAD commit OID) -> stale again
    run(["post"], env, repo)
    st2 = wait_done(env, repo)
    assert st2["head"] == head2 and run(["stop"], env, repo, stdin="{}").stdout.strip() == ""

    tree2 = git(repo, "rev-parse", "HEAD^{tree}")
    git(repo, "commit", "--allow-empty", "-qm", "empty commit moving HEAD only")
    head3 = git(repo, "rev-parse", "HEAD")
    assert head3 != head2 and git(repo, "rev-parse", "HEAD^{tree}") == tree2
    assert "changed after that check started" in context(run(["prompt"], env, repo))
    assert json.loads(run(["stop"], env, repo, stdin="{}").stdout)["decision"] == "block"


def test_head_change_while_check_running_rechecks_and_binds_new_head(box, tmp_path):
    """If HEAD moves during a running check while dirty m.py diff is unchanged, the worker re-runs against the new HEAD."""
    repo, env = box
    count = tmp_path / "count"
    env = {**env, "STUB_SLEEP": "2", "STUB_EXIT": "0", "STUB_COUNT": str(count)}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    time.sleep(0.7)
    (repo / "context.txt").write_text("v2-while-running\n")
    git(repo, "add", "context.txt")
    git(repo, "commit", "-qm", "commit while check running")
    head2 = git(repo, "rev-parse", "HEAD")

    st = wait_done(env, repo, seconds=30)
    assert count.read_text().count("run") == 2
    assert st["head"] == head2 and st["exit"] == 0
    assert "LANDED" in context(run(["prompt"], env, repo)) and "changed after" not in context(run(["prompt"], env, repo))
    assert run(["stop"], env, repo, stdin="{}").stdout.strip() == ""


def test_parallel_post_calls_launch_only_one_worker_and_publish_atomically(box, tmp_path):
    """Simultaneous `post` hooks are serialized per repo: exactly one starts a worker, all others report RUNNING."""
    repo, env = box
    count = tmp_path / "count"
    env = {**env, "STUB_SLEEP": "1.5", "STUB_EXIT": "0", "STUB_COUNT": str(count)}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")

    procs = [
        subprocess.Popen(["bash", str(HOOK), "post"], cwd=repo, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(10)
    ]
    outs = [p.communicate(timeout=30)[0] for p in procs]
    assert all(p.returncode == 0 for p in procs)
    ctxs = [json.loads(o)["hookSpecificOutput"]["additionalContext"] for o in outs]
    started = [c for c in ctxs if "started in the background" in c]
    running = [c for c in ctxs if "still RUNNING" in c]
    assert len(started) == 1, ctxs
    assert len(running) == 9, ctxs

    st = wait_done(env, repo, seconds=30)
    assert st["status"] == "done" and st["exit"] == 0
    assert count.read_text().count("run") == 1
    assert run(["stop"], env, repo, stdin="{}").stdout.strip() == ""


@pytest.mark.parametrize("case,exit_code,raw_stdout", [
    ("truncated-json", "0", '{"envelope": "hlith.check/1"'),
    ("empty-stdout", "0", ""),
    ("wrong-envelope", "0", '{"envelope": "other/1", "exit_status": 0, "check": {"base_commit": "BASE"}, "artifact": {"outcome": "landed", "exit_status": 0}}'),
    ("exit-disagrees", "0", '{"envelope": "hlith.check/1", "exit_status": 10, "check": {"base_commit": "BASE"}, "artifact": {"outcome": "refused", "exit_status": 10}}'),
    ("outcome-not-landed", "0", '{"envelope": "hlith.check/1", "exit_status": 0, "check": {"base_commit": "BASE"}, "artifact": {"outcome": "refused", "exit_status": 0}}'),
    ("missing-base-commit", "0", '{"envelope": "hlith.check/1", "exit_status": 0, "check": {"run_id": "r1"}, "artifact": {"outcome": "landed", "exit_status": 0}}'),
    ("wrong-base-commit", "0", '{"envelope": "hlith.check/1", "exit_status": 0, "check": {"base_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "artifact": {"outcome": "landed", "exit_status": 0}}'),
    ("wrong-replay-tree", "0", '{"envelope": "hlith.check/1", "exit_status": 0, "check": {"base_commit": "BASE"}, "artifact": {"outcome": "landed", "exit_status": 0, "run": {"replay_context": {"base": {"commit": "BASE", "tree_oid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}}}'),
    ("refuted-malformed-json", "10", "not-json"),
])
def test_malformed_or_mismatched_envelope_fails_closed(box, case, exit_code, raw_stdout):
    repo, env = box
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    head = git(repo, "rev-parse", "HEAD")
    payload = raw_stdout.replace("BASE", head)
    env_case = {**env, "STUB_EXIT": exit_code, "STUB_RAW_STDOUT": payload}
    run(["post"], env_case, repo)
    wait_done(env_case, repo)

    pr = context(run(["prompt"], env_case, repo))
    assert "invalid or mismatched" in pr and "UNVERIFIED" in pr and "LANDED" not in pr, (case, pr)
    blocked = json.loads(run(["stop"], env_case, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "UNVERIFIED" in blocked["reason"], (case, blocked)


def test_deleted_or_corrupted_receipt_after_finish_fails_closed(box):
    repo, env = box
    env = {**env, "STUB_EXIT": "0"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env, repo)
    wait_done(env, repo)
    home = hook_dir(env, repo)

    # Delete last.json after an exit 0 check finished -> fail closed
    (home / "last.json").unlink()
    assert "invalid or mismatched" in context(run(["prompt"], env, repo))
    assert json.loads(run(["stop"], env, repo, stdin="{}").stdout)["decision"] == "block"

    # Legacy status.json missing head/tree (even with exit 0) -> fail closed
    (home / "status.json").write_text('{"status": "done", "exit": 0, "seconds": 1, "started": 1, "fp": "' + "a" * 64 + '"}\n')
    assert "invalid or mismatched" in context(run(["prompt"], env, repo))
    assert json.loads(run(["stop"], env, repo, stdin="{}").stdout)["decision"] == "block"

    # Corrupted non-JSON status.json -> status reports invalid, prompt/stop fail closed
    (home / "status.json").write_text("{corrupt\n")
    assert json.loads(run(["status"], env, repo).stdout)["status"] == "invalid"
    assert "invalid or mismatched" in context(run(["prompt"], env, repo))
    assert json.loads(run(["stop"], env, repo, stdin="{}").stdout)["decision"] == "block"


def test_failed_git_or_fingerprint_read_fails_closed(box, tmp_path):
    # 1. Non-git directory on post -> does NOT silently treat as clean; emits UNVERIFIED and blocks stop
    nongit = tmp_path / "not_a_repo"
    nongit.mkdir()
    (nongit / "a.py").write_text("x = 1\n")
    _, env_base = box
    env_ng = {**env_base, "HLITH_HOOK_HOME": str(tmp_path / "home_ng"), "CLAUDE_PROJECT_DIR": str(nongit)}
    p = run(["post"], env_ng, nongit)
    assert "UNVERIFIED" in context(p)
    assert json.loads(run(["status"], env_ng, nongit).stdout)["status"] == "error"
    assert json.loads(run(["stop"], env_ng, nongit, stdin="{}").stdout)["decision"] == "block"

    # 2. Unborn HEAD (git init, no commits yet) -> fails closed
    unborn = tmp_path / "unborn"
    unborn.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(unborn)], check=True)
    (unborn / "a.py").write_text("x = 1\n")
    env_ub = {**env_base, "HLITH_HOOK_HOME": str(tmp_path / "home_ub"), "CLAUDE_PROJECT_DIR": str(unborn)}
    assert "UNVERIFIED" in context(run(["post"], env_ub, unborn))
    assert json.loads(run(["stop"], env_ub, unborn, stdin="{}").stdout)["decision"] == "block"

    # 3. Valid exit 0 receipt followed by broken .git/HEAD -> fails closed on prompt/stop
    repo, env = box
    env0 = {**env, "STUB_EXIT": "0"}
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    run(["post"], env0, repo)
    wait_done(env0, repo)
    assert run(["stop"], env0, repo, stdin="{}").stdout.strip() == ""
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/does-not-exist\n")
    assert "UNVERIFIED" in context(run(["prompt"], env0, repo))
    assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"

    # 4. Missing repository path -> fails closed
    missing = tmp_path / "does-not-exist"
    assert "UNVERIFIED" in context(run(["post", str(missing)], env_base, tmp_path))
    assert json.loads(run(["stop", str(missing)], env_base, tmp_path, stdin="{}").stdout)["decision"] == "block"


def test_untracked_special_files_symlinks_and_oversize_fail_closed_without_hanging(box, tmp_path):
    repo, env = box
    env0 = {**env, "STUB_EXIT": "0"}

    # 1. Untracked FIFO: must fail closed immediately (no hang!) on post AND when created after exit 0
    fifo = repo / "hang.fifo"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    p = run(["post"], env0, repo)
    assert time.monotonic() - t0 < 10
    assert "fifo" in context(p) and "UNVERIFIED" in context(p)
    assert json.loads(run(["status"], env0, repo).stdout)["status"] == "error"
    assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    fifo.unlink()

    # 2. Untracked UNIX domain socket: fails closed promptly
    sock_path = repo / "local.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(str(sock_path))
        p_sock = run(["post"], env0, repo)
        assert "socket" in context(p_sock) and "UNVERIFIED" in context(p_sock)
        assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    finally:
        srv.close()
        sock_path.unlink(missing_ok=True)

    # 3. Untracked symlink pointing to a FIFO or /dev/zero: hashed by readlink target (never opened!), target change invalidates
    ext_fifo = tmp_path / "external.fifo"
    os.mkfifo(ext_fifo)
    link = repo / "link_to_fifo"
    link.symlink_to(ext_fifo)
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    t0 = time.monotonic()
    run(["post"], env0, repo)
    st = wait_done(env0, repo)
    assert time.monotonic() - t0 < 10 and st["status"] == "done" and st["exit"] == 0
    assert run(["stop"], env0, repo, stdin="{}").stdout.strip() == ""
    link.unlink()
    link.symlink_to("/dev/zero")
    assert "changed after that check started" in context(run(["prompt"], env0, repo))
    assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    link.unlink()

    # 4. Untracked FIFO created AFTER a valid exit 0 receipt -> prompt/stop fail closed immediately without hanging
    run(["post"], env0, repo)
    wait_done(env0, repo)
    assert run(["stop"], env0, repo, stdin="{}").stdout.strip() == ""
    os.mkfifo(fifo)
    t0 = time.monotonic()
    pr = context(run(["prompt"], env0, repo))
    assert time.monotonic() - t0 < 10 and "fifo" in pr and "UNVERIFIED" in pr
    assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    fifo.unlink()

    # 5. Oversized untracked file (> 8 MiB sparse file) -> fails closed via size bound
    big = repo / "huge.bin"
    with open(big, "wb") as f:
        f.truncate(9 * 1024 * 1024)
    p_big = run(["post"], env0, repo)
    assert "limit" in context(p_big) and "UNVERIFIED" in context(p_big)
    assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    big.unlink()

    # 6. Gitignored .venv directory containing a FIFO is pruned cleanly (negative control)
    (repo / ".gitignore").write_text(".venv/\n")
    (repo / ".venv").mkdir()
    os.mkfifo(repo / ".venv" / "ignored.fifo")
    run(["post"], env0, repo)
    st_ig = wait_done(env0, repo)
    assert st_ig["status"] == "done" and st_ig["exit"] == 0
    assert run(["stop"], env0, repo, stdin="{}").stdout.strip() == ""

    # 7. Tracked file replaced by a FIFO fails closed promptly before git diff can open it
    orig_m = (repo / "m.py").read_text()
    (repo / "m.py").unlink()
    os.mkfifo(repo / "m.py")
    try:
        t0 = time.monotonic()
        p_tf = run(["post"], env0, repo)
        assert time.monotonic() - t0 < 10
        assert "fifo" in context(p_tf) and "UNVERIFIED" in context(p_tf)
        assert json.loads(run(["stop"], env0, repo, stdin="{}").stdout)["decision"] == "block"
    finally:
        (repo / "m.py").unlink()
        (repo / "m.py").write_text(orig_m)


def test_real_engine_check_exit0_receipt_invalidates_on_head_move_same_diff(tmp_path):
    """End-to-end with real `hlith check` (confined, skipped unless HLITH_CONTRACT_FULL=1):
    a real LANDED rehearsal receipt passes envelope/base validation on the same HEAD,
    then becomes stale and blocks stop as soon as HEAD advances with an identical dirty diff."""
    if os.environ.get("HLITH_CONTRACT_FULL") != "1":
        pytest.skip("runs real confined hlith check; set HLITH_CONTRACT_FULL=1")

    import sys

    repo = tmp_path / "fx_real"
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "pkg" / "__init__.py").write_text("")
    (repo / "src" / "pkg" / "limits.py").write_text(
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    if value > 300:\n"
        "        return 300\n"
        "    return value\n"
    )
    (repo / "tests" / "test_limits.py").write_text(
        "from pkg.limits import effective_timeout\n\n"
        "def test_caps():\n"
        "    assert effective_timeout(60) == 60\n"
        "    assert effective_timeout(600) == 300\n"
    )
    (repo / "context.txt").write_text("v1\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")

    hlith_wrap = tmp_path / "hlith-real"
    src_root = Path(__file__).resolve().parents[1] / "src"
    hlith_wrap.write_text(
        f"#!/usr/bin/env bash\n"
        f"export PYTHONPATH={str(src_root)!r}\n"
        f"export PYTHONDONTWRITEBYTECODE=1\n"
        f"exec {sys.executable!r} -m hlith.operator.cli \"$@\"\n"
    )
    hlith_wrap.chmod(0o755)
    state_dir = tmp_path / "hlith_state"
    ui_dir = tmp_path / "hlith_ui"
    state_dir.mkdir(mode=0o700)
    ui_dir.mkdir(mode=0o700)
    env = {
        **os.environ,
        "HLITH_BIN": str(hlith_wrap),
        "HLITH_TARGET_PYTHON": sys.executable,
        "HLITH_STATE_DIR": str(state_dir),
        "HLITH_UI_STATE": str(ui_dir),
        "HLITH_HOOK_HOME": str(tmp_path / "hook_home"),
        "CLAUDE_PROJECT_DIR": str(repo),
    }

    # Behavior-preserving edit -> real LANDED rehearsal (exit 0)
    (repo / "src" / "pkg" / "limits.py").write_text(
        "def effective_timeout(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    capped = 300 if value > 300 else value\n"
        "    return capped\n"
    )
    diff_before = git(repo, "diff", "HEAD", "--binary")
    head1 = git(repo, "rev-parse", "HEAD")

    p = run(["post"], env, repo)
    assert "started in the background" in context(p)
    st = wait_done(env, repo, seconds=180)
    assert st["status"] == "done" and st["exit"] == 0 and st["head"] == head1 and st["envelope_ok"] is True, st
    assert "LANDED" in context(run(["prompt"], env, repo)) and "changed after" not in context(run(["prompt"], env, repo))
    assert run(["stop"], env, repo, stdin="{}").stdout.strip() == ""

    # Advance HEAD with unrelated commit while dirty diff stays identical -> stale + stop blocked
    (repo / "context.txt").write_text("v2\n")
    git(repo, "add", "context.txt")
    git(repo, "commit", "-qm", "unrelated context")
    assert git(repo, "rev-parse", "HEAD") != head1
    assert git(repo, "diff", "HEAD", "--binary") == diff_before
    assert "changed after that check started" in context(run(["prompt"], env, repo))
    blocked = json.loads(run(["stop"], env, repo, stdin="{}").stdout)
    assert blocked["decision"] == "block" and "UNVERIFIED" in blocked["reason"]
