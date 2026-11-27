# SPDX-License-Identifier: Apache-2.0
"""E1: a crash BETWEEN agent turns must leave a durable thread that a new process can continue (review, case).

The proposer is MockModelProposer (kind mock, plumbing_only): no model, no credentials, no network."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hlith import layer1
from hlith.proposer import MockModelProposer
from hlith.runtime import RuntimeBoundary, run_worker

PATCH_A = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-VALUE_A = 1\n+VALUE_A = 10\n"
PATCH_B = "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-VALUE_B = 2\n+VALUE_B = 20\n"
SCRIPT = [
    [{"name": "apply_patch", "diff": PATCH_A}],
    [{"name": "apply_patch", "diff": PATCH_B}, {"name": "declare", "paths": {"a.py": ["modify"], "b.py": ["modify"]}},
     {"name": "finish", "summary": "done"}],
]


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("VALUE_A = 1\n")
    (r / "b.py").write_text("VALUE_B = 2\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


class CrashAtTurn(MockModelProposer):
    """The proposer call for turn ``n`` fails: stands for the supervisor dying between turns (the real SIGKILL is the harness)."""

    def __init__(self, script, n):
        super().__init__(script)
        self.n = n

    def reply(self, turn):
        if turn["turn"] == self.n:
            raise RuntimeError("supervisor crash")
        return super().reply(turn)


def test_mock_proposer_is_indexed_by_the_turn_number_not_by_how_often_it_was_called():
    fresh = MockModelProposer(SCRIPT)  # a NEW process: its call count is 0, the thread is at turn 1
    assert fresh.reply({"turn": 1, "task": "t", "transcript": []})["tool_calls"] == SCRIPT[1]
    assert fresh.reply({"turn": 0, "task": "t", "transcript": []})["tool_calls"] == SCRIPT[0]
    assert fresh.reply({"turn": 5, "task": "t", "transcript": []})["tool_calls"][0]["name"] == "finish"  # exhausted script


def _crashed_run(repo, store):
    with pytest.raises(RuntimeBoundary):
        run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=CrashAtTurn(SCRIPT, 1))
    threads = sorted(p for p in Path(store).iterdir() if p.is_dir())
    assert len(threads) == 1, "a crash between turns must leave one durable thread"
    return threads[0]


def test_a_crash_between_turns_leaves_a_durable_in_progress_thread(repo, tmp_path):
    d = _crashed_run(repo, tmp_path / "store")
    meta = json.loads((d / "meta.json").read_text())
    assert meta["state"] == "agent-progress" and meta["turns_done"] == 1 and meta["thread_id"] == d.name
    assert (d / "stage_delta" / "files" / "a.py").read_text() == "VALUE_A = 10\n"  # turn 0's edit is in the persisted delta
    assert not (d / "stage_delta" / "files" / "b.py").exists()  # unchanged base file is never copied into store


def test_new_process_resume_continues_from_the_recorded_turn_without_replaying_turn_zero(repo, tmp_path):
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    ids_before = layer1._read_ids(d / "ckpt", tmp_path, d.name)[0]
    p = MockModelProposer(SCRIPT)  # fresh instance, as in a new process
    rep = layer1.resume_agent_thread(d.name, store, p, timeout=120, redo_inflight=True)
    assert [t["turn"] for t in p.seen_turns] == [1]  # turn 0 was not asked again
    assert rep["thread_id"] == d.name and rep["resumed_from_turn"] == 1 and rep["reached"] == "propose"
    assert rep["checkpoint_prefix_preserved"] is True and rep["ids_after"][:len(ids_before)] == ids_before
    assert rep["proposer"]["redo_inflight"] is True and rep["proposer"]["redone_turn"] == 1
    assert [(t["turn"], t["ok"]) for t in rep["transcript"] if t["tool"] == "apply_patch"] == [(0, True), (1, True)]
    assert sorted(rep["claimed_paths"]) == ["a.py", "b.py"]
    # the gate side: a run that died before any gate never lands; feedback ran once; replay is idempotent
    g1 = layer1.resume_thread(d.name, store, timeout=120)
    g2 = layer1.resume_thread(d.name, store, timeout=120)
    assert g1["verdict_source"] == "interrupted" and g1["exit_status"] == 4 and g1["feedback_executions"] == 1 and g1["resumed"] is True
    assert g2["already_finished"] is True and g2["feedback_executions"] == 1 and g2["verdict_source"] == "recorded"
    assert (repo / "a.py").read_text() == "VALUE_A = 1\n" and (repo / "b.py").read_text() == "VALUE_B = 2\n"  # target untouched


def test_a_second_mid_agent_resume_is_refused_and_the_proposer_is_not_asked(repo, tmp_path):
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    layer1.resume_agent_thread(d.name, store, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    again = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary):
        layer1.resume_agent_thread(d.name, store, again, timeout=120)
    assert again.seen_turns == []


def _clear_inflight_for_test(d):
    """Make the test fixture represent a valid completed-turn checkpoint, not a call whose outcome is uncertain."""
    meta = json.loads((d / "meta.json").read_text())
    meta["in_flight_turn"] = None
    meta["progress_mac"] = layer1._progress_mac(
        d.name, meta["turns_done"], meta["reply_sha256"], meta["target_path"], meta["base_tree"], meta["tree_digest"],
        layer1._avoid_for(d, meta), in_flight_turn=None, pending_reply_turn=meta["pending_reply_turn"],
        pending_reply_sha256=meta["pending_reply_sha256"], command_argv_sha256=meta["command_argv_sha256"],
        export_manifest_sha256=meta.get("export_manifest_sha256"), create=False,
    )
    (d / "meta.json").write_text(json.dumps(meta))


def test_inflight_marker_is_mac_protected_and_resume_refuses_without_explicit_redo(repo, tmp_path):
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    meta = json.loads((d / "meta.json").read_text())
    assert meta["in_flight_turn"] == 1
    p = MockModelProposer(SCRIPT)
    with pytest.raises(layer1.IndeterminateProposerCall, match="turn 1.*side effects are unknown"):
        layer1.resume_agent_thread(d.name, store, p, timeout=120)
    assert p.seen_turns == []

    meta["in_flight_turn"] = None
    (d / "meta.json").write_text(json.dumps(meta))
    with pytest.raises(RuntimeBoundary, match="not authenticated"):
        layer1.resume_agent_thread(d.name, store, p, timeout=120)
    assert p.seen_turns == []

    meta.pop("in_flight_turn")
    (d / "meta.json").write_text(json.dumps(meta))
    with pytest.raises(RuntimeBoundary, match="malformed agent-progress metadata"):
        layer1.resume_agent_thread(d.name, store, p, timeout=120)


def test_gate_side_resume_of_a_mid_agent_thread_says_so(repo, tmp_path):
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    with pytest.raises(RuntimeBoundary) as e:
        layer1.resume_thread(d.name, store, timeout=60)
    assert "mid-agent" in str(e.value)


def test_resume_refuses_when_the_target_moved_on(repo, tmp_path):
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    (repo / "c.py").write_text("X = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "operator commit")
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary) as e:
        layer1.resume_agent_thread(d.name, store, p, timeout=120)
    assert "base" in str(e.value) and p.seen_turns == []


@pytest.mark.xfail(
    strict=True,
    reason="CONTRACT CHANGED by imported PR #3 (00bac464, checkpoint.py:922-923): a symlink in the effect-interrupt stage now aborts the run with RuntimeBoundary (fail-closed) instead of continuing with a not-durable turn; contract decision pending: restore the continue-semantics or keep the abort",
)
def test_a_stage_with_a_symlink_does_not_abort_the_run_and_that_turn_is_reported_not_durable(repo, tmp_path):
    """Durability must not change what a run can reach: a model-created symlink is an effect the later checks judge. The turn is simply
    not made durable (and says so); the earlier complete copy, if any, stays the resume point."""
    store = tmp_path / "store"
    link = {"name": "apply_patch", "diff": "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+a.py\n\\ No newline at end of file\n"}
    script = [[{"name": "apply_patch", "diff": PATCH_A}], [link], [{"name": "finish", "summary": "done"}]]
    try:
        run = run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=MockModelProposer(script))
    except RuntimeBoundary as e:  # a later check (not the persistence) may refuse the symlink: that is the point of the test
        assert "refusing to persist" not in str(e)
        return
    assert run.graph.proposer.get("progress_not_durable_at_turns") == [1, 2]


def test_a_stage_symlink_aborts_without_persisting_its_delta(repo, tmp_path):
    store = tmp_path / "store"
    marker = "EFFECT_SYMLINK_DELTA_MARKER"
    (repo / "secret.txt").write_text(marker + "\n")
    _git(repo, "add", "secret.txt")
    _git(repo, "commit", "-q", "-m", "add marker file")
    link = {"name": "apply_patch", "diff": "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+secret.txt\n\\ No newline at end of file\n"}
    script = [[{"name": "apply_patch", "diff": PATCH_A}], [link], [{"name": "finish", "summary": "done"}]]

    with pytest.raises(
        RuntimeBoundary,
        match="layer1: effect interrupt stage is not a regular delta; refusing to persist an unresumable checkpoint",
    ):
        run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=MockModelProposer(script))

    threads = [p for p in store.iterdir() if p.is_dir() and not p.name.startswith(".")]
    assert len(threads) == 1
    thread = threads[0]
    meta = json.loads((thread / "meta.json").read_text())
    assert meta["state"] == "agent-progress" and meta["turns_done"] == 1
    persisted_link = thread / "stage_delta" / "files" / "l"
    assert not persisted_link.exists() and not persisted_link.is_symlink()
    store_bytes = b"".join(p.read_bytes() for p in store.rglob("*") if p.is_file())
    assert marker.encode() not in store_bytes


def test_concurrent_mid_agent_resume_calls_proposer_only_once(repo, tmp_path):
    """A11: a second concurrent resume_agent_thread must block on the lock across _swap_dir and refuse without calling proposer."""
    import threading

    store = tmp_path / "store"
    script3 = [
        [{"name": "apply_patch", "diff": PATCH_A}],
        [{"name": "apply_patch", "diff": PATCH_B}],
        [{"name": "declare", "paths": {"a.py": ["modify"], "b.py": ["modify"]}}, {"name": "finish", "summary": "done"}],
    ]
    with pytest.raises(RuntimeBoundary):
        run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=CrashAtTurn(script3, 1))
    d = next(p for p in store.iterdir() if p.is_dir())
    _clear_inflight_for_test(d)
    at_turn2, release_turn2 = threading.Event(), threading.Event()

    class BlockingProposer(MockModelProposer):
        def reply(self, turn):
            if turn["turn"] == 2:
                at_turn2.set()
                assert release_turn2.wait(timeout=30)
            return super().reply(turn)

    p1 = BlockingProposer(script3)
    p2 = MockModelProposer(script3)
    res1: list = []
    res2: list = []

    def run1():
        try:
            res1.append(("ok", layer1.resume_agent_thread(d.name, store, p1, timeout=120)))
        except BaseException as e:  # noqa: BLE001
            res1.append(("err", e))

    def run2():
        try:
            res2.append(("ok", layer1.resume_agent_thread(d.name, store, p2, timeout=120)))
        except BaseException as e:  # noqa: BLE001
            res2.append(("err", e))

    t1 = threading.Thread(target=run1)
    t1.start()
    assert at_turn2.wait(timeout=30), f"t1 never reached turn 2: {res1}"
    t2 = threading.Thread(target=run2)
    t2.start()
    # Give t2 a moment to acquire the lock if it's broken (on the buggy code it enters turn 1 immediately).
    release_turn2.wait(timeout=0.5)
    release_turn2.set()
    t1.join(timeout=60)
    t2.join(timeout=60)
    assert res1 and res1[0][0] == "ok", res1
    assert res2 and res2[0][0] == "err" and isinstance(res2[0][1], (RuntimeBoundary, layer1.IndeterminateProposerCall)), res2
    assert p2.seen_turns == []


def test_forged_progress_fields_and_target_path_are_refused(repo, tmp_path):
    """A7 & A9: tampering with turns_done/reply_sha256 or target_path in agent-progress meta fails HMAC authentication."""
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    meta_path = d / "meta.json"
    orig = json.loads(meta_path.read_text())

    # A7: forge turns_done / reply_sha256
    forged = dict(orig)
    forged["turns_done"] = 5
    forged["reply_sha256"] = ["f" * 64] * 5
    meta_path.write_text(json.dumps(forged))
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="malformed agent-progress metadata"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert p.seen_turns == []

    # A9: point target_path at another repo with the same base tree
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    _git(other, "config", "user.email", "t@t")
    _git(other, "config", "user.name", "t")
    (other / "a.py").write_text("VALUE_A = 1\n")
    (other / "b.py").write_text("VALUE_B = 2\n")
    _git(other, "add", "-A")
    _git(other, "commit", "-q", "-m", "base")
    retargeted = dict(orig)
    retargeted["target_path"] = str(other.resolve())
    meta_path.write_text(json.dumps(retargeted))
    with pytest.raises(RuntimeBoundary, match="authenticated"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert p.seen_turns == []


def test_hardlink_in_stored_stage_is_refused(repo, tmp_path):
    """A4: a hardlink (st_nlink > 1) in the stored stage must be refused on resume."""
    import os

    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET_TOKEN\n")
    (d / "stage_delta" / "files" / "a.py").unlink()
    os.link(secret, d / "stage_delta" / "files" / "a.py")
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="hardlink"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert p.seen_turns == []


def test_command_proposer_caps_huge_output_without_buffering(tmp_path):
    """B3: CommandProposer stops reading once stdout exceeds max_output instead of buffering unbounded output."""
    import sys
    from hlith.proposer import CommandProposer, HostSideProposerTrust, NotConfigured

    script = tmp_path / "huge.py"
    script.write_text(
        "import sys; sys.stdin.read()\n"
        "chunk = ' ' * (1 << 16)\n"
        "for _ in range(128):\n"
        "    sys.stdout.write(chunk)\n"
    )
    cp = CommandProposer([sys.executable, str(script)], timeout=30.0, max_output=32 * 1024)
    with pytest.raises(NotConfigured, match="output exceeded 32768 byte limit"):
        cp.reply({"turn": 0, "task": "t", "transcript": []})


def test_command_proposer_kills_grandchild_daemon_on_timeout(tmp_path):
    """B6: CommandProposer kills grandchild daemons (even setsid holding stdout) when the call ends/times out."""
    import sys
    import time
    from hlith.proposer import CommandProposer, HostSideProposerTrust, NotConfigured

    marker = tmp_path / "daemon-marker.txt"
    script = tmp_path / "daemon.py"
    script.write_text(
        "import json, os, sys, time\n"
        "sys.stdin.read()\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    time.sleep(2.5)\n"
        f"    open({str(marker)!r}, 'w').write('alive')\n"
        "    os._exit(0)\n"
        "print(json.dumps({'tool_calls': [{'name': 'finish', 'summary': 'ok'}]}), flush=True)\n"
    )
    cp = CommandProposer([sys.executable, str(script)], timeout=0.8, host_trust=HostSideProposerTrust(authorized=True))
    with pytest.raises(NotConfigured, match="TimeoutExpired"):
        cp.reply({"turn": 0, "task": "t", "transcript": []})
    time.sleep(3.0)
    assert not marker.exists()


def test_lock_symlink_directory_and_unlink_are_refused_cleanly(repo, tmp_path, monkeypatch):
    """L1/L2/L3: symlink or directory at _locked(d).path raises RuntimeBoundary (never raw OSError), and unlinking is detected."""
    import os

    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "hlith-state"))
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    lock_path = layer1._locked(d).path
    if lock_path.exists():
        lock_path.unlink()
    p = MockModelProposer(SCRIPT)

    # L2: symlink at lock path -> RuntimeBoundary
    outside = tmp_path / "outside"
    outside.write_text("x")
    os.symlink(outside, lock_path)
    with pytest.raises(RuntimeBoundary, match="cannot lock"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    lock_path.unlink()

    # L3: directory at lock path -> RuntimeBoundary
    lock_path.mkdir()
    with pytest.raises(RuntimeBoundary, match="cannot lock"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    lock_path.rmdir()
    assert p.seen_turns == []

    # L1: replacing lock file while _acquire_flock waits raises RuntimeBoundary after retries
    with layer1._locked(d):
        assert lock_path.exists()
        lock_path.unlink()
        with pytest.raises(RuntimeBoundary, match="cannot lock|replaced"):
            # Pre-plant a directory after unlink to verify _acquire_flock refuses
            from hlith.agent.checkpoint import _acquire_flock
            lock_path.mkdir()
            _acquire_flock(lock_path)
        lock_path.rmdir()


def test_k1_state_dir_under_worker_ro_refused_at_run_start_and_key_rotates(repo, tmp_path, monkeypatch):
    """K1: HLITH_STATE_DIR under --worker-ro is refused before spawning the worker; rotate_mac_key replaces the key."""
    ro_dir = tmp_path / "worker_ro"
    ro_dir.mkdir()
    bad_state = ro_dir / "state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(bad_state))
    with pytest.raises(RuntimeBoundary, match="must not be inside"):
        run_worker(repo, ["true"], timeout=30, worker_ro=(str(ro_dir),))
    assert not (bad_state / "thread-store.key").exists()

    good_state = tmp_path / "good_state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(good_state))
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    old_key = (good_state / "thread-store.key").read_bytes()
    layer1.rotate_mac_key()
    new_key = (good_state / "thread-store.key").read_bytes()
    assert len(new_key) == 32 and new_key != old_key
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="authenticated"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert p.seen_turns == []


def test_k2_deleted_mac_key_fails_closed_with_clear_message(repo, tmp_path, monkeypatch):
    """K2: deleting thread-store.key does not silently create a new key during verification."""
    state = tmp_path / "state_k2"
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    (state / "thread-store.key").unlink()
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="missing"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert not (state / "thread-store.key").exists()
    assert p.seen_turns == []


def test_k4_tampered_stage_after_crash_is_refused_by_tree_digest(repo, tmp_path):
    """K4: modifying a file in the stored stage after the crash is refused even with untouched meta.json."""
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    (d / "stage_delta" / "files" / "a.py").write_text("VALUE_A = 999\n")
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="tree digest"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60)
    assert p.seen_turns == []


def test_l4_copied_thread_in_second_store_cannot_resume_twice(repo, tmp_path):
    """L4: copying a mid-agent thread to a second store does not allow a second resume."""
    import shutil

    store1 = tmp_path / "store1"
    store2 = tmp_path / "store2"
    d1 = _crashed_run(repo, store1)
    store2.mkdir(mode=0o700)
    shutil.copytree(d1, store2 / d1.name)
    for sub in ("", "ckpt", "driver", "inputs", "stage", "channel"):
        (store2 / d1.name / sub if sub else store2 / d1.name).chmod(0o700)

    rep = layer1.resume_agent_thread(d1.name, store1, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    assert rep["reached"] == "propose"
    p2 = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="already been resumed|refusing duplicate resume"):
        layer1.resume_agent_thread(d1.name, store2, p2, timeout=60)
    assert p2.seen_turns == []


def test_persist_progress_and_resume_with_tracked_symlink(repo, tmp_path):
    """Tracked repo symlinks (like requests' tests/certs/*/ca) must not block persist_progress and must never enter stage_delta."""
    certs = repo / "tests" / "certs" / "valid"
    certs.mkdir(parents=True)
    (certs.parent / "ca.pem").write_text("CA\n")
    (certs / "ca").symlink_to("../ca.pem")
    _git(repo, "add", "tests")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "add tracked symlink")

    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    assert not (d / "stage_delta" / "files" / "tests" / "certs" / "valid" / "ca").exists()
    rep = layer1.resume_agent_thread(d.name, store, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    assert rep["reached"] == "propose"
    assert sorted(rep["claimed_paths"]) == ["a.py", "b.py"]


def test_persist_progress_refuses_agent_created_or_modified_symlink(repo, tmp_path):
    """Agent-created or modified symlinks in stage must fail closed (persist_progress returns None)."""
    import tempfile
    from hlith.agent.checkpoint import persist_progress
    from hlith.agent.supervisor import Layer1Session

    store = tmp_path / "store"
    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        base_ro = tp / "target_ro"
        stage = tp / "stage"
        channel = tp / "channel"
        ckpt = tp / "ckpt"
        driver = tp / "driver"
        inputs = tp / "inputs"
        for p in (base_ro, stage, channel, ckpt, driver, inputs):
            p.mkdir()
        (base_ro / "kept").symlink_to("real.txt")
        (stage / "kept").symlink_to("real.txt")
        (stage / "agent_link").symlink_to("/etc/passwd")

        class _Tmp:
            name = td

        sess = Layer1Session(
            tmp=_Tmp(), stage=stage, ckpt=ckpt, channel=channel, driver=driver,
            inputs=inputs, thread_id="hlith-0123456789abcdef0123", env={}, timeout=60,
        )
        assert persist_progress(sess, store, target=repo, base_tree="0" * 40, turns_done=0, reply_sha256=[]) is None

        (stage / "agent_link").unlink()
        (stage / "kept").unlink()
        (stage / "kept").symlink_to("/etc/shadow")
        assert persist_progress(sess, store, target=repo, base_tree="0" * 40, turns_done=0, reply_sha256=[]) is None


def test_tampered_stage_delta_refused_on_resume(repo, tmp_path):
    """Tampering stage_delta between kill and resume (../x in deleted.json, symlink in files/, changed content) must refuse."""
    for kind in ("escape", "symlink", "hash"):
        store = tmp_path / f"store_{kind}"
        d = _crashed_run(repo, store)
        if kind == "escape":
            (d / "stage_delta" / "deleted.json").write_text('{"deleted":["../x"]}\n')
        elif kind == "symlink":
            (d / "stage_delta" / "files" / "evil").symlink_to("/etc/passwd")
        else:
            (d / "stage_delta" / "files" / "a.py").write_text("VALUE_A = 999\n")
        p = MockModelProposer(SCRIPT)
        with pytest.raises(RuntimeBoundary):
            layer1.resume_agent_thread(d.name, store, p, timeout=60, redo_inflight=True)
        assert p.seen_turns == []


def test_defect1_replaced_tracked_file_symlink_never_overwrites_target(repo, tmp_path):
    """Defect 1: agent replacing a tracked symlink with a regular file must unlink the symlink, never overwrite its target."""
    import shutil, tempfile
    from hlith.agent.checkpoint import persist_progress
    from hlith.agent.supervisor import Layer1Session, _export_clean_tree, _read_head_tree

    (repo / "secret.txt").write_text("KEEP_ME\n")
    (repo / "link").symlink_to("secret.txt")
    _git(repo, "add", "secret.txt", "link")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "add tracked file symlink")

    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    meta = json.loads((d / "meta.json").read_text())
    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        base_ro = tp / "target_ro"
        stage = tp / "stage"
        _export_clean_tree(repo, base_ro)
        shutil.copytree(base_ro, stage, symlinks=True)
        (stage / "link").unlink()
        (stage / "link").write_text("REPLACED\n")
        for sub in ("ckpt", "driver", "inputs", "channel"):
            shutil.copytree(d / sub, tp / sub)
        shutil.rmtree(d)

        class _Tmp:
            name = td

        sess = Layer1Session(
            tmp=_Tmp(), stage=stage, ckpt=tp / "ckpt", channel=tp / "channel",
            driver=tp / "driver", inputs=tp / "inputs", thread_id=d.name, env={}, timeout=120,
        )
        persist_progress(
            sess, store, target=repo, base_tree=_read_head_tree(repo),
            turns_done=meta["turns_done"], reply_sha256=meta["reply_sha256"],
            in_flight_turn=meta["in_flight_turn"], command_argv_sha256=meta["command_argv_sha256"],
            profile_sha256=meta.get("profile_sha256"), run_id=meta.get("run_id"),
        )
    assert (d / "stage_delta" / "files" / "link").read_text() == "REPLACED\n"
    rep = layer1.resume_agent_thread(d.name, store, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    assert rep["reached"] == "propose"
    assert (repo / "secret.txt").read_text() == "KEEP_ME\n"


def test_defect2_tracked_symlinked_dir_and_replaced_symlinked_dir(repo, tmp_path):
    """Defect 2: untouched tracked symlinked dir does not break persist_progress; replaced symlinked dir is recorded in deleted.json."""
    import shutil, tempfile
    from hlith.agent.checkpoint import persist_progress
    from hlith.agent.supervisor import Layer1Session, _export_clean_tree, _read_head_tree

    real_dir = repo / "real_dir"
    real_dir.mkdir()
    (real_dir / "keep.txt").write_text("SAFE\n")
    (repo / "sub").symlink_to("real_dir")
    _git(repo, "add", "real_dir", "sub")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "add tracked dir symlink")

    store1 = tmp_path / "store1"
    d1 = _crashed_run(repo, store1)
    assert "sub" not in json.loads((d1 / "stage_delta" / "deleted.json").read_text())["deleted"]
    rep1 = layer1.resume_agent_thread(d1.name, store1, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    assert rep1["reached"] == "propose"

    store2 = tmp_path / "store2"
    d2 = _crashed_run(repo, store2)
    meta2 = json.loads((d2 / "meta.json").read_text())
    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        base_ro = tp / "target_ro"
        stage = tp / "stage"
        _export_clean_tree(repo, base_ro)
        shutil.copytree(base_ro, stage, symlinks=True)
        (stage / "sub").unlink()
        (stage / "sub").mkdir()
        (stage / "sub" / "x.txt").write_text("IN_STAGE\n")
        for sub in ("ckpt", "driver", "inputs", "channel"):
            shutil.copytree(d2 / sub, tp / sub)
        shutil.rmtree(d2)

        class _Tmp:
            name = td

        sess = Layer1Session(
            tmp=_Tmp(), stage=stage, ckpt=tp / "ckpt", channel=tp / "channel",
            driver=tp / "driver", inputs=tp / "inputs", thread_id=d2.name, env={}, timeout=120,
        )
        persist_progress(
            sess, store2, target=repo, base_tree=_read_head_tree(repo),
            turns_done=meta2["turns_done"], reply_sha256=meta2["reply_sha256"],
            in_flight_turn=meta2["in_flight_turn"], command_argv_sha256=meta2["command_argv_sha256"],
            profile_sha256=meta2.get("profile_sha256"), run_id=meta2.get("run_id"),
        )
    assert "sub" in json.loads((d2 / "stage_delta" / "deleted.json").read_text())["deleted"]
    rep2 = layer1.resume_agent_thread(d2.name, store2, MockModelProposer(SCRIPT), timeout=120, redo_inflight=True)
    assert rep2["reached"] == "propose"
    assert not (real_dir / "x.txt").exists()


def test_defect3_reverted_turn0_edit_does_not_resurrect_on_resume(repo, tmp_path):
    """Defect 3: edit in turn 0 reverted in turn 1 must not stay in stage_delta or resurrect on resume."""
    revert_script = [
        [{"name": "apply_patch", "diff": PATCH_A}],
        [{"name": "apply_patch", "diff": "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-VALUE_A = 10\n+VALUE_A = 1\n"}],
        [{"name": "finish", "summary": "done"}],
    ]
    store = tmp_path / "store"
    with pytest.raises(RuntimeBoundary):
        run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=CrashAtTurn(revert_script, 2))
    d = next(p for p in store.iterdir() if p.is_dir())
    assert not (d / "stage_delta" / "files" / "a.py").exists()
    rep = layer1.resume_agent_thread(d.name, store, MockModelProposer(revert_script), timeout=120, redo_inflight=True)
    assert rep["claimed_paths"] == []


def test_defect4_target_tree_change_during_resume_refused(repo, tmp_path, monkeypatch):
    """Defect 4: exported stage tree OID mismatch vs meta['base_tree'] refuses with RuntimeBoundary."""
    import hlith.agent.supervisor as _sup
    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    orig_export = _sup._export_clean_tree

    def _drift_export(target, dest, *, git_read=None, snapshot_service=None):
        orig_export(target, dest, git_read=git_read, snapshot_service=snapshot_service)
        (dest / "b.py").write_text("DRIFTED = 1\n")

    monkeypatch.setattr(_sup, "_export_clean_tree", _drift_export)
    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="exported stage manifest"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60, redo_inflight=True)
    assert p.seen_turns == []


def test_export_manifest_digest_tamper_and_missing_in_meta_refused(repo, tmp_path):
    """Tampering or stripping export_manifest_sha256 in meta.json fails closed before proposer is called."""
    for mode in ("tamper", "strip"):
        store = tmp_path / f"store_{mode}"
        d = _crashed_run(repo, store)
        meta_p = d / "meta.json"
        meta = json.loads(meta_p.read_text())
        assert isinstance(meta.get("export_manifest_sha256"), str) and len(meta["export_manifest_sha256"]) == 64
        if mode == "tamper":
            meta["export_manifest_sha256"] = "0" * 64
        else:
            meta.pop("export_manifest_sha256")
        meta_p.write_text(json.dumps(meta))
        p = MockModelProposer(SCRIPT)
        with pytest.raises(RuntimeBoundary):
            layer1.resume_agent_thread(d.name, store, p, timeout=60, redo_inflight=True)
        assert p.seen_turns == []


def test_resume_refuses_smudge_filter_added_after_kill_without_running_host_filter(repo, tmp_path):
    """case: resume must never run unhardened git archive against a hostile target."""
    import sys
    from hlith import cli

    store = tmp_path / "store"
    d = _crashed_run(repo, store)
    marker = tmp_path / "smudge.marker"
    (repo / ".git" / "info" / "attributes").write_text("* filter=evil\n")
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.evil.smudge", f"touch {marker}; cat"],
        check=True,
    )

    p = MockModelProposer(SCRIPT)
    with pytest.raises(RuntimeBoundary, match="hostile|filter|attribute|smudge"):
        layer1.resume_agent_thread(d.name, store, p, timeout=60, redo_inflight=True)
    assert not marker.exists(), "smudge filter executed on host during resume_agent_thread"
    assert p.seen_turns == []

    # Also verify legacy CLI resume route refuses with exit 4 (EXIT_BOUNDARY) and does not run the filter.
    prop_script = tmp_path / "prop.py"
    prop_script.write_text("import json\nprint(json.dumps({'tool_calls': [{'name': 'finish', 'summary': 'ok'}]}))\n")
    art_out = tmp_path / "out.json"
    rc = cli.main([
        "resume", d.name,
        "--engine", "legacy",
        "--proposer-command", f"{sys.executable} {prop_script}",
        "--thread-store", str(store),
        "--artifact-out", str(art_out),
        "--redo-inflight",
    ])
    assert rc == cli.EXIT_BOUNDARY
    assert not marker.exists(), "smudge filter executed on host during legacy CLI resume"

