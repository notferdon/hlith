"""_confine.py lifecycle: the launcher's mount-point dir must never outlive a run.

Causes found and fixed: (1) after the child's pivot_root the LAUNCHER's '/' is the tmpfs too, so path-based
umount2/rmdir hit ENOENT, swallowed (every normal run leaked); (2) review: a catchable signal before the handler existed
took the default action; (3) review: an uncatchable SIGKILL before pivot can never be handled inside the launcher, so the
supervisor (sandbox.run_confined) owns a per-run tree holding the dir and removes it after reaping.
Every launcher run here uses a PRIVATE TMPDIR, counted before/after.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

LAUNCHER = str(Path(__file__).parents[1] / "src/hlith/_confine.py")
HOSTIO_LAUNCHER = str(Path(__file__).parents[1] / "src/hlith/hostio/confine_exec.py")
BASE = {"ro": ["/usr", "/lib", "/lib64", "/bin", "/etc"], "rw": []}
SPEC = json.dumps(BASE)
N = 10
STAGES = ["pre_mkdtemp", "post_mkdtemp", "pre_fork", "post_fork", "post_pivot"]


def _launch(tmp: Path, spec: str, *argv: str, env_extra: dict | None = None) -> subprocess.Popen:
    env = {"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp), **(env_extra or {})}
    return subprocess.Popen([sys.executable, "-I", LAUNCHER, spec, "--", *argv], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def _wait_stopped(pid: int, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with open(f"/proc/{pid}/stat") as f:
            if f.read().rsplit(")", 1)[1].split()[0] == "T":
                return
        time.sleep(0.002)
    raise AssertionError("launcher never reached its stage")


def _scenario(name: str, tmp: Path) -> tuple[int | None, str]:
    if name == "normal":
        p = _launch(tmp, SPEC, "/bin/true")
    elif name == "nonzero":
        p = _launch(tmp, SPEC, "/bin/false")
    elif name == "die_in_child":  # build_root fails after the tmpfs is mounted, before pivot_root
        p = _launch(tmp, json.dumps({"ro": ["/usr"], "ro_bind": ["/nonexistent-hlith-x"]}), "/bin/true")
    elif name == "die_in_launcher":  # refused before any mount
        p = _launch(tmp, json.dumps({**BASE, "root_parent": "relative/dir"}), "/bin/true")
    elif name in ("sigterm", "sigint", "sigkill"):
        p = _launch(tmp, SPEC, "/bin/sleep", "30")
        time.sleep(0.4)  # well past pivot_root: the worker is running
        p.send_signal({"sigterm": signal.SIGTERM, "sigint": signal.SIGINT, "sigkill": signal.SIGKILL}[name])
    else:
        raise AssertionError(name)
    _, err = p.communicate(timeout=60)
    return p.returncode, err


@pytest.mark.parametrize("name", ["normal", "nonzero", "die_in_child", "die_in_launcher", "sigterm", "sigint",
                                  "sigkill"])
def test_no_mount_point_dir_outlives_a_run(tmp_path, name):
    tmp = tmp_path / "tmpdir"
    tmp.mkdir()
    rcs = set()
    for _ in range(N):
        rc, err = _scenario(name, tmp)
        rcs.add(rc)
        assert "cleanup" not in err, err  # an unexpected umount/rmdir errno is reported, never swallowed
    assert sorted(os.listdir(tmp)) == [], (name, rcs)
    want = {"normal": {0}, "nonzero": {1}, "die_in_child": {4}, "die_in_launcher": {4},
            "sigterm": {128 + signal.SIGTERM}, "sigint": {128 + signal.SIGINT}, "sigkill": {-signal.SIGKILL}}[name]
    assert rcs == want, (name, rcs)


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT])
def test_catchable_signal_at_every_lifecycle_stage_leaves_nothing(tmp_path, stage, sig):
    """Deterministic (review race): the launcher stops itself at `stage`; the signal is delivered there; it must exit
    128+sig with nothing left in TMPDIR, whatever the stage."""
    tmp = tmp_path / "tmpdir"
    tmp.mkdir()
    for _ in range(2):
        p = _launch(tmp, SPEC, "/bin/sleep", "30", env_extra={"HLITH_CONFINE_STOP_AT": stage})
        _wait_stopped(p.pid)
        os.kill(p.pid, sig)
        os.kill(p.pid, signal.SIGCONT)
        _, err = p.communicate(timeout=60)
        assert p.returncode == 128 + sig, (stage, sig, p.returncode, err)
        assert "cleanup" not in err, err
    assert os.listdir(tmp) == [], (stage, sig)


def test_root_parent_keeps_the_mount_point_inside_the_supervisor_tree(tmp_path):
    """spec.root_parent: the dir is created there (not in TMPDIR) and removed; the worker still sees only its grants."""
    tmp, own = tmp_path / "tmpdir", tmp_path / "own"
    tmp.mkdir()
    own.mkdir()
    out = subprocess.run([sys.executable, "-I", LAUNCHER, json.dumps({**BASE, "root_parent": str(own)}),
                          "--", "/bin/sh", "-c", f"test -d /usr && test ! -e /tmp && test ! -e {own}"],
                         env={"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp)}, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "no root_parent" not in out.stderr  # the fallback note only appears without root_parent
    # confinement unchanged: grants visible, the host tmp and the supervisor tree are not
    assert os.listdir(tmp) == [] and os.listdir(own) == []


def _kill_launcher_after(token: str, delay: float) -> None:
    deadline = time.monotonic() + delay
    while time.monotonic() < deadline:
        time.sleep(0.0005)
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                cmd = Path(f"/proc/{d}/cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if (LAUNCHER.encode() in cmd or HOSTIO_LAUNCHER.encode() in cmd) and token.encode() in cmd:
                try:
                    os.kill(int(d), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def test_launcher_sigkill_at_any_ms_leaves_nothing_via_run_confined(tmp_path, monkeypatch):
    """Uncatchable kill (review: SIGKILL at ~100 ms, before pivot, left dirs): through the real supervisor entry point
    sandbox.run_confined, a launcher SIGKILLed at 1..200 ms (10 runs per delay) leaves ZERO entries in the private
    temp root: neither the caller's per-run tree nor any mount-point dir survives the caller reaping it."""
    import tempfile

    from hlith.sandbox import Profile, run_confined

    tmp = tmp_path / "tmpdir"
    tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    rcs = set()
    for ms in (1, 5, 10, 20, 40, 60, 80, 100, 150, 200):
        for i in range(N):
            token = f"30.{ms:03d}{i:02d}"  # unique worker argv: identifies this run's launcher in /proc
            t = threading.Thread(target=_kill_launcher_after, args=(token, ms / 1000))
            t.start()
            # the launcher's own TMPDIR is the private root too: a mount point outside the caller's tree would show
            cp = run_confined(["/bin/sleep", token], Profile(), timeout=60,
                              env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": str(tmp)})
            t.join()
            rcs.add(cp.returncode)
            assert os.listdir(tmp) == [], (ms, i, os.listdir(tmp))
    assert -signal.SIGKILL in rcs, rcs


def _aged(p: Path, hours: float = 2) -> Path:
    t = time.time() - hours * 3600
    os.utime(p, (t, t), follow_symlinks=False)
    return p


def test_dead_supervisor_leftover_is_reaped_by_the_next_run(tmp_path, monkeypatch):
    """review: a SIGKILLed SUPERVISOR leaves its empty hlith-run-* tree (TemporaryDirectory cannot clean after that).
    Real: a python supervisor calling run_confined is SIGKILLed while its worker runs; the empty tree stays; once it
    is older than the age bar, the next run_confined removes it. Live/young/non-empty/foreign/symlink/other entries
    stay untouched."""
    import tempfile

    from hlith.sandbox import Profile, run_confined

    tmp = tmp_path / "t"
    tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    src = str(Path(__file__).parents[1] / "src")
    code = ("import sys,tempfile;sys.path.insert(0,sys.argv[1]);tempfile.tempdir=sys.argv[2];"
            "from hlith.sandbox import Profile,run_confined;run_confined(['/bin/sleep','1.5'],Profile())")
    sup = subprocess.Popen([sys.executable, "-I", "-c", code, src, str(tmp)])
    deadline = time.monotonic() + 30
    while not [n for n in os.listdir(tmp) if n.startswith("hlith-run-")] and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.5)  # worker running
    sup.kill()
    sup.wait()
    time.sleep(2)  # the orphaned launcher finishes its 1.5 s worker
    (left,) = [tmp / n for n in os.listdir(tmp) if n.startswith("hlith-run-")]
    assert os.listdir(left) == []  # the launcher already removed its mount point; only the supervisor tree stays
    keep = [tmp / "hlith-run-young", tmp / "hlith-run-full", tmp / "hlith-root-old", tmp / "other-old"]
    for k in keep:
        k.mkdir()
    (tmp / "hlith-run-full" / "f").write_text("x")
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp / "hlith-run-link").symlink_to(target)
    for p in (left, tmp / "hlith-run-full", tmp / "hlith-root-old", tmp / "other-old", tmp / "hlith-run-link", target):
        _aged(p)
    cp = run_confined(["/bin/true"], Profile(), env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": str(tmp)})
    assert cp.returncode == 0, cp.stderr
    assert not left.exists()
    assert all(k.exists() for k in keep) and (tmp / "hlith-run-link").is_symlink() and target.is_dir()
    assert sorted(os.listdir(tmp)) == sorted(["hlith-run-young", "hlith-run-full", "hlith-root-old", "other-old",
                                              "hlith-run-link"])


def test_reaper_is_bounded_owner_checked_and_never_fatal(tmp_path, monkeypatch):
    from hlith import sandbox

    for i in range(60):
        (tmp_path / f"hlith-run-{i:02d}").mkdir()
        _aged(tmp_path / f"hlith-run-{i:02d}")
    assert sandbox.reap_stale_run_dirs(str(tmp_path)) == 50  # cap per call
    assert sandbox.reap_stale_run_dirs(str(tmp_path)) == 10
    (tmp_path / "hlith-run-x").mkdir()
    _aged(tmp_path / "hlith-run-x")
    me = os.getuid()
    monkeypatch.setattr(sandbox.os, "getuid", lambda: me + 1)  # a foreign owner's entry is never removed
    assert sandbox.reap_stale_run_dirs(str(tmp_path)) == 0 and (tmp_path / "hlith-run-x").is_dir()
    monkeypatch.undo()
    assert sandbox.reap_stale_run_dirs(str(tmp_path / "missing")) == 0  # unreadable parent: reported, not raised
