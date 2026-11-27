# SPDX-License-Identifier: Apache-2.0
"""E2 confinement attack battery + paired negative controls (case).

Every attack runs against real kernel confinement (user/mount/pid/net namespaces +
ro_bind + Landlock ABI >= 6 + scrubbed fds/env + RLIMIT_AS) and has an explicit
negative control proving the identical probe detects the escape when confinement
is removed. Allocation controls stay bounded well under a 4 GiB / 2 GiB scope.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import resource
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from hlith.agent.supervisor import run_worker
from hlith.hostio import confinement
from hlith.hostio.confinement import GrantError, Profile, run_confined
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _init_repo(tmp_path: Path, name: str = "target_repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Hlith E2")
    _git(repo, "config", "user.email", "e2@example.invalid")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _tree_digest(root: Path) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        if ".git" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out.append((rel, f"link:{os.readlink(p)}"))
        elif p.is_dir():
            out.append((rel, "dir"))
        else:
            out.append((rel, hashlib.sha256(p.read_bytes()).hexdigest()))
    return tuple(out)


# ---------------------------------------------------------------------------
# 1. R_target kernel read-only, R_stage writable, ungranted paths hidden
# ---------------------------------------------------------------------------

_FS_PROBE = r"""
import json, os, sys
ro_dir, stage_dir, secret_path = sys.argv[1], sys.argv[2], sys.argv[3]
target_file = os.path.join(ro_dir, "app.py")
res = {}
for name, fn in [
    ("open_write", lambda: open(target_file, "a").write("PWNED\n")),
    ("create_sibling", lambda: open(os.path.join(ro_dir, "pwn.py"), "w").write("x")),
    ("chmod_ro", lambda: os.chmod(target_file, 0o777)),
    ("utime_ro", lambda: os.utime(target_file, None)),
    ("unlink_ro", lambda: os.unlink(target_file)),
    ("symlink_out", lambda: os.symlink(secret_path, os.path.join(ro_dir, "esc"))),
    ("read_secret", lambda: open(secret_path, "r").read().strip()),
    ("write_stage", lambda: open(os.path.join(stage_dir, "stage_out.txt"), "w").write("STAGE_OK")),
]:
    try:
        v = fn()
        res[name] = ("OK", str(v))
    except OSError as exc:
        res[name] = ("ERR", exc.errno, type(exc).__name__)
print(json.dumps(res))
"""


def test_e2_r_target_ro_r_stage_rw_and_ungranted_hidden_with_negative_control(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _init_repo(tmp_path)
    before = _tree_digest(repo)

    ro_dir = tmp_path / "ro_target"
    ro_dir.mkdir()
    (ro_dir / "app.py").write_text("SAFE\n", encoding="utf-8")
    stage_dir = tmp_path / "stage"
    stage_dir.mkdir()
    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP_SECRET_CRED\n", encoding="utf-8")

    # Attack under real kernel confinement (ro_bind on target_ro, rw on stage)
    prof = Profile(ro=(str(ro_dir),), ro_bind=(str(ro_dir),), rw=(str(stage_dir),), net=False)
    cp = run_confined([sys.executable, "-I", "-c", _FS_PROBE, str(ro_dir), str(stage_dir), str(secret)], prof, timeout=30)
    assert cp.returncode == 0, cp.stderr
    confined = json.loads(cp.stdout.strip().splitlines()[-1])

    for key in ("open_write", "create_sibling", "chmod_ro", "utime_ro", "unlink_ro", "symlink_out", "read_secret"):
        assert confined[key][0] == "ERR", (key, confined)
    assert confined["write_stage"][0] == "OK", confined
    assert (ro_dir / "app.py").read_text(encoding="utf-8") == "SAFE\n"
    assert (stage_dir / "stage_out.txt").read_text(encoding="utf-8") == "STAGE_OK"

    # Also verify real run_worker seam preserves R_target while confining worker writes to R_stage
    host = LocalHostState(tmp_path / "state")
    snaps = LocalSnapshotService(HardenedGitRead(), root=tmp_path / "snaps", cleanup_on_exit=False)
    try:
        worker_script = (
            "import os, pathlib; "
            "t = pathlib.Path(os.environ['HLITH_TARGET']) / 'app.py'; "
            "s = pathlib.Path(os.environ['HLITH_STAGE']) / 'new.txt'; "
            "s.write_text('worker_ok'); "
            "open(t, 'a').write('ESCAPE')"
        )
        wr = run_worker(
            repo,
            [sys.executable, "-I", "-c", worker_script],
            host_state=host,
            snapshot_service=snaps,
        )
        assert wr.worker_returncode != 0
        assert _tree_digest(repo) == before
    finally:
        snaps.close()

    # Negative control: identical probe WITHOUT confinement detects writable tree & secret read
    unconf_ro = tmp_path / "unconf_target"
    unconf_ro.mkdir()
    (unconf_ro / "app.py").write_text("SAFE\n", encoding="utf-8")
    unconf_stage = tmp_path / "unconf_stage"
    unconf_stage.mkdir()
    neg = subprocess.run(
        [sys.executable, "-I", "-c", _FS_PROBE, str(unconf_ro), str(unconf_stage), str(secret)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
    assert unconfined["open_write"][0] == "OK"
    assert unconfined["chmod_ro"][0] == "OK"
    assert unconfined["read_secret"] == ["OK", "TOP_SECRET_CRED"]


# ---------------------------------------------------------------------------
# 2. Namespace, mount, capabilities, and /proc isolation
# ---------------------------------------------------------------------------

_NS_PROBE = r"""
import ctypes, json, os
libc = ctypes.CDLL(None, use_errno=True)
mount_rc = libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, None)
mount_err = ctypes.get_errno() if mount_rc != 0 else 0
pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
status = {}
with open("/proc/self/status", "r", encoding="utf-8") as fh:
    for ln in fh:
        k, _, v = ln.partition(":")
        if k in ("NoNewPrivs", "CapEff", "CapBnd"):
            status[k] = v.strip()
print(json.dumps({
    "mount_rc": mount_rc,
    "mount_err": mount_err,
    "pid_count": len(pids),
    "status": status,
}))
"""


def test_e2_namespace_mount_cap_and_proc_isolation_with_negative_control(tmp_path: Path):
    stage = tmp_path / "stage"
    stage.mkdir()
    prof = Profile(rw=(str(stage),), net=False)
    cp = run_confined([sys.executable, "-I", "-c", _NS_PROBE], prof, timeout=30)
    assert cp.returncode == 0, cp.stderr
    confined = json.loads(cp.stdout.strip().splitlines()[-1])

    assert confined["mount_rc"] == -1
    assert confined["status"]["NoNewPrivs"] == "1"
    assert int(confined["status"]["CapEff"], 16) == 0
    assert int(confined["status"]["CapBnd"], 16) == 0
    assert confined["pid_count"] <= 4, confined

    # Negative control: unconfined process has NoNewPrivs == 0 and sees host PIDs in /proc
    neg = subprocess.run([sys.executable, "-I", "-c", _NS_PROBE], capture_output=True, text=True, check=True, timeout=30)
    unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
    assert unconfined["status"]["NoNewPrivs"] == "0"
    assert unconfined["pid_count"] > confined["pid_count"]


# ---------------------------------------------------------------------------
# 3. Inherited FD escape and special-file (FIFO / UNIX socket) rendezvous denial
# ---------------------------------------------------------------------------

_FD_AND_SPECIAL_PROBE = r"""
import json, os, socket, sys
fd_num, rw_dir = int(sys.argv[1]), sys.argv[2]
out = {}
try:
    out["fd_read"] = ("OK", os.read(fd_num, 64).decode("utf-8", "replace"))
except OSError as exc:
    out["fd_read"] = ("ERR", exc.errno, type(exc).__name__)
try:
    os.mkfifo(os.path.join(rw_dir, "evil.fifo"))
    out["mkfifo"] = "OK"
except OSError as exc:
    out["mkfifo"] = ("ERR", exc.errno, type(exc).__name__)
sock_path = os.path.join(rw_dir, "evil.sock")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(sock_path)
    out["unix_bind"] = "OK"
except OSError as exc:
    out["unix_bind"] = ("ERR", exc.errno, type(exc).__name__)
finally:
    s.close()
print(json.dumps(out))
"""


def test_e2_fd_escape_and_rendezvous_special_file_denied_with_negative_control(tmp_path: Path):
    stage = tmp_path / "stage"
    stage.mkdir()
    secret_f = tmp_path / "secret_fd.txt"
    secret_f.write_text("HOST_FD_SECRET", encoding="utf-8")

    # vet_grants also rejects a pre-existing FIFO inside a granted tree
    ro_bad = tmp_path / "ro_with_fifo"
    ro_bad.mkdir()
    os.mkfifo(ro_bad / "preexisting.fifo")
    with pytest.raises(GrantError, match="special file"):
        run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(ro_bad),), rw=(str(stage),)), timeout=30)

    fd = os.open(secret_f, os.O_RDONLY)
    try:
        os.set_inheritable(fd, True)
        # run_confined closes FDs >= 3 AND Landlock strips MAKE_FIFO / MAKE_SOCK from rw
        cp = run_confined(
            [sys.executable, "-I", "-c", _FD_AND_SPECIAL_PROBE, str(fd), str(stage)],
            Profile(rw=(str(stage),), net=False),
            timeout=30,
        )
        assert cp.returncode == 0, cp.stderr
        confined = json.loads(cp.stdout.strip().splitlines()[-1])
        assert confined["fd_read"][0] == "ERR"
        assert confined["mkfifo"][0] == "ERR"
        assert confined["unix_bind"][0] == "ERR"

        # Negative control: unconfined child with pass_fds reads secret & creates FIFO/socket
        unconf_rw = tmp_path / "unconf_rw"
        unconf_rw.mkdir()
        neg = subprocess.run(
            [sys.executable, "-I", "-c", _FD_AND_SPECIAL_PROBE, str(fd), str(unconf_rw)],
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
        assert unconfined["fd_read"] == ["OK", "HOST_FD_SECRET"]
        assert unconfined["mkfifo"] == "OK"
        assert unconfined["unix_bind"] == "OK"
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 4. Grandchild subprocess inheritance + host-state exclusion
# ---------------------------------------------------------------------------

_SUBPROC_PROBE = r"""
import json, subprocess, sys
ro_dir, secret_path = sys.argv[1], sys.argv[2]
child_code = "\n".join([
    "import json, os, sys",
    "out = {}",
    "out['nnp'] = [ln.split(':', 1)[1].strip() for ln in open('/proc/self/status') if ln.startswith('NoNewPrivs:')][0]",
    "try:",
    "    open(sys.argv[1], 'a').write('X')",
    "    out['w'] = 'OK'",
    "except OSError as e:",
    "    out['w'] = type(e).__name__",
    "try:",
    "    out['s'] = open(sys.argv[2]).read().strip()",
    "except OSError as e:",
    "    out['s'] = type(e).__name__",
    "print(json.dumps(out))",
])
cp = subprocess.run([sys.executable, "-I", "-c", child_code, ro_dir + "/app.py", secret_path], capture_output=True, text=True, check=True)
print(cp.stdout.strip())
"""


def test_e2_subprocess_inheritance_and_host_state_exclusion_with_negative_control(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "hlith_state"
    state_dir.mkdir()
    monkeypatch.setenv("HLITH_STATE_DIR", str(state_dir))
    LocalHostState(state_dir)

    ro_dir = tmp_path / "ro_target"
    ro_dir.mkdir()
    (ro_dir / "app.py").write_text("SAFE\n", encoding="utf-8")
    stage = tmp_path / "stage"
    stage.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET_SUBPROC\n", encoding="utf-8")

    # Host state directory (or ancestor) must be rejected before spawning
    with pytest.raises(GrantError, match="host state root"):
        run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(state_dir),), rw=(str(stage),)), timeout=30)
    with pytest.raises(GrantError, match="host state root"):
        run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(tmp_path),), rw=(str(stage),)), timeout=30)

    # Grandchild spawned inside confined parent inherits Landlock + mountns + NoNewPrivs
    cp = run_confined(
        [sys.executable, "-I", "-c", _SUBPROC_PROBE, str(ro_dir), str(secret)],
        Profile(ro=(str(ro_dir),), ro_bind=(str(ro_dir),), rw=(str(stage),), net=False),
        timeout=30,
    )
    assert cp.returncode == 0, cp.stderr
    confined = json.loads(cp.stdout.strip().splitlines()[-1])
    assert confined["nnp"] == "1"
    assert confined["w"] != "OK"
    assert confined["s"] != "SECRET_SUBPROC"

    # Negative control: unconfined parent spawns grandchild that reads secret & sees NoNewPrivs == 0
    neg = subprocess.run([sys.executable, "-I", "-c", _SUBPROC_PROBE, str(ro_dir), str(secret)], capture_output=True, text=True, check=True, timeout=30)
    unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
    assert unconfined["nnp"] == "0"
    assert unconfined["s"] == "SECRET_SUBPROC"


# ---------------------------------------------------------------------------
# 5. Network isolation (TCP/UDP + abstract UNIX socket scope)
# ---------------------------------------------------------------------------

_NET_PROBE = r"""
import json, socket, sys
port, abs_name = int(sys.argv[1]), sys.argv[2]
out = {}
for name, fn in [
    ("tcp_connect", lambda: _try_tcp_connect(port)),
    ("tcp_bind", lambda: _try_tcp_bind()),
    ("udp_connect", lambda: _try_udp(port)),
    ("abstract_unix", lambda: _try_abs(abs_name)),
]:
    pass
"""

_NET_PROBE_CODE = r"""
import json, socket, sys
port, abs_name = int(sys.argv[1]), sys.argv[2]
out = {}

s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.settimeout(1.0)
try:
    s1.connect(("127.0.0.1", port))
    out["tcp_connect"] = ("OK", s1.recv(32).decode("utf-8", "replace"))
except OSError as exc:
    out["tcp_connect"] = ("ERR", exc.errno, type(exc).__name__)
finally:
    s1.close()

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s2.bind(("127.0.0.1", 0))
    out["tcp_bind"] = "OK"
except OSError as exc:
    out["tcp_bind"] = ("ERR", exc.errno, type(exc).__name__)
finally:
    s2.close()

s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s3.sendto(b"hi", ("127.0.0.1", port))
    out["udp_send"] = "OK"
except OSError as exc:
    out["udp_send"] = ("ERR", exc.errno, type(exc).__name__)
finally:
    s3.close()

s4 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s4.settimeout(1.0)
try:
    s4.connect("\0" + abs_name)
    out["abstract_unix"] = ("OK", s4.recv(32).decode("utf-8", "replace"))
except OSError as exc:
    out["abstract_unix"] = ("ERR", exc.errno, type(exc).__name__)
finally:
    s4.close()

print(json.dumps(out))
"""


def test_e2_network_and_abstract_unix_denied_with_negative_control(tmp_path: Path):
    stage = tmp_path / "stage"
    stage.mkdir()
    abs_name = f"hlith-e2-probe-{os.getpid()}-{int(time.time() * 1000)}"

    tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_srv.bind(("127.0.0.1", 0))
    tcp_srv.listen(4)
    port = tcp_srv.getsockname()[1]

    abs_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abs_srv.bind("\0" + abs_name)
    abs_srv.listen(4)

    stop = threading.Event()

    def _serve(srv: socket.socket) -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.sendall(b"HOST_REACHED")

    t1 = threading.Thread(target=_serve, args=(tcp_srv,), daemon=True)
    t2 = threading.Thread(target=_serve, args=(abs_srv,), daemon=True)
    t1.start()
    t2.start()
    try:
        cp = run_confined(
            [sys.executable, "-I", "-c", _NET_PROBE_CODE, str(port), abs_name],
            Profile(rw=(str(stage),), net=False),
            timeout=30,
        )
        assert cp.returncode == 0, cp.stderr
        confined = json.loads(cp.stdout.strip().splitlines()[-1])
        for k in ("tcp_connect", "tcp_bind", "udp_send", "abstract_unix"):
            assert confined[k][0] == "ERR", (k, confined)

        # Negative control: unconfined process reaches both host TCP and abstract UNIX listeners
        neg = subprocess.run(
            [sys.executable, "-I", "-c", _NET_PROBE_CODE, str(port), abs_name],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
        assert unconfined["tcp_connect"] == ["OK", "HOST_REACHED"]
        assert unconfined["tcp_bind"] == "OK"
        assert unconfined["abstract_unix"] == ["OK", "HOST_REACHED"]
    finally:
        stop.set()
        tcp_srv.close()
        abs_srv.close()
        t1.join(timeout=2)
        t2.join(timeout=2)


# ---------------------------------------------------------------------------
# 6. Credential / environment scrubbing on real worker seam
# ---------------------------------------------------------------------------

def test_e2_worker_credential_scrubbing_with_negative_control(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    creds = {
        "OPENAI_API_KEY": "sk-test-e2-openai-secret",
        "ANTHROPIC_API_KEY": "sk-ant-e2-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-e2-secret-key",
        "GITHUB_TOKEN": "ghp_e2testsecrettoken",
    }
    for k, v in creds.items():
        monkeypatch.setenv(k, v)

    repo = _init_repo(tmp_path)
    host = LocalHostState(tmp_path / "state")
    snaps = LocalSnapshotService(HardenedGitRead(), root=tmp_path / "snaps", cleanup_on_exit=False)
    try:
        probe = (
            "import json, os, pathlib; "
            "dump = pathlib.Path(os.environ['HLITH_STAGE']) / 'env_seen.txt'; "
            "dump.write_text(json.dumps(dict(os.environ))); "
            "print(json.dumps(sorted(k for k in os.environ)))"
        )
        wr = run_worker(
            repo,
            [sys.executable, "-I", "-c", probe],
            host_state=host,
            snapshot_service=snaps,
        )
        assert wr.worker_returncode == 0
        for k, v in creds.items():
            assert k not in wr.effect.unified_diff and v not in wr.effect.unified_diff
            assert k not in wr.worker_stderr and v not in wr.worker_stderr
    finally:
        snaps.close()

    # Negative control: unconfined subprocess inherits every secret env var
    neg = subprocess.run(
        [sys.executable, "-I", "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    seen = json.loads(neg.stdout)
    for k, v in creds.items():
        assert seen.get(k) == v


# ---------------------------------------------------------------------------
# 7. Virtual allocation cap well under 4 GiB scope (no 1 TB control)
# ---------------------------------------------------------------------------

_ALLOC_PROBE = r"""
import json, mmap, resource, sys
mb = int(sys.argv[1])
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
try:
    m = mmap.mmap(-1, mb * 1024 * 1024)
    m.close()
    res = "ALLOCATED"
except (OSError, MemoryError) as exc:
    res = f"DENIED:{type(exc).__name__}"
print(json.dumps({"soft": soft, "hard": hard, "result": res}))
"""


def test_e2_allocation_cap_under_4g_scope_with_negative_control(tmp_path: Path):
    stage = tmp_path / "stage"
    stage.mkdir()

    # Production Profile enforces DEFAULT_AS_LIMIT_BYTES (<= 8 GiB virtual ceiling)
    cp_default = run_confined(
        [sys.executable, "-I", "-c", "import json, resource; print(json.dumps(resource.getrlimit(resource.RLIMIT_AS)))"],
        Profile(rw=(str(stage),), net=False),
        timeout=30,
    )
    assert cp_default.returncode == 0, cp_default.stderr
    soft, hard = json.loads(cp_default.stdout.strip().splitlines()[-1])
    assert soft != resource.RLIM_INFINITY and soft <= 8 * 1024**3
    assert hard == soft

    # Launcher with explicit 256 MiB AS limit rejects a 512 MiB zero-page mmap (well inside 4G scope)
    spec = Profile(rw=(str(stage),), net=False).spec()
    spec["as_limit_bytes"] = 256 * 1024 * 1024
    own = tmp_path / "own"
    own.mkdir()
    cp_cap = subprocess.run(
        [sys.executable, "-I", confinement._LAUNCHER, json.dumps({**spec, "root_parent": str(own)}), "--",
         sys.executable, "-I", "-c", _ALLOC_PROBE, "512"],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        timeout=30,
    )
    capped = json.loads(cp_cap.stdout.strip().splitlines()[-1])
    assert capped["soft"] == 256 * 1024 * 1024
    assert capped["result"].startswith("DENIED:"), capped

    # Negative control: without as_limit_bytes cap, reserving 512 MiB virtual pages succeeds (~0 KB RSS)
    neg = subprocess.run(
        [sys.executable, "-I", "-c", _ALLOC_PROBE, "512"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    unconfined = json.loads(neg.stdout.strip().splitlines()[-1])
    assert unconfined["result"] == "ALLOCATED", unconfined
