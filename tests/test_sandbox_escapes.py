# SPDX-License-Identifier: Apache-2.0
"""Real-kernel escape tests. Every attempt runs inside the confined worker and
must fail; the target tree must be byte-identical afterwards."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.sandbox import Profile, run_confined


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        h.update(f"{p.relative_to(root)}:{st.st_mode}:{st.st_size}:{st.st_mtime_ns}".encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()


@pytest.fixture()
def world(tmp_path):
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()
    (target / "a.py").write_text("x = 1\n")
    (target / "sub").mkdir()
    (target / "sub" / "b.py").write_text("y = 2\n")
    return target, stage


PROBE = r"""
import json, os, shutil, socket, subprocess, sys
T, S = sys.argv[1], sys.argv[2]
res = {}
res["open_fds"] = sorted(int(x) for x in os.listdir("/proc/self/fd") if int(x) > 2 and os.path.exists(f"/proc/self/fd/{x}") and "proc" not in os.readlink(f"/proc/self/fd/{x}"))
def attempt(name, fn):
    try:
        fn(); res[name] = "ALLOWED"
    except OSError as e:
        res[name] = "denied:" + (os.strerror(e.errno) if e.errno else str(e))
    except Exception as e:
        res[name] = "denied:" + type(e).__name__
def w(p, m="w"):
    with open(p, m) as f: f.write("pwn")
attempt("open_w_existing", lambda: w(f"{T}/a.py"))
attempt("open_w_new", lambda: w(f"{T}/new.py"))
attempt("append_existing", lambda: w(f"{T}/a.py", "a"))
attempt("truncate", lambda: os.truncate(f"{T}/a.py", 0))
attempt("unlink", lambda: os.unlink(f"{T}/a.py"))
attempt("rename_in", lambda: os.rename(f"{T}/a.py", f"{T}/c.py"))
attempt("rename_out", lambda: os.rename(f"{T}/a.py", f"{S}/a.py"))
attempt("mkdir", lambda: os.mkdir(f"{T}/d"))
attempt("symlink_in_target", lambda: os.symlink("/etc/passwd", f"{T}/ln"))
attempt("hardlink_into_stage", lambda: os.link(f"{T}/a.py", f"{S}/hl.py"))
attempt("chmod", lambda: os.chmod(f"{T}/a.py", 0o777))
attempt("utime", lambda: os.utime(f"{T}/a.py", (1, 1)))
attempt("setxattr", lambda: os.setxattr(f"{T}/a.py", "user.x", b"1"))
attempt("rmtree", lambda: shutil.rmtree(f"{T}/sub"))
attempt("shell_redirect", lambda: subprocess.run(["/bin/sh", "-c", f"echo pwn > {T}/sh.py"], check=True, capture_output=True))
attempt("dd_subprocess", lambda: subprocess.run(["/bin/sh", "-c", f"printf pwn | dd of={T}/a.py 2>/dev/null"], check=True, capture_output=True))
# mount escape: try to remount rw / umount the ro bind
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
def mnt(op):
    def f():
        r = op()
        if r != 0:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
    return f
attempt("umount_target", mnt(lambda: libc.umount2(T.encode(), 2)))
attempt("remount_rw", mnt(lambda: libc.mount(None, T.encode(), None, 32, None)))
# A bare nested userns is permitted by the kernel; the test is whether it buys
# write access: unshare user+mount ns, then try to unlock the ro bind and write.
def nested():
    pid = os.fork()
    if pid == 0:
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
            open("/proc/self/setgroups", "w").write("deny")
            open("/proc/self/uid_map", "w").write(f"0 {os.getuid()} 1")
            libc.mount(None, T.encode(), None, 32, None)           # remount rw
            libc.umount2(T.encode(), 2)                            # unlock
            w(f"{T}/a.py")                                         # write attempt
            os._exit(0)
        except BaseException:
            os._exit(1)
    _, st = os.waitpid(pid, 0)
    if os.WEXITSTATUS(st) == 0:
        return
    raise OSError(1, "Operation not permitted")
attempt("nested_userns_write_escape", nested)
def raw_proc_mem():  # /proc/self/root path trick: reach target via another name
    w(f"/proc/self/root{T}/a.py")
attempt("proc_root_alias", raw_proc_mem)
def tcp():
    s = socket.socket(); s.settimeout(1); s.connect(("127.0.0.1", 9))
attempt("tcp_connect", tcp)
# sanity: stage IS writable
try:
    w(f"{S}/ok.txt"); res["stage_write"] = "ok"
except OSError as e:
    res["stage_write"] = "BROKEN:" + str(e)
print(json.dumps(res))
"""


def test_every_escape_denied_and_target_untouched(world):
    target, stage = world
    before = tree_digest(target)
    # parent holds a write descriptor into the target; must not reach the worker
    leaked = open(target / "a.py", "r+")
    try:
        prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),))
        cp = run_confined([sys.executable, "-c", PROBE, str(target), str(stage)], prof)
    finally:
        leaked.close()
    assert cp.returncode == 0, cp.stderr
    res = json.loads(cp.stdout.strip().splitlines()[-1])
    allowed = {k: v for k, v in res.items() if v == "ALLOWED"}
    assert not allowed, f"escape paths allowed: {allowed}"
    assert res["stage_write"] == "ok"
    assert res["open_fds"] == []
    assert tree_digest(target) == before


def test_fails_closed_on_unusable_profile(world):
    target, stage = world
    prof = Profile(ro_bind=(str(target / "does-not-exist"),))
    cp = run_confined([sys.executable, "-c", "print('ran')"], prof)
    assert cp.returncode == 4
    assert "ran" not in cp.stdout


# ---- finding 23: net=False must mean no datagram path to the host either (UDP/ICMP/AF_UNIX/raw) ----
import socket as _s

NETPROBE = r"""
import json, os, socket, sys
port, port6, upath = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
res = {}
def attempt(name, fn):
    try:
        fn(); res[name] = "ALLOWED"
    except OSError as e:
        res[name] = "denied:" + (os.strerror(e.errno) if e.errno else str(e))
    except Exception as e:
        res[name] = "denied:" + type(e).__name__
def udp4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"HLITH-EXFIL4", ("127.0.0.1", port))
def udp6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.sendto(b"HLITH-EXFIL6", ("::1", port6))
def unix():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.sendto(b"HLITH-EXFIL-UNIX", upath)
def packet():
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
def icmp():
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
def dgram_icmp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP); s.sendto(b"\x08\0\0\0\0\0\0\0", ("127.0.0.1", 0))
for n, f in (("udp4", udp4), ("udp6", udp6), ("unix_dgram", unix), ("af_packet", packet), ("icmp_raw", icmp), ("icmp_dgram", dgram_icmp)):
    attempt(n, f)
try:
    res["interfaces"] = sorted(n for _, n in socket.if_nameindex())
except OSError as e:
    res["interfaces"] = "err:" + str(e)
print(json.dumps(res))
"""


def _listeners(tmp_path):
    l4 = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    l4.bind(("127.0.0.1", 0))
    l4.settimeout(0.5)
    l6 = None
    try:
        l6 = _s.socket(_s.AF_INET6, _s.SOCK_DGRAM)
        l6.bind(("::1", 0))
        l6.settimeout(0.5)
    except OSError:
        l6 = None
    up = str(tmp_path / "host.sock")
    lu = _s.socket(_s.AF_UNIX, _s.SOCK_DGRAM)
    lu.bind(up)
    lu.settimeout(0.5)
    return l4, l6, lu, up


def _received(sock):
    if sock is None:
        return None
    try:
        return sock.recvfrom(100)[0]
    except (TimeoutError, _s.timeout, BlockingIOError):
        return None


def test_net_false_blocks_every_datagram_path_to_the_host(tmp_path):
    l4, l6, lu, up = _listeners(tmp_path)
    try:
        prof = Profile(net=False)  # the host socket lives outside every granted path (outside the root)
        cp = run_confined([sys.executable, "-I", "-c", NETPROBE, str(l4.getsockname()[1]),
                           str(l6.getsockname()[1]) if l6 else "9", up], prof, timeout=60)
        assert cp.returncode == 0, cp.stderr
        res = json.loads(cp.stdout.strip().splitlines()[-1])
        # nothing may arrive on any host listener (this is the exfiltration witness)
        assert _received(l4) is None, "UDP datagram reached a host listener"
        assert _received(l6) is None, "IPv6 datagram reached a host listener"
        assert _received(lu) is None, "AF_UNIX datagram reached a host socket"
        for k in ("udp4", "udp6", "unix_dgram", "af_packet", "icmp_raw", "icmp_dgram"):
            assert res[k].startswith("denied:"), (k, res)
        # a fresh empty network namespace: no host interfaces visible (lo at most)
        assert res["interfaces"] in ([], ["lo"]), res["interfaces"]
    finally:
        for x in (l4, l6, lu):
            if x is not None:
                x.close()


# ---- finding 24, every caller: run_confined itself refuses special files in ANY granted tree ----
def _sock_in(d):
    s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    d.mkdir(exist_ok=True)
    s.bind(str(d / "leak.sock"))
    return s


@pytest.mark.parametrize("kind", ["ro", "rw", "ro_bind", "sys_prefix"])
def test_run_confined_rejects_a_socket_in_any_granted_tree(tmp_path, monkeypatch, kind):
    from hlith.sandbox import GrantError
    d = tmp_path / "grant"
    s = _sock_in(d)
    try:
        if kind == "sys_prefix":
            monkeypatch.setattr(sys, "prefix", str(d))
            prof = Profile()
        else:
            prof = Profile(**{kind: (str(d),)})
        with pytest.raises(GrantError, match="special file"):
            run_confined([sys.executable, "-I", "-c", "print(1)"], prof, timeout=30)
    finally:
        s.close()


def test_run_confined_accepts_clean_grants_and_a_fifo_is_rejected(tmp_path):
    from hlith.sandbox import GrantError
    d = tmp_path / "g"
    d.mkdir()
    (d / "a.txt").write_text("x")
    cp = run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(d),)), timeout=30)
    assert cp.returncode == 0 and cp.stdout.strip() == "1", cp.stderr
    os.mkfifo(d / "f")
    with pytest.raises(GrantError, match="special file"):
        run_confined([sys.executable, "-I", "-c", "print(1)"], Profile(ro=(str(d),)), timeout=30)
