"""review / case: a lost or killed `hlith check` client must not leave the engine or its confined worker running, and the
orphaned run must read as lost/unknown (never a verdict).

Real processes: `hlith check` is started as a subprocess against a repository whose reached callable never returns, so the
engine sits in a confined differential run; the client is then SIGKILLed (uncatchable: no handler can help) and the process
table is read (zombie-aware) until the engine and every descendant are gone or a bound is hit."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")
BOUND = 25.0  # seconds from the client's death to "engine and worker gone"


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)


def _repo(root: Path) -> Path:
    r = root / "repo"
    (r / "pkg").mkdir(parents=True)
    (r / "tests").mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "pkg/__init__.py").write_text("")
    (r / "pkg/m.py").write_text("def add(a, b):\n    return a + b\n")
    (r / "tests/test_m.py").write_text("from pkg.m import add\n\ndef test_add():\n    assert add(1, 2) == 3\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    # a reached callable that never returns (pure spin: the per-call alarm is what ends it)
    (r / "pkg/m.py").write_text("def add(a, b):\n    while True:\n        pass\n")
    return r


def _alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def _children() -> dict[int, list[int]]:
    kids: dict[int, list[int]] = {}
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                ppid = int(Path(f"/proc/{d}/stat").read_text().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
            kids.setdefault(ppid, []).append(int(d))
    return kids


def _tree(pid: int) -> list[int]:
    kids, out, todo = _children(), [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        todo.extend(kids.get(p, []))
    return out


def _find_engine(marker: str) -> int | None:
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                cmd = Path(f"/proc/{d}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if "hlith.operator.engine_cli" in cmd and marker in cmd and _alive(int(d)):
                return int(d)
    return None


@pytest.fixture(params=["client", "engine"])
def lost_client(request, tmp_path):
    """Start `hlith check`, wait until a confined worker exists under the engine, SIGKILL the client. Returns (engine_pid, tree, state)."""
    repo = _repo(tmp_path)
    state = tmp_path / "xdg"
    env = dict(os.environ, PYTHONPATH=SRC, HLITH_UI_STATE=str(state), TMPDIR=str(tmp_path))
    env.pop("HLITH_STATE_DIR", None)
    client = subprocess.Popen([sys.executable, "-m", "hlith.cli", "check", "--repo", str(repo), "--uncommitted", "--json",
                               "--artifact-out", str(tmp_path / "a.json")], env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    tree: list[int] = []
    engine = None
    try:
        end = time.monotonic() + 150
        while time.monotonic() < end and client.poll() is None:
            engine = engine or _find_engine(str(repo))
            if engine:
                tree = _tree(engine)
                names = [Path(f"/proc/{p}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace") if os.path.exists(f"/proc/{p}/cmdline") else "" for p in tree]
                if any("confine_exec" in n or "-I -c" in n for n in names):  # a confined run is in flight
                    break
            time.sleep(0.5)
        assert engine and client.poll() is None, "the engine never reached a confined run (fixture problem)"
        tree = _tree(engine)
        if request.param == "client":
            os.kill(client.pid, signal.SIGKILL)  # the engine's supervisor dies
            client.wait()
        else:  # the engine itself is SIGKILLed: its confined launcher/worker must still end (launcher-side supervisor watch)
            os.kill(engine, signal.SIGKILL)
        yield engine, tree, state
    finally:
        for p in sorted(set(tree + (_tree(engine) if engine and _alive(engine) else []))):
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.kill(client.pid, signal.SIGKILL)
        except OSError:
            pass


def test_sigkill_leaves_no_engine_and_no_worker(lost_client):
    engine, tree, _state = lost_client
    assert len(tree) >= 2, f"expected the engine and a confined launcher/worker, saw {tree}"
    end = time.monotonic() + BOUND
    while time.monotonic() < end and any(_alive(p) for p in tree):
        time.sleep(0.25)
    left = [p for p in tree if _alive(p)]
    assert not left, f"{len(left)} process(es) still running {BOUND}s after the client was SIGKILLed: " + ", ".join(
        f"{p}:{Path(f'/proc/{p}/cmdline').read_bytes().replace(chr(0).encode(), b' ').decode(errors='replace')[:70]}" for p in left)


def test_lost_client_run_is_never_a_verdict(lost_client):
    engine, tree, state = lost_client
    end = time.monotonic() + BOUND
    while time.monotonic() < end and any(_alive(p) for p in tree):
        time.sleep(0.25)
    runs = sorted(Path(state).glob("**/launch-*"))
    assert runs, "the killed client's launch folder should still exist as evidence"
    for d in runs:
        assert not (d / "out.json").exists(), "a killed run must not carry an artifact/verdict"
        out = subprocess.run([sys.executable, "-m", "hlith.cli", "inspect", str(d)], env=dict(os.environ, PYTHONPATH=SRC, HLITH_UI_STATE=str(state)),
                             capture_output=True, text=True, timeout=60)
        text = (out.stdout + out.stderr).upper()
        assert "LOST" in text and "WITHOUT A RECORDED DECISION" in text, text[:400]
        for word in ("LANDED", "HELD", "REFUSED", "REFUTED", "VERIFIED"):
            assert word not in text, f"inspect of a lost run shows a decision word {word}: {text[:400]}"
