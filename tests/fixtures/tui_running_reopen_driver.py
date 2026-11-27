"""One bounded real-PTY UI run, three Running captures, detach, then History -> Verdict.

The caller supplies a fresh output directory outside any repository. This driver
starts exactly one engine run. The foreign id must come from another real launch.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import select
import signal
import shutil
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from tui_running_reopen import prepare  # noqa: E402
from _vt import Screen  # noqa: E402
from hlith.operator.tui import launch  # noqa: E402


def _set_size(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class PTY:
    def __init__(self, repo: Path, state: Path, rows: int, cols: int, output: Path | None = None,
                 fake_support: Path | None = None, interpreter: Path | None = None):
        self.master, slave = pty.openpty()
        self.rows, self.cols = rows, cols
        self.output = output
        self.interpreter = Path(interpreter or sys.executable)
        self.executable_receipt = (output or state) / f"tui-child-executable-{rows}x{cols}.txt"
        _set_size(slave, rows, cols)
        self.raw = bytearray()
        self.env = {
            **os.environ,
            "TERM": "xterm-256color",
            "ESCDELAY": "25",
            "LINES": str(rows),
            "COLUMNS": str(cols),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join([str(fake_support), str(ROOT / "src")]) if fake_support else str(ROOT / "src"),
            "HLITH_UI_STATE": str(state),
            "HLITH_STATE_DIR": str(state),
            "XDG_STATE_HOME": str(state),
            "HLITH_UI_FRAMES": str((output or state) / "app-frames.txt"),
            "HLITH_TUI_EXECUTABLE_RECEIPT": str(self.executable_receipt),
            "GIT_CEILING_DIRECTORIES": str(repo.parent),
        }
        if fake_support is not None and (fake_support / "source-launch").is_dir():
            self.env["HLITH_TUI_FAKE_SOURCE_LAUNCH"] = str(fake_support / "source-launch")
            self.env["HLITH_TUI_FAKE_LIFETIME"] = "18"
        self.proc = subprocess.Popen(
            [str(self.interpreter), "-B", "-m", "hlith.operator.tui", "--repo", str(repo)],
            cwd=repo, stdin=slave, stdout=slave, stderr=slave, env=self.env,
            start_new_session=True, close_fds=True,
        )
        os.close(slave)

    def drain(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], min(0.1, max(0.0, end - time.monotonic())))
            if not ready:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return
            if not data:
                return
            self.raw.extend(data)

    def wait_text(self, text: str, seconds: float = 20) -> str:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.drain(0.1)
            shown = Screen(self.rows, self.cols).feed(bytes(self.raw)).text()
            flat = "\n".join(shown)
            if text.lower() in flat.lower():
                self._save_marker(text, flat)
                return flat
            if self.proc.poll() is not None:
                raise RuntimeError(f"UI exited {self.proc.returncode} before {text!r}: {flat}")
        flat = "\n".join(Screen(self.rows, self.cols).feed(bytes(self.raw)).text())
        if self.output is not None:
            (self.output / "pty-timeout.txt").write_text(flat + "\n", encoding="utf-8")
            (self.output / "pty-timeout.ansi").write_bytes(bytes(self.raw))
            self._save_marker(f"TIMEOUT waiting for {text}", flat)
        raise TimeoutError(f"timed out waiting for {text!r}: {flat}")

    def _save_marker(self, marker: str, flat: str) -> None:
        if self.output is None:
            return
        index = len(list(self.output.glob("pty-frame-*.txt"))) + 1
        safe = "".join(c if c.isalnum() else "_" for c in marker).strip("_")[:48] or "frame"
        stem = f"pty-frame-{index:02d}-{safe}"
        (self.output / f"{stem}.txt").write_text(flat + "\n", encoding="utf-8")
        (self.output / f"{stem}.ansi").write_bytes(bytes(self.raw))

    def key(self, value: bytes, settle: float = 0.4) -> None:
        os.write(self.master, value)
        self.drain(settle)

    def resize(self, rows: int, cols: int) -> None:
        self.rows, self.cols = rows, cols
        _set_size(self.master, rows, cols)
        self.env["LINES"], self.env["COLUMNS"] = str(rows), str(cols)
        os.kill(self.proc.pid, signal.SIGWINCH)
        self.raw.clear()
        self.drain(1.0)

    def capture(self, output: Path, label: str) -> dict:
        screen = Screen(self.rows, self.cols).feed(bytes(self.raw))
        text = "\n".join(screen.text())
        if "checking" not in text.lower() or "not a verdict" not in text.lower():
            raise RuntimeError(f"{label}: screen is not visibly Running:\n{text}")
        (output / f"running-{label}.txt").write_text(text + "\n", encoding="utf-8")
        (output / f"running-{label}.ansi").write_bytes(bytes(self.raw))
        cells = [[[c.ch, c.fg, c.bg, c.bold, c.dim, c.rev] for c in row] for row in screen.grid]
        (output / f"running-{label}.cells.json").write_text(json.dumps(cells), encoding="utf-8")
        return {"size": [self.rows, self.cols], "running_visible": True, "sgr_seen": screen.sgr_seen,
                "unhandled_vt": sorted(screen.unhandled), "transcript": f"running-{label}.txt"}

    def close(self) -> int:
        if self.proc.poll() is None:
            self.proc.terminate()
        rc = self.proc.wait(timeout=5)
        self.master and os.close(self.master)
        return rc


def _launch_dirs(state: Path, repo: Path) -> list[Path]:
    found = []
    for path in state.rglob("launch-*"):
        if not path.is_dir() or path.is_symlink():
            continue
        try:
            meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if Path(str(meta.get("source_repo", ""))).resolve() == repo.resolve():
            found.append(path)
    return found


def _save_verdict_transcript(output: Path, driver: PTY, label: str, predicate: str) -> str:
    flat = driver.wait_text(predicate, 30)
    (output / f"verdict-{label}.txt").write_text(flat + "\n", encoding="utf-8")
    (output / f"verdict-{label}.ansi").write_bytes(bytes(driver.raw))
    return flat


def _install_tui_support(output: Path, source_launch: Path | None, lifetime: int = 18) -> Path:
    """Write TUI child sys.executable and optionally replace launch.start for dry runs."""
    support = output / "tui-support"
    support.mkdir()
    source = r'''import os, sys
from pathlib import Path
Path(os.environ["HLITH_TUI_EXECUTABLE_RECEIPT"]).write_text(sys.executable + "\n", encoding="utf-8")
'''
    if source_launch is not None:
        source_launch = Path(source_launch).resolve(strict=True)
        if not (source_launch / "engine-run.json").is_file() or not (source_launch / "out.json").is_file():
            raise FileNotFoundError(f"completed source launch is incomplete: {source_launch}")
        shutil.copytree(source_launch, support / "source-launch")
        source += r'''import json, os, shutil, subprocess, sys, time
from pathlib import Path
from hlith.operator.tui import launch as _launch
_source = Path(os.environ["HLITH_TUI_FAKE_SOURCE_LAUNCH"])
def _fake_start(p, *, cwd=None):
    p.run_dir.mkdir(parents=True, exist_ok=True)
    link = json.loads((_source / "engine-run.json").read_text(encoding="utf-8"))
    run_id = link["run_id"]
    source_engine = Path(link["run_dir"]).resolve(strict=True)
    target_engine = p.run_dir.parent / run_id
    if not target_engine.exists():
        shutil.copytree(source_engine, target_engine)
    (p.run_dir / "out.json").write_bytes((_source / "out.json").read_bytes())
    (p.run_dir / "engine-run.json").write_text(json.dumps({"run_id": run_id, "run_dir": str(target_engine)}), encoding="utf-8")
    helper = "import pathlib,sys,time; time.sleep(int(sys.argv[2])); pathlib.Path(sys.argv[1]).write_text('0')"
    delay = int(os.environ.get("HLITH_TUI_FAKE_LIFETIME", "18"))
    proc = subprocess.Popen([sys.executable, "-c", helper, str(p.run_dir / "rc"), str(delay)], start_new_session=True, close_fds=True)
    meta = {"run_id": p.run_id, "started": time.time(), "pid": proc.pid,
            "pid_starttime": _launch._starttime(proc.pid), "argv": p.argv,
            "source_repo": str(p.source_repo), "clone": str(p.clone), "state": "started",
            "base_rev": p.base_rev, "label": p.label}
    (p.run_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return meta
_launch.start = _fake_start
'''
    (support / "sitecustomize.py").write_text(source, encoding="utf-8")
    return support


def _verify_foreign_run_id(foreign_run_id: str, source_launch: Path | None) -> str | None:
    if source_launch is None:
        return None
    source_launch = Path(source_launch).resolve(strict=True)
    link = json.loads((source_launch / "engine-run.json").read_text(encoding="utf-8"))
    artifact = json.loads((source_launch / "out.json").read_text(encoding="utf-8"))
    linked_id = link.get("run_id")
    artifact_id = (artifact.get("run") or {}).get("run_id")
    if linked_id != foreign_run_id or artifact_id != foreign_run_id:
        raise ValueError("foreign RunId is not backed by the selected completed launch and its artifact")
    return str(source_launch)


def _project_python_preflight(project_python: Path) -> dict:
    project_python = Path(project_python).expanduser()
    if not project_python.is_file():
        raise FileNotFoundError(f"project interpreter not found: {project_python}")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    executable = subprocess.run([str(project_python), "-B", "-c", "import sys; print(sys.executable)"],
                                cwd=ROOT, env=env, check=True, text=True, capture_output=True).stdout.strip()
    command = [str(project_python), "-B", "-c", "import hlith.effect.engine"]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"engine import preflight failed rc={result.returncode}: {result.stderr[-1000:]}")
    if Path(executable).absolute() != project_python.absolute():
        raise RuntimeError(f"TUI interpreter mismatch: requested {project_python}, sys.executable {executable}")
    return {"tui_project_interpreter": executable, "engine_import_command": command,
            "engine_import_returncode": result.returncode, "engine_import_stdout": result.stdout,
            "engine_import_stderr": result.stderr}


def run(output: Path, foreign_run_id: str, fake_source_launch: Path | None = None,
        foreign_source_launch: Path | None = None, project_python: Path | None = None) -> dict:
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory must be fresh and empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    seed, repo = prepare(output / "fixture")
    state = output / "state"
    state.mkdir()
    if project_python is None:
        raise ValueError("--project-python is required; never use Python selected from PATH")
    project_python = Path(project_python).expanduser()
    python_preflight = _project_python_preflight(project_python)
    fake_support = _install_tui_support(output, fake_source_launch)
    foreign_source = _verify_foreign_run_id(foreign_run_id, foreign_source_launch)
    summary: dict = {"source_sha": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                                        check=True, text=True, capture_output=True).stdout.strip(),
                     "seed": str(seed), "repo": str(repo), "state": str(state), "foreign_run_id": foreign_run_id,
                     "foreign_run_id_source_launch": foreign_source,
                     "python_preflight": python_preflight, "driver_sys_executable": sys.executable,
                     "mock_mode": fake_source_launch is not None, "running_captures": []}
    ui = PTY(repo, state, 24, 80, output, fake_support, project_python)
    try:
        offer = ui.wait_text("change to review", 20)
        summary["tui_child_sys_executable"] = ui.executable_receipt.read_text(encoding="utf-8").strip()
        if Path(summary["tui_child_sys_executable"]).absolute() != project_python.absolute():
            raise RuntimeError("TUI child sys.executable differs from the explicit project interpreter")
        (output / "offer-before-run.txt").write_text(offer + "\n", encoding="utf-8")
        (output / "offer-before-run.ansi").write_bytes(bytes(ui.raw))
        ui.key(b"\r")
        ui.wait_text("select a change", 10)
        ui.key(b"\r")
        ui.wait_text("claim", 10)
        for _ in range(8):
            current = "\n".join(Screen(ui.rows, ui.cols).feed(bytes(ui.raw)).text())
            if ("the command end is visible. run enables after the safety pause." in current.lower()
                    or "the complete argv was shown. enter starts exactly this command" in current.lower()):
                break
            ui.key(b"\x1b[6~")  # xterm PgDn: expose the next part of the exact command for review
            ui.drain(0.2)
        else:
            raise RuntimeError("PgDn did not expose the exact command end")
        if "the command end is visible. run enables after the safety pause." in current.lower():
            ui.wait_text("run enables after the safety pause", 5)
            ui.drain(0.6)
        ui.wait_text("the complete argv was shown", 5)
        current = "\n".join(Screen(ui.rows, ui.cols).feed(bytes(ui.raw)).text())
        if "run independent check" not in current.lower():
            raise RuntimeError(f"Run did not enable after the command dwell:\n{current}")
        ui.drain(0.2)
        ui.key(b"\r")
        ui.wait_text("checking", 45)
        ui.drain(0.7)
        summary["running_captures"].append(ui.capture(output, "80x24"))
        ui.resize(30, 100)
        ui.wait_text("checking", 10)
        summary["running_captures"].append(ui.capture(output, "100x30"))
        ui.resize(44, 160)
        ui.wait_text("checking", 10)
        summary["running_captures"].append(ui.capture(output, "160x44"))
        ui.key(b"q")
        ui.wait_text("the check keeps running", 5)
        ui.key(b"\x1b[B")  # choose Detach in the quit overlay
        overlay = "\n".join(Screen(ui.rows, ui.cols).feed(bytes(ui.raw)).text())
        if "[ Detach ]" not in overlay or "›[ Detach ]" not in overlay:
            raise RuntimeError(f"Detach was not the focused quit action:\n{overlay}")
        ui._save_marker("detach focused", overlay)
        ui.key(b"\r")
        summary["detach_ui_returncode"] = ui.proc.wait(timeout=5)
    finally:
        if ui.proc.poll() is None:
            ui.close()

    launch_dirs = _launch_dirs(state, repo)
    if len(launch_dirs) != 1:
        raise RuntimeError(f"expected exactly one UI launch, found {[p.name for p in launch_dirs]}")
    launch_dir = launch_dirs[0]
    summary["launch_dir"] = str(launch_dir)
    summary["launch_id"] = launch_dir.name
    deadline = time.monotonic() + 115
    engine_id = None
    status = None
    while time.monotonic() < deadline:
        engine_id = launch.engine_run_id(launch_dir)
        status = launch.status(launch_dir)
        if status and status.get("state") in ("finished", "clone-failed", "lost"):
            break
        time.sleep(0.5)
    summary["launch_status"] = status
    if not status or status.get("state") != "finished":
        raise TimeoutError(f"launch did not finish within bound: {status}")
    engine_argv = ((status.get("meta") or {}).get("argv") or status.get("argv") or [])
    engine_interpreter = engine_argv[0] if engine_argv else None
    if not engine_interpreter or Path(engine_interpreter).absolute() != project_python.absolute():
        raise RuntimeError(f"engine child interpreter {engine_interpreter!r} != project venv {str(project_python)!r}")
    summary["engine_child_argv"] = engine_argv
    summary["engine_child_interpreter"] = engine_interpreter
    summary["engine_run_id"] = engine_id
    record = launch.result(launch_dir)
    summary["artifact_status"] = record.status if record else None
    summary["artifact_run_id"] = ((record.art or {}).get("run") or {}).get("run_id") if record and record.art else None
    if not engine_id or summary["artifact_run_id"] != engine_id:
        raise RuntimeError(f"artifact id {summary['artifact_run_id']!r} does not match engine RunId {engine_id!r}")
    if foreign_run_id == engine_id:
        raise RuntimeError("negative-control RunId must differ from this launch")

    artifact = launch_dir / "out.json"
    canonical = artifact.read_bytes()
    try:
        doc = json.loads(canonical.decode("utf-8"))
        doc["run"]["run_id"] = foreign_run_id
        artifact.write_text(json.dumps(doc), encoding="utf-8")
        negative = launch.result(launch_dir)
        summary["negative_control"] = {
            "foreign_run_id": foreign_run_id,
            "foreign_id_is_from_other_actual_launch": foreign_source is not None,
            "foreign_source_launch": foreign_source,
            "launch_result_status": negative.status if negative else None,
            "rejected_as_verdict": bool(negative and negative.status == "id-mismatch"),
        }
        if not summary["negative_control"]["rejected_as_verdict"]:
            raise RuntimeError(f"foreign RunId was not rejected: {summary['negative_control']}")
    finally:
        artifact.write_bytes(canonical)

    reopened = PTY(repo, state, 30, 100, output, fake_support, project_python)
    try:
        offer = reopened.wait_text("change to review", 20)
        if "running" in offer.lower():
            raise RuntimeError("reopen unexpectedly returned to a Running screen after completion")
        reopened.key(b"h")
        history = reopened.wait_text(launch_dir.name, 20)
        (output / "history-row.txt").write_text(history + "\n", encoding="utf-8")
        reopened.key(b"\r")
        verdict = _save_verdict_transcript(output, reopened, "same-run", engine_id[:8])
        if engine_id[:8] not in verdict or foreign_run_id[:8] in verdict:
            raise RuntimeError("historical Verdict did not identify only the expected engine RunId")
        summary["history_reopen"] = {"route": "Offer -> h -> History row -> Enter", "history_launch_id": launch_dir.name,
                                     "verdict_engine_run_id": engine_id, "foreign_run_id_visible": False}
        reopened.key(b"\x1b")
        offer_after_esc = _save_verdict_transcript(output, reopened, "after-esc", "change to review")
        summary["lone_esc_destination"] = "Offer"
    finally:
        if reopened.proc.poll() is None:
            reopened.key(b"q")
            reopened.wait_text("nothing is running", 5)
            reopened.key(b"\x1b[B")  # choose Quit in the Offer exit overlay
            reopened.key(b"\r")
            try:
                reopened.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                reopened.proc.terminate()
                reopened.proc.wait(timeout=5)
        os.close(reopened.master)

    summary["fixture_diff_numstat"] = subprocess.run(
        ["git", "-C", str(repo), "diff", "--numstat"], check=True, text=True, capture_output=True
    ).stdout.splitlines()
    summary["fixture_tests"] = "python -B -m unittest: passed during prepare()"
    (output / "receipt.json").write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--foreign-run-id", required=True)
    parser.add_argument("--fake-source-launch", type=Path)
    parser.add_argument("--foreign-source-launch", type=Path, required=True)
    parser.add_argument("--project-python", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.output, args.foreign_run_id, args.fake_source_launch, args.foreign_source_launch, args.project_python)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        if args.output.exists():
            for frame in sorted(args.output.glob("pty-frame-*.txt")):
                print(f"--- captured {frame.name} ---")
                print(frame.read_text(encoding="utf-8"))
            timeout_frame = args.output / "pty-timeout.txt"
            if timeout_frame.exists():
                print("--- captured timeout frame ---")
                print(timeout_frame.read_text(encoding="utf-8"))
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
