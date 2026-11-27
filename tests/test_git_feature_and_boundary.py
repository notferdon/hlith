# SPDX-License-Identifier: Apache-2.0
"""Targeted tests for Git hardened feature probing, typed Git read errors, and host confinement boundary exit 4.

NOTE ON SIMULATED VS ACTUAL GIT:
- Tests using ``_make_git_wrapper`` explicitly simulate an unsupported Git binary by rejecting specific CLI flags
  (such as ``--attr-source`` or ``--path-format``) while delegating other invocations to the host's real ``git``.
  They prove feature-probe and fail-closed behavior without claiming an older Git version binary was executed.
- Real host Git tests run against the actual installed ``git`` on ``PATH``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.contract.errors import EXIT_BOUNDARY, BoundaryReason, Refusal, RefusalError
from hlith.hostio import confinement, git_read
from hlith.hostio.confinement import (
    ConfinedProcess,
    ConfinementBoundaryError,
    ConfinementBoundaryInfo,
    Profile,
    raise_if_confinement_boundary,
    run_confined,
)
from hlith.hostio.git_read import GitReadError, GitReadErrorKind, probe_git_features, require_supported_git
from hlith.operator import cli, gitq, presentation
from hlith.operator.tui import changes, frame, host as tui_host, repos
from hlith.operator.tui.model import ViewState

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
HOOK = ROOT / "scripts" / "agent-hook" / "hlith-agent-hook.sh"


def _real_git_bin() -> str:
    found = shutil.which("git")
    assert found, "host git binary required for tests"
    return found


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [_real_git_bin(), "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _make_repo(tmp_path: Path, name: str = "repo", *, commit: bool = True) -> Path:
    repo = tmp_path / name
    (repo / "demo").mkdir(parents=True)
    (repo / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "demo" / "calc.py").write_text(
        "def validate(x: int) -> int:\n"
        "    if x <= 0:\n"
        "        raise ValueError('must be positive')\n"
        "    return x\n",
        encoding="utf-8",
    )
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calc.py").write_text(
        "from demo.calc import validate\n\n\ndef test_pos():\n    assert validate(5) == 5\n",
        encoding="utf-8",
    )
    _git(repo, "init", "-q", "-b", "main")
    if commit:
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "base")
    return repo


def _repo_fingerprint(repo: Path) -> str:
    h = hashlib.sha256()
    for args in (("rev-parse", "HEAD"), ("status", "--porcelain", "-uall"), ("diff",)):
        h.update(_git(repo, *args).encode("utf-8"))
    for p in sorted(repo.rglob("*")):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(repo).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def _make_git_wrapper(
    tmp_path: Path,
    *,
    name: str = "fakebin",
    reject_token: str = "--attr-source",
    reject_rc: int = 129,
    reject_msg: str | None = None,
    fake_version: str | None = None,
    real_git: str | None = None,
) -> Path:
    """Create a simulated unsupported ``git`` wrapper on a dedicated bin dir (delegates allowed calls to real git)."""
    real_git = real_git or _real_git_bin()
    bin_dir = tmp_path / name
    bin_dir.mkdir(parents=True, exist_ok=True)
    wrapper = bin_dir / "git"
    msg = reject_msg or f"unknown option: {reject_token}"
    ver_block = (
        f'if [ "${{1:-}}" = "--version" ] || [ "${{2:-}}" = "--version" ]; then\n'
        f'  printf "%s\\n" "{fake_version}"\n'
        f"  exit 0\n"
        f"fi\n"
        if fake_version
        else ""
    )
    wrapper.write_text(
        "#!/bin/sh\n"
        f"{ver_block}"
        'for arg in "$@"; do\n'
        '  case "$arg" in\n'
        f'    *{reject_token}*)\n'
        f'      printf "%s\\n" "{msg}" >&2\n'
        f"      exit {reject_rc}\n"
        "      ;;\n"
        "  esac\n"
        "done\n"
        f'exec "{real_git}" "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return bin_dir


def _run_cli(args: list[str], *, env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        timeout=180,
    )


def _base_env(tmp_path: Path, *, prepend_bin: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HLITH_STATE_DIR"] = str(tmp_path / "state")
    env["HLITH_UI_STATE"] = str(tmp_path / "ui")
    if prepend_bin is not None:
        env["PATH"] = f"{prepend_bin}{os.pathsep}{env.get('PATH', '')}"
    return env


# ------------------------------------------------------------------ 1. Git feature probe & doctor (simulated vs actual)


def test_git_feature_probe_actual_supported_and_simulated_unsupported_no_version_guessing(
    tmp_path: Path, monkeypatch
) -> None:
    orig_path = os.environ.get("PATH", "")
    real_git = _real_git_bin()

    # Actual host Git passes every probed hardened feature.
    actual = probe_git_features(fresh=True)
    assert actual.ok is True, actual
    assert actual.failed_feature is None
    assert actual.executable is not None
    check_names = {c.name for c in actual.checks}
    assert {"attr-source", "status-porcelain-v1-z", "rev-parse-path-format", "diff-hardened-flags", "apply-numstat-z"} <= check_names

    # Simulated unsupported Git rejecting --attr-source EVEN while claiming "git version 2.99.0" -> MUST FAIL.
    # Proves probe checks real behavior, never guesses from version string.
    fake_attr = _make_git_wrapper(
        tmp_path,
        name="fake-attr",
        reject_token="--attr-source",
        fake_version="git version 2.99.0 (simulated)",
        real_git=real_git,
    )
    monkeypatch.setenv("PATH", f"{fake_attr}{os.pathsep}{orig_path}")
    res_attr = probe_git_features(fresh=True)
    assert res_attr.ok is False
    assert res_attr.failed_feature == "attr-source"
    assert res_attr.version == "git version 2.99.0 (simulated)"
    assert "attr-source" in res_attr.reason
    with pytest.raises(GitReadError) as exc_info:
        require_supported_git(fresh=True)
    assert exc_info.value.kind is GitReadErrorKind.UNSUPPORTED_FEATURE
    assert exc_info.value.feature == "attr-source"

    # Simulated Git rejecting --path-format -> pinpoints rev-parse-path-format.
    fake_pf = _make_git_wrapper(tmp_path, name="fake-pf", reject_token="--path-format", real_git=real_git)
    monkeypatch.setenv("PATH", f"{fake_pf}{os.pathsep}{orig_path}")
    res_pf = probe_git_features(fresh=True)
    assert res_pf.ok is False
    assert res_pf.failed_feature == "rev-parse-path-format"

    # Missing git on PATH -> fails closed cleanly.
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    res_missing = probe_git_features(fresh=True)
    assert res_missing.ok is False
    assert res_missing.failed_feature == "git-executable"


def test_doctor_reports_git_feature_failure_on_simulated_unsupported_git_and_ok_on_actual(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    # Actual host Git -> doctor Git check ok.
    proc_ok = _run_cli(["doctor", "--repo", str(repo), "--json"], env=_base_env(tmp_path / "ok"), cwd=repo)
    assert proc_ok.returncode == 0, (proc_ok.stdout, proc_ok.stderr)
    doc_ok = json.loads(proc_ok.stdout)
    checks_ok = {c["name"]: c for c in doc_ok["checks"]}
    assert checks_ok["Git"]["status"] == "ok"
    assert doc_ok["git"]["ok"] is True

    # Simulated Git rejecting --attr-source -> doctor MUST report problem (never "Git: ok").
    fake_bin = _make_git_wrapper(tmp_path, name="fake-doc-attr", reject_token="--attr-source")
    proc_bad = _run_cli(
        ["doctor", "--repo", str(repo), "--json"],
        env=_base_env(tmp_path / "bad", prepend_bin=fake_bin),
        cwd=repo,
    )
    assert proc_bad.returncode == 1, (proc_bad.stdout, proc_bad.stderr)
    doc_bad = json.loads(proc_bad.stdout)
    checks_bad = {c["name"]: c for c in doc_bad["checks"]}
    assert checks_bad["Git"]["status"] == "problem"
    assert "attr-source" in checks_bad["Git"]["detail"]
    assert doc_bad["git"]["ok"] is False
    assert doc_bad["git"]["failed_feature"] == "attr-source"

    proc_plain = _run_cli(
        ["doctor", "--repo", str(repo)],
        env=_base_env(tmp_path / "bad-plain", prepend_bin=fake_bin),
        cwd=repo,
    )
    assert proc_plain.returncode == 1
    assert "Git: problem" in proc_plain.stdout and "attr-source" in proc_plain.stdout


# ------------------------------------------------------------------ 2. Simulated unsupported Git on dirty & clean trees


def test_simulated_unsupported_git_never_fakes_no_uncommitted_change_on_dirty_or_clean_tree(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _make_repo(tmp_path)
    fake_bin = _make_git_wrapper(tmp_path, name="fake-check-attr", reject_token="--attr-source")

    # (a) Clean tree on simulated unsupported Git -> exit 4 BOUNDARY (NOT exit 2 "no uncommitted change").
    fp_clean = _repo_fingerprint(repo)
    proc_clean = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json"],
        env=_base_env(tmp_path / "st-clean", prepend_bin=fake_bin),
        cwd=repo,
    )
    assert _repo_fingerprint(repo) == fp_clean
    assert proc_clean.returncode == EXIT_BOUNDARY, (proc_clean.returncode, proc_clean.stdout, proc_clean.stderr)
    env_clean = json.loads(proc_clean.stdout)
    assert env_clean["exit_status"] == EXIT_BOUNDARY
    assert env_clean["check"]["boundary_kind"] == GitReadErrorKind.UNSUPPORTED_FEATURE.value
    assert "no uncommitted change" not in env_clean["check"]["reason"].lower()

    # (b) Dirty tree (tracked edit + untracked file) on simulated unsupported Git -> exit 4 BOUNDARY in JSON & plain.
    (repo / "demo" / "calc.py").write_text("def validate(x: int) -> int:\n    return x\n", encoding="utf-8")
    (repo / "notes.txt").write_text("untracked\n", encoding="utf-8")
    fp_dirty = _repo_fingerprint(repo)

    proc_dirty_json = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json"],
        env=_base_env(tmp_path / "st-dirty-j", prepend_bin=fake_bin),
        cwd=repo,
    )
    assert _repo_fingerprint(repo) == fp_dirty
    assert proc_dirty_json.returncode == EXIT_BOUNDARY, (proc_dirty_json.stdout, proc_dirty_json.stderr)
    env_dirty = json.loads(proc_dirty_json.stdout)
    assert env_dirty["exit_status"] == EXIT_BOUNDARY
    assert env_dirty["check"]["boundary_kind"] == GitReadErrorKind.UNSUPPORTED_FEATURE.value
    assert "attr-source" in env_dirty["check"]["reason"]

    proc_dirty_plain = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted"],
        env=_base_env(tmp_path / "st-dirty-p", prepend_bin=fake_bin),
        cwd=repo,
    )
    assert _repo_fingerprint(repo) == fp_dirty
    assert proc_dirty_plain.returncode == EXIT_BOUNDARY
    assert "hlith: boundary:" in proc_dirty_plain.stderr
    assert "no uncommitted change" not in proc_dirty_plain.stderr.lower()

    # (c) Direct Python consumers (merge_conflict_reason, changes.uncommitted, repos.info, tui_host._repo_context).
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    with pytest.raises(GitReadError) as e_conf:
        gitq.merge_conflict_reason(repo)
    assert e_conf.value.kind is GitReadErrorKind.UNSUPPORTED_FEATURE

    with pytest.raises(GitReadError) as e_unc:
        changes.uncommitted(repo)
    assert e_unc.value.kind is GitReadErrorKind.UNSUPPORTED_FEATURE

    info = repos.info(repo)
    assert any("attr-source" in n for n in info.notes), info.notes
    assert not any("no commits yet" in n for n in info.notes), info.notes

    ctx = tui_host._repo_context(repo)
    assert ctx.get("blocked") and "attr-source" in ctx["blocked"]["reason"]
    rendered = "\n".join(frame.render(ViewState(st="blocked", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=ctx).text_rows())
    assert "hlith doctor" in rendered
    assert "clean clone without executable repository settings" not in rendered


def test_actual_supported_git_clean_dirty_unborn_and_root_commit_semantics(tmp_path: Path) -> None:
    # Clean committed repo -> legitimately no uncommitted change (exit 2), no conflicts.
    clean = _make_repo(tmp_path, "clean")
    assert gitq.merge_conflict_reason(clean) is None
    assert changes.uncommitted(clean) is None
    proc = _run_cli(["check", "--repo", str(clean), "--uncommitted", "--json"], env=_base_env(tmp_path / "st-c"), cwd=clean)
    assert proc.returncode == 2
    assert "no uncommitted change" in json.loads(proc.stdout)["check"]["reason"].lower()

    # Root commit -> allowed exit-1 empty-stderr parent lookup gives explicit "root commit" problem.
    c_list = changes.commits(clean)
    assert len(c_list) == 1 and "root commit" in c_list[0].problem

    # Dirty repo -> detects tracked + untracked changes accurately.
    (clean / "demo" / "calc.py").write_text("def validate(x: int) -> int:\n    return x\n", encoding="utf-8")
    (clean / "extra.py").write_text("Y = 1\n", encoding="utf-8")
    dirty_change = changes.uncommitted(clean)
    assert dirty_change is not None and not dirty_change.problem
    paths = {p for p, _, _ in dirty_change.files}
    assert paths == {"demo/calc.py", "extra.py"}

    # Unborn repo (0 commits) -> allowed exit-1 empty-stderr HEAD lookup distinguishes unborn from Git failure.
    unborn = _make_repo(tmp_path, "unborn", commit=False)
    assert changes.uncommitted(unborn) is None
    u_info = repos.info(unborn)
    assert any("no commits yet" in n for n in u_info.notes), u_info.notes


# ------------------------------------------------------------------ 3. Injected failure at every load-bearing read


def test_injected_failures_at_load_bearing_reads_raise_typed_errors_never_silent_empty(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _make_repo(tmp_path)
    (repo / "demo" / "calc.py").write_text("def validate(x: int) -> int:\n    return x\n", encoding="utf-8")

    # (a) Timeout
    def _boom_timeout(*_a, **_kw):
        raise subprocess.TimeoutExpired(["git"], 1)

    monkeypatch.setattr(gitq, "_run", _boom_timeout)
    with pytest.raises(GitReadError) as e_to:
        gitq.read(repo, "status", "--porcelain=v1", "-z")
    assert e_to.value.kind is GitReadErrorKind.TIMEOUT

    # (b) Spawn failure
    def _boom_spawn(*_a, **_kw):
        raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr(gitq, "_run", _boom_spawn)
    with pytest.raises(GitReadError) as e_sp:
        gitq.merge_conflict_paths(repo)
    assert e_sp.value.kind is GitReadErrorKind.SPAWN_FAILED

    # (c) Mid-read config/HEAD mutation
    monkeypatch.undo()
    calls = {"n": 0}
    orig_fp = git_read._fingerprint

    def _mutating_fp(p: Path):
        calls["n"] += 1
        return ("before",) if calls["n"] == 1 else ("after",)

    monkeypatch.setattr(git_read, "_fingerprint", _mutating_fp)
    with pytest.raises(GitReadError) as e_mut:
        gitq.read(repo, "status", "--porcelain=v1", "-z")
    assert e_mut.value.kind is GitReadErrorKind.CONCURRENT_MUTATION

    # (d) Streaming diff nonzero failure (changes.scan must NEVER report "no difference" on git diff failure)
    monkeypatch.setattr(git_read, "_fingerprint", orig_fp)
    fake_diff = _make_git_wrapper(
        tmp_path,
        name="fake-diff-fail",
        reject_token="--no-textconv",
        reject_rc=128,
        reject_msg="fatal: simulated diff failure",
    )
    monkeypatch.setenv("PATH", f"{fake_diff}{os.pathsep}{os.environ.get('PATH', '')}")
    head = _git(repo, "rev-parse", "HEAD").strip()
    c = changes.Change("commit", "test", head, b"")
    scanned = changes.scan(repo, ["HEAD"], {}, c)
    assert scanned._git_error is not None
    assert scanned.problem and "no difference" not in scanned.problem.lower()
    assert "simulated diff failure" in scanned.problem or "could not diff" in scanned.problem

    with pytest.raises(GitReadError):
        changes._stream(repo, ["diff", *changes.DIFF_ARGS, "HEAD"], {}, keep=1024)
    with pytest.raises(GitReadError):
        changes._prefix(repo, ["diff", *changes.DIFF_ARGS, "HEAD"], {}, limit=1024)


# ------------------------------------------------------------------ 4. Host confinement boundary exit 4 & negative controls


def test_target_code_spoofing_exit4_and_landlock_stderr_is_never_classified_as_host_boundary() -> None:
    """Negative control: target code exiting 4 with fake 'hlith-confine: Landlock ENOSYS' stderr MUST NOT
    produce ``boundary_failure`` (the O_CLOEXEC boundary status file was closed before ``execvp``)."""
    spoof = (
        "import sys; "
        "sys.stderr.write('hlith-confine: Landlock syscall unavailable: [Errno 38] Function not implemented\\n'); "
        "sys.exit(4)"
    )
    cp = run_confined([sys.executable, "-I", "-c", spoof], Profile(), timeout=30)
    assert cp.returncode == EXIT_BOUNDARY
    assert "Landlock" in cp.stderr and "Function not implemented" in cp.stderr
    assert cp.boundary_failure is None
    raise_if_confinement_boundary(cp)  # must NOT raise!


def test_launcher_authored_boundary_status_maps_to_typed_confinement_boundary_error(tmp_path: Path) -> None:
    """Real ``confine_exec.py`` launcher failure writes host-private O_CLOEXEC ``boundary.json`` and maps to
    ``ConfinementBoundaryError``; unit parser also handles ENOSYS Landlock JSON."""
    # Real end-to-end launcher failure (missing ro_bind path triggers die() inside child before execvp).
    missing_bind = tmp_path / "missing-ro-bind-path"
    real_cp = run_confined(
        [sys.executable, "-I", "-c", "print('should-not-run')"],
        Profile(ro_bind=(str(missing_bind),)),
        timeout=30,
    )
    assert real_cp.returncode == EXIT_BOUNDARY
    assert real_cp.boundary_failure is not None
    assert "ro_bind path missing" in real_cp.boundary_failure.detail
    with pytest.raises(ConfinementBoundaryError):
        raise_if_confinement_boundary(real_cp)

    # Structured ENOSYS Landlock payload parsing.
    status_file = tmp_path / "boundary.json"
    status_file.write_text(
        json.dumps({"code": "landlock-unavailable", "stage": "landlock", "errno": 38, "detail": "Landlock syscall unavailable: [Errno 38] Function not implemented"}),
        encoding="utf-8",
    )
    info = confinement._read_boundary_failure(str(status_file), EXIT_BOUNDARY)
    assert info is not None
    assert info.code == "landlock-unavailable"
    assert info.stage == "landlock"
    assert info.errno_num == 38
    fake_cp = ConfinedProcess(["launcher"], EXIT_BOUNDARY, stdout="", stderr="", boundary_failure=info)
    with pytest.raises(ConfinementBoundaryError) as exc_info:
        raise_if_confinement_boundary(fake_cp)
    assert exc_info.value.info.code == "landlock-unavailable"


def test_real_check_with_target_spoofing_landlock_stderr_is_not_classified_as_host_boundary(tmp_path: Path) -> None:
    """End-to-end negative control: target code raising/printing fake Landlock ENOSYS text inside a real confined
    ``hlith check`` must be judged on its actual semantic behavior (REFUTED exit 10), NEVER misclassified as exit 4."""
    repo = _make_repo(tmp_path, "spoof-repo")
    (repo / "demo" / "calc.py").write_text(
        "import sys\n\n"
        "def validate(x: int) -> int:\n"
        "    if x <= 0:\n"
        "        sys.stderr.write('hlith-confine: Landlock syscall unavailable: [Errno 38] Function not implemented\\n')\n"
        "        return 0\n"
        "    return x\n",
        encoding="utf-8",
    )
    proc = _run_cli(
        ["check", "--repo", str(repo), "--uncommitted", "--json", "--target-python", sys.executable],
        env=_base_env(tmp_path / "st-spoof"),
        cwd=repo,
    )
    assert proc.returncode == 10, (proc.returncode, proc.stdout, proc.stderr)
    env = json.loads(proc.stdout)
    assert env["exit_status"] == 10
    assert env["check"]["headline"] == "REFUSED · REFUTED"
    assert env["check"].get("boundary_kind") is None


def test_enosys_landlock_and_canary_failure_map_to_exit4_across_cli_json_plain_tui_and_hook(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """End-to-end check with controlled ENOSYS Landlock failure in confinement launcher:
    - CLI JSON & plain output exit 4 (REFUSED · BOUNDARY, host-confinement-unavailable, Landlock hint, NO restructure advice);
    - TUI verdict screen renders REFUSED · BOUNDARY with confinement guidance and NO restructure advice;
    - Agent hook maps exit 4 cleanly as BOUNDARY refusal without contract/restructure misdirection;
    - Original repository remains byte-identical.
    """
    repo = _make_repo(tmp_path)
    (repo / "demo" / "calc.py").write_text("def validate(x: int) -> int:\n    return x\n", encoding="utf-8")
    fp_before = _repo_fingerprint(repo)

    # Inject a controlled launcher-authored ENOSYS Landlock boundary failure at run_confined.
    enosys_info = ConfinementBoundaryInfo(
        code="landlock-unavailable",
        stage="landlock",
        detail="Landlock syscall unavailable: [Errno 38] Function not implemented",
        errno_num=38,
    )

    def _fake_enosys_confined(argv, profile, *, cwd=None, timeout=60, env=None):
        return ConfinedProcess(
            argv,
            EXIT_BOUNDARY,
            stdout="",
            stderr="hlith-confine: Landlock syscall unavailable: [Errno 38] Function not implemented\n",
            boundary_failure=enosys_info,
        )

    monkeypatch.setattr(confinement, "run_confined", _fake_enosys_confined)
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state-enosys"))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui-enosys"))

    # 1) CLI JSON
    art_dir_j = tmp_path / "art-json"
    rc_j = cli.main(["check", "--repo", str(repo), "--uncommitted", "--json", "--artifact-out", str(art_dir_j)])
    out_j = capsys.readouterr()
    assert rc_j == EXIT_BOUNDARY, (rc_j, out_j.out, out_j.err)
    assert _repo_fingerprint(repo) == fp_before
    env_j = json.loads(out_j.out)
    assert env_j["envelope"] == "hlith.check/1"
    assert env_j["exit_status"] == EXIT_BOUNDARY
    assert env_j["check"]["headline"] == "REFUSED · BOUNDARY"
    assert env_j["check"]["boundary_kind"] == BoundaryReason.CONFINEMENT_UNAVAILABLE.value
    assert any("Landlock" in n for n in env_j["check"]["headline_notes"])
    assert not any("restructure" in n.lower() for n in env_j["check"]["headline_notes"])
    art = env_j["artifact"]
    assert art["outcome"] == "refused" and art["exit_status"] == EXIT_BOUNDARY
    assert art["blocking"][0] == BoundaryReason.CONFINEMENT_UNAVAILABLE.value
    assert "landlock-unavailable" in art["blocking"][1]
    assert art["obligations"] == []

    # 2) CLI plain output
    art_dir_p = tmp_path / "art-plain"
    rc_p = cli.main(["check", "--repo", str(repo), "--uncommitted", "--artifact-out", str(art_dir_p)])
    out_p = capsys.readouterr()
    assert rc_p == EXIT_BOUNDARY, (rc_p, out_p.out, out_p.err)
    assert "Decision: REFUSED · BOUNDARY exit=4" in out_p.out
    assert "host-confinement-unavailable" in out_p.out
    assert "Landlock" in out_p.out
    assert "restructure" not in out_p.out.lower()

    # 3) TUI rendering on the recorded exit-4 artifact
    rendered = "\n".join(frame.render(ViewState(st="verdict", cols=110, rows=34), 110, 34, art, context={"repo": {"name": "repo", "branch": "main", "head": "0" * 40, "path": str(repo)}}).text_rows())
    assert "REFUSED" in rendered and "BOUNDARY" in rendered
    assert "restructure the unsupported construct" not in rendered.lower()
    assert "Landlock" in rendered or "confinement" in rendered.lower()

    # 4) Agent hook mapping using a stub hlith that replays the exact exit-4 JSON envelope
    hook_home = tmp_path / "hook-home"
    stub_hlith = tmp_path / "stub-hlith"
    saved_env_path = tmp_path / "saved-exit4.json"
    saved_env_path.write_text(json.dumps(env_j, sort_keys=True) + "\n", encoding="utf-8")
    stub_hlith.write_text(
        "#!/bin/sh\n"
        f'cat "{saved_env_path}"\n'
        "exit 4\n",
        encoding="utf-8",
    )
    stub_hlith.chmod(0o755)
    hook_env = {**os.environ, "HLITH_BIN": str(stub_hlith), "HLITH_HOOK_HOME": str(hook_home)}
    wk = subprocess.run(["bash", str(HOOK), "worker", str(repo)], capture_output=True, text=True, env=hook_env, timeout=30)
    assert wk.returncode == 0, wk.stderr

    prompt = subprocess.run(["bash", str(HOOK), "prompt", str(repo)], input="{}", capture_output=True, text=True, env=hook_env, timeout=30)
    assert prompt.returncode == 0, prompt.stderr
    prompt_ctx = json.loads(prompt.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "BOUNDARY refusal (exit 4" in prompt_ctx
    assert "host-confinement-unavailable" in prompt_ctx
    assert "hlith doctor --probe-target" in prompt_ctx
    assert "restructuring target code" in prompt_ctx

    stop = subprocess.run(["bash", str(HOOK), "stop", str(repo)], input="{}", capture_output=True, text=True, env=hook_env, timeout=30)
    assert stop.returncode == 0, stop.stderr
    stop_obj = json.loads(stop.stdout)
    assert stop_obj["decision"] == "block"
    assert "BOUNDARY refusal (exit 4" in stop_obj["reason"]
    assert "host-confinement-unavailable" in stop_obj["reason"]

    # 5) Failed confinement canary (exit 7 without boundary_status) ALSO maps to exit 4 BOUNDARY.
    def _fake_canary_crash(argv, profile, *, cwd=None, timeout=60, env=None):
        return ConfinedProcess(argv, 7, stdout="", stderr="canary died unexpectedly", boundary_failure=None)

    monkeypatch.setattr(confinement, "run_confined", _fake_canary_crash)
    rc_c = cli.main(["check", "--repo", str(repo), "--uncommitted", "--json"])
    out_c = capsys.readouterr()
    assert rc_c == EXIT_BOUNDARY, (rc_c, out_c.out, out_c.err)
    env_c = json.loads(out_c.out)
    assert env_c["exit_status"] == EXIT_BOUNDARY
    assert env_c["check"]["boundary_kind"] == BoundaryReason.CONFINEMENT_UNAVAILABLE.value
    assert "confinement-canary-failed" in env_c["artifact"]["blocking"][1]
    assert _repo_fingerprint(repo) == fp_before


def test_verification_failed_next_step_never_advises_restructure_construct() -> None:
    ob = {"id": "verification-failed", "verdict": "not-derived", "stop_reason": "RuntimeError: unexpected checker bug"}
    step = presentation._next_step(ob, {})
    assert "restructure" not in step.lower()
    assert "hlith doctor" in step.lower()
    art = {
        "format": 2,
        "run": {"run_id": "run-123456789abc", "mode": "headless", "landing_target": "rehearsal", "origin": "supplied-patch"},
        "outcome": "refused",
        "exit_status": 11,
        "landed_commit": None,
        "blocking": ["verification-failed"],
        "obligations": [ob],
    }
    nxt = frame._next_for_verdict(art, ("REFUSED · NOT-DERIVED", "warn", 11))
    assert "restructure" not in nxt.lower()
    assert "hlith doctor" in nxt.lower()
