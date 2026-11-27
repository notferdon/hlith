# SPDX-License-Identifier: Apache-2.0
"""P2.0 review-contract and bypass regression suite (portable: throwaway repos under tmp_path, no host paths).

Each row runs the real CLI in a child process with an isolated HOME/state, against a disposable git repository, and asserts the
public contract: every write route is refused (exit 4) and leaves the original repository byte-for-byte unchanged; `check` reports
in a rehearsal only; `replay --pytest-out` requires `--expect`; the exported witness runs without Hlith.

Tiers:
  default             rows that are refused before any confined engine work (seconds).
  HLITH_CONTRACT_FULL=1  rows that run a full confined `check` (about 30-60 s each; one heavy job at a time).

Rows A-H, T, T2 and the state-root rows come from the review review probes of 75defaa1..987361cf. P2.6 removed the engine write
commands from `hlith` and the caller-supplied marker/env-token/capability route from the engine: each write row now runs on both
surfaces (`hlith` -> exit 2, no such command; the shipped engine module -> exit 4, review-only refusal), T2 is an ordinary row.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
FULL = os.environ.get("HLITH_CONTRACT_FULL") == "1"
full_only = pytest.mark.skipif(not FULL, reason="runs a full confined check; set HLITH_CONTRACT_FULL=1")

REFUTE_PATCH = """diff --git a/demo/m.py b/demo/m.py
--- a/demo/m.py
+++ b/demo/m.py
@@ -1,2 +1,2 @@
 def f(x):
-    return x + 1
+    return x + 2
"""
COMMENT_PATCH = """diff --git a/demo/m.py b/demo/m.py
--- a/demo/m.py
+++ b/demo/m.py
@@ -1,2 +1,3 @@
 def f(x):
+    # explain: increment
     return x + 1
"""
MANIFEST = '{"paths": {"demo/m.py": ["modify"]}, "deltas": []}\n'
WORKER = (
    "import os\nfrom pathlib import Path\n"
    "Path('demo/m.py').write_text('def f(x):\\n    # explain: increment\\n    return x + 1\\n')\n"
    "Path(os.environ['HLITH_MANIFEST_DIR'], 'manifest.json').write_text(" + repr(MANIFEST) + ")\n"
)
_BOOT = "import sys; from hlith.operator.cli import main; sys.exit(main())"
_GIT_ID = ["-c", "user.name=contract", "-c", "user.email=contract@localhost"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def make_repo(path: Path) -> Path:
    (path / "demo").mkdir(parents=True)
    (path / "tests").mkdir()
    (path / "demo" / "m.py").write_text("def f(x):\n    return x + 1\n")
    (path / "demo" / "__init__.py").write_text("")
    (path / "tests" / "test_m.py").write_text("from demo.m import f\n\n\ndef test_f():\n    assert f(1) == 2\n")
    _git(path, "init", "-q")
    _git(path, "add", "-A")
    _git(path, *_GIT_ID, "commit", "-qm", "base")
    return path


def _tree_digest(root: Path, h, *, skip_git: bool) -> None:
    """Path, mode and bytes (or link target) of every entry under `root`, in sorted order."""
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if skip_git and rel.parts and rel.parts[0] == ".git":
            continue
        st = path.lstat()
        h.update(f"{rel}\x00{stat.S_IMODE(st.st_mode):o}\x00{stat.S_IFMT(st.st_mode)}\x00".encode())
        if path.is_symlink():
            h.update(os.readlink(path).encode())
        elif path.is_file():
            h.update(path.read_bytes())
        h.update(b"\x01")


def fingerprint(repo: Path) -> str:
    """Everything a landing or stray write could change: HEAD, every ref, index, status, .git config/hooks/info, and the
    content of every worktree file (tracked, untracked and ignored)."""
    h = hashlib.sha256()
    for part in (_git(repo, "rev-parse", "HEAD"), _git(repo, "for-each-ref"), _git(repo, "ls-files", "-s"),
                 _git(repo, "status", "--porcelain", "--untracked-files=all", "--ignored")):
        h.update(part.encode() + b"\x00")
    git_dir = repo / ".git"
    h.update((git_dir / "config").read_bytes())
    for sub in ("hooks", "info"):
        if (git_dir / sub).exists():
            h.update(sub.encode())
            _tree_digest(git_dir / sub, h, skip_git=False)
    _tree_digest(repo, h, skip_git=True)
    return h.hexdigest()


@pytest.fixture
def box(tmp_path: Path):
    """An isolated HOME and private state roots; the child never sees the caller's environment or real home."""
    home = tmp_path / "home"
    home.mkdir()
    st = tmp_path / "st"
    for name in ("state", "ui", "threads", "tmp"):
        (st / name).mkdir(parents=True)
        (st / name).chmod(0o700)
    files = tmp_path / "in"
    files.mkdir()
    (files / "refute.patch").write_text(REFUTE_PATCH)
    (files / "comment.patch").write_text(COMMENT_PATCH)
    (files / "comment.manifest.json").write_text(MANIFEST)
    wk = tmp_path / "wk"
    wk.mkdir()
    (wk / "worker.py").write_text(WORKER)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "PYTHONPATH": str(SRC),
           "TMPDIR": str(st / "tmp"), "HLITH_STATE_DIR": str(st / "state"), "HLITH_UI_STATE": str(st / "ui"),
           "HLITH_THREAD_STORE": str(st / "threads")}
    return {"tmp": tmp_path, "home": home, "st": st, "in": files, "wk": wk, "env": env}


def hlith(box: dict, *args: str, env: dict | None = None, drop: tuple[str, ...] = (), timeout: int = 900, umask: int | None = None):
    e = dict(box["env"])
    e.update(env or {})
    for k in drop:
        e.pop(k, None)
    pre = (lambda: os.umask(umask)) if umask is not None else None
    return subprocess.run([sys.executable, "-c", _BOOT, *args], env=e, capture_output=True, text=True, timeout=timeout,
                          cwd=str(box["tmp"]), preexec_fn=pre)


NO_COMMAND = "invalid choice"  # argparse: the command does not exist in `hlith` (P2.6)
ENGINE_REFUSAL = "Hlith Review is read-only"
APPLY_REFUSAL = "Apply is not offered in this distribution"
_ENGINE_BOOT = "import sys; from hlith.operator.engine_cli import main; sys.exit(main())"


def engine_module(box: dict, *args: str, env: dict | None = None, timeout: int = 300):
    """The engine module directly (`python -m hlith.operator.engine_cli ...`): shipped in the package, so it must refuse too."""
    e = dict(box["env"])
    e.update(env or {})
    return subprocess.run([sys.executable, "-c", _ENGINE_BOOT, *args], env=e, capture_output=True, text=True, timeout=timeout,
                          cwd=str(box["tmp"]))


def assert_refused_unchanged(proc, repo: Path, before: str, code: int = 4, reason: str | None = None) -> None:
    """Exit code alone is ambiguous (4 is also any input boundary): a review-only refusal row also names its reason."""
    assert proc.returncode == code, f"rc={proc.returncode}\nstdout:{proc.stdout[-1500:]}\nstderr:{proc.stderr[-1500:]}"
    assert "Traceback" not in proc.stderr, proc.stderr[-1500:]
    if reason is not None:
        assert reason in proc.stdout + proc.stderr, f"refused for another reason:\n{proc.stderr[-1500:]}"
    assert fingerprint(repo) == before, "the original repository changed"


# ---------------------------------------------------------------- harness identity


def test_child_imports_hlith_from_this_tree(box):
    proc = subprocess.run([sys.executable, "-c", "import hlith; print(hlith.__file__)"], env=box["env"], capture_output=True,
                          text=True, check=True)
    assert Path(proc.stdout.strip()).resolve().is_relative_to(SRC), proc.stdout


# ---------------------------------------------------------------- write routes (default tier)
# P2.6: `hlith run|resume|apply|propose-deltas` are not commands (exit 2, "invalid choice"); the engine module, still shipped,
# refuses every one of them (exit 4, review-only reason; argparse errors stay 2). Each row runs BOTH surfaces and asserts the
# original repository is byte-for-byte unchanged (refs, index, status incl. ignored, .git config/hooks/info, every file's bytes).

SURFACES = ["hlith", "engine-module"]


def _route(box, surface, *argv, env=None):
    return hlith(box, *argv, env=env) if surface == "hlith" else engine_module(box, *argv, env=env)


def _expect(surface, engine_code=4, engine_reason=ENGINE_REFUSAL):
    return (2, NO_COMMAND) if surface == "hlith" else (engine_code, engine_reason)


def _pipeline_argv(box, repo, src=None, *extra):
    argv = ["run", "--engine", "pipeline", *extra, "--repo", str(repo)]
    if src is not None:
        argv += ["--source-repo", str(src)]
    return argv + ["--patch", str(box["in"] / "comment.patch"), "--manifest", str(box["in"] / "comment.manifest.json"),
                   "--artifact-out", str(box["tmp"] / "out.json"), "--timeout", "300"]


@pytest.mark.parametrize("surface", SURFACES)
def test_A_legacy_run_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    before = fingerprint(repo)
    proc = _route(box, surface, "run", "--engine", "legacy", "--repo", str(repo), "--worker-cmd",
                  f"{sys.executable} {box['wk'] / 'worker.py'}", "--worker-ro", str(box["wk"]), "--artifact-out", str(box["tmp"] / "a.json"))
    code, reason = _expect(surface)
    assert_refused_unchanged(proc, repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
def test_B_pipeline_run_on_the_original_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    before = fingerprint(repo)
    code, reason = _expect(surface)
    assert_refused_unchanged(_route(box, surface, *_pipeline_argv(box, repo)), repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
def test_C_resume_is_refused_without_traceback(box, surface):
    proc = _route(box, surface, "resume", "x", "--artifact-out", str(box["tmp"] / "c.json"))
    code, reason = _expect(surface)
    assert proc.returncode == code, proc.stderr[-1500:]
    assert "Traceback" not in proc.stderr
    assert reason in proc.stderr, proc.stderr[-1500:]


@pytest.mark.parametrize("surface", SURFACES)
def test_D_removed_hidden_flag_is_a_usage_error(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    src = make_repo(box["tmp"] / "src")
    before = fingerprint(repo)
    proc = _route(box, surface, *_pipeline_argv(box, repo, src, "--review-internal-check"))
    expected = NO_COMMAND if surface == "hlith" else "--review-internal-check"
    assert_refused_unchanged(proc, repo, before, code=2, reason=expected)


@pytest.mark.parametrize("surface", SURFACES)
def test_F_hand_made_marker_without_token_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    src = make_repo(box["tmp"] / "src")
    (repo / ".hlith-review-rehearsal").write_text("x\n")
    before = fingerprint(repo)
    code, reason = _expect(surface)
    assert_refused_unchanged(_route(box, surface, *_pipeline_argv(box, repo, src)), repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
def test_T_hand_made_marker_with_matching_env_token_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    src = make_repo(box["tmp"] / "src")
    (repo / ".hlith-review-rehearsal").write_text("handmadetoken\n")
    before = fingerprint(repo)
    proc = _route(box, surface, *_pipeline_argv(box, repo, src), env={"HLITH_REVIEW_INTERNAL": "handmadetoken"})
    code, reason = _expect(surface)
    assert_refused_unchanged(proc, repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
def test_T2_hand_written_capability_record_cannot_land_in_the_original(box, surface):
    """Formerly a strict xfail (it LANDED through the env-token/capability route); P2.6 removed the route."""
    repo = make_repo(box["tmp"] / "fx")
    src = make_repo(box["tmp"] / "src")
    forged = box["tmp"] / "forged-state"
    forged.mkdir(mode=0o700)
    forged.chmod(0o700)
    (repo / ".hlith-review-rehearsal").write_text("handmadetoken\n")
    rec = forged / "review-capabilities" / (hashlib.sha256(str(repo.resolve()).encode()).hexdigest() + ".json")
    rec.parent.mkdir(mode=0o700)
    rec.write_text(json.dumps({"repo": str(repo.resolve()), "token": "handmadetoken", "created": time.time()}))
    before = fingerprint(repo)
    proc = _route(box, surface, *_pipeline_argv(box, repo, src),
                  env={"HLITH_REVIEW_INTERNAL": "handmadetoken", "HLITH_STATE_DIR": str(forged)})
    code, reason = _expect(surface)
    assert_refused_unchanged(proc, repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("variant", ["marker+env", "hidden-flag+marker"])
def test_G_committed_marker_is_refused(box, variant, surface):
    """A marker COMMITTED to the original (not just an untracked file), with the matching env token or the removed flag."""
    repo = make_repo(box["tmp"] / "fx")
    src = make_repo(box["tmp"] / "src")
    (repo / ".hlith-review-rehearsal").write_text("handmadetoken\n")
    _git(repo, "add", ".hlith-review-rehearsal")
    _git(repo, *_GIT_ID, "commit", "-qm", "marker")
    before = fingerprint(repo)
    flag = ["--review-internal-check"] if variant == "hidden-flag+marker" else []
    proc = _route(box, surface, *_pipeline_argv(box, repo, src, *flag), env={"HLITH_REVIEW_INTERNAL": "handmadetoken"})
    if surface == "hlith":
        assert_refused_unchanged(proc, repo, before, code=2, reason=NO_COMMAND)
    elif flag:
        assert_refused_unchanged(proc, repo, before, code=2, reason="--review-internal-check")
    else:
        assert_refused_unchanged(proc, repo, before, reason=ENGINE_REFUSAL)


@pytest.mark.parametrize("surface", SURFACES)
def test_H_apply_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    fake = box["tmp"] / "rehearsal.json"
    fake.write_text("{}")
    before = fingerprint(repo)
    proc = _route(box, surface, "apply", "--repo", str(repo), "--rehearsal-artifact", str(fake), "--patch", str(box["in"] / "comment.patch"))
    code, reason = _expect(surface, engine_reason=APPLY_REFUSAL)
    assert_refused_unchanged(proc, repo, before, code=code, reason=reason)


@pytest.mark.parametrize("surface", SURFACES)
def test_propose_deltas_is_refused(box, surface):
    repo = make_repo(box["tmp"] / "fx")
    before = fingerprint(repo)
    proc = _route(box, surface, "propose-deltas", "--repo", str(repo), "--patch", str(box["in"] / "comment.patch"))
    code, reason = _expect(surface)
    if surface == "engine-module" and proc.returncode == 2:  # argparse rejected the argv first: still refused, still unchanged
        assert_refused_unchanged(proc, repo, before, code=2)
    else:
        assert_refused_unchanged(proc, repo, before, code=code, reason=reason)


# ---------------------------------------------------------------- P2.6 surface and negative controls (default tier)


def test_P26_help_lists_no_write_command(box):
    proc = hlith(box, "--help")
    assert proc.returncode == 0
    listed = proc.stdout.split("{", 1)[1].split("}", 1)[0].split(",") if "{" in proc.stdout else []
    assert listed, proc.stdout[:800]
    assert not {"run", "resume", "apply", "propose-deltas"} & set(listed), listed
    assert "check" in listed


def test_P26_check_rehearses_in_process_and_reads_no_caller_authority():
    """Negative control on the source: check builds the run through run_inline/default_capabilities and launches no engine command."""
    src = (SRC / "hlith" / "operator" / "check.py").read_text()
    assert "run_inline(" in src and "default_capabilities(" in src
    for needle in ("engine_cli", "run_sync(", "HLITH_REVIEW_INTERNAL", ".hlith-review-rehearsal", "review_capability"):
        assert needle not in src, needle


def test_P26_tui_start_is_unavailable_and_creates_nothing(tmp_path):
    from hlith.operator.tui import launch
    plan = launch.Plan("launch-000000000000", tmp_path / "runs" / "launch-000000000000", tmp_path / "src", tmp_path / "clone",
                       ["hlith", "check"], None, None, None, b"", {"paths": {}}, "0" * 40, "label")
    meta = launch.start(plan)
    assert meta["state"] == launch.UNAVAILABLE_STATE
    assert "hlith check" in meta["reason"] and "not changed" in meta["reason"]
    assert not (tmp_path / "runs").exists() and not (tmp_path / "clone").exists()


@pytest.mark.parametrize("fault", [RuntimeError("injected engine fault"), KeyError("injected"), RecursionError("injected")],
                         ids=lambda e: type(e).__name__)
def test_P26_engine_fault_in_check_is_internal_error_with_envelope_not_traceback(box, monkeypatch, capsys, fault):
    """D1: an exception from the in-process rehearsal is a finished INTERNAL ERROR (exit 3) with the normal hlith.check/1
    envelope and out.json; nothing escapes, nothing is decided, nothing lands, the original is unchanged."""
    from hlith.operator import api as api_module
    from hlith.operator import cli as hlith_cli

    for key, value in box["env"].items():
        if key != "PYTHONPATH":
            monkeypatch.setenv(key, value)

    def boom(self, req, caps, *, on_start=None):
        raise fault

    monkeypatch.setattr(api_module.OperatorApi, "run_inline", boom)
    repo = make_repo(box["tmp"] / "fx")
    base = _git(repo, "rev-parse", "HEAD").strip()
    before = fingerprint(repo)
    out_dir = box["tmp"] / "r"
    rc = hlith_cli.main(["--no-input", "check", "--repo", str(repo), "--patch", str(box["in"] / "refute.patch"), "--base", base,
                         "--manifest", str(box["in"] / "comment.manifest.json"), "--json", "--artifact-out", str(out_dir)])
    out = capsys.readouterr()
    assert rc == 3, (rc, out.err[-1500:])
    assert "Traceback" not in out.err + out.out
    payload = json.loads(out.out)  # run output is captured (stdout stays one envelope); the cause is in the artifact reason
    assert "internal error" in payload["artifact"]["reason"] and type(fault).__name__ in payload["artifact"]["reason"]
    assert payload["envelope"] == "hlith.check/1" and payload["exit_status"] == 3
    assert payload["artifact"]["verdict"] == "INTERNAL ERROR" and payload["artifact"].get("outcome") != "landed"
    assert payload["check"]["headline"] == "INTERNAL ERROR" and payload["check"]["apply_command"] is None
    assert json.loads((out_dir / "out.json").read_text())["exit_status"] == 3
    assert fingerprint(repo) == before


def test_P26_check_on_a_tty_runs_headless_never_the_terminal_screen(monkeypatch):
    """`hlith check` on a TTY without --no-input must not open the terminal screen's Claim (its start is unavailable)."""
    from hlith.operator import check as operator_check
    from hlith.operator import cli as hlith_cli

    monkeypatch.setattr(hlith_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(hlith_cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(hlith_cli, "_open_interactive_check", lambda _a: pytest.fail("the terminal screen was opened"))
    seen = []
    monkeypatch.setattr(operator_check, "execute", lambda args, api=None: seen.append(args.repo) or 0)
    assert hlith_cli.main(["check", "--repo", "/nonexistent/repo", "--uncommitted"]) == 0
    assert seen == [Path("/nonexistent/repo")]


# ---------------------------------------------------------------- export contract (default tier)


def test_pytest_out_without_expect_is_a_usage_error_and_writes_nothing(box):
    out = box["tmp"] / "w" / "test_w.py"
    proc = hlith(box, "replay", str(box["tmp"] / "missing.json"), "--pytest-out", str(out))
    assert proc.returncode == 2, proc.stderr[-800:]
    assert "--expect" in proc.stderr
    assert not out.exists() and not out.parent.exists()


# ---------------------------------------------------------------- state root (default tier: refused before engine work)


def test_existing_group_readable_state_root_is_refused_and_not_chmodded(box):
    repo = make_repo(box["tmp"] / "fx")
    loose = box["tmp"] / "loose-state"
    loose.mkdir()
    loose.chmod(0o755)
    before = fingerprint(repo)
    base = _git(repo, "rev-parse", "HEAD").strip()
    proc = hlith(box, "check", "--repo", str(repo), "--patch", str(box["in"] / "refute.patch"), "--base", base, "--manifest",
                 str(box["in"] / "comment.manifest.json"), "--no-input", "--artifact-out", str(box["tmp"] / "r"),
                 env={"HLITH_STATE_DIR": str(loose)})
    assert_refused_unchanged(proc, repo, before, reason="0700")
    assert stat.S_IMODE(loose.stat().st_mode) == 0o755, "a pre-existing state root must never be chmodded"


# ---------------------------------------------------------------- full tier: confined check runs


def _check(box, repo: Path, patch: str, out: Path, *extra: str, **kw):
    base = _git(repo, "rev-parse", "HEAD").strip()
    proc = hlith(box, "check", "--repo", str(repo), "--patch", str(box["in"] / patch), "--base", base, "--manifest",
                 str(box["in"] / "comment.manifest.json"), "--no-input", "--json", "--artifact-out", str(out), *extra, **kw)
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        payload = None
    return proc, payload


@full_only
@pytest.mark.parametrize("umask", [0o002, 0o022], ids=["umask002", "umask022"])
def test_E1_check_refuting_change_is_REFUTED_in_a_rehearsal_and_creates_a_fresh_state_root_0700(box, umask):
    repo = make_repo(box["tmp"] / "fx")
    fresh = box["tmp"] / "fresh-state"
    before = fingerprint(repo)
    proc, p = _check(box, repo, "refute.patch", box["tmp"] / "r", env={"HLITH_STATE_DIR": str(fresh)}, umask=umask)
    assert proc.returncode == 10, proc.stderr[-1500:]
    assert p is not None, proc.stdout[-800:]
    art = p["artifact"]
    assert art["outcome"] == "refused" and art["exit_status"] == 10
    assert (art.get("run") or {}).get("landing_target") == "rehearsal"
    assert (p.get("check") or {}).get("apply_command") is None
    assert fingerprint(repo) == before
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o700
    assert not (fresh / "review-capabilities").exists(), "P2.6: check writes no capability record"


@full_only
def test_E2_check_comment_only_change_lands_only_in_its_own_clone(box):
    repo = make_repo(box["tmp"] / "fx")
    head = _git(repo, "rev-parse", "HEAD").strip()
    before = fingerprint(repo)
    proc, p = _check(box, repo, "comment.patch", box["tmp"] / "h", "--keep-clone")
    assert proc.returncode == 0, proc.stderr[-1500:]
    art = p["artifact"]
    assert art["outcome"] == "landed" and art["exit_status"] == 0
    assert (art.get("run") or {}).get("landing_target") == "rehearsal"
    assert (p.get("check") or {}).get("apply_command") is None
    assert art.get("landed_commit") != head
    assert fingerprint(repo) == before
    clone = Path(p["check"]["clone_path"])
    assert _git(clone, "rev-parse", "HEAD").strip() == art["landed_commit"], "the landing is in check's own disposable clone"
    assert not (clone / ".hlith-review-rehearsal").exists(), "P2.6: no marker is written"


@full_only
@pytest.mark.parametrize("umask", [0o002, 0o022], ids=["umask002", "umask022"])
def test_default_state_root_is_xdg_style_0700_with_no_dot_hlith_in_home(box, umask):
    repo = make_repo(box["tmp"] / "fx")
    proc, _ = _check(box, repo, "refute.patch", box["tmp"] / "r",
                     drop=("HLITH_STATE_DIR", "XDG_STATE_HOME", "HLITH_UI_STATE", "HLITH_THREAD_STORE"), umask=umask)
    assert proc.returncode == 10, proc.stderr[-1500:]
    root = box["home"] / ".local" / "state" / "hlith"
    assert root.is_dir() and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert not (box["home"] / ".hlith").exists()


def _run_witness(witness: Path, tree: Path) -> int:
    """Run an exported witness with Hlith made unimportable, from a checkout of `tree`."""
    boot = ("import sys; sys.modules['hlith'] = None; import pytest; "
            f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(witness)!r}]))")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HLITH_WITNESS_ROOT": str(tree), "HOME": str(tree)}
    return subprocess.run([sys.executable, "-I", "-c", boot], cwd=str(tree), env=env, capture_output=True, text=True,
                          timeout=300).returncode


@full_only
def test_exported_witness_contract_pre_and_post(box):
    repo = make_repo(box["tmp"] / "fx")
    proc, _ = _check(box, repo, "refute.patch", box["tmp"] / "r")
    assert proc.returncode == 10, proc.stderr[-1500:]
    base = _git(repo, "rev-parse", "HEAD").strip()
    pre_tree, post_tree = box["tmp"] / "tree-base", box["tmp"] / "tree-post"
    _git(repo, "worktree", "add", "-q", "--detach", str(pre_tree), base)
    _git(repo, "worktree", "add", "-q", "--detach", str(post_tree), base)
    _git(post_tree, "apply", str(box["in"] / "refute.patch"))
    expected = {"pre": (0, 1), "post": (1, 0)}  # (pytest rc on base, on post): pre = regression guard, post = accepted change
    for side, (on_base, on_post) in expected.items():
        out = box["tmp"] / f"test_witness_{side}.py"
        rp = hlith(box, "replay", str(box["tmp"] / "r" / "out.json"), "--repo", str(repo), "--pytest-out", str(out), "--expect", side)
        assert rp.returncode == 0 and out.is_file(), rp.stderr[-1500:]
        imported = {a.name.split(".")[0] for n in ast.walk(ast.parse(out.read_text())) if isinstance(n, ast.Import) for a in n.names}
        imported |= {(n.module or "").split(".")[0] for n in ast.walk(ast.parse(out.read_text())) if isinstance(n, ast.ImportFrom)}
        assert "hlith" not in imported, "the exported witness must not depend on Hlith"
        assert (_run_witness(out, pre_tree), _run_witness(out, post_tree)) == (on_base, on_post), side


# ---------------------------------------------------------------- export contract C1-C6 and L1 (review design rev2, design review-locked)
# Implemented by P2.4. After C1, exit 0 no longer implies a file was written: callers read `pytest_export.status`
# (written|refused|not-attempted). The exporter takes the typed versioned record (contract/witness.py), never a raw call.


def _record(witness_call: dict) -> dict:
    from hlith.contract.witness import adapt
    return adapt(witness_call)


def _plain_witness(**extra) -> dict:
    w = {"module": "demo.m", "qualname": "f", "args": [1], "kwargs": {}, "pre": {"k": "ret", "r": "2"}, "post": {"k": "ret", "r": "3"}}
    w.update(extra)
    return w


def test_control_a_plain_return_witness_exports():
    from hlith.operator.witness_export import build_pytest_source
    src = build_pytest_source(_record(_plain_witness()), expect="pre")
    assert "test_recorded_pre_behavior" in src


@pytest.mark.parametrize("channel", ["g", "w", "s"])
@pytest.mark.parametrize("shape", ["differs", "same-nonempty"])
def test_L1_unasserted_behaviour_channel_is_refused(channel, shape):
    from hlith.operator.witness_export import NotExportable, build_pytest_source
    w = _plain_witness()
    w["pre"] = dict(w["pre"], **{channel: "pre-state"})
    w["post"] = dict(w["post"], **{channel: "post-state" if shape == "differs" else "pre-state"})
    with pytest.raises(NotExportable, match="channel"):
        build_pytest_source(_record(w), expect="pre")


@pytest.mark.parametrize("channel", ["g", "w", "s"])
def test_L1_divergence_only_in_a_channel_is_refused(channel):
    """Same return on both sides, divergence only in g/w/s: never exported (a return-only test would pass on both revisions)."""
    from hlith.operator.witness_export import NotExportable, build_pytest_source
    w = _plain_witness(post={"k": "ret", "r": "2"})
    w["pre"] = dict(w["pre"], **{channel: "a"})
    w["post"] = dict(w["post"], **{channel: "b"})
    with pytest.raises(NotExportable, match="channel"):
        build_pytest_source(_record(w), expect="pre")


def test_C5_legacy_record_without_schema_version_is_not_exported():
    from hlith.operator.witness_export import NotExportable, build_pytest_source
    with pytest.raises(NotExportable, match="legacy"):
        build_pytest_source(_plain_witness(), expect="pre")


def test_C5_unknown_newer_schema_version_is_not_exported():
    from hlith.operator.witness_export import NotExportable, build_pytest_source
    with pytest.raises(NotExportable, match="schema_version"):
        build_pytest_source(dict(_record(_plain_witness()), schema_version=999), expect="pre")


def test_C4_not_reproduced_exit_has_a_named_constant():
    from hlith.operator import replay_cmd
    named = {k for k, v in vars(replay_cmd).items() if k.startswith("EXIT_") and "REPRODUCED" in k and v == 1}
    assert named, "no EXIT_*REPRODUCED* == 1 constant in replay_cmd"


def test_C3_missing_expect_under_json_still_emits_an_envelope(box):
    out = box["tmp"] / "w" / "test_w.py"
    proc = hlith(box, "replay", str(box["tmp"] / "missing.json"), "--json", "--pytest-out", str(out))
    assert proc.returncode == 2
    assert not out.exists() and not out.parent.exists()
    env = json.loads(proc.stdout)
    assert env["envelope"] == "hlith.replay/1" and env["exit_status"] == 2
    assert env["pytest_export"]["status"] == "not-attempted"


CONTAINER_PATCH = """diff --git a/demo/m.py b/demo/m.py
--- a/demo/m.py
+++ b/demo/m.py
@@ -1,2 +1,2 @@
 def f(x):
-    return x + 1
+    return [x + 1]
"""


@full_only
def test_C1_C2_reproduced_but_unexportable_witness_exits_0_and_reports_refused(box):
    repo = make_repo(box["tmp"] / "fx")
    (box["in"] / "container.patch").write_text(CONTAINER_PATCH)
    proc, _ = _check(box, repo, "container.patch", box["tmp"] / "r")
    assert proc.returncode == 10, proc.stderr[-1500:]
    out = box["tmp"] / "w" / "test_w.py"
    rp = hlith(box, "replay", str(box["tmp"] / "r" / "out.json"), "--repo", str(repo), "--json", "--pytest-out", str(out),
               "--expect", "post")
    assert not out.exists() and not out.parent.exists(), "a refused export must write no file and no parent"
    assert "container" in rp.stdout + rp.stderr, f"export was not refused for the container reason:\n{rp.stderr[-1500:]}"
    assert rp.returncode == 0, rp.stderr[-1500:]
    env = json.loads(rp.stdout)
    assert env["status"] == "REPRODUCED"
    assert env["pytest_export"]["status"] == "refused" and env["pytest_export"]["reason"]


@full_only
def test_C2_C6_written_export_is_reported_and_record_is_current_schema(box):
    repo = make_repo(box["tmp"] / "fx")
    proc, _ = _check(box, repo, "refute.patch", box["tmp"] / "r")
    assert proc.returncode == 10, proc.stderr[-1500:]
    out = box["tmp"] / "test_w.py"
    rp = hlith(box, "replay", str(box["tmp"] / "r" / "out.json"), "--repo", str(repo), "--json", "--pytest-out", str(out),
               "--expect", "pre")
    assert rp.returncode == 0 and out.is_file(), rp.stderr[-1500:]
    exp = json.loads(rp.stdout)["pytest_export"]
    assert exp["status"] == "written" and exp["expect"] == "pre" and Path(exp["path"]) == out
    rows = json.loads((box["tmp"] / "r" / "out.json").read_text())["obligations"]
    recorded = [r for r in rows if "witness_call" in r]
    assert recorded and all(r["witness_record"] == _record(r["witness_call"]) for r in recorded)


# ---------------------------------------------------------------- G1: exporter refusals (default tier; from review g5_refusals4)
# Each row changes ONE thing in an otherwise exportable witness and must refuse on BOTH --expect sides with no file and no
# parent directory. A control proves the base exports, so a refusal row cannot pass because everything is refused.

_OK = {"k": "ret", "r": "1"}
_EXC = {"k": "exc", "t": "builtins.ValueError"}
_BASE = {"module": "m", "qualname": "f", "args": [1], "kwargs": {}, "receiver": None, "env": None,
         "pre": {**_EXC, "mi": "text"}, "post": _OK}
_TRUNC = "head\u2026#0123456789abcdef"
_REFUSALS = {
    # printed output
    "pre-printed": {"pre": {"k": "ret", "r": "0", "out": "stdout='a' stderr=''"}},
    "post-printed": {"post": {"k": "ret", "r": "1", "out": "stdout='a' stderr=''"}},
    # exception with no message (type-only is vacuous)
    "exc-no-message": {"pre": _EXC},
    "exc-empty-message": {"pre": {**_EXC, "m": ""}},
    # message truncated by the engine cap
    "exc-truncated-m": {"pre": {**_EXC, "m": _TRUNC}},
    "exc-truncated-mi": {"pre": {**_EXC, "mi": _TRUNC}},
    "post-exc-truncated": {"post": {**_EXC, "mi": _TRUNC}},
    # placeholder / address in a message
    "exc-address-m": {"pre": {**_EXC, "m": "at 0x?"}},
    "exc-tree-m": {"pre": {**_EXC, "m": "<tree>/m.py"}},
    # container / opaque / non-literal returns
    "post-list": {"post": {"k": "ret", "r": "[1]"}},
    "post-set": {"post": {"k": "ret", "r": "{1}"}},
    "pre-list": {"pre": {"k": "ret", "r": "[1]"}},
    "post-opaque": {"post": {"k": "ret", "r": "<m.C object at 0x?>"}},
    "post-bytes": {"post": {"k": "ret", "r": "b'x'"}},
    "post-nan": {"post": {"k": "ret", "r": "nan"}},
    "post-tree-token": {"post": {"k": "ret", "r": repr("<tree>/m.py")}},
    "post-raw-address": {"post": {"k": "ret", "r": repr("at 0x1f2e3d")}},
    "ret-without-repr": {"pre": {"k": "ret"}},
    # evaluator argument markers
    "marker-arg": {"args": [{"__hlith_callable__": {}}]},
    "dollar-marker-kwarg": {"kwargs": {"x": {"$bytes": "eA=="}}},
    # recorded environment and other evaluator machinery
    "env": {"env": {"A": "1"}},
    "receiver": {"receiver": {"cls": "C", "kind": "static"}},
    "inject": {"inject": {"x": 1}},
    "throw": {"throw": "x"},
    "truncated-flag": {"truncated": True},
    "same-outcome": {"post": {**_EXC, "mi": "text"}},
}


@pytest.mark.parametrize("expect", ["pre", "post"])
def test_G1_control_base_witness_exports(tmp_path, expect):
    from hlith.operator.witness_export import write_pytest
    out = tmp_path / "w" / "t.py"
    write_pytest(out, _record(_BASE), expect=expect)
    assert out.is_file()


@pytest.mark.parametrize("expect", ["pre", "post"])
@pytest.mark.parametrize("row", sorted(_REFUSALS))
def test_G1_export_refuses_with_no_file_and_no_parent(tmp_path, row, expect):
    from hlith.operator.witness_export import NotExportable, write_pytest
    out = tmp_path / "w" / "t.py"
    with pytest.raises(NotExportable):
        write_pytest(out, _record({**_BASE, **_REFUSALS[row]}), expect=expect)
    assert not out.exists() and not out.parent.exists()


@pytest.mark.parametrize("field", ["m", "mi"])
def test_G1_exported_exception_message_is_asserted(tmp_path, field):
    """An exception witness asserts its message, whether recorded as `mi` or only as `m`: a different message must fail."""
    from hlith.operator.witness_export import write_pytest
    witness = {**_BASE, "module": "msgmod", "pre": {**_EXC, field: "text"}}
    out = tmp_path / "t_witness.py"
    write_pytest(out, _record(witness), expect="pre")
    results = {}
    for message in ("text", "other"):
        root = tmp_path / message
        root.mkdir()
        (root / "msgmod.py").write_text(f"def f(x):\n    raise ValueError({message!r})\n")
        boot = ("import sys; sys.modules['hlith'] = None; import pytest; "
                f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(out)!r}]))")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HLITH_WITNESS_ROOT": str(root), "HOME": str(root)}
        results[message] = subprocess.run([sys.executable, "-I", "-c", boot], cwd=str(root), env=env, capture_output=True,
                                          text=True, timeout=120).returncode
    assert results == {"text": 0, "other": 1}, results


# ---------------------------------------------------------------- G3: the fingerprint sees every write a landing could make


def _fp_git_config(repo):
    _git(repo, "config", "core.hooksPath", "/nonexistent")


def _fp_hook(repo):
    (repo / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\n")


def _fp_ignored(repo):
    (repo / ".gitignore").write_text("*.bin\n")
    _git(repo, "add", ".gitignore")
    _git(repo, *_GIT_ID, "commit", "-qm", "ignore")
    (repo / "x.bin").write_text("1")
    return "x.bin"


def _fp_untracked_content(repo):
    (repo / "u.txt").write_text("one")
    return "u.txt"


@pytest.mark.parametrize("change", ["git-config", "hook", "ignored-content", "untracked-content", "tracked-mode"])
def test_G3_fingerprint_detects_writes_outside_refs_and_index(tmp_path, change):
    repo = make_repo(tmp_path / "fx")
    if change == "ignored-content":
        name = _fp_ignored(repo)
    elif change == "untracked-content":
        name = _fp_untracked_content(repo)
    before = fingerprint(repo)
    assert fingerprint(repo) == before, "fingerprint must be stable when nothing changes"
    if change == "git-config":
        _fp_git_config(repo)
    elif change == "hook":
        _fp_hook(repo)
    elif change in ("ignored-content", "untracked-content"):
        (repo / name).write_text("two")  # same status line, different bytes
    else:
        (repo / "demo" / "m.py").chmod(0o755)
    assert fingerprint(repo) != before, change


# ---------------------------------------------------------------- residual rows (design review after d42b0924 PASS)


@pytest.mark.parametrize("expect", ["pre", "post"])
def test_R1_absolute_extra_sys_path_is_refused(tmp_path, expect):
    from hlith.operator.witness_export import NotExportable, write_pytest
    out = tmp_path / "w" / "t.py"
    with pytest.raises(NotExportable):
        write_pytest(out, _record(_BASE), extra_sys_path=[str(tmp_path / "site")], expect=expect)
    assert not out.exists() and not out.parent.exists()


@pytest.mark.parametrize("expect", ["pre", "post"])
@pytest.mark.parametrize("qualname", ["outer.<locals>.f", "C.m.<locals>.inner"])
def test_R2_locals_qualname_is_refused(tmp_path, expect, qualname):
    from hlith.operator.witness_export import NotExportable, write_pytest
    out = tmp_path / "w" / "t.py"
    with pytest.raises(NotExportable):
        write_pytest(out, _record({**_BASE, "qualname": qualname}), expect=expect)
    assert not out.exists() and not out.parent.exists()


def test_R3_symlink_pytest_out_is_refused_and_target_untouched(tmp_path):
    from hlith.operator.witness_export import NotExportable, write_pytest
    target = tmp_path / "victim.txt"
    target.write_text("keep\n")
    link = tmp_path / "t.py"
    link.symlink_to(target)
    with pytest.raises(NotExportable):
        write_pytest(link, _record(_BASE), expect="pre")
    assert link.is_symlink() and os.readlink(link) == str(target)
    assert target.read_text() == "keep\n"


def _run_exported(tmp_path: Path, out: Path, name: str, body: str) -> int:
    root = tmp_path / name
    root.mkdir()
    (root / "msgmod.py").write_text(body)
    boot = ("import sys; sys.modules['hlith'] = None; import pytest; "
            f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(out)!r}]))")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HLITH_WITNESS_ROOT": str(root), "HOME": str(root)}
    return subprocess.run([sys.executable, "-I", "-c", boot], cwd=str(root), env=env, capture_output=True, text=True,
                          timeout=120).returncode


@pytest.mark.parametrize("field", ["m", "mi"])
def test_R4_exported_exception_type_is_asserted(tmp_path, field):
    """Same message, different exception type must fail: the generated test is not message-only."""
    from hlith.operator.witness_export import write_pytest
    out = tmp_path / "t_witness.py"
    write_pytest(out, _record({**_BASE, "module": "msgmod", "pre": {**_EXC, field: "text"}}), expect="pre")
    results = {
        "ValueError": _run_exported(tmp_path, out, "same", "def f(x):\n    raise ValueError('text')\n"),
        "TypeError": _run_exported(tmp_path, out, "other-type", "def f(x):\n    raise TypeError('text')\n"),
        "subclass": _run_exported(tmp_path, out, "subclass",
                                  "class E(ValueError):\n    pass\n\n\ndef f(x):\n    raise E('text')\n"),
    }
    assert results == {"ValueError": 0, "TypeError": 1, "subclass": 1}, results


@full_only
def test_R5_fix_after_refuted_explicit_raise_lands_rehearsal_and_altered_message_stays_refuted(box):
    """After REFUTED pins a type-only exception outcome, a non-revert fix restoring the exact raise lands in rehearsal
    (exit 0), while a fix with a DIFFERENT exception message stays REFUTED (exit 10, no message weakening)."""
    repo = box["tmp"] / "fx_exc"
    (repo / "demo").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "demo" / "__init__.py").write_text("")
    base_src = (
        "def cap(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    if value > 300:\n"
        "        result = 300\n"
        "    else:\n"
        "        result = value\n"
        "    return result\n"
    )
    (repo / "demo" / "m.py").write_text(base_src)
    (repo / "tests" / "test_m.py").write_text(
        "from demo.m import cap\n\n\ndef test_cap():\n    assert cap(60) == 60\n    assert cap(600) == 300\n"
    )
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, *_GIT_ID, "commit", "-qm", "base")
    before = fingerprint(repo)

    # Run 1: drop the <= 0 guard -> REFUTED (exit 10) and writes Layer 5 exception pins
    (repo / "demo" / "m.py").write_text("def cap(value: int) -> int:\n    return 300 if value > 300 else value\n")
    p1 = hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(box["tmp"] / "r1"))
    assert p1.returncode == 10, p1.stderr[-1500:]
    j1 = json.loads(p1.stdout)
    written = set(j1["artifact"]["feedback"]["written_feedback_ids"])
    assert written, j1["artifact"]["feedback"]

    # Run 2 (positive): useful non-revert simplification restoring the exact guard -> LANDED rehearsal (exit 0)
    (repo / "demo" / "m.py").write_text(
        "def cap(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Timeout must be positive')\n"
        "    return 300 if value > 300 else value\n"
    )
    p2 = hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(box["tmp"] / "r2"))
    assert p2.returncode == 0, p2.stdout[-1500:] + p2.stderr[-1500:]
    j2 = json.loads(p2.stdout)
    assert written <= set(j2["artifact"]["feedback"]["loaded_feedback_ids"])
    assert j2["artifact"]["outcome"] == "landed" and j2["artifact"]["run"]["landing_target"] == "rehearsal"

    # Run 3 (negative control): altered exception message MUST STILL BE REFUTED (exit 10)
    (repo / "demo" / "m.py").write_text(
        "def cap(value: int) -> int:\n"
        "    if value <= 0:\n"
        "        raise ValueError('Different message')\n"
        "    return 300 if value > 300 else value\n"
    )
    p3 = hlith(box, "check", "--repo", str(repo), "--uncommitted", "--no-input", "--json", "--artifact-out", str(box["tmp"] / "r3"))
    assert p3.returncode == 10, p3.stdout[-1500:] + p3.stderr[-1500:]
    _git(repo, "checkout", "-q", "--", "demo/m.py")
    assert fingerprint(repo) == before
