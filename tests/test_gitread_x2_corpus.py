# SPDX-License-Identifier: Apache-2.0
"""X2/X2b: closed-world Git-read vet, proven by a corpus generated from `git help --config` (review generator).

Self-contained (inline helpers). Only seams that exist before AND after the structural change are called:
HardenedGitRead().repository_hostile_reason/head_tree/export_tree, hostio.git_read.safe_git_read, operator.gitq refusal/git/text/popen/toplevel,
LocalSnapshotService().seal_base, agent.capture._diff_stage, gate.git_write commit_staged/commit_tree_cas.

Oracle (hostile case): refused (non-None reason or HostIntegrityError/RuntimeError/OSError), no marker file, no git process started in/with cwd or
-C/--git-dir/--work-tree inside the repository (spawn spy: only `git config --file` allowed), X9 hashes unchanged. Allowed (Tier A/P) keys with benign
values must PASS. Tests assert behaviour, not reason text.

Run: PYTHONPATH=<worktree>/src <venv>/bin/python -m pytest tests/test_gitread_x2_corpus.py -p no:cacheprovider   (one process, no -n)
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

import hlith

_SRC = Path(__file__).resolve().parents[1] / "src"
assert Path(hlith.__file__).resolve().is_relative_to(_SRC), f"hlith imported from {hlith.__file__}, not the tree under test {_SRC}"

from hlith.contract.identities import tree_oid  # noqa: E402
from hlith.hostio.git_read import HardenedGitRead, safe_git_read  # noqa: E402
from hlith.hostio.integrity import HostIntegrityError  # noqa: E402
from hlith.hostio.snapshot import LocalSnapshotService  # noqa: E402
from hlith.operator import gitq  # noqa: E402

REFUSAL_EXC = (HostIntegrityError, RuntimeError, OSError, ValueError)
BASE_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
_REAL_POPEN = subprocess.Popen

# ----------------------------------------------------------------------------------------------------------------------------------------
# helpers


def _plain_env(home: Path) -> dict:
    return {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PAGER": "cat", "GIT_PAGER": "cat",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "LC_ALL": "C"}


def _git(repo: Path, *args: str, home: Path, inp: bytes | None = None) -> str:
    # test setup must not trip the marker hooks itself (e.g. `git add` runs post-index-change): hooks off for setup commands only
    cp = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args], capture_output=True, env=_plain_env(home), input=inp)
    assert cp.returncode == 0, (args, cp.stderr)
    return cp.stdout.decode().strip()


def _inside(path, root: str) -> bool:
    if path is None:
        return False
    p = os.path.realpath(str(path))
    return p == root or p.startswith(root + os.sep)


def _subcommand(argv: list) -> str | None:
    i, takes = 1, {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--attr-source", "--super-prefix", "--config-env"}
    while i < len(argv):
        a = str(argv[i])
        if a in takes:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return None


def git_violations(calls: list, repo: Path) -> list:
    """git processes that touched `repo` in any way other than `git config --file <path>` (the only thing a pre-vet step may do)."""
    root = os.path.realpath(str(repo))
    bad = []
    for argv, cwd in calls:
        if not argv or os.path.basename(str(argv[0])) != "git":
            continue
        scoped = any(str(a) in ("-C", "--git-dir", "--work-tree") or str(a).startswith(("--git-dir=", "--work-tree=")) for a in argv)
        mentions = any(root in str(a) for a in argv)
        if _inside(cwd, root) or scoped or (mentions and (_subcommand(argv) != "config" or "--file" not in [str(a) for a in argv])):
            bad.append(" ".join(map(str, argv))[:160])
    return bad


class SpawnSpy:
    def __init__(self) -> None:
        self.calls: list = []

    def install(self, monkeypatch) -> "SpawnSpy":
        calls = self.calls

        class _P(_REAL_POPEN):  # subprocess.run() and gitq._popen both construct through subprocess.Popen
            def __init__(self, args, *a, **kw):
                calls.append((list(args) if not isinstance(args, (str, bytes)) else [args], kw.get("cwd")))
                super().__init__(args, *a, **kw)

        monkeypatch.setattr(subprocess, "Popen", _P)
        return self


def tree_hash(root: Path) -> str:
    """X9 fingerprint: every file's bytes under root (config, index, HEAD, refs, objects, worktree) + mtimes of index and HEAD."""
    h = hashlib.sha256()
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for f in sorted(fn):
            p = Path(dp) / f
            st = p.lstat()
            h.update(str(p.relative_to(root)).encode() + (b"L" if stat.S_ISLNK(st.st_mode) else b"F"))
            if stat.S_ISREG(st.st_mode):
                h.update(p.read_bytes())
            if f in ("index", "HEAD"):
                h.update(str(st.st_mtime_ns).encode())
    return h.hexdigest()


def refuses(fn) -> tuple[bool, str]:
    """(True, why) when fn refuses by a non-None/exception; (False, repr) when it returned data."""
    try:
        out = fn()
    except REFUSAL_EXC as e:
        return True, f"{type(e).__name__}: {str(e)[:80]}"
    return False, repr(out)[:80]


# ---- repository fixtures -------------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("x2world")
    home = root / "home"
    home.mkdir()
    tpl = root / "tpl"
    tpl.mkdir()
    _git(tpl, "init", "-q", "-b", "main", home=home)
    (tpl / "a.py").write_text("x = 1\nprint(x)\n")
    (tpl / "run.sh").write_text("#!/bin/sh\n")
    os.chmod(tpl / "run.sh", 0o755)
    (tpl / "sub").mkdir()
    (tpl / "sub" / "b.txt").write_text("b\n")
    _git(tpl, "add", "-A", home=home)
    _git(tpl, "commit", "-qm", "base", home=home)
    (tpl / "a.py").write_text("x = 2\n\nprint(x)\n")  # modified tracked file
    (tpl / "new.py").write_text("y = 1\n")  # untracked
    marker = root / "MARKER"
    script = root / "marker.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n")
    os.chmod(script, 0o755)
    hooks = root / "hooks"
    hooks.mkdir()
    for name in ("pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "post-checkout", "post-merge", "post-rewrite", "post-index-change",
                 "reference-transaction", "pre-push", "fsmonitor-watchman", "applypatch-msg", "pre-applypatch", "post-applypatch"):
        (hooks / name).write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(hooks / name, 0o755)
    benign_hooks = root / "benign-hooks"
    benign_hooks.mkdir()
    excl = root / "excl"
    excl.write_text("new.py\n")
    elsewhere = root / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "other.txt").write_text("other\n")
    inc = root / "inc.cfg"
    inc.write_text(f"[core]\n\tfsmonitor = {script}\n")
    return dict(root=root, home=home, tpl=tpl, marker=marker, script=script, hooks=hooks, benign_hooks=benign_hooks, excl=excl, elsewhere=elsewhere, inc=inc,
                tree=tree_oid(_git(tpl, "rev-parse", "HEAD^{tree}", home=home)))


@pytest.fixture(autouse=True)
def _fresh_marker(request):
    """The marker file is shared by the module; a test that fails before consuming it must not poison the next one."""
    if "world" in request.fixturenames:
        m = request.getfixturevalue("world")["marker"]
        if m.exists():
            m.unlink()
    yield


def clone_tpl(world, dest: Path) -> Path:
    shutil.copytree(world["tpl"], dest, symlinks=True)
    return dest


def set_config(repo: Path, text: str) -> None:
    (repo / ".git" / "config").write_text(text)


def marker_fired(world) -> bool:
    m = world["marker"]
    if m.exists():
        m.unlink()
        return True
    return False


# ----------------------------------------------------------------------------------------------------------------------------------------
# the corpus (review generator design)

ALLOWED_A = [r"core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks|compression)", r"user\.(name|email)",
             r"remote\..+\.(url|fetch|tagopt|pushurl)", r"branch\..+\.(remote|merge|rebase|vscode-merge-base)", r"submodule\.active", r"submodule\..+\.(url|active)", r"gc\.auto",
             r"commit\.gpgsign", r"pull\.rebase", r"push\.default", r"fetch\.prune", r"init\.defaultbranch", r"maintenance\..+", r"http\.(sslverify|proxy)",
             r"lfs\.url",
             # widened after the independent false-refusal review (f1218118)
             r"fetch\.prunetags", r"remote\..+\.(prune|prunetags|push|gh-resolved)", r"pull\.ff", r"push\.(autosetupremote|followtags)",
             r"branch\..+\.(pushremote|description)", r"branch\.(autosetuprebase|autosetupmerge)", r"rerere\.enabled", r"user\.signingkey",
             r"core\.untrackedcache", r"advice\..+"]
ALLOWED_P = [r"core\.hookspath", r"color\.(ui|diff|status|branch|interactive)", r"core\.abbrev", r"diff\.renames"]
_A = re.compile("^(" + "|".join(ALLOWED_A) + ")$")
_P = re.compile("^(" + "|".join(ALLOWED_P) + ")$")


def tier(key: str) -> str:
    k = key.lower()
    return "A" if _A.match(k) else "P" if _P.match(k) else "R"


BENIGN = {"core.repositoryformatversion": "0", "core.filemode": "true", "core.bare": "false", "core.logallrefupdates": "true", "core.ignorecase": "false",
          "core.precomposeunicode": "false", "core.symlinks": "true", "core.compression": "1", "user.name": "x", "user.email": "x@x.invalid", "url": "https://example.invalid/r.git",
          "pushurl": "https://example.invalid/p.git", "fetch": "+refs/heads/*:refs/remotes/o/*", "tagopt": "--no-tags", "remote": "origin", "merge": "refs/heads/main",
          "rebase": "true", "vscode-merge-base": "origin/main", "submodule.active": ".", "gc.auto": "6700", "commit.gpgsign": "false", "pull.rebase": "false",
          "push.default": "simple", "fetch.prune": "true", "init.defaultbranch": "main", "http.sslverify": "true", "http.proxy": "http://127.0.0.1:9", "lfs.url": "https://example.invalid/lfs",
          "core.abbrev": "7", "fetch.prunetags": "true", "prune": "true", "prunetags": "true", "push": "refs/heads/main", "gh-resolved": "base",
          "pull.ff": "only", "push.autosetupremote": "true", "push.followtags": "true", "pushremote": "origin", "description": "a branch description",
          "branch.autosetuprebase": "never", "branch.autosetupmerge": "true", "rerere.enabled": "true", "user.signingkey": "ABCDEF12", "core.untrackedcache": "true"}
_EXEC_SUFFIX = re.compile(r"(command|program|helper|hook|hooks|pager|editor|path|file|dir|script|cmd|tool|driver|textconv|clean|smudge|process)$")
_BOOLISH = re.compile(r"^(enable|use|allow|auto|ignore|show|prune|sign|verify|track|detect|follow|warn|safe|quick|strict|verbose|optional|force|require)")


def benign_value(key: str, world) -> str:
    k = key.lower()
    var = k.rsplit(".", 1)[-1]
    if k.startswith("maintenance."):
        return {"auto": "false", "strategy": "incremental", "enabled": "true", "schedule": "weekly"}.get(var, "false")
    if k.startswith(("color.", "advice.")):
        return "false"
    if k == "core.hookspath":
        return str(world["benign_hooks"])
    if k in BENIGN:
        return BENIGN[k]
    if k == "diff.renames":
        return "true"
    if k.startswith("submodule.") and var == "active":  # submodule.<name>.active is a bool (submodule.active itself is a pathspec, handled above)
        return "true"
    if k.startswith(("remote.", "branch.", "submodule.")) and var in BENIGN:
        return BENIGN[var]
    return BENIGN[k]


def hostile_value(key: str, world) -> str:
    var = key.rsplit(".", 1)[-1].lower()
    if _EXEC_SUFFIX.search(var):
        return str(world["script"])
    if _BOOLISH.match(var):
        return "true"
    return "x"


PLACEHOLDER = re.compile(r"<[a-z0-9-]+>")
SUBS = ("hlith", "HlithX", "a.b")


def load_doc_names() -> list[str]:
    cp = subprocess.run(["git", "help", "--config"], capture_output=True, env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", "PAGER": "cat", "GIT_PAGER": "cat",
                                                                               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
    assert cp.returncode == 0, cp.stderr
    valid = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9<>*_-]+)+$")  # `git help --config` also prints a footer line ("'git help config' for more information")
    return sorted({ln.strip() for ln in cp.stdout.decode().splitlines() if valid.match(ln.strip())})


def expand(name: str) -> list[str]:
    if "*" in name:
        name = name.replace("*", "hlith")
    if not PLACEHOLDER.search(name):
        return [name]
    return [PLACEHOLDER.sub(s, name) for s in SUBS]


def split_key(key: str) -> tuple[str, str, str]:
    parts = key.split(".")
    return parts[0], ".".join(parts[1:-1]), parts[-1]


def cfg_text(entries: list[tuple[str, str | None]]) -> str:
    """BASE_CONFIG (minus colliding vars) + [section "sub"] var = "value" (value None -> valueless key)."""
    drop = {k.lower() for k, _ in entries}
    base = [ln for ln in BASE_CONFIG.splitlines(keepends=True) if ln.startswith("[") or ("core." + ln.split("=")[0].strip().lower()) not in drop]
    out = "".join(base)
    for key, val in entries:
        sec, sub, var = split_key(key)
        out += f'[{sec} "{sub}"]\n' if sub else f"[{sec}]\n"
        out += f"\t{var}\n" if val is None else '\t%s = "%s"\n' % (var, val.replace("\\", "\\\\").replace('"', '\\"'))
    return out


def build_cases(world) -> list[dict]:
    names = load_doc_names()
    cases: list[dict] = []
    seen = set()

    def add(key: str, label: str, value: str | None = ..., expect: str | None = None):
        t = tier(key)
        v = (benign_value(key, world) if t != "R" else hostile_value(key, world)) if value is ... else value
        ident = (key, v)
        if ident in seen:
            return
        seen.add(ident)
        cases.append(dict(id=f"{label}:{key}", key=key, value=v, tier=t, expect=expect or ("pass" if t != "R" else "refuse")))

    for i, n in enumerate(names):
        for k in expand(n):
            add(k, "doc")
            if i % 7 == 0 or re.search(r"command|program|helper|hook|pager|editor|ssh|gpg|filter|driver|proxy|path|worktree|include|alternate", n, re.I):
                sec, sub, var = split_key(k)
                add(".".join(filter(None, [sec.lower(), sub, var.lower()])), "lower")
                add(".".join(filter(None, [sec.upper(), sub, var.upper()])), "UPPER")
    for sec in sorted({n.split(".")[0] for n in names}):
        add(f"{sec}.hlithunknown", "invented", "x" if tier(f"{sec}.hlithunknown") == "R" else ...)  # advice.* / maintenance.* accept any name (value stays benign)
    add("hlithsection.x", "invented", "x")
    for k in ("remote.origin.gh-resolved", "advice.hlithunknownhint", "core.editor", "core.autocrlf",
              "extensions.partialclone", "lfs.concurrenttransfers", "lfs.url", "filter.lfs.clean", "filter.lfs.smudge", "filter.lfs.process", "filter.lfs.required",
              "branch.main.vscode-merge-base", "core.hlithunknown", "remote.origin.promisor", "remote.origin.partialclonefilter"):
        add(k, "omitted")
    return cases


HOSTILE_VALUES = [  # (label, key, value-template) on keys that ARE allowed: the VALUE must be vetted (section 9 / 13)
    ("rfv1", "core.repositoryformatversion", "1"), ("bare-true", "core.bare", "true"), ("filemode-junk", "core.filemode", "banana"),
    ("logref-junk", "core.logallrefupdates", "maybe"), ("ignorecase-junk", "core.ignorecase", "banana"),
    ("url-ext", "remote.origin.url", "ext::sh -c 'touch {marker}'"), ("url-dash", "remote.origin.url", "-oProxyCommand=touch {marker}"),
    ("url-helper", "remote.origin.url", "evil::payload"), ("url-ctrl", "remote.origin.url", "https://example.invalid/\x07x"),
    ("sub-url-ext", "submodule.lib.url", "ext::sh -c 'touch {marker}'"), ("sub-url-dash", "submodule.lib.url", "-oProxyCommand=touch {marker}"),
    ("sub-url-helper", "submodule.lib.url", "evil::payload"), ("sub-active-junk", "submodule.lib.active", "banana"),
    ("pushurl-ext", "remote.origin.pushurl", "ext::sh -c 'touch {marker}'"), ("merge-dash", "branch.main.merge", "--upload-pack=x"), ("remote-dash", "branch.main.remote", "-x"),
]


@pytest.fixture(scope="module")
def corpus_run(world, tmp_path_factory):
    """Run every corpus case through BOTH vet seams once (spawn spy on); the tests below assert one dimension each."""
    repo = tmp_path_factory.mktemp("x2corpus") / "r"
    clone_tpl(world, repo)
    cases = build_cases(world)
    for label, key, tpl_val in HOSTILE_VALUES:
        cases.append(dict(id=f"value:{label}", key=key, value=tpl_val.format(marker=world["marker"]), tier="A", expect="refuse"))
    results = []
    spy_calls: list = []
    real = _REAL_POPEN

    class _P(real):
        def __init__(self, args, *a, **kw):
            spy_calls.append((list(args) if not isinstance(args, (str, bytes)) else [args], kw.get("cwd")))
            super().__init__(args, *a, **kw)

    subprocess.Popen = _P  # module scope: monkeypatch fixture is function scoped, so restore by hand
    t0 = time.monotonic()
    try:
        for case in cases:
            set_config(repo, cfg_text([(case["key"], case["value"])]))
            before = tree_hash(repo)
            row = dict(case=case)
            for seam, fn in (("vet_a", lambda: HardenedGitRead().repository_hostile_reason(repo)), ("vet_b", lambda: gitq.refusal(repo))):
                del spy_calls[:]
                try:
                    res = fn()
                    row[seam] = res
                except REFUSAL_EXC as e:
                    row[seam] = f"EXC {type(e).__name__}: {e}"
                row[seam + "_git"] = git_violations(spy_calls, repo)
            row["hash_changed"] = tree_hash(repo) != before
            row["marker"] = marker_fired(world)
            results.append(row)
    finally:
        subprocess.Popen = real
    return dict(rows=results, seconds=time.monotonic() - t0, repo=repo)


def _fmt(bad: list[str], what: str) -> str:
    return f"{len(bad)} case(s) {what}; first: " + "; ".join(bad[:5])


def test_corpus_shape(corpus_run):
    rows = corpus_run["rows"]
    keys = {r["case"]["key"].lower() for r in rows}
    assert len(rows) >= 1200, len(rows)
    assert sum(1 for r in rows if r["case"]["id"].startswith("invented")) >= 40
    for must in ("core.fsmonitor", "core.worktree", "core.hookspath", "include.path", "extensions.worktreeconfig", "core.alternaterefscommand", "core.hlithunknown", "extensions.partialclone"):
        assert must in keys, must
    assert any(r["case"]["tier"] == "P" for r in rows) and any(r["case"]["tier"] == "A" for r in rows)
    assert corpus_run["seconds"] < 60, f"corpus took {corpus_run['seconds']:.0f}s"


@pytest.mark.parametrize("seam", ["vet_a", "vet_b"])
def test_corpus_not_allowlisted_keys_are_refused(corpus_run, seam):
    """Closed world: EVERY documented key not on the allowlist (and invented/omitted keys) is refused by BOTH vets."""
    bad = [r["case"]["id"] for r in corpus_run["rows"] if r["case"]["expect"] == "refuse" and not r[seam]]
    assert not bad, _fmt(bad, f"ACCEPTED by {seam} (hostile/unknown key not refused)")


@pytest.mark.parametrize("seam", ["vet_a", "vet_b"])
def test_corpus_allowlisted_keys_pass_with_benign_values(corpus_run, seam):
    """Tier A/P keys with benign values must NOT be refused (a false refusal is a product defect, X11)."""
    bad = [f"{r['case']['id']} -> {str(r[seam])[:60]}" for r in corpus_run["rows"] if r["case"]["expect"] == "pass" and r[seam]]
    assert not bad, _fmt(bad, f"FALSELY REFUSED by {seam}")


@pytest.mark.parametrize("seam", ["vet_a", "vet_b"])
def test_corpus_vet_starts_no_git_in_the_repository(corpus_run, seam):
    """The vet may only run `git config --file <path>`: no process with cwd/-C/--git-dir/--work-tree inside the untrusted repository (X7 oracle)."""
    bad = [f"{r['case']['id']}: {r[seam + '_git'][0]}" for r in corpus_run["rows"] if r[seam + "_git"]]
    assert not bad, _fmt(bad, f"started git inside the repository during {seam}")


def test_corpus_no_marker_and_target_unchanged(corpus_run):
    assert not [r["case"]["id"] for r in corpus_run["rows"] if r["marker"]], "a repository-chosen program ran during the vet"
    bad = [r["case"]["id"] for r in corpus_run["rows"] if r["hash_changed"]]
    assert not bad, _fmt(bad, "changed the target (X9: config/index/HEAD/refs/objects/worktree or index/HEAD mtime)")


def test_clean_repository_passes_both_vets(world, tmp_path):
    repo = clone_tpl(world, tmp_path / "r")
    assert HardenedGitRead().repository_hostile_reason(repo) is None
    assert gitq.refusal(repo) is None


@pytest.mark.parametrize("label,key,tpl_val", HOSTILE_VALUES, ids=[h[0] for h in HOSTILE_VALUES])
@pytest.mark.parametrize("seam", ["vet_a", "vet_b"])
def test_allowed_key_with_hostile_value_is_refused(world, tmp_path, label, key, tpl_val, seam):
    """VALUE checks on allowlisted keys: rfv must be 0, bare false, strict bool, url without <helper>:: / leading '-' / control chars."""
    repo = clone_tpl(world, tmp_path / "r")
    set_config(repo, cfg_text([(key, tpl_val.format(marker=world["marker"]))]))
    out = HardenedGitRead().repository_hostile_reason(repo) if seam == "vet_a" else gitq.refusal(repo)
    assert out, f"{key}={tpl_val!r} accepted by {seam}"
    assert not marker_fired(world)


# ---- Tier P: allowed ONLY because the choke point pins it on every spawn (each proven by a marker / byte-identity test) ------------------------


def _hooks_repo(world, tmp_path) -> Path:
    repo = clone_tpl(world, tmp_path / "hk")
    set_config(repo, cfg_text([("core.hookspath", str(world["hooks"]))]))
    return repo


def test_tier_p_hookspath_marker_dir_is_allowed_by_the_vet(world, tmp_path):
    repo = _hooks_repo(world, tmp_path)
    assert HardenedGitRead().repository_hostile_reason(repo) is None, "core.hooksPath is Tier P: allowed (husky repos are real targets)"
    assert gitq.refusal(repo) is None
    assert not marker_fired(world)


@pytest.mark.parametrize("args", [("status", "--porcelain=v1"), ("diff", "--no-ext-diff", "HEAD"), ("log", "-1", "--format=%H"), ("rev-parse", "HEAD"), ("ls-tree", "-r", "HEAD")])
def test_tier_p_hookspath_reads_run_and_fire_no_hook(world, tmp_path, args):
    """Reads (incl. status, which refreshes the index and would run post-index-change) work on a husky-style repo and never run a hook."""
    clean = clone_tpl(world, tmp_path / "clean")
    expected = safe_git_read(clean, *args)
    repo = _hooks_repo(world, tmp_path)
    os.utime(repo / "a.py", ns=(1_000_000_000_000_000_000,) * 2)  # force a stat refresh
    assert safe_git_read(repo, *args) == expected, "false refusal or different data on a hooksPath repo"
    assert gitq.text(repo, *args) == gitq.text(clean, *args)
    assert not marker_fired(world), "a hook in core.hooksPath ran during a READ"


def test_tier_p_hookspath_writes_fire_no_hook(world, tmp_path):
    """Writer path: commit and commit-tree+update-ref (reference-transaction) with a marker hook dir. Green on bfaeb00c (writes pin /dev/null): must stay green."""
    from hlith.gate.git_write import commit_staged, commit_tree_cas, head_commit

    repo = _hooks_repo(world, tmp_path)
    _git(repo, "add", "-A", home=world["home"])
    commit_staged(repo, "marker test commit")
    assert not marker_fired(world), "commit ran a hook from core.hooksPath"
    (repo / "c.txt").write_text("c\n")
    _git(repo, "add", "-A", home=world["home"])
    tree = _git(repo, "write-tree", home=world["home"])
    commit_tree_cas(repo, tree, head_commit(repo), "marker test commit-tree")
    assert not marker_fired(world), "update-ref ran reference-transaction from core.hooksPath"


_SHAPING = [("color.ui", "always"), ("color.diff", "always"), ("color.status", "always"), ("color.branch", "always"), ("color.interactive", "always"), ("core.abbrev", "12")]
_SHAPED_CMDS = [("diff", "--no-ext-diff", "HEAD"), ("status", "-s"), ("log", "-1", "--oneline"), ("rev-parse", "--short", "HEAD"), ("branch", "-v")]


@pytest.mark.parametrize("val", ["false", "copies"])
@pytest.mark.parametrize("runner", ["safe_git_read", "gitq"])
def test_tier_p_diff_renames_is_pinned(world, tmp_path, val, runner):
    """diff.renames is Tier P: allowed, pinned to true. A staged rename must read identically whatever the repo sets."""
    repos = []
    for name, cfg in (("clean", None), ("shaped", val)):
        r = clone_tpl(world, tmp_path / name)
        _git(r, "mv", "sub/b.txt", "sub/c.txt", home=world["home"])
        if cfg:
            set_config(r, cfg_text([("diff.renames", cfg)]))
        repos.append(r)
    args = ("diff", "--no-ext-diff", "--cached", "HEAD")
    run = (lambda r: safe_git_read(r, *args)) if runner == "safe_git_read" else (lambda r: gitq.text(r, *args))
    want, got = run(repos[0]), run(repos[1])
    assert "rename from" in want
    assert got == want, f"diff.renames={val} changed the read (not pinned)"


@pytest.mark.parametrize("key,val", _SHAPING, ids=[k for k, _ in _SHAPING])
@pytest.mark.parametrize("args", _SHAPED_CMDS, ids=[a[0] for a in _SHAPED_CMDS])
@pytest.mark.parametrize("runner", ["safe_git_read", "gitq"])
def test_tier_p_output_shaping_is_pinned(world, tmp_path, key, val, args, runner):
    """color.*=always / core.abbrev must not reshape any read: output byte-identical to the clean-config output, and no ANSI (F3)."""
    clean = clone_tpl(world, tmp_path / "clean")
    shaped = clone_tpl(world, tmp_path / "shaped")
    set_config(shaped, cfg_text([(key, val)]))
    run = (lambda r: safe_git_read(r, *args)) if runner == "safe_git_read" else (lambda r: gitq.text(r, *args))
    want, got = run(clean), run(shaped)
    assert "\x1b[" not in got, f"{key}={val}: ANSI in {args[0]} output"
    assert got == want, f"{key}={val} changed the output of {args[0]}"


# ---- ~10 representative hostiles through EVERY entrypoint (X10) ---------------------------------------------------------------------------

REPS = {
    "fsmonitor": ("[core]\n\tfsmonitor = {script}\n", None, set()),
    "worktree": ("[core]\n\tworktree = {elsewhere}\n", None, {"identity"}),
    "include": ("[include]\n\tpath = {inc}\n", None, set()),
    "invented": ("[core]\n\thlithunknown = 1\n", None, set()),
    "inline-header": ("[core] fsmonitor = {script}\n", None, set()),
    "valueless": ("[core]\n\tfsmonitor\n", None, set()),
    "continuation": ("[core]\n\tfsmon\\\nitor = {script}\n", None, set()),
    "partialclone": ("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tpartialclone = origin\n[remote \"origin\"]\n\turl = https://example.invalid/x\n\tpromisor = true\n", None, set()),
    "autocrlf": ("[core]\n\tautocrlf = true\n", None, set()),
    "excludes": ("[core]\n\texcludesFile = {excl}\n", None, set()),
    "filter-attr": ("[filter \"evil\"]\n\tclean = {script}\n\tsmudge = {script}\n", ".gitattributes", set()),
    "bare": ("[core]\n\tbare = true\n", None, {"identity"}),
    "protocol": ("[protocol \"ext\"]\n\tallow = always\n", None, set()),
}


def _rep_repo(world, tmp_path, name: str) -> Path:
    text, extra, _tags = REPS[name]
    repo = clone_tpl(world, tmp_path / "hostile")
    set_config(repo, BASE_CONFIG + text.format(script=world["script"], elsewhere=world["elsewhere"], inc=world["inc"], excl=world["excl"]))
    if extra:
        (repo / extra).write_text("* filter=evil\n")
    return repo


def _ep_safe_git_read(repo, w, tmp):
    return refuses(lambda: safe_git_read(repo, "status", "--porcelain=v1"))


def _ep_head_tree(repo, w, tmp):
    return refuses(lambda: HardenedGitRead().head_tree(repo))


def _ep_export_tree(repo, w, tmp):
    return refuses(lambda: HardenedGitRead().export_tree(repo, w["tree"], tmp / "exported"))


def _ep_gitq_git_check(repo, w, tmp):
    return refuses(lambda: gitq.git(repo, "status", "--porcelain=v1", check=True) or None)


def _ep_gitq_git_nocheck(repo, w, tmp):
    out = gitq.git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    return out == b"", f"returned {out[:40]!r}"


def _ep_gitq_text(repo, w, tmp):
    out = gitq.text(repo, "rev-parse", "HEAD")
    return out == "", f"returned {out[:40]!r}"


def _ep_gitq_popen(repo, w, tmp):
    def go():
        p = gitq.popen(repo, ["diff", "HEAD"])
        p.kill()
        p.wait()
        return p
    return refuses(go)


def _ep_gitq_refusal(repo, w, tmp):
    r = gitq.refusal(repo)
    return bool(r), f"refusal={r!r}"


def _ep_toplevel(repo, w, tmp):
    root, why = gitq.toplevel(repo)
    return root is None, f"toplevel={root}"


def _ep_seal_base(repo, w, tmp):
    return refuses(lambda: LocalSnapshotService(root=tmp / "seal").seal_base(repo))


ENTRYPOINTS = {"safe_git_read": _ep_safe_git_read, "head_tree": _ep_head_tree, "export_tree": _ep_export_tree, "gitq.git(check)": _ep_gitq_git_check,
               "gitq.git": _ep_gitq_git_nocheck, "gitq.text": _ep_gitq_text, "gitq.popen": _ep_gitq_popen, "gitq.refusal": _ep_gitq_refusal,
               "gitq.toplevel": _ep_toplevel, "seal_base": _ep_seal_base}


@pytest.mark.parametrize("ep", sorted(ENTRYPOINTS))
@pytest.mark.parametrize("rep", sorted(REPS))
def test_hostile_representative_is_refused_at_every_entrypoint(world, tmp_path, rep, ep):
    if ep == "gitq.toplevel" and "identity" not in REPS[rep][2]:
        pytest.skip("toplevel vets the repository SHAPE/IDENTITY only (design section 11)")
    repo = _rep_repo(world, tmp_path, rep)
    before = tree_hash(repo)
    ok, detail = ENTRYPOINTS[ep](repo, world, tmp_path)
    assert ok, f"{rep} via {ep}: NOT refused ({detail})"
    assert not marker_fired(world), f"{rep} via {ep}: a repository-chosen program ran"
    assert tree_hash(repo) == before, f"{rep} via {ep}: the hostile target was modified (X9)"


@pytest.mark.parametrize("rep", sorted(REPS))
def test_seal_base_hostile_target_touched_only_by_config_file(world, tmp_path, monkeypatch, rep):
    """X7: no git process starts in/with the target before the vet passes; the only allowed process is `git config --file`."""
    repo = _rep_repo(world, tmp_path, rep)
    spy = SpawnSpy().install(monkeypatch)
    refused, detail = refuses(lambda: LocalSnapshotService(root=tmp_path / "seal").seal_base(repo))
    bad = git_violations(spy.calls, repo)
    assert refused, f"{rep}: seal_base did not refuse ({detail})"
    assert not bad, f"{rep}: git ran inside the hostile target before/without the vet: {bad[0]}"


@pytest.mark.parametrize("rep", ["fsmonitor", "include", "invented", "partialclone", "autocrlf", "excludes", "bare"])
def test_capture_diff_stage_refuses_hostile_live_target_before_the_fetch(world, tmp_path, monkeypatch, rep):
    """Seam C: agent.capture._diff_stage fetches from the LIVE target (upload-pack runs inside it): it must be vetted first."""
    from hlith.agent import capture

    repo = _rep_repo(world, tmp_path, rep)
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "a.py").write_text("x = 1\nprint(x)\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    spy = SpawnSpy().install(monkeypatch)
    try:
        capture._diff_stage(repo, stage, scratch)
        raised = False
    except Exception:  # noqa: BLE001 - any refusal counts; the spy below decides whether it came BEFORE the fetch
        raised = True
    fetched = [" ".join(map(str, a))[:140] for a, _ in spy.calls if a and os.path.basename(str(a[0])) == "git" and "fetch" in a and any(str(repo) in str(x) for x in a)]
    assert not fetched, f"{rep}: git fetch ran against the hostile live target: {fetched[0]}"
    assert raised, f"{rep}: _diff_stage returned a diff for a hostile target"
    assert not marker_fired(world)


def test_capture_scratch_holds_no_copy_of_the_targets_git_config(world, tmp_path):
    """X9 addition: after a successful _diff_stage on a clean target the scratch/stage dirs contain no copy of the target's .git/config."""
    from hlith.agent import capture

    repo = clone_tpl(world, tmp_path / "t")
    set_config(repo, cfg_text([("user.name", "UNIQUE-NAME-123")]))
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "a.py").write_text("x = 1\nprint(x)\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    try:
        capture._diff_stage(repo, stage, scratch)
    except Exception:  # noqa: BLE001 - the scratch contents are what is asserted
        pass
    leaked = [str(p) for p in list(scratch.rglob("*")) + list(stage.rglob("*")) if p.is_file() and b"UNIQUE-NAME-123" in p.read_bytes()]
    assert not leaked, f"target config copied into {leaked[0]}"


# ---- X6: fail closed on spawn failure / timeout / non-zero exit ------------------------------------------------------------------------------


class _FakePopen:
    def __init__(self, args, mode, record):
        self.args, self.mode, self.pid, self.returncode = args, mode, 4194303, None
        self.stdin = self.stderr = None
        self.stdout = io.BytesIO(b"")
        self._timed_out = False
        record.append((list(args), None))

    def communicate(self, input=None, timeout=None):
        if self.mode == "hang" and not self._timed_out:
            self._timed_out = True
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        self.returncode = -9 if self.mode == "hang" else 128
        return b"", b"fatal: simulated failure"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = -9
        return self.returncode

    def kill(self):
        self.returncode = -9

    terminate = kill

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install_fake(monkeypatch, mode: str) -> list:
    record: list = []

    def factory(args, *a, **kw):
        if args and os.path.basename(str(args[0])) == "git":
            if mode == "oserror":
                raise OSError(2, "simulated spawn failure")
            return _FakePopen(args, mode, record)
        return _REAL_POPEN(args, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", factory)
    monkeypatch.setattr(os, "killpg", lambda *a, **k: None)
    return record


X6_ENDPOINTS = {
    "gitq.refusal": lambda r, w, t: (bool(gitq.refusal(r)), "refusal returned None (repository treated as OK)"),
    "gitq.git(check)": lambda r, w, t: refuses(lambda: gitq.git(r, "rev-parse", "HEAD", check=True) or None),
    "gitq.popen": lambda r, w, t: refuses(lambda: gitq.popen(r, ["diff", "HEAD"])),
    "safe_git_read": lambda r, w, t: refuses(lambda: safe_git_read(r, "rev-parse", "HEAD")),
    "head_tree": lambda r, w, t: refuses(lambda: HardenedGitRead().head_tree(r)),
    "export_tree": lambda r, w, t: refuses(lambda: HardenedGitRead().export_tree(r, w["tree"], t / "exp")),
    "seal_base": lambda r, w, t: refuses(lambda: LocalSnapshotService(root=t / "seal").seal_base(r)),
    "repository_hostile_reason": lambda r, w, t: (bool(HardenedGitRead().repository_hostile_reason(r)), "vet returned None under failure"),
}


@pytest.mark.parametrize("ep", sorted(X6_ENDPOINTS))
@pytest.mark.parametrize("mode", ["oserror", "hang", "nonzero"])
def test_x6_spawn_failure_timeout_or_nonzero_is_a_refusal_never_data(world, tmp_path, monkeypatch, mode, ep):
    repo = clone_tpl(world, tmp_path / "r")
    _install_fake(monkeypatch, mode)
    ok, detail = X6_ENDPOINTS[ep](repo, world, tmp_path)
    assert ok, f"{ep} under {mode}: not a refusal ({detail})"


def test_x6_real_cyclic_include_is_refused_by_every_vet(world, tmp_path):
    """A REAL non-zero `git config --list` (cyclic [include]): gitq.refusal must not fail open (Seam A, observed by review)."""
    repo = clone_tpl(world, tmp_path / "r")
    (repo / ".git" / "cyc").write_text("[include]\n\tpath = cyc\n")
    set_config(repo, BASE_CONFIG + "[include]\n\tpath = cyc\n")
    assert HardenedGitRead().repository_hostile_reason(repo), "HardenedGitRead accepted a cyclic include"
    assert gitq.refusal(repo), "gitq.refusal returned None for a config git cannot read (fails OPEN)"
    assert gitq.git(repo, "status", "--porcelain=v1") == b""
    assert refuses(lambda: gitq.git(repo, "status", check=True) or None)[0]


@pytest.mark.parametrize("ep", ["safe_git_read", "head_tree", "export_tree", "gitq.git", "gitq.refusal", "seal_base"])
def test_x6_every_git_spawn_carries_a_timeout(world, tmp_path, monkeypatch, ep):
    repo = clone_tpl(world, tmp_path / "r")
    seen: list = []

    class _Rec(_REAL_POPEN):
        def communicate(self, input=None, timeout=None):
            seen.append((" ".join(map(str, self.args))[:120], timeout))
            return super().communicate(input, timeout)

    monkeypatch.setattr(subprocess, "Popen", _Rec)
    calls = {"safe_git_read": lambda: safe_git_read(repo, "rev-parse", "HEAD"), "head_tree": lambda: HardenedGitRead().head_tree(repo),
             "export_tree": lambda: HardenedGitRead().export_tree(repo, world["tree"], tmp_path / "exp"), "gitq.git": lambda: gitq.git(repo, "rev-parse", "HEAD"),
             "gitq.refusal": lambda: gitq.refusal(repo), "seal_base": lambda: LocalSnapshotService(root=tmp_path / "seal").seal_base(repo)}
    calls[ep]()
    gits = [(c, t) for c, t in seen if c.split(" ", 1)[0].endswith("git")]
    assert gits, "no git spawn observed"
    missing = [c for c, t in gits if t is None]
    assert not missing, f"{ep}: {len(missing)} git spawn(s) without a timeout, e.g. {missing[0]}"


# ---- review falsifiers F1/F2 (red on bfaeb00c, mandatory per section 13) ------------------------------------------------------------------------


def test_f1_replace_ref_cannot_substitute_the_tree_a_read_returns(world, tmp_path):
    repo = clone_tpl(world, tmp_path / "r")
    home = world["home"]
    true_tree = _git(repo, "--no-replace-objects", "rev-parse", "HEAD^{tree}", home=home)
    (repo / "a.py").write_text("x = 'EVIL'\n")
    _git(repo, "add", "a.py", home=home)
    evil = _git(repo, "commit-tree", _git(repo, "write-tree", home=home), "-m", "evil", home=home)
    _git(repo, "replace", _git(repo, "--no-replace-objects", "rev-parse", "HEAD", home=home), evil, home=home)
    got = refuses(lambda: HardenedGitRead().head_tree(repo))
    if not got[0]:
        assert str(HardenedGitRead().head_tree(repo)) == true_tree, "head_tree returned the REPLACED tree (refs/replace not neutralised)"
        dest = tmp_path / "exp"
        HardenedGitRead().export_tree(repo, tree_oid(true_tree), dest)
        assert (dest / "a.py").read_text() == "x = 1\nprint(x)\n", "export_tree wrote content substituted by a replace ref"
    assert gitq.text(repo, "rev-parse", "HEAD^{tree}") in ("", true_tree), "gitq described the REPLACED tree"


def test_safe_git_read_diff_works_on_an_ordinary_repository(world, tmp_path):
    """Found while writing X2: `-c diff.external=` (empty) in _HARDEN makes a plain `diff` die ('cannot run : No such file') on any repo with a modified
    tracked file. The pin must not break the read (use --no-ext-diff / a valid neutral value). Positive control for X11."""
    repo = clone_tpl(world, tmp_path / "r")
    out = safe_git_read(repo, "diff", "HEAD")
    assert "a.py" in out and "+x = 2" in out


def test_f2_reads_never_rewrite_the_index(world, tmp_path):
    """safe_git_read(status) lacks GIT_OPTIONAL_LOCKS=0 and refreshes .git/index; the gitq control already does not."""
    repo = clone_tpl(world, tmp_path / "r")
    idx = repo / ".git" / "index"
    os.utime(repo / "a.py", ns=(1_000_000_000_000_000_000,) * 2)
    before = (idx.read_bytes(), idx.stat().st_mtime_ns)
    safe_git_read(repo, "status", "--porcelain=v1", "--untracked-files=no")
    HardenedGitRead().head_tree(repo)
    gitq.git(repo, "status", "--porcelain=v1")
    assert (idx.read_bytes(), idx.stat().st_mtime_ns) == before, "a read rewrote .git/index (X9: reads must be byte-identical, mtime included)"
