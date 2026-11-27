# SPDX-License-Identifier: Apache-2.0
"""RED-FIRST falsifiers X3/X3b/X4/X5/X5b (+X9 index preservation, F1/F2) for the Git-read structural fix (design note).

Self-contained: inline helpers, no shared module. Every hostile case is built on a throwaway repository under pytest's tmp_path and is judged
only through seams that exist before AND after the change: HardenedGitRead().repository_hostile_reason/head_tree/export_tree,
hostio.git_read.safe_git_read, operator.gitq refusal/git/popen/toplevel, LocalSnapshotService().seal_base, gate.git_write.run_target_git,
operator.tui.changes.branches/uncommitted.

Oracle per hostile case (no exact reason text is asserted):
  1. the marker file (touched by a repository- or environment-chosen program) does not exist,
  2. the call did not hang (a blocking open of a FIFO is a failure, not a pass),
  3. the call REFUSED (non-None reason / HostIntegrityError / RuntimeError / OSError / ValueError),
  4. the hostile target is byte-identical afterwards (X9: .git, worktree, index bytes AND mtime; no lock/cache debris).
Positive controls (clean repositories must still be read correctly) keep a trivially-refusing implementation from passing.

Named decision hook: NAMED_FALSE_REFUSAL_ATTRS. The X5b design removes the attribute-file scan, so an
executable-looking attribute with NO matching config must NOT be refused. If design review restores the scan as defence in depth the false refusal
is named and these `not_falsely_refused` cases become expected failures (set the flag True; the no-marker cases keep running).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import threading
from pathlib import Path

import pytest

from hlith.contract.identities import tree_oid
from hlith.gate import git_write
from hlith.hostio.git_read import HardenedGitRead, safe_git_read
from hlith.hostio.integrity import HostIntegrityError
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.operator import gitq
from hlith.operator.tui import changes

NAMED_FALSE_REFUSAL_ATTRS = False
REFUSED = (HostIntegrityError, RuntimeError, OSError, ValueError)
HUNG = "HUNG: the call did not return (blocking open / no timeout)"
CMDS = (("status", "--porcelain"), ("diff", "--no-ext-diff"))  # diff runs textconv; stat-dirty files make `status` run clean filters. (plain `diff` dies on the old code: `-c diff.external=` makes git run an empty program)
MIB = 1024 * 1024

# ----------------------------------------------------------------------------------------------------------------- building blocks


def _clean_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": "/nonexistent-hlith-test-home", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid",
        "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z",
    }


def g(cwd, *args: str, input: bytes | None = None) -> str:
    """Test-side git for BUILDING fixtures only (never used as an oracle)."""
    cp = subprocess.run(["git", "-C", str(cwd), *args], input=input, capture_output=True, env=_clean_env(), check=True)
    return cp.stdout.decode("utf-8", "replace").strip()


def tree_state(root: Path) -> dict:
    """Everything under root, without following symlinks and without opening FIFOs: type, content hash / link target, index mtime."""
    out: dict = {}
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files + [x for x in dirs if os.path.islink(os.path.join(d, x))]):
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256(Path(p).read_bytes()).hexdigest()
                out[rel] = ("file", h, st.st_mtime_ns if rel.endswith(os.path.join(".git", "index")) or rel == os.path.join(".git", "index") else 0)
            else:
                out[rel] = ("special", stat.S_IFMT(st.st_mode))
        for x in dirs:
            if not os.path.islink(os.path.join(d, x)):
                out[os.path.relpath(os.path.join(d, x), root) + "/"] = ("dir",)
    return out


def _deadline(fn, secs: float):
    box: dict = {}

    def run():
        try:
            box["v"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below in the caller's thread
            box["e"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(secs)
    if t.is_alive():
        return HUNG
    if "e" in box:
        raise box["e"]
    return box["v"]


def _refuse(fn):
    try:
        fn()
    except REFUSED as exc:
        return f"{type(exc).__name__}: {exc}"[:200]
    return None


class Ctx:
    def __init__(self, root: Path, template: dict) -> None:
        self.root = root
        self.w = root / "w"          # everything the target and its neighbours live in: snapshotted for X9
        self.out = root / "out"      # marker, scripts, export/seal outputs: outside the snapshot
        self.w.mkdir()
        self.out.mkdir()
        self.repo = self.w / "repo"
        shutil.copytree(template["dir"], self.repo, symlinks=True)
        self.tree, self.head = template["tree"], template["head"]
        self.marker = self.out / "MARKER"
        self.script = self._script("marker.sh", f': > "{self.marker}"\nexit 0\n')
        self.filter_script = self._script("filter.sh", f': > "{self.marker}"\ncat\n')
        self.textconv_script = self._script("textconv.sh", f': > "{self.marker}"\ncat "$1"\n')
        self.fifos: list[Path] = []
        self._victim: Path | None = None
        # one unstaged edit (shows in diff) and stat-dirty tracked files (status must re-hash them: that is where clean filters run)
        (self.repo / "a.py").write_text("x = 2\n")
        for rel in ("c.py", "sub/b.py", ".hlith/x.py"):
            os.utime(self.repo / rel, (1_700_000_000, 1_700_000_000))

    def _script(self, name: str, body: str) -> Path:
        p = self.out / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)
        return p

    def victim(self) -> Path:
        if self._victim is None:
            self._victim = self.w / "victim"
            shutil.copytree(self.repo.parent / "repo", self._victim, symlinks=True)
            g(self._victim, "commit", "-q", "--allow-empty", "-m", "victim only")
        return self._victim

    def release(self) -> None:
        # Unblock readers stuck in open(); O_RDWR never blocks. Repeated for a few seconds: a call that returned after the first release
        # (old code) may start ANOTHER git that opens the FIFO again, and nobody would be left to unblock it (orphaned child).
        import time

        for _ in range(30 if self.fifos else 0):
            for p in self.fifos:
                try:
                    os.close(os.open(p, os.O_RDWR | os.O_NONBLOCK))
                except OSError:
                    pass
            time.sleep(0.1)


@pytest.fixture(scope="session")
def template(tmp_path_factory) -> dict:
    d = tmp_path_factory.mktemp("tpl") / "repo"
    d.mkdir()
    for rel, body in (("a.py", "x = 1\n"), ("c.py", "y = 1\n"), ("sub/b.py", "z = 1\n"), (".hlith/x.py", "w = 1\n"), ("README", "hi\n")):
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(body)
    g(d, "init", "-q", "-b", "main")
    g(d, "add", "-A")
    g(d, "commit", "-q", "-m", "base")
    return {"dir": d, "tree": tree_oid(g(d, "rev-parse", "HEAD^{tree}")), "head": g(d, "rev-parse", "HEAD")}


@pytest.fixture
def ctx(tmp_path, template):
    c = Ctx(tmp_path, template)
    yield c
    c.release()


# ----------------------------------------------------------------------------------------------------------------- entry points


def entry_vet(repo, c):
    return HardenedGitRead().repository_hostile_reason(repo)


def entry_head_tree(repo, c):
    return _refuse(lambda: HardenedGitRead().head_tree(repo))


def entry_export(repo, c):
    return _refuse(lambda: HardenedGitRead().export_tree(repo, c.tree, c.out / "export"))


def entry_safe(repo, c):
    return _refuse(lambda: [safe_git_read(repo, *a) for a in CMDS])


def entry_gitq_refusal(repo, c):
    return gitq.refusal(repo)


def entry_gitq_git(repo, c):
    return _refuse(lambda: [gitq.git(repo, *a, check=True) for a in CMDS])


def entry_gitq_popen(repo, c):
    def run():
        for a in CMDS:
            gitq.popen(repo, list(a)).communicate(timeout=60)

    return _refuse(run)


def entry_toplevel(repo, c):
    root, why = gitq.toplevel(repo)
    return why or None


def entry_seal(repo, c):
    return _refuse(lambda: LocalSnapshotService(root=c.out / "seal").seal_base(repo))


def entry_writer(repo, c):
    return _refuse(lambda: [git_write.run_target_git(repo, a) for a in CMDS])


ENTRIES = {f.__name__[6:]: f for f in (entry_vet, entry_head_tree, entry_export, entry_safe, entry_gitq_refusal, entry_gitq_git,
                                       entry_gitq_popen, entry_toplevel, entry_seal, entry_writer)}
CORE = ("vet", "head_tree", "safe", "gitq_refusal", "gitq_git", "gitq_popen", "seal", "writer")
SHAPE = CORE + ("export", "toplevel")
FIFO_ENTRIES = ("vet", "safe", "gitq_refusal")


def run_entry(name: str, repo, c, secs: float = 120):
    return _deadline(lambda: ENTRIES[name](repo, c), secs)


# ----------------------------------------------------------------------------------------------------------------- hostile builders


def cfg(c: Ctx, text: str) -> None:
    with open(c.repo / ".git" / "config", "a") as f:
        f.write(text)


def info_file(c: Ctx, name: str, text: str) -> None:
    p = c.repo / ".git" / "info" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(text)


def drivers(c: Ctx) -> str:
    s, f, t = c.script, c.filter_script, c.textconv_script
    return (f'[filter "evil"]\n\tclean = {f}\n\tsmudge = {f}\n[diff "evil"]\n\ttextconv = {t}\n\tcommand = {s}\n'
            f'[merge "evil"]\n\tdriver = {s} %O %A %B\n')


ATTR = "*.py filter=evil diff=evil merge=evil ident\n"


def b_valueless_fsmonitor(c): cfg(c, "[core]\n\tfsmonitor\n")
def b_inline_fsmonitor(c): cfg(c, f"[core] fsmonitor = {c.script}\n")
def b_continuation_key(c): cfg(c, f"[core]\n\tfsmon\\\nitor = {c.script}\n")
def b_continuation_value(c): cfg(c, f"[core]\n\tfsmonitor = {c.out}/\\\n{c.script.name}\n")
def b_mixedcase_section(c): cfg(c, f"[CORE]\n\tFsMonitor = {c.script}\n")


def b_filter_dotted_subsection(c):
    cfg(c, f'[Filter "Evil.X"]\n\tClean = {c.filter_script}\n\tSmudge = {c.filter_script}\n')
    info_file(c, "attributes", "*.py filter=Evil.X\n")


def b_diff_textconv_dotted(c):
    cfg(c, f'[diff "A.b"]\n\tTextConv = {c.textconv_script}\n')
    info_file(c, "attributes", "*.py diff=A.b\n")


def _extra(c, body):
    p = c.out / "extra.cfg"
    p.write_text(body)
    return p


def b_include_benign(c): cfg(c, f"[include]\n\tpath = {_extra(c, '[user]\\n\\tname = x\\n')}\n")
def b_include_evil(c): cfg(c, f"[include]\n\tpath = {_extra(c, f'[core]\\n\\tfsmonitor = {c.script}\\n')}\n")
def b_includeif_benign(c): cfg(c, f'[includeIf "gitdir:/"]\n\tpath = {_extra(c, "[user]\\n\\tname = x\\n")}\n')
def b_includeif_evil(c): cfg(c, f'[includeIf "gitdir:/"]\n\tpath = {_extra(c, f"[core]\\n\\tfsmonitor = {c.script}\\n")}\n')
def b_config_worktree_file(c): (c.repo / ".git" / "config.worktree").write_text("[user]\n\tname = x\n")
def b_ext_worktreeconfig(c): cfg(c, "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tworktreeConfig = true\n")


def _modules(c, name, body):
    d = c.repo / ".git" / "modules" / "x"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


def b_modules_inline(c): _modules(c, "config", f"[core] fsmonitor = {c.script}\n")
def b_modules_valueless(c): _modules(c, "config", "[core]\n\tfsmonitor\n")
def b_modules_continuation(c): _modules(c, "config", f"[core]\n\tfsmon\\\nitor = {c.script}\n")
def b_modules_config_worktree(c): _modules(c, "config.worktree", "[user]\n\tname = x\n")


def b_fifo_config(c):
    p = c.repo / ".git" / "config"
    p.unlink()
    os.mkfifo(p)
    c.fifos.append(p)


def b_fifo_modules_config(c):
    d = c.repo / ".git" / "modules" / "x"
    d.mkdir(parents=True)
    os.mkfifo(d / "config")
    c.fifos.append(d / "config")


def _symlink_file(c, rel, body):
    target = c.out / ("target_" + rel.replace("/", "_"))
    target.write_text(body)
    p = c.repo / ".git" / rel
    if p.exists() or p.is_symlink():
        p.unlink()
    p.parent.mkdir(exist_ok=True)
    os.symlink(target, p)


def b_symlink_config(c): _symlink_file(c, "config", (c.repo / ".git" / "config").read_text())
def b_symlink_info_attributes(c): _symlink_file(c, "info/attributes", "# benign\n")
def b_symlink_info_exclude(c): _symlink_file(c, "info/exclude", "# benign\n")


def b_huge_config(c): cfg(c, ("# " + "x" * 78 + "\n") * (2 * MIB // 80))
def b_huge_info_exclude(c): info_file(c, "exclude", ("# " + "x" * 78 + "\n") * (2 * MIB // 80))


def b_core_worktree(c): cfg(c, f"[core]\n\tworktree = {c.victim()}\n")


def b_gitfile(c):
    real = c.w / "gitdir_real"
    shutil.move(str(c.repo / ".git"), real)
    (c.repo / ".git").write_text(f"gitdir: {real}\n")


def b_symlink_dotgit(c):
    real = c.w / "moved_git"
    shutil.move(str(c.repo / ".git"), real)
    os.symlink(real, c.repo / ".git")


def _swap_for_symlink(c, rel, target):
    p = c.repo / ".git" / rel
    shutil.rmtree(p)
    os.symlink(target, p)


def b_symlink_refs(c): _swap_for_symlink(c, "refs", c.victim() / ".git" / "refs")
def b_symlink_refs_heads(c): _swap_for_symlink(c, "refs/heads", c.victim() / ".git" / "refs" / "heads")


def _benign_copy(c, rel):
    copy = c.w / ("copy_" + rel.replace("/", "_"))
    shutil.copytree(c.repo / ".git" / rel, copy, symlinks=True)
    _swap_for_symlink(c, rel, copy)


def b_symlink_objects(c): _benign_copy(c, "objects")
def b_symlink_objects_pack(c): _benign_copy(c, "objects/pack")
def b_commondir_other(c): (c.repo / ".git" / "commondir").write_text(f"{c.victim() / '.git'}\n")
def b_commondir_dot(c): (c.repo / ".git" / "commondir").write_text(".\n")


def b_linked_worktree(c):
    g(c.repo, "worktree", "add", "-q", str(c.w / "wt"), "-b", "wtb")
    return c.w / "wt"


def b_alternates(c): (c.repo / ".git" / "objects" / "info" / "alternates").write_text(f"{c.victim() / '.git' / 'objects'}\n")
def b_http_alternates(c): (c.repo / ".git" / "objects" / "info" / "http-alternates").write_text("http://example.invalid/objects\n")
def b_bare_true(c): cfg(c, "[core]\n\tbare = true\n")
def b_info_grafts(c): info_file(c, "grafts", c.head + "\n")


def _attr_source(c, kind):
    if kind == "worktree":
        (c.repo / ".gitattributes").write_text(ATTR)
    elif kind == "nested":
        (c.repo / "sub" / ".gitattributes").write_text(ATTR)
    elif kind == "hlith":
        (c.repo / ".hlith" / ".gitattributes").write_text(ATTR)
    elif kind == "info":
        info_file(c, "attributes", ATTR)
    elif kind in ("committed_deleted", "index_only"):
        (c.repo / ".gitattributes").write_text(ATTR)
        g(c.repo, "add", ".gitattributes")
        if kind == "committed_deleted":
            g(c.repo, "commit", "-q", "-m", "attrs")
        (c.repo / ".gitattributes").unlink()


ATTR_SOURCES = ("worktree", "nested", "hlith", "info", "committed_deleted", "index_only")

# fixture id -> (builder, entries, per-call deadline seconds)
X3 = {
    "valueless_fsmonitor": (b_valueless_fsmonitor, CORE, 120),
    "inline_fsmonitor": (b_inline_fsmonitor, CORE, 120),
    "continuation_key": (b_continuation_key, CORE, 120),
    "continuation_value": (b_continuation_value, CORE, 120),
    "mixedcase_section": (b_mixedcase_section, CORE, 120),
    "filter_dotted_subsection": (b_filter_dotted_subsection, CORE, 120),
    "diff_textconv_dotted": (b_diff_textconv_dotted, CORE, 120),
    "include_benign": (b_include_benign, CORE, 120),
    "include_evil": (b_include_evil, CORE, 120),
    "includeif_benign": (b_includeif_benign, CORE, 120),
    "includeif_evil": (b_includeif_evil, CORE, 120),
    "config_worktree_file": (b_config_worktree_file, CORE, 120),
    "ext_worktreeconfig": (b_ext_worktreeconfig, CORE, 120),
    "modules_inline": (b_modules_inline, CORE, 120),
    "modules_valueless": (b_modules_valueless, CORE, 120),
    "modules_continuation": (b_modules_continuation, CORE, 120),
    "modules_config_worktree": (b_modules_config_worktree, CORE, 120),
    # X3b input hygiene: lstat BEFORE open; a blocking open in our own process cannot be saved by a spawn timeout
    "fifo_config": (b_fifo_config, FIFO_ENTRIES, 8),
    "fifo_modules_config": (b_fifo_modules_config, ("vet", "safe"), 8),
    "symlink_config": (b_symlink_config, CORE, 120),
    "huge_config": (b_huge_config, CORE, 120),
    "symlink_info_attributes": (b_symlink_info_attributes, CORE, 120),
    "symlink_info_exclude": (b_symlink_info_exclude, CORE, 120),
    "huge_info_exclude": (b_huge_info_exclude, CORE, 120),
}
X5 = {
    "core_worktree": (b_core_worktree, SHAPE, 120),
    "gitfile": (b_gitfile, SHAPE, 120),
    "symlink_dotgit": (b_symlink_dotgit, SHAPE, 120),
    "symlink_refs": (b_symlink_refs, SHAPE, 120),
    "symlink_refs_heads": (b_symlink_refs_heads, SHAPE, 120),
    "symlink_objects": (b_symlink_objects, CORE + ("export",), 120),
    "symlink_objects_pack": (b_symlink_objects_pack, CORE + ("export",), 120),
    "commondir_other": (b_commondir_other, SHAPE, 120),
    "commondir_dot": (b_commondir_dot, SHAPE, 120),
    "linked_worktree": (b_linked_worktree, SHAPE, 120),
    "alternates": (b_alternates, CORE + ("export",), 120),
    "http_alternates": (b_http_alternates, CORE, 120),
    "bare_true": (b_bare_true, CORE + ("export",), 120),
    "info_grafts": (b_info_grafts, CORE, 120),
}
# X5b WITH matching config: the vet must refuse first, for every entrypoint including the writer (apply --index / status / diff)
X5B_CFG = {
    f"cfg_{k}": ((lambda c, k=k: (_attr_source(c, k), cfg(c, drivers(c)))[0]), CORE, 120) for k in ATTR_SOURCES
}
HOSTILE = {**X3, **X5, **X5B_CFG}
PAIRS = [(h, e) for h, (_b, ents, _d) in HOSTILE.items() for e in ents]


@pytest.mark.parametrize("hid,entry", PAIRS, ids=[f"{h}-{e}" for h, e in PAIRS])
def test_hostile_repository_is_refused_untouched_and_runs_nothing(hid, entry, ctx):
    builder, _entries, secs = HOSTILE[hid]
    repo = builder(ctx) or ctx.repo
    before = tree_state(ctx.w)
    res = run_entry(entry, repo, ctx, secs)
    after = tree_state(ctx.w)
    assert not ctx.marker.exists(), f"MARKER FIRED: a repository-chosen program ran ({hid} via {entry})"
    assert res != HUNG, f"{HUNG} ({hid} via {entry})"
    assert res is not None, f"ACCEPTED a hostile repository ({hid} via {entry}): no refusal"
    assert before == after, f"TARGET MODIFIED by a refused/accepted read ({hid} via {entry}): " + ", ".join(
        sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))[:5])


# ----------------------------------------------------------------------------------------------------------------- X5b: no config => nothing runs, and no false refusal


@pytest.mark.parametrize("kind", ATTR_SOURCES)
@pytest.mark.parametrize("entry", CORE)
def test_x5b_attribute_sources_without_config_never_run_anything(kind, entry, ctx):
    _attr_source(ctx, kind)
    run_entry(entry, ctx.repo, ctx)
    assert not ctx.marker.exists()


@pytest.mark.parametrize("kind", ATTR_SOURCES)
@pytest.mark.parametrize("entry", ("vet", "head_tree", "safe", "gitq_refusal", "gitq_git", "seal", "writer"))
def test_x5b_attribute_sources_without_config_are_not_falsely_refused(kind, entry, ctx):
    if NAMED_FALSE_REFUSAL_ATTRS:
        pytest.xfail("attribute scan restored as defence in depth: named false refusal")
    _attr_source(ctx, kind)
    res = run_entry(entry, ctx.repo, ctx)
    assert res is None, f"FALSE REFUSAL of a repository whose attributes name drivers that are not defined ({kind} via {entry}): {res}"


def test_x5b_writer_apply_index_runs_no_clean_filter_in_a_hostile_target(ctx):
    cfg(ctx, drivers(ctx))
    info_file(ctx, "attributes", "*.py filter=evil\n")
    patch = b"diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -1 +1 @@\n-y = 1\n+y = 5\n"
    res = _refuse(lambda: git_write.apply_index_and_verify_tree(ctx.repo, patch, ctx.tree))
    assert not ctx.marker.exists(), "MARKER FIRED: the writer's apply --index ran filter.evil.clean from the target's own config"
    assert res is not None, "writer ACCEPTED a hostile target (apply --index)"


def test_x5b_writer_diff_runs_no_textconv_in_a_hostile_target(ctx):
    b_diff_textconv_dotted(ctx)
    res = _refuse(lambda: git_write.run_target_git(ctx.repo, ("diff", "--no-ext-diff")))
    assert not ctx.marker.exists(), "MARKER FIRED: the writer ran diff.A.b.textconv from the target's own config"
    assert res is not None, "writer ACCEPTED a hostile target (diff)"


# ----------------------------------------------------------------------------------------------------------------- X4: the inherited environment is never an input


def _dir_with(c, name):
    d = c.w / name
    d.mkdir(exist_ok=True)
    return d


def _evil_cfg_file(c, name="evil.cfg"):
    p = c.out / name
    p.write_text(f"[core]\n\tfsmonitor = {c.script}\n")
    return str(p)


def _home_with_gitconfig(c):
    h = c.out / "home"
    (h / ".config" / "git").mkdir(parents=True)
    (h / ".gitconfig").write_text(f"[core]\n\tfsmonitor = {c.script}\n[user]\n\tname = evil\n")
    (h / ".config" / "git" / "config").write_text(f"[core]\n\tfsmonitor = {c.script}\n")
    (h / ".config" / "git" / "attributes").write_text("*.py filter=evil\n")
    return {"HOME": str(h), "XDG_CONFIG_HOME": str(h / ".config")}


def _exec_path(c):
    d = c.out / "execpath"
    d.mkdir()
    for n in ("git-upload-pack", "git-remote-ext", "git-credential-hlith"):
        shutil.copy(c.script, d / n)
    return str(d)


ENV_CASES = {
    "GIT_DIR": lambda c: {"GIT_DIR": str(c.victim() / ".git")},
    "GIT_WORK_TREE": lambda c: {"GIT_WORK_TREE": str(c.victim())},
    "GIT_INDEX_FILE": lambda c: {"GIT_INDEX_FILE": str(c.victim() / ".git" / "index")},
    "GIT_COMMON_DIR": lambda c: {"GIT_COMMON_DIR": str(c.victim() / ".git")},
    "GIT_OBJECT_DIRECTORY": lambda c: {"GIT_OBJECT_DIRECTORY": str(c.victim() / ".git" / "objects")},
    "GIT_ALTERNATE_OBJECT_DIRECTORIES": lambda c: {"GIT_ALTERNATE_OBJECT_DIRECTORIES": str(c.victim() / ".git" / "objects")},
    "GIT_CONFIG_COUNT": lambda c: {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": str(c.script)},
    "GIT_CONFIG_PARAMETERS": lambda c: {"GIT_CONFIG_PARAMETERS": f"'core.fsmonitor'='{c.script}'"},
    "GIT_CONFIG_GLOBAL": lambda c: {"GIT_CONFIG_GLOBAL": _evil_cfg_file(c)},
    "GIT_CONFIG_SYSTEM": lambda c: {"GIT_CONFIG_SYSTEM": _evil_cfg_file(c), "GIT_CONFIG_NOSYSTEM": "0"},
    "HOME_XDG_CONFIG_HOME": _home_with_gitconfig,
    "GIT_EXTERNAL_DIFF": lambda c: {"GIT_EXTERNAL_DIFF": str(c.script)},
    "GIT_PAGER": lambda c: {"GIT_PAGER": str(c.script), "PAGER": str(c.script)},
    "GIT_EDITOR": lambda c: {"GIT_EDITOR": str(c.script), "EDITOR": str(c.script), "GIT_SEQUENCE_EDITOR": str(c.script)},
    "GIT_SSH": lambda c: {"GIT_SSH": str(c.script), "GIT_SSH_COMMAND": str(c.script), "GIT_PROXY_COMMAND": str(c.script)},
    "GIT_ASKPASS": lambda c: {"GIT_ASKPASS": str(c.script), "SSH_ASKPASS": str(c.script)},
    "GIT_TRACE": lambda c: {"GIT_TRACE": str(c.out / "trace1"), "GIT_TRACE_SETUP": str(c.out / "trace2"),
                            "GIT_TRACE_PERFORMANCE": str(c.out / "trace3")},
    "GIT_TRACE2": lambda c: {"GIT_TRACE2": str(c.out / "trace4"), "GIT_TRACE2_EVENT": str(c.out / "trace5"),
                             "GIT_TRACE2_PERF": str(c.out / "trace6")},
    "GIT_EXEC_PATH": lambda c: {"GIT_EXEC_PATH": _exec_path(c)},
    "GIT_TEMPLATE_DIR": lambda c: {"GIT_TEMPLATE_DIR": str(_dir_with(c, "tpl"))},
    "GIT_NAMESPACE": lambda c: {"GIT_NAMESPACE": "hlith"},
    "GIT_REPLACE_REF_BASE": lambda c: {"GIT_REPLACE_REF_BASE": "refs/hlith-replace/"},
    "GIT_LITERAL_PATHSPECS": lambda c: {"GIT_LITERAL_PATHSPECS": "1"},
    "GIT_GLOB_PATHSPECS": lambda c: {"GIT_GLOB_PATHSPECS": "1"},
    "GIT_NOGLOB_PATHSPECS": lambda c: {"GIT_NOGLOB_PATHSPECS": "1"},
    "GIT_ICASE_PATHSPECS": lambda c: {"GIT_ICASE_PATHSPECS": "1"},
    "GIT_ATTR_SOURCE": lambda c: {"GIT_ATTR_SOURCE": "HEAD"},
    "GIT_OPTIONAL_LOCKS": lambda c: {"GIT_OPTIONAL_LOCKS": "1"},
    "GIT_ALLOW_PROTOCOL": lambda c: {"GIT_ALLOW_PROTOCOL": "ext:file:http", "GIT_PROTOCOL_FROM_USER": "1"},
    "GIT_CEILING_DIRECTORIES": lambda c: {"GIT_CEILING_DIRECTORIES": str(c.victim())},
}


def _reads(repo) -> dict:
    ops = {
        "rev-parse": ("rev-parse", "HEAD"), "status": ("status", "--porcelain"), "diff": ("diff", "--no-ext-diff"), "diff-ext": ("diff",),
        "ls-files-glob": ("ls-files", "--", "*.py"), "log": ("log", "-1", "--format=%H%x1f%s"),
    }
    out: dict = {}
    for k, a in ops.items():
        out["safe:" + k] = _refuse_val(lambda a=a: safe_git_read(repo, *a))
        out["gitq:" + k] = _refuse_val(lambda a=a: gitq.git(repo, *a, check=True).decode("utf-8", "replace").strip())
    out["head_tree"] = _refuse_val(lambda: str(HardenedGitRead().head_tree(repo)))
    return out


def _refuse_val(fn):
    try:
        return fn()
    except REFUSED as exc:
        return f"REFUSED {type(exc).__name__}"


def test_x4_baseline_clean_reads_work(ctx):
    r = _reads(ctx.repo)
    assert not [k for k, v in r.items() if str(v).startswith("REFUSED") and "diff-ext" not in k], r
    assert r["safe:rev-parse"] == ctx.head and r["head_tree"] == str(ctx.tree)
    assert "a.py" in r["safe:status"] and "a.py" in r["gitq:status"]
    # pathspecs are LITERAL on every read (a broad review confirmed ':(exclude)x' / '[id]' paths broke landing and rollback): a '*.py' glob matches no file named '*.py'
    assert r["safe:ls-files-glob"] == "" and r["gitq:ls-files-glob"] == ""


@pytest.mark.parametrize("case", list(ENV_CASES))
def test_x4_hostile_environment_changes_nothing(case, ctx, monkeypatch):
    base = _reads(ctx.repo)
    assert not [k for k, v in base.items() if str(v).startswith("REFUSED") and "diff-ext" not in k], base
    for k, v in ENV_CASES[case](ctx).items():
        monkeypatch.setenv(k, v)
    got = _reads(ctx.repo)
    assert not ctx.marker.exists(), f"MARKER FIRED: an inherited {case} ran a program"
    leaked = sorted(p.name for p in ctx.out.glob("trace*"))
    assert not leaked, f"inherited {case} reached git (trace files written: {leaked})"
    diff = {k: (base[k], got[k]) for k in base if base[k] != got[k]}
    assert not diff, f"inherited {case} changed what the read returned: {diff}"


def _untracked(c):
    (c.repo / "new.txt").write_text("new\n")


def _objects_listing(repo):
    return sorted(str(p.relative_to(repo)) for p in (repo / ".git" / "objects").rglob("*") if p.is_file())


@pytest.mark.parametrize("which", ["index_is_the_targets_own", "objects_dir_is_the_targets_own", "alternates_name_another_repository"])
def test_x4_caller_env_may_only_name_its_own_temp_index_and_objects(which, ctx):
    _untracked(ctx)
    tmp = Path(__import__("tempfile").mkdtemp(prefix="hlith-ui-index-"))
    env = {"GIT_INDEX_FILE": str(tmp / "index"), "GIT_OBJECT_DIRECTORY": str(tmp / "objects"),
           "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(ctx.repo / ".git" / "objects")}
    (tmp / "objects").mkdir()
    try:
        if which == "index_is_the_targets_own":
            env["GIT_INDEX_FILE"] = str(ctx.repo / ".git" / "index")
        elif which == "objects_dir_is_the_targets_own":
            env["GIT_OBJECT_DIRECTORY"] = str(ctx.repo / ".git" / "objects")
        else:
            env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(ctx.victim() / ".git" / "objects")
        before = tree_state(ctx.repo / ".git")
        listing = _objects_listing(ctx.repo)
        res = _refuse(lambda: gitq.git(ctx.repo, "add", "-A", env=env, check=True))
        assert before == tree_state(ctx.repo / ".git") and listing == _objects_listing(ctx.repo), (
            "TARGET MODIFIED: add -A wrote into the target's own index/object store through a caller-supplied environment variable")
        assert res is not None, f"ACCEPTED a caller environment that escapes its own temp directory ({which})"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_x4_positive_real_temp_index_flow_still_works(ctx):
    _untracked(ctx)
    c = changes.uncommitted(ctx.repo)
    assert c is not None and not c.problem, getattr(c, "problem", "no change returned")
    assert {f[0] for f in c.files} >= {"a.py", "new.txt"}
    assert not (ctx.repo / ".git" / "index.lock").exists()


# ----------------------------------------------------------------------------------------------------------------- X5 identity: the answer describes the repository that was opened


def _evil_replacement(c):
    """A replacement commit with a different tree for HEAD, and a replacement tree for HEAD's tree."""
    blob = g(c.repo, "hash-object", "-w", "--stdin", input=b"EVIL = 1\n")
    evil_tree = g(c.repo, "mktree", input=f"100644 blob {blob}\ta.py\n".encode())
    evil_commit = g(c.repo, "commit-tree", evil_tree, "-m", "evil")
    return evil_tree, evil_commit


@pytest.mark.parametrize("seam", ["head_tree", "safe_rev_parse", "gitq_rev_parse"])
def test_x5_replace_ref_cannot_swap_the_commit_head_resolves_to(seam, ctx):
    _tree, evil_commit = _evil_replacement(ctx)
    g(ctx.repo, "replace", ctx.head, evil_commit)
    fn = {"head_tree": lambda: str(HardenedGitRead().head_tree(ctx.repo)),
          "safe_rev_parse": lambda: safe_git_read(ctx.repo, "rev-parse", "HEAD^{tree}"),
          "gitq_rev_parse": lambda: gitq.text(ctx.repo, "rev-parse", "HEAD^{tree}")}[seam]
    try:
        got = fn()
    except REFUSED:
        return
    assert got in (str(ctx.tree), ""), f"a replace ref swapped HEAD's commit: the read returned the EVIL tree {got} instead of {ctx.tree}"


@pytest.mark.parametrize("seam", ["export_tree", "seal_base"])
def test_x5_replace_ref_cannot_swap_the_tree_that_is_exported(seam, ctx):
    evil_tree, _c = _evil_replacement(ctx)
    g(ctx.repo, "replace", str(ctx.tree), evil_tree)
    if seam == "export_tree":
        dest = ctx.out / "export"
        try:
            HardenedGitRead().export_tree(ctx.repo, ctx.tree, dest)
        except REFUSED:
            return
    else:
        try:
            dest = LocalSnapshotService(root=ctx.out / "seal").seal_base(ctx.repo).path
        except REFUSED:
            return
    assert (dest / "a.py").read_text() == "x = 1\n" and (dest / "sub" / "b.py").exists(), (
        f"a replace ref swapped the exported tree: a.py={(dest / 'a.py').read_text()!r}")


def _foreign_uid(monkeypatch, paths: set[str], uid: int):
    real_stat, real_lstat, real_open, real_fstat = os.stat, os.lstat, os.open, os.fstat
    fds: dict[int, str] = {}

    def fake(st):
        t = list(st)
        t[4] = uid
        return os.stat_result(tuple(t), {"st_atime": st.st_atime, "st_mtime": st.st_mtime, "st_ctime": st.st_ctime})

    def wrap(real):
        def f(path, *a, **k):
            r = real(path, *a, **k)
            try:
                p = os.path.abspath(os.fsdecode(os.fspath(path)))
            except TypeError:
                return r
            return fake(r) if p in paths else r
        return f

    def f_open(path, *a, **k):
        fd = real_open(path, *a, **k)
        try:
            fds[fd] = os.path.abspath(os.fsdecode(os.fspath(path)))
        except TypeError:
            pass
        return fd

    def f_fstat(fd):
        r = real_fstat(fd)
        return fake(r) if fds.get(fd) in paths else r

    monkeypatch.setattr(os, "stat", wrap(real_stat))
    monkeypatch.setattr(os, "lstat", wrap(real_lstat))
    monkeypatch.setattr(os, "open", f_open)
    monkeypatch.setattr(os, "fstat", f_fstat)


UID_ENTRIES = ("vet", "safe", "head_tree", "gitq_refusal", "seal", "writer")


@pytest.mark.skipif(os.geteuid() == 0, reason="foreign uid is euid+1; root test would not be foreign to the stub")
@pytest.mark.parametrize("owned", ["dotgit_dir", "dotgit_config", "worktree_root"])
@pytest.mark.parametrize("entry", UID_ENTRIES)
def test_x5_repository_owned_by_another_uid_is_refused_without_git(owned, entry, ctx, monkeypatch):
    repo = ctx.repo
    paths = {"dotgit_dir": {str(repo / ".git")}, "dotgit_config": {str(repo / ".git" / "config")}, "worktree_root": {str(repo)}}[owned]
    _foreign_uid(monkeypatch, paths, os.geteuid() + 1)
    res = run_entry(entry, repo, ctx)
    assert res != HUNG and res is not None, f"ACCEPTED a repository whose {owned} is owned by another uid (explicit --git-dir skips Git's own check) via {entry}"


@pytest.mark.parametrize("entry", UID_ENTRIES)
def test_x5_ownership_stub_with_own_uid_is_accepted_control(entry, ctx, monkeypatch):
    repo = ctx.repo
    _foreign_uid(monkeypatch, {str(repo), str(repo / ".git"), str(repo / ".git" / "config")}, os.geteuid())
    assert run_entry(entry, repo, ctx) is None


def _spy_popen(rec):
    base = subprocess.Popen

    class Spy(base):
        def __init__(self, args, *a, **k):
            rec.append([os.fsdecode(x) for x in args] if not isinstance(args, (str, bytes)) else [os.fsdecode(args)])
            super().__init__(args, *a, **k)

    return Spy


def test_x5_ref_named_like_an_option_is_never_an_unguarded_operand(ctx, monkeypatch):
    hostile = "--output=hlith-opmark"
    g(ctx.repo, "update-ref", f"refs/heads/{hostile}", ctx.head)
    feat = g(ctx.repo, "commit-tree", f"{ctx.head}^{{tree}}", "-p", ctx.head, "-m", "feature")
    g(ctx.repo, "update-ref", "refs/heads/feature", feat)
    rec: list = []
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", _spy_popen(rec))
        found = changes.branches(ctx.repo)
    assert any("feature" in c.label for c in found), "the legitimate branch must still be offered"
    seen = [a for a in rec if hostile in a]
    bad = [a for a in seen if "--end-of-options" not in a[: a.index(hostile)]]
    assert not bad, f"a ref name from the repository reached git as an unguarded operand (no --end-of-options before it): {bad[0][-6:]}"
    assert not (ctx.repo / "hlith-opmark").exists()


# ----------------------------------------------------------------------------------------------------------------- X9 / F2: a read never writes the target


READS = {
    "safe_status": lambda c: safe_git_read(c.repo, "status", "--porcelain"),
    "safe_diff": lambda c: safe_git_read(c.repo, "diff"),
    "gitq_status": lambda c: gitq.git(c.repo, "status", "--porcelain", check=True),
    "gitq_popen_status": lambda c: gitq.popen(c.repo, ["status", "--porcelain"]).communicate(timeout=60),
    "head_tree": lambda c: HardenedGitRead().head_tree(c.repo),
    "seal_base": lambda c: LocalSnapshotService(root=c.out / "seal").seal_base(c.repo),
}


@pytest.mark.parametrize("read", list(READS))
def test_x9_a_read_leaves_index_bytes_mtime_and_objects_unchanged(read, ctx):
    before = tree_state(ctx.repo)
    READS[read](ctx)
    after = tree_state(ctx.repo)
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    assert not changed, f"a read WROTE to the repository (index refresh / lock / cache debris): {changed[:6]}"


# ----------------------------------------------------------------------------------------------------------------- positive controls (false refusal is a product defect)


@pytest.mark.parametrize("entry", ["vet", "head_tree", "export", "safe", "gitq_refusal", "gitq_git", "gitq_popen", "toplevel", "seal", "writer"])
def test_control_clean_repository_is_accepted_by_every_entrypoint(entry, ctx):
    assert run_entry(entry, ctx.repo, ctx) is None


def test_control_inert_benign_config_is_accepted(ctx):
    cfg(ctx, '[user]\n\tname = Dev\n\temail = d@example.invalid\n[remote "A.b"]\n\turl = https://example.invalid/r.git\n'
             '\tfetch = +refs/heads/*:refs/remotes/A.b/*\n[branch "main"]\n\tremote = A.b\n\tmerge = refs/heads/main\n')
    for entry in ("vet", "safe", "gitq_refusal", "seal"):
        assert run_entry(entry, ctx.repo, ctx) is None, entry


def test_control_config_just_under_the_size_cap_is_accepted(ctx):
    cfg(ctx, ("# " + "x" * 78 + "\n") * (64 * 1024 // 80))
    assert run_entry("vet", ctx.repo, ctx) is None


def test_control_clean_reads_return_the_true_values(ctx):
    assert str(HardenedGitRead().head_tree(ctx.repo)) == str(ctx.tree)
    assert safe_git_read(ctx.repo, "rev-parse", "HEAD") == ctx.head
    root, why = gitq.toplevel(ctx.repo)
    assert why == "" and Path(root).resolve() == ctx.repo.resolve()
    snap = LocalSnapshotService(root=ctx.out / "seal").seal_base(ctx.repo)
    assert str(snap.tree_oid) == str(ctx.tree) and (snap.path / "a.py").read_text() == "x = 1\n"
