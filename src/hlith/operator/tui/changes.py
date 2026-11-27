# SPDX-License-Identifier: Apache-2.0
"""Discover REAL changes in a repository, read-only: uncommitted work (incl. untracked files), recent commits, branches against their
merge-base, patch files. Each becomes a Change = (base revision the clone must be at, the diff text, a summary). The source repo's
index, worktree, refs and object store are never written (uncommitted work is diffed through a temporary index and a temporary
object directory whose alternate is the repo's own objects)."""

from __future__ import annotations

import io
import re
import atexit
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import gitq

MAX_PATCH = 8 * 1024 * 1024  # the ENGINE's patch-size policy; the UI never raises or bypasses it, it makes bigger changes workable by scope
MAX_UNTRACKED = 5000
DIFF_ARGS = ("--binary", "--no-renames", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/")
PAGE_MAX_BYTES = 256 * 1024  # a diff page never reads more than this from git

_GENERATED_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Cargo.lock", "Gemfile.lock", "composer.lock", "go.sum"}
_GENERATED_DIRS = {"node_modules", "dist", "build", "__pycache__", ".next", "vendor", "target", ".venv", "site-packages"}
_GENERATED_SUFFIX = (".min.js", ".min.css", ".map", ".pyc", ".pb.go", "_pb2.py", ".generated.ts", ".lock")
_TOOL_STATE_DIRS = {".beads", ".ntm", ".serena", ".claude", ".codex", ".gemini", ".cursor", ".hlith", ".vscode", ".idea", "scratchpad"}


def generated_label(path: str) -> str:
    """'generated' for paths that are conventionally machine-made (lock files, build output, vendored trees). A LABEL only: never auto-excluded."""
    parts = path.split("/")
    if parts[-1] in _GENERATED_NAMES or any(path.endswith(x) for x in _GENERATED_SUFFIX) or any(p in _GENERATED_DIRS for p in parts[:-1]):
        return "generated"
    return ""


def tool_state_label(path: str) -> str:
    """'tool' for agent/harness/editor state directories (excluded by default in the UI selector with explicit visibility, never silently)."""
    parts = path.split("/")
    if any(p in _TOOL_STATE_DIRS for p in parts[:-1]):
        return "tool"
    return ""


def tool_state_paths(change) -> list[str]:
    """Paths of a change that are UNTRACKED files under an agent/harness/editor state directory. Fail closed: a tracked edit, or any path outside the labelled
    directories, is never in this list (it stays in the claim)."""
    return [i.path for i in getattr(change, "infos", []) if i.tool_state and getattr(i, "untracked", False)]


class TooBig(Exception):
    """The selected scope is larger than the engine's patch-size policy."""

    def __init__(self, size: int):
        super().__init__(f"patch is {size // 1024:,} KiB; engine patch limit is {MAX_PATCH // 1024:,} KiB")
        self.size = size


@dataclass
class FileInfo:
    path: str
    added: int | None  # None: binary
    deleted: int | None
    bytes: int  # size of this file's part of the diff text
    status: str = "modify"  # add | modify | delete
    untracked: bool = False
    binary: bool = False
    generated: str = ""
    tool_state: str = ""


@dataclass
class Change:
    kind: str  # uncommitted | commit | branch | patchfile
    label: str
    base_rev: str  # full commit id the disposable clone must be at (the patch applies on it)
    patch: bytes  # the whole diff when it fits the engine policy, else b"" (use diff(paths) for a scoped patch)
    files: list = field(default_factory=list)  # (path, added|None, deleted|None)
    detail: str = ""
    problem: str = ""  # why it cannot be offered (shown, not hidden)
    source: str = ""  # a patch file's path
    infos: list = field(default_factory=list)  # FileInfo per file, from ONE streaming pass over the diff
    total_bytes: int = 0
    oversize: bool = False  # whole diff larger than the engine policy: choose a scope
    _repo: str = ""
    _args: tuple = ()
    _env: dict = field(default_factory=dict)
    _kept: dict = field(default_factory=dict)  # path -> bytes of that file's diff (only while the whole diff fits)
    _raw: bytes | None = None  # patch files: the file's own bytes
    _manifest_path: str = ""  # paired manifest discovered with this patch file
    _manifest_raw: bytes | None = None  # exact manifest bytes captured with the displayed patch
    default_excluded: tuple = ()  # paths the headless selector leaves out by default (untracked agent/tool state); diff() with no explicit scope honours it
    _git_error: gitq.GitReadError | None = None  # typed Git read failure when scan/diff failed (never confused with empty diff)

    @property
    def stats(self) -> tuple[int, int, int]:
        return len(self.files), sum(f[1] or 0 for f in self.files), sum(f[2] or 0 for f in self.files)

    def summary(self) -> str:
        n, a, d = self.stats
        return (f"{n} file{'s' if n != 1 else ''}  +{a} -{d}"
                + (f"  full patch {self.total_bytes // 1024:,} KiB" if self.oversize else ""))

    # ---- scoped access: never loads a whole oversize diff ----
    def diff(self, paths=None) -> bytes:
        """The patch for `paths` (all files when None). Raises TooBig when that scope still exceeds the engine policy."""
        if paths is None and self.default_excluded:
            paths = [i.path for i in self.infos if i.path not in set(self.default_excluded)]
        want = [i.path for i in self.infos] if paths is None else [p for p in paths]
        if self._raw is not None:
            return self._raw if (paths is None or set(want) == {i.path for i in self.infos}) else self._filter_raw(set(want))
        chosen = [i for i in self.infos if i.path in set(want)]
        total = sum(i.bytes for i in chosen)
        if total > MAX_PATCH:
            raise TooBig(total)
        if self._kept and all(i.path in self._kept for i in chosen):
            return b"".join(self._kept[i.path] for i in chosen)
        if not chosen:
            return b""
        data, _n = _stream(self._repo, ["--literal-pathspecs", "diff", *DIFF_ARGS, *self._args, "--", *[i.path for i in chosen]], self._env, keep=MAX_PATCH + 1)
        if data is None or len(data) > MAX_PATCH:
            raise TooBig(total)
        return data

    def _filter_raw(self, want: set) -> bytes:
        keep = []
        for part in _split_files(self._raw or b""):
            if part[0] in want:
                keep.append(part[1])
        return b"".join(keep)

    def page(self, path: str, start: int = 0, count: int = 200) -> tuple[list[str], bool]:
        """(lines start..start+count of ONE file's diff, more-after). Reads at most PAGE_MAX_BYTES beyond the page from git or the kept text;
        a whole oversize diff is never loaded."""
        info = next((i for i in self.infos if i.path == path), None)
        if info is None:
            return [], False
        if info.binary:
            return ["binary file: no text diff (its size counts toward the patch)"], False
        raw = self._kept.get(path)
        if raw is None and self._raw is not None:
            raw = next((p[1] for p in _split_files(self._raw) if p[0] == path), b"")
        if raw is None:
            try:
                raw, cut = _prefix(self._repo, ["--literal-pathspecs", "diff", *DIFF_ARGS, *self._args, "--", path], self._env, PAGE_MAX_BYTES * 4)
            except gitq.GitReadError as exc:
                return [f"could not read diff: {exc}"], False
        else:
            cut = False
        lines = raw.decode("utf-8", "replace").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if cut and lines:
            lines.pop()  # the last line may be cut short
        window = lines[start: start + count]
        if cut and start + count >= len(lines):
            return window + [f"... diff continues beyond the {PAGE_MAX_BYTES * 4 // 1024} KiB this viewer reads at a time (file diff is {info.bytes // 1024} KiB)"], False
        return window, start + count < len(lines)


def _prefix(repo, args, env, limit: int):
    """(first `limit` bytes of git's stdout, cut) and stop git: a bounded read of a possibly huge diff.

    Raises ``gitq.GitReadError`` on refusal, unsupported Git feature, nonzero exit, timeout, or mid-read mutation.
    """
    stream = gitq.open_stream(repo, args, env)
    buf = bytearray()
    cut = False

    def _on_chunk(chunk: bytes) -> bool:
        nonlocal cut
        buf.extend(chunk)
        if len(buf) > limit:
            cut = True
            return False
        return True

    killed, timed_out, err = gitq.drain_stream(stream, on_chunk=_on_chunk, timeout=gitq.TIMEOUT * 4)
    gitq.finish_stream(stream, stderr_bytes=err, killed_for_limit=killed, timed_out=timed_out, timeout=gitq.TIMEOUT * 4)
    return bytes(buf[:limit]), cut


def _stream(repo, args, env, keep: int):
    """Run `git` and stream stdout: (first `keep` bytes or None if more, total bytes counted). Memory stays bounded by `keep`.

    Raises ``gitq.GitReadError`` on refusal, unsupported Git feature, nonzero exit, timeout, or mid-read mutation.
    """
    stream = gitq.open_stream(repo, args, env)
    buf = bytearray()
    total = 0
    over = False

    def _on_chunk(chunk: bytes) -> bool:
        nonlocal total, over
        total += len(chunk)
        if not over:
            if len(buf) + len(chunk) > keep:
                over = True
                buf.clear()
            else:
                buf.extend(chunk)
        return True

    killed, timed_out, err = gitq.drain_stream(stream, on_chunk=_on_chunk, timeout=gitq.TIMEOUT * 4)
    gitq.finish_stream(stream, stderr_bytes=err, killed_for_limit=killed, timed_out=timed_out, timeout=gitq.TIMEOUT * 4)
    return (None if over else bytes(buf)), total


_HUNK_RE = re.compile(rb"@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@")


def _split_files(data: bytes):
    """[(path, bytes of that file's diff)] by 'diff --git a/X b/Y' boundaries (path = the b/ side)."""
    return _split_files_checked(data)[0]


def _split_files_checked(data: bytes):
    """([(path, bytes)], malformed): lines end at b'\\n' ONLY, and inside a hunk the header's own line counts decide what is body, so a line that merely STARTS with
    'diff --git a/' can never open a phantom file. git's grammar is enforced both ways: inside a hunk a '+' with the new side exhausted, a '-' with the old side
    exhausted or a context line with either exhausted is a mismatch; after a COMPLETE hunk only '@@', 'diff --git', a '\\ No newline' marker (or the format-patch
    '-- ' signature, which ends the diff) may follow, so a '+', '-' or ' ' line there (one git ignores or refuses) is never shown as a change. Zero counts are
    legal ('@@ -0,0 +1,3 @@', '@@ -5,0 +6,2 @@'). A hunk that ends early, an unreadable (e.g. negative-count) header or a truncated hunk is MALFORMED: no boundary is
    invented and the caller refuses the patch."""
    out = []
    cur_path, cur = None, bytearray()
    rem_old = rem_new = 0
    after_hunk = sig_seen = False
    malformed = None
    for n, raw in enumerate(io.BytesIO(data), 1):
        if rem_old > 0 or rem_new > 0:
            if raw.startswith(b"\\"):
                pass  # '\ No newline at end of file' belongs to the hunk and counts nowhere
            elif raw.startswith(b"+") and rem_new > 0:
                rem_new -= 1
            elif raw.startswith(b"-") and rem_old > 0:
                rem_old -= 1
            elif (raw.startswith(b" ") or raw in (b"\n", b"\r\n")) and rem_old > 0 and rem_new > 0:
                rem_old -= 1
                rem_new -= 1
            else:
                malformed = malformed or f"hunk body does not match its header counts at patch line {n}"
                rem_old = rem_new = 0
            if rem_old == 0 and rem_new == 0:
                after_hunk = True
            cur += raw
            continue
        if sig_seen and not raw.startswith(b"diff --git a/"):
            if raw.startswith(b"@@"):
                malformed = malformed or f"a hunk follows the '-- ' signature at patch line {n} (git: patch fragment without header)"
            continue  # signature text: git ignores it, so it is neither a change nor part of the file's chunk
        if raw.startswith(b"diff --git a/") and malformed is None:
            if cur_path is not None:
                out.append((cur_path, bytes(cur)))
            cur_path, cur = _hdr_path(raw), bytearray()
            after_hunk = sig_seen = False
        elif raw.startswith(b"@@") and cur_path is not None:
            m = _HUNK_RE.match(raw)
            if not m:
                malformed = malformed or f"unreadable hunk header at patch line {n}"
            else:
                rem_old = int(m.group(1)) if m.group(1) is not None else 1
                rem_new = int(m.group(2)) if m.group(2) is not None else 1
                after_hunk = rem_old == 0 and rem_new == 0
        elif after_hunk and cur_path is not None and raw[:1] in (b"+", b"-", b" "):
            if raw.rstrip(b"\r\n") == b"-- ":
                sig_seen = True  # git format-patch's signature separator: ends only THIS file's body; a later 'diff --git' still starts a file (git applies it), a later '@@' is refused
                continue
            else:
                malformed = malformed or f"a change line follows a complete hunk at patch line {n} (git ignores or refuses it)"
        cur += raw
    if rem_old > 0 or rem_new > 0:
        malformed = malformed or "the patch ends inside a hunk"
    if cur_path is not None:
        out.append((cur_path, bytes(cur)))
    return out, malformed


def _hdr_path(line: bytes) -> str:
    s = line.decode("utf-8", "replace").rstrip("\n")
    rest = s[len("diff --git a/"):]
    half = rest.find(" b/")
    return rest[half + 3:] if half >= 0 else rest


def scan(repo, args, env, c: Change, untracked: set | None = None) -> Change:
    """ONE streaming pass over `git diff args`: per-file bytes/+/-/status/binary (no whole-diff buffer beyond the engine policy)."""
    c._repo, c._args, c._env = str(repo), tuple(args), dict(env or {})
    try:
        stream = gitq.open_stream(repo, ["diff", *DIFF_ARGS, *args], env)
    except gitq.GitReadError as ex:
        c.problem = f"could not diff: {ex}"
        c._git_error = ex
        return c
    except OSError as ex:
        c.problem = f"could not diff: {ex.strerror or ex}"
        return c
    infos: list[FileInfo] = []
    kept: dict = {}
    cur: FileInfo | None = None
    cur_buf = bytearray()
    total = 0
    keeping = True
    in_hunk = False
    pending = bytearray()

    def close():
        nonlocal cur, cur_buf
        if cur is not None:
            cur.bytes = len(cur_buf) if keeping else cur.bytes
            infos.append(cur)
            if keeping:
                kept[cur.path] = bytes(cur_buf)
        cur, cur_buf = None, bytearray()

    def _consume_line(raw: bytes) -> None:
        nonlocal cur, cur_buf, total, keeping, in_hunk
        total += len(raw)
        if raw.startswith(b"diff --git a/"):
            close()
            path = _hdr_path(raw)
            cur = FileInfo(path, 0, 0, 0, generated=generated_label(path), tool_state=tool_state_label(path), untracked=bool(untracked and path in untracked))
            in_hunk = False
        if cur is None:
            return
        if keeping and total > MAX_PATCH:
            keeping = False
            kept.clear()
            cur.bytes += len(cur_buf)  # what this file already accumulated before the policy was crossed
            cur_buf = bytearray()
        # byte accounting per file even when not keeping
        if keeping:
            cur_buf += raw
        else:
            cur.bytes += len(raw)
        if raw.startswith(b"@@"):
            in_hunk = True
        elif raw.startswith(b"new file mode"):
            cur.status = "add"
        elif raw.startswith(b"deleted file mode"):
            cur.status = "delete"
        elif raw.startswith(b"GIT binary patch") or raw.startswith(b"Binary files"):
            cur.binary, cur.added, cur.deleted = True, None, None
        elif in_hunk and cur.added is not None:
            if raw.startswith(b"+"):
                cur.added += 1
            elif raw.startswith(b"-"):
                cur.deleted = (cur.deleted or 0) + 1

    def _on_chunk(chunk: bytes) -> bool:
        pending.extend(chunk)
        start = 0
        while True:
            nl = pending.find(b"\n", start)
            if nl < 0:
                break
            _consume_line(bytes(pending[start:nl + 1]))
            start = nl + 1
        if start:
            del pending[:start]
        return True

    killed, timed_out, err = gitq.drain_stream(stream, on_chunk=_on_chunk, timeout=gitq.TIMEOUT * 4)
    if pending:
        _consume_line(bytes(pending))
        pending.clear()
    close()
    try:
        gitq.finish_stream(stream, stderr_bytes=err, killed_for_limit=killed, timed_out=timed_out, timeout=gitq.TIMEOUT * 4)
    except gitq.GitReadError as ex:
        c.problem = (
            "git took too long to produce this diff"
            if ex.kind is gitq.GitReadErrorKind.TIMEOUT
            else f"could not diff: {ex}"
        )
        c._git_error = ex
        c.infos = []
        c.files = []
        c._kept = {}
        c.patch = b""
        c.total_bytes = 0
        c.oversize = False
        return c
    infos.sort(key=lambda i: (bool(i.tool_state), bool(i.generated), i.path))
    c.infos = infos
    c.total_bytes = total
    c.files = [(i.path, i.added, i.deleted) for i in infos]
    c.oversize = total > MAX_PATCH
    if c.oversize:
        c._kept = {}
        c.patch = b""
    else:
        c._kept = kept
        c.patch = b"".join(kept[i.path] for i in infos)
    if total == 0 and not c.problem:
        c.problem = "no difference"
    return c


def _head(repo) -> str:
    """HEAD commit OID, or '' ONLY when HEAD is genuinely unborn (exit 1, empty stderr). Raises ``GitReadError`` on failure."""
    return gitq.optional_text(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}") or ""


_TEMPS: list[str] = []


def close_all() -> None:
    """Remove the temporary index/object directories created for uncommitted-work diffs (never touches the repository)."""
    while _TEMPS:
        shutil.rmtree(_TEMPS.pop(), ignore_errors=True)


atexit.register(close_all)


def uncommitted(repo) -> Change | None:
    why = gitq.refusal(repo)
    if why:  # a refused repository is NEVER "no uncommitted work" (silent-empty): the Change carries the reason
        c = Change("uncommitted", "Uncommitted work (not inspected)", "", b"")
        c.problem = why
        return c
    head = _head(repo)
    if not head:
        return None
    status_normal = gitq.read(repo, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
    n = len([e for e in status_normal.split(b"\0") if e])
    if n == 0:
        return None
    c = Change("uncommitted", "Uncommitted work (tracked edits and new files)", head, b"")
    status_all_raw = gitq.read(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    status_all = [e for e in status_all_raw.split(b"\0") if e]
    untracked = {e[3:].decode("utf-8", "replace") for e in status_all if e.startswith(b"??")}
    if len(untracked) > MAX_UNTRACKED:
        c.problem = f"{len(untracked)} untracked files: too many to diff; add a .gitignore or commit first"
        return c
    idx = gitq.read_text(repo, "rev-parse", "--path-format=absolute", "--git-path", "index")
    objs = gitq.read_text(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects")
    tmp = tempfile.mkdtemp(prefix="hlith-ui-index-")
    _TEMPS.append(tmp)  # kept until exit: a scoped diff of this work is re-read from it on demand
    try:
        if idx and Path(idx).is_file():
            shutil.copy2(idx, Path(tmp) / "index")  # keep the index mtime: git decides racily-clean entries by comparing file mtimes with it
        env = {"GIT_INDEX_FILE": str(Path(tmp) / "index"), "GIT_OBJECT_DIRECTORY": str(Path(tmp) / "objects"),
               "GIT_ALTERNATE_OBJECT_DIRECTORIES": objs}
        os.makedirs(Path(tmp) / "objects", exist_ok=True)
        gitq.read(repo, "add", "-A", env=env)
    except gitq.GitReadError as e:
        c.problem = f"could not diff: {e}"
        c._git_error = e
        return c
    except RuntimeError as e:
        c.problem = f"could not diff: {e}"
        return c
    return scan(repo, ["--cached", head], env, c, untracked)


def commits(repo, n: int = 8) -> list[Change]:
    out: list[Change] = []
    if not _head(repo):
        return out
    raw = gitq.read_text(repo, "log", f"-n{n}", "--no-merges", "--format=%H%x1f%h%x1f%an%x1f%as%x1f%s")
    for line in raw.splitlines():
        try:
            full, short, author, day, subj = line.split("\x1f", 4)
        except ValueError:
            continue
        parent = gitq.optional_text(repo, "rev-parse", "--verify", "-q", f"{full}^") or ""
        c = Change("commit", f"{short} {subj}", parent, b"", detail=f"{author}, {day}")
        if not parent:
            c.problem = "root commit: no base to apply it on"
        else:
            scan(repo, [parent, full], {}, c)
        out.append(c)
    return out


def _default_branch(repo) -> str:
    ref = gitq.optional_text(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD")
    if ref:
        return ref
    for b in ("main", "master"):
        if gitq.optional_text(repo, "rev-parse", "--verify", "-q", b):
            return b
    return gitq.optional_text(repo, "symbolic-ref", "-q", "--short", "HEAD") or ""


def branches(repo, limit: int = 6) -> list[Change]:
    base = _default_branch(repo)
    if not base:
        return []
    out: list[Change] = []
    for b in gitq.read_text(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines():
        if b == base or b == base.split("/", 1)[-1]:
            continue
        if b.startswith("-"):  # a ref NAME comes from the repository: one that looks like an option is never handed to git as an operand
            continue
        mb = gitq.optional_text(repo, "merge-base", base, b)
        tip = gitq.read_text(repo, "rev-parse", b)
        if not mb or mb == tip:
            continue
        cnt = gitq.read_text(repo, "rev-list", "--count", f"{mb}..{tip}")
        c = Change("branch", f"branch {b} vs {base} ({cnt} commit{'s' if cnt != '1' else ''})", mb, b"", detail=f"merge-base {mb[:8]}")
        scan(repo, [mb, tip], {}, c)
        out.append(c)
        if len(out) >= limit:
            break
    return out


def _patch_change(label, head, p, data) -> Change:
    c = Change("patchfile", label, head, b"", detail=str(p.parent), source=str(p.resolve()))
    if len(data) > MAX_PATCH:
        # refuse an oversize patch FILE before parsing it (a 40 MB patch cost ~250 MB of RSS); a patch file cannot be scoped, so there is nothing to review
        c._raw, c.total_bytes, c.oversize = b"", len(data), True
        c.problem = f"the patch is {len(data) // 1024:,} KiB; the engine patch limit is {MAX_PATCH // 1024:,} KiB, so Hlith will not review or start it"
        return c
    parts, malformed = _split_files_checked(data)
    if malformed:
        c.problem = f"the patch is malformed ({malformed}); Hlith will not review or start it"
    c._raw = data
    c.total_bytes = len(data)
    c.oversize = len(data) > MAX_PATCH
    for path, chunk in parts:
        info = FileInfo(path, 0, 0, len(chunk), generated=generated_label(path), tool_state=tool_state_label(path))
        in_hunk = False
        for ln in chunk.split(b"\n"):
            if ln.startswith(b"@@"):
                in_hunk = True
            elif ln.startswith(b"new file mode"):
                info.status = "add"
            elif ln.startswith(b"deleted file mode"):
                info.status = "delete"
            elif ln.startswith(b"GIT binary patch") or ln.startswith(b"Binary files"):
                info.binary, info.added, info.deleted = True, None, None
            elif in_hunk and info.added is not None:
                if ln.startswith(b"+"):
                    info.added += 1
                elif ln.startswith(b"-"):
                    info.deleted += 1
        c.infos.append(info)
        if not c.oversize:
            c._kept[path] = chunk
    c.infos.sort(key=lambda i: (bool(i.tool_state), bool(i.generated), i.path))
    c.files = [(i.path, i.added, i.deleted) for i in c.infos]
    if not c.oversize:
        c.patch = data
    return c


def patchfiles(repo, extra_dirs=()) -> list[Change]:
    head = _head(repo)
    out: list[Change] = []
    seen = set()
    for d in (repo, *map(Path, extra_dirs)):  # the repository and the directories the operator named; NOT the process's cwd (it may be another session's folder)
        try:
            names = sorted(Path(d).iterdir())
        except OSError:
            continue
        for p in names:
            if p.suffix in (".patch", ".diff") and p.is_file() and p.resolve() not in seen and len(seen) < 20:
                seen.add(p.resolve())
                try:
                    data = p.read_bytes()
                except OSError as e:
                    c = Change("patchfile", f"patch file {p.name}", head, b"", detail=str(p.parent), source=str(p.resolve()))
                    c.problem = f"unreadable: {e.strerror}"
                    out.append(c)
                    continue
                c = _patch_change(f"patch file {p.name}", head, p, data)
                if not c.files:
                    c.problem = "not a git diff (no files recognised)"
                out.append(c)
    return out


def discover(repo, extra_dirs=()) -> list[Change]:
    """Everything offered for this repo, uncommitted work first."""
    out: list[Change] = []
    if gitq.refusal(repo):  # settings that can run programs: nothing is inspected, repos.info says why
        return out
    u = uncommitted(repo)
    if u:
        out.append(u)
    out += commits(repo)
    out += branches(repo)
    out += patchfiles(repo, extra_dirs)
    return out
