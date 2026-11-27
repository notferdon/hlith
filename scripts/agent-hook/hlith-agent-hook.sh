#!/usr/bin/env bash
# Asynchronous Hlith Review glue for a coding agent (Claude Code hook JSON; usable from any agent that can run a command).
#
# A real `hlith check` can take minutes (the recorded external anchor: 76 s cold / 74 s warm; larger repositories may take longer), so it never runs inside a hook call. This script:
#   post    (PostToolUse after an edit)   start ONE detached `hlith check --uncommitted` and return at once. The agent is told
#                                         the change is UNVERIFIED while the check is pending (model-visible additionalContext).
#   prompt  (UserPromptSubmit, next turn) report the receipt: pending, or the finished outcome with the witness and next commands.
#   stop    (Stop)                        block the stop ONLY when a finished check REFUTED the change or could not decide;
#                                         a pending check never blocks and is never reported as success.
#   status                                print the receipt JSON.
#
# Receipts live OUTSIDE the repository: ${HLITH_HOOK_HOME:-$HOME/.local/state/hlith-agent-hook}/<repo-name>-<hash>/ .
# Receipt routing integrity scope: binds each receipt to HEAD commit OID, HEAD^{tree} OID, tracked working-tree diff vs HEAD,
# git porcelain state, and bounded non-ignored untracked files (regular files up to 8 MiB/file, 32 MiB total; symlink targets
# via readlink; special files such as FIFOs/sockets/devices fail closed), and validates the hlith.check/1 JSON envelope.
# This is local receipt routing integrity, NOT an adversarial tamper-proof boundary or full dependency/venv fingerprint.
# Environment: HLITH_BIN (default: hlith), HLITH_TARGET_PYTHON (optional; when unset, hlith check auto-detects .venv/venv or its own interpreter),
#              HLITH_HOOK_TIMEOUT seconds for the detached check (default 3000), CLAUDE_PROJECT_DIR or PWD for the repository.
# Never runs `hlith apply`; exit 0 from hlith is reported as a rehearsal only.
set -u
MODE="${1:-post}"
RAW_REPO="${2:-${CLAUDE_PROJECT_DIR:-$PWD}}"
HLITH_BIN="${HLITH_BIN:-hlith}"
TARGET_PY="${HLITH_TARGET_PYTHON:-}"
TIMEOUT="${HLITH_HOOK_TIMEOUT:-3000}"

hook_py() {
  python3 - "$@" <<'PY'
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

SCHEMA_VERSION = 2
GIT_TIMEOUT = 30
MAX_DIFF_BYTES = 64 * 1024 * 1024
MAX_UNTRACKED_FILES = 5000
MAX_UNTRACKED_FILE_BYTES = 8 * 1024 * 1024
MAX_UNTRACKED_TOTAL_BYTES = 32 * 1024 * 1024
CHUNK_SIZE = 65536
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NON_ENVELOPE_EXITS = {124, 126, 127}
BASE_REQUIRED_EXITS = {0, 10, 11, 12}

NAMES = {
    0: "LANDED (disposable rehearsal only; NOT merge permission)",
    3: "INTERNAL ERROR (nothing decided)",
    10: "REFUTED",
    11: "NOT-DERIVED (undetermined)",
    12: "UNVERIFIED/unsupported",
    4: "BOUNDARY refusal",
    124: "TIMED OUT (UNVERIFIED)",
}


def _git_env():
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git_run(repo, args):
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo, *args],
            capture_output=True,
            timeout=GIT_TIMEOUT,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired:
        return None, f"git {args[0]} timed out after {GIT_TIMEOUT}s"
    except OSError as exc:
        return None, f"git {args[0]} failed to start: {exc.strerror or type(exc).__name__}"
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        detail = f": {err[0][:160]}" if err else ""
        return None, f"git {args[0]} failed (exit {proc.returncode}){detail}"
    return proc.stdout, None


def _git_stream_hash(repo, args, hasher, max_bytes):
    try:
        proc = subprocess.Popen(
            ["git", "--no-optional-locks", "-C", repo, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(),
        )
    except OSError as exc:
        return None, f"git {args[0]} failed to start: {exc.strerror or type(exc).__name__}"
    total = 0
    assert proc.stdout is not None and proc.stderr is not None
    try:
        while True:
            chunk = proc.stdout.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                proc.kill()
                proc.wait(timeout=5)
                return None, f"git {args[0]} output exceeds {max_bytes // (1024 * 1024)} MiB fingerprint limit"
            hasher.update(chunk)
        stderr_data = proc.stderr.read(4096)
        rc = proc.wait(timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        return None, f"git {args[0]} timed out after {GIT_TIMEOUT}s"
    if rc != 0:
        err = stderr_data.decode("utf-8", "replace").strip().splitlines()
        detail = f": {err[0][:160]}" if err else ""
        return None, f"git {args[0]} failed (exit {rc}){detail}"
    return total, None


def _special_kind(mode):
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "char-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISDIR(mode):
        return "directory"
    return "special"


MAX_SCAN_ENTRIES = 50000


def _git_ignored_set(repo, rel_paths):
    if not rel_paths:
        return set()
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo, "check-ignore", "--stdin", "-z"],
            input=b"\0".join(rel_paths) + b"\0",
            capture_output=True,
            timeout=GIT_TIMEOUT,
            env=_git_env(),
        )
    except (subprocess.TimeoutExpired, OSError):
        return set()
    # check-ignore exits 0 when at least one path is ignored, 1 when none are ignored, 128 on fatal error
    if proc.returncode not in (0, 1):
        return set()
    return {p for p in proc.stdout.split(b"\0") if p}


def _scan_special_files(repo):
    """Detect non-ignored special files (FIFO, socket, char/block device) without opening them or walking ignored trees."""
    repo_bytes = os.fsencode(repo)
    stack = [b""]
    scanned = 0
    while stack:
        rel_dir = stack.pop()
        abs_dir = repo_bytes if not rel_dir else os.path.join(repo_bytes, rel_dir)
        try:
            with os.scandir(abs_dir) as it:
                entries = list(it)
        except OSError as exc:
            disp = rel_dir.decode("utf-8", "replace") or "."
            return f"cannot scan directory {disp}: {exc.strerror or type(exc).__name__}"

        subdirs = []
        specials = []
        for entry in entries:
            name = entry.name
            if not rel_dir and name == b".git":
                continue
            scanned += 1
            if scanned > MAX_SCAN_ENTRIES:
                return f"working tree entry count exceeds {MAX_SCAN_ENTRIES} fingerprint scan limit"
            rel = name if not rel_dir else rel_dir + b"/" + name
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    subdirs.append(rel)
                    continue
                st = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and not stat.S_ISDIR(st.st_mode):
                    specials.append((rel, _special_kind(st.st_mode)))
            except OSError as exc:
                disp = rel.decode("utf-8", "replace")
                return f"cannot stat working tree entry {disp}: {exc.strerror or type(exc).__name__}"

        if specials:
            ignored_specials = _git_ignored_set(repo, [r for r, _ in specials])
            for rel, kind in sorted(specials):
                if rel not in ignored_specials:
                    return f"refusing special untracked/working-tree file ({kind}): {rel.decode('utf-8', 'replace')}"
        if subdirs:
            ignored_dirs = _git_ignored_set(repo, [d + b"/" for d in subdirs])
            for d in reversed(sorted(subdirs)):
                if (d + b"/") not in ignored_dirs and d not in ignored_dirs:
                    stack.append(d)
    return None


def compute_fp(repo):
    if not repo or not os.path.isdir(repo):
        return {"ok": False, "error": "repository path is unavailable or not a directory"}

    head_raw, err = _git_run(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
    if err:
        return {"ok": False, "error": err}
    head = head_raw.decode("ascii", "replace").strip().lower()
    if not HEX40.fullmatch(head):
        return {"ok": False, "error": "git rev-parse HEAD^{commit} returned an invalid commit OID"}

    tree_raw, err = _git_run(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{tree}"])
    if err:
        return {"ok": False, "error": err}
    tree = tree_raw.decode("ascii", "replace").strip().lower()
    if not HEX40.fullmatch(tree):
        return {"ok": False, "error": "git rev-parse HEAD^{tree} returned an invalid tree OID"}

    special_err = _scan_special_files(repo)
    if special_err:
        return {"ok": False, "error": special_err}

    porcelain, err = _git_run(repo, ["status", "--porcelain=v1", "-z"])
    if err:
        return {"ok": False, "error": err}

    h = hashlib.sha256()
    h.update(b"case/2\0")
    h.update(b"H" + head.encode("ascii") + b"\0")
    h.update(b"T" + tree.encode("ascii") + b"\0")
    h.update(b"S" + str(len(porcelain)).encode("ascii") + b"\0" + porcelain)

    h.update(b"\0D\0")
    diff_len, err = _git_stream_hash(
        repo,
        [
            "diff",
            "--binary",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--full-index",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "HEAD",
            "--",
        ],
        h,
        MAX_DIFF_BYTES,
    )
    if err:
        return {"ok": False, "error": err}
    h.update(b"\0DL" + str(diff_len).encode("ascii") + b"\0")

    untracked_raw, err = _git_run(repo, ["ls-files", "-o", "--exclude-standard", "-z"])
    if err:
        return {"ok": False, "error": err}
    names = sorted(x for x in untracked_raw.split(b"\0") if x)
    if len(names) > MAX_UNTRACKED_FILES:
        return {"ok": False, "error": f"untracked file count ({len(names)}) exceeds {MAX_UNTRACKED_FILES} fingerprint limit"}

    repo_bytes = os.fsencode(repo)
    untracked_total = 0
    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for rel in names:
        display = rel.decode("utf-8", "replace")
        full = os.path.join(repo_bytes, rel)
        try:
            st = os.lstat(full)
        except OSError as exc:
            return {"ok": False, "error": f"cannot stat untracked file {display}: {exc.strerror or type(exc).__name__}"}
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(full)
            except OSError as exc:
                return {"ok": False, "error": f"cannot readlink untracked symlink {display}: {exc.strerror or type(exc).__name__}"}
            h.update(b"\0L" + rel + b"\0" + str(len(target)).encode("ascii") + b"\0" + target)
            continue
        if not stat.S_ISREG(st.st_mode):
            return {"ok": False, "error": f"refusing special untracked file ({_special_kind(st.st_mode)}): {display}"}
        if st.st_size > MAX_UNTRACKED_FILE_BYTES:
            return {"ok": False, "error": f"untracked file exceeds {MAX_UNTRACKED_FILE_BYTES // (1024 * 1024)} MiB fingerprint limit: {display}"}
        try:
            fd = os.open(full, open_flags)
        except OSError as exc:
            return {"ok": False, "error": f"cannot open untracked file {display}: {exc.strerror or type(exc).__name__}"}
        try:
            finfo = os.fstat(fd)
            if not stat.S_ISREG(finfo.st_mode):
                return {"ok": False, "error": f"refusing special untracked file ({_special_kind(finfo.st_mode)}): {display}"}
            h.update(b"\0F" + rel + b"\0" + oct(finfo.st_mode & 0o777).encode("ascii") + b"\0")
            file_bytes = 0
            while True:
                chunk = os.read(fd, CHUNK_SIZE)
                if not chunk:
                    break
                file_bytes += len(chunk)
                untracked_total += len(chunk)
                if file_bytes > MAX_UNTRACKED_FILE_BYTES:
                    return {"ok": False, "error": f"untracked file exceeds {MAX_UNTRACKED_FILE_BYTES // (1024 * 1024)} MiB fingerprint limit: {display}"}
                if untracked_total > MAX_UNTRACKED_TOTAL_BYTES:
                    return {"ok": False, "error": f"total untracked bytes exceed {MAX_UNTRACKED_TOTAL_BYTES // (1024 * 1024)} MiB fingerprint limit"}
                h.update(chunk)
            h.update(b"\0FL" + str(file_bytes).encode("ascii") + b"\0")
        except OSError as exc:
            return {"ok": False, "error": f"cannot read untracked file {display}: {exc.strerror or type(exc).__name__}"}
        finally:
            os.close(fd)

    clean = (porcelain == b"" and diff_len == 0 and len(names) == 0)
    return {"ok": True, "head": head, "tree": tree, "clean": clean, "fp": h.hexdigest()}


def atomic_write_bytes(path, data):
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".hook", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_replace_file(src_path, dst_path):
    if src_path and os.path.exists(src_path):
        try:
            fd = os.open(src_path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
        os.chmod(src_path, 0o600)
        os.replace(src_path, dst_path)
    elif os.path.exists(dst_path):
        try:
            os.unlink(dst_path)
        except OSError:
            pass


def validate_envelope(last_path, rc, expected_head, expected_tree):
    if rc in NON_ENVELOPE_EXITS or rc > 128:
        return True, None, {}
    if not os.path.isfile(last_path):
        return False, "missing last.json check envelope", {}
    try:
        with open(last_path, "r", encoding="utf-8") as stream:
            env = json.load(stream)
    except Exception as exc:
        return False, f"malformed last.json ({type(exc).__name__})", {}
    if not isinstance(env, dict):
        return False, "malformed last.json (not a JSON object)", {}
    if env.get("envelope") != "hlith.check/1":
        return False, f"unexpected check envelope {env.get('envelope')!r}", {}
    env_rc = env.get("exit_status")
    if type(env_rc) is not int or env_rc != rc:
        return False, f"envelope exit_status {env_rc!r} disagrees with process exit {rc}", {}
    chk = env.get("check")
    if not isinstance(chk, dict):
        return False, "malformed check metadata in last.json", {}
    art = env.get("artifact")
    if rc == 0:
        if not isinstance(art, dict):
            return False, "exit 0 receipt has no artifact object", {}
        art_rc = art.get("exit_status")
        if type(art_rc) is not int or art_rc != 0:
            return False, f"exit 0 receipt artifact.exit_status is {art_rc!r}", {}
        if art.get("outcome") != "landed":
            return False, f"exit 0 receipt artifact.outcome is {art.get('outcome')!r}, not 'landed'", {}
    elif art is not None:
        if not isinstance(art, dict):
            return False, "malformed artifact object in last.json", {}
        art_rc = art.get("exit_status")
        if art_rc is not None and (type(art_rc) is not int or art_rc != rc):
            return False, f"artifact.exit_status {art_rc!r} disagrees with process exit {rc}", {}

    base_commit = chk.get("base_commit")
    if rc in BASE_REQUIRED_EXITS:
        if not isinstance(base_commit, str) or not HEX40.fullmatch(base_commit.lower()):
            return False, "check envelope is missing valid check.base_commit", {}
        if base_commit.lower() != expected_head.lower():
            return False, f"envelope base_commit {base_commit[:8]} disagrees with receipt HEAD {expected_head[:8]}", {}
    elif base_commit is not None:
        if not isinstance(base_commit, str) or base_commit.lower() != expected_head.lower():
            return False, f"envelope base_commit {str(base_commit)[:8]} disagrees with receipt HEAD {expected_head[:8]}", {}

    if isinstance(art, dict):
        run_meta = art.get("run")
        rc_meta = run_meta.get("replay_context") if isinstance(run_meta, dict) else None
        rc_base = rc_meta.get("base") if isinstance(rc_meta, dict) else None
        if isinstance(rc_base, dict):
            rc_commit = rc_base.get("commit")
            if isinstance(rc_commit, str) and rc_commit.lower() != expected_head.lower():
                return False, f"artifact replay_context base commit {rc_commit[:8]} disagrees with receipt HEAD {expected_head[:8]}", {}
            rc_tree = rc_base.get("tree_oid")
            if isinstance(rc_tree, str) and rc_tree.lower() != expected_tree.lower():
                return False, f"artifact replay_context base tree {rc_tree[:8]} disagrees with receipt tree {expected_tree[:8]}", {}

    return True, None, env


def _worker_lock_held(home_dir):
    lock_path = os.path.join(home_dir, "worker.lock")
    if not os.path.exists(lock_path):
        return None
    fd = os.open(lock_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _pid_alive(pid):
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _format_summary(home_dir, st, env):
    rc = st.get("exit")
    art = env.get("artifact") if isinstance(env, dict) else None
    if not isinstance(art, dict):
        art = {}
    chk = env.get("check") if isinstance(env, dict) else None
    if not isinstance(chk, dict):
        chk = {}
    wit = []
    for o in art.get("obligations") or []:
        if not isinstance(o, dict):
            continue
        w = o.get("witness_call")
        if isinstance(w, dict) and o.get("verdict") == "refuted":
            wit.append("%s args=%s kwargs=%s" % (o.get("id"), json.dumps(w.get("args")), json.dumps(w.get("kwargs"))))
    head = st.get("head")
    base_note = f", base {head[:8]}" if isinstance(head, str) and HEX40.fullmatch(head) else ""
    t = "hlith check %s (exit %s, %ss, run %s%s)." % (
        NAMES.get(rc, "exit %s" % rc),
        rc,
        st.get("seconds"),
        chk.get("run_id"),
        base_note,
    )
    if rc == 4:
        bkind = chk.get("boundary_kind")
        breason = chk.get("reason")
        if not breason and isinstance(art.get("blocking"), list) and art.get("blocking"):
            breason = ": ".join(str(x) for x in art.get("blocking")[:2])
        if breason:
            prefix = f"[{bkind}] " if isinstance(bkind, str) and bkind and bkind not in str(breason) else ""
            t += " Boundary: %s%s." % (prefix, str(breason).strip()[:220])
    if wit:
        t += " Witness: " + "; ".join(wit) + "."
    if chk.get("replay_command"):
        t += " Replay: %s . Inspect: %s ." % (chk.get("replay_command"), chk.get("inspect_command"))
    t += " Receipt: %s" % os.path.join(home_dir, "last.json")
    return t


def _read_status_snapshot(home_dir):
    lock_path = os.path.join(home_dir, "state.lock")
    status_path = os.path.join(home_dir, "status.json")
    last_path = os.path.join(home_dir, "last.json")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        worker_held = _worker_lock_held(home_dir)
        if not os.path.exists(status_path):
            return None, None, worker_held, None
        try:
            with open(status_path, "r", encoding="utf-8") as stream:
                st = json.load(stream)
        except Exception as exc:
            return None, f"malformed status.json ({type(exc).__name__})", worker_held, None
        if not isinstance(st, dict):
            return None, "malformed status.json (not a JSON object)", worker_held, None
        last_bytes = None
        if os.path.isfile(last_path):
            try:
                with open(last_path, "rb") as stream:
                    last_bytes = stream.read(16 * 1024 * 1024)
            except OSError:
                last_bytes = None
        return st, None, worker_held, last_bytes
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def inspect_state(repo, home_dir):
    st, st_err, worker_held, last_bytes = _read_status_snapshot(home_dir)
    if st_err is not None:
        return {"state": "invalid", "error": st_err}
    if st is None:
        if worker_held is True:
            return {"state": "running"}
        return {"state": "none"}

    kind = st.get("status")
    if kind == "error":
        reason = st.get("error") if isinstance(st.get("error"), str) and st.get("error") else "repository fingerprint failed"
        return {"state": "error", "error": reason}
    if kind == "running":
        if worker_held is True:
            return {"state": "running"}
        if worker_held is False:
            return {"state": "interrupted"}
        pid = st.get("pid")
        return {"state": "running" if _pid_alive(pid) else "interrupted"}
    if kind != "done":
        return {"state": "invalid", "error": f"unknown receipt status {kind!r}"}

    rc = st.get("exit")
    head = st.get("head")
    tree = st.get("tree")
    fp_val = st.get("fp")
    if type(rc) is not int:
        return {"state": "invalid", "error": "receipt is missing integer exit code"}
    if not isinstance(head, str) or not HEX40.fullmatch(head.lower()):
        return {"state": "invalid", "error": "receipt is missing valid HEAD base commit"}
    if not isinstance(tree, str) or not HEX40.fullmatch(tree.lower()):
        return {"state": "invalid", "error": "receipt is missing valid HEAD tree OID"}
    if not isinstance(fp_val, str) or not HEX64.fullmatch(fp_val.lower()):
        return {"state": "invalid", "error": "receipt is missing valid SHA-256 fingerprint"}

    # Validate envelope against the snapshot read under state.lock
    if rc in NON_ENVELOPE_EXITS or rc > 128:
        env_ok, env_err, env = True, None, {}
    else:
        tmp_env = None
        if last_bytes is None:
            env_ok, env_err, env = False, "missing last.json check envelope", {}
        else:
            try:
                tmp_env = os.path.join(home_dir, f".validate-{os.getpid()}.json")
                with open(tmp_env, "wb") as stream:
                    stream.write(last_bytes)
                env_ok, env_err, env = validate_envelope(tmp_env, rc, head, tree)
            finally:
                if tmp_env:
                    try:
                        os.unlink(tmp_env)
                    except OSError:
                        pass
    if not env_ok:
        return {"state": "invalid", "exit": rc, "error": env_err or "malformed check envelope"}

    now = compute_fp(repo)
    if not now.get("ok"):
        return {"state": "error", "error": now.get("error") or "failed to fingerprint repository"}

    summary = _format_summary(home_dir, st, env)
    same = (
        head.lower() == now["head"]
        and tree.lower() == now["tree"]
        and fp_val.lower() == now["fp"]
    )
    return {
        "state": "done" if same else "stale",
        "exit": rc,
        "summary": summary,
        "head": head.lower(),
        "current_head": now["head"],
    }


def main():
    cmd = sys.argv[1]
    if cmd == "fp":
        print(json.dumps(compute_fp(sys.argv[2]), sort_keys=True))
    elif cmd == "emit-context":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": sys.argv[2], "additionalContext": sys.argv[3]}}))
    elif cmd == "emit-block":
        print(json.dumps({"decision": "block", "reason": sys.argv[2]}))
    elif cmd == "stop-active":
        raw = sys.argv[2] if len(sys.argv) > 2 else ""
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except Exception:
            sys.exit(1)
        sys.exit(0 if isinstance(payload, dict) and payload.get("stop_hook_active") is True else 1)
    elif cmd == "write-status":
        status_path = sys.argv[2]
        payload = json.loads(sys.argv[3])
        payload["schema_version"] = SCHEMA_VERSION
        atomic_write_bytes(status_path, (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
    elif cmd == "publish-worker":
        home_dir, status_json_str, tmp_last, tmp_err = sys.argv[2:6]
        payload = json.loads(status_json_str)
        payload["schema_version"] = SCHEMA_VERSION
        lock_path = os.path.join(home_dir, "state.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if tmp_last != "-":
                atomic_replace_file(tmp_last, os.path.join(home_dir, "last.json"))
            if tmp_err != "-":
                atomic_replace_file(tmp_err, os.path.join(home_dir, "last.err"))
            atomic_write_bytes(
                os.path.join(home_dir, "status.json"),
                (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
            )
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
    elif cmd == "validate-envelope":
        ok, err, _ = validate_envelope(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
        print(json.dumps({"ok": ok, "error": err}, sort_keys=True))
    elif cmd == "inspect":
        print(json.dumps(inspect_state(sys.argv[2], sys.argv[3]), sort_keys=True))
    elif cmd == "status":
        st, st_err, _, _ = _read_status_snapshot(sys.argv[2])
        if st_err is not None:
            print(json.dumps({"status": "invalid", "error": st_err}, sort_keys=True))
        elif st is None:
            print(json.dumps({"status": "none"}, sort_keys=True))
        else:
            print(json.dumps(st, sort_keys=True))
    elif cmd == "clear-state":
        home_dir = sys.argv[2]
        lock_path = os.path.join(home_dir, "state.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            for name in ("status.json", "last.json", "last.err"):
                try:
                    os.unlink(os.path.join(home_dir, name))
                except OSError:
                    pass
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
    else:
        raise SystemExit(f"unknown internal command: {cmd}")


if __name__ == "__main__":
    main()
PY
}

emit_context() { hook_py emit-context "$1" "$2"; }
emit_block() { hook_py emit-block "$1"; }

if [ ! -d "$RAW_REPO" ] || ! REPO="$(cd "$RAW_REPO" 2>/dev/null && pwd -P)"; then
  case "$MODE" in
    post)
      cat > /dev/null
      emit_context PostToolUse "hlith check could not read repository path ($RAW_REPO): this change is UNVERIFIED. Do not report it as verified."
      exit 0;;
    prompt)
      cat > /dev/null
      emit_context UserPromptSubmit "hlith check could not read repository path ($RAW_REPO): this change is UNVERIFIED. Do not claim success."
      exit 0;;
    stop)
      PAYLOAD="$(cat)"
      hook_py stop-active "$PAYLOAD" && exit 0
      emit_block "hlith check could not read repository path ($RAW_REPO): this change is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe."
      exit 0;;
    status)
      echo '{"status": "error", "error": "repository path is unavailable"}'
      exit 0;;
    *)
      echo "usage: $0 post|prompt|stop|status|worker [repo]" >&2; exit 2;;
  esac
fi

KEY="$(basename "$REPO")-$(printf '%s' "$REPO" | cksum | cut -d' ' -f1)"
HOME_DIR="${HLITH_HOOK_HOME:-$HOME/.local/state/hlith-agent-hook}/$KEY"
mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR" 2>/dev/null || true
STATUS="$HOME_DIR/status.json"

case "$MODE" in
worker)
  LOCKED_BY_POST="${_HLITH_HOOK_LOCKED_FD8:-0}"
  unset _HLITH_HOOK_LOCKED_FD8
  if [ "$LOCKED_BY_POST" != "1" ]; then
    exec 8>"$HOME_DIR/worker.lock"
    flock -n 8 || exit 0
  fi
  START="${3:-$(date +%s)}"
  for ATTEMPT in 1 2 3; do   # a tree or HEAD that changed while the check ran is checked again (at most twice more)
    PRE_JSON="$(hook_py fp "$REPO" 8>&-)"
    PRE_OK="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print("1" if d.get("ok") else "0")' "$PRE_JSON" 8>&-)"
    if [ "$PRE_OK" != "1" ]; then
      ERR_MSG="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","fingerprint failed"))' "$PRE_JSON" 8>&-)"
      ERR_STATUS="$(python3 -c 'import json,sys; print(json.dumps({"status":"error","started":int(sys.argv[1]),"error":sys.argv[2]}))' "$START" "$ERR_MSG" 8>&-)"
      hook_py publish-worker "$HOME_DIR" "$ERR_STATUS" "" "" 8>&-
      break
    fi
    PRE_CLEAN="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("clean") else "0")' "$PRE_JSON" 8>&-)"
    if [ "$PRE_CLEAN" = "1" ]; then
      [ "$ATTEMPT" = "1" ] && hook_py clear-state "$HOME_DIR" 8>&-
      break
    fi
    HEAD_OID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["head"])' "$PRE_JSON" 8>&-)"
    TREE_OID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tree"])' "$PRE_JSON" 8>&-)"
    FP_VAL="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fp"])' "$PRE_JSON" 8>&-)"

    RUN_STATUS="$(python3 -c 'import json,sys; print(json.dumps({"status":"running","started":int(sys.argv[1]),"pid":int(sys.argv[2]),"attempt":int(sys.argv[3]),"head":sys.argv[4],"tree":sys.argv[5],"fp":sys.argv[6]}))' "$START" "$$" "$ATTEMPT" "$HEAD_OID" "$TREE_OID" "$FP_VAL" 8>&-)"
    hook_py publish-worker "$HOME_DIR" "$RUN_STATUS" "-" "-" 8>&-

    RUN_OUT="$HOME_DIR/artifact-${START}-$$-${ATTEMPT}"   # --artifact-out must be a NEW directory outside the repository
    TMP_LAST="$(mktemp "$HOME_DIR/.last-${START}-$$-${ATTEMPT}-XXXXXX.json" 8>&-)"
    TMP_ERR="$(mktemp "$HOME_DIR/.err-${START}-$$-${ATTEMPT}-XXXXXX.err" 8>&-)"
    PY_ARGS=()
    [ -n "$TARGET_PY" ] && PY_ARGS=(--target-python "$TARGET_PY")
    timeout "$TIMEOUT" "$HLITH_BIN" check --repo "$REPO" --uncommitted --no-input --json "${PY_ARGS[@]}" \
      --artifact-out "$RUN_OUT" > "$TMP_LAST" 2> "$TMP_ERR" 8>&-
    RC=$?

    POST_JSON="$(hook_py fp "$REPO" 8>&-)"
    POST_OK="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("ok") else "0")' "$POST_JSON" 8>&-)"
    if [ "$POST_OK" != "1" ]; then
      ERR_MSG="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","fingerprint failed"))' "$POST_JSON" 8>&-)"
      ERR_STATUS="$(python3 -c 'import json,sys; print(json.dumps({"status":"error","started":int(sys.argv[1]),"error":sys.argv[2]}))' "$START" "$ERR_MSG" 8>&-)"
      hook_py publish-worker "$HOME_DIR" "$ERR_STATUS" "$TMP_LAST" "$TMP_ERR" 8>&-
      break
    fi

    POST_SAME="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print("1" if (d.get("head")==sys.argv[2] and d.get("tree")==sys.argv[3] and d.get("fp")==sys.argv[4]) else "0")' "$POST_JSON" "$HEAD_OID" "$TREE_OID" "$FP_VAL" 8>&-)"
    POST_CLEAN="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("clean") else "0")' "$POST_JSON" 8>&-)"
    ENV_VAL="$(hook_py validate-envelope "$TMP_LAST" "$RC" "$HEAD_OID" "$TREE_OID" 8>&-)"
    ENV_OK="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("ok") else "0")' "$ENV_VAL" 8>&-)"
    ENV_ERR="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error") or "")' "$ENV_VAL" 8>&-)"
    ELAPSED="$(( $(date +%s) - START ))"

    if [ "$POST_SAME" = "1" ] || [ "$ATTEMPT" = "3" ] || [ "$POST_CLEAN" = "1" ]; then
      DONE_STATUS="$(python3 -c 'import json,sys; d={"status":"done","exit":int(sys.argv[1]),"seconds":int(sys.argv[2]),"started":int(sys.argv[3]),"head":sys.argv[4],"tree":sys.argv[5],"fp":sys.argv[6],"envelope_ok":(sys.argv[7]=="1")};
if sys.argv[8]: d["envelope_error"]=sys.argv[8]
print(json.dumps(d))' "$RC" "$ELAPSED" "$START" "$HEAD_OID" "$TREE_OID" "$FP_VAL" "$ENV_OK" "$ENV_ERR" 8>&-)"
      hook_py publish-worker "$HOME_DIR" "$DONE_STATUS" "$TMP_LAST" "$TMP_ERR" 8>&-
      break
    fi

    rm -f "$TMP_LAST" "$TMP_ERR"
  done
  exec 8>&-
  ;;
post)
  cat > /dev/null
  exec 9>"$HOME_DIR/state.lock"
  flock 9

  FP_JSON="$(hook_py fp "$REPO" 9>&-)"
  FP_OK="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("ok") else "0")' "$FP_JSON" 9>&-)"
  if [ "$FP_OK" != "1" ]; then
    ERR_MSG="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","fingerprint failed"))' "$FP_JSON" 9>&-)"
    exec 8>"$HOME_DIR/worker.lock"
    if flock -n 8; then
      rm -f "$HOME_DIR/last.json" "$HOME_DIR/last.err"
      ERR_STATUS="$(python3 -c 'import json,sys; print(json.dumps({"status":"error","started":int(sys.argv[1]),"error":sys.argv[2]}))' "$(date +%s)" "$ERR_MSG" 9>&-)"
      hook_py write-status "$STATUS" "$ERR_STATUS" 9>&-
      exec 8>&-
    else
      exec 8>&-
    fi
    exec 9>&-
    emit_context PostToolUse "hlith check could not fingerprint the repository ($ERR_MSG); this change is UNVERIFIED. Do not report it as verified."
    exit 0
  fi

  IS_CLEAN="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("clean") else "0")' "$FP_JSON" 9>&-)"
  if [ "$IS_CLEAN" = "1" ]; then
    exec 8>"$HOME_DIR/worker.lock"
    if flock -n 8; then
      rm -f "$STATUS" "$HOME_DIR/last.json" "$HOME_DIR/last.err"
      exec 8>&-
      exec 9>&-
      exit 0
    fi
    exec 8>&-
    exec 9>&-
    emit_context PostToolUse "hlith check is still RUNNING for an earlier edit; this change is UNVERIFIED until it finishes. Do not report it as verified."
    exit 0
  fi

  exec 8>"$HOME_DIR/worker.lock"
  if ! flock -n 8; then
    exec 8>&-
    exec 9>&-
    emit_context PostToolUse "hlith check is still RUNNING for an earlier edit; this change is UNVERIFIED until it finishes. Do not report it as verified."
    exit 0
  fi

  START="$(date +%s)"
  HEAD_OID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["head"])' "$FP_JSON" 9>&-)"
  TREE_OID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tree"])' "$FP_JSON" 9>&-)"
  FP_VAL="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fp"])' "$FP_JSON" 9>&-)"
  rm -f "$HOME_DIR/last.json" "$HOME_DIR/last.err"
  _HLITH_HOOK_LOCKED_FD8=1 setsid nohup "$0" worker "$REPO" "$START" > /dev/null 2>&1 < /dev/null 9>&- &
  WORKER_PID=$!
  INIT_STATUS="$(python3 -c 'import json,sys; print(json.dumps({"status":"running","started":int(sys.argv[1]),"pid":int(sys.argv[2]),"attempt":1,"head":sys.argv[3],"tree":sys.argv[4],"fp":sys.argv[5]}))' "$START" "$WORKER_PID" "$HEAD_OID" "$TREE_OID" "$FP_VAL" 9>&-)"
  hook_py write-status "$STATUS" "$INIT_STATUS" 9>&-
  exec 8>&-
  exec 9>&-
  emit_context PostToolUse "hlith check started in the background (it can take minutes on a large repo). Until its receipt says otherwise this change is UNVERIFIED: do not tell the user it is safe or verified. Receipt: $STATUS"
  ;;
prompt)
  cat > /dev/null
  INFO="$(hook_py inspect "$REPO" "$HOME_DIR")"
  STATE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("state","invalid"))' "$INFO")"
  case "$STATE" in
    none) exit 0;;
    running) emit_context UserPromptSubmit "hlith check is still RUNNING; the pending change is UNVERIFIED. Say so; do not claim success.";;
    interrupted) emit_context UserPromptSubmit "hlith check was interrupted (its worker is gone); this change is UNVERIFIED. A new edit starts a new check; do not claim success.";;
    stale)
      SUM="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("summary",""))' "$INFO")"
      emit_context UserPromptSubmit "$SUM BUT the working tree changed after that check started: the current tree is UNVERIFIED (no check covers it). Do not claim success.";;
    done)
      RC="$(python3 -c 'import json,sys; v=json.loads(sys.argv[1]).get("exit"); print("" if v is None else v)' "$INFO")"
      SUM="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("summary",""))' "$INFO")"
      if [ "$RC" = "4" ]; then
        emit_context UserPromptSubmit "$SUM Host or repository boundary refused this check before verification; nothing in your change was judged. Run 'hlith doctor --probe-target' and resolve the boundary rather than restructuring target code."
      else
        emit_context UserPromptSubmit "$SUM A REFUTED witness is evidence, not a decision: ask the human whether the change was intended. If not intended, restore the behavior and let the next edit trigger a new check."
      fi;;
    invalid)
      ERR="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","malformed or mismatched receipt"))' "$INFO")"
      emit_context UserPromptSubmit "hlith check receipt is invalid or mismatched ($ERR); this change is UNVERIFIED. Do not claim success.";;
    error|*)
      ERR="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","repository state could not be read"))' "$INFO")"
      emit_context UserPromptSubmit "hlith check could not verify repository state ($ERR); this change is UNVERIFIED. Do not claim success.";;
  esac
  ;;
stop)
  PAYLOAD="$(cat)"
  hook_py stop-active "$PAYLOAD" && exit 0   # block at most once per stop
  INFO="$(hook_py inspect "$REPO" "$HOME_DIR")"
  STATE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("state","invalid"))' "$INFO")"
  case "$STATE" in
    none|running) exit 0;;   # pending never blocks and is never success
    interrupted) emit_block "hlith check was interrupted (its worker is gone); this change is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.";;
    stale)
      SUM="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("summary",""))' "$INFO")"
      emit_block "$SUM BUT the working tree changed after that check started: the current tree is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.";;
    done)
      RC="$(python3 -c 'import json,sys; v=json.loads(sys.argv[1]).get("exit"); print("" if v is None else v)' "$INFO")"
      [ "$RC" = "0" ] && exit 0
      SUM="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("summary",""))' "$INFO")"
      if [ "$RC" = "4" ]; then
        emit_block "$SUM Host or repository boundary refused this check before verification. Tell the human the change is unverified and run 'hlith doctor --probe-target' to resolve the boundary. Never claim this change is safe."
      else
        emit_block "$SUM Resolve it (keep the intended contract, or tell the human the change is unverified) before finishing. Never claim this change is safe."
      fi;;
    invalid)
      ERR="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","malformed or mismatched receipt"))' "$INFO")"
      emit_block "hlith check receipt is invalid or mismatched ($ERR); this change is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.";;
    error|*)
      ERR="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("error","repository state could not be read"))' "$INFO")"
      emit_block "hlith check could not verify repository state ($ERR); this change is UNVERIFIED. Tell the human it is unverified before finishing. Never claim this change is safe.";;
  esac
  ;;
status)
  hook_py status "$HOME_DIR"
  ;;
*)
  echo "usage: $0 post|prompt|stop|status|worker [repo]" >&2; exit 2;;
esac
