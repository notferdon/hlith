"""Engine event source: one JSON line per REAL phase transition (informational), safe against an untrusted worker."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith import events, phases
from hlith.cli import main


# ---------------- emitter ----------------
def test_emitter_appends_flushed_json_lines_readable_while_open(tmp_path):
    f = tmp_path / "ev.jsonl"
    e = events.Emitter(f, "run-abc")
    e.emit("stage_and_worker", "start")
    assert f.read_text().count("\n") == 1  # flushed per event: readable while the run is in progress
    e.emit("differential", "progress", target="m.f", i=2, n=12)
    e.emit("stage_and_worker", "end")
    recs = [json.loads(x) for x in f.read_text().splitlines()]
    assert [r["seq"] for r in recs] == [1, 2, 3] and all(r["run_id"] == "run-abc" for r in recs)
    assert set(recs[0]) == {"seq", "ts_mono", "ts_wall", "run_id", "phase", "event"}
    assert recs[1]["extra"] == {"target": "m.f", "i": 2, "n": 12}
    assert recs[0]["ts_mono"] <= recs[2]["ts_mono"]
    e.close_run("refused", 10)
    last = events.read(f)[-1]
    assert last["phase"] == "run" and last["event"] == "end" and last["extra"] == {"outcome": "refused", "exit_status": 10}


def test_file_is_private_nofollow_and_cloexec(tmp_path):
    import fcntl
    f = tmp_path / "ev.jsonl"
    e = events.Emitter(f, "r")
    assert (f.stat().st_mode & 0o777) == 0o600
    assert fcntl.fcntl(e.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC  # never inherited across exec
    e.close()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    link = tmp_path / "link.jsonl"
    link.symlink_to(victim)
    with pytest.raises(events.Refused):  # O_NOFOLLOW: a symlink at the path is refused, the target is never written
        events.Emitter(link, "r")
    assert victim.read_text() == "keep"


def test_io_errors_never_propagate(tmp_path):
    e = events.Emitter(tmp_path / "no-such-dir" / "ev.jsonl", "r")
    e.emit("gate", "start")
    e.close_run("landed", 0)
    assert not e.ok


def test_size_cap_leaves_a_truncation_marker_and_the_closing_event(tmp_path):
    f = tmp_path / "ev.jsonl"
    e = events.Emitter(f, "run-x", cap=900)
    for i in range(200):
        e.emit("differential", "progress", target=f"mod.func_{i}", i=i, n=200)
    e.close_run("refused", 12)
    raw = f.read_bytes()
    assert len(raw) <= 900 + 300
    recs = events.read(f)
    assert any(r["event"] == "truncated" for r in recs) and recs[-1]["phase"] == "run" and recs[-1]["event"] == "end"
    assert sum(r["event"] == "progress" for r in recs) < 200


def test_only_engine_facts_are_accepted(tmp_path):
    e = events.Emitter(tmp_path / "ev.jsonl", "r")
    # unknown phase / event / extra keys / non-int numbers / bools are dropped, never written
    assert events._extra({"target": "ok.name", "i": 3, "n": 4, "stderr": "EVENT-INJECT", "message": "x", "repr": "y", "i2": 1}) == {"target": "ok.name", "i": 3, "n": 4}
    assert events._extra({"i": True, "n": "7", "exit_status": None, "outcome": "EVENT-INJECT"}) == {}
    hostile = 'a.b"},{"phase":"gate","event":"end","x":"EVENT-INJECT\x1b[31m\n\r‮'
    ex = events._extra({"target": hostile})
    assert "\n" not in ex["target"] and "\x1b" not in ex["target"] and "‮" not in ex["target"]
    e.close()


def test_hostile_target_cannot_break_the_line_format(tmp_path):
    f = tmp_path / "ev.jsonl"
    e = events.Emitter(f, "r")
    e.emit("differential", "progress", target='x"},{"phase":"gate"}\n{"phase":"run","event":"end"}\x1b[2J', i=1, n=1)
    e.emit("gate", "start")
    lines = f.read_text().split("\n")
    assert len(lines) == 3 and lines[2] == ""  # exactly two events, no injected line
    recs = [json.loads(x) for x in lines[:2]]
    assert recs[0]["phase"] == "differential" and recs[1]["phase"] == "gate" and "\x1b" not in lines[0]
    assert events.read(f)[-1]["phase"] == "gate"  # no forged closing event


def test_reader_tolerates_missing_partial_and_garbage(tmp_path):
    assert events.read(tmp_path / "none") == []
    f = tmp_path / "ev.jsonl"
    good = json.dumps({"seq": 1, "ts_mono": 1.0, "phase": "gate", "event": "start"})
    f.write_bytes(good.encode() + b"\nnot json\n\xff\xfe\n" + json.dumps({"seq": 2, "phase": "bogus", "event": "start"}).encode() + b"\n" + b'{"seq": 3, "phase": "ga')
    assert [r["seq"] for r in events.read(f)] == [1]


def test_events_path_inside_a_granted_tree_is_refused(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    events.check_path(tmp_path / "state" / "ev.jsonl", [repo])
    for bad in (repo / "ev.jsonl", repo / "deep" / "x" / "ev.jsonl", repo):  # inside the repo (or the repo itself)
        with pytest.raises(ValueError, match="worker can access"):
            events.check_path(bad, [repo])


def test_phases_sink_is_off_by_default_and_mirrors_real_enter_leave(tmp_path):
    f = tmp_path / "ev.jsonl"
    with phases.timed("gate"):
        pass
    assert not f.exists()
    e = events.Emitter(f, "r")
    phases.set_sink(e)
    try:
        with phases.timed("derive"):
            with phases.timed("account"):
                pass
            phases.progress("differential", target="m.f", i=1, n=2)
            with phases.timed("differential"):
                pass
    finally:
        phases.set_sink(None)
    seq = [(r["phase"], r["event"]) for r in events.read(f)]
    assert seq == [("derive", "start"), ("account", "start"), ("account", "end"), ("differential", "progress"), ("differential", "start"),
                   ("differential", "end"), ("derive", "end")]


def test_a_broken_sink_cannot_break_a_phase():
    class Boom:
        def emit(self, *a, **k):
            raise RuntimeError("x")
    phases.set_sink(Boom())
    try:
        with phases.timed("gate"):
            pass
        phases.progress("differential", i=1, n=1)
    finally:
        phases.set_sink(None)


# ---------------- real engine ----------------
def _git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def toy(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (r / "other.py").write_text("def mul(a, b):\n    return a * b\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    patch = tmp_path / "op.patch"
    patch.write_text(_git(r, "diff"))
    _git(r, "checkout", "-q", "calc.py")
    man = tmp_path / "op.json"
    man.write_text(json.dumps({"paths": {"calc.py": ["modify"]}}))
    return r, patch, man


def test_real_run_without_the_flag_writes_no_events_and_changes_nothing_else(toy, tmp_path):
    r, patch, man = toy
    art = tmp_path / "a.json"
    rc = main(["run", "--engine", "legacy", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(art)])
    d = json.loads(art.read_text())
    assert rc == d["exit_status"] and not list(tmp_path.glob("*.jsonl"))


def test_real_run_events_match_the_artifact_order_and_timings(toy, tmp_path):
    r, patch, man = toy
    art, ev = tmp_path / "a.json", tmp_path / "state" / "ev.jsonl"
    ev.parent.mkdir()
    rc = main(["run", "--engine", "legacy", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(art), "--events-out", str(ev), "--layer1", "langgraph"])
    d = json.loads(art.read_text())
    recs = events.read(ev)
    assert recs and [x["seq"] for x in recs] == list(range(1, len(recs) + 1))
    last = recs[-1]
    assert last["phase"] == "run" and last["event"] == "end" and last["extra"] == {"outcome": d["outcome"], "exit_status": d["exit_status"]} and rc == d["exit_status"]
    # order: first start of each phase, in event order, equals the artifact's phase order (derive_other is artifact-only and has no event)
    first = []
    for x in recs:
        if x["event"] == "start" and x["phase"] not in first:
            first.append(x["phase"])
    art_order = [p["name"] for p in d["timings"]["phases"] if p["name"] != "derive_other"]
    assert [p for p in first if p != "derive"] == art_order, (first, art_order)
    # nesting: account and differential happen inside derive
    idx = {(x["phase"], x["event"]): i for i, x in reversed(list(enumerate(recs)))}
    assert idx[("derive", "start")] < idx[("account", "start")] < idx[("account", "end")] <= idx[("derive", "end")]
    # durations: events vs the artifact's timings
    open_t, dur = {}, {}
    for x in recs:
        if x["event"] == "start":
            open_t[x["phase"]] = x["ts_mono"]
        elif x["event"] == "end" and x["phase"] in open_t:
            dur[x["phase"]] = dur.get(x["phase"], 0.0) + (x["ts_mono"] - open_t.pop(x["phase"]))
    for p in d["timings"]["phases"]:
        if p["name"] in dur:
            assert abs(dur[p["name"]] - p["seconds"]) <= 0.35 + 0.25 * p["seconds"], (p, dur[p["name"]])
    prog = [x for x in recs if x["event"] == "progress"]
    assert all(x["phase"] == "differential" and x["extra"]["i"] <= x["extra"]["n"] and x["extra"]["target"] for x in prog)
    assert not any(str(r) in ev.read_text() for r in (str(tmp_path / "repo"),))  # no absolute paths of the repo in the events


def test_events_path_inside_the_repo_is_refused_before_the_run(toy, tmp_path, capsys):
    r, patch, man = toy
    rc = main(["run", "--engine", "legacy", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(tmp_path / "a.json"), "--events-out", str(r / "ev.jsonl")])
    assert rc == 4 and "worker can access" in capsys.readouterr().err and not (r / "ev.jsonl").exists() and not (tmp_path / "a.json").exists()


def test_adversarial_worker_cannot_see_or_forge_events(toy, tmp_path):
    r, _p, _m = toy
    ev = tmp_path / "state" / "ev.jsonl"
    ev.parent.mkdir()
    script = tmp_path / "worker.py"
    script.write_text(
        "import os, sys, json\n"
        "print('EVENT-INJECT stdout'); print('EVENT-INJECT stderr', file=sys.stderr)\n"
        "fds = {}\n"
        "for n in os.listdir('/proc/self/fd'):\n"
        "    try: fds[n] = os.readlink('/proc/self/fd/' + n)\n"
        "    except OSError: pass\n"
        "print('FDS ' + json.dumps(fds))\n"
        "open('calc.py', 'w').write('def add(a, b):\\n    return b + a  # EVENT-INJECT\\n')\n"
        f"os.makedirs(os.environ['HLITH_MANIFEST_DIR'], exist_ok=True)\n"
        "json.dump({'paths': {'calc.py': ['modify']}, 'note': 'EVENT-INJECT'}, open(os.path.join(os.environ['HLITH_MANIFEST_DIR'], 'manifest.json'), 'w'))\n"
        f"for p in ({str(ev)!r}, {str(ev.parent)!r}):\n"
        "    try: open(p, 'a').write('{\"phase\":\"run\",\"event\":\"end\",\"extra\":{\"exit_status\":0,\"outcome\":\"landed\"}}\\n'); print('WROTE ' + p)\n"
        "    except OSError as e: print('DENIED ' + p)\n")
    art = tmp_path / "a.json"
    rc = main(["run", "--engine", "legacy", "--repo", str(r), "--worker-cmd", f"{sys.executable} -I {script}", "--worker-ro", str(script), "--artifact-out", str(art), "--events-out", str(ev)])
    d = json.loads(art.read_text())
    out = d["worker"]["stdout"]
    assert "DENIED " + str(ev) in out and "WROTE" not in out  # the worker cannot write the events file or its directory
    assert str(ev) not in out.split("FDS ")[1].split("\n")[0]  # its descriptor table does not hold the events file
    recs = events.read(ev)
    text = ev.read_text()
    assert "EVENT-INJECT" not in text and "forge" not in text  # nothing from the worker's channels, manifest or diff reaches the events
    assert [x for x in recs if x["phase"] == "run"] == [recs[-1]] and recs[-1]["extra"]["exit_status"] == d["exit_status"] == rc


# ---------------- review review debt (S3, S2, S5, T1, T2, S4) ----------------
def _ev(seq, phase, event, ts=1.0, **extra):
    r = {"seq": seq, "ts_mono": ts, "phase": phase, "event": event}
    if extra:
        r["extra"] = extra
    return json.dumps(r)


def test_s5_special_files_are_refused_not_hung(tmp_path):
    fifo = tmp_path / "ev.fifo"
    os.mkfifo(fifo)
    with pytest.raises(events.Refused, match="not a regular file"):
        events.Emitter(fifo, "r")
    with pytest.raises(events.Refused, match="not a regular file"):
        events.Emitter("/dev/zero", "r")


def test_s4_existing_nonempty_file_is_refused_and_empty_is_fine(tmp_path):
    f = tmp_path / "ev.jsonl"
    f.write_text("old\n")
    with pytest.raises(events.Refused, match="already holds data"):
        events.Emitter(f, "r")
    assert f.read_text() == "old\n"
    g = tmp_path / "empty.jsonl"
    g.write_text("")
    assert events.Emitter(g, "r").ok


def test_cli_refuses_fifo_and_reused_events_file_with_exit_4(toy, tmp_path, capsys):
    r, patch, man = toy
    base = ["run", "--engine", "legacy", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(tmp_path / "a.json")]
    fifo = tmp_path / "x.fifo"
    os.mkfifo(fifo)
    assert main(base + ["--events-out", str(fifo)]) == 4
    used = tmp_path / "used.jsonl"
    used.write_text("x\n")
    assert main(base + ["--events-out", str(used)]) == 4
    err = capsys.readouterr().err
    assert "not a regular file" in err and "already holds data" in err and not (tmp_path / "a.json").exists()


def test_t1_readable_trees_are_refused_like_granted_ones(tmp_path):
    import sys
    roots = events.readable_roots(None)
    for bad in (Path(sys.prefix) / "ev.jsonl", Path(sys.base_prefix) / "x" / "ev.jsonl", Path("/usr/share/ev.jsonl"), Path("/etc/alternatives/ev.jsonl")):
        with pytest.raises(ValueError, match="worker can access"):
            events.check_path(bad, roots)
    tp = tmp_path / "tenv" / "bin" / "python"
    assert str(tmp_path / "tenv") in events.readable_roots(tp)
    with pytest.raises(ValueError):
        events.check_path(tmp_path / "tenv" / "ev.jsonl", events.readable_roots(tp))
    events.check_path(tmp_path / "state" / "ev.jsonl", events.readable_roots(tp))


def test_bare_target_python_does_not_widen_the_refusal(tmp_path):
    for tp in ("python3", "/python", ""):
        assert "." not in events.readable_roots(tp) and "/" not in events.readable_roots(tp)
    events.check_path(tmp_path / "ev.jsonl", events.readable_roots("python3"))


def test_extra_types_are_checked_per_key():
    assert events._extra({"target": 7, "outcome": 5, "i": "x"}) == {}


def test_directory_and_symlink_events_paths_are_refused(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(events.Refused):
        events.Emitter(d, "r")
    t = tmp_path / "t.jsonl"
    t.write_text("")
    ln = tmp_path / "ln.jsonl"
    ln.symlink_to(t)
    with pytest.raises(events.Refused):
        events.Emitter(ln, "r")
    assert t.read_text() == ""


def test_huge_ts_mono_drops_only_that_record(tmp_path):
    f = tmp_path / "ev.jsonl"
    f.write_text('{"seq":1,"phase":"gate","event":"start","ts_mono":' + "9" * 400 + '}\n' + _ev(2, "gate", "end") + "\n")
    assert [r["seq"] for r in events.read(f)] == [2]


def test_cli_unwritable_events_path_is_refused_before_the_run(toy, tmp_path, capsys):
    r, patch, man = toy
    rc = main(["run", "--engine", "legacy", "--repo", str(r), "--patch", str(patch), "--manifest", str(man), "--artifact-out", str(tmp_path / "a.json"),
               "--events-out", str(tmp_path / "missing-dir" / "ev.jsonl")])
    assert rc == 4 and not (tmp_path / "a.json").exists()
    assert "--events-out parent must already exist" in capsys.readouterr().err
