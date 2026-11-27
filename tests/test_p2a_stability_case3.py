"""False REFUTED from repository-test observation (P2a): a divergence must be STABLE across reruns of both sides, auditable, and not an artefact of a sandbox
without loopback name resolution. The observation function is driven with scripted runs, so each falsifier is deterministic."""

import json
import sys

import pytest

from hlith import differential as D
from hlith import sandbox

NODE = "tests/test_m.py::test_f"


def drive(monkeypatch, tmp_path, pre, post):
    """Run `_observe_through_tests` with scripted per-run outcomes; `pre` / `post` are the `out` strings of successive runs of that side (the last repeats)."""
    script, seen = {"pre": list(pre), "post": list(post)}, []

    def fake(spec, root, ids, tag, module, qual):
        side = "pre" if tag.startswith("pre") else "post"
        seen.append(tag)
        out = script[side].pop(0) if len(script[side]) > 1 else script[side][0]
        return {"calls": {(NODE, 0): {"args": "(1,)", "out": out}}, "outcomes": {NODE: "passed"}}, ""

    monkeypatch.setattr(D, "_run_tests_recording", fake)
    monkeypatch.setattr(D, "_changed_test_side", lambda base, post_: (set(), False))
    stats: dict = {}
    witness, note = D._observe_through_tests({"scratch": str(tmp_path)}, "/base", "/post", [NODE], [NODE], "m", "f", stats)
    return witness, note, stats, seen


def test_pure_rename_with_a_racy_channel_is_not_refuted(monkeypatch, tmp_path):
    # both versions behave alike but a side channel is flaky: the first two runs of each side happen to agree among themselves and differ across sides
    witness, note, stats, _ = drive(monkeypatch, tmp_path, ["ret 1 | state=t0", "ret 1 | state=t0", "ret 1 | state=t1", "ret 1 | state=t0"],
                                    ["ret 1 | state=t1", "ret 1 | state=t1", "ret 1 | state=t0", "ret 1 | state=t1"])
    assert witness is None, witness
    assert stats.get("unstable_divergence") and "unstable" in note


def test_a_flaky_real_regression_is_unverified_unstable_not_held(monkeypatch, tmp_path):
    witness, note, stats, _ = drive(monkeypatch, tmp_path, ["ret 1"], ["ret 2", "ret 2", "ret 2", "ret 1", "ret 2"])
    assert witness is None, witness
    assert stats.get("unstable_divergence") and "unstable" in note


def test_flakiness_on_the_base_side_also_blocks(monkeypatch, tmp_path):
    witness, _, stats, _ = drive(monkeypatch, tmp_path, ["ret 1", "ret 1", "ret 9", "ret 1"], ["ret 2"])
    assert witness is None, witness
    assert stats.get("unstable_divergence")


def test_a_deterministic_regression_is_refuted_with_the_differing_field(monkeypatch, tmp_path):
    long = "raise E | m=" + "x" * 300
    witness, _, stats, seen = drive(monkeypatch, tmp_path, [long + " | state=fds+0"], [long + " | state=fds+1"])
    assert witness and "state=fds+0" in witness and "state=fds+1" in witness, witness
    assert not stats.get("unstable_divergence")
    assert sum(t.startswith("pre") for t in seen) >= 5 and sum(t.startswith("post") for t in seen) >= 5, seen
    saved = json.loads((tmp_path / "p2a-divergence.json").read_text())
    assert saved["pre"] == long + " | state=fds+0" and saved["post"] == long + " | state=fds+1"
    assert saved["differing_fields"] == [{"field": 2, "pre": "state=fds+0", "post": "state=fds+1"}]


def test_a_difference_past_the_displayed_prefix_is_shown(monkeypatch, tmp_path):
    witness, *_ = drive(monkeypatch, tmp_path, ["raise E | m=" + "a" * 260 + "RESOLVED-ONE"], ["raise E | m=" + "a" * 260 + "RESOLVED-TWO"])
    assert witness and "RESOLVED-ONE" in witness and "RESOLVED-TWO" in witness, witness


def test_agreement_needs_no_confirmation_runs(monkeypatch, tmp_path):
    witness, _, stats, seen = drive(monkeypatch, tmp_path, ["ret 1"], ["ret 1"])
    assert witness is None and not stats.get("unstable_divergence") and len(seen) == 4, seen


PROBE = """
import errno, json, socket, struct, fcntl
r = {}
try:
    r["localhost"] = sorted({a[4][0] for a in socket.getaddrinfo("localhost", 80, type=socket.SOCK_STREAM)})
except OSError as e:
    r["localhost"] = "error %s" % e
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH", b"lo", 0))[:18])[1]
r["lo_up"] = bool(flags & 1)
try:
    s.sendto(b"x", ("192.0.2.1", 9))
    r["outside"] = "sent"
except OSError as e:
    r["outside"] = errno.errorcode.get(e.errno, str(e.errno))
try:
    s.sendto(b"x", ("127.0.0.1", 9))
    r["udp_loopback"] = "sent"
except OSError as e:
    r["udp_loopback"] = errno.errorcode.get(e.errno, str(e.errno))
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    t.connect(("127.0.0.1", 9))
    r["tcp_connect"] = "connected"
except OSError as e:
    r["tcp_connect"] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(r))
"""


def test_the_sandbox_resolves_localhost_while_loopback_stays_down_and_nothing_can_be_sent(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text(PROBE)
    cp = sandbox.run_confined([sys.executable, "-I", str(probe)], sandbox.Profile(rw=(str(tmp_path),), net=False))
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    assert "127.0.0.1" in out["localhost"], out
    assert out["lo_up"] is False, out  # up would let confined processes exchange datagrams (finding 23)
    assert out["udp_loopback"] in ("ENETUNREACH", "EACCES", "EPERM"), out
    assert out["outside"] in ("ENETUNREACH", "EACCES", "EPERM"), out
    assert out["tcp_connect"] in ("EACCES", "EPERM"), out  # TCP stays denied by Landlock; the confinement self-test relies on it


@pytest.mark.parametrize("grants,allowed", [({}, True), ({"ro": ["/etc/ld.so.cache"]}, True), ({"ro": ["/etc"]}, False), ({"rw": ["/etc"]}, False),
                                            ({"ro_bind": ["/"]}, False), ({"rw": ["/etc/hosts"]}, False), ({"net": True}, False)])
def test_the_hosts_file_is_never_written_where_a_grant_could_carry_it_to_the_host(tmp_path, grants, allowed):
    from hlith.hostio import confine_exec

    assert confine_exec._may_synthesize_hosts(grants, str(tmp_path)) is allowed
