"""Which repository tests depend on loopback networking (unavailable in confinement): their outcomes support neither REFUTED nor HELD, attempts that cannot
be tied to a test of the repository are disclosed, and an unrelated library probe blocks nothing."""

import pytest

from hlith import differential
from hlith.types import Verdict

REASON = "loopback networking unavailable in confinement"
CORE = ("import threading\n\n\nclass Pump:\n    def __init__(self):\n        self.gate = None\n        self.width = 0\n        self.total = 0\n\n"
        "    def push(self, n):\n        with self.gate:\n            %s\n        return self.total\n")
PLAIN = "self.total += n * self.width"
BROKEN = "self.total += n * self.width if n != 2 else 0"
HEAD = "import socket\nimport threading\nimport pkg.m as core\n\n\ndef pump():\n    p = core.Pump()\n    p.gate = threading.Lock()\n    p.width = 3\n    return p\n\n\n"
BIND = "def can_bind():\n    try:\n        socket.socket().bind(('127.0.0.1', 0))\n        return True\n    except OSError:\n        return False\n\n\n"


def run(tmp_path, test_source, names, post=BROKEN, deps=None):
    for side, body in (("base", PLAIN), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(CORE % body)
        (tmp_path / side / "test_m.py").write_text(test_source)
    extra = []
    if deps:
        for rel, text in deps.items():
            (tmp_path / "deps" / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / "deps" / rel).write_text(text)
        extra = [str(tmp_path / "deps")]
    (tmp_path / "prop").mkdir()
    nodes = [{"node_id": f"test_m.py::{n}", "reaches": [f"test_m.{n.split('[')[0].replace('::', '.')}", "pkg.m.Pump.push"]} for n in names]
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Pump.push",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=20,
                                       impacted_test_nodes=nodes, adequacy_gate=True, extra_sys_path=extra)
    ev = getattr(ob, "evidence", None)
    return ob, f"{ob.witness} || {ob.stop_reason} || {getattr(ev, 'explored', '')} || {getattr(ev, 'unexplored', '')}"


def test_a_module_fixture_attempt_covers_every_test_of_the_module(tmp_path):
    source = HEAD + BIND + ("import pytest\n\n\n@pytest.fixture(scope='module')\ndef server():\n    return can_bind()\n\n\n"
                            "def test_a(server):\n    assert pump().push(1) is not None\n\n\ndef test_b(server):\n    assert pump().push(2) == (6 if not server else 6)\n")
    ob, text = run(tmp_path, source, ["test_a", "test_b"])
    assert ob.verdict is Verdict.UNVERIFIED and REASON in text, (ob.verdict, text[:900])


def test_an_import_time_attempt_by_the_test_module_covers_its_tests(tmp_path):
    source = HEAD + BIND + "SERVER = can_bind()\n\n\ndef test_b():\n    assert pump().push(2) == (6 if not SERVER else 6)\n"
    ob, text = run(tmp_path, source, ["test_b"])
    assert ob.verdict is Verdict.UNVERIFIED and REASON in text, (ob.verdict, text[:900])


def test_a_subprocess_server_the_test_connects_to_is_seen_through_the_connect(tmp_path):
    source = HEAD + ("import subprocess\nimport sys\n\n\ndef test_b():\n"
                     "    subprocess.run([sys.executable, '-c', 'import socket; s = socket.socket(); s.bind((\"127.0.0.1\", 0))'], timeout=30)\n"
                     "    c = socket.socket()\n    try:\n        c.connect(('127.0.0.1', 9))\n    except OSError:\n        pass\n    assert pump().push(2) == 6\n")
    ob, text = run(tmp_path, source, ["test_b"])
    assert ob.verdict is Verdict.UNVERIFIED and REASON in text, (ob.verdict, text[:900])


def test_a_library_probe_at_import_blocks_nothing_and_is_disclosed(tmp_path):
    deps = {"probe_lib/__init__.py": "import socket\n\ntry:\n    socket.socket(socket.AF_INET6).bind(('::1', 0))\n    HAS = True\nexcept OSError:\n    HAS = False\n"}
    source = HEAD + "import probe_lib\n\n\ndef test_b():\n    assert pump().push(2) == 6\n"
    ob, text = run(tmp_path, source, ["test_b"], deps=deps)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, text[:900])
    assert "start-up loopback attempt" in text and REASON not in str(ob.stop_reason), text[:900]


def test_class_and_parametrized_node_ids_match_and_other_tests_still_count(tmp_path):
    source = HEAD + BIND + ("import pytest\n\n\nclass TestK:\n    @pytest.mark.parametrize('v', ['a b (c)'])\n    def test_net(self, v):\n        can_bind()\n"
                            "        assert pump().push(2) == 6\n\n\ndef test_plain():\n    assert pump().push(2) == 6\n")
    ob, text = run(tmp_path, source, ["TestK::test_net[a b (c)]", "test_plain"])
    assert ob.verdict is Verdict.REFUTED and "test_m.py::test_plain" in str(ob.witness) and REASON in text, (ob.verdict, text[:900])


def test_only_the_loopback_dependent_failure_is_withheld(tmp_path):
    source = HEAD + BIND + "def test_net():\n    can_bind()\n    assert pump().push(2) == 6\n"
    ob, text = run(tmp_path, source, ["test_net"])
    assert ob.verdict is Verdict.UNVERIFIED and REASON in text, (ob.verdict, text[:900])
