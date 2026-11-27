"""Loopback dependencies that cannot be tied to one test (session fixture shared across modules, an import-time server thread running library code, a child
process): the dependent outcome supports neither REFUTED nor HELD, and the reason names loopback networking."""

import pytest

from hlith import differential
from hlith.types import Verdict

REASON = "loopback networking unavailable in confinement"
CORE = ("import threading\n\n\nclass Pump:\n    def __init__(self):\n        self.gate = None\n        self.width = 0\n        self.total = 0\n\n"
        "    def push(self, n):\n        with self.gate:\n            %s\n        return self.total\n")
PLAIN = "self.total += n * self.width"
BROKEN = "self.total += n * self.width if n != 2 else 0"
HEAD = "import socket\nimport threading\nimport pkg.m as core\n\n\ndef pump():\n    p = core.Pump()\n    p.gate = threading.Lock()\n    p.width = 3\n    return p\n\n\n"


def run(tmp_path, files, nodes, deps=None):
    for side, body in (("base", PLAIN), ("post", BROKEN)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(CORE % body)
        for name, text in files.items():
            (tmp_path / side / name).write_text(text)
    extra = []
    for rel, text in (deps or {}).items():
        (tmp_path / "deps" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "deps" / rel).write_text(text)
        extra = [str(tmp_path / "deps")]
    (tmp_path / "prop").mkdir()
    impacted = [{"node_id": f"{f}::{n}", "reaches": [f"{f[:-3]}.{n}", "pkg.m.Pump.push"]} for f, n in nodes]
    ob = differential.run_differential(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Pump.push",
                                       proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=20,
                                       impacted_test_nodes=impacted, adequacy_gate=True, extra_sys_path=extra)
    ev = getattr(ob, "evidence", None)
    return ob, f"{ob.witness} || {ob.stop_reason} || {getattr(ev, 'explored', '')} || {getattr(ev, 'unexplored', '')}"


def withheld(ob, text):
    assert ob.verdict is Verdict.UNVERIFIED and REASON in text, (ob.verdict, text[:900])


def test_a_session_fixture_attempt_covers_a_second_module(tmp_path):
    conftest = ("import socket\nimport pytest\n\n\n@pytest.fixture(scope='session')\ndef server():\n    try:\n"
                "        socket.socket().bind(('127.0.0.1', 0))\n        return True\n    except OSError:\n        return False\n")
    first = HEAD + "def test_a(server):\n    assert pump().push(1) is not None\n"
    second = HEAD + "def test_b(server):\n    assert pump().push(2) == 6\n"
    ob, text = run(tmp_path, {"conftest.py": conftest, "test_a.py": first, "test_m.py": second}, [("test_a.py", "test_a"), ("test_m.py", "test_b")])
    withheld(ob, text)


def test_an_import_time_server_thread_running_library_code_covers_the_tests(tmp_path):
    deps = {"srv_lib/__init__.py": ("import socket\n\nSTATE = []\n\n\ndef serve():\n    try:\n        socket.socket().bind(('127.0.0.1', 0))\n"
                                    "        STATE.append(True)\n    except OSError:\n        STATE.append(False)\n")}
    source = HEAD + ("import srv_lib\n\nT = threading.Thread(target=srv_lib.serve)\nT.start()\nT.join()\n\n\n"
                     "def test_b():\n    assert pump().push(2) == (6 if srv_lib.STATE else 0)\n")
    ob, text = run(tmp_path, {"test_m.py": source}, [("test_m.py", "test_b")], deps=deps)
    withheld(ob, text)


@pytest.mark.parametrize("how", ["subprocess", "fork"])
def test_a_child_process_that_reports_by_exit_status_withholds_its_test(tmp_path, how):
    spawn = ("    code = subprocess.run([sys.executable, '-c', 'import socket; socket.socket().bind((\"127.0.0.1\", 0))'], timeout=30).returncode\n"
             if how == "subprocess" else
             "    pid = os.fork()\n    if pid == 0:\n        try:\n            socket.socket().connect(('127.0.0.1', 9))\n        finally:\n"
             "            os._exit(1)\n    code = os.waitpid(pid, 0)[1]\n")
    source = HEAD + "import os\nimport subprocess\nimport sys\n\n\ndef test_b():\n" + spawn + "    assert pump().push(2) == (6 if code else 6)\n"
    ob, text = run(tmp_path, {"test_m.py": source}, [("test_m.py", "test_b")])
    withheld(ob, text)


def test_control_the_same_change_without_the_session_server_cites_the_second_module_test(tmp_path):
    first = HEAD + "def test_a():\n    assert pump().push(1) is not None\n"
    second = HEAD + "def test_b():\n    assert pump().push(2) == 6\n"
    ob, text = run(tmp_path, {"test_a.py": first, "test_m.py": second}, [("test_a.py", "test_a"), ("test_m.py", "test_b")])
    assert ob.verdict is Verdict.REFUTED and "test_m.py::test_b" in str(ob.witness), (ob.verdict, text[:900])
