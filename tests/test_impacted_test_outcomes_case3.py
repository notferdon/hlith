"""Fail-closed regressions for mapped pytest outcome transitions in the O2 slice."""

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict

ORIGINAL_SUBPROCESS_RUN = differential.subprocess.run


BASE_MODULE = '''
BASE_MODE = False


def _token():
    return "-".join(["k", str(6 * 7), "z"])


class Registry:
    def __init__(self, token):
        if token != _token():
            raise ValueError("bad token")
        self.base = 40


def _helper(reg, n):
    if n > 10:
        return reg.base + 1
    return reg.base + n


def build(n):
    return _helper(Registry(_token()), n)
'''

BASE_TEST = '''
import pytest
import pkg.m as core


def test_build():
    assert core.build(2) == 42
    if core.BASE_MODE:
        assert False, "post fails after the target call"
    pytest.skip("base skips after the target call")
'''

NODES = [{"node_id": "tests/test_m.py::test_build", "file": "tests/test_m.py", "line": 5,
          "reaches": ["pkg.m.build", "pkg.m._helper"], "exists_in_base": True, "provenance": "test"}]


@pytest.mark.parametrize(("before", "after", "expected"), [
    ("passed", "failed", "witness"),
    ("passed", "skipped", "unverified"),
    ("skipped", "failed", "unverified"),
    ("failed", "passed", "unverified"),
    ("failed", "skipped", "unverified"),
    ("skipped", "passed", "unverified"),
    ("failed", "failed", "same"),
    ("skipped", "skipped", "same"),
    ("passed", None, "unverified"),
])
def test_mapped_outcome_policy_is_fail_closed(before, after, expected):
    assert differential._mapped_outcome_disposition(before, after) == expected


def _outcome_world(tmp_path, *, post_test=BASE_TEST, post_module=None):
    post_module = post_module or BASE_MODULE.replace("BASE_MODE = False", "BASE_MODE = True").replace(
        "return reg.base + n", "return n + reg.base")
    for side, module, test in (("base", BASE_MODULE, BASE_TEST), ("post", post_module, post_test)):
        root = tmp_path / side
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")
        (root / "pkg" / "m.py").write_text(module)
        (root / "tests").mkdir()
        (root / "tests" / "test_m.py").write_text(test)
    proposer = tmp_path / "proposer"
    proposer.mkdir()
    return dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m",
                function="_helper", proposer_paths=[str(proposer)], scratch=str(tmp_path / "scratch"),
                max_seeds=300, max_examples=20, adequacy_gate=True, impacted_test_nodes=NODES)


def test_skip_to_fail_after_same_target_call_is_unverified(monkeypatch, tmp_path):
    """A skip/fail transition after an equal real call cannot be entrypoint agreement."""
    monkeypatch.setattr(differential, "_ENTRY_HELD", True)
    result = differential.run_differential(**_outcome_world(tmp_path))

    assert result.verdict is Verdict.UNVERIFIED, result
    assert "skipped -> failed" in str(result.stop_reason), result.stop_reason
    assert "entrypoint" not in result.evidence.explored.lower(), result.evidence.explored


def test_fresh_post_failure_remains_a_refutation(tmp_path):
    """An added post-only failing test retains the existing conservative REFUTED behavior."""
    test = BASE_TEST.replace(
        "    pytest.skip(\"base skips after the target call\")\n", "    if False:\n        pytest.skip(\"unreachable\")\n")
    # The test node is absent from the base side, so the failure has no mapped base outcome.
    world = _outcome_world(tmp_path, post_test=test)
    (tmp_path / "base" / "tests" / "test_m.py").unlink()
    result = differential.run_differential(**world)

    assert result.verdict is Verdict.REFUTED, result
    assert "test_build" in str(result.witness), result.witness


def test_real_pytest_duplicate_junit_identity_is_marked_ambiguous(monkeypatch, tmp_path):
    """A collection hook can emit same-key rows with a hidden per-execution pass-to-fail change."""
    nodeid = "tests/test_dup.py::test_x"
    roots = {}
    for side, changed in (("base", False), ("post", True)):
        root = tmp_path / side
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")
        changed_expr = "n + 1 if n == 2 else n" if changed else "n"
        (root / "pkg" / "m.py").write_text(f"def value(n):\n    return {changed_expr}\n")
        (root / "tests").mkdir()
        (root / "pytest.ini").write_text("[pytest]\njunit_family = xunit1\n")
        (root / "conftest.py").write_text(
            "def pytest_collection_modifyitems(session, config, items):\n"
            "    if not getattr(config, '_duplicate_items_added', False):\n"
            "        config._duplicate_items_added = True\n"
            "        items.extend(list(items))\n"
        )
        (root / "tests" / "test_dup.py").write_text(
            "import pkg.m as core\n\n_count = 0\n\ndef test_x():\n"
            "    global _count\n    _count += 1\n    value = core.value(_count)\n"
            "    if _count == 1:\n        assert value == 0\n"
            "    else:\n        assert value == 2\n"
        )
        roots[side] = root

    collected = {}
    (tmp_path / "scratch").mkdir()
    spec = {"base": str(roots["base"]), "scratch": str(tmp_path / "scratch"), "import_root": "",
            "extra_sys_path": [], "dist_info": {}, "eval_spec": {"rw": []},
            "python": sys.executable, "target_python": sys.executable}
    for side in ("base", "post"):
        root = roots[side]
        ids = [str(root / nodeid)]

        def run_real_pytest(argv, **kwargs):
            junit = Path(kwargs["cwd"]) / "junit.xml"
            return ORIGINAL_SUBPROCESS_RUN(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                 "-o", "junit_family=xunit1", "--rootdir", str(root), "--junitxml", str(junit), *ids],
                cwd=root, capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"})

        monkeypatch.setattr(differential.subprocess, "run", run_real_pytest)
        outcomes, note = differential._run_tests(spec, str(root), ids, side)
        assert outcomes is not None, note
        junit = tmp_path / "scratch" / f"tests-{side}" / "junit.xml"
        rows = list(ET.parse(junit).getroot().iter("testcase"))
        assert len(rows) == 2, [(row.attrib) for row in rows]
        assert {(row.get("classname"), row.get("name"), row.get("file")) for row in rows} == {
            ("tests.test_dup", "test_x", "tests/test_dup.py")}
        statuses = ["failed" if {child.tag for child in row} & {"failure", "error"}
                    else "skipped" if any(child.tag == "skipped" for child in row) else "passed" for row in rows]
        collected[side] = (outcomes, statuses)

    base_outcomes, base_rows = collected["base"]
    post_outcomes, post_rows = collected["post"]
    assert base_rows == ["failed", "passed"]
    assert post_rows == ["failed", "failed"]
    assert base_outcomes.get("tests/test_dup.py::test_x") == "failed"
    assert post_outcomes.get("tests/test_dup.py::test_x") == "failed"
    assert any(key.startswith("ambiguous impacted test: ") for key in base_outcomes)


@pytest.mark.parametrize(("post_mode", "expected", "disposition"), [
    ("memory", "resource", "unverified"),
    ("assert", "failed", "witness"),
])
def test_real_pytest_resource_failure_is_not_a_replayable_regression(
    monkeypatch, tmp_path, post_mode, expected, disposition
):
    pytest.importorskip("resource")
    roots = {}
    for side, mode in (("base", "pass"), ("post", post_mode)):
        root = tmp_path / side
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")
        (root / "pkg" / "m.py").write_text(f"MODE = {mode!r}\ndef value():\n    return 1\n")
        (root / "tests").mkdir()
        (root / "tests" / "test_m.py").write_text(
            "import pkg.m as core\n\n"
            "def test_value():\n"
            "    assert core.value() == 1\n"
            "    if core.MODE == 'memory':\n"
            "        import resource\n"
            "        limit = 1024 ** 3\n"
            "        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))\n"
            "        bytearray(2 * 1024 ** 3)\n"
            "    elif core.MODE == 'assert':\n"
            "        assert False, 'ordinary post-side regression'\n"
        )
        roots[side] = root

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    spec = {"base": str(roots["base"]), "scratch": str(scratch), "import_root": "",
            "extra_sys_path": [], "dist_info": {}, "eval_spec": {"rw": []},
            "python": sys.executable, "target_python": sys.executable}
    statuses = {}
    for side in ("base", "post"):
        root = roots[side]
        ids = [str(root / "tests" / "test_m.py") + "::test_value"]

        def run_real_pytest(argv, **kwargs):
            junit = Path(kwargs["cwd"]) / "junit.xml"
            return ORIGINAL_SUBPROCESS_RUN(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                 "--rootdir", str(root), "--junitxml", str(junit), *ids],
                cwd=root, capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"},
            )

        monkeypatch.setattr(differential.subprocess, "run", run_real_pytest)
        outcomes, note = differential._run_tests(spec, str(root), ids, side)
        assert outcomes is not None, note
        statuses[side] = outcomes

    base_key, base_status = next(iter(statuses["base"].items()))
    post_pairs = [(key, value) for key, value in statuses["post"].items()
                  if not key.startswith("ambiguous impacted test: ")]
    assert len(post_pairs) == 1, statuses
    post_key, post_status = post_pairs[0]
    assert post_key == base_key
    assert (base_status, post_status) == ("passed", expected)
    assert differential._mapped_outcome_disposition(base_status, post_status) == disposition


@pytest.mark.parametrize("runner", ("plain", "recording"))
def test_sigkill_of_impacted_test_runner_is_resource_unexplored(monkeypatch, tmp_path, runner):
    root = tmp_path / "repo"
    root.mkdir()
    spec = {"base": str(root), "scratch": str(tmp_path / "scratch"), "import_root": "",
            "extra_sys_path": [], "dist_info": {}, "eval_spec": {"rw": []},
            "python": sys.executable, "target_python": sys.executable}

    def killed(argv, **kwargs):
        return subprocess.CompletedProcess(argv, -9, stdout="", stderr="")

    monkeypatch.setattr(differential.subprocess, "run", killed)
    (tmp_path / "scratch").mkdir()
    if runner == "plain":
        outcomes, note = differential._run_tests(spec, str(root), [], "sigkill")
        assert outcomes is None
        assert "resource limit" in note and "unexplored" in note
    else:
        result = differential._entry_run(spec, str(root), [], "sigkill", "pkg.m", "value")
        assert result.get("resource_limited") is True
        assert "resource limit" in result.get("err", "")

