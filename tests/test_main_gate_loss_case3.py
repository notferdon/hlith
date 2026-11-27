"""Main-gate timeout controls for review's bounded falsifier."""

from hlith import differential
from hlith.types import Verdict


def _run(tmp_path, base_body, post_body, **kwargs):
    for side, body in (("base", base_body), ("post", post_body)):
        module = tmp_path / side / "pkg" / "m.py"
        module.parent.mkdir(parents=True)
        (module.parent / "__init__.py").write_text("")
        module.write_text(body)
        (tmp_path / side / "test_reach.py").write_text(
            "import pkg.m as m\n\ndef test_reach():\n    if hasattr(m, 'f'):\n        m.f\n"
        )
    proposer = tmp_path / "proposer"
    proposer.mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(proposer)], scratch=str(tmp_path / "scratch"),
        max_seeds=kwargs.pop("max_seeds", 1), max_examples=1,
        call_timeout=0.1, timeout=30.0, **kwargs,
    )


def test_identical_nonreturning_targets_are_unverified(tmp_path):
    spinner = "def f():\n    while True:\n        pass\n"
    ob = _run(tmp_path, spinner, spinner)

    assert ob.verdict is Verdict.UNVERIFIED, ob
    detail = " ".join((ob.stop_reason or "", ob.evidence.explored if ob.evidence else "",
                       ob.evidence.unexplored if ob.evidence else ""))
    assert "timeout" in detail.lower(), (ob.verdict, ob.stop_reason, ob.evidence)


def test_timeout_on_only_one_side_is_unverified_not_a_refutation(tmp_path):
    base = "def f(x: int):\n    return x\n"
    post = "def f(x: int):\n    if x == 0:\n        while True:\n            pass\n    return x\n"
    ob = _run(tmp_path, base, post, seeds=[([0], {})])

    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert ob.witness is None, ob.witness
    detail = " ".join((ob.stop_reason or "", ob.evidence.explored if ob.evidence else "",
                       ob.evidence.unexplored if ob.evidence else ""))
    assert "timeout" in detail.lower(), (ob.verdict, ob.stop_reason, ob.evidence)


def test_sigkill_on_only_one_side_is_unverified_not_a_refutation(tmp_path):
    base = "def f():\n    return 1\n"
    post = "import os, signal\ndef f():\n    os.kill(os.getpid(), signal.SIGKILL)\n"
    ob = _run(tmp_path, base, post, seeds=[([], {})])

    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "crash" in (ob.stop_reason or "").lower(), (ob.verdict, ob.stop_reason, ob.evidence)


def test_memory_limit_on_only_one_side_is_unverified(tmp_path):
    base = "def f():\n    return 1\n"
    post = "def f():\n    return bytearray(3 * 1024 * 1024 * 1024)\n"
    ob = _run(tmp_path, base, post, seeds=[([], {})])

    assert ob.verdict is Verdict.UNVERIFIED, ob
    assert "resource limit" in (ob.stop_reason or "").lower(), (ob.verdict, ob.stop_reason, ob.evidence)


def test_replayable_divergence_wins_over_unrelated_timeout(tmp_path):
    base = (
        "def f(x: int):\n"
        "    if x == 0:\n        return 0\n"
        "    if x == 3:\n        while True:\n            pass\n"
        "    return x\n"
    )
    post = (
        "def f(x: int):\n"
        "    if x == 0:\n        return 1\n"
        "    if x == 3:\n        while True:\n            pass\n"
        "    return x\n"
    )
    # Record the unrelated runtime loss first, then the deterministic counterexample.
    ob = _run(tmp_path, base, post, max_seeds=2, seeds=[([3], {}), ([0], {})])

    assert ob.verdict is Verdict.REFUTED, ob
    assert "x=0" in (ob.witness or "") and "pre -> return 0" in ob.witness and "post -> return 1" in ob.witness
    assert ob.evidence is not None
    assert "timeout" in ob.evidence.unexplored.lower() and "x=3" in ob.evidence.unexplored, ob.evidence
