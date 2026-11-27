# SPDX-License-Identifier: Apache-2.0
"""case (review wave 5, D21-D24): state classes the direct path's _StateWatch did not see. Each effect is
fused into the return of a DIRECT-path target at SHIPPED defaults; none shows in the return value.

Predeclared (before the first run): each of D21-D24 is REFUTED by a deterministic pre != post state difference, and an
EQUIVALENT edit on a module that merely HOLDS the same state (an untouched oversize container, a repo module, an RNG)
is not refuted - the watch must not invent differences (the oversize-container bug reported `changed` for an UNTOUCHED
container on both sides, which also hid real changes behind a 200-char cut)."""
from hlith import differential
from hlith.types import Verdict

BASE = '''import os
import random
from pkg import cfg


class Registry:
    pass


_BIG = ['x' * 70000]


def f(n: int) -> int:
    if n > 10:
        return n + 1
    return n * 2
'''
TEST = "from pkg.m import f\n\n\ndef test_f():\n    assert f(2) == 4\n    assert f(12) == 13\n"


def _run(tmp_path, post):
    for side, body in (("base", BASE), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "cfg.py").write_text("LEVEL = 1\n")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "tests").mkdir()
        (tmp_path / side / "tests" / "test_m.py").write_text(TEST)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), adequacy_gate=True)


def _edit(line):
    return BASE.replace("    return n * 2\n", line)


def test_d21_dunder_class_attribute_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, setattr(Registry, '__hlith_seen__', n))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "__hlith_seen__" in ob.witness, ob


def test_d22_oversize_container_mutation_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, _BIG.append(n))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "_BIG" in ob.witness, ob


def test_d23_other_repository_module_global_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, setattr(cfg, 'LEVEL', 2))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "LEVEL" in ob.witness, ob


def test_d24_random_state_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, random.seed(1234))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "random" in ob.witness, ob


def test_untouched_oversize_container_does_not_create_a_difference(tmp_path):
    ob = _run(tmp_path, _edit("    return 2 * n\n"))
    assert ob.verdict is not Verdict.REFUTED, ob.witness


# ---- wave 6 (review E1-E4): process / stdlib state a call can change for every later one --------------------------------
# Predeclared REFUTED: decimal context precision, the process umask, a signal disposition, an open file descriptor left
# behind. The guard: an equivalent edit on the same module is not refuted.
def test_e1_decimal_context_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, __import__('decimal').getcontext().__setattr__('prec', 7))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "decimal" in ob.witness, ob


def test_e2_umask_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, os.umask(0o077))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "umask" in ob.witness, ob


def test_e3_signal_disposition_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit(
        "    return (n * 2, __import__('signal').signal(__import__('signal').SIGUSR1, lambda *a: None))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "signal" in ob.witness, ob


def test_e5_leaked_file_descriptor_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, _FDS.append(open('/dev/null')))[0]\n").replace(
        "_BIG = [", "_FDS = []\n_BIG = ["))
    assert ob.verdict is Verdict.REFUTED and "file descriptors" in ob.witness, ob


def test_f3_atexit_registration_is_refuted(tmp_path):
    ob = _run(tmp_path, _edit("    return (n * 2, __import__('atexit').register(print, 'bye'))[0]\n"))
    assert ob.verdict is Verdict.REFUTED and "atexit" in ob.witness, ob


def test_evidence_names_what_is_not_watched(tmp_path):
    """The disclosure must list the unwatchable remainder by name (it was claimed for atexit before it was true)."""
    ob = _run(tmp_path, _edit("    return 2 * n\n"))
    u = ob.evidence.unexplored if ob.evidence else ""
    for name in ("atexit", "sockets", "C extensions", "files outside the working directory", "third-party"):
        assert name in u or name.replace("the ", "") in u, (name, u[-700:])


# ---- RNG determinism across the two evaluators (found by test_hollow_primary_unstable_calls_make_no_claim) -----------
# Predeclared: the StateWatch restores the RNG after every call, which makes a random-using target deterministic WITHIN an
# evaluator; if the two evaluators were seeded differently every such target would read as a divergence. Both evaluators
# start from the same RNG state, so an equivalent edit that draws the same numbers is not refuted, and an edit that
# draws a different NUMBER of values is (the state channel sees the consumption).
_RAND_BASE = "import random\n\n\ndef f(x: int) -> float:\n    return x + random.random()\n"


def _run_rand(tmp_path, post):
    for side, body in (("base", _RAND_BASE), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text("import pkg.m as m\n\n\ndef test_reach():\n    m.f\n")
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=80, max_examples=10,
        adequacy_gate=True)


def test_equivalent_edit_of_a_random_using_target_is_not_refuted(tmp_path):
    ob = _run_rand(tmp_path, _RAND_BASE.replace("x + random.random()", "random.random() + x"))
    assert ob.verdict is not Verdict.REFUTED, ob.witness


def test_extra_random_draw_is_refuted(tmp_path):
    ob = _run_rand(tmp_path, _RAND_BASE.replace("    return x + random.random()\n",
                                                 "    random.random()\n    return x + random.random()\n"))
    assert ob.verdict is Verdict.REFUTED, ob


def test_q5_pure_atexit_statement_is_live_in_the_ablation(tmp_path):
    """review Q5: `atexit.register(print, n)` as its OWN statement was 'dead' (the ablation compared return and exception only)
    although the state watch counts atexit callbacks. Removing it changes the state channel, so it is live; the verdict
    must not be a dead-statement UNVERIFIED."""
    base = "import atexit\n\n\ndef f(n: int) -> int:\n    return n * 2\n"
    post = "import atexit\n\n\ndef f(n: int) -> int:\n    atexit.register(print, n)\n    return n * 2\n"
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text("import pkg.m as m\n\n\ndef test_reach():\n    m.f\n")
    (tmp_path / "proposer").mkdir()
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=60, max_examples=10,
        adequacy_gate=True)
    assert ob.verdict is Verdict.REFUTED and "atexit" in ob.witness, (ob.verdict, ob.witness, ob.stop_reason)
