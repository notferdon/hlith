# SPDX-License-Identifier: Apache-2.0
"""derive: guard identity (F-C1), removed entry guards, and the feedback hooks on constant readers."""
import subprocess

from hlith.derive import make_derive
from hlith.runtime import DeltaEffect
from hlith.types import ProposedEffect, Verdict

DELTA = {"id": "d1", "symbol": "m.f", "kind": "exception", "claim": "negative x is rejected",
         "input_domain": "x < 0", "pre": "returns x", "post": "raises ValueError",
         "predicate": {"type": "expr", "param": "x", "expr": "x < 0"},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}


def _repo(tmp_path, old, new):
    repo = tmp_path / "r"
    repo.mkdir(parents=True)
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text(old)
    (repo / "test_m.py").write_text("from m import f\n\n\ndef test_f():\n    assert f(3) == 3\n")  # non-empty test slice
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    (repo / "m.py").write_text(new)
    diff = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True, text=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "m.py"], check=True)
    prop = tmp_path / "p"
    prop.mkdir(parents=True)
    (prop / "x").write_text("x")
    return repo, diff, prop


def _derive(tmp_path, old, new, deltas=(), feedback=None):
    repo, diff, prop = _repo(tmp_path, old, new)
    eff = DeltaEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",), deltas=tuple(deltas)) if deltas else\
        ProposedEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",))
    return make_derive(proposer_paths=[str(prop)], feedback=feedback)(repo, eff)


BASE = "BLOCK = {7, 9}\n\n\ndef f(x: int):\n    return x\n"
TWO_GUARDS = ("BLOCK = {7, 9}\n\n\ndef f(x: int):\n    if x < 0:\n        raise ValueError('neg')\n"
              "    if x in BLOCK:\n        raise ValueError('blocked')\n    return x\n")


ONE_GUARD = "BLOCK = {7, 9}\n\n\ndef f(x: int):\n    if x < 0:\n        raise ValueError('neg')\n    return x\n"


def test_a_single_described_guard_is_not_over_refused(tmp_path):
    """The identity rule must not over-refuse the real use: one guard, one delta that describes exactly it."""
    s = _derive(tmp_path, BASE, ONE_GUARD, deltas=[DELTA])
    bad = [(o.obligation_id, o.verdict.name) for o in s.obligations
           if o.verdict is Verdict.NOT_DERIVED or o.obligation_id.startswith("guard-removed")]
    assert not bad, bad


def test_one_delta_never_covers_a_second_guard_of_the_same_exception_type(tmp_path):
    s = _derive(tmp_path, BASE, TWO_GUARDS, deltas=[DELTA])
    blocked = [o for o in s.obligations if o.obligation_id.startswith("unresolved-") and "x in BLOCK" in (o.stop_reason or "")]
    assert blocked and all(o.verdict is Verdict.NOT_DERIVED for o in blocked), [(o.obligation_id, o.verdict.name) for o in s.obligations]
    assert not any(o.obligation_id.startswith("guard-covered") and o.verdict is Verdict.HELD and "BLOCK" in (o.evidence.explored if o.evidence else "")
                   for o in s.obligations)


def _blockers(s):
    """Obligations that stop a removed entry guard from landing: review's unresolved-N (pre-side guard evidence) or mine."""
    return [o for o in s.obligations
            if o.verdict is Verdict.NOT_DERIVED and (o.obligation_id.startswith("unresolved-") or o.obligation_id.startswith("guard-removed:"))]


def _no_pre_guard_evidence(monkeypatch):
    """Simulate an emitter that records NO pre-side entry-guard evidence: my guard-removed path must then be the blocker."""
    import dataclasses

    # SEAM CHANGE (A5): the account is built once by effect.api.EffectService.build -> engine._build_account; the emitter this
    # simulates is that engine. Same stripping, same assertion downstream.
    from hlith.effect import engine

    real = engine._build_account

    def stripped(*a, **k):
        acct = real(*a, **k)
        keep = tuple(c for c in acct.unresolved_constructs
                     if not (getattr(c, "side", "post") == "pre" and c.kind == "unsupported_entry_guard"))
        try:
            return dataclasses.replace(acct, unresolved_constructs=keep)
        except TypeError:
            acct.unresolved_constructs = keep
            return acct

    monkeypatch.setattr(engine, "_build_account", stripped)


def test_removed_entry_guard_blocks(tmp_path):
    # review's emitter now keeps the pre-side guard evidence (an `unresolved-N` obligation naming the guard), and
    # derive correctly drops its own duplicate: the block is by EITHER id, never HELD.
    s = _derive(tmp_path, TWO_GUARDS, BASE)
    b = _blockers(s)
    assert b, [(o.obligation_id, o.verdict) for o in s.obligations]
    text = " ".join((o.stop_reason or "") for o in b)
    assert "x in BLOCK" in text and "x < 0" in text, text
    assert not all(o.verdict is Verdict.HELD for o in s.obligations)


def test_removed_entry_guard_blocks_by_guard_removed_when_the_account_has_no_pre_evidence(tmp_path, monkeypatch):
    _no_pre_guard_evidence(monkeypatch)
    s = _derive(tmp_path, TWO_GUARDS, BASE)
    rm = [o for o in s.obligations if o.obligation_id.startswith("guard-removed:m.f")]
    assert rm and all(o.verdict is Verdict.NOT_DERIVED for o in rm), [(o.obligation_id, o.verdict) for o in s.obligations]
    assert any("x in BLOCK" in o.stop_reason for o in rm) and any("x < 0" in o.stop_reason for o in rm)
    assert not all(o.verdict is Verdict.HELD for o in s.obligations)


def test_unchanged_guards_and_added_guards_do_not_report_removal(tmp_path):
    s = _derive(tmp_path, BASE, TWO_GUARDS, deltas=[DELTA])
    assert not [o for o in s.obligations if o.obligation_id.startswith("guard-removed")]
    unchanged = TWO_GUARDS.replace("return x\n", "return x + 0\n")
    s2 = _derive(tmp_path / "b", TWO_GUARDS, unchanged)
    assert not [o for o in s2.obligations if o.obligation_id.startswith("guard-removed")]


class _Fbk:
    def __init__(self):
        self.calls = []

    def not_derived(self):
        return []

    def constraints(self, symbol):
        self.calls.append(("constraints", symbol))
        return None

    def note_witness(self, symbol, witness):
        self.calls.append(("note_witness", symbol))

    def pinned_obligation(self, base, post, symbol):
        self.calls.append(("pinned_obligation", symbol))
        return None


def test_constant_readers_get_the_same_feedback_hooks_as_modified_callables(tmp_path):
    old = "LIMIT = 10\n\n\ndef ok(n):\n    return n < LIMIT\n"
    new = "LIMIT = 20\n\n\ndef ok(n):\n    return n < LIMIT\n"
    fb = _Fbk()
    _derive(tmp_path, old, new, feedback=lambda repo, ad: fb)
    syms = {(c, s) for c, s in fb.calls}
    assert ("constraints", "m.ok") in syms and ("note_witness", "m.ok") in syms and ("pinned_obligation", "m.ok") in syms, fb.calls


TWO_PLAIN = ("def f(x: int, y: int):\n    if x < 0:\n        raise ValueError('bad')\n    if y < 0:\n"
             "        raise ValueError('bad')\n    return x + y\n")


def test_neutral_guard_rewrite_makes_no_removal_obligation_end_to_end(tmp_path):
    merged = "def f(x: int, y: int):\n    if x < 0 or y < 0:\n        raise ValueError('bad')\n    return x + y\n"
    s = _derive(tmp_path, TWO_PLAIN, merged)
    assert not [o for o in s.obligations if o.obligation_id.startswith("guard-removed")], [o.obligation_id for o in s.obligations]


def test_dropped_guard_still_blocks_end_to_end(tmp_path):
    dropped = "def f(x: int, y: int):\n    if x < 0:\n        raise ValueError('bad')\n    return x + y\n"
    s = _derive(tmp_path, TWO_PLAIN, dropped)
    assert _blockers(s), [(o.obligation_id, o.verdict) for o in s.obligations]  # unresolved-N (review) or guard-removed (review)


def test_dropped_guard_blocks_by_guard_removed_when_the_account_has_no_pre_evidence(tmp_path, monkeypatch):
    _no_pre_guard_evidence(monkeypatch)
    dropped = "def f(x: int, y: int):\n    if x < 0:\n        raise ValueError('bad')\n    return x + y\n"
    s = _derive(tmp_path, TWO_PLAIN, dropped)
    assert [o for o in s.obligations if o.obligation_id.startswith("guard-removed") and o.verdict is Verdict.NOT_DERIVED],\
        [(o.obligation_id, o.verdict) for o in s.obligations]
