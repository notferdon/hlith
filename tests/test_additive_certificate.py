"""The guard-removal certificate also runs when the differential did NOT hold (design review, review's finding on C2/h1/C3).

review: delta_follow seeds an unguarded changed region with type-agnostic candidates, so n='' (pre TypeError, post 0) refuted the
differential off-domain BEFORE the certificate ran; the certificate's own counterexample (inside P at n=-997) never showed.
The fix is additive: the certificate's verdict is appended as a NAMED obligation beside the blocker. Two properties are pinned:

  1. whatever the certificate says (proved / counterexample / unknown / unsupported), the additive obligation is never HELD and
     never replaces anything, so it cannot discharge scope or upgrade a verdict;
  2. end to end, turning the additive path off changes NOTHING except the added `guard-removal-certificate` obligation.
"""

import importlib.util
import subprocess
from types import SimpleNamespace

import pytest

from hlith import derive as derive_mod
from hlith.derive import make_derive
from hlith.obligation import guard_certificate as gc
from hlith.runtime import DeltaEffect
from hlith.types import Verdict

MC = SimpleNamespace(qualified_name="m.f")
RG = {"line": 2, "cond": "n < 0", "exc": "builtins.ValueError"}
D = {"id": "d1", "symbol": "m.f", "predicate": {"type": "expr", "param": "n", "expr": "n < 0"},
     "expected": {"kind": "returns_expr", "expr": "0"}}


def _additive(monkeypatch, cert, replay=lambda cand: None, deltas=(D,)):
    monkeypatch.setattr(derive_mod, "_certificate_for", lambda *a, **k: cert)
    return derive_mod._additive_certificate(MC, RG, list(deltas), "/b", "/p", replay)


@pytest.mark.parametrize("cert,verdict", [
    (gc.Cert(gc.PROVED, "ok"), Verdict.UNVERIFIED),
    (gc.Cert(gc.COUNTEREXAMPLE, "counterexample (inside-P): n=-997", {"side": "inside-P", "params": {"n": -997}}), Verdict.UNVERIFIED),
    (gc.Cert(gc.UNKNOWN, "the solver exceeded its wall limit"), Verdict.UNVERIFIED),
    (gc.Cert(gc.UNSUPPORTED, "outside the model"), Verdict.NOT_DERIVED),
])
def test_the_additive_obligation_is_never_held(monkeypatch, cert, verdict):
    ob = _additive(monkeypatch, cert)
    assert ob is not None and ob.verdict is verdict and ob.verdict is not Verdict.HELD
    assert ob.obligation_id == "guard-removal-certificate:m.f:2"
    assert not ob.obligation_id.startswith("guard-removal-covered")  # the id that can discharge scope


@pytest.mark.parametrize("cert", [
    gc.Cert(gc.PROVED, "ok"),
    gc.Cert(gc.COUNTEREXAMPLE, "counterexample (inside-P): n=0.5", {"side": "inside-P", "params": {"n": 0.5}}),
    gc.Cert(gc.UNKNOWN, "wall limit"),
])
def test_every_certificate_text_states_the_proof_domain_first(monkeypatch, cert):
    """C8: 'the certificate proves ...' beside a float counterexample read as a global claim. The domain note comes FIRST (the texts are
    length-capped) in the proved, counterexample and unknown texts."""
    ob = _additive(monkeypatch, cert)
    text = ob.stop_reason or ob.witness or ""
    assert text.startswith("[" + gc.SCOPE_NOTE + "]"), text
    assert "NOT covered" in text and "PROVES" not in text, text


def test_a_proved_certificate_beside_a_blocker_discharges_nothing(monkeypatch):
    ob = _additive(monkeypatch, gc.Cert(gc.PROVED, "ok"))
    assert ob.verdict is Verdict.UNVERIFIED and "nothing is discharged" in ob.stop_reason


def test_a_reproduced_counterexample_is_refuted_and_a_non_reproduced_one_is_unverified(monkeypatch):
    cex = gc.Cert(gc.COUNTEREXAMPLE, "counterexample (inside-P): n=-997", {"side": "inside-P", "params": {"n": -997}})
    rep = SimpleNamespace(verdict=Verdict.REFUTED, witness="f(-997) pre raised, post returned 1")
    ob = _additive(monkeypatch, cex, replay=lambda cand: rep)
    assert ob.verdict is Verdict.REFUTED and "-997" in (ob.witness or "")
    ob = _additive(monkeypatch, cex, replay=lambda cand: None)
    assert ob.verdict is Verdict.UNVERIFIED and "-997" in ob.stop_reason and "not replayable" in ob.stop_reason


def test_no_delta_naming_the_symbol_means_no_obligation(monkeypatch):
    assert _additive(monkeypatch, gc.Cert(gc.PROVED, "ok"), deltas=[{**D, "symbol": "m.other"}]) is None
    assert _additive(monkeypatch, gc.Cert(gc.PROVED, "ok"), deltas=[]) is None


def test_a_modelled_delta_is_preferred_over_an_advisory_one(monkeypatch):
    seen = {}

    def spy(mc, rg, rcov, base, post, deltas):
        seen["id"] = rcov.delta_id
        return gc.Cert(gc.UNSUPPORTED, "x")

    monkeypatch.setattr(derive_mod, "_certificate_for", spy)
    advisory = {"id": "adv", "symbol": "m.f"}
    derive_mod._additive_certificate(MC, RG, [advisory, D], "/b", "/p", lambda c: None)
    assert seen["id"] == "d1"


# ------------------------------------------------------------------------------------------------ end to end (C2)
def _repo(tmp_path, old, new):
    repo = tmp_path / "r"
    repo.mkdir(parents=True)
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text(old)
    (repo / "test_m.py").write_text("from m import f\n\n\ndef test_f():\n    assert f(3) == 0\n    assert f(0) == 0\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    (repo / "m.py").write_text(new)
    diff = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True, text=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "m.py"], check=True)
    prop = tmp_path / "p"
    prop.mkdir(parents=True)
    (prop / "x").write_text("x")
    return repo, diff, prop


BASE = "def f(n: int):\n    if n < 0:\n        raise ValueError()\n    return 0\n"
C2 = "def f(n: int):\n    return int(n == -997 or n == 997)\n"
C2_DELTA = {"id": "d1", "symbol": "m.f", "kind": "behavior", "claim": "negative n returns 0", "input_domain": "n < 0",
            "pre": "raises ValueError", "post": "returns 0",
            "predicate": {"type": "expr", "param": "n", "expr": "n < 0"}, "expected": {"kind": "returns_expr", "expr": "0"}}


def _run(tmp_path, tag, post=C2):
    repo, diff, prop = _repo(tmp_path / tag, BASE, post)
    eff = DeltaEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",), deltas=(C2_DELTA,))
    return make_derive(proposer_paths=[str(prop)])(repo, eff)


@pytest.mark.skipif(importlib.util.find_spec("z3") is None, reason="z3 is not installed")
def test_c2_shows_the_certificate_counterexample_and_the_additive_path_changes_nothing_else(tmp_path, monkeypatch):
    with_add = _run(tmp_path, "on")
    monkeypatch.setattr(derive_mod, "_additive_certificate", lambda *a, **k: None)
    without = _run(tmp_path, "off")

    def sig(s):
        return sorted((o.obligation_id, o.verdict.name) for o in s.obligations if not o.obligation_id.startswith("guard-removal-certificate"))

    assert sig(with_add) == sig(without), "the additive path changed an existing obligation"
    added = [o for o in with_add.obligations if o.obligation_id.startswith("guard-removal-certificate")]
    assert added and all(o.verdict is not Verdict.HELD for o in added), [(o.obligation_id, o.verdict.name) for o in added]
    text = " ".join((o.witness or "") + (o.stop_reason or "") for o in added)
    assert "-997" in text and "inside-P" in text, text  # the certificate's own counterexample, shown beside the blocker
    assert not any(o.obligation_id.startswith("guard-removal-covered") for o in with_add.obligations)
    # a refusal stays a refusal: something non-HELD exists with and without the certificate
    assert any(o.verdict is not Verdict.HELD for o in without.obligations)
    assert any(o.verdict is not Verdict.HELD for o in with_add.obligations)



C7 = "def f(n: int):\n    return n != n\n"  # always False: a bool where the declared outcome is the int 0


def test_c7_a_proved_certificate_never_discharges_scope_alone(tmp_path, monkeypatch):
    """design review invariant: the certificate is one of THREE conditions for a HELD guard-removal-covered (type-exact differential HELD, observed
    coverage, certificate). Force the weakest possible certificate (PROVED, as if its equality were type-blind) on the C7 shape (a bool
    return); the type-exact differential refuses, so NOTHING is HELD for the removal and the outcome is a refusal. A future change that
    let the certificate (or a weaker equality) discharge scope on its own would turn this red."""
    monkeypatch.setattr(gc, "certify_removal", lambda *a, **k: gc.Cert(gc.PROVED, "forced PROVED (type-blind equality)"))
    s = _run(tmp_path, "c7", post=C7)
    held_cover = [o.obligation_id for o in s.obligations
                  if o.obligation_id.startswith("guard-removal-covered") and o.verdict is Verdict.HELD]
    assert not held_cover, held_cover
    diff_ob = next(o for o in s.obligations if o.obligation_id == "differential:m.f")
    assert diff_ob.verdict is not Verdict.HELD, (diff_ob.verdict, diff_ob.witness, diff_ob.stop_reason)
    assert any(o.verdict is not Verdict.HELD for o in s.obligations)  # a refusal
    named = [o for o in s.obligations if o.obligation_id.startswith("guard-removal-certificate")]
    assert named and all(o.verdict is not Verdict.HELD for o in named)
    assert all((o.stop_reason or o.witness or "").startswith("[" + gc.SCOPE_NOTE + "]") for o in named)


@pytest.mark.skipif(importlib.util.find_spec("z3") is None, reason="z3 is not installed")
def test_c7_the_real_certificate_also_refuses_the_bool_return():
    """And without forcing: the encoder's static kind check makes the certificate itself unsupported for a bool post (RT-1)."""
    import ast
    import textwrap

    c = gc.certify_removal(ast.parse(textwrap.dedent(BASE)).body[0], ast.parse(textwrap.dedent(C7)).body[0], "n < 0", D)
    assert c.status == gc.UNSUPPORTED and "TYPE" in c.why, c

