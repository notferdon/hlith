# SPDX-License-Identifier: Apache-2.0
"""ObligationSet.evidence carries non-gating delta_rel items in the shape review's closed schema encodes."""
import json

import pytest
import re
import subprocess

from hlith.derive import make_derive
from hlith.types import ProposedEffect, Verdict

DIFF = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,2 @@\n def f(x: int) -> int:\n-    return x + 1\n+    return x + 2\n"


def _derive(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text("def f(x: int) -> int:\n    return x + 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    prop = tmp_path / "p"
    prop.mkdir()
    (prop / "x").write_text("x")
    return make_derive(proposer_paths=[str(prop)])(repo, ProposedEffect(unified_diff=DIFF, proposer_id="t", touched_files=("m.py",)))


def test_delta_rel_evidence_item_shape_and_non_gating(tmp_path):
    s = _derive(tmp_path)
    (it,) = s.evidence
    assert it["symbol"] == "m.f" and it["verdict"] == "COUNTEREXAMPLE" and len(it["reason"]) <= 300
    assert it["witness_inputs"] == [{"x": "0"}]  # {param: value_repr}
    assert all(re.fullmatch(r"[a-f0-9]{64}", it["provenance"][k]) for k in ("pre_sha256", "post_sha256"))
    assert it["provenance"]["analysis"] == "delta_rel" and "\n" not in it["fragment_notes"]
    json.dumps(s.evidence)  # JSON-safe
    # the counterexample seeded the differential, which decided; the evidence itself gates nothing
    assert any(o.verdict is Verdict.REFUTED for o in s.obligations)
    assert all(o.obligation_id != "delta_rel" for o in s.obligations)


METHOD_DIFF = ("diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,3 +1,3 @@\n class C:\n     def f(self, a):\n-        return a.x\n"
               "+        return a.y\n")


def test_method_gets_a_delta_rel_item_with_schema_shaped_function(tmp_path):
    import subprocess

    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text("class C:\n    def f(self, a):\n        return a.x\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    prop = tmp_path / "p"
    prop.mkdir()
    (prop / "x").write_text("x")
    s = make_derive(proposer_paths=[str(prop)])(
        repo, ProposedEffect(unified_diff=METHOD_DIFF, proposer_id="t", touched_files=("m.py",)))
    (it,) = s.evidence
    assert it["symbol"] == "m.C.f" and it["provenance"]["function"] == "f"  # last component, as the schema checks
    assert it["verdict"] == "UNMODELED" and "differ" in it["reason"]  # an edit under UF is never PROVED without a delta


# ---------------------------------------------------------------- proof tier (design review: only the unconditional tier may ever count alone)
NUM_OLD = "def f(x: int) -> int:\n    return x + 1\n"
NUM_NEW = "def f(x: int) -> int:\n    return 1 + x\n"
UF_OLD = "def f(x):\n    return g(x)\n"
UF_NEW = "def f(x):\n    y = g(x)\n    return y\n"


@pytest.fixture
def clean_universe(monkeypatch):
    """derive does not yet supply the repo class universe (review's runtime universe); until it does an exact-int proof is
    CONDITIONAL (review D01/D03/D04/D06). This fixture stands in for a caller that PROVES the universe clean."""
    from hlith import delta_rel

    real = delta_rel.check_callable
    monkeypatch.setattr(delta_rel, "check_callable",
                        lambda *a, **k: real(*a, **{"repo_universe": {"subclasses": [], "complete": True}, **k}))


def test_numeric_proved_is_unconditional_only_with_a_proved_clean_universe():
    from hlith import delta_rel

    r = delta_rel.check_callable(NUM_OLD, NUM_NEW, "f", None, None, {"subclasses": [], "complete": True})
    assert r.verdict == "PROVED" and r.tier == "unconditional" and r.assumptions == []
    r = delta_rel.check_callable(NUM_OLD, NUM_NEW, "f")  # universe unknown: conditional, and it says why
    assert r.verdict == "PROVED" and r.tier == "conditional" and any("subclass" in a for a in r.assumptions)


def test_uf_proved_is_conditional_and_names_its_assumptions():
    from hlith import delta_rel

    r = delta_rel.check_callable(UF_OLD, UF_NEW, "f")
    assert r.verdict == "PROVED" and r.tier == "conditional"
    assert any("deterministic" in a and "not verified" in a for a in r.assumptions), r.assumptions


def test_counterexample_and_unmodeled_have_no_tier():
    from hlith import delta_rel

    ce = delta_rel.check_callable(NUM_OLD, "def f(x: int) -> int:\n    return x + 2\n", "f")
    um = delta_rel.check_callable("def f(x):\n    return g(x)\n", "def f(x):\n    return h(x)\n", "f")
    assert (ce.verdict, ce.tier, ce.assumptions) == ("COUNTEREXAMPLE", "none", [])
    assert (um.verdict, um.tier) == ("UNMODELED", "none")


def test_numeric_proved_with_deltas_says_the_deltas_are_assumed():
    from hlith import delta_rel

    d = {"id": "d1", "symbol": "m.f", "kind": "behavior", "claim": "c", "input_domain": "x<0", "pre": "p", "post": "q",
         "predicate": {"type": "expr", "param": "x", "expr": "x < 0"}, "expected": {"kind": "returns", "value_repr": "0"}}
    r = delta_rel.check_callable(NUM_OLD, "def f(x: int) -> int:\n    return 0 if x < 0 else x + 1\n", "f", [d], None,
                                 {"subclasses": [], "complete": True})
    assert r.verdict == "PROVED" and r.tier == "unconditional"
    assert any("declared delta" in a for a in r.assumptions), r.assumptions


def _evidence(tmp_path, old, new, name="f"):
    import subprocess

    from hlith.derive import make_derive

    repo = tmp_path / "r"
    repo.mkdir(parents=True)
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text(old)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    (repo / "m.py").write_text(new)
    diff = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True, text=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "m.py"], check=True)
    prop = tmp_path / "p"
    prop.mkdir(parents=True)
    (prop / "x").write_text("x")
    return make_derive(proposer_paths=[str(prop)])(repo, ProposedEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",)))


def test_evidence_item_carries_proof_tier_and_validates_against_schema(clean_universe, tmp_path):
    import json
    from pathlib import Path

    from test_feedback import schema_errors

    root = json.loads((Path(__file__).parents[1] / "src/hlith/hlith.schema.json").read_text())
    item_schema = root["$defs"]["delta_rel_item"]
    for old, new, tier in ((NUM_OLD, NUM_NEW, "unconditional"), (UF_OLD, UF_NEW, "conditional"),
                           (NUM_OLD, "def f(x: int) -> int:\n    return x + 2\n", "none")):
        (it,) = _evidence(tmp_path / tier, old, new).evidence
        assert it["proof_tier"] == tier, it
        assert isinstance(it["assumptions"], list) and (it["assumptions"] == [] or tier == "conditional")
        assert schema_errors(it, item_schema, root) == [], schema_errors(it, item_schema, root)


# ---------------------------------------------------------------- adequacy waiver: only an UNCONDITIONAL PROVED without assumptions
def _capture_adequacy(monkeypatch, tmp_path, old, new):
    from hlith import derive as dv

    seen = {}
    real = dv.differential.run_differential

    def stub(*a, adequacy_proved="", **kw):
        seen["adequacy_proved"] = adequacy_proved
        return real(*a, **kw)

    monkeypatch.setattr(dv.differential, "run_differential", stub)
    _evidence(tmp_path, old, new)
    return seen["adequacy_proved"]


def test_unconditional_proved_waives_adequacy_for_that_symbol(clean_universe, monkeypatch, tmp_path):
    from hlith import derive as dv

    monkeypatch.setattr(dv, "ADEQUACY_PROVED_WAIVER", True)  # OFF by default (review D07-D09); mechanism test only
    assert _capture_adequacy(monkeypatch, tmp_path, NUM_OLD, NUM_NEW) == "delta_rel:m.f"


def test_conditional_or_counterexample_never_waives(monkeypatch, tmp_path):
    from hlith import derive as dv

    monkeypatch.setattr(dv, "ADEQUACY_PROVED_WAIVER", True)
    assert _capture_adequacy(monkeypatch, tmp_path / "uf", UF_OLD, UF_NEW) == ""
    assert _capture_adequacy(monkeypatch, tmp_path / "ce", NUM_OLD, "def f(x: int) -> int:\n    return x + 2\n") == ""


def test_derive_still_works_when_run_differential_has_no_adequacy_parameter(clean_universe, tmp_path):
    # merge order independence: the real run_differential on this branch may predate review's parameter
    (it,) = _evidence(tmp_path, NUM_OLD, NUM_NEW).evidence
    assert it["proof_tier"] == "unconditional"
