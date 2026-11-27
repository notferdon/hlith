"""Rule C (effect-declared-vs-observed): REFUTED means a witnessed difference or a claim violation; a change the account cannot model is NOT_DERIVED."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # tests/ is not a package (bare pytest)

from hlith import summary
from hlith.cli import build_artifact, incident_obligation, run_pipeline
from hlith.runtime import DeclaredEffects, ObservedChange, reconcile
from hlith.types import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict

OBS_COMPAT = (ObservedChange("src/requests/compat.py", frozenset({"modify"})),)   # requests 1c38e1f5: from-import names added
OBS_CERTS = (ObservedChange("src/requests/certs.py", frozenset({"modify"})),)      # requests 2a6f290b: AST-equal file


def _held(_repo, _effect):
    prov = CheckProvenance("t", "0" * 64, True, False, "1" * 64, 0)
    return ObligationSet((Obligation("o1", "calc.add", "claim", Verdict.HELD, evidence=BoundedEvidence(1, "synthetic", "rest"), provenance=prov, account_bound=True),))


def test_a_file_the_account_cannot_model_is_not_derived_with_no_witness():
    declared = DeclaredEffects.from_paths(["src/requests/utils.py"])  # the account modelled some other file
    manifest = DeclaredEffects.from_paths(["src/requests/compat.py"])  # and the claim is right: it names the file
    rec = reconcile(OBS_COMPAT, declared, manifest=manifest, require_manifest=True)
    ob = incident_obligation(rec)
    assert ob.verdict is Verdict.NOT_DERIVED and ob.witness is None and ob.obligation_id == "effect-declared-vs-observed"
    assert "undeclared by account: file src/requests/compat.py" in ob.stop_reason and "the checker cannot model this change" in ob.stop_reason
    assert rec.not_modelled_files == ("src/requests/compat.py",) and rec.claim_violations == ()


def test_ast_equal_file_case_is_also_not_derived():
    rec = reconcile(OBS_CERTS, DeclaredEffects.from_paths([]), manifest=DeclaredEffects.from_paths(["src/requests/certs.py"]), require_manifest=True)
    ob = incident_obligation(rec)
    assert ob.verdict is Verdict.NOT_DERIVED and "the checker cannot model this change" in ob.stop_reason


def test_a_change_outside_the_agents_claim_is_a_labelled_claim_violation_and_stays_refused():
    declared = DeclaredEffects.from_paths(["a.py", "extra.py"])  # the account saw both files
    manifest = DeclaredEffects.from_paths(["a.py"])              # the agent claimed only a.py
    obs = (ObservedChange("a.py", frozenset({"modify"})), ObservedChange("extra.py", frozenset({"add"})))
    rec = reconcile(obs, declared, manifest=manifest, require_manifest=True)
    ob = incident_obligation(rec)
    assert ob.verdict is Verdict.REFUTED and ob.witness.startswith("claim violation:") and "undeclared by manifest: file extra.py" in ob.witness
    assert rec.claim_violations and rec.not_modelled_files == ()


def test_an_undeclared_kind_on_a_modelled_file_is_a_claim_violation():
    rec = reconcile((ObservedChange("a.py", frozenset({"modify", "mode"})),), DeclaredEffects.from_paths(["a.py"]),
                    manifest=DeclaredEffects.from_paths(["a.py"], frozenset({"modify", "mode"})), require_manifest=True)
    ob = incident_obligation(rec)
    assert ob.verdict is Verdict.REFUTED and ob.witness.startswith("claim violation:") and "undeclared by account: mode on a.py" in ob.witness


def test_mixed_case_is_refused_as_a_claim_violation_and_names_the_unmodelled_file_too():
    declared = DeclaredEffects.from_paths(["a.py"])
    manifest = DeclaredEffects.from_paths(["a.py"])
    obs = (ObservedChange("a.py", frozenset({"modify"})), ObservedChange("b.py", frozenset({"modify"})))
    ob = incident_obligation(reconcile(obs, declared, manifest=manifest, require_manifest=True))
    assert ob.verdict is Verdict.REFUTED and ob.witness.startswith("claim violation:") and "b.py" in ob.witness


def test_missing_sources_stay_unverified():
    ob = incident_obligation(reconcile(OBS_COMPAT, None, manifest=DeclaredEffects.from_paths(["src/requests/compat.py"]), require_manifest=True))
    assert ob.verdict is Verdict.UNVERIFIED and "effect-account declaration" in ob.stop_reason


def test_through_the_gate_exit_codes(tmp_path):
    import subprocess

    def g(*a):
        return subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True, capture_output=True, text=True).stdout
    g("init", "-q", "-b", "main")
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    g("add", "-A")
    g("commit", "-q", "-m", "base")
    edit = "s=open('calc.py').read(); open('calc.py','w').write(s+'# e\\n');"
    man = lambda paths: "import os,json; open(os.environ['HLITH_MANIFEST_DIR']+'/manifest.json','w').write(json.dumps({'paths': %r}))" % (paths,)  # noqa: E731
    cmd = lambda s: [sys.executable, "-I", "-c", s]  # noqa: E731
    # the account declares nothing it can model for calc.py: the checker cannot model this change -> NOT_DERIVED -> exit 11
    run, obl, decision, rec = run_pipeline(tmp_path, cmd(edit + man({"calc.py": ["modify"]})), derive=_held, declare=lambda r, e: DeclaredEffects.from_paths([]))
    assert decision.exit_status == 11 and decision.blocking == ("effect-declared-vs-observed",)
    art = build_artifact(run, obl, decision, rec)
    o = next(x for x in art["obligations"] if x["id"] == "effect-declared-vs-observed")
    assert o["verdict"] == "not-derived" and o["witness"] is None and "the checker cannot model this change" in o["stop_reason"]
    # the agent claims only calc.py but also writes extra.py: a claim violation -> still REFUTED -> exit 10
    run, obl, decision, rec = run_pipeline(tmp_path, cmd(edit + "open('extra.py','w').write('1');" + man({"calc.py": ["modify"]})), derive=_held,
                                           declare=lambda r, e: DeclaredEffects.from_paths(["calc.py", "extra.py"]))
    o = next(x for x in build_artifact(run, obl, decision, rec)["obligations"] if x["id"] == "effect-declared-vs-observed")
    assert decision.exit_status == 10 and o["verdict"] == "refuted" and o["witness"].startswith("claim violation:")


def test_summary_says_the_checker_cannot_model_it_not_fix_your_manifest():
    ob = {"id": "effect-declared-vs-observed", "verdict": "not-derived", "claim": "c",
          "stop_reason": "undeclared by account: file src/requests/compat.py; the checker cannot model this change"}
    nxt = summary._next_step(ob, {})
    assert "cannot model" in nxt and "not a defect in your change" in nxt and "add it to the manifest" not in nxt
    ref = summary._next_step({"id": "effect-declared-vs-observed", "verdict": "refuted", "witness": "claim violation: undeclared by manifest: file x.py"}, {})
    assert "claim" in ref.lower() and "manifest" in ref


def test_incident_kind_distinguishes_not_modelled_from_claim_violation(tmp_path):
    import subprocess

    def g(*a):
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True, capture_output=True)
    g("init", "-q", "-b", "main")
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    g("add", "-A")
    g("commit", "-q", "-m", "base")
    edit = "s=open('calc.py').read(); open('calc.py','w').write(s+'# e\\n');"
    man = "import os,json; open(os.environ['HLITH_MANIFEST_DIR']+'/manifest.json','w').write(json.dumps({'paths': {'calc.py': ['modify']}}))"
    run, obl, decision, rec = run_pipeline(tmp_path, [sys.executable, "-I", "-c", edit + man], derive=_held, declare=lambda r, e: DeclaredEffects.from_paths([]))
    assert build_artifact(run, obl, decision, rec)["incident"]["kind"] == "not-modelled"
    g("checkout", "-q", "calc.py")
    run, obl, decision, rec = run_pipeline(tmp_path, [sys.executable, "-I", "-c", edit + "open('extra.py','w').write('1');" + man], derive=_held,
                                           declare=lambda r, e: DeclaredEffects.from_paths(["calc.py", "extra.py"]))
    assert build_artifact(run, obl, decision, rec)["incident"]["kind"] == "claim-violation"
