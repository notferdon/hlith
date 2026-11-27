# SPDX-License-Identifier: Apache-2.0
"""z3_binding tests. Logic cases plus real call sites from psf/requests @0e322af.

The call-site extractor below is TEST SUPPORT (stdlib ast, direct ``name(...)`` /
``x.name(...)`` calls). It stands in for review's effect-account builder only until that
lands; it emits the agreed ``impacted_call_sites`` shape.
"""

from __future__ import annotations

import ast
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from hlith.sandbox import Profile
from hlith.types import Verdict
from hlith.z3_binding import (
    SignatureError,
    analyze,
    derive_obligation,
    measure_proposer_readable,
    parse_signature,
    verify_confined,
)

REQ_SHA = "0e322af87745eff34caffe4df68456ebc20d9068"
REQ_ROOT = Path(os.environ.get("HLITH_REQUESTS_ROOT", Path(tempfile.gettempdir()) / "hlith-acc" / "requests"))
REQ_SRC = REQ_ROOT / "src" / "requests"

needs_requests = pytest.mark.skipif(not REQ_SRC.is_dir(), reason="requests clone missing (set HLITH_REQUESTS_ROOT)")


def _sig_text(path: Path, func: str) -> str:
    """Real parameter list of ``def func`` in a real file, as source text."""
    tree = ast.parse(path.read_text())
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func:
            return "(" + ast.unparse(n.args) + ")"
    raise LookupError(func)


def _call_sites(callee_short: str, *, method: bool = False, only: tuple[str, ...] = ()) -> list[dict]:
    out = []
    for f in sorted(REQ_SRC.glob("*.py")):
        if only and f.name not in only:
            continue
        for n in ast.walk(ast.parse(f.read_text())):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if name != callee_short or (method != isinstance(fn, ast.Attribute)):
                continue
            lits = {}
            for i, a in enumerate(n.args):
                if isinstance(a, ast.Constant):
                    lits[str(i)] = repr(a.value)
            for k in n.keywords:
                if k.arg and isinstance(k.value, ast.Constant):
                    lits[k.arg] = repr(k.value.value)
            out.append({
                "caller_qualified_name": f"{f.stem}:L{n.lineno}",
                "callee_qualified_name": callee_short,
                "file_path": f"src/requests/{f.name}",
                "line_number": n.lineno,
                "arg_structure": {
                    "n_positional": sum(not isinstance(a, ast.Starred) for a in n.args),
                    "keywords": [k.arg for k in n.keywords if k.arg],
                    "star_args": any(isinstance(a, ast.Starred) for a in n.args),
                    "star_kwargs": any(k.arg is None for k in n.keywords),
                    "arg_literals": lits,
                    "is_method_call": method,
                },
            })
    return out


_ACCEPT_ALL = "(*args, **kw)"  # pre-change stand-in that accepted every call, so post failures are regressions


def _req(sig: str, sites: list[dict], pre: str | None = _ACCEPT_ALL, guards=(), oid="o1") -> dict:
    return {"obligation_id": oid, "target_symbol": "pkg.f", "post_signature": sig,
            "pre_signature": pre, "call_sites": sites, "entry_guards": list(guards), "pre_entry_guards": []}


def _site(n=0, kw=(), star=False, kwstar=False, lits=None, method=False, line=10):
    return {"caller_qualified_name": "c", "callee_qualified_name": "f", "file_path": "m.py", "line_number": line,
            "arg_structure": {"n_positional": n, "keywords": list(kw), "star_args": star, "star_kwargs": kwstar,
                              "arg_literals": lits or {}, "is_method_call": method}}


# ------------------------------------------------------------------ signature parsing
def test_parse_all_kinds():
    p = parse_signature("(self, a, /, b=1, *args, c, d=2, **kw)")
    assert [(x.name, x.kind, x.has_default) for x in p] == [
        ("self", "posonly", False), ("a", "posonly", False), ("b", "pos_or_kw", True),
        ("args", "vararg", True), ("c", "kwonly", False), ("d", "kwonly", True), ("kw", "kwarg", True)]


def test_parse_rejects_garbage():
    with pytest.raises(SignatureError):
        parse_signature("a, b")
    with pytest.raises(SignatureError):
        parse_signature("(a b)")


# ------------------------------------------------------------------ binding semantics
@pytest.mark.parametrize("sig,site,expect", [
    ("(a, b=1)", _site(1), []),
    ("(a, b=1)", _site(0), ["missing:a"]),
    ("(a, b=1)", _site(3), ["too_many_positional"]),
    ("(a, b=1)", _site(1, kw=("a",)), ["multiple_values:a"]),
    ("(a, b=1)", _site(1, kw=("zzz",)), ["unexpected_keyword:zzz"]),
    ("(a, b=1, **kw)", _site(1, kw=("zzz",)), []),
    ("(a, *args)", _site(5), []),
    ("(a, /, b)", _site(2), []),
    ("(a, /, b)", _site(1, kw=("a", "b")), ["unexpected_keyword:a"]),
    ("(a, *, k)", _site(1), ["missing:k"]),
    ("(a, *, k)", _site(1, kw=("k",)), []),
    ("(self, a)", _site(1, method=True), []),          # implicit self
    ("(self, a)", _site(2, method=True), ["too_many_positional"]),
])
def test_binding_table(sig, site, expect):
    got = analyze(_req(sig, [site]))
    errs = got["refuted"][0]["errors"] if got["refuted"] else []
    assert sorted(errs) == sorted(expect)


def test_entry_guard_literal_none_refutes():
    r = analyze(_req("(a, b)", [_site(2, lits={"1": "None"})], guards=[{"param": "b", "raises_when": "none"}]))
    assert r["refuted"] and r["refuted"][0]["errors"] == ["guard:b:none"]


# ------------------------------------------------------------------ unsound-pass cases
def test_star_args_site_is_not_derived():
    r = analyze(_req("(a, b)", [_site(1, star=True)]))
    o = derive_obligation(_req("(a, b)", [_site(1, star=True)]), r, None)
    assert o.verdict is Verdict.NOT_DERIVED and "m.py:10" in o.stop_reason and "*args" in o.stop_reason


def test_visible_definite_error_survives_double_star():
    # **kw at the call site cannot hide an explicit unexpected keyword
    req = _req("(a)", [_site(1, kw=("zzz",), kwstar=True)])
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.REFUTED and "unexpected_keyword:zzz" in o.witness


def test_opaque_string_arg_structure_is_not_derived():
    s = {"caller_qualified_name": "c", "callee_qualified_name": "f", "file_path": "m.py", "line_number": 3,
         "arg_structure": "f(x, y)"}
    req = _req("(a, b)", [s])
    assert derive_obligation(req, analyze(req), None).verdict is Verdict.NOT_DERIVED


def test_direct_fields_accepted_when_arg_structure_is_opaque_text():
    s = {"caller_qualified_name": "c", "callee_qualified_name": "f", "file_path": "m.py", "line_number": 3,
         "arg_structure": "f(x, y)", "n_positional": 2, "keywords": [], "star_args": False, "star_kwargs": False}
    req = _req("(a, b)", [s])
    assert not analyze(req)["unresolved"] and not analyze(req)["refuted"]
    s["n_positional"] = 3
    assert analyze(_req("(a, b)", [s]))["refuted"]


def test_zero_call_sites_is_not_derived_not_held():
    req = _req("(a)", [])
    assert derive_obligation(req, analyze(req), None).verdict is Verdict.NOT_DERIVED


def test_clean_without_provenance_is_unverified_never_held():
    req = _req("(a)", [_site(1)])
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.UNVERIFIED and "CheckProvenance" in o.stop_reason


# ------------------------------------------------------------------ real requests call sites
@needs_requests
def test_requests_clone_is_the_pinned_revision():
    sha = subprocess.run(["git", "-C", str(REQ_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert sha == REQ_SHA


@needs_requests
def test_real_removed_required_parameter_is_refuted_with_caller_and_line():
    sites = _call_sites("get_auth_from_url")
    assert len(sites) >= 4
    pre = _sig_text(REQ_SRC / "utils.py", "get_auth_from_url")
    assert pre == "(url)"
    req = _req("()", sites, pre=pre)  # the change removes the required `url`
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.REFUTED
    assert "src/requests/" in o.witness and "too_many_positional" in o.witness and "pre-change binding: binds" in o.witness
    assert len(analyze(req)["refuted"]) == len(sites)  # every real caller is broken, none missed


@needs_requests
def test_real_added_required_parameter_is_refuted():
    sites = _call_sites("prepend_scheme_if_needed")
    pre = _sig_text(REQ_SRC / "utils.py", "prepend_scheme_if_needed")
    req = _req("(url, new_scheme, realm)", sites, pre=pre)
    r = analyze(req)
    assert r["refuted"] and all(x["errors"] == ["missing:realm"] for x in r["refuted"])


@needs_requests
def test_real_identity_change_binds_everywhere():
    sites = _call_sites("to_native_string")
    sig = _sig_text(REQ_SRC / "_internal_utils.py", "to_native_string")
    r = analyze(_req(sig, sites))
    assert not r["refuted"] and not r["unresolved"] and len(r["clean"]) == len(sites) >= 5
    # a change that makes `encoding` required breaks exactly the 1-arg callers
    r2 = analyze(_req("(string, encoding)", sites))
    assert len(r2["refuted"]) == sum(1 for s in sites if s["arg_structure"]["n_positional"] == 1
                                     and "encoding" not in s["arg_structure"]["keywords"])


@needs_requests
def test_real_kwargs_forwarding_sites_are_not_derived():
    sites = _call_sites("request", method=True, only=("sessions.py",))
    assert any(s["arg_structure"]["star_kwargs"] for s in sites)
    sig = _sig_text(REQ_SRC / "sessions.py", "request")
    req = _req(sig, sites)
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.NOT_DERIVED and "**kwargs" in o.stop_reason and "sessions.py:" in o.stop_reason


@needs_requests
def test_real_double_star_site_still_refuted_by_visible_part():
    sites = _call_sites("request", method=True, only=("sessions.py",))
    req = _req("(self)", sites)  # callee collapsed to (self): positional args are definitely too many
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.REFUTED and "too_many_positional" in o.witness


# ------------------------------------------------------------------ confined supervisor path
@pytest.fixture
def proposer_dir(tmp_path):
    d = tmp_path / "proposer_stage"
    d.mkdir()
    (d / "patch.diff").write_text("--- a\n+++ b\n")
    return d


@needs_requests
def test_held_only_via_confined_run_with_measured_provenance(tmp_path, proposer_dir):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    sites = _call_sites("to_native_string")
    sig = _sig_text(REQ_SRC / "_internal_utils.py", "to_native_string")
    req = _req(sig, sites, pre=sig)
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(proposer_dir), str(proposer_dir / "patch.diff")])
    assert o.verdict is Verdict.HELD, o.stop_reason
    assert o.provenance.confined and not o.provenance.proposer_paths_readable and o.provenance.exit_code == 0
    assert o.evidence.executions == len(sites)
    assert "callers outside the account" in o.evidence.unexplored
    assert o.provenance.checker_id.startswith("z3_call_binding_verifier@z3-")


@needs_requests
def test_confined_run_refutes_real_break(tmp_path, proposer_dir):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    req = _req("()", _call_sites("get_auth_from_url"), oid="o2")
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(proposer_dir)])
    assert o.verdict is Verdict.REFUTED and "too_many_positional" in o.witness


def test_readability_probe_detects_a_readable_proposer_path(tmp_path, proposer_dir):
    open_profile = Profile(ro=(str(proposer_dir),))
    assert measure_proposer_readable([str(proposer_dir / "patch.diff")], open_profile) is True
    assert measure_proposer_readable([str(proposer_dir / "patch.diff")], Profile()) is False


def test_readable_proposer_blocks_held(monkeypatch, tmp_path, proposer_dir):
    import hlith.z3_binding as zb

    monkeypatch.setattr(zb, "measure_proposer_readable", lambda *a, **k: True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    o = zb.verify_confined(_req("(a)", [_site(1)], oid="o3"), scratch_dir=scratch, proposer_paths=[str(proposer_dir)])
    assert o.verdict is Verdict.UNVERIFIED


# ------------------------------------------------------------------ differential vs CPython's own binder
@pytest.mark.parametrize("sig", ["(a, b=1)", "(a, b=1, **kw)", "(a, *args)", "(a, /, b)", "(a, *, k)", "(self, a)", "(a, /, b=2, *, k, m=3)"])
@pytest.mark.parametrize("n", [0, 1, 2, 3])
@pytest.mark.parametrize("kw", [(), ("a",), ("b",), ("k",), ("zzz",), ("a", "k"), ("b", "k")])
def test_z3_binding_agrees_with_cpython_bind(sig, n, kw):
    import inspect

    ns: dict = {}
    exec(f"def f{sig}: pass", ns)  # noqa: S102 - synthetic, test-only signature text
    py_fails = False
    try:
        inspect.signature(ns["f"]).bind(*range(n), **{k: 0 for k in kw})
    except TypeError:
        py_fails = True
    r = analyze(_req(sig, [_site(n, kw=kw)]))
    assert bool(r["refuted"]) == py_fails, (sig, n, kw, r)


# ------------------------------------------------------------------ subsumption (stronger than refusing star sites)
from hlith.z3_binding import signature_subsumption  # noqa: E402


@pytest.mark.parametrize("pre,post,holds", [
    ("(a, b=1)", "(a, b=1, c=2)", True),          # added optional param
    ("(a, b=1)", "(a, b=1, **kw)", True),
    ("(a, b=1)", "(a, *, b=1)", False),           # b no longer positional
    ("(a, b=1)", "(a)", False),                   # removed b
    ("(a)", "(a, b)", False),                     # added required
    ("(a, /, b)", "(a, b)", True),                # relaxing posonly -> normal
    ("(a, b)", "(a, /, b)", False),               # tightening to posonly breaks a=kw
    ("(a, **kw)", "(a)", False),
    ("(a, *args)", "(a)", False),
    ("(a)", "(a, *args, **kw)", True),
])
def test_subsumption_table(pre, post, holds):
    assert signature_subsumption(parse_signature(pre), parse_signature(post)).holds is holds


SIGS = ["(a, b=1)", "(a, b=1, c=2)", "(a, *, b=1)", "(a)", "(a, b)", "(a, /, b)", "(a, **kw)", "(a, *args)",
        "(a, b=1, **kw)", "(a, /, b=2, *, k, m=3)", "(a, b=1, *args, **kw)", "()", "(*, k)"]


def _py_accepts(sig, n, kw):
    import inspect

    ns: dict = {}
    exec(f"def f{sig}: pass", ns)  # noqa: S102
    try:
        inspect.signature(ns["f"]).bind(*range(n), **{k: 0 for k in kw})
        return True
    except TypeError:
        return False


def test_subsumption_matches_exhaustive_enumeration_over_cpython_bind():
    """Z3's universal claim agrees with brute force over call shapes (0..4 positionals, keyword subsets)."""
    import itertools

    names = ["a", "b", "c", "k", "m", "zzz"]
    kwsets = [c for r in range(0, 4) for c in itertools.combinations(names, r)]
    for pre, post in itertools.product(SIGS, SIGS):
        brute = all(_py_accepts(post, n, kw) for n in range(5) for kw in kwsets if _py_accepts(pre, n, kw))
        z = signature_subsumption(parse_signature(pre), parse_signature(post))
        if z.holds:
            assert brute, (pre, post)          # soundness: never claims compat that CPython refutes on the grid
        else:
            # every refutation is a real witness: CPython accepts it under pre and rejects it under post
            kws = tuple("zzz" if k == "__other__" else k for k in z.keywords)
            assert _py_accepts(pre, z.n_positional, kws) and not _py_accepts(post, z.n_positional, kws), (pre, post, z)


@needs_requests
def test_real_star_forwarding_sites_resolved_when_change_is_backward_compatible(tmp_path):
    sites = _call_sites("request", method=True, only=("sessions.py",))
    pre = _sig_text(REQ_SRC / "sessions.py", "request")
    post = pre[:-1] + ", trust_env_override=None)"          # appends one optional keyword parameter
    req = _req(post, sites, pre=pre)
    r = analyze(req)
    assert r["subsumption"]["holds"] and not r["unresolved"] and not r["refuted"]
    assert any(c.get("by_subsumption") for c in r["clean"])
    prop = tmp_path / "prop"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD, o.stop_reason
    assert "subsumption" in o.evidence.explored and "assumes those sites bound pre-change" in o.evidence.explored


@needs_requests
def test_real_star_forwarding_names_the_exact_breaking_shape_when_not_compatible():
    sites = _call_sites("request", method=True, only=("sessions.py",))
    pre = _sig_text(REQ_SRC / "sessions.py", "request")
    assert "timeout=None" in pre
    post = pre.replace("timeout=None, ", "")                 # removes the real `timeout` parameter
    req = _req(post, sites, pre=pre)
    r = analyze(req)
    assert r["subsumption"]["holds"] is False
    o = derive_obligation(req, r, None)
    assert o.verdict is Verdict.NOT_DERIVED and "timeout" in o.stop_reason and "bind pre-change, fail post-change" in o.stop_reason


def test_new_entry_guard_blocks_subsumption_shortcut():
    req = _req("(a, b)", [_site(1, star=True)], pre="(a, b)", guards=[{"param": "b", "raises_when": "none"}])
    assert analyze(req)["unresolved"], "post gained a guard: subsumption alone cannot cover value-level behaviour"


# ------------------------------------------------------------------ structured witnesses for downstream falsifiers
import json  # noqa: E402

from hlith.z3_binding import verify_confined_detailed  # noqa: E402


def _replay(sig_text: str, w: dict) -> bool:
    """Build the concrete call described by a witness and report whether CPython accepts it."""
    return _py_accepts(sig_text, w["n_positional"] + (1 if w.get("is_method_call") else 0),
                       tuple(k for k in w["keywords"]))


@needs_requests
def test_structured_witness_replays_as_a_real_failing_call():
    sites = _call_sites("get_auth_from_url")
    req = _req("()", sites, pre="(url)")
    r = analyze(req)
    assert r["witness_inputs"] and len(r["witness_inputs"]) == len(sites)
    json.dumps(r["witness_inputs"])  # structured and serialisable
    for w in r["witness_inputs"]:
        assert w["kind"] == "call_site_binding_error" and w["violated"] == ["too_many_positional"]
        assert w["site"].startswith("src/requests/") and w["callee"] == "get_auth_from_url"
        assert not _replay("()", w)                       # the witness really fails post-change
        assert _replay("(url)", w)                        # and bound pre-change


def test_guard_witness_carries_the_triggering_literal():
    req = _req("(a, b)", [_site(2, lits={"1": "None"})], guards=[{"param": "b", "raises_when": "none"}])
    w = analyze(req)["witness_inputs"][0]
    assert w["violated"] == ["guard:b:none"] and w["path_literals"] == {"1": "None"}


@needs_requests
def test_subsumption_break_is_exposed_as_structured_shape():
    sites = _call_sites("request", method=True, only=("sessions.py",))
    pre = _sig_text(REQ_SRC / "sessions.py", "request")
    post = pre.replace("timeout=None, ", "")
    r = analyze(_req(post, sites, pre=pre))
    w = [x for x in r["witness_inputs"] if x["kind"] == "signature_subsumption_break"]
    assert len(w) == 1 and "timeout" in w[0]["keywords"]
    assert _py_accepts(pre, w[0]["n_positional"], tuple(w[0]["keywords"]))
    assert not _py_accepts(post, w[0]["n_positional"], tuple(w[0]["keywords"]))


@needs_requests
def test_confined_detailed_returns_witness_inputs(tmp_path):
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o, analysis = verify_confined_detailed(_req("()", _call_sites("get_auth_from_url"), pre="(url)", oid="o9"),
                                           scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.REFUTED and analysis["witness_inputs"]


def test_checker_imports_no_analyzer_modules():
    import hlith.z3_binding as zb

    src = Path(zb.__file__).read_text()
    for banned in ("libcst", "tree_sitter", "hlith.effect", "hlith.account"):
        assert banned not in src


# ------------------------------------------------------------------ account closure: unknown edges
def test_unknown_edges_block_when_signature_not_backward_compatible():
    req = _req("(a)", [_site(1)], pre="(a, b=1)")
    req["unknown_edge_count"] = 2
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.NOT_DERIVED and "2 unknown call edge(s)" in o.stop_reason and "bind pre-change" in o.stop_reason


def test_unknown_edges_covered_by_subsumption_when_compatible_and_scope_text_is_kept(tmp_path):
    req = _req("(a, b=1, c=2)", [_site(1)], pre="(a, b=1)", oid="u1")
    req["unknown_edge_count"] = 3
    req["unexplored_scope"] = "external callers; dynamic dispatch"
    r = analyze(req)
    assert not r["unresolved"] and r["unknown_covered_by_subsumption"] == 3
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD, o.stop_reason
    assert "3 unknown call edge(s)" in o.evidence.explored and "external callers; dynamic dispatch" in o.evidence.unexplored


def test_unknown_edges_without_pre_signature_are_not_derived():
    req = _req("(a)", [_site(1)])
    req["unknown_edge_count"] = 1
    assert derive_obligation(req, analyze(req), None).verdict is Verdict.NOT_DERIVED


def test_unknown_edges_only_no_direct_sites_still_needs_proof_not_silence():
    req = _req("(a, b=1)", [], pre="(a)")
    req["unknown_edge_count"] = 1
    r = analyze(req)
    assert not r["unresolved"] and r["unknown_covered_by_subsumption"] == 1


def test_subsumption_break_witness_carries_concrete_literals():
    pre, post = "(a, b=7, c='x')", "(a, c='x')"        # b removed
    r = analyze(_req(post, [_site(1, star=True)], pre=pre))
    w = [x for x in r["witness_inputs"] if x["kind"] == "signature_subsumption_break"][0]
    assert w["includes_implicit_self"] is False and "path_literals" in w   # free function: index 0 is `a`
    for k, v in w["path_literals"].items():
        import ast as _ast
        _ast.literal_eval(v)                           # every literal is a parseable literal
    if "b" in w["keywords"]:
        assert w["path_literals"]["b"] == "7" and "b" not in w["synthetic"]
    assert all(k in w["path_literals"] and w["path_literals"][k] == "None" for k in w["synthetic"])
    assert "0" in w["synthetic"]                       # `a` has no default: its literal is a placeholder
    # replaying the shape: accepted pre, rejected post
    kws = tuple(("zzz" if k.startswith("<") else k) for k in w["keywords"])
    assert _py_accepts(pre, w["n_positional"], kws) and not _py_accepts(post, w["n_positional"], kws)


def test_includes_implicit_self_only_for_self_or_cls_first_param():
    w = analyze(_req("(self, a)", [_site(1, star=True)], pre="(self, a, b=1)"))["witness_inputs"]
    assert [x for x in w if x["kind"] == "signature_subsumption_break"][0]["includes_implicit_self"] is True
    w = analyze(_req("(url)", [_site(1, star=True)], pre="(url, b=1)"))["witness_inputs"]
    assert [x for x in w if x["kind"] == "signature_subsumption_break"][0]["includes_implicit_self"] is False


# ------------------------------------------------------------------ effect-account adapter
from hlith.z3_binding import requests_from_account  # noqa: E402


def _account(pre, post, sites, unknown=(), file="src/pkg/m.py"):
    return {
        "modified_callables": [{"qualified_name": "pkg.m.f", "file_path": file, "pre_signature": pre,
                                "post_signature": post, "pre_entry_guards": [], "entry_guards": []}],
        "impacted_call_sites": sites, "unknown_edges": list(unknown), "unexplored_scope": "external callers",
    }


def _asite(file, line=5, n=1):
    return {"caller_qualified_name": "pkg.o.g", "callee_qualified_name": "pkg.m.f", "file_path": file,
            "line_number": line, "arg_structure": {"n_positional": n, "keywords": [], "star_args": False,
                                                   "star_kwargs": False, "arg_literals": {}, "is_method_call": False}}


def test_adapter_one_request_per_modified_callable_and_filters_by_callee():
    acc = _account("(a)", "(a, b)", [_asite("src/pkg/o.py"), {**_asite("src/pkg/o.py"), "callee_qualified_name": "pkg.z"}])
    (r,) = requests_from_account(acc)
    assert r["target_symbol"] == "pkg.m.f" and len(r["call_sites"]) == 1 and r["unexplored_scope"] == "external callers"
    assert derive_obligation(r, analyze(r), None).verdict is Verdict.REFUTED


def test_baseline_site_in_a_file_the_effect_changes_is_not_trusted():
    acc = _account("(a)", "(a, b)", [_asite("src/pkg/m.py")])      # same file as the change: caller may be rewritten
    (r,) = requests_from_account(acc)
    o = derive_obligation(r, analyze(r), None)
    assert o.verdict is Verdict.NOT_DERIVED and "candidate-tree call sites needed" in o.stop_reason


def test_candidate_tree_sites_are_used_when_the_account_supplies_them():
    acc = _account("(a)", "(a, b)", [_asite("src/pkg/m.py")])
    acc["post_call_sites"] = [_asite("src/pkg/m.py", n=2)]        # caller was updated in the same effect
    (r,) = requests_from_account(acc)
    a = analyze(r)
    assert not a["refuted"] and not a["unresolved"]


def test_deleted_callable_is_not_derived():
    (r,) = requests_from_account(_account("(a)", "UNKNOWN", [_asite("src/pkg/o.py")]))
    o = derive_obligation(r, analyze(r), None)
    assert o.verdict is Verdict.NOT_DERIVED and "absent from the candidate tree" in o.stop_reason


def test_new_callable_is_bounded_held_only_with_provenance(tmp_path):
    acc = _account("UNKNOWN", "(a)", [], unknown=[{"reason": "unresolved construct: callable_absent_in_baseline",
                                                    "caller_qualified_name": None}])
    (r,) = requests_from_account(acc)
    assert derive_obligation(r, analyze(r), None).verdict is Verdict.UNVERIFIED
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o = verify_confined(r, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD and "absent from the baseline" in o.evidence.explored


@pytest.mark.real
def test_real_effect_account_end_to_end_when_builder_is_present(tmp_path):
    effect = pytest.importorskip("hlith.effect")
    if not REQ_SRC.is_dir():
        pytest.skip("requests clone missing")
    src = (REQ_SRC / "utils.py").read_text()
    for post_def, expect in (("def get_auth_from_url(url, strict):", Verdict.REFUTED),
                             ("def get_auth_from_url(url, strict=False):", Verdict.HELD)):
        new = tmp_path / "utils_new.py"
        new.write_text(src.replace("def get_auth_from_url(url):", post_def))
        diff = subprocess.run(["diff", "-u", "--label", "a/src/requests/utils.py", "--label", "b/src/requests/utils.py",
                               str(REQ_SRC / "utils.py"), str(new)], capture_output=True, text=True).stdout
        acc = effect.build_effect_account(REQ_ROOT, diff).to_dict()
        prop = tmp_path / "prop"; prop.mkdir(exist_ok=True); (prop / "x").write_text("x")
        scratch = tmp_path / "scr"; scratch.mkdir(exist_ok=True)
        (r,) = [q for q in requests_from_account(acc, touched_files=["src/requests/utils.py"])
                if q["target_symbol"].endswith("get_auth_from_url")]
        o = verify_confined(r, scratch_dir=scratch, proposer_paths=[str(prop)])
        assert o.verdict is expect, o.stop_reason or o.witness


def test_adapter_counts_only_unknown_caller_edges_tagged_to_this_callable():
    acc = _account("(a)", "(a, b=1)", [_asite("src/pkg/o.py")], unknown=[
        {"target_qualified_name": "pkg.m.f", "reason": "unresolved construct: dynamic_getattr", "caller_qualified_name": "x"},
        {"target_qualified_name": "pkg.other", "reason": "unresolved construct: dynamic_getattr", "caller_qualified_name": "y"},
        {"target_qualified_name": "UNKNOWN", "reason": "unresolved construct: dynamic_getattr", "caller_qualified_name": "z"},
        {"target_qualified_name": "pkg.m.f", "reason": "unresolved construct: unsupported_entry_guard", "caller_qualified_name": "pkg.m.f"},
    ])
    (r,) = requests_from_account(acc)
    assert r["unknown_edge_count"] == 1                       # only the dynamic edge tagged to this callable
    assert "1 entry guard(s) of pkg.m.f could not be expressed" in r["unexplored_scope"]


# ------------------------------------------------------------------ zero listed callers
def test_zero_sites_identical_signature_is_held_by_subsumption_with_honest_evidence(tmp_path):
    req = _req("(a, b=1)", [], pre="(a, b=1)", oid="z1")
    a = analyze(req)
    assert not a["unresolved"] and a["zero_sites_covered_by_subsumption"] is True
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD, o.stop_reason
    assert "0 direct call sites in the account" in o.evidence.explored
    assert "subsumption only" in o.evidence.explored
    assert "callers outside the account" in o.evidence.unexplored
    assert o.evidence.executions == 1


def test_zero_sites_compatible_widening_is_held_but_without_provenance_only_unverified():
    req = _req("(a, b=1, c=2)", [], pre="(a, b=1)")
    assert derive_obligation(req, analyze(req), None).verdict is Verdict.UNVERIFIED


@pytest.mark.parametrize("pre,post", [("(a, b=1)", "(a)"), ("(a)", "(a, b)"), ("(a, b)", "(a, /, b)")])
def test_zero_sites_non_subsumed_change_stays_not_derived(pre, post):
    req = _req(post, [], pre=pre)
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.NOT_DERIVED and "zero call sites" in o.stop_reason and "bind pre-change, fail post-change" in o.stop_reason


def test_zero_sites_with_new_entry_guard_stays_not_derived():
    req = _req("(a, b)", [], pre="(a, b)", guards=[{"param": "b", "raises_when": "none"}])
    o = derive_obligation(req, analyze(req), None)
    assert o.verdict is Verdict.NOT_DERIVED and "entry guards changed" in o.stop_reason


def test_zero_sites_unchanged_guard_does_not_block():
    g = [{"param": "b", "raises_when": "none"}]
    req = _req("(a, b)", [], pre="(a, b)", guards=g)
    req["pre_entry_guards"] = g
    assert not analyze(req)["unresolved"]


def test_zero_sites_without_pre_signature_stays_not_derived():
    req = _req("(a)", [])
    assert derive_obligation(req, analyze(req), None).verdict is Verdict.NOT_DERIVED


@needs_requests
def test_real_zero_caller_public_api_identical_signature(tmp_path):
    """requests.utils.from_key_val_list: public API, zero in-repo callers."""
    sig = _sig_text(REQ_SRC / "utils.py", "from_key_val_list")
    assert _call_sites("from_key_val_list") == []   # premise: no in-repo caller in src/requests
    req = _req(sig, [], pre=sig, oid="kv")
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o = verify_confined(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD and "0 direct call sites" in o.evidence.explored


# ------------------------------------------------ pre-failing shapes are not regressions (review 482f5c4)
def test_pre_failing_call_is_not_refuted_neutral_change(tmp_path):
    # Neutral change: only a default value changes. One caller already passed too few args BEFORE the change.
    req = _req("(a, b=2)", [_site(0)], pre="(a, b=1)")
    an = analyze(req)
    assert an["refuted"] == [] and len(an["pre_failing"]) == 1
    assert an["pre_failing"][0]["pre_errors"] == ["missing:a"]
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o, _ = verify_confined_detailed(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD and "already failed to bind BEFORE" in o.evidence.unexplored


def test_pre_failing_does_not_mask_a_real_regression():
    req = _req("(a, b)", [_site(0), _site(1, line=20)], pre="(a, b=1)")
    an = analyze(req)
    assert len(an["pre_failing"]) == 1 and an["pre_failing"][0]["where"].endswith(":10")
    assert [r["where"] for r in an["refuted"]] == ["m.py:20"] and an["refuted"][0]["pre_change"] == "binds"
    assert derive_obligation(req, an, None).verdict is Verdict.REFUTED


def test_pre_failing_guard_is_excluded_but_new_guard_hit_is_refuted():
    g = {"param": "a", "raises_when": "none"}
    site = _site(1, lits={"a": "None"})
    already = {**_req("(a)", [site], pre="(a)", guards=[g]), "pre_entry_guards": [g]}
    assert analyze(already)["refuted"] == [] and len(analyze(already)["pre_failing"]) == 1
    fresh = _req("(a)", [site], pre="(a)", guards=[g])  # guard is new in the change
    assert len(analyze(fresh)["refuted"]) == 1


def test_failing_site_without_pre_signature_is_not_asserted_as_regression():
    req = _req("(a, b)", [_site(1)], pre=None)
    an = analyze(req)
    assert an["refuted"] == [] and an["unresolved"]
    assert derive_obligation(req, an, None).verdict is Verdict.NOT_DERIVED


def test_all_sites_pre_failing_evidence_does_not_claim_zero_checked_sites(tmp_path):
    req = _req("(a, b=2)", [_site(0)], pre="(a, b=1)")
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    o, _ = verify_confined_detailed(req, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD
    assert "0 direct call sites" not in o.evidence.explored and "already failed to bind before" in o.evidence.explored


# ------------------------------------------------ added callables: post-only binding (review ae31e43)
def _added_account(post="(a, b=1)", sites=(), extra=None, modified=()):
    rec = {"qualified_name": "pkg.g", "module": "pkg", "file_path": "pkg.py", "post_signature": post,
           "provenance": {}, "post_call_sites": list(sites), "reached_from": [], "entry_guards": [],
           "unknown_edges": [], "unexplored_scope": ""}
    rec.update(extra or {})
    return {"modified_callables": list(modified), "added_callables": [rec], "impacted_call_sites": [],
            "post_call_sites": []}


def _added_run(account, tmp_path):
    reqs = requests_from_account(account)
    prop = tmp_path / "p"; prop.mkdir(exist_ok=True); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir(exist_ok=True)
    return [verify_confined_detailed(r, scratch_dir=scratch, proposer_paths=[str(prop)]) for r in reqs]


def test_added_valid_caller_is_held_post_only(tmp_path):
    (o, an), = _added_run(_added_account(sites=[_site(1)]), tmp_path)
    assert o.verdict is Verdict.HELD and an["added"] and "no pre-change signature exists" in o.evidence.explored


def test_added_failing_site_is_refuted_with_witness(tmp_path):
    (o, an), = _added_run(_added_account(sites=[_site(0, line=7)]), tmp_path)
    assert o.verdict is Verdict.REFUTED and "m.py:7" in o.witness and "missing:a" in o.witness
    assert an["refuted"][0]["pre_change"].startswith("n/a") and an["witness_inputs"]


def test_added_zero_post_sites_is_blocking_not_derived_never_held(tmp_path):
    (o, an), = _added_run(_added_account(sites=[]), tmp_path)
    assert o.verdict is Verdict.NOT_DERIVED and "unexplored: no caller reaches the added callable" in o.stop_reason


def test_added_star_args_site_is_not_derived(tmp_path):
    (o, _), = _added_run(_added_account(sites=[_site(1, star=True)]), tmp_path)
    assert o.verdict is Verdict.NOT_DERIVED and "*args" in o.stop_reason


def test_added_unknown_edge_blocks(tmp_path):
    acct = _added_account(sites=[_site(1)], extra={"unknown_edges": [{"reason": "x"}]})
    (o, _), = _added_run(acct, tmp_path)
    assert o.verdict is Verdict.NOT_DERIVED and "unknown call edge" in o.stop_reason


def test_added_wins_over_modified_entry_for_same_symbol():
    mod = {"qualified_name": "pkg.g", "file_path": "pkg.py", "pre_signature": "UNKNOWN", "post_signature": "(a)",
           "entry_guards": [], "pre_entry_guards": []}
    reqs = requests_from_account(_added_account(sites=[_site(1)], modified=[mod]))
    assert len(reqs) == 1 and reqs[0]["added"] is True


def test_requests_stay_index_aligned_with_modified_callables():
    # derive.py zips acct.modified_callables with these requests by index: added entries must not shift them.
    def mod(q):
        return {"qualified_name": q, "file_path": "pkg.py", "pre_signature": "(a)", "post_signature": "(a)",
                "entry_guards": [], "pre_entry_guards": []}
    acct = _added_account(sites=[_site(1)], modified=[mod("pkg.m1"), mod("pkg.g"), mod("pkg.m2")])
    reqs = requests_from_account(acct)
    assert [r["target_symbol"] for r in reqs] == ["pkg.m1", "pkg.g", "pkg.m2"]
    assert [bool(r.get("added")) for r in reqs] == [False, True, False]
    solo = requests_from_account(_added_account(sites=[_site(1)], modified=[mod("pkg.m1")]))
    assert [r["target_symbol"] for r in solo] == ["pkg.m1", "pkg.g"]  # added-only records go last


# ------------------------------------------------ contains_literal guards (review shape, O3-A)
_CG = {"param": "a", "raises_when": "contains_literal", "literal": "\0", "raised_exception": "builtins.ValueError",
       "condition_source": '"\\\\0" in a', "condition_sha256": "0" * 64, "file_path": "m.py", "line_number": 3,
       "node_id": "n1"}


def test_contains_literal_guard_new_in_change_refutes_a_literal_that_trips_it():
    # the guard is NEW (absent from pre_entry_guards): a call whose literal argument contains it now raises
    req = {**_req("(a)", [_site(1, lits={"a": repr("x\0y")})], pre="(a)", guards=[_CG]), "pre_entry_guards": []}
    an = analyze(req)
    assert [r["errors"] for r in an["refuted"]] == [["guard:a:contains_literal"]]


def test_contains_literal_guard_does_not_trip_other_literals_or_unknown_values():
    for lits in ({"a": repr("plain")}, {"a": "None"}, {}):
        req = {**_req("(a)", [_site(1, lits=lits)], pre="(a)", guards=[_CG]), "pre_entry_guards": []}
        assert analyze(req)["refuted"] == [], lits


def test_contains_literal_guard_present_pre_change_is_pre_failing_not_refuted():
    req = {**_req("(a)", [_site(1, lits={"a": repr("x\0y")})], pre="(a)", guards=[_CG]), "pre_entry_guards": [_CG]}
    an = analyze(req)
    assert an["refuted"] == [] and len(an["pre_failing"]) == 1


def test_guards_changed_keys_on_literal_and_exception_not_provenance():
    import hlith.z3_binding as z3_binding

    same = {**_CG, "line_number": 99, "node_id": "other"}
    other_lit = {**_CG, "literal": "\t"}
    assert not z3_binding._guards_changed({"entry_guards": [same], "pre_entry_guards": [_CG]})
    assert z3_binding._guards_changed({"entry_guards": [other_lit], "pre_entry_guards": [_CG]})


# ------------------------------------------------ finding-24 class: no special file in any granted path
def _clean_req():
    return _req("(a)", [_site(1)], pre="(a)")


def _scratch_with(tmp_path, kind):
    import socket

    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    scratch = tmp_path / "s"; scratch.mkdir()
    if kind == "fifo":
        os.mkfifo(scratch / "chan")
    elif kind == "socket":
        sk = socket.socket(socket.AF_UNIX); sk.bind(str(scratch / "sock")); sk.close()
    return prop, scratch


@pytest.mark.parametrize("kind", ["fifo", "socket"])
def test_special_file_in_scratch_fails_closed_unverified(tmp_path, kind):
    prop, scratch = _scratch_with(tmp_path, kind)
    o, an = verify_confined_detailed(_clean_req(), scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.UNVERIFIED and "special file" in o.stop_reason and an == {}
    assert o.provenance is None  # no confined run happened, so no provenance is claimed


def test_clean_scratch_still_verifies(tmp_path):
    prop, scratch = _scratch_with(tmp_path, None)
    o, _ = verify_confined_detailed(_clean_req(), scratch_dir=scratch, proposer_paths=[str(prop)])
    assert o.verdict is Verdict.HELD


def test_opaque_caller_guard_note_is_present_on_held_and_conservative_refusal(tmp_path):
    clean = {**_clean_req(), "opaque_caller_guard_count": 2, "opaque_caller_guard_callers": ["pkg.use"]}
    prop, scratch = _scratch_with(tmp_path, None)
    held, _ = verify_confined_detailed(clean, scratch_dir=scratch, proposer_paths=[str(prop)])
    assert held.verdict is Verdict.HELD
    assert "predicates of 2 caller guard(s) are not modelled" in held.evidence.unexplored
    assert "checked regardless of both guard polarities" in held.evidence.unexplored

    changed = {
        **_req("(a, b)", [_site(1, line=17)], pre="(a)"),
        "opaque_caller_guard_count": 1,
        "opaque_caller_guard_callers": ["pkg.use"],
    }
    # A site that might be unreachable under its opaque caller predicate is still checked.
    changed["call_sites"][0]["caller_qualified_name"] = "pkg.use"
    refused = derive_obligation(changed, analyze(changed), None)
    assert refused.verdict is Verdict.REFUTED
    assert "guard is not modelled" in refused.witness
    assert "may be unreachable" in refused.witness


def test_requests_from_account_adds_opaque_guard_count_without_changing_binding_keys(tmp_path):
    from hlith.z3_binding import return_shape_requests_from_account

    mod = {"qualified_name": "pkg.target", "file_path": "pkg.py", "pre_signature": "(a)",
           "post_signature": "(a)", "entry_guards": [], "pre_entry_guards": []}
    site = _site(1)
    site.update({"callee_qualified_name": "pkg.target", "caller_qualified_name": "pkg.use"})
    opaque = {"caller_qualified_name": "pkg.use", "node_id": "guard-1", "side": "both"}
    account = {"modified_callables": [mod], "added_callables": [], "post_call_sites": [site],
               "impacted_call_sites": [site], "unknown_edges": [], "unexplored_scope": "",
               "opaque_caller_guards": [opaque]}
    (request,) = requests_from_account(account)
    assert request["opaque_caller_guard_count"] == 1
    assert request["opaque_caller_guard_callers"] == ["pkg.use"]
    assert {"call_sites", "stale_sites", "unknown_edge_count", "unexplored_scope"} <= request.keys()
    (return_request,) = return_shape_requests_from_account({
        "modified_callables": [{**mod,
                                 "pre_return_shapes": [{"kind": "container", "container_kind": "tuple", "length": 2, "source": "(1, 2)"}],
                                 "post_return_shapes": [{"kind": "container", "container_kind": "tuple", "length": 1, "source": "(1,)"}]}],
        "post_call_sites": [site], "impacted_call_sites": [site], "unknown_edges": [], "unexplored_scope": "",
        "opaque_caller_guards": [opaque],
    }, tmp_path)
    assert "opaque_caller_guard_count" not in return_request


# ------------------------------------------------ comparison / isinstance / truthiness guards (review shape)
_VALUES = ["0", "1", "-1", "3", "2", "-3", "340282366920938463463374607431768211456", "True", "False", "None", "0.0",
           "1.5", "''", "'abc'", "'3'", "'x\\0y'", "b''", "b'a'", "[]", "[1]", "()", "(1, 2)", "{}", "{'a': 1}", "{1, 2}", "'é'"]
_GUARDS = (
    [{"raises_when": w} for w in ("none", "empty", "falsy", "truthy")]
    + [{"raises_when": "compare", "operator": op, "literal": lit}
       for op in ("<", "<=", ">", ">=", "==", "!=") for lit in ("3", "-1", "0", "'abc'", "340282366920938463463374607431768211456")]
    + [{"raises_when": "isinstance", "type": t, "negated": n} for t in (["builtins.int"], ["builtins.str"], ["builtins.bool"],
       ["builtins.int", "builtins.float"], ["builtins.NoneType"], ["builtins.list", "builtins.tuple"], ["builtins.dict"],
       ["builtins.bytes"]) for n in (False, True)]
    + [{"raises_when": "contains_literal", "literal": lit} for lit in ("\0", "a", "")]
)
_COND = {
    "none": "p is None", "truthy": "bool(p)", "falsy": "not p",
    "empty": "p is None or (isinstance(p, (str, bytes, list, tuple, dict, set)) and len(p) == 0)",
}


def _real_trips(g: dict, value) -> bool:
    w = g["raises_when"]
    if w == "compare":
        cond = f"p {g['operator']} {g['literal']}"
    elif w == "isinstance":
        names = ", ".join(t.split(".")[1] if t != "builtins.NoneType" else "type(None)" for t in g["type"])
        cond = f"{'not ' if g['negated'] else ''}isinstance(p, ({names},))"
    elif w == "contains_literal":
        cond = f"{g['literal']!r} in p"
    else:
        cond = _COND[w]
    ns: dict = {}
    exec(f"def f(p):\n    if {cond}:\n        raise ValueError\n", ns)  # noqa: S102 - fixture
    try:
        ns["f"](value)
    except ValueError:
        return True
    except TypeError:
        return None  # e.g. 'abc' < 3: the real guard itself errors; no decision claimed
    return False


def test_guard_encoding_equals_real_python_execution():
    import ast as _ast

    from hlith.z3_binding import _guard, _guard_trips

    decided = skipped = 0
    for g in _GUARDS:
        gd = {"param": "p", "raised_exception": "builtins.ValueError", **g}
        for text in _VALUES:
            trips = _guard_trips(_guard(gd), text)
            real = _real_trips(g, _ast.literal_eval(text))
            if trips is None or real is None:
                skipped += 1
                continue
            import z3
            s = z3.Solver(); s.add(trips)
            assert (s.check() == z3.sat) == real, (g, text, real)
            decided += 1
    assert decided > 600 and skipped > 0  # 713 pairs decided by both sides, the rest declined by either, none guessed


def test_new_guard_variants_not_decided_when_unsupported():
    from hlith.z3_binding import _guard, _guard_trips

    g = lambda **k: _guard({"param": "p", "raised_exception": "builtins.ValueError", **k})  # noqa: E731
    assert _guard_trips(g(raises_when="compare", operator="<", literal="3"), "True") is None  # bool operand: declined
    assert _guard_trips(g(raises_when="compare", operator="<", literal="3"), "1.5") is None  # float: declined
    assert _guard_trips(g(raises_when="compare", operator="<", literal="'a'"), "'b'") is None  # str ordering declined
    assert _guard_trips(g(raises_when="isinstance", type=["pkg.Custom"]), "1") is None  # non-builtin type
    assert _guard_trips(g(raises_when="isinstance", type=["builtins.int"]), "some_name") is None  # not a literal
    assert _guard_trips(g(raises_when="compare", operator="~", literal="3"), "1") is None


def test_guard_key_covers_operator_type_negated_and_not_provenance():
    from hlith.z3_binding import _guards_changed

    base = {"param": "p", "raises_when": "compare", "operator": "<", "literal": "3", "raised_exception": "builtins.ValueError"}
    same = {**base, "line_number": 9, "node_id": "other", "provenance": {"x": 1}}
    assert not _guards_changed({"entry_guards": [same], "pre_entry_guards": [base]})
    assert _guards_changed({"entry_guards": [{**base, "operator": "<="}], "pre_entry_guards": [base]})
    iso = {"param": "p", "raises_when": "isinstance", "type": ["builtins.int"], "negated": False, "raised_exception": "builtins.TypeError"}
    assert _guards_changed({"entry_guards": [{**iso, "negated": True}], "pre_entry_guards": [iso]})
    assert _guards_changed({"entry_guards": [{**iso, "type": ["builtins.str"]}], "pre_entry_guards": [iso]})
    assert not _guards_changed({"entry_guards": [dict(iso, type="builtins.int")], "pre_entry_guards": [iso | {"type": ["builtins.int"]}]})


def test_compare_guard_new_in_change_refutes_a_tripping_literal_call():
    g = {"param": "a", "raises_when": "compare", "operator": "<", "literal": "0", "raised_exception": "builtins.ValueError"}
    hit = {**_req("(a)", [_site(1, lits={"a": "-5"})], pre="(a)", guards=[g]), "pre_entry_guards": []}
    assert [r["errors"] for r in analyze(hit)["refuted"]] == [["guard:a:compare"]]
    miss = {**_req("(a)", [_site(1, lits={"a": "5"})], pre="(a)", guards=[g]), "pre_entry_guards": []}
    assert analyze(miss)["refuted"] == []
    already = {**hit, "pre_entry_guards": [g]}  # the same guard existed before: a pre-failing call, not a regression
    assert analyze(already)["refuted"] == [] and len(analyze(already)["pre_failing"]) == 1
