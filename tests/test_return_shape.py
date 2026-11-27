# SPDX-License-Identifier: Apache-2.0
"""Z3 return-shape check: a changed return shape must still fit what each listed caller does with the result.

Sound bounded modelling: a shape the account cannot pin to an arity, an opaque consumer, or an unlisted
caller set is NOT_DERIVED (explicit UNMODELED), never HELD.
"""
import hashlib
import subprocess

import pytest

from hlith import effect, z3_binding
from hlith.types import Verdict


def shape(kind="container", container_kind="tuple", length=2, source=None, line=6, literal=None):
    if source is None:
        source = "(" + ", ".join(f"v{i}" for i in range(length or 0)) + ("," if length == 1 else "") + ")"
    return {"kind": kind, "container_kind": container_kind, "length": length, "source": source,
            "line_number": line, "file_path": "pkg/stats.py", "literal_value": literal, "resolution": "resolved"}


def _local_binding_shape(length, source="auth", **overrides):
    def assignment(arity, line):
        values = [f"v{i}" for i in range(arity)]
        assignment_source = "(" + ", ".join(values) + ("," if arity == 1 else "") + ")"
        return {
            "analysis_pass": "return_shape_local_tuple_binding",
            "resolution": "resolved",
            "source_file": "pkg/stats.py",
            "source_line": line,
            "node_sha256": hashlib.sha256(assignment_source.encode("utf-8")).hexdigest(),
            "assignment_source": assignment_source,
            "container_kind": "tuple",
            "length": arity,
        }

    assignment_lengths = overrides.pop("assignment_lengths", (length, length))
    assignments = overrides.pop(
        "assignments",
        [assignment(arity, line) for line, arity in zip((10, 12), assignment_lengths)],
    )
    local = {
        "resolution": "resolved",
        "assignment_scope": "pre_return_expression",
        "assignment_scan_complete": True,
        "all_assignments_resolved": True,
        "all_assignments_same_tuple_shape": True,
        "all_normal_return_paths_use_scanned_local_assignment": True,
        "no_other_rebindings": True,
        "no_starred_tuple_assignments": True,
        "no_tuple_mutations": True,
        "no_opaque_assignment_or_dynamic_local_access": True,
        "container_kind": "tuple",
        "length": length,
        "assignments": assignments,
    }
    local.update(overrides)
    return {
        "kind": "container",
        "container_kind": "tuple",
        "length": length,
        "source": source,
        "line_number": 20,
        "file_path": "pkg/stats.py",
        "resolution": "resolved",
        "provenance": {
            "analysis_pass": "return_shape_inference",
            "resolution": "resolved",
            "source_file": "pkg/stats.py",
            "source_line": 20,
            "node_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "local_binding_provenance": local,
        },
    }


NONE = shape("none", None, None, "")


def site(demand, where="pkg/use.py:5", callee="pkg.stats.Window.bounds"):
    return {"where": where, "caller": "pkg.use.span", "callee": callee, "demand": demand}


def req(pre, post, sites, **kw):
    return {"kind": "return_shape", "obligation_id": "return_shape:pkg.stats.Window.bounds",
            "target_symbol": "pkg.stats.Window.bounds", "pre_shapes": pre, "post_shapes": post,
            "sites": sites, "unknown_edge_count": 0, "unexplored_scope": "", "returns_wrapped": False, **kw}


UNPACK2 = {"kind": "unpack", "n": 2, "star": False}


# ------------------------------------------------------------------ consumer facts from caller source
@pytest.mark.parametrize("src,node,want", [
    ("def f(x):\n    lo, hi = w.bounds()\n", "w.bounds()", {"kind": "unpack", "n": 2, "star": False}),
    ("def f(x):\n    [a, b, c] = w.bounds()\n", "w.bounds()", {"kind": "unpack", "n": 3, "star": False}),
    ("def f(x):\n    a, *rest = w.bounds()\n", "w.bounds()", {"kind": "unpack", "n": 1, "star": True}),
    ("def f(x):\n    return w.bounds()[1]\n", "w.bounds()", {"kind": "index", "k": 1}),
    ("def f(x):\n    return w.bounds()[-2]\n", "w.bounds()", {"kind": "index", "k": -2}),
    ("def f(x):\n    w.bounds()\n", "w.bounds()", {"kind": "discard"}),
])
def test_consumer_demand_shapes(src, node, want):
    line = 2
    assert z3_binding.consumer_demand(src, line, node) == want


@pytest.mark.parametrize("src", [
    "def f(x):\n    r = w.bounds()\n    return r\n",        # result kept whole: later use unknown
    "def f(x):\n    return g(w.bounds())\n",                # passed on
    "def f(x):\n    for a, b in w.bounds():\n        pass\n",  # iteration of the result
    "def f(x):\n    return w.bounds()[x]\n",                # non-literal index
    "def f(x):\n    a, b = w.bounds() or (0, 0)\n",        # call is not the whole right side
])
def test_consumer_demand_opaque(src):
    d = z3_binding.consumer_demand(src, 2, "w.bounds()")
    assert d["kind"] == "opaque", d


def test_consumer_demand_missing_call_is_opaque():
    assert z3_binding.consumer_demand("def f():\n    pass\n", 2, "w.bounds()")["kind"] == "opaque"


# ------------------------------------------------------------------ the Z3 check
def test_arity_change_breaks_unpacking_caller():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], [site(UNPACK2)]))
    assert [r["where"] for r in a["refuted"]] == ["pkg/use.py:5"]
    assert not a["unresolved"]
    ob = z3_binding.derive_obligation(req([shape(length=2)], [shape(length=3)], [site(UNPACK2)]), a, None)
    assert ob.verdict is Verdict.REFUTED and "pkg/use.py:5" in ob.witness and "3" in ob.witness


def test_none_return_breaks_unpacking_caller():
    a = z3_binding.analyze(req([shape(length=2)], [NONE], [site(UNPACK2)]))
    assert len(a["refuted"]) == 1


def test_index_out_of_range_refuted():
    a = z3_binding.analyze(req([shape(length=3)], [shape(length=2)], [site({"kind": "index", "k": 2})]))
    assert len(a["refuted"]) == 1
    a = z3_binding.analyze(req([shape(length=3)], [shape(length=2)], [site({"kind": "index", "k": -2})]))
    assert not a["refuted"] and len(a["clean"]) == 1


def test_starred_unpack_accepts_longer():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], [site({"kind": "unpack", "n": 1, "star": True})]))
    assert not a["refuted"] and len(a["clean"]) == 1


def test_pre_failing_site_is_not_blamed():
    a = z3_binding.analyze(req([shape(length=3)], [shape(length=4)], [site(UNPACK2)]))
    assert not a["refuted"] and len(a["pre_failing"]) == 1


def test_no_listed_callers_is_unresolved():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], []))
    assert a["unresolved"] and not a["refuted"]
    ob = z3_binding.derive_obligation(req([shape(length=2)], [shape(length=3)], []), a, None)
    assert ob.verdict is Verdict.NOT_DERIVED


def test_unknown_post_shape_is_unresolved_not_held():
    a = z3_binding.analyze(req([shape(length=2)], [shape("call", None, None, "g()")], [site(UNPACK2)]))
    assert a["unresolved"] and not a["clean"] and not a["refuted"]


def test_one_violating_path_of_two_is_unresolved_not_refuted():
    # a returning path may be unreachable: refute only when EVERY post path violates
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=2), shape(length=3)], [site(UNPACK2)]))
    assert not a["refuted"] and a["unresolved"]


def test_opaque_consumer_unresolved():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], [site({"kind": "opaque", "why": "kept whole"})]))
    assert a["unresolved"] and not a["refuted"]


def test_discarded_result_is_clean():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], [site({"kind": "discard"})]))
    assert len(a["clean"]) == 1 and not a["unresolved"]


def test_wrapped_return_is_unresolved():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=3)], [site(UNPACK2)], returns_wrapped=True))
    assert a["unresolved"] and not a["refuted"]


def test_unknown_edges_unresolved():
    a = z3_binding.analyze(req([shape(length=2)], [shape(length=2)], [site(UNPACK2)], unknown_edge_count=1))
    assert a["unresolved"]


def test_all_sites_fit_is_held_with_provenance():
    from hlith.types import CheckProvenance
    r = req([shape(length=2)], [shape(length=2)], [site(UNPACK2)])
    a = z3_binding.analyze(r)
    prov = CheckProvenance("z3", "0" * 64, True, False, "1" * 64, 0)
    ob = z3_binding.derive_obligation(r, a, prov)
    assert ob.verdict is Verdict.HELD and "callers outside the account" in ob.evidence.unexplored
    assert z3_binding.derive_obligation(r, a, None).verdict is Verdict.UNVERIFIED


def test_local_tuple_binding_provenance_survives_adapter_and_refutes_unpack(tmp_path):
    d = _repo(tmp_path, "def span(xs):\n    lo, hi = Window.bounds(Window(xs))\n    return hi - lo\n")
    ad, _ = _requests(d)
    changed = next(
        item for item in ad["modified_callables"]
        if item["qualified_name"] == "pkg.stats.Window.bounds"
    )
    changed["pre_return_shapes"] = [_local_binding_shape(2)]
    changed["post_return_shapes"] = [_local_binding_shape(3)]

    (request,) = z3_binding.return_shape_requests_from_account(ad, tmp_path / "post")
    assert request["pre_shapes"][0]["provenance"]["local_binding_provenance"] ==\
        changed["pre_return_shapes"][0]["provenance"]["local_binding_provenance"]
    assert request["post_shapes"][0]["provenance"]["local_binding_provenance"] ==\
        changed["post_return_shapes"][0]["provenance"]["local_binding_provenance"]
    analysis = z3_binding.analyze(request)
    assert [item["where"] for item in analysis["refuted"]] == ["pkg/use.py:5"]
    assert not analysis["unresolved"]


@pytest.mark.parametrize("case", [
    "different-branch-arity",
    "reassignment-after-tuple",
    "call-result-return",
    "missing-evidence",
    "missing-assignment-scope",
    "assignment-source-missing",
    "assignment-hash-mismatch",
    "assignment-kind-mismatch",
    "assignment-length-mismatch",
    "starred-tuple",
    "tuple-mutation",
    "opaque-assignment",
])
def test_unverified_local_tuple_provenance_stays_unresolved(case):
    overrides = {}
    source = "auth"
    if case == "different-branch-arity":
        overrides["assignments"] = [
            _local_binding_shape(3)["provenance"]["local_binding_provenance"]["assignments"][0],
            _local_binding_shape(2)["provenance"]["local_binding_provenance"]["assignments"][1],
        ]
    elif case == "reassignment-after-tuple":
        overrides["no_other_rebindings"] = False
    elif case == "call-result-return":
        source = "get_auth_from_url()"
    elif case == "assignment-hash-mismatch":
        assignments = _local_binding_shape(3)["provenance"]["local_binding_provenance"]["assignments"]
        assignments[0]["node_sha256"] = "0" * 64
        overrides["assignments"] = assignments
    elif case == "assignment-kind-mismatch":
        assignments = _local_binding_shape(3)["provenance"]["local_binding_provenance"]["assignments"]
        assignments[0]["container_kind"] = "list"
        overrides["assignments"] = assignments
    elif case == "assignment-length-mismatch":
        assignments = _local_binding_shape(3)["provenance"]["local_binding_provenance"]["assignments"]
        assignments[0]["length"] = 2
        overrides["assignments"] = assignments
    elif case == "starred-tuple":
        overrides["no_starred_tuple_assignments"] = False
    elif case == "tuple-mutation":
        overrides["no_tuple_mutations"] = False
    elif case == "opaque-assignment":
        overrides["no_opaque_assignment_or_dynamic_local_access"] = False

    bad_post = _local_binding_shape(3, source=source, **overrides)
    if case == "missing-evidence":
        bad_post.pop("provenance")
    elif case == "missing-assignment-scope":
        bad_post["provenance"]["local_binding_provenance"].pop("assignment_scope")
    elif case == "assignment-source-missing":
        bad_post["provenance"]["local_binding_provenance"]["assignments"][0]["assignment_source"] = ""
    request = req([_local_binding_shape(2)], [bad_post], [site(UNPACK2)])
    analysis = z3_binding.analyze(request)
    assert analysis["unresolved"]
    assert not analysis["refuted"]
    assert z3_binding.derive_obligation(request, analysis, None).verdict is Verdict.NOT_DERIVED


# ------------------------------------------------------------------ adapter on a real account
def _git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)


def _repo(tmp_path, use_body, stats_extra=""):
    d = tmp_path / "r"
    d.mkdir()
    _git(d, "init", "-q"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")
    (d / "pkg").mkdir()
    (d / "pkg/__init__.py").write_text("")
    (d / "pkg/stats.py").write_text(
        "class Window:\n    def __init__(self, xs):\n        self.xs = xs\n\n"
        "    def bounds(self):\n        return (min(self.xs), max(self.xs))\n" + stats_extra)
    (d / "pkg/use.py").write_text("from pkg.stats import Window\n\n\n" + use_body)
    _git(d, "add", "-A"); _git(d, "commit", "-q", "-m", "b")
    return d


OLD_RET = "        return (min(self.xs), max(self.xs))\n"
NEW_RET = "        return (min(self.xs), max(self.xs), sum(self.xs) / len(self.xs))\n"


def _patch(d, new=NEW_RET):
    f = d / "pkg/stats.py"
    base = f.read_text()
    f.write_text(base.replace(OLD_RET, new))
    diff = subprocess.run(["git", "-C", str(d), "diff"], check=True, capture_output=True, text=True).stdout
    f.write_text(base)
    return diff


def _requests(d):
    patch = _patch(d)
    acct = effect.build_effect_account(d, patch)
    ad = acct.to_dict()
    post = d.parent / "post"
    subprocess.run(["git", "-C", str(d), "worktree", "add", "-q", "--detach", str(post)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(post), "apply", "-"], input=patch.encode(), check=True, capture_output=True)
    return ad, z3_binding.return_shape_requests_from_account(ad, post)


def test_adapter_unbound_method_caller_gets_unpack_demand(tmp_path):
    d = _repo(tmp_path, "def span(xs):\n    lo, hi = Window.bounds(Window(xs))\n    return hi - lo\n")
    ad, reqs = _requests(d)
    assert len(reqs) == 1
    r = reqs[0]
    assert r["kind"] == "return_shape" and r["obligation_id"] == "return_shape:pkg.stats.Window.bounds"
    assert [s["demand"] for s in r["sites"]] == [UNPACK2]
    a = z3_binding.analyze(r)
    assert [x["where"] for x in a["refuted"]] == ["pkg/use.py:5"]


def test_adapter_instance_caller_is_listed_and_refuted(tmp_path):
    # review (68b9918) resolves `w = Window(xs); w.bounds()`: the arity change must now be REFUTED at that exact site
    d = _repo(tmp_path, "def span(xs):\n    w = Window(xs)\n    lo, hi = w.bounds()\n    return hi - lo\n")
    ad, reqs = _requests(d)
    assert reqs and [s["where"] for s in reqs[0]["sites"]] == ["pkg/use.py:6"]
    assert [s["demand"] for s in reqs[0]["sites"]] == [UNPACK2]
    an = z3_binding.analyze(reqs[0])
    assert [r["where"] for r in an["refuted"]] == ["pkg/use.py:6"]
    ob = z3_binding.derive_obligation(reqs[0], an, None)
    assert ob.verdict is Verdict.REFUTED and "pkg/use.py:6" in ob.witness


def test_adapter_unresolvable_receiver_is_not_derived(tmp_path):
    # a receiver no rule resolves: the account must flag it (unknown edge) or list nothing; never HELD
    d = _repo(tmp_path, "def span(thing):\n    lo, hi = thing.bounds()\n    return hi - lo\n")
    ad, reqs = _requests(d)
    assert reqs
    an = z3_binding.analyze(reqs[0])
    ob = z3_binding.derive_obligation(reqs[0], an, None)
    assert ob.verdict is Verdict.NOT_DERIVED, (ob.verdict, reqs[0]["sites"], reqs[0]["unknown_edge_count"])


def test_adapter_same_class_method_caller(tmp_path):
    d = _repo(tmp_path, "pass\n", stats_extra="\n    def spread(self):\n        lo, hi = self.bounds()\n        return hi - lo\n")
    ad, reqs = _requests(d)
    r = reqs[0]
    if r["sites"]:  # when review lists the self.bounds() caller, the check must refute it
        assert [s["demand"] for s in r["sites"]] == [UNPACK2]
        assert z3_binding.analyze(r)["refuted"]
    else:
        assert z3_binding.derive_obligation(r, z3_binding.analyze(r), None).verdict is Verdict.NOT_DERIVED


def test_unchanged_shapes_make_no_request(tmp_path):
    d = _repo(tmp_path, "def span(xs):\n    lo, hi = Window.bounds(Window(xs))\n    return hi - lo\n")
    ad = effect.build_effect_account(d, _patch(d, "        return (max(self.xs), min(self.xs))\n")).to_dict()
    assert ad["modified_callables"]
    assert z3_binding.return_shape_requests_from_account(ad, d) == []


def test_neutral_refactor_with_unpinned_shapes_makes_no_request(tmp_path):
    """`return helper(x)` -> `y = helper(x); return y`: both sides' arity is undecided, so nothing is known to have
    changed; a request here would refuse every temp-variable refactor (the differential owns behaviour)."""
    d = tmp_path / "r"
    d.mkdir()
    _git(d, "init", "-q"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")
    (d / "m.py").write_text("def helper(x):\n    return x\n\n\ndef f(x):\n    return helper(x)\n")
    _git(d, "add", "-A"); _git(d, "commit", "-q", "-m", "b")
    (d / "m.py").write_text("def helper(x):\n    return x\n\n\ndef f(x):\n    y = helper(x)\n    return y\n")
    diff = subprocess.run(["git", "-C", str(d), "diff"], check=True, capture_output=True, text=True).stdout
    _git(d, "checkout", "-q", "m.py")
    ad = effect.build_effect_account(d, diff).to_dict()
    assert ad["modified_callables"]
    assert z3_binding.return_shape_requests_from_account(ad, d) == []


def test_arity_key_distinguishes_decided_from_unknown():
    a = [shape(length=2)]
    b = [shape("call", None, None, "g()")]
    assert z3_binding._arity_key(a) != z3_binding._arity_key(b)
    c = [shape("name", None, None, "y")]
    assert z3_binding._arity_key(b) == z3_binding._arity_key(c)  # unknown vs unknown: nothing decided changed


# ---------------------------------------------------------------- undecided shapes must not block without evidence of a change
def _mini(tmp_path, old, new, caller="def use(u):\n    a, b = f(u)\n    return a\n"):
    d = tmp_path / "r"
    d.mkdir(parents=True)
    _git(d, "init", "-q"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")
    (d / "m.py").write_text(old)
    (d / "c.py").write_text("from m import f\n\n\n" + caller)
    _git(d, "add", "-A"); _git(d, "commit", "-q", "-m", "b")
    (d / "m.py").write_text(new)
    diff = subprocess.run(["git", "-C", str(d), "diff"], check=True, capture_output=True, text=True).stdout
    _git(d, "checkout", "-q", "m.py")
    ad = effect.build_effect_account(d, diff).to_dict()
    post = tmp_path / "post"
    subprocess.run(["git", "-C", str(d), "worktree", "add", "-q", "--detach", str(post)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(post), "apply", "-"], input=diff.encode(), check=True, capture_output=True)
    return z3_binding.return_shape_requests_from_account(ad, post)


GAU_OLD = ("def f(u):\n    p = parse(u)\n    try:\n        auth = (p.a, p.b)\n    except AttributeError:\n"
           "        auth = ('', '')\n    return auth\n")
GAU_EARLY = ("def f(u):\n    if u == '':\n        return (None, None)\n    p = parse(u)\n    try:\n        auth = (p.a, p.b)\n"
             "    except AttributeError:\n        auth = ('', '')\n    return auth\n")


def test_early_return_of_the_consumed_arity_over_an_undecided_local_is_no_request(tmp_path):
    """review's requests cases: pre `return auth` (undecided), post adds `return (None, None)` (arity 2) + `return auth`.
    The caller unpacks 2: nothing decided is violated, and undecided-vs-undecided is no evidence of a change."""
    assert _mini(tmp_path, GAU_OLD, GAU_EARLY) == []


def test_local_then_return_and_try_except_refactors_are_no_request(tmp_path):
    old = "def f(u):\n    return g(u)\n"
    assert _mini(tmp_path / "a", old, "def f(u):\n    r = g(u)\n    return r\n") == []
    new_try = "def f(u):\n    try:\n        r = g(u)\n    except ValueError:\n        raise\n    return r\n"
    assert _mini(tmp_path / "b", old, new_try) == []
    new_early = "def f(u):\n    if not u:\n        return g(0)\n    return g(u)\n"
    assert _mini(tmp_path / "c", old, new_early) == []


def test_real_arity_change_hidden_behind_an_opaque_local_stays_blocked(tmp_path):
    # The post local comes from an opaque call, so its return arity stays unresolved.
    old = "def f(u):\n    return (u, u)\n"
    new = "def f(u):\n    r = make(u)\n    return r\n"
    reqs = _mini(tmp_path / "a", old, new)
    assert reqs, "a hidden arity change must still produce a request"
    an = z3_binding.analyze(reqs[0])
    assert not an["refuted"] and an["unresolved"]
    assert z3_binding.derive_obligation(reqs[0], an, None).verdict is Verdict.NOT_DERIVED


def test_resolved_local_tuple_arity_change_refutes_with_caller_site(tmp_path):
    old = "def f(u):\n    return (u, u)\n"
    new = "def f(u):\n    r = (u, u, u)\n    return r\n"
    reqs = _mini(tmp_path / "a", old, new)
    assert reqs, "a changed local tuple arity must still produce a request"
    analysis = z3_binding.analyze(reqs[0])
    assert [item["where"] for item in analysis["refuted"]] == ["c.py:5"]
    assert not analysis["unresolved"]
    assert z3_binding.derive_obligation(reqs[0], analysis, None).verdict is Verdict.REFUTED


def test_new_decided_path_that_violates_a_listed_consumer_is_blocked_even_if_pre_is_undecided(tmp_path):
    old = "def f(u):\n    r = g(u)\n    return r\n"
    new = "def f(u):\n    if not u:\n        return (None, None, None)\n    r = g(u)\n    return r\n"
    reqs = _mini(tmp_path / "a", old, new)  # caller unpacks 2
    assert reqs, "the new 3-tuple return breaks the listed unpack-2 caller"
    ob = z3_binding.derive_obligation(reqs[0], z3_binding.analyze(reqs[0]), None)
    assert ob.verdict in (Verdict.NOT_DERIVED, Verdict.REFUTED)


def test_decided_arity_change_still_refutes_end_to_end(tmp_path):
    reqs = _mini(tmp_path / "a", "def f(u):\n    return (u, u)\n", "def f(u):\n    return (u, u, u)\n")
    an = z3_binding.analyze(reqs[0])
    assert an["refuted"] and z3_binding.derive_obligation(reqs[0], an, None).verdict is Verdict.REFUTED


def test_decided_same_arity_and_new_decided_consumed_arity_are_quiet(tmp_path):
    old = "def f(u):\n    return (u, u)\n"
    assert _mini(tmp_path / "a", old, "def f(u):\n    x = u\n    return (x, x)\n") == []
    assert _mini(tmp_path / "b", old, "def f(u):\n    if not u:\n        return (None, None)\n    return (u, u)\n") == []
