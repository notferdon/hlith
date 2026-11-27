# SPDX-License-Identifier: Apache-2.0
"""review (L5 feedback, cross-run correctness) on 25813b32: REAL two-run pipeline experiments in ONE shared HLITH state, each with an
empty-store control. design review (5a5bb3f1) leads re-checked on the current source:

- P1-2: the canonical pipeline never handed L5 the target interpreter / extra sys.path, so post-landing and refusal probes ran under
  Hlith's own interpreter WITHOUT the target's dependencies: on a repo that needs ``--extra-sys-path`` the probe could not import the
  module, wrote no record, and Run 2's consequence was lost (F1 durable consumption / F2 causal novelty on a real dependency layout).
- P0-1: a NOT_DERIVED construct stored by a refused Run 1 must not block a later run in the same state once the construct is gone,
  and must not relax a run where it is still present.
- P0-2: the pipeline must tell L5 that a REHEARSAL landing happened in a clone (L5 then records no supersession for the source store).
Tiny synthetic repositories (the dotted_netmask shape of tests/test_feedback_domain_producer.py), real confinement, real differential.
"""
from __future__ import annotations

import dataclasses
import difflib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.contract.errors import EXIT_LANDED, EXIT_NOT_DERIVED, EXIT_REFUTED, EXIT_UNVERIFIED
from hlith.contract.identities import InvocationId

_HDR = "import socket\nimport struct\n\n\ndef f(mask):\n    if mask < -64:\n        raise ValueError('mask')\n"
BASE = _HDR + "    bits = 0xFFFFFFFF ^ (1 << 32 - mask) - 1\n    return socket.inet_ntoa(struct.pack('>I', bits))\n"
SOUND = _HDR + "    bits = ((1 << 32 - mask) - 1) ^ 0xFFFFFFFF\n    return socket.inet_ntoa(struct.pack('>I', bits))\n"
# positive-HELD gate (case): the SOUND operand swap is not a certified rewrite (UNVERIFIED, exit 12). A Run that
# must LAND uses SOUND_R0: the same computation with a consistently renamed local, certified by rule R0 (still a modified f).
SOUND_R0 = BASE.replace("bits", "mask_bits")
WIDE_BREAK = _HDR + ("    bits = 0xFFFFFFFF ^ (1 << 32 - (mask % (1 << 1000) if mask >= 0 else mask)) - 1\n"
                     "    return socket.inet_ntoa(struct.pack('>I', bits))\n")
TEST = "from pkg.m import f\n\n\ndef test_f():\n    assert f(24) == '255.255.255.0'\n"

# the same shapes, but the module needs a dependency that exists ONLY on --extra-sys-path (not in Hlith's own environment)
_DEP_IMPORT = "import n2_netmask_dep\n"
DEP_MOD = "WIDTH = 32\n"


def _with_dep(src: str) -> str:
    return _DEP_IMPORT + src.replace("1 << 32 - ", "1 << n2_netmask_dep.WIDTH - ")


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout


def _source(root: Path, src: str, *, test: str = TEST) -> Path:
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("")
    (root / "src" / "pkg" / "m.py").write_text(src)
    (root / "tests").mkdir()
    (root / "tests" / "test_m.py").write_text(test)
    for a in (("init", "-q"), ("config", "user.email", "t@t"), ("config", "user.name", "t"), ("add", "."), ("commit", "-qm", "base")):
        _git(root, *a)
    return root


def _clone(src: Path, dst: Path) -> Path:
    """Same root commit -> same pipeline repo identity (hostio/state.py), i.e. the SAME feedback store under one state root."""
    subprocess.run(["git", "clone", "-q", str(src), str(dst)], check=True)
    _git(dst, "config", "user.email", "t@t")
    _git(dst, "config", "user.name", "t")
    return dst


def _patch(old: str, new: str) -> bytes:
    d = difflib.unified_diff(old.splitlines(True), new.splitlines(True), "a/src/pkg/m.py", "b/src/pkg/m.py")
    return ("diff --git a/src/pkg/m.py b/src/pkg/m.py\n" + "".join(d)).encode()


def _caps(tmp: Path, state: Path, label: str, *, extra=(), transform=None):
    from hlith.operator.capabilities import default_capabilities
    prop = tmp / f"prop-{label}"
    prop.mkdir()
    caps = default_capabilities(state_root=state, python=sys.executable, proposer_paths=(str(prop),), extra_sys_path=tuple(map(str, extra)))
    return transform(caps) if transform else caps


def _run(tmp: Path, repo: Path, state: Path, label: str, old: str, new: str, *, extra=(), transform=None, request_kw=None):
    from hlith.operator.pipeline import PipelineRequest, run_pipeline
    caps = _caps(tmp, state, label, extra=extra, transform=transform)
    from hlith.contract.runs import LandingTarget
    # Hlith Review refuses an ORIGINAL-target landing; `hlith check` rehearses in a disposable clone (these tmp clones are disposable)
    kw = {"landing_target": LandingTarget.REHEARSAL, **(request_kw or {})}
    req = PipelineRequest(target=repo, invocation_id=InvocationId(label), external_patch=_patch(old, new), external_patch_label=label, **kw)
    return run_pipeline(req, caps)


def _records(state: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(state.rglob("fb-*.json"))]


def _kind(rec: dict) -> str:
    return str((rec.get("record") or rec).get("directive_kind")).lower()


def _feedback_events(result) -> list[dict]:
    return [dict(e.detail) for e in result.events if str(getattr(e, "phase", "")).lower().endswith("feedback")]


def _blocking(result) -> str:
    return " ".join(map(str, result.gate_receipt.blocking))


# ------------------------------------------------------------------------------------------------------------------ P1-2
def test_extra_sys_path_reaches_layer5_so_run1_feedback_changes_run2(tmp_path):
    """Run 1 (SOUND, lands) on a module that imports a dependency available only on --extra-sys-path. L5's post-landing probe must
    run with that path and write a domain-constraint record. Run 2 (WIDE_BREAK, wrong only for mask >= 2**1000) in the SAME state is
    REFUTED citing Run 1's feedback; the identical Run 2 with an EMPTY state LANDS (the engine's own domain does not reach 2**1000).
    RED before the fix: the probe ran without the dependency, nothing was stored, and Run 2 landed in both arms."""
    deps = tmp_path / "deps"
    deps.mkdir()
    (deps / "n2_netmask_dep.py").write_text(DEP_MOD)
    base, sound, wide = _with_dep(BASE), _with_dep(SOUND_R0), _with_dep(WIDE_BREAK)
    src = _source(tmp_path / "source", base)
    state = tmp_path / "state"

    r1 = _run(tmp_path, _clone(src, tmp_path / "r1"), state, "r1", base, sound, extra=(deps,))
    assert r1.gate_receipt.exit_status == EXIT_LANDED, (r1.gate_receipt, _feedback_events(r1))
    domain = [r for r in _records(state) if _kind(r) == "require_differential_domain_constraint"]
    assert domain, f"Run 1's L5 probe stored no domain record (probe ran without --extra-sys-path?): {_feedback_events(r1)}"

    ctrl = _run(tmp_path, _clone(src, tmp_path / "ctrl"), tmp_path / "state-empty", "ctrl", base, wide, extra=(deps,))
    # control: no feedback; the engine alone does not refute it, and the positive-HELD gate does not certify it: UNVERIFIED, never REFUTED
    # (it used to LAND, a designed false HELD the gate now refuses)
    assert ctrl.gate_receipt.exit_status == EXIT_UNVERIFIED and tuple(ctrl.gate_receipt.blocking) == ("differential:pkg.m.f",), ctrl.gate_receipt
    treat = _run(tmp_path, _clone(src, tmp_path / "treat"), state, "treat", base, wide, extra=(deps,))
    assert treat.gate_receipt.exit_status == EXIT_REFUTED, (treat.gate_receipt, _feedback_events(treat))
    loaded = {r.record_id for r in treat.feedback_input.records}
    assert loaded & {(r.get("record") or r)["feedback_id"] for r in domain}, "treat's refusal is not attributable to Run 1's record"
    assert not ctrl.feedback_input.records


def test_layer5_service_applies_its_interpreter_and_paths_to_both_probe_routes(tmp_path):
    """Unit seam (cheap): the service's observe_kw reaches observe() on the landing route AND the refusal route; an explicit
    per-call value wins; an unknown key is a construction error, never silently dropped."""
    from types import SimpleNamespace

    from hlith.feedback import api as fb_api
    from hlith.feedback.api import LandingProbeContext, LocalFeedbackService
    from hlith.hostio.state import LocalHostState

    seen: list[tuple[str, dict]] = []
    orig_landing, orig_refusal = fb_api.run_landing_probes, fb_api.run_refusal_probes

    def landing(store, receipt, base, landed, **kw):
        seen.append(("landing", dict(kw["observe_kw"])))
        return ()

    def refusal(store, receipt, account, evidence, **kw):
        seen.append(("refusal", dict(evidence.get("observe_kw") or {})))
        return ()

    with pytest.raises((TypeError, ValueError)):
        LocalFeedbackService(LocalHostState(tmp_path / "s0"), observe_kw={"pyhton": "/x"})
    svc = LocalFeedbackService(LocalHostState(tmp_path / "s"), observe_kw={"python": "/opt/t/bin/python", "extra_sys_path": ("/deps",)})
    fb_api.run_landing_probes, fb_api.run_refusal_probes = landing, refusal
    try:
        receipt = SimpleNamespace(run_id="run-000000000001")
        svc.register_landing_context(receipt.run_id, LandingProbeContext(repo_identity="r", base=None, symbols=("m.f",)))
        svc.post_landing_probe(receipt, SimpleNamespace(path=tmp_path))
        svc.persist_refusal(receipt, None, {"repo_identity": "r"})
        svc.persist_refusal(receipt, None, {"repo_identity": "r", "observe_kw": {"python": "/explicit"}})
    finally:
        fb_api.run_landing_probes, fb_api.run_refusal_probes = orig_landing, orig_refusal
    assert seen[0] == ("landing", {"python": "/opt/t/bin/python", "extra_sys_path": ("/deps",)})
    assert seen[1] == ("refusal", {"python": "/opt/t/bin/python", "extra_sys_path": ("/deps",)})
    assert seen[2] == ("refusal", {"python": "/explicit", "extra_sys_path": ("/deps",)})


# ------------------------------------------------------------------------------------------------------------------ P0-1
# design review's P0-1 shape: an added entry guard the account cannot model (unsupported_entry_guard), scoped to the modified callable, so
# the stored construct is keyed by pkg.m.f and IS loaded by a later run on f. The call site is non-literal (a literal-only call site
# would discharge the guard).
_GUARD = "    if mask.bit_length() > 4096:\n        raise ValueError('mask')\n"
GUARDED = SOUND.replace("    bits = ((1", _GUARD + "    bits = ((1", 1)
TEST_VAR = "from pkg.m import f\n\n\ndef test_f():\n    n = int('24')\n    assert f(n) == '255.255.255.0'\n"


def test_a_stored_construct_does_not_block_a_later_run_once_the_construct_is_gone(tmp_path):
    """Run 1 introduces an unsupported entry guard -> refused with unresolved-* blocking, L5 stores it keyed by pkg.m.f. Run 2 in the SAME state is a
    sound change without the guard and LOADS that record -> it LANDS (design review P0-1 on 5a5bb3: refused by feedback-unknown forever).
    Negative control: Run 3 in the same state with the guard still present -> still refused (unresolved-*), the same exit as with an empty state (feedback
    never relaxes a live unknown)."""
    src = _source(tmp_path / "source", BASE, test=TEST_VAR)
    state = tmp_path / "state"
    r1 = _run(tmp_path, _clone(src, tmp_path / "r1"), state, "r1", BASE, GUARDED)
    assert r1.gate_receipt.exit_status in (EXIT_NOT_DERIVED, EXIT_REFUTED) and "unresolved" in _blocking(r1), (r1.gate_receipt,)
    cons = [(r.get("record") or r) for r in _records(state) if _kind(r) == "not_derived_construct"]
    assert any(c["target_symbols"] == ["pkg.m.f"] for c in cons), f"no construct keyed by pkg.m.f: the experiment is vacuous: {cons}"

    r2 = _run(tmp_path, _clone(src, tmp_path / "r2"), state, "r2", BASE, SOUND_R0)
    assert r2.gate_receipt.exit_status == EXIT_LANDED, (r2.gate_receipt, _blocking(r2))
    assert {c["feedback_id"] for c in cons} & {r.record_id for r in r2.feedback_input.records},\
        "Run 2 did not load Run 1's construct record: the same-state premise does not hold"

    r3 = _run(tmp_path, _clone(src, tmp_path / "r3"), state, "r3", BASE, GUARDED)
    r3e = _run(tmp_path, _clone(src, tmp_path / "r3e"), tmp_path / "state-empty", "r3e", BASE, GUARDED)
    assert r3.gate_receipt.exit_status == r3e.gate_receipt.exit_status != EXIT_LANDED, (r3.gate_receipt, r3e.gate_receipt)
    assert "unresolved" in _blocking(r3) and "unresolved" in _blocking(r3e)


# ------------------------------------------------------------------------------------------------------------------ P0-2
def test_the_pipeline_tells_layer5_a_rehearsal_landing_happened_in_a_clone(tmp_path):
    """The L5 rule (test_feedback_domain_producer::test_a_rehearsal_landing_never_supersedes_the_source_stores_pins) only protects the
    source store if the PIPELINE marks the context as a rehearsal. A real REHEARSAL landing must reach L5 with rehearsal=True.
    Control, retargeted to Hlith Review (product.REVIEW_ONLY): the same run as ORIGINAL was a landing with rehearsal=False; it is now
    refused before the gate (exit 4, review-only-distribution), reaches L5 with no landing context, and leaves its clone unchanged."""
    from hlith.contract.runs import LandingTarget

    contexts: dict[str, object] = {}

    def spy(label):
        def transform(caps):
            api = caps.feedback_api
            real = api.register_landing_context

            def register(run_id, ctx):
                contexts[label] = ctx
                return real(run_id, ctx)

            api.register_landing_context = register
            return caps
        return transform

    src = _source(tmp_path / "source", BASE)
    results = {}
    for label, target in (("reh", LandingTarget.REHEARSAL), ("orig", LandingTarget.ORIGINAL)):
        clone = _clone(src, tmp_path / label)
        head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout
        results[label] = _run(tmp_path, clone, tmp_path / f"state-{label}", label, BASE, SOUND_R0, transform=spy(label),
                              request_kw={"landing_target": target}), clone, head
    reh = results["reh"][0]
    assert reh.gate_receipt.exit_status == EXIT_LANDED, reh.gate_receipt
    assert getattr(contexts["reh"], "rehearsal") is True
    orig, clone, head = results["orig"]
    assert orig.gate_receipt.exit_status == 4 and orig.gate_receipt.blocking[0] == "review-only-distribution", orig.gate_receipt
    assert orig.gate_receipt.landed_commit is None and "orig" not in contexts, contexts
    after = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout
    status = subprocess.run(["git", "-C", str(clone), "status", "--porcelain"], capture_output=True, text=True, check=True).stdout
    assert after == head and status == "", "an ORIGINAL-target run wrote its repository in Hlith Review"


_ = dataclasses  # kept for transforms that replace a capability
