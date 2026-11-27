from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gate_empty_derived_set import _env, _held_core  # noqa: E402

from hlith.contract.feedback import FeedbackInput
from hlith.contract.legacy import Obligation, Verdict
from hlith import derive as derive_module
from hlith.obligation import api as obligation_api


TARGETS = ("pkg.alpha", "pkg.beta", "pkg.gamma")


def _fake_view():
    return SimpleNamespace(
        touched_files=("m.py",),
        modified_callables=tuple(SimpleNamespace(qualified_name=name, file_path="m.py") for name in TARGETS),
        site_attribution=None,
        to_dict=lambda: {"modified_callables": list(TARGETS)},
        enclosing=lambda _filename, _line: None,
    )


def _core_with_progress(**kwargs):
    callback = kwargs.get("progress")
    for index, target in enumerate(TARGETS, 1):
        if callback is not None:
            callback(target, index, len(TARGETS))
    return _held_core(**kwargs)


def _run(env, monkeypatch, *, progress_marker=False, progress=None):
    _repo, _patch, _gate, _verifier, engine, account, base, post, identity = env
    monkeypatch.setattr(obligation_api._facts, "build", lambda *_args: _fake_view())
    engine._derive = SimpleNamespace(core=_core_with_progress)
    if progress_marker:
        return engine.verify(account, FeedbackInput(), base, post, identity, progress=progress)
    return engine.verify(account, FeedbackInput(), base, post, identity)


def test_verify_reports_each_modified_target_in_order_with_one_based_counts(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _held_core)
    seen = []

    _run(env, monkeypatch, progress_marker=True, progress=lambda target, i, n: seen.append((target, i, n)))

    assert seen == [(name, index, len(TARGETS)) for index, name in enumerate(TARGETS, 1)]


def test_raising_progress_callback_does_not_change_verdict(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _held_core)
    baseline = _run(env, monkeypatch)

    def raising_callback(_target, _index, _total):
        raise RuntimeError("progress sink unavailable")

    observed = _run(env, monkeypatch, progress_marker=True, progress=raising_callback)

    assert observed.obligations.obligations == baseline.obligations.obligations


def test_derive_core_reports_each_target_before_running_its_checks(tmp_path, monkeypatch):
    callables = tuple(
        SimpleNamespace(qualified_name=name, file_path="m.py", post_signature="(x)") for name in TARGETS
    )
    account_view = SimpleNamespace(
        modified_callables=callables,
        unknown_edges=(),
        unresolved_constructs=(),
        side_effect_primitive_delta=(),
        impacted_test_nodes=(),
    )
    account_dict = {
        "modified_callables": [{"qualified_name": name, "file_path": "m.py"} for name in TARGETS],
        "added_callables": [{"qualified_name": TARGETS[1], "reached_from": []}],
        "deleted_callables": [],
        "modified_constants": [],
        "modified_class_attributes": [],
    }
    monkeypatch.setattr(
        derive_module.z3_binding,
        "requests_from_account",
        lambda *_args: [
            {"obligation_id": f"signature_binding:{name}", "target_symbol": name, "added": False}
            for name in TARGETS
        ],
    )
    check_order = []

    def verify_binding(request, **_kw):
        check_order.append(("check", request["target_symbol"]))
        return (Obligation(request["obligation_id"], request["target_symbol"], "binds",
                           Verdict.NOT_DERIVED, stop_reason="test stub"), {})

    monkeypatch.setattr(derive_module.z3_binding, "verify_confined_detailed", verify_binding)
    monkeypatch.setattr(derive_module.z3_binding, "return_shape_requests_from_account", lambda *_args: [])
    monkeypatch.setattr(derive_module.differential, "run_differential", lambda **_kw: Obligation(
        "differential", "*", "equivalent", Verdict.NOT_DERIVED, stop_reason="test stub"))
    monkeypatch.setattr(derive_module.differential, "read_observations", lambda *_args: {})
    monkeypatch.setattr(derive_module.differential, "read_witness", lambda *_args: None)
    monkeypatch.setattr(derive_module.guard_removed, "removed_entry_guards", lambda *_args: [])
    monkeypatch.setattr(derive_module, "_delta_rel_item", lambda *_args: None)
    phase_events = []
    monkeypatch.setattr(derive_module._phases, "progress", lambda phase, **extra: phase_events.append(
        (phase, extra.get("target"), extra.get("i"), extra.get("n"))))

    base_dir, post_dir = tmp_path / "base", tmp_path / "post"
    base_dir.mkdir()
    post_dir.mkdir()
    source = "\n".join(f"def {name.rsplit('.', 1)[-1]}(x):\n    return x" for name in TARGETS) + "\n"
    (base_dir / "m.py").write_text(source)
    (post_dir / "m.py").write_text(source)

    derive = derive_module.make_derive(proposer_paths=())
    seen = []

    def report(target, index, total):
        seen.append((target, index, total))
        check_order.append(("progress", target))

    result = derive.core(
        touched_files=("README.txt",),
        deltas=(),
        acct=account_view,
        ad=account_dict,
        fbk=None,
        base_dir=base_dir,
        post_dir=post_dir,
        progress=report,
    )

    expected_progress = [(TARGETS[0], 1, 2), (TARGETS[2], 2, 2)]
    assert seen == expected_progress
    assert [(target, index, total) for phase, target, index, total in phase_events if phase == "differential"] == expected_progress
    assert check_order == [
        ("progress", TARGETS[0]), ("check", TARGETS[0]),
        ("check", TARGETS[1]),
        ("progress", TARGETS[2]), ("check", TARGETS[2]),
    ]
    assert result.obligations
