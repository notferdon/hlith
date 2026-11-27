# SPDX-License-Identifier: Apache-2.0
"""Targeted falsifier for design plan: differential scratch dirs must be unique per qualified call site."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import hlith.derive as derive_mod
from hlith.obligation.facts import Facts, ModCallable
from hlith.types import BoundedEvidence, CheckProvenance, Obligation, Verdict

_EV = BoundedEvidence(1, "test domain", "unexplored")
_PR = CheckProvenance("test", "0" * 64, True, False, "0" * 64, 0)


def _acct_for(
    *,
    modified_callables: tuple[str, ...] = (),
    modified_constants: tuple[dict, ...] = (),
) -> tuple[Facts, dict]:
    mc_objs = tuple(
        ModCallable(
            qualified_name=qn,
            file_path=qn.rsplit(".", 1)[0].replace(".", "/") + ".py",
            pre_signature="def fn(x: int) -> int",
            post_signature="def fn(x: int) -> int",
        )
        for qn in modified_callables
    )
    acct = Facts()
    acct.modified_callables = mc_objs
    acct.constants = list(modified_constants)
    ad = acct.to_dict()
    return acct, ad


def test_differential_scratch_dirs_are_unique_across_modules_and_threads(
    tmp_path: Path, monkeypatch
) -> None:
    base = tmp_path / "base"
    post = tmp_path / "post"
    for root in (base, post):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")

    # Case A: two modules each with `helper` (modified callable) and `read_k` (reader of K).
    (base / "pkg" / "a.py").write_text(
        "K = 1\ndef helper(x: int) -> int:\n    return x\ndef read_k(x: int) -> int:\n    return x + K\n",
        encoding="utf-8",
    )
    (post / "pkg" / "a.py").write_text(
        "K = 2\ndef helper(x: int) -> int:\n    return x + 1\ndef read_k(x: int) -> int:\n    return x + K\n",
        encoding="utf-8",
    )
    (base / "pkg" / "b.py").write_text(
        "from pkg.a import K\ndef helper(x: int) -> int:\n    return x\ndef read_k(x: int) -> int:\n    return x + K\n",
        encoding="utf-8",
    )
    (post / "pkg" / "b.py").write_text(
        "from pkg.a import K\ndef helper(x: int) -> int:\n    return x + 2\ndef read_k(x: int) -> int:\n    return x + K\n",
        encoding="utf-8",
    )

    lock = threading.Lock()
    recorded: list[tuple[str, str, str]] = []
    collisions: list[tuple[str, str, str]] = []

    def fake_run_differential(*, module: str, function: str, scratch: str, **_kw) -> Obligation:
        with lock:
            try:
                Path(scratch).mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                collisions.append((module, function, scratch))
            recorded.append((module, function, scratch))
        return Obligation(
            f"differential:{module}.{function}",
            f"{module}.{function}",
            "behaviour preserved",
            Verdict.HELD,
            evidence=_EV,
            provenance=_PR,
        )

    monkeypatch.setattr(derive_mod.differential, "run_differential", fake_run_differential)
    monkeypatch.setattr(
        derive_mod.z3_binding,
        "requests_from_account",
        lambda ad, touched: [{"obligation_id": f"signature_binding:{c['qualified_name']}"} for c in ad["modified_callables"]],
    )
    monkeypatch.setattr(derive_mod.z3_binding, "return_shape_requests_from_account", lambda ad, post, touched: [])
    monkeypatch.setattr(
        derive_mod.z3_binding,
        "verify_confined_detailed",
        lambda req, **_kw: (
            Obligation(req["obligation_id"], "sym", "sig", Verdict.HELD, evidence=_EV, provenance=_PR),
            {},
        ),
    )
    monkeypatch.setattr(derive_mod, "_delta_rel_item", lambda *a, **k: None)
    monkeypatch.setattr(derive_mod.guard_removed, "removed_entry_guards", lambda *a, **k: [])

    core = derive_mod.make_derive(proposer_paths=[]).core
    acct_a, ad_a = _acct_for(
        modified_callables=("pkg.a.helper", "pkg.b.helper"),
        modified_constants=(
            {
                "qualified_name": "pkg.a.K",
                "readers": [
                    {"qualified_name": "pkg.a.read_k", "file_path": "pkg/a.py", "line_number": 5},
                    {"qualified_name": "pkg.b.read_k", "file_path": "pkg/b.py", "line_number": 5},
                ],
            },
        ),
    )
    core(
        touched_files=("pkg/a.py", "pkg/b.py"),
        deltas=[],
        acct=acct_a,
        ad=ad_a,
        fbk=None,
        base_dir=base,
        post_dir=post,
    )
    assert not collisions, f"scratch directory collision(s): {collisions!r}"
    assert len(recorded) == 4

    # Case B: doc_other ThreadPoolExecutor across two modules with the same unmodified helper name.
    recorded.clear()
    collisions.clear()
    for p, doc in ((base, '"""old"""'), (post, '"""new"""')):
        (p / "pkg" / "a.py").write_text(f"def doc_fn():\n    {doc}\n    return 1\ndef helper():\n    return 1\n", encoding="utf-8")
        (p / "pkg" / "b.py").write_text(f"def doc_fn():\n    {doc}\n    return 2\ndef helper():\n    return 2\n", encoding="utf-8")

    monkeypatch.setattr(
        derive_mod.docstring_check,
        "verify_docstring_only_diff",
        lambda *a, **k: SimpleNamespace(
            obligations=(),
            allow_skip_unrelated=True,
            static_clear={},
            static_tuple_receiver_sites=(),
        ),
    )
    acct_b, ad_b = _acct_for(modified_callables=("pkg.a.doc_fn", "pkg.b.doc_fn"))
    core(
        touched_files=("pkg/a.py", "pkg/b.py"),
        deltas=[],
        acct=acct_b,
        ad=ad_b,
        fbk=None,
        base_dir=base,
        post_dir=post,
    )
    assert not collisions, f"doc_other scratch directory collision(s): {collisions!r}"
    assert {r[0] for r in recorded if r[1] == "helper"} == {"pkg.a", "pkg.b"}
