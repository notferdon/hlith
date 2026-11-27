# SPDX-License-Identifier: Apache-2.0
"""A2: an added callable is ADDED, not modified (case, from the review A2 wrapper finding A2-1 on 118e79d).

A patch that adds one function and modifies another, across two modules. The account must list the new
function only in ``added_callables`` and the existing one only in ``modified_callables``, while the existing
consumers keep working for the modified one (pre/post signature, impacted and post call sites, the feedback
account slice) and the added one keeps its own record (post call sites, reached_from) and its binding request.
"""
from __future__ import annotations

import difflib
from pathlib import Path

from hlith.effect import build_effect_account
from hlith.feedback import account_slice
from hlith.z3_binding import requests_from_account

CORE = "pkg/core.py"
USE = "pkg/use.py"
CORE_BEFORE = (
    "def normalize(value):\n"
    "    return value.strip().lower()\n"
)
CORE_AFTER = (
    "def normalize(value):\n"
    "    return _trim(value).lower()\n"
    "\n"
    "\n"
    "def _trim(value):\n"
    "    return value.strip()\n"
)
USE_TEXT = (
    "from pkg.core import normalize\n"
    "\n"
    "\n"
    "def handle(name):\n"
    "    return normalize(name)\n"
)


def _diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def _account(tmp_path: Path) -> dict:
    for rel, text in (("pkg/__init__.py", ""), (CORE, CORE_BEFORE), (USE, USE_TEXT)):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return build_effect_account(tmp_path, _diff(CORE, CORE_BEFORE, CORE_AFTER)).to_dict()


def test_added_callable_is_listed_only_as_added(tmp_path: Path) -> None:
    acc = _account(tmp_path)
    modified = {m["qualified_name"] for m in acc["modified_callables"]}
    added = {a["qualified_name"] for a in acc["added_callables"]}
    assert added == {"pkg.core._trim"}
    assert modified == {"pkg.core.normalize"}, modified
    assert not any(m["pre_signature"] == "UNKNOWN" for m in acc["modified_callables"])


def test_modified_callable_consumers_unchanged(tmp_path: Path) -> None:
    acc = _account(tmp_path)
    (norm,) = [m for m in acc["modified_callables"] if m["qualified_name"] == "pkg.core.normalize"]
    assert norm["pre_signature"] == "(value)" and norm["post_signature"] == "(value)"
    for key in ("impacted_call_sites", "post_call_sites"):
        sites = {(s["caller_qualified_name"], s["file_path"], s["line_number"]) for s in acc[key]
                 if s["callee_qualified_name"] == "pkg.core.normalize"}
        assert sites == {("pkg.use.handle", USE, 5)}, (key, sites)
    sl = account_slice(acc)
    assert {"pkg.core.normalize", "pkg.use.handle", "pkg.core._trim"} <= sl


def test_added_callable_keeps_its_own_record_and_binding_request(tmp_path: Path) -> None:
    acc = _account(tmp_path)
    (trim,) = acc["added_callables"]
    assert {(s["caller_qualified_name"], s["file_path"], s["line_number"]) for s in trim["post_call_sites"]} == {
        ("pkg.core.normalize", CORE, 2)}
    assert [r["caller_qualified_name"] for r in trim["reached_from"]] == ["pkg.core.normalize"]
    reqs = {r["obligation_id"]: r for r in requests_from_account(acc, (CORE,))}
    assert set(reqs) == {"signature_binding:pkg.core.normalize", "signature_binding:pkg.core._trim"}
    assert reqs["signature_binding:pkg.core._trim"].get("added") is True
    assert not reqs["signature_binding:pkg.core.normalize"].get("added")
