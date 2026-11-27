# SPDX-License-Identifier: Apache-2.0
"""A2 remaining findings (review, case): call through an escaped reference, and `side` on call-site records."""
from __future__ import annotations

import difflib
from pathlib import Path

from hlith.effect import build_effect_account

PRE = '''def changed(x):
    return x


def run(self, x):
    strip = getattr(self, "hook", changed)
    return strip(x)
'''


def _account(tmp_path: Path, pre: str, post: str, rel: str = "m.py") -> dict:
    (tmp_path / rel).write_text(pre)
    diff = "".join(difflib.unified_diff(pre.splitlines(True), post.splitlines(True), f"a/{rel}", f"b/{rel}"))
    return build_effect_account(tmp_path, diff).to_dict()


def _kinds(acc: dict) -> list[tuple[str, int]]:
    return sorted((u["kind"], u["line_number"]) for u in acc["unresolved_constructs"])


def test_call_through_a_local_bound_from_an_escaping_reference_has_its_own_record(tmp_path: Path) -> None:
    acc = _account(tmp_path, PRE, PRE.replace("return x\n\n\ndef run", "return x + 1\n\n\ndef run", 1))
    assert _kinds(acc) == [("call_through_escaped_reference", 7), ("unresolved_method_reference", 6)]
    call = next(u for u in acc["unresolved_constructs"] if u["kind"] == "call_through_escaped_reference")
    assert call["caller_qualified_name"] == "m.run" and call["target_qualified_name"] == "m.changed"
    assert acc["unknown_edge_count"] == 2 and {e["line_number"] for e in acc["unknown_edges"]} == {6, 7}


def test_a_local_rebound_to_something_harmless_is_not_an_escaped_call(tmp_path: Path) -> None:
    pre = PRE.replace("    return strip(x)\n", "    strip = len\n    return strip(x)\n")
    acc = _account(tmp_path, pre, pre.replace("return x\n\n\ndef run", "return x + 1\n\n\ndef run", 1))
    assert _kinds(acc) == [("unresolved_method_reference", 6)]  # the reference still escapes; the later call is of `len`


def test_a_plain_direct_call_of_the_changed_callable_gets_no_escape_record(tmp_path: Path) -> None:
    pre = "def changed(x):\n    return x\n\n\ndef run(x):\n    return changed(x)\n"
    acc = _account(tmp_path, pre, pre.replace("return x\n\n\ndef run", "return x + 1\n\n\ndef run", 1))
    assert _kinds(acc) == [] and acc["unknown_edge_count"] == 0
    assert acc["impacted_call_sites"], "the direct call is still a resolved impacted call site"


def test_call_site_records_say_which_tree_they_were_resolved_on(tmp_path: Path) -> None:
    pre = "def changed(x):\n    return x\n\n\ndef run(x):\n    return changed(x)\n"
    post = pre.replace("return x\n\n\ndef run", "return x + 1\n\n\ndef helper(y):\n    return y\n\n\ndef run", 1).replace(
        "return changed(x)", "return changed(helper(x))")
    acc = _account(tmp_path, pre, post)
    assert acc["impacted_call_sites"] and {c["side"] for c in acc["impacted_call_sites"]} == {"pre"}
    assert acc["post_call_sites"] and {c["side"] for c in acc["post_call_sites"]} == {"post"}
    added = acc["added_callables"][0]
    assert added["qualified_name"] == "m.helper" and added["post_call_sites"]
    assert {c["side"] for c in added["post_call_sites"]} == {"post"}


def test_deleted_callable_surviving_sites_are_post(tmp_path: Path) -> None:
    pre = "def gone(x):\n    return x\n\n\ndef run(x):\n    return gone(x)\n"
    post = "def run(x):\n    return gone(x)\n"
    acc = _account(tmp_path, pre, post)
    sites = acc["deleted_callables"][0]["post_call_sites"]
    assert sites and {c["side"] for c in sites} == {"post"}
