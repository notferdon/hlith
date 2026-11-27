# SPDX-License-Identifier: Apache-2.0
"""Regression and adversarial soundness tests for Workstream 2 practical verification improvements."""
from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from hlith.obligation import delta_cover, delta_follow, equiv_cert
from hlith.obligation.symeq import certify as symeq_certify
from hlith.obligation.symeq.tree import _defs, tree_taint
from hlith import differential


def test_changed_literal_dict_seeds_catch_deleted_escape_on_unannotated_mapping(tmp_path: Path) -> None:
    base = tmp_path / "base"
    post = tmp_path / "post"
    for root in (base, post):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg/__init__.py").write_text("", encoding="utf-8")
    src_base = (
        "import json\n"
        "def render(report):\n"
        "    rep = dict(report)\n"
        "    if rep.get('path'):\n"
        "        rep['path'] = 'safe'\n"
        "    return json.dumps(rep).replace('</', '<\\\\/')\n"
    )
    src_post = (
        "import json\n"
        "def render(report):\n"
        "    rep = dict(report)\n"
        "    if rep.get('path'):\n"
        "        rep['path'] = 'safe'\n"
        "    return json.dumps(rep)\n"
    )
    (base / "pkg/html_mod.py").write_text(src_base, encoding="utf-8")
    (post / "pkg/html_mod.py").write_text(src_post, encoding="utf-8")
    ob = differential.run_differential(
        base_root=str(base),
        post_root=str(post),
        module="pkg.html_mod",
        function="render",
        proposer_paths=[str(tmp_path / "prop")],
        scratch=str(tmp_path / "scratch"),
    ) if (tmp_path / "prop").mkdir(exist_ok=True) or True else None
    assert ob is not None
    assert ob.verdict.value == "refuted", (ob.verdict, ob.stop_reason, ob.witness)
    assert "</" in (ob.witness or "")


def test_symeq_opaque_str_method_and_unchanged_helper_with_dunder_file(tmp_path: Path) -> None:
    base = tmp_path / "base"
    post = tmp_path / "post"
    post_bad = tmp_path / "post_bad"
    for root in (base, post, post_bad):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg/__init__.py").write_text("", encoding="utf-8")
        (root / "pkg/other.py").write_text(
            "import os\n"
            "def get(p):\n"
            "    return os.path.dirname(p)\n",
            encoding="utf-8",
        )
        (root / "tests").mkdir()
        (root / "tests/test_r.py").write_text(
            "import os\n"
            "from pkg import rep\n"
            "def test_monkey():\n"
            "    orig = os.path.dirname\n"
            "    try:\n"
            "        os.path.dirname = lambda _: '/x'\n"
            "        rep.render({'a': 1})\n"
            "    finally:\n"
            "        os.path.dirname = orig\n",
            encoding="utf-8",
        )

    helper = (
        "import json, os\n"
        "TEMPLATE = '<style>__F__</style><script>__D__</script>'\n"
        "def _fontface():\n"
        "    return open(os.path.join(os.path.dirname(__file__), 'a.woff2'), 'rb').read().decode('ascii')\n"
    )
    fn_base = (
        "def render(report):\n"
        "    rep = dict(report)\n"
        "    if rep.get('path'):\n"
        "        rep['path'] = os.path.basename(str(rep['path']))\n"
        "    data = json.dumps(rep).replace('</', '<\\\\/')\n"
        "    return TEMPLATE.replace('__F__', _fontface()).replace('__D__', data)\n"
    )
    fn_post = fn_base.replace("data", "serialized")
    fn_bad = fn_base.replace(".replace('</', '<\\\\/')", "")
    (base / "pkg/rep.py").write_text(helper + fn_base, encoding="utf-8")
    (post / "pkg/rep.py").write_text(helper + fn_post, encoding="utf-8")
    (post_bad / "pkg/rep.py").write_text(helper + fn_bad, encoding="utf-8")

    # Clean local-rename refactor certifies unconditionally via SYM.
    ok_cert = equiv_cert.certify(base, post, "pkg.rep", "render")
    assert ok_cert.ok and ok_cert.rules == ("SYM",) and ok_cert.domain == (), (ok_cert.reason, ok_cert.detail)

    # Regression deleting the escape MUST NOT certify.
    bad_cert = equiv_cert.certify(base, post_bad, "pkg.rep", "render")
    assert not bad_cert.ok

    # Negative taint control: local indirect aliasing to an attribute write MUST STILL propagate taint.
    base_files = {"a.py": "def render(x):\n    return x\n", "b.py": "def sneaky(holder):\n    tmp = render\n    holder.cb = tmp\n"}
    post_files = {"a.py": "def render(x):\n    return x + 1\n", "b.py": base_files["b.py"]}
    tainted, _ = tree_taint(base_files, post_files, "a.py", "render")
    assert "cb" in tainted and "sneaky" in tainted
    assert "tmp" not in tainted  # local variable name does not leak globally


def test_singleton_identity_predicate_and_int_r2_certificate_soundness(tmp_path: Path) -> None:
    # 1. Singleton identity predicate check
    assert delta_cover.is_singleton_identity_predicate("text is None", ["text"])
    assert delta_cover.is_singleton_identity_predicate("None is text", ["text"])
    assert delta_cover.is_singleton_identity_predicate("flag is False", ["flag"])
    assert not delta_cover.is_singleton_identity_predicate("text is None", ["text", "other"])
    assert not delta_cover.is_singleton_identity_predicate("text == ''", ["text"])

    # 2. R2 int-guard certificate admits exact-int guard in scoped mode, refuses under strict_domain without entry guard,
    #    refuses if an int subclass exists in module, and refuses leaky body change.
    base_src = (
        "def truncate(text: str, limit: int = 400) -> str:\n"
        "    if len(text) <= limit:\n"
        "        return text\n"
        "    return text[: limit - 1] + '...'\n"
    )
    post_ok = (
        "def truncate(text: str, limit: int = 400) -> str:\n"
        "    if limit <= 0:\n"
        "        raise ValueError('limit must be positive')\n"
        "    if len(text) <= limit:\n"
        "        return text\n"
        "    return text[: limit - 1] + '...'\n"
    )
    post_leaky = post_ok.replace("if len(text) <= limit:", "if len(text) < limit:")
    deltas = [{
        "id": "truncate-nonpos",
        "symbol": "m.truncate",
        "type": "expr",
        "param": "limit",
        "expr": "limit <= 0",
        "expected": {"kind": "raises", "exc_type": "builtins.ValueError"},
    }]

    c_scoped = equiv_cert.certify_sources(base_src, post_ok, "truncate", deltas=deltas, module="m", strict_domain=False)
    assert c_scoped.ok and c_scoped.rules == ("R2",) and c_scoped.domain == (("limit", "int"),), (c_scoped.reason, c_scoped.domain)

    c_strict = equiv_cert.certify_sources(base_src, post_ok, "truncate", deltas=deltas, module="m", strict_domain=True)
    assert not c_strict.ok and "self-enforce exact int" in c_strict.reason

    c_leaky = equiv_cert.certify_sources(base_src, post_leaky, "truncate", deltas=deltas, module="m", strict_domain=False)
    assert not c_leaky.ok

    sub_prefix = "class WeirdInt(int):\n    def __le__(self, other):\n        return True\n\n"
    c_sub = equiv_cert.certify_sources(sub_prefix + base_src, sub_prefix + post_ok, "truncate", deltas=deltas, module="m", strict_domain=False)
    assert not c_sub.ok and "int subclass" in c_sub.reason

    # 3. Multi-parameter domain_seeds with source/qual produces bounded seeds and preserves no-source behavior.
    delta_full = {
        "id": "truncate-nonpos",
        "symbol": "m.truncate",
        "predicate": {"type": "expr", "param": "limit", "expr": "limit <= 0"},
        "expected": {"kind": "raises", "exc_type": "builtins.ValueError"},
    }
    s_no_src, n_no_src = delta_follow.domain_seeds([delta_full], "m.truncate", ["text", "limit"])
    assert s_no_src == [] and "one-parameter" in n_no_src[0]
    s_with_src, n_with_src = delta_follow.domain_seeds(
        [delta_full], "m.truncate", ["text", "limit"], source=post_ok, qual="truncate"
    )
    assert any(a[1] <= 0 for a, _, tag in s_with_src if tag.endswith(":in"))
    assert any(a[1] > 0 for a, _, tag in s_with_src if tag.endswith(":out"))
    assert any("fixed background" in n for n in n_with_src)
