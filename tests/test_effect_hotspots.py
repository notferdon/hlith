"""Regression, soundness, and scaling tests for L2 effect engine hotspots."""

from __future__ import annotations

import ast
import time
from pathlib import Path

from hlith.effect.engine import (
    _ModuleIndexes,
    _changed_dynamic_dispatch_targets,
    _class_method_may_be_rebound,
    _index_tree,
    _instance_method_shadowed,
    _known_subclasses_for,
    _resolve_impacted_calls,
    _scope_rebinds_name,
    _stable_init_attribute_class,
    _unresolved_method_references,
    build_effect_account,
)


def _write_files(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_module_indexes_invalidates_derived_caches_on_mutation(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "class Base:\n    def f(self):\n        return 1\n",
            "pkg/b.py": "from pkg.a import Base\n\nclass Child(Base):\n    def f(self):\n        return 2\n",
        },
    )
    indexes = _index_tree(tmp_path, ())
    assert isinstance(indexes, _ModuleIndexes)
    assert "pkg.b.Child" in _known_subclasses_for("pkg.a.Base", indexes)
    assert "pkg.a.Base" in indexes.class_index_map()
    assert "pkg.a.Base.f" in indexes.function_index_map()
    assert "pkg.b" in indexes.module_names_set()

    # Mutating via __delitem__ must clear derived lookup tables and subclass maps.
    del indexes["pkg/b.py"]
    assert "pkg.b.Child" not in _known_subclasses_for("pkg.a.Base", indexes)
    assert "pkg.b" not in indexes.module_names_set()

    # Mutating via __setitem__ must rebuild derived maps.
    rebuilt = _index_tree(tmp_path, ())
    indexes["pkg/b.py"] = rebuilt["pkg/b.py"]
    assert "pkg.b.Child" in _known_subclasses_for("pkg.a.Base", indexes)


def test_dynamic_dispatch_handles_self_cls_super_and_incomplete_mro(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/base.py": (
                "class Base:\n"
                "    def work(self):\n"
                "        return self.hook()\n"
                "    def hook(self):\n"
                "        return 1\n"
                "    @classmethod\n"
                "    def build(cls):\n"
                "        return cls.hook(cls())\n"
            ),
            "pkg/sub.py": (
                "from external_dep import ExternalMixin\n"
                "from pkg.base import Base\n"
                "\n"
                "class Sub(Base):\n"
                "    def work(self):\n"
                "        return super().hook()\n"
                "    def hook(self):\n"
                "        return 2\n"
                "\n"
                "class Deep(Sub):\n"
                "    def hook(self):\n"
                "        return 3\n"
                "\n"
                "class UncertainSub(ExternalMixin, Base):\n"
                "    def hook(self):\n"
                "        return 4\n"
                "\n"
                "class UncertainChild(ExternalMixin, Sub):\n"
                "    pass\n"
            ),
        },
    )
    indexes = _index_tree(tmp_path, ())
    base_idx = indexes["pkg/base.py"]
    sub_idx = indexes["pkg/sub.py"]

    work_call = next(c for c in base_idx.calls if c.caller == "pkg.base.Base.work" and c.function_name == "self.hook")
    cls_call = next(c for c in base_idx.calls if c.caller == "pkg.base.Base.build" and c.function_name == "cls.hook")
    super_call = next(c for c in sub_idx.calls if c.caller == "pkg.sub.Sub.work" and c.function_name == "super().hook")

    # Fast-path empty match: unrelated function change returns empty sets.
    assert _changed_dynamic_dispatch_targets(base_idx, work_call, indexes, {"pkg.other.fn"}) == (set(), set())

    # Subclass overrides are resolved when proven by the local MRO prefix (including own override on UncertainSub),
    # while Sub.hook inherited behind ExternalMixin on UncertainChild is marked uncertain.
    changed = {"pkg.sub.Sub.hook", "pkg.sub.Deep.hook", "pkg.sub.UncertainSub.hook"}
    resolved_self, uncertain_self = _changed_dynamic_dispatch_targets(base_idx, work_call, indexes, changed)
    assert resolved_self == {"pkg.sub.Sub.hook", "pkg.sub.Deep.hook", "pkg.sub.UncertainSub.hook"}
    assert uncertain_self == {"pkg.sub.Sub.hook"}

    resolved_cls, uncertain_cls = _changed_dynamic_dispatch_targets(base_idx, cls_call, indexes, changed)
    assert resolved_cls == {"pkg.sub.Sub.hook", "pkg.sub.Deep.hook", "pkg.sub.UncertainSub.hook"}
    assert uncertain_cls == {"pkg.sub.Sub.hook"}

    # super().hook() inside Sub looks after Sub in MRO, so changing Base.hook resolves for Deep(Sub)
    # and is uncertain for UncertainChild(ExternalMixin, Sub).
    resolved_super, uncertain_super = _changed_dynamic_dispatch_targets(
        sub_idx, super_call, indexes, {"pkg.base.Base.hook"}
    )
    assert resolved_super == {"pkg.base.Base.hook"}
    assert uncertain_super == {"pkg.base.Base.hook"}


def test_class_method_rebind_matches_with_and_without_preindexed_attr_writes(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": (
                "class A:\n"
                "    def f(self):\n"
                "        return 1\n"
                "    def g(self):\n"
                "        return 2\n"
                "\n"
                "class B:\n"
                "    def h(self):\n"
                "        return 3\n"
            ),
            "pkg/patch.py": (
                "from pkg.a import A, B\n"
                "A.f = lambda self: 9\n"
                "setattr(B, 'h', lambda self: 10)\n"
            ),
        },
    )
    indexes_fast = _index_tree(tmp_path, ())
    assert indexes_fast["pkg/patch.py"].attr_writes is not None
    assert _class_method_may_be_rebound("pkg.a.A", "f", "pkg.a.A.f", indexes_fast) is True
    assert _class_method_may_be_rebound("pkg.a.A", "g", "pkg.a.A.g", indexes_fast) is False
    assert _class_method_may_be_rebound("pkg.a.B", "h", "pkg.a.B.h", indexes_fast) is True

    # Fallback path when attr_writes is None must agree identically.
    indexes_fallback = _index_tree(tmp_path, ())
    for mod in indexes_fallback.values():
        mod.attr_writes = None
    indexes_fallback.class_mutation_cache = None
    assert _class_method_may_be_rebound("pkg.a.A", "f", "pkg.a.A.f", indexes_fallback) is True
    assert _class_method_may_be_rebound("pkg.a.A", "g", "pkg.a.A.g", indexes_fallback) is False
    assert _class_method_may_be_rebound("pkg.a.B", "h", "pkg.a.B.h", indexes_fallback) is True


def test_scope_rebind_instance_shadow_and_init_attr_caches(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/mod.py": (
                "class Helper:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class Owner:\n"
                "    def __init__(self):\n"
                "        self.helper = Helper()\n"
                "    def use(self):\n"
                "        return self.helper.run()\n"
                "\n"
                "def caller(arg_name):\n"
                "    local_x = 1\n"
                "    h = Helper()\n"
                "    h.run = lambda: 0\n"
                "    return h.run()\n"
            ),
        },
    )
    indexes = _index_tree(tmp_path, ())
    mod = indexes["pkg/mod.py"]

    assert _scope_rebinds_name(mod, "pkg.mod.caller", "arg_name") is True
    assert _scope_rebinds_name(mod, "pkg.mod.caller", "local_x") is True
    assert _scope_rebinds_name(mod, "pkg.mod.caller", "Helper") is False
    # Second query uses cached bindings set.
    assert ("pkg.mod.caller", False) in mod.scope_bindings_cache
    assert _scope_rebinds_name(mod, "pkg.mod.caller", "h") is True

    # Instance attribute shadowing detected before call line.
    raw_call = next(c for c in mod.calls if c.caller == "pkg.mod.caller" and c.function_name == "h.run")
    assert _instance_method_shadowed(mod, raw_call, ast.Name(id="h"), "run") is True
    assert _instance_method_shadowed(mod, raw_call, ast.Name(id="other"), "run") is False

    # Stable __init__ attribute class resolves and populates cache.
    assert _stable_init_attribute_class("pkg.mod.Owner", "helper", indexes) == "pkg.mod.Helper"
    assert ("pkg.mod.Owner", "helper") in indexes._init_attr_class_cache
    assert _stable_init_attribute_class("pkg.mod.Owner", "missing", indexes) is None


def test_unresolved_method_references_preserves_escaped_getattr_and_non_ascii(tmp_path: Path) -> None:
    _write_files(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/clean.py": "def untouched():\n    return 42\n",
            "pkg/escaped.py": (
                "def dynamic_lookup(obj):\n"
                '    fn = getattr(obj, "\\x66oo")\n'
                "    return fn()\n"
            ),
            "pkg/unicode_id.py": (
                "# non-ascii comment: \u00e9\n"
                "def ref(obj):\n"
                "    return obj.foo\n"
            ),
        },
    )
    indexes = _index_tree(tmp_path, ())
    unresolved = _unresolved_method_references(indexes, {"foo": {"pkg.target.C.foo"}})
    kinds_by_file = {(u.file_path, u.kind) for u in unresolved}
    assert ("pkg/escaped.py", "dynamic_method_getattr") in kinds_by_file
    assert ("pkg/escaped.py", "call_through_escaped_reference") in kinds_by_file
    assert ("pkg/unicode_id.py", "unresolved_method_reference") in kinds_by_file
    assert not any(u.file_path == "pkg/clean.py" for u in unresolved)


def test_dynamic_dispatch_scales_cleanly_on_many_classes(tmp_path: Path) -> None:
    """Guard against O(calls * classes * files) blowup when non-method functions change."""
    files: dict[str, str] = {"pkg/__init__.py": ""}
    files["pkg/target.py"] = "def validate(x: int) -> int:\n    if x <= 0:\n        raise ValueError('bad')\n    return x\n"
    for i in range(60):
        body = [f"class Model{i}:"]
        for m in range(6):
            body.append(f"    def m{m}(self):\n        return self.m{(m + 1) % 6}()")
        files[f"pkg/m{i}.py"] = "\n".join(body) + "\n"
    before_dir = tmp_path / "before"
    _write_files(before_dir, files)
    patch = (
        "--- a/pkg/target.py\n"
        "+++ b/pkg/target.py\n"
        "@@ -1,4 +1,2 @@\n"
        " def validate(x: int) -> int:\n"
        "-    if x <= 0:\n"
        "-        raise ValueError('bad')\n"
        "     return x\n"
    )

    t0 = time.perf_counter()
    account = build_effect_account(before_dir, patch)
    elapsed = time.perf_counter() - t0

    assert [fn.qualified_name for fn in account.modified_callables] == ["pkg.target.validate"]
    assert elapsed < 3.0, f"build_effect_account regressed to {elapsed:.2f}s on 60-class synthetic repo"

    # Also verify _resolve_impacted_calls stays fast when a class method changes on one unrelated class.
    before_idx = _index_tree(before_dir, ())
    t1 = time.perf_counter()
    sites, unresolved, _ = _resolve_impacted_calls(before_idx, {"pkg.m0.Model0.m0"})
    elapsed_method = time.perf_counter() - t1
    assert any(site.callee_qualified_name == "pkg.m0.Model0.m0" for site in sites)
    assert not unresolved
    assert elapsed_method < 2.0, f"_resolve_impacted_calls regressed to {elapsed_method:.2f}s"
