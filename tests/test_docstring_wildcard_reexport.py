"""Importer regressions for static package re-exports in docstring checks."""

import ast
import sys
from pathlib import Path

from hlith.obligation.docstring_check import verify_docstring_only_diff
from hlith.types import Verdict


def _repo(
    root: Path,
    doc: str,
    package_init: str | None = None,
    module_doc: str | None = None,
) -> None:
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pkg" / "__init__.py").write_text(
        package_init or '__all__ = ["f"]\nfrom .mod import *\n',
        encoding="utf-8",
    )
    prefix = f'"""{module_doc}"""\n\n' if module_doc is not None else ""
    (root / "pkg" / "mod.py").write_text(
        prefix + f'def f():\n    """{doc}"""\n    return "stable"\n',
        encoding="utf-8",
    )
    (root / "tests" / "test_direct_module.py").write_text(
        "import pkg.mod\n\n"
        "def test_direct_import_is_stable():\n"
        "    assert pkg.mod.f() == 'stable'\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_reexport_reader.py").write_text(
        "from pkg import f\n\n"
        "def test_reexport_reads_docstring():\n"
        "    assert f.__doc__ == 'old wording'\n",
        encoding="utf-8",
    )


def _result(base: Path, post: Path, rel: str = "pkg/mod.py"):
    return verify_docstring_only_diff(
        base,
        post,
        (rel,),
        python=sys.executable,
        extra_sys_path=(),
        proposer_paths=(),
    )


def _obligation(result, obligation_id: str):
    return next(item for item in result.obligations if item.obligation_id == obligation_id)


def test_static_wildcard_reexport_reader_is_measured_and_refuted(tmp_path):
    base, post = tmp_path / "base", tmp_path / "post"
    _repo(base, "old wording")
    _repo(post, "new wording")

    result = _result(base, post)

    assert result.allow_skip_unrelated is False
    obligation = _obligation(result, "docstring-test-regression:pkg/mod.py")
    assert obligation.verdict is Verdict.REFUTED
    assert "tests/test_reexport_reader.py::test_reexport_reads_docstring" in (
        obligation.witness or ""
    )


def test_package_alias_of_static_wildcard_reexport_is_measured(tmp_path):
    base, post = tmp_path / "base", tmp_path / "post"
    _repo(base, "old wording")
    _repo(post, "new wording")
    for root in (base, post):
        (root / "tests" / "test_reexport_reader.py").write_text(
            "import pkg as m\n\n"
            "def test_reexport_reads_docstring():\n"
            "    assert m.f.__doc__ == 'old wording'\n",
            encoding="utf-8",
        )

    result = _result(base, post)

    obligation = _obligation(result, "docstring-test-regression:pkg/mod.py")
    assert obligation.verdict is Verdict.REFUTED
    assert "tests/test_reexport_reader.py::test_reexport_reads_docstring" in (
        obligation.witness or ""
    )


def test_dynamic_wildcard_export_is_a_named_unverified_blocker(tmp_path):
    base, post = tmp_path / "base", tmp_path / "post"
    dynamic_init = (
        "def _exports():\n    return ['f']\n\n"
        "__all__ = _exports()\nfrom .mod import *\n"
    )
    _repo(base, "old wording", dynamic_init)
    _repo(post, "new wording", dynamic_init)

    result = _result(base, post)

    assert result.allow_skip_unrelated is False
    obligation = _obligation(result, "docstring-import-test-error:pkg/mod.py")
    assert obligation.verdict is Verdict.UNVERIFIED
    assert "dynamic __all__ in pkg" in (obligation.stop_reason or "")


def test_module_docstring_uses_static_package_init_reach(tmp_path):
    base, post = tmp_path / "base", tmp_path / "post"
    package_init = "from . import mod\n"
    _repo(base, "stable wording", package_init, module_doc="old module docs")
    _repo(post, "stable wording", package_init, module_doc="new module docs")
    for root in (base, post):
        (root / "tests" / "test_reexport_reader.py").write_text(
            "import pkg\n\n"
            "def test_package_import_reads_module_doc():\n"
            "    assert pkg.mod.__doc__ == 'old module docs'\n",
            encoding="utf-8",
        )

    result = _result(base, post)

    obligation = _obligation(result, "docstring-test-regression:pkg/mod.py")
    assert obligation.verdict is Verdict.REFUTED
    assert "tests/test_reexport_reader.py::test_package_import_reads_module_doc" in (
        obligation.witness or ""
    )


def test_docstring_reader_resolver_uses_only_the_allowed_effect_api():
    source = Path(__file__).resolve().parents[1] / "src/hlith/obligation/docstring_check.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imports = [
        (node.level, node.module)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name == "resolve_static_wildcard_export"
    ]

    assert imports == [(2, "effect.api")]
