from __future__ import annotations

from pathlib import Path

from hlith.effect import resolve_static_wildcard_export


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def test_more_itertools_static_all_resolves_star_export_to_source_module(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "more_itertools/__init__.py",
        "from more_itertools.more import *\n__all__ = ['one', 'only']\n",
    )
    _write(
        tmp_path,
        "more_itertools/more.py",
        "def one(value=1):\n    return value\n\ndef only(value=1):\n    return value\n",
    )

    resolution = resolve_static_wildcard_export(
        "more_itertools", "one", [tmp_path]
    )

    assert resolution.status == "resolved"
    assert resolution.target_module == "more_itertools.more"
    assert resolution.reason is None
