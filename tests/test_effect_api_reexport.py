"""Keep the static export resolver reachable through the allowed L2 API."""

from hlith.effect.api import resolve_static_wildcard_export


def test_static_wildcard_resolver_is_public_from_effect_api(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        '__all__ = ["f"]\nfrom .mod import *\n', encoding="utf-8"
    )
    (package / "mod.py").write_text("def f():\n    return None\n", encoding="utf-8")

    resolution = resolve_static_wildcard_export("pkg", "f", (tmp_path,))

    assert resolution.status == "resolved"
    assert resolution.target_module == "pkg.mod"
