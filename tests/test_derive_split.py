# SPDX-License-Identifier: Apache-2.0
from hlith.derive import _split_qualified


def test_function_in_src_layout():
    assert _split_qualified("requests.utils.get_auth_from_url", "src/requests/utils.py") == (
        "requests.utils", "get_auth_from_url", "src")


def test_method_keeps_class_out_of_module():
    assert _split_qualified("requests.adapters.HTTPAdapter.send", "src/requests/adapters.py") == (
        "requests.adapters", "HTTPAdapter.send", "src")


def test_flat_layout_and_package_init():
    assert _split_qualified("pkg.mod.C.m", "pkg/mod.py") == ("pkg.mod", "C.m", "")
    assert _split_qualified("pkg.f", "src/pkg/__init__.py") == ("pkg", "f", "src")


def test_nested_class_method():
    assert _split_qualified("pkg.mod.Outer.Inner.m", "pkg/mod.py") == ("pkg.mod", "Outer.Inner.m", "")
