# SPDX-License-Identifier: Apache-2.0
"""case: on Python 3.9 sys.stdlib_module_names does not exist, so _atexit_is_stdlib() was False for every
non-builtin module (stdlib callbacks hashed recursively / unmeasurable: over-refusal, fail-closed). The fallback must
recognise the interpreter's own stdlib by builtin names or by the module file living under the stdlib directory (never
site-packages), and must never call a non-stdlib module stdlib (that would turn a refusal into a false HELD)."""
from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from hlith import differential as d


@pytest.fixture
def no_names(monkeypatch):
    monkeypatch.delattr(sys, "stdlib_module_names", raising=False)
    monkeypatch.setattr(d, "_STDLIB_ROOT_CACHE", {}, raising=False)


def test_stdlib_modules_recognised_without_stdlib_module_names(no_names):
    assert not hasattr(sys, "stdlib_module_names")
    for m in ("os", "os.path", "json.decoder", "logging", "time", "sys", "builtins", "collections.abc"):
        assert d._atexit_is_stdlib(m), m


def test_control_non_stdlib_modules_stay_non_stdlib(no_names, tmp_path, monkeypatch):
    (tmp_path / "zpd_user_mod.py").write_text("x = 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.import_module("zpd_user_mod")
    assert not d._atexit_is_stdlib("zpd_user_mod")
    assert not d._atexit_is_stdlib("pytest")  # third party in site-packages
    assert not d._atexit_is_stdlib("hlith")
    assert not d._atexit_is_stdlib("not_imported_anywhere_zpd")  # unknown module: fail closed
    assert not d._atexit_is_stdlib(None) and not d._atexit_is_stdlib("")


def test_a_user_module_shadowing_a_stdlib_name_is_not_stdlib(no_names, tmp_path, monkeypatch):
    """A module named like a stdlib one but loaded from a user path (cwd/sys.path shadowing) is NOT stdlib."""
    (tmp_path / "colorsys.py").write_text("x = 1\n")
    monkeypatch.setitem(sys.modules, "colorsys", importlib.util.module_from_spec(
        importlib.util.spec_from_file_location("colorsys", tmp_path / "colorsys.py")))
    sys.modules["colorsys"].__file__ = str(tmp_path / "colorsys.py")
    assert not d._atexit_is_stdlib("colorsys")


def test_names_present_path_unchanged():
    if not hasattr(sys, "stdlib_module_names"):
        pytest.skip("3.9")
    assert d._atexit_is_stdlib("os") and not d._atexit_is_stdlib("pytest")


@pytest.mark.skipif(shutil.which("python3.9") is None, reason="needs a real python3.9")
def test_real_python39_target_recognises_stdlib_and_not_user_code(tmp_path):
    code = textwrap.dedent(f"""
        import importlib.util, sys
        sys.path.insert(0, {str(tmp_path)!r})
        open({str(tmp_path / 'zpd_user_mod.py')!r}, 'w').write('x=1\\n')
        spec = importlib.util.spec_from_file_location('hlith_diff_standalone', {str(Path(d.__file__))!r})
        m = importlib.util.module_from_spec(spec); sys.modules['hlith_diff_standalone'] = m; spec.loader.exec_module(m)
        import os.path, logging, zpd_user_mod
        assert not hasattr(sys, 'stdlib_module_names')
        print([m._atexit_is_stdlib(x) for x in ('os', 'os.path', 'logging', 'zpd_user_mod', 'nope')])
    """)
    cp = subprocess.run(["python3.9", "-I", "-c", code], capture_output=True, text=True, timeout=120)
    assert cp.returncode == 0, cp.stderr[-800:]
    assert cp.stdout.strip() == "[True, True, True, False, False]", cp.stdout + cp.stderr[-400:]


_PY311 = Path.home() / ".local/share/uv/python/cpython-3.11.14-linux-x86_64-gnu/bin/python3.11"
_IDENT = textwrap.dedent("""
    import importlib.util, os, sys, logging
    spec = importlib.util.spec_from_file_location('hlith_diff_standalone', sys.argv[1])
    m = importlib.util.module_from_spec(spec); sys.modules['hlith_diff_standalone'] = m; spec.loader.exec_module(m)
    def cb():
        return os.path.join('a', 'b'), logging.getLogger('x')
    try:
        m._atexit_identity(cb, (), {}, '/nonexistent', 0)
        print('MEASURABLE')
    except m._AtexitUnmeasurable:
        print('UNMEASURABLE')
""")


@pytest.mark.skipif(shutil.which("python3.9") is None or not _PY311.exists(), reason="needs python3.9 and 3.11")
def test_same_callback_has_the_same_verdict_on_3_9_and_3_11(tmp_path):
    """Control (review): the evaluator child loads differential.py standalone under the TARGET interpreter, so its own sys /
    sysconfig decide what is stdlib; a callback over os.path.join and logging is MEASURABLE on both 3.9 and 3.11."""
    script = tmp_path / "idc.py"
    script.write_text(_IDENT)
    got = {}
    for name, py in (("3.9", "python3.9"), ("3.11", str(_PY311))):
        cp = subprocess.run([py, "-I", str(script), str(Path(d.__file__))], capture_output=True, text=True, timeout=120)
        assert cp.returncode == 0, cp.stderr[-600:]
        got[name] = cp.stdout.strip()
    assert got == {"3.9": "MEASURABLE", "3.11": "MEASURABLE"}, got


# --- review findings A/B and the surviving mutants ---

def test_user_module_in_a_venv_style_platstdlib_is_not_stdlib(no_names, tmp_path, monkeypatch):
    """A: a venv's platstdlib is the venv's own (user-writable) lib dir, outside the base install."""
    import sysconfig

    venv_lib = tmp_path / "venv" / "lib" / "python3.9"
    venv_lib.mkdir(parents=True)
    (venv_lib / "venvuser.py").write_text("x = 1\n")
    real_get = sysconfig.get_path
    monkeypatch.setattr(sysconfig, "get_path", lambda k, *a, **kw: str(venv_lib) if k == "platstdlib" else real_get(k, *a, **kw))
    monkeypatch.syspath_prepend(str(venv_lib))
    importlib.import_module("venvuser")
    assert not d._atexit_is_stdlib("venvuser")
    assert d._atexit_is_stdlib("os")  # control: the real stdlib is still recognised


def test_symlink_into_stdlib_resolves_to_the_real_stdlib_file(no_names, tmp_path, monkeypatch):
    import os as _os

    link = tmp_path / "zpd_osln.py"
    link.symlink_to(_os.__file__)
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.import_module("zpd_osln")
    assert d._atexit_is_stdlib("zpd_osln")  # content IS the stdlib file (named limit); realpath is what decides
    copy = tmp_path / "zpd_oscopy.py"
    copy.write_text(Path(_os.__file__).read_text())
    importlib.import_module("zpd_oscopy")
    assert not d._atexit_is_stdlib("zpd_oscopy")  # a COPY is user code


def test_not_yet_imported_false_is_not_cached(no_names, monkeypatch):
    monkeypatch.delitem(sys.modules, "sched", raising=False)
    assert not d._atexit_is_stdlib("sched")
    assert "sched" not in d._STDLIB_ROOT_CACHE
    importlib.import_module("sched")
    assert d._atexit_is_stdlib("sched")


def test_cached_true_is_dropped_when_the_module_is_replaced(no_names, tmp_path, monkeypatch):
    """B: a root classified stdlib must not stay stdlib after a user module takes its place in sys.modules."""
    importlib.import_module("sched")
    assert d._atexit_is_stdlib("sched")
    (tmp_path / "sched.py").write_text("x = 1\n")
    spec = importlib.util.spec_from_file_location("sched", tmp_path / "sched.py")
    user = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(user)
    monkeypatch.setitem(sys.modules, "sched", user)
    assert not d._atexit_is_stdlib("sched")


@pytest.mark.skipif(shutil.which("python3.9") is None, reason="needs a real python3.9")
def test_real_python39_venv_child_user_module_in_venv_lib_is_not_stdlib(tmp_path):
    """Finding A on a real venv: <venv>/lib/python3.9 is the venv's platstdlib; a user module placed there is NOT stdlib,
    the real stdlib and a site-packages module are classified as before."""
    venv = tmp_path / "v"
    subprocess.run(["python3.9", "-m", "venv", "--without-pip", str(venv)], check=True, capture_output=True, timeout=120)
    lib = venv / "lib" / "python3.9"
    (lib / "venvuser.py").write_text("x = 1\n")
    (lib / "site-packages" / "spuser.py").write_text("x = 1\n")
    code = textwrap.dedent(f"""
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location('hlith_diff_standalone', {str(Path(d.__file__))!r})
        m = importlib.util.module_from_spec(spec); sys.modules['hlith_diff_standalone'] = m; spec.loader.exec_module(m)
        sys.path[:0] = [{str(lib)!r}, {str(lib / 'site-packages')!r}]
        import os.path, venvuser, spuser
        print([m._atexit_is_stdlib(x) for x in ('os', 'os.path', 'venvuser', 'spuser')])
    """)
    cp = subprocess.run([str(venv / "bin" / "python"), "-S", "-c", code], capture_output=True, text=True, timeout=120)
    assert cp.returncode == 0, cp.stderr[-600:]
    assert cp.stdout.strip() == "[True, True, False, False]", cp.stdout + cp.stderr[-400:]


def test_site_packages_under_the_stdlib_dir_is_not_stdlib(no_names, tmp_path, monkeypatch):
    """Distro layouts put site-packages INSIDE the stdlib directory: still not stdlib (kills the exclusion mutant)."""
    import sysconfig

    std = tmp_path / "base" / "lib" / "python3.9"
    (std / "site-packages").mkdir(parents=True)
    (std / "site-packages" / "zpd_sp.py").write_text("x = 1\n")
    (std / "zpd_inlib.py").write_text("x = 1\n")
    real_get = sysconfig.get_path
    monkeypatch.setattr(sysconfig, "get_path", lambda k, *a, **kw: str(std) if k in ("stdlib", "platstdlib") else real_get(k, *a, **kw))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(sys, "base_exec_prefix", str(tmp_path / "base"))
    monkeypatch.syspath_prepend(str(std))
    monkeypatch.syspath_prepend(str(std / "site-packages"))
    importlib.import_module("zpd_sp")
    importlib.import_module("zpd_inlib")
    assert not d._atexit_is_stdlib("zpd_sp")
    assert d._atexit_is_stdlib("zpd_inlib")  # control: a file directly in the (base) stdlib dir is stdlib by this rule
