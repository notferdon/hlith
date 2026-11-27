"""case: a CONFINED standalone replay must see the same dependency tree the capture saw.

Cause (review, 82b06814): the confined profile granted ``Path(extra).resolve()`` while the replay script put the
UNRESOLVED ``extra`` on sys.path. When the extra path is a symlink, the
unresolved name does not exist inside the confined root, the entry is silently skipped and the import falls back to
the interpreter's own (different) package versions. A replay that cannot see a granted sys.path entry must also say
so instead of silently differing.
"""
import json
from pathlib import Path

import pytest

from hlith import differential


def _trees(tmp_path):
    deps_real = tmp_path / "real" / "deps"
    (deps_real / "envdep").mkdir(parents=True)
    (deps_real / "envdep" / "__init__.py").write_text("VERSION = 'dep-1.0'\n")
    deps_link = tmp_path / "deps_link"
    deps_link.symlink_to(deps_real, target_is_directory=True)
    for side, suffix in (("base", ""), ("post", "!")):
        pkg = tmp_path / side / "pkg"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "m.py").write_text(f"import envdep\n\n\ndef f():\n    return envdep.VERSION + {suffix!r}\n")
    witness = {"module": "pkg.m", "qualname": "f", "args": [], "kwargs": {},
               "pre": {"k": "ret", "r": "'dep-1.0'"}, "post": {"k": "ret", "r": "'dep-1.0!'"}}
    return tmp_path / "base", tmp_path / "post", deps_link, witness


def _replay(tmp_path, extra, witness, base, post):
    try:
        return differential.replay_witness(witness, str(base), str(post), "", [str(extra)], confined=True)
    except Exception as e:  # noqa: BLE001 - a host without the sandbox cannot run this class of test
        pytest.skip(f"confined replay unavailable on this host: {type(e).__name__}")


def test_confined_replay_sees_a_symlinked_extra_sys_path(tmp_path):
    base, post, link, witness = _trees(tmp_path)
    rep = _replay(tmp_path, link, witness, base, post)
    if rep["pre"].get("k") == "replay-error":
        pytest.skip("confined replay unavailable on this host")
    assert rep["pre"] == {**rep["pre"], "k": "ret"}, rep["pre"]
    assert rep["reproduced"] is True, json.dumps({k: v for k, v in rep.items() if k != "scripts"}, default=repr)[:600]


def test_confined_replay_reports_a_sys_path_entry_it_cannot_see(tmp_path):
    base, post, _link, witness = _trees(tmp_path)
    missing = tmp_path / "does_not_exist"
    rep = _replay(tmp_path, missing, witness, base, post)
    assert rep["reproduced"] is False
    assert rep.get("environment_gap"), rep
    assert str(missing) in json.dumps(rep["environment_gap"])
