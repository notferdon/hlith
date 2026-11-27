# SPDX-License-Identifier: Apache-2.0
"""F1 durability across SEPARATE PROCESSES through the real CLI (design review 2026-11-21 task 2). Default suite (not `-m real`): the existing
cross-process CLI two-runs (test_feedback_approved_after_refusal.py, test_feedback.py::test_cli_run_*) are all marked `real` and are
deselected by pyproject addopts, so nothing in the default run proved that a record written by one `hlith run` PROCESS is loaded by the next.

Shape (review-2 refusal route on a tiny repo; three `python -m hlith.cli run --engine pipeline` processes, HLITH_STATE_DIR on a tmpdir):
  Run 1  (state S):     a regression the engine itself refutes (mask >= 2**64) -> exit 10; Layer 5's refusal probe writes records,
                        including an extended-probe input of the 2**1024 class (NOT Run 1's own witness).
  Run 2  (state S):     a DIFFERENT change, wrong only for mask >= 2**1000 -> exit 10 via a loaded Run-1 record; its artifact's
                        loaded_feedback_ids contain Run 1's written ids.
  Control (empty state): the identical Run 2 -> exit 0 (the engine's own domain does not reach 2**1000).
Not an F2 claim: Run 1 is a REFUSAL (its probe saw the divergence in run one); this test is about durable consumption (F1)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_HDR = "import socket\nimport struct\n\n\ndef f(mask):\n    if mask < -64:\n        raise ValueError('mask')\n"
BASE = _HDR + "    bits = 0xFFFFFFFF ^ (1 << 32 - mask) - 1\n    return socket.inet_ntoa(struct.pack('>I', bits))\n"
RUN1 = _HDR + ("    bits = 0xFFFFFFFF ^ (1 << 32 - (mask % 2**64 if mask >= 0 else mask)) - 1\n"
               "    return socket.inet_ntoa(struct.pack('>I', bits))\n")
RUN2 = _HDR + ("    bits = 0xFFFFFFFF ^ (1 << 32 - (mask % (1 << 1000) if mask >= 0 else mask)) - 1\n"
               "    return socket.inet_ntoa(struct.pack('>I', bits))\n")
TEST = "from pkg.m import f\n\n\ndef test_f():\n    assert f(24) == '255.255.255.0'\n"
REL = "src/pkg/m.py"


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout


def _source(root: Path) -> Path:
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("")
    (root / REL).write_text(BASE)
    (root / "tests").mkdir()
    (root / "tests" / "test_m.py").write_text(TEST)
    for a in (("init", "-q"), ("config", "user.email", "t@t"), ("config", "user.name", "t"), ("add", "."), ("commit", "-qm", "base")):
        _git(root, *a)
    return root


def _clone(src: Path, dst: Path) -> Path:
    subprocess.run(["git", "clone", "-q", str(src), str(dst)], check=True)
    _git(dst, "config", "user.email", "t@t")
    _git(dst, "config", "user.name", "t")
    return dst


def _patch(repo: Path, new: str, out: Path) -> Path:
    old = (repo / REL).read_text()
    (repo / REL).write_text(new)
    out.write_text(_git(repo, "diff"))
    (repo / REL).write_text(old)
    return out


def _cli(tmp: Path, tag: str, repo: Path, new: str, state: Path) -> tuple[int, dict, str]:
    """One SEPARATE process. The child imports the same hlith as this test (PYTHONPATH pinned to it) and reads state ONLY from
    HLITH_STATE_DIR: nothing is shared in memory with the parent or with another run."""
    import hlith
    patch = _patch(repo, new, tmp / f"{tag}.patch")
    man = tmp / f"{tag}.manifest.json"
    man.write_text(json.dumps({"paths": {REL: ["modify"]}}))
    out_dir = tmp / f"{tag}.result"  # `hlith check --artifact-out` is a new directory; the artifact is its out.json
    art = out_dir / "out.json"
    state.mkdir(mode=0o700, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("HLITH_")}
    env.update(HLITH_STATE_DIR=str(state), PYTHONPATH=str(Path(hlith.__file__).resolve().parent.parent))
    # Retargeted to Hlith Review (product.REVIEW_ONLY): was `hlith run --engine pipeline` (not offered); `hlith check --patch` runs the
    # same pipeline as a rehearsal in its own disposable clone and reads/writes feedback in the same HLITH_STATE_DIR.
    cmd = [sys.executable, "-m", "hlith.cli", "check", "--repo", str(repo), "--patch", str(patch), "--manifest", str(man),
           "--artifact-out", str(out_dir), "--target-python", sys.executable]
    cp = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900)
    return cp.returncode, (json.loads(art.read_text()) if art.is_file() else {}), cp.stdout[-1500:] + cp.stderr[-1500:]


def _stored(state: Path) -> dict[str, dict]:
    out = {}
    for p in state.glob("repositories/*/feedback/fb-*.json"):
        r = json.loads(p.read_text())
        r = r.get("record", r)
        out[r["feedback_id"]] = r
    return out


def _bits(o) -> int:
    if isinstance(o, bool):
        return 0
    if isinstance(o, int):
        return abs(o).bit_length()
    if isinstance(o, dict):
        return max([_bits(v) for v in o.values()] or [0])
    if isinstance(o, list):
        return max([_bits(v) for v in o] or [0])
    return 0


def test_a_record_written_by_one_cli_process_is_loaded_and_decisive_in_the_next(tmp_path):
    src = _source(tmp_path / "source")
    state = tmp_path / "state"

    rc1, a1, log1 = _cli(tmp_path, "r1", _clone(src, tmp_path / "r1"), RUN1, state)
    assert rc1 == 10 and a1.get("outcome") == "refused", (rc1, a1.get("blocking"), log1)
    import platform
    tp = a1.get("target_python")  # R3 provenance: what the CONFINED worker reported about itself (never inferred from --target-python)
    assert tp and tp["observed_in"] == "confined-differential-worker" and tp["version"] == platform.python_version() and tp["implementation"] == "cpython", tp
    written = set(a1["feedback"]["written_feedback_ids"])
    on_disk = _stored(state)
    assert written and written <= set(on_disk), (written, sorted(on_disk))  # durable: the artifact's ids are files in HLITH_STATE_DIR
    big = {i for i in written if _bits(on_disk[i].get("directive_payload")) > 1000}
    assert big, "Run 1 stored no 2**1024-class record: the experiment is vacuous"
    # ablation state: Run 1's store minus ONLY its 2**1024-class records (copied before Run 2 writes anything)
    import shutil
    abl = tmp_path / "state-ablation"
    shutil.copytree(state, abl)
    for p in abl.glob("repositories/*/feedback/fb-*.json"):
        if p.stem in big:
            p.unlink()

    rc2, a2, log2 = _cli(tmp_path, "r2", _clone(src, tmp_path / "r2"), RUN2, state)
    rca, aa, loga = _cli(tmp_path, "abl", _clone(src, tmp_path / "abl"), RUN2, abl)
    # without those records Run 2 is NOT refuted: under the positive-HELD gate it is UNVERIFIED / exit 12 on exactly the differential (it used to
    # LAND, a designed false HELD the gate now refuses); the records decide REFUTED vs UNVERIFIED
    assert rca == 12 and aa.get("outcome") == "refused" and aa.get("blocking") == ["differential:pkg.m.f"], (rca, aa.get("blocking"), loga)
    assert not [o for o in aa.get("obligations", []) if o.get("verdict") == "refuted"], aa.get("obligations")
    assert not (big & set(aa["feedback"]["loaded_feedback_ids"]))
    rcc, ac, logc = _cli(tmp_path, "ctrl", _clone(src, tmp_path / "ctrl"), RUN2, tmp_path / "state-empty")

    # control: the engine alone does not refute Run 2 (positive-HELD gate: UNVERIFIED / exit 12 on exactly the differential, never REFUTED)
    assert rcc == 12 and ac.get("outcome") == "refused" and ac.get("blocking") == ["differential:pkg.m.f"], (rcc, ac.get("blocking"), logc)
    assert not [o for o in ac.get("obligations", []) if o.get("verdict") == "refuted"], ac.get("obligations")
    assert not ac["feedback"]["loaded_feedback_ids"]
    loaded = set(a2["feedback"]["loaded_feedback_ids"])
    assert written <= loaded, (written - loaded)  # the next PROCESS loaded everything Run 1 wrote
    assert rc2 == 10 and a2.get("outcome") == "refused", (rc2, a2.get("blocking"), log2)
    witnesses = " ".join(str(o.get("witness") or "") for o in a2.get("obligations", []) if o.get("verdict") == "refuted")
    assert "pinned" in witnesses, witnesses  # refused THROUGH a pinned (stored) input, not the engine's own seeds
