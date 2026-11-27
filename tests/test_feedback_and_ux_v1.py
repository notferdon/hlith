# SPDX-License-Identifier: Apache-2.0
"""Tests for F2 computational feedback upgrades and R3 operator UX fixes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from hlith.contract.effects import CalleeEdge
from hlith.feedback import LocalFeedbackService
from hlith.feedback._legacy import (
    cone_domain_seeds_for_targets,
    harvested_call_seeds,
    pin_regression_counterexample,
    require_differential_domain_constraint,
)
from hlith.feedback.store import load_stored_records, persist_record
from hlith.hostio.state import LocalHostState
from hlith.operator import check as check_mod
from hlith.operator import cli as cli_mod
from hlith.operator import engine_cli
from hlith.operator.tui import artifact_facts, feedback_view, frame, host


GIT_ENV = {
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
        env={**os.environ, **GIT_ENV},
    )


# --------------------------------------------------------------------------- F2 computational feedback upgrades


def test_harvested_call_seeds_rejects_unrelated_receiver_methods(tmp_path):
    """Top-level function `get` in `pkg.api` must not harvest `os.environ.get` or `d.get` calls."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "api.py").write_text("def get(url):\n    return url\n")
    (tmp_path / "pkg" / "caller.py").write_text(
        "import os\n"
        "from pkg import api\n\n"
        "def run():\n"
        "    a = os.environ.get('SHOULD_NOT_HARVEST')\n"
        "    d = {'k': 1}\n"
        "    b = d.get('ALSO_NOT_HARVEST')\n"
        "    c = api.get('https://real.example/path')\n"
        "    return a, b, c\n"
    )
    seeds = harvested_call_seeds(tmp_path, "get", module="pkg.api")
    args_seen = [s["args"] for s in seeds]
    assert ["https://real.example/path"] in args_seen
    assert ["SHOULD_NOT_HARVEST"] not in args_seen
    assert ["ALSO_NOT_HARVEST"] not in args_seen


def test_cone_domain_seeds_transfer_semantic_param_and_isolate_unrelated(tmp_path):
    """Same-module siblings and call-cone neighbors transfer semantic parameter inputs as pure seeds (no expected)."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "urls.py").write_text(
        "def inspect_url(url: str) -> str:\n"
        "    return url\n\n"
        "def normalize_url(url: str, scheme: str) -> str:\n"
        "    return f'{scheme}://{url}'\n\n"
        "def unrelated_helper(x: int) -> int:\n"
        "    return x + 1\n\n"
        "def typed_mismatch(url: int) -> int:\n"
        "    return url * 2\n"
    )
    (tmp_path / "pkg" / "other.py").write_text(
        "def caller_fn(url: str) -> str:\n"
        "    return url\n"
    )
    store = tmp_path / "store"
    rec = pin_regression_counterexample(
        "run-111111111111",
        "pkg.urls.inspect_url",
        ["http://user:pass@127.0.0.1:8080/p"],
        {},
        expected={"kind": "return", "repr": "'ok'"},
        observed={"kind": "return", "repr": "'bad'"},
    )
    persist_record(store, rec)
    all_stored = load_stored_records(store, None)

    # 1. Same-module sibling sharing semantic param `url` receives transferred seed.
    donors, seeds = cone_domain_seeds_for_targets(all_stored, ("pkg.urls.normalize_url",), tmp_path)
    assert len(donors) == 1 and donors[0].record.feedback_id == rec.feedback_id
    from hlith.feedback.project import project_feedback_input
    from hlith.feedback._legacy import FeedbackIntegrityError
    import pytest

    projected = project_feedback_input((), required_record_ids=[rec.feedback_id], donor_records=donors, extra_seeds=seeds)
    assert [r.record_id for r in projected.records] == [rec.feedback_id]
    with pytest.raises(FeedbackIntegrityError):
        project_feedback_input((), extra_seeds=seeds)
    assert any(
        sym == "pkg.urls.normalize_url"
        and inp["args"][0] == "http://user:pass@127.0.0.1:8080/p"
        and fid == rec.feedback_id
        for sym, inp, fid in seeds
    )

    # 2. Unrelated function with generic param `x` receives ZERO transferred seeds and ZERO donor refs.
    donors_u, seeds_u = cone_domain_seeds_for_targets(all_stored, ("pkg.urls.unrelated_helper",), tmp_path)
    assert donors_u == () and seeds_u == ()

    # 3. Same-module sibling whose annotation (`url: int`) rejects `str` receives ZERO seeds.
    donors_m, seeds_m = cone_domain_seeds_for_targets(all_stored, ("pkg.urls.typed_mismatch",), tmp_path)
    assert donors_m == () and seeds_m == ()

    # 4. Cross-module caller connected by a call-cone edge transfers `url`.
    edge = CalleeEdge(caller="pkg.other.caller_fn", callee="pkg.urls.inspect_url", file="pkg/other.py", line=2)
    donors_c, seeds_c = cone_domain_seeds_for_targets(
        all_stored, ("pkg.other.caller_fn",), tmp_path, callee_edges=(edge,)
    )
    assert len(donors_c) == 1
    assert any(sym == "pkg.other.caller_fn" and inp["args"] == ["http://user:pass@127.0.0.1:8080/p"] for sym, inp, _ in seeds_c)

    # 5. LocalFeedbackService.load projects cross-symbol seeds ONLY into `.seeds` (never `.pins`).
    state = LocalHostState(tmp_path / "host_state")
    svc = LocalFeedbackService(state)
    persist_record(state.namespace("repo-x", "feedback"), rec)
    fb = svc.load("repo-x", ("pkg.urls.normalize_url",), base_path=tmp_path)
    assert fb.pins == ()
    assert len(fb.seeds) == 1 and fb.seeds[0][0] == "pkg.urls.normalize_url"
    assert [r.record_id for r in fb.records] == [rec.feedback_id]
    assert svc.load("repo-x", ("pkg.urls.unrelated_helper",), base_path=tmp_path).records == ()


def test_transferred_input_binds_positional_only_and_required_keywords(tmp_path):
    from inspect import signature

    source = (
        "def donor(url: str): pass\n"
        "def target(url: str = '', /, *, retries: int): pass\n"
    )
    (tmp_path / "mod.py").write_text(source)
    record = require_differential_domain_constraint("run-111111111111", ("mod.donor",), ((["from-memory"], {}),))
    persist_record(tmp_path / "store", record)
    _, seeds = cone_domain_seeds_for_targets(load_stored_records(tmp_path / "store", None), ("mod.target",), tmp_path)
    _, call, _ = seeds[0]
    def target(url: str = '', /, *, retries: int): pass
    assert signature(target).bind(*call["args"], **call["kwargs"]).arguments == {"url": "from-memory", "retries": 1}


def test_witness_guided_neighbor_refutes_with_causal_controls(tmp_path):
    """A stored domain seed's boundary neighbor refutes a related regression while empty memory misses it,
    with exact `feedback_record_ids` attribution and sound behavior-preserving non-refutation."""
    from hlith import differential
    from hlith.obligation.feedbackview import FeedbackView
    from hlith.feedback.project import project_feedback_input

    base = tmp_path / "base"
    post_bug = tmp_path / "post_bug"
    post_ok = tmp_path / "post_ok"
    for root in (base, post_bug, post_ok):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")

    # Base function: handles a rare structured token `alpha:beta@gamma99` and its case/prefix variants identically.
    src_base = (
        "def route_key(token: str) -> str:\n"
        "    if token == 'beta@gamma99':\n"
        "        return 'special'\n"
        "    return token.lower()\n"
    )
    # Buggy post: breaks specifically on the prefix-dropped neighbor `'beta@gamma99'` of stored witness `'alpha:beta@gamma99'`,
    # WITHOUT mentioning `'beta@gamma99'` as a literal in either base or post (check via sha256 digest so literal harvest cannot see it!).
    import hashlib

    target_hash = hashlib.sha256(b"beta@gamma99").hexdigest()
    src_base_opaque = (
        "import hashlib\n\n"
        "def route_key(token: str) -> str:\n"
        f"    if hashlib.sha256(token.encode('utf-8')).hexdigest() == {target_hash!r}:\n"
        "        return 'special'\n"
        "    return token.lower()\n"
    )
    src_post_bug = (
        "import hashlib\n\n"
        "def route_key(token: str) -> str:\n"
        f"    if hashlib.sha256(token.encode('utf-8')).hexdigest() == {target_hash!r}:\n"
        "        return 'broken'\n"
        "    return token.lower()\n"
    )
    src_post_ok = (
        "import hashlib\n\n"
        "def route_key(token: str) -> str:\n"
        f"    if hashlib.sha256(token.encode('utf-8')).hexdigest() == {target_hash!r}:\n"
        "        return 'special'\n"
        "    return str(token).lower()\n"
    )
    (base / "pkg" / "m.py").write_text(src_base_opaque)
    (post_bug / "pkg" / "m.py").write_text(src_post_bug)
    (post_ok / "pkg" / "m.py").write_text(src_post_ok)
    proposer_file = tmp_path / "proposer.secret"
    proposer_file.write_text("proposer-canary")

    # Empty control: neither base nor post exposes `'beta@gamma99'` as a literal, so standalone diff cannot refute it.
    res_empty = differential.run_differential(
        base_root=str(base),
        post_root=str(post_bug),
        module="pkg.m",
        function="route_key",
        proposer_paths=(str(proposer_file),),
        scratch=str(tmp_path / "scr_empty"),
        timeout=30,
        require_impacted_slice=False,
    )
    assert res_empty.verdict.value != "refuted", res_empty

    # Full memory: stored domain seed `'alpha:beta@gamma99'` (NOT the exact failing input!) triggers
    # prefix-drop boundary neighbor `'beta@gamma99'` and refutes with exact record provenance.
    store = tmp_path / "store"
    rec = require_differential_domain_constraint(
        "run-222222222222",
        ("pkg.m.route_key",),
        [(("alpha:beta@gamma99",), {})],
    )
    persist_record(store, rec)
    fb = project_feedback_input(load_stored_records(store, ("pkg.m.route_key",)))
    fv = FeedbackView(fb)
    cons = fv.constraints("pkg.m.route_key")
    scr_full = tmp_path / "scr_full"
    res_full = differential.run_differential(
        base_root=str(base),
        post_root=str(post_bug),
        module="pkg.m",
        function="route_key",
        proposer_paths=(str(proposer_file),),
        scratch=str(scr_full),
        constraints=cons,
        timeout=30,
        require_impacted_slice=False,
    )
    assert res_full.verdict.value == "refuted", res_full
    assert res_full.witness and res_full.witness.startswith("pinned-neighbor "), res_full.witness
    wc = differential.read_witness(str(scr_full))
    assert wc is not None
    assert wc.get("oracle") == "feedback-neighbor"
    assert wc.get("feedback_record_ids") == [rec.feedback_id]

    # TUI / feedback_view parse & display the neighbor provenance cleanly.
    parsed = artifact_facts.parse_witness(res_full.witness)
    assert parsed is not None and parsed[0] == "pinned-neighbor"
    fake_art = {
        "feedback": {
            "loaded_feedback_ids": [rec.feedback_id],
            "loaded_source_runs": {rec.feedback_id: "run-222222222222"},
            "written_feedback_ids": [],
        },
        "obligations": [
            {"id": "differential:pkg.m.route_key", "verdict": "refuted", "witness": res_full.witness, "witness_call": wc}
        ],
    }
    note = feedback_view.pinned_note(fake_art)
    assert note is not None and "boundary neighbor" in note and rec.feedback_id in note

    # Soundness check: behavior-preserving refactor with the same feedback is NOT refuted.
    res_ok = differential.run_differential(
        base_root=str(base),
        post_root=str(post_ok),
        module="pkg.m",
        function="route_key",
        proposer_paths=(str(proposer_file),),
        scratch=str(tmp_path / "scr_ok"),
        constraints=cons,
        timeout=30,
        require_impacted_slice=False,
    )
    assert res_ok.verdict.value != "refuted", res_ok


def test_pipeline_cross_symbol_feedback_end_to_end_and_replay(tmp_path):
    """End-to-end `hlith check` + `hlith replay`:
    Run 1 refutes `pkg.urls.inspect_url(url)` and persists its witness;
    Run 2 checks a distinct same-module sibling `pkg.urls.normalize_url(url, scheme)` and refutes via the
    transferred semantic parameter seed (`feedback_record_ids` citing Run 1, replay `REPRODUCED`) while
    empty memory misses it;
    Run 3 checks an unrelated sibling `pkg.urls.count_items(n)` and loads zero records from Run 1."""
    import hashlib

    secret_url = "https://alice:s3cr3t@10.20.30.40:8443/v2/items?sort=asc"
    # Hash the prefix-dropped neighbor `'alice:s3cr3t@10.20.30.40:8443/v2/items?sort=asc'` (or the URL itself)
    # so Run 2's code never mentions the URL literal!
    url_digest = hashlib.sha256(secret_url.encode("utf-8")).hexdigest()

    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    (repo / "pkg").mkdir()
    (repo / "pkg" / "__init__.py").write_text("")
    (repo / "pkg" / "urls.py").write_text(
        "import hashlib\n\n"
        "def inspect_url(url: str) -> str:\n"
        f"    if url == {secret_url!r}:\n"
        "        return 'auth-ok'\n"
        "    return url.strip()\n\n"
        "def normalize_url(url: str, scheme: str) -> str:\n"
        f"    if hashlib.sha256(url.encode('utf-8')).hexdigest() == {url_digest!r}:\n"
        "        return f'{scheme}://preserved'\n"
        "    return f'{scheme}://{url}'\n\n"
        "def count_items(n: int) -> int:\n"
        "    return n + 1\n"
    )
    (repo / "tests").mkdir()
    (repo / "tests" / "test_urls.py").write_text(
        "from pkg.urls import inspect_url, normalize_url, count_items\n\n"
        "def test_basic():\n"
        "    assert inspect_url('http://example.com') == 'http://example.com'\n"
        "    assert normalize_url('example.com', 'http') == 'http://example.com'\n"
        "    assert count_items(1) == 2\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")

    # Patch 1: breaks inspect_url on secret_url (known literal -> Run 1 discovers & pins secret_url)
    orig = (repo / "pkg" / "urls.py").read_text()
    (repo / "pkg" / "urls.py").write_text(orig.replace("return 'auth-ok'", "return 'auth-broken'"))
    p1 = tmp_path / "e1.patch"
    p1.write_text(_git(repo, "diff").stdout)
    _git(repo, "checkout", "--", "pkg/urls.py")

    # Patch 2: breaks normalize_url ONLY on url matching sha256(secret_url) (no literal in normalize_url!)
    (repo / "pkg" / "urls.py").write_text(orig.replace("return f'{scheme}://preserved'", "return f'{scheme}://stripped'"))
    p2 = tmp_path / "e2.patch"
    p2.write_text(_git(repo, "diff").stdout)
    _git(repo, "checkout", "--", "pkg/urls.py")

    # Patch 3: unrelated refactor in count_items(n)
    (repo / "pkg" / "urls.py").write_text(orig.replace("return n + 1", "return 1 + n"))
    p3 = tmp_path / "e3.patch"
    p3.write_text(_git(repo, "diff").stdout)
    _git(repo, "checkout", "--", "pkg/urls.py")

    state_full = tmp_path / "state_full"
    state_empty = tmp_path / "state_empty"
    base_env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

    def run_check(patch_path: Path, state_dir: Path, out_dir: Path) -> tuple[int, dict]:
        cp = subprocess.run(
            [
                sys.executable, "-m", "hlith.operator.cli", "check",
                "--no-input", "--json", "--repo", str(repo),
                "--patch", str(patch_path), "--artifact-out", str(out_dir),
            ],
            capture_output=True,
            text=True,
            env={**base_env, "HLITH_STATE_DIR": str(state_dir)},
            timeout=120,
        )
        return cp.returncode, json.loads(cp.stdout)

    # 1. Writer run on E1 -> REFUTED, writes feedback record(s)
    rc1, d1 = run_check(p1, state_full, tmp_path / "out1")
    assert rc1 == 10, d1
    written1 = d1["artifact"]["feedback"]["written_feedback_ids"]
    assert written1, d1["artifact"]["feedback"]

    # 2. Empty control on E2 -> does NOT refute (cannot guess sha256 preimage without E1's witness)
    rc2_empty, d2_empty = run_check(p2, state_empty, tmp_path / "out2_empty")
    assert rc2_empty != 10, d2_empty

    # 3. Full memory run on E2 -> loads E1's donor record, REFUTES normalize_url, attributes feedback_record_ids!
    rc2_full, d2_full = run_check(p2, state_full, tmp_path / "out2_full")
    assert rc2_full == 10, d2_full
    loaded2 = d2_full["artifact"]["feedback"]["loaded_feedback_ids"]
    assert set(loaded2) & set(written1), (loaded2, written1)
    refuted_ob = next(o for o in d2_full["artifact"]["obligations"] if o.get("verdict") == "refuted")
    fb_ids = (refuted_ob.get("witness_call") or {}).get("feedback_record_ids") or []
    assert set(fb_ids) & set(written1), refuted_ob

    # 4. Standalone `hlith replay` independently reproduces Run 2's witness!
    run2_id = d2_full["check"]["run_id"]
    rep = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", "replay", run2_id, "--repo", str(repo)],
        capture_output=True,
        text=True,
        env={**base_env, "HLITH_STATE_DIR": str(state_full)},
        timeout=60,
    )
    assert rep.returncode == 0 and "Replay: REPRODUCED" in rep.stdout, rep.stdout + rep.stderr

    # 5. Unrelated sibling E3 (`count_items(n)`) loads ZERO records from E1!
    rc3, d3 = run_check(p3, state_full, tmp_path / "out3")
    assert rc3 == 0, d3
    assert d3["artifact"]["feedback"]["loaded_feedback_ids"] == [], d3["artifact"]["feedback"]


# --------------------------------------------------------------------------- R3 operator UX fixes


def test_check_uncommitted_refuses_unresolved_merge_conflicts_cleanly(tmp_path):
    """UX-1: `hlith check --uncommitted` fails fast with a plain merge-conflict refusal instead of cloning markers."""
    repo = tmp_path / "conflict_repo"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "other")
    (repo / "m.py").write_text("def f(x):\n    return x + 2\n")
    _git(repo, "commit", "-qam", "other")
    _git(repo, "checkout", "-q", "main")
    (repo / "m.py").write_text("def f(x):\n    return x + 3\n")
    _git(repo, "commit", "-qam", "main")
    m = _git(repo, "merge", "other", check=False)
    assert m.returncode != 0  # genuine unresolved merge conflict

    proc = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", "check", "--no-input", "--repo", str(repo), "--uncommitted", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 4, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["check"]["run_state"] == "boundary-unavailable"
    assert "unresolved conflicts" in data["check"]["reason"]
    assert "m.py" in data["check"]["reason"]


def test_tui_root_commit_plain_never_claims_no_python_or_not_scanned(tmp_path):
    """UX-2: 1-commit clean repo in `hlith ui --plain` does not falsely say NO PYTHON FILE or permanently not scanned."""
    repo = tmp_path / "single_commit"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    # Unit check on frame._no_python sentinel guard
    assert frame._no_python({"file": "not recorded", "note": "root commit: no base to apply it on", "can_run": False}) is False
    assert frame._no_python({"file": "README.md", "can_run": True}) is True

    # End-to-end --plain output on a clean 1-commit Python repository
    proc = subprocess.run(
        [sys.executable, "-m", "hlith.operator.cli", "ui", "--plain", "--repo", str(repo)],
        capture_output=True,
        text=True,
        env={**os.environ, "HLITH_STATE_DIR": str(tmp_path / "state")},
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "NO PYTHON FILE IN THIS CHANGE" not in proc.stdout
    assert "not scanned" not in proc.stdout
    assert "root commit: no base to apply it on" in proc.stdout


def test_cli_help_flags_are_all_documented():
    """UX-3: Every flag in `check`, `apply`, `run`, `resume`, `propose-deltas`, `annotate`, `quarantine`, `escalate` has help text."""
    for argv in (
        ["check", "--help"],
        ["apply", "--help"],
        ["run", "--help"],
        ["resume", "--help"],
        ["propose-deltas", "--help"],
        ["inspect", "--help"],
        ["annotate", "--help"],
        ["quarantine", "--help"],
        ["escalate", "--help"],
    ):
        proc = subprocess.run(
            [sys.executable, "-m", "hlith.operator.cli", *argv],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0, (argv, proc.stderr)
        out = proc.stdout
        assert "--repo" in out or "thread_id" in out or "target" in out
        # Spot-check previously undocumented flags now have prose descriptions on their option lines.
        if argv[0] == "check":
            for flag in ("--repo", "--uncommitted", "--commit", "--branch", "--base", "--patch", "--manifest", "--json", "--target-venv", "--target-python", "--keep-clone"):
                line = next((ln for ln in out.splitlines() if flag in ln), "")
                assert line and len(line.strip()) > len(flag) + 12, (flag, line)
        if argv[0] == "apply":
            for flag in ("--manifest", "--artifact-out", "--timeout", "--target-python", "--invocation-id"):
                line = next((ln for ln in out.splitlines() if flag in ln), "")
                assert line and len(line.strip()) > len(flag) + 12, (flag, line)
