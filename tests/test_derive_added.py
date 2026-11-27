# SPDX-License-Identifier: Apache-2.0
"""An added callable that no modified caller reaches must stop the gate (NOT_DERIVED), never pass."""
import subprocess

import pytest

from hlith.derive import make_derive
from hlith.types import ProposedEffect, Verdict


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


DIFF = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,2 +1,5 @@
 def f(x):
     return x + 1
+
+def g(y):
+    return y * 2
"""


def test_unreached_added_callable_is_not_derived(tmp_path):
    repo = _repo(tmp_path)
    eff = ProposedEffect(unified_diff=DIFF, proposer_id="t", touched_files=("m.py",))
    obs = make_derive(proposer_paths=[])(repo, eff).obligations
    verdicts = {o.obligation_id: o.verdict for o in obs}
    unreached = [o for o in obs if o.obligation_id.startswith("added-unreached:")]
    assert unreached and all(o.verdict is Verdict.NOT_DERIVED for o in unreached)
    assert "no caller reaches the added callable" in unreached[0].stop_reason
    assert not all(v is Verdict.HELD for v in verdicts.values())  # the set can never land


REACHED = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,2 +1,5 @@
 def f(x):
-    return x + 1
+    return g(x)
+
+def g(y):
+    return y + 1
"""


def test_added_callable_reached_by_a_differentially_checked_caller_is_not_flagged(tmp_path):
    repo = _repo(tmp_path)
    eff = ProposedEffect(unified_diff=REACHED, proposer_id="t", touched_files=("m.py",))
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    obs = {o.obligation_id: o for o in make_derive(proposer_paths=[str(prop)])(repo, eff).obligations}
    assert "differential:m.f" in obs and not any(k.startswith("added-unexercised") for k in obs), sorted(obs)
    # the added callable keeps its own signature-binding obligation (it is listed only as added, case)
    assert "signature_binding:m.g" in obs and "signature_binding:m.f" in obs, sorted(obs)


def test_added_callable_whose_caller_differential_did_not_run_is_unverified(tmp_path):
    repo = _repo(tmp_path)
    eff = ProposedEffect(unified_diff=REACHED.replace("g(x)", "g(x)  # same"), proposer_id="t", touched_files=("m.py",))
    # a target interpreter that cannot run: the caller's differential never executes inputs
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    obs = {o.obligation_id: o for o in make_derive(proposer_paths=[str(prop)], target_python="/nonexistent/python")(repo, eff).obligations}
    assert obs["added-unexercised:m.g"].verdict is Verdict.UNVERIFIED
    assert "not reached by any differentially checked caller" in obs["added-unexercised:m.g"].stop_reason


# False accept being closed (review/maintainer): X is reached STATICALLY by a modified caller whose differential ran,
# but the call sits under a branch no generated input takes, so X's own code never executed.
DEAD_BRANCH = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,2 +1,7 @@
 def f(x):
-    return x + 1
+    if x * x < 0:
+        return g(x)
+    return x + 1
+
+def g(y):
+    return y * 2
"""


def _derive_dead(tmp_path):
    repo = _repo(tmp_path)
    eff = ProposedEffect(unified_diff=DEAD_BRANCH, proposer_id="t", touched_files=("m.py",))
    prop = tmp_path / "p"; prop.mkdir(); (prop / "x").write_text("x")
    return {o.obligation_id: o for o in make_derive(proposer_paths=[str(prop)])(repo, eff).obligations}


def test_repro_added_callable_never_executed_is_flagged(tmp_path):
    obs = _derive_dead(tmp_path)
    assert "differential:m.f" in obs  # the caller's differential ran
    # the false accept: g is reached statically by f, f's differential ran, yet g never executed (the call sits
    # under a computed condition no generated or seeded input satisfies). derive must say so, from the
    # differential's executed_post_callables, never from static reach.
    assert "added-unexercised:m.g" in obs, sorted(obs)
    # With the adequacy gate ON (default since the maintainer-case/design review work) f's own differential is UNVERIFIED (its
    # changed condition was never True), so the engine may say "not reached by any differentially checked caller"
    # instead of "never executed": both refuse; what must never happen is a HELD for g.
    assert any(k in obs["added-unexercised:m.g"].stop_reason
               for k in ("never executed", "not reached by any differentially checked caller"))
    assert obs["added-unexercised:m.g"].verdict.value == "unverified"
