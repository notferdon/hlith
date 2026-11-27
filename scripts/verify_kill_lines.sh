#!/usr/bin/env bash
# Kill-line verification gate (HARD-FAIL on missing file, collected 0, skipped/deselected/xfail/xpass, or nonzero exit).
# Gate coverage map:
# - KL1 (test_kl1_unbypassable_gate.py): sandbox.run_confined + contract.legacy.decide + LEGACY gate._legacy.land
# - KL2 (test_kl2_non_empty_obligations.py): contract.legacy.ObligationSet / decide + derive (no land call)
# - KL3 (test_kl3_independent_held_check.py): contract.legacy.Obligation HELD invariants (no land call)
# - KL4 (test_kl4_not_derived_refuses.py): derive.make_derive + contract.legacy.decide (no land call)
# - KL5 (test_kl5_external_repo_understanding.py): effect/derive on external repo mirror (no land call)
# - KL6 (test_kl6_architecture_integrity.py): AST import/dependency check on L2/L3/L4 (no land call)
# - KL7 (test_kl7_gate_service.py): NEW LocalGateService.land (real LocalHostState, HardenedGitRead, LocalSnapshotService, LocalVerificationService)
# - Gate invariants (tests/property/test_gate_invariants.py): ObligationSet/Obligation + contract.legacy.decide + LEGACY gate._legacy.land (prop6)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "${HLITH_PYTHON:-}" ]; then
  PY="$HLITH_PYTHON"
elif [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  echo "FAIL: python not found at $ROOT/.venv/bin/python (and HLITH_PYTHON not set)" >&2
  exit 2
fi
[ -x "$PY" ] || { echo "FAIL: python not executable: $PY" >&2; exit 2; }

if [ -z "${HLITH_KL5_REPO:-}" ]; then
  echo "FAIL: HLITH_KL5_REPO is not set (fail-closed: KL5 requires a declared SHA-pinned mirror path)" >&2
  exit 2
fi
[ -d "$HLITH_KL5_REPO" ] || { echo "FAIL: HLITH_KL5_REPO does not exist: $HLITH_KL5_REPO" >&2; exit 2; }

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

run_pytest_exact() {
  local rel_file="$1"
  local min_passed="$2"
  local target="$ROOT/$rel_file"
  if [ ! -f "$target" ]; then
    echo "FAIL: missing test file: $target" >&2
    exit 1
  fi
  local out rc passed
  set +e
  # -m "real or not real": the gate runs EVERY kill-line test, including the real-repository tier (KL5) that the default `pytest`
  # collection deselects; a skipped/deselected test or a count below the floor still FAILS below (case).
  out=$("$PY" -m pytest "$target" -v -m "real or not real" 2>&1)
  rc=$?
  set -e
  echo "$out"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: pytest exited $rc for $rel_file" >&2
    exit "$rc"
  fi
  local summary_line
  summary_line=$(printf '%s\n' "$out" | grep -E '={2,}.* in [0-9]+\.[0-9]+s' | tail -n 1 || true)
  if printf '%s\n' "$out" | grep -qE 'collected 0 items'; then
    echo "FAIL: collected 0 items for $rel_file" >&2
    exit 1
  fi
  if printf '%s\n' "$summary_line" | grep -qiE '\b(skipped|deselected|xfailed|xpassed|xfail|xpass)\b'; then
    echo "FAIL: skipped/deselected/xfail/xpass forbidden in $rel_file ($summary_line)" >&2
    exit 1
  fi
  passed=$(printf '%s\n' "$out" | grep -oE '[0-9]+ passed' | tail -n 1 | grep -oE '[0-9]+' || echo 0)
  if [ "${passed:-0}" -lt "$min_passed" ]; then
    echo "FAIL: vacuous pytest run ($passed < $min_passed passed) for $rel_file" >&2
    exit 1
  fi
}

echo "=== KILL LINE 1: Gate cannot be bypassed by direct write, shell redirect, or fd write ==="
run_pytest_exact "tests/kill_lines/test_kl1_unbypassable_gate.py" 2

echo "=== KILL LINE 2: Derivation cannot return empty obligation set; gate never treats empty as landed ==="
run_pytest_exact "tests/kill_lines/test_kl2_non_empty_obligations.py" 1

echo "=== KILL LINE 3: Verdict 'held' requires bounded evidence and independent blind check ==="
run_pytest_exact "tests/kill_lines/test_kl3_independent_held_check.py" 1

echo "=== KILL LINE 4: 'not-derived' refuses exit 11, never lands, no warning/pass text ==="
run_pytest_exact "tests/kill_lines/test_kl4_not_derived_refuses.py" 1

echo "=== KILL LINE 5: Understanding layer reads arbitrary real external repositories ==="
run_pytest_exact "tests/kill_lines/test_kl5_external_repo_understanding.py" 1

echo "=== KILL LINE 6: Zero scanner/policy/dashboard/auth deps; deterministic L2/L3/L4 ==="
run_pytest_exact "tests/kill_lines/test_kl6_architecture_integrity.py" 1

echo "=== KILL LINE 7: LocalGateService.land enforces MAC, digests, scope, consumption, identity, hostility, and idempotence ==="
run_pytest_exact "tests/kill_lines/test_kl7_gate_service.py" 38

echo "=== GATE PROPERTY INVARIANTS (Hlith.md s5.6 + monotonicity + identity + scope) ==="
run_pytest_exact "tests/property/test_gate_invariants.py" 7

echo "=== IMPORT CYCLE REPORT (informational, non-enforcing) ==="
"$PY" - <<PY
import ast
from collections import defaultdict
from pathlib import Path

root = Path(${ROOT@Q})
src = root / "src" / "hlith"
mods = {}
for p in sorted(src.rglob("*.py")):
    parts = list(p.relative_to(root / "src").with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    mods[".".join(parts)] = p

edges = defaultdict(set)
for m, p in mods.items():
    pkg = m.rsplit(".", 1)[0] if "." in m else "hlith"
    for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "hlith" or a.name.startswith("hlith."):
                    edges[m].add(a.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            base = ".".join(m.split(".")[:-node.level] + ([mod] if mod else [])) if node.level > 0 else mod
            if base == "hlith" or base.startswith("hlith."):
                if (node.level == 1 and not mod) or base == "hlith":
                    for a in node.names:
                        cand = f"{pkg}.{a.name}" if node.level == 1 and not mod else f"hlith.{a.name}"
                        edges[m].add(cand if cand in mods else base)
                else:
                    edges[m].add(base)

idx, indices, low, stack, on, sccs = 0, {}, {}, [], set(), []
def scc(v):
    global idx
    indices[v] = low[v] = idx
    idx += 1
    stack.append(v); on.add(v)
    for w in sorted(edges.get(v, ())):
        if w not in mods:
            continue
        if w not in indices:
            scc(w); low[v] = min(low[v], low[w])
        elif w in on:
            low[v] = min(low[v], indices[w])
    if low[v] == indices[v]:
        comp = []
        while True:
            w = stack.pop(); on.remove(w); comp.append(w)
            if w == v:
                break
        sccs.append(comp)
for m in sorted(mods):
    if m not in indices:
        scc(m)
cycles = [c for c in sccs if len(c) > 1 or c[0] in edges.get(c[0], ())]
print(f"modules={len(mods)} edges={sum(len(v) for v in edges.values())} cycles={cycles}")
PY

echo "ALL SIX SPRINT 1 KILL LINES HELD."
