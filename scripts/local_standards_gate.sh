#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The bounded standards gate for Hlith Review. .github/workflows/standards.yml runs exactly this script, and so does a person
# locally; GitHub Actions is dispatch-only and disabled for the public repository. It checks the exported
# tree, not the working copy: it exports COMMIT with `git archive` (the curated public view, see docs/STAGING-VIEW.md) and runs:
# standards checks, a named Review-product test group (REVIEW_TESTS below, with retired tests skipped one by one with
# their reason), and the kill lines. It is not a whole-suite result.
#
# usage: scripts/local_standards_gate.sh [COMMIT]         (default: HEAD)
#
# environment:
#   HLITH_KL5_REPO      REQUIRED. A psf/requests clone checked out (detached) at 0e322af87745eff34caffe4df68456ebc20d9068.
#                       The workflow clones it from GitHub; this script never touches the network for it.
#   HLITH_GATE_OUT      Output directory (default: a new mktemp -d under ${TMPDIR:-/tmp}). The export lands in $HLITH_GATE_OUT/view.
#   HLITH_GATE_PYTHON   Python for `uv sync` (default 3.13.9, the measured interpreter; the workflow file says 3.12).
#   HLITH_PYTHON        Reuse an existing interpreter instead of `uv sync`. Its environment must hold the locked dependencies;
#                       `hlith` is imported from the export's src/ (asserted), never from the interpreter's own install.
#
# exit: 0 all steps passed; 4 host lacks Landlock ABI >= 6 or unprivileged user namespaces (standards ran, kill lines NOT
# run: a BOUNDARY, not a pass); 2 usage/setup; any other nonzero: the failing step's status.
# Bound it the way the workstation bounds tests, e.g.:
#   systemd-run --user --pipe --wait -p MemoryMax=1G -p MemorySwapMax=0 -p CPUQuota=100% \
#     --working-directory="$PWD" -E HOME="$HOME" -E PATH="$PATH" -E HLITH_KL5_REPO=... scripts/local_standards_gate.sh HEAD
set -euo pipefail

KL5_SHA=0e322af87745eff34caffe4df68456ebc20d9068
# The supported Review product, by name. Changing this list changes what the gate claims: say so in the review request.
REVIEW_TESTS=(
  tests/test_review_product.py tests/test_review_contract_suite.py tests/test_review_surface_case3.py
  tests/test_public_claims_case2.py tests/test_packaging_first_use.py tests/test_cli_recover_pending.py
  tests/test_engine_hash_flags.py tests/test_git_feature_and_boundary.py tests/test_obsolete_census.py
)
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="${1:-HEAD}"
step() { printf '\n=== local gate: %s ===\n' "$*"; }
die() { echo "local gate FAIL: $*" >&2; exit "${2:-2}"; }

git -C "$SRC" rev-parse --verify --quiet "$COMMIT^{commit}" >/dev/null || die "not a commit: $COMMIT"
FULL=$(git -C "$SRC" rev-parse "$COMMIT^{commit}")
[ -n "${HLITH_KL5_REPO:-}" ] || die "HLITH_KL5_REPO is not set (requests clone at $KL5_SHA)"
[ "$(git -C "$HLITH_KL5_REPO" rev-parse HEAD 2>/dev/null || true)" = "$KL5_SHA" ] || die "HLITH_KL5_REPO HEAD is not $KL5_SHA"

OUT="${HLITH_GATE_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/caseXXXXXX")}"
VIEW="$OUT/view"
[ ! -e "$VIEW" ] || die "$VIEW already exists; choose a new HLITH_GATE_OUT"
mkdir -p "$VIEW"

step "export $FULL"
git -C "$SRC" archive --format=tar "$FULL" | tar -x -C "$VIEW"
FILES=$(cd "$VIEW" && find . -type f | wc -l)
echo "commit $FULL; exported files: $FILES; export: $VIEW"
cd "$VIEW"

step "environment"
if [ -n "${HLITH_PYTHON:-}" ]; then
  PY="$HLITH_PYTHON"
  uv lock --check
else
  uv lock --check
  uv sync --frozen --python "${HLITH_GATE_PYTHON:-3.13.9}"
  PY="$VIEW/.venv/bin/python"
fi
[ -x "$PY" ] || die "python not executable: $PY"
export PYTHONPATH="$VIEW/src"
"$PY" - "$VIEW" <<'PY'
import sys, pathlib, hlith
where = pathlib.Path(hlith.__file__).resolve()
view = pathlib.Path(sys.argv[1]).resolve()
print(f"python {sys.version.split()[0]}; hlith from {where}")
if view not in where.parents:
    sys.exit(f"hlith is not imported from the export ({where})")
PY

step "host facts"
set +e
"$PY" - <<'PY'
import sys
sys.path.insert(0, "tests")
from host_gate import host_facts
f = host_facts()
print(f"landlock: {f['landlock']}; userns: {f['userns_detail']}; supported: {f['supported']}")
for r in f["reasons"]:
    print(f"  unsupported: {r}")
sys.exit(0 if f["supported"] else 4)
PY
HOST=$?
set -e
[ "$HOST" -eq 0 ] || [ "$HOST" -eq 4 ] || die "host probe failed ($HOST)"

step "fail-closed standards checks"
test -d tests/standards
"$PY" scripts/check_standards.py
"$PY" scripts/check_term_lock.py
"$PY" scripts/check_layer_dag.py
"$PY" scripts/check_no_vacuous.py
RETIRED=$("$PY" - <<'PY'
import sys
sys.path.insert(0, "tests")
from obsolete_census import OBSOLETE
print(len(OBSOLETE))
PY
)
if [ "$HOST" -ne 0 ]; then
  # tests/conftest.py stops a session that selects `confinement` tests on this host; run only the host-independent ones.
  "$PY" -m pytest -q -p no:cacheprovider -m "not real and not confinement" tests/standards
  step "Review product, host-independent part ($RETIRED retired tests named in tests/obsolete_census.py)"
  "$PY" -m pytest -q -p no:cacheprovider -rs -m "not real and not confinement" "${REVIEW_TESTS[@]}"
  echo "local gate BOUNDARY: host-independent standards and Review tests passed; confinement tests and kill lines NOT run" \
       "(host lacks required confinement). This is not a pass." >&2
  exit 4
fi
"$PY" -m pytest -q -p no:cacheprovider tests/standards

step "Review product ($RETIRED retired tests named in tests/obsolete_census.py are skipped with their reason)"
"$PY" -m pytest -q -p no:cacheprovider -rs "${REVIEW_TESTS[@]}"

step "kill lines (scripts/verify_kill_lines.sh)"
HLITH_PYTHON="$PY" scripts/verify_kill_lines.sh

step "result"
echo "local gate PASSED: commit $FULL, $FILES exported files: standards, named Review tests, kill lines (not a whole-suite result)"
