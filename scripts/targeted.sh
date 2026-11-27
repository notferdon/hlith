#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/targeted.sh — Fast (<90s) discriminating security + gate must-not-break test runner
#
# Enforces the core invariant suite per merge:
#   - tests/test_sandbox_escapes.py (kernel confinement, Landlock, read-only target, signal/proc isolation)
#   - tests/test_gate.py (gate decision invariants, non-empty obligations, independent proof, atomic journal & rollback)
#   - tests/test_escapes_adversarial.py (all 19 independent findings: sockets, TIOCSTI, PID ns, stat disclosure,
#                                       CRLF/quoted-diff bypasses, symlink cycle ELOOP, non-utf8 diff, deep dir PATH_MAX)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Hlith Targeted Must-Not-Break Gate Suite ==="
echo "Working directory: $REPO_ROOT"
START_TIME=$(date +%s)

# Run with python/uv environment
if command -v uv >/dev/null 2>&1; then
    PYTEST_CMD=(uv run --frozen pytest)
else
    PYTEST_CMD=(pytest)
fi

TARGETED_FILES=(
    "tests/test_sandbox_escapes.py"
    "tests/test_gate.py"
    "tests/test_escapes_adversarial.py"
)

echo "Executing: ${PYTEST_CMD[*]} -q ${TARGETED_FILES[*]} $*"
"${PYTEST_CMD[@]}" -q "${TARGETED_FILES[@]}" "$@"
RC=$?

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "================================================="
if [ $RC -eq 0 ]; then
    echo "STATUS: ALL TARGETED TESTS PASSED (${DURATION}s < 90s budget)"
else
    echo "STATUS: TARGETED SUITE FAILED (exit code: $RC, ${DURATION}s)"
fi
echo "================================================="

exit $RC
