#!/usr/bin/env bash
# One command: open the real `hlith ui` on a PUBLIC pinned repository (psf/requests) with a real upstream change left as UNCOMMITTED work,
# so the first thing the operator sees is exactly one consequential change to check. Disposable clone only; nothing is pushed or landed
# anywhere you care about; the mirror is only read.
#   scripts/dogfood.sh                 the recorded case (requests 3fd309a, super_len on str: the engine must catch it)
#   scripts/dogfood.sh SHA             any other upstream commit of the mirror (small plain function change works best)
#   HLITH_DOGFOOD_NO_UI=1 ...          build the clone and print its path, do not open the UI
#   HLITH_REQUESTS_MIRROR=PATH         pinned mirror (default: the restored v2.32.3 mirror)
#   HLITH_TARGET_PYTHON=PATH           interpreter that can import the repo's dependencies and pytest
set -eu
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
SHA="${1:-3fd309a}"
PY="${HLITH_TARGET_PYTHON:-$(command -v python3 || command -v python || true)}"
M="${HLITH_REQUESTS_MIRROR:-}"
if [ -z "$M" ]; then
  TMP_ROOT="$(python3 -c 'import tempfile; print(tempfile.gettempdir())')"
  c="$TMP_ROOT/hlith-acc/requests"
  [ -d "$c/.git" ] && M="$c"
fi
[ -n "$M" ] && [ -d "$M/.git" ] || { echo "no requests mirror found (set HLITH_REQUESTS_MIRROR)"; exit 2; }
[ -x "$PY" ] && "$PY" -c "import pytest, requests" 2>/dev/null || { echo "$PY cannot import pytest and requests (set HLITH_TARGET_PYTHON)"; exit 2; }
git -C "$M" cat-file -e "$SHA^{commit}" 2>/dev/null || { echo "commit $SHA is not in the mirror $M"; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/dogfood-XXXXXX")"
R="$T/requests"
git clone -q --no-hardlinks "$M" "$R"
git -C "$R" checkout -q -B trial "$SHA^"
git -C "$R" remote remove origin
git -C "$M" diff "$SHA^" "$SHA" > "$T/change.patch"
git -C "$R" apply "$T/change.patch"          # the upstream change, applied but NOT committed: this is "the change under review"
git -C "$R" config user.name hlith-dogfood; git -C "$R" config user.email dogfood@invalid.local
mkdir -p "$T/state"
if [ "${HLITH_DOGFOOD_NO_UI:-}" = "1" ]; then
  echo "$R"
  exit 0
fi
cat <<EOF
Hlith dogfood: public repo psf/requests, upstream change $SHA applied as uncommitted work in a disposable clone.
  clone: $R      state (runs, artifacts): $T/state
  Keys inside the screen: arrows/enter to move, ? for help, q to quit (a run keeps going if you quit).
Starting hlith ui...
EOF
export HLITH_UI_STATE="$T/state"
cd "$R"
exec uv run --frozen --project "$ROOT" hlith ui --repo "$R" --target-python "$PY"
