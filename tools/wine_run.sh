#!/usr/bin/env bash
# Run one test exe under Wine in a throw-away, HEADLESS sandbox.
#   tools/wine_run.sh build/<area>.exe [name-filter]
# - fresh copy of the base prefix per run (tests cannot pollute each other or your real prefix)
# - no X: DISPLAY/WAYLAND_DISPLAY are unset so Wine uses its built-in null display driver; this keeps
#   the main X session untouched (many parallel wine runs with persistent explorer.exe exhausted the X
#   server's client slots before). Set TP_DISPLAY=xephyr to run inside a nested Xephyr server instead
#   (only for tests that genuinely need a display driver); the nested server is torn down afterwards.
# - hard timeout, and the prefix's wineserver and children are killed + the prefix removed afterwards.
set -euo pipefail
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then echo "usage: $0 executable [filter]" >&2; exit 2; fi
EXE="$1"; FILTER="${2:-}"
WINE="${WINE:-$HOME/work/wine/proton-ge-custom/build/dist/files/bin/wine}"
BASE="${TP_BASE_PREFIX:-$HOME/.cache/test_pattern/prefix}"
TMO="${TP_TIMEOUT:-600}"
[ -d "$BASE/drive_c" ] || "$(dirname "$0")/make_base_prefix.sh" >&2
RUN="$(mktemp -d "${TMPDIR:-/tmp/opencode}/tp_prefix.XXXXXX")"
cleanup() {
  WINEPREFIX="$RUN" "$(dirname "$WINE")/wineserver" -k 2>/dev/null || true
  WINEPREFIX="$RUN" timeout 10 "$(dirname "$WINE")/wineserver" -w 2>/dev/null || true
  rm -rf "$RUN"
  if [ -n "${XEPID:-}" ]; then kill "$XEPID" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp -a --reflink=auto "$BASE/." "$RUN/"
ENVV=(WINEPREFIX="$RUN" WINEARCH=win64 WINEDEBUG="${WINEDEBUG:--all}")
if [ "${TP_DISPLAY:-none}" = "xephyr" ]; then
  N=$((100 + RANDOM % 800)); Xephyr ":$N" -screen 1024x768 -nolisten tcp >/dev/null 2>&1 & XEPID=$!
  sleep 1; ENVV+=(DISPLAY=":$N")
  env -u WAYLAND_DISPLAY "${ENVV[@]}" timeout --kill-after=5 "$TMO" "$WINE" "$EXE" ${FILTER:+"$FILTER"}
else
  env -u DISPLAY -u WAYLAND_DISPLAY "${ENVV[@]}" timeout --kill-after=5 "$TMO" "$WINE" "$EXE" ${FILTER:+"$FILTER"}
fi
