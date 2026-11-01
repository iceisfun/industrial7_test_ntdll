#!/bin/sh
# Manual stand-in for the oracle job until bbtestd has an oracle runner:
# build -> pack payload -> win10vm.sh under the lab lock -> convert the serial log.
#
#   WIN10VM=/path/to/win10vm.sh oracle_local.sh <corpus-checkout> <mode std|adm> <outdir> [timeout_s]
#
# Needs x86_64-w64-mingw32-gcc, make, python3 and the pinned Win10 base image
# (win10vm.sh's own WIN10_* environment applies). LOCK defaults to a per-user file.
set -eu
[ $# -ge 3 ] || { sed -n '2,8p' "$0"; exit 2; }
src=$1 mode=$2 out=$3 tmo=${4:-900}
here=$(cd "$(dirname "$0")" && pwd)
: "${WIN10VM:?set WIN10VM to win10vm.sh}"
lock=${LOCK:-${XDG_RUNTIME_DIR:-/tmp}/ntdll-oracle.lock}
mkdir -p "$out"
make -C "$src" -j8 CFLAGS='-O1 -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wl,--no-insert-timestamp' >"$out/make.log" 2>&1
python3 "$here/pack_payload.py" artifact --build-dir "$src/build" --out "$out"
rm -rf "$out/payload"
python3 "$here/pack_payload.py" payload --build "$out/ntdll-build.tar" --mode "$mode" --out "$out/payload"
id=ntdllq-$mode-$$
rc=0
flock -w 7200 "$lock" "$WIN10VM" run --payload "$out/payload" --shutdown --timeout "$tmo" --id "$id" || rc=$?
echo "win10vm exit $rc"
root=${I7_ROOT:-$(git -C "$(dirname "$WIN10VM")" rev-parse --show-toplevel)}
log=$root/target/win10vm/runs/$id/serial.log
[ -f "$log" ] || { echo "no serial log at $log" >&2; exit 65; }
cp "$log" "$out/oracle-$mode.serial.log"
python3 "$here/ntdll_result.py" convert --serial "$out/oracle-$mode.serial.log" \
  --out "$out" --prefix "oracle-$mode." --require-payload-exit --exit-zero
