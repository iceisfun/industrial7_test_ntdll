# Shared helpers for the bbtest namespace checks (POSIX sh; sourced).
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; exit 1; }
note() { echo "NOTE $*"; }
