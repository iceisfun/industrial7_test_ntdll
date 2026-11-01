# Network namespace: loopback only, nothing reachable.
. bbtest/ns/common.sh
ifs=$(sed -n 's/^[[:space:]]*\([^:]*\):.*/\1/p' /proc/net/dev | tr -d ' ' | grep -v '^Inter\|^face' | sort | tr '\n' ' ')
[ "$ifs" = "lo " ] || fail "interfaces are [$ifs], expected only lo"
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY' || fail "an external connect succeeded or hung"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("192.0.2.1", 53))
except OSError:
    sys.exit(0)
sys.exit(1)
PY
else
  note "python3 absent: connect probe skipped"
fi
pass "net ns: only lo"
