# The step runs in its own PID namespace with a fresh /proc.
. bbtest/ns/common.sh
[ "$$" -lt 200 ] || fail "pid $$ is not a small namespace-local pid"
comm=$(cat /proc/1/comm)
case "$comm" in systemd|init) fail "/proc/1 is the host init ($comm)" ;; esac
n=$(ls /proc | grep -c '^[0-9][0-9]*$')
[ "$n" -lt 50 ] || fail "/proc lists $n processes; the host pid space is visible"
[ "$(sed -n 's/^NSpid:[[:space:]]*//p' /proc/self/status | wc -w)" -ge 1 ] || fail "no NSpid"
pass "pid ns: self=$$ init=$comm procs=$n"
