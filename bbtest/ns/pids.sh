# The profile caps pids.max at 64: starting 200 sleepers must fail early.
# The spawner records progress with builtins only (a full cgroup cannot
# fork even `cat`), and the sleepers expire on their own.
. bbtest/ns/common.sh
f=${BBTEST_OUT_DIR:-/tmp}/pids-count.$$
: > "$f"
sh -c 'i=0; while [ $i -lt 200 ]; do sleep 4 & i=$((i+1)); echo $i > '"$f"'; done; wait' >/dev/null 2>&1
read n < "$f"
n=${n:-0}
echo "sleepers started: $n"
[ "$n" -ge 1 ] || fail "no sleeper started at all"
[ "$n" -lt 200 ] || fail "all 200 sleepers started: pids.max did not cap the cgroup"
[ "$n" -le 64 ] || fail "$n sleepers: more than pids.max"
pass "pids limit held at $n"
