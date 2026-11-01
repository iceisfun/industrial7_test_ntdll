# Chain link: $1 is the link name. Records when it ran.
. bbtest/ns/common.sh
[ -n "$1" ] || fail "no link name"
date +%s > "$BBTEST_OUT_DIR/stamp-$1"
pass "link $1 at $(cat "$BBTEST_OUT_DIR/stamp-$1")"
