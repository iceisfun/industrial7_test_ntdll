# Writes an artifact into $BBTEST_OUT_DIR; the daemon hashes and reports it.
. bbtest/ns/common.sh
[ -n "$BBTEST_OUT_DIR" ] && [ -d "$BBTEST_OUT_DIR" ] || fail "BBTEST_OUT_DIR is not a directory"
head -c 1048576 /dev/urandom > "$BBTEST_OUT_DIR/blob.bin"
sha256sum "$BBTEST_OUT_DIR/blob.bin" | cut -d' ' -f1 > "$BBTEST_OUT_DIR/blob.sha256"
[ "$(wc -c < "$BBTEST_OUT_DIR/blob.bin")" -eq 1048576 ] || fail "short blob"
pass "artifact blob.bin $(cat "$BBTEST_OUT_DIR/blob.sha256")"
