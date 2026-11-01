# Mount namespace: the daemon state dir is hidden under a 4 KiB tmpfs and
# the daemon key file is a /dev/null bind.
. bbtest/ns/common.sh
grep -q ' - tmpfs .*size=4k' /proc/self/mountinfo || fail "no 4 KiB tmpfs in mountinfo"
grep -q ' /null .* devtmpfs ' /proc/self/mountinfo || grep -q ' /null .* tmpfs ' /proc/self/mountinfo \
  || fail "no /dev/null bind mount over a file in mountinfo"
for d in /StorageScratch/bbtestd/state /var/lib/bbtestd; do
  if [ -d "$d" ]; then
    [ -z "$(ls -A "$d" 2>/dev/null)" ] || fail "$d is not empty"
  fi
done
pass "mount ns: state hidden, key bound to /dev/null"
