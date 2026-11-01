# Allocates far over the profile memory limit. The cgroup OOM kill ends the
# pipeline (the daemon classifies the attempt as error/oom from the cgroup's
# oom_kill counter); surviving it means the limit did not hold.
echo "allocating 1.5 GiB in a 512 MiB cgroup"
if head -c 1610612736 /dev/zero | tr '\0' x | sed 's/y/z/' > /dev/null; then
  echo "NOT KILLED: the memory limit did not hold"
  exit 0
fi
echo "allocation was killed"
exit 1
