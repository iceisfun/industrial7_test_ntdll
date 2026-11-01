# Reports whether the step can open /dev/kvm. EXPECT_KVM: any (report
# only), open (must open), closed (must not open: the Command runner's
# default).
. bbtest/ns/common.sh
exp=${EXPECT_KVM:-any}
if [ ! -e /dev/kvm ]; then st=absent
elif ( exec 3<>/dev/kvm ) 2>/dev/null; then st=open
else st=denied
fi
echo "kvm=$st expect=$exp"
case "$exp:$st" in
  any:*|open:open|closed:absent|closed:denied) pass "kvm $st" ;;
  *) fail "kvm is $st, expected $exp" ;;
esac
