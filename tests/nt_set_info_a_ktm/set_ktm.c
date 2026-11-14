/* Kernel transaction manager setters: NtSetInformationTransaction (success and error paths on a real
 * transaction), NtSetInformationEnlistment, NtSetInformationResourceManager and
 * NtSetInformationTransactionManager (object-type and handle validation).
 */
#include "t.h"

UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtQueryInformationTransaction, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationTransaction, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetInformationEnlistment, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPE_MISM    S(0xC0000024)

typedef struct {
    ULONG IsolationLevel, IsolationFlags;
    LARGE_INTEGER Timeout;
    ULONG Outcome, DescriptionLength;
    WCHAR Description[32];
} tx_props;

static HANDLE make_tx(NTSTATUS *stp)
{
    HANDLE h = NULL; NTSTATUS st;
    if (!UN(NtCreateTransaction)) { *stp = S(0xC0000002); return NULL; }
    st = UN(NtCreateTransaction)(&h, 0x1F003F /* TRANSACTION_ALL_ACCESS */, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    *stp = st;
    return st == 0 ? h : NULL;
}

TEST(set_ktm_alias_pairs)
{
    EXPECT_EQ(t_proc("NtSetInformationTransaction"), t_proc("ZwSetInformationTransaction"));
    EXPECT_EQ(t_proc("NtSetInformationEnlistment"), t_proc("ZwSetInformationEnlistment"));
    EXPECT_EQ(t_proc("NtSetInformationResourceManager"), t_proc("ZwSetInformationResourceManager"));
    EXPECT_EQ(t_proc("NtSetInformationTransactionManager"), t_proc("ZwSetInformationTransactionManager"));
}

TEST(set_transaction_properties)
{
    HANDLE tx; NTSTATUS st; tx_props in, out; ULONG rl = 0; static const WCHAR d[] = L"setinfo-desc";
    REQUIRE(UN(NtSetInformationTransaction)); REQUIRE(UN(NtQueryInformationTransaction));
    tx = make_tx(&st);
    if (!tx) { t_skip("cannot create a transaction (%08lx)", (unsigned long)st); return; }
    memset(&in, 0, sizeof in);
    in.Timeout.QuadPart = -3000000000LL;                       /* 300 s relative */
    in.DescriptionLength = sizeof d - sizeof(WCHAR);
    memcpy(in.Description, d, sizeof d);
    st = UN(NtSetInformationTransaction)(tx, 1 /* TransactionPropertiesInformation */, &in, offsetof(tx_props, Description) + in.DescriptionLength);
    t_note("NtSetInformationTransaction(properties) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    memset(&out, 0, sizeof out);
    st = UN(NtQueryInformationTransaction)(tx, 1, &out, sizeof out, &rl);
    EXPECT_EQ(st, 0);
    t_note("props: iso=%lx timeout=%lld outcome=%lu desclen=%lu", out.IsolationLevel, (long long)out.Timeout.QuadPart, out.Outcome, out.DescriptionLength);
    EXPECT_EQ(out.DescriptionLength, in.DescriptionLength);
    CHECK(memcmp(out.Description, d, in.DescriptionLength) == 0);
    /* errors */
    EXPECT_EQ(UN(NtSetInformationTransaction)(tx, 0x7fff, &in, sizeof in), ST_BAD_CLASS);
    st = UN(NtSetInformationTransaction)(tx, 1, &in, 4);
    t_note("NtSetInformationTransaction(short buffer) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationTransaction)((HANDLE)(ULONG_PTR)0xdeadbee4, 1, &in, sizeof in), ST_INV_HANDLE);
    if (UN(NtRollbackTransaction)) UN(NtRollbackTransaction)(tx, TRUE);
    CloseHandle(tx);
}

/* Settable classes: enlistment 1 (EnlistmentRecoveryInformation), resource manager 1
 * (ResourceManagerCompletionInformation, 16 bytes), transaction manager 3 (recovery), transaction 1 and 4.
 * The class and the buffer length are validated before the handle is resolved. */
TEST(set_ktm_validation_order)
{
    HANDLE ev, tx; NTSTATUS st; ULONG v[16] = { 0 }; HANDLE bad = (HANDLE)(ULONG_PTR)0xdeadbee4;
    REQUIRE(UN(NtSetInformationEnlistment)); REQUIRE(UN(NtSetInformationResourceManager)); REQUIRE(UN(NtSetInformationTransactionManager));
    /* classes that cannot be set */
    EXPECT_EQ(UN(NtSetInformationEnlistment)(bad, 0, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationEnlistment)(bad, 2, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(bad, 0, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(bad, 2, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransactionManager)(bad, 0, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransactionManager)(bad, 1, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransactionManager)(bad, 4, v, 16), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransaction)(bad, 0, v, 16), ST_BAD_CLASS);
    /* length is checked before the handle */
    EXPECT_EQ(UN(NtSetInformationResourceManager)(bad, 1, v, 4), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationTransactionManager)(bad, 3, v, 4), ST_BAD_LENGTH);
    /* then the handle */
    EXPECT_EQ(UN(NtSetInformationEnlistment)(bad, 1, v, 16), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(bad, 1, v, 16), ST_INV_HANDLE);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL);
    if (ev) {
        EXPECT_EQ(UN(NtSetInformationEnlistment)(ev, 1, v, 16), ST_TYPE_MISM);
        EXPECT_EQ(UN(NtSetInformationResourceManager)(ev, 1, v, 16), ST_TYPE_MISM);
        EXPECT_EQ(UN(NtSetInformationTransaction)(ev, 1, v, 32), ST_TYPE_MISM);
        CloseHandle(ev);
    }
    tx = make_tx(&st);
    if (tx) {
        EXPECT_EQ(UN(NtSetInformationEnlistment)(tx, 1, v, 16), ST_TYPE_MISM);
        EXPECT_EQ(UN(NtSetInformationResourceManager)(tx, 1, v, 16), ST_TYPE_MISM);
        if (UN(NtRollbackTransaction)) UN(NtRollbackTransaction)(tx, TRUE);
        CloseHandle(tx);
    }
}
