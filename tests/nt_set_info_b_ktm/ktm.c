/* NtSetInformationTransaction / TransactionManager / ResourceManager / Enlistment on volatile kernel
 * transaction manager objects. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtSetInformationTransaction, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationTransaction, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationEnlistment, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationEnlistment, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define OK(s) ((NTSTATUS)(s) >= 0)
#define ST_INV_HANDLE S(0xC0000008)
#define ST_TYPE_MISM  S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_LEN_MISM   S(0xC0000004)
#define ST_INV_CLASS  S(0xC0000003)

static HANDLE mkevent(void)
{
    HANDLE h = NULL;
    if (UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE) != 0) return NULL;
    return h;
}
static HANDLE reduced(HANDLE h, DWORD access)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, FALSE, 0)) return NULL;
    return d;
}

typedef struct { HANDLE tm, rm, tx, en; BOOL ok; } KT;
static const GUID g_rm = { 0x6f1e9a10, 0x4d3a, 0x4a9e, { 0x91, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 } };
static void kt_up(KT *k)
{
    memset(k, 0, sizeof *k);
    if (!UN(NtCreateTransactionManager) || !UN(NtCreateResourceManager) || !UN(NtCreateTransaction) || !UN(NtCreateEnlistment)) { t_skip("KTM exports missing"); return; }
    NTSTATUS s = UN(NtCreateTransactionManager)(&k->tm, 0x1F00FF /*TRANSACTIONMANAGER_ALL_ACCESS*/, NULL, NULL, 1 /*VOLATILE*/, 0);
    if (!OK(s)) { t_skip("cannot create a volatile transaction manager: %08lx", (unsigned long)s); return; }
    k->ok = TRUE;
}
static void kt_down(KT *k)
{
    if (k->en) UN(NtClose)(k->en);
    if (k->tx) { UN(NtRollbackTransaction)(k->tx, TRUE); UN(NtClose)(k->tx); }
    if (k->rm) UN(NtClose)(k->rm);
    if (k->tm) UN(NtClose)(k->tm);
}
#define KSTART() KT k; kt_up(&k); if (!k.ok) return

typedef struct {
    ULONG IsolationLevel, IsolationFlags; LARGE_INTEGER Timeout; ULONG Outcome; ULONG DescriptionLength; WCHAR Description[16];
} TXPROPS;

TEST(set_info_transaction)
{
    KSTART();
    REQUIRE(UN(NtSetInformationTransaction)); REQUIRE(UN(NtQueryInformationTransaction));
    CHECK(t_proc("NtSetInformationTransaction") == t_proc("ZwSetInformationTransaction"));
    /* a NULL transaction-manager handle selects the default (system) manager */
    NTSTATUS s = UN(NtCreateTransaction)(&k.tx, 0x1F003F /*TRANSACTION_ALL_ACCESS*/, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (!OK(s)) { k.tx = NULL; kt_down(&k); return; }
    TXPROPS q; ULONG rl = 0; memset(&q, 0xcc, sizeof q);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 1 /*TransactionPropertiesInformation*/, &q, sizeof q, &rl), 0);
    EXPECT_EQ(q.Timeout.QuadPart, 0);                         /* no timeout by default */
    /* the settable form of class 1 is at least 32 bytes long */
    BYTE si[48]; memset(si, 0, sizeof si);
    for (ULONG l = 0; l < 32; l += 4) EXPECT_EQ(UN(NtSetInformationTransaction)(k.tx, 1, si, l), ST_LEN_MISM);
    *(LONGLONG *)(si + 8) = -100000000LL;                     /* 10 s relative, at the offset of Timeout in the properties layout */
    NTSTATUS st = UN(NtSetInformationTransaction)(k.tx, 1, si, 32);
    EXPECT_EQ(st, 0);
    memset(&q, 0xcc, sizeof q);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 1, &q, sizeof q, &rl), 0);
    EXPECT_EQ(q.Timeout.QuadPart, -100000000LL);
    EXPECT_EQ(rl, 32);
    memset(si, 0, sizeof si);                                 /* a zero Timeout leaves the existing one alone */
    EXPECT_EQ(UN(NtSetInformationTransaction)(k.tx, 1, si, 32), 0);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 1, &q, sizeof q, &rl), 0);
    EXPECT_EQ(q.Timeout.QuadPart, -100000000LL);
    EXPECT_EQ(UN(NtSetInformationTransaction)(k.tx, 0, si, 32), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransaction)(k.tx, 99, si, 32), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationTransaction)(NULL, 1, si, 32), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationTransaction)(ev, 1, si, 32), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = reduced(k.tx, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetInformationTransaction)(ro, 1, si, 32), ST_DENIED); CloseHandle(ro); }
    kt_down(&k);
}
TEST(set_info_transaction_manager)
{
    KSTART();
    REQUIRE(UN(NtSetInformationTransactionManager));
    CHECK(t_proc("NtSetInformationTransactionManager") == t_proc("ZwSetInformationTransactionManager"));
    ULONGLONG lsn = 0;
    /* only the recovery class (3) is settable; every other class is rejected before the handle is looked at */
    static const ULONG bad[] = { 0, 1, 2, 4, 5, 99 };
    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(UN(NtSetInformationTransactionManager)(k.tm, bad[i], &lsn, sizeof lsn), ST_INV_CLASS);
        EXPECT_EQ(UN(NtSetInformationTransactionManager)(NULL, bad[i], &lsn, sizeof lsn), ST_INV_CLASS);
    }
    for (ULONG l = 4; l <= 32; l += 4) EXPECT_EQ(UN(NtSetInformationTransactionManager)(k.tm, 3, &lsn, l), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationTransactionManager)(NULL, 3, &lsn, sizeof lsn), ST_LEN_MISM);   /* size is checked first */
    kt_down(&k);
}
TEST(set_info_resource_manager_enlistment)
{
    KSTART();
    REQUIRE(UN(NtSetInformationResourceManager)); REQUIRE(UN(NtSetInformationEnlistment));
    CHECK(t_proc("NtSetInformationResourceManager") == t_proc("ZwSetInformationResourceManager"));
    CHECK(t_proc("NtSetInformationEnlistment") == t_proc("ZwSetInformationEnlistment"));
    GUID g = g_rm;
    /* a volatile transaction manager only hosts volatile resource managers */
    NTSTATUS s = UN(NtCreateResourceManager)(&k.rm, 0x1F00FF /*RESOURCEMANAGER_ALL_ACCESS*/, k.tm, &g, NULL, 0, NULL);
    EXPECT_EQ(s, S(0xC019003B));
    if (OK(s)) { UN(NtClose)(k.rm); k.rm = NULL; }
    s = UN(NtCreateResourceManager)(&k.rm, 0x1F00FF, k.tm, &g, NULL, 1 /*VOLATILE*/, NULL);
    EXPECT_EQ(s, 0);
    if (!OK(s)) { k.rm = NULL; kt_down(&k); return; }
    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(port != NULL);
    struct { HANDLE port; ULONG_PTR key; } ci = { port, 0x1234 };
    /* class 1 = completion information (port, key): 16 bytes, accepted once per resource manager */
    for (ULONG l = 0; l <= 24; l += 4) if (l != 16) EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, 1, &ci, l), ST_LEN_MISM);
    HANDLE ev = mkevent();
    if (ev) {
        EXPECT_EQ(UN(NtSetInformationResourceManager)(ev, 1, &ci, sizeof ci), ST_TYPE_MISM);
        struct { HANDLE p; ULONG_PTR k; } evp = { ev, 0 };
        EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, 1, &evp, sizeof evp), ST_TYPE_MISM);   /* the port must be an I/O completion port */
    }
    struct { HANDLE p; ULONG_PTR k; } nul = { NULL, 0 };
    EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, 1, &nul, sizeof nul), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(NULL, 1, &ci, sizeof ci), ST_INV_HANDLE);
    HANDLE ro = reduced(k.rm, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetInformationResourceManager)(ro, 1, &ci, sizeof ci), ST_DENIED); CloseHandle(ro); }
    EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, 1, &ci, sizeof ci), 0);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, 1, &ci, sizeof ci), S(0xC0000184));   /* STATUS_INVALID_DEVICE_STATE: already set */
    static const ULONG badc[] = { 0, 2, 3, 99 };
    for (int i = 0; i < 4; i++) EXPECT_EQ(UN(NtSetInformationResourceManager)(k.rm, badc[i], &ci, sizeof ci), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationResourceManager)(NULL, 0, &ci, sizeof ci), ST_INV_CLASS);
    /* enlistments */
    s = UN(NtCreateTransaction)(&k.tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (OK(s)) {
        s = UN(NtCreateEnlistment)(&k.en, 0x1F001F /*ENLISTMENT_ALL_ACCESS*/, k.rm, k.tx, NULL, 0, 0xF, NULL);
        EXPECT_EQ(s, 0);
        if (OK(s)) {
            ULONGLONG ed[2] = { 0, 0 };
            EXPECT_EQ(UN(NtSetInformationEnlistment)(k.en, 1 /*EnlistmentRecoveryInformation*/, ed, 0), ST_INV_PARAM);
            EXPECT_EQ(UN(NtSetInformationEnlistment)(k.en, 1, ed, 8), 0);
            EXPECT_EQ(UN(NtSetInformationEnlistment)(k.en, 1, ed, 16), 0);
            static const ULONG bade[] = { 0, 2, 3, 99 };
            for (int i = 0; i < 4; i++) EXPECT_EQ(UN(NtSetInformationEnlistment)(k.en, bade[i], ed, 8), ST_INV_CLASS);
            EXPECT_EQ(UN(NtSetInformationEnlistment)(NULL, 1, ed, 8), ST_INV_HANDLE);
            if (ev) EXPECT_EQ(UN(NtSetInformationEnlistment)(ev, 1, ed, 8), ST_TYPE_MISM);
            HANDLE ro2 = reduced(k.en, SYNCHRONIZE);
            if (ro2) { EXPECT_EQ(UN(NtSetInformationEnlistment)(ro2, 1, ed, 8), ST_DENIED); CloseHandle(ro2); }
        } else k.en = NULL;
    } else k.tx = NULL;
    if (ev) UN(NtClose)(ev);
    if (port) CloseHandle(port);
    kt_down(&k);
}
