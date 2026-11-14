/* Kernel Transaction Manager object queries on a private volatile transaction manager:
 * NtQueryInformationTransactionManager, NtQueryInformationResourceManager,
 * NtQueryInformationTransaction, NtQueryInformationEnlistment. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtQueryInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationTransaction, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationEnlistment, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define TRANSACTION_ALL_ACCESS_ 0x12003F
#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_INV_PARAM    S(0xC000000D)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define CUR_PROC ((HANDLE)(LONG_PTR)-1)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}
TEST(alias_pairs)
{
    static const char *n[] = { "NtQueryInformationTransactionManager", "NtQueryInformationResourceManager",
        "NtQueryInformationTransaction", "NtQueryInformationEnlistment" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

typedef struct { HANDLE tm, rm, tx, en; GUID rmg, uow; int logged; } KT;
static const WCHAR kdesc[] = L"qib resource manager";

/* Builds a volatile TM and RM, a transaction (user-mode callers cannot name a transaction manager: an explicit
 * TmHandle is STATUS_INVALID_PARAMETER, so the transaction belongs to the default manager) and, when asked,
 * tries an enlistment of the transaction in the resource manager. */
static NTSTATUS kt_make(KT *k, int want_enlist)
{
    NTSTATUS st; UNICODE_STRING d; OBJECT_ATTRIBUTES oa;
    memset(k, 0, sizeof *k);
    k->rmg.Data1 = 0x51420001; k->rmg.Data2 = 0x1234; k->rmg.Data3 = 0x4321; memset(k->rmg.Data4, 0x5a, 8);
    k->uow.Data1 = 0x51420002; k->uow.Data2 = 0x1234; k->uow.Data3 = 0x4321; memset(k->uow.Data4, 0xa5, 8);
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    st = UN(NtCreateTransactionManager)(&k->tm, 0x1F00FF /* TRANSACTIONMANAGER_ALL_ACCESS */, &oa, NULL, 1 /* TRANSACTION_MANAGER_VOLATILE */, 0);
    if (st != 0) { t_note("step TM: %08lx", (unsigned long)st); return st; }
    d.Buffer = (PWSTR)kdesc; d.Length = sizeof kdesc - 2; d.MaximumLength = sizeof kdesc;
    st = UN(NtCreateResourceManager)(&k->rm, 0x1F00FF, k->tm, &k->rmg, &oa, 1 /* RESOURCE_MANAGER_VOLATILE */, &d);
    if (st != 0) { t_note("step RM: %08lx", (unsigned long)st); return st; }
    st = UN(NtCreateTransaction)(&k->tx, 0x1F003F /* TRANSACTION_ALL_ACCESS */, &oa, &k->uow, NULL, 0, 0, 0, NULL, NULL);
    if (st != 0) { t_note("step TX: %08lx", (unsigned long)st); return st; }
    if (want_enlist) {
        st = UN(NtCreateEnlistment)(&k->en, 0xF003F /* ENLISTMENT_ALL_ACCESS */, k->rm, k->tx, &oa, 0, 0, NULL);
        t_note("enlistment of a default-manager transaction in a private resource manager: %08lx", (unsigned long)st);
        if (st != 0) { k->en = NULL; return S(0x40000000); }
    }
    return st;
}
static void kt_free(KT *k)
{
    if (k->en) UN(NtClose)(k->en);
    if (k->tx) { UN(NtRollbackTransaction)(k->tx, FALSE); UN(NtClose)(k->tx); }
    if (k->rm) UN(NtClose)(k->rm);
    if (k->tm) UN(NtClose)(k->tm);
}
#define KT_START(k, en) KT k; do { NTSTATUS st_; if (!UN(NtCreateTransactionManager) || !UN(NtCreateResourceManager) || !UN(NtCreateTransaction) || !UN(NtCreateEnlistment)) { t_skip("KTM export missing"); return; } \
    st_ = kt_make(&k, en); if (st_ != 0) { kt_free(&k); t_skip("cannot build a volatile transaction manager chain: %08lx", (unsigned long)st_); return; } } while (0)

TEST(query_transaction_manager)
{
    BYTE buf[64]; ULONG ret; GUID g;
    REQUIRE(UN(NtQueryInformationTransactionManager));
    KT_START(k, 0);
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0, buf, 24, &ret), 0);
    EXPECT_EQ(ret, 24);
    memcpy(&g, buf, 16);
    { static const GUID zero; CHECK(memcmp(&g, &zero, 16) != 0); }
    { ULONG ret2; BYTE b2[24]; EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0, b2, 24, &ret2), 0); CHECK(!memcmp(b2, buf, 16)); }   /* identity is stable */
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0, buf, 23, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0, buf, 25, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0, buf, 0, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0x100, buf, 24, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.tm, 0xFFFF, buf, 24, &ret), ST_INV_CLASS);
    OBS("log info", UN(NtQueryInformationTransactionManager)(k.tm, 1, buf, 64, &ret));
    OBS("recovery info", UN(NtQueryInformationTransactionManager)(k.tm, 3, buf, 8, &ret));
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(NULL, 0, buf, 24, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(CUR_PROC, 0, buf, 24, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(k.rm, 0, buf, 24, &ret), ST_TYPE_MISM);
    { HANDLE d = NULL; EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, k.tm, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
      if (d) { EXPECT_EQ(UN(NtQueryInformationTransactionManager)(d, 0, buf, 24, &ret), ST_DENIED); UN(NtClose)(d); } }
    kt_free(&k);
}

TEST(query_resource_manager)
{
    BYTE buf[128]; ULONG ret;
    REQUIRE(UN(NtQueryInformationResourceManager));
    KT_START(k, 0);
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(k.rm, 0, buf, sizeof buf, &ret), 0);
    CHECK(!memcmp(buf, &k.rmg, 16));                         /* ResourceManagerId is the supplied GUID */
    EXPECT_EQ(*(ULONG *)(buf + 16), sizeof kdesc - 2);
    CHECK(!memcmp(buf + 20, kdesc, sizeof kdesc - 2));
    t_note("RM basic ret=%lu", ret);
    EXPECT_EQ(ret, 20 + sizeof kdesc - 2);
    /* too small for the fixed part, then truncated description */
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(k.rm, 0, buf, 19, &ret), S(0xC0000023));   /* STATUS_BUFFER_TOO_SMALL */
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(k.rm, 0, buf, 22, &ret), S(0xC0000023));
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(k.rm, 0x100, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(NULL, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationResourceManager)(k.tm, 0, buf, sizeof buf, &ret), ST_TYPE_MISM);
    { HANDLE d = NULL; EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, k.rm, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
      if (d) { EXPECT_EQ(UN(NtQueryInformationResourceManager)(d, 0, buf, sizeof buf, &ret), ST_DENIED); UN(NtClose)(d); } }
    kt_free(&k);
}

TEST(query_transaction)
{
    BYTE buf[128]; ULONG ret;
    REQUIRE(UN(NtQueryInformationTransaction));
    KT_START(k, 0);
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 0, buf, 24, &ret), 0);
    EXPECT_EQ(ret, 24);
    CHECK(!memcmp(buf, &k.uow, 16));                         /* TransactionId is the supplied unit-of-work GUID */
    EXPECT_EQ(*(ULONG *)(buf + 16), 1);                      /* TransactionStateNormal */
    EXPECT_EQ(*(ULONG *)(buf + 20), 1);                      /* TransactionOutcomeUndetermined */
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 0, buf, 23, &ret), ST_LEN_MISMATCH);
    /* TransactionPropertiesInformation (1) */
    memset(buf, 0xcc, sizeof buf);
    OBS("properties", UN(NtQueryInformationTransaction)(k.tx, 1, buf, sizeof buf, &ret)); t_note("  ret=%lu", ret);
    OBS("enlistments", UN(NtQueryInformationTransaction)(k.tx, 2, buf, sizeof buf, &ret)); t_note("  ret=%lu", ret);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 0x100, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(NULL, 0, buf, 24, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tm, 0, buf, 24, &ret), ST_TYPE_MISM);
    /* after rollback the state changes */
    EXPECT_EQ(UN(NtRollbackTransaction)(k.tx, TRUE), 0);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(k.tx, 0, buf, 24, &ret), 0);
    t_note("after rollback: state=%lu outcome=%lu", *(ULONG *)(buf + 16), *(ULONG *)(buf + 20));
    EXPECT_EQ(*(ULONG *)(buf + 20), 3);                      /* TransactionOutcomeAborted */
    { HANDLE d = NULL; EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, k.tx, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
      if (d) { EXPECT_EQ(UN(NtQueryInformationTransaction)(d, 0, buf, 24, &ret), ST_DENIED); UN(NtClose)(d); } }
    kt_free(&k);
}

TEST(query_enlistment)
{
    BYTE buf[128]; ULONG ret; OBJECT_ATTRIBUTES oa; NTSTATUS st;
    REQUIRE(UN(NtQueryInformationEnlistment));
    KT_START(k, 0);
    /* error paths that do not need an enlistment */
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(NULL, 0, buf, 48, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationEnlistment)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, 48, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(k.tx, 0, buf, 48, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(k.rm, 0, buf, 48, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(CUR_PROC, 0, buf, 48, &ret), ST_TYPE_MISM);
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    st = UN(NtCreateEnlistment)(&k.en, 0xF003F /* ENLISTMENT_ALL_ACCESS */, k.rm, k.tx, &oa, 0, 0, NULL);
    t_note("enlistment of a default-manager transaction in a private resource manager: %08lx", (unsigned long)st);
    if (st != 0) { k.en = NULL; kt_free(&k); t_skip("enlistment cannot be created from user mode with a private transaction manager: %08lx", (unsigned long)st); return; }
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(k.en, 0, buf, 48, &ret), 0);
    EXPECT_EQ(ret, 48);
    { static const GUID zero; CHECK(memcmp(buf, &zero, 16) != 0); }       /* EnlistmentId */
    CHECK(!memcmp(buf + 16, &k.uow, 16));                                 /* TransactionId */
    CHECK(!memcmp(buf + 32, &k.rmg, 16));                                 /* ResourceManagerId */
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(k.en, 0, buf, 47, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationEnlistment)(k.en, 0x100, buf, sizeof buf, &ret), ST_INV_CLASS);
    { HANDLE d = NULL; EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, k.en, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
      if (d) { EXPECT_EQ(UN(NtQueryInformationEnlistment)(d, 0, buf, 48, &ret), ST_DENIED); UN(NtClose)(d); } }
    kt_free(&k);
}
