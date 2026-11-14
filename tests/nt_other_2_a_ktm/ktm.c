/* Kernel transaction manager calls: rollback / recover / rollforward / enlistment completion / registry
 * transaction rollback, argument validation first, then a volatile transaction manager, resource manager,
 * transaction and enlistment chain.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_TYPE_MISM    S(0xC0000024)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)

UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtRecoverTransactionManager, (HANDLE));
UDECL(NTSTATUS, NtRollforwardTransactionManager, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtRenameTransactionManager, (PUNICODE_STRING, GUID *));
UDECL(NTSTATUS, NtRollbackComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtRollbackEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtSinglePhaseReject, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtRollbackRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, NtThawTransactions, (void));
UDECL(NTSTATUS, NtThawRegistry, (void));
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, GUID *, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, GUID *, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtCreateRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)
#define N(call) ((NTSTATUS)(call))
#define NOTE(call) do { NTSTATUS st_ = (call); t_note(#call " -> 0x%lx", (unsigned long)st_); } while (0)

TEST(ktm_invalid_handles)
{
    REQUIRE(UN(NtRollbackTransaction)); REQUIRE(UN(NtRecoverTransactionManager)); REQUIRE(UN(NtRollforwardTransactionManager));
    REQUIRE(UN(NtRollbackComplete)); REQUIRE(UN(NtRollbackEnlistment)); REQUIRE(UN(NtSinglePhaseReject)); REQUIRE(UN(NtRollbackRegistryTransaction));
    LARGE_INTEGER zero = {0};
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE hs[2] = { BOGUS, ev };
    NTSTATUS want[2] = { ST_INV_HANDLE, ST_TYPE_MISM };
    for (int i = 0; i < 2; i++) {
        EXPECT_ST(UN(NtRollbackTransaction)(hs[i], TRUE), want[i]);
        EXPECT_ST(UN(NtRollbackTransaction)(hs[i], FALSE), want[i]);
        EXPECT_ST(UN(NtRecoverTransactionManager)(hs[i]), want[i]);
        EXPECT_ST(UN(NtRollforwardTransactionManager)(hs[i], NULL), want[i]);
        EXPECT_ST(UN(NtRollforwardTransactionManager)(hs[i], &zero), want[i]);
        EXPECT_ST(UN(NtRollbackComplete)(hs[i], NULL), want[i]);
        EXPECT_ST(UN(NtRollbackEnlistment)(hs[i], NULL), want[i]);
        EXPECT_ST(UN(NtSinglePhaseReject)(hs[i], NULL), want[i]);
        EXPECT_ST(UN(NtRollbackRegistryTransaction)(hs[i], 0), want[i]);
    }
    EXPECT_ST(UN(NtRollbackTransaction)(NULL, TRUE), ST_INV_HANDLE);
    CloseHandle(ev);
    CHECK(t_proc("NtRollbackTransaction") == t_proc("ZwRollbackTransaction"));
    CHECK(t_proc("NtRecoverTransactionManager") == t_proc("ZwRecoverTransactionManager"));
    CHECK(t_proc("NtRollforwardTransactionManager") == t_proc("ZwRollforwardTransactionManager"));
    CHECK(t_proc("NtRollbackComplete") == t_proc("ZwRollbackComplete"));
    CHECK(t_proc("NtRollbackEnlistment") == t_proc("ZwRollbackEnlistment"));
    CHECK(t_proc("NtSinglePhaseReject") == t_proc("ZwSinglePhaseReject"));
    CHECK(t_proc("NtRollbackRegistryTransaction") == t_proc("ZwRollbackRegistryTransaction"));
}

TEST(ktm_rename_manager_errors)
{
    REQUIRE(UN(NtRenameTransactionManager)); REQUIRE(UN(RtlInitUnicodeString));
    UNICODE_STRING nm; UN(RtlInitUnicodeString)(&nm, L"\\??\\C:\\NoSuchDir_NtOther2a\\log");
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    NTSTATUS st = UN(NtRenameTransactionManager)(&nm, &g);
    t_note("NtRenameTransactionManager(missing log) -> 0x%lx", (unsigned long)st);
    CHECK(st < 0);
    CHECK(t_proc("NtRenameTransactionManager") == t_proc("ZwRenameTransactionManager"));
}

TEST(ktm_volatile_manager)
{
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtCreateTransaction));
    REQUIRE(UN(NtRecoverTransactionManager)); REQUIRE(UN(NtRollforwardTransactionManager));
    HANDLE tm = NULL, rm = NULL, tx = NULL;
    NTSTATUS st = UN(NtCreateTransactionManager)(&tm, 0x1F003F, NULL, NULL, 1 /*TRANSACTION_MANAGER_VOLATILE*/, 0);
    if (st) { t_skip("NtCreateTransactionManager(volatile) status 0x%lx", (unsigned long)st); return; }
    /* a volatile manager has no log: it cannot host resource managers, be recovered or rolled forward */
    GUID rg = { 0x7a2b1c3d, 0x1111, 0x2222, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    UNICODE_STRING desc; UN(RtlInitUnicodeString)(&desc, L"NtOther2aRM");
    EXPECT_ST(UN(NtCreateResourceManager)(&rm, 0x1F003F, tm, &rg, NULL, 0, &desc), S(0xC019003B)); /* STATUS_TM_VOLATILE */
    EXPECT_ST(UN(NtRecoverTransactionManager)(tm), S(0xC019003B));
    LARGE_INTEGER zero = {0};
    EXPECT_ST(UN(NtRollforwardTransactionManager)(tm, &zero), S(0xC019003B));
    /* transactions cannot be created under it through the plain create call */
    EXPECT_ST(UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, tm, 0, 0, 0, NULL, NULL), ST_INV_PARAM);
    UN(NtClose)(tm);
}

TEST(ktm_logged_manager_chain)
{
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtCreateTransaction));
    REQUIRE(UN(NtCreateEnlistment)); REQUIRE(UN(NtRollbackTransaction)); REQUIRE(UN(NtRecoverTransactionManager));
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "tmlog");
    WCHAR nt[MAX_PATH + 16] = L"\\??\\"; WCHAR w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, p, -1, w, MAX_PATH);
    wcscat(nt, w);
    UNICODE_STRING log; UN(RtlInitUnicodeString)(&log, nt);
    HANDLE tm = NULL, rm = NULL, tx = NULL, en = NULL;
    NTSTATUS st = UN(NtCreateTransactionManager)(&tm, 0x1F003F, NULL, &log, 0, 0);
    t_note("NtCreateTransactionManager(logged) -> 0x%lx", (unsigned long)st);
    if (st) { t_skip("logged transaction manager cannot be created here (status 0x%lx)", (unsigned long)st); return; }
    GUID rg = { 0x7a2b1c3e, 0x1111, 0x2222, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    UNICODE_STRING desc; UN(RtlInitUnicodeString)(&desc, L"NtOther2aRM");
    EXPECT_ST(UN(NtCreateResourceManager)(&rm, 0x1F003F, tm, &rg, NULL, 0, &desc), 0);
    EXPECT_ST(UN(NtRecoverTransactionManager)(tm), 0);
    LARGE_INTEGER zero = {0};
    EXPECT_ST(UN(NtRollforwardTransactionManager)(tm, &zero), 0);
    GUID uow = { 0x5a5a5a5a, 0x1234, 0x5678, { 9, 9, 9, 9, 1, 2, 3, 4 } };
    st = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, &uow, tm, 0, 0, 0, NULL, NULL);
    t_note("NtCreateTransaction(tm, uow) -> 0x%lx", (unsigned long)st);
    if (tx && rm) {
        st = UN(NtCreateEnlistment)(&en, 0x1F003F, rm, tx, NULL, 0, 0x3FFFFFFF, NULL);
        t_note("NtCreateEnlistment -> 0x%lx", (unsigned long)st);
    }
    if (en) {
        NOTE(UN(NtSinglePhaseReject)(en, NULL));
        NOTE(UN(NtRollbackEnlistment)(en, NULL));
        NOTE(UN(NtRollbackComplete)(en, NULL));
    }
    if (tx) NOTE(UN(NtRollbackTransaction)(tx, TRUE));
    if (en) UN(NtClose)(en);
    if (tx) UN(NtClose)(tx);
    if (rm) UN(NtClose)(rm);
    UN(NtClose)(tm);
}

TEST(ktm_standalone_transaction_rollback)
{
    REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtRollbackTransaction));
    HANDLE tx = NULL;
    NTSTATUS st = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (st) { t_skip("NtCreateTransaction status 0x%lx", (unsigned long)st); return; }
    EXPECT_ST(UN(NtRollbackTransaction)(tx, FALSE), 0);
    EXPECT_ST(UN(NtRollbackTransaction)(tx, FALSE), 0);   /* repeating the rollback is not an error */
    UN(NtClose)(tx);
}

TEST(registry_transaction_rollback)
{
    REQUIRE(UN(NtCreateRegistryTransaction)); REQUIRE(UN(NtRollbackRegistryTransaction));
    HANDLE rt = NULL;
    NTSTATUS st = UN(NtCreateRegistryTransaction)(&rt, 0x1F003F, NULL, 0);
    if (st) { t_skip("NtCreateRegistryTransaction status 0x%lx", (unsigned long)st); return; }
    EXPECT_ST(UN(NtRollbackRegistryTransaction)(rt, 1), ST_INV_PARAM);      /* flags must be zero */
    EXPECT_ST(UN(NtRollbackRegistryTransaction)(rt, 0), 0);
    EXPECT_ST(UN(NtRollbackRegistryTransaction)(rt, 0), S(0xC0190015));    /* already rolled back (observed code) */
    UN(NtClose)(rt);
}

TEST(thaw_calls)
{
    REQUIRE(UN(NtThawTransactions)); REQUIRE(UN(NtThawRegistry)); REQUIRE(UN(RtlAdjustPrivilege));
    BOOLEAN old;
    UN(RtlAdjustPrivilege)(17, FALSE, FALSE, &old); UN(RtlAdjustPrivilege)(18, FALSE, FALSE, &old);
    EXPECT_ST(UN(NtThawTransactions)(), S(0xC0000061));    /* STATUS_PRIVILEGE_NOT_HELD */
    EXPECT_ST(UN(NtThawRegistry)(), S(0xC0000061));
    NTSTATUS pb = UN(RtlAdjustPrivilege)(17, TRUE, FALSE, &old), pr = UN(RtlAdjustPrivilege)(18, TRUE, FALSE, &old);
    if (pb || pr) { t_skip("backup/restore privileges not held (0x%lx / 0x%lx)", (unsigned long)pb, (unsigned long)pr); return; }
    EXPECT_ST(UN(NtThawTransactions)(), S(0xC0190045));   /* STATUS_TRANSACTIONS_NOT_FROZEN */
    EXPECT_ST(UN(NtThawRegistry)(), S(0xC0000189));       /* nothing frozen (observed code) */
    UN(RtlAdjustPrivilege)(17, FALSE, FALSE, &old); UN(RtlAdjustPrivilege)(18, FALSE, FALSE, &old);
}
