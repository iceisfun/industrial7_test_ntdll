/* Registry open/create variants (NtOpenKeyEx, transacted keys), kernel transaction manager objects
 * (transactions, transaction managers, resource managers, enlistments) and registry transactions.
 * Expectations were observed on Windows 10 22H2 (see EVIDENCE.md). */
#include "oa.h"

static BOOL guid_eq(const GUID *a, const GUID *b) { return !memcmp(a, b, sizeof *a); }

/* ---- NtOpenKeyEx ------------------------------------------------------- */

#define CV_KEY L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

TEST(open_key_ex_options)
{
    HANDLE k = NULL; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtOpenKeyEx)); REQUIRE(UN(NtClose));
    oa_init(&oa, CV_KEY, OBJ_CI);
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 0), ST_SUCCESS);
    CHECK(k != NULL);
    if (k) {
        /* the handle is a usable registry key: read a string value through the Win32 layer */
        char buf[64]; DWORD sz = sizeof buf, type = 0;
        LONG r = RegQueryValueExA((HKEY)k, "ProductName", NULL, &type, (LPBYTE)buf, &sz);
        EXPECT_EQ(r, 0); EXPECT_EQ(type, REG_SZ); CHECK(sz > 1);
    }
    CLOSE(k);
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 8 /* REG_OPTION_OPEN_LINK */), ST_SUCCESS); CLOSE(k);
    /* unsupported option bits are parameter 4 errors */
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 1), ST(0xC00000F2));
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 0x100), ST(0xC00000F2));
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 0x80000000u), ST(0xC00000F2));
    CHECK(k == NULL);
}

TEST(open_key_ex_missing_and_null)
{
    HANDLE k = NULL; OBJECT_ATTRIBUTES oa; WCHAR nm[160]; REQUIRE(UN(NtOpenKeyEx)); REQUIRE(UN(NtClose));
    wsprintfW(nm, L"\\Registry\\Machine\\SOFTWARE\\oa_missing_%lu", GetCurrentProcessId());
    oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, &oa, 0), ST_NAME_NOT_FOUND);
    CHECK(k == NULL);
    EXPECT_EQ(UN(NtOpenKeyEx)(&k, KEY_QUERY_VALUE, NULL, 0), ST_ACCESS_VIOLATION);
}

/* ---- transacted keys --------------------------------------------------- */

TEST(transacted_key_requires_valid_transaction)
{
    HANDLE k = NULL; OBJECT_ATTRIBUTES oa; ULONG disp = 0;
    REQUIRE(UN(NtOpenKeyTransacted)); REQUIRE(UN(NtOpenKeyTransactedEx)); REQUIRE(UN(NtCreateKeyTransacted));
    oa_init(&oa, CV_KEY, OBJ_CI);
    EXPECT_EQ(UN(NtOpenKeyTransacted)(&k, KEY_QUERY_VALUE, &oa, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenKeyTransacted)(&k, KEY_QUERY_VALUE, &oa, (HANDLE)(ULONG_PTR)0x1234), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenKeyTransactedEx)(&k, KEY_QUERY_VALUE, &oa, 0, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenKeyTransactedEx)(&k, KEY_QUERY_VALUE, &oa, 0, (HANDLE)(ULONG_PTR)0x1234), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateKeyTransacted)(&k, KEY_READ, &oa, 0, NULL, 0, NULL, &disp), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateKeyTransacted)(&k, KEY_READ, &oa, 0, NULL, 0, (HANDLE)(ULONG_PTR)0x1234, &disp), ST_INV_HANDLE);
    CHECK(k == NULL);
}

TEST(transacted_key_create_visibility_and_commit)
{
    HANDLE root = NULL, tx = NULL, k = NULL, k2 = NULL, k3 = NULL; OBJECT_ATTRIBUTES oa; WCHAR sub[96]; ULONG disp = 0xcc;
    REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtCreateKeyTransacted)); REQUIRE(UN(NtOpenKeyTransacted));
    REQUIRE(UN(NtOpenKeyEx)); REQUIRE(UN(NtCommitTransaction)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtClose));
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &root) < 0) { t_skip("cannot open the current user hive"); return; }
    wsprintfW(sub, L"Software\\oa_ktm_%lu_%u", GetCurrentProcessId(), ++g_serial);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.RootDirectory = root; oa.ObjectName = oa_us(sub); oa.Attributes = OBJ_CI;
    NTSTATUS st = UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (st < 0) { t_skip("NtCreateTransaction failed: %08lx", (unsigned long)st); CLOSE(root); return; }
    st = UN(NtCreateKeyTransacted)(&k, KEY_ALL_ACCESS, &oa, 0, NULL, 0, tx, &disp);
    EXPECT_EQ(st, ST_SUCCESS);
    EXPECT_EQ(disp, 1 /* REG_CREATED_NEW_KEY */);
    if (st >= 0) {
        /* not visible outside the transaction until it commits */
        EXPECT_EQ(UN(NtOpenKeyEx)(&k2, KEY_READ, &oa, 0), ST_NAME_NOT_FOUND);
        CHECK(k2 == NULL);
        /* visible inside it */
        EXPECT_EQ(UN(NtOpenKeyTransacted)(&k3, KEY_READ, &oa, tx), ST_SUCCESS);
        CLOSE(k3);
        CLOSE(k);
        EXPECT_EQ(UN(NtCommitTransaction)(tx, TRUE), ST_SUCCESS);
        EXPECT_EQ(UN(NtOpenKeyEx)(&k2, KEY_ALL_ACCESS, &oa, 0), ST_SUCCESS);
        if (k2) { EXPECT_EQ(UN(NtDeleteKey)(k2), ST_SUCCESS); }
        CLOSE(k2);
    }
    CLOSE(k); CLOSE(tx); CLOSE(root);
}

TEST(transacted_key_rollback_discards_create)
{
    HANDLE root = NULL, tx = NULL, k = NULL, k2 = NULL; OBJECT_ATTRIBUTES oa; WCHAR sub[96]; ULONG disp = 0;
    REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtCreateKeyTransacted)); REQUIRE(UN(NtOpenKeyTransactedEx));
    REQUIRE(UN(NtOpenKeyEx)); REQUIRE(UN(NtRollbackTransaction)); REQUIRE(UN(NtClose));
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &root) < 0) { t_skip("cannot open the current user hive"); return; }
    wsprintfW(sub, L"Software\\oa_ktm_rb_%lu_%u", GetCurrentProcessId(), ++g_serial);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.RootDirectory = root; oa.ObjectName = oa_us(sub); oa.Attributes = OBJ_CI;
    NTSTATUS st = UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (st < 0) { t_skip("NtCreateTransaction failed: %08lx", (unsigned long)st); CLOSE(root); return; }
    EXPECT_EQ(UN(NtCreateKeyTransacted)(&k, KEY_ALL_ACCESS, &oa, 0, NULL, 0, tx, &disp), ST_SUCCESS);
    EXPECT_EQ(UN(NtOpenKeyTransactedEx)(&k2, KEY_READ, &oa, 0, tx), ST_SUCCESS); CLOSE(k2);
    CLOSE(k);
    EXPECT_EQ(UN(NtRollbackTransaction)(tx, TRUE), ST_SUCCESS);
    EXPECT_EQ(UN(NtOpenKeyEx)(&k2, KEY_READ, &oa, 0), ST_NAME_NOT_FOUND);
    CHECK(k2 == NULL);
    CLOSE(tx); CLOSE(root);
}

/* ---- transactions ------------------------------------------------------ */

TEST(transaction_create_options_and_uow)
{
    HANDLE tx = NULL, o = NULL; GUID uow = {0x12345678, 0x1234, 0x4321, {1, 2, 3, 4, 5, 6, 7, 8}}; WCHAR d[] = L"oa test";
    REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtOpenTransaction)); REQUIRE(UN(NtQueryInformationTransaction)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, &uow, NULL, 0, 0, 0, NULL, NULL), ST_SUCCESS);
    CHECK(tx != NULL);
    if (tx) {
        struct { GUID id; ULONG state, outcome; } bi; ULONG ret = 0;
        memset(&bi, 0xcc, sizeof bi);
        EXPECT_EQ(UN(NtQueryInformationTransaction)(tx, 0 /* TransactionBasicInformation */, &bi, sizeof bi, &ret), ST_SUCCESS);
        CHECK(guid_eq(&bi.id, &uow));
        EXPECT_EQ(bi.state, 1 /* TransactionStateNormal */);
        /* a second handle by unit-of-work GUID */
        EXPECT_EQ(UN(NtOpenTransaction)(&o, TX_ALL, NULL, &uow, NULL), ST_SUCCESS);
        CLOSE(o);
    }
    CLOSE(tx);
    /* closing the last handle of an active transaction rolls it back and frees it */
    EXPECT_EQ(UN(NtOpenTransaction)(&o, TX_ALL, NULL, &uow, NULL), ST(0xC019004E));
    CHECK(o == NULL);
    /* creation variants that succeed */
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 1 /* DO_NOT_PROMOTE */, 0, 0, NULL, NULL), ST_SUCCESS); CLOSE(tx);
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 1, 0, NULL, NULL), ST_SUCCESS); CLOSE(tx);
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 1, NULL, NULL), ST_SUCCESS); CLOSE(tx);
    { LARGE_INTEGER to; to.QuadPart = -100000000; EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, &to, NULL), ST_SUCCESS); CLOSE(tx); }
    { UNICODE_STRING us = {sizeof d - 2, sizeof d, d}; EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, &us), ST_SUCCESS); CLOSE(tx); }
}

TEST(transaction_invalid_arguments)
{
    HANDLE tx = NULL; REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtOpenTransaction)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0x10, 0, 0, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0xFF, 0, 0, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, (HANDLE)(ULONG_PTR)0x1234, 0, 0, 0, NULL, NULL), ST_INVALID_PARAMETER);
    /* open needs a name or a GUID */
    EXPECT_EQ(UN(NtOpenTransaction)(&tx, TX_ALL, NULL, NULL, NULL), ST_INVALID_PARAMETER);
    CHECK(tx == NULL);
}

/* ---- transaction managers ---------------------------------------------- */

TEST(transaction_manager_volatile_and_errors)
{
    HANDLE tm = NULL, o = NULL; GUID g = {1, 2, 3, {4}}; REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtOpenTransactionManager)); REQUIRE(UN(NtClose));
    NTSTATUS st = UN(NtCreateTransactionManager)(&tm, TX_ALL, NULL, NULL, 1 /* TRANSACTION_MANAGER_VOLATILE */, 0);
    if (st == ST_ACCESS_DENIED || st == ST(0xC0000061)) { t_skip("creating a transaction manager is not permitted for this account (%08lx)", (unsigned long)st); return; }
    EXPECT_EQ(st, ST_SUCCESS);
    CHECK(tm != NULL);
    CLOSE(tm);
    /* non-volatile managers need a log file name */
    EXPECT_EQ(UN(NtCreateTransactionManager)(&tm, TX_ALL, NULL, NULL, 0, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateTransactionManager)(&tm, TX_ALL, NULL, NULL, 8, 0), ST_INVALID_PARAMETER);
    CHECK(tm == NULL);
    EXPECT_EQ(UN(NtOpenTransactionManager)(&o, TX_ALL, NULL, NULL, NULL, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtOpenTransactionManager)(&o, TX_ALL, NULL, NULL, &g, 0), ST(0xC0190051));
    CHECK(o == NULL);
}

/* ---- resource managers and enlistments --------------------------------- */

TEST(resource_manager_requires_online_manager)
{
    HANDLE tm = NULL, rm = NULL; GUID g = {0x11111111, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}}, g2 = {5, 6, 7, {8}};
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtOpenResourceManager)); REQUIRE(UN(NtClose));
    { NTSTATUS ts = UN(NtCreateTransactionManager)(&tm, TX_ALL, NULL, NULL, 1, 0); if (ts < 0) { t_skip("no volatile transaction manager (%08lx)", (unsigned long)ts); return; } }
    /* a persistent resource manager cannot be created on a manager that has not finished recovery */
    EXPECT_EQ(UN(NtCreateResourceManager)(&rm, 0x1F00FF, tm, &g, NULL, 0, NULL), ST(0xC019003B));
    CHECK(rm == NULL);
    /* a volatile one (option 1) can */
    EXPECT_EQ(UN(NtCreateResourceManager)(&rm, 0x1F00FF, tm, &g2, NULL, 1, NULL), ST_SUCCESS);
    CHECK(rm != NULL);
    CLOSE(rm);
    EXPECT_EQ(UN(NtOpenResourceManager)(&rm, 0x1F00FF, tm, &g, NULL), ST(0xC019004F));
    CHECK(rm == NULL);
    EXPECT_EQ(UN(NtCreateResourceManager)(&rm, 0x1F00FF, (HANDLE)(ULONG_PTR)0x1234, &g, NULL, 1, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateResourceManager)(&rm, 0x1F00FF, tm, NULL, NULL, 1, NULL), ST_ACCESS_VIOLATION);
    CLOSE(tm);
}

TEST(enlistment_invalid_handles_and_guid)
{
    HANDLE e = NULL; GUID g = {1, 2, 3, {4}}; REQUIRE(UN(NtCreateEnlistment)); REQUIRE(UN(NtOpenEnlistment)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateEnlistment)(&e, 0x1F001F, (HANDLE)(ULONG_PTR)0x1234, (HANDLE)(ULONG_PTR)0x1234, NULL, 0, 1, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateEnlistment)(&e, 0x1F001F, NULL, NULL, NULL, 0, 1, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenEnlistment)(&e, 0x1F001F, (HANDLE)(ULONG_PTR)0x1234, &g, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenEnlistment)(&e, 0x1F001F, NULL, NULL, NULL), ST_INVALID_PARAMETER);
    CHECK(e == NULL);
}

/* ---- registry transactions --------------------------------------------- */

TEST(registry_transaction_create_open)
{
    HANDLE r = NULL, o = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtCreateRegistryTransaction)); REQUIRE(UN(NtOpenRegistryTransaction)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateRegistryTransaction)(&r, TX_ALL, NULL, 0), ST_SUCCESS);
    CHECK(r != NULL);
    CLOSE(r);
    EXPECT_EQ(UN(NtCreateRegistryTransaction)(&r, TX_ALL, NULL, 1), ST_INVALID_PARAMETER);
    CHECK(r == NULL);
    wsprintfW(nm, L"\\BaseNamedObjects\\oa_rtx_%lu_%u", GetCurrentProcessId(), ++g_serial); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateRegistryTransaction)(&r, TX_ALL, &oa, 0), ST_SUCCESS);
    EXPECT_EQ(UN(NtOpenRegistryTransaction)(&o, TX_ALL, &oa), ST_SUCCESS);
    CHECK(o != NULL && o != r);
    CLOSE(o); CLOSE(r);
    EXPECT_EQ(UN(NtOpenRegistryTransaction)(&o, TX_ALL, &oa), ST_NAME_NOT_FOUND);
    CHECK(o == NULL);
    EXPECT_EQ(UN(NtOpenRegistryTransaction)(&o, TX_ALL, NULL), ST_INVALID_PARAMETER);
}

TEST(enlistment_requires_transaction_of_same_manager)
{
    HANDLE tm = NULL, rm = NULL, tx = NULL, en = NULL; GUID g = {0x22222222, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtCreateEnlistment)); REQUIRE(UN(NtCreateTransaction));
    { NTSTATUS ts = UN(NtCreateTransactionManager)(&tm, TX_ALL, NULL, NULL, 1, 0); if (ts < 0) { t_skip("no volatile transaction manager (%08lx)", (unsigned long)ts); return; } }
    EXPECT_EQ(UN(NtCreateResourceManager)(&rm, 0x1F00FF, tm, &g, NULL, 1, NULL), ST_SUCCESS);
    /* a transaction cannot be created inside a private volatile manager */
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, tm, 0, 0, 0, NULL, NULL), ST_INVALID_PARAMETER);
    CHECK(tx == NULL);
    /* a transaction of the default manager cannot be enlisted in this resource manager */
    EXPECT_EQ(UN(NtCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL), ST_SUCCESS);
    if (tx && rm) {
        EXPECT_EQ(UN(NtCreateEnlistment)(&en, 0x1F001F, rm, tx, NULL, 0, 1, NULL), ST_INVALID_PARAMETER);
        CHECK(en == NULL);
    }
    CLOSE(tx); CLOSE(rm); CLOSE(tm);
}
