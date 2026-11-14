/* Kernel transaction manager objects: transactions, transaction managers, resource managers, enlistments. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, ZwOpenTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE));
UDECL(NTSTATUS, ZwCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, ZwOpenTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, LPGUID, ULONG));
UDECL(NTSTATUS, ZwCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, ZwOpenResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQueryInformationTransaction, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtCommitTransaction, (HANDLE, BOOLEAN));

#define TX_ALL 0x1F003F
#define TM_ALL 0x1F00FF
#define RM_ALL 0x1F007F
typedef struct { GUID id; ULONG state, outcome; } txbasic;

#define NEEDT(x) do { REQUIRE(UN(x)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); } while (0)

TEST(nt_create_open_b_transaction)
{
    HANDLE tx = NULL, tx2 = NULL, o = NULL; NTSTATUS s; txbasic bi; ULONG ret = 0; GUID uow; UNICODE_STRING u, desc; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40];
    NEEDT(ZwCreateTransaction); REQUIRE(UN(ZwOpenTransaction)); REQUIRE(UN(NtQueryInformationTransaction)); REQUIRE(UN(NtRollbackTransaction));
    COB_ALIAS("CreateTransaction"); COB_ALIAS("OpenTransaction");
    /* default (anonymous) transaction manager */
    s = UN(ZwCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (s == S_NOTSUPP || s == S_NOTIMPL) { t_skip("transactions not available: 0x%08lx", (unsigned long)s); return; }
    EXPECT_EQ(s, S_OK_); if (!tx) return;
    CHECK(cob_typename(tx, tn, 40)); EXPECT_WSTR(tn, L"TmTx");
    memset(&bi, 0xcc, sizeof bi);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(tx, 0, &bi, sizeof bi, &ret), S_OK_);
    EXPECT_EQ(ret, sizeof bi); EXPECT_EQ(bi.state, 1 /* TransactionStateNormal */); EXPECT_EQ(bi.outcome, 1 /* TransactionOutcomeUndetermined */);
    CHECK(bi.id.Data1 || bi.id.Data2 || bi.id.Data3);
    EXPECT_EQ(UN(NtQueryInformationTransaction)(tx, 0, &bi, sizeof bi - 1, &ret), S_LENMM);
    UN(NtRollbackTransaction)(tx, TRUE); cob_close(tx); tx = NULL;
    /* caller-chosen UOW id is reported back and usable for open */
    memset(&uow, 0, sizeof uow); uow.Data1 = 0xC0B00000 + GetCurrentProcessId(); uow.Data2 = 0x1234; uow.Data3 = 0x5678; uow.Data4[0] = 0x9a; uow.Data4[7] = 0xbc;
    cob_oa(&oa, NULL, 0, NULL);
    cob_us(&desc, L"cob test transaction");
    s = UN(ZwCreateTransaction)(&tx, TX_ALL, &oa, &uow, NULL, 0, 0, 0, NULL, &desc); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQueryInformationTransaction)(tx, 0, &bi, sizeof bi, &ret), S_OK_); CHECK(!memcmp(&bi.id, &uow, sizeof uow));
        /* open by UOW id */
        s = UN(ZwOpenTransaction)(&o, TX_ALL, &oa, &uow, NULL); EXPECT_EQ(s, S_OK_);
        if (o) { memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQueryInformationTransaction)(o, 0, &bi, sizeof bi, &ret), S_OK_); CHECK(!memcmp(&bi.id, &uow, sizeof uow)); cob_close(o); o = NULL; }
        s = UN(ZwOpenTransaction)(&o, TX_ALL, NULL, &uow, NULL); EXPECT_EQ(s, S_OK_); cob_close(o); o = NULL;
        UN(NtRollbackTransaction)(tx, TRUE); cob_close(tx);
    }
    /* errors */
    { GUID none = uow; none.Data1 ^= 0x5a5a5a5a; o = (HANDLE)0x1234; s = UN(ZwOpenTransaction)(&o, TX_ALL, &oa, &none, NULL); EXPECT_EQ(s, (NTSTATUS)0xC019004E); }
    EXPECT_EQ(UN(ZwOpenTransaction)(&o, TX_ALL, &oa, NULL, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenTransaction)(&o, TX_ALL, NULL, NULL, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenTransaction)(NULL, TX_ALL, &oa, &uow, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateTransaction)(NULL, TX_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateTransaction)(&tx, TX_ALL, NULL, NULL, NULL, 0xffffffff, 0, 0, NULL, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateTransaction)(&tx, TX_ALL, NULL, NULL, (HANDLE)(ULONG_PTR)0x7ffffff0, 0, 0, 0, NULL, NULL), S_INVPARAM);
}

TEST(nt_create_open_b_transaction_manager)
{
    HANDLE tm = NULL, tm2 = NULL, o = NULL; NTSTATUS s; struct { GUID id; LARGE_INTEGER clock; } bi; ULONG ret = 0; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40];
    NEEDT(ZwCreateTransactionManager); REQUIRE(UN(ZwOpenTransactionManager)); REQUIRE(UN(NtQueryInformationTransactionManager));
    COB_ALIAS("CreateTransactionManager"); COB_ALIAS("OpenTransactionManager");
    cob_oa(&oa, NULL, 0, NULL);
    /* volatile TM: no log file */
    s = UN(ZwCreateTransactionManager)(&tm, TM_ALL, &oa, NULL, 1 /* TRANSACTION_MANAGER_VOLATILE */, 0);
    if (s == S_PRIVNH || s == S_DENIED || s == S_NOTSUPP) { t_skip("volatile transaction manager creation refused: 0x%08lx", (unsigned long)s); return; }
    EXPECT_EQ(s, S_OK_); if (!tm) return;
    CHECK(cob_typename(tm, tn, 40)); EXPECT_WSTR(tn, L"TmTm");
    memset(&bi, 0, sizeof bi);
    EXPECT_EQ(UN(NtQueryInformationTransactionManager)(tm, 0, &bi, sizeof bi, &ret), S_OK_);
    CHECK(bi.id.Data1 || bi.id.Data2 || bi.id.Data3);
    /* open by identity is refused for a volatile manager, even to its creator */
    s = UN(ZwOpenTransactionManager)(&o, TM_ALL, NULL, NULL, &bi.id, 0); EXPECT_EQ(s, S_DENIED); cob_close(o); o = NULL;
    cob_close(tm); tm = NULL;
    /* invalid combinations */
    EXPECT_EQ(UN(ZwCreateTransactionManager)(&tm, TM_ALL, NULL, NULL, 0, 0), S_INVPARAM);   /* non-volatile needs a log file */
    EXPECT_EQ(UN(ZwCreateTransactionManager)(&tm, TM_ALL, NULL, NULL, 0xffffffff, 0), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateTransactionManager)(NULL, TM_ALL, NULL, NULL, 1, 0), S_AV);
    o = (HANDLE)0x1234; { GUID none = bi.id; none.Data1 ^= 0x5a5a5a5a; s = UN(ZwOpenTransactionManager)(&o, TM_ALL, NULL, NULL, &none, 0); EXPECT_EQ(s, (NTSTATUS)0xC0190051); }
    EXPECT_EQ(UN(ZwOpenTransactionManager)(&o, TM_ALL, NULL, NULL, NULL, 0), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenTransactionManager)(NULL, TM_ALL, NULL, NULL, &bi.id, 0), S_AV);
}

TEST(nt_create_open_b_resource_manager_and_enlistment)
{
    HANDLE tm = NULL, rm = NULL, rm2 = NULL, o = NULL; NTSTATUS s; GUID rg; UNICODE_STRING u, desc; OBJECT_ATTRIBUTES oa; WCHAR name[200], rname[200], tn[40];
    NEEDT(ZwCreateTransactionManager); REQUIRE(UN(ZwCreateResourceManager)); REQUIRE(UN(ZwOpenResourceManager)); REQUIRE(UN(ZwOpenEnlistment));
    COB_ALIAS("CreateResourceManager"); COB_ALIAS("OpenResourceManager"); COB_ALIAS("OpenEnlistment");
    cob_oa(&oa, NULL, 0, NULL);
    s = UN(ZwCreateTransactionManager)(&tm, TM_ALL, &oa, NULL, 1, 0);
    if (s == S_PRIVNH || s == S_DENIED || s == S_NOTSUPP) { t_skip("volatile transaction manager creation refused: 0x%08lx", (unsigned long)s); return; }
    EXPECT_EQ(s, S_OK_); if (!tm) return;
    memset(&rg, 0, sizeof rg); rg.Data1 = 0xC0B10000 + GetCurrentProcessId(); rg.Data2 = 7; rg.Data3 = 8; rg.Data4[1] = 9;
    cob_oa(&oa, NULL, 0, NULL); cob_us(&desc, L"cob rm");
    s = UN(ZwCreateResourceManager)(&rm, RM_ALL, tm, &rg, &oa, 1 /* RESOURCE_MANAGER_VOLATILE */, &desc); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        CHECK(cob_typename(rm, tn, 40)); EXPECT_WSTR(tn, L"TmRm");
        s = UN(ZwCreateResourceManager)(&rm2, RM_ALL, tm, &rg, &oa, 1, &desc); EXPECT_EQ(s, S_COLLIDE); cob_close(rm2);
        s = UN(ZwOpenResourceManager)(&o, RM_ALL, tm, &rg, NULL); EXPECT_EQ(s, S_OK_); cob_close(o); o = NULL;
        s = UN(ZwOpenResourceManager)(&o, RM_ALL, tm, NULL, &oa); EXPECT_EQ(s, S_INVPARAM); cob_close(o); o = NULL;
        /* enlistments: none exist */
        { GUID eg = rg; eg.Data1++; o = (HANDLE)0x1234;
          s = UN(ZwOpenEnlistment)(&o, RM_ALL, rm, &eg, NULL); CHECK(s < 0); EXPECT_EQ(UN(ZwOpenEnlistment)(&o, RM_ALL, rm, NULL, NULL), S_INVPARAM);
          EXPECT_EQ(UN(ZwOpenEnlistment)(&o, RM_ALL, (HANDLE)(ULONG_PTR)0x7ffffff0, &eg, NULL), S_INVHANDLE);
          EXPECT_EQ(UN(ZwOpenEnlistment)(&o, RM_ALL, tm, &eg, NULL), S_TYPEMM); }
        /* RM with an unknown GUID */
        { GUID bad = rg; bad.Data1 += 5; o = (HANDLE)0x1234; s = UN(ZwOpenResourceManager)(&o, RM_ALL, tm, &bad, NULL); CHECK(s < 0); }
        cob_close(rm);
    }
    EXPECT_EQ(UN(ZwCreateResourceManager)(&rm, RM_ALL, (HANDLE)(ULONG_PTR)0x7ffffff0, &rg, NULL, 1, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateResourceManager)(NULL, RM_ALL, tm, &rg, NULL, 1, NULL), S_AV);
    EXPECT_EQ(UN(ZwOpenResourceManager)(&o, RM_ALL, (HANDLE)(ULONG_PTR)0x7ffffff0, &rg, NULL), S_INVHANDLE);
    cob_close(tm);
}
