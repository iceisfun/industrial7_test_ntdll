/* Zw-named kernel transaction manager services on volatile transaction managers. */
#include "t.h"
#include <wchar.h>

UDECL(NTSTATUS, ZwRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, ZwRollbackEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwRollbackComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwReadOnlyEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwSinglePhaseReject, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwRecoverEnlistment, (HANDLE, PVOID));
UDECL(NTSTATUS, ZwRecoverResourceManager, (HANDLE));
UDECL(NTSTATUS, ZwRecoverTransactionManager, (HANDLE));
UDECL(NTSTATUS, ZwRenameTransactionManager, (PUNICODE_STRING, LPGUID));
UDECL(NTSTATUS, ZwRollforwardTransactionManager, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtCommitTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define S(x) ((NTSTATUS)(x))
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define WRONG_TYPE S(0xc0000024)
#define KTM_ALL 0x1f003f

static void cl(HANDLE h) { if (h) UN(NtClose)(h); }
static HANDLE evh(void)
{
    HANDLE ev = NULL;
    if (!UN(NtCreateEvent) || UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) < 0) return NULL;
    return ev;
}

TEST(zw_ktm_aliases)
{
    static const char *names[] = { "RollbackTransaction", "RollbackEnlistment", "RollbackComplete", "ReadOnlyEnlistment",
        "SinglePhaseReject", "RecoverEnlistment", "RecoverResourceManager", "RecoverTransactionManager",
        "RenameTransactionManager", "RollforwardTransactionManager" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[80], zw[80]; FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

TEST(zw_ktm_invalid_handles)
{
    HANDLE bad = (HANDLE)(ULONG_PTR)0x7ffffff4, ev; LARGE_INTEGER vc; GUID g; UNICODE_STRING u; WCHAR nm[] = L"\\??\\C:\\ntdllt_none.blf";
    REQUIRE(UN(ZwRollbackTransaction)); REQUIRE(UN(ZwRollbackEnlistment)); REQUIRE(UN(ZwRollbackComplete));
    REQUIRE(UN(ZwReadOnlyEnlistment)); REQUIRE(UN(ZwSinglePhaseReject)); REQUIRE(UN(ZwRecoverEnlistment));
    REQUIRE(UN(ZwRecoverResourceManager)); REQUIRE(UN(ZwRecoverTransactionManager)); REQUIRE(UN(ZwRollforwardTransactionManager));
    vc.QuadPart = 0;
    EXPECT_EQ(UN(ZwRollbackTransaction)(NULL, FALSE), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollbackTransaction)(bad, TRUE), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollbackEnlistment)(NULL, &vc), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollbackEnlistment)(bad, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollbackComplete)(NULL, &vc), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReadOnlyEnlistment)(NULL, &vc), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSinglePhaseReject)(NULL, &vc), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRecoverEnlistment)(NULL, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRecoverResourceManager)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRecoverTransactionManager)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollforwardTransactionManager)(NULL, &vc), BAD_HANDLE);
    ev = evh();
    if (ev) {
        EXPECT_EQ(UN(ZwRollbackTransaction)(ev, FALSE), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRollbackEnlistment)(ev, &vc), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRollbackComplete)(ev, &vc), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReadOnlyEnlistment)(ev, &vc), WRONG_TYPE);
        EXPECT_EQ(UN(ZwSinglePhaseReject)(ev, &vc), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRecoverEnlistment)(ev, NULL), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRecoverResourceManager)(ev), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRecoverTransactionManager)(ev), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRollforwardTransactionManager)(ev, &vc), WRONG_TYPE);
        cl(ev);
    }
    if (UN(ZwRenameTransactionManager)) {
        memset(&g, 0, sizeof g);
        u.Buffer = nm; u.Length = sizeof nm - 2; u.MaximumLength = sizeof nm;
        EXPECT_EQ(UN(ZwRenameTransactionManager)(&u, &g), S(0xc0000034)); /* no manager with that identity */
    }
}

static int mk_tm(HANDLE *tm, UNICODE_STRING *log, WCHAR *logbuf, size_t cap, const char *leaf)
{
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; UNICODE_STRING nt; NTSTATUS s;
    t_tmpfile(path, sizeof path, leaf);
    MultiByteToWideChar(CP_ACP, 0, path, -1, w, MAX_PATH);
    if (!UN(RtlDosPathNameToNtPathName_U) || !UN(RtlDosPathNameToNtPathName_U)(w, &nt, NULL, NULL)) return -1;
    wcsncpy(logbuf, nt.Buffer, cap - 1); logbuf[cap - 1] = 0;
    log->Buffer = logbuf; log->Length = (USHORT)(wcslen(logbuf) * 2); log->MaximumLength = log->Length + 2;
    UN(RtlFreeUnicodeString)(&nt);
    s = UN(NtCreateTransactionManager)(tm, KTM_ALL, NULL, log, 0, 0);
    return s;
}

TEST(zw_ktm_transaction_lifecycle)
{
    HANDLE tm = NULL, rm = NULL, tx = NULL, en = NULL, tx2 = NULL; NTSTATUS s; GUID rmid = { 0x1234, 0x5678, 0x9abc, {1,2,3,4,5,6,7,8} };
    LARGE_INTEGER vc; UNICODE_STRING log; WCHAR logbuf[MAX_PATH + 8];
    vc.QuadPart = 0;
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtCreateTransaction));
    REQUIRE(UN(NtCreateEnlistment)); REQUIRE(UN(ZwRollbackTransaction));
    REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(UN(RtlFreeUnicodeString));
    s = mk_tm(&tm, &log, logbuf, MAX_PATH + 8, "zw_ktm_log");
    if (s < 0) { t_skip("transaction manager with a log file could not be created: %08lx", (ULONG)s); return; }
    s = UN(ZwRecoverTransactionManager)(tm);
    EXPECT_EQ(s, 0);
    /* binding a new transaction to an explicit manager handle is rejected; transactions live in the default manager */
    s = UN(NtCreateTransaction)(&tx, 0x1f003f, NULL, NULL, tm, 0, 0, 0, NULL, NULL);
    EXPECT_EQ(s, BAD_PARAM);
    if (s == 0) cl(tx);
    tx = NULL;
    /* a fresh transaction can be rolled back once */
    s = UN(NtCreateTransaction)(&tx, 0x1f003f, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(UN(ZwRollbackTransaction)(tx, TRUE), 0);
        EXPECT_EQ(UN(ZwRollbackTransaction)(tx, TRUE), 0); /* observed: repeating a rollback is accepted */
        cl(tx); tx = NULL;
    }
    if (UN(NtCreateTransaction)(&tx2, 0x1f003f, NULL, NULL, NULL, 0, 0, 0, NULL, NULL) == 0) {
        s = UN(ZwRollbackTransaction)(tx2, FALSE);
        EXPECT_EQ(s, 0);
        cl(tx2);
    }
    s = UN(NtCreateResourceManager)(&rm, 0x1f003f, tm, &rmid, NULL, 0, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        s = UN(ZwRecoverResourceManager)(rm);
        EXPECT_EQ(s, S(0x103)); /* STATUS_PENDING: recovery completes asynchronously */
        if (UN(NtCreateTransaction)(&tx, 0x1f003f, NULL, NULL, NULL, 0, 0, 0, NULL, NULL) == 0) {
            s = UN(NtCreateEnlistment)(&en, 0x1f003f, rm, tx, NULL, 0, 0x3f /* all notifications */, (PVOID)0x1234);
            EXPECT_EQ(s, BAD_PARAM); /* transaction and resource manager belong to different managers */
            if (s == 0) {
                s = UN(ZwRecoverEnlistment)(en, (PVOID)0x1234);
                t_note("ZwRecoverEnlistment: %08lx", (ULONG)s);
                s = UN(ZwReadOnlyEnlistment)(en, &vc);
                t_note("ZwReadOnlyEnlistment: %08lx", (ULONG)s);
                s = UN(ZwSinglePhaseReject)(en, &vc);
                t_note("ZwSinglePhaseReject: %08lx", (ULONG)s);
                s = UN(ZwRollbackComplete)(en, &vc);
                t_note("ZwRollbackComplete: %08lx", (ULONG)s);
                s = UN(ZwRollbackEnlistment)(en, &vc);
                t_note("ZwRollbackEnlistment: %08lx", (ULONG)s);
                cl(en);
            }
            s = UN(ZwRollbackTransaction)(tx, TRUE);
            EXPECT_EQ(s, 0);
            cl(tx);
        }
    }
    s = UN(ZwRollforwardTransactionManager)(tm, &vc);
    EXPECT_EQ(s, 0);
    cl(rm); cl(tm);
}
