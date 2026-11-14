/* Kernel object families: transactions (KTM and registry), legacy LPC ports, debug objects, WNF state names,
 * private namespaces. */
#include "t.h"

/* transactions */
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCommitTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtEnumerateTransactionObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtCommitEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCommitComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCommitRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, NtRollbackRegistryTransaction, (HANDLE, ULONG));
/* ports */
UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtListenPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtConnectPort, (PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PVOID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtAcceptConnectPort, (PHANDLE, PVOID, PVOID, BOOLEAN, PVOID, PVOID));
UDECL(NTSTATUS, NtCompleteConnectPort, (HANDLE));
/* debug objects */
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtDebugActiveProcess, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtDebugContinue, (HANDLE, PCLIENT_ID, NTSTATUS));
UDECL(NTSTATUS, NtWaitForDebugEvent, (HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, NtRemoveProcessDebug, (HANDLE, HANDLE));
/* WNF */
UDECL(NTSTATUS, NtCreateWnfStateName, (PVOID, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PSECURITY_DESCRIPTOR));
UDECL(NTSTATUS, NtUpdateWnfStateData, (PVOID, PVOID, ULONG, PVOID, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryWnfStateData, (PVOID, PVOID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtDeleteWnfStateData, (PVOID, PVOID));
UDECL(NTSTATUS, NtDeleteWnfStateName, (PVOID));
/* private namespace */
UDECL(NTSTATUS, NtDeletePrivateNamespace, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define ST_INVHANDLE  S(0xC0000008)
#define ST_INVPARAM   S(0xC000000D)
#define ST_AV         S(0xC0000005)
#define ST_TYPEMISM   S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define NT_SELF       ((HANDLE)(LONG_PTR)-1)

static void us(UNICODE_STRING *u, const WCHAR *w) { u->Buffer = (PWSTR)w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }

TEST(kobj_aliases)
{
    static const char *n[] = { "CreateTransaction", "CommitTransaction", "EnumerateTransactionObject", "CommitEnlistment", "CommitComplete",
        "CommitRegistryTransaction", "ConnectPort", "AcceptConnectPort", "CompleteConnectPort", "DebugActiveProcess", "DebugContinue",
        "DeleteWnfStateData", "DeleteWnfStateName", "DeletePrivateNamespace" };
    char a[96], b[96];
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "alias %s", a);
    }
}

/* ---- transactions -------------------------------------------------------------------------- */
#define TM_ALL   0x1F003F
#define RM_ALL   0x1F00FF
#define EN_ALL   0x1F01FF

/* Transaction manager backed by a log file in the scratch directory (volatile managers cannot host enlistments). */
static HANDLE make_tm(const char *leaf, NTSTATUS *st)
{
    WCHAR path[MAX_PATH + 16]; UNICODE_STRING u; HANDLE tm = NULL; NTSTATUS s;
    swprintf(path, MAX_PATH + 16, L"\\??\\%hs%hs", t_tmpdir(), leaf);
    us(&u, path);
    s = UN(NtCreateTransactionManager)(&tm, TM_ALL, NULL, &u, 0, 0);
    if (st) *st = s;
    return s >= 0 ? tm : NULL;
}

TEST(transaction_commit_rollback)
{
    HANDLE tx = NULL, ro = NULL; NTSTATUS s;
    REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtCommitTransaction)); REQUIRE(UN(NtRollbackTransaction));
    s = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    EXPECT_EQ(s, 0); CHECK(tx != NULL); if (s < 0 || !tx) return;
    s = UN(NtCommitTransaction)(tx, TRUE);
    EXPECT_EQ(s, 0);
    s = UN(NtCommitTransaction)(tx, TRUE);               /* already committed */
    EXPECT_EQ(s, S(0xC0190016));                  /* STATUS_TRANSACTION_ALREADY_COMMITTED */
    s = UN(NtRollbackTransaction)(tx, TRUE);
    EXPECT_EQ(s, S(0xC0190016));
    UN(NtClose)(tx);
    tx = NULL;
    s = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (s >= 0 && tx) {
        EXPECT_EQ(UN(NtRollbackTransaction)(tx, TRUE), 0);
        s = UN(NtCommitTransaction)(tx, TRUE);
        EXPECT_EQ(s, S(0xC0190015));                   /* STATUS_TRANSACTION_ALREADY_ABORTED */
        UN(NtClose)(tx);
    }
    tx = NULL;
    s = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (s >= 0 && tx) {
        if (DuplicateHandle(GetCurrentProcess(), tx, GetCurrentProcess(), &ro, SYNCHRONIZE, FALSE, 0)) {
            EXPECT_EQ(UN(NtCommitTransaction)(ro, TRUE), ST_DENIED);
            EXPECT_EQ(UN(NtRollbackTransaction)(ro, TRUE), ST_DENIED);
            CloseHandle(ro);
        }
        UN(NtClose)(tx);          /* closing the last handle rolls the transaction back */
    }
    EXPECT_EQ(UN(NtCommitTransaction)(NULL, TRUE), ST_INVHANDLE);
    EXPECT_EQ(UN(NtRollbackTransaction)(NULL, TRUE), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL);
      EXPECT_EQ(UN(NtCommitTransaction)(ev, TRUE), ST_TYPEMISM);
      EXPECT_EQ(UN(NtRollbackTransaction)(ev, TRUE), ST_TYPEMISM);
      CloseHandle(ev); }
}

TEST(enumerate_transaction_object)
{
    HANDLE tm; NTSTATUS s, st; ULONG ret = 0xcc; union { ULONGLONG a; BYTE b[256]; } cur;
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtEnumerateTransactionObject));
    tm = make_tm("enum.tm", &st);
    if (!tm) { t_skip("cannot create a log-backed transaction manager (0x%08lx)", st); return; }
    /* a fresh manager has no transactions: STATUS_NO_MORE_ENTRIES (0x8000001A) with an empty cursor */
    memset(&cur, 0, sizeof cur);
    s = UN(NtEnumerateTransactionObject)(tm, 0 /* KTMOBJECT_TRANSACTION */, cur.b, 36, &ret);
    EXPECT_EQ(s, S(0x8000001A)); EXPECT_EQ(*(ULONG *)(cur.b + 16), 0);
    s = UN(NtEnumerateTransactionObject)(tm, 0, cur.b, sizeof cur, &ret);
    EXPECT_EQ(s, S(0x8000001A));
    /* the other object types of a manager enumerate successfully */
    EXPECT_EQ(UN(NtEnumerateTransactionObject)(tm, 1 /* KTMOBJECT_TRANSACTION_MANAGER */, cur.b, 36, &ret), 0);
    EXPECT_EQ(UN(NtEnumerateTransactionObject)(tm, 2 /* KTMOBJECT_RESOURCE_MANAGER */, cur.b, 36, &ret), 0);
    /* argument errors */
    EXPECT_EQ(UN(NtEnumerateTransactionObject)(tm, 0, cur.b, 8, &ret), ST_INVPARAM);        /* cursor too small */
    EXPECT_EQ(UN(NtEnumerateTransactionObject)(tm, 99, cur.b, sizeof cur, &ret), ST_INVPARAM);
    EXPECT_EQ(UN(NtEnumerateTransactionObject)(tm, 0, NULL, 0, &ret), ST_INVPARAM);
    UN(NtClose)(tm);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL);
      s = UN(NtEnumerateTransactionObject)(ev, 0, cur.b, 36, &ret); EXPECT_EQ(s, ST_TYPEMISM); CloseHandle(ev); }
}

TEST(enlistment_commit)
{
    NTSTATUS s; LARGE_INTEGER clk; HANDLE ev;
    REQUIRE(UN(NtCommitEnlistment)); REQUIRE(UN(NtCommitComplete));
    clk.QuadPart = 0;
    EXPECT_EQ(UN(NtCommitEnlistment)(NULL, &clk), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCommitComplete)(NULL, &clk), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCommitEnlistment)((HANDLE)(ULONG_PTR)0xdeadbee0, NULL), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCommitComplete)((HANDLE)(ULONG_PTR)0xdeadbee0, NULL), ST_INVHANDLE);
    ev = CreateEventW(NULL, 1, 0, NULL);
    EXPECT_EQ(UN(NtCommitEnlistment)(ev, &clk), ST_TYPEMISM);
    EXPECT_EQ(UN(NtCommitComplete)(ev, &clk), ST_TYPEMISM);
    CloseHandle(ev);
    /* a resource manager on a log-backed manager can be created and closed */
    if (UN(NtCreateTransactionManager) && UN(NtCreateResourceManager)) {
        HANDLE tm, rm = NULL; GUID g = { 0x1234, 0x5678, 0x9abc, { 1, 2, 3, 4, 5, 6, 7, 8 } }; NTSTATUS st;
        tm = make_tm("enlist.tm", &st);
        if (tm) {
            s = UN(NtCreateResourceManager)(&rm, RM_ALL, tm, &g, NULL, 0, NULL);
            EXPECT_EQ(s, 0);
            /* a resource manager is not an enlistment */
            if (rm) { EXPECT_EQ(UN(NtCommitEnlistment)(rm, &clk), ST_TYPEMISM); EXPECT_EQ(UN(NtCommitComplete)(rm, &clk), ST_TYPEMISM); UN(NtClose)(rm); }
            UN(NtClose)(tm);
        } else t_note("log-backed transaction manager unavailable: 0x%08lx", st);
    }
}

TEST(registry_transaction)
{
    HANDLE rt = NULL; NTSTATUS s;
    if (!UN(NtCreateRegistryTransaction) || !UN(NtCommitRegistryTransaction)) { t_skip("registry transactions not exported"); return; }
    s = UN(NtCreateRegistryTransaction)(&rt, 0x1F0003, NULL, 0);
    EXPECT_EQ(s, 0); CHECK(rt != NULL);
    if (s >= 0 && rt) {
        EXPECT_EQ(UN(NtCommitRegistryTransaction)(rt, 1), ST_INVPARAM);        /* flags must be zero */
        s = UN(NtCommitRegistryTransaction)(rt, 0);
        EXPECT_EQ(s, ST_DENIED);       /* observed: the handle created above lacks the access the commit requires */
        UN(NtClose)(rt);
    }
    rt = NULL;
    s = UN(NtCreateRegistryTransaction)(&rt, 0x1F0003, NULL, 1);
    EXPECT_EQ(s, ST_INVPARAM);         /* creation flags must be zero */
    if (s >= 0 && rt) UN(NtClose)(rt);
    EXPECT_EQ(UN(NtCommitRegistryTransaction)(NULL, 0), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtCommitRegistryTransaction)(ev, 0), ST_TYPEMISM); CloseHandle(ev); }
    /* a handle created with MAXIMUM_ALLOWED can commit, and only once */
    rt = NULL;
    s = UN(NtCreateRegistryTransaction)(&rt, MAXIMUM_ALLOWED, NULL, 0);
    EXPECT_EQ(s, 0);
    if (s >= 0 && rt) {
        EXPECT_EQ(UN(NtCommitRegistryTransaction)(rt, 0), 0);
        s = UN(NtCommitRegistryTransaction)(rt, 0); EXPECT_EQ(s, S(0xC0190003));   /* observed: transaction no longer active */
        UN(NtClose)(rt);
    }
}

/* ---- legacy LPC ports ----------------------------------------------------------------------------- */
TEST(port_errors)
{
    HANDLE h = NULL; NTSTATUS s; UNICODE_STRING nm; SECURITY_QUALITY_OF_SERVICE q; ULONG ml = 0, cl = 0; WCHAR name[96];
    REQUIRE(UN(NtConnectPort)); REQUIRE(UN(NtAcceptConnectPort)); REQUIRE(UN(NtCompleteConnectPort));
    swprintf(name, 96, L"\\RPC Control\\nt1a_no_such_port_%lu", GetCurrentProcessId()); us(&nm, name);
    memset(&q, 0, sizeof q); q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation;
    s = UN(NtConnectPort)(&h, &nm, &q, NULL, NULL, &ml, NULL, &cl);
    EXPECT_EQ(s, S(0xC0000034));               /* STATUS_OBJECT_NAME_NOT_FOUND */
    s = UN(NtConnectPort)(&h, NULL, &q, NULL, NULL, &ml, NULL, &cl);
    EXPECT_EQ(s, S(0xC0000033));               /* STATUS_OBJECT_NAME_INVALID */
    s = UN(NtConnectPort)(&h, &nm, NULL, NULL, NULL, &ml, NULL, &cl);
    EXPECT_EQ(s, S(0xC0000034));
    /* NtCompleteConnectPort does not validate its handle */
    EXPECT_EQ(UN(NtCompleteConnectPort)(NULL), 0);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtCompleteConnectPort)(ev), 0); CloseHandle(ev); }
    { BYTE msg[256] = {0}; h = NULL;
      s = UN(NtAcceptConnectPort)(&h, NULL, msg, FALSE, NULL, NULL);
      EXPECT_EQ(s, S(0xC000021F));             /* STATUS_REPLY_MESSAGE_MISMATCH: no such pending connection request */
      s = UN(NtAcceptConnectPort)(&h, NULL, NULL, TRUE, NULL, NULL);
      EXPECT_EQ(s, ST_AV); }
}

/* Full legacy-LPC connection handshake, run in a child process with a hard timeout:
 * CreatePort -> client NtConnectPort / server NtListenPort -> NtAcceptConnectPort -> NtCompleteConnectPort. */
typedef struct { volatile LONG step; volatile NTSTATUS st[6]; volatile ULONG msgtype; } lpc_state;
static lpc_state g_lpc;
static WCHAR g_lpc_name[96];
static HANDLE g_lpc_port;

static DWORD WINAPI lpc_server(LPVOID p)
{
    union { ULONGLONG a; BYTE b[0x400]; } lb; HANDLE sp = NULL; NTSTATUS s;
    memset(&lb, 0, sizeof lb);
    s = UN(NtListenPort)(g_lpc_port, lb.b); g_lpc.st[1] = s; if (s < 0) return 1;
    g_lpc.msgtype = *(USHORT *)(lb.b + 4) & 0xFF;
    s = UN(NtAcceptConnectPort)(&sp, (PVOID)(ULONG_PTR)0x1234, lb.b, TRUE, NULL, NULL); g_lpc.st[2] = s; if (s < 0) return 2;
    s = UN(NtCompleteConnectPort)(sp); g_lpc.st[3] = s;
    InterlockedExchange(&g_lpc.step, 3);
    Sleep(500);
    UN(NtClose)(sp);
    return 0;
}

CHILD(nt1a_lpc)
{
    UNICODE_STRING nm; OBJECT_ATTRIBUTES oa; NTSTATUS s; HANDLE th, cp = NULL; SECURITY_QUALITY_OF_SERVICE q; ULONG maxlen = 0; DWORD w;
    swprintf(g_lpc_name, 96, L"\\RPC Control\\nt1a_lpc_%lu", GetCurrentProcessId());
    us(&nm, g_lpc_name);
    InitializeObjectAttributes(&oa, &nm, 0, NULL, NULL);
    s = UN(NtCreatePort)(&g_lpc_port, &oa, 0x100, 0x100, 0); g_lpc.st[0] = s;
    if (s < 0) return 10 + 0;
    th = CreateThread(NULL, 0, lpc_server, NULL, 0, NULL);
    memset(&q, 0, sizeof q); q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation; q.ContextTrackingMode = 1;
    s = UN(NtConnectPort)(&cp, &nm, &q, NULL, NULL, &maxlen, NULL, NULL); g_lpc.st[4] = s;
    w = WaitForSingleObject(th, 20000);
    printf("lpc: create=%08lx listen=%08lx accept=%08lx complete=%08lx connect=%08lx maxlen=%lu msgtype=%lu wait=%lu\n",
        g_lpc.st[0], g_lpc.st[1], g_lpc.st[2], g_lpc.st[3], g_lpc.st[4], maxlen, g_lpc.msgtype, w);
    if (w != WAIT_OBJECT_0) return 20;
    if (g_lpc.st[1] < 0) return 21;
    if (g_lpc.st[2] < 0) return 22;
    if (g_lpc.st[3] < 0) return 23;
    if (s < 0) return 24;
    if (g_lpc.msgtype != 10) return 25;         /* LPC_CONNECTION_REQUEST */
    if (maxlen == 0) return 26;
    UN(NtClose)(cp); UN(NtClose)(g_lpc_port);
    return 0;
}

TEST(port_connect_accept_complete)
{
    DWORD rc;
    REQUIRE(UN(NtCreatePort)); REQUIRE(UN(NtListenPort)); REQUIRE(UN(NtConnectPort)); REQUIRE(UN(NtAcceptConnectPort)); REQUIRE(UN(NtCompleteConnectPort));
    rc = t_run_child("nt1a_lpc", "", 60000);
    t_note("lpc child exit code %lu", rc);
    EXPECT_EQ(rc, 0);
}

/* ---- debug objects -------------------------------------------------------------------------------------- */
CHILD(nt1a_dbg_idle) { Sleep(60000); return 0; }

TEST(debug_object_attach)
{
    HANDLE dbg = NULL, proc, ev; NTSTATUS s; PROCESS_INFORMATION pi; LARGE_INTEGER to;
    REQUIRE(UN(NtCreateDebugObject)); REQUIRE(UN(NtDebugActiveProcess)); REQUIRE(UN(NtDebugContinue));
    s = UN(NtCreateDebugObject)(&dbg, 0x1F000F, NULL, 0); EXPECT_EQ(s, 0);
    if (s < 0) return;
    /* error paths */
    s = UN(NtDebugActiveProcess)(NULL, dbg); EXPECT_EQ(s, ST_INVHANDLE);
    s = UN(NtDebugActiveProcess)(NT_SELF, NULL); EXPECT_EQ(s, ST_DENIED);
    ev = CreateEventW(NULL, 1, 0, NULL);
    s = UN(NtDebugActiveProcess)(NT_SELF, ev); EXPECT_EQ(s, ST_DENIED);
    s = UN(NtDebugActiveProcess)(ev, dbg); EXPECT_EQ(s, ST_TYPEMISM);
    CloseHandle(ev);
    s = UN(NtDebugActiveProcess)(NT_SELF, dbg); EXPECT_EQ(s, ST_DENIED);
    { CLIENT_ID cid = { 0, 0 };
      s = UN(NtDebugContinue)(dbg, &cid, 0x10002); EXPECT_EQ(s, ST_INVPARAM);
      s = UN(NtDebugContinue)(dbg, &cid, 0x123); EXPECT_EQ(s, ST_INVPARAM);
      s = UN(NtDebugContinue)(NULL, &cid, 0x10002); EXPECT_EQ(s, ST_INVHANDLE);
      s = UN(NtDebugContinue)(dbg, NULL, 0x10002); EXPECT_EQ(s, ST_AV); }
    /* attach to a child process */
    proc = t_spawn_child("nt1a_dbg_idle", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (proc) {
        HANDLE noacc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
        if (noacc) { s = UN(NtDebugActiveProcess)(noacc, dbg); EXPECT_EQ(s, ST_DENIED); CloseHandle(noacc); }
        s = UN(NtDebugActiveProcess)(proc, dbg); EXPECT_EQ(s, 0);
        if (s >= 0) {
            s = UN(NtDebugActiveProcess)(proc, dbg); EXPECT_EQ(s, S(0xC0000048));   /* STATUS_PORT_ALREADY_SET */
            if (UN(NtWaitForDebugEvent)) {
                BYTE sc[512]; memset(sc, 0, sizeof sc); to.QuadPart = -100000000;
                s = UN(NtWaitForDebugEvent)(dbg, FALSE, &to, sc);
                EXPECT_EQ(s, 0);
                EXPECT_EQ(*(ULONG *)sc, 3);                                /* DbgCreateProcessStateChange */
                EXPECT_EQ(*(ULONG *)(sc + 8), pi.dwProcessId);
                EXPECT_EQ(*(ULONG *)(sc + 16), pi.dwThreadId);
                if (s == 0) { CLIENT_ID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)*(ULONG_PTR *)(sc + 8); cid.UniqueThread = (HANDLE)(ULONG_PTR)*(ULONG_PTR *)(sc + 16);
                    s = UN(NtDebugContinue)(dbg, &cid, 0x10002); EXPECT_EQ(s, 0); }
            }
            if (UN(NtRemoveProcessDebug)) { s = UN(NtRemoveProcessDebug)(proc, dbg); EXPECT_EQ(s, 0); }
        }
        TerminateProcess(proc, 0); WaitForSingleObject(proc, 10000);
        CloseHandle(pi.hThread); CloseHandle(proc);
    }
    UN(NtClose)(dbg);
}

/* ---- WNF ----------------------------------------------------------------------------------------------------------- */
TEST(wnf_delete)
{
    ULONGLONG name[2] = { 0x41C64E6DA3BC0074ULL, 0 }, tmpl[2] = { 0, 0 }; NTSTATUS s; BYTE sd[256], acl[256];
    REQUIRE(UN(NtDeleteWnfStateData)); REQUIRE(UN(NtDeleteWnfStateName));
    s = UN(NtDeleteWnfStateData)(name, NULL); EXPECT_EQ(s, ST_INVPARAM);
    s = UN(NtDeleteWnfStateName)(name); EXPECT_EQ(s, ST_INVPARAM);
    s = UN(NtDeleteWnfStateData)(NULL, NULL); EXPECT_EQ(s, ST_AV);
    s = UN(NtDeleteWnfStateName)(NULL); EXPECT_EQ(s, ST_AV);
    s = UN(NtDeleteWnfStateName)((PVOID)(ULONG_PTR)8); EXPECT_EQ(s, ST_AV);
    if (UN(NtCreateWnfStateName) && UN(RtlCreateSecurityDescriptor)) {
        static const BYTE world[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
        UN(RtlCreateSecurityDescriptor)(sd, 1);
        UN(RtlSetOwnerSecurityDescriptor)(sd, (PSID)world, FALSE);
        UN(RtlSetGroupSecurityDescriptor)(sd, (PSID)world, FALSE);
        UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, NULL, FALSE);   /* NULL DACL: everyone full access */
        for (ULONG scope = 0; scope < 6; scope++) {
            tmpl[0] = tmpl[1] = 0;
            s = UN(NtCreateWnfStateName)(tmpl, 3 /* temporary */, scope, FALSE, NULL, 0x1000, sd);
            t_note("create temporary name scope %lu: 0x%08lx name=%llx", scope, s, tmpl[0]);
            if (s >= 0) {
                ULONG v = 5;
                if (UN(NtUpdateWnfStateData)) { s = UN(NtUpdateWnfStateData)(tmpl, &v, 4, NULL, NULL, 0, 0); EXPECT_EQ(s, 0); }
                s = UN(NtDeleteWnfStateData)(tmpl, NULL); EXPECT_EQ(s, 0);
                s = UN(NtDeleteWnfStateData)(tmpl, NULL); EXPECT_EQ(s, 0);      /* deleting absent data is not an error */
                s = UN(NtDeleteWnfStateName)(tmpl); EXPECT_EQ(s, 0);
                s = UN(NtDeleteWnfStateName)(tmpl); EXPECT_EQ(s, S(0xC0000034));
                break;
            }
        }
    }
}

/* ---- private namespace ------------------------------------------------------------------------------------------------ */
TEST(delete_private_namespace)
{
    HANDLE bd, ns; NTSTATUS s; WCHAR nm[64], bdn[64]; static const BYTE world[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
    REQUIRE(UN(NtDeletePrivateNamespace));
    swprintf(bdn, 64, L"nt1a_bd_%lu", GetCurrentProcessId()); swprintf(nm, 64, L"nt1a_ns_%lu", GetCurrentProcessId());
    bd = CreateBoundaryDescriptorW(bdn, 0);
    CHECK(bd != NULL);
    if (bd) {
        CHECK(AddSIDToBoundaryDescriptor(&bd, (PSID)world));
        ns = CreatePrivateNamespaceW(NULL, bd, nm);
        if (!ns && GetLastError() == ERROR_ACCESS_DENIED) t_note("CreatePrivateNamespace denied for this account: namespace deletion not exercised");
        else CHECKF(ns != NULL, "CreatePrivateNamespace error %lu", GetLastError());
        if (ns) {
            s = UN(NtDeletePrivateNamespace)(ns); EXPECT_EQ(s, 0);
            s = UN(NtDeletePrivateNamespace)(ns); EXPECT_EQ(s, ST_INVHANDLE);   /* the handle was invalidated */
            CloseHandle(ns);
        }
        DeleteBoundaryDescriptor(bd);
    }
    s = UN(NtDeletePrivateNamespace)(NULL); EXPECT_EQ(s, ST_INVHANDLE);
    s = UN(NtDeletePrivateNamespace)((HANDLE)(ULONG_PTR)0xdeadbee0); EXPECT_EQ(s, ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); s = UN(NtDeletePrivateNamespace)(ev); EXPECT_EQ(s, ST_TYPEMISM); CloseHandle(ev); }
}
