/* Worker factory objects: NtCreateWorkerFactory, NtQuery/SetInformationWorkerFactory,
 * NtShutdownWorkerFactory, NtReleaseWorkerFactoryWorker, NtWorkerFactoryWorkerReady,
 * NtWaitForWorkViaWorkerFactory (argument validation only). See EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtCreateWorkerFactory, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T));
UDECL(NTSTATUS, NtQueryInformationWorkerFactory, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationWorkerFactory, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtShutdownWorkerFactory, (HANDLE, LONG *));
UDECL(NTSTATUS, NtReleaseWorkerFactoryWorker, (HANDLE));
UDECL(NTSTATUS, NtWorkerFactoryWorkerReady, (HANDLE));
UDECL(NTSTATUS, NtWaitForWorkViaWorkerFactory, (HANDLE, PVOID, ULONG, PULONG, PVOID));
UDECL(NTSTATUS, NtCreateIoCompletion, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE S(0xC0000008)
#define ST_INV_PARAM S(0xC000000D)
#define ST_TYPE S(0xC0000024)
#define ST_INFO_CLASS S(0xC0000003)
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_ACCVIO S(0xC0000005)
#define ST_DENIED S(0xC0000022)
#define WF_ALL 0xF00FF
#define CUR_PROC ((HANDLE)(LONG_PTR)-1)

typedef struct {
    LARGE_INTEGER Timeout, RetryTimeout, IdleTimeout;
    BOOLEAN Paused, TimerSet, QueuedToExWorker, MayCreate, CreateInProgress, InsertedIntoQueue, Shutdown;
    ULONG BindingCount, ThreadMinimum, ThreadMaximum, PendingWorkerCount, WaitingWorkerCount, TotalWorkerCount, ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine, StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve, StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WFBASIC;

static volatile LONG g_started;
static volatile ULONG_PTR g_param;
static DWORD WINAPI wf_start(LPVOID p) { g_param = (ULONG_PTR)p; InterlockedIncrement(&g_started); return 0; }

#define NEED() do { REQUIRE(UN(NtCreateWorkerFactory)); REQUIRE(UN(NtQueryInformationWorkerFactory)); REQUIRE(UN(NtSetInformationWorkerFactory)); REQUIRE(UN(NtShutdownWorkerFactory)); REQUIRE(UN(NtCreateIoCompletion)); REQUIRE(UN(NtClose)); } while (0)

static NTSTATUS make(HANDLE *wf, HANDLE *io, ULONG maxthr)
{
    *wf = NULL; *io = NULL;
    NTSTATUS st = UN(NtCreateIoCompletion)(io, 0x1F0003, NULL, 0);
    if (st) return st;
    st = UN(NtCreateWorkerFactory)(wf, WF_ALL, NULL, *io, CUR_PROC, (PVOID)wf_start, (PVOID)0x1234, maxthr, 0, 0);
    if (st) { UN(NtClose)(*io); *io = NULL; }
    return st;
}

TEST(alias_pairs)
{
    static const char *n[] = { "CreateWorkerFactory", "QueryInformationWorkerFactory", "SetInformationWorkerFactory",
        "ShutdownWorkerFactory", "ReleaseWorkerFactoryWorker", "WorkerFactoryWorkerReady", "WaitForWorkViaWorkerFactory" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64];
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == pb, "%s / %s must be the same entry", a, b);
    }
}

TEST(create_query_basic)
{
    NEED();
    HANDLE wf, io; NTSTATUS st = make(&wf, &io, 4);
    EXPECT_EQ(st, 0);
    if (st) return;
    WFBASIC b; ULONG rl = 0; memset(&b, 0xcc, sizeof b);
    st = UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, &rl);
    t_note("basic query -> 0x%lx rl=%lu sizeof=%zu", (unsigned long)st, rl, sizeof b);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        EXPECT_EQ(rl, sizeof b);
        EXPECT_EQ((ULONG_PTR)b.StartRoutine, (ULONG_PTR)wf_start);
        EXPECT_EQ((ULONG_PTR)b.StartParameter, 0x1234);
        EXPECT_EQ(b.ThreadMaximum, 4);
        EXPECT_EQ(b.ThreadMinimum, 0);
        EXPECT_EQ((ULONG_PTR)b.ProcessId, GetCurrentProcessId());
        EXPECT_EQ(b.Shutdown, 0);
        EXPECT_EQ(b.TotalWorkerCount, 0);
        EXPECT_EQ(b.BindingCount, 0);
        t_note("timeout=%lld retry=%lld idle=%lld paused=%d mayCreate=%d stack=%zx/%zx", b.Timeout.QuadPart, b.RetryTimeout.QuadPart, b.IdleTimeout.QuadPart, b.Paused, b.MayCreate, b.StackReserve, b.StackCommit);
    }
    /* info length validation */
    st = UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b - 1, &rl);
    EXPECT_EQ(st, ST_LEN_MISMATCH);
    EXPECT_EQ(rl, sizeof b);
    st = UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL);
    EXPECT_EQ(st, 0);
    st = UN(NtQueryInformationWorkerFactory)(wf, 0x40, &b, sizeof b, &rl);
    EXPECT_EQ(st, ST_INFO_CLASS);
    st = UN(NtQueryInformationWorkerFactory)(wf, 7, NULL, sizeof b, &rl);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtQueryInformationWorkerFactory)(NULL, 7, &b, sizeof b, &rl);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtQueryInformationWorkerFactory)(io, 7, &b, sizeof b, &rl);
    EXPECT_EQ(st, ST_TYPE);
    UN(NtClose)(wf);
    UN(NtClose)(io);
}

TEST(create_errors)
{
    NEED();
    HANDLE wf = NULL, io = NULL; NTSTATUS st;
    EXPECT_EQ(UN(NtCreateIoCompletion)(&io, 0x1F0003, NULL, 0), 0);
    st = UN(NtCreateWorkerFactory)(NULL, WF_ALL, NULL, io, CUR_PROC, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, NULL, CUR_PROC, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, io, NULL, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, ev, CUR_PROC, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, io, ev, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, ST_TYPE);
    CloseHandle(ev);
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, io, CUR_PROC, (PVOID)wf_start, NULL, 0, 0, 0);
    EXPECT_EQ(st, 0);   /* accepted on Windows 10 */
    if (st == 0) { UN(NtClose)(wf); wf = NULL; }
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, io, CUR_PROC, NULL, NULL, 4, 0, 0);
    EXPECT_EQ(st, 0);
    if (st == 0) { UN(NtClose)(wf); wf = NULL; }
    st = UN(NtCreateWorkerFactory)(&wf, WF_ALL, NULL, io, CUR_PROC, (PVOID)wf_start, NULL, 4, 0x1000, 0x2000);
    EXPECT_EQ(st, 0);
    if (st == 0) { UN(NtClose)(wf); wf = NULL; }
    /* the same completion port cannot back two factories */
    HANDLE a = NULL, b = NULL;
    EXPECT_EQ(UN(NtCreateWorkerFactory)(&a, WF_ALL, NULL, io, CUR_PROC, (PVOID)wf_start, NULL, 4, 0, 0), 0);
    st = UN(NtCreateWorkerFactory)(&b, WF_ALL, NULL, io, CUR_PROC, (PVOID)wf_start, NULL, 4, 0, 0);
    EXPECT_EQ(st, 0);
    if (st == 0) UN(NtClose)(b);
    if (a) UN(NtClose)(a);
    UN(NtClose)(io);
}

TEST(set_info_classes)
{
    NEED();
    HANDLE wf, io; NTSTATUS st = make(&wf, &io, 8);
    EXPECT_EQ(st, 0);
    if (st) return;
    WFBASIC b; ULONG v;
    /* probe every class for set and query */
    /* only BasicInformation (7) can be queried */
    for (ULONG c = 0; c < 20; c++) {
        ULONG qv[8] = {0}, rl = 0;
        if (c == 7) continue;
        st = UN(NtQueryInformationWorkerFactory)(wf, c, qv, sizeof qv, &rl);
        EXPECT_EQ(st, ST_INFO_CLASS);
    }
    /* set: ULONG classes take exactly 4 bytes */
    static const ULONG ulong_classes[] = { 3, 4, 5, 8, 11, 12, 13, 14 };
    for (unsigned k = 0; k < sizeof ulong_classes / sizeof *ulong_classes; k++) {
        ULONG c = ulong_classes[k], one = 1;
        EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, c, &one, 4), 0);
        EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, c, &one, 3), ST_LEN_MISMATCH);
        EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, c, &one, 8), ST_LEN_MISMATCH);
        EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, c, &one, 0), ST_LEN_MISMATCH);
    }
    for (ULONG c = 0; c < 20; c++) {
        ULONGLONG buf[4] = { 1, 1, 1, 1 };
        if (c == 0 || c == 1 || c == 7 || c >= 16)
            EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, c, buf, 4), ST_INFO_CLASS);
    }
    { ULONG zero = 0; EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 6, &zero, 4), S(0xC0000002)); }  /* Paused: not implemented */
    { LARGE_INTEGER neg; neg.QuadPart = -50000000;
      EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 2, &neg, 8), 0);
      EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 2, &neg, 4), ST_LEN_MISMATCH);
      LARGE_INTEGER pos; pos.QuadPart = 1;
      EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 2, &pos, 8), ST_INV_PARAM);
      EXPECT_EQ(UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL), 0);
      EXPECT_EQ(b.IdleTimeout.QuadPart, -50000000); }
    { ULONGLONG stk[2] = { 0x200000, 0x4000 };
      EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 10, stk, 16), 0);
      EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 10, stk, 8), ST_LEN_MISMATCH);
      EXPECT_EQ(UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL), 0);
      EXPECT_EQ(b.StackReserve, 0x200000); EXPECT_EQ(b.StackCommit, 0x4000); }
    { ULONG badcb = 3; t_note("callback-type 3 -> 0x%lx", (unsigned long)UN(NtSetInformationWorkerFactory)(wf, 9, &badcb, 4)); }
    v = 2;
    EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 4, &v, 4), 0);
    v = 6;
    EXPECT_EQ(UN(NtSetInformationWorkerFactory)(wf, 5, &v, 4), 0);
    EXPECT_EQ(UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.ThreadMinimum, 2);
    EXPECT_EQ(b.ThreadMaximum, 6);
    st = UN(NtSetInformationWorkerFactory)(wf, 0x40, &v, 4);
    EXPECT_EQ(st, ST_INFO_CLASS);
    st = UN(NtSetInformationWorkerFactory)(NULL, 4, &v, 4);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtSetInformationWorkerFactory)(io, 4, &v, 4);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtSetInformationWorkerFactory)(wf, 4, NULL, 4);
    EXPECT_EQ(st, ST_ACCVIO);
    UN(NtClose)(wf); UN(NtClose)(io);
}

TEST(shutdown_release_ready)
{
    NEED();
    REQUIRE(UN(NtReleaseWorkerFactoryWorker)); REQUIRE(UN(NtWorkerFactoryWorkerReady)); REQUIRE(UN(NtWaitForWorkViaWorkerFactory));
    HANDLE wf, io; NTSTATUS st = make(&wf, &io, 2);
    EXPECT_EQ(st, 0);
    if (st) return;
    LONG pend = 0x55;
    st = UN(NtShutdownWorkerFactory)(NULL, &pend);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtShutdownWorkerFactory)(io, &pend);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtReleaseWorkerFactoryWorker)(NULL);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtReleaseWorkerFactoryWorker)(io);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtWorkerFactoryWorkerReady)(NULL);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtWorkerFactoryWorkerReady)(io);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtWaitForWorkViaWorkerFactory)(NULL, NULL, 0, NULL, NULL);
    t_note("wait for work NULL handle -> 0x%lx", (unsigned long)st);
    st = UN(NtWaitForWorkViaWorkerFactory)(io, NULL, 0, NULL, NULL);
    t_note("wait for work wrong type -> 0x%lx", (unsigned long)st);
    st = UN(NtWorkerFactoryWorkerReady)(wf);
    EXPECT_EQ(st, S(0xC0000001));

    g_started = 0;
    st = UN(NtReleaseWorkerFactoryWorker)(wf);
    EXPECT_EQ(st, 0);
    DWORD t0 = GetTickCount();
    while (g_started == 0 && GetTickCount() - t0 < 3000) Sleep(10);
    CHECK(g_started >= 1);
    EXPECT_EQ(g_param, 0x1234);
    WFBASIC b; memset(&b, 0, sizeof b);
    UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL);
    t_note("after release: total=%lu pending=%lu waiting=%lu release=%lu", b.TotalWorkerCount, b.PendingWorkerCount, b.WaitingWorkerCount, b.ReleaseCount);

    pend = 0x55;
    st = UN(NtShutdownWorkerFactory)(wf, &pend);
    EXPECT_EQ(st, 0);
    t_note("shutdown pending=%ld", pend);
    memset(&b, 0, sizeof b);
    st = UN(NtQueryInformationWorkerFactory)(wf, 7, &b, sizeof b, NULL);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(b.Shutdown, 1);
    st = UN(NtReleaseWorkerFactoryWorker)(wf);
    t_note("release after shutdown -> 0x%lx", (unsigned long)st);
    st = UN(NtShutdownWorkerFactory)(wf, &pend);
    EXPECT_EQ(st, 0);
    Sleep(200);
    UN(NtClose)(wf); UN(NtClose)(io);
}
