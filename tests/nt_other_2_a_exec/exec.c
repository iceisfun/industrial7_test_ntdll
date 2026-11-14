/* Thread/process suspension and termination, alerts, signal-and-wait, keyed events, event pairs,
 * write watch, VM unlock, view unmapping, file unlock, gather writes, debug objects.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_TIMEOUT      S(0x102)
#define ST_ALERTED      S(0x101)
#define ST_NO_YIELD     S(0x40000024)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_INV_PARAM_1  S(0xC00000EF)
#define ST_INV_PARAM_3  S(0xC00000F1)
#define ST_NOT_IMPL     S(0xC0000002)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_NOT_MAPPED   S(0xC0000019)
#define ST_NOT_LOCKED   S(0xC000002A)
#define ST_RANGE_NOT_LOCKED S(0xC000007E)
#define ST_PROC_TERM    S(0xC000010A)
#define ST_THREAD_TERM  S(0xC000004B)
#define ST_MUTANT_NOT_OWNED S(0xC0000046)
#define NT_CUR_PROC ((HANDLE)(LONG_PTR)-1)
#define NT_CUR_THREAD ((HANDLE)(LONG_PTR)-2)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)

UDECL(NTSTATUS, NtSuspendThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtSuspendProcess, (HANDLE));
UDECL(NTSTATUS, NtResumeProcess, (HANDLE));
UDECL(NTSTATUS, NtTerminateThread, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtTerminateJobObject, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtTestAlert, (void));
UDECL(NTSTATUS, NtYieldExecution, (void));
UDECL(NTSTATUS, NtSignalAndWaitForSingleObject, (HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForMultipleObjects32, (ULONG, LONG *, ULONG, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtWaitLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtWaitForAlertByThreadId, (PVOID, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAlertThreadByThreadId, (HANDLE));
UDECL(NTSTATUS, NtReleaseKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCreateEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtResetWriteWatch, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, NtUnlockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSectionEx, (HANDLE, PVOID, ULONG));
UDECL(NTSTATUS, NtLockFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, NtUnlockFile, (HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG));
UDECL(NTSTATUS, NtWriteFileGather, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtWaitForDebugEvent, (HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, NtRemoveProcessDebug, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtSystemDebugControl, (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtStartProfile, (HANDLE));
UDECL(NTSTATUS, NtStopProfile, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)
#define REL(ms) (LARGE_INTEGER){ .QuadPart = -(LONGLONG)(ms) * 10000 }

static volatile LONG g_stop;
static DWORD WINAPI spin_thread(LPVOID p) { while (!g_stop) Sleep(5); return 0x55; }

/* ---- thread suspend / resume / terminate ------------------------------- */
TEST(thread_suspend_resume_counts)
{
    REQUIRE(UN(NtSuspendThread)); REQUIRE(UN(NtResumeThread));
    g_stop = 0;
    HANDLE th = CreateThread(NULL, 0, spin_thread, NULL, CREATE_SUSPENDED, NULL);
    REQUIRE(th);
    ULONG prev = 0xcccc;
    EXPECT_ST(UN(NtSuspendThread)(th, &prev), 0); EXPECT_EQ(prev, 1);   /* created suspended: count 1 -> 2 */
    EXPECT_ST(UN(NtSuspendThread)(th, NULL), 0);                        /* optional output; count 3 */
    prev = 0xcccc; EXPECT_ST(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 3);
    prev = 0xcccc; EXPECT_ST(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 2);
    prev = 0xcccc; EXPECT_ST(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 1); /* now running */
    prev = 0xcccc; EXPECT_ST(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 0); /* not suspended: stays 0 */
    prev = 0xcccc; EXPECT_ST(UN(NtSuspendThread)(th, &prev), 0); EXPECT_EQ(prev, 0);
    prev = 0xcccc; EXPECT_ST(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 1);
    g_stop = 1;
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    DWORD code = 0; GetExitCodeThread(th, &code); EXPECT_EQ(code, 0x55);
    CloseHandle(th);
}

TEST(thread_suspend_resume_errors)
{
    REQUIRE(UN(NtSuspendThread)); REQUIRE(UN(NtResumeThread));
    ULONG prev = 0xcccc;
    EXPECT_ST(UN(NtSuspendThread)(BOGUS, &prev), ST_INV_HANDLE);
    EXPECT_ST(UN(NtResumeThread)(BOGUS, &prev), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSuspendThread)(NULL, &prev), ST_INV_HANDLE);
    EXPECT_ST(UN(NtResumeThread)(NULL, NULL), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtSuspendThread)(ev, &prev), ST_TYPE_MISM);
    EXPECT_ST(UN(NtResumeThread)(ev, &prev), ST_TYPE_MISM);
    CloseHandle(ev);
    /* handle without THREAD_SUSPEND_RESUME */
    g_stop = 0;
    HANDLE th = CreateThread(NULL, 0, spin_thread, NULL, 0, NULL);
    REQUIRE(th);
    HANDLE ro = NULL;
    if (DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &ro, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0)) {
        EXPECT_ST(UN(NtSuspendThread)(ro, &prev), ST_DENIED);
        EXPECT_ST(UN(NtResumeThread)(ro, &prev), ST_DENIED);
        CloseHandle(ro);
    }
    /* unwritable output pointer */
    EXPECT_ST(UN(NtSuspendThread)(th, (PULONG)(ULONG_PTR)8), S(0xC0000005));
    EXPECT_ST(UN(NtResumeThread)(th, (PULONG)(ULONG_PTR)8), S(0xC0000005));
    g_stop = 1; WaitForSingleObject(th, 5000); CloseHandle(th);
}

TEST(thread_terminate)
{
    REQUIRE(UN(NtTerminateThread));
    g_stop = 0;
    HANDLE th = CreateThread(NULL, 0, spin_thread, NULL, 0, NULL);
    REQUIRE(th);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtTerminateThread)(BOGUS, 1), ST_INV_HANDLE);
    EXPECT_ST(UN(NtTerminateThread)(ev, 1), ST_TYPE_MISM);
    HANDLE ro = NULL;
    if (DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &ro, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0)) {
        EXPECT_ST(UN(NtTerminateThread)(ro, 1), ST_DENIED);
        CloseHandle(ro);
    }
    EXPECT_ST(UN(NtTerminateThread)(th, S(0x1234)), 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    DWORD code = 0; GetExitCodeThread(th, &code); EXPECT_EQ(code, 0x1234);
    NTSTATUS st = UN(NtTerminateThread)(th, S(0x99));
    EXPECT_ST(st, 0);   /* terminating an already-exited thread through a valid handle still succeeds */
    CloseHandle(ev); CloseHandle(th);
    CHECK(t_proc("NtTerminateThread") == t_proc("ZwTerminateThread"));
}

/* ---- processes ---------------------------------------------------------- */
CHILD(sleeper) { Sleep(120000); return 0; }

TEST(process_suspend_resume_terminate)
{
    REQUIRE(UN(NtSuspendProcess)); REQUIRE(UN(NtResumeProcess)); REQUIRE(UN(NtTerminateProcess));
    REQUIRE(UN(NtSuspendThread)); REQUIRE(UN(NtResumeThread));
    PROCESS_INFORMATION pi;
    HANDLE hp = t_spawn_child("sleeper", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    REQUIRE(hp);
    ULONG prev = 0xcccc;
    /* initial thread is suspended once from creation */
    EXPECT_ST(UN(NtSuspendProcess)(hp), 0);
    EXPECT_ST(UN(NtSuspendThread)(pi.hThread, &prev), 0); EXPECT_EQ(prev, 2);
    EXPECT_ST(UN(NtResumeProcess)(hp), 0);
    EXPECT_ST(UN(NtResumeThread)(pi.hThread, &prev), 0); EXPECT_EQ(prev, 2);
    EXPECT_ST(UN(NtResumeThread)(pi.hThread, &prev), 0); EXPECT_EQ(prev, 1);   /* creation suspend released: running */
    EXPECT_EQ(WaitForSingleObject(hp, 200), WAIT_TIMEOUT);

    /* errors */
    EXPECT_ST(UN(NtSuspendProcess)(BOGUS), ST_INV_HANDLE);
    EXPECT_ST(UN(NtResumeProcess)(BOGUS), ST_INV_HANDLE);
    EXPECT_ST(UN(NtTerminateProcess)(BOGUS, 1), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtSuspendProcess)(ev), ST_TYPE_MISM);
    EXPECT_ST(UN(NtResumeProcess)(ev), ST_TYPE_MISM);
    EXPECT_ST(UN(NtTerminateProcess)(ev, 1), ST_TYPE_MISM);
    CloseHandle(ev);
    HANDLE ro = NULL;
    if (DuplicateHandle(GetCurrentProcess(), hp, GetCurrentProcess(), &ro, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0)) {
        EXPECT_ST(UN(NtSuspendProcess)(ro), ST_DENIED);
        EXPECT_ST(UN(NtResumeProcess)(ro), ST_DENIED);
        EXPECT_ST(UN(NtTerminateProcess)(ro, 1), ST_DENIED);
        CloseHandle(ro);
    }
    EXPECT_ST(UN(NtTerminateProcess)(hp, S(0x4321)), 0);
    EXPECT_EQ(WaitForSingleObject(hp, 10000), WAIT_OBJECT_0);
    DWORD code = 0; GetExitCodeProcess(hp, &code); EXPECT_EQ(code, 0x4321);
    EXPECT_ST(UN(NtTerminateProcess)(hp, S(0x99)), ST_PROC_TERM);
    CloseHandle(pi.hThread); CloseHandle(hp);
    CHECK(t_proc("NtTerminateProcess") == t_proc("ZwTerminateProcess"));
    CHECK(t_proc("NtSuspendProcess") == t_proc("ZwSuspendProcess"));
}

TEST(job_terminate)
{
    REQUIRE(UN(NtTerminateJobObject));
    HANDLE job = CreateJobObjectW(NULL, NULL);
    REQUIRE(job);
    PROCESS_INFORMATION pi;
    HANDLE hp = t_spawn_child("sleeper", "", CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!hp) hp = t_spawn_child("sleeper", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    REQUIRE(hp);
    if (!AssignProcessToJobObject(job, hp)) {
        TerminateProcess(hp, 1); CloseHandle(pi.hThread); CloseHandle(hp); CloseHandle(job);
        t_skip("cannot assign child to a job (GetLastError %lu)", GetLastError());
        return;
    }
    ResumeThread(pi.hThread);
    EXPECT_ST(UN(NtTerminateJobObject)(BOGUS, 1), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtTerminateJobObject)(ev, 1), ST_TYPE_MISM);
    CloseHandle(ev);
    HANDLE ro = NULL;
    if (DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &ro, SYNCHRONIZE | JOB_OBJECT_QUERY, FALSE, 0)) {
        EXPECT_ST(UN(NtTerminateJobObject)(ro, 1), ST_DENIED);
        CloseHandle(ro);
    }
    EXPECT_EQ(WaitForSingleObject(hp, 100), WAIT_TIMEOUT);
    EXPECT_ST(UN(NtTerminateJobObject)(job, S(0x7777)), 0);
    EXPECT_EQ(WaitForSingleObject(hp, 10000), WAIT_OBJECT_0);
    DWORD code = 0; GetExitCodeProcess(hp, &code); EXPECT_EQ(code, 0x7777);
    /* empty job again: still fine */
    EXPECT_ST(UN(NtTerminateJobObject)(job, 1), 0);
    CloseHandle(pi.hThread); CloseHandle(hp); CloseHandle(job);
}

/* ---- alerts and yield -------------------------------------------------- */
static volatile LONG g_apc_hits;
static void CALLBACK apc_fn(ULONG_PTR p) { g_apc_hits += (LONG)p; }

TEST(test_alert)
{
    REQUIRE(UN(NtTestAlert));
    EXPECT_ST(UN(NtTestAlert)(), 0);             /* nothing queued */
    g_apc_hits = 0;
    CHECK(QueueUserAPC(apc_fn, GetCurrentThread(), 5));
    CHECK(QueueUserAPC(apc_fn, GetCurrentThread(), 7));
    EXPECT_EQ(g_apc_hits, 0);
    EXPECT_ST(UN(NtTestAlert)(), 0);    /* delivers all queued user APCs; status stays SUCCESS */
    EXPECT_EQ(g_apc_hits, 12);
    EXPECT_ST(UN(NtTestAlert)(), 0);
}

TEST(yield_execution)
{
    REQUIRE(UN(NtYieldExecution));
    for (int i = 0; i < 20; i++) {
        NTSTATUS st = UN(NtYieldExecution)();
        CHECKF(st == 0 || st == ST_NO_YIELD, "got 0x%lx", (unsigned long)st);
    }
}

TEST(wait_for_alert_by_thread_id)
{
    REQUIRE(UN(NtWaitForAlertByThreadId)); REQUIRE(UN(NtAlertThreadByThreadId));
    LARGE_INTEGER to = REL(50);
    DWORD t0 = GetTickCount();
    EXPECT_ST(UN(NtWaitForAlertByThreadId)(NULL, &to), ST_TIMEOUT);
    CHECK(GetTickCount() - t0 >= 40);
    LARGE_INTEGER zero = {0};
    EXPECT_ST(UN(NtWaitForAlertByThreadId)(NULL, &zero), ST_TIMEOUT);
    /* alert delivered before the wait is remembered and consumed by the wait */
    EXPECT_ST(UN(NtAlertThreadByThreadId)((HANDLE)(ULONG_PTR)GetCurrentThreadId()), 0);
    to = REL(5000);
    EXPECT_ST(UN(NtWaitForAlertByThreadId)(NULL, &to), ST_ALERTED);
    EXPECT_ST(UN(NtWaitForAlertByThreadId)(NULL, &zero), ST_TIMEOUT);   /* consumed */
    /* alert from another thread wakes a blocked waiter */
    typedef struct { volatile LONG started; NTSTATUS st; } W;
    static W w;
    DWORD WINAPI waiter(LPVOID p) { LARGE_INTEGER t = REL(8000); InterlockedExchange(&w.started, 1);
        w.st = UN(NtWaitForAlertByThreadId)(NULL, &t); return 0; }
    DWORD tid; memset((void *)&w, 0, sizeof w);
    HANDLE th = CreateThread(NULL, 0, waiter, NULL, 0, &tid);
    REQUIRE(th);
    while (!w.started) Sleep(1);
    Sleep(50);
    EXPECT_ST(UN(NtAlertThreadByThreadId)((HANDLE)(ULONG_PTR)tid), 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    EXPECT_ST(w.st, ST_ALERTED);
    CloseHandle(th);
    EXPECT_ST(UN(NtAlertThreadByThreadId)((HANDLE)(ULONG_PTR)0xfffffff0), S(0xC000000B)); /* STATUS_INVALID_CID */
}

/* ---- signal and wait --------------------------------------------------- */
typedef struct { HANDLE a, b; } pp_t;
static DWORD WINAPI pingpong(LPVOID p)
{
    pp_t *x = p;
    WaitForSingleObject(x->a, 5000);
    SetEvent(x->b);
    return 0;
}

TEST(signal_and_wait)
{
    REQUIRE(UN(NtSignalAndWaitForSingleObject));
    HANDLE a = CreateEventW(NULL, FALSE, FALSE, NULL), b = CreateEventW(NULL, FALSE, FALSE, NULL);
    LARGE_INTEGER to = REL(5000), zero = {0};
    /* wait target already signaled */
    SetEvent(b);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(a, b, FALSE, &to), 0);
    EXPECT_EQ(WaitForSingleObject(a, 0), WAIT_OBJECT_0);          /* signal happened (consumed here) */
    EXPECT_EQ(WaitForSingleObject(b, 0), WAIT_TIMEOUT);           /* auto-reset consumed by wait */
    /* wait target never signaled: signal still performed, wait times out */
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(a, b, FALSE, &zero), ST_TIMEOUT);
    EXPECT_EQ(WaitForSingleObject(a, 0), WAIT_OBJECT_0);
    /* real ping-pong with a helper thread */
    pp_t pp = { a, b };
    HANDLE th = CreateThread(NULL, 0, pingpong, &pp, 0, NULL);
    REQUIRE(th);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(a, b, FALSE, &to), 0);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    /* semaphore: signal releases one count */
    HANDLE sem = CreateSemaphoreW(NULL, 0, 5, NULL);
    SetEvent(b);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(sem, b, FALSE, &to), 0);
    EXPECT_EQ(WaitForSingleObject(sem, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(sem, 0), WAIT_TIMEOUT);
    /* semaphore at max count */
    ReleaseSemaphore(sem, 5, NULL); SetEvent(b);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(sem, b, FALSE, &to), S(0xC0000047)); /* STATUS_SEMAPHORE_LIMIT_EXCEEDED */
    /* mutant: release of unowned mutex fails; owned works */
    HANDLE mtx = CreateMutexW(NULL, FALSE, NULL);
    SetEvent(b);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(mtx, b, FALSE, &to), ST_MUTANT_NOT_OWNED);
    WaitForSingleObject(mtx, 0); SetEvent(b);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(mtx, b, FALSE, &to), 0);
    /* errors */
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(BOGUS, b, FALSE, &zero), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(a, BOGUS, FALSE, &zero), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(NULL, b, FALSE, &zero), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(NT_CUR_PROC, b, FALSE, &zero), ST_TYPE_MISM);
    HANDLE sync_only = NULL;
    if (DuplicateHandle(GetCurrentProcess(), a, GetCurrentProcess(), &sync_only, SYNCHRONIZE, FALSE, 0)) {
        EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(sync_only, b, FALSE, &zero), ST_DENIED);
        CloseHandle(sync_only);
    }
    /* pending user APC with alertable wait */
    g_apc_hits = 0; QueueUserAPC(apc_fn, GetCurrentThread(), 1);
    EXPECT_ST(UN(NtSignalAndWaitForSingleObject)(a, b, TRUE, &to), S(0xC0)); /* STATUS_USER_APC */
    EXPECT_EQ(g_apc_hits, 1);
    CloseHandle(a); CloseHandle(b); CloseHandle(sem); CloseHandle(mtx);
    CHECK(t_proc("NtSignalAndWaitForSingleObject") == t_proc("ZwSignalAndWaitForSingleObject"));
}

TEST(wait_for_multiple_objects32)
{
    REQUIRE(UN(NtWaitForMultipleObjects32));
    HANDLE e[3];
    for (int i = 0; i < 3; i++) e[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG h32[3];
    for (int i = 0; i < 3; i++) h32[i] = (LONG)(LONG_PTR)e[i];
    LARGE_INTEGER zero = {0}, to = REL(2000);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(3, h32, 1 /*WaitAny*/, FALSE, &zero), ST_TIMEOUT);
    SetEvent(e[1]);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(3, h32, 1, FALSE, &to), 1);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(3, h32, 0 /*WaitAll*/, FALSE, &zero), ST_TIMEOUT);
    SetEvent(e[0]); SetEvent(e[2]);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(3, h32, 0, FALSE, &to), 0);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(1, &h32[2], 1, FALSE, &to), 0);
    /* errors */
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(0, h32, 1, FALSE, &zero), ST_INV_PARAM_1);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(65, h32, 1, FALSE, &zero), ST_INV_PARAM_1);
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(3, h32, 2, FALSE, &zero), ST_INV_PARAM_3);
    LONG bad[2] = { h32[0], (LONG)(LONG_PTR)BOGUS };
    EXPECT_ST(UN(NtWaitForMultipleObjects32)(2, bad, 1, FALSE, &zero), ST_INV_HANDLE);
    for (int i = 0; i < 3; i++) CloseHandle(e[i]);
}

/* ---- event pair -------------------------------------------------------- */
TEST(event_pair_wait)
{
    /* Event pairs are unsupported: both waits fail before looking at the handle. */
    REQUIRE(UN(NtWaitHighEventPair)); REQUIRE(UN(NtWaitLowEventPair));
    EXPECT_ST(UN(NtWaitHighEventPair)(BOGUS), ST_NOT_IMPL);
    EXPECT_ST(UN(NtWaitLowEventPair)(BOGUS), ST_NOT_IMPL);
    EXPECT_ST(UN(NtWaitHighEventPair)(NULL), ST_NOT_IMPL);
    HANDLE ev = CreateEventW(NULL, TRUE, TRUE, NULL);
    EXPECT_ST(UN(NtWaitHighEventPair)(ev), ST_NOT_IMPL);
    EXPECT_ST(UN(NtWaitLowEventPair)(ev), ST_NOT_IMPL);
    CloseHandle(ev);
    if (UN(NtCreateEventPair)) {
        HANDLE ep = NULL;
        EXPECT_ST(UN(NtCreateEventPair)(&ep, 0x1F0000, NULL), ST_NOT_IMPL);
    }
}

/* ---- keyed events ------------------------------------------------------ */
typedef struct { HANDLE ke; PVOID key; volatile LONG started; NTSTATUS st; } kw_t;
static DWORD WINAPI keyed_waiter(LPVOID p)
{
    kw_t *k = p; LARGE_INTEGER to = REL(8000);
    InterlockedExchange(&k->started, 1);
    k->st = UN(NtWaitForKeyedEvent)(k->ke, k->key, FALSE, &to);
    return 0;
}

TEST(keyed_event)
{
    REQUIRE(UN(NtWaitForKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtCreateKeyedEvent));
    HANDLE ke = NULL;
    EXPECT_ST(UN(NtCreateKeyedEvent)(&ke, 0x1F0003, NULL, 0), 0);
    REQUIRE(ke);
    LARGE_INTEGER zero = {0}, to = REL(30);
    PVOID key = (PVOID)(ULONG_PTR)0x1000;
    EXPECT_ST(UN(NtWaitForKeyedEvent)(ke, key, FALSE, &to), ST_TIMEOUT);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, key, FALSE, &to), ST_TIMEOUT);
    EXPECT_ST(UN(NtWaitForKeyedEvent)(ke, key, FALSE, &zero), ST_TIMEOUT);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, key, FALSE, &zero), ST_TIMEOUT);
    /* the key must have its low bit clear */
    EXPECT_ST(UN(NtWaitForKeyedEvent)(ke, (PVOID)(ULONG_PTR)0x1001, FALSE, &zero), ST_INV_PARAM_1);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, (PVOID)(ULONG_PTR)0x1001, FALSE, &zero), ST_INV_PARAM_1);
    /* handle checks */
    EXPECT_ST(UN(NtWaitForKeyedEvent)(BOGUS, key, FALSE, &zero), ST_INV_HANDLE);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(BOGUS, key, FALSE, &zero), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtWaitForKeyedEvent)(ev, key, FALSE, &zero), ST_TYPE_MISM);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ev, key, FALSE, &zero), ST_TYPE_MISM);
    CloseHandle(ev);
    /* waiter first, then releaser */
    kw_t k = { ke, key, 0, 0x7777 };
    HANDLE th = CreateThread(NULL, 0, keyed_waiter, &k, 0, NULL);
    REQUIRE(th);
    while (!k.started) Sleep(1);
    Sleep(50);
    LARGE_INTEGER rel = REL(5000);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, key, FALSE, &rel), 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    EXPECT_ST(k.st, 0);
    CloseHandle(th);
    /* a different key does not match */
    k.started = 0; k.st = 0x7777; k.key = (PVOID)(ULONG_PTR)0x2000;
    th = CreateThread(NULL, 0, keyed_waiter, &k, 0, NULL);
    REQUIRE(th);
    while (!k.started) Sleep(1);
    Sleep(50);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, key, FALSE, &to), ST_TIMEOUT);
    EXPECT_ST(UN(NtReleaseKeyedEvent)(ke, (PVOID)(ULONG_PTR)0x2000, FALSE, &rel), 0);
    WaitForSingleObject(th, 5000); EXPECT_ST(k.st, 0);
    CloseHandle(th);
    /* releaser first, then waiter */
    typedef struct { HANDLE ke; PVOID key; NTSTATUS st; } rl_t;
    static rl_t r;
    DWORD WINAPI releaser(LPVOID p) { LARGE_INTEGER t = REL(8000); r.st = UN(NtReleaseKeyedEvent)(r.ke, r.key, FALSE, &t); return 0; }
    r.ke = ke; r.key = key; r.st = 0x7777;
    th = CreateThread(NULL, 0, releaser, NULL, 0, NULL);
    REQUIRE(th);
    Sleep(100);
    EXPECT_ST(UN(NtWaitForKeyedEvent)(ke, key, FALSE, &rel), 0);
    WaitForSingleObject(th, 5000); EXPECT_ST(r.st, 0);
    CloseHandle(th);
    UN(NtClose)(ke);
    CHECK(t_proc("NtWaitForKeyedEvent") == t_proc("ZwWaitForKeyedEvent"));
    CHECK(t_proc("NtReleaseKeyedEvent") == t_proc("ZwReleaseKeyedEvent"));
}

/* ---- virtual memory ---------------------------------------------------- */
TEST(write_watch_reset)
{
    REQUIRE(UN(NtResetWriteWatch));
    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T pg = si.dwPageSize;
    BYTE *base = VirtualAlloc(NULL, 4 * pg, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    REQUIRE(base);
    base[0] = 1; base[2 * pg] = 1;
    PVOID addrs[8]; ULONG_PTR cnt = 8; DWORD gran;
    EXPECT_EQ(GetWriteWatch(0, base, 4 * pg, addrs, &cnt, &gran), 0);
    EXPECT_EQ(cnt, 2);
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, base, 4 * pg), 0);
    cnt = 8; EXPECT_EQ(GetWriteWatch(0, base, 4 * pg, addrs, &cnt, &gran), 0);
    EXPECT_EQ(cnt, 0);
    base[3 * pg] = 1;
    /* partial reset leaves other pages tracked */
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, base, pg), 0);
    cnt = 8; EXPECT_EQ(GetWriteWatch(0, base, 4 * pg, addrs, &cnt, &gran), 0);
    EXPECT_EQ(cnt, 1); EXPECT_EQ(addrs[0], base + 3 * pg);
    /* errors */
    EXPECT_ST(UN(NtResetWriteWatch)(BOGUS, base, pg), ST_INV_HANDLE);
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, base, 0), ST_INV_PARAM_3);
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, base, 8 * pg), ST_INV_PARAM_1);  /* range exceeds region */
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtResetWriteWatch)(ev, base, pg), ST_TYPE_MISM);
    CloseHandle(ev);
    VirtualFree(base, 0, MEM_RELEASE);
    /* region without write watch */
    BYTE *plain = VirtualAlloc(NULL, pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(plain);
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, plain, pg), ST_INV_PARAM_1);
    VirtualFree(plain, 0, MEM_RELEASE);
    /* freed memory */
    EXPECT_ST(UN(NtResetWriteWatch)(NT_CUR_PROC, plain, pg), ST_INV_PARAM_1);
}

TEST(unlock_virtual_memory)
{
    REQUIRE(UN(NtUnlockVirtualMemory));
    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T pg = si.dwPageSize;
    BYTE *p = VirtualAlloc(NULL, 2 * pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(p);
    PVOID base = p; SIZE_T len = pg;
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 1), ST_NOT_LOCKED);
    if (!VirtualLock(p, pg)) { t_note("VirtualLock failed %lu", GetLastError()); VirtualFree(p, 0, MEM_RELEASE); t_skip("cannot lock memory"); return; }
    base = p + 100; len = 8;                         /* rounded out to the page */
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 1), 0);
    EXPECT_EQ(base, p); EXPECT_EQ(len, pg);
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 1), ST_NOT_LOCKED);
    /* bad map type */
    base = p; len = pg;
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 0), ST_INV_PARAM);
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 4), ST_INV_PARAM);
    EXPECT_ST(UN(NtUnlockVirtualMemory)(BOGUS, &base, &len, 1), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtUnlockVirtualMemory)(ev, &base, &len, 1), ST_TYPE_MISM);
    CloseHandle(ev);
    len = 0; base = p;
    EXPECT_ST(UN(NtUnlockVirtualMemory)(NT_CUR_PROC, &base, &len, 1), ST_INV_PARAM);
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(unmap_view_of_section_ex)
{
    REQUIRE(UN(NtUnmapViewOfSectionEx));
    HANDLE m = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL);
    REQUIRE(m);
    BYTE *v = MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    REQUIRE(v);
    v[0] = 1;
    MEMORY_BASIC_INFORMATION mbi;
    EXPECT_EQ(VirtualQuery(v, &mbi, sizeof mbi) != 0 && mbi.Type == MEM_MAPPED, 1);
    EXPECT_ST(UN(NtUnmapViewOfSectionEx)(BOGUS, v, 0), ST_INV_HANDLE);
    EXPECT_ST(UN(NtUnmapViewOfSectionEx)(NT_CUR_PROC, v, 0xF0000000), ST_INV_PARAM_3);
    CHECK(VirtualQuery(v, &mbi, sizeof mbi) && mbi.Type == MEM_MAPPED);  /* rejected: still mapped */
    EXPECT_ST(UN(NtUnmapViewOfSectionEx)(NT_CUR_PROC, v + 0x1000, 0), 0);   /* any address inside the view */
    CHECK(VirtualQuery(v, &mbi, sizeof mbi) && mbi.State == MEM_FREE);
    EXPECT_ST(UN(NtUnmapViewOfSectionEx)(NT_CUR_PROC, v, 0), ST_NOT_MAPPED);
    /* a non-section region is not a mapped view */
    BYTE *priv = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(priv);
    EXPECT_ST(UN(NtUnmapViewOfSectionEx)(NT_CUR_PROC, priv, 0), ST_NOT_MAPPED);
    VirtualFree(priv, 0, MEM_RELEASE);
    CloseHandle(m);
}

/* ---- files ------------------------------------------------------------- */
TEST(unlock_file)
{
    REQUIRE(UN(NtUnlockFile)); REQUIRE(UN(NtLockFile));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "unlock.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    DWORD n; WriteFile(f, "0123456789abcdef0123456789abcdef", 32, &n, NULL);
    LARGE_INTEGER off = { .QuadPart = 4 }, len = { .QuadPart = 8 };
    IO_STATUS_BLOCK io;
    memset(&io, 0xcc, sizeof io);
    EXPECT_ST(UN(NtUnlockFile)(f, &io, &off, &len, 0), ST_RANGE_NOT_LOCKED);
    EXPECT_ST(io.Status, ST_RANGE_NOT_LOCKED);
    EXPECT_ST(UN(NtLockFile)(f, NULL, NULL, NULL, &io, &off, &len, 0, TRUE, TRUE), 0);
    /* a second handle must now be refused access to the locked range */
    HANDLE f2 = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    char b[8];
    SetFilePointer(f2, 4, NULL, FILE_BEGIN);
    CHECK(!ReadFile(f2, b, 8, &n, NULL)); EXPECT_ERR(ERROR_LOCK_VIOLATION);
    /* wrong key or range does not unlock */
    memset(&io, 0xcc, sizeof io);
    EXPECT_ST(UN(NtUnlockFile)(f, &io, &off, &len, 7), ST_RANGE_NOT_LOCKED);
    LARGE_INTEGER len2 = { .QuadPart = 4 };
    EXPECT_ST(UN(NtUnlockFile)(f, &io, &off, &len2, 0), ST_RANGE_NOT_LOCKED);
    EXPECT_ST(UN(NtUnlockFile)(f2, &io, &off, &len, 0), ST_RANGE_NOT_LOCKED);   /* not the owner */
    memset(&io, 0xcc, sizeof io);
    EXPECT_ST(UN(NtUnlockFile)(f, &io, &off, &len, 0), 0);
    EXPECT_ST(io.Status, 0);
    SetFilePointer(f2, 4, NULL, FILE_BEGIN);
    CHECK(ReadFile(f2, b, 8, &n, NULL)); EXPECT_EQ(n, 8);
    EXPECT_ST(UN(NtUnlockFile)(f, &io, &off, &len, 0), ST_RANGE_NOT_LOCKED);    /* double unlock */
    /* errors */
    EXPECT_ST(UN(NtUnlockFile)(BOGUS, &io, &off, &len, 0), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtUnlockFile)(ev, &io, &off, &len, 0), ST_TYPE_MISM);
    CloseHandle(ev);
    CloseHandle(f2); CloseHandle(f);
    DeleteFileA(path);
    CHECK(t_proc("NtUnlockFile") == t_proc("ZwUnlockFile"));
}

TEST(write_file_gather)
{
    REQUIRE(UN(NtWriteFileGather));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "gather.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                           FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T pg = si.dwPageSize;
    BYTE *buf = VirtualAlloc(NULL, 3 * pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(buf);
    for (int i = 0; i < 3; i++) memset(buf + i * pg, 'A' + i, pg);
    /* FILE_SEGMENT_ELEMENT array, null-terminated; segments listed out of address order */
    FILE_SEGMENT_ELEMENT seg[4];
    memset(seg, 0, sizeof seg);
    seg[0].Buffer = buf + 2 * pg; seg[1].Buffer = buf; seg[2].Buffer = buf + pg;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    IO_STATUS_BLOCK io; memset(&io, 0xcc, sizeof io);
    LARGE_INTEGER off = {0};
    NTSTATUS st = UN(NtWriteFileGather)(f, ev, NULL, NULL, &io, seg, (ULONG)(3 * pg), &off, NULL);
    CHECKF(st == 0 || st == S(0x103), "got 0x%lx", (unsigned long)st);
    if (st == S(0x103)) EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_ST(io.Status, 0); EXPECT_EQ(io.Information, 3 * pg);
    /* read back plainly */
    BYTE *rb = VirtualAlloc(NULL, 3 * pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    OVERLAPPED ov; memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD n = 0;
    BOOL ok = ReadFile(f, rb, (DWORD)(3 * pg), &n, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) ok = GetOverlappedResult(f, &ov, &n, TRUE);
    CHECK(ok); EXPECT_EQ(n, 3 * pg);
    CHECK(rb[0] == 'C' && rb[pg - 1] == 'C' && rb[pg] == 'A' && rb[2 * pg - 1] == 'A' && rb[2 * pg] == 'B' && rb[3 * pg - 1] == 'B');
    /* second write at a page-aligned offset, single segment */
    seg[0].Buffer = buf; seg[1].Buffer = NULL;
    memset(&io, 0xcc, sizeof io); ResetEvent(ev);
    off.QuadPart = (LONGLONG)(3 * pg);
    st = UN(NtWriteFileGather)(f, ev, NULL, NULL, &io, seg, (ULONG)pg, &off, NULL);
    CHECKF(st == 0 || st == S(0x103), "got 0x%lx", (unsigned long)st);
    if (st == S(0x103)) WaitForSingleObject(ev, 10000);
    EXPECT_EQ(io.Information, pg);
    /* unaligned length and unaligned offset are rejected */
    memset(&io, 0xcc, sizeof io);
    EXPECT_ST(UN(NtWriteFileGather)(f, NULL, NULL, NULL, &io, seg, 100, &off, NULL), ST_INV_PARAM);
    off.QuadPart = 1;
    EXPECT_ST(UN(NtWriteFileGather)(f, NULL, NULL, NULL, &io, seg, (ULONG)pg, &off, NULL), ST_INV_PARAM);
    off.QuadPart = 0;
    EXPECT_ST(UN(NtWriteFileGather)(BOGUS, NULL, NULL, NULL, &io, seg, (ULONG)pg, &off, NULL), ST_INV_HANDLE);
    CloseHandle(ov.hEvent); CloseHandle(ev); VirtualFree(rb, 0, MEM_RELEASE); VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(f);
    /* a handle without FILE_FLAG_NO_BUFFERING|OVERLAPPED does not qualify */
    HANDLE g = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (g != INVALID_HANDLE_VALUE) {
        BYTE *b2 = VirtualAlloc(NULL, pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        memset(seg, 0, sizeof seg); seg[0].Buffer = b2;
        EXPECT_ST(UN(NtWriteFileGather)(g, NULL, NULL, NULL, &io, seg, (ULONG)pg, &off, NULL), ST_INV_PARAM);
        VirtualFree(b2, 0, MEM_RELEASE);
        CloseHandle(g);
    }
    DeleteFileA(path);
}

/* ---- debug objects, profile, system debug control ---------------------- */
TEST(debug_object_wait_remove)
{
    REQUIRE(UN(NtCreateDebugObject)); REQUIRE(UN(NtWaitForDebugEvent)); REQUIRE(UN(NtRemoveProcessDebug));
    HANDLE dbg = NULL;
    EXPECT_ST(UN(NtCreateDebugObject)(&dbg, 0x1F000F, NULL, 0), 0);
    REQUIRE(dbg);
    BYTE state[512]; memset(state, 0xcc, sizeof state);
    LARGE_INTEGER zero = {0}, to = REL(30);
    EXPECT_ST(UN(NtWaitForDebugEvent)(dbg, FALSE, &zero, state), ST_TIMEOUT);
    EXPECT_ST(UN(NtWaitForDebugEvent)(dbg, FALSE, &to, state), ST_TIMEOUT);
    EXPECT_ST(UN(NtWaitForDebugEvent)(dbg, TRUE, &to, state), ST_TIMEOUT);
    EXPECT_ST(UN(NtWaitForDebugEvent)(BOGUS, FALSE, &zero, state), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtWaitForDebugEvent)(ev, FALSE, &zero, state), ST_TYPE_MISM);
    EXPECT_ST(UN(NtRemoveProcessDebug)(NT_CUR_PROC, ev), ST_TYPE_MISM);
    CloseHandle(ev);
    /* process is not attached to this object */
    EXPECT_ST(UN(NtRemoveProcessDebug)(NT_CUR_PROC, dbg), S(0xC0000353));   /* STATUS_PORT_NOT_SET */
    EXPECT_ST(UN(NtRemoveProcessDebug)(BOGUS, dbg), ST_INV_HANDLE);
    EXPECT_ST(UN(NtRemoveProcessDebug)(NT_CUR_PROC, BOGUS), ST_INV_HANDLE);
    UN(NtClose)(dbg);
}

TEST(profile_invalid_handles)
{
    REQUIRE(UN(NtStartProfile)); REQUIRE(UN(NtStopProfile));
    EXPECT_ST(UN(NtStartProfile)(BOGUS), ST_INV_HANDLE);
    EXPECT_ST(UN(NtStopProfile)(BOGUS), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtStartProfile)(ev), ST_TYPE_MISM);
    EXPECT_ST(UN(NtStopProfile)(ev), ST_TYPE_MISM);
    CloseHandle(ev);
}

TEST(system_debug_control_bad_command)
{
    REQUIRE(UN(NtSystemDebugControl));
    ULONG ret = 0xcccc; BYTE out[16];
    NTSTATUS st = UN(NtSystemDebugControl)(0x7fffffff, NULL, 0, out, sizeof out, &ret);
    t_note("NtSystemDebugControl(bogus) -> 0x%lx", (unsigned long)st);
    CHECK(st < 0);   /* never succeeds for an undefined command */
}
