/* Thread pool timers, waits, I/O completions, job notifications and ALPC completions (Tp* exports).
 * TpSetTimerEx, TpTimerOutstandingCallbackCount, TpSetWaitEx, TpAllocIoCompletion, TpStartAsyncIoOperation,
 * TpCancelAsyncIoOperation, TpWaitForIoCompletion, TpReleaseIoCompletion, TpAllocJobNotification,
 * TpWaitForJobNotification, TpReleaseJobNotification, TpAllocAlpcCompletion(Ex), TpWaitForAlpcCompletion,
 * TpReleaseAlpcCompletion, TpAlpcRegisterCompletionList, TpAlpcUnregisterCompletionList.
 * TppRaiseInvalidParameter raises a continuable STATUS_INVALID_PARAMETER exception that a vectored
 * handler records and continues. See EVIDENCE.md. */
#include "t.h"

typedef VOID (NTAPI *WORKCB)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);
typedef VOID (NTAPI *TIMERCB)(PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER);
typedef VOID (NTAPI *WAITCB)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT);
typedef VOID (NTAPI *IOCB)(PTP_CALLBACK_INSTANCE, PVOID, PVOID, PIO_STATUS_BLOCK, PTP_IO);
typedef VOID (NTAPI *JOBCB)(PTP_CALLBACK_INSTANCE, PVOID, PVOID);
typedef VOID (NTAPI *ALPCCB)(PTP_CALLBACK_INSTANCE, PVOID, PVOID);
UDECL(NTSTATUS, TpAllocPool, (PTP_POOL *, PVOID));
UDECL(VOID, TpReleasePool, (PTP_POOL));
UDECL(NTSTATUS, TpAllocTimer, (PTP_TIMER *, TIMERCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpReleaseTimer, (PTP_TIMER));
UDECL(VOID, TpWaitForTimer, (PTP_TIMER, BOOLEAN));
UDECL(ULONG, TpSetTimerEx, (PTP_TIMER, PLARGE_INTEGER, ULONG, ULONG));
UDECL(ULONG, TpTimerOutstandingCallbackCount, (PTP_TIMER));
UDECL(NTSTATUS, TpAllocWait, (PTP_WAIT *, WAITCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpReleaseWait, (PTP_WAIT));
UDECL(VOID, TpWaitForWait, (PTP_WAIT, BOOLEAN));
UDECL(ULONG, TpSetWaitEx, (PTP_WAIT, HANDLE, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, TpAllocIoCompletion, (PTP_IO *, HANDLE, IOCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpReleaseIoCompletion, (PTP_IO));
UDECL(VOID, TpWaitForIoCompletion, (PTP_IO, BOOLEAN));
UDECL(VOID, TpStartAsyncIoOperation, (PTP_IO));
UDECL(VOID, TpCancelAsyncIoOperation, (PTP_IO));
UDECL(NTSTATUS, TpAllocJobNotification, (PVOID *, HANDLE, JOBCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpReleaseJobNotification, (PVOID));
UDECL(VOID, TpWaitForJobNotification, (PVOID));
UDECL(NTSTATUS, TpAllocAlpcCompletion, (PVOID *, HANDLE, ALPCCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(NTSTATUS, TpAllocAlpcCompletionEx, (PVOID *, HANDLE, ALPCCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpReleaseAlpcCompletion, (PVOID));
UDECL(VOID, TpWaitForAlpcCompletion, (PVOID));
UDECL(VOID, TpAlpcRegisterCompletionList, (PVOID));
UDECL(VOID, TpAlpcUnregisterCompletionList, (PVOID));
UDECL(NTSTATUS, NtAlpcCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_PARAM S(0xC000000D)

static volatile LONG g_exc;
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xC000000D) { InterlockedIncrement(&g_exc); return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static PVOID g_veh;
static void veh_on(void) { g_exc = 0; if (!g_veh) g_veh = AddVectoredExceptionHandler(1, veh); }
static void veh_off(void) { if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; } }
static LONG exc_take(void) { return InterlockedExchange(&g_exc, 0); }

static void env_init(TP_CALLBACK_ENVIRON *e, PTP_POOL pool)
{
    memset(e, 0, sizeof *e); e->Version = 3; e->Pool = pool; e->Size = sizeof *e;
}
static BOOL wait_until(volatile LONG *v, LONG want, DWORD ms)
{
    DWORD t0 = GetTickCount();
    while (*v < want && GetTickCount() - t0 < ms) Sleep(5);
    return *v >= want;
}

/* ---------------- timers ---------------- */
static volatile LONG g_tm;
static PTP_TIMER g_tm_obj;
static volatile LONG g_tm_outstanding_in_cb;
static ULONG (*dummy_ptr)(void);
static VOID NTAPI timer_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PTP_TIMER t)
{
    if (ctx == (PVOID)0x7777 && t == g_tm_obj) {
        g_tm_outstanding_in_cb = UN(TpTimerOutstandingCallbackCount)(t);
        InterlockedIncrement(&g_tm);
    }
}

TEST(timer_set_ex)
{
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpAllocTimer)); REQUIRE(UN(TpSetTimerEx)); REQUIRE(UN(TpTimerOutstandingCallbackCount));
    REQUIRE(UN(TpReleaseTimer)); REQUIRE(UN(TpWaitForTimer)); REQUIRE(UN(TpReleasePool));
    PTP_POOL pool = NULL; PTP_TIMER t = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    EXPECT_EQ(UN(TpAllocTimer)(&t, timer_cb, (PVOID)0x7777, &env), 0);
    if (!pool || !t) return;
    g_tm_obj = t; g_tm = 0;
    EXPECT_EQ(UN(TpTimerOutstandingCallbackCount)(t), 0);
    LARGE_INTEGER due; due.QuadPart = -300000;    /* 30 ms */
    EXPECT_EQ(UN(TpSetTimerEx)(t, &due, 0, 0), 0);
    CHECK(wait_until(&g_tm, 1, 3000));
    Sleep(100);
    EXPECT_EQ(g_tm, 1);          /* one-shot */
    EXPECT_EQ(g_tm_outstanding_in_cb, 1);   /* the running callback counts */
    EXPECT_EQ(UN(TpTimerOutstandingCallbackCount)(t), 0);
    /* re-arm far in the future, then replace it: set returns whether a pending timer was replaced */
    due.QuadPart = -600000000LL;
    EXPECT_EQ(UN(TpSetTimerEx)(t, &due, 0, 0), 0);
    EXPECT_EQ(UN(TpSetTimerEx)(t, &due, 0, 0), 1);
    /* cancel (NULL due time) returns TRUE when the timer was set, FALSE when not */
    EXPECT_EQ(UN(TpSetTimerEx)(t, NULL, 0, 0), 1);
    EXPECT_EQ(UN(TpSetTimerEx)(t, NULL, 0, 0), 0);
    Sleep(50);
    EXPECT_EQ(g_tm, 1);
    /* periodic */
    g_tm = 0;
    due.QuadPart = -100000; /* 10 ms */
    EXPECT_EQ(UN(TpSetTimerEx)(t, &due, 20, 0), 0);
    CHECK(wait_until(&g_tm, 4, 3000));
    EXPECT_EQ(UN(TpSetTimerEx)(t, NULL, 0, 0), 1);
    UN(TpWaitForTimer)(t, FALSE);
    LONG after = g_tm;
    Sleep(100);
    EXPECT_EQ(g_tm, after);      /* no callbacks once cancelled and drained */
    EXPECT_EQ(UN(TpTimerOutstandingCallbackCount)(t), 0);
    /* absolute due time in the past fires immediately */
    g_tm = 0;
    due.QuadPart = 1;   /* absolute 1601: already past */
    EXPECT_EQ(UN(TpSetTimerEx)(t, &due, 0, 0), 0);
    CHECK(wait_until(&g_tm, 1, 3000));
    UN(TpWaitForTimer)(t, TRUE);
    UN(TpReleaseTimer)(t);
    UN(TpReleasePool)(pool);
}

TEST(timer_invalid)
{
    REQUIRE(UN(TpSetTimerEx)); REQUIRE(UN(TpTimerOutstandingCallbackCount));
    veh_on();
    LARGE_INTEGER due; due.QuadPart = -10000;
    NTSTATUS r;
    r = UN(TpSetTimerEx)(NULL, &due, 0, 0);
    t_note("TpSetTimerEx(NULL) -> %lu, exceptions=%ld", (unsigned long)r, exc_take());
    EXPECT_EQ(r, 0);
    g_exc = 0;
    r = UN(TpTimerOutstandingCallbackCount)(NULL);
    t_note("TpTimerOutstandingCallbackCount(NULL) -> %lu, exceptions=%ld", (unsigned long)r, exc_take());
    EXPECT_EQ(r, 0);
    veh_off();
}

/* ---------------- waits ---------------- */
static volatile LONG g_wt;
static volatile TP_WAIT_RESULT g_wt_res[8];
static VOID NTAPI wait_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PTP_WAIT w, TP_WAIT_RESULT r)
{
    LONG k = g_wt;
    if (k < 8) g_wt_res[k] = r;
    InterlockedIncrement(&g_wt);
}

TEST(wait_set_ex)
{
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpAllocWait)); REQUIRE(UN(TpSetWaitEx)); REQUIRE(UN(TpReleaseWait));
    REQUIRE(UN(TpWaitForWait)); REQUIRE(UN(TpReleasePool));
    PTP_POOL pool = NULL; PTP_WAIT w = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    EXPECT_EQ(UN(TpAllocWait)(&w, wait_cb, NULL, &env), 0);
    if (!pool || !w) return;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_wt = 0;
    /* signalled before the timeout */
    LARGE_INTEGER to; to.QuadPart = -100000000LL;  /* 10 s */
    EXPECT_EQ(UN(TpSetWaitEx)(w, ev, &to, NULL), 0);
    SetEvent(ev);
    CHECK(wait_until(&g_wt, 1, 3000));
    EXPECT_EQ(g_wt_res[0], WAIT_OBJECT_0);
    UN(TpWaitForWait)(w, FALSE);
    /* timeout */
    ResetEvent(ev);
    to.QuadPart = -300000;
    EXPECT_EQ(UN(TpSetWaitEx)(w, ev, &to, NULL), 0);
    CHECK(wait_until(&g_wt, 2, 3000));
    EXPECT_EQ(g_wt_res[1], WAIT_TIMEOUT);
    UN(TpWaitForWait)(w, FALSE);
    /* cancel: a pending wait is reported as cancelled-by-this-call (TRUE), nothing pending is FALSE */
    to.QuadPart = -600000000LL;
    EXPECT_EQ(UN(TpSetWaitEx)(w, ev, &to, NULL), 0);
    EXPECT_EQ(UN(TpSetWaitEx)(w, NULL, NULL, NULL), 1);
    EXPECT_EQ(UN(TpSetWaitEx)(w, NULL, NULL, NULL), 0);
    Sleep(50);
    EXPECT_EQ(g_wt, 2);
    /* NULL timeout waits indefinitely: only a signal completes it */
    EXPECT_EQ(UN(TpSetWaitEx)(w, ev, NULL, NULL), 0);
    Sleep(100);
    EXPECT_EQ(g_wt, 2);
    SetEvent(ev);
    CHECK(wait_until(&g_wt, 3, 3000));
    EXPECT_EQ(g_wt_res[2], WAIT_OBJECT_0);
    UN(TpWaitForWait)(w, FALSE);
    /* the reserved parameter must be NULL */
    veh_on();
    ResetEvent(ev);
    NTSTATUS r = UN(TpSetWaitEx)(w, ev, NULL, (PVOID)1);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(r, 0);
    veh_off();
    EXPECT_EQ(g_wt, 3);
    CloseHandle(ev);
    UN(TpWaitForWait)(w, TRUE);
    UN(TpReleaseWait)(w);
    UN(TpReleasePool)(pool);
}

/* ---------------- I/O completion ---------------- */
static volatile LONG g_io;
/* The native callback receives (Instance, Context, ApcContext = the OVERLAPPED, IoStatusBlock, Io). */
static struct { PVOID ctx, ov; NTSTATUS res; ULONG_PTR bytes; PTP_IO io; PVOID iosb; } g_io_rec[4];
static VOID NTAPI io_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PVOID ov, PIO_STATUS_BLOCK iosb, PTP_IO io)
{
    LONG k = g_io;
    if (k < 4) { g_io_rec[k].ctx = ctx; g_io_rec[k].ov = ov; g_io_rec[k].res = iosb->Status; g_io_rec[k].bytes = iosb->Information; g_io_rec[k].io = io; g_io_rec[k].iosb = iosb; }
    InterlockedIncrement(&g_io);
}

TEST(io_completion)
{
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpAllocIoCompletion)); REQUIRE(UN(TpStartAsyncIoOperation));
    REQUIRE(UN(TpCancelAsyncIoOperation)); REQUIRE(UN(TpWaitForIoCompletion)); REQUIRE(UN(TpReleaseIoCompletion)); REQUIRE(UN(TpReleasePool));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "tpio.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    if (f == INVALID_HANDLE_VALUE) return;
    PTP_POOL pool = NULL; PTP_IO io = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    NTSTATUS st = UN(TpAllocIoCompletion)(&io, f, io_cb, (PVOID)0x4242, &env);
    EXPECT_EQ(st, 0);
    CHECK(io != NULL);
    if (st || !io) { CloseHandle(f); return; }
    g_io = 0;
    /* real I/O: start, issue, callback reports result */
    char data[16] = "tp-io-completion";
    OVERLAPPED ov; memset(&ov, 0, sizeof ov);
    UN(TpStartAsyncIoOperation)(io);
    BOOL ok = WriteFile(f, data, 16, NULL, &ov);
    DWORD err = ok ? 0 : GetLastError();
    if (!ok && err != ERROR_IO_PENDING) { UN(TpCancelAsyncIoOperation)(io); t_note("WriteFile failed %lu", err); }
    else {
        CHECK(wait_until(&g_io, 1, 3000));
        EXPECT_EQ(g_io_rec[0].ctx, 0x4242);
        CHECK(g_io_rec[0].ov == &ov);
        EXPECT_EQ(g_io_rec[0].res, 0);
        EXPECT_EQ(g_io_rec[0].bytes, 16);
        CHECK(g_io_rec[0].io == io);
    }
    UN(TpWaitForIoCompletion)(io, FALSE);
    EXPECT_EQ(g_io, 1);
    /* read it back through a second operation on the same object */
    char back[16] = {0};
    OVERLAPPED ov2; memset(&ov2, 0, sizeof ov2);
    UN(TpStartAsyncIoOperation)(io);
    ok = ReadFile(f, back, 16, NULL, &ov2);
    err = ok ? 0 : GetLastError();
    if (!ok && err != ERROR_IO_PENDING) UN(TpCancelAsyncIoOperation)(io);
    else {
        CHECK(wait_until(&g_io, 2, 3000));
        EXPECT_EQ(g_io_rec[1].res, 0);
        EXPECT_EQ(g_io_rec[1].bytes, 16);
        CHECK(g_io_rec[1].ov == &ov2);
    }
    UN(TpWaitForIoCompletion)(io, FALSE);
    CHECK(memcmp(back, data, 16) == 0);
    /* read at EOF reports the error through the callback result */
    OVERLAPPED ov3; memset(&ov3, 0, sizeof ov3); ov3.Offset = 16;
    UN(TpStartAsyncIoOperation)(io);
    ok = ReadFile(f, back, 16, NULL, &ov3);
    err = ok ? 0 : GetLastError();
    if (!ok && err != ERROR_IO_PENDING) { t_note("EOF read failed synchronously %lu", err); UN(TpCancelAsyncIoOperation)(io); }
    else {
        CHECK(wait_until(&g_io, 3, 3000));
        EXPECT_EQ(g_io_rec[2].res, S(0xC0000011));   /* STATUS_END_OF_FILE */
        EXPECT_EQ(g_io_rec[2].bytes, 0);
    }
    UN(TpWaitForIoCompletion)(io, FALSE);
    /* started but never issued: cancel undoes the start, the wait does not block, no callback */
    LONG before = g_io;
    UN(TpStartAsyncIoOperation)(io);
    UN(TpCancelAsyncIoOperation)(io);
    UN(TpWaitForIoCompletion)(io, TRUE);
    Sleep(50);
    EXPECT_EQ(g_io, before);
    UN(TpWaitForIoCompletion)(io, FALSE);
    UN(TpReleaseIoCompletion)(io);
    UN(TpReleasePool)(pool);
    CloseHandle(f);
    DeleteFileA(path);
}

TEST(io_completion_invalid)
{
    REQUIRE(UN(TpAllocIoCompletion)); REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpReleasePool));
    PTP_POOL pool = NULL; PTP_IO io = (PTP_IO)(ULONG_PTR)0x99;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "tpio2.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    veh_on();
    EXPECT_EQ(UN(TpAllocIoCompletion)(NULL, f, io_cb, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpAllocIoCompletion)(&io, NULL, io_cb, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpAllocIoCompletion)(&io, f, NULL, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    /* a handle that is not a file */
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    io = NULL;
    NTSTATUS st = UN(TpAllocIoCompletion)(&io, ev, io_cb, NULL, &env);
    t_note("TpAllocIoCompletion(event handle) -> 0x%lx", (unsigned long)st);
    EXPECT_NE(st, 0);
    exc_take();
    CloseHandle(ev);
    veh_off();
    if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); DeleteFileA(path); }
    UN(TpReleasePool)(pool);
}

/* ---------------- job notifications ---------------- */
static volatile LONG g_job;
static ULONG_PTR g_job_arg[8][2];
static VOID NTAPI job_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PVOID msg)
{
    LONG k = g_job;
    if (k < 8) { g_job_arg[k][0] = (ULONG_PTR)ctx; g_job_arg[k][1] = (ULONG_PTR)msg; }
    InterlockedIncrement(&g_job);
}

TEST(job_notification)
{
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpAllocJobNotification)); REQUIRE(UN(TpReleaseJobNotification));
    REQUIRE(UN(TpWaitForJobNotification)); REQUIRE(UN(TpReleasePool));
    PTP_POOL pool = NULL; PVOID jn = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    HANDLE job = CreateJobObjectW(NULL, NULL);
    CHECK(job != NULL);
    veh_on();
    EXPECT_EQ(UN(TpAllocJobNotification)(NULL, job, job_cb, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpAllocJobNotification)(&jn, NULL, job_cb, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpAllocJobNotification)(&jn, job, NULL, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    veh_off();
    NTSTATUS st = UN(TpAllocJobNotification)(&jn, job, job_cb, (PVOID)0x5150, &env);
    EXPECT_EQ(st, 0);
    CHECK(jn != NULL);
    if (st || !jn) { CloseHandle(job); UN(TpReleasePool)(pool); return; }
    g_job = 0;
    /* a child assigned to the job produces new-process / exit-process notifications */
    WCHAR sysdir[MAX_PATH], cmd[2 * MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    wsprintfW(cmd, L"\"%s\\cmd.exe\" /c exit 0", sysdir);
    STARTUPINFOW si; PROCESS_INFORMATION pi; memset(&si, 0, sizeof si); si.cb = sizeof si;
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi);
    if (!ok) ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) { t_note("cannot start child: %lu", GetLastError()); }
    else {
        if (!AssignProcessToJobObject(job, pi.hProcess)) {
            t_note("cannot assign child to job: %lu", GetLastError());
            TerminateProcess(pi.hProcess, 0);
        } else {
            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hProcess, 10000);
            CHECK(wait_until(&g_job, 2, 5000));
            t_note("job callbacks: %ld", g_job);
            for (LONG k = 0; k < g_job && k < 8; k++) EXPECT_EQ(g_job_arg[k][0], 0x5150);
        }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    UN(TpWaitForJobNotification)(jn);
    LONG n = g_job;
    t_note("job callbacks total %ld", n);
    UN(TpReleaseJobNotification)(jn);
    CloseHandle(job);
    UN(TpReleasePool)(pool);
}

/* ---------------- ALPC completions ---------------- */
static volatile LONG g_alpc;
static VOID NTAPI alpc_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PVOID msg) { InterlockedIncrement(&g_alpc); }

TEST(alpc_completion)
{
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpAllocAlpcCompletion)); REQUIRE(UN(TpReleaseAlpcCompletion)); REQUIRE(UN(TpWaitForAlpcCompletion));
    REQUIRE(UN(NtAlpcCreatePort)); REQUIRE(UN(NtClose)); REQUIRE(UN(TpReleasePool));
    PTP_POOL pool = NULL; PVOID ac = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool);
    HANDLE port = NULL;
    EXPECT_EQ(UN(NtAlpcCreatePort)(&port, NULL, NULL), 0);
    if (!pool || !port) return;
    veh_on();
    EXPECT_EQ(UN(TpAllocAlpcCompletion)(NULL, port, alpc_cb, NULL, &env), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    NTSTATUS st = UN(TpAllocAlpcCompletion)(&ac, port, NULL, NULL, &env);
    EXPECT_EQ(st, ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    st = UN(TpAllocAlpcCompletion)(&ac, NULL, alpc_cb, NULL, &env);
    EXPECT_EQ(st, ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    ac = NULL;
    st = UN(TpAllocAlpcCompletion)(&ac, ev, alpc_cb, NULL, &env);
    EXPECT_EQ(st, S(0xC0000024));
    EXPECT_EQ(exc_take(), 0);
    CloseHandle(ev);
    veh_off();
    ac = NULL;
    EXPECT_EQ(exc_take(), 0);
    st = UN(TpAllocAlpcCompletion)(&ac, port, alpc_cb, (PVOID)0x77, &env);
    EXPECT_EQ(st, 0);
    CHECK(ac != NULL);
    if (st == 0 && ac) {
        UN(TpWaitForAlpcCompletion)(ac);   /* nothing outstanding: returns */
        if (UN(TpAlpcRegisterCompletionList) && UN(TpAlpcUnregisterCompletionList)) {
            veh_on();
            UN(TpAlpcRegisterCompletionList)(ac);
            EXPECT_EQ(exc_take(), 1);   /* the object was not allocated for a completion list */
            UN(TpAlpcUnregisterCompletionList)(ac);
            EXPECT_EQ(exc_take(), 1);
            veh_off();
        }
        UN(TpReleaseAlpcCompletion)(ac);
    }
    if (UN(TpAllocAlpcCompletionEx)) {
        ac = NULL;
        /* a port accepts one completion association: allocating again on it fails, a new port works */
        st = UN(TpAllocAlpcCompletionEx)(&ac, port, alpc_cb, (PVOID)0x78, &env);
        t_note("TpAllocAlpcCompletionEx on a used port -> 0x%lx", (unsigned long)st);
        if (st == 0 && ac) UN(TpReleaseAlpcCompletion)(ac);
        UN(NtClose)(port); port = NULL;
        EXPECT_EQ(UN(NtAlpcCreatePort)(&port, NULL, NULL), 0);
        ac = NULL;
        st = UN(TpAllocAlpcCompletionEx)(&ac, port, alpc_cb, (PVOID)0x78, &env);
        EXPECT_EQ(st, 0);
        if (st == 0 && ac) {
            UN(TpWaitForAlpcCompletion)(ac);
            UN(TpReleaseAlpcCompletion)(ac);
        }
    }
    EXPECT_EQ(g_alpc, 0);
    if (port) UN(NtClose)(port);
    UN(TpReleasePool)(pool);
}
