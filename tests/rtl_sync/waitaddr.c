/* Wait-on-address, lock contention, timer queues, registered waits and work items. */
#include "t.h"

UDECL(NTSTATUS, RtlWaitOnAddress, (volatile VOID *, PVOID, SIZE_T, PLARGE_INTEGER));
UDECL(VOID, RtlWakeAddressAll, (PVOID));
UDECL(VOID, RtlWakeAddressSingle, (PVOID));
UDECL(VOID, RtlInitializeSRWLock, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockShared, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(NTSTATUS, RtlInitializeCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlEnterCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlLeaveCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlDeleteCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlCreateTimer, (HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, DWORD, DWORD, ULONG));
UDECL(NTSTATUS, RtlUpdateTimer, (HANDLE, HANDLE, DWORD, DWORD));
UDECL(NTSTATUS, RtlDeleteTimer, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlRegisterWait, (PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeregisterWait, (HANDLE));
UDECL(NTSTATUS, RtlDeregisterWaitEx, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlQueueWorkItem, (WORKERCALLBACKFUNC, PVOID, ULONG));

#define S(x) ((NTSTATUS)(x))
#define TIMEOUT S(0x102)
#define BAD_PARAM S(0xc000000d)
#define WT_ONLY_ONCE 0x8
#define WT_IN_WAIT_THREAD 0x4

static LARGE_INTEGER rel_ms(LONG ms) { LARGE_INTEGER t; t.QuadPart = -(LONGLONG)ms * 10000; return t; }

/* ---------------- RtlWaitOnAddress ---------------- */
static void wait_differs(SIZE_T size)
{
    ULONGLONG value = 0x0102030405060708ull, other = 0x1111111111111111ull;
    LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(RtlWaitOnAddress));
    /* The wait returns at once when the current contents differ from the comparand. */
    DWORD t0 = GetTickCount();
    EXPECT_EQ(UN(RtlWaitOnAddress)(&value, &other, size, &t), 0);
    CHECK(GetTickCount() - t0 < 2000);
}
TEST(rtl_sync_waitaddr_differs_size1) { wait_differs(1); }
TEST(rtl_sync_waitaddr_differs_size2) { wait_differs(2); }
TEST(rtl_sync_waitaddr_differs_size4) { wait_differs(4); }
TEST(rtl_sync_waitaddr_differs_size8) { wait_differs(8); }

static void wait_equal_times_out(SIZE_T size, LONG ms)
{
    ULONGLONG value = 0x0102030405060708ull, same = value;
    LARGE_INTEGER t = rel_ms(ms);
    DWORD t0, t1;
    REQUIRE(UN(RtlWaitOnAddress));
    t0 = GetTickCount();
    EXPECT_EQ(UN(RtlWaitOnAddress)(&value, &same, size, &t), TIMEOUT);
    t1 = GetTickCount();
    if (ms) CHECK(t1 - t0 >= (DWORD)(ms * 3 / 4));
    CHECK(t1 - t0 < 5000);
}
TEST(rtl_sync_waitaddr_equal_timeout_size1) { wait_equal_times_out(1, 40); }
TEST(rtl_sync_waitaddr_equal_timeout_size2) { wait_equal_times_out(2, 40); }
TEST(rtl_sync_waitaddr_equal_timeout_size4) { wait_equal_times_out(4, 40); }
TEST(rtl_sync_waitaddr_equal_timeout_size8) { wait_equal_times_out(8, 40); }
TEST(rtl_sync_waitaddr_equal_zero_timeout) { wait_equal_times_out(4, 0); }

TEST(rtl_sync_waitaddr_compares_only_size_bytes)
{
    BYTE value[8] = {1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd}, probe[8] = {1, 2, 3, 4, 0, 0, 0, 0};
    LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(RtlWaitOnAddress));
    EXPECT_EQ(UN(RtlWaitOnAddress)(value, probe, 4, &t), TIMEOUT); /* trailing bytes are not compared */
}
TEST(rtl_sync_waitaddr_invalid_size)
{
    ULONGLONG value = 0, same = 0;
    LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(RtlWaitOnAddress));
    EXPECT_EQ(UN(RtlWaitOnAddress)(&value, &same, 0, &t), BAD_PARAM);
    EXPECT_EQ(UN(RtlWaitOnAddress)(&value, &same, 3, &t), BAD_PARAM);
    EXPECT_EQ(UN(RtlWaitOnAddress)(&value, &same, 16, &t), BAD_PARAM);
}

typedef struct { volatile LONG word; volatile LONG woke; volatile NTSTATUS status; volatile LONG ready; } wa_t;
static DWORD WINAPI wa_waiter(PVOID p)
{
    wa_t *w = p; LONG undesired = 0; LARGE_INTEGER t = rel_ms(10000);
    InterlockedIncrement(&w->ready);
    w->status = UN(RtlWaitOnAddress)(&w->word, &undesired, sizeof(LONG), &t);
    InterlockedIncrement(&w->woke);
    return 0;
}
static void wait_wake(int all)
{
    wa_t w = {0}; HANDLE th[2]; int n = all ? 2 : 1;
    REQUIRE(UN(RtlWaitOnAddress)); REQUIRE(UN(RtlWakeAddressAll)); REQUIRE(UN(RtlWakeAddressSingle));
    for (int i = 0; i < n; i++) th[i] = CreateThread(NULL, 0, wa_waiter, &w, 0, NULL);
    for (int i = 0; i < 500 && w.ready < n; i++) Sleep(10);
    Sleep(100);
    CHECK(w.woke == 0);
    InterlockedExchange(&w.word, 1);
    if (all) UN(RtlWakeAddressAll)((PVOID)&w.word); else UN(RtlWakeAddressSingle)((PVOID)&w.word);
    WaitForMultipleObjects(n, th, TRUE, 10000);
    EXPECT_EQ(w.woke, n);
    EXPECT_EQ(w.status, 0);
    for (int i = 0; i < n; i++) CloseHandle(th[i]);
}
TEST(rtl_sync_waitaddr_wake_single) { wait_wake(0); }
TEST(rtl_sync_waitaddr_wake_all) { wait_wake(1); }

TEST(rtl_sync_waitaddr_wake_without_waiters)
{
    LONG word = 0;
    REQUIRE(UN(RtlWakeAddressAll)); REQUIRE(UN(RtlWakeAddressSingle));
    UN(RtlWakeAddressSingle)(&word);
    UN(RtlWakeAddressAll)(&word);
    UN(RtlWakeAddressAll)(NULL);
    CHECK(1);
}
TEST(rtl_sync_waitaddr_wake_other_address_does_not_release)
{
    wa_t w = {0}; LONG decoy = 0; HANDLE th;
    REQUIRE(UN(RtlWaitOnAddress)); REQUIRE(UN(RtlWakeAddressAll));
    th = CreateThread(NULL, 0, wa_waiter, &w, 0, NULL);
    for (int i = 0; i < 500 && !w.ready; i++) Sleep(10);
    Sleep(100);
    UN(RtlWakeAddressAll)(&decoy);
    Sleep(100);
    EXPECT_EQ(w.woke, 0);
    InterlockedExchange(&w.word, 1);
    UN(RtlWakeAddressAll)((PVOID)&w.word);
    WaitForSingleObject(th, 10000);
    EXPECT_EQ(w.woke, 1);
    CloseHandle(th);
}

/* ---------------- lock contention ---------------- */
#define NTHREADS 4
#define ITERS 20000
typedef struct { RTL_CRITICAL_SECTION cs; RTL_SRWLOCK srw; volatile LONG64 counter; int mode; } lock_t;
static DWORD WINAPI hammer(PVOID p)
{
    lock_t *l = p;
    for (int i = 0; i < ITERS; i++) {
        if (l->mode == 0) { UN(RtlEnterCriticalSection)(&l->cs); l->counter++; UN(RtlLeaveCriticalSection)(&l->cs); }
        else { UN(RtlAcquireSRWLockExclusive)(&l->srw); l->counter++; UN(RtlReleaseSRWLockExclusive)(&l->srw); }
    }
    return 0;
}
static void contention(int mode)
{
    static lock_t l; HANDLE th[NTHREADS];
    REQUIRE(UN(RtlInitializeCriticalSection)); REQUIRE(UN(RtlEnterCriticalSection)); REQUIRE(UN(RtlLeaveCriticalSection));
    REQUIRE(UN(RtlDeleteCriticalSection)); REQUIRE(UN(RtlInitializeSRWLock)); REQUIRE(UN(RtlAcquireSRWLockExclusive));
    REQUIRE(UN(RtlReleaseSRWLockExclusive));
    memset(&l, 0, sizeof l);
    l.mode = mode;
    EXPECT_EQ(UN(RtlInitializeCriticalSection)(&l.cs), 0);
    UN(RtlInitializeSRWLock)(&l.srw);
    for (int i = 0; i < NTHREADS; i++) th[i] = CreateThread(NULL, 0, hammer, &l, 0, NULL);
    EXPECT_EQ(WaitForMultipleObjects(NTHREADS, th, TRUE, 60000), WAIT_OBJECT_0);
    for (int i = 0; i < NTHREADS; i++) CloseHandle(th[i]);
    EXPECT_EQ((ULONG_PTR)l.counter, (ULONG_PTR)NTHREADS * ITERS);
    UN(RtlDeleteCriticalSection)(&l.cs);
}
TEST(rtl_sync_contention_critical_section) { contention(0); }
TEST(rtl_sync_contention_srw_exclusive) { contention(1); }

TEST(rtl_sync_srw_same_thread_try_matrix)
{
    RTL_SRWLOCK l;
    REQUIRE(UN(RtlInitializeSRWLock)); REQUIRE(UN(RtlTryAcquireSRWLockExclusive)); REQUIRE(UN(RtlTryAcquireSRWLockShared));
    REQUIRE(UN(RtlReleaseSRWLockExclusive)); REQUIRE(UN(RtlReleaseSRWLockShared));
    UN(RtlInitializeSRWLock)(&l);
    /* exclusive held: neither mode can be taken */
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), 1);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), 0);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l), 0);
    UN(RtlReleaseSRWLockExclusive)(&l);
    /* shared held: more readers may enter, a writer may not */
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l), 1);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l), 1);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), 0);
    UN(RtlReleaseSRWLockShared)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), 0); /* one reader still holds it */
    UN(RtlReleaseSRWLockShared)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), 1);
    UN(RtlReleaseSRWLockExclusive)(&l);
    EXPECT_EQ((ULONG_PTR)l.Ptr, 0); /* fully released lock returns to the initial state */
}

/* ---------------- timer queues ---------------- */
static volatile LONG timer_hits, timer_fired_flag_bad;
static void NTAPI timer_cb(PVOID ctx, BOOLEAN fired)
{
    if (!fired) InterlockedIncrement(&timer_fired_flag_bad); /* timers always report TimerOrWaitFired == TRUE */
    InterlockedIncrement(&timer_hits);
    if (ctx) SetEvent((HANDLE)ctx);
}
static int wait_hits(LONG n, int ms) { for (int i = 0; i < ms / 5 && timer_hits < n; i++) Sleep(5); return timer_hits >= n; }
#define TIMER_EXPORTS \
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimer)); \
    REQUIRE(UN(RtlDeleteTimerQueueEx)); REQUIRE(UN(RtlUpdateTimer))

TEST(rtl_sync_timer_queue_one_shot_fires_once)
{
    HANDLE q = NULL, t = NULL; INT_PTR dummy;
    TIMER_EXPORTS;
    timer_hits = timer_fired_flag_bad = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    CHECK(q != NULL);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, NULL, 20, 0, 0), 0);
    CHECK(t != NULL);
    CHECK(wait_hits(1, 5000));
    Sleep(150);
    EXPECT_EQ(timer_hits, 1);
    EXPECT_EQ(timer_fired_flag_bad, 0);
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    (void)dummy;
}
TEST(rtl_sync_timer_queue_periodic_stops_after_delete)
{
    HANDLE q = NULL, t = NULL; LONG after;
    TIMER_EXPORTS;
    timer_hits = timer_fired_flag_bad = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, NULL, 10, 15, 0), 0);
    CHECK(wait_hits(4, 8000));
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0); /* blocks until running callbacks finish */
    after = timer_hits;
    Sleep(150);
    EXPECT_EQ(timer_hits, after);
    EXPECT_EQ(timer_fired_flag_bad, 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
}
TEST(rtl_sync_timer_queue_update_reschedules)
{
    HANDLE q = NULL, t = NULL;
    TIMER_EXPORTS;
    timer_hits = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, NULL, 600000, 0, 0), 0);
    Sleep(100);
    EXPECT_EQ(timer_hits, 0);
    EXPECT_EQ(UN(RtlUpdateTimer)(q, t, 10, 0), 0);
    CHECK(wait_hits(1, 5000));
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
}
TEST(rtl_sync_timer_queue_delete_before_due_never_fires)
{
    HANDLE q = NULL, t = NULL;
    TIMER_EXPORTS;
    timer_hits = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, NULL, 600000, 0, 0), 0);
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(timer_hits, 0);
}
TEST(rtl_sync_timer_queue_delete_queue_cancels_timers)
{
    HANDLE q = NULL, t1 = NULL, t2 = NULL;
    TIMER_EXPORTS;
    timer_hits = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t1, timer_cb, NULL, 600000, 0, 0), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t2, timer_cb, NULL, 600000, 0, 0), 0);
    CHECK(t1 != t2);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    Sleep(50);
    EXPECT_EQ(timer_hits, 0);
}
TEST(rtl_sync_timer_queue_completion_event_signaled)
{
    HANDLE q = NULL, t = NULL, done = CreateEventA(NULL, TRUE, FALSE, NULL);
    NTSTATUS s;
    TIMER_EXPORTS;
    timer_hits = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, NULL, 600000, 0, 0), 0);
    s = UN(RtlDeleteTimer)(q, t, done);
    CHECK(s == 0 || s == S(0x103)); /* success, or STATUS_PENDING with the event set later */
    EXPECT_EQ(WaitForSingleObject(done, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    CloseHandle(done);
}
TEST(rtl_sync_timer_queue_callback_context_delivered)
{
    HANDLE q = NULL, t = NULL, ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    TIMER_EXPORTS;
    timer_hits = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, timer_cb, ev, 10, 0, WT_ONLY_ONCE), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0); /* callback signalled the context handle */
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    CloseHandle(ev);
}
/* ---------------- registered waits ---------------- */
static volatile LONG wait_hits_signaled, wait_hits_timeout;
static void NTAPI wait_cb(PVOID ctx, BOOLEAN timed_out)
{
    if (timed_out) InterlockedIncrement(&wait_hits_timeout); else InterlockedIncrement(&wait_hits_signaled);
    if (ctx) SetEvent((HANDLE)ctx);
}
TEST(rtl_sync_registered_wait_signaled)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL), done = CreateEventA(NULL, TRUE, FALSE, NULL), w = NULL;
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    wait_hits_signaled = wait_hits_timeout = 0;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, done, INFINITE, WT_ONLY_ONCE), 0);
    CHECK(w != NULL);
    Sleep(50);
    EXPECT_EQ(wait_hits_signaled, 0);
    SetEvent(ev);
    EXPECT_EQ(WaitForSingleObject(done, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(wait_hits_signaled, 1);
    EXPECT_EQ(wait_hits_timeout, 0);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    CloseHandle(ev); CloseHandle(done);
}
TEST(rtl_sync_registered_wait_timeout)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL), done = CreateEventA(NULL, TRUE, FALSE, NULL), w = NULL;
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    wait_hits_signaled = wait_hits_timeout = 0;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, done, 30, WT_ONLY_ONCE), 0);
    EXPECT_EQ(WaitForSingleObject(done, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(wait_hits_timeout, 1);
    EXPECT_EQ(wait_hits_signaled, 0);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    CloseHandle(ev); CloseHandle(done);
}
TEST(rtl_sync_registered_wait_deregistered_never_fires)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL), w = NULL;
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    wait_hits_signaled = wait_hits_timeout = 0;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, NULL, INFINITE, WT_ONLY_ONCE), 0);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    SetEvent(ev);
    Sleep(100);
    EXPECT_EQ(wait_hits_signaled, 0);
    CloseHandle(ev);
}
TEST(rtl_sync_registered_wait_repeats_without_only_once)
{
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL), w = NULL; /* auto-reset: each set releases one callback */
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    wait_hits_signaled = wait_hits_timeout = 0;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, NULL, INFINITE, 0), 0);
    for (int i = 0; i < 3; i++) {
        SetEvent(ev);
        for (int j = 0; j < 500 && wait_hits_signaled <= i; j++) Sleep(10);
    }
    EXPECT_EQ(wait_hits_signaled, 3);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    CloseHandle(ev);
}

/* ---------------- work items ---------------- */
static volatile DWORD work_tid; static volatile LONG work_runs;
static void NTAPI work_cb(PVOID ctx)
{
    work_tid = GetCurrentThreadId();
    InterlockedIncrement(&work_runs);
    SetEvent((HANDLE)ctx);
}
TEST(rtl_sync_work_item_runs_on_other_thread)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(UN(RtlQueueWorkItem));
    work_runs = 0; work_tid = 0;
    EXPECT_EQ(UN(RtlQueueWorkItem)(work_cb, ev, 0), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    Sleep(50);
    EXPECT_EQ(work_runs, 1);
    CHECK(work_tid != 0 && work_tid != GetCurrentThreadId());
    CloseHandle(ev);
}
TEST(rtl_sync_work_item_many)
{
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    REQUIRE(UN(RtlQueueWorkItem));
    work_runs = 0;
    for (int i = 0; i < 16; i++) EXPECT_EQ(UN(RtlQueueWorkItem)(work_cb, ev, 0), 0);
    for (int i = 0; i < 1000 && work_runs < 16; i++) Sleep(10);
    EXPECT_EQ(work_runs, 16);
    CloseHandle(ev);
}
