#include "t.h"
#include <stdlib.h>

/* phnt nttp.h signatures; environment layout checked against Win10 PDB. */
UDECL(NTSTATUS, TpAllocPool, (PTP_POOL *, PVOID));
UDECL(VOID, TpReleasePool, (PTP_POOL));
UDECL(VOID, TpSetPoolMaxThreads, (PTP_POOL, ULONG));
UDECL(NTSTATUS, TpAllocWork, (PTP_WORK *, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpPostWork, (PTP_WORK));
UDECL(VOID, TpWaitForWork, (PTP_WORK, ULONG));
UDECL(VOID, TpReleaseWork, (PTP_WORK));
UDECL(NTSTATUS, TpSimpleTryPost, (PTP_SIMPLE_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpCallbackSetEventOnCompletion, (PTP_CALLBACK_INSTANCE, HANDLE));
UDECL(NTSTATUS, TpAllocTimer, (PTP_TIMER *, PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpSetTimer, (PTP_TIMER, PLARGE_INTEGER, ULONG, ULONG));
UDECL(ULONG, TpIsTimerSet, (PTP_TIMER));
UDECL(VOID, TpWaitForTimer, (PTP_TIMER, ULONG));
UDECL(VOID, TpReleaseTimer, (PTP_TIMER));
UDECL(NTSTATUS, TpAllocWait, (PTP_WAIT *, PTP_WAIT_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpSetWait, (PTP_WAIT, HANDLE, PLARGE_INTEGER));
UDECL(VOID, TpWaitForWait, (PTP_WAIT, ULONG));
UDECL(VOID, TpReleaseWait, (PTP_WAIT));

_Static_assert(sizeof(TP_CALLBACK_ENVIRON) == 72, "Win10 x64 environment");
_Static_assert(offsetof(TP_CALLBACK_ENVIRON, Pool) == 8, "Pool");
_Static_assert(offsetof(TP_CALLBACK_ENVIRON, u) == 56, "flags");
_Static_assert(offsetof(TP_CALLBACK_ENVIRON, CallbackPriority) == 60, "priority");
_Static_assert(offsetof(TP_CALLBACK_ENVIRON, Size) == 64, "size");

typedef struct {
    HANDLE done;
    volatile LONG calls, bad;
    PVOID object;
    DWORD parent_tid;
    DWORD result;
    ULONG cookie;
} callback_state;

/* Failure exits immediately: never return a callback's stack context while it
 * may still be in use. The parent diagnoses the line and bounds the process. */
#define C(c) do { if (!(c)) { printf("child prerequisite/check line %d: %s\n", __LINE__, #c); ExitProcess(__LINE__); } } while (0)
static void observe(callback_state *s, PTP_CALLBACK_INSTANCE instance, PVOID object)
{
    if (!instance || object != s->object || s->cookie != 0x1234abcd ||
        GetCurrentThreadId() == s->parent_tid) InterlockedIncrement(&s->bad);
    InterlockedIncrement(&s->calls);
    SetEvent(s->done);
}
static void CALLBACK work_cb(PTP_CALLBACK_INSTANCE i, PVOID p, PTP_WORK w)
{ observe(p, i, w); }
static void CALLBACK timer_cb(PTP_CALLBACK_INSTANCE i, PVOID p, PTP_TIMER t)
{ observe(p, i, t); }
static void CALLBACK wait_cb(PTP_CALLBACK_INSTANCE i, PVOID p, PTP_WAIT w, TP_WAIT_RESULT r)
{ callback_state *s = p; s->result = r; observe(s, i, w); }
static void CALLBACK simple_cb(PTP_CALLBACK_INSTANCE i, PVOID p)
{
    callback_state *s = p;
    /* This event is signaled after return, unlike an event set in the body. */
    UN(TpCallbackSetEventOnCompletion)(i, s->done);
    if (!i || s->cookie != 0x1234abcd || GetCurrentThreadId() == s->parent_tid)
        InterlockedIncrement(&s->bad);
    InterlockedIncrement(&s->calls);
}
typedef struct { HANDLE entered, release; volatile LONG bad; } gate_state;
static void CALLBACK gate_cb(PTP_CALLBACK_INSTANCE i, PVOID p, PTP_WORK w)
{
    gate_state *g = p;
    SetEvent(g->entered);
    if (WaitForSingleObject(g->release, 5000) != WAIT_OBJECT_0)
        InterlockedIncrement(&g->bad);
}
static void init_state(callback_state *s)
{
    memset(s, 0, sizeof(*s));
    s->done = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!s->done) ExitProcess(77);
    s->parent_tid = GetCurrentThreadId();
    s->cookie = 0x1234abcd;
}
static void init_env(TP_CALLBACK_ENVIRON *e, PTP_POOL p)
{
    memset(e, 0, sizeof(*e));
    e->Version = 3; e->Size = sizeof(*e);
    e->CallbackPriority = TP_CALLBACK_PRIORITY_NORMAL; e->Pool = p;
}

CHILD(rtl_tp_case)
{
    int mode = argc > 1 ? atoi(argv[1]) : -1;
    PTP_POOL pool = NULL, second = NULL;
    TP_CALLBACK_ENVIRON env;
    callback_state s;
    init_state(&s);
    init_env(&env, NULL);
    if (mode < 2) {
        C(UN(TpAllocPool)(&pool, NULL) == 0 && pool);
        if (mode == 1) {
            C(UN(TpAllocPool)(&second, NULL) == 0 && second && second != pool);
            UN(TpReleasePool)(second);
        }
        UN(TpReleasePool)(pool);
    } else if (mode < 12) {
        PTP_WORK work = NULL, other = NULL;
        int k = mode - 2, n = k == 3 ? 16 : 1;
        if (k >= 5 && k <= 8) {
            C(UN(TpAllocPool)(&pool, NULL) == 0 && pool);
            init_env(&env, pool);
            if (k == 6) env.CallbackPriority = TP_CALLBACK_PRIORITY_HIGH;
            if (k == 7) env.CallbackPriority = TP_CALLBACK_PRIORITY_LOW;
            if (k == 8) UN(TpSetPoolMaxThreads)(pool, 1);
        }
        C(UN(TpAllocWork)(&work, work_cb, &s, pool ? &env : NULL) == 0 && work);
        s.object = work;
        if (k < 2) {
            UN(TpWaitForWork)(work, k == 1);
            C(s.calls == 0);
        } else if (k == 9) {
            callback_state b;
            init_state(&b);
            C(UN(TpAllocWork)(&other, work_cb, &b, NULL) == 0 && other && other != work);
            b.object = other;
            UN(TpPostWork)(other); UN(TpPostWork)(work);
            UN(TpWaitForWork)(other, FALSE); UN(TpWaitForWork)(work, FALSE);
            C(b.calls == 1 && b.bad == 0 && s.calls == 1);
            UN(TpReleaseWork)(other); CloseHandle(b.done);
        } else if (k == 8) {
            PTP_WORK blocker = NULL;
            gate_state g;
            memset(&g, 0, sizeof(g));
            g.entered = CreateEventW(NULL, FALSE, FALSE, NULL);
            g.release = CreateEventW(NULL, FALSE, FALSE, NULL);
            if (!g.entered || !g.release) ExitProcess(77);
            C(UN(TpAllocWork)(&blocker, gate_cb, &g, &env) == 0 && blocker);
            UN(TpPostWork)(blocker);
            C(WaitForSingleObject(g.entered, 5000) == WAIT_OBJECT_0);
            /* The private pool's only worker is inside our bounded gate. */
            UN(TpPostWork)(work);
            UN(TpWaitForWork)(work, TRUE);
            C(s.calls == 0);
            C(SetEvent(g.release));
            UN(TpWaitForWork)(blocker, FALSE);
            C(g.bad == 0);
            UN(TpPostWork)(work); UN(TpWaitForWork)(work, FALSE);
            C(s.calls == 1);
            UN(TpReleaseWork)(blocker);
            CloseHandle(g.entered); CloseHandle(g.release);
        } else {
            for (int j = 0; j < n; j++) UN(TpPostWork)(work);
            UN(TpWaitForWork)(work, FALSE);
            C(s.calls == n);
            if (k == 4) {
                UN(TpPostWork)(work); UN(TpWaitForWork)(work, FALSE);
                C(s.calls == 2);
            }
        }
        C(s.bad == 0);
        UN(TpReleaseWork)(work);
        if (pool) UN(TpReleasePool)(pool);
    } else if (mode < 16) {
        int k = mode - 12, n = k == 1 ? 8 : 1;
        if (k >= 2) {
            C(UN(TpAllocPool)(&pool, NULL) == 0 && pool);
            init_env(&env, pool);
            if (k == 3) env.CallbackPriority = TP_CALLBACK_PRIORITY_LOW;
        }
        for (int j = 0; j < n; j++) {
            C(UN(TpSimpleTryPost)(simple_cb, &s, pool ? &env : NULL) == 0);
            C(WaitForSingleObject(s.done, 5000) == WAIT_OBJECT_0);
            C(s.calls == j + 1 && s.bad == 0);
        }
        if (pool) UN(TpReleasePool)(pool);
    } else if (mode < 21) {
        PTP_TIMER timer = NULL;
        LARGE_INTEGER due;
        int k = mode - 16;
        C(UN(TpAllocTimer)(&timer, timer_cb, &s, NULL) == 0 && timer);
        s.object = timer;
        C(!UN(TpIsTimerSet)(timer));
        if (k == 0) {
            UN(TpWaitForTimer)(timer, FALSE); C(s.calls == 0);
        } else if (k == 2) {
            due.QuadPart = -600000000LL;
            UN(TpSetTimer)(timer, &due, 0, 0);
            C(UN(TpIsTimerSet)(timer));
            UN(TpSetTimer)(timer, NULL, 0, 0);
            C(!UN(TpIsTimerSet)(timer));
            UN(TpWaitForTimer)(timer, TRUE); C(s.calls == 0);
        } else {
            int rounds = k == 3 ? 2 : 1;
            for (int j = 0; j < rounds; j++) {
                /* One-shot relative and already-expired absolute times. */
                due.QuadPart = k == 4 ? 1 : -10000;
                UN(TpSetTimer)(timer, &due, 0, 0);
                C(WaitForSingleObject(s.done, 5000) == WAIT_OBJECT_0);
                UN(TpWaitForTimer)(timer, FALSE);
                C(s.calls == j + 1 && s.bad == 0);
            }
            UN(TpSetTimer)(timer, NULL, 0, 0);
            UN(TpWaitForTimer)(timer, TRUE);
        }
        C(!UN(TpIsTimerSet)(timer));
        UN(TpReleaseTimer)(timer);
    } else {
        PTP_WAIT wait = NULL;
        HANDLE trigger = CreateEventW(NULL, TRUE, FALSE, NULL);
        LARGE_INTEGER due;
        int k = mode - 21;
        if (!trigger) ExitProcess(77);
        C(UN(TpAllocWait)(&wait, wait_cb, &s, NULL) == 0 && wait);
        s.object = wait;
        if (k == 0) {
            UN(TpWaitForWait)(wait, FALSE); C(s.calls == 0);
        } else if (k == 4) {
            UN(TpSetWait)(wait, trigger, NULL);
            UN(TpSetWait)(wait, NULL, NULL);
            UN(TpWaitForWait)(wait, TRUE);
            C(s.calls == 0);
        } else {
            int rounds = k == 3 ? 2 : 1;
            int timeout = k == 2 || k == 5;
            if (k == 6) {
                UN(TpSetWait)(wait, trigger, NULL);
                UN(TpSetWait)(wait, NULL, NULL);
                UN(TpWaitForWait)(wait, TRUE);
                C(s.calls == 0);
            }
            for (int j = 0; j < rounds; j++) {
                due.QuadPart = k == 5 ? 1 : -10000;
                if (!timeout) C(ResetEvent(trigger));
                if (k == 1) C(SetEvent(trigger));
                UN(TpSetWait)(wait, trigger, timeout ? &due : NULL);
                if (!timeout && k != 1) C(SetEvent(trigger));
                C(WaitForSingleObject(s.done, 5000) == WAIT_OBJECT_0);
                UN(TpWaitForWait)(wait, FALSE);
                C(s.calls == j + 1 && s.bad == 0);
                C(s.result == (timeout ? WAIT_TIMEOUT : WAIT_OBJECT_0));
            }
        }
        UN(TpSetWait)(wait, NULL, NULL);
        UN(TpWaitForWait)(wait, TRUE);
        UN(TpReleaseWait)(wait); CloseHandle(trigger);
    }
    CloseHandle(s.done);
    return 0;
}

static void run_case(int mode)
{
    char arg[16]; DWORD result;
    REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpReleasePool));
    if (mode >= 2 && mode < 12) {
        REQUIRE(UN(TpAllocWork)); REQUIRE(UN(TpPostWork));
        REQUIRE(UN(TpWaitForWork)); REQUIRE(UN(TpReleaseWork));
        if (mode == 10) { REQUIRE(UN(TpSetPoolMaxThreads)); }
    } else if (mode >= 12 && mode < 16) {
        REQUIRE(UN(TpSimpleTryPost)); REQUIRE(UN(TpCallbackSetEventOnCompletion));
    } else if (mode >= 16 && mode < 21) {
        REQUIRE(UN(TpAllocTimer)); REQUIRE(UN(TpSetTimer)); REQUIRE(UN(TpIsTimerSet));
        REQUIRE(UN(TpWaitForTimer)); REQUIRE(UN(TpReleaseTimer));
    } else if (mode >= 21) {
        REQUIRE(UN(TpAllocWait)); REQUIRE(UN(TpSetWait));
        REQUIRE(UN(TpWaitForWait)); REQUIRE(UN(TpReleaseWait));
    }
    snprintf(arg, sizeof(arg), "%d", mode);
    result = t_run_child("rtl_tp_case", arg, 15000);
    if (result == 77) { t_skip("cannot create callback fixture event"); return; }
    EXPECT_EQ(result, 0);
}
#define CASE(name, mode) TEST(rtl_tp_##name) { run_case(mode); }
CASE(pool_allocate_release, 0)
CASE(pool_distinct_live, 1)
CASE(work_idle_drain, 2)
CASE(work_idle_cancel, 3)
CASE(work_single_dispatch, 4)
CASE(work_batch_dispatch, 5)
CASE(work_reuse_after_drain, 6)
CASE(work_private_pool, 7)
CASE(work_high_priority, 8)
CASE(work_low_priority, 9)
CASE(work_cancel_queued_and_reuse, 10)
CASE(work_distinct_contexts, 11)
CASE(simple_default_pool, 12)
CASE(simple_repeated_completion, 13)
CASE(simple_private_pool, 14)
CASE(simple_low_priority, 15)
CASE(timer_idle_drain, 16)
CASE(timer_relative_fire, 17)
CASE(timer_disarm_future, 18)
CASE(timer_rearm_after_completion, 19)
CASE(timer_expired_absolute, 20)
CASE(wait_idle_drain, 21)
CASE(wait_signaled_event, 22)
CASE(wait_timeout_result, 23)
CASE(wait_explicit_rearm, 24)
CASE(wait_disarm_unsignaled, 25)
CASE(wait_expired_absolute_timeout, 26)
CASE(wait_reuse_after_disarm, 27)
