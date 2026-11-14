/* Zw-named synchronization services: events, semaphores, mutants, waits, alerts,
 * keyed events, event pairs, signal-and-wait. Behaviour is driven through the Zw names. */
#include "t.h"

UDECL(NTSTATUS, ZwReleaseSemaphore, (HANDLE, LONG, PLONG));
UDECL(NTSTATUS, ZwReleaseMutant, (HANDLE, PLONG));
UDECL(NTSTATUS, ZwResetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, ZwWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwWaitForMultipleObjects, (ULONG, PHANDLE, ULONG, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwWaitForMultipleObjects32, (ULONG, PULONG, ULONG, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwSignalAndWaitForSingleObject, (HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwTestAlert, (VOID));
UDECL(NTSTATUS, ZwYieldExecution, (VOID));
UDECL(NTSTATUS, ZwWaitForAlertByThreadId, (PVOID, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwReleaseKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwWaitForKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwWaitHighEventPair, (HANDLE));
UDECL(NTSTATUS, ZwWaitLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCreateSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG));
UDECL(NTSTATUS, NtCreateMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN));
UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCreateKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCreateEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtAlertThread, (HANDLE));
UDECL(NTSTATUS, NtAlertThreadByThreadId, (HANDLE));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 1
#endif
#define NOTIF 0
#define SYNC 1
#define P1 ((NTSTATUS)0xc00000ef)
#define P3 ((NTSTATUS)0xc00000f1)
#define S(x) ((NTSTATUS)(x))
#define TIMEOUT S(0x102)
#define ALERTED S(0x101)
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define DENIED S(0xc0000022)
#define WRONG_TYPE S(0xc0000024)
#define KEYED_ALL (STANDARD_RIGHTS_REQUIRED | 3)
#define ALL_SYNC (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 3)
#define MUTANT_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 1)
#define SELF_THREAD ((HANDLE)(LONG_PTR)-2)

static LARGE_INTEGER rel_ms(LONG ms) { LARGE_INTEGER t; t.QuadPart = -(LONGLONG)ms * 10000; return t; }
static HANDLE mk_event(ULONG type, BOOLEAN st, ACCESS_MASK acc)
{
    HANDLE h = NULL;
    if (!UN(NtCreateEvent)) return NULL;
    if (UN(NtCreateEvent)(&h, acc, NULL, type, st) < 0) return NULL;
    return h;
}
static HANDLE mk_sem(LONG init, LONG max)
{
    HANDLE h = NULL;
    if (UN(NtCreateSemaphore)(&h, ALL_SYNC, NULL, init, max) < 0) return NULL;
    return h;
}
static HANDLE mk_mut(BOOLEAN owned)
{
    HANDLE h = NULL;
    if (UN(NtCreateMutant)(&h, MUTANT_ACCESS, NULL, owned) < 0) return NULL;
    return h;
}
static void cl(HANDLE h) { if (h) UN(NtClose)(h); }

TEST(zw_sync_aliases)
{
    static const char *names[] = { "ReleaseSemaphore", "ReleaseMutant", "ResetEvent", "WaitForSingleObject",
        "WaitForMultipleObjects", "WaitForMultipleObjects32", "SignalAndWaitForSingleObject", "TestAlert",
        "YieldExecution", "WaitForAlertByThreadId", "ReleaseKeyedEvent", "WaitForKeyedEvent",
        "WaitHighEventPair", "WaitLowEventPair" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[64], zw[64];
        FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

TEST(zw_reset_event)
{
    HANDLE h, ro, sem; LONG prev; NTSTATUS s;
    REQUIRE(UN(ZwResetEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtSetEvent));
    h = mk_event(1 /* notification */, TRUE, EVENT_ALL_ACCESS);
    if (!h) { t_skip("event creation failed"); return; }
    prev = -5;
    EXPECT_EQ(UN(ZwResetEvent)(h, &prev), 0);
    EXPECT_EQ(prev, 1);
    prev = -5;
    EXPECT_EQ(UN(ZwResetEvent)(h, &prev), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(UN(ZwResetEvent)(h, NULL), 0);
    /* reset actually clears the state: zero timeout wait times out */
    { LARGE_INTEGER z = {0}; EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), TIMEOUT); }
    EXPECT_EQ(UN(NtSetEvent)(h, NULL), 0);
    { LARGE_INTEGER z = {0}; EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), 0); }
    EXPECT_EQ(UN(ZwResetEvent)(h, &prev), 0);
    { LARGE_INTEGER z = {0}; EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), TIMEOUT); }
    cl(h);
    /* access check: SYNCHRONIZE only (no modify) */
    ro = mk_event(NOTIF, TRUE, SYNCHRONIZE | EVENT_QUERY_STATE);
    if (ro) {
        prev = -5;
        s = UN(ZwResetEvent)(ro, &prev);
        EXPECT_EQ(s, DENIED); EXPECT_EQ(prev, -5);
        cl(ro);
    }
    /* wrong type and bad handles */
    sem = mk_sem(0, 1);
    if (sem) { EXPECT_EQ(UN(ZwResetEvent)(sem, NULL), WRONG_TYPE); cl(sem); }
    EXPECT_EQ(UN(ZwResetEvent)(NULL, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwResetEvent)((HANDLE)(ULONG_PTR)0x7ffffff4, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwResetEvent)(INVALID_HANDLE_VALUE, NULL), WRONG_TYPE);
}

TEST(zw_release_semaphore)
{
    HANDLE h, h0; LONG prev; LARGE_INTEGER z = {0};
    REQUIRE(UN(ZwReleaseSemaphore)); REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(ZwWaitForSingleObject));
    h = mk_sem(0, 3);
    if (!h) { t_skip("semaphore creation failed"); return; }
    EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), TIMEOUT);
    prev = -5;
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 2, &prev), 0);
    EXPECT_EQ(prev, 0);
    prev = -5;
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 1, &prev), 0);
    EXPECT_EQ(prev, 2);
    /* at the maximum now: any further release overflows and leaves the count alone */
    prev = -5;
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 1, &prev), S(0xc0000047)); /* STATUS_SEMAPHORE_LIMIT_EXCEEDED */
    EXPECT_EQ(prev, -5);
    /* invalid counts */
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 0, NULL), BAD_PARAM);
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, -1, NULL), BAD_PARAM);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), 0);   /* consumes one */
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 1, NULL), 0);
    EXPECT_EQ(UN(ZwReleaseSemaphore)(h, 0x7fffffff, NULL), S(0xc0000047));
    cl(h);
    /* wrong type, bad handle */
    h0 = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS);
    if (h0) { EXPECT_EQ(UN(ZwReleaseSemaphore)(h0, 1, NULL), WRONG_TYPE); cl(h0); }
    EXPECT_EQ(UN(ZwReleaseSemaphore)(NULL, 1, NULL), BAD_HANDLE);
    /* access: SYNCHRONIZE only lacks SEMAPHORE_MODIFY_STATE */
    { HANDLE ro = NULL;
      if (UN(NtCreateSemaphore)(&ro, SYNCHRONIZE | 1, NULL, 0, 2) >= 0) {
        EXPECT_EQ(UN(ZwReleaseSemaphore)(ro, 1, NULL), DENIED);
        cl(ro);
      } }
}

TEST(zw_release_mutant)
{
    HANDLE h; LONG prev; LARGE_INTEGER z = {0};
    REQUIRE(UN(ZwReleaseMutant)); REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(ZwWaitForSingleObject));
    /* not owned: release fails */
    h = mk_mut(FALSE);
    if (!h) { t_skip("mutant creation failed"); return; }
    prev = -5;
    EXPECT_EQ(UN(ZwReleaseMutant)(h, &prev), S(0xc0000046)); /* STATUS_MUTANT_NOT_OWNED */
    EXPECT_EQ(prev, -5);
    /* acquire twice (recursive), release twice */
    EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), 0);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(h, FALSE, &z), 0);
    prev = -5;
    EXPECT_EQ(UN(ZwReleaseMutant)(h, &prev), 0);
    t_note("mutant previous count after releasing twice-acquired mutant: %ld", (long)prev);
    EXPECT_EQ(prev, -1); /* count of a twice-acquired mutant is -1 before the release */
    EXPECT_EQ(UN(ZwReleaseMutant)(h, NULL), 0);
    EXPECT_EQ(UN(ZwReleaseMutant)(h, NULL), S(0xc0000046));
    cl(h);
    /* initially owned */
    h = mk_mut(TRUE);
    if (h) {
        EXPECT_EQ(UN(ZwReleaseMutant)(h, NULL), 0);
        EXPECT_EQ(UN(ZwReleaseMutant)(h, NULL), S(0xc0000046));
        cl(h);
    }
    h = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS);
    if (h) { EXPECT_EQ(UN(ZwReleaseMutant)(h, NULL), WRONG_TYPE); cl(h); }
    EXPECT_EQ(UN(ZwReleaseMutant)(NULL, NULL), BAD_HANDLE);
}

TEST(zw_wait_single)
{
    HANDLE ev, ev_auto, tm; LARGE_INTEGER z = {0}, t = rel_ms(20); DWORD t0, dt;
    REQUIRE(UN(ZwWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(NOTIF, TRUE, EVENT_ALL_ACCESS);
    ev_auto = mk_event(SYNC, TRUE, EVENT_ALL_ACCESS);
    if (!ev || !ev_auto) { t_skip("event creation failed"); cl(ev); cl(ev_auto); return; }
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev, FALSE, &z), 0);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev, FALSE, &z), 0);       /* notification: stays signaled */
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev_auto, FALSE, &z), 0);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev_auto, FALSE, &z), TIMEOUT); /* auto-reset consumed */
    t0 = GetTickCount();
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev_auto, FALSE, &t), TIMEOUT);
    dt = GetTickCount() - t0;
    CHECKF(dt >= 10 && dt < 5000, "relative timeout elapsed %lu ms", dt);
    /* absolute timeout in the past */
    { LARGE_INTEGER a; a.QuadPart = 1; EXPECT_EQ(UN(ZwWaitForSingleObject)(ev_auto, FALSE, &a), TIMEOUT); }
    EXPECT_EQ(UN(ZwWaitForSingleObject)(NULL, FALSE, &z), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWaitForSingleObject)((HANDLE)(ULONG_PTR)0x7ffffff4, FALSE, &z), BAD_HANDLE);
    /* no SYNCHRONIZE access */
    { HANDLE ns = mk_event(NOTIF, TRUE, EVENT_QUERY_STATE);
      if (ns) { EXPECT_EQ(UN(ZwWaitForSingleObject)(ns, FALSE, &z), DENIED); cl(ns); } }
    /* pseudo handles: current process is a waitable object (unsignaled), current thread too */
    EXPECT_EQ(UN(ZwWaitForSingleObject)(GetCurrentProcess(), FALSE, &z), TIMEOUT);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(GetCurrentThread(), FALSE, &z), TIMEOUT);
    /* timer object: unsignaled, then waitable type check */
    tm = NULL;
    if (UN(NtCreateTimer) && UN(NtCreateTimer)(&tm, TIMER_ALL_ACCESS, NULL, 1) >= 0) {
        EXPECT_EQ(UN(ZwWaitForSingleObject)(tm, FALSE, &z), TIMEOUT);
        cl(tm);
    }
    cl(ev); cl(ev_auto);
}

TEST(zw_wait_alertable)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(2000);
    REQUIRE(UN(ZwWaitForSingleObject)); REQUIRE(UN(ZwTestAlert)); REQUIRE(UN(NtAlertThread));
    ev = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS);
    if (!ev) { t_skip("event creation failed"); return; }
    /* drain any stale alert */
    UN(ZwTestAlert)();
    /* alert pending + alertable wait returns STATUS_ALERTED, consuming the alert */
    EXPECT_EQ(UN(NtAlertThread)(GetCurrentThread()), 0);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(ev, TRUE, &t), ALERTED);
    EXPECT_EQ(UN(ZwTestAlert)(), 0);
    /* non-alertable wait ignores the alert */
    { LARGE_INTEGER z = {0};
      EXPECT_EQ(UN(NtAlertThread)(GetCurrentThread()), 0);
      EXPECT_EQ(UN(ZwWaitForSingleObject)(ev, FALSE, &z), TIMEOUT);
      EXPECT_EQ(UN(ZwTestAlert)(), ALERTED);
      EXPECT_EQ(UN(ZwTestAlert)(), 0); }
    cl(ev);
}

TEST(zw_test_alert)
{
    REQUIRE(UN(ZwTestAlert)); REQUIRE(UN(NtAlertThread));
    UN(ZwTestAlert)();
    EXPECT_EQ(UN(ZwTestAlert)(), 0);
    EXPECT_EQ(UN(NtAlertThread)(GetCurrentThread()), 0);
    EXPECT_EQ(UN(ZwTestAlert)(), ALERTED);
    EXPECT_EQ(UN(ZwTestAlert)(), 0);
}

TEST(zw_wait_multiple)
{
    HANDLE a, b, c, arr[3]; LARGE_INTEGER z = {0}; HANDLE big[65]; unsigned i;
    REQUIRE(UN(ZwWaitForMultipleObjects)); REQUIRE(UN(NtCreateEvent));
    a = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS); b = mk_event(NOTIF, TRUE, EVENT_ALL_ACCESS); c = mk_event(SYNC, FALSE, EVENT_ALL_ACCESS);
    if (!a || !b || !c) { t_skip("event creation failed"); cl(a); cl(b); cl(c); return; }
    arr[0] = a; arr[1] = b; arr[2] = c;
    /* WaitAny (type 1): returns index of signaled object */
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(3, arr, 1, FALSE, &z), 1);
    arr[1] = a;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(2, arr, 1, FALSE, &z), TIMEOUT);
    /* WaitAll (type 0) */
    arr[0] = a; arr[1] = b;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(2, arr, 0, FALSE, &z), TIMEOUT);
    UN(NtSetEvent)(a, NULL);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(2, arr, 0, FALSE, &z), 0);
    /* single-object forms */
    arr[0] = b;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 1, FALSE, &z), 0);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 0, FALSE, &z), 0);
    /* WaitAny returns the index of the object at that position: place signaled last */
    arr[0] = c; arr[1] = a; arr[2] = b;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(3, arr, 1, FALSE, &z), 1);
    /* auto-reset event is consumed by a successful WaitAny */
    arr[0] = c; UN(NtSetEvent)(c, NULL);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 1, FALSE, &z), 0);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 1, FALSE, &z), TIMEOUT);
    /* invalid parameters */
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(0, arr, 1, FALSE, &z), P1);
    for (i = 0; i < 65; i++) big[i] = a;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(65, big, 1, FALSE, &z), P1);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 2, FALSE, &z), S(0xc00000f1));   /* invalid wait type */
    arr[0] = NULL;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(1, arr, 1, FALSE, &z), BAD_HANDLE);
    arr[0] = a; arr[1] = (HANDLE)(ULONG_PTR)0x7ffffff4;
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(2, arr, 1, FALSE, &z), BAD_HANDLE);
    /* exactly 64 handles are accepted */
    UN(NtSetEvent)(a, NULL);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects)(64, big, 1, FALSE, &z), 0);
    cl(a); cl(b); cl(c);
}

TEST(zw_wait_multiple32)
{
    HANDLE a; ULONG arr[2]; LARGE_INTEGER z = {0}; NTSTATUS s;
    REQUIRE(UN(ZwWaitForMultipleObjects32)); REQUIRE(UN(NtCreateEvent));
    a = mk_event(NOTIF, TRUE, EVENT_ALL_ACCESS);
    if (!a) { t_skip("event creation failed"); return; }
    arr[0] = (ULONG)(ULONG_PTR)a; arr[1] = 0;
    s = UN(ZwWaitForMultipleObjects32)(1, arr, 1, FALSE, &z);
    t_note("ZwWaitForMultipleObjects32 with a 32-bit handle array on x64: %08lx", (ULONG)s);
    /* Argument validation precedes handle lookup and is independent of the calling ABI. */
    EXPECT_EQ(UN(ZwWaitForMultipleObjects32)(0, arr, 1, FALSE, &z), P1);
    EXPECT_EQ(UN(ZwWaitForMultipleObjects32)(1, arr, 2, FALSE, &z), P3);
    cl(a);
}

TEST(zw_signal_and_wait)
{
    HANDLE sig, wt, sem, mut; LARGE_INTEGER z = {0}, t = rel_ms(2000); LONG prev;
    REQUIRE(UN(ZwSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    sig = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS); wt = mk_event(NOTIF, TRUE, EVENT_ALL_ACCESS);
    if (!sig || !wt) { t_skip("event creation failed"); cl(sig); cl(wt); return; }
    /* signals first object, then wait on the (already signaled) second returns 0 */
    EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(sig, wt, FALSE, &t), 0);
    EXPECT_EQ(UN(ZwWaitForSingleObject)(sig, FALSE, &z), 0);   /* proves the signal side effect */
    /* wait object not signaled: times out, signal still happened */
    UN(ZwResetEvent)(sig, NULL); UN(ZwResetEvent)(wt, NULL);
    { LARGE_INTEGER t1 = rel_ms(20);
      EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(sig, wt, FALSE, &t1), TIMEOUT);
      EXPECT_EQ(UN(ZwWaitForSingleObject)(sig, FALSE, &z), 0); }
    /* semaphore as signal object */
    sem = mk_sem(0, 5);
    if (sem) {
        UN(NtSetEvent)(wt, NULL);
        EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(sem, wt, FALSE, &t), 0);
        prev = -1; EXPECT_EQ(UN(ZwReleaseSemaphore)(sem, 1, &prev), 0); EXPECT_EQ(prev, 1);
        cl(sem);
    }
    /* mutant as signal object: not owned -> failure from release */
    mut = mk_mut(FALSE);
    if (mut) { EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(mut, wt, FALSE, &t), S(0xc0000046)); cl(mut); }
    mut = mk_mut(TRUE);
    if (mut) { EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(mut, wt, FALSE, &t), 0); cl(mut); }
    /* signal object of an unsupported type (timer) */
    { HANDLE tm = NULL;
      if (UN(NtCreateTimer) && UN(NtCreateTimer)(&tm, TIMER_ALL_ACCESS, NULL, 1) >= 0) {
          EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(tm, wt, FALSE, &t), WRONG_TYPE); cl(tm); } }
    EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(NULL, wt, FALSE, &t), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(sig, NULL, FALSE, &t), BAD_HANDLE);
    /* signal handle without modify access */
    { HANDLE ro = mk_event(NOTIF, FALSE, SYNCHRONIZE | EVENT_QUERY_STATE);
      if (ro) { EXPECT_EQ(UN(ZwSignalAndWaitForSingleObject)(ro, wt, FALSE, &t), DENIED); cl(ro); } }
    cl(sig); cl(wt);
}

TEST(zw_yield_execution)
{
    NTSTATUS s;
    REQUIRE(UN(ZwYieldExecution));
    s = UN(ZwYieldExecution)();
    /* STATUS_SUCCESS when another thread was scheduled, STATUS_NO_YIELD_PERFORMED otherwise */
    CHECKF(s == 0 || s == S(0x40000024), "status %08lx", (ULONG)s);
}

TEST(zw_wait_alert_by_thread_id)
{
    LARGE_INTEGER t = rel_ms(30), z = {0}; NTSTATUS s; HANDLE tid = (HANDLE)(ULONG_PTR)GetCurrentThreadId();
    REQUIRE(UN(ZwWaitForAlertByThreadId)); REQUIRE(UN(NtAlertThreadByThreadId));
    /* drain any pending alert */
    UN(ZwWaitForAlertByThreadId)(NULL, &z);
    EXPECT_EQ(UN(ZwWaitForAlertByThreadId)(NULL, &t), TIMEOUT);
    /* alert before the wait is remembered once */
    EXPECT_EQ(UN(NtAlertThreadByThreadId)(tid), 0);
    EXPECT_EQ(UN(ZwWaitForAlertByThreadId)(NULL, &t), ALERTED);
    EXPECT_EQ(UN(ZwWaitForAlertByThreadId)(NULL, &t), TIMEOUT);
    /* a second thread alerts us */
    EXPECT_EQ(UN(NtAlertThreadByThreadId)(tid), 0);
    EXPECT_EQ(UN(NtAlertThreadByThreadId)(tid), 0);
    EXPECT_EQ(UN(ZwWaitForAlertByThreadId)((PVOID)0x1234, &t), ALERTED);
    EXPECT_EQ(UN(ZwWaitForAlertByThreadId)((PVOID)0x1234, &t), TIMEOUT);
    s = UN(NtAlertThreadByThreadId)((HANDLE)(ULONG_PTR)0xfffffffc);
    EXPECT_EQ(s, S(0xc000000b)); /* STATUS_INVALID_CID */
}

typedef struct { HANDLE keyed; PVOID key; volatile NTSTATUS st; volatile LONG done; int release; } kw_t;
static DWORD WINAPI keyed_thread(PVOID p)
{
    kw_t *k = p; LARGE_INTEGER t = rel_ms(10000);
    k->st = k->release ? UN(ZwReleaseKeyedEvent)(k->keyed, k->key, FALSE, &t)
                       : UN(ZwWaitForKeyedEvent)(k->keyed, k->key, FALSE, &t);
    InterlockedExchange(&k->done, 1);
    return 0;
}

TEST(zw_keyed_event)
{
    HANDLE k = NULL, th; LARGE_INTEGER z = {0}, t = rel_ms(10000); kw_t w; NTSTATUS s; int i;
    REQUIRE(UN(ZwReleaseKeyedEvent)); REQUIRE(UN(ZwWaitForKeyedEvent)); REQUIRE(UN(NtCreateKeyedEvent));
    if (UN(NtCreateKeyedEvent)(&k, KEYED_ALL, NULL, 0) < 0) { t_skip("keyed event creation failed"); return; }
    EXPECT_EQ(UN(ZwWaitForKeyedEvent)(k, (PVOID)0x1000, FALSE, &z), TIMEOUT);
    EXPECT_EQ(UN(ZwReleaseKeyedEvent)(k, (PVOID)0x1000, FALSE, &z), TIMEOUT);
    EXPECT_EQ(UN(ZwWaitForKeyedEvent)(k, (PVOID)0x1001, FALSE, &z), S(0xc00000ef));
    EXPECT_EQ(UN(ZwReleaseKeyedEvent)(k, (PVOID)0x1001, FALSE, &z), S(0xc00000ef));
    EXPECT_EQ(UN(ZwWaitForKeyedEvent)(NULL, (PVOID)0x1000, FALSE, &z), TIMEOUT);
    EXPECT_EQ(UN(ZwWaitForKeyedEvent)((HANDLE)(ULONG_PTR)0x7ffffff4, (PVOID)0x1000, FALSE, &z), BAD_HANDLE);
    { HANDLE ev = mk_event(NOTIF, FALSE, EVENT_ALL_ACCESS);
      if (ev) { EXPECT_EQ(UN(ZwReleaseKeyedEvent)(ev, (PVOID)0x1000, FALSE, &z), WRONG_TYPE); cl(ev); } }
    /* both pairing directions */
    for (i = 0; i < 2; i++) {
        memset(&w, 0, sizeof w); w.keyed = k; w.key = (PVOID)0x2000; w.release = i;
        th = CreateThread(NULL, 0, keyed_thread, &w, 0, NULL);
        if (!th) { t_skip("CreateThread failed"); break; }
        Sleep(100);
        CHECK(!w.done);
        s = i ? UN(ZwWaitForKeyedEvent)(k, (PVOID)0x2000, FALSE, &t) : UN(ZwReleaseKeyedEvent)(k, (PVOID)0x2000, FALSE, &t);
        EXPECT_EQ(s, 0);
        WaitForSingleObject(th, 15000);
        EXPECT_EQ(w.st, 0);
        CloseHandle(th);
    }
    cl(k);
}

TEST(zw_event_pair)
{
    HANDLE ep = NULL; NTSTATUS s;
    REQUIRE(UN(ZwWaitLowEventPair)); REQUIRE(UN(ZwWaitHighEventPair));
    REQUIRE(UN(NtCreateEventPair)); 
    /* Event pairs are not creatable on this release: creation is rejected, so waits can only fail. */
    s = UN(NtCreateEventPair)(&ep, 0x1f0000 | SYNCHRONIZE, NULL);
    EXPECT_EQ(s, S(0xc0000002)); /* STATUS_NOT_IMPLEMENTED */
    if (s >= 0) cl(ep);
    /* The wait services are stubs too: not-implemented regardless of the handle. */
    EXPECT_EQ(UN(ZwWaitLowEventPair)(NULL), S(0xc0000002));
    EXPECT_EQ(UN(ZwWaitHighEventPair)(NULL), S(0xc0000002));
    EXPECT_EQ(UN(ZwWaitLowEventPair)((HANDLE)(ULONG_PTR)0x7ffffff4), S(0xc0000002));
    { HANDLE ev = mk_event(NOTIF, TRUE, EVENT_ALL_ACCESS);
      if (ev) { EXPECT_EQ(UN(ZwWaitLowEventPair)(ev), S(0xc0000002)); EXPECT_EQ(UN(ZwWaitHighEventPair)(ev), S(0xc0000002)); cl(ev); } }
}
