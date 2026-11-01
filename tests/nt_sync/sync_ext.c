/* Keyed events, signal-and-wait, delays, alerts and user APC delivery. */
#include "t.h"

UDECL(NTSTATUS, NtCreateKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtReleaseKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClearEvent, (HANDLE));
UDECL(NTSTATUS, NtSetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtCreateSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG));
UDECL(NTSTATUS, NtQuerySemaphore, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSignalAndWaitForSingleObject, (HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtDelayExecution, (BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtYieldExecution, (VOID));
UDECL(NTSTATUS, NtAlertThread, (HANDLE));
UDECL(NTSTATUS, NtTestAlert, (VOID));
UDECL(NTSTATUS, NtQueueApcThread, (HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define TIMEOUT S(0x102)
#define USER_APC S(0xc0)
#define ALERTED S(0x101)
#define STATUS_BAD_HANDLE S(0xc0000008)
#define TYPE_MISMATCH S(0xc0000024)
#define BAD_PARAM S(0xc000000d)
#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 1
#endif
#define KEYED_ALL (STANDARD_RIGHTS_REQUIRED | 3)
#define SELF_THREAD ((HANDLE)(LONG_PTR)-2)

static LARGE_INTEGER rel_ms(LONG ms) { LARGE_INTEGER t; t.QuadPart = -(LONGLONG)ms * 10000; return t; }
static HANDLE mk_event(ULONG type, BOOLEAN state)
{
    HANDLE h = NULL;
    NTSTATUS s = UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, type, state);
    EXPECT_EQ(s, 0);
    return s < 0 ? NULL : h;
}
static HANDLE mk_keyed(void)
{
    HANDLE h = NULL;
    NTSTATUS s = UN(NtCreateKeyedEvent)(&h, KEYED_ALL, NULL, 0);
    EXPECT_EQ(s, 0);
    return s < 0 ? NULL : h;
}
static int event_state(HANDLE h)
{
    struct { LONG type, state; } i = {-1, -1};
    if (UN(NtQueryEvent)(h, 0, &i, sizeof i, NULL) != 0) return -1;
    return i.state;
}

/* ---------------- keyed events ---------------- */
TEST(nt_sync_keyed_wait_without_release_times_out)
{
    HANDLE k; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    k = mk_keyed(); if (!k) return;
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(k, (PVOID)0x1000, FALSE, &t), TIMEOUT);
    UN(NtClose)(k);
}
TEST(nt_sync_keyed_release_without_waiter_times_out)
{
    HANDLE k; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent));
    k = mk_keyed(); if (!k) return;
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(k, (PVOID)0x1000, FALSE, &t), TIMEOUT);
    UN(NtClose)(k);
}
TEST(nt_sync_keyed_zero_timeout_polls)
{
    HANDLE k; LARGE_INTEGER t; t.QuadPart = 0;
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    k = mk_keyed(); if (!k) return;
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(k, (PVOID)0x2000, FALSE, &t), TIMEOUT);
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(k, (PVOID)0x2000, FALSE, &t), TIMEOUT);
    UN(NtClose)(k);
}
TEST(nt_sync_keyed_key_low_bit_rejected)
{
    HANDLE k; LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    k = mk_keyed(); if (!k) return;
    /* Keys are pointer-aligned values: the low bit is reserved. */
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(k, (PVOID)0x1001, FALSE, &t), S(0xc00000ef)); /* STATUS_INVALID_PARAMETER_1 */
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(k, (PVOID)0x1001, FALSE, &t), S(0xc00000ef));
    UN(NtClose)(k);
}
typedef struct { HANDLE keyed; PVOID key; volatile NTSTATUS status; volatile LONG done; } kw_t;
static DWORD WINAPI keyed_waiter(PVOID p)
{
    kw_t *k = p; LARGE_INTEGER t = rel_ms(10000);
    k->status = UN(NtWaitForKeyedEvent)(k->keyed, k->key, FALSE, &t);
    InterlockedExchange(&k->done, 1);
    return 0;
}
static DWORD WINAPI keyed_releaser(PVOID p)
{
    kw_t *k = p; LARGE_INTEGER t = rel_ms(10000);
    k->status = UN(NtReleaseKeyedEvent)(k->keyed, k->key, FALSE, &t);
    InterlockedExchange(&k->done, 1);
    return 0;
}
static void keyed_pair(int waiter_first, PVOID wait_key, PVOID rel_key, NTSTATUS expect_main, int expect_paired)
{
    HANDLE k, th; kw_t w = {0}; LARGE_INTEGER t = rel_ms(expect_paired ? 10000 : 80);
    NTSTATUS s;
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    k = mk_keyed(); if (!k) return;
    w.keyed = k; w.key = waiter_first ? wait_key : rel_key;
    th = CreateThread(NULL, 0, waiter_first ? keyed_waiter : keyed_releaser, &w, 0, NULL);
    if (!th) { t_skip("CreateThread failed"); UN(NtClose)(k); return; }
    Sleep(100); /* let the other side block first */
    CHECK(!w.done);
    if (waiter_first) s = UN(NtReleaseKeyedEvent)(k, rel_key, FALSE, &t);
    else s = UN(NtWaitForKeyedEvent)(k, wait_key, FALSE, &t);
    EXPECT_EQ(s, expect_main);
    if (!expect_paired) { /* unpaired: the thread is still blocked; pair it up with the right key so it can exit */
        LARGE_INTEGER t2 = rel_ms(10000);
        if (waiter_first) UN(NtReleaseKeyedEvent)(k, wait_key, FALSE, &t2);
        else UN(NtWaitForKeyedEvent)(k, rel_key, FALSE, &t2);
    }
    WaitForSingleObject(th, 15000);
    EXPECT_EQ(w.status, 0);
    CloseHandle(th);
    UN(NtClose)(k);
}
TEST(nt_sync_keyed_release_wakes_blocked_waiter) { keyed_pair(1, (PVOID)0x3000, (PVOID)0x3000, 0, 1); }
TEST(nt_sync_keyed_wait_wakes_blocked_releaser) { keyed_pair(0, (PVOID)0x3000, (PVOID)0x3000, 0, 1); }
TEST(nt_sync_keyed_mismatched_key_does_not_pair) { keyed_pair(1, (PVOID)0x4000, (PVOID)0x4008, TIMEOUT, 0); }

TEST(nt_sync_keyed_invalid_handle_and_type)
{
    HANDLE ev, k; LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    ev = mk_event(0, FALSE); if (!ev) return;
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(ev, (PVOID)0x1000, FALSE, &t), TYPE_MISMATCH);
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(ev, (PVOID)0x1000, FALSE, &t), TYPE_MISMATCH);
    UN(NtClose)(ev);
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(ev, (PVOID)0x1000, FALSE, &t), STATUS_BAD_HANDLE);
    k = mk_keyed(); if (!k) return;
    UN(NtClose)(k);
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(k, (PVOID)0x1000, FALSE, &t), STATUS_BAD_HANDLE);
}
TEST(nt_sync_keyed_wait_right_required)
{
    HANDLE k = NULL, d = NULL; LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtReleaseKeyedEvent)); REQUIRE(UN(NtWaitForKeyedEvent));
    k = mk_keyed(); if (!k) return;
    /* KEYEDEVENT_WAIT = 1, KEYEDEVENT_WAKE = 2: a duplicate holding only one right cannot do the other operation. */
    if (!DuplicateHandle(GetCurrentProcess(), k, GetCurrentProcess(), &d, 1, FALSE, 0)) { t_skip("DuplicateHandle failed"); UN(NtClose)(k); return; }
    EXPECT_EQ(UN(NtReleaseKeyedEvent)(d, (PVOID)0x1000, FALSE, &t), S(0xc0000022)); /* STATUS_ACCESS_DENIED */
    EXPECT_EQ(UN(NtWaitForKeyedEvent)(d, (PVOID)0x1000, FALSE, &t), TIMEOUT);
    CloseHandle(d);
    UN(NtClose)(k);
}

/* ---------------- NtClearEvent ---------------- */
TEST(nt_sync_clear_event_resets_state)
{
    HANDLE ev;
    REQUIRE(UN(NtClearEvent)); REQUIRE(UN(NtQueryEvent)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, TRUE); if (!ev) return;
    EXPECT_EQ(event_state(ev), 1);
    EXPECT_EQ(UN(NtClearEvent)(ev), 0);
    EXPECT_EQ(event_state(ev), 0);
    EXPECT_EQ(UN(NtClearEvent)(ev), 0); /* idempotent */
    UN(NtClose)(ev);
}
TEST(nt_sync_clear_event_errors)
{
    HANDLE ev, sem = NULL;
    REQUIRE(UN(NtClearEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateSemaphore));
    EXPECT_EQ(UN(NtClearEvent)(NULL), STATUS_BAD_HANDLE);
    EXPECT_EQ(UN(NtCreateSemaphore)(&sem, SEMAPHORE_ALL_ACCESS, NULL, 0, 1), 0);
    if (sem) { EXPECT_EQ(UN(NtClearEvent)(sem), TYPE_MISMATCH); UN(NtClose)(sem); }
    ev = mk_event(1, TRUE); if (!ev) return;
    UN(NtClose)(ev);
    EXPECT_EQ(UN(NtClearEvent)(ev), STATUS_BAD_HANDLE);
}
TEST(nt_sync_clear_event_needs_modify_right)
{
    HANDLE ev, d = NULL;
    REQUIRE(UN(NtClearEvent)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, TRUE); if (!ev) return;
    if (DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), &d, EVENT_QUERY_STATE | SYNCHRONIZE, FALSE, 0)) {
        EXPECT_EQ(UN(NtClearEvent)(d), S(0xc0000022));
        CloseHandle(d);
    }
    UN(NtClose)(ev);
}

/* ---------------- NtSignalAndWaitForSingleObject ---------------- */
TEST(nt_sync_signal_and_wait_event_to_event)
{
    HANDLE a, b; LARGE_INTEGER t = rel_ms(2000);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtQueryEvent));
    a = mk_event(0, FALSE); b = mk_event(0, TRUE);
    if (a && b) {
        EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(a, b, FALSE, &t), 0);
        EXPECT_EQ(event_state(a), 1);
    }
    if (a) UN(NtClose)(a);
    if (b) UN(NtClose)(b);
}
TEST(nt_sync_signal_and_wait_timeout_still_signals)
{
    HANDLE a, b; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtQueryEvent));
    a = mk_event(0, FALSE); b = mk_event(0, FALSE);
    if (a && b) {
        EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(a, b, FALSE, &t), TIMEOUT);
        EXPECT_EQ(event_state(a), 1);
        EXPECT_EQ(event_state(b), 0);
    }
    if (a) UN(NtClose)(a);
    if (b) UN(NtClose)(b);
}
TEST(nt_sync_signal_and_wait_semaphore_release_consumed)
{
    HANDLE sem = NULL; LARGE_INTEGER t = rel_ms(2000);
    struct { LONG count, maximum; } q = {-1, -1};
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtQuerySemaphore));
    EXPECT_EQ(UN(NtCreateSemaphore)(&sem, SEMAPHORE_ALL_ACCESS, NULL, 0, 5), 0);
    if (!sem) return;
    /* Signal and wait on the same semaphore: the release is immediately consumed by the wait. */
    EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(sem, sem, FALSE, &t), 0);
    EXPECT_EQ(UN(NtQuerySemaphore)(sem, 0, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q.count, 0);
    EXPECT_EQ(q.maximum, 5);
    UN(NtClose)(sem);
}
TEST(nt_sync_signal_and_wait_semaphore_at_maximum)
{
    HANDLE sem = NULL, ev; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtCreateEvent));
    EXPECT_EQ(UN(NtCreateSemaphore)(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 1), 0);
    ev = mk_event(0, TRUE);
    if (sem && ev) EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(sem, ev, FALSE, &t), S(0xc0000047)); /* STATUS_SEMAPHORE_LIMIT_EXCEEDED */
    if (sem) UN(NtClose)(sem);
    if (ev) UN(NtClose)(ev);
}
TEST(nt_sync_signal_and_wait_mutant_not_owned)
{
    HANDLE mut = NULL, ev; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtCreateEvent));
    EXPECT_EQ(UN(NtCreateMutant)(&mut, MUTANT_ALL_ACCESS, NULL, FALSE), 0);
    ev = mk_event(0, TRUE);
    if (mut && ev) EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(mut, ev, FALSE, &t), S(0xc0000046)); /* STATUS_MUTANT_NOT_OWNED */
    if (mut) UN(NtClose)(mut);
    if (ev) UN(NtClose)(ev);
}
TEST(nt_sync_signal_and_wait_owned_mutant_released)
{
    HANDLE mut = NULL, ev; LARGE_INTEGER t = rel_ms(2000);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtCreateEvent));
    EXPECT_EQ(UN(NtCreateMutant)(&mut, MUTANT_ALL_ACCESS, NULL, TRUE), 0);
    ev = mk_event(0, TRUE);
    if (mut && ev) {
        EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(mut, ev, FALSE, &t), 0);
        /* ownership was released, so a second release must fail */
        EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(mut, ev, FALSE, &t), S(0xc0000046));
    }
    if (mut) UN(NtClose)(mut);
    if (ev) UN(NtClose)(ev);
}
TEST(nt_sync_signal_and_wait_invalid_objects)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, TRUE); if (!ev) return;
    EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(NULL, ev, FALSE, &t), STATUS_BAD_HANDLE);
    EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(ev, NULL, FALSE, &t), STATUS_BAD_HANDLE);
    /* a process pseudo-handle is not a signalable object type */
    EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)((HANDLE)(LONG_PTR)-1, ev, FALSE, &t), TYPE_MISMATCH);
    UN(NtClose)(ev);
}
TEST(nt_sync_signal_and_wait_signal_needs_modify_right)
{
    HANDLE a, b, d = NULL; LARGE_INTEGER t = rel_ms(10);
    REQUIRE(UN(NtSignalAndWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    a = mk_event(0, FALSE); b = mk_event(0, TRUE);
    if (a && b && DuplicateHandle(GetCurrentProcess(), a, GetCurrentProcess(), &d, SYNCHRONIZE | EVENT_QUERY_STATE, FALSE, 0)) {
        EXPECT_EQ(UN(NtSignalAndWaitForSingleObject)(d, b, FALSE, &t), S(0xc0000022));
        CloseHandle(d);
    }
    if (a) UN(NtClose)(a);
    if (b) UN(NtClose)(b);
}

/* ---------------- NtDelayExecution ---------------- */
TEST(nt_sync_delay_relative_elapses)
{
    LARGE_INTEGER t = rel_ms(60); DWORD t0, t1;
    REQUIRE(UN(NtDelayExecution));
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &t), 0);
    t1 = GetTickCount();
    CHECK(t1 - t0 >= 40);   /* clock granularity allowance */
    CHECK(t1 - t0 < 5000);
}
TEST(nt_sync_delay_zero_returns)
{
    LARGE_INTEGER t; DWORD t0, t1;
    REQUIRE(UN(NtDelayExecution));
    t.QuadPart = 0;
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &t), 0);
    t1 = GetTickCount();
    CHECK(t1 - t0 < 1000);
}
TEST(nt_sync_delay_absolute_past_returns)
{
    LARGE_INTEGER t; DWORD t0, t1;
    REQUIRE(UN(NtDelayExecution));
    t.QuadPart = 1; /* positive values are absolute system times; this one is long past */
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &t), 0);
    t1 = GetTickCount();
    CHECK(t1 - t0 < 1000);
}
TEST(nt_sync_delay_absolute_future)
{
    FILETIME ft; LARGE_INTEGER t; DWORD t0, t1;
    REQUIRE(UN(NtDelayExecution));
    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime; t.HighPart = ft.dwHighDateTime;
    t.QuadPart += 600000; /* 60 ms ahead */
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &t), 0);
    t1 = GetTickCount();
    CHECK(t1 - t0 >= 30);
    CHECK(t1 - t0 < 5000);
}

/* ---------------- alerts and user APCs ---------------- */
static volatile LONG apc_runs;
static volatile ULONG_PTR apc_args[3];
static void NTAPI apc_routine(PVOID a, PVOID b, PVOID c)
{
    apc_args[0] = (ULONG_PTR)a; apc_args[1] = (ULONG_PTR)b; apc_args[2] = (ULONG_PTR)c;
    InterlockedIncrement(&apc_runs);
}
TEST(nt_sync_apc_runs_on_test_alert)
{
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtTestAlert));
    apc_runs = 0;
    EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)0x11, (PVOID)0x22, (PVOID)0x33), 0);
    EXPECT_EQ(apc_runs, 0); /* delivery waits for an alertable point */
    UN(NtTestAlert)();
    EXPECT_EQ(apc_runs, 1);
    EXPECT_EQ(apc_args[0], 0x11);
    EXPECT_EQ(apc_args[1], 0x22);
    EXPECT_EQ(apc_args[2], 0x33);
    UN(NtTestAlert)();
    EXPECT_EQ(apc_runs, 1); /* delivered exactly once */
}
TEST(nt_sync_apc_runs_in_queue_order)
{
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtTestAlert));
    apc_runs = 0;
    for (ULONG_PTR i = 1; i <= 3; i++) EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)i, 0, 0), 0);
    UN(NtTestAlert)();
    EXPECT_EQ(apc_runs, 3);
    EXPECT_EQ(apc_args[0], 3); /* the last argument seen belongs to the last APC */
}
TEST(nt_sync_apc_alertable_wait_returns_user_apc)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, FALSE); if (!ev) return;
    apc_runs = 0;
    EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)1, 0, 0), 0);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, TRUE, &t), USER_APC);
    EXPECT_EQ(apc_runs, 1);
    UN(NtClose)(ev);
}
TEST(nt_sync_apc_nonalertable_wait_defers)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(40);
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtTestAlert));
    ev = mk_event(0, FALSE); if (!ev) return;
    apc_runs = 0;
    EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)1, 0, 0), 0);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, FALSE, &t), TIMEOUT);
    EXPECT_EQ(apc_runs, 0);
    UN(NtTestAlert)();
    EXPECT_EQ(apc_runs, 1);
    UN(NtClose)(ev);
}
TEST(nt_sync_apc_alertable_delay_returns_user_apc)
{
    LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtDelayExecution));
    apc_runs = 0;
    EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)1, 0, 0), 0);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &t), USER_APC);
    EXPECT_EQ(apc_runs, 1);
}
TEST(nt_sync_apc_pending_apc_wins_over_signaled_object)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtTestAlert));
    ev = mk_event(0, TRUE); if (!ev) return;
    apc_runs = 0;
    EXPECT_EQ(UN(NtQueueApcThread)(SELF_THREAD, (PVOID)apc_routine, (PVOID)1, 0, 0), 0);
    /* An alertable wait delivers a pending user APC even when the object is already signaled. */
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, TRUE, &t), USER_APC);
    EXPECT_EQ(apc_runs, 1);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, TRUE, &t), 0);      /* the signaled object then satisfies the wait */
    UN(NtTestAlert)();
    UN(NtClose)(ev);
}
TEST(nt_sync_alert_wakes_alertable_wait)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(NtAlertThread)); REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, FALSE); if (!ev) return;
    EXPECT_EQ(UN(NtAlertThread)(SELF_THREAD), 0);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, TRUE, &t), ALERTED);
    t = rel_ms(30);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, TRUE, &t), TIMEOUT); /* the alert was consumed */
    UN(NtClose)(ev);
}
TEST(nt_sync_alert_ignored_by_nonalertable_wait)
{
    HANDLE ev; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(UN(NtAlertThread)); REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtTestAlert));
    ev = mk_event(0, FALSE); if (!ev) return;
    EXPECT_EQ(UN(NtAlertThread)(SELF_THREAD), 0);
    EXPECT_EQ(UN(NtWaitForSingleObject)(ev, FALSE, &t), TIMEOUT);
    EXPECT_EQ(UN(NtTestAlert)(), ALERTED); /* still pending; NtTestAlert reports and clears it */
    EXPECT_EQ(UN(NtTestAlert)(), 0);
    UN(NtClose)(ev);
}
TEST(nt_sync_alert_wakes_alertable_delay)
{
    LARGE_INTEGER t = rel_ms(5000);
    REQUIRE(UN(NtAlertThread)); REQUIRE(UN(NtDelayExecution));
    EXPECT_EQ(UN(NtAlertThread)(SELF_THREAD), 0);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &t), ALERTED);
}
TEST(nt_sync_alert_invalid_handle_and_type)
{
    HANDLE ev;
    REQUIRE(UN(NtAlertThread)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, FALSE); if (!ev) return;
    EXPECT_EQ(UN(NtAlertThread)(ev), TYPE_MISMATCH);
    UN(NtClose)(ev);
    EXPECT_EQ(UN(NtAlertThread)(ev), STATUS_BAD_HANDLE);
}
TEST(nt_sync_queue_apc_invalid_handle)
{
    HANDLE ev;
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtCreateEvent));
    ev = mk_event(0, FALSE); if (!ev) return;
    EXPECT_EQ(UN(NtQueueApcThread)(ev, (PVOID)apc_routine, 0, 0, 0), TYPE_MISMATCH);
    UN(NtClose)(ev);
    EXPECT_EQ(UN(NtQueueApcThread)(ev, (PVOID)apc_routine, 0, 0, 0), STATUS_BAD_HANDLE);
}
TEST(nt_sync_yield_execution_status)
{
    NTSTATUS s;
    REQUIRE(UN(NtYieldExecution));
    s = UN(NtYieldExecution)();
    CHECK(s == 0 || s == S(0x40000024));
}
