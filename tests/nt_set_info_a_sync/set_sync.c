/* Timer, event and notification setters: NtSetTimerEx, NtSetTimer2, NtSetIRTimer, NtSetTimerResolution,
 * NtSetEventBoostPriority, the event-pair setters and NtSetWnfProcessNotificationEvent.
 *
 * Every wait uses a bounded timeout. Handles created by a test are closed by that test.
 */
#include "t.h"

UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCreateTimer2, (PHANDLE, PVOID, PVOID, ULONG, ACCESS_MASK));
UDECL(NTSTATUS, NtCreateIRTimer, (PHANDLE, PVOID, ACCESS_MASK));
UDECL(NTSTATUS, NtSetTimerEx, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetTimer2, (HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, NtSetIRTimer, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtSetTimerResolution, (ULONG, BOOLEAN, PULONG));
UDECL(NTSTATUS, NtSetEventBoostPriority, (HANDLE));
UDECL(NTSTATUS, NtSetLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetLowWaitHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetHighWaitLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetWnfProcessNotificationEvent, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_NOT_IMPL     S(0xC0000002)
#define ST_PARAM2       S(0xC00000F0)
#define ST_PARAM3       S(0xC00000F1)

/* TIMER_SET_COALESCING_INFO as consumed by NtSetTimerEx class 0 (TimerSetCoalescedTimer) */
typedef struct {
    PLARGE_INTEGER DueTime;
    PVOID          ApcRoutine;
    PVOID          ApcContext;
    PVOID          WakeContext;
    ULONG          Period;
    ULONG          TolerableDelay;
    PBOOLEAN       PreviousState;
} setex_info;

static volatile LONG g_apc_hits;
static volatile ULONG_PTR g_apc_ctx;
static VOID NTAPI apc_cb(PVOID ctx, ULONG lo, LONG hi) { g_apc_ctx = (ULONG_PTR)ctx; InterlockedIncrement(&g_apc_hits); }

TEST(set_sync_alias_pairs)
{
    EXPECT_EQ(t_proc("NtSetTimerEx"), t_proc("ZwSetTimerEx"));
    EXPECT_EQ(t_proc("NtSetTimer2"), t_proc("ZwSetTimer2"));
    EXPECT_EQ(t_proc("NtSetIRTimer"), t_proc("ZwSetIRTimer"));
    EXPECT_EQ(t_proc("NtSetTimerResolution"), t_proc("ZwSetTimerResolution"));
    EXPECT_EQ(t_proc("NtSetEventBoostPriority"), t_proc("ZwSetEventBoostPriority"));
    EXPECT_EQ(t_proc("NtSetLowEventPair"), t_proc("ZwSetLowEventPair"));
    EXPECT_EQ(t_proc("NtSetHighEventPair"), t_proc("ZwSetHighEventPair"));
    EXPECT_EQ(t_proc("NtSetLowWaitHighEventPair"), t_proc("ZwSetLowWaitHighEventPair"));
    EXPECT_EQ(t_proc("NtSetHighWaitLowEventPair"), t_proc("ZwSetHighWaitLowEventPair"));
    EXPECT_EQ(t_proc("NtSetWnfProcessNotificationEvent"), t_proc("ZwSetWnfProcessNotificationEvent"));
}

TEST(set_timer_ex_coalescing)
{
    HANDLE t = NULL; LARGE_INTEGER due; BOOLEAN prev = 0xAA; setex_info in; NTSTATUS st;
    REQUIRE(UN(NtSetTimerEx)); REQUIRE(UN(NtCreateTimer));
    EXPECT_EQ(UN(NtCreateTimer)(&t, TIMER_ALL_ACCESS, NULL, 1 /* SynchronizationTimer */), 0);
    if (!t) return;
    memset(&in, 0, sizeof in);
    due.QuadPart = -200000;                       /* 20 ms relative */
    in.DueTime = &due; in.PreviousState = &prev; in.TolerableDelay = 0;
    st = UN(NtSetTimerEx)(t, 0, &in, sizeof in);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(WaitForSingleObject(t, 5000), WAIT_OBJECT_0);
    /* re-arming a timer succeeds (the reported previous state is observed to vary, so it is not asserted) */
    due.QuadPart = -600000000;                    /* 60 s, will be cancelled */
    prev = 0xAA;
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, sizeof in), 0);
    CHECK(prev == 0 || prev == 1);
    prev = 0xAA;
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, sizeof in), 0);
    CHECK(prev == 0 || prev == 1);
    CHECK(CancelWaitableTimer(t));
    /* error paths */
    EXPECT_EQ(UN(NtSetTimerEx)(t, 1, &in, sizeof in), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, sizeof in - 8), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, 0x38), ST_BAD_LENGTH);
    in.Period = 0x80000000u;
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, sizeof in), ST_PARAM3);
    in.Period = 0;
    EXPECT_EQ(UN(NtSetTimerEx)((HANDLE)(ULONG_PTR)0xdeadbee4, 0, &in, sizeof in), ST_INV_HANDLE);
    UN(NtClose) ? UN(NtClose)(t) : (void)CloseHandle(t);
}

TEST(set_timer_ex_apc_and_period)
{
    HANDLE t = NULL; LARGE_INTEGER due; setex_info in; DWORD r; int i;
    REQUIRE(UN(NtSetTimerEx)); REQUIRE(UN(NtCreateTimer));
    EXPECT_EQ(UN(NtCreateTimer)(&t, TIMER_ALL_ACCESS, NULL, 0 /* NotificationTimer */), 0);
    if (!t) return;
    memset(&in, 0, sizeof in);
    g_apc_hits = 0; g_apc_ctx = 0;
    due.QuadPart = -100000;                       /* 10 ms */
    in.DueTime = &due; in.ApcRoutine = (PVOID)apc_cb; in.ApcContext = (PVOID)(ULONG_PTR)0xC0DE; in.Period = 20;
    EXPECT_EQ(UN(NtSetTimerEx)(t, 0, &in, sizeof in), 0);
    for (i = 0; i < 100 && g_apc_hits < 2; i++) { r = SleepEx(50, TRUE); (void)r; }
    CHECK(g_apc_hits >= 2);                       /* periodic: the APC is queued repeatedly */
    EXPECT_EQ(g_apc_ctx, 0xC0DE);
    CHECK(CancelWaitableTimer(t));
    CloseHandle(t);
}

TEST(set_timer_ex_wrong_object_type)
{
    HANDLE e; setex_info in; LARGE_INTEGER due;
    REQUIRE(UN(NtSetTimerEx));
    e = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(e != NULL); if (!e) return;
    memset(&in, 0, sizeof in); due.QuadPart = -10000000; in.DueTime = &due;
    EXPECT_EQ(UN(NtSetTimerEx)(e, 0, &in, sizeof in), ST_TYPE_MISM);
    CloseHandle(e);
}

TEST(set_timer2_and_ir_timer)
{
    HANDLE t = NULL, ir = NULL; LARGE_INTEGER due; NTSTATUS st; int i;
    REQUIRE(UN(NtSetTimer2)); REQUIRE(UN(NtSetIRTimer));
    /* a NULL due-time pointer is rejected before the handle is looked at */
    EXPECT_EQ(UN(NtSetTimer2)((HANDLE)(ULONG_PTR)0xdeadbee4, NULL, NULL, NULL), ST_PARAM2);
    EXPECT_EQ(UN(NtSetTimer2)(NULL, NULL, NULL, NULL), ST_PARAM2);
    due.QuadPart = -100000;
    EXPECT_EQ(UN(NtSetTimer2)((HANDLE)(ULONG_PTR)0xdeadbee4, &due, NULL, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetIRTimer)((HANDLE)(ULONG_PTR)0xdeadbee4, &due), ST_INV_HANDLE);
    if (!UN(NtCreateTimer2)) { t_skip("NtCreateTimer2 not available"); return; }
    st = UN(NtCreateTimer2)(&t, NULL, NULL, 0, TIMER_ALL_ACCESS);
    EXPECT_EQ(st, 0);
    if (st == 0 && t) {
        due.QuadPart = -200000;
        EXPECT_EQ(UN(NtSetTimer2)(t, &due, NULL, NULL), 0);
        EXPECT_EQ(WaitForSingleObject(t, 5000), WAIT_OBJECT_0);
        CloseHandle(t);
    }
    /* NtSetIRTimer arms a timer2 object the same way (no period, no parameters) */
    st = UN(NtCreateTimer2)(&t, NULL, NULL, 0, TIMER_ALL_ACCESS);
    EXPECT_EQ(st, 0);
    if (st == 0 && t) {
        due.QuadPart = -200000;
        EXPECT_EQ(UN(NtSetIRTimer)(t, &due), 0);
        EXPECT_EQ(WaitForSingleObject(t, 5000), WAIT_OBJECT_0);
        CloseHandle(t);
    }
    /* an IR timer cannot be created without a valid timer id */
    if (UN(NtCreateIRTimer)) {
        ir = NULL;
        EXPECT_EQ(UN(NtCreateIRTimer)(&ir, NULL, TIMER_ALL_ACCESS), ST_BAD_PARAM);
        if (ir) CloseHandle(ir);
    }
    (void)i;
}

TEST(set_timer_resolution)
{
    ULONG act = 0, act2 = 0; NTSTATUS st;
    REQUIRE(UN(NtSetTimerResolution));
    st = UN(NtSetTimerResolution)(10000, TRUE, &act);          /* request 1 ms */
    EXPECT_EQ(st, 0);
    CHECK(act != 0 && act <= 156250);
    t_note("NtSetTimerResolution(10000,TRUE): actual=%lu", (unsigned long)act);
    st = UN(NtSetTimerResolution)(10000, FALSE, &act2);        /* withdraw the request */
    EXPECT_EQ(st, 0);
    CHECK(act2 != 0 && act2 <= 156250);
    CHECK(act2 >= act);                                        /* releasing the request cannot improve resolution */
}

TEST(set_event_boost_priority)
{
    HANDLE ev, ne, mx; NTSTATUS st;
    REQUIRE(UN(NtSetEventBoostPriority));
    ev = CreateEventW(NULL, FALSE, FALSE, NULL);               /* auto-reset (SynchronizationEvent) */
    ne = CreateEventW(NULL, TRUE, FALSE, NULL);                /* manual-reset (NotificationEvent) */
    mx = CreateMutexW(NULL, FALSE, NULL);
    CHECK(ev && ne && mx);
    if (ev && ne && mx) {
        st = UN(NtSetEventBoostPriority)(ev);
        t_note("NtSetEventBoostPriority(auto-reset, no waiter) = %08lx, signaled afterwards: %d", (unsigned long)st,
               WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
        EXPECT_EQ(st, 0);
        EXPECT_EQ(UN(NtSetEventBoostPriority)(ne), ST_TYPE_MISM);
        EXPECT_EQ(UN(NtSetEventBoostPriority)(mx), ST_TYPE_MISM);
    }
    EXPECT_EQ(UN(NtSetEventBoostPriority)((HANDLE)(ULONG_PTR)0xdeadbee4), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetEventBoostPriority)(NULL), ST_INV_HANDLE);
    if (ev) CloseHandle(ev);
    if (ne) CloseHandle(ne);
    if (mx) CloseHandle(mx);
}

static DWORD WINAPI waiter(LPVOID p) { return WaitForSingleObject((HANDLE)p, 10000); }

TEST(set_event_boost_priority_wakes_waiter)
{
    HANDLE ev, th; DWORD code = 0xFFFF;
    REQUIRE(UN(NtSetEventBoostPriority));
    ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(ev != NULL); if (!ev) return;
    th = CreateThread(NULL, 0, waiter, ev, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        Sleep(200);                                            /* let the waiter block */
        EXPECT_EQ(UN(NtSetEventBoostPriority)(ev), 0);
        EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
        GetExitCodeThread(th, &code);
        EXPECT_EQ(code, WAIT_OBJECT_0);
        CloseHandle(th);
    }
    CloseHandle(ev);
}

TEST(set_event_pair_services)
{
    HANDLE h = NULL;
    /* the event-pair services are not implemented on Windows 10: every setter fails the same way,
       whatever the handle is */
    REQUIRE(UN(NtSetLowEventPair));
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(NtSetLowEventPair)(h), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetHighEventPair)(h), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetLowWaitHighEventPair)(h), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetHighWaitLowEventPair)(h), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetLowEventPair)(NULL), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetHighWaitLowEventPair)((HANDLE)(ULONG_PTR)0xdeadbee4), ST_NOT_IMPL);
    if (h) CloseHandle(h);
}

TEST(set_wnf_process_notification_event)
{
    HANDLE ev, mx; NTSTATUS st, again;
    REQUIRE(UN(NtSetWnfProcessNotificationEvent));
    ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    mx = CreateMutexW(NULL, FALSE, NULL);
    CHECK(ev && mx); if (!ev || !mx) return;
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)((HANDLE)(ULONG_PTR)0xdeadbee4), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)(mx), ST_TYPE_MISM);
    st = UN(NtSetWnfProcessNotificationEvent)(ev);
    t_note("first NtSetWnfProcessNotificationEvent: %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    /* the process-wide notification event can be installed only once */
    again = UN(NtSetWnfProcessNotificationEvent)(ev);
    EXPECT_EQ(again, S(0xC0000718));
    CloseHandle(mx);
    CloseHandle(ev);
}
