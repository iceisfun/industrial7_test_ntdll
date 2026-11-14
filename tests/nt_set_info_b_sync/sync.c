/* NtSetEvent, NtSetEventBoostPriority, event-pair setters, NtSetTimer/Ex/2, NtSetIRTimer,
 * NtSetTimerResolution, NtSetThreadExecutionState, NtSetWnfProcessNotificationEvent.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtSetEventBoostPriority, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetHighWaitLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtSetLowWaitHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtWaitHighEventPair, (HANDLE));
UDECL(NTSTATUS, NtWaitLowEventPair, (HANDLE));
UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtSetTimer, (HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN));
UDECL(NTSTATUS, NtSetTimerEx, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetTimer2, (HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, NtCancelTimer, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, NtQueryTimer, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateIRTimer, (PHANDLE, PVOID, ACCESS_MASK));
UDECL(NTSTATUS, NtSetIRTimer, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtSetTimerResolution, (ULONG, BOOLEAN, PULONG));
UDECL(NTSTATUS, NtQueryTimerResolution, (PULONG, PULONG, PULONG));
UDECL(NTSTATUS, NtSetThreadExecutionState, (ULONG, PULONG));
UDECL(NTSTATUS, NtSetWnfProcessNotificationEvent, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE S(0xC0000008)
#define ST_TYPE_MISM  S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_AV         S(0xC0000005)

typedef struct { ULONG Type; LONG State; } EVT_BASIC;
typedef struct { LARGE_INTEGER Remaining; BOOLEAN State; } TMR_BASIC;
typedef struct {
    LARGE_INTEGER DueTime; PVOID Routine; PVOID Context; PVOID WakeContext;
    ULONG Period; ULONG Tolerable; PBOOLEAN Prev;
} TMR_COAL;

static HANDLE mkevent(ULONG type, BOOLEAN initial)
{
    HANDLE h = NULL;
    if (UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, type, initial) != 0) return NULL;
    return h;
}
static LONG evstate(HANDLE h)
{
    EVT_BASIC b = { 9, 9 }; ULONG rl = 0;
    if (UN(NtQueryEvent)(h, 0, &b, sizeof b, &rl) != 0) return -99;
    return b.State;
}
static HANDLE reduced(HANDLE h, DWORD access)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, FALSE, 0)) return NULL;
    return d;
}

/* ---- events ----------------------------------------------------------- */
TEST(set_event_basic)
{
    REQUIRE(UN(NtSetEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtQueryEvent));
    HANDLE ev = mkevent(0 /*notification*/, FALSE);
    CHECK(ev != NULL); if (!ev) return;
    LONG prev = 0x55;
    EXPECT_EQ(UN(NtSetEvent)(ev, &prev), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(evstate(ev), 1);
    prev = 0x55;
    EXPECT_EQ(UN(NtSetEvent)(ev, &prev), 0);
    EXPECT_EQ(prev, 1);
    EXPECT_EQ(UN(NtSetEvent)(ev, NULL), 0);   /* PreviousState is optional */
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    EXPECT_EQ(evstate(ev), 1);                /* notification: stays signaled */
    UN(NtClose)(ev);
}
TEST(set_event_autoreset)
{
    REQUIRE(UN(NtSetEvent));
    HANDLE ev = mkevent(1 /*synchronization*/, FALSE);
    CHECK(ev != NULL); if (!ev) return;
    LONG prev = 7;
    EXPECT_EQ(UN(NtSetEvent)(ev, &prev), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);   /* consumed */
    EXPECT_EQ(evstate(ev), 0);
    UN(NtClose)(ev);
}
TEST(set_event_errors)
{
    REQUIRE(UN(NtSetEvent));
    LONG prev = 0x55;
    EXPECT_EQ(UN(NtSetEvent)(NULL, &prev), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetEvent)((HANDLE)(LONG_PTR)-1, &prev), ST_TYPE_MISM);  /* current process pseudo-handle */
    EXPECT_EQ(UN(NtSetEvent)((HANDLE)(LONG_PTR)0x7ff0, &prev), ST_INV_HANDLE);
    HANDLE mtx = CreateMutexW(NULL, FALSE, NULL);
    EXPECT_EQ(UN(NtSetEvent)(mtx, &prev), ST_TYPE_MISM);
    CloseHandle(mtx);
    HANDLE ev = mkevent(0, FALSE);
    CHECK(ev != NULL); if (!ev) return;
    HANDLE ro = reduced(ev, SYNCHRONIZE);
    CHECK(ro != NULL);
    if (ro) {
        EXPECT_EQ(UN(NtSetEvent)(ro, &prev), ST_DENIED);
        EXPECT_EQ(evstate(ev), 0);
        CloseHandle(ro);
    }
    HANDLE ms = reduced(ev, EVENT_MODIFY_STATE);
    if (ms) { EXPECT_EQ(UN(NtSetEvent)(ms, &prev), 0); CloseHandle(ms); EXPECT_EQ(evstate(ev), 1); }
    EXPECT_EQ(UN(NtSetEvent)(ev, (PLONG)(ULONG_PTR)8), ST_AV);   /* unwritable PreviousState */
    UN(NtClose)(ev);
    /* alias */
    CHECK(t_proc("NtSetEvent") == t_proc("ZwSetEvent"));
}
TEST(set_event_boost)
{
    REQUIRE(UN(NtSetEventBoostPriority)); REQUIRE(UN(NtCreateEvent));
    CHECK(t_proc("NtSetEventBoostPriority") == t_proc("ZwSetEventBoostPriority"));
    HANDLE ev = mkevent(1 /*sync*/, FALSE);
    CHECK(ev != NULL); if (!ev) return;
    EXPECT_EQ(UN(NtSetEventBoostPriority)(ev), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    HANDLE ro = reduced(ev, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetEventBoostPriority)(ro), ST_DENIED); CloseHandle(ro); }
    UN(NtClose)(ev);
    HANDLE nev = mkevent(0 /*notification*/, FALSE);
    if (nev) {
        NTSTATUS st = UN(NtSetEventBoostPriority)(nev);
        EXPECT_EQ(st, ST_TYPE_MISM);               /* only synchronization events are accepted */
        EXPECT_EQ(evstate(nev), 0);
        UN(NtClose)(nev);
    }
    EXPECT_EQ(UN(NtSetEventBoostPriority)(NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetEventBoostPriority)((HANDLE)(LONG_PTR)-2), ST_TYPE_MISM);
}

/* ---- event pairs ------------------------------------------------------ */
/* Event pairs were removed from Windows 10: every entry point (including creation) reports
 * STATUS_NOT_IMPLEMENTED before looking at its argument. */
TEST(event_pair_not_implemented)
{
    static const char *n[] = { "NtSetHighEventPair", "NtSetLowEventPair", "NtSetHighWaitLowEventPair", "NtSetLowWaitHighEventPair" };
    HANDLE ev = mkevent(0, FALSE);
    CHECK(ev != NULL);
    for (int i = 0; i < 4; i++) {
        char zn[64]; snprintf(zn, sizeof zn, "Zw%s", n[i] + 2);
        NTSTATUS (WINAPI *f)(HANDLE) = (void *)t_proc(n[i]);
        if (!f) { t_skip("missing export %s", n[i]); continue; }
        CHECK(t_proc(zn) == (FARPROC)f);
        EXPECT_EQ(f(NULL), S(0xC0000002));
        EXPECT_EQ(f(ev), S(0xC0000002));
        EXPECT_EQ(f((HANDLE)(LONG_PTR)-1), S(0xC0000002));
    }
    HANDLE ep = NULL;
    if (UN(NtCreateEventPair)) EXPECT_EQ(UN(NtCreateEventPair)(&ep, EVENT_ALL_ACCESS, NULL), S(0xC0000002));
    if (ep) UN(NtClose)(ep);
    if (ev) UN(NtClose)(ev);
}

/* ---- timers ----------------------------------------------------------- */
static HANDLE mktimer(ULONG type)
{
    HANDLE h = NULL;
    if (UN(NtCreateTimer)(&h, TIMER_ALL_ACCESS, NULL, type) != 0) return NULL;
    return h;
}
TEST(set_timer_basic)
{
    REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtQueryTimer)); REQUIRE(UN(NtCancelTimer));
    CHECK(t_proc("NtSetTimer") == t_proc("ZwSetTimer"));
    HANDLE tm = mktimer(0 /*notification*/);
    CHECK(tm != NULL); if (!tm) return;
    LARGE_INTEGER due; BOOLEAN prev = 9;
    due.QuadPart = -1000LL * 10000 * 100;                       /* 100 s relative */
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, 0, &prev), 0);
    EXPECT_EQ(prev, 0);
    TMR_BASIC b; ULONG rl = 0;
    EXPECT_EQ(UN(NtQueryTimer)(tm, 0, &b, sizeof b, &rl), 0);
    EXPECT_EQ(b.State, 0);
    CHECK(b.Remaining.QuadPart > 0 && b.Remaining.QuadPart <= 100LL * 10000000);
    prev = 9;
    due.QuadPart = -500000;                                     /* 50 ms; re-arm */
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, 0, &prev), 0);
    EXPECT_EQ(prev, 0);                                         /* PreviousState is the old signal state, not "was armed" */
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    prev = 9;
    due.QuadPart = -1000LL * 10000 * 100;
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, 0, &prev), 0);
    EXPECT_EQ(prev, 1);                                         /* it was signaled */
    EXPECT_EQ(WaitForSingleObject(tm, 0), WAIT_TIMEOUT);        /* re-arming clears the signal */
    prev = 9;
    EXPECT_EQ(UN(NtCancelTimer)(tm, &prev), 0);
    EXPECT_EQ(prev, 0);                                         /* armed, not signaled */
    /* absolute time in the past fires at once */
    LARGE_INTEGER now; FILETIME ft; GetSystemTimeAsFileTime(&ft);
    now.LowPart = ft.dwLowDateTime; now.HighPart = ft.dwHighDateTime;
    due.QuadPart = now.QuadPart - 10000000;
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, 0, NULL), 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    UN(NtClose)(tm);
}
TEST(set_timer_periodic_sync)
{
    REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCreateTimer));
    HANDLE tm = mktimer(1 /*synchronization*/);
    CHECK(tm != NULL); if (!tm) return;
    LARGE_INTEGER due; due.QuadPart = -300000;                  /* 30 ms */
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, 40, NULL), 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);    /* periodic: fires again */
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    UN(NtCancelTimer)(tm, NULL);
    EXPECT_EQ(WaitForSingleObject(tm, 200), WAIT_TIMEOUT);
    UN(NtClose)(tm);
}
TEST(set_timer_errors)
{
    REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCreateTimer));
    LARGE_INTEGER due; due.QuadPart = -100000000LL; BOOLEAN prev;
    EXPECT_EQ(UN(NtSetTimer)(NULL, &due, NULL, NULL, FALSE, 0, &prev), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetTimer)((HANDLE)(LONG_PTR)-1, &due, NULL, NULL, FALSE, 0, &prev), ST_TYPE_MISM);
    HANDLE ev = mkevent(0, FALSE);
    if (ev) { EXPECT_EQ(UN(NtSetTimer)(ev, &due, NULL, NULL, FALSE, 0, &prev), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE tm = mktimer(0);
    CHECK(tm != NULL); if (!tm) return;
    EXPECT_EQ(UN(NtSetTimer)(tm, &due, NULL, NULL, FALSE, -1, &prev), S(0xC00000F4));    /* negative period: STATUS_INVALID_PARAMETER_6 */
    EXPECT_EQ(UN(NtSetTimer)(tm, NULL, NULL, NULL, FALSE, 0, &prev), ST_AV);
    HANDLE ro = reduced(tm, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetTimer)(ro, &due, NULL, NULL, FALSE, 0, &prev), ST_DENIED); CloseHandle(ro); }
    TMR_BASIC b; ULONG rl;
    EXPECT_EQ(UN(NtQueryTimer)(tm, 0, &b, sizeof b, &rl), 0);
    EXPECT_EQ(b.State, 0);
    UN(NtClose)(tm);
}
TEST(set_timer_ex)
{
    REQUIRE(UN(NtSetTimerEx)); REQUIRE(UN(NtCreateTimer));
    CHECK(t_proc("NtSetTimerEx") == t_proc("ZwSetTimerEx"));
    HANDLE tm = mktimer(0);
    CHECK(tm != NULL); if (!tm) return;
    BOOLEAN prev = 9;
    TMR_COAL c; memset(&c, 0, sizeof c);
    c.DueTime.QuadPart = -1000000000LL; c.Prev = &prev;
    NTSTATUS st = UN(NtSetTimerEx)(tm, 0, &c, sizeof c);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(prev, 0);
    c.DueTime.QuadPart = -300000; prev = 9; c.Tolerable = 10;
    EXPECT_EQ(UN(NtSetTimerEx)(tm, 0, &c, sizeof c), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    prev = 9;
    EXPECT_EQ(UN(NtSetTimerEx)(tm, 0, &c, sizeof c), 0);
    EXPECT_EQ(prev, 1);                                         /* previous signal state */
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(NtSetTimerEx)(tm, 0, &c, sizeof c - 8), S(0xC0000004));   /* STATUS_INFO_LENGTH_MISMATCH */
    EXPECT_EQ(UN(NtSetTimerEx)(tm, 0x7fff, &c, sizeof c), S(0xC0000003));  /* STATUS_INVALID_INFO_CLASS */
    EXPECT_EQ(UN(NtSetTimerEx)(NULL, 0, &c, sizeof c), ST_INV_HANDLE);
    HANDLE ev = mkevent(0, FALSE);
    if (ev) { EXPECT_EQ(UN(NtSetTimerEx)(ev, 0, &c, sizeof c), ST_TYPE_MISM); UN(NtClose)(ev); }
    UN(NtCancelTimer)(tm, NULL);
    UN(NtClose)(tm);
}
TEST(set_timer2)
{
    REQUIRE(UN(NtSetTimer2));
    CHECK(t_proc("NtSetTimer2") == t_proc("ZwSetTimer2"));
    HANDLE tm = CreateWaitableTimerExW(NULL, NULL, 2 /*HIGH_RESOLUTION*/, TIMER_ALL_ACCESS);
    if (!tm) { t_skip("CreateWaitableTimerExW failed %lu", GetLastError()); return; }
    LARGE_INTEGER due; due.QuadPart = -300000;
    EXPECT_EQ(UN(NtSetTimer2)(tm, &due, NULL, NULL), 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    LARGE_INTEGER period; period.QuadPart = 400000;   /* positive 100ns units? see EVIDENCE */
    due.QuadPart = -300000;
    NTSTATUS st = UN(NtSetTimer2)(tm, &due, &period, NULL);
    t_note("NtSetTimer2 with period: %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    CancelWaitableTimer(tm);
    EXPECT_EQ(UN(NtSetTimer2)(NULL, &due, NULL, NULL), ST_INV_HANDLE);
    HANDLE ev = mkevent(0, FALSE);
    if (ev) { EXPECT_EQ(UN(NtSetTimer2)(ev, &due, NULL, NULL), ST_TYPE_MISM); UN(NtClose)(ev); }
    CloseHandle(tm);
}
TEST(set_ir_timer)
{
    REQUIRE(UN(NtSetIRTimer));
    CHECK(t_proc("NtSetIRTimer") == t_proc("ZwSetIRTimer"));
    /* A high-resolution waitable timer is a Timer2 object; NtSetIRTimer arms it like NtSetTimer2 with no period. */
    HANDLE tm = CreateWaitableTimerExW(NULL, NULL, 2 /*HIGH_RESOLUTION*/, TIMER_ALL_ACCESS);
    if (!tm) { t_skip("high-resolution waitable timer unavailable: %lu", GetLastError()); return; }
    LARGE_INTEGER due; due.QuadPart = -300000;
    EXPECT_EQ(UN(NtSetIRTimer)(tm, &due), 0);
    EXPECT_EQ(WaitForSingleObject(tm, 5000), WAIT_OBJECT_0);
    due.QuadPart = -1000000000LL;
    EXPECT_EQ(UN(NtSetIRTimer)(tm, &due), 0);
    EXPECT_EQ(WaitForSingleObject(tm, 100), WAIT_TIMEOUT);
    CancelWaitableTimer(tm);
    EXPECT_EQ(UN(NtSetIRTimer)(NULL, &due), ST_INV_HANDLE);
    HANDLE ev = mkevent(0, FALSE);
    if (ev) { EXPECT_EQ(UN(NtSetIRTimer)(ev, &due), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = reduced(tm, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetIRTimer)(ro, &due), ST_DENIED); CloseHandle(ro); }
    CloseHandle(tm);
}

/* ---- timer resolution ------------------------------------------------- */
TEST(set_timer_resolution)
{
    REQUIRE(UN(NtSetTimerResolution)); REQUIRE(UN(NtQueryTimerResolution));
    CHECK(t_proc("NtSetTimerResolution") == t_proc("ZwSetTimerResolution"));
    ULONG mn = 0, mx = 0, cur = 0, act = 0;
    EXPECT_EQ(UN(NtQueryTimerResolution)(&mn, &mx, &cur), 0);
    CHECK(mx > 0 && mx <= mn);
    /* Removing a request that was never made. */
    EXPECT_EQ(UN(NtSetTimerResolution)(0, FALSE, &act), S(0xC0000245));   /* STATUS_TIMER_RESOLUTION_NOT_SET */
    act = 0;
    EXPECT_EQ(UN(NtSetTimerResolution)(50000, TRUE, &act), 0);    /* 5 ms */
    CHECK(act > 0 && act <= 50000 && act >= mx);
    EXPECT_EQ(UN(NtQueryTimerResolution)(&mn, &mx, &cur), 0);
    CHECK(cur <= 50000);
    EXPECT_EQ(UN(NtSetTimerResolution)(50000, TRUE, &act), 0);    /* repeated request is idempotent */
    act = 0;
    EXPECT_EQ(UN(NtSetTimerResolution)(0, FALSE, &act), 0);
    CHECK(act > 0);
    EXPECT_EQ(UN(NtSetTimerResolution)(0, FALSE, &act), S(0xC0000245));
    /* requests outside the supported range are clamped */
    act = 0;
    EXPECT_EQ(UN(NtSetTimerResolution)(1, TRUE, &act), 0);
    CHECK(act >= mx);
    UN(NtSetTimerResolution)(0, FALSE, &act);
}

/* ---- thread execution state ------------------------------------------- */
typedef struct { NTSTATUS st[8]; ULONG prev[8]; } ES_RES;
static DWORD WINAPI es_thread(LPVOID p)
{
    ES_RES *r = p;
    ULONG ES_CONT = 0x80000000u, ES_SYS = 1, ES_DISP = 2;
    r->prev[0] = 0xdeadbeef; r->st[0] = UN(NtSetThreadExecutionState)(ES_CONT | ES_SYS, &r->prev[0]);
    r->prev[1] = 0xdeadbeef; r->st[1] = UN(NtSetThreadExecutionState)(ES_CONT | ES_DISP, &r->prev[1]);
    r->prev[2] = 0xdeadbeef; r->st[2] = UN(NtSetThreadExecutionState)(ES_CONT, &r->prev[2]);
    r->prev[3] = 0xdeadbeef; r->st[3] = UN(NtSetThreadExecutionState)(ES_CONT, &r->prev[3]);
    r->prev[4] = 0xdeadbeef; r->st[4] = UN(NtSetThreadExecutionState)(0x40000000u, &r->prev[4]);
    return 0;
}
TEST(set_thread_execution_state)
{
    REQUIRE(UN(NtSetThreadExecutionState));
    CHECK(t_proc("NtSetThreadExecutionState") == t_proc("ZwSetThreadExecutionState"));
    ES_RES r; memset(&r, 0, sizeof r);
    HANDLE t = CreateThread(NULL, 0, es_thread, &r, 0, NULL);
    CHECK(t != NULL); if (!t) return;
    WaitForSingleObject(t, 10000); CloseHandle(t);
    EXPECT_EQ(r.st[0], 0);
    EXPECT_EQ(r.prev[0], 0x80000000u);                  /* initial state of a new thread */
    EXPECT_EQ(r.st[1], 0);
    EXPECT_EQ(r.prev[1], 0x80000001u);
    EXPECT_EQ(r.st[2], 0);
    EXPECT_EQ(r.prev[2], 0x80000002u);
    EXPECT_EQ(r.st[3], 0);
    EXPECT_EQ(r.prev[3], 0x80000000u);
    EXPECT_EQ(r.st[4], ST_INV_PARAM);                   /* invalid flag bits */
}
/* ---- WNF process notification event ----------------------------------- */
TEST(set_wnf_process_notification_event)
{
    REQUIRE(UN(NtSetWnfProcessNotificationEvent));
    CHECK(t_proc("NtSetWnfProcessNotificationEvent") == t_proc("ZwSetWnfProcessNotificationEvent"));
    HANDLE ev = mkevent(0, FALSE);
    CHECK(ev != NULL); if (!ev) return;
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)(ev), 0);
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)(NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)((HANDLE)(LONG_PTR)0x7ff0), ST_INV_HANDLE);
    HANDLE mtx = CreateMutexW(NULL, FALSE, NULL);
    EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)(mtx), ST_TYPE_MISM);
    CloseHandle(mtx);
    HANDLE ro = reduced(ev, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetWnfProcessNotificationEvent)(ro), ST_DENIED); CloseHandle(ro); }
    UN(NtClose)(ev);
}
