/* PEB lock, SRW wait, resource locks, vectored handlers, timer queues, atom tables and privilege acquisition. */
#include "t.h"

UDECL(VOID, RtlAcquirePebLock, (VOID));
UDECL(VOID, RtlReleasePebLock, (VOID));
UDECL(NTSTATUS, RtlAcquirePrivilege, (PULONG, ULONG, ULONG, PVOID *));
UDECL(VOID, RtlReleasePrivilege, (PVOID));
UDECL(VOID, RtlAcquireReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlInitializeResource, (PVOID));
UDECL(VOID, RtlDeleteResource, (PVOID));
UDECL(BOOLEAN, RtlAcquireResourceExclusive, (PVOID, BOOLEAN));
UDECL(BOOLEAN, RtlAcquireResourceShared, (PVOID, BOOLEAN));
UDECL(VOID, RtlReleaseResource, (PVOID));
UDECL(PVOID, RtlAddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(PVOID, RtlAddVectoredContinueHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(ULONG, RtlRemoveVectoredExceptionHandler, (PVOID));
UDECL(ULONG, RtlRemoveVectoredContinueHandler, (PVOID));
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlCreateTimer, (HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeleteTimer, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
UDECL(VOID, RtlCheckForOrphanedCriticalSections, (HANDLE));
UDECL(NTSTATUS, RtlInitializeCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlDeleteCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlEnterCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlLeaveCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PCWSTR, PUSHORT));
UDECL(NTSTATUS, RtlLookupAtomInAtomTable, (PVOID, PCWSTR, PUSHORT));
UDECL(NTSTATUS, RtlDeleteAtomFromAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlQueryAtomInAtomTable, (PVOID, USHORT, PULONG, PULONG, PWSTR, PULONG));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_INVPARAM     S(0xC000000D)
#define ST_NO_TOKEN     S(0xC000007C)
#define ST_NOT_HELD     S(0xC0000061)
#define ST_NAME_INVALID S(0xC0000033)
#define ST_NOTFOUND     S(0xC0000034)

static BYTE *peb(void) { return (BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock; }

/* ---- PEB lock ---- */
TEST(rtl_acquire_peb_lock) {
    REQUIRE(UN(RtlAcquirePebLock)); REQUIRE(UN(RtlReleasePebLock));
    RTL_CRITICAL_SECTION *cs = *(RTL_CRITICAL_SECTION **)(peb() + 0x38);
    EXPECT_NE(cs, NULL);
    if (!cs) return;
    LONG rc0 = cs->RecursionCount;
    UN(RtlAcquirePebLock)();
    EXPECT_EQ(cs->RecursionCount, rc0 + 1);
    EXPECT_EQ(cs->OwningThread, (HANDLE)(ULONG_PTR)GetCurrentThreadId());
    UN(RtlAcquirePebLock)();                       /* recursive */
    EXPECT_EQ(cs->RecursionCount, rc0 + 2);
    UN(RtlReleasePebLock)();
    EXPECT_EQ(cs->RecursionCount, rc0 + 1);
    UN(RtlReleasePebLock)();
    EXPECT_EQ(cs->RecursionCount, rc0);
}
static volatile LONG g_peb_got;
static DWORD WINAPI peb_thread(LPVOID p) {
    UN(RtlAcquirePebLock)(); g_peb_got = 1; UN(RtlReleasePebLock)(); return 0;
}
TEST(rtl_acquire_peb_lock_excludes_other_thread) {
    REQUIRE(UN(RtlAcquirePebLock)); REQUIRE(UN(RtlReleasePebLock));
    g_peb_got = 0;
    UN(RtlAcquirePebLock)();
    HANDLE th = CreateThread(NULL, 0, peb_thread, NULL, 0, NULL);
    EXPECT_NE(th, NULL);
    if (!th) { UN(RtlReleasePebLock)(); return; }
    Sleep(150);
    EXPECT_EQ(g_peb_got, 0);                       /* blocked while we own the lock */
    UN(RtlReleasePebLock)();
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(g_peb_got, 1);
    CloseHandle(th);
}

/* ---- SRW lock: wait for the lock to become free ---- */
static volatile LONG g_srw_done;
static DWORD WINAPI srw_thread(LPVOID p) { UN(RtlAcquireReleaseSRWLockExclusive)((PRTL_SRWLOCK)p); g_srw_done = 1; return 0; }
TEST(rtl_srw_acquire_release_exclusive) {
    REQUIRE(UN(RtlAcquireReleaseSRWLockExclusive)); REQUIRE(UN(RtlAcquireSRWLockExclusive)); REQUIRE(UN(RtlReleaseSRWLockExclusive));
    REQUIRE(UN(RtlAcquireSRWLockShared)); REQUIRE(UN(RtlReleaseSRWLockShared));
    RTL_SRWLOCK l = RTL_SRWLOCK_INIT;
    /* free lock: returns at once and leaves the lock untouched */
    UN(RtlAcquireReleaseSRWLockExclusive)(&l);
    EXPECT_EQ(l.Ptr, NULL);
    /* held exclusive: a second thread waits until release */
    for (int mode = 0; mode < 2; mode++) {
        g_srw_done = 0;
        if (mode == 0) UN(RtlAcquireSRWLockExclusive)(&l); else UN(RtlAcquireSRWLockShared)(&l);
        HANDLE th = CreateThread(NULL, 0, srw_thread, &l, 0, NULL);
        EXPECT_NE(th, NULL);
        if (!th) { if (mode == 0) UN(RtlReleaseSRWLockExclusive)(&l); else UN(RtlReleaseSRWLockShared)(&l); return; }
        Sleep(150);
        EXPECT_EQ(g_srw_done, 0);
        if (mode == 0) UN(RtlReleaseSRWLockExclusive)(&l); else UN(RtlReleaseSRWLockShared)(&l);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(g_srw_done, 1);
        EXPECT_EQ(l.Ptr, NULL);                    /* the waiter released it again */
        CloseHandle(th);
    }
}

/* ---- RTL_RESOURCE ---- */
typedef struct { BYTE cs[40]; HANDLE SharedSem; ULONG WaitShared; HANDLE ExclSem; ULONG WaitExcl; LONG NumberOfActive; HANDLE ExclOwner; ULONG Flags; PVOID Debug; } RES;
#define RES_FIXTURE \
    REQUIRE(UN(RtlInitializeResource)); REQUIRE(UN(RtlDeleteResource)); REQUIRE(UN(RtlAcquireResourceExclusive)); \
    REQUIRE(UN(RtlAcquireResourceShared)); REQUIRE(UN(RtlReleaseResource)); \
    static RES r; memset(&r, 0, sizeof r); UN(RtlInitializeResource)(&r); EXPECT_EQ(r.NumberOfActive, 0)
static volatile LONG g_res_try_excl, g_res_try_shared;
static DWORD WINAPI res_try_thread(LPVOID p) {
    g_res_try_excl = UN(RtlAcquireResourceExclusive)(p, FALSE);
    if (g_res_try_excl) UN(RtlReleaseResource)(p);
    g_res_try_shared = UN(RtlAcquireResourceShared)(p, FALSE);
    if (g_res_try_shared) UN(RtlReleaseResource)(p);
    return 0;
}
static void res_probe(RES *res, int *excl, int *shared) {
    g_res_try_excl = g_res_try_shared = -1;
    HANDLE th = CreateThread(NULL, 0, res_try_thread, res, 0, NULL);
    if (!th) { *excl = *shared = -1; return; }
    WaitForSingleObject(th, 10000); CloseHandle(th);
    *excl = g_res_try_excl; *shared = g_res_try_shared;
}
TEST(rtl_resource_exclusive) {
    RES_FIXTURE;
    BOOLEAN ok = UN(RtlAcquireResourceExclusive)(&r, TRUE);
    EXPECT_EQ(ok, TRUE); EXPECT_EQ(r.NumberOfActive, -1);
    EXPECT_EQ(r.ExclOwner, (HANDLE)(ULONG_PTR)GetCurrentThreadId());
    /* the owner may re-acquire recursively, exclusive or shared */
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), TRUE); EXPECT_EQ(r.NumberOfActive, -2);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE); EXPECT_EQ(r.NumberOfActive, -3);
    int ex, sh;
    res_probe(&r, &ex, &sh);                          /* other thread: both non-blocking attempts fail */
    EXPECT_EQ(ex, 0); EXPECT_EQ(sh, 0);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(r.NumberOfActive, -2);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(r.NumberOfActive, -1);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(r.NumberOfActive, 0);
    res_probe(&r, &ex, &sh);                          /* free again */
    EXPECT_EQ(ex, 1); EXPECT_EQ(sh, 1);
    UN(RtlDeleteResource)(&r);
}
TEST(rtl_resource_shared) {
    RES_FIXTURE;
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, TRUE), TRUE); EXPECT_EQ(r.NumberOfActive, 1);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE); EXPECT_EQ(r.NumberOfActive, 2);
    int ex, sh;
    res_probe(&r, &ex, &sh);                          /* readers coexist; a writer cannot get in */
    EXPECT_EQ(ex, 0); EXPECT_EQ(sh, 1);
    /* a shared owner cannot upgrade without waiting */
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), FALSE); EXPECT_EQ(r.NumberOfActive, 2);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(r.NumberOfActive, 1);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(r.NumberOfActive, 0);
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), TRUE); EXPECT_EQ(r.NumberOfActive, -1);
    UN(RtlReleaseResource)(&r);
    UN(RtlDeleteResource)(&r);
}
static volatile LONG g_res_blocked_done;
static DWORD WINAPI res_wait_thread(LPVOID p) {
    if (UN(RtlAcquireResourceExclusive)(p, TRUE)) { g_res_blocked_done = 1; UN(RtlReleaseResource)(p); }
    return 0;
}
TEST(rtl_resource_wait_for_release) {
    RES_FIXTURE;
    g_res_blocked_done = 0;
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, TRUE), TRUE);
    HANDLE th = CreateThread(NULL, 0, res_wait_thread, &r, 0, NULL);
    EXPECT_NE(th, NULL);
    if (!th) { UN(RtlReleaseResource)(&r); UN(RtlDeleteResource)(&r); return; }
    Sleep(200);
    EXPECT_EQ(g_res_blocked_done, 0);                 /* writer waits for the reader */
    UN(RtlReleaseResource)(&r);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(g_res_blocked_done, 1);
    EXPECT_EQ(r.NumberOfActive, 0);
    CloseHandle(th);
    UN(RtlDeleteResource)(&r);
}

/* ---- vectored handlers ---- */
#define TEST_CODE 0xE0DDA001u
static volatile LONG g_order[8]; static volatile LONG g_norder; static volatile LONG g_cont_calls, g_cont_code;
static LONG CALLBACK veh_a(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != TEST_CODE) return EXCEPTION_CONTINUE_SEARCH;
    g_order[g_norder++ & 7] = 'a'; return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG CALLBACK veh_b(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != TEST_CODE) return EXCEPTION_CONTINUE_SEARCH;
    g_order[g_norder++ & 7] = 'b'; return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK vch(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != TEST_CODE) return EXCEPTION_CONTINUE_SEARCH;
    g_cont_calls++; g_cont_code = ep->ExceptionRecord->ExceptionCode; return EXCEPTION_CONTINUE_SEARCH;
}
static void raise_test(void) { RaiseException(TEST_CODE, 0, 0, NULL); }
TEST(rtl_vectored_exception_handler) {
    REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredExceptionHandler));
    g_norder = 0;
    PVOID ha = UN(RtlAddVectoredExceptionHandler)(0, veh_a);
    EXPECT_NE(ha, NULL);
    if (!ha) return;
    raise_test();
    EXPECT_EQ(g_norder, 1); EXPECT_EQ(g_order[0], 'a');
    /* First=1 puts the handler at the head of the list */
    PVOID hb = UN(RtlAddVectoredExceptionHandler)(1, veh_b);
    EXPECT_NE(hb, NULL); EXPECT_NE(hb, ha);
    g_norder = 0; raise_test();
    EXPECT_EQ(g_norder, 2); EXPECT_EQ(g_order[0], 'b'); EXPECT_EQ(g_order[1], 'a');
    /* removing b: only a sees the exception again */
    if (hb) EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hb), 1);
    g_norder = 0; raise_test();
    EXPECT_EQ(g_norder, 1); EXPECT_EQ(g_order[0], 'a');
    if (hb) EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hb), 0);     /* already gone */
    /* First=0 appends: add b at the tail, a (head) still handles first and stops the search */
    hb = UN(RtlAddVectoredExceptionHandler)(0, veh_b);
    g_norder = 0; raise_test();
    EXPECT_EQ(g_norder, 1); EXPECT_EQ(g_order[0], 'a');
    if (hb) EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hb), 1);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(ha), 1);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(ha), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(NULL), 0);
}
TEST(rtl_vectored_continue_handler) {
    REQUIRE(UN(RtlAddVectoredContinueHandler)); REQUIRE(UN(RtlRemoveVectoredContinueHandler));
    REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredExceptionHandler));
    PVOID hc = UN(RtlAddVectoredContinueHandler)(1, vch);
    EXPECT_NE(hc, NULL);
    PVOID ha = UN(RtlAddVectoredExceptionHandler)(1, veh_a);
    if (!hc || !ha) { if (hc) UN(RtlRemoveVectoredContinueHandler)(hc); if (ha) UN(RtlRemoveVectoredExceptionHandler)(ha); return; }
    g_cont_calls = 0; g_cont_code = 0; g_norder = 0;
    raise_test();
    EXPECT_EQ(g_norder, 1);
    EXPECT_EQ(g_cont_calls, 1);                       /* called after the exception handler chose to continue */
    EXPECT_EQ(g_cont_code, (LONG)TEST_CODE);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hc), 1);
    g_cont_calls = 0; raise_test();
    EXPECT_EQ(g_cont_calls, 0);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hc), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(ha), 1);
    /* handle namespaces are separate: a continue handle is not an exception handle */
    hc = UN(RtlAddVectoredContinueHandler)(0, vch);
    if (hc) { EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hc), 0); EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hc), 1); }
}

/* ---- timer queues ---- */
static volatile LONG g_tm_count, g_tm_fired_flag;
static HANDLE g_tm_event;
static VOID CALLBACK tm_cb(PVOID ctx, BOOLEAN fired) {
    InterlockedIncrement(&g_tm_count);
    if (fired) g_tm_fired_flag = 1;
    if (g_tm_event) SetEvent(g_tm_event);
}
TEST(rtl_timer_queue_oneshot) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    g_tm_count = 0; g_tm_fired_flag = 0;
    g_tm_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE q = NULL;
    NTSTATUS s = UN(RtlCreateTimerQueue)(&q);
    EXPECT_EQ(s, 0); EXPECT_NE(q, NULL);
    if (s < 0 || !q) { CloseHandle(g_tm_event); return; }
    HANDLE t = NULL;
    s = UN(RtlCreateTimer)(q, &t, tm_cb, NULL, 30, 0, 0);
    EXPECT_EQ(s, 0); EXPECT_NE(t, NULL);
    EXPECT_EQ(WaitForSingleObject(g_tm_event, 10000), WAIT_OBJECT_0);
    Sleep(200);
    EXPECT_EQ(g_tm_count, 1);                         /* period 0: fires exactly once */
    EXPECT_EQ(g_tm_fired_flag, 1);                    /* TimerOrWaitFired is TRUE for timers */
    s = UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE);   /* waits for callbacks, frees timers */
    EXPECT_EQ(s, 0);
    CloseHandle(g_tm_event); g_tm_event = NULL;
}
TEST(rtl_timer_queue_periodic_delete) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    g_tm_count = 0; g_tm_event = NULL;
    HANDLE q = NULL, t = NULL;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    if (!q) return;
    NTSTATUS s = UN(RtlCreateTimer)(q, &t, tm_cb, NULL, 10, 20, 0);
    EXPECT_EQ(s, 0); EXPECT_NE(t, NULL);
    DWORD t0 = GetTickCount();
    while (g_tm_count < 4 && GetTickCount() - t0 < 10000) Sleep(10);
    EXPECT_EQ(g_tm_count >= 4, 1);
    s = UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE);
    t_note("RtlDeleteTimer(blocking) status 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, 0);
    LONG after = g_tm_count;
    Sleep(200);
    EXPECT_EQ(g_tm_count, after);                     /* no further callbacks */
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
}
TEST(rtl_timer_queue_delete_cancels_pending) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    g_tm_count = 0; g_tm_event = NULL;
    HANDLE q = NULL, t = NULL;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    if (!q) return;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, tm_cb, NULL, 60000, 0, 0), 0);     /* far in the future */
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    Sleep(50);
    EXPECT_EQ(g_tm_count, 0);
}

/* ---- orphaned critical section scan ---- */
TEST(rtl_check_for_orphaned_critical_sections) {
    REQUIRE(UN(RtlCheckForOrphanedCriticalSections)); REQUIRE(UN(RtlInitializeCriticalSection));
    RTL_CRITICAL_SECTION cs;
    EXPECT_EQ(UN(RtlInitializeCriticalSection)(&cs), 0);
    EXPECT_EQ(UN(RtlEnterCriticalSection)(&cs), 0);
    /* a live thread holding a critical section is not orphaned: the scan returns and leaves ownership alone */
    UN(RtlCheckForOrphanedCriticalSections)(GetCurrentThread());
    EXPECT_EQ(cs.RecursionCount, 1);
    EXPECT_EQ(cs.OwningThread, (HANDLE)(ULONG_PTR)GetCurrentThreadId());
    EXPECT_EQ(UN(RtlLeaveCriticalSection)(&cs), 0);
    UN(RtlCheckForOrphanedCriticalSections)(GetCurrentThread());
    EXPECT_EQ(cs.RecursionCount, 0);
    UN(RtlDeleteCriticalSection)(&cs);
}

/* ---- atom tables ---- */
TEST(rtl_atom_table_basic) {
    REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable)); REQUIRE(UN(RtlLookupAtomInAtomTable));
    REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlDeleteAtomFromAtomTable)); REQUIRE(UN(RtlDestroyAtomTable));
    PVOID tab = NULL;
    NTSTATUS s = UN(RtlCreateAtomTable)(37, &tab);
    EXPECT_EQ(s, 0); EXPECT_NE(tab, NULL);
    if (s < 0 || !tab) return;
    USHORT a1 = 0, a2 = 0, a3 = 0, look = 0;
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"NtdlltAtomFoo", &a1), 0);
    EXPECT_EQ(a1 >= 0xC000, 1);                        /* string atoms live in 0xC000..0xFFFF */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"NtdlltAtomFoo", &a2), 0);
    EXPECT_EQ(a2, a1);                                 /* same string, same atom */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"NtdlltAtomBar", &a3), 0);
    EXPECT_NE(a3, a1);
    /* lookup is case-insensitive and does not bump the reference count */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tab, L"NTDLLTATOMFOO", &look), 0); EXPECT_EQ(look, a1);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tab, L"NtdlltAtomNone", &look), ST_NOTFOUND);
    ULONG ref = 0, pin = 99, nlen = 0; WCHAR name[40];
    nlen = sizeof name;
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(tab, a1, &ref, &pin, name, &nlen), 0);
    EXPECT_EQ(ref, 2); EXPECT_EQ(pin, 0); EXPECT_EQ(nlen, 13 * 2);
    EXPECT_EQ(wcsncmp(name, L"NtdlltAtomFoo", 13), 0);
    EXPECT_EQ(name[13], 0);
    /* name buffer too small */
    nlen = 10; WCHAR small[8];
    s = UN(RtlQueryAtomInAtomTable)(tab, a1, &ref, &pin, small, &nlen);
    EXPECT_EQ(s, 0);                                   /* the name is truncated, not an error */
    EXPECT_EQ(nlen, 8);                                /* room for 4 characters plus the terminator */
    EXPECT_EQ(wcsncmp(small, L"Ntdl", 4), 0); EXPECT_EQ(small[4], 0);
    /* NULL name buffer: only counts */
    ref = 0; EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(tab, a1, &ref, NULL, NULL, NULL), 0); EXPECT_EQ(ref, 2);
    /* delete drops references one by one */
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tab, a1), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tab, L"NtdlltAtomFoo", &look), 0);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tab, a1), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tab, L"NtdlltAtomFoo", &look), ST_NOTFOUND);
    s = UN(RtlDeleteAtomFromAtomTable)(tab, a1);
    EXPECT_EQ(s, S(0xC0000008));                       /* STATUS_INVALID_HANDLE: the atom no longer exists */
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tab, a3), 0);
    EXPECT_EQ(UN(RtlDestroyAtomTable)(tab), 0);
}
TEST(rtl_atom_table_integer_atoms) {
    REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable)); REQUIRE(UN(RtlLookupAtomInAtomTable));
    REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlDestroyAtomTable));
    PVOID tab = NULL;
    if (UN(RtlCreateAtomTable)(37, &tab) < 0 || !tab) { t_skip("atom table creation failed"); return; }
    USHORT a = 0;
    /* a name of the form "#nnnn" denotes the integer atom nnnn (1..0xBFFF), a MAKEINTATOM pointer likewise */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"#1234", &a), 0); EXPECT_EQ(a, 1234);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, (PCWSTR)(ULONG_PTR)0x1111, &a), 0); EXPECT_EQ(a, 0x1111);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"#49151", &a), 0); EXPECT_EQ(a, 0xBFFF);
    a = 77; NTSTATUS s = UN(RtlAddAtomToAtomTable)(tab, L"#49152", &a);
    EXPECT_EQ(s, ST_INVPARAM);
    a = 77; EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tab, L"#99", &a), 0); EXPECT_EQ(a, 99);
    /* an integer atom is reported with the "#nnnn" spelling */
    ULONG nlen = 16; WCHAR nm[8];
    s = UN(RtlQueryAtomInAtomTable)(tab, 1234, NULL, NULL, nm, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(nlen, 10); EXPECT_EQ(wcsncmp(nm, L"#1234", 5), 0);
    /* invalid names */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"", &a), ST_NAME_INVALID);
    WCHAR big[300]; for (int i = 0; i < 299; i++) big[i] = L'x'; big[299] = 0;
    s = UN(RtlAddAtomToAtomTable)(tab, big, &a);
    EXPECT_EQ(s, ST_INVPARAM);                         /* names are limited to 255 characters */
    WCHAR ok255[256]; for (int i = 0; i < 255; i++) ok255[i] = L'y'; ok255[255] = 0;
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, ok255, &a), 0);
    EXPECT_EQ(a >= 0xC000, 1);
    /* NULL table */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(NULL, L"abc", &a), ST_INVPARAM);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(NULL, L"abc", &a), ST_INVPARAM);
    EXPECT_EQ(UN(RtlDestroyAtomTable)(tab), 0);
}

/* ---- privilege acquisition ---- */
/* returns 1 if the token holds the privilege (enabled or not), 0 if not, -1 on failure; *enabled set when currently enabled */
static int token_has_priv(HANDLE tok, ULONG luid, int *enabled) {
    BYTE buf[2048]; ULONG rl = 0;
    if (UN(NtQueryInformationToken)(tok, 3 /* TokenPrivileges */, buf, sizeof buf, &rl) < 0) return -1;
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == luid && tp->Privileges[i].Luid.HighPart == 0) {
            if (enabled) *enabled = !!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);
            return 1;
        }
    return 0;
}
static int proc_has_priv(ULONG luid) {
    HANDLE p = NULL; int r = -1;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &p) >= 0) { r = token_has_priv(p, luid, NULL); UN(NtClose)(p); }
    return r;
}
/* A privilege every token carries: increase-working-set (disabled) for administrators, change-notify (enabled) for all. */
static ULONG pick_held(void) { if (proc_has_priv(14) == 1) return 14; if (proc_has_priv(23) == 1) return 23; return 0; }
TEST(rtl_acquire_privilege_thread_token) {
    REQUIRE(UN(RtlAcquirePrivilege)); REQUIRE(UN(RtlReleasePrivilege)); REQUIRE(UN(NtOpenThreadToken));
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    const ULONG held = pick_held();
    if (!held) { t_skip("process token holds neither SeIncreaseWorkingSetPrivilege (14) nor SeChangeNotifyPrivilege (23)"); return; }
    HANDLE h = NULL;
    EXPECT_EQ(UN(NtOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY, TRUE, &h), ST_NO_TOKEN);
    PVOID state = NULL; ULONG priv = held;
    NTSTATUS s = UN(RtlAcquirePrivilege)(&priv, 1, 0, &state);
    EXPECT_EQ(s, 0); EXPECT_NE(state, NULL);
    if (s == 0) {
        /* flags 0: the thread now impersonates a copy of the process token with the privilege enabled */
        int en = -1;
        s = UN(NtOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY, TRUE, &h);
        EXPECT_EQ(s, 0);
        if (s == 0) { EXPECT_EQ(token_has_priv(h, held, &en), 1); EXPECT_EQ(en, 1); UN(NtClose)(h); }
        UN(RtlReleasePrivilege)(state);
        EXPECT_EQ(UN(NtOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY, TRUE, &h), ST_NO_TOKEN);  /* reverted */
    }
    /* flags: bits above 1 are rejected */
    state = NULL;
    EXPECT_EQ(UN(RtlAcquirePrivilege)(&priv, 1, 4, &state), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAcquirePrivilege)(&priv, 1, 0x80000000, &state), ST_INVPARAM);
}
TEST(rtl_acquire_privilege_not_held) {
    REQUIRE(UN(RtlAcquirePrivilege)); REQUIRE(UN(RtlReleasePrivilege)); REQUIRE(UN(NtOpenProcessToken));
    REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    const ULONG notheld = 7 /* SeTcbPrivilege */, held = pick_held();
    if (!held) { t_skip("process token holds no usable privilege"); return; }
    int has = proc_has_priv(notheld);
    if (has != 0) { t_skip("the process token holds SeTcbPrivilege (or could not be queried)"); return; }
    PVOID state = (PVOID)1; ULONG priv = notheld;
    NTSTATUS s = UN(RtlAcquirePrivilege)(&priv, 1, 0, &state);
    EXPECT_EQ(s, ST_NOT_HELD);
    /* with several privileges one missing privilege is not an error */
    ULONG two[2] = {held, notheld}; state = NULL;
    s = UN(RtlAcquirePrivilege)(two, 2, 0, &state);
    EXPECT_EQ(s, 0);
    if (s == 0 && state) UN(RtlReleasePrivilege)(state);
    /* ... but only missing privileges is */
    ULONG two2[2] = {notheld, 2 /* SeCreateTokenPrivilege */}; state = NULL;
    if (proc_has_priv(2) == 0) {
        s = UN(RtlAcquirePrivilege)(two2, 2, 0, &state);
        EXPECT_EQ(s, 0);                              /* observed: only a lone missing privilege is reported */
        if (s >= 0 && state) UN(RtlReleasePrivilege)(state);
    }
}
TEST(rtl_acquire_privilege_process_token) {
    REQUIRE(UN(RtlAcquirePrivilege)); REQUIRE(UN(RtlReleasePrivilege)); REQUIRE(UN(NtOpenProcessToken));
    REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    const ULONG luid = pick_held();
    if (!luid) { t_skip("process token holds neither privilege 14 nor 23"); return; }
    HANDLE p = NULL; int en0 = -1, en1 = -1, en2 = -1;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &p) < 0) { t_skip("cannot open the process token"); return; }
    token_has_priv(p, luid, &en0);
    PVOID state = NULL; ULONG priv = luid;
    NTSTATUS s = UN(RtlAcquirePrivilege)(&priv, 1, 2 /* modify the process token */, &state);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        token_has_priv(p, luid, &en1);
        EXPECT_EQ(en1, 1);
        UN(RtlReleasePrivilege)(state);
        token_has_priv(p, luid, &en2);
        EXPECT_EQ(en2, en0);                          /* restored to the previous state */
    }
    UN(NtClose)(p);
}
