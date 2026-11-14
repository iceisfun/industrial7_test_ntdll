/* PEB lock, SRW shared-to-exclusive conversion, address waits, resources, barriers, timer queues, registered waits,
 * thread/module/zone locks, vectored handler removal, boot status data and process heap enumeration. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define K(name) UIN("kernel32.dll", name)

UDECL(BOOLEAN, RtlTryAcquirePebLock, (VOID));
UDECL(VOID, RtlAcquirePebLock, (VOID));
UDECL(VOID, RtlReleasePebLock, (VOID));
UDECL(BOOLEAN, RtlTryConvertSRWLockSharedToExclusiveOrRelease, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(NTSTATUS, RtlWaitOnAddress, (volatile VOID *, PVOID, SIZE_T, PLARGE_INTEGER));
UDECL(VOID, RtlWakeAddressAll, (PVOID));
UDECL(VOID, RtlWakeAddressSingle, (PVOID));
UDECL(VOID, RtlInitializeResource, (PVOID));
UDECL(VOID, RtlDeleteResource, (PVOID));
UDECL(BOOLEAN, RtlAcquireResourceExclusive, (PVOID, BOOLEAN));
UDECL(BOOLEAN, RtlAcquireResourceShared, (PVOID, BOOLEAN));
UDECL(VOID, RtlReleaseResource, (PVOID));
UDECL(VOID, RtlConvertSharedToExclusive, (PVOID));
UDECL(NTSTATUS, RtlInitBarrier, (PVOID, ULONG, ULONG));
UDECL(BOOLEAN, RtlBarrier, (PVOID, ULONG));
UDECL(VOID, RtlDeleteBarrier, (PVOID));
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlCreateTimer, (HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeleteTimer, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueue, (HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlRegisterWait, (PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeregisterWaitEx, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlLockCurrentThread, (VOID));
UDECL(NTSTATUS, RtlUnlockCurrentThread, (VOID));
UDECL(NTSTATUS, RtlLockModuleSection, (PVOID));
UDECL(NTSTATUS, RtlUnlockModuleSection, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryZone, (PVOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlDestroyMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlLockMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlUnlockMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryBlockLookaside, (PVOID *, ULONG, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlDestroyMemoryBlockLookaside, (PVOID));
UDECL(NTSTATUS, RtlLockMemoryBlockLookaside, (PVOID));
UDECL(NTSTATUS, RtlUnlockMemoryBlockLookaside, (PVOID));
UDECL(PVOID, RtlAddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(PVOID, RtlAddVectoredContinueHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(ULONG, RtlRemoveVectoredExceptionHandler, (PVOID));
UDECL(ULONG, RtlRemoveVectoredContinueHandler, (PVOID));
UDECL(NTSTATUS, RtlLockBootStatusData, (PHANDLE));
UDECL(VOID, RtlUnlockBootStatusData, (HANDLE));
UDECL(NTSTATUS, RtlEnumProcessHeaps, (NTSTATUS (NTAPI *)(PVOID, PVOID), PVOID));
UDECL(NTSTATUS, RtlRegisterSecureMemoryCacheCallback, (PVOID));
UDECL(BOOLEAN, RtlDeregisterSecureMemoryCacheCallback, (PVOID));
UDECL(NTSTATUS, RtlRegisterFeatureConfigurationChangeNotification, (PVOID, PVOID, PVOID, PVOID *));
UDECL(VOID, RtlUnregisterFeatureConfigurationChangeNotification, (PVOID));
UDECL(NTSTATUS, RtlRegisterForWnfMetaNotification, (PVOID *, PVOID, ULONG, PVOID, PVOID));

/* page locking needs working-set headroom (default minimum is only a few dozen pages) */
static void raise_ws(void) { SetProcessWorkingSetSize(GetCurrentProcess(), 64u << 20, 128u << 20); }

/* ---------------- PEB lock ---------------- */
typedef struct { HANDLE start, done; volatile LONG got; } PEBARG;
static DWORD WINAPI peb_thread(PVOID p) {
    PEBARG *a = p; WaitForSingleObject(a->start, 10000);
    a->got = UN(RtlTryAcquirePebLock)() ? 1 : 2;
    if (a->got == 1) UN(RtlReleasePebLock)();
    SetEvent(a->done); return 0;
}
TEST(rtl_cad_b_pebloc_try) {
    REQUIRE(UN(RtlTryAcquirePebLock)); REQUIRE(UN(RtlReleasePebLock)); REQUIRE(UN(RtlAcquirePebLock));
    PRTL_CRITICAL_SECTION cs = *(PRTL_CRITICAL_SECTION *)((BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock + 0x38); /* PEB.FastPebLock */
    CHECK(cs != NULL); if (!cs) return;
    EXPECT_EQ(cs->RecursionCount, -1 + 1);   /* unowned: recursion count 0 in an unowned section */
    EXPECT_EQ(UN(RtlTryAcquirePebLock)(), TRUE);
    EXPECT_EQ(cs->OwningThread, (HANDLE)(ULONG_PTR)GetCurrentThreadId());
    EXPECT_EQ(cs->RecursionCount, 1);
    EXPECT_EQ(UN(RtlTryAcquirePebLock)(), TRUE);   /* recursive */
    EXPECT_EQ(cs->RecursionCount, 2);
    /* another thread cannot take it */
    PEBARG a = { CreateEventW(NULL, TRUE, FALSE, NULL), CreateEventW(NULL, TRUE, FALSE, NULL), 0 };
    HANDLE th = K(CreateThread)(NULL, 0, peb_thread, &a, 0, NULL);
    SetEvent(a.start);
    EXPECT_EQ(WaitForSingleObject(a.done, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(a.got, 2);
    UN(RtlReleasePebLock)(); EXPECT_EQ(cs->RecursionCount, 1);
    UN(RtlReleasePebLock)(); EXPECT_EQ(cs->RecursionCount, 0);
    EXPECT_EQ(cs->OwningThread, 0);
    /* now free: the other thread can */
    ResetEvent(a.start); ResetEvent(a.done); WaitForSingleObject(th, 5000); CloseHandle(th);
    a.got = 0; ResetEvent(a.start);
    th = K(CreateThread)(NULL, 0, peb_thread, &a, 0, NULL); SetEvent(a.start);
    EXPECT_EQ(WaitForSingleObject(a.done, 10000), WAIT_OBJECT_0); EXPECT_EQ(a.got, 1);
    WaitForSingleObject(th, 5000); CloseHandle(th); CloseHandle(a.start); CloseHandle(a.done);
    EXPECT_EQ(UN(RtlTryAcquirePebLock)(), TRUE); UN(RtlReleasePebLock)();
}

/* ---------------- SRW shared -> exclusive ---------------- */
TEST(rtl_cad_b_srw_try_convert) {
    REQUIRE(UN(RtlTryConvertSRWLockSharedToExclusiveOrRelease)); REQUIRE(UN(RtlAcquireSRWLockShared));
    REQUIRE(UN(RtlReleaseSRWLockShared)); REQUIRE(UN(RtlReleaseSRWLockExclusive));
    REQUIRE(UN(RtlTryAcquireSRWLockExclusive)); REQUIRE(UN(RtlTryAcquireSRWLockShared));
    RTL_SRWLOCK l = RTL_SRWLOCK_INIT;
    UN(RtlAcquireSRWLockShared)(&l);
    /* sole shared owner converts to exclusive */
    EXPECT_EQ(UN(RtlTryConvertSRWLockSharedToExclusiveOrRelease)(&l), TRUE);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l), FALSE);      /* exclusively held now */
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), FALSE);
    UN(RtlReleaseSRWLockExclusive)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), TRUE); UN(RtlReleaseSRWLockExclusive)(&l);
    /* with a second shared owner conversion fails and the caller's share is released */
    UN(RtlAcquireSRWLockShared)(&l); UN(RtlAcquireSRWLockShared)(&l);
    EXPECT_EQ(UN(RtlTryConvertSRWLockSharedToExclusiveOrRelease)(&l), FALSE);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), FALSE);   /* one share left */
    UN(RtlReleaseSRWLockShared)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l), TRUE); UN(RtlReleaseSRWLockExclusive)(&l);
}

/* ---------------- RtlWaitOnAddress ---------------- */
TEST(rtl_cad_b_wait_on_address) {
    REQUIRE(UN(RtlWaitOnAddress)); REQUIRE(UN(RtlWakeAddressAll)); REQUIRE(UN(RtlWakeAddressSingle));
    volatile ULONGLONG v = 0x1122334455667788ULL; ULONGLONG cmp = v; LARGE_INTEGER to;
    /* invalid sizes */
    static const SIZE_T bad[] = { 0, 3, 5, 6, 7, 9, 16 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        to.QuadPart = 0; NTSTATUS s = UN(RtlWaitOnAddress)(&v, &cmp, bad[i], &to);
        CHECKF(s == S(0xC000000D), "size %llu status %08lx", (unsigned long long)bad[i], (unsigned long)s);
    }
    /* value differs from the compare value: returns immediately with success */
    ULONGLONG other = 1; to.QuadPart = -10000000;
    EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &other, 8, &to), 0);
    ULONG o4 = 1; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &o4, 4, &to), 0);
    USHORT o2 = 1; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &o2, 2, &to), 0);
    UCHAR o1 = 1; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &o1, 1, &to), 0);
    /* value equal and zero timeout: STATUS_TIMEOUT */
    to.QuadPart = 0;
    EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &cmp, 8, &to), S(0x102));
    ULONG c4 = (ULONG)v; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &c4, 4, &to), S(0x102));
    USHORT c2 = (USHORT)v; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &c2, 2, &to), S(0x102));
    UCHAR c1 = (UCHAR)v; EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &c1, 1, &to), S(0x102));
    /* relative 50 ms timeout expires */
    to.QuadPart = -500000; DWORD t0 = GetTickCount();
    EXPECT_EQ(UN(RtlWaitOnAddress)(&v, &cmp, 8, &to), S(0x102));
    DWORD el = GetTickCount() - t0; CHECKF(el >= 30 && el < 5000, "elapsed %lu", el);
}
typedef struct { volatile ULONG v; volatile LONG status; HANDLE started; } WAITARG;
static DWORD WINAPI wa_thread(PVOID p) {
    WAITARG *a = p; ULONG c = 0; LARGE_INTEGER to; to.QuadPart = -100000000LL; /* 10 s */
    SetEvent(a->started);
    a->status = UN(RtlWaitOnAddress)(&a->v, &c, 4, &to);
    return 0;
}
TEST(rtl_cad_b_wait_on_address_wake) {
    REQUIRE(UN(RtlWaitOnAddress)); REQUIRE(UN(RtlWakeAddressAll)); REQUIRE(UN(RtlWakeAddressSingle));
    for (int mode = 0; mode < 2; mode++) {
        WAITARG a = { 0, 0x7fffffff, CreateEventW(NULL, FALSE, FALSE, NULL) };
        HANDLE th = K(CreateThread)(NULL, 0, wa_thread, &a, 0, NULL);
        WaitForSingleObject(a.started, 5000); Sleep(100);
        a.v = 1;
        if (mode) UN(RtlWakeAddressSingle)((PVOID)&a.v); else UN(RtlWakeAddressAll)((PVOID)&a.v);
        EXPECT_EQ(WaitForSingleObject(th, 8000), WAIT_OBJECT_0);
        EXPECT_EQ(a.status, 0);
        CloseHandle(th); CloseHandle(a.started);
    }
}

/* ---------------- resources ---------------- */
typedef struct { BYTE b[0x60]; } RES;
TEST(rtl_cad_b_resource_release_delete) {
    REQUIRE(UN(RtlInitializeResource)); REQUIRE(UN(RtlDeleteResource)); REQUIRE(UN(RtlReleaseResource));
    REQUIRE(UN(RtlAcquireResourceExclusive)); REQUIRE(UN(RtlAcquireResourceShared)); REQUIRE(UN(RtlConvertSharedToExclusive));
    RES r; memset(&r, 0xCC, sizeof r);
    UN(RtlInitializeResource)(&r);
    LONG *active = (LONG *)(r.b + 0x44);        /* NumberOfActive */
    EXPECT_EQ(*active, 0);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE);  EXPECT_EQ(*active, 1);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE);  EXPECT_EQ(*active, 2);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(*active, 1);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(*active, 0);
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), TRUE); EXPECT_EQ(*active, -1);
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), TRUE); EXPECT_EQ(*active, -2);   /* recursive */
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE);    EXPECT_EQ(*active, -3);   /* owner acquires shared as exclusive */
    UN(RtlReleaseResource)(&r); UN(RtlReleaseResource)(&r); EXPECT_EQ(*active, -1);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(*active, 0);
    /* shared -> exclusive conversion with one shared owner */
    EXPECT_EQ(UN(RtlAcquireResourceShared)(&r, FALSE), TRUE);
    UN(RtlConvertSharedToExclusive)(&r); EXPECT_EQ(*active, -1);
    UN(RtlReleaseResource)(&r); EXPECT_EQ(*active, 0);
    UN(RtlDeleteResource)(&r);
    /* delete wipes the structure */
    BYTE zero[0x60] = {0}; CHECK(!memcmp(&r, zero, sizeof zero));
}
typedef struct { RES *r; HANDLE got, go; volatile LONG ok; } RESARG;
static DWORD WINAPI res_thread(PVOID p) {
    RESARG *a = p;
    a->ok = UN(RtlAcquireResourceShared)(a->r, FALSE);    /* must fail: exclusive owned elsewhere */
    SetEvent(a->got);
    WaitForSingleObject(a->go, 10000);
    BOOLEAN r2 = UN(RtlAcquireResourceShared)(a->r, TRUE);   /* blocks until released */
    a->ok = a->ok * 10 + r2;
    if (r2) UN(RtlReleaseResource)(a->r);
    return 0;
}
TEST(rtl_cad_b_resource_contention) {
    REQUIRE(UN(RtlInitializeResource)); REQUIRE(UN(RtlDeleteResource)); REQUIRE(UN(RtlReleaseResource));
    REQUIRE(UN(RtlAcquireResourceExclusive)); REQUIRE(UN(RtlAcquireResourceShared));
    RES r; UN(RtlInitializeResource)(&r);
    RESARG a = { &r, CreateEventW(NULL, TRUE, FALSE, NULL), CreateEventW(NULL, TRUE, FALSE, NULL), -1 };
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(&r, FALSE), TRUE);
    HANDLE th = K(CreateThread)(NULL, 0, res_thread, &a, 0, NULL);
    EXPECT_EQ(WaitForSingleObject(a.got, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(a.ok, 0);
    SetEvent(a.go); Sleep(100);
    EXPECT_EQ(WaitForSingleObject(th, 200), WAIT_TIMEOUT);   /* still blocked */
    UN(RtlReleaseResource)(&r);                              /* wakes the waiter */
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(a.ok, 1);
    CloseHandle(th); CloseHandle(a.got); CloseHandle(a.go);
    UN(RtlDeleteResource)(&r);
}

/* ---------------- barrier ---------------- */
static DWORD WINAPI bar_thread(PVOID p) { PVOID *a = p; return UN(RtlBarrier)(a[0], 0) ? 1 : 2; }
TEST(rtl_cad_b_barrier) {
    REQUIRE(UN(RtlInitBarrier)); REQUIRE(UN(RtlBarrier)); REQUIRE(UN(RtlDeleteBarrier));
    __attribute__((aligned(16))) BYTE b[64]; memset(b, 0xCC, sizeof b);
    EXPECT_EQ(UN(RtlInitBarrier)(b, 1, 0), 0);
    EXPECT_EQ(UN(RtlBarrier)(b, 0), TRUE);     /* a one-thread barrier always completes */
    EXPECT_EQ(UN(RtlBarrier)(b, 0), TRUE);
    UN(RtlDeleteBarrier)(b);
    EXPECT_EQ(UN(RtlInitBarrier)(NULL, 1, 0), S(0xC000000D));
    /* two threads: exactly one is told it was the last to arrive */
    EXPECT_EQ(UN(RtlInitBarrier)(b, 2, 0), 0);
    PVOID arg[1] = { b };
    HANDLE th = K(CreateThread)(NULL, 0, bar_thread, arg, 0, NULL);
    BOOLEAN mine = UN(RtlBarrier)(b, 0);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    DWORD ec = 0; GetExitCodeThread(th, &ec); CloseHandle(th);
    CHECKF((mine ? 1 : 0) + (ec == 1 ? 1 : 0) == 1, "mine=%d other=%lu", mine, ec);
    UN(RtlDeleteBarrier)(b);
}

/* ---------------- timers ---------------- */
typedef struct { HANDLE fired, entered, release; volatile LONG count; volatile LONG tow; } TMR;
static VOID NTAPI tmr_cb(PVOID ctx, BOOLEAN tow) { TMR *t = ctx; t->tow = tow; InterlockedIncrement(&t->count); SetEvent(t->fired); }
static VOID NTAPI tmr_slow_cb(PVOID ctx, BOOLEAN tow) { TMR *t = ctx; SetEvent(t->entered); WaitForSingleObject(t->release, 10000); InterlockedIncrement(&t->count); }
TEST(rtl_cad_b_timer_delete_errors) {
    REQUIRE(UN(RtlDeleteTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx)); REQUIRE(UN(RtlDeleteTimerQueue));
    EXPECT_EQ(UN(RtlDeleteTimer)(NULL, (HANDLE)0x1000, NULL), S(0xC00000EF));
    HANDLE q = NULL; REQUIRE(UN(RtlCreateTimerQueue)); EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    CHECK(q != NULL); if (!q) return;
    EXPECT_EQ(UN(RtlDeleteTimer)(q, NULL, NULL), S(0xC00000F0));
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(NULL, NULL), S(0xC00000EF));
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
}
TEST(rtl_cad_b_timer_delete_flow) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimer));
    REQUIRE(UN(RtlDeleteTimerQueueEx)); REQUIRE(UN(RtlDeleteTimerQueue));
    TMR t = { CreateEventW(NULL, FALSE, FALSE, NULL), NULL, NULL, 0, -1 };
    HANDLE q = NULL, tm = NULL;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0); if (!q) return;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &tm, tmr_cb, &t, 10, 0, 0), 0); CHECK(tm != NULL);
    EXPECT_EQ(WaitForSingleObject(t.fired, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(t.count, 1); EXPECT_EQ(t.tow, TRUE);
    /* one-shot timer already fired; deleting it, waiting for completion, succeeds */
    EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, INVALID_HANDLE_VALUE), 0);
    /* periodic timer stops firing after deletion */
    tm = NULL; EXPECT_EQ(UN(RtlCreateTimer)(q, &tm, tmr_cb, &t, 10, 20, 0), 0);
    EXPECT_EQ(WaitForSingleObject(t.fired, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, INVALID_HANDLE_VALUE), 0);
    LONG n = t.count; Sleep(150); EXPECT_EQ(t.count, n);
    /* queue with a live timer is deleted, completion by blocking wait */
    tm = NULL; EXPECT_EQ(UN(RtlCreateTimer)(q, &tm, tmr_cb, &t, 3600000, 0, 0), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    /* non-waiting delete of an idle queue completes synchronously */
    q = NULL; EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueue)(q), 0);
    CloseHandle(t.fired);
}
TEST(rtl_cad_b_timer_delete_pending) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlDeleteTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    TMR t = { NULL, CreateEventW(NULL, FALSE, FALSE, NULL), CreateEventW(NULL, TRUE, FALSE, NULL), 0, 0 };
    HANDLE q = NULL, tm = NULL;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0); if (!q) return;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &tm, tmr_slow_cb, &t, 5, 0, 0), 0);
    EXPECT_EQ(WaitForSingleObject(t.entered, 10000), WAIT_OBJECT_0);
    /* callback is running: a non-waiting delete reports STATUS_PENDING */
    EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, NULL), S(0x103));
    EXPECT_EQ(t.count, 0);
    SetEvent(t.release);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(t.count, 1);
    CloseHandle(t.entered); CloseHandle(t.release);
}

/* ---------------- RtlRegisterWait ---------------- */
TEST(rtl_cad_b_register_wait) {
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    TMR t = { CreateEventW(NULL, FALSE, FALSE, NULL), NULL, NULL, 0, -1 };
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), w = (HANDLE)(ULONG_PTR)0x77;
    /* invalid objects / callback */
    EXPECT_EQ(UN(RtlRegisterWait)(&w, NULL, tmr_cb, &t, 100, 0), S(0xC000000D));
    EXPECT_EQ(UN(RtlRegisterWait)(&w, (HANDLE)(LONG_PTR)-1, tmr_cb, &t, 100, 0), S(0xC000000D));
    EXPECT_EQ(UN(RtlRegisterWait)(&w, (HANDLE)(LONG_PTR)-2, tmr_cb, &t, 100, 0), S(0xC000000D));
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, NULL, &t, 100, 0), S(0xC000000D));
    /* signaled object runs the callback with TimerOrWaitFired == FALSE */
    w = NULL; EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, tmr_cb, &t, INFINITE, 0x8 /* execute once */), 0);
    CHECK(w != NULL);
    SetEvent(ev);
    EXPECT_EQ(WaitForSingleObject(t.fired, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(t.count, 1); EXPECT_EQ(t.tow, FALSE);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    /* timeout path */
    ResetEvent(ev); t.count = 0;
    w = NULL; EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, tmr_cb, &t, 30, 0x8), 0);
    EXPECT_EQ(WaitForSingleObject(t.fired, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(t.count, 1); EXPECT_EQ(t.tow, TRUE);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    CloseHandle(ev); CloseHandle(t.fired);
}

/* ---------------- current thread / module section / zones ---------------- */
static DWORD WINAPI lockthread(PVOID p) {
    NTSTATUS *r = p;
    r[0] = UN(RtlUnlockCurrentThread)();    /* not locked yet */
    r[1] = UN(RtlLockCurrentThread)();
    r[2] = UN(RtlLockCurrentThread)();
    r[3] = UN(RtlUnlockCurrentThread)();
    r[4] = UN(RtlUnlockCurrentThread)();
    r[5] = UN(RtlUnlockCurrentThread)();    /* count exhausted */
    return 0;
}
TEST(rtl_cad_b_lock_current_thread) {
    REQUIRE(UN(RtlLockCurrentThread)); REQUIRE(UN(RtlUnlockCurrentThread)); raise_ws();
    NTSTATUS r[6]; for (int i = 0; i < 6; i++) r[i] = S(0x12345678);
    HANDLE th = K(CreateThread)(NULL, 0, lockthread, r, 0, NULL);
    EXPECT_EQ(WaitForSingleObject(th, 20000), WAIT_OBJECT_0); CloseHandle(th);
    EXPECT_EQ(r[0], S(0xC000002A));
    if (r[1] != 0) { t_skip("RtlLockCurrentThread failed with %08lx", (unsigned long)r[1]); return; }
    EXPECT_EQ(r[2], 0); EXPECT_EQ(r[3], 0); EXPECT_EQ(r[4], 0); EXPECT_EQ(r[5], S(0xC000002A));
}
TEST(rtl_cad_b_lock_module_section) {
    REQUIRE(UN(RtlLockModuleSection)); REQUIRE(UN(RtlUnlockModuleSection));
    raise_ws();
    /* a small section of this image */
    BYTE *mb = (BYTE *)GetModuleHandleW(NULL); IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(mb + ((IMAGE_DOS_HEADER *)mb)->e_lfanew);
    IMAGE_SECTION_HEADER *sh = IMAGE_FIRST_SECTION(nt); PVOID addr = NULL;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (sh[i].Misc.VirtualSize >= 16 && sh[i].Misc.VirtualSize <= 0x8000 && (sh[i].Characteristics & IMAGE_SCN_MEM_READ)) { addr = mb + sh[i].VirtualAddress; break; }
    if (!addr) { t_skip("no small section in the test image"); return; }
    EXPECT_EQ(UN(RtlUnlockModuleSection)(addr), S(0xC000002A));   /* not locked */
    NTSTATUS a = UN(RtlLockModuleSection)(addr);
    if (a == S(0xC00000A1)) { t_skip("locking refused: working set quota"); return; }
    EXPECT_EQ(a, 0); if (a != 0) return;
    EXPECT_EQ(UN(RtlLockModuleSection)(addr), 0);                 /* counted */
    NTSTATUS u1 = UN(RtlUnlockModuleSection)(addr);
    EXPECT_EQ(u1, 0);
    EXPECT_EQ(UN(RtlUnlockModuleSection)(addr), 0);   /* count reaches zero */
    EXPECT_EQ(UN(RtlUnlockModuleSection)(addr), S(0xC000002A));
    /* address not in any module section */
    EXPECT_EQ(UN(RtlLockModuleSection)((PVOID)0x10), S(0xC0000225));
}
TEST(rtl_cad_b_memory_zone_lock) {
    REQUIRE(UN(RtlCreateMemoryZone)); REQUIRE(UN(RtlDestroyMemoryZone)); REQUIRE(UN(RtlLockMemoryZone)); REQUIRE(UN(RtlUnlockMemoryZone)); raise_ws();
    PVOID z = NULL;
    NTSTATUS s = UN(RtlCreateMemoryZone)(&z, 0x10000, 0);
    EXPECT_EQ(s, 0); if (s != 0 || !z) return;
    EXPECT_EQ(UN(RtlUnlockMemoryZone)(z), S(0xC0000001));         /* not locked */
    NTSTATUS l = UN(RtlLockMemoryZone)(z);
    if (l != 0) { t_skip("RtlLockMemoryZone refused with %08lx", (unsigned long)l); UN(RtlDestroyMemoryZone)(z); return; }
    {
        EXPECT_EQ(UN(RtlLockMemoryZone)(z), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryZone)(z), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryZone)(z), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryZone)(z), S(0xC0000001));
    }
    EXPECT_EQ(UN(RtlDestroyMemoryZone)(z), 0);
}
TEST(rtl_cad_b_memory_block_lookaside_lock) {
    REQUIRE(UN(RtlCreateMemoryBlockLookaside)); REQUIRE(UN(RtlDestroyMemoryBlockLookaside));
    REQUIRE(UN(RtlLockMemoryBlockLookaside)); REQUIRE(UN(RtlUnlockMemoryBlockLookaside)); raise_ws();
    PVOID lk = NULL;
    NTSTATUS s = UN(RtlCreateMemoryBlockLookaside)(&lk, 0, 0x1000, 0x10, 0x100);
    EXPECT_EQ(s, 0); if (s != 0 || !lk) return;
    EXPECT_EQ(UN(RtlUnlockMemoryBlockLookaside)(lk), S(0xC0000001));
    NTSTATUS l = UN(RtlLockMemoryBlockLookaside)(lk);
    if (l != 0) { t_skip("RtlLockMemoryBlockLookaside refused with %08lx", (unsigned long)l); UN(RtlDestroyMemoryBlockLookaside)(lk); return; }
    {
        EXPECT_EQ(UN(RtlLockMemoryBlockLookaside)(lk), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryBlockLookaside)(lk), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryBlockLookaside)(lk), 0);
        EXPECT_EQ(UN(RtlUnlockMemoryBlockLookaside)(lk), S(0xC0000001));
    }
    EXPECT_EQ(UN(RtlDestroyMemoryBlockLookaside)(lk), 0);
}

/* ---------------- vectored handler removal ---------------- */
static volatile LONG veh_a, veh_b, vch_a, vch_b;
static LONG NTAPI veh_a_fn(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == 0xE0CADB01) { InterlockedIncrement(&veh_a); return EXCEPTION_CONTINUE_EXECUTION; } return EXCEPTION_CONTINUE_SEARCH; }
static LONG NTAPI veh_b_fn(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == 0xE0CADB01) { InterlockedIncrement(&veh_b); return EXCEPTION_CONTINUE_EXECUTION; } return EXCEPTION_CONTINUE_SEARCH; }
static LONG NTAPI vch_a_fn(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == 0xE0CADB01) InterlockedIncrement(&vch_a); return EXCEPTION_CONTINUE_SEARCH; }
static LONG NTAPI vch_b_fn(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == 0xE0CADB01) InterlockedIncrement(&vch_b); return EXCEPTION_CONTINUE_SEARCH; }
static void raise_it(void) { RaiseException(0xE0CADB01, 0, 0, NULL); }
TEST(rtl_cad_b_vectored_remove) {
    REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredExceptionHandler));
    REQUIRE(UN(RtlAddVectoredContinueHandler)); REQUIRE(UN(RtlRemoveVectoredContinueHandler));
    veh_a = veh_b = vch_a = vch_b = 0;
    PVOID ha = UN(RtlAddVectoredExceptionHandler)(1, veh_a_fn), hb = UN(RtlAddVectoredExceptionHandler)(0, veh_b_fn);
    CHECK(ha && hb && ha != hb); if (!ha || !hb) return;
    raise_it();
    EXPECT_EQ(veh_a, 1); EXPECT_EQ(veh_b, 0);     /* first-in-line handler consumed it */
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(ha), 1);
    raise_it();
    EXPECT_EQ(veh_a, 1); EXPECT_EQ(veh_b, 1);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(ha), 0);      /* already removed */
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hb), 1);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hb), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(NULL), 0);
    /* an exception handler handle is not a continue-handler handle */
    PVOID hc = UN(RtlAddVectoredContinueHandler)(1, vch_a_fn), hd = UN(RtlAddVectoredContinueHandler)(0, vch_b_fn);
    CHECK(hc && hd); if (!hc || !hd) return;
    PVOID he = UN(RtlAddVectoredExceptionHandler)(1, veh_a_fn);
    CHECK(he != NULL);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(he), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(hc), 0);
    raise_it();
    EXPECT_EQ(vch_a, 1); EXPECT_EQ(vch_b, 1);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hc), 1);
    raise_it();
    EXPECT_EQ(vch_a, 1); EXPECT_EQ(vch_b, 2);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hc), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(hd), 1);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)(NULL), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)(he), 1);
}

/* ---------------- boot status data ---------------- */
TEST(rtl_cad_b_boot_status_lock) {
    REQUIRE(UN(RtlLockBootStatusData)); REQUIRE(UN(RtlUnlockBootStatusData));
    HANDLE h = (HANDLE)(ULONG_PTR)0x1234;
    NTSTATUS s = UN(RtlLockBootStatusData)(&h);
    EXPECT_EQ(s, S(0xC00000BB));      /* STATUS_NOT_SUPPORTED, output handle cleared */
    EXPECT_EQ((ULONG_PTR)h, 0);
    UN(RtlUnlockBootStatusData)((HANDLE)(ULONG_PTR)0x1);   /* non-NULL handle: nothing to do */
}

/* ---------------- RtlEnumProcessHeaps ---------------- */
typedef struct { PVOID heaps[64]; int n; PVOID want; int seen_want; NTSTATUS ret; int stop_after; } HENUM;
static NTSTATUS NTAPI heap_cb(PVOID h, PVOID ctx) {
    HENUM *e = ctx; if (e->n < 64) e->heaps[e->n] = h; e->n++;
    if (h == e->want) e->seen_want = 1;
    return (e->stop_after && e->n >= e->stop_after) ? e->ret : 0;
}
TEST(rtl_cad_b_enum_process_heaps) {
    REQUIRE(UN(RtlEnumProcessHeaps));
    HANDLE mine = HeapCreate(0, 0x1000, 0);
    CHECK(mine != NULL); if (!mine) return;
    HENUM e; memset(&e, 0, sizeof e); e.want = mine;
    NTSTATUS s = UN(RtlEnumProcessHeaps)(heap_cb, &e);
    EXPECT_EQ(s, 0); CHECK(e.n >= 2); EXPECT_EQ(e.seen_want, 1);
    int found_proc = 0; for (int i = 0; i < e.n && i < 64; i++) if (e.heaps[i] == GetProcessHeap()) found_proc = 1;
    EXPECT_EQ(found_proc, 1);
    for (int i = 0; i < e.n && i < 64; i++) for (int j = i + 1; j < e.n && j < 64; j++) CHECK(e.heaps[i] != e.heaps[j]);
    /* a failing callback status stops the enumeration and is returned */
    memset(&e, 0, sizeof e); e.stop_after = 1; e.ret = S(0xC0001234);
    s = UN(RtlEnumProcessHeaps)(heap_cb, &e);
    EXPECT_EQ(s, S(0xC0001234)); EXPECT_EQ(e.n, 1);
    HeapDestroy(mine);
    memset(&e, 0, sizeof e); e.want = mine;
    UN(RtlEnumProcessHeaps)(heap_cb, &e); EXPECT_EQ(e.seen_want, 0);
}

/* ---------------- secure memory cache callback / feature notifications / WNF meta ---------------- */
static NTSTATUS NTAPI smc_cb(PVOID a, ULONG_PTR b) { return 0; }
TEST(rtl_cad_b_secure_memory_cache_callback) {
    REQUIRE(UN(RtlRegisterSecureMemoryCacheCallback)); REQUIRE(UN(RtlDeregisterSecureMemoryCacheCallback));
    NTSTATUS s = UN(RtlRegisterSecureMemoryCacheCallback)(smc_cb);
    t_note("RtlRegisterSecureMemoryCacheCallback status %08lx", (unsigned long)s);
    if (s != 0) { t_skip("registration refused with %08lx", (unsigned long)s); return; }
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(smc_cb), TRUE);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(smc_cb), FALSE);   /* no longer registered */
}
static VOID NTAPI feat_cb(PVOID ctx) { }
TEST(rtl_cad_b_feature_change_notification) {
    REQUIRE(UN(RtlRegisterFeatureConfigurationChangeNotification)); REQUIRE(UN(RtlUnregisterFeatureConfigurationChangeNotification));
    PVOID reg = NULL;
    NTSTATUS s = UN(RtlRegisterFeatureConfigurationChangeNotification)((PVOID)feat_cb, NULL, NULL, &reg);
    if (s != 0) { t_skip("feature notification registration returned %08lx", (unsigned long)s); return; }
    CHECK(reg != NULL);
    PVOID reg2 = NULL;
    EXPECT_EQ(UN(RtlRegisterFeatureConfigurationChangeNotification)((PVOID)feat_cb, NULL, NULL, &reg2), 0);
    CHECK(reg2 != NULL && reg2 != reg);
    UN(RtlUnregisterFeatureConfigurationChangeNotification)(reg2);
    UN(RtlUnregisterFeatureConfigurationChangeNotification)(reg);
}
TEST(rtl_cad_b_wnf_meta_register_invalid) {
    REQUIRE(UN(RtlRegisterForWnfMetaNotification));
    ULONGLONG name = 0x0D83063EA3BE0075ULL; PVOID sub = (PVOID)0x99;
    EXPECT_EQ(UN(RtlRegisterForWnfMetaNotification)(&sub, &name, 0, (PVOID)smc_cb, NULL), S(0xC000000D));
    EXPECT_EQ((ULONG_PTR)sub, 0);
    sub = (PVOID)0x99;
    EXPECT_EQ(UN(RtlRegisterForWnfMetaNotification)(&sub, &name, 0x1, (PVOID)smc_cb, NULL), S(0xC000000D));
    EXPECT_EQ((ULONG_PTR)sub, 0);
    sub = (PVOID)0x99;
    EXPECT_EQ(UN(RtlRegisterForWnfMetaNotification)(&sub, &name, 0x10, (PVOID)smc_cb, NULL), S(0xC000000D));
    EXPECT_EQ((ULONG_PTR)sub, 0);
}
