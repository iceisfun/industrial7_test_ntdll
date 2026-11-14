/* Thread pool configuration, cleanup groups and per-callback completion actions (Tp* exports).
 * Pools, work items and cleanup groups are created with TpAllocPool/TpAllocWork/... (not under test here)
 * so the target exports can be driven through real callbacks. TppRaiseInvalidParameter raises a
 * continuable STATUS_INVALID_PARAMETER exception; a vectored handler records and continues it.
 * See EVIDENCE.md. */
#include "t.h"

typedef VOID (NTAPI *WORKCB)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);
UDECL(NTSTATUS, TpAllocPool, (PTP_POOL *, PVOID));
UDECL(VOID, TpReleasePool, (PTP_POOL));
UDECL(VOID, TpSetPoolMaxThreads, (PTP_POOL, ULONG));
UDECL(NTSTATUS, TpAllocWork, (PTP_WORK *, WORKCB, PVOID, PTP_CALLBACK_ENVIRON));
UDECL(VOID, TpPostWork, (PTP_WORK));
UDECL(VOID, TpWaitForWork, (PTP_WORK, BOOLEAN));
UDECL(VOID, TpReleaseWork, (PTP_WORK));
UDECL(NTSTATUS, TpAllocCleanupGroup, (PTP_CLEANUP_GROUP *));
UDECL(VOID, TpReleaseCleanupGroup, (PTP_CLEANUP_GROUP));
UDECL(VOID, TpReleaseCleanupGroupMembers, (PTP_CLEANUP_GROUP, BOOLEAN, PVOID));
UDECL(NTSTATUS, TpSetPoolMinThreads, (PTP_POOL, LONG));
UDECL(VOID, TpSetPoolMaxThreadsSoftLimit, (PTP_POOL, LONG));
UDECL(VOID, TpSetDefaultPoolMaxThreads, (ULONG));
UDECL(NTSTATUS, TpQueryPoolStackInformation, (PTP_POOL, SIZE_T *));
UDECL(NTSTATUS, TpSetPoolStackInformation, (PTP_POOL, SIZE_T *));
UDECL(NTSTATUS, TpSetDefaultPoolStackInformation, (SIZE_T *));
UDECL(NTSTATUS, TpSetPoolThreadBasePriority, (PTP_POOL, ULONG));
UDECL(NTSTATUS, TpSetPoolWorkerThreadIdleTimeout, (PTP_POOL, LONGLONG));
UDECL(NTSTATUS, TpSetPoolThreadCpuSets, (PTP_POOL, PVOID, ULONG));
UDECL(VOID, TpTrimPools, (VOID));
UDECL(NTSTATUS, TpDisablePoolCallbackChecks, (PTP_POOL));
UDECL(VOID, TpCaptureCaller, (ULONG));
UDECL(VOID, TpCheckTerminateWorker, (HANDLE));
UDECL(VOID, TpCallbackLeaveCriticalSectionOnCompletion, (PTP_CALLBACK_INSTANCE, PCRITICAL_SECTION));
UDECL(VOID, TpCallbackReleaseMutexOnCompletion, (PTP_CALLBACK_INSTANCE, HANDLE));
UDECL(VOID, TpCallbackReleaseSemaphoreOnCompletion, (PTP_CALLBACK_INSTANCE, HANDLE, ULONG));
UDECL(VOID, TpCallbackUnloadDllOnCompletion, (PTP_CALLBACK_INSTANCE, PVOID));
UDECL(NTSTATUS, TpCallbackMayRunLong, (PTP_CALLBACK_INSTANCE));
UDECL(NTSTATUS, TpCallbackIndependent, (PTP_CALLBACK_INSTANCE));
UDECL(VOID, TpDisassociateCallback, (PTP_CALLBACK_INSTANCE));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_PARAM S(0xC000000D)

/* ---- invalid-parameter exception capture ---- */
static volatile LONG g_exc;
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xC000000D) {
        InterlockedIncrement(&g_exc);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static PVOID g_veh;
static void veh_on(void) { g_exc = 0; if (!g_veh) g_veh = AddVectoredExceptionHandler(1, veh); }
static void veh_off(void) { if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; } }
/* expected: number of invalid-parameter exceptions raised since the previous call */
static LONG exc_take(void) { return InterlockedExchange(&g_exc, 0); }

#define NEED_POOL() do { REQUIRE(UN(TpAllocPool)); REQUIRE(UN(TpReleasePool)); REQUIRE(UN(TpAllocWork)); REQUIRE(UN(TpPostWork)); \
    REQUIRE(UN(TpWaitForWork)); REQUIRE(UN(TpReleaseWork)); } while (0)

static void env_init(TP_CALLBACK_ENVIRON *e, PTP_POOL pool, PTP_CLEANUP_GROUP cg)
{
    memset(e, 0, sizeof *e);
    e->Version = 3;
    e->Pool = pool;
    e->CleanupGroup = cg;
    e->Size = sizeof *e;
}

TEST(pool_threads_and_priority)
{
    NEED_POOL();
    REQUIRE(UN(TpSetPoolMinThreads)); REQUIRE(UN(TpSetPoolMaxThreads)); REQUIRE(UN(TpSetPoolMaxThreadsSoftLimit));
    REQUIRE(UN(TpSetPoolThreadBasePriority)); REQUIRE(UN(TpSetPoolWorkerThreadIdleTimeout));
    REQUIRE(UN(TpDisablePoolCallbackChecks));
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    CHECK(pool != NULL);
    if (!pool) return;
    veh_on();
    UN(TpSetPoolMaxThreads)(pool, 4);
    EXPECT_EQ(exc_take(), 0);
    EXPECT_EQ(UN(TpSetPoolMinThreads)(pool, 1), 0);
    EXPECT_EQ(UN(TpSetPoolMinThreads)(pool, 0), 0);
    EXPECT_EQ(exc_take(), 0);
    /* negative min / NULL pool raise STATUS_INVALID_PARAMETER and return it */
    EXPECT_EQ(UN(TpSetPoolMinThreads)(pool, -1), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpSetPoolMinThreads)(NULL, 1), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    /* soft limit is void: valid call is silent, bad ones raise */
    UN(TpSetPoolMaxThreadsSoftLimit)(pool, 2);
    EXPECT_EQ(exc_take(), 0);
    UN(TpSetPoolMaxThreadsSoftLimit)(pool, -1);
    EXPECT_EQ(exc_take(), 1);
    UN(TpSetPoolMaxThreadsSoftLimit)(NULL, 1);
    EXPECT_EQ(exc_take(), 1);
    UN(TpSetPoolMaxThreads)(NULL, 1);
    EXPECT_EQ(exc_take(), 1);
    /* base priority: NULL pool is a silent error, no exception */
    EXPECT_EQ(UN(TpSetPoolThreadBasePriority)(NULL, 0), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 0);
    NTSTATUS st = UN(TpSetPoolThreadBasePriority)(pool, 0);
    t_note("TpSetPoolThreadBasePriority(pool, 0) -> 0x%lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    /* idle timeout: must be negative (relative) */
    EXPECT_EQ(UN(TpSetPoolWorkerThreadIdleTimeout)(pool, -50000000LL), 0);
    EXPECT_EQ(exc_take(), 0);
    EXPECT_EQ(UN(TpSetPoolWorkerThreadIdleTimeout)(pool, 0), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpSetPoolWorkerThreadIdleTimeout)(pool, 1000), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    EXPECT_EQ(UN(TpSetPoolWorkerThreadIdleTimeout)(NULL, -1000), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    /* disable callback checks */
    EXPECT_EQ(UN(TpDisablePoolCallbackChecks)(pool), 0);
    EXPECT_EQ(UN(TpDisablePoolCallbackChecks)(NULL), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 0);
    veh_off();
    UN(TpReleasePool)(pool);
}

TEST(pool_stack_information)
{
    NEED_POOL();
    REQUIRE(UN(TpQueryPoolStackInformation)); REQUIRE(UN(TpSetPoolStackInformation)); REQUIRE(UN(TpSetDefaultPoolStackInformation));
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    SIZE_T si[2] = { 0x1111, 0x2222 };
    NTSTATUS st = UN(TpQueryPoolStackInformation)(pool, si);
    EXPECT_EQ(st, 0);
    t_note("default pool stack reserve=0x%zx commit=0x%zx", si[0], si[1]);
    SIZE_T def[2] = { si[0], si[1] };
    EXPECT_EQ(UN(TpQueryPoolStackInformation)(NULL, si), ST_INV_PARAM);
    EXPECT_EQ(UN(TpQueryPoolStackInformation)(pool, NULL), ST_INV_PARAM);
    EXPECT_EQ(UN(TpSetPoolStackInformation)(NULL, si), ST_INV_PARAM);
    EXPECT_EQ(UN(TpSetPoolStackInformation)(pool, NULL), ST_INV_PARAM);
    EXPECT_EQ(UN(TpSetDefaultPoolStackInformation)(NULL), ST_INV_PARAM);
    SIZE_T want[2] = { 0x200000, 0x10000 };
    st = UN(TpSetPoolStackInformation)(pool, want);
    t_note("TpSetPoolStackInformation -> 0x%lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    SIZE_T got[2] = { 0, 0 };
    EXPECT_EQ(UN(TpQueryPoolStackInformation)(pool, got), 0);
    EXPECT_EQ(got[0], want[0]);
    EXPECT_EQ(got[1], want[1]);
    /* default pool stack info: only grows the global default; the call itself succeeds */
    SIZE_T dflt[2] = { 0x100000, 0x8000 };
    st = UN(TpSetDefaultPoolStackInformation)(dflt);
    EXPECT_EQ(st, 0);
    UN(TpReleasePool)(pool);
}

TEST(pool_misc_calls)
{
    NEED_POOL();
    REQUIRE(UN(TpTrimPools)); REQUIRE(UN(TpSetDefaultPoolMaxThreads)); REQUIRE(UN(TpSetPoolThreadCpuSets));
    REQUIRE(UN(TpCaptureCaller)); REQUIRE(UN(TpCheckTerminateWorker));
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    veh_on();
    UN(TpTrimPools)();
    UN(TpSetDefaultPoolMaxThreads)(1);   /* below the default limit: no effect */
    UN(TpSetDefaultPoolMaxThreads)(0);
    EXPECT_EQ(exc_take(), 0);
    UN(TpCaptureCaller)(1);              /* only records state on pool worker threads */
    UN(TpCaptureCaller)(0);
    UN(TpCaptureCaller)(99);
    EXPECT_EQ(exc_take(), 0);
    /* termination check on threads that are not pool workers returns normally */
    UN(TpCheckTerminateWorker)(NULL);
    HANDLE dup = NULL;
    BOOL ok = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CHECK(ok);
    UN(TpCheckTerminateWorker)(dup);
    if (dup) CloseHandle(dup);
    EXPECT_EQ(exc_take(), 0);
    /* cpu sets */
    ULONG dummy = 0;
    EXPECT_EQ(UN(TpSetPoolThreadCpuSets)(NULL, &dummy, 0), ST_INV_PARAM);
    EXPECT_EQ(UN(TpSetPoolThreadCpuSets)(pool, NULL, 0), ST_INV_PARAM);
    ULONG ids[1] = { 0 };
    NTSTATUS st = UN(TpSetPoolThreadCpuSets)(pool, ids, 0);
    t_note("TpSetPoolThreadCpuSets(count 0) -> 0x%lx", (unsigned long)st);
    veh_off();
    UN(TpReleasePool)(pool);
}

/* ---- cleanup groups ---- */
TEST(cleanup_group_alloc_release)
{
    REQUIRE(UN(TpAllocCleanupGroup)); REQUIRE(UN(TpReleaseCleanupGroup)); REQUIRE(UN(TpReleaseCleanupGroupMembers));
    PTP_CLEANUP_GROUP g = (PTP_CLEANUP_GROUP)(ULONG_PTR)0x1234;
    veh_on();
    EXPECT_EQ(UN(TpAllocCleanupGroup)(&g), 0);
    CHECK(g != NULL && g != (PTP_CLEANUP_GROUP)(ULONG_PTR)0x1234);
    PTP_CLEANUP_GROUP g2 = NULL;
    EXPECT_EQ(UN(TpAllocCleanupGroup)(&g2), 0);
    CHECK(g2 != NULL && g2 != g);
    EXPECT_EQ(exc_take(), 0);
    /* an empty group has no members: release members returns at once, repeatable */
    UN(TpReleaseCleanupGroupMembers)(g, FALSE, NULL);
    UN(TpReleaseCleanupGroupMembers)(g, TRUE, NULL);
    EXPECT_EQ(exc_take(), 0);
    UN(TpReleaseCleanupGroup)(g);
    UN(TpReleaseCleanupGroup)(g2);
    EXPECT_EQ(exc_take(), 0);
    /* invalid parameters */
    EXPECT_EQ(UN(TpAllocCleanupGroup)(NULL), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    UN(TpReleaseCleanupGroup)(NULL);
    EXPECT_EQ(exc_take(), 1);
    UN(TpReleaseCleanupGroupMembers)(NULL, FALSE, NULL);
    EXPECT_EQ(exc_take(), 1);
    veh_off();
}

static volatile LONG g_ran[8];
static volatile LONG g_cancelcb;
static PVOID g_cancel_obj[8], g_cancel_cleanup[8];
static HANDLE g_block;

static VOID NTAPI work_count_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PTP_WORK w)
{
    InterlockedIncrement(&g_ran[(ULONG_PTR)ctx & 7]);
}
static VOID NTAPI work_block_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PTP_WORK w)
{
    InterlockedIncrement(&g_ran[(ULONG_PTR)ctx & 7]);
    WaitForSingleObject(g_block, 5000);
}
static VOID NTAPI cancel_cb(PVOID obj, PVOID cleanup)
{
    LONG k = InterlockedIncrement(&g_cancelcb) - 1;
    if (k < 8) { g_cancel_obj[k] = obj; g_cancel_cleanup[k] = cleanup; }
}
static DWORD WINAPI setter_thr(LPVOID p) { Sleep(300); SetEvent((HANDLE)p); return 0; }

TEST(cleanup_group_members)
{
    NEED_POOL();
    REQUIRE(UN(TpAllocCleanupGroup)); REQUIRE(UN(TpReleaseCleanupGroup)); REQUIRE(UN(TpReleaseCleanupGroupMembers));
    REQUIRE(UN(TpSetPoolMaxThreads));
    PTP_POOL pool = NULL; PTP_CLEANUP_GROUP g = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    EXPECT_EQ(UN(TpAllocCleanupGroup)(&g), 0);
    if (!pool || !g) return;
    UN(TpSetPoolMaxThreads)(pool, 1);
    TP_CALLBACK_ENVIRON env; env_init(&env, pool, g);
    /* 1: wait for finished callbacks (no cancel) */
    memset((void *)g_ran, 0, sizeof g_ran);
    PTP_WORK w1 = NULL, w2 = NULL;
    EXPECT_EQ(UN(TpAllocWork)(&w1, work_count_cb, (PVOID)1, &env), 0);
    EXPECT_EQ(UN(TpAllocWork)(&w2, work_count_cb, (PVOID)2, &env), 0);
    UN(TpPostWork)(w1); UN(TpPostWork)(w2); UN(TpPostWork)(w2);
    UN(TpReleaseCleanupGroupMembers)(g, FALSE, NULL);
    EXPECT_EQ(g_ran[1], 1);
    EXPECT_EQ(g_ran[2], 2);
    /* members were released with the group call: the group is empty and reusable */
    PTP_WORK w3 = NULL;
    EXPECT_EQ(UN(TpAllocWork)(&w3, work_count_cb, (PVOID)3, &env), 0);
    UN(TpPostWork)(w3);
    UN(TpReleaseCleanupGroupMembers)(g, FALSE, NULL);
    EXPECT_EQ(g_ran[3], 1);

    /* 2: cancel pending callbacks; the running one is waited for. One pool thread, blocked by w4. */
    g_block = CreateEventW(NULL, TRUE, FALSE, NULL);
    env.CleanupGroupCancelCallback = cancel_cb;
    g_cancelcb = 0;
    PTP_WORK w4 = NULL, w5 = NULL;
    EXPECT_EQ(UN(TpAllocWork)(&w4, work_block_cb, (PVOID)4, &env), 0);
    EXPECT_EQ(UN(TpAllocWork)(&w5, work_count_cb, (PVOID)5, &env), 0);
    UN(TpPostWork)(w4);
    DWORD t0 = GetTickCount();
    while (g_ran[4] == 0 && GetTickCount() - t0 < 3000) Sleep(5);
    EXPECT_EQ(g_ran[4], 1);
    UN(TpPostWork)(w5);
    HANDLE th = CreateThread(NULL, 0, setter_thr, g_block, 0, NULL);
    UN(TpReleaseCleanupGroupMembers)(g, TRUE, (PVOID)0xABCD);
    WaitForSingleObject(th, 3000); CloseHandle(th);
    EXPECT_EQ(g_ran[4], 1);
    EXPECT_EQ(g_ran[5], 0);   /* cancelled before it could run */
    t_note("cancel callback invoked %ld times", g_cancelcb);
    /* the cancel callback runs for every member: the running one (4) and the cancelled pending one (5) */
    EXPECT_EQ(g_cancelcb, 2);
    int saw4 = 0, saw5 = 0;
    for (LONG k = 0; k < g_cancelcb && k < 8; k++) {
        if (g_cancel_obj[k] == (PVOID)4) saw4 = 1;
        if (g_cancel_obj[k] == (PVOID)5) saw5 = 1;
        CHECK(g_cancel_cleanup[k] == (PVOID)0xABCD);
    }
    CHECK(saw4 && saw5);
    CloseHandle(g_block);
    UN(TpReleaseCleanupGroup)(g);
    UN(TpReleasePool)(pool);
}

/* ---- callback instance completion actions ---- */
typedef struct {
    int op;
    HANDLE h;               /* semaphore / mutex */
    CRITICAL_SECTION *cs;
    HMODULE dll;
    HANDLE ev;
    volatile LONG done;
    NTSTATUS st;
    LONG exc;
    LONGLONG t_ret;
} INST;
enum { OP_SEM = 1, OP_MUTEX, OP_CS, OP_DLL, OP_MAYRUN, OP_INDEP, OP_ERRS, OP_DISASSOC };
static INST g_inst;

static VOID NTAPI inst_cb(PTP_CALLBACK_INSTANCE i, PVOID ctx, PTP_WORK w)
{
    INST *p = (INST *)ctx;
    switch (p->op) {
    case OP_SEM: UN(TpCallbackReleaseSemaphoreOnCompletion)(i, p->h, 2); break;
    case OP_MUTEX: WaitForSingleObject(p->h, 2000); UN(TpCallbackReleaseMutexOnCompletion)(i, p->h); break;
    case OP_CS: EnterCriticalSection(p->cs); UN(TpCallbackLeaveCriticalSectionOnCompletion)(i, p->cs); break;
    case OP_DLL: UN(TpCallbackUnloadDllOnCompletion)(i, p->dll); break;
    case OP_MAYRUN: p->st = UN(TpCallbackMayRunLong)(i); break;
    case OP_INDEP: p->st = UN(TpCallbackIndependent)(i); break;
    case OP_DISASSOC:
        UN(TpDisassociateCallback)(i);
        WaitForSingleObject(p->ev, 2500);
        break;
    case OP_ERRS: {
        HANDLE sem = CreateSemaphoreW(NULL, 0, 10, NULL);
        g_exc = 0;
        UN(TpCallbackReleaseSemaphoreOnCompletion)(i, NULL, 1);
        UN(TpCallbackReleaseSemaphoreOnCompletion)(i, INVALID_HANDLE_VALUE, 1);
        UN(TpCallbackReleaseSemaphoreOnCompletion)(i, sem, 0);
        UN(TpCallbackReleaseSemaphoreOnCompletion)(NULL, sem, 1);
        UN(TpCallbackReleaseMutexOnCompletion)(i, NULL);
        UN(TpCallbackReleaseMutexOnCompletion)(NULL, sem);
        UN(TpCallbackLeaveCriticalSectionOnCompletion)(i, NULL);
        UN(TpCallbackLeaveCriticalSectionOnCompletion)(NULL, p->cs);
        UN(TpCallbackUnloadDllOnCompletion)(i, NULL);
        UN(TpCallbackUnloadDllOnCompletion)(NULL, (PVOID)p->dll);
        p->exc = InterlockedExchange(&g_exc, 0);
        /* a second registration of the same kind is also rejected */
        UN(TpCallbackReleaseSemaphoreOnCompletion)(i, sem, 1);
        UN(TpCallbackReleaseSemaphoreOnCompletion)(i, sem, 1);
        p->t_ret = InterlockedExchange(&g_exc, 0);
        p->h = sem;   /* closed by the test after the callback has completed */
        break; }
    }
    InterlockedExchange(&p->done, 1);
}

static BOOL run_inst(int op, PTP_POOL pool, BOOL wait_work)
{
    PTP_WORK w = NULL;
    TP_CALLBACK_ENVIRON env; env_init(&env, pool, NULL);
    g_inst.op = op; g_inst.done = 0;
    if (UN(TpAllocWork)(&w, inst_cb, &g_inst, &env) != 0) return FALSE;
    UN(TpPostWork)(w);
    if (wait_work) UN(TpWaitForWork)(w, FALSE);
    DWORD t0 = GetTickCount();
    while (!g_inst.done && GetTickCount() - t0 < 5000) Sleep(5);
    if (wait_work) UN(TpWaitForWork)(w, FALSE);
    UN(TpReleaseWork)(w);
    return g_inst.done != 0;
}

#define NEED_INST() do { NEED_POOL(); REQUIRE(UN(TpCallbackReleaseSemaphoreOnCompletion)); REQUIRE(UN(TpCallbackReleaseMutexOnCompletion)); \
    REQUIRE(UN(TpCallbackLeaveCriticalSectionOnCompletion)); REQUIRE(UN(TpCallbackUnloadDllOnCompletion)); } while (0)

TEST(callback_release_semaphore)
{
    NEED_INST();
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.h = CreateSemaphoreW(NULL, 0, 10, NULL);
    CHECK(run_inst(OP_SEM, pool, TRUE));
    /* released exactly 2 when the callback returned */
    EXPECT_EQ(WaitForSingleObject(g_inst.h, 1000), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(g_inst.h, 1000), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(g_inst.h, 50), WAIT_TIMEOUT);
    CloseHandle(g_inst.h);
    UN(TpReleasePool)(pool);
}

TEST(callback_release_mutex)
{
    NEED_INST();
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.h = CreateMutexW(NULL, FALSE, NULL);
    CHECK(run_inst(OP_MUTEX, pool, TRUE));
    /* the worker owned the mutex during the callback; it was released afterwards (not abandoned) */
    EXPECT_EQ(WaitForSingleObject(g_inst.h, 2000), WAIT_OBJECT_0);
    ReleaseMutex(g_inst.h);
    CloseHandle(g_inst.h);
    UN(TpReleasePool)(pool);
}

TEST(callback_leave_critical_section)
{
    NEED_INST();
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    CRITICAL_SECTION cs; InitializeCriticalSection(&cs);
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.cs = &cs;
    CHECK(run_inst(OP_CS, pool, TRUE));
    BOOL got = TryEnterCriticalSection(&cs);
    CHECK(got);
    if (got) { CHECK(cs.RecursionCount == 1); LeaveCriticalSection(&cs); }
    DeleteCriticalSection(&cs);
    UN(TpReleasePool)(pool);
}

TEST(callback_unload_dll)
{
    NEED_INST();
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    if (GetModuleHandleW(L"dbghelp.dll")) { t_skip("dbghelp.dll already loaded in this process"); UN(TpReleasePool)(pool); return; }
    HMODULE m = LoadLibraryW(L"dbghelp.dll");
    if (!m) { t_skip("dbghelp.dll not loadable"); UN(TpReleasePool)(pool); return; }
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.dll = m;
    CHECK(run_inst(OP_DLL, pool, TRUE));
    DWORD t0 = GetTickCount();
    while (GetModuleHandleW(L"dbghelp.dll") && GetTickCount() - t0 < 3000) Sleep(10);
    CHECK(GetModuleHandleW(L"dbghelp.dll") == NULL);
    UN(TpReleasePool)(pool);
}

TEST(callback_instance_errors)
{
    NEED_INST();
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    CRITICAL_SECTION cs; InitializeCriticalSection(&cs);
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.cs = &cs; g_inst.dll = GetModuleHandleW(L"kernel32.dll");
    veh_on();
    CHECK(run_inst(OP_ERRS, pool, TRUE));
    veh_off();
    if (g_inst.h) CloseHandle(g_inst.h);
    /* ten invalid registrations, ten exceptions */
    EXPECT_EQ(g_inst.exc, 10);
    /* of two identical registrations the second one is rejected */
    EXPECT_EQ(g_inst.t_ret, 1);
    DeleteCriticalSection(&cs);
    UN(TpReleasePool)(pool);
}

TEST(callback_may_run_long_independent)
{
    NEED_INST();
    REQUIRE(UN(TpCallbackMayRunLong)); REQUIRE(UN(TpCallbackIndependent));
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    UN(TpSetPoolMaxThreads)(pool, 4);
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.st = S(0x5a5a5a5a);
    CHECK(run_inst(OP_MAYRUN, pool, TRUE));
    t_note("TpCallbackMayRunLong in callback -> 0x%lx", (unsigned long)g_inst.st);
    CHECK(g_inst.st == 0 || g_inst.st == 1 || g_inst.st == S(0xC00000BB));
    g_inst.st = S(0x5a5a5a5a);
    CHECK(run_inst(OP_INDEP, pool, TRUE));
    t_note("TpCallbackIndependent in callback -> 0x%lx", (unsigned long)g_inst.st);
    EXPECT_EQ(g_inst.st, 0);
    veh_on();
    EXPECT_EQ(UN(TpCallbackIndependent)(NULL), ST_INV_PARAM);
    EXPECT_EQ(exc_take(), 1);
    veh_off();
    UN(TpReleasePool)(pool);
}

TEST(callback_disassociate)
{
    NEED_INST();
    REQUIRE(UN(TpDisassociateCallback));
    PTP_POOL pool = NULL;
    EXPECT_EQ(UN(TpAllocPool)(&pool, NULL), 0);
    if (!pool) return;
    memset(&g_inst, 0, sizeof g_inst);
    g_inst.ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    PTP_WORK w = NULL;
    TP_CALLBACK_ENVIRON env; env_init(&env, pool, NULL);
    g_inst.op = OP_DISASSOC;
    EXPECT_EQ(UN(TpAllocWork)(&w, inst_cb, &g_inst, &env), 0);
    UN(TpPostWork)(w);
    DWORD t0 = GetTickCount();
    UN(TpWaitForWork)(w, FALSE);
    DWORD el = GetTickCount() - t0;
    t_note("TpWaitForWork returned after %lu ms with the callback still blocked", el);
    CHECK(g_inst.done == 0);
    CHECK(el < 2000);
    SetEvent(g_inst.ev);
    t0 = GetTickCount();
    while (!g_inst.done && GetTickCount() - t0 < 3000) Sleep(5);
    UN(TpReleaseWork)(w);
    CloseHandle(g_inst.ev);
    UN(TpReleasePool)(pool);
}
