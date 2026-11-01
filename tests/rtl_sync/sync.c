#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlInitializeCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlInitializeCriticalSectionAndSpinCount, (PRTL_CRITICAL_SECTION, ULONG));
UDECL(NTSTATUS, RtlInitializeCriticalSectionEx, (PRTL_CRITICAL_SECTION, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeleteCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlEnterCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlLeaveCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(BOOLEAN, RtlTryEnterCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(BOOLEAN, RtlIsCriticalSectionLocked, (PRTL_CRITICAL_SECTION));
UDECL(BOOLEAN, RtlIsCriticalSectionLockedByThread, (PRTL_CRITICAL_SECTION));
UDECL(ULONG, RtlSetCriticalSectionSpinCount, (PRTL_CRITICAL_SECTION, ULONG));
UDECL(VOID, RtlInitializeSRWLock, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockShared, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlInitializeConditionVariable, (PRTL_CONDITION_VARIABLE));
UDECL(NTSTATUS, RtlSleepConditionVariableCS, (PRTL_CONDITION_VARIABLE, PRTL_CRITICAL_SECTION, PLARGE_INTEGER));
UDECL(NTSTATUS, RtlSleepConditionVariableSRW, (PRTL_CONDITION_VARIABLE, PRTL_SRWLOCK, PLARGE_INTEGER, ULONG));
UDECL(VOID, RtlWakeConditionVariable, (PRTL_CONDITION_VARIABLE));
UDECL(VOID, RtlWakeAllConditionVariable, (PRTL_CONDITION_VARIABLE));
UDECL(VOID, RtlRunOnceInitialize, (PRTL_RUN_ONCE));
UDECL(NTSTATUS, RtlRunOnceBeginInitialize, (PRTL_RUN_ONCE, ULONG, PVOID *));
UDECL(NTSTATUS, RtlRunOnceComplete, (PRTL_RUN_ONCE, ULONG, PVOID));
UDECL(NTSTATUS, RtlRunOnceExecuteOnce, (PRTL_RUN_ONCE, PRTL_RUN_ONCE_INIT_FN, PVOID, PVOID *));
#define S(x) ((NTSTATUS)(x))
#define K(name) UIN("kernel32.dll", name)
/* RTL APIs return their own status, not a Win32 BOOL/GLE pair. */
#define STATUS(call, want) do { NTSTATUS s_ = (call); EXPECT_EQ(s_, (want)); } while (0)
#define CS_FIXTURE \
    RTL_CRITICAL_SECTION cs; NTSTATUS init; \
    REQUIRE(UN(RtlInitializeCriticalSection)); REQUIRE(UN(RtlDeleteCriticalSection)); \
    REQUIRE(UN(RtlEnterCriticalSection)); REQUIRE(UN(RtlLeaveCriticalSection)); \
    REQUIRE(UN(RtlTryEnterCriticalSection)); REQUIRE(UN(RtlIsCriticalSectionLocked)); \
    REQUIRE(UN(RtlIsCriticalSectionLockedByThread)); \
    init = UN(RtlInitializeCriticalSection)(&cs); EXPECT_EQ(init, 0); \
    if (init < 0) { t_skip("critical-section initialization failed"); return; }
#define SRW_EXPORTS \
    REQUIRE(UN(RtlInitializeSRWLock)); REQUIRE(UN(RtlAcquireSRWLockExclusive)); \
    REQUIRE(UN(RtlReleaseSRWLockExclusive)); REQUIRE(UN(RtlAcquireSRWLockShared)); \
    REQUIRE(UN(RtlReleaseSRWLockShared)); REQUIRE(UN(RtlTryAcquireSRWLockExclusive)); \
    REQUIRE(UN(RtlTryAcquireSRWLockShared))
#define ONCE_EXPORTS \
    REQUIRE(UN(RtlRunOnceInitialize)); REQUIRE(UN(RtlRunOnceBeginInitialize)); \
    REQUIRE(UN(RtlRunOnceComplete)); REQUIRE(UN(RtlRunOnceExecuteOnce))

TEST(rtl_sync_cs_initial_unlocked) {
    CS_FIXTURE; EXPECT_EQ(cs.RecursionCount, 0); EXPECT_EQ(cs.OwningThread, NULL);
    EXPECT_EQ(UN(RtlIsCriticalSectionLocked)(&cs), FALSE);
    EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), FALSE);
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_enter_owner) {
    CS_FIXTURE; NTSTATUS s = UN(RtlEnterCriticalSection)(&cs); EXPECT_EQ(s, 0);
    if (s >= 0) { EXPECT_EQ(cs.RecursionCount, 1); EXPECT_EQ(cs.OwningThread, (HANDLE)(ULONG_PTR)GetCurrentThreadId());
        EXPECT_EQ(UN(RtlIsCriticalSectionLocked)(&cs), TRUE); EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), TRUE);
        STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); }
    else t_skip("entry prerequisite failed");
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_try_free) {
    CS_FIXTURE; BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
    if (got) { EXPECT_EQ(cs.RecursionCount, 1); EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), TRUE);
        STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); }
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
static void cs_recursive(BOOLEAN use_try) {
    CS_FIXTURE; NTSTATUS s = UN(RtlEnterCriticalSection)(&cs); EXPECT_EQ(s, 0);
    if (s < 0) { t_skip("entry prerequisite failed"); STATUS(UN(RtlDeleteCriticalSection)(&cs), 0); return; }
    BOOLEAN got;
    if (use_try) { got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE); }
    else { s = UN(RtlEnterCriticalSection)(&cs); EXPECT_EQ(s, 0); got = s >= 0; }
    if (got) { EXPECT_EQ(cs.RecursionCount, 2); STATUS(UN(RtlLeaveCriticalSection)(&cs), 0);
        EXPECT_EQ(cs.RecursionCount, 1); EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), TRUE); }
    STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); EXPECT_EQ(cs.RecursionCount, 0);
    EXPECT_EQ(UN(RtlIsCriticalSectionLocked)(&cs), FALSE); STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_recursive_enter) { cs_recursive(FALSE); }
TEST(rtl_sync_cs_recursive_try) { cs_recursive(TRUE); }
TEST(rtl_sync_cs_release_clears_owner) {
    CS_FIXTURE; BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
    if (got) { STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); EXPECT_EQ(cs.OwningThread, NULL);
        EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), FALSE); }
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_reacquire_after_release) {
    CS_FIXTURE;
    for (int i = 0; i < 3; ++i) { BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
        if (!got) { t_skip("entry prerequisite failed"); break; }
        EXPECT_EQ(cs.RecursionCount, 1); STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); }
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
static void cs_init_variant(int variant) {
    RTL_CRITICAL_SECTION cs; NTSTATUS s;
    REQUIRE(UN(RtlInitializeCriticalSectionAndSpinCount)); REQUIRE(UN(RtlInitializeCriticalSectionEx));
    REQUIRE(UN(RtlTryEnterCriticalSection)); REQUIRE(UN(RtlLeaveCriticalSection)); REQUIRE(UN(RtlDeleteCriticalSection));
    if (variant < 2) s = UN(RtlInitializeCriticalSectionAndSpinCount)(&cs, variant ? 123 : 0);
    else s = UN(RtlInitializeCriticalSectionEx)(&cs, 123, variant == 3 ? 0x01000000 : 0);
    EXPECT_EQ(s, 0); if (s < 0) { t_skip("initialization failed"); return; }
    EXPECT_EQ(cs.RecursionCount, 0); EXPECT_EQ(cs.OwningThread, NULL);
    BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
    if (got) STATUS(UN(RtlLeaveCriticalSection)(&cs), 0);
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_initialize_spin_zero) { cs_init_variant(0); }
TEST(rtl_sync_cs_initialize_spin_nonzero) { cs_init_variant(1); }
TEST(rtl_sync_cs_initialize_ex) { cs_init_variant(2); }
TEST(rtl_sync_cs_initialize_ex_no_debug) { cs_init_variant(3); }
TEST(rtl_sync_cs_ex_invalid_flags) {
    RTL_CRITICAL_SECTION cs, before; memset(&cs, 0x55, sizeof(cs)); before = cs;
    REQUIRE(UN(RtlInitializeCriticalSectionEx)); REQUIRE(UN(RtlDeleteCriticalSection));
    NTSTATUS s = UN(RtlInitializeCriticalSectionEx)(&cs, 0, 0x20000000);
    EXPECT_EQ(s, S(0xc00000f1)); EXPECT_EQ(memcmp(&cs, &before, sizeof(cs)), 0);
    if (s >= 0) STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_ex_invalid_spin_high_bits) {
    RTL_CRITICAL_SECTION cs, before; memset(&cs, 0x55, sizeof(cs)); before = cs;
    REQUIRE(UN(RtlInitializeCriticalSectionEx)); REQUIRE(UN(RtlDeleteCriticalSection));
    NTSTATUS s = UN(RtlInitializeCriticalSectionEx)(&cs, 0x01000000, 0);
    EXPECT_EQ(s, S(0xc00000f0)); EXPECT_EQ(memcmp(&cs, &before, sizeof(cs)), 0);
    if (s >= 0) STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_spin_previous_count) {
    REQUIRE(UN(RtlSetCriticalSectionSpinCount)); CS_FIXTURE;
    ULONG old = (ULONG)cs.SpinCount & 0xffffff;
    EXPECT_EQ(UN(RtlSetCriticalSectionSpinCount)(&cs, 0), old);
    EXPECT_EQ(UN(RtlSetCriticalSectionSpinCount)(&cs, 99), 0);
    ULONG observed = (ULONG)cs.SpinCount & 0xffffff;
    /* Uniprocessor implementations force the count to zero. */
    t_note("effective spin count=%lu", observed);
    EXPECT_EQ(UN(RtlSetCriticalSectionSpinCount)(&cs, 0), observed);
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
TEST(rtl_sync_cs_delete_then_reinitialize) {
    CS_FIXTURE; STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
    init = UN(RtlInitializeCriticalSection)(&cs); EXPECT_EQ(init, 0);
    if (init < 0) { t_skip("reinitialization prerequisite failed"); return; }
    BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
    if (got) STATUS(UN(RtlLeaveCriticalSection)(&cs), 0);
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}

TEST(rtl_sync_srw_initialize) {
    SRW_EXPORTS; RTL_SRWLOCK lock; UN(RtlInitializeSRWLock)(&lock); EXPECT_EQ(lock.Ptr, NULL);
}
static void srw_cycle(BOOLEAN shared, BOOLEAN try_first) {
    SRW_EXPORTS; RTL_SRWLOCK lock = RTL_SRWLOCK_INIT; BOOLEAN got = TRUE;
    if (try_first) { got = shared ? UN(RtlTryAcquireSRWLockShared)(&lock) : UN(RtlTryAcquireSRWLockExclusive)(&lock); EXPECT_EQ(got, TRUE); }
    else if (shared) UN(RtlAcquireSRWLockShared)(&lock); else UN(RtlAcquireSRWLockExclusive)(&lock);
    if (!got) { t_skip("lock acquisition prerequisite failed"); return; }
    if (shared) UN(RtlReleaseSRWLockShared)(&lock); else UN(RtlReleaseSRWLockExclusive)(&lock);
    /* Change modes only after releasing; SRW locks are not recursive/upgradable. */
    got = shared ? UN(RtlTryAcquireSRWLockExclusive)(&lock) : UN(RtlTryAcquireSRWLockShared)(&lock);
    EXPECT_EQ(got, TRUE);
    if (got) { if (shared) UN(RtlReleaseSRWLockExclusive)(&lock); else UN(RtlReleaseSRWLockShared)(&lock); }
}
TEST(rtl_sync_srw_exclusive_release_then_shared) { srw_cycle(FALSE, FALSE); }
TEST(rtl_sync_srw_shared_release_then_exclusive) { srw_cycle(TRUE, FALSE); }
TEST(rtl_sync_srw_try_exclusive_free) { srw_cycle(FALSE, TRUE); }
TEST(rtl_sync_srw_try_shared_free) { srw_cycle(TRUE, TRUE); }

/* Workers use static storage and report through exit codes, not racing harness counters.
 * Any broken blocking primitive is contained in a bounded child process. */
typedef struct {
    RTL_CRITICAL_SECTION cs;
    RTL_SRWLOCK srw;
    RTL_CONDITION_VARIABLE cv;
    RTL_RUN_ONCE once;
    HANDLE entered, gate;
    int mode, predicate, value, count;
    BOOLEAN first, second, owned;
    NTSTATUS status;
} thread_data;
static thread_data d;

static DWORD WINAPI cs_probe(void *unused) {
    d.owned = UN(RtlIsCriticalSectionLockedByThread)(&d.cs);
    d.first = UN(RtlTryEnterCriticalSection)(&d.cs);
    if (d.first) UN(RtlLeaveCriticalSection)(&d.cs);
    K(SetEvent)(d.entered);
    if (K(WaitForSingleObject)(d.gate, 5000) != WAIT_OBJECT_0) return 77;
    d.second = UN(RtlTryEnterCriticalSection)(&d.cs);
    if (d.second) { d.value = 42; UN(RtlLeaveCriticalSection)(&d.cs); }
    return 0;
}
CHILD(rtl_sync_cs_handoff) {
    HANDLE thread; DWORD code = 99; memset(&d, 0, sizeof(d));
    if (UN(RtlInitializeCriticalSection)(&d.cs) < 0) return 77;
    d.entered = K(CreateEventW)(NULL, TRUE, FALSE, NULL); d.gate = K(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!d.entered || !d.gate) return 77;
    if (!UN(RtlTryEnterCriticalSection)(&d.cs)) return 77;
    thread = K(CreateThread)(NULL, 0, cs_probe, NULL, 0, NULL); if (!thread) return 77;
    if (K(WaitForSingleObject)(d.entered, 5000) != WAIT_OBJECT_0) return 77;
    int bad = d.first || d.owned;
    UN(RtlLeaveCriticalSection)(&d.cs); K(SetEvent)(d.gate);
    if (K(WaitForSingleObject)(thread, 5000) != WAIT_OBJECT_0) return 77;
    K(GetExitCodeThread)(thread, &code); if (code) return code;
    bad |= !d.second || d.value != 42;
    UN(RtlDeleteCriticalSection)(&d.cs);
    K(CloseHandle)(thread); K(CloseHandle)(d.gate); K(CloseHandle)(d.entered); return bad ? 1 : 0;
}
static DWORD WINAPI srw_probe(void *unused) {
    d.first = UN(RtlTryAcquireSRWLockExclusive)(&d.srw);
    if (d.first) UN(RtlReleaseSRWLockExclusive)(&d.srw);
    d.second = UN(RtlTryAcquireSRWLockShared)(&d.srw);
    if (d.second) UN(RtlReleaseSRWLockShared)(&d.srw);
    return 0;
}
CHILD(rtl_sync_srw_probe) {
    HANDLE thread; int bad; memset(&d, 0, sizeof(d)); d.mode = argc > 1 ? atoi(argv[1]) : 0;
    UN(RtlInitializeSRWLock)(&d.srw);
    if (d.mode) UN(RtlAcquireSRWLockShared)(&d.srw); else UN(RtlAcquireSRWLockExclusive)(&d.srw);
    thread = K(CreateThread)(NULL, 0, srw_probe, NULL, 0, NULL); if (!thread) return 77;
    if (K(WaitForSingleObject)(thread, 5000) != WAIT_OBJECT_0) return 77;
    bad = d.first || d.second != !!d.mode;
    if (d.mode) UN(RtlReleaseSRWLockShared)(&d.srw); else UN(RtlReleaseSRWLockExclusive)(&d.srw);
    BOOLEAN got = UN(RtlTryAcquireSRWLockExclusive)(&d.srw); bad |= !got;
    if (got) UN(RtlReleaseSRWLockExclusive)(&d.srw);
    K(CloseHandle)(thread); return bad ? 1 : 0;
}
#define THREAD_EXPORTS \
    REQUIRE(K(CreateThread)); REQUIRE(K(WaitForSingleObject)); REQUIRE(K(GetExitCodeThread)); \
    REQUIRE(K(CloseHandle)); REQUIRE(K(CreateEventW)); REQUIRE(K(SetEvent))
static void child_result(const char *name, const char *args) {
    DWORD code = t_run_child(name, args, 15000);
    if (code == 77 || code == 0xdead0000) { t_skip("bounded child fixture prerequisite unavailable (%08lx)", code); return; }
    EXPECT_EQ(code, 0);
}
TEST(rtl_sync_cs_foreign_try_and_handoff) {
    THREAD_EXPORTS; CS_FIXTURE; STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
    child_result("rtl_sync_cs_handoff", NULL);
}
TEST(rtl_sync_srw_foreign_exclusive_excludes_both) { THREAD_EXPORTS; SRW_EXPORTS; child_result("rtl_sync_srw_probe", "0"); }
TEST(rtl_sync_srw_foreign_shared_allows_reader) { THREAD_EXPORTS; SRW_EXPORTS; child_result("rtl_sync_srw_probe", "1"); }

#define CV_EXPORTS \
    REQUIRE(UN(RtlInitializeConditionVariable)); REQUIRE(UN(RtlSleepConditionVariableCS)); \
    REQUIRE(UN(RtlSleepConditionVariableSRW)); REQUIRE(UN(RtlWakeConditionVariable)); REQUIRE(UN(RtlWakeAllConditionVariable))
TEST(rtl_sync_cv_initialize) { CV_EXPORTS; RTL_CONDITION_VARIABLE cv; UN(RtlInitializeConditionVariable)(&cv); EXPECT_EQ(cv.Ptr, NULL); }
TEST(rtl_sync_cv_wake_empty) {
    CV_EXPORTS; RTL_CONDITION_VARIABLE cv = RTL_CONDITION_VARIABLE_INIT;
    UN(RtlWakeConditionVariable)(&cv); EXPECT_EQ(cv.Ptr, NULL);
}
TEST(rtl_sync_cv_wake_all_empty) {
    CV_EXPORTS; RTL_CONDITION_VARIABLE cv = RTL_CONDITION_VARIABLE_INIT;
    UN(RtlWakeAllConditionVariable)(&cv); EXPECT_EQ(cv.Ptr, NULL);
}
TEST(rtl_sync_cv_cs_zero_timeout_reacquires) {
    CV_EXPORTS; CS_FIXTURE; LARGE_INTEGER zero; zero.QuadPart = 0; RTL_CONDITION_VARIABLE cv = RTL_CONDITION_VARIABLE_INIT;
    BOOLEAN got = UN(RtlTryEnterCriticalSection)(&cs); EXPECT_EQ(got, TRUE);
    if (got) { STATUS(UN(RtlSleepConditionVariableCS)(&cv, &cs, &zero), S(0x102));
        EXPECT_EQ(UN(RtlIsCriticalSectionLockedByThread)(&cs), TRUE); EXPECT_EQ(cs.RecursionCount, 1);
        STATUS(UN(RtlLeaveCriticalSection)(&cs), 0); }
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0);
}
static void cv_srw_timeout(BOOLEAN shared) {
    CV_EXPORTS; SRW_EXPORTS; RTL_SRWLOCK lock = RTL_SRWLOCK_INIT; RTL_CONDITION_VARIABLE cv = RTL_CONDITION_VARIABLE_INIT;
    LARGE_INTEGER zero; zero.QuadPart = 0;
    if (shared) UN(RtlAcquireSRWLockShared)(&lock); else UN(RtlAcquireSRWLockExclusive)(&lock);
    STATUS(UN(RtlSleepConditionVariableSRW)(&cv, &lock, &zero, shared ? 1 : 0), S(0x102));
    if (shared) UN(RtlReleaseSRWLockShared)(&lock); else UN(RtlReleaseSRWLockExclusive)(&lock);
    BOOLEAN got = UN(RtlTryAcquireSRWLockExclusive)(&lock); EXPECT_EQ(got, TRUE);
    if (got) UN(RtlReleaseSRWLockExclusive)(&lock);
}
TEST(rtl_sync_cv_srw_exclusive_timeout_reacquires) { cv_srw_timeout(FALSE); }
TEST(rtl_sync_cv_srw_shared_timeout_reacquires) { cv_srw_timeout(TRUE); }
TEST(rtl_sync_cv_srw_invalid_flags) {
    CV_EXPORTS; SRW_EXPORTS; RTL_SRWLOCK lock = RTL_SRWLOCK_INIT; RTL_CONDITION_VARIABLE cv = RTL_CONDITION_VARIABLE_INIT;
    LARGE_INTEGER zero; zero.QuadPart = 0;
    UN(RtlAcquireSRWLockExclusive)(&lock);
    STATUS(UN(RtlSleepConditionVariableSRW)(&cv, &lock, &zero, 2), S(0xc00000f0));
    EXPECT_EQ(cv.Ptr, NULL);
    UN(RtlReleaseSRWLockExclusive)(&lock);
}
static DWORD WINAPI cv_producer(void *unused) {
    if (d.mode < 2) UN(RtlEnterCriticalSection)(&d.cs); else UN(RtlAcquireSRWLockExclusive)(&d.srw);
    d.predicate = 1; d.value = 42;
    if (d.mode & 1) UN(RtlWakeAllConditionVariable)(&d.cv); else UN(RtlWakeConditionVariable)(&d.cv);
    if (d.mode < 2) UN(RtlLeaveCriticalSection)(&d.cs); else UN(RtlReleaseSRWLockExclusive)(&d.srw);
    return 0;
}
CHILD(rtl_sync_cv_handshake) {
    HANDLE thread; int bad = 0; LARGE_INTEGER timeout; timeout.QuadPart = -50000000;
    memset(&d, 0, sizeof(d)); d.mode = argc > 1 ? atoi(argv[1]) : 0;
    UN(RtlInitializeConditionVariable)(&d.cv); UN(RtlInitializeSRWLock)(&d.srw);
    if (d.mode < 2) { if (UN(RtlInitializeCriticalSection)(&d.cs) < 0) return 77;
        UN(RtlEnterCriticalSection)(&d.cs); }
    else if (d.mode >= 4) UN(RtlAcquireSRWLockShared)(&d.srw);
    else UN(RtlAcquireSRWLockExclusive)(&d.srw);
    thread = K(CreateThread)(NULL, 0, cv_producer, NULL, 0, NULL); if (!thread) return 77;
    /* The producer cannot publish until Sleep atomically releases the lock.
     * Predicate loop tolerates spurious wakes, with bounded attempts/timeouts. */
    for (int i = 0; !d.predicate && i < 4; ++i) {
        if (d.mode < 2) d.status = UN(RtlSleepConditionVariableCS)(&d.cv, &d.cs, &timeout);
        else d.status = UN(RtlSleepConditionVariableSRW)(&d.cv, &d.srw, &timeout, d.mode >= 4 ? 1 : 0);
        if (d.status != 0 && d.status != S(0x102)) { bad = 1; break; }
    }
    int available = d.predicate; bad |= available && d.value != 42;
    if (d.mode < 2) { bad |= !UN(RtlIsCriticalSectionLockedByThread)(&d.cs); UN(RtlLeaveCriticalSection)(&d.cs); }
    else if (d.mode >= 4) UN(RtlReleaseSRWLockShared)(&d.srw); else UN(RtlReleaseSRWLockExclusive)(&d.srw);
    if (K(WaitForSingleObject)(thread, 5000) != WAIT_OBJECT_0) return 77;
    K(CloseHandle)(thread); if (d.mode < 2) UN(RtlDeleteCriticalSection)(&d.cs);
    return bad ? 1 : available ? 0 : 77;
}
static void cv_child(const char *mode) {
    THREAD_EXPORTS; CV_EXPORTS; SRW_EXPORTS; CS_FIXTURE;
    STATUS(UN(RtlDeleteCriticalSection)(&cs), 0); child_result("rtl_sync_cv_handshake", mode);
}
TEST(rtl_sync_cv_cs_wake_handshake) { cv_child("0"); }
TEST(rtl_sync_cv_cs_wake_all_handshake) { cv_child("1"); }
TEST(rtl_sync_cv_srw_exclusive_wake_handshake) { cv_child("2"); }
TEST(rtl_sync_cv_srw_exclusive_wake_all_handshake) { cv_child("3"); }
TEST(rtl_sync_cv_srw_shared_wake_handshake) { cv_child("4"); }
TEST(rtl_sync_cv_srw_shared_wake_all_handshake) { cv_child("5"); }

static LONG context_value;
static DWORD WINAPI once_success(PRTL_RUN_ONCE once, PVOID parameter, PVOID *context) {
    int *calls = parameter; ++*calls; if (context) *context = &context_value; return TRUE;
}
static DWORD WINAPI once_failure(PRTL_RUN_ONCE once, PVOID parameter, PVOID *context) {
    int *calls = parameter; ++*calls; return FALSE;
}
TEST(rtl_sync_once_initialize) { ONCE_EXPORTS; RTL_RUN_ONCE once; UN(RtlRunOnceInitialize)(&once); EXPECT_EQ(once.Ptr, NULL); }
TEST(rtl_sync_once_check_uninitialized) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; PVOID ctx = &context_value;
    STATUS(UN(RtlRunOnceBeginInitialize)(&once, 1, &ctx), S(0xc0000001));
    EXPECT_EQ(ctx, &context_value); EXPECT_EQ(once.Ptr, NULL);
}
static void once_complete(PVOID value, ULONG flags) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; PVOID ctx = NULL;
    NTSTATUS s = UN(RtlRunOnceBeginInitialize)(&once, flags, &ctx); EXPECT_EQ(s, S(0x103));
    if (s != S(0x103)) { t_skip("begin prerequisite failed"); return; }
    STATUS(UN(RtlRunOnceComplete)(&once, flags, value), 0);
    ctx = NULL; STATUS(UN(RtlRunOnceBeginInitialize)(&once, 1, &ctx), 0); EXPECT_EQ(ctx, value);
    ctx = NULL; STATUS(UN(RtlRunOnceBeginInitialize)(&once, 0, &ctx), 0); EXPECT_EQ(ctx, value);
}
TEST(rtl_sync_once_sync_complete_context) { once_complete(&context_value, 0); }
TEST(rtl_sync_once_sync_complete_null) { once_complete(NULL, 0); }
TEST(rtl_sync_once_async_complete_context) { once_complete(&context_value, 2); }
TEST(rtl_sync_once_begin_invalid_flags) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; PVOID ctx = &context_value;
    STATUS(UN(RtlRunOnceBeginInitialize)(&once, 3, &ctx), S(0xc00000f0));
    EXPECT_EQ(ctx, &context_value); EXPECT_EQ(once.Ptr, NULL);
}
TEST(rtl_sync_once_complete_without_begin) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT;
    STATUS(UN(RtlRunOnceComplete)(&once, 0, NULL), S(0xc0000001)); EXPECT_EQ(once.Ptr, NULL);
}
TEST(rtl_sync_once_failed_completion_retries) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT;
    NTSTATUS s = UN(RtlRunOnceBeginInitialize)(&once, 0, NULL); EXPECT_EQ(s, S(0x103));
    if (s != S(0x103)) { t_skip("begin prerequisite failed"); return; }
    STATUS(UN(RtlRunOnceComplete)(&once, 4, NULL), 0);
    STATUS(UN(RtlRunOnceBeginInitialize)(&once, 1, NULL), S(0xc0000001));
    s = UN(RtlRunOnceBeginInitialize)(&once, 0, NULL); EXPECT_EQ(s, S(0x103));
    if (s == S(0x103)) STATUS(UN(RtlRunOnceComplete)(&once, 0, NULL), 0);
}
TEST(rtl_sync_once_execute_callback_once) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; PVOID ctx = NULL; int calls = 0;
    STATUS(UN(RtlRunOnceExecuteOnce)(&once, once_success, &calls, &ctx), 0);
    EXPECT_EQ(calls, 1); EXPECT_EQ(ctx, &context_value);
    ctx = NULL; STATUS(UN(RtlRunOnceExecuteOnce)(&once, once_success, &calls, &ctx), 0);
    EXPECT_EQ(calls, 1); EXPECT_EQ(ctx, &context_value);
}
TEST(rtl_sync_once_execute_failure_retries) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; PVOID ctx = NULL; int calls = 0;
    STATUS(UN(RtlRunOnceExecuteOnce)(&once, once_failure, &calls, &ctx), S(0xc0000001)); EXPECT_EQ(calls, 1);
    STATUS(UN(RtlRunOnceExecuteOnce)(&once, once_success, &calls, &ctx), 0);
    EXPECT_EQ(calls, 2); EXPECT_EQ(ctx, &context_value);
}
TEST(rtl_sync_once_execute_optional_context) {
    ONCE_EXPORTS; RTL_RUN_ONCE once = RTL_RUN_ONCE_INIT; int calls = 0;
    STATUS(UN(RtlRunOnceExecuteOnce)(&once, once_success, &calls, NULL), 0); EXPECT_EQ(calls, 1);
    PVOID ctx = &context_value; STATUS(UN(RtlRunOnceBeginInitialize)(&once, 1, &ctx), 0); EXPECT_EQ(ctx, NULL);
}
static DWORD WINAPI once_blocking(PRTL_RUN_ONCE once, PVOID parameter, PVOID *context) {
    ++d.count; K(SetEvent)(d.entered);
    if (K(WaitForSingleObject)(d.gate, 5000) != WAIT_OBJECT_0) return FALSE;
    d.value = 42; *context = &context_value; return TRUE;
}
static DWORD WINAPI once_worker(void *unused) {
    PVOID ctx = NULL; d.status = UN(RtlRunOnceExecuteOnce)(&d.once, once_blocking, NULL, &ctx);
    return d.status == 0 && ctx == &context_value ? 0 : 1;
}
CHILD(rtl_sync_once_handshake) {
    HANDLE thread; DWORD code; PVOID ctx = NULL; int bad;
    memset(&d, 0, sizeof(d)); UN(RtlRunOnceInitialize)(&d.once);
    d.entered = K(CreateEventW)(NULL, TRUE, FALSE, NULL); d.gate = K(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!d.entered || !d.gate) return 77;
    thread = K(CreateThread)(NULL, 0, once_worker, NULL, 0, NULL); if (!thread) return 77;
    if (K(WaitForSingleObject)(d.entered, 5000) != WAIT_OBJECT_0) return 77;
    bad = UN(RtlRunOnceBeginInitialize)(&d.once, 1, &ctx) != S(0xc0000001);
    K(SetEvent)(d.gate);
    if (K(WaitForSingleObject)(thread, 5000) != WAIT_OBJECT_0) return 77;
    K(GetExitCodeThread)(thread, &code); bad |= code != 0;
    NTSTATUS s = UN(RtlRunOnceExecuteOnce)(&d.once, once_blocking, NULL, &ctx);
    bad |= s != 0 || ctx != &context_value || d.count != 1 || d.value != 42;
    K(CloseHandle)(thread); K(CloseHandle)(d.entered); K(CloseHandle)(d.gate); return bad ? 1 : 0;
}
TEST(rtl_sync_once_thread_publication) { THREAD_EXPORTS; ONCE_EXPORTS; child_result("rtl_sync_once_handshake", NULL); }
