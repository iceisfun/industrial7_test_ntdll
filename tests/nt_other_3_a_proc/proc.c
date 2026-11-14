/* Process, thread, token, event and system-information services:
 * NtGetNextProcess/Thread, NtGetCurrentProcessorNumber(Ex), NtIsProcessInJob, NtGetContextThread,
 * NtQueueApcThread(Ex), NtPulseEvent, NtPrivilegeCheck, NtImpersonateAnonymousToken, NtImpersonateThread,
 * NtMakeTemporaryObject/NtMakePermanentObject, NtPowerInformation, NtRaiseException, NLS/MUI queries. */
#include "t.h"

UDECL(NTSTATUS, NtGetNextProcess, (HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE));
UDECL(NTSTATUS, NtGetNextThread, (HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE));
UDECL(ULONG, NtGetCurrentProcessorNumber, (void));
UDECL(ULONG, NtGetCurrentProcessorNumberEx, (PROCESSOR_NUMBER *));
UDECL(NTSTATUS, NtIsProcessInJob, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtGetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtQueueApcThread, (HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtQueueApcThreadEx, (HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtPulseEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtPrivilegeCheck, (HANDLE, PPRIVILEGE_SET, PBOOLEAN));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtImpersonateAnonymousToken, (HANDLE));
UDECL(NTSTATUS, NtImpersonateThread, (HANDLE, HANDLE, PSECURITY_QUALITY_OF_SERVICE));
UDECL(NTSTATUS, NtMakeTemporaryObject, (HANDLE));
UDECL(NTSTATUS, NtMakePermanentObject, (HANDLE));
UDECL(NTSTATUS, NtPowerInformation, (ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtRaiseException, (PEXCEPTION_RECORD, PCONTEXT, BOOLEAN));
UDECL(NTSTATUS, NtListenPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtImpersonateClientOfPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtGetNlsSectionPtr, (ULONG, ULONG, PVOID, PVOID *, PSIZE_T));
UDECL(NTSTATUS, NtIsUILanguageComitted, (void));
UDECL(NTSTATUS, NtGetMUIRegistryInfo, (ULONG, PULONG, PVOID));
UDECL(BOOLEAN, NtIsSystemResumeAutomatic, (void));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(VOID, RtlCaptureContext, (PCONTEXT));

#define XS(x) ((NTSTATUS)(x))
#define N(f) UN(f)
#define BADH ((HANDLE)(LONG_PTR)-77)
#define SELFP ((HANDLE)(LONG_PTR)-1)
#define SELFT ((HANDLE)(LONG_PTR)-2)

TEST(other3a_proc_nt_zw_aliases)
{
    static const char *n[] = { "GetNextProcess", "GetNextThread", "GetCurrentProcessorNumber", "GetCurrentProcessorNumberEx",
        "IsProcessInJob", "GetContextThread", "QueueApcThread", "QueueApcThreadEx", "PulseEvent", "PrivilegeCheck",
        "ImpersonateAnonymousToken", "ImpersonateThread", "CreatePort", "MakeTemporaryObject", "MakePermanentObject", "PowerInformation",
        "RaiseException", "ListenPort", "ImpersonateClientOfPort", "GetNlsSectionPtr", "IsUILanguageComitted",
        "GetMUIRegistryInfo", "IsSystemResumeAutomatic" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "%s / %s", a, b);
    }
}

/* ---- NtGetNextProcess / NtGetNextThread ---------------------------------- */
TEST(other3a_get_next_process_enumerates_self)
{
    HANDLE cur = NULL, nxt; NTSTATUS s; int n = 0, found = 0; DWORD me = GetCurrentProcessId(); REQUIRE(N(NtGetNextProcess)); REQUIRE(N(NtClose));
    for (;;) {
        nxt = NULL;
        s = N(NtGetNextProcess)(cur, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &nxt);
        if (cur) N(NtClose)(cur);
        if (s != 0) break;
        CHECK(nxt != NULL); if (!nxt) break;
        if (GetProcessId(nxt) == me) found = 1;
        cur = nxt;
        if (++n > 2000) { N(NtClose)(cur); cur = NULL; break; }
    }
    EXPECT_EQ(s, XS(0x8000001A));                                     /* STATUS_NO_MORE_ENTRIES */
    CHECK(n >= 2); CHECK(found);
}
TEST(other3a_get_next_process_reverse_and_attributes)
{
    HANDLE a = NULL, b = NULL; DWORD fl = 0; NTSTATUS s; REQUIRE(N(NtGetNextProcess)); REQUIRE(N(NtClose));
    s = N(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, OBJ_INHERIT, 0, &a);
    EXPECT_EQ(s, 0);
    if (a) { GetHandleInformation(a, &fl); CHECK(fl & HANDLE_FLAG_INHERIT); N(NtClose)(a); }
    s = N(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 1 /* reverse */, &b);
    EXPECT_EQ(s, 0);
    if (b) { GetHandleInformation(b, &fl); CHECK(!(fl & HANDLE_FLAG_INHERIT)); N(NtClose)(b); }
    a = (HANDLE)0x1234;
    EXPECT_EQ(N(NtGetNextProcess)(BADH, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &a), XS(0xC0000008));
    EXPECT_EQ(N(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0x80, &a), XS(0xC000000D));
}
TEST(other3a_get_next_thread_enumerates_own_threads)
{
    HANDLE cur = NULL, nxt; NTSTATUS s; int n = 0, found = 0; DWORD me = GetCurrentThreadId(); REQUIRE(N(NtGetNextThread)); REQUIRE(N(NtClose));
    for (;;) {
        nxt = NULL;
        s = N(NtGetNextThread)(SELFP, cur, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt);
        if (cur) N(NtClose)(cur);
        if (s != 0) break;
        CHECK(nxt != NULL); if (!nxt) break;
        if (GetThreadId(nxt) == me) found = 1;
        cur = nxt;
        if (++n > 1000) { N(NtClose)(cur); cur = NULL; break; }
    }
    EXPECT_EQ(s, XS(0x8000001A));
    CHECK(n >= 1); CHECK(found);
}
static DWORD WINAPI park(LPVOID p) { WaitForSingleObject((HANDLE)p, 20000); return 0; }
TEST(other3a_get_next_thread_sees_new_thread_and_reverse)
{
    HANDLE stop, th, cur = NULL, nxt; NTSTATUS s; int n = 0, found = 0; DWORD tid; REQUIRE(N(NtGetNextThread)); REQUIRE(N(NtClose));
    stop = CreateEventA(NULL, TRUE, FALSE, NULL); th = CreateThread(NULL, 0, park, stop, 0, &tid); CHECK(stop && th);
    if (th) {
        for (;;) {
            nxt = NULL;
            s = N(NtGetNextThread)(SELFP, cur, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt);
            if (cur) N(NtClose)(cur);
            if (s != 0) break;
            if (GetThreadId(nxt) == tid) found = 1;
            cur = nxt; if (++n > 1000) { N(NtClose)(cur); break; }
        }
        CHECK(found); CHECK(n >= 2);
        for (ULONG fl = 1; fl < 8; fl++) {
            nxt = NULL; s = N(NtGetNextThread)(SELFP, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, fl, &nxt);
            EXPECT_EQ(s, XS(0xC000000D));                                 /* only flags value 0 is accepted for threads (observed) */
        }
        EXPECT_EQ(N(NtGetNextThread)(BADH, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt), XS(0xC0000008));
        EXPECT_EQ(N(NtGetNextThread)(SELFP, BADH, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt), XS(0xC0000008));
    }
    if (stop) SetEvent(stop);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (stop) CloseHandle(stop);
}

/* ---- processor number ------------------------------------------------------ */
TEST(other3a_current_processor_number)
{
    PROCESSOR_NUMBER pn; DWORD cnt = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); ULONG r; REQUIRE(N(NtGetCurrentProcessorNumber)); REQUIRE(N(NtGetCurrentProcessorNumberEx));
    r = N(NtGetCurrentProcessorNumber)();
    CHECKF(r < cnt, "processor %lu of %lu", (unsigned long)r, (unsigned long)cnt);
    memset(&pn, 0xcc, sizeof pn);
    N(NtGetCurrentProcessorNumberEx)(&pn);
    CHECK(pn.Group < GetActiveProcessorGroupCount()); CHECK(pn.Number < 64); EXPECT_EQ(pn.Reserved, 0);
    {   DWORD_PTR old = SetThreadAffinityMask(GetCurrentThread(), 1);          /* pinned to processor 0 */
        if (old) {
            Sleep(1);
            EXPECT_EQ(N(NtGetCurrentProcessorNumber)(), 0);
            N(NtGetCurrentProcessorNumberEx)(&pn); EXPECT_EQ(pn.Number, 0);
            SetThreadAffinityMask(GetCurrentThread(), old);
        } else t_note("cannot pin thread");
    }
}

/* ---- NtIsProcessInJob ------------------------------------------------------- */
CHILD(o3a_sleeper) { Sleep(60000); return 0; }
TEST(other3a_is_process_in_job)
{
    PROCESS_INFORMATION pi; HANDLE job, job2; NTSTATUS s; REQUIRE(N(NtIsProcessInJob));
    job = CreateJobObjectA(NULL, NULL); job2 = CreateJobObjectA(NULL, NULL); CHECK(job && job2);
    if (!job || !job2) goto out;
    memset(&pi, 0, sizeof pi);
    if (!t_spawn_child("o3a_sleeper", NULL, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, NULL, FALSE, NULL, &pi)) {
        if (!t_spawn_child("o3a_sleeper", NULL, CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi)) { t_skip("cannot spawn child"); goto out; }
    }
    if (!pi.hProcess) { t_skip("cannot spawn child"); goto out; }
    s = N(NtIsProcessInJob)(pi.hProcess, job);
    EXPECT_EQ(s, XS(0x123));                                                   /* STATUS_PROCESS_NOT_IN_JOB */
    if (AssignProcessToJobObject(job, pi.hProcess)) {
        EXPECT_EQ(N(NtIsProcessInJob)(pi.hProcess, job), XS(0x124));           /* STATUS_PROCESS_IN_JOB */
        EXPECT_EQ(N(NtIsProcessInJob)(pi.hProcess, job2), XS(0x123));
        EXPECT_EQ(N(NtIsProcessInJob)(pi.hProcess, NULL), XS(0x124));          /* any job */
    } else t_skip("child cannot be assigned to a job (%lu)", GetLastError());
    EXPECT_EQ(N(NtIsProcessInJob)(BADH, job), XS(0xC0000008));
    EXPECT_EQ(N(NtIsProcessInJob)(pi.hProcess, BADH), XS(0xC0000008));
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
out:
    if (job) CloseHandle(job);
    if (job2) CloseHandle(job2);
}

/* ---- NtGetContextThread ----------------------------------------------------- */
TEST(other3a_get_context_thread_suspended_thread)
{
    HANDLE stop, th, ro; CONTEXT *c; BYTE raw[sizeof(CONTEXT) + 16]; NTSTATUS s; DWORD tid; REQUIRE(N(NtGetContextThread));
    c = (CONTEXT *)(((ULONG_PTR)raw + 15) & ~(ULONG_PTR)15);
    stop = CreateEventA(NULL, TRUE, FALSE, NULL); th = CreateThread(NULL, 0, park, stop, 0, &tid); CHECK(stop && th);
    if (th) {
        Sleep(50);                                                              /* let it reach its wait */
        SuspendThread(th);
        memset(c, 0xcc, sizeof *c); c->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        s = N(NtGetContextThread)(th, c);
        EXPECT_EQ(s, 0);
        CHECK(c->Rip != 0); CHECK(c->Rsp != 0 && (c->Rsp & 7) == 0);
        EXPECT_EQ(c->ContextFlags & (CONTEXT_CONTROL | CONTEXT_INTEGER), CONTEXT_CONTROL | CONTEXT_INTEGER);
        EXPECT_EQ(c->SegCs, 0x33); CHECK((c->EFlags & 0x200) != 0);                    /* user code segment, interrupts enabled */
        memset(c, 0xcc, sizeof *c); c->ContextFlags = CONTEXT_CONTROL;
        s = N(NtGetContextThread)(th, c);
        EXPECT_EQ(s, 0); CHECK(c->Rip != 0); EXPECT_EQ(c->Rax, 0xcccccccccccccccc);   /* integer registers not requested: untouched */
        EXPECT_EQ(N(NtGetContextThread)(BADH, c), XS(0xC0000008));
        ro = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
        if (ro) { c->ContextFlags = CONTEXT_CONTROL; EXPECT_EQ(N(NtGetContextThread)(ro, c), XS(0xC0000022)); CloseHandle(ro); }
        ResumeThread(th);
    }
    if (stop) SetEvent(stop);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (stop) CloseHandle(stop);
}

static volatile LONG g_spin_stop;
static DWORD WINAPI spin(LPVOID p) { DWORD t0 = GetTickCount(); (void)p; while (!g_spin_stop && GetTickCount() - t0 < 20000) YieldProcessor(); return 0; }
/* ---- NtQueueApcThread / Ex --------------------------------------------------- */
static volatile LONG g_apc_hits; static volatile ULONG_PTR g_apc_a[3];
static VOID NTAPI apc_fn(ULONG_PTR a, ULONG_PTR b, ULONG_PTR c) { g_apc_a[0] = a; g_apc_a[1] = b; g_apc_a[2] = c; InterlockedIncrement(&g_apc_hits); }
static DWORD WINAPI alertable(LPVOID p) { for (int i = 0; i < 100 && !g_apc_hits; i++) SleepEx(100, TRUE); (void)p; return 0; }
TEST(other3a_queue_apc_thread_delivers_arguments)
{
    HANDLE th, ro; DWORD tid; NTSTATUS s; REQUIRE(N(NtQueueApcThread));
    g_apc_hits = 0; memset((void *)g_apc_a, 0, sizeof g_apc_a);
    th = CreateThread(NULL, 0, alertable, NULL, 0, &tid); CHECK(th != NULL); if (!th) return;
    ro = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (ro) { EXPECT_EQ(N(NtQueueApcThread)(ro, (PVOID)apc_fn, (PVOID)1, (PVOID)2, (PVOID)3), XS(0xC0000022)); CloseHandle(ro); }   /* needs THREAD_SET_CONTEXT */
    EXPECT_EQ(N(NtQueueApcThread)(BADH, (PVOID)apc_fn, NULL, NULL, NULL), XS(0xC0000008));
    s = N(NtQueueApcThread)(th, (PVOID)apc_fn, (PVOID)0x11, (PVOID)0x22, (PVOID)0x33);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(g_apc_hits, 1); EXPECT_EQ(g_apc_a[0], 0x11); EXPECT_EQ(g_apc_a[1], 0x22); EXPECT_EQ(g_apc_a[2], 0x33);
    CloseHandle(th);
}
TEST(other3a_queue_apc_thread_ex_normal_and_special)
{
    HANDLE th, stop; DWORD tid; NTSTATUS s; REQUIRE(N(NtQueueApcThreadEx));
    g_apc_hits = 0;
    th = CreateThread(NULL, 0, alertable, NULL, 0, &tid); CHECK(th != NULL); if (!th) return;
    s = N(NtQueueApcThreadEx)(th, NULL, (PVOID)apc_fn, (PVOID)7, (PVOID)8, (PVOID)9);       /* no reserve object: ordinary user APC */
    EXPECT_EQ(s, 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(g_apc_hits, 1); EXPECT_EQ(g_apc_a[0], 7); EXPECT_EQ(g_apc_a[2], 9);
    EXPECT_EQ(N(NtQueueApcThreadEx)(BADH, NULL, (PVOID)apc_fn, NULL, NULL, NULL), XS(0xC0000008));
    CloseHandle(th);
    /* special user APC (reserve handle value 1): runs without an alertable wait */
    g_apc_hits = 0; g_spin_stop = 0; stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, spin, NULL, 0, &tid); CHECK(th && stop);
    if (th && stop) {
        Sleep(50);
        s = N(NtQueueApcThreadEx)(th, (HANDLE)1, (PVOID)apc_fn, (PVOID)4, (PVOID)5, (PVOID)6);
        if (s == 0) {
            for (int i = 0; i < 100 && !g_apc_hits; i++) Sleep(20);
            EXPECT_EQ(g_apc_hits, 1); EXPECT_EQ(g_apc_a[0], 4); EXPECT_EQ(g_apc_a[1], 5);
        } else EXPECT_EQ(s, XS(0xC000000D));                   /* only reached where special APCs are unsupported */
    }
    g_spin_stop = 1;
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (stop) CloseHandle(stop);
}

/* ---- NtPulseEvent --------------------------------------------------------- */
static DWORD WINAPI evwait(LPVOID p) { return WaitForSingleObject((HANDLE)p, 5000); }
TEST(other3a_pulse_event_releases_waiters_and_leaves_unsignaled)
{
    HANDLE ev = NULL, th; LONG prev = 77; NTSTATUS s; DWORD tid, code = 99; REQUIRE(N(NtPulseEvent)); REQUIRE(N(NtCreateEvent));
    s = N(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */, FALSE); EXPECT_EQ(s, 0); if (!ev) return;
    s = N(NtPulseEvent)(ev, &prev);
    EXPECT_EQ(s, 0); EXPECT_EQ(prev, 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);                          /* pulse with no waiter leaves it clear */
    th = CreateThread(NULL, 0, evwait, ev, 0, &tid); CHECK(th != NULL);
    if (th) {
        int i;
        for (i = 0; i < 100; i++) {                                                  /* pulse until the waiter has arrived and is released */
            prev = 77; s = N(NtPulseEvent)(ev, &prev);
            if (s != 0 || prev != 0) break;
            if (WaitForSingleObject(th, 50) == WAIT_OBJECT_0) break;
        }
        EXPECT_EQ(s, 0); EXPECT_EQ(prev, 0);
        EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
        GetExitCodeThread(th, &code); EXPECT_EQ(code, WAIT_OBJECT_0);             /* waiter released by the pulse */
        EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        CloseHandle(th);
    }
    SetEvent(ev); prev = 77;
    EXPECT_EQ(N(NtPulseEvent)(ev, &prev), 0); EXPECT_EQ(prev, 1);                /* previous state reported; event ends unsignaled */
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    EXPECT_EQ(N(NtPulseEvent)(ev, NULL), 0);
    N(NtClose)(ev);
}
TEST(other3a_pulse_event_errors)
{
    HANDLE ev = NULL, ro = NULL, mtx; LONG prev; REQUIRE(N(NtPulseEvent)); REQUIRE(N(NtCreateEvent)); REQUIRE(N(NtDuplicateObject));
    EXPECT_EQ(N(NtPulseEvent)(BADH, &prev), XS(0xC0000008));
    EXPECT_EQ(N(NtPulseEvent)(NULL, &prev), XS(0xC0000008));
    mtx = CreateMutexA(NULL, FALSE, NULL);
    if (mtx) { EXPECT_EQ(N(NtPulseEvent)(mtx, &prev), XS(0xC0000024)); CloseHandle(mtx); }          /* STATUS_OBJECT_TYPE_MISMATCH */
    N(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    if (ev) {
        EXPECT_EQ(N(NtDuplicateObject)(SELFP, ev, SELFP, &ro, SYNCHRONIZE, 0, 0), 0);
        if (ro) { EXPECT_EQ(N(NtPulseEvent)(ro, &prev), XS(0xC0000022)); N(NtClose)(ro); }          /* no EVENT_MODIFY_STATE */
        N(NtClose)(ev);
    }
}

/* ---- NtPrivilegeCheck ------------------------------------------------------- */
typedef struct { ULONG Count, Control; LUID_AND_ATTRIBUTES P[2]; } pset;
static HANDLE imp_token(void)
{
    HANDLE p = NULL, d = NULL; OBJECT_ATTRIBUTES oa; SECURITY_QUALITY_OF_SERVICE q;
    if (N(NtOpenProcessToken)(SELFP, TOKEN_DUPLICATE | TOKEN_QUERY, &p) < 0) return NULL;
    q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation; q.ContextTrackingMode = 0; q.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL); oa.SecurityQualityOfService = &q;
    if (N(NtDuplicateToken)(p, TOKEN_QUERY, &oa, FALSE, 2 /* TokenImpersonation */, &d) < 0) d = NULL;
    N(NtClose)(p);
    return d;
}
TEST(other3a_privilege_check_default_privileges)
{
    HANDLE t; pset ps; BOOLEAN r = 0xcc; NTSTATUS s; LUID notify = { 23, 0 }, debug = { 7, 0 };
    REQUIRE(N(NtPrivilegeCheck)); REQUIRE(N(NtOpenProcessToken)); REQUIRE(N(NtDuplicateToken)); REQUIRE(N(NtClose));
    t = imp_token(); CHECK(t != NULL); if (!t) return;
    memset(&ps, 0, sizeof ps); ps.Count = 1; ps.Control = 0; ps.P[0].Luid = notify;                   /* SeChangeNotifyPrivilege */
    s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, TRUE);
    CHECK(ps.P[0].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS);                                          /* output: attribute set when held and enabled */
    memset(&ps, 0, sizeof ps); ps.Count = 1; ps.Control = PRIVILEGE_SET_ALL_NECESSARY; ps.P[0].Luid = debug;   /* SeTcbPrivilege: never held by an interactive user */
    r = 0xcc; s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, FALSE);
    CHECK(!(ps.P[0].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS));
    memset(&ps, 0, sizeof ps); ps.Count = 2; ps.Control = 0; ps.P[0].Luid = debug; ps.P[1].Luid = notify;     /* any-of: notify suffices */
    r = 0xcc; s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, TRUE);
    memset(&ps, 0, sizeof ps); ps.Count = 2; ps.Control = PRIVILEGE_SET_ALL_NECESSARY; ps.P[0].Luid = debug; ps.P[1].Luid = notify;
    r = 0xcc; s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, FALSE);
    memset(&ps, 0, sizeof ps); ps.Count = 0;
    r = 0xcc; s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, FALSE);                                          /* empty set: nothing satisfied (observed) */
    N(NtClose)(t);
}
TEST(other3a_privilege_check_errors)
{
    HANDLE t, p = NULL; pset ps; BOOLEAN r; NTSTATUS s; LUID notify = { 23, 0 };
    REQUIRE(N(NtPrivilegeCheck)); REQUIRE(N(NtOpenProcessToken)); REQUIRE(N(NtClose));
    memset(&ps, 0, sizeof ps); ps.Count = 1; ps.P[0].Luid = notify;
    EXPECT_EQ(N(NtPrivilegeCheck)(BADH, (PPRIVILEGE_SET)&ps, &r), XS(0xC0000008));
    if (N(NtOpenProcessToken)(SELFP, TOKEN_QUERY, &p) == 0) {
        r = 0xcc; s = N(NtPrivilegeCheck)(p, (PPRIVILEGE_SET)&ps, &r);             /* a primary token is accepted as well (observed) */
        EXPECT_EQ(s, 0); EXPECT_EQ(r, TRUE);
        N(NtClose)(p);
    }
    t = imp_token();
    if (t) {
        ps.Count = 1; ps.P[0].Luid.LowPart = 0xfff;                                /* unknown privilege luid */
        r = 0xcc; s = N(NtPrivilegeCheck)(t, (PPRIVILEGE_SET)&ps, &r);
        EXPECT_EQ(s, 0); EXPECT_EQ(r, FALSE);                                      /* a privilege the token does not hold simply fails the check */
        N(NtClose)(t);
    }
}

/* ---- impersonation ---------------------------------------------------------- */
static int cur_thread_is_anonymous(void)
{
    HANDLE t = NULL; BYTE buf[256]; ULONG ret; PSID anon; BYTE sidb[16]; int r = -1;
    if (N(NtOpenThreadToken)(SELFT, TOKEN_QUERY, TRUE, &t) != 0) return -1;
    anon = (PSID)sidb; memset(sidb, 0, sizeof sidb); sidb[0] = 1; sidb[1] = 1; sidb[7] = 5; sidb[8] = 7;     /* S-1-5-7 */
    if (N(NtQueryInformationToken)(t, 1 /* TokenUser */, buf, sizeof buf, &ret) == 0) {
        PSID u = *(PSID *)buf; r = (u && ((BYTE *)u)[1] == 1 && !memcmp((BYTE *)u + 2, sidb + 2, 6) && ((ULONG *)((BYTE *)u + 8))[0] == 7);
    }
    (void)anon; N(NtClose)(t);
    return r;
}
static void revert(void) { HANDLE nul = NULL; N(NtSetInformationThread)(SELFT, 5 /* ThreadImpersonationToken */, &nul, sizeof nul); }
TEST(other3a_impersonate_anonymous_token)
{
    NTSTATUS s; HANDLE t = NULL; REQUIRE(N(NtImpersonateAnonymousToken)); REQUIRE(N(NtOpenThreadToken)); REQUIRE(N(NtQueryInformationToken)); REQUIRE(N(NtSetInformationThread));
    EXPECT_EQ(N(NtOpenThreadToken)(SELFT, TOKEN_QUERY, TRUE, &t), XS(0xC000007C));              /* STATUS_NO_TOKEN: not impersonating */
    s = N(NtImpersonateAnonymousToken)(SELFT);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(cur_thread_is_anonymous(), 1); revert(); }
    EXPECT_EQ(N(NtOpenThreadToken)(SELFT, TOKEN_QUERY, TRUE, &t), XS(0xC000007C));
    EXPECT_EQ(N(NtImpersonateAnonymousToken)(BADH), XS(0xC0000008));
    EXPECT_EQ(N(NtImpersonateAnonymousToken)(NULL), XS(0xC0000008));
    EXPECT_EQ(N(NtImpersonateAnonymousToken)(SELFP), XS(0xC0000024));                         /* a process handle is not a thread */
}
TEST(other3a_impersonate_thread_adopts_client_token)
{
    HANDLE stop, th, cl; DWORD tid; SECURITY_QUALITY_OF_SERVICE q; NTSTATUS s; HANDLE t = NULL; ULONG ret, lvl = 99;
    REQUIRE(N(NtImpersonateThread)); REQUIRE(N(NtOpenThreadToken)); REQUIRE(N(NtQueryInformationToken)); REQUIRE(N(NtSetInformationThread));
    stop = CreateEventA(NULL, TRUE, FALSE, NULL); th = CreateThread(NULL, 0, park, stop, 0, &tid); CHECK(stop && th); if (!th) goto out;
    q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation; q.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING; q.EffectiveOnly = FALSE;
    cl = OpenThread(THREAD_DIRECT_IMPERSONATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    CHECK(cl != NULL);
    if (cl) {
        s = N(NtImpersonateThread)(SELFT, cl, &q);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            EXPECT_EQ(N(NtOpenThreadToken)(SELFT, TOKEN_QUERY, TRUE, &t), 0);
            if (t) {
                EXPECT_EQ(N(NtQueryInformationToken)(t, 8 /* TokenType */, &lvl, sizeof lvl, &ret), 0); EXPECT_EQ(lvl, 2);
                lvl = 99; EXPECT_EQ(N(NtQueryInformationToken)(t, 9 /* TokenImpersonationLevel */, &lvl, sizeof lvl, &ret), 0); EXPECT_EQ(lvl, 2);
                N(NtClose)(t);
            }
            revert();
        }
        q.ImpersonationLevel = SecurityAnonymous;
        s = N(NtImpersonateThread)(SELFT, cl, &q);
        EXPECT_EQ(s, 0);
        if (s == 0) { t = NULL; EXPECT_EQ(N(NtOpenThreadToken)(SELFT, TOKEN_QUERY, TRUE, &t), XS(0xC00000A6)); if (t) N(NtClose)(t); revert(); }   /* STATUS_BAD_IMPERSONATION_LEVEL: anonymous-level token cannot be opened */
        q.ImpersonationLevel = SecurityImpersonation;
        EXPECT_EQ(N(NtImpersonateThread)(BADH, cl, &q), XS(0xC0000008));
        EXPECT_EQ(N(NtImpersonateThread)(SELFT, BADH, &q), XS(0xC0000008));
        CloseHandle(cl);
    }
    cl = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);                           /* lacks THREAD_DIRECT_IMPERSONATION */
    if (cl) { EXPECT_EQ(N(NtImpersonateThread)(SELFT, cl, &q), XS(0xC0000022)); CloseHandle(cl); }
out:
    if (stop) SetEvent(stop);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (stop) CloseHandle(stop);
}
TEST(other3a_port_services_reject_bad_handles)
{
    HANDLE ev = NULL; BYTE msg[128]; REQUIRE(N(NtListenPort)); REQUIRE(N(NtImpersonateClientOfPort)); REQUIRE(N(NtCreateEvent));
    memset(msg, 0, sizeof msg); ((USHORT *)msg)[1] = 0x28; *(ULONG *)(msg + 0x18) = 1;       /* PORT_MESSAGE header: TotalLength, MessageId */
    EXPECT_EQ(N(NtListenPort)(BADH, msg), XS(0xC0000008));
    EXPECT_EQ(N(NtImpersonateClientOfPort)(BADH, msg), XS(0xC0000008));
    N(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    if (ev) {
        EXPECT_EQ(N(NtListenPort)(ev, msg), XS(0xC0000024));
        EXPECT_EQ(N(NtImpersonateClientOfPort)(ev, msg), XS(0xC0000024));
        N(NtClose)(ev);
    }
}

UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
TEST(other3a_impersonate_client_of_port_without_client)
{
    HANDLE port = NULL; BYTE msg[128]; OBJECT_ATTRIBUTES oa; NTSTATUS s; REQUIRE(N(NtImpersonateClientOfPort)); REQUIRE(N(NtCreatePort));
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    s = N(NtCreatePort)(&port, &oa, 0, 0x100, 0);                                     /* unnamed server port; never listened on */
    EXPECT_EQ(s, 0); if (s != 0 || !port) return;
    memset(msg, 0, sizeof msg); ((USHORT *)msg)[1] = 0x28; *(ULONG *)(msg + 0x18) = 1;
    EXPECT_EQ(N(NtImpersonateClientOfPort)(port, msg), XS(0xC000021F));              /* STATUS_REPLY_MESSAGE_MISMATCH: no such client message */
    memset(msg, 0, sizeof msg);
    EXPECT_EQ(N(NtImpersonateClientOfPort)(port, msg), XS(0xC000000D));              /* header without a length */
    N(NtClose)(port);
}
TEST(other3a_user_pointer_faults_are_reported)
{
    HANDLE t = NULL; PRIVILEGE_SET ps; BOOLEAN r; REQUIRE(N(NtGetContextThread)); REQUIRE(N(NtPrivilegeCheck)); REQUIRE(N(NtOpenProcessToken)); REQUIRE(N(NtGetNextProcess));
    EXPECT_EQ(N(NtGetContextThread)(GetCurrentThread(), NULL), XS(0xC0000005));
    EXPECT_EQ(N(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, NULL), XS(0xC0000005));
    if (N(NtOpenProcessToken)(SELFP, TOKEN_QUERY, &t) == 0) {
        memset(&ps, 0, sizeof ps);
        EXPECT_EQ(N(NtPrivilegeCheck)(t, &ps, NULL), XS(0xC0000005));
        EXPECT_EQ(N(NtPrivilegeCheck)(t, NULL, &r), XS(0xC0000005));
        EXPECT_EQ(N(NtPrivilegeCheck)(NULL, &ps, &r), XS(0xC0000008));
        N(NtClose)(t);
    }
}

/* ---- NtMakeTemporaryObject / NtMakePermanentObject --------------------------- */
TEST(other3a_make_temporary_and_permanent_object)
{
    HANDLE ev = NULL, ro = NULL; NTSTATUS s; int privheld; REQUIRE(N(NtMakeTemporaryObject)); REQUIRE(N(NtMakePermanentObject)); REQUIRE(N(NtCreateEvent)); REQUIRE(N(NtDuplicateObject));
    EXPECT_EQ(N(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0); if (!ev) return;
    s = N(NtMakeTemporaryObject)(ev);
    EXPECT_EQ(s, 0);                                                                     /* already temporary: still success */
    s = N(NtMakePermanentObject)(ev);
    if (s == 0) { EXPECT_EQ(N(NtMakeTemporaryObject)(ev), 0); }                         /* undo so the object dies with its last handle */
    else EXPECT_EQ(s, XS(0xC0000061));                                                  /* STATUS_PRIVILEGE_NOT_HELD: SeCreatePermanentPrivilege */
    privheld = (s == 0);
    EXPECT_EQ(N(NtDuplicateObject)(SELFP, ev, SELFP, &ro, SYNCHRONIZE, 0, 0), 0);
    if (ro) { EXPECT_EQ(N(NtMakeTemporaryObject)(ro), XS(0xC0000022)); N(NtClose)(ro); }   /* DELETE access required */
    EXPECT_EQ(N(NtMakeTemporaryObject)(BADH), XS(0xC0000008));
    EXPECT_EQ(N(NtMakePermanentObject)(BADH), privheld ? XS(0xC0000008) : XS(0xC0000061));   /* privilege is checked before the handle */
    N(NtClose)(ev);
}

/* ---- NtPowerInformation ----------------------------------------------------- */
TEST(other3a_power_information_levels)
{
    BYTE buf[1024]; NTSTATUS s; ULONG state = 0; SYSTEM_INFO si; REQUIRE(N(NtPowerInformation));
    GetSystemInfo(&si);
    memset(buf, 0, sizeof buf);
    s = N(NtPowerInformation)(4 /* SystemPowerCapabilities */, NULL, 0, buf, 76);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(N(NtPowerInformation)(4, NULL, 0, buf, 8), XS(0xC0000023));                 /* STATUS_BUFFER_TOO_SMALL */
    memset(buf, 0, sizeof buf);
    s = N(NtPowerInformation)(11 /* ProcessorInformation */, NULL, 0, buf, si.dwNumberOfProcessors * 0x18);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        struct pp { ULONG Number, MaxMhz, CurrentMhz, MhzLimit, MaxIdleState, CurrentIdleState; } *p = (struct pp *)buf;
        for (DWORD i = 0; i < si.dwNumberOfProcessors && i < 8; i++) { EXPECT_EQ(p[i].Number, i); CHECK(p[i].CurrentMhz <= p[i].MaxMhz || p[i].MaxMhz == 0); }
    }
    EXPECT_EQ(N(NtPowerInformation)(11, NULL, 0, buf, 4), XS(0xC0000023));
    state = 0xcc;
    s = N(NtPowerInformation)(16 /* SystemExecutionState */, NULL, 0, &state, sizeof state);
    EXPECT_EQ(s, 0); CHECK((state & ~0x8000000Fu) == 0);                    /* only EXECUTION_STATE bits */
    state = 0xcc; EXPECT_EQ(N(NtPowerInformation)(16, NULL, 0, &state, 2), XS(0xC0000023));
    {   ULONG64 t = 0xcc; s = N(NtPowerInformation)(14 /* LastWakeTime */, NULL, 0, &t, sizeof t); EXPECT_EQ(s, 0); }
    s = N(NtPowerInformation)(0x7fff, NULL, 0, buf, sizeof buf);
    EXPECT_EQ(s, XS(0xC000000D));                                                          /* unknown information level */
}
TEST(other3a_is_system_resume_automatic)
{
    BOOLEAN r; REQUIRE(N(NtIsSystemResumeAutomatic));
    r = N(NtIsSystemResumeAutomatic)();
    EXPECT_EQ(r, FALSE);                                                                   /* the session was not started by a timer wake */
}

/* ---- NtRaiseException -------------------------------------------------------- */
static volatile LONG g_veh_seen; static volatile ULONG g_veh_code; static volatile ULONG_PTR g_veh_arg0; static volatile int g_veh_nc;
static LONG CALLBACK veh(PEXCEPTION_POINTERS p)
{
    if (p->ExceptionRecord->ExceptionCode == 0xE0A3A001) {
        g_veh_seen++; g_veh_code = p->ExceptionRecord->ExceptionCode; g_veh_arg0 = p->ExceptionRecord->ExceptionInformation[0];
        g_veh_nc = (p->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
CHILD(o3a_raise)
{
    EXCEPTION_RECORD er; CONTEXT ctx; volatile int hits = 0; PVOID h; NTSTATUS s = 0x77777777;
    if (!N(NtRaiseException) || !N(RtlCaptureContext)) return 90;
    h = AddVectoredExceptionHandler(1, veh);
    memset(&er, 0, sizeof er); er.ExceptionCode = 0xE0A3A001; er.NumberParameters = 1; er.ExceptionInformation[0] = 0x1234;
    N(RtlCaptureContext)(&ctx);                                      /* continuation point: execution resumes here after a handled exception */
    if (!hits) { hits = 1; er.ExceptionAddress = (PVOID)(ULONG_PTR)ctx.Rip; N(NtRaiseException)(&er, &ctx, TRUE); s = 0x66666666; }
    RemoveVectoredExceptionHandler(h);
    if (s == 0x66666666) return 91;                                  /* NtRaiseException must not return when the handler continues */
    if (g_veh_seen != 1) return 92;
    if (g_veh_arg0 != 0x1234) return 93;
    if (g_veh_nc) return 94;
    return 0;
}
TEST(other3a_raise_exception_first_chance_continue)
{
    REQUIRE(N(NtRaiseException)); REQUIRE(N(RtlCaptureContext));
    EXPECT_EQ(t_run_child("o3a_raise", NULL, 20000), 0);
}

/* ---- NLS / MUI ---------------------------------------------------------------- */
TEST(other3a_get_nls_section_ptr)
{
    PVOID p = NULL; SIZE_T sz = 0; NTSTATUS s; REQUIRE(N(NtGetNlsSectionPtr));
    s = N(NtGetNlsSectionPtr)(11 /* codepage */, 1252, NULL, &p, &sz);
    EXPECT_EQ(s, 0); CHECK(p != NULL); CHECK(sz >= 0x1000);
    if (p) { s = N(NtGetNlsSectionPtr)(11, 1252, NULL, &p, &sz); EXPECT_EQ(s, 0); }
    p = NULL; sz = 0;
    s = N(NtGetNlsSectionPtr)(11, 0xfffff, NULL, &p, &sz);
    EXPECT_EQ(s, XS(0xC0000034));                                     /* STATUS_OBJECT_NAME_NOT_FOUND: no such code page file */
    s = N(NtGetNlsSectionPtr)(0x7f, 0, NULL, &p, &sz);
    EXPECT_EQ(s, XS(0xC00000EF));                                     /* unknown section type: invalid parameter 1 */
}
TEST(other3a_ui_language_committed_and_mui_registry_info)
{
    NTSTATUS s; ULONG sz = 0; BYTE buf[4096]; REQUIRE(N(NtIsUILanguageComitted)); REQUIRE(N(NtGetMUIRegistryInfo));
    s = N(NtIsUILanguageComitted)();
    if (s != 0) t_skip("UI language not committed on this installation: 0x%08lx", (unsigned long)s);
    else EXPECT_EQ(s, 0);
    s = N(NtGetMUIRegistryInfo)(0, &sz, NULL);
    EXPECT_EQ(s, 0); CHECK(sz > 0);                                    /* NULL data: required size is returned */
    if (s == 0 && sz > 0 && sz <= sizeof buf) {
        ULONG sz2 = sz; memset(buf, 0, sizeof buf);
        EXPECT_EQ(N(NtGetMUIRegistryInfo)(0, &sz2, buf), 0);
        EXPECT_EQ(sz2, sz);
        sz2 = sz - 1;
        s = N(NtGetMUIRegistryInfo)(0, &sz2, buf);
        EXPECT_EQ(s, XS(0xC0000023)); EXPECT_EQ(sz2, sz);                 /* STATUS_BUFFER_TOO_SMALL, required size reported */
    }
}
