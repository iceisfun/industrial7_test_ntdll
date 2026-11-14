/* Process/thread/system natives: NtGetCurrentProcessorNumber(Ex), NtGetTickCount, NtGetNextProcess,
 * NtGetNextThread, NtIsProcessInJob, NtIsSystemResumeAutomatic, NtIsUILanguageComitted, NtGetContextThread,
 * NtQueueApcThread(Ex), NtImpersonateThread, NtImpersonateAnonymousToken, NtPrivilegeCheck, NtPowerInformation. */
#include "t.h"

UDECL(ULONG, NtGetCurrentProcessorNumber, (VOID));
UDECL(ULONG, NtGetCurrentProcessorNumberEx, (PPROCESSOR_NUMBER));
UDECL(ULONG, NtGetTickCount, (VOID));
UDECL(NTSTATUS, NtGetNextProcess, (HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE));
UDECL(NTSTATUS, NtGetNextThread, (HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE));
UDECL(NTSTATUS, NtIsProcessInJob, (HANDLE, HANDLE));
UDECL(BOOLEAN, NtIsSystemResumeAutomatic, (VOID));
UDECL(NTSTATUS, NtIsUILanguageComitted, (VOID));
UDECL(NTSTATUS, NtGetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtQueueApcThread, (HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtQueueApcThreadEx, (HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtImpersonateThread, (HANDLE, HANDLE, PSECURITY_QUALITY_OF_SERVICE));
UDECL(NTSTATUS, NtImpersonateAnonymousToken, (HANDLE));
UDECL(NTSTATUS, NtPrivilegeCheck, (HANDLE, PPRIVILEGE_SET, PBOOLEAN));
UDECL(NTSTATUS, NtPowerInformation, (ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));

static DWORD WINAPI waiter(LPVOID p) { WaitForSingleObject((HANDLE)p, 10000); return 0; }
typedef struct { ULONG Number, MaxMhz, CurrentMhz, MhzLimit, MaxIdleState, CurrentIdleState; } PROCESSOR_POWER_INFORMATION;
#define XS(x) ((NTSTATUS)(x))
#define BADH ((HANDLE)(LONG_PTR)0x7777c)
#define PSEUDO_PROC ((HANDLE)(LONG_PTR)-1)
#define PSEUDO_THREAD ((HANDLE)(LONG_PTR)-2)

TEST(alias_pairs)
{
    const char *n[] = { "GetCurrentProcessorNumber", "GetCurrentProcessorNumberEx", "GetNextProcess", "GetNextThread",
        "IsProcessInJob", "IsSystemResumeAutomatic", "IsUILanguageComitted", "GetContextThread", "QueueApcThread",
        "QueueApcThreadEx", "ImpersonateThread", "ImpersonateAnonymousToken", "PrivilegeCheck", "PowerInformation" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa || !pb) { t_skip("missing %s", pa ? b : a); return; }
        CHECKF(pa == pb, "%s and %s differ", a, b);
    }
}

TEST(processor_number)
{
    REQUIRE(UN(NtGetCurrentProcessorNumber)); REQUIRE(UN(NtGetCurrentProcessorNumberEx));
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD total = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    for (int i = 0; i < 20; i++) {
        ULONG n = UN(NtGetCurrentProcessorNumber)();
        CHECKF(n < total, "processor %lu of %lu", n, total);
        PROCESSOR_NUMBER pn; memset(&pn, 0xcc, sizeof pn);
        ULONG r = UN(NtGetCurrentProcessorNumberEx)(&pn);
        (void)r;
        CHECKF(pn.Group < 32 && pn.Number < 64, "group %u number %u", pn.Group, pn.Number);
        EXPECT_EQ(pn.Reserved, 0);
        Sleep(1);
    }
    /* pin to a single processor and verify both report it */
    DWORD_PTR old = SetThreadAffinityMask(GetCurrentThread(), 1);
    if (old) {
        PROCESSOR_NUMBER pn; Sleep(1);
        EXPECT_EQ(UN(NtGetCurrentProcessorNumber)(), 0);
        UN(NtGetCurrentProcessorNumberEx)(&pn);
        EXPECT_EQ(pn.Number, 0);
        SetThreadAffinityMask(GetCurrentThread(), old);
    }
}

TEST(tick_count)
{
    REQUIRE(UN(NtGetTickCount));
    ULONG a = UN(NtGetTickCount)(); DWORD k = GetTickCount();
    CHECKF((ULONG)(k - a) < 2000, "NtGetTickCount %lu vs GetTickCount %lu", a, k);
    Sleep(120);
    ULONG b = UN(NtGetTickCount)();
    CHECKF(b - a >= 100 && b - a < 2000, "delta %lu", b - a);
}

TEST(next_process)
{
    REQUIRE(UN(NtGetNextProcess)); REQUIRE(UN(NtClose));
    HANDLE cur = NULL, nxt = NULL; int found = 0, count = 0; NTSTATUS s;
    DWORD me = GetCurrentProcessId();
    s = UN(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &cur);
    EXPECT_EQ(s, 0);
    while (s == 0 && count < 4000) {
        count++;
        if (GetProcessId(cur) == me) found++;
        s = UN(NtGetNextProcess)(cur, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &nxt);
        UN(NtClose)(cur);
        cur = nxt; nxt = NULL;
    }
    EXPECT_EQ(s, XS(0x8000001A)); /* STATUS_NO_MORE_ENTRIES (warning severity) */
    EXPECT_EQ(found, 1);
    CHECK(count >= 3);
    /* reverse direction (flags=1) starting from NULL gives the newest process */
    HANDLE last = NULL;
    s = UN(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 1, &last);
    EXPECT_EQ(s, 0);
    if (s == 0) UN(NtClose)(last);
    /* errors */
    nxt = (HANDLE)0x1234;
    EXPECT_EQ(UN(NtGetNextProcess)(BADH, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &nxt), XS(0xC0000008));
    EXPECT_EQ(UN(NtGetNextProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0x80, &nxt), XS(0xC000000D));
}

TEST(next_thread)
{
    REQUIRE(UN(NtGetNextThread)); REQUIRE(UN(NtClose));
    HANDLE cur = NULL, nxt = NULL, self = NULL; NTSTATUS s; int found = 0, count = 0;
    DWORD tid = GetCurrentThreadId();
    s = UN(NtGetNextThread)(PSEUDO_PROC, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &cur);
    EXPECT_EQ(s, 0);
    while (s == 0 && count < 1000) {
        count++;
        if (GetThreadId(cur) == tid) found++;
        s = UN(NtGetNextThread)(PSEUDO_PROC, cur, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt);
        UN(NtClose)(cur); cur = nxt; nxt = NULL;
    }
    EXPECT_EQ(s, XS(0x8000001A));
    EXPECT_EQ(found, 1);
    CHECK(count >= 1);
    /* extra thread shows up */
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE th = CreateThread(NULL, 0, waiter, ev, 0, NULL);
    int c2 = 0; cur = NULL; s = 0;
    {
        HANDLE c = NULL;
        s = UN(NtGetNextThread)(PSEUDO_PROC, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &c);
        while (s == 0 && c2 < 1000) { c2++; HANDLE n = NULL; s = UN(NtGetNextThread)(PSEUDO_PROC, c, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &n); UN(NtClose)(c); c = n; }
    }
    CHECKF(c2 == count + 1, "threads %d then %d", count, c2);
    SetEvent(ev); WaitForSingleObject(th, 5000); CloseHandle(th); CloseHandle(ev);
    /* errors */
    EXPECT_EQ(UN(NtGetNextThread)(BADH, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt), XS(0xC0000008));
    EXPECT_EQ(UN(NtGetNextThread)(PSEUDO_PROC, BADH, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &nxt), XS(0xC0000008));
    EXPECT_EQ(UN(NtGetNextThread)(PSEUDO_PROC, NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 0x80, &nxt), XS(0xC000000D));
    (void)self;
}

CHILD(sleeper) { Sleep(30000); return 0; }

TEST(is_process_in_job)
{
    REQUIRE(UN(NtIsProcessInJob));
    HANDLE job = CreateJobObjectA(NULL, NULL);
    CHECK(job != NULL); if (!job) return;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof pi);
    HANDLE ph = t_spawn_child("sleeper", "", CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!ph && !pi.hProcess) { CloseHandle(job); t_skip("cannot spawn child"); return; }
    HANDLE child = pi.hProcess;
    EXPECT_EQ(UN(NtIsProcessInJob)(child, job), XS(0x123)); /* STATUS_PROCESS_NOT_IN_JOB */
    if (AssignProcessToJobObject(job, child)) {
        EXPECT_EQ(UN(NtIsProcessInJob)(child, job), XS(0x124)); /* STATUS_PROCESS_IN_JOB */
        EXPECT_EQ(UN(NtIsProcessInJob)(child, NULL), XS(0x124));
        EXPECT_EQ(UN(NtIsProcessInJob)(child, BADH), XS(0xC0000008));
        EXPECT_EQ(UN(NtIsProcessInJob)(BADH, job), XS(0xC0000008));
        /* current process is not in this fresh job */
        EXPECT_EQ(UN(NtIsProcessInJob)(PSEUDO_PROC, job), XS(0x123));
    } else t_note("assign to job failed: %lu", GetLastError());
    /* job handle of wrong type */
    EXPECT_EQ(UN(NtIsProcessInJob)(child, child), XS(0xC0000024));
    TerminateProcess(child, 0);
    WaitForSingleObject(child, 5000);
    CloseHandle(pi.hThread); CloseHandle(child); CloseHandle(job);
}

TEST(resume_and_ui_language)
{
    REQUIRE(UN(NtIsSystemResumeAutomatic)); REQUIRE(UN(NtIsUILanguageComitted));
    EXPECT_EQ(UN(NtIsSystemResumeAutomatic)(), 0);
    NTSTATUS s = UN(NtIsUILanguageComitted)();
    t_note("NtIsUILanguageComitted -> %08lx", s);
    EXPECT_EQ(s, 0);
}

static DWORD WINAPI idle_thread(LPVOID p) { return 0; }

TEST(get_context_thread)
{
    REQUIRE(UN(NtGetContextThread));
    HANDLE th = CreateThread(NULL, 0, idle_thread, (LPVOID)0x1234, CREATE_SUSPENDED, NULL);
    CHECK(th != NULL); if (!th) return;
    CONTEXT *c = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(c != NULL);
    if (c) {
        memset(c, 0xcc, sizeof *c);
        c->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        NTSTATUS s = UN(NtGetContextThread)(th, c);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            HMODULE nt = GetModuleHandleA("ntdll.dll");
            CHECK(c->Rip > (ULONG_PTR)nt && c->Rip < (ULONG_PTR)nt + 0x400000);
            EXPECT_EQ(c->Rdx, 0x1234);
            EXPECT_EQ(c->Rcx, (ULONG_PTR)idle_thread);
            CHECK(c->Rsp != 0 && (c->Rsp & 7) == 0);
            EXPECT_EQ(c->ContextFlags & (CONTEXT_CONTROL | CONTEXT_INTEGER), CONTEXT_CONTROL | CONTEXT_INTEGER);
            EXPECT_EQ(c->SegCs, 0x33);
        }
        /* only the requested groups are returned: floating point untouched */
        memset(c, 0xcc, sizeof *c);
        c->ContextFlags = CONTEXT_CONTROL;
        s = UN(NtGetContextThread)(th, c);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(c->Rax, 0xcccccccccccccccc);
        /* debug registers only */
        c->ContextFlags = CONTEXT_DEBUG_REGISTERS;
        EXPECT_EQ(UN(NtGetContextThread)(th, c), 0);
        EXPECT_EQ(c->Dr7, 0);
        /* extended registers */
        c->ContextFlags = CONTEXT_FLOATING_POINT;
        EXPECT_EQ(UN(NtGetContextThread)(th, c), 0);
        /* bogus flags and handles */
        c->ContextFlags = 0;
        EXPECT_EQ(UN(NtGetContextThread)(th, c), 0);
        EXPECT_EQ(UN(NtGetContextThread)(BADH, c), XS(0xC0000008));
        c->ContextFlags = CONTEXT_FULL;
        EXPECT_EQ(UN(NtGetContextThread)(NULL, c), XS(0xC0000008));
        EXPECT_EQ(UN(NtGetContextThread)(PSEUDO_PROC, c), XS(0xC0000024));
        /* no access to the buffer */
        EXPECT_EQ(UN(NtGetContextThread)(th, NULL), XS(0xC0000005));
        /* a handle without THREAD_GET_CONTEXT */
        HANDLE lim = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetThreadId(th));
        if (lim) { EXPECT_EQ(UN(NtGetContextThread)(lim, c), XS(0xC0000022)); CloseHandle(lim); }
        VirtualFree(c, 0, MEM_RELEASE);
    }
    ResumeThread(th);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
}

static volatile struct { PVOID a1, a2, a3; DWORD tid; LONG n; } g_apc;
static VOID NTAPI apc_proc(PVOID a1, PVOID a2, PVOID a3)
{
    g_apc.a1 = a1; g_apc.a2 = a2; g_apc.a3 = a3; g_apc.tid = GetCurrentThreadId(); InterlockedIncrement(&g_apc.n);
}

TEST(queue_apc_thread)
{
    REQUIRE(UN(NtQueueApcThread)); REQUIRE(UN(NtQueueApcThreadEx));
    HANDLE self = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &self, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CHECK(self != NULL); if (!self) return;
    memset((void *)&g_apc, 0, sizeof g_apc);
    EXPECT_EQ(UN(NtQueueApcThread)(self, apc_proc, (PVOID)1, (PVOID)2, (PVOID)3), 0);
    EXPECT_EQ(g_apc.n, 0);                     /* not delivered until alertable */
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    EXPECT_EQ(g_apc.n, 1); EXPECT_EQ((ULONG_PTR)g_apc.a1, 1); EXPECT_EQ((ULONG_PTR)g_apc.a2, 2); EXPECT_EQ((ULONG_PTR)g_apc.a3, 3);
    EXPECT_EQ(g_apc.tid, GetCurrentThreadId());
    /* pseudo handle works too, order of two queued APCs is FIFO */
    EXPECT_EQ(UN(NtQueueApcThread)(PSEUDO_THREAD, apc_proc, (PVOID)10, 0, 0), 0);
    EXPECT_EQ(UN(NtQueueApcThread)(PSEUDO_THREAD, apc_proc, (PVOID)11, 0, 0), 0);
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    EXPECT_EQ(g_apc.n, 3); EXPECT_EQ((ULONG_PTR)g_apc.a1, 11);
    /* Ex variant with no reserve object */
    EXPECT_EQ(UN(NtQueueApcThreadEx)(self, NULL, apc_proc, (PVOID)21, (PVOID)22, (PVOID)23), 0);
    EXPECT_EQ(SleepEx(0, TRUE), WAIT_IO_COMPLETION);
    EXPECT_EQ(g_apc.n, 4); EXPECT_EQ((ULONG_PTR)g_apc.a1, 21); EXPECT_EQ((ULONG_PTR)g_apc.a3, 23);
    /* errors */
    EXPECT_EQ(UN(NtQueueApcThread)(BADH, apc_proc, 0, 0, 0), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueueApcThreadEx)(BADH, NULL, apc_proc, 0, 0, 0), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueueApcThread)(PSEUDO_PROC, apc_proc, 0, 0, 0), XS(0xC0000024));
    HANDLE lim = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    if (lim) {
        EXPECT_EQ(UN(NtQueueApcThread)(lim, apc_proc, 0, 0, 0), XS(0xC0000022));
        EXPECT_EQ(UN(NtQueueApcThreadEx)(lim, NULL, apc_proc, 0, 0, 0), XS(0xC0000022));
        CloseHandle(lim);
    }
    EXPECT_EQ(UN(NtQueueApcThreadEx)(self, BADH, apc_proc, 0, 0, 0), XS(0xC0000008));
    EXPECT_EQ(g_apc.n, 4);
    /* APC queued to a thread that has exited */
    HANDLE th = CreateThread(NULL, 0, idle_thread, NULL, 0, NULL);
    WaitForSingleObject(th, 5000);
    EXPECT_EQ(UN(NtQueueApcThread)(th, apc_proc, 0, 0, 0), XS(0xC0000001)); /* STATUS_UNSUCCESSFUL */
    CloseHandle(th); CloseHandle(self);
}

static BOOL token_user_sid(HANDLE tok, BYTE *sid_out /* 16 bytes copy of sid */, ULONG *len)
{
    BYTE buf[256]; ULONG got = 0;
    if (UN(NtQueryInformationToken)(tok, 1 /* TokenUser */, buf, sizeof buf, &got) != 0) return FALSE;
    PSID sid = *(PSID *)buf; BYTE *b = sid;
    *len = 8 + 4 * b[1]; memcpy(sid_out, sid, *len);
    return TRUE;
}

static struct { HANDLE client; NTSTATUS st, st_bad; ULONG level; BOOL got; BYTE sid[64]; ULONG sidlen; } g_imp;
static DWORD WINAPI imp_thread(LPVOID p)
{
    SECURITY_QUALITY_OF_SERVICE q; memset(&q, 0, sizeof q);
    q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation; q.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING; q.EffectiveOnly = FALSE;
    g_imp.st = UN(NtImpersonateThread)(PSEUDO_THREAD, g_imp.client, &q);
    if (g_imp.st == 0) {
        HANDLE t = NULL;
        if (UN(NtOpenThreadToken)(PSEUDO_THREAD, TOKEN_QUERY, TRUE, &t) == 0) {
            struct { ULONG lvl; } x; ULONG got;
            if (UN(NtQueryInformationToken)(t, 9 /* TokenImpersonationLevel */, &x, sizeof x, &got) == 0) g_imp.level = x.lvl;
            g_imp.got = token_user_sid(t, g_imp.sid, &g_imp.sidlen);
            UN(NtClose)(t);
        }
        HANDLE nul = NULL;
        UN(NtOpenThreadToken)(PSEUDO_THREAD, TOKEN_QUERY, TRUE, &nul); if (nul) UN(NtClose)(nul);
    }
    return 0;
}

TEST(impersonate_thread)
{
    REQUIRE(UN(NtImpersonateThread)); REQUIRE(UN(NtOpenThreadToken)); REQUIRE(UN(NtQueryInformationToken));
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE cl = CreateThread(NULL, 0, waiter, ev, 0, NULL);
    memset(&g_imp, 0, sizeof g_imp); g_imp.client = cl;
    HANDLE w = CreateThread(NULL, 0, imp_thread, NULL, 0, NULL);
    WaitForSingleObject(w, 10000);
    EXPECT_EQ(g_imp.st, 0);
    EXPECT_EQ(g_imp.level, 2);  /* SecurityImpersonation */
    CHECK(g_imp.got);
    /* the impersonated identity is the process identity */
    HANDLE pt = NULL; BYTE psid[64]; ULONG plen = 0;
    if (UN(NtOpenProcessToken)(PSEUDO_PROC, TOKEN_QUERY, &pt) == 0) {
        CHECK(token_user_sid(pt, psid, &plen));
        CHECK(plen == g_imp.sidlen && !memcmp(psid, g_imp.sid, plen));
        UN(NtClose)(pt);
    }
    SetEvent(ev); WaitForSingleObject(cl, 5000);
    CloseHandle(w); CloseHandle(cl); CloseHandle(ev);
}

static struct { NTSTATUS st, st_bad; BOOL got; BYTE sid[64]; ULONG sidlen, level; } g_anon;
static DWORD WINAPI anon_thread(LPVOID p)
{
    g_anon.st = UN(NtImpersonateAnonymousToken)(PSEUDO_THREAD);
    if (g_anon.st == 0) {
        HANDLE t = NULL;
        if (UN(NtOpenThreadToken)(PSEUDO_THREAD, TOKEN_QUERY, TRUE, &t) == 0) {
            ULONG got, lvl = 0;
            if (UN(NtQueryInformationToken)(t, 9, &lvl, sizeof lvl, &got) == 0) g_anon.level = lvl;
            g_anon.got = token_user_sid(t, g_anon.sid, &g_anon.sidlen);
            UN(NtClose)(t);
        }
        /* revert */
        HANDLE none = NULL;
        typedef NTSTATUS (WINAPI *setinfo_t)(HANDLE, ULONG, PVOID, ULONG);
        setinfo_t sit = (setinfo_t)t_proc("NtSetInformationThread");
        if (sit) sit(PSEUDO_THREAD, 5 /* ThreadImpersonationToken */, &none, sizeof none);
    }
    return 0;
}

TEST(impersonate_anonymous_token)
{
    REQUIRE(UN(NtImpersonateAnonymousToken)); REQUIRE(UN(NtOpenThreadToken)); REQUIRE(UN(NtQueryInformationToken));
    memset(&g_anon, 0, sizeof g_anon);
    HANDLE w = CreateThread(NULL, 0, anon_thread, NULL, 0, NULL);
    WaitForSingleObject(w, 10000); CloseHandle(w);
    EXPECT_EQ(g_anon.st, 0);
    CHECK(g_anon.got);
    /* S-1-5-7 ANONYMOUS LOGON */
    static const BYTE anon[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0 };
    CHECK(g_anon.sidlen == 12 && !memcmp(g_anon.sid, anon, 12));
    EXPECT_EQ(g_anon.level, 2);
    EXPECT_EQ(UN(NtImpersonateAnonymousToken)(BADH), XS(0xC0000008));
    EXPECT_EQ(UN(NtImpersonateAnonymousToken)(NULL), XS(0xC0000008));
    EXPECT_EQ(UN(NtImpersonateAnonymousToken)(PSEUDO_PROC), XS(0xC0000024));
    HANDLE lim = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    if (lim) { EXPECT_EQ(UN(NtImpersonateAnonymousToken)(lim), XS(0xC0000022)); CloseHandle(lim); }
}

static void make_priv_set(PRIVILEGE_SET *ps, ULONG n, ULONG control, const ULONG *luids)
{
    memset(ps, 0, sizeof(PRIVILEGE_SET) + 4 * sizeof(LUID_AND_ATTRIBUTES));
    ps->PrivilegeCount = n; ps->Control = control;
    for (ULONG i = 0; i < n; i++) { ps->Privilege[i].Luid.LowPart = luids[i]; }
}

TEST(privilege_check)
{
    REQUIRE(UN(NtPrivilegeCheck)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken));
    HANDLE pt = NULL, it = NULL;
    NTSTATUS s = UN(NtOpenProcessToken)(PSEUDO_PROC, TOKEN_QUERY | TOKEN_DUPLICATE, &pt);
    EXPECT_EQ(s, 0); if (s) return;
    SECURITY_QUALITY_OF_SERVICE sq __attribute__((aligned(8))); OBJECT_ATTRIBUTES oa;
    memset(&sq, 0, sizeof sq); sq.Length = sizeof sq; sq.ImpersonationLevel = SecurityImpersonation; sq.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    oa.SecurityQualityOfService = &sq;
    s = UN(NtDuplicateToken)(pt, TOKEN_QUERY, &oa, FALSE, 2 /* TokenImpersonation */, &it);
    EXPECT_EQ(s, 0);
    BYTE buf[256]; PRIVILEGE_SET *ps = (PRIVILEGE_SET *)buf; BOOLEAN res;
    ULONG notify = 23, tcb = 7;
    if (s == 0) {
        /* SeChangeNotifyPrivilege is enabled for every user by default */
        make_priv_set(ps, 1, 0, &notify); res = 0xcc;
        EXPECT_EQ(UN(NtPrivilegeCheck)(it, ps, &res), 0); EXPECT_EQ(res, 1);
        EXPECT_NE(ps->Privilege[0].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS, 0);
        /* SeTcbPrivilege is held by neither a standard nor a filtered/admin user token */
        make_priv_set(ps, 1, 0, &tcb); res = 0xcc;
        EXPECT_EQ(UN(NtPrivilegeCheck)(it, ps, &res), 0); EXPECT_EQ(res, 0);
        EXPECT_EQ(ps->Privilege[0].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS, 0);
        /* one of two vs all required */
        { ULONG two[2] = { 23, 7 };
          make_priv_set(ps, 2, 0, two); res = 0xcc;
          EXPECT_EQ(UN(NtPrivilegeCheck)(it, ps, &res), 0); EXPECT_EQ(res, 1);
          make_priv_set(ps, 2, PRIVILEGE_SET_ALL_NECESSARY, two); res = 0xcc;
          EXPECT_EQ(UN(NtPrivilegeCheck)(it, ps, &res), 0); EXPECT_EQ(res, 0); }
        /* zero privileges: nothing required */
        make_priv_set(ps, 0, PRIVILEGE_SET_ALL_NECESSARY, &notify); res = 0xcc;
        s = UN(NtPrivilegeCheck)(it, ps, &res);
        EXPECT_EQ(s, 0); EXPECT_EQ(res, 1);   /* vacuously satisfied */
        /* invalid control flags */
        make_priv_set(ps, 1, 2, &notify); res = 0xcc;
        s = UN(NtPrivilegeCheck)(it, ps, &res);
        t_note("control flag 2: %08lx", s);
    }
    /* primary token */
    { make_priv_set(ps, 1, 0, &notify); res = 0xcc;
      s = UN(NtPrivilegeCheck)(pt, ps, &res);   /* a primary token is accepted */
      EXPECT_EQ(s, 0); EXPECT_EQ(res, 1); }
    make_priv_set(ps, 1, 0, &notify); res = 0xcc;
    EXPECT_EQ(UN(NtPrivilegeCheck)(BADH, ps, &res), XS(0xC0000008));
    EXPECT_EQ(UN(NtPrivilegeCheck)(PSEUDO_PROC, ps, &res), XS(0xC0000024));
    /* impersonation token opened without TOKEN_QUERY */
    {   HANDLE nq = NULL;
        if (UN(NtDuplicateToken)(pt, TOKEN_DUPLICATE, &oa, FALSE, 2, &nq) == 0) {
            EXPECT_EQ(UN(NtPrivilegeCheck)(nq, ps, &res), XS(0xC0000022));
            UN(NtClose)(nq);
        } }
    if (it) UN(NtClose)(it);
    UN(NtClose)(pt);
}

TEST(power_information)
{
    REQUIRE(UN(NtPowerInformation));
    BYTE buf[1024]; NTSTATUS s;
    /* SystemPowerCapabilities = 4 */
    memset(buf, 0xcc, sizeof buf);
    s = UN(NtPowerInformation)(4, NULL, 0, buf, 76);
    t_note("SystemPowerCapabilities: %08lx", s);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(UN(NtPowerInformation)(4, NULL, 0, buf, 8), XS(0xC0000023)); /* STATUS_BUFFER_TOO_SMALL */
    /* SystemExecutionState = 16 */
    ULONG es = 0xcc; s = UN(NtPowerInformation)(16, NULL, 0, &es, sizeof es);
    t_note("SystemExecutionState: %08lx value %08lx", s, es);
    EXPECT_EQ(s, 0);
    /* ProcessorPowerInformation = 11: one entry per processor */
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    ULONG ncpu = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    PROCESSOR_POWER_INFORMATION *ppi = VirtualAlloc(NULL, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ppi) {
        s = UN(NtPowerInformation)(11, NULL, 0, ppi, ncpu * sizeof *ppi);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            CHECK(ppi[0].Number == 0);
            for (ULONG i = 0; i < ncpu && i < 64; i++) EXPECT_EQ(ppi[i].Number, i);
        }
        EXPECT_EQ(UN(NtPowerInformation)(11, NULL, 0, ppi, 4), XS(0xC0000023));
        VirtualFree(ppi, 0, MEM_RELEASE);
    }
    /* invalid information level */
    EXPECT_EQ(UN(NtPowerInformation)(0x7fff, NULL, 0, buf, sizeof buf), XS(0xC000000D));
    /* LastWakeTime = 14, LastSleepTime = 15 */
    ULONGLONG t = 0xcc; s = UN(NtPowerInformation)(14, NULL, 0, &t, 8); t_note("LastWakeTime %08lx", s);
    EXPECT_EQ(s, 0);
    s = UN(NtPowerInformation)(15, NULL, 0, &t, 8); EXPECT_EQ(s, 0);
    EXPECT_EQ(UN(NtPowerInformation)(15, NULL, 0, &t, 4), XS(0xC0000023));
}
