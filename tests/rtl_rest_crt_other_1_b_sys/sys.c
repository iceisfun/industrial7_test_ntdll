/* Process/thread level helpers: self impersonation, default named-pipe ACL, registered waits, thread and
 * process exit, dynamic function tables, activation context frames, secure memory cache callbacks,
 * thread profiling argument checks and assorted small state helpers. */
#include "t.h"

#define ST_INVPARAM ((NTSTATUS)0xC000000D)
#define ST_PENDING  ((NTSTATUS)0x103)

UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

/* ---------------- self impersonation ---------------- */
UDECL(NTSTATUS, RtlImpersonateSelf, (ULONG));
UDECL(NTSTATUS, RtlImpersonateSelfEx, (ULONG, ACCESS_MASK, PHANDLE));

static void revert_self(void) {
    HANDLE n = NULL;
    UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-2, 5 /* ThreadImpersonationToken */, &n, sizeof n);
}
static NTSTATUS thread_token_level(ULONG *lvl, ULONG *type) {
    HANDLE h = NULL; ULONG rl = 0;
    NTSTATUS s = UN(NtOpenThreadToken)((HANDLE)(LONG_PTR)-2, TOKEN_QUERY, TRUE, &h);
    if (s < 0) return s;
    *lvl = 99; *type = 99;
    UN(NtQueryInformationToken)(h, 9 /* TokenImpersonationLevel */, lvl, 4, &rl);
    UN(NtQueryInformationToken)(h, 8 /* TokenType */, type, 4, &rl);
    UN(NtClose)(h);
    return 0;
}
TEST(rtl_rest_b_impersonate_self) {
    REQUIRE(UN(RtlImpersonateSelf)); REQUIRE(UN(NtOpenThreadToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtSetInformationThread));
    ULONG lvl = 0, type = 0;
    revert_self();
    EXPECT_EQ(thread_token_level(&lvl, &type), (NTSTATUS)0xC000007C);          /* STATUS_NO_TOKEN */
    for (ULONG want = 0; want <= 3; want++) {                                  /* anonymous .. delegation */
        NTSTATUS s = UN(RtlImpersonateSelf)(want);
        CHECKF(s == 0, "level %lu -> 0x%lx", (unsigned long)want, (unsigned long)s);
        if (s == 0) {
            NTSTATUS t = thread_token_level(&lvl, &type);
            if (want == 0) { /* an anonymous token is not openable at all or reports level 0 */
                EXPECT_EQ(t, (NTSTATUS)0xC00000A6);       /* STATUS_BAD_IMPERSONATION_LEVEL: an anonymous token cannot be opened */
            } else {
                EXPECT_EQ(t, 0);
                if (t == 0) { EXPECT_EQ(type, 2); EXPECT_EQ(lvl, want); }      /* TokenImpersonation, requested level */
            }
        }
        revert_self();
        EXPECT_EQ(thread_token_level(&lvl, &type), (NTSTATUS)0xC000007C);
    }
    NTSTATUS bad = UN(RtlImpersonateSelf)(4);
    EXPECT_EQ(bad, (NTSTATUS)0xC00000A5);                                      /* STATUS_BAD_IMPERSONATION_LEVEL */
    revert_self();
    EXPECT_EQ(thread_token_level(&lvl, &type), (NTSTATUS)0xC000007C);
}
TEST(rtl_rest_b_impersonate_self_ex) {
    REQUIRE(UN(RtlImpersonateSelfEx)); REQUIRE(UN(NtOpenThreadToken)); REQUIRE(UN(NtQueryInformationToken));
    REQUIRE(UN(NtSetInformationThread)); REQUIRE(UN(NtClose));
    ULONG lvl = 0, type = 0, rl = 0; HANDLE h = (HANDLE)1;
    revert_self();
    /* an access mask needs somewhere to return the handle */
    EXPECT_EQ(UN(RtlImpersonateSelfEx)(2, TOKEN_QUERY, NULL), (NTSTATUS)0xC00000F0);
    EXPECT_EQ(thread_token_level(&lvl, &type), (NTSTATUS)0xC000007C);          /* nothing was impersonated */
    /* no handle requested */
    EXPECT_EQ(UN(RtlImpersonateSelfEx)(2, 0, NULL), 0);
    EXPECT_EQ(thread_token_level(&lvl, &type), 0); EXPECT_EQ(lvl, 2); EXPECT_EQ(type, 2);
    revert_self();
    /* handle to the impersonation token returned */
    EXPECT_EQ(UN(RtlImpersonateSelfEx)(3, TOKEN_QUERY, &h), 0);
    CHECK(h != NULL && h != (HANDLE)1);
    if (h && h != (HANDLE)1) {
        lvl = type = 99;
        EXPECT_EQ(UN(NtQueryInformationToken)(h, 9, &lvl, 4, &rl), 0); EXPECT_EQ(lvl, 3);
        EXPECT_EQ(UN(NtQueryInformationToken)(h, 8, &type, 4, &rl), 0); EXPECT_EQ(type, 2);
        UN(NtClose)(h);
    }
    EXPECT_EQ(thread_token_level(&lvl, &type), 0); EXPECT_EQ(lvl, 3);
    revert_self();
    EXPECT_EQ(thread_token_level(&lvl, &type), (NTSTATUS)0xC000007C);
}

/* ---------------- default named-pipe ACL ---------------- */
UDECL(NTSTATUS, RtlDefaultNpAcl, (PACL *));
UDECL(BOOLEAN, RtlValidAcl, (PACL));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(NTSTATUS, RtlGetAce, (PACL, ULONG, PVOID *));
TEST(rtl_rest_b_default_np_acl) {
    REQUIRE(UN(RtlDefaultNpAcl)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(RtlGetAce));
    HANDLE tok = NULL; ULONG rl = 0, ac = 0;
    if (UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &tok) < 0) { t_skip("cannot open process token"); return; }
    UN(NtQueryInformationToken)(tok, 29 /* TokenIsAppContainer */, &ac, 4, &rl);
    UCHAR ub[sizeof(TOKEN_OWNER) + SECURITY_MAX_SID_SIZE + 16];
    EXPECT_EQ(UN(NtQueryInformationToken)(tok, 4 /* TokenOwner */, ub, sizeof ub, &rl), 0);
    UN(NtClose)(tok);
    if (ac) { t_skip("process token is an AppContainer token: extra ACEs are added"); return; }
    PSID user = ((TOKEN_OWNER *)ub)->Owner;                             /* default owner: the user, or Administrators when elevated */
    PACL acl = (PACL)1;
    EXPECT_EQ(UN(RtlDefaultNpAcl)(&acl), 0);
    CHECK(acl != NULL && acl != (PACL)1);
    if (!acl || acl == (PACL)1) return;
    EXPECT_EQ(acl->AclRevision, 2);
    EXPECT_EQ(acl->AceCount, 5);
    if (UN(RtlValidAcl)) EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
    static const UCHAR sys[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };                  /* S-1-5-18 */
    static const UCHAR adm[16] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0 };   /* S-1-5-32-544 */
    static const UCHAR wld[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };                   /* S-1-1-0 */
    static const UCHAR ano[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0 };                   /* S-1-5-7 */
    const UCHAR *fixed[5] = { sys, adm, NULL, wld, ano };
    static const ACCESS_MASK mask[5] = { 0x10000000, 0x10000000, 0x10000000, 0x80000000, 0x80000000 };
    for (ULONG i = 0; i < 5; i++) {
        ACCESS_ALLOWED_ACE *a = NULL;
        EXPECT_EQ(UN(RtlGetAce)(acl, i, (PVOID *)&a), 0);
        if (!a) continue;
        CHECKF(a->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ace %lu type %d", (unsigned long)i, a->Header.AceType);
        CHECKF(a->Header.AceFlags == 0, "ace %lu flags %d", (unsigned long)i, a->Header.AceFlags);
        CHECKF(a->Mask == mask[i], "ace %lu mask 0x%lx", (unsigned long)i, (unsigned long)a->Mask);
        PSID sid = (PSID)&a->SidStart;
        PSID ref = fixed[i] ? (PSID)fixed[i] : user;
        BOOLEAN eq = UN(RtlEqualSid) ? UN(RtlEqualSid)(sid, ref) : 0;
        CHECKF(eq, "ace %lu sid mismatch", (unsigned long)i);
    }
    ACE_HEADER *none = NULL;
    CHECK(UN(RtlGetAce)(acl, 5, (PVOID *)&none) < 0);
    CHECK(HeapFree(GetProcessHeap(), 0, acl));                       /* allocated from the process heap */
}

/* ---------------- registered waits ---------------- */
UDECL(NTSTATUS, RtlRegisterWait, (PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeregisterWait, (HANDLE));
UDECL(NTSTATUS, RtlDeregisterWaitEx, (HANDLE, HANDLE));
typedef struct { volatile LONG calls, timed; HANDLE entered, gate; } WCTX;
static VOID CALLBACK wait_cb(PVOID p, BOOLEAN timedout) {
    WCTX *c = p; InterlockedIncrement(&c->calls); if (timedout) InterlockedIncrement(&c->timed);
    if (c->entered) SetEvent(c->entered);
    if (c->gate) WaitForSingleObject(c->gate, 10000);
}
#define WT_ONCE 8
TEST(rtl_rest_b_deregister_wait) {
    REQUIRE(UN(RtlRegisterWait)); REQUIRE(UN(RtlDeregisterWait)); REQUIRE(UN(RtlDeregisterWaitEx));
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL), done = CreateEventW(NULL, FALSE, FALSE, NULL);
    WCTX c; memset(&c, 0, sizeof c); c.entered = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE w = NULL;
    /* unsignalled object: deregistration succeeds immediately and the callback never ran */
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, &c, INFINITE, WT_ONCE), 0);
    CHECK(w != NULL);
    if (w) EXPECT_EQ(UN(RtlDeregisterWait)(w), 0);
    EXPECT_EQ(c.calls, 0);
    /* blocking deregistration after the callback fired */
    w = NULL; c.calls = 0;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, &c, INFINITE, WT_ONCE), 0);
    SetEvent(ev);
    EXPECT_EQ(WaitForSingleObject(c.entered, 10000), WAIT_OBJECT_0);
    if (w) EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(c.calls, 1); EXPECT_EQ(c.timed, 0);
    /* timeout expiry reports TimerOrWaitFired */
    w = NULL; memset((void *)&c.calls, 0, 8);
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, &c, 30, WT_ONCE), 0);
    EXPECT_EQ(WaitForSingleObject(c.entered, 10000), WAIT_OBJECT_0);
    if (w) EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(c.calls, 1); EXPECT_EQ(c.timed, 1);
    /* callback still running: non-blocking forms report pending, the event is signalled when it ends */
    c.gate = CreateEventW(NULL, TRUE, FALSE, NULL); memset((void *)&c.calls, 0, 8);
    w = NULL;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, &c, INFINITE, WT_ONCE), 0);
    SetEvent(ev);
    EXPECT_EQ(WaitForSingleObject(c.entered, 10000), WAIT_OBJECT_0);
    if (w) {
        EXPECT_EQ(UN(RtlDeregisterWaitEx)(w, done), ST_PENDING);
        EXPECT_EQ(WaitForSingleObject(done, 100), WAIT_TIMEOUT);          /* callback still blocked */
        SetEvent(c.gate);
        EXPECT_EQ(WaitForSingleObject(done, 10000), WAIT_OBJECT_0);        /* completion event signalled */
    }
    EXPECT_EQ(c.calls, 1);
    /* same with the plain form */
    ResetEvent(c.gate); memset((void *)&c.calls, 0, 8); w = NULL;
    EXPECT_EQ(UN(RtlRegisterWait)(&w, ev, wait_cb, &c, INFINITE, WT_ONCE), 0);
    SetEvent(ev);
    EXPECT_EQ(WaitForSingleObject(c.entered, 10000), WAIT_OBJECT_0);
    if (w) EXPECT_EQ(UN(RtlDeregisterWait)(w), ST_PENDING);
    SetEvent(c.gate);
    Sleep(200);
    /* invalid handle */
    EXPECT_EQ(UN(RtlDeregisterWait)(NULL), (NTSTATUS)0xC00000EF);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(NULL, NULL), (NTSTATUS)0xC00000EF);
    EXPECT_EQ(UN(RtlDeregisterWaitEx)(NULL, INVALID_HANDLE_VALUE), (NTSTATUS)0xC00000EF);
    CloseHandle(ev); CloseHandle(done); CloseHandle(c.entered); CloseHandle(c.gate);
}

/* ---------------- thread / process exit ---------------- */
UDECL(VOID, RtlExitUserThread, (ULONG));
UDECL(VOID, RtlExitUserProcess, (ULONG));
UDECL(BOOLEAN, RtlDllShutdownInProgress, (VOID));
static volatile LONG g_after_exit;
static DWORD WINAPI exit_thread_proc(LPVOID p) {
    UN(RtlExitUserThread)((ULONG)(ULONG_PTR)p);
    InterlockedExchange(&g_after_exit, 1);
    return 0;
}
TEST(rtl_rest_b_exit_user_thread) {
    REQUIRE(UN(RtlExitUserThread));
    g_after_exit = 0;
    HANDLE th = CreateThread(NULL, 0, exit_thread_proc, (LPVOID)(ULONG_PTR)0x5150, 0, NULL);
    CHECK(th != NULL);
    if (!th) return;
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    DWORD code = 0; GetExitCodeThread(th, &code);
    EXPECT_EQ(code, 0x5150);
    EXPECT_EQ(g_after_exit, 0);                                    /* never returns to the caller */
    CloseHandle(th);
    /* a code that looks like STILL_ACTIVE is simply the exit code */
    th = CreateThread(NULL, 0, exit_thread_proc, (LPVOID)(ULONG_PTR)0xC0DE0001, 0, NULL);
    if (th) { WaitForSingleObject(th, 10000); GetExitCodeThread(th, &code); EXPECT_EQ(code, 0xC0DE0001); CloseHandle(th); }
}
static DWORD WINAPI sleeper(LPVOID p) { (void)p; Sleep(INFINITE); return 0; }
CHILD(rtl_rest_b_exit_proc_plain) {
    (void)argc; (void)argv;
    if (!UN(RtlExitUserProcess)) return 90;
    if (UN(RtlDllShutdownInProgress) && UN(RtlDllShutdownInProgress)()) return 91;
    UN(RtlExitUserProcess)(0x2A);
    return 92;
}
CHILD(rtl_rest_b_exit_proc_threads) {
    (void)argc; (void)argv;
    if (!UN(RtlExitUserProcess)) return 90;
    HANDLE t1 = CreateThread(NULL, 0, sleeper, NULL, 0, NULL), t2 = CreateThread(NULL, 0, sleeper, NULL, 0, NULL);
    if (!t1 || !t2) return 93;
    Sleep(50);
    UN(RtlExitUserProcess)(0x33);                                  /* terminates the sleeping threads as well */
    return 92;
}
TEST(rtl_rest_b_exit_user_process) {
    REQUIRE(UN(RtlExitUserProcess));
    EXPECT_EQ(t_run_child("rtl_rest_b_exit_proc_plain", "", 30000), 0x2A);
    EXPECT_EQ(t_run_child("rtl_rest_b_exit_proc_threads", "", 30000), 0x33);
}
TEST(rtl_rest_b_dll_shutdown_in_progress) {
    REQUIRE(UN(RtlDllShutdownInProgress));
    EXPECT_EQ(UN(RtlDllShutdownInProgress)(), FALSE);
}

/* ---------------- dynamic function tables ---------------- */
UDECL(DWORD, RtlAddGrowableFunctionTable, (PVOID *, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR));
UDECL(VOID, RtlDeleteGrowableFunctionTable, (PVOID));
UDECL(VOID, RtlGrowFunctionTable, (PVOID, ULONG));
UDECL(BOOLEAN, RtlInstallFunctionTableCallback, (DWORD64, DWORD64, DWORD, PGET_RUNTIME_FUNCTION_CALLBACK, PVOID, PCWSTR));
UDECL(BOOLEAN, RtlDeleteFunctionTable, (PRUNTIME_FUNCTION));
UDECL(PRUNTIME_FUNCTION, RtlLookupFunctionEntry, (DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE));

TEST(rtl_rest_b_growable_function_table) {
    REQUIRE(UN(RtlAddGrowableFunctionTable)); REQUIRE(UN(RtlDeleteGrowableFunctionTable));
    REQUIRE(UN(RtlGrowFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    PUCHAR range = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!range) { t_skip("no scratch memory"); return; }
    static RUNTIME_FUNCTION tab[4];
    memset(tab, 0, sizeof tab);
    tab[0].BeginAddress = 0x100; tab[0].EndAddress = 0x200; tab[0].UnwindData = 0x800;
    tab[1].BeginAddress = 0x300; tab[1].EndAddress = 0x400; tab[1].UnwindData = 0x800;
    tab[2].BeginAddress = 0x500; tab[2].EndAddress = 0x600; tab[2].UnwindData = 0x800;
    PVOID h = NULL; DWORD64 ib = 0;
    DWORD s = UN(RtlAddGrowableFunctionTable)(&h, tab, 1, 3, (ULONG_PTR)range, (ULONG_PTR)range + 0x10000);
    if ((NTSTATUS)s < 0) { t_note("RtlAddGrowableFunctionTable -> 0x%lx", (unsigned long)s); CHECK(0); VirtualFree(range, 0, MEM_RELEASE); return; }
    EXPECT_EQ(s, 0); CHECK(h != NULL);
    PRUNTIME_FUNCTION r = UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x150, &ib, NULL);
    EXPECT_EQ((ULONG_PTR)r, (ULONG_PTR)&tab[0]); EXPECT_EQ(ib, (DWORD64)(ULONG_PTR)range);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x350, &ib, NULL), 0);   /* not yet counted */
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x250, &ib, NULL), 0);   /* gap between functions */
    UN(RtlGrowFunctionTable)(h, 2);
    r = UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x350, &ib, NULL);
    EXPECT_EQ((ULONG_PTR)r, (ULONG_PTR)&tab[1]); EXPECT_EQ(ib, (DWORD64)(ULONG_PTR)range);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x550, &ib, NULL), 0);
    UN(RtlGrowFunctionTable)(h, 2);                                  /* same count is allowed */
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x350, &ib, NULL), (ULONG_PTR)&tab[1]);
    UN(RtlGrowFunctionTable)(h, 3);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x5FF, &ib, NULL), (ULONG_PTR)&tab[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x600, &ib, NULL), 0);   /* end address is exclusive */
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x100, &ib, NULL), (ULONG_PTR)&tab[0]);
    UN(RtlDeleteGrowableFunctionTable)(h);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)range + 0x150, &ib, NULL), 0);
    VirtualFree(range, 0, MEM_RELEASE);
}
static volatile LONG g_ft_calls; static volatile DWORD64 g_ft_pc; static volatile PVOID g_ft_ctx;
static RUNTIME_FUNCTION g_ft_rf = { 0x10, 0x90, 0x800 };
static PRUNTIME_FUNCTION NTAPI ft_cb(DWORD64 pc, PVOID ctx) {
    InterlockedIncrement(&g_ft_calls); g_ft_pc = pc; g_ft_ctx = ctx;
    return (pc & 1) ? NULL : &g_ft_rf;
}
TEST(rtl_rest_b_function_table_callback) {
    REQUIRE(UN(RtlInstallFunctionTableCallback)); REQUIRE(UN(RtlDeleteFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    PUCHAR range = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!range) { t_skip("no scratch memory"); return; }
    DWORD64 base = (DWORD64)(ULONG_PTR)range, id = base | 3, ib = 0;
    /* argument validation */
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(base, base, 0x1000, ft_cb, NULL, NULL), FALSE);        /* identifier low bits must be 3 */
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(base | 1, base, 0x1000, ft_cb, NULL, NULL), FALSE);
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(base | 2, base, 0x1000, ft_cb, NULL, NULL), FALSE);
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(id, base, 0x80000000u, ft_cb, NULL, NULL), FALSE);    /* length must fit 31 bits */
    EXPECT_EQ(UN(RtlDeleteFunctionTable)((PRUNTIME_FUNCTION)(ULONG_PTR)id), FALSE);                      /* nothing installed under this id */
    g_ft_calls = 0;
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(id, base, 0x10000, ft_cb, (PVOID)0xC0FFEE, NULL), TRUE);
    EXPECT_EQ(g_ft_calls, 0);                                                                            /* installing does not call back */
    PRUNTIME_FUNCTION r = UN(RtlLookupFunctionEntry)(base + 0x1234, &ib, NULL);
    EXPECT_EQ((ULONG_PTR)r, (ULONG_PTR)&g_ft_rf);
    EXPECT_EQ(g_ft_calls, 1); EXPECT_EQ(g_ft_pc, base + 0x1234); EXPECT_EQ(g_ft_ctx, (PVOID)0xC0FFEE);
    t_note("callback table lookup reported ImageBase 0x%llx (range base 0x%llx)", (unsigned long long)ib, (unsigned long long)base);
    CHECK(ib == base);
    g_ft_calls = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)(base + 0x1235, &ib, NULL), 0);                       /* callback returned NULL */
    EXPECT_EQ(g_ft_calls, 1);
    g_ft_calls = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)(base + 0x10000, &ib, NULL) == (ULONG_PTR)&g_ft_rf, 0);   /* one past the range */
    EXPECT_EQ(g_ft_calls, 0);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)((PRUNTIME_FUNCTION)(ULONG_PTR)id), TRUE);
    g_ft_calls = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)(base + 0x1234, &ib, NULL), 0);
    EXPECT_EQ(g_ft_calls, 0);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)((PRUNTIME_FUNCTION)(ULONG_PTR)id), FALSE);                      /* already removed */
    VirtualFree(range, 0, MEM_RELEASE);
}

/* ---------------- activation context frames ---------------- */
UDECL(NTSTATUS, RtlActivateActivationContext, (ULONG, HANDLE, PULONG_PTR));
UDECL(VOID, RtlDeactivateActivationContext, (ULONG, ULONG_PTR));
UDECL(NTSTATUS, RtlGetActiveActivationContext, (HANDLE *));
UDECL(PVOID, RtlActivateActivationContextUnsafeFast, (PVOID, HANDLE));
UDECL(PVOID, RtlDeactivateActivationContextUnsafeFast, (PVOID));
static HANDLE make_actctx(void) {
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "ctx.manifest");
    static const char xml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
        "<assemblyIdentity type=\"win32\" name=\"rtlrestb.test.app\" version=\"1.0.0.0\"/>\r\n</assembly>\r\n";
    HANDLE f = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    DWORD w; WriteFile(f, xml, sizeof xml - 1, &w, NULL); CloseHandle(f);
    WCHAR wp[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    ACTCTXW ac; memset(&ac, 0, sizeof ac); ac.cbSize = sizeof ac; ac.lpSource = wp;
    HANDLE h = CreateActCtxW(&ac);
    DeleteFileA(p);
    return h;
}
TEST(rtl_rest_b_deactivate_activation_context) {
    REQUIRE(UN(RtlActivateActivationContext)); REQUIRE(UN(RtlDeactivateActivationContext)); REQUIRE(UN(RtlGetActiveActivationContext));
    HANDLE ctx = make_actctx();
    if (ctx == INVALID_HANDLE_VALUE) { t_skip("cannot create an activation context from a manifest"); return; }
    HANDLE before = (HANDLE)1, cur = (HANDLE)1; ULONG_PTR cookie = 0, cookie2 = 0;
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&before), 0);
    EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &cookie), 0);
    CHECK(cookie != 0);
    EXPECT_EQ(cookie >> 60, 1);                                        /* cookie type nibble */
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    /* a zero cookie is ignored */
    UN(RtlDeactivateActivationContext)(0, 0);
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    /* nesting: the inner deactivation restores the outer context */
    EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &cookie2), 0);
    CHECK(cookie2 != 0 && cookie2 != cookie);
    UN(RtlDeactivateActivationContext)(0, cookie2);
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    UN(RtlDeactivateActivationContext)(0, cookie);
    cur = (HANDLE)1; EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, before);
    /* forced early deactivation flag */
    cookie = 0; EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &cookie), 0);
    UN(RtlDeactivateActivationContext)(1, cookie);
    cur = (HANDLE)1; EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, before);
    ReleaseActCtx(ctx);
}
TEST(rtl_rest_b_deactivate_activation_context_unsafe_fast) {
    REQUIRE(UN(RtlActivateActivationContextUnsafeFast)); REQUIRE(UN(RtlDeactivateActivationContextUnsafeFast));
    REQUIRE(UN(RtlGetActiveActivationContext));
    HANDLE ctx = make_actctx();
    if (ctx == INVALID_HANDLE_VALUE) { t_skip("cannot create an activation context from a manifest"); return; }
    HANDLE before = (HANDLE)1, cur = (HANDLE)1;
    ULONG_PTR frame[9]; memset(frame, 0, sizeof frame);
    frame[0] = sizeof frame;          /* Size (extended frame) */
    frame[1] = 1;                     /* Format: Whistler */
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&before), 0);
    UN(RtlActivateActivationContextUnsafeFast)(frame, ctx);
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    UN(RtlDeactivateActivationContextUnsafeFast)(frame);
    cur = (HANDLE)1; EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, before);
    /* a second pair on the same frame storage works again */
    memset(frame, 0, sizeof frame); frame[0] = sizeof frame; frame[1] = 1;
    UN(RtlActivateActivationContextUnsafeFast)(frame, ctx);
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    UN(RtlDeactivateActivationContextUnsafeFast)(frame);
    cur = (HANDLE)1; EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, before);
    ReleaseActCtx(ctx);
}

/* ---------------- secure memory cache ---------------- */
UDECL(NTSTATUS, RtlRegisterSecureMemoryCacheCallback, (PVOID));
UDECL(BOOLEAN, RtlDeregisterSecureMemoryCacheCallback, (PVOID));
UDECL(BOOLEAN, RtlFlushSecureMemoryCache, (PVOID, SIZE_T));
static volatile LONG g_sm_calls; static volatile PVOID g_sm_addr; static volatile SIZE_T g_sm_len; static volatile BOOLEAN g_sm_ret; static volatile LONG g_sm2_calls;
static BOOLEAN NTAPI sm_cb(PVOID a, SIZE_T n) { InterlockedIncrement(&g_sm_calls); g_sm_addr = a; g_sm_len = n; return g_sm_ret; }
static BOOLEAN NTAPI sm_cb2(PVOID a, SIZE_T n) { (void)a; (void)n; InterlockedIncrement(&g_sm2_calls); return FALSE; }
TEST(rtl_rest_b_secure_memory_cache) {
    REQUIRE(UN(RtlRegisterSecureMemoryCacheCallback)); REQUIRE(UN(RtlDeregisterSecureMemoryCacheCallback)); REQUIRE(UN(RtlFlushSecureMemoryCache));
    PUCHAR m = VirtualAlloc(NULL, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) { t_skip("no scratch memory"); return; }
    g_sm_ret = TRUE;
    /* nothing registered */
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb), FALSE);
    g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0x1000), FALSE);
    EXPECT_EQ(g_sm_calls, 0);
    /* registered */
    EXPECT_EQ(UN(RtlRegisterSecureMemoryCacheCallback)(sm_cb), 0);
    g_sm_calls = 0; g_sm_ret = TRUE;                                      /* the callback result is a BOOLEAN: TRUE = flushed */
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m + 0x10, 0x1000), TRUE);
    EXPECT_EQ(g_sm_calls, 1); EXPECT_EQ(g_sm_addr, (PVOID)(m + 0x10)); EXPECT_EQ(g_sm_len, 0x1000);
    /* a callback that reports FALSE makes the flush report FALSE */
    g_sm_ret = FALSE;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0x1000), FALSE);
    EXPECT_EQ(g_sm_calls, 2);
    /* with several callbacks all are called and any TRUE makes the result TRUE */
    EXPECT_EQ(UN(RtlRegisterSecureMemoryCacheCallback)(sm_cb2), 0);
    g_sm2_calls = 0; g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0x1000), FALSE);
    EXPECT_EQ(g_sm_calls, 1); EXPECT_EQ(g_sm2_calls, 1);
    g_sm_ret = TRUE;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0x1000), TRUE);
    EXPECT_EQ(g_sm_calls, 2); EXPECT_EQ(g_sm2_calls, 2);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb2), TRUE);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb2), FALSE);
    g_sm_ret = TRUE;
    /* a zero length selects the whole region the address belongs to */
    g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0), TRUE);
    EXPECT_EQ(g_sm_calls, 1); EXPECT_EQ(g_sm_addr, (PVOID)m); EXPECT_EQ(g_sm_len, 0x3000);
    /* zero length on unallocated address space: no callback */
    VirtualFree(m, 0, MEM_RELEASE);
    g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)(m, 0), FALSE);
    EXPECT_EQ(g_sm_calls, 0);
    /* registrations are counted */
    EXPECT_EQ(UN(RtlRegisterSecureMemoryCacheCallback)(sm_cb), 0);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb), TRUE);
    g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)((PVOID)0x10000, 0x1000), TRUE);   /* still registered once */
    EXPECT_EQ(g_sm_calls, 1);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb), TRUE);
    g_sm_calls = 0;
    EXPECT_EQ(UN(RtlFlushSecureMemoryCache)((PVOID)0x10000, 0x1000), FALSE);
    EXPECT_EQ(g_sm_calls, 0);
    EXPECT_EQ(UN(RtlDeregisterSecureMemoryCacheCallback)(sm_cb), FALSE);
}

/* ---------------- thread profiling argument checks ---------------- */
UDECL(NTSTATUS, RtlEnableThreadProfiling, (HANDLE, ULONG, ULONG64, PVOID *));
UDECL(NTSTATUS, RtlDisableThreadProfiling, (PVOID));
TEST(rtl_rest_b_thread_profiling) {
    REQUIRE(UN(RtlEnableThreadProfiling)); REQUIRE(UN(RtlDisableThreadProfiling));
    PVOID h = (PVOID)0x77; HANDLE self = (HANDLE)(LONG_PTR)-2;
    EXPECT_EQ(UN(RtlEnableThreadProfiling)(self, 2, 0, &h), (NTSTATUS)0xC00000F0);           /* only flag bit 0 is defined */
    EXPECT_EQ(UN(RtlEnableThreadProfiling)(self, 0x80000000, 0, &h), (NTSTATUS)0xC00000F0);
    EXPECT_EQ(UN(RtlEnableThreadProfiling)(self, 0, 0x10000, &h), (NTSTATUS)0xC00000F1);     /* counter mask limited to 16 bits */
    EXPECT_EQ(UN(RtlEnableThreadProfiling)(self, 1, 0x1000000, &h), (NTSTATUS)0xC00000F1);
    EXPECT_EQ(UN(RtlEnableThreadProfiling)(self, 3, 0x10000, &h), (NTSTATUS)0xC00000F0);      /* flags are checked first */
    EXPECT_EQ(h, (PVOID)0x77);
    NTSTATUS s = UN(RtlEnableThreadProfiling)(self, 0, 0, &h);
    if (s == 0) {
        CHECK(h != NULL && h != (PVOID)0x77);
        EXPECT_EQ(UN(RtlDisableThreadProfiling)(h), 0);
    } else {
        t_note("RtlEnableThreadProfiling(self,0,0) -> 0x%lx", (unsigned long)s);
        EXPECT_EQ(h, (PVOID)0x77);
        CHECK(s < 0);
    }
}

/* ---------------- small state helpers ---------------- */
UDECL(VOID, RtlFlushHeaps, (VOID));
UDECL(NTSTATUS, RtlDisownModuleHeapAllocation, (HANDLE, PVOID));
UDECL(VOID, RtlEnableEarlyCriticalSectionEventCreation, (VOID));
UDECL(NTSTATUS, RtlInitializeCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlDeleteCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlGuardCheckLongJumpTarget, (PVOID, BOOLEAN, PBOOLEAN));
TEST(rtl_rest_b_flush_heaps) {
    REQUIRE(UN(RtlFlushHeaps));
    HANDLE hp = GetProcessHeap(); PUCHAR a = HeapAlloc(hp, 0, 100), b = HeapAlloc(hp, 0, 5000);
    CHECK(a && b);
    if (a) memset(a, 0x42, 100);
    UN(RtlFlushHeaps)();
    CHECK(HeapValidate(hp, 0, NULL));
    if (a) { EXPECT_EQ(a[0], 0x42); EXPECT_EQ(a[99], 0x42); EXPECT_EQ(HeapSize(hp, 0, a), 100); HeapFree(hp, 0, a); }
    if (b) { EXPECT_EQ(HeapSize(hp, 0, b), 5000); HeapFree(hp, 0, b); }
    UN(RtlFlushHeaps)();
    CHECK(HeapValidate(hp, 0, NULL));
}
TEST(rtl_rest_b_disown_module_heap_allocation) {
    REQUIRE(UN(RtlDisownModuleHeapAllocation));
    HANDLE hp = GetProcessHeap(); PVOID p = HeapAlloc(hp, 0, 64);
    CHECK(p != NULL);
    EXPECT_EQ(UN(RtlDisownModuleHeapAllocation)(hp, p), 0);
    if (p) { EXPECT_EQ(HeapSize(hp, 0, p), 64); CHECK(HeapFree(hp, 0, p)); }       /* the block stays an ordinary allocation */
    EXPECT_EQ(UN(RtlDisownModuleHeapAllocation)(NULL, NULL), 0);
}
TEST(rtl_rest_b_enable_early_cs_event_creation) {
    REQUIRE(UN(RtlEnableEarlyCriticalSectionEventCreation)); REQUIRE(UN(RtlInitializeCriticalSection)); REQUIRE(UN(RtlDeleteCriticalSection));
    volatile ULONG *flags = (volatile ULONG *)((PUCHAR)NtCurrentTeb()->ProcessEnvironmentBlock + 0xBC);   /* PEB.NtGlobalFlag */
    ULONG orig = *flags;
    RTL_CRITICAL_SECTION cs;
    if (!(orig & 0x10000000)) {
        memset(&cs, 0, sizeof cs);
        EXPECT_EQ(UN(RtlInitializeCriticalSection)(&cs), 0);
        EXPECT_EQ((ULONG_PTR)cs.LockSemaphore, 0);                           /* lazily created by default */
        UN(RtlDeleteCriticalSection)(&cs);
    }
    UN(RtlEnableEarlyCriticalSectionEventCreation)();
    EXPECT_EQ(*flags & 0x10000000, 0x10000000);                              /* FLG_CRITSEC_EVENT_CREATION */
    EXPECT_EQ(*flags & ~0x10000000u, orig & ~0x10000000u);                    /* nothing else changes */
    memset(&cs, 0, sizeof cs);
    EXPECT_EQ(UN(RtlInitializeCriticalSection)(&cs), 0);
    t_note("LockSemaphore after early-event creation: %p (observed only)", (void *)cs.LockSemaphore);
    UN(RtlDeleteCriticalSection)(&cs);
    UN(RtlEnableEarlyCriticalSectionEventCreation)();                        /* idempotent */
    EXPECT_EQ(*flags & 0x10000000, 0x10000000);
    *flags = orig;                                                           /* restore the process state */
}
TEST(rtl_rest_b_guard_check_long_jump_target) {
    REQUIRE(UN(RtlGuardCheckLongJumpTarget));
    BOOLEAN valid = 0xEE;
    EXPECT_EQ(UN(RtlGuardCheckLongJumpTarget)((PVOID)test_rtl_rest_b_guard_check_long_jump_target, FALSE, &valid), 0);
    EXPECT_EQ(valid, 1);                                                     /* process is not CFG-enforced: every target is valid */
    valid = 0xEE;
    EXPECT_EQ(UN(RtlGuardCheckLongJumpTarget)((PVOID)0x10, TRUE, &valid), 0);
    EXPECT_EQ(valid, 1);
    EXPECT_EQ(UN(RtlGuardCheckLongJumpTarget)((PVOID)test_rtl_rest_b_guard_check_long_jump_target, FALSE, NULL), 0);
}

/* ---------------- user-mode scheduling argument checks ---------------- */
UDECL(NTSTATUS, RtlEnterUmsSchedulingMode, (PVOID));
UDECL(NTSTATUS, RtlExecuteUmsThread, (PVOID));
UDECL(NTSTATUS, RtlDequeueUmsCompletionListItems, (PVOID, PLARGE_INTEGER, PVOID *));
TEST(rtl_rest_b_ums_argument_checks) {
    REQUIRE(UN(RtlEnterUmsSchedulingMode)); REQUIRE(UN(RtlExecuteUmsThread)); REQUIRE(UN(RtlDequeueUmsCompletionListItems));
    ULONG_PTR info[8]; memset(info, 0, sizeof info);
    EXPECT_EQ(UN(RtlEnterUmsSchedulingMode)(info), ST_INVPARAM);               /* UmsVersion must be 0x100 */
    ((ULONG *)info)[0] = 0x101; EXPECT_EQ(UN(RtlEnterUmsSchedulingMode)(info), ST_INVPARAM);
    ((ULONG *)info)[0] = 0xFF;  EXPECT_EQ(UN(RtlEnterUmsSchedulingMode)(info), ST_INVPARAM);
    EXPECT_EQ(UN(RtlExecuteUmsThread)(NULL), ST_INVPARAM);
    PVOID items = (PVOID)1; LARGE_INTEGER zero; zero.QuadPart = 0;
    EXPECT_EQ(UN(RtlDequeueUmsCompletionListItems)(NULL, &zero, &items), ST_INVPARAM);
    ULONG_PTR dummy[2] = { 0, 0 };
    EXPECT_EQ(UN(RtlDequeueUmsCompletionListItems)(dummy, &zero, NULL), ST_INVPARAM);
}
