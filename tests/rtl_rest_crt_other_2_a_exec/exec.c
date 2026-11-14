#include "t.h"
#include <stdlib.h>

UDECL(LONG, RtlKnownExceptionFilter, (PEXCEPTION_POINTERS));
UDECL(PVOID, RtlLocateLegacyContext, (PVOID, PULONG));
UDECL(PVOID, RtlLocateExtendedFeature, (PVOID, ULONG, PULONG));
UDECL(PVOID, RtlLocateExtendedFeature2, (PVOID, ULONG, PVOID, PULONG));
UDECL(VOID, RtlLookupFunctionTable, (ULONG_PTR, PULONG_PTR, PULONG));
UDECL(VOID, RtlRestoreContext, (PCONTEXT, PEXCEPTION_RECORD));
UDECL(VOID, RtlCaptureContext, (PCONTEXT));
UDECL(VOID, RtlRaiseStatus, (NTSTATUS));
UDECL(VOID, RtlRaiseNoncontinuableException, (PEXCEPTION_RECORD, PCONTEXT, BOOLEAN));
UDECL(NTSTATUS, RtlQueueWorkItem, (PVOID, PVOID, ULONG));
UDECL(NTSTATUS, RtlQueueApcWow64Thread, (HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtQueueApcThread, (HANDLE, PVOID, PVOID, PVOID, PVOID));
UDECL(PVOID, RtlNormalizeProcessParams, (PVOID));
UDECL(ULONG, RtlOsDeploymentState, (void));
UDECL(NTSTATUS, RtlRetrieveNtUserPfn, (PVOID *, PVOID *, PVOID *));
UDECL(PVOID, RtlAddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(ULONG, RtlRemoveVectoredExceptionHandler, (PVOID));

#define S(x) ((NTSTATUS)(x))
#define NOINLINE __attribute__((noinline))

/* ---------- RtlKnownExceptionFilter ---------- */
TEST(known_exception_filter) {
    EXCEPTION_RECORD r; EXCEPTION_POINTERS ep; ULONG codes[] = { 0xC0000005, 0xC0000194 + 1, 0x80000003, 0, 0xE06D7363, 0xC00000FD, 0xC0000193 };
    size_t i;
    REQUIRE(UN(RtlKnownExceptionFilter));
    memset(&r, 0, sizeof r); ep.ExceptionRecord = &r; ep.ContextRecord = NULL;
    r.ExceptionCode = 0xC0000194;                              /* STATUS_POSSIBLE_DEADLOCK: continue execution */
    EXPECT_EQ(UN(RtlKnownExceptionFilter)(&ep), EXCEPTION_CONTINUE_EXECUTION);
    for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        r.ExceptionCode = codes[i];
        CHECKF(UN(RtlKnownExceptionFilter)(&ep) == EXCEPTION_CONTINUE_SEARCH, "code 0x%lx did not continue the search", codes[i]);
    }
}

/* ---------- RtlLocateLegacyContext ---------- */
TEST(locate_legacy_context) {
    /* CONTEXT_EX-shaped header: {All.Offset, All.Length, Legacy.Offset, Legacy.Length} */
    LONG hdr[4]; ULONG len; PVOID p;
    static UCHAR blk[0x200];
    REQUIRE(UN(RtlLocateLegacyContext));
    memset(blk, 0, sizeof blk);
    { LONG *h = (LONG *)blk; h[0] = -0x100; h[1] = 0x300; h[2] = 0x20; h[3] = 0x100; (void)hdr; }
    len = 0xDEAD;
    p = UN(RtlLocateLegacyContext)(blk, &len);
    EXPECT_EQ(p, blk + 0x20); EXPECT_EQ(len, 0x100);
    p = UN(RtlLocateLegacyContext)(blk, NULL);                  /* length output is optional */
    EXPECT_EQ(p, blk + 0x20);
    /* legacy chunk exactly filling the range is accepted, one byte more is not */
    { LONG *h = (LONG *)blk; h[0] = 0x10; h[1] = 0x110; h[2] = 0x10; h[3] = 0x110; }
    len = 0xDEAD; p = UN(RtlLocateLegacyContext)(blk, &len);
    EXPECT_EQ(p, blk + 0x10); EXPECT_EQ(len, 0x110);
    { LONG *h = (LONG *)blk; h[3] = 0x111; }
    len = 0xDEAD; p = UN(RtlLocateLegacyContext)(blk, &len);
    EXPECT_EQ(p, NULL); EXPECT_EQ(len, 0xDEAD);                 /* output untouched on failure */
    /* legacy chunk starting before the range */
    { LONG *h = (LONG *)blk; h[0] = 0x20; h[1] = 0x100; h[2] = 0x10; h[3] = 0x10; }
    EXPECT_EQ(UN(RtlLocateLegacyContext)(blk, &len), NULL);
}

/* ---------- RtlLocateExtendedFeature / 2 ---------- */
typedef BOOL (WINAPI *InitCtx_t)(PVOID, DWORD, PCONTEXT *, PDWORD);
typedef PVOID (WINAPI *LocXS_t)(PCONTEXT, DWORD, PDWORD);
typedef ULONG64 (WINAPI *GetXS_t)(void);
TEST(locate_extended_feature) {
    InitCtx_t ic = (InitCtx_t)t_proc_in("kernel32.dll", "InitializeContext");
    LocXS_t lx = (LocXS_t)t_proc_in("kernel32.dll", "LocateXStateFeature");
    GetXS_t ge = (GetXS_t)t_proc_in("kernel32.dll", "GetEnabledXStateFeatures");
    DWORD len = 0, l1 = 0xDEAD, l2 = 0xDEAD; PVOID buf; PCONTEXT ctx = NULL; PVOID p1, p2, p3; ULONG f;
    UCHAR cfg[0x340];
    REQUIRE(UN(RtlLocateExtendedFeature)); REQUIRE(UN(RtlLocateExtendedFeature2));
    if (!ic || !lx || !ge) { t_skip("xstate APIs missing from kernel32"); return; }
    if (!(ge() & 4)) { t_skip("AVX state not enabled on this CPU/VM"); return; }
    ic(NULL, 0x100040 | 0x1F, NULL, &len);
    buf = malloc(len + 64);
    if (!buf || !ic(buf, 0x100040 | 0x1F, &ctx, &len)) { free(buf); t_skip("InitializeContext with XSTATE failed (GLE %lu)", GetLastError()); return; }
    p1 = lx(ctx, 2, &l1);
    p2 = UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 2, &l2);
    CHECK(p1 != NULL);
    EXPECT_EQ(p2, p1);
    EXPECT_EQ(l2, l1);
    EXPECT_EQ(l2, 256);                                        /* YMM_H: 16 x 16 bytes */
    p2 = UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 2, NULL);
    EXPECT_EQ(p2, p1);                                         /* length output optional */
    /* ids below 2 are the legacy area, ids from 64 up do not exist */
    EXPECT_EQ(UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 0, &l2), NULL);
    EXPECT_EQ(UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 1, &l2), NULL);
    EXPECT_EQ(UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 64, &l2), NULL);
    EXPECT_EQ(UN(RtlLocateExtendedFeature)((PVOID)(ctx + 1), 0xFFFFFFFF, &l2), NULL);
    /* the 2 variant takes the configuration explicitly: use the one from shared user data */
    l2 = 0xDEAD;
    p3 = UN(RtlLocateExtendedFeature2)((PVOID)(ctx + 1), 2, (PVOID)(ULONG_PTR)0x7ffe03d8, &l2);
    EXPECT_EQ(p3, p1); EXPECT_EQ(l2, 256);
    /* a configuration with no features enabled locates nothing */
    memcpy(cfg, (void *)(ULONG_PTR)0x7ffe03d8, sizeof cfg);
    for (f = 0; f < 8; f++) cfg[f] = 0;                        /* EnabledFeatures */
    memset(cfg + 0x330, 0, 8);                                  /* the second feature mask word */
    l2 = 0xDEAD;
    EXPECT_EQ(UN(RtlLocateExtendedFeature2)((PVOID)(ctx + 1), 2, cfg, &l2), NULL);
    EXPECT_EQ(l2, 0xDEAD);
    free(buf);
}

/* ---------- RtlLookupFunctionTable ---------- */
static ULONG pe_exception_size(HMODULE m) {
    IMAGE_DOS_HEADER *d = (void *)m; IMAGE_NT_HEADERS64 *n = (void *)((char *)m + d->e_lfanew);
    return n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
}
NOINLINE static void local_func(void) { __asm__ volatile(""); }
TEST(lookup_function_table) {
    ULONG_PTR base = 0; ULONG len = 0; HMODULE nt = GetModuleHandleA("ntdll.dll"), self = GetModuleHandleA(NULL);
    FARPROC f = t_proc("RtlLookupFunctionTable");
    REQUIRE(UN(RtlLookupFunctionTable));
    CHECK(nt != NULL);
    UN(RtlLookupFunctionTable)((ULONG_PTR)f, &base, &len);
    EXPECT_EQ(base, (ULONG_PTR)nt);
    EXPECT_EQ(len, pe_exception_size(nt));
    CHECK(len > 0);
    /* an address inside this executable resolves to its own table */
    base = 0; len = 0;
    UN(RtlLookupFunctionTable)((ULONG_PTR)&local_func, &base, &len);
    EXPECT_EQ(base, (ULONG_PTR)self);
    EXPECT_EQ(len, pe_exception_size(self));
    /* an address of another loaded module */
    {
        HMODULE k = GetModuleHandleA("kernel32.dll");
        base = 0; len = 0;
        UN(RtlLookupFunctionTable)((ULONG_PTR)GetProcAddress(k, "CreateFileW"), &base, &len);
        EXPECT_EQ(base, (ULONG_PTR)k); EXPECT_EQ(len, pe_exception_size(k));
    }
    /* an address that is not in any image leaves the outputs alone */
    base = 0x1111; len = 0x2222;
    UN(RtlLookupFunctionTable)(0x10, &base, &len);
    EXPECT_EQ(base, 0x1111); EXPECT_EQ(len, 0x2222);
    base = 0x1111; len = 0x2222;
    UN(RtlLookupFunctionTable)((ULONG_PTR)&base, &base, &len);   /* stack address */
    EXPECT_EQ(base, 0x1111); EXPECT_EQ(len, 0x2222);
}

/* ---------- RtlRestoreContext ---------- */
static CONTEXT g_rc;
NOINLINE static int restore_probe(int use_record) {
    volatile int n = 0;
    UN(RtlCaptureContext)(&g_rc);
    n++;
    if (n == 1) {
        EXCEPTION_RECORD r;
        if (use_record) { memset(&r, 0, sizeof r); r.ExceptionCode = 0xE0000001; UN(RtlRestoreContext)(&g_rc, &r); }
        else UN(RtlRestoreContext)(&g_rc, NULL);
    }
    return n;
}
TEST(restore_context) {
    REQUIRE(UN(RtlRestoreContext)); REQUIRE(UN(RtlCaptureContext));
    EXPECT_EQ(restore_probe(0), 2);             /* control returns to the capture point exactly once more */
    EXPECT_EQ(restore_probe(1), 2);             /* an ordinary exception record does not change the outcome */
    EXPECT_EQ(g_rc.ContextFlags & 0x100000, 0x100000);
}

/* ---------- raising exceptions ---------- */
static CONTEXT g_jmp;
static volatile LONG g_state;
static ULONG g_want_code, g_restore;
static EXCEPTION_RECORD g_seen;
static LONG CALLBACK probe_veh(PEXCEPTION_POINTERS ep) {
    if (g_state == 1 && ep->ExceptionRecord->ExceptionCode == g_want_code) {
        g_seen = *ep->ExceptionRecord;
        g_state = 2;
        if (g_restore) *ep->ContextRecord = g_jmp;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
NOINLINE static void probe_raise_status(NTSTATUS st) {
    UN(RtlCaptureContext)(&g_jmp);
    if (g_state == 0) { g_state = 1; UN(RtlRaiseStatus)(st); }
}
NOINLINE static void probe_raise_nc(PEXCEPTION_RECORD r, PCONTEXT c) {
    UN(RtlCaptureContext)(&g_jmp);
    if (g_state == 0) { g_state = 1; UN(RtlRaiseNoncontinuableException)(r, c, TRUE); }
}
TEST(raise_status_noncontinuable) {
    PVOID h;
    REQUIRE(UN(RtlRaiseStatus)); REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredExceptionHandler)); REQUIRE(UN(RtlCaptureContext));
    h = UN(RtlAddVectoredExceptionHandler)(1, probe_veh);
    CHECK(h != NULL);
    g_want_code = 0xE0001234; g_restore = 1; g_state = 0; memset(&g_seen, 0, sizeof g_seen);
    probe_raise_status((NTSTATUS)0xE0001234);
    UN(RtlRemoveVectoredExceptionHandler)(h);
    EXPECT_EQ(g_state, 2);
    EXPECT_EQ(g_seen.ExceptionCode, 0xE0001234);
    EXPECT_EQ(g_seen.ExceptionFlags & EXCEPTION_NONCONTINUABLE, EXCEPTION_NONCONTINUABLE);
    EXPECT_EQ(g_seen.NumberParameters, 0);
    EXPECT_EQ(g_seen.ExceptionRecord, NULL);
    CHECK(g_seen.ExceptionAddress != NULL);
}
TEST(raise_noncontinuable_exception_record) {
    PVOID h; EXCEPTION_RECORD r; static CONTEXT c;
    REQUIRE(UN(RtlRaiseNoncontinuableException)); REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredExceptionHandler)); REQUIRE(UN(RtlCaptureContext));
    h = UN(RtlAddVectoredExceptionHandler)(1, probe_veh);
    memset(&r, 0, sizeof r); r.ExceptionCode = 0xE0005678; r.ExceptionFlags = 0; r.NumberParameters = 2;
    r.ExceptionInformation[0] = 0x1111; r.ExceptionInformation[1] = 0x2222;
    g_want_code = 0xE0005678; g_restore = 1; g_state = 0; memset(&g_seen, 0, sizeof g_seen);
    probe_raise_nc(&r, &c);
    UN(RtlRemoveVectoredExceptionHandler)(h);
    EXPECT_EQ(g_state, 2);
    EXPECT_EQ(g_seen.ExceptionCode, 0xE0005678);
    EXPECT_EQ(g_seen.NumberParameters, 2);
    EXPECT_EQ(g_seen.ExceptionInformation[0], 0x1111); EXPECT_EQ(g_seen.ExceptionInformation[1], 0x2222);
    CHECK(g_seen.ExceptionAddress != NULL);
    EXPECT_EQ(g_seen.ExceptionAddress, (PVOID)c.Rip);          /* the address is taken from the supplied context */
    CHECK(c.Rip != 0 && c.Rsp != 0);                            /* the context was captured */
}
/* ---------- work items and APCs ---------- */
static volatile LONG g_wi_hits; static volatile DWORD g_wi_tid; static volatile PVOID g_wi_ctx; static HANDLE g_wi_ev;
static VOID WINAPI wi_cb(PVOID ctx) {
    g_wi_ctx = ctx; g_wi_tid = GetCurrentThreadId(); InterlockedIncrement(&g_wi_hits); SetEvent(g_wi_ev);
}
TEST(queue_work_item) {
    ULONG flags[] = { 0, 0x10 /* WT_EXECUTELONGFUNCTION */, 0x20 /* WT_EXECUTEINPERSISTENTTHREAD */ }; size_t i;
    REQUIRE(UN(RtlQueueWorkItem));
    g_wi_ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    for (i = 0; i < 3; i++) {
        LONG before = g_wi_hits; PVOID tag = (PVOID)(ULONG_PTR)(0xABC00 + i);
        g_wi_ctx = NULL; g_wi_tid = 0;
        EXPECT_EQ(UN(RtlQueueWorkItem)((PVOID)wi_cb, tag, flags[i]), 0);
        EXPECT_EQ(WaitForSingleObject(g_wi_ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(g_wi_hits, before + 1);
        EXPECT_EQ(g_wi_ctx, tag);
        EXPECT_NE(g_wi_tid, GetCurrentThreadId());
        EXPECT_NE(g_wi_tid, 0);
    }
    /* several queued items all run exactly once */
    {
        LONG before = g_wi_hits; int k, spins = 0;
        for (k = 0; k < 20; k++) EXPECT_EQ(UN(RtlQueueWorkItem)((PVOID)wi_cb, (PVOID)(ULONG_PTR)k, 0), 0);
        while (g_wi_hits < before + 20 && spins++ < 1000) Sleep(10);
        EXPECT_EQ(g_wi_hits, before + 20);
    }
    CloseHandle(g_wi_ev);
}

static VOID NTAPI apc_cb(PVOID a, PVOID b, PVOID c) { (void)a; (void)b; (void)c; }
static DWORD WINAPI never_runs(LPVOID p) { (void)p; return 0; }
TEST(queue_apc_wow64_thread) {
    HANDLE th; DWORD tid; NTSTATUS s, s2;
    REQUIRE(UN(RtlQueueApcWow64Thread)); REQUIRE(UN(NtQueueApcThread));
    /* The routine is a 32-bit entry point for the WOW64 thunk, so it is never allowed to run here: the
     * target thread stays suspended and is terminated with the APC still queued. */
    th = CreateThread(NULL, 0, never_runs, NULL, CREATE_SUSPENDED, &tid);
    if (!th) { t_skip("CreateThread failed"); return; }
    s = UN(RtlQueueApcWow64Thread)(th, (PVOID)apc_cb, (PVOID)(ULONG_PTR)0x11, (PVOID)(ULONG_PTR)0x22, (PVOID)(ULONG_PTR)0x33);
    EXPECT_EQ(s, 0);
    TerminateThread(th, 0);
    WaitForSingleObject(th, 5000);
    /* a terminated thread no longer accepts apcs */
    s = UN(RtlQueueApcWow64Thread)(th, (PVOID)apc_cb, NULL, NULL, NULL);
    s2 = UN(NtQueueApcThread)(th, (PVOID)apc_cb, NULL, NULL, NULL);
    EXPECT_EQ(s, s2);
    CHECK(s < 0);
    CloseHandle(th);
    EXPECT_EQ(UN(RtlQueueApcWow64Thread)((HANDLE)(ULONG_PTR)0xDEAD0, (PVOID)apc_cb, NULL, NULL, NULL), S(0xC0000008));
    EXPECT_EQ(UN(RtlQueueApcWow64Thread)(NULL, (PVOID)apc_cb, NULL, NULL, NULL), S(0xC0000008));
}

/* ---------- RtlNormalizeProcessParams ---------- */
TEST(normalize_process_params) {
    static ULONGLONG raw[0x600 / 8]; UCHAR *p = (UCHAR *)raw; static const ULONG offs[] = { 0x40, 0x58, 0x68, 0x78, 0xb8, 0xc8, 0xd8, 0xe8, 0x418 };
    size_t i; PVOID r; PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock; PVOID live;
    REQUIRE(UN(RtlNormalizeProcessParams));
    EXPECT_EQ(UN(RtlNormalizeProcessParams)(NULL), NULL);
    memset(raw, 0, sizeof raw);
    for (i = 0; i < sizeof offs / sizeof offs[0]; i++) *(ULONG_PTR *)(p + offs[i]) = 0x500 + 0x10 * i;   /* offsets from the structure start */
    *(ULONG_PTR *)(p + 0x80) = 0x5F0;                            /* Environment is a real pointer, not an offset */
    *(ULONG_PTR *)(p + 0x48) = 0x77;                             /* not a normalized field */
    r = UN(RtlNormalizeProcessParams)(p);
    EXPECT_EQ(r, p);
    EXPECT_EQ(*(ULONG *)(p + 8) & 1, 1);                         /* RTL_USER_PROC_PARAMS_NORMALIZED */
    for (i = 0; i < sizeof offs / sizeof offs[0]; i++) EXPECT_EQ(*(ULONG_PTR *)(p + offs[i]), (ULONG_PTR)p + 0x500 + 0x10 * i);
    EXPECT_EQ(*(ULONG_PTR *)(p + 0x80), 0x5F0);
    EXPECT_EQ(*(ULONG_PTR *)(p + 0x48), 0x77);
    /* already normalized: a second call changes nothing */
    r = UN(RtlNormalizeProcessParams)(p);
    EXPECT_EQ(r, p);
    for (i = 0; i < sizeof offs / sizeof offs[0]; i++) EXPECT_EQ(*(ULONG_PTR *)(p + offs[i]), (ULONG_PTR)p + 0x500 + 0x10 * i);
    /* null fields stay null */
    memset(raw, 0, sizeof raw);
    UN(RtlNormalizeProcessParams)(p);
    for (i = 0; i < sizeof offs / sizeof offs[0]; i++) EXPECT_EQ(*(ULONG_PTR *)(p + offs[i]), 0);
    EXPECT_EQ(*(ULONG *)(p + 8) & 1, 1);
    /* the live parameter block is already normalized and is returned untouched */
    live = peb->ProcessParameters;
    {
        PVOID cl = *(PVOID *)((UCHAR *)live + 0x78);
        EXPECT_EQ(UN(RtlNormalizeProcessParams)(live), live);
        EXPECT_EQ(*(PVOID *)((UCHAR *)live + 0x78), cl);
        CHECK(cl != NULL);
    }
}

/* ---------- RtlOsDeploymentState ---------- */
TEST(os_deployment_state) {
    ULONG a, b;
    REQUIRE(UN(RtlOsDeploymentState));
    a = UN(RtlOsDeploymentState)(); b = UN(RtlOsDeploymentState)();
    CHECKF(a == 1 || a == 2, "unexpected deployment state %lu", a);   /* 1 = standard, 2 = compact */
    EXPECT_EQ(a, b);
}

/* ---------- RtlRetrieveNtUserPfn ---------- */
TEST(retrieve_nt_user_pfn) {
    PVOID a = NULL, b = NULL, c = NULL; NTSTATUS s; HMODULE u, nt = GetModuleHandleA("ntdll.dll"); ULONG_PTR lo, hi;
    IMAGE_NT_HEADERS64 *n;
    REQUIRE(UN(RtlRetrieveNtUserPfn));
    u = LoadLibraryA("user32.dll");
    if (!u) { t_skip("user32 not loadable"); return; }
    s = UN(RtlRetrieveNtUserPfn)(&a, &b, &c);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(a && b && c);
        n = (void *)((char *)nt + ((IMAGE_DOS_HEADER *)nt)->e_lfanew);
        lo = (ULONG_PTR)nt; hi = lo + n->OptionalHeader.SizeOfImage;
        CHECKF((ULONG_PTR)a >= lo && (ULONG_PTR)a < hi, "table 1 not in ntdll");
        CHECKF((ULONG_PTR)b >= lo && (ULONG_PTR)b < hi, "table 2 not in ntdll");
        CHECKF((ULONG_PTR)c >= lo && (ULONG_PTR)c < hi, "table 3 not in ntdll");
        { PVOID a2 = NULL, b2 = NULL, c2 = NULL; UN(RtlRetrieveNtUserPfn)(&a2, &b2, &c2); EXPECT_EQ(a2, a); EXPECT_EQ(b2, b); EXPECT_EQ(c2, c); }
    }
    FreeLibrary(u);
}
