/* Exception dispatch, unwinding, context restore, dynamic function tables and extended
 * (XSTATE) context layout. Anything that raises exceptions or transfers control runs in a
 * child process under a watchdog. */
#include "t.h"
#include <stdlib.h>

UDECL(PVOID, RtlAddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(ULONG, RtlRemoveVectoredExceptionHandler, (PVOID));
UDECL(PVOID, RtlAddVectoredContinueHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
UDECL(ULONG, RtlRemoveVectoredContinueHandler, (PVOID));
UDECL(VOID, RtlRaiseException, (PEXCEPTION_RECORD));
UDECL(VOID, RtlRaiseStatus, (NTSTATUS));
UDECL(NTSTATUS, NtRaiseException, (PEXCEPTION_RECORD, PCONTEXT, BOOLEAN));
UDECL(NTSTATUS, NtContinue, (PCONTEXT, BOOLEAN));
UDECL(VOID, RtlRestoreContext, (PCONTEXT, PEXCEPTION_RECORD));
UDECL(VOID, RtlCaptureContext, (PCONTEXT));
UDECL(PRUNTIME_FUNCTION, RtlLookupFunctionEntry, (DWORD64, PDWORD64, PVOID));
UDECL(PVOID, RtlVirtualUnwind, (ULONG, ULONG64, ULONG64, PRUNTIME_FUNCTION, PCONTEXT, PVOID *, PULONG64, PVOID));
UDECL(VOID, RtlUnwindEx, (PVOID, PVOID, PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID));
UDECL(BOOLEAN, RtlAddFunctionTable, (PRUNTIME_FUNCTION, DWORD, DWORD64));
UDECL(BOOLEAN, RtlDeleteFunctionTable, (PRUNTIME_FUNCTION));
UDECL(BOOLEAN, RtlInstallFunctionTableCallback, (DWORD64, DWORD64, DWORD, PVOID, PVOID, PCWSTR));
UDECL(PLIST_ENTRY, RtlGetFunctionTableListHead, (VOID));
UDECL(ULONG64, RtlGetEnabledExtendedFeatures, (ULONG64));
UDECL(NTSTATUS, RtlGetExtendedContextLength, (ULONG, PULONG));
UDECL(NTSTATUS, RtlInitializeExtendedContext, (PVOID, ULONG, PVOID *));
UDECL(PVOID, RtlLocateLegacyContext, (PVOID, PULONG));
UDECL(PVOID, RtlLocateExtendedFeature, (PVOID, ULONG, PULONG));
UDECL(ULONG64, RtlGetExtendedFeaturesMask, (PVOID));
UDECL(VOID, RtlSetExtendedFeaturesMask, (PVOID, ULONG64));

#define S(x) ((NTSTATUS)(x))
#define CODE_A 0xe0421001u
#define CODE_B 0xe0421002u

/* ------------------------------------------------------------------ */
/* child-process scenarios                                            */
/* ------------------------------------------------------------------ */
static volatile LONG g_seq[16];
static volatile LONG g_n;
static void rec(LONG v) { LONG i = InterlockedIncrement(&g_n) - 1; if (i < 16) g_seq[i] = v; }
/* Exit code describing an observed sequence: count in bits 16-23, first two entries below. */
static int seq_code(void) { return 0x1000000 | ((g_n & 0xff) << 16) | ((g_seq[0] & 0xff) << 8) | (g_seq[1] & 0xff); }
static int seq_is(const LONG *want, int n)
{
    if (g_n != n) return 0;
    for (int i = 0; i < n; i++) if (g_seq[i] != want[i]) return 0;
    return 1;
}
static EXCEPTION_RECORD make_rec(DWORD code)
{
    EXCEPTION_RECORD r;
    memset(&r, 0, sizeof r);
    r.ExceptionCode = code;
    return r;
}
static LONG CALLBACK veh_1(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_A) rec(1); return EXCEPTION_CONTINUE_SEARCH; }
static LONG CALLBACK veh_2(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_A) rec(2); return EXCEPTION_CONTINUE_EXECUTION; }
static LONG CALLBACK veh_3(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_A) rec(3); return EXCEPTION_CONTINUE_SEARCH; }
static LONG CALLBACK veh_4(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_A) rec(4); return EXCEPTION_CONTINUE_SEARCH; }

static int run_veh_order(void)
{
    PVOID h1, h2, h3, h4;
    EXCEPTION_RECORD r;
    static const LONG full[] = {4, 3, 1, 2}, partial[] = {4, 1, 2}, none[] = {1, 2};
    h1 = UN(RtlAddVectoredExceptionHandler)(0, veh_1);
    h2 = UN(RtlAddVectoredExceptionHandler)(0, veh_2);
    h3 = UN(RtlAddVectoredExceptionHandler)(1, veh_3);
    h4 = UN(RtlAddVectoredExceptionHandler)(1, veh_4);
    if (!h1 || !h2 || !h3 || !h4) return 10;
    if (h1 == h2 || h3 == h4) return 11;
    g_n = 0; r = make_rec(CODE_A);
    UN(RtlRaiseException)(&r);
    if (!seq_is(full, 4)) return seq_code();           /* handlers added "first" run ahead, newest first */
    if (!UN(RtlRemoveVectoredExceptionHandler)(h3)) return 13;
    if (UN(RtlRemoveVectoredExceptionHandler)(h3)) return 14;   /* already removed */
    g_n = 0; r = make_rec(CODE_A);
    UN(RtlRaiseException)(&r);
    if (!seq_is(partial, 3)) return seq_code();
    if (!UN(RtlRemoveVectoredExceptionHandler)(h4)) return 16;
    g_n = 0; r = make_rec(CODE_A);
    UN(RtlRaiseException)(&r);
    if (!seq_is(none, 2)) return seq_code();
    if (!UN(RtlRemoveVectoredExceptionHandler)(h1) || !UN(RtlRemoveVectoredExceptionHandler)(h2)) return 18;
    return 0;
}

static LONG CALLBACK vch_a(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_B) rec(11); return EXCEPTION_CONTINUE_EXECUTION; }
static LONG CALLBACK vch_b(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_B) rec(12); return EXCEPTION_CONTINUE_SEARCH; }
static LONG CALLBACK veh_b(PEXCEPTION_POINTERS p) { if (p->ExceptionRecord->ExceptionCode == CODE_B) rec(10); return EXCEPTION_CONTINUE_EXECUTION; }
static int run_continue_handler(void)
{
    PVOID veh, a, b;
    EXCEPTION_RECORD r;
    static const LONG both[] = {10, 12, 11}, only_veh[] = {10};
    veh = UN(RtlAddVectoredExceptionHandler)(0, veh_b);
    a = UN(RtlAddVectoredContinueHandler)(0, vch_a);
    b = UN(RtlAddVectoredContinueHandler)(1, vch_b);
    if (!veh || !a || !b) return 10;
    g_n = 0; r = make_rec(CODE_B);
    UN(RtlRaiseException)(&r);
    if (!seq_is(both, 3)) return seq_code();           /* exception handler first, then continue handlers newest-first */
    if (!UN(RtlRemoveVectoredContinueHandler)(a) || !UN(RtlRemoveVectoredContinueHandler)(b)) return 12;
    if (UN(RtlRemoveVectoredContinueHandler)(a)) return 13;
    g_n = 0; r = make_rec(CODE_B);
    UN(RtlRaiseException)(&r);
    if (!seq_is(only_veh, 1)) return seq_code();
    return UN(RtlRemoveVectoredExceptionHandler)(veh) ? 0 : 15;
}

static volatile LONG st_first_flags_ok, st_second_seen;
#define RAISED_STATUS 0xc0aabbccu
static LONG CALLBACK veh_status(PEXCEPTION_POINTERS p)
{
    EXCEPTION_RECORD *e = p->ExceptionRecord;
    if (e->ExceptionCode == RAISED_STATUS) {
        st_first_flags_ok = (e->ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0 && e->NumberParameters == 0;
        if (!st_first_flags_ok) ExitProcess(20);
        return EXCEPTION_CONTINUE_EXECUTION;    /* not permitted for a noncontinuable exception */
    }
    if (e->ExceptionCode == 0xc0000025u) {      /* STATUS_NONCONTINUABLE_EXCEPTION */
        st_second_seen = 1;
        ExitProcess(0);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static int run_raise_status(void)
{
    if (!UN(RtlAddVectoredExceptionHandler)(1, veh_status)) return 10;
    UN(RtlRaiseStatus)(S(RAISED_STATUS));
    return 21;   /* a noncontinuable raise must not return */
}

static volatile LONG g_pass;
static volatile LONG g_veh_hits;
static LONG CALLBACK veh_count(PEXCEPTION_POINTERS p)
{
    if (p->ExceptionRecord->ExceptionCode == CODE_A) { InterlockedIncrement(&g_veh_hits); return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
__attribute__((noinline)) static int nt_raise_case(void)
{
    CONTEXT c; EXCEPTION_RECORD r = make_rec(CODE_A);
    UN(RtlCaptureContext)(&c);
    if (g_pass++ == 0) {
        NTSTATUS s = UN(NtRaiseException)(&r, &c, TRUE);
        return 100 + (s != 0);       /* a continued exception resumes at the captured context instead of returning */
    }
    return g_veh_hits == 1 ? 0 : 102;
}
__attribute__((noinline)) static int nt_continue_case(int test_alert)
{
    CONTEXT c;
    UN(RtlCaptureContext)(&c);
    if (g_pass++ == 0) {
        NTSTATUS s = UN(NtContinue)(&c, (BOOLEAN)test_alert);
        return 100 + (s != 0);
    }
    return 0;
}
__attribute__((noinline)) static int restore_case(int with_record)
{
    CONTEXT c; EXCEPTION_RECORD r = make_rec(0);
    UN(RtlCaptureContext)(&c);
    if (g_pass++ == 0) {
        UN(RtlRestoreContext)(&c, with_record ? &r : NULL);
        return 100;
    }
    return 0;
}

__attribute__((noinline)) static ULONG_PTR uw_target(int mode)
{
    CONTEXT c, c2, c3, scratch;
    DWORD64 base = 0, base2 = 0, frame1 = 0, frame2 = 0;
    PVOID hd = NULL, handler;
    RUNTIME_FUNCTION *fe, *fe2;
    UN(RtlCaptureContext)(&c);
    fe = UN(RtlLookupFunctionEntry)(c.Rip, &base, NULL);
    if (!fe || base == 0) return 0xf1;
    c2 = c;
    handler = UN(RtlVirtualUnwind)(0 /* UNW_FLAG_NHANDLER */, base, c2.Rip, fe, &c2, &hd, &frame1, NULL);
    if (handler != NULL) return 0xf5;
    if (c2.Rip != (DWORD64)(ULONG_PTR)__builtin_return_address(0)) return 0xf2;
    if (c2.Rsp <= c.Rsp) return 0xf6;
    if (frame1 == 0 || frame1 > c2.Rsp) return 0xf7;
    fe2 = UN(RtlLookupFunctionEntry)(c2.Rip, &base2, NULL);
    if (!fe2 || base2 != base) return 0xf3;
    c3 = c2;
    UN(RtlVirtualUnwind)(0, base2, c3.Rip, fe2, &c3, &hd, &frame2, NULL);
    if (mode == 0) return 5;
    memset(&scratch, 0, sizeof scratch);
    UN(RtlUnwindEx)((PVOID)(ULONG_PTR)frame2, (PVOID)(ULONG_PTR)c2.Rip, NULL, (PVOID)(ULONG_PTR)77, &scratch, NULL);
    return 0xf4;   /* an unwind to the caller does not return here */
}
__attribute__((noinline)) static ULONG_PTR uw_caller(int mode)
{
    ULONG_PTR r = uw_target(mode);
    __asm__ volatile("" : "+r"(r));
    return r + 1000;
}

CHILD(rtl_exc)
{
    const char *m = argc > 1 ? argv[1] : "";
    int rc;
    if (!strcmp(m, "veh_order")) return run_veh_order();
    if (!strcmp(m, "continue_handler")) return run_continue_handler();
    if (!strcmp(m, "raise_status")) return run_raise_status();
    if (!strcmp(m, "nt_raise")) {
        if (!UN(RtlAddVectoredExceptionHandler)(1, veh_count)) return 10;
        return nt_raise_case();
    }
    if (!strcmp(m, "nt_continue")) return nt_continue_case(0);
    if (!strcmp(m, "nt_continue_test_alert")) return nt_continue_case(1);
    if (!strcmp(m, "restore")) return restore_case(0);
    if (!strcmp(m, "restore_record")) return restore_case(1);
    if (!strcmp(m, "unwind_probe")) { rc = (int)uw_caller(0); return rc == 1005 ? 0 : rc; }
    if (!strcmp(m, "unwind_ex")) { rc = (int)uw_caller(1); return rc == 1077 ? 0 : rc; }
    return 0xc0de0002;
}
static void child_case(const char *mode)
{
    DWORD rc;
    if (!UN(RtlCaptureContext) || !UN(RtlRaiseException) || !UN(RtlAddVectoredExceptionHandler)) { t_skip("exception exports missing"); return; }
    rc = t_run_child("rtl_exc", mode, 20000);
    EXPECT_EQ(rc, 0);
}
#define CHILD_TEST(name, mode, ...) TEST(rtl_exc_##name) { __VA_ARGS__; child_case(mode); }
CHILD_TEST(vector_handler_order_and_removal, "veh_order", REQUIRE(UN(RtlRemoveVectoredExceptionHandler)))
CHILD_TEST(continue_handler_order_and_removal, "continue_handler", REQUIRE(UN(RtlAddVectoredContinueHandler)); REQUIRE(UN(RtlRemoveVectoredContinueHandler)))
TEST(rtl_exc_raise_status_is_noncontinuable)
{
    DWORD rc;
    REQUIRE(UN(RtlRaiseStatus)); REQUIRE(UN(RtlAddVectoredExceptionHandler)); REQUIRE(UN(RtlCaptureContext));
    rc = t_run_child("rtl_exc", "raise_status", 20000);
    /* A vectored handler cannot resume a noncontinuable exception: the raise never returns (21), and the
       process ends with the raised status or with STATUS_NONCONTINUABLE_EXCEPTION (0 when a handler saw it). */
    CHECKF(rc == 0 || rc == 0xc0aabbccu || rc == 0xc0000025u, "child exit code 0x%08lx", (unsigned long)rc);
}
CHILD_TEST(nt_raise_exception_continues_at_context, "nt_raise", REQUIRE(UN(NtRaiseException)))
CHILD_TEST(nt_continue_resumes_captured_context, "nt_continue", REQUIRE(UN(NtContinue)))
CHILD_TEST(nt_continue_with_test_alert, "nt_continue_test_alert", REQUIRE(UN(NtContinue)))
CHILD_TEST(restore_context_resumes, "restore", REQUIRE(UN(RtlRestoreContext)))
CHILD_TEST(restore_context_with_record, "restore_record", REQUIRE(UN(RtlRestoreContext)))
CHILD_TEST(virtual_unwind_one_frame, "unwind_probe", REQUIRE(UN(RtlVirtualUnwind)); REQUIRE(UN(RtlLookupFunctionEntry)))
CHILD_TEST(unwind_ex_to_caller_frame, "unwind_ex", REQUIRE(UN(RtlUnwindEx)); REQUIRE(UN(RtlVirtualUnwind)); REQUIRE(UN(RtlLookupFunctionEntry)))

TEST(rtl_exc_lookup_function_entry_rejects_non_code)
{
    DWORD64 base = 0x1234; int local; void *heap = malloc(32);
    REQUIRE(UN(RtlLookupFunctionEntry));
    CHECK(UN(RtlLookupFunctionEntry)(0x10, &base, NULL) == NULL);
    base = 0x1234;
    CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)&local, &base, NULL) == NULL);
    CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)heap, &base, NULL) == NULL);
    t_note("image base reported for non-code addresses: %llx", (unsigned long long)base);
    free(heap);
}
TEST(rtl_exc_remove_unknown_handler)
{
    REQUIRE(UN(RtlRemoveVectoredExceptionHandler)); REQUIRE(UN(RtlRemoveVectoredContinueHandler));
    EXPECT_EQ(UN(RtlRemoveVectoredExceptionHandler)((PVOID)0x1234), 0);
    EXPECT_EQ(UN(RtlRemoveVectoredContinueHandler)((PVOID)0x1234), 0);
}

/* ------------------------------------------------------------------ */
/* dynamic function tables                                            */
/* ------------------------------------------------------------------ */
#define FT_CODE_LEN 0x10
#define FT_TABLE 0x100
#define FT_UNWIND 0x120
static BYTE *ft_region(void)
{
    BYTE *m = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) return NULL;
    memset(m, 0xcc, FT_CODE_LEN);
    m[0] = 0xc3;
    memset(m + FT_UNWIND, 0, 8);
    m[FT_UNWIND] = 0x01;    /* version 1, no flags, empty prologue */
    return m;
}
static void ft_fill(RUNTIME_FUNCTION *rf)
{
    rf->BeginAddress = 0; rf->EndAddress = FT_CODE_LEN; rf->UnwindData = FT_UNWIND;
}
TEST(rtl_exc_function_table_static_lookup)
{
    BYTE *m; RUNTIME_FUNCTION *rf; DWORD64 base = 0; PRUNTIME_FUNCTION found;
    REQUIRE(UN(RtlAddFunctionTable)); REQUIRE(UN(RtlDeleteFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    m = ft_region(); if (!m) { t_skip("VirtualAlloc failed"); return; }
    rf = (RUNTIME_FUNCTION *)(m + FT_TABLE); ft_fill(rf);
    EXPECT_EQ(UN(RtlAddFunctionTable)(rf, 1, (DWORD64)(ULONG_PTR)m), 1);
    found = UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + 4, &base, NULL);
    EXPECT_EQ(found, rf);
    EXPECT_EQ(base, (DWORD64)(ULONG_PTR)m);
    found = UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m, &base, NULL);
    EXPECT_EQ(found, rf);                                              /* begin is inclusive */
    CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + FT_CODE_LEN, &base, NULL) == NULL); /* end is exclusive */
    if (UN(RtlGetFunctionTableListHead)) {
        PLIST_ENTRY head = UN(RtlGetFunctionTableListHead)();
        CHECK(head != NULL && head->Flink != head);
    }
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(rf), 1);
    CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + 4, &base, NULL) == NULL);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(rf), 0);                      /* no longer registered */
    VirtualFree(m, 0, MEM_RELEASE);
}
static volatile LONG ft_calls; static DWORD64 ft_last_pc; static PVOID ft_last_ctx;
static RUNTIME_FUNCTION ft_entry;
static PRUNTIME_FUNCTION NTAPI ft_callback(DWORD64 pc, PVOID ctx)
{
    InterlockedIncrement(&ft_calls);
    ft_last_pc = pc; ft_last_ctx = ctx;
    return &ft_entry;
}
TEST(rtl_exc_function_table_callback)
{
    BYTE *m; DWORD64 base = 0, id; PRUNTIME_FUNCTION found; int ctx_marker;
    REQUIRE(UN(RtlInstallFunctionTableCallback)); REQUIRE(UN(RtlDeleteFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    m = ft_region(); if (!m) { t_skip("VirtualAlloc failed"); return; }
    ft_fill(&ft_entry); ft_calls = 0;
    id = (DWORD64)(ULONG_PTR)m | 3;
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(id & ~3ull, (DWORD64)(ULONG_PTR)m, 0x1000, (PVOID)ft_callback, &ctx_marker, NULL), 0); /* low bits must be set */
    EXPECT_EQ(UN(RtlInstallFunctionTableCallback)(id, (DWORD64)(ULONG_PTR)m, 0x1000, (PVOID)ft_callback, &ctx_marker, NULL), 1);
    found = UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + 4, &base, NULL);
    EXPECT_EQ(found, &ft_entry);
    CHECK(ft_calls >= 1);
    EXPECT_EQ(ft_last_pc, (DWORD64)(ULONG_PTR)m + 4);
    EXPECT_EQ(ft_last_ctx, &ctx_marker);
    EXPECT_EQ(base, (DWORD64)(ULONG_PTR)m);
    {
        LONG before = ft_calls;
        CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + 0x2000, &base, NULL) == NULL);   /* outside the registered range */
        EXPECT_EQ(ft_calls, before);
    }
    EXPECT_EQ(UN(RtlDeleteFunctionTable)((PRUNTIME_FUNCTION)(ULONG_PTR)id), 1);
    {
        LONG before = ft_calls;
        CHECK(UN(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)m + 4, &base, NULL) == NULL);
        EXPECT_EQ(ft_calls, before);
    }
    VirtualFree(m, 0, MEM_RELEASE);
}

/* ------------------------------------------------------------------ */
/* extended context                                                   */
/* ------------------------------------------------------------------ */
#define CTX_FULL 0x10000bu
#define CTX_XSTATE 0x100040u
typedef struct { LONG offset; DWORD length; } ctx_chunk;
typedef struct { ctx_chunk legacy, xstate; } ctx_ex_head;

TEST(rtl_exc_xstate_enabled_features_mask)
{
    REQUIRE(UN(RtlGetEnabledExtendedFeatures));
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(0), 0);
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(~0ull) & 3, 3);     /* x87 and SSE state are always enabled */
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(3), 3);
    {
        ULONG64 all = UN(RtlGetEnabledExtendedFeatures)(~0ull);
        EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(2), all & 2);   /* the argument masks the result */
        t_note("enabled extended features: %llx", (unsigned long long)all);
    }
}
TEST(rtl_exc_xstate_context_length)
{
    ULONG plain = 0, xs = 0; NTSTATUS s1, s2;
    REQUIRE(UN(RtlGetExtendedContextLength));
    s1 = UN(RtlGetExtendedContextLength)(CTX_FULL, &plain);
    EXPECT_EQ(s1, 0);
    CHECK(plain >= sizeof(CONTEXT) + sizeof(ctx_ex_head));
    s2 = UN(RtlGetExtendedContextLength)(CTX_FULL | CTX_XSTATE, &xs);
    if (s2 == 0) { CHECK(xs >= plain); if (UN(RtlGetEnabledExtendedFeatures) && (UN(RtlGetEnabledExtendedFeatures)(~0ull) & 4)) CHECK(xs > plain); }
    else t_note("XSTATE context length status=%08lx", (ULONG)s2);
    t_note("context lengths plain=%lu xstate=%lu", plain, xs);
}
TEST(rtl_exc_xstate_initialize_and_locate)
{
    ULONG len = 0, legacy_len = 0, flen = 0; BYTE *buf; PVOID ex = NULL, legacy, feat; NTSTATUS s;
    ULONG flags = CTX_FULL | CTX_XSTATE;
    REQUIRE(UN(RtlGetExtendedContextLength)); REQUIRE(UN(RtlInitializeExtendedContext)); REQUIRE(UN(RtlLocateLegacyContext));
    s = UN(RtlGetExtendedContextLength)(flags, &len);
    if (s != 0) { t_skip("XSTATE contexts not supported: %08lx", (ULONG)s); return; }
    buf = calloc(1, len + 64);
    if (!buf) return;
    s = UN(RtlInitializeExtendedContext)(buf, flags, &ex);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(ex != NULL);
        legacy = UN(RtlLocateLegacyContext)(ex, &legacy_len);
        CHECK(legacy != NULL);
        EXPECT_EQ(legacy_len, sizeof(CONTEXT));
        EXPECT_EQ((ULONG_PTR)legacy & 15, 0);
        CHECK((BYTE *)legacy >= buf && (BYTE *)legacy + legacy_len <= buf + len + 64);
        if (legacy) t_note("legacy ContextFlags=%08lx (requested %08lx)", ((CONTEXT *)legacy)->ContextFlags, flags);
        if (UN(RtlLocateExtendedFeature) && UN(RtlGetEnabledExtendedFeatures) && (UN(RtlGetEnabledExtendedFeatures)(~0ull) & 4)) {
            feat = UN(RtlLocateExtendedFeature)(ex, 2 /* XSTATE_AVX */, &flen);
            if (feat) {
                CHECK((BYTE *)feat >= buf && (BYTE *)feat + flen <= buf + len + 64);
                t_note("AVX state length %lu", flen);
            } else t_note("AVX state not located");
        }
        if (UN(RtlGetExtendedFeaturesMask) && UN(RtlSetExtendedFeaturesMask)) {
            ULONG64 got3, got1;
            UN(RtlSetExtendedFeaturesMask)(ex, 3);
            got3 = UN(RtlGetExtendedFeaturesMask)(ex);
            UN(RtlSetExtendedFeaturesMask)(ex, 1);
            got1 = UN(RtlGetExtendedFeaturesMask)(ex);
            CHECK(got3 != got1 || got3 == 0);
            if (got3 == 3 && got1 == 1) CHECK(1); else t_note("feature mask round trip: set 3 -> %llx, set 1 -> %llx", (unsigned long long)got3, (unsigned long long)got1);
        }
    }
    free(buf);
}
TEST(rtl_exc_xstate_initialize_without_xstate)
{
    ULONG len = 0, legacy_len = 0; BYTE *buf; PVOID ex = NULL; NTSTATUS s;
    REQUIRE(UN(RtlGetExtendedContextLength)); REQUIRE(UN(RtlInitializeExtendedContext)); REQUIRE(UN(RtlLocateLegacyContext));
    EXPECT_EQ(UN(RtlGetExtendedContextLength)(CTX_FULL, &len), 0);
    buf = calloc(1, len + 64);
    if (!buf) return;
    s = UN(RtlInitializeExtendedContext)(buf, CTX_FULL, &ex);
    EXPECT_EQ(s, 0);
    if (s == 0 && ex) {
        PVOID legacy = UN(RtlLocateLegacyContext)(ex, &legacy_len);
        CHECK(legacy != NULL);
        EXPECT_EQ(legacy_len, sizeof(CONTEXT));
        if (UN(RtlLocateExtendedFeature)) {
            ULONG flen = 0;
            PVOID f = UN(RtlLocateExtendedFeature)(ex, 2, &flen);
            t_note("AVX location without XSTATE flag: %p", f);
        }
    }
    free(buf);
}
