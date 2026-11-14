/* NtContinue / NtContinueEx: resume execution from a captured CONTEXT (setjmp-like round trip), alert testing
 * on continue, and argument errors. */
#include "t.h"

UDECL(NTSTATUS, NtContinue, (PCONTEXT, BOOLEAN));
UDECL(NTSTATUS, NtContinueEx, (PCONTEXT, PVOID));
UDECL(VOID, RtlCaptureContext, (PCONTEXT));
UDECL(NTSTATUS, NtAlertThread, (HANDLE));
UDECL(NTSTATUS, NtDelayExecution, (BOOLEAN, PLARGE_INTEGER));

#define S(x) ((NTSTATUS)(x))

static volatile LONG g_phase, g_apc, g_stage;
static void CALLBACK apc_fn(ULONG_PTR p) { InterlockedIncrement(&g_apc); }

TEST(ctx_aliases)
{
    CHECK(t_proc("NtContinue") != NULL && t_proc("NtContinue") == t_proc("ZwContinue"));
    CHECK(t_proc("NtContinueEx") != NULL && t_proc("NtContinueEx") == t_proc("ZwContinueEx"));
}

/* Capture, then jump back to the capture point once. */
static __attribute__((noinline)) NTSTATUS roundtrip(int ex, BOOLEAN test_alert, int queue_apc)
{
    static CONTEXT ctx;
    NTSTATUS s = 0;
    g_phase = 0; g_apc = 0;
    UN(RtlCaptureContext)(&ctx);
    if (g_phase == 0) {
        g_phase = 1;
        if (queue_apc) QueueUserAPC(apc_fn, GetCurrentThread(), 0);
        if (ex) s = UN(NtContinueEx)(&ctx, (PVOID)(ULONG_PTR)test_alert);
        else    s = UN(NtContinue)(&ctx, test_alert);
        g_phase = -1;          /* only reached when the service failed */
        return s;
    }
    return 0;                  /* resumed at the capture point */
}

TEST(continue_roundtrip)
{
    NTSTATUS s;
    REQUIRE(UN(NtContinue)); REQUIRE(UN(RtlCaptureContext));
    s = roundtrip(0, FALSE, 0);
    EXPECT_EQ(g_phase, 1); EXPECT_EQ(s, 0);
}

TEST(continue_ex_roundtrip)
{
    NTSTATUS s;
    REQUIRE(UN(NtContinueEx)); REQUIRE(UN(RtlCaptureContext));
    s = roundtrip(1, FALSE, 0);
    EXPECT_EQ(g_phase, 1); EXPECT_EQ(s, 0);
}

TEST(continue_test_alert)
{
    NTSTATUS s; LARGE_INTEGER d;
    REQUIRE(UN(NtContinue)); REQUIRE(UN(RtlCaptureContext)); REQUIRE(UN(NtDelayExecution));
    /* TestAlert FALSE: a queued user APC stays queued until an alertable wait */
    s = roundtrip(0, FALSE, 1);
    EXPECT_EQ(g_phase, 1); EXPECT_EQ(s, 0); EXPECT_EQ(g_apc, 0);
    d.QuadPart = -10000;
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), S(0xC0));      /* STATUS_USER_APC */
    EXPECT_EQ(g_apc, 1);
    /* TestAlert TRUE: queued user APCs are delivered as part of the continue */
    s = roundtrip(0, TRUE, 1);
    EXPECT_EQ(g_phase, 1); EXPECT_EQ(s, 0);
    EXPECT_EQ(g_apc, 1);
    /* nothing left over */
    d.QuadPart = -10000;
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), 0);
}

TEST(continue_errors)
{
    NTSTATUS s;
    REQUIRE(UN(NtContinue)); REQUIRE(UN(NtContinueEx));
    s = UN(NtContinue)(NULL, FALSE);
    t_note("NtContinue(NULL) = 0x%08lx", s);
    s = UN(NtContinueEx)(NULL, NULL);
    t_note("NtContinueEx(NULL) = 0x%08lx", s);
    s = UN(NtContinue)((PCONTEXT)(ULONG_PTR)0x1000, FALSE);
    t_note("NtContinue(unmapped) = 0x%08lx", s);
    { static BYTE buf[sizeof(CONTEXT) + 16]; PCONTEXT c = (PCONTEXT)(((ULONG_PTR)buf + 15) & ~15) ; c = (PCONTEXT)((BYTE *)c + 4);
      s = UN(NtContinue)(c, FALSE); t_note("NtContinue(misaligned) = 0x%08lx", s); }
}
