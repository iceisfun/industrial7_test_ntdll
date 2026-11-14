/* NtSetInformationThread, NtSetContextThread, NtSetThreadExecutionState, NtSetLdtEntries.
 *
 * Every helper thread blocks on an event (with a timeout) and is released, waited for and closed
 * by the test that created it. Information classes used (THREADINFOCLASS numbering):
 *   2 ThreadPriority, 3 ThreadBasePriority, 4 ThreadAffinityMask, 5 ThreadImpersonationToken,
 *   9 ThreadQuerySetWin32StartAddress, 10 ThreadZeroTlsCell, 13 ThreadIdealProcessor,
 *   14 ThreadPriorityBoost, 17 ThreadHideFromDebugger, 38 ThreadNameInformation.
 */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtGetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtSetThreadExecutionState, (ULONG, PULONG));
UDECL(NTSTATUS, NtSetLdtEntries, (ULONG, ULONG, ULONG, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtSuspendThread, (HANDLE, PULONG));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_NOT_IMPL     S(0xC0000002)
#define NT_THREAD       ((HANDLE)(LONG_PTR)-2)

typedef struct { HANDLE ev; HANDLE th; DWORD tid; } helper;

static DWORD WINAPI helper_main(LPVOID p)
{
    WaitForSingleObject(((helper *)p)->ev, 20000);
    return 7;
}

static BOOL helper_start(helper *h, DWORD flags)
{
    memset(h, 0, sizeof *h);
    h->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!h->ev) return FALSE;
    h->th = CreateThread(NULL, 0, helper_main, h, flags, &h->tid);
    return h->th != NULL;
}

static void helper_end(helper *h)
{
    if (h->th) {
        SetEvent(h->ev);
        ResumeThread(h->th);
        WaitForSingleObject(h->th, 5000);
        CloseHandle(h->th);
    }
    if (h->ev) CloseHandle(h->ev);
    memset(h, 0, sizeof *h);
}

#define NEED_SET() REQUIRE(UN(NtSetInformationThread))

TEST(set_thread_alias_pairs)
{
    CHECK(t_proc("NtSetInformationThread") != NULL);
    EXPECT_EQ(t_proc("NtSetInformationThread"), t_proc("ZwSetInformationThread"));
    EXPECT_EQ(t_proc("NtSetContextThread"), t_proc("ZwSetContextThread"));
    EXPECT_EQ(t_proc("NtSetThreadExecutionState"), t_proc("ZwSetThreadExecutionState"));
    EXPECT_EQ(t_proc("NtSetLdtEntries"), t_proc("ZwSetLdtEntries"));
}

TEST(set_thread_base_priority)
{
    helper h; LONG v; NEED_SET();
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    v = 1;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 3, &v, sizeof v), 0);
    EXPECT_EQ(GetThreadPriority(h.th), 1);
    v = -1;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 3, &v, sizeof v), 0);
    EXPECT_EQ(GetThreadPriority(h.th), -1);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 3, &v, sizeof v), 0);
    EXPECT_EQ(GetThreadPriority(h.th), 0);
    /* length must be exactly sizeof(LONG) */
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 3, &v, 0), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 3, &v, 8), ST_BAD_LENGTH);
    helper_end(&h);
}

TEST(set_thread_priority_boost)
{
    helper h; ULONG v; BOOL dis = FALSE; NEED_SET();
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    v = 1;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 14, &v, sizeof v), 0);
    CHECK(GetThreadPriorityBoost(h.th, &dis)); EXPECT_EQ(dis, TRUE);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 14, &v, sizeof v), 0);
    CHECK(GetThreadPriorityBoost(h.th, &dis)); EXPECT_EQ(dis, FALSE);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 14, &v, 2), ST_BAD_LENGTH);
    helper_end(&h);
}

TEST(set_thread_affinity_mask)
{
    helper h; DWORD_PTR pam = 0, sam = 0, prev; ULONG_PTR m; NEED_SET();
    CHECK(GetProcessAffinityMask(GetCurrentProcess(), &pam, &sam));
    CHECK(helper_start(&h, 0));
    if (!h.th || !pam) { helper_end(&h); return; }
    m = pam & (~pam + 1);               /* lowest allowed CPU */
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 4, &m, sizeof m), 0);
    prev = SetThreadAffinityMask(h.th, pam);   /* returns the mask just set */
    EXPECT_EQ(prev, m);
    /* an empty mask and a length other than sizeof(ULONG_PTR) are rejected */
    m = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 4, &m, sizeof m), ST_BAD_PARAM);
    m = pam;
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 4, &m, 4), ST_BAD_LENGTH);
    /* a mask with a CPU outside the process affinity is rejected */
    m = ~pam;
    if (m) EXPECT_EQ(UN(NtSetInformationThread)(h.th, 4, &m, sizeof m), ST_BAD_PARAM);
    helper_end(&h);
}

TEST(set_thread_ideal_processor)
{
    helper h; ULONG v = 0; NEED_SET();
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    /* the (non-negative) success status is the previous ideal processor */
    CHECK(UN(NtSetInformationThread)(h.th, 13, &v, sizeof v) >= 0);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 13, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 13, &v, 2), ST_BAD_LENGTH);
    helper_end(&h);
}

TEST(set_thread_hide_from_debugger)
{
    helper h; ULONG hidden = 0xAA; ULONG rl = 0; NTSTATUS st; NEED_SET(); REQUIRE(UN(NtQueryInformationThread));
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    hidden = 0xAA; st = UN(NtQueryInformationThread)(h.th, 17, &hidden, 1, &rl);
    EXPECT_EQ(st, 0); EXPECT_EQ(hidden & 0xff, 0);
    /* the information buffer has length 0; any other length is a mismatch */
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 17, &hidden, 1), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 17, NULL, 0), 0);
    hidden = 0xAA; st = UN(NtQueryInformationThread)(h.th, 17, &hidden, 1, &rl);
    EXPECT_EQ(st, 0); EXPECT_EQ(hidden & 0xff, 1);
    helper_end(&h);
}

TEST(set_thread_name_roundtrip)
{
    helper h; NTSTATUS st; static const WCHAR nm[] = L"setinfo-thread-name";
    struct { UNICODE_STRING us; WCHAR buf[40]; } in, out; ULONG rl = 0;
    NEED_SET(); REQUIRE(UN(NtQueryInformationThread));
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    memset(&in, 0, sizeof in);
    memcpy(in.buf, nm, sizeof nm);
    in.us.Length = sizeof nm - sizeof(WCHAR);
    in.us.MaximumLength = sizeof nm;
    in.us.Buffer = in.buf;
    st = UN(NtSetInformationThread)(h.th, 38, &in.us, sizeof(UNICODE_STRING));
    if (st == ST_BAD_CLASS) { t_skip("ThreadNameInformation not available"); helper_end(&h); return; }
    EXPECT_EQ(st, 0);
    memset(&out, 0, sizeof out);
    st = UN(NtQueryInformationThread)(h.th, 38, &out, sizeof out, &rl);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(out.us.Length, sizeof nm - sizeof(WCHAR));
    if (st == 0 && out.us.Length == sizeof nm - sizeof(WCHAR))
        CHECK(memcmp(out.us.Buffer, nm, out.us.Length) == 0);
    /* a UNICODE_STRING-sized buffer is required */
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 38, &in.us, 4), ST_BAD_LENGTH);
    helper_end(&h);
}

TEST(set_thread_win32_start_address)
{
    helper h; PVOID addr = (PVOID)(ULONG_PTR)0x123450, got = NULL; ULONG rl = 0; NEED_SET(); REQUIRE(UN(NtQueryInformationThread));
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    /* CreateThread already recorded the start address: it can be set only once */
    EXPECT_EQ(UN(NtQueryInformationThread)(h.th, 9, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, (PVOID)helper_main);
    EXPECT_EQ(rl, sizeof got);
    EXPECT_EQ(UN(NtSetInformationThread)(h.th, 9, &addr, sizeof addr), ST_BAD_PARAM);
    got = NULL;
    EXPECT_EQ(UN(NtQueryInformationThread)(h.th, 9, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, (PVOID)helper_main);
    helper_end(&h);
}

TEST(set_thread_zero_tls_cell)
{
    DWORD idx = TlsAlloc(); ULONG v; NEED_SET();
    CHECK(idx != TLS_OUT_OF_INDEXES);
    if (idx == TLS_OUT_OF_INDEXES) return;
    CHECK(TlsSetValue(idx, (LPVOID)0x1234));
    EXPECT_EQ(TlsGetValue(idx), (LPVOID)0x1234);
    v = idx;
    EXPECT_EQ(UN(NtSetInformationThread)(NT_THREAD, 10, &v, sizeof v), 0);
    EXPECT_EQ(TlsGetValue(idx), NULL);
    EXPECT_EQ(UN(NtSetInformationThread)(NT_THREAD, 10, &v, 2), ST_BAD_LENGTH);
    TlsFree(idx);
}

TEST(set_thread_impersonation_clear)
{
    HANDLE tok = NULL; NEED_SET();
    /* a NULL token handle clears (no-op) impersonation of the calling thread */
    EXPECT_EQ(UN(NtSetInformationThread)(NT_THREAD, 5, &tok, sizeof tok), 0);
    EXPECT_EQ(UN(NtSetInformationThread)(NT_THREAD, 5, &tok, 4), ST_BAD_LENGTH);
}

TEST(set_thread_errors)
{
    helper h; HANDLE ro = NULL; ULONG v = 0; LONG b = 0; NEED_SET();
    EXPECT_EQ(UN(NtSetInformationThread)(NT_THREAD, 0x7fffffff, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationThread)((HANDLE)(ULONG_PTR)0xdeadbee4, 3, &b, sizeof b), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationThread)(NULL, 3, &b, sizeof b), ST_INV_HANDLE);
    CHECK(helper_start(&h, 0));
    if (!h.th) return;
    /* a handle without THREAD_SET_INFORMATION cannot change the thread */
    CHECK(DuplicateHandle(GetCurrentProcess(), h.th, GetCurrentProcess(), &ro, THREAD_QUERY_INFORMATION, FALSE, 0));
    if (ro) {
        EXPECT_EQ(UN(NtSetInformationThread)(ro, 3, &b, sizeof b), ST_DENIED);
        CloseHandle(ro);
    }
    helper_end(&h);
}

#if defined(__x86_64__)
TEST(set_context_roundtrip)
{
    helper h; CONTEXT in, out; HANDLE ro = NULL; NTSTATUS st; ULONG sc;
    REQUIRE(UN(NtSetContextThread)); REQUIRE(UN(NtGetContextThread));
    CHECK(helper_start(&h, CREATE_SUSPENDED));
    if (!h.th) return;
    memset(&in, 0, sizeof in);
    in.ContextFlags = CONTEXT_INTEGER;
    st = UN(NtGetContextThread)(h.th, &in);
    EXPECT_EQ(st, 0);
    in.Rbx = 0x1111222233334444ULL; in.R12 = 0x5555666677778888ULL; in.R15 = 0x0123456789abcdefULL;
    st = UN(NtSetContextThread)(h.th, &in);
    EXPECT_EQ(st, 0);
    memset(&out, 0, sizeof out);
    out.ContextFlags = CONTEXT_INTEGER;
    EXPECT_EQ(UN(NtGetContextThread)(h.th, &out), 0);
    EXPECT_EQ(out.Rbx, in.Rbx); EXPECT_EQ(out.R12, in.R12); EXPECT_EQ(out.R15, in.R15);
    /* Win32 view agrees */
    memset(&out, 0, sizeof out);
    out.ContextFlags = CONTEXT_INTEGER;
    CHECK(GetThreadContext(h.th, &out));
    EXPECT_EQ(out.R12, in.R12);
    /* an invalid handle and a handle lacking THREAD_SET_CONTEXT */
    EXPECT_EQ(UN(NtSetContextThread)((HANDLE)(ULONG_PTR)0xdeadbee4, &in), ST_INV_HANDLE);
    CHECK(DuplicateHandle(GetCurrentProcess(), h.th, GetCurrentProcess(), &ro, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, 0));
    if (ro) {
        EXPECT_EQ(UN(NtSetContextThread)(ro, &in), ST_DENIED);
        CloseHandle(ro);
    }
    (void)sc;
    helper_end(&h);
}
#endif

TEST(set_thread_execution_state)
{
    ULONG prev = 0xAAAAAAAA, prev2 = 0xAAAAAAAA; NTSTATUS st; REQUIRE(UN(NtSetThreadExecutionState));
    /* ES_CONTINUOUS | ES_SYSTEM_REQUIRED, then ES_CONTINUOUS alone clears it */
    st = UN(NtSetThreadExecutionState)(0x80000001, &prev);
    EXPECT_EQ(st, 0);
    st = UN(NtSetThreadExecutionState)(0x80000000, &prev2);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(prev2 & 0x80000001, 0x80000001);
    st = UN(NtSetThreadExecutionState)(0x80000000, &prev);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(prev & 1, 0);
    /* reserved flag bits are invalid */
    prev = 0xAAAAAAAA;
    EXPECT_EQ(UN(NtSetThreadExecutionState)(0x100, &prev), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetThreadExecutionState)(0x80000100, &prev), ST_BAD_PARAM);
    /* ES_USER_PRESENT (0x4) is a legacy flag and not accepted by the native service */
    EXPECT_EQ(UN(NtSetThreadExecutionState)(0x4, &prev), ST_BAD_PARAM);
    /* ES_AWAYMODE_REQUIRED (0x40) is only valid together with ES_CONTINUOUS */
    EXPECT_EQ(UN(NtSetThreadExecutionState)(0x40, &prev), ST_BAD_PARAM);
}

TEST(set_ldt_entries_x64)
{
    REQUIRE(UN(NtSetLdtEntries));
#if defined(__x86_64__)
    EXPECT_EQ(UN(NtSetLdtEntries)(0, 0, 0, 0, 0, 0), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtSetLdtEntries)(0x7, 0x1234, 0x5678, 0, 0, 0), ST_NOT_IMPL);
#else
    t_skip("32-bit only service");
#endif
}
