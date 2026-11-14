/* NtSetInformationProcess on a suspended child process (so changes never touch the test process),
 * plus NtSetInformationVirtualMemory on private memory of the calling process.
 *
 * PROCESSINFOCLASS numbers: 12 DefaultHardErrorMode, 17 EnableAlignmentFaultFixup, 18 PriorityClass,
 * 21 AffinityMask, 22 PriorityBoost, 31 DebugFlags, 33 IoPriority, 39 PagePriority.
 */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationProcess, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationVirtualMemory, (HANDLE, ULONG, ULONG_PTR, PVOID, PVOID, ULONG));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define NT_PROCESS      ((HANDLE)(LONG_PTR)-1)

CHILD(idle_child) { Sleep(100); return 0; }

typedef struct { HANDLE ph; HANDLE th; } child;

static BOOL child_start(child *c)
{
    PROCESS_INFORMATION pi;
    memset(c, 0, sizeof *c);
    c->ph = t_spawn_child("idle_child", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!c->ph) return FALSE;
    c->th = pi.hThread;
    return TRUE;
}

static void child_end(child *c)
{
    if (c->ph) { TerminateProcess(c->ph, 0); WaitForSingleObject(c->ph, 5000); CloseHandle(c->ph); }
    if (c->th) CloseHandle(c->th);
    memset(c, 0, sizeof *c);
}

#define NEED() do { REQUIRE(UN(NtSetInformationProcess)); REQUIRE(UN(NtQueryInformationProcess)); } while (0)

TEST(set_process_alias_pairs)
{
    EXPECT_EQ(t_proc("NtSetInformationProcess"), t_proc("ZwSetInformationProcess"));
    EXPECT_EQ(t_proc("NtSetInformationVirtualMemory"), t_proc("ZwSetInformationVirtualMemory"));
}

TEST(set_process_priority_class)
{
    child c; struct { BOOLEAN fg; UCHAR cls; } pc; NEED();
    CHECK(child_start(&c)); if (!c.ph) return;
    pc.fg = 0; pc.cls = 5;                    /* PROCESS_PRIORITY_CLASS_BELOW_NORMAL */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(c.ph), BELOW_NORMAL_PRIORITY_CLASS);
    pc.cls = 1;                               /* IDLE */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(c.ph), IDLE_PRIORITY_CLASS);
    pc.cls = 3;                               /* HIGH */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(c.ph), HIGH_PRIORITY_CLASS);
    pc.cls = 2;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(c.ph), NORMAL_PRIORITY_CLASS);
    pc.cls = 0;                               /* PROCESS_PRIORITY_CLASS_UNKNOWN: accepted, class unchanged */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(c.ph), NORMAL_PRIORITY_CLASS);
    pc.cls = 7;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, sizeof pc), ST_BAD_PARAM);
    EXPECT_EQ(GetPriorityClass(c.ph), NORMAL_PRIORITY_CLASS);
    pc.cls = 2;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, 1), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 18, &pc, 4), ST_BAD_LENGTH);
    child_end(&c);
}

TEST(set_process_priority_boost)
{
    child c; ULONG v; BOOL dis = FALSE; NEED();
    CHECK(child_start(&c)); if (!c.ph) return;
    v = 1;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 22, &v, sizeof v), 0);
    CHECK(GetProcessPriorityBoost(c.ph, &dis)); EXPECT_EQ(dis, TRUE);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 22, &v, sizeof v), 0);
    CHECK(GetProcessPriorityBoost(c.ph, &dis)); EXPECT_EQ(dis, FALSE);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 22, &v, 8), ST_BAD_LENGTH);
    child_end(&c);
}

TEST(set_process_default_hard_error_mode)
{
    child c; ULONG v, got = 0xAAAAAAAA, rl = 0; NEED();
    CHECK(child_start(&c)); if (!c.ph) return;
    v = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;       /* 0x1 | 0x2 */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 12, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 12, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, v);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 12, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 12, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 0);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 12, &v, 2), ST_BAD_LENGTH);
    child_end(&c);
}

TEST(set_process_affinity_mask)
{
    child c; DWORD_PTR pam = 0, sam = 0, got = 0, sys = 0; ULONG_PTR m; NEED();
    CHECK(GetProcessAffinityMask(GetCurrentProcess(), &pam, &sam));
    CHECK(child_start(&c)); if (!c.ph) return;
    m = pam & (~pam + 1);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 21, &m, sizeof m), 0);
    CHECK(GetProcessAffinityMask(c.ph, &got, &sys));
    EXPECT_EQ(got, m);
    m = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 21, &m, sizeof m), ST_BAD_PARAM);
    m = pam;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 21, &m, 4), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 21, &m, sizeof m), 0);
    CHECK(GetProcessAffinityMask(c.ph, &got, &sys));
    EXPECT_EQ(got, pam);
    child_end(&c);
}

TEST(set_process_io_and_page_priority)
{
    child c; ULONG v, got = 0xAAAAAAAA, rl = 0; NTSTATUS st; NEED();
    CHECK(child_start(&c)); if (!c.ph) return;
    v = 1;                                      /* IoPriorityLow */
    st = UN(NtSetInformationProcess)(c.ph, 33, &v, sizeof v);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 33, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 1);
    v = 2;                                      /* IoPriorityNormal */
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 33, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 33, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 2);
    v = 99;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 33, &v, sizeof v), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 33, &v, 2), ST_BAD_LENGTH);
    v = 3;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 39, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 39, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 3);
    v = 99;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 39, &v, sizeof v), ST_BAD_PARAM);
    child_end(&c);
}

TEST(set_process_debug_flags)
{
    child c; ULONG v, got = 0xAAAAAAAA, rl = 0; NEED();
    CHECK(child_start(&c)); if (!c.ph) return;
    /* ProcessDebugFlags reports the inverse of NoDebugInherit: 1 means children inherit the debugger */
    v = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 31, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 31, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 0);
    v = 1;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 31, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(c.ph, 31, &got, sizeof got, &rl), 0);
    EXPECT_EQ(got, 1);
    v = 2;
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 31, &v, sizeof v), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetInformationProcess)(c.ph, 31, &v, 1), ST_BAD_LENGTH);
    child_end(&c);
}

TEST(set_process_errors)
{
    child c; HANDLE ro = NULL; ULONG v = 0; NEED();
    EXPECT_EQ(UN(NtSetInformationProcess)(NT_PROCESS, 0x7fffffff, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationProcess)(NULL, 22, &v, sizeof v), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationProcess)((HANDLE)(ULONG_PTR)0xdeadbee4, 22, &v, sizeof v), ST_INV_HANDLE);
    CHECK(child_start(&c)); if (!c.ph) return;
    CHECK(DuplicateHandle(GetCurrentProcess(), c.ph, GetCurrentProcess(), &ro, PROCESS_QUERY_INFORMATION, FALSE, 0));
    if (ro) {
        EXPECT_EQ(UN(NtSetInformationProcess)(ro, 22, &v, sizeof v), ST_DENIED);
        CloseHandle(ro);
    }
    child_end(&c);
}

/* VmPrefetchInformation = 0: argument is a ULONG flags word, ranges are WIN32_MEMORY_RANGE_ENTRY */
TEST(set_virtual_memory_prefetch)
{
    PVOID p; struct { PVOID va; SIZE_T len; } r; ULONG flags = 0; NTSTATUS st;
    REQUIRE(UN(NtSetInformationVirtualMemory));
    p = VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(p != NULL); if (!p) return;
    memset(p, 1, 0x4000);
    r.va = p; r.len = 0x4000;
    st = UN(NtSetInformationVirtualMemory)(NT_PROCESS, 0, 1, &r, &flags, sizeof flags);
    EXPECT_EQ(st, 0);
    /* bad class, zero entries, wrong data length, NULL data */
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(NT_PROCESS, 0x7f, 1, &r, &flags, sizeof flags), S(0xC00000F0));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(NT_PROCESS, 0, 0, &r, &flags, sizeof flags), S(0xC00000F1));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(NT_PROCESS, 0, 1, &r, &flags, 2), S(0xC00000F4));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(NT_PROCESS, 0, 1, &r, NULL, sizeof flags), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)((HANDLE)(ULONG_PTR)0xdeadbee4, 0, 1, &r, &flags, sizeof flags), ST_INV_HANDLE);
    VirtualFree(p, 0, MEM_RELEASE);
}
