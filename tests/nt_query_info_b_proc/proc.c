/* Process, thread, token, job, virtual-memory and system information queries:
 * NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken,
 * NtQueryInformationJobObject, NtQueryVirtualMemory, NtQuerySystemInformation(Ex),
 * NtQuerySecurityAttributesToken. Expected values: see EVIDENCE.md. x64 layouts. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationJobObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtAssignProcessToJobObject, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtQueryVirtualMemory, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtQuerySystemInformation, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemInformationEx, (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySecurityAttributesToken, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtAllocateVirtualMemory, (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_BUF_SMALL    S(0xC0000023)
#define ST_BUF_OVERFLOW S(0x80000005)
#define ST_INV_PARAM    S(0xC000000D)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define CUR_PROC ((HANDLE)(LONG_PTR)-1)
#define CUR_THREAD ((HANDLE)(LONG_PTR)-2)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}
TEST(alias_pairs)
{
    static const char *n[] = { "NtQueryInformationProcess", "NtQueryInformationThread", "NtQueryInformationToken",
        "NtQueryInformationJobObject", "NtQueryVirtualMemory", "NtQuerySystemInformation", "NtQuerySystemInformationEx",
        "NtQuerySecurityAttributesToken" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

/* ---- process ---- */
typedef struct { NTSTATUS exit; PVOID peb; ULONG_PTR affinity; LONG prio; ULONG_PTR pid, ppid; } PBI;

TEST(process_basic_information)
{
    PBI b; ULONG ret; NTSTATUS st; HANDLE d = NULL;
    REQUIRE(UN(NtQueryInformationProcess));
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, 48); EXPECT_EQ(sizeof b, 48);
    EXPECT_EQ(b.exit, STILL_ACTIVE);
    EXPECT_EQ(b.pid, GetCurrentProcessId());
    CHECK(b.peb == (PVOID)NtCurrentTeb()->ProcessEnvironmentBlock);
    CHECK(b.affinity != 0); CHECK(b.ppid != 0);
    CHECK(b.prio >= 1 && b.prio <= 15);
    /* a real handle behaves the same */
    EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, CUR_PROC, CUR_PROC, &d, PROCESS_QUERY_INFORMATION, 0, 0), 0);
    if (d) {
        PBI c; memset(&c, 0, sizeof c);
        EXPECT_EQ(UN(NtQueryInformationProcess)(d, 0, &c, sizeof c, NULL), 0);
        EXPECT_EQ(c.pid, b.pid); CHECK(c.peb == b.peb);
        UN(NtClose)(d); d = NULL;
        /* synchronize-only handle: no query rights */
        EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, CUR_PROC, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQueryInformationProcess)(d, 0, &c, sizeof c, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0, &b, sizeof b + 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0, &b, 0, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationProcess)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationProcess)((HANDLE)(ULONG_PTR)0x7ffc, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_THREAD, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0xFFFF, &b, sizeof b, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 0x1000, &b, sizeof b, &ret), ST_INV_CLASS);
    (void)st;
}

TEST(process_simple_classes)
{
    BYTE buf[1024]; ULONG ret; HANDLE dbg = NULL; DWORD hc = 0;
    REQUIRE(UN(NtQueryInformationProcess));
    /* ProcessDebugPort (7): no debugger */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 7, buf, 8, &ret), 0);
    EXPECT_EQ(ret, 8); EXPECT_EQ(*(ULONGLONG *)buf, 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 7, buf, 4, &ret), ST_LEN_MISMATCH);
    /* ProcessWow64Information (26): native process */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 26, buf, 8, &ret), 0);
    EXPECT_EQ(*(ULONGLONG *)buf, 0);
    /* ProcessDebugFlags (31): inherit set when not debugged */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 31, buf, 4, &ret), 0);
    EXPECT_EQ(ret, 4); EXPECT_EQ(*(ULONG *)buf, 1);
    /* ProcessDebugObjectHandle (30): STATUS_PORT_NOT_SET without a debug object */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 30, &dbg, sizeof dbg, &ret), S(0xC0000353));
    /* ProcessBreakOnTermination (29) */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 29, buf, 4, &ret), 0);
    EXPECT_EQ(*(ULONG *)buf, 0);
    /* ProcessHandleCount (20) agrees with the Win32 count */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 20, buf, 4, &ret), 0);
    EXPECT_EQ(ret, 4);
    if (GetProcessHandleCount(GetCurrentProcess(), &hc)) CHECK(*(ULONG *)buf >= hc - 4 && *(ULONG *)buf <= hc + 4);
    /* ProcessTimes (4) */
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 4, buf, 32, &ret), 0);
    EXPECT_EQ(ret, 32);
    { LONGLONG *t = (LONGLONG *)buf; FILETIME c, e, k, u; CHECK(t[0] > 0); CHECK(t[1] == 0); CHECK(t[2] >= 0 && t[3] >= 0);
      GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
      EXPECT_EQ(t[0], ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime); }
    /* ProcessCookie (36): stable and non-zero */
    { ULONG c1, c2;
      EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 36, &c1, 4, &ret), 0);
      EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 36, &c2, 4, &ret), 0);
      CHECK(c1 != 0); EXPECT_EQ(c1, c2); }
    /* ProcessSessionInformation (24) */
    { DWORD sid = 0xffff; EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 24, buf, 4, &ret), 0);
      if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) EXPECT_EQ(*(ULONG *)buf, sid); }
    /* ProcessPriorityClass (18): {BOOLEAN Foreground; UCHAR PriorityClass} */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 18, buf, 2, &ret), 0);
    { DWORD pc = GetPriorityClass(GetCurrentProcess()); CHECK(pc != 0);
      CHECK(buf[1] >= 1 && buf[1] <= 5); t_note("priority class win32=%lx nt=%u", pc, buf[1]); }
    /* ProcessImageFileName (27) / Win32 form (43) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 27, buf, sizeof buf, &ret), 0);
    {
        UNICODE_STRING *u = (UNICODE_STRING *)buf; char self[MAX_PATH]; const char *leaf; size_t n;
        CHECK(u->Length > 0 && u->Length <= sizeof buf - 16); CHECK(ret >= sizeof(UNICODE_STRING) + u->Length);
        CHECK((BYTE *)u->Buffer == buf + sizeof(UNICODE_STRING));
        CHECK(u->Buffer[0] == L'\\');
        strcpy(self, t_self_path()); leaf = strrchr(self, '\\'); leaf = leaf ? leaf + 1 : self; n = strlen(leaf);
        CHECK(u->Length / 2 >= n);
        { size_t i, ok = 1; for (i = 0; i < n; i++) if (tolower((unsigned char)leaf[i]) != tolower((unsigned char)u->Buffer[u->Length / 2 - n + i])) ok = 0; CHECK(ok); }
        EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 27, buf, ret - 1, &ret), ST_LEN_MISMATCH);
        CHECK(ret > 0);
        EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 27, buf, 4, &ret), ST_LEN_MISMATCH);
    }
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 43, buf, sizeof buf, &ret), 0);
    { UNICODE_STRING *u = (UNICODE_STRING *)buf; CHECK(u->Length > 4 && u->Buffer[1] == L':'); }
    /* ProcessVmCounters (3): at least the 0x70 basic form */
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 3, buf, 0x70, &ret), 0);
    EXPECT_EQ(ret, 0x70);
    CHECK(*(ULONGLONG *)(buf + 8) > 0);   /* VirtualSize */
    EXPECT_EQ(UN(NtQueryInformationProcess)(CUR_PROC, 3, buf, 0x20, &ret), ST_LEN_MISMATCH);
}

/* ---- thread ---- */
typedef struct { NTSTATUS exit; PVOID teb; ULONG_PTR pid, tid, affinity; LONG prio, base; } TBI;
static volatile LONG g_stop;
static DWORD WINAPI idle_thread(LPVOID p)
{
    while (!g_stop) Sleep(5);
    return 7;
}

TEST(thread_information)
{
    TBI b; BYTE buf[256]; ULONG ret; HANDLE t; DWORD tid; PVOID start = NULL;
    REQUIRE(UN(NtQueryInformationThread));
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, 48); EXPECT_EQ(sizeof b, 48);
    EXPECT_EQ(b.exit, STILL_ACTIVE);
    CHECK(b.teb == (PVOID)NtCurrentTeb());
    EXPECT_EQ(b.pid, GetCurrentProcessId()); EXPECT_EQ(b.tid, GetCurrentThreadId());
    CHECK(b.affinity != 0);
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationThread)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_PROC, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 0xFFFF, &b, sizeof b, &ret), ST_INV_CLASS);
    /* ThreadTimes (1) */
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 1, buf, 32, &ret), 0);
    EXPECT_EQ(ret, 32); CHECK(*(LONGLONG *)buf > 0);
    /* ThreadIsIoPending (16) */
    EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 16, buf, 4, &ret), 0);
    EXPECT_EQ(*(ULONG *)buf, 0);
    /* ThreadAmILastThread (12) is false while a second thread exists */
    g_stop = 0;
    t = CreateThread(NULL, 0, idle_thread, NULL, 0, &tid); CHECK(t != NULL);
    if (t) {
        TBI o;
        EXPECT_EQ(UN(NtQueryInformationThread)(CUR_THREAD, 12, buf, 4, &ret), 0);
        EXPECT_EQ(*(ULONG *)buf, 0);
        memset(&o, 0, sizeof o);
        EXPECT_EQ(UN(NtQueryInformationThread)(t, 0, &o, sizeof o, NULL), 0);
        EXPECT_EQ(o.tid, tid); EXPECT_EQ(o.pid, GetCurrentProcessId()); EXPECT_EQ(o.exit, STILL_ACTIVE);
        CHECK(o.teb != NULL && o.teb != (PVOID)NtCurrentTeb());
        /* ThreadQuerySetWin32StartAddress (9) is the user start routine */
        EXPECT_EQ(UN(NtQueryInformationThread)(t, 9, &start, sizeof start, &ret), 0);
        EXPECT_EQ(ret, sizeof start);
        CHECK(start == (PVOID)idle_thread);
        EXPECT_EQ(UN(NtQueryInformationThread)(t, 9, &start, 4, &ret), ST_LEN_MISMATCH);
        g_stop = 1;
        WaitForSingleObject(t, 5000);
        memset(&o, 0, sizeof o);
        EXPECT_EQ(UN(NtQueryInformationThread)(t, 0, &o, sizeof o, NULL), 0);
        EXPECT_EQ(o.exit, 7);
        /* thread handle without query rights */
        { HANDLE d = NULL; EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, t, CUR_PROC, &d, SYNCHRONIZE, 0, 0), 0);
          if (d) { EXPECT_EQ(UN(NtQueryInformationThread)(d, 0, &o, sizeof o, &ret), ST_DENIED); UN(NtClose)(d); } }
        CloseHandle(t);
    }
    g_stop = 1;
}

/* ---- token ---- */
typedef struct { ULONG count; LUID_AND_ATTRIBUTES p[1]; } TPRIV;

TEST(token_information)
{
    HANDLE t = NULL; BYTE buf[2048]; ULONG ret; NTSTATUS st; ULONG il = 0, elev = 0;
    REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtOpenProcessToken));
    EXPECT_EQ(UN(NtOpenProcessToken)(CUR_PROC, TOKEN_QUERY, &t), 0);
    if (!t) return;
    /* TokenUser (1) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 1, buf, sizeof buf, &ret), 0);
    { PSID sid = *(PSID *)buf; CHECK(ret >= 16 + 8); CHECK((BYTE *)sid == buf + 16); EXPECT_EQ(((BYTE *)sid)[0], 1); CHECK(IsValidSid(sid)); }
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 1, buf, 4, &ret), ST_BUF_SMALL);
    { ULONG need = ret; CHECK(need >= 24); EXPECT_EQ(UN(NtQueryInformationToken)(t, 1, buf, need - 1, &ret), ST_BUF_SMALL); EXPECT_EQ(ret, need); }
    /* TokenGroups (2), TokenPrivileges (3) */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 2, buf, sizeof buf, &ret), 0);
    CHECK(*(ULONG *)buf >= 1);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 3, buf, sizeof buf, &ret), 0);
    CHECK(ret >= 4 && ret == 4 + ((TPRIV *)buf)->count * 12 + (((TPRIV *)buf)->count == 0 ? 0 : 0));
    /* TokenType (8): primary */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, buf, 4, &ret), 0);
    EXPECT_EQ(*(ULONG *)buf, 1); EXPECT_EQ(ret, 4);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, buf, 3, &ret), ST_BUF_SMALL);
    EXPECT_EQ(ret, 4);
    /* TokenImpersonationLevel (9) is only for impersonation tokens */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 9, buf, 4, &ret), ST_INV_CLASS);   /* observed: impersonation level of a primary token */
    /* TokenStatistics (10) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 10, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 56); EXPECT_EQ(*(ULONG *)(buf + 24), 1 /* TokenPrimary */);
    /* TokenSessionId (12) */
    { DWORD sid = 0xffff; EXPECT_EQ(UN(NtQueryInformationToken)(t, 12, buf, 4, &ret), 0);
      if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) EXPECT_EQ(*(ULONG *)buf, sid); }
    /* TokenElevation (20) and TokenIntegrityLevel (25) agree */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 20, &elev, 4, &ret), 0);
    EXPECT_EQ(ret, 4);
    st = UN(NtQueryInformationToken)(t, 25, buf, sizeof buf, &ret);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        PSID sid = *(PSID *)buf; il = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
        t_note("elevation=%lu integrity=%#lx", elev, il);
        if (elev) CHECK(il >= 0x3000); else CHECK(il < 0x3000);
    }
    /* TokenElevationType (18): full (2) when elevated, default (1) or limited (3) */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 18, buf, 4, &ret), 0);
    if (elev) CHECK(*(ULONG *)buf == 2 || *(ULONG *)buf == 1); else CHECK(*(ULONG *)buf == 1 || *(ULONG *)buf == 3);
    /* TokenOrigin (17) */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 17, buf, 8, &ret), 0);
    EXPECT_EQ(ret, 8);
    /* classes and handles */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 0, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 0x100, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationToken)(NULL, 1, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationToken)(CUR_PROC, 1, buf, sizeof buf, &ret), ST_TYPE_MISM);
    UN(NtClose)(t);
    /* a token handle without TOKEN_QUERY */
    EXPECT_EQ(UN(NtOpenProcessToken)(CUR_PROC, TOKEN_DUPLICATE, &t), 0);
    if (t) { EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, buf, 4, &ret), ST_DENIED); UN(NtClose)(t); }
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, buf, 4, &ret), ST_INV_HANDLE);
}

TEST(security_attributes_token)
{
    HANDLE t = NULL; BYTE buf[1024]; ULONG ret = 0xdead; UNICODE_STRING nm; static WCHAR n[] = L"QIB://NOSUCHATTRIBUTE";
    REQUIRE(UN(NtQuerySecurityAttributesToken)); REQUIRE(UN(NtOpenProcessToken));
    EXPECT_EQ(UN(NtOpenProcessToken)(CUR_PROC, TOKEN_QUERY, &t), 0);
    if (!t) return;
    nm.Buffer = n; nm.Length = sizeof n - 2; nm.MaximumLength = sizeof n;
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(t, NULL, 0, buf, sizeof buf, &ret), 0);
    CHECK(ret >= 24 && ret <= sizeof buf);
    EXPECT_EQ(*(USHORT *)buf, 1);                        /* Version */
    EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(t, NULL, 0, buf, 0, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(t, &nm, 1, buf, sizeof buf, &ret), S(0xC0000225));   /* STATUS_NOT_FOUND */
    EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(NULL, NULL, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(CUR_PROC, NULL, 0, buf, sizeof buf, &ret), ST_TYPE_MISM);
    UN(NtClose)(t);
    EXPECT_EQ(UN(NtOpenProcessToken)(CUR_PROC, TOKEN_DUPLICATE, &t), 0);
    if (t) { EXPECT_EQ(UN(NtQuerySecurityAttributesToken)(t, NULL, 0, buf, sizeof buf, &ret), ST_DENIED); UN(NtClose)(t); }
}

/* ---- job object ---- */
CHILD(sleeper) { Sleep(60000); return 0; }

TEST(job_information)
{
    HANDLE j = NULL; BYTE buf[512]; ULONG ret; PROCESS_INFORMATION pi; HANDLE dup = NULL; HANDLE cp;
    REQUIRE(UN(NtQueryInformationJobObject)); REQUIRE(UN(NtCreateJobObject)); REQUIRE(UN(NtAssignProcessToJobObject));
    EXPECT_EQ(UN(NtCreateJobObject)(&j, JOB_OBJECT_ALL_ACCESS, NULL), 0);
    /* BasicAccountingInformation (1): empty job */
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 1, buf, 48, &ret), 0);
    EXPECT_EQ(ret, 48);
    { ULONG *u = (ULONG *)(buf + 32); EXPECT_EQ(*(LONGLONG *)buf, 0); EXPECT_EQ(u[0], 0); EXPECT_EQ(u[1], 0); EXPECT_EQ(u[2], 0); EXPECT_EQ(u[3], 0); }
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 1, buf, 47, &ret), ST_LEN_MISMATCH);
    /* BasicLimitInformation (2): all zero */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 2, buf, 64, &ret), 0);
    EXPECT_EQ(ret, 64); EXPECT_EQ(*(ULONG *)(buf + 16), 0); EXPECT_EQ(*(LONGLONG *)buf, 0);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 2, buf, 63, &ret), ST_LEN_MISMATCH);
    /* ExtendedLimitInformation (9) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 9, buf, 144, &ret), 0);
    EXPECT_EQ(ret, 144); EXPECT_EQ(*(ULONG *)(buf + 16), 0);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 9, buf, 64, &ret), ST_LEN_MISMATCH);
    /* BasicProcessIdList (3): empty */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 3, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(((ULONG *)buf)[0], 0); EXPECT_EQ(((ULONG *)buf)[1], 0);
    EXPECT_EQ(ret, 8);
    /* a job with one suspended child */
    memset(&pi, 0, sizeof pi);
    cp = t_spawn_child("sleeper", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!cp) { t_skip("child process could not be created"); UN(NtClose)(j); return; }
    EXPECT_EQ(UN(NtAssignProcessToJobObject)(j, pi.hProcess), 0);
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 3, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(((ULONG *)buf)[0], 1); EXPECT_EQ(((ULONG *)buf)[1], 1);
    EXPECT_EQ(*(ULONG_PTR *)(buf + 8), pi.dwProcessId);
    EXPECT_EQ(ret, 8 + 8);
    /* header only is shorter than the 16-byte structure */
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 3, buf, 8, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 3, buf, 7, &ret), ST_LEN_MISMATCH);
    /* accounting counts the process */
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 1, buf, 48, &ret), 0);
    { ULONG *u = (ULONG *)(buf + 36); EXPECT_EQ(u[0], 1); EXPECT_EQ(u[1], 1); EXPECT_EQ(u[2], 0); }
    /* classes and handles */
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 0, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 0x1000, buf, sizeof buf, &ret), ST_INV_CLASS);
        EXPECT_EQ(UN(NtQueryInformationJobObject)(CUR_THREAD, 1, buf, 48, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, j, CUR_PROC, &dup, JOB_OBJECT_ASSIGN_PROCESS, 0, 0), 0);
    if (dup) { EXPECT_EQ(UN(NtQueryInformationJobObject)(dup, 1, buf, 48, &ret), ST_DENIED); UN(NtClose)(dup); }
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    UN(NtClose)(j);
}

/* ---- virtual memory ---- */
typedef struct { PVOID base, allocBase; ULONG allocProt; USHORT pad1, pad2; SIZE_T size; ULONG state, prot, type, pad3; } MBI;

TEST(virtual_memory_basic)
{
    MBI m; SIZE_T ret; BYTE *p; HMODULE nt = GetModuleHandleA("ntdll.dll");
    REQUIRE(UN(NtQueryVirtualMemory));
    CHECK(sizeof m == 48);
    p = VirtualAlloc(NULL, 0x4000, MEM_RESERVE, PAGE_NOACCESS); CHECK(p != NULL); if (!p) return;
    CHECK(VirtualAlloc(p, 0x2000, MEM_COMMIT, PAGE_READWRITE) == p);
    memset(&m, 0xcc, sizeof m); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p + 0x10, 0, &m, sizeof m, &ret), 0);
    EXPECT_EQ(ret, 48);
    EXPECT_EQ(m.base, p); EXPECT_EQ(m.allocBase, p); EXPECT_EQ(m.allocProt, PAGE_NOACCESS);
    EXPECT_EQ(m.size, 0x2000); EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.type, MEM_PRIVATE);
    /* reserved tail of the same allocation */
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p + 0x2000, 0, &m, sizeof m, &ret), 0);
    EXPECT_EQ(m.base, p + 0x2000); EXPECT_EQ(m.allocBase, p); EXPECT_EQ(m.size, 0x2000);
    EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.prot, 0); EXPECT_EQ(m.type, MEM_PRIVATE);
    /* image mapping */
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, nt, 0, &m, sizeof m, &ret), 0);
    EXPECT_EQ(m.base, nt); EXPECT_EQ(m.allocBase, nt); EXPECT_EQ(m.type, MEM_IMAGE); EXPECT_EQ(m.state, MEM_COMMIT);
    EXPECT_EQ(m.prot, PAGE_READONLY);
    /* MemorySectionName (2) for the image; private memory has no section name */
    {
        BYTE buf[1024]; UNICODE_STRING *u = (UNICODE_STRING *)buf; NTSTATUS st;
        memset(buf, 0xcc, sizeof buf);
        st = UN(NtQueryVirtualMemory)(CUR_PROC, nt, 2, buf, sizeof buf, &ret);
        EXPECT_EQ(st, 0);
        if (st == 0) {
            CHECK(u->Length >= 18 && !_wcsnicmp(u->Buffer + u->Length / 2 - 9, L"ntdll.dll", 9));
            CHECK(ret >= sizeof *u + u->Length);
            EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, nt, 2, buf, 8, &ret), ST_LEN_MISMATCH);
        }
        EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p, 2, buf, sizeof buf, &ret), S(0xC0000141) /* STATUS_INVALID_ADDRESS */);
    }
    /* free region */
    VirtualFree(p, 0, MEM_RELEASE);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p, 0, &m, sizeof m, &ret), 0);
    EXPECT_EQ(m.state, MEM_FREE); EXPECT_EQ(m.prot, PAGE_NOACCESS); EXPECT_EQ(m.allocBase, NULL); EXPECT_EQ(m.type, 0);
    /* errors */
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p, 0, &m, sizeof m - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p, 0, &m, 0, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, (PVOID)0x7FFFFFFF0000ULL, 0, &m, sizeof m, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, (PVOID)0xFFFF800000000000ULL, 0, &m, sizeof m, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, p, 0x1000, &m, sizeof m, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(NULL, p, 0, &m, sizeof m, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_THREAD, p, 0, &m, sizeof m, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, CUR_PROC, CUR_PROC, &d, PROCESS_VM_READ, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQueryVirtualMemory)(d, nt, 0, &m, sizeof m, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    /* mapped view */
    {
        HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x3000, NULL);
        PVOID v = sec ? MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0) : NULL;
        CHECK(v != NULL);
        if (v) {
            EXPECT_EQ(UN(NtQueryVirtualMemory)(CUR_PROC, v, 0, &m, sizeof m, &ret), 0);
            EXPECT_EQ(m.type, MEM_MAPPED); EXPECT_EQ(m.size, 0x3000); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.base, v);
            UnmapViewOfFile(v);
        }
        if (sec) CloseHandle(sec);
    }
}

/* ---- system information ---- */
TEST(system_basic_processor)
{
    BYTE buf[256]; ULONG ret; SYSTEM_INFO si;
    REQUIRE(UN(NtQuerySystemInformation));
    GetSystemInfo(&si);
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, buf, 64, &ret), 0);
    EXPECT_EQ(ret, 64);
    EXPECT_EQ(buf[56], si.dwNumberOfProcessors);   /* NumberOfProcessors */
    EXPECT_EQ(*(ULONG *)(buf + 8), si.dwPageSize);
    EXPECT_EQ(*(ULONG *)(buf + 24), si.dwAllocationGranularity);
    EXPECT_EQ(*(ULONGLONG *)(buf + 32), (ULONGLONG)si.lpMinimumApplicationAddress);
    EXPECT_EQ(*(ULONGLONG *)(buf + 40), (ULONGLONG)si.lpMaximumApplicationAddress);
    EXPECT_EQ(*(ULONGLONG *)(buf + 48), (ULONGLONG)si.dwActiveProcessorMask);
    CHECK(*(ULONG *)(buf + 4) > 0);                /* TimerResolution */
    CHECK(*(ULONG *)(buf + 12) >= 1);              /* NumberOfPhysicalPages */
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, buf, 63, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(ret, 64);
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, buf, 65, &ret), ST_LEN_MISMATCH);
    /* SystemProcessorInformation (1) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQuerySystemInformation)(1, buf, 12, &ret), 0);
    EXPECT_EQ(ret, 12);
    EXPECT_EQ(*(USHORT *)buf, si.wProcessorArchitecture);
    EXPECT_EQ(*(USHORT *)(buf + 2), si.wProcessorLevel); EXPECT_EQ(*(USHORT *)(buf + 4), si.wProcessorRevision);
    EXPECT_EQ(UN(NtQuerySystemInformation)(1, buf, 11, &ret), ST_LEN_MISMATCH);
    /* SystemProcessorPerformanceInformation (8): one 48-byte record per processor */
    {
        BYTE big[48 * 512]; ULONG n = si.dwNumberOfProcessors;
        memset(big, 0, sizeof big);
        EXPECT_EQ(UN(NtQuerySystemInformation)(8, big, sizeof big, &ret), 0);
        EXPECT_EQ(ret, 48 * n);
        EXPECT_EQ(UN(NtQuerySystemInformation)(8, big, 48 * n - 1, &ret), ST_LEN_MISMATCH);
        CHECK(*(LONGLONG *)(big) > 0);   /* idle time of CPU 0 */
    }
    /* SystemTimeOfDayInformation (3) */
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQuerySystemInformation)(3, buf, 0x30, &ret), 0);
    { FILETIME ft; ULONGLONG now; GetSystemTimeAsFileTime(&ft); now = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
      LONGLONG cur = *(LONGLONG *)(buf + 8), boot = *(LONGLONG *)buf;
      CHECK(cur > 0 && (ULONGLONG)cur >= now - 20000000ULL * 5 && (ULONGLONG)cur <= now + 20000000ULL * 5);
      CHECK(boot > 0 && boot < cur); }
    /* SystemRangeStart (50) */
    EXPECT_EQ(UN(NtQuerySystemInformation)(50, buf, 8, &ret), 0);
    EXPECT_EQ(ret, 8); CHECK(*(ULONGLONG *)buf > (ULONGLONG)si.lpMaximumApplicationAddress);
    /* SystemFlagsInformation (9) agrees with the PEB */
    EXPECT_EQ(UN(NtQuerySystemInformation)(9, buf, 4, &ret), 0);
    EXPECT_EQ(ret, 4);
    /* SystemKernelDebuggerInformation (35) */
    EXPECT_EQ(UN(NtQuerySystemInformation)(35, buf, 2, &ret), 0);
    EXPECT_EQ(ret, 2);
    /* classes */
    EXPECT_EQ(UN(NtQuerySystemInformation)(0xFFFF, buf, 64, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQuerySystemInformation)(0x1000, buf, 64, &ret), ST_INV_CLASS);
}

TEST(system_process_information)
{
    BYTE *buf; ULONG ret = 0, sz, tries; NTSTATUS st; int found = 0;
    REQUIRE(UN(NtQuerySystemInformation));
    EXPECT_EQ(UN(NtQuerySystemInformation)(5, NULL, 0, &ret), ST_LEN_MISMATCH);
    CHECK(ret > 0x100);
    sz = ret + 0x10000; buf = NULL;
    for (tries = 0; tries < 8; tries++) {
        buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!buf) break;
        st = UN(NtQuerySystemInformation)(5, buf, sz, &ret);
        if (st != ST_LEN_MISMATCH) break;
        VirtualFree(buf, 0, MEM_RELEASE); buf = NULL; sz = ret + 0x10000;
    }
    CHECK(buf != NULL); if (!buf) return;
    EXPECT_EQ(st, 0);
    CHECK(ret > 0 && ret <= sz);
    {
        BYTE *p = buf; int n = 0;
        for (;;) {
            ULONG next = *(ULONG *)p; ULONG_PTR pid = *(ULONG_PTR *)(p + 80);
            n++;
            if (pid == GetCurrentProcessId()) {
                UNICODE_STRING *img = (UNICODE_STRING *)(p + 56); char self[MAX_PATH]; const char *leaf; size_t i, len;
                found++;
                CHECK(*(ULONG *)(p + 4) >= 1);   /* NumberOfThreads */
                strcpy(self, t_self_path()); leaf = strrchr(self, '\\'); leaf = leaf ? leaf + 1 : self; len = strlen(leaf);
                EXPECT_EQ(img->Length / 2, len);
                if (img->Length / 2 == len) { int ok = 1; for (i = 0; i < len; i++) if (tolower((unsigned char)leaf[i]) != tolower((unsigned char)img->Buffer[i])) ok = 0; CHECK(ok); }
                CHECK(*(ULONG_PTR *)(p + 88) != 0);   /* parent */
                CHECK(*(ULONG *)(p + 96) > 0);        /* handles */
            }
            if (!next) break;
            p += next;
        }
        CHECK(n >= 3);
    }
    EXPECT_EQ(found, 1);
    /* a too-small non-null buffer reports the required size as well */
    ret = 0;
    EXPECT_EQ(UN(NtQuerySystemInformation)(5, buf, 16, &ret), ST_LEN_MISMATCH);
    CHECK(ret > 0x100);
    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST(system_module_information)
{
    BYTE *buf; ULONG ret = 0; NTSTATUS st;
    REQUIRE(UN(NtQuerySystemInformation));
    EXPECT_EQ(UN(NtQuerySystemInformation)(11, NULL, 0, &ret), ST_LEN_MISMATCH);
    CHECK(ret > 8);
    buf = (BYTE *)VirtualAlloc(NULL, ret + 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(buf != NULL); if (!buf) return;
    st = UN(NtQuerySystemInformation)(11, buf, ret + 0x10000, &ret);
    EXPECT_EQ(st, 0);
    CHECK(*(ULONG *)buf >= 10);
    /* first entry is the kernel: RTL_PROCESS_MODULE_INFORMATION is 0x128 bytes; OffsetToFileName at 0x26, name at 0x28 */
    {
        BYTE *e = buf + 8; USHORT off = *(USHORT *)(e + 0x26); char *full = (char *)(e + 0x28);
        CHECK(off > 0 && off < 256);
        CHECK(!_strnicmp(full + off, "ntoskrnl.exe", 12) || !_strnicmp(full + off, "ntkrnl", 6));
        CHECK(*(ULONG *)(e + 0x18 + 4) != 0 || *(ULONG *)(e + 0x1c) != 0);
        CHECK(*(PVOID *)(e + 0x10) != NULL);
    }
    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST(system_information_ex)
{
    BYTE *buf; ULONG ret = 0, in = 0; NTSTATUS st; DWORD need = 0;
    REQUIRE(UN(NtQuerySystemInformationEx));
    /* SystemLogicalProcessorInformationEx (107) with RelationProcessorCore agrees with the Win32 size */
    st = UN(NtQuerySystemInformationEx)(107, &in, sizeof in, NULL, 0, &ret);
    EXPECT_EQ(st, ST_LEN_MISMATCH);
    CHECK(ret >= 0x30);
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &need);
    EXPECT_EQ(ret, need);
    buf = (BYTE *)VirtualAlloc(NULL, ret + 64, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(buf != NULL); if (!buf) return;
    {
        ULONG r2 = 0;
        memset(buf, 0xcc, ret + 64);
        EXPECT_EQ(UN(NtQuerySystemInformationEx)(107, &in, sizeof in, buf, ret, &r2), 0);
        EXPECT_EQ(r2, ret);
        EXPECT_EQ(*(ULONG *)buf, 0);                  /* Relationship = RelationProcessorCore */
        CHECK(*(ULONG *)(buf + 4) >= 0x30);
        EXPECT_EQ(UN(NtQuerySystemInformationEx)(107, &in, sizeof in, buf, ret - 1, &r2), ST_LEN_MISMATCH);
        EXPECT_EQ(r2, ret);
    }
    in = 0xFFFF;   /* RelationAll */
    EXPECT_EQ(UN(NtQuerySystemInformationEx)(107, &in, sizeof in, NULL, 0, &ret), ST_LEN_MISMATCH);
    CHECK(ret >= 0x30);
    EXPECT_EQ(UN(NtQuerySystemInformationEx)(107, NULL, 0, buf, 64, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQuerySystemInformationEx)(0xFFFF, &in, sizeof in, buf, 64, &ret), ST_INV_CLASS);
    VirtualFree(buf, 0, MEM_RELEASE);
}
