/* NtSetInformationObject / Process / Thread / Token / JobObject / DebugObject / SymbolicLink / Key,
 * NtSetValueKey, NtSetContextThread. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetInformationObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationProcess, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtGetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtSetInformationToken, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtSetInformationJobObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtSetInformationDebugObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtSetInformationSymbolicLink, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationKey, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));

#define S(x) ((NTSTATUS)(x))
#define OK(s) ((NTSTATUS)(s) >= 0)
#define ST_INV_HANDLE S(0xC0000008)
#define ST_TYPE_MISM  S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_LEN_MISM   S(0xC0000004)
#define ST_INV_CLASS  S(0xC0000003)
#define ST_PRIV       S(0xC0000061)

static HANDLE reduced(HANDLE h, DWORD access)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, FALSE, 0)) return NULL;
    return d;
}
static HANDLE mkevent(void)
{
    HANDLE h = NULL;
    if (UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE) != 0) return NULL;
    return h;
}

/* ---- NtSetInformationObject ------------------------------------------ */
typedef struct { BOOLEAN Inherit, ProtectFromClose; } OHF;
TEST(set_info_object_handle_flags)
{
    REQUIRE(UN(NtSetInformationObject)); REQUIRE(UN(NtQueryObject)); REQUIRE(UN(NtClose));
    CHECK(t_proc("NtSetInformationObject") == t_proc("ZwSetInformationObject"));
    HANDLE ev = mkevent();
    CHECK(ev != NULL); if (!ev) return;
    OHF f = { 1, 0 }, q; DWORD fl = 0;
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 4, &f, sizeof f), 0);
    CHECK(GetHandleInformation(ev, &fl)); EXPECT_EQ(fl & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    memset(&q, 9, sizeof q);
    EXPECT_EQ(UN(NtQueryObject)(ev, 4, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q.Inherit, 1); EXPECT_EQ(q.ProtectFromClose, 0);
    f.Inherit = 0; f.ProtectFromClose = 1;
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 4, &f, sizeof f), 0);
    CHECK(GetHandleInformation(ev, &fl));
    EXPECT_EQ(fl & HANDLE_FLAG_INHERIT, 0);
    EXPECT_EQ(fl & HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    EXPECT_EQ(UN(NtClose)(ev), S(0xC0000235));               /* STATUS_HANDLE_NOT_CLOSABLE */
    f.ProtectFromClose = 0;
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 4, &f, sizeof f), 0);
    /* errors */
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 4, &f, 1), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 4, &f, 4), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 0x7fff, &f, sizeof f), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationObject)(ev, 0, &f, sizeof f), ST_INV_CLASS);   /* basic info is query-only */
    /* observed: handle-attribute changes on an unresolvable handle report ACCESS_DENIED, not INVALID_HANDLE */
    EXPECT_EQ(UN(NtSetInformationObject)(NULL, 4, &f, sizeof f), ST_DENIED);
    EXPECT_EQ(UN(NtSetInformationObject)((HANDLE)(LONG_PTR)0x7ff0, 4, &f, sizeof f), ST_DENIED);
    EXPECT_EQ(UN(NtClose)(ev), 0);
}

/* ---- processes -------------------------------------------------------- */
CHILD(nsib_idle) { return 0; }
static BOOL spawn_suspended(PROCESS_INFORMATION *pi)
{
    HANDLE h = t_spawn_child("nsib_idle", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, pi);
    return h != NULL;
}
static void kill_child(PROCESS_INFORMATION *pi)
{
    TerminateProcess(pi->hProcess, 0);
    WaitForSingleObject(pi->hProcess, 5000);
    CloseHandle(pi->hThread); CloseHandle(pi->hProcess);
}
typedef struct { BOOLEAN Foreground; UCHAR PriorityClass; } PPC;
TEST(set_info_process_child)
{
    REQUIRE(UN(NtSetInformationProcess)); REQUIRE(UN(NtQueryInformationProcess));
    CHECK(t_proc("NtSetInformationProcess") == t_proc("ZwSetInformationProcess"));
    PROCESS_INFORMATION pi;
    if (!spawn_suspended(&pi)) { t_skip("cannot create a child process"); return; }
    PPC pc = { 0, 1 };                                        /* IDLE */
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(pi.hProcess), IDLE_PRIORITY_CLASS);
    pc.PriorityClass = 6;                                     /* ABOVE_NORMAL */
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(pi.hProcess), ABOVE_NORMAL_PRIORITY_CLASS);
    pc.PriorityClass = 5;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 18, &pc, sizeof pc), 0);
    EXPECT_EQ(GetPriorityClass(pi.hProcess), BELOW_NORMAL_PRIORITY_CLASS);
    pc.PriorityClass = 7;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 18, &pc, sizeof pc), ST_INV_PARAM);
    pc.PriorityClass = 2;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 18, &pc, 1), ST_LEN_MISM);
    EXPECT_EQ(GetPriorityClass(pi.hProcess), BELOW_NORMAL_PRIORITY_CLASS);   /* failures changed nothing */
    /* affinity */
    DWORD_PTR pm = 0, sm = 0;
    CHECK(GetProcessAffinityMask(pi.hProcess, &pm, &sm));
    DWORD_PTR one = pm & (~pm + 1);                           /* lowest allowed CPU */
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 21, &one, sizeof one), 0);
    DWORD_PTR pm2 = 0; CHECK(GetProcessAffinityMask(pi.hProcess, &pm2, &sm));
    EXPECT_EQ(pm2, one);
    DWORD_PTR zero = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 21, &zero, sizeof zero), ST_INV_PARAM);
    DWORD_PTR huge = ~(DWORD_PTR)0;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 21, &huge, sizeof huge), ST_INV_PARAM);   /* bits outside the system mask */
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 21, &one, 4), ST_LEN_MISM);
    /* priority boost */
    ULONG dis = 1, q = 9;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 22, &dis, sizeof dis), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(pi.hProcess, 22, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q, 1);
    BOOL b = FALSE; CHECK(GetProcessPriorityBoost(pi.hProcess, &b)); EXPECT_EQ(b, TRUE);
    dis = 0;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 22, &dis, sizeof dis), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(pi.hProcess, 22, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q, 0);
    /* default hard error mode */
    ULONG em = 1;
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 12, &em, sizeof em), 0);
    q = 9; EXPECT_EQ(UN(NtQueryInformationProcess)(pi.hProcess, 12, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q, 1);
    em = 0; UN(NtSetInformationProcess)(pi.hProcess, 12, &em, sizeof em);
    /* errors */
    EXPECT_EQ(UN(NtSetInformationProcess)(pi.hProcess, 0x7fff, &em, sizeof em), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationProcess)(NULL, 22, &em, sizeof em), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationProcess)((HANDLE)(LONG_PTR)-2, 22, &em, sizeof em), ST_TYPE_MISM);   /* thread pseudo-handle */
    HANDLE ro = reduced(pi.hProcess, PROCESS_QUERY_LIMITED_INFORMATION);
    if (ro) {
        dis = 1;
        EXPECT_EQ(UN(NtSetInformationProcess)(ro, 22, &dis, sizeof dis), ST_DENIED);
        EXPECT_EQ(UN(NtSetInformationProcess)(ro, 12, &dis, sizeof dis), ST_DENIED);
        CloseHandle(ro);
    }
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationProcess)(ev, 22, &em, sizeof em), ST_TYPE_MISM); UN(NtClose)(ev); }
    kill_child(&pi);
}
TEST(set_info_process_self)
{
    REQUIRE(UN(NtSetInformationProcess)); REQUIRE(UN(NtQueryInformationProcess));
    HANDLE self = GetCurrentProcess();                        /* pseudo handle -1 */
    ULONG old = 0, em = 3, q = 9;
    EXPECT_EQ(UN(NtQueryInformationProcess)(self, 12, &old, sizeof old, NULL), 0);
    EXPECT_EQ(UN(NtSetInformationProcess)(self, 12, &em, sizeof em), 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(self, 12, &q, sizeof q, NULL), 0);
    EXPECT_EQ(q, 3);
    EXPECT_EQ(GetErrorMode() & 3, 2);                         /* bit 0 of the native value is inverted: set = hard-error popups enabled */
    EXPECT_EQ(UN(NtSetInformationProcess)(self, 12, &old, sizeof old), 0);
    EXPECT_EQ(UN(NtSetInformationProcess)(self, 12, &em, 2), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationProcess)(self, 12, &em, 8), ST_LEN_MISM);
}

/* ---- threads ---------------------------------------------------------- */
static DWORD WINAPI idle_thread(LPVOID p) { return 0; }
static HANDLE mk_susp_thread(void)
{
    return CreateThread(NULL, 0, idle_thread, NULL, CREATE_SUSPENDED, NULL);
}
static void kill_thread(HANDLE t)
{
    TerminateThread(t, 0); WaitForSingleObject(t, 5000); CloseHandle(t);
}
TEST(set_info_thread_priority_affinity)
{
    REQUIRE(UN(NtSetInformationThread)); REQUIRE(UN(NtQueryInformationThread));
    CHECK(t_proc("NtSetInformationThread") == t_proc("ZwSetInformationThread"));
    HANDLE t = mk_susp_thread();
    CHECK(t != NULL); if (!t) return;
    LONG bp = 2;                                              /* base priority increment relative to the process class */
    EXPECT_EQ(UN(NtSetInformationThread)(t, 3, &bp, sizeof bp), 0);
    EXPECT_EQ(GetThreadPriority(t), 2);
    bp = -2;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 3, &bp, sizeof bp), 0);
    EXPECT_EQ(GetThreadPriority(t), -2);
    bp = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 3, &bp, sizeof bp), 0);
    EXPECT_EQ(GetThreadPriority(t), 0);
    EXPECT_EQ(UN(NtSetInformationThread)(t, 3, &bp, 2), ST_LEN_MISM);
    /* affinity */
    DWORD_PTR pm = 0, sm = 0; CHECK(GetProcessAffinityMask(GetCurrentProcess(), &pm, &sm));
    DWORD_PTR one = pm & (~pm + 1);
    EXPECT_EQ(UN(NtSetInformationThread)(t, 4, &one, sizeof one), 0);
    DWORD_PTR zero = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 4, &zero, sizeof zero), ST_INV_PARAM);
    EXPECT_EQ(UN(NtSetInformationThread)(t, 4, &one, 4), ST_LEN_MISM);
    DWORD_PTR prev = SetThreadAffinityMask(t, one);           /* returns the previous mask: the one set natively */
    EXPECT_EQ(prev, one);
    /* priority boost */
    ULONG dis = 1;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 14, &dis, sizeof dis), 0);
    BOOL b = FALSE; CHECK(GetThreadPriorityBoost(t, &b)); EXPECT_EQ(b, TRUE);
    dis = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 14, &dis, sizeof dis), 0);
    CHECK(GetThreadPriorityBoost(t, &b)); EXPECT_EQ(b, FALSE);
    EXPECT_EQ(UN(NtSetInformationThread)(t, 14, &dis, 1), ST_LEN_MISM);
    /* errors */
    EXPECT_EQ(UN(NtSetInformationThread)(t, 0x7fff, &dis, sizeof dis), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationThread)(NULL, 14, &dis, sizeof dis), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-1, 14, &dis, sizeof dis), ST_TYPE_MISM);   /* process pseudo-handle */
    HANDLE ro = reduced(t, THREAD_QUERY_LIMITED_INFORMATION);
    if (ro) { EXPECT_EQ(UN(NtSetInformationThread)(ro, 14, &dis, sizeof dis), ST_DENIED); CloseHandle(ro); }
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationThread)(ev, 14, &dis, sizeof dis), ST_TYPE_MISM); UN(NtClose)(ev); }
    kill_thread(t);
}
TEST(set_info_thread_hide_name)
{
    REQUIRE(UN(NtSetInformationThread)); REQUIRE(UN(NtQueryInformationThread));
    HANDLE t = mk_susp_thread();
    CHECK(t != NULL); if (!t) return;
    BOOLEAN h = 9;
    EXPECT_EQ(UN(NtQueryInformationThread)(t, 17, &h, sizeof h, NULL), 0);   /* ThreadHideFromDebugger query: one BOOLEAN */
    EXPECT_EQ(h, 0);
    ULONG dummy = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 17, &dummy, 4), ST_LEN_MISM);       /* takes no data */
    EXPECT_EQ(UN(NtSetInformationThread)(t, 17, NULL, 0), 0);
    h = 0;
    EXPECT_EQ(UN(NtQueryInformationThread)(t, 17, &h, sizeof h, NULL), 0);
    EXPECT_EQ(h, 1);
    /* thread name (Windows 10 1607+) */
    typedef HRESULT (WINAPI *PGetDesc)(HANDLE, PWSTR *);
    PGetDesc gd = (PGetDesc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetThreadDescription");
    WCHAR nm[] = L"nsib-name";
    UNICODE_STRING us; us.Buffer = nm; us.Length = us.MaximumLength = (USHORT)(lstrlenW(nm) * 2);
    NTSTATUS st = UN(NtSetInformationThread)(t, 38, &us, sizeof us);
    EXPECT_EQ(st, 0);
    if (gd) {
        PWSTR got = NULL;
        CHECK(gd(t, &got) >= 0);
        if (got) { EXPECT_WSTR(got, nm); LocalFree(got); }
    }
    us.Length = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(t, 38, &us, sizeof us), 0);        /* clears the name */
    EXPECT_EQ(UN(NtSetInformationThread)(t, 38, &us, 4), ST_LEN_MISM);
    kill_thread(t);
}
TEST(set_context_thread)
{
    REQUIRE(UN(NtSetContextThread)); REQUIRE(UN(NtGetContextThread));
    CHECK(t_proc("NtSetContextThread") == t_proc("ZwSetContextThread"));
#ifdef __x86_64__
    HANDLE t = mk_susp_thread();
    CHECK(t != NULL); if (!t) return;
    static CONTEXT ctx __attribute__((aligned(16)));
    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_INTEGER;
    EXPECT_EQ(UN(NtGetContextThread)(t, &ctx), 0);
    ctx.Rbx = 0x1122334455667788ULL; ctx.R12 = 0xA5A5A5A55A5A5A5AULL; ctx.R15 = 0xdeadbeef;
    EXPECT_EQ(UN(NtSetContextThread)(t, &ctx), 0);
    static CONTEXT c2 __attribute__((aligned(16)));
    memset(&c2, 0, sizeof c2);
    c2.ContextFlags = CONTEXT_INTEGER;
    EXPECT_EQ(UN(NtGetContextThread)(t, &c2), 0);
    EXPECT_EQ(c2.Rbx, 0x1122334455667788ULL);
    EXPECT_EQ(c2.R12, 0xA5A5A5A55A5A5A5AULL);
    EXPECT_EQ(c2.R15, 0xdeadbeef);
    /* floating point / segment state round-trips */
    c2.ContextFlags = CONTEXT_FLOATING_POINT;
    EXPECT_EQ(UN(NtGetContextThread)(t, &c2), 0);
    c2.FltSave.ControlWord = 0x27f;
    c2.FltSave.MxCsr = 0x1f80;
    EXPECT_EQ(UN(NtSetContextThread)(t, &c2), 0);
    memset(&ctx, 0, sizeof ctx); ctx.ContextFlags = CONTEXT_FLOATING_POINT;
    EXPECT_EQ(UN(NtGetContextThread)(t, &ctx), 0);
    EXPECT_EQ(ctx.FltSave.ControlWord, 0x27f);
    EXPECT_EQ(ctx.MxCsr, 0x1f80);
    /* errors */
    ctx.ContextFlags = CONTEXT_INTEGER;
    EXPECT_EQ(UN(NtSetContextThread)(NULL, &ctx), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetContextThread)((HANDLE)(LONG_PTR)-1, &ctx), ST_TYPE_MISM);
    HANDLE ro = reduced(t, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT);
    if (ro) { EXPECT_EQ(UN(NtSetContextThread)(ro, &ctx), ST_DENIED); CloseHandle(ro); }
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetContextThread)(ev, &ctx), ST_TYPE_MISM); UN(NtClose)(ev); }
    EXPECT_EQ(UN(NtSetContextThread)(t, NULL), S(0xC0000005));
    static BYTE raw[sizeof(CONTEXT) + 32] __attribute__((aligned(16)));
    memcpy(raw + 8, &ctx, sizeof ctx);
    EXPECT_EQ(UN(NtSetContextThread)(t, (PCONTEXT)(raw + 8)), S(0x80000002));   /* STATUS_DATATYPE_MISALIGNMENT */
    kill_thread(t);
#else
    t_skip("x64 context layout only");
#endif
}
