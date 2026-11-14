/* DbgPrint family, break points, filter state and the DbgUi debugger-side wrappers.
 * Status values are NTSTATUS unless noted. The DbgUi wrappers act on the per-thread debug object stored in the
 * TEB (DbgSsReserved[1], offset 0x16a8 on x64); each test that touches it runs on a private worker thread.
 */
#include "t.h"

typedef LONG NTS;
typedef struct { ULONG_PTR p, t; } CID;
typedef struct { ULONG NewState; ULONG pad; CID Client; BYTE Info[0x300]; } WSC;

UDECL(ULONG, DbgPrint, (PCSTR, ...));
UDECL(ULONG, DbgPrintEx, (ULONG, ULONG, PCSTR, ...));
UDECL(ULONG, DbgPrintReturnControlC, (PCSTR, ...));
UDECL(ULONG, DbgPrompt, (PCSTR, PCHAR, ULONG));
UDECL(NTS, DbgQueryDebugFilterState, (ULONG, ULONG));
UDECL(NTS, DbgSetDebugFilterState, (ULONG, ULONG, BOOLEAN));
UDECL(VOID, DbgBreakPoint, (void));
UDECL(VOID, DbgUserBreakPoint, (void));
UDECL(NTS, DbgUiConnectToDbg, (void));
UDECL(HANDLE, DbgUiGetThreadDebugObject, (void));
UDECL(VOID, DbgUiSetThreadDebugObject, (HANDLE));
UDECL(NTS, DbgUiWaitStateChange, (WSC *, PLARGE_INTEGER));
UDECL(NTS, DbgUiContinue, (CID *, NTS));
UDECL(NTS, DbgUiStopDebugging, (HANDLE));
UDECL(NTS, DbgUiDebugActiveProcess, (HANDLE));
UDECL(NTS, DbgUiIssueRemoteBreakin, (HANDLE));
UDECL(VOID, DbgUiRemoteBreakin, (PVOID));
UDECL(NTS, DbgUiConvertStateChangeStructure, (WSC *, DEBUG_EVENT *));
UDECL(NTS, DbgUiConvertStateChangeStructureEx, (WSC *, DEBUG_EVENT *, ULONG));

#define NEED(n) REQUIRE(UN(n))
#define DBG_CONT 0x00010002
#define DBG_NOT_HANDLED ((NTS)0x80010001)

CHILD(dbg_sleeper) { Sleep(60000); return 0; }

static HANDLE spawn_sleeper(PROCESS_INFORMATION *pi)
{
    return t_spawn_child("dbg_sleeper", NULL, 0, NULL, NULL, NULL, FALSE, NULL, pi);
}
static void reap(HANDLE h, HANDLE ht)
{
    if (h) { TerminateProcess(h, 0); WaitForSingleObject(h, 10000); CloseHandle(h); }
    if (ht) CloseHandle(ht);
}

/* ---- DbgPrint ---------------------------------------------------------- */
static volatile LONG g_dp_n; static DWORD g_dp_code[16]; static char g_dp_msg[16][128];
static LONG CALLBACK dp_veh(PEXCEPTION_POINTERS ep)
{
    EXCEPTION_RECORD *r = ep->ExceptionRecord;
    if (r->ExceptionCode == 0x40010006 || r->ExceptionCode == 0x4001000A) {
        LONG i = InterlockedIncrement(&g_dp_n) - 1;
        if (i < 16) {
            g_dp_code[i] = r->ExceptionCode;
            g_dp_msg[i][0] = 0;
            if (r->NumberParameters >= 2 && r->ExceptionInformation[1]) {
                strncpy(g_dp_msg[i], (const char *)r->ExceptionInformation[1], 127); g_dp_msg[i][127] = 0;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

TEST(dbg_print_family)
{
    NEED(DbgPrint); NEED(DbgPrintEx); NEED(DbgPrintReturnControlC);
    PVOID vh = AddVectoredExceptionHandler(1, dp_veh);
    ULONG r;
    g_dp_n = 0;
    r = UN(DbgPrint)("ntdllt dbgprint %d %s\n", 42, "abc");
    EXPECT_EQ(r, 0);   /* DbgPrint: no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrint)("ntdllt dbgprint plain\n");
    EXPECT_EQ(r, 0);   /* DbgPrint plain: no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintEx)(101, 0, "ntdllt dbgprintex err %d\n", 7);
    EXPECT_EQ(r, 0);   /* DbgPrintEx(101,0): no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintEx)(101, 3, "ntdllt dbgprintex lvl3\n");
    EXPECT_EQ(r, 0);   /* DbgPrintEx(101,3): no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintEx)(101, 31, "ntdllt dbgprintex lvl31\n");
    EXPECT_EQ(r, 0);   /* DbgPrintEx(101,31): no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintEx)(101, 0x80000000, "ntdllt dbgprintex mask\n");
    EXPECT_EQ(r, 0);   /* DbgPrintEx(101,mask): no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintEx)(0xffff, 0, "ntdllt dbgprintex badcomp\n");
    EXPECT_EQ(r, 0);   /* DbgPrintEx(0xffff,0): no debugger, nothing raised */
    g_dp_n = 0;
    r = UN(DbgPrintReturnControlC)("ntdllt dbgprint rcc %d\n", 1);
    EXPECT_EQ(r, 0);   /* DbgPrintReturnControlC: no debugger, nothing raised */
    RemoveVectoredExceptionHandler(vh);
}

static volatile LONG g_pr_n; static PVOID g_pr_addr; static DWORD g_pr_code; static BYTE g_pr_bytes[4];
static LONG CALLBACK pr_veh(PEXCEPTION_POINTERS ep)
{
    EXCEPTION_RECORD *r = ep->ExceptionRecord;
    if (r->ExceptionCode != 0x80000003) return EXCEPTION_CONTINUE_SEARCH;
    BYTE *a = (BYTE *)r->ExceptionAddress;
    g_pr_code = r->ExceptionCode; g_pr_addr = a; memcpy(g_pr_bytes, a, 4);
    InterlockedIncrement(&g_pr_n);
    /* "int 2d; int3; ret": the exception is reported at the byte after the service byte, resume at the ret */
    if (a[-3] == 0xCD && a[-2] == 0x2D && a[-1] == 0xCC && a[0] == 0xC3) ep->ContextRecord->Rip = (ULONG_PTR)a;
    else if (a[0] == 0xCD && a[1] == 0x2D) ep->ContextRecord->Rip = (ULONG_PTR)a + 3;
    else if (a[0] == 0xCC) ep->ContextRecord->Rip = (ULONG_PTR)a + 1;
    else return EXCEPTION_CONTINUE_SEARCH;
    return EXCEPTION_CONTINUE_EXECUTION;
}
TEST(dbg_prompt_and_filter)
{
    NEED(DbgPrompt); NEED(DbgQueryDebugFilterState); NEED(DbgSetDebugFilterState);
    char resp[32] = {0};
    if (!IsDebuggerPresent()) {
        PVOID vh = AddVectoredExceptionHandler(1, pr_veh);
        g_pr_n = 0;
        ULONG r = UN(DbgPrompt)("ntdllt> ", resp, sizeof resp);
        RemoveVectoredExceptionHandler(vh);
        /* int 2d with no debugger: one breakpoint exception; the return value is whatever eax holds afterwards */
        EXPECT_EQ(g_pr_n, 1);
        EXPECT_EQ(g_pr_code, 0x80000003);
        EXPECT_EQ(resp[0], 0);
    }
    NTS s;
    s = UN(DbgQueryDebugFilterState)(101, 0); EXPECT_EQ(s, 1);        /* DPFLTR_ERROR_LEVEL of the default component is on */
    s = UN(DbgQueryDebugFilterState)(101, 3); EXPECT_EQ(s, 0);
    s = UN(DbgQueryDebugFilterState)(101, 31); EXPECT_EQ(s, 0);
    s = UN(DbgQueryDebugFilterState)(101, 32); EXPECT_EQ(s, 0);
    s = UN(DbgQueryDebugFilterState)(0xffffffff, 0); EXPECT_EQ(s, 0);
    s = UN(DbgQueryDebugFilterState)(0x1000, 0); EXPECT_EQ(s, 0);
    /* clearing a level that is already clear changes nothing */
    s = UN(DbgSetDebugFilterState)(101, 3, FALSE); t_note("Set(101,3,FALSE)=0x%lx", s);
    s = UN(DbgSetDebugFilterState)(0xffffffff, 0, FALSE); t_note("Set(-1,0,FALSE)=0x%lx", s);
    s = UN(DbgQueryDebugFilterState)(101, 3); EXPECT_EQ(s, 0);
}

/* ---- break points ------------------------------------------------------ */
static volatile LONG g_bp_n; static PVOID g_bp_addr; static DWORD g_bp_np; static DWORD g_bp_code;
static LONG CALLBACK bp_veh(PEXCEPTION_POINTERS ep)
{
    EXCEPTION_RECORD *r = ep->ExceptionRecord;
    if (r->ExceptionCode != 0x80000003) return EXCEPTION_CONTINUE_SEARCH;
    g_bp_code = r->ExceptionCode; g_bp_addr = r->ExceptionAddress; g_bp_np = r->NumberParameters;
    InterlockedIncrement(&g_bp_n);
    if ((ULONG_PTR)ep->ContextRecord->Rip == (ULONG_PTR)r->ExceptionAddress && *(BYTE *)r->ExceptionAddress == 0xCC)
        ep->ContextRecord->Rip++;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static void do_break(const char *name, FARPROC f)
{
    if (!f) { t_skip("missing export: %s", name); return; }
    if (IsDebuggerPresent()) { t_skip("debugger attached to the test process"); return; }
    if (*(BYTE *)f != 0xCC) { t_note("%s does not start with int3 (first byte %02x)", name, *(BYTE *)f); }
    PVOID vh = AddVectoredExceptionHandler(1, bp_veh);
    g_bp_n = 0; g_bp_addr = NULL;
    ((void (WINAPI *)(void))f)();
    RemoveVectoredExceptionHandler(vh);
    EXPECT_EQ(g_bp_n, 1);
    EXPECT_EQ(g_bp_code, 0x80000003);
    CHECK(g_bp_addr == (PVOID)f);
    t_note("%s: addr==fn %d, nparams=%lu", name, g_bp_addr == (PVOID)f, (unsigned long)g_bp_np);
}
TEST(dbg_break_point) { do_break("DbgBreakPoint", t_proc("DbgBreakPoint")); }
TEST(dbg_user_break_point) { do_break("DbgUserBreakPoint", t_proc("DbgUserBreakPoint")); }

/* ---- DbgUi thread debug object ---------------------------------------- */
typedef struct { int stage; NTS st[16]; HANDLE h[4]; } uiobj;
static DWORD WINAPI getset_thread(LPVOID p)
{
    uiobj *o = p;
    HANDLE *slot = (HANDLE *)((char *)NtCurrentTeb() + 0x16a8);
    o->h[0] = UN(DbgUiGetThreadDebugObject)();
    UN(DbgUiSetThreadDebugObject)((HANDLE)(ULONG_PTR)0x1234);
    o->h[1] = UN(DbgUiGetThreadDebugObject)();
    o->h[2] = *slot;
    UN(DbgUiSetThreadDebugObject)(NULL);
    o->h[3] = *slot;
    return 0;
}
TEST(dbg_ui_get_set_debug_object)
{
    NEED(DbgUiGetThreadDebugObject); NEED(DbgUiSetThreadDebugObject);
    uiobj o; memset(&o, 0, sizeof o);
    HANDLE th = CreateThread(NULL, 0, getset_thread, &o, 0, NULL);
    CHECK(th != NULL); if (!th) return;
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0); CloseHandle(th);
    EXPECT_EQ((ULONG_PTR)o.h[0], 0);
    EXPECT_EQ((ULONG_PTR)o.h[1], 0x1234);
    EXPECT_EQ((ULONG_PTR)o.h[2], 0x1234);
    EXPECT_EQ((ULONG_PTR)o.h[3], 0);
}

static DWORD WINAPI connect_thread(LPVOID p)
{
    uiobj *o = p;
    LARGE_INTEGER to; to.QuadPart = -500000;   /* 50 ms */
    WSC sc; memset(&sc, 0, sizeof sc);
    o->h[0] = UN(DbgUiGetThreadDebugObject)();
    o->st[0] = UN(DbgUiWaitStateChange)(&sc, &to);            /* no debug object yet */
    o->st[1] = UN(DbgUiConnectToDbg)();
    o->h[1] = UN(DbgUiGetThreadDebugObject)();
    o->st[2] = UN(DbgUiConnectToDbg)();                       /* already connected: no-op */
    o->h[2] = UN(DbgUiGetThreadDebugObject)();
    o->st[3] = UN(DbgUiWaitStateChange)(&sc, &to);            /* empty queue */
    o->st[4] = UN(DbgUiStopDebugging)((HANDLE)(LONG_PTR)-1);
    o->st[5] = UN(DbgUiDebugActiveProcess)(NULL);
    o->st[6] = UN(DbgUiDebugActiveProcess)((HANDLE)(LONG_PTR)-1);
    CID cid = {0x4, 0x8};
    o->st[7] = UN(DbgUiContinue)(&cid, DBG_CONT);             /* nothing to continue */
    if (o->h[1]) {
        o->st[8] = CloseHandle(o->h[1]) ? 0 : (NTS)GetLastError();
        UN(DbgUiSetThreadDebugObject)(NULL);
    }
    o->h[3] = UN(DbgUiGetThreadDebugObject)();
    return 0;
}
TEST(dbg_ui_connect_wait_empty)
{
    NEED(DbgUiConnectToDbg); NEED(DbgUiGetThreadDebugObject); NEED(DbgUiSetThreadDebugObject);
    NEED(DbgUiWaitStateChange); NEED(DbgUiStopDebugging); NEED(DbgUiDebugActiveProcess); NEED(DbgUiContinue);
    uiobj o; memset(&o, 0, sizeof o);
    HANDLE th = CreateThread(NULL, 0, connect_thread, &o, 0, NULL);
    CHECK(th != NULL); if (!th) return;
    EXPECT_EQ(WaitForSingleObject(th, 20000), WAIT_OBJECT_0); CloseHandle(th);
    EXPECT_EQ((ULONG_PTR)o.h[0], 0);
    EXPECT_EQ(o.st[0], (NTS)0xC0000008);
    EXPECT_EQ(o.st[1], 0);
    CHECK(o.h[1] != NULL);
    EXPECT_EQ(o.st[2], 0);
    EXPECT_EQ((ULONG_PTR)o.h[2], (ULONG_PTR)o.h[1]);
    EXPECT_EQ(o.st[3], 0x102);                                /* STATUS_TIMEOUT */
    EXPECT_EQ(o.st[4], (NTS)0xC0000353);     /* STATUS_PORT_NOT_SET: not being debugged */
    EXPECT_EQ(o.st[5], (NTS)0xC0000008);
    EXPECT_EQ(o.st[6], (NTS)0xC0000022);
    EXPECT_EQ(o.st[7], (NTS)0xC000000D);
    EXPECT_EQ(o.st[8], 0);
    EXPECT_EQ((ULONG_PTR)o.h[3], 0);
}

/* ---- convert ----------------------------------------------------------- */
TEST(dbg_ui_convert_state_change)
{
    NEED(DbgUiConvertStateChangeStructure); NEED(DbgUiConvertStateChangeStructureEx);
    WSC sc; DEBUG_EVENT de; NTS st;
    /* DbgExitProcessStateChange (5): ExitStatus right after the client id */
    memset(&sc, 0, sizeof sc); memset(&de, 0xcc, sizeof de);
    sc.NewState = 5; sc.Client.p = 0x1234; sc.Client.t = 0x5678;
    *(NTS *)&sc.Info[0] = 0x4321;
    st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
    t_note("convert exit-process rc=0x%lx code=%lu pid=%lu tid=%lu exit=0x%lx", st, de.dwDebugEventCode, de.dwProcessId, de.dwThreadId, de.u.ExitProcess.dwExitCode);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(de.dwDebugEventCode, EXIT_PROCESS_DEBUG_EVENT);
    EXPECT_EQ(de.dwProcessId, 0x1234);
    EXPECT_EQ(de.dwThreadId, 0x5678);
    EXPECT_EQ(de.u.ExitProcess.dwExitCode, 0x4321);
    /* DbgExitThreadStateChange (4) */
    memset(&de, 0xcc, sizeof de);
    sc.NewState = 4;
    st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(de.dwDebugEventCode, EXIT_THREAD_DEBUG_EVENT);
    EXPECT_EQ(de.dwProcessId, 0x1234);
    EXPECT_EQ(de.dwThreadId, 0x5678);
    EXPECT_EQ(de.u.ExitThread.dwExitCode, 0x4321);
    /* DbgBreakpointStateChange (7) / DbgExceptionStateChange (6): EXCEPTION_RECORD at +0x18 */
    EXCEPTION_RECORD er; memset(&er, 0, sizeof er);
    er.ExceptionCode = 0x80000003; er.ExceptionAddress = (PVOID)0x7ff600001000ULL;
    memset(&sc, 0, sizeof sc); sc.NewState = 7; sc.Client.p = 0x1234; sc.Client.t = 0x5678;
    memcpy(sc.Info, &er, sizeof er);
    memset(&de, 0xcc, sizeof de);
    st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
    t_note("convert breakpoint rc=0x%lx code=%lu first=%lu exc=0x%lx", st, de.dwDebugEventCode, de.u.Exception.dwFirstChance, de.u.Exception.ExceptionRecord.ExceptionCode);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(de.dwDebugEventCode, EXCEPTION_DEBUG_EVENT);
    EXPECT_EQ(de.u.Exception.ExceptionRecord.ExceptionCode, 0x80000003);
    EXPECT_EQ((ULONG_PTR)de.u.Exception.ExceptionRecord.ExceptionAddress, 0x7ff600001000ULL);
    EXPECT_EQ(de.dwProcessId, 0x1234);
    er.ExceptionCode = 0xC0000005;
    memset(&sc, 0, sizeof sc); sc.NewState = 6; sc.Client.p = 0x1234; sc.Client.t = 0x5678;
    memcpy(sc.Info, &er, sizeof er);
    *(ULONG *)&sc.Info[sizeof er] = 0;       /* FirstChance follows the record */
    memset(&de, 0xcc, sizeof de);
    st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
    t_note("convert exception rc=0x%lx code=%lu first=%lu exc=0x%lx", st, de.dwDebugEventCode, de.u.Exception.dwFirstChance, de.u.Exception.ExceptionRecord.ExceptionCode);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(de.dwDebugEventCode, EXCEPTION_DEBUG_EVENT);
    EXPECT_EQ(de.u.Exception.ExceptionRecord.ExceptionCode, 0xC0000005);
    /* the non-Ex entry point gives the same result */
    memset(&de, 0xcc, sizeof de);
    sc.NewState = 5; sc.Client.p = 0x1234; sc.Client.t = 0x5678; *(NTS *)&sc.Info[0] = 0x4321;
    st = UN(DbgUiConvertStateChangeStructure)(&sc, &de);
    t_note("non-Ex rc=0x%lx code=%lu", st, de.dwDebugEventCode);
    EXPECT_EQ(de.dwDebugEventCode, EXIT_PROCESS_DEBUG_EVENT);
    EXPECT_EQ(de.u.ExitProcess.dwExitCode, 0x4321);
    /* states that carry no debug event */
    for (ULONG s = 0; s <= 1; s++) {
        memset(&sc, 0, sizeof sc); sc.NewState = s; memset(&de, 0xcc, sizeof de);
        st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
        EXPECT_EQ(st, (NTS)0xC0000001);
    }
    memset(&sc, 0, sizeof sc); sc.NewState = 0x99; memset(&de, 0xcc, sizeof de);
    st = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
    EXPECT_EQ(st, (NTS)0xC0000001);
}

/* ---- remote break-in --------------------------------------------------- */
TEST(dbg_ui_remote_breakin_thread)
{
    NEED(DbgUiRemoteBreakin);
    if (IsDebuggerPresent()) { t_skip("debugger attached"); return; }
    if (*(volatile BYTE *)0x7ffe02d4 & 3) { t_skip("kernel debugger enabled"); return; }
    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)t_proc("DbgUiRemoteBreakin"), NULL, 0, NULL);
    CHECK(th != NULL); if (!th) return;
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    DWORD ec = 0xdead; GetExitCodeThread(th, &ec);
    EXPECT_EQ(ec, 0);
    CloseHandle(th);
}

TEST(dbg_ui_issue_remote_breakin)
{
    NEED(DbgUiIssueRemoteBreakin);
    EXPECT_EQ(UN(DbgUiIssueRemoteBreakin)(NULL), (NTS)0xC0000008);
    EXPECT_EQ(UN(DbgUiIssueRemoteBreakin)((HANDLE)(LONG_PTR)-4), (NTS)0xC0000008);
    PROCESS_INFORMATION pi; HANDLE h = spawn_sleeper(&pi);
    CHECK(h != NULL); if (!h) return;
    NTS st = UN(DbgUiIssueRemoteBreakin)(h);
    EXPECT_EQ(st, 0);
    /* the injected thread exits quietly when no debugger is attached; the target survives */
    EXPECT_EQ(WaitForSingleObject(h, 500), WAIT_TIMEOUT);
    reap(h, pi.hThread);
}

/* ---- full attach / event / detach cycle -------------------------------- */
typedef struct {
    NTS attach, stop, stop2, cont_bad;
    int first_state, saw_thread, saw_bp, saw_exit_t, nevents, conv_ok, bp_conv_ok, pid_ok;
    DWORD pid; HANDLE hproc; HANDLE hdbg;
} cyc;
static DWORD WINAPI cycle_thread(LPVOID p)
{
    cyc *c = p; WSC sc; DEBUG_EVENT de; LARGE_INTEGER to;
    c->first_state = -1; c->conv_ok = 1; c->pid_ok = 1;
    if (UN(DbgUiConnectToDbg)() != 0) return 1;
    c->hdbg = UN(DbgUiGetThreadDebugObject)();
    c->attach = UN(DbgUiDebugActiveProcess)(c->hproc);
    if (c->attach != 0) goto out;
    DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < 20000 && !c->saw_bp) {
        to.QuadPart = -10000000LL;  /* 1 s */
        memset(&sc, 0, sizeof sc);
        NTS ws = UN(DbgUiWaitStateChange)(&sc, &to);
        if (ws == 0x102) continue;
        if (ws != 0) { c->nevents = -(int)ws; break; }
        c->nevents++;
        if (c->first_state < 0) c->first_state = sc.NewState;
        memset(&de, 0xcc, sizeof de);
        NTS cs = UN(DbgUiConvertStateChangeStructureEx)(&sc, &de, 0);
        if (cs != 0) c->conv_ok = 0;
        else {
            if (de.dwProcessId != c->pid) c->pid_ok = 0;
            if (sc.NewState == 2) c->saw_thread = 1;
            if (sc.NewState == 7) { c->saw_bp = 1; if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && de.u.Exception.ExceptionRecord.ExceptionCode == 0x80000003) c->bp_conv_ok = 1; }
            if (sc.NewState == 3) { if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) c->conv_ok = 0; if (de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile); }
            if (sc.NewState == 9 && de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
        }
        UN(DbgUiContinue)(&sc.Client, DBG_CONT);
    }
    c->stop = UN(DbgUiStopDebugging)(c->hproc);
    c->stop2 = UN(DbgUiStopDebugging)(c->hproc);
out:
    if (c->hdbg) CloseHandle(c->hdbg);
    UN(DbgUiSetThreadDebugObject)(NULL);
    return 0;
}
TEST(dbg_ui_attach_event_detach)
{
    NEED(DbgUiConnectToDbg); NEED(DbgUiGetThreadDebugObject); NEED(DbgUiSetThreadDebugObject); NEED(DbgUiWaitStateChange);
    NEED(DbgUiContinue); NEED(DbgUiStopDebugging); NEED(DbgUiDebugActiveProcess); NEED(DbgUiConvertStateChangeStructureEx);
    if (IsDebuggerPresent()) { t_skip("debugger attached to the test process"); return; }
    PROCESS_INFORMATION pi; HANDLE h = spawn_sleeper(&pi);
    CHECK(h != NULL); if (!h) return;
    cyc c; memset(&c, 0, sizeof c); c.hproc = h; c.pid = pi.dwProcessId;
    HANDLE th = CreateThread(NULL, 0, cycle_thread, &c, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        DWORD w = WaitForSingleObject(th, 60000);
        EXPECT_EQ(w, WAIT_OBJECT_0);
        if (w == WAIT_OBJECT_0) CloseHandle(th);
    }
    t_note("attach=0x%lx stop=0x%lx stop2=0x%lx events=%d first=%d thread=%d bp=%d", c.attach, c.stop, c.stop2, c.nevents, c.first_state, c.saw_thread, c.saw_bp);
    EXPECT_EQ(c.attach, 0);
    EXPECT_EQ(c.first_state, 3);          /* DbgCreateProcessStateChange */
    CHECK(c.saw_bp);
    CHECK(c.bp_conv_ok);
    CHECK(c.conv_ok);
    CHECK(c.pid_ok);
    EXPECT_EQ(c.stop, 0);
    EXPECT_EQ(c.stop2, (NTS)0xC0000353);
    CHECK(c.saw_thread);
    reap(h, pi.hThread);
}
