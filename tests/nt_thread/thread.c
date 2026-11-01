/* Native thread services: creation, suspend/resume, termination, information classes
 * and thread context. Every thread created here is waited for or terminated and closed
 * by the test that created it. */
#include "t.h"

UDECL(NTSTATUS, NtCreateThreadEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID));
UDECL(NTSTATUS, RtlCreateUserThread, (HANDLE, PVOID, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID));
UDECL(VOID, RtlExitUserThread, (NTSTATUS));
UDECL(NTSTATUS, NtSuspendThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtTerminateThread, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtGetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtSetContextThread, (HANDLE, PCONTEXT));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtYieldExecution, (VOID));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlSetThreadIsCritical, (BOOLEAN, PBOOLEAN, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define INVALID_HANDLE_ST S(0xc0000008)
#define TYPE_MISMATCH S(0xc0000024)
#define BAD_CLASS S(0xc0000003)
#define BAD_LENGTH S(0xc0000004)
#define BAD_PARAM S(0xc000000d)
#define THREAD_ALL 0x1fffff
#define CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)

enum { TI_BASIC = 0, TI_TIMES = 1, TI_PRIORITY_BOOST = 14, TI_IS_TERMINATED = 20, TI_AFFINITY = 4,
       TI_SUSPEND_COUNT = 35, TI_NAME = 38 };

typedef struct { NTSTATUS exit; PVOID teb; CLIENT_ID id; ULONG_PTR affinity; LONG priority; LONG base; } th_basic;
typedef struct { LARGE_INTEGER create, exit, kernel, user; } th_times;

typedef struct {
    volatile LONG started;
    volatile PVOID teb;
    volatile DWORD tid;
    HANDLE gate;       /* manual-reset event the thread waits on, or NULL */
    ULONG result;      /* value returned from the thread routine */
    int use_exit;      /* leave through RtlExitUserThread instead */
} worker_t;

static ULONG NTAPI worker(PVOID p)
{
    worker_t *w = p;
    w->teb = NtCurrentTeb();
    w->tid = GetCurrentThreadId();
    InterlockedIncrement(&w->started);
    if (w->gate) WaitForSingleObject(w->gate, 20000);
    if (w->use_exit) { UN(RtlExitUserThread)(S(w->result)); return 0xdead; }
    return w->result;
}

static LARGE_INTEGER rel_ms(LONG ms) { LARGE_INTEGER t; t.QuadPart = -(LONGLONG)ms * 10000; return t; }
static NTSTATUS wait_thread(HANDLE h, LONG ms) { LARGE_INTEGER t = rel_ms(ms); return UN(NtWaitForSingleObject)(h, FALSE, &t); }

static HANDLE make(worker_t *w, ULONG flags)
{
    HANDLE h = NULL;
    NTSTATUS s = UN(NtCreateThreadEx)(&h, THREAD_ALL, NULL, CURRENT_PROCESS, (PVOID)worker, w, flags, 0, 0, 0, NULL);
    EXPECT_EQ(s, 0);
    if (s < 0) return NULL;
    return h;
}
static void finish(HANDLE h, worker_t *w)
{
    if (!h) return;
    if (w && w->gate) SetEvent(w->gate);
    if (wait_thread(h, 10000) != 0) UN(NtTerminateThread)(h, 0);
    UN(NtClose)(h);
}
static HANDLE new_gate(void) { return CreateEventA(NULL, TRUE, FALSE, NULL); }
static void wait_started(worker_t *w) { for (int i = 0; i < 500 && !w->started; i++) Sleep(10); }

#define THREAD_EXPORTS \
    do { if (!UN(NtCreateThreadEx) || !UN(NtWaitForSingleObject) || !UN(NtClose) || !UN(NtQueryInformationThread) || \
             !UN(NtSuspendThread) || !UN(NtResumeThread) || !UN(NtTerminateThread)) { t_skip("thread exports missing"); return; } } while (0)

TEST(nt_thread_create_runs_and_exit_status)
{
    worker_t w = {0};
    HANDLE h;
    th_basic b;
    THREAD_EXPORTS;
    w.result = 0x1234;
    h = make(&w, 0);
    if (!h) return;
    EXPECT_EQ(wait_thread(h, 10000), 0);
    EXPECT_EQ(w.started, 1);
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x1234);
    UN(NtClose)(h);
}

TEST(nt_thread_create_suspended_defers_start)
{
    worker_t w = {0};
    ULONG prev = 99;
    HANDLE h;
    THREAD_EXPORTS;
    h = make(&w, 1 /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED */);
    if (!h) return;
    Sleep(100);
    EXPECT_EQ(w.started, 0);
    EXPECT_EQ(UN(NtResumeThread)(h, &prev), 0);
    EXPECT_EQ(prev, 1);
    EXPECT_EQ(wait_thread(h, 10000), 0);
    EXPECT_EQ(w.started, 1);
    UN(NtClose)(h);
}

TEST(nt_thread_create_running_reports_pending_exit)
{
    worker_t w = {0};
    th_basic b;
    HANDLE h;
    THREAD_EXPORTS;
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x103); /* STATUS_PENDING / STILL_ACTIVE while running */
    EXPECT_EQ((ULONG_PTR)b.id.UniqueProcess, GetCurrentProcessId());
    EXPECT_EQ((ULONG_PTR)b.id.UniqueThread, w.tid);
    EXPECT_EQ(b.teb, w.teb);
    CHECK(w.teb != (PVOID)NtCurrentTeb());
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_create_invalid_process_handle)
{
    worker_t w = {0};
    HANDLE h = (HANDLE)0x1234, ev;
    NTSTATUS s;
    THREAD_EXPORTS;
    s = UN(NtCreateThreadEx)(&h, THREAD_ALL, NULL, NULL, (PVOID)worker, &w, 0, 0, 0, 0, NULL);
    EXPECT_EQ(s, INVALID_HANDLE_ST);
    EXPECT_EQ(w.started, 0);
    /* A handle of the wrong object type is rejected as a type mismatch. */
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    s = UN(NtCreateThreadEx)(&h, THREAD_ALL, NULL, ev, (PVOID)worker, &w, 0, 0, 0, 0, NULL);
    EXPECT_EQ(s, TYPE_MISMATCH);
    CloseHandle(ev);
}

TEST(nt_thread_suspend_resume_counts)
{
    worker_t w = {0};
    ULONG p = 99, c = 99;
    HANDLE h;
    THREAD_EXPORTS;
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    for (ULONG i = 0; i < 3; i++) { p = 99; EXPECT_EQ(UN(NtSuspendThread)(h, &p), 0); EXPECT_EQ(p, i); }
    if (UN(NtQueryInformationThread)(h, TI_SUSPEND_COUNT, &c, sizeof c, NULL) == 0) EXPECT_EQ(c, 3);
    else t_note("ThreadSuspendCount class not available");
    for (ULONG i = 3; i > 0; i--) { p = 99; EXPECT_EQ(UN(NtResumeThread)(h, &p), 0); EXPECT_EQ(p, i); }
    p = 99;
    EXPECT_EQ(UN(NtResumeThread)(h, &p), 0); /* resuming a thread that is not suspended is not an error */
    EXPECT_EQ(p, 0);
    EXPECT_EQ(UN(NtSuspendThread)(h, NULL), 0); /* previous count is optional */
    EXPECT_EQ(UN(NtResumeThread)(h, NULL), 0);
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_suspend_count_limit)
{
    worker_t w = {0};
    ULONG p = 0;
    int ok = 0;
    NTSTATUS s;
    HANDLE h;
    THREAD_EXPORTS;
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    for (int i = 0; i < 127; i++) if (UN(NtSuspendThread)(h, &p) == 0) ok++;
    EXPECT_EQ(ok, 127); /* MAXIMUM_SUSPEND_COUNT */
    s = UN(NtSuspendThread)(h, &p);
    EXPECT_EQ(s, S(0xc000004a)); /* STATUS_SUSPEND_COUNT_EXCEEDED */
    for (int i = 0; i < ok; i++) UN(NtResumeThread)(h, NULL);
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_terminate_sets_exit_status)
{
    worker_t w = {0};
    th_basic b;
    ULONG term = 99;
    HANDLE h;
    THREAD_EXPORTS;
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    if (UN(NtQueryInformationThread)(h, TI_IS_TERMINATED, &term, sizeof term, NULL) == 0) EXPECT_EQ(term, 0);
    EXPECT_EQ(UN(NtTerminateThread)(h, S(0x4242)), 0);
    EXPECT_EQ(wait_thread(h, 10000), 0);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x4242);
    if (UN(NtQueryInformationThread)(h, TI_IS_TERMINATED, &term, sizeof term, NULL) == 0) EXPECT_EQ(term, 1);
    /* Terminating a thread that has already exited succeeds and leaves the exit status unchanged. */
    EXPECT_EQ(UN(NtTerminateThread)(h, 0), 0);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x4242);
    UN(NtClose)(h);
    CloseHandle(w.gate);
}

TEST(nt_thread_terminate_suspended_unstarted)
{
    worker_t w = {0};
    th_basic b;
    HANDLE h;
    THREAD_EXPORTS;
    h = make(&w, 1);
    if (!h) return;
    EXPECT_EQ(UN(NtTerminateThread)(h, S(0x5151)), 0);
    EXPECT_EQ(wait_thread(h, 10000), 0);
    EXPECT_EQ(w.started, 0);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x5151);
    UN(NtClose)(h);
}

TEST(nt_thread_invalid_handles)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL), closed;
    ULONG v = 0;
    THREAD_EXPORTS;
    closed = ev;
    CloseHandle(ev);
    EXPECT_EQ(UN(NtTerminateThread)(closed, 0), INVALID_HANDLE_ST);
    EXPECT_EQ(UN(NtSuspendThread)(closed, &v), INVALID_HANDLE_ST);
    EXPECT_EQ(UN(NtResumeThread)(closed, &v), INVALID_HANDLE_ST);
    { th_basic tb; EXPECT_EQ(UN(NtQueryInformationThread)(closed, TI_BASIC, &tb, sizeof tb, NULL), INVALID_HANDLE_ST); }
    /* A process pseudo-handle is not a thread. */
    EXPECT_EQ(UN(NtSuspendThread)(CURRENT_PROCESS, &v), TYPE_MISMATCH);
    EXPECT_EQ(UN(NtResumeThread)(CURRENT_PROCESS, &v), TYPE_MISMATCH);
    { th_basic tb; EXPECT_EQ(UN(NtQueryInformationThread)(CURRENT_PROCESS, TI_BASIC, &tb, sizeof tb, NULL), TYPE_MISMATCH); }
}

TEST(nt_thread_times_class)
{
    worker_t w = {0};
    th_times t;
    HANDLE h;
    THREAD_EXPORTS;
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    memset(&t, 0, sizeof t);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_TIMES, &t, sizeof t, NULL), 0);
    CHECK(t.create.QuadPart > 0);
    EXPECT_EQ(t.exit.QuadPart, 0);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_TIMES, &t, sizeof t - 1, NULL), BAD_LENGTH);
    SetEvent(w.gate);
    EXPECT_EQ(wait_thread(h, 10000), 0);
    memset(&t, 0, sizeof t);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_TIMES, &t, sizeof t, NULL), 0);
    CHECK(t.exit.QuadPart >= t.create.QuadPart);
    CHECK(t.exit.QuadPart > 0);
    UN(NtClose)(h);
    CloseHandle(w.gate);
}

TEST(nt_thread_priority_boost_roundtrip)
{
    worker_t w = {0};
    ULONG v = 0;
    HANDLE h;
    THREAD_EXPORTS;
    if (!UN(NtSetInformationThread)) { t_skip("NtSetInformationThread missing"); return; }
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    v = 1;
    EXPECT_EQ(UN(NtSetInformationThread)(h, TI_PRIORITY_BOOST, &v, sizeof v), 0);
    v = 99;
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_PRIORITY_BOOST, &v, sizeof v, NULL), 0);
    EXPECT_EQ(v, 1);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationThread)(h, TI_PRIORITY_BOOST, &v, sizeof v), 0);
    v = 99;
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_PRIORITY_BOOST, &v, sizeof v, NULL), 0);
    EXPECT_EQ(v, 0);
    EXPECT_EQ(UN(NtSetInformationThread)(h, TI_PRIORITY_BOOST, &v, 1), BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationThread)(h, 0x7fff, &v, sizeof v), BAD_CLASS);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, 0x7fff, &v, sizeof v, NULL), BAD_CLASS);
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_affinity_zero_rejected)
{
    worker_t w = {0};
    ULONG_PTR mask = 0;
    HANDLE h;
    THREAD_EXPORTS;
    if (!UN(NtSetInformationThread)) { t_skip("NtSetInformationThread missing"); return; }
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    EXPECT_EQ(UN(NtSetInformationThread)(h, TI_AFFINITY, &mask, sizeof mask), BAD_PARAM);
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_name_roundtrip)
{
    worker_t w = {0};
    static const WCHAR name[] = L"corpus-thread-name";
    UNICODE_STRING u;
    union { UNICODE_STRING us; BYTE raw[256]; } out;
    ULONG ret = 0;
    NTSTATUS s;
    HANDLE h;
    THREAD_EXPORTS;
    if (!UN(NtSetInformationThread)) { t_skip("NtSetInformationThread missing"); return; }
    w.gate = new_gate();
    h = make(&w, 0);
    if (!h) { CloseHandle(w.gate); return; }
    wait_started(&w);
    u.Buffer = (PWSTR)name; u.Length = sizeof name - sizeof(WCHAR); u.MaximumLength = sizeof name;
    s = UN(NtSetInformationThread)(h, TI_NAME, &u, sizeof u);
    if (s == BAD_CLASS) { t_note("ThreadNameInformation not available"); }
    else {
        EXPECT_EQ(s, 0);
        memset(&out, 0, sizeof out);
        s = UN(NtQueryInformationThread)(h, TI_NAME, &out, sizeof out, &ret);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(out.us.Length, u.Length);
        CHECK(out.us.Buffer && !memcmp(out.us.Buffer, name, u.Length));
        CHECK(ret >= sizeof(UNICODE_STRING) + u.Length);
        /* Header-only buffer cannot hold the string. */
        s = UN(NtQueryInformationThread)(h, TI_NAME, &out, sizeof(UNICODE_STRING), &ret);
        EXPECT_EQ(s, S(0xC0000023));   /* variable-length class: buffer too small, the required size is returned */
        t_note("short-buffer name query status=%08lx return=%lu", (ULONG)s, ret);
    }
    finish(h, &w);
    CloseHandle(w.gate);
}

TEST(nt_thread_initial_context)
{
    worker_t w = {0}, w2 = {0};
    CONTEXT c;
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE h;
    THREAD_EXPORTS;
    if (!UN(NtGetContextThread) || !UN(NtSetContextThread)) { t_skip("context exports missing"); return; }
    h = make(&w, 1);
    if (!h) return;
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    EXPECT_EQ(UN(NtGetContextThread)(h, &c), 0);
    CHECK(c.Rip != 0);
    CHECK(c.Rsp != 0);
    memset(&mbi, 0, sizeof mbi);
    if (VirtualQuery((PVOID)c.Rip, &mbi, sizeof mbi))
        EXPECT_EQ(mbi.AllocationBase, GetModuleHandleA("ntdll.dll")); /* new threads start inside ntdll */
    t_note("initial Rcx=%p (routine %p) Rdx=%p (argument %p)", (PVOID)c.Rcx, (PVOID)worker, (PVOID)c.Rdx, (PVOID)&w);
    /* Redirect the argument register before the thread runs. */
    c.Rdx = (DWORD64)(ULONG_PTR)&w2;
    EXPECT_EQ(UN(NtSetContextThread)(h, &c), 0);
    {
        CONTEXT back;
        memset(&back, 0, sizeof back);
        back.ContextFlags = CONTEXT_INTEGER;
        EXPECT_EQ(UN(NtGetContextThread)(h, &back), 0);
        EXPECT_EQ(back.Rdx, (DWORD64)(ULONG_PTR)&w2);
    }
    EXPECT_EQ(UN(NtResumeThread)(h, NULL), 0);
    EXPECT_EQ(wait_thread(h, 10000), 0);
    t_note("argument redirect: original=%ld replacement=%ld", w.started, w2.started);
    UN(NtClose)(h);
}

TEST(nt_thread_context_invalid_handle)
{
    CONTEXT c;
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    THREAD_EXPORTS;
    if (!UN(NtGetContextThread)) { t_skip("NtGetContextThread missing"); CloseHandle(ev); return; }
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_CONTROL;
    EXPECT_EQ(UN(NtGetContextThread)(ev, &c), TYPE_MISMATCH);
    CloseHandle(ev);
    EXPECT_EQ(UN(NtGetContextThread)(ev, &c), INVALID_HANDLE_ST);
}

static void create_user_thread(BOOLEAN suspended, BOOLEAN via_exit)
{
    worker_t w = {0};
    CLIENT_ID id;
    th_basic b;
    HANDLE h = NULL;
    NTSTATUS s;
    THREAD_EXPORTS;
    if (!UN(RtlCreateUserThread) || (via_exit && !UN(RtlExitUserThread))) { t_skip("RtlCreateUserThread exports missing"); return; }
    w.result = 0x7777;
    w.use_exit = via_exit;
    memset(&id, 0, sizeof id);
    s = UN(RtlCreateUserThread)(CURRENT_PROCESS, NULL, suspended, 0, 0, 0, (PVOID)worker, &w, &h, &id);
    EXPECT_EQ(s, 0);
    if (s < 0) return;
    CHECK(h != NULL);
    EXPECT_EQ((ULONG_PTR)id.UniqueProcess, GetCurrentProcessId());
    CHECK(id.UniqueThread != NULL);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.id.UniqueThread, id.UniqueThread);
    if (suspended) {
        Sleep(50);
        EXPECT_EQ(w.started, 0);
        EXPECT_EQ(UN(NtResumeThread)(h, NULL), 0);
    }
    EXPECT_EQ(wait_thread(h, 10000), 0);
    EXPECT_EQ(w.started, 1);
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)(h, TI_BASIC, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.exit, 0x7777);
    UN(NtClose)(h);
}
TEST(nt_thread_user_thread_running) { create_user_thread(FALSE, FALSE); }
TEST(nt_thread_user_thread_suspended) { create_user_thread(TRUE, FALSE); }
TEST(nt_thread_user_thread_exit_routine) { create_user_thread(FALSE, TRUE); }

TEST(nt_thread_yield_status)
{
    NTSTATUS s;
    REQUIRE(UN(NtYieldExecution));
    s = UN(NtYieldExecution)();
    CHECK(s == 0 || s == S(0x40000024)); /* STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED */
}

TEST(nt_thread_critical_flag_clear)
{
    BOOLEAN old = 0xff;
    NTSTATUS s;
    ULONG v = 99;
    REQUIRE(UN(RtlSetThreadIsCritical));
    s = UN(RtlSetThreadIsCritical)(FALSE, &old, FALSE);
    EXPECT_EQ(s, 0);
    if (s == 0) EXPECT_EQ(old, 0);
    s = UN(RtlSetThreadIsCritical)(FALSE, NULL, FALSE); /* previous value is optional */
    EXPECT_EQ(s, 0);
    if (UN(NtQueryInformationThread) && UN(NtQueryInformationThread)((HANDLE)(LONG_PTR)-2, 18 /* ThreadBreakOnTermination */, &v, sizeof v, NULL) == 0)
        EXPECT_EQ(v, 0);
}
