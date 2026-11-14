/* Alerts, delays, event clearing, identifier allocation, reserve objects, object comparison,
 * job assignment, timers (Timer2), context continuation and unusual callback returns. */
#include "t.h"

UDECL(NTSTATUS, NtAlertThread, (HANDLE));
UDECL(NTSTATUS, NtAlertResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtAlertThreadByThreadId, (ULONG_PTR));
UDECL(NTSTATUS, NtWaitForAlertByThreadId, (PVOID, PLARGE_INTEGER));
UDECL(NTSTATUS, NtDelayExecution, (BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtClearEvent, (HANDLE));
UDECL(NTSTATUS, NtAllocateLocallyUniqueId, (PLUID));
UDECL(NTSTATUS, NtAllocateUuids, (PULARGE_INTEGER, PULONG, PULONG, PCHAR));
UDECL(NTSTATUS, NtAllocateReserveObject, (PHANDLE, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCompareObjects, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtCompareSigningLevels, (ULONG, ULONG));
UDECL(NTSTATUS, NtAssignProcessToJobObject, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtCreateTimer2, (PHANDLE, PVOID, POBJECT_ATTRIBUTES, ULONG, ACCESS_MASK));
UDECL(NTSTATUS, NtCancelTimer2, (HANDLE, PVOID));
UDECL(NTSTATUS, NtCallbackReturn, (PVOID, ULONG, NTSTATUS));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCancelIoFileEx, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCancelSynchronousIoFile, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_ALERTED     S(0x101)
#define ST_TIMEOUT     S(0x102)
#define ST_USER_APC    S(0xC0)
#define ST_INVHANDLE   S(0xC0000008)
#define ST_TYPEMISM    S(0xC0000024)
#define ST_DENIED      S(0xC0000022)
#define ST_INVPARAM    S(0xC000000D)
#define ST_AV          S(0xC0000005)
#define ST_NOT_SAME    S(0xC00001AC)  /* STATUS_NOT_SAME_OBJECT */
#define THR_CUR        ((HANDLE)(LONG_PTR)-2)
#define PRC_CUR        ((HANDLE)(LONG_PTR)-1)

static LARGE_INTEGER rel_ms(LONGLONG ms) { LARGE_INTEGER l; l.QuadPart = -ms * 10000; return l; }

TEST(misc_aliases)
{
    static const char *n[] = { "AlertThread", "AlertResumeThread", "AlertThreadByThreadId", "AllocateLocallyUniqueId", "AllocateUuids",
        "AllocateReserveObject", "ClearEvent", "CompareObjects", "CompareSigningLevels", "DelayExecution", "AssignProcessToJobObject",
        "CancelTimer2", "CallbackReturn" };
    char a[64], b[64];
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "alias %s", a);
    }
}

/* ---- NtDelayExecution --------------------------------------------------- */
static void CALLBACK apc_nop(ULONG_PTR p) { (*(volatile LONG *)p)++; }

TEST(delay_execution)
{
    LARGE_INTEGER d; DWORD t0, dt; NTSTATUS s; volatile LONG ran = 0;
    REQUIRE(UN(NtDelayExecution)); REQUIRE(UN(NtAlertThread));
    d.QuadPart = 0;
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &d), 0);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), 0);
    d = rel_ms(60);
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &d), 0);
    dt = GetTickCount() - t0;
    CHECKF(dt >= 45 && dt < 2000, "elapsed %lu ms", dt);
    /* absolute time in the past returns at once */
    d.QuadPart = 1;
    t0 = GetTickCount();
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &d), 0);
    CHECK(GetTickCount() - t0 < 1000);
    /* queued user APC interrupts an alertable delay with STATUS_USER_APC and runs first */
    CHECK(QueueUserAPC(apc_nop, GetCurrentThread(), (ULONG_PTR)&ran));
    d = rel_ms(20000);
    t0 = GetTickCount();
    s = UN(NtDelayExecution)(TRUE, &d);
    EXPECT_EQ(s, ST_USER_APC); EXPECT_EQ(ran, 1);
    CHECK(GetTickCount() - t0 < 10000);
    /* a non-alertable delay does not consume a pending APC */
    CHECK(QueueUserAPC(apc_nop, GetCurrentThread(), (ULONG_PTR)&ran));
    d = rel_ms(20);
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &d), 0);
    EXPECT_EQ(ran, 1);
    d = rel_ms(20000);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), ST_USER_APC);
    EXPECT_EQ(ran, 2);
    /* pending alert: alertable delay returns STATUS_ALERTED immediately, once */
    EXPECT_EQ(UN(NtAlertThread)(THR_CUR), 0);
    d = rel_ms(10);
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, &d), 0);          /* not alertable: alert stays pending */
    t0 = GetTickCount();
    d = rel_ms(20000);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), ST_ALERTED);
    CHECK(GetTickCount() - t0 < 10000);
    d = rel_ms(20);
    EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), 0);                          /* consumed */
    /* NULL interval means infinite for the kernel; only the pointer check is asserted via a bad pointer */
    EXPECT_EQ(UN(NtDelayExecution)(FALSE, (PLARGE_INTEGER)(ULONG_PTR)8), ST_AV);
}

/* ---- alerts -------------------------------------------------------------- */
typedef struct { volatile LONG started; NTSTATUS st; DWORD ms; } alert_ctx;

static DWORD WINAPI alert_waiter(LPVOID p)
{
    alert_ctx *c = p; LARGE_INTEGER d = rel_ms(30000); DWORD t0 = GetTickCount();
    InterlockedExchange(&c->started, 1);
    c->st = UN(NtDelayExecution)(TRUE, &d);
    c->ms = GetTickCount() - t0;
    return 0;
}

TEST(alert_thread)
{
    alert_ctx c = {0}; HANDLE th, noalert; NTSTATUS s;
    REQUIRE(UN(NtAlertThread));
    th = CreateThread(NULL, 0, alert_waiter, &c, 0, NULL); CHECK(th != NULL); if (!th) return;
    for (int i = 0; i < 500 && !c.started; i++) Sleep(10);
    Sleep(50);
    EXPECT_EQ(UN(NtAlertThread)(th), 0);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(c.st, ST_ALERTED);
    CHECK(c.ms < 20000);
    /* a terminated thread whose handle is still open accepts the alert (observed) */
    s = UN(NtAlertThread)(th);
    EXPECT_EQ(s, 0);
    CloseHandle(th);
    /* error paths */
    EXPECT_EQ(UN(NtAlertThread)(NULL), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAlertThread)((HANDLE)(ULONG_PTR)0xdeadbee0), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAlertThread)(PRC_CUR), ST_TYPEMISM);
    /* handle without THREAD_ALERT */
    noalert = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    if (noalert) {
        EXPECT_EQ(UN(NtAlertThread)(noalert), ST_DENIED);
        CloseHandle(noalert);
    }
    /* pending self alert is consumed by an alertable delay; clear nothing is left behind */
    EXPECT_EQ(UN(NtAlertThread)(THR_CUR), 0);
    { LARGE_INTEGER d = rel_ms(10000); EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), ST_ALERTED); }
}

typedef struct { NTSTATUS st; DWORD ms; volatile LONG started; } resume_ctx;
static DWORD WINAPI resume_main(LPVOID p)
{
    resume_ctx *c = p; LARGE_INTEGER d = rel_ms(30000); DWORD t0 = GetTickCount();
    InterlockedExchange(&c->started, 1);
    c->st = UN(NtDelayExecution)(TRUE, &d);
    c->ms = GetTickCount() - t0;
    return 0;
}

TEST(alert_resume_thread)
{
    resume_ctx c = {0}; HANDLE th; ULONG prev = 0xcccccccc; NTSTATUS s;
    REQUIRE(UN(NtAlertResumeThread));
    th = CreateThread(NULL, 0, resume_main, &c, 0, NULL); CHECK(th != NULL); if (!th) return;
    for (int i = 0; i < 500 && !c.started; i++) Sleep(10);
    Sleep(100);                                 /* let the worker block in its alertable delay */
    CHECK(SuspendThread(th) == 0);
    /* suspended once: previous suspend count is 1; the alert wakes the delay and the thread resumes */
    s = UN(NtAlertResumeThread)(th, &prev);
    EXPECT_EQ(s, 0); EXPECT_EQ(prev, 1);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(c.st, ST_ALERTED);
    CloseHandle(th);
    /* optional output pointer and a thread that is not suspended (suspend count 0) */
    th = CreateThread(NULL, 0, resume_main, &(resume_ctx){0}, CREATE_SUSPENDED, NULL);
    if (th) {
        SuspendThread(th);                         /* count 2 */
        prev = 0xcccccccc;
        EXPECT_EQ(UN(NtAlertResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 2);
        EXPECT_EQ(UN(NtAlertResumeThread)(th, NULL), 0);    /* count 1 -> 0, NULL out is allowed */
        WaitForSingleObject(th, 10000);
        CloseHandle(th);
    }
    EXPECT_EQ(UN(NtAlertResumeThread)(NULL, &prev), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAlertResumeThread)(PRC_CUR, &prev), ST_TYPEMISM);
    prev = 0xcccccccc;
    EXPECT_EQ(UN(NtAlertResumeThread)(THR_CUR, &prev), 0); EXPECT_EQ(prev, 0);   /* self: not suspended */
    { LARGE_INTEGER d = rel_ms(10000); EXPECT_EQ(UN(NtDelayExecution)(TRUE, &d), ST_ALERTED); }
}

/* ---- by-thread-id alert ---------------------------------------------------- */
typedef struct { volatile LONG started; ULONG tid; NTSTATUS st; DWORD ms; LONG mode; } byid_ctx;
static DWORD WINAPI byid_main(LPVOID p)
{
    byid_ctx *c = p; LARGE_INTEGER d = rel_ms(c->mode ? 150 : 20000); DWORD t0 = GetTickCount();
    c->tid = GetCurrentThreadId();
    InterlockedExchange(&c->started, 1);
    c->st = UN(NtWaitForAlertByThreadId)((PVOID)&c->started, &d);
    c->ms = GetTickCount() - t0;
    return 0;
}

TEST(alert_thread_by_thread_id)
{
    byid_ctx c = {0}; HANDLE th; NTSTATUS s;
    REQUIRE(UN(NtAlertThreadByThreadId)); REQUIRE(UN(NtWaitForAlertByThreadId));
    th = CreateThread(NULL, 0, byid_main, &c, 0, NULL); CHECK(th != NULL); if (!th) return;
    for (int i = 0; i < 500 && !c.started; i++) Sleep(10);
    Sleep(50);
    s = UN(NtAlertThreadByThreadId)(c.tid);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(c.st, ST_ALERTED);   /* the wait ends with STATUS_ALERTED when alerted by thread id */
    CHECK(c.ms < 15000);
    CloseHandle(th);
    /* nobody alerts: the wait times out */
    memset(&c, 0, sizeof c); c.mode = 1;
    th = CreateThread(NULL, 0, byid_main, &c, 0, NULL);
    if (th) { WaitForSingleObject(th, 10000); EXPECT_EQ(c.st, ST_TIMEOUT); CHECK(c.ms >= 100); CloseHandle(th); }
    /* an alert delivered before the wait is remembered once */
    EXPECT_EQ(UN(NtAlertThreadByThreadId)(GetCurrentThreadId()), 0);
    { LARGE_INTEGER d = rel_ms(10000); DWORD t0 = GetTickCount();
      EXPECT_EQ(UN(NtWaitForAlertByThreadId)(&d, &d), ST_ALERTED); CHECK(GetTickCount() - t0 < 5000);
      d = rel_ms(30);
      EXPECT_EQ(UN(NtWaitForAlertByThreadId)(&d, &d), ST_TIMEOUT); }
    /* thread ids that cannot exist (ids are multiples of 4) */
    EXPECT_EQ(UN(NtAlertThreadByThreadId)(0xFFFFFFF1), S(0xC000000B));   /* STATUS_INVALID_CID */
}

/* ---- NtClearEvent ---------------------------------------------------------- */
TEST(clear_event)
{
    HANDLE ev, ro; NTSTATUS s;
    REQUIRE(UN(NtClearEvent));
    ev = CreateEventW(NULL, TRUE, TRUE, NULL); CHECK(ev != NULL); if (!ev) return;
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    s = UN(NtClearEvent)(ev);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    s = UN(NtClearEvent)(ev);                 /* already clear: still success */
    EXPECT_EQ(s, 0);
    SetEvent(ev);
    EXPECT_EQ(UN(NtClearEvent)(ev), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    /* auto-reset event too */
    CloseHandle(ev);
    ev = CreateEventW(NULL, FALSE, TRUE, NULL);
    EXPECT_EQ(UN(NtClearEvent)(ev), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
    CloseHandle(ev);
    /* handle that lacks EVENT_MODIFY_STATE */
    ev = CreateEventW(NULL, TRUE, TRUE, L"nt1a_clearevent");
    if (ev) {
        ro = OpenEventW(SYNCHRONIZE, FALSE, L"nt1a_clearevent");
        if (ro) { EXPECT_EQ(UN(NtClearEvent)(ro), ST_DENIED); EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0); CloseHandle(ro); }
        CloseHandle(ev);
    }
    EXPECT_EQ(UN(NtClearEvent)(NULL), ST_INVHANDLE);
    EXPECT_EQ(UN(NtClearEvent)((HANDLE)(ULONG_PTR)0xdeadbee0), ST_INVHANDLE);
    EXPECT_EQ(UN(NtClearEvent)(PRC_CUR), ST_TYPEMISM);
    EXPECT_EQ(UN(NtClearEvent)(THR_CUR), ST_TYPEMISM);
}

/* ---- identifier allocation --------------------------------------------------- */
TEST(allocate_luid)
{
    LUID a = {0}, b = {0}; ULONGLONG x, y; NTSTATUS s;
    REQUIRE(UN(NtAllocateLocallyUniqueId));
    s = UN(NtAllocateLocallyUniqueId)(&a); EXPECT_EQ(s, 0);
    s = UN(NtAllocateLocallyUniqueId)(&b); EXPECT_EQ(s, 0);
    x = ((ULONGLONG)a.HighPart << 32) | a.LowPart; y = ((ULONGLONG)b.HighPart << 32) | b.LowPart;
    CHECK(x != 0 && y > x);                     /* strictly increasing */
    CHECK(x > 1000);                            /* ids below 1000 are reserved for well-known privileges */
    EXPECT_EQ(UN(NtAllocateLocallyUniqueId)(NULL), ST_AV);
    EXPECT_EQ(UN(NtAllocateLocallyUniqueId)((PLUID)(ULONG_PTR)8), ST_AV);
    { LUID c; BOOL ok = AllocateLocallyUniqueId(&c);          /* Win32 wrapper draws from the same sequence */
      CHECK(ok); if (ok) CHECK((((ULONGLONG)c.HighPart << 32) | c.LowPart) > y); }
}

TEST(allocate_uuids)
{
    ULARGE_INTEGER t1 = {0}, t2 = {0}; ULONG r1 = 0, r2 = 0, q1 = 0, q2 = 0; CHAR sd1[6] = {0}, sd2[6] = {0}; NTSTATUS s;
    REQUIRE(UN(NtAllocateUuids));
    s = UN(NtAllocateUuids)(&t1, &r1, &q1, sd1); EXPECT_EQ(s, 0);
    s = UN(NtAllocateUuids)(&t2, &r2, &q2, sd2); EXPECT_EQ(s, 0);
    CHECK(t1.QuadPart != 0);
    CHECK(t2.QuadPart >= t1.QuadPart);          /* UUID time is monotonic across calls */
    CHECK(r1 != 0 && r2 != 0);
    EXPECT_EQ(q1, q2);                          /* the clock sequence stays unchanged between calls */
    EXPECT_EQ(memcmp(sd1, sd2, 6), 0);          /* node seed is stable */
    EXPECT_EQ(UN(NtAllocateUuids)(NULL, &r1, &q1, sd1), ST_AV);
    EXPECT_EQ(UN(NtAllocateUuids)(&t1, NULL, &q1, sd1), ST_AV);
    EXPECT_EQ(UN(NtAllocateUuids)(&t1, &r1, NULL, sd1), ST_AV);
    EXPECT_EQ(UN(NtAllocateUuids)(&t1, &r1, &q1, NULL), ST_AV);
}

/* ---- reserve objects ------------------------------------------------------------ */
static void type_name(HANDLE h, char *out, size_t cap)
{
    union { ULONGLONG a; BYTE b[512]; } buf; ULONG ret = 0; UNICODE_STRING *u = (UNICODE_STRING *)buf.b;
    out[0] = 0;
    if (UN(NtQueryObject)(h, 2, buf.b, sizeof buf, &ret) >= 0)
        snprintf(out, cap, "%.*ls", (int)(u->Length / 2), u->Buffer);
}

TEST(allocate_reserve_object)
{
    HANDLE h = NULL; NTSTATUS s; char nm[64];
    REQUIRE(UN(NtAllocateReserveObject)); REQUIRE(UN(NtQueryObject)); REQUIRE(UN(NtClose));
    s = UN(NtAllocateReserveObject)(&h, NULL, 0);          /* MemoryReserveTypeUserApc */
    EXPECT_EQ(s, 0); CHECK(h != NULL);
    if (h) { type_name(h, nm, sizeof nm); EXPECT_STR(nm, "UserApcReserve"); EXPECT_EQ(UN(NtClose)(h), 0); }
    h = NULL;
    s = UN(NtAllocateReserveObject)(&h, NULL, 1);          /* MemoryReserveTypeIoCompletion */
    EXPECT_EQ(s, 0); CHECK(h != NULL);
    if (h) { type_name(h, nm, sizeof nm); EXPECT_STR(nm, "IoCompletionReserve"); EXPECT_EQ(UN(NtClose)(h), 0); }
    h = (HANDLE)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(NtAllocateReserveObject)(&h, NULL, 2), ST_INVPARAM);
    EXPECT_EQ(UN(NtAllocateReserveObject)(&h, NULL, 0xFFFFFFFF), ST_INVPARAM);
    EXPECT_EQ(UN(NtAllocateReserveObject)(NULL, NULL, 0), ST_AV);
    /* named reserve object */
    { UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[64]; HANDLE h2 = NULL;
      swprintf(name, 64, L"nt1a_reserve_%lu", GetCurrentProcessId());
      u.Buffer = name; u.Length = u.MaximumLength = (USHORT)(lstrlenW(name) * 2);
      InitializeObjectAttributes(&oa, &u, 0, NULL, NULL);
      /* named objects must live in a directory the caller can write; a relative name has no root directory */
      s = UN(NtAllocateReserveObject)(&h2, &oa, 0);
      EXPECT_EQ(s, S(0xC0000033));      /* STATUS_OBJECT_NAME_INVALID: no root directory for a relative name */
      if (s >= 0 && h2) UN(NtClose)(h2); }
}

/* ---- NtCompareObjects ------------------------------------------------------------ */
TEST(compare_objects)
{
    HANDLE e1, e2, d1 = NULL; NTSTATUS s;
    if (!UN(NtCompareObjects)) { t_skip("NtCompareObjects not exported"); return; }
    e1 = CreateEventW(NULL, TRUE, FALSE, NULL); e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(e1 && e2); if (!e1 || !e2) return;
    EXPECT_EQ(UN(NtCompareObjects)(e1, e1), 0);
    CHECK(DuplicateHandle(GetCurrentProcess(), e1, GetCurrentProcess(), &d1, 0, FALSE, DUPLICATE_SAME_ACCESS));
    EXPECT_EQ(UN(NtCompareObjects)(e1, d1), 0);
    EXPECT_EQ(UN(NtCompareObjects)(d1, e1), 0);
    s = UN(NtCompareObjects)(e1, e2);
    EXPECT_EQ(s, ST_NOT_SAME);
    /* different types are also "not the same" */
    EXPECT_EQ(UN(NtCompareObjects)(e1, GetCurrentProcess()), ST_NOT_SAME);
    EXPECT_EQ(UN(NtCompareObjects)(GetCurrentProcess(), GetCurrentProcess()), 0);
    EXPECT_EQ(UN(NtCompareObjects)(GetCurrentProcess(), GetCurrentThread()), ST_NOT_SAME);
    EXPECT_EQ(UN(NtCompareObjects)(NULL, e1), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCompareObjects)(e1, NULL), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCompareObjects)((HANDLE)(ULONG_PTR)0xdeadbee0, e1), ST_INVHANDLE);
    /* a handle with no access rights still compares (identity, not access) */
    { HANDLE z = NULL; if (DuplicateHandle(GetCurrentProcess(), e1, GetCurrentProcess(), &z, SYNCHRONIZE, FALSE, 0)) {
        EXPECT_EQ(UN(NtCompareObjects)(z, e1), 0); CloseHandle(z); } }
    CloseHandle(d1); CloseHandle(e1); CloseHandle(e2);
}

TEST(compare_signing_levels)
{
    NTSTATUS s;
    if (!UN(NtCompareSigningLevels)) { t_skip("NtCompareSigningLevels not exported"); return; }
    /* the comparison is not numeric: a level is acceptable when it maps at or above the required level */
    EXPECT_EQ(UN(NtCompareSigningLevels)(0, 0), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(8, 8), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(12, 12), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(14, 14), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(1, 0), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(0, 1), S(0xC0000428));
    EXPECT_EQ(UN(NtCompareSigningLevels)(12, 8), 0);
    EXPECT_EQ(UN(NtCompareSigningLevels)(8, 12), S(0xC0000428));
    EXPECT_EQ(UN(NtCompareSigningLevels)(0x100, 1), S(0xC0000428));
}

/* ---- job assignment ------------------------------------------------------------------ */
CHILD(nt1a_idle) { Sleep(60000); return 0; }

TEST(assign_process_to_job)
{
    HANDLE job, jobq, proc, pro_lim, ev; PROCESS_INFORMATION pi; NTSTATUS s; BOOL in = FALSE; WCHAR nm[64];
    REQUIRE(UN(NtAssignProcessToJobObject));
    swprintf(nm, 64, L"nt1a_job_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    job = CreateJobObjectW(NULL, nm); CHECK(job != NULL); if (!job) return;
    proc = t_spawn_child("nt1a_idle", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    CHECK(proc != NULL); if (!proc) { CloseHandle(job); return; }
    /* error paths first, leaving the child alone */
    EXPECT_EQ(UN(NtAssignProcessToJobObject)(NULL, proc), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAssignProcessToJobObject)(job, NULL), ST_INVHANDLE);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_EQ(UN(NtAssignProcessToJobObject)(ev, proc), ST_TYPEMISM);
    EXPECT_EQ(UN(NtAssignProcessToJobObject)(job, ev), ST_TYPEMISM);
    CloseHandle(ev);
    jobq = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, nm);
    if (jobq) { EXPECT_EQ(UN(NtAssignProcessToJobObject)(jobq, proc), ST_DENIED); CloseHandle(jobq); }
    pro_lim = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
    if (pro_lim) { EXPECT_EQ(UN(NtAssignProcessToJobObject)(job, pro_lim), ST_DENIED); CloseHandle(pro_lim); }
    CHECK(IsProcessInJob(proc, job, &in) && !in);
    /* success */
    s = UN(NtAssignProcessToJobObject)(job, proc);
    EXPECT_EQ(s, 0);
    in = FALSE; CHECK(IsProcessInJob(proc, job, &in)); CHECK(in);
    /* same job again */
    s = UN(NtAssignProcessToJobObject)(job, proc);
    EXPECT_EQ(s, 0);     /* idempotent for the same job */
    /* terminated process cannot be assigned to another job */
    TerminateProcess(proc, 1); WaitForSingleObject(proc, 10000);
    { HANDLE job2 = CreateJobObjectW(NULL, NULL);
      if (job2) { s = UN(NtAssignProcessToJobObject)(job2, proc); EXPECT_EQ(s, ST_DENIED); CloseHandle(job2); } }
    CloseHandle(pi.hThread); CloseHandle(proc); CloseHandle(job);
}

/* ---- Timer2 -------------------------------------------------------------------------- */
TEST(timer2_cancel)
{
    HANDLE h = NULL; NTSTATUS s; BYTE params[64];
    if (!UN(NtCreateTimer2) || !UN(NtCancelTimer2)) { t_skip("Timer2 services not exported"); return; }
    s = UN(NtCreateTimer2)(&h, NULL, NULL, 0, 0x1F0003);
    EXPECT_EQ(s, 0);
    if (s >= 0 && h) {
        memset(params, 0, sizeof params);
        EXPECT_EQ(UN(NtCancelTimer2)(h, params), 0);     /* idle timer: cancelling is a successful no-op */
        EXPECT_EQ(UN(NtCancelTimer2)(h, NULL), 0);
        UN(NtClose)(h);
        EXPECT_EQ(UN(NtCancelTimer2)(h, params), ST_INVHANDLE);   /* closed */
    }
    EXPECT_EQ(UN(NtCancelTimer2)(NULL, params), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtCancelTimer2)(ev, params), ST_TYPEMISM); CloseHandle(ev); }
}

/* ---- callback return ---------------------------------------------------------------------- */
TEST(callback_return_outside_callback)
{
    NTSTATUS s;
    REQUIRE(UN(NtCallbackReturn));
    s = UN(NtCallbackReturn)(NULL, 0, 0);
    EXPECT_EQ(s, S(0xC0000258));       /* STATUS_NO_CALLBACK_ACTIVE */
}

/* ---- cancel services with nothing pending (full pending-request coverage lives in nt_cancel_io) ---------- */
TEST(cancel_io_nothing_pending)
{
    IO_STATUS_BLOCK io; HANDLE f; char p[MAX_PATH]; NTSTATUS s;
    REQUIRE(UN(NtCancelIoFile)); REQUIRE(UN(NtCancelIoFileEx)); REQUIRE(UN(NtCancelSynchronousIoFile));
    t_tmpfile(p, sizeof p, "cancel_idle.bin");
    f = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    memset(&io, 0xcc, sizeof io);
    s = UN(NtCancelIoFile)(f, &io);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0);
    memset(&io, 0xcc, sizeof io);
    s = UN(NtCancelIoFileEx)(f, NULL, &io);
    EXPECT_EQ(s, S(0xC0000225));                 /* STATUS_NOT_FOUND: no request to cancel */
    EXPECT_EQ(io.Status, S(0xC0000225));
    memset(&io, 0xcc, sizeof io);
    s = UN(NtCancelSynchronousIoFile)(THR_CUR, NULL, &io);
    EXPECT_EQ(s, S(0xC0000225));
    EXPECT_EQ(UN(NtCancelIoFile)(NULL, &io), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCancelIoFileEx)(NULL, NULL, &io), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(NULL, NULL, &io), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL);
      EXPECT_EQ(UN(NtCancelIoFile)(ev, &io), ST_TYPEMISM);
      EXPECT_EQ(UN(NtCancelIoFileEx)(ev, NULL, &io), ST_TYPEMISM);
      EXPECT_EQ(UN(NtCancelSynchronousIoFile)(ev, NULL, &io), ST_TYPEMISM);
      CloseHandle(ev); }
    EXPECT_EQ(UN(NtCancelIoFile)(f, NULL), ST_AV);
    CloseHandle(f); DeleteFileA(p);
}
