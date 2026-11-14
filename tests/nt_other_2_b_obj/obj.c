/* Zw-named object / atom / memory / wait services: ZwAddAtom(Ex), ZwFindAtom, ZwDeleteAtom,
 * ZwAllocateLocallyUniqueId, ZwAllocateUuids, ZwAllocateVirtualMemory(Ex), ZwClose, ZwDuplicateObject,
 * ZwCompareObjects, ZwClearEvent, ZwCancelTimer(2), ZwDelayExecution, ZwAlertThread, ZwAlertResumeThread,
 * ZwAlertThreadByThreadId, ZwAllocateReserveObject, ZwAreMappedFilesTheSame.
 * Status values: see EVIDENCE.md. */
#include "t.h"

typedef USHORT xatom;
UDECL(NTSTATUS, ZwAddAtom, (PWSTR, ULONG, xatom *));
UDECL(NTSTATUS, ZwAddAtomEx, (PWSTR, ULONG, xatom *, ULONG));
UDECL(NTSTATUS, ZwFindAtom, (PWSTR, ULONG, xatom *));
UDECL(NTSTATUS, ZwDeleteAtom, (xatom));
UDECL(NTSTATUS, ZwAllocateLocallyUniqueId, (PLUID));
UDECL(NTSTATUS, ZwAllocateUuids, (PULARGE_INTEGER, PULONG, PULONG, PCHAR));
UDECL(NTSTATUS, ZwAllocateVirtualMemory, (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG));
UDECL(NTSTATUS, ZwAllocateVirtualMemoryEx, (HANDLE, PVOID *, PSIZE_T, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, ZwClose, (HANDLE));
UDECL(NTSTATUS, ZwDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, ZwCompareObjects, (HANDLE, HANDLE));
UDECL(NTSTATUS, ZwClearEvent, (HANDLE));
UDECL(NTSTATUS, ZwCancelTimer, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, ZwCancelTimer2, (HANDLE, PVOID));
UDECL(NTSTATUS, ZwDelayExecution, (BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwAlertThread, (HANDLE));
UDECL(NTSTATUS, ZwAlertResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, ZwAlertThreadByThreadId, (ULONG_PTR));
UDECL(NTSTATUS, NtWaitForAlertByThreadId, (PVOID, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwAllocateReserveObject, (PHANDLE, PVOID, ULONG));
UDECL(NTSTATUS, ZwAreMappedFilesTheSame, (PVOID, PVOID));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, PVOID, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCreateSemaphore, (PHANDLE, ACCESS_MASK, PVOID, LONG, LONG));
UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, PVOID, ULONG));
UDECL(NTSTATUS, NtSetTimer, (HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN));
UDECL(NTSTATUS, NtCreateTimer2, (PHANDLE, PVOID, PVOID, ULONG, ACCESS_MASK));

#define S(x) ((NTSTATUS)(x))
#define ST_INVALID_HANDLE S(0xC0000008)
#define ST_INVALID_PARAMETER S(0xC000000D)
#define ST_NOT_FOUND S(0xC0000034)
#define ST_TYPE_MISMATCH S(0xC0000024)
#define ST_NOT_SAME_OBJECT S(0xC00001AC)
#define ST_ALERTED S(0x101)
#define ST_TIMEOUT S(0x102)
#define ST_USER_APC S(0xC0)
#define SELF ((HANDLE)(LONG_PTR)-1)

#define PROBE(what, st) t_note("%s -> 0x%08lx", what, (unsigned long)(st))

TEST(alias_pairs)
{
    static const char *n[] = {"AddAtom","AddAtomEx","FindAtom","DeleteAtom","AllocateLocallyUniqueId","AllocateUuids",
        "AllocateVirtualMemory","AllocateVirtualMemoryEx","Close","DuplicateObject","CompareObjects","ClearEvent",
        "CancelTimer","CancelTimer2","DelayExecution","AlertThread","AlertResumeThread","AlertThreadByThreadId",
        "AllocateReserveObject","AreMappedFilesTheSame"};
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64];
        wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa && !pb) { t_note("%s absent", n[i]); continue; }
        CHECKF(pa == pb, "%s: Nt/Zw differ", n[i]);
    }
}

static void atom_name(WCHAR *out, const char *tag)
{
    wsprintfW(out, L"NO2B%S%lu", tag, GetCurrentProcessId());
}

TEST(atoms)
{
    REQUIRE(UN(ZwAddAtom)); REQUIRE(UN(ZwFindAtom)); REQUIRE(UN(ZwDeleteAtom));
    WCHAR nm[64]; atom_name(nm, "a");
    xatom a = 0, b = 0, c = 0;
    ULONG len = lstrlenW(nm) * 2;
    EXPECT_EQ(UN(ZwFindAtom)(nm, len, &c), ST_NOT_FOUND);
    EXPECT_EQ(UN(ZwAddAtom)(nm, len, &a), 0);
    CHECK(a >= 0xC000);
    EXPECT_EQ(UN(ZwAddAtom)(nm, len, &b), 0);           /* refcount 2 */
    EXPECT_EQ(b, a);
    EXPECT_EQ(UN(ZwFindAtom)(nm, len, &c), 0);
    EXPECT_EQ(c, a);
    /* case-insensitive */
    WCHAR up[64]; lstrcpyW(up, nm); CharUpperW(up);
    c = 0; EXPECT_EQ(UN(ZwFindAtom)(up, len, &c), 0); EXPECT_EQ(c, a);
    EXPECT_EQ(UN(ZwDeleteAtom)(a), 0);
    EXPECT_EQ(UN(ZwFindAtom)(nm, len, &c), 0);          /* one reference left */
    EXPECT_EQ(UN(ZwDeleteAtom)(a), 0);
    EXPECT_EQ(UN(ZwFindAtom)(nm, len, &c), ST_NOT_FOUND);
    NTSTATUS st = UN(ZwDeleteAtom)(a);
    EXPECT_EQ(st, ST_INVALID_HANDLE);
    /* error paths */
    EXPECT_EQ(UN(ZwDeleteAtom)(0), ST_INVALID_HANDLE);
    st = UN(ZwFindAtom)(nm, 0, &c); EXPECT_EQ(st, S(0xC0000033));
    st = UN(ZwAddAtom)(nm, 0, &c); EXPECT_EQ(st, S(0xC0000033));
    st = UN(ZwAddAtom)(NULL, 4, &c); EXPECT_EQ(st, ST_INVALID_PARAMETER);
}

TEST(atom_ex)
{
    REQUIRE(UN(ZwAddAtomEx)); REQUIRE(UN(ZwFindAtom)); REQUIRE(UN(ZwDeleteAtom));
    WCHAR nm[64]; atom_name(nm, "x");
    xatom a = 0, c = 0; ULONG len = lstrlenW(nm) * 2;
    NTSTATUS st = UN(ZwAddAtomEx)(nm, len, &a, 0);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        CHECK(a >= 0xC000);
        EXPECT_EQ(UN(ZwFindAtom)(nm, len, &c), 0); EXPECT_EQ(c, a);
        EXPECT_EQ(UN(ZwDeleteAtom)(a), 0);
    }
    st = UN(ZwAddAtomEx)(nm, len, &a, 0x80000000);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    if (st == 0) UN(ZwDeleteAtom)(a);
}

TEST(luid_uuid)
{
    REQUIRE(UN(ZwAllocateLocallyUniqueId)); REQUIRE(UN(ZwAllocateUuids));
    LUID a = {0}, b = {0};
    EXPECT_EQ(UN(ZwAllocateLocallyUniqueId)(&a), 0);
    EXPECT_EQ(UN(ZwAllocateLocallyUniqueId)(&b), 0);
    unsigned long long x = ((unsigned long long)a.HighPart << 32) | a.LowPart, y = ((unsigned long long)b.HighPart << 32) | b.LowPart;
    CHECK(x != 0); CHECK(y > x);
    EXPECT_EQ(UN(ZwAllocateLocallyUniqueId)(NULL), S(0xC0000005));

    ULARGE_INTEGER t1 = {{0}}, t2 = {{0}}; ULONG r1 = 0, r2 = 0, s1 = 0, s2 = 0; char seed1[6] = {0}, seed2[6] = {0};
    EXPECT_EQ(UN(ZwAllocateUuids)(&t1, &r1, &s1, seed1), 0);
    EXPECT_EQ(UN(ZwAllocateUuids)(&t2, &r2, &s2, seed2), 0);
    CHECK(t1.QuadPart != 0); CHECK(r1 != 0);
    CHECK(t2.QuadPart >= t1.QuadPart);
    EXPECT_EQ(memcmp(seed1, seed2, 6), 0);
    EXPECT_EQ(UN(ZwAllocateUuids)(NULL, &r1, &s1, seed1), S(0xC0000005));
}

TEST(virtual_memory)
{
    REQUIRE(UN(ZwAllocateVirtualMemory)); REQUIRE(UN(NtFreeVirtualMemory));
    PVOID base = NULL; SIZE_T sz = 0x1800;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0);
    CHECK(base != NULL); EXPECT_EQ(sz, 0x2000); EXPECT_EQ((ULONG_PTR)base & 0xFFFF, 0);
    if (base) {
        ((BYTE *)base)[0x1fff] = 7; EXPECT_EQ(((BYTE *)base)[0], 0);
        MEMORY_BASIC_INFORMATION mbi; VirtualQuery(base, &mbi, sizeof mbi);
        EXPECT_EQ(mbi.State, MEM_COMMIT); EXPECT_EQ(mbi.Protect, PAGE_READWRITE);
        PVOID fb = base; SIZE_T fs = 0;
        EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &fb, &fs, MEM_RELEASE), 0);
    }
    /* zero size, invalid handle, bad zero bits, bad protection */
    base = NULL; sz = 0;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_COMMIT, PAGE_READWRITE), ST_INVALID_PARAMETER);
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)((HANDLE)(ULONG_PTR)0x7777770, &base, 0, &sz, MEM_COMMIT, PAGE_READWRITE), ST_INVALID_HANDLE);
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_COMMIT, 0x3), S(0xC0000045));
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)(SELF, &base, 0, &sz, 0, PAGE_READWRITE), ST_INVALID_PARAMETER);
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(ZwAllocateVirtualMemory)(SELF, &base, 63, &sz, MEM_COMMIT, PAGE_READWRITE), ST_INVALID_PARAMETER);
}

TEST(virtual_memory_ex)
{
    REQUIRE(UN(ZwAllocateVirtualMemoryEx)); REQUIRE(UN(NtFreeVirtualMemory));
    PVOID base = NULL; SIZE_T sz = 0x3000;
    NTSTATUS st = UN(ZwAllocateVirtualMemoryEx)(SELF, &base, &sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        EXPECT_EQ(sz, 0x3000); ((BYTE *)base)[0x2fff] = 1;
        PVOID fb = base; SIZE_T fs = 0;
        EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &fb, &fs, MEM_RELEASE), 0);
    }
    base = NULL; sz = 0;
    EXPECT_EQ(UN(ZwAllocateVirtualMemoryEx)(SELF, &base, &sz, MEM_COMMIT, PAGE_READWRITE, NULL, 0), ST_INVALID_PARAMETER);
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(ZwAllocateVirtualMemoryEx)((HANDLE)(ULONG_PTR)0x7777770, &base, &sz, MEM_COMMIT, PAGE_READWRITE, NULL, 0), ST_INVALID_HANDLE);
    base = NULL; sz = 0x1000;
    st = UN(ZwAllocateVirtualMemoryEx)(SELF, &base, &sz, MEM_COMMIT, PAGE_READWRITE, NULL, 3);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    if (st == 0) { PVOID fb = base; SIZE_T fs = 0; UN(NtFreeVirtualMemory)(SELF, &fb, &fs, MEM_RELEASE); }
}

TEST(close_dup_compare)
{
    REQUIRE(UN(ZwClose)); REQUIRE(UN(ZwDuplicateObject)); REQUIRE(UN(NtCreateEvent));
    HANDLE e = NULL, e2 = NULL, d = NULL, d2 = NULL;
    EXPECT_EQ(UN(NtCreateEvent)(&e, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    EXPECT_EQ(UN(NtCreateEvent)(&e2, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    EXPECT_EQ(UN(ZwDuplicateObject)(SELF, e, SELF, &d, 0, 0, DUPLICATE_SAME_ACCESS), 0);
    CHECK(d != NULL && d != e);
    if (UN(ZwCompareObjects)) {
        EXPECT_EQ(UN(ZwCompareObjects)(e, d), 0);
        EXPECT_EQ(UN(ZwCompareObjects)(e, e), 0);
        EXPECT_EQ(UN(ZwCompareObjects)(e, e2), ST_NOT_SAME_OBJECT);
        EXPECT_EQ(UN(ZwCompareObjects)(e, (HANDLE)(ULONG_PTR)0x7777770), ST_INVALID_HANDLE);
        EXPECT_EQ(UN(ZwCompareObjects)(NULL, e), ST_INVALID_HANDLE);
    } else t_note("ZwCompareObjects missing");
    /* the duplicate is independent: signalling through one is visible through the other */
    SetEvent(e); EXPECT_EQ(WaitForSingleObject(d, 0), WAIT_OBJECT_0);
    /* restricted access */
    EXPECT_EQ(UN(ZwDuplicateObject)(SELF, e, SELF, &d2, SYNCHRONIZE, 0, 0), 0);
    CHECK(SetEvent(d2) == 0);
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    EXPECT_EQ(UN(ZwClose)(d2), 0);
    /* close source on duplicate */
    HANDLE d3 = NULL;
    EXPECT_EQ(UN(ZwDuplicateObject)(SELF, d, SELF, &d3, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE), 0);
    EXPECT_EQ(UN(ZwClose)(d3), 0);
    EXPECT_EQ(UN(ZwClose)(d3), ST_INVALID_HANDLE);
    /* errors */
    EXPECT_EQ(UN(ZwDuplicateObject)(SELF, (HANDLE)(ULONG_PTR)0x7777770, SELF, &d, 0, 0, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDuplicateObject)((HANDLE)(ULONG_PTR)0x7777770, e, SELF, &d, 0, 0, 0), ST_INVALID_HANDLE);
    /* no target handle pointer: only valid with CLOSE_SOURCE; otherwise succeeds without a result */
    EXPECT_EQ(UN(ZwClose)(e), 0);
    EXPECT_EQ(UN(ZwClose)(e), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwClose)(e2), 0);
    EXPECT_EQ(UN(ZwClose)(NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwClose)((HANDLE)(ULONG_PTR)0x7777770), ST_INVALID_HANDLE);
}

TEST(clear_event)
{
    REQUIRE(UN(ZwClearEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateSemaphore));
    HANDLE e = NULL, s = NULL;
    EXPECT_EQ(UN(NtCreateEvent)(&e, EVENT_ALL_ACCESS, NULL, 0, TRUE), 0);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_OBJECT_0);
    EXPECT_EQ(UN(ZwClearEvent)(e), 0);
    EXPECT_EQ(WaitForSingleObject(e, 0), WAIT_TIMEOUT);
    EXPECT_EQ(UN(ZwClearEvent)(e), 0);               /* already clear */
    EXPECT_EQ(UN(NtCreateSemaphore)(&s, SEMAPHORE_ALL_ACCESS, NULL, 0, 1), 0);
    EXPECT_EQ(UN(ZwClearEvent)(s), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwClearEvent)(NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwClearEvent)((HANDLE)(ULONG_PTR)0x7777770), ST_INVALID_HANDLE);
    HANDLE ro = NULL;
    EXPECT_EQ(UN(ZwDuplicateObject)(SELF, e, SELF, &ro, SYNCHRONIZE, 0, 0), 0);
    EXPECT_EQ(UN(ZwClearEvent)(ro), S(0xC0000022));
    CloseHandle(ro); CloseHandle(e); CloseHandle(s);
}

TEST(cancel_timer)
{
    REQUIRE(UN(ZwCancelTimer)); REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtSetTimer));
    HANDLE t = NULL; BOOLEAN st = 0xCC; LARGE_INTEGER due;
    EXPECT_EQ(UN(NtCreateTimer)(&t, TIMER_ALL_ACCESS, NULL, 0), 0);
    EXPECT_EQ(UN(ZwCancelTimer)(t, &st), 0); EXPECT_EQ(st, 0);          /* never set */
    due.QuadPart = -600000000LL;                                           /* 60 s */
    EXPECT_EQ(UN(NtSetTimer)(t, &due, NULL, NULL, FALSE, 0, NULL), 0);
    st = 0xCC; EXPECT_EQ(UN(ZwCancelTimer)(t, &st), 0); EXPECT_EQ(st, 0);   /* state = signalled, not pending */
    st = 0xCC; EXPECT_EQ(UN(ZwCancelTimer)(t, &st), 0); EXPECT_EQ(st, 0);
    EXPECT_EQ(UN(NtSetTimer)(t, &due, NULL, NULL, FALSE, 0, NULL), 0);
    EXPECT_EQ(UN(ZwCancelTimer)(t, NULL), 0);                              /* state optional */
    /* an expired notification timer is signalled; CurrentState reports the signalled state */
    due.QuadPart = -10000;
    EXPECT_EQ(UN(NtSetTimer)(t, &due, NULL, NULL, FALSE, 0, NULL), 0);
    EXPECT_EQ(WaitForSingleObject(t, 5000), WAIT_OBJECT_0);
    st = 0xCC; EXPECT_EQ(UN(ZwCancelTimer)(t, &st), 0); EXPECT_EQ(st, 1);
    EXPECT_EQ(UN(ZwCancelTimer)(NULL, &st), ST_INVALID_HANDLE);
    HANDLE ev = NULL; REQUIRE(UN(NtCreateEvent));
    EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    EXPECT_EQ(UN(ZwCancelTimer)(ev, &st), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwCancelTimer)(t, (PBOOLEAN)(ULONG_PTR)8), S(0xC0000005));
    CloseHandle(ev); CloseHandle(t);
}

TEST(cancel_timer2)
{
    REQUIRE(UN(ZwCancelTimer2)); REQUIRE(UN(NtCreateTimer2));
    HANDLE t = NULL;
    NTSTATUS st = UN(NtCreateTimer2)(&t, NULL, NULL, 0, TIMER_ALL_ACCESS);
    PROBE("NtCreateTimer2", st);
    if (st != 0) { t_skip("NtCreateTimer2 not usable: 0x%08lx", (unsigned long)st); return; }
    ULONG params[2] = {0, 0};
    st = UN(ZwCancelTimer2)(t, params);
    EXPECT_EQ(st, 0);
    st = UN(ZwCancelTimer2)(t, NULL);
    EXPECT_EQ(st, 0);
    st = UN(ZwCancelTimer2)(NULL, params);
    EXPECT_EQ(st, ST_INVALID_HANDLE);
    CloseHandle(t);
}

static void CALLBACK apc_fn(ULONG_PTR p) { *(volatile LONG *)p = 1; }

TEST(delay_execution)
{
    REQUIRE(UN(ZwDelayExecution));
    LARGE_INTEGER d; d.QuadPart = -500000;                                 /* 50 ms */
    DWORD t0 = GetTickCount();
    EXPECT_EQ(UN(ZwDelayExecution)(FALSE, &d), 0);
    CHECK(GetTickCount() - t0 >= 40);
    /* a zero interval is a yield: STATUS_YIELD_EXECUTION (0x40000024) when another thread was ready, else 0 */
    d.QuadPart = 0; { NTSTATUS y = UN(ZwDelayExecution)(FALSE, &d); CHECKF(y == 0 || y == S(0x40000024), "yield status 0x%08lx", (unsigned long)y); }
    d.QuadPart = 0; { NTSTATUS y = UN(ZwDelayExecution)(TRUE, &d); CHECKF(y == 0 || y == S(0x40000024), "yield status 0x%08lx", (unsigned long)y); }
    /* absolute time in the past returns immediately */
    d.QuadPart = 1; t0 = GetTickCount();
    EXPECT_EQ(UN(ZwDelayExecution)(FALSE, &d), 0);
    CHECK(GetTickCount() - t0 < 1000);
    /* alertable delay is interrupted by a queued APC */
    static volatile LONG ran; ran = 0;
    QueueUserAPC(apc_fn, GetCurrentThread(), (ULONG_PTR)&ran);
    d.QuadPart = -100000000LL;
    t0 = GetTickCount();
    EXPECT_EQ(UN(ZwDelayExecution)(TRUE, &d), ST_USER_APC);
    EXPECT_EQ(ran, 1); CHECK(GetTickCount() - t0 < 5000);
    EXPECT_EQ(UN(ZwDelayExecution)(FALSE, NULL), S(0xC0000005));
}

typedef struct { volatile LONG ready; NTSTATUS st; } wt;
static DWORD WINAPI delay_thread(LPVOID p)
{
    wt *w = p; LARGE_INTEGER d; d.QuadPart = -100000000LL;                 /* 10 s */
    InterlockedExchange(&w->ready, 1);
    w->st = UN(ZwDelayExecution)(TRUE, &d);
    return 0;
}
static void wait_ready(wt *w) { for (int i = 0; i < 500 && !w->ready; i++) Sleep(10); Sleep(50); }

TEST(alert_thread)
{
    REQUIRE(UN(ZwAlertThread));
    wt w = {0, 0x55555555};
    HANDLE th = CreateThread(NULL, 0, delay_thread, &w, 0, NULL);
    REQUIRE(th);
    wait_ready(&w);
    EXPECT_EQ(UN(ZwAlertThread)(th), 0);
    EXPECT_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(w.st, ST_ALERTED);
    CloseHandle(th);
    EXPECT_EQ(UN(ZwAlertThread)(NULL), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwAlertThread)(ev), ST_TYPE_MISMATCH);
    CloseHandle(ev);
}

TEST(alert_resume_thread)
{
    REQUIRE(UN(ZwAlertResumeThread));
    wt w = {0, 0x55555555};
    HANDLE th = CreateThread(NULL, 0, delay_thread, &w, CREATE_SUSPENDED, NULL);
    REQUIRE(th);
    ULONG prev = 0xCC;
    EXPECT_EQ(UN(ZwAlertResumeThread)(th, &prev), 0);
    EXPECT_EQ(prev, 1);
    wait_ready(&w);
    prev = 0xCC;                                         /* running now: previous suspend count 0, alerts the wait */
    EXPECT_EQ(UN(ZwAlertResumeThread)(th, &prev), 0);
    EXPECT_EQ(prev, 0);
    EXPECT_EQ(WaitForSingleObject(th, 8000), WAIT_OBJECT_0);
    EXPECT_EQ(w.st, ST_ALERTED);
    CloseHandle(th);
    EXPECT_EQ(UN(ZwAlertResumeThread)(NULL, &prev), ST_INVALID_HANDLE);
}

TEST(alert_by_thread_id)
{
    REQUIRE(UN(ZwAlertThreadByThreadId)); REQUIRE(UN(NtWaitForAlertByThreadId));
    LARGE_INTEGER d; d.QuadPart = -10000;                                  /* 1 ms */
    EXPECT_EQ(UN(NtWaitForAlertByThreadId)(NULL, &d), ST_TIMEOUT);
    EXPECT_EQ(UN(ZwAlertThreadByThreadId)(GetCurrentThreadId()), 0);
    d.QuadPart = -50000000LL;
    EXPECT_EQ(UN(NtWaitForAlertByThreadId)(NULL, &d), ST_ALERTED);
    d.QuadPart = -10000;
    EXPECT_EQ(UN(NtWaitForAlertByThreadId)(NULL, &d), ST_TIMEOUT);       /* alert was consumed */
    EXPECT_EQ(UN(ZwAlertThreadByThreadId)(0xFFFFFFF0u), S(0xC000000B));  /* STATUS_INVALID_CID */
}

TEST(reserve_object)
{
    REQUIRE(UN(ZwAllocateReserveObject));
    HANDLE h = NULL;
    EXPECT_EQ(UN(ZwAllocateReserveObject)(&h, NULL, 0), 0);
    CHECK(h != NULL);
    if (h) CHECK(CloseHandle(h));
    h = NULL; EXPECT_EQ(UN(ZwAllocateReserveObject)(&h, NULL, 1), 0);
    if (h) CloseHandle(h);
    h = NULL; NTSTATUS st = UN(ZwAllocateReserveObject)(&h, NULL, 2);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    if (st == 0 && h) CloseHandle(h);
    EXPECT_EQ(UN(ZwAllocateReserveObject)(NULL, NULL, 0), S(0xC0000005));
}

TEST(mapped_files_same)
{
    REQUIRE(UN(ZwAreMappedFilesTheSame));
    HMODULE k = GetModuleHandleA("kernel32.dll"), n = GetModuleHandleA("ntdll.dll");
    EXPECT_EQ(UN(ZwAreMappedFilesTheSame)(k, k), 0);
    EXPECT_EQ(UN(ZwAreMappedFilesTheSame)((BYTE *)k + 0x1000, k), 0);
    NTSTATUS st = UN(ZwAreMappedFilesTheSame)(k, n);
    EXPECT_EQ(st, S(0xC00000D4));
    PVOID mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    st = UN(ZwAreMappedFilesTheSame)(mem, k);
    EXPECT_EQ(st, S(0xC0000018));
    VirtualFree(mem, 0, MEM_RELEASE);
}
