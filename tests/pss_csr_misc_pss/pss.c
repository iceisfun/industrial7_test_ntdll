/* PssNt* process snapshot routines (the native layer behind PssCaptureSnapshot & co). */
#include "t.h"

#define ST_INV_PARAM  ((NTSTATUS)0xC000000D)
#define ST_INV_HANDLE ((NTSTATUS)0xC0000008)
#define ST_LEN_MISM   ((NTSTATUS)0xC0000004)
#define ST_INV_INFO   ((NTSTATUS)0xC0000003)
#define ST_NOT_FOUND  ((NTSTATUS)0xC0000225)
#define ST_MIX        ((NTSTATUS)0xC0000030)
#define ST_NO_MORE    ((NTSTATUS)0x8000001A)
#define ST_MORE       ((NTSTATUS)0x105)
#define ST_PARTIAL    ((NTSTATUS)0x8000000D)
#define NT_CUR_PROC   ((HANDLE)(LONG_PTR)-1)

UDECL(NTSTATUS, PssNtCaptureSnapshot, (PVOID *, HANDLE, ULONG, ULONG));
UDECL(NTSTATUS, PssNtQuerySnapshot, (PVOID, int, PVOID, ULONG));
UDECL(NTSTATUS, PssNtWalkSnapshot, (PVOID, int, PVOID, PVOID, ULONG));
UDECL(NTSTATUS, PssNtFreeSnapshot, (PVOID));
UDECL(NTSTATUS, PssNtValidateDescriptor, (PVOID));
UDECL(VOID, PssNtFreeWalkMarker, (PVOID));
UDECL(NTSTATUS, PssNtDuplicateSnapshot, (HANDLE, PVOID, HANDLE, PVOID *, ULONG));
UDECL(NTSTATUS, PssNtFreeRemoteSnapshot, (HANDLE, PVOID));

#define NEED() do { REQUIRE(UN(PssNtCaptureSnapshot)); REQUIRE(UN(PssNtQuerySnapshot)); REQUIRE(UN(PssNtWalkSnapshot)); \
    REQUIRE(UN(PssNtFreeSnapshot)); REQUIRE(UN(PssNtValidateDescriptor)); REQUIRE(UN(PssNtFreeWalkMarker)); } while (0)

#define C_PROCESS 0
#define C_VACLONE 1
#define C_AUX     2
#define C_VASPACE 3
#define C_HANDLES 4
#define C_THREADS 5
#define C_TRACE   6
#define C_PERF    7
#define W_AUX 0
#define W_VA 1
#define W_HANDLES 2
#define W_THREADS 3

static PVOID cap(HANDLE proc, ULONG flags, ULONG tflags)
{
    PVOID s = NULL;
    NTSTATUS st = UN(PssNtCaptureSnapshot)(&s, proc, flags, tflags);
    CHECKF(st == 0 && s, "capture flags 0x%lx status 0x%lx", flags, (ULONG)st);
    return st == 0 ? s : NULL;
}

/* Walk a class to the end; returns entry count, stores the final status. Buffer must hold one entry. */
static int walk_all(PVOID s, int cls, ULONG entsz, BYTE *first_two /* 2*entsz or NULL */, NTSTATUS *last,
                    int (*visit)(const BYTE *, void *), void *ctx)
{
    BYTE mk[16] = {0}, e[0x100];
    int n = 0; NTSTATUS st;
    for (;;) {
        memset(e, 0xcc, sizeof e);
        st = UN(PssNtWalkSnapshot)(s, cls, mk, e, entsz);
        if (st != 0 || n > 100000) break;
        if (first_two && n < 2) memcpy(first_two + n * entsz, e, entsz);
        if (visit) n += visit(e, ctx) ? 0 : 0;
        n++;
    }
    *last = st;
    UN(PssNtFreeWalkMarker)(mk);
    return n;
}

static int q(PVOID s, int cls, PVOID out, ULONG sz) { return UN(PssNtQuerySnapshot)(s, cls, out, sz); }

TEST(capture_errors)
{
    NEED();
    PVOID s = NULL;
    ULONG bad[] = { 0x8000, 0x10000, 0x200000, 0x2000000, 0x3ff8000 };
    for (int i = 0; i < 5; i++) {
        s = NULL;
        CHECKF(UN(PssNtCaptureSnapshot)(&s, NT_CUR_PROC, bad[i], 0) == ST_INV_PARAM, "flags 0x%lx", bad[i]);
        EXPECT_EQ(s, 0);
    }
    s = NULL;
    EXPECT_EQ(UN(PssNtCaptureSnapshot)(&s, NT_CUR_PROC, 0x4000000, 0), ST_MIX);
    EXPECT_EQ(s, 0);
    s = NULL;
    EXPECT_EQ(UN(PssNtCaptureSnapshot)(&s, (HANDLE)0x1234, 0, 0), ST_INV_HANDLE);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(UN(PssNtCaptureSnapshot)(&s, NULL, 0, 0), ST_INV_HANDLE);
    EXPECT_EQ(UN(PssNtValidateDescriptor)(NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(PssNtFreeSnapshot)(NULL), ST_INV_HANDLE);
    BYTE buf[0x100];
    EXPECT_EQ(UN(PssNtQuerySnapshot)(NULL, 0, buf, 0xf0), ST_INV_HANDLE);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(NULL, 0, buf, buf, 0x50), ST_INV_HANDLE);
}

TEST(process_information)
{
    NEED();
    PVOID s = cap(NT_CUR_PROC, 0, 0);
    if (!s) return;
    EXPECT_EQ(UN(PssNtValidateDescriptor)(s), 0);
    BYTE b[0xf0]; memset(b, 0xcc, sizeof b);
    EXPECT_EQ(q(s, C_PROCESS, b, 0xf0), 0);
    EXPECT_EQ(*(ULONG *)(b + 8), STILL_ACTIVE);
    EXPECT_EQ(*(PVOID *)(b + 0x10), (PVOID)NtCurrentTeb()->ProcessEnvironmentBlock);
    CHECK(*(ULONG_PTR *)(b + 0x18) != 0);                       /* affinity */
    EXPECT_EQ(*(ULONG *)(b + 0x28), GetCurrentProcessId());
    CHECK(*(ULONG *)(b + 0x30) != 0);                           /* parent id */
    FILETIME ct, xt, kt, ut;
    if (GetProcessTimes(GetCurrentProcess(), &ct, &xt, &kt, &ut)) {
        ULONG64 c = ((ULONG64)ct.dwHighDateTime << 32) | ct.dwLowDateTime;
        EXPECT_EQ(*(ULONG64 *)(b + 0x40), c);
    }
    /* sizes and classes */
    BYTE big[0x200];
    EXPECT_EQ(q(s, C_PROCESS, big, 0xef), ST_LEN_MISM);
    EXPECT_EQ(q(s, C_PROCESS, big, 0xf1), ST_LEN_MISM);
    EXPECT_EQ(q(s, C_PROCESS, big, 0), ST_LEN_MISM);
    EXPECT_EQ(q(s, 10, big, 8), ST_LEN_MISM);
    EXPECT_EQ(q(s, 0x7fffffff, big, 8), ST_INV_INFO);
    EXPECT_EQ(q(s, -1, big, 8), ST_INV_INFO);
    /* classes for data that was not captured */
    EXPECT_EQ(q(s, C_VACLONE, big, 8), ST_NOT_FOUND);
    EXPECT_EQ(q(s, C_AUX, big, 4), ST_NOT_FOUND);
    EXPECT_EQ(q(s, C_VASPACE, big, 4), ST_NOT_FOUND);
    EXPECT_EQ(q(s, C_HANDLES, big, 4), ST_NOT_FOUND);
    EXPECT_EQ(q(s, C_THREADS, big, 8), ST_NOT_FOUND);
    EXPECT_EQ(q(s, C_TRACE, big, 0x10), ST_NOT_FOUND);
    EXPECT_EQ(q(s, 9, big, 0x28), ST_NOT_FOUND);
    for (int c = C_VACLONE; c <= C_TRACE; c++) {
        ULONG szs[] = { 0, 8, 4, 4, 4, 8, 0x10 };
        CHECKF(q(s, c, big, szs[c] + 1) == ST_LEN_MISM, "class %d oversize", c);
        CHECKF(q(s, c, big, szs[c] - 1) == ST_LEN_MISM, "class %d undersize", c);
    }
    /* class 8 is always available */
    EXPECT_EQ(q(s, 8, big, 0x70), 0);
    EXPECT_EQ(q(s, 8, big, 0x6f), ST_LEN_MISM);
    /* performance counters are zero unless measurement was requested */
    BYTE perf[0x60]; memset(perf, 0xcc, sizeof perf);
    EXPECT_EQ(q(s, C_PERF, perf, 0x60), 0);
    for (int i = 0; i < 0x60; i++) if (perf[i]) { CHECKF(0, "perf byte %d = 0x%x", i, perf[i]); break; }
    EXPECT_EQ(q(s, C_PERF, perf, 0x5f), ST_LEN_MISM);
    EXPECT_EQ(UN(PssNtFreeSnapshot)(s), 0);
}

static int count_threads_cb(const BYTE *e, void *ctx) { return 0; }

TEST(threads_walk)
{
    NEED();
    PVOID s = cap(NT_CUR_PROC, 0x80, 0x1f);
    if (!s) return;
    ULONG tc[2] = { 0xdead, 0xdead };
    EXPECT_EQ(q(s, C_THREADS, tc, 8), 0);
    CHECK(tc[0] >= 1);
    EXPECT_EQ(tc[1], 0);                                /* no context captured */
    BYTE mk[16] = {0}, e[0x88]; ULONG n = 0, found = 0; NTSTATUS st;
    for (;;) {
        memset(e, 0xcc, sizeof e);
        st = UN(PssNtWalkSnapshot)(s, W_THREADS, mk, e, 0x88);
        if (st != 0 || n > 4096) break;
        n++;
        EXPECT_EQ(*(ULONG *)(e + 0x10), GetCurrentProcessId());
        if (*(ULONG *)(e + 0x18) == GetCurrentThreadId()) { found++; EXPECT_EQ(*(PVOID *)(e + 8), (PVOID)NtCurrentTeb()); }
    }
    EXPECT_EQ(st, ST_NO_MORE);
    EXPECT_EQ(n, tc[0]);
    EXPECT_EQ(found, 1);
    UN(PssNtFreeWalkMarker)(mk);
    EXPECT_EQ(*(ULONG64 *)mk, 0); EXPECT_EQ(*(ULONG64 *)(mk + 8), 0);
    /* walk argument errors */
    memset(mk, 0, sizeof mk);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_THREADS, mk, e, 0x87), ST_LEN_MISM);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_THREADS, mk, e, 0x89), ST_LEN_MISM);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, 4, mk, e, 0x88), ST_INV_INFO);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, -1, mk, e, 0x88), ST_INV_INFO);
    /* classes that were not captured */
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_AUX, mk, e, 0x50), ST_NOT_FOUND);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_VA, mk, e, 0x50), ST_NOT_FOUND);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_HANDLES, mk, e, 0x48), ST_NOT_FOUND);
    UN(PssNtFreeWalkMarker)(mk);
    EXPECT_EQ(UN(PssNtFreeSnapshot)(s), 0);
}

TEST(aux_pages_and_va_space)
{
    NEED();
    PVOID s = cap(NT_CUR_PROC, 0x2 | 0x800, 0);
    if (!s) return;
    ULONG aux = 0xdead, va = 0xdead;
    EXPECT_EQ(q(s, C_AUX, &aux, 4), 0);
    EXPECT_EQ(aux, 1);
    EXPECT_EQ(q(s, C_VASPACE, &va, 4), 0);
    CHECK(va > 10);
    BYTE mk[16] = {0}, e[0x50]; NTSTATUS st;
    memset(e, 0xcc, sizeof e);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_AUX, mk, e, 0x50), 0);
    EXPECT_EQ(*(ULONG64 *)e, 0x7ffe0000);              /* the shared user data page */
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_AUX, mk, e, 0x50), ST_NO_MORE);
    UN(PssNtFreeWalkMarker)(mk);
    memset(mk, 0, sizeof mk);
    ULONG n = 0;
    for (;;) { st = UN(PssNtWalkSnapshot)(s, W_VA, mk, e, 0x50); if (st != 0 || n > 100000) break; n++; }
    EXPECT_EQ(st, ST_NO_MORE);
    EXPECT_EQ(n, va);
    UN(PssNtFreeWalkMarker)(mk);
    EXPECT_EQ(*(ULONG64 *)mk, 0); EXPECT_EQ(*(ULONG64 *)(mk + 8), 0);
    /* a NULL entry buffer starts a walk without returning data */
    memset(mk, 0, sizeof mk);
    st = UN(PssNtWalkSnapshot)(s, W_AUX, mk, NULL, 0);
    t_note("walk with NULL buffer -> 0x%lx", (ULONG)st);
    UN(PssNtFreeWalkMarker)(mk);
    EXPECT_EQ(*(ULONG64 *)mk, 0); EXPECT_EQ(*(ULONG64 *)(mk + 8), 0);
    EXPECT_EQ(UN(PssNtFreeSnapshot)(s), 0);
}

TEST(handles)
{
    NEED();
    PVOID s = cap(NT_CUR_PROC, 0x7c, 0x1f);
    if (!s) return;
    ULONG hc = 0xdead;
    EXPECT_EQ(q(s, C_HANDLES, &hc, 4), 0);
    CHECK(hc > 3);
    BYTE mk[16] = {0}, e[0x48]; ULONG n = 0; NTSTATUS st;
    for (;;) { st = UN(PssNtWalkSnapshot)(s, W_HANDLES, mk, e, 0x48); if (st != 0 || n > 100000) break; n++; }
    EXPECT_EQ(st, ST_NO_MORE);
    EXPECT_EQ(n, hc);
    UN(PssNtFreeWalkMarker)(mk);
    memset(mk, 0, sizeof mk);
    EXPECT_EQ(UN(PssNtWalkSnapshot)(s, W_HANDLES, mk, e, 0x47), ST_LEN_MISM);
    UN(PssNtFreeWalkMarker)(mk);
    EXPECT_EQ(UN(PssNtFreeSnapshot)(s), 0);
}

TEST(va_clone_and_perf)
{
    NEED();
    PVOID s = cap(NT_CUR_PROC, 0x40000001, 0);
    if (!s) return;
    HANDLE clone = NULL;
    EXPECT_EQ(q(s, C_VACLONE, &clone, 8), 0);
    CHECK(clone != NULL);
    DWORD cpid = clone ? GetProcessId(clone) : 0;
    CHECK(cpid != 0 && cpid != GetCurrentProcessId());
    BYTE perf[0x60]; memset(perf, 0, sizeof perf);
    EXPECT_EQ(q(s, C_PERF, perf, 0x60), 0);
    CHECK(*(ULONG64 *)perf != 0);                       /* total capture time was measured */
    BYTE b[0xf0];
    EXPECT_EQ(q(s, C_PROCESS, b, 0xf0), 0);
    EXPECT_EQ(*(ULONG *)(b + 0x28), GetCurrentProcessId());
    EXPECT_EQ(UN(PssNtFreeSnapshot)(s), 0);
    /* the clone handle is owned by the snapshot and closed with it */
    if (clone) { DWORD fl; SetLastError(0); CHECK(!GetHandleInformation(clone, &fl)); }
}

CHILD(pss_idle) { Sleep(60000); return 0; }

TEST(remote_process_and_duplicate)
{
    NEED(); REQUIRE(UN(PssNtDuplicateSnapshot)); REQUIRE(UN(PssNtFreeRemoteSnapshot));
    /* local duplicate */
    PVOID s = cap(NT_CUR_PROC, 0x80, 0x1f);
    if (!s) return;
    PVOID d = NULL;
    EXPECT_EQ(UN(PssNtDuplicateSnapshot)(NT_CUR_PROC, s, NT_CUR_PROC, &d, 0), 0);
    CHECK(d != NULL && d != s);
    if (d) {
        EXPECT_EQ(UN(PssNtValidateDescriptor)(d), 0);
        BYTE b[0xf0], e[0x88], mk[16] = {0}; ULONG tc[2];
        EXPECT_EQ(q(d, C_PROCESS, b, 0xf0), 0);
        EXPECT_EQ(*(ULONG *)(b + 0x28), GetCurrentProcessId());
        EXPECT_EQ(q(d, C_THREADS, tc, 8), 0);
        CHECK(tc[0] >= 1);
        EXPECT_EQ(UN(PssNtWalkSnapshot)(d, W_THREADS, mk, e, 0x88), 0);
        UN(PssNtFreeWalkMarker)(mk);
        EXPECT_EQ(UN(PssNtFreeSnapshot)(d), 0);
    }
    /* close-source duplicate: the source descriptor is released by the call */
    PVOID s2 = cap(NT_CUR_PROC, 0, 0);
    if (s2) {
        d = NULL;
        EXPECT_EQ(UN(PssNtDuplicateSnapshot)(NT_CUR_PROC, s2, NT_CUR_PROC, &d, 1), 0);
        if (d) { BYTE b[0xf0]; EXPECT_EQ(q(d, C_PROCESS, b, 0xf0), 0); EXPECT_EQ(UN(PssNtFreeSnapshot)(d), 0); }
    }

    /* remote process: capture it, and duplicate a local snapshot into it */
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof pi);
    t_spawn_child("pss_idle", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!pi.hProcess) { t_note("child spawn failed"); UN(PssNtFreeSnapshot)(s); return; }
    PVOID rs = cap(pi.hProcess, 0x80, 0x1f);
    if (rs) {
        BYTE b[0xf0], tcs[8];
        EXPECT_EQ(q(rs, C_PROCESS, b, 0xf0), 0);
        EXPECT_EQ(*(ULONG *)(b + 0x28), pi.dwProcessId);
        EXPECT_EQ(*(ULONG *)(b + 0x30), GetCurrentProcessId());
        EXPECT_EQ(q(rs, C_THREADS, tcs, 8), 0);
        EXPECT_EQ(*(ULONG *)tcs, 1);
        UN(PssNtFreeSnapshot)(rs);
    }
    d = NULL;
    NTSTATUS st = UN(PssNtDuplicateSnapshot)(NT_CUR_PROC, s, pi.hProcess, &d, 0);
    EXPECT_EQ(st, 0);
    if (st == 0 && d) {
        EXPECT_EQ(UN(PssNtFreeRemoteSnapshot)(pi.hProcess, d), 0);
        /* the remote block is gone now */
        EXPECT_EQ(UN(PssNtFreeRemoteSnapshot)(pi.hProcess, d), ST_PARTIAL);
    }
    EXPECT_EQ(UN(PssNtFreeRemoteSnapshot)(pi.hProcess, (PVOID)0x10000), ST_PARTIAL);
    UN(PssNtFreeSnapshot)(s);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}
