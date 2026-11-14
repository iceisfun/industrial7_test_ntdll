/* Zw-named virtual memory, thread/process lifecycle, job, section unmap, debug object and file I/O services. */
#include "t.h"

UDECL(NTSTATUS, ZwReadVirtualMemory, (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, ZwWriteVirtualMemory, (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, ZwSuspendThread, (HANDLE, PULONG));
UDECL(NTSTATUS, ZwResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, ZwSuspendProcess, (HANDLE));
UDECL(NTSTATUS, ZwResumeProcess, (HANDLE));
UDECL(NTSTATUS, ZwTerminateThread, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, ZwTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, ZwTerminateJobObject, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, ZwUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, ZwUnmapViewOfSectionEx, (HANDLE, PVOID, ULONG));
UDECL(NTSTATUS, ZwUnlockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, ZwResetWriteWatch, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, ZwRemoveProcessDebug, (HANDLE, HANDLE));
UDECL(NTSTATUS, ZwWaitForDebugEvent, (HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID));
UDECL(NTSTATUS, ZwUnlockFile, (HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG));
UDECL(NTSTATUS, ZwWriteFile, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, ZwWriteFileGather, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, ZwTerminateEnclave, (PVOID, BOOLEAN));
UDECL(NTSTATUS, ZwRevertContainerImpersonation, (VOID));
UDECL(NTSTATUS, NtLockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtLockFile, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtMapViewOfSection, (HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtAssignProcessToJobObject, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtDebugActiveProcess, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define DENIED S(0xc0000022)
#define WRONG_TYPE S(0xc0000024)
#define PARTIAL_COPY S(0x8000000d)
#define SELF ((HANDLE)(LONG_PTR)-1)
#define SELF_THREAD ((HANDLE)(LONG_PTR)-2)
#define ZERO_T(n) LARGE_INTEGER n = {0}

CHILD(sleeper) { Sleep(120000); return 0; }

static HANDLE mk_child(PROCESS_INFORMATION *pi, DWORD flags)
{
    HANDLE h = t_spawn_child("sleeper", "", flags, NULL, NULL, NULL, FALSE, NULL, pi);
    return h;
}
static void kill_child(PROCESS_INFORMATION *pi)
{
    if (pi->hProcess) { TerminateProcess(pi->hProcess, 0); WaitForSingleObject(pi->hProcess, 10000); CloseHandle(pi->hProcess); }
    if (pi->hThread) CloseHandle(pi->hThread);
}
static void cl(HANDLE h) { if (h) UN(NtClose)(h); }

TEST(zw_proc_aliases)
{
    static const char *names[] = { "ReadVirtualMemory", "WriteVirtualMemory", "SuspendThread", "ResumeThread",
        "SuspendProcess", "ResumeProcess", "TerminateThread", "TerminateProcess", "TerminateJobObject",
        "UnmapViewOfSection", "UnmapViewOfSectionEx", "UnlockVirtualMemory", "ResetWriteWatch", "RemoveProcessDebug",
        "WaitForDebugEvent", "UnlockFile", "WriteFile", "WriteFileGather", "TerminateEnclave", "RevertContainerImpersonation" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[64], zw[64];
        FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

/* ---------------- virtual memory ---------------- */
TEST(zw_read_virtual_memory)
{
    static char src[64] = "zw read virtual memory source";
    char dst[64]; SIZE_T got; NTSTATUS s; PVOID p; HANDLE ro = NULL;
    REQUIRE(UN(ZwReadVirtualMemory));
    memset(dst, 0x5a, sizeof dst); got = 99;
    EXPECT_EQ(UN(ZwReadVirtualMemory)(SELF, src, dst, sizeof src, &got), 0);
    EXPECT_EQ(got, sizeof src);
    CHECK(!memcmp(src, dst, sizeof src));
    /* output count is optional */
    memset(dst, 0, sizeof dst);
    EXPECT_EQ(UN(ZwReadVirtualMemory)(SELF, src, dst, 8, NULL), 0);
    CHECK(!memcmp(src, dst, 8));
    /* real process handle with VM_READ */
    ro = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (ro) {
        got = 0; memset(dst, 0, sizeof dst);
        EXPECT_EQ(UN(ZwReadVirtualMemory)(ro, src, dst, 16, &got), 0);
        EXPECT_EQ(got, 16);
        CHECK(!memcmp(src, dst, 16));
        CloseHandle(ro);
    }
    ro = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (ro) { got = 99; EXPECT_EQ(UN(ZwReadVirtualMemory)(ro, src, dst, 16, &got), DENIED); CloseHandle(ro); }
    /* zero length */
    got = 99;
    EXPECT_EQ(UN(ZwReadVirtualMemory)(SELF, src, dst, 0, &got), 0);
    EXPECT_EQ(got, 0);
    /* reserved-only (inaccessible) region: nothing copied */
    p = VirtualAlloc(NULL, 0x2000, MEM_RESERVE, PAGE_NOACCESS);
    if (p) {
        got = 99; s = UN(ZwReadVirtualMemory)(SELF, p, dst, 16, &got);
        EXPECT_EQ(s, PARTIAL_COPY); EXPECT_EQ(got, 0);
        VirtualFree(p, 0, MEM_RELEASE);
    }
    /* straddling the end of an accessible page into a reserved page: partial copy up to the boundary */
    p = VirtualAlloc(NULL, 0x2000, MEM_RESERVE, PAGE_NOACCESS);
    if (p && VirtualAlloc(p, 0x1000, MEM_COMMIT, PAGE_READWRITE)) {
        char *buf = HeapAlloc(GetProcessHeap(), 0, 64);
        if (buf) {
            memset(p, 0x11, 0x1000);
            got = 99; s = UN(ZwReadVirtualMemory)(SELF, (char *)p + 0x1000 - 8, buf, 32, &got);
            EXPECT_EQ(s, PARTIAL_COPY); CHECKF(got <= 8, "bytes copied before the fault: %llu", (unsigned long long)got);
            HeapFree(GetProcessHeap(), 0, buf);
        }
    }
    if (p) VirtualFree(p, 0, MEM_RELEASE);
    /* null source */
    got = 99; EXPECT_EQ(UN(ZwReadVirtualMemory)(SELF, NULL, dst, 4, &got), PARTIAL_COPY); EXPECT_EQ(got, 0);
    EXPECT_EQ(UN(ZwReadVirtualMemory)(NULL, src, dst, 4, &got), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReadVirtualMemory)((HANDLE)(ULONG_PTR)0x7ffffff4, src, dst, 4, &got), BAD_HANDLE);
    /* a thread handle is the wrong type */
    EXPECT_EQ(UN(ZwReadVirtualMemory)(GetCurrentThread(), src, dst, 4, &got), WRONG_TYPE);
}

TEST(zw_write_virtual_memory)
{
    char dst[32]; const char pat[] = "0123456789abcdef"; SIZE_T got; NTSTATUS s; PVOID p; HANDLE h;
    REQUIRE(UN(ZwWriteVirtualMemory));
    memset(dst, 0, sizeof dst); got = 99;
    EXPECT_EQ(UN(ZwWriteVirtualMemory)(SELF, dst, (PVOID)pat, 16, &got), 0);
    EXPECT_EQ(got, 16);
    CHECK(!memcmp(dst, pat, 16)); EXPECT_EQ(dst[16], 0);
    EXPECT_EQ(UN(ZwWriteVirtualMemory)(SELF, dst + 16, (PVOID)pat, 4, NULL), 0);
    CHECK(!memcmp(dst + 16, pat, 4));
    got = 99; EXPECT_EQ(UN(ZwWriteVirtualMemory)(SELF, dst, (PVOID)pat, 0, &got), 0); EXPECT_EQ(got, 0);
    /* process opened with only VM_WRITE (no VM_OPERATION) */
    h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
    if (h) { got = 0; EXPECT_EQ(UN(ZwWriteVirtualMemory)(h, dst, (PVOID)pat, 8, &got), 0); EXPECT_EQ(got, 8); CloseHandle(h); }
    h = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (h) { got = 99; EXPECT_EQ(UN(ZwWriteVirtualMemory)(h, dst, (PVOID)pat, 8, &got), DENIED); CloseHandle(h); }
    /* write into a read-only page of this process: copy-on-write protection is bypassed only for the
       memory manager's own rules; observed behaviour is a partial copy of zero bytes. */
    p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    if (p) {
        got = 99; s = UN(ZwWriteVirtualMemory)(SELF, p, (PVOID)pat, 8, &got);
        EXPECT_EQ(s, PARTIAL_COPY); EXPECT_EQ(got, 0);
        VirtualFree(p, 0, MEM_RELEASE);
    }
    got = 99; EXPECT_EQ(UN(ZwWriteVirtualMemory)(SELF, NULL, (PVOID)pat, 8, &got), PARTIAL_COPY); EXPECT_EQ(got, 0);
    EXPECT_EQ(UN(ZwWriteVirtualMemory)(NULL, dst, (PVOID)pat, 8, &got), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWriteVirtualMemory)(GetCurrentThread(), dst, (PVOID)pat, 8, &got), WRONG_TYPE);
}

TEST(zw_unlock_virtual_memory)
{
    PVOID base; SIZE_T size; NTSTATUS s; PVOID p;
    REQUIRE(UN(ZwUnlockVirtualMemory)); REQUIRE(UN(NtLockVirtualMemory));
    p = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc failed"); return; }
    base = p; size = 0x1000;
    s = UN(NtLockVirtualMemory)(SELF, &base, &size, 1 /* MAP_PROCESS */);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(base, p); EXPECT_EQ(size, 0x1000);
        base = p; size = 0x1000;
        EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 1), 0);
        base = p; size = 0x1000;
        EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 1), S(0xc000002a)); /* STATUS_NOT_LOCKED */
    }
    /* never-locked page */
    base = (char *)p + 0x1000; size = 0x1000;
    EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 1), S(0xc000002a));
    /* bad map types */
    base = p; size = 0x1000;
    EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 0), BAD_PARAM);
    base = p; size = 0x1000;
    EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 4), BAD_PARAM);
    base = p; size = 0x1000;
    EXPECT_EQ(UN(ZwUnlockVirtualMemory)(NULL, &base, &size, 1), BAD_HANDLE);
    /* zero-size request */
    base = p; size = 0;
    EXPECT_EQ(UN(ZwUnlockVirtualMemory)(SELF, &base, &size, 1), BAD_PARAM);
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(zw_reset_write_watch)
{
    PVOID p, addrs[8]; ULONG_PTR cnt; DWORD gran; NTSTATUS s; UINT r;
    REQUIRE(UN(ZwResetWriteWatch));
    p = VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
    if (!p) { t_skip("write-watch allocation failed"); return; }
    *(volatile char *)p = 1; *((volatile char *)p + 0x2000) = 1;
    cnt = 8; r = GetWriteWatch(0, p, 0x4000, addrs, &cnt, &gran);
    EXPECT_EQ(r, 0); EXPECT_EQ(cnt, 2);
    EXPECT_EQ(UN(ZwResetWriteWatch)(SELF, p, 0x4000), 0);
    cnt = 8; r = GetWriteWatch(0, p, 0x4000, addrs, &cnt, &gran);
    EXPECT_EQ(r, 0); EXPECT_EQ(cnt, 0);
    /* partial reset */
    *(volatile char *)p = 2; *((volatile char *)p + 0x2000) = 2;
    EXPECT_EQ(UN(ZwResetWriteWatch)(SELF, p, 0x1000), 0);
    cnt = 8; r = GetWriteWatch(0, p, 0x4000, addrs, &cnt, &gran);
    EXPECT_EQ(r, 0); EXPECT_EQ(cnt, 1);
    if (cnt == 1) EXPECT_EQ(addrs[0], (char *)p + 0x2000);
    /* unaligned and out-of-range */
    s = UN(ZwResetWriteWatch)(SELF, (char *)p + 1, 0x1000);
    t_note("reset unaligned base: %08lx", (ULONG)s);
    VirtualFree(p, 0, MEM_RELEASE);
    /* not a write-watch region */
    p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p) {
        EXPECT_EQ(UN(ZwResetWriteWatch)(SELF, p, 0x1000), S(0xc00000ef)); /* STATUS_INVALID_PARAMETER_1 */
        VirtualFree(p, 0, MEM_RELEASE);
    }
    EXPECT_EQ(UN(ZwResetWriteWatch)(NULL, addrs, 0x1000), BAD_HANDLE);
}

/* ---------------- threads ---------------- */
/* The thread reports that it has left the loader (thread attach) before the test terminates it: killing a thread
   inside its start-up would leave the loader lock owned. */
static DWORD WINAPI idle_thread(PVOID p) { if (p) InterlockedExchange((volatile LONG *)p, 1); Sleep(60000); return 0; }
static void wait_started(volatile LONG *f) { int i; for (i = 0; i < 1000 && !*f; i++) Sleep(10); }
static int thread_suspend_count(HANDLE th)
{
    ULONG c = 0xfff;
    if (!UN(NtQueryInformationThread) || UN(NtQueryInformationThread)(th, 35 /* ThreadSuspendCount */, &c, sizeof c, NULL) < 0) return -1;
    return (int)c;
}

TEST(zw_suspend_resume_thread)
{
    HANDLE th; ULONG prev; DWORD code; static volatile LONG started;
    REQUIRE(UN(ZwSuspendThread)); REQUIRE(UN(ZwResumeThread));
    started = 0;
    th = CreateThread(NULL, 0, idle_thread, (PVOID)&started, CREATE_SUSPENDED, NULL);
    if (!th) { t_skip("CreateThread failed"); return; }
    /* created suspended: count 1 */
    prev = 77; EXPECT_EQ(UN(ZwSuspendThread)(th, &prev), 0); EXPECT_EQ(prev, 1);
    prev = 77; EXPECT_EQ(UN(ZwSuspendThread)(th, &prev), 0); EXPECT_EQ(prev, 2);
    EXPECT_EQ(UN(ZwSuspendThread)(th, NULL), 0);
    { int c = thread_suspend_count(th); if (c >= 0) EXPECT_EQ(c, 4); }
    prev = 77; EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 4);
    EXPECT_EQ(UN(ZwResumeThread)(th, NULL), 0);
    prev = 77; EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 2);
    prev = 77; EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 1);
    wait_started(&started);
    CHECK(started);
    /* now running: resume is a no-op that reports 0 */
    prev = 77; EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 0);
    /* suspend/resume cycle of a running thread */
    prev = 77; EXPECT_EQ(UN(ZwSuspendThread)(th, &prev), 0); EXPECT_EQ(prev, 0);
    prev = 77; EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 1);
    /* errors */
    prev = 77;
    EXPECT_EQ(UN(ZwSuspendThread)(NULL, &prev), BAD_HANDLE); EXPECT_EQ(prev, 77);
    EXPECT_EQ(UN(ZwResumeThread)(NULL, &prev), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSuspendThread)((HANDLE)(ULONG_PTR)0x7ffffff4, &prev), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSuspendThread)(GetCurrentProcess(), &prev), WRONG_TYPE);
    EXPECT_EQ(UN(ZwResumeThread)(GetCurrentProcess(), &prev), WRONG_TYPE);
    /* without THREAD_SUSPEND_RESUME */
    { HANDLE ro = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetThreadId(th));
      if (ro) { EXPECT_EQ(UN(ZwSuspendThread)(ro, &prev), DENIED); EXPECT_EQ(UN(ZwResumeThread)(ro, &prev), DENIED); CloseHandle(ro); } }
    /* terminate then suspend: terminated thread cannot be suspended */
    EXPECT_EQ(UN(ZwTerminateThread)(th, S(0x1234)), 0);
    WaitForSingleObject(th, 10000);
    GetExitCodeThread(th, &code);
    EXPECT_EQ(code, 0x1234);
    prev = 77;
    EXPECT_EQ(UN(ZwSuspendThread)(th, &prev), S(0xc000004b)); /* STATUS_THREAD_IS_TERMINATING */
    EXPECT_EQ(UN(ZwResumeThread)(th, &prev), 0);
    CloseHandle(th);
}

TEST(zw_terminate_thread)
{
    HANDLE th; DWORD code; NTSTATUS s; static volatile LONG started, started2;
    REQUIRE(UN(ZwTerminateThread));
    started = started2 = 0;
    th = CreateThread(NULL, 0, idle_thread, (PVOID)&started, 0, NULL);
    if (!th) { t_skip("CreateThread failed"); return; }
    wait_started(&started);
    EXPECT_EQ(UN(ZwTerminateThread)(th, S(0xc0001234)), 0);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    GetExitCodeThread(th, &code);
    EXPECT_EQ(code, 0xc0001234);
    s = UN(ZwTerminateThread)(th, 1);
    EXPECT_EQ(s, 0); /* observed: terminating an already terminated thread still succeeds */
    GetExitCodeThread(th, &code);
    EXPECT_EQ(code, 0xc0001234);
    CloseHandle(th);
    /* a thread handle without THREAD_TERMINATE */
    th = CreateThread(NULL, 0, idle_thread, (PVOID)&started2, 0, NULL);
    if (th) {
        HANDLE ro = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetThreadId(th));
        if (ro) { EXPECT_EQ(UN(ZwTerminateThread)(ro, 5), DENIED); CloseHandle(ro); }
        wait_started(&started2);
        TerminateThread(th, 0); WaitForSingleObject(th, 10000); CloseHandle(th);
    }
    EXPECT_EQ(UN(ZwTerminateThread)((HANDLE)(ULONG_PTR)0x7ffffff4, 5), BAD_HANDLE);
    EXPECT_EQ(UN(ZwTerminateThread)(GetCurrentProcess(), 5), WRONG_TYPE);
}

/* ---------------- processes ---------------- */
TEST(zw_suspend_resume_process)
{
    PROCESS_INFORMATION pi; HANDLE hp; DWORD tid_count_before;
    REQUIRE(UN(ZwSuspendProcess)); REQUIRE(UN(ZwResumeProcess));
    hp = mk_child(&pi, 0);
    if (!hp) { t_skip("child spawn failed"); return; }
    Sleep(200);
    EXPECT_EQ(UN(ZwSuspendProcess)(hp), 0);
    { int c = thread_suspend_count(pi.hThread); if (c >= 0) EXPECT_EQ(c, 1); }
    EXPECT_EQ(UN(ZwSuspendProcess)(hp), 0);
    { int c = thread_suspend_count(pi.hThread); if (c >= 0) EXPECT_EQ(c, 2); }
    EXPECT_EQ(UN(ZwResumeProcess)(hp), 0);
    { int c = thread_suspend_count(pi.hThread); if (c >= 0) EXPECT_EQ(c, 1); }
    EXPECT_EQ(UN(ZwResumeProcess)(hp), 0);
    { int c = thread_suspend_count(pi.hThread); if (c >= 0) EXPECT_EQ(c, 0); }
    /* access: query-limited only */
    { HANDLE ro = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
      if (ro) { EXPECT_EQ(UN(ZwSuspendProcess)(ro), DENIED); EXPECT_EQ(UN(ZwResumeProcess)(ro), DENIED); CloseHandle(ro); } }
    EXPECT_EQ(UN(ZwSuspendProcess)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwResumeProcess)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSuspendProcess)(pi.hThread), WRONG_TYPE);
    EXPECT_EQ(UN(ZwResumeProcess)(pi.hThread), WRONG_TYPE);
    kill_child(&pi);
}

TEST(zw_terminate_process)
{
    PROCESS_INFORMATION pi; HANDLE hp; DWORD code;
    REQUIRE(UN(ZwTerminateProcess));
    hp = mk_child(&pi, 0);
    if (!hp) { t_skip("child spawn failed"); return; }
    /* handle lacking PROCESS_TERMINATE */
    { HANDLE ro = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
      if (ro) { EXPECT_EQ(UN(ZwTerminateProcess)(ro, 9), DENIED); CloseHandle(ro); } }
    EXPECT_EQ(WaitForSingleObject(hp, 0), WAIT_TIMEOUT);
    EXPECT_EQ(UN(ZwTerminateProcess)(pi.hThread, 9), WRONG_TYPE);
    EXPECT_EQ(UN(ZwTerminateProcess)((HANDLE)(ULONG_PTR)0x7ffffff4, 9), BAD_HANDLE);
    EXPECT_EQ(UN(ZwTerminateProcess)(hp, S(0xc0000005)), 0);
    EXPECT_EQ(WaitForSingleObject(hp, 15000), WAIT_OBJECT_0);
    GetExitCodeProcess(hp, &code);
    EXPECT_EQ(code, 0xc0000005);
    EXPECT_EQ(UN(ZwTerminateProcess)(hp, 1), S(0xc000010a)); /* STATUS_PROCESS_IS_TERMINATING */
    GetExitCodeProcess(hp, &code);
    EXPECT_EQ(code, 0xc0000005);
    kill_child(&pi);
}

TEST(zw_terminate_job_object)
{
    PROCESS_INFORMATION pi; HANDLE hp, job = NULL; DWORD code; NTSTATUS s;
    REQUIRE(UN(ZwTerminateJobObject)); REQUIRE(UN(NtCreateJobObject)); REQUIRE(UN(NtAssignProcessToJobObject));
    hp = mk_child(&pi, CREATE_SUSPENDED);
    if (!hp) { t_skip("child spawn failed"); return; }
    s = UN(NtCreateJobObject)(&job, JOB_OBJECT_ALL_ACCESS, NULL);
    if (s < 0) { t_skip("job creation failed %08lx", (ULONG)s); kill_child(&pi); return; }
    s = UN(NtAssignProcessToJobObject)(job, hp);
    if (s < 0) { t_skip("assign to job failed %08lx", (ULONG)s); cl(job); kill_child(&pi); return; }
    EXPECT_EQ(UN(ZwTerminateJobObject)(NULL, 1), BAD_HANDLE);
    EXPECT_EQ(UN(ZwTerminateJobObject)((HANDLE)(ULONG_PTR)0x7ffffff4, 1), BAD_HANDLE);
    EXPECT_EQ(UN(ZwTerminateJobObject)(hp, 1), WRONG_TYPE);
    EXPECT_EQ(WaitForSingleObject(hp, 0), WAIT_TIMEOUT);
    /* handle duplicate without JOB_OBJECT_TERMINATE */
    { HANDLE dup = NULL;
      if (DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &dup, JOB_OBJECT_QUERY, FALSE, 0)) {
          EXPECT_EQ(UN(ZwTerminateJobObject)(dup, 1), DENIED); CloseHandle(dup); } }
    EXPECT_EQ(WaitForSingleObject(hp, 0), WAIT_TIMEOUT);
    EXPECT_EQ(UN(ZwTerminateJobObject)(job, S(0x4d2)), 0);
    EXPECT_EQ(WaitForSingleObject(hp, 15000), WAIT_OBJECT_0);
    GetExitCodeProcess(hp, &code);
    EXPECT_EQ(code, 0x4d2);
    /* terminating an empty job is still a success */
    EXPECT_EQ(UN(ZwTerminateJobObject)(job, 3), 0);
    cl(job);
    kill_child(&pi);
}

/* ---------------- sections ---------------- */
TEST(zw_unmap_view_of_section)
{
    HANDLE sec = NULL; PVOID base = NULL; SIZE_T vsz = 0; LARGE_INTEGER max; NTSTATUS s; MEMORY_BASIC_INFORMATION mbi;
    REQUIRE(UN(ZwUnmapViewOfSection)); REQUIRE(UN(NtCreateSection)); REQUIRE(UN(NtMapViewOfSection));
    max.QuadPart = 0x4000;
    s = UN(NtCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, &max, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (s < 0) { t_skip("section creation failed %08lx", (ULONG)s); return; }
    s = UN(NtMapViewOfSection)(sec, SELF, &base, 0, 0, NULL, &vsz, 1 /* ViewShare */, 0, PAGE_READWRITE);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        *(volatile char *)base = 7;
        EXPECT_EQ(VirtualQuery(base, &mbi, sizeof mbi), sizeof mbi);
        EXPECT_EQ(mbi.Type, MEM_MAPPED);
        /* any address inside the view selects (and removes) the whole view */
        EXPECT_EQ(UN(ZwUnmapViewOfSection)(SELF, (char *)base + 0x1000), 0);
        EXPECT_EQ(VirtualQuery(base, &mbi, sizeof mbi), sizeof mbi);
        EXPECT_EQ(mbi.State, MEM_FREE);
        EXPECT_EQ(UN(ZwUnmapViewOfSection)(SELF, base), S(0xc0000019));
    }
    /* private allocation is not a section view */
    { PVOID p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      if (p) { EXPECT_EQ(UN(ZwUnmapViewOfSection)(SELF, p), S(0xc0000019)); VirtualFree(p, 0, MEM_RELEASE); } }
    EXPECT_EQ(UN(ZwUnmapViewOfSection)(NULL, base), BAD_HANDLE);
    EXPECT_EQ(UN(ZwUnmapViewOfSection)(GetCurrentThread(), base), WRONG_TYPE);
    { HANDLE ro = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
      if (ro) { EXPECT_EQ(UN(ZwUnmapViewOfSection)(ro, (PVOID)0x10000), DENIED); CloseHandle(ro); } }
    cl(sec);
}

TEST(zw_unmap_view_of_section_ex)
{
    HANDLE sec = NULL; PVOID base = NULL; SIZE_T vsz = 0; LARGE_INTEGER max; NTSTATUS s;
    REQUIRE(UN(ZwUnmapViewOfSectionEx)); REQUIRE(UN(NtCreateSection)); REQUIRE(UN(NtMapViewOfSection));
    max.QuadPart = 0x2000;
    s = UN(NtCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, &max, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (s < 0) { t_skip("section creation failed %08lx", (ULONG)s); return; }
    s = UN(NtMapViewOfSection)(sec, SELF, &base, 0, 0, NULL, &vsz, 1, 0, PAGE_READWRITE);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        /* undefined flag bits are rejected before the unmap happens */
        EXPECT_EQ(UN(ZwUnmapViewOfSectionEx)(SELF, base, 0x80000000), S(0xc00000f1)); /* STATUS_INVALID_PARAMETER_3 */
        EXPECT_EQ(UN(ZwUnmapViewOfSectionEx)(SELF, (char *)base + 0x1000, 0), 0);   /* any address inside the view */
        EXPECT_EQ(UN(ZwUnmapViewOfSectionEx)(SELF, base, 0), S(0xc0000019));
    }
    /* MEM_UNMAP_WITH_TRANSIENT_BOOST (0x1) */
    base = NULL; vsz = 0;
    s = UN(NtMapViewOfSection)(sec, SELF, &base, 0, 0, NULL, &vsz, 1, 0, PAGE_READWRITE);
    if (s == 0) { EXPECT_EQ(UN(ZwUnmapViewOfSectionEx)(SELF, base, 1), 0); }
    EXPECT_EQ(UN(ZwUnmapViewOfSectionEx)(NULL, base, 0), BAD_HANDLE);
    cl(sec);
}

/* ---------------- debug objects ---------------- */
TEST(zw_debug_object_services)
{
    HANDLE dbg = NULL; PROCESS_INFORMATION pi; HANDLE hp; NTSTATUS s; LARGE_INTEGER z = {0}; BYTE state[256];
    REQUIRE(UN(ZwRemoveProcessDebug)); REQUIRE(UN(ZwWaitForDebugEvent));
    REQUIRE(UN(NtCreateDebugObject)); REQUIRE(UN(NtDebugActiveProcess));
    s = UN(NtCreateDebugObject)(&dbg, 0x1f000f /* DEBUG_ALL_ACCESS */, NULL, 0);
    if (s < 0) { t_skip("debug object creation failed %08lx", (ULONG)s); return; }
    /* empty queue */
    memset(state, 0xcc, sizeof state);
    EXPECT_EQ(UN(ZwWaitForDebugEvent)(dbg, FALSE, &z, state), S(0x102));
    EXPECT_EQ(UN(ZwWaitForDebugEvent)(NULL, FALSE, &z, state), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWaitForDebugEvent)((HANDLE)(ULONG_PTR)0x7ffffff4, FALSE, &z, state), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWaitForDebugEvent)(GetCurrentProcess(), FALSE, &z, state), WRONG_TYPE);
    hp = mk_child(&pi, CREATE_SUSPENDED);
    if (!hp) { t_skip("child spawn failed"); cl(dbg); return; }
    EXPECT_EQ(UN(ZwRemoveProcessDebug)(hp, dbg), S(0xc0000353)); /* STATUS_PORT_NOT_SET: not being debugged */
    EXPECT_EQ(UN(ZwRemoveProcessDebug)(NULL, dbg), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRemoveProcessDebug)(hp, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRemoveProcessDebug)(dbg, hp), WRONG_TYPE);
    s = UN(NtDebugActiveProcess)(hp, dbg);
    if (s < 0) { t_skip("attach failed %08lx", (ULONG)s); }
    else {
        memset(state, 0xcc, sizeof state);
        s = UN(ZwWaitForDebugEvent)(dbg, FALSE, &z, state);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            ULONG newstate = *(ULONG *)state;
            t_note("first debug wait-state-change NewState=%lu", newstate);
            EXPECT_EQ(newstate, 3); /* DbgCreateProcessStateChange */
        }
        EXPECT_EQ(UN(ZwRemoveProcessDebug)(hp, dbg), 0);
        /* detached: a second removal reports that no port is set */
        EXPECT_EQ(UN(ZwRemoveProcessDebug)(hp, dbg), S(0xc0000353));
    }
    kill_child(&pi);
    cl(dbg);
}

/* ---------------- files ---------------- */
static HANDLE mk_file(char *path, size_t cap, const char *leaf, DWORD access, DWORD flags)
{
    HANDLE h;
    t_tmpfile(path, cap, leaf);
    h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, flags, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}

TEST(zw_write_file)
{
    char path[MAX_PATH], buf[64]; HANDLE h, ro; IO_STATUS_BLOCK io; LARGE_INTEGER off; DWORD n; NTSTATUS s;
    REQUIRE(UN(ZwWriteFile));
    h = mk_file(path, sizeof path, "zw_write_file.tmp", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_ATTRIBUTE_NORMAL);
    if (!h) { t_skip("scratch file creation failed"); return; }
    memset(&io, 0xcc, sizeof io);
    s = UN(ZwWriteFile)(h, NULL, NULL, NULL, &io, "abcdefgh", 8, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 8);
    /* synchronous handle: file pointer advances */
    EXPECT_EQ(SetFilePointer(h, 0, NULL, FILE_CURRENT), 8);
    off.QuadPart = 2;
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(ZwWriteFile)(h, NULL, NULL, NULL, &io, "XY", 2, &off, NULL), 0);
    EXPECT_EQ(io.Information, 2);
    off.QuadPart = -1; /* FILE_WRITE_TO_END_OF_FILE = {0xffffffff, -1} */
    off.LowPart = 0xffffffff; off.HighPart = -1;
    EXPECT_EQ(UN(ZwWriteFile)(h, NULL, NULL, NULL, &io, "END", 3, &off, NULL), 0);
    EXPECT_EQ(io.Information, 3);
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    memset(buf, 0, sizeof buf);
    CHECK(ReadFile(h, buf, 11, &n, NULL)); EXPECT_EQ(n, 11);
    EXPECT_STR(buf, "abXYefghEND");
    /* zero-length write succeeds with zero information */
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(ZwWriteFile)(h, NULL, NULL, NULL, &io, buf, 0, NULL, NULL), 0);
    EXPECT_EQ(io.Information, 0);
    /* FILE_USE_FILE_POINTER_POSITION = {FILE_USE_FILE_POINTER_POSITION low 0xfffffffe, -1} */
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    off.LowPart = 0xfffffffe; off.HighPart = -1;
    EXPECT_EQ(UN(ZwWriteFile)(h, NULL, NULL, NULL, &io, "Q", 1, &off, NULL), 0);
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    CHECK(ReadFile(h, buf, 3, &n, NULL)); buf[3] = 0;
    EXPECT_STR(buf, "QbX");
    /* read-only handle */
    ro = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (ro != INVALID_HANDLE_VALUE) {
        memset(&io, 0xcc, sizeof io);
        EXPECT_EQ(UN(ZwWriteFile)(ro, NULL, NULL, NULL, &io, "no", 2, NULL, NULL), DENIED);
        CloseHandle(ro);
    }
    EXPECT_EQ(UN(ZwWriteFile)(NULL, NULL, NULL, NULL, &io, "no", 2, NULL, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWriteFile)((HANDLE)(ULONG_PTR)0x7ffffff4, NULL, NULL, NULL, &io, "no", 2, NULL, NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwWriteFile)(GetCurrentProcess(), NULL, NULL, NULL, &io, "no", 2, NULL, NULL), BAD_HANDLE);
    CloseHandle(h);
    DeleteFileA(path);
}

TEST(zw_unlock_file)
{
    char path[MAX_PATH]; HANDLE h; IO_STATUS_BLOCK io; LARGE_INTEGER off, len; NTSTATUS s;
    REQUIRE(UN(ZwUnlockFile)); REQUIRE(UN(NtLockFile));
    h = mk_file(path, sizeof path, "zw_unlock_file.tmp", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_ATTRIBUTE_NORMAL);
    if (!h) { t_skip("scratch file creation failed"); return; }
    off.QuadPart = 0; len.QuadPart = 100;
    memset(&io, 0xcc, sizeof io);
    s = UN(NtLockFile)(h, NULL, NULL, NULL, &io, &off, &len, 5, TRUE, TRUE);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        /* wrong key / wrong range */
        EXPECT_EQ(UN(ZwUnlockFile)(h, &io, &off, &len, 6), S(0xc000007e)); /* STATUS_RANGE_NOT_LOCKED */
        { LARGE_INTEGER l2; l2.QuadPart = 50; EXPECT_EQ(UN(ZwUnlockFile)(h, &io, &off, &l2, 5), S(0xc000007e)); }
        memset(&io, 0xcc, sizeof io);
        EXPECT_EQ(UN(ZwUnlockFile)(h, &io, &off, &len, 5), 0);
        EXPECT_EQ(io.Status, 0);
        EXPECT_EQ(UN(ZwUnlockFile)(h, &io, &off, &len, 5), S(0xc000007e));
    }
    /* never locked */
    off.QuadPart = 4096;
    EXPECT_EQ(UN(ZwUnlockFile)(h, &io, &off, &len, 0), S(0xc000007e));
    EXPECT_EQ(UN(ZwUnlockFile)(NULL, &io, &off, &len, 0), BAD_HANDLE);
    EXPECT_EQ(UN(ZwUnlockFile)(GetCurrentProcess(), &io, &off, &len, 0), WRONG_TYPE);
    CloseHandle(h);
    DeleteFileA(path);
}

TEST(zw_write_file_gather)
{
    char path[MAX_PATH]; HANDLE h, ev = NULL; IO_STATUS_BLOCK io; LARGE_INTEGER off; NTSTATUS s; char *pg;
    ULONG64 seg[2]; DWORD n; ULONG i; char *rd;
    REQUIRE(UN(ZwWriteFileGather)); REQUIRE(UN(NtCreateEvent));
    h = mk_file(path, sizeof path, "zw_write_gather.tmp", GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED);
    if (!h) { t_skip("unbuffered overlapped scratch file creation failed (%lu)", GetLastError()); return; }
    pg = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    rd = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pg || !rd || UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 1, FALSE) < 0) {
        t_skip("buffer/event setup failed"); goto out;
    }
    memset(pg, 'A', 0x1000); memset(pg + 0x1000, 'B', 0x1000);
    seg[0] = (ULONG64)(ULONG_PTR)pg; seg[1] = (ULONG64)(ULONG_PTR)(pg + 0x1000);
    off.QuadPart = 0;
    memset(&io, 0xcc, sizeof io);
    s = UN(ZwWriteFileGather)(h, ev, NULL, NULL, &io, seg, 0x2000, &off, NULL);
    CHECKF(s == 0 || s == S(0x103), "gather write status %08lx", (ULONG)s);
    if (s == S(0x103)) { EXPECT_EQ(WaitForSingleObject(ev, 15000), WAIT_OBJECT_0); }
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0x2000);
    /* read back with the Win32 path */
    { OVERLAPPED ov; memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
      if (ReadFile(h, rd, 0x2000, NULL, &ov) || GetLastError() == ERROR_IO_PENDING) {
          CHECK(GetOverlappedResult(h, &ov, &n, TRUE)); EXPECT_EQ(n, 0x2000);
          for (i = 0; i < 0x1000; i++) if (rd[i] != 'A' || rd[0x1000 + i] != 'B') break;
          EXPECT_EQ(i, 0x1000);
      }
      CloseHandle(ov.hEvent); }
    /* length not a multiple of the sector size */
    memset(&io, 0xcc, sizeof io);
    s = UN(ZwWriteFileGather)(h, ev, NULL, NULL, &io, seg, 0x1001, &off, NULL);
    EXPECT_EQ(s, BAD_PARAM);
    /* missing byte offset on an overlapped handle */
    s = UN(ZwWriteFileGather)(h, ev, NULL, NULL, &io, seg, 0x1000, NULL, NULL);
    EXPECT_EQ(s, BAD_PARAM);
    s = UN(ZwWriteFileGather)(NULL, ev, NULL, NULL, &io, seg, 0x1000, &off, NULL);
    EXPECT_EQ(s, BAD_HANDLE);
out:
    if (ev) cl(ev);
    if (pg) VirtualFree(pg, 0, MEM_RELEASE);
    if (rd) VirtualFree(rd, 0, MEM_RELEASE);
    CloseHandle(h);
    DeleteFileA(path);
}

/* ---------------- enclave / container ---------------- */
TEST(zw_terminate_enclave)
{
    PVOID p; NTSTATUS s;
    REQUIRE(UN(ZwTerminateEnclave));
    p = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc failed"); return; }
    s = UN(ZwTerminateEnclave)(p, TRUE);
    t_note("terminate enclave on a regular allocation: %08lx", (ULONG)s);
    EXPECT_EQ(s, S(0xc0000018)); /* STATUS_CONFLICTING_ADDRESSES: allocation is not an enclave */
    s = UN(ZwTerminateEnclave)((PVOID)0x10000, FALSE);
    EXPECT_EQ(s, S(0xc00000a0)); /* STATUS_MEMORY_NOT_ALLOCATED */
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(zw_revert_container_impersonation)
{
    NTSTATUS s;
    REQUIRE(UN(ZwRevertContainerImpersonation));
    s = UN(ZwRevertContainerImpersonation)();
    EXPECT_EQ(s, S(0xc0000001)); /* STATUS_UNSUCCESSFUL: no container impersonation active */
}
