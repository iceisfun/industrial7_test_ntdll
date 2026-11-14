/* Open services for processes, threads and their tokens; thread and process creation primitives. */
#include "cob.h"

UDECL(NTSTATUS, ZwOpenProcess, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID));
UDECL(NTSTATUS, ZwOpenThread, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID));
UDECL(NTSTATUS, ZwOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, ZwOpenProcessTokenEx, (HANDLE, ACCESS_MASK, ULONG, PHANDLE));
UDECL(NTSTATUS, ZwOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, ZwOpenThreadTokenEx, (HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, ZwCreateThreadEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, ZwCreateThread, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PVOID, PVOID, BOOLEAN));
UDECL(NTSTATUS, ZwCreateProcessEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, ZwCreateProcess, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, ZwCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define NEEDP() do { REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); } while (0)
#define TOKEN_QUERY_ 0x8
#define S_INVCID ((NTSTATUS)0xC000000B)
#define S_INVMIX ((NTSTATUS)0xC0000030)
#define S_NOTOKEN ((NTSTATUS)0xC000007C)
#define S_BADIMPL ((NTSTATUS)0xC00000A5)

TEST(nt_create_open_b_open_process)
{
    HANDLE h = NULL; CLIENT_ID cid; OBJECT_ATTRIBUTES oa; NTSTATUS s; WCHAR tn[40]; ULONG g = 0;
    NEEDP(); REQUIRE(UN(ZwOpenProcess)); COB_ALIAS("OpenProcess");
    cob_oa(&oa, NULL, 0, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid.UniqueThread = NULL;
    s = UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, &oa, &cid); EXPECT_EQ(s, S_OK_);
    if (h) {
        CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Process");
        EXPECT_EQ(GetProcessId(h), GetCurrentProcessId());
        CHECK(cob_granted(h, &g)); EXPECT_EQ(g & (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE), PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
        EXPECT_EQ(g & PROCESS_TERMINATE, 0);
        cob_close(h); h = NULL;
    }
    /* handle attributes: OBJ_INHERIT is reflected in the handle flags */
    oa.Attributes = 0x2;
    s = UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_OK_);
    if (h) { DWORD f = 0; CHECK(GetHandleInformation(h, &f)); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT); cob_close(h); h = NULL; }
    oa.Attributes = 0;
    /* errors */
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0xfffffff0; s = UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_INVCID); EXPECT_EQ(h, NULL);
    cid.UniqueProcess = NULL; s = UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_INVCID);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    EXPECT_EQ(UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, NULL), S_INVMIX);
    EXPECT_EQ(UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, NULL, &cid), S_AV);
    EXPECT_EQ(UN(ZwOpenProcess)(NULL, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid), S_AV);
    { UNICODE_STRING u; cob_us(&u, L"\\x"); cob_oa(&oa, &u, 0, NULL); EXPECT_EQ(UN(ZwOpenProcess)(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid), S_INVMIX); }
    /* the System process refuses full access to non-system callers */
    cob_oa(&oa, NULL, 0, NULL); cid.UniqueProcess = (HANDLE)(ULONG_PTR)4;
    s = UN(ZwOpenProcess)(&h, PROCESS_ALL_ACCESS, &oa, &cid); EXPECT_EQ(s, S_DENIED); cob_close(h);
}

TEST(nt_create_open_b_open_thread)
{
    HANDLE h = NULL; CLIENT_ID cid; OBJECT_ATTRIBUTES oa; NTSTATUS s; WCHAR tn[40]; DWORD tid = GetCurrentThreadId();
    NEEDP(); REQUIRE(UN(ZwOpenThread)); COB_ALIAS("OpenThread");
    cob_oa(&oa, NULL, 0, NULL);
    cid.UniqueProcess = NULL; cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
    s = UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_OK_);
    if (h) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Thread"); EXPECT_EQ(GetThreadId(h), tid); cob_close(h); h = NULL; }
    /* matching process id is verified */
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    s = UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0xfffffff0;
    s = UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_INVCID); EXPECT_EQ(h, NULL);
    cid.UniqueProcess = NULL; cid.UniqueThread = (HANDLE)(ULONG_PTR)0xfffffff0;
    s = UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_INVCID);
    cid.UniqueThread = NULL; s = UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid); EXPECT_EQ(s, S_INVCID);
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;
    EXPECT_EQ(UN(ZwOpenThread)(&h, THREAD_QUERY_LIMITED_INFORMATION, &oa, NULL), S_INVMIX);
    EXPECT_EQ(UN(ZwOpenThread)(NULL, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid), S_AV);
}

static HANDLE open_ptoken(ACCESS_MASK a) { HANDLE t = NULL; if (UN(ZwOpenProcessToken)(GetCurrentProcess(), a, &t) != 0) return NULL; return t; }

TEST(nt_create_open_b_process_token)
{
    HANDLE t = NULL; NTSTATUS s; WCHAR tn[40]; ULONG g = 0, ret = 0, v;
    NEEDP(); REQUIRE(UN(ZwOpenProcessToken)); REQUIRE(UN(ZwOpenProcessTokenEx)); REQUIRE(UN(NtQueryInformationToken));
    COB_ALIAS("OpenProcessToken"); COB_ALIAS("OpenProcessTokenEx");
    s = UN(ZwOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY_, &t); EXPECT_EQ(s, S_OK_);
    if (t) {
        CHECK(cob_typename(t, tn, 40)); EXPECT_WSTR(tn, L"Token");
        CHECK(cob_granted(t, &g)); EXPECT_EQ(g & 0xffff, TOKEN_QUERY_);
        v = 0xcc; EXPECT_EQ(UN(NtQueryInformationToken)(t, 8 /* TokenType */, &v, sizeof v, &ret), S_OK_); EXPECT_EQ(v, 1 /* TokenPrimary */);
        cob_close(t); t = NULL;
    }
    /* Ex: handle attributes */
    s = UN(ZwOpenProcessTokenEx)(GetCurrentProcess(), TOKEN_QUERY_, 0x2 /* OBJ_INHERIT */, &t); EXPECT_EQ(s, S_OK_);
    if (t) { DWORD f = 0; CHECK(GetHandleInformation(t, &f)); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT); cob_close(t); t = NULL; }
    s = UN(ZwOpenProcessTokenEx)(GetCurrentProcess(), TOKEN_QUERY_, 0, &t); EXPECT_EQ(s, S_OK_);
    if (t) { DWORD f = 0; CHECK(GetHandleInformation(t, &f)); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, 0); cob_close(t); t = NULL; }
    /* MAXIMUM_ALLOWED yields at least query and duplicate rights */
    s = UN(ZwOpenProcessToken)(GetCurrentProcess(), MAXIMUM_ALLOWED, &t); EXPECT_EQ(s, S_OK_);
    if (t) { CHECK(cob_granted(t, &g)); CHECK((g & (TOKEN_QUERY_ | TOKEN_DUPLICATE)) == (TOKEN_QUERY_ | TOKEN_DUPLICATE)); cob_close(t); t = NULL; }
    /* errors */
    t = (HANDLE)0x1234;
    EXPECT_EQ(UN(ZwOpenProcessToken)(NULL, TOKEN_QUERY_, &t), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenProcessToken)((HANDLE)(ULONG_PTR)0x7ffffff0, TOKEN_QUERY_, &t), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenProcessToken)(GetCurrentThread(), TOKEN_QUERY_, &t), S_TYPEMM);
    EXPECT_EQ(UN(ZwOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY_, NULL), S_AV);
    EXPECT_EQ(UN(ZwOpenProcessTokenEx)(GetCurrentProcess(), TOKEN_QUERY_, 0, NULL), S_AV);
    EXPECT_EQ(UN(ZwOpenProcessTokenEx)(NULL, TOKEN_QUERY_, 0, &t), S_INVHANDLE);
    /* access bits that no token grants */
    s = UN(ZwOpenProcessToken)(GetCurrentProcess(), 0x00800000, &t); EXPECT_EQ(s, S_DENIED);
    /* a process handle without PROCESS_QUERY_INFORMATION cannot yield a token */
    { HANDLE lim = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
      if (lim) { t = NULL; EXPECT_EQ(UN(ZwOpenProcessToken)(lim, TOKEN_QUERY_, &t), S_DENIED); cob_close(t); CloseHandle(lim); } }
}

TEST(nt_create_open_b_thread_token)
{
    HANDLE t = NULL, imp = NULL, base = NULL; NTSTATUS s; WCHAR tn[40]; ULONG ret = 0, v = 0; OBJECT_ATTRIBUTES oa;
    NEEDP(); REQUIRE(UN(ZwOpenThreadToken)); REQUIRE(UN(ZwOpenThreadTokenEx)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtSetInformationThread)); REQUIRE(UN(ZwOpenProcessToken));
    COB_ALIAS("OpenThreadToken"); COB_ALIAS("OpenThreadTokenEx");
    /* no impersonation: no token */
    t = (HANDLE)0x1234;
    EXPECT_EQ(UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, FALSE, &t), S_NOTOKEN);
    EXPECT_EQ(UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, TRUE, &t), S_NOTOKEN);
    EXPECT_EQ(UN(ZwOpenThreadTokenEx)(GetCurrentThread(), TOKEN_QUERY_, FALSE, 0, &t), S_NOTOKEN);
    /* impersonate with a duplicate of the process token */
    s = UN(ZwOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY_, &base); EXPECT_EQ(s, S_OK_); if (!base) return;
    cob_oa(&oa, NULL, 0, NULL);
    { struct { ULONG len; ULONG level; BYTE tracking, effective; } sqos; SECURITY_QUALITY_OF_SERVICE q; memset(&q, 0, sizeof q); q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation;
      oa.SecurityQualityOfService = &q;
      s = UN(NtDuplicateToken)(base, TOKEN_ALL_ACCESS, &oa, FALSE, 2 /* TokenImpersonation */, &imp); EXPECT_EQ(s, S_OK_); }
    if (imp) {
        s = UN(NtSetInformationThread)(GetCurrentThread(), 5 /* ThreadImpersonationToken */, &imp, sizeof imp); EXPECT_EQ(s, S_OK_);
        if (s == S_OK_) {
            s = UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, FALSE, &t); EXPECT_EQ(s, S_OK_);
            if (t) { CHECK(cob_typename(t, tn, 40)); EXPECT_WSTR(tn, L"Token"); v = 0; EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, &v, sizeof v, &ret), S_OK_); EXPECT_EQ(v, 2); cob_close(t); t = NULL; }
            s = UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, TRUE, &t); EXPECT_EQ(s, S_OK_); cob_close(t); t = NULL;
            s = UN(ZwOpenThreadTokenEx)(GetCurrentThread(), TOKEN_QUERY_, FALSE, 0x2, &t); EXPECT_EQ(s, S_OK_);
            if (t) { DWORD f = 0; CHECK(GetHandleInformation(t, &f)); EXPECT_EQ(f & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT); cob_close(t); t = NULL; }
            s = UN(ZwOpenThreadTokenEx)(GetCurrentThread(), TOKEN_QUERY_, TRUE, 0, &t); EXPECT_EQ(s, S_OK_); cob_close(t); t = NULL;
            /* access the impersonation token does not grant to the caller's identity is checked against the token's DACL */
            EXPECT_EQ(UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, FALSE, NULL), S_AV);
            { HANDLE nul = NULL; UN(NtSetInformationThread)(GetCurrentThread(), 5, &nul, sizeof nul); }
        }
        cob_close(imp);
    }
    EXPECT_EQ(UN(ZwOpenThreadToken)(GetCurrentThread(), TOKEN_QUERY_, FALSE, &t), S_NOTOKEN);
    EXPECT_EQ(UN(ZwOpenThreadToken)(NULL, TOKEN_QUERY_, FALSE, &t), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenThreadToken)(GetCurrentProcess(), TOKEN_QUERY_, FALSE, &t), S_TYPEMM);
    EXPECT_EQ(UN(ZwOpenThreadTokenEx)(NULL, TOKEN_QUERY_, FALSE, 0, &t), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenThreadTokenEx)(GetCurrentProcess(), TOKEN_QUERY_, FALSE, 0, &t), S_TYPEMM);
    cob_close(base);
}

static volatile LONG g_thread_ran, g_thread_arg;
static ULONG WINAPI thread_main(PVOID arg) { g_thread_arg = (LONG)(ULONG_PTR)arg; InterlockedExchange(&g_thread_ran, 1); return 7; }

TEST(nt_create_open_b_create_thread_ex)
{
    HANDLE h = NULL; NTSTATUS s; ULONG susp = 0xcc; DWORD w, code = 0; WCHAR tn[40];
    NEEDP(); REQUIRE(UN(ZwCreateThreadEx)); REQUIRE(UN(NtResumeThread)); COB_ALIAS("CreateThreadEx");
    g_thread_ran = 0; g_thread_arg = 0;
    /* CREATE_SUSPENDED: the thread does not run until resumed */
    s = UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)thread_main, (PVOID)(ULONG_PTR)0x1234, 1, 0, 0, 0, NULL);
    EXPECT_EQ(s, S_OK_);
    if (h) {
        CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Thread");
        CHECK(GetThreadId(h) != 0); EXPECT_NE(GetThreadId(h), GetCurrentThreadId());
        Sleep(50); EXPECT_EQ(g_thread_ran, 0);
        EXPECT_EQ(UN(NtResumeThread)(h, &susp), S_OK_); EXPECT_EQ(susp, 1);
        w = WaitForSingleObject(h, 10000); EXPECT_EQ(w, WAIT_OBJECT_0);
        EXPECT_EQ(g_thread_ran, 1); EXPECT_EQ(g_thread_arg, 0x1234);
        CHECK(GetExitCodeThread(h, &code)); EXPECT_EQ(code, 7);
        cob_close(h); h = NULL;
    }
    /* not suspended */
    g_thread_ran = 0;
    s = UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)thread_main, (PVOID)(ULONG_PTR)5, 0, 0, 0, 0, NULL);
    EXPECT_EQ(s, S_OK_);
    if (h) { w = WaitForSingleObject(h, 10000); EXPECT_EQ(w, WAIT_OBJECT_0); EXPECT_EQ(g_thread_arg, 5); cob_close(h); h = NULL; }
    /* errors */
    EXPECT_EQ(UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, NULL, (PVOID)thread_main, NULL, 0, 0, 0, 0, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x7ffffff0, (PVOID)thread_main, NULL, 0, 0, 0, 0, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentThread(), (PVOID)thread_main, NULL, 0, 0, 0, 0, NULL), S_TYPEMM);
    EXPECT_EQ(UN(ZwCreateThreadEx)(NULL, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)thread_main, NULL, 0, 0, 0, 0, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)thread_main, NULL, 0xffffff00, 0, 0, 0, NULL), (NTSTATUS)0xC00000F5);
    EXPECT_EQ(UN(ZwCreateThreadEx)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)thread_main, NULL, 0, 0, 0, 0, (PVOID)(ULONG_PTR)8), S_AV);
}

TEST(nt_create_open_b_create_thread_errors)
{
    HANDLE h = NULL; CLIENT_ID cid;
    NEEDP(); REQUIRE(UN(ZwCreateThread)); COB_ALIAS("CreateThread");
    /* without a thread context and initial TEB the legacy entry rejects every call as invalid parameter, before looking at the process handle */
    EXPECT_EQ(UN(ZwCreateThread)(&h, THREAD_ALL_ACCESS, NULL, NULL, &cid, NULL, NULL, TRUE), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateThread)(&h, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x7ffffff0, &cid, NULL, NULL, TRUE), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateThread)(&h, THREAD_ALL_ACCESS, NULL, GetCurrentThread(), &cid, NULL, NULL, TRUE), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateThread)(NULL, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), &cid, NULL, NULL, TRUE), S_INVPARAM);
    EXPECT_EQ(h, NULL);
}

TEST(nt_create_open_b_create_process_ex)
{
    HANDLE sec = NULL, f, ph = NULL; NTSTATUS s; WCHAR tn[40]; OBJECT_ATTRIBUTES oa; DWORD pid;
    NEEDP(); REQUIRE(UN(ZwCreateProcessEx)); REQUIRE(UN(ZwCreateSection)); REQUIRE(UN(NtTerminateProcess)); COB_ALIAS("CreateProcessEx");
    cob_oa(&oa, NULL, 0, NULL);
    f = CreateFileA(t_self_path(), GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    s = UN(ZwCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, 0x1000000 /* SEC_IMAGE */, f); EXPECT_EQ(s, S_OK_);
    CloseHandle(f);
    if (!sec) return;
    s = UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), 0, sec, NULL, NULL, 0);
    EXPECT_EQ(s, S_OK_);
    if (ph) {
        CHECK(cob_typename(ph, tn, 40)); EXPECT_WSTR(tn, L"Process");
        pid = GetProcessId(ph); CHECK(pid != 0); EXPECT_NE(pid, GetCurrentProcessId());
        /* a process created without a thread is still running */
        EXPECT_EQ(WaitForSingleObject(ph, 0), WAIT_TIMEOUT);
        /* terminating a process that has no threads reports STATUS_NOTHING_TO_TERMINATE; the process still goes away on close */
        EXPECT_EQ(UN(NtTerminateProcess)(ph, 0x42), (NTSTATUS)0x122);
        cob_close(ph); ph = NULL;
    }
    /* errors */
    EXPECT_EQ(UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, NULL, 0, sec, NULL, NULL, 0), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, (HANDLE)(ULONG_PTR)0x7ffffff0, 0, sec, NULL, NULL, 0), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, GetCurrentThread(), 0, sec, NULL, NULL, 0), S_TYPEMM);
    EXPECT_EQ(UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), 0, (HANDLE)(ULONG_PTR)0x7ffffff0, NULL, NULL, 0), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateProcessEx)(NULL, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), 0, sec, NULL, NULL, 0), S_AV);
    EXPECT_EQ(UN(ZwCreateProcessEx)(&ph, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), 0xffff0000, sec, NULL, NULL, 0), S_INVPARAM);
    cob_close(ph); cob_close(sec);
}

TEST(nt_create_open_b_create_process_legacy)
{
    HANDLE sec = NULL, f, ph = NULL; NTSTATUS s; OBJECT_ATTRIBUTES oa;
    NEEDP(); REQUIRE(UN(ZwCreateProcess)); REQUIRE(UN(ZwCreateSection)); REQUIRE(UN(NtTerminateProcess)); COB_ALIAS("CreateProcess");
    cob_oa(&oa, NULL, 0, NULL);
    f = CreateFileA(t_self_path(), GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    s = UN(ZwCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, 0x1000000, f); EXPECT_EQ(s, S_OK_); CloseHandle(f);
    if (!sec) return;
    s = UN(ZwCreateProcess)(&ph, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), FALSE, sec, NULL, NULL);
    EXPECT_EQ(s, S_OK_);
    if (ph) { EXPECT_NE(GetProcessId(ph), GetCurrentProcessId()); UN(NtTerminateProcess)(ph, 0); WaitForSingleObject(ph, 10000); cob_close(ph); ph = NULL; }
    EXPECT_EQ(UN(ZwCreateProcess)(&ph, PROCESS_ALL_ACCESS, &oa, NULL, FALSE, sec, NULL, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateProcess)(&ph, PROCESS_ALL_ACCESS, &oa, (HANDLE)(ULONG_PTR)0x7ffffff0, FALSE, sec, NULL, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateProcess)(NULL, PROCESS_ALL_ACCESS, &oa, GetCurrentProcess(), FALSE, sec, NULL, NULL), S_AV);
    cob_close(sec);
}
