/* RtlCreateUserProcess / RtlCreateUserProcessEx and RtlCreateProcessReflection against this test image. */
#include "t.h"

#define S(x)            ((NTSTATUS)(x))
#define ST_INVPARAM     S(0xC000000D)
#define ST_NOTFOUND     S(0xC0000034)
#define ST_BADIMAGE     S(0xC000012F)   /* STATUS_INVALID_IMAGE_NOT_MZ */

typedef struct { ULONG Length; ULONG pad; HANDLE Process, Thread; CLIENT_ID Cid; BYTE Image[0x40]; } PINFO;
typedef struct { USHORT Version, NodeNumber; ULONG pad; PVOID ProcessSd, ThreadSd; HANDLE Parent, DebugPort, Token, Job; } PEXT;
typedef struct { HANDLE Process, Thread; CLIENT_ID Cid; } REFL;

UDECL(NTSTATUS, RtlCreateProcessParametersEx, (PVOID *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlDestroyProcessParameters, (PVOID));
UDECL(NTSTATUS, RtlCreateUserProcess, (PUNICODE_STRING, ULONG, PVOID, PVOID, PVOID, HANDLE, BOOLEAN, HANDLE, HANDLE, PINFO *));
UDECL(NTSTATUS, RtlCreateUserProcessEx, (PUNICODE_STRING, PVOID, BOOLEAN, PEXT *, PINFO *));
UDECL(NTSTATUS, RtlCreateProcessReflection, (HANDLE, ULONG, PVOID, PVOID, HANDLE, REFL *));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));

CHILD(rtl_cup_child) { return 37; }

/* Builds "\??\<path>" and the DOS path for the given narrow path. */
static void paths(const char *path, WCHAR *nt, WCHAR *dos) {
    MultiByteToWideChar(CP_ACP, 0, path, -1, dos, MAX_PATH);
    wcscpy(nt, L"\\??\\"); wcscat(nt, dos);
}
static NTSTATUS make_params(const WCHAR *dos, const WCHAR *args, PVOID *pp) {
    UNICODE_STRING img, cmd; WCHAR cl[1200];
    UN(RtlInitUnicodeString)(&img, dos);
    wsprintfW(cl, L"\"%s\" %s", dos, args);
    UN(RtlInitUnicodeString)(&cmd, cl);
    return UN(RtlCreateProcessParametersEx)(pp, &img, NULL, NULL, &cmd, NULL, NULL, NULL, NULL, NULL, 1);
}
static void run_and_check(PINFO *info, const char *tag) {
    EXPECT_NE(info->Process, NULL); EXPECT_NE(info->Thread, NULL);
    if (!info->Process || !info->Thread) return;
    EXPECT_EQ(GetProcessId(info->Process), (DWORD)(ULONG_PTR)info->Cid.UniqueProcess);
    EXPECT_EQ(GetThreadId(info->Thread), (DWORD)(ULONG_PTR)info->Cid.UniqueThread);
    EXPECT_NE(GetProcessId(info->Process), GetCurrentProcessId());
    EXPECT_EQ(WaitForSingleObject(info->Process, 0), WAIT_TIMEOUT);          /* created suspended */
    ULONG_PTR sub = *(ULONG *)(info->Image + 0x20);                           /* SECTION_IMAGE_INFORMATION.SubSystemType */
    EXPECT_EQ(sub, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    EXPECT_NE(*(PVOID *)(info->Image), NULL);                                 /* TransferAddress */
    EXPECT_EQ(ResumeThread(info->Thread), 1);
    DWORD w = WaitForSingleObject(info->Process, 30000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) TerminateProcess(info->Process, 1);
    DWORD code = 0xDEAD; GetExitCodeProcess(info->Process, &code);
    EXPECT_EQ(code, 37);
    CloseHandle(info->Thread); CloseHandle(info->Process);
}
TEST(rtl_create_user_process) {
    REQUIRE(UN(RtlCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(RtlInitUnicodeString));
    WCHAR nt[MAX_PATH + 8], dos[MAX_PATH];
    paths(t_self_path(), nt, dos);
    UNICODE_STRING ntimg; UN(RtlInitUnicodeString)(&ntimg, nt);
    PVOID pp = NULL;
    NTSTATUS s = make_params(dos, L"--child rtl_cup_child", &pp);
    EXPECT_EQ(s, 0);
    if (s < 0) return;
    PINFO info; memset(&info, 0, sizeof info); info.Length = sizeof info;
    s = UN(RtlCreateUserProcess)(&ntimg, OBJ_CASE_INSENSITIVE, pp, NULL, NULL, (HANDLE)(LONG_PTR)-1, FALSE, NULL, NULL, &info);
    EXPECT_EQ(s, 0);
    if (s == 0) run_and_check(&info, "create");
    UN(RtlDestroyProcessParameters)(pp);
}
TEST(rtl_create_user_process_errors) {
    REQUIRE(UN(RtlCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(RtlInitUnicodeString));
    WCHAR nt[MAX_PATH + 8], dos[MAX_PATH];
    char missing[MAX_PATH], text[MAX_PATH];
    t_tmpfile(missing, sizeof missing, "nosuchprog.exe");
    t_tmpfile(text, sizeof text, "notanimage.exe");
    FILE *f = fopen(text, "wb"); if (f) { fputs("this is not a PE image\n", f); fclose(f); }
    PINFO info; UNICODE_STRING ntimg; PVOID pp = NULL;
    paths(missing, nt, dos); UN(RtlInitUnicodeString)(&ntimg, nt);
    EXPECT_EQ(make_params(dos, L"", &pp), 0);
    if (!pp) return;
    memset(&info, 0, sizeof info); info.Length = sizeof info;
    EXPECT_EQ(UN(RtlCreateUserProcess)(&ntimg, OBJ_CASE_INSENSITIVE, pp, NULL, NULL, (HANDLE)(LONG_PTR)-1, FALSE, NULL, NULL, &info), ST_NOTFOUND);
    EXPECT_EQ(info.Process, NULL);
    UN(RtlDestroyProcessParameters)(pp); pp = NULL;
    if (f) {
        paths(text, nt, dos); UN(RtlInitUnicodeString)(&ntimg, nt);
        EXPECT_EQ(make_params(dos, L"", &pp), 0);
        if (pp) {
            memset(&info, 0, sizeof info); info.Length = sizeof info;
            EXPECT_EQ(UN(RtlCreateUserProcess)(&ntimg, OBJ_CASE_INSENSITIVE, pp, NULL, NULL, (HANDLE)(LONG_PTR)-1, FALSE, NULL, NULL, &info), ST_BADIMAGE);
            EXPECT_EQ(info.Process, NULL);
            UN(RtlDestroyProcessParameters)(pp);
        }
    }
    DeleteFileA(text);
}
TEST(rtl_create_user_process_ex) {
    REQUIRE(UN(RtlCreateUserProcessEx)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(RtlInitUnicodeString));
    WCHAR nt[MAX_PATH + 8], dos[MAX_PATH];
    paths(t_self_path(), nt, dos);
    UNICODE_STRING ntimg; UN(RtlInitUnicodeString)(&ntimg, nt);
    PVOID pp = NULL;
    EXPECT_EQ(make_params(dos, L"--child rtl_cup_child", &pp), 0);
    if (!pp) return;
    PEXT ext; memset(&ext, 0, sizeof ext); ext.Version = 1; ext.Parent = (HANDLE)(LONG_PTR)-1;
    PINFO info; memset(&info, 0, sizeof info); info.Length = sizeof info;
    NTSTATUS s = UN(RtlCreateUserProcessEx)(&ntimg, pp, FALSE, &ext, &info);
    EXPECT_EQ(s, 0);
    if (s == 0) run_and_check(&info, "ex");
    /* argument validation precedes any system call */
    memset(&info, 0, sizeof info); info.Length = sizeof info;
    EXPECT_EQ(UN(RtlCreateUserProcessEx)(NULL, pp, FALSE, &ext, &info), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateUserProcessEx)(&ntimg, NULL, FALSE, &ext, &info), ST_INVPARAM);
    EXPECT_EQ(info.Process, NULL);
    UN(RtlDestroyProcessParameters)(pp);
}

/* ---- process reflection ---- */
TEST(rtl_create_process_reflection_args) {
    REQUIRE(UN(RtlCreateProcessReflection));
    REFL r; memset(&r, 0xAB, sizeof r);
    HANDLE self = (HANDLE)(LONG_PTR)-1;
    EXPECT_EQ(UN(RtlCreateProcessReflection)(self, 1, NULL, NULL, NULL, &r), S(0xC00000F0));          /* unsupported flag bits: parameter 2 */
    EXPECT_EQ(UN(RtlCreateProcessReflection)(self, 0x20, NULL, NULL, NULL, &r), S(0xC00000F0));
    EXPECT_EQ(UN(RtlCreateProcessReflection)(self, 0x80000000, NULL, NULL, NULL, &r), S(0xC00000F0));
    EXPECT_EQ(UN(RtlCreateProcessReflection)(self, 8, (PVOID)0x1000, NULL, NULL, &r), S(0xC00000F3)); /* NO_SYNCHRONIZE excludes a start routine */
}
TEST(rtl_create_process_reflection_clone) {
    REQUIRE(UN(RtlCreateProcessReflection));
    REFL r; memset(&r, 0, sizeof r);
    NTSTATUS s = UN(RtlCreateProcessReflection)((HANDLE)(LONG_PTR)-1, 0, NULL, NULL, NULL, &r);
    t_note("reflection status 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    EXPECT_NE(r.Process, NULL); EXPECT_NE(r.Thread, NULL);
    if (r.Process) {
        DWORD pid = GetProcessId(r.Process);
        EXPECT_NE(pid, 0); EXPECT_NE(pid, GetCurrentProcessId());
        EXPECT_EQ(pid, (DWORD)(ULONG_PTR)r.Cid.UniqueProcess);
        char img[MAX_PATH]; DWORD n = MAX_PATH;
        BOOL (WINAPI *q)(HANDLE, DWORD, LPSTR, PDWORD) = (void *)t_proc_in("kernel32.dll", "QueryFullProcessImageNameA");
        if (q && q(r.Process, 0, img, &n)) EXPECT_EQ(_stricmp(img, t_self_path()), 0);     /* a clone of this very image */
        TerminateProcess(r.Process, 0);
        EXPECT_EQ(WaitForSingleObject(r.Process, 20000), WAIT_OBJECT_0);
    }
    if (r.Thread) CloseHandle(r.Thread);
    if (r.Process) CloseHandle(r.Process);
}
