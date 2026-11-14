/* ZwCreateUserProcess: suspended creation of a system image, attribute list validation. */
#include "cob.h"

typedef struct { ULONG_PTR Attribute; SIZE_T Size; ULONG_PTR Value; PSIZE_T ReturnLength; } PSATTR;
typedef struct { SIZE_T TotalLength; PSATTR Attributes[2]; } PSATTRLIST;
typedef struct { SIZE_T Size; ULONG State; ULONG InitFlags; ULONG AdditionalFileAccess; BYTE rest[0x58 - 0x18]; } PSCREATEINFO;

UDECL(NTSTATUS, ZwCreateUserProcess, (PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, RtlCreateProcessParametersEx, (PVOID *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlDestroyProcessParameters, (PVOID));
UDECL(NTSTATUS, NtTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define PS_ATTR_IMAGE_NAME 0x20005

static int sys_image(WCHAR *nt, size_t cap)
{
    char d[260]; size_t i, k = 0; UINT n = GetSystemDirectoryA(d, sizeof d);
    if (!n || n > 200) return 0;
    nt[k++] = '\\'; nt[k++] = '?'; nt[k++] = '?'; nt[k++] = '\\';
    for (i = 0; d[i] && k + 20 < cap; i++) nt[k++] = (WCHAR)(unsigned char)d[i];
    { const char *tail = "\\cmd.exe"; for (i = 0; tail[i]; i++) nt[k++] = (WCHAR)tail[i]; }
    nt[k] = 0; return 1;
}

static NTSTATUS spawn(const WCHAR *image, ULONG tflags, HANDLE *ph, HANDLE *th, int skip_image_attr, int null_params, ULONG info_size)
{
    UNICODE_STRING img, cmd; PVOID pp = NULL; PSATTRLIST al; PSCREATEINFO ci; NTSTATUS s; WCHAR cl[300];
    const WCHAR *dos = image + 4;
    cob_us(&img, image);
    wsprintfW(cl, L"\"%s\"", dos); cob_us(&cmd, cl);
    { UNICODE_STRING dosu; cob_us(&dosu, dos);
      s = UN(RtlCreateProcessParametersEx)(&pp, &dosu, NULL, NULL, &cmd, NULL, NULL, NULL, NULL, NULL, 1);
      if (s != 0) return s; }
    memset(&al, 0, sizeof al); memset(&ci, 0, sizeof ci);
    al.TotalLength = sizeof(SIZE_T) + sizeof(PSATTR);
    al.Attributes[0].Attribute = PS_ATTR_IMAGE_NAME; al.Attributes[0].Size = img.Length; al.Attributes[0].Value = (ULONG_PTR)img.Buffer;
    if (skip_image_attr) al.TotalLength = sizeof(SIZE_T);
    ci.Size = info_size; ci.State = 0;
    s = UN(ZwCreateUserProcess)(ph, th, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, tflags, null_params ? NULL : pp, &ci, &al);
    UN(RtlDestroyProcessParameters)(pp);
    return s;
}

TEST(nt_create_open_b_create_user_process)
{
    HANDLE ph = NULL, th = NULL; WCHAR img[300], tn[40]; NTSTATUS s; DWORD code = 0;
    REQUIRE(UN(ZwCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(NtTerminateProcess)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject));
    COB_ALIAS("CreateUserProcess");
    CHECK(sys_image(img, 300));
    s = spawn(img, 1 /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED */, &ph, &th, 0, 0, 0x58);
    EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        CHECK(cob_typename(ph, tn, 40)); EXPECT_WSTR(tn, L"Process");
        CHECK(cob_typename(th, tn, 40)); EXPECT_WSTR(tn, L"Thread");
        CHECK(GetProcessId(ph) != 0); EXPECT_NE(GetProcessId(ph), GetCurrentProcessId());
        EXPECT_EQ(GetProcessIdOfThread(th), GetProcessId(ph));
        EXPECT_EQ(WaitForSingleObject(ph, 0), WAIT_TIMEOUT);      /* suspended thread: process has not run */
        { WCHAR path[300]; DWORD n = 300; if (QueryFullProcessImageNameW(ph, 0, path, &n)) { CHECK(n > 7); CHECK(!lstrcmpiW(path + n - 7, L"cmd.exe")); } else t_note("QueryFullProcessImageNameW failed %lu", GetLastError()); }
        EXPECT_EQ(UN(NtTerminateProcess)(ph, 0x77), S_OK_);
        EXPECT_EQ(WaitForSingleObject(ph, 10000), WAIT_OBJECT_0);
        CHECK(GetExitCodeProcess(ph, &code)); EXPECT_EQ(code, 0x77);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    }
    cob_close(th); cob_close(ph); ph = th = NULL;
}

TEST(nt_create_open_b_create_user_process_errors)
{
    HANDLE ph = (HANDLE)0x1234, th = (HANDLE)0x1234; WCHAR img[300]; NTSTATUS s;
    REQUIRE(UN(ZwCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(NtClose));
    CHECK(sys_image(img, 300));
    /* no image name attribute */
    s = spawn(img, 1, &ph, &th, 1, 0, 0x58); EXPECT_EQ(s, S_INVPARAM); if (s == 0) { cob_close(ph); cob_close(th); }
    /* no process parameters */
    ph = th = NULL; s = spawn(img, 1, &ph, &th, 0, 1, 0x58); EXPECT_EQ(s, S_AV); if (s == 0) { cob_close(ph); cob_close(th); }
    /* wrong create-info size */
    ph = th = NULL; s = spawn(img, 1, &ph, &th, 0, 0, 0x10); EXPECT_EQ(s, S_INVPARAM); if (s == 0) { cob_close(ph); cob_close(th); }
    /* missing image file */
    { WCHAR bad[300]; lstrcpyW(bad, img); lstrcpyW(bad + lstrlenW(bad) - 7, L"cob_missing_image.exe");
      ph = th = NULL; s = spawn(bad, 1, &ph, &th, 0, 0, 0x58); EXPECT_EQ(s, S_NOTFOUND); if (s == 0) { cob_close(ph); cob_close(th); } }
    /* NULL attribute list and create info */
    EXPECT_EQ(UN(ZwCreateUserProcess)(&ph, &th, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 1, NULL, NULL, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateUserProcess)(NULL, NULL, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 1, NULL, NULL, NULL), S_AV);
}
