#include "t.h"
#include <stdlib.h>

typedef struct { UNICODE_STRING RelativeName; HANDLE ContainingDirectory; PVOID CurDirRef; } RELNAME;
typedef struct { USHORT Checksum; BOOLEAN ChecksumInserted; UCHAR NameLength; WCHAR NameBuffer[8]; ULONG ExtensionLength; WCHAR ExtensionBuffer[4]; ULONG LastIndexValue; } GEN8;
typedef struct { UCHAR Version; char Vector[129]; } CORRVEC;

UDECL(ULONG, RtlDosSearchPath_U, (PCWSTR, PCWSTR, PCWSTR, ULONG, PWSTR, PWSTR *));
UDECL(BOOLEAN, RtlDosPathNameToRelativeNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, RELNAME *));
UDECL(NTSTATUS, RtlDosPathNameToRelativeNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, RELNAME *));
UDECL(NTSTATUS, RtlDosLongPathNameToNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, RELNAME *));
UDECL(NTSTATUS, RtlDosLongPathNameToRelativeNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, RELNAME *));
UDECL(VOID, RtlReleaseRelativeName, (RELNAME *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, RtlGenerate8dot3Name, (const UNICODE_STRING *, BOOLEAN, GEN8 *, PUNICODE_STRING));
UDECL(BOOLEAN, RtlEqualComputerName, (const UNICODE_STRING *, const UNICODE_STRING *));
UDECL(BOOLEAN, RtlEqualDomainName, (const UNICODE_STRING *, const UNICODE_STRING *));
UDECL(NTSTATUS, RtlInitializeCorrelationVector, (CORRVEC *, int, const GUID *));
UDECL(NTSTATUS, RtlExtendCorrelationVector, (CORRVEC *));
UDECL(NTSTATUS, RtlConvertDeviceFamilyInfoToString, (PULONG, PULONG, PWSTR, PWSTR));
UDECL(NTSTATUS, RtlFindMessage, (PVOID, ULONG, ULONG, ULONG, PVOID *));
UDECL(PVOID, RtlFindExportedRoutineByName, (PVOID, PCSTR));

#define ST(x) ((NTSTATUS)(x))

static void mkus(UNICODE_STRING *u, const WCHAR *w) { u->Buffer = (PWSTR)w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }

static int mkfile(const char *leaf, WCHAR *wpath, size_t cap) {
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, leaf);
    HANDLE h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    MultiByteToWideChar(CP_ACP, 0, p, -1, wpath, (int)cap);
    return 1;
}

TEST(rtl_net_ip_str_a_dos_search_path_u) {
    REQUIRE(UN(RtlDosSearchPath_U));
    WCHAR f[MAX_PATH], dir[MAX_PATH], out[MAX_PATH], *part = NULL;
    if (!mkfile("srch_target.dat", f, MAX_PATH)) { t_skip("cannot create fixture file"); return; }
    lstrcpyW(dir, f); WCHAR *sl = wcsrchr(dir, L'\\'); *sl = 0;
    WCHAR path[2 * MAX_PATH]; wsprintfW(path, L"C:\\no_such_dir_ipa;%s", dir);
    ULONG n = UN(RtlDosSearchPath_U)(path, L"srch_target.dat", NULL, MAX_PATH * 2, out, &part);
    EXPECT_EQ(n, lstrlenW(f) * 2);
    CHECK(!lstrcmpiW(out, f)); CHECK(part && !lstrcmpW(part, L"srch_target.dat")); if (part) EXPECT_EQ(part, out + (sl - dir) + 1);
    /* extension appended when name has none */
    memset(out, 0, sizeof out); part = NULL;
    n = UN(RtlDosSearchPath_U)(path, L"srch_target", L".dat", MAX_PATH * 2, out, &part);
    EXPECT_EQ(n, lstrlenW(f) * 2); CHECK(!lstrcmpiW(out, f));
    /* extension ignored when name already has one */
    n = UN(RtlDosSearchPath_U)(path, L"srch_target.dat", L".xyz", MAX_PATH * 2, out, &part); EXPECT_EQ(n, lstrlenW(f) * 2);
    /* not found: returns 0 */
    n = UN(RtlDosSearchPath_U)(path, L"definitely_missing.dat", NULL, MAX_PATH * 2, out, &part); EXPECT_EQ(n, 0);
    /* buffer too small: returns required size in bytes incl. NUL, no write */
    WCHAR sm[4]; memset(sm, 0x55, sizeof sm);
    n = UN(RtlDosSearchPath_U)(path, L"srch_target.dat", NULL, sizeof sm, sm, &part);
    EXPECT_EQ(n, (lstrlenW(f) + 1) * 2); EXPECT_EQ(sm[0], 0);   /* empty string written */
    DeleteFileW(f);
}
static void relname_case(const char *nm, NTSTATUS (WINAPI *f)(PCWSTR, PUNICODE_STRING, PWSTR *, RELNAME *), int ws) {
    UNICODE_STRING nt; WCHAR *part = NULL; RELNAME rel; NTSTATUS s;
    memset(&nt, 0, sizeof nt); memset(&rel, 0xcc, sizeof rel);
    s = f(L"C:\\Windows\\System32\\x.dll", &nt, &part, &rel);
    CHECKF(s == 0, "%s status %08lx", nm, (unsigned long)s);
    if (s == 0) {
        CHECKF(nt.Buffer && !_wcsnicmp(nt.Buffer, L"\\??\\C:\\Windows\\System32\\x.dll", 28), "%s nt name", nm);
        CHECKF(part && !lstrcmpW(part, L"x.dll"), "%s file part", nm);
        EXPECT_EQ(nt.Length, lstrlenW(L"\\??\\C:\\Windows\\System32\\x.dll") * 2);
        if (UN(RtlReleaseRelativeName)) UN(RtlReleaseRelativeName)(&rel);
        UN(RtlFreeUnicodeString)(&nt);
    }
    /* trailing component path with dot-dot collapses */
    memset(&nt, 0, sizeof nt); part = NULL;
    s = f(L"C:\\Windows\\..\\Windows\\a.txt", &nt, &part, &rel);
    CHECKF(s == 0, "%s dotdot status", nm);
    if (s == 0) { CHECKF(nt.Buffer && !_wcsnicmp(nt.Buffer, L"\\??\\C:\\Windows\\a.txt", 20), "%s collapsed", nm);
        UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt); }
    /* empty string is invalid */
    memset(&nt, 0, sizeof nt);
    s = f(L"", &nt, &part, &rel);
    CHECKF(s < 0, "%s empty path must fail (got %08lx)", nm, (unsigned long)s);
    if (ws) EXPECT_EQ(s, ST(0xC0000033));
    if (s >= 0) { UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt); }
}
static BOOLEAN WINAPI bool_adapter_dummy(void) { return 0; }
TEST(rtl_net_ip_str_a_relative_nt_path_withstatus) {
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)); REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlReleaseRelativeName));
    relname_case("RtlDosPathNameToRelativeNtPathName_U_WithStatus", UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus), 1);
    UNICODE_STRING nt; RELNAME rel; WCHAR *part;
    NTSTATUS s = UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)(NULL, &nt, &part, &rel);
    CHECK(s < 0);
    CHECK(t_proc("RtlDosPathNameToRelativeNtPathName_U_WithStatus") != t_proc("RtlDosPathNameToRelativeNtPathName_U"));
}
TEST(rtl_net_ip_str_a_relative_nt_path_bool) {
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U)); REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlReleaseRelativeName));
    UNICODE_STRING nt; WCHAR *part = NULL; RELNAME rel; memset(&nt, 0, sizeof nt);
    BOOLEAN b = UN(RtlDosPathNameToRelativeNtPathName_U)(L"C:\\Windows\\notepad.exe", &nt, &part, &rel);
    EXPECT_EQ(b, 1);
    if (b) { CHECK(nt.Buffer && !_wcsnicmp(nt.Buffer, L"\\??\\C:\\Windows\\notepad.exe", 26)); CHECK(part && !lstrcmpW(part, L"notepad.exe"));
        UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt); }
    memset(&nt, 0, sizeof nt);
    b = UN(RtlDosPathNameToRelativeNtPathName_U)(L"", &nt, &part, &rel);
    EXPECT_EQ(b, 0);
    b = UN(RtlDosPathNameToRelativeNtPathName_U)(L"\\\\server\\share\\dir\\f.txt", &nt, &part, &rel);
    EXPECT_EQ(b, 1);
    if (b) { CHECK(nt.Buffer && !_wcsnicmp(nt.Buffer, L"\\??\\UNC\\server\\share\\dir\\f.txt", 30)); UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt); }
}
TEST(rtl_net_ip_str_a_long_path_withstatus) {
    REQUIRE(UN(RtlDosLongPathNameToNtPathName_U_WithStatus)); REQUIRE(UN(RtlDosLongPathNameToRelativeNtPathName_U_WithStatus)); REQUIRE(UN(RtlFreeUnicodeString));
    UNICODE_STRING nt; WCHAR *part = NULL; RELNAME rel; memset(&nt, 0, sizeof nt);
    NTSTATUS s = UN(RtlDosLongPathNameToNtPathName_U_WithStatus)(L"C:\\Windows\\notepad.exe", &nt, &part, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0) { CHECK(nt.Buffer && !_wcsnicmp(nt.Buffer, L"\\??\\C:\\Windows\\notepad.exe", 26)); CHECK(part && !lstrcmpW(part, L"notepad.exe")); UN(RtlFreeUnicodeString)(&nt); }
    /* a path longer than MAX_PATH works through the long-path variants */
    WCHAR *lp = malloc(700 * 2); lstrcpyW(lp, L"C:\\Windows\\");
    for (int i = 0; i < 40; i++) lstrcatW(lp, L"abcdefghij\\");
    lstrcatW(lp, L"end.txt");
    memset(&nt, 0, sizeof nt); part = NULL;
    s = UN(RtlDosLongPathNameToNtPathName_U_WithStatus)(lp, &nt, &part, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0) { CHECK(part && !lstrcmpW(part, L"end.txt")); CHECK(nt.Length > 520); UN(RtlFreeUnicodeString)(&nt); }
    memset(&nt, 0, sizeof nt);
    s = UN(RtlDosLongPathNameToRelativeNtPathName_U_WithStatus)(lp, &nt, &part, &rel);
    EXPECT_EQ(s, 0);
    if (s == 0) { UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt); }
    free(lp);
    memset(&nt, 0, sizeof nt);
    s = UN(RtlDosLongPathNameToNtPathName_U_WithStatus)(L"", &nt, &part, NULL);
    CHECK(s < 0);
}
TEST(rtl_net_ip_str_a_gen_8dot3) {
    REQUIRE(UN(RtlGenerate8dot3Name));
    UNICODE_STRING name; WCHAR out[12]; UNICODE_STRING o; GEN8 ctx;
    mkus(&name, L"LongFileName.txt");
    memset(&ctx, 0, sizeof ctx); o.Buffer = out; o.Length = 0; o.MaximumLength = sizeof out;
    EXPECT_EQ(UN(RtlGenerate8dot3Name)(&name, FALSE, &ctx, &o), 0);
    EXPECT_EQ(o.Length, 24);
    CHECK(o.Length == 24 && !_wcsnicmp(out, L"LONGFI~1.TXT", 12));
    EXPECT_EQ(ctx.LastIndexValue, 1);
    /* second call with same context increments index */
    o.Length = 0;
    EXPECT_EQ(UN(RtlGenerate8dot3Name)(&name, FALSE, &ctx, &o), 0);
    CHECK(o.Length == 24 && !_wcsnicmp(out, L"LONGFI~2.TXT", 12));
    /* no extension */
    mkus(&name, L"NoExtensionHere");
    memset(&ctx, 0, sizeof ctx); o.Length = 0;
    EXPECT_EQ(UN(RtlGenerate8dot3Name)(&name, FALSE, &ctx, &o), 0);
    CHECK(o.Length == 16 && !_wcsnicmp(out, L"NOEXTE~1", 8));
    /* long extension truncated to three characters */
    mkus(&name, L"abc.longext");
    memset(&ctx, 0, sizeof ctx); o.Length = 0;
    EXPECT_EQ(UN(RtlGenerate8dot3Name)(&name, FALSE, &ctx, &o), 0);
    CHECK(o.Length == 18 && !_wcsnicmp(out, L"ABC~1.LO", 8));   /* extension is cut to 2 chars + a trailing mark; observed */
    /* spaces are stripped */
    mkus(&name, L"my file name.doc");
    memset(&ctx, 0, sizeof ctx); o.Length = 0;
    EXPECT_EQ(UN(RtlGenerate8dot3Name)(&name, FALSE, &ctx, &o), 0);
    CHECK(o.Length == 24 && !_wcsnicmp(out, L"MYFILE~1.DOC", 12));
}
TEST(rtl_net_ip_str_a_equal_computer_domain) {
    REQUIRE(UN(RtlEqualComputerName)); REQUIRE(UN(RtlEqualDomainName));
    UNICODE_STRING a, b, c, d;
    mkus(&a, L"HOSTNAME"); mkus(&b, L"hostname"); mkus(&c, L"OTHER"); mkus(&d, L"HostName1");
    EXPECT_EQ(UN(RtlEqualComputerName)(&a, &b) & 1, 1); EXPECT_EQ(UN(RtlEqualComputerName)(&a, &c) & 1, 0);
    EXPECT_EQ(UN(RtlEqualComputerName)(&a, &d) & 1, 0); EXPECT_EQ(UN(RtlEqualComputerName)(&a, &a) & 1, 1);
    EXPECT_EQ(UN(RtlEqualDomainName)(&a, &b) & 1, 1); EXPECT_EQ(UN(RtlEqualDomainName)(&a, &c) & 1, 0);
    EXPECT_EQ(UN(RtlEqualDomainName)(&a, &d) & 1, 0);
    UNICODE_STRING big; WCHAR bw[300]; for (int i = 0; i < 299; i++) bw[i] = 'A'; bw[299] = 0; mkus(&big, bw);
    EXPECT_EQ(UN(RtlEqualComputerName)(&big, &big) & 1, 0);   /* too long to canonicalize */
}
TEST(rtl_net_ip_str_a_correlation_vector) {
    REQUIRE(UN(RtlInitializeCorrelationVector)); REQUIRE(UN(RtlExtendCorrelationVector));
    GUID g = {0x01234567, 0x89ab, 0xcdef, {1, 2, 3, 4, 5, 6, 7, 8}};
    CORRVEC cv; memset(&cv, 0xcc, sizeof cv);
    EXPECT_EQ(UN(RtlInitializeCorrelationVector)(&cv, 1, &g), 0);
    EXPECT_EQ(cv.Version, 1);
    CHECK(strlen(cv.Vector) == 18); CHECK(cv.Vector[16] == '.' && cv.Vector[17] == '0');
    char first[32]; memcpy(first, cv.Vector, 16); first[16] = 0;
    EXPECT_EQ(UN(RtlExtendCorrelationVector)(&cv), 0);
    CHECK(!strncmp(cv.Vector, first, 16)); EXPECT_STR(cv.Vector + 16, ".0.0");
    EXPECT_EQ(UN(RtlExtendCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector + 16, ".0.0.0");
    memset(&cv, 0xcc, sizeof cv);
    EXPECT_EQ(UN(RtlInitializeCorrelationVector)(&cv, 2, &g), 0);
    EXPECT_EQ(cv.Version, 2); CHECK(strlen(cv.Vector) == 24); CHECK(cv.Vector[22] == '.' && cv.Vector[23] == '0');
    /* same GUID gives the same base */
    CORRVEC cv2; memset(&cv2, 0, sizeof cv2); UN(RtlInitializeCorrelationVector)(&cv2, 2, &g); EXPECT_STR(cv2.Vector, cv.Vector);
    EXPECT_EQ(UN(RtlInitializeCorrelationVector)(&cv, 0, &g), ST(0xC000000D));
    EXPECT_EQ(UN(RtlInitializeCorrelationVector)(&cv, 3, &g), ST(0xC000000D));
    EXPECT_EQ(UN(RtlInitializeCorrelationVector)(&cv, 1, NULL), ST(0xC000000D));
    /* extend until the 63-char limit of v1 is exhausted */
    UN(RtlInitializeCorrelationVector)(&cv, 1, &g); NTSTATUS s = 0; int n = 0;
    while (s == 0 && n < 200) { s = UN(RtlExtendCorrelationVector)(&cv); n++; }
    EXPECT_EQ(s, ST(0x80000005)); CHECK(strlen(cv.Vector) <= 63);
}
TEST(rtl_net_ip_str_a_device_family_string) {
    REQUIRE(UN(RtlConvertDeviceFamilyInfoToString));
    WCHAR fam[64], form[64]; ULONG fs = sizeof fam, ms = sizeof form;
    NTSTATUS s = UN(RtlConvertDeviceFamilyInfoToString)(&fs, &ms, fam, form);
    EXPECT_EQ(s, 0);
    if (s == 0) { CHECK(fs >= 2 && fs <= sizeof fam && (fs & 1) == 0); CHECK(ms >= 2 && (ms & 1) == 0);
        EXPECT_EQ(fam[fs / 2 - 1], 0); EXPECT_EQ(form[ms / 2 - 1], 0); EXPECT_EQ(lstrlenW(fam) * 2 + 2, fs); EXPECT_EQ(lstrlenW(form) * 2 + 2, ms);
        CHECK(!wcsncmp(fam, L"Windows.", 8)); }
    ULONG a = 2, b = 2; WCHAR x[2], y[2];
    s = UN(RtlConvertDeviceFamilyInfoToString)(&a, &b, x, y);
    EXPECT_EQ(s, ST(0xC0000023));    /* STATUS_BUFFER_TOO_SMALL */
    EXPECT_EQ(a, fs); EXPECT_EQ(b, ms);    /* required sizes are returned */
}
TEST(rtl_net_ip_str_a_find_exported_routine) {
    REQUIRE(UN(RtlFindExportedRoutineByName));
    HMODULE nt = t_module("ntdll.dll");
    PVOID p = UN(RtlFindExportedRoutineByName)(nt, "RtlInitString");
    EXPECT_EQ(p, GetProcAddress(nt, "RtlInitString"));
    EXPECT_EQ(UN(RtlFindExportedRoutineByName)(nt, "NoSuchExport_ipa"), NULL);
    EXPECT_EQ(UN(RtlFindExportedRoutineByName)(nt, "rtlinitstring"), NULL);   /* case sensitive */
    HMODULE k = t_module("kernel32.dll");
    EXPECT_EQ(UN(RtlFindExportedRoutineByName)(k, "CreateFileW"), GetProcAddress(k, "CreateFileW"));
}
