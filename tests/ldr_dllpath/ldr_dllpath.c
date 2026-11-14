/* Loader DLL search-path state: the user DLL directory, added DLL directories, default directory
 * flags, per-call search path construction, package search path and MUI cache type.
 * Process-global state that cannot be restored runs in a child process. */
#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, LdrSetDllDirectory, (PUNICODE_STRING));
UDECL(NTSTATUS, LdrGetDllDirectory, (PUNICODE_STRING));
UDECL(NTSTATUS, LdrAddDllDirectory, (PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrRemoveDllDirectory, (PVOID));
UDECL(NTSTATUS, LdrSetDefaultDllDirectories, (ULONG));
UDECL(NTSTATUS, LdrGetDllPath, (PCWSTR, ULONG, PWSTR *, PWSTR *));
UDECL(VOID, RtlReleasePath, (PWSTR));
UDECL(NTSTATUS, LdrUpdatePackageSearchPath, (PCWSTR));
UDECL(NTSTATUS, LdrSetMUICacheType, (ULONG));
UDECL(ULONG, LdrFlushAlternateResourceModules, (void));

#define S(x) ((NTSTATUS)(x))
#define ST_BAD_PARAM     S(0xC000000D)
#define ST_BUF_TOO_SMALL S(0xC0000023)
#define ST_NAME_NOTFOUND S(0xC0000034)
#define ST_NAME_TOO_LONG S(0xC0000106)
#define ST_UNSUCCESSFUL  S(0xC0000001)

static UNICODE_STRING us(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2;
    return u;
}
static void get_dir(WCHAR *out, size_t cap, NTSTATUS *st)
{
    UNICODE_STRING b; b.Buffer = out; b.Length = 0; b.MaximumLength = (USHORT)(cap * 2);
    out[0] = 0;
    *st = UN(LdrGetDllDirectory)(&b);
    if (*st == 0) out[b.Length / 2] = 0;
}

TEST(ldr_path_dll_directory_roundtrip)
{
    REQUIRE(UN(LdrSetDllDirectory)); REQUIRE(UN(LdrGetDllDirectory));
    WCHAR orig[MAX_PATH], cur[MAX_PATH]; NTSTATUS st;
    get_dir(orig, MAX_PATH, &st);
    EXPECT_EQ(st, 0);
    UNICODE_STRING d = us(L"C:\\corpus_dll_directory");
    NTSTATUS s = UN(LdrSetDllDirectory)(&d);
    EXPECT_EQ(s, 1);                              /* success is reported as TRUE */
    get_dir(cur, MAX_PATH, &st);
    EXPECT_EQ(st, 0);
    EXPECT_WSTR(cur, L"C:\\corpus_dll_directory");
    /* exact-fit buffer succeeds, one short fails and reports the needed size including the NUL */
    USHORT need = d.Length + 2;
    WCHAR b1[64]; UNICODE_STRING o; o.Buffer = b1; o.Length = 0; o.MaximumLength = need;
    EXPECT_EQ(UN(LdrGetDllDirectory)(&o), 0);
    EXPECT_EQ(o.Length, d.Length);
    WCHAR b2[64]; b2[0] = 0x55;
    o.Buffer = b2; o.Length = 0; o.MaximumLength = need - 2;
    EXPECT_EQ(UN(LdrGetDllDirectory)(&o), ST_BUF_TOO_SMALL);
    EXPECT_EQ(o.Length, need);
    EXPECT_EQ(b2[0], 0);
    /* a semicolon is rejected and the previous value stays */
    UNICODE_STRING sc = us(L"C:\\a;b");
    EXPECT_EQ(UN(LdrSetDllDirectory)(&sc), ST_BAD_PARAM);
    get_dir(cur, MAX_PATH, &st);
    EXPECT_WSTR(cur, L"C:\\corpus_dll_directory");
    /* an empty string clears it */
    UNICODE_STRING em = {0, 0, NULL};
    EXPECT_EQ(UN(LdrSetDllDirectory)(&em), 1);
    get_dir(cur, MAX_PATH, &st);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(lstrlenW(cur), 0);
    /* restore */
    UNICODE_STRING r = us(orig);
    UN(LdrSetDllDirectory)(&r);
}

static BOOL path_contains(const WCHAR *path, const WCHAR *dir)
{
    size_t n = lstrlenW(dir); const WCHAR *p = path;
    while (p && *p) {
        if (!_wcsnicmp(p, dir, n) && (p[n] == L';' || p[n] == 0)) return TRUE;
        p = wcschr(p, L';'); if (p) p++;
    }
    return FALSE;
}
static NTSTATUS get_path(const WCHAR *dll, ULONG flags, WCHAR *out, size_t cap)
{
    PWSTR p = NULL, fr = NULL;
    NTSTATUS s = UN(LdrGetDllPath)(dll, flags, &p, &fr);
    out[0] = 0;
    if (s == 0 && p) lstrcpynW(out, p, (int)cap);
    if (fr && UN(RtlReleasePath)) UN(RtlReleasePath)(fr);
    return s;
}

TEST(ldr_path_get_dll_path_default_layout)
{
    REQUIRE(UN(LdrGetDllPath)); REQUIRE(UN(RtlReleasePath));
    WCHAR p[2048], sys[MAX_PATH], exe[MAX_PATH];
    NTSTATUS s = get_path(L"corpus_x.dll", 0, p, 2048);
    EXPECT_EQ(s, 0);
    GetSystemDirectoryW(sys, MAX_PATH);
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    *wcsrchr(exe, L'\\') = 0;
    /* application directory first, then the system directory, then the Windows directory */
    size_t n = lstrlenW(exe);
    CHECK(!_wcsnicmp(p, exe, n) && p[n] == L';');
    CHECK(path_contains(p, sys));
    WCHAR win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    CHECK(path_contains(p, win));
    const WCHAR *ps = wcsstr(p, L";"), *pw = NULL;
    (void)ps;
    for (const WCHAR *q = p; q; ) { if (!_wcsnicmp(q, sys, lstrlenW(sys)) && !pw) { pw = q; break; } q = wcschr(q, L';'); if (q) q++; }
    CHECK(pw != NULL && pw > p);
}

TEST(ldr_path_get_dll_path_flags)
{
    REQUIRE(UN(LdrGetDllPath)); REQUIRE(UN(RtlReleasePath));
    WCHAR p[2048], sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    /* LOAD_LIBRARY_SEARCH_SYSTEM32 alone yields exactly the system directory */
    EXPECT_EQ(get_path(L"corpus_x.dll", 0x800, p, 2048), 0);
    CHECK(!lstrcmpiW(p, sys));
    /* an unsupported combination is rejected */
    EXPECT_EQ(get_path(L"corpus_x.dll", 0x7f9, p, 2048), ST_BAD_PARAM);
}

TEST(ldr_path_user_dll_directory_in_search_path)
{
    REQUIRE(UN(LdrGetDllPath)); REQUIRE(UN(RtlReleasePath)); REQUIRE(UN(LdrSetDllDirectory)); REQUIRE(UN(LdrGetDllDirectory));
    WCHAR orig[MAX_PATH], p[4096]; NTSTATUS st;
    get_dir(orig, MAX_PATH, &st);
    UNICODE_STRING d = us(L"C:\\corpus_dll_directory");
    EXPECT_EQ(UN(LdrSetDllDirectory)(&d), 1);
    EXPECT_EQ(get_path(L"corpus_x.dll", 0, p, 4096), 0);
    CHECK(path_contains(p, L"C:\\corpus_dll_directory"));
    UNICODE_STRING em = {0, 0, NULL};
    EXPECT_EQ(UN(LdrSetDllDirectory)(&em), 1);
    EXPECT_EQ(get_path(L"corpus_x.dll", 0, p, 4096), 0);
    CHECK(!path_contains(p, L"C:\\corpus_dll_directory"));
    UNICODE_STRING r = us(orig);
    UN(LdrSetDllDirectory)(&r);
}

TEST(ldr_path_add_remove_dll_directory)
{
    REQUIRE(UN(LdrAddDllDirectory)); REQUIRE(UN(LdrRemoveDllDirectory)); REQUIRE(UN(LdrGetDllPath)); REQUIRE(UN(RtlReleasePath));
    WCHAR dir[MAX_PATH], p[4096];
    MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, dir, MAX_PATH);
    size_t n = lstrlenW(dir);
    if (n > 3 && dir[n - 1] == L'\\') dir[n - 1] = 0;
    UNICODE_STRING d = us(dir); PVOID ck = NULL;
    EXPECT_EQ(UN(LdrAddDllDirectory)(&d, &ck), 0);
    CHECK(ck != NULL);
    if (!ck) return;
    /* LOAD_LIBRARY_SEARCH_USER_DIRS lists directories added this way */
    EXPECT_EQ(get_path(L"corpus_x.dll", 0x400, p, 4096), 0);
    CHECK(path_contains(p, dir));
    EXPECT_EQ(UN(LdrRemoveDllDirectory)(ck), 0);
    EXPECT_EQ(get_path(L"corpus_x.dll", 0x400, p, 4096), 0);
    CHECK(!path_contains(p, dir));
    /* validation */
    PVOID c2 = NULL;
    UNICODE_STRING rel = us(L"corpus_relative\\dir");
    EXPECT_EQ(UN(LdrAddDllDirectory)(&rel, &c2), ST_BAD_PARAM);
    UNICODE_STRING nx = us(L"C:\\corpus_nonexistent_directory_zz");
    EXPECT_EQ(UN(LdrAddDllDirectory)(&nx, &c2), ST_NAME_NOTFOUND);
    EXPECT_EQ(c2, NULL);
}

/* ---- child-isolated state ----------------------------------------------------------------- */
static int g_cfail;
#define C_EXPECT(a, b) do { ULONG_PTR x_ = (ULONG_PTR)(a), y_ = (ULONG_PTR)(b); if (x_ != y_) { printf("  child mismatch line %d: %s got 0x%llx want 0x%llx\n", __LINE__, #a, (unsigned long long)x_, (unsigned long long)y_); g_cfail++; } } while (0)

CHILD(default_dirs)
{
    if (!UN(LdrSetDefaultDllDirectories)) return 77;
    static const ULONG bad[] = {0, 0x1, 0x2, 0x4, 0x8, 0x80, 0x100, 0x80000000u, 0x8000, 0x10000, 0x100 | 0x800};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) C_EXPECT(UN(LdrSetDefaultDllDirectories)(bad[i]), ST_BAD_PARAM);
    static const ULONG good[] = {0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x600, 0xA00, 0x7e00};
    for (unsigned i = 0; i < sizeof good / sizeof *good; i++) C_EXPECT(UN(LdrSetDefaultDllDirectories)(good[i]), 0);
    /* the default flag set changes what an unflagged search path covers */
    if (UN(LdrGetDllPath) && UN(RtlReleasePath)) {
        WCHAR p[2048], sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
        C_EXPECT(UN(LdrSetDefaultDllDirectories)(0x800), 0);
        NTSTATUS s = get_path(L"corpus_x.dll", 0, p, 2048);
        printf("  default dirs 0x800 -> path status %08lx '%ls'\n", s, p);
        C_EXPECT(s, 0);
        C_EXPECT(_wcsicmp(p, sys) == 0, 1);
    }
    return g_cfail ? 1 : 0;
}
TEST(ldr_path_set_default_dll_directories)
{
    REQUIRE(UN(LdrSetDefaultDllDirectories));
    DWORD rc = t_run_child("default_dirs", "", 30000);
    if (rc == 77) { t_skip("export missing"); return; }
    EXPECT_EQ(rc, 0);
}

CHILD(package_path)
{
    if (!UN(LdrUpdatePackageSearchPath)) return 77;
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(NULL), ST_BAD_PARAM);
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(L""), ST_BAD_PARAM);
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(L"C:\\corpus_package_dir"), 0);
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(L"C:\\corpus_package_dir2"), 0);   /* replaces the earlier value */
    /* 0x7fff characters is 0xfffe bytes, more than the 0xfffd limit */
    WCHAR *big = (WCHAR *)malloc(0x8000 * 2);
    for (int i = 0; i < 0x7fff; i++) big[i] = L'a';
    big[0x7fff] = 0;
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(big), ST_NAME_TOO_LONG);
    big[0x7ffe] = 0;                                                            /* 0x7ffe chars = 0xfffc bytes */
    C_EXPECT(UN(LdrUpdatePackageSearchPath)(big), 0);
    free(big);
    return g_cfail ? 1 : 0;
}
TEST(ldr_path_update_package_search_path)
{
    REQUIRE(UN(LdrUpdatePackageSearchPath));
    DWORD rc = t_run_child("package_path", "", 30000);
    if (rc == 77) { t_skip("export missing"); return; }
    EXPECT_EQ(rc, 0);
}

CHILD(mui_cache)
{
    if (!UN(LdrSetMUICacheType)) return 77;
    C_EXPECT(UN(LdrSetMUICacheType)(8), ST_BAD_PARAM);
    C_EXPECT(UN(LdrSetMUICacheType)(0xFFFFFFFFu), ST_BAD_PARAM);
    C_EXPECT(UN(LdrSetMUICacheType)(6), ST_BAD_PARAM);        /* both of the exclusive bits */
    C_EXPECT(UN(LdrSetMUICacheType)(7), ST_BAD_PARAM);
    C_EXPECT(UN(LdrSetMUICacheType)(1), 0);                   /* the type can be set once */
    C_EXPECT(UN(LdrSetMUICacheType)(1), ST_UNSUCCESSFUL);
    C_EXPECT(UN(LdrSetMUICacheType)(2), ST_UNSUCCESSFUL);
    return g_cfail ? 1 : 0;
}
TEST(ldr_path_set_mui_cache_type)
{
    REQUIRE(UN(LdrSetMUICacheType));
    DWORD rc = t_run_child("mui_cache", "", 30000);
    if (rc == 77) { t_skip("export missing"); return; }
    EXPECT_EQ(rc, 0);
}

TEST(ldr_path_flush_alternate_resource_modules)
{
    REQUIRE(UN(LdrFlushAlternateResourceModules));
    EXPECT_EQ(UN(LdrFlushAlternateResourceModules)() & 0xff, 1);
    EXPECT_EQ(UN(LdrFlushAlternateResourceModules)() & 0xff, 1);   /* repeated flush on an empty cache */
}
