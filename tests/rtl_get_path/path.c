#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlGetFullPathName_UEx, (PCWSTR, ULONG, PWSTR, PWSTR *, ULONG *));
UDECL(NTSTATUS, RtlGetFullPathName_UstrEx, (PCUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING *, SIZE_T *, BOOLEAN *, ULONG *, SIZE_T *));
UDECL(NTSTATUS, RtlGetLengthWithoutLastFullDosOrNtPathElement, (ULONG, PCUNICODE_STRING, ULONG *));
UDECL(NTSTATUS, RtlGetLengthWithoutTrailingPathSeperators, (ULONG, PCUNICODE_STRING, ULONG *));
UDECL(NTSTATUS, RtlGetExePath, (PCWSTR, PWSTR *));
UDECL(NTSTATUS, RtlGetSearchPath, (PWSTR *));
UDECL(BOOLEAN, RtlGetIntegerAtom, (PCWSTR, USHORT *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, RtlGetPersistedStateLocation, (PCWSTR, PCWSTR, PCWSTR, ULONG, PWSTR, ULONG, ULONG *));

#define ST_INVALID_PARAM ((NTSTATUS)0xC000000D)
#define ST_BUF_TOO_SMALL ((NTSTATUS)0xC0000023)
#define ST_OBJ_NAME_INVALID ((NTSTATUS)0xC0000033)

static UNICODE_STRING us(const WCHAR *s) { UNICODE_STRING u; u.Buffer = (PWSTR)s; u.Length = (USHORT)(wcslen(s) * 2); u.MaximumLength = u.Length + 2; return u; }

TEST(get_full_path_uex_absolute) {
    REQUIRE(UN(RtlGetFullPathName_UEx));
    WCHAR buf[MAX_PATH]; PWSTR part = (PWSTR)0x1; ULONG len = 0xdead;
    NTSTATUS s = UN(RtlGetFullPathName_UEx)(L"C:\\dir\\sub\\file.txt", sizeof buf, buf, &part, &len);
    EXPECT_EQ(s, 0);
    EXPECT_WSTR(buf, L"C:\\dir\\sub\\file.txt");
    EXPECT_EQ(len, wcslen(L"C:\\dir\\sub\\file.txt") * 2);
    CHECK(part == buf + 11);
    EXPECT_WSTR(part, L"file.txt");
    /* dot segments and duplicate separators are collapsed */
    s = UN(RtlGetFullPathName_UEx)(L"C:\\a\\.\\b\\..\\c//d", sizeof buf, buf, &part, &len);
    EXPECT_EQ(s, 0); EXPECT_WSTR(buf, L"C:\\a\\c\\d"); EXPECT_WSTR(part, L"d");
    /* trailing separator: no file part */
    s = UN(RtlGetFullPathName_UEx)(L"C:\\a\\b\\", sizeof buf, buf, &part, &len);
    EXPECT_EQ(s, 0); EXPECT_WSTR(buf, L"C:\\a\\b\\"); EXPECT_EQ(part, NULL);
    /* the optional outputs may be NULL */
    s = UN(RtlGetFullPathName_UEx)(L"C:\\x", sizeof buf, buf, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_WSTR(buf, L"C:\\x");
}

TEST(get_full_path_uex_relative) {
    REQUIRE(UN(RtlGetFullPathName_UEx));
    WCHAR cwd[MAX_PATH], buf[MAX_PATH]; PWSTR part; ULONG len = 0;
    DWORD n = GetCurrentDirectoryW(MAX_PATH, cwd);
    CHECK(n > 2 && n < MAX_PATH);
    NTSTATUS s = UN(RtlGetFullPathName_UEx)(L"rel.txt", sizeof buf, buf, &part, &len);
    EXPECT_EQ(s, 0);
    WCHAR want[MAX_PATH]; wcscpy(want, cwd);
    if (want[wcslen(want) - 1] != L'\\') wcscat(want, L"\\");
    wcscat(want, L"rel.txt");
    CHECK(lstrcmpiW(buf, want) == 0);
    EXPECT_EQ(len, wcslen(buf) * 2);
    EXPECT_WSTR(part, L"rel.txt");
}

TEST(get_full_path_uex_sizes) {
    REQUIRE(UN(RtlGetFullPathName_UEx));
    WCHAR buf[64]; PWSTR part; ULONG len = 0xdead;
    const WCHAR *p = L"C:\\one\\two";
    ULONG need = (ULONG)wcslen(p) * 2;
    /* buffer exactly one char short of the terminator: reports needed size (incl. NUL) */
    memset(buf, 0x55, sizeof buf);
    NTSTATUS s = UN(RtlGetFullPathName_UEx)(p, need, buf, &part, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, need + 2);          /* length > BufferLength means "too small", status stays success */
    memset(buf, 0x55, sizeof buf);
    s = UN(RtlGetFullPathName_UEx)(p, need + 2, buf, &part, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, need); EXPECT_WSTR(buf, p); EXPECT_WSTR(part, L"two");
    /* zero-length buffer queries the size */
    len = 0xdead;
    s = UN(RtlGetFullPathName_UEx)(p, 0, NULL, NULL, &len);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(len, need + 2);
    s = UN(RtlGetFullPathName_UEx)(p, 4, buf, &part, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, need + 2);
    /* empty name is invalid */
    len = 0xdead;
    s = UN(RtlGetFullPathName_UEx)(L"", sizeof buf, buf, &part, &len);
    EXPECT_EQ(s, ST_OBJ_NAME_INVALID);
    EXPECT_EQ(len, 0);
}

TEST(get_full_path_ustrex) {
    REQUIRE(UN(RtlGetFullPathName_UstrEx)); REQUIRE(UN(RtlFreeUnicodeString));
    WCHAR sbuf[MAX_PATH]; UNICODE_STRING in = us(L"C:\\p\\q\\..\\r.txt"), stat, *used = (PUNICODE_STRING)0x1, dyn;
    SIZE_T prefix = 0xdead, need = 0xdead; BOOLEAN inval = 0xcc; ULONG type = 0;
    stat.Buffer = sbuf; stat.Length = 0; stat.MaximumLength = sizeof sbuf;
    memset(&dyn, 0xcc, sizeof dyn);
    NTSTATUS s = UN(RtlGetFullPathName_UstrEx)(&in, &stat, &dyn, &used, &prefix, &inval, &type, &need);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(used, &stat);
    EXPECT_EQ(stat.Length, wcslen(L"C:\\p\\r.txt") * 2);
    CHECK(stat.Buffer == sbuf && !memcmp(sbuf, L"C:\\p\\r.txt", stat.Length + 2));
    EXPECT_EQ(prefix, 5);
    EXPECT_EQ(inval, FALSE);
    EXPECT_EQ(type, 2);                              /* RtlPathTypeDriveAbsolute */
    /* static buffer too small -> dynamic buffer is allocated */
    WCHAR tiny[4]; stat.Buffer = tiny; stat.Length = 0; stat.MaximumLength = sizeof tiny;
    used = NULL; memset(&dyn, 0, sizeof dyn); prefix = 0xdead;
    s = UN(RtlGetFullPathName_UstrEx)(&in, &stat, &dyn, &used, &prefix, &inval, &type, &need);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(used, &dyn);
    CHECK(dyn.Buffer != NULL && dyn.Length == wcslen(L"C:\\p\\r.txt") * 2 && dyn.MaximumLength > dyn.Length);
    if (dyn.Buffer) { EXPECT_WSTR(dyn.Buffer, L"C:\\p\\r.txt"); UN(RtlFreeUnicodeString)(&dyn); }
    /* static buffer too small, no dynamic string given: BUFFER_TOO_SMALL and required size */
    stat.Length = 0; need = 0xdead; used = (PUNICODE_STRING)0x1;
    s = UN(RtlGetFullPathName_UstrEx)(&in, &stat, NULL, &used, NULL, NULL, &type, &need);
    EXPECT_EQ(s, ST_BUF_TOO_SMALL);
    EXPECT_EQ(need, wcslen(L"C:\\p\\q\\..\\r.txt") * 2 + 2);     /* conservative: the unnormalized length plus NUL */
    /* dynamic string without a StringUsed pointer is invalid */
    stat.Buffer = sbuf; stat.MaximumLength = sizeof sbuf; memset(&dyn, 0, sizeof dyn);
    s = UN(RtlGetFullPathName_UstrEx)(&in, &stat, &dyn, NULL, NULL, NULL, &type, NULL);
    EXPECT_EQ(s, ST_INVALID_PARAM);
    /* empty path */
    UNICODE_STRING empty = us(L"");
    type = 0; s = UN(RtlGetFullPathName_UstrEx)(&empty, &stat, NULL, &used, NULL, NULL, &type, NULL);
    EXPECT_EQ(s, ST_OBJ_NAME_INVALID);
    /* no static buffer at all: a dynamic buffer is returned */
    used = NULL; memset(&dyn, 0, sizeof dyn);
    type = 0; s = UN(RtlGetFullPathName_UstrEx)(&in, NULL, &dyn, &used, NULL, NULL, &type, NULL);
    t_note("UstrEx no static buffer: status=%08lx", (ULONG)s);
    if (s == 0 && dyn.Buffer) { EXPECT_WSTR(dyn.Buffer, L"C:\\p\\r.txt"); UN(RtlFreeUnicodeString)(&dyn); }
}

TEST(get_length_without_trailing_separators) {
    REQUIRE(UN(RtlGetLengthWithoutTrailingPathSeperators));
    ULONG len = 0xdead;
    struct { const WCHAR *p; ULONG want; } c[] = {
        { L"C:\\a\\b", 6 }, { L"C:\\a\\b\\", 6 }, { L"C:\\a\\b\\\\//", 6 }, { L"/", 0 }, { L"\\\\\\", 0 },
        { L"", 0 }, { L"abc", 3 }, { L"a/b/", 3 }, { L"C:\\", 2 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        UNICODE_STRING u = us(c[i].p); len = 0xdead;
        EXPECT_EQ(UN(RtlGetLengthWithoutTrailingPathSeperators)(0, &u, &len), 0);
        CHECKF(len == c[i].want, "case %u got %lu want %lu", i, len, c[i].want);
    }
    UNICODE_STRING u = us(L"C:\\a\\");
    len = 0xdead; EXPECT_EQ(UN(RtlGetLengthWithoutTrailingPathSeperators)(1, &u, &len), ST_INVALID_PARAM); EXPECT_EQ(len, 0);
    len = 0xdead; EXPECT_EQ(UN(RtlGetLengthWithoutTrailingPathSeperators)(0, NULL, &len), ST_INVALID_PARAM); EXPECT_EQ(len, 0);
    EXPECT_EQ(UN(RtlGetLengthWithoutTrailingPathSeperators)(0, &u, NULL), ST_INVALID_PARAM);
}

TEST(get_length_without_last_element) {
    REQUIRE(UN(RtlGetLengthWithoutLastFullDosOrNtPathElement));
    ULONG len = 0xdead;
    struct { const WCHAR *p; ULONG want; } c[] = {
        { L"C:\\a\\b", 5 }, { L"C:\\a\\b\\", 5 }, { L"C:\\a\\b\\\\", 5 }, { L"C:\\a", 3 }, { L"C:\\", 0 },
        { L"\\\\?\\C:\\a\\b", 9 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        UNICODE_STRING u = us(c[i].p); len = 0xdead;
        NTSTATUS s = UN(RtlGetLengthWithoutLastFullDosOrNtPathElement)(0, &u, &len);
        t_note("without-last(\"%ls\") = %08lx len=%lu", c[i].p, (ULONG)s, len);
        EXPECT_EQ(s, 0);
        CHECKF(len == c[i].want, "case %u got %lu want %lu", i, len, c[i].want);
    }
    UNICODE_STRING e = us(L"");
    len = 0xdead; EXPECT_EQ(UN(RtlGetLengthWithoutLastFullDosOrNtPathElement)(0, &e, &len), 0); EXPECT_EQ(len, 0);
    UNICODE_STRING u = us(L"C:\\a\\b");
    len = 0xdead; EXPECT_EQ(UN(RtlGetLengthWithoutLastFullDosOrNtPathElement)(1, &u, &len), ST_INVALID_PARAM); EXPECT_EQ(len, 0);
    len = 0xdead; EXPECT_EQ(UN(RtlGetLengthWithoutLastFullDosOrNtPathElement)(0, NULL, &len), ST_INVALID_PARAM); EXPECT_EQ(len, 0);
    EXPECT_EQ(UN(RtlGetLengthWithoutLastFullDosOrNtPathElement)(0, &u, NULL), ST_INVALID_PARAM);
}

TEST(get_search_and_exe_path) {
    REQUIRE(UN(RtlGetSearchPath)); REQUIRE(UN(RtlGetExePath));
    PWSTR sp = (PWSTR)0x1;
    EXPECT_EQ(UN(RtlGetSearchPath)(&sp), 0);
    CHECK(sp > (PWSTR)0x10000);
    WCHAR sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
    if (sp > (PWSTR)0x10000) {
        CHECK(wcslen(sp) > wcslen(sys));
        /* system directory is a path element */
        WCHAR needle[MAX_PATH + 2]; wsprintfW(needle, L"%s;", sys);
        WCHAR *lc = _wcsdup(sp); WCHAR *lneedle = _wcsdup(needle); CharLowerW(lc); CharLowerW(lneedle);
        CHECK(wcsstr(lc, lneedle) != NULL);
        free(lc); free(lneedle);
        PWSTR sp2 = NULL; EXPECT_EQ(UN(RtlGetSearchPath)(&sp2), 0); EXPECT_EQ(sp2, sp);   /* cached */
    }
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    WCHAR *slash = wcsrchr(exe, L'\\'); if (slash) *slash = 0;
    PWSTR ep = (PWSTR)0x1, ep2 = (PWSTR)0x1;
    SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", NULL);
    EXPECT_EQ(UN(RtlGetExePath)(L"tool.exe", &ep), 0);
    EXPECT_EQ(UN(RtlGetExePath)(L"C:\\dir\\tool.exe", &ep2), 0);
    CHECK(ep > (PWSTR)0x10000 && ep2 > (PWSTR)0x10000);
    if (ep > (PWSTR)0x10000 && ep2 > (PWSTR)0x10000) {
        /* application directory first, then the current directory ".", then the system directories */
        size_t n = wcslen(exe);
        CHECK(!_wcsnicmp(ep, exe, n) && ep[n] == L';');
        CHECK(!_wcsnicmp(ep2, exe, n) && ep2[n] == L';');
        CHECK(wcsstr(ep, L";.;") != NULL);
        CHECK(wcsstr(ep2, L";.;") != NULL);
        WCHAR *lc = _wcsdup(ep); CharLowerW(lc);
        WCHAR *ls = _wcsdup(sys); CharLowerW(ls);
        CHECK(wcsstr(lc, ls) != NULL);
        free(lc); free(ls);
    }
    /* with NoDefaultCurrentDirectoryInExePath set the bare-name path drops the current directory */
    SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", L"1");
    PWSTR ep3 = (PWSTR)0x1;
    NTSTATUS s3 = UN(RtlGetExePath)(L"tool.exe", &ep3);
    EXPECT_EQ(s3, 0);
    if (s3 == 0 && ep3 > (PWSTR)0x10000) { t_note("exe path without cwd: %.60ls", ep3); CHECK(wcsstr(ep3, L";.;") == NULL && wcscmp(ep3, L".") != 0); }
    SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", NULL);
}

TEST(get_integer_atom) {
    REQUIRE(UN(RtlGetIntegerAtom));
    USHORT a = 0xdead;
    EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)0x1234, &a), TRUE); EXPECT_EQ(a, 0x1234);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)1, &a), TRUE); EXPECT_EQ(a, 1);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)0xbfff, &a), TRUE); EXPECT_EQ(a, 0xbfff);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)0, &a), TRUE); EXPECT_EQ(a, 0xc000);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)0xc000, &a), FALSE); EXPECT_EQ(a, 0xdead);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)((PCWSTR)(ULONG_PTR)0xffff, &a), FALSE);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#1234", &a), TRUE); EXPECT_EQ(a, 1234);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#1", &a), TRUE); EXPECT_EQ(a, 1);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#49151", &a), TRUE); EXPECT_EQ(a, 49151);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#49152", &a), TRUE); EXPECT_EQ(a, 0xc000);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#0", &a), TRUE); EXPECT_EQ(a, 0xc000);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#12ab", &a), FALSE); EXPECT_EQ(a, 0xdead);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"name", &a), FALSE); EXPECT_EQ(a, 0xdead);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"1234", &a), FALSE);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#-5", &a), FALSE);
    /* the atom output is optional */
    EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#77", NULL), TRUE);
    EXPECT_EQ(UN(RtlGetIntegerAtom)(L"zzz", NULL), FALSE);
    a = 0xdead; EXPECT_EQ(UN(RtlGetIntegerAtom)(L"#", &a), FALSE); EXPECT_EQ(a, 0xdead);
}
