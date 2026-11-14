#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlGetUserPreferredUILanguages, (ULONG, PCWSTR, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlGetSystemPreferredUILanguages, (ULONG, PCWSTR, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlGetProcessPreferredUILanguages, (ULONG, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlGetThreadPreferredUILanguages, (ULONG, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlGetUILanguageInfo, (ULONG, PCWSTR, PWSTR, ULONG *, ULONG *));
UDECL(NTSTATUS, RtlGetParentLocaleName, (PCWSTR, PUNICODE_STRING, ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlGetThreadLangIdByIndex, (ULONG, ULONG, ULONG *, ULONG *));
UDECL(NTSTATUS, RtlGetFileMUIPath, (ULONG, PCWSTR, PWSTR, ULONG *, PWSTR, ULONG *, ULONGLONG *));

#define ST_INVALID_PARAM ((NTSTATUS)0xC000000D)
#define ST_BUF_TOO_SMALL ((NTSTATUS)0xC0000023)
#define NAME 8u
#define LID 4u

/* length in WCHARs of a double-NUL terminated list including the terminators; the empty list is two NULs */
static ULONG multisz(const WCHAR *p, ULONG *count) {
    ULONG n = 0, c = 0;
    while (p[n]) { c++; n += (ULONG)wcslen(p + n) + 1; }
    *count = c; return c ? n + 1 : 2;
}

typedef NTSTATUS (*lang_get_fn)(ULONG flags, ULONG *count, WCHAR *buf, ULONG *size);
static NTSTATUS user_get(ULONG f, ULONG *c, WCHAR *b, ULONG *s) { return UN(RtlGetUserPreferredUILanguages)(f, NULL, c, b, s); }
static NTSTATUS sys_get(ULONG f, ULONG *c, WCHAR *b, ULONG *s) { return UN(RtlGetSystemPreferredUILanguages)(f, NULL, c, b, s); }
static NTSTATUS proc_get(ULONG f, ULONG *c, WCHAR *b, ULONG *s) { return UN(RtlGetProcessPreferredUILanguages)(f, c, b, s); }
static NTSTATUS thr_get(ULONG f, ULONG *c, WCHAR *b, ULONG *s) { return UN(RtlGetThreadPreferredUILanguages)(f, c, b, s); }

static void check_family(const char *what, lang_get_fn get, BOOL (WINAPI *k32)(DWORD, PULONG, PZZWSTR, PULONG), int null_count_ok, int null_count_invalid) {
    WCHAR buf[512], kb[512]; ULONG cnt = 0, size = 0;
    /* size query with no buffer */
    NTSTATUS s = get(NAME, &cnt, NULL, &size);
    EXPECT_EQ(s, 0);
    CHECK(size >= 2 && size < 512);
    ULONG need = size, qcnt = cnt;
    /* exact buffer */
    memset(buf, 0x55, sizeof buf); cnt = 0; size = need;
    s = get(NAME, &cnt, buf, &size);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(size, need); EXPECT_EQ(cnt, qcnt);
    ULONG n2 = 0; ULONG len = multisz(buf, &n2);
    CHECKF(len == need, "%s: multi-string length %lu vs reported %lu", what, len, need);
    EXPECT_EQ(n2, cnt);
    /* same list as the documented Win32 wrapper */
    if (k32) {
        ULONG kc = 0xdead, ks = 512; memset(kb, 0x55, sizeof kb);
        if (k32(NAME, &kc, kb, &ks)) { if (cnt) EXPECT_EQ(kc, cnt); EXPECT_EQ(ks, need); CHECK(!memcmp(kb, buf, need * 2)); }
    }
    /* one char short */
    if (need > 2) {
        ULONG short_size = need - 1, c2 = 0;
        s = get(NAME, &c2, buf, &short_size);
        EXPECT_EQ(s, ST_BUF_TOO_SMALL);
        EXPECT_EQ(short_size, need);
    }
    /* language ids: 4 hex digits per entry */
    ULONG idsize = 0, idcnt = 0;
    s = get(LID, &idcnt, NULL, &idsize);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(idcnt, cnt);
    WCHAR ids[512]; idsize = 512; idcnt = 0;
    s = get(LID, &idcnt, ids, &idsize);
    EXPECT_EQ(s, 0);
    if (s == 0) { ULONG ic = 0; ULONG l = multisz(ids, &ic); EXPECT_EQ(ic, cnt); EXPECT_EQ(l, idsize);
        for (WCHAR *p = ids; *p; p += wcslen(p) + 1) CHECK(wcslen(p) == 4); }
    /* argument validation */
    if (null_count_invalid) { size = 512; EXPECT_EQ(get(NAME, NULL, buf, &size), ST_INVALID_PARAM); }
    if (null_count_ok) { size = 512; EXPECT_EQ(get(NAME, NULL, buf, &size), 0); }
    cnt = 0; size = 512; EXPECT_EQ(get(NAME | LID, &cnt, buf, &size), ST_INVALID_PARAM);
    size = 512; EXPECT_EQ(get(0x80000000u, &cnt, buf, &size), ST_INVALID_PARAM);
}

TEST(get_user_preferred_ui_languages) {
    REQUIRE(UN(RtlGetUserPreferredUILanguages));
    check_family("user", user_get, (void *)UIN("kernel32.dll", GetUserPreferredUILanguages), 0, 0);
    ULONG c, s = 512; WCHAR b[512];
    EXPECT_EQ(UN(RtlGetUserPreferredUILanguages)(NAME, NULL, &c, b, &s), 0);
    CHECK(c >= 1);                    /* the user always has at least one UI language */
}

TEST(get_system_preferred_ui_languages) {
    REQUIRE(UN(RtlGetSystemPreferredUILanguages));
    check_family("system", sys_get, (void *)UIN("kernel32.dll", GetSystemPreferredUILanguages), 0, 0);
    ULONG c, s = 512; WCHAR b[512];
    EXPECT_EQ(UN(RtlGetSystemPreferredUILanguages)(NAME, NULL, &c, b, &s), 0);
    CHECK(c >= 1);
}

TEST(get_process_preferred_ui_languages) {
    REQUIRE(UN(RtlGetProcessPreferredUILanguages));
    check_family("process", proc_get, (void *)UIN("kernel32.dll", GetProcessPreferredUILanguages), 0, 1);
    { WCHAR b[16]; ULONG sz = 16, c = 0; EXPECT_EQ(UN(RtlGetProcessPreferredUILanguages)(NAME, &c, b, NULL), ST_INVALID_PARAM);
      sz = 4; EXPECT_EQ(UN(RtlGetProcessPreferredUILanguages)(NAME, &c, NULL, &sz), ST_INVALID_PARAM); }
    /* flags 0 default to MUI_LANGUAGE_NAME */
    WCHAR a[512], b[512]; ULONG ca, cb, sa = 512, sb = 512;
    ca = cb = 0; sa = sb = 512;
    EXPECT_EQ(UN(RtlGetProcessPreferredUILanguages)(0, &ca, a, &sa), 0);
    EXPECT_EQ(UN(RtlGetProcessPreferredUILanguages)(NAME, &cb, b, &sb), 0);
    EXPECT_EQ(ca, cb); EXPECT_EQ(sa, sb); CHECK(!memcmp(a, b, sa * 2));
}

TEST(get_thread_preferred_ui_languages) {
    REQUIRE(UN(RtlGetThreadPreferredUILanguages));
    BOOL (WINAPI *setl)(DWORD, PCZZWSTR, PULONG) = (void *)UIN("kernel32.dll", SetThreadPreferredUILanguages);
    check_family("thread", thr_get, (void *)UIN("kernel32.dll", GetThreadPreferredUILanguages), 1, 0);
    { WCHAR b[16]; ULONG c = 0; EXPECT_EQ(UN(RtlGetThreadPreferredUILanguages)(NAME, &c, b, NULL), ST_INVALID_PARAM); }
    REQUIRE(setl);
    ULONG n = 0; WCHAR b[512]; ULONG c, s = 512;
    CHECK(setl(MUI_LANGUAGE_NAME, L"en-US\0", &n));
    EXPECT_EQ(n, 1);
    /* thread languages only (MUI_THREAD_LANGUAGES = 0x40 has no effect on the Rtl call: just query) */
    s = 512; memset(b, 0, sizeof b);
    EXPECT_EQ(UN(RtlGetThreadPreferredUILanguages)(NAME | 0x40, &c, b, &s), 0);
    t_note("thread languages after set: count=%lu first=%ls size=%lu", c, b, s);
    CHECK(c >= 1);
    CHECK(lstrcmpiW(b, L"en-US") == 0);
    /* index lookup */
    if (UN(RtlGetThreadLangIdByIndex)) {
        ULONG id = 0xdead, total = 0xdead;
        EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(0, 0, &id, &total), 0);
        EXPECT_EQ(id, 0x409); EXPECT_EQ(total, 1);
        id = 0xdead; total = 0xdead;
        EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(0, 1, &id, &total), (NTSTATUS)0xC0000225);
        EXPECT_EQ(id, 0); EXPECT_EQ(total, 1);
        id = 0xdead; EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(0, 0, &id, NULL), 0); EXPECT_EQ(id, 0x409);
        EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(0, 0, NULL, &total), ST_INVALID_PARAM);
        EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(1, 0, &id, &total), ST_INVALID_PARAM);
    }
    /* a two entry list round-trips in order */
    n = 0;
    if (setl(MUI_LANGUAGE_NAME, L"en-US\0en-GB\0", &n) && n == 2) {
        s = 512; memset(b, 0, sizeof b);
        EXPECT_EQ(UN(RtlGetThreadPreferredUILanguages)(NAME, &c, b, &s), 0);
        CHECK(c >= 2);
        { WCHAR all[600]; all[0] = 0; for (WCHAR *q = b; *q; q += wcslen(q) + 1) { wcscat(all, q); wcscat(all, L"|"); } t_note("thread list: %ls", all); }
        { int has_gb = 0; for (WCHAR *q = b; *q; q += wcslen(q) + 1) if (!lstrcmpiW(q, L"en-GB")) has_gb = 1; CHECK(has_gb); }
        CHECK(lstrcmpiW(b, L"en-US") == 0);              /* merged with fallbacks (en-US, en, en-GB) but in preference order */
        if (UN(RtlGetThreadLangIdByIndex)) {
            ULONG id = 0, total = 0;
            EXPECT_EQ(UN(RtlGetThreadLangIdByIndex)(0, 1, &id, &total), 0); EXPECT_EQ(id, 0x809); EXPECT_EQ(total, 2);
        }
    } else t_note("two-entry thread language list was not accepted");
    /* clearing restores the empty thread list */
    n = 0xdead; CHECK(setl(MUI_LANGUAGE_NAME, L"\0", &n));
    if (UN(RtlGetThreadLangIdByIndex)) {
        ULONG id = 0xdead, total = 0xdead;
        NTSTATUS st = UN(RtlGetThreadLangIdByIndex)(0, 0, &id, &total);
        EXPECT_EQ(st, (NTSTATUS)0xC0000225); EXPECT_EQ(id, 0);
    }
}

TEST(get_ui_language_info) {
    REQUIRE(UN(RtlGetUILanguageInfo));
    WCHAR fb[256]; ULONG len = 256, attr = 0xdead;
    NTSTATUS s = UN(RtlGetUILanguageInfo)(NAME, L"en-US\0", fb, &len, &attr);
    t_note("UILanguageInfo(en-US): status=%08lx len=%lu attr=%lx fb=%ls", (ULONG)s, len, attr, fb);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(len, 2); EXPECT_EQ(fb[0], 0); EXPECT_EQ(fb[1], 0);   /* no fallback languages: empty list */
        EXPECT_EQ(attr & 0x61, 0x61);             /* full + installed + licensed */
    }
    /* Win32 wrapper agrees */
    BOOL (WINAPI *k)(DWORD, PCZZWSTR, PZZWSTR, PULONG, PDWORD) = (void *)UIN("kernel32.dll", GetUILanguageInfo);
    if (k) { WCHAR kb[256]; ULONG kl = 256; DWORD ka = 0xdead; if (k(NAME, L"en-US\0", kb, &kl, &ka)) { EXPECT_EQ(kl, len); EXPECT_EQ(ka, attr & 0x61); } }
    /* attributes only */
    attr = 0xdead; s = UN(RtlGetUILanguageInfo)(NAME, L"en-US\0", NULL, NULL, &attr);
    EXPECT_EQ(s, 0); EXPECT_EQ(attr & 0x61, 0x61);
    /* language id form */
    len = 256; attr = 0xdead;
    s = UN(RtlGetUILanguageInfo)(LID, L"0409\0", fb, &len, &attr);
    EXPECT_EQ(s, 0); EXPECT_EQ(attr & 0x61, 0x61);
    /* small fallback buffer */
    len = 1;
    s = UN(RtlGetUILanguageInfo)(NAME, L"en-US\0", fb, &len, &attr);
    t_note("UILanguageInfo(1-char buffer): status=%08lx len=%lu", (ULONG)s, len);
    /* validation */
    len = 256;
    EXPECT_EQ(UN(RtlGetUILanguageInfo)(NAME, NULL, fb, &len, &attr), ST_INVALID_PARAM);
    EXPECT_EQ(UN(RtlGetUILanguageInfo)(NAME, L"\0", fb, &len, &attr), ST_INVALID_PARAM);
    EXPECT_EQ(UN(RtlGetUILanguageInfo)(NAME | LID, L"en-US\0", fb, &len, &attr), ST_INVALID_PARAM);
    len = 4; EXPECT_EQ(UN(RtlGetUILanguageInfo)(NAME, L"en-US\0", NULL, &len, &attr), ST_INVALID_PARAM);
}

TEST(get_parent_locale_name) {
    REQUIRE(UN(RtlGetParentLocaleName));
    struct { const WCHAR *loc; const WCHAR *parent; } c[] = {
        { L"en-US", L"en" }, { L"de-DE", L"de" }, { L"fr-CA", L"fr" }, { L"pt-BR", L"pt" },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        WCHAR buf[LOCALE_NAME_MAX_LENGTH] = {0}; UNICODE_STRING u; u.Buffer = buf; u.Length = 0; u.MaximumLength = sizeof buf;
        NTSTATUS s = UN(RtlGetParentLocaleName)(c[i].loc, &u, 2, 0);
        t_note("parent(%ls) = %08lx '%ls'", c[i].loc, (ULONG)s, buf);
        EXPECT_EQ(s, 0);
        if (s == 0) { CHECK(u.Length == wcslen(c[i].parent) * 2); CHECK(!lstrcmpiW(buf, c[i].parent)); }
        /* the Win32 view of the same data */
        WCHAR kb[LOCALE_NAME_MAX_LENGTH] = {0};
        int (WINAPI *gli)(LPCWSTR, LCTYPE, LPWSTR, int) = (void *)UIN("kernel32.dll", GetLocaleInfoEx);
        if (gli && gli(c[i].loc, LOCALE_SPARENT, kb, LOCALE_NAME_MAX_LENGTH)) CHECK(!lstrcmpiW(kb, c[i].parent));
    }
    WCHAR buf[LOCALE_NAME_MAX_LENGTH]; UNICODE_STRING u; u.Buffer = buf; u.Length = 0; u.MaximumLength = sizeof buf;
    /* unknown locale name */
    EXPECT_EQ(UN(RtlGetParentLocaleName)(L"xx-ZZ-nope", &u, 2, 0), (NTSTATUS)0xC00000EF);
    /* NULL name */
    EXPECT_EQ(UN(RtlGetParentLocaleName)(NULL, &u, 2, 0), (NTSTATUS)0xC00000EF);
    /* output string problems */
    EXPECT_EQ(UN(RtlGetParentLocaleName)(L"en-US", NULL, 2, 0), (NTSTATUS)0xC00000F0);
    UNICODE_STRING nb = { 0, 0, NULL };
    EXPECT_EQ(UN(RtlGetParentLocaleName)(L"en-US", &nb, 2, 0), (NTSTATUS)0xC00000F0);
    /* bad flag bits */
    EXPECT_EQ(UN(RtlGetParentLocaleName)(L"en-US", &u, 1, 0), (NTSTATUS)0xC00000F1);
    EXPECT_EQ(UN(RtlGetParentLocaleName)(L"en-US", &u, 8, 0), (NTSTATUS)0xC00000F1);
    /* too small output */
    UNICODE_STRING sm; sm.Buffer = buf; sm.Length = 0; sm.MaximumLength = 2;
    NTSTATUS s = UN(RtlGetParentLocaleName)(L"en-US", &sm, 2, 0);
    t_note("parent into 1-char buffer = %08lx", (ULONG)s);
    CHECK(s < 0);
}

TEST(get_file_mui_path) {
    REQUIRE(UN(RtlGetFileMUIPath));
    WCHAR sys[MAX_PATH], file[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH); wsprintfW(file, L"%s\\kernel32.dll", sys);
    WCHAR lang[LOCALE_NAME_MAX_LENGTH] = {0}, path[MAX_PATH] = {0}; ULONG ll = LOCALE_NAME_MAX_LENGTH, pl = MAX_PATH; ULONGLONG en = 0;
    NTSTATUS s = UN(RtlGetFileMUIPath)(0x10 /* MUI_USER_PREFERRED_UI_LANGUAGES */, file, lang, &ll, path, &pl, &en);
    t_note("FileMUIPath(user) = %08lx lang='%ls' path='%ls' enum=%llx", (ULONG)s, lang, path, en);
    if (s != 0) { t_note("no MUI file resolved; skipping content checks"); }
    else {
        EXPECT_EQ(ll, LOCALE_NAME_MAX_LENGTH); EXPECT_EQ(pl, MAX_PATH);   /* observed: lengths are only rewritten when a buffer is too small */
        size_t n = wcslen(path);
        CHECK(n > 4 && lstrcmpiW(path + n - 4, L".mui") == 0);
        CHECK(wcsstr(path, lang) != NULL || wcsstr(path, L"\\") != NULL);
        CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
        BOOL (WINAPI *k)(DWORD, PCWSTR, PWSTR, PULONG, PWSTR, PULONG, PULONGLONG) = (void *)UIN("kernel32.dll", GetFileMUIPath);
        if (k) { WCHAR l2[LOCALE_NAME_MAX_LENGTH] = {0}, p2[MAX_PATH] = {0}; ULONG ll2 = LOCALE_NAME_MAX_LENGTH, pl2 = MAX_PATH; ULONGLONG e2 = 0;
            if (k(0x10, file, l2, &ll2, p2, &pl2, &e2)) { CHECK(!lstrcmpiW(l2, lang)); CHECK(!lstrcmpiW(p2, path)); } }
        /* path buffer too small */
        ULONG small = 4; ll = LOCALE_NAME_MAX_LENGTH; en = 0;
        s = UN(RtlGetFileMUIPath)(0x10, file, lang, &ll, path, &small, &en);
        EXPECT_EQ(s, 0);                                   /* observed: success status, required size reported */
        EXPECT_EQ(small, wcslen(path) + 1);
    }
    /* validation */
    ll = LOCALE_NAME_MAX_LENGTH; pl = MAX_PATH; en = 0;
    EXPECT_EQ(UN(RtlGetFileMUIPath)(0x10, NULL, lang, &ll, path, &pl, &en), ST_INVALID_PARAM);
    EXPECT_EQ(UN(RtlGetFileMUIPath)(0xffffffff, file, lang, &ll, path, &pl, &en), ST_INVALID_PARAM);
}
