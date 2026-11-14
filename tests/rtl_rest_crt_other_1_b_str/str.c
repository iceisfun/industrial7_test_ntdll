/* String, name, address and message helpers: Ethernet addresses, GUID parsing, integer to string,
 * downcase/erase, wildcard detection, file existence, environment expansion, IDN, DNS host name,
 * FormatMessage, correlation vectors and capability SIDs. */
#include "t.h"

#define ST_INVPARAM ((NTSTATUS)0xC000000D)
#define ST_BUFOVER  ((NTSTATUS)0x80000005)
#define ST_BUFSMALL ((NTSTATUS)0xC0000023)

/* ---------------- Ethernet addresses ---------------- */
UDECL(PSTR,  RtlEthernetAddressToStringA, (const UCHAR *, PSTR));
UDECL(PWSTR, RtlEthernetAddressToStringW, (const UCHAR *, PWSTR));
UDECL(NTSTATUS, RtlEthernetStringToAddressA, (PCSTR, PCSTR *, UCHAR *));
UDECL(NTSTATUS, RtlEthernetStringToAddressW, (PCWSTR, PCWSTR *, UCHAR *));

TEST(rtl_rest_b_eth_to_string) {
    REQUIRE(UN(RtlEthernetAddressToStringA)); REQUIRE(UN(RtlEthernetAddressToStringW));
    static const UCHAR mac[6] = { 0x00, 0x1a, 0x2B, 0x3c, 0xFF, 0x05 };
    char a[32]; WCHAR w[32];
    memset(a, 'x', sizeof a); for (int i = 0; i < 32; i++) w[i] = L'x';
    PSTR e = UN(RtlEthernetAddressToStringA)(mac, a);
    EXPECT_STR(a, "00-1A-2B-3C-FF-05");           /* upper-case hex, '-' separated */
    EXPECT_EQ(e, a + 17);                         /* returns pointer to the terminating NUL */
    EXPECT_EQ(a[17], 0);
    PWSTR ew = UN(RtlEthernetAddressToStringW)(mac, w);
    EXPECT_WSTR(w, L"00-1A-2B-3C-FF-05");
    EXPECT_EQ(ew, w + 17);
    static const UCHAR zero[6] = { 0 }, ones[6] = { 255, 255, 255, 255, 255, 255 };
    UN(RtlEthernetAddressToStringA)(zero, a); EXPECT_STR(a, "00-00-00-00-00-00");
    UN(RtlEthernetAddressToStringA)(ones, a); EXPECT_STR(a, "FF-FF-FF-FF-FF-FF");
}
TEST(rtl_rest_b_eth_from_string) {
    REQUIRE(UN(RtlEthernetStringToAddressA)); REQUIRE(UN(RtlEthernetStringToAddressW));
    UCHAR out[8]; PCSTR term; PCWSTR termw;
    static const UCHAR want[6] = { 0x00, 0x1a, 0x2b, 0x3c, 0xff, 0x05 };
    const char *s1 = "00-1a-2B-3c-Ff-05";
    memset(out, 0xEE, sizeof out); term = NULL;
    EXPECT_EQ(UN(RtlEthernetStringToAddressA)(s1, &term, out), 0);
    CHECK(!memcmp(out, want, 6)); EXPECT_EQ(out[6], 0xEE);
    EXPECT_EQ(term, s1 + 17);
    const char *s2 = "00:1a:2b:3c:ff:05";           /* ':' accepted as separator */
    memset(out, 0xEE, sizeof out);
    EXPECT_EQ(UN(RtlEthernetStringToAddressA)(s2, &term, out), 0);
    CHECK(!memcmp(out, want, 6));
    const char *s3 = "00-1a-2b-3c-ff-05zz";        /* trailing text is reported through the terminator */
    memset(out, 0xEE, sizeof out);
    EXPECT_EQ(UN(RtlEthernetStringToAddressA)(s3, &term, out), 0);
    CHECK(!memcmp(out, want, 6)); EXPECT_EQ(term, s3 + 17);
    memset(out, 0xEE, sizeof out);
    const char *s4 = "00-1a-2b-3c-ff-05 ";
    EXPECT_EQ(UN(RtlEthernetStringToAddressA)(s4, &term, out), 0); EXPECT_EQ(term, s4 + 17);
    /* wide */
    memset(out, 0xEE, sizeof out); termw = NULL;
    const WCHAR *w1 = L"00-1a-2B-3c-Ff-05";
    EXPECT_EQ(UN(RtlEthernetStringToAddressW)(w1, &termw, out), 0);
    CHECK(!memcmp(out, want, 6)); EXPECT_EQ(termw, w1 + 17);
    const WCHAR *w2 = L"00:1A:2B:3C:FF:05!";
    EXPECT_EQ(UN(RtlEthernetStringToAddressW)(w2, &termw, out), 0); EXPECT_EQ(termw, w2 + 17);
    /* failures */
    static const char *bad[] = { "", "00-1a-2b-3c-ff", "00-1a-2b-3c-ff-0", "0-1a-2b-3c-ff-05", "00-1a-2b-3c-ff-050",
        "00-1a-2b-3c-ff-05-06", "00-1a-2b-3c-ff-05-", "zz-1a-2b-3c-ff-05", "00 1a 2b 3c ff 05" };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        WCHAR wb[64]; for (int j = 0; ; j++) { wb[j] = (WCHAR)(unsigned char)bad[i][j]; if (!bad[i][j]) break; }
        memset(out, 0xEE, sizeof out);
        NTSTATUS s = UN(RtlEthernetStringToAddressA)(bad[i], &term, out);
        CHECKF(s == ST_INVPARAM, "A \"%s\" -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(out[0] == 0xEE && out[5] == 0xEE, "A \"%s\" wrote output on failure", bad[i]);
        s = UN(RtlEthernetStringToAddressW)(wb, &termw, out);
        CHECKF(s == ST_INVPARAM, "W \"%s\" -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(out[0] == 0xEE && out[5] == 0xEE, "W \"%s\" wrote output on failure", bad[i]);
    }
}

/* ---------------- GUID from string / Int64 to string ---------------- */
UDECL(NTSTATUS, RtlGUIDFromString, (PUNICODE_STRING, GUID *));
UDECL(NTSTATUS, RtlInt64ToUnicodeString, (ULONGLONG, ULONG, PUNICODE_STRING));

static void us_init(UNICODE_STRING *u, const WCHAR *s) { U(RtlInitUnicodeString)(u, s); }

TEST(rtl_rest_b_guid_from_string) {
    REQUIRE(UN(RtlGUIDFromString)); REQUIRE(U(RtlInitUnicodeString));
    GUID g; UNICODE_STRING u;
    us_init(&u, L"{01234567-89AB-cdef-0123-456789ABCDEF}");
    memset(&g, 0, sizeof g);
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0);
    EXPECT_EQ(g.Data1, 0x01234567); EXPECT_EQ(g.Data2, 0x89AB); EXPECT_EQ(g.Data3, 0xCDEF);
    static const unsigned char d4[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    CHECK(!memcmp(g.Data4, d4, 8));
    us_init(&u, L"{00000000-0000-0000-0000-000000000000}");
    memset(&g, 0xAA, sizeof g);
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0);
    CHECK(g.Data1 == 0 && g.Data2 == 0 && g.Data3 == 0 && g.Data4[0] == 0 && g.Data4[7] == 0);
    /* Length controls how much is parsed, not the NUL position */
    static const WCHAR padded[] = L"{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}xx";
    u.Buffer = (PWSTR)padded; u.Length = 38 * 2; u.MaximumLength = sizeof padded;
    memset(&g, 0, sizeof g);
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0); EXPECT_EQ(g.Data1, 0xFFFFFFFFu); EXPECT_EQ(g.Data4[7], 0xFF);
    static const WCHAR *bad[] = {
        L"", L"01234567-89AB-CDEF-0123-456789ABCDEF", L"{01234567-89AB-CDEF-0123-456789ABCDEF",
        L"{01234567-89AB-CDEF-0123-456789ABCDE}", L"{0123456-789AB-CDEF-0123-456789ABCDEF}",
        L"{01234567-89AB-CDEF-0123-456789ABCDEG}", L"{01234567_89AB_CDEF_0123_456789ABCDEF}",
        L"{01234567-89AB-CDEF-01234-56789ABCDEF}" };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        us_init(&u, bad[i]);
        NTSTATUS s = UN(RtlGUIDFromString)(&u, &g);
        CHECKF(s == ST_INVPARAM, "case %u -> 0x%lx", i, (unsigned long)s);
    }
}
TEST(rtl_rest_b_int64_to_unicode_string) {
    REQUIRE(UN(RtlInt64ToUnicodeString));
    WCHAR buf[80]; UNICODE_STRING u;
    struct { ULONGLONG v; ULONG base; const WCHAR *want; } c[] = {
        { 0, 10, L"0" }, { 123456789, 10, L"123456789" }, { 255, 16, L"FF" }, { 255, 2, L"11111111" },
        { 8, 8, L"10" }, { 0, 0, L"0" }, { 12345, 0, L"12345" },
        { ~0ULL, 10, L"18446744073709551615" }, { ~0ULL, 16, L"FFFFFFFFFFFFFFFF" },
        { 0x8000000000000000ULL, 10, L"9223372036854775808" }, { 0x123456789ABCDEF0ULL, 16, L"123456789ABCDEF0" },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        for (int k = 0; k < 80; k++) buf[k] = L'#';
        u.Buffer = buf; u.Length = 0; u.MaximumLength = sizeof buf;
        NTSTATUS s = UN(RtlInt64ToUnicodeString)(c[i].v, c[i].base, &u);
        CHECKF(s == 0, "case %u status 0x%lx", i, (unsigned long)s);
        size_t n = lstrlenW(c[i].want);
        CHECKF(u.Length == n * 2, "case %u Length %u", i, u.Length);
        CHECKF(!memcmp(buf, c[i].want, n * 2), "case %u text", i);
        EXPECT_EQ(u.MaximumLength, sizeof buf);
        if (u.Length == n * 2) EXPECT_EQ(buf[n], L'\0');   /* terminator written when room remains */
    }
    /* invalid base: no output change */
    for (int k = 0; k < 80; k++) buf[k] = L'#';
    u.Buffer = buf; u.Length = 0; u.MaximumLength = sizeof buf;
    EXPECT_EQ(UN(RtlInt64ToUnicodeString)(5, 3, &u), ST_INVPARAM);
    EXPECT_EQ(u.Length, 0); EXPECT_EQ(buf[0], L'#');
    EXPECT_EQ(UN(RtlInt64ToUnicodeString)(5, 37, &u), ST_INVPARAM);
    /* buffer too small for the digits */
    for (int k = 0; k < 80; k++) buf[k] = L'#';
    u.Buffer = buf; u.Length = 0; u.MaximumLength = 4;
    EXPECT_EQ(UN(RtlInt64ToUnicodeString)(123456, 10, &u), ST_BUFOVER);
    EXPECT_EQ(buf[0], L'#');
}

/* ---------------- Downcase / Erase / wildcard / file exists ---------------- */
UDECL(NTSTATUS, RtlDowncaseUnicodeString, (PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(VOID, RtlEraseUnicodeString, (PUNICODE_STRING));
UDECL(BOOLEAN, RtlDoesNameContainWildCards, (PUNICODE_STRING));
UDECL(BOOLEAN, RtlDoesFileExists_U, (PCWSTR));

TEST(rtl_rest_b_downcase_unicode_string) {
    REQUIRE(UN(RtlDowncaseUnicodeString)); REQUIRE(U(RtlFreeUnicodeString));
    static const WCHAR src[] = { L'A', L'B', L'c', L' ', L'X', L'Y', L'Z', L'1', 0x00C0, 0x00C9, 0x03A3, 0x0410, 0 };
    static const WCHAR low[] = { L'a', L'b', L'c', L' ', L'x', L'y', L'z', L'1', 0x00E0, 0x00E9, 0x03C3, 0x0430, 0 };
    UNICODE_STRING in, out; WCHAR buf[32];
    in.Buffer = (PWSTR)src; in.Length = 12 * 2; in.MaximumLength = sizeof src;
    for (int i = 0; i < 32; i++) buf[i] = L'#';
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&out, &in, FALSE), 0);
    EXPECT_EQ(out.Length, 24); CHECK(!memcmp(buf, low, 24)); EXPECT_EQ(buf[12], L'#');  /* no terminator added */
    EXPECT_EQ(out.MaximumLength, sizeof buf);
    EXPECT_EQ((ULONG_PTR)out.Buffer, (ULONG_PTR)buf);
    /* in place */
    WCHAR inplace[16]; memcpy(inplace, src, sizeof src);
    UNICODE_STRING ip = { 24, sizeof inplace, inplace };
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&ip, &ip, FALSE), 0);
    CHECK(!memcmp(inplace, low, 24));
    /* destination too small: overflow, destination untouched */
    for (int i = 0; i < 32; i++) buf[i] = L'#';
    out.Buffer = buf; out.Length = 0; out.MaximumLength = 10;
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&out, &in, FALSE), ST_BUFOVER);
    EXPECT_EQ(buf[0], L'#'); EXPECT_EQ(out.Length, 0);
    /* exactly sized */
    out.Length = 0; out.MaximumLength = 24;
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&out, &in, FALSE), 0); EXPECT_EQ(out.Length, 24);
    /* allocating */
    UNICODE_STRING al; memset(&al, 0, sizeof al);
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&al, &in, TRUE), 0);
    CHECK(al.Buffer != NULL);
    if (al.Buffer) {
        EXPECT_EQ(al.Length, 24); CHECK(al.MaximumLength >= 24); CHECK(!memcmp(al.Buffer, low, 24));
        U(RtlFreeUnicodeString)(&al);
    }
    /* empty */
    UNICODE_STRING e = { 0, 0, NULL };
    out.Length = 5; out.MaximumLength = 4; out.Buffer = buf;
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&out, &e, FALSE), 0); EXPECT_EQ(out.Length, 0);
}
TEST(rtl_rest_b_erase_unicode_string) {
    REQUIRE(UN(RtlEraseUnicodeString));
    WCHAR buf[16]; for (int i = 0; i < 16; i++) buf[i] = L'S';
    UNICODE_STRING u = { 8, 24, buf };
    UN(RtlEraseUnicodeString)(&u);
    EXPECT_EQ(u.Length, 0); EXPECT_EQ(u.MaximumLength, 24);
    for (int i = 0; i < 12; i++) EXPECT_EQ(buf[i], 0);     /* whole MaximumLength is wiped, not just Length */
    for (int i = 12; i < 16; i++) EXPECT_EQ(buf[i], L'S');
    /* NULL buffer: nothing happens, Length preserved */
    UNICODE_STRING n = { 6, 8, NULL };
    UN(RtlEraseUnicodeString)(&n); EXPECT_EQ(n.Length, 6);
    /* zero MaximumLength: nothing happens */
    for (int i = 0; i < 4; i++) buf[i] = L'S';
    UNICODE_STRING z = { 4, 0, buf };
    UN(RtlEraseUnicodeString)(&z); EXPECT_EQ(z.Length, 4); EXPECT_EQ(buf[0], L'S');
}
TEST(rtl_rest_b_name_contains_wildcards) {
    REQUIRE(UN(RtlDoesNameContainWildCards)); REQUIRE(U(RtlInitUnicodeString));
    static const struct { const WCHAR *s; BOOLEAN want; } c[] = {
        { L"abc", 0 }, { L"abc.txt", 0 }, { L"*", 1 }, { L"a*", 1 }, { L"*.txt", 1 }, { L"a?c", 1 }, { L"?", 1 },
        { L"a<b", 1 }, { L"a>b", 1 }, { L"a\"b", 1 }, { L"dir\\file", 0 }, { L"dir\\*", 1 }, { L"dir\\f?le", 1 },
        { L"*\\file", 0 },            /* only the final path component is examined */
        { L"?:\\x\\y", 0 }, { L"c:\\dir\\a*b\\file", 0 }, { L"a|b", 0 }, { L"a/b*", 1 }, { L"a%b", 0 },
        { L"x\\", 0 }, { L"*\\", 0 }, { L"", 0 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        UNICODE_STRING u; us_init(&u, c[i].s);
        BOOLEAN r = UN(RtlDoesNameContainWildCards)(&u);
        CHECKF(r == c[i].want, "case %u \"%ls\" got %d want %d", i, c[i].s, r, c[i].want);
    }
    /* Length bounds the scan: a wildcard beyond Length is ignored */
    static const WCHAR t[] = L"abc*";
    UNICODE_STRING u = { 6, 10, (PWSTR)t };
    EXPECT_EQ(UN(RtlDoesNameContainWildCards)(&u), 0);
    u.Length = 8; EXPECT_EQ(UN(RtlDoesNameContainWildCards)(&u), 1);
}
TEST(rtl_rest_b_does_file_exist) {
    REQUIRE(UN(RtlDoesFileExists_U));
    char path[MAX_PATH]; WCHAR wp[MAX_PATH + 16], wd[MAX_PATH + 16];
    t_tmpfile(path, sizeof path, "exists.bin");
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wp), 0);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create scratch file"); return; }
    CloseHandle(h);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wp), 1);
    /* a file that is open without sharing still "exists" (attributes query only) */
    h = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wp), 1);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    /* directory */
    MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, wd, MAX_PATH);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wd), 1);
    /* system file and a missing sibling */
    WCHAR sys[MAX_PATH + 16]; UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n && n < MAX_PATH) {
        WCHAR f[MAX_PATH + 32]; lstrcpyW(f, sys); lstrcatW(f, L"\\ntdll.dll");
        EXPECT_EQ(UN(RtlDoesFileExists_U)(f), 1);
        lstrcpyW(f, sys); lstrcatW(f, L"\\no_such_file_rtl_rest_b.dll");
        EXPECT_EQ(UN(RtlDoesFileExists_U)(f), 0);
        lstrcpyW(f, sys); lstrcatW(f, L"\\no_such_dir_rtl_rest_b\\ntdll.dll");
        EXPECT_EQ(UN(RtlDoesFileExists_U)(f), 0);
    }
    /* wildcards are not expanded */
    lstrcpyW(wd + lstrlenW(wd), L"*");
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wd), 0);
    /* path with a trailing separator after a file does not name an existing file */
    lstrcpyW(wd, wp); lstrcatW(wd, L"\\x");
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wd), 0);
    DeleteFileA(path);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(wp), 0);
}

/* ---------------- Environment expansion ---------------- */
UDECL(NTSTATUS, RtlExpandEnvironmentStrings, (PVOID, PWSTR, SIZE_T, PWSTR, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, RtlCreateEnvironment, (BOOLEAN, PVOID *));
UDECL(NTSTATUS, RtlDestroyEnvironment, (PVOID));
UDECL(NTSTATUS, RtlSetEnvironmentVariable, (PVOID *, PUNICODE_STRING, PUNICODE_STRING));

static NTSTATUS expand(PVOID env, const WCHAR *src, WCHAR *dst, SIZE_T dstcap, SIZE_T *ret) {
    for (SIZE_T i = 0; i < dstcap; i++) dst[i] = L'#';
    return UN(RtlExpandEnvironmentStrings)(env, (PWSTR)src, lstrlenW(src), dst, dstcap, ret);
}
TEST(rtl_rest_b_expand_environment_strings) {
    REQUIRE(UN(RtlExpandEnvironmentStrings)); REQUIRE(UN(RtlCreateEnvironment)); REQUIRE(UN(RtlDestroyEnvironment));
    REQUIRE(UN(RtlSetEnvironmentVariable)); REQUIRE(U(RtlInitUnicodeString));
    PVOID env = NULL;
    if (UN(RtlCreateEnvironment)(FALSE, &env) < 0 || !env) { t_skip("cannot create an environment block"); return; }
    UNICODE_STRING n1, v1, n2, v2, n3, v3;
    us_init(&n1, L"RTLB_ONE"); us_init(&v1, L"first");
    us_init(&n2, L"RTLB_TWO"); us_init(&v2, L"2");
    us_init(&n3, L"rtlb_mixed"); us_init(&v3, L"Value With Spaces");
    EXPECT_EQ(UN(RtlSetEnvironmentVariable)(&env, &n1, &v1), 0);
    EXPECT_EQ(UN(RtlSetEnvironmentVariable)(&env, &n2, &v2), 0);
    EXPECT_EQ(UN(RtlSetEnvironmentVariable)(&env, &n3, &v3), 0);
    WCHAR d[128]; SIZE_T rl;
    rl = 0; EXPECT_EQ(expand(env, L"[%RTLB_ONE%]", d, 128, &rl), 0);
    EXPECT_WSTR(d, L"[first]"); EXPECT_EQ(rl, 8);                       /* includes the terminator */
    rl = 0; EXPECT_EQ(expand(env, L"%RTLB_ONE%%RTLB_TWO%-%RTLB_ONE%", d, 128, &rl), 0);
    EXPECT_WSTR(d, L"first2-first"); EXPECT_EQ(rl, 13);
    rl = 0; EXPECT_EQ(expand(env, L"%RTLB_MIXED%", d, 128, &rl), 0);      /* names are case-insensitive */
    EXPECT_WSTR(d, L"Value With Spaces"); EXPECT_EQ(rl, 18);
    rl = 0; EXPECT_EQ(expand(env, L"%rtlb_one%", d, 128, &rl), 0); EXPECT_WSTR(d, L"first");
    rl = 0; EXPECT_EQ(expand(env, L"no variables", d, 128, &rl), 0); EXPECT_WSTR(d, L"no variables"); EXPECT_EQ(rl, 13);
    rl = 0; EXPECT_EQ(expand(env, L"%RTLB_UNDEFINED%x", d, 128, &rl), 0);  /* unknown names are left untouched */
    EXPECT_WSTR(d, L"%RTLB_UNDEFINED%x"); EXPECT_EQ(rl, 18);
    rl = 0; EXPECT_EQ(expand(env, L"50% off", d, 128, &rl), 0); EXPECT_WSTR(d, L"50% off");
    rl = 0; EXPECT_EQ(expand(env, L"%RTLB_ONE", d, 128, &rl), 0); EXPECT_WSTR(d, L"%RTLB_ONE");
    rl = 0; EXPECT_EQ(expand(env, L"%%", d, 128, &rl), 0); EXPECT_WSTR(d, L"%%");
    rl = 0; EXPECT_EQ(expand(env, L"", d, 128, &rl), 0); EXPECT_WSTR(d, L""); EXPECT_EQ(rl, 1);
    /* source length controls how much is read */
    for (int i = 0; i < 128; i++) d[i] = L'#';
    EXPECT_EQ(UN(RtlExpandEnvironmentStrings)(env, (PWSTR)L"%RTLB_ONE%tail", 10, d, 128, &rl), 0);
    EXPECT_WSTR(d, L"first"); EXPECT_EQ(rl, 6);
    /* too-small destination: required size is still reported */
    rl = 0; EXPECT_EQ(expand(env, L"[%RTLB_ONE%]", d, 4, &rl), ST_BUFSMALL); EXPECT_EQ(rl, 8);
    rl = 0; EXPECT_EQ(expand(env, L"[%RTLB_ONE%]", d, 7, &rl), ST_BUFSMALL); EXPECT_EQ(rl, 8);
    rl = 0; EXPECT_EQ(expand(env, L"[%RTLB_ONE%]", d, 8, &rl), 0); EXPECT_WSTR(d, L"[first]");
    rl = 0; EXPECT_EQ(expand(env, L"abc", d, 3, &rl), ST_BUFSMALL); EXPECT_EQ(rl, 4);
    /* return length is optional */
    EXPECT_EQ(expand(env, L"%RTLB_TWO%", d, 128, NULL), 0); EXPECT_WSTR(d, L"2");
    UN(RtlDestroyEnvironment)(env);
    /* NULL environment means the current process environment */
    SetEnvironmentVariableW(L"RTLB_PROC_VAR", L"from-process");
    rl = 0; EXPECT_EQ(expand(NULL, L"<%RTLB_PROC_VAR%>", d, 128, &rl), 0);
    EXPECT_WSTR(d, L"<from-process>"); EXPECT_EQ(rl, 15);
    SetEnvironmentVariableW(L"RTLB_PROC_VAR", NULL);
    rl = 0; EXPECT_EQ(expand(NULL, L"<%RTLB_PROC_VAR%>", d, 128, &rl), 0);
    EXPECT_WSTR(d, L"<%RTLB_PROC_VAR%>");
}

/* ---------------- IDN ---------------- */
UDECL(NTSTATUS, RtlIdnToAscii, (ULONG, PCWSTR, LONG, PWSTR, PLONG));
UDECL(NTSTATUS, RtlIdnToUnicode, (ULONG, PCWSTR, LONG, PWSTR, PLONG));
UDECL(NTSTATUS, RtlIdnToNameprepUnicode, (ULONG, PCWSTR, LONG, PWSTR, PLONG));

TEST(rtl_rest_b_idn_to_ascii) {
    REQUIRE(UN(RtlIdnToAscii));
    WCHAR d[256]; LONG n;
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, L"example.com", -1, d, &n), 0);
    EXPECT_WSTR(d, L"example.com"); EXPECT_EQ(n, 12);
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, L"example.com", 11, d, &n), 0);
    EXPECT_EQ(n, 11); CHECK(!memcmp(d, L"example.com", 22));
    static const WCHAR bu[] = { 'b', 0x00FC, 'c', 'h', 'e', 'r', '.', 'd', 'e', 0 };
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, bu, -1, d, &n), 0);
    EXPECT_WSTR(d, L"xn--bcher-kva.de"); EXPECT_EQ(n, 17);
    static const WCHAR up[] = { 'B', 0x00DC, 'C', 'H', 'E', 'R', 0 };           /* nameprep case-folds */
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, up, -1, d, &n), 0);
    EXPECT_WSTR(d, L"xn--bcher-kva"); EXPECT_EQ(n, 14);
    /* query the required size */
    n = 0; EXPECT_EQ(UN(RtlIdnToAscii)(0, bu, -1, NULL, &n), 0); EXPECT_EQ(n, 17);
    /* destination too small */
    n = 5; EXPECT_EQ(UN(RtlIdnToAscii)(0, bu, -1, d, &n), ST_BUFSMALL);
    /* argument validation */
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, NULL, -1, d, &n), ST_INVPARAM);
    EXPECT_EQ(UN(RtlIdnToAscii)(0, L"a", -1, d, NULL), ST_INVPARAM);
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0x10, L"a", -1, d, &n), ST_INVPARAM);   /* undefined flag bits */
    n = 256; EXPECT_EQ(UN(RtlIdnToAscii)(0, L"a", -2, d, &n), ST_INVPARAM);
    n = -1;  EXPECT_EQ(UN(RtlIdnToAscii)(0, L"a", -1, d, &n), ST_INVPARAM);
}
TEST(rtl_rest_b_idn_to_unicode) {
    REQUIRE(UN(RtlIdnToUnicode));
    WCHAR d[256]; LONG n;
    static const WCHAR bu[] = { 'b', 0x00FC, 'c', 'h', 'e', 'r', '.', 'd', 'e', 0 };
    n = 256; EXPECT_EQ(UN(RtlIdnToUnicode)(0, L"xn--bcher-kva.de", -1, d, &n), 0);
    EXPECT_WSTR(d, bu); EXPECT_EQ(n, 10);
    n = 256; EXPECT_EQ(UN(RtlIdnToUnicode)(0, L"plain.example", -1, d, &n), 0);
    EXPECT_WSTR(d, L"plain.example"); EXPECT_EQ(n, 14);
    n = 256; EXPECT_EQ(UN(RtlIdnToUnicode)(0, L"xn--bcher-kva", 13, d, &n), 0);
    EXPECT_EQ(n, 6); CHECK(d[1] == 0x00FC);
    n = 4; EXPECT_EQ(UN(RtlIdnToUnicode)(0, L"xn--bcher-kva.de", -1, d, &n), ST_BUFSMALL);
    n = 256; EXPECT_EQ(UN(RtlIdnToUnicode)(0, NULL, -1, d, &n), ST_INVPARAM);
    EXPECT_EQ(UN(RtlIdnToUnicode)(0, L"a", -1, d, NULL), ST_INVPARAM);
    n = 256; EXPECT_EQ(UN(RtlIdnToUnicode)(0x10, L"a", -1, d, &n), ST_INVPARAM);
}
TEST(rtl_rest_b_idn_to_nameprep_unicode) {
    REQUIRE(UN(RtlIdnToNameprepUnicode));
    WCHAR d[256]; LONG n;
    static const WCHAR up[] = { 'B', 0x00DC, 'C', 'H', 'E', 'R', '.', 'D', 'E', 0 };
    static const WCHAR lo[] = { 'b', 0x00FC, 'c', 'h', 'e', 'r', '.', 'd', 'e', 0 };
    n = 256; EXPECT_EQ(UN(RtlIdnToNameprepUnicode)(0, up, -1, d, &n), 0);
    EXPECT_WSTR(d, lo); EXPECT_EQ(n, 10);                    /* case-folded, still Unicode */
    n = 256; EXPECT_EQ(UN(RtlIdnToNameprepUnicode)(0, L"Example.COM", -1, d, &n), 0);
    EXPECT_WSTR(d, L"Example.COM"); EXPECT_EQ(n, 12);        /* observed: ASCII letters are not case-folded */
    n = 256; EXPECT_EQ(UN(RtlIdnToNameprepUnicode)(0, NULL, -1, d, &n), ST_INVPARAM);
    n = 3; EXPECT_EQ(UN(RtlIdnToNameprepUnicode)(0, up, -1, d, &n), ST_BUFSMALL);
}

/* ---------------- DNS host name to computer name ---------------- */
UDECL(NTSTATUS, RtlDnsHostNameToComputerName, (PUNICODE_STRING, PUNICODE_STRING, BOOLEAN));
TEST(rtl_rest_b_dns_host_to_computer_name) {
    REQUIRE(UN(RtlDnsHostNameToComputerName)); REQUIRE(U(RtlFreeUnicodeString));
    UNICODE_STRING host, out; WCHAR buf[40];
    us_init(&host, L"my-host.sub.example.com");
    memset(&out, 0, sizeof out);
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), 0);
    CHECK(out.Buffer != NULL);
    if (out.Buffer) { EXPECT_EQ(out.Length, 14); CHECK(!memcmp(out.Buffer, L"MY-HOST", 14)); U(RtlFreeUnicodeString)(&out); }
    us_init(&host, L"plainname");                           /* no dot: the whole name */
    memset(&out, 0, sizeof out);
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), 0);
    if (out.Buffer) { EXPECT_EQ(out.Length, 18); CHECK(!memcmp(out.Buffer, L"PLAINNAME", 18)); U(RtlFreeUnicodeString)(&out); }
    /* caller-supplied buffer */
    us_init(&host, L"abc.def");
    for (int i = 0; i < 40; i++) buf[i] = L'#';
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, FALSE), 0);
    EXPECT_EQ(out.Length, 6); CHECK(!memcmp(buf, L"ABC", 6)); EXPECT_EQ((ULONG_PTR)out.Buffer, (ULONG_PTR)buf);
    /* 15 characters is the NetBIOS maximum; 16 is rejected */
    us_init(&host, L"abcdefghijklmno.example");
    memset(&out, 0, sizeof out);
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), 0);
    if (out.Buffer) { EXPECT_EQ(out.Length, 30); U(RtlFreeUnicodeString)(&out); }
    us_init(&host, L"abcdefghijklmnop.example");            /* 16 characters: truncated to the NetBIOS limit */
    memset(&out, 0, sizeof out);
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), 0);
    if (out.Buffer) { EXPECT_EQ(out.Length, 30); CHECK(!memcmp(out.Buffer, L"ABCDEFGHIJKLMNO", 30)); U(RtlFreeUnicodeString)(&out); }
    /* empty first label / empty string */
    us_init(&host, L".example");
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), (NTSTATUS)0xC0000122);
    us_init(&host, L"");
    EXPECT_EQ(UN(RtlDnsHostNameToComputerName)(&out, &host, TRUE), (NTSTATUS)0xC0000122);
}

/* ---------------- FormatMessage ---------------- */
UDECL(NTSTATUS, RtlFormatMessage, (PWSTR, ULONG, BOOLEAN, BOOLEAN, BOOLEAN, va_list *, PWSTR, ULONG, PULONG));
UDECL(NTSTATUS, RtlFormatMessageEx, (PWSTR, ULONG, BOOLEAN, BOOLEAN, BOOLEAN, va_list *, PWSTR, ULONG, PULONG, PVOID));

static NTSTATUS fmt_arr(const WCHAR *f, BOOLEAN ignore, ULONG_PTR *args, WCHAR *out, ULONG bytes, ULONG *ret, ULONG width) {
    for (ULONG i = 0; i < bytes / 2; i++) out[i] = L'#';
    return UN(RtlFormatMessage)((PWSTR)f, width, ignore, FALSE, TRUE, (va_list *)args, out, bytes, ret);
}
TEST(rtl_rest_b_format_message_inserts) {
    REQUIRE(UN(RtlFormatMessage));
    WCHAR o[128]; ULONG rl; ULONG_PTR a[4];
    a[0] = (ULONG_PTR)L"AA"; a[1] = (ULONG_PTR)L"B";
    rl = 0; EXPECT_EQ(fmt_arr(L"Hi %1 and %2.", FALSE, a, o, sizeof o, &rl, 0), 0);
    EXPECT_WSTR(o, L"Hi AA and B."); EXPECT_EQ(rl, 26);             /* bytes, including the terminator */
    a[0] = 42; a[1] = 255; a[2] = 7;
    rl = 0; EXPECT_EQ(fmt_arr(L"%1!d!|%2!x!|%3!04d!|%2!X!|%1!5d!", FALSE, a, o, sizeof o, &rl, 0), 0);
    EXPECT_WSTR(o, L"42|ff|0007|FF|   42");
    a[0] = (ULONG_PTR)L"s1"; a[1] = (ULONG_PTR)L"s2";
    rl = 0; EXPECT_EQ(fmt_arr(L"%2%1%2", FALSE, a, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"s2s1s2");
    rl = 0; EXPECT_EQ(fmt_arr(L"%1!s!", FALSE, a, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"s1");
    /* ignore inserts: %n sequences are passed through unexpanded */
    rl = 0; EXPECT_EQ(fmt_arr(L"x %1 y", TRUE, a, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"x %1 y");
    /* no argument pointer needed when nothing is inserted */
    rl = 0; EXPECT_EQ(UN(RtlFormatMessage)((PWSTR)L"plain", 0, FALSE, FALSE, TRUE, NULL, o, sizeof o, &rl), 0);
    EXPECT_WSTR(o, L"plain"); EXPECT_EQ(rl, 12);
    /* ReturnLength is optional */
    EXPECT_EQ(UN(RtlFormatMessage)((PWSTR)L"plain", 0, FALSE, FALSE, TRUE, NULL, o, sizeof o, NULL), 0);
    /* Ex with a NULL context is the same operation */
    if (UN(RtlFormatMessageEx)) {
        a[0] = (ULONG_PTR)L"E";
        for (int i = 0; i < 128; i++) { o[i] = L'#'; }
        rl = 0;
        EXPECT_EQ(UN(RtlFormatMessageEx)((PWSTR)L"<%1>", 0, FALSE, FALSE, TRUE, (va_list *)a, o, sizeof o, &rl, NULL), 0);
        EXPECT_WSTR(o, L"<E>"); EXPECT_EQ(rl, 8);
    }
}
TEST(rtl_rest_b_format_message_escapes) {
    REQUIRE(UN(RtlFormatMessage));
    WCHAR o[128]; ULONG rl = 0;
    EXPECT_EQ(fmt_arr(L"100%%", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"100%");
    EXPECT_EQ(fmt_arr(L"a%nb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a\r\nb");
    EXPECT_EQ(fmt_arr(L"a%rb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a\rb");
    EXPECT_EQ(fmt_arr(L"a%tb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a\tb");
    EXPECT_EQ(fmt_arr(L"a%bb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a b");
    EXPECT_EQ(fmt_arr(L"a%.b", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a.b");
    EXPECT_EQ(fmt_arr(L"a%!b", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a!b");
    EXPECT_EQ(fmt_arr(L"abc%0def", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"abc");   /* %0 ends the message */
    /* line breaks in the source: kept as CRLF without a width, folded to a space when a width is given */
    EXPECT_EQ(fmt_arr(L"a\nb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a\r\nb");
    EXPECT_EQ(fmt_arr(L"a\r\nb", FALSE, NULL, o, sizeof o, &rl, 0), 0); EXPECT_WSTR(o, L"a\r\nb");
    EXPECT_EQ(fmt_arr(L"a\nb", FALSE, NULL, o, sizeof o, &rl, 0xFF), 0); EXPECT_WSTR(o, L"a b");
    /* a lone trailing percent is malformed */
    EXPECT_EQ(fmt_arr(L"abc%", FALSE, NULL, o, sizeof o, &rl, 0), ST_INVPARAM);
    /* output too small */
    EXPECT_EQ(fmt_arr(L"abcdef", FALSE, NULL, o, 6, &rl, 0), ST_BUFOVER);
    EXPECT_EQ(fmt_arr(L"abcdef", FALSE, NULL, o, 14, &rl, 0), 0); EXPECT_WSTR(o, L"abcdef");
    EXPECT_EQ(fmt_arr(L"abcdef", FALSE, NULL, o, 12, &rl, 0), ST_BUFOVER);
}

/* ---------------- Correlation vector ---------------- */
typedef struct { CHAR Version; CHAR Vector[128]; } TCV;
UDECL(NTSTATUS, RtlIncrementCorrelationVector, (TCV *));
static void cv_set(TCV *cv, int ver, const char *s) { memset(cv, 0, sizeof *cv); cv->Version = (CHAR)ver; strcpy(cv->Vector, s); }
TEST(rtl_rest_b_correlation_vector_increment) {
    REQUIRE(UN(RtlIncrementCorrelationVector));
    TCV cv;
    cv_set(&cv, 1, "ABCDEFGHIJKLMNOP.0");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.1");
    EXPECT_EQ(cv.Version, 1);
    for (int i = 0; i < 8; i++) UN(RtlIncrementCorrelationVector)(&cv);
    EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.9");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.10");
    cv_set(&cv, 1, "ABCDEFGHIJKLMNOP.99");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.100");
    /* only the last component is incremented */
    cv_set(&cv, 2, "ABCDEFGHIJKLMNOPQRSTUV.3.7.12");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOPQRSTUV.3.7.13");
    cv_set(&cv, 2, "ABCDEFGHIJKLMNOPQRSTUV.0");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOPQRSTUV.1");
    /* length limit: 63 characters for version 1, 127 for version 2; a failed increment leaves the vector alone */
    char big[160], before[160];
    memset(big, 'A', 60); strcpy(big + 60, ".9");              /* 62 characters, grows to 63 */
    cv_set(&cv, 1, big);
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_EQ(strlen(cv.Vector), 63); EXPECT_STR(cv.Vector + 60, ".10");
    memset(big, 'A', 61); strcpy(big + 61, ".9");              /* 63 characters, ".10" would make 64 */
    cv_set(&cv, 1, big); strcpy(before, cv.Vector);
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), ST_BUFOVER); EXPECT_STR(cv.Vector, before);
    memset(big, 'A', 61); strcpy(big + 61, ".5");              /* same length but no digit is added */
    cv_set(&cv, 1, big);
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_STR(cv.Vector + 61, ".6");
    memset(big, 'A', 124); strcpy(big + 124, ".9");            /* 126 characters, grows to 127 */
    cv_set(&cv, 2, big);
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), 0); EXPECT_EQ(strlen(cv.Vector), 127);
    memset(big, 'A', 125); strcpy(big + 125, ".9");            /* 127 characters */
    cv_set(&cv, 2, big); strcpy(before, cv.Vector);
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), ST_BUFOVER); EXPECT_STR(cv.Vector, before);
    /* a version that has no defined buffer length is rejected without modification */
    cv_set(&cv, 0, "ABCDEFGHIJKLMNOP.5");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), ST_BUFOVER); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.5");
    cv_set(&cv, 3, "ABCDEFGHIJKLMNOP.5");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), ST_BUFOVER); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP.5");
    /* no component separator */
    cv_set(&cv, 1, "ABCDEFGHIJKLMNOP");
    EXPECT_EQ(UN(RtlIncrementCorrelationVector)(&cv), ST_BUFOVER); EXPECT_STR(cv.Vector, "ABCDEFGHIJKLMNOP");
}

/* ---------------- Capability SIDs ---------------- */
UDECL(NTSTATUS, RtlDeriveCapabilitySidsFromName, (PUNICODE_STRING, PSID, PSID));

typedef struct { ULONG h[8]; ULONGLONG len; UCHAR buf[64]; ULONG used; } SHA256C;
static const ULONG K256[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(SHA256C *c, const UCHAR *p) {
    ULONG w[64], a, b, cc, d, e, f, g, h;
    for (int i = 0; i < 16; i++) w[i] = (ULONG)p[4*i] << 24 | (ULONG)p[4*i+1] << 16 | (ULONG)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        ULONG s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3), s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (int i = 0; i < 64; i++) {
        ULONG t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        ULONG t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}
static void sha256(const UCHAR *m, size_t n, UCHAR out[32]) {
    SHA256C c = { { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 } };
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha_block(&c, m + i);
    UCHAR t[128]; size_t r = n - i; memcpy(t, m + i, r); t[r++] = 0x80;
    size_t tot = (r + 8 <= 64) ? 64 : 128; memset(t + r, 0, tot - r);
    ULONGLONG bits = (ULONGLONG)n * 8; for (int k = 0; k < 8; k++) t[tot - 1 - k] = (UCHAR)(bits >> (8 * k));
    for (size_t o = 0; o < tot; o += 64) sha_block(&c, t + o);
    for (int k = 0; k < 8; k++) { out[4*k] = c.h[k] >> 24; out[4*k+1] = c.h[k] >> 16; out[4*k+2] = c.h[k] >> 8; out[4*k+3] = (UCHAR)c.h[k]; }
}
static void sid_subs(PSID s, UCHAR *cnt, ULONG *sub, SID_IDENTIFIER_AUTHORITY *ia) {
    SID *x = (SID *)s; *cnt = x->SubAuthorityCount; *ia = x->IdentifierAuthority;
    for (int i = 0; i < x->SubAuthorityCount; i++) sub[i] = x->SubAuthority[i];
}
TEST(rtl_rest_b_derive_capability_sids) {
    REQUIRE(UN(RtlDeriveCapabilitySidsFromName));
    UCHAR gbuf[SECURITY_MAX_SID_SIZE + 16], cbuf[SECURITY_MAX_SID_SIZE + 16];
    UNICODE_STRING nm; ULONG sub[16]; UCHAR cnt; SID_IDENTIFIER_AUTHORITY ia;
    /* custom capability: hash of the upper-cased UTF-16LE name */
    us_init(&nm, L"myCustomCapability");
    memset(gbuf, 0xCC, sizeof gbuf); memset(cbuf, 0xCC, sizeof cbuf);
    EXPECT_EQ(UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)gbuf, (PSID)cbuf), 0);
    UCHAR dig[32]; const WCHAR *up = L"MYCUSTOMCAPABILITY";
    sha256((const UCHAR *)up, lstrlenW(up) * 2, dig);
    ULONG hw[8]; memcpy(hw, dig, 32);
    sid_subs(gbuf, &cnt, sub, &ia);
    EXPECT_EQ(((SID *)gbuf)->Revision, 1); EXPECT_EQ(cnt, 9);
    CHECK(ia.Value[5] == 5 && !ia.Value[0] && !ia.Value[4]);                 /* NT authority */
    EXPECT_EQ(sub[0], 32); CHECK(!memcmp(sub + 1, hw, 32));                   /* S-1-5-32-<8 hash words> */
    sid_subs(cbuf, &cnt, sub, &ia);
    EXPECT_EQ(((SID *)cbuf)->Revision, 1); EXPECT_EQ(cnt, 10);
    CHECK(ia.Value[5] == 15 && !ia.Value[0] && !ia.Value[4]);                /* app-package authority */
    EXPECT_EQ(sub[0], 3); EXPECT_EQ(sub[1], 1024); CHECK(!memcmp(sub + 2, hw, 32));   /* S-1-15-3-1024-<8 hash words> */
    /* case-insensitive: another spelling gives identical SIDs */
    UCHAR g2[SECURITY_MAX_SID_SIZE + 16], c2[SECURITY_MAX_SID_SIZE + 16];
    us_init(&nm, L"MYCUSTOMcapability");
    EXPECT_EQ(UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)g2, (PSID)c2), 0);
    CHECK(!memcmp(g2, gbuf, 8 + 4 * 9)); CHECK(!memcmp(c2, cbuf, 8 + 4 * 10));
    /* a different name gives different SIDs */
    us_init(&nm, L"myCustomCapability2");
    EXPECT_EQ(UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)g2, (PSID)c2), 0);
    CHECK(memcmp(c2, cbuf, 8 + 4 * 10) != 0);
    /* legacy named capabilities map to well-known S-1-15-3-<n>, the group SID is still hashed */
    static const struct { const WCHAR *n; ULONG rid; } leg[] = {
        { L"internetClient", 1 }, { L"internetClientServer", 2 }, { L"privateNetworkClientServer", 3 },
        { L"picturesLibrary", 4 }, { L"videosLibrary", 5 }, { L"musicLibrary", 6 }, { L"documentsLibrary", 7 },
        { L"enterpriseAuthentication", 8 }, { L"sharedUserCertificates", 9 }, { L"removableStorage", 10 },
        { L"appointments", 11 }, { L"contacts", 12 } };
    for (unsigned i = 0; i < sizeof leg / sizeof *leg; i++) {
        us_init(&nm, leg[i].n);
        memset(cbuf, 0xCC, sizeof cbuf);
        NTSTATUS s = UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)gbuf, (PSID)cbuf);
        CHECKF(s == 0, "%ls status 0x%lx", leg[i].n, (unsigned long)s);
        sid_subs(cbuf, &cnt, sub, &ia);
        CHECKF(cnt == 2 && sub[0] == 3 && sub[1] == leg[i].rid, "%ls -> count %d sub %lu %lu", leg[i].n, cnt, (unsigned long)sub[0], (unsigned long)sub[1]);
        EXPECT_EQ(((SID *)gbuf)->SubAuthorityCount, 9);
    }
    us_init(&nm, L"INTERNETCLIENT");
    EXPECT_EQ(UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)gbuf, (PSID)cbuf), 0);
    sid_subs(cbuf, &cnt, sub, &ia); EXPECT_EQ(cnt, 2); EXPECT_EQ(sub[1], 1);
    us_init(&nm, L"internetClient2");                       /* not a legacy name */
    EXPECT_EQ(UN(RtlDeriveCapabilitySidsFromName)(&nm, (PSID)gbuf, (PSID)cbuf), 0);
    sid_subs(cbuf, &cnt, sub, &ia); EXPECT_EQ(cnt, 10);
}
