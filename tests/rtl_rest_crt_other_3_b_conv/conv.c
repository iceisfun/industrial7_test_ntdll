/* CRT-style ntdll exports: unsigned integer to string, string to integer, narrow/wide multibyte
 * conversion. Only well-defined inputs are used; the bounded "_s" functions are not driven into
 * their invalid-parameter path. See EVIDENCE.md. */
#include "t.h"

typedef long long i64;
typedef unsigned long long u64;

UDECL(char *, _ultoa, (unsigned long, char *, int));
UDECL(int, _ultoa_s, (unsigned long, char *, size_t, int));
UDECL(WCHAR *, _ultow, (unsigned long, WCHAR *, int));
UDECL(int, _ultow_s, (unsigned long, WCHAR *, size_t, int));
UDECL(i64, _wcstoi64, (const WCHAR *, WCHAR **, int));
UDECL(u64, _wcstoui64, (const WCHAR *, WCHAR **, int));
UDECL(int, _wtoi, (const WCHAR *));
UDECL(long, _wtol, (const WCHAR *));
UDECL(i64, _wtoi64, (const WCHAR *));
UDECL(long, wcstol, (const WCHAR *, WCHAR **, int));
UDECL(unsigned long, wcstoul, (const WCHAR *, WCHAR **, int));
UDECL(int, atoi, (const char *));
UDECL(long, atol, (const char *));
UDECL(long, strtol, (const char *, char **, int));
UDECL(unsigned long, strtoul, (const char *, char **, int));
UDECL(size_t, mbstowcs, (WCHAR *, const char *, size_t));
UDECL(size_t, wcstombs, (char *, const WCHAR *, size_t));
UDECL(int *, _errno, (void));

static void w2n(const WCHAR *w, char *out, size_t cap) {
    size_t i = 0;
    for (; w[i] && i + 1 < cap; i++) out[i] = (char)w[i];
    out[i] = 0;
}
static const WCHAR *W(const char *s) {
    static WCHAR buf[8][128]; static int k;
    WCHAR *b = buf[k++ & 7]; size_t i = 0;
    for (; s[i]; i++) b[i] = (unsigned char)s[i];
    b[i] = 0; return b;
}

TEST(ultoa) {
    REQUIRE(UN(_ultoa)); REQUIRE(UN(_ultoa_s));
    char b[80];
    static const struct { unsigned long v; int r; const char *s; } c[] = {
        { 0, 10, "0" }, { 9, 10, "9" }, { 4294967295u, 10, "4294967295" }, { 4294967295u, 16, "ffffffff" },
        { 255, 2, "11111111" }, { 255, 8, "377" }, { 35, 36, "z" }, { 36, 36, "10" }, { 0x80000000u, 10, "2147483648" },
        { 4294967295u, 2, "11111111111111111111111111111111" }, { 1295, 36, "zz" },
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        memset(b, 0x5a, sizeof b);
        EXPECT_EQ(UN(_ultoa)(c[i].v, b, c[i].r), b);
        EXPECT_STR(b, c[i].s);
        memset(b, 0x5a, sizeof b);
        EXPECT_EQ(UN(_ultoa_s)(c[i].v, b, sizeof b, c[i].r), 0);
        EXPECT_STR(b, c[i].s);
    }
    /* buffer of exactly strlen+1 */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_ultoa_s)(4294967295u, b, 11, 10), 0); EXPECT_STR(b, "4294967295"); EXPECT_EQ(b[11], 0x5a);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_ultoa_s)(0, b, 2, 10), 0); EXPECT_STR(b, "0");
    /* _ultoa does not write past the terminator */
    memset(b, 0x5a, sizeof b); UN(_ultoa)(42, b + 1, 10);
    EXPECT_EQ(b[0], 0x5a); EXPECT_EQ(b[3], 0); EXPECT_EQ(b[4], 0x5a);
}

TEST(ultow) {
    REQUIRE(UN(_ultow)); REQUIRE(UN(_ultow_s));
    WCHAR w[80]; char n[80];
    EXPECT_EQ(UN(_ultow)(4294967295u, w, 10), w); w2n(w, n, sizeof n); EXPECT_STR(n, "4294967295");
    UN(_ultow)(4294967295u, w, 16); w2n(w, n, sizeof n); EXPECT_STR(n, "ffffffff");
    UN(_ultow)(0, w, 10); EXPECT_EQ(w[0], '0'); EXPECT_EQ(w[1], 0);
    UN(_ultow)(35, w, 36); w2n(w, n, sizeof n); EXPECT_STR(n, "z");
    UN(_ultow)(5, w, 2); w2n(w, n, sizeof n); EXPECT_STR(n, "101");
    for (int i = 0; i < 80; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_ultow_s)(123456, w, 80, 10), 0); w2n(w, n, sizeof n); EXPECT_STR(n, "123456");
    for (int i = 0; i < 80; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_ultow_s)(123456, w, 7, 10), 0); w2n(w, n, sizeof n); EXPECT_STR(n, "123456"); EXPECT_EQ(w[7], 0x5a5a);
    EXPECT_EQ(UN(_ultow_s)(4294967295u, w, 80, 16), 0); w2n(w, n, sizeof n); EXPECT_STR(n, "ffffffff");
    EXPECT_EQ(UN(_ultow_s)(0, w, 2, 10), 0); EXPECT_EQ(w[0], '0'); EXPECT_EQ(w[1], 0);
}

TEST(wcstoi64) {
    REQUIRE(UN(_wcstoi64)); REQUIRE(UN(_wcstoui64));
    WCHAR *e; const WCHAR *s;
    EXPECT_EQ(UN(_wcstoi64)(W("12345"), &e, 10), 12345);
    s = W("12345"); UN(_wcstoi64)(s, &e, 10); EXPECT_EQ(e, s + 5);
    EXPECT_EQ(UN(_wcstoi64)(W("  -42xyz"), &e, 10), -42);
    s = W("  -42xyz"); UN(_wcstoi64)(s, &e, 10); EXPECT_EQ(e, s + 5);
    EXPECT_EQ(UN(_wcstoi64)(W("+7"), NULL, 10), 7);
    EXPECT_EQ(UN(_wcstoi64)(W("ff"), NULL, 16), 255);
    EXPECT_EQ(UN(_wcstoi64)(W("0xFF"), NULL, 16), 255);
    EXPECT_EQ(UN(_wcstoi64)(W("0xFF"), NULL, 0), 255);
    EXPECT_EQ(UN(_wcstoi64)(W("077"), NULL, 0), 63);
    EXPECT_EQ(UN(_wcstoi64)(W("99"), NULL, 0), 99);
    EXPECT_EQ(UN(_wcstoi64)(W("101"), NULL, 2), 5);
    EXPECT_EQ(UN(_wcstoi64)(W("zz"), NULL, 36), 1295);
    EXPECT_EQ(UN(_wcstoi64)(W("9223372036854775807"), NULL, 10), 9223372036854775807LL);
    EXPECT_EQ(UN(_wcstoi64)(W("-9223372036854775808"), NULL, 10), (u64)(-9223372036854775807LL - 1));
    EXPECT_EQ(UN(_wcstoi64)(W("99999999999999999999"), NULL, 10), 9223372036854775807LL);   /* clamped */
    EXPECT_EQ(UN(_wcstoi64)(W("-99999999999999999999"), NULL, 10), (u64)(-9223372036854775807LL - 1));
    s = W("abc"); EXPECT_EQ(UN(_wcstoi64)(s, &e, 10), 0); EXPECT_EQ(e, s);   /* no digits: endptr = start */
    s = W(""); EXPECT_EQ(UN(_wcstoi64)(s, &e, 10), 0); EXPECT_EQ(e, s);

    EXPECT_EQ(UN(_wcstoui64)(W("18446744073709551615"), NULL, 10), ~0ULL);
    EXPECT_EQ(UN(_wcstoui64)(W("18446744073709551616"), NULL, 10), ~0ULL);     /* clamped */
    EXPECT_EQ(UN(_wcstoui64)(W("ffffffffffffffff"), NULL, 16), ~0ULL);
    EXPECT_EQ(UN(_wcstoui64)(W("-1"), NULL, 10), ~0ULL);                       /* negated like the C library */
    EXPECT_EQ(UN(_wcstoui64)(W("123 456"), &e, 10), 123);
    s = W("123 456"); UN(_wcstoui64)(s, &e, 10); EXPECT_EQ(e, s + 3);
    s = W("xyz"); EXPECT_EQ(UN(_wcstoui64)(s, &e, 10), 0); EXPECT_EQ(e, s);
}

TEST(wtoi_family) {
    REQUIRE(UN(_wtoi)); REQUIRE(UN(_wtol)); REQUIRE(UN(_wtoi64));
    EXPECT_EQ(UN(_wtoi)(W("0")), 0);
    EXPECT_EQ(UN(_wtoi)(W("123")), 123);
    EXPECT_EQ(UN(_wtoi)(W("-45")), -45);
    EXPECT_EQ(UN(_wtoi)(W("  \t+7")), 7);
    EXPECT_EQ(UN(_wtoi)(W("12abc")), 12);
    EXPECT_EQ(UN(_wtoi)(W("abc")), 0);
    EXPECT_EQ(UN(_wtoi)(W("")), 0);
    EXPECT_EQ(UN(_wtoi)(W("2147483647")), 2147483647);
    EXPECT_EQ(UN(_wtoi)(W("-2147483648")), (ULONG_PTR)(long long)-2147483647 - 1);
    EXPECT_EQ(UN(_wtol)(W("  -99x")), (ULONG_PTR)(long long)-99);
    EXPECT_EQ(UN(_wtol)(W("31337")), 31337);
    EXPECT_EQ(UN(_wtol)(W("")), 0);
    EXPECT_EQ(UN(_wtoi64)(W("9223372036854775807")), 9223372036854775807LL);
    EXPECT_EQ(UN(_wtoi64)(W("-9223372036854775808")), (u64)(-9223372036854775807LL - 1));
    EXPECT_EQ(UN(_wtoi64)(W("4294967296")), 4294967296LL);
    EXPECT_EQ(UN(_wtoi64)(W(" -5")), (u64)-5LL);
    EXPECT_EQ(UN(_wtoi64)(W("x")), 0);
}

TEST(wcstol_wcstoul) {
    REQUIRE(UN(wcstol)); REQUIRE(UN(wcstoul));
    WCHAR *e; const WCHAR *s;
    EXPECT_EQ(UN(wcstol)(W("1234"), &e, 10), 1234);
    EXPECT_EQ(UN(wcstol)(W("-1234"), NULL, 10), (ULONG_PTR)(long long)-1234);
    EXPECT_EQ(UN(wcstol)(W("  +0x1f"), NULL, 16), 31);
    EXPECT_EQ(UN(wcstol)(W("0x1f"), NULL, 0), 31);
    EXPECT_EQ(UN(wcstol)(W("010"), NULL, 0), 8);
    EXPECT_EQ(UN(wcstol)(W("10"), NULL, 8), 8);
    EXPECT_EQ(UN(wcstol)(W("zz"), NULL, 36), 1295);
    s = W("77 rest"); EXPECT_EQ(UN(wcstol)(s, &e, 10), 77); EXPECT_EQ(e, s + 2);
    s = W("q"); EXPECT_EQ(UN(wcstol)(s, &e, 10), 0); EXPECT_EQ(e, s);
    EXPECT_EQ(UN(wcstol)(W("2147483647"), NULL, 10), 2147483647);
    EXPECT_EQ(UN(wcstol)(W("-2147483648"), NULL, 10), (ULONG_PTR)(long long)-2147483647 - 1);
    EXPECT_EQ(UN(wcstol)(W("2147483648"), NULL, 10), 2147483647);                /* clamped */
    EXPECT_EQ(UN(wcstol)(W("-2147483649"), NULL, 10), (ULONG_PTR)(long long)-2147483647 - 1);
    EXPECT_EQ(UN(wcstoul)(W("4294967295"), NULL, 10), 4294967295u);
    EXPECT_EQ(UN(wcstoul)(W("4294967296"), NULL, 10), 4294967295u);              /* clamped */
    EXPECT_EQ(UN(wcstoul)(W("ffffffff"), NULL, 16), 4294967295u);
    EXPECT_EQ(UN(wcstoul)(W("-1"), NULL, 10), 4294967295u);
    EXPECT_EQ(UN(wcstoul)(W("0"), NULL, 10), 0);
    s = W("12ab"); EXPECT_EQ(UN(wcstoul)(s, &e, 10), 12); EXPECT_EQ(e, s + 2);
    s = W("zz"); EXPECT_EQ(UN(wcstoul)(s, &e, 10), 0); EXPECT_EQ(e, s);
    /* only the low 32 bits of the result are meaningful for 'unsigned long' on this ABI */
}

TEST(atoi_strtol) {
    REQUIRE(UN(atoi)); REQUIRE(UN(atol)); REQUIRE(UN(strtol)); REQUIRE(UN(strtoul));
    char *e; const char *s;
    EXPECT_EQ(UN(atoi)("0"), 0);
    EXPECT_EQ(UN(atoi)("  -321"), (ULONG_PTR)(long long)-321);
    EXPECT_EQ(UN(atoi)("+8z"), 8);
    EXPECT_EQ(UN(atoi)("z8"), 0);
    EXPECT_EQ(UN(atoi)("2147483647"), 2147483647);
    EXPECT_EQ(UN(atol)("123456"), 123456);
    EXPECT_EQ(UN(atol)("\t\n 9"), 9);
    EXPECT_EQ(UN(atol)("-0"), 0);
    EXPECT_EQ(UN(atol)(""), 0);

    EXPECT_EQ(UN(strtol)("1234", &e, 10), 1234);
    EXPECT_EQ(UN(strtol)("-0x10", NULL, 16), (ULONG_PTR)(long long)-16);
    EXPECT_EQ(UN(strtol)("0x10", NULL, 0), 16);
    EXPECT_EQ(UN(strtol)("0755", NULL, 0), 493);
    EXPECT_EQ(UN(strtol)("11", NULL, 2), 3);
    EXPECT_EQ(UN(strtol)("Zz", NULL, 36), 1295);
    s = "42,43"; EXPECT_EQ(UN(strtol)(s, &e, 10), 42); EXPECT_EQ(e, s + 2);
    s = "none"; EXPECT_EQ(UN(strtol)(s, &e, 10), 0); EXPECT_EQ(e, s);
    EXPECT_EQ(UN(strtol)("2147483648", NULL, 10), 2147483647);
    EXPECT_EQ(UN(strtol)("-2147483649", NULL, 10), (ULONG_PTR)(long long)-2147483647 - 1);
    EXPECT_EQ(UN(strtoul)("4294967295", NULL, 10), 4294967295u);
    EXPECT_EQ(UN(strtoul)("4294967296", NULL, 10), 4294967295u);
    EXPECT_EQ(UN(strtoul)("0xdeadbeef", NULL, 16), 0xdeadbeefu);
    EXPECT_EQ(UN(strtoul)("-1", NULL, 10), 4294967295u);
    s = "99x"; EXPECT_EQ(UN(strtoul)(s, &e, 10), 99); EXPECT_EQ(e, s + 2);
    s = ""; EXPECT_EQ(UN(strtoul)(s, &e, 10), 0); EXPECT_EQ(e, s);
}

TEST(mbstowcs_wcstombs) {
    REQUIRE(UN(mbstowcs)); REQUIRE(UN(wcstombs));
    WCHAR w[32]; char n[32];
    /* ASCII only so the result does not depend on the ANSI code page */
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(mbstowcs)(w, "hello", 32), 5);
    EXPECT_EQ(w[0], 'h'); EXPECT_EQ(w[4], 'o'); EXPECT_EQ(w[5], 0);
    EXPECT_EQ(UN(mbstowcs)(NULL, "hello", 0), 5);                    /* length query */
    EXPECT_EQ(UN(mbstowcs)(NULL, "", 0), 0);
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(mbstowcs)(w, "hello", 3), 3);                       /* truncated: no terminator */
    EXPECT_EQ(w[2], 'l'); EXPECT_EQ(w[3], 0x5a5a);
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(mbstowcs)(w, "hello", 5), 5);                       /* exact: no terminator */
    EXPECT_EQ(w[5], 0x5a5a);
    EXPECT_EQ(UN(mbstowcs)(w, "", 4), 0); EXPECT_EQ(w[0], 0);

    memset(n, 0x5a, sizeof n);
    EXPECT_EQ(UN(wcstombs)(n, W("world"), 32), 5);
    EXPECT_STR(n, "world");
    EXPECT_EQ(UN(wcstombs)(NULL, W("world"), 0), 5);
    EXPECT_EQ(UN(wcstombs)(NULL, W(""), 0), 0);
    memset(n, 0x5a, sizeof n);
    /* the terminator is converted too: a truncated conversion writes 'max' bytes (no terminator)
     * and reports one less than that */
    EXPECT_EQ(UN(wcstombs)(n, W("world"), 3), 2);
    EXPECT_EQ(memcmp(n, "wor", 3), 0); EXPECT_EQ(n[3], 0x5a);
    memset(n, 0x5a, sizeof n);
    EXPECT_EQ(UN(wcstombs)(n, W("world"), 5), 4);
    EXPECT_EQ(memcmp(n, "worl", 4), 0); EXPECT_EQ(n[5], 0x5a);
    memset(n, 0x5a, sizeof n);
    EXPECT_EQ(UN(wcstombs)(n, W("world"), 6), 5);                    /* exact fit incl. NUL */
    EXPECT_STR(n, "world");
    memset(n, 0x5a, sizeof n);
    EXPECT_EQ(UN(wcstombs)(n, W(""), 4), 0); EXPECT_EQ(n[0], 0);
}

TEST(errno_on_range) {
    REQUIRE(UN(strtol)); REQUIRE(UN(_errno));
    int *e = UN(_errno)();
    *e = 0; UN(strtol)("12", NULL, 10); EXPECT_EQ(*e, 0);          /* success leaves errno alone */
    *e = 0; UN(strtol)("99999999999", NULL, 10);
    EXPECT_EQ(*e, 34);                                             /* ERANGE */
    *e = 0; UN(strtoul)("99999999999", NULL, 10); EXPECT_EQ(*e, 34);
    *e = 0; UN(wcstol)(W("-99999999999"), NULL, 10); EXPECT_EQ(*e, 34);
    *e = 0; UN(_wcstoi64)(W("99999999999999999999"), NULL, 10); EXPECT_EQ(*e, 34);
    *e = 0;
}
