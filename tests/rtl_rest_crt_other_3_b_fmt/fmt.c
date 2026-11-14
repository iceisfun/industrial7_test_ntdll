/* CRT-style ntdll exports: formatted output (sprintf/vsprintf families, counting variants), formatted
 * input (sscanf family) and the debug-print entry points. Floating point conversions are not used;
 * bounded variants are only driven into their documented truncation results. See EVIDENCE.md. */
#include "t.h"

#define TRUNC ((size_t)-1)

UDECL(int, sprintf, (char *, const char *, ...));
UDECL(int, sprintf_s, (char *, size_t, const char *, ...));
UDECL(int, swprintf, (WCHAR *, const WCHAR *, ...));
UDECL(int, swprintf_s, (WCHAR *, size_t, const WCHAR *, ...));
UDECL(int, vsprintf, (char *, const char *, va_list));
UDECL(int, vsprintf_s, (char *, size_t, const char *, va_list));
UDECL(int, vswprintf_s, (WCHAR *, size_t, const WCHAR *, va_list));
UDECL(int, _vswprintf, (WCHAR *, const WCHAR *, va_list));
UDECL(int, _vsnprintf, (char *, size_t, const char *, va_list));
UDECL(int, _vsnprintf_s, (char *, size_t, size_t, const char *, va_list));
UDECL(int, _vsnwprintf, (WCHAR *, size_t, const WCHAR *, va_list));
UDECL(int, _vsnwprintf_s, (WCHAR *, size_t, size_t, const WCHAR *, va_list));
UDECL(int, _vscprintf, (const char *, va_list));
UDECL(int, _vscwprintf, (const WCHAR *, va_list));
UDECL(int, sscanf, (const char *, const char *, ...));
UDECL(int, sscanf_s, (const char *, const char *, ...));
UDECL(int, swscanf_s, (const WCHAR *, const WCHAR *, ...));
UDECL(NTSTATUS, vDbgPrintEx, (ULONG, ULONG, const char *, va_list));
UDECL(NTSTATUS, vDbgPrintExWithPrefix, (const char *, ULONG, ULONG, const char *, va_list));

static const WCHAR *W(const char *s) {
    static WCHAR buf[8][160]; static int k;
    WCHAR *b = buf[k++ & 7]; size_t i = 0;
    for (; s[i]; i++) b[i] = (unsigned char)s[i];
    b[i] = 0; return b;
}
static int weq(const WCHAR *w, const char *s) {
    size_t i = 0;
    for (; s[i]; i++) if (w[i] != (unsigned char)s[i]) return 0;
    return w[i] == 0;
}
#define EXPECT_W(w, s) CHECKF(weq((w), (s)), "wide string mismatch, wanted \"%s\"", (s))
static void fillw(WCHAR *w, int n, WCHAR v) { for (int i = 0; i < n; i++) w[i] = v; }

/* ---- va_list wrappers ---- */
static int v_sprintf(char *b, const char *f, ...) { va_list a; va_start(a, f); int r = UN(vsprintf)(b, f, a); va_end(a); return r; }
static int v_sprintf_s(char *b, size_t n, const char *f, ...) { va_list a; va_start(a, f); int r = UN(vsprintf_s)(b, n, f, a); va_end(a); return r; }
static int v_swprintf_s(WCHAR *b, size_t n, const WCHAR *f, ...) { va_list a; va_start(a, f); int r = UN(vswprintf_s)(b, n, f, a); va_end(a); return r; }
static int v_vswprintf(WCHAR *b, const WCHAR *f, ...) { va_list a; va_start(a, f); int r = UN(_vswprintf)(b, f, a); va_end(a); return r; }
static int v_snprintf(char *b, size_t n, const char *f, ...) { va_list a; va_start(a, f); int r = UN(_vsnprintf)(b, n, f, a); va_end(a); return r; }
static int v_snprintf_s(char *b, size_t n, size_t c, const char *f, ...) { va_list a; va_start(a, f); int r = UN(_vsnprintf_s)(b, n, c, f, a); va_end(a); return r; }
static int v_snwprintf(WCHAR *b, size_t n, const WCHAR *f, ...) { va_list a; va_start(a, f); int r = UN(_vsnwprintf)(b, n, f, a); va_end(a); return r; }
static int v_snwprintf_s(WCHAR *b, size_t n, size_t c, const WCHAR *f, ...) { va_list a; va_start(a, f); int r = UN(_vsnwprintf_s)(b, n, c, f, a); va_end(a); return r; }
static int v_scprintf(const char *f, ...) { va_list a; va_start(a, f); int r = UN(_vscprintf)(f, a); va_end(a); return r; }
static int v_scwprintf(const WCHAR *f, ...) { va_list a; va_start(a, f); int r = UN(_vscwprintf)(f, a); va_end(a); return r; }

TEST(sprintf_narrow) {
    REQUIRE(UN(sprintf)); REQUIRE(UN(sprintf_s));
    char b[128];
    EXPECT_EQ(UN(sprintf)(b, "plain"), 5); EXPECT_STR(b, "plain");
    EXPECT_EQ(UN(sprintf)(b, "%d|%i|%u", -12, 34, 4000000000u), 17);
    EXPECT_STR(b, "-12|34|4000000000");
    EXPECT_EQ(UN(sprintf)(b, "%x %X %o %#x %#o", 255, 255, 8, 255, 8), 17); EXPECT_STR(b, "ff FF 10 0xff 010");
    EXPECT_EQ(UN(sprintf)(b, "[%5d][%-5d][%05d][%+d][% d]", 42, 42, 42, 42, 42), 31); EXPECT_STR(b, "[   42][42   ][00042][+42][ 42]");
    EXPECT_EQ(UN(sprintf)(b, "[%s][%10s][%-6s][%.2s]", "abc", "abc", "abc", "abc"), 29); EXPECT_STR(b, "[abc][       abc][abc   ][ab]");
    EXPECT_EQ(UN(sprintf)(b, "%c%c%c", 'x', 'y', 'z'), 3); EXPECT_STR(b, "xyz");
    EXPECT_EQ(UN(sprintf)(b, "100%%"), 4); EXPECT_STR(b, "100%");
    EXPECT_EQ(UN(sprintf)(b, "[%*d][%-*d]", 6, 7, 4, 8), 14); EXPECT_STR(b, "[     7][8   ]");
    EXPECT_EQ(UN(sprintf)(b, "[%.*s]", 2, "abcdef"), 4); EXPECT_STR(b, "[ab]");
    EXPECT_EQ(UN(sprintf)(b, "%I64d %I64u %I64x", -5000000000LL, 18446744073709551615ULL, 0x123456789abcdefULL), 11 + 1 + 20 + 1 + 15);
    EXPECT_STR(b, "-5000000000 18446744073709551615 123456789abcdef");
    EXPECT_EQ(UN(sprintf)(b, "%hd %hu %ld %lu", (short)-3, (unsigned short)65535, -7L, 7UL), 13); EXPECT_STR(b, "-3 65535 -7 7");
    EXPECT_EQ(UN(sprintf)(b, "%ls|%S", W("wide"), W("WIDE")), 9); EXPECT_STR(b, "wide|WIDE");
    EXPECT_EQ(UN(sprintf)(b, "%s", ""), 0); EXPECT_EQ(b[0], 0);
    EXPECT_EQ(UN(sprintf)(b, "%.0d", 0), 0);
    /* %n is not supported by this CRT: the count is neither stored nor does it abort */
    int n = -1; UN(sprintf)(b, "abc%nde", &n); EXPECT_EQ(n, -1);
    EXPECT_EQ(UN(sprintf)(b, ""), 0); EXPECT_EQ(b[0], 0);

    char d[16]; memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(sprintf_s)(d, sizeof d, "%d-%s", 7, "xyz"), 5); EXPECT_STR(d, "7-xyz");
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(sprintf_s)(d, 6, "%d-%s", 7, "xyz"), 5); EXPECT_STR(d, "7-xyz"); EXPECT_EQ(d[6], 0x5a);  /* exact fit incl. NUL */
    EXPECT_EQ(UN(sprintf_s)(d, 1, ""), 0); EXPECT_EQ(d[0], 0);
    EXPECT_EQ(UN(sprintf_s)(d, sizeof d, "%c", 'q'), 1);
}

TEST(swprintf_wide) {
    REQUIRE(UN(swprintf)); REQUIRE(UN(swprintf_s));
    WCHAR b[128];
    EXPECT_EQ(UN(swprintf)(b, W("plain")), 5); EXPECT_W(b, "plain");
    EXPECT_EQ(UN(swprintf)(b, W("%d|%u|%x|%X"), -12, 34, 255, 255), 12); EXPECT_W(b, "-12|34|ff|FF");
    EXPECT_EQ(UN(swprintf)(b, W("[%5d][%-5d][%05d][%+d]"), 42, 42, 42, 42), 26); EXPECT_W(b, "[   42][42   ][00042][+42]");
    EXPECT_EQ(UN(swprintf)(b, W("[%s][%10s][%.2s]"), W("abc"), W("abc"), W("abc")), 21); EXPECT_W(b, "[abc][       abc][ab]");   /* %s is a wide string */
    EXPECT_EQ(UN(swprintf)(b, W("%hs|%ls|%S"), "narrow", W("wide"), "N"), 13); EXPECT_W(b, "narrow|wide|N");
    EXPECT_EQ(UN(swprintf)(b, W("%c%c"), 'a', L'b'), 2); EXPECT_W(b, "ab");
    EXPECT_EQ(UN(swprintf)(b, W("%I64d %I64x"), -5000000000LL, 0xabcdef123456ULL), 11 + 1 + 12); EXPECT_W(b, "-5000000000 abcdef123456");
    EXPECT_EQ(UN(swprintf)(b, W("%%")), 1); EXPECT_W(b, "%");
    EXPECT_EQ(UN(swprintf)(b, W("")), 0); EXPECT_EQ(b[0], 0);
    WCHAR big[] = { 0x3b1, 0x3b2, 0 };
    EXPECT_EQ(UN(swprintf)(b, W("%s"), big), 2); EXPECT_EQ(b[0], 0x3b1); EXPECT_EQ(b[1], 0x3b2); EXPECT_EQ(b[2], 0);

    WCHAR d[16]; fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(swprintf_s)(d, 16, W("%d-%s"), 7, W("xyz")), 5); EXPECT_W(d, "7-xyz");
    fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(swprintf_s)(d, 6, W("%d-%s"), 7, W("xyz")), 5); EXPECT_W(d, "7-xyz"); EXPECT_EQ(d[6], 0x5a5a);
    EXPECT_EQ(UN(swprintf_s)(d, 1, W("")), 0); EXPECT_EQ(d[0], 0);
    EXPECT_EQ(UN(swprintf_s)(d, 16, W("%04x"), 0xab), 4); EXPECT_W(d, "00ab");
}

TEST(vsprintf_family) {
    REQUIRE(UN(vsprintf));
    char b[64];
    EXPECT_EQ(v_sprintf(b, "%d:%s:%c:%x", -9, "str", 'k', 0xbeef), 13); EXPECT_STR(b, "-9:str:k:beef");
    EXPECT_EQ(v_sprintf(b, ""), 0); EXPECT_EQ(b[0], 0);
    EXPECT_EQ(v_sprintf(b, "%I64u", ~0ULL), 20); EXPECT_STR(b, "18446744073709551615");

}

TEST(vsprintf_s_narrow) {
    REQUIRE(UN(vsprintf_s));
    char b[64];
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_sprintf_s(b, sizeof b, "%d/%d", 3, 4), 3); EXPECT_STR(b, "3/4");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_sprintf_s(b, 4, "%d/%d", 3, 4), 3); EXPECT_STR(b, "3/4"); EXPECT_EQ(b[4], 0x5a);
    EXPECT_EQ(v_sprintf_s(b, 1, ""), 0); EXPECT_EQ(b[0], 0);

}

TEST(vswprintf_s_wide) {
    REQUIRE(UN(vswprintf_s));
    WCHAR w[64];
    fillw(w, 64, 0x5a5a);
    EXPECT_EQ(v_swprintf_s(w, 64, W("%d/%s"), 3, W("ab")), 4); EXPECT_W(w, "3/ab");
    fillw(w, 64, 0x5a5a);
    EXPECT_EQ(v_swprintf_s(w, 5, W("%d/%s"), 3, W("ab")), 4); EXPECT_W(w, "3/ab"); EXPECT_EQ(w[5], 0x5a5a);

}

TEST(vswprintf_unbounded) {
    REQUIRE(UN(_vswprintf));
    WCHAR w[64];
    fillw(w, 64, 0x5a5a);
    EXPECT_EQ(v_vswprintf(w, W("%d+%d"), 1, 2), 3); EXPECT_W(w, "1+2"); EXPECT_EQ(w[4], 0x5a5a);
    fillw(w, 64, 0x5a5a);
    EXPECT_EQ(v_vswprintf(w, W("%s"), W("hello")), 5); EXPECT_W(w, "hello");
    EXPECT_EQ(v_vswprintf(w, W("")), 0); EXPECT_EQ(w[0], 0);
    EXPECT_EQ(v_vswprintf(w, W("%hs|%x"), "ab", 0xff), 5); EXPECT_W(w, "ab|ff");
}

TEST(vsnprintf_family) {
    REQUIRE(UN(_vsnprintf)); REQUIRE(UN(_vsnprintf_s)); REQUIRE(UN(_vsnwprintf)); REQUIRE(UN(_vsnwprintf_s));
    char b[32]; WCHAR w[32];
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf(b, sizeof b, "%s=%d", "k", 12), 4); EXPECT_STR(b, "k=12");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf(b, 5, "%s=%d", "k", 12), 4); EXPECT_STR(b, "k=12");          /* fits with NUL */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf(b, 4, "%s=%d", "k", 12), 4); EXPECT_EQ(memcmp(b, "k=12", 4), 0); EXPECT_EQ(b[4], 0x5a);   /* exact: no NUL */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf(b, 3, "%s=%d", "k", 12), -1); EXPECT_EQ(memcmp(b, "k=1", 3), 0); EXPECT_EQ(b[3], 0x5a);    /* truncated */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf(b, 0, "abc"), -1); EXPECT_EQ(b[0], 0x5a);
    EXPECT_EQ(v_snprintf(NULL, 0, ""), 0);

    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf_s(b, sizeof b, 3, "%s", "abcdef"), -1); EXPECT_STR(b, "abc");  /* count < size: cut at count, terminated */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf_s(b, sizeof b, 10, "%s", "abcdef"), 6); EXPECT_STR(b, "abcdef");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf_s(b, 4, TRUNC, "%s", "abcdef"), -1); EXPECT_STR(b, "abc");     /* _TRUNCATE */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf_s(b, 7, TRUNC, "%s", "abcdef"), 6); EXPECT_STR(b, "abcdef");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(v_snprintf_s(b, 7, 6, "%s", "abcdef"), 6); EXPECT_STR(b, "abcdef");
    EXPECT_EQ(v_snprintf_s(b, 1, TRUNC, ""), 0); EXPECT_EQ(b[0], 0);

    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf(w, 32, W("%s=%d"), W("k"), 12), 4); EXPECT_W(w, "k=12");
    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf(w, 4, W("%s=%d"), W("k"), 12), 4); EXPECT_EQ(w[3], '2'); EXPECT_EQ(w[4], 0x5a5a);
    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf(w, 3, W("%s=%d"), W("k"), 12), -1); EXPECT_EQ(w[2], '1'); EXPECT_EQ(w[3], 0x5a5a);
    EXPECT_EQ(v_snwprintf(NULL, 0, W("")), 0);

    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf_s(w, 32, 3, W("%s"), W("abcdef")), -1); EXPECT_W(w, "abc");
    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf_s(w, 32, 10, W("%s"), W("abcdef")), 6); EXPECT_W(w, "abcdef");
    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf_s(w, 4, TRUNC, W("%s"), W("abcdef")), -1); EXPECT_W(w, "abc");
    fillw(w, 32, 0x5a5a);
    EXPECT_EQ(v_snwprintf_s(w, 7, TRUNC, W("%s"), W("abcdef")), 6); EXPECT_W(w, "abcdef");
    EXPECT_EQ(v_snwprintf_s(NULL, 0, 0, W("x")), 0);
}

TEST(vscprintf_family) {
    REQUIRE(UN(_vscprintf)); REQUIRE(UN(_vscwprintf));
    EXPECT_EQ(v_scprintf(""), 0);
    EXPECT_EQ(v_scprintf("abc"), 3);
    EXPECT_EQ(v_scprintf("%d-%s-%c", -123, "four", 'x'), 11);
    EXPECT_EQ(v_scprintf("%10d", 5), 10);
    EXPECT_EQ(v_scprintf("%I64x", 0xfedcba9876543210ULL), 16);
    EXPECT_EQ(v_scwprintf(W("")), 0);
    EXPECT_EQ(v_scwprintf(W("abc")), 3);
    EXPECT_EQ(v_scwprintf(W("%d-%s-%c"), -123, W("four"), 'x'), 11);
    EXPECT_EQ(v_scwprintf(W("%S"), "narrow"), 6);
    EXPECT_EQ(v_scwprintf(W("%5s|%-5s"), W("a"), W("b")), 11);
}

TEST(sscanf_narrow) {
    REQUIRE(UN(sscanf)); REQUIRE(UN(sscanf_s));
    int a = -1, b = -1; char s[32] = "", c = 0; unsigned x = 0;
    EXPECT_EQ(UN(sscanf)("12 34", "%d %d", &a, &b), 2); EXPECT_EQ(a, 12); EXPECT_EQ(b, 34);
    a = b = -1; EXPECT_EQ(UN(sscanf)("12 abc", "%d %d", &a, &b), 1); EXPECT_EQ(a, 12); EXPECT_EQ(b, -1);   /* match failure */
    EXPECT_EQ(UN(sscanf)("abc", "%d", &a), 0);
    EXPECT_EQ(UN(sscanf)("", "%d", &a), -1);                              /* input exhausted: EOF */
    EXPECT_EQ(UN(sscanf)("  word rest", "%s", s), 1); EXPECT_STR(s, "word");
    EXPECT_EQ(UN(sscanf)("ff 0x1F 17", "%x %x %o", &x, &a, &b), 3); EXPECT_EQ(x, 255); EXPECT_EQ(a, 31); EXPECT_EQ(b, 15);
    EXPECT_EQ(UN(sscanf)("-5 +6", "%d %d", &a, &b), 2); EXPECT_EQ(a, -5); EXPECT_EQ(b, 6);
    EXPECT_EQ(UN(sscanf)("0x10 010 10", "%i %i %i", &a, &b, &x), 3); EXPECT_EQ(a, 16); EXPECT_EQ(b, 8); EXPECT_EQ(x, 10);
    EXPECT_EQ(UN(sscanf)("x", "%c", &c), 1); EXPECT_EQ(c, 'x');
    EXPECT_EQ(UN(sscanf)("key=val", "%[a-z]=%s", s, s + 16), 2); EXPECT_STR(s, "key"); EXPECT_STR(s + 16, "val");
    EXPECT_EQ(UN(sscanf)("12345", "%2d%3d", &a, &b), 2); EXPECT_EQ(a, 12); EXPECT_EQ(b, 345);
    EXPECT_EQ(UN(sscanf)("7 8", "%*d %d", &a), 1); EXPECT_EQ(a, 8);              /* assignment suppression */
    EXPECT_EQ(UN(sscanf)("abc def", "%s%n", s, &a), 1); EXPECT_EQ(a, 3);          /* %n not counted */
    long long ll = 0; EXPECT_EQ(UN(sscanf)("-9000000000", "%I64d", &ll), 1); EXPECT_EQ(ll, -9000000000LL);
    short sh = 0; EXPECT_EQ(UN(sscanf)("-77", "%hd", &sh), 1); EXPECT_EQ(sh, -77);
    EXPECT_EQ(UN(sscanf)("100%", "%d%%", &a), 1); EXPECT_EQ(a, 100);
    a = 0; EXPECT_EQ(UN(sscanf)("xy", "x%d", &a), 0);                             /* literal matched, conversion failed */

    memset(s, 0x5a, sizeof s);
    EXPECT_EQ(UN(sscanf_s)("hello world", "%s", s, (unsigned)sizeof s), 1); EXPECT_STR(s, "hello");
    EXPECT_EQ(UN(sscanf_s)("1 2 3", "%d %d %d", &a, &b, &x), 3); EXPECT_EQ(a, 1); EXPECT_EQ(b, 2); EXPECT_EQ(x, 3);
    EXPECT_EQ(UN(sscanf_s)("z", "%c", &c, (unsigned)1), 1); EXPECT_EQ(c, 'z');
    EXPECT_EQ(UN(sscanf_s)("abc", "%d", &a), 0);
    EXPECT_EQ(UN(sscanf_s)("", "%d", &a), -1);
    memset(s, 0x5a, sizeof s);
    EXPECT_EQ(UN(sscanf_s)("abcdef", "%3c", s, (unsigned)3), 1); EXPECT_EQ(memcmp(s, "abc", 3), 0); EXPECT_EQ(s[3], 0x5a);
}

TEST(swscanf_wide) {
    REQUIRE(UN(swscanf_s));
    int a = -1, b = -1; WCHAR s[32]; unsigned x = 0; WCHAR c = 0;
    EXPECT_EQ(UN(swscanf_s)(W("12 34"), W("%d %d"), &a, &b), 2); EXPECT_EQ(a, 12); EXPECT_EQ(b, 34);
    a = b = -1; EXPECT_EQ(UN(swscanf_s)(W("12 xyz"), W("%d %d"), &a, &b), 1); EXPECT_EQ(b, -1);
    EXPECT_EQ(UN(swscanf_s)(W(""), W("%d"), &a), 0);   /* unlike sscanf, empty wide input reports 0, not EOF (observed) */
    EXPECT_EQ(UN(swscanf_s)(W("  word rest"), W("%s"), s, (unsigned)32), 1); EXPECT_W(s, "word");
    EXPECT_EQ(UN(swscanf_s)(W("ff 0x1F"), W("%x %x"), &x, &a), 2); EXPECT_EQ(x, 255); EXPECT_EQ(a, 31);
    EXPECT_EQ(UN(swscanf_s)(W("q"), W("%c"), &c, (unsigned)1), 1); EXPECT_EQ(c, 'q');
    EXPECT_EQ(UN(swscanf_s)(W("name=val"), W("%[a-z]=%s"), s, (unsigned)16, s + 16, (unsigned)16), 2); EXPECT_W(s, "name"); EXPECT_W(s + 16, "val");
    EXPECT_EQ(UN(swscanf_s)(W("7 8"), W("%*d %d"), &a), 1); EXPECT_EQ(a, 8);
    long long ll = 0; EXPECT_EQ(UN(swscanf_s)(W("-9000000000"), W("%I64d"), &ll), 1); EXPECT_EQ(ll, -9000000000LL);
    EXPECT_EQ(UN(swscanf_s)(W("abc"), W("%d"), &a), 0);
    WCHAR g[] = { 0x3b1, 0x3b2, 0 };
    EXPECT_EQ(UN(swscanf_s)(g, W("%s"), s, (unsigned)32), 1); EXPECT_EQ(s[0], 0x3b1); EXPECT_EQ(s[1], 0x3b2); EXPECT_EQ(s[2], 0);
}

static NTSTATUS call_dbg(ULONG comp, ULONG lvl, const char *f, ...) { va_list a; va_start(a, f); NTSTATUS r = UN(vDbgPrintEx)(comp, lvl, f, a); va_end(a); return r; }
static NTSTATUS call_dbgp(const char *p, ULONG comp, ULONG lvl, const char *f, ...) { va_list a; va_start(a, f); NTSTATUS r = UN(vDbgPrintExWithPrefix)(p, comp, lvl, f, a); va_end(a); return r; }

TEST(dbgprint) {
    REQUIRE(UN(vDbgPrintEx)); REQUIRE(UN(vDbgPrintExWithPrefix));
    /* component 77 (IHVDRIVER), level 0: formatting happens in the caller and the call returns normally */
    NTSTATUS st;
    st = call_dbg(77, 0, "ntdll conformance vDbgPrintEx %d %s\n", 42, "text");
    t_note("vDbgPrintEx status 0x%08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    st = call_dbgp("PFX: ", 77, 0, "ntdll conformance vDbgPrintExWithPrefix %d\n", 7);
    t_note("vDbgPrintExWithPrefix status 0x%08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    /* a component id beyond the filter table is filtered out, not an error */
    st = call_dbg(0x7fffffff, 0, "never shown\n");
    t_note("vDbgPrintEx with out of range component 0x%08lx", (unsigned long)st);
    st = call_dbgp("", 77, 0, "empty prefix\n");
    EXPECT_EQ(st, 0);
}
