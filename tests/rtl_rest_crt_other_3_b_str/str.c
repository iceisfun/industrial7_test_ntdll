/* CRT-style ntdll exports: bounded string and memory copy/concatenate, tokenizing, wide case mapping,
 * path split/make. Only non-reporting paths are exercised (truncation with STRUNCATE is a normal
 * return; argument errors would enter the invalid-parameter routine and are not driven). See EVIDENCE.md. */
#include "t.h"

#define STRUNCATE 80
#define TRUNC ((size_t)-1)

UDECL(WCHAR *, _wcslwr, (WCHAR *));
UDECL(WCHAR *, _wcsupr, (WCHAR *));
UDECL(int, _wcslwr_s, (WCHAR *, size_t));
UDECL(int, _wcsupr_s, (WCHAR *, size_t));
UDECL(int, _wcsnicmp, (const WCHAR *, const WCHAR *, size_t));
UDECL(int, _wcsset_s, (WCHAR *, size_t, WCHAR));
UDECL(int, _wcsnset_s, (WCHAR *, size_t, WCHAR, size_t));
UDECL(int, strncat_s, (char *, size_t, const char *, size_t));
UDECL(int, strncpy_s, (char *, size_t, const char *, size_t));
UDECL(int, wcsncat_s, (WCHAR *, size_t, const WCHAR *, size_t));
UDECL(int, wcsncpy_s, (WCHAR *, size_t, const WCHAR *, size_t));
UDECL(char *, strtok_s, (char *, const char *, char **));
UDECL(WCHAR *, wcstok_s, (WCHAR *, const WCHAR *, WCHAR **));
UDECL(void *, memcpy, (void *, const void *, size_t));
UDECL(int, memcpy_s, (void *, size_t, const void *, size_t));
UDECL(int, memmove_s, (void *, size_t, const void *, size_t));
UDECL(int, _wmakepath_s, (WCHAR *, size_t, const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *));
UDECL(int, _wsplitpath_s, (const WCHAR *, WCHAR *, size_t, WCHAR *, size_t, WCHAR *, size_t, WCHAR *, size_t));

static const WCHAR *W(const char *s) {
    static WCHAR buf[8][160]; static int k;
    WCHAR *b = buf[k++ & 7]; size_t i = 0;
    for (; s[i]; i++) b[i] = (unsigned char)s[i];
    b[i] = 0; return b;
}
static void setw(WCHAR *d, const char *s) { size_t i = 0; for (; s[i]; i++) d[i] = (unsigned char)s[i]; d[i] = 0; }
static int weq(const WCHAR *w, const char *s) {
    size_t i = 0;
    for (; s[i]; i++) if (w[i] != (unsigned char)s[i]) return 0;
    return w[i] == 0;
}
#define EXPECT_W(w, s) CHECKF(weq((w), (s)), "wide string mismatch, wanted \"%s\"", (s))
static void fillw(WCHAR *w, int n, WCHAR v) { for (int i = 0; i < n; i++) w[i] = v; }

TEST(wcslwr_wcsupr) {
    REQUIRE(UN(_wcslwr)); REQUIRE(UN(_wcsupr)); REQUIRE(UN(_wcslwr_s)); REQUIRE(UN(_wcsupr_s));
    WCHAR b[40];
    setw(b, "Hello, World_123 [@`{"); EXPECT_EQ(UN(_wcslwr)(b), b); EXPECT_W(b, "hello, world_123 [@`{");
    setw(b, "Hello, World_123 [@`{"); EXPECT_EQ(UN(_wcsupr)(b), b); EXPECT_W(b, "HELLO, WORLD_123 [@`{");
    b[0] = 0; EXPECT_EQ(UN(_wcsupr)(b), b); EXPECT_EQ(b[0], 0);
    /* only ASCII letters are mapped; Latin-1 and other letters are left alone (observed) */
    b[0] = 0xe9; b[1] = 0x3b1; b[2] = 0; UN(_wcsupr)(b); EXPECT_EQ(b[0], 0xe9); EXPECT_EQ(b[1], 0x3b1);
    b[0] = 0xc9; b[1] = 0x391; b[2] = 0; UN(_wcslwr)(b); EXPECT_EQ(b[0], 0xc9); EXPECT_EQ(b[1], 0x391);

    setw(b, "MiXeD"); EXPECT_EQ(UN(_wcslwr_s)(b, 6), 0); EXPECT_W(b, "mixed");
    setw(b, "MiXeD"); EXPECT_EQ(UN(_wcsupr_s)(b, 6), 0); EXPECT_W(b, "MIXED");
    setw(b, "MiXeD"); EXPECT_EQ(UN(_wcsupr_s)(b, 40), 0); EXPECT_W(b, "MIXED");
    b[0] = 0; EXPECT_EQ(UN(_wcslwr_s)(b, 1), 0); EXPECT_EQ(b[0], 0);
}

TEST(wcsnicmp) {
    REQUIRE(UN(_wcsnicmp));
    EXPECT_EQ(UN(_wcsnicmp)(W("HELLO world"), W("hello WORLD"), 11), 0);
    EXPECT_EQ(UN(_wcsnicmp)(W("HELLO world"), W("hello WORLD"), 5), 0);
    CHECK(UN(_wcsnicmp)(W("abcX"), W("ABCy"), 4) < 0);
    CHECK(UN(_wcsnicmp)(W("abcZ"), W("ABCy"), 4) > 0);
    EXPECT_EQ(UN(_wcsnicmp)(W("abcX"), W("ABCy"), 3), 0);
    EXPECT_EQ(UN(_wcsnicmp)(W("abc"), W("xyz"), 0), 0);
    EXPECT_EQ(UN(_wcsnicmp)(W("ab"), W("AB"), 100), 0);   /* stops at the terminator */
    CHECK(UN(_wcsnicmp)(W("ab"), W("abc"), 3) < 0);
    CHECK(UN(_wcsnicmp)(W("abc"), W(""), 3) > 0);
    WCHAR a[2] = { 0xe9, 0 }, b[2] = { 0xc9, 0 };
    CHECK(UN(_wcsnicmp)(a, b, 1) > 0);                    /* no Latin-1 case folding: 0xe9 > 0xc9 */
    WCHAR c[2] = { 0x3b1, 0 }, d[2] = { 0x391, 0 };
    CHECK(UN(_wcsnicmp)(c, d, 1) > 0);
}

TEST(wcsset_wcsnset) {
    REQUIRE(UN(_wcsset_s)); REQUIRE(UN(_wcsnset_s));
    WCHAR b[16];
    fillw(b, 16, 0x7777); setw(b, "abcde");
    EXPECT_EQ(UN(_wcsset_s)(b, 16, 'x'), 0); EXPECT_W(b, "xxxxx"); EXPECT_EQ(b[6], 0x7777);
    setw(b, "abcde"); EXPECT_EQ(UN(_wcsset_s)(b, 6, 'y'), 0); EXPECT_W(b, "yyyyy");
    b[0] = 0; EXPECT_EQ(UN(_wcsset_s)(b, 1, 'z'), 0); EXPECT_EQ(b[0], 0);
    setw(b, "abcde"); EXPECT_EQ(UN(_wcsnset_s)(b, 16, 'q', 3), 0); EXPECT_W(b, "qqqde");
    setw(b, "abcde"); EXPECT_EQ(UN(_wcsnset_s)(b, 16, 'q', 0), 0); EXPECT_W(b, "abcde");
    setw(b, "abcde"); EXPECT_EQ(UN(_wcsnset_s)(b, 16, 'q', 100), 0); EXPECT_W(b, "qqqqq");  /* stops at terminator */
    setw(b, "ab"); EXPECT_EQ(UN(_wcsnset_s)(b, 16, 'q', 100), 0); EXPECT_EQ(b[2], 0);
    setw(b, "abcde"); EXPECT_EQ(UN(_wcsnset_s)(b, 6, 'r', 5), 0); EXPECT_W(b, "rrrrr");
    EXPECT_EQ(UN(_wcsnset_s)(NULL, 0, 'r', 0), 0);   /* NULL, size 0, count 0 is explicitly valid */
}

TEST(strncpy_strncat) {
    REQUIRE(UN(strncpy_s)); REQUIRE(UN(strncat_s));
    char d[16];
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, sizeof d, "hello", 5), 0); EXPECT_STR(d, "hello");
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, sizeof d, "hello", 3), 0); EXPECT_STR(d, "hel");   /* count limits and terminates */
    EXPECT_EQ(d[4], 0x5a);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, sizeof d, "hi", 10), 0); EXPECT_STR(d, "hi");      /* count > length: stops at NUL */
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, 6, "hello", TRUNC), 0); EXPECT_STR(d, "hello");    /* exact fit */
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, 4, "hello", TRUNC), STRUNCATE); EXPECT_STR(d, "hel"); /* _TRUNCATE: truncate and terminate */
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, 1, "hello", TRUNC), STRUNCATE); EXPECT_EQ(d[0], 0);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(strncpy_s)(d, sizeof d, "", 4), 0); EXPECT_EQ(d[0], 0);
    EXPECT_EQ(UN(strncpy_s)(d, sizeof d, "abc", 0), 0); EXPECT_EQ(d[0], 0);       /* count 0 empties destination */

    strcpy(d, "ab");
    EXPECT_EQ(UN(strncat_s)(d, sizeof d, "cdef", 2), 0); EXPECT_STR(d, "abcd");
    EXPECT_EQ(UN(strncat_s)(d, sizeof d, "xy", 10), 0); EXPECT_STR(d, "abcdxy");
    EXPECT_EQ(UN(strncat_s)(d, sizeof d, "zzz", 0), 0); EXPECT_STR(d, "abcdxy");
    EXPECT_EQ(UN(strncat_s)(d, sizeof d, "", 5), 0); EXPECT_STR(d, "abcdxy");
    strcpy(d, "abc");
    EXPECT_EQ(UN(strncat_s)(d, 7, "def", TRUNC), 0); EXPECT_STR(d, "abcdef");      /* exact fit */
    strcpy(d, "abc");
    EXPECT_EQ(UN(strncat_s)(d, 6, "defgh", TRUNC), STRUNCATE); EXPECT_STR(d, "abcde");
    strcpy(d, "abc");
    EXPECT_EQ(UN(strncat_s)(d, 4, "d", TRUNC), STRUNCATE); EXPECT_STR(d, "abc");   /* no room at all */
}

TEST(wcsncpy_wcsncat) {
    REQUIRE(UN(wcsncpy_s)); REQUIRE(UN(wcsncat_s));
    WCHAR d[16];
    fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(wcsncpy_s)(d, 16, W("hello"), 5), 0); EXPECT_W(d, "hello");
    fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(wcsncpy_s)(d, 16, W("hello"), 3), 0); EXPECT_W(d, "hel"); EXPECT_EQ(d[4], 0x5a5a);
    fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(wcsncpy_s)(d, 16, W("hi"), 10), 0); EXPECT_W(d, "hi");
    EXPECT_EQ(UN(wcsncpy_s)(d, 6, W("hello"), TRUNC), 0); EXPECT_W(d, "hello");
    fillw(d, 16, 0x5a5a);
    EXPECT_EQ(UN(wcsncpy_s)(d, 4, W("hello"), TRUNC), STRUNCATE); EXPECT_W(d, "hel");
    EXPECT_EQ(UN(wcsncpy_s)(d, 1, W("hello"), TRUNC), STRUNCATE); EXPECT_EQ(d[0], 0);
    EXPECT_EQ(UN(wcsncpy_s)(d, 16, W("abc"), 0), 0); EXPECT_EQ(d[0], 0);

    setw(d, "ab");
    EXPECT_EQ(UN(wcsncat_s)(d, 16, W("cdef"), 2), 0); EXPECT_W(d, "abcd");
    EXPECT_EQ(UN(wcsncat_s)(d, 16, W("xy"), 10), 0); EXPECT_W(d, "abcdxy");
    EXPECT_EQ(UN(wcsncat_s)(d, 16, W("zzz"), 0), 0); EXPECT_W(d, "abcdxy");
    setw(d, "abc");
    EXPECT_EQ(UN(wcsncat_s)(d, 7, W("def"), TRUNC), 0); EXPECT_W(d, "abcdef");
    setw(d, "abc");
    EXPECT_EQ(UN(wcsncat_s)(d, 6, W("defgh"), TRUNC), STRUNCATE); EXPECT_W(d, "abcde");
}

TEST(tokenizers) {
    REQUIRE(UN(strtok_s)); REQUIRE(UN(wcstok_s));
    char s[] = ",,alpha, beta;;gamma,", *ctx = NULL, *t;
    t = UN(strtok_s)(s, ",; ", &ctx); CHECK(t == s + 2); EXPECT_STR(t, "alpha");
    t = UN(strtok_s)(NULL, ",; ", &ctx); CHECK(t == s + 9); EXPECT_STR(t, "beta");
    t = UN(strtok_s)(NULL, ",; ", &ctx); EXPECT_STR(t, "gamma");
    t = UN(strtok_s)(NULL, ",; ", &ctx); CHECK(t == NULL);
    t = UN(strtok_s)(NULL, ",; ", &ctx); CHECK(t == NULL);    /* stays exhausted */
    char e[] = ",,,"; ctx = NULL;
    CHECK(UN(strtok_s)(e, ",", &ctx) == NULL);                /* only delimiters */
    char one[] = "single"; ctx = NULL;
    t = UN(strtok_s)(one, ",", &ctx); CHECK(t == one); EXPECT_STR(t, "single");
    CHECK(UN(strtok_s)(NULL, ",", &ctx) == NULL);
    char sw[] = "a b c"; ctx = NULL;
    UN(strtok_s)(sw, " ", &ctx); CHECK(UN(strtok_s)(NULL, "", &ctx) != NULL); /* an empty delimiter set returns the rest */

    WCHAR w[40], *wctx = NULL, *wt;
    setw(w, ",,alpha, beta;;gamma,");
    wt = UN(wcstok_s)(w, W(",; "), &wctx); CHECK(wt == w + 2); EXPECT_W(wt, "alpha");
    wt = UN(wcstok_s)(NULL, W(",; "), &wctx); CHECK(wt == w + 9); EXPECT_W(wt, "beta");
    wt = UN(wcstok_s)(NULL, W(",; "), &wctx); EXPECT_W(wt, "gamma");
    wt = UN(wcstok_s)(NULL, W(",; "), &wctx); CHECK(wt == NULL);
    setw(w, ",,,"); wctx = NULL; CHECK(UN(wcstok_s)(w, W(","), &wctx) == NULL);
    setw(w, "x"); wctx = NULL; wt = UN(wcstok_s)(w, W(","), &wctx); CHECK(wt == w); CHECK(UN(wcstok_s)(NULL, W(","), &wctx) == NULL);
}

TEST(memcpy_family) {
    REQUIRE(UN(memcpy)); REQUIRE(UN(memcpy_s)); REQUIRE(UN(memmove_s));
    char s[32], d[32];
    for (int i = 0; i < 32; i++) s[i] = (char)(i + 1);
    for (int n = 0; n <= 32; n++) {   /* sizes cover all internal copy strategies */
        memset(d, 0, sizeof d);
        EXPECT_EQ(UN(memcpy)(d, s, n), d);
        EXPECT_EQ(memcmp(d, s, n), 0);
        if (n < 32) EXPECT_EQ(d[n], 0);
    }
    static char big[70000], bigd[70000];
    for (int i = 0; i < 70000; i++) big[i] = (char)(i * 7);
    EXPECT_EQ(UN(memcpy)(bigd, big, 70000), bigd); EXPECT_EQ(memcmp(bigd, big, 70000), 0);
    EXPECT_EQ(UN(memcpy)(bigd + 1, big + 3, 69990), bigd + 1); EXPECT_EQ(memcmp(bigd + 1, big + 3, 69990), 0);

    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(memcpy_s)(d, 32, s, 10), 0); EXPECT_EQ(memcmp(d, s, 10), 0); EXPECT_EQ(d[10], 0x5a);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(memcpy_s)(d, 10, s, 10), 0); EXPECT_EQ(memcmp(d, s, 10), 0); EXPECT_EQ(d[10], 0x5a);
    EXPECT_EQ(UN(memcpy_s)(d, 32, NULL, 0), 0);        /* zero count with NULL source is valid */
    EXPECT_EQ(UN(memcpy_s)(NULL, 0, NULL, 0), 0);
    EXPECT_EQ(UN(memcpy_s)(d, 0, s, 0), 0);

    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(memmove_s)(d, 32, s, 10), 0); EXPECT_EQ(memcmp(d, s, 10), 0);
    /* overlapping, forward and backward */
    for (int i = 0; i < 32; i++) d[i] = (char)(i + 1);
    EXPECT_EQ(UN(memmove_s)(d + 4, 28, d, 20), 0);
    for (int i = 0; i < 20; i++) EXPECT_EQ(d[4 + i], i + 1);
    for (int i = 0; i < 32; i++) d[i] = (char)(i + 1);
    EXPECT_EQ(UN(memmove_s)(d, 32, d + 5, 20), 0);
    for (int i = 0; i < 20; i++) EXPECT_EQ(d[i], i + 6);
    EXPECT_EQ(UN(memmove_s)(d, 32, d, 8), 0);          /* self move */
    EXPECT_EQ(UN(memmove_s)(NULL, 0, NULL, 0), 0);
}

TEST(wmakepath) {
    REQUIRE(UN(_wmakepath_s));
    WCHAR b[260]; fillw(b, 260, 0x5a5a);
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, W("C"), W("\\dir\\sub\\"), W("file"), W(".ext")), 0); EXPECT_W(b, "C:\\dir\\sub\\file.ext");
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, W("C:"), W("\\dir"), W("file"), W("ext")), 0); EXPECT_W(b, "C:\\dir\\file.ext"); /* drive colon, dir slash and ext dot supplied */
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, W("D"), W("a/b/"), W("f"), NULL), 0); EXPECT_W(b, "D:a/b/f");   /* forward slash accepted */
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, NULL, NULL, W("name"), W(".x")), 0); EXPECT_W(b, "name.x");
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, NULL, W("\\only\\"), NULL, NULL), 0); EXPECT_W(b, "\\only\\");
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, W(""), W(""), W(""), W("")), 0); EXPECT_EQ(b[0], 0);
    EXPECT_EQ(UN(_wmakepath_s)(b, 260, NULL, NULL, NULL, W("txt")), 0); EXPECT_W(b, ".txt");
    EXPECT_EQ(UN(_wmakepath_s)(b, 20, W("C"), W("\\d\\"), W("f"), W(".e")), 0); EXPECT_W(b, "C:\\d\\f.e");  /* result 8 chars fits in 20 */
    fillw(b, 260, 0x5a5a);
    EXPECT_EQ(UN(_wmakepath_s)(b, 9, W("C"), W("\\d\\"), W("f"), W(".e")), 0); EXPECT_W(b, "C:\\d\\f.e"); EXPECT_EQ(b[9], 0x5a5a); /* exact fit: 8 + NUL */
}

TEST(wsplitpath) {
    REQUIRE(UN(_wsplitpath_s));
    WCHAR dr[16], di[260], fn[260], ex[260];
    EXPECT_EQ(UN(_wsplitpath_s)(W("C:\\dir\\sub\\file.ext"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_W(dr, "C:"); EXPECT_W(di, "\\dir\\sub\\"); EXPECT_W(fn, "file"); EXPECT_W(ex, ".ext");
    EXPECT_EQ(UN(_wsplitpath_s)(W("file"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_EQ(dr[0], 0); EXPECT_EQ(di[0], 0); EXPECT_W(fn, "file"); EXPECT_EQ(ex[0], 0);
    EXPECT_EQ(UN(_wsplitpath_s)(W("a.b.c"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_W(fn, "a.b"); EXPECT_W(ex, ".c");                    /* last dot starts the extension */
    EXPECT_EQ(UN(_wsplitpath_s)(W("dir/sub/x.y"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_W(di, "dir/sub/"); EXPECT_W(fn, "x"); EXPECT_W(ex, ".y");
    EXPECT_EQ(UN(_wsplitpath_s)(W("\\\\srv\\share\\f.t"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_EQ(dr[0], 0); EXPECT_W(di, "\\\\srv\\share\\"); EXPECT_W(fn, "f"); EXPECT_W(ex, ".t");
    EXPECT_EQ(UN(_wsplitpath_s)(W("C:"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_W(dr, "C:"); EXPECT_EQ(di[0], 0); EXPECT_EQ(fn[0], 0);
    EXPECT_EQ(UN(_wsplitpath_s)(W("\\dir\\"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_W(di, "\\dir\\"); EXPECT_EQ(fn[0], 0); EXPECT_EQ(ex[0], 0);
    EXPECT_EQ(UN(_wsplitpath_s)(W(".hidden"), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_EQ(fn[0], 0); EXPECT_W(ex, ".hidden");
    EXPECT_EQ(UN(_wsplitpath_s)(W(""), dr, 16, di, 260, fn, 260, ex, 260), 0);
    EXPECT_EQ(dr[0], 0); EXPECT_EQ(di[0], 0); EXPECT_EQ(fn[0], 0); EXPECT_EQ(ex[0], 0);
    /* individual components may be omitted when pointer and size are both zero */
    EXPECT_EQ(UN(_wsplitpath_s)(W("C:\\d\\f.e"), NULL, 0, NULL, 0, fn, 260, NULL, 0), 0); EXPECT_W(fn, "f");
    EXPECT_EQ(UN(_wsplitpath_s)(W("C:\\d\\f.e"), NULL, 0, NULL, 0, NULL, 0, ex, 260), 0); EXPECT_W(ex, ".e");
    /* exact-fit buffers */
    EXPECT_EQ(UN(_wsplitpath_s)(W("C:\\d\\f.e"), dr, 3, di, 4, fn, 2, ex, 3), 0);
    EXPECT_W(dr, "C:"); EXPECT_W(di, "\\d\\"); EXPECT_W(fn, "f"); EXPECT_W(ex, ".e");
}
