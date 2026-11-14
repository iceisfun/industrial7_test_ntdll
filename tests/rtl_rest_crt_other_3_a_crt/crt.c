/* CRT-style ntdll exports: number/string conversion, ctype helpers, search/copy, path split/make,
 * formatted output/input, jump buffers and stack probing. Only success paths and non-reporting
 * edge cases are used: the bounded "_s" functions call an invalid-parameter routine that does not
 * return on bad arguments, so those paths are never exercised. See EVIDENCE.md. */
#include "t.h"
#include <stdint.h>

typedef long long i64;
typedef unsigned long long u64;

UDECL(char *, _itoa, (long, char *, int));
UDECL(char *, _ltoa, (long, char *, int));
UDECL(char *, _i64toa, (i64, char *, int));
UDECL(char *, _ui64toa, (u64, char *, int));
UDECL(WCHAR *, _itow, (long, WCHAR *, int));
UDECL(WCHAR *, _ltow, (long, WCHAR *, int));
UDECL(WCHAR *, _i64tow, (i64, WCHAR *, int));
UDECL(WCHAR *, _ui64tow, (u64, WCHAR *, int));
UDECL(int, _itoa_s, (long, char *, size_t, int));
UDECL(int, _ltoa_s, (long, char *, size_t, int));
UDECL(int, _i64toa_s, (i64, char *, size_t, int));
UDECL(int, _ui64toa_s, (u64, char *, size_t, int));
UDECL(int, _itow_s, (long, WCHAR *, size_t, int));
UDECL(int, _ltow_s, (long, WCHAR *, size_t, int));
UDECL(int, _i64tow_s, (i64, WCHAR *, size_t, int));
UDECL(int, _ui64tow_s, (u64, WCHAR *, size_t, int));
UDECL(i64, _atoi64, (const char *));
UDECL(int *, _errno, (void));
UDECL(int, __isascii, (int));
UDECL(int, __toascii, (int));
UDECL(int, __iscsym, (int));
UDECL(int, __iscsymf, (int));
UDECL(void *, _lfind, (const void *, const void *, unsigned *, unsigned, int (__cdecl *)(const void *, const void *)));
UDECL(void *, _memccpy, (void *, const void *, int, size_t));
UDECL(int, _memicmp, (const void *, const void *, size_t));
UDECL(int, _strcmpi, (const char *, const char *));
UDECL(int, _strnicmp, (const char *, const char *, size_t));
UDECL(char *, _strlwr, (char *));
UDECL(char *, _strupr, (char *));
UDECL(int, _strlwr_s, (char *, size_t));
UDECL(int, _strupr_s, (char *, size_t));
UDECL(int, _strset_s, (char *, size_t, int));
UDECL(int, _strnset_s, (char *, size_t, int, size_t));
UDECL(int, _makepath_s, (char *, size_t, const char *, const char *, const char *, const char *));
UDECL(void, _splitpath, (const char *, char *, char *, char *, char *));
UDECL(int, _splitpath_s, (const char *, char *, size_t, char *, size_t, char *, size_t, char *, size_t));
UDECL(int, _snprintf, (char *, size_t, const char *, ...));
UDECL(int, _snprintf_s, (char *, size_t, size_t, const char *, ...));
UDECL(int, _snwprintf, (WCHAR *, size_t, const WCHAR *, ...));
UDECL(int, _snwprintf_s, (WCHAR *, size_t, size_t, const WCHAR *, ...));
UDECL(int, _swprintf, (WCHAR *, const WCHAR *, ...));
UDECL(int, _snscanf_s, (const char *, size_t, const char *, ...));
UDECL(int, _snwscanf_s, (const WCHAR *, size_t, const WCHAR *, ...));
UDECL(int, _setjmp, (void *, void *));
UDECL(int, _setjmpex, (void *, void *));

#define TRUNC ((size_t)-1)

/* -------------------------------------------------- integer -> string */
static void wide_to_narrow(const WCHAR *w, char *out, size_t cap) {
    size_t i = 0;
    for (; w[i] && i + 1 < cap; i++) out[i] = (char)w[i];
    out[i] = 0;
}

TEST(itoa_ltoa) {
    REQUIRE(UN(_itoa)); REQUIRE(UN(_ltoa));
    char b[80];
    static const struct { long v; int r; const char *s; } c[] = {
        { 0, 10, "0" }, { 7, 10, "7" }, { 12345, 10, "12345" }, { -12345, 10, "-12345" },
        { 255, 16, "ff" }, { 255, 2, "11111111" }, { -1, 16, "ffffffff" }, { -1, 2, "11111111111111111111111111111111" },
        { 35, 36, "z" }, { 1295, 36, "zz" }, { -8, 8, "37777777770" }, { 0x7fffffff, 10, "2147483647" },
        { (long)0x80000000u, 10, "-2147483648" }, { 8, 8, "10" }, { 31, 32, "v" },
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        memset(b, 0x5a, sizeof b);
        EXPECT_EQ(UN(_itoa)(c[i].v, b, c[i].r), b);
        EXPECT_STR(b, c[i].s);
        memset(b, 0x5a, sizeof b);
        EXPECT_EQ(UN(_ltoa)(c[i].v, b, c[i].r), b);
        EXPECT_STR(b, c[i].s);
    }
    /* exact-size write: terminator lands right after the digits and nothing beyond */
    memset(b, 0x5a, sizeof b); UN(_itoa)(42, b + 1, 10);
    EXPECT_EQ(b[0], 0x5a); EXPECT_EQ(b[4], 0x5a);
    EXPECT_EQ(t_proc("_itoa") == t_proc("_ltoa"), 1);
}

TEST(i64toa_ui64toa) {
    REQUIRE(UN(_i64toa)); REQUIRE(UN(_ui64toa));
    char b[96];
    EXPECT_EQ(UN(_i64toa)(0, b, 10), b); EXPECT_STR(b, "0");
    UN(_i64toa)(-9223372036854775807LL - 1, b, 10); EXPECT_STR(b, "-9223372036854775808");
    UN(_i64toa)(9223372036854775807LL, b, 10); EXPECT_STR(b, "9223372036854775807");
    UN(_i64toa)(-1, b, 16); EXPECT_STR(b, "ffffffffffffffff");
    UN(_i64toa)(-42, b, 10); EXPECT_STR(b, "-42");
    UN(_i64toa)(0x123456789abcdefLL, b, 16); EXPECT_STR(b, "123456789abcdef");
    UN(_i64toa)(5, b, 2); EXPECT_STR(b, "101");
    EXPECT_EQ(UN(_ui64toa)(~0ULL, b, 10), b); EXPECT_STR(b, "18446744073709551615");
    UN(_ui64toa)(~0ULL, b, 16); EXPECT_STR(b, "ffffffffffffffff");
    UN(_ui64toa)(0, b, 10); EXPECT_STR(b, "0");
    UN(_ui64toa)(1ULL << 63, b, 10); EXPECT_STR(b, "9223372036854775808");
    UN(_ui64toa)(35, b, 36); EXPECT_STR(b, "z");
}

TEST(itow_family) {
    REQUIRE(UN(_itow)); REQUIRE(UN(_ltow)); REQUIRE(UN(_i64tow)); REQUIRE(UN(_ui64tow));
    WCHAR w[96]; char n[96];
    EXPECT_EQ(UN(_itow)(-12345, w, 10), w); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "-12345");
    EXPECT_EQ(UN(_ltow)(255, w, 16), w); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "ff");
    UN(_itow)(-1, w, 16); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "ffffffff");
    UN(_itow)(0, w, 10); EXPECT_EQ(w[0], '0'); EXPECT_EQ(w[1], 0);
    UN(_i64tow)(-9223372036854775807LL - 1, w, 10); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "-9223372036854775808");
    UN(_i64tow)(-1, w, 2); wide_to_narrow(w, n, sizeof n); EXPECT_EQ(strlen(n), 64); EXPECT_EQ(n[0], '1');
    EXPECT_EQ(UN(_ui64tow)(~0ULL, w, 10), w); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "18446744073709551615");
    UN(_ui64tow)(0xdeadbeefULL, w, 16); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "deadbeef");
    EXPECT_EQ(t_proc("_itow") == t_proc("_ltow"), 1);
}

TEST(itoa_s_family) {
    REQUIRE(UN(_itoa_s)); REQUIRE(UN(_ltoa_s)); REQUIRE(UN(_i64toa_s)); REQUIRE(UN(_ui64toa_s));
    char b[40]; memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_itoa_s)(-1234, b, sizeof b, 10), 0); EXPECT_STR(b, "-1234");
    /* buffer of exactly strlen+1 succeeds */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_itoa_s)(-1234, b, 6, 10), 0); EXPECT_STR(b, "-1234"); EXPECT_EQ(b[6], 0x5a);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_itoa_s)(255, b, 3 + 1, 16), 0); EXPECT_STR(b, "ff");
    EXPECT_EQ(UN(_ltoa_s)(-1, b, sizeof b, 16), 0); EXPECT_STR(b, "ffffffff");
    EXPECT_EQ(UN(_ltoa_s)(0, b, 2, 10), 0); EXPECT_STR(b, "0");
    EXPECT_EQ(UN(_i64toa_s)(-9223372036854775807LL - 1, b, sizeof b, 10), 0); EXPECT_STR(b, "-9223372036854775808");
    EXPECT_EQ(UN(_i64toa_s)(-1, b, sizeof b, 16), 0); EXPECT_STR(b, "ffffffffffffffff");
    EXPECT_EQ(UN(_ui64toa_s)(~0ULL, b, sizeof b, 10), 0); EXPECT_STR(b, "18446744073709551615");
    EXPECT_EQ(UN(_ui64toa_s)(1000, b, 5, 10), 0); EXPECT_STR(b, "1000");
    EXPECT_EQ(t_proc("_itoa_s") == t_proc("_ltoa_s"), 1);
}

TEST(itow_s_family) {
    REQUIRE(UN(_itow_s)); REQUIRE(UN(_ltow_s)); REQUIRE(UN(_i64tow_s)); REQUIRE(UN(_ui64tow_s));
    WCHAR w[40]; char n[40];
    EXPECT_EQ(UN(_itow_s)(-1234, w, 40, 10), 0); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "-1234");
    EXPECT_EQ(UN(_itow_s)(-1234, w, 6, 10), 0); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "-1234");
    EXPECT_EQ(UN(_ltow_s)(255, w, 40, 2), 0); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "11111111");
    EXPECT_EQ(UN(_i64tow_s)(-1, w, 40, 16), 0); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "ffffffffffffffff");
    EXPECT_EQ(UN(_ui64tow_s)(~0ULL, w, 40, 10), 0); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "18446744073709551615");
    EXPECT_EQ(UN(_ui64tow_s)(0, w, 2, 10), 0); EXPECT_EQ(w[0], '0'); EXPECT_EQ(w[1], 0);
}

TEST(atoi64) {
    REQUIRE(UN(_atoi64));
    EXPECT_EQ(UN(_atoi64)("0"), 0);
    EXPECT_EQ(UN(_atoi64)("123"), 123);
    EXPECT_EQ(UN(_atoi64)("-45"), -45);
    EXPECT_EQ(UN(_atoi64)("  \t+7"), 7);
    EXPECT_EQ(UN(_atoi64)("12abc"), 12);
    EXPECT_EQ(UN(_atoi64)("abc"), 0);
    EXPECT_EQ(UN(_atoi64)(""), 0);
    EXPECT_EQ(UN(_atoi64)("9223372036854775807"), 9223372036854775807LL);
    EXPECT_EQ(UN(_atoi64)("-9223372036854775808"), (u64)(-9223372036854775807LL - 1));
    EXPECT_EQ(UN(_atoi64)("4294967296"), 4294967296LL);
    EXPECT_EQ(UN(_atoi64)(NULL), 0);
}

/* ------------------------------------------------------------ _errno */
static DWORD WINAPI errno_thread(LPVOID p) { *(int **)p = UN(_errno)(); return 0; }
TEST(errno_ptr) {
    REQUIRE(UN(_errno));
    int *e = UN(_errno)();
    CHECK(e != NULL);
    EXPECT_EQ(UN(_errno)(), e);
    int old = *e; *e = 0x1234; EXPECT_EQ(*UN(_errno)(), 0x1234); *e = old;
    /* per-thread storage inside the TEB */
    EXPECT_EQ((char *)e, (char *)NtCurrentTeb() + 0x1500);
    int *other = NULL; HANDLE h = CreateThread(NULL, 0, errno_thread, &other, 0, NULL);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0); CloseHandle(h); CHECK(other != NULL && other != e); }
}

/* ------------------------------------------------------------- ctype */
TEST(ctype_helpers) {
    REQUIRE(UN(__isascii)); REQUIRE(UN(__toascii)); REQUIRE(UN(__iscsym)); REQUIRE(UN(__iscsymf));
    for (int c = 0; c < 128; c++) {
        int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        int digit = c >= '0' && c <= '9';
        EXPECT_EQ(!!UN(__isascii)(c), 1);
        EXPECT_EQ(UN(__toascii)(c), c);
        EXPECT_EQ(!!UN(__iscsym)(c), alpha || digit || c == '_');
        EXPECT_EQ(!!UN(__iscsymf)(c), alpha || c == '_');
    }
    for (int c = 128; c < 256; c++) {
        EXPECT_EQ(UN(__isascii)(c), 0);
        EXPECT_EQ(UN(__toascii)(c), c & 0x7f);
    }
    EXPECT_EQ(UN(__isascii)(0x100), 0);
    EXPECT_EQ(UN(__toascii)(0x1ff), 0x7f);
    EXPECT_EQ(UN(__isascii)(-1), 0);
}

/* --------------------------------------------------------- search/copy */
static int __cdecl cmp_int(const void *a, const void *b) { return *(const int *)a != *(const int *)b; }
TEST(lfind) {
    REQUIRE(UN(_lfind));
    int a[] = { 5, 9, 2, 9, 7 }; unsigned n = 5; int key;
    key = 2; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), &a[2]);
    key = 9; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), &a[1]); /* first match */
    key = 5; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), &a[0]);
    key = 7; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), &a[4]);
    key = 8; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), NULL);
    n = 2; key = 2; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), NULL); /* count honoured */
    EXPECT_EQ(n, 2); /* _lfind does not modify the count */
    n = 0; key = 5; EXPECT_EQ(UN(_lfind)(&key, a, &n, sizeof(int), cmp_int), NULL);
    n = 0; EXPECT_EQ(UN(_lfind)(&key, NULL, &n, sizeof(int), cmp_int), NULL); /* empty table with NULL base is valid */
}

TEST(memccpy) {
    REQUIRE(UN(_memccpy));
    char d[16]; const char s[] = "abcXdef";
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(_memccpy)(d, s, 'X', 7), d + 4);
    EXPECT_EQ(memcmp(d, "abcX", 4), 0); EXPECT_EQ(d[4], 0x5a);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(_memccpy)(d, s, 'q', 7), NULL);          /* not found: whole count copied */
    EXPECT_EQ(memcmp(d, s, 7), 0); EXPECT_EQ(d[7], 0x5a);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(_memccpy)(d, s, 'a', 7), d + 1);
    EXPECT_EQ(d[0], 'a'); EXPECT_EQ(d[1], 0x5a);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(_memccpy)(d, s, 'X', 3), NULL);          /* match beyond count */
    EXPECT_EQ(memcmp(d, "abc", 3), 0); EXPECT_EQ(d[3], 0x5a);
    EXPECT_EQ(UN(_memccpy)(d, s, 'a', 0), NULL);
    memset(d, 0x5a, sizeof d);
    EXPECT_EQ(UN(_memccpy)(d, s, 'f', 7), d + 7);         /* match at the last byte */
    EXPECT_EQ(UN(_memccpy)(d, s, 0x158, 7), d + 4);       /* only the low byte (0x58 = 'X') of the value counts */
}

TEST(memicmp_strcmpi) {
    REQUIRE(UN(_memicmp)); REQUIRE(UN(_strcmpi)); REQUIRE(UN(_strnicmp));
    EXPECT_EQ(UN(_memicmp)("AbC", "aBc", 3), 0);
    CHECK(UN(_memicmp)("abc", "abd", 3) < 0);
    CHECK(UN(_memicmp)("abd", "ABC", 3) > 0);
    EXPECT_EQ(UN(_memicmp)("abc", "abd", 2), 0);
    EXPECT_EQ(UN(_memicmp)("abc", "xyz", 0), 0);
    EXPECT_EQ(UN(_memicmp)("a\0b", "A\0B", 3), 0); /* embedded zero does not stop it */
    CHECK(UN(_memicmp)("[", "a", 1) < 0);   /* '[' (0x5b) < 'a' (0x61) ; no upper-folding of punctuation */
    CHECK(UN(_memicmp)("_", "A", 1) < 0);   /* letters fold to lower case: '_' (0x5f) < 'a' (0x61) */

    EXPECT_EQ(UN(_strcmpi)("Hello", "hELLO"), 0);
    EXPECT_EQ(UN(_strcmpi)("", ""), 0);
    CHECK(UN(_strcmpi)("abc", "abcd") < 0);
    CHECK(UN(_strcmpi)("abd", "ABC") > 0);
    CHECK(UN(_strcmpi)("a", "") > 0);

    EXPECT_EQ(UN(_strnicmp)("HELLO world", "hello WORLD", 5), 0);
    EXPECT_EQ(UN(_strnicmp)("HELLO world", "hello WORLD", 11), 0);
    CHECK(UN(_strnicmp)("abcX", "ABCy", 4) < 0);
    EXPECT_EQ(UN(_strnicmp)("abcX", "ABCy", 3), 0);
    EXPECT_EQ(UN(_strnicmp)("abc", "xyz", 0), 0);
    EXPECT_EQ(UN(_strnicmp)("ab", "AB", 100), 0); /* stops at the terminator */
}

/* -------------------------------------------------- case / set (string) */
TEST(strlwr_strupr) {
    REQUIRE(UN(_strlwr)); REQUIRE(UN(_strupr));
    char b[32];
    strcpy(b, "Hello, World_123 [@`{"); EXPECT_EQ(UN(_strlwr)(b), b); EXPECT_STR(b, "hello, world_123 [@`{");
    strcpy(b, "Hello, World_123 [@`{"); EXPECT_EQ(UN(_strupr)(b), b); EXPECT_STR(b, "HELLO, WORLD_123 [@`{");
    b[0] = 0; EXPECT_EQ(UN(_strupr)(b), b); EXPECT_EQ(b[0], 0);
}

TEST(strlwr_strupr_s) {
    REQUIRE(UN(_strlwr_s)); REQUIRE(UN(_strupr_s));
    char b[32]; memset(b, 0x5a, sizeof b);
    strcpy(b, "MiXeD 09 az AZ");
    EXPECT_EQ(UN(_strlwr_s)(b, sizeof b), 0); EXPECT_STR(b, "mixed 09 az az");
    EXPECT_EQ(UN(_strupr_s)(b, sizeof b), 0); EXPECT_STR(b, "MIXED 09 AZ AZ");
    /* size equal to strlen+1 is sufficient, and bytes >= 0x80 are left alone */
    memset(b, 0x5a, sizeof b); strcpy(b, "ab\xe9z");
    EXPECT_EQ(UN(_strupr_s)(b, 5), 0); EXPECT_EQ((unsigned char)b[2], 0xe9); EXPECT_EQ(b[0], 'A'); EXPECT_EQ(b[3], 'Z'); EXPECT_EQ(b[5], 0x5a);
    strcpy(b, "ab\xc9z");
    EXPECT_EQ(UN(_strlwr_s)(b, 5), 0); EXPECT_EQ((unsigned char)b[2], 0xc9); EXPECT_EQ(b[3], 'z');
    b[0] = 0; EXPECT_EQ(UN(_strlwr_s)(b, 1), 0);
}

TEST(strset_strnset_s) {
    REQUIRE(UN(_strset_s)); REQUIRE(UN(_strnset_s));
    char b[16];
    memset(b, 0x5a, sizeof b); strcpy(b, "abcd");
    EXPECT_EQ(UN(_strset_s)(b, 5, '*'), 0); EXPECT_STR(b, "****"); EXPECT_EQ(b[5], 0x5a);
    memset(b, 0x5a, sizeof b); strcpy(b, "abcd");
    EXPECT_EQ(UN(_strset_s)(b, sizeof b, 'x' + 0x100), 0); EXPECT_STR(b, "xxxx"); /* only the low byte is used */
    b[0] = 0; EXPECT_EQ(UN(_strset_s)(b, 1, 'q'), 0); EXPECT_EQ(b[0], 0);

    memset(b, 0x5a, sizeof b); strcpy(b, "abcdef");
    EXPECT_EQ(UN(_strnset_s)(b, 7, '-', 3), 0); EXPECT_STR(b, "---def");
    memset(b, 0x5a, sizeof b); strcpy(b, "abc");
    EXPECT_EQ(UN(_strnset_s)(b, 4, '-', 10), 0); EXPECT_STR(b, "---");     /* count beyond the string */
    memset(b, 0x5a, sizeof b); strcpy(b, "abc");
    EXPECT_EQ(UN(_strnset_s)(b, 4, '-', 0), 0); EXPECT_STR(b, "abc");      /* zero count */
    EXPECT_EQ(UN(_strnset_s)(NULL, 0, '-', 0), 0);                          /* empty request with NULL is valid */
}

/* ------------------------------------------------------ makepath/splitpath */
TEST(makepath_s) {
    REQUIRE(UN(_makepath_s));
    char b[64]; memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, "C", "\\dir\\sub", "file", "txt"), 0); EXPECT_STR(b, "C:\\dir\\sub\\file.txt");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, "D:", "dir/", "name", ".ext"), 0); EXPECT_STR(b, "D:dir/name.ext");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, NULL, "dir", "name", NULL), 0); EXPECT_STR(b, "dir\\name");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, "", "", "name", ""), 0); EXPECT_STR(b, "name");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, NULL, NULL, NULL, NULL), 0); EXPECT_STR(b, "");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, NULL, NULL, NULL, "e"), 0); EXPECT_STR(b, ".e");
    EXPECT_EQ(UN(_makepath_s)(b, sizeof b, "Z", NULL, "f", NULL), 0); EXPECT_STR(b, "Z:f");
    /* exact fit: "a\b.c" is 5 characters */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_makepath_s)(b, 6, NULL, "a", "b", "c"), 0); EXPECT_STR(b, "a\\b.c"); EXPECT_EQ(b[6], 0x5a);
}

TEST(splitpath) {
    REQUIRE(UN(_splitpath));
    char dr[16], di[300], fn[300], ex[300];
    memset(dr, 0x5a, sizeof dr);
    UN(_splitpath)("C:\\dir\\sub\\file.tar.gz", dr, di, fn, ex);
    EXPECT_STR(dr, "C:"); EXPECT_STR(di, "\\dir\\sub\\"); EXPECT_STR(fn, "file.tar"); EXPECT_STR(ex, ".gz");
    UN(_splitpath)("/usr/lib/name", dr, di, fn, ex);
    EXPECT_STR(dr, ""); EXPECT_STR(di, "/usr/lib/"); EXPECT_STR(fn, "name"); EXPECT_STR(ex, "");
    UN(_splitpath)("name.e", dr, di, fn, ex);
    EXPECT_STR(dr, ""); EXPECT_STR(di, ""); EXPECT_STR(fn, "name"); EXPECT_STR(ex, ".e");
    UN(_splitpath)("D:rel\\x", dr, di, fn, ex);
    EXPECT_STR(dr, "D:"); EXPECT_STR(di, "rel\\"); EXPECT_STR(fn, "x"); EXPECT_STR(ex, "");
    UN(_splitpath)("", dr, di, fn, ex);
    EXPECT_STR(dr, ""); EXPECT_STR(di, ""); EXPECT_STR(fn, ""); EXPECT_STR(ex, "");
    UN(_splitpath)("C:\\a\\b.c", NULL, di, NULL, ex);   /* NULL outputs are skipped */
    EXPECT_STR(di, "\\a\\"); EXPECT_STR(ex, ".c");
    UN(_splitpath)("dir\\.hidden", dr, di, fn, ex);
    EXPECT_STR(di, "dir\\"); EXPECT_STR(fn, ""); EXPECT_STR(ex, ".hidden");
}

TEST(splitpath_s) {
    REQUIRE(UN(_splitpath_s));
    char dr[3], di[64], fn[64], ex[16];
    EXPECT_EQ(UN(_splitpath_s)("C:\\dir\\sub\\file.tar.gz", dr, 3, di, 64, fn, 64, ex, 16), 0);
    EXPECT_STR(dr, "C:"); EXPECT_STR(di, "\\dir\\sub\\"); EXPECT_STR(fn, "file.tar"); EXPECT_STR(ex, ".gz");
    EXPECT_EQ(UN(_splitpath_s)("name", dr, 3, di, 64, fn, 64, ex, 16), 0);
    EXPECT_STR(dr, ""); EXPECT_STR(di, ""); EXPECT_STR(fn, "name"); EXPECT_STR(ex, "");
    /* exactly-sized buffers: "\d\" needs 4, ".gz" needs 4, "file" needs 5 */
    char d4[4], f5[5], e4[4];
    EXPECT_EQ(UN(_splitpath_s)("\\d\\file.gz", NULL, 0, d4, 4, f5, 5, e4, 4), 0);
    EXPECT_STR(d4, "\\d\\"); EXPECT_STR(f5, "file"); EXPECT_STR(e4, ".gz");
    EXPECT_EQ(UN(_splitpath_s)("a\\b.c", NULL, 0, NULL, 0, fn, 64, NULL, 0), 0);
    EXPECT_STR(fn, "b");
}

/* ------------------------------------------------------------- printf */
TEST(snprintf) {
    REQUIRE(UN(_snprintf));
    char b[32]; memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, sizeof b, "%d|%s|%x|%c", -42, "ab", 0xbeef, 'Z'), 13); EXPECT_STR(b, "-42|ab|beef|Z");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, 5, "%s", "abcdef"), -1);       /* truncated, no terminator */
    EXPECT_EQ(memcmp(b, "abcde", 5), 0);
    EXPECT_EQ(b[5], 0x5a);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, 5, "%s", "abcde"), 5);         /* exact fit: count returned, no terminator */
    EXPECT_EQ(b[5], 0x5a);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, 5, "%s", "abcd"), 4); EXPECT_STR(b, "abcd");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, 4, "%s", "abcd"), 4);          /* exact fit: count returned, no terminator */
    EXPECT_EQ(memcmp(b, "abcd", 4), 0); EXPECT_EQ(b[4], 0x5a);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf)(b, 0, "%s", "abcd"), -1); EXPECT_EQ(b[0], 0x5a);
    EXPECT_EQ(UN(_snprintf)(b, sizeof b, "%08d|%-4d|%+d|%5s|%-3c", 314, 7, 5, "ab", 'q'), 8 + 1 + 4 + 1 + 2 + 1 + 5 + 1 + 3); EXPECT_STR(b, "00000314|7   |+5|   ab|q  ");
    EXPECT_EQ(UN(_snprintf)(b, sizeof b, "%I64d|%llu", -5LL, 7ULL), 4); EXPECT_STR(b, "-5|7");
}

TEST(snprintf_s) {
    REQUIRE(UN(_snprintf_s));
    char b[32]; memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf_s)(b, sizeof b, sizeof b - 1, "%d-%s", 12, "xy"), 5); EXPECT_STR(b, "12-xy");
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf_s)(b, 5, 4, "%s", "abcd"), 4); EXPECT_STR(b, "abcd");          /* fits exactly */
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf_s)(b, 8, TRUNC, "%s", "abcdefghij"), -1);                       /* _TRUNCATE: truncated, terminated */
    EXPECT_EQ(memcmp(b, "abcdefg", 7), 0); EXPECT_EQ(b[7], 0);
    memset(b, 0x5a, sizeof b);
    EXPECT_EQ(UN(_snprintf_s)(b, 16, 3, "%s", "abcdef"), -1);                              /* count limit hit */
    EXPECT_STR(b, "abc");
    EXPECT_EQ(UN(_snprintf_s)(NULL, 0, 0, "x"), 0);                                        /* empty request, NULL buffer */
}

TEST(snwprintf) {
    REQUIRE(UN(_snwprintf)); REQUIRE(UN(_snwprintf_s)); REQUIRE(UN(_swprintf));
    WCHAR w[32]; char n[64];
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_snwprintf)(w, 32, L"%d|%x|%c|%ls", -42, 0xbeef, L'Z', L"ab"), 13); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "-42|beef|Z|ab");
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_snwprintf)(w, 3, L"%ls", L"abcd"), -1); EXPECT_EQ(w[0], 'a'); EXPECT_EQ(w[2], 'c'); EXPECT_EQ(w[3], 0x5a5a);
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_snwprintf)(w, 4, L"%ls", L"abcd"), 4); EXPECT_EQ(w[3], 'd'); EXPECT_EQ(w[4], 0x5a5a);

    EXPECT_EQ(UN(_snwprintf_s)(w, 32, 31, L"%d-%ls", 12, L"xy"), 5); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "12-xy");
    for (int i = 0; i < 32; i++) w[i] = 0x5a5a;
    EXPECT_EQ(UN(_snwprintf_s)(w, 4, TRUNC, L"%ls", L"abcdef"), -1); EXPECT_EQ(w[2], 'c'); EXPECT_EQ(w[3], 0);
    EXPECT_EQ(UN(_snwprintf_s)(w, 16, 2, L"%ls", L"abcdef"), -1); EXPECT_EQ(w[0], 'a'); EXPECT_EQ(w[1], 'b'); EXPECT_EQ(w[2], 0);

    EXPECT_EQ(UN(_swprintf)(w, L"[%5d][%-3ls]", 42, L"z"), 12); wide_to_narrow(w, n, sizeof n); EXPECT_STR(n, "[   42][z  ]");
    EXPECT_EQ(w[12], 0);
}

/* -------------------------------------------------------------- scanf */
TEST(snscanf_s) {
    REQUIRE(UN(_snscanf_s));
    int i = -1, j = -1; char s[16] = "";
    EXPECT_EQ(UN(_snscanf_s)("123 abc", 7, "%d %s", &i, s, (unsigned)sizeof s), 2); EXPECT_EQ(i, 123); EXPECT_STR(s, "abc");
    i = -1; EXPECT_EQ(UN(_snscanf_s)("12345", 3, "%d", &i), 1); EXPECT_EQ(i, 123);   /* count limits input */
    i = -1; j = -1; EXPECT_EQ(UN(_snscanf_s)("ff 10", 5, "%x %d", &i, &j), 2); EXPECT_EQ(i, 0xff); EXPECT_EQ(j, 10);
    i = -1; EXPECT_EQ(UN(_snscanf_s)("abc", 3, "%d", &i), 0); EXPECT_EQ(i, -1);       /* matching failure */
    i = -1; EXPECT_EQ(UN(_snscanf_s)("", 0, "%d", &i), -1); EXPECT_EQ(i, -1);         /* input exhausted */
    i = -1; j = -1; EXPECT_EQ(UN(_snscanf_s)("7 x", 3, "%d %d", &i, &j), 1); EXPECT_EQ(i, 7); EXPECT_EQ(j, -1);
}

TEST(snwscanf_s) {
    REQUIRE(UN(_snwscanf_s));
    int i = -1, j = -1;
    EXPECT_EQ(UN(_snwscanf_s)(L"123 45", 6, L"%d %d", &i, &j), 2); EXPECT_EQ(i, 123); EXPECT_EQ(j, 45);
    i = -1; EXPECT_EQ(UN(_snwscanf_s)(L"12345", 3, L"%d", &i), 1); EXPECT_EQ(i, 123);
    i = -1; EXPECT_EQ(UN(_snwscanf_s)(L"zz", 2, L"%d", &i), 0); EXPECT_EQ(i, -1);
    i = -1; EXPECT_EQ(UN(_snwscanf_s)(L"", 0, L"%d", &i), 0); EXPECT_EQ(i, -1);   /* observed: the wide reader reports 0, not EOF, for empty input */
    WCHAR w[8] = { 0 };
    EXPECT_EQ(UN(_snwscanf_s)(L"ab cd", 5, L"%ls", w, (unsigned)8), 1); EXPECT_EQ(w[0], 'a'); EXPECT_EQ(w[1], 'b'); EXPECT_EQ(w[2], 0);
}

/* ------------------------------------------------------ setjmp / chkstk */
static int in_self_image(ULONG_PTR p) {
    char *base = (char *)GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    return p >= (ULONG_PTR)base && p < (ULONG_PTR)base + nt->OptionalHeader.SizeOfImage;
}
/* _JUMP_BUFFER (x64): Frame, Rbx, Rsp, Rbp, Rsi, Rdi, R12..R15, Rip (8 bytes each), MxCsr(4), FpCsr(2) */
static int jb_check(ULONG64 *jb, ULONG64 frame, int check_frame) {
    char local; int bad = 0;
    if (check_frame && jb[0] != frame) bad |= 1;
    if (jb[2] < (ULONG64)(ULONG_PTR)&local - 0x2000 || jb[2] > (ULONG64)(ULONG_PTR)&local + 0x2000) bad |= 2;
    if (!in_self_image((ULONG_PTR)jb[10])) bad |= 4;
    return bad;
}
TEST(setjmp_buffers) {
    REQUIRE(UN(_setjmp)); REQUIRE(UN(_setjmpex));
    ULONG64 jb[32]; memset(jb, 0xcc, sizeof jb);
    volatile int r = UN(_setjmpex)(jb, (void *)(ULONG_PTR)0x1122334455667788ULL);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(jb_check(jb, 0x1122334455667788ULL, 1), 0);
    ULONG mxcsr; __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
    EXPECT_EQ(*(ULONG *)&jb[11], mxcsr);
    USHORT fcw; __asm__ volatile("fnstcw %0" : "=m"(fcw));
    EXPECT_EQ(*(USHORT *)((char *)jb + 0x5c), fcw);
    EXPECT_EQ(jb[12] != 0xcccccccccccccccc || jb[13] != 0xcccccccccccccccc, 1); /* XMM6 slot written */

    memset(jb, 0xcc, sizeof jb);
    r = UN(_setjmp)(jb, (void *)(ULONG_PTR)0x0badf00d);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(jb_check(jb, 0x0badf00d, 1), 0);   /* the second argument is stored as the frame */
    EXPECT_EQ(*(ULONG *)&jb[11], mxcsr);
}

TEST(chkstk_probe) {
    REQUIRE(t_proc("__chkstk"));
    void *fn = (void *)t_proc("__chkstk");
    ULONG_PTR rax_out = 0, sp_before = 0, sp_after = 0, sz = 0x9000;
    /* custom ABI: rax = frame size; rsp is unchanged, rax is preserved, r10/r11 are clobbered */
    __asm__ volatile(
        "mov %%rsp, %%r12\n\t"
        "and $-16, %%rsp\n\t"
        "sub $32, %%rsp\n\t"
        "mov %%rsp, %%r13\n\t"
        "mov %[sz], %%rax\n\t"
        "call *%[fn]\n\t"
        "mov %%rsp, %%r14\n\t"
        "mov %%rax, %%r15\n\t"
        "mov %%r12, %%rsp\n\t"
        "mov %%r13, %[sb]\n\t"
        "mov %%r14, %[sa]\n\t"
        "mov %%r15, %[ro]\n\t"
        : [sb] "=r"(sp_before), [sa] "=r"(sp_after), [ro] "=r"(rax_out)
        : [fn] "r"(fn), [sz] "r"(sz)
        : "rax", "r10", "r11", "r12", "r13", "r14", "r15", "memory", "cc");
    EXPECT_EQ(sp_after, sp_before);
    EXPECT_EQ(rax_out, sz);
}
