#include "t.h"
#include <wchar.h>

#define C_TEXT(x) x
#define W_TEXT(x) L##x
#define LOAD(fn) __typeof__(&fn) f = UIN("ntdll.dll", fn); REQUIRE(f)
#define ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))
#define FILL(a, value) do { size_t j_; for (j_ = 0; j_ < ELEMENTS(a); ++j_) (a)[j_] = (value); } while (0)
#define SAME(a, b, n) do { size_t j_; for (j_ = 0; j_ < (n); ++j_) EXPECT_EQ((a)[j_], (b)[j_]); } while (0)

/* the reference uses element comparisons, never another CRT string export. */
#define LEN_CASE(fn, T, Q, id, text, expected) \
    TEST(crt_strings_##fn##_##id) { \
        T s[96] = Q(text); LOAD(fn); EXPECT_EQ(f(s), expected); \
    }
#define NLEN_CASE(fn, T, Q, id, text, count, expected) \
    TEST(crt_strings_##fn##_##id) { \
        T s[96] = Q(text); LOAD(fn); EXPECT_EQ(f(s, count), expected); \
    }
#define COPY_CASE(fn, T, Q, id, text) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q(text), out[128], expected[] = Q(text); size_t n = 0; \
        while (expected[n]) { ++n; } \
        ++n; \
        LOAD(fn); FILL(out, 0x5a); CHECK(f(out + 1, src) == out + 1); \
        SAME(out + 1, expected, n); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[n + 1], 0x5a); \
        SAME(src, expected, ELEMENTS(expected)); \
    }
#define NCOPY_CASE(fn, T, Q, id, text, count, bytes) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q(text), out[128], expected[] = Q(bytes); \
        LOAD(fn); FILL(out, 0x5a); CHECK(f(out + 1, src, count) == out + 1); \
        SAME(out + 1, expected, (size_t)(count)); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[(count) + 1], 0x5a); \
    }
#define CAT_CASE(fn, T, Q, id, initial, text, result) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q(text), seed[] = Q(initial), out[128], expected[] = Q(result); \
        LOAD(fn); FILL(out, 0x5a); \
        { size_t i; for (i = 0; i < ELEMENTS(seed); ++i) out[i + 1] = seed[i]; } \
        CHECK(f(out + 1, src) == out + 1); SAME(out + 1, expected, ELEMENTS(expected)); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[ELEMENTS(expected) + 1], 0x5a); \
    }
#define NCAT_CASE(fn, T, Q, id, count, result) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q("cdef"), out[128], expected[] = Q(result); \
        LOAD(fn); FILL(out, 0x5a); out[1] = 'a'; out[2] = 'b'; out[3] = 0; \
        CHECK(f(out + 1, src, count) == out + 1); SAME(out + 1, expected, ELEMENTS(expected)); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[ELEMENTS(expected) + 1], 0x5a); \
    }
#define CMP_CASE(fn, T, Q, id, left, right, sign) \
    TEST(crt_strings_##fn##_##id) { \
        T a[96] = Q(left), b[96] = Q(right); int r; LOAD(fn); r = f(a, b); \
        EXPECT_EQ((r > 0) - (r < 0), sign); \
    }
#define NCMP_CASE(fn, T, Q, id, left, right, count, sign) \
    TEST(crt_strings_##fn##_##id) { \
        T a[96] = Q(left), b[96] = Q(right); int r; LOAD(fn); r = f(a, b, count); \
        EXPECT_EQ((r > 0) - (r < 0), sign); \
    }
#define CHAR_CASE(fn, T, Q, id, text, ch, offset) \
    TEST(crt_strings_##fn##_##id) { \
        T s[96] = Q(text); T *expected = (offset) < 0 ? NULL : s + (offset); \
        LOAD(fn); CHECK(f(s, ch) == expected); \
    }
#define FIND_CASE(fn, T, Q, id, text, needle, offset) \
    TEST(crt_strings_##fn##_##id) { \
        T s[96] = Q(text), control[96] = Q(needle); \
        T *expected = (offset) < 0 ? NULL : s + (offset), *actual; \
        LOAD(fn); actual = f(s, control); \
        CHECKF(actual == expected, "got %p want %p; haystack %p control %p", actual, expected, s, control); \
    }
#define SPAN_CASE(fn, T, Q, id, text, control, expected) \
    TEST(crt_strings_##fn##_##id) { \
        T s[96] = Q(text), set[96] = Q(control); LOAD(fn); EXPECT_EQ(f(s, set), expected); \
    }

#define LENGTHS(T, Q, len, nlen) \
    LEN_CASE(len, T, Q, empty, "", 0) \
    LEN_CASE(len, T, Q, one, "x", 1) \
    LEN_CASE(len, T, Q, word_boundary, "0123456789abcdef", 16) \
    LEN_CASE(len, T, Q, embedded_nul, "ab\0cd", 2) \
    NLEN_CASE(nlen, T, Q, zero, "abcdef", 0, 0) \
    NLEN_CASE(nlen, T, Q, one, "abcdef", 1, 1) \
    NLEN_CASE(nlen, T, Q, bounded, "abcdef", 3, 3) \
    NLEN_CASE(nlen, T, Q, exact, "abcdef", 6, 6) \
    NLEN_CASE(nlen, T, Q, includes_nul, "abcdef", 7, 6) \
    NLEN_CASE(nlen, T, Q, empty, "", 12, 0) \
    NLEN_CASE(nlen, T, Q, embedded_nul, "ab\0cd", 5, 2)

#define COPIES(T, Q, copy, ncopy, cat, ncat) \
    COPY_CASE(copy, T, Q, empty, "") \
    COPY_CASE(copy, T, Q, short, "abcd") \
    COPY_CASE(copy, T, Q, long, "0123456789abcdefghijklmnopqrstuvwxyz") \
    COPY_CASE(copy, T, Q, embedded_nul, "ab\0cd") \
    NCOPY_CASE(ncopy, T, Q, zero, "abcd", 0, "") \
    NCOPY_CASE(ncopy, T, Q, truncated, "abcdef", 3, "abc") \
    NCOPY_CASE(ncopy, T, Q, exact_unterminated, "abcd", 4, "abcd") \
    NCOPY_CASE(ncopy, T, Q, exact_terminated, "abcd", 5, "abcd") \
    NCOPY_CASE(ncopy, T, Q, padding, "ab", 8, "ab\0\0\0\0\0\0") \
    NCOPY_CASE(ncopy, T, Q, empty_padding, "", 4, "\0\0\0\0") \
    CAT_CASE(cat, T, Q, empty_destination, "", "abcd", "abcd") \
    CAT_CASE(cat, T, Q, empty_source, "ab", "", "ab") \
    CAT_CASE(cat, T, Q, append, "ab", "cdef", "abcdef") \
    CAT_CASE(cat, T, Q, long, "0123456789", "abcdefghijklmnopqrstuvwxyz", "0123456789abcdefghijklmnopqrstuvwxyz") \
    NCAT_CASE(ncat, T, Q, zero, 0, "ab") \
    NCAT_CASE(ncat, T, Q, one, 1, "abc") \
    NCAT_CASE(ncat, T, Q, truncated_terminated, 2, "abcd") \
    NCAT_CASE(ncat, T, Q, exact, 4, "abcdef") \
    NCAT_CASE(ncat, T, Q, past_nul, 12, "abcdef")

#define COMPARES(T, Q, cmp, ncmp, icmp) \
    CMP_CASE(cmp, T, Q, empty, "", "", 0) \
    CMP_CASE(cmp, T, Q, equal, "same", "same", 0) \
    CMP_CASE(cmp, T, Q, less, "abc", "abd", -1) \
    CMP_CASE(cmp, T, Q, greater, "abd", "abc", 1) \
    CMP_CASE(cmp, T, Q, prefix, "ab", "abc", -1) \
    CMP_CASE(cmp, T, Q, case_sensitive, "A", "a", -1) \
    CMP_CASE(cmp, T, Q, embedded_nul, "ab\0x", "ab\0y", 0) \
    NCMP_CASE(ncmp, T, Q, zero, "a", "z", 0, 0) \
    NCMP_CASE(ncmp, T, Q, equal_prefix, "abcx", "abcy", 3, 0) \
    NCMP_CASE(ncmp, T, Q, mismatch, "abcx", "abcy", 4, -1) \
    NCMP_CASE(ncmp, T, Q, greater, "abz", "abc", 3, 1) \
    NCMP_CASE(ncmp, T, Q, stop_at_nul, "ab\0x", "ab\0y", 5, 0) \
    CMP_CASE(icmp, T, Q, ascii_equal, "AbCz09", "aBcZ09", 0) \
    CMP_CASE(icmp, T, Q, ascii_less, "AbC", "aBD", -1) \
    CMP_CASE(icmp, T, Q, ascii_greater, "Z", "a", 1) \
    CMP_CASE(icmp, T, Q, punctuation, "[", "{", -1) \
    CMP_CASE(icmp, T, Q, prefix, "Ab", "aBC", -1)

#define SEARCHES(T, Q, chr, rchr, sub, span, cspan, pbrk) \
    CHAR_CASE(chr, T, Q, first, "abaca", 'a', 0) \
    CHAR_CASE(chr, T, Q, middle, "abaca", 'c', 3) \
    CHAR_CASE(chr, T, Q, missing, "abaca", 'x', -1) \
    CHAR_CASE(chr, T, Q, terminator, "abaca", 0, 5) \
    CHAR_CASE(chr, T, Q, empty, "", 0, 0) \
    CHAR_CASE(rchr, T, Q, last, "abaca", 'a', 4) \
    CHAR_CASE(rchr, T, Q, first_only, "abc", 'a', 0) \
    CHAR_CASE(rchr, T, Q, missing, "abc", 'x', -1) \
    CHAR_CASE(rchr, T, Q, terminator, "abc", 0, 3) \
    CHAR_CASE(rchr, T, Q, empty_missing, "", 'a', -1) \
    FIND_CASE(sub, T, Q, empty_needle, "abc", "", 0) \
    FIND_CASE(sub, T, Q, both_empty, "", "", 0) \
    FIND_CASE(sub, T, Q, empty_haystack, "", "a", -1) \
    FIND_CASE(sub, T, Q, first_match, "ababab", "ab", 0) \
    FIND_CASE(sub, T, Q, suffix, "abcde", "de", 3) \
    FIND_CASE(sub, T, Q, restart, "aaaab", "aab", 2) \
    FIND_CASE(sub, T, Q, too_long, "ab", "abc", -1) \
    FIND_CASE(sub, T, Q, case_sensitive, "ABC", "bc", -1) \
    SPAN_CASE(span, T, Q, partial, "aabcz", "abc", 4) \
    SPAN_CASE(span, T, Q, all, "abca", "cba", 4) \
    SPAN_CASE(span, T, Q, empty_set, "abc", "", 0) \
    SPAN_CASE(span, T, Q, empty_string, "", "abc", 0) \
    SPAN_CASE(cspan, T, Q, partial, "abcde", "dx", 3) \
    SPAN_CASE(cspan, T, Q, first, "abc", "a", 0) \
    SPAN_CASE(cspan, T, Q, absent, "abc", "xyz", 3) \
    SPAN_CASE(cspan, T, Q, empty_set, "abc", "", 3) \
    SPAN_CASE(cspan, T, Q, empty_string, "", "abc", 0) \
    FIND_CASE(pbrk, T, Q, first_in_string, "abcde", "dc", 2) \
    FIND_CASE(pbrk, T, Q, absent, "abc", "xyz", -1) \
    FIND_CASE(pbrk, T, Q, empty_set, "abc", "", -1) \
    FIND_CASE(pbrk, T, Q, empty_string, "", "abc", -1)

LENGTHS(char, C_TEXT, strlen, strnlen)
LENGTHS(wchar_t, W_TEXT, wcslen, wcsnlen)
COPIES(char, C_TEXT, strcpy, strncpy, strcat, strncat)
COPIES(wchar_t, W_TEXT, wcscpy, wcsncpy, wcscat, wcsncat)
COMPARES(char, C_TEXT, strcmp, strncmp, _stricmp)
COMPARES(wchar_t, W_TEXT, wcscmp, wcsncmp, _wcsicmp)
SEARCHES(char, C_TEXT, strchr, strrchr, strstr, strspn, strcspn, strpbrk)
SEARCHES(wchar_t, W_TEXT, wcschr, wcsrchr, wcsstr, wcsspn, wcscspn, wcspbrk)

/* Only successful secure calls: every invalid branch invokes _invalid_parameter. */
#define SECURE_COPY(fn, T, Q, id, text, capacity) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q(text), expected[] = Q(text), out[128]; \
        LOAD(fn); FILL(out, 0x5a); EXPECT_EQ(f(out + 1, capacity, src), 0); \
        SAME(out + 1, expected, ELEMENTS(expected)); \
        EXPECT_EQ(out[ELEMENTS(expected) + 1], 0x5a); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[(capacity) + 1], 0x5a); \
    }
#define SECURE_CAT(fn, T, Q, id, initial, text, result, capacity) \
    TEST(crt_strings_##fn##_##id) { \
        T src[96] = Q(text), seed[] = Q(initial), expected[] = Q(result), out[128]; \
        LOAD(fn); FILL(out, 0x5a); \
        { size_t i; for (i = 0; i < ELEMENTS(seed); ++i) out[i + 1] = seed[i]; } \
        EXPECT_EQ(f(out + 1, capacity, src), 0); SAME(out + 1, expected, ELEMENTS(expected)); \
        EXPECT_EQ(out[ELEMENTS(expected) + 1], 0x5a); \
        EXPECT_EQ(out[0], 0x5a); EXPECT_EQ(out[(capacity) + 1], 0x5a); \
    }
#define SECURE_CASES(T, Q, copy, cat) \
    SECURE_COPY(copy, T, Q, empty_exact, "", 1) \
    SECURE_COPY(copy, T, Q, exact, "abcd", 5) \
    SECURE_COPY(copy, T, Q, roomy, "abcd", 16) \
    SECURE_CAT(cat, T, Q, empty_exact, "", "", "", 1) \
    SECURE_CAT(cat, T, Q, exact, "ab", "cd", "abcd", 5) \
    SECURE_CAT(cat, T, Q, roomy, "ab", "cd", "abcd", 16) \
    SECURE_CAT(cat, T, Q, empty_source, "ab", "", "ab", 3)

SECURE_CASES(char, C_TEXT, strcpy_s, strcat_s)
SECURE_CASES(wchar_t, W_TEXT, wcscpy_s, wcscat_s)

TEST(crt_strings_strcmp_unsigned_bytes)
{
    char a[16] = {(char)0x80, 0}, b[16] = {0x7f, 0};
    LOAD(strcmp); CHECK(f(a, b) > 0);
}

TEST(crt_strings_wcscmp_unsigned_units)
{
    wchar_t a[] = {0xff00, 0}, b[] = {0x100, 0};
    LOAD(wcscmp); CHECK(f(a, b) > 0);
}

TEST(crt_strings_wcslen_utf16_units)
{
    wchar_t s[] = {0xd83d, 0xde00, 0};
    LOAD(wcslen); EXPECT_EQ(f(s), 2);
}

TEST(crt_strings_strnlen_unterminated)
{
    char s[8] = {'a','b','c','d','e','f','g','h'};
    LOAD(strnlen); EXPECT_EQ(f(s, ELEMENTS(s)), ELEMENTS(s));
}

TEST(crt_strings_wcsnlen_unterminated)
{
    wchar_t s[] = {'a','b','c','d'};
    LOAD(wcsnlen); EXPECT_EQ(f(s, ELEMENTS(s)), ELEMENTS(s));
}
