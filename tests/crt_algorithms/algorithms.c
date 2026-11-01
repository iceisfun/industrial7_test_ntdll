#include "t.h"
#include <stdlib.h>
#include <ctype.h>

#define LOAD(fn) __typeof__(&fn) f = UIN("ntdll.dll", fn); REQUIRE(f)
#define ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))

static void copy_memory(int moving, size_t count, size_t dst_offset, size_t src_offset)
{
    unsigned char src[512], out[512]; size_t i;
    __typeof__(&memcpy) f = moving ? UIN("ntdll.dll", memmove) : UIN("ntdll.dll", memcpy);
    REQUIRE(f);
    CHECK(count + dst_offset < sizeof(out)); CHECK(count + src_offset < sizeof(src));
    if (count + dst_offset >= sizeof(out) || count + src_offset >= sizeof(src)) return;
    for (i = 0; i < sizeof(src); ++i) { src[i] = (unsigned char)(i * 37 + 11); out[i] = 0x5a; }
    CHECK(f(out + dst_offset, src + src_offset, count) == out + dst_offset);
    for (i = 0; i < sizeof(out); ++i) {
        unsigned char expected = i >= dst_offset && i < dst_offset + count ?
            (unsigned char)((i - dst_offset + src_offset) * 37 + 11) : 0x5a;
        EXPECT_EQ(out[i], expected);
        EXPECT_EQ(src[i], (unsigned char)(i * 37 + 11));
    }
}
#define COPY(id, n) TEST(crt_algorithms_memcpy_##id) { copy_memory(0, n, 3, 1); }
COPY(zero, 0)
COPY(one, 1)
COPY(seven, 7)
COPY(eight, 8)
COPY(fifteen, 15)
COPY(sixteen, 16)
COPY(seventeen, 17)
COPY(thirty_one, 31)
COPY(thirty_two, 32)
COPY(thirty_three, 33)
COPY(sixty_three, 63)
COPY(sixty_four, 64)
COPY(sixty_five, 65)
COPY(one_twenty_seven, 127)
COPY(one_twenty_eight, 128)
COPY(one_twenty_nine, 129)
COPY(two_fifty_five, 255)
TEST(crt_algorithms_memcpy_aligned) { copy_memory(0, 128, 16, 32); }
TEST(crt_algorithms_memmove_disjoint) { copy_memory(1, 129, 7, 3); }

static void overlap_move(size_t count, size_t dst_offset, size_t src_offset)
{
    unsigned char out[512], original[512]; size_t i;
    LOAD(memmove);
    CHECK(count + dst_offset < sizeof(out)); CHECK(count + src_offset < sizeof(out));
    if (count + dst_offset >= sizeof(out) || count + src_offset >= sizeof(out)) return;
    for (i = 0; i < sizeof(out); ++i) original[i] = out[i] = (unsigned char)(i * 29 + 7);
    CHECK(f(out + dst_offset, out + src_offset, count) == out + dst_offset);
    for (i = 0; i < sizeof(out); ++i)
        EXPECT_EQ(out[i], i >= dst_offset && i < dst_offset + count ?
            original[i - dst_offset + src_offset] : original[i]);
}
#define MOVE(id, n) \
    TEST(crt_algorithms_memmove_right_##id) { overlap_move(n, 19, 16); } \
    TEST(crt_algorithms_memmove_left_##id) { overlap_move(n, 16, 19); }
MOVE(zero, 0)
MOVE(one, 1)
MOVE(seven, 7)
MOVE(eight, 8)
MOVE(sixteen, 16)
MOVE(seventeen, 17)
MOVE(thirty_two, 32)
MOVE(thirty_three, 33)
MOVE(sixty_five, 65)
MOVE(one_twenty_nine, 129)
MOVE(two_fifty_five, 255)
TEST(crt_algorithms_memmove_self) { overlap_move(129, 16, 16); }

static void fill_memory(size_t count, int value)
{
    unsigned char out[512]; size_t i;
    LOAD(memset);
    CHECK(count + 3 < sizeof(out)); if (count + 3 >= sizeof(out)) return;
    for (i = 0; i < sizeof(out); ++i) out[i] = 0x5a;
    CHECK(f(out + 3, value, count) == out + 3);
    for (i = 0; i < sizeof(out); ++i)
        EXPECT_EQ(out[i], i >= 3 && i < 3 + count ? (unsigned char)value : 0x5a);
}
#define FILL(id, n, v) TEST(crt_algorithms_memset_##id) { fill_memory(n, v); }
FILL(zero, 0, 0)
FILL(one, 1, 0x81)
FILL(seven, 7, 0)
FILL(eight, 8, 0xff)
FILL(sixteen, 16, 0x81)
FILL(seventeen, 17, 0x81)
FILL(thirty_two, 32, 0x81)
FILL(seventy_eight, 78, 0x81)
FILL(seventy_nine, 79, 0x81)
FILL(eighty, 80, 0x81)
FILL(one_twenty_seven, 127, 0x81)
FILL(one_twenty_eight, 128, 0x81)
FILL(one_twenty_nine, 129, 0x81)
FILL(two_fifty_five, 255, 0x81)
FILL(low_byte, 33, 0x1234)
FILL(negative, 65, -1)

#define MEMCHR(id, value, count, offset) \
    TEST(crt_algorithms_memchr_##id) { \
        unsigned char s[] = {0x11, 0, 0x80, 0x22, 0x80, 0xff, 0x33, 0x44}; \
        void *expected = (offset) < 0 ? NULL : s + (offset); \
        LOAD(memchr); CHECK(f(s, value, count) == expected); \
    }
MEMCHR(zero, 0x11, 0, -1)
MEMCHR(first, 0x11, 8, 0)
MEMCHR(nul_is_data, 0, 8, 1)
MEMCHR(first_repeated, 0x80, 8, 2)
MEMCHR(high_byte, 0xff, 8, 5)
MEMCHR(excluded, 0x22, 3, -1)
MEMCHR(last, 0x44, 8, 7)
MEMCHR(missing, 0x55, 8, -1)
MEMCHR(low_byte, 0x180, 8, 2)

static void compare_memory(size_t count, size_t mismatch, int sign)
{
    unsigned char a[160], b[160]; size_t i; int r;
    LOAD(memcmp);
    CHECK(count <= 128); CHECK(mismatch < 128);
    if (count > 128 || mismatch >= 128) return;
    for (i = 0; i < sizeof(a); ++i) a[i] = b[i] = (unsigned char)i;
    a[mismatch + 1] = 0x80; b[mismatch + 1] = 0x7f;
    r = f(a + 1, b + 1, count); EXPECT_EQ((r > 0) - (r < 0), sign);
    r = f(b + 1, a + 1, count); EXPECT_EQ((r > 0) - (r < 0), -sign);
}
#define MEMCMP(id, count, mismatch, sign) \
    TEST(crt_algorithms_memcmp_##id) { compare_memory(count, mismatch, sign); }
MEMCMP(zero, 0, 0, 0)
MEMCMP(excluded, 7, 7, 0)
MEMCMP(first, 1, 0, 1)
MEMCMP(short_tail, 7, 6, 1)
MEMCMP(eight, 8, 7, 1)
MEMCMP(word_boundary, 17, 8, 1)
MEMCMP(block_boundary, 65, 32, 1)
MEMCMP(long_tail, 128, 127, 1)
TEST(crt_algorithms_memcmp_self)
{
    unsigned char s[32] = {0, 0x80, 0xff};
    LOAD(memcmp); EXPECT_EQ(f(s, s, sizeof(s)), 0);
}

struct compare_context { int direction; unsigned calls; };
static struct compare_context *active_context;
static unsigned plain_calls;

static int __cdecl compare_int(const void *left, const void *right)
{
    int a = *(const int *)left, b = *(const int *)right;
    ++plain_calls;
    return (a > b) - (a < b);
}

static int __cdecl compare_int_s(void *context, const void *left, const void *right)
{
    struct compare_context *c = context;
    CHECK(c == active_context);
    if (c != active_context) return 0;
    ++c->calls;
    return c->direction * ((*(const int *)left > *(const int *)right) -
                           (*(const int *)left < *(const int *)right));
}

static void sort_case(int secure, size_t count, int pattern, int direction)
{
    int storage[34], original[32]; int *a = storage + 1; size_t i, j;
    struct compare_context context = {direction, 0};
    __typeof__(&qsort) sort = UIN("ntdll.dll", qsort);
    __typeof__(&qsort_s) sort_s = UIN("ntdll.dll", qsort_s);
    if (secure) { REQUIRE(sort_s); } else { REQUIRE(sort); }
    CHECK(count <= ELEMENTS(original)); if (count > ELEMENTS(original)) return;
    for (i = 0; i < ELEMENTS(storage); ++i) storage[i] = 0x12345678;
    for (i = 0; i < count; ++i) {
        int value = pattern == 0 ? (int)(count - i) : pattern == 1 ? (int)i :
                    pattern == 2 ? (int)(i % 3) - 1 : pattern == 3 ? 7 :
                    (int)((i * 7) % 17) - 8;
        original[i] = a[i] = value;
    }
    active_context = &context; plain_calls = 0;
    if (secure) sort_s(a, count, sizeof(*a), compare_int_s, &context);
    else sort(a, count, sizeof(*a), compare_int);
    active_context = NULL;
    if (count > 1) CHECK((secure ? context.calls : plain_calls) > 0);
    else EXPECT_EQ(secure ? context.calls : plain_calls, 0);
    for (i = 1; i < count; ++i) CHECK(direction > 0 ? a[i-1] <= a[i] : a[i-1] >= a[i]);
    /* Order alone would miss a sorter which loses or duplicates elements. */
    for (i = 0; i < count; ++i) {
        unsigned before = 0, after = 0;
        for (j = 0; j < count; ++j) { before += original[j] == original[i]; after += a[j] == original[i]; }
        EXPECT_EQ(before, after);
    }
    EXPECT_EQ(storage[0], 0x12345678);
    for (i = count + 1; i < ELEMENTS(storage); ++i) EXPECT_EQ(storage[i], 0x12345678);
}
#define SORT(fn, secure, id, count, pattern, direction) \
    TEST(crt_algorithms_##fn##_##id) { sort_case(secure, count, pattern, direction); }
SORT(qsort, 0, zero, 0, 0, 1)
SORT(qsort, 0, singleton, 1, 0, 1)
SORT(qsort, 0, pair, 2, 0, 1)
SORT(qsort, 0, eight, 8, 0, 1)
SORT(qsort, 0, nine, 9, 0, 1)
SORT(qsort, 0, partition, 32, 4, 1)
SORT(qsort, 0, sorted, 17, 1, 1)
SORT(qsort, 0, duplicates, 32, 2, 1)
SORT(qsort, 0, equal, 17, 3, 1)
SORT(qsort_s, 1, zero, 0, 0, 1)
SORT(qsort_s, 1, singleton, 1, 0, 1)
SORT(qsort_s, 1, pair, 2, 0, 1)
SORT(qsort_s, 1, eight, 8, 0, 1)
SORT(qsort_s, 1, sorted, 8, 1, 1)
SORT(qsort_s, 1, duplicates, 8, 2, 1)
SORT(qsort_s, 1, equal, 8, 3, 1)
SORT(qsort_s, 1, descending_context, 8, 4, -1)

static void search_case(int secure, size_t count, int key, int expected_index, int direction)
{
    int storage[10] = {0x12345678, -7, -3, 0, 2, 5, 8, 11, 20, 0x12345678};
    const int values[] = {-7, -3, 0, 2, 5, 8, 11, 20};
    int *a = storage + 1, *result, original_key = key; size_t i;
    struct compare_context context = {direction, 0};
    __typeof__(&bsearch) search = UIN("ntdll.dll", bsearch);
    __typeof__(&bsearch_s) search_s = UIN("ntdll.dll", bsearch_s);
    if (secure) { REQUIRE(search_s); } else { REQUIRE(search); }
    CHECK(count <= ELEMENTS(values)); if (count > ELEMENTS(values)) return;
    if (direction < 0) for (i = 0; i < ELEMENTS(values); ++i) a[i] = values[7-i];
    active_context = &context; plain_calls = 0;
    if (secure) result = search_s(&key, a, count, sizeof(*a), compare_int_s, &context);
    else result = search(&key, a, count, sizeof(*a), compare_int);
    active_context = NULL;
    CHECK(result == (expected_index < 0 ? NULL : a + expected_index));
    if (count == 0) EXPECT_EQ(secure ? context.calls : plain_calls, 0);
    else CHECK((secure ? context.calls : plain_calls) > 0);
    EXPECT_EQ(key, original_key); EXPECT_EQ(storage[0], 0x12345678); EXPECT_EQ(storage[9], 0x12345678);
    for (i = 0; i < ELEMENTS(values); ++i) EXPECT_EQ(a[i], direction < 0 ? values[7-i] : values[i]);
}
#define SEARCH(fn, secure, id, count, key, expected, direction) \
    TEST(crt_algorithms_##fn##_##id) { search_case(secure, count, key, expected, direction); }
#define SEARCH_CASES(fn, secure) \
    SEARCH(fn, secure, empty, 0, -7, -1, 1) \
    SEARCH(fn, secure, singleton_hit, 1, -7, 0, 1) \
    SEARCH(fn, secure, singleton_miss, 1, 0, -1, 1) \
    SEARCH(fn, secure, first, 8, -7, 0, 1) \
    SEARCH(fn, secure, last, 8, 20, 7, 1) \
    SEARCH(fn, secure, even_midpoint, 8, 2, 3, 1) \
    SEARCH(fn, secure, odd_midpoint, 7, 2, 3, 1) \
    SEARCH(fn, secure, below, 8, -10, -1, 1) \
    SEARCH(fn, secure, above, 8, 30, -1, 1) \
    SEARCH(fn, secure, gap, 8, 6, -1, 1)
SEARCH_CASES(bsearch, 0)
SEARCH_CASES(bsearch_s, 1)
SEARCH(bsearch_s, 1, descending_context, 8, 8, 2, -1)

enum ascii_kind { ALNUM, ALPHA, CNTRL, DIGIT, GRAPH, LOWER, PRINT, PUNCT, SPACE, UPPER, XDIGIT };
static int ascii_expected(enum ascii_kind kind, int c)
{
    int upper = c >= 'A' && c <= 'Z', lower = c >= 'a' && c <= 'z';
    int digit = c >= '0' && c <= '9', graph = c >= 0x21 && c <= 0x7e;
    switch (kind) {
    case ALNUM: return upper || lower || digit;
    case ALPHA: return upper || lower;
    case CNTRL: return c < 0x20 || c == 0x7f;
    case DIGIT: return digit;
    case GRAPH: return graph;
    case LOWER: return lower;
    case PRINT: return c >= 0x20 && c <= 0x7e;
    case PUNCT: return graph && !upper && !lower && !digit;
    case SPACE: return c == ' ' || (c >= '\t' && c <= '\r');
    case UPPER: return upper;
    case XDIGIT: return digit || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }
    return 0;
}
#define CLASS_RANGE(fn, kind, id, first, last) \
    TEST(crt_algorithms_##fn##_##id) { \
        int c; LOAD(fn); for (c = first; c <= last; ++c) \
            CHECKF(!!f(c) == ascii_expected(kind, c), "ASCII 0x%02x", c); \
    }
#define CLASS(fn, kind) \
    CLASS_RANGE(fn, kind, controls, 0, 31) \
    CLASS_RANGE(fn, kind, printable, 32, 126) \
    CLASS_RANGE(fn, kind, delete, 127, 127)
CLASS(isalnum, ALNUM)
CLASS(isalpha, ALPHA)
CLASS(iscntrl, CNTRL)
CLASS(isdigit, DIGIT)
CLASS(isgraph, GRAPH)
CLASS(islower, LOWER)
CLASS(isprint, PRINT)
CLASS(ispunct, PUNCT)
CLASS(isspace, SPACE)
CLASS(isupper, UPPER)
CLASS(isxdigit, XDIGIT)

#define CASE_RANGE(fn, id, first, last, upper) \
    TEST(crt_algorithms_##fn##_##id) { \
        int c; LOAD(fn); for (c = first; c <= last; ++c) { \
            int expected = upper ? (c >= 'a' && c <= 'z' ? c - 32 : c) : \
                                   (c >= 'A' && c <= 'Z' ? c + 32 : c); \
            EXPECT_EQ(f(c), expected); \
        } \
    }
CASE_RANGE(tolower, letters, 'A', 'z', 0)
CASE_RANGE(tolower, controls, 0, 31, 0)
CASE_RANGE(tolower, digits_punctuation, 32, 64, 0)
CASE_RANGE(tolower, tail, 123, 127, 0)
CASE_RANGE(toupper, letters, 'A', 'z', 1)
CASE_RANGE(toupper, controls, 0, 31, 1)
CASE_RANGE(toupper, digits_punctuation, 32, 64, 1)
CASE_RANGE(toupper, tail, 123, 127, 1)
