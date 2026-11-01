#include "t.h"

UDECL(NTSTATUS, RtlCharToInteger, (PCSZ, ULONG, PULONG));
UDECL(NTSTATUS, RtlUnicodeStringToInteger, (const UNICODE_STRING *, ULONG, PULONG));
UDECL(NTSTATUS, RtlIntegerToChar, (ULONG, ULONG, ULONG, PCHAR));
UDECL(NTSTATUS, RtlIntegerToUnicodeString, (ULONG, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, RtlLargeIntegerToChar, (const LARGE_INTEGER *, ULONG, ULONG, PCHAR));
UDECL(USHORT, RtlUshortByteSwap, (USHORT));
UDECL(ULONG, RtlUlongByteSwap, (ULONG));
UDECL(ULONGLONG, RtlUlonglongByteSwap, (ULONGLONG));
UDECL(int, abs, (int));
UDECL(LONG, labs, (LONG));

static void parse(const char *text, ULONG base, ULONG expected)
{
    WCHAR wide[128];
    UNICODE_STRING s;
    ULONG value = 0xdeadbeef;
    size_t n = strlen(text), i;
    REQUIRE(UN(RtlCharToInteger));
    REQUIRE(UN(RtlUnicodeStringToInteger));
    CHECK(n < 128);
    if (n >= 128) return;
    for (i = 0; i <= n; ++i) wide[i] = (unsigned char)text[i];
    EXPECT_EQ(UN(RtlCharToInteger)(text, base, &value), 0);
    EXPECT_EQ(value, expected);
    s.Buffer = wide; s.Length = n * sizeof(WCHAR); s.MaximumLength = sizeof(wide);
    value = 0xdeadbeef;
    EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, base, &value), 0);
    EXPECT_EQ(value, expected);
}

#define PARSE(name, text, base, value) TEST(rtl_numeric_parse_##name) { parse(text, base, value); }
PARSE(zero, "0", 10, 0)
PARSE(one, "1", 10, 1)
PARSE(decimal, "123456789", 10, 123456789)
PARSE(maximum, "4294967295", 10, 0xffffffff)
PARSE(wrap_zero, "4294967296", 10, 0)
PARSE(wrap_one, "4294967297", 10, 1)
PARSE(minus_one, "-1", 10, 0xffffffff)
PARSE(minimum_signed, "-2147483648", 10, 0x80000000)
PARSE(plus, "+42", 10, 42)
PARSE(whitespace, " \t\r\n42", 10, 42)
PARSE(negative_space, " \t-42", 10, (ULONG)-42)
PARSE(trailing_space, "42 99", 10, 42)
PARSE(trailing_text, "123xyz", 10, 123)
PARSE(no_digits, "xyz", 10, 0)
PARSE(sign_only, "-", 10, 0)
PARSE(only_space, "   ", 10, 0)
PARSE(autodecimal, "123", 0, 123)
PARSE(leading_zero_decimal, "0123", 0, 123)
PARSE(autohex, "0xAbCd", 0, 0xabcd)
PARSE(autooctal, "0o177", 0, 127)
PARSE(autobinary, "0b101101", 0, 45)
PARSE(negative_hex, "-0xFF", 0, (ULONG)-255)
PARSE(uppercase_prefix, "0XFF", 0, 0)
PARSE(explicit_prefix, "0xFF", 16, 0)
PARSE(hex_upper, "FEDCBA98", 16, 0xfedcba98)
PARSE(hex_lower, "abcdef", 16, 0xabcdef)
PARSE(hex_wrap, "100000000", 16, 0)
PARSE(octal, "377", 8, 255)
PARSE(octal_stop, "1789", 8, 15)
PARSE(binary, "11111111", 2, 255)
PARSE(binary_stop, "1012", 2, 5)

TEST(rtl_numeric_invalid_bases)
{
    const ULONG bases[] = {1, 3, 7, 9, 11, 15, 17, 36, 0xffffffff};
    WCHAR w[] = L"123";
    UNICODE_STRING s = {6, sizeof(w), w};
    unsigned i;
    REQUIRE(UN(RtlCharToInteger)); REQUIRE(UN(RtlUnicodeStringToInteger));
    for (i = 0; i < sizeof(bases)/sizeof(bases[0]); ++i) {
        ULONG a = 0x12345678, b = 0x12345678;
        EXPECT_EQ(UN(RtlCharToInteger)("123", bases[i], &a), (NTSTATUS)0xc000000d);
        EXPECT_EQ(a, 0x12345678);
        EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, bases[i], &b), (NTSTATUS)0xc000000d);
        EXPECT_EQ(b, 0);
    }
}

TEST(rtl_numeric_unicode_counted)
{
    WCHAR w[] = {L'1', L'2', L'3', L'4'};
    UNICODE_STRING s = {4, sizeof(w), w};
    ULONG v = 0;
    REQUIRE(UN(RtlUnicodeStringToInteger));
    EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, 10, &v), 0);
    EXPECT_EQ(v, 12);
}

TEST(rtl_numeric_unicode_invalid_lengths)
{
    WCHAR w[] = L"123";
    UNICODE_STRING s = {0, sizeof(w), w};
    ULONG v = 99;
    REQUIRE(UN(RtlUnicodeStringToInteger));
    EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, 10, &v), (NTSTATUS)0xc000000d);
    EXPECT_EQ(v, 0);
    s.Length = 3; v = 99;
    EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, 10, &v), (NTSTATUS)0xc000000d);
    EXPECT_EQ(v, 0);
}

TEST(rtl_numeric_unicode_embedded_nul)
{
    WCHAR w[] = {L'4', L'2', 0, L'9'};
    UNICODE_STRING s = {sizeof(w), sizeof(w), w};
    ULONG v = 0;
    REQUIRE(UN(RtlUnicodeStringToInteger));
    EXPECT_EQ(UN(RtlUnicodeStringToInteger)(&s, 10, &v), 0);
    EXPECT_EQ(v, 42);
}

static void format32(ULONG value, ULONG base, const char *expected)
{
    char out[80]; WCHAR wide[80];
    size_t n = strlen(expected), i;
    UNICODE_STRING s = {0, sizeof(wide), wide};
    NTSTATUS status;
    REQUIRE(UN(RtlIntegerToChar)); REQUIRE(UN(RtlIntegerToUnicodeString));
    memset(out, 0x5a, sizeof(out)); memset(wide, 0x5a, sizeof(wide));
    status = UN(RtlIntegerToChar)(value, base, sizeof(out), out);
    EXPECT_EQ(status, 0);
    if (status == 0) CHECK(memcmp(out, expected, n + 1) == 0);
    EXPECT_EQ(out[n + 1], 0x5a);
    status = UN(RtlIntegerToUnicodeString)(value, base, &s);
    EXPECT_EQ(status, 0);
    if (status != 0) return;
    EXPECT_EQ(s.Length, n * 2); EXPECT_EQ(s.MaximumLength, sizeof(wide));
    CHECK(s.Buffer == wide);
    for (i = 0; i < n; ++i) EXPECT_EQ(wide[i], (unsigned char)expected[i]);
    EXPECT_EQ(wide[n], 0); EXPECT_EQ(wide[n + 1], 0x5a5a);
}
#define FORMAT(name, value, base, expected) TEST(rtl_numeric_format_##name) { format32(value, base, expected); }
FORMAT(zero, 0, 10, "0")
FORMAT(default, 12345, 0, "12345")
FORMAT(decimal, 12345, 10, "12345")
FORMAT(maximum, 0xffffffff, 10, "4294967295")
FORMAT(highbit, 0x80000000, 10, "2147483648")
FORMAT(hex, 0xabcdef, 16, "ABCDEF")
FORMAT(hex_max, 0xffffffff, 16, "FFFFFFFF")
FORMAT(octal, 511, 8, "777")
FORMAT(octal_max, 0xffffffff, 8, "37777777777")
FORMAT(binary, 45, 2, "101101")
FORMAT(binary_max, 0xffffffff, 2, "11111111111111111111111111111111")

static void char_capacity(ULONG capacity, NTSTATUS expected)
{
    char out[16], old[16];
    NTSTATUS status;
    REQUIRE(UN(RtlIntegerToChar));
    memset(out, 0x5a, sizeof(out)); memcpy(old, out, sizeof(out));
    status = UN(RtlIntegerToChar)(123, 10, capacity, out);
    EXPECT_EQ(status, expected);
    if (expected != 0) CHECK(memcmp(out, old, sizeof(out)) == 0);
    else {
        CHECK(memcmp(out, "123", 3) == 0);
        EXPECT_EQ(out[3], capacity == 3 ? 0x5a : 0);
        EXPECT_EQ(out[4], 0x5a);
    }
}
TEST(rtl_numeric_char_zero_capacity) { char_capacity(0, (NTSTATUS)0x80000005); }
TEST(rtl_numeric_char_one_capacity) { char_capacity(1, (NTSTATUS)0x80000005); }
TEST(rtl_numeric_char_short_capacity) { char_capacity(2, (NTSTATUS)0x80000005); }
TEST(rtl_numeric_char_exact_capacity) { char_capacity(3, 0); }
TEST(rtl_numeric_char_terminated_capacity) { char_capacity(4, 0); }

TEST(rtl_numeric_format_invalid_base)
{
    char out[16]; WCHAR w[16]; UNICODE_STRING s = {8, sizeof(w), w};
    REQUIRE(UN(RtlIntegerToChar)); REQUIRE(UN(RtlIntegerToUnicodeString));
    memset(out, 0x5a, sizeof(out)); memset(w, 0x5a, sizeof(w));
    EXPECT_EQ(UN(RtlIntegerToChar)(123, 3, sizeof(out), out), (NTSTATUS)0xc000000d);
    EXPECT_EQ(out[0], 0x5a);
    EXPECT_EQ(UN(RtlIntegerToUnicodeString)(123, 3, &s), (NTSTATUS)0xc000000d);
    EXPECT_EQ(s.Length, 8); EXPECT_EQ(w[0], 0x5a5a);
}

TEST(rtl_numeric_unicode_short_capacity)
{
    WCHAR w[8]; UNICODE_STRING s = {0, 6, w};
    REQUIRE(UN(RtlIntegerToUnicodeString));
    memset(w, 0x5a, sizeof(w));
    EXPECT_EQ(UN(RtlIntegerToUnicodeString)(123, 10, &s), (NTSTATUS)0x80000005);
    EXPECT_EQ(s.Length, 6); EXPECT_EQ(w[0], 0x5a5a);
}

static void format64(ULONGLONG value, ULONG base, const char *expected)
{
    LARGE_INTEGER v; char out[80]; size_t n = strlen(expected); NTSTATUS status;
    REQUIRE(UN(RtlLargeIntegerToChar));
    v.QuadPart = value; memset(out, 0x5a, sizeof(out));
    status = UN(RtlLargeIntegerToChar)(&v, base, sizeof(out), out);
    EXPECT_EQ(status, 0);
    if (status == 0) CHECK(memcmp(out, expected, n + 1) == 0);
    EXPECT_EQ(out[n + 1], 0x5a);
}
#define LARGE(name, value, base, expected) TEST(rtl_numeric_large_##name) { format64(value, base, expected); }
LARGE(zero, 0, 10, "0")
LARGE(default, 4294967296ULL, 0, "4294967296")
LARGE(maximum, 0xffffffffffffffffULL, 10, "18446744073709551615")
LARGE(highbit, 0x8000000000000000ULL, 10, "9223372036854775808")
LARGE(hex, 0x123456789abcdef0ULL, 16, "123456789ABCDEF0")
LARGE(hex_max, 0xffffffffffffffffULL, 16, "FFFFFFFFFFFFFFFF")
LARGE(octal, 0x100000000ULL, 8, "40000000000")
LARGE(binary, 0x100000000ULL, 2, "100000000000000000000000000000000")

TEST(rtl_numeric_large_capacity)
{
    LARGE_INTEGER v; char out[16];
    REQUIRE(UN(RtlLargeIntegerToChar)); v.QuadPart = 123;
    memset(out, 0x5a, sizeof(out));
    EXPECT_EQ(UN(RtlLargeIntegerToChar)(&v, 10, 2, out), (NTSTATUS)0x80000005);
    EXPECT_EQ(out[0], 0x5a);
    EXPECT_EQ(UN(RtlLargeIntegerToChar)(&v, 10, 3, out), 0);
    CHECK(memcmp(out, "123", 3) == 0); EXPECT_EQ(out[3], 0x5a);
    EXPECT_EQ(UN(RtlLargeIntegerToChar)(&v, 10, 4, out), 0);
    CHECK(memcmp(out, "123\0", 4) == 0); EXPECT_EQ(out[4], 0x5a);
}

TEST(rtl_numeric_large_invalid_base)
{
    LARGE_INTEGER v; char out[16];
    REQUIRE(UN(RtlLargeIntegerToChar)); v.QuadPart = 123;
    memset(out, 0x5a, sizeof(out));
    EXPECT_EQ(UN(RtlLargeIntegerToChar)(&v, 36, sizeof(out), out), (NTSTATUS)0xc000000d);
    EXPECT_EQ(out[0], 0x5a);
}

/* These are macros/intrinsics, not exports in the reference x64 image. */
TEST(rtl_numeric_byteswap16_optional)
{
    REQUIRE(UN(RtlUshortByteSwap));
    t_note("unexpected optional export; no user-mode x64 contract in reference corpus");
}
TEST(rtl_numeric_byteswap32_optional)
{
    REQUIRE(UN(RtlUlongByteSwap));
    t_note("unexpected optional export; no user-mode x64 contract in reference corpus");
}
TEST(rtl_numeric_byteswap64_optional)
{
    REQUIRE(UN(RtlUlonglongByteSwap));
    t_note("unexpected optional export; no user-mode x64 contract in reference corpus");
}

#define ABSCASE(name, input, expected) \
    TEST(rtl_numeric_absolute_##name) { \
        REQUIRE(UN(abs)); REQUIRE(UN(labs)); \
        EXPECT_EQ(UN(abs)(input), expected); EXPECT_EQ(UN(labs)(input), expected); \
    }
ABSCASE(zero, 0, 0)
ABSCASE(positive, 1234567, 1234567)
ABSCASE(negative, -1234567, 1234567)
ABSCASE(maximum, 2147483647, 2147483647)
ABSCASE(negative_maximum, -2147483647, 2147483647)
