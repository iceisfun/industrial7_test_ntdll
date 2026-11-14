#include "t.h"

/* Additional string services: GUID text, validation, allocation helpers, case mapping
 * to narrow strings, normalization, text heuristics. */
UDECL(NTSTATUS, RtlGUIDFromString, (PCUNICODE_STRING, GUID *));
UDECL(NTSTATUS, RtlStringFromGUID, (const GUID *, PUNICODE_STRING));
UDECL(NTSTATUS, RtlValidateUnicodeString, (ULONG, PCUNICODE_STRING));
UDECL(BOOLEAN, RtlCreateUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(BOOLEAN, RtlCreateUnicodeStringFromAsciiz, (PUNICODE_STRING, PCSTR));
UDECL(NTSTATUS, RtlInitAnsiStringEx, (PANSI_STRING, PCSTR));
UDECL(NTSTATUS, RtlUpcaseUnicodeStringToAnsiString, (PANSI_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, RtlUpcaseUnicodeToMultiByteN, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlDowncaseUnicodeString, (PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, RtlAppendAsciizToString, (PANSI_STRING, PCSTR));
UDECL(void, RtlUpperString, (PANSI_STRING, const ANSI_STRING *));
UDECL(LONG, RtlCompareUnicodeStrings, (PCWCH, SIZE_T, PCWCH, SIZE_T, BOOLEAN));
UDECL(ULONG, RtlxAnsiStringToUnicodeSize, (const ANSI_STRING *));
UDECL(ULONG, RtlxUnicodeStringToAnsiSize, (PCUNICODE_STRING));
UDECL(NTSTATUS, RtlInt64ToUnicodeString, (ULONGLONG, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, RtlNormalizeString, (ULONG, PCWSTR, LONG, PWSTR, PLONG));
UDECL(NTSTATUS, RtlIsNormalizedString, (ULONG, PCWSTR, LONG, BOOLEAN *));
UDECL(BOOLEAN, RtlIsTextUnicode, (const VOID *, INT, INT *));
UDECL(void, RtlFreeAnsiString, (PANSI_STRING));
UDECL(void, RtlFreeUnicodeString, (PUNICODE_STRING));

#define INVALID  ((NTSTATUS)0xC000000D)
#define SMALL    ((NTSTATUS)0xC0000023)
#define OVERFLOW ((NTSTATUS)0x80000005)
#define TOOLONG  ((NTSTATUS)0xC0000106)

static void init_us(UNICODE_STRING *u, const WCHAR *s, USHORT cap_bytes)
{
    u->Buffer = (PWSTR)s; u->Length = (USHORT)(lstrlenW(s) * 2); u->MaximumLength = cap_bytes ? cap_bytes : (USHORT)(u->Length + 2);
}

/* ---- GUID <-> string ---------------------------------------------------- */

TEST(strx_guid_parse_valid)
{
    static const WCHAR *const forms[] = {
        L"{01234567-89AB-CDEF-0123-456789ABCDEF}",
        L"{01234567-89ab-cdef-0123-456789abcdef}",
        L"{01234567-89aB-cDeF-0123-456789AbCdEf}",
    };
    REQUIRE(UN(RtlGUIDFromString));
    for (unsigned i = 0; i < 3; ++i) {
        UNICODE_STRING u; GUID g; memset(&g, 0x55, sizeof g);
        init_us(&u, forms[i], 0);
        EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0);
        EXPECT_EQ(g.Data1, 0x01234567);
        EXPECT_EQ(g.Data2, 0x89AB);
        EXPECT_EQ(g.Data3, 0xCDEF);
        CHECK(g.Data4[0] == 0x01 && g.Data4[1] == 0x23 && g.Data4[2] == 0x45 && g.Data4[7] == 0xEF);
    }
}

TEST(strx_guid_parse_special_values)
{
    UNICODE_STRING u; GUID g; GUID zero = {0}, ones;
    REQUIRE(UN(RtlGUIDFromString));
    memset(&ones, 0xff, sizeof ones);
    init_us(&u, L"{00000000-0000-0000-0000-000000000000}", 0);
    memset(&g, 0x55, sizeof g);
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0); CHECK(!memcmp(&g, &zero, sizeof g));
    init_us(&u, L"{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}", 0);
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0); CHECK(!memcmp(&g, &ones, sizeof g));
}

TEST(strx_guid_parse_invalid)
{
    static const WCHAR *const bad[] = {
        L"", L"{}",
        L"01234567-89AB-CDEF-0123-456789ABCDEF",          /* no braces */
        L"{01234567-89AB-CDEF-0123-456789ABCDEF",         /* missing close */
        L"01234567-89AB-CDEF-0123-456789ABCDEF}",         /* missing open */
        L"{01234567-89AB-CDEF-0123-456789ABCDE}",         /* short */
        L"{01234567-89AB-CDEF-0123-456789ABCDEF0}",       /* long */
        L"{0123456-789AB-CDEF-0123-456789ABCDEF}",        /* dash misplaced */
        L"{01234567-89AB-CDEF-0123456789ABCDEF}",         /* missing dash */
        L"{01234567_89AB_CDEF_0123_456789ABCDEF}",        /* wrong separators */
        L"{0123456G-89AB-CDEF-0123-456789ABCDEF}",        /* non-hex */
        L"{01234567-89AB-CDEF-0123-456789ABCDEG}",
        L" {01234567-89AB-CDEF-0123-456789ABCDEF}",       /* leading blank */
        L"{+1234567-89AB-CDEF-0123-456789ABCDEF}",        /* sign */
        L"{0x234567-89AB-CDEF-0123-456789ABCDEF}",        /* radix prefix */
    };
    REQUIRE(UN(RtlGUIDFromString));
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        UNICODE_STRING u; GUID g; init_us(&u, bad[i], 0);
        NTSTATUS st = UN(RtlGUIDFromString)(&u, &g);
        CHECKF(st == INVALID, "case %u status 0x%lx", i, (unsigned long)st);
    }
}

TEST(strx_guid_parse_length_is_counted)
{
    /* a valid 38-character GUID where the counted length cuts it short or extends past it */
    WCHAR buf[48] = L"{01234567-89AB-CDEF-0123-456789ABCDEF}garbage";
    UNICODE_STRING u = { 76, sizeof buf, buf }; GUID g;
    REQUIRE(UN(RtlGUIDFromString));
    EXPECT_EQ(UN(RtlGUIDFromString)(&u, &g), 0);
    u.Length = 74;
    t_note("counted length 74: status 0x%lx", (unsigned long)UN(RtlGUIDFromString)(&u, &g));
    u.Length = 78;
    t_note("counted length 78: status 0x%lx", (unsigned long)UN(RtlGUIDFromString)(&u, &g));
}

TEST(strx_guid_format)
{
    static const GUID g = { 0x01234567, 0x89AB, 0xCDEF, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF } };
    static const GUID z = {0};
    UNICODE_STRING u = { 0x55, 0x55, (PWSTR)(ULONG_PTR)0x1 };
    REQUIRE(UN(RtlStringFromGUID)); REQUIRE(UN(RtlFreeUnicodeString));
    EXPECT_EQ(UN(RtlStringFromGUID)(&g, &u), 0);
    EXPECT_EQ(u.Length, 76);
    EXPECT_EQ(u.MaximumLength, 78);
    CHECK(u.Buffer != NULL);
    if (u.Buffer) {
        EXPECT_WSTR(u.Buffer, L"{01234567-89ab-cdef-0123-456789abcdef}");   /* hexadecimal digits are lower case */
        UN(RtlFreeUnicodeString)(&u);
    }
    EXPECT_EQ(UN(RtlStringFromGUID)(&z, &u), 0);
    if (u.Buffer) { EXPECT_WSTR(u.Buffer, L"{00000000-0000-0000-0000-000000000000}"); UN(RtlFreeUnicodeString)(&u); }
}

TEST(strx_guid_roundtrip)
{
    REQUIRE(UN(RtlStringFromGUID)); REQUIRE(UN(RtlGUIDFromString)); REQUIRE(UN(RtlFreeUnicodeString));
    for (unsigned n = 0; n < 16; ++n) {
        GUID a, b; UNICODE_STRING u; unsigned x = n * 2246822519u + 7;
        for (unsigned i = 0; i < 16; ++i) { x = x * 1664525u + 1013904223u; ((BYTE *)&a)[i] = (BYTE)(x >> 24); }
        EXPECT_EQ(UN(RtlStringFromGUID)(&a, &u), 0);
        EXPECT_EQ(UN(RtlGUIDFromString)(&u, &b), 0);
        CHECK(!memcmp(&a, &b, sizeof a));
        UN(RtlFreeUnicodeString)(&u);
    }
}

/* ---- RtlValidateUnicodeString ------------------------------------------- */

TEST(strx_validate_good)
{
    WCHAR b[4] = L"abc"; UNICODE_STRING u = { 6, 8, b }, e = { 0, 0, NULL };
    REQUIRE(UN(RtlValidateUnicodeString));
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
    u.Length = 8;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
    u.Length = 0;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &e), 0);
}

TEST(strx_validate_bad)
{
    WCHAR b[4] = L"abc"; UNICODE_STRING u;
    REQUIRE(UN(RtlValidateUnicodeString));
    u.Buffer = b; u.Length = 5; u.MaximumLength = 8;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), INVALID);       /* odd Length */
    u.Length = 10; u.MaximumLength = 8;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), INVALID);       /* Length > MaximumLength */
    u.Buffer = NULL; u.Length = 2; u.MaximumLength = 2;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), INVALID);       /* data count without a buffer */
    u.Buffer = NULL; u.Length = 0; u.MaximumLength = 4;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), INVALID);
    u.Buffer = b; u.Length = 2; u.MaximumLength = 8;
    EXPECT_EQ(UN(RtlValidateUnicodeString)(1, &u), INVALID);       /* reserved flags must be zero */
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0x80000000, &u), INVALID);
}

TEST(strx_validate_odd_maximum_note)
{
    WCHAR b[4] = L"abc"; UNICODE_STRING u = { 2, 7, b };
    REQUIRE(UN(RtlValidateUnicodeString));
    t_note("odd MaximumLength status 0x%lx", (unsigned long)UN(RtlValidateUnicodeString)(0, &u));
    t_note("NULL string status 0x%lx", (unsigned long)UN(RtlValidateUnicodeString)(0, NULL));
}

/* ---- allocation helpers ------------------------------------------------- */

TEST(strx_create_unicode_string)
{
    UNICODE_STRING u = { 1, 1, (PWSTR)(ULONG_PTR)1 };
    REQUIRE(UN(RtlCreateUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    CHECK(UN(RtlCreateUnicodeString)(&u, L"abc"));
    EXPECT_EQ(u.Length, 6); EXPECT_EQ(u.MaximumLength, 8);
    CHECK(u.Buffer != NULL);
    if (u.Buffer) { EXPECT_WSTR(u.Buffer, L"abc"); EXPECT_EQ(u.Buffer[3], 0); }
    UN(RtlFreeUnicodeString)(&u);
    EXPECT_EQ(u.Buffer, NULL); EXPECT_EQ(u.Length, 0); EXPECT_EQ(u.MaximumLength, 0);
}

TEST(strx_create_unicode_string_empty)
{
    UNICODE_STRING u = { 1, 1, (PWSTR)(ULONG_PTR)1 };
    REQUIRE(UN(RtlCreateUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    CHECK(UN(RtlCreateUnicodeString)(&u, L""));
    EXPECT_EQ(u.Length, 0); EXPECT_EQ(u.MaximumLength, 2);
    CHECK(u.Buffer != NULL);
    if (u.Buffer) EXPECT_EQ(u.Buffer[0], 0);
    UN(RtlFreeUnicodeString)(&u);
}

TEST(strx_create_unicode_string_long)
{
    static WCHAR big[0x8000 + 1];
    UNICODE_STRING u = {0};
    BOOLEAN ok;
    REQUIRE(UN(RtlCreateUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    for (unsigned i = 0; i < 0x7ffe; ++i) big[i] = 'a';
    big[0x7ffe] = 0;                         /* 32766 chars = 65532 bytes; the terminator still fits in 16 bits */
    ok = UN(RtlCreateUnicodeString)(&u, big);
    CHECK(ok);
    if (ok) { EXPECT_EQ(u.Length, 0xFFFC); EXPECT_EQ(u.MaximumLength, 0xFFFE); }
    if (ok) UN(RtlFreeUnicodeString)(&u);
}

TEST(strx_create_unicode_string_from_asciiz)
{
    UNICODE_STRING u = { 1, 1, (PWSTR)(ULONG_PTR)1 };
    REQUIRE(UN(RtlCreateUnicodeStringFromAsciiz)); REQUIRE(UN(RtlFreeUnicodeString));
    CHECK(UN(RtlCreateUnicodeStringFromAsciiz)(&u, "Hello 123"));
    EXPECT_EQ(u.Length, 18); EXPECT_EQ(u.MaximumLength, 20);
    if (u.Buffer) { EXPECT_WSTR(u.Buffer, L"Hello 123"); EXPECT_EQ(u.Buffer[9], 0); }
    UN(RtlFreeUnicodeString)(&u);
    CHECK(UN(RtlCreateUnicodeStringFromAsciiz)(&u, ""));
    EXPECT_EQ(u.Length, 0); EXPECT_EQ(u.MaximumLength, 2);
    UN(RtlFreeUnicodeString)(&u);
}

/* ---- RtlInitAnsiStringEx ------------------------------------------------ */

TEST(strx_init_ansi_ex_basic)
{
    ANSI_STRING a; NTSTATUS st;
    REQUIRE(UN(RtlInitAnsiStringEx));
    memset(&a, 0xcc, sizeof a);
    st = UN(RtlInitAnsiStringEx)(&a, "abc");
    EXPECT_EQ(st, 0); EXPECT_EQ(a.Length, 3); EXPECT_EQ(a.MaximumLength, 4);
    memset(&a, 0xcc, sizeof a);
    st = UN(RtlInitAnsiStringEx)(&a, NULL);
    EXPECT_EQ(st, 0); EXPECT_EQ(a.Length, 0); EXPECT_EQ(a.MaximumLength, 0); EXPECT_EQ(a.Buffer, NULL);
    memset(&a, 0xcc, sizeof a);
    st = UN(RtlInitAnsiStringEx)(&a, "");
    EXPECT_EQ(st, 0); EXPECT_EQ(a.Length, 0); EXPECT_EQ(a.MaximumLength, 1);
}

TEST(strx_init_ansi_ex_limits)
{
    char *big = HeapAlloc(GetProcessHeap(), 0, 0x10010);
    ANSI_STRING a; NTSTATUS st;
    REQUIRE(UN(RtlInitAnsiStringEx));
    if (!big) { t_skip("allocation failed"); return; }
    memset(big, 'x', 0x10010);
    big[0xFFFE] = 0;                        /* length 65534 */
    memset(&a, 0, sizeof a);
    st = UN(RtlInitAnsiStringEx)(&a, big);
    EXPECT_EQ(st, 0); EXPECT_EQ(a.Length, 0xFFFE); EXPECT_EQ(a.MaximumLength, 0xFFFF);
    big[0xFFFE] = 'x'; big[0xFFFF] = 0;     /* length 65535 */
    st = UN(RtlInitAnsiStringEx)(&a, big);
    t_note("length 65535: status 0x%lx Length %u Maximum %u", (unsigned long)st, a.Length, a.MaximumLength);
    big[0xFFFF] = 'x'; big[0x10005] = 0;    /* length 65541 */
    st = UN(RtlInitAnsiStringEx)(&a, big);
    EXPECT_EQ(st, TOOLONG);
    t_note("oversize result fields: Length %u Maximum %u Buffer %p", a.Length, a.MaximumLength, (void *)a.Buffer);
    HeapFree(GetProcessHeap(), 0, big);
}

/* ---- case mapping ------------------------------------------------------- */

TEST(strx_upcase_to_ansi_allocate)
{
    UNICODE_STRING u; ANSI_STRING a = {0};
    REQUIRE(UN(RtlUpcaseUnicodeStringToAnsiString)); REQUIRE(UN(RtlFreeAnsiString));
    init_us(&u, L"Hello, World 42", 0);
    EXPECT_EQ(UN(RtlUpcaseUnicodeStringToAnsiString)(&a, &u, TRUE), 0);
    EXPECT_EQ(a.Length, 15); EXPECT_EQ(a.MaximumLength, 16);
    if (a.Buffer) { CHECK(!memcmp(a.Buffer, "HELLO, WORLD 42", 15)); EXPECT_EQ(a.Buffer[15], 0); }
    UN(RtlFreeAnsiString)(&a);
}

TEST(strx_upcase_to_ansi_caller_buffer)
{
    UNICODE_STRING u; char b[8]; ANSI_STRING a = { 0, 8, b }; NTSTATUS st;
    REQUIRE(UN(RtlUpcaseUnicodeStringToAnsiString));
    memset(b, 0x55, sizeof b);
    init_us(&u, L"abc", 0);
    st = UN(RtlUpcaseUnicodeStringToAnsiString)(&a, &u, FALSE);
    EXPECT_EQ(st, 0); EXPECT_EQ(a.Length, 3); EXPECT_EQ(a.Buffer, b);
    CHECK(!memcmp(b, "ABC", 3));
    a.MaximumLength = 2; a.Length = 0;
    st = UN(RtlUpcaseUnicodeStringToAnsiString)(&a, &u, FALSE);
    CHECKF(st == OVERFLOW || st == SMALL, "undersized buffer status 0x%lx", (unsigned long)st);
}

TEST(strx_upcase_to_multibyte)
{
    static const WCHAR w[] = { 'a', 'b', 'Z', '1', '_' };
    char b[16]; ULONG n = 0x55555555; NTSTATUS st;
    REQUIRE(UN(RtlUpcaseUnicodeToMultiByteN));
    memset(b, 0x55, sizeof b);
    st = UN(RtlUpcaseUnicodeToMultiByteN)(b, sizeof b, &n, w, sizeof w);
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 5);
    CHECK(!memcmp(b, "ABZ1_", 5)); EXPECT_EQ(b[5], 0x55);
    /* short destination: converts what fits */
    memset(b, 0x55, sizeof b); n = 0x55555555;
    st = UN(RtlUpcaseUnicodeToMultiByteN)(b, 3, &n, w, sizeof w);
    CHECKF(st == 0 || st == OVERFLOW, "short destination status 0x%lx", (unsigned long)st);
    EXPECT_EQ(n, 3);
    CHECK(!memcmp(b, "ABZ", 3)); EXPECT_EQ(b[3], 0x55);
    /* odd byte count in the source is rejected */
    n = 0x55555555;
    st = UN(RtlUpcaseUnicodeToMultiByteN)(b, sizeof b, &n, w, 3);
    t_note("odd source byte count: status 0x%lx count %lu", (unsigned long)st, (unsigned long)n);
    /* empty input */
    n = 0x55555555;
    st = UN(RtlUpcaseUnicodeToMultiByteN)(b, sizeof b, &n, w, 0);
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 0);
}

TEST(strx_downcase_unicode_string)
{
    WCHAR out[8]; UNICODE_STRING d = { 0, sizeof out, out }, s;
    static const WCHAR in[] = { 'A', 'b', 'Z', 0x00C9, 0x03A3, 0x0410, '9' };
    static const WCHAR want[] = { 'a', 'b', 'z', 0x00E9, 0x03C3, 0x0430, '9' };
    REQUIRE(UN(RtlDowncaseUnicodeString));
    s.Buffer = (PWSTR)in; s.Length = sizeof in; s.MaximumLength = sizeof in;
    memset(out, 0x55, sizeof out);
    EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&d, &s, FALSE), 0);
    EXPECT_EQ(d.Length, sizeof in); EXPECT_EQ(d.Buffer, out);
    CHECK(!memcmp(out, want, sizeof want));
    EXPECT_EQ(out[7], 0x5555);
}

TEST(strx_downcase_unicode_string_buffers)
{
    WCHAR out[8]; UNICODE_STRING d = { 0, 4, out }, s; NTSTATUS st;
    REQUIRE(UN(RtlDowncaseUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    init_us(&s, L"ABCDEF", 0);
    st = UN(RtlDowncaseUnicodeString)(&d, &s, FALSE);
    EXPECT_EQ(st, OVERFLOW);
    /* in place */
    {
        WCHAR b[4] = { 'Q', 'R', 'S', 0 }; UNICODE_STRING t = { 6, 8, b };
        EXPECT_EQ(UN(RtlDowncaseUnicodeString)(&t, &t, FALSE), 0);
        CHECK(!memcmp(b, L"qrs", 6));
    }
    /* allocating */
    memset(&d, 0, sizeof d);
    st = UN(RtlDowncaseUnicodeString)(&d, &s, TRUE);
    EXPECT_EQ(st, 0); EXPECT_EQ(d.Length, 12);
    if (d.Buffer) { CHECK(!memcmp(d.Buffer, L"abcdef", 12)); UN(RtlFreeUnicodeString)(&d); }
}

TEST(strx_upper_string)
{
    char src[] = "mixed Case 09 _-";
    char dst[32]; ANSI_STRING s = { 16, 17, src }, d = { 0, sizeof dst, dst };
    REQUIRE(UN(RtlUpperString));
    memset(dst, 0x55, sizeof dst);
    UN(RtlUpperString)(&d, &s);
    EXPECT_EQ(d.Length, 16);
    CHECK(!memcmp(dst, "MIXED CASE 09 _-", 16));
    EXPECT_EQ(dst[16], 0x55);
    EXPECT_EQ(src[0], 'm');
    /* the destination capacity limits the copy */
    d.Length = 0; d.MaximumLength = 5;
    UN(RtlUpperString)(&d, &s);
    EXPECT_EQ(d.Length, 5);
}

/* ---- appends and compares ----------------------------------------------- */

TEST(strx_append_asciiz)
{
    char b[8]; ANSI_STRING d = { 0, 8, b }; NTSTATUS st;
    REQUIRE(UN(RtlAppendAsciizToString));
    memset(b, 0x55, sizeof b);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&d, "ab"), 0);
    EXPECT_EQ(d.Length, 2);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&d, "cdef"), 0);
    EXPECT_EQ(d.Length, 6);
    CHECK(!memcmp(b, "abcdef", 6)); EXPECT_EQ(b[6], 0x55);       /* no terminator appended */
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&d, ""), 0);
    EXPECT_EQ(d.Length, 6);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&d, "gh"), 0);          /* fills exactly */
    EXPECT_EQ(d.Length, 8);
    st = UN(RtlAppendAsciizToString)(&d, "i");
    EXPECT_EQ(st, SMALL);
    EXPECT_EQ(d.Length, 8);
    CHECK(!memcmp(b, "abcdefgh", 8));
}

TEST(strx_append_asciiz_null_source)
{
    char b[4]; ANSI_STRING d = { 0, 4, b };
    REQUIRE(UN(RtlAppendAsciizToString));
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&d, NULL), 0);
    EXPECT_EQ(d.Length, 0);
}

TEST(strx_compare_unicode_strings)
{
    static const WCHAR a[] = L"Alpha", b[] = L"alpha", c[] = L"alphb", d[] = L"alph";
    REQUIRE(UN(RtlCompareUnicodeStrings));
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 5, a, 5, FALSE), 0);
    CHECK(UN(RtlCompareUnicodeStrings)(a, 5, b, 5, FALSE) < 0);   /* 'A' < 'a' */
    CHECK(UN(RtlCompareUnicodeStrings)(b, 5, a, 5, FALSE) > 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 5, b, 5, TRUE), 0);
    CHECK(UN(RtlCompareUnicodeStrings)(b, 5, c, 5, TRUE) < 0);
    CHECK(UN(RtlCompareUnicodeStrings)(b, 5, d, 4, FALSE) > 0);   /* longer wins when prefix equal */
    CHECK(UN(RtlCompareUnicodeStrings)(d, 4, b, 5, FALSE) < 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(b, 0, d, 0, FALSE), 0);
    CHECK(UN(RtlCompareUnicodeStrings)(b, 0, d, 4, FALSE) < 0);
    CHECK(UN(RtlCompareUnicodeStrings)(d, 4, b, 0, TRUE) > 0);
    /* lengths count characters, not bytes, and NULs are data */
    {
        static const WCHAR x[] = { 'a', 0, 'b' }, y[] = { 'a', 0, 'c' };
        CHECK(UN(RtlCompareUnicodeStrings)(x, 3, y, 3, FALSE) < 0);
        EXPECT_EQ(UN(RtlCompareUnicodeStrings)(x, 2, y, 2, FALSE), 0);
    }
}

TEST(strx_compare_unicode_strings_non_ascii_case)
{
    static const WCHAR a[] = { 0x00E9 }, b[] = { 0x00C9 }, c[] = { 0x0430 }, d[] = { 0x0410 };
    REQUIRE(UN(RtlCompareUnicodeStrings));
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 1, b, 1, TRUE), 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(c, 1, d, 1, TRUE), 0);
    CHECK(UN(RtlCompareUnicodeStrings)(a, 1, b, 1, FALSE) > 0);
}

/* ---- size helpers ------------------------------------------------------- */

TEST(strx_size_helpers)
{
    ANSI_STRING a = { 5, 6, "hello" }; UNICODE_STRING u = { 10, 12, L"hello" };
    ANSI_STRING e = { 0, 0, NULL }; UNICODE_STRING eu = { 0, 0, NULL };
    REQUIRE(UN(RtlxAnsiStringToUnicodeSize)); REQUIRE(UN(RtlxUnicodeStringToAnsiSize));
    EXPECT_EQ(UN(RtlxAnsiStringToUnicodeSize)(&a), 12);      /* includes a terminator */
    EXPECT_EQ(UN(RtlxUnicodeStringToAnsiSize)(&u), 6);
    EXPECT_EQ(UN(RtlxAnsiStringToUnicodeSize)(&e), 2);
    EXPECT_EQ(UN(RtlxUnicodeStringToAnsiSize)(&eu), 1);
}

/* ---- Int64 -> text ------------------------------------------------------ */

TEST(strx_int64_to_unicode_string)
{
    static const struct { ULONGLONG v; ULONG base; const WCHAR *s; } c[] = {
        { 0, 10, L"0" }, { 7, 10, L"7" }, { 1234567890123ULL, 10, L"1234567890123" },
        { 255, 16, L"FF" }, { 0x123456789ABCDEFULL, 16, L"123456789ABCDEF" },
        { 8, 8, L"10" }, { 5, 2, L"101" }, { 42, 0, L"42" },
    };
    REQUIRE(UN(RtlInt64ToUnicodeString));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        WCHAR b[32]; UNICODE_STRING u = { 0, sizeof b, b }; NTSTATUS st;
        for (unsigned k = 0; k < 32; ++k) b[k] = 0x5555;
        st = UN(RtlInt64ToUnicodeString)(c[i].v, c[i].base, &u);
        CHECKF(st == 0, "case %u status 0x%lx", i, (unsigned long)st);
        if (st == 0) {
            CHECKF(u.Length == lstrlenW(c[i].s) * 2 && !memcmp(b, c[i].s, u.Length), "case %u text", i);
            EXPECT_EQ(u.MaximumLength, sizeof b);
        }
    }
}

TEST(strx_int64_to_unicode_string_errors)
{
    WCHAR b[8]; UNICODE_STRING u = { 0, sizeof b, b }; NTSTATUS st;
    REQUIRE(UN(RtlInt64ToUnicodeString));
    st = UN(RtlInt64ToUnicodeString)(5, 3, &u);               /* only 2, 8, 10, 16 */
    EXPECT_EQ(st, INVALID);
    st = UN(RtlInt64ToUnicodeString)(5, 37, &u);
    EXPECT_EQ(st, INVALID);
    u.MaximumLength = 4;                                       /* "12345" needs 10 bytes */
    st = UN(RtlInt64ToUnicodeString)(12345, 10, &u);
    EXPECT_EQ(st, OVERFLOW);
    u.MaximumLength = 10;                                      /* text fits, terminator does not */
    st = UN(RtlInt64ToUnicodeString)(12345, 10, &u);
    t_note("exact fit without room for a terminator: status 0x%lx Length %u", (unsigned long)st, u.Length);
}

/* ---- normalization ------------------------------------------------------ */

enum { NORM_C = 1, NORM_D = 2, NORM_KC = 5, NORM_KD = 6 };

TEST(strx_normalize_composition)
{
    static const WCHAR decomposed[] = { 'e', 0x0301 }, composed[] = { 0x00E9 };
    WCHAR out[8]; LONG n; NTSTATUS st;
    REQUIRE(UN(RtlNormalizeString));
    n = 8; memset(out, 0, sizeof out);
    st = UN(RtlNormalizeString)(NORM_C, decomposed, 2, out, &n);
    if (st) { t_note("NFC status 0x%lx", (unsigned long)st); return; }
    EXPECT_EQ(n, 1); CHECK(out[0] == 0x00E9);
    n = 8; memset(out, 0, sizeof out);
    st = UN(RtlNormalizeString)(NORM_D, composed, 1, out, &n);
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 2);
    CHECK(out[0] == 'e' && out[1] == 0x0301);
}

TEST(strx_normalize_compat)
{
    static const WCHAR lig[] = { 0xFB01 };               /* fi ligature */
    static const WCHAR width[] = { 0xFF21 };             /* fullwidth A */
    WCHAR out[8]; LONG n; NTSTATUS st;
    REQUIRE(UN(RtlNormalizeString));
    n = 8;
    st = UN(RtlNormalizeString)(NORM_KC, lig, 1, out, &n);
    if (st) { t_note("NFKC status 0x%lx", (unsigned long)st); return; }
    EXPECT_EQ(n, 2); CHECK(out[0] == 'f' && out[1] == 'i');
    n = 8;
    st = UN(RtlNormalizeString)(NORM_KD, width, 1, out, &n);
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 1); CHECK(out[0] == 'A');
    n = 8;
    st = UN(RtlNormalizeString)(NORM_C, lig, 1, out, &n);   /* canonical forms leave compatibility characters */
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 1); CHECK(out[0] == 0xFB01);
}

TEST(strx_normalize_size_query_and_small_buffer)
{
    static const WCHAR in[] = { 0x00E9, 'x' };
    WCHAR out[1]; LONG n; NTSTATUS st;
    REQUIRE(UN(RtlNormalizeString));
    n = 0;
    st = UN(RtlNormalizeString)(NORM_D, in, 2, NULL, &n);
    t_note("size query: status 0x%lx length %ld", (unsigned long)st, (long)n);
    n = 1;
    st = UN(RtlNormalizeString)(NORM_D, in, 2, out, &n);
    t_note("small buffer: status 0x%lx required %ld", (unsigned long)st, (long)n);
    CHECK(st != 0);
}

TEST(strx_is_normalized)
{
    static const WCHAR decomposed[] = { 'e', 0x0301 }, composed[] = { 0x00E9 }, plain[] = { 'a', 'b' };
    BOOLEAN r; NTSTATUS st;
    REQUIRE(UN(RtlIsNormalizedString));
    r = 0xFF; st = UN(RtlIsNormalizedString)(NORM_C, composed, 1, &r);
    if (st) { t_note("status 0x%lx", (unsigned long)st); return; }
    EXPECT_EQ(r, TRUE);
    r = 0xFF; st = UN(RtlIsNormalizedString)(NORM_C, decomposed, 2, &r);
    EXPECT_EQ(st, 0); EXPECT_EQ(r, FALSE);
    r = 0xFF; st = UN(RtlIsNormalizedString)(NORM_D, composed, 1, &r);
    EXPECT_EQ(st, 0); EXPECT_EQ(r, FALSE);
    r = 0xFF; st = UN(RtlIsNormalizedString)(NORM_D, decomposed, 2, &r);
    EXPECT_EQ(st, 0); EXPECT_EQ(r, TRUE);
    r = 0xFF; st = UN(RtlIsNormalizedString)(NORM_KC, plain, 2, &r);
    EXPECT_EQ(st, 0); EXPECT_EQ(r, TRUE);
}

/* ---- text heuristics ---------------------------------------------------- */

TEST(strx_is_text_unicode_signature)
{
    static const WCHAR bom[] = { 0xFEFF, 'a', 'b' }, rbom[] = { 0xFFFE, 'a', 'b' };
    INT flags;
    REQUIRE(UN(RtlIsTextUnicode));
    flags = IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_REVERSE_SIGNATURE;
    CHECK(UN(RtlIsTextUnicode)(bom, sizeof bom, &flags));
    CHECK(flags & IS_TEXT_UNICODE_SIGNATURE);
    CHECK(!(flags & IS_TEXT_UNICODE_REVERSE_SIGNATURE));
    flags = IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_REVERSE_SIGNATURE;
    UN(RtlIsTextUnicode)(rbom, sizeof rbom, &flags);
    CHECK(flags & IS_TEXT_UNICODE_REVERSE_SIGNATURE);
    CHECK(!(flags & IS_TEXT_UNICODE_SIGNATURE));
}

TEST(strx_is_text_unicode_ascii_and_odd)
{
    static const WCHAR wide[] = L"This is plain wide text";
    static const char narrow[] = "This is plain narrow text";
    INT flags;
    REQUIRE(UN(RtlIsTextUnicode));
    flags = IS_TEXT_UNICODE_ASCII16;
    t_note("wide ASCII: result %d flags 0x%x", UN(RtlIsTextUnicode)(wide, sizeof wide - 2, &flags), flags);
    /* a byte count that is not a whole number of characters can never be Unicode text */
    flags = IS_TEXT_UNICODE_ODD_LENGTH;
    UN(RtlIsTextUnicode)(wide, 7, &flags);
    CHECK(flags & IS_TEXT_UNICODE_ODD_LENGTH);
    flags = IS_TEXT_UNICODE_ASCII16 | IS_TEXT_UNICODE_STATISTICS;
    CHECK(!UN(RtlIsTextUnicode)(narrow, sizeof narrow - 1, &flags));
}

TEST(strx_is_text_unicode_null_result)
{
    static const WCHAR bom[] = { 0xFEFF, 'a' };
    REQUIRE(UN(RtlIsTextUnicode));
    CHECK(UN(RtlIsTextUnicode)(bom, sizeof bom, NULL));
}
