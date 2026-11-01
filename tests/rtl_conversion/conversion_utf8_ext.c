#include "t.h"

/* UTF-8 conversion: invalid and boundary sequences, surrogates, size queries. */
UDECL(NTSTATUS, RtlUTF8ToUnicodeN, (PWSTR, ULONG, PULONG, PCSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToUTF8N, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));

#define SOME_NOT_MAPPED ((NTSTATUS)0x00000107)

static NTSTATUS to_wide(const char *s, ULONG n, WCHAR *w, ULONG cap_chars, ULONG *out_chars)
{
    ULONG bytes = 0x55555555;
    NTSTATUS st = UN(RtlUTF8ToUnicodeN)(w, cap_chars * 2, &bytes, s, n);
    *out_chars = bytes / 2;
    return st;
}

TEST(utf8x_decode_valid_boundaries)
{
    static const struct { const char *s; ULONG n; WCHAR w[2]; ULONG chars; } c[] = {
        { "\x7f", 1, { 0x007F }, 1 },
        { "\xc2\x80", 2, { 0x0080 }, 1 },
        { "\xdf\xbf", 2, { 0x07FF }, 1 },
        { "\xe0\xa0\x80", 3, { 0x0800 }, 1 },
        { "\xef\xbf\xbf", 3, { 0xFFFF }, 1 },
        { "\xed\x9f\xbf", 3, { 0xD7FF }, 1 },
        { "\xee\x80\x80", 3, { 0xE000 }, 1 },
        { "\xf0\x90\x80\x80", 4, { 0xD800, 0xDC00 }, 2 },
        { "\xf4\x8f\xbf\xbf", 4, { 0xDBFF, 0xDFFF }, 2 },
        { "\xf0\x9f\x98\x80", 4, { 0xD83D, 0xDE00 }, 2 },
    };
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        WCHAR w[8]; ULONG n; NTSTATUS st;
        for (unsigned k = 0; k < 8; ++k) w[k] = 0x5555;
        st = to_wide(c[i].s, c[i].n, w, 8, &n);
        CHECKF(st == 0, "case %u status 0x%lx", i, (unsigned long)st);
        CHECKF(n == c[i].chars, "case %u produced %lu characters", i, (unsigned long)n);
        for (unsigned k = 0; k < c[i].chars && k < 2; ++k) CHECKF(w[k] == c[i].w[k], "case %u unit %u = 0x%x", i, k, w[k]);
        CHECKF(w[c[i].chars] == 0x5555, "case %u wrote past the result", i);
    }
}

TEST(utf8x_decode_invalid_sequences)
{
    static const struct { const char *s; ULONG n; const char *what; } c[] = {
        { "\xff", 1, "byte never used in UTF-8" },
        { "\xfe", 1, "byte never used in UTF-8 (FE)" },
        { "\x80", 1, "lone continuation" },
        { "\xbf", 1, "lone continuation (BF)" },
        { "\xc0\x80", 2, "overlong NUL" },
        { "\xc1\xbf", 2, "overlong two-byte" },
        { "\xe0\x80\x80", 3, "overlong three-byte" },
        { "\xf0\x80\x80\x80", 4, "overlong four-byte" },
        { "\xed\xa0\x80", 3, "encoded high surrogate" },
        { "\xed\xbf\xbf", 3, "encoded low surrogate" },
        { "\xf4\x90\x80\x80", 4, "above U+10FFFF" },
        { "\xf8\x88\x80\x80\x80", 5, "five-byte form" },
        { "\xc2", 1, "truncated two-byte" },
        { "\xe2\x82", 2, "truncated three-byte" },
        { "\xf0\x9f\x98", 3, "truncated four-byte" },
        { "\xc2\x20", 2, "continuation replaced by ASCII" },
    };
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        WCHAR w[16]; ULONG n; NTSTATUS st; int has_repl = 0;
        for (unsigned k = 0; k < 16; ++k) w[k] = 0x5555;
        st = to_wide(c[i].s, c[i].n, w, 16, &n);
        CHECKF(st == SOME_NOT_MAPPED, "%s: status 0x%lx", c[i].what, (unsigned long)st);
        CHECKF(n >= 1 && n <= c[i].n, "%s: %lu characters", c[i].what, (unsigned long)n);
        for (ULONG k = 0; k < n && k < 16; ++k) if (w[k] == 0xFFFD) has_repl = 1;
        CHECKF(has_repl, "%s: no replacement character", c[i].what);
        t_note("%s: %lu replacement-mapped characters", c[i].what, (unsigned long)n);
    }
}

TEST(utf8x_decode_resync_after_error)
{
    /* ASCII after a bad byte must still be decoded */
    WCHAR w[8]; ULONG n; NTSTATUS st;
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    st = to_wide("A\xff" "B", 3, w, 8, &n);
    EXPECT_EQ(st, SOME_NOT_MAPPED);
    CHECK(n == 3);
    if (n == 3) { EXPECT_EQ(w[0], 'A'); EXPECT_EQ(w[1], 0xFFFD); EXPECT_EQ(w[2], 'B'); }
}

TEST(utf8x_decode_embedded_nul)
{
    WCHAR w[8]; ULONG n; NTSTATUS st;
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    st = to_wide("a\0b", 3, w, 8, &n);
    EXPECT_EQ(st, 0); EXPECT_EQ(n, 3);
    EXPECT_EQ(w[0], 'a'); EXPECT_EQ(w[1], 0); EXPECT_EQ(w[2], 'b');
}

TEST(utf8x_decode_size_query)
{
    ULONG bytes = 0x55555555; NTSTATUS st;
    const char *s = "A\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80";   /* 1 + 2 + 3 + 4 bytes -> 1 + 1 + 1 + 2 characters */
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    st = UN(RtlUTF8ToUnicodeN)(NULL, 0, &bytes, s, 10);
    EXPECT_EQ(st, 0); EXPECT_EQ(bytes, 10);
    bytes = 0x55555555;
    st = UN(RtlUTF8ToUnicodeN)(NULL, 0, &bytes, "", 0);
    EXPECT_EQ(st, 0); EXPECT_EQ(bytes, 0);
    {
        /* output limited to part of the result */
        WCHAR w[2]; bytes = 0x55555555;
        st = UN(RtlUTF8ToUnicodeN)(w, 4, &bytes, s, 10);
        EXPECT_EQ(st, (NTSTATUS)0xC0000023);
        EXPECT_EQ(bytes, 4);
        EXPECT_EQ(w[0], 'A'); EXPECT_EQ(w[1], 0x00E9);
    }
}

TEST(utf8x_encode_boundaries)
{
    static const struct { WCHAR w[2]; ULONG n; const char *s; ULONG len; } c[] = {
        { { 0x0000 }, 1, "\0", 1 },
        { { 0x007F }, 1, "\x7f", 1 },
        { { 0x0080 }, 1, "\xc2\x80", 2 },
        { { 0x07FF }, 1, "\xdf\xbf", 2 },
        { { 0x0800 }, 1, "\xe0\xa0\x80", 3 },
        { { 0xD7FF }, 1, "\xed\x9f\xbf", 3 },
        { { 0xE000 }, 1, "\xee\x80\x80", 3 },
        { { 0xFFFD }, 1, "\xef\xbf\xbd", 3 },
        { { 0xFFFF }, 1, "\xef\xbf\xbf", 3 },
        { { 0xD800, 0xDC00 }, 2, "\xf0\x90\x80\x80", 4 },
        { { 0xDBFF, 0xDFFF }, 2, "\xf4\x8f\xbf\xbf", 4 },
        { { 0xD83D, 0xDE00 }, 2, "\xf0\x9f\x98\x80", 4 },
    };
    REQUIRE(UN(RtlUnicodeToUTF8N));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        char b[16]; ULONG n = 0x55555555; NTSTATUS st;
        memset(b, 0x55, sizeof b);
        st = UN(RtlUnicodeToUTF8N)(b, sizeof b, &n, c[i].w, c[i].n * 2);
        CHECKF(st == 0, "case %u status 0x%lx", i, (unsigned long)st);
        CHECKF(n == c[i].len && !memcmp(b, c[i].s, c[i].len), "case %u encoded %lu bytes", i, (unsigned long)n);
        CHECKF(b[c[i].len] == 0x55, "case %u wrote past the result", i);
        /* size query agrees with the real conversion */
        n = 0x55555555;
        st = UN(RtlUnicodeToUTF8N)(NULL, 0, &n, c[i].w, c[i].n * 2);
        CHECKF(st == 0 && n == c[i].len, "case %u size query %lu", i, (unsigned long)n);
    }
}

TEST(utf8x_encode_unpaired_surrogates)
{
    static const WCHAR low_first[] = { 0xDC00, 0xD800 };
    static const WCHAR high_then_ascii[] = { 0xD800, 'A' };
    static const WCHAR high_high[] = { 0xD800, 0xD800 };
    static const WCHAR low_only[] = { 0xDFFF };
    char b[16]; ULONG n; NTSTATUS st;
    REQUIRE(UN(RtlUnicodeToUTF8N));
    memset(b, 0x55, sizeof b);
    st = UN(RtlUnicodeToUTF8N)(b, sizeof b, &n, high_then_ascii, 4);
    EXPECT_EQ(st, SOME_NOT_MAPPED); EXPECT_EQ(n, 4);
    CHECK(!memcmp(b, "\xef\xbf\xbd" "A", 4));
    st = UN(RtlUnicodeToUTF8N)(b, sizeof b, &n, low_only, 2);
    EXPECT_EQ(st, SOME_NOT_MAPPED); EXPECT_EQ(n, 3);
    CHECK(!memcmp(b, "\xef\xbf\xbd", 3));
    st = UN(RtlUnicodeToUTF8N)(b, sizeof b, &n, low_first, 4);
    EXPECT_EQ(st, SOME_NOT_MAPPED);
    t_note("reversed pair encodes to %lu bytes", (unsigned long)n);
    st = UN(RtlUnicodeToUTF8N)(b, sizeof b, &n, high_high, 4);
    EXPECT_EQ(st, SOME_NOT_MAPPED);
    t_note("two high surrogates encode to %lu bytes", (unsigned long)n);
}

TEST(utf8x_encode_destination_limits)
{
    static const WCHAR w[] = { 'A', 0x00E9, 0x20AC, 0xD83D, 0xDE00 };   /* 1 + 2 + 3 + 4 bytes */
    static const ULONG want[] = { 0, 1, 1, 3, 3, 3, 6, 6, 6, 6, 10 };
    REQUIRE(UN(RtlUnicodeToUTF8N));
    for (unsigned cap = 0; cap <= 10; ++cap) {
        char b[16]; ULONG n = 0x55555555; NTSTATUS st;
        memset(b, 0x55, sizeof b);
        st = UN(RtlUnicodeToUTF8N)(b, cap, &n, w, sizeof w);
        CHECKF(st == (cap < 10 ? (NTSTATUS)0xC0000023 : 0), "capacity %u status 0x%lx", cap, (unsigned long)st);
        CHECKF(n == want[cap], "capacity %u wrote %lu bytes want %lu", cap, (unsigned long)n, (unsigned long)want[cap]);
        CHECKF(b[cap] == 0x55, "capacity %u overran", cap);
    }
}

TEST(utf8x_roundtrip_bmp_sample)
{
    WCHAR in[64], out[64]; char mid[256]; ULONG nb, nw; unsigned i, count = 0;
    REQUIRE(UN(RtlUnicodeToUTF8N)); REQUIRE(UN(RtlUTF8ToUnicodeN));
    for (i = 1; i < 0x10000 && count < 64; i += 997) {
        if (i >= 0xD800 && i <= 0xDFFF) continue;
        in[count++] = (WCHAR)i;
    }
    EXPECT_EQ(UN(RtlUnicodeToUTF8N)(mid, sizeof mid, &nb, in, count * 2), 0);
    EXPECT_EQ(UN(RtlUTF8ToUnicodeN)(out, sizeof out, &nw, mid, nb), 0);
    EXPECT_EQ(nw, count * 2);
    CHECK(!memcmp(in, out, count * 2));
}
