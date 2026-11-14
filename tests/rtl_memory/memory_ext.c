/* Block moves, pattern fills and in-memory obfuscation helpers. */
#include "t.h"

UDECL(void, RtlMoveMemory, (void *, const void *, SIZE_T));
UDECL(void, RtlFillMemory, (void *, SIZE_T, UCHAR));
UDECL(void, RtlFillMemoryUlong, (void *, SIZE_T, ULONG));
UDECL(void, RtlFillMemoryUlonglong, (void *, SIZE_T, ULONGLONG));
UDECL(void, RtlCopyMemoryNonTemporal, (void *, const void *, SIZE_T));
UDECL(void, RtlZeroMemory, (void *, SIZE_T));
UDECL(SIZE_T, RtlCompareMemoryUlong, (const void *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlEncryptMemory, (void *, ULONG, ULONG));
UDECL(NTSTATUS, RtlDecryptMemory, (void *, ULONG, ULONG));
UDECL(void, RtlRunEncodeUnicodeString, (PUCHAR, PUNICODE_STRING));
UDECL(void, RtlRunDecodeUnicodeString, (UCHAR, PUNICODE_STRING));

static void mx_pattern(BYTE *p, SIZE_T n) { SIZE_T i; for (i = 0; i < n; ++i) p[i] = (BYTE)(i * 29 + 7); }

TEST(rtl_memory_ext_move_overlap_forward_and_backward) {
    REQUIRE(UN(RtlMoveMemory));
    static const SIZE_T lens[] = {1, 7, 8, 15, 16, 17, 31, 32, 33, 100};
    static const int shifts[] = {-17, -9, -8, -1, 1, 3, 8, 16, 21};
    unsigned li, si; int bad = 0;
    for (li = 0; li < sizeof(lens)/sizeof(*lens); ++li)
        for (si = 0; si < sizeof(shifts)/sizeof(*shifts); ++si) {
            BYTE buf[320], ref[320]; BYTE *src = buf + 100, *dst = buf + 100 + shifts[si];
            mx_pattern(buf, sizeof(buf)); memcpy(ref, buf, sizeof(buf));
            memmove(ref + 100 + shifts[si], ref + 100, lens[li]);
            UN(RtlMoveMemory)(dst, src, lens[li]);
            if (memcmp(buf, ref, sizeof(buf))) bad++;
        }
    CHECK(bad == 0);
}

TEST(rtl_memory_ext_move_zero_length_and_same_pointer) {
    REQUIRE(UN(RtlMoveMemory));
    BYTE a[32], b[32]; mx_pattern(a, 32); memcpy(b, a, 32);
    UN(RtlMoveMemory)(a, a + 5, 0); CHECK(!memcmp(a, b, 32));
    UN(RtlMoveMemory)(a, a, 32); CHECK(!memcmp(a, b, 32));
}

TEST(rtl_memory_ext_fill_bytes_with_guards) {
    REQUIRE(UN(RtlFillMemory));
    static const SIZE_T lens[] = {0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255};
    unsigned i, off; int bad = 0;
    for (i = 0; i < sizeof(lens)/sizeof(*lens); ++i)
        for (off = 0; off < 17; off += 3) {
            BYTE b[320]; SIZE_T k; memset(b, 0xa5, sizeof(b));
            UN(RtlFillMemory)(b + 32 + off, lens[i], 0x3c);
            for (k = 0; k < sizeof(b); ++k) {
                BYTE want = (k >= 32 + off && k < 32 + off + lens[i]) ? 0x3c : 0xa5;
                if (b[k] != want) bad++;
            }
        }
    CHECK(bad == 0);
}

TEST(rtl_memory_ext_zero_with_guards) {
    REQUIRE(UN(RtlZeroMemory));
    static const SIZE_T lens[] = {0, 1, 3, 8, 16, 33, 64, 100, 200};
    unsigned i; int bad = 0;
    for (i = 0; i < sizeof(lens)/sizeof(*lens); ++i) {
        BYTE b[320]; SIZE_T k; memset(b, 0xff, sizeof(b));
        UN(RtlZeroMemory)(b + 40, lens[i]);
        for (k = 0; k < sizeof(b); ++k) {
            BYTE want = (k >= 40 && k < 40 + lens[i]) ? 0 : 0xff;
            if (b[k] != want) bad++;
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_memory_ext_copy_non_temporal) {
    REQUIRE(UN(RtlCopyMemoryNonTemporal));
    static const SIZE_T lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 1000};
    unsigned i; int bad = 0;
    for (i = 0; i < sizeof(lens)/sizeof(*lens); ++i) {
        BYTE src[1100], dst[1100]; SIZE_T k;
        mx_pattern(src, sizeof(src)); memset(dst, 0x77, sizeof(dst));
        UN(RtlCopyMemoryNonTemporal)(dst + 8, src + 3, lens[i]);
        for (k = 0; k < sizeof(dst); ++k) {
            BYTE want = (k >= 8 && k < 8 + lens[i]) ? src[3 + k - 8] : 0x77;
            if (dst[k] != want) bad++;
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_memory_ext_run_encode_decode_unicode_round_trip) {
    REQUIRE(UN(RtlRunEncodeUnicodeString)); REQUIRE(UN(RtlRunDecodeUnicodeString));
    static WCHAR text[] = L"Round trip me, 0123456789";
    WCHAR work[32]; UNICODE_STRING us; UCHAR seed = 0;
    memcpy(work, text, sizeof(text));
    us.Buffer = work; us.Length = sizeof(text) - sizeof(WCHAR); us.MaximumLength = sizeof(text);
    UN(RtlRunEncodeUnicodeString)(&seed, &us);
    CHECK(seed != 0);
    CHECK(memcmp(work, text, us.Length) != 0);
    UN(RtlRunDecodeUnicodeString)(seed, &us);
    CHECK(!memcmp(work, text, us.Length));
    EXPECT_EQ(us.Length, sizeof(text) - sizeof(WCHAR));
}

TEST(rtl_memory_ext_run_encode_fixed_seed_is_deterministic) {
    REQUIRE(UN(RtlRunEncodeUnicodeString));
    WCHAR a[8] = L"abcdefg", b[8] = L"abcdefg"; UNICODE_STRING ua, ub; UCHAR sa = 0, sb = 0;
    ua.Buffer = a; ua.Length = 14; ua.MaximumLength = 16;
    ub.Buffer = b; ub.Length = 14; ub.MaximumLength = 16;
    /* A zero seed asks for one to be generated; a supplied nonzero seed is used as is. */
    UN(RtlRunEncodeUnicodeString)(&sa, &ua);
    sb = sa;
    UN(RtlRunEncodeUnicodeString)(&sb, &ub);
    EXPECT_EQ(sb, sa);
    CHECK(!memcmp(a, b, 14));
}
