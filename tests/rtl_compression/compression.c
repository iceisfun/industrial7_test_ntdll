#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlGetCompressionWorkSpaceSize, (USHORT, PULONG, PULONG));
UDECL(NTSTATUS, RtlCompressBuffer, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID));
UDECL(NTSTATUS, RtlDecompressBuffer, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG));
UDECL(NTSTATUS, RtlDecompressBufferEx, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID));
UDECL(NTSTATUS, RtlDecompressFragment, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID));

#define RC_INVALID ((NTSTATUS)0xc000000d)
#define RC_UNSUPPORTED ((NTSTATUS)0xc000025f)
#define RC_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define RC_SMALL ((NTSTATUS)0xc0000023)
#define RC_ZEROS ((NTSTATUS)0x117)

static void rc_workspace(USHORT format, NTSTATUS expected)
{
    ULONG c = 0xdeadbeef, f = 0xdeadbeef;
    NTSTATUS s;
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize));
    s = UN(RtlGetCompressionWorkSpaceSize)(format, &c, &f);
    EXPECT_EQ(s, expected);
    if (!s) {
        EXPECT_EQ(c, format == 0x102 ? 0x20 : 0x10020);
        EXPECT_EQ(f, 4096);
    } else {
        EXPECT_EQ(c, 0xdeadbeef);
        EXPECT_EQ(f, 0xdeadbeef);
    }
}

/* Dispatch rejects the low-byte format before touching any output or workspace. */
static void rc_invalid(unsigned api, USHORT format)
{
    BYTE input[32] = {0}, output[64], work[64] = {0};
    ULONG final = 0xdeadbeef;
    NTSTATUS s = 0, expected = format < 2 ? RC_INVALID : RC_UNSUPPORTED;
    memset(output, 0xa5, sizeof(output));
    switch (api) {
    case 0:
        REQUIRE(UN(RtlCompressBuffer));
        s = UN(RtlCompressBuffer)(format, input, sizeof(input), output, sizeof(output), 4096, &final, work);
        break;
    case 1:
        REQUIRE(UN(RtlDecompressBuffer));
        s = UN(RtlDecompressBuffer)(format, output, sizeof(output), input, sizeof(input), &final);
        break;
    case 2:
        REQUIRE(UN(RtlDecompressBufferEx));
        s = UN(RtlDecompressBufferEx)(format, output, sizeof(output), input, sizeof(input), &final, work);
        break;
    case 3:
        REQUIRE(UN(RtlDecompressFragment));
        s = UN(RtlDecompressFragment)(format, output, sizeof(output), input, sizeof(input), 0, &final, work);
        break;
    }
    EXPECT_EQ(s, expected);
    EXPECT_EQ(final, 0xdeadbeef);
    for (unsigned i = 0; i < sizeof(output); ++i) EXPECT_EQ(output[i], 0xa5);
}

static void rc_fill(BYTE *p, ULONG n, unsigned pattern)
{
    for (ULONG i = 0; i < n; ++i)
        p[i] = pattern == 0 ? 0 : pattern == 1 ? 'C' : (BYTE)((i % 251) + 1);
}

/* All streams come from the matching compressor; never feed damaged streams. */
static void rc_roundtrip(ULONG n, unsigned pattern, USHORT engine, unsigned api,
                         ULONG offset, ULONG capacity, ULONG chunk)
{
    BYTE input[12288], packed[16384], output[12289];
    ULONG cw = 0, fw = 0, packed_size = 0, final = 0xdeadbeef;
    void *work, *fragment;
    NTSTATUS s;
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize));
    REQUIRE(UN(RtlCompressBuffer));
    if (api == 0) { REQUIRE(UN(RtlDecompressBuffer)); }
    if (api == 1) { REQUIRE(UN(RtlDecompressBufferEx)); }
    if (api == 2) { REQUIRE(UN(RtlDecompressFragment)); }
    CHECK(n <= sizeof(input) && capacity < sizeof(output) && offset <= n);
    if (n > sizeof(input) || capacity >= sizeof(output) || offset > n) return;
    s = UN(RtlGetCompressionWorkSpaceSize)(2 | engine, &cw, &fw);
    EXPECT_EQ(s, 0);
    if (s) return;
    CHECK(cw && fw && cw <= 1024 * 1024 && fw <= 1024 * 1024);
    if (!cw || !fw || cw > 1024 * 1024 || fw > 1024 * 1024) return;
    work = calloc(1, cw); fragment = calloc(1, fw);
    CHECK(work && fragment);
    if (!work || !fragment) { free(work); free(fragment); return; }
    rc_fill(input, n, pattern);
    memset(packed, 0xa5, sizeof(packed));
    s = UN(RtlCompressBuffer)(2 | engine, input, n, packed, sizeof(packed), chunk, &packed_size, work);
    EXPECT_EQ(s, pattern == 0 ? RC_ZEROS : 0);
    CHECK(packed_size > 0 && packed_size <= sizeof(packed));
    if (s < 0 || !packed_size || packed_size > sizeof(packed)) goto done;
    memset(output, 0xa5, sizeof(output));
    if (api == 0)
        s = UN(RtlDecompressBuffer)(2, output, capacity, packed, packed_size, &final);
    else if (api == 1)
        s = UN(RtlDecompressBufferEx)(2, output, capacity, packed, packed_size, &final, fragment);
    else
        s = UN(RtlDecompressFragment)(2, output, capacity, packed, packed_size, offset, &final, fragment);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(final, capacity < n - offset ? capacity : n - offset);
    if (s >= 0 && final <= capacity) CHECK(!memcmp(output, input + offset, final));
    EXPECT_EQ(output[capacity], 0xa5);
done:
    free(fragment); free(work);
}

static void rc_compress_boundary(unsigned mode)
{
    BYTE input[4096], packed[8192], second[8192];
    ULONG cw = 0, fw = 0, size = 0, final = 0xdeadbeef, cap;
    void *work;
    NTSTATUS s;
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize));
    REQUIRE(UN(RtlCompressBuffer));
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw);
    EXPECT_EQ(s, 0);
    if (s || !cw || cw > 1024 * 1024) return;
    work = calloc(1, cw); CHECK(work != NULL); if (!work) return;
    rc_fill(input, sizeof(input), 2);
    s = UN(RtlCompressBuffer)(2, input, sizeof(input), packed, sizeof(packed), 4096, &size, work);
    EXPECT_EQ(s, 0);
    CHECK(size > 1 && size < sizeof(second));
    if (s || size <= 1 || size >= sizeof(second)) { free(work); return; }
    cap = mode == 0 ? 0 : mode == 1 ? size - 1 : size;
    memset(second, 0xa5, sizeof(second));
    s = UN(RtlCompressBuffer)(2, input, sizeof(input), second, cap, 4096, &final, work);
    EXPECT_EQ(s, mode == 2 ? 0 : RC_SMALL);
    if (mode == 2 && !s) { EXPECT_EQ(final, size); CHECK(!memcmp(second, packed, size)); }
    EXPECT_EQ(second[cap], 0xa5);
    free(work);
}

TEST(rtl_compression_workspace_standard) { rc_workspace(2, 0); }
TEST(rtl_compression_workspace_maximum) { rc_workspace(0x102, 0); }
TEST(rtl_compression_workspace_none) { rc_workspace(0, RC_INVALID); }
TEST(rtl_compression_workspace_default) { rc_workspace(1, RC_INVALID); }
TEST(rtl_compression_workspace_unknown) { rc_workspace(5, RC_UNSUPPORTED); }
TEST(rtl_compression_workspace_hiber) { rc_workspace(0x202, RC_NOT_SUPPORTED); }
TEST(rtl_compression_compress_none) { rc_invalid(0, 0); }
TEST(rtl_compression_compress_default) { rc_invalid(0, 1); }
TEST(rtl_compression_compress_unknown) { rc_invalid(0, 5); }
TEST(rtl_compression_decompress_none) { rc_invalid(1, 0); }
TEST(rtl_compression_decompress_default) { rc_invalid(1, 1); }
TEST(rtl_compression_decompress_unknown) { rc_invalid(1, 5); }
TEST(rtl_compression_ex_none) { rc_invalid(2, 0); }
TEST(rtl_compression_ex_default) { rc_invalid(2, 1); }
TEST(rtl_compression_ex_unknown) { rc_invalid(2, 5); }
TEST(rtl_compression_fragment_none) { rc_invalid(3, 0); }
TEST(rtl_compression_fragment_default) { rc_invalid(3, 1); }
TEST(rtl_compression_fragment_unknown) { rc_invalid(3, 5); }
TEST(rtl_compression_roundtrip_one) { rc_roundtrip(1, 2, 0, 0, 0, 1, 4096); }
TEST(rtl_compression_roundtrip_511) { rc_roundtrip(511, 2, 0, 0, 0, 511, 4096); }
TEST(rtl_compression_roundtrip_512) { rc_roundtrip(512, 2, 0, 0, 0, 512, 512); }
TEST(rtl_compression_roundtrip_1024) { rc_roundtrip(1024, 2, 0, 0, 0, 1024, 1024); }
TEST(rtl_compression_roundtrip_2048) { rc_roundtrip(2048, 2, 0, 0, 0, 2048, 2048); }
TEST(rtl_compression_roundtrip_4095) { rc_roundtrip(4095, 2, 0, 0, 0, 4095, 4096); }
TEST(rtl_compression_roundtrip_4096) { rc_roundtrip(4096, 2, 0, 0, 0, 4096, 4096); }
TEST(rtl_compression_roundtrip_4097) { rc_roundtrip(4097, 2, 0, 0, 0, 4097, 4096); }
TEST(rtl_compression_roundtrip_multichunk) { rc_roundtrip(12288, 2, 0, 0, 0, 12288, 4096); }
TEST(rtl_compression_roundtrip_zeros) { rc_roundtrip(4096, 0, 0, 0, 0, 4096, 4096); }
TEST(rtl_compression_roundtrip_maximum) { rc_roundtrip(8192, 2, 0x100, 0, 0, 8192, 4096); }
TEST(rtl_compression_roundtrip_repeated) { rc_roundtrip(4096, 1, 0, 0, 0, 4096, 4096); }
TEST(rtl_compression_ex_exact) { rc_roundtrip(4096, 2, 0, 1, 0, 4096, 4096); }
TEST(rtl_compression_ex_spare) { rc_roundtrip(4096, 2, 0, 1, 0, 4097, 4096); }
TEST(rtl_compression_ex_multichunk) { rc_roundtrip(8192, 2, 0, 1, 0, 8192, 4096); }
TEST(rtl_compression_ex_zeros) { rc_roundtrip(4096, 0, 0, 1, 0, 4096, 4096); }
TEST(rtl_compression_fragment_prefix) { rc_roundtrip(8192, 2, 0, 2, 0, 128, 4096); }
TEST(rtl_compression_fragment_interior) { rc_roundtrip(8192, 2, 0, 2, 123, 257, 4096); }
TEST(rtl_compression_fragment_cross_chunk) { rc_roundtrip(8192, 2, 0, 2, 4000, 256, 4096); }
TEST(rtl_compression_fragment_second_chunk) { rc_roundtrip(8192, 2, 0, 2, 4096, 4096, 4096); }
TEST(rtl_compression_fragment_last_byte) { rc_roundtrip(8192, 2, 0, 2, 8191, 1, 4096); }
TEST(rtl_compression_fragment_maximum) { rc_roundtrip(8192, 2, 0x100, 2, 4097, 127, 4096); }
TEST(rtl_compression_compress_zero_capacity) { rc_compress_boundary(0); }
TEST(rtl_compression_compress_short_capacity) { rc_compress_boundary(1); }
TEST(rtl_compression_compress_exact_capacity) { rc_compress_boundary(2); }
