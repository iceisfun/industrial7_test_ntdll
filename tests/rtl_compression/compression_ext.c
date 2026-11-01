/* Additional compression coverage: stream structure, incompressible data, the
   XPRESS formats when available, parameter errors and damaged-stream safety. */
#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlGetCompressionWorkSpaceSize, (USHORT, PULONG, PULONG));
UDECL(NTSTATUS, RtlCompressBuffer, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID));
UDECL(NTSTATUS, RtlDecompressBuffer, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG));
UDECL(NTSTATUS, RtlDecompressBufferEx, (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID));

#define CX_SUCCESS(s) ((s) >= 0)

static ULONG cx_state;
static BYTE cx_rand(void) { cx_state = cx_state * 1103515245u + 12345u; return (BYTE)(cx_state >> 16); }

/* kind 0: all 'A'; 1: pseudo-random bytes; 2: repeating text; 3: sparse zeros with marks */
static void cx_fill(BYTE *p, ULONG n, int kind, ULONG seed)
{
    static const char text[] = "the quick brown fox jumps over the lazy dog. ";
    ULONG i; cx_state = seed;
    for (i = 0; i < n; ++i)
        p[i] = kind == 0 ? 'A' : kind == 1 ? cx_rand() : kind == 2 ? (BYTE)text[i % (sizeof(text) - 1)]
                                                                   : (BYTE)((i % 97) == 0 ? (i & 0xff) | 1 : 0);
}

/* Compress then decompress with the same format; returns packed size via *packed_out or 0 on failure. */
static int cx_roundtrip(USHORT format, int kind, ULONG n, ULONG chunk, ULONG *packed_out)
{
    BYTE *in = malloc(n + 1), *packed = malloc(n + n / 2 + 4096), *out = malloc(n + 16);
    ULONG cw = 0, fw = 0, psize = 0, final = 0xdeadbeef; void *work = NULL, *frag = NULL;
    NTSTATUS s; int ok = 0;
    if (!in || !packed || !out) goto done;
    s = UN(RtlGetCompressionWorkSpaceSize)(format, &cw, &fw);
    if (s) { t_note("workspace size for format 0x%x: 0x%08lx", format, (ULONG)s); goto done; }
    work = calloc(1, cw + 16); frag = calloc(1, fw + 16);
    cx_fill(in, n, kind, 1000 + n);
    memset(packed, 0xa5, n + n / 2 + 4096);
    s = UN(RtlCompressBuffer)(format, in, n, packed, n + n / 2 + 4096, chunk, &psize, work);
    CHECKF(CX_SUCCESS(s), "compress fmt=0x%x kind=%d n=%lu status=0x%08lx", format, kind, n, (ULONG)s);
    if (!CX_SUCCESS(s)) goto done;
    memset(out, 0xa5, n + 16);
    if ((format & 0xff) == 2) s = UN(RtlDecompressBuffer)(format & 0xff, out, n + 16, packed, psize, &final);
    else s = UN(RtlDecompressBufferEx)(format & 0xff, out, n, packed, psize, &final, frag);   /* XPRESS needs the Ex form with a work space and the exact output size */
    CHECKF(CX_SUCCESS(s), "decompress fmt=0x%x kind=%d n=%lu status=0x%08lx", format, kind, n, (ULONG)s);
    if (!CX_SUCCESS(s)) goto done;
    EXPECT_EQ(final, n);
    CHECKF(final == n && !memcmp(out, in, n), "payload mismatch fmt=0x%x kind=%d n=%lu", format, kind, n);
    ok = 1; if (packed_out) *packed_out = psize;
done:
    free(in); free(packed); free(out); free(work); free(frag);
    return ok;
}

TEST(rtl_compression_ext_lznt1_incompressible_roundtrip) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    static const ULONG sizes[] = {1, 100, 4095, 4096, 4097, 9000, 20000};
    unsigned i;
    for (i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) cx_roundtrip(2, 1, sizes[i], 4096, NULL);
}

TEST(rtl_compression_ext_lznt1_text_roundtrip) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    static const ULONG sizes[] = {45, 46, 1000, 4096, 4100, 30000};
    unsigned i; ULONG packed;
    for (i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i)
        if (cx_roundtrip(2, 2, sizes[i], 4096, &packed) && sizes[i] >= 1000) CHECK(packed < sizes[i]);
}

TEST(rtl_compression_ext_lznt1_sparse_roundtrip) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    static const ULONG sizes[] = {97, 98, 5000, 16384};
    unsigned i;
    for (i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) cx_roundtrip(2, 3, sizes[i], 4096, NULL);
}

TEST(rtl_compression_ext_lznt1_maximum_engine_roundtrip) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    cx_roundtrip(0x102, 2, 20000, 4096, NULL);
    cx_roundtrip(0x102, 1, 5000, 4096, NULL);
}

TEST(rtl_compression_ext_lznt1_runs_shrink_substantially) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    ULONG packed = 0;
    if (cx_roundtrip(2, 0, 16384, 4096, &packed)) CHECK(packed < 16384 / 8);
}

/* Walk the chunk headers of a compressed LZNT1 stream. */
TEST(rtl_compression_ext_lznt1_chunk_headers_well_formed) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer));
    enum { N = 3 * 4096 + 1000 };
    BYTE *in = malloc(N), *packed = malloc(N * 2); ULONG cw = 0, fw = 0, psize = 0, pos = 0; int chunks = 0;
    void *work = NULL; NTSTATUS s;
    if (!in || !packed) goto done;
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw); EXPECT_EQ(s, 0); if (s) goto done;
    work = calloc(1, cw + 16);
    cx_fill(in, N, 2, 77);
    s = UN(RtlCompressBuffer)(2, in, N, packed, N * 2, 4096, &psize, work);
    CHECK(CX_SUCCESS(s)); if (!CX_SUCCESS(s)) goto done;
    while (pos + 2 <= psize) {
        USHORT hdr = (USHORT)(packed[pos] | (packed[pos + 1] << 8));
        if (hdr == 0) { pos += 2; break; }
        CHECKF((hdr & 0x7000) == 0x3000, "chunk %d header 0x%04x signature bits", chunks, hdr);
        pos += (hdr & 0x0fff) + 3; ++chunks;
        if (chunks > 16) break;
    }
    EXPECT_EQ(chunks, 4);
    EXPECT_EQ(pos, psize);
done:
    free(in); free(packed); free(work);
}

TEST(rtl_compression_ext_xpress_formats_if_available) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    ULONG cw, fw; USHORT fmt;
    for (fmt = 3; fmt <= 4; ++fmt) {
        NTSTATUS s = UN(RtlGetCompressionWorkSpaceSize)(fmt, &cw, &fw);
        t_note("workspace size for format %u: status 0x%08lx", fmt, (ULONG)s);
        if (s != 0) continue;
        cx_roundtrip(fmt, 2, 10000, 4096, NULL);
        cx_roundtrip(fmt, 1, 5000, 4096, NULL);
        cx_roundtrip(fmt, 0, 8192, 4096, NULL);
    }
}

TEST(rtl_compression_ext_lznt1_alternate_chunk_sizes) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    static const ULONG chunks[] = {512, 1024, 2048, 4096};
    unsigned i;
    for (i = 0; i < sizeof(chunks)/sizeof(*chunks); ++i) cx_roundtrip(2, 2, 10000, chunks[i], NULL);
}

TEST(rtl_compression_ext_decompress_output_too_small) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    enum { N = 8192 };
    BYTE *in = malloc(N), *packed = malloc(N * 2), *out = malloc(N); ULONG cw = 0, fw = 0, psize = 0, final = 0xdeadbeef;
    void *work = NULL; NTSTATUS s;
    if (!in || !packed || !out) goto done;
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw); if (s) goto done;
    work = calloc(1, cw + 16);
    cx_fill(in, N, 2, 5);
    s = UN(RtlCompressBuffer)(2, in, N, packed, N * 2, 4096, &psize, work);
    if (!CX_SUCCESS(s)) goto done;
    memset(out, 0xa5, N);
    s = UN(RtlDecompressBuffer)(2, out, 100, packed, psize, &final);
    t_note("decompress into 100 of %d bytes: status 0x%08lx final %lu", N, (ULONG)s, final);
    /* Whatever the status, nothing beyond the supplied capacity may be written. */
    EXPECT_EQ(out[100], 0xa5); EXPECT_EQ(out[N - 1], 0xa5);
    if (CX_SUCCESS(s)) { CHECK(final <= 100); CHECK(!memcmp(out, in, final)); }
done:
    free(in); free(packed); free(out); free(work);
}

TEST(rtl_compression_ext_compress_output_too_small_status) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer));
    BYTE in[4096], out[64]; ULONG cw = 0, fw = 0, psize = 0xdeadbeef; void *work; NTSTATUS s;
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw); if (s) return;
    work = calloc(1, cw + 16); if (!work) return;
    cx_fill(in, sizeof(in), 1, 9);       /* incompressible: cannot fit into 64 bytes */
    s = UN(RtlCompressBuffer)(2, in, sizeof(in), out, sizeof(out), 4096, &psize, work);
    CHECK(!CX_SUCCESS(s));
    t_note("compress 4096 random bytes into 64: status 0x%08lx", (ULONG)s);
    free(work);
}

TEST(rtl_compression_ext_compress_empty_input) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer));
    BYTE in[1] = {0}, out[64]; ULONG cw = 0, fw = 0, psize = 0xdeadbeef; void *work; NTSTATUS s;
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw); if (s) return;
    work = calloc(1, cw + 16); if (!work) return;
    s = UN(RtlCompressBuffer)(2, in, 0, out, sizeof(out), 4096, &psize, work);
    t_note("compress empty input: status 0x%08lx size %lu", (ULONG)s, psize);
    free(work);
}

/* Damaged streams must be rejected or decoded safely, never overrun the output.
   Runs in a child process so a fault cannot affect the rest of the area. */
CHILD(rtl_compression_ext_damage_child) {
    enum { N = 6000 };
    BYTE *in = malloc(N), *packed = malloc(N * 2), *out = malloc(N + 64); ULONG cw = 0, fw = 0, psize = 0, final;
    void *work; unsigned trial; int guard_ok = 1;
    if (!UN(RtlGetCompressionWorkSpaceSize) || !UN(RtlCompressBuffer) || !UN(RtlDecompressBuffer)) return 0;
    if (UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw)) return 0;
    work = calloc(1, cw + 16);
    cx_fill(in, N, 2, 3);
    if (!CX_SUCCESS(UN(RtlCompressBuffer)(2, in, N, packed, N * 2, 4096, &psize, work))) return 0;
    for (trial = 0; trial < 300; ++trial) {
        BYTE *copy = malloc(psize); ULONG cut = psize;
        memcpy(copy, packed, psize);
        cx_state = trial * 7 + 1;
        if (trial & 1) cut = 1 + (cx_rand() | (cx_rand() << 8)) % psize;   /* truncate */
        else { ULONG k; for (k = 0; k < 1 + trial % 4; ++k) copy[(cx_rand() | (cx_rand() << 8)) % psize] ^= (BYTE)(1 + cx_rand() % 255); }
        memset(out, 0xa5, N + 64);
        final = 0;
        UN(RtlDecompressBuffer)(2, out, N, copy, cut, &final);
        { unsigned g; for (g = N; g < N + 64; ++g) if (out[g] != 0xa5) guard_ok = 0; }
        free(copy);
    }
    return guard_ok ? 0 : 3;
}
TEST(rtl_compression_ext_damaged_streams_are_contained) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer)); REQUIRE(UN(RtlDecompressBuffer));
    EXPECT_EQ(t_run_child("rtl_compression_ext_damage_child", NULL, 60000), 0);
}

TEST(rtl_compression_ext_decompress_ex_matches_plain) {
    REQUIRE(UN(RtlGetCompressionWorkSpaceSize)); REQUIRE(UN(RtlCompressBuffer));
    REQUIRE(UN(RtlDecompressBuffer)); REQUIRE(UN(RtlDecompressBufferEx));
    enum { N = 10000 };
    BYTE *in = malloc(N), *packed = malloc(N * 2), *a = malloc(N), *b = malloc(N);
    ULONG cw = 0, fw = 0, psize = 0, fa = 0, fb = 0; void *work = NULL, *frag = NULL; NTSTATUS s;
    if (!in || !packed || !a || !b) goto done;
    s = UN(RtlGetCompressionWorkSpaceSize)(2, &cw, &fw); if (s) goto done;
    work = calloc(1, cw + 16); frag = calloc(1, fw + 16);
    cx_fill(in, N, 2, 11);
    s = UN(RtlCompressBuffer)(2, in, N, packed, N * 2, 4096, &psize, work);
    if (!CX_SUCCESS(s)) goto done;
    EXPECT_EQ(UN(RtlDecompressBuffer)(2, a, N, packed, psize, &fa), 0);
    EXPECT_EQ(UN(RtlDecompressBufferEx)(2, b, N, packed, psize, &fb, frag), 0);
    EXPECT_EQ(fa, N); EXPECT_EQ(fb, N);
    CHECK(!memcmp(a, in, N)); CHECK(!memcmp(b, in, N));
done:
    free(in); free(packed); free(a); free(b); free(work); free(frag);
}
