/* Digests (MD4, MD5, SHA-1 "A_SHA"), NLS data exports, prefix tables, 64-bit bitmaps,
 * access-mask helpers, code-page conversion helpers and CM resource encoding.
 * See EVIDENCE.md for the source of every expectation. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))

/* ---------------------------------------------------------------- digests */
typedef struct { ULONG i[2]; ULONG buf[4]; UCHAR in[64]; UCHAR digest[16]; } MDX_CTX;
typedef struct { ULONG buf[4]; ULONG i[2]; UCHAR in[64]; UCHAR digest[16]; } MD4_CTX_T;
typedef struct { UCHAR buffer[64]; ULONG state[5]; ULONG countHi; ULONG countLo; } SHA_CTX_T;

UDECL(VOID, MD5Init, (MDX_CTX *));
UDECL(VOID, MD5Update, (MDX_CTX *, const void *, ULONG));
UDECL(VOID, MD5Final, (MDX_CTX *));
UDECL(VOID, MD4Init, (MD4_CTX_T *));
UDECL(VOID, MD4Update, (MD4_CTX_T *, const void *, ULONG));
UDECL(VOID, MD4Final, (MD4_CTX_T *));
UDECL(VOID, A_SHAInit, (SHA_CTX_T *));
UDECL(VOID, A_SHAUpdate, (SHA_CTX_T *, const void *, ULONG));
UDECL(VOID, A_SHAFinal, (SHA_CTX_T *, UCHAR *));

static void hex(const UCHAR *p, int n, char *out) { for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]); }

static const char *QF = "The quick brown fox jumps over the lazy dog";

TEST(md5_vectors) {
    REQUIRE(UN(MD5Init)); REQUIRE(UN(MD5Update)); REQUIRE(UN(MD5Final));
    struct { const char *in; const char *want; } v[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { QF, "9e107d9d372bb6826bd81d3542a419d6" },
    };
    for (int k = 0; k < 4; k++) {
        MDX_CTX c; char h[40]; memset(&c, 0xAA, sizeof c);
        UN(MD5Init)(&c);
        EXPECT_EQ(c.i[0], 0); EXPECT_EQ(c.i[1], 0);
        EXPECT_EQ(c.buf[0], 0x67452301); EXPECT_EQ(c.buf[1], 0xefcdab89);
        EXPECT_EQ(c.buf[2], 0x98badcfe); EXPECT_EQ(c.buf[3], 0x10325476);
        UN(MD5Update)(&c, v[k].in, (ULONG)strlen(v[k].in));
        UN(MD5Final)(&c);
        hex(c.digest, 16, h); EXPECT_STR(h, v[k].want);
    }
}
TEST(md5_incremental_and_unaligned) {
    REQUIRE(UN(MD5Init)); REQUIRE(UN(MD5Update)); REQUIRE(UN(MD5Final));
    UCHAR data[200]; for (int i = 0; i < 200; i++) data[i] = (UCHAR)i;
    MDX_CTX a, b, c; UCHAR da[16], db[16], dc[16];
    UN(MD5Init)(&a); UN(MD5Update)(&a, data, 200); UN(MD5Final)(&a); memcpy(da, a.digest, 16);
    UN(MD5Init)(&b); UN(MD5Update)(&b, data, 10); UN(MD5Update)(&b, data + 10, 100); UN(MD5Update)(&b, data + 110, 0);
    UN(MD5Update)(&b, data + 110, 90); UN(MD5Final)(&b); memcpy(db, b.digest, 16);
    EXPECT_EQ(memcmp(da, db, 16), 0);
    /* unaligned source buffer takes a separate copy path for whole blocks */
    __attribute__((aligned(16))) UCHAR buf[260]; memcpy(buf + 1, data, 200);
    UN(MD5Init)(&c); UN(MD5Update)(&c, buf + 1, 200); UN(MD5Final)(&c); memcpy(dc, c.digest, 16);
    EXPECT_EQ(memcmp(da, dc, 16), 0);
    /* Final wipes the pending-input block */
    UCHAR zero[64] = { 0 }; EXPECT_EQ(memcmp(a.in, zero, 64), 0);
    /* million 'a' reference value */
    MDX_CTX m; char h[40]; UCHAR blk[1000]; memset(blk, 'a', sizeof blk);
    UN(MD5Init)(&m); for (int i = 0; i < 1000; i++) UN(MD5Update)(&m, blk, 1000); UN(MD5Final)(&m);
    hex(m.digest, 16, h); EXPECT_STR(h, "7707d6ae4e027c70eea2a935c2296f21");
}
TEST(md4_vectors) {
    REQUIRE(UN(MD4Init)); REQUIRE(UN(MD4Update)); REQUIRE(UN(MD4Final));
    struct { const char *in; const char *want; } v[] = {
        { "", "31d6cfe0d16ae931b73c59d7e0c089c0" },
        { "a", "bde52cb31de33e46245e05fbdbd6fb24" },
        { "abc", "a448017aaf21d8525fc10ae87aa6729d" },
        { "message digest", "d9130a8164549fe818874806e1c7014b" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536" },
    };
    for (int k = 0; k < 5; k++) {
        MD4_CTX_T c; char h[40]; memset(&c, 0x55, sizeof c);
        UN(MD4Init)(&c);
        EXPECT_EQ(c.i[0], 0); EXPECT_EQ(c.i[1], 0);
        EXPECT_EQ(c.buf[0], 0x67452301); EXPECT_EQ(c.buf[3], 0x10325476);
        UN(MD4Update)(&c, v[k].in, (ULONG)strlen(v[k].in));
        UN(MD4Final)(&c);
        hex(c.digest, 16, h); EXPECT_STR(h, v[k].want);
    }
    /* split update equals single update */
    MD4_CTX_T a, b; const char *s = v[4].in;
    UN(MD4Init)(&a); UN(MD4Update)(&a, s, 80); UN(MD4Final)(&a);
    UN(MD4Init)(&b); UN(MD4Update)(&b, s, 7); UN(MD4Update)(&b, s + 7, 70); UN(MD4Update)(&b, s + 77, 3); UN(MD4Final)(&b);
    EXPECT_EQ(memcmp(a.digest, b.digest, 16), 0);
}
TEST(sha1_vectors) {
    REQUIRE(UN(A_SHAInit)); REQUIRE(UN(A_SHAUpdate)); REQUIRE(UN(A_SHAFinal));
    struct { const char *in; const char *want; } v[] = {
        { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { QF, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
    };
    for (int k = 0; k < 4; k++) {
        SHA_CTX_T c; UCHAR d[20]; char h[48]; memset(&c, 0x77, sizeof c);
        UN(A_SHAInit)(&c);
        EXPECT_EQ(c.state[0], 0x67452301); EXPECT_EQ(c.state[1], 0xefcdab89); EXPECT_EQ(c.state[2], 0x98badcfe);
        EXPECT_EQ(c.state[3], 0x10325476); EXPECT_EQ(c.state[4], 0xc3d2e1f0);
        EXPECT_EQ(c.countHi, 0); EXPECT_EQ(c.countLo, 0);
        UN(A_SHAUpdate)(&c, v[k].in, (ULONG)strlen(v[k].in));
        EXPECT_EQ(c.countLo, strlen(v[k].in));
        UN(A_SHAFinal)(&c, d);
        hex(d, 20, h); EXPECT_STR(h, v[k].want);
        /* Final re-arms the context: state is back to the initial vector and the buffer is wiped */
        EXPECT_EQ(c.state[0], 0x67452301); EXPECT_EQ(c.state[4], 0xc3d2e1f0); EXPECT_EQ(c.countLo, 0);
        UCHAR zero[64] = { 0 }; EXPECT_EQ(memcmp(c.buffer, zero, 64), 0);
    }
    /* the re-armed context hashes a second message without Init */
    SHA_CTX_T c; UCHAR d[20]; char h[48];
    UN(A_SHAInit)(&c); UN(A_SHAUpdate)(&c, "abc", 3); UN(A_SHAFinal)(&c, d);
    UN(A_SHAUpdate)(&c, "abc", 3); UN(A_SHAFinal)(&c, d); hex(d, 20, h);
    EXPECT_STR(h, "a9993e364706816aba3e25717850c26c9cd0d89d");
    /* chunked updates across block boundaries, million 'a' */
    UCHAR blk[1000]; memset(blk, 'a', sizeof blk);
    UN(A_SHAInit)(&c); for (int i = 0; i < 1000; i++) UN(A_SHAUpdate)(&c, blk, 1000); UN(A_SHAFinal)(&c, d);
    hex(d, 20, h); EXPECT_STR(h, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    UN(A_SHAInit)(&c); UN(A_SHAUpdate)(&c, QF, 5); UN(A_SHAUpdate)(&c, QF + 5, 38); UN(A_SHAFinal)(&c, d);
    hex(d, 20, h); EXPECT_STR(h, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

/* ------------------------------------------------------------- NLS data */
TEST(nls_data_exports) {
    FARPROC pa = t_proc("NlsAnsiCodePage"), pm = t_proc("NlsMbCodePageTag"), po = t_proc("NlsMbOemCodePageTag");
    if (!pa || !pm || !po) { t_skip("NLS data exports not resolvable"); return; }
    UINT acp = GetACP(), oem = GetOEMCP();
    if (acp == 65001) { t_skip("UTF-8 process code page: NLS tables do not describe a table ACP"); return; }
    EXPECT_EQ(*(ULONG *)pa, acp);
    CPINFO ci;
    if (GetCPInfo(acp, &ci)) EXPECT_EQ(*(BOOLEAN *)pm != 0, ci.MaxCharSize > 1);
    if (oem != 65001 && GetCPInfo(oem, &ci)) EXPECT_EQ(*(BOOLEAN *)po != 0, ci.MaxCharSize > 1);
    EXPECT_NE(pa, pm); EXPECT_NE(pm, po);
}

/* -------------------------------------------------------- prefix tables */
UDECL(VOID, PfxInitialize, (PVOID));
UDECL(BOOLEAN, PfxInsertPrefix, (PVOID, PANSI_STRING, PVOID));
UDECL(PVOID, PfxFindPrefix, (PVOID, PANSI_STRING));
UDECL(VOID, PfxRemovePrefix, (PVOID, PVOID));
typedef struct { __attribute__((aligned(16))) UCHAR b[0x30]; } PFXE;

static void as(ANSI_STRING *s, const char *c) { s->Buffer = (PCHAR)c; s->Length = s->MaximumLength = (USHORT)strlen(c); }

TEST(pfx_table) {
    REQUIRE(UN(PfxInitialize)); REQUIRE(UN(PfxInsertPrefix)); REQUIRE(UN(PfxFindPrefix)); REQUIRE(UN(PfxRemovePrefix));
    __attribute__((aligned(16))) UCHAR tbl[0x10]; memset(tbl, 0xCC, sizeof tbl);
    UN(PfxInitialize)(tbl);
    EXPECT_EQ(*(USHORT *)tbl, 0x200); EXPECT_EQ(*(USHORT *)(tbl + 2), 0);
    EXPECT_EQ(*(PVOID *)(tbl + 8), tbl);
    ANSI_STRING pa, pb, pc, q;
    PFXE ea, eb, ec, ed; memset(&ea, 0, sizeof ea); memset(&eb, 0, sizeof eb); memset(&ec, 0, sizeof ec); memset(&ed, 0, sizeof ed);
    as(&pa, "\\a"); as(&pb, "\\a\\b"); as(&pc, "\\c");
    as(&q, "\\a\\b\\x"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    EXPECT_EQ(UN(PfxInsertPrefix)(tbl, &pa, &ea), TRUE);
    EXPECT_EQ(*(PVOID *)(ea.b + 0x28), &pa);
    EXPECT_EQ(*(USHORT *)(ea.b + 2), 2);
    EXPECT_EQ(UN(PfxInsertPrefix)(tbl, &pb, &eb), TRUE);
    EXPECT_EQ(*(USHORT *)(eb.b + 2), 3);
    EXPECT_EQ(UN(PfxInsertPrefix)(tbl, &pc, &ec), TRUE);
    /* duplicate prefix is rejected */
    EXPECT_EQ(UN(PfxInsertPrefix)(tbl, &pa, &ed), FALSE);
    /* longest matching prefix wins */
    EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &eb);
    as(&q, "\\a\\b"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &eb);
    as(&q, "\\a\\z\\y"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ea);
    as(&q, "\\a"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ea);
    as(&q, "\\c\\d"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ec);
    as(&q, "\\zzz"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    /* matching is case sensitive */
    as(&q, "\\A\\B"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    /* component boundary: "\ab" is not under "\a" */
    as(&q, "\\ab"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    UN(PfxRemovePrefix)(tbl, &eb);
    as(&q, "\\a\\b\\x"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ea);
    UN(PfxRemovePrefix)(tbl, &ea);
    EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    as(&q, "\\c"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ec);
    UN(PfxRemovePrefix)(tbl, &ec);
    EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), NULL);
    /* removed prefix can be inserted again */
    EXPECT_EQ(UN(PfxInsertPrefix)(tbl, &pa, &ed), TRUE);
    as(&q, "\\a\\k"); EXPECT_EQ(UN(PfxFindPrefix)(tbl, &q), &ed);
    UN(PfxRemovePrefix)(tbl, &ed);
}

/* -------------------------------------------------------------- bitmaps */
typedef struct { ULONG64 Size; ULONG64 *Buffer; } BMX;
typedef struct { ULONG Size; ULONG *Buffer; } BM32;
UDECL(BOOLEAN, RtlAreBitsClearEx, (BMX *, ULONG64, ULONG64));
UDECL(VOID, RtlClearAllBitsEx, (BMX *));
UDECL(VOID, RtlClearBitEx, (BMX *, ULONG64));
UDECL(VOID, RtlClearBitsEx, (BMX *, ULONG64, ULONG64));
UDECL(VOID, RtlClearBit, (BM32 *, ULONG));

static int bitx(ULONG64 *b, int n) { return (int)((b[n >> 6] >> (n & 63)) & 1); }
TEST(bitmap_ex_clear) {
    REQUIRE(UN(RtlAreBitsClearEx)); REQUIRE(UN(RtlClearAllBitsEx)); REQUIRE(UN(RtlClearBitEx)); REQUIRE(UN(RtlClearBitsEx));
    ULONG64 buf[4]; BMX bm = { 200, buf };
    memset(buf, 0xFF, sizeof buf);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 0, 1), FALSE);
    UN(RtlClearBitEx)(&bm, 5);
    EXPECT_EQ(bitx(buf, 5), 0); EXPECT_EQ(bitx(buf, 4), 1); EXPECT_EQ(bitx(buf, 6), 1);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 5, 1), TRUE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 4, 1), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 5, 2), FALSE);
    UN(RtlClearBitEx)(&bm, 130);
    EXPECT_EQ(bitx(buf, 130), 0); EXPECT_EQ(bitx(buf, 129), 1);
    /* ranges inside one word, across a word boundary and across several words */
    UN(RtlClearBitsEx)(&bm, 10, 20);
    for (int i = 10; i < 30; i++) EXPECT_EQ(bitx(buf, i), 0);
    EXPECT_EQ(bitx(buf, 9), 1); EXPECT_EQ(bitx(buf, 30), 1);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 10, 20), TRUE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 9, 21), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 10, 21), FALSE);
    UN(RtlClearBitsEx)(&bm, 60, 90);
    for (int i = 60; i < 150; i++) EXPECT_EQ(bitx(buf, i), 0);
    EXPECT_EQ(bitx(buf, 59), 1); EXPECT_EQ(bitx(buf, 150), 1);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 60, 90), TRUE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 59, 91), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 60, 91), FALSE);
    /* clearing zero bits changes nothing */
    ULONG64 save[4]; memcpy(save, buf, sizeof buf);
    UN(RtlClearBitsEx)(&bm, 40, 0); EXPECT_EQ(memcmp(save, buf, sizeof buf), 0);
    /* boundaries of AreBitsClearEx: start past the end, run past the end, zero length */
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 200, 1), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 190, 11), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 60, 0), FALSE);
    UN(RtlClearAllBitsEx)(&bm);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 0, 200), TRUE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 0, 201), FALSE);
    EXPECT_EQ(UN(RtlAreBitsClearEx)(&bm, 199, 1), TRUE);
    /* the clear covers whole 32-bit units: ceil(200/32) = 7 units = 28 bytes */
    ULONG64 z[4] = { 0, 0, 0, 0 }; EXPECT_EQ(memcmp(buf, z, 28), 0);
}
TEST(bitmap_clear_bit) {
    REQUIRE(UN(RtlClearBit));
    ULONG buf[2] = { 0xFFFFFFFF, 0xFFFFFFFF }; BM32 bm = { 64, buf };
    UN(RtlClearBit)(&bm, 0); EXPECT_EQ(buf[0], 0xFFFFFFFE);
    UN(RtlClearBit)(&bm, 31); EXPECT_EQ(buf[0], 0x7FFFFFFE);
    UN(RtlClearBit)(&bm, 32); EXPECT_EQ(buf[1], 0xFFFFFFFE);
    UN(RtlClearBit)(&bm, 63); EXPECT_EQ(buf[1], 0x7FFFFFFE);
    UN(RtlClearBit)(&bm, 0); EXPECT_EQ(buf[0], 0x7FFFFFFE);   /* idempotent */
    UN(RtlClearBit)(&bm, 9); EXPECT_EQ(buf[0], 0x7FFFFDFE);
}

/* -------------------------------------------------- access mask helpers */
UDECL(BOOLEAN, RtlAreAllAccessesGranted, (ACCESS_MASK, ACCESS_MASK));
UDECL(BOOLEAN, RtlAreAnyAccessesGranted, (ACCESS_MASK, ACCESS_MASK));
UDECL(BOOLEAN, RtlAreLongPathsEnabled, (void));
TEST(access_mask_helpers) {
    REQUIRE(UN(RtlAreAllAccessesGranted)); REQUIRE(UN(RtlAreAnyAccessesGranted));
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x1F01FF, 0x120089), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x1, 0x3), FALSE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x3, 0x3), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0, 0), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0, 1), FALSE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0xFFFFFFFF, 0x80000000), TRUE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x1, 0x3), TRUE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x4, 0x3), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0, 0), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0xFFFFFFFF, 0), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x80000000, 0x80000001), TRUE);
}
TEST(long_paths_flag_matches_peb) {
    REQUIRE(UN(RtlAreLongPathsEnabled));
    PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    BOOLEAN want = (((UCHAR *)peb)[3] >> 7) & 1;
    EXPECT_EQ(UN(RtlAreLongPathsEnabled)() != 0, want != 0);
}

/* -------------------------------------------------- code page conversion */
typedef struct {
    USHORT CodePage, MaximumCharacterSize, DefaultChar, UnicodeDefaultChar, TransDefaultChar, TransUniDefaultChar, DBCSCodePage;
    UCHAR LeadByte[12]; PUSHORT MultiByteTable; PVOID WideCharTable; PUSHORT DBCSRanges; PUSHORT DBCSOffsets;
} CPTI;
UDECL(NTSTATUS, RtlCustomCPToUnicodeN, (CPTI *, PWCH, ULONG, PULONG, const CHAR *, ULONG));
UDECL(NTSTATUS, RtlConsoleMultiByteToUnicodeN, (PWCH, ULONG, PULONG, const CHAR *, ULONG, PULONG));

TEST(custom_cp_utf8) {
    REQUIRE(UN(RtlCustomCPToUnicodeN));
    CPTI cp; memset(&cp, 0, sizeof cp); cp.CodePage = 65001;
    WCHAR out[8]; ULONG n = 0xDEAD; memset(out, 0, sizeof out);
    NTSTATUS s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, &n, "A\xC3\xA9z", 4);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 6); EXPECT_EQ(out[0], 'A'); EXPECT_EQ(out[1], 0xE9); EXPECT_EQ(out[2], 'z');
    /* three-byte sequence */
    n = 0; s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, &n, "\xE2\x82\xAC", 3);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 2); EXPECT_EQ(out[0], 0x20AC);
    /* empty input */
    n = 0xDEAD; s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, &n, "", 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 0);
    /* output too small: partial conversion and STATUS_BUFFER_OVERFLOW */
    n = 0; memset(out, 0, sizeof out);
    s = UN(RtlCustomCPToUnicodeN)(&cp, out, 4, &n, "abcd", 4);
    EXPECT_EQ(s, S(0x80000005)); EXPECT_EQ(n, 4); EXPECT_EQ(out[0], 'a'); EXPECT_EQ(out[1], 'b'); EXPECT_EQ(out[2], 0);
    /* result length is optional */
    s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, NULL, "xy", 2);
    EXPECT_EQ(s, 0); EXPECT_EQ(out[0], 'x');
}
TEST(custom_cp_single_byte_table) {
    REQUIRE(UN(RtlCustomCPToUnicodeN));
    static USHORT tab[256]; for (int i = 0; i < 256; i++) tab[i] = (USHORT)(0x100 + i);
    CPTI cp; memset(&cp, 0, sizeof cp); cp.CodePage = 1252; cp.MaximumCharacterSize = 1; cp.MultiByteTable = tab;
    WCHAR out[8]; ULONG n = 0;
    NTSTATUS s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, &n, "\x01\x7F\xFF", 3);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 6); EXPECT_EQ(out[0], 0x101); EXPECT_EQ(out[1], 0x17F); EXPECT_EQ(out[2], 0x1FF);
    /* unsigned bytes index the table */
    n = 0; s = UN(RtlCustomCPToUnicodeN)(&cp, out, 4, &n, "\x80\x81\x82\x83", 4);
    EXPECT_EQ(n, 4); EXPECT_EQ(s, S(0x80000005)); EXPECT_EQ(out[0], 0x180); EXPECT_EQ(out[1], 0x181);
    n = 0xDEAD; s = UN(RtlCustomCPToUnicodeN)(&cp, out, sizeof out, &n, "A", 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 0);
}
TEST(console_multibyte_to_unicode) {
    REQUIRE(UN(RtlConsoleMultiByteToUnicodeN));
    if (GetACP() == 65001) { t_skip("UTF-8 ACP uses a different conversion path"); return; }
    WCHAR out[8]; ULONG n = 0, sp = 0xDEAD;
    NTSTATUS s = UN(RtlConsoleMultiByteToUnicodeN)(out, sizeof out, &n, "AB", 2, &sp);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 4); EXPECT_EQ(out[0], 'A'); EXPECT_EQ(out[1], 'B'); EXPECT_EQ(sp, 0);
    /* control characters below 0x20 are flagged */
    sp = 0; s = UN(RtlConsoleMultiByteToUnicodeN)(out, sizeof out, &n, "A\x01", 2, &sp);
    EXPECT_EQ(s, 0); EXPECT_EQ(sp, 1); EXPECT_EQ(out[0], 'A'); EXPECT_EQ(out[1], 1);
    sp = 0xDEAD; UN(RtlConsoleMultiByteToUnicodeN)(out, sizeof out, &n, "\t", 1, &sp); EXPECT_EQ(sp, 1);
    sp = 0xDEAD; UN(RtlConsoleMultiByteToUnicodeN)(out, sizeof out, &n, " ~", 2, &sp); EXPECT_EQ(sp, 0);
    /* output limits the count; no error status is reported for truncation */
    n = 0; s = UN(RtlConsoleMultiByteToUnicodeN)(out, 2, &n, "abc", 3, &sp);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 2); EXPECT_EQ(out[0], 'a');
    n = 0xDEAD; s = UN(RtlConsoleMultiByteToUnicodeN)(out, sizeof out, &n, "", 0, &sp);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 0);
}

/* ------------------------------------------------ CM resource encoding */
typedef struct { UCHAR Type, Share; USHORT Flags; ULONG StartLo, StartHi; ULONG Length; } CMPD;
#define CMSTART(d) (((ULONG64)(d).StartHi << 32) | (d).StartLo)
UDECL(NTSTATUS, RtlCmEncodeMemIoResource, (CMPD *, UCHAR, ULONG64, ULONG64));
UDECL(ULONG64, RtlCmDecodeMemIoResource, (CMPD *, ULONG64 *));
TEST(cm_mem_io_resource) {
    REQUIRE(UN(RtlCmEncodeMemIoResource)); REQUIRE(UN(RtlCmDecodeMemIoResource));
    CMPD d; ULONG64 start = 0; ULONG64 len;
    memset(&d, 0, sizeof d);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 3, 0x1000, 0x5000), 0);
    EXPECT_EQ(d.Type, 3); EXPECT_EQ(d.Length, 0x1000); EXPECT_EQ(CMSTART(d), 0x5000);
    len = UN(RtlCmDecodeMemIoResource)(&d, &start); EXPECT_EQ(len, 0x1000); EXPECT_EQ(start, 0x5000);
    EXPECT_EQ(UN(RtlCmDecodeMemIoResource)(&d, NULL), 0x1000);
    /* port resource */
    memset(&d, 0, sizeof d);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 1, 0x20, 0x3F8), 0);
    EXPECT_EQ(d.Type, 1); EXPECT_EQ(d.Length, 0x20);
    len = UN(RtlCmDecodeMemIoResource)(&d, &start); EXPECT_EQ(len, 0x20); EXPECT_EQ(start, 0x3F8);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 1, 0x100000000ULL, 0), S(0xC000000D));
    /* large memory: the length is stored scaled by 2^8, 2^16 or 2^32 */
    memset(&d, 0, sizeof d);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 3, 0x100000000ULL, 0x80000000ULL), 0);
    EXPECT_EQ(d.Type, 7); EXPECT_EQ(d.Flags & 0xE00, 0x200); EXPECT_EQ(d.Length, 0x1000000);
    len = UN(RtlCmDecodeMemIoResource)(&d, &start); EXPECT_EQ(len, 0x100000000ULL); EXPECT_EQ(start, 0x80000000ULL);
    memset(&d, 0, sizeof d);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 3, 0x10000000000ULL, 0x1000), 0);
    EXPECT_EQ(d.Type, 7); EXPECT_EQ(d.Flags & 0xE00, 0x400); EXPECT_EQ(d.Length, 0x1000000);
    EXPECT_EQ(UN(RtlCmDecodeMemIoResource)(&d, NULL), 0x10000000000ULL);
    memset(&d, 0, sizeof d);
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 7, 0x1000000000000ULL, 0x1000), 0);
    EXPECT_EQ(d.Type, 7); EXPECT_EQ(d.Flags & 0xE00, 0x800); EXPECT_EQ(d.Length, 0x10000);
    EXPECT_EQ(UN(RtlCmDecodeMemIoResource)(&d, NULL), 0x1000000000000ULL);
    /* unrepresentable lengths and unsupported types */
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 3, 0x100000001ULL, 0), S(0xC0000001));
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 3, 0x10000000001ULL, 0), S(0xC0000001));
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 2, 0x10, 0), S(0xC000000D));
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 0, 0x10, 0), S(0xC000000D));
    EXPECT_EQ(UN(RtlCmEncodeMemIoResource)(&d, 4, 0x10, 0), S(0xC000000D));
}
