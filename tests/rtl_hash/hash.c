#include "t.h"

UDECL(ULONG, RtlComputeCrc32, (ULONG, const void *, ULONG));
UDECL(ULONG, RtlCrc32, (const void *, SIZE_T, ULONG));
UDECL(ULONGLONG, RtlCrc64, (const void *, SIZE_T, ULONGLONG));
UDECL(ULONG, RtlUniform, (ULONG *));

static ULONGLONG crc_reference(const BYTE *p, SIZE_T n, ULONGLONG seed, int kind)
{
    ULONGLONG mask = kind == 2 ? ~(ULONGLONG)0 : 0xffffffff;
    ULONGLONG poly = kind == 2 ? 0x9a6c9329ac4bc9b5ULL :
                       kind == 1 ? 0x82f63b78 : 0xedb88320;
    ULONGLONG c = seed ^ mask;
    SIZE_T i; unsigned bit;
    for (i = 0; i < n; ++i) {
        c ^= p[i];
        for (bit = 0; bit < 8; ++bit) c = (c >> 1) ^ ((c & 1) ? poly : 0);
    }
    return (c ^ mask) & mask;
}

static ULONGLONG crc_call(int kind, const BYTE *p, SIZE_T n, ULONGLONG seed)
{
    if (kind == 0) return UN(RtlComputeCrc32)((ULONG)seed,p,(ULONG)n);
    if (kind == 1) return UN(RtlCrc32)(p,n,(ULONG)seed);
    return UN(RtlCrc64)(p,n,seed);
}

#define REQUIRE_CRC(k) do { \
    if ((k) == 0) { REQUIRE(UN(RtlComputeCrc32)); } \
    else if ((k) == 1) { REQUIRE(UN(RtlCrc32)); } \
    else { REQUIRE(UN(RtlCrc64)); } \
} while (0)

static void vector_case(int kind, const char *text, SIZE_T n, ULONGLONG expected)
{
    BYTE copy[300];
    ULONGLONG result, chunked = 0;
    DWORD error; SIZE_T i;
    REQUIRE_CRC(kind);
    CHECK(n <= sizeof copy);
    if (n > sizeof copy) return;
    memcpy(copy,text,n);
    SET_ERR(0x12345678);
    result = crc_call(kind,(const BYTE *)text,n,0);
    error = GetLastError();
    for (i = 0; i < n; ++i) chunked = crc_call(kind,(const BYTE *)text + i,1,chunked);
    EXPECT_EQ(result,expected); EXPECT_EQ(chunked,expected);
    EXPECT_EQ(error,0x12345678);
    CHECK(!memcmp(copy,text,n));
}
#define VEC(name,k,s,v) TEST(rtl_hash_##name) { vector_case(k,s,sizeof(s)-1,v); }
VEC(ieee_empty,0,"",0)
VEC(ieee_a,0,"a",0xe8b7be43)
VEC(ieee_abc,0,"abc",0x352441c2)
VEC(ieee_digits,0,"123456789",0xcbf43926)
VEC(ieee_fox,0,"The quick brown fox jumps over the lazy dog",0x414fa339)
VEC(castagnoli_empty,1,"",0)
VEC(castagnoli_a,1,"a",0xc1d04330)
VEC(castagnoli_abc,1,"abc",0x364b3fb7)
VEC(castagnoli_digits,1,"123456789",0xe3069283)
VEC(castagnoli_fox,1,"The quick brown fox jumps over the lazy dog",0x22620404)
VEC(crc64_empty,2,"",0)
VEC(crc64_a,2,"a",0x8c2f8445b4cbfc3cULL)
VEC(crc64_abc,2,"abc",0x05e5cabb3fc1faebULL)
VEC(crc64_digits,2,"123456789",0xae8b14860a799888ULL)
VEC(crc64_fox,2,"The quick brown fox jumps over the lazy dog",0xd76c54054954c143ULL)

static void boundary_case(int kind, SIZE_T n, unsigned offset, ULONGLONG seed)
{
    BYTE data[528], before[528];
    ULONGLONG expected, result, chunked;
    SIZE_T i, split;
    DWORD error;
    REQUIRE_CRC(kind);
    CHECK(n + offset <= sizeof data);
    if (n + offset > sizeof data) return;
    for (i = 0; i < sizeof data; ++i) data[i] = (BYTE)(i * 37 + 19);
    memcpy(before,data,sizeof data);
    expected = crc_reference(data + offset,n,seed,kind);
    SET_ERR(0x12345678);
    result = crc_call(kind,data + offset,n,seed);
    error = GetLastError();
    EXPECT_EQ(result,expected); EXPECT_EQ(error,0x12345678);
    /* Every split includes empty prefix/suffix and crosses aligned block paths. */
    for (split = 0; split <= n; ++split) {
        chunked = crc_call(kind,data + offset,split,seed);
        chunked = crc_call(kind,data + offset + split,n - split,chunked);
        EXPECT_EQ(chunked,expected);
    }
    CHECK(!memcmp(before,data,sizeof data));
}
#define BOUND(name,k,n,o,s) TEST(rtl_hash_##name) { boundary_case(k,n,o,s); }
#define BOUNDS(prefix,k,s) \
    BOUND(prefix##_zero_seeded,k,0,1,s) \
    BOUND(prefix##_seven,k,7,1,s) \
    BOUND(prefix##_eight,k,8,0,s) \
    BOUND(prefix##_31,k,31,3,s) \
    BOUND(prefix##_32,k,32,0,s) \
    BOUND(prefix##_63,k,63,7,s) \
    BOUND(prefix##_64,k,64,0,s) \
    BOUND(prefix##_65,k,65,1,s) \
    BOUND(prefix##_255,k,255,5,s) \
    BOUND(prefix##_512,k,512,0,s)
BOUNDS(ieee,0,0x12345678)
BOUNDS(castagnoli,1,0x87654321)
BOUNDS(crc64,2,0x1234567887654321ULL)

static void binary_case(int kind, ULONGLONG expected)
{
    BYTE data[256]; unsigned i;
    REQUIRE_CRC(kind);
    for (i = 0; i < sizeof data; ++i) data[i] = (BYTE)i;
    EXPECT_EQ(crc_call(kind,data,sizeof data,0),expected);
}
TEST(rtl_hash_ieee_binary) { binary_case(0,0x29058c73); }
TEST(rtl_hash_castagnoli_binary) { binary_case(1,0x9c44184b); }
TEST(rtl_hash_crc64_binary) { binary_case(2,0xff71e21279d9966eULL); }

static void uniform_case(ULONG initial)
{
    ULONG seed = initial, expected = initial, result, i;
    DWORD error;
    REQUIRE(UN(RtlUniform));
    /* Reciprocal-multiply reduction in Windows implements this exact modulus. */
    for (i = 0; i < 16; ++i) {
        expected = (ULONG)(((ULONGLONG)expected * 0x7fffffed + 0x7fffffc3) % 0x7fffffff);
        SET_ERR(0x12345678);
        result = UN(RtlUniform)(&seed);
        error = GetLastError();
        EXPECT_EQ(result,expected); EXPECT_EQ(seed,expected);
        EXPECT_EQ(error,0x12345678);
        CHECK(result < 0x7fffffff);
    }
}
#define UNIFORM(name,s) TEST(rtl_hash_uniform_##name) { uniform_case(s); }
UNIFORM(zero,0)
UNIFORM(one,1)
UNIFORM(two,2)
UNIFORM(midrange,0x12345678)
UNIFORM(modulus_minus_one,0x7ffffffe)
UNIFORM(modulus,0x7fffffff)
UNIFORM(high_bit,0x80000000)
UNIFORM(all_bits,0xffffffff)
