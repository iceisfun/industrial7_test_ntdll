#include "t.h"

UDECL(SIZE_T, RtlCompareMemory, (const void *, const void *, SIZE_T));
UDECL(SIZE_T, RtlCompareMemoryUlong, (const void *, SIZE_T, ULONG));
UDECL(void, RtlFillMemory, (void *, SIZE_T, UCHAR));
UDECL(void, RtlFillMemoryUlong, (void *, SIZE_T, ULONG));
UDECL(void, RtlMoveMemory, (void *, const void *, SIZE_T));
UDECL(void, RtlZeroMemory, (void *, SIZE_T));
UDECL(void *, RtlEncodePointer, (void *));
UDECL(void *, RtlDecodePointer, (void *));

static void compare_case(SIZE_T n, SIZE_T mismatch, unsigned offset)
{
    BYTE a[258], b[258]; SIZE_T i;
    REQUIRE(UN(RtlCompareMemory));
    for (i = 0; i < sizeof a; ++i) a[i] = b[i] = (BYTE)(i * 37 + 19);
    if (mismatch < n) b[offset + mismatch] ^= 0xff;
    SET_ERR(0x12345678);
    EXPECT_EQ(UN(RtlCompareMemory)(a + offset, b + offset, n), mismatch < n ? mismatch : n);
    EXPECT_ERR(0x12345678);
    EXPECT_EQ(UN(RtlCompareMemory)(b + offset, a + offset, n), mismatch < n ? mismatch : n);
}
#define COMP(name,n,m,o) TEST(rtl_memory_compare_##name) { compare_case(n,m,o); }
COMP(empty,0,0,0)
COMP(one_equal,1,1,0)
COMP(one_different,1,0,0)
COMP(first,64,0,0)
COMP(second,64,1,0)
COMP(qword_end,64,7,0)
COMP(qword_start,64,8,0)
COMP(vector_end,64,15,0)
COMP(vector_start,64,16,0)
COMP(last,64,63,0)
COMP(equal_255,255,255,0)
COMP(unaligned_equal,127,127,1)
COMP(unaligned_middle,127,65,1)

static void ulong_case(SIZE_T n, unsigned mismatch)
{
    ULONG a[20]; unsigned i;
    REQUIRE(UN(RtlCompareMemoryUlong));
    for (i = 0; i < 20; ++i) a[i] = 0x81abcdef;
    if (mismatch < 20) a[mismatch] ^= 1;
    SET_ERR(0x12345678);
    EXPECT_EQ(UN(RtlCompareMemoryUlong)(a,n,0x81abcdef),
              mismatch < n / 4 ? mismatch * 4 : (n / 4) * 4);
    EXPECT_ERR(0x12345678);
}
#define UC(name,n,m) TEST(rtl_memory_ulong_##name) { ulong_case(n,m); }
UC(empty,0,20)
UC(subword,3,20)
UC(one,4,20)
UC(tail_ignored,7,1)
UC(first_mismatch,64,0)
UC(second_mismatch,64,1)
UC(last_mismatch,64,15)
UC(all_equal,64,20)

static void fill_case(SIZE_T n, BYTE value, unsigned offset, int zero)
{
    BYTE a[260]; SIZE_T i; int ok = 1;
    if (zero) { REQUIRE(UN(RtlZeroMemory)); }
    else { REQUIRE(UN(RtlFillMemory)); }
    memset(a,0xa5,sizeof a);
    SET_ERR(0x12345678);
    if (zero) UN(RtlZeroMemory)(a + offset,n);
    else UN(RtlFillMemory)(a + offset,n,value);
    EXPECT_ERR(0x12345678);
    for (i = 0; i < sizeof a; ++i)
        if (a[i] != (i >= offset && i < offset + n ? value : 0xa5)) ok = 0;
    CHECK(ok);
}
#define FILL(name,n,v,o,z) TEST(rtl_memory_##name) { fill_case(n,v,o,z); }
FILL(fill_empty,0,0x12,2,0)
FILL(fill_one,1,0xff,1,0)
FILL(fill_seven,7,0x80,1,0)
FILL(fill_sixteen,16,0x5a,16,0)
FILL(fill_255,255,0xfe,3,0)
FILL(fill_zero_byte,127,0,1,0)
FILL(zero_empty,0,0,1,1)
FILL(zero_one,1,0,1,1)
FILL(zero_seven,7,0,3,1)
FILL(zero_sixteen,16,0,16,1)
FILL(zero_255,255,0,1,1)

static void move_case(unsigned dst, unsigned src, unsigned n)
{
    BYTE a[260], original[260]; unsigned i; int ok = 1;
    REQUIRE(UN(RtlMoveMemory));
    for (i = 0; i < sizeof a; ++i) a[i] = original[i] = (BYTE)(i * 71 + 3);
    SET_ERR(0x12345678);
    UN(RtlMoveMemory)(a + dst,a + src,n);
    EXPECT_ERR(0x12345678);
    for (i = 0; i < sizeof a; ++i)
        if (a[i] != (i >= dst && i < dst + n ? original[src + i - dst] : original[i])) ok = 0;
    CHECK(ok);
}
#define MOVE(name,d,s,n) TEST(rtl_memory_move_##name) { move_case(d,s,n); }
MOVE(empty,1,2,0)
MOVE(one,5,1,1)
MOVE(disjoint,128,1,64)
MOVE(adjacent,65,1,64)
MOVE(self,1,1,127)
MOVE(overlap_right_one,2,1,127)
MOVE(overlap_left_one,1,2,127)
MOVE(overlap_right_vector,17,1,127)
MOVE(overlap_left_vector,1,17,127)
MOVE(overlap_right_long,65,1,191)
MOVE(overlap_left_long,1,65,191)

TEST(rtl_memory_fill_ulong_pattern)
{
    ULONG a[18]; unsigned i;
    REQUIRE(UN(RtlFillMemoryUlong));
    for (i = 0; i < 18; ++i) a[i] = 0xaaaaaaaa;
    UN(RtlFillMemoryUlong)(a + 1,64,0x12345678);
    EXPECT_EQ(a[0],0xaaaaaaaa); EXPECT_EQ(a[17],0xaaaaaaaa);
    for (i = 1; i < 17; ++i) EXPECT_EQ(a[i],0x12345678);
}

static void pointer_case(unsigned kind)
{
    BYTE a[32]; void *p, *encoded;
    REQUIRE(UN(RtlEncodePointer)); REQUIRE(UN(RtlDecodePointer));
    p = kind == 0 ? NULL : kind == 1 ? a : kind == 2 ? a + 1 : a + 31;
    encoded = UN(RtlEncodePointer)(p);
    EXPECT_EQ(UN(RtlDecodePointer)(encoded),p);
    EXPECT_EQ(UN(RtlEncodePointer)(p),encoded);
    EXPECT_EQ(UN(RtlEncodePointer)(UN(RtlDecodePointer)(p)),p);
}
TEST(rtl_memory_pointer_null) { pointer_case(0); }
TEST(rtl_memory_pointer_aligned) { pointer_case(1); }
TEST(rtl_memory_pointer_unaligned) { pointer_case(2); }
TEST(rtl_memory_pointer_last_byte) { pointer_case(3); }
