/* RtlWow64 cross-process work lists: lock-free free list and work list stored inside a shared block.
 * Header is a 64-bit word: low 31 bits = byte offset of the first entry from the header, bit 31 = heavy-flush
 * request, high 32 bits = sequence number bumped by every update. */
#include "t.h"

UDECL(BOOLEAN, RtlWow64PushCrossProcessWorkOntoFreeList, (ULONG64 *, ULONG *));
UDECL(ULONG *, RtlWow64PopCrossProcessWorkFromFreeList, (ULONG64 *));
UDECL(BOOLEAN, RtlWow64PushCrossProcessWorkOntoWorkList, (ULONG64 *, ULONG *, ULONG **));
UDECL(ULONG *, RtlWow64PopAllCrossProcessWorkFromWorkList, (ULONG64 *, BOOLEAN *));
UDECL(BOOLEAN, RtlWow64RequestCrossProcessHeavyFlush, (ULONG64 *));

#define SEQ(h) ((ULONG)((h) >> 32))
#define LOW(h) ((ULONG)(h) & 0x7fffffff)

static __attribute__((aligned(64))) BYTE blk[0x400];
#define HDR ((ULONG64 *)blk)
#define ENT(o) ((ULONG *)(blk + (o)))

TEST(free_list)
{
    REQUIRE(UN(RtlWow64PushCrossProcessWorkOntoFreeList)); REQUIRE(UN(RtlWow64PopCrossProcessWorkFromFreeList));
    memset(blk, 0, sizeof blk);
    EXPECT_EQ(UN(RtlWow64PopCrossProcessWorkFromFreeList)(HDR), 0);       /* empty */
    EXPECT_EQ(*HDR, 0);
    *ENT(0x40) = 0xdeadbeef; *ENT(0x80) = 0xdeadbeef;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoFreeList)(HDR, ENT(0x40)), 1);
    EXPECT_EQ(*ENT(0x40), 0); EXPECT_EQ(LOW(*HDR), 0x40); EXPECT_EQ(SEQ(*HDR), 1);
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoFreeList)(HDR, ENT(0x80)), 1);
    EXPECT_EQ(*ENT(0x80), 0x40); EXPECT_EQ(LOW(*HDR), 0x80); EXPECT_EQ(SEQ(*HDR), 2);
    EXPECT_EQ(UN(RtlWow64PopCrossProcessWorkFromFreeList)(HDR), ENT(0x80));   /* LIFO */
    EXPECT_EQ(*ENT(0x80), 0); EXPECT_EQ(LOW(*HDR), 0x40); EXPECT_EQ(SEQ(*HDR), 3);
    EXPECT_EQ(UN(RtlWow64PopCrossProcessWorkFromFreeList)(HDR), ENT(0x40));
    EXPECT_EQ(LOW(*HDR), 0); EXPECT_EQ(SEQ(*HDR), 4);
    ULONG64 h = *HDR;
    EXPECT_EQ(UN(RtlWow64PopCrossProcessWorkFromFreeList)(HDR), 0);
    EXPECT_EQ(*HDR, h);                                                   /* empty pop leaves the header alone */
    /* the flush-request bit survives pushes */
    *HDR = 0x80000000ull;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoFreeList)(HDR, ENT(0x40)), 1);
    EXPECT_EQ((ULONG)*HDR, 0x80000040); EXPECT_EQ(SEQ(*HDR), 1);
}

TEST(heavy_flush_and_work_list)
{
    REQUIRE(UN(RtlWow64RequestCrossProcessHeavyFlush)); REQUIRE(UN(RtlWow64PushCrossProcessWorkOntoWorkList));
    REQUIRE(UN(RtlWow64PopAllCrossProcessWorkFromWorkList));
    memset(blk, 0, sizeof blk);
    BOOLEAN fl = 9; ULONG *rej;
    EXPECT_EQ(UN(RtlWow64PopAllCrossProcessWorkFromWorkList)(HDR, &fl), 0);   /* empty, no request */
    EXPECT_EQ(fl, 0); EXPECT_EQ(*HDR, 0);

    ULONG *a = ENT(0x40), *b = ENT(0x80), *c = ENT(0xc0);
    memset(blk + 0x40, 0, 0xc0);                       /* entry type word != 8: never coalesced */
    rej = (ULONG *)1;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, a, &rej), 1);
    EXPECT_EQ(rej, 0); EXPECT_EQ(*a, 0); EXPECT_EQ(LOW(*HDR), 0x40); EXPECT_EQ(SEQ(*HDR), 1);
    rej = (ULONG *)1;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, b, &rej), 1);
    EXPECT_EQ(rej, 0); EXPECT_EQ(*b, 0x40); EXPECT_EQ(LOW(*HDR), 0x80); EXPECT_EQ(SEQ(*HDR), 2);

    /* pop all returns the entries oldest first, header cleared, sequence bumped */
    fl = 9;
    ULONG *r = UN(RtlWow64PopAllCrossProcessWorkFromWorkList)(HDR, &fl);
    EXPECT_EQ(r, a); EXPECT_EQ(fl, 0);
    EXPECT_EQ(*a, 0x80); EXPECT_EQ(*b, 0);
    EXPECT_EQ(*HDR, 3ull << 32);

    /* a heavy flush request sets bit 31 and bumps the sequence */
    ULONG64 h = *HDR;
    EXPECT_EQ(UN(RtlWow64RequestCrossProcessHeavyFlush)(HDR), 1);
    EXPECT_EQ(*HDR, (h + (1ull << 32)) | 0x80000000);
    /* with a request pending, pushes are refused: entry handed back, list not linked */
    memset(blk + 0x40, 0, 0xc0);
    h = *HDR; rej = (ULONG *)1;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, c, &rej), 1);
    EXPECT_EQ(rej, c); EXPECT_EQ(LOW(*HDR), 0); EXPECT_EQ(*c, 0);
    EXPECT_EQ(*HDR, h + (1ull << 32));
    /* pop all reports and clears the request even when the list is empty */
    fl = 9;
    EXPECT_EQ(UN(RtlWow64PopAllCrossProcessWorkFromWorkList)(HDR, &fl), 0);
    EXPECT_EQ(fl, 1);
    EXPECT_EQ((ULONG)*HDR & 0x80000000, 0);
    EXPECT_EQ(LOW(*HDR), 0);
}

TEST(work_list_coalescing)
{
    REQUIRE(UN(RtlWow64PushCrossProcessWorkOntoWorkList)); REQUIRE(UN(RtlWow64PopAllCrossProcessWorkFromWorkList));
    memset(blk, 0, sizeof blk);
    /* entry: +0 next, +4 type (8), +8 start, +16 length. A new entry starting where the head entry ends
     * absorbs it: the head entry is handed back for reuse and the new one covers both ranges. */
    ULONG *a = ENT(0x40), *b = ENT(0x80);
    a[1] = 8; *(ULONG64 *)(a + 2) = 0x1000; *(ULONG64 *)(a + 4) = 0x1000;
    b[1] = 8; *(ULONG64 *)(b + 2) = 0x2000; *(ULONG64 *)(b + 4) = 0x500;
    ULONG *rej = (ULONG *)1;
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, a, &rej), 1);
    EXPECT_EQ(rej, 0); EXPECT_EQ(LOW(*HDR), 0x40);
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, b, &rej), 1);
    EXPECT_EQ(rej, a);
    EXPECT_EQ(LOW(*HDR), 0x80);
    EXPECT_EQ(*(ULONG64 *)(b + 2), 0x1000); EXPECT_EQ(*(ULONG64 *)(b + 4), 0x1500);
    EXPECT_EQ(*b, 0);
    BOOLEAN fl;
    EXPECT_EQ(UN(RtlWow64PopAllCrossProcessWorkFromWorkList)(HDR, &fl), b);
    EXPECT_EQ(fl, 0);
    /* non-adjacent ranges are linked, not merged */
    memset(blk, 0, sizeof blk);
    a[1] = 8; *(ULONG64 *)(a + 2) = 0x1000; *(ULONG64 *)(a + 4) = 0x1000;
    b[1] = 8; *(ULONG64 *)(b + 2) = 0x5000; *(ULONG64 *)(b + 4) = 0x500;
    UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, a, &rej);
    EXPECT_EQ(UN(RtlWow64PushCrossProcessWorkOntoWorkList)(HDR, b, &rej), 1);
    EXPECT_EQ(rej, 0); EXPECT_EQ(*b, 0x40); EXPECT_EQ(*(ULONG64 *)(b + 4), 0x500);
}
