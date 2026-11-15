#include "t.h"
#include <stdlib.h>

typedef struct { ULONG_PTR SizeOfBitMap; PULONG64 Buffer; } BITMAPEX;
typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } BITMAP32;
typedef struct { ULONG MaximumNumberOfHandles, SizeOfHandleTableEntry; ULONG Reserved[2]; PVOID FreeHandles, CommittedHandles, UnCommittedHandles, MaxReservedHandles; } HTAB;
typedef struct { LIST_ENTRY Linkage; ULONG_PTR Signature; } HENTRY;
typedef struct { BYTE raw[128]; } HENUM;

UDECL(VOID, RtlInitializeBitMapEx, (BITMAPEX *, PULONG64, ULONG_PTR));
UDECL(ULONG_PTR, RtlFindSetBitsEx, (BITMAPEX *, ULONG_PTR, ULONG_PTR));
UDECL(ULONG_PTR, RtlFindClearBitsEx, (BITMAPEX *, ULONG_PTR, ULONG_PTR));
UDECL(ULONG_PTR, RtlFindSetBitsAndClearEx, (BITMAPEX *, ULONG_PTR, ULONG_PTR));
UDECL(VOID, RtlInitializeBitMap, (BITMAP32 *, PULONG, ULONG));
UDECL(VOID, RtlCopyBitMap, (BITMAP32 *, BITMAP32 *, ULONG));
UDECL(VOID, RtlExtractBitMap, (BITMAP32 *, BITMAP32 *, ULONG, ULONG));
UDECL(VOID, RtlInitializeHandleTable, (ULONG, ULONG, HTAB *));
UDECL(NTSTATUS, RtlDestroyHandleTable, (HTAB *));
UDECL(PVOID, RtlAllocateHandle, (HTAB *, PULONG));
UDECL(BOOLEAN, RtlFreeHandle, (HTAB *, PVOID));
UDECL(BOOLEAN, RtlIsValidHandle, (HTAB *, PVOID));
UDECL(NTSTATUS, RtlCreateMemoryZone, (PVOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlAllocateMemoryZone, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlExtendMemoryZone, (PVOID, SIZE_T));
UDECL(NTSTATUS, RtlDestroyMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryBlockLookaside, (PVOID *, ULONG, SIZE_T, SIZE_T, SIZE_T));
UDECL(NTSTATUS, RtlAllocateMemoryBlockLookaside, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlFreeMemoryBlockLookaside, (PVOID, PVOID));
UDECL(NTSTATUS, RtlExtendMemoryBlockLookaside, (PVOID, SIZE_T));
UDECL(NTSTATUS, RtlDestroyMemoryBlockLookaside, (PVOID));
UDECL(NTSTATUS, RtlInitBarrier, (PVOID, ULONG, ULONG));
UDECL(BOOLEAN, RtlCreateHashTable, (PVOID *, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (PVOID));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (PVOID, HENTRY *, ULONG_PTR, PVOID));
UDECL(BOOLEAN, RtlInitEnumerationHashTable, (PVOID, HENUM *));
UDECL(BOOLEAN, RtlInitWeakEnumerationHashTable, (PVOID, HENUM *));
UDECL(BOOLEAN, RtlInitStrongEnumerationHashTable, (PVOID, HENUM *));
UDECL(HENTRY *, RtlEnumerateEntryHashTable, (PVOID, HENUM *));
UDECL(VOID, RtlEndEnumerationHashTable, (PVOID, HENUM *));
UDECL(HENTRY *, RtlWeaklyEnumerateEntryHashTable, (PVOID, HENUM *));
UDECL(VOID, RtlEndWeakEnumerationHashTable, (PVOID, HENUM *));
UDECL(HENTRY *, RtlStronglyEnumerateEntryHashTable, (PVOID, HENUM *));
UDECL(VOID, RtlEndStrongEnumerationHashTable, (PVOID, HENUM *));
UDECL(NTSTATUS, RtlAllocateActivationContextStack, (PVOID *));
UDECL(VOID, RtlFreeActivationContextStack, (PVOID));
UDECL(VOID, RtlFreeThreadActivationContextStack, (VOID));
UDECL(VOID, RtlInitializeContext, (HANDLE, PCONTEXT, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, RtlCopyContext, (PCONTEXT, ULONG, PCONTEXT));
UDECL(BOOLEAN, RtlConvertSRWLockExclusiveToShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockShared, (PRTL_SRWLOCK));
UDECL(VOID, RtlReleaseSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockShared, (PRTL_SRWLOCK));
UDECL(BOOLEAN, RtlTryAcquireSRWLockExclusive, (PRTL_SRWLOCK));
UDECL(NTSTATUS, RtlCopyMemoryStreamTo, (PVOID, PVOID, ULONGLONG, PULONGLONG, PULONGLONG));
UDECL(NTSTATUS, RtlCopyOutOfProcessMemoryStreamTo, (PVOID, PVOID, ULONGLONG, PULONGLONG, PULONGLONG));
UDECL(NTSTATUS, RtlFreeNonVolatileToken, (PVOID));
UDECL(VOID, RtlInitializeResource, (PVOID));
UDECL(VOID, RtlDeleteResource, (PVOID));
UDECL(BOOLEAN, RtlAcquireResourceExclusive, (PVOID, BOOLEAN));
UDECL(BOOLEAN, RtlAcquireResourceShared, (PVOID, BOOLEAN));
UDECL(VOID, RtlReleaseResource, (PVOID));
UDECL(VOID, RtlConvertExclusiveToShared, (PVOID));
UDECL(VOID, RtlConvertSharedToExclusive, (PVOID));
UDECL(PVOID, RtlAllocateHeap, (PVOID, ULONG, SIZE_T));

#define ST(x) ((NTSTATUS)(x))
#define NOTFOUND ((ULONG_PTR)-1)

TEST(rtl_net_ip_str_a_bitmap_ex_find) {
    REQUIRE(UN(RtlInitializeBitMapEx)); REQUIRE(UN(RtlFindSetBitsEx)); REQUIRE(UN(RtlFindClearBitsEx)); REQUIRE(UN(RtlFindSetBitsAndClearEx));
    ULONG64 buf[2] = {0, 0}; BITMAPEX bm; memset(&bm, 0xcc, sizeof bm);
    UN(RtlInitializeBitMapEx)(&bm, buf, 128);
    EXPECT_EQ(bm.SizeOfBitMap, 128); EXPECT_EQ(bm.Buffer, buf);
    buf[0] = 0x7C00;                 /* bits 10..14 */
    buf[1] = 1ULL << 6;              /* bit 70 */
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 5, 0), 10);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 1, 0), 10);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 2, 11), 11);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 6, 0), NOTFOUND);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 1, 15), 70);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 1, 71), 10);      /* wraps to find a run before the hint */
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 1, 5000), 10);    /* hint beyond end restarts at 0 */
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 129, 0), NOTFOUND);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 10, 0), 0);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 11, 0), 15);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 55, 0), 15);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 56, 0), 71);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 57, 0), 71);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 58, 0), NOTFOUND);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 3, 10), 15);
    EXPECT_EQ(UN(RtlFindSetBitsAndClearEx)(&bm, 3, 0), 10);     EXPECT_EQ(buf[0], 0x6000ULL);                         /* bits 10..12 cleared */
    EXPECT_EQ(UN(RtlFindSetBitsAndClearEx)(&bm, 3, 0), NOTFOUND); EXPECT_EQ(buf[0], 0x6000ULL);
    EXPECT_EQ(UN(RtlFindSetBitsAndClearEx)(&bm, 1, 0), 13); EXPECT_EQ(buf[0], 0x4000ULL);
    /* run crossing the 64-bit word boundary */
    buf[0] = 0xF000000000000000ULL; buf[1] = 0x3;
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 6, 0), 60);
    EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 7, 0), NOTFOUND);
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 60, 0), 0);
    buf[0] = ~0ULL; buf[1] = ~0ULL;
    EXPECT_EQ(UN(RtlFindClearBitsEx)(&bm, 1, 0), NOTFOUND); EXPECT_EQ(UN(RtlFindSetBitsEx)(&bm, 128, 0), 0);
}
static void fill32(ULONG *b, int n) { for (int i = 0; i < n; i++) b[i] = 0; }
TEST(rtl_net_ip_str_a_bitmap_copy_extract) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlCopyBitMap)); REQUIRE(UN(RtlExtractBitMap));
    ULONG sb[4] = {0xA5A5A5A5, 0x12345678, 0, 0}, db[4]; BITMAP32 src, dst;
    UN(RtlInitializeBitMap)(&src, sb, 64);
    fill32(db, 4); UN(RtlInitializeBitMap)(&dst, db, 128);
    /* extract 32 bits at byte-aligned start */
    BITMAP32 out; ULONG ob[1] = {0xFFFFFFFF}; UN(RtlInitializeBitMap)(&out, ob, 32);
    UN(RtlExtractBitMap)(&src, &out, 8, 32);
    EXPECT_EQ(ob[0], (ULONG)(((ULONGLONG)sb[1] << 24 | sb[0] >> 8) & 0xFFFFFFFF));
    /* unaligned start */
    ob[0] = 0; UN(RtlExtractBitMap)(&src, &out, 3, 20);
    EXPECT_EQ(ob[0] & 0xFFFFF, (sb[0] >> 3) & 0xFFFFF);
    /* count limited by destination size */
    BITMAP32 small; ULONG smb[1] = {0}; UN(RtlInitializeBitMap)(&small, smb, 8);
    UN(RtlExtractBitMap)(&src, &small, 0, 32); EXPECT_EQ(smb[0], 0xA5);
    /* count limited by source remainder */
    ob[0] = 0; UN(RtlExtractBitMap)(&src, &out, 60, 32); EXPECT_EQ(ob[0] & 0xF, sb[1] >> 28);
    /* copy: byte-aligned destination offset */
    fill32(db, 4); UN(RtlCopyBitMap)(&src, &dst, 32);
    EXPECT_EQ(db[0], 0); EXPECT_EQ(db[1], 0xA5A5A5A5); EXPECT_EQ(db[2], 0x12345678); EXPECT_EQ(db[3], 0);
    /* copy: unaligned destination offset, bits outside the range preserved */
    db[0] = 0xFFFFFFFF; db[1] = 0xFFFFFFFF; db[2] = 0xFFFFFFFF; db[3] = 0xFFFFFFFF;
    BITMAP32 s8; ULONG s8b[1] = {0}; UN(RtlInitializeBitMap)(&s8, s8b, 8);
    UN(RtlCopyBitMap)(&s8, &dst, 4);
    EXPECT_EQ(db[0], 0xFFFFF00F); EXPECT_EQ(db[1], 0xFFFFFFFF);
    /* copy limited by destination end */
    fill32(db, 4); UN(RtlCopyBitMap)(&src, &dst, 100);
    EXPECT_EQ(db[0], 0); EXPECT_EQ(db[3], 0x5A5A5A50);   /* 28 bits fit: bits 100..127 */
}
TEST(rtl_net_ip_str_a_handle_table) {
    REQUIRE(UN(RtlInitializeHandleTable)); REQUIRE(UN(RtlAllocateHandle)); REQUIRE(UN(RtlFreeHandle)); REQUIRE(UN(RtlIsValidHandle)); REQUIRE(UN(RtlDestroyHandleTable));
    HTAB t; memset(&t, 0xcc, sizeof t);
    UN(RtlInitializeHandleTable)(32, 32, &t);
    EXPECT_EQ(t.MaximumNumberOfHandles, 32); EXPECT_EQ(t.SizeOfHandleTableEntry, 32);
    EXPECT_EQ(t.FreeHandles, NULL); EXPECT_EQ(t.CommittedHandles, NULL);
    ULONG i0 = 99, i1 = 99, i2 = 99;
    BYTE *h0 = UN(RtlAllocateHandle)(&t, &i0), *h1 = UN(RtlAllocateHandle)(&t, &i1), *h2 = UN(RtlAllocateHandle)(&t, &i2);
    CHECK(h0 && h1 && h2);
    if (h0 && h1 && h2) {
        EXPECT_NE(h0, h1); EXPECT_NE(h1, h2); EXPECT_NE(h0, h2);
        EXPECT_NE(i0, i1); EXPECT_NE(i1, i2);
        EXPECT_EQ((ULONG)((h1 - h0) / 32 * 32), (ULONG)(h1 - h0));     /* entries are entry-size multiples apart */
        EXPECT_EQ(((ULONG_PTR)h0) & 31, 0);
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, h0) & 1, 0);                  /* not yet flagged allocated */
        *(ULONG *)h0 = 1;                                                /* RTL_HANDLE_ALLOCATED */
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, h0) & 1, 1);
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, h0 + 8) & 1, 0);              /* misaligned */
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, NULL) & 1, 0);
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, &t) & 1, 0);                  /* outside the table */
        ULONG_PTR *w = (ULONG_PTR *)h1; w[1] = 0x1234;                   /* dirty payload */
        EXPECT_EQ(UN(RtlFreeHandle)(&t, h1) & 1, 1);
        EXPECT_EQ(w[1], 0);                                              /* freed entry is zeroed */
        EXPECT_EQ(UN(RtlIsValidHandle)(&t, h1) & 1, 0);
        ULONG ir = 0; PVOID r = UN(RtlAllocateHandle)(&t, &ir);
        EXPECT_EQ(r, h1); EXPECT_EQ(ir, i1);                              /* LIFO reuse */
        UN(RtlFreeHandle)(&t, r);
        EXPECT_EQ(UN(RtlFreeHandle)(&t, h0) & 1, 1);
        EXPECT_EQ(UN(RtlFreeHandle)(&t, h2) & 1, 1);
    }
    EXPECT_EQ(UN(RtlDestroyHandleTable)(&t), 0);
}
TEST(rtl_net_ip_str_a_memory_zone) {
    REQUIRE(UN(RtlCreateMemoryZone)); REQUIRE(UN(RtlAllocateMemoryZone)); REQUIRE(UN(RtlExtendMemoryZone)); REQUIRE(UN(RtlDestroyMemoryZone));
    PVOID zone = NULL;
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0, 0), ST(0xC000000D));
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0x1000, 1), ST(0xC000000D));
    zone = NULL;
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0x1000, 0), 0);
    CHECK(zone != NULL);
    if (!zone) return;
    PVOID a = (PVOID)1, b = (PVOID)1;
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 0, &a), ST(0xC000000D)); EXPECT_EQ(a, NULL);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 10, &a), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 8, &b), 0);
    CHECK(a && b); EXPECT_EQ(((ULONG_PTR)a) & 7, 0);
    EXPECT_EQ((ULONG_PTR)b - (ULONG_PTR)a, 16);        /* 10 rounds to 16 */
    memset(a, 0xaa, 10); memset(b, 0xbb, 8); EXPECT_EQ(((BYTE *)a)[9], 0xaa);
    /* exhaust */
    NTSTATUS s = 0; int n = 0; PVOID p;
    while (n < 100000 && (s = UN(RtlAllocateMemoryZone)(zone, 512, &p)) == 0) n++;
    EXPECT_EQ(s, ST(0xC000009A)); EXPECT_EQ(p, NULL); CHECK(n > 0 && n < 100000);
    EXPECT_EQ(UN(RtlExtendMemoryZone)(zone, 0), ST(0xC000000D));
    EXPECT_EQ(UN(RtlExtendMemoryZone)(zone, 0x4000), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 512, &p), 0); CHECK(p != NULL);
    if (p) memset(p, 1, 512);
    EXPECT_EQ(UN(RtlDestroyMemoryZone)(zone), 0);
}
TEST(rtl_net_ip_str_a_memory_block_lookaside) {
    REQUIRE(UN(RtlCreateMemoryBlockLookaside)); REQUIRE(UN(RtlAllocateMemoryBlockLookaside)); REQUIRE(UN(RtlFreeMemoryBlockLookaside));
    REQUIRE(UN(RtlExtendMemoryBlockLookaside)); REQUIRE(UN(RtlDestroyMemoryBlockLookaside));
    PVOID la = NULL;
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x4000, 0, 256), ST(0xC000000D)); EXPECT_EQ(la, NULL);
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x4000, 512, 256), ST(0xC000000D));
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 1, 0x4000, 16, 256), ST(0xC000000D));
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0, 16, 256), ST(0xC000000D));
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x8000, 16, 256), 0);
    CHECK(la != NULL); if (!la) return;
    PVOID a = NULL, b = NULL, big = (PVOID)1;
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 100, &a), 0);
    CHECK(a != NULL); if (a) { memset(a, 0x5a, 100); }
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 16, &b), 0);
    CHECK(b != NULL && a != b);
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 257, &big), ST(0xC000000D));   /* above maximum block size */
    EXPECT_EQ(UN(RtlFreeMemoryBlockLookaside)(la, a), 0);
    PVOID c = NULL; EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 100, &c), 0);
    EXPECT_EQ(c, a);                                                                    /* freed block recycled */
    UN(RtlFreeMemoryBlockLookaside)(la, c); UN(RtlFreeMemoryBlockLookaside)(la, b);
    UN(RtlExtendMemoryBlockLookaside)(la, 0x4000);
    EXPECT_EQ(UN(RtlDestroyMemoryBlockLookaside)(la), 0);
}
TEST(rtl_net_ip_str_a_init_barrier) {
    REQUIRE(UN(RtlInitBarrier));
    ULONG64 b[5]; memset(b, 0xcc, sizeof b);
    EXPECT_EQ(UN(RtlInitBarrier)(b, 3, 0), 0);
    EXPECT_EQ(b[0], 0); EXPECT_EQ(b[1], 0); EXPECT_EQ(*(ULONG *)&b[2], 3);
    EXPECT_EQ(UN(RtlInitBarrier)(b, 1, 100), 0); EXPECT_EQ(*(ULONG *)&b[2], 1);
    EXPECT_EQ(UN(RtlInitBarrier)(NULL, 1, 0), ST(0xC000000D));
}
static void hash_enum_case(const char *nm, BOOLEAN (WINAPI *init)(PVOID, HENUM *), HENTRY *(WINAPI *enm)(PVOID, HENUM *), VOID (WINAPI *endf)(PVOID, HENUM *)) {
    PVOID ht = NULL;
    BOOLEAN s = UN(RtlCreateHashTable)(&ht, 0, 0);
    CHECKF((s & 1) && ht, "%s: create %02x", nm, (unsigned)s);
    if (!(s & 1) || !ht) return;
    HENUM en; HENTRY e[5];
    memset(&en, 0, sizeof en);
    CHECKF(init(ht, &en) & 1, "%s init empty", nm);
    CHECKF(enm(ht, &en) == NULL, "%s empty enumerate", nm);
    endf(ht, &en);
    for (int i = 0; i < 5; i++) { memset(&e[i], 0, sizeof e[i]); CHECK(UN(RtlInsertEntryHashTable)(ht, &e[i], 100 + i, NULL) & 1); }
    memset(&en, 0, sizeof en);
    CHECKF(init(ht, &en) & 1, "%s init", nm);
    int seen[5] = {0}, total = 0; HENTRY *p;
    while ((p = enm(ht, &en)) != NULL && total < 20) {
        total++; for (int i = 0; i < 5; i++) if (p == &e[i]) seen[i]++;
    }
    endf(ht, &en);
    CHECKF(total == 5, "%s: enumerated %d entries", nm, total);
    for (int i = 0; i < 5; i++) CHECKF(seen[i] == 1, "%s entry %d seen %d times", nm, i, seen[i]);
    UN(RtlDeleteHashTable)(ht);
}
TEST(rtl_net_ip_str_a_hash_enum_init) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlEnumerateEntryHashTable)); REQUIRE(UN(RtlEndEnumerationHashTable));
    REQUIRE(UN(RtlInitEnumerationHashTable)); REQUIRE(UN(RtlInitWeakEnumerationHashTable)); REQUIRE(UN(RtlInitStrongEnumerationHashTable));
    hash_enum_case("RtlInitEnumerationHashTable", UN(RtlInitEnumerationHashTable), UN(RtlEnumerateEntryHashTable), UN(RtlEndEnumerationHashTable));
    REQUIRE(UN(RtlWeaklyEnumerateEntryHashTable)); REQUIRE(UN(RtlEndWeakEnumerationHashTable));
    hash_enum_case("RtlInitWeakEnumerationHashTable", UN(RtlInitWeakEnumerationHashTable), UN(RtlWeaklyEnumerateEntryHashTable), UN(RtlEndWeakEnumerationHashTable));
    REQUIRE(UN(RtlStronglyEnumerateEntryHashTable)); REQUIRE(UN(RtlEndStrongEnumerationHashTable));
    hash_enum_case("RtlInitStrongEnumerationHashTable", UN(RtlInitStrongEnumerationHashTable), UN(RtlStronglyEnumerateEntryHashTable), UN(RtlEndStrongEnumerationHashTable));
}
TEST(rtl_net_ip_str_a_activation_context_stack) {
    REQUIRE(UN(RtlAllocateActivationContextStack)); REQUIRE(UN(RtlFreeActivationContextStack));
    PVOID st = NULL;
    EXPECT_EQ(UN(RtlAllocateActivationContextStack)(&st), 0);
    CHECK(st != NULL); if (!st) return;
    ULONG_PTR *w = st;
    EXPECT_EQ(w[0], 0);                                /* no active frame */
    EXPECT_EQ(w[1], (ULONG_PTR)&w[1]); EXPECT_EQ(w[2], (ULONG_PTR)&w[1]);   /* empty frame-cache list */
    EXPECT_EQ(((ULONG *)st)[6], 0); EXPECT_EQ(((ULONG *)st)[7], 1);
    PVOID again = st;
    EXPECT_EQ(UN(RtlAllocateActivationContextStack)(&again), 0);
    EXPECT_EQ(again, st);                              /* existing stack kept */
    UN(RtlFreeActivationContextStack)(st);
}
static DWORD WINAPI actstack_thread(LPVOID p) {
    PVOID *teb = (PVOID *)NtCurrentTeb();
    PVOID before = teb[0x2c8 / 8];
    UN(RtlFreeThreadActivationContextStack)();
    PVOID after = teb[0x2c8 / 8];
    *(int *)p = (before != NULL) * 2 + (after != NULL);
    return 0;
}
TEST(rtl_net_ip_str_a_free_thread_actctx_stack) {
    REQUIRE(UN(RtlFreeThreadActivationContextStack));
    volatile int r = -1; HANDLE h = CreateThread(NULL, 0, actstack_thread, (LPVOID)&r, 0, NULL);
    if (!h) { t_skip("CreateThread failed"); return; }
    EXPECT_EQ(WaitForSingleObject(h, 20000), WAIT_OBJECT_0); CloseHandle(h);
    EXPECT_EQ(r, 3);   /* stack pointer present before, and re-initialized (non-NULL) after */
}
TEST(rtl_net_ip_str_a_initialize_context) {
#ifdef __x86_64__
    REQUIRE(UN(RtlInitializeContext));
    CONTEXT c; memset(&c, 0xcc, sizeof c);
    UN(RtlInitializeContext)((HANDLE)-1, &c, (PVOID)0x1111, (PVOID)0x2222, (PVOID)0x30000);
    EXPECT_EQ(c.Rcx, 0x1111); EXPECT_EQ(c.Rip, 0x2222); EXPECT_EQ(c.Rsp, 0x30000);
    EXPECT_EQ(c.Rax, 0); EXPECT_EQ(c.Rbp, 0); EXPECT_EQ(c.EFlags, 0x200);
    EXPECT_EQ(c.ContextFlags, 0x10000b); EXPECT_EQ(c.MxCsr, 0x1f80);
    EXPECT_EQ(c.Rbx, 1); EXPECT_EQ(c.Rsi, 4); EXPECT_EQ(c.Rdi, 5); EXPECT_EQ(c.R8, 8);
    EXPECT_EQ(c.R10, 10); EXPECT_EQ(c.R11, 11); EXPECT_EQ(c.R12, 12); EXPECT_EQ(c.R13, 13); EXPECT_EQ(c.R14, 14); EXPECT_EQ(c.R15, 15);
    EXPECT_EQ(c.FltSave.ControlWord, 0x27f); EXPECT_EQ(c.FltSave.MxCsr, 0x1f80);
#else
    t_skip("x64 CONTEXT layout only");
#endif
}
TEST(rtl_net_ip_str_a_copy_context) {
#ifdef __x86_64__
    REQUIRE(UN(RtlCopyContext));
    CONTEXT *src = _aligned_malloc(sizeof(CONTEXT), 16), *dst = _aligned_malloc(sizeof(CONTEXT), 16);
    memset(src, 0, sizeof *src); memset(dst, 0, sizeof *dst);
    src->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; dst->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    src->Rax = 0x1111; src->Rbx = 0x2222; src->Rip = 0x3333; src->Rsp = 0x4444; src->EFlags = 0x246; src->Rdi = 0x5555;
    dst->Rax = 0xdead; dst->Rip = 0xdead;
    NTSTATUS s = UN(RtlCopyContext)(dst, CONTEXT_INTEGER, src);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(dst->Rax, 0x1111); EXPECT_EQ(dst->Rbx, 0x2222); EXPECT_EQ(dst->Rdi, 0x5555);
    EXPECT_EQ(dst->Rip, 0xdead);      /* only the requested INTEGER part is copied */
    s = UN(RtlCopyContext)(dst, CONTEXT_CONTROL, src);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->Rip, 0x3333); EXPECT_EQ(dst->Rsp, 0x4444);
    EXPECT_EQ(UN(RtlCopyContext)(dst, 0xffffffff, src) < 0, 1);                       /* invalid flags */
    _aligned_free(src); _aligned_free(dst);
#else
    t_skip("x64 CONTEXT layout only");
#endif
}
TEST(rtl_net_ip_str_a_srw_convert_exclusive_to_shared) {
    REQUIRE(UN(RtlConvertSRWLockExclusiveToShared)); REQUIRE(UN(RtlAcquireSRWLockExclusive)); REQUIRE(UN(RtlReleaseSRWLockShared));
    REQUIRE(UN(RtlTryAcquireSRWLockShared)); REQUIRE(UN(RtlTryAcquireSRWLockExclusive));
    RTL_SRWLOCK l = {0};
    UN(RtlAcquireSRWLockExclusive)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l) & 1, 0);
    UN(RtlConvertSRWLockExclusiveToShared)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockShared)(&l) & 1, 1);          /* now readable by others */
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l) & 1, 0);
    UN(RtlReleaseSRWLockShared)(&l); UN(RtlReleaseSRWLockShared)(&l);
    EXPECT_EQ(UN(RtlTryAcquireSRWLockExclusive)(&l) & 1, 1);       /* fully released */
    UN(RtlReleaseSRWLockExclusive)(&l);
    EXPECT_EQ(l.Ptr, NULL);
}
TEST(rtl_net_ip_str_a_memory_stream_stubs) {
    REQUIRE(UN(RtlCopyMemoryStreamTo)); REQUIRE(UN(RtlCopyOutOfProcessMemoryStreamTo));
    ULONGLONG a = 7, b = 7;
    EXPECT_EQ(UN(RtlCopyMemoryStreamTo)(NULL, NULL, 10, &a, &b), ST(0x80004001));
    EXPECT_EQ(UN(RtlCopyOutOfProcessMemoryStreamTo)(NULL, NULL, 10, &a, &b), ST(0x80004001));
    EXPECT_EQ(a, 7); EXPECT_EQ(b, 7);
}

TEST(rtl_net_ip_str_a_resource_convert) {
    REQUIRE(UN(RtlInitializeResource)); REQUIRE(UN(RtlDeleteResource)); REQUIRE(UN(RtlAcquireResourceExclusive));
    REQUIRE(UN(RtlAcquireResourceShared)); REQUIRE(UN(RtlReleaseResource)); REQUIRE(UN(RtlConvertExclusiveToShared)); REQUIRE(UN(RtlConvertSharedToExclusive));
    BYTE res[0x80]; memset(res, 0, sizeof res);
    LONG *active = (LONG *)(res + 0x44); ULONG_PTR *owner = (ULONG_PTR *)(res + 0x48);
    UN(RtlInitializeResource)(res);
    EXPECT_EQ(*active, 0);
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(res, TRUE) & 1, 1);
    EXPECT_EQ(*active, -1); EXPECT_EQ(*owner, GetCurrentThreadId());
    UN(RtlConvertExclusiveToShared)(res);
    EXPECT_EQ(*active, 1); EXPECT_EQ(*owner, 0);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(res, FALSE) & 1, 1);        /* other readers now allowed */
    EXPECT_EQ(*active, 2);
    UN(RtlReleaseResource)(res); EXPECT_EQ(*active, 1);
    UN(RtlConvertSharedToExclusive)(res);                               /* sole reader upgrades */
    EXPECT_EQ(*active, -1); EXPECT_EQ(*owner, GetCurrentThreadId());
    UN(RtlReleaseResource)(res);
    EXPECT_EQ(*active, 0);
    UN(RtlDeleteResource)(res);
}
