/* Hash tables, generic tables (splay and AVL), splay link deletion, interlocked bit runs and SLists. */
#include "t.h"

/* ---- types (declared locally; not all are in the SDK headers) ---- */
typedef struct TBITMAP { ULONG SizeOfBitMap; ULONG *Buffer; } TBITMAP;
typedef struct THASHENTRY { LIST_ENTRY Linkage; ULONG_PTR Signature; } THASHENTRY;
typedef struct THASHTABLE {
    ULONG Flags, Shift, TableSize, Pivot, DivisorMask, NumEntries, NonEmptyBuckets, NumEnumerators;
    PVOID Directory;
} THASHTABLE;
typedef struct THASHENUM { THASHENTRY HashEntry; PLIST_ENTRY ChainHead; ULONG BucketIndex; } THASHENUM;
typedef struct TSPLAY { struct TSPLAY *Parent, *Left, *Right; } TSPLAY;
typedef struct TGTABLE TGTABLE;
typedef PVOID (NTAPI *TALLOC)(TGTABLE *, ULONG);
typedef VOID (NTAPI *TFREE)(TGTABLE *, PVOID);
typedef int (NTAPI *TCMP)(TGTABLE *, PVOID, PVOID);   /* GenericLessThan=0, GenericGreaterThan=1, GenericEqual=2 */
struct TGTABLE {
    TSPLAY *TableRoot; LIST_ENTRY InsertOrderList; PLIST_ENTRY OrderedPointer;
    ULONG WhichOrderedElement, NumberGenericTableElements;
    TCMP Compare; TALLOC Alloc; TFREE Free; PVOID Context;
};
typedef struct TBAL { struct TBAL *Parent, *Left, *Right; CHAR Balance; UCHAR Reserved[3]; } TBAL;
typedef struct TAVL {
    TBAL BalancedRoot; PVOID OrderedPointer; ULONG WhichOrderedElement, NumberGenericTableElements, DepthOfTree;
    TBAL *RestartKey; ULONG DeleteCount;
    TCMP Compare; TALLOC Alloc; TFREE Free; PVOID Context;
} TAVL;
typedef struct __attribute__((aligned(16))) TSLE { struct TSLE *Next; } TSLE;
typedef struct __attribute__((aligned(16))) TSLH { ULONGLONG a, b; } TSLH;

UDECL(NTSTATUS, RtlCreateHashTable, (THASHTABLE **, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (THASHTABLE *));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (THASHTABLE *, THASHENTRY *, ULONG_PTR, PVOID));
UDECL(BOOLEAN, RtlRemoveEntryHashTable, (THASHTABLE *, THASHENTRY *, PVOID));
UDECL(THASHENTRY *, RtlLookupEntryHashTable, (THASHTABLE *, ULONG_PTR, PVOID));
UDECL(BOOLEAN, RtlInitEnumerationHashTable, (THASHTABLE *, THASHENUM *));
UDECL(THASHENTRY *, RtlEnumerateEntryHashTable, (THASHTABLE *, THASHENUM *));
UDECL(VOID, RtlEndEnumerationHashTable, (THASHTABLE *, THASHENUM *));
UDECL(VOID, RtlInterlockedSetBitRun, (TBITMAP *, ULONG, ULONG));
UDECL(VOID, RtlInterlockedClearBitRun, (TBITMAP *, ULONG, ULONG));
UDECL(VOID, RtlInitializeGenericTable, (TGTABLE *, TCMP, TALLOC, TFREE, PVOID));
UDECL(PVOID, RtlLookupElementGenericTableFull, (TGTABLE *, PVOID, PVOID *, ULONG *));
UDECL(PVOID, RtlInsertElementGenericTableFull, (TGTABLE *, PVOID, ULONG, BOOLEAN *, PVOID, ULONG));
UDECL(ULONG, RtlNumberGenericTableElements, (TGTABLE *));
UDECL(BOOLEAN, RtlDeleteElementGenericTable, (TGTABLE *, PVOID));
UDECL(VOID, RtlInitializeGenericTableAvl, (TAVL *, TCMP, TALLOC, TFREE, PVOID));
UDECL(PVOID, RtlLookupElementGenericTableFullAvl, (TAVL *, PVOID, PVOID *, ULONG *));
UDECL(PVOID, RtlInsertElementGenericTableFullAvl, (TAVL *, PVOID, ULONG, BOOLEAN *, PVOID, ULONG));
UDECL(VOID, RtlDeleteElementGenericTableAvlEx, (TAVL *, PVOID));
UDECL(ULONG, RtlNumberGenericTableElementsAvl, (TAVL *));
UDECL(BOOLEAN, RtlIsGenericTableEmptyAvl, (TAVL *));
UDECL(PVOID, RtlEnumerateGenericTableLikeADirectory, (TAVL *, PVOID, PVOID, ULONG, PVOID *, ULONG *, PVOID));
UDECL(PVOID, RtlEnumerateGenericTableAvl, (TAVL *, BOOLEAN));
UDECL(TSPLAY *, RtlDelete, (TSPLAY *));
UDECL(VOID, RtlDeleteNoSplay, (TSPLAY *, TSPLAY **));
UDECL(PVOID, RtlInterlockedPushEntrySList, (TSLH *, TSLE *));
UDECL(PVOID, RtlInterlockedPopEntrySList, (TSLH *));
UDECL(PVOID, RtlInterlockedFlushSList, (TSLH *));
UDECL(PVOID, RtlInterlockedPushListSList, (TSLH *, TSLE *, TSLE *, ULONG));
UDECL(PVOID, RtlInterlockedPushListSListEx, (TSLH *, TSLE *, TSLE *, ULONG));
UDECL(USHORT, RtlQueryDepthSList, (TSLH *));

/* ------------------------------ hash table ------------------------------ */
TEST(rtl_cad_b_hash_basic) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlRemoveEntryHashTable)); REQUIRE(UN(RtlLookupEntryHashTable));
    THASHTABLE *t = NULL; THASHENTRY e[4];
    EXPECT_EQ(UN(RtlCreateHashTable)(&t, 0, 0), TRUE);
    if (!t) return;
    EXPECT_EQ(t->Flags & 1, 1);               /* header allocated by the call */
    EXPECT_EQ(t->TableSize, 128); EXPECT_EQ(t->DivisorMask, 127);
    EXPECT_EQ(t->NumEntries, 0); EXPECT_EQ(t->NonEmptyBuckets, 0); EXPECT_EQ(t->NumEnumerators, 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 5, NULL), 0);
    memset(e, 0, sizeof e);
    EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e[0], 5, NULL), TRUE);
    EXPECT_EQ(e[0].Signature, 5); EXPECT_EQ(t->NumEntries, 1); EXPECT_EQ(t->NonEmptyBuckets, 1);
    EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e[1], 6, NULL), TRUE);
    EXPECT_EQ(t->NumEntries, 2); CHECK(t->NonEmptyBuckets >= 1 && t->NonEmptyBuckets <= 2);
    /* a third entry may or may not share a bucket */
    EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e[2], 5 + 128, NULL), TRUE);
    EXPECT_EQ(t->NumEntries, 3); CHECK(t->NonEmptyBuckets >= 1 && t->NonEmptyBuckets <= 3);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 5, NULL), (ULONG_PTR)&e[0]);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 6, NULL), (ULONG_PTR)&e[1]);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 5 + 128, NULL), (ULONG_PTR)&e[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 7, NULL), 0);
    /* context filled by lookup is accepted by insert */
    struct { PLIST_ENTRY Chain, Prev; ULONG_PTR Sig; } ctx; memset(&ctx, 0, sizeof ctx);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 9, &ctx), 0);
    EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e[3], 9, &ctx), TRUE);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 9, NULL), (ULONG_PTR)&e[3]);
    EXPECT_EQ(t->NumEntries, 4);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[0], NULL), TRUE);
    EXPECT_EQ(t->NumEntries, 3);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 5, NULL), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 5 + 128, NULL), (ULONG_PTR)&e[2]);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[2], NULL), TRUE);
    EXPECT_EQ(t->NumEntries, 2);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[1], NULL), TRUE);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[3], NULL), TRUE);
    EXPECT_EQ(t->NumEntries, 0); EXPECT_EQ(t->NonEmptyBuckets, 0);
    UN(RtlDeleteHashTable)(t);
}
TEST(rtl_cad_b_hash_enum) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlRemoveEntryHashTable)); REQUIRE(UN(RtlInitEnumerationHashTable));
    REQUIRE(UN(RtlEnumerateEntryHashTable)); REQUIRE(UN(RtlEndEnumerationHashTable));
    THASHTABLE *t = NULL; THASHENTRY e[10]; THASHENUM en; int seen[10] = {0}, n = 0;
    EXPECT_EQ(UN(RtlCreateHashTable)(&t, 0, 0), TRUE); if (!t) return;
    memset(e, 0, sizeof e);
    for (int i = 0; i < 10; i++) UN(RtlInsertEntryHashTable)(t, &e[i], 100 + i * 37, NULL);
    EXPECT_EQ(t->NumEntries, 10);
    memset(&en, 0, sizeof en);
    EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &en), TRUE);
    EXPECT_EQ(t->NumEnumerators, 1);
    for (;;) {
        THASHENTRY *x = UN(RtlEnumerateEntryHashTable)(t, &en);
        if (!x) break;
        int idx = (int)(x - e); CHECK(idx >= 0 && idx < 10);
        if (idx >= 0 && idx < 10) seen[idx]++;
        if (++n > 20) break;
    }
    EXPECT_EQ(n, 10);
    for (int i = 0; i < 10; i++) EXPECT_EQ(seen[i], 1);
    UN(RtlEndEnumerationHashTable)(t, &en);
    EXPECT_EQ(t->NumEnumerators, 0);
    /* empty table enumerates nothing */
    for (int i = 0; i < 10; i++) EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[i], NULL), TRUE);
    EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &en), TRUE);
    EXPECT_EQ((ULONG_PTR)UN(RtlEnumerateEntryHashTable)(t, &en), 0);
    UN(RtlEndEnumerationHashTable)(t, &en);
    UN(RtlDeleteHashTable)(t);
}
TEST(rtl_cad_b_hash_caller_header) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlLookupEntryHashTable)); REQUIRE(UN(RtlRemoveEntryHashTable));
    THASHTABLE hdr; THASHTABLE *t = &hdr; THASHENTRY e; memset(&hdr, 0xAA, sizeof hdr); memset(&e, 0, sizeof e);
    hdr.Directory = NULL;
    *(ULONG_PTR *)&t = (ULONG_PTR)&hdr;
    /* a non-NULL table pointer designates caller-provided storage */
    EXPECT_EQ(UN(RtlCreateHashTable)(&t, 3, 0), TRUE);
    EXPECT_EQ((ULONG_PTR)t, (ULONG_PTR)&hdr);
    EXPECT_EQ(hdr.Flags & 1, 0); EXPECT_EQ(hdr.Shift, 3); EXPECT_EQ(hdr.NumEntries, 0);
    EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e, 42, NULL), TRUE);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 42, NULL), (ULONG_PTR)&e);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e, NULL), TRUE);
    UN(RtlDeleteHashTable)(t);   /* must not free the caller's header */
    EXPECT_EQ(hdr.TableSize, 128);   /* header memory still readable */
}

/* ------------------------------ bit runs ------------------------------ */
static ULONG ref_apply(ULONG *w, ULONG start, ULONG n, int set) {
    for (ULONG i = start; i < start + n; i++) { if (set) w[i >> 5] |= 1u << (i & 31); else w[i >> 5] &= ~(1u << (i & 31)); }
    return 0;
}
TEST(rtl_cad_b_bitrun) {
    REQUIRE(UN(RtlInterlockedSetBitRun)); REQUIRE(UN(RtlInterlockedClearBitRun));
    static const ULONG cases[][2] = { {0,1},{0,5},{3,10},{0,32},{5,27},{31,1},{31,2},{30,40},{0,64},{32,32},{7,90},{64,0},{17,0},{1,127},{0,128} };
    for (unsigned c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        ULONG buf[4], ref[4]; TBITMAP bm = { 128, buf };
        memset(buf, 0, sizeof buf); memset(ref, 0, sizeof ref);
        UN(RtlInterlockedSetBitRun)(&bm, cases[c][0], cases[c][1]); ref_apply(ref, cases[c][0], cases[c][1], 1);
        CHECKF(!memcmp(buf, ref, sizeof buf), "set run start=%lu n=%lu got %08lx %08lx %08lx %08lx", cases[c][0], cases[c][1], buf[0], buf[1], buf[2], buf[3]);
        memset(buf, 0xFF, sizeof buf); memset(ref, 0xFF, sizeof ref);
        UN(RtlInterlockedClearBitRun)(&bm, cases[c][0], cases[c][1]); ref_apply(ref, cases[c][0], cases[c][1], 0);
        CHECKF(!memcmp(buf, ref, sizeof buf), "clear run start=%lu n=%lu got %08lx %08lx %08lx %08lx", cases[c][0], cases[c][1], buf[0], buf[1], buf[2], buf[3]);
    }
    /* set never clears pre-existing bits and clear never sets any */
    ULONG buf[2] = { 0xA5A5A5A5, 0x5A5A5A5A }; TBITMAP bm = { 64, buf };
    UN(RtlInterlockedSetBitRun)(&bm, 4, 8);
    EXPECT_EQ(buf[0], 0xA5A5A5A5 | 0xFF0); EXPECT_EQ(buf[1], 0x5A5A5A5A);
    UN(RtlInterlockedClearBitRun)(&bm, 28, 8);
    EXPECT_EQ(buf[0], (0xA5A5A5A5 | 0xFF0) & 0x0FFFFFFF); EXPECT_EQ(buf[1], 0x5A5A5A5A & 0xFFFFFFF0);
}

/* ------------------------------ splay links ------------------------------ */
TEST(rtl_cad_b_splay_delete) {
    REQUIRE(UN(RtlDelete)); REQUIRE(UN(RtlDeleteNoSplay));
    TSPLAY r, l, t, *root;
    /* root with a single right child: the child becomes the root (its parent is itself) */
    memset(&r, 0, sizeof r); memset(&t, 0, sizeof t);
    r.Parent = &r; r.Right = &t; t.Parent = &r;
    root = UN(RtlDelete)(&r);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&t); EXPECT_EQ((ULONG_PTR)t.Parent, (ULONG_PTR)&t);
    /* root with a single left child */
    memset(&r, 0, sizeof r); memset(&l, 0, sizeof l);
    r.Parent = &r; r.Left = &l; l.Parent = &r;
    root = UN(RtlDelete)(&r);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&l); EXPECT_EQ((ULONG_PTR)l.Parent, (ULONG_PTR)&l);
    /* root with both children: in-order predecessor (the left child) takes over */
    memset(&r, 0, sizeof r); memset(&l, 0, sizeof l); memset(&t, 0, sizeof t);
    r.Parent = &r; r.Left = &l; r.Right = &t; l.Parent = &r; t.Parent = &r;
    root = UN(RtlDelete)(&r);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&l); EXPECT_EQ((ULONG_PTR)l.Parent, (ULONG_PTR)&l);
    EXPECT_EQ((ULONG_PTR)l.Left, 0); EXPECT_EQ((ULONG_PTR)l.Right, (ULONG_PTR)&t);
    EXPECT_EQ((ULONG_PTR)t.Parent, (ULONG_PTR)&l);
    /* delete a leaf: parent link cleared, parent returned as root */
    memset(&r, 0, sizeof r); memset(&l, 0, sizeof l); memset(&t, 0, sizeof t);
    r.Parent = &r; r.Left = &l; r.Right = &t; l.Parent = &r; t.Parent = &r;
    root = UN(RtlDelete)(&t);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&r); EXPECT_EQ((ULONG_PTR)r.Right, 0); EXPECT_EQ((ULONG_PTR)r.Left, (ULONG_PTR)&l);
    /* lone root: returns NULL */
    memset(&r, 0, sizeof r); r.Parent = &r;
    EXPECT_EQ((ULONG_PTR)UN(RtlDelete)(&r), 0);

    /* no-splay variant reports the new root through the second argument */
    memset(&r, 0, sizeof r); r.Parent = &r; root = &r;
    UN(RtlDeleteNoSplay)(&r, &root);
    EXPECT_EQ((ULONG_PTR)root, 0);
    memset(&r, 0, sizeof r); memset(&t, 0, sizeof t); r.Parent = &r; r.Right = &t; t.Parent = &r; root = &r;
    UN(RtlDeleteNoSplay)(&r, &root);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&t); EXPECT_EQ((ULONG_PTR)t.Parent, (ULONG_PTR)&t);
    memset(&r, 0, sizeof r); memset(&l, 0, sizeof l); memset(&t, 0, sizeof t);
    r.Parent = &r; r.Left = &l; r.Right = &t; l.Parent = &r; t.Parent = &r; root = &r;
    UN(RtlDeleteNoSplay)(&r, &root);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&l); EXPECT_EQ((ULONG_PTR)l.Right, (ULONG_PTR)&t); EXPECT_EQ((ULONG_PTR)l.Left, 0);
    /* deleting a non-root leaf leaves the root pointer alone */
    memset(&r, 0, sizeof r); memset(&l, 0, sizeof l); r.Parent = &r; r.Left = &l; l.Parent = &r; root = &r;
    UN(RtlDeleteNoSplay)(&l, &root);
    EXPECT_EQ((ULONG_PTR)root, (ULONG_PTR)&r); EXPECT_EQ((ULONG_PTR)r.Left, 0);
}

/* ------------------------------ generic tables ------------------------------ */
static int g_alloc_calls, g_free_calls; static ULONG g_last_alloc_size; static PVOID g_last_free;
static int NTAPI cmp_int(TGTABLE *t, PVOID a, PVOID b) { int x = *(int *)a, y = *(int *)b; return x < y ? 0 : x > y ? 1 : 2; }
static PVOID NTAPI al(TGTABLE *t, ULONG n) { g_alloc_calls++; g_last_alloc_size = n; return HeapAlloc(GetProcessHeap(), 0, n); }
static VOID NTAPI fr(TGTABLE *t, PVOID p) { g_free_calls++; g_last_free = p; HeapFree(GetProcessHeap(), 0, p); }
TEST(rtl_cad_b_generic_full) {
    REQUIRE(UN(RtlInitializeGenericTable)); REQUIRE(UN(RtlLookupElementGenericTableFull));
    REQUIRE(UN(RtlInsertElementGenericTableFull)); REQUIRE(UN(RtlNumberGenericTableElements)); REQUIRE(UN(RtlDeleteElementGenericTable));
    TGTABLE tb; memset(&tb, 0, sizeof tb);
    UN(RtlInitializeGenericTable)(&tb, cmp_int, al, fr, NULL);
    g_alloc_calls = g_free_calls = 0;
    PVOID np = NULL; ULONG sr = 99; int k = 10; BOOLEAN nw = 7;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupElementGenericTableFull)(&tb, &k, &np, &sr), 0);
    EXPECT_EQ(sr, 0);   /* TableEmptyTree */
    int *p = UN(RtlInsertElementGenericTableFull)(&tb, &k, sizeof k, &nw, np, sr);
    CHECK(p != NULL); if (!p) return;
    EXPECT_EQ(nw, TRUE); EXPECT_EQ(*p, 10); EXPECT_EQ(g_alloc_calls, 1);
    EXPECT_EQ(g_last_alloc_size, sizeof(int) + 0x28);   /* splay links + list entry header */
    EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 1);
    /* second element lands right of the first */
    k = 20; np = NULL; sr = 99;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupElementGenericTableFull)(&tb, &k, &np, &sr), 0);
    EXPECT_EQ(sr, 3);   /* TableInsertAsRight */
    nw = 7; int *q = UN(RtlInsertElementGenericTableFull)(&tb, &k, sizeof k, &nw, np, sr);
    CHECK(q != NULL && q != p); EXPECT_EQ(nw, TRUE); EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 2);
    /* lookup finds, and insert with TableFoundNode returns the existing element without allocating */
    k = 10; np = NULL; sr = 99;
    PVOID f = UN(RtlLookupElementGenericTableFull)(&tb, &k, &np, &sr);
    EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)p); EXPECT_EQ(sr, 1);
    int calls = g_alloc_calls; nw = 7;
    PVOID again = UN(RtlInsertElementGenericTableFull)(&tb, &k, sizeof k, &nw, np, sr);
    EXPECT_EQ((ULONG_PTR)again, (ULONG_PTR)p); EXPECT_EQ(nw, FALSE); EXPECT_EQ(g_alloc_calls, calls);
    EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 2);
    /* NULL NewElement is allowed */
    EXPECT_EQ((ULONG_PTR)UN(RtlInsertElementGenericTableFull)(&tb, &k, sizeof k, NULL, np, sr), (ULONG_PTR)p);
    /* size overflow rejected before calling the allocator */
    k = 30; np = NULL; sr = 99; UN(RtlLookupElementGenericTableFull)(&tb, &k, &np, &sr);
    calls = g_alloc_calls; nw = 7;
    EXPECT_EQ((ULONG_PTR)UN(RtlInsertElementGenericTableFull)(&tb, &k, 0xFFFFFFF8u, &nw, np, sr), 0);
    EXPECT_EQ(nw, FALSE); EXPECT_EQ(g_alloc_calls, calls); EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 2);
    /* allocator failure */
    /* cleanup */
    EXPECT_EQ(UN(RtlDeleteElementGenericTable)(&tb, p), TRUE);
    EXPECT_EQ(UN(RtlDeleteElementGenericTable)(&tb, q), TRUE);
    EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 0); EXPECT_EQ(g_free_calls, 2);
}
static PVOID NTAPI al_fail(TGTABLE *t, ULONG n) { g_alloc_calls++; return NULL; }
TEST(rtl_cad_b_generic_full_allocfail) {
    REQUIRE(UN(RtlInitializeGenericTable)); REQUIRE(UN(RtlInsertElementGenericTableFull)); REQUIRE(UN(RtlNumberGenericTableElements));
    TGTABLE tb; memset(&tb, 0, sizeof tb); UN(RtlInitializeGenericTable)(&tb, cmp_int, al_fail, fr, NULL);
    g_alloc_calls = 0; int k = 1; BOOLEAN nw = 7;
    EXPECT_EQ((ULONG_PTR)UN(RtlInsertElementGenericTableFull)(&tb, &k, sizeof k, &nw, NULL, 0), 0);
    EXPECT_EQ(nw, FALSE); EXPECT_EQ(g_alloc_calls, 1); EXPECT_EQ(UN(RtlNumberGenericTableElements)(&tb), 0);
}
TEST(rtl_cad_b_avl_full_delete) {
    REQUIRE(UN(RtlInitializeGenericTableAvl)); REQUIRE(UN(RtlLookupElementGenericTableFullAvl));
    REQUIRE(UN(RtlInsertElementGenericTableFullAvl)); REQUIRE(UN(RtlDeleteElementGenericTableAvlEx));
    REQUIRE(UN(RtlNumberGenericTableElementsAvl)); REQUIRE(UN(RtlIsGenericTableEmptyAvl));
    TAVL tb; memset(&tb, 0, sizeof tb);
    UN(RtlInitializeGenericTableAvl)(&tb, (TCMP)cmp_int, (TALLOC)al, (TFREE)fr, NULL);
    g_alloc_calls = g_free_calls = 0;
    EXPECT_EQ(UN(RtlIsGenericTableEmptyAvl)(&tb), TRUE);
    int keys[5] = { 50, 20, 70, 10, 30 }; int *el[5]; PVOID np; ULONG sr; BOOLEAN nw;
    for (int i = 0; i < 5; i++) {
        np = NULL; sr = 99; nw = 7;
        EXPECT_EQ((ULONG_PTR)UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[i], &np, &sr), 0);
        if (i == 0) EXPECT_EQ(sr, 0); else EXPECT_NE(sr, 1);
        el[i] = UN(RtlInsertElementGenericTableFullAvl)(&tb, &keys[i], sizeof(int), &nw, np, sr);
        CHECK(el[i] != NULL); if (!el[i]) return;
        EXPECT_EQ(nw, TRUE); EXPECT_EQ(*el[i], keys[i]);
    }
    EXPECT_EQ(g_last_alloc_size, sizeof(int) + 0x20);   /* balanced links header */
    EXPECT_EQ(UN(RtlNumberGenericTableElementsAvl)(&tb), 5);
    EXPECT_EQ(UN(RtlIsGenericTableEmptyAvl)(&tb), FALSE);
    /* found-node insert */
    np = NULL; sr = 99; nw = 7; int calls = g_alloc_calls;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[2], &np, &sr), (ULONG_PTR)el[2]);
    EXPECT_EQ(sr, 1);
    EXPECT_EQ((ULONG_PTR)UN(RtlInsertElementGenericTableFullAvl)(&tb, &keys[2], sizeof(int), &nw, np, sr), (ULONG_PTR)el[2]);
    EXPECT_EQ(nw, FALSE); EXPECT_EQ(g_alloc_calls, calls); EXPECT_EQ(UN(RtlNumberGenericTableElementsAvl)(&tb), 5);
    /* overflow */
    int k = 99; np = NULL; sr = 99; UN(RtlLookupElementGenericTableFullAvl)(&tb, &k, &np, &sr); nw = 7;
    EXPECT_EQ((ULONG_PTR)UN(RtlInsertElementGenericTableFullAvl)(&tb, &k, 0xFFFFFFF0u, &nw, np, sr), 0);
    EXPECT_EQ(nw, FALSE); EXPECT_EQ(g_alloc_calls, calls);
    /* delete by node: free routine receives the node (user data minus the 0x20 header) */
    ULONG dc = tb.DeleteCount;
    for (int i = 0; i < 5; i++) {
        np = NULL; sr = 99; PVOID f = UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[i], &np, &sr);
        EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)el[i]); EXPECT_EQ(sr, 1);
        g_last_free = NULL;
        UN(RtlDeleteElementGenericTableAvlEx)(&tb, np);
        EXPECT_EQ((ULONG_PTR)g_last_free, (ULONG_PTR)np);
        EXPECT_EQ((ULONG_PTR)np, (ULONG_PTR)el[i] - 0x20);
        EXPECT_EQ(UN(RtlNumberGenericTableElementsAvl)(&tb), 4 - i);
        EXPECT_EQ(tb.DeleteCount, dc + i + 1);
        np = NULL; sr = 99;
        EXPECT_EQ((ULONG_PTR)UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[i], &np, &sr), 0);
    }
    EXPECT_EQ(g_free_calls, 5); EXPECT_EQ(UN(RtlIsGenericTableEmptyAvl)(&tb), TRUE);
}
typedef struct { TAVL *t; int mod; } MATCHCTX;
static ULONG NTAPI match_mod(TAVL *t, PVOID elem, PVOID data) {
    MATCHCTX *m = data; return (*(int *)elem % m->mod == 0) ? 0 : 0xC0000272; /* SUCCESS : STATUS_NO_MATCH */
}
TEST(rtl_cad_b_avl_enum_directory) {
    REQUIRE(UN(RtlInitializeGenericTableAvl)); REQUIRE(UN(RtlEnumerateGenericTableLikeADirectory)); REQUIRE(UN(RtlLookupElementGenericTableFullAvl));
    REQUIRE(UN(RtlInsertElementGenericTableFullAvl)); REQUIRE(UN(RtlDeleteElementGenericTableAvlEx));
    TAVL tb; memset(&tb, 0, sizeof tb);
    UN(RtlInitializeGenericTableAvl)(&tb, (TCMP)cmp_int, (TALLOC)al, (TFREE)fr, NULL);
    PVOID np, restart = NULL; ULONG sr, delcnt = 0; BOOLEAN nw; MATCHCTX mc = { &tb, 20 };
    /* empty table: NULL and the restart key is cleared */
    restart = (PVOID)0x1234; int key = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 0, &restart, &delcnt, &key), 0);
    EXPECT_EQ((ULONG_PTR)restart, 0);
    int keys[6] = { 10, 20, 30, 40, 50, 60 };
    for (int i = 0; i < 6; i++) { np = NULL; UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[i], &np, &sr); UN(RtlInsertElementGenericTableFullAvl)(&tb, &keys[i], sizeof(int), &nw, np, sr); }
    restart = NULL; delcnt = tb.DeleteCount; key = 0;
    int *r = UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 0, &restart, &delcnt, &key);
    CHECK(r != NULL); if (r) EXPECT_EQ(*r, 20);
    EXPECT_NE((ULONG_PTR)restart, 0);
    r = UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 1, &restart, &delcnt, &key);
    CHECK(r != NULL); if (r) EXPECT_EQ(*r, 40);
    r = UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 1, &restart, &delcnt, &key);
    CHECK(r != NULL); if (r) EXPECT_EQ(*r, 60);
    r = UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 1, &restart, &delcnt, &key);
    EXPECT_EQ((ULONG_PTR)r, 0);
    /* start at a key: match from key 35 forward */
    restart = NULL; key = 35; delcnt = tb.DeleteCount; mc.mod = 10;
    r = UN(RtlEnumerateGenericTableLikeADirectory)(&tb, match_mod, &mc, 0, &restart, &delcnt, &key);
    CHECK(r != NULL); if (r) EXPECT_EQ(*r, 40);
    for (int i = 0; i < 6; i++) { np = NULL; UN(RtlLookupElementGenericTableFullAvl)(&tb, &keys[i], &np, &sr); UN(RtlDeleteElementGenericTableAvlEx)(&tb, np); }
    EXPECT_EQ(UN(RtlNumberGenericTableElementsAvl)(&tb), 0);
}

/* ------------------------------ SLists ------------------------------ */
TEST(rtl_cad_b_slist) {
    REQUIRE(UN(RtlInterlockedPushEntrySList)); REQUIRE(UN(RtlInterlockedPopEntrySList)); REQUIRE(UN(RtlInterlockedFlushSList));
    REQUIRE(UN(RtlInterlockedPushListSList)); REQUIRE(UN(RtlQueryDepthSList));
    TSLH h; TSLE e[8]; memset(&h, 0, sizeof h); memset(e, 0, sizeof e);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPopEntrySList)(&h), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedFlushSList)(&h), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPushEntrySList)(&h, &e[0]), 0);   /* previous top */
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPushEntrySList)(&h, &e[1]), (ULONG_PTR)&e[0]);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPushEntrySList)(&h, &e[2]), (ULONG_PTR)&e[1]);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 3);
    EXPECT_EQ((ULONG_PTR)e[2].Next, (ULONG_PTR)&e[1]); EXPECT_EQ((ULONG_PTR)e[0].Next, 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPopEntrySList)(&h), (ULONG_PTR)&e[2]);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 2);
    /* push a pre-linked list e[4]->e[5]->e[6] */
    e[4].Next = &e[5]; e[5].Next = &e[6];
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPushListSList)(&h, &e[4], &e[6], 3), (ULONG_PTR)&e[1]);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 5);
    EXPECT_EQ((ULONG_PTR)e[6].Next, (ULONG_PTR)&e[1]);
    if (UN(RtlInterlockedPushListSListEx)) {
        e[7].Next = NULL;
        EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPushListSListEx)(&h, &e[7], &e[7], 1), (ULONG_PTR)&e[4]);
        EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 6);
        EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPopEntrySList)(&h), (ULONG_PTR)&e[7]);
    }
    TSLE *top = UN(RtlInterlockedFlushSList)(&h);
    EXPECT_EQ((ULONG_PTR)top, (ULONG_PTR)&e[4]);
    int n = 0; for (TSLE *x = top; x && n < 20; x = x->Next) n++;
    EXPECT_EQ(n, 5);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPopEntrySList)(&h), 0);
}
