#include "t.h"
#include <stdlib.h>

/* ---- local declarations (not in the SDK headers) ---- */
typedef struct { PVOID Parent, Left, Right; } SPLAY;
typedef struct { LIST_ENTRY Linkage; ULONG_PTR Signature; } HENTRY;
typedef struct { PVOID ChainHead, PrevLinkage; ULONG_PTR Signature; } HCTX;
typedef struct RBN { struct RBN *Left, *Right; ULONG_PTR ParentValue; } RBN;
typedef struct { RBN *Root, *Min; } RBT;
typedef struct { int g, s; } ELEM;

UDECL(PVOID, RtlRealPredecessor, (PVOID));
UDECL(PVOID, RtlRealSuccessor, (PVOID));
UDECL(VOID, RtlInitializeGenericTable, (PVOID, PVOID, PVOID, PVOID, PVOID));
UDECL(VOID, RtlInitializeGenericTableAvl, (PVOID, PVOID, PVOID, PVOID, PVOID));
UDECL(PVOID, RtlInsertElementGenericTable, (PVOID, PVOID, ULONG, BOOLEAN *));
UDECL(PVOID, RtlInsertElementGenericTableAvl, (PVOID, PVOID, ULONG, BOOLEAN *));
UDECL(PVOID, RtlLookupElementGenericTableFull, (PVOID, PVOID, PVOID *, ULONG *));
UDECL(PVOID, RtlLookupElementGenericTableFullAvl, (PVOID, PVOID, PVOID *, ULONG *));
UDECL(PVOID, RtlLookupFirstMatchingElementGenericTableAvl, (PVOID, PVOID, PVOID *));
UDECL(BOOLEAN, RtlDeleteElementGenericTable, (PVOID, PVOID));
UDECL(BOOLEAN, RtlDeleteElementGenericTableAvl, (PVOID, PVOID));
UDECL(BOOLEAN, RtlCreateHashTable, (PVOID *, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (PVOID));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (PVOID, PVOID, ULONG_PTR, PVOID));
UDECL(BOOLEAN, RtlRemoveEntryHashTable, (PVOID, PVOID, PVOID));
UDECL(PVOID, RtlLookupEntryHashTable, (PVOID, ULONG_PTR, PVOID));
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PCWSTR, USHORT *));
UDECL(NTSTATUS, RtlDeleteAtomFromAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlLookupAtomInAtomTable, (PVOID, PCWSTR, USHORT *));
UDECL(NTSTATUS, RtlPinAtomInAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlQueryAtomInAtomTable, (PVOID, USHORT, ULONG *, ULONG *, PWSTR, ULONG *));
UDECL(VOID, RtlRbInsertNodeEx, (RBT *, RBN *, BOOLEAN, RBN *));
UDECL(VOID, RtlRbRemoveNode, (RBT *, RBN *));
UDECL(VOID, RtlPushFrame, (PVOID));
UDECL(VOID, RtlPopFrame, (PVOID));
UDECL(PVOID, RtlGetFrame, (void));
UDECL(NTSTATUS, RtlCreateMemoryZone, (PVOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlAllocateMemoryZone, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlResetMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlDestroyMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryBlockLookaside, (PVOID *, ULONG, SIZE_T, SIZE_T, SIZE_T));
UDECL(NTSTATUS, RtlAllocateMemoryBlockLookaside, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlFreeMemoryBlockLookaside, (PVOID, PVOID));
UDECL(NTSTATUS, RtlResetMemoryBlockLookaside, (PVOID));
UDECL(NTSTATUS, RtlDestroyMemoryBlockLookaside, (PVOID));
UDECL(ULONG, RtlRandom, (ULONG *));
UDECL(ULONG, RtlRandomEx, (ULONG *));
UDECL(VOID, RtlRunEncodeUnicodeString, (UCHAR *, PUNICODE_STRING));
UDECL(VOID, RtlRunDecodeUnicodeString, (UCHAR, PUNICODE_STRING));
UDECL(NTSTATUS, RtlIoEncodeMemIoResource, (PVOID, UCHAR, ULONG64, ULONG64, ULONG64, ULONG64));
UDECL(LONG, RtlMemStreamStub, (PVOID, PVOID, ULONG, PVOID));

#define S(x) ((NTSTATUS)(x))

/* ---------- splay links ---------- */
TEST(splay_real_successor_predecessor) {
    REQUIRE(UN(RtlRealSuccessor)); REQUIRE(UN(RtlRealPredecessor));
    /*        5
     *      /   \
     *     3     8
     *      \   /
     *       4 6        in-order: 3 4 5 6 8 */
    SPLAY n3 = {0}, n4 = {0}, n5 = {0}, n6 = {0}, n8 = {0};
    n5.Parent = &n5; n5.Left = &n3; n5.Right = &n8;
    n3.Parent = &n5; n3.Right = &n4;
    n4.Parent = &n3;
    n8.Parent = &n5; n8.Left = &n6;
    n6.Parent = &n8;
    EXPECT_EQ(UN(RtlRealSuccessor)(&n3), &n4);
    EXPECT_EQ(UN(RtlRealSuccessor)(&n4), &n5);
    EXPECT_EQ(UN(RtlRealSuccessor)(&n5), &n6);
    EXPECT_EQ(UN(RtlRealSuccessor)(&n6), &n8);
    EXPECT_EQ(UN(RtlRealSuccessor)(&n8), NULL);
    EXPECT_EQ(UN(RtlRealPredecessor)(&n3), NULL);
    EXPECT_EQ(UN(RtlRealPredecessor)(&n4), &n3);
    EXPECT_EQ(UN(RtlRealPredecessor)(&n5), &n4);
    EXPECT_EQ(UN(RtlRealPredecessor)(&n6), &n5);
    EXPECT_EQ(UN(RtlRealPredecessor)(&n8), &n6);
}

/* ---------- generic tables ---------- */
static int g_cmp_group_only;
static ULONG WINAPI cmp(PVOID t, PVOID a, PVOID b) {
    const ELEM *x = a, *y = b; (void)t;
    if (x->g != y->g) return x->g < y->g ? 0 : 1;
    if (g_cmp_group_only) return 2;
    if (x->s != y->s) return x->s < y->s ? 0 : 1;
    return 2;
}
static PVOID WINAPI talloc(PVOID t, ULONG n) { (void)t; return malloc(n); }
static VOID WINAPI tfree(PVOID t, PVOID p) { (void)t; free(p); }

static void generic_table_body(int avl) {
    static ULONGLONG tbl[32];
    ELEM e[6]; PVOID ret[6]; BOOLEAN nw; PVOID node; ULONG res; ELEM k; PVOID p;
    int i;
    memset(tbl, 0, sizeof tbl);
    g_cmp_group_only = 0;
    if (avl) UN(RtlInitializeGenericTableAvl)(tbl, cmp, talloc, tfree, NULL);
    else UN(RtlInitializeGenericTable)(tbl, cmp, talloc, tfree, NULL);
#define INS(a, b, c, d) (avl ? UN(RtlInsertElementGenericTableAvl)(a, b, c, d) : UN(RtlInsertElementGenericTable)(a, b, c, d))
#define LOOK(a, b, c, d) (avl ? UN(RtlLookupElementGenericTableFullAvl)(a, b, c, d) : UN(RtlLookupElementGenericTableFull)(a, b, c, d))

    /* empty tree */
    k.g = 10; k.s = 0; node = (PVOID)1; res = 99;
    p = LOOK(tbl, &k, &node, &res);
    EXPECT_EQ(p, NULL); EXPECT_EQ(res, 0); /* TableEmptyTree */

    for (i = 0; i < 6; i++) { e[i].g = (i + 1) * 10; e[i].s = 0; }
    for (i = 0; i < 6; i++) {
        int j = (i * 5) % 6;       /* insertion order 0,5,4,3,2,1 */
        nw = 0; ret[j] = INS(tbl, &e[j], sizeof(ELEM), &nw);
        EXPECT_NE(ret[j], NULL); EXPECT_EQ(nw, TRUE);
    }
    for (i = 0; i < 6; i++) {
        k.g = (i + 1) * 10; k.s = 0; node = NULL; res = 99;
        p = LOOK(tbl, &k, &node, &res);
        EXPECT_EQ(res, 1);          /* TableFoundNode */
        EXPECT_EQ(p, ret[i]);
        EXPECT_NE(node, NULL);
        if (p) EXPECT_EQ(((ELEM *)p)->g, (i + 1) * 10);
    }
    /* absent keys: below min, between, above max */
    {
        int absent[3] = { 5, 35, 99 };
        for (i = 0; i < 3; i++) {
            k.g = absent[i]; k.s = 0; node = NULL; res = 99;
            p = LOOK(tbl, &k, &node, &res);
            EXPECT_EQ(p, NULL);
            CHECKF(res == 2 || res == 3, "SearchResult %lu for absent key %d", res, absent[i]);
            EXPECT_NE(node, NULL);
        }
        /* below the minimum is always an insert-as-left of the leftmost node */
        k.g = 5; k.s = 0; res = 99; LOOK(tbl, &k, &node, &res); EXPECT_EQ(res, 2);
        k.g = 99; k.s = 0; res = 99; LOOK(tbl, &k, &node, &res); EXPECT_EQ(res, 3);
    }
    if (avl) {
        /* first-matching: with a group-only comparison the lowest-order element of the group wins */
        ELEM d[4] = { {7,1}, {7,2}, {7,3}, {8,1} };
        PVOID r[4], restart; ELEM q = { 7, 0 };
        for (i = 0; i < 4; i++) { nw = 0; r[i] = INS(tbl, &d[i], sizeof(ELEM), &nw); EXPECT_EQ(nw, TRUE); }
        g_cmp_group_only = 1;
        restart = (PVOID)1;
        p = UN(RtlLookupFirstMatchingElementGenericTableAvl)(tbl, &q, &restart);
        EXPECT_EQ(p, r[0]);
        EXPECT_NE(restart, NULL);
        EXPECT_NE(restart, (PVOID)1);
        q.g = 8; p = UN(RtlLookupFirstMatchingElementGenericTableAvl)(tbl, &q, &restart);
        EXPECT_EQ(p, r[3]);
        q.g = 9; restart = (PVOID)1;
        p = UN(RtlLookupFirstMatchingElementGenericTableAvl)(tbl, &q, &restart);
        EXPECT_EQ(p, NULL); EXPECT_EQ(restart, NULL);
        g_cmp_group_only = 0;
    }
    /* drain the table so the allocator hooks are balanced */
    for (i = 0; i < 6; i++) {
        k.g = (i + 1) * 10; k.s = 0;
        EXPECT_EQ(avl ? UN(RtlDeleteElementGenericTableAvl)(tbl, &k) : UN(RtlDeleteElementGenericTable)(tbl, &k), TRUE);
    }
    if (avl) {
        ELEM d[4] = { {7,1}, {7,2}, {7,3}, {8,1} };
        for (i = 0; i < 4; i++) UN(RtlDeleteElementGenericTableAvl)(tbl, &d[i]);
    }
    k.g = 20; res = 99; p = LOOK(tbl, &k, &node, &res);
    EXPECT_EQ(p, NULL); EXPECT_EQ(res, 0);
#undef INS
#undef LOOK
}
TEST(generic_table_lookup_full_splay) {
    REQUIRE(UN(RtlInitializeGenericTable)); REQUIRE(UN(RtlInsertElementGenericTable));
    REQUIRE(UN(RtlLookupElementGenericTableFull)); REQUIRE(UN(RtlDeleteElementGenericTable));
    generic_table_body(0);
}
TEST(generic_table_lookup_full_avl_and_first_matching) {
    REQUIRE(UN(RtlInitializeGenericTableAvl)); REQUIRE(UN(RtlInsertElementGenericTableAvl));
    REQUIRE(UN(RtlLookupElementGenericTableFullAvl)); REQUIRE(UN(RtlDeleteElementGenericTableAvl));
    REQUIRE(UN(RtlLookupFirstMatchingElementGenericTableAvl));
    generic_table_body(1);
}

/* ---------- dynamic hash table ---------- */
TEST(hash_table_lookup_entry) {
    PVOID ht = NULL; static HENTRY ent[200]; HCTX ctx; int i;
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlLookupEntryHashTable)); REQUIRE(UN(RtlRemoveEntryHashTable)); REQUIRE(UN(RtlDeleteHashTable));
    EXPECT_EQ(UN(RtlCreateHashTable)(&ht, 0, 0), TRUE);
    if (!ht) return;
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(ht, 12345, NULL), NULL);
    memset(ent, 0, sizeof ent);
    for (i = 0; i < 200; i++)
        EXPECT_EQ(UN(RtlInsertEntryHashTable)(ht, &ent[i], (ULONG_PTR)(i * 7919 + 3), NULL), TRUE);
    for (i = 0; i < 200; i++) {
        PVOID p = UN(RtlLookupEntryHashTable)(ht, (ULONG_PTR)(i * 7919 + 3), NULL);
        EXPECT_EQ(p, &ent[i]);
        if (p) EXPECT_EQ(((HENTRY *)p)->Signature, (ULONG_PTR)(i * 7919 + 3));
    }
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(ht, 4, NULL), NULL);
    /* with an explicit zeroed context */
    memset(&ctx, 0, sizeof ctx);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(ht, (ULONG_PTR)(5 * 7919 + 3), &ctx), &ent[5]);
    EXPECT_NE(ctx.ChainHead, NULL);
    EXPECT_EQ(ctx.Signature, (ULONG_PTR)(5 * 7919 + 3));
    /* NumEntries lives at +0x14 of the table */
    EXPECT_EQ(*(ULONG *)((char *)ht + 0x14), 200);
    /* removal makes the lookup fail */
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(ht, &ent[5], NULL), TRUE);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(ht, (ULONG_PTR)(5 * 7919 + 3), NULL), NULL);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(ht, (ULONG_PTR)(6 * 7919 + 3), NULL), &ent[6]);
    for (i = 0; i < 200; i++) if (i != 5) UN(RtlRemoveEntryHashTable)(ht, &ent[i], NULL);
    UN(RtlDeleteHashTable)(ht);
}

/* ---------- atoms ---------- */
TEST(atom_lookup_pin) {
    PVOID tbl = NULL; USHORT a = 0, b = 0, c = 0; ULONG ref = 0, pin = 0, len;
    WCHAR name[40];
    REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable)); REQUIRE(UN(RtlLookupAtomInAtomTable));
    REQUIRE(UN(RtlPinAtomInAtomTable)); REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlDeleteAtomFromAtomTable));
    REQUIRE(UN(RtlDestroyAtomTable));
    EXPECT_EQ(UN(RtlCreateAtomTable)(37, &tbl), 0);
    if (!tbl) return;
    /* absent / invalid names */
    a = 0x1234;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"absent", &a), S(0xC0000034));
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"", &a), S(0xC0000033));
    /* integer atoms */
    a = 0;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"#1234", &a), 0); EXPECT_EQ(a, 1234);
    a = 0;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, (PCWSTR)(ULONG_PTR)777, &a), 0); EXPECT_EQ(a, 777);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"#49152", &a), S(0xC000000D)); /* 0xC000 is not an integer atom */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"#1234", NULL), 0);
    /* string atoms */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tbl, L"MyAtom", &a), 0);
    CHECKF(a >= 0xC000, "string atom value 0x%x", a);
    b = 0;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"MyAtom", &b), 0); EXPECT_EQ(b, a);
    b = 0;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"MYATOM", &b), 0); EXPECT_EQ(b, a); /* case-insensitive */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"MyAtom", NULL), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tbl, L"Other", &c), 0);
    EXPECT_NE(c, a);
    /* pin */
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tbl, 0), S(0xC0000008));
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tbl, 77), 0);          /* integer atoms: no-op success */
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tbl, 0xFFF0), S(0xC0000008)); /* unallocated string atom */
    ref = pin = 0xFF; len = sizeof name; name[0] = 0;
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(tbl, a, &ref, &pin, name, &len), 0);
    EXPECT_EQ(pin, 0);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tbl, a), 0);
    ref = pin = 0xFF; len = sizeof name;
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(tbl, a, &ref, &pin, name, &len), 0);
    EXPECT_EQ(pin, 1); EXPECT_EQ(ref, 1);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"MyAtom", &b), 0); EXPECT_EQ(b, a);
    /* the unpinned atom can be deleted and is then gone */
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tbl, c), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tbl, L"Other", &b), S(0xC0000034));
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tbl, c), S(0xC0000008));
    UN(RtlDestroyAtomTable)(tbl);
}

/* ---------- red-black tree ---------- */
static int rb_red(RBN *n) { return (int)(n->ParentValue & 1); }
static RBN *rb_parent(RBN *n) { return (RBN *)(n->ParentValue & ~(ULONG_PTR)3); }
/* returns black height, or -1 on violation; counts nodes */
static int rb_check(RBT *t, RBN *n, RBN *parent, int *count, int *last, int *ok) {
    int lh, rh;
    if (!n) return 1;
    (*count)++;
    if (rb_parent(n) != parent) *ok = 0;
    if (rb_red(n) && ((n->Left && rb_red(n->Left)) || (n->Right && rb_red(n->Right)))) *ok = 0;
    lh = rb_check(t, n->Left, n, count, last, ok);
    { int key = (int)(((ULONG_PTR *)n)[3]); if (key < *last) *ok = 0; *last = key; }
    rh = rb_check(t, n->Right, n, count, last, ok);
    if (lh != rh) *ok = 0;
    return lh + (rb_red(n) ? 0 : 1);
}
typedef struct { RBN n; ULONG_PTR key; } RBK;
static void rb_validate(RBT *t, int expect_count, const char *what) {
    int count = 0, last = -1, ok = 1; RBN *m;
    if (t->Root && rb_red(t->Root)) ok = 0;
    if (t->Root && rb_parent(t->Root) != NULL) ok = 0;
    rb_check(t, t->Root, NULL, &count, &last, &ok);
    if (count != expect_count) ok = 0;
    m = t->Root; while (m && m->Left) m = m->Left;
    if (m != t->Min) ok = 0;
    CHECKF(ok, "red-black invariants broken (%s), nodes %d expected %d", what, count, expect_count);
}
static void rb_insert(RBT *t, RBK *k) {
    RBN *p = NULL; RBN *cur = t->Root; BOOLEAN right = FALSE;
    while (cur) { p = cur; right = k->key > ((RBK *)cur)->key; cur = right ? cur->Right : cur->Left; }
    UN(RtlRbInsertNodeEx)(t, p, right, &k->n);
}
TEST(rbtree_insert_remove_invariants) {
    static RBK nodes[400]; RBT tree; int i, cnt = 0; unsigned seed = 12345;
    REQUIRE(UN(RtlRbInsertNodeEx)); REQUIRE(UN(RtlRbRemoveNode));
    memset(&tree, 0, sizeof tree); memset(nodes, 0, sizeof nodes);
    /* single node */
    nodes[0].key = 50;
    UN(RtlRbInsertNodeEx)(&tree, NULL, FALSE, &nodes[0].n);
    EXPECT_EQ(tree.Root, &nodes[0].n); EXPECT_EQ(tree.Min, &nodes[0].n);
    EXPECT_EQ(rb_red(&nodes[0].n), 0);
    cnt = 1;
    /* ascending run exercises rotations; then pseudo-random keys */
    for (i = 1; i < 200; i++) { nodes[i].key = 50 + i; rb_insert(&tree, &nodes[i]); cnt++; if (i % 20 == 0) rb_validate(&tree, cnt, "ascending insert"); }
    for (i = 200; i < 400; i++) { seed = seed * 1103515245u + 12345u; nodes[i].key = 1000 + (seed >> 8) % 100000 + (ULONG_PTR)i * 100001; rb_insert(&tree, &nodes[i]); cnt++; if (i % 20 == 0) rb_validate(&tree, cnt, "random insert"); }
    rb_validate(&tree, cnt, "after inserts");
    /* remove every third node, then the minimum repeatedly, validating as we go */
    for (i = 0; i < 400; i += 3) { UN(RtlRbRemoveNode)(&tree, &nodes[i].n); cnt--; if (i % 30 == 0) rb_validate(&tree, cnt, "remove"); }
    rb_validate(&tree, cnt, "after removals");
    while (tree.Min) { RBN *m = tree.Min; UN(RtlRbRemoveNode)(&tree, m); cnt--; if (cnt % 25 == 0) rb_validate(&tree, cnt, "remove min"); }
    EXPECT_EQ(cnt, 0);
    EXPECT_EQ(tree.Root, NULL); EXPECT_EQ(tree.Min, NULL);
}

/* ---------- active frames ---------- */
typedef struct { ULONG Flags; ULONG pad; PVOID Previous; PVOID Context; } FRAME;
TEST(push_pop_frame) {
    FRAME a, b; PVOID *slot = (PVOID *)((char *)NtCurrentTeb() + 0x17c0); PVOID orig;
    REQUIRE(UN(RtlPushFrame)); REQUIRE(UN(RtlPopFrame));
    orig = *slot;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    UN(RtlPushFrame)(&a);
    EXPECT_EQ(*slot, &a); EXPECT_EQ(a.Previous, orig);
    if (UN(RtlGetFrame)) EXPECT_EQ(UN(RtlGetFrame)(), &a);
    UN(RtlPushFrame)(&b);
    EXPECT_EQ(*slot, &b); EXPECT_EQ(b.Previous, &a);
    if (UN(RtlGetFrame)) EXPECT_EQ(UN(RtlGetFrame)(), &b);
    UN(RtlPopFrame)(&b);
    EXPECT_EQ(*slot, &a);
    UN(RtlPopFrame)(&a);
    EXPECT_EQ(*slot, orig);
    EXPECT_EQ(a.Previous, orig); /* popping leaves the frame's link intact */
}

/* ---------- memory zone and block lookaside ---------- */
TEST(memory_zone_alloc_reset) {
    PVOID zone = NULL, p1 = NULL, p2 = NULL, p3 = NULL, p4 = NULL, big = (PVOID)1;
    REQUIRE(UN(RtlCreateMemoryZone)); REQUIRE(UN(RtlAllocateMemoryZone));
    REQUIRE(UN(RtlResetMemoryZone)); REQUIRE(UN(RtlDestroyMemoryZone));
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0, 0), S(0xC000000D));
    EXPECT_EQ(zone, NULL);
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0x1000, 1), S(0xC000000D));
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&zone, 0x1000, 0), 0);
    if (!zone) return;
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 0, &p1), S(0xC000000D));
    EXPECT_EQ(p1, NULL);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 13, &p1), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 8, &p2), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 1, &p3), 0);
    EXPECT_NE(p1, NULL);
    EXPECT_EQ((ULONG_PTR)p2, (ULONG_PTR)p1 + 16);   /* sizes round up to 8 */
    EXPECT_EQ((ULONG_PTR)p3, (ULONG_PTR)p2 + 8);
    memset(p1, 0xAB, 13);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 0x100000, &big), S(0xC000009A));
    EXPECT_EQ(big, NULL);
    EXPECT_EQ(UN(RtlResetMemoryZone)(zone), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(zone, 13, &p4), 0);
    EXPECT_EQ(p4, p1);                              /* reset rewinds the zone */
    EXPECT_EQ(UN(RtlDestroyMemoryZone)(zone), 0);
}
TEST(memory_block_lookaside_reset) {
    PVOID la = NULL, b1 = NULL, b2 = NULL, b3 = NULL, bad = (PVOID)1;
    REQUIRE(UN(RtlCreateMemoryBlockLookaside)); REQUIRE(UN(RtlAllocateMemoryBlockLookaside));
    REQUIRE(UN(RtlFreeMemoryBlockLookaside)); REQUIRE(UN(RtlResetMemoryBlockLookaside));
    REQUIRE(UN(RtlDestroyMemoryBlockLookaside));
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x4000, 16, 256), 0);
    if (!la) return;
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 1000, &bad), S(0xC000000D)); /* above maximum block size */
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 20, &b1), 0);
    EXPECT_NE(b1, NULL);
    memset(b1, 0x5A, 20);
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 20, &b2), 0);
    EXPECT_NE(b2, b1);
    EXPECT_EQ(UN(RtlResetMemoryBlockLookaside)(la), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 20, &b3), 0);
    EXPECT_EQ(b3, b1);                              /* zones rewound by the reset */
    EXPECT_EQ(UN(RtlDestroyMemoryBlockLookaside)(la), 0);
}

/* ---------- RtlRandom / RtlRandomEx ---------- */
TEST(random_seed_progression) {
    ULONG seed, s2, i; ULONG vals[512]; int distinct = 0, j;
    REQUIRE(UN(RtlRandom)); REQUIRE(UN(RtlRandomEx));
    CHECK((void *)UN(RtlRandom) != NULL);
    EXPECT_EQ((ULONG_PTR)t_proc("RtlRandom"), (ULONG_PTR)t_proc("RtlRandomEx"));
    seed = 1;
    for (i = 0; i < 100; i++) {
        ULONGLONG want = ((ULONGLONG)seed * 0x7fffffedULL + 0x7fffffc3ULL) % 0x7fffffffULL;
        ULONG r = UN(RtlRandom)(&seed); (void)r;
        EXPECT_EQ(seed, want);
        if (seed != want) break;
    }
    seed = 0x12345; s2 = 0x12345;
    for (i = 0; i < 20; i++) { UN(RtlRandom)(&seed); UN(RtlRandomEx)(&s2); }
    EXPECT_EQ(seed, s2);                            /* both names advance the seed identically */
    EXPECT_EQ(s2 < 0x7fffffff, 1);
    seed = 777;
    for (i = 0; i < 512; i++) vals[i] = UN(RtlRandom)(&seed);
    for (i = 0; i < 512; i++) { int dup = 0; for (j = 0; j < (int)i; j++) if (vals[j] == vals[i]) { dup = 1; break; } if (!dup) distinct++; }
    CHECKF(distinct > 480, "only %d distinct values in 512", distinct);
}

/* ---------- RtlRunEncode/DecodeUnicodeString ---------- */
TEST(run_encode_decode_unicode) {
    static WCHAR buf[16] = L"Secret Value!";
    WCHAR orig[16]; UNICODE_STRING us; UCHAR seed; USHORT n; int i;
    REQUIRE(UN(RtlRunEncodeUnicodeString)); REQUIRE(UN(RtlRunDecodeUnicodeString));
    memcpy(orig, buf, sizeof buf);
    n = (USHORT)(13 * sizeof(WCHAR));
    us.Buffer = buf; us.Length = n; us.MaximumLength = sizeof buf;
    /* explicit non-zero seed: the byte stream is fully specified */
    seed = 0x55;
    UN(RtlRunEncodeUnicodeString)(&seed, &us);
    EXPECT_EQ(seed, 0x55);
    {
        UCHAR exp[26]; const UCHAR *src = (const UCHAR *)orig;
        exp[0] = src[0] ^ (0x55 | 0x43);
        for (i = 1; i < n; i++) exp[i] = exp[i - 1] ^ src[i] ^ 0x55;
        EXPECT_EQ(memcmp(buf, exp, n), 0);
    }
    EXPECT_EQ(us.Length, n);
    CHECK(memcmp(buf, orig, n) != 0);
    UN(RtlRunDecodeUnicodeString)(0x55, &us);
    EXPECT_EQ(memcmp(buf, orig, n), 0);
    /* seed 0 is replaced by a non-zero value that decodes correctly */
    seed = 0;
    UN(RtlRunEncodeUnicodeString)(&seed, &us);
    CHECK(seed != 0);
    CHECK(memcmp(buf, orig, n) != 0);
    UN(RtlRunDecodeUnicodeString)(seed, &us);
    EXPECT_EQ(memcmp(buf, orig, n), 0);
    /* zero-length string: nothing touched; length 1 touches only the first byte */
    us.Length = 0; seed = 9; UN(RtlRunEncodeUnicodeString)(&seed, &us);
    EXPECT_EQ(memcmp(buf, orig, n), 0);
    us.Length = 1; UN(RtlRunEncodeUnicodeString)(&seed, &us);
    EXPECT_EQ(((UCHAR *)buf)[0], ((UCHAR *)orig)[0] ^ (9 | 0x43));
    EXPECT_EQ(memcmp((UCHAR *)buf + 1, (UCHAR *)orig + 1, n - 1), 0);
    UN(RtlRunDecodeUnicodeString)(9, &us);
    EXPECT_EQ(memcmp(buf, orig, n), 0);
}

/* ---------- RtlIoEncodeMemIoResource ---------- */
TEST(io_encode_mem_io_resource) {
    UCHAR r[0x20]; NTSTATUS s;
    REQUIRE(UN(RtlIoEncodeMemIoResource));
    memset(r, 0, sizeof r);
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 2, 4, 8, 0, 0), S(0xC000000D));      /* unsupported type */
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 1, 0x100000000ULL, 8, 0, 0), S(0xC000000D)); /* type 1 is 32-bit only */
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 1, 0x1000, 0x20, 0x1111, 0x2222), 0);
    EXPECT_EQ(r[1], 1);
    EXPECT_EQ(*(ULONG *)(r + 8), 0x1000); EXPECT_EQ(*(ULONG *)(r + 0xc), 0x20);
    EXPECT_EQ(*(ULONG64 *)(r + 0x10), 0x1111); EXPECT_EQ(*(ULONG64 *)(r + 0x18), 0x2222);
    memset(r, 0, sizeof r);
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 3, 0x1000, 0x20, 5, 6), 0);
    EXPECT_EQ(r[1], 3);
    EXPECT_EQ(*(ULONG *)(r + 8), 0x1000); EXPECT_EQ(*(ULONG *)(r + 0xc), 0x20);
    /* values above 32 bits are stored scaled by 2^8 / 2^16 / 2^32 and flagged in the header */
    memset(r, 0, sizeof r);
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 3, 0x100000000ULL, 0x100, 0, 0), 0);
    EXPECT_EQ(r[1], 7);
    EXPECT_EQ(*(USHORT *)(r + 4) & 0xe00, 0x200);
    EXPECT_EQ(*(ULONG *)(r + 8), 0x1000000); EXPECT_EQ(*(ULONG *)(r + 0xc), 1);
    memset(r, 0, sizeof r);
    EXPECT_EQ(UN(RtlIoEncodeMemIoResource)(r, 3, 0x1000000000000ULL, 0x10000, 0, 0), 0);
    EXPECT_EQ(r[1], 7);
    EXPECT_EQ(*(USHORT *)(r + 4) & 0xe00, 0x800);
    EXPECT_EQ(*(ULONG *)(r + 8), 0x10000); EXPECT_EQ(*(ULONG *)(r + 0xc), 1);
    /* not representable */
    s = UN(RtlIoEncodeMemIoResource)(r, 3, 0x100000001ULL, 0x100, 0, 0);
    EXPECT_EQ(s, S(0xC0000001));
}

/* ---------- memory-stream helpers that only report E_NOTIMPL ---------- */
TEST(memory_stream_not_implemented) {
    const char *names[] = { "RtlReadMemoryStream", "RtlReadOutOfProcessMemoryStream", "RtlRevertMemoryStream", "RtlSeekMemoryStream" };
    FARPROC first = NULL; int i;
    for (i = 0; i < 4; i++) {
        FARPROC f = t_proc(names[i]);
        char buf[8];
        if (!f) { t_skip("missing export: %s", names[i]); return; }
        EXPECT_EQ(((LONG (WINAPI *)(PVOID, PVOID, ULONG, PVOID))f)(NULL, buf, 8, NULL), (LONG)0x80004001);
        EXPECT_EQ(((LONG (WINAPI *)(PVOID, PVOID, ULONG, PVOID))f)(buf, buf, 0, buf), (LONG)0x80004001);
        if (!first) first = f;
        EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)first); /* shared stub body */
    }
}
