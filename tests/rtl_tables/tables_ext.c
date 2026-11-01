/* Splay-link primitives and the "Full" generic-table entry points. */
#include "t.h"
#include <stdlib.h>

typedef struct XS_LINKS { struct XS_LINKS *Parent, *Left, *Right; } XS_LINKS;
typedef struct { XS_LINKS links; LONG key; } XS_NODE;
typedef enum { XLess, XGreater, XEqual } XORDER;

UDECL(XS_LINKS *, RtlSplay, (XS_LINKS *));
UDECL(XS_LINKS *, RtlDelete, (XS_LINKS *));
UDECL(void, RtlDeleteNoSplay, (XS_LINKS *, XS_LINKS **));
UDECL(XS_LINKS *, RtlSubtreeSuccessor, (XS_LINKS *));
UDECL(XS_LINKS *, RtlSubtreePredecessor, (XS_LINKS *));
UDECL(XS_LINKS *, RtlRealSuccessor, (XS_LINKS *));
UDECL(XS_LINKS *, RtlRealPredecessor, (XS_LINKS *));
UDECL(void, RtlInitializeSplayLinks, (XS_LINKS *));

/* Tables are passed as opaque aligned storage (0x48 bytes splay, 0x68 bytes AVL). */
typedef struct { _Alignas(16) BYTE raw[0x80]; } XTABLE;
typedef XORDER (WINAPI *X_COMPARE)(void *, void *, void *);
typedef void *(WINAPI *X_ALLOC)(void *, ULONG);
typedef void (WINAPI *X_FREE)(void *, void *);
UDECL(void, RtlInitializeGenericTable, (void *, X_COMPARE, X_ALLOC, X_FREE, void *));
UDECL(void, RtlInitializeGenericTableAvl, (void *, X_COMPARE, X_ALLOC, X_FREE, void *));
UDECL(void *, RtlInsertElementGenericTableFull, (void *, void *, ULONG, BOOLEAN *, void *, ULONG));
UDECL(void *, RtlInsertElementGenericTableFullAvl, (void *, void *, ULONG, BOOLEAN *, void *, ULONG));
UDECL(void *, RtlLookupElementGenericTableFull, (void *, void *, void **, ULONG *));
UDECL(void *, RtlLookupElementGenericTableFullAvl, (void *, void *, void **, ULONG *));
UDECL(void *, RtlEnumerateGenericTable, (void *, BOOLEAN));
UDECL(void *, RtlEnumerateGenericTableAvl, (void *, BOOLEAN));
UDECL(ULONG, RtlNumberGenericTableElements, (void *));
UDECL(ULONG, RtlNumberGenericTableElementsAvl, (void *));
UDECL(BOOLEAN, RtlDeleteElementGenericTable, (void *, void *));
UDECL(BOOLEAN, RtlDeleteElementGenericTableAvl, (void *, void *));

static void xs_link(XS_NODE *p, XS_NODE *l, XS_NODE *r)
{
    p->links.Left = l ? &l->links : NULL;
    p->links.Right = r ? &r->links : NULL;
    if (l) l->links.Parent = &p->links;
    if (r) r->links.Parent = &p->links;
}

/* Balanced seven-node tree, keys 1..7, root key 4. */
static XS_LINKS *xs_build(XS_NODE n[8])
{
    int i;
    memset(n, 0, 8 * sizeof(*n));
    for (i = 1; i <= 7; ++i) n[i].key = i;
    xs_link(&n[4], &n[2], &n[6]); xs_link(&n[2], &n[1], &n[3]); xs_link(&n[6], &n[5], &n[7]);
    n[4].links.Parent = &n[4].links;
    return &n[4].links;
}
static XS_NODE *xs_first(XS_LINKS *root)
{
    while (root->Left) root = root->Left;
    return (XS_NODE *)root;
}
/* In-order walk using RtlRealSuccessor; returns the number of nodes and fills keys. */
static int xs_walk(XS_LINKS *root, LONG *keys, int cap)
{
    int n = 0; XS_LINKS *c = &xs_first(root)->links;
    while (c && n < cap) { keys[n++] = ((XS_NODE *)c)->key; c = UN(RtlRealSuccessor)(c); }
    return n;
}

TEST(rtl_tables_ext_subtree_successor_predecessor) {
    REQUIRE(UN(RtlSubtreeSuccessor)); REQUIRE(UN(RtlSubtreePredecessor));
    XS_NODE n[8]; xs_build(n);
    /* Within the subtree only: leftmost of right child / rightmost of left child. */
    CHECK(UN(RtlSubtreeSuccessor)(&n[4].links) == &n[5].links);
    CHECK(UN(RtlSubtreePredecessor)(&n[4].links) == &n[3].links);
    CHECK(UN(RtlSubtreeSuccessor)(&n[2].links) == &n[3].links);
    CHECK(UN(RtlSubtreePredecessor)(&n[2].links) == &n[1].links);
    CHECK(UN(RtlSubtreeSuccessor)(&n[6].links) == &n[7].links);
    CHECK(UN(RtlSubtreePredecessor)(&n[6].links) == &n[5].links);
    /* Leaves have no subtree successor or predecessor. */
    CHECK(UN(RtlSubtreeSuccessor)(&n[1].links) == NULL);
    CHECK(UN(RtlSubtreePredecessor)(&n[7].links) == NULL);
}

TEST(rtl_tables_ext_real_successor_walks_in_order) {
    REQUIRE(UN(RtlRealSuccessor));
    XS_NODE n[8]; XS_LINKS *root = xs_build(n); LONG keys[16]; int c, i;
    c = xs_walk(root, keys, 16);
    EXPECT_EQ(c, 7);
    for (i = 0; i < c && i < 7; ++i) EXPECT_EQ(keys[i], i + 1);
    CHECK(UN(RtlRealSuccessor)(&n[7].links) == NULL);
}

TEST(rtl_tables_ext_real_predecessor_walks_in_reverse) {
    REQUIRE(UN(RtlRealPredecessor));
    XS_NODE n[8]; XS_LINKS *c; int count = 0; LONG last = 8;
    xs_build(n);
    c = &n[7].links;
    while (c && count < 16) {
        EXPECT_EQ(((XS_NODE *)c)->key, last - 1);
        last = ((XS_NODE *)c)->key; c = UN(RtlRealPredecessor)(c); ++count;
    }
    EXPECT_EQ(count, 7);
}

TEST(rtl_tables_ext_splay_brings_node_to_root) {
    REQUIRE(UN(RtlSplay)); REQUIRE(UN(RtlRealSuccessor));
    int k;
    for (k = 1; k <= 7; ++k) {
        XS_NODE n[8]; XS_LINKS *nr; LONG keys[16]; int c, i;
        xs_build(n);
        nr = UN(RtlSplay)(&n[k].links);
        CHECK(nr == &n[k].links);
        CHECK(nr->Parent == nr);
        c = xs_walk(nr, keys, 16);
        EXPECT_EQ(c, 7);
        for (i = 0; i < c && i < 7; ++i) EXPECT_EQ(keys[i], i + 1);
    }
}

TEST(rtl_tables_ext_delete_leaf_and_internal) {
    REQUIRE(UN(RtlDelete)); REQUIRE(UN(RtlRealSuccessor));
    int k;
    for (k = 1; k <= 7; ++k) {
        XS_NODE n[8]; XS_LINKS *nr; LONG keys[16]; int c, i, want = 0;
        xs_build(n);
        nr = UN(RtlDelete)(&n[k].links);
        CHECK(nr != NULL); if (!nr) continue;
        CHECK(nr->Parent == nr);
        c = xs_walk(nr, keys, 16);
        EXPECT_EQ(c, 6);
        for (i = 0; i < c && i < 6; ++i) { ++want; if (want == k) ++want; EXPECT_EQ(keys[i], want); }
    }
}

TEST(rtl_tables_ext_delete_no_splay_keeps_order) {
    REQUIRE(UN(RtlDeleteNoSplay)); REQUIRE(UN(RtlRealSuccessor));
    int k;
    for (k = 1; k <= 7; ++k) {
        XS_NODE n[8]; XS_LINKS *root; LONG keys[16]; int c, i, want = 0;
        root = xs_build(n);
        UN(RtlDeleteNoSplay)(&n[k].links, &root);
        CHECK(root != NULL); if (!root) continue;
        c = xs_walk(root, keys, 16);
        EXPECT_EQ(c, 6);
        for (i = 0; i < c && i < 6; ++i) { ++want; if (want == k) ++want; EXPECT_EQ(keys[i], want); }
    }
}

/* ---- Full entry points ------------------------------------------------- */
typedef struct { LONG key; ULONG pad; } XITEM;
typedef struct { int allocs, frees; } XCTX;
static XCTX xctx;
static XORDER WINAPI x_cmp(void *t, void *a, void *b)
{
    LONG x = ((XITEM *)a)->key, y = ((XITEM *)b)->key;
    return x < y ? XLess : x > y ? XGreater : XEqual;
}
static void *WINAPI x_alloc(void *t, ULONG n) { ++xctx.allocs; return malloc(n); }
static void WINAPI x_free(void *t, void *p) { ++xctx.frees; free(p); }

enum { X_EMPTY_TREE = 0, X_FOUND = 1, X_AS_LEFT = 2, X_AS_RIGHT = 3 };

static void full_case(int avl)
{
    XTABLE t; XITEM probe; BOOLEAN fresh; void *node = NULL; ULONG res = 99; XITEM *e;
    static const LONG keys[] = {50, 20, 80, 10, 30, 70, 90, 25};
    const unsigned nkeys = sizeof(keys) / sizeof(*keys);
    unsigned i; LONG prev; XITEM *it;
    void *(*lookup)(void *, void *, void **, ULONG *) = avl ? UN(RtlLookupElementGenericTableFullAvl) : UN(RtlLookupElementGenericTableFull);
    void *(*insert)(void *, void *, ULONG, BOOLEAN *, void *, ULONG) = avl ? UN(RtlInsertElementGenericTableFullAvl) : UN(RtlInsertElementGenericTableFull);
    void *(*enumerate)(void *, BOOLEAN) = avl ? UN(RtlEnumerateGenericTableAvl) : UN(RtlEnumerateGenericTable);
    ULONG (*number)(void *) = avl ? UN(RtlNumberGenericTableElementsAvl) : UN(RtlNumberGenericTableElements);
    BOOLEAN (*del)(void *, void *) = avl ? UN(RtlDeleteElementGenericTableAvl) : UN(RtlDeleteElementGenericTable);
    REQUIRE(lookup); REQUIRE(insert); REQUIRE(enumerate); REQUIRE(number); REQUIRE(del);
    if (avl) REQUIRE(UN(RtlInitializeGenericTableAvl)); else REQUIRE(UN(RtlInitializeGenericTable));
    memset(&t, 0, sizeof(t)); memset(&xctx, 0, sizeof(xctx));
    if (avl) UN(RtlInitializeGenericTableAvl)(&t, x_cmp, x_alloc, x_free, NULL);
    else UN(RtlInitializeGenericTable)(&t, x_cmp, x_alloc, x_free, NULL);

    probe.key = 50; probe.pad = 0;
    e = lookup(&t, &probe, &node, &res);
    CHECK(e == NULL); EXPECT_EQ(res, X_EMPTY_TREE);

    for (i = 0; i < nkeys; ++i) {
        probe.key = keys[i]; probe.pad = (ULONG)keys[i] * 3; node = NULL; res = 99;
        e = lookup(&t, &probe, &node, &res);
        CHECK(e == NULL);
        if (i == 0) EXPECT_EQ(res, X_EMPTY_TREE);
        else CHECK(res == X_AS_LEFT || res == X_AS_RIGHT);
        fresh = 0xee;
        e = insert(&t, &probe, sizeof(probe), &fresh, node, res);
        CHECK(e != NULL); EXPECT_EQ(fresh, 1);
        if (e) { EXPECT_EQ(e->key, keys[i]); EXPECT_EQ(e->pad, (ULONG)keys[i] * 3); }
    }
    EXPECT_EQ(number(&t), nkeys);
    EXPECT_EQ(xctx.allocs, nkeys);

    for (i = 0; i < nkeys; ++i) {
        probe.key = keys[i]; node = NULL; res = 99;
        e = lookup(&t, &probe, &node, &res);
        CHECK(e != NULL); EXPECT_EQ(res, X_FOUND);
        if (e) EXPECT_EQ(e->key, keys[i]);
    }
    /* Inserting an existing key through the Full path returns it with fresh == FALSE. */
    probe.key = 30; node = NULL; res = 99;
    e = lookup(&t, &probe, &node, &res);
    fresh = 0xee;
    e = insert(&t, &probe, sizeof(probe), &fresh, node, res);
    CHECK(e != NULL); EXPECT_EQ(fresh, 0);
    EXPECT_EQ(number(&t), nkeys);

    /* Enumeration is in key order. */
    prev = -1; i = 0;
    for (it = enumerate(&t, TRUE); it; it = enumerate(&t, FALSE)) {
        CHECK(it->key > prev); prev = it->key; ++i;
        if (i > 32) break;
    }
    EXPECT_EQ(i, nkeys);

    for (i = 0; i < nkeys; ++i) {
        probe.key = keys[i]; CHECK(del(&t, &probe));
    }
    EXPECT_EQ(number(&t), 0); EXPECT_EQ(xctx.frees, xctx.allocs);
}
TEST(rtl_tables_ext_full_splay_table) { full_case(0); }
TEST(rtl_tables_ext_full_avl_table) { full_case(1); }

TEST(rtl_tables_ext_full_lookup_side_matches_comparison) {
    REQUIRE(UN(RtlInitializeGenericTable)); REQUIRE(UN(RtlLookupElementGenericTableFull));
    REQUIRE(UN(RtlInsertElementGenericTableFull)); REQUIRE(UN(RtlDeleteElementGenericTable));
    XTABLE t; XITEM probe; void *node; ULONG res; BOOLEAN fresh; XITEM *e;
    memset(&t, 0, sizeof(t)); memset(&xctx, 0, sizeof(xctx));
    UN(RtlInitializeGenericTable)(&t, x_cmp, x_alloc, x_free, NULL);
    probe.key = 100; probe.pad = 0; node = NULL; res = 99;
    UN(RtlLookupElementGenericTableFull)(&t, &probe, &node, &res);
    e = UN(RtlInsertElementGenericTableFull)(&t, &probe, sizeof(probe), &fresh, node, res);
    CHECK(e != NULL);
    probe.key = 50; node = NULL; res = 99;
    CHECK(UN(RtlLookupElementGenericTableFull)(&t, &probe, &node, &res) == NULL);
    EXPECT_EQ(res, X_AS_LEFT); CHECK(node != NULL);
    probe.key = 150; node = NULL; res = 99;
    CHECK(UN(RtlLookupElementGenericTableFull)(&t, &probe, &node, &res) == NULL);
    EXPECT_EQ(res, X_AS_RIGHT); CHECK(node != NULL);
    probe.key = 100; UN(RtlDeleteElementGenericTable)(&t, &probe);
}
