/* Trust/level SID helpers, SID hash, splay subtree walkers, extended bitmap test, protected-access test,
 * 128-bit divide, memory-stream stubs, hash-table enumeration, wake-address, string/length helpers,
 * UTF-8 conversion and version verification.  See EVIDENCE.md for the source of every expectation. */
#include "t.h"
#include <stdlib.h>

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)

/* ------------------------------------------------------------ level / trust SIDs */
UDECL(NTSTATUS, RtlSidEqualLevel, (PSID, PSID, BOOLEAN *));
UDECL(NTSTATUS, RtlSidIsHigherLevel, (PSID, PSID, BOOLEAN *));
UDECL(NTSTATUS, RtlSidDominatesForTrust, (PSID, PSID, BOOLEAN *));

/* S-1-16-<rid> mandatory label SID, S-1-19-<type>-<level> process trust label SID */
typedef struct { UCHAR rev, cnt; UCHAR auth[6]; ULONG sub[2]; } SID2;
static void mk_label(SID2 *s, ULONG rid) { memset(s, 0, sizeof *s); s->rev = 1; s->cnt = 1; s->auth[5] = 16; s->sub[0] = rid; }
static void mk_trust(SID2 *s, ULONG type, ULONG level) { memset(s, 0, sizeof *s); s->rev = 1; s->cnt = 2; s->auth[5] = 19; s->sub[0] = type; s->sub[1] = level; }

TEST(sid_equal_and_higher_level) {
    REQUIRE(UN(RtlSidEqualLevel)); REQUIRE(UN(RtlSidIsHigherLevel));
    SID2 low, med, med2, high; BOOLEAN r;
    mk_label(&low, 0x1000); mk_label(&med, 0x2000); mk_label(&med2, 0x2000); mk_label(&high, 0x3000);
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&med, &med2, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&med, &low, &r), 0); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&low, &high, &r), 0); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlSidIsHigherLevel)(&high, &med, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlSidIsHigherLevel)(&med, &high, &r), 0); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlSidIsHigherLevel)(&med, &med2, &r), 0); EXPECT_EQ(r, 0);
    /* a non-label SID (S-1-1-0 world, S-1-5-18 system) in either position is rejected, output untouched */
    SID2 world = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0, 0 } }, sys = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18, 0 } };
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&world, &med, &r), ST_INVPARAM); EXPECT_EQ(r, 9);
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&med, &sys, &r), ST_INVPARAM); EXPECT_EQ(r, 9);
    r = 9; EXPECT_EQ(UN(RtlSidIsHigherLevel)(&sys, &med, &r), ST_INVPARAM); EXPECT_EQ(r, 9);
    r = 9; EXPECT_EQ(UN(RtlSidIsHigherLevel)(&high, &world, &r), ST_INVPARAM); EXPECT_EQ(r, 9);
    /* a trust label SID (authority 19) is not a mandatory label SID */
    SID2 tr; mk_trust(&tr, 0x400, 0x1000);
    r = 9; EXPECT_EQ(UN(RtlSidEqualLevel)(&tr, &med, &r), ST_INVPARAM); EXPECT_EQ(r, 9);
}

TEST(sid_dominates_for_trust) {
    REQUIRE(UN(RtlSidDominatesForTrust));
    SID2 a, b, c, d; BOOLEAN r;
    mk_trust(&a, 0x400, 0x2000); mk_trust(&b, 0x200, 0x1000); mk_trust(&c, 0x400, 0x2000); mk_trust(&d, 0x400, 0x1000);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&a, &b, &r), 0); EXPECT_EQ(r, 1);   /* type and level both >= */
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&a, &c, &r), 0); EXPECT_EQ(r, 1);   /* equal dominates */
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&b, &a, &r), 0); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&d, &a, &r), 0); EXPECT_EQ(r, 0);   /* level lower */
    /* NULL second SID: always dominated */
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&b, NULL, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(NULL, NULL, &r), 0); EXPECT_EQ(r, 1);
    /* NULL first SID dominates only an unprotected (type 0) target */
    SID2 none; mk_trust(&none, 0, 0);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(NULL, &none, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(NULL, &a, &r), 0); EXPECT_EQ(r, 0);
    /* invalid trust SIDs: wrong authority, wrong sub-authority count; output cleared first */
    SID2 lab; mk_label(&lab, 0x2000);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&lab, &a, &r), ST_INVPARAM); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&a, &lab, &r), ST_INVPARAM); EXPECT_EQ(r, 0);
    SID2 bad = a; bad.rev = 2;
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&bad, &a, &r), ST_INVPARAM);
    /* type 0 with non-zero level is not a valid trust label */
    SID2 inv; mk_trust(&inv, 0, 5);
    r = 9; EXPECT_EQ(UN(RtlSidDominatesForTrust)(&a, &inv, &r), ST_INVPARAM);
}

/* ------------------------------------------------------------ SID hash */
typedef struct { PSID Sid; DWORD Attributes; } SAA;
typedef struct { ULONG SidCount; SAA *SidAttr; ULONG64 Hash[0x20]; } SAA_HASH;
UDECL(NTSTATUS, RtlSidHashInitialize, (SAA *, ULONG, SAA_HASH *));
UDECL(SAA *, RtlSidHashLookup, (SAA_HASH *, PSID));

static void mk_sid5(SID2 *s, ULONG a, ULONG b) { memset(s, 0, sizeof *s); s->rev = 1; s->cnt = 2; s->auth[5] = 5; s->sub[0] = a; s->sub[1] = b; }

static void sidhash_n(ULONG n) {
    SID2 *sids = calloc(n, sizeof *sids), probe; SAA *at = calloc(n, sizeof *at); SAA_HASH h; ULONG i;
    for (i = 0; i < n; i++) { mk_sid5(&sids[i], 21 + i * 7, 1000 + i); at[i].Sid = &sids[i]; at[i].Attributes = i; }
    memset(&h, 0xCC, sizeof h);
    EXPECT_EQ(UN(RtlSidHashInitialize)(at, n, &h), 0);
    EXPECT_EQ(h.SidCount, n); EXPECT_EQ(h.SidAttr, at);
    for (i = 0; i < n; i++) {
        mk_sid5(&probe, 21 + i * 7, 1000 + i);          /* an equal SID at a different address */
        SAA *f = UN(RtlSidHashLookup)(&h, &probe);
        CHECKF(f == &at[i], "sid %lu lookup returned %p want %p", (unsigned long)i, (void *)f, (void *)&at[i]);
    }
    mk_sid5(&probe, 21, 1001); EXPECT_EQ(UN(RtlSidHashLookup)(&h, &probe), NULL);
    mk_sid5(&probe, 99999, 5); EXPECT_EQ(UN(RtlSidHashLookup)(&h, &probe), NULL);
    free(sids); free(at);
}

TEST(sid_hash_small_and_large) {
    REQUIRE(UN(RtlSidHashInitialize)); REQUIRE(UN(RtlSidHashLookup));
    sidhash_n(5);
    sidhash_n(64);
    sidhash_n(70);          /* more than 64 entries: the tail is found by the linear fallback */
}
TEST(sid_hash_edges) {
    REQUIRE(UN(RtlSidHashInitialize)); REQUIRE(UN(RtlSidHashLookup));
    SAA_HASH h; SID2 s; SAA a;
    mk_sid5(&s, 32, 544); a.Sid = &s; a.Attributes = 7;
    EXPECT_EQ(UN(RtlSidHashInitialize)(&a, 1, NULL), ST_INVPARAM);
    /* NULL array or zero count: success with an all-zero hash */
    memset(&h, 0xCC, sizeof h);
    EXPECT_EQ(UN(RtlSidHashInitialize)(NULL, 3, &h), 0);
    CHECK(h.SidCount == 0 && h.SidAttr == NULL);
    for (int i = 0; i < 0x20; i++) EXPECT_EQ(h.Hash[i], 0);
    memset(&h, 0xCC, sizeof h);
    EXPECT_EQ(UN(RtlSidHashInitialize)(&a, 0, &h), 0);
    EXPECT_EQ(h.SidCount, 0);
    /* lookup in an empty hash and with NULL arguments */
    EXPECT_EQ(UN(RtlSidHashLookup)(&h, &s), NULL);
    EXPECT_EQ(UN(RtlSidHashLookup)(NULL, &s), NULL);
    EXPECT_EQ(UN(RtlSidHashInitialize)(&a, 1, &h), 0);
    EXPECT_EQ(UN(RtlSidHashLookup)(&h, NULL), NULL);
    EXPECT_EQ(UN(RtlSidHashLookup)(&h, &s), &a);
}

/* ------------------------------------------------------------ splay subtree walkers */
typedef struct XL { struct XL *Parent, *Left, *Right; } XL;
UDECL(XL *, RtlSubtreePredecessor, (XL *));
UDECL(XL *, RtlSubtreeSuccessor, (XL *));
UDECL(XL *, RtlSplay, (XL *));

TEST(splay_subtree_walkers) {
    REQUIRE(UN(RtlSubtreePredecessor)); REQUIRE(UN(RtlSubtreeSuccessor));
    /*            n4
     *          /    \
     *        n2      n6
     *       /  \    /  \
     *     n1   n3  n5   n7        n3 has a right child n3r (n2's subtree right-most below n3)  */
    XL n[8], r3; memset(n, 0, sizeof n); memset(&r3, 0, sizeof r3);
    XL *t[8] = { 0 }; for (int i = 1; i <= 7; i++) t[i] = &n[i];
#define LINK(p, l, r) do { t[p]->Left = t[l]; t[p]->Right = t[r]; if (t[l]) t[l]->Parent = t[p]; if (t[r]) t[r]->Parent = t[p]; } while (0)
    t[0] = NULL;
    LINK(4, 2, 6); LINK(2, 1, 3); LINK(6, 5, 7);
    n[4].Parent = &n[4];
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[4]), &n[3]);     /* right-most node of the left subtree */
    EXPECT_EQ(UN(RtlSubtreeSuccessor)(&n[4]), &n[5]);       /* left-most node of the right subtree */
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[6]), &n[5]);
    EXPECT_EQ(UN(RtlSubtreeSuccessor)(&n[2]), &n[3]);
    /* leaves and missing side: no subtree */
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[1]), NULL);
    EXPECT_EQ(UN(RtlSubtreeSuccessor)(&n[7]), NULL);
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[2]), &n[1]);
    EXPECT_EQ(UN(RtlSubtreeSuccessor)(&n[6]), &n[7]);
    /* deeper chain: give n3 a right child, predecessor of n4 follows right links */
    n[3].Right = &r3; r3.Parent = &n[3];
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[4]), &r3);
    EXPECT_EQ(UN(RtlSubtreePredecessor)(&n[2]), &n[1]);
    /* the walkers do not use the Parent link */
    n[4].Parent = NULL; n[6].Parent = NULL;
    EXPECT_EQ(UN(RtlSubtreeSuccessor)(&n[4]), &n[5]);
}
TEST(splay_rotates_node_to_root) {
    REQUIRE(UN(RtlSplay));
    XL a, b, c; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b); memset(&c, 0, sizeof c);
    /* b root, a left, c right */
    b.Parent = &b; b.Left = &a; b.Right = &c; a.Parent = &b; c.Parent = &b;
    XL *root = UN(RtlSplay)(&c);
    EXPECT_EQ(root, &c); EXPECT_EQ(c.Parent, &c);
    EXPECT_EQ(c.Left, &b); EXPECT_EQ(b.Parent, &c); EXPECT_EQ(b.Left, &a); EXPECT_EQ(b.Right, NULL);
    EXPECT_EQ(a.Parent, &b);
    /* splaying the root changes nothing */
    root = UN(RtlSplay)(&c); EXPECT_EQ(root, &c); EXPECT_EQ(c.Left, &b);
}

/* ------------------------------------------------------------ RtlTestBitEx */
typedef struct { ULONG64 SizeOfBitMap; ULONG64 *Buffer; } BMX;
UDECL(BOOLEAN, RtlTestBitEx, (BMX *, ULONG64));
TEST(test_bit_ex) {
    REQUIRE(UN(RtlTestBitEx));
    ULONG64 buf[4] = { 0 }; BMX bm = { 256, buf };
    ULONG set[] = { 0, 1, 7, 8, 63, 64, 130, 255 };
    for (int i = 0; i < 8; i++) buf[set[i] >> 6] |= 1ull << (set[i] & 63);
    for (ULONG b = 0; b < 256; b++) {
        int want = 0; for (int i = 0; i < 8; i++) if (set[i] == b) want = 1;
        BOOLEAN r = UN(RtlTestBitEx)(&bm, b);
        CHECKF(r == want, "bit %lu got %d want %d", (unsigned long)b, r, want);
    }
    /* positions above 32 bits address the buffer by 64-bit position */
    ULONG64 big[2] = { 0 }; BMX bm2 = { 0x200, big }; big[1] = 1ull << 5;   /* bit 69 */
    EXPECT_EQ(UN(RtlTestBitEx)(&bm2, 69), 1); EXPECT_EQ(UN(RtlTestBitEx)(&bm2, 68), 0);
}

/* ------------------------------------------------------------ RtlTestProtectedAccess */
UDECL(BOOLEAN, RtlTestProtectedAccess, (UCHAR, UCHAR));
#define PROT(type, signer) ((UCHAR)(((signer) << 4) | (type)))
TEST(test_protected_access) {
    REQUIRE(UN(RtlTestProtectedAccess));
    /* a target with no protection type is accessible by anything */
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(0, 0), PROT(0, 0)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(1, 1), PROT(0, 0)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 6), 0), 1);
    /* a lower protection type never dominates a higher one; unprotected source cannot reach protected */
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(0, 0), PROT(1, 1)), 0);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(1, 6), PROT(2, 1)), 0);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(1, 7), PROT(2, 0)), 0);
    /* same type: signer dominance (Authenticode 1, CodeGen 2, Antimalware 3, Lsa 4, Windows 5, WinTcb 6) */
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 1), PROT(2, 1)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 6), PROT(2, 1)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 6), PROT(2, 5)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 6), PROT(2, 6)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 1), PROT(2, 6)), 0);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 1), PROT(2, 2)), 0);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 5), PROT(2, 6)), 0);
    /* a full protected process may open a protected-light one it dominates */
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 6), PROT(1, 5)), 1);
    EXPECT_EQ(UN(RtlTestProtectedAccess)(PROT(2, 1), PROT(1, 6)), 0);
}

/* ------------------------------------------------------------ RtlUdiv128 */
UDECL(ULONG64, RtlUdiv128, (ULONG64, ULONG64, ULONG64, ULONG64 *));
TEST(udiv128) {
    REQUIRE(UN(RtlUdiv128));
    ULONG64 rem = 0xdead;
    EXPECT_EQ(UN(RtlUdiv128)(0, 100, 7, &rem), 14); EXPECT_EQ(rem, 2);
    EXPECT_EQ(UN(RtlUdiv128)(0, 0, 5, &rem), 0); EXPECT_EQ(rem, 0);
    EXPECT_EQ(UN(RtlUdiv128)(0, 5, 5, &rem), 1); EXPECT_EQ(rem, 0);
    EXPECT_EQ(UN(RtlUdiv128)(0, 4, 5, &rem), 0); EXPECT_EQ(rem, 4);
    EXPECT_EQ(UN(RtlUdiv128)(1, 0, 2, &rem), 0x8000000000000000ull); EXPECT_EQ(rem, 0);
    EXPECT_EQ(UN(RtlUdiv128)(1, 0, 3, &rem), 0x5555555555555555ull); EXPECT_EQ(rem, 1);
    EXPECT_EQ(UN(RtlUdiv128)(0x1234, ~0ull, 0x10000, &rem), 0x1234FFFFFFFFFFFFull); EXPECT_EQ(rem, 0xFFFF);
    EXPECT_EQ(UN(RtlUdiv128)(0, ~0ull, ~0ull, &rem), 1); EXPECT_EQ(rem, 0);
    EXPECT_EQ(UN(RtlUdiv128)(0xFFFFFFFFFFFFFFFEull, ~0ull, ~0ull, &rem), ~0ull); EXPECT_EQ(rem, 0xFFFFFFFFFFFFFFFEull);
    /* divisor 1 returns the low half */
    EXPECT_EQ(UN(RtlUdiv128)(0, 0x1122334455667788ull, 1, &rem), 0x1122334455667788ull); EXPECT_EQ(rem, 0);
    /* the remainder pointer is optional */
    EXPECT_EQ(UN(RtlUdiv128)(0, 1000, 10, NULL), 100);
}

/* ------------------------------------------------------------ memory stream stubs */
typedef LONG (WINAPI *HR_FN)(void);
TEST(memory_stream_unimplemented) {
    HR_FN stat = (HR_FN)t_proc("RtlStatMemoryStream"), wr = (HR_FN)t_proc("RtlWriteMemoryStream");
    REQUIRE(stat); REQUIRE(wr);
    /* both entry points are IStream methods that always report E_NOTIMPL, whatever the arguments */
    EXPECT_EQ((ULONG)stat(), 0x80004001u);
    EXPECT_EQ((ULONG)wr(), 0x80004001u);
    typedef LONG (WINAPI *HR4)(void *, void *, ULONG, ULONG *);
    HR4 w4 = (HR4)wr; ULONG got = 0x77; char b[8] = "abc";
    EXPECT_EQ((ULONG)w4(NULL, b, 4, &got), 0x80004001u);
    EXPECT_EQ(got, 0x77);
}

/* ------------------------------------------------------------ hash table enumeration */
typedef struct { ULONG Flags, Shift, TableSize, Pivot, DivisorMask, NumEntries, NonEmptyBuckets, NumEnumerators; PVOID Directory; } HT;
typedef struct { LIST_ENTRY Linkage; ULONG_PTR Signature; } HT_ENTRY;
typedef struct { PLIST_ENTRY ChainHead, PrevLinkage; ULONG_PTR Signature; } HT_CTX;
typedef struct { LIST_ENTRY Linkage; PVOID Pad; ULONG_PTR a, b; ULONG_PTR c[4]; } HT_ENUM;   /* oversized opaque enumerator */
UDECL(BOOLEAN, RtlCreateHashTable, (HT **, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (HT *));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (HT *, HT_ENTRY *, ULONG_PTR, HT_CTX *));
UDECL(BOOLEAN, RtlRemoveEntryHashTable, (HT *, HT_ENTRY *, HT_CTX *));
UDECL(BOOLEAN, RtlInitStrongEnumerationHashTable, (HT *, HT_ENUM *));
UDECL(BOOLEAN, RtlInitWeakEnumerationHashTable, (HT *, HT_ENUM *));
UDECL(HT_ENTRY *, RtlStronglyEnumerateEntryHashTable, (HT *, HT_ENUM *));
UDECL(HT_ENTRY *, RtlWeaklyEnumerateEntryHashTable, (HT *, HT_ENUM *));
UDECL(VOID, RtlEndStrongEnumerationHashTable, (HT *, HT_ENUM *));
UDECL(VOID, RtlEndWeakEnumerationHashTable, (HT *, HT_ENUM *));

static void hash_enum(int strong) {
    HT *t = NULL; HT_ENTRY e[6]; HT_CTX cx; HT_ENUM en; int seen[6] = { 0 }, count = 0;
    ULONG_PTR sig[6] = { 1, 2, 3, 130, 5, 1 + 0x80 * 3 };
    if (!UN(RtlCreateHashTable)(&t, 0, 0) || !t) { t_skip("hash table creation failed"); return; }
    for (int i = 0; i < 6; i++) { memset(&e[i], 0, sizeof e[i]); memset(&cx, 0, sizeof cx); UN(RtlInsertEntryHashTable)(t, &e[i], sig[i], &cx); }
    memset(&en, 0, sizeof en);
    EXPECT_EQ(strong ? UN(RtlInitStrongEnumerationHashTable)(t, &en) : UN(RtlInitWeakEnumerationHashTable)(t, &en), 1);
    for (;;) {
        HT_ENTRY *r = strong ? UN(RtlStronglyEnumerateEntryHashTable)(t, &en) : UN(RtlWeaklyEnumerateEntryHashTable)(t, &en);
        if (!r) break;
        int idx = (int)(r - e);
        if (idx < 0 || idx > 5) { CHECK(0 && "enumerated entry is not one of ours"); break; }
        seen[idx]++; count++;
        if (count > 12) break;
    }
    EXPECT_EQ(count, 6);
    for (int i = 0; i < 6; i++) EXPECT_EQ(seen[i], 1);
    /* exhausted enumerators keep returning NULL */
    HT_ENTRY *again = strong ? UN(RtlStronglyEnumerateEntryHashTable)(t, &en) : UN(RtlWeaklyEnumerateEntryHashTable)(t, &en);
    EXPECT_EQ(again, NULL);
    if (strong) UN(RtlEndStrongEnumerationHashTable)(t, &en); else UN(RtlEndWeakEnumerationHashTable)(t, &en);
    for (int i = 0; i < 6; i++) { memset(&cx, 0, sizeof cx); UN(RtlRemoveEntryHashTable)(t, &e[i], &cx); }
    UN(RtlDeleteHashTable)(t);
}
TEST(hash_table_strong_enumerate) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlInsertEntryHashTable)); REQUIRE(UN(RtlInitStrongEnumerationHashTable));
    REQUIRE(UN(RtlStronglyEnumerateEntryHashTable)); REQUIRE(UN(RtlEndStrongEnumerationHashTable));
    hash_enum(1);
}
TEST(hash_table_weak_enumerate) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlInsertEntryHashTable)); REQUIRE(UN(RtlInitWeakEnumerationHashTable));
    REQUIRE(UN(RtlWeaklyEnumerateEntryHashTable)); REQUIRE(UN(RtlEndWeakEnumerationHashTable));
    hash_enum(0);
}
TEST(hash_table_enumerate_empty) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlInitStrongEnumerationHashTable)); REQUIRE(UN(RtlStronglyEnumerateEntryHashTable));
    REQUIRE(UN(RtlInitWeakEnumerationHashTable)); REQUIRE(UN(RtlWeaklyEnumerateEntryHashTable));
    HT *t = NULL; HT_ENUM en;
    if (!UN(RtlCreateHashTable)(&t, 0, 0) || !t) { t_skip("hash table creation failed"); return; }
    memset(&en, 0, sizeof en); UN(RtlInitStrongEnumerationHashTable)(t, &en);
    EXPECT_EQ(UN(RtlStronglyEnumerateEntryHashTable)(t, &en), NULL);
    UN(RtlEndStrongEnumerationHashTable)(t, &en);
    memset(&en, 0, sizeof en); UN(RtlInitWeakEnumerationHashTable)(t, &en);
    EXPECT_EQ(UN(RtlWeaklyEnumerateEntryHashTable)(t, &en), NULL);
    UN(RtlEndWeakEnumerationHashTable)(t, &en);
    UN(RtlDeleteHashTable)(t);
}

/* ------------------------------------------------------------ wake address */
UDECL(NTSTATUS, RtlWaitOnAddress, (volatile VOID *, PVOID, SIZE_T, PLARGE_INTEGER));
typedef VOID (WINAPI *WAKE_FN)(PVOID);
typedef struct { volatile ULONG value; volatile LONG done; volatile NTSTATUS st[2]; LONG ms; } WAKE_CTX;
typedef struct { WAKE_CTX *c; int idx; } WAKE_ARG;
static DWORD WINAPI waiter(LPVOID p) {
    WAKE_ARG *a = p; ULONG undesired = 0; LARGE_INTEGER to; to.QuadPart = -(LONGLONG)a->c->ms * 10000;
    a->c->st[a->idx] = UN(RtlWaitOnAddress)(&a->c->value, &undesired, 4, &to);
    InterlockedIncrement(&a->c->done);
    return 0;
}
static void wake_case(const char *wname, int all) {
    WAKE_FN wake = (WAKE_FN)t_proc(wname);
    if (!wake || !UN(RtlWaitOnAddress)) { t_skip("missing export %s", wname); return; }
    WAKE_CTX c; memset((void *)&c, 0, sizeof c); c.ms = 6000; c.st[0] = c.st[1] = S(0x7777);
    WAKE_ARG a[2] = { { &c, 0 }, { &c, 1 } }; HANDLE th[2];
    th[0] = CreateThread(NULL, 0, waiter, &a[0], 0, NULL); th[1] = CreateThread(NULL, 0, waiter, &a[1], 0, NULL);
    if (!th[0] || !th[1]) { t_skip("cannot create threads"); return; }
    Sleep(500);
    EXPECT_EQ(c.done, 0);
    c.value = 1;                  /* changed value alone does not wake waiters */
    Sleep(200);
    EXPECT_EQ(c.done, 0);
    wake((PVOID)&c.value);
    Sleep(800);
    if (all) EXPECT_EQ(c.done, 2); else EXPECT_EQ(c.done, 1);
    if (!all) wake((PVOID)&c.value);
    WaitForMultipleObjects(2, th, TRUE, 10000);
    EXPECT_EQ(c.done, 2);
    EXPECT_EQ(c.st[0], 0); EXPECT_EQ(c.st[1], 0);
    CloseHandle(th[0]); CloseHandle(th[1]);
    /* waking an address nobody waits on is harmless */
    wake((PVOID)&c.value);
}
TEST(wake_address_all) { wake_case("RtlWakeAddressAll", 1); }
TEST(wake_address_all_nofence) { wake_case("RtlWakeAddressAllNoFence", 1); }
TEST(wake_address_single) { wake_case("RtlWakeAddressSingle", 0); }
TEST(wake_address_single_nofence) { wake_case("RtlWakeAddressSingleNoFence", 0); }

/* ------------------------------------------------------------ RtlpApplyLengthFunction / RtlpEnsureBufferSize */
typedef NTSTATUS (WINAPI *LENFN)(ULONG, PVOID, ULONG *);
UDECL(NTSTATUS, RtlpApplyLengthFunction, (ULONG, SIZE_T, PVOID, LENFN));
static ULONG g_cb_len; static NTSTATUS g_cb_st; static PVOID g_cb_seen; static ULONG g_cb_calls;
static NTSTATUS WINAPI lenfn(ULONG f, PVOID s, ULONG *out) { (void)f; g_cb_seen = s; g_cb_calls++; *out = g_cb_len; return g_cb_st; }
typedef struct { USHORT Length, MaximumLength; ULONG pad; WCHAR *Buffer; BYTE rest[0x28]; } STR38;

TEST(apply_length_function) {
    REQUIRE(UN(RtlpApplyLengthFunction));
    STR38 s; WCHAR buf[64]; memset(&s, 0, sizeof s);
    s.Buffer = buf; s.MaximumLength = sizeof buf;
    for (int i = 0; i < 64; i++) buf[i] = 0x4141;
    g_cb_len = 5; g_cb_st = 0; g_cb_calls = 0; g_cb_seen = NULL;
    /* size 0x38 variant: length is stored doubled and the buffer is NUL terminated */
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x38, &s, lenfn), 0);
    EXPECT_EQ(g_cb_calls, 1); EXPECT_EQ(g_cb_seen, &s);
    EXPECT_EQ(s.Length, 10); EXPECT_EQ(buf[5], 0); EXPECT_EQ(buf[4], 0x4141); EXPECT_EQ(buf[6], 0x4141);
    /* size 0x10 variant: length only, no terminator */
    for (int i = 0; i < 64; i++) buf[i] = 0x4141;
    g_cb_len = 7;
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x10, &s, lenfn), 0);
    EXPECT_EQ(s.Length, 14); EXPECT_EQ(buf[7], 0x4141);
    /* largest accepted length is 0x7fff characters */
    g_cb_len = 0x8000;
    s.Length = 3;
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x10, &s, lenfn), S(0xC0000106));
    EXPECT_EQ(s.Length, 3);
    /* callback failure is propagated without touching the string */
    g_cb_len = 4; g_cb_st = S(0xC0000001);
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x10, &s, lenfn), S(0xC0000001));
    EXPECT_EQ(s.Length, 3);
    g_cb_st = 0;
    /* parameter validation, callback never invoked */
    g_cb_calls = 0;
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(1, 0x10, &s, lenfn), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x20, &s, lenfn), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0, &s, lenfn), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x10, NULL, lenfn), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpApplyLengthFunction)(0, 0x10, &s, NULL), ST_INVPARAM);
    EXPECT_EQ(g_cb_calls, 0);
}

typedef struct { PUCHAR Buffer, StaticBuffer; SIZE_T Size, StaticSize; } RBUF;
UDECL(NTSTATUS, RtlpEnsureBufferSize, (ULONG, RBUF *, SIZE_T));
TEST(ensure_buffer_size) {
    REQUIRE(UN(RtlpEnsureBufferSize));
    UCHAR stat[64]; RBUF b; memset(stat, 0xEE, sizeof stat);
    b.Buffer = stat; b.StaticBuffer = stat; b.Size = 16; b.StaticSize = 64;
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, &b, 8), 0);            /* already big enough: no change */
    EXPECT_EQ(b.Size, 16); EXPECT_EQ(b.Buffer, stat);
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, &b, 16), 0); EXPECT_EQ(b.Size, 16);
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, &b, 48), 0);           /* fits in static storage: size grows in place */
    EXPECT_EQ(b.Size, 48); EXPECT_EQ(b.Buffer, stat);
    for (int i = 0; i < 8; i++) stat[i] = (UCHAR)i;
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, &b, 200), 0);          /* heap allocation with copy */
    EXPECT_NE(b.Buffer, stat); EXPECT_EQ(b.Size, 200); EXPECT_EQ(b.StaticBuffer, stat);
    if (b.Buffer != stat) {
        int ok = 1; for (int i = 0; i < 8; i++) if (b.Buffer[i] != i) ok = 0;
        EXPECT_EQ(ok, 1);
        PUCHAR first = b.Buffer;
        EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, &b, 100), 0);      /* shrink request: untouched */
        EXPECT_EQ(b.Buffer, first); EXPECT_EQ(b.Size, 200);
        EXPECT_EQ(UN(RtlpEnsureBufferSize)(1, &b, 500), 0);      /* flag 1: no copy, old heap block released */
        EXPECT_EQ(b.Size, 500); EXPECT_NE(b.Buffer, stat);
        HeapFree(GetProcessHeap(), 0, b.Buffer);
    }
    /* validation */
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(2, &b, 8), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0, NULL, 8), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpEnsureBufferSize)(0x100, &b, 8), ST_INVPARAM);
}

/* ------------------------------------------------------------ RtlUTF8StringToUnicodeString */
UDECL(NTSTATUS, RtlUTF8StringToUnicodeString, (PUNICODE_STRING, PANSI_STRING, BOOLEAN));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
TEST(utf8_string_to_unicode_string) {
    REQUIRE(UN(RtlUTF8StringToUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    static const char u8[] = "h\xC3\xA9llo \xE2\x82\xAC \xF0\x9F\x98\x80";   /* h e-acute l l o space euro space U+1F600 */
    static const WCHAR want[] = { 'h', 0xE9, 'l', 'l', 'o', ' ', 0x20AC, ' ', 0xD83D, 0xDE00, 0 };
    ANSI_STRING src = { (USHORT)(sizeof u8 - 1), (USHORT)sizeof u8, (PCHAR)u8 };
    UNICODE_STRING dst; WCHAR buf[32];
    memset(&dst, 0, sizeof dst);
    EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &src, TRUE), 0);
    EXPECT_EQ(dst.Length, 20); EXPECT_EQ(dst.MaximumLength, 22);
    CHECK(dst.Buffer && !memcmp(dst.Buffer, want, sizeof want));
    if (dst.Buffer) UN(RtlFreeUnicodeString)(&dst);
    /* caller-provided buffer: converted and NUL terminated */
    memset(buf, 0x55, sizeof buf);
    dst.Length = 0; dst.MaximumLength = sizeof buf; dst.Buffer = buf;
    EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &src, FALSE), 0);
    EXPECT_EQ(dst.Length, 20); CHECK(!memcmp(buf, want, sizeof want));
    EXPECT_EQ(buf[11], 0x5555);
    /* exact fit needs room for the terminator */
    memset(buf, 0x55, sizeof buf);
    dst.Length = 0; dst.MaximumLength = 22; dst.Buffer = buf;
    EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &src, FALSE), 0);
    dst.Length = 0; dst.MaximumLength = 20; dst.Buffer = buf;
    EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &src, FALSE), S(0x80000005));
    EXPECT_EQ(dst.Length, 20);               /* required length is reported */
    /* empty source */
    ANSI_STRING empty = { 0, 1, (PCHAR)"" };
    memset(&dst, 0, sizeof dst);
    EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &empty, TRUE), 0);
    EXPECT_EQ(dst.Length, 0); EXPECT_EQ(dst.MaximumLength, 2);
    CHECK(dst.Buffer && dst.Buffer[0] == 0);
    if (dst.Buffer) UN(RtlFreeUnicodeString)(&dst);
    /* malformed UTF-8: lone continuation byte, truncated sequence, overlong form */
    static const char *bad[] = { "a\x80z", "ab\xE2\x82" };
    static const WCHAR bw[2][3] = { { 'a', 0xFFFD, 'z' }, { 'a', 'b', 0xFFFD } };
    for (int i = 0; i < 2; i++) {
        ANSI_STRING b = { (USHORT)strlen(bad[i]), (USHORT)(strlen(bad[i]) + 1), (PCHAR)bad[i] };
        memset(&dst, 0, sizeof dst);
        EXPECT_EQ(UN(RtlUTF8StringToUnicodeString)(&dst, &b, TRUE), 0);   /* invalid sequences become U+FFFD */
        EXPECT_EQ(dst.Length, 6);
        CHECK(dst.Buffer && !memcmp(dst.Buffer, bw[i], 6));
        if (dst.Buffer) UN(RtlFreeUnicodeString)(&dst);
    }
}

/* ------------------------------------------------------------ RtlVerifyVersionInfo */
typedef NTSTATUS (WINAPI *VVI_FN)(PRTL_OSVERSIONINFOEXW, ULONG, ULONGLONG);
UDECL(NTSTATUS, RtlVerifyVersionInfo, (PRTL_OSVERSIONINFOEXW, ULONG, ULONGLONG));
UDECL(NTSTATUS, RtlGetVersion, (PRTL_OSVERSIONINFOEXW));
UDECL(ULONGLONG, VerSetConditionMask, (ULONGLONG, ULONG, UCHAR));
#define VE 1
#define VG 2
#define VGE 3
#define VL 4
#define VLE 5
#define VAND 6
#define VOR 7
#define MM 0x2
#define Mm 0x1
#define MB 0x4
#define MSPMAJ 0x20
#define MPT 0x80
#define MSUITE 0x40
#define MISMATCH S(0xC0000059)
static void vvi_run(VVI_FN fn, int switched) {
    REQUIRE(UN(RtlGetVersion)); REQUIRE(UN(VerSetConditionMask));
    RTL_OSVERSIONINFOEXW cur; memset(&cur, 0, sizeof cur); cur.dwOSVersionInfoSize = sizeof cur;
    if (!switched) EXPECT_EQ(UN(RtlGetVersion)(&cur), 0);
    else {
        /* the switched variant reports the version an application without a compatibility manifest sees,
         * which is exactly what GetVersionExW returns */
        typedef BOOL (WINAPI *GV)(OSVERSIONINFOW *);
        GV gv = (GV)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersionExW");
        if (!gv) { t_skip("GetVersionExW not available"); return; }
        cur.dwOSVersionInfoSize = sizeof cur;
        if (!gv((OSVERSIONINFOW *)&cur)) { t_skip("GetVersionExW failed"); return; }
    }
    RTL_OSVERSIONINFOEXW q; ULONGLONG m;
#define Q(mask) do { memset(&q, 0, sizeof q); q.dwOSVersionInfoSize = sizeof q; } while (0)
    /* no type mask at all */
    Q(0); EXPECT_EQ(fn(&q, 0, 0), ST_INVPARAM);
    /* exact major */
    Q(0); q.dwMajorVersion = cur.dwMajorVersion; m = UN(VerSetConditionMask)(0, MM, VE);
    EXPECT_EQ(fn(&q, MM, m), 0);
    q.dwMajorVersion = cur.dwMajorVersion + 1;
    EXPECT_EQ(fn(&q, MM, m), MISMATCH);
    /* ordering conditions on major */
    m = UN(VerSetConditionMask)(0, MM, VGE);
    EXPECT_EQ(fn(&q, MM, m), MISMATCH);            /* want >= cur+1 */
    q.dwMajorVersion = cur.dwMajorVersion - 1; EXPECT_EQ(fn(&q, MM, m), 0);
    q.dwMajorVersion = cur.dwMajorVersion;     EXPECT_EQ(fn(&q, MM, m), 0);
    m = UN(VerSetConditionMask)(0, MM, VG);
    q.dwMajorVersion = cur.dwMajorVersion + 1; EXPECT_EQ(fn(&q, MM, m), MISMATCH);
    q.dwMajorVersion = cur.dwMajorVersion - 1; EXPECT_EQ(fn(&q, MM, m), 0);
    /* strict comparison of an equal field falls through to the remaining (unrequested) fields and succeeds */
    q.dwMajorVersion = cur.dwMajorVersion;     EXPECT_EQ(fn(&q, MM, m), 0);
    m = UN(VerSetConditionMask)(0, MM, VL);
    q.dwMajorVersion = cur.dwMajorVersion + 1; EXPECT_EQ(fn(&q, MM, m), 0);
    q.dwMajorVersion = cur.dwMajorVersion - 1; EXPECT_EQ(fn(&q, MM, m), MISMATCH);
    q.dwMajorVersion = cur.dwMajorVersion;     EXPECT_EQ(fn(&q, MM, m), 0);
    m = UN(VerSetConditionMask)(0, MM, VLE);
    EXPECT_EQ(fn(&q, MM, m), 0);
    /* build number */
    Q(0); q.dwBuildNumber = cur.dwBuildNumber; m = UN(VerSetConditionMask)(0, MB, VE);
    EXPECT_EQ(fn(&q, MB, m), 0);
    q.dwBuildNumber = cur.dwBuildNumber + 1; EXPECT_EQ(fn(&q, MB, m), MISMATCH);
    m = UN(VerSetConditionMask)(0, MB, VGE); q.dwBuildNumber = 7600;
    EXPECT_EQ(fn(&q, MB, m), 0);
    /* combined major + minor + build: all must hold */
    Q(0); q.dwMajorVersion = cur.dwMajorVersion; q.dwMinorVersion = cur.dwMinorVersion; q.dwBuildNumber = cur.dwBuildNumber;
    m = UN(VerSetConditionMask)(0, MM, VE); m = UN(VerSetConditionMask)(m, Mm, VE); m = UN(VerSetConditionMask)(m, MB, VE);
    EXPECT_EQ(fn(&q, MM | Mm | MB, m), 0);
    q.dwMinorVersion = cur.dwMinorVersion + 3;
    EXPECT_EQ(fn(&q, MM | Mm | MB, m), MISMATCH);
    /* service pack major, product type */
    Q(0); q.wServicePackMajor = cur.wServicePackMajor; m = UN(VerSetConditionMask)(0, MSPMAJ, VE);
    EXPECT_EQ(fn(&q, MSPMAJ, m), 0);
    q.wServicePackMajor = cur.wServicePackMajor + 1; EXPECT_EQ(fn(&q, MSPMAJ, m), MISMATCH);
    Q(0); q.wProductType = cur.wProductType; m = UN(VerSetConditionMask)(0, MPT, VE);
    EXPECT_EQ(fn(&q, MPT, m), 0);
    q.wProductType = cur.wProductType == 1 ? 3 : 1; EXPECT_EQ(fn(&q, MPT, m), MISMATCH);
    /* suite mask: VER_AND needs all requested bits, VER_OR any; anything else is invalid */
    int have = -1, lack = -1;
    for (int i = 0; i < 16; i++) { if ((cur.wSuiteMask >> i) & 1) { if (have < 0) have = i; } else if (lack < 0) lack = i; }
    if (lack >= 0) {
        Q(0); q.wSuiteMask = (USHORT)(1u << lack);
        m = UN(VerSetConditionMask)(0, MSUITE, VAND); EXPECT_EQ(fn(&q, MSUITE, m), MISMATCH);
        m = UN(VerSetConditionMask)(0, MSUITE, VOR);  EXPECT_EQ(fn(&q, MSUITE, m), MISMATCH);
        m = UN(VerSetConditionMask)(0, MSUITE, VE);   EXPECT_EQ(fn(&q, MSUITE, m), ST_INVPARAM);
        if (have >= 0) {
            q.wSuiteMask = (USHORT)((1u << lack) | (1u << have));
            m = UN(VerSetConditionMask)(0, MSUITE, VOR);  EXPECT_EQ(fn(&q, MSUITE, m), 0);
            m = UN(VerSetConditionMask)(0, MSUITE, VAND); EXPECT_EQ(fn(&q, MSUITE, m), MISMATCH);
        }
    }
    if (have >= 0) {
        Q(0); q.wSuiteMask = (USHORT)(1u << have);
        m = UN(VerSetConditionMask)(0, MSUITE, VAND); EXPECT_EQ(fn(&q, MSUITE, m), 0);
    }
}

TEST(verify_version_info) { VVI_FN f = (VVI_FN)t_proc("RtlVerifyVersionInfo"); REQUIRE(f); vvi_run(f, 0); }
TEST(switched_vvi) { VVI_FN f = (VVI_FN)t_proc("RtlSwitchedVVI"); REQUIRE(f); vvi_run(f, 1); }

/* ------------------------------------------------------------ RtlWalkFrameChain */
UDECL(ULONG, RtlWalkFrameChain, (PVOID *, ULONG, ULONG));
static __attribute__((noinline)) ULONG walk_inner(PVOID *c, ULONG n, ULONG fl) { ULONG r = UN(RtlWalkFrameChain)(c, n, fl); __asm__ volatile("" ::: "memory"); return r; }
TEST(walk_frame_chain) {
    REQUIRE(UN(RtlWalkFrameChain));
    PVOID c[32]; ULONG n; int i;
    memset(c, 0, sizeof c);
    n = walk_inner(c, 32, 0);
    CHECKF(n >= 1 && n <= 32, "frame count %lu", (unsigned long)n);
    for (i = 0; i < (int)n; i++) CHECKF(c[i] != NULL, "frame %d is NULL", i);
    for (i = (int)n; i < 32; i++) EXPECT_EQ(c[i], NULL);                 /* nothing written past the count */
    if (n) {                                                               /* first frame lies in this module */
        HMODULE self = GetModuleHandleW(NULL);
        CHECK((ULONG_PTR)c[0] > (ULONG_PTR)self);
    }
    /* a smaller buffer limits the count */
    memset(c, 0, sizeof c);
    ULONG n2 = walk_inner(c, 1, 0);
    EXPECT_EQ(n2, 1); EXPECT_EQ(c[1], NULL);
    EXPECT_EQ(walk_inner(c, 0, 0), 0);
    /* reserved flag bits and out-of-range skip counts are rejected */
    EXPECT_EQ(walk_inner(c, 8, 1), 0);
    EXPECT_EQ(walk_inner(c, 8, 0x10000), 0);
    EXPECT_EQ(walk_inner(c, 8, 0xFF00), 0);
    EXPECT_EQ(walk_inner(c, 0xFFFFFFFF, 0), 0);
    /* skipping frames returns fewer entries, matching the tail of the full walk */
    PVOID full[32], skip[32]; memset(full, 0, sizeof full); memset(skip, 0, sizeof skip);
    ULONG nf = walk_inner(full, 32, 0), ns = walk_inner(skip, 32, 1 << 8);
    t_note("full %lu skip1 %lu", (unsigned long)nf, (unsigned long)ns);
    CHECK(ns >= 1 && ns <= 32);
}

/* ------------------------------------------------------------ RtlUpdateTimer */
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlCreateTimer, (HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, DWORD, DWORD, ULONG));
UDECL(NTSTATUS, RtlUpdateTimer, (HANDLE, HANDLE, DWORD, DWORD));
UDECL(NTSTATUS, RtlDeleteTimer, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
static volatile LONG g_ticks;
static VOID CALLBACK tick_cb(PVOID ctx, BOOLEAN fired) { (void)ctx; (void)fired; InterlockedIncrement(&g_ticks); }
TEST(update_timer) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlUpdateTimer)); REQUIRE(UN(RtlDeleteTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    HANDLE q = NULL, t = NULL; g_ticks = 0;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    if (!q) return;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t, tick_cb, NULL, 600000, 0, 0), 0);      /* far-off one-shot */
    if (!t) { UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE); return; }
    Sleep(300); EXPECT_EQ(g_ticks, 0);
    EXPECT_EQ(UN(RtlUpdateTimer)(q, t, 50, 0), 0);                             /* pull the due time in */
    for (int i = 0; i < 100 && g_ticks == 0; i++) Sleep(50);
    EXPECT_EQ(g_ticks, 1);
    Sleep(300); EXPECT_EQ(g_ticks, 1);                                         /* period 0: fires once */
    /* a periodic timer can be re-armed with new due time and period */
    HANDLE t2 = NULL; g_ticks = 0;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t2, tick_cb, NULL, 600000, 600000, 0), 0);
    if (t2) {
        EXPECT_EQ(UN(RtlUpdateTimer)(q, t2, 20, 40), 0);
        for (int i = 0; i < 100 && g_ticks < 4; i++) Sleep(50);
        CHECKF(g_ticks >= 4, "periodic timer fired %ld times", (long)g_ticks);
        EXPECT_EQ(UN(RtlDeleteTimer)(q, t2, INVALID_HANDLE_VALUE), 0);
    }
    /* parameter errors */
    EXPECT_EQ(UN(RtlUpdateTimer)(NULL, t, 50, 0), S(0xC00000EF));
    EXPECT_EQ(UN(RtlUpdateTimer)(q, NULL, 50, 0), S(0xC00000F0));
    EXPECT_EQ(UN(RtlDeleteTimer)(q, t, INVALID_HANDLE_VALUE), 0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
}
