/* Run-search and single-bit routines, checked against a plain reference model. */
#include "t.h"

typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } RBM;
UDECL(void, RtlInitializeBitMap, (RBM *, PULONG, ULONG));
UDECL(void, RtlSetBit, (RBM *, ULONG));
UDECL(void, RtlClearBit, (RBM *, ULONG));
UDECL(void, RtlSetBitEx, (RBM *, ULONG64));
UDECL(void, RtlClearBitEx, (RBM *, ULONG64));
UDECL(BOOLEAN, RtlTestBit, (RBM *, ULONG));
UDECL(BOOLEAN, RtlTestBitEx, (RBM *, ULONG64));
UDECL(ULONG, RtlFindNextForwardRunClear, (RBM *, ULONG, PULONG));
UDECL(ULONG, RtlFindLastBackwardRunClear, (RBM *, ULONG, PULONG));
UDECL(ULONG, RtlFindLongestRunClear, (RBM *, PULONG));
UDECL(ULONG, RtlNumberOfSetBits, (RBM *));
UDECL(ULONG, RtlNumberOfClearBits, (RBM *));
UDECL(ULONG, RtlNumberOfSetBitsUlongPtr, (ULONG_PTR));

#define RW 12
typedef struct { _Alignas(8) ULONG buf[RW]; } RBUF;

static ULONG rb_state;
static ULONG rb_rand(void) { rb_state = rb_state * 1664525u + 1013904223u; return rb_state >> 8; }

static ULONG rb_bit(const ULONG *p, ULONG i) { return (p[i / 32] >> (i % 32)) & 1; }

/* Fill with runs of varying lengths so both polarities have several runs. */
static void rb_fill(RBUF *b, ULONG n, ULONG seed)
{
    ULONG i = 0, v;
    rb_state = seed; memset(b, 0, sizeof(*b));
    v = rb_rand() & 1;
    while (i < n) {
        ULONG len = 1 + rb_rand() % 11, k;
        for (k = 0; k < len && i < n; ++k, ++i)
            if (v) b->buf[i / 32] |= 1u << (i % 32);
        v ^= 1;
    }
}

static ULONG model_fwd(const ULONG *p, ULONG n, ULONG from, ULONG want, ULONG *start)
{
    ULONG i = from, e;
    while (i < n && rb_bit(p, i) != want) ++i;
    if (i >= n) return 0;
    for (e = i; e < n && rb_bit(p, e) == want; ++e) ;
    *start = i; return e - i;
}
static ULONG model_back(const ULONG *p, ULONG n, ULONG from, ULONG want, ULONG *start)
{
    LONG i = (LONG)from; LONG s;
    if (i >= (LONG)n) i = (LONG)n - 1;
    while (i >= 0 && rb_bit(p, (ULONG)i) != want) --i;
    if (i < 0) return 0;
    for (s = i; s > 0 && rb_bit(p, (ULONG)s - 1) == want; --s) ;
    *start = (ULONG)s; return (ULONG)(i - s + 1);
}
static ULONG model_longest(const ULONG *p, ULONG n, ULONG want)
{
    ULONG i = 0, best = 0, st, len;
    while ((len = model_fwd(p, n, i, want, &st)) != 0) {
        if (len > best) best = len;
        i = st + len;
    }
    return best;
}
static int run_is_maximal(const ULONG *p, ULONG n, ULONG st, ULONG len, ULONG want)
{
    ULONG k;
    if (st + len > n) return 0;
    for (k = 0; k < len; ++k) if (rb_bit(p, st + k) != want) return 0;
    if (st > 0 && rb_bit(p, st - 1) == want) return 0;
    if (st + len < n && rb_bit(p, st + len) == want) return 0;
    return 1;
}

static const ULONG rb_sizes[] = {1, 2, 31, 32, 33, 63, 64, 65, 100, 128, 129, 300};

TEST(rtl_bitmap_runs_forward_model_clear) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlFindNextForwardRunClear));
    unsigned si; int bad = 0;
    for (si = 0; si < sizeof(rb_sizes)/sizeof(*rb_sizes); ++si) {
        ULONG n = rb_sizes[si], from, seed;
        if (n > 32 * RW) continue;
        for (seed = 1; seed <= 3; ++seed) {
            RBUF b; RBM bm; rb_fill(&b, n, seed * 7919 + n);
            UN(RtlInitializeBitMap)(&bm, b.buf, n);
            for (from = 0; from < n; ++from) {
                ULONG ms = 0, gs = 0xfffffff0, ml, gl;
                ml = model_fwd(b.buf, n, from, 0, &ms);
                gl = UN(RtlFindNextForwardRunClear)(&bm, from, &gs);
                if (gl != ml || (ml && gs != ms)) { bad++; CHECKF(0, "fwd n=%lu from=%lu got %lu@%lu want %lu@%lu", n, from, gl, gs, ml, ms); }
                if (bad > 8) return;
            }
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_bitmap_runs_backward_model_clear) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlFindLastBackwardRunClear));
    unsigned si; int bad = 0;
    for (si = 0; si < sizeof(rb_sizes)/sizeof(*rb_sizes); ++si) {
        ULONG n = rb_sizes[si], from, seed;
        if (n > 32 * RW) continue;
        for (seed = 1; seed <= 3; ++seed) {
            RBUF b; RBM bm; rb_fill(&b, n, seed * 104729 + n);
            UN(RtlInitializeBitMap)(&bm, b.buf, n);
            for (from = 0; from < n; ++from) {
                ULONG ms = 0, gs = 0xfffffff0, ml, gl;
                ml = model_back(b.buf, n, from, 0, &ms);
                gl = UN(RtlFindLastBackwardRunClear)(&bm, from, &gs);
                if (gl != ml || (ml && gs != ms)) { bad++; CHECKF(0, "back n=%lu from=%lu got %lu@%lu want %lu@%lu", n, from, gl, gs, ml, ms); }
                if (bad > 8) return;
            }
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_bitmap_runs_longest_model) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlFindLongestRunClear));
    unsigned si; int bad = 0;
    for (si = 0; si < sizeof(rb_sizes)/sizeof(*rb_sizes); ++si) {
        ULONG n = rb_sizes[si], seed;
        if (n > 32 * RW) continue;
        for (seed = 20; seed < 28; ++seed) {
            RBUF b; RBM bm; ULONG st = 0xfffffff0, len, want;
            rb_fill(&b, n, seed * 977 + n);
            UN(RtlInitializeBitMap)(&bm, b.buf, n);
            want = model_longest(b.buf, n, 0); len = UN(RtlFindLongestRunClear)(&bm, &st);
            if (len != want || (want && !run_is_maximal(b.buf, n, st, len, 0))) { bad++; CHECKF(0, "longest n=%lu got %lu@%lu want %lu", n, len, st, want); }
            if (bad > 8) return;
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_bitmap_single_bit_set_clear_test) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlSetBit));
    REQUIRE(UN(RtlClearBit)); REQUIRE(UN(RtlTestBit));
    static const ULONG idx[] = {0, 1, 7, 8, 31, 32, 33, 63, 64, 95, 96, 129};
    RBUF b; RBM bm; unsigned i, j;
    memset(&b, 0, sizeof(b)); UN(RtlInitializeBitMap)(&bm, b.buf, 130);
    for (i = 0; i < sizeof(idx)/sizeof(*idx); ++i) {
        UN(RtlSetBit)(&bm, idx[i]);
        EXPECT_EQ(rb_bit(b.buf, idx[i]), 1); CHECK(UN(RtlTestBit)(&bm, idx[i]));
    }
    if (UN(RtlNumberOfSetBits)) EXPECT_EQ(UN(RtlNumberOfSetBits)(&bm), sizeof(idx)/sizeof(*idx));
    /* Setting twice is idempotent. */
    UN(RtlSetBit)(&bm, 33); EXPECT_EQ(rb_bit(b.buf, 33), 1);
    for (i = 0; i < sizeof(idx)/sizeof(*idx); ++i) {
        UN(RtlClearBit)(&bm, idx[i]);
        EXPECT_EQ(rb_bit(b.buf, idx[i]), 0); CHECK(!UN(RtlTestBit)(&bm, idx[i]));
        for (j = i + 1; j < sizeof(idx)/sizeof(*idx); ++j) EXPECT_EQ(rb_bit(b.buf, idx[j]), 1);
    }
    for (i = 0; i < RW; ++i) EXPECT_EQ(b.buf[i], 0);
}

TEST(rtl_bitmap_single_bit_ex_variants) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlSetBitEx));
    REQUIRE(UN(RtlClearBitEx)); REQUIRE(UN(RtlTestBitEx));
    static const ULONG64 idx[] = {0, 5, 31, 32, 63, 64, 127, 200};
    RBUF b; RBM bm; unsigned i;
    memset(&b, 0, sizeof(b)); UN(RtlInitializeBitMap)(&bm, b.buf, 201);
    for (i = 0; i < sizeof(idx)/sizeof(*idx); ++i) {
        UN(RtlSetBitEx)(&bm, idx[i]);
        EXPECT_EQ(rb_bit(b.buf, (ULONG)idx[i]), 1); CHECK(UN(RtlTestBitEx)(&bm, idx[i]));
    }
    CHECK(!UN(RtlTestBitEx)(&bm, 1)); CHECK(!UN(RtlTestBitEx)(&bm, 199));
    for (i = 0; i < sizeof(idx)/sizeof(*idx); ++i) {
        UN(RtlClearBitEx)(&bm, idx[i]);
        EXPECT_EQ(rb_bit(b.buf, (ULONG)idx[i]), 0); CHECK(!UN(RtlTestBitEx)(&bm, idx[i]));
    }
    for (i = 0; i < RW; ++i) EXPECT_EQ(b.buf[i], 0);
}

TEST(rtl_bitmap_number_of_set_bits_ulongptr) {
    REQUIRE(UN(RtlNumberOfSetBitsUlongPtr));
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0), 0);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(1), 1);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0x8000000000000000ULL), 1);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0xff), 8);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0x5555555555555555ULL), 32);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(~(ULONG_PTR)0), 64);
}

TEST(rtl_bitmap_counts_match_model) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlNumberOfSetBits));
    REQUIRE(UN(RtlNumberOfClearBits));
    unsigned si;
    for (si = 0; si < sizeof(rb_sizes)/sizeof(*rb_sizes); ++si) {
        ULONG n = rb_sizes[si], i, ones = 0;
        RBUF b; RBM bm;
        if (n > 32 * RW) continue;
        rb_fill(&b, n, 4242 + n);
        for (i = 0; i < n; ++i) ones += rb_bit(b.buf, i);
        UN(RtlInitializeBitMap)(&bm, b.buf, n);
        EXPECT_EQ(UN(RtlNumberOfSetBits)(&bm), ones);
        EXPECT_EQ(UN(RtlNumberOfClearBits)(&bm), n - ones);
    }
}
