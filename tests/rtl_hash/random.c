/* Pseudo-random generators: range, seed update and distribution sanity. */
#include "t.h"

UDECL(ULONG, RtlRandom, (PULONG));
UDECL(ULONG, RtlRandomEx, (PULONG));
UDECL(ULONG, RtlUniform, (PULONG));

static int rnd_distinct(const ULONG *v, unsigned n)
{
    unsigned i, j, d = 0;
    for (i = 0; i < n; ++i) { int dup = 0; for (j = 0; j < i; ++j) if (v[j] == v[i]) { dup = 1; break; } d += !dup; }
    return (int)d;
}

/* On Windows 10 RtlRandom and RtlRandomEx return values over the whole 32-bit range (RtlUniform stays below 2^31). */
TEST(rtl_random_results_cover_32_bit_range) {
    REQUIRE(UN(RtlRandom));
    ULONG seed = 12345, v; unsigned i; int high = 0;
    for (i = 0; i < 2000; ++i) { v = UN(RtlRandom)(&seed); if (v > 0x7fffffff) high++; }
    CHECK(high > 0);
}

TEST(rtl_random_ex_results_cover_32_bit_range) {
    REQUIRE(UN(RtlRandomEx));
    ULONG seed = 777, v; unsigned i; int high = 0;
    for (i = 0; i < 2000; ++i) { v = UN(RtlRandomEx)(&seed); if (v > 0x7fffffff) high++; }
    CHECK(high > 0);
}

TEST(rtl_random_updates_seed) {
    REQUIRE(UN(RtlRandom));
    ULONG seed = 1, prev, changed = 0; unsigned i;
    for (i = 0; i < 100; ++i) { prev = seed; UN(RtlRandom)(&seed); if (seed != prev) ++changed; }
    CHECK(changed >= 99);
}

TEST(rtl_random_ex_updates_seed) {
    REQUIRE(UN(RtlRandomEx));
    ULONG seed = 1, prev, changed = 0; unsigned i;
    for (i = 0; i < 100; ++i) { prev = seed; UN(RtlRandomEx)(&seed); if (seed != prev) ++changed; }
    CHECK(changed >= 99);
}

TEST(rtl_random_mostly_distinct_values) {
    REQUIRE(UN(RtlRandom));
    ULONG seed = 0x1234567, v[200]; unsigned i;
    for (i = 0; i < 200; ++i) v[i] = UN(RtlRandom)(&seed);
    CHECK(rnd_distinct(v, 200) >= 190);
}

TEST(rtl_random_ex_mostly_distinct_values) {
    REQUIRE(UN(RtlRandomEx));
    ULONG seed = 0x7654321, v[200]; unsigned i;
    for (i = 0; i < 200; ++i) v[i] = UN(RtlRandomEx)(&seed);
    CHECK(rnd_distinct(v, 200) >= 190);
}

TEST(rtl_random_uses_both_halves_of_range) {
    REQUIRE(UN(RtlRandom)); REQUIRE(UN(RtlRandomEx));
    ULONG s1 = 99, s2 = 99; unsigned i, lo1 = 0, hi1 = 0, lo2 = 0, hi2 = 0;
    for (i = 0; i < 1000; ++i) {
        if (UN(RtlRandom)(&s1) < 0x40000000) ++lo1; else ++hi1;
        if (UN(RtlRandomEx)(&s2) < 0x40000000) ++lo2; else ++hi2;
    }
    CHECK(lo1 > 100 && hi1 > 100); CHECK(lo2 > 100 && hi2 > 100);
}

TEST(rtl_random_different_seeds_diverge) {
    REQUIRE(UN(RtlRandomEx));
    ULONG a = 1, b = 2, same = 0, i;
    for (i = 0; i < 50; ++i) if (UN(RtlRandomEx)(&a) == UN(RtlRandomEx)(&b)) ++same;
    CHECK(same < 5);
}

TEST(rtl_uniform_seed_zero_and_max) {
    REQUIRE(UN(RtlUniform));
    ULONG seed = 0, v;
    v = UN(RtlUniform)(&seed);
    CHECK(v < 0x7fffffff); EXPECT_EQ(v, seed);
    seed = 0x7ffffffe; v = UN(RtlUniform)(&seed);
    CHECK(v < 0x7fffffff); EXPECT_EQ(v, seed);
}

TEST(rtl_uniform_never_reaches_modulus) {
    REQUIRE(UN(RtlUniform));
    ULONG seed = 42, v; unsigned i; int bad = 0;
    for (i = 0; i < 5000; ++i) { v = UN(RtlUniform)(&seed); if (v >= 0x7fffffff) bad++; }
    CHECK(bad == 0);
}

TEST(rtl_uniform_replays_from_same_seed) {
    REQUIRE(UN(RtlUniform));
    ULONG a = 5555, b = 5555, i; int bad = 0;
    for (i = 0; i < 100; ++i) if (UN(RtlUniform)(&a) != UN(RtlUniform)(&b)) bad++;
    CHECK(bad == 0); EXPECT_EQ(a, b);
}
