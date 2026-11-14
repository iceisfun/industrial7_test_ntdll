/* CRT-style ntdll exports: floating point math, wide character classification and case mapping,
 * non-local jumps. Transcendental results are compared with a tolerance; exact functions
 * (ceil, floor, fabs, sqrt) and special values are compared exactly. See EVIDENCE.md. */
#include "t.h"
#include <math.h>

typedef double (__cdecl *d1_fn)(double);
typedef double (__cdecl *d2_fn)(double, double);
UDECL(double, sin, (double)); UDECL(double, cos, (double)); UDECL(double, tan, (double));
UDECL(double, atan, (double)); UDECL(double, atan2, (double, double));
UDECL(double, sqrt, (double)); UDECL(double, pow, (double, double)); UDECL(double, log, (double));
UDECL(double, ceil, (double)); UDECL(double, floor, (double)); UDECL(double, fabs, (double));
UDECL(int, iswalnum, (unsigned)); UDECL(int, iswalpha, (unsigned)); UDECL(int, iswascii, (unsigned));
UDECL(int, iswctype, (unsigned, unsigned)); UDECL(int, iswdigit, (unsigned)); UDECL(int, iswgraph, (unsigned));
UDECL(int, iswlower, (unsigned)); UDECL(int, iswprint, (unsigned)); UDECL(int, iswspace, (unsigned));
UDECL(int, iswxdigit, (unsigned));
UDECL(unsigned, towlower, (unsigned)); UDECL(unsigned, towupper, (unsigned));
UDECL(int, _setjmp, (void *, void *));
UDECL(void, longjmp, (void *, int));

#define PI 3.14159265358979323846
static int is_near(double a, double b) { double d = a - b; if (d < 0) d = -d; return d < 1e-12 * (1 + (b < 0 ? -b : b)); }
#define EXPECT_NEAR(a, b) do { double a_ = (a), b_ = (b); CHECKF(is_near(a_, b_), "%s: got %.17g want %.17g", #a, a_, b_); } while (0)
#define EXPECT_D(a, b) do { double a_ = (a), b_ = (b); CHECKF(a_ == b_, "%s: got %.17g want %.17g", #a, a_, b_); } while (0)
#define EXPECT_NAN(a) do { double a_ = (a); CHECKF(a_ != a_, "%s: got %.17g want NaN", #a, a_); } while (0)

TEST(trig) {
    REQUIRE(UN(sin)); REQUIRE(UN(cos)); REQUIRE(UN(tan)); REQUIRE(UN(atan)); REQUIRE(UN(atan2));
    EXPECT_D(UN(sin)(0.0), 0.0); EXPECT_D(UN(cos)(0.0), 1.0); EXPECT_D(UN(tan)(0.0), 0.0); EXPECT_D(UN(atan)(0.0), 0.0);
    EXPECT_NEAR(UN(sin)(PI / 2), 1.0); EXPECT_NEAR(UN(sin)(PI / 6), 0.5); EXPECT_NEAR(UN(sin)(-PI / 2), -1.0);
    CHECK(fabs(UN(sin)(PI)) < 1e-15);
    EXPECT_NEAR(UN(cos)(PI), -1.0); EXPECT_NEAR(UN(cos)(PI / 3), 0.5); CHECK(fabs(UN(cos)(PI / 2)) < 1e-15);
    EXPECT_NEAR(UN(cos)(-PI), -1.0); EXPECT_NEAR(UN(cos)(2 * PI), 1.0);
    EXPECT_NEAR(UN(tan)(PI / 4), 1.0); EXPECT_NEAR(UN(tan)(-PI / 4), -1.0);
    EXPECT_NEAR(UN(sin)(1.0), 0.8414709848078965); EXPECT_NEAR(UN(cos)(1.0), 0.5403023058681398); EXPECT_NEAR(UN(tan)(1.0), 1.5574077246549023);
    EXPECT_NEAR(UN(sin)(100.0), -0.5063656411097588); EXPECT_NEAR(UN(cos)(100.0), 0.8623188722876839);
    EXPECT_NAN(UN(sin)(INFINITY)); EXPECT_NAN(UN(cos)(INFINITY)); EXPECT_NAN(UN(tan)(-INFINITY));
    EXPECT_NAN(UN(sin)(NAN));

    EXPECT_NEAR(UN(atan)(1.0), PI / 4); EXPECT_NEAR(UN(atan)(-1.0), -PI / 4);
    EXPECT_NEAR(UN(atan)(INFINITY), PI / 2); EXPECT_NEAR(UN(atan)(-INFINITY), -PI / 2);
    EXPECT_NEAR(UN(atan)(1e300), PI / 2); EXPECT_NEAR(UN(atan)(0.5), 0.4636476090008061);
    EXPECT_NAN(UN(atan)(NAN));

    EXPECT_NEAR(UN(atan2)(1.0, 1.0), PI / 4); EXPECT_NEAR(UN(atan2)(1.0, -1.0), 3 * PI / 4);
    EXPECT_NEAR(UN(atan2)(-1.0, -1.0), -3 * PI / 4); EXPECT_NEAR(UN(atan2)(-1.0, 1.0), -PI / 4);
    EXPECT_NEAR(UN(atan2)(1.0, 0.0), PI / 2); EXPECT_NEAR(UN(atan2)(-1.0, 0.0), -PI / 2);
    EXPECT_D(UN(atan2)(0.0, 1.0), 0.0); EXPECT_NEAR(UN(atan2)(0.0, -1.0), PI); EXPECT_NEAR(UN(atan2)(-0.0, -1.0), -PI);
    EXPECT_D(UN(atan2)(0.0, 0.0), 0.0); EXPECT_NEAR(UN(atan2)(0.0, -0.0), PI);
    EXPECT_NEAR(UN(atan2)(2.0, 1.0), 1.1071487177940904);
    EXPECT_NAN(UN(atan2)(NAN, 1.0)); EXPECT_NAN(UN(atan2)(1.0, NAN));
    EXPECT_NEAR(UN(atan2)(INFINITY, INFINITY), PI / 4);
}

TEST(sqrt_pow_log) {
    REQUIRE(UN(sqrt)); REQUIRE(UN(pow)); REQUIRE(UN(log));
    EXPECT_D(UN(sqrt)(0.0), 0.0); EXPECT_D(UN(sqrt)(1.0), 1.0); EXPECT_D(UN(sqrt)(4.0), 2.0);
    EXPECT_D(UN(sqrt)(144.0), 12.0); EXPECT_D(UN(sqrt)(0.25), 0.5); EXPECT_D(UN(sqrt)(2.0), 1.4142135623730951);
    EXPECT_D(UN(sqrt)(INFINITY), INFINITY); EXPECT_NAN(UN(sqrt)(-1.0)); EXPECT_NAN(UN(sqrt)(-INFINITY)); EXPECT_NAN(UN(sqrt)(NAN));
    CHECK(1.0 / UN(sqrt)(-0.0) < 0);                       /* sqrt(-0) = -0 */

    EXPECT_D(UN(pow)(2.0, 10.0), 1024.0); EXPECT_D(UN(pow)(10.0, 3.0), 1000.0); EXPECT_D(UN(pow)(2.0, 0.0), 1.0);
    EXPECT_D(UN(pow)(0.0, 0.0), 1.0); EXPECT_D(UN(pow)(2.0, -1.0), 0.5); EXPECT_D(UN(pow)(-2.0, 3.0), -8.0);
    EXPECT_D(UN(pow)(-2.0, 2.0), 4.0); EXPECT_NEAR(UN(pow)(2.0, 0.5), 1.4142135623730951);
    EXPECT_NEAR(UN(pow)(9.0, 0.5), 3.0); EXPECT_NEAR(UN(pow)(10.0, -2.0), 0.01); EXPECT_NEAR(UN(pow)(1.5, 2.5), 2.7556759606310752);
    EXPECT_D(UN(pow)(1.0, 1e300), 1.0); EXPECT_D(UN(pow)(1.0, NAN), 1.0);
    EXPECT_D(UN(pow)(0.0, 3.0), 0.0); EXPECT_D(UN(pow)(0.0, -1.0), INFINITY);
    EXPECT_NAN(UN(pow)(-8.0, 1.0 / 3.0)); EXPECT_NAN(UN(pow)(NAN, 2.0));
    EXPECT_D(UN(pow)(10.0, 400.0), INFINITY); EXPECT_D(UN(pow)(10.0, -400.0), 0.0);
    EXPECT_D(UN(pow)(2.0, INFINITY), INFINITY); EXPECT_D(UN(pow)(2.0, -INFINITY), 0.0);

    EXPECT_D(UN(log)(1.0), 0.0); EXPECT_NEAR(UN(log)(2.718281828459045), 1.0); EXPECT_NEAR(UN(log)(10.0), 2.302585092994046);
    EXPECT_NEAR(UN(log)(0.5), -0.6931471805599453); EXPECT_NEAR(UN(log)(1e100), 230.25850929940458);
    EXPECT_D(UN(log)(0.0), -INFINITY); EXPECT_NAN(UN(log)(-1.0)); EXPECT_D(UN(log)(INFINITY), INFINITY); EXPECT_NAN(UN(log)(NAN));
}

TEST(ceil_floor_fabs) {
    REQUIRE(UN(ceil)); REQUIRE(UN(floor)); REQUIRE(UN(fabs));
    EXPECT_D(UN(ceil)(1.2), 2.0); EXPECT_D(UN(ceil)(-1.2), -1.0); EXPECT_D(UN(ceil)(2.0), 2.0); EXPECT_D(UN(ceil)(0.0), 0.0);
    EXPECT_D(UN(ceil)(1e300), 1e300); EXPECT_D(UN(ceil)(-0.5), 0.0); CHECK(1.0 / UN(ceil)(-0.5) < 0);   /* -0 */
    EXPECT_D(UN(ceil)(2251799813685248.5), 2251799813685249.0); EXPECT_D(UN(ceil)(INFINITY), INFINITY);
    EXPECT_NAN(UN(ceil)(NAN));
    EXPECT_D(UN(floor)(1.8), 1.0); EXPECT_D(UN(floor)(-1.2), -2.0); EXPECT_D(UN(floor)(-2.0), -2.0); EXPECT_D(UN(floor)(0.9999999999), 0.0);
    EXPECT_D(UN(floor)(-1e-300), -1.0); EXPECT_D(UN(floor)(-INFINITY), -INFINITY); EXPECT_NAN(UN(floor)(NAN));
    EXPECT_D(UN(floor)(2251799813685248.5), 2251799813685248.0);
    EXPECT_D(UN(fabs)(-3.5), 3.5); EXPECT_D(UN(fabs)(3.5), 3.5); EXPECT_D(UN(fabs)(0.0), 0.0); EXPECT_D(UN(fabs)(-INFINITY), INFINITY);
    CHECK(1.0 / UN(fabs)(-0.0) > 0);                     /* sign bit cleared */
    EXPECT_NAN(UN(fabs)(-NAN));
}

TEST(wctype_ascii) {
    REQUIRE(UN(iswalnum)); REQUIRE(UN(iswalpha)); REQUIRE(UN(iswascii)); REQUIRE(UN(iswctype)); REQUIRE(UN(iswdigit));
    REQUIRE(UN(iswgraph)); REQUIRE(UN(iswlower)); REQUIRE(UN(iswprint)); REQUIRE(UN(iswspace)); REQUIRE(UN(iswxdigit));
    for (unsigned c = 0; c < 128; c++) {
        int up = c >= 'A' && c <= 'Z', lo = c >= 'a' && c <= 'z', dg = c >= '0' && c <= '9';
        int sp = (c >= 9 && c <= 13) || c == 32, hx = dg || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        int ctl = c < 32 || c == 127, pr = c >= 32 && c < 127, gr = c > 32 && c < 127;
        int pu = gr && !up && !lo && !dg;
        /* iswprint is built from the _BLANK|_PUNCT|_ALPHA|_DIGIT bits, so TAB (a _BLANK) counts as printable (observed) */
        EXPECT_EQ(!!UN(iswalnum)(c), up || lo || dg);
        EXPECT_EQ(!!UN(iswalpha)(c), up || lo);
        EXPECT_EQ(!!UN(iswdigit)(c), dg);
        EXPECT_EQ(!!UN(iswlower)(c), lo);
        EXPECT_EQ(!!UN(iswspace)(c), sp);
        EXPECT_EQ(!!UN(iswxdigit)(c), hx);
        CHECKF(!!UN(iswprint)(c) == (pr || c == 9), "iswprint(0x%x)=%d", c, UN(iswprint)(c));
        EXPECT_EQ(!!UN(iswgraph)(c), gr);
        EXPECT_EQ(!!UN(iswascii)(c), 1);
        /* ctype.h masks: _UPPER 1 _LOWER 2 _DIGIT 4 _SPACE 8 _PUNCT 0x10 _CONTROL 0x20 _BLANK 0x40 _HEX 0x80 _ALPHA 0x100 */
        EXPECT_EQ(!!UN(iswctype)(c, 0x01), up);
        EXPECT_EQ(!!UN(iswctype)(c, 0x02), lo);
        EXPECT_EQ(!!UN(iswctype)(c, 0x04), dg);
        EXPECT_EQ(!!UN(iswctype)(c, 0x08), sp);
        EXPECT_EQ(!!UN(iswctype)(c, 0x10), pu);
        EXPECT_EQ(!!UN(iswctype)(c, 0x20), ctl);
        EXPECT_EQ(!!UN(iswctype)(c, 0x80), hx);
        EXPECT_EQ(!!UN(iswctype)(c, 0x100), up || lo);
        EXPECT_EQ(!!UN(iswctype)(c, 0x40), c == ' ' || c == '\t');
    }
    EXPECT_EQ(UN(iswctype)('a', 0), 0);
    EXPECT_EQ(UN(iswctype)('a', 0x103) != 0, 1);          /* any matching bit */
    EXPECT_EQ(!!UN(iswascii)(0x80), 0); EXPECT_EQ(!!UN(iswascii)(0xe9), 0); EXPECT_EQ(!!UN(iswascii)(0x3b1), 0); EXPECT_EQ(!!UN(iswascii)(0xffff), 0);
    EXPECT_EQ(!!UN(iswalpha)(0xe9), 1); EXPECT_EQ(!!UN(iswlower)(0xe9), 1); EXPECT_EQ(!!UN(iswalpha)(0xc9), 1);   /* Latin-1 letters */
    EXPECT_EQ(!!UN(iswctype)(0xc9, 1), 1);
    EXPECT_EQ(!!UN(iswdigit)(0xb2), 1);                   /* superscript two carries the _DIGIT bit in the table (observed) */
    EXPECT_EQ(!!UN(iswspace)(0xa0), 1); EXPECT_EQ(!!UN(iswprint)(0xa0), 1);   /* no-break space (observed) */
    EXPECT_EQ(!!UN(iswalpha)(0x3b1), 0); EXPECT_EQ(!!UN(iswprint)(0x3b1), 0);
    /* the classification table covers code points below 0x100 only */
    EXPECT_EQ(UN(iswctype)(0x100, 0xffff), 0); EXPECT_EQ(UN(iswctype)(0x3b1, 0xffff), 0); EXPECT_EQ(UN(iswctype)(0xffff, 0xffff), 0);
}

TEST(wchar_case) {
    REQUIRE(UN(towlower)); REQUIRE(UN(towupper));
    for (unsigned c = 0; c < 128; c++) {
        unsigned lo = (c >= 'A' && c <= 'Z') ? c + 32 : c, up = (c >= 'a' && c <= 'z') ? c - 32 : c;
        EXPECT_EQ(UN(towlower)(c), lo);
        EXPECT_EQ(UN(towupper)(c), up);
    }
    EXPECT_EQ(UN(towupper)(0xe9), 0xc9); EXPECT_EQ(UN(towlower)(0xc9), 0xe9);
    EXPECT_EQ(UN(towupper)(0xc9), 0xc9); EXPECT_EQ(UN(towlower)(0xe9), 0xe9);
    EXPECT_EQ(UN(towupper)(0xe0), 0xc0); EXPECT_EQ(UN(towlower)(0xde), 0xfe);
    EXPECT_EQ(UN(towupper)(0xd7), 0xd7); EXPECT_EQ(UN(towlower)(0xd7), 0xd7);    /* multiplication sign */
    EXPECT_EQ(UN(towupper)(0xf7), 0xf7);
    EXPECT_EQ(UN(towupper)(0xffff), 0xffff); EXPECT_EQ(UN(towlower)(0xffff), 0xffff);
    EXPECT_EQ(UN(towupper)('1'), '1');
    /* upper-casing follows the Unicode simple mapping above Latin-1 (observed); lower-casing does not
     * reach above Latin-1 */
    EXPECT_EQ(UN(towupper)(0x3b1), 0x391); EXPECT_EQ(UN(towupper)(0xff), 0x178); EXPECT_EQ(UN(towupper)(0x101), 0x100);
    EXPECT_EQ(UN(towupper)(0xb5), 0xb5); EXPECT_EQ(UN(towlower)(0x391), 0x391);
}

/* ---- non-local jump: unwind target 0 means "restore registers only" ---- */
static ULONG64 g_jb[64] __attribute__((aligned(16)));
static volatile int g_phase, g_val;
static __attribute__((noinline)) void do_jump(int v) { UN(longjmp)(g_jb, v); g_phase = 99; }
static __attribute__((noinline)) int jump_test(int v) {
    g_phase = 0;
    int r = UN(_setjmp)(g_jb, NULL);
    if (r == 0) { g_phase = 1; do_jump(v); }
    else { g_phase = 2; g_val = r; }
    return r;
}
TEST(longjmp_restore) {
    REQUIRE(UN(_setjmp)); REQUIRE(UN(longjmp));
    int r;
    r = jump_test(7);  EXPECT_EQ(g_phase, 2); EXPECT_EQ(r, 7); EXPECT_EQ(g_val, 7);
    r = jump_test(-3); EXPECT_EQ(g_phase, 2); EXPECT_EQ(r, -3);
    r = jump_test(0);  EXPECT_EQ(g_phase, 2); EXPECT_EQ(r, 1);          /* a zero value is delivered as 1 */
    r = jump_test(0x12345678); EXPECT_EQ(r, 0x12345678);
}
