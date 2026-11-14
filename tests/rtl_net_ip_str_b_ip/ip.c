#include "t.h"

UDECL(PSTR,  RtlIpv4AddressToStringA, (const void *, PSTR));
UDECL(PWSTR, RtlIpv4AddressToStringW, (const void *, PWSTR));
UDECL(NTSTATUS, RtlIpv4AddressToStringExA, (const void *, USHORT, PSTR, PULONG));
UDECL(NTSTATUS, RtlIpv4AddressToStringExW, (const void *, USHORT, PWSTR, PULONG));
UDECL(NTSTATUS, RtlIpv4StringToAddressA, (PCSTR, BOOLEAN, PCSTR *, void *));
UDECL(NTSTATUS, RtlIpv4StringToAddressW, (PCWSTR, BOOLEAN, PCWSTR *, void *));
UDECL(NTSTATUS, RtlIpv4StringToAddressExA, (PCSTR, BOOLEAN, void *, PUSHORT));
UDECL(NTSTATUS, RtlIpv4StringToAddressExW, (PCWSTR, BOOLEAN, void *, PUSHORT));
UDECL(PSTR,  RtlIpv6AddressToStringA, (const void *, PSTR));
UDECL(PWSTR, RtlIpv6AddressToStringW, (const void *, PWSTR));
UDECL(NTSTATUS, RtlIpv6AddressToStringExA, (const void *, ULONG, USHORT, PSTR, PULONG));
UDECL(NTSTATUS, RtlIpv6AddressToStringExW, (const void *, ULONG, USHORT, PWSTR, PULONG));
UDECL(NTSTATUS, RtlIpv6StringToAddressA, (PCSTR, PCSTR *, void *));
UDECL(NTSTATUS, RtlIpv6StringToAddressW, (PCWSTR, PCWSTR *, void *));
UDECL(NTSTATUS, RtlIpv6StringToAddressExA, (PCSTR, void *, PULONG, PUSHORT));
UDECL(NTSTATUS, RtlIpv6StringToAddressExW, (PCWSTR, void *, PULONG, PUSHORT));

#define INVP ((NTSTATUS)0xC000000D)
#define NN(s) ((NTSTATUS)(s))

static void widen(WCHAR *w, const char *s) { while ((*w++ = (unsigned char)*s++)) ; }
static int weq(const WCHAR *w, const char *s) { while (*w && *s) { if (*w != (unsigned char)*s) return 0; w++; s++; } return *w == 0 && *s == 0; }

TEST(rtl_net_ip_str_b_ip_aliases) {
    /* Nt-style pairs do not exist here; the A/W variants must be distinct routines */
    CHECK(t_proc("RtlIpv4AddressToStringA") != t_proc("RtlIpv4AddressToStringW"));
    CHECK(t_proc("RtlIpv6AddressToStringA") != t_proc("RtlIpv6AddressToStringW"));
}

TEST(rtl_net_ip_str_b_ip_v4_to_string) {
    REQUIRE(UN(RtlIpv4AddressToStringA)); REQUIRE(UN(RtlIpv4AddressToStringW));
    static const struct { BYTE a[4]; const char *s; } c[] = {
        {{0,0,0,0}, "0.0.0.0"}, {{1,2,3,4}, "1.2.3.4"}, {{255,255,255,255}, "255.255.255.255"},
        {{192,168,10,200}, "192.168.10.200"}, {{10,0,0,1}, "10.0.0.1"} };
    for (int i = 0; i < 5; i++) {
        char buf[32]; memset(buf, 0x7f, sizeof buf);
        PSTR e = UN(RtlIpv4AddressToStringA)(c[i].a, buf);
        EXPECT_STR(buf, c[i].s);
        EXPECT_EQ(e, buf + strlen(c[i].s));   /* returns pointer to terminating NUL */
        WCHAR wb[32]; memset(wb, 0x7f, sizeof wb);
        PWSTR we = UN(RtlIpv4AddressToStringW)(c[i].a, wb);
        CHECK(weq(wb, c[i].s));
        EXPECT_EQ(we, wb + strlen(c[i].s));
    }
}

TEST(rtl_net_ip_str_b_ip_v4_to_string_ex) {
    REQUIRE(UN(RtlIpv4AddressToStringExA)); REQUIRE(UN(RtlIpv4AddressToStringExW));
    BYTE a[4] = {1,2,3,4};
    char buf[40]; WCHAR wb[40]; ULONG len;
    len = sizeof buf; memset(buf, 0x7f, sizeof buf);
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0, buf, &len), 0);
    EXPECT_STR(buf, "1.2.3.4"); EXPECT_EQ(len, 8);
    /* port is in network byte order; 0 means no port */
    len = sizeof buf;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0x5000, buf, &len), 0);
    EXPECT_STR(buf, "1.2.3.4:80"); EXPECT_EQ(len, 11);
    len = sizeof buf;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0xffff, buf, &len), 0);
    EXPECT_STR(buf, "1.2.3.4:65535");
    len = 40;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExW)(a, 0x5000, wb, &len), 0);
    CHECK(weq(wb, "1.2.3.4:80")); EXPECT_EQ(len, 11);
    /* too small: INVALID_PARAMETER, required length (incl. NUL) returned */
    len = 7; memset(buf, 0x7f, sizeof buf);
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0, buf, &len), INVP);
    EXPECT_EQ(len, 8);
    len = 10;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0x5000, buf, &len), INVP);
    EXPECT_EQ(len, 11);
    len = 7;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExW)(a, 0, wb, &len), INVP);
    EXPECT_EQ(len, 8);
    len = 8;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExW)(a, 0, wb, &len), 0);
    /* NULL args */
    len = 40;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(NULL, 0, buf, &len), INVP);
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0, buf, NULL), INVP);
    EXPECT_EQ(UN(RtlIpv4AddressToStringExW)(NULL, 0, wb, &len), INVP);
    EXPECT_EQ(UN(RtlIpv4AddressToStringExW)(a, 0, wb, NULL), INVP);
    len = 40;
    EXPECT_EQ(UN(RtlIpv4AddressToStringExA)(a, 0, NULL, &len), INVP);
}

TEST(rtl_net_ip_str_b_ip_v4_from_string) {
    REQUIRE(UN(RtlIpv4StringToAddressA)); REQUIRE(UN(RtlIpv4StringToAddressW));
    static const struct { const char *s; BOOLEAN strict; NTSTATUS st; BYTE a[4]; int term; } c[] = {
        {"1.2.3.4", 1, 0, {1,2,3,4}, 7},
        {"255.255.255.255", 1, 0, {255,255,255,255}, 15},
        {"0.0.0.0", 1, 0, {0,0,0,0}, 7},
        {"1.2.3.4xyz", 1, 0, {1,2,3,4}, 7},       /* stops at first non-address char */
        {"1.2.3.4:80", 1, 0, {1,2,3,4}, 7},
        {"1.2.3", 1, INVP, {0}, -1},              /* strict wants 4 parts */
        {"1.2.3", 0, 0, {1,2,0,3}, 5},            /* last part fills the remaining bytes */
        {"1.2", 0, 0, {1,0,0,2}, 3},
        {"16909060", 0, 0, {1,2,3,4}, 8},         /* single 32-bit number */
        {"0x01020304", 0, 0, {1,2,3,4}, 10},
        {"0x1.0x2.0x3.0x4", 0, 0, {1,2,3,4}, 15},
        {"010.0.0.1", 0, 0, {8,0,0,1}, 9},        /* octal */
        {"010.0.0.1", 1, INVP, {0}, -1},          /* strict is decimal only */
        {"256.1.1.1", 1, INVP, {0}, -1},
        {"1.2.3.256", 1, INVP, {0}, -1},
        {"1..3.4", 1, INVP, {0}, -1},
        {".1.2.3", 1, INVP, {0}, -1},
        {"", 1, INVP, {0}, -1},
        {"abc", 1, INVP, {0}, -1},
        {"1.2.3.4.5", 1, INVP, {0}, -1},          /* a fifth part is rejected */
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE out[4] = {9,9,9,9}; PCSTR term = (PCSTR)1;
        NTSTATUS s = UN(RtlIpv4StringToAddressA)(c[i].s, c[i].strict, &term, out);
        CHECKF(s == c[i].st, "A \"%s\" strict=%d got 0x%lx want 0x%lx", c[i].s, c[i].strict, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            CHECKF(!memcmp(out, c[i].a, 4), "A \"%s\" addr %d.%d.%d.%d", c[i].s, out[0], out[1], out[2], out[3]);
            CHECKF(term == c[i].s + c[i].term, "A \"%s\" terminator off %d", c[i].s, (int)(term - c[i].s));
        }
        WCHAR w[64]; widen(w, c[i].s); PCWSTR wt = (PCWSTR)1; memset(out, 9, 4);
        s = UN(RtlIpv4StringToAddressW)(w, c[i].strict, &wt, out);
        CHECKF(s == c[i].st, "W \"%s\" strict=%d got 0x%lx want 0x%lx", c[i].s, c[i].strict, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            CHECKF(!memcmp(out, c[i].a, 4), "W \"%s\" addr", c[i].s);
            CHECKF(wt == w + c[i].term, "W \"%s\" terminator", c[i].s);
        }
    }
}

TEST(rtl_net_ip_str_b_ip_v4_from_string_ex) {
    REQUIRE(UN(RtlIpv4StringToAddressExA)); REQUIRE(UN(RtlIpv4StringToAddressExW));
    static const struct { const char *s; BOOLEAN strict; NTSTATUS st; BYTE a[4]; USHORT port; } c[] = {
        {"1.2.3.4", 1, 0, {1,2,3,4}, 0},
        {"1.2.3.4:80", 1, 0, {1,2,3,4}, 0x5000},      /* port returned in network order */
        {"1.2.3.4:65535", 1, 0, {1,2,3,4}, 0xffff},
        {"1.2.3.4:65536", 1, INVP, {0}, 0},
        {"1.2.3.4:", 1, INVP, {0}, 0},
        {"1.2.3.4:8x", 1, INVP, {0}, 0},
        {"1.2.3.4 ", 1, INVP, {0}, 0},                /* whole string must be consumed */
        {"1.2.3.4x", 1, INVP, {0}, 0},
        {"1.2.3", 1, INVP, {0}, 0},
        {"1.2.3:81", 0, 0, {1,2,0,3}, 0x5100},
        {"1.2.3.4:0x50", 1, 0, {1,2,3,4}, 0x5000},    /* hex port */
        {"1.2.3.4:010", 1, 0, {1,2,3,4}, 0x0800},     /* octal port */
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE out[4] = {9,9,9,9}; USHORT port = 0x1234;
        NTSTATUS s = UN(RtlIpv4StringToAddressExA)(c[i].s, c[i].strict, out, &port);
        CHECKF(s == c[i].st, "ExA \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            CHECKF(!memcmp(out, c[i].a, 4), "ExA \"%s\" addr", c[i].s);
            CHECKF(port == c[i].port, "ExA \"%s\" port 0x%x want 0x%x", c[i].s, port, c[i].port);
        }
        WCHAR w[64]; widen(w, c[i].s); memset(out, 9, 4); port = 0x1234;
        s = UN(RtlIpv4StringToAddressExW)(w, c[i].strict, out, &port);
        CHECKF(s == c[i].st, "ExW \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            CHECKF(!memcmp(out, c[i].a, 4), "ExW \"%s\" addr", c[i].s);
            CHECKF(port == c[i].port, "ExW \"%s\" port", c[i].s);
        }
    }
    BYTE out[4]; USHORT port; WCHAR w[] = L"1.2.3.4";
    EXPECT_EQ(UN(RtlIpv4StringToAddressExA)(NULL, 1, out, &port), INVP);
    EXPECT_EQ(UN(RtlIpv4StringToAddressExA)("1.2.3.4", 1, NULL, &port), INVP);
    EXPECT_EQ(UN(RtlIpv4StringToAddressExA)("1.2.3.4", 1, out, NULL), INVP);
    EXPECT_EQ(UN(RtlIpv4StringToAddressExW)(NULL, 1, out, &port), INVP);
    EXPECT_EQ(UN(RtlIpv4StringToAddressExW)(w, 1, NULL, &port), INVP);
    EXPECT_EQ(UN(RtlIpv4StringToAddressExW)(w, 1, out, NULL), INVP);
}

static void v6(BYTE *b, const unsigned short *g) { for (int i = 0; i < 8; i++) { b[2*i] = g[i] >> 8; b[2*i+1] = g[i] & 0xff; } }

TEST(rtl_net_ip_str_b_ip_v6_to_string) {
    REQUIRE(UN(RtlIpv6AddressToStringA)); REQUIRE(UN(RtlIpv6AddressToStringW));
    static const struct { unsigned short g[8]; const char *s; } c[] = {
        {{0,0,0,0,0,0,0,0}, "::"},
        {{0,0,0,0,0,0,0,1}, "::1"},
        {{1,0,0,0,0,0,0,0}, "1::"},
        {{0x2001,0xdb8,0,0,0,0,0,1}, "2001:db8::1"},
        {{0xfe80,0,0,0,0,0,0x1234,0xabcd}, "fe80::1234:abcd"},
        {{1,2,3,4,5,6,7,8}, "1:2:3:4:5:6:7:8"},
        {{1,0,2,0,0,3,0,4}, "1:0:2::3:0:4"},           /* longest run compressed */
        {{1,0,0,2,0,0,3,4}, "1::2:0:0:3:4"},           /* first of equal runs */
        {{1,0,2,3,4,5,6,7}, "1:0:2:3:4:5:6:7"},        /* single zero not compressed */
        {{0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff}, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
        {{0,0,0,0,0,0xffff,0x102,0x304}, "::ffff:1.2.3.4"},  /* v4-mapped */
        {{0,0,0,0,0,0,0x102,0x304}, "::1.2.3.4"},           /* v4-compatible */
        {{0,0,0,0,0xffff,0,0x102,0x304}, "::ffff:0:1.2.3.4"}, /* v4-translated */
        {{0x64,0xff9b,0,0,0,0,0x102,0x304}, "64:ff9b::102:304"},
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE a[16]; v6(a, c[i].g);
        char buf[64]; memset(buf, 0x7f, sizeof buf);
        PSTR e = UN(RtlIpv6AddressToStringA)(a, buf);
        CHECKF(!strcmp(buf, c[i].s), "A got \"%s\" want \"%s\"", buf, c[i].s);
        CHECKF(e == buf + strlen(buf), "A end pointer %s", c[i].s);
        WCHAR wb[64]; memset(wb, 0x7f, sizeof wb);
        PWSTR we = UN(RtlIpv6AddressToStringW)(a, wb);
        CHECKF(weq(wb, c[i].s), "W \"%s\"", c[i].s);
        CHECKF(we == wb + strlen(c[i].s), "W end %s", c[i].s);
    }
}

TEST(rtl_net_ip_str_b_ip_v6_to_string_ex) {
    REQUIRE(UN(RtlIpv6AddressToStringExA)); REQUIRE(UN(RtlIpv6AddressToStringExW));
    BYTE a[16]; unsigned short g[8] = {0xfe80,0,0,0,0,0,0,1}; v6(a, g);
    char buf[100]; WCHAR wb[100]; ULONG len;
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0, 0, buf, &len), 0);
    EXPECT_STR(buf, "fe80::1"); EXPECT_EQ(len, 8);
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 3, 0, buf, &len), 0);
    EXPECT_STR(buf, "fe80::1%3"); EXPECT_EQ(len, 10);
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0, 0x5000, buf, &len), 0);
    EXPECT_STR(buf, "[fe80::1]:80"); EXPECT_EQ(len, 13);
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 12, 0x5000, buf, &len), 0);
    EXPECT_STR(buf, "[fe80::1%12]:80"); EXPECT_EQ(len, 16);
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0xffffffff, 0, buf, &len), 0);
    EXPECT_STR(buf, "fe80::1%4294967295");
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 12, 0x5000, wb, &len), 0);
    CHECK(weq(wb, "[fe80::1%12]:80")); EXPECT_EQ(len, 16);
    len = 100; EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 0, 0, wb, &len), 0);
    CHECK(weq(wb, "fe80::1"));
    /* too small */
    len = 7; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0, 0, buf, &len), INVP); EXPECT_EQ(len, 8);
    len = 15; EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 12, 0x5000, buf, &len), INVP); EXPECT_EQ(len, 16);
    len = 7; EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 0, 0, wb, &len), INVP); EXPECT_EQ(len, 8);
    len = 8; EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 0, 0, wb, &len), 0);
    /* NULL args */
    len = 100;
    EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(NULL, 0, 0, buf, &len), INVP);
    EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0, 0, buf, NULL), INVP);
    EXPECT_EQ(UN(RtlIpv6AddressToStringExA)(a, 0, 0, NULL, &len), INVP);
    EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(NULL, 0, 0, wb, &len), INVP);
    EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 0, 0, wb, NULL), INVP);
    EXPECT_EQ(UN(RtlIpv6AddressToStringExW)(a, 0, 0, NULL, &len), INVP);
}

TEST(rtl_net_ip_str_b_ip_v6_from_string) {
    REQUIRE(UN(RtlIpv6StringToAddressA)); REQUIRE(UN(RtlIpv6StringToAddressW));
    static const struct { const char *s; NTSTATUS st; unsigned short g[8]; int term; } c[] = {
        {"::", 0, {0,0,0,0,0,0,0,0}, 2},
        {"::1", 0, {0,0,0,0,0,0,0,1}, 3},
        {"1::", 0, {1,0,0,0,0,0,0,0}, 3},
        {"2001:db8::1", 0, {0x2001,0xdb8,0,0,0,0,0,1}, 11},
        {"2001:DB8::A", 0, {0x2001,0xdb8,0,0,0,0,0,0xa}, 11},
        {"1:2:3:4:5:6:7:8", 0, {1,2,3,4,5,6,7,8}, 15},
        {"1:2:3:4:5:6:1.2.3.4", 0, {1,2,3,4,5,6,0x102,0x304}, 19},
        {"::ffff:1.2.3.4", 0, {0,0,0,0,0,0xffff,0x102,0x304}, 14},
        {"::1.2.3.4", 0, {0,0,0,0,0,0,0x102,0x304}, 9},
        {"1::2:3", 0, {1,0,0,0,0,0,2,3}, 6},
        {"fe80::1%5", 0, {0xfe80,0,0,0,0,0,0,1}, 7},        /* parsing stops at the scope marker */
        {"[::1]", INVP, {0}, -1},
        {"1:2:3:4:5:6:7", INVP, {0}, -1},
        {"1:2:3:4:5:6:7:8:9", 0, {1,2,3,4,5,6,7,8}, 15},   /* stops after the 8th group */
        {"1::2::3", 0, {1,0,0,0,0,0,0,2}, 4},
        {"12345::", INVP, {0}, -1},
        {":1", INVP, {0}, -1},
        {"1:", INVP, {0}, -1},
        {"g::", INVP, {0}, -1},
        {"", INVP, {0}, -1},
        {":::", 0, {0,0,0,0,0,0,0,0}, 2},
        {"1:2:3:4:5:6:7::", 0, {1,2,3,4,5,6,7,0}, 15},
        {"::2:3:4:5:6:7:8", 0, {0,0,2,3,4,5,6,7}, 13},
        {"1:2:3:4:5:6:7:8::", 0, {1,2,3,4,5,6,7,8}, 15},
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE out[16], want[16]; memset(out, 9, 16); PCSTR term = (PCSTR)1;
        NTSTATUS s = UN(RtlIpv6StringToAddressA)(c[i].s, &term, out);
        CHECKF(s == c[i].st, "A \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            v6(want, c[i].g);
            CHECKF(!memcmp(out, want, 16), "A \"%s\" addr", c[i].s);
            CHECKF(term == c[i].s + c[i].term, "A \"%s\" term off %d want %d", c[i].s, (int)(term - c[i].s), c[i].term);
        }
        WCHAR w[64]; widen(w, c[i].s); PCWSTR wt = (PCWSTR)1; memset(out, 9, 16);
        s = UN(RtlIpv6StringToAddressW)(w, &wt, out);
        CHECKF(s == c[i].st, "W \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            v6(want, c[i].g);
            CHECKF(!memcmp(out, want, 16), "W \"%s\" addr", c[i].s);
            CHECKF(wt == w + c[i].term, "W \"%s\" term", c[i].s);
        }
    }
}

TEST(rtl_net_ip_str_b_ip_v6_from_string_ex) {
    REQUIRE(UN(RtlIpv6StringToAddressExA)); REQUIRE(UN(RtlIpv6StringToAddressExW));
    static const struct { const char *s; NTSTATUS st; unsigned short g[8]; ULONG scope; USHORT port; } c[] = {
        {"::1", 0, {0,0,0,0,0,0,0,1}, 0, 0},
        {"fe80::1%5", 0, {0xfe80,0,0,0,0,0,0,1}, 5, 0},
        {"[::1]", 0, {0,0,0,0,0,0,0,1}, 0, 0},
        {"[::1]:80", 0, {0,0,0,0,0,0,0,1}, 0, 0x5000},
        {"[fe80::1%7]:443", 0, {0xfe80,0,0,0,0,0,0,1}, 7, 0xbb01},
        {"[::1]:65535", 0, {0,0,0,0,0,0,0,1}, 0, 0xffff},
        {"[::1]:65536", INVP, {0}, 0, 0},
        {"[::1", INVP, {0}, 0, 0},
        {"::1]", INVP, {0}, 0, 0},
        {"[::1]x", INVP, {0}, 0, 0},
        {"[::1]:", 0, {0,0,0,0,0,0,0,1}, 0, 0},     /* empty port is accepted as 0 */
        {"::1 ", INVP, {0}, 0, 0},
        {"::1:80", 0, {0,0,0,0,0,0,1,0x80}, 0, 0},       /* no brackets: port is just a group */
        {"fe80::1%", INVP, {0}, 0, 0},
        {"fe80::1%x", INVP, {0}, 0, 0},
        {"", INVP, {0}, 0, 0},
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE out[16], want[16]; memset(out, 9, 16); ULONG sc = 0x77; USHORT port = 0x1234;
        NTSTATUS s = UN(RtlIpv6StringToAddressExA)(c[i].s, out, &sc, &port);
        CHECKF(s == c[i].st, "ExA \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            v6(want, c[i].g);
            CHECKF(!memcmp(out, want, 16), "ExA \"%s\" addr", c[i].s);
            CHECKF(sc == c[i].scope, "ExA \"%s\" scope %lu", c[i].s, sc);
            CHECKF(port == c[i].port, "ExA \"%s\" port 0x%x", c[i].s, port);
        }
        WCHAR w[64]; widen(w, c[i].s); memset(out, 9, 16); sc = 0x77; port = 0x1234;
        s = UN(RtlIpv6StringToAddressExW)(w, out, &sc, &port);
        CHECKF(s == c[i].st, "ExW \"%s\" got 0x%lx want 0x%lx", c[i].s, (long)s, (long)c[i].st);
        if (c[i].st == 0 && s == 0) {
            v6(want, c[i].g);
            CHECKF(!memcmp(out, want, 16), "ExW \"%s\" addr", c[i].s);
            CHECKF(sc == c[i].scope, "ExW \"%s\" scope", c[i].s);
            CHECKF(port == c[i].port, "ExW \"%s\" port", c[i].s);
        }
    }
    BYTE out[16]; ULONG sc; USHORT port; WCHAR w[] = L"::1";
    EXPECT_EQ(UN(RtlIpv6StringToAddressExA)(NULL, out, &sc, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExA)("::1", NULL, &sc, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExA)("::1", out, NULL, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExA)("::1", out, &sc, NULL), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExW)(NULL, out, &sc, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExW)(w, NULL, &sc, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExW)(w, out, NULL, &port), INVP);
    EXPECT_EQ(UN(RtlIpv6StringToAddressExW)(w, out, &sc, NULL), INVP);
}
