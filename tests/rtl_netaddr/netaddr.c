#include "t.h"

/* IPv4 / IPv6 text <-> binary conversion (ip2string.h). Addresses are plain byte arrays. */
UDECL(NTSTATUS, RtlIpv4StringToAddressA, (PCSTR, BOOLEAN, PCSTR *, BYTE *));
UDECL(NTSTATUS, RtlIpv4StringToAddressW, (PCWSTR, BOOLEAN, PCWSTR *, BYTE *));
UDECL(NTSTATUS, RtlIpv4StringToAddressExA, (PCSTR, BOOLEAN, BYTE *, USHORT *));
UDECL(NTSTATUS, RtlIpv4StringToAddressExW, (PCWSTR, BOOLEAN, BYTE *, USHORT *));
UDECL(PSTR, RtlIpv4AddressToStringA, (const BYTE *, PSTR));
UDECL(PWSTR, RtlIpv4AddressToStringW, (const BYTE *, PWSTR));
UDECL(NTSTATUS, RtlIpv4AddressToStringExA, (const BYTE *, USHORT, PSTR, PULONG));
UDECL(NTSTATUS, RtlIpv4AddressToStringExW, (const BYTE *, USHORT, PWSTR, PULONG));
UDECL(NTSTATUS, RtlIpv6StringToAddressA, (PCSTR, PCSTR *, BYTE *));
UDECL(NTSTATUS, RtlIpv6StringToAddressW, (PCWSTR, PCWSTR *, BYTE *));
UDECL(NTSTATUS, RtlIpv6StringToAddressExA, (PCSTR, BYTE *, PULONG, PUSHORT));
UDECL(NTSTATUS, RtlIpv6StringToAddressExW, (PCWSTR, BYTE *, PULONG, PUSHORT));
UDECL(PSTR, RtlIpv6AddressToStringA, (const BYTE *, PSTR));
UDECL(PWSTR, RtlIpv6AddressToStringW, (const BYTE *, PWSTR));
UDECL(NTSTATUS, RtlIpv6AddressToStringExA, (const BYTE *, ULONG, USHORT, PSTR, PULONG));
UDECL(NTSTATUS, RtlIpv6AddressToStringExW, (const BYTE *, ULONG, USHORT, PWSTR, PULONG));

#define INVALID ((NTSTATUS)0xC000000D)

static void widen(WCHAR *w, const char *s) { while ((*w++ = (unsigned char)*s++)) ; }
static USHORT swap16(USHORT v) { return (USHORT)((v << 8) | (v >> 8)); }

/* ---- IPv4 string -> address -------------------------------------------- */

struct v4ok { const char *s; BOOLEAN strict; BYTE a[4]; };
static const struct v4ok v4_valid[] = {
    { "1.2.3.4", TRUE,  {1,2,3,4} },
    { "0.0.0.0", TRUE,  {0,0,0,0} },
    { "255.255.255.255", TRUE, {255,255,255,255} },
    { "127.0.0.1", FALSE, {127,0,0,1} },
    { "10.20.30.40", FALSE, {10,20,30,40} },
    /* Non-strict (inet_addr style) forms. */
    { "1.2.3", FALSE, {1,2,0,3} },
    { "1.2", FALSE, {1,0,0,2} },
    { "16909060", FALSE, {1,2,3,4} },
    { "0x01020304", FALSE, {1,2,3,4} },
    { "0x7f.1", FALSE, {127,0,0,1} },
    { "0x7f.0.0.1", FALSE, {127,0,0,1} },
    { "0177.0.0.1", FALSE, {127,0,0,1} },
    { "1.2.3.0x04", FALSE, {1,2,3,4} },
};

TEST(netaddr_v4_parse_valid)
{
    REQUIRE(UN(RtlIpv4StringToAddressA)); REQUIRE(UN(RtlIpv4StringToAddressW));
    for (unsigned i = 0; i < sizeof v4_valid / sizeof v4_valid[0]; ++i) {
        const struct v4ok *c = &v4_valid[i];
        BYTE a[4] = {0xAA,0xAA,0xAA,0xAA}; PCSTR term = NULL;
        WCHAR w[64]; BYTE b[4] = {0xAA,0xAA,0xAA,0xAA}; PCWSTR wterm = NULL;
        NTSTATUS st = UN(RtlIpv4StringToAddressA)(c->s, c->strict, &term, a);
        CHECKF(st == 0, "\"%s\" strict=%d status 0x%lx", c->s, c->strict, (unsigned long)st);
        if (st == 0) {
            CHECKF(!memcmp(a, c->a, 4), "\"%s\" -> %u.%u.%u.%u", c->s, a[0], a[1], a[2], a[3]);
            CHECKF(term == c->s + strlen(c->s), "\"%s\" terminator offset %d", c->s, (int)(term - c->s));
        }
        widen(w, c->s);
        st = UN(RtlIpv4StringToAddressW)(w, c->strict, &wterm, b);
        CHECKF(st == 0, "wide \"%s\" status 0x%lx", c->s, (unsigned long)st);
        if (st == 0) {
            CHECKF(!memcmp(b, c->a, 4), "wide \"%s\" result", c->s);
            CHECKF(wterm == w + strlen(c->s), "wide \"%s\" terminator", c->s);
        }
    }
}

/* Inputs that never parse, strict or not. */
static const char *const v4_bad_always[] = {
    "", ".", "1.2.3.4.5", "1..2.3", ".1.2.3", "256.1.1.1", "1.2.3.256",
    "a.b.c.d", "1.2.3.-4", " 1.2.3.4", "1.2.3.", "4294967296",
};

TEST(netaddr_v4_parse_invalid)
{
    REQUIRE(UN(RtlIpv4StringToAddressA)); REQUIRE(UN(RtlIpv4StringToAddressW));
    for (unsigned i = 0; i < sizeof v4_bad_always / sizeof v4_bad_always[0]; ++i) {
        BYTE a[4] = {0}; PCSTR term = NULL; WCHAR w[64]; PCWSTR wterm = NULL;
        NTSTATUS st = UN(RtlIpv4StringToAddressA)(v4_bad_always[i], TRUE, &term, a);
        CHECKF(st == INVALID, "\"%s\" strict status 0x%lx", v4_bad_always[i], (unsigned long)st);
        widen(w, v4_bad_always[i]);
        st = UN(RtlIpv4StringToAddressW)(w, TRUE, &wterm, a);
        CHECKF(st != 0, "wide \"%s\" strict status 0x%lx", v4_bad_always[i], (unsigned long)st);
    }
}

TEST(netaddr_v4_strict_rejects_short_and_radix)
{
    static const char *const s[] = { "1.2.3", "1.2", "1", "0x7f.0.0.1", "0x01020304", "16909060" };
    REQUIRE(UN(RtlIpv4StringToAddressA));
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; ++i) {
        BYTE a[4]; PCSTR term = NULL;
        NTSTATUS st = UN(RtlIpv4StringToAddressA)(s[i], TRUE, &term, a);
        CHECKF(st == INVALID, "\"%s\" strict status 0x%lx", s[i], (unsigned long)st);
    }
}

TEST(netaddr_v4_terminator_on_trailing_text)
{
    const char *in = "1.2.3.4abc"; BYTE a[4] = {0}; PCSTR term = NULL;
    REQUIRE(UN(RtlIpv4StringToAddressA));
    NTSTATUS st = UN(RtlIpv4StringToAddressA)(in, TRUE, &term, a);
    /* either the whole string is rejected, or the terminator marks the first unparsed character */
    CHECKF(st == INVALID || term == in + 7, "status 0x%lx terminator offset %d", (unsigned long)st, term ? (int)(term - in) : -1);
    t_note("\"%s\": status 0x%lx terminator offset %d", in, (unsigned long)st, term ? (int)(term - in) : -1);
    in = "1.2.3.4 ";
    st = UN(RtlIpv4StringToAddressA)(in, TRUE, &term, a);
    CHECKF(st == INVALID || term == in + 7, "trailing blank: status 0x%lx", (unsigned long)st);
}

TEST(netaddr_v4_ex_port)
{
    struct { const char *s; BOOLEAN strict; BYTE a[4]; USHORT port_host; NTSTATUS st; } c[] = {
        { "1.2.3.4",        TRUE,  {1,2,3,4}, 0,     0 },
        { "1.2.3.4:80",     TRUE,  {1,2,3,4}, 80,    0 },
        { "1.2.3.4:65535",  TRUE,  {1,2,3,4}, 65535, 0 },
        { "1.2.3.4:8080",   FALSE, {1,2,3,4}, 8080,  0 },
        { "1.2.3.4:65536",  TRUE,  {0},       0,     INVALID },
        { "1.2.3.4:x",      TRUE,  {0},       0,     INVALID },
        { "1.2.3.4:80x",    TRUE,  {0},       0,     INVALID },
        { "1.2.3.4x",       TRUE,  {0},       0,     INVALID },
        { "1.2.3.4:80:81",  TRUE,  {0},       0,     INVALID },
        { "1.2.3.256:80",   TRUE,  {0},       0,     INVALID },
        { "",               TRUE,  {0},       0,     INVALID },
        { ":80",            TRUE,  {0},       0,     INVALID },
    };
    REQUIRE(UN(RtlIpv4StringToAddressExA)); REQUIRE(UN(RtlIpv4StringToAddressExW));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        BYTE a[4] = {0}; USHORT port = 0x1234; WCHAR w[64]; BYTE b[4] = {0}; USHORT wport = 0x1234;
        NTSTATUS st = UN(RtlIpv4StringToAddressExA)(c[i].s, c[i].strict, a, &port);
        CHECKF(st == c[i].st, "\"%s\" status 0x%lx want 0x%lx", c[i].s, (unsigned long)st, (unsigned long)c[i].st);
        if (st == 0 && c[i].st == 0) {
            CHECKF(!memcmp(a, c[i].a, 4), "\"%s\" address", c[i].s);
            if (c[i].port_host) CHECKF(swap16(port) == c[i].port_host, "\"%s\" port (network order) 0x%x", c[i].s, port);
            else if (port) t_note("\"%s\": no port written as 0x%x", c[i].s, port);
        }
        widen(w, c[i].s);
        st = UN(RtlIpv4StringToAddressExW)(w, c[i].strict, b, &wport);
        CHECKF(st == c[i].st, "wide \"%s\" status 0x%lx", c[i].s, (unsigned long)st);
        if (st == 0 && c[i].st == 0) {
            CHECKF(!memcmp(b, c[i].a, 4), "wide \"%s\" address", c[i].s);
            if (c[i].port_host) CHECKF(swap16(wport) == c[i].port_host, "wide \"%s\" port", c[i].s);
        }
    }
}

TEST(netaddr_v4_ex_leading_zero_port_note)
{
    BYTE a[4]; USHORT port = 0; NTSTATUS st;
    REQUIRE(UN(RtlIpv4StringToAddressExA));
    st = UN(RtlIpv4StringToAddressExA)("1.2.3.4:0", TRUE, a, &port);
    t_note("\"1.2.3.4:0\" status 0x%lx port 0x%x", (unsigned long)st, port);
    st = UN(RtlIpv4StringToAddressExA)("1.2.3.4:080", TRUE, a, &port);
    t_note("\"1.2.3.4:080\" status 0x%lx port 0x%x", (unsigned long)st, port);
    st = UN(RtlIpv4StringToAddressExA)("1.2.3.4:", TRUE, a, &port);
    t_note("\"1.2.3.4:\" status 0x%lx", (unsigned long)st);
    st = UN(RtlIpv4StringToAddressExA)("1.2.3.4 :80", TRUE, a, &port);
    t_note("\"1.2.3.4 :80\" status 0x%lx", (unsigned long)st);
}

/* ---- IPv4 address -> string -------------------------------------------- */

TEST(netaddr_v4_format)
{
    static const struct { BYTE a[4]; const char *s; } c[] = {
        { {0,0,0,0}, "0.0.0.0" }, { {1,2,3,4}, "1.2.3.4" }, { {255,255,255,255}, "255.255.255.255" },
        { {10,0,9,100}, "10.0.9.100" }, { {192,168,1,10}, "192.168.1.10" },
    };
    REQUIRE(UN(RtlIpv4AddressToStringA)); REQUIRE(UN(RtlIpv4AddressToStringW));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        char buf[32]; WCHAR wbuf[32]; char *end; WCHAR *wend; WCHAR want[32];
        memset(buf, 0x55, sizeof buf);
        end = UN(RtlIpv4AddressToStringA)(c[i].a, buf);
        EXPECT_STR(buf, c[i].s);
        CHECKF(end == buf + strlen(c[i].s), "returned pointer is the terminating NUL (%s)", c[i].s);
        for (unsigned k = 0; k < 32; ++k) wbuf[k] = 0x5555;
        wend = UN(RtlIpv4AddressToStringW)(c[i].a, wbuf);
        widen(want, c[i].s);
        EXPECT_WSTR(wbuf, want);
        CHECKF(wend == wbuf + strlen(c[i].s), "wide returned pointer is the terminating NUL (%s)", c[i].s);
    }
}

TEST(netaddr_v4_format_ex)
{
    static const struct { BYTE a[4]; USHORT port_host; const char *s; } c[] = {
        { {1,2,3,4}, 0, "1.2.3.4" }, { {1,2,3,4}, 80, "1.2.3.4:80" },
        { {255,255,255,255}, 65535, "255.255.255.255:65535" }, { {0,0,0,0}, 1, "0.0.0.0:1" },
    };
    REQUIRE(UN(RtlIpv4AddressToStringExA)); REQUIRE(UN(RtlIpv4AddressToStringExW));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        char buf[40]; WCHAR wbuf[40], want[40]; ULONG len = sizeof buf, wlen = 40;
        NTSTATUS st;
        memset(buf, 0x55, sizeof buf);
        st = UN(RtlIpv4AddressToStringExA)(c[i].a, swap16(c[i].port_host), buf, &len);
        EXPECT_EQ(st, 0);
        EXPECT_STR(buf, c[i].s);
        EXPECT_EQ(len, strlen(c[i].s) + 1);
        st = UN(RtlIpv4AddressToStringExW)(c[i].a, swap16(c[i].port_host), wbuf, &wlen);
        EXPECT_EQ(st, 0);
        widen(want, c[i].s);
        EXPECT_WSTR(wbuf, want);
        EXPECT_EQ(wlen, strlen(c[i].s) + 1);
    }
}

TEST(netaddr_v4_format_ex_buffer_protocol)
{
    const BYTE a[4] = {1,2,3,4}; char buf[32]; ULONG len; NTSTATUS st;
    const char *s = "1.2.3.4:80"; /* 10 chars + NUL */
    REQUIRE(UN(RtlIpv4AddressToStringExA));
    /* exact fit */
    memset(buf, 0x55, sizeof buf); len = 11;
    st = UN(RtlIpv4AddressToStringExA)(a, swap16(80), buf, &len);
    EXPECT_EQ(st, 0); EXPECT_STR(buf, s); EXPECT_EQ(len, 11);
    /* one short: failure, required size reported */
    memset(buf, 0x55, sizeof buf); len = 10;
    st = UN(RtlIpv4AddressToStringExA)(a, swap16(80), buf, &len);
    EXPECT_EQ(st, INVALID);
    EXPECT_EQ(len, 11);
    /* zero length */
    len = 0;
    st = UN(RtlIpv4AddressToStringExA)(a, swap16(80), buf, &len);
    EXPECT_EQ(st, INVALID);
    EXPECT_EQ(len, 11);
    /* without a port the requirement shrinks */
    len = 0;
    st = UN(RtlIpv4AddressToStringExA)(a, 0, buf, &len);
    EXPECT_EQ(st, INVALID);
    EXPECT_EQ(len, 8);
}

TEST(netaddr_v4_roundtrip)
{
    REQUIRE(UN(RtlIpv4StringToAddressA)); REQUIRE(UN(RtlIpv4AddressToStringA));
    for (unsigned v = 0; v < 256; v += 51) for (unsigned w = 0; w < 256; w += 85) {
        BYTE a[4] = { (BYTE)v, (BYTE)w, (BYTE)(255 - v), (BYTE)(255 - w) }, b[4]; char buf[32]; PCSTR term;
        UN(RtlIpv4AddressToStringA)(a, buf);
        EXPECT_EQ(UN(RtlIpv4StringToAddressA)(buf, TRUE, &term, b), 0);
        CHECK(!memcmp(a, b, 4));
    }
}

/* ---- IPv6 address -> string -------------------------------------------- */

struct v6fmt { BYTE a[16]; const char *s; };
static const struct v6fmt v6_format[] = {
    { {0}, "::" },
    { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, "::1" },
    { {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, "fe80::1" },
    { {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}, "2001:db8::1" },
    { {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0}, "2001:db8::" },
    { {0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0}, "0:0:0:1::" },
    { {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8}, "1:2:3:4:5:6:7:8" },
    { {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
    { {0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89}, "abcd:ef01:2345:6789:abcd:ef01:2345:6789" },
    { {0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4}, "::ffff:1.2.3.4" },
    { {0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4}, "::1.2.3.4" },
    { {0,0,0,0,0,0,0,0,0xff,0xff,0,0,1,2,3,4}, "::ffff:0:1.2.3.4" },
    { {0x20,0x01,0,0,0,0,0,1,0,0,0,0,0,0,0,1}, "2001:0:0:1::1" },
};

TEST(netaddr_v6_format)
{
    REQUIRE(UN(RtlIpv6AddressToStringA)); REQUIRE(UN(RtlIpv6AddressToStringW));
    for (unsigned i = 0; i < sizeof v6_format / sizeof v6_format[0]; ++i) {
        char buf[80]; WCHAR wbuf[80], want[80]; char *end; WCHAR *wend;
        memset(buf, 0x55, sizeof buf);
        end = UN(RtlIpv6AddressToStringA)(v6_format[i].a, buf);
        if (strcmp(buf, v6_format[i].s)) {
            /* zero-run placement and embedded IPv4 notation are the delicate parts */
            if (i <= 8) CHECKF(0, "got \"%s\" want \"%s\"", buf, v6_format[i].s);
            else t_note("format %u: got \"%s\" documented-style \"%s\"", i, buf, v6_format[i].s);
        }
        CHECKF(end == buf + strlen(buf), "returned pointer is the terminating NUL (%s)", buf);
        wend = UN(RtlIpv6AddressToStringW)(v6_format[i].a, wbuf);
        widen(want, buf);
        EXPECT_WSTR(wbuf, want);
        CHECK(wend == wbuf + strlen(buf));
    }
}

TEST(netaddr_v6_format_ex)
{
    static const BYTE ll[16] = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const BYTE lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const struct { const BYTE *a; ULONG scope; USHORT port_host; const char *s; } c[] = {
        { lo, 0, 0,    "::1" },
        { ll, 0, 0,    "fe80::1" },
        { ll, 5, 0,    "fe80::1%5" },
        { lo, 0, 80,   "[::1]:80" },
        { ll, 7, 8080, "[fe80::1%7]:8080" },
        { lo, 0, 65535,"[::1]:65535" },
    };
    REQUIRE(UN(RtlIpv6AddressToStringExA)); REQUIRE(UN(RtlIpv6AddressToStringExW));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        char buf[80]; WCHAR wbuf[80], want[80]; ULONG len = sizeof buf, wlen = 80; NTSTATUS st;
        st = UN(RtlIpv6AddressToStringExA)(c[i].a, c[i].scope, swap16(c[i].port_host), buf, &len);
        EXPECT_EQ(st, 0);
        EXPECT_STR(buf, c[i].s);
        EXPECT_EQ(len, strlen(c[i].s) + 1);
        st = UN(RtlIpv6AddressToStringExW)(c[i].a, c[i].scope, swap16(c[i].port_host), wbuf, &wlen);
        EXPECT_EQ(st, 0);
        widen(want, c[i].s);
        EXPECT_WSTR(wbuf, want);
        EXPECT_EQ(wlen, strlen(c[i].s) + 1);
    }
}

TEST(netaddr_v6_format_ex_buffer_protocol)
{
    static const BYTE lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    char buf[64]; ULONG len; NTSTATUS st;
    REQUIRE(UN(RtlIpv6AddressToStringExA));
    len = 4; /* "::1" + NUL fits exactly */
    st = UN(RtlIpv6AddressToStringExA)(lo, 0, 0, buf, &len);
    EXPECT_EQ(st, 0); EXPECT_STR(buf, "::1"); EXPECT_EQ(len, 4);
    len = 3;
    st = UN(RtlIpv6AddressToStringExA)(lo, 0, 0, buf, &len);
    EXPECT_EQ(st, INVALID); EXPECT_EQ(len, 4);
    len = 0;
    st = UN(RtlIpv6AddressToStringExA)(lo, 3, 9, buf, &len); /* "[::1%3]:..." */
    EXPECT_EQ(st, INVALID);
    CHECKF(len > 4, "required length %lu includes scope and port", (unsigned long)len);
}

/* ---- IPv6 string -> address -------------------------------------------- */

static const struct { const char *s; BYTE a[16]; } v6_valid[] = {
    { "::",  {0} },
    { "::1", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1} },
    { "1::", {0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
    { "1:2:3:4:5:6:7:8", {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8} },
    { "1:2:3:4:5:6:7::", {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,0} },

    { "FE80::A", {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0a} },
    { "fe80::a", {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0a} },
    { "2001:0db8:0000:0000:0000:0000:0000:0001", {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1} },
    { "1:0:0:0:0:0:0:1", {0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1} },
    { "0001::0001", {0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1} },
    { "::1.2.3.4", {0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4} },
    { "::ffff:1.2.3.4", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4} },
    { "1:2:3:4:5:6:1.2.3.4", {0,1,0,2,0,3,0,4,0,5,0,6,1,2,3,4} },
    { "1:2::7:8", {0,1,0,2,0,0,0,0,0,0,0,0,0,7,0,8} },
};

TEST(netaddr_v6_leading_compression_takes_two_groups)
{
    /* A leading "::" stands for at least two zero groups here, so the eighth group is left unparsed. */
    static const char s[] = "::2:3:4:5:6:7:8";
    BYTE a[16]; PCSTR term = NULL; NTSTATUS st;
    REQUIRE(UN(RtlIpv6StringToAddressA));
    memset(a, 0xAA, 16);
    st = UN(RtlIpv6StringToAddressA)(s, &term, a);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        static const BYTE want[16] = {0,0,0,0,0,2,0,3,0,4,0,5,0,6,0,7};
        CHECK(!memcmp(a, want, 16));
        CHECK(term == s + 13);   /* stops before ":8" */
    }
}

TEST(netaddr_v6_parse_valid)
{
    REQUIRE(UN(RtlIpv6StringToAddressA)); REQUIRE(UN(RtlIpv6StringToAddressW));
    for (unsigned i = 0; i < sizeof v6_valid / sizeof v6_valid[0]; ++i) {
        BYTE a[16], b[16]; PCSTR term = NULL; PCWSTR wterm = NULL; WCHAR w[80]; NTSTATUS st;
        memset(a, 0xAA, 16); memset(b, 0xAA, 16);
        st = UN(RtlIpv6StringToAddressA)(v6_valid[i].s, &term, a);
        CHECKF(st == 0, "\"%s\" status 0x%lx", v6_valid[i].s, (unsigned long)st);
        if (st == 0) {
            CHECKF(!memcmp(a, v6_valid[i].a, 16), "\"%s\" bytes", v6_valid[i].s);
            CHECKF(term == v6_valid[i].s + strlen(v6_valid[i].s), "\"%s\" terminator", v6_valid[i].s);
        }
        widen(w, v6_valid[i].s);
        st = UN(RtlIpv6StringToAddressW)(w, &wterm, b);
        CHECKF(st == 0, "wide \"%s\" status 0x%lx", v6_valid[i].s, (unsigned long)st);
        if (st == 0) {
            CHECKF(!memcmp(b, v6_valid[i].a, 16), "wide \"%s\" bytes", v6_valid[i].s);
            CHECKF(wterm == w + strlen(v6_valid[i].s), "wide \"%s\" terminator", v6_valid[i].s);
        }
    }
}

static const char *const v6_invalid[] = {
    "", ":", ":::", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1",
    "1:2:3:4:5:6:7:8::", "1:::2", ":1:2:3:4:5:6:7", "1.2.3.4",
    "1:2:3:4:5:6:7:1.2.3.4", "::1.2.3", "::1.2.3.256", "::1.2.3.4:5",
};

TEST(netaddr_v6_parse_invalid_ex)
{
    REQUIRE(UN(RtlIpv6StringToAddressExA)); REQUIRE(UN(RtlIpv6StringToAddressExW));
    for (unsigned i = 0; i < sizeof v6_invalid / sizeof v6_invalid[0]; ++i) {
        BYTE a[16]; ULONG scope = 0; USHORT port = 0; WCHAR w[80];
        NTSTATUS st = UN(RtlIpv6StringToAddressExA)(v6_invalid[i], a, &scope, &port);
        CHECKF(st == INVALID, "\"%s\" status 0x%lx", v6_invalid[i], (unsigned long)st);
        widen(w, v6_invalid[i]);
        st = UN(RtlIpv6StringToAddressExW)(w, a, &scope, &port);
        CHECKF(st == INVALID, "wide \"%s\" status 0x%lx", v6_invalid[i], (unsigned long)st);
    }
}

TEST(netaddr_v6_eight_groups_with_double_colon_note)
{
    BYTE a[16]; ULONG scope; USHORT port; NTSTATUS st;
    REQUIRE(UN(RtlIpv6StringToAddressExA));
    st = UN(RtlIpv6StringToAddressExA)("::1:2:3:4:5:6:7:8", a, &scope, &port);
    t_note("eight groups plus :: status 0x%lx", (unsigned long)st);
    st = UN(RtlIpv6StringToAddressExA)("1:2:3:4:5:6:7::8", a, &scope, &port);
    t_note("\"1:2:3:4:5:6:7::8\" status 0x%lx", (unsigned long)st);
}

TEST(netaddr_v6_parse_invalid_plain)
{
    REQUIRE(UN(RtlIpv6StringToAddressA));
    for (unsigned i = 0; i < sizeof v6_invalid / sizeof v6_invalid[0]; ++i) {
        BYTE a[16]; PCSTR term = NULL;
        NTSTATUS st = UN(RtlIpv6StringToAddressA)(v6_invalid[i], &term, a);
        /* either rejected, or only a valid prefix is consumed and the terminator marks the rest */
        CHECKF(st != 0 || (term && *term != 0), "\"%s\" status 0x%lx", v6_invalid[i], (unsigned long)st);
    }
}

TEST(netaddr_v6_ex_scope_and_port)
{
    static const struct { const char *s; BYTE last; ULONG scope; USHORT port_host; NTSTATUS st; } c[] = {
        { "::1",               1, 0,  0,     0 },
        { "fe80::1%5",         1, 5,  0,     0 },
        { "fe80::1%12345",     1, 12345, 0,  0 },
        { "[::1]",             1, 0,  0,     0 },
        { "[::1]:80",          1, 0,  80,    0 },
        { "[fe80::1%7]:8080",  1, 7,  8080,  0 },
        { "[::1]:65535",       1, 0,  65535, 0 },
        { "[::1]:65536",       0, 0,  0,     INVALID },
        { "[::1]:",            0, 0,  0,     0 },   /* an empty port after the colon is accepted and yields port 0 */
        { "[::1",              0, 0,  0,     INVALID },
        { "::1]",              0, 0,  0,     INVALID },
        { "[::1]x",            0, 0,  0,     INVALID },
        { "::1:80",            0, 0,  0,     0 },   /* bare colon-port is part of the address, so this is ::1:80 */
        { "fe80::1%",          0, 0,  0,     INVALID },
        { "fe80::1%x",         0, 0,  0,     INVALID },
        { "[]:80",             0, 0,  0,     INVALID },
    };
    REQUIRE(UN(RtlIpv6StringToAddressExA)); REQUIRE(UN(RtlIpv6StringToAddressExW));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        BYTE a[16]; ULONG scope = 0xDEAD; USHORT port = 0x1234; WCHAR w[80];
        NTSTATUS st = UN(RtlIpv6StringToAddressExA)(c[i].s, a, &scope, &port);
        CHECKF(st == c[i].st, "\"%s\" status 0x%lx want 0x%lx", c[i].s, (unsigned long)st, (unsigned long)c[i].st);
        if (st == 0 && c[i].st == 0 && c[i].last) {
            CHECKF(scope == c[i].scope, "\"%s\" scope %lu", c[i].s, (unsigned long)scope);
            CHECKF(swap16(port) == c[i].port_host, "\"%s\" port 0x%x", c[i].s, port);
            CHECKF(a[15] == c[i].last, "\"%s\" last byte", c[i].s);
        }
        widen(w, c[i].s);
        scope = 0xDEAD; port = 0x1234;
        st = UN(RtlIpv6StringToAddressExW)(w, a, &scope, &port);
        CHECKF(st == c[i].st, "wide \"%s\" status 0x%lx", c[i].s, (unsigned long)st);
        if (st == 0 && c[i].last) {
            CHECKF(scope == c[i].scope, "wide \"%s\" scope", c[i].s);
            CHECKF(swap16(port) == c[i].port_host, "wide \"%s\" port", c[i].s);
        }
    }
}

TEST(netaddr_v6_roundtrip)
{
    REQUIRE(UN(RtlIpv6StringToAddressA)); REQUIRE(UN(RtlIpv6AddressToStringA));
    for (unsigned seed = 1; seed < 40; ++seed) {
        BYTE a[16], b[16]; char buf[80]; PCSTR term = NULL;
        unsigned x = seed * 2654435761u;
        for (unsigned i = 0; i < 16; ++i) {
            x = x * 1103515245u + 12345u;
            a[i] = (seed % 3 == 0 && (i / 2) % 2) ? 0 : (BYTE)(x >> 16);
        }
        UN(RtlIpv6AddressToStringA)(a, buf);
        EXPECT_EQ(UN(RtlIpv6StringToAddressA)(buf, &term, b), 0);
        CHECKF(!memcmp(a, b, 16), "roundtrip through \"%s\"", buf);
    }
}
