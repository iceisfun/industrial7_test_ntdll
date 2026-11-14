#include "t.h"

#define ST(x) ((ULONG)(x))
typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } STR8;

UDECL(ULONG, RtlUnicodeStringToAnsiSize, (const UNICODE_STRING *));
UDECL(ULONG, RtlUnicodeStringToOemSize, (const UNICODE_STRING *));
UDECL(ULONG, RtlOemStringToUnicodeSize, (const STR8 *));
UDECL(NTSTATUS, RtlUnicodeStringToCountedOemString, (STR8 *, const UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlUpcaseUnicodeStringToCountedOemString, (STR8 *, const UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlUpcaseUnicodeStringToAnsiString, (STR8 *, const UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlUpcaseUnicodeStringToOemString, (STR8 *, const UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlUpcaseUnicodeToMultiByteN, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUpcaseUnicodeToOemN, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToCustomCPN, (void *, PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUpcaseUnicodeToCustomCPN, (void *, PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeStringToUTF8String, (STR8 *, const UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlFreeUTF8String, (STR8 *));
UDECL(VOID, RtlFreeAnsiString, (STR8 *));
UDECL(VOID, RtlFreeOemString, (STR8 *));
UDECL(VOID, RtlFreeUnicodeString, (UNICODE_STRING *));
UDECL(NTSTATUS, RtlStringFromGUID, (const GUID *, UNICODE_STRING *));
UDECL(NTSTATUS, RtlStringFromGUIDEx, (const GUID *, UNICODE_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlMultiAppendUnicodeStringBuffer, (void *, ULONG, const UNICODE_STRING *));
UDECL(NTSTATUS, RtlInitializeExtendedContext, (PVOID, ULONG, PVOID *));
UDECL(NTSTATUS, RtlInitializeExtendedContext2, (PVOID, ULONG, PVOID *, ULONG64));
UDECL(NTSTATUS, RtlInitializeRXact, (HANDLE, BOOLEAN, PVOID *));
UDECL(VOID, RtlInitializeResource, (void *));
UDECL(VOID, RtlDeleteResource, (void *));
UDECL(BOOLEAN, RtlAcquireResourceShared, (void *, BOOLEAN));
UDECL(BOOLEAN, RtlAcquireResourceExclusive, (void *, BOOLEAN));
UDECL(VOID, RtlReleaseResource, (void *));
UDECL(PVOID, RtlFreeHeap, (PVOID, ULONG, PVOID));

static UNICODE_STRING us(const WCHAR *s) { UNICODE_STRING u; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2; u.Buffer = (PWSTR)s; return u; }
static void free_ansi(STR8 *s) { if (s->Buffer) { if (UN(RtlFreeAnsiString)) UN(RtlFreeAnsiString)(s); else UN(RtlFreeHeap)(GetProcessHeap(), 0, s->Buffer); } }

TEST(rtl_net_ip_str_b_str_aliases) {
    CHECK(t_proc("RtlUnicodeStringToAnsiSize") != NULL);
    CHECK(t_proc("RtlUnicodeStringToOemSize") == t_proc("RtlUnicodeStringToAnsiSize"));
    CHECK(t_proc("RtlStringFromGUID") != t_proc("RtlStringFromGUIDEx"));
}

TEST(rtl_net_ip_str_b_str_conversion_sizes) {
    REQUIRE(UN(RtlUnicodeStringToAnsiSize)); REQUIRE(UN(RtlUnicodeStringToOemSize)); REQUIRE(UN(RtlOemStringToUnicodeSize));
    UNICODE_STRING u = us(L"abc");
    EXPECT_EQ(UN(RtlUnicodeStringToAnsiSize)(&u), 4);        /* includes the terminating NUL */
    EXPECT_EQ(UN(RtlUnicodeStringToOemSize)(&u), 4);
    u = us(L"");
    EXPECT_EQ(UN(RtlUnicodeStringToAnsiSize)(&u), 1);
    EXPECT_EQ(UN(RtlUnicodeStringToOemSize)(&u), 1);
    u = us(L"abcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(UN(RtlUnicodeStringToAnsiSize)(&u), 37);
    u = us(L"abc"); u.Length = 2;                              /* only the counted length matters */
    EXPECT_EQ(UN(RtlUnicodeStringToAnsiSize)(&u), 2);
    STR8 s = { 3, 4, "abc" };
    EXPECT_EQ(UN(RtlOemStringToUnicodeSize)(&s), 8);         /* 3 chars * 2 + terminating WCHAR */
    s.Length = 0; EXPECT_EQ(UN(RtlOemStringToUnicodeSize)(&s), 2);
    s.Length = 10; s.Buffer = "0123456789"; EXPECT_EQ(UN(RtlOemStringToUnicodeSize)(&s), 22);
}

static void check_counted(NTSTATUS (WINAPI *f)(STR8 *, const UNICODE_STRING *, BOOLEAN), const char *name, int upper) {
    UNICODE_STRING u = us(L"Abc.dEf");
    const char *want = upper ? "ABC.DEF" : "Abc.dEf";
    STR8 o; memset(&o, 0xcc, sizeof o);
    NTSTATUS s = f(&o, &u, TRUE);
    CHECKF(s == 0, "%s alloc status 0x%lx", name, (long)s);
    if (s == 0) {
        CHECKF(o.Length == 7 && o.MaximumLength == 7, "%s counted lengths %u/%u", name, o.Length, o.MaximumLength);
        CHECKF(o.Buffer && !memcmp(o.Buffer, want, 7), "%s content", name);
        if (UN(RtlFreeOemString)) UN(RtlFreeOemString)(&o); else free_ansi(&o);
    }
    char buf[16]; memset(buf, '#', sizeof buf);
    memset(&o, 0, sizeof o); o.Buffer = buf; o.MaximumLength = 7;
    s = f(&o, &u, FALSE);
    CHECKF(s == 0, "%s exact fit status 0x%lx", name, (long)s);
    CHECKF(o.Length == 7 && !memcmp(buf, want, 7) && buf[7] == '#', "%s non-alloc content", name);
    memset(buf, '#', sizeof buf); o.Buffer = buf; o.MaximumLength = 6; o.Length = 0;
    s = f(&o, &u, FALSE);
    CHECKF(ST(s) == 0x80000005, "%s too small status 0x%lx", name, (long)s);
    /* empty source clears the destination */
    UNICODE_STRING e = us(L"");
    memset(&o, 0xcc, sizeof o);
    s = f(&o, &e, TRUE);
    CHECKF(s == 0 && o.Length == 0 && o.Buffer == NULL, "%s empty", name);
}

TEST(rtl_net_ip_str_b_str_counted_oem) {
    REQUIRE(UN(RtlUnicodeStringToCountedOemString)); REQUIRE(UN(RtlUpcaseUnicodeStringToCountedOemString));
    check_counted(UN(RtlUnicodeStringToCountedOemString), "ToCountedOem", 0);
    check_counted(UN(RtlUpcaseUnicodeStringToCountedOemString), "UpcaseToCountedOem", 1);
}

static void check_terminated(NTSTATUS (WINAPI *f)(STR8 *, const UNICODE_STRING *, BOOLEAN), const char *name, int oem) {
    UNICODE_STRING u = us(L"Hello1");
    STR8 o; memset(&o, 0xcc, sizeof o);
    NTSTATUS s = f(&o, &u, TRUE);
    CHECKF(s == 0, "%s alloc status 0x%lx", name, (long)s);
    if (s == 0) {
        CHECKF(o.Length == 6 && o.MaximumLength == 7, "%s lengths %u/%u", name, o.Length, o.MaximumLength);
        CHECKF(o.Buffer && !memcmp(o.Buffer, "HELLO1", 7), "%s content/terminator", name);
        if (oem && UN(RtlFreeOemString)) UN(RtlFreeOemString)(&o); else free_ansi(&o);
    }
    char buf[16]; memset(buf, '#', sizeof buf);
    o.Buffer = buf; o.Length = 0; o.MaximumLength = 7;
    s = f(&o, &u, FALSE);
    CHECKF(s == 0 && o.Length == 6 && !memcmp(buf, "HELLO1", 7), "%s non-alloc status 0x%lx", name, (long)s);
    memset(buf, '#', sizeof buf); o.MaximumLength = 6; o.Length = 0;
    s = f(&o, &u, FALSE);
    CHECKF(ST(s) == 0x80000005, "%s no room for NUL status 0x%lx", name, (long)s);
    memset(buf, '#', sizeof buf); o.MaximumLength = 0;
    s = f(&o, &u, FALSE);
    CHECKF(ST(s) == 0x80000005, "%s zero capacity status 0x%lx", name, (long)s);
}

TEST(rtl_net_ip_str_b_str_upcase_ansi_oem_string) {
    REQUIRE(UN(RtlUpcaseUnicodeStringToAnsiString)); REQUIRE(UN(RtlUpcaseUnicodeStringToOemString));
    check_terminated(UN(RtlUpcaseUnicodeStringToAnsiString), "UpcaseToAnsiString", 0);
    check_terminated(UN(RtlUpcaseUnicodeStringToOemString), "UpcaseToOemString", 1);
}

static void check_upcase_n(NTSTATUS (WINAPI *f)(PCHAR, ULONG, PULONG, PCWSTR, ULONG), const char *name) {
    static const WCHAR src[] = L"Hello, wOrld-09";
    char dst[32]; ULONG n = 0xdead;
    memset(dst, '#', sizeof dst);
    NTSTATUS s = f(dst, sizeof dst, &n, src, 15 * 2);
    CHECKF(s == 0 && n == 15 && !memcmp(dst, "HELLO, WORLD-09", 15) && dst[15] == '#', "%s basic status 0x%lx n=%lu", name, (long)s, n);
    memset(dst, '#', sizeof dst); n = 0xdead;
    s = f(dst, 5, &n, src, 15 * 2);
    CHECKF(ST(s) == 0x80000005 && n == 5 && !memcmp(dst, "HELLO#", 6), "%s truncated status 0x%lx n=%lu", name, (long)s, n);
    n = 0xdead; s = f(dst, 8, &n, src, 0);
    CHECKF(s == 0 && n == 0, "%s empty status 0x%lx n=%lu", name, (long)s, n);
    n = 0xdead; s = f(dst, 8, &n, src, 7);                      /* odd byte count: trailing half character ignored */
    CHECKF(s == 0 && n == 3 && !memcmp(dst, "HEL", 3), "%s odd byte count n=%lu", name, n);
    n = 0xdead; s = f(dst, 0, &n, src, 4);
    CHECKF(ST(s) == 0x80000005 && n == 0, "%s zero dest status 0x%lx n=%lu", name, (long)s, n);
}

TEST(rtl_net_ip_str_b_str_upcase_to_multibyte_oem_n) {
    REQUIRE(UN(RtlUpcaseUnicodeToMultiByteN)); REQUIRE(UN(RtlUpcaseUnicodeToOemN));
    check_upcase_n(UN(RtlUpcaseUnicodeToMultiByteN), "UpcaseToMultiByteN");
    check_upcase_n(UN(RtlUpcaseUnicodeToOemN), "UpcaseToOemN");
}

typedef struct {
    USHORT CodePage, MaximumCharacterSize, DefaultChar, UniDefaultChar, TransDefaultChar, TransUniDefaultChar, DBCSCodePage;
    UCHAR LeadByte[12]; PUSHORT MultiByteTable; PVOID WideCharTable; PUSHORT DBCSRanges; PUSHORT DBCSOffsets;
} CPTBL;

TEST(rtl_net_ip_str_b_str_custom_cpn) {
    REQUIRE(UN(RtlUnicodeToCustomCPN)); REQUIRE(UN(RtlUpcaseUnicodeToCustomCPN));
    static UCHAR wide[65536]; static USHORT mb[256];
    for (int i = 0; i < 65536; i++) wide[i] = i < 256 ? (UCHAR)i : '?';
    for (int i = 0; i < 256; i++) mb[i] = (USHORT)i;
    CPTBL cp; memset(&cp, 0, sizeof cp);
    cp.CodePage = 28591; cp.MaximumCharacterSize = 1; cp.DefaultChar = '?'; cp.UniDefaultChar = '?';
    cp.TransDefaultChar = '?'; cp.TransUniDefaultChar = '?';
    cp.MultiByteTable = mb; cp.WideCharTable = wide;
    static const WCHAR src[] = { 'a', 'B', 0xe9, 0x20ac, 'z' };
    char dst[16]; ULONG n = 0xdead; NTSTATUS s;
    memset(dst, '#', sizeof dst);
    s = UN(RtlUnicodeToCustomCPN)(&cp, dst, 16, &n, src, sizeof src);
    CHECKF(s == 0 && n == 5 && !memcmp(dst, "aB\xe9?z", 5) && dst[5] == '#', "sbcs convert status 0x%lx n=%lu", (long)s, n);
    memset(dst, '#', sizeof dst);
    s = UN(RtlUnicodeToCustomCPN)(&cp, dst, 3, &n, src, sizeof src);
    CHECKF(ST(s) == 0x80000005 && n == 3 && !memcmp(dst, "aB\xe9#", 4), "sbcs truncated status 0x%lx n=%lu", (long)s, n);
    s = UN(RtlUnicodeToCustomCPN)(&cp, dst, 16, NULL, src, sizeof src);   /* result length is optional */
    EXPECT_EQ(s, 0);
    n = 0xdead; s = UN(RtlUnicodeToCustomCPN)(&cp, dst, 16, &n, src, 0);
    CHECKF(s == 0 && n == 0, "sbcs empty n=%lu", n);
    /* upcase variant */
    memset(dst, '#', sizeof dst); n = 0xdead;
    s = UN(RtlUpcaseUnicodeToCustomCPN)(&cp, dst, 16, &n, src, sizeof src);
    CHECKF(s == 0 && n == 5, "upcase sbcs status 0x%lx n=%lu", (long)s, n);
    CHECKF(dst[0] == 'A' && dst[1] == 'B' && dst[4] == 'Z', "upcase sbcs content %.5s", dst);
    /* UTF-8 table (code page 65001) takes the UTF-8 encoder */
    CPTBL u8; memset(&u8, 0, sizeof u8); u8.CodePage = 65001; u8.MaximumCharacterSize = 4;
    memset(dst, '#', sizeof dst); n = 0xdead;
    s = UN(RtlUnicodeToCustomCPN)(&u8, dst, 16, &n, src, sizeof src);
    CHECKF(s == 0 && n == 8 && !memcmp(dst, "aB\xc3\xa9\xe2\x82\xac" "z", 8), "utf8 status 0x%lx n=%lu", (long)s, n);
    memset(dst, '#', sizeof dst); n = 0xdead;
    s = UN(RtlUnicodeToCustomCPN)(&u8, dst, 3, &n, src, sizeof src);
    CHECKF(ST(s) == 0x80000005, "utf8 small status 0x%lx", (long)s);
    n = 0xdead; s = UN(RtlUnicodeToCustomCPN)(&u8, dst, 16, &n, src, 0);
    CHECKF(s == 0 && n == 0, "utf8 empty");
}

TEST(rtl_net_ip_str_b_str_unicode_to_utf8_string) {
    REQUIRE(UN(RtlUnicodeStringToUTF8String)); REQUIRE(UN(RtlFreeUTF8String));
    STR8 o; NTSTATUS s;
    UNICODE_STRING u = us(L"abc");
    memset(&o, 0xcc, sizeof o);
    s = UN(RtlUnicodeStringToUTF8String)(&o, &u, TRUE);
    CHECKF(s == 0 && o.Length == 3 && o.MaximumLength == 4 && !memcmp(o.Buffer, "abc", 4), "ascii alloc 0x%lx", (long)s);
    if (s == 0) UN(RtlFreeUTF8String)(&o);
    static const WCHAR mixed[] = { 'a', 0xe9, 0x20ac, 0xd83d, 0xde00, 0 };         /* a, e-acute, euro, U+1F600 */
    u = us(mixed);
    memset(&o, 0xcc, sizeof o);
    s = UN(RtlUnicodeStringToUTF8String)(&o, &u, TRUE);
    CHECKF(s == 0 && o.Length == 10 && o.MaximumLength == 11, "mixed alloc 0x%lx len %u", (long)s, o.Length);
    if (s == 0) {
        CHECK(!memcmp(o.Buffer, "a\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 11));
        UN(RtlFreeUTF8String)(&o);
    }
    /* caller-supplied buffer */
    char buf[16]; memset(buf, '#', sizeof buf);
    u = us(L"abc"); o.Buffer = buf; o.Length = 0; o.MaximumLength = 4;
    s = UN(RtlUnicodeStringToUTF8String)(&o, &u, FALSE);
    CHECKF(s == 0 && o.Length == 3 && !memcmp(buf, "abc", 4), "non-alloc exact 0x%lx", (long)s);
    memset(buf, '#', sizeof buf); o.MaximumLength = 3; o.Length = 0;
    s = UN(RtlUnicodeStringToUTF8String)(&o, &u, FALSE);
    CHECKF(ST(s) == 0xC0000023 && o.Length == 2 && !memcmp(buf, "ab", 2), "non-alloc truncated 0x%lx len %u", (long)s, o.Length);
    o.MaximumLength = 0; o.Length = 0;
    s = UN(RtlUnicodeStringToUTF8String)(&o, &u, FALSE);
    EXPECT_EQ(ST(s), 0x80000005);
    UNICODE_STRING e = us(L"");
    memset(&o, 0xcc, sizeof o);
    s = UN(RtlUnicodeStringToUTF8String)(&o, &e, TRUE);
    CHECKF(s == 0 && o.Length == 0 && o.MaximumLength == 1 && o.Buffer && o.Buffer[0] == 0, "empty 0x%lx", (long)s);
    if (s == 0) UN(RtlFreeUTF8String)(&o);
}

TEST(rtl_net_ip_str_b_str_string_from_guid) {
    REQUIRE(UN(RtlStringFromGUID)); REQUIRE(UN(RtlStringFromGUIDEx));
    GUID g = { 0x00112233, 0x4455, 0x6677, { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } };
    UNICODE_STRING u; memset(&u, 0xcc, sizeof u);
    NTSTATUS s = UN(RtlStringFromGUID)(&g, &u);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(u.Length, 76); EXPECT_EQ(u.MaximumLength, 78);
        char a[80]; for (int i = 0; i <= 38; i++) a[i] = (char)u.Buffer[i];
        t_note("RtlStringFromGUID -> %s", a);
        CHECK(!_stricmp(a, "{00112233-4455-6677-8899-AABBCCDDEEFF}"));
        EXPECT_EQ(u.Buffer[38], 0);
        UN(RtlFreeUnicodeString)(&u);
    }
    GUID z = { 0 };
    s = UN(RtlStringFromGUID)(&z, &u);
    EXPECT_EQ(s, 0);
    if (s == 0) { CHECK(!lstrcmpW(u.Buffer, L"{00000000-0000-0000-0000-000000000000}")); UN(RtlFreeUnicodeString)(&u); }
    GUID f; memset(&f, 0xff, sizeof f);
    s = UN(RtlStringFromGUID)(&f, &u);
    if (s == 0) { CHECK(!_wcsicmp(u.Buffer, L"{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}")); UN(RtlFreeUnicodeString)(&u); }
    /* Ex with caller storage */
    WCHAR buf[48]; for (int i = 0; i < 48; i++) buf[i] = 0x7777;
    u.Buffer = buf; u.Length = 0; u.MaximumLength = 78;
    s = UN(RtlStringFromGUIDEx)(&g, &u, FALSE);
    EXPECT_EQ(s, 0);
    CHECK(!_wcsicmp(buf, L"{00112233-4455-6677-8899-AABBCCDDEEFF}"));
    EXPECT_EQ(buf[38], 0);
    EXPECT_EQ(buf[39], 0x7777);
    EXPECT_EQ(u.Length, 76);
    u.MaximumLength = 76; u.Length = 0;
    EXPECT_EQ(ST(UN(RtlStringFromGUIDEx)(&g, &u, FALSE)), 0xC0000023);      /* needs the NUL: STATUS_BUFFER_TOO_SMALL */
    u.MaximumLength = 0;
    EXPECT_EQ(ST(UN(RtlStringFromGUIDEx)(&g, &u, FALSE)), 0xC0000023);
    memset(&u, 0xcc, sizeof u);
    s = UN(RtlStringFromGUIDEx)(&g, &u, TRUE);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(u.Length, 76); EXPECT_EQ(u.MaximumLength, 78); UN(RtlFreeUnicodeString)(&u); }
}

TEST(rtl_net_ip_str_b_str_multi_append) {
    REQUIRE(UN(RtlMultiAppendUnicodeStringBuffer));
    /* RTL_UNICODE_STRING_BUFFER: UNICODE_STRING String; RTL_BUFFER ByteBuffer { Buffer, StaticBuffer, Size, StaticSize, ... } */
    struct { UNICODE_STRING String; PUCHAR Buffer, StaticBuffer; SIZE_T Size, StaticSize, Reserved1; PVOID Reserved2; } b;
    WCHAR stat[32]; memset(&b, 0, sizeof b);
    memcpy(stat, L"ab", 6);
    b.Buffer = b.StaticBuffer = (PUCHAR)stat; b.Size = b.StaticSize = sizeof stat;
    b.String.Buffer = stat; b.String.Length = 4; b.String.MaximumLength = 6;
    UNICODE_STRING parts[3] = { us(L"cd"), us(L"E"), us(L"fgh") };
    NTSTATUS s = UN(RtlMultiAppendUnicodeStringBuffer)(&b, 3, parts);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(b.String.Length, 16); EXPECT_EQ(b.String.MaximumLength, 18);
    CHECK(!lstrcmpW(b.String.Buffer, L"abcdEfgh"));
    EXPECT_EQ(b.String.Buffer, stat);                    /* fits in the static buffer */
    s = UN(RtlMultiAppendUnicodeStringBuffer)(&b, 0, parts);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(b.String.Length, 16); CHECK(!lstrcmpW(b.String.Buffer, L"abcdEfgh"));
    /* growth beyond the static buffer moves to a heap buffer and keeps the content */
    WCHAR big[40]; for (int i = 0; i < 39; i++) big[i] = L'a' + (i % 26); big[39] = 0;
    UNICODE_STRING bp = us(big);
    s = UN(RtlMultiAppendUnicodeStringBuffer)(&b, 1, &bp);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(b.String.Length, 16 + 78);
    CHECK(!wcsncmp(b.String.Buffer, L"abcdEfgh", 8) && !wcscmp(b.String.Buffer + 8, big));
    CHECK(b.String.Buffer != stat);
    if (b.Buffer != b.StaticBuffer) HeapFree(GetProcessHeap(), 0, b.Buffer);
    /* total length limit */
    memset(&b, 0, sizeof b);
    memcpy(stat, L"ab", 6);
    b.Buffer = b.StaticBuffer = (PUCHAR)stat; b.Size = b.StaticSize = sizeof stat;
    b.String.Buffer = stat; b.String.Length = 4; b.String.MaximumLength = 6;
    UNICODE_STRING huge[2] = { { 0xfff0, 0xfff0, stat }, { 0x20, 0x20, stat } };
    s = UN(RtlMultiAppendUnicodeStringBuffer)(&b, 2, huge);
    EXPECT_EQ(ST(s), 0xC0000106);                         /* STATUS_NAME_TOO_LONG */
    EXPECT_EQ(b.String.Length, 4);                        /* unchanged on failure */
}

TEST(rtl_net_ip_str_b_str_extended_context) {
    REQUIRE(UN(RtlInitializeExtendedContext)); REQUIRE(UN(RtlInitializeExtendedContext2));
    BYTE *mem = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(mem != NULL); if (!mem) return;
    const ULONG flags = CONTEXT_AMD64 | 0x0b;                 /* CONTEXT_FULL: control, integer, floating point */
    PVOID ex = NULL;
    NTSTATUS s = UN(RtlInitializeExtendedContext)(mem + 5, flags, &ex);     /* deliberately misaligned start */
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE *ctx = (BYTE *)(((ULONG_PTR)(mem + 5) + 15) & ~(ULONG_PTR)15);
        EXPECT_EQ(*(ULONG *)(ctx + 0x30), flags);              /* CONTEXT.ContextFlags */
        EXPECT_EQ((BYTE *)ex, ctx + sizeof(CONTEXT));          /* CONTEXT_EX follows the CONTEXT */
        LONG *c = ex;                                          /* Legacy {Offset,Length}, All {Offset,Length}, XState {Offset,Length} */
        EXPECT_EQ(c[0], -(LONG)sizeof(CONTEXT));
        EXPECT_EQ(c[2], -(LONG)sizeof(CONTEXT));
        EXPECT_EQ(c[1], sizeof(CONTEXT) + 0x18);
        EXPECT_EQ(c[5], 0);                                    /* no XSTATE area requested */
    }
    PVOID ex2 = NULL;
    s = UN(RtlInitializeExtendedContext2)(mem, flags, &ex2, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) EXPECT_EQ((BYTE *)ex2, mem + sizeof(CONTEXT));
    /* an invalid context flag set is rejected */
    ex = (PVOID)(ULONG_PTR)0x1234;
    s = UN(RtlInitializeExtendedContext)(mem, 0, &ex);
    CHECKF(s < 0, "zero flags rejected, got 0x%lx", (long)s);
    EXPECT_EQ(ex, 0x1234);
    s = UN(RtlInitializeExtendedContext2)(mem, 0x10, &ex, 0);
    CHECKF(s < 0, "flags without architecture rejected, got 0x%lx", (long)s);
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(rtl_net_ip_str_b_str_rxact) {
    REQUIRE(UN(RtlInitializeRXact));
    HKEY k; char name[64]; wsprintfA(name, "Software\\ntdll_conf_rxact_%lu", GetCurrentProcessId());
    if (RegCreateKeyExA(HKEY_CURRENT_USER, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) { t_skip("cannot create test key"); return; }
    PVOID ctx = NULL;
    NTSTATUS s = UN(RtlInitializeRXact)(k, FALSE, &ctx);
    CHECKF(ST(s) == 0x40000004, "first init status 0x%lx", (long)s);        /* STATUS_RXACT_STATE_CREATED */
    CHECK(ctx != NULL);
    if (ctx) { UN(RtlFreeHeap)(GetProcessHeap(), 0, ctx); }
    ctx = NULL;
    s = UN(RtlInitializeRXact)(k, FALSE, &ctx);
    EXPECT_EQ(s, 0);                                                        /* state already exists, nothing pending */
    CHECK(ctx != NULL);
    if (ctx) UN(RtlFreeHeap)(GetProcessHeap(), 0, ctx);
    ctx = (PVOID)(ULONG_PTR)0x1234;
    s = UN(RtlInitializeRXact)((HANDLE)(ULONG_PTR)0x77777770, FALSE, &ctx);
    CHECKF(s < 0, "invalid root handle status 0x%lx", (long)s);
    EXPECT_EQ(ctx, 0x1234);
    RegCloseKey(k); RegDeleteTreeA(HKEY_CURRENT_USER, name);
}

TEST(rtl_net_ip_str_b_str_resource) {
    REQUIRE(UN(RtlInitializeResource)); REQUIRE(UN(RtlDeleteResource)); REQUIRE(UN(RtlAcquireResourceShared));
    REQUIRE(UN(RtlAcquireResourceExclusive)); REQUIRE(UN(RtlReleaseResource));
    BYTE r[0x68] __attribute__((aligned(16)));
    memset(r, 0xcc, sizeof r);
    UN(RtlInitializeResource)(r);
    /* RTL_RESOURCE: CriticalSection(0x28) SharedSemaphore(0x28) NumberOfWaitingShared(0x30) ExclusiveSemaphore(0x38)
       NumberOfWaitingExclusive(0x40) NumberOfActive(0x44) ExclusiveOwnerThread(0x48) Flags(0x50) DebugInfo(0x58) */
    CHECK(*(HANDLE *)(r + 0x28) != NULL); CHECK(*(HANDLE *)(r + 0x38) != NULL);
    EXPECT_EQ(*(ULONG *)(r + 0x30), 0); EXPECT_EQ(*(ULONG *)(r + 0x40), 0); EXPECT_EQ(*(LONG *)(r + 0x44), 0);
    EXPECT_EQ(*(PVOID *)(r + 0x48), 0);
    CHECK(*(PVOID *)(r + 0x58) != NULL);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(r, FALSE), 1);
    EXPECT_EQ(*(LONG *)(r + 0x44), 1);
    EXPECT_EQ(UN(RtlAcquireResourceShared)(r, FALSE), 1);
    EXPECT_EQ(*(LONG *)(r + 0x44), 2);
    UN(RtlReleaseResource)(r); UN(RtlReleaseResource)(r);
    EXPECT_EQ(*(LONG *)(r + 0x44), 0);
    EXPECT_EQ(UN(RtlAcquireResourceExclusive)(r, FALSE), 1);
    EXPECT_EQ(*(LONG *)(r + 0x44), -1);
    CHECK(*(PVOID *)(r + 0x48) != NULL);
    UN(RtlReleaseResource)(r);
    EXPECT_EQ(*(LONG *)(r + 0x44), 0);
    UN(RtlDeleteResource)(r);
}
