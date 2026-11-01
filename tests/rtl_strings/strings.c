#include "t.h"

UDECL(void, RtlCopyString, (PANSI_STRING, const ANSI_STRING *));
UDECL(void, RtlCopyUnicodeString, (PUNICODE_STRING, PCUNICODE_STRING));
UDECL(NTSTATUS, RtlInitUnicodeStringEx, (PUNICODE_STRING, PCWSTR));
UDECL(NTSTATUS, RtlAppendStringToString, (PANSI_STRING, const ANSI_STRING *));
UDECL(NTSTATUS, RtlAppendUnicodeStringToString, (PUNICODE_STRING, PCUNICODE_STRING));
UDECL(NTSTATUS, RtlAppendUnicodeToString, (PUNICODE_STRING, PCWSTR));
UDECL(LONG, RtlCompareString, (const ANSI_STRING *, const ANSI_STRING *, BOOLEAN));
UDECL(LONG, RtlCompareUnicodeString, (PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(BOOLEAN, RtlEqualString, (const ANSI_STRING *, const ANSI_STRING *, BOOLEAN));
UDECL(BOOLEAN, RtlEqualUnicodeString, (PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(BOOLEAN, RtlPrefixString, (const ANSI_STRING *, const ANSI_STRING *, BOOLEAN));
UDECL(BOOLEAN, RtlPrefixUnicodeString, (PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, RtlFindCharInUnicodeString, (ULONG, PCUNICODE_STRING, PCUNICODE_STRING, PUSHORT));
UDECL(WCHAR, RtlUpcaseUnicodeChar, (WCHAR));
UDECL(WCHAR, RtlDowncaseUnicodeChar, (WCHAR));
UDECL(NTSTATUS, RtlUpcaseUnicodeString, (PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, RtlHashUnicodeString, (PCUNICODE_STRING, BOOLEAN, ULONG, PULONG));
UDECL(NTSTATUS, RtlDuplicateUnicodeString, (ULONG, PCUNICODE_STRING, PUNICODE_STRING));

#define SMALL ((NTSTATUS)0xc0000023)
#define INVALID ((NTSTATUS)0xc000000d)
#define OVERFLOW ((NTSTATUS)0x80000005)

static void init_case(unsigned n)
{
    ANSI_STRING a; UNICODE_STRING w, x;
    char *s = n == 0 ? NULL : n == 1 ? "" : "a\0tail";
    WCHAR *u = n == 0 ? NULL : n == 1 ? L"" : L"a\0tail";
    REQUIRE(U(RtlInitAnsiString)); REQUIRE(U(RtlInitUnicodeString));
    REQUIRE(UN(RtlInitUnicodeStringEx));
    memset(&a, 0xcc, sizeof a); memset(&w, 0xcc, sizeof w); memset(&x, 0xcc, sizeof x);
    U(RtlInitAnsiString)(&a, s); U(RtlInitUnicodeString)(&w, u);
    EXPECT_EQ(UN(RtlInitUnicodeStringEx)(&x, u), 0);
    EXPECT_EQ(a.Length, n == 2); EXPECT_EQ(a.MaximumLength, n ? (n == 2) + 1 : 0);
    EXPECT_EQ(a.Buffer, s); EXPECT_EQ(w.Buffer, u); EXPECT_EQ(x.Buffer, u);
    EXPECT_EQ(w.Length, n == 2 ? 2 : 0); EXPECT_EQ(w.MaximumLength, n ? w.Length + 2 : 0);
    EXPECT_EQ(x.Length, w.Length); EXPECT_EQ(x.MaximumLength, w.MaximumLength);
}
TEST(rtl_strings_init_null) { init_case(0); }
TEST(rtl_strings_init_empty) { init_case(1); }
TEST(rtl_strings_init_embedded_zero) { init_case(2); }

TEST(rtl_strings_init_large_boundaries)
{
    static WCHAR b[32769]; UNICODE_STRING s;
    REQUIRE(U(RtlInitUnicodeString)); REQUIRE(UN(RtlInitUnicodeStringEx));
    for (unsigned i = 0; i < 32768; ++i) b[i] = 'x';
    b[32766] = 0;
    EXPECT_EQ(UN(RtlInitUnicodeStringEx)(&s, b), 0); EXPECT_EQ(s.Length, 65532); EXPECT_EQ(s.MaximumLength, 65534);
    b[32766] = 'x';
    EXPECT_EQ(UN(RtlInitUnicodeStringEx)(&s, b), (NTSTATUS)0xc0000106);
    EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.MaximumLength, 0); EXPECT_EQ(s.Buffer, b);
    U(RtlInitUnicodeString)(&s, b); EXPECT_EQ(s.Length, 65532); EXPECT_EQ(s.MaximumLength, 65534);
}

static void copy_case(unsigned cap, BOOL wide, BOOL null_source)
{
    char a[12]; WCHAR w[12];
    ANSI_STRING as = {3, 3, "a\0c"}, ad = {1, cap, a};
    UNICODE_STRING ws = {6, 6, L"a\0c"}, wd = {2, cap, w};
    memset(a, 0x55, sizeof a); for (unsigned i = 0; i < 12; ++i) w[i] = 0x5555;
    if (wide) {
        REQUIRE(UN(RtlCopyUnicodeString)); UN(RtlCopyUnicodeString)(&wd, null_source ? NULL : &ws);
        unsigned n = null_source ? 0 : cap < 6 ? cap : 6;
        EXPECT_EQ(wd.Length, n); EXPECT_EQ(wd.MaximumLength, cap); EXPECT_EQ(wd.Buffer, w);
        CHECK(!memcmp(w, ws.Buffer, n));
        EXPECT_EQ(w[n / 2], !null_source && n + 2 <= cap ? 0 : 0x5555);
    } else {
        REQUIRE(UN(RtlCopyString)); UN(RtlCopyString)(&ad, null_source ? NULL : &as);
        unsigned n = null_source ? 0 : cap < 3 ? cap : 3;
        EXPECT_EQ(ad.Length, n); EXPECT_EQ(ad.MaximumLength, cap); EXPECT_EQ(ad.Buffer, a);
        CHECK(!memcmp(a, as.Buffer, n)); EXPECT_EQ(a[n], 0x55);
    }
}
#define COPY(n,c,w,z) TEST(rtl_strings_copy_##n) { copy_case(c,w,z); }
COPY(ansi_zero,0,0,0) COPY(ansi_short,2,0,0) COPY(ansi_exact,3,0,0) COPY(ansi_spare,5,0,0) COPY(ansi_null,5,0,1)
COPY(wide_zero,0,1,0) COPY(wide_short,4,1,0) COPY(wide_exact,6,1,0) COPY(wide_spare,8,1,0) COPY(wide_null,8,1,1)

static void append_case(unsigned kind, unsigned cap, BOOL empty)
{
    char a[12]; WCHAR w[12];
    ANSI_STRING as = {empty ? 0 : 2, 2, "bc"}, ad = {1, cap, a};
    UNICODE_STRING ws = {empty ? 0 : 4, 4, L"bc"}, wd = {2, cap, w};
    NTSTATUS st; unsigned want = empty ? 1 : 3;
    memset(a, 0x55, sizeof a); for (unsigned i = 0; i < 12; ++i) w[i] = 0x5555;
    a[0] = 'a'; w[0] = 'a';
    if (!kind) {
        REQUIRE(UN(RtlAppendStringToString)); st = UN(RtlAppendStringToString)(&ad, &as);
        EXPECT_EQ(st, cap < want ? SMALL : 0); EXPECT_EQ(ad.Length, cap < want ? 1 : want);
        unsigned n = cap < want ? 1 : want;
        CHECK(!memcmp(a, cap < want || empty ? "a" : "abc", n)); EXPECT_EQ(a[n], 0x55);
        EXPECT_EQ(ad.MaximumLength, cap); EXPECT_EQ(ad.Buffer, a);
    } else {
        if (kind == 1) { REQUIRE(UN(RtlAppendUnicodeStringToString)); st = UN(RtlAppendUnicodeStringToString)(&wd, &ws); }
        else { REQUIRE(UN(RtlAppendUnicodeToString)); st = UN(RtlAppendUnicodeToString)(&wd, empty ? L"" : L"bc"); }
        EXPECT_EQ(st, cap < want * 2 ? SMALL : 0); EXPECT_EQ(wd.Length, cap < want * 2 ? 2 : want * 2);
        unsigned n = cap < want * 2 ? 1 : want;
        CHECK(!memcmp(w, cap < want * 2 || empty ? L"a" : L"abc", n * 2));
        BOOL term = st == 0 && n * 2 + 2 <= cap && (!empty || kind == 2);
        EXPECT_EQ(w[n], term ? 0 : 0x5555);
        EXPECT_EQ(wd.MaximumLength, cap); EXPECT_EQ(wd.Buffer, w);
    }
}
#define APP(n,k,c,e) TEST(rtl_strings_append_##n) { append_case(k,c,e); }
APP(ansi_short,0,2,0) APP(ansi_exact,0,3,0) APP(ansi_spare,0,5,0) APP(ansi_empty,0,5,1)
APP(wide_short,1,4,0) APP(wide_exact,1,6,0) APP(wide_spare,1,8,0) APP(wide_empty,1,8,1)
APP(z_short,2,4,0) APP(z_exact,2,6,0) APP(z_spare,2,8,0) APP(z_empty,2,8,1)

static void compare_case(unsigned v, BOOL wide)
{
    const char *aa[] = {"", "abc", "abc", "ab", "abZ", "a\0b"};
    const char *bb[] = {"", "abc", "ABC", "abcd", "aba", "a\0c"};
    const WCHAR *wa[] = {L"", L"abc", L"abc", L"ab", L"abZ", L"a\0b"};
    const WCHAR *wb[] = {L"", L"abc", L"ABC", L"abcd", L"aba", L"a\0c"};
    unsigned al[] = {0,3,3,2,3,3}, bl[] = {0,3,3,4,3,3};
    for (unsigned ci = 0; ci < 2; ++ci) {
        LONG expected = v < 2 ? 0 : v == 2 ? (ci ? 0 : 32) : v == 3 ? -2 : v == 4 ? (ci ? 25 : -7) : -1;
        BOOL equal = v < 2 || (v == 2 && ci), prefix = equal || v == 3;
        if (wide) {
            UNICODE_STRING a = {al[v]*2,al[v]*2,(PWSTR)wa[v]}, b = {bl[v]*2,bl[v]*2,(PWSTR)wb[v]};
            REQUIRE(UN(RtlCompareUnicodeString)); REQUIRE(UN(RtlEqualUnicodeString)); REQUIRE(UN(RtlPrefixUnicodeString));
            if (v == 3) expected = -2; /* Unicode comparator returns character-count difference. */
            EXPECT_EQ(UN(RtlCompareUnicodeString)(&a,&b,ci), expected);
            EXPECT_EQ(UN(RtlEqualUnicodeString)(&a,&b,ci), equal); EXPECT_EQ(UN(RtlPrefixUnicodeString)(&a,&b,ci), prefix);
        } else {
            ANSI_STRING a = {al[v],al[v],(PCHAR)aa[v]}, b = {bl[v],bl[v],(PCHAR)bb[v]};
            REQUIRE(UN(RtlCompareString)); REQUIRE(UN(RtlEqualString)); REQUIRE(UN(RtlPrefixString));
            EXPECT_EQ(UN(RtlCompareString)(&a,&b,ci), expected);
            EXPECT_EQ(UN(RtlEqualString)(&a,&b,ci), equal); EXPECT_EQ(UN(RtlPrefixString)(&a,&b,ci), prefix);
        }
    }
}
#define CMP(n,v,w) TEST(rtl_strings_compare_##n) { compare_case(v,w); }
CMP(ansi_empty,0,0) CMP(ansi_equal,1,0) CMP(ansi_case,2,0) CMP(ansi_length,3,0) CMP(ansi_order,4,0) CMP(ansi_nul,5,0)
CMP(wide_empty,0,1) CMP(wide_equal,1,1) CMP(wide_case,2,1) CMP(wide_length,3,1) CMP(wide_order,4,1) CMP(wide_nul,5,1)

static void find_case(ULONG flags, PCWSTR set, NTSTATUS status, USHORT offset)
{
    UNICODE_STRING s = {10,10,L"abAba"}, chars = {(USHORT)(wcslen(set)*2),(USHORT)(wcslen(set)*2),(PWSTR)set};
    USHORT out = 0x5555;
    REQUIRE(UN(RtlFindCharInUnicodeString));
    EXPECT_EQ(UN(RtlFindCharInUnicodeString)(flags,&s,&chars,&out),status); EXPECT_EQ(out,offset);
}
TEST(rtl_strings_find_forward) { find_case(0,L"a",0,2); }
TEST(rtl_strings_find_reverse) { find_case(1,L"a",0,8); }
TEST(rtl_strings_find_not) { find_case(2,L"a",0,4); }
TEST(rtl_strings_find_case) { find_case(4,L"A",0,2); }
TEST(rtl_strings_find_missing) { find_case(0,L"z",(NTSTATUS)0xc0000225,0); }
TEST(rtl_strings_find_invalid_flags) { find_case(8,L"a",INVALID,0); }

TEST(rtl_strings_case_ascii)
{
    REQUIRE(UN(RtlUpcaseUnicodeChar)); REQUIRE(UN(RtlDowncaseUnicodeChar));
    for (unsigned c = 0; c < 128; ++c) {
        EXPECT_EQ(UN(RtlUpcaseUnicodeChar)(c), c >= 'a' && c <= 'z' ? c-32 : c);
        EXPECT_EQ(UN(RtlDowncaseUnicodeChar)(c), c >= 'A' && c <= 'Z' ? c+32 : c);
    }
}
static void upcase_case(unsigned cap, BOOL allocate)
{
    WCHAR b[8] = {0x5555,0x5555,0x5555,0x5555};
    UNICODE_STRING s = {6,6,L"a\0z"}, d = {2,cap,b};
    REQUIRE(UN(RtlUpcaseUnicodeString)); REQUIRE(U(RtlFreeUnicodeString));
    NTSTATUS st = UN(RtlUpcaseUnicodeString)(&d,&s,allocate);
    EXPECT_EQ(st, !allocate && cap < 6 ? OVERFLOW : 0);
    if (st == 0 && d.Buffer) { EXPECT_EQ(d.Length,6); CHECK(!memcmp(d.Buffer,L"A\0Z",6));
        if (!allocate) EXPECT_EQ(b[3],0x5555);
    } else if (!allocate) { EXPECT_EQ(d.Length,2); EXPECT_EQ(b[0],0x5555); }
    if (allocate && d.Buffer && d.Buffer != b) { U(RtlFreeUnicodeString)(&d); EXPECT_EQ(d.Buffer,NULL); EXPECT_EQ(d.Length,0); EXPECT_EQ(d.MaximumLength,0); }
}
TEST(rtl_strings_upcase_short) { upcase_case(4,0); }
TEST(rtl_strings_upcase_exact) { upcase_case(6,0); }
TEST(rtl_strings_upcase_spare) { upcase_case(8,0); }
TEST(rtl_strings_upcase_allocate) { upcase_case(0,1); }

static void hash_case(ULONG algorithm, BOOL ci)
{
    UNICODE_STRING s = {8,8,L"aB\0z"}; ULONG h = 0x55555555, expected = 0;
    REQUIRE(UN(RtlHashUnicodeString));
    for (unsigned i=0;i<4;++i) { WCHAR c=s.Buffer[i]; if(ci && c>='a' && c<='z') c-=32; expected=expected*65599u+c; }
    EXPECT_EQ(UN(RtlHashUnicodeString)(&s,ci,algorithm,&h),algorithm<2?0:INVALID);
    EXPECT_EQ(h,algorithm<2?expected:0);
}
TEST(rtl_strings_hash_default) { hash_case(0,0); }
TEST(rtl_strings_hash_x65599) { hash_case(1,0); }
TEST(rtl_strings_hash_case) { hash_case(1,1); }
TEST(rtl_strings_hash_invalid) { hash_case(2,0); }

static void duplicate_case(ULONG flags, BOOL empty)
{
    UNICODE_STRING s = {empty?0:6,6,L"a\0z"}, d = {0,0,NULL};
    REQUIRE(UN(RtlDuplicateUnicodeString)); REQUIRE(U(RtlFreeUnicodeString));
    NTSTATUS st=UN(RtlDuplicateUnicodeString)(flags,&s,&d);
    EXPECT_EQ(st,flags==2 || flags>3 ? INVALID:0);
    if (st==0) {
        unsigned cap=empty && flags!=3?0:s.Length+((flags&1)?2:0);
        EXPECT_EQ(d.Length,s.Length); EXPECT_EQ(d.MaximumLength,cap);
        if (cap) { CHECK(d.Buffer!=NULL); if(d.Buffer) { CHECK(d.Buffer!=s.Buffer); CHECK(!memcmp(d.Buffer,s.Buffer,s.Length)); if(flags&1) EXPECT_EQ(d.Buffer[s.Length/2],0); } }
        else EXPECT_EQ(d.Buffer,NULL);
    }
    if(d.Buffer) { U(RtlFreeUnicodeString)(&d); EXPECT_EQ(d.Buffer,NULL); EXPECT_EQ(d.Length,0); EXPECT_EQ(d.MaximumLength,0); }
}
TEST(rtl_strings_duplicate_raw) { duplicate_case(0,0); }
TEST(rtl_strings_duplicate_terminated) { duplicate_case(1,0); }
TEST(rtl_strings_duplicate_empty_raw) { duplicate_case(0,1); }
TEST(rtl_strings_duplicate_empty_term) { duplicate_case(1,1); }
TEST(rtl_strings_duplicate_empty_allocated) { duplicate_case(3,1); }
TEST(rtl_strings_duplicate_invalid_two) { duplicate_case(2,0); }
TEST(rtl_strings_duplicate_invalid_bits) { duplicate_case(4,0); }
