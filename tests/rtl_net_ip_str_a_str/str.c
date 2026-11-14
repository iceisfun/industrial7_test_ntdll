#include "t.h"
#include <stdlib.h>

typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } STR8;
UDECL(VOID, RtlInitString, (STR8 *, const char *));
UDECL(NTSTATUS, RtlInitStringEx, (STR8 *, const char *));
UDECL(NTSTATUS, RtlInitAnsiStringEx, (STR8 *, const char *));
UDECL(VOID, RtlInitUTF8String, (STR8 *, const char *));
UDECL(NTSTATUS, RtlInitUTF8StringEx, (STR8 *, const char *));
UDECL(WCHAR, RtlAnsiCharToUnicodeChar, (UCHAR **));
UDECL(ULONG, RtlAnsiStringToUnicodeSize, (const STR8 *));
UDECL(NTSTATUS, RtlAppendAsciizToString, (STR8 *, const char *));
UDECL(LONG, RtlCompareUnicodeStrings, (const WCHAR *, SIZE_T, const WCHAR *, SIZE_T, BOOLEAN));
UDECL(PWSTR, RtlFindUnicodeSubstring, (const UNICODE_STRING *, const UNICODE_STRING *, BOOLEAN));
UDECL(LONG, RtlCompareAltitudes, (const UNICODE_STRING *, const UNICODE_STRING *));
UDECL(NTSTATUS, RtlConvertLCIDToString, (ULONG, ULONG, ULONG, PWSTR, ULONG));
UDECL(NTSTATUS, RtlFindClosestEncodableLength, (ULONGLONG, PULONGLONG));
UDECL(ULONG, RtlFindLeastSignificantBit, (ULONGLONG));
UDECL(ULONG, RtlFindMostSignificantBit, (ULONGLONG));
UDECL(BOOLEAN, RtlEqualWnfChangeStamps, (ULONG, ULONG));
UDECL(BOOLEAN, RtlEqualLuid, (const LUID *, const LUID *));
UDECL(VOID, RtlCopyLuid, (LUID *, const LUID *));
UDECL(VOID, RtlCopyLuidAndAttributesArray, (ULONG, const LUID_AND_ATTRIBUTES *, LUID_AND_ATTRIBUTES *));
UDECL(NTSTATUS, RtlCopySidAndAttributesArray, (ULONG, const SID_AND_ATTRIBUTES *, ULONG, SID_AND_ATTRIBUTES *, PSID, PSID *, PULONG));
UDECL(NTSTATUS, RtlAllocateAndInitializeSidEx, (PSID_IDENTIFIER_AUTHORITY, UCHAR, PULONG, PSID *));
UDECL(PVOID, RtlFreeSid, (PSID));
UDECL(NTSTATUS, RtlConvertSidToUnicodeString, (PUNICODE_STRING, PSID, BOOLEAN));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(PVOID, RtlFindAceByType, (PACL, UCHAR, PULONG));
UDECL(NTSTATUS, RtlCopySecurityDescriptor, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *));
UDECL(ULONG, RtlLengthSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(PVOID, RtlFreeHeap, (PVOID, ULONG, PVOID));
UDECL(VOID, RtlCopyMappedMemory, (PVOID, const VOID *, SIZE_T));
UDECL(VOID, RtlCopyMemory, (PVOID, const VOID *, SIZE_T));
UDECL(VOID, RtlCopyMemoryNonTemporal, (PVOID, const VOID *, SIZE_T));
UDECL(NTSTATUS, RtlFreeUTF8String, (STR8 *));

#define ST(x) ((NTSTATUS)(x))
#define SGN(x) ((x) < 0 ? -1 : (x) > 0)

TEST(rtl_net_ip_str_a_init_string) {
    REQUIRE(UN(RtlInitString));
    STR8 s; memset(&s, 0xcc, sizeof s);
    UN(RtlInitString)(&s, "abc");
    EXPECT_EQ(s.Length, 3); EXPECT_EQ(s.MaximumLength, 4); EXPECT_EQ(s.Buffer != NULL, 1);
    memset(&s, 0xcc, sizeof s);
    UN(RtlInitString)(&s, NULL);
    EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.MaximumLength, 0); EXPECT_EQ(s.Buffer, NULL);
    memset(&s, 0xcc, sizeof s);
    UN(RtlInitString)(&s, "");
    EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.MaximumLength, 1);
    /* very long string saturates */
    char *big = malloc(70001); memset(big, 'x', 70000); big[70000] = 0;
    UN(RtlInitString)(&s, big);
    EXPECT_EQ(s.Length, 0xfffe); EXPECT_EQ(s.MaximumLength, 0xffff);
    free(big);
}
static void ex_variant(NTSTATUS (WINAPI *f)(STR8 *, const char *)) {
    STR8 s; memset(&s, 0xcc, sizeof s);
    EXPECT_EQ(f(&s, "hello"), 0); EXPECT_EQ(s.Length, 5); EXPECT_EQ(s.MaximumLength, 6);
    memset(&s, 0xcc, sizeof s);
    EXPECT_EQ(f(&s, NULL), 0); EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.MaximumLength, 0); EXPECT_EQ(s.Buffer, NULL);
    char *big = malloc(70001); memset(big, 'x', 70000); big[70000] = 0;
    memset(&s, 0xcc, sizeof s);
    EXPECT_EQ(f(&s, big), ST(0xC0000106)); EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.MaximumLength, 0);
    big[0xffff] = 0;
    EXPECT_EQ(f(&s, big), ST(0xC0000106));   /* 0xffff chars rejected */
    big[0xffff] = 'x'; big[0xfffe] = 0;
    EXPECT_EQ(f(&s, big), 0); EXPECT_EQ(s.Length, 0xfffe); EXPECT_EQ(s.MaximumLength, 0xffff);
    free(big);
}
TEST(rtl_net_ip_str_a_init_string_ex) {
    REQUIRE(UN(RtlInitStringEx)); ex_variant(UN(RtlInitStringEx));
}
TEST(rtl_net_ip_str_a_init_ansi_ex) {
    REQUIRE(UN(RtlInitAnsiStringEx)); ex_variant(UN(RtlInitAnsiStringEx));
}
TEST(rtl_net_ip_str_a_init_utf8) {
    REQUIRE(UN(RtlInitUTF8String)); REQUIRE(UN(RtlInitUTF8StringEx));
    STR8 s; memset(&s, 0xcc, sizeof s);
    UN(RtlInitUTF8String)(&s, "caf\xc3\xa9");
    EXPECT_EQ(s.Length, 5); EXPECT_EQ(s.MaximumLength, 6);
    memset(&s, 0xcc, sizeof s);
    UN(RtlInitUTF8String)(&s, NULL);
    EXPECT_EQ(s.Length, 0); EXPECT_EQ(s.Buffer, NULL);
    ex_variant(UN(RtlInitUTF8StringEx));
}
TEST(rtl_net_ip_str_a_free_utf8_empty) {
    REQUIRE(UN(RtlFreeUTF8String));
    /* freeing a string with a NULL buffer is a no-op that leaves it zeroed */
    STR8 s = {0, 0, NULL};
    UN(RtlFreeUTF8String)(&s);
    EXPECT_EQ(s.Buffer, NULL); EXPECT_EQ(s.Length, 0);
}
TEST(rtl_net_ip_str_a_ansi_char) {
    REQUIRE(UN(RtlAnsiCharToUnicodeChar));
    UCHAR buf[] = "AZ"; UCHAR *p = buf;
    EXPECT_EQ(UN(RtlAnsiCharToUnicodeChar)(&p), 'A'); EXPECT_EQ(p, buf + 1);
    EXPECT_EQ(UN(RtlAnsiCharToUnicodeChar)(&p), 'Z'); EXPECT_EQ(p, buf + 2);
    UCHAR one[] = " "; p = one;
    EXPECT_EQ(UN(RtlAnsiCharToUnicodeChar)(&p), ' ');
}
TEST(rtl_net_ip_str_a_ansi_size) {
    REQUIRE(UN(RtlAnsiStringToUnicodeSize));
    REQUIRE(UN(RtlInitString));
    STR8 s; UN(RtlInitString)(&s, "hello");
    EXPECT_EQ(UN(RtlAnsiStringToUnicodeSize)(&s), 12);
    UN(RtlInitString)(&s, "");
    EXPECT_EQ(UN(RtlAnsiStringToUnicodeSize)(&s), 2);
    char ab[] = "abcdef"; s.Buffer = ab; s.Length = 3; s.MaximumLength = 7;
    EXPECT_EQ(UN(RtlAnsiStringToUnicodeSize)(&s), 8);   /* Length, not strlen, is used */
}
TEST(rtl_net_ip_str_a_append_asciiz) {
    REQUIRE(UN(RtlAppendAsciizToString));
    char buf[8]; memset(buf, 'Z', sizeof buf);
    STR8 s = {0, 8, buf};
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&s, "abc"), 0); EXPECT_EQ(s.Length, 3);
    EXPECT_EQ(memcmp(buf, "abcZ", 4), 0);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&s, "defgh"), 0); EXPECT_EQ(s.Length, 8);   /* exact fit, no NUL needed */
    EXPECT_EQ(memcmp(buf, "abcdefgh", 8), 0);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&s, "i"), ST(0xC0000023)); EXPECT_EQ(s.Length, 8);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&s, NULL), 0); EXPECT_EQ(s.Length, 8);
    EXPECT_EQ(UN(RtlAppendAsciizToString)(&s, ""), 0); EXPECT_EQ(s.Length, 8);
}
TEST(rtl_net_ip_str_a_compare_unicode_strings) {
    REQUIRE(UN(RtlCompareUnicodeStrings));
    const WCHAR a[] = L"abc", A[] = L"ABC", b[] = L"abd";
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 3, a, 3, FALSE), 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 3, A, 3, FALSE) > 0, 1);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(A, 3, a, 3, FALSE) < 0, 1);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 3, A, 3, TRUE), 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 3, b, 3, FALSE) < 0, 1);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(b, 3, a, 3, TRUE) > 0, 1);
    /* lengths are in characters; shorter prefix sorts first */
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 2, a, 3, FALSE), -1);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 3, a, 2, FALSE), 1);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 0, a, 0, FALSE), 0);
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(a, 0, a, 1, TRUE), -1);
    const WCHAR hi[] = {0xff21, 0}, lo[] = {0x41, 0};
    EXPECT_EQ(UN(RtlCompareUnicodeStrings)(hi, 1, lo, 1, FALSE) > 0, 1);   /* ordinal */
}
TEST(rtl_net_ip_str_a_find_substring) {
    REQUIRE(UN(RtlFindUnicodeSubstring));
    WCHAR full[] = L"Hello World", s1[] = L"World", s2[] = L"WORLD", s3[] = L"x", s4[] = L"Hello World!";
    UNICODE_STRING F = {22, 24, full}, S1 = {10, 12, s1}, S2 = {10, 12, s2}, S3 = {2, 4, s3}, S4 = {24, 26, s4};
    UNICODE_STRING E = {0, 2, s3};
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &S1, FALSE), full + 6);
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &S2, FALSE), NULL);
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &S2, TRUE), full + 6);
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &S3, TRUE), NULL);
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &S4, FALSE), NULL);   /* longer than haystack */
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&F, &E, FALSE), full);    /* empty needle matches at start */
    WCHAR rep[] = L"aXaXa", x[] = L"aX"; UNICODE_STRING R = {10, 12, rep}, X = {4, 6, x};
    EXPECT_EQ(UN(RtlFindUnicodeSubstring)(&R, &X, FALSE), rep);       /* first match */
}
TEST(rtl_net_ip_str_a_compare_altitudes) {
    REQUIRE(UN(RtlCompareAltitudes));
    UNICODE_STRING a, b; WCHAR a1[] = L"10000", b1[] = L"20000", a2[] = L"10000.5", a3[] = L"9999";
    a.Length = 10; a.MaximumLength = 12; a.Buffer = a1;
    b.Length = 10; b.MaximumLength = 12; b.Buffer = b1;
    EXPECT_EQ(UN(RtlCompareAltitudes)(&a, &a), 0);
    EXPECT_EQ(SGN(UN(RtlCompareAltitudes)(&a, &b)), -1);
    EXPECT_EQ(SGN(UN(RtlCompareAltitudes)(&b, &a)), 1);
    UNICODE_STRING c = {14, 16, a2}; EXPECT_EQ(SGN(UN(RtlCompareAltitudes)(&a, &c)), -1);
    UNICODE_STRING d = {8, 10, a3}; EXPECT_EQ(SGN(UN(RtlCompareAltitudes)(&d, &a)), -1);  /* numeric, not lexical */
}
TEST(rtl_net_ip_str_a_lcid_string) {
    REQUIRE(UN(RtlConvertLCIDToString));
    WCHAR buf[32];
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 4, buf, 32), 0); EXPECT_WSTR(buf, L"0409");
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 8, buf, 32), 0); EXPECT_WSTR(buf, L"00000409");
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 0, buf, 32), 0); EXPECT_WSTR(buf, L"409");
    EXPECT_EQ(UN(RtlConvertLCIDToString)(1033, 10, 0, buf, 32), 0); EXPECT_WSTR(buf, L"1033");
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 4, buf, 4), ST(0xC0000001));   /* no room for NUL */
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 4, buf, 5), 0);
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 16, 4, buf, 0x200), ST(0x80000005)); /* length cap 0x200 */
    EXPECT_EQ(UN(RtlConvertLCIDToString)(0x409, 3, 4, buf, 32) < 0, 1);                /* bad base */
}
TEST(rtl_net_ip_str_a_closest_encodable) {
    REQUIRE(UN(RtlFindClosestEncodableLength));
    ULONGLONG o;
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0, &o), 0); EXPECT_EQ(o, 0);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0xffffffffULL, &o), 0); EXPECT_EQ(o, 0xffffffffULL);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0x100000000ULL, &o), 0); EXPECT_EQ(o, 0x100000000ULL);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0x100000001ULL, &o), 0); EXPECT_EQ(o, 0x100000100ULL);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0xffffffff00ULL, &o), 0); EXPECT_EQ(o, 0xffffffff00ULL);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0xffffffff01ULL, &o), 0); EXPECT_EQ(o, 0x10000000000ULL);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0xffffffff00000001ULL, &o), ST(0xC0000001)); EXPECT_EQ(o, 0);
    EXPECT_EQ(UN(RtlFindClosestEncodableLength)(0xffffffff00000000ULL, &o), 0); EXPECT_EQ(o, 0xffffffff00000000ULL);
}
TEST(rtl_net_ip_str_a_msb_lsb) {
    REQUIRE(UN(RtlFindLeastSignificantBit)); REQUIRE(UN(RtlFindMostSignificantBit));
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(0), 0xff); EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(0), 0xff);
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(1), 0); EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(1), 0);
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(0x8000000000000000ULL), 63);
    EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(0x8000000000000000ULL), 63);
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(0x1010), 4); EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(0x1010), 12);
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(0x100000000ULL), 32);
    EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(0xffffffffULL), 31);
    EXPECT_EQ((UCHAR)UN(RtlFindLeastSignificantBit)(~0ULL), 0); EXPECT_EQ((UCHAR)UN(RtlFindMostSignificantBit)(~0ULL), 63);
}
TEST(rtl_net_ip_str_a_wnf_stamps) {
    REQUIRE(UN(RtlEqualWnfChangeStamps));
    EXPECT_EQ(UN(RtlEqualWnfChangeStamps)(5, 5) & 1, 1); EXPECT_EQ(UN(RtlEqualWnfChangeStamps)(5, 6) & 1, 0);
    EXPECT_EQ(UN(RtlEqualWnfChangeStamps)(0, 0) & 1, 1); EXPECT_EQ(UN(RtlEqualWnfChangeStamps)(0, 0x80000000u) & 1, 0);
}
TEST(rtl_net_ip_str_a_luid) {
    REQUIRE(UN(RtlEqualLuid)); REQUIRE(UN(RtlCopyLuid)); REQUIRE(UN(RtlCopyLuidAndAttributesArray));
    LUID a = {1, 2}, b = {1, 2}, c = {1, 3}, d = {4, 2}, z;
    EXPECT_EQ(UN(RtlEqualLuid)(&a, &b) & 1, 1); EXPECT_EQ(UN(RtlEqualLuid)(&a, &c) & 1, 0); EXPECT_EQ(UN(RtlEqualLuid)(&a, &d) & 1, 0);
    memset(&z, 0, sizeof z); UN(RtlCopyLuid)(&z, &c); EXPECT_EQ(z.LowPart, 1); EXPECT_EQ(z.HighPart, 3);
    LUID_AND_ATTRIBUTES src[3] = {{{1, 0}, 2}, {{3, 4}, 5}, {{6, 7}, 8}}, dst[4];
    memset(dst, 0x77, sizeof dst);
    UN(RtlCopyLuidAndAttributesArray)(2, src, dst);
    EXPECT_EQ(dst[0].Luid.LowPart, 1); EXPECT_EQ(dst[0].Attributes, 2);
    EXPECT_EQ(dst[1].Luid.LowPart, 3); EXPECT_EQ(dst[1].Luid.HighPart, 4); EXPECT_EQ(dst[1].Attributes, 5);
    EXPECT_EQ(dst[2].Attributes, 0x77777777);   /* only Count elements written */
    UN(RtlCopyLuidAndAttributesArray)(0, src, dst + 3);
    EXPECT_EQ(dst[3].Attributes, 0x77777777);
}
TEST(rtl_net_ip_str_a_sid_ex) {
    REQUIRE(UN(RtlAllocateAndInitializeSidEx)); REQUIRE(UN(RtlFreeSid)); REQUIRE(UN(RtlConvertSidToUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    SID_IDENTIFIER_AUTHORITY ia = {{0, 0, 0, 0, 0, 5}}; ULONG sub[15] = {21, 1, 2, 3, 500};
    PSID sid = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSidEx)(&ia, 5, sub, &sid), 0);
    if (sid) {
        SID *s = sid; EXPECT_EQ(s->Revision, 1); EXPECT_EQ(s->SubAuthorityCount, 5);
        EXPECT_EQ(s->IdentifierAuthority.Value[5], 5); EXPECT_EQ(s->SubAuthority[4], 500); EXPECT_EQ(s->SubAuthority[0], 21);
        UNICODE_STRING us; memset(&us, 0, sizeof us);
        EXPECT_EQ(UN(RtlConvertSidToUnicodeString)(&us, sid, TRUE), 0);
        EXPECT_WSTR(us.Buffer, L"S-1-5-21-1-2-3-500"); EXPECT_EQ(us.Length, 36);
        UN(RtlFreeUnicodeString)(&us);
        WCHAR small[8]; us.Buffer = small; us.Length = 0; us.MaximumLength = sizeof small;
        EXPECT_EQ(UN(RtlConvertSidToUnicodeString)(&us, sid, FALSE), ST(0x80000005));
        WCHAR fit[32]; us.Buffer = fit; us.MaximumLength = sizeof fit;
        EXPECT_EQ(UN(RtlConvertSidToUnicodeString)(&us, sid, FALSE), 0); EXPECT_WSTR(fit, L"S-1-5-21-1-2-3-500");
        UN(RtlFreeSid)(sid);
    }
    sid = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSidEx)(&ia, 0, sub, &sid), 0);
    if (sid) { EXPECT_EQ(((SID *)sid)->SubAuthorityCount, 0); UN(RtlFreeSid)(sid); }
    sid = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSidEx)(&ia, 15, sub, &sid), 0);
    if (sid) { EXPECT_EQ(((SID *)sid)->SubAuthorityCount, 15); UN(RtlFreeSid)(sid); }
    sid = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSidEx)(&ia, 16, sub, &sid), ST(0xC000000D)); EXPECT_EQ(sid, NULL);
}
TEST(rtl_net_ip_str_a_sid_attr_array) {
    REQUIRE(UN(RtlCopySidAndAttributesArray)); REQUIRE(UN(RtlAllocateAndInitializeSidEx)); REQUIRE(UN(RtlFreeSid));
    SID_IDENTIFIER_AUTHORITY ia = {{0, 0, 0, 0, 0, 5}}; ULONG s1[2] = {32, 544}, s2[1] = {18};
    PSID p1 = NULL, p2 = NULL;
    UN(RtlAllocateAndInitializeSidEx)(&ia, 2, s1, &p1); UN(RtlAllocateAndInitializeSidEx)(&ia, 1, s2, &p2);
    if (!p1 || !p2) { t_skip("sid allocation failed"); return; }
    SID_AND_ATTRIBUTES src[2] = {{p1, 7}, {p2, 9}}, dst[2]; BYTE area[64]; memset(area, 0, sizeof area);
    PSID rem = NULL; ULONG remsz = 0;
    memset(dst, 0, sizeof dst);
    EXPECT_EQ(UN(RtlCopySidAndAttributesArray)(2, src, 64, dst, area, &rem, &remsz), 0);
    EXPECT_EQ(dst[0].Sid, area); EXPECT_EQ(dst[0].Attributes, 7);
    EXPECT_EQ(dst[1].Sid, area + 16); EXPECT_EQ(dst[1].Attributes, 9);
    EXPECT_EQ(rem, area + 28); EXPECT_EQ(remsz, 64 - 28);
    EXPECT_EQ(memcmp(dst[0].Sid, p1, 16), 0); EXPECT_EQ(memcmp(dst[1].Sid, p2, 12), 0);
    /* second SID does not fit */
    EXPECT_EQ(UN(RtlCopySidAndAttributesArray)(2, src, 27, dst, area, &rem, &remsz), ST(0xC0000023));
    EXPECT_EQ(UN(RtlCopySidAndAttributesArray)(2, src, 28, dst, area, &rem, &remsz), 0); EXPECT_EQ(remsz, 0);
    EXPECT_EQ(UN(RtlCopySidAndAttributesArray)(0, src, 5, dst, area, &rem, &remsz), 0); EXPECT_EQ(rem, area); EXPECT_EQ(remsz, 5);
    UN(RtlFreeSid)(p1); UN(RtlFreeSid)(p2);
}
TEST(rtl_net_ip_str_a_find_ace) {
    REQUIRE(UN(RtlFindAceByType));
    /* ACL with three ACEs: ALLOWED(0), DENIED(1), ALLOWED(0). SID S-1-1-0 (12 bytes) => ACE size 16 */
    BYTE buf[8 + 3 * 16]; memset(buf, 0, sizeof buf);
    ACL *acl = (ACL *)buf; acl->AclRevision = 2; acl->AclSize = sizeof buf; acl->AceCount = 3;
    static const UCHAR types[3] = {0, 1, 0};
    for (int i = 0; i < 3; i++) { BYTE *a = buf + 8 + i * 16; a[0] = types[i]; a[2] = 16; a[4 + 4] = 1; a[4 + 5] = 0; }
    EXPECT_EQ(UN(RtlFindAceByType)(acl, 0, NULL), buf + 8);
    EXPECT_EQ(UN(RtlFindAceByType)(acl, 1, NULL), buf + 24);
    EXPECT_EQ(UN(RtlFindAceByType)(acl, 2, NULL), NULL);
    ULONG idx = 0; EXPECT_EQ(UN(RtlFindAceByType)(acl, 0, &idx), buf + 8); EXPECT_EQ(idx, 0);
    idx = 1; EXPECT_EQ(UN(RtlFindAceByType)(acl, 0, &idx), buf + 40); EXPECT_EQ(idx, 2);   /* start index honoured */
    idx = 1; EXPECT_EQ(UN(RtlFindAceByType)(acl, 1, &idx), buf + 24); EXPECT_EQ(idx, 1);
    idx = 3; EXPECT_EQ(UN(RtlFindAceByType)(acl, 0, &idx), NULL);
    EXPECT_EQ(UN(RtlFindAceByType)(NULL, 0, NULL), NULL);
    acl->AceCount = 0; EXPECT_EQ(UN(RtlFindAceByType)(acl, 0, NULL), NULL);
}
TEST(rtl_net_ip_str_a_copy_sd) {
    REQUIRE(UN(RtlCopySecurityDescriptor)); REQUIRE(UN(RtlLengthSecurityDescriptor)); REQUIRE(UN(RtlFreeHeap));
    SECURITY_DESCRIPTOR sd; memset(&sd, 0, sizeof sd);
    sd.Revision = 1; /* absolute-style but without owner/group/dacl/sacl */
    PSECURITY_DESCRIPTOR out = NULL;
    NTSTATUS s = UN(RtlCopySecurityDescriptor)(&sd, &out);
    EXPECT_EQ(s, 0);
    if (s == 0 && out) { EXPECT_EQ(((SECURITY_DESCRIPTOR *)out)->Revision, 1); EXPECT_EQ(memcmp(out, &sd, 20), 0);
        UN(RtlFreeHeap)(GetProcessHeap(), 0, out); }
}
TEST(rtl_net_ip_str_a_copy_memory) {
    REQUIRE(UN(RtlCopyMemory)); REQUIRE(UN(RtlCopyMappedMemory)); REQUIRE(UN(RtlCopyMemoryNonTemporal));
    BYTE src[300], dst[320];
    for (int i = 0; i < 300; i++) src[i] = (BYTE)(i * 7 + 1);
    static const char *names[3] = {"RtlCopyMemory", "RtlCopyMappedMemory", "RtlCopyMemoryNonTemporal"};
    for (int k = 0; k < 3; k++) {
        VOID (WINAPI *f)(PVOID, const VOID *, SIZE_T) = (void *)t_proc(names[k]);
        memset(dst, 0xaa, sizeof dst);
        f(dst + 3, src, 300);
        CHECKF(memcmp(dst + 3, src, 300) == 0, "%s copy", names[k]);
        CHECKF(dst[2] == 0xaa && dst[303] == 0xaa, "%s no overrun", names[k]);
        memset(dst, 0xaa, sizeof dst); f(dst, src, 0);
        CHECKF(dst[0] == 0xaa, "%s zero length", names[k]);
        memset(dst, 0xaa, sizeof dst); f(dst, src, 1);
        CHECKF(dst[0] == src[0] && dst[1] == 0xaa, "%s one byte", names[k]);
    }
}
