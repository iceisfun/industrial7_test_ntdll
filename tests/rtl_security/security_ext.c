/* Security Rtl: ACL and ACE editing, SID formatting, access-mask helpers,
 * security descriptor format conversion. Pure in-memory; nothing touches the system. */
#include "t.h"

UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAce, (PACL, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlDeleteAce, (PACL, ULONG));
UDECL(NTSTATUS, RtlGetAce, (PACL, ULONG, PVOID *));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessAllowedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAuditAccessAce, (PACL, ULONG, ACCESS_MASK, PSID, BOOLEAN, BOOLEAN));
UDECL(BOOLEAN, RtlValidAcl, (PACL));
UDECL(BOOLEAN, RtlFirstFreeAce, (PACL, PVOID *));
UDECL(NTSTATUS, RtlQueryInformationAcl, (PACL, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlSetInformationAcl, (PACL, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlConvertSidToUnicodeString, (PUNICODE_STRING, PSID, BOOLEAN));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(BOOLEAN, RtlAreAllAccessesGranted, (ACCESS_MASK, ACCESS_MASK));
UDECL(BOOLEAN, RtlAreAnyAccessesGranted, (ACCESS_MASK, ACCESS_MASK));
UDECL(VOID, RtlMapGenericMask, (PACCESS_MASK, const GENERIC_MAPPING *));
UDECL(VOID, RtlCopyLuid, (PLUID, const LUID *));
UDECL(NTSTATUS, RtlCreateServiceSid, (PUNICODE_STRING, PSID, PULONG));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(ULONG, RtlLengthSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(NTSTATUS, RtlAbsoluteToSelfRelativeSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG));
UDECL(NTSTATUS, RtlSelfRelativeToAbsoluteSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG, PACL, PULONG, PACL, PULONG, PSID, PULONG, PSID, PULONG));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
typedef struct { BYTE rev, count; BYTE auth[6]; ULONG sub[8]; } xs_sid;
typedef struct { BYTE type, flags; WORD size; ULONG mask; } xs_ace;
static const xs_sid xs_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const xs_sid xs_system   = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const xs_sid xs_admins   = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };
static const xs_sid xs_domain   = { 1, 5, { 0, 0, 0, 0, 0, 5 }, { 21, 1, 2, 3, 1001 } };
#define SID_LEN(s) (8 + 4 * (s).count)

static ULONG xs_ace_count(ACL *a) { return ((WORD *)a)[2]; }
#define XS_NEED() do { REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAce)); REQUIRE(UN(RtlGetAce)); REQUIRE(UN(RtlAddAccessAllowedAceEx)); } while (0)

TEST(rtl_security_x_create_acl_validation)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ACL *acl = (ACL *)buf.b; XS_NEED();
    memset(&buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 2), 0);
    EXPECT_EQ(acl->AclRevision, 2); EXPECT_EQ(acl->AclSize, 256); EXPECT_EQ(acl->AceCount, 0);
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 4), 0);
    EXPECT_EQ(acl->AclRevision, 4);
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 4, 2), XS(0xC0000023));     /* smaller than the header */
    { static const ULONG bad[] = { 0, 1, 5 };
      for (int i = 0; i < 3; i++) { NTSTATUS s = UN(RtlCreateAcl)(acl, 256, bad[i]); CHECKF(!XOK(s), "revision %lu accepted", bad[i]); t_note("RtlCreateAcl revision %lu status=%08lx", bad[i], s); } }
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 8, 2), 0);                  /* header only is allowed */
    { NTSTATUS s = UN(RtlCreateAcl)(acl, 0x10000, 2); CHECK(!XOK(s)); t_note("RtlCreateAcl oversize status=%08lx", s); }
}
TEST(rtl_security_x_valid_acl)
{
    union { ULONGLONG a; BYTE b[128]; } buf; ACL *acl = (ACL *)buf.b; XS_NEED(); REQUIRE(UN(RtlValidAcl));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 128, 2), 0);
    EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x1f, (PSID)&xs_system), 0);
    EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
    acl->AclRevision = 0; EXPECT_EQ(UN(RtlValidAcl)(acl), FALSE);   /* revisions 2 to 4 are valid */
    acl->AclRevision = 1; EXPECT_EQ(UN(RtlValidAcl)(acl), FALSE);
    acl->AclRevision = 3; EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
    acl->AclRevision = 4; EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
    acl->AclRevision = 5; EXPECT_EQ(UN(RtlValidAcl)(acl), FALSE);
    acl->AclRevision = 2;
    acl->AclSize = 10; EXPECT_EQ(UN(RtlValidAcl)(acl), FALSE);   /* too small for its own ACE */
    acl->AclSize = 128;
    acl->AclSize = 130; EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);   /* a size that is not a multiple of four is not rejected */
    acl->AclSize = 128;
    memset(buf.b + 28, 0xff, sizeof buf.b - 28);                 /* what follows the one ACE claims a size beyond the ACL */
    acl->AceCount = 5; EXPECT_EQ(UN(RtlValidAcl)(acl), FALSE);   /* more ACEs than the space holds */
}
TEST(rtl_security_x_add_ace_ex_flags_and_size)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ACL *acl = (ACL *)buf.b; xs_ace *ace = NULL; XS_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0x03 /* OBJECT|CONTAINER inherit */, 0x120089, (PSID)&xs_domain), 0);
    EXPECT_EQ(xs_ace_count(acl), 1);
    EXPECT_EQ(UN(RtlGetAce)(acl, 0, (PVOID *)&ace), 0);
    if (ace) {
        EXPECT_EQ(ace->type, 0); EXPECT_EQ(ace->flags, 3); EXPECT_EQ(ace->mask, 0x120089);
        EXPECT_EQ(ace->size, 8 + SID_LEN(xs_domain));
        CHECK(!memcmp((BYTE *)ace + 8, &xs_domain, SID_LEN(xs_domain)));
    }
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_everyone), 0);
    EXPECT_EQ(xs_ace_count(acl), 2);
    EXPECT_EQ(UN(RtlGetAce)(acl, 1, (PVOID *)&ace), 0);
    if (ace) { EXPECT_EQ(ace->flags, 0); EXPECT_EQ(ace->size, 8 + SID_LEN(xs_everyone)); }
}
TEST(rtl_security_x_add_ace_denied_and_audit_types)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ACL *acl = (ACL *)buf.b; xs_ace *ace = NULL; XS_NEED(); REQUIRE(UN(RtlAddAccessDeniedAceEx)); REQUIRE(UN(RtlAddAuditAccessAce));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(acl, 2, 0x10 /* INHERIT_ONLY */, 2, (PSID)&xs_admins), 0);
    EXPECT_EQ(UN(RtlGetAce)(acl, 0, (PVOID *)&ace), 0);
    if (ace) { EXPECT_EQ(ace->type, 1); EXPECT_EQ(ace->flags, 0x10); EXPECT_EQ(ace->mask, 2); }
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 4, (PSID)&xs_system, TRUE, FALSE), 0);
    EXPECT_EQ(UN(RtlGetAce)(acl, 1, (PVOID *)&ace), 0);
    if (ace) { EXPECT_EQ(ace->type, 2); EXPECT_EQ(ace->flags, 0x40); EXPECT_EQ(ace->mask, 4); }
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 4, (PSID)&xs_system, FALSE, TRUE), 0);
    EXPECT_EQ(UN(RtlGetAce)(acl, 2, (PVOID *)&ace), 0);
    if (ace) EXPECT_EQ(ace->flags, 0x80);
}
TEST(rtl_security_x_add_ace_out_of_space)
{
    union { ULONGLONG a; BYTE b[64]; } buf; ACL *acl = (ACL *)buf.b; XS_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 8 + 8 + SID_LEN(xs_system), 2), 0);   /* room for exactly one ACE */
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system), 0);
    { NTSTATUS s = UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system);
      CHECKF(s == XS(0xC0000023) || s == XS(0xC0000099), "no-space status=%08lx", s); t_note("no-space status=%08lx", s); }
    EXPECT_EQ(xs_ace_count(acl), 1);
}
TEST(rtl_security_x_add_ace_invalid_revision)
{
    union { ULONGLONG a; BYTE b[128]; } buf; ACL *acl = (ACL *)buf.b; XS_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 128, 2), 0);
    { NTSTATUS s = UN(RtlAddAccessAllowedAceEx)(acl, 5, 0, 1, (PSID)&xs_system); CHECK(!XOK(s)); t_note("ace revision 5 status=%08lx", s); }
    EXPECT_EQ(xs_ace_count(acl), 0);
    { NTSTATUS s = UN(RtlAddAccessAllowedAceEx)(acl, 0, 0, 1, (PSID)&xs_system); EXPECT_EQ(s, 0); }   /* an ACE revision below the ACL revision is accepted */
    EXPECT_EQ(xs_ace_count(acl), 1);
}
TEST(rtl_security_x_add_ace_raw_list_and_index)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ACL *acl = (ACL *)buf.b; BYTE raw[2][24]; xs_ace *a0, *a1, *got = NULL; XS_NEED();
    memset(raw, 0, sizeof raw);
    a0 = (xs_ace *)raw[0]; a0->type = 0; a0->size = 8 + SID_LEN(xs_system); a0->mask = 0x11; memcpy(raw[0] + 8, &xs_system, SID_LEN(xs_system));
    a1 = (xs_ace *)raw[1]; a1->type = 1; a1->size = 8 + SID_LEN(xs_system); a1->mask = 0x22; memcpy(raw[1] + 8, &xs_system, SID_LEN(xs_system));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 2), 0);
    EXPECT_EQ(UN(RtlAddAce)(acl, 2, 0xFFFFFFFF, a0, a0->size), 0);          /* append */
    EXPECT_EQ(UN(RtlAddAce)(acl, 2, 0, a1, a1->size), 0);                   /* insert first */
    EXPECT_EQ(xs_ace_count(acl), 2);
    EXPECT_EQ(UN(RtlGetAce)(acl, 0, (PVOID *)&got), 0); if (got) EXPECT_EQ(got->mask, 0x22);
    EXPECT_EQ(UN(RtlGetAce)(acl, 1, (PVOID *)&got), 0); if (got) EXPECT_EQ(got->mask, 0x11);
    { NTSTATUS s = UN(RtlAddAce)(acl, 2, 3, a0, a0->size); t_note("index beyond the count status=%08lx", s);   /* unspecified: observe only */
      if (XOK(s)) UN(RtlDeleteAce)(acl, xs_ace_count(acl) - 1); }
    EXPECT_EQ(xs_ace_count(acl), 2);
    { BYTE both[48]; memcpy(both, raw[0], a0->size); memcpy(both + a0->size, raw[1], a1->size);
      EXPECT_EQ(UN(RtlAddAce)(acl, 2, 1, both, a0->size + a1->size), 0);    /* a list inserts all its ACEs */
      EXPECT_EQ(xs_ace_count(acl), 4);
      EXPECT_EQ(UN(RtlGetAce)(acl, 1, (PVOID *)&got), 0); if (got) EXPECT_EQ(got->mask, 0x11);
      EXPECT_EQ(UN(RtlGetAce)(acl, 2, (PVOID *)&got), 0); if (got) EXPECT_EQ(got->mask, 0x22); }
}
TEST(rtl_security_x_get_and_delete_ace_bounds)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ACL *acl = (ACL *)buf.b; xs_ace *ace = NULL; XS_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 256, 2), 0);
    EXPECT_EQ(UN(RtlGetAce)(acl, 0, (PVOID *)&ace), XS(0xC000000D));         /* empty ACL */
    EXPECT_EQ(UN(RtlDeleteAce)(acl, 0), XS(0xC000000D));
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 2, (PSID)&xs_admins);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 4, (PSID)&xs_everyone);
    EXPECT_EQ(UN(RtlGetAce)(acl, 3, (PVOID *)&ace), XS(0xC000000D));
    EXPECT_EQ(UN(RtlDeleteAce)(acl, 3), XS(0xC000000D));
    EXPECT_EQ(UN(RtlDeleteAce)(acl, 1), 0);
    EXPECT_EQ(xs_ace_count(acl), 2);
    EXPECT_EQ(UN(RtlGetAce)(acl, 1, (PVOID *)&ace), 0); if (ace) EXPECT_EQ(ace->mask, 4);   /* later ACEs move down */
    EXPECT_EQ(UN(RtlDeleteAce)(acl, 0), 0);
    EXPECT_EQ(UN(RtlDeleteAce)(acl, 0), 0);
    EXPECT_EQ(xs_ace_count(acl), 0);
    if (UN(RtlValidAcl)) EXPECT_EQ(UN(RtlValidAcl)(acl), TRUE);
}
TEST(rtl_security_x_first_free_ace)
{
    union { ULONGLONG a; BYTE b[64]; } buf; ACL *acl = (ACL *)buf.b; PVOID free_ace = (PVOID)1; BOOLEAN r; XS_NEED(); REQUIRE(UN(RtlFirstFreeAce));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 64, 2), 0);
    r = UN(RtlFirstFreeAce)(acl, &free_ace);
    EXPECT_EQ(r, TRUE); EXPECT_EQ((BYTE *)free_ace, (BYTE *)acl + 8);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system);
    r = UN(RtlFirstFreeAce)(acl, &free_ace);
    EXPECT_EQ(r, TRUE); EXPECT_EQ((BYTE *)free_ace, (BYTE *)acl + 8 + 8 + SID_LEN(xs_system));
    /* fill the ACL exactly: no free space remains */
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 8 + 8 + SID_LEN(xs_system), 2), 0);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system);
    free_ace = (PVOID)1;
    r = UN(RtlFirstFreeAce)(acl, &free_ace);
    /* a full ACL reports the address just past the last ACE (the end of the ACL), not NULL */
    EXPECT_EQ(r, TRUE); EXPECT_EQ((BYTE *)free_ace, (BYTE *)acl + 8 + 8 + SID_LEN(xs_system));
}
TEST(rtl_security_x_acl_information_classes)
{
    union { ULONGLONG a; BYTE b[128]; } buf; ACL *acl = (ACL *)buf.b; ULONG info[3]; NTSTATUS s; XS_NEED(); REQUIRE(UN(RtlQueryInformationAcl)); REQUIRE(UN(RtlSetInformationAcl));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 128, 2), 0);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, (PSID)&xs_system);
    memset(info, 0xcc, sizeof info);
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, info, sizeof info, 2 /* AclSizeInformation */), 0);
    EXPECT_EQ(info[0], 1);                                   /* AceCount */
    EXPECT_EQ(info[1], 8 + 8 + SID_LEN(xs_system));          /* AclBytesInUse */
    EXPECT_EQ(info[2], 128 - info[1]);                       /* AclBytesFree */
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, info, 8, 2), XS(0xC0000023));
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, info, 4, 1 /* AclRevisionInformation */), 0);
    EXPECT_EQ(info[0], 2);
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, info, 2, 1), XS(0xC0000023));
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, info, sizeof info, 7), XS(0xC0000003));
    info[0] = 4;
    s = UN(RtlSetInformationAcl)(acl, info, 4, 1);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(acl->AclRevision, 4); }
    info[0] = 2;
    s = UN(RtlSetInformationAcl)(acl, info, 4, 1);
    CHECK(!XOK(s) || acl->AclRevision >= 2); t_note("lower revision status=%08lx", s);
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, info, 2, 1), XS(0xC0000023));
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, info, 4, 2), XS(0xC0000003));   /* size information is read-only */
}

/* ---- SIDs --------------------------------------------------------------- */
static void xs_sid_text(const xs_sid *sid, const WCHAR *want)
{
    UNICODE_STRING u; NTSTATUS s;
    memset(&u, 0, sizeof u);
    s = UN(RtlConvertSidToUnicodeString)(&u, (PSID)sid, TRUE);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(u.Buffer != NULL); EXPECT_EQ(u.Length, lstrlenW(want) * 2); CHECK(u.MaximumLength >= u.Length);
        CHECK(u.Buffer && !memcmp(u.Buffer, want, u.Length));
        UN(RtlFreeUnicodeString)(&u);
    }
}
TEST(rtl_security_x_sid_to_string_formats)
{
    REQUIRE(UN(RtlConvertSidToUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    xs_sid_text(&xs_everyone, L"S-1-1-0");
    xs_sid_text(&xs_system, L"S-1-5-18");
    xs_sid_text(&xs_admins, L"S-1-5-32-544");
    xs_sid_text(&xs_domain, L"S-1-5-21-1-2-3-1001");
    { xs_sid big = { 1, 1, { 0, 0, 1, 0, 0, 0 }, { 7 } }; UNICODE_STRING u; memset(&u, 0, sizeof u);
      if (XOK(UN(RtlConvertSidToUnicodeString)(&u, (PSID)&big, TRUE))) { t_note("authority above 32 bits formats as %.*ls", u.Length / 2, u.Buffer); UN(RtlFreeUnicodeString)(&u); } }
    { xs_sid none = { 1, 0, { 0, 0, 0, 0, 0, 5 }, { 0 } }; xs_sid_text(&none, L"S-1-5"); }
}
TEST(rtl_security_x_sid_to_string_caller_buffer)
{
    UNICODE_STRING u; WCHAR small[4], big[64]; NTSTATUS s; REQUIRE(UN(RtlConvertSidToUnicodeString));
    u.Buffer = big; u.Length = 0; u.MaximumLength = sizeof big;
    s = UN(RtlConvertSidToUnicodeString)(&u, (PSID)&xs_system, FALSE);
    EXPECT_EQ(s, 0); EXPECT_EQ(u.Length, 16); CHECK(!memcmp(big, L"S-1-5-18", 16)); EXPECT_EQ(u.Buffer, big);
    u.Buffer = small; u.Length = 0; u.MaximumLength = sizeof small;
    s = UN(RtlConvertSidToUnicodeString)(&u, (PSID)&xs_system, FALSE);
    EXPECT_EQ(s, XS(0x80000005));
    u.MaximumLength = 16;
    u.Buffer = big;
    s = UN(RtlConvertSidToUnicodeString)(&u, (PSID)&xs_system, FALSE);
    CHECK(s == 0 || s == XS(0x80000005)); t_note("exact-length buffer status=%08lx (terminator needs 18 bytes)", s);
}
TEST(rtl_security_x_sid_to_string_invalid)
{
    UNICODE_STRING u; xs_sid bad = { 2, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } }; xs_sid many = { 1, 16, { 0, 0, 0, 0, 0, 5 }, { 0 } }; WCHAR buf[64]; REQUIRE(UN(RtlConvertSidToUnicodeString));
    u.Buffer = buf; u.Length = 0; u.MaximumLength = sizeof buf;
    EXPECT_EQ(UN(RtlConvertSidToUnicodeString)(&u, (PSID)&bad, FALSE), XS(0xC0000078));
    EXPECT_EQ(UN(RtlConvertSidToUnicodeString)(&u, (PSID)&many, FALSE), XS(0xC0000078));
}
TEST(rtl_security_x_create_service_sid)
{
    UNICODE_STRING a, b, c; xs_sid s1, s2, s3; ULONG len; NTSTATUS s; REQUIRE(UN(RtlCreateServiceSid));
    a.Buffer = L"MyService"; a.Length = a.MaximumLength = 18;
    b.Buffer = L"MYSERVICE"; b.Length = b.MaximumLength = 18;
    c.Buffer = L"OtherService"; c.Length = c.MaximumLength = 24;
    len = 0;
    s = UN(RtlCreateServiceSid)(&a, NULL, &len);
    EXPECT_EQ(s, XS(0xC0000023)); EXPECT_EQ(len, 32);
    len = sizeof s1; memset(&s1, 0, sizeof s1);
    s = UN(RtlCreateServiceSid)(&a, &s1, &len);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(len, 32); EXPECT_EQ(s1.rev, 1); EXPECT_EQ(s1.count, 6);
        EXPECT_EQ(s1.auth[5], 5); EXPECT_EQ(s1.sub[0], 80);
        len = sizeof s2; UN(RtlCreateServiceSid)(&b, &s2, &len);
        CHECK(!memcmp(&s1, &s2, 32));                         /* service names are case-insensitive */
        len = sizeof s3; UN(RtlCreateServiceSid)(&c, &s3, &len);
        CHECK(memcmp(&s1, &s3, 32) != 0);
    }
    len = 16;
    EXPECT_EQ(UN(RtlCreateServiceSid)(&a, &s1, &len), XS(0xC0000023));
    EXPECT_EQ(len, 32);
}

/* ---- access masks -------------------------------------------------------- */
TEST(rtl_security_x_access_granted_predicates)
{
    REQUIRE(UN(RtlAreAllAccessesGranted)); REQUIRE(UN(RtlAreAnyAccessesGranted));
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x7, 0x5), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x5, 0x7), FALSE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0, 0), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0x1, 0), TRUE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0, 1), FALSE);
    EXPECT_EQ(UN(RtlAreAllAccessesGranted)(0xFFFFFFFF, 0x80000000), TRUE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x5, 0x2), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x5, 0x6), TRUE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0, 0), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0xFFFFFFFF, 0), FALSE);
    EXPECT_EQ(UN(RtlAreAnyAccessesGranted)(0x10000, 0x10001), TRUE);
}
TEST(rtl_security_x_map_generic_mask)
{
    GENERIC_MAPPING m = { 0x1, 0x2, 0x4, 0x8 };
    static const struct { ACCESS_MASK in, out; } cases[] = {
        { GENERIC_READ, 0x1 }, { GENERIC_WRITE, 0x2 }, { GENERIC_EXECUTE, 0x4 }, { GENERIC_ALL, 0x8 },
        { GENERIC_READ | GENERIC_WRITE, 0x3 }, { GENERIC_READ | 0x100, 0x101 }, { 0x100, 0x100 }, { 0, 0 },
        { GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_ALL, 0xf },
        { ACCESS_SYSTEM_SECURITY | GENERIC_READ, ACCESS_SYSTEM_SECURITY | 0x1 },
        { MAXIMUM_ALLOWED, MAXIMUM_ALLOWED },
    };
    REQUIRE(UN(RtlMapGenericMask));
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ACCESS_MASK v = cases[i].in;
        UN(RtlMapGenericMask)(&v, &m);
        CHECKF(v == cases[i].out, "case %u in=%08lx got=%08lx want=%08lx", (unsigned)i, cases[i].in, v, cases[i].out);
    }
    { ACCESS_MASK v = GENERIC_READ; GENERIC_MAPPING z = { 0, 0, 0, 0 }; UN(RtlMapGenericMask)(&v, &z); EXPECT_EQ(v, 0); }
}
TEST(rtl_security_x_copy_luid)
{
    LUID src = { 0x12345678, 0x7abcdef0 }, dst = { 1, 2 };
    REQUIRE(UN(RtlCopyLuid));
    UN(RtlCopyLuid)(&dst, &src);
    EXPECT_EQ(dst.LowPart, 0x12345678); EXPECT_EQ(dst.HighPart, 0x7abcdef0);
}

/* ---- descriptor format conversion ---------------------------------------- */
typedef struct { BYTE rev, sbz1; WORD control; ULONG owner, group, sacl, dacl; } xs_rel_sd;
static BOOL xs_build_sd(SECURITY_DESCRIPTOR *sd, ACL *acl)
{
    if (!XOK(UN(RtlCreateSecurityDescriptor)(sd, 1))) return FALSE;
    if (!XOK(UN(RtlSetOwnerSecurityDescriptor)(sd, (PSID)&xs_admins, FALSE))) return FALSE;
    if (!XOK(UN(RtlSetGroupSecurityDescriptor)(sd, (PSID)&xs_system, FALSE))) return FALSE;
    if (!XOK(UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, acl, FALSE))) return FALSE;
    return TRUE;
}
#define XS_SD_NEED() do { XS_NEED(); REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor)); REQUIRE(UN(RtlSetGroupSecurityDescriptor)); \
    REQUIRE(UN(RtlSetDaclSecurityDescriptor)); REQUIRE(UN(RtlAbsoluteToSelfRelativeSD)); REQUIRE(UN(RtlSelfRelativeToAbsoluteSD)); REQUIRE(UN(RtlValidSecurityDescriptor)); REQUIRE(UN(RtlLengthSecurityDescriptor)); } while (0)
TEST(rtl_security_x_absolute_to_self_relative)
{
    union { ULONGLONG a; BYTE b[128]; } abuf; ACL *acl = (ACL *)abuf.b; SECURITY_DESCRIPTOR sd; union { ULONGLONG a; BYTE b[512]; } rel; ULONG need = 0; NTSTATUS s; XS_SD_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 128, 2), 0);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x1f, (PSID)&xs_everyone);
    CHECK(xs_build_sd(&sd, acl));
    s = UN(RtlAbsoluteToSelfRelativeSD)(&sd, NULL, &need);
    EXPECT_EQ(s, XS(0xC0000023));
    CHECK(need >= sizeof(xs_rel_sd) + SID_LEN(xs_admins) + SID_LEN(xs_system) + 8 + 8 + SID_LEN(xs_everyone));
    CHECK(need <= sizeof rel.b);
    if (need <= sizeof rel.b) {
        ULONG len = need;
        memset(&rel, 0xcc, sizeof rel);
        s = UN(RtlAbsoluteToSelfRelativeSD)(&sd, &rel, &len);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            xs_rel_sd *r = (xs_rel_sd *)rel.b;
            EXPECT_EQ(r->rev, 1); CHECK(r->control & 0x8000); CHECK(r->control & 0x0004);
            CHECK(r->owner != 0 && r->group != 0 && r->dacl != 0 && r->sacl == 0);
            CHECK(r->owner < need && r->group < need && r->dacl < need);
            CHECK(!memcmp(rel.b + r->owner, &xs_admins, SID_LEN(xs_admins)));
            CHECK(!memcmp(rel.b + r->group, &xs_system, SID_LEN(xs_system)));
            EXPECT_EQ(UN(RtlValidSecurityDescriptor)(&rel), TRUE);
            EXPECT_EQ(UN(RtlLengthSecurityDescriptor)(&rel), need);
            /* converting a relative descriptor to relative again is refused */
            { union { ULONGLONG a; BYTE b[512]; } again; len = sizeof again;
              s = UN(RtlAbsoluteToSelfRelativeSD)(&rel, &again, &len);
              EXPECT_EQ(s, XS(0xC00000E7)); }
        }
    }
}
TEST(rtl_security_x_self_relative_to_absolute)
{
    union { ULONGLONG a; BYTE b[128]; } abuf; ACL *acl = (ACL *)abuf.b; SECURITY_DESCRIPTOR sd, out; union { ULONGLONG a; BYTE b[512]; } rel;
    union { ULONGLONG a; BYTE b[128]; } dacl; BYTE owner[40], group[40]; ULONG need = 0, len, abs_size, dacl_size, sacl_size, owner_size, group_size; NTSTATUS s; XS_SD_NEED();
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 128, 2), 0);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x1f, (PSID)&xs_everyone);
    CHECK(xs_build_sd(&sd, acl));
    UN(RtlAbsoluteToSelfRelativeSD)(&sd, NULL, &need);
    len = need;
    if (!XOK(UN(RtlAbsoluteToSelfRelativeSD)(&sd, &rel, &len))) { t_skip("could not build relative descriptor"); return; }
    abs_size = dacl_size = sacl_size = owner_size = group_size = 0;
    s = UN(RtlSelfRelativeToAbsoluteSD)(&rel, NULL, &abs_size, NULL, &dacl_size, NULL, &sacl_size, NULL, &owner_size, NULL, &group_size);
    EXPECT_EQ(s, XS(0xC0000023));
    CHECK(abs_size >= sizeof(SECURITY_DESCRIPTOR)); EXPECT_EQ(owner_size, SID_LEN(xs_admins)); EXPECT_EQ(group_size, SID_LEN(xs_system));
    CHECK(dacl_size >= 8 + 8 + SID_LEN(xs_everyone));
    t_note("sizes abs=%lu dacl=%lu sacl=%lu owner=%lu group=%lu", abs_size, dacl_size, sacl_size, owner_size, group_size);
    if (abs_size <= sizeof out && dacl_size <= sizeof dacl.b && owner_size <= sizeof owner && group_size <= sizeof group) {
        BOOLEAN present = FALSE, defaulted = TRUE; ACL *got = NULL; PSID so = NULL;
        s = UN(RtlSelfRelativeToAbsoluteSD)(&rel, &out, &abs_size, (PACL)dacl.b, &dacl_size, NULL, &sacl_size, owner, &owner_size, group, &group_size);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            CHECK(!(out.Control & 0x8000));
            EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(&out, &so, &defaulted), 0);
            CHECK(so == (PSID)owner && UN(RtlEqualSid)(so, (PSID)&xs_admins));
            EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(&out, &present, &got, &defaulted), 0);
            EXPECT_EQ(present, TRUE); CHECK(got == (ACL *)dacl.b); if (got) EXPECT_EQ(got->AceCount, 1);
        }
    }
    /* an absolute descriptor is not a valid input */
    abs_size = dacl_size = sacl_size = owner_size = group_size = 0;
    s = UN(RtlSelfRelativeToAbsoluteSD)(&sd, NULL, &abs_size, NULL, &dacl_size, NULL, &sacl_size, NULL, &owner_size, NULL, &group_size);
    EXPECT_EQ(s, XS(0xC00000E7));
}
TEST(rtl_security_x_security_descriptor_validity)
{
    SECURITY_DESCRIPTOR sd; XS_NEED(); REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlValidSecurityDescriptor)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor));
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(&sd, 1), 0);
    EXPECT_EQ(UN(RtlValidSecurityDescriptor)(&sd), TRUE);           /* an empty descriptor is valid */
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(&sd, 0), XS(0xC0000058));   /* STATUS_UNKNOWN_REVISION */
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(&sd, 2), XS(0xC0000058));
    UN(RtlCreateSecurityDescriptor)(&sd, 1);
    sd.Revision = 2;
    EXPECT_EQ(UN(RtlValidSecurityDescriptor)(&sd), FALSE);
    sd.Revision = 1;
    {
        xs_sid bad = { 2, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
        UN(RtlSetOwnerSecurityDescriptor)(&sd, (PSID)&bad, FALSE);
        EXPECT_EQ(UN(RtlValidSecurityDescriptor)(&sd), FALSE);      /* owner SID with an unknown revision */
    }
}
