#include "t.h"

UDECL(NTSTATUS, RtlInitializeSid, (PSID, PSID_IDENTIFIER_AUTHORITY, UCHAR));
UDECL(NTSTATUS, RtlAllocateAndInitializeSid, (PSID_IDENTIFIER_AUTHORITY, UCHAR, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PSID *));
UDECL(PVOID, RtlFreeSid, (PSID));
UDECL(ULONG, RtlLengthRequiredSid, (ULONG));
UDECL(ULONG, RtlLengthSid, (PSID));
UDECL(BOOLEAN, RtlValidSid, (PSID));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(BOOLEAN, RtlEqualPrefixSid, (PSID, PSID));
UDECL(PULONG, RtlSubAuthoritySid, (PSID, ULONG));
UDECL(PUCHAR, RtlSubAuthorityCountSid, (PSID));
UDECL(PSID_IDENTIFIER_AUTHORITY, RtlIdentifierAuthoritySid, (PSID));
UDECL(NTSTATUS, RtlCopySid, (ULONG, PSID, PSID));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlGetAce, (PACL, ULONG, PVOID *));
UDECL(NTSTATUS, RtlDeleteAce, (PACL, ULONG));
UDECL(NTSTATUS, RtlQueryInformationAcl, (PACL, PVOID, ULONG, ACL_INFORMATION_CLASS));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(ULONG, RtlLengthSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlGetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlSetSaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlGetSaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetControlSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, PULONG));
UDECL(NTSTATUS, RtlSetControlSecurityDescriptor, (PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SECURITY_DESCRIPTOR_CONTROL));
UDECL(NTSTATUS, RtlAbsoluteToSelfRelativeSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG));
UDECL(NTSTATUS, RtlSelfRelativeToAbsoluteSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG, PACL, PULONG, PACL, PULONG, PSID, PULONG, PSID, PULONG));

#define S(x) ((NTSTATUS)(x))
#define RS_OK(call) do { NTSTATUS s_ = (call); EXPECT_EQ(s_, 0); if (s_ != 0) return; } while (0)
typedef struct { BYTE revision, count; SID_IDENTIFIER_AUTHORITY authority; ULONG sub[15]; } rs_sid;
typedef union { ULONGLONG align; BYTE bytes[256]; ACL acl; } rs_acl;
typedef union { ULONGLONG align; BYTE bytes[512]; SECURITY_DESCRIPTOR_RELATIVE sd; } rs_relative;
_Static_assert(offsetof(rs_sid, sub) == 8 && sizeof(rs_sid) == 68, "SID layout");
_Static_assert(sizeof(ACL) == 8 && offsetof(ACCESS_ALLOWED_ACE, SidStart) == 8, "ACL/ACE layout");
_Static_assert(sizeof(SECURITY_DESCRIPTOR) == 40 && sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 20, "x64 SD layout");
static SID_IDENTIFIER_AUTHORITY rs_nt = SECURITY_NT_AUTHORITY;

/* Fixtures are local structures, never installed on a process or object. */
static rs_sid rs_make_sid(BYTE count)
{
    rs_sid s = {1, count, {{0,0,0,0,0,5}}, {21, 42, 77, 99}};
    return s;
}

#define RS_LENGTH_TEST(name, count) TEST(rtlsec_sid_length_##name) { \
    rs_sid sid = rs_make_sid(count); \
    REQUIRE(UN(RtlLengthRequiredSid)); REQUIRE(UN(RtlLengthSid)); \
    EXPECT_EQ(UN(RtlLengthRequiredSid)(count), 8 + 4 * (count)); \
    EXPECT_EQ(UN(RtlLengthSid)(&sid), 8 + 4 * (count)); }
RS_LENGTH_TEST(zero, 0)
RS_LENGTH_TEST(one, 1)
RS_LENGTH_TEST(two, 2)
RS_LENGTH_TEST(eight, 8)
RS_LENGTH_TEST(fifteen, 15)

#define RS_INIT_TEST(name, nsub) TEST(rtlsec_sid_initialize_##name) { \
    rs_sid sid; memset(&sid, 0xa5, sizeof sid); \
    REQUIRE(UN(RtlInitializeSid)); REQUIRE(UN(RtlValidSid)); \
    RS_OK(UN(RtlInitializeSid)(&sid, &rs_nt, nsub)); \
    EXPECT_EQ(sid.revision, 1); EXPECT_EQ(sid.count, nsub); \
    CHECK(!memcmp(&sid.authority, &rs_nt, sizeof rs_nt)); \
    CHECK(UN(RtlValidSid)(&sid)); EXPECT_EQ(sid.sub[0], 0xa5a5a5a5); }
RS_INIT_TEST(zero, 0)
RS_INIT_TEST(one, 1)
RS_INIT_TEST(fifteen, 15)

TEST(rtlsec_sid_initialize_count_sixteen)
{
    rs_sid sid = rs_make_sid(0), before = sid;
    REQUIRE(UN(RtlInitializeSid));
    EXPECT_EQ(UN(RtlInitializeSid)(&sid, &rs_nt, 16), S(0xc000000d));
    CHECK(!memcmp(&sid, &before, sizeof sid));
}

#define RS_ALLOC_TEST(name, nsub) TEST(rtlsec_sid_allocate_##name) { \
    PSID p = NULL; NTSTATUS st; \
    REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid)); \
    st = UN(RtlAllocateAndInitializeSid)(&rs_nt, nsub, 11,22,33,44,55,66,77,88,&p); \
    EXPECT_EQ(st, 0); if (st != 0) return; \
    CHECK(p != NULL); if (!p) return; \
    EXPECT_EQ(((rs_sid *)p)->revision, 1); EXPECT_EQ(((rs_sid *)p)->count, nsub); \
    for (unsigned i = 0; i < (nsub); i++) EXPECT_EQ(((rs_sid *)p)->sub[i], 11 * (i+1)); \
    CHECK(!memcmp(&((rs_sid *)p)->authority, &rs_nt, sizeof rs_nt)); \
    EXPECT_EQ(UN(RtlFreeSid)(p), NULL); }
RS_ALLOC_TEST(zero, 0)
RS_ALLOC_TEST(one, 1)
RS_ALLOC_TEST(two, 2)
RS_ALLOC_TEST(eight, 8)

TEST(rtlsec_sid_allocate_nine)
{
    PSID p = NULL;
    REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid));
    NTSTATUS st = UN(RtlAllocateAndInitializeSid)(&rs_nt,9,0,0,0,0,0,0,0,0,&p);
    EXPECT_EQ(st, S(0xc0000078)); CHECK(p == NULL);
    if (st == 0 && p) UN(RtlFreeSid)(p);
}

TEST(rtlsec_sid_valid_null) { REQUIRE(UN(RtlValidSid)); CHECK(!UN(RtlValidSid)(NULL)); }
TEST(rtlsec_sid_valid_bad_revision)
{
    rs_sid s = rs_make_sid(2); s.revision = 2;
    REQUIRE(UN(RtlValidSid)); CHECK(!UN(RtlValidSid)(&s));
}
TEST(rtlsec_sid_valid_count_sixteen)
{
    rs_sid s = rs_make_sid(16);
    REQUIRE(UN(RtlValidSid)); CHECK(!UN(RtlValidSid)(&s));
}
TEST(rtlsec_sid_subauthority_addresses)
{
    rs_sid s = rs_make_sid(3);
    REQUIRE(UN(RtlSubAuthoritySid)); REQUIRE(UN(RtlSubAuthorityCountSid)); REQUIRE(UN(RtlIdentifierAuthoritySid));
    EXPECT_EQ(UN(RtlSubAuthorityCountSid)(&s), &s.count);
    EXPECT_EQ(UN(RtlIdentifierAuthoritySid)(&s), &s.authority);
    for (ULONG i = 0; i < 3; i++) {
        PULONG p = UN(RtlSubAuthoritySid)(&s, i);
        EXPECT_EQ(p, &s.sub[i]); if (p != &s.sub[i]) return;
        EXPECT_EQ(*p, s.sub[i]);
    }
}

#define RS_COMPARE_TEST(name, change, equal, prefix) TEST(rtlsec_sid_compare_##name) { \
    rs_sid a = rs_make_sid(3), b = a; change; \
    REQUIRE(UN(RtlEqualSid)); REQUIRE(UN(RtlEqualPrefixSid)); \
    EXPECT_EQ(!!UN(RtlEqualSid)(&a,&b), equal); \
    EXPECT_EQ(!!UN(RtlEqualPrefixSid)(&a,&b), prefix); }
RS_COMPARE_TEST(same, (void)0, 1, 1)
RS_COMPARE_TEST(last_subauthority, b.sub[2]++, 0, 1)
RS_COMPARE_TEST(first_subauthority, b.sub[0]++, 0, 0)
RS_COMPARE_TEST(authority, b.authority.Value[5]++, 0, 0)
RS_COMPARE_TEST(count, b.count = 2, 0, 0)
RS_COMPARE_TEST(revision, b.revision = 2, 0, 0)

TEST(rtlsec_sid_copy_exact)
{
    rs_sid a = rs_make_sid(3), b; memset(&b,0xa5,sizeof b);
    REQUIRE(UN(RtlCopySid));
    RS_OK(UN(RtlCopySid)(20,&b,&a)); CHECK(!memcmp(&a,&b,20));
    EXPECT_EQ(b.sub[3],0xa5a5a5a5);
}
TEST(rtlsec_sid_copy_short)
{
    rs_sid a = rs_make_sid(3), b, before; memset(&b,0xa5,sizeof b); before = b;
    REQUIRE(UN(RtlCopySid));
    EXPECT_EQ(UN(RtlCopySid)(19,&b,&a), S(0xc0000023));
    CHECK(!memcmp(&before,&b,sizeof b));
}

#define RS_ACL_CREATE(name, size, rev, status) TEST(rtlsec_acl_create_##name) { \
    rs_acl a; memset(&a,0xa5,sizeof a); REQUIRE(UN(RtlCreateAcl)); \
    NTSTATUS st = UN(RtlCreateAcl)(&a.acl,size,rev); EXPECT_EQ(st,S(status)); \
    if (st == 0) { EXPECT_EQ(a.acl.AclRevision,rev); EXPECT_EQ(a.acl.AclSize,(size)&~3); \
    EXPECT_EQ(a.acl.AceCount,0); EXPECT_EQ(a.acl.Sbz1,0); EXPECT_EQ(a.acl.Sbz2,0); } }
RS_ACL_CREATE(minimum, 8, 2, 0)
RS_ACL_CREATE(ds, 256, 4, 0)
RS_ACL_CREATE(round_down, 255, 2, 0)
RS_ACL_CREATE(short, 7, 2, 0xc0000023)
RS_ACL_CREATE(bad_revision, 256, 1, 0xc000000d)

#define RS_ACL_FIX() rs_acl a; rs_sid sid = rs_make_sid(1); \
    REQUIRE(UN(RtlCreateAcl)); RS_OK(UN(RtlCreateAcl)(&a.acl,sizeof a,2))

TEST(rtlsec_acl_query_empty_size)
{
    ACL_SIZE_INFORMATION q; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    RS_OK(UN(RtlQueryInformationAcl)(&a.acl,&q,sizeof q,AclSizeInformation));
    EXPECT_EQ(q.AceCount,0); EXPECT_EQ(q.AclBytesInUse,8); EXPECT_EQ(q.AclBytesFree,248);
}
TEST(rtlsec_acl_query_revision)
{
    ACL_REVISION_INFORMATION q; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    RS_OK(UN(RtlQueryInformationAcl)(&a.acl,&q,sizeof q,AclRevisionInformation)); EXPECT_EQ(q.AclRevision,2);
}
TEST(rtlsec_acl_query_short)
{
    ACL_SIZE_INFORMATION q, before; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    memset(&q,0xa5,sizeof q); before = q;
    EXPECT_EQ(UN(RtlQueryInformationAcl)(&a.acl,&q,sizeof q-1,AclSizeInformation),S(0xc0000023));
    CHECK(!memcmp(&q,&before,sizeof q));
}
TEST(rtlsec_acl_query_bad_class)
{
    ACL_SIZE_INFORMATION q, before; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    memset(&q,0xa5,sizeof q); before = q;
    EXPECT_EQ(UN(RtlQueryInformationAcl)(&a.acl,&q,sizeof q,(ACL_INFORMATION_CLASS)0),S(0xc0000003));
    CHECK(!memcmp(&q,&before,sizeof q));
}

TEST(rtlsec_acl_create_short_before_revision)
{
    rs_acl a, before; REQUIRE(UN(RtlCreateAcl));
    memset(&a,0xa5,sizeof a); before = a;
    EXPECT_EQ(UN(RtlCreateAcl)(&a.acl,7,1),S(0xc0000023));
    CHECK(!memcmp(&a,&before,sizeof a));
}
TEST(rtlsec_acl_query_revision_before_class_and_size)
{
    ACL_SIZE_INFORMATION q, before; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    a.acl.AclRevision = 1; memset(&q,0xa5,sizeof q); before = q;
    EXPECT_EQ(UN(RtlQueryInformationAcl)(&a.acl,&q,0,(ACL_INFORMATION_CLASS)0),S(0xc000000d));
    CHECK(!memcmp(&q,&before,sizeof q));
}
TEST(rtlsec_acl_query_class_before_size)
{
    ACL_SIZE_INFORMATION q, before; RS_ACL_FIX(); REQUIRE(UN(RtlQueryInformationAcl));
    memset(&q,0xa5,sizeof q); before = q;
    EXPECT_EQ(UN(RtlQueryInformationAcl)(&a.acl,&q,0,(ACL_INFORMATION_CLASS)0),S(0xc0000003));
    CHECK(!memcmp(&q,&before,sizeof q));
}

#define RS_ACE_TEST(name, api, type) TEST(rtlsec_acl_add_##name) { \
    PVOID out = NULL; RS_ACL_FIX(); REQUIRE(UN(api)); REQUIRE(UN(RtlGetAce)); \
    RS_OK(UN(api)(&a.acl,2,0x123456,&sid)); EXPECT_EQ(a.acl.AceCount,1); \
    RS_OK(UN(RtlGetAce)(&a.acl,0,&out)); EXPECT_EQ(out,a.bytes+8); if (out != a.bytes+8) return; \
    ACCESS_ALLOWED_ACE *ace = out; EXPECT_EQ(ace->Header.AceType,type); \
    EXPECT_EQ(ace->Header.AceFlags,0); EXPECT_EQ(ace->Header.AceSize,20); \
    EXPECT_EQ(ace->Mask,0x123456); CHECK(!memcmp(&ace->SidStart,&sid,12)); }
RS_ACE_TEST(allowed, RtlAddAccessAllowedAce, ACCESS_ALLOWED_ACE_TYPE)
RS_ACE_TEST(denied, RtlAddAccessDeniedAce, ACCESS_DENIED_ACE_TYPE)

TEST(rtlsec_acl_add_no_space)
{
    rs_acl a; rs_sid sid = rs_make_sid(1);
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    RS_OK(UN(RtlCreateAcl)(&a.acl,8,2));
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(&a.acl,2,1,&sid),S(0xc0000099)); EXPECT_EQ(a.acl.AceCount,0);
}
TEST(rtlsec_acl_get_empty)
{
    PVOID out = NULL; RS_ACL_FIX(); REQUIRE(UN(RtlGetAce));
    EXPECT_EQ(UN(RtlGetAce)(&a.acl,0,&out),S(0xc000000d)); CHECK(out == NULL);
}
TEST(rtlsec_acl_delete_empty)
{
    RS_ACL_FIX(); REQUIRE(UN(RtlDeleteAce));
    EXPECT_EQ(UN(RtlDeleteAce)(&a.acl,0),S(0xc000000d)); EXPECT_EQ(a.acl.AceCount,0);
}

#define RS_DELETE_TEST(name, index, remaining) TEST(rtlsec_acl_delete_##name) { \
    PVOID out = NULL; RS_ACL_FIX(); REQUIRE(UN(RtlAddAccessAllowedAce)); REQUIRE(UN(RtlDeleteAce)); REQUIRE(UN(RtlGetAce)); \
    RS_OK(UN(RtlAddAccessAllowedAce)(&a.acl,2,11,&sid)); \
    RS_OK(UN(RtlAddAccessAllowedAce)(&a.acl,2,22,&sid)); \
    RS_OK(UN(RtlDeleteAce)(&a.acl,index)); EXPECT_EQ(a.acl.AceCount,1); \
    RS_OK(UN(RtlGetAce)(&a.acl,0,&out)); EXPECT_EQ(out,a.bytes+8); if (out != a.bytes+8) return; \
    EXPECT_EQ(((ACCESS_ALLOWED_ACE *)out)->Mask,remaining); }
RS_DELETE_TEST(first, 0, 22)
RS_DELETE_TEST(last, 1, 11)

#define RS_SD_FIX() SECURITY_DESCRIPTOR sd; REQUIRE(UN(RtlCreateSecurityDescriptor)); \
    RS_OK(UN(RtlCreateSecurityDescriptor)(&sd,1))

TEST(rtlsec_sd_initialize)
{
    RS_SD_FIX(); REQUIRE(UN(RtlValidSecurityDescriptor)); REQUIRE(UN(RtlLengthSecurityDescriptor));
    EXPECT_EQ(sd.Revision,1); EXPECT_EQ(sd.Control,0); CHECK(sd.Owner == NULL); CHECK(sd.Group == NULL);
    CHECK(sd.Dacl == NULL); CHECK(sd.Sacl == NULL); CHECK(UN(RtlValidSecurityDescriptor)(&sd));
    EXPECT_EQ(UN(RtlLengthSecurityDescriptor)(&sd),40);
}
TEST(rtlsec_sd_bad_revision)
{
    SECURITY_DESCRIPTOR sd, before; memset(&sd,0xa5,sizeof sd); before = sd;
    REQUIRE(UN(RtlCreateSecurityDescriptor));
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(&sd,2),S(0xc0000058)); CHECK(!memcmp(&sd,&before,sizeof sd));
}
TEST(rtlsec_sd_invalid_revision_validity)
{
    RS_SD_FIX(); REQUIRE(UN(RtlValidSecurityDescriptor)); sd.Revision = 2; CHECK(!UN(RtlValidSecurityDescriptor)(&sd));
}

#define RS_SID_FIELD_TEST(name, field, set, get, value, def) TEST(rtlsec_sd_##name) { \
    rs_sid sid = rs_make_sid(2); PSID out = NULL; BOOLEAN d = 0x7f; RS_SD_FIX(); \
    REQUIRE(UN(set)); REQUIRE(UN(get)); \
    RS_OK(UN(set)(&sd,value,def)); RS_OK(UN(get)(&sd,&out,&d)); \
    EXPECT_EQ(out,value); EXPECT_EQ(d,def); EXPECT_EQ(sd.field,value); }
RS_SID_FIELD_TEST(owner, Owner, RtlSetOwnerSecurityDescriptor, RtlGetOwnerSecurityDescriptor, &sid, FALSE)
RS_SID_FIELD_TEST(owner_defaulted, Owner, RtlSetOwnerSecurityDescriptor, RtlGetOwnerSecurityDescriptor, &sid, TRUE)
RS_SID_FIELD_TEST(owner_null, Owner, RtlSetOwnerSecurityDescriptor, RtlGetOwnerSecurityDescriptor, NULL, FALSE)
RS_SID_FIELD_TEST(group, Group, RtlSetGroupSecurityDescriptor, RtlGetGroupSecurityDescriptor, &sid, FALSE)
RS_SID_FIELD_TEST(group_defaulted, Group, RtlSetGroupSecurityDescriptor, RtlGetGroupSecurityDescriptor, &sid, TRUE)
RS_SID_FIELD_TEST(group_null, Group, RtlSetGroupSecurityDescriptor, RtlGetGroupSecurityDescriptor, NULL, FALSE)

#define RS_ACL_FIELD_TEST(name, set, get, present, nullacl, def) TEST(rtlsec_sd_##name) { \
    rs_acl acl; PACL out = &acl.acl; BOOLEAN p = 0x7f, d = 0x7f; RS_SD_FIX(); \
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(set)); REQUIRE(UN(get)); \
    RS_OK(UN(RtlCreateAcl)(&acl.acl,sizeof acl,2)); \
    PACL value = (nullacl) ? NULL : &acl.acl; \
    RS_OK(UN(set)(&sd,present,value,def)); RS_OK(UN(get)(&sd,&p,&out,&d)); \
    EXPECT_EQ(p,present); if (present) { EXPECT_EQ(out,value); EXPECT_EQ(d,def); } \
    else { EXPECT_EQ(out,&acl.acl); EXPECT_EQ(d,0x7f); } }
RS_ACL_FIELD_TEST(dacl_absent, RtlSetDaclSecurityDescriptor, RtlGetDaclSecurityDescriptor, FALSE, TRUE, FALSE)
RS_ACL_FIELD_TEST(dacl_null, RtlSetDaclSecurityDescriptor, RtlGetDaclSecurityDescriptor, TRUE, TRUE, FALSE)
RS_ACL_FIELD_TEST(dacl_empty, RtlSetDaclSecurityDescriptor, RtlGetDaclSecurityDescriptor, TRUE, FALSE, FALSE)
RS_ACL_FIELD_TEST(dacl_defaulted, RtlSetDaclSecurityDescriptor, RtlGetDaclSecurityDescriptor, TRUE, FALSE, TRUE)
RS_ACL_FIELD_TEST(sacl_absent, RtlSetSaclSecurityDescriptor, RtlGetSaclSecurityDescriptor, FALSE, TRUE, FALSE)
RS_ACL_FIELD_TEST(sacl_null, RtlSetSaclSecurityDescriptor, RtlGetSaclSecurityDescriptor, TRUE, TRUE, FALSE)
RS_ACL_FIELD_TEST(sacl_empty, RtlSetSaclSecurityDescriptor, RtlGetSaclSecurityDescriptor, TRUE, FALSE, FALSE)
RS_ACL_FIELD_TEST(sacl_defaulted, RtlSetSaclSecurityDescriptor, RtlGetSaclSecurityDescriptor, TRUE, FALSE, TRUE)

TEST(rtlsec_sd_control_set_clear)
{
    SECURITY_DESCRIPTOR_CONTROL control = 0; ULONG rev = 0; RS_SD_FIX();
    REQUIRE(UN(RtlSetControlSecurityDescriptor)); REQUIRE(UN(RtlGetControlSecurityDescriptor));
    RS_OK(UN(RtlSetControlSecurityDescriptor)(&sd,SE_DACL_PROTECTED,SE_DACL_PROTECTED));
    RS_OK(UN(RtlGetControlSecurityDescriptor)(&sd,&control,&rev)); EXPECT_EQ(control,SE_DACL_PROTECTED); EXPECT_EQ(rev,1);
    RS_OK(UN(RtlSetControlSecurityDescriptor)(&sd,SE_DACL_PROTECTED,0)); EXPECT_EQ(sd.Control,0);
}
TEST(rtlsec_sd_control_forbidden)
{
    RS_SD_FIX(); REQUIRE(UN(RtlSetControlSecurityDescriptor));
    EXPECT_EQ(UN(RtlSetControlSecurityDescriptor)(&sd,SE_SELF_RELATIVE,SE_SELF_RELATIVE),S(0xc000000d)); EXPECT_EQ(sd.Control,0);
}
TEST(rtlsec_sd_control_bits_outside_mask)
{
    RS_SD_FIX(); REQUIRE(UN(RtlSetControlSecurityDescriptor));
    EXPECT_EQ(UN(RtlSetControlSecurityDescriptor)(&sd,0,SE_DACL_PROTECTED),S(0xc000000d)); EXPECT_EQ(sd.Control,0);
}

TEST(rtlsec_sd_control_bad_revision_outputs)
{
    SECURITY_DESCRIPTOR_CONTROL control = 0x1234; ULONG revision = 0; RS_SD_FIX();
    REQUIRE(UN(RtlGetControlSecurityDescriptor)); sd.Revision = 2;
    EXPECT_EQ(UN(RtlGetControlSecurityDescriptor)(&sd,&control,&revision),S(0xc0000058));
    EXPECT_EQ(revision,2); EXPECT_EQ(control,0x1234);
}

/* Relative conversion uses a compact owner/group/DACL/SACL fixture. */
#define RS_CONVERT_FIX() rs_sid owner = rs_make_sid(2), group = rs_make_sid(1); \
    rs_acl dacl, sacl; rs_relative rel; RS_SD_FIX(); \
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAbsoluteToSelfRelativeSD)); \
    RS_OK(UN(RtlCreateAcl)(&dacl.acl,8,2)); RS_OK(UN(RtlCreateAcl)(&sacl.acl,8,2)); \
    sd.Owner = &owner; sd.Group = &group; sd.Dacl = &dacl.acl; sd.Sacl = &sacl.acl; \
    sd.Control = SE_DACL_PRESENT | SE_SACL_PRESENT

TEST(rtlsec_sd_relative_size_query)
{
    ULONG n = 0; RS_CONVERT_FIX();
    EXPECT_EQ(UN(RtlAbsoluteToSelfRelativeSD)(&sd,NULL,&n),S(0xc0000023)); EXPECT_EQ(n,64);
}
TEST(rtlsec_sd_relative_short)
{
    ULONG n = 63; RS_CONVERT_FIX(); memset(&rel,0xa5,sizeof rel);
    EXPECT_EQ(UN(RtlAbsoluteToSelfRelativeSD)(&sd,&rel,&n),S(0xc0000023)); EXPECT_EQ(n,64);
    EXPECT_EQ(rel.bytes[0],0xa5);
}
TEST(rtlsec_sd_relative_null_sufficient)
{
    ULONG n = 64; RS_CONVERT_FIX();
    EXPECT_EQ(UN(RtlAbsoluteToSelfRelativeSD)(&sd,NULL,&n),S(0xc000000d));
}
TEST(rtlsec_sd_relative_exact)
{
    ULONG n = 64; PSID out = NULL; BOOLEAN def = TRUE; RS_CONVERT_FIX();
    REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlLengthSecurityDescriptor)); REQUIRE(UN(RtlValidSecurityDescriptor));
    memset(&rel,0xa5,sizeof rel); RS_OK(UN(RtlAbsoluteToSelfRelativeSD)(&sd,&rel,&n));
    EXPECT_EQ(rel.sd.Control,sd.Control|SE_SELF_RELATIVE); EXPECT_EQ(rel.bytes[64],0xa5);
    CHECK(UN(RtlValidSecurityDescriptor)(&rel)); EXPECT_EQ(UN(RtlLengthSecurityDescriptor)(&rel),64);
    RS_OK(UN(RtlGetOwnerSecurityDescriptor)(&rel,&out,&def));
    ULONG_PTR offset = (ULONG_PTR)out - (ULONG_PTR)rel.bytes;
    CHECK(offset <= 48);
    if (offset > 48) return;
    CHECK(!memcmp(out,&owner,16)); EXPECT_EQ(def,FALSE);
}
TEST(rtlsec_sd_absolute_sizes)
{
    ULONG n = sizeof(rs_relative), an = 0, dn = 0, sn = 0, on = 0, gn = 0; RS_CONVERT_FIX();
    REQUIRE(UN(RtlSelfRelativeToAbsoluteSD)); RS_OK(UN(RtlAbsoluteToSelfRelativeSD)(&sd,&rel,&n));
    EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD)(&rel,NULL,&an,NULL,&dn,NULL,&sn,NULL,&on,NULL,&gn),S(0xc0000023));
    EXPECT_EQ(an,40); EXPECT_EQ(dn,8); EXPECT_EQ(sn,8); EXPECT_EQ(on,16); EXPECT_EQ(gn,12);
}
TEST(rtlsec_sd_absolute_roundtrip)
{
    ULONG n = sizeof(rs_relative), an = sizeof(SECURITY_DESCRIPTOR), dn = 8, sn = 8, on = 16, gn = 12;
    SECURITY_DESCRIPTOR absolute; rs_acl da, sa; rs_sid o, g; RS_CONVERT_FIX();
    REQUIRE(UN(RtlSelfRelativeToAbsoluteSD)); RS_OK(UN(RtlAbsoluteToSelfRelativeSD)(&sd,&rel,&n));
    RS_OK(UN(RtlSelfRelativeToAbsoluteSD)(&rel,&absolute,&an,&da.acl,&dn,&sa.acl,&sn,&o,&on,&g,&gn));
    EXPECT_EQ(absolute.Control,sd.Control); EXPECT_EQ(absolute.Owner,&o); EXPECT_EQ(absolute.Group,&g);
    EXPECT_EQ(absolute.Dacl,&da.acl); EXPECT_EQ(absolute.Sacl,&sa.acl);
    CHECK(!memcmp(&o,&owner,16)); CHECK(!memcmp(&g,&group,12));
    CHECK(!memcmp(&da,&dacl,8)); CHECK(!memcmp(&sa,&sacl,8));
}
TEST(rtlsec_sd_absolute_owner_short)
{
    ULONG n = sizeof(rs_relative), an = 40, dn = 8, sn = 8, on = 15, gn = 12;
    SECURITY_DESCRIPTOR absolute; rs_acl da, sa; rs_sid o, g; RS_CONVERT_FIX();
    REQUIRE(UN(RtlSelfRelativeToAbsoluteSD)); RS_OK(UN(RtlAbsoluteToSelfRelativeSD)(&sd,&rel,&n));
    EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD)(&rel,&absolute,&an,&da.acl,&dn,&sa.acl,&sn,&o,&on,&g,&gn),S(0xc0000023));
    EXPECT_EQ(an,40); EXPECT_EQ(on,16); EXPECT_EQ(gn,12); EXPECT_EQ(dn,8); EXPECT_EQ(sn,8);
}
