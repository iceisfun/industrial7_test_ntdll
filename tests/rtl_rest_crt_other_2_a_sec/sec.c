#include "t.h"
#include <stdlib.h>

UDECL(VOID, RtlMapGenericMask, (PACCESS_MASK, const GENERIC_MAPPING *));
UDECL(LONG, RtlMapSecurityErrorToNtStatus, (LONG));
UDECL(NTSTATUS, RtlLengthSidAsUnicodeString, (PSID, PULONG));
UDECL(NTSTATUS, RtlSidDominates, (PSID, PSID, PBOOLEAN));
UDECL(BOOLEAN, RtlOwnerAcesPresent, (PACL));
UDECL(NTSTATUS, RtlMakeSelfRelativeSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG));
UDECL(NTSTATUS, RtlSelfRelativeToAbsoluteSD2, (PSECURITY_DESCRIPTOR, PULONG));
UDECL(NTSTATUS, RtlReplaceSidInSd, (PSECURITY_DESCRIPTOR, PSID, PSID, PULONG));
UDECL(NTSTATUS, RtlNewSecurityObject, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, BOOLEAN, HANDLE, PGENERIC_MAPPING));
UDECL(NTSTATUS, RtlNewSecurityObjectEx, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, GUID *, BOOLEAN, ULONG, HANDLE, PGENERIC_MAPPING));
UDECL(NTSTATUS, RtlNewSecurityObjectWithMultipleInheritance, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, GUID **, ULONG, BOOLEAN, ULONG, HANDLE, PGENERIC_MAPPING));
UDECL(NTSTATUS, RtlNewInstanceSecurityObject, (BOOLEAN, BOOLEAN, PLUID, PLUID, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, BOOLEAN, HANDLE, PGENERIC_MAPPING));
UDECL(NTSTATUS, RtlNewSecurityGrantedAccess, (ACCESS_MASK, PPRIVILEGE_SET, PULONG, HANDLE, PGENERIC_MAPPING, PACCESS_MASK));
UDECL(NTSTATUS, RtlDeleteSecurityObject, (PSECURITY_DESCRIPTOR *));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlGetAce, (PACL, ULONG, PVOID *));
UDECL(NTSTATUS, RtlAllocateAndInitializeSid, (PSID_IDENTIFIER_AUTHORITY, UCHAR, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PSID *));
UDECL(PVOID, RtlFreeSid, (PSID));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(ULONG, RtlLengthSid, (PSID));
UDECL(ULONG, RtlLengthSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(NTSTATUS, RtlConvertSidToUnicodeString, (PUNICODE_STRING, PSID, BOOLEAN));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
static SID_IDENTIFIER_AUTHORITY NT_AUTH = { {0,0,0,0,0,5} };
static SID_IDENTIFIER_AUTHORITY WORLD_AUTH = { {0,0,0,0,0,1} };
static SID_IDENTIFIER_AUTHORITY LABEL_AUTH = { {0,0,0,0,0,16} };
static const GENERIC_MAPPING FILE_MAP = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };

#define ALLOC_SID(out, auth, n, a0, a1) UN(RtlAllocateAndInitializeSid)(&(auth), (n), (a0), (a1), 0, 0, 0, 0, 0, 0, &(out))

/* ---------- RtlMapGenericMask ---------- */
TEST(map_generic_mask) {
    GENERIC_MAPPING m = { 0x11, 0x22, 0x44, 0x88 };
    ACCESS_MASK a;
    REQUIRE(UN(RtlMapGenericMask));
    a = GENERIC_READ;    UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x11);
    a = GENERIC_WRITE;   UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x22);
    a = GENERIC_EXECUTE; UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x44);
    a = GENERIC_ALL;     UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x88);
    a = GENERIC_READ | GENERIC_EXECUTE | 0x1000; UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x11 | 0x44 | 0x1000);
    a = 0xF0000000;      UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x11 | 0x22 | 0x44 | 0x88);
    a = 0x12345;         UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0x12345);          /* no generic bits: unchanged */
    a = 0;               UN(RtlMapGenericMask)(&a, &m); EXPECT_EQ(a, 0);
    a = MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY; UN(RtlMapGenericMask)(&a, &m);
    EXPECT_EQ(a, MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);                            /* only the four generic bits are cleared */
    a = GENERIC_ALL | 0x1;
    { GENERIC_MAPPING z = {0,0,0,0}; UN(RtlMapGenericMask)(&a, &z); EXPECT_EQ(a, 0x1); }
    a = GENERIC_READ | GENERIC_WRITE;
    { GENERIC_MAPPING f = FILE_MAP; UN(RtlMapGenericMask)(&a, &f); EXPECT_EQ(a, FILE_GENERIC_READ | FILE_GENERIC_WRITE); }
}

/* ---------- RtlMapSecurityErrorToNtStatus ---------- */
TEST(map_security_error_to_status) {
    static const struct { ULONG in, out; } t[] = {
        { 0x80090300, 0xC000009A }, { 0x80090301, 0xC0000008 }, { 0x80090302, 0xC00000BB },
        { 0x80090303, 0xC00000BE }, { 0x80090304, 0xC00000E5 }, { 0x80090305, 0xC00000FE },
        { 0x80090306, 0xC0000061 }, { 0x80090307, 0xC00000FE }, { 0x80090308, 0xC000000D },
        { 0x80090309, 0xC000000D }, { 0x8009030A, 0xC00000BB }, { 0x8009030B, 0xC000010D },
        { 0x8009030C, 0xC000006D }, { 0x8009030D, 0xC000005F }, { 0x8009030E, 0xC000005F },
        { 0x8009030F, 0xC0000022 }, { 0x80090310, 0xC0000022 }, { 0x80090311, 0xC000005E },
        { 0x80090316, 0xC00000FE }, { 0x80090324, 0xC0000133 }, { 0x80090331, 0xC00000BB },
        { 0x8009035D, 0xC000000D },
    };
    static const ULONG pass[] = { 0, 1, 0xC0000005, 0x80090000, 0x800902FF, 0x80090312, 0x80090315, 0x80090317, 0x80090323, 0x80090325,
                                  0x80090330, 0x80090332, 0x8009035C, 0x8009035E, 0x80090400, 0x7FFFFFFF, 0xFFFFFFFF };
    size_t i;
    REQUIRE(UN(RtlMapSecurityErrorToNtStatus));
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
        CHECKF(UN(RtlMapSecurityErrorToNtStatus)((LONG)t[i].in) == (LONG)t[i].out, "map 0x%08lx -> got 0x%08lx want 0x%08lx", t[i].in, (ULONG)UN(RtlMapSecurityErrorToNtStatus)((LONG)t[i].in), t[i].out);
    for (i = 0; i < sizeof pass / sizeof pass[0]; i++)
        CHECKF(UN(RtlMapSecurityErrorToNtStatus)((LONG)pass[i]) == (LONG)pass[i], "0x%08lx must pass through, got 0x%08lx", pass[i], (ULONG)UN(RtlMapSecurityErrorToNtStatus)((LONG)pass[i]));
}

/* ---------- SID helpers ---------- */
TEST(length_sid_as_unicode_string) {
    PSID sids[4] = {0}; ULONG len, i; UNICODE_STRING us; static UCHAR bad[8] = { 2, 1, 0,0,0,0,0,5 };
    ULONG expect_sub[4] = { 1, 2, 1, 5 };
    SID_IDENTIFIER_AUTHORITY big = { {0x12,0x34,0,0,0,0x56} };
    REQUIRE(UN(RtlLengthSidAsUnicodeString)); REQUIRE(UN(RtlConvertSidToUnicodeString));
    REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid)); REQUIRE(UN(RtlFreeUnicodeString));
    EXPECT_EQ(ALLOC_SID(sids[0], WORLD_AUTH, 1, 0, 0), 0);                       /* S-1-1-0 */
    EXPECT_EQ(ALLOC_SID(sids[1], NT_AUTH, 2, 32, 544), 0);                       /* S-1-5-32-544 */
    EXPECT_EQ(UN(RtlAllocateAndInitializeSid)(&NT_AUTH, 5, 21, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFF0, 1000, 0, 0, 0, &sids[3]), 0);
    EXPECT_EQ(UN(RtlAllocateAndInitializeSid)(&big, 1, 7, 0, 0, 0, 0, 0, 0, 0, &sids[2]), 0);
    for (i = 0; i < 4; i++) {
        len = 0xdeadbeef;
        EXPECT_EQ(UN(RtlLengthSidAsUnicodeString)(sids[i], &len), 0);
        /* decimal-authority SIDs: 28 + 22 per sub-authority; hex-authority SIDs 36 + 22 per sub-authority */
        EXPECT_EQ(len, (i == 2 ? 0x24 : 0x1c) + 0x16 * expect_sub[i]);
        memset(&us, 0, sizeof us);
        if (UN(RtlConvertSidToUnicodeString)(&us, sids[i], TRUE) == 0) {
            CHECKF(us.Length <= len, "string length %u exceeds reported bound %lu", us.Length, len);
            UN(RtlFreeUnicodeString)(&us);
        }
    }
    len = 0xdeadbeef;
    EXPECT_EQ(UN(RtlLengthSidAsUnicodeString)(bad, &len), S(0xC0000078));          /* revision 2 is not a valid SID */
    EXPECT_EQ(len, 0xdeadbeef);
    for (i = 0; i < 4; i++) UN(RtlFreeSid)(sids[i]);
}

TEST(sid_dominates) {
    PSID lo, md, hi, other = NULL; BOOLEAN d; NTSTATUS s;
    REQUIRE(UN(RtlSidDominates)); REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid));
    EXPECT_EQ(ALLOC_SID(lo, LABEL_AUTH, 1, 0x1000, 0), 0);   /* low */
    EXPECT_EQ(ALLOC_SID(md, LABEL_AUTH, 1, 0x2000, 0), 0);   /* medium */
    EXPECT_EQ(ALLOC_SID(hi, LABEL_AUTH, 1, 0x3000, 0), 0);   /* high */
    EXPECT_EQ(ALLOC_SID(other, NT_AUTH, 1, 18, 0), 0);
    d = 0xFF; EXPECT_EQ(UN(RtlSidDominates)(hi, md, &d), 0); EXPECT_EQ(d, 1);
    d = 0xFF; EXPECT_EQ(UN(RtlSidDominates)(md, md, &d), 0); EXPECT_EQ(d, 1);
    d = 0xFF; EXPECT_EQ(UN(RtlSidDominates)(lo, md, &d), 0); EXPECT_EQ(d, 0);
    d = 0xFF; EXPECT_EQ(UN(RtlSidDominates)(md, hi, &d), 0); EXPECT_EQ(d, 0);
    d = 0xFF; EXPECT_EQ(UN(RtlSidDominates)(md, lo, &d), 0); EXPECT_EQ(d, 1);
    /* both arguments must be integrity-label SIDs; the output is cleared first */
    d = 0xFF; s = UN(RtlSidDominates)(other, md, &d); EXPECT_EQ(s, S(0xC000000D)); EXPECT_EQ(d, 0);
    d = 0xFF; s = UN(RtlSidDominates)(md, other, &d); EXPECT_EQ(s, S(0xC000000D)); EXPECT_EQ(d, 0);
    UN(RtlFreeSid)(lo); UN(RtlFreeSid)(md); UN(RtlFreeSid)(hi); UN(RtlFreeSid)(other);
}

/* ---------- ACL / SD building helpers ---------- */
typedef struct { ACE_HEADER h; ACCESS_MASK mask; DWORD sid[1]; } ACE_;
static PACL make_acl(void *buf, ULONG size) { UN(RtlCreateAcl)((PACL)buf, size, 2); return (PACL)buf; }

TEST(owner_aces_present) {
    PSID owner_rights, everyone; UCHAR b1[256], b2[256]; PACL a1, a2;
    REQUIRE(UN(RtlOwnerAcesPresent)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAceEx));
    EXPECT_EQ(UN(RtlAllocateAndInitializeSid)(&(SID_IDENTIFIER_AUTHORITY){ {0,0,0,0,0,3} }, 1, 4, 0, 0, 0, 0, 0, 0, 0, &owner_rights), 0); /* S-1-3-4 */
    EXPECT_EQ(ALLOC_SID(everyone, WORLD_AUTH, 1, 0, 0), 0);
    a1 = make_acl(b1, sizeof b1); a2 = make_acl(b2, sizeof b2);
    EXPECT_EQ(UN(RtlOwnerAcesPresent)(a1), FALSE);                                /* empty ACL */
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(a1, 2, 0, GENERIC_READ, everyone), 0);
    EXPECT_EQ(UN(RtlOwnerAcesPresent)(a1), FALSE);                                /* no OWNER RIGHTS ace */
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(a2, 2, 0, GENERIC_READ, everyone), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(a2, 2, 0, READ_CONTROL, owner_rights), 0);
    EXPECT_EQ(UN(RtlOwnerAcesPresent)(a2), TRUE);
    UN(RtlFreeSid)(owner_rights); UN(RtlFreeSid)(everyone);
}

/* build an absolute SD: owner Administrators, group Everyone, DACL with two allow aces */
typedef struct { SECURITY_DESCRIPTOR sd; PSID owner, group, other; UCHAR acl[128]; } ABSSD;
static int build_abs(ABSSD *a) {
    PACL acl;
    memset(a, 0, sizeof *a);
    if (ALLOC_SID(a->owner, NT_AUTH, 2, 32, 544)) return 0;
    if (ALLOC_SID(a->group, WORLD_AUTH, 1, 0, 0)) return 0;
    if (ALLOC_SID(a->other, NT_AUTH, 1, 18, 0)) return 0;
    UN(RtlCreateSecurityDescriptor)(&a->sd, 1);
    UN(RtlSetOwnerSecurityDescriptor)(&a->sd, a->owner, FALSE);
    UN(RtlSetGroupSecurityDescriptor)(&a->sd, a->group, FALSE);
    acl = make_acl(a->acl, sizeof a->acl);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, GENERIC_READ, a->group);
    UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, GENERIC_ALL, a->other);
    UN(RtlSetDaclSecurityDescriptor)(&a->sd, TRUE, acl, FALSE);
    return 1;
}
static void free_abs(ABSSD *a) { UN(RtlFreeSid)(a->owner); UN(RtlFreeSid)(a->group); UN(RtlFreeSid)(a->other); }
#define SD_EXPORTS \
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor)); REQUIRE(UN(RtlSetGroupSecurityDescriptor)); \
    REQUIRE(UN(RtlSetDaclSecurityDescriptor)); REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlGetGroupSecurityDescriptor)); \
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAceEx)); REQUIRE(UN(RtlGetAce)); \
    REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid)); REQUIRE(UN(RtlEqualSid)); REQUIRE(UN(RtlLengthSid)); \
    REQUIRE(UN(RtlLengthSecurityDescriptor)); REQUIRE(UN(RtlValidSecurityDescriptor))

static void check_sd_content(PSECURITY_DESCRIPTOR sd, ABSSD *a, const char *what) {
    PSID o = NULL, g = NULL; BOOLEAN def, present; PACL dacl = NULL; ACE_ *ace = NULL;
    EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def), 0);
    CHECKF(o && UN(RtlEqualSid)(o, a->owner), "%s: owner", what);
    EXPECT_EQ(UN(RtlGetGroupSecurityDescriptor)(sd, &g, &def), 0);
    CHECKF(g && UN(RtlEqualSid)(g, a->group), "%s: group", what);
    EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def), 0);
    EXPECT_EQ(present, TRUE);
    if (dacl) {
        EXPECT_EQ(dacl->AceCount, 2);
        EXPECT_EQ(UN(RtlGetAce)(dacl, 0, (PVOID *)&ace), 0);
        if (ace) { EXPECT_EQ(ace->h.AceType, ACCESS_ALLOWED_ACE_TYPE); EXPECT_EQ(ace->mask, GENERIC_READ); CHECK(UN(RtlEqualSid)((PSID)ace->sid, a->group)); }
        EXPECT_EQ(UN(RtlGetAce)(dacl, 1, (PVOID *)&ace), 0);
        if (ace) { EXPECT_EQ(ace->mask, GENERIC_ALL); CHECK(UN(RtlEqualSid)((PSID)ace->sid, a->other)); }
    }
}

TEST(make_self_relative_and_back) {
    ABSSD a; ULONG need = 0, len; UCHAR *rel; ULONG sidlen_total, i;
    SD_EXPORTS; REQUIRE(UN(RtlMakeSelfRelativeSD)); REQUIRE(UN(RtlSelfRelativeToAbsoluteSD2));
    if (!build_abs(&a)) { t_skip("could not build fixture SD"); return; }
    sidlen_total = UN(RtlLengthSid)(a.owner) + UN(RtlLengthSid)(a.group) + a.sd.Dacl->AclSize;
    /* size query */
    len = 0;
    EXPECT_EQ(UN(RtlMakeSelfRelativeSD)(&a.sd, NULL, &len), S(0xC0000023));
    need = len;
    EXPECT_EQ(need, 0x14 + sidlen_total);
    EXPECT_EQ(UN(RtlLengthSecurityDescriptor)(&a.sd), 0x28 + sidlen_total);   /* absolute: 0x28-byte header */
    len = need - 1;
    EXPECT_EQ(UN(RtlMakeSelfRelativeSD)(&a.sd, (PSECURITY_DESCRIPTOR)a.acl /*unused*/, &len), S(0xC0000023));
    EXPECT_EQ(len, need);
    /* NULL output with sufficient length */
    len = need;
    EXPECT_EQ(UN(RtlMakeSelfRelativeSD)(&a.sd, NULL, &len), S(0xC000000D));
    rel = calloc(1, need + 64); if (!rel) { free_abs(&a); return; }
    memset(rel + need, 0xCC, 64);
    len = need;
    EXPECT_EQ(UN(RtlMakeSelfRelativeSD)(&a.sd, rel, &len), 0);
    EXPECT_EQ(len, need);                                  /* length is only written on the too-small path */
    CHECK((((SECURITY_DESCRIPTOR_RELATIVE *)rel)->Control & SE_SELF_RELATIVE) != 0);
    EXPECT_EQ(rel[0], 1);                                  /* revision */
    for (i = 0; i < 64; i++) if (rel[need + i] != 0xCC) { CHECKF(0, "wrote past the computed size"); break; }
    CHECK(UN(RtlValidSecurityDescriptor)(rel));
    EXPECT_EQ(UN(RtlLengthSecurityDescriptor)(rel), need);
    check_sd_content(rel, &a, "self-relative");
    /* the self-relative offsets must all point inside the image */
    {
        SECURITY_DESCRIPTOR_RELATIVE *r = (void *)rel;
        EXPECT_EQ(r->Sacl, 0);
        CHECK(r->Owner >= 0x14 && r->Owner < need); CHECK(r->Group >= 0x14 && r->Group < need); CHECK(r->Dacl >= 0x14 && r->Dacl < need);
    }
    /* a larger buffer is fine too */
    {
        UCHAR *rel2 = calloc(1, need + 100); ULONG l2 = need + 100;
        if (rel2) { EXPECT_EQ(UN(RtlMakeSelfRelativeSD)(&a.sd, rel2, &l2), 0); EXPECT_EQ(memcmp(rel2, rel, need), 0); free(rel2); }
    }

    /* ---- RtlSelfRelativeToAbsoluteSD2 (in place) ---- */
    {
        UCHAR *buf = calloc(1, need + 0x100); ULONG l; SECURITY_DESCRIPTOR *abs_;
        if (!buf) { free(rel); free_abs(&a); return; }
        memcpy(buf, rel, need);
        l = 0x28;
        EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(NULL, &l), S(0xC00000EF));
        EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(buf, NULL), S(0xC00000F0));
        l = 0x13; EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(buf, &l), S(0xC000000D));
        l = 0x28; EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(&a.sd, &l), S(0xC00000E7));   /* already absolute */
        l = 0x14;
        EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(buf, &l), S(0xC0000023));
        EXPECT_EQ(l, 0x28 + ((need - 0x14 + 7) & ~7u));    /* 0x28 header + data blocks rounded up to 8 */
        CHECK((((SECURITY_DESCRIPTOR_RELATIVE *)buf)->Control & SE_SELF_RELATIVE) != 0); /* untouched on failure */
        EXPECT_EQ(memcmp(buf, rel, need), 0);
        EXPECT_EQ(UN(RtlSelfRelativeToAbsoluteSD2)(buf, &l), 0);
        abs_ = (SECURITY_DESCRIPTOR *)buf;
        EXPECT_EQ(abs_->Control & SE_SELF_RELATIVE, 0);
        CHECK((UCHAR *)abs_->Owner >= buf && (UCHAR *)abs_->Owner < buf + l);
        CHECK((UCHAR *)abs_->Dacl >= buf && (UCHAR *)abs_->Dacl < buf + l);
        EXPECT_EQ(abs_->Sacl, NULL);
        check_sd_content(buf, &a, "converted-back absolute");
        free(buf);
    }
    free(rel);
    free_abs(&a);
}

TEST(replace_sid_in_sd) {
    ABSSD a; PSID from, to, o = NULL, g = NULL, longer, diffauth; ULONG cnt; BOOLEAN def; PACL dacl; ACE_ *ace = NULL; BOOLEAN present;
    SD_EXPORTS; REQUIRE(UN(RtlReplaceSidInSd));
    if (!build_abs(&a)) { t_skip("could not build fixture SD"); return; }
    EXPECT_EQ(ALLOC_SID(from, WORLD_AUTH, 1, 0, 0), 0);         /* S-1-1-0: the group and the first ace sid */
    EXPECT_EQ(ALLOC_SID(to, WORLD_AUTH, 1, 5, 0), 0);           /* S-1-1-5: same authority and length */
    EXPECT_EQ(ALLOC_SID(longer, NT_AUTH, 2, 32, 545), 0);
    EXPECT_EQ(ALLOC_SID(diffauth, NT_AUTH, 1, 0, 0), 0);        /* S-1-5-0: same length, different authority */
    cnt = 77;
    EXPECT_EQ(UN(RtlReplaceSidInSd)(&a.sd, longer, to, &cnt), 0); EXPECT_EQ(cnt, 0);   /* no match: count is cleared */
    cnt = 77;
    EXPECT_EQ(UN(RtlReplaceSidInSd)(&a.sd, diffauth, to, &cnt), 0); EXPECT_EQ(cnt, 0);
    cnt = 77;
    EXPECT_EQ(UN(RtlReplaceSidInSd)(&a.sd, from, to, &cnt), 0);
    EXPECT_EQ(cnt, 2);                                          /* group + one DACL ace */
    UN(RtlGetOwnerSecurityDescriptor)(&a.sd, &o, &def); CHECK(UN(RtlEqualSid)(o, a.owner));
    UN(RtlGetGroupSecurityDescriptor)(&a.sd, &g, &def); CHECK(UN(RtlEqualSid)(g, to));
    UN(RtlGetDaclSecurityDescriptor)(&a.sd, &present, &dacl, &def);
    UN(RtlGetAce)(dacl, 0, (PVOID *)&ace); CHECK(UN(RtlEqualSid)((PSID)ace->sid, to));
    UN(RtlGetAce)(dacl, 1, (PVOID *)&ace); CHECK(UN(RtlEqualSid)((PSID)ace->sid, a.other));
    /* the pattern no longer occurs */
    cnt = 77;
    EXPECT_EQ(UN(RtlReplaceSidInSd)(&a.sd, from, to, &cnt), 0); EXPECT_EQ(cnt, 0);
    /* the owner is replaced too; only the sub-authority words are copied, never the identifier authority */
    {
        PSID oldown, newown; ALLOC_SID(oldown, NT_AUTH, 2, 32, 544); ALLOC_SID(newown, NT_AUTH, 2, 32, 551);
        cnt = 77;
        EXPECT_EQ(UN(RtlReplaceSidInSd)(&a.sd, oldown, newown, &cnt), 0); EXPECT_EQ(cnt, 1);
        UN(RtlGetOwnerSecurityDescriptor)(&a.sd, &o, &def); CHECK(UN(RtlEqualSid)(o, newown));
        UN(RtlFreeSid)(oldown); UN(RtlFreeSid)(newown);
    }
    UN(RtlFreeSid)(from); UN(RtlFreeSid)(to); UN(RtlFreeSid)(longer); UN(RtlFreeSid)(diffauth);
    free_abs(&a);
}

/* ---------- RtlNewSecurityObject family ---------- */
static HANDLE open_token(void) {
    HANDLE h = NULL;
    if (UN(NtOpenProcessToken)((HANDLE)-1, TOKEN_QUERY, &h) < 0) return NULL;
    return h;
}
static PVOID query_token(HANDLE h, ULONG cls) {
    ULONG need = 0; PVOID p;
    UN(NtQueryInformationToken)(h, cls, NULL, 0, &need);
    if (!need) return NULL;
    p = calloc(1, need);
    if (p && UN(NtQueryInformationToken)(h, cls, p, need, &need) < 0) { free(p); return NULL; }
    return p;
}
#define NEWSEC_EXPORTS \
    SD_EXPORTS; REQUIRE(UN(RtlNewSecurityObject)); REQUIRE(UN(RtlDeleteSecurityObject)); \
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose))

TEST(new_security_object_defaults_from_token) {
    HANDLE tok; PSECURITY_DESCRIPTOR sd = NULL; TOKEN_OWNER *to; TOKEN_PRIMARY_GROUP *tg; TOKEN_DEFAULT_DACL *td;
    GENERIC_MAPPING m = FILE_MAP; PSID o = NULL, g = NULL; BOOLEAN def, present; PACL dacl = NULL;
    NEWSEC_EXPORTS;
    tok = open_token(); if (!tok) { t_skip("cannot open process token"); return; }
    to = query_token(tok, 4); tg = query_token(tok, 5); td = query_token(tok, 6);
    EXPECT_EQ(UN(RtlNewSecurityObject)(NULL, NULL, &sd, FALSE, tok, &m), 0);
    CHECK(sd != NULL);
    if (sd) {
        CHECK(UN(RtlValidSecurityDescriptor)(sd));
        EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def), 0);
        if (to) CHECK(o && UN(RtlEqualSid)(o, to->Owner));
        EXPECT_EQ(UN(RtlGetGroupSecurityDescriptor)(sd, &g, &def), 0);
        if (tg) CHECK(g && UN(RtlEqualSid)(g, tg->PrimaryGroup));
        EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def), 0);
        if (td && td->DefaultDacl) { EXPECT_EQ(present, TRUE); if (dacl) EXPECT_EQ(dacl->AceCount, td->DefaultDacl->AceCount); }
        EXPECT_EQ(UN(RtlDeleteSecurityObject)(&sd), 0);
    }
    free(to); free(tg); free(td);
    UN(NtClose)(tok);
}

TEST(new_security_object_creator_and_inheritance) {
    HANDLE tok; PSECURITY_DESCRIPTOR sd = NULL, parent_sd = NULL; ABSSD par; TOKEN_USER *tu; PSID everyone;
    UCHAR cacl[128], pacl[128]; SECURITY_DESCRIPTOR csd; GENERIC_MAPPING m = FILE_MAP;
    BOOLEAN def, present; PACL dacl = NULL; ACE_ *ace = NULL; NTSTATUS s;
    NEWSEC_EXPORTS;
    tok = open_token(); if (!tok) { t_skip("cannot open process token"); return; }
    tu = query_token(tok, 1);
    if (!tu) { UN(NtClose)(tok); t_skip("cannot query token user"); return; }
    EXPECT_EQ(ALLOC_SID(everyone, WORLD_AUTH, 1, 0, 0), 0);

    /* explicit creator DACL replaces the token default; generic bits are mapped */
    UN(RtlCreateSecurityDescriptor)(&csd, 1);
    make_acl(cacl, sizeof cacl);
    UN(RtlAddAccessAllowedAceEx)((PACL)cacl, 2, 0, GENERIC_READ, everyone);
    UN(RtlSetDaclSecurityDescriptor)(&csd, TRUE, (PACL)cacl, FALSE);
    UN(RtlSetOwnerSecurityDescriptor)(&csd, tu->User.Sid, FALSE);
    s = UN(RtlNewSecurityObject)(NULL, &csd, &sd, FALSE, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        PSID o = NULL;
        UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def); CHECK(o && UN(RtlEqualSid)(o, tu->User.Sid));
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        EXPECT_EQ(present, TRUE);
        if (dacl) {
            EXPECT_EQ(dacl->AceCount, 1);
            if (UN(RtlGetAce)(dacl, 0, (PVOID *)&ace) == 0) { EXPECT_EQ(ace->mask, FILE_GENERIC_READ); CHECK(UN(RtlEqualSid)((PSID)ace->sid, everyone)); }
        }
        UN(RtlDeleteSecurityObject)(&sd);
    }

    /* parent with an inheritable ace: container child receives it */
    memset(&par, 0, sizeof par);
    UN(RtlCreateSecurityDescriptor)(&par.sd, 1);
    make_acl(pacl, sizeof pacl);
    UN(RtlAddAccessAllowedAceEx)((PACL)pacl, 2, CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE, GENERIC_READ, everyone);
    UN(RtlSetDaclSecurityDescriptor)(&par.sd, TRUE, (PACL)pacl, FALSE);
    parent_sd = &par.sd;
    sd = NULL;
    s = UN(RtlNewSecurityObject)(parent_sd, NULL, &sd, TRUE, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        EXPECT_EQ(present, TRUE);
        if (dacl) {
            EXPECT_EQ(dacl->AceCount, 1);
            if (UN(RtlGetAce)(dacl, 0, (PVOID *)&ace) == 0) {
                EXPECT_EQ(ace->h.AceType, ACCESS_ALLOWED_ACE_TYPE);
                EXPECT_EQ(ace->mask, FILE_GENERIC_READ);
                EXPECT_EQ(ace->h.AceFlags & (INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE), 0);
                CHECK(UN(RtlEqualSid)((PSID)ace->sid, everyone));
            }
        }
        UN(RtlDeleteSecurityObject)(&sd);
    }
    /* the same parent for a non-container: a CONTAINER_INHERIT-only ace is not inherited, defaults apply */
    sd = NULL;
    s = UN(RtlNewSecurityObject)(parent_sd, NULL, &sd, FALSE, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        if (present && dacl) {
            BOOLEAN found = FALSE; ULONG i;
            for (i = 0; i < dacl->AceCount; i++)
                if (UN(RtlGetAce)(dacl, i, (PVOID *)&ace) == 0 && ace->h.AceType == ACCESS_ALLOWED_ACE_TYPE && UN(RtlEqualSid)((PSID)ace->sid, everyone) && ace->mask == FILE_GENERIC_READ) found = TRUE;
            EXPECT_EQ(found, FALSE);
        }
        UN(RtlDeleteSecurityObject)(&sd);
    }
    /* creator naming an owner the caller may not assign */
    {
        PSID admins; ALLOC_SID(admins, NT_AUTH, 2, 32, 544);
        UN(RtlCreateSecurityDescriptor)(&csd, 1);
        UN(RtlSetOwnerSecurityDescriptor)(&csd, everyone, FALSE);       /* Everyone is never a valid owner */
        sd = NULL;
        s = UN(RtlNewSecurityObject)(NULL, &csd, &sd, FALSE, tok, &m);
        EXPECT_EQ(s, S(0xC000005A));                                    /* STATUS_INVALID_OWNER */
        EXPECT_EQ(sd, NULL);
        UN(RtlFreeSid)(admins);
    }
    UN(RtlFreeSid)(everyone); free(tu); UN(NtClose)(tok);
}

TEST(new_security_object_ex_and_multiple_inheritance) {
    HANDLE tok; PSECURITY_DESCRIPTOR sd = NULL; GENERIC_MAPPING m = FILE_MAP; PSID everyone; UCHAR pacl[128]; SECURITY_DESCRIPTOR psd;
    BOOLEAN def, present; PACL dacl = NULL; ACE_ *ace = NULL; NTSTATUS s;
    NEWSEC_EXPORTS; REQUIRE(UN(RtlNewSecurityObjectEx)); REQUIRE(UN(RtlNewSecurityObjectWithMultipleInheritance));
    tok = open_token(); if (!tok) { t_skip("cannot open process token"); return; }
    EXPECT_EQ(ALLOC_SID(everyone, WORLD_AUTH, 1, 0, 0), 0);
    UN(RtlCreateSecurityDescriptor)(&psd, 1);
    make_acl(pacl, sizeof pacl);
    UN(RtlAddAccessAllowedAceEx)((PACL)pacl, 2, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, GENERIC_WRITE, everyone);
    UN(RtlSetDaclSecurityDescriptor)(&psd, TRUE, (PACL)pacl, FALSE);

    /* Ex without auto-inherit flags behaves like the plain variant for a non-container: effective mapped ace */
    s = UN(RtlNewSecurityObjectEx)(&psd, NULL, &sd, NULL, FALSE, 0, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        EXPECT_EQ(present, TRUE);
        if (dacl && dacl->AceCount >= 1 && UN(RtlGetAce)(dacl, 0, (PVOID *)&ace) == 0) {
            EXPECT_EQ(dacl->AceCount, 1);
            EXPECT_EQ(ace->mask, FILE_GENERIC_WRITE);
            CHECK(UN(RtlEqualSid)((PSID)ace->sid, everyone));
        } else CHECK(0);
        UN(RtlDeleteSecurityObject)(&sd);
    }
    /* auto-inherit (SEF_DACL_AUTO_INHERIT = 1): inherited aces carry INHERITED_ACE, descriptor is flagged auto-inherited */
    sd = NULL;
    s = UN(RtlNewSecurityObjectEx)(&psd, NULL, &sd, NULL, FALSE, 1, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        if (dacl && dacl->AceCount >= 1 && UN(RtlGetAce)(dacl, 0, (PVOID *)&ace) == 0) {
            CHECK((ace->h.AceFlags & INHERITED_ACE) != 0);
            EXPECT_EQ(ace->mask, FILE_GENERIC_WRITE);
        } else CHECK(0);
        CHECK((((SECURITY_DESCRIPTOR *)sd)->Control & SE_DACL_AUTO_INHERITED) != 0);
        UN(RtlDeleteSecurityObject)(&sd);
    }
    /* multiple-inheritance variant with no object types matches the plain Ex result */
    sd = NULL;
    s = UN(RtlNewSecurityObjectWithMultipleInheritance)(&psd, NULL, &sd, NULL, 0, FALSE, 0, tok, &m);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def);
        if (dacl && dacl->AceCount >= 1 && UN(RtlGetAce)(dacl, 0, (PVOID *)&ace) == 0) EXPECT_EQ(ace->mask, FILE_GENERIC_WRITE); else CHECK(0);
        UN(RtlDeleteSecurityObject)(&sd);
    }
    UN(RtlFreeSid)(everyone); UN(NtClose)(tok);
}

TEST(new_instance_security_object) {
    HANDLE tok; PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)1; GENERIC_MAPPING m = FILE_MAP; TOKEN_STATISTICS *st; LUID oldid, newid;
    NTSTATUS s;
    NEWSEC_EXPORTS; REQUIRE(UN(RtlNewInstanceSecurityObject));
    tok = open_token(); if (!tok) { t_skip("cannot open process token"); return; }
    st = query_token(tok, 10);
    if (!st) { UN(NtClose)(tok); t_skip("cannot query token statistics"); return; }
    oldid = st->ModifiedId; memset(&newid, 0xEE, sizeof newid);
    /* neither descriptor changed and the token is unchanged: no new descriptor is produced */
    s = UN(RtlNewInstanceSecurityObject)(FALSE, FALSE, &oldid, &newid, NULL, NULL, &sd, FALSE, tok, &m);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(sd, NULL);
    EXPECT_EQ(newid.LowPart, st->ModifiedId.LowPart); EXPECT_EQ(newid.HighPart, st->ModifiedId.HighPart);
    /* a changed parent descriptor forces a rebuild */
    sd = NULL; oldid = st->ModifiedId;
    s = UN(RtlNewInstanceSecurityObject)(TRUE, FALSE, &oldid, &newid, NULL, NULL, &sd, FALSE, tok, &m);
    EXPECT_EQ(s, 0);
    CHECK(sd != NULL);
    if (sd) UN(RtlDeleteSecurityObject)(&sd);
    /* a stale modified id forces a rebuild as well */
    sd = NULL; oldid.LowPart ^= 0x5A5A5A5A; oldid.HighPart ^= 0x1111;
    s = UN(RtlNewInstanceSecurityObject)(FALSE, FALSE, &oldid, &newid, NULL, NULL, &sd, FALSE, tok, &m);
    EXPECT_EQ(s, 0);
    CHECK(sd != NULL);
    if (sd) UN(RtlDeleteSecurityObject)(&sd);
    /* invalid token handle: the token query fails first */
    sd = (PSECURITY_DESCRIPTOR)1;
    s = UN(RtlNewInstanceSecurityObject)(TRUE, TRUE, &oldid, &newid, NULL, NULL, &sd, FALSE, (HANDLE)(ULONG_PTR)0xDEAD0, &m);
    EXPECT_EQ(s, S(0xC0000008));
    free(st); UN(NtClose)(tok);
}

TEST(new_security_granted_access) {
    HANDLE tok; GENERIC_MAPPING m = FILE_MAP; UCHAR buf[64]; ULONG len; ACCESS_MASK rem; NTSTATUS s; PRIVILEGE_SET *ps = (PRIVILEGE_SET *)buf;
    NEWSEC_EXPORTS; REQUIRE(UN(RtlNewSecurityGrantedAccess));
    tok = open_token(); if (!tok) { t_skip("cannot open process token"); return; }
    /* generic access is mapped; no privileges are needed, an empty set is returned */
    memset(buf, 0xAA, sizeof buf); len = sizeof buf; rem = 0xFFFFFFFF;
    s = UN(RtlNewSecurityGrantedAccess)(GENERIC_READ, ps, &len, tok, &m, &rem);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(rem, FILE_GENERIC_READ);
    EXPECT_EQ(ps->PrivilegeCount, 0);
    EXPECT_EQ(ps->Control, 0);
    /* buffer smaller than an empty PRIVILEGE_SET header (0x14): length reported, status too small */
    len = 0x13; rem = 0;
    s = UN(RtlNewSecurityGrantedAccess)(GENERIC_WRITE | 0x1, ps, &len, tok, &m, &rem);
    EXPECT_EQ(s, S(0xC0000023));
    EXPECT_EQ(len, 0x14);
    EXPECT_EQ(rem, FILE_GENERIC_WRITE | 1);
    /* ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege enabled; it is not enabled in a default token */
    len = sizeof buf; rem = 0;
    s = UN(RtlNewSecurityGrantedAccess)(ACCESS_SYSTEM_SECURITY, ps, &len, tok, &m, &rem);
    EXPECT_EQ(s, S(0xC0000061));
    UN(NtClose)(tok);
}
