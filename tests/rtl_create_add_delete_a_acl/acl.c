/* RtlAdd*Ace family, RtlCreateAndSetSD, boundary descriptors and token membership checks.
 * Everything works on private ACL buffers and duplicates of the caller's own token. */
#include "t.h"

UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessAllowedObjectAce, (PACL, ULONG, ULONG, ACCESS_MASK, GUID *, GUID *, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedObjectAce, (PACL, ULONG, ULONG, ACCESS_MASK, GUID *, GUID *, PSID));
UDECL(NTSTATUS, RtlAddAuditAccessAce, (PACL, ULONG, ACCESS_MASK, PSID, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, RtlAddAuditAccessAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, RtlAddAuditAccessObjectAce, (PACL, ULONG, ULONG, ACCESS_MASK, GUID *, GUID *, PSID, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, RtlAddAce, (PACL, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlAddCompoundAce, (PACL, ULONG, UCHAR, ACCESS_MASK, PSID, PSID));
UDECL(NTSTATUS, RtlAddMandatoryAce, (PACL, ULONG, ULONG, PSID, UCHAR, ACCESS_MASK));
UDECL(NTSTATUS, RtlAddProcessTrustLabelAce, (PACL, ULONG, ULONG, PSID, UCHAR, ACCESS_MASK));
UDECL(NTSTATUS, RtlAddAccessFilterAce, (PACL, ULONG, ULONG, PSID, UCHAR, ACCESS_MASK, PVOID, USHORT));
UDECL(NTSTATUS, RtlAddScopedPolicyIDAce, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddResourceAttributeAce, (PACL, ULONG, ULONG, ACCESS_MASK, PSID, PVOID, PULONG));
UDECL(NTSTATUS, RtlCreateAndSetSD, (PVOID, ULONG, PSID, PSID, PSECURITY_DESCRIPTOR *));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetSaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetAce, (PACL, ULONG, PVOID *));
UDECL(PVOID, RtlCreateBoundaryDescriptor, (PUNICODE_STRING, ULONG));
UDECL(VOID, RtlDeleteBoundaryDescriptor, (PVOID));
UDECL(NTSTATUS, RtlAddSIDToBoundaryDescriptor, (PVOID *, PSID));
UDECL(NTSTATUS, RtlAddIntegrityLabelToBoundaryDescriptor, (PVOID *, PSID));
UDECL(NTSTATUS, RtlCreateServiceSid, (PUNICODE_STRING, PSID, PULONG));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(ULONG, RtlLengthSid, (PSID));
UDECL(NTSTATUS, RtlCheckTokenMembership, (HANDLE, PSID, PBOOLEAN));
UDECL(NTSTATUS, RtlCheckTokenMembershipEx, (HANDLE, PSID, ULONG, PBOOLEAN));
UDECL(NTSTATUS, RtlCheckTokenCapability, (HANDLE, PSID, PBOOLEAN));
UDECL(VOID, RtlCheckSandboxedToken, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreatePrivateNamespace, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtDeletePrivateNamespace, (HANDLE));

#ifndef COMPOUND_ACE_IMPERSONATION
#define COMPOUND_ACE_IMPERSONATION 1
#endif
#define S(x)            ((NTSTATUS)(x))
#define ST_INVPARAM     S(0xC000000D)
#define ST_REVMISMATCH  S(0xC0000059)
#define ST_INVALID_ACL  S(0xC0000077)
#define ST_INVALID_SID  S(0xC0000078)
#define ST_ALLOTTED     S(0xC0000099)
#define ST_BUFSMALL     S(0xC0000023)

static BYTE SID_EVERYONE[12] = {1, 1, 0,0,0,0,0,1, 0,0,0,0};
static BYTE SID_ADMINS[16]   = {1, 2, 0,0,0,0,0,5, 32,0,0,0, 0x20,0x02,0,0};
static BYTE SID_LOWLABEL[12] = {1, 1, 0,0,0,0,0,16, 0x00,0x10,0,0};   /* S-1-16-4096 */
static BYTE SID_PTLABEL[16]  = {1, 2, 0,0,0,0,0,19, 0x00,0x02,0,0, 0x00,0x20,0,0}; /* S-1-19-512-8192 */
static BYTE SID_POLICY[12]   = {1, 1, 0,0,0,0,0,17, 1,0,0,0};          /* S-1-17-1 */
static BYTE SID_BADCOUNT[12] = {1, 16, 0,0,0,0,0,1, 0,0,0,0};          /* 16 subauthorities: invalid */
static BYTE SID_BADREV[12]   = {2, 1, 0,0,0,0,0,1, 0,0,0,0};
static GUID G1 = {0x11111111, 0x2222, 0x3333, {1,2,3,4,5,6,7,8}};
static GUID G2 = {0xaaaaaaaa, 0xbbbb, 0xcccc, {8,7,6,5,4,3,2,1}};

typedef struct { BYTE AceType, AceFlags; USHORT AceSize; ULONG Mask; } KACE;


#define ACLBUF(name, size) static BYTE name[size] __attribute__((aligned(8)))
static PACL mkacl(BYTE *b, ULONG size, ULONG rev) {
    memset(b, 0xCC, size);
    NTSTATUS s = UN(RtlCreateAcl)((PACL)b, size, rev);
    EXPECT_EQ(s, 0);
    return (PACL)b;
}
static KACE *ace_at(PACL acl, ULONG i) {
    PVOID p = NULL;
    NTSTATUS s = UN(RtlGetAce)(acl, i, &p);
    EXPECT_EQ(s, 0);
    return (KACE *)p;
}
#define NEED_ACE_API \
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlGetAce)); REQUIRE(UN(RtlEqualSid))

/* ---- simple known ACEs (RtlpAddKnownAce) ---- */
TEST(rtl_ace_allowed_ex_layout) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAccessAllowedAceEx));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 2);
    NTSTATUS s = UN(RtlAddAccessAllowedAceEx)(acl, 2, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, 0x1234, SID_EVERYONE);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1); EXPECT_EQ(acl->AclRevision, 2);
    KACE *a = ace_at(acl, 0);
    if (a) {
        EXPECT_EQ(a->AceType, ACCESS_ALLOWED_ACE_TYPE); EXPECT_EQ(a->AceFlags, 3);
        EXPECT_EQ(a->AceSize, 8 + 12); EXPECT_EQ(a->Mask, 0x1234);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_EVERYONE), TRUE);
    }
    /* second ACE is appended after the first */
    s = UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x5, SID_ADMINS);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 2);
    KACE *a2 = ace_at(acl, 1);
    if (a && a2) { EXPECT_EQ((BYTE *)a2, (BYTE *)a + a->AceSize); EXPECT_EQ(a2->AceSize, 8 + 16); }
    /* a higher revision raises the ACL revision, never lowers it */
    s = UN(RtlAddAccessAllowedAceEx)(acl, 3, 0, 0x7, SID_EVERYONE);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AclRevision, 3);
    s = UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x7, SID_EVERYONE);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AclRevision, 3); EXPECT_EQ(acl->AceCount, 4);
}
TEST(rtl_ace_allowed_ex_errors) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAccessAllowedAceEx));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, SID_BADCOUNT), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 1, SID_BADREV), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 5, 0, 1, SID_EVERYONE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0x40, 1, SID_EVERYONE), ST_INVPARAM);   /* audit flags are invalid on allow ACEs */
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0x80, 1, SID_EVERYONE), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0x10, 1, SID_EVERYONE), 0);             /* INHERITED_ACE is accepted */
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0x20, 1, SID_EVERYONE), 0);             /* bit 0x20 is accepted on allow ACEs only */
    EXPECT_EQ(acl->AceCount, 2);
    /* ACL with a bad revision */
    ACLBUF(b2, 64); PACL bad = mkacl(b2, 64, 2); bad->AclRevision = 1;
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(bad, 2, 0, 1, SID_EVERYONE), ST_INVALID_ACL);
    /* no room: 8-byte header + 8 bytes free cannot take a 20-byte ACE */
    ACLBUF(b3, 16); PACL tiny = mkacl(b3, 16, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(tiny, 2, 0, 1, SID_EVERYONE), ST_ALLOTTED);
    EXPECT_EQ(tiny->AceCount, 0);
    /* exactly fitting ACL: 8 + 20 */
    ACLBUF(b4, 28); PACL fit = mkacl(b4, 28, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(fit, 2, 0, 1, SID_EVERYONE), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(fit, 2, 0, 1, SID_EVERYONE), ST_ALLOTTED);
    EXPECT_EQ(fit->AceCount, 1);
}
TEST(rtl_ace_denied_ex) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAccessDeniedAceEx));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 2);
    NTSTATUS s = UN(RtlAddAccessDeniedAceEx)(acl, 2, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, 0xF0, SID_ADMINS);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, ACCESS_DENIED_ACE_TYPE); EXPECT_EQ(a->AceFlags, 9); EXPECT_EQ(a->AceSize, 24); EXPECT_EQ(a->Mask, 0xF0);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_ADMINS), TRUE); }
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(acl, 2, 0x40, 1, SID_ADMINS), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(acl, 2, 0x20, 1, SID_ADMINS), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(acl, 2, 0, 1, SID_BADCOUNT), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(acl, 6, 0, 1, SID_ADMINS), ST_REVMISMATCH);
    EXPECT_EQ(acl->AceCount, 1);
}

/* ---- audit ACEs ---- */
TEST(rtl_ace_audit) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAuditAccessAce)); REQUIRE(UN(RtlAddAuditAccessAceEx));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 2);
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 0x11, SID_EVERYONE, TRUE, FALSE), 0);
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 0x22, SID_EVERYONE, FALSE, TRUE), 0);
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 0x33, SID_EVERYONE, TRUE, TRUE), 0);
    EXPECT_EQ(UN(RtlAddAuditAccessAce)(acl, 2, 0x44, SID_EVERYONE, FALSE, FALSE), 0);
    EXPECT_EQ(acl->AceCount, 4);
    static const BYTE want_flags[4] = {SUCCESSFUL_ACCESS_ACE_FLAG, FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG, 0};
    for (ULONG i = 0; i < 4; i++) {
        KACE *a = ace_at(acl, i);
        if (a) { EXPECT_EQ(a->AceType, SYSTEM_AUDIT_ACE_TYPE); EXPECT_EQ(a->AceFlags, want_flags[i]); EXPECT_EQ(a->Mask, 0x11 * (i + 1)); EXPECT_EQ(a->AceSize, 20); }
    }
    /* Ex: inheritance flags are combined with the audit flags */
    ACLBUF(b2, 256); PACL acl2 = mkacl(b2, 256, 2);
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 2, CONTAINER_INHERIT_ACE, 0x9, SID_ADMINS, TRUE, TRUE), 0);
    KACE *e = ace_at(acl2, 0);
    if (e) { EXPECT_EQ(e->AceType, SYSTEM_AUDIT_ACE_TYPE); EXPECT_EQ(e->AceFlags, 0xC2); EXPECT_EQ(e->AceSize, 24); }
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 2, 0x40, 0x9, SID_ADMINS, FALSE, FALSE), 0);   /* explicit audit flag in Flags is allowed */
    KACE *e2 = ace_at(acl2, 1);
    if (e2) EXPECT_EQ(e2->AceFlags, 0x40);
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 2, 0x10, 0x9, SID_ADMINS, FALSE, FALSE), 0);          /* INHERITED_ACE */
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 2, 0x20, 0x9, SID_ADMINS, FALSE, FALSE), ST_INVPARAM); /* bit 0x20 is rejected on audit ACEs */
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 5, 0, 0x9, SID_ADMINS, FALSE, FALSE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddAuditAccessAceEx)(acl2, 2, 0, 0x9, SID_BADCOUNT, FALSE, FALSE), ST_INVALID_SID);
    EXPECT_EQ(acl2->AceCount, 3);
}

/* ---- object ACEs ---- */
TEST(rtl_ace_object_allowed_denied) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAccessAllowedObjectAce)); REQUIRE(UN(RtlAddAccessDeniedObjectAce));
    ACLBUF(b, 512); PACL acl = mkacl(b, 512, 4);
    /* both GUIDs: type 5, flags dword 3, two GUIDs then the SID */
    NTSTATUS s = UN(RtlAddAccessAllowedObjectAce)(acl, 4, 2, 0x100, &G1, &G2, SID_EVERYONE);
    EXPECT_EQ(s, 0);
    KACE *a = ace_at(acl, 0);
    if (a) {
        EXPECT_EQ(a->AceType, ACCESS_ALLOWED_OBJECT_ACE_TYPE); EXPECT_EQ(a->AceFlags, 2); EXPECT_EQ(a->Mask, 0x100);
        EXPECT_EQ(a->AceSize, 12 + 16 + 16 + 12);
        BYTE *p = (BYTE *)a + 8;
        EXPECT_EQ(*(ULONG *)p, 3);
        EXPECT_EQ(memcmp(p + 4, &G1, 16), 0); EXPECT_EQ(memcmp(p + 20, &G2, 16), 0);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)(p + 36), SID_EVERYONE), TRUE);
    }
    /* only the object type */
    s = UN(RtlAddAccessAllowedObjectAce)(acl, 4, 0, 0x200, &G1, NULL, SID_ADMINS);
    EXPECT_EQ(s, 0);
    KACE *a1 = ace_at(acl, 1);
    if (a1) { EXPECT_EQ(a1->AceType, ACCESS_ALLOWED_OBJECT_ACE_TYPE); EXPECT_EQ(a1->AceSize, 12 + 16 + 16); EXPECT_EQ(*(ULONG *)((BYTE *)a1 + 8), 1);
        EXPECT_EQ(memcmp((BYTE *)a1 + 12, &G1, 16), 0); }
    /* only the inherited object type */
    s = UN(RtlAddAccessAllowedObjectAce)(acl, 4, 0, 0x200, NULL, &G2, SID_EVERYONE);
    EXPECT_EQ(s, 0);
    KACE *a2 = ace_at(acl, 2);
    if (a2) { EXPECT_EQ(a2->AceSize, 12 + 16 + 12); EXPECT_EQ(*(ULONG *)((BYTE *)a2 + 8), 2);
        EXPECT_EQ(memcmp((BYTE *)a2 + 12, &G2, 16), 0); }
    /* neither GUID: degenerates into a plain access-allowed ACE */
    s = UN(RtlAddAccessAllowedObjectAce)(acl, 4, 0, 0x300, NULL, NULL, SID_EVERYONE);
    EXPECT_EQ(s, 0);
    KACE *a3 = ace_at(acl, 3);
    if (a3) { EXPECT_EQ(a3->AceType, ACCESS_ALLOWED_ACE_TYPE); EXPECT_EQ(a3->AceSize, 20); EXPECT_EQ(a3->Mask, 0x300); }
    /* denied object ACE */
    s = UN(RtlAddAccessDeniedObjectAce)(acl, 4, 1, 0x400, &G2, &G1, SID_ADMINS);
    EXPECT_EQ(s, 0);
    KACE *a4 = ace_at(acl, 4);
    if (a4) { EXPECT_EQ(a4->AceType, ACCESS_DENIED_OBJECT_ACE_TYPE); EXPECT_EQ(a4->AceFlags, 1); EXPECT_EQ(a4->AceSize, 12 + 32 + 16);
        EXPECT_EQ(memcmp((BYTE *)a4 + 12, &G2, 16), 0); EXPECT_EQ(memcmp((BYTE *)a4 + 28, &G1, 16), 0); }
    EXPECT_EQ(UN(RtlAddAccessDeniedObjectAce)(acl, 4, 0, 1, NULL, NULL, SID_ADMINS), 0);
    KACE *a5 = ace_at(acl, 5);
    if (a5) EXPECT_EQ(a5->AceType, ACCESS_DENIED_ACE_TYPE);
    EXPECT_EQ(acl->AceCount, 6); EXPECT_EQ(acl->AclRevision, 4);
    /* errors */
    EXPECT_EQ(UN(RtlAddAccessAllowedObjectAce)(acl, 4, 0, 1, &G1, NULL, SID_BADCOUNT), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddAccessAllowedObjectAce)(acl, 3, 0, 1, &G1, NULL, SID_EVERYONE), ST_REVMISMATCH);  /* object ACEs need revision 4 */
    EXPECT_EQ(UN(RtlAddAccessAllowedObjectAce)(acl, 2, 0, 1, &G1, NULL, SID_EVERYONE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddAccessAllowedObjectAce)(acl, 4, 0x40, 1, &G1, NULL, SID_EVERYONE), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessDeniedObjectAce)(acl, 4, 0x40, 1, &G1, NULL, SID_EVERYONE), ST_INVPARAM);
    EXPECT_EQ(acl->AceCount, 6);
    ACLBUF(bs, 40); PACL small = mkacl(bs, 40, 4);
    EXPECT_EQ(UN(RtlAddAccessAllowedObjectAce)(small, 4, 0, 1, &G1, &G2, SID_EVERYONE), ST_ALLOTTED);
    EXPECT_EQ(small->AceCount, 0);
}
TEST(rtl_ace_audit_object) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAuditAccessObjectAce));
    ACLBUF(b, 512); PACL acl = mkacl(b, 512, 4);
    NTSTATUS s = UN(RtlAddAuditAccessObjectAce)(acl, 4, 1, 0x55, &G1, &G2, SID_EVERYONE, TRUE, TRUE);
    EXPECT_EQ(s, 0);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, SYSTEM_AUDIT_OBJECT_ACE_TYPE); EXPECT_EQ(a->AceFlags, 0xC1); EXPECT_EQ(a->Mask, 0x55);
        EXPECT_EQ(a->AceSize, 12 + 32 + 12); EXPECT_EQ(*(ULONG *)((BYTE *)a + 8), 3); }
    s = UN(RtlAddAuditAccessObjectAce)(acl, 4, 0, 0x66, &G1, NULL, SID_ADMINS, FALSE, TRUE);
    EXPECT_EQ(s, 0);
    KACE *a1 = ace_at(acl, 1);
    if (a1) { EXPECT_EQ(a1->AceType, SYSTEM_AUDIT_OBJECT_ACE_TYPE); EXPECT_EQ(a1->AceFlags, 0x80); EXPECT_EQ(a1->AceSize, 12 + 16 + 16); }
    s = UN(RtlAddAuditAccessObjectAce)(acl, 4, 0, 0x77, NULL, NULL, SID_EVERYONE, TRUE, FALSE);
    EXPECT_EQ(s, 0);
    KACE *a2 = ace_at(acl, 2);
    if (a2) { EXPECT_EQ(a2->AceType, SYSTEM_AUDIT_ACE_TYPE); EXPECT_EQ(a2->AceFlags, 0x40); EXPECT_EQ(a2->AceSize, 20); }
    EXPECT_EQ(acl->AceCount, 3);
    EXPECT_EQ(UN(RtlAddAuditAccessObjectAce)(acl, 4, 0x20, 1, &G1, NULL, SID_EVERYONE, TRUE, TRUE), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAuditAccessObjectAce)(acl, 3, 0, 1, &G1, NULL, SID_EVERYONE, TRUE, TRUE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddAuditAccessObjectAce)(acl, 4, 0, 1, &G1, NULL, SID_BADREV, TRUE, TRUE), ST_INVALID_SID);
    EXPECT_EQ(acl->AceCount, 3);
}

/* ---- RtlAddAce ---- */
static ULONG ace_list_bytes(PACL acl) {
    ULONG n = 0;
    for (ULONG i = 0; i < acl->AceCount; i++) { KACE *a = ace_at(acl, i); if (a) n += a->AceSize; }
    return n;
}
TEST(rtl_addace_insert_append) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAce)); REQUIRE(UN(RtlAddAccessAllowedAceEx)); REQUIRE(UN(RtlAddAccessDeniedAceEx));
    ACLBUF(sb, 256); PACL src = mkacl(sb, 256, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(src, 2, 0, 0x1, SID_EVERYONE), 0);
    EXPECT_EQ(UN(RtlAddAccessDeniedAceEx)(src, 2, 0, 0x2, SID_ADMINS), 0);
    ULONG len = ace_list_bytes(src); EXPECT_EQ(len, 20 + 24);
    ACLBUF(db, 256); PACL dst = mkacl(db, 256, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(dst, 2, 0, 0x4, SID_EVERYONE), 0);
    /* insert at the front */
    NTSTATUS s = UN(RtlAddAce)(dst, 2, 0, ace_at(src, 0), len);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AceCount, 3);
    KACE *a;
    if ((a = ace_at(dst, 0))) { EXPECT_EQ(a->Mask, 1); EXPECT_EQ(a->AceType, ACCESS_ALLOWED_ACE_TYPE); }
    if ((a = ace_at(dst, 1))) { EXPECT_EQ(a->Mask, 2); EXPECT_EQ(a->AceType, ACCESS_DENIED_ACE_TYPE); }
    if ((a = ace_at(dst, 2))) { EXPECT_EQ(a->Mask, 4); }
    /* append with MAXULONG */
    s = UN(RtlAddAce)(dst, 2, 0xFFFFFFFF, ace_at(src, 0), 20);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AceCount, 4);
    if ((a = ace_at(dst, 3))) { EXPECT_EQ(a->Mask, 1); EXPECT_EQ(a->AceSize, 20); }
    /* insert in the middle */
    s = UN(RtlAddAce)(dst, 2, 2, ace_at(src, 1), 24);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AceCount, 5);
    if ((a = ace_at(dst, 2))) { EXPECT_EQ(a->Mask, 2); EXPECT_EQ(a->AceType, ACCESS_DENIED_ACE_TYPE); }
    if ((a = ace_at(dst, 3))) { EXPECT_EQ(a->Mask, 4); }
    /* an index past the end appends */
    s = UN(RtlAddAce)(dst, 2, 100, ace_at(src, 0), 20);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AceCount, 6);
    if ((a = ace_at(dst, 5))) EXPECT_EQ(a->Mask, 1);
    /* empty list: success, no change */
    s = UN(RtlAddAce)(dst, 2, 0, ace_at(src, 0), 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AceCount, 6);
    /* revision is raised, not lowered */
    EXPECT_EQ(dst->AclRevision, 2);
    s = UN(RtlAddAce)(dst, 3, 0xFFFFFFFF, ace_at(src, 0), 20);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AclRevision, 3);
    s = UN(RtlAddAce)(dst, 2, 0xFFFFFFFF, ace_at(src, 0), 20);
    EXPECT_EQ(s, 0); EXPECT_EQ(dst->AclRevision, 3); EXPECT_EQ(dst->AceCount, 8);
}
TEST(rtl_addace_errors) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAce)); REQUIRE(UN(RtlAddAccessAllowedAceEx));
    ACLBUF(sb, 128); PACL src = mkacl(sb, 128, 2);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(src, 2, 0, 0x1, SID_EVERYONE), 0);
    /* list length that ends in the middle of an ACE */
    ACLBUF(db, 128); PACL dst = mkacl(db, 128, 2);
    EXPECT_EQ(UN(RtlAddAce)(dst, 2, 0, ace_at(src, 0), 19), ST_INVPARAM);
    EXPECT_EQ(dst->AceCount, 0);
    /* destination too small */
    ACLBUF(tb, 24); PACL tiny = mkacl(tb, 24, 2);
    EXPECT_EQ(UN(RtlAddAce)(tiny, 2, 0, ace_at(src, 0), 20), ST_BUFSMALL);
    EXPECT_EQ(tiny->AceCount, 0);
    /* destination has an invalid revision */
    dst->AclRevision = 7;
    EXPECT_EQ(UN(RtlAddAce)(dst, 2, 0, ace_at(src, 0), 20), ST_INVPARAM);
    dst->AclRevision = 2;
    EXPECT_EQ(UN(RtlAddAce)(dst, 2, 0, ace_at(src, 0), 20), 0);
}

/* ---- ACEs that only exist in revision 3/4 ACLs ---- */
TEST(rtl_ace_compound) {
    NEED_ACE_API; REQUIRE(UN(RtlAddCompoundAce));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 3);
    NTSTATUS s = UN(RtlAddCompoundAce)(acl, 3, COMPOUND_ACE_IMPERSONATION, 0x42, SID_EVERYONE, SID_ADMINS);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1); EXPECT_EQ(acl->AclRevision, 3);
    KACE *a = ace_at(acl, 0);
    if (a) {
        EXPECT_EQ(a->AceType, ACCESS_ALLOWED_COMPOUND_ACE_TYPE); EXPECT_EQ(a->AceFlags, 0);
        EXPECT_EQ(a->AceSize, 12 + 12 + 16); EXPECT_EQ(a->Mask, 0x42);
        EXPECT_EQ(*(USHORT *)((BYTE *)a + 8), COMPOUND_ACE_IMPERSONATION);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 12), SID_EVERYONE), TRUE);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 24), SID_ADMINS), TRUE);
    }
    EXPECT_EQ(UN(RtlAddCompoundAce)(acl, 4, COMPOUND_ACE_IMPERSONATION, 1, SID_ADMINS, SID_EVERYONE), 0);
    EXPECT_EQ(acl->AclRevision, 4);
    EXPECT_EQ(UN(RtlAddCompoundAce)(acl, 2, COMPOUND_ACE_IMPERSONATION, 1, SID_ADMINS, SID_EVERYONE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddCompoundAce)(acl, 5, COMPOUND_ACE_IMPERSONATION, 1, SID_ADMINS, SID_EVERYONE), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddCompoundAce)(acl, 3, COMPOUND_ACE_IMPERSONATION, 1, SID_BADCOUNT, SID_EVERYONE), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddCompoundAce)(acl, 3, COMPOUND_ACE_IMPERSONATION, 1, SID_EVERYONE, SID_BADREV), ST_INVALID_SID);
    ACLBUF(b2, 40); PACL small = mkacl(b2, 40, 3);
    EXPECT_EQ(UN(RtlAddCompoundAce)(small, 3, COMPOUND_ACE_IMPERSONATION, 1, SID_EVERYONE, SID_ADMINS), ST_ALLOTTED);
    EXPECT_EQ(acl->AceCount, 2);
}
TEST(rtl_ace_mandatory_label) {
    NEED_ACE_API; REQUIRE(UN(RtlAddMandatoryAce));
    ACLBUF(b, 128); PACL acl = mkacl(b, 128, 2);
    NTSTATUS s = UN(RtlAddMandatoryAce)(acl, 2, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, SYSTEM_MANDATORY_LABEL_ACE_TYPE); EXPECT_EQ(a->AceFlags, 0); EXPECT_EQ(a->Mask, 1); EXPECT_EQ(a->AceSize, 20);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_LOWLABEL), TRUE); }
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 7), 0);
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 8), ST_INVPARAM);     /* only the three policy bits */
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_LOWLABEL, 0x10, 1), ST_INVPARAM);                               /* wrong AceType */
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_LOWLABEL, 0x12, 1), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0x20, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_INVPARAM);  /* flags beyond the low five */
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_EVERYONE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_INVPARAM);    /* not a label SID */
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 2, 0, SID_BADCOUNT, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddMandatoryAce)(acl, 5, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddMandatoryAce)(NULL, 2, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_INVALID_ACL);
    EXPECT_EQ(acl->AceCount, 2);
    ACLBUF(b2, 16); PACL tiny = mkacl(b2, 16, 2);
    EXPECT_EQ(UN(RtlAddMandatoryAce)(tiny, 2, 0, SID_LOWLABEL, SYSTEM_MANDATORY_LABEL_ACE_TYPE, 1), ST_ALLOTTED);
}
TEST(rtl_ace_process_trust_label) {
    NEED_ACE_API; REQUIRE(UN(RtlAddProcessTrustLabelAce));
    ACLBUF(b, 128); PACL acl = mkacl(b, 128, 4);
    NTSTATUS s = UN(RtlAddProcessTrustLabelAce)(acl, 4, 0, SID_PTLABEL, 0x14, 0x3);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, 0x14); EXPECT_EQ(a->Mask, 3); EXPECT_EQ(a->AceSize, 8 + 16);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_PTLABEL), TRUE); }
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 4, 0, SID_PTLABEL, 0x11, 3), ST_INVPARAM);          /* wrong AceType */
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 4, 0, SID_EVERYONE, 0x14, 3), ST_INVPARAM);         /* not a trust-label SID */
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 4, 0, SID_BADCOUNT, 0x14, 3), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 5, 0, SID_PTLABEL, 0x14, 3), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 4, 0x20, SID_PTLABEL, 0x14, 3), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(acl, 4, 0, SID_PTLABEL, 0x14, 0x01000000), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddProcessTrustLabelAce)(NULL, 4, 0, SID_PTLABEL, 0x14, 3), ST_INVALID_ACL);
    EXPECT_EQ(acl->AceCount, 1);
}
TEST(rtl_ace_access_filter) {
    NEED_ACE_API; REQUIRE(UN(RtlAddAccessFilterAce));
    ACLBUF(b, 256); PACL acl = mkacl(b, 256, 4);
    static const BYTE cond[8] = {'a', 'r', 't', 'x', 0, 0, 0, 0};
    NTSTATUS s = UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_EVERYONE, 0x15, 0x1F, (PVOID)cond, sizeof cond);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, 0x15); EXPECT_EQ(a->Mask, 0x1F); EXPECT_EQ(a->AceSize, 20 + 8);
        EXPECT_EQ(memcmp((BYTE *)a + 20, cond, 8), 0); }
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_EVERYONE, 0x14, 1, (PVOID)cond, 8), ST_INVPARAM);
    static const BYTE badcond[8] = {'x', 'x', 'x', 'x', 0, 0, 0, 0};
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_EVERYONE, 0x15, 1, (PVOID)badcond, 8), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_EVERYONE, 0x15, 1, NULL, 8), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_EVERYONE, 0x15, 1, (PVOID)cond, 4), ST_INVPARAM);   /* condition shorter than 6 bytes */
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_ADMINS, 0x15, 1, (PVOID)cond, 8), ST_INVPARAM);     /* only Everyone is accepted without the trust flag */
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 4, 0, SID_BADCOUNT, 0x15, 1, (PVOID)cond, 8), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(acl, 5, 0, SID_EVERYONE, 0x15, 1, (PVOID)cond, 8), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddAccessFilterAce)(NULL, 4, 0, SID_EVERYONE, 0x15, 1, (PVOID)cond, 8), ST_INVALID_ACL);
    EXPECT_EQ(acl->AceCount, 1);
}
TEST(rtl_ace_scoped_policy_id) {
    NEED_ACE_API; REQUIRE(UN(RtlAddScopedPolicyIDAce));
    ACLBUF(b, 128); PACL acl = mkacl(b, 128, 4);
    NTSTATUS s = UN(RtlAddScopedPolicyIDAce)(acl, 4, 0, 0, SID_POLICY);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, 0x13); EXPECT_EQ(a->Mask, 0); EXPECT_EQ(a->AceSize, 20);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_POLICY), TRUE); }
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(acl, 4, 0, 1, SID_POLICY), ST_INVPARAM);        /* access mask must be zero */
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(acl, 4, 0, 0, SID_EVERYONE), ST_INVPARAM);      /* wrong SID authority */
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(acl, 4, 0x20, 0, SID_POLICY), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(acl, 4, 0, 0, SID_BADCOUNT), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(acl, 5, 0, 0, SID_POLICY), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddScopedPolicyIDAce)(NULL, 4, 0, 0, SID_POLICY), ST_INVALID_ACL);
    EXPECT_EQ(acl->AceCount, 1);
}
typedef struct { PWSTR Name; USHORT ValueType; USHORT Reserved; ULONG Flags; ULONG ValueCount; PLONG64 pInt64; } CSA_V1;
typedef struct { USHORT Version; USHORT Reserved; ULONG AttributeCount; CSA_V1 *pAttributeV1; } CSA_INFO;
TEST(rtl_ace_resource_attribute) {
    NEED_ACE_API; REQUIRE(UN(RtlAddResourceAttributeAce));
    ACLBUF(b, 512); PACL acl = mkacl(b, 512, 4);
    static WCHAR nm[] = L"Project"; LONG64 val = 42;
    CSA_V1 at = {nm, 1 /* INT64 */, 0, 0, 1, &val};
    CSA_INFO info = {1, 0, 1, &at};
    ULONG ret = 0xFFFFFFFF;
    NTSTATUS s = UN(RtlAddResourceAttributeAce)(acl, 4, 0, 0, SID_EVERYONE, &info, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(acl->AceCount, 1);
    KACE *a = ace_at(acl, 0);
    if (a) { EXPECT_EQ(a->AceType, 0x12); EXPECT_EQ(a->Mask, 0);
        EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_EVERYONE), TRUE);
        EXPECT_EQ(ret, 8 + a->AceSize);   /* required size = ACL header + all ACEs */ }
    ULONG ret2 = 0xFFFFFFFF;
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 4, 0, 0, SID_EVERYONE, &info, NULL), ST_INVPARAM);        /* ReturnLength is mandatory */
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 4, 0, 1, SID_EVERYONE, &info, &ret2), ST_INVPARAM);       /* mask must be 0 */
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 4, 0, 0, SID_ADMINS, &info, &ret2), ST_INVPARAM);         /* only Everyone */
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 4, 0, 0, SID_BADCOUNT, &info, &ret2), ST_INVALID_SID);
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 5, 0, 0, SID_EVERYONE, &info, &ret2), ST_REVMISMATCH);
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(NULL, 4, 0, 0, SID_EVERYONE, &info, &ret2), ST_INVALID_ACL);
    CSA_INFO badver = {2, 0, 1, &at};
    EXPECT_EQ(UN(RtlAddResourceAttributeAce)(acl, 4, 0, 0, SID_EVERYONE, &badver, &ret2), ST_INVPARAM);
    /* too small an ACL: reports the needed size and fails */
    ACLBUF(b2, 24); PACL tiny = mkacl(b2, 24, 4);
    ULONG need = 0;
    s = UN(RtlAddResourceAttributeAce)(tiny, 4, 0, 0, SID_EVERYONE, &info, &need);
    EXPECT_EQ(s, ST_ALLOTTED); EXPECT_EQ(need, ret); EXPECT_EQ(tiny->AceCount, 0);
}

/* ---- RtlCreateAndSetSD ---- */
typedef struct { UCHAR AceType, InheritFlags, AceFlags; ACCESS_MASK Mask; PSID *Sid; } ACE_DATA;
TEST(rtl_create_and_set_sd) {
    REQUIRE(UN(RtlCreateAndSetSD)); NEED_ACE_API;
    REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlGetGroupSecurityDescriptor));
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UN(RtlGetSaclSecurityDescriptor));
    PSID everyone = SID_EVERYONE, admins = SID_ADMINS;
    ACE_DATA ad[3];
    ad[0] = (ACE_DATA){ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, 0, 0x1F01FF, &everyone};
    ad[1] = (ACE_DATA){ACCESS_DENIED_ACE_TYPE, 0, 0, 0x2, &admins};
    ad[2] = (ACE_DATA){SYSTEM_AUDIT_ACE_TYPE, 0, SUCCESSFUL_ACCESS_ACE_FLAG, 0x10, &everyone};
    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS s = UN(RtlCreateAndSetSD)(ad, 3, admins, everyone, &sd);
    EXPECT_EQ(s, 0); EXPECT_NE(sd, NULL);
    if (s == 0 && sd) {
        PSID o = NULL, g = NULL; BOOLEAN def = TRUE, pres = FALSE; PACL dacl = NULL, sacl = NULL;
        EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def), 0); EXPECT_EQ(o, admins); EXPECT_EQ(def, FALSE);
        EXPECT_EQ(UN(RtlGetGroupSecurityDescriptor)(sd, &g, &def), 0); EXPECT_EQ(g, everyone);
        EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(sd, &pres, &dacl, &def), 0);
        EXPECT_EQ(pres, TRUE);
        if (pres && dacl) {
            EXPECT_EQ(dacl->AceCount, 2); EXPECT_EQ(dacl->AclRevision, 2);
            KACE *a = ace_at(dacl, 0);
            if (a) { EXPECT_EQ(a->AceType, ACCESS_ALLOWED_ACE_TYPE); EXPECT_EQ(a->AceFlags, CONTAINER_INHERIT_ACE); EXPECT_EQ(a->Mask, 0x1F01FF); }
            a = ace_at(dacl, 1);
            if (a) { EXPECT_EQ(a->AceType, ACCESS_DENIED_ACE_TYPE); EXPECT_EQ(a->Mask, 2);
                EXPECT_EQ(UN(RtlEqualSid)((PSID)((BYTE *)a + 8), SID_ADMINS), TRUE); }
        }
        EXPECT_EQ(UN(RtlGetSaclSecurityDescriptor)(sd, &pres, &sacl, &def), 0);
        EXPECT_EQ(pres, TRUE);
        if (pres && sacl) {
            EXPECT_EQ(sacl->AceCount, 1);
            KACE *a = ace_at(sacl, 0);
            if (a) { EXPECT_EQ(a->AceType, SYSTEM_AUDIT_ACE_TYPE); EXPECT_EQ(a->AceFlags, SUCCESSFUL_ACCESS_ACE_FLAG); EXPECT_EQ(a->Mask, 0x10); }
        }
        HeapFree(GetProcessHeap(), 0, sd);
    }
    /* no ACEs: a NULL DACL (everyone allowed) with no SACL */
    sd = NULL;
    s = UN(RtlCreateAndSetSD)(NULL, 0, NULL, NULL, &sd);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        BOOLEAN def, pres = FALSE; PACL dacl = (PACL)1;
        EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(sd, &pres, &dacl, &def), 0);
        EXPECT_EQ(pres, TRUE); EXPECT_EQ(dacl, NULL);
        PACL sacl = (PACL)1;
        EXPECT_EQ(UN(RtlGetSaclSecurityDescriptor)(sd, &pres, &sacl, &def), 0);
        EXPECT_EQ(pres, FALSE);
        PSID o = (PSID)1;
        EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def), 0); EXPECT_EQ(o, NULL);
        HeapFree(GetProcessHeap(), 0, sd);
    }
    /* an unsupported AceType is rejected */
    ad[0].AceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
    sd = NULL;
    s = UN(RtlCreateAndSetSD)(ad, 1, NULL, NULL, &sd);
    EXPECT_EQ(s, ST_INVPARAM);
}

/* ---- boundary descriptors ---- */
TEST(rtl_boundary_descriptor) {
    REQUIRE(UN(RtlCreateBoundaryDescriptor)); REQUIRE(UN(RtlDeleteBoundaryDescriptor));
    REQUIRE(UN(RtlAddSIDToBoundaryDescriptor)); REQUIRE(UN(RtlAddIntegrityLabelToBoundaryDescriptor));
    REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(RtlLengthSid));
    UNICODE_STRING name; UN(RtlInitUnicodeString)(&name, L"NtdlltBoundary");
    PVOID bd = UN(RtlCreateBoundaryDescriptor)(&name, 0);
    EXPECT_NE(bd, NULL);
    if (!bd) return;
    ULONG *w = (ULONG *)bd;
    EXPECT_EQ(w[0], 1);                         /* Version */
    EXPECT_EQ(w[3], 0);                         /* no flags */
    EXPECT_EQ(w[4], 1);                         /* first item: the name */
    EXPECT_EQ(w[5], name.Length + 8);           /* item size includes its 8-byte header */
    EXPECT_EQ(memcmp(&w[6], name.Buffer, name.Length), 0);
    ULONG size0 = w[2];
    EXPECT_NE(size0, 0);
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, SID_EVERYONE), 0);
    w = (ULONG *)bd; EXPECT_EQ(w[0], 1); EXPECT_EQ(w[1], 2); EXPECT_EQ(w[2], size0 + ((8 + 12 + 7) & ~7u));   /* items are 8-byte aligned */
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, SID_ADMINS), 0);
    w = (ULONG *)bd; EXPECT_EQ(w[1], 3);
    EXPECT_EQ(UN(RtlAddIntegrityLabelToBoundaryDescriptor)(&bd, SID_LOWLABEL), 0);
    w = (ULONG *)bd; EXPECT_EQ(w[1], 4);
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, SID_BADCOUNT), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, SID_BADREV), ST_INVPARAM);
    EXPECT_EQ(UN(RtlAddIntegrityLabelToBoundaryDescriptor)(&bd, SID_BADREV), ST_INVPARAM);
    w = (ULONG *)bd; EXPECT_EQ(w[1], 4);
    UN(RtlDeleteBoundaryDescriptor)(bd);

    /* a descriptor holding the name and the Everyone SID is accepted by the object manager */
    if (UN(NtCreatePrivateNamespace) && UN(NtDeletePrivateNamespace) && UN(NtClose)) {
        UNICODE_STRING nm2; UN(RtlInitUnicodeString)(&nm2, L"NtdlltBoundaryNs");
        PVOID b2 = UN(RtlCreateBoundaryDescriptor)(&nm2, 0);
        EXPECT_NE(b2, NULL);
        if (b2) {
            EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&b2, SID_EVERYONE), 0);
            HANDLE h = NULL;
            NTSTATUS ns = UN(NtCreatePrivateNamespace)(&h, 0xF0001, NULL, b2);
            EXPECT_EQ(ns, 0);
            if (ns >= 0 && h) { UN(NtDeletePrivateNamespace)(h); UN(NtClose)(h); }
            UN(RtlDeleteBoundaryDescriptor)(b2);
        }
    }

    /* flags: only bit 0 (add-package-SID) is accepted */
    PVOID bd1 = UN(RtlCreateBoundaryDescriptor)(&name, 1);
    EXPECT_NE(bd1, NULL);
    if (bd1) { EXPECT_EQ(((ULONG *)bd1)[3], 1); UN(RtlDeleteBoundaryDescriptor)(bd1); }
    EXPECT_EQ(UN(RtlCreateBoundaryDescriptor)(&name, 2), NULL);
    EXPECT_EQ(UN(RtlCreateBoundaryDescriptor)(&name, 0x80000000), NULL);
    UNICODE_STRING empty; UN(RtlInitUnicodeString)(&empty, L"");
    EXPECT_EQ(UN(RtlCreateBoundaryDescriptor)(&empty, 0), NULL);
    UNICODE_STRING odd = {5, 6, (PWSTR)L"abc"};
    EXPECT_EQ(UN(RtlCreateBoundaryDescriptor)(&odd, 0), NULL);
}

/* ---- service SID ---- */
TEST(rtl_create_service_sid) {
    REQUIRE(UN(RtlCreateServiceSid)); REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(RtlLengthSid));
    UNICODE_STRING nm; UN(RtlInitUnicodeString)(&nm, L"Spooler");
    BYTE sid[32]; ULONG len = 32;
    NTSTATUS s = UN(RtlCreateServiceSid)(&nm, sid, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, 32);
    /* S-1-5-80-<5 sub-authorities of SHA-1> */
    EXPECT_EQ(sid[0], 1); EXPECT_EQ(sid[1], 6); EXPECT_EQ(sid[7], 5); EXPECT_EQ(*(ULONG *)(sid + 8), 80);
    EXPECT_EQ(UN(RtlLengthSid)(sid), 32);
    /* the well-known value for "Spooler" is S-1-5-80-3702785172-... on every Windows 10 system; check determinism and case-insensitivity */
    BYTE sid2[32]; ULONG len2 = 32; UNICODE_STRING nm2; UN(RtlInitUnicodeString)(&nm2, L"sPOOLER");
    EXPECT_EQ(UN(RtlCreateServiceSid)(&nm2, sid2, &len2), 0);
    EXPECT_EQ(memcmp(sid, sid2, 32), 0);
    UNICODE_STRING nm3; UN(RtlInitUnicodeString)(&nm3, L"Spooler2");
    BYTE sid3[32]; ULONG len3 = 32;
    EXPECT_EQ(UN(RtlCreateServiceSid)(&nm3, sid3, &len3), 0);
    EXPECT_NE(memcmp(sid + 8, sid3 + 8, 24), 0);
    /* small buffer: required length reported */
    ULONG small = 31; BYTE junk[32];
    EXPECT_EQ(UN(RtlCreateServiceSid)(&nm, junk, &small), ST_BUFSMALL); EXPECT_EQ(small, 32);
    EXPECT_EQ(UN(RtlCreateServiceSid)(NULL, junk, &len), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateServiceSid)(&nm, junk, NULL), ST_INVPARAM);
}

/* ---- token membership / capability / sandbox ---- */
static HANDLE dup_imp_token_qos(void) {
    HANDLE p = NULL, t = NULL;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &p) < 0) return NULL;
    SECURITY_QUALITY_OF_SERVICE q = {sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE};
    OBJECT_ATTRIBUTES oa = {sizeof oa}; oa.SecurityQualityOfService = &q;
    NTSTATUS s = UN(NtDuplicateToken)(p, TOKEN_QUERY | TOKEN_IMPERSONATE, &oa, FALSE, TokenImpersonation, &t);
    UN(NtClose)(p);
    return s >= 0 ? t : NULL;
}
TEST(rtl_check_token_membership) {
    REQUIRE(UN(RtlCheckTokenMembership)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtClose));
    BYTE other[16] = {1, 2, 0,0,0,0,0,5, 21,0,0,0, 0x39,0x30,0,0};  /* S-1-5-21-12345 never present */
    for (int pass = 0; pass < 2; pass++) {
        HANDLE tok = pass ? dup_imp_token_qos() : NULL;     /* NULL: current thread / process token */
        if (pass && !tok) { t_skip("could not duplicate the process token"); return; }
        BOOLEAN m = FALSE;
        NTSTATUS s = UN(RtlCheckTokenMembership)(tok, SID_EVERYONE, &m);
        EXPECT_EQ(s, 0); EXPECT_EQ(m, TRUE);
        m = TRUE; s = UN(RtlCheckTokenMembership)(tok, other, &m);
        EXPECT_EQ(s, 0); EXPECT_EQ(m, FALSE);
        /* Administrators: must match the answer from the Win32 layer (enabled-group semantics) */
        BOOL w32 = FALSE; BOOL (WINAPI *cm)(HANDLE, PSID, PBOOL) = (void *)t_proc_in("advapi32.dll", "CheckTokenMembership");
        m = 2; s = UN(RtlCheckTokenMembership)(tok, SID_ADMINS, &m);
        EXPECT_EQ(s, 0);
        if (cm && cm(tok, SID_ADMINS, &w32)) EXPECT_EQ(m, (BOOLEAN)(w32 != 0));
        else t_note("CheckTokenMembership unavailable for comparison");
        if (tok) UN(NtClose)(tok);
    }
    /* a primary token handle (not an impersonation token) cannot be used for the access check: result is FALSE */
    HANDLE ptok = NULL; BOOLEAN m = 2;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &ptok) >= 0) {
        NTSTATUS s = UN(RtlCheckTokenMembership)(ptok, SID_EVERYONE, &m);
        t_note("primary token handle: status 0x%08lx member=%d", (unsigned long)s, m);
        EXPECT_EQ(m, FALSE);
        UN(NtClose)(ptok);
    }
}
TEST(rtl_check_token_membership_ex) {
    REQUIRE(UN(RtlCheckTokenMembershipEx)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtClose));
    HANDLE tok = dup_imp_token_qos();
    if (!tok) { t_skip("could not duplicate the process token"); return; }
    BOOLEAN m = FALSE;
    EXPECT_EQ(UN(RtlCheckTokenMembershipEx)(tok, SID_EVERYONE, 0, &m), 0); EXPECT_EQ(m, TRUE);
    /* unknown flag bits: the output is cleared to FALSE */
    m = TRUE;
    UN(RtlCheckTokenMembershipEx)(tok, SID_EVERYONE, 4, &m); EXPECT_EQ(m, FALSE);
    m = TRUE;
    UN(RtlCheckTokenMembershipEx)(tok, SID_EVERYONE, 0x80000000, &m); EXPECT_EQ(m, FALSE);
    /* flag 1 (RTL_CHECK_TOKEN_MEMBERSHIP_FLAG_*) is accepted */
    m = FALSE;
    NTSTATUS s = UN(RtlCheckTokenMembershipEx)(tok, SID_EVERYONE, 1, &m);
    t_note("flags=1: status 0x%08lx member=%d", (unsigned long)s, m);
    EXPECT_EQ(s, 0);
    UN(NtClose)(tok);
}
TEST(rtl_check_token_capability) {
    REQUIRE(UN(RtlCheckTokenCapability)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtClose));
    static BYTE cap[16] = {1, 2, 0,0,0,0,0,15, 3,0,0,0, 1,0,0,0};   /* S-1-15-3-1 */
    BOOLEAN has = 2;
    NTSTATUS s = UN(RtlCheckTokenCapability)(NULL, cap, &has);
    EXPECT_EQ(s, 0); EXPECT_EQ(has, TRUE);                          /* a token that is not an app container passes every capability check */
    HANDLE tok = dup_imp_token_qos();
    if (tok) { has = 2; s = UN(RtlCheckTokenCapability)(tok, cap, &has); EXPECT_EQ(s, 0); EXPECT_EQ(has, TRUE); UN(NtClose)(tok); }
    has = 2; s = UN(RtlCheckTokenCapability)(NULL, SID_EVERYONE, &has);
    EXPECT_EQ(s, ST_INVPARAM); EXPECT_EQ(has, FALSE);                /* not a capability SID */
    has = 2; s = UN(RtlCheckTokenCapability)(NULL, SID_BADCOUNT, &has);
    EXPECT_EQ(s, ST_INVPARAM);
}
TEST(rtl_check_sandboxed_token) {
    REQUIRE(UN(RtlCheckSandboxedToken)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtClose));
    HANDLE p = NULL;
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &p), 0);
    BOOLEAN sb = 2;
    UN(RtlCheckSandboxedToken)(p, &sb);
    EXPECT_EQ(sb, FALSE);                   /* the test process is not sandboxed */
    sb = 2; UN(RtlCheckSandboxedToken)(NULL, &sb); EXPECT_EQ(sb, FALSE);          /* failure to query leaves FALSE */
    if (p) UN(NtClose)(p);
}
