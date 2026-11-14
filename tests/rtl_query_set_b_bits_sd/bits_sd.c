/* RtlSetBit/RtlSetBitEx/RtlSetBitsEx, security descriptor attribute and RM-control setters,
 * RtlSetInformationAcl and RtlSetSecurityObject(Ex). Everything works on private buffers. */
#include "t.h"
#include <stdlib.h>

typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } BM;
typedef struct { ULONG64 SizeOfBitMap; PULONG64 Buffer; } BMEX;

UDECL(VOID, RtlInitializeBitMap, (BM *, PULONG, ULONG));
UDECL(VOID, RtlInitializeBitMapEx, (BMEX *, PULONG64, ULONG64));
UDECL(VOID, RtlSetBit, (BM *, ULONG));
UDECL(VOID, RtlSetBitEx, (BMEX *, ULONG64));
UDECL(VOID, RtlSetBitsEx, (BMEX *, ULONG64, ULONG64));
UDECL(BOOLEAN, RtlTestBit, (BM *, ULONG));
UDECL(BOOLEAN, RtlTestBitEx, (BMEX *, ULONG64));
UDECL(ULONG64, RtlNumberOfSetBitsEx, (BMEX *));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetAttributesSecurityDescriptor, (PSECURITY_DESCRIPTOR, USHORT, PULONG));
UDECL(NTSTATUS, RtlGetControlSecurityDescriptor, (PSECURITY_DESCRIPTOR, PUSHORT, PULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(VOID, RtlSetSecurityDescriptorRMControl, (PSECURITY_DESCRIPTOR, PUCHAR));
UDECL(BOOLEAN, RtlGetSecurityDescriptorRMControl, (PSECURITY_DESCRIPTOR, PUCHAR));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlSetInformationAcl, (PACL, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlQueryInformationAcl, (PACL, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlSetSecurityObject, (ULONG, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, PGENERIC_MAPPING, HANDLE));
UDECL(NTSTATUS, RtlSetSecurityObjectEx, (ULONG, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, ULONG, PGENERIC_MAPPING, HANDLE));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlDeleteSecurityObject, (PSECURITY_DESCRIPTOR *));
UDECL(NTSTATUS, RtlAbsoluteToSelfRelativeSD, (PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(ULONG, RtlLengthSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)
#define ST_REV S(0xC0000058)
#define ST_BADCLASS S(0xC0000003)
#define ST_BUFSMALL S(0xC0000023)

/* ---- bitmaps ---- */
static int model_bit(unsigned char *m, unsigned i) { return (m[i >> 3] >> (i & 7)) & 1; }

TEST(rtl_set_bit_basic) {
    REQUIRE(UN(RtlSetBit)); REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlTestBit));
    ULONG buf[4]; BM bm; memset(buf, 0, sizeof buf);
    UN(RtlInitializeBitMap)(&bm, buf, 128);
    UN(RtlSetBit)(&bm, 0);   EXPECT_EQ(buf[0], 1);
    UN(RtlSetBit)(&bm, 7);   EXPECT_EQ(buf[0], 0x81);
    UN(RtlSetBit)(&bm, 31);  EXPECT_EQ(buf[0], 0x80000081u);
    UN(RtlSetBit)(&bm, 32);  EXPECT_EQ(buf[1], 1);
    UN(RtlSetBit)(&bm, 127); EXPECT_EQ(buf[3], 0x80000000u);
    UN(RtlSetBit)(&bm, 7);   EXPECT_EQ(buf[0], 0x80000081u);   /* idempotent */
    EXPECT_EQ(buf[2], 0);
    EXPECT_EQ(UN(RtlTestBit)(&bm, 7), TRUE);
    EXPECT_EQ(UN(RtlTestBit)(&bm, 8), FALSE);
    EXPECT_EQ(UN(RtlTestBit)(&bm, 127), TRUE);
    /* a bitmap whose buffer is already full is left alone */
    memset(buf, 0xff, sizeof buf); UN(RtlSetBit)(&bm, 50);
    for (int i = 0; i < 4; i++) EXPECT_EQ(buf[i], 0xffffffffu);
}

TEST(rtl_set_bit_ex_basic) {
    REQUIRE(UN(RtlSetBitEx)); REQUIRE(UN(RtlInitializeBitMapEx)); REQUIRE(UN(RtlTestBitEx));
    ULONG64 buf[4]; BMEX bm; memset(buf, 0, sizeof buf);
    UN(RtlInitializeBitMapEx)(&bm, buf, 256);
    EXPECT_EQ(bm.SizeOfBitMap, 256); EXPECT_EQ(bm.Buffer, buf);
    UN(RtlSetBitEx)(&bm, 0);   EXPECT_EQ(buf[0], 1);
    UN(RtlSetBitEx)(&bm, 63);  EXPECT_EQ(buf[0], 0x8000000000000001ull);
    UN(RtlSetBitEx)(&bm, 64);  EXPECT_EQ(buf[1], 1);
    UN(RtlSetBitEx)(&bm, 255); EXPECT_EQ(buf[3], 0x8000000000000000ull);
    UN(RtlSetBitEx)(&bm, 64);  EXPECT_EQ(buf[1], 1);
    EXPECT_EQ(buf[2], 0);
    EXPECT_EQ(UN(RtlTestBitEx)(&bm, 63), TRUE);
    EXPECT_EQ(UN(RtlTestBitEx)(&bm, 65), FALSE);
    if (UN(RtlNumberOfSetBitsEx)) EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 4);
}

TEST(rtl_set_bits_ex_model) {
    REQUIRE(UN(RtlSetBitsEx)); REQUIRE(UN(RtlInitializeBitMapEx));
    /* every (start,count) with start+count <= 130 over a 192-bit map, compared with a bit-by-bit model;
       the bytes after the range must stay untouched (sentinel) */
    int bad = 0;
    for (unsigned start = 0; start <= 130 && bad < 5; start += (start < 20 ? 1 : 3)) {
        for (unsigned cnt = 0; start + cnt <= 130 && bad < 5; cnt += (cnt < 20 ? 1 : 5)) {
            ULONG64 buf[3] = {0, 0, 0}; unsigned char want[24] = {0}; BMEX bm;
            UN(RtlInitializeBitMapEx)(&bm, buf, 192);
            UN(RtlSetBitsEx)(&bm, start, cnt);
            for (unsigned i = start; i < start + cnt; i++) want[i >> 3] |= 1u << (i & 7);
            if (memcmp(want, buf, 24)) { bad++; CHECKF(0, "start=%u count=%u mismatch", start, cnt); }
        }
    }
    CHECK(bad == 0);
}

TEST(rtl_set_bits_ex_preserves_and_wide) {
    REQUIRE(UN(RtlSetBitsEx)); REQUIRE(UN(RtlInitializeBitMapEx)); REQUIRE(UN(RtlNumberOfSetBitsEx));
    ULONG64 buf[4]; BMEX bm; memset(buf, 0, sizeof buf);
    UN(RtlInitializeBitMapEx)(&bm, buf, 256);
    UN(RtlSetBitsEx)(&bm, 3, 0);  EXPECT_EQ(buf[0], 0);          /* zero count: no change */
    UN(RtlSetBitsEx)(&bm, 1, 1);  EXPECT_EQ(buf[0], 2);
    UN(RtlSetBitsEx)(&bm, 4, 4);  EXPECT_EQ(buf[0], 0xf2);        /* earlier bits preserved */
    UN(RtlSetBitsEx)(&bm, 60, 8); EXPECT_EQ(buf[0], 0xf0000000000000f2ull); EXPECT_EQ(buf[1], 0xf);
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 13);
    memset(buf, 0, sizeof buf);
    UN(RtlSetBitsEx)(&bm, 0, 256); for (int i = 0; i < 4; i++) EXPECT_EQ(buf[i], ~0ull);
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 256);
    /* a range wider than 32 bits, unaligned at both ends */
    memset(buf, 0, sizeof buf);
    UN(RtlSetBitsEx)(&bm, 5, 200);
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 200);
    CHECK(!(buf[0] & 0x1f)); CHECK((buf[0] >> 5) == (~0ull >> 5)); EXPECT_EQ(buf[2], ~0ull);
    EXPECT_EQ(buf[3], 0x1fffull);
}

/* ---- security descriptors ---- */
TEST(rtl_set_attributes_sd) {
    REQUIRE(UN(RtlSetAttributesSecurityDescriptor)); REQUIRE(UN(RtlCreateSecurityDescriptor));
    REQUIRE(UN(RtlGetControlSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor));
    BYTE sdb[64]; PSECURITY_DESCRIPTOR sd = sdb; USHORT ctl; ULONG rev = 0xdead;
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(sd, 1), 0);
    /* the call ORs the requested bits of the 0x3fc0 group into the control word; it never clears */
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0, &rev), 0);
    EXPECT_EQ(rev, 1);
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl, 0);
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0x0100, &rev), 0);
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl, 0x0100);
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0, &rev), 0);          /* 0 does not clear */
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl, 0x0100);
    /* bits outside 0x3fc0 (SE_SELF_RELATIVE 0x8000, SE_DACL_DEFAULTED 8, 0x4000) in the request are ignored */
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0xc008 | 0x0040, &rev), 0);
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl, 0x0040);
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0xffff, &rev), 0);
    EXPECT_EQ(rev, 1);
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl, 0x3fc0);
    /* unknown revision: reported through the out parameter, status STATUS_UNKNOWN_REVISION */
    sdb[0] = 2; rev = 0xdead;
    EXPECT_EQ(UN(RtlSetAttributesSecurityDescriptor)(sd, 0x0040, &rev), ST_REV);
    EXPECT_EQ(rev, 2);
}

TEST(rtl_set_sd_rm_control) {
    REQUIRE(UN(RtlSetSecurityDescriptorRMControl)); REQUIRE(UN(RtlGetSecurityDescriptorRMControl));
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlGetControlSecurityDescriptor));
    BYTE sdb[64]; PSECURITY_DESCRIPTOR sd = sdb; USHORT ctl; ULONG rev; UCHAR rm = 0x5a, out = 0xee;
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(sd, &out), FALSE);   /* flag absent */
    UN(RtlSetSecurityDescriptorRMControl)(sd, &rm);
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl & 0x4000, 0x4000);
    EXPECT_EQ(sdb[1], 0x5a);                 /* Sbz1 carries the value */
    out = 0xee; EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(sd, &out), TRUE); EXPECT_EQ(out, 0x5a);
    rm = 0;
    UN(RtlSetSecurityDescriptorRMControl)(sd, &rm);                       /* value 0 still sets the flag */
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl & 0x4000, 0x4000);
    out = 0xee; EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(sd, &out), TRUE); EXPECT_EQ(out, 0);
    rm = 0x11; UN(RtlSetSecurityDescriptorRMControl)(sd, &rm);
    UN(RtlSetSecurityDescriptorRMControl)(sd, NULL);                      /* NULL clears flag and value */
    UN(RtlGetControlSecurityDescriptor)(sd, &ctl, &rev); EXPECT_EQ(ctl & 0x4000, 0);
    EXPECT_EQ(sdb[1], 0);
    out = 0xee; EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(sd, &out), FALSE);
    EXPECT_EQ(out, 0);   /* observed on Windows 10 / decompiled getter: output cleared when the flag is absent */
}

/* ---- ACL information ---- */
TEST(rtl_set_information_acl) {
    REQUIRE(UN(RtlSetInformationAcl)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlQueryInformationAcl));
    BYTE ab[256]; PACL acl = (PACL)ab; ULONG rev;
    struct { ULONG AclRevision; } q;
    EXPECT_EQ(UN(RtlCreateAcl)(acl, sizeof ab, 2), 0); EXPECT_EQ(acl->AclRevision, 2);
    rev = 4;
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), 0);
    EXPECT_EQ(acl->AclRevision, 4);
    EXPECT_EQ(UN(RtlQueryInformationAcl)(acl, &q, sizeof q, 1), 0); EXPECT_EQ(q.AclRevision, 4);
    rev = 3;                                                              /* lowering is rejected */
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), ST_INVPARAM);
    EXPECT_EQ(acl->AclRevision, 4);
    rev = 4;                                                              /* same revision is fine */
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), 0);
    /* wrong class (2 = size information) and class 0 */
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 2), ST_BADCLASS);
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 0), ST_BADCLASS);
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 99), ST_BADCLASS);
    /* length below 4 */
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, 3, 1), ST_BUFSMALL);
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, 0, 1), ST_BUFSMALL);
    /* a larger buffer than needed is accepted */
    rev = 4; EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, 16, 1), 0);
    /* raising 2 -> 3 */
    UN(RtlCreateAcl)(acl, sizeof ab, 2); rev = 3;
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), 0); EXPECT_EQ(acl->AclRevision, 3);
    /* an ACL whose own revision is out of range is rejected before the class check result matters */
    UN(RtlCreateAcl)(acl, sizeof ab, 2); acl->AclRevision = 1; rev = 4;
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), ST_INVPARAM);
    acl->AclRevision = 5;
    EXPECT_EQ(UN(RtlSetInformationAcl)(acl, &rev, sizeof rev, 1), ST_INVPARAM);
}

/* ---- RtlSetSecurityObject ---- */
static BYTE SID_EVERYONE[12] = {1, 1, 0,0,0,0,0,1, 0,0,0,0};
static BYTE SID_ADMINS[16]   = {1, 2, 0,0,0,0,0,5, 32,0,0,0, 0x20,0x02,0,0};
static BYTE SID_SYSTEM[12]   = {1, 1, 0,0,0,0,0,5, 18,0,0,0};

/* self-relative SD (process heap, as RtlSetSecurityObject frees/reallocs through it) with owner=Admins and a one-ACE DACL */
static PSECURITY_DESCRIPTOR make_obj_sd(PSID owner, PSID acesid, ACCESS_MASK mask) {
    BYTE abs_[64]; BYTE aclb[128]; ULONG len = 0;
    UN(RtlCreateSecurityDescriptor)(abs_, 1);
    UN(RtlCreateAcl)((PACL)aclb, sizeof aclb, 2);
    UN(RtlAddAccessAllowedAce)((PACL)aclb, 2, mask, acesid);
    UN(RtlSetDaclSecurityDescriptor)(abs_, TRUE, (PACL)aclb, FALSE);
    UN(RtlSetOwnerSecurityDescriptor)(abs_, owner, FALSE);
    UN(RtlSetGroupSecurityDescriptor)(abs_, owner, FALSE);
    UN(RtlAbsoluteToSelfRelativeSD)(abs_, NULL, &len);
    PSECURITY_DESCRIPTOR sr = HeapAlloc(GetProcessHeap(), 0, len);
    if (sr && UN(RtlAbsoluteToSelfRelativeSD)(abs_, sr, &len) != 0) { HeapFree(GetProcessHeap(), 0, sr); sr = NULL; }
    return sr;
}
static ACCESS_MASK first_ace_mask(PSECURITY_DESCRIPTOR sd, int *count) {
    BOOLEAN pres, def; PACL dacl = NULL;
    *count = -1;
    if (UN(RtlGetDaclSecurityDescriptor)(sd, &pres, &dacl, &def) < 0 || !pres || !dacl) return 0;
    *count = dacl->AceCount;
    if (!dacl->AceCount) return 0;
    return ((ACCESS_ALLOWED_ACE *)(dacl + 1))->Mask;
}
static GENERIC_MAPPING gm = { 0x1, 0x2, 0x4, 0x1f0007 };

static void setobj_body(int ex) {
    REQUIRE(UN(RtlSetSecurityObject)); REQUIRE(UN(RtlSetSecurityObjectEx)); REQUIRE(UN(RtlAbsoluteToSelfRelativeSD));
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    REQUIRE(UN(RtlSetDaclSecurityDescriptor)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor));
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlDeleteSecurityObject));
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtClose));
    HANDLE ptok = NULL, itok = NULL;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &ptok) < 0) { t_skip("cannot open process token"); return; }
    OBJECT_ATTRIBUTES oa = { sizeof oa };
    NTSTATUS st = UN(NtDuplicateToken)(ptok, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &oa, FALSE, 2 /* TokenImpersonation */, &itok);
    UN(NtClose)(ptok);
    /* impersonation-level SecurityImpersonation needs a SECURITY_QUALITY_OF_SERVICE; fall back to the process token */
    (void)st;

    PSECURITY_DESCRIPTOR obj = make_obj_sd((PSID)SID_ADMINS, (PSID)SID_EVERYONE, 0x1);
    if (!obj) { t_skip("could not build object descriptor"); if (itok) UN(NtClose)(itok); return; }
    int cnt; EXPECT_EQ(first_ace_mask(obj, &cnt), 0x1); EXPECT_EQ(cnt, 1);

    /* modification descriptor with a different DACL; DACL_SECURITY_INFORMATION replaces only the DACL */
    PSECURITY_DESCRIPTOR mod = make_obj_sd((PSID)SID_SYSTEM, (PSID)SID_EVERYONE, 0x6);
    NTSTATUS s;
    if (ex) s = UN(RtlSetSecurityObjectEx)(DACL_SECURITY_INFORMATION, mod, &obj, 0, &gm, itok);
    else    s = UN(RtlSetSecurityObject)(DACL_SECURITY_INFORMATION, mod, &obj, &gm, itok);
    t_note("RtlSetSecurityObject%s status 0x%lx", ex ? "Ex" : "", (unsigned long)s);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        EXPECT_EQ(first_ace_mask(obj, &cnt), 0x6); EXPECT_EQ(cnt, 1);
        PSID o = NULL; BOOLEAN def = 1;
        EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(obj, &o, &def), 0);
        CHECK(o && !memcmp(o, SID_ADMINS, sizeof SID_ADMINS));          /* owner untouched */
        CHECK(((SECURITY_DESCRIPTOR *)obj)->Control & SE_SELF_RELATIVE);
    }
    HeapFree(GetProcessHeap(), 0, mod);
    if (obj) UN(RtlDeleteSecurityObject)(&obj);
    if (itok) UN(NtClose)(itok);
}
TEST(rtl_set_security_object_dacl) { setobj_body(0); }
TEST(rtl_set_security_object_ex_dacl) { setobj_body(1); }

TEST(rtl_set_security_object_owner_and_info) {
    REQUIRE(UN(RtlSetSecurityObject)); REQUIRE(UN(RtlAbsoluteToSelfRelativeSD)); REQUIRE(UN(RtlCreateSecurityDescriptor));
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce)); REQUIRE(UN(RtlSetDaclSecurityDescriptor));
    REQUIRE(UN(RtlSetOwnerSecurityDescriptor)); REQUIRE(UN(RtlSetGroupSecurityDescriptor));
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlDeleteSecurityObject));
    PSECURITY_DESCRIPTOR obj = make_obj_sd((PSID)SID_ADMINS, (PSID)SID_EVERYONE, 0x1);
    PSECURITY_DESCRIPTOR mod = make_obj_sd((PSID)SID_SYSTEM, (PSID)SID_EVERYONE, 0x6);
    if (!obj || !mod) { t_skip("could not build descriptors"); return; }
    /* SecurityInformation == 0 changes nothing */
    NTSTATUS s = UN(RtlSetSecurityObject)(0, mod, &obj, &gm, NULL);
    EXPECT_EQ(s, 0);
    int cnt;
    EXPECT_EQ(first_ace_mask(obj, &cnt), 0x1);
    /* only the DACL asked for: owner SID in the modification descriptor must not leak in */
    s = UN(RtlSetSecurityObject)(DACL_SECURITY_INFORMATION, mod, &obj, &gm, NULL);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        EXPECT_EQ(first_ace_mask(obj, &cnt), 0x6);
        PSID o = NULL; BOOLEAN def;
        UN(RtlGetOwnerSecurityDescriptor)(obj, &o, &def);
        CHECK(o && !memcmp(o, SID_ADMINS, sizeof SID_ADMINS));
    }
    HeapFree(GetProcessHeap(), 0, mod);
    if (obj) UN(RtlDeleteSecurityObject)(&obj);
}
