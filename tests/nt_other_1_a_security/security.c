/* Access checks, token adjustment/filtering/comparison and the privilege-gated audit alarm services.
 * Everything operates on duplicates of the caller's own token and on private security descriptors. */
#include "t.h"

UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtAccessCheck, (PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, NtAccessCheckByType, (PSECURITY_DESCRIPTOR, PSID, HANDLE, ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, NtAccessCheckByTypeResultList, (PSECURITY_DESCRIPTOR, PSID, HANDLE, ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, NtAdjustPrivilegesToken, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG));
UDECL(NTSTATUS, NtAdjustGroupsToken, (HANDLE, BOOLEAN, PTOKEN_GROUPS, ULONG, PTOKEN_GROUPS, PULONG));
UDECL(NTSTATUS, NtFilterToken, (HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, PHANDLE));
UDECL(NTSTATUS, NtFilterTokenEx, (HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, ULONG, PVOID, ULONG, PVOID, PTOKEN_GROUPS, PVOID, PVOID, PTOKEN_GROUPS, PHANDLE));
UDECL(NTSTATUS, NtCompareTokens, (HANDLE, HANDLE, PBOOLEAN));
UDECL(NTSTATUS, NtAdjustTokenClaimsAndDeviceGroups, (HANDLE, BOOLEAN, BOOLEAN, BOOLEAN, PVOID, PVOID, PTOKEN_GROUPS, ULONG, PVOID, ULONG, PVOID, ULONG, PTOKEN_GROUPS, PULONG, PULONG, PULONG));
UDECL(NTSTATUS, NtAccessCheckAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, ACCESS_MASK, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, NtAccessCheckByTypeAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, NtAccessCheckByTypeResultListAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, NtAccessCheckByTypeResultListAndAuditAlarmByHandle, (PUNICODE_STRING, PVOID, HANDLE, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, NtCloseObjectAuditAlarm, (PUNICODE_STRING, PVOID, BOOLEAN));
UDECL(NTSTATUS, NtDeleteObjectAuditAlarm, (PUNICODE_STRING, PVOID, BOOLEAN));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define OKS(s) ((NTSTATUS)(s) >= 0)
#define ST_INVHANDLE  S(0xC0000008)
#define ST_INVPARAM   S(0xC000000D)
#define ST_AV         S(0xC0000005)
#define ST_DENIED     S(0xC0000022)
#define ST_TYPEMISM   S(0xC0000024)
#define ST_NOT_ALL    S(0x106)          /* STATUS_NOT_ALL_ASSIGNED */
#define ST_BUFSMALL   S(0xC0000023)
#define ST_NO_IMP     S(0xC000005C)     /* STATUS_NO_IMPERSONATION_TOKEN */
#define ST_BAD_IMPLVL S(0xC00000A5)     /* STATUS_BAD_IMPERSONATION_LEVEL */
#define ST_PRIVNH     S(0xC0000061)     /* STATUS_PRIVILEGE_NOT_HELD */
#define ST_CANT_DIS   S(0xC000005D)     /* STATUS_CANT_DISABLE_MANDATORY */

typedef struct { BYTE rev, count; BYTE auth[6]; ULONG sub[4]; } sid_t;
static const sid_t everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid_t sys_sid  = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const sid_t admins   = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };

#define NEED() do { REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose)); } while (0)

static HANDLE dup_tok(ACCESS_MASK access, ULONG type, ULONG implevel)
{
    HANDLE src = NULL, d = NULL; SECURITY_QUALITY_OF_SERVICE q; OBJECT_ATTRIBUTES oa;
    if (!OKS(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &src))) return NULL;
    q.Length = sizeof q; q.ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)implevel; q.ContextTrackingMode = 0; q.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL); oa.SecurityQualityOfService = &q;
    if (!OKS(UN(NtDuplicateToken)(src, access, &oa, FALSE, type, &d))) d = NULL;
    UN(NtClose)(src);
    return d;
}
#define IMP_DUP(a) dup_tok((a), 2, SecurityImpersonation)

/* attributes of privilege `luid` in token, -1 if absent, -2 on query error */
static LONG priv_attr(HANDLE tok, ULONG luid)
{
    union { ULONGLONG a; BYTE b[4096]; } buf; ULONG got = 0; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf.b;
    if (!OKS(UN(NtQueryInformationToken)(tok, 3, buf.b, sizeof buf, &got))) return -2;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == luid && tp->Privileges[i].Luid.HighPart == 0) return (LONG)tp->Privileges[i].Attributes;
    return -1;
}
static ULONG priv_count(HANDLE tok)
{
    union { ULONGLONG a; BYTE b[4096]; } buf; ULONG got = 0;
    if (!OKS(UN(NtQueryInformationToken)(tok, 3, buf.b, sizeof buf, &got))) return 0xFFFFFFFF;
    return ((TOKEN_PRIVILEGES *)buf.b)->PrivilegeCount;
}
/* group attributes by SID (everyone, ...); -1 absent */
static LONG group_attr(HANDLE tok, const sid_t *sid)
{
    union { ULONGLONG a; BYTE b[8192]; } buf; ULONG got = 0; TOKEN_GROUPS *g = (TOKEN_GROUPS *)buf.b;
    if (!OKS(UN(NtQueryInformationToken)(tok, 2, buf.b, sizeof buf, &got))) return -2;
    for (DWORD i = 0; i < g->GroupCount; i++)
        if (EqualSid(g->Groups[i].Sid, (PSID)sid)) return (LONG)g->Groups[i].Attributes;
    return -1;
}
static ULONG tok_ulong(HANDLE tok, ULONG cls)
{
    ULONG v = 0xdeadbeef, got = 0;
    if (!OKS(UN(NtQueryInformationToken)(tok, cls, &v, sizeof v, &got))) return 0xdeadbeef;
    return v;
}

TEST(security_aliases)
{
    static const char *n[] = { "AccessCheck", "AccessCheckByType", "AccessCheckByTypeResultList", "AccessCheckAndAuditAlarm",
        "AccessCheckByTypeAndAuditAlarm", "AccessCheckByTypeResultListAndAuditAlarm", "AccessCheckByTypeResultListAndAuditAlarmByHandle",
        "AdjustGroupsToken", "AdjustPrivilegesToken", "AdjustTokenClaimsAndDeviceGroups", "CloseObjectAuditAlarm", "DeleteObjectAuditAlarm",
        "CompareTokens", "FilterToken", "FilterTokenEx" };
    char a[96], b[96];
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "alias %s", a);
    }
}

/* ---- access checks ------------------------------------------------------------------ */
#define RIGHT_A 0x1
#define RIGHT_B 0x2
#define RIGHT_C 0x4
static GENERIC_MAPPING gm = { RIGHT_A, RIGHT_B, RIGHT_C, RIGHT_A | RIGHT_B | RIGHT_C };

/* SD: owner=System, group=System, DACL: Everyone allowed A|B (and optionally an explicit deny of B for Everyone first). */
static void build_sd(BYTE *sd, BYTE *acl, BOOL deny_b)
{
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    UN(RtlSetOwnerSecurityDescriptor)(sd, (PSID)&sys_sid, FALSE);
    UN(RtlSetGroupSecurityDescriptor)(sd, (PSID)&sys_sid, FALSE);
    UN(RtlCreateAcl)((PACL)acl, 256, 2);
    if (deny_b) UN(RtlAddAccessDeniedAce)((PACL)acl, 2, RIGHT_B, (PSID)&everyone);
    UN(RtlAddAccessAllowedAce)((PACL)acl, 2, RIGHT_A | RIGHT_B, (PSID)&everyone);
    UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, (PACL)acl, FALSE);
}
#define NEED_AC() do { NEED(); REQUIRE(UN(NtAccessCheck)); REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce)); REQUIRE(UN(RtlAddAccessDeniedAce)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor)); REQUIRE(UN(RtlSetGroupSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor)); } while (0)

TEST(access_check)
{
    BYTE sd[256], acl[256]; HANDLE imp, prim, ident, anon; ACCESS_MASK granted; NTSTATUS as, s; ULONG psl; PRIVILEGE_SET ps;
    NEED_AC();
    build_sd(sd, acl, FALSE);
    imp = IMP_DUP(TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE); CHECK(imp != NULL); if (!imp) return;
    psl = sizeof ps;
    /* allowed */
    granted = 0xcc; as = 0xcc; memset(&ps, 0, sizeof ps);
    s = UN(NtAccessCheck)(sd, imp, RIGHT_A, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A);
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheck)(sd, imp, RIGHT_A | RIGHT_B, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A | RIGHT_B);
    /* denied: right C is not granted by the DACL */
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheck)(sd, imp, RIGHT_C, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, ST_DENIED); EXPECT_EQ(granted, 0);
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheck)(sd, imp, RIGHT_A | RIGHT_C, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, ST_DENIED); EXPECT_EQ(granted, 0);
    /* MAXIMUM_ALLOWED yields every right the DACL grants */
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheck)(sd, imp, MAXIMUM_ALLOWED, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A | RIGHT_B);
    /* generic rights must already be mapped by the caller */
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheck)(sd, imp, GENERIC_READ, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, S(0xC00000E6));            /* STATUS_GENERIC_NOT_MAPPED */
    /* an explicit deny entry placed ahead of the allow */
    { BYTE sd2[256], acl2[256]; build_sd(sd2, acl2, TRUE);
      granted = 0xcc; as = 0xcc;
      s = UN(NtAccessCheck)(sd2, imp, RIGHT_B, &gm, &ps, &psl, &granted, &as);
      EXPECT_EQ(s, 0); EXPECT_EQ(as, ST_DENIED); EXPECT_EQ(granted, 0);
      granted = 0xcc; as = 0xcc;
      s = UN(NtAccessCheck)(sd2, imp, MAXIMUM_ALLOWED, &gm, &ps, &psl, &granted, &as);
      EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A); }
    /* primary token is not acceptable */
    prim = dup_tok(TOKEN_QUERY | TOKEN_DUPLICATE, 1, SecurityImpersonation);
    if (prim) { EXPECT_EQ(UN(NtAccessCheck)(sd, prim, RIGHT_A, &gm, &ps, &psl, &granted, &as), ST_NO_IMP); UN(NtClose)(prim); }
    /* identification-level tokens are accepted, anonymous-level ones are not */
    ident = dup_tok(TOKEN_QUERY | TOKEN_IMPERSONATE, 2, SecurityIdentification);
    if (ident) { as = 0xcc; s = UN(NtAccessCheck)(sd, ident, RIGHT_A, &gm, &ps, &psl, &granted, &as); EXPECT_EQ(s, 0); UN(NtClose)(ident); }
    anon = dup_tok(TOKEN_QUERY | TOKEN_IMPERSONATE, 2, SecurityAnonymous);
    if (anon) { s = UN(NtAccessCheck)(sd, anon, RIGHT_A, &gm, &ps, &psl, &granted, &as); EXPECT_EQ(s, ST_BAD_IMPLVL); UN(NtClose)(anon); }
    /* token handle without TOKEN_QUERY */
    { HANDLE nq = dup_tok(TOKEN_IMPERSONATE, 2, SecurityImpersonation);
      if (nq) { s = UN(NtAccessCheck)(sd, nq, RIGHT_A, &gm, &ps, &psl, &granted, &as); EXPECT_EQ(s, ST_DENIED); UN(NtClose)(nq); } }
    /* descriptor without owner is invalid */
    { BYTE sd3[256]; UN(RtlCreateSecurityDescriptor)(sd3, 1);
      s = UN(NtAccessCheck)(sd3, imp, RIGHT_A, &gm, &ps, &psl, &granted, &as);
      EXPECT_EQ(s, S(0xC0000079)); }          /* STATUS_INVALID_SECURITY_DESCR */
    /* handle and pointer errors */
    EXPECT_EQ(UN(NtAccessCheck)(sd, NULL, RIGHT_A, &gm, &ps, &psl, &granted, &as), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtAccessCheck)(sd, ev, RIGHT_A, &gm, &ps, &psl, &granted, &as), ST_TYPEMISM); CloseHandle(ev); }
    EXPECT_EQ(UN(NtAccessCheck)(sd, imp, RIGHT_A, NULL, &ps, &psl, &granted, &as), ST_AV);
    EXPECT_EQ(UN(NtAccessCheck)(sd, imp, RIGHT_A, &gm, &ps, &psl, NULL, &as), ST_AV);
    EXPECT_EQ(UN(NtAccessCheck)(sd, imp, RIGHT_A, &gm, &ps, &psl, &granted, NULL), ST_AV);
    EXPECT_EQ(UN(NtAccessCheck)(NULL, imp, RIGHT_A, &gm, &ps, &psl, &granted, &as), S(0xC0000079));
    /* privilege set buffer too small to describe privileges used (MAXIMUM_ALLOWED does not need any here) */
    psl = 0;
    s = UN(NtAccessCheck)(sd, imp, RIGHT_A, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, ST_BUFSMALL);
    UN(NtClose)(imp);
}

TEST(access_check_by_type)
{
    BYTE sd[256], acl[256]; HANDLE imp; ACCESS_MASK granted, gl[2]; NTSTATUS as, asl[2], s; ULONG psl; PRIVILEGE_SET ps; OBJECT_TYPE_LIST otl[2]; GUID g1 = {1,2,3,{4,5,6,7,8,9,10,11}};
    NEED_AC(); REQUIRE(UN(NtAccessCheckByType)); REQUIRE(UN(NtAccessCheckByTypeResultList));
    build_sd(sd, acl, FALSE);
    imp = IMP_DUP(TOKEN_QUERY | TOKEN_IMPERSONATE); CHECK(imp != NULL); if (!imp) return;
    psl = sizeof ps;
    /* no object type list: behaves like a plain access check */
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheckByType)(sd, NULL, imp, RIGHT_A, NULL, 0, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A);
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheckByType)(sd, NULL, imp, RIGHT_C, NULL, 0, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, ST_DENIED); EXPECT_EQ(granted, 0);
    /* single-entry list at level 0 */
    memset(otl, 0, sizeof otl); otl[0].Level = 0; otl[0].ObjectType = &g1;
    granted = 0xcc; as = 0xcc;
    s = UN(NtAccessCheckByType)(sd, NULL, imp, RIGHT_A | RIGHT_B, otl, 1, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, 0); EXPECT_EQ(as, 0); EXPECT_EQ(granted, RIGHT_A | RIGHT_B);
    /* result list: root plus one child, plain ACEs apply to every element */
    { GUID g2 = {9,8,7,{6,5,4,3,2,1,0,1}};
      otl[0].Level = 0; otl[0].ObjectType = &g1; otl[1].Level = 1; otl[1].ObjectType = &g2;
      gl[0] = gl[1] = 0xcc; asl[0] = asl[1] = 0xcc;
      s = UN(NtAccessCheckByTypeResultList)(sd, NULL, imp, RIGHT_A, otl, 2, &gm, &ps, &psl, gl, asl);
      EXPECT_EQ(s, 0); EXPECT_EQ(asl[0], 0); EXPECT_EQ(asl[1], 0); EXPECT_EQ(gl[0], RIGHT_A); EXPECT_EQ(gl[1], RIGHT_A);
      gl[0] = gl[1] = 0xcc; asl[0] = asl[1] = 0xcc;
      s = UN(NtAccessCheckByTypeResultList)(sd, NULL, imp, RIGHT_C, otl, 2, &gm, &ps, &psl, gl, asl);
      EXPECT_EQ(s, 0); EXPECT_EQ(asl[0], ST_DENIED); EXPECT_EQ(asl[1], ST_DENIED); EXPECT_EQ(gl[0], 0); EXPECT_EQ(gl[1], 0);
      /* first list element must be at level zero */
      otl[0].Level = 1;
      s = UN(NtAccessCheckByTypeResultList)(sd, NULL, imp, RIGHT_A, otl, 2, &gm, &ps, &psl, gl, asl);
      EXPECT_EQ(s, ST_INVPARAM);
      otl[0].Level = 0; }
    /* list count with a NULL list */
    s = UN(NtAccessCheckByType)(sd, NULL, imp, RIGHT_A, NULL, 2, &gm, &ps, &psl, &granted, &as);
    EXPECT_EQ(s, ST_INVPARAM);
    EXPECT_EQ(UN(NtAccessCheckByType)(sd, NULL, NULL, RIGHT_A, NULL, 0, &gm, &ps, &psl, &granted, &as), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAccessCheckByTypeResultList)(sd, NULL, NULL, RIGHT_A, otl, 1, &gm, &ps, &psl, gl, asl), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAccessCheckByTypeResultList)(sd, NULL, imp, RIGHT_A, NULL, 0, &gm, &ps, &psl, gl, asl), ST_INVPARAM);   /* the result-list form requires a type list */
    UN(NtClose)(imp);
}

/* ---- privilege adjustment ----------------------------------------------------------------- */
typedef struct { ULONG n; LUID_AND_ATTRIBUTES p[2]; } tp2;
#define SE_CHANGE_NOTIFY 23
#define SE_TCB 7

TEST(adjust_privileges_token)
{
    HANDLE t, qonly; tp2 st; union { ULONGLONG a; BYTE b[512]; } prev; ULONG ret = 0; NTSTATUS s; LONG a0;
    NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    t = dup_tok(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, 1, SecurityImpersonation); CHECK(t != NULL); if (!t) return;
    a0 = priv_attr(t, SE_CHANGE_NOTIFY);
    if (a0 < 0) { t_skip("token has no change-notify privilege"); UN(NtClose)(t); return; }
    CHECK(a0 & SE_PRIVILEGE_ENABLED);
    /* disable it and read back the previous state */
    memset(&st, 0, sizeof st); st.n = 1; st.p[0].Luid.LowPart = SE_CHANGE_NOTIFY; st.p[0].Attributes = 0;
    memset(&prev, 0xcc, sizeof prev); ret = 0xcc;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, sizeof prev, (PTOKEN_PRIVILEGES)prev.b, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 4 + sizeof(LUID_AND_ATTRIBUTES));
    EXPECT_EQ(((TOKEN_PRIVILEGES *)prev.b)->PrivilegeCount, 1);
    EXPECT_EQ(((TOKEN_PRIVILEGES *)prev.b)->Privileges[0].Luid.LowPart, SE_CHANGE_NOTIFY);
    EXPECT_EQ(((TOKEN_PRIVILEGES *)prev.b)->Privileges[0].Attributes & SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED);
    EXPECT_EQ(priv_attr(t, SE_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED, 0);
    /* re-enable, no PreviousState requested */
    st.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(priv_attr(t, SE_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED);
    /* previous-state buffer too small: no change is made and the needed length is returned */
    st.p[0].Attributes = 0; ret = 0;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 4, (PTOKEN_PRIVILEGES)prev.b, &ret);
    EXPECT_EQ(s, ST_BUFSMALL); EXPECT_EQ(ret, 4 + sizeof(LUID_AND_ATTRIBUTES));
    EXPECT_EQ(priv_attr(t, SE_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED);
    /* a privilege the token does not hold: STATUS_NOT_ALL_ASSIGNED success code */
    memset(&st, 0, sizeof st); st.n = 1; st.p[0].Luid.LowPart = SE_TCB; st.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (priv_attr(t, SE_TCB) == -1) {
        s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL);
        EXPECT_EQ(s, ST_NOT_ALL);
    }
    /* privilege 0 / out of range LUID */
    st.p[0].Luid.LowPart = 0x7777;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL);
    EXPECT_EQ(s, ST_NOT_ALL);
    /* two entries: one held, one not -> NOT_ALL_ASSIGNED and the held one still applies */
    memset(&st, 0, sizeof st); st.n = 2;
    st.p[0].Luid.LowPart = SE_CHANGE_NOTIFY; st.p[0].Attributes = 0;
    st.p[1].Luid.LowPart = 0x7777; st.p[1].Attributes = SE_PRIVILEGE_ENABLED;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL);
    EXPECT_EQ(s, ST_NOT_ALL);
    EXPECT_EQ(priv_attr(t, SE_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED, 0);
    /* DisableAllPrivileges ignores the new state */
    st.p[0].Attributes = SE_PRIVILEGE_ENABLED; st.n = 1;
    s = UN(NtAdjustPrivilegesToken)(t, TRUE, NULL, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    { union { ULONGLONG a; BYTE b[4096]; } q; ULONG got; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)q.b; int any = 0;
      if (OKS(UN(NtQueryInformationToken)(t, 3, q.b, sizeof q, &got))) for (DWORD i = 0; i < tp->PrivilegeCount; i++) if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) any = 1;
      EXPECT_EQ(any, 0); }
    /* without a new state and without DisableAll the call is invalid */
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, NULL, 0, NULL, NULL);
    EXPECT_EQ(s, ST_INVPARAM);
    /* zero-entry state: success, no change */
    memset(&st, 0, sizeof st);
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    UN(NtClose)(t);
    /* handle checks */
    qonly = dup_tok(TOKEN_QUERY, 1, SecurityImpersonation);
    if (qonly) { st.n = 1; st.p[0].Luid.LowPart = SE_CHANGE_NOTIFY;
        EXPECT_EQ(UN(NtAdjustPrivilegesToken)(qonly, FALSE, (PTOKEN_PRIVILEGES)&st, 0, NULL, NULL), ST_DENIED); UN(NtClose)(qonly); }
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(NULL, TRUE, NULL, 0, NULL, NULL), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtAdjustPrivilegesToken)(ev, TRUE, NULL, 0, NULL, NULL), ST_TYPEMISM); CloseHandle(ev); }
}

TEST(adjust_groups_token)
{
    HANDLE t; NTSTATUS s; tp2 dummy; struct { ULONG n; SID_AND_ATTRIBUTES g[1]; } ng;
    NEED(); REQUIRE(UN(NtAdjustGroupsToken));
    t = dup_tok(TOKEN_QUERY | TOKEN_ADJUST_GROUPS, 1, SecurityImpersonation); CHECK(t != NULL); if (!t) return;
    /* ResetToDefault with no state */
    s = UN(NtAdjustGroupsToken)(t, TRUE, NULL, 0, NULL, NULL);
    EXPECT_EQ(s, 0);
    /* Everyone is a mandatory group: it cannot be disabled */
    { LONG a = group_attr(t, &everyone);
      CHECK(a >= 0);
      if (a >= 0) CHECK(a & SE_GROUP_MANDATORY); }
    memset(&ng, 0, sizeof ng); ng.n = 1; ng.g[0].Sid = (PSID)&everyone; ng.g[0].Attributes = 0;
    s = UN(NtAdjustGroupsToken)(t, FALSE, (PTOKEN_GROUPS)&ng, 0, NULL, NULL);
    EXPECT_EQ(s, ST_CANT_DIS);
    /* a group the token does not have */
    ng.g[0].Sid = (PSID)&sys_sid; ng.g[0].Attributes = 0;
    s = UN(NtAdjustGroupsToken)(t, FALSE, (PTOKEN_GROUPS)&ng, 0, NULL, NULL);
    EXPECT_EQ(s, ST_NOT_ALL);
    s = UN(NtAdjustGroupsToken)(t, FALSE, NULL, 0, NULL, NULL);
    EXPECT_EQ(s, ST_INVPARAM);
    s = UN(NtAdjustGroupsToken)(t, TRUE, (PTOKEN_GROUPS)&ng, 0, NULL, NULL);
    EXPECT_EQ(s, 0);                     /* ResetToDefault wins over a supplied state */
    UN(NtClose)(t);
    { HANDLE q = dup_tok(TOKEN_QUERY, 1, SecurityImpersonation);
      if (q) { EXPECT_EQ(UN(NtAdjustGroupsToken)(q, TRUE, NULL, 0, NULL, NULL), ST_DENIED); UN(NtClose)(q); } }
    EXPECT_EQ(UN(NtAdjustGroupsToken)(NULL, TRUE, NULL, 0, NULL, NULL), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtAdjustGroupsToken)(ev, TRUE, NULL, 0, NULL, NULL), ST_TYPEMISM); CloseHandle(ev); }
}

/* ---- filtering and comparing ------------------------------------------------------------------- */
TEST(filter_token)
{
    HANDLE src, f = NULL; NTSTATUS s; ULONG before, after; struct { ULONG n; SID_AND_ATTRIBUTES g[1]; } sids; tp2 pr;
    NEED(); REQUIRE(UN(NtFilterToken));
    src = IMP_DUP(TOKEN_QUERY | TOKEN_DUPLICATE); CHECK(src != NULL); if (!src) return;
    before = priv_count(src);
    /* no filtering: an equivalent token of the same type */
    s = UN(NtFilterToken)(src, 0, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, 0); CHECK(f != NULL);
    if (f) { EXPECT_EQ(priv_count(f), before); EXPECT_EQ(tok_ulong(f, 8 /* TokenType */), 2); UN(NtClose)(f); f = NULL; }
    /* DISABLE_MAX_PRIVILEGE keeps only change-notify (disabled privileges are removed) */
    s = UN(NtFilterToken)(src, DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, 0);
    if (f) { after = priv_count(f); CHECK(after <= 1); CHECK(after <= before); UN(NtClose)(f); f = NULL; }
    /* delete a specific privilege */
    memset(&pr, 0, sizeof pr); pr.n = 1; pr.p[0].Luid.LowPart = SE_CHANGE_NOTIFY;
    s = UN(NtFilterToken)(src, 0, NULL, (PTOKEN_PRIVILEGES)&pr, NULL, &f);
    EXPECT_EQ(s, 0);
    if (f) { EXPECT_EQ(priv_attr(f, SE_CHANGE_NOTIFY), -1); EXPECT_EQ(priv_count(f), before - 1); UN(NtClose)(f); f = NULL; }
    /* deny-only for Everyone */
    memset(&sids, 0, sizeof sids); sids.n = 1; sids.g[0].Sid = (PSID)&everyone;
    s = UN(NtFilterToken)(src, 0, (PTOKEN_GROUPS)&sids, NULL, NULL, &f);
    EXPECT_EQ(s, 0);
    if (f) { LONG a = group_attr(f, &everyone); CHECK(a >= 0 && (a & SE_GROUP_USE_FOR_DENY_ONLY)); UN(NtClose)(f); f = NULL; }
    /* restricting SIDs make the token restricted */
    s = UN(NtFilterToken)(src, 0, NULL, NULL, (PTOKEN_GROUPS)&sids, &f);
    EXPECT_EQ(s, 0);
    if (f) { EXPECT_EQ(tok_ulong(f, 40 /* TokenIsRestricted */), 1); UN(NtClose)(f); f = NULL; }
    EXPECT_EQ(tok_ulong(src, 40), 0);
    /* sandbox-inert flag */
    s = UN(NtFilterToken)(src, SANDBOX_INERT, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, 0);
    if (f) { t_note("TokenSandBoxInert of a SANDBOX_INERT filtered token: %lu", tok_ulong(f, 15)); UN(NtClose)(f); f = NULL; }
    /* invalid flag bits */
    s = UN(NtFilterToken)(src, 0x100, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, 0);                    /* undefined flag bits are ignored */
    if (s >= 0 && f) { UN(NtClose)(f); }
    f = NULL;
    /* a SID that is not in the token cannot be disabled */
    sids.g[0].Sid = (PSID)&sys_sid;
    s = UN(NtFilterToken)(src, 0, (PTOKEN_GROUPS)&sids, NULL, NULL, &f);
    EXPECT_EQ(s, 0);                    /* SIDs the token does not have are ignored */
    if (s >= 0 && f) { UN(NtClose)(f); }
    f = NULL;
    UN(NtClose)(src);
    /* access and handle checks */
    { HANDLE q = dup_tok(TOKEN_QUERY, 2, SecurityImpersonation);
      if (q) { s = UN(NtFilterToken)(q, 0, NULL, NULL, NULL, &f); EXPECT_EQ(s, ST_DENIED); UN(NtClose)(q); } }
    EXPECT_EQ(UN(NtFilterToken)(NULL, 0, NULL, NULL, NULL, &f), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtFilterToken)(ev, 0, NULL, NULL, NULL, &f), ST_TYPEMISM); CloseHandle(ev); }
    { HANDLE s2 = IMP_DUP(TOKEN_QUERY | TOKEN_DUPLICATE); if (s2) { EXPECT_EQ(UN(NtFilterToken)(s2, 0, NULL, NULL, NULL, NULL), ST_AV); UN(NtClose)(s2); } }
}

TEST(filter_token_ex)
{
    HANDLE src, f = (HANDLE)(ULONG_PTR)0x1234; NTSTATUS s; tp2 pr;
    NEED(); REQUIRE(UN(NtFilterTokenEx));
    src = IMP_DUP(TOKEN_QUERY | TOKEN_DUPLICATE); CHECK(src != NULL); if (!src) return;
    /* Windows 10 22H2 does not implement the extended filter: every call fails before looking at its arguments */
    s = UN(NtFilterTokenEx)(src, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, S(0xC0000002)); EXPECT_EQ(f, (HANDLE)(ULONG_PTR)0x1234);
    memset(&pr, 0, sizeof pr); pr.n = 1; pr.p[0].Luid.LowPart = SE_CHANGE_NOTIFY;
    s = UN(NtFilterTokenEx)(src, DISABLE_MAX_PRIVILEGE, NULL, (PTOKEN_PRIVILEGES)&pr, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &f);
    EXPECT_EQ(s, S(0xC0000002));
    EXPECT_EQ(UN(NtFilterTokenEx)(NULL, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &f), S(0xC0000002));
    EXPECT_EQ(UN(NtFilterTokenEx)(src, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL), S(0xC0000002));
    UN(NtClose)(src);
}

TEST(compare_tokens)
{
    HANDLE a, b, f = NULL; BOOLEAN eq; NTSTATUS s; struct { ULONG n; SID_AND_ATTRIBUTES g[1]; } sids; tp2 pr;
    NEED(); REQUIRE(UN(NtCompareTokens)); REQUIRE(UN(NtFilterToken));
    a = IMP_DUP(TOKEN_QUERY | TOKEN_DUPLICATE); b = IMP_DUP(TOKEN_QUERY | TOKEN_DUPLICATE);
    CHECK(a && b); if (!a || !b) return;
    eq = 0xcc; s = UN(NtCompareTokens)(a, a, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 1);
    eq = 0xcc; s = UN(NtCompareTokens)(a, b, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 1);
    { HANDLE p = dup_tok(TOKEN_QUERY | TOKEN_DUPLICATE, 1, SecurityImpersonation);
      if (p) { eq = 0xcc; s = UN(NtCompareTokens)(a, p, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 1); UN(NtClose)(p); } }
    memset(&sids, 0, sizeof sids); sids.n = 1; sids.g[0].Sid = (PSID)&everyone;
    if (OKS(UN(NtFilterToken)(a, 0, (PTOKEN_GROUPS)&sids, NULL, NULL, &f)) && f) {
        eq = 0xcc; s = UN(NtCompareTokens)(a, f, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 0);
        UN(NtClose)(f); f = NULL; }
    memset(&pr, 0, sizeof pr); pr.n = 1; pr.p[0].Luid.LowPart = SE_CHANGE_NOTIFY;
    if (OKS(UN(NtFilterToken)(a, 0, NULL, (PTOKEN_PRIVILEGES)&pr, NULL, &f)) && f) {
        eq = 0xcc; s = UN(NtCompareTokens)(a, f, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 0);
        UN(NtClose)(f); f = NULL; }
    if (OKS(UN(NtFilterToken)(a, 0, NULL, NULL, (PTOKEN_GROUPS)&sids, &f)) && f) {
        eq = 0xcc; s = UN(NtCompareTokens)(a, f, &eq); EXPECT_EQ(s, 0); EXPECT_EQ(eq, 0);
        UN(NtClose)(f); f = NULL; }
    EXPECT_EQ(UN(NtCompareTokens)(NULL, a, &eq), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCompareTokens)(a, NULL, &eq), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCompareTokens)(a, b, NULL), ST_AV);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtCompareTokens)(ev, a, &eq), ST_TYPEMISM); EXPECT_EQ(UN(NtCompareTokens)(a, ev, &eq), ST_TYPEMISM); CloseHandle(ev); }
    { HANDLE nq = dup_tok(TOKEN_IMPERSONATE, 2, SecurityImpersonation);
      if (nq) { EXPECT_EQ(UN(NtCompareTokens)(nq, a, &eq), ST_DENIED); UN(NtClose)(nq); } }
    UN(NtClose)(a); UN(NtClose)(b);
}

TEST(adjust_token_claims_and_device_groups)
{
    HANDLE t; NTSTATUS s; ULONG u = 0xcc, d = 0xcc, g = 0xcc;
    NEED(); REQUIRE(UN(NtAdjustTokenClaimsAndDeviceGroups));
    t = dup_tok(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES, 1, SecurityImpersonation);
    CHECK(t != NULL); if (!t) return;
    /* not implemented in the user/kernel interface on this build: arguments are never examined */
    s = UN(NtAdjustTokenClaimsAndDeviceGroups)(t, FALSE, FALSE, FALSE, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, &u, &d, &g);
    EXPECT_EQ(s, S(0xC0000002)); EXPECT_EQ(u, 0xcc); EXPECT_EQ(d, 0xcc); EXPECT_EQ(g, 0xcc);
    s = UN(NtAdjustTokenClaimsAndDeviceGroups)(t, TRUE, TRUE, TRUE, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, &u, &d, &g);
    EXPECT_EQ(s, S(0xC0000002));
    UN(NtClose)(t);
    EXPECT_EQ(UN(NtAdjustTokenClaimsAndDeviceGroups)(NULL, FALSE, FALSE, FALSE, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, &u, &d, &g), S(0xC0000002));
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL);
      EXPECT_EQ(UN(NtAdjustTokenClaimsAndDeviceGroups)(ev, FALSE, FALSE, FALSE, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, &u, &d, &g), S(0xC0000002));
      CloseHandle(ev); }
}

/* ---- audit alarm services (all gated on SeAuditPrivilege) ------------------------------------------- */
#define SE_AUDIT 21

static void us_init(UNICODE_STRING *u, const WCHAR *w) { u->Buffer = (PWSTR)w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }

TEST(audit_alarm_requires_privilege)
{
    BYTE sd[256], acl[256]; HANDLE pt = NULL, imp; UNICODE_STRING sub, typ, nam; ACCESS_MASK granted, gl[1]; NTSTATUS as, asl[1], s; BOOLEAN goc; OBJECT_TYPE_LIST otl; GUID g1 = {1,2,3,{4,5,6,7,8,9,10,11}};
    NEED_AC();
    REQUIRE(UN(NtAccessCheckAndAuditAlarm)); REQUIRE(UN(NtAccessCheckByTypeAndAuditAlarm)); REQUIRE(UN(NtAccessCheckByTypeResultListAndAuditAlarm));
    REQUIRE(UN(NtAccessCheckByTypeResultListAndAuditAlarmByHandle)); REQUIRE(UN(NtCloseObjectAuditAlarm)); REQUIRE(UN(NtDeleteObjectAuditAlarm));
    if (!OKS(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &pt))) { CHECK(0); return; }
    if (priv_attr(pt, SE_AUDIT) != -1) { t_skip("token holds SeAuditPrivilege"); UN(NtClose)(pt); return; }
    UN(NtClose)(pt);
    build_sd(sd, acl, FALSE);
    us_init(&sub, L"nt1a_subsys"); us_init(&typ, L"nt1a_type"); us_init(&nam, L"nt1a_object");
    imp = IMP_DUP(TOKEN_QUERY | TOKEN_IMPERSONATE); CHECK(imp != NULL);
    memset(&otl, 0, sizeof otl); otl.ObjectType = &g1;

    /* Without an impersonation token on the thread the services refuse first */
    granted = 0xcc; as = 0xcc; goc = 0xcc;
    s = UN(NtAccessCheckAndAuditAlarm)(&sub, (PVOID)1, &typ, &nam, sd, RIGHT_A, &gm, FALSE, &granted, &as, &goc);
    EXPECT_EQ(s, ST_NO_IMP);
    EXPECT_EQ(UN(NtCloseObjectAuditAlarm)(&sub, (PVOID)1, TRUE), ST_PRIVNH);
    EXPECT_EQ(UN(NtDeleteObjectAuditAlarm)(&sub, (PVOID)1, TRUE), ST_PRIVNH);
    REQUIRE(UN(NtSetInformationThread));
    if (!imp || !OKS(UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-2, 5 /* ThreadImpersonationToken */, &imp, sizeof imp))) { CHECK(0); return; }
    granted = 0xcc; as = 0xcc; goc = 0xcc;
    s = UN(NtAccessCheckAndAuditAlarm)(&sub, (PVOID)1, &typ, &nam, sd, RIGHT_A, &gm, FALSE, &granted, &as, &goc);
    EXPECT_EQ(s, ST_PRIVNH);
    s = UN(NtAccessCheckByTypeAndAuditAlarm)(&sub, (PVOID)1, &typ, &nam, sd, NULL, RIGHT_A, 0 /* AuditEventObjectAccess */, 0, &otl, 1, &gm, FALSE, &granted, &as, &goc);
    EXPECT_EQ(s, ST_PRIVNH);
    s = UN(NtAccessCheckByTypeResultListAndAuditAlarm)(&sub, (PVOID)1, &typ, &nam, sd, NULL, RIGHT_A, 0, 0, &otl, 1, &gm, FALSE, gl, asl, &goc);
    EXPECT_EQ(s, ST_PRIVNH);
    if (imp) {
        s = UN(NtAccessCheckByTypeResultListAndAuditAlarmByHandle)(&sub, (PVOID)1, imp, &typ, &nam, sd, NULL, RIGHT_A, 0, 0, &otl, 1, &gm, FALSE, gl, asl, &goc);
        EXPECT_EQ(s, ST_PRIVNH);
    }
    s = UN(NtCloseObjectAuditAlarm)(&sub, (PVOID)1, TRUE);
    EXPECT_EQ(s, ST_PRIVNH);
    s = UN(NtDeleteObjectAuditAlarm)(&sub, (PVOID)1, TRUE);
    EXPECT_EQ(s, ST_PRIVNH);
    { HANDLE none = NULL; UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-2, 5, &none, sizeof none); }   /* revert */
    if (imp) UN(NtClose)(imp);
}
