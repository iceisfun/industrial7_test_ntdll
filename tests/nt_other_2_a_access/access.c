/* ZwAccessCheck* family: impersonation-token access checks against a hand-built security descriptor
 * (plain, by-type, by-type result list) and the audit-alarm variants (privilege gated).
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_DENIED       S(0xC0000022)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_PRIV_NOT_HELD S(0xC0000061)
#define ST_NO_IMP_TOKEN S(0xC000005C)
#define ST_BAD_IMP_LEVEL S(0xC00000A5)
#define NT_CUR_PROC ((HANDLE)(LONG_PTR)-1)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)

UDECL(NTSTATUS, ZwAccessCheck, (PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, ZwAccessCheckByType, (PSECURITY_DESCRIPTOR, PSID, HANDLE, ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, ZwAccessCheckByTypeResultList, (PSECURITY_DESCRIPTOR, PSID, HANDLE, ACCESS_MASK, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, ZwAccessCheckAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, ACCESS_MASK, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, ZwAccessCheckByTypeAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, ZwAccessCheckByTypeResultListAndAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, ZwAccessCheckByTypeResultListAndAuditAlarmByHandle, (PUNICODE_STRING, PVOID, HANDLE, PUNICODE_STRING, PUNICODE_STRING, PSECURITY_DESCRIPTOR, PSID, ACCESS_MASK, ULONG, ULONG, POBJECT_TYPE_LIST, ULONG, PGENERIC_MAPPING, BOOLEAN, PACCESS_MASK, PNTSTATUS, PBOOLEAN));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)

static BYTE g_everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };   /* S-1-1-0 */
static GENERIC_MAPPING g_map = { 1, 2, 4, 7 };

typedef struct {
    SECURITY_DESCRIPTOR sd;
    BYTE acl[64];
    HANDLE imp, prim, anon;
} ctx_t;

static int setup(ctx_t *c, ACCESS_MASK allowed)
{
    memset(c, 0, sizeof *c);
    if (!UN(RtlCreateSecurityDescriptor) || !UN(NtOpenProcessToken) || !UN(NtDuplicateToken)) return 0;
    UN(RtlCreateSecurityDescriptor)(&c->sd, 1);
    UN(RtlSetOwnerSecurityDescriptor)(&c->sd, g_everyone, FALSE);
    UN(RtlSetGroupSecurityDescriptor)(&c->sd, g_everyone, FALSE);
    UN(RtlCreateAcl)((PACL)c->acl, sizeof c->acl, 2);
    UN(RtlAddAccessAllowedAce)((PACL)c->acl, 2, allowed, g_everyone);
    UN(RtlSetDaclSecurityDescriptor)(&c->sd, TRUE, (PACL)c->acl, FALSE);
    if (UN(NtOpenProcessToken)(NT_CUR_PROC, TOKEN_DUPLICATE | TOKEN_QUERY, &c->prim)) return 0;
    SECURITY_QUALITY_OF_SERVICE q = { sizeof q, SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.SecurityQualityOfService = &q;
    if (UN(NtDuplicateToken)(c->prim, TOKEN_QUERY | TOKEN_IMPERSONATE, &oa, FALSE, 2, &c->imp)) return 0;
    q.ImpersonationLevel = SecurityAnonymous;
    if (UN(NtDuplicateToken)(c->prim, TOKEN_QUERY | TOKEN_IMPERSONATE, &oa, FALSE, 2, &c->anon)) c->anon = NULL;
    return 1;
}
static void teardown(ctx_t *c)
{
    if (c->imp) UN(NtClose)(c->imp);
    if (c->prim) UN(NtClose)(c->prim);
    if (c->anon) UN(NtClose)(c->anon);
}

static int has_privilege(HANDLE tok, LONG luid_low)
{
    BYTE buf[4096]; ULONG ret = 0;
    if (UN(NtQueryInformationToken)(tok, 3, buf, sizeof buf, &ret)) return 0;
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == (DWORD)luid_low && tp->Privileges[i].Luid.HighPart == 0) return 1;
    return 0;
}

TEST(access_check)
{
    REQUIRE(UN(ZwAccessCheck));
    ctx_t c; if (!setup(&c, 3)) { teardown(&c); t_skip("cannot build SD/token"); return; }
    PRIVILEGE_SET ps; ULONG pslen = sizeof ps; ACCESS_MASK granted; NTSTATUS as;
#define AC(desired, want_ret) do { granted = 0xcccccccc; as = 0x7777; pslen = sizeof ps; memset(&ps, 0, sizeof ps); \
        EXPECT_ST(UN(ZwAccessCheck)(&c.sd, c.imp, (desired), &g_map, &ps, &pslen, &granted, &as), (want_ret)); } while (0)
    AC(1, 0); EXPECT_EQ(granted, 1); EXPECT_ST(as, 0);
    AC(2, 0); EXPECT_EQ(granted, 2); EXPECT_ST(as, 0);
    AC(3, 0); EXPECT_EQ(granted, 3); EXPECT_ST(as, 0);
    AC(4, 0); EXPECT_EQ(granted, 0); EXPECT_ST(as, ST_DENIED);          /* not in the DACL */
    AC(5, 0); EXPECT_EQ(granted, 0); EXPECT_ST(as, ST_DENIED);          /* partly denied: nothing granted */
    AC(0x02000000, 0); EXPECT_EQ(granted, 0x60003); EXPECT_ST(as, 0);   /* MAXIMUM_ALLOWED: DACL bits plus owner-implied READ_CONTROL|WRITE_DAC (token user is owner via Everyone) */
    /* generic bits must be mapped by the caller */
    AC(0x80000000, S(0xC00000E6)); EXPECT_ST(as, 0x7777);              /* STATUS_GENERIC_NOT_MAPPED */
    AC(0x10000000, S(0xC00000E6));
    AC(0x40000000, S(0xC00000E6));
    AC(0x20000000, S(0xC00000E6));
    /* empty DACL grants nothing; NULL DACL grants everything */
    SECURITY_DESCRIPTOR nulldacl; UN(RtlCreateSecurityDescriptor)(&nulldacl, 1);
    UN(RtlSetOwnerSecurityDescriptor)(&nulldacl, g_everyone, FALSE); UN(RtlSetGroupSecurityDescriptor)(&nulldacl, g_everyone, FALSE);
    UN(RtlSetDaclSecurityDescriptor)(&nulldacl, TRUE, NULL, FALSE);
    granted = 0; as = 0x7777;
    EXPECT_ST(UN(ZwAccessCheck)(&nulldacl, c.imp, 7, &g_map, &ps, &pslen, &granted, &as), 0);
    EXPECT_EQ(granted, 7); EXPECT_ST(as, 0);
    BYTE empty[16]; UN(RtlCreateAcl)((PACL)empty, sizeof empty, 2);
    UN(RtlSetDaclSecurityDescriptor)(&nulldacl, TRUE, (PACL)empty, FALSE);
    EXPECT_ST(UN(ZwAccessCheck)(&nulldacl, c.imp, 1, &g_map, &ps, &pslen, &granted, &as), 0);
    EXPECT_EQ(granted, 0); EXPECT_ST(as, ST_DENIED);
    /* token errors */
    EXPECT_ST(UN(ZwAccessCheck)(&c.sd, c.prim, 1, &g_map, &ps, &pslen, &granted, &as), ST_NO_IMP_TOKEN);
    EXPECT_ST(UN(ZwAccessCheck)(&c.sd, BOGUS, 1, &g_map, &ps, &pslen, &granted, &as), ST_INV_HANDLE);
    EXPECT_ST(UN(ZwAccessCheck)(&c.sd, NULL, 1, &g_map, &ps, &pslen, &granted, &as), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(ZwAccessCheck)(&c.sd, ev, 1, &g_map, &ps, &pslen, &granted, &as), S(0xC0000024));
    CloseHandle(ev);
    if (c.anon) EXPECT_ST(UN(ZwAccessCheck)(&c.sd, c.anon, 1, &g_map, &ps, &pslen, &granted, &as), ST_BAD_IMP_LEVEL);
    /* SD without owner is not a valid descriptor for a check */
    SECURITY_DESCRIPTOR noowner; UN(RtlCreateSecurityDescriptor)(&noowner, 1);
    NTSTATUS st = UN(ZwAccessCheck)(&noowner, c.imp, 1, &g_map, &ps, &pslen, &granted, &as);
    EXPECT_ST(st, S(0xC0000079));    /* STATUS_INVALID_SECURITY_DESCR */
    /* unwritable outputs */
    st = UN(ZwAccessCheck)(&c.sd, c.imp, 1, &g_map, &ps, &pslen, (PACCESS_MASK)(ULONG_PTR)8, &as);
    EXPECT_ST(st, S(0xC0000005));
    CHECK(t_proc("NtAccessCheck") == t_proc("ZwAccessCheck"));
    teardown(&c);
}

TEST(access_check_by_type)
{
    REQUIRE(UN(ZwAccessCheckByType)); REQUIRE(UN(ZwAccessCheckByTypeResultList));
    ctx_t c; if (!setup(&c, 3)) { teardown(&c); t_skip("cannot build SD/token"); return; }
    PRIVILEGE_SET ps; ULONG pslen = sizeof ps; ACCESS_MASK granted; NTSTATUS as;
    /* no object type list: behaves like the plain check */
    granted = 0xcccccccc; as = 0x7777;
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, c.imp, 3, NULL, 0, &g_map, &ps, &pslen, &granted, &as), 0);
    EXPECT_EQ(granted, 3); EXPECT_ST(as, 0);
    granted = 0xcccccccc; as = 0x7777;
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, c.imp, 4, NULL, 0, &g_map, &ps, &pslen, &granted, &as), 0);
    EXPECT_EQ(granted, 0); EXPECT_ST(as, ST_DENIED);
    /* single-entry object type list */
    GUID g0 = { 0x11111111, 0x2222, 0x3333, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    OBJECT_TYPE_LIST ot[2];
    memset(ot, 0, sizeof ot);
    ot[0].Level = 0; ot[0].ObjectType = &g0;
    granted = 0xcccccccc; as = 0x7777;
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, c.imp, 1, ot, 1, &g_map, &ps, &pslen, &granted, &as), 0);
    EXPECT_EQ(granted, 1); EXPECT_ST(as, 0);
    /* list must start at level 0 */
    ot[0].Level = 1;
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, c.imp, 1, ot, 1, &g_map, &ps, &pslen, &granted, &as), S(0xC000000D));
    ot[0].Level = 0;
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, BOGUS, 1, ot, 1, &g_map, &ps, &pslen, &granted, &as), ST_INV_HANDLE);
    EXPECT_ST(UN(ZwAccessCheckByType)(&c.sd, NULL, c.prim, 1, ot, 1, &g_map, &ps, &pslen, &granted, &as), ST_NO_IMP_TOKEN);

    /* result list: per-element results */
    GUID g1 = { 0x44444444, 0x5555, 0x6666, { 9, 8, 7, 6, 5, 4, 3, 2 } };
    ot[0].Level = 0; ot[0].ObjectType = &g0;
    ot[1].Level = 1; ot[1].ObjectType = &g1;
    ACCESS_MASK gr[2] = { 0xcccccccc, 0xcccccccc }; NTSTATUS rs[2] = { 0x7777, 0x7777 };
    EXPECT_ST(UN(ZwAccessCheckByTypeResultList)(&c.sd, NULL, c.imp, 2, ot, 2, &g_map, &ps, &pslen, gr, rs), 0);
    EXPECT_EQ(gr[0], 2); EXPECT_EQ(gr[1], 2); EXPECT_ST(rs[0], 0); EXPECT_ST(rs[1], 0);
    gr[0] = gr[1] = 0xcccccccc; rs[0] = rs[1] = 0x7777;
    EXPECT_ST(UN(ZwAccessCheckByTypeResultList)(&c.sd, NULL, c.imp, 4, ot, 2, &g_map, &ps, &pslen, gr, rs), 0);
    EXPECT_EQ(gr[0], 0); EXPECT_EQ(gr[1], 0); EXPECT_ST(rs[0], ST_DENIED); EXPECT_ST(rs[1], ST_DENIED);
    gr[0] = gr[1] = 0xcccccccc; rs[0] = rs[1] = 0x7777;
    EXPECT_ST(UN(ZwAccessCheckByTypeResultList)(&c.sd, NULL, c.imp, 0x02000000, ot, 2, &g_map, &ps, &pslen, gr, rs), 0);
    EXPECT_EQ(gr[0], 0x60003); EXPECT_EQ(gr[1], 0x60003);
    EXPECT_ST(UN(ZwAccessCheckByTypeResultList)(&c.sd, NULL, BOGUS, 1, ot, 2, &g_map, &ps, &pslen, gr, rs), ST_INV_HANDLE);
    EXPECT_ST(UN(ZwAccessCheckByTypeResultList)(&c.sd, NULL, c.prim, 1, ot, 2, &g_map, &ps, &pslen, gr, rs), ST_NO_IMP_TOKEN);
    CHECK(t_proc("NtAccessCheckByType") == t_proc("ZwAccessCheckByType"));
    CHECK(t_proc("NtAccessCheckByTypeResultList") == t_proc("ZwAccessCheckByTypeResultList"));
    teardown(&c);
}

TEST(access_check_audit_alarm_privilege)
{
    REQUIRE(UN(ZwAccessCheckAndAuditAlarm)); REQUIRE(UN(ZwAccessCheckByTypeAndAuditAlarm));
    REQUIRE(UN(ZwAccessCheckByTypeResultListAndAuditAlarm)); REQUIRE(UN(ZwAccessCheckByTypeResultListAndAuditAlarmByHandle));
    ctx_t c; if (!setup(&c, 3)) { teardown(&c); t_skip("cannot build SD/token"); return; }
    if (has_privilege(c.prim, 21 /*SeAuditPrivilege*/)) { teardown(&c); t_skip("token holds SeAuditPrivilege; the denial path is not reachable"); return; }
    UNICODE_STRING sub, typ, obj;
    UN(RtlInitUnicodeString)(&sub, L"ConformanceTest"); UN(RtlInitUnicodeString)(&typ, L"File"); UN(RtlInitUnicodeString)(&obj, L"\\Dummy");
    ACCESS_MASK granted = 0xcccccccc, grl[2] = { 0xcccccccc, 0xcccccccc }; NTSTATUS as = 0x7777, asl[2] = { 0x7777, 0x7777 }; BOOLEAN onclose = 0x5a;
    GUID g0 = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    OBJECT_TYPE_LIST ot = { 0, 0, &g0 };
    /* without an impersonation token on the calling thread the check stops before the privilege test */
    EXPECT_ST(UN(ZwAccessCheckAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, 1, &g_map, FALSE, &granted, &as, &onclose), ST_NO_IMP_TOKEN);
    EXPECT_ST(UN(ZwAccessCheckByTypeAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, NULL, 1, 0, 0, &ot, 1, &g_map, FALSE, &granted, &as, &onclose), ST_NO_IMP_TOKEN);
    EXPECT_ST(UN(ZwAccessCheckByTypeResultListAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, NULL, 1, 0, 0, &ot, 1, &g_map, FALSE, grl, asl, &onclose), ST_NO_IMP_TOKEN);
    HANDLE tok = c.imp;
    EXPECT_ST(UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-2, 5 /*ThreadImpersonationToken*/, &tok, sizeof tok), 0);
    EXPECT_ST(UN(ZwAccessCheckAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, 1, &g_map, FALSE, &granted, &as, &onclose), ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(ZwAccessCheckByTypeAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, NULL, 1, 0 /*AuditEventObjectAccess*/, 0, &ot, 1, &g_map, FALSE, &granted, &as, &onclose), ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(ZwAccessCheckByTypeResultListAndAuditAlarm)(&sub, NULL, &typ, &obj, &c.sd, NULL, 1, 0, 0, &ot, 1, &g_map, FALSE, grl, asl, &onclose), ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(ZwAccessCheckByTypeResultListAndAuditAlarmByHandle)(&sub, NULL, c.imp, &typ, &obj, &c.sd, NULL, 1, 0, 0, &ot, 1, &g_map, FALSE, grl, asl, &onclose), ST_PRIV_NOT_HELD);
    tok = NULL;
    UN(NtSetInformationThread)((HANDLE)(LONG_PTR)-2, 5, &tok, sizeof tok);
    CHECK(t_proc("NtAccessCheckAndAuditAlarm") == t_proc("ZwAccessCheckAndAuditAlarm"));
    CHECK(t_proc("NtAccessCheckByTypeAndAuditAlarm") == t_proc("ZwAccessCheckByTypeAndAuditAlarm"));
    CHECK(t_proc("NtAccessCheckByTypeResultListAndAuditAlarm") == t_proc("ZwAccessCheckByTypeResultListAndAuditAlarm"));
    CHECK(t_proc("NtAccessCheckByTypeResultListAndAuditAlarmByHandle") == t_proc("ZwAccessCheckByTypeResultListAndAuditAlarmByHandle"));
    teardown(&c);
}
