/* Tokens and object security: privilege adjustment, filtering, token information
 * updates, NtAccessCheck and security-descriptor queries. Works on duplicates of the
 * caller's token and on private objects only. */
#include "t.h"

UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationToken, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtAdjustPrivilegesToken, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG));
UDECL(NTSTATUS, NtFilterToken, (HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, PHANDLE));
UDECL(NTSTATUS, NtAccessCheck, (PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, PNTSTATUS));
UDECL(NTSTATUS, NtQuerySecurityObject, (HANDLE, ULONG, PSECURITY_DESCRIPTOR, ULONG, PULONG));
UDECL(NTSTATUS, NtSetSecurityObject, (HANDLE, ULONG, PSECURITY_DESCRIPTOR));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlAddAccessDeniedAceEx, (PACL, ULONG, ULONG, ACCESS_MASK, PSID));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG));
UDECL(NTSTATUS, RtlSetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID, BOOLEAN));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN));
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XT_PRIV_CHANGE_NOTIFY 23
typedef struct { BYTE rev, count; BYTE auth[6]; ULONG sub[4]; } xt_sid;
static const xt_sid xt_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const xt_sid xt_system = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
typedef struct { BYTE type, flags; WORD size; ULONG mask; } xt_ace;

#define XT_NEED() do { REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose)); } while (0)

/* Impersonation-level duplicate of the process token. */
static HANDLE xt_dup(ACCESS_MASK access, ULONG type)
{
    HANDLE src = NULL, dup = NULL; SECURITY_QUALITY_OF_SERVICE qos; OBJECT_ATTRIBUTES oa; NTSTATUS s;
    if (!XOK(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &src))) return NULL;
    qos.Length = sizeof qos; qos.ImpersonationLevel = SecurityImpersonation; qos.ContextTrackingMode = 0; qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    oa.SecurityQualityOfService = &qos;
    s = UN(NtDuplicateToken)(src, access, &oa, FALSE, type, &dup);
    UN(NtClose)(src);
    return XOK(s) ? dup : NULL;
}
/* Find a privilege in the token; returns attributes or -1 when absent. */
static LONG xt_priv_attr(HANDLE tok, ULONG luid)
{
    union { ULONGLONG a; BYTE b[2048]; } buf; ULONG got = 0; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf.b;
    if (!XOK(UN(NtQueryInformationToken)(tok, 3, buf.b, sizeof buf, &got))) return -2;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == luid && tp->Privileges[i].Luid.HighPart == 0) return (LONG)tp->Privileges[i].Attributes;
    return -1;
}
static BOOL xt_have_notify(HANDLE t) { LONG a = xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY); if (a < 0) { t_skip("token has no change-notify privilege"); return FALSE; } return TRUE; }

TEST(nt_token_x_adjust_disable_enable_remove)
{
    HANDLE t; struct { DWORD n; LUID_AND_ATTRIBUTES p[1]; } ns, prev; ULONG ret = 0; NTSTATUS s; LONG a; XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    if (!xt_have_notify(t)) { UN(NtClose)(t); return; }
    ns.n = 1; ns.p[0].Luid.LowPart = XT_PRIV_CHANGE_NOTIFY; ns.p[0].Luid.HighPart = 0; ns.p[0].Attributes = 0;
    memset(&prev, 0xcc, sizeof prev);
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof prev, (PTOKEN_PRIVILEGES)&prev, &ret);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(prev.n, 1); EXPECT_EQ(prev.p[0].Luid.LowPart, XT_PRIV_CHANGE_NOTIFY); CHECK(prev.p[0].Attributes & SE_PRIVILEGE_ENABLED); EXPECT_EQ(ret, 16); }
    a = xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY); CHECK(a >= 0 && !(a & SE_PRIVILEGE_ENABLED));
    ns.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof ns, NULL, NULL), 0);
    a = xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY); CHECK(a >= 0 && (a & SE_PRIVILEGE_ENABLED));
    ns.p[0].Attributes = SE_PRIVILEGE_REMOVED;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof ns, NULL, NULL), 0);
    EXPECT_EQ(xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY), -1);
    ns.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof ns, NULL, NULL), XS(0x106)); /* no longer held */
    UN(NtClose)(t);
}
TEST(nt_token_x_adjust_unknown_privilege)
{
    HANDLE t; struct { DWORD n; LUID_AND_ATTRIBUTES p[1]; } ns; XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    ns.n = 1; ns.p[0].Luid.LowPart = 0x7777; ns.p[0].Luid.HighPart = 0; ns.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof ns, NULL, NULL), XS(0x106));
    UN(NtClose)(t);
}
TEST(nt_token_x_adjust_requires_access)
{
    HANDLE t = NULL; struct { DWORD n; LUID_AND_ATTRIBUTES p[1]; } ns; XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &t), 0); if (!t) return;
    ns.n = 1; ns.p[0].Luid.LowPart = XT_PRIV_CHANGE_NOTIFY; ns.p[0].Luid.HighPart = 0; ns.p[0].Attributes = SE_PRIVILEGE_ENABLED;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof ns, NULL, NULL), XS(0xC0000022));
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, TRUE, NULL, 0, NULL, NULL), XS(0xC0000022));
    UN(NtClose)(t);
}
TEST(nt_token_x_adjust_disable_all)
{
    HANDLE t; union { ULONGLONG a; BYTE b[2048]; } buf; ULONG got; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf.b; int enabled = 0; XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)(t, TRUE, NULL, 0, NULL, NULL), 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 3, buf.b, sizeof buf, &got), 0);
    for (DWORD i = 0; i < tp->PrivilegeCount; i++) if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) enabled++;
    EXPECT_EQ(enabled, 0);
    UN(NtClose)(t);
}
TEST(nt_token_x_adjust_previous_state_too_small)
{
    HANDLE t; struct { DWORD n; LUID_AND_ATTRIBUTES p[1]; } ns; BYTE small[4]; ULONG ret = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    if (!xt_have_notify(t)) { UN(NtClose)(t); return; }
    ns.n = 1; ns.p[0].Luid.LowPart = XT_PRIV_CHANGE_NOTIFY; ns.p[0].Luid.HighPart = 0; ns.p[0].Attributes = 0;
    s = UN(NtAdjustPrivilegesToken)(t, FALSE, (PTOKEN_PRIVILEGES)&ns, sizeof small, (PTOKEN_PRIVILEGES)small, &ret);   /* the length argument describes the previous-state buffer */
    EXPECT_EQ(s, XS(0xC0000023)); EXPECT_EQ(ret, 16);
    CHECK(xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED); /* nothing was changed */
    UN(NtClose)(t);
}
TEST(nt_token_x_adjust_bad_handle)
{
    XT_NEED(); REQUIRE(UN(NtAdjustPrivilegesToken));
    EXPECT_EQ(UN(NtAdjustPrivilegesToken)((HANDLE)(ULONG_PTR)0x7ffc, TRUE, NULL, 0, NULL, NULL), XS(0xC0000008));
}
TEST(nt_token_x_rtl_adjust_privilege_process)
{
    BOOLEAN was = 0xcc; NTSTATUS s; XT_NEED(); REQUIRE(UN(RtlAdjustPrivilege));
    s = UN(RtlAdjustPrivilege)(XT_PRIV_CHANGE_NOTIFY, TRUE, FALSE, &was);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        was = 0xcc;
        EXPECT_EQ(UN(RtlAdjustPrivilege)(XT_PRIV_CHANGE_NOTIFY, TRUE, FALSE, &was), 0);
        CHECK(was != 0);                                          /* now it was enabled */
    }
}
TEST(nt_token_x_rtl_adjust_privilege_unknown_and_no_token)
{
    BOOLEAN was = 0; XT_NEED(); REQUIRE(UN(RtlAdjustPrivilege));
    EXPECT_EQ(UN(RtlAdjustPrivilege)(0x7777, TRUE, FALSE, &was), XS(0xC0000061));
    EXPECT_EQ(UN(RtlAdjustPrivilege)(XT_PRIV_CHANGE_NOTIFY, TRUE, TRUE, &was), XS(0xC000007C));  /* thread has no token */
}
TEST(nt_token_x_rtl_adjust_privilege_thread_token)
{
    HANDLE t; BOOLEAN was = 0; BOOL (WINAPI *set_token)(PHANDLE, HANDLE); XT_NEED(); REQUIRE(UN(RtlAdjustPrivilege)); REQUIRE(UIN("kernel32.dll", SetThreadToken));
    set_token = (void *)UIN("kernel32.dll", SetThreadToken);
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    if (set_token(NULL, t)) {
        EXPECT_EQ(UN(RtlAdjustPrivilege)(XT_PRIV_CHANGE_NOTIFY, FALSE, TRUE, &was), 0);
        CHECK(was != 0);
        CHECK(!(xt_priv_attr(t, XT_PRIV_CHANGE_NOTIFY) & SE_PRIVILEGE_ENABLED));
        EXPECT_EQ(UN(RtlAdjustPrivilege)(XT_PRIV_CHANGE_NOTIFY, TRUE, TRUE, &was), 0);
        CHECK(!was);
        set_token(NULL, NULL);
    } else t_note("SetThreadToken failed");
    UN(NtClose)(t);
}

/* ---- NtFilterToken --------------------------------------------------------- */
static HANDLE xt_open_dup_query(void)
{
    HANDLE h = NULL;
    if (!XOK(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &h))) return NULL;
    return h;
}
TEST(nt_token_x_filter_disable_max_privilege)
{
    HANDLE src, nt = NULL; union { ULONGLONG a; BYTE b[2048]; } buf; ULONG got; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf.b; int others = 0, seen = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtFilterToken));
    src = xt_open_dup_query(); CHECK(src != NULL); if (!src) return;
    s = UN(NtFilterToken)(src, 1 /* DISABLE_MAX_PRIVILEGE */, NULL, NULL, NULL, &nt);
    EXPECT_EQ(s, 0);
    if (s == 0 && nt) {
        EXPECT_EQ(UN(NtQueryInformationToken)(nt, 3, buf.b, sizeof buf, &got), 0);
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            if (tp->Privileges[i].Luid.LowPart == XT_PRIV_CHANGE_NOTIFY) seen++;
            else if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) others++;
        }
        EXPECT_EQ(others, 0); CHECK(seen <= 1);
        t_note("privileges left after DISABLE_MAX_PRIVILEGE: %lu", tp->PrivilegeCount);
        { ULONG type = 0; EXPECT_EQ(UN(NtQueryInformationToken)(nt, 8, &type, 4, &got), 0); EXPECT_EQ(type, 1); } /* still a primary token */
        UN(NtClose)(nt);
    }
    UN(NtClose)(src);
}
TEST(nt_token_x_filter_restricting_sid)
{
    HANDLE src, nt = NULL; struct { DWORD n; SID_AND_ATTRIBUTES g[1]; } rs; ULONG restricted = 9, got; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtFilterToken));
    src = xt_open_dup_query(); CHECK(src != NULL); if (!src) return;
    if (!XOK(UN(NtQueryInformationToken)(src, 40, &restricted, 4, &got))) { t_note("TokenIsRestricted unavailable"); UN(NtClose)(src); return; }
    if (restricted) { t_skip("caller token is already restricted"); UN(NtClose)(src); return; }
    rs.n = 1; rs.g[0].Sid = (PSID)&xt_everyone; rs.g[0].Attributes = 0;
    s = UN(NtFilterToken)(src, 0, NULL, NULL, (PTOKEN_GROUPS)&rs, &nt);
    EXPECT_EQ(s, 0);
    if (s == 0 && nt) {
        restricted = 0;
        EXPECT_EQ(UN(NtQueryInformationToken)(nt, 40, &restricted, 4, &got), 0);
        EXPECT_EQ(restricted, 1);
        UN(NtClose)(nt);
    }
    UN(NtClose)(src);
}
TEST(nt_token_x_filter_deny_only_group)
{
    HANDLE src, nt = NULL; struct { DWORD n; SID_AND_ATTRIBUTES g[1]; } dis; union { ULONGLONG a; BYTE b[4096]; } buf; ULONG got; TOKEN_GROUPS *tg = (TOKEN_GROUPS *)buf.b; int found = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtFilterToken));
    src = xt_open_dup_query(); CHECK(src != NULL); if (!src) return;
    dis.n = 1; dis.g[0].Sid = (PSID)&xt_everyone; dis.g[0].Attributes = 0;
    s = UN(NtFilterToken)(src, 0, (PTOKEN_GROUPS)&dis, NULL, NULL, &nt);
    EXPECT_EQ(s, 0);
    if (s == 0 && nt) {
        EXPECT_EQ(UN(NtQueryInformationToken)(nt, 2, buf.b, sizeof buf, &got), 0);
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            BYTE *sid = (BYTE *)tg->Groups[i].Sid;
            if (sid[1] == 1 && !memcmp(sid, &xt_everyone, 12)) { found = 1; CHECK(tg->Groups[i].Attributes & 0x10 /* USE_FOR_DENY_ONLY */); CHECK(!(tg->Groups[i].Attributes & SE_GROUP_ENABLED)); }
        }
        CHECK(found);
        UN(NtClose)(nt);
    }
    /* disabling a SID the token does not carry is rejected */
    dis.g[0].Sid = (PSID)&xt_system;
    nt = NULL;
    s = UN(NtFilterToken)(src, 0, (PTOKEN_GROUPS)&dis, NULL, NULL, &nt);
    t_note("disable of an unheld sid status=%08lx", s);
    if (XOK(s) && nt) UN(NtClose)(nt);
    UN(NtClose)(src);
}
TEST(nt_token_x_filter_access_and_handle)
{
    HANDLE q = NULL, nt = NULL; XT_NEED(); REQUIRE(UN(NtFilterToken));
    EXPECT_EQ(UN(NtFilterToken)((HANDLE)(ULONG_PTR)0x7ffc, 0, NULL, NULL, NULL, &nt), XS(0xC0000008));
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &q), 0);   /* no TOKEN_DUPLICATE */
    if (q) { EXPECT_EQ(UN(NtFilterToken)(q, 0, NULL, NULL, NULL, &nt), XS(0xC0000022)); UN(NtClose)(q); }
}

/* ---- NtSetInformationToken ---------------------------------------------------- */
TEST(nt_token_x_set_default_dacl_roundtrip)
{
    HANDLE t; union { ULONGLONG a; BYTE b[64]; } aclbuf; ACL *acl = (ACL *)aclbuf.b; TOKEN_DEFAULT_DACL td; union { ULONGLONG a; BYTE b[512]; } out; ULONG got = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtSetInformationToken)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAceEx));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 64, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 0x1f, (PSID)&xt_everyone), 0);
    td.DefaultDacl = acl;
    s = UN(NtSetInformationToken)(t, 6 /* TokenDefaultDacl */, &td, sizeof td);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        s = UN(NtQueryInformationToken)(t, 6, out.b, sizeof out, &got);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            ACL *back = ((TOKEN_DEFAULT_DACL *)out.b)->DefaultDacl;
            CHECK(back != NULL && (BYTE *)back >= out.b && (BYTE *)back < out.b + got);
            if (back) EXPECT_EQ(back->AceCount, 1);
        }
    }
    td.DefaultDacl = NULL;   /* a null default DACL is allowed */
    s = UN(NtSetInformationToken)(t, 6, &td, sizeof td);
    EXPECT_EQ(s, 0);
    UN(NtClose)(t);
}
TEST(nt_token_x_set_information_errors)
{
    HANDLE t, q = NULL; BYTE buf[64] = {0}; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtSetInformationToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 0x7f, buf, sizeof buf), XS(0xC0000003));
    EXPECT_EQ(UN(NtSetInformationToken)(t, 0, buf, sizeof buf), XS(0xC0000003));
    s = UN(NtSetInformationToken)(t, 1 /* TokenUser: query only */, buf, sizeof buf);
    CHECK(!XOK(s)); t_note("set of TokenUser status=%08lx", s);
    EXPECT_EQ(UN(NtSetInformationToken)(t, 6, buf, 4), XS(0xC0000004));
    EXPECT_EQ(UN(NtSetInformationToken)((HANDLE)(ULONG_PTR)0x7ffc, 6, buf, 8), XS(0xC0000008));
    UN(NtClose)(t);
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &q), 0);
    if (q) { TOKEN_DEFAULT_DACL td; td.DefaultDacl = NULL; EXPECT_EQ(UN(NtSetInformationToken)(q, 6, &td, sizeof td), XS(0xC0000022)); UN(NtClose)(q); }
}
TEST(nt_token_x_set_owner_must_be_assignable)
{
    HANDLE t; TOKEN_OWNER ow; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtSetInformationToken));
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    ow.Owner = (PSID)&xt_everyone;
    s = UN(NtSetInformationToken)(t, 4 /* TokenOwner */, &ow, sizeof ow);
    EXPECT_EQ(s, XS(0xC000005A));
    UN(NtClose)(t);
}
TEST(nt_token_x_query_token_classes_length_protocol)
{
    HANDLE t; union { ULONGLONG a; BYTE b[2048]; } buf; ULONG got = 0; NTSTATUS s; XT_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    static const struct { ULONG cls; const char *name; } var[] = { {1,"User"}, {2,"Groups"}, {3,"Privileges"}, {4,"Owner"}, {5,"PrimaryGroup"}, {6,"DefaultDacl"} };
    for (size_t i = 0; i < sizeof var / sizeof var[0]; i++) {
        got = 0;
        s = UN(NtQueryInformationToken)(t, var[i].cls, buf.b, 0, &got);
        CHECKF(s == XS(0xC0000023), "%s zero length status=%08lx", var[i].name, s);
        if (s == XS(0xC0000023)) {
            ULONG need = got;
            CHECKF(need > 0 && need <= sizeof buf, "%s need=%lu", var[i].name, need);
            s = UN(NtQueryInformationToken)(t, var[i].cls, buf.b, need - 1, &got);
            CHECKF(s == XS(0xC0000023), "%s need-1 status=%08lx", var[i].name, s);
            s = UN(NtQueryInformationToken)(t, var[i].cls, buf.b, need, &got);
            CHECKF(s == 0 && got <= need, "%s exact status=%08lx", var[i].name, s);
        }
    }
    s = UN(NtQueryInformationToken)(t, 0x7f, buf.b, sizeof buf, &got);
    EXPECT_EQ(s, XS(0xC0000003));
    s = UN(NtQueryInformationToken)(t, 0, buf.b, sizeof buf, &got);
    EXPECT_EQ(s, XS(0xC0000003));
    UN(NtClose)(t);
}
TEST(nt_token_x_query_token_fixed_classes)
{
    HANDLE t; ULONG v[16]; ULONG got = 0; XT_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    memset(v, 0xcc, sizeof v);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, v, 4, &got), 0); EXPECT_EQ(v[0], 2); EXPECT_EQ(got, 4);          /* TokenImpersonation */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 9, v, 4, &got), 0); EXPECT_EQ(v[0], 2);                              /* SecurityImpersonation */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 8, v, 3, &got), XS(0xC0000023));
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 9, v, 0, &got), XS(0xC0000023));
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 12, v, 4, &got), 0);
    UN(NtClose)(t);
}
TEST(nt_token_x_impersonation_level_on_primary_token)
{
    HANDLE h = NULL; ULONG v = 0, got = 0; NTSTATUS s; XT_NEED();
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &h), 0); if (!h) return;
    EXPECT_EQ(UN(NtQueryInformationToken)(h, 8, &v, 4, &got), 0); EXPECT_EQ(v, 1);   /* TokenPrimary */
    s = UN(NtQueryInformationToken)(h, 9, &v, 4, &got);   /* primary tokens carry no impersonation level: observed only */
    t_note("TokenImpersonationLevel on a primary token status=%08lx", s);
    UN(NtClose)(h);
}

/* ---- NtAccessCheck ---------------------------------------------------------------- */
#define XT_SD_NEED() do { XT_NEED(); REQUIRE(UN(NtAccessCheck)); REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetOwnerSecurityDescriptor)); \
    REQUIRE(UN(RtlSetGroupSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAceEx)); REQUIRE(UN(RtlAddAccessDeniedAceEx)); } while (0)
static const GENERIC_MAPPING xt_map = { 0x1, 0x2, 0x4, 0x7 };
typedef struct { SECURITY_DESCRIPTOR sd; union { ULONGLONG a; BYTE b[256]; } acl; } xt_sdbuf;
/* user = the token's user SID, copied into 'user'. dacl_mode: 0 = no DACL, 1 = empty DACL, 2 = allow user 3, 3 = deny user 2 then allow user 3 */
static void xt_user_sid(HANDLE t, BYTE *out, ULONG cap)
{
    union { ULONGLONG a; BYTE b[256]; } buf; ULONG got; memset(out, 0, cap);
    if (XOK(UN(NtQueryInformationToken)(t, 1, buf.b, sizeof buf, &got))) { BYTE *sid = (BYTE *)((TOKEN_USER *)buf.b)->User.Sid; ULONG n = 8 + 4 * sid[1]; if (n <= cap) memcpy(out, sid, n); }
}
static BOOL xt_make_sd(xt_sdbuf *b, const BYTE *user, int mode)
{
    ACL *acl = (ACL *)b->acl.b;
    if (!XOK(UN(RtlCreateSecurityDescriptor)(&b->sd, 1))) return FALSE;
    if (!XOK(UN(RtlSetOwnerSecurityDescriptor)(&b->sd, (PSID)&xt_system, FALSE))) return FALSE;
    if (!XOK(UN(RtlSetGroupSecurityDescriptor)(&b->sd, (PSID)&xt_system, FALSE))) return FALSE;
    if (mode == 0) return XOK(UN(RtlSetDaclSecurityDescriptor)(&b->sd, FALSE, NULL, FALSE));
    if (!XOK(UN(RtlCreateAcl)(acl, 256, 2))) return FALSE;
    if (mode == 3 && !XOK(UN(RtlAddAccessDeniedAceEx)(acl, 2, 0, 2, (PSID)user))) return FALSE;
    if (mode >= 2 && !XOK(UN(RtlAddAccessAllowedAceEx)(acl, 2, 0, 3, (PSID)user))) return FALSE;
    return XOK(UN(RtlSetDaclSecurityDescriptor)(&b->sd, TRUE, acl, FALSE));
}
static NTSTATUS xt_check(xt_sdbuf *b, HANDLE tok, ACCESS_MASK want, ACCESS_MASK *granted, NTSTATUS *astatus)
{
    BYTE ps[64]; ULONG pl = sizeof ps;
    *granted = 0xcccccccc; *astatus = XS(0xcccccccc);
    return UN(NtAccessCheck)(&b->sd, tok, want, (PGENERIC_MAPPING)&xt_map, (PPRIVILEGE_SET)ps, &pl, granted, astatus);
}
TEST(nt_token_x_access_check_allow_ace)
{
    xt_sdbuf b; HANDLE t; BYTE user[40]; ACCESS_MASK g; NTSTATUS st, s; XT_SD_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    xt_user_sid(t, user, sizeof user); CHECK(xt_make_sd(&b, user, 2));
    s = xt_check(&b, t, 1, &g, &st);   EXPECT_EQ(s, 0); EXPECT_EQ(st, 0); EXPECT_EQ(g, 1);
    s = xt_check(&b, t, 3, &g, &st);   EXPECT_EQ(s, 0); EXPECT_EQ(st, 0); EXPECT_EQ(g, 3);
    s = xt_check(&b, t, 4, &g, &st);   EXPECT_EQ(s, 0); EXPECT_EQ(st, XS(0xC0000022)); EXPECT_EQ(g, 0);
    s = xt_check(&b, t, 5, &g, &st);   EXPECT_EQ(s, 0); EXPECT_EQ(st, XS(0xC0000022)); EXPECT_EQ(g, 0);   /* all requested bits must be allowed */
    s = xt_check(&b, t, MAXIMUM_ALLOWED, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, 0); EXPECT_EQ(g, 3);
    UN(NtClose)(t);
}
TEST(nt_token_x_access_check_null_and_empty_dacl)
{
    xt_sdbuf b; HANDLE t; BYTE user[40]; ACCESS_MASK g; NTSTATUS st, s; XT_SD_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    xt_user_sid(t, user, sizeof user);
    CHECK(xt_make_sd(&b, user, 0));                                   /* no DACL: everyone gets everything */
    s = xt_check(&b, t, 7, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, 0); EXPECT_EQ(g, 7);
    CHECK(xt_make_sd(&b, user, 1));                                   /* empty DACL: nobody gets anything */
    s = xt_check(&b, t, 1, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, XS(0xC0000022)); EXPECT_EQ(g, 0);
    s = xt_check(&b, t, MAXIMUM_ALLOWED, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(g, 0);
    UN(NtClose)(t);
}
TEST(nt_token_x_access_check_deny_precedes_allow)
{
    xt_sdbuf b; HANDLE t; BYTE user[40]; ACCESS_MASK g; NTSTATUS st, s; XT_SD_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    xt_user_sid(t, user, sizeof user); CHECK(xt_make_sd(&b, user, 3));
    s = xt_check(&b, t, 1, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, 0); EXPECT_EQ(g, 1);
    s = xt_check(&b, t, 2, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, XS(0xC0000022)); EXPECT_EQ(g, 0);
    s = xt_check(&b, t, 3, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(st, XS(0xC0000022));
    s = xt_check(&b, t, MAXIMUM_ALLOWED, &g, &st); EXPECT_EQ(s, 0); EXPECT_EQ(g, 1);
    UN(NtClose)(t);
}
TEST(nt_token_x_access_check_argument_errors)
{
    xt_sdbuf b; HANDLE t, p = NULL; BYTE user[40]; ACCESS_MASK g; NTSTATUS st, s; XT_SD_NEED();
    t = xt_dup(TOKEN_ALL_ACCESS, 2); CHECK(t != NULL); if (!t) return;
    xt_user_sid(t, user, sizeof user); CHECK(xt_make_sd(&b, user, 2));
    s = xt_check(&b, t, GENERIC_READ, &g, &st);                      /* generic bits must be mapped by the caller */
    EXPECT_EQ(s, XS(0xC00000E6));
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &p), 0);
    if (p) { s = xt_check(&b, p, 1, &g, &st); EXPECT_EQ(s, XS(0xC000005C)); UN(NtClose)(p); }   /* needs an impersonation token */
    s = xt_check(&b, (HANDLE)(ULONG_PTR)0x7ffc, 1, &g, &st); EXPECT_EQ(s, XS(0xC0000008));
    { xt_sdbuf nob; CHECK(xt_make_sd(&nob, user, 2)); nob.sd.Owner = NULL;
      s = xt_check(&nob, t, 1, &g, &st); t_note("descriptor without owner status=%08lx", s); }
    UN(NtClose)(t);
    (void)st;
}
TEST(nt_token_x_access_check_token_without_query_access)
{
    xt_sdbuf b; HANDLE q = NULL, src = NULL; BYTE user[40]; ACCESS_MASK g; NTSTATUS st, s; SECURITY_QUALITY_OF_SERVICE qos; OBJECT_ATTRIBUTES oa; XT_SD_NEED();
    if (!XOK(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &src))) { t_skip("token open"); return; }
    qos.Length = sizeof qos; qos.ImpersonationLevel = SecurityImpersonation; qos.ContextTrackingMode = 0; qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL); oa.SecurityQualityOfService = &qos;
    s = UN(NtDuplicateToken)(src, TOKEN_ADJUST_DEFAULT, &oa, FALSE, 2, &q);   /* an impersonation token that cannot be queried */
    if (!XOK(s)) { UN(NtClose)(src); t_skip("duplicate"); return; }
    xt_user_sid(src, user, sizeof user); CHECK(xt_make_sd(&b, user, 2));
    s = xt_check(&b, q, 1, &g, &st);
    EXPECT_EQ(s, XS(0xC0000022));
    UN(NtClose)(q); UN(NtClose)(src);
}

/* ---- object security ---------------------------------------------------------------- */
TEST(nt_token_x_query_security_object_event)
{
    HANDLE ev; WCHAR nm[64]; union { ULONGLONG a; BYTE b[1024]; } sd; ULONG need = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtQuerySecurityObject)); REQUIRE(UN(RtlValidSecurityDescriptor));
    REQUIRE(UIN("kernel32.dll", CreateEventW)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    /* Only named objects carry a security descriptor; an unnamed event yields an empty one. */
    wsprintfW(nm, L"Local\\NtdllConf_sd_q_%lu", GetCurrentProcessId());
    ev = UIN("kernel32.dll", CreateEventW)(NULL, TRUE, FALSE, nm); CHECK(ev != NULL); if (!ev) return;
    s = UN(NtQuerySecurityObject)(ev, 4 /* DACL */, NULL, 0, &need);
    EXPECT_EQ(s, XS(0xC0000023)); CHECK(need >= 20 && need <= sizeof sd);
    if (need <= sizeof sd) {
        ULONG got = 0;
        memset(&sd, 0, sizeof sd);
        s = UN(NtQuerySecurityObject)(ev, 1 | 2 | 4, &sd, sizeof sd, &got);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            WORD control = *(WORD *)(sd.b + 2);
            CHECK(sd.b[0] == 1); CHECK(control & 0x8000);   /* self-relative */
            CHECK(got >= 20 && got <= sizeof sd);
            EXPECT_EQ(UN(RtlValidSecurityDescriptor)(&sd), TRUE);
            CHECK(*(ULONG *)(sd.b + 4) != 0);               /* owner offset */
        }
        s = UN(NtQuerySecurityObject)(ev, 4, &sd, 10, &got);
        EXPECT_EQ(s, XS(0xC0000023));
    }
    UIN("kernel32.dll", CloseHandle)(ev);
}
TEST(nt_token_x_set_security_object_dacl_roundtrip)
{
    HANDLE ev; WCHAR nm[64]; xt_sdbuf b; union { ULONGLONG a; BYTE b[1024]; } out; ULONG got = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtQuerySecurityObject)); REQUIRE(UN(NtSetSecurityObject));
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAceEx));
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UIN("kernel32.dll", CreateEventW)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    wsprintfW(nm, L"Local\\NtdllConf_sd_s_%lu", GetCurrentProcessId());
    ev = UIN("kernel32.dll", CreateEventW)(NULL, TRUE, FALSE, nm); CHECK(ev != NULL); if (!ev) return;
    CHECK(XOK(UN(RtlCreateSecurityDescriptor)(&b.sd, 1)));
    CHECK(XOK(UN(RtlCreateAcl)((ACL *)b.acl.b, 256, 2)));
    CHECK(XOK(UN(RtlAddAccessAllowedAceEx)((ACL *)b.acl.b, 2, 0, 0x1F0003, (PSID)&xt_everyone)));
    CHECK(XOK(UN(RtlSetDaclSecurityDescriptor)(&b.sd, TRUE, (ACL *)b.acl.b, FALSE)));
    s = UN(NtSetSecurityObject)(ev, 4, &b.sd);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BOOLEAN present = 0, defaulted = 0; ACL *dacl = NULL;
        memset(&out, 0, sizeof out);
        EXPECT_EQ(UN(NtQuerySecurityObject)(ev, 4, &out, sizeof out, &got), 0);
        { BYTE *sdp = out.b; ULONG off = *(ULONG *)(sdp + 16); CHECK(off != 0 && off < got); if (off && off < got) { ACL *a = (ACL *)(sdp + off); EXPECT_EQ(a->AceCount, 1);
            xt_ace *ace = (xt_ace *)(a + 1); EXPECT_EQ(ace->type, 0); EXPECT_EQ(ace->mask, 0x1F0003); } }
        (void)present; (void)defaulted; (void)dacl;
    }
    UIN("kernel32.dll", CloseHandle)(ev);
}
TEST(nt_token_x_query_security_object_requires_read_control)
{
    HANDLE t = NULL; union { ULONGLONG a; BYTE b[1024]; } sd; ULONG need = 0; NTSTATUS s; XT_NEED(); REQUIRE(UN(NtQuerySecurityObject));
    EXPECT_EQ(UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &t), 0); if (!t) return;
    s = UN(NtQuerySecurityObject)(t, 4, &sd, sizeof sd, &need);
    EXPECT_EQ(s, XS(0xC0000022));
    UN(NtClose)(t);
    EXPECT_EQ(UN(NtQuerySecurityObject)((HANDLE)(ULONG_PTR)0x7ffc, 4, &sd, sizeof sd, &need), XS(0xC0000008));
}
