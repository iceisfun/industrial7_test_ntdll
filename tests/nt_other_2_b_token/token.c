/* Zw-named token services: ZwDuplicateToken, ZwAdjustPrivilegesToken, ZwAdjustGroupsToken, ZwFilterToken,
 * ZwFilterTokenEx, ZwCompareTokens, ZwAdjustTokenClaimsAndDeviceGroups.
 * All adjustments are made on duplicates of the process token; the process token is never modified. */
#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, ZwAdjustPrivilegesToken, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG));
UDECL(NTSTATUS, ZwAdjustGroupsToken, (HANDLE, BOOLEAN, PTOKEN_GROUPS, ULONG, PTOKEN_GROUPS, PULONG));
UDECL(NTSTATUS, ZwFilterToken, (HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, PHANDLE));
UDECL(NTSTATUS, ZwFilterTokenEx, (HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, ULONG, PVOID, ULONG, PVOID, PVOID, PVOID, PVOID, PVOID, PHANDLE));
UDECL(NTSTATUS, ZwCompareTokens, (HANDLE, HANDLE, PBOOLEAN));
UDECL(NTSTATUS, ZwAdjustTokenClaimsAndDeviceGroups, (HANDLE, BOOLEAN, BOOLEAN, BOOLEAN, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG, PVOID, PULONG, PULONG, PULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_INVALID_HANDLE S(0xC0000008)
#define ST_INVALID_PARAMETER S(0xC000000D)
#define ST_ACCESS_DENIED S(0xC0000022)
#define ST_TYPE_MISMATCH S(0xC0000024)
#define ST_BUFFER_TOO_SMALL S(0xC0000023)
#define ST_NOT_ALL_ASSIGNED S(0x106)
#define PROBE(what, st) t_note("%s -> 0x%08lx", what, (unsigned long)(st))
#define BADH ((HANDLE)(ULONG_PTR)0x7777770)

#define SE_NOTIFY 23     /* SeChangeNotifyPrivilege: held and enabled by every logon */
#define SE_CREATE_TOKEN 2 /* SeCreateTokenPrivilege: held by no interactive logon */

static HANDLE open_tok(void)
{
    HANDLE h = NULL;
    NTSTATUS st = UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_DUPLICATE | TOKEN_QUERY, &h);
    EXPECT_EQ(st, 0);
    return st == 0 ? h : NULL;
}

static HANDLE dup_tok(HANDLE src, ACCESS_MASK acc)
{
    SECURITY_QUALITY_OF_SERVICE q = {sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE};
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.SecurityQualityOfService = &q;
    HANDLE h = NULL;
    NTSTATUS st = UN(ZwDuplicateToken)(src, acc, &oa, FALSE, 2, &h);
    EXPECT_EQ(st, 0);
    return st == 0 ? h : NULL;
}

static void *query(HANDLE h, ULONG cls, ULONG *len)
{
    ULONG n = 0;
    UN(NtQueryInformationToken)(h, cls, NULL, 0, &n);
    void *b = calloc(1, n + 16);
    NTSTATUS st = UN(NtQueryInformationToken)(h, cls, b, n, &n);
    if (st) { free(b); return NULL; }
    if (len) *len = n;
    return b;
}

static LONG priv_attr(HANDLE h, ULONG luid, BOOL *found)
{
    TOKEN_PRIVILEGES *tp = query(h, 3, NULL);
    LONG a = -1; *found = FALSE;
    if (tp) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++)
            if (tp->Privileges[i].Luid.LowPart == luid && !tp->Privileges[i].Luid.HighPart) { a = tp->Privileges[i].Attributes; *found = TRUE; }
        free(tp);
    }
    return a;
}

#define NEED() do { REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(ZwDuplicateToken)); } while (0)

TEST(alias_pairs)
{
    static const char *n[] = {"DuplicateToken","AdjustPrivilegesToken","AdjustGroupsToken","FilterToken","FilterTokenEx",
        "CompareTokens","AdjustTokenClaimsAndDeviceGroups"};
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64];
        wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa && !pb) { t_note("%s absent", n[i]); continue; }
        CHECKF(pa == pb, "%s: Nt/Zw differ", n[i]);
    }
}

TEST(duplicate_token)
{
    NEED();
    HANDLE t = open_tok(); if (!t) return;
    SECURITY_QUALITY_OF_SERVICE q = {sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE};
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.SecurityQualityOfService = &q;
    HANDLE d = NULL;
    EXPECT_EQ(UN(ZwDuplicateToken)(t, TOKEN_QUERY, &oa, FALSE, 2, &d), 0);
    if (d) {
        ULONG n = 0; TOKEN_TYPE *ty = query(d, 8, &n);       /* TokenType */
        if (ty) { EXPECT_EQ(*ty, 2); free(ty); }
        CloseHandle(d);
    }
    d = NULL;
    EXPECT_EQ(UN(ZwDuplicateToken)(t, TOKEN_QUERY, &oa, FALSE, 1, &d), 0);   /* primary */
    if (d) { TOKEN_TYPE *ty = query(d, 8, NULL); if (ty) { EXPECT_EQ(*ty, 1); free(ty); } CloseHandle(d); }
    d = NULL;
    EXPECT_EQ(UN(ZwDuplicateToken)(t, TOKEN_QUERY, &oa, FALSE, 3, &d), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwDuplicateToken)(NULL, TOKEN_QUERY, &oa, FALSE, 2, &d), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDuplicateToken)(BADH, TOKEN_QUERY, &oa, FALSE, 2, &d), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwDuplicateToken)(ev, TOKEN_QUERY, &oa, FALSE, 2, &d), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    /* handle opened without TOKEN_DUPLICATE */
    HANDLE ro = NULL;
    EXPECT_EQ(UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &ro), 0);
    EXPECT_EQ(UN(ZwDuplicateToken)(ro, TOKEN_QUERY, &oa, FALSE, 2, &d), ST_ACCESS_DENIED);
    CloseHandle(ro); CloseHandle(t);
}

TEST(adjust_privileges)
{
    NEED(); REQUIRE(UN(ZwAdjustPrivilegesToken));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE d = dup_tok(t, TOKEN_ALL_ACCESS); CloseHandle(t); if (!d) return;
    BOOL f; LONG a = priv_attr(d, SE_NOTIFY, &f);
    CHECK(f); CHECK(a & SE_PRIVILEGE_ENABLED);

    TOKEN_PRIVILEGES np; np.PrivilegeCount = 1; np.Privileges[0].Luid.LowPart = SE_NOTIFY; np.Privileges[0].Luid.HighPart = 0;
    np.Privileges[0].Attributes = 0;
    BYTE pbuf[64]; ULONG rl = 0xCC;
    memset(pbuf, 0xCC, sizeof pbuf);
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, sizeof pbuf, (TOKEN_PRIVILEGES *)pbuf, &rl), 0);
    TOKEN_PRIVILEGES *pp = (TOKEN_PRIVILEGES *)pbuf;
    EXPECT_EQ(rl, 4 + 12);
    EXPECT_EQ(pp->PrivilegeCount, 1); EXPECT_EQ(pp->Privileges[0].Luid.LowPart, SE_NOTIFY);
    CHECK(pp->Privileges[0].Attributes & SE_PRIVILEGE_ENABLED);
    a = priv_attr(d, SE_NOTIFY, &f); CHECK(f); EXPECT_EQ(a & SE_PRIVILEGE_ENABLED, 0);
    /* previous state now disabled; enabling again */
    np.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; rl = 0xCC;
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, sizeof pbuf, (TOKEN_PRIVILEGES *)pbuf, &rl), 0);
    EXPECT_EQ(pp->PrivilegeCount, 1); EXPECT_EQ(pp->Privileges[0].Attributes & SE_PRIVILEGE_ENABLED, 0);
    a = priv_attr(d, SE_NOTIFY, &f); CHECK(a & SE_PRIVILEGE_ENABLED);
    /* no change needed: nothing reported as previous */
    rl = 0xCC;
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, sizeof pbuf, (TOKEN_PRIVILEGES *)pbuf, &rl), 0);
    EXPECT_EQ(pp->PrivilegeCount, 0);
    /* previous-state buffer too small */
    np.Privileges[0].Attributes = 0; rl = 0xCC;
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, 4, (TOKEN_PRIVILEGES *)pbuf, &rl), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(rl, 16);
    a = priv_attr(d, SE_NOTIFY, &f); CHECK(a & SE_PRIVILEGE_ENABLED);   /* nothing applied */
    /* restore for later checks */
    np.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, 0, NULL, NULL);
    /* no previous state requested */
    np.Privileges[0].Attributes = 0;
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, 0, NULL, NULL), 0);
    a = priv_attr(d, SE_NOTIFY, &f); EXPECT_EQ(a & SE_PRIVILEGE_ENABLED, 0);
    /* privilege this token does not hold */
    np.Privileges[0].Luid.LowPart = SE_CREATE_TOKEN; np.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, 0, NULL, NULL), ST_NOT_ALL_ASSIGNED);
    /* DisableAllPrivileges */
    np.Privileges[0].Luid.LowPart = SE_NOTIFY;
    UN(ZwAdjustPrivilegesToken)(d, FALSE, &np, 0, NULL, NULL);
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(d, TRUE, NULL, 0, NULL, NULL), 0);
    TOKEN_PRIVILEGES *tp = query(d, 3, NULL);
    if (tp) { for (DWORD i = 0; i < tp->PrivilegeCount; i++) EXPECT_EQ(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED, 0); free(tp); }
    /* errors */
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(NULL, FALSE, &np, 0, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(BADH, FALSE, &np, 0, NULL, NULL), ST_INVALID_HANDLE);
    NTSTATUS st = UN(ZwAdjustPrivilegesToken)(d, FALSE, NULL, 0, NULL, NULL);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    HANDLE ro = dup_tok(d, TOKEN_QUERY);
    if (ro) { EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(ro, FALSE, &np, 0, NULL, NULL), ST_ACCESS_DENIED); CloseHandle(ro); }
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwAdjustPrivilegesToken)(ev, FALSE, &np, 0, NULL, NULL), ST_TYPE_MISMATCH);
    CloseHandle(ev); CloseHandle(d);
}

TEST(adjust_groups)
{
    NEED(); REQUIRE(UN(ZwAdjustGroupsToken));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE d = dup_tok(t, TOKEN_ALL_ACCESS); CloseHandle(t); if (!d) return;
    TOKEN_GROUPS *g = query(d, 2, NULL);
    CHECK(g != NULL);
    SID_AND_ATTRIBUTES *mand = NULL, *opt = NULL;
    if (g) for (DWORD i = 0; i < g->GroupCount; i++) {
        DWORD at = g->Groups[i].Attributes;
        if ((at & SE_GROUP_MANDATORY) && !mand) mand = &g->Groups[i];
        if ((at & SE_GROUP_ENABLED) && !(at & (SE_GROUP_MANDATORY | SE_GROUP_INTEGRITY | SE_GROUP_LOGON_ID)) && !opt) opt = &g->Groups[i];
    }
    TOKEN_GROUPS one; one.GroupCount = 1;
    if (mand) {
        one.Groups[0].Sid = mand->Sid; one.Groups[0].Attributes = 0;
        EXPECT_EQ(UN(ZwAdjustGroupsToken)(d, FALSE, &one, 0, NULL, NULL), S(0xC000005D));   /* STATUS_CANT_DISABLE_MANDATORY */
    } else t_note("no mandatory group in token");
    if (opt) {
        BYTE pb[256]; ULONG rl = 0xCC; memset(pb, 0, sizeof pb);
        one.Groups[0].Sid = opt->Sid; one.Groups[0].Attributes = 0;
        EXPECT_EQ(UN(ZwAdjustGroupsToken)(d, FALSE, &one, sizeof pb, (TOKEN_GROUPS *)pb, &rl), 0);
        TOKEN_GROUPS *pg = (TOKEN_GROUPS *)pb;
        EXPECT_EQ(pg->GroupCount, 1); CHECK(pg->Groups[0].Attributes & SE_GROUP_ENABLED);
        CHECK(rl >= 8 + 16);
        TOKEN_GROUPS *g2 = query(d, 2, NULL);
        if (g2) { for (DWORD i = 0; i < g2->GroupCount; i++) if (EqualSid(g2->Groups[i].Sid, opt->Sid)) EXPECT_EQ(g2->Groups[i].Attributes & SE_GROUP_ENABLED, 0); free(g2); }
        EXPECT_EQ(UN(ZwAdjustGroupsToken)(d, TRUE, NULL, 0, NULL, NULL), 0);          /* reset to defaults */
        g2 = query(d, 2, NULL);
        if (g2) { for (DWORD i = 0; i < g2->GroupCount; i++) if (EqualSid(g2->Groups[i].Sid, opt->Sid)) CHECK(g2->Groups[i].Attributes & SE_GROUP_ENABLED); free(g2); }
    } else t_note("no optional enabled group in token");
    EXPECT_EQ(UN(ZwAdjustGroupsToken)(d, TRUE, NULL, 0, NULL, NULL), 0);              /* reset to defaults, always valid */
    EXPECT_EQ(UN(ZwAdjustGroupsToken)(d, TRUE, NULL, 0, NULL, NULL), 0);
    /* group not in the token: S-1-5-99-12345 */
    BYTE sidbuf[SECURITY_MAX_SID_SIZE]; SID *sid = (SID *)sidbuf;
    memset(sidbuf, 0, sizeof sidbuf);
    sid->Revision = 1; sid->SubAuthorityCount = 2; sid->IdentifierAuthority.Value[5] = 5;
    sid->SubAuthority[0] = 99; sid->SubAuthority[1] = 12345;
    one.Groups[0].Sid = sid; one.Groups[0].Attributes = 0;
    NTSTATUS st = UN(ZwAdjustGroupsToken)(d, FALSE, &one, 0, NULL, NULL);
    EXPECT_EQ(st, ST_NOT_ALL_ASSIGNED);
    st = UN(ZwAdjustGroupsToken)(d, FALSE, NULL, 0, NULL, NULL);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwAdjustGroupsToken)(NULL, FALSE, &one, 0, NULL, NULL), ST_INVALID_HANDLE);
    HANDLE ro = dup_tok(d, TOKEN_QUERY);
    if (ro) { EXPECT_EQ(UN(ZwAdjustGroupsToken)(ro, FALSE, &one, 0, NULL, NULL), ST_ACCESS_DENIED); CloseHandle(ro); }
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwAdjustGroupsToken)(ev, FALSE, &one, 0, NULL, NULL), ST_TYPE_MISMATCH);
    CloseHandle(ev); free(g); CloseHandle(d);
}

TEST(filter_token)
{
    NEED(); REQUIRE(UN(ZwFilterToken));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE n = NULL;
    EXPECT_EQ(UN(ZwFilterToken)(t, 0, NULL, NULL, NULL, &n), 0);
    CHECK(n != NULL);
    HANDLE m = NULL;
    NTSTATUS st = UN(ZwFilterToken)(t, DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, &m);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        TOKEN_PRIVILEGES *tp = query(m, 3, NULL);
        CHECK(tp != NULL);
        if (tp) { EXPECT_EQ(tp->PrivilegeCount, 1); if (tp->PrivilegeCount) EXPECT_EQ(tp->Privileges[0].Luid.LowPart, SE_NOTIFY); free(tp); }
    }
    if (UN(ZwCompareTokens)) {
        BOOLEAN eq = 0xCC;
        EXPECT_EQ(UN(ZwCompareTokens)(t, n, &eq), 0);
        EXPECT_EQ(eq, 1);
        eq = 0xCC; st = UN(ZwCompareTokens)(t, m, &eq);
        EXPECT_EQ(st, 0); EXPECT_EQ(eq, 0);          /* privilege set differs */
    }
    /* deny-only conversion of the Everyone group */
    BYTE sb[16] = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};            /* S-1-1-0 */
    TOKEN_GROUPS dg; dg.GroupCount = 1; dg.Groups[0].Sid = sb; dg.Groups[0].Attributes = 0;
    HANDLE dn = NULL;
    st = UN(ZwFilterToken)(t, 0, &dg, NULL, NULL, &dn);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        TOKEN_GROUPS *g = query(dn, 2, NULL); int seen = 0;
        if (g) { for (DWORD i = 0; i < g->GroupCount; i++) if (EqualSid(g->Groups[i].Sid, sb)) { seen = 1; CHECK(g->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY); } CHECK(seen); free(g); }
    }
    /* privilege deletion */
    TOKEN_PRIVILEGES dp; dp.PrivilegeCount = 1; dp.Privileges[0].Luid.LowPart = SE_NOTIFY; dp.Privileges[0].Luid.HighPart = 0; dp.Privileges[0].Attributes = 0;
    HANDLE pn = NULL;
    st = UN(ZwFilterToken)(t, 0, NULL, &dp, NULL, &pn);
    EXPECT_EQ(st, 0);
    if (st == 0) { BOOL f; priv_attr(pn, SE_NOTIFY, &f); CHECK(!f); }
    /* errors */
    HANDLE e = NULL;
    EXPECT_EQ(UN(ZwFilterToken)(NULL, 0, NULL, NULL, NULL, &e), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwFilterToken)(BADH, 0, NULL, NULL, NULL, &e), ST_INVALID_HANDLE);
    st = UN(ZwFilterToken)(t, 0x100, NULL, NULL, NULL, &e); PROBE("filter unknown flag 0x100 (ignored)", st);
    if (st == 0) CloseHandle(e);
    HANDLE ro = NULL;
    EXPECT_EQ(UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &ro), 0);
    EXPECT_EQ(UN(ZwFilterToken)(ro, 0, NULL, NULL, NULL, &e), ST_ACCESS_DENIED);
    CloseHandle(ro);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwFilterToken)(ev, 0, NULL, NULL, NULL, &e), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    CloseHandle(n); if (m) CloseHandle(m); if (dn) CloseHandle(dn); if (pn) CloseHandle(pn); CloseHandle(t);
}

/* On this Windows 10 build NtFilterTokenEx is a stub: every call fails with STATUS_NOT_IMPLEMENTED
 * before looking at its arguments. */
TEST(filter_token_ex)
{
    NEED(); REQUIRE(UN(ZwFilterTokenEx));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE n = NULL, e = NULL;
    EXPECT_EQ(UN(ZwFilterTokenEx)(t, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &n), S(0xC0000002));
    EXPECT_EQ(UN(ZwFilterTokenEx)(t, DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &n), S(0xC0000002));
    EXPECT_EQ(UN(ZwFilterTokenEx)(NULL, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &e), S(0xC0000002));
    EXPECT_EQ(UN(ZwFilterTokenEx)(BADH, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, &e), S(0xC0000002));
    CHECK(n == NULL && e == NULL);
    CloseHandle(t);
}

TEST(compare_tokens)
{
    NEED(); REQUIRE(UN(ZwCompareTokens));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE d = dup_tok(t, TOKEN_QUERY);
    BOOLEAN eq = 0xCC;
    EXPECT_EQ(UN(ZwCompareTokens)(t, t, &eq), 0); EXPECT_EQ(eq, 1);
    if (d) { eq = 0xCC; EXPECT_EQ(UN(ZwCompareTokens)(t, d, &eq), 0); EXPECT_EQ(eq, 1); }
    /* a token with a different user: anonymous logon cannot be created here; use a restricted-SID filter */
    BYTE sb[12] = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
    TOKEN_GROUPS rg; rg.GroupCount = 1; rg.Groups[0].Sid = sb; rg.Groups[0].Attributes = 0;
    HANDLE r = NULL;
    if (UN(ZwFilterToken) && UN(ZwFilterToken)(t, 0, NULL, NULL, &rg, &r) == 0) {
        eq = 0xCC; EXPECT_EQ(UN(ZwCompareTokens)(t, r, &eq), 0); EXPECT_EQ(eq, 0);
        CloseHandle(r);
    }
    EXPECT_EQ(UN(ZwCompareTokens)(NULL, t, &eq), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCompareTokens)(t, BADH, &eq), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCompareTokens)(t, t, NULL), S(0xC0000005));
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwCompareTokens)(t, ev, &eq), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    if (d) CloseHandle(d);
    CloseHandle(t);
}

/* Stub on this build: STATUS_NOT_IMPLEMENTED for every argument combination. */
TEST(adjust_claims)
{
    REQUIRE(UN(ZwAdjustTokenClaimsAndDeviceGroups));
    EXPECT_EQ(UN(ZwAdjustTokenClaimsAndDeviceGroups)(NULL, 0, 0, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL), S(0xC0000002));
    EXPECT_EQ(UN(ZwAdjustTokenClaimsAndDeviceGroups)(BADH, 1, 1, 1, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL), S(0xC0000002));
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(ZwDuplicateToken));
    HANDLE t = open_tok(); if (!t) return;
    HANDLE d = dup_tok(t, TOKEN_ALL_ACCESS); CloseHandle(t); if (!d) return;
    EXPECT_EQ(UN(ZwAdjustTokenClaimsAndDeviceGroups)(d, 0, 0, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL), S(0xC0000002));
    CloseHandle(d);
}
