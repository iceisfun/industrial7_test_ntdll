/* NtSetInformationToken on a private duplicate of the process token (the process token itself is
 * never modified). Classes: 4 TokenOwner, 5 TokenPrimaryGroup, 6 TokenDefaultDacl, 12 TokenSessionId.
 */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationToken, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, RtlCreateAcl, (PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PVOID, ULONG, ACCESS_MASK, PVOID));
UDECL(BOOLEAN, RtlEqualSid, (PVOID, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_INV_OWNER    S(0xC000005A)
#define ST_INV_GROUP    S(0xC000005B)
#define ST_PRIV         S(0xC0000061)
#define NT_PROCESS      ((HANDLE)(LONG_PTR)-1)
#define TOK_ADJUST_DEFAULT 0x0080
#define TOK_QUERY          0x0008

static const BYTE g_world_sid[12]  = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };       /* S-1-1-0 */
static const BYTE g_bogus_sid[12]  = { 1, 1, 0, 0, 0, 0, 0, 5, 0x7B, 0, 0, 0 };    /* S-1-5-123 */

static HANDLE dup_token(ACCESS_MASK access)
{
    HANDLE p = NULL, d = NULL; NTSTATUS st;
    if (!UN(NtOpenProcessToken) || !UN(NtDuplicateToken)) return NULL;
    st = UN(NtOpenProcessToken)(NT_PROCESS, TOKEN_DUPLICATE | TOKEN_QUERY, &p);
    if (st != 0) return NULL;
    st = UN(NtDuplicateToken)(p, access, NULL, FALSE, 1 /* TokenPrimary */, &d);
    CloseHandle(p);
    return st == 0 ? d : NULL;
}

#define NEED() do { REQUIRE(UN(NtSetInformationToken)); REQUIRE(UN(NtQueryInformationToken)); } while (0)

TEST(set_token_alias_pair)
{
    EXPECT_EQ(t_proc("NtSetInformationToken"), t_proc("ZwSetInformationToken"));
}

TEST(set_token_default_dacl)
{
    HANDLE t; struct { PVOID acl; } in, out_hdr; BYTE acl[64] __attribute__((aligned(8))); BYTE buf[512] __attribute__((aligned(8))); ULONG rl = 0;
    PBYTE got; NEED();
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    t = dup_token(TOKEN_ALL_ACCESS);
    CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(RtlCreateAcl)(acl, sizeof acl, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, GENERIC_ALL, (PVOID)g_world_sid), 0);
    in.acl = acl;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 6, &in, sizeof in), 0);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 6, buf, sizeof buf, &rl), 0);
    got = *(PBYTE *)buf;
    CHECK(got != NULL);
    if (got) {
        EXPECT_EQ(*(WORD *)(got + 4), 1);                  /* AceCount */
        EXPECT_EQ(*(ACCESS_MASK *)(got + 8 + 4), GENERIC_ALL);
        CHECK(UN(RtlEqualSid)(got + 8 + 8, (PVOID)g_world_sid));
    }
    /* a NULL ACL removes the default DACL */
    in.acl = NULL;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 6, &in, sizeof in), 0);
    memset(buf, 0xCC, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 6, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(PVOID *)buf, NULL);
    EXPECT_EQ(UN(NtSetInformationToken)(t, 6, &in, 4), ST_BAD_LENGTH);
    (void)out_hdr;
    CloseHandle(t);
}

TEST(set_token_owner_and_primary_group)
{
    HANDLE t; BYTE ub[256] __attribute__((aligned(8))), ob[256] __attribute__((aligned(8))), gb[256] __attribute__((aligned(8)));
    struct { PVOID sid; } in; ULONG rl = 0; NTSTATUS st; PVOID user, grp;
    NEED(); REQUIRE(UN(RtlEqualSid));
    t = dup_token(TOKEN_ALL_ACCESS);
    CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 1 /* TokenUser */, ub, sizeof ub, &rl), 0);
    user = *(PVOID *)ub;
    /* the user SID is always a valid owner */
    in.sid = user;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 4, &in, sizeof in), 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 4, ob, sizeof ob, &rl), 0);
    CHECK(UN(RtlEqualSid)(*(PVOID *)ob, user));
    /* a SID that is neither the user nor a group of the token is not */
    in.sid = (PVOID)g_bogus_sid;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 4, &in, sizeof in), ST_INV_OWNER);
    EXPECT_EQ(UN(NtSetInformationToken)(t, 4, &in, 4), ST_BAD_LENGTH);
    /* primary group: re-setting the current one works, an unknown SID does not */
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 5, gb, sizeof gb, &rl), 0);
    grp = *(PVOID *)gb;
    in.sid = grp;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 5, &in, sizeof in), 0);
    in.sid = (PVOID)g_bogus_sid;
    st = UN(NtSetInformationToken)(t, 5, &in, sizeof in);
    EXPECT_EQ(st, ST_INV_GROUP);
    memset(gb, 0, sizeof gb);
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 5, gb, sizeof gb, &rl), 0);
    CHECK(UN(RtlEqualSid)(*(PVOID *)gb, grp));          /* unchanged by the failed call */
    CloseHandle(t);
}

TEST(set_token_session_id_needs_tcb)
{
    HANDLE t; ULONG sid = 0, cur = 0, rl = 0; NTSTATUS st; NEED();
    t = dup_token(TOKEN_ALL_ACCESS);
    CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(NtQueryInformationToken)(t, 12, &cur, sizeof cur, &rl), 0);
    sid = cur;
    st = UN(NtSetInformationToken)(t, 12, &sid, sizeof sid);
    if (st == 0) { t_skip("caller holds SeTcbPrivilege"); CloseHandle(t); return; }
    EXPECT_EQ(st, ST_PRIV);
    EXPECT_EQ(UN(NtSetInformationToken)(t, 12, &sid, 2), ST_BAD_LENGTH);
    CloseHandle(t);
}

TEST(set_token_errors)
{
    HANDLE t, ro, ev; ULONG v = 0; struct { PVOID p; } in = { NULL }; NEED();
    EXPECT_EQ(UN(NtSetInformationToken)((HANDLE)(ULONG_PTR)0xdeadbee4, 6, &in, sizeof in), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationToken)(NULL, 6, &in, sizeof in), ST_INV_HANDLE);
    t = dup_token(TOKEN_ALL_ACCESS);
    CHECK(t != NULL); if (!t) return;
    EXPECT_EQ(UN(NtSetInformationToken)(t, 0x7fff, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationToken)(t, 0, &v, sizeof v), ST_BAD_CLASS);
    /* TokenUser is query-only */
    EXPECT_EQ(UN(NtSetInformationToken)(t, 1, &v, sizeof v), ST_BAD_CLASS);
    ro = dup_token(TOK_QUERY);
    CHECK(ro != NULL);
    if (ro) { EXPECT_EQ(UN(NtSetInformationToken)(ro, 6, &in, sizeof in), ST_DENIED); CloseHandle(ro); }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) { EXPECT_EQ(UN(NtSetInformationToken)(ev, 6, &in, sizeof in), ST_TYPE_MISM); CloseHandle(ev); }
    CloseHandle(t);
}
