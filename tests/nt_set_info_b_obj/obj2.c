/* NtSetInformationToken / JobObject / DebugObject / SymbolicLink / Key and NtSetValueKey.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetInformationToken, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtSetInformationJobObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtSetInformationDebugObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtSetInformationSymbolicLink, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationKey, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, RtlCreateAcl, (PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PVOID, ULONG, ACCESS_MASK, PSID));

#define DIRECTORY_ALL_ACCESS 0x000F000F
#define SYMBOLIC_LINK_ALL_ACCESS 0x000F0003
#define S(x) ((NTSTATUS)(x))
#define OK(s) ((NTSTATUS)(s) >= 0)
#define ST_INV_HANDLE S(0xC0000008)
#define ST_TYPE_MISM  S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_LEN_MISM   S(0xC0000004)
#define ST_INV_CLASS  S(0xC0000003)
#define ST_PRIV       S(0xC0000061)

static HANDLE reduced(HANDLE h, DWORD access)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, FALSE, 0)) return NULL;
    return d;
}
static HANDLE mkevent(void)
{
    HANDLE h = NULL;
    if (UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE) != 0) return NULL;
    return h;
}

/* ---- tokens ------------------------------------------------------------ */
static BYTE g_everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };          /* S-1-1-0 */
static BYTE g_low[12]      = { 1, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x10, 0, 0 };   /* S-1-16-4096 */
static HANDLE dup_token(ACCESS_MASK access)
{
    HANDLE t = NULL, d = NULL;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE, &t) != 0) return NULL;
    if (UN(NtDuplicateToken)(t, access, NULL, FALSE, 1 /*TokenPrimary*/, &d) != 0) d = NULL;
    UN(NtClose)(t);
    return d;
}
TEST(set_info_token)
{
    REQUIRE(UN(NtSetInformationToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtOpenProcessToken));
    CHECK(t_proc("NtSetInformationToken") == t_proc("ZwSetInformationToken"));
    HANDLE tk = dup_token(TOKEN_ALL_ACCESS);
    if (!tk) { t_skip("cannot duplicate the process token"); return; }
    BYTE buf[512]; ULONG rl = 0;
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 1 /*TokenUser*/, buf, sizeof buf, &rl), 0);
    PSID user = *(PSID *)buf;
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 5 /*TokenPrimaryGroup*/, buf + 256, 200, &rl), 0);
    PSID pgrp = *(PSID *)(buf + 256);
    /* owner */
    TOKEN_OWNER ow; ow.Owner = user;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 4 /*TokenOwner*/, &ow, sizeof ow), 0);
    BYTE q[256];
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 4, q, sizeof q, &rl), 0);
    CHECK(EqualSid(*(PSID *)q, user));
    ow.Owner = g_everyone;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 4, &ow, sizeof ow), S(0xC000005A));      /* STATUS_INVALID_OWNER */
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 4, &ow, 4), ST_LEN_MISM);
    /* primary group */
    TOKEN_PRIMARY_GROUP pg; pg.PrimaryGroup = pgrp;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 5, &pg, sizeof pg), 0);
    pg.PrimaryGroup = g_low;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 5, &pg, sizeof pg), S(0xC000005B));      /* STATUS_INVALID_PRIMARY_GROUP */
    /* default DACL */
    BYTE acl[64]; REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    EXPECT_EQ(UN(RtlCreateAcl)(acl, sizeof acl, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, GENERIC_ALL, g_everyone), 0);
    TOKEN_DEFAULT_DACL dd; dd.DefaultDacl = (PACL)acl;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 6 /*TokenDefaultDacl*/, &dd, sizeof dd), 0);
    memset(q, 0, sizeof q);
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 6, q, sizeof q, &rl), 0);
    {
        PACL a = *(PACL *)q;
        CHECK(a != NULL);
        if (a) { EXPECT_EQ(a->AceCount, 1); EXPECT_EQ(((ACCESS_ALLOWED_ACE *)(a + 1))->Mask, GENERIC_ALL); }
    }
    dd.DefaultDacl = NULL;                                    /* NULL DACL = no default DACL */
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 6, &dd, sizeof dd), 0);
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 6, &dd, 4), ST_LEN_MISM);
    /* integrity level can be lowered */
    TOKEN_MANDATORY_LABEL ml; ml.Label.Sid = g_low; ml.Label.Attributes = 0x20;      /* SE_GROUP_INTEGRITY */
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 25 /*TokenIntegrityLevel*/, &ml, sizeof ml), 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 25, q, sizeof q, &rl), 0);
    {
        PSID s = *(PSID *)q;
        CHECK(s != NULL && *GetSidSubAuthorityCount(s) == 1);
        if (s) EXPECT_EQ(*GetSidSubAuthority(s, 0), 4096);
    }
    /* privileged / read-only classes */
    ULONG sess = 0;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 12 /*TokenSessionId*/, &sess, sizeof sess), ST_PRIV);
    ULONG el = 1;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 20 /*TokenElevation*/, &el, sizeof el), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 0, &el, sizeof el), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 0x7fff, &el, sizeof el), ST_INV_CLASS);
    /* handle problems */
    EXPECT_EQ(UN(NtSetInformationToken)(NULL, 4, &ow, sizeof ow), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationToken)((HANDLE)(LONG_PTR)-1, 4, &ow, sizeof ow), ST_TYPE_MISM);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationToken)(ev, 4, &ow, sizeof ow), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = reduced(tk, TOKEN_QUERY);
    if (ro) {
        ow.Owner = user;
        EXPECT_EQ(UN(NtSetInformationToken)(ro, 4, &ow, sizeof ow), ST_DENIED);
        EXPECT_EQ(UN(NtSetInformationToken)(ro, 6, &dd, sizeof dd), ST_DENIED);
        CloseHandle(ro);
    }
    UN(NtClose)(tk);
}
TEST(set_info_token_virtualization)
{
    REQUIRE(UN(NtSetInformationToken)); REQUIRE(UN(NtQueryInformationToken));
    HANDLE tk = dup_token(TOKEN_ALL_ACCESS);
    if (!tk) { t_skip("cannot duplicate the process token"); return; }
    ULONG v = 1, q = 9, rl;
    NTSTATUS st = UN(NtSetInformationToken)(tk, 24 /*TokenVirtualizationEnabled*/, &v, sizeof v);
    t_note("TokenVirtualizationEnabled=1: %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 24, &q, sizeof q, &rl), 0);
    ULONG allowed = 9;
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 23 /*TokenVirtualizationAllowed*/, &allowed, sizeof allowed, &rl), 0);
    EXPECT_EQ(q, allowed ? 1 : 0);                            /* the enabled flag only sticks when virtualization is allowed */
    v = 0;
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 24, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(tk, 24, &q, sizeof q, &rl), 0);
    EXPECT_EQ(q, 0);
    EXPECT_EQ(UN(NtSetInformationToken)(tk, 24, &v, 2), ST_LEN_MISM);
    UN(NtClose)(tk);
}

/* ---- job objects ------------------------------------------------------- */
TEST(set_info_job_object)
{
    REQUIRE(UN(NtSetInformationJobObject));
    CHECK(t_proc("NtSetInformationJobObject") == t_proc("ZwSetInformationJobObject"));
    HANDLE job = CreateJobObjectW(NULL, NULL);
    CHECK(job != NULL); if (!job) return;
    JOBOBJECT_BASIC_LIMIT_INFORMATION bl; memset(&bl, 0, sizeof bl);
    bl.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS; bl.ActiveProcessLimit = 3;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 2, &bl, sizeof bl), 0);
    JOBOBJECT_BASIC_LIMIT_INFORMATION q; memset(&q, 0, sizeof q); DWORD rl = 0;
    CHECK(QueryInformationJobObject(job, JobObjectBasicLimitInformation, &q, sizeof q, &rl));
    EXPECT_EQ(q.LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS);
    EXPECT_EQ(q.ActiveProcessLimit, 3);
    /* extended limit */
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION el; memset(&el, 0, sizeof el);
    el.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    el.BasicLimitInformation.ActiveProcessLimit = 7;
    el.JobMemoryLimit = 256 * 1024 * 1024;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 9, &el, sizeof el), 0);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION qe; memset(&qe, 0, sizeof qe);
    CHECK(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &qe, sizeof qe, &rl));
    EXPECT_EQ(qe.BasicLimitInformation.ActiveProcessLimit, 7);
    EXPECT_EQ(qe.JobMemoryLimit, 256 * 1024 * 1024);
    /* kill-on-close needs the extended structure */
    bl.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 2, &bl, sizeof bl), ST_INV_PARAM);
    bl.LimitFlags = 0x80000000u;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 2, &bl, sizeof bl), ST_INV_PARAM);
    bl.LimitFlags = 0;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 2, &bl, sizeof bl - 8), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 9, &el, sizeof el - 8), ST_LEN_MISM);
    /* UI restrictions */
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui; ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_EXITWINDOWS;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 4, &ui, sizeof ui), 0);
    JOBOBJECT_BASIC_UI_RESTRICTIONS qu; memset(&qu, 0, sizeof qu);
    CHECK(QueryInformationJobObject(job, JobObjectBasicUIRestrictions, &qu, sizeof qu, &rl));
    EXPECT_EQ(qu.UIRestrictionsClass, JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_EXITWINDOWS);
    ui.UIRestrictionsClass = 0x80000000u;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 4, &ui, sizeof ui), ST_INV_PARAM);
    ui.UIRestrictionsClass = 0;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 4, &ui, 2), ST_LEN_MISM);
    /* end-of-job-time action */
    ULONG act = 1;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 6, &act, sizeof act), 0);
    act = 2;
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 6, &act, sizeof act), ST_INV_PARAM);
    /* classes and handles */
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 0x7fff, &act, sizeof act), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 0, &act, sizeof act), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationJobObject)(job, 1, &act, sizeof act), ST_LEN_MISM);     /* accounting is query-only: size is checked first */
    EXPECT_EQ(UN(NtSetInformationJobObject)(NULL, 2, &bl, sizeof bl), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationJobObject)(ev, 2, &bl, sizeof bl), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = reduced(job, JOB_OBJECT_QUERY);
    if (ro) { EXPECT_EQ(UN(NtSetInformationJobObject)(ro, 2, &bl, sizeof bl), ST_DENIED); CloseHandle(ro); }
    CloseHandle(job);
}

/* ---- debug objects ----------------------------------------------------- */
TEST(set_info_debug_object)
{
    REQUIRE(UN(NtSetInformationDebugObject)); REQUIRE(UN(NtCreateDebugObject));
    CHECK(t_proc("NtSetInformationDebugObject") == t_proc("ZwSetInformationDebugObject"));
    HANDLE d = NULL;
    NTSTATUS st = UN(NtCreateDebugObject)(&d, 0x1F000F, NULL, 0);
    if (st != 0) { t_skip("NtCreateDebugObject returned %08lx", (unsigned long)st); return; }
    ULONG fl = 1, rl = 0x55;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &fl, sizeof fl, &rl), 0);
    EXPECT_EQ(rl, 0);                                          /* ReturnLength is zeroed */
    fl = 0;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &fl, sizeof fl, NULL), 0);   /* ReturnLength optional */
    fl = 2;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &fl, sizeof fl, NULL), ST_INV_PARAM);
    fl = 1;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &fl, 2, NULL), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 0, &fl, sizeof fl, NULL), ST_INV_PARAM);
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 2, &fl, sizeof fl, NULL), ST_INV_PARAM);
    EXPECT_EQ(UN(NtSetInformationDebugObject)(NULL, 1, &fl, sizeof fl, NULL), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationDebugObject)(ev, 1, &fl, sizeof fl, NULL), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = reduced(d, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetInformationDebugObject)(ro, 1, &fl, sizeof fl, NULL), ST_DENIED); CloseHandle(ro); }
    UN(NtClose)(d);
}

/* ---- symbolic links ---------------------------------------------------- */
TEST(set_info_symbolic_link)
{
    REQUIRE(UN(NtSetInformationSymbolicLink)); REQUIRE(UN(NtCreateDirectoryObject)); REQUIRE(UN(NtCreateSymbolicLinkObject));
    CHECK(t_proc("NtSetInformationSymbolicLink") == t_proc("ZwSetInformationSymbolicLink"));
    HANDLE dir = NULL, lnk = NULL; OBJECT_ATTRIBUTES oa; UNICODE_STRING n, tgt;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    NTSTATUS st = UN(NtCreateDirectoryObject)(&dir, DIRECTORY_ALL_ACCESS, &oa);
    if (st != 0) { t_skip("cannot create an object directory: %08lx", (unsigned long)st); return; }
    WCHAR nm[] = L"Lnk", tw[] = L"\\Device\\Null";
    n.Buffer = nm; n.Length = n.MaximumLength = 6;
    tgt.Buffer = tw; tgt.Length = tgt.MaximumLength = (USHORT)(lstrlenW(tw) * 2);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, dir, NULL);
    st = UN(NtCreateSymbolicLinkObject)(&lnk, SYMBOLIC_LINK_ALL_ACCESS, &oa, &tgt);
    if (st != 0) { UN(NtClose)(dir); t_skip("cannot create a symbolic link: %08lx", (unsigned long)st); return; }
    ULONG g = 1;
    HANDLE qo = reduced(lnk, 0x1);                            /* SYMBOLIC_LINK_QUERY only */
    if (qo) { EXPECT_EQ(UN(NtSetInformationSymbolicLink)(qo, 1, &g, sizeof g), ST_DENIED); CloseHandle(qo); }
    NTSTATUS r1 = UN(NtSetInformationSymbolicLink)(lnk, 1 /*SymbolicLinkGlobalInformation*/, &g, sizeof g);
    EXPECT_EQ(r1, ST_PRIV);                                   /* global-link flag needs SeTcbPrivilege */
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(lnk, 0, &g, sizeof g), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(lnk, 0x7fff, &g, sizeof g), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(lnk, 1, &g, 1), ST_LEN_MISM);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(NULL, 1, &g, sizeof g), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationSymbolicLink)(ev, 1, &g, sizeof g), ST_TYPE_MISM); UN(NtClose)(ev); }
    UN(NtClose)(lnk);
    UN(NtClose)(dir);
}

/* ---- registry keys ----------------------------------------------------- */
typedef struct { HANDLE hcu, root; BOOL ok; } KFIX;
static UNICODE_STRING us(const WCHAR *w) { UNICODE_STRING u; u.Buffer = (PWSTR)w; u.Length = u.MaximumLength = (USHORT)(lstrlenW(w) * 2); return u; }
static void kup(KFIX *f)
{
    memset(f, 0, sizeof *f);
    if (!UN(RtlOpenCurrentUser) || !UN(NtCreateKey) || !UN(NtOpenKey) || !UN(NtDeleteKey) || !UN(NtQueryKey) || !UN(NtQueryValueKey)) { t_skip("missing registry exports"); return; }
    NTSTATUS s = UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &f->hcu);
    if (!OK(s)) { t_skip("cannot open the current user key (%08lx)", (unsigned long)s); return; }
    WCHAR path[80]; wsprintfW(path, L"Software\\NtdllConfSib_%lu", GetCurrentProcessId());
    UNICODE_STRING n = us(path); OBJECT_ATTRIBUTES oa; ULONG d;
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->hcu, NULL);
    s = UN(NtCreateKey)(&f->root, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, REG_OPTION_VOLATILE, &d);
    if (!OK(s)) { UN(NtClose)(f->hcu); t_skip("cannot create the scratch key (%08lx)", (unsigned long)s); return; }
    f->ok = TRUE;
}
static void kdown(KFIX *f)
{
    if (f->ok) { UN(NtDeleteKey)(f->root); UN(NtClose)(f->root); }
    if (f->hcu) UN(NtClose)(f->hcu);
}
#define KSTART() KFIX f; kup(&f); if (!f.ok) return

TEST(set_value_key)
{
    KSTART();
    REQUIRE(UN(NtSetValueKey)); CHECK(t_proc("NtSetValueKey") == t_proc("ZwSetValueKey"));
    UNICODE_STRING vn = us(L"dword"), dn = us(L""), sn = us(L"str");
    ULONG dw = 0xA1B2C3D4; BYTE buf[128]; ULONG rl = 0;
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &vn, 0, REG_DWORD, &dw, 4), 0);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &vn, 2 /*KeyValuePartialInformation*/, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_DWORD); EXPECT_EQ(*(ULONG *)(buf + 8), 4); EXPECT_EQ(*(ULONG *)(buf + 12), 0xA1B2C3D4);
    EXPECT_EQ(rl, 16);
    /* overwrite with another type and size */
    WCHAR str[] = L"hello";
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &vn, 0, REG_SZ, str, sizeof str), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &vn, 2, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 8), sizeof str);
    CHECK(!lstrcmpW((WCHAR *)(buf + 12), L"hello"));
    /* the nameless (default) value */
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &dn, 0, REG_BINARY, "\x01\x02\x03", 3), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &dn, 2, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)(buf + 8), 3); CHECK(!memcmp(buf + 12, "\x01\x02\x03", 3));
    /* zero-length data, and names are case-insensitive */
    UNICODE_STRING up = us(L"STR");
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &up, 0, REG_NONE, NULL, 0), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &sn, 2, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_NONE); EXPECT_EQ(*(ULONG *)(buf + 8), 0);
    /* TitleIndex is ignored */
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &sn, 77, REG_DWORD, &dw, 4), 0);
    /* errors */
    EXPECT_EQ(UN(NtSetValueKey)(NULL, &vn, 0, REG_DWORD, &dw, 4), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetValueKey)((HANDLE)(LONG_PTR)-1, &vn, 0, REG_DWORD, &dw, 4), ST_TYPE_MISM);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetValueKey)(ev, &vn, 0, REG_DWORD, &dw, 4), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = NULL; UNICODE_STRING nm = us(L""); OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, f.root, NULL);
    EXPECT_EQ(UN(NtOpenKey)(&ro, KEY_READ, &oa), 0);
    if (ro) { EXPECT_EQ(UN(NtSetValueKey)(ro, &vn, 0, REG_DWORD, &dw, 4), ST_DENIED); UN(NtClose)(ro); }
    EXPECT_EQ(UN(NtSetValueKey)(f.root, NULL, 0, REG_DWORD, &dw, 4), S(0xC0000005));         /* STATUS_ACCESS_VIOLATION */
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &vn, 0, REG_DWORD, NULL, 4), S(0xC0000005));
    {
        WCHAR *big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 70000);
        UNICODE_STRING bn; bn.Buffer = big; bn.Length = 33000; bn.MaximumLength = 33000;
        for (int i = 0; i < 16500; i++) big[i] = L'a';
        EXPECT_EQ(UN(NtSetValueKey)(f.root, &bn, 0, REG_DWORD, &dw, 4), ST_INV_PARAM);   /* name longer than 16383 characters */
        HeapFree(GetProcessHeap(), 0, big);
    }
    /* deleted key */
    HANDLE sub = NULL; UNICODE_STRING sname = us(L"sub");
    InitializeObjectAttributes(&oa, &sname, OBJ_CASE_INSENSITIVE, f.root, NULL);
    EXPECT_EQ(UN(NtCreateKey)(&sub, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, REG_OPTION_VOLATILE, NULL), 0);
    if (sub) {
        EXPECT_EQ(UN(NtDeleteKey)(sub), 0);
        EXPECT_EQ(UN(NtSetValueKey)(sub, &vn, 0, REG_DWORD, &dw, 4), S(0xC000017C));   /* STATUS_KEY_DELETED */
        UN(NtClose)(sub);
    }
    kdown(&f);
}
typedef struct { ULONG Wow64Flags, KeyFlags, ControlFlags; } KFLAGS;
TEST(set_info_key)
{
    KSTART();
    REQUIRE(UN(NtSetInformationKey));
    CHECK(t_proc("NtSetInformationKey") == t_proc("ZwSetInformationKey"));
    KFLAGS kf; ULONG rl = 0, v;
    memset(&kf, 0xcc, sizeof kf);
    EXPECT_EQ(UN(NtQueryKey)(f.root, 5 /*KeyFlagsInformation*/, &kf, sizeof kf, &rl), 0);
    t_note("initial KeyFlagsInformation: wow=%lx key=%lx ctl=%lx", (unsigned long)kf.Wow64Flags, (unsigned long)kf.KeyFlags, (unsigned long)kf.ControlFlags);
    /* KeyControlFlagsInformation (2): REG_KEY_DONT_VIRTUALIZE|REG_KEY_DONT_SILENT_FAIL|REG_KEY_RECURSE_FLAG */
    v = 1;
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 2, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryKey)(f.root, 5, &kf, sizeof kf, &rl), 0);
    EXPECT_EQ(kf.ControlFlags & 7, 1);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 2, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryKey)(f.root, 5, &kf, sizeof kf, &rl), 0);
    EXPECT_EQ(kf.ControlFlags & 7, 0);
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 2, &v, 2), ST_LEN_MISM);
    /* KeyWow64FlagsInformation (1) */
    v = 1;
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 1, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryKey)(f.root, 5, &kf, sizeof kf, &rl), 0);
    EXPECT_EQ(kf.Wow64Flags, 1);
    static const ULONG badw[] = { 0x20, 0x100, 0x200, 0x300 };      /* KEY_WOW64_* style bits are rejected */
    for (int i = 0; i < 4; i++) { v = badw[i]; EXPECT_EQ(UN(NtSetInformationKey)(f.root, 1, &v, sizeof v), ST_INV_PARAM); }
    EXPECT_EQ(UN(NtQueryKey)(f.root, 5, &kf, sizeof kf, &rl), 0);
    EXPECT_EQ(kf.Wow64Flags, 1);                                    /* rejected values changed nothing */
    v = 0;
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 1, &v, sizeof v), 0);
    /* classes and handles */
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 0x7fff, &v, sizeof v), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationKey)(f.root, 0xff, &v, sizeof v), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationKey)(NULL, 2, &v, sizeof v), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationKey)(ev, 2, &v, sizeof v), ST_TYPE_MISM); UN(NtClose)(ev); }
    HANDLE ro = NULL; UNICODE_STRING nm = us(L""); OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, f.root, NULL);
    EXPECT_EQ(UN(NtOpenKey)(&ro, KEY_READ, &oa), 0);
    if (ro) { EXPECT_EQ(UN(NtSetInformationKey)(ro, 2, &v, sizeof v), ST_DENIED); UN(NtClose)(ro); }
    kdown(&f);
}
