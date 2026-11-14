/* Object-manager flavoured setters: NtSetInformationObject, NtSetSecurityObject,
 * NtSetInformationSymbolicLink, NtSetInformationDebugObject, NtSetInformationJobObject.
 *
 * Handle-flag and DACL changes are verified by reading the state back (NtQueryObject,
 * NtQuerySecurityObject, NtQueryInformationJobObject). Everything created is closed again.
 */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetSecurityObject, (HANDLE, ULONG, PVOID));
UDECL(NTSTATUS, NtQuerySecurityObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationSymbolicLink, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtSetInformationDebugObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetInformationJobObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationJobObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));
UDECL(NTSTATUS, RtlCreateAcl, (PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PVOID, ULONG, ACCESS_MASK, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_PRIV         S(0xC0000061)
#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif
#define SYMBOLIC_LINK_QUERY       0x0001
#define SYMBOLIC_LINK_ALL_ACCESS  0x000F0003   /* STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY | SYMBOLIC_LINK_SET */
#define ST_NOT_CLOSABLE S(0xC0000235)

/* S-1-1-0 (Everyone) */
static const BYTE g_world_sid[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };

TEST(set_object_alias_pairs)
{
    EXPECT_EQ(t_proc("NtSetInformationObject"), t_proc("ZwSetInformationObject"));
    EXPECT_EQ(t_proc("NtSetSecurityObject"), t_proc("ZwSetSecurityObject"));
    EXPECT_EQ(t_proc("NtSetInformationSymbolicLink"), t_proc("ZwSetInformationSymbolicLink"));
    EXPECT_EQ(t_proc("NtSetInformationDebugObject"), t_proc("ZwSetInformationDebugObject"));
    EXPECT_EQ(t_proc("NtSetInformationJobObject"), t_proc("ZwSetInformationJobObject"));
}

/* ---- NtSetInformationObject ------------------------------------------- */

TEST(set_object_handle_flags)
{
    HANDLE h; BYTE fl[2], got[2]; DWORD wf = 0; NTSTATUS st; ULONG rl = 0;
    REQUIRE(UN(NtSetInformationObject)); REQUIRE(UN(NtQueryObject));
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(h != NULL); if (!h) return;
    fl[0] = 1; fl[1] = 0;                            /* Inherit */
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, fl, sizeof fl), 0);
    CHECK(GetHandleInformation(h, &wf)); EXPECT_EQ(wf & 3, HANDLE_FLAG_INHERIT);
    memset(got, 0xCC, sizeof got);
    EXPECT_EQ(UN(NtQueryObject)(h, 4, got, sizeof got, &rl), 0);
    EXPECT_EQ(got[0], 1); EXPECT_EQ(got[1], 0);
    fl[0] = 0; fl[1] = 1;                            /* ProtectFromClose */
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, fl, sizeof fl), 0);
    CHECK(GetHandleInformation(h, &wf)); EXPECT_EQ(wf & 3, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    st = U(NtClose)(h);                              /* refused while protected */
    EXPECT_EQ(st, ST_NOT_CLOSABLE);
    fl[0] = 0; fl[1] = 0;
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, fl, sizeof fl), 0);
    CHECK(GetHandleInformation(h, &wf)); EXPECT_EQ(wf & 3, 0);
    EXPECT_EQ(U(NtClose)(h), 0);
}

TEST(set_object_errors)
{
    HANDLE h; BYTE fl[2] = { 0, 0 }; ULONG v = 0; NTSTATUS st;
    REQUIRE(UN(NtSetInformationObject));
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, fl, 1), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, fl, 4), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationObject)(h, 0x7fffffff, fl, sizeof fl), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationObject)(h, 0, fl, sizeof fl), ST_BAD_CLASS);       /* ObjectBasicInformation is query-only */
    /* handle-attribute updates report an unresolvable handle as access denied */
    EXPECT_EQ(UN(NtSetInformationObject)((HANDLE)(ULONG_PTR)0xdeadbee4, 4, fl, sizeof fl), ST_DENIED);
    EXPECT_EQ(UN(NtSetInformationObject)(NULL, 4, fl, sizeof fl), ST_DENIED);
    /* ObjectSessionInformation (5) needs SeTcbPrivilege, which neither user nor administrator tokens enable */
    st = UN(NtSetInformationObject)(h, 5, &v, 0);
    if (st != ST_PRIV) t_skip("caller holds SeTcbPrivilege (status %08lx)", (unsigned long)st);
    else EXPECT_EQ(st, ST_PRIV);
    CloseHandle(h);
}

/* ---- NtSetSecurityObject ---------------------------------------------- */

/* self-relative security descriptor holding only a DACL with one allow ACE for Everyone */
typedef struct { __attribute__((aligned(8))) BYTE sd[128]; } dacl_buf;

static void build_sd(dacl_buf *b, ACCESS_MASK mask)
{
    BYTE *acl = b->sd + 20; WORD aclsize = 8 + 8 + 12;
    memset(b, 0, sizeof *b);
    b->sd[0] = 1;                                   /* Revision */
    *(WORD *)(b->sd + 2) = 0x8000 | 0x0004;         /* SE_SELF_RELATIVE | SE_DACL_PRESENT */
    *(ULONG *)(b->sd + 16) = 20;                    /* Dacl offset */
    acl[0] = 2; *(WORD *)(acl + 2) = aclsize; *(WORD *)(acl + 4) = 1;
    acl[8] = 0 /* ACCESS_ALLOWED_ACE_TYPE */; *(WORD *)(acl + 10) = 8 + 12;
    *(ACCESS_MASK *)(acl + 12) = mask;
    memcpy(acl + 16, g_world_sid, 12);
}

/* parse a self-relative SD: returns DACL ace count, or -1; first ACE mask in *mask */
static int rel_dacl_info(const BYTE *sd, ACCESS_MASK *mask)
{
    ULONG off = *(const ULONG *)(sd + 16); const BYTE *acl; int n;
    if (!off) return -1;
    acl = sd + off; n = *(const WORD *)(acl + 4);
    if (n && mask) *mask = *(const ACCESS_MASK *)(acl + 8 + 4);
    return n;
}

/* unnamed kernel objects carry no security descriptor, named ones get the default one */
static HANDLE named_event(void)
{
    WCHAR nm[80];
    swprintf(nm, 80, L"Local\\ntdllt_setsec_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    return CreateEventW(NULL, TRUE, FALSE, nm);
}

static int rel_dacl_info(const BYTE *sd, ACCESS_MASK *mask);

TEST(set_security_object_unnamed_has_no_descriptor)
{
    HANDLE h; dacl_buf b; BYTE out[256]; ULONG rl = 0;
    REQUIRE(UN(NtSetSecurityObject)); REQUIRE(UN(NtQuerySecurityObject));
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(h != NULL); if (!h) return;
    build_sd(&b, EVENT_ALL_ACCESS);
    EXPECT_EQ(UN(NtSetSecurityObject)(h, DACL_SECURITY_INFORMATION, b.sd), S(0xC00000D7));     /* STATUS_NO_SECURITY_ON_OBJECT */
    /* querying succeeds and returns a descriptor without a DACL */
    memset(out, 0, sizeof out);
    EXPECT_EQ(UN(NtQuerySecurityObject)(h, DACL_SECURITY_INFORMATION, out, sizeof out, &rl), 0);
    EXPECT_EQ(rel_dacl_info(out, NULL), -1);
    CloseHandle(h);
}

TEST(set_security_object_dacl)
{
    HANDLE h; dacl_buf b; BYTE out[512]; ULONG rl = 0; ACCESS_MASK m = 0; NTSTATUS st;
    REQUIRE(UN(NtSetSecurityObject)); REQUIRE(UN(NtQuerySecurityObject));
    h = named_event();
    CHECK(h != NULL); if (!h) return;
    build_sd(&b, EVENT_QUERY_STATE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC);
    st = UN(NtSetSecurityObject)(h, DACL_SECURITY_INFORMATION, b.sd);
    EXPECT_EQ(st, 0);
    memset(out, 0, sizeof out);
    st = UN(NtQuerySecurityObject)(h, DACL_SECURITY_INFORMATION, out, sizeof out, &rl);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(rel_dacl_info(out, &m), 1);
    EXPECT_EQ(m, EVENT_QUERY_STATE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC);
    /* replace it again with a different mask */
    build_sd(&b, EVENT_QUERY_STATE | READ_CONTROL | WRITE_DAC);
    EXPECT_EQ(UN(NtSetSecurityObject)(h, DACL_SECURITY_INFORMATION, b.sd), 0);
    memset(out, 0, sizeof out);
    EXPECT_EQ(UN(NtQuerySecurityObject)(h, DACL_SECURITY_INFORMATION, out, sizeof out, &rl), 0);
    EXPECT_EQ(rel_dacl_info(out, &m), 1);
    EXPECT_EQ(m, EVENT_QUERY_STATE | READ_CONTROL | WRITE_DAC);
    CloseHandle(h);
}

TEST(set_security_object_errors)
{
    HANDLE h, ro = NULL; dacl_buf b; NTSTATUS st;
    REQUIRE(UN(NtSetSecurityObject));
    h = named_event();
    CHECK(h != NULL); if (!h) return;
    build_sd(&b, EVENT_ALL_ACCESS);
    EXPECT_EQ(UN(NtSetSecurityObject)((HANDLE)(ULONG_PTR)0xdeadbee4, DACL_SECURITY_INFORMATION, b.sd), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetSecurityObject)(NULL, DACL_SECURITY_INFORMATION, b.sd), ST_INV_HANDLE);
    /* a handle without WRITE_DAC cannot change the DACL */
    CHECK(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &ro, READ_CONTROL | EVENT_QUERY_STATE, FALSE, 0));
    if (ro) {
        EXPECT_EQ(UN(NtSetSecurityObject)(ro, DACL_SECURITY_INFORMATION, b.sd), ST_DENIED);
        CloseHandle(ro);
    }
    /* the descriptor has no owner: setting OWNER_SECURITY_INFORMATION is rejected */
    st = UN(NtSetSecurityObject)(h, OWNER_SECURITY_INFORMATION, b.sd);
    t_note("NtSetSecurityObject(OWNER, SD without owner) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, S(0xC0000079));     /* STATUS_INVALID_SECURITY_DESCR */
    /* the descriptor has no group */
    st = UN(NtSetSecurityObject)(h, GROUP_SECURITY_INFORMATION, b.sd);
    t_note("NtSetSecurityObject(GROUP, SD without group) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, S(0xC0000079));     /* STATUS_INVALID_SECURITY_DESCR */
    CloseHandle(h);
}

/* ---- NtSetInformationSymbolicLink ------------------------------------- */

TEST(set_symlink_information)
{
    HANDLE l = NULL, ro = NULL, ev; OBJECT_ATTRIBUTES oa; UNICODE_STRING target; ULONG v = 0; NTSTATUS st;
    static WCHAR tgt[] = L"\\Device\\Null";
    REQUIRE(UN(NtSetInformationSymbolicLink)); REQUIRE(UN(NtCreateSymbolicLinkObject));
    target.Buffer = tgt; target.Length = sizeof tgt - 2; target.MaximumLength = sizeof tgt;
    InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = UN(NtCreateSymbolicLinkObject)(&l, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target);
    if (st < 0 || !l) { t_skip("unnamed symbolic link cannot be created (%08lx)", (unsigned long)st); return; }
    /* checks happen in order: class, length, then SeTcbPrivilege */
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(l, 0, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(l, 3, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(l, 1, &v, 0), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)(l, 2, &v, 8), ST_BAD_LENGTH);
    st = UN(NtSetInformationSymbolicLink)(l, 1, &v, sizeof v);
    if (st != ST_PRIV) t_note("caller holds SeTcbPrivilege (status %08lx)", (unsigned long)st);
    else EXPECT_EQ(st, ST_PRIV);
    st = UN(NtSetInformationSymbolicLink)(l, 2, &v, sizeof v);
    if (st != ST_PRIV) t_note("caller holds SeTcbPrivilege (status %08lx)", (unsigned long)st);
    else EXPECT_EQ(st, ST_PRIV);
    /* without SYMBOLIC_LINK_SET the handle is rejected before anything else */
    CHECK(DuplicateHandle(GetCurrentProcess(), l, GetCurrentProcess(), &ro, SYMBOLIC_LINK_QUERY, FALSE, 0));
    if (ro) {
        EXPECT_EQ(UN(NtSetInformationSymbolicLink)(ro, 1, &v, sizeof v), ST_DENIED);
        CloseHandle(ro);
    }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) { EXPECT_EQ(UN(NtSetInformationSymbolicLink)(ev, 1, &v, sizeof v), ST_TYPE_MISM); CloseHandle(ev); }
    EXPECT_EQ(UN(NtSetInformationSymbolicLink)((HANDLE)(ULONG_PTR)0xdeadbee4, 1, &v, sizeof v), ST_INV_HANDLE);
    CloseHandle(l);
}

/* ---- NtSetInformationDebugObject -------------------------------------- */

TEST(set_debug_object_flags)
{
    HANDLE d = NULL, ro = NULL, ev; OBJECT_ATTRIBUTES oa; ULONG v, rl; NTSTATUS st;
    REQUIRE(UN(NtSetInformationDebugObject)); REQUIRE(UN(NtCreateDebugObject));
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    st = UN(NtCreateDebugObject)(&d, 0x1f000f /* DEBUG_ALL_ACCESS */, &oa, 0);
    EXPECT_EQ(st, 0);
    if (st != 0 || !d) return;
    v = 1;                                               /* DebugObjectKillProcessOnExitInformation */
    rl = 0xAAAAAAAA;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &v, sizeof v, &rl), 0);
    EXPECT_EQ(rl, 0);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &v, sizeof v, NULL), 0);
    v = 2;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &v, sizeof v, &rl), ST_BAD_PARAM);
    /* wrong length: the required length is reported through ReturnLength */
    rl = 0;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 1, &v, 8, &rl), ST_BAD_LENGTH);
    EXPECT_EQ(rl, 4);
    v = 0;
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 0, &v, sizeof v, &rl), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetInformationDebugObject)(d, 2, &v, sizeof v, &rl), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetInformationDebugObject)((HANDLE)(ULONG_PTR)0xdeadbee4, 1, &v, sizeof v, &rl), ST_INV_HANDLE);
    CHECK(DuplicateHandle(GetCurrentProcess(), d, GetCurrentProcess(), &ro, 0x1 /* DEBUG_READ_EVENT */, FALSE, 0));
    if (ro) { EXPECT_EQ(UN(NtSetInformationDebugObject)(ro, 1, &v, sizeof v, &rl), ST_DENIED); CloseHandle(ro); }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) { EXPECT_EQ(UN(NtSetInformationDebugObject)(ev, 1, &v, sizeof v, &rl), ST_TYPE_MISM); CloseHandle(ev); }
    CloseHandle(d);
}

/* ---- NtSetInformationJobObject ---------------------------------------- */

TEST(set_job_object_limits)
{
    HANDLE j = NULL, ro = NULL; OBJECT_ATTRIBUTES oa; NTSTATUS st; ULONG rl = 0;
    JOBOBJECT_BASIC_LIMIT_INFORMATION in, out; JOBOBJECT_BASIC_UI_RESTRICTIONS ui, uo;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ex, exo;
    REQUIRE(UN(NtSetInformationJobObject)); REQUIRE(UN(NtCreateJobObject)); REQUIRE(UN(NtQueryInformationJobObject));
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    st = UN(NtCreateJobObject)(&j, JOB_OBJECT_ALL_ACCESS, &oa);
    EXPECT_EQ(st, 0); if (st != 0 || !j) return;
    memset(&in, 0, sizeof in);
    in.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    in.ActiveProcessLimit = 5;
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 2, &in, sizeof in), 0);          /* JobObjectBasicLimitInformation */
    memset(&out, 0xCC, sizeof out);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 2, &out, sizeof out, &rl), 0);
    EXPECT_EQ(out.LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS);
    EXPECT_EQ(out.ActiveProcessLimit, 5);
    /* extended limits: per-process memory */
    memset(&ex, 0, sizeof ex);
    ex.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    ex.BasicLimitInformation.ActiveProcessLimit = 7;
    ex.ProcessMemoryLimit = 0x10000000;
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 9, &ex, sizeof ex), 0);          /* JobObjectExtendedLimitInformation */
    memset(&exo, 0xCC, sizeof exo);
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 9, &exo, sizeof exo, &rl), 0);
    EXPECT_EQ(exo.BasicLimitInformation.ActiveProcessLimit, 7);
    EXPECT_EQ(exo.ProcessMemoryLimit, 0x10000000);
    /* UI restrictions */
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS;
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 4, &ui, sizeof ui), 0);          /* JobObjectBasicUIRestrictions */
    uo.UIRestrictionsClass = 0xCCCCCCCC;
    EXPECT_EQ(UN(NtQueryInformationJobObject)(j, 4, &uo, sizeof uo, &rl), 0);
    EXPECT_EQ(uo.UIRestrictionsClass, JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS);
    /* errors */
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 2, &in, sizeof in - 8), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 4, &ui, 2), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 0x7fff, &in, sizeof in), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationJobObject)(j, 0, &in, sizeof in), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationJobObject)((HANDLE)(ULONG_PTR)0xdeadbee4, 2, &in, sizeof in), ST_INV_HANDLE);
    CHECK(DuplicateHandle(GetCurrentProcess(), j, GetCurrentProcess(), &ro, JOB_OBJECT_QUERY, FALSE, 0));
    if (ro) { EXPECT_EQ(UN(NtSetInformationJobObject)(ro, 2, &in, sizeof in), ST_DENIED); CloseHandle(ro); }
    CloseHandle(j);
}
