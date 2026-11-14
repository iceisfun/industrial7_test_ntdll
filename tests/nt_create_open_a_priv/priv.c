/* Privileged, platform-dependent and unimplemented creators: NtCreateToken(Ex), NtCreateLowBoxToken,
 * NtCreateProfile(Ex), NtCreatePagingFile, NtCreatePartition/NtOpenPartition, NtOpenSession, NtCreateEnclave,
 * NtCreateCrossVmEvent/Mutant, NtCreateWnfStateName, NtOpenObjectAuditAlarm.
 * Only the failure paths of the destructive ones (pagefile, token forging) are exercised, and only with
 * privileges that the account does not hold by default. Expectations observed on Windows 10 22H2. */
#include "oa.h"

TEST(zw_aliases_share_nt_entry)
{
    static const char *names[] = {"CreateCrossVmEvent", "CreateCrossVmMutant", "CreateEnclave"};
    char nt[64], zw[64]; REQUIRE(t_proc("NtCreateEnclave"));
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        wsprintfA(nt, "Nt%s", names[i]); wsprintfA(zw, "Zw%s", names[i]);
        CHECKF(t_proc(nt) != NULL && t_proc(nt) == t_proc(zw), "%s", names[i]);
    }
}

/* ---- tokens ------------------------------------------------------------- */

TEST(create_token_needs_create_token_privilege)
{
    HANDLE h = NULL; LUID luid = {0x1234, 0}; LARGE_INTEGER ex; ex.QuadPart = 0;
    BYTE sid[12] = {1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}; /* S-1-5-18 */
    struct { PVOID sid; ULONG attr; } user = {sid, 0}; struct { ULONG count; } groups = {0}, privs = {0};
    struct { PVOID sid; } owner = {sid}, pgrp = {sid}; struct { PVOID acl; } dacl = {NULL}; struct { CHAR name[8]; LUID id; } src = {"oa_test", {1, 0}};
    REQUIRE(UN(NtCreateToken)); REQUIRE(UN(NtCreateTokenEx)); REQUIRE(UN(NtClose));
    /* neither the administrators group nor standard users hold SeCreateTokenPrivilege, and the check is made first */
    EXPECT_EQ(UN(NtCreateToken)(&h, TOKEN_ALL_ACCESS, NULL, 1, &luid, &ex, NULL, NULL, NULL, NULL, NULL, NULL, NULL), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreateToken)(&h, TOKEN_ALL_ACCESS, NULL, 5, &luid, &ex, NULL, NULL, NULL, NULL, NULL, NULL, NULL), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreateToken)(&h, TOKEN_ALL_ACCESS, NULL, 1, &luid, &ex, &user, &groups, &privs, &owner, &pgrp, &dacl, &src), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreateTokenEx)(&h, TOKEN_ALL_ACCESS, NULL, 1, &luid, &ex, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), ST_PRIV_NOT_HELD);
    CHECK(h == NULL);
}

TEST(create_lowbox_token_argument_checks)
{
    HANDLE h = NULL, t = NULL; REQUIRE(UN(NtCreateLowBoxToken)); REQUIRE(UN(NtOpenProcessTokenEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenProcessTokenEx)((HANDLE)(LONG_PTR)-1, TOKEN_ALL_ACCESS, 0, &t), ST_SUCCESS);
    /* no package SID */
    EXPECT_EQ(UN(NtCreateLowBoxToken)(&h, t, TOKEN_ALL_ACCESS, NULL, NULL, 0, NULL, 0, NULL), ST_INVALID_PARAMETER);
    /* no source token */
    EXPECT_EQ(UN(NtCreateLowBoxToken)(&h, NULL, TOKEN_ALL_ACCESS, NULL, NULL, 0, NULL, 0, NULL), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
    CLOSE(t);
}

/* ---- paging file and partitions ---------------------------------------- */

TEST(create_paging_file_needs_privilege)
{
    WCHAR pf[] = L"\\??\\C:\\oa_never_created_pagefile.sys"; UNICODE_STRING name = {sizeof pf - 2, sizeof pf, pf}; LARGE_INTEGER mn, mx;
    REQUIRE(UN(NtCreatePagingFile));
    mn.QuadPart = 16 << 20; mx.QuadPart = 32 << 20;
    /* SeCreatePagefilePrivilege is held (disabled) at best, never enabled here: nothing may be created */
    EXPECT_EQ(UN(NtCreatePagingFile)(&name, &mn, &mx, 0), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreatePagingFile)(&name, &mx, &mn, 0), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreatePagingFile)(NULL, &mn, &mx, 0), ST_PRIV_NOT_HELD);
    CHECK(GetFileAttributesW(L"C:\\oa_never_created_pagefile.sys") == INVALID_FILE_ATTRIBUTES);
}

TEST(partition_create_open)
{
    HANDLE h = NULL; OBJECT_ATTRIBUTES oa; WCHAR nm[96]; REQUIRE(UN(NtCreatePartition)); REQUIRE(UN(NtOpenPartition));
    wsprintfW(nm, L"\\BaseNamedObjects\\oa_part_%lu", GetCurrentProcessId()); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreatePartition)(NULL, &h, 0x1F0003, &oa, 0), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreatePartition)((HANDLE)(LONG_PTR)-1, &h, 0x1F0003, &oa, 0), ST_PRIV_NOT_HELD);
    CHECK(h == NULL);
    EXPECT_EQ(UN(NtOpenPartition)(&h, 0x1F0003, &oa), ST_NAME_NOT_FOUND);
    EXPECT_EQ(UN(NtOpenPartition)(&h, 0x1F0003, NULL), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
}

TEST(open_session_object)
{
    HANDLE h = NULL; OBJECT_ATTRIBUTES oa; WCHAR nm[64]; DWORD sid = 0; REQUIRE(UN(NtOpenSession)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenSession)(&h, 1, NULL), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
    oa_init(&oa, L"\\KernelObjects\\NoSuchSessionZZ", 0);
    EXPECT_EQ(UN(NtOpenSession)(&h, 1, &oa), ST_NAME_NOT_FOUND);
    CHECK(h == NULL);
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid)) { t_skip("session id unavailable"); return; }
    wsprintfW(nm, L"\\KernelObjects\\Session%lu", sid); oa_init(&oa, nm, 0);
    NTSTATUS st = UN(NtOpenSession)(&h, 1 /* SESSION_QUERY_ACCESS */, &oa);
    if (st == ST_NAME_NOT_FOUND) { t_skip("no session object named %ls", nm); return; }
    if (st == ST_ACCESS_DENIED) { t_skip("session object %ls cannot be opened by this account", nm); return; }
    EXPECT_EQ(st, ST_SUCCESS);
    CLOSE(h);
    /* full control over a session object is not granted to ordinary callers */
    EXPECT_EQ(UN(NtOpenSession)(&h, 0x1F0001, &oa), ST_ACCESS_DENIED);
    CHECK(h == NULL);
}

/* ---- enclaves and cross-VM objects -------------------------------------- */

TEST(create_enclave_unsupported_configuration)
{
    PVOID base = NULL; ULONG err = 0xcc; REQUIRE(UN(NtCreateEnclave));
    NTSTATUS st = UN(NtCreateEnclave)((HANDLE)(LONG_PTR)-1, &base, 0, 0x100000, 0x1000, 1 /* SGX */, NULL, 0, &err);
    if (st >= 0) { t_skip("enclaves are supported on this machine"); return; }
    CHECK(base == NULL);
    t_note("NtCreateEnclave status %08lx", (unsigned long)st);
    base = NULL;
    st = UN(NtCreateEnclave)((HANDLE)(ULONG_PTR)0x1234, &base, 0, 0x100000, 0x1000, 1, NULL, 0, &err);
    CHECK(st < 0);
    CHECK(base == NULL);
}

TEST(create_cross_vm_objects_not_implemented)
{
    HANDLE h = NULL; REQUIRE(UN(NtCreateCrossVmEvent)); REQUIRE(UN(NtCreateCrossVmMutant));
    EXPECT_EQ(UN(NtCreateCrossVmEvent)(&h, 0x1F0003, NULL, 0, NULL, NULL, NULL), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtCreateCrossVmMutant)(&h, 0x1F0003, NULL, 0, NULL, NULL, NULL), ST_NOT_IMPL);
    CHECK(h == NULL);
}

/* ---- WNF ----------------------------------------------------------------- */

#define WNF_KEY 0x41C64E6DA3BC0074ULL
static void wnf_decode(ULONG64 name, ULONG *ver, ULONG *life, ULONG *scope, ULONG *perm)
{
    ULONG64 d = name ^ WNF_KEY;
    *ver = (ULONG)(d & 0xF); *life = (ULONG)((d >> 4) & 3); *scope = (ULONG)((d >> 6) & 0xF); *perm = (ULONG)((d >> 10) & 1);
}

TEST(wnf_create_temporary_state_name)
{
    SECURITY_DESCRIPTOR sd; ULONG64 a = 0, b = 0; ULONG ver, life, scope, perm;
    REQUIRE(UN(NtCreateWnfStateName)); REQUIRE(UN(NtDeleteWnfStateName));
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    /* lifetime 3 = temporary; scope 1 = session, 2 = user */
    { NTSTATUS ws = UN(NtCreateWnfStateName)(&a, 3, 1, FALSE, NULL, 0x1000, &sd);
      if (ws == ST_ACCESS_DENIED || ws == ST_PRIV_NOT_HELD) { t_skip("session-scope WNF names cannot be created by this account (%08lx)", (unsigned long)ws); return; }
      EXPECT_EQ(ws, ST_SUCCESS); }
    EXPECT_EQ(UN(NtCreateWnfStateName)(&b, 3, 1, FALSE, NULL, 0x1000, &sd), ST_SUCCESS);
    CHECK(a != 0 && b != 0 && a != b);
    wnf_decode(a, &ver, &life, &scope, &perm);
    EXPECT_EQ(ver, 1); EXPECT_EQ(life, 3); EXPECT_EQ(scope, 1); EXPECT_EQ(perm, 0);
    if (a) EXPECT_EQ(UN(NtDeleteWnfStateName)(&a), ST_SUCCESS);
    if (b) EXPECT_EQ(UN(NtDeleteWnfStateName)(&b), ST_SUCCESS);
    a = 0;
    EXPECT_EQ(UN(NtCreateWnfStateName)(&a, 3, 2, FALSE, NULL, 1, &sd), ST_SUCCESS);
    wnf_decode(a, &ver, &life, &scope, &perm);
    EXPECT_EQ(scope, 2);
    if (a) UN(NtDeleteWnfStateName)(&a);
}

TEST(wnf_create_invalid_arguments)
{
    SECURITY_DESCRIPTOR sd; ULONG64 w = 0; REQUIRE(UN(NtCreateWnfStateName)); REQUIRE(UN(NtDeleteWnfStateName));
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 3, FALSE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);   /* scope 3 not defined */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 5, FALSE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 9, FALSE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 4, 1, FALSE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);   /* lifetime */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 0, 1, FALSE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);   /* well-known names are not creatable */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 1, FALSE, NULL, 0x1001, &sd), ST_INVALID_PARAMETER);   /* max size is 4096 */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 1, TRUE, NULL, 0x1000, &sd), ST_INVALID_PARAMETER);    /* temporary names cannot persist data */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 3, 1, FALSE, NULL, 0x1000, NULL), ST_ACCESS_VIOLATION);   /* the SD is required */
    CHECK(w == 0);
    /* permanent and persistent names need a privilege */
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 1, 1, FALSE, NULL, 0x1000, &sd), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtCreateWnfStateName)(&w, 2, 1, FALSE, NULL, 0x1000, &sd), ST_PRIV_NOT_HELD);
    CHECK(w == 0);
}

/* ---- audit ---------------------------------------------------------------- */

TEST(open_object_audit_alarm_needs_audit_privilege)
{
    UNICODE_STRING sub, typ, obj; BOOLEAN gen = 0xCC; SECURITY_DESCRIPTOR sd; REQUIRE(UN(NtOpenObjectAuditAlarm));
    sub = *oa_us(L"Security"); typ = *oa_us(L"Section"); obj = *oa_us(L"oa_object");
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    EXPECT_EQ(UN(NtOpenObjectAuditAlarm)(&sub, NULL, &typ, &obj, NULL, NULL, 1, 1, NULL, FALSE, TRUE, &gen), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(NtOpenObjectAuditAlarm)(&sub, NULL, &typ, &obj, &sd, NULL, 1, 1, NULL, FALSE, TRUE, &gen), ST_PRIV_NOT_HELD);
    EXPECT_EQ(gen, 0xCC);
}

/* ---- profiles ----------------------------------------------------------- */

#define PROFILE_REGION ((PVOID)(ULONG_PTR)0x10000)

TEST(profile_create_buffer_sizing_and_validation)
{
    HANDLE h = NULL; ULONG *buf; REQUIRE(UN(NtCreateProfile)); REQUIRE(UN(NtClose));
    buf = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(buf != NULL); if (!buf) return;
    NTSTATUS st = UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x4000, 0, 1);
    if (st == ST_PRIV_NOT_HELD || st == ST_ACCESS_DENIED) { t_skip("profiling the current process is not permitted for this account (%08lx)", (unsigned long)st); VirtualFree(buf, 0, MEM_RELEASE); return; }
    /* one counter (ULONG) per (1 << (BucketShift - 2)) bytes of range: 0x10000 >> 2 = 0x4000 bytes at shift 4 */
    EXPECT_EQ(st, ST_SUCCESS);
    CLOSE(h);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x3FFC, 0, 1), ST(0xC0000023));
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 2, buf, 0x10000, 0, 1), ST_SUCCESS); CLOSE(h);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 3, buf, 0x10000, 0, 1), ST_SUCCESS); CLOSE(h);
    /* bucket shifts 0 and 1 are not allowed */
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 0, buf, 0x10000, 0, 1), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 1, buf, 0x10000, 0, 1), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 40, buf, 0x10000, 0, 1), ST_INVALID_PARAMETER);
    /* empty affinity, unsupported source, bad process, no buffer */
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 0, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 1, 1), ST_NOT_SUPP);
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(ULONG_PTR)0x1234, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 0, 1), ST(0xC0000008));
    EXPECT_EQ(UN(NtCreateProfile)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, NULL, 0x10000, 0, 1), ST_ACCESS_VIOLATION);
    CHECK(h == NULL);
    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST(profile_ex_group_affinity)
{
    HANDLE h = NULL; ULONG *buf; struct { ULONG_PTR mask; USHORT group; USHORT res[3]; } ga = {1, 0, {0, 0, 0}};
    REQUIRE(UN(NtCreateProfileEx)); REQUIRE(UN(NtClose));
    buf = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(buf != NULL); if (!buf) return;
    NTSTATUS st = UN(NtCreateProfileEx)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 0, 0, NULL);
    if (st == ST_PRIV_NOT_HELD || st == ST_ACCESS_DENIED) { t_skip("profiling the current process is not permitted for this account (%08lx)", (unsigned long)st); VirtualFree(buf, 0, MEM_RELEASE); return; }
    EXPECT_EQ(st, ST_SUCCESS); CLOSE(h);
    EXPECT_EQ(UN(NtCreateProfileEx)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 0, 1, &ga), ST_SUCCESS); CLOSE(h);
    EXPECT_EQ(UN(NtCreateProfileEx)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 0, 1, NULL), ST_ACCESS_VIOLATION);
    EXPECT_EQ(UN(NtCreateProfileEx)(&h, (HANDLE)(LONG_PTR)-1, PROFILE_REGION, 0x10000, 4, buf, 0x10000, 1, 0, NULL), ST_NOT_SUPP);
    CHECK(h == NULL);
    VirtualFree(buf, 0, MEM_RELEASE);
}
