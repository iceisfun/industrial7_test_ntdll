/* Privileged or rarely used create/open services: partitions, sessions, job sets, audit alarms,
 * token creation, low-box tokens, profile objects, legacy ports and WNF state names. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreatePartition, (HANDLE, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwOpenPartition, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenSession, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreateJobSet, (ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwOpenObjectAuditAlarm, (PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PVOID, HANDLE, ACCESS_MASK, ACCESS_MASK, PVOID, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(NTSTATUS, ZwCreateToken, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PLUID, PLARGE_INTEGER, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, ZwCreateTokenEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PLUID, PLARGE_INTEGER, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, ZwCreateLowBoxToken, (PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG, PVOID, ULONG, PHANDLE));
UDECL(NTSTATUS, ZwOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwCreateProfile, (PHANDLE, HANDLE, PVOID, SIZE_T, ULONG, PULONG, ULONG, ULONG, ULONG_PTR));
UDECL(NTSTATUS, ZwCreateProfileEx, (PHANDLE, HANDLE, PVOID, SIZE_T, ULONG, PULONG, ULONG, ULONG, USHORT, PVOID));
UDECL(NTSTATUS, ZwCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, ZwCreateWaitablePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, ZwCreateWnfStateName, (PULONGLONG, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PVOID));
UDECL(NTSTATUS, NtDeleteWnfStateName, (PULONGLONG));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));

#define NEEDM() do { REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); } while (0)
#define S_BADPKGSID ((NTSTATUS)0xC000A202)
#define S_PARAM7 ((NTSTATUS)0xC00000F5)

TEST(nt_create_open_b_partition_session)
{
    HANDLE h = (HANDLE)0x1234, o = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200]; NTSTATUS s;
    NEEDM(); REQUIRE(UN(ZwOpenPartition)); REQUIRE(UN(ZwOpenSession)); REQUIRE(UN(ZwCreatePartition));
    COB_ALIAS("CreatePartition"); COB_ALIAS("OpenPartition"); COB_ALIAS("OpenSession");
    cob_name(name, 200, "part"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(ZwOpenPartition)(&o, 0xF0007, &oa), S_NOTFOUND);
    EXPECT_EQ(UN(ZwOpenPartition)(&o, 0xF0007, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenSession)(&o, 0x1F0001, &oa), S_NOTFOUND);
    EXPECT_EQ(UN(ZwOpenSession)(&o, 0x1F0001, NULL), S_INVPARAM);
    /* partition creation needs a privilege that neither standard nor elevated tokens hold by default */
    cob_oa(&oa, NULL, 0, NULL);
    s = UN(ZwCreatePartition)(NULL, &h, 0xF0007, &oa, 0);
    if (s == S_OK_) { t_skip("caller holds the partition-creation privilege"); cob_close(h); return; }
    EXPECT_EQ(s, S_PRIVNH);
    EXPECT_EQ(UN(ZwCreatePartition)((HANDLE)(ULONG_PTR)-1, &h, 0xF0007, &oa, 0), S_PRIVNH);
    EXPECT_EQ(UN(ZwCreatePartition)((HANDLE)(ULONG_PTR)0x7ff0, &h, 0xF0007, &oa, 0), S_PRIVNH);
    EXPECT_EQ(UN(ZwCreatePartition)(NULL, NULL, 0xF0007, &oa, 0), S_AV);
}

TEST(nt_create_open_b_job_set)
{
    struct { HANDLE j; ULONG lvl, fl; } arr[2]; HANDLE j1 = NULL, j2 = NULL; OBJECT_ATTRIBUTES oa;
    NEEDM(); REQUIRE(UN(ZwCreateJobSet)); COB_ALIAS("CreateJobSet");
    /* The service is not supported on this version for any argument combination. */
    EXPECT_EQ(UN(ZwCreateJobSet)(0, NULL, 0), S_NOTSUPP);
    EXPECT_EQ(UN(ZwCreateJobSet)(1, NULL, 0), S_NOTSUPP);
    memset(arr, 0, sizeof arr); arr[0].j = (HANDLE)(ULONG_PTR)0x7ff0; arr[1].j = (HANDLE)(ULONG_PTR)0x7ff4;
    EXPECT_EQ(UN(ZwCreateJobSet)(2, arr, 0), S_NOTSUPP);
    EXPECT_EQ(UN(ZwCreateJobSet)(2, arr, 1), S_NOTSUPP);
    { UNICODE_STRING dummy; (void)dummy; (void)oa; (void)j1; (void)j2; }
}

TEST(nt_create_open_b_audit_alarm)
{
    UNICODE_STRING sub, typ, obj; BOOLEAN gen = 7; NTSTATUS s;
    NEEDM(); REQUIRE(UN(ZwOpenObjectAuditAlarm)); COB_ALIAS("OpenObjectAuditAlarm");
    cob_us(&sub, L"CobTest"); cob_us(&typ, L"Event"); cob_us(&obj, L"CobObject");
    /* SeAuditPrivilege is required; it is not held by users or by an elevated administrator token */
    s = UN(ZwOpenObjectAuditAlarm)(&sub, NULL, &typ, &obj, NULL, NULL, 1, 1, NULL, FALSE, TRUE, &gen);
    EXPECT_EQ(s, S_PRIVNH); EXPECT_EQ(gen, 7);
    EXPECT_EQ(UN(ZwOpenObjectAuditAlarm)(NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, NULL, FALSE, FALSE, NULL), S_PRIVNH);
}

TEST(nt_create_open_b_create_token_privilege)
{
    HANDLE h = (HANDLE)0x1234; NTSTATUS s;
    NEEDM(); REQUIRE(UN(ZwCreateToken)); REQUIRE(UN(ZwCreateTokenEx));
    COB_ALIAS("CreateToken"); COB_ALIAS("CreateTokenEx");
    /* SeCreateTokenPrivilege is held only by the security subsystem; the check precedes any argument validation */
    s = UN(ZwCreateToken)(&h, 0xF01FF, NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(s, S_PRIVNH);
    s = UN(ZwCreateTokenEx)(&h, 0xF01FF, NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(s, S_PRIVNH);
    if (s == S_OK_) cob_close(h);
}

TEST(nt_create_open_b_lowbox_token)
{
    HANDLE tok = NULL, lb = NULL; NTSTATUS s; ULONG v = 0, ret = 0; WCHAR tn[40];
    BYTE sid[40] = {1, 8, 0, 0, 0, 0, 0, 15, 2,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0, 4,0,0,0, 5,0,0,0, 6,0,0,0, 7,0,0,0};   /* S-1-15-2-1-2-3-4-5-6-7 */
    BYTE shortsid[32] = {1, 6, 0, 0, 0, 0, 0, 15, 2,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0, 4,0,0,0, 5,0,0,0};
    NEEDM(); REQUIRE(UN(ZwCreateLowBoxToken)); REQUIRE(UN(ZwOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken));
    COB_ALIAS("CreateLowBoxToken");
    s = UN(ZwOpenProcessToken)(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &tok); EXPECT_EQ(s, S_OK_); if (!tok) return;
    s = UN(ZwCreateLowBoxToken)(&lb, tok, 0xF01FF, NULL, (PSID)sid, 0, NULL, 0, NULL);
    EXPECT_EQ(s, S_OK_);
    if (lb) {
        CHECK(cob_typename(lb, tn, 40)); EXPECT_WSTR(tn, L"Token");
        v = 0xcc; EXPECT_EQ(UN(NtQueryInformationToken)(lb, 29 /* TokenIsAppContainer */, &v, sizeof v, &ret), S_OK_); EXPECT_EQ(v, 1);
        v = 0xcc; EXPECT_EQ(UN(NtQueryInformationToken)(lb, 8 /* TokenType */, &v, sizeof v, &ret), S_OK_); EXPECT_EQ(v, 1);
        { BYTE buf[256]; memset(buf, 0, sizeof buf); s = UN(NtQueryInformationToken)(lb, 31 /* TokenAppContainerSid */, buf, sizeof buf, &ret); EXPECT_EQ(s, S_OK_);
          if (s == S_OK_) { PSID p = *(PSID *)buf; CHECK(p != NULL); if (p) { EXPECT_EQ(GetLengthSid(p), 40); CHECK(!memcmp(p, sid, 40)); } } }
        cob_close(lb); lb = NULL;
    }
    /* the source token must still be a normal token */
    v = 0xcc; EXPECT_EQ(UN(NtQueryInformationToken)(tok, 29, &v, sizeof v, &ret), S_OK_); EXPECT_EQ(v, 0);
    /* errors */
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(&lb, tok, 0xF01FF, NULL, NULL, 0, NULL, 0, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(&lb, tok, 0xF01FF, NULL, (PSID)shortsid, 0, NULL, 0, NULL), S_BADPKGSID);
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(&lb, NULL, 0xF01FF, NULL, (PSID)sid, 0, NULL, 0, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(&lb, (HANDLE)(ULONG_PTR)0x7ffffff0, 0xF01FF, NULL, (PSID)sid, 0, NULL, 0, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(NULL, tok, 0xF01FF, NULL, (PSID)sid, 0, NULL, 0, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateLowBoxToken)(&lb, GetCurrentProcess(), 0xF01FF, NULL, (PSID)sid, 0, NULL, 0, NULL), S_TYPEMM);
    cob_close(lb); cob_close(tok);
}

TEST(nt_create_open_b_profile)
{
    HANDLE h = NULL; NTSTATUS s; ULONG buf[0x40]; static char region[0x10000]; WCHAR tn[40];
    NEEDM(); REQUIRE(UN(ZwCreateProfile)); REQUIRE(UN(ZwCreateProfileEx));
    COB_ALIAS("CreateProfile"); COB_ALIAS("CreateProfileEx");
    /* a profile of the caller's own process needs no privilege; it is created stopped */
    s = UN(ZwCreateProfile)(&h, GetCurrentProcess(), region, sizeof region, 12, buf, sizeof buf, 0 /* ProfileTime */, 1);
    EXPECT_EQ(s, S_OK_);
    if (h) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Profile"); cob_close(h); h = NULL; }
    /* a system-wide profile (no process) needs SeSystemProfilePrivilege, which is not enabled */
    s = UN(ZwCreateProfile)(&h, NULL, region, sizeof region, 12, buf, sizeof buf, 0, 1); EXPECT_EQ(s, S_PRIVNH); cob_close(h); h = NULL;
    /* argument validation precedes the privilege check */
    EXPECT_EQ(UN(ZwCreateProfile)(&h, NULL, region, sizeof region, 1, buf, sizeof buf, 0, 1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateProfile)(&h, NULL, region, sizeof region, 40, buf, sizeof buf, 0, 1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateProfile)(&h, NULL, region, sizeof region, 12, buf, 0, 0, 1), S_PARAM7);
    EXPECT_EQ(UN(ZwCreateProfile)(&h, GetCurrentProcess(), region, sizeof region, 12, buf, sizeof buf, 0x7fff, 1), S_NOTSUPP);
    EXPECT_EQ(UN(ZwCreateProfile)(NULL, GetCurrentProcess(), region, sizeof region, 12, buf, sizeof buf, 0, 1), S_AV);
    EXPECT_EQ(UN(ZwCreateProfile)(&h, (HANDLE)(ULONG_PTR)0x7ffffff0, region, sizeof region, 12, buf, sizeof buf, 0, 1), S_INVHANDLE);
    /* extended form */
    s = UN(ZwCreateProfileEx)(&h, GetCurrentProcess(), region, sizeof region, 12, buf, sizeof buf, 0, 0, NULL);
    t_note("ZwCreateProfileEx(self) status 0x%08lx", (unsigned long)s);
    if (s == S_OK_) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Profile"); cob_close(h); h = NULL; }
    EXPECT_EQ(UN(ZwCreateProfileEx)(&h, NULL, region, sizeof region, 12, buf, sizeof buf, 0, 0, NULL), S_PRIVNH);
    EXPECT_EQ(UN(ZwCreateProfileEx)(&h, NULL, region, sizeof region, 1, buf, sizeof buf, 0, 0, NULL), S_INVPARAM);
}

TEST(nt_create_open_b_legacy_port)
{
    HANDLE h = NULL, h2 = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40]; NTSTATUS s;
    NEEDM(); REQUIRE(UN(ZwCreatePort)); REQUIRE(UN(ZwCreateWaitablePort));
    COB_ALIAS("CreatePort"); COB_ALIAS("CreateWaitablePort");
    /* unnamed port; legacy ports are ALPC port objects on this version */
    cob_oa(&oa, NULL, 0, NULL);
    s = UN(ZwCreatePort)(&h, &oa, 0, 0x100, 0); EXPECT_EQ(s, S_OK_);
    if (h) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"ALPC Port"); cob_close(h); h = NULL; }
    s = UN(ZwCreatePort)(&h, NULL, 0, 0x100, 0); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    s = UN(ZwCreateWaitablePort)(&h, &oa, 0, 0x100, 0); EXPECT_EQ(s, S_OK_);
    if (h) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"ALPC Port"); cob_close(h); h = NULL; }
    /* named port in the session namespace; a second create under the same name collides */
    cob_name(name, 200, "port"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreatePort)(&h, &oa, 0, 0x100, 0); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        h2 = (HANDLE)0x1234; EXPECT_EQ(UN(ZwCreatePort)(&h2, &oa, 0, 0x100, 0), S_COLLIDE);
        h2 = (HANDLE)0x1234; EXPECT_EQ(UN(ZwCreateWaitablePort)(&h2, &oa, 0, 0x100, 0), S_COLLIDE);
        cob_close(h);
        h = NULL;
    }
    cob_oa(&oa, NULL, 0, NULL);
    /* message length limit */
    EXPECT_EQ(UN(ZwCreatePort)(&h, &oa, 0, 0x10000, 0), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateWaitablePort)(&h, &oa, 0, 0x10000, 0), S_INVPARAM);
    /* large connection info and zero lengths are accepted */
    s = UN(ZwCreatePort)(&h, &oa, 0x10000, 0x100, 0); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    s = UN(ZwCreatePort)(&h, &oa, 0, 0, 0); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    EXPECT_EQ(UN(ZwCreatePort)(NULL, &oa, 0, 0x100, 0), S_AV);
    EXPECT_EQ(UN(ZwCreateWaitablePort)(NULL, &oa, 0, 0x100, 0), S_AV);
}

TEST(nt_create_open_b_wnf_state_name)
{
    ULONGLONG nm = 0x1122334455667788ULL; BYTE sd[64]; NTSTATUS s;
    NEEDM(); REQUIRE(UN(ZwCreateWnfStateName)); REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor));
    COB_ALIAS("CreateWnfStateName");
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(sd, 1), S_OK_);
    EXPECT_EQ(UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, NULL, FALSE), S_OK_);
    /* Argument validation: lifetime, scope and maximum state size */
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 0, 3, FALSE, NULL, 0x1000, sd), S_INVPARAM);     /* well-known names cannot be created */
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 3, 3, FALSE, NULL, 0x1000, sd), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 9, 3, FALSE, NULL, 0x1000, sd), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 1, 5, FALSE, NULL, 0x1000, sd), S_INVPARAM);     /* scope beyond machine */
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 1, 3, FALSE, NULL, 0x100000, sd), S_INVPARAM);   /* above the 4 KiB limit */
    EXPECT_EQ(UN(ZwCreateWnfStateName)(NULL, 1, 3, FALSE, NULL, 0x1000, sd), S_AV);
    EXPECT_EQ(UN(ZwCreateWnfStateName)(&nm, 1, 3, FALSE, NULL, 0x1000, NULL), S_AV);
    /* A valid request needs a privilege that neither standard nor elevated tokens hold by default. */
    nm = 0x1122334455667788ULL;
    s = UN(ZwCreateWnfStateName)(&nm, 1 /* temporary */, 3 /* process */, FALSE, NULL, 0x1000, sd);
    if (s == S_OK_) { t_note("create succeeded; name 0x%llx", (unsigned long long)nm); CHECK(nm != 0x1122334455667788ULL); if (UN(NtDeleteWnfStateName)) UN(NtDeleteWnfStateName)(&nm); }
    else { EXPECT_EQ(s, S_PRIVNH); EXPECT_EQ(nm, 0x1122334455667788ULL); }
}
