/* System-level services that are privilege gated or environment dependent: boot and driver entries,
 * firmware environment enumeration, application-compatibility cache control, process activity references,
 * auxiliary counters, registry compaction, display services. */
#include "t.h"

UDECL(NTSTATUS, NtEnumerateBootEntries, (PVOID, PULONG));
UDECL(NTSTATUS, NtEnumerateDriverEntries, (PVOID, PULONG));
UDECL(NTSTATUS, NtAddBootEntry, (PVOID, PULONG));
UDECL(NTSTATUS, NtDeleteBootEntry, (ULONG));
UDECL(NTSTATUS, NtAddDriverEntry, (PVOID, PULONG));
UDECL(NTSTATUS, NtDeleteDriverEntry, (ULONG));
UDECL(NTSTATUS, NtFilterBootOption, (ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtEnumerateSystemEnvironmentValuesEx, (ULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtApphelpCacheControl, (ULONG, PVOID));
UDECL(NTSTATUS, NtAcquireProcessActivityReference, (PHANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, NtAcquireCrossVmMutant, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtConvertBetweenAuxiliaryCounterAndPerformanceCounter, (BOOLEAN, PULONG64, PULONG64, PULONG64));
UDECL(NTSTATUS, NtCompactKeys, (ULONG, HANDLE *));
UDECL(NTSTATUS, NtCompressKey, (HANDLE));
UDECL(NTSTATUS, NtDisplayString, (PUNICODE_STRING));
UDECL(NTSTATUS, NtDrawText, (PUNICODE_STRING));
UDECL(NTSTATUS, NtCallEnclave, (PVOID, PVOID, BOOLEAN, PVOID *));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define ST_INVHANDLE  S(0xC0000008)
#define ST_INVPARAM   S(0xC000000D)
#define ST_AV         S(0xC0000005)
#define ST_PRIVNH     S(0xC0000061)
#define ST_TYPEMISM   S(0xC0000024)
#define ST_NOTIMPL    S(0xC0000002)
#define ST_BUFSMALL   S(0xC0000023)
#define ST_LEN_MISM   S(0xC0000004)
#define SE_SYSTEM_ENVIRONMENT 22

static LONG priv_attr(ULONG luid)
{
    HANDLE t = NULL; union { ULONGLONG a; BYTE b[4096]; } buf; ULONG got = 0; TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf.b; LONG r = -1;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &t) < 0) return -2;
    if (UN(NtQueryInformationToken)(t, 3, buf.b, sizeof buf, &got) < 0) r = -2;
    else for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == luid && !tp->Privileges[i].Luid.HighPart) r = (LONG)tp->Privileges[i].Attributes;
    UN(NtClose)(t);
    return r;
}

TEST(system_aliases)
{
    static const char *n[] = { "EnumerateBootEntries", "EnumerateDriverEntries", "AddBootEntry", "DeleteBootEntry", "AddDriverEntry",
        "DeleteDriverEntry", "FilterBootOption", "EnumerateSystemEnvironmentValuesEx", "ApphelpCacheControl", "AcquireProcessActivityReference",
        "AcquireCrossVmMutant", "ConvertBetweenAuxiliaryCounterAndPerformanceCounter", "CompactKeys", "CompressKey", "DisplayString", "DrawText", "CallEnclave" };
    char a[96], b[96];
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "alias %s", a);
    }
}

#define ST_NOT_SUPPORTED S(0xC00000BB)
/* Boot and driver entries and firmware variables are only reachable on UEFI machines; on BIOS machines the
 * services report STATUS_NOT_IMPLEMENTED, on UEFI without the privilege enabled STATUS_PRIVILEGE_NOT_HELD. */
static int fw_status_ok(NTSTATUS s) { return s == ST_NOTIMPL || s == ST_PRIVNH; }

TEST(boot_entries_without_privilege)
{
    ULONG id = 0x1234, len = 0; BYTE buf[64]; NTSTATUS s;
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtEnumerateBootEntries));
    if (priv_attr(SE_SYSTEM_ENVIRONMENT) > 0 && (priv_attr(SE_SYSTEM_ENVIRONMENT) & SE_PRIVILEGE_ENABLED)) { t_skip("SeSystemEnvironmentPrivilege is enabled in the token"); return; }
    len = sizeof buf;
    s = UN(NtEnumerateBootEntries)(buf, &len);   CHECKF(fw_status_ok(s), "EnumerateBootEntries 0x%08lx", s);
    len = sizeof buf;
    s = UN(NtEnumerateDriverEntries)(buf, &len); CHECKF(fw_status_ok(s), "EnumerateDriverEntries 0x%08lx", s);
    memset(buf, 0, sizeof buf);
    s = UN(NtAddBootEntry)(buf, &id);            CHECKF(fw_status_ok(s), "AddBootEntry 0x%08lx", s);
    s = UN(NtAddDriverEntry)(buf, &id);          CHECKF(fw_status_ok(s), "AddDriverEntry 0x%08lx", s);
    s = UN(NtDeleteBootEntry)(0xFFFFFFF0);       CHECKF(fw_status_ok(s), "DeleteBootEntry 0x%08lx", s);
    s = UN(NtDeleteDriverEntry)(0xFFFFFFF0);     CHECKF(fw_status_ok(s), "DeleteDriverEntry 0x%08lx", s);
    s = UN(NtFilterBootOption)(0, 0, 0, buf, 8); CHECKF(s < 0 || (ULONG)s >= 0x80000000, "FilterBootOption 0x%08lx", s);
    for (ULONG c = 1; c <= 2; c++) { len = sizeof buf; s = UN(NtEnumerateSystemEnvironmentValuesEx)(c, buf, &len); CHECKF(fw_status_ok(s), "EnumerateSystemEnvironmentValuesEx(%lu) 0x%08lx", c, s); }
    len = sizeof buf;
    s = UN(NtEnumerateSystemEnvironmentValuesEx)(99, buf, &len); CHECKF(fw_status_ok(s) || s == ST_INVPARAM, "EnumerateSystemEnvironmentValuesEx(99) 0x%08lx", s);
    if (s == ST_NOTIMPL) t_note("BIOS-style firmware: boot/driver/environment services report STATUS_NOT_IMPLEMENTED");
}

TEST(apphelp_cache_control)
{
    NTSTATUS s; BYTE buf[256]; ULONG c;
    REQUIRE(UN(NtApphelpCacheControl));
    memset(buf, 0, sizeof buf);
    for (c = 0; c < 12; c++) { s = UN(NtApphelpCacheControl)(c, NULL); CHECKF(s == ST_AV, "class %lu NULL data: 0x%08lx", c, s); }
    EXPECT_EQ(UN(NtApphelpCacheControl)(0x7FFF, buf), ST_INVPARAM);
    EXPECT_EQ(UN(NtApphelpCacheControl)(0xFFFFFFFF, buf), ST_INVPARAM);
}

TEST(process_activity_reference)
{
    HANDLE h = NULL; NTSTATUS s;
    REQUIRE(UN(NtAcquireProcessActivityReference));
    /* the service is restricted to callers inside the process lifetime manager */
    s = UN(NtAcquireProcessActivityReference)(&h, GetCurrentProcess(), 0);
    EXPECT_EQ(s, S(0xC0000022)); EXPECT_EQ(h, NULL);
    if (s >= 0 && h) UN(NtClose)(h);
    h = NULL; s = UN(NtAcquireProcessActivityReference)(&h, GetCurrentProcess(), 1);
    EXPECT_EQ(s, S(0xC00000F1));      /* STATUS_INVALID_PARAMETER_3 */
    EXPECT_EQ(UN(NtAcquireProcessActivityReference)(&h, NULL, 0), S(0xC0000022));
    EXPECT_EQ(UN(NtAcquireProcessActivityReference)(NULL, GetCurrentProcess(), 0), ST_AV);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtAcquireProcessActivityReference)(&h, ev, 0), S(0xC0000022)); CloseHandle(ev); }
}

TEST(cross_vm_mutant)
{
    NTSTATUS s; LARGE_INTEGER t; HANDLE mx;
    REQUIRE(UN(NtAcquireCrossVmMutant));
    t.QuadPart = 0;
    /* only objects of the cross-VM mutant type are accepted */
    EXPECT_EQ(UN(NtAcquireCrossVmMutant)(NULL, &t), ST_TYPEMISM);
    mx = CreateMutexW(NULL, FALSE, NULL);
    EXPECT_EQ(UN(NtAcquireCrossVmMutant)(mx, &t), ST_TYPEMISM);
    CloseHandle(mx);
}

TEST(convert_auxiliary_counter)
{
    NTSTATUS s; ULONG64 in = 1000, out = 0xcc, err = 0xcc; LARGE_INTEGER pc;
    REQUIRE(UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter));
    QueryPerformanceCounter(&pc); in = pc.QuadPart;
    /* hardware without an auxiliary counter reports STATUS_NOT_SUPPORTED and leaves the outputs alone */
    s = UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(FALSE, &in, &out, &err);
    if (s == ST_NOT_SUPPORTED) { EXPECT_EQ(out, 0xcc); EXPECT_EQ(err, 0xcc);
        EXPECT_EQ(UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(TRUE, &in, &out, &err), ST_NOT_SUPPORTED);
        /* pointers are probed before support is checked, the error output is optional */
        EXPECT_EQ(UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(TRUE, NULL, &out, &err), ST_AV);
        EXPECT_EQ(UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(TRUE, &in, NULL, &err), ST_AV);
        EXPECT_EQ(UN(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(TRUE, &in, &out, NULL), ST_NOT_SUPPORTED);
    } else if (s >= 0) { CHECK(out != 0xcc); t_note("auxiliary counter available: converted value 0x%llx error 0x%llx", out, err); }
    else CHECKF(0, "unexpected status 0x%08lx", s);
}

TEST(compact_compress_key)
{
    NTSTATUS s; HANDLE h = NULL, h2; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR path[200]; ULONG disp = 0;
    REQUIRE(UN(NtCompactKeys)); REQUIRE(UN(NtCompressKey)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtDeleteKey));
    /* these services require a privilege that ordinary and administrator tokens do not hold */
    if (priv_attr(7 /* SeTcbPrivilege */) >= 0) { t_skip("token holds SeTcbPrivilege"); return; }
    EXPECT_EQ(UN(NtCompressKey)(NULL), ST_PRIVNH);
    EXPECT_EQ(UN(NtCompactKeys)(0, NULL), ST_PRIVNH);
    h2 = NULL; EXPECT_EQ(UN(NtCompactKeys)(1, &h2), ST_PRIVNH);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtCompressKey)(ev), ST_PRIVNH); CloseHandle(ev); }
    swprintf(path, 200, L"\\Registry\\User\\.Default\\nt1a_compact_%lu", GetCurrentProcessId());
    u.Buffer = path; u.Length = (USHORT)(lstrlenW(path) * 2); u.MaximumLength = u.Length + 2;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateKey)(&h, KEY_ALL_ACCESS, &oa, 0, NULL, 0, &disp);
    if (s >= 0 && h) {
        EXPECT_EQ(UN(NtCompressKey)(h), ST_PRIVNH);
        h2 = h; EXPECT_EQ(UN(NtCompactKeys)(1, &h2), ST_PRIVNH);
        UN(NtDeleteKey)(h); UN(NtClose)(h);
    } else t_note("scratch key could not be created (0x%08lx): privilege checks on real keys skipped", s);
}

TEST(display_string)
{
    UNICODE_STRING u = { 0, 2, (PWSTR)L"" };
    REQUIRE(UN(NtDisplayString)); REQUIRE(UN(NtDrawText));
    /* boot-display output requires SeTcbPrivilege (checked before the string is looked at, except NULL) */
    if (priv_attr(7) >= 0) { t_skip("token holds SeTcbPrivilege"); return; }
    EXPECT_EQ(UN(NtDisplayString)(&u), ST_PRIVNH);
    EXPECT_EQ(UN(NtDrawText)(&u), ST_PRIVNH);
    EXPECT_EQ(UN(NtDisplayString)(NULL), ST_INVPARAM);
    EXPECT_EQ(UN(NtDrawText)(NULL), ST_PRIVNH);
}
