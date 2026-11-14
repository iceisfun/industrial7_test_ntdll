/* System-wide query services: NtQuerySystemTime, NtQueryPerformanceCounter, NtQueryTimerResolution,
 * NtQueryDefaultLocale, NtQueryDefaultUILanguage, NtQueryInstallUILanguage, NtQueryIntervalProfile,
 * NtQueryDebugFilterState, NtQueryAuxiliaryCounterFrequency, NtQuerySystemInformationEx,
 * NtQueryLicenseValue, NtQueryPortInformationProcess, and the privilege-gated firmware queries
 * (NtQueryBootEntryOrder, NtQueryBootOptions, NtQueryDriverEntryOrder, NtQuerySystemEnvironmentValue[Ex]).
 * Expected values are documented in EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryPerformanceCounter, (PLARGE_INTEGER, PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryTimerResolution, (PULONG, PULONG, PULONG));
UDECL(NTSTATUS, NtQueryDefaultLocale, (BOOLEAN, PLCID));
UDECL(NTSTATUS, NtQueryDefaultUILanguage, (LANGID *));
UDECL(NTSTATUS, NtQueryInstallUILanguage, (LANGID *));
UDECL(NTSTATUS, NtQueryIntervalProfile, (ULONG, PULONG));
UDECL(NTSTATUS, NtQueryDebugFilterState, (ULONG, ULONG));
UDECL(NTSTATUS, NtQueryAuxiliaryCounterFrequency, (PULONGLONG));
UDECL(NTSTATUS, NtQuerySystemInformationEx, (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryLicenseValue, (PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryPortInformationProcess, (void));
UDECL(NTSTATUS, NtQueryBootEntryOrder, (PULONG, PULONG));
UDECL(NTSTATUS, NtQueryDriverEntryOrder, (PULONG, PULONG));
UDECL(NTSTATUS, NtQueryBootOptions, (PVOID, PULONG));
UDECL(NTSTATUS, NtQuerySystemEnvironmentValue, (PUNICODE_STRING, PWSTR, USHORT, PUSHORT));
UDECL(NTSTATUS, NtQuerySystemEnvironmentValueEx, (PUNICODE_STRING, GUID *, PVOID, PULONG, PULONG));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define S(x) ((NTSTATUS)(x))
#define ST_AV        S(0xC0000005)
#define ST_INV_CLASS S(0xC0000003)
#define ST_LEN_MISM  S(0xC0000004)
#define ST_INV_PARM  S(0xC000000D)
#define ST_NOT_IMPL  S(0xC0000002)
#define ST_PRIV      S(0xC0000061)
#define ST_NOT_FOUND S(0xC0000034)
#define ST_TOO_SMALL S(0xC0000023)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE 22

TEST(sys_alias_pairs)
{
    static const char *n[] = { "QuerySystemTime", "QueryPerformanceCounter", "QueryTimerResolution", "QueryDefaultLocale",
        "QueryDefaultUILanguage", "QueryInstallUILanguage", "QueryIntervalProfile", "QueryDebugFilterState",
        "QueryAuxiliaryCounterFrequency", "QuerySystemInformationEx", "QueryLicenseValue", "QueryPortInformationProcess",
        "QueryBootEntryOrder", "QueryDriverEntryOrder", "QueryBootOptions", "QuerySystemEnvironmentValue",
        "QuerySystemEnvironmentValueEx" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[80], b[80];
        sprintf(a, "Nt%s", n[i]); sprintf(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == pb, "%s and %s must share an address", a, b);
    }
}

TEST(sys_time)
{
    LARGE_INTEGER a, b; FILETIME ft; ULONGLONG k;
    REQUIRE(UN(NtQuerySystemTime));
    memset(&a, 0xcc, sizeof a);
    EXPECT_EQ(UN(NtQuerySystemTime)(&a), 0);
    GetSystemTimeAsFileTime(&ft);
    k = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    CHECKF(a.QuadPart > 0 && (ULONGLONG)a.QuadPart <= k, "system time %llx vs kernel32 %llx", (long long)a.QuadPart, (long long)k);
    CHECK(k - (ULONGLONG)a.QuadPart < 10000000ULL); /* within one second */
    Sleep(50);
    EXPECT_EQ(UN(NtQuerySystemTime)(&b), 0);
    CHECK(b.QuadPart >= a.QuadPart);
    /* sanity: after year 2020 (FILETIME 0x01D5 ...) */
    CHECK((ULONGLONG)a.QuadPart > 0x01D5E0000000000ULL);
}

TEST(sys_perf_counter)
{
    LARGE_INTEGER c1, c2, f, qf, qc; NTSTATUS s;
    REQUIRE(UN(NtQueryPerformanceCounter));
    memset(&c1, 0, sizeof c1); memset(&f, 0, sizeof f);
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c1, &f), 0);
    QueryPerformanceFrequency(&qf);
    CHECK(f.QuadPart > 0);
    EXPECT_EQ(f.QuadPart, qf.QuadPart);
    Sleep(20);
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c2, NULL), 0);   /* frequency is optional */
    CHECK(c2.QuadPart > c1.QuadPart);
    QueryPerformanceCounter(&qc);
    CHECK(qc.QuadPart >= c2.QuadPart);
    CHECK(qc.QuadPart - c2.QuadPart < f.QuadPart * 5);
    /* elapsed ticks over a 20ms+ sleep must be at least ~15ms worth */
    CHECK((c2.QuadPart - c1.QuadPart) * 1000 / f.QuadPart >= 15);
    /* invalid counter pointer is reported as a status, not an exception */
    s = UN(NtQueryPerformanceCounter)(NULL, &f);
    EXPECT_EQ(s, ST_AV);
    s = UN(NtQueryPerformanceCounter)((PLARGE_INTEGER)(ULONG_PTR)0x10, NULL);
    EXPECT_EQ(s, ST_AV);
}

TEST(sys_timer_resolution)
{
    ULONG mn = 0, mx = 0, cur = 0; NTSTATUS s;
    REQUIRE(UN(NtQueryTimerResolution));
    EXPECT_EQ(UN(NtQueryTimerResolution)(&mn, &mx, &cur), 0);
    /* 100ns units; Minimum is the coarsest period, Maximum the finest */
    CHECKF(mx > 0 && mn >= mx, "min %lu max %lu", mn, mx);
    CHECKF(cur >= mx && cur <= mn, "cur %lu", cur);
    CHECK(mn >= 100000 && mn <= 200000);   /* default tick 15.6ms */
    s = UN(NtQueryTimerResolution)(NULL, &mx, &cur);
    EXPECT_EQ(s, ST_AV);
    s = UN(NtQueryTimerResolution)(&mn, NULL, &cur);
    EXPECT_EQ(s, ST_AV);
    s = UN(NtQueryTimerResolution)(&mn, &mx, NULL);
    EXPECT_EQ(s, ST_AV);
}

TEST(sys_locale)
{
    LCID l = 0xcc, u = 0xcc; LANGID ui = 0xcccc, inst = 0xcccc, ui2;
    REQUIRE(UN(NtQueryDefaultLocale)); REQUIRE(UN(NtQueryDefaultUILanguage)); REQUIRE(UN(NtQueryInstallUILanguage));
    EXPECT_EQ(UN(NtQueryDefaultLocale)(TRUE, &u), 0);
    EXPECT_EQ(u, GetUserDefaultLCID());
    EXPECT_EQ(UN(NtQueryDefaultLocale)(FALSE, &l), 0);
    EXPECT_EQ(l, GetSystemDefaultLCID());
    CHECK(l != 0 && u != 0);
    EXPECT_EQ(UN(NtQueryDefaultUILanguage)(&ui), 0);
    ui2 = GetUserDefaultUILanguage();
    EXPECT_EQ(ui, ui2);
    EXPECT_EQ(UN(NtQueryInstallUILanguage)(&inst), 0);
    CHECK(inst != 0 && inst != 0xcccc);
    EXPECT_EQ(inst, GetSystemDefaultUILanguage());
    EXPECT_EQ(UN(NtQueryDefaultLocale)(TRUE, NULL), ST_AV);
    EXPECT_EQ(UN(NtQueryDefaultUILanguage)(NULL), ST_AV);
    EXPECT_EQ(UN(NtQueryInstallUILanguage)(NULL), ST_AV);
}

TEST(sys_interval_profile)
{
    ULONG v = 0; NTSTATUS s;
    REQUIRE(UN(NtQueryIntervalProfile));
    s = UN(NtQueryIntervalProfile)(0, &v);          /* ProfileTime */
    t_note("NtQueryIntervalProfile(0) = %08lx interval %lu", (unsigned long)s, v);
    EXPECT_EQ(s, 0);
    CHECK(v > 0);
    v = 0; s = UN(NtQueryIntervalProfile)(1, &v);   /* ProfileAlignmentFixup */
    t_note("NtQueryIntervalProfile(1) = %08lx interval %lu", (unsigned long)s, v);
    s = UN(NtQueryIntervalProfile)(0x1000, &v);
    t_note("NtQueryIntervalProfile(0x1000) = %08lx", (unsigned long)s);
    EXPECT_EQ(UN(NtQueryIntervalProfile)(0, NULL), ST_AV);
}

TEST(sys_debug_filter)
{
    NTSTATUS s;
    REQUIRE(UN(NtQueryDebugFilterState));
    for (ULONG lvl = 0; lvl < 4; lvl++) {
        s = UN(NtQueryDebugFilterState)(0, lvl);
        t_note("NtQueryDebugFilterState(0,%lu) = %08lx", lvl, (unsigned long)s);
        CHECK(s == 0 || s == 1);   /* DbgPrint filter: not-enabled / enabled, no error */
    }
    s = UN(NtQueryDebugFilterState)(0xFFFFFFFF, 0);
    t_note("NtQueryDebugFilterState(-1,0) = %08lx", (unsigned long)s);
    s = UN(NtQueryDebugFilterState)(0, 32);
    t_note("NtQueryDebugFilterState(0,32) = %08lx", (unsigned long)s);
}

TEST(sys_aux_counter)
{
    ULONGLONG v = 0xcc; NTSTATUS s;
    REQUIRE(UN(NtQueryAuxiliaryCounterFrequency));
    s = UN(NtQueryAuxiliaryCounterFrequency)(&v);
    t_note("NtQueryAuxiliaryCounterFrequency = %08lx value %llu", (unsigned long)s, v);
    CHECK(s == 0 || (s & 0xC0000000) == 0xC0000000);
    if (s == 0) CHECK(v != 0 && v != 0xcc);
    s = UN(NtQueryAuxiliaryCounterFrequency)(NULL);
    t_note("NtQueryAuxiliaryCounterFrequency(NULL) = %08lx", (unsigned long)s);
}

TEST(sys_sysinfoex)
{
    ULONG ret = 0, rel = 0, want; NTSTATUS s; BYTE *buf; DWORD len = 0;
    REQUIRE(UN(NtQuerySystemInformationEx));
    /* SystemLogicalProcessorInformationEx = 107, input = LOGICAL_PROCESSOR_RELATIONSHIP */
    s = UN(NtQuerySystemInformationEx)(107, &rel, sizeof rel, NULL, 0, &ret);
    t_note("SysInfoEx(107) probe = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    CHECK(ret >= 32);
    want = ret;
    buf = HeapAlloc(GetProcessHeap(), 0, want + 64);
    memset(buf, 0xcc, want + 64);
    ret = 0;
    s = UN(NtQuerySystemInformationEx)(107, &rel, sizeof rel, buf, want, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, want);
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    EXPECT_EQ(len, want);
    if (s == 0 && want >= 8) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *p = (void *)buf;
        EXPECT_EQ(p->Relationship, RelationProcessorCore);
        EXPECT_EQ(p->Size, ((SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)buf)->Size);
        CHECK(p->Size >= 32 && p->Size <= want);
    }
    CHECK(buf[want] == 0xcc);               /* no write past the reported length */
    s = UN(NtQuerySystemInformationEx)(107, &rel, sizeof rel, buf, 4, &ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    EXPECT_EQ(ret, want);
    s = UN(NtQuerySystemInformationEx)(107, &rel, 0, buf, want, &ret);
    t_note("SysInfoEx(107, inlen 0) = %08lx", (unsigned long)s);
    EXPECT_EQ(s, ST_INV_PARM);
    s = UN(NtQuerySystemInformationEx)(0x7777, &rel, sizeof rel, buf, want, &ret);
    EXPECT_EQ(s, ST_INV_CLASS);
    /* non-Ex class through the Ex entry: basic information */
    { SYSTEM_BASIC_INFORMATION bi; memset(&bi, 0, sizeof bi);
      s = UN(NtQuerySystemInformationEx)(0, NULL, 0, &bi, sizeof bi, &ret);
      t_note("SysInfoEx(Basic) = %08lx ret %lu", (unsigned long)s, ret);
      if (s == 0) { EXPECT_EQ(ret, sizeof bi); CHECK(bi.NumberOfProcessors > 0); } }
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(sys_license)
{
    UNICODE_STRING n; ULONG type = 0xcc, res = 0xcc, data = 0; NTSTATUS s;
    REQUIRE(UN(NtQueryLicenseValue)); REQUIRE(UN(RtlInitUnicodeString));
    UN(RtlInitUnicodeString)(&n, L"Kernel-ProductInfo");
    s = UN(NtQueryLicenseValue)(&n, &type, &data, sizeof data, &res);
    t_note("NtQueryLicenseValue(Kernel-ProductInfo) = %08lx type %lu res %lu data %lu", (unsigned long)s, type, res, data);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(type, REG_DWORD);
    EXPECT_EQ(res, 4);
    CHECK(data != 0);
    /* too-small buffer still reports the size */
    type = 0xcc; res = 0xcc;
    s = UN(NtQueryLicenseValue)(&n, &type, &data, 2, &res);
    t_note("small buffer = %08lx res %lu", (unsigned long)s, res);
    EXPECT_EQ(s, ST_TOO_SMALL);
    EXPECT_EQ(res, 4);
    /* size query: NULL buffer, zero length */
    res = 0xcc;
    s = UN(NtQueryLicenseValue)(&n, &type, NULL, 0, &res);
    t_note("size query = %08lx res %lu", (unsigned long)s, res);
    EXPECT_EQ(res, 4);
    UN(RtlInitUnicodeString)(&n, L"No-Such-License-Value-Zz");
    res = 0xcc;
    s = UN(NtQueryLicenseValue)(&n, &type, &data, sizeof data, &res);
    t_note("missing = %08lx", (unsigned long)s);
    EXPECT_EQ(s, ST_NOT_FOUND);
    s = UN(NtQueryLicenseValue)(NULL, &type, &data, sizeof data, &res);
    t_note("NULL name = %08lx", (unsigned long)s);
    CHECK((s & 0xC0000000) == 0xC0000000);
    UN(RtlInitUnicodeString)(&n, L"");
    s = UN(NtQueryLicenseValue)(&n, &type, &data, sizeof data, &res);
    t_note("empty name = %08lx", (unsigned long)s);
    CHECK((s & 0xC0000000) == 0xC0000000);
}

TEST(sys_port_info_process)
{
    NTSTATUS s;
    REQUIRE(UN(NtQueryPortInformationProcess));
    s = UN(NtQueryPortInformationProcess)();
    t_note("NtQueryPortInformationProcess = %08lx", (unsigned long)s);
    CHECK(s == 0 || s == 1 || s == (NTSTATUS)0xC0000001 || s == (NTSTATUS)0xC00000BB);
}

/* ---- firmware queries ------------------------------------------------- */

static BOOLEAN priv_on(void)
{
    BOOLEAN was = 0;
    if (!UN(RtlAdjustPrivilege)) return 0;
    return UN(RtlAdjustPrivilege)(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &was) == 0;
}

/* without the privilege enabled every firmware query is refused first */
TEST(sys_firmware_no_privilege)
{
    ULONG ids[8], cnt = 8, len = 64; BYTE opt[64]; UNICODE_STRING n; WCHAR out[8]; USHORT rl = 0; GUID g = {0}; ULONG vl = 16, at = 0; BYTE v[16];
    NTSTATUS s;
    REQUIRE(UN(NtQueryBootEntryOrder)); REQUIRE(UN(NtQueryDriverEntryOrder)); REQUIRE(UN(NtQueryBootOptions));
    REQUIRE(UN(NtQuerySystemEnvironmentValue)); REQUIRE(UN(NtQuerySystemEnvironmentValueEx)); REQUIRE(UN(RtlInitUnicodeString));
    { BOOLEAN was; UN(RtlAdjustPrivilege)(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE, FALSE, &was); }
    /* BIOS-booted systems answer STATUS_NOT_IMPLEMENTED before looking at the token */
    s = UN(NtQueryBootEntryOrder)(ids, &cnt);   CHECKF(s == ST_PRIV || s == ST_NOT_IMPL, "got %08lx", (unsigned long)s);
    cnt = 8;
    s = UN(NtQueryDriverEntryOrder)(ids, &cnt); CHECKF(s == ST_PRIV || s == ST_NOT_IMPL, "got %08lx", (unsigned long)s);
    s = UN(NtQueryBootOptions)(opt, &len);      CHECKF(s == ST_PRIV || s == ST_NOT_IMPL, "got %08lx", (unsigned long)s);
    UN(RtlInitUnicodeString)(&n, L"BootCurrent");
    s = UN(NtQuerySystemEnvironmentValue)(&n, out, sizeof out, &rl); EXPECT_EQ(s, ST_PRIV);
    s = UN(NtQuerySystemEnvironmentValueEx)(&n, &g, v, &vl, &at);    EXPECT_EQ(s, ST_PRIV);
}

/* with the privilege (administrator only) the answer depends on firmware type */
TEST(sys_firmware_privileged)
{
    ULONG ids[16], cnt = 16, len = 64; BYTE opt[64]; UNICODE_STRING n; WCHAR out[16]; USHORT rl = 0; GUID g = {0}; ULONG vl = 16, at = 0; BYTE v[16];
    NTSTATUS s;
    REQUIRE(UN(NtQueryBootEntryOrder)); REQUIRE(UN(NtQueryDriverEntryOrder)); REQUIRE(UN(NtQueryBootOptions));
    REQUIRE(UN(NtQuerySystemEnvironmentValue)); REQUIRE(UN(NtQuerySystemEnvironmentValueEx)); REQUIRE(UN(RtlInitUnicodeString));
    if (!priv_on()) { t_skip("SeSystemEnvironmentPrivilege not held by this token (STATUS_PRIVILEGE_NOT_HELD)"); return; }
    s = UN(NtQueryBootEntryOrder)(ids, &cnt);
    t_note("NtQueryBootEntryOrder = %08lx cnt %lu", (unsigned long)s, cnt);
    CHECK(s == ST_NOT_IMPL || s == 0 || s == ST_TOO_SMALL || s == S(0xC0000225) || s == S(0xC0000034));
    cnt = 16; s = UN(NtQueryDriverEntryOrder)(ids, &cnt);
    t_note("NtQueryDriverEntryOrder = %08lx cnt %lu", (unsigned long)s, cnt);
    CHECK(s != ST_PRIV);
    s = UN(NtQueryBootOptions)(opt, &len);
    t_note("NtQueryBootOptions = %08lx len %lu", (unsigned long)s, len);
    CHECK(s != ST_PRIV);
    UN(RtlInitUnicodeString)(&n, L"NoSuchFirmwareVariableZz");
    s = UN(NtQuerySystemEnvironmentValue)(&n, out, sizeof out, &rl);
    t_note("NtQuerySystemEnvironmentValue = %08lx", (unsigned long)s);
    CHECK(s != ST_PRIV && s != 0);
    s = UN(NtQuerySystemEnvironmentValueEx)(&n, &g, v, &vl, &at);
    t_note("NtQuerySystemEnvironmentValueEx = %08lx", (unsigned long)s);
    CHECK(s != ST_PRIV && s != 0);
}
