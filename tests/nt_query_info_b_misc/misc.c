/* Time, counter, language, license, firmware-variable, driver-order, WNF and port queries:
 * NtQuerySystemTime, NtQueryPerformanceCounter, NtQueryTimerResolution, NtQueryIntervalProfile,
 * NtQueryInstallUILanguage, NtQueryLicenseValue, NtQuerySystemEnvironmentValue(Ex),
 * NtQueryDriverEntryOrder, NtQueryWnfStateData, NtQueryWnfStateNameInformation,
 * NtQueryInformationPort, NtQueryPortInformationProcess. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryPerformanceCounter, (PLARGE_INTEGER, PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryTimerResolution, (PULONG, PULONG, PULONG));
UDECL(NTSTATUS, NtQueryIntervalProfile, (ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInstallUILanguage, (PUSHORT));
UDECL(NTSTATUS, NtQueryLicenseValue, (PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemEnvironmentValue, (PUNICODE_STRING, PWSTR, USHORT, PUSHORT));
UDECL(NTSTATUS, NtQuerySystemEnvironmentValueEx, (PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG));
UDECL(NTSTATUS, NtQueryDriverEntryOrder, (PULONG, PULONG));
UDECL(NTSTATUS, NtQueryWnfStateData, (PVOID, PVOID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtQueryWnfStateNameInformation, (PVOID, ULONG, PVOID, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateWnfStateName, (PVOID, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PVOID));
UDECL(NTSTATUS, NtUpdateWnfStateData, (PVOID, PVOID, ULONG, PVOID, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtDeleteWnfStateName, (PVOID));
UDECL(NTSTATUS, NtQuerySecurityPolicy, (PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtQueryInformationPort, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryPortInformationProcess, (void));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define ST_PRIV         S(0xC0000061)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define CUR_PROC ((HANDLE)(LONG_PTR)-1)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}
TEST(alias_pairs)
{
    static const char *n[] = { "NtQuerySystemTime", "NtQueryPerformanceCounter", "NtQueryTimerResolution", "NtQueryIntervalProfile",
        "NtQueryInstallUILanguage", "NtQueryLicenseValue", "NtQuerySystemEnvironmentValue", "NtQuerySystemEnvironmentValueEx",
        "NtQueryDriverEntryOrder", "NtQuerySecurityPolicy", "NtQueryWnfStateData", "NtQueryWnfStateNameInformation", "NtQueryInformationPort", "NtQueryPortInformationProcess" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

static ULONGLONG ft_now(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

TEST(system_time)
{
    LARGE_INTEGER a, b; ULONGLONG k1, k2;
    REQUIRE(UN(NtQuerySystemTime));
    k1 = ft_now();
    EXPECT_EQ(UN(NtQuerySystemTime)(&a), 0);
    k2 = ft_now();
    CHECK((ULONGLONG)a.QuadPart + 200000 >= k1 && (ULONGLONG)a.QuadPart <= k2 + 200000);   /* within 20 ms of the Win32 clock */
    Sleep(30);
    EXPECT_EQ(UN(NtQuerySystemTime)(&b), 0);
    CHECK(b.QuadPart > a.QuadPart);
    CHECK(b.QuadPart - a.QuadPart < 10 * 10000000LL);
    /* the shared user data time (UTC, 100 ns) agrees */
    { volatile ULONG *k = (volatile ULONG *)0x7FFE0014; ULONGLONG ks = ((ULONGLONG)k[1] << 32) | k[0];
      CHECK(ks + 10 * 10000000ULL > (ULONGLONG)b.QuadPart && ks < (ULONGLONG)b.QuadPart + 10 * 10000000ULL); }
}

TEST(performance_counter)
{
    LARGE_INTEGER c1, c2, f, f2, k;
    REQUIRE(UN(NtQueryPerformanceCounter));
    memset(&f, 0xcc, sizeof f);
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c1, &f), 0);
    CHECK(f.QuadPart >= 1000000); CHECK(c1.QuadPart > 0);
    Sleep(20);
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c2, NULL), 0);
    CHECK(c2.QuadPart > c1.QuadPart);
    { LONGLONG ms = (c2.QuadPart - c1.QuadPart) * 1000 / f.QuadPart; CHECK(ms >= 15 && ms < 2000); }
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c1, &f2), 0);
    EXPECT_EQ(f2.QuadPart, f.QuadPart);
    QueryPerformanceFrequency(&k);
    EXPECT_EQ(k.QuadPart, f.QuadPart);
    QueryPerformanceCounter(&k);
    CHECK(k.QuadPart >= c1.QuadPart && k.QuadPart - c1.QuadPart < f.QuadPart);
}

TEST(timer_resolution)
{
    ULONG mx = 0, mn = 0, cur = 0;
    REQUIRE(UN(NtQueryTimerResolution));
    EXPECT_EQ(UN(NtQueryTimerResolution)(&mx, &mn, &cur), 0);
    t_note("timer resolution max=%lu min=%lu cur=%lu", mx, mn, cur);
    /* "maximum" is the coarsest period, "minimum" the finest: 100 ns units */
    CHECK(mn > 0); CHECK(mx >= mn); CHECK(cur >= mn && cur <= mx);
    CHECK(mn <= 100000 && mx >= 100000 && mx <= 1000000);
    { ULONG a2, b2, c2; EXPECT_EQ(UN(NtQueryTimerResolution)(&a2, &b2, &c2), 0); EXPECT_EQ(a2, mx); EXPECT_EQ(b2, mn); }
}

TEST(interval_profile)
{
    ULONG v = 0xdeadbeef; NTSTATUS st;
    REQUIRE(UN(NtQueryIntervalProfile));
    st = UN(NtQueryIntervalProfile)(0 /* ProfileTime */, &v);
    t_note("interval profile time: %08lx %lu", (unsigned long)st, v);
    EXPECT_EQ(st, 0);
    CHECK(v != 0xdeadbeef && v > 0);
    { ULONG v2 = 0; EXPECT_EQ(UN(NtQueryIntervalProfile)(0, &v2), 0); EXPECT_EQ(v2, v); }
    EXPECT_EQ(UN(NtQueryIntervalProfile)(1 /* ProfileAlignmentFixup */, &v), 0);
    CHECK(v != 0xdeadbeef);
}

TEST(install_ui_language)
{
    USHORT a = 0, b = 0;
    REQUIRE(UN(NtQueryInstallUILanguage));
    EXPECT_EQ(UN(NtQueryInstallUILanguage)(&a), 0);
    t_note("install UI language %04x", a);
    CHECK(a != 0); CHECK((a & 0x3ff) != 0 && (a >> 10) <= 0x3f);
    EXPECT_EQ(UN(NtQueryInstallUILanguage)(&b), 0);
    EXPECT_EQ(a, b);
}

TEST(license_value)
{
    UNICODE_STRING n; ULONG type = 0xdead, res = 0xdead; BYTE buf[64]; NTSTATUS st; static WCHAR none[] = L"QIB-No-Such-License-Value", pi[] = L"Kernel-ProductInfo";
    REQUIRE(UN(NtQueryLicenseValue));
    n.Buffer = none; n.Length = sizeof none - 2; n.MaximumLength = sizeof none;
    EXPECT_EQ(UN(NtQueryLicenseValue)(&n, &type, buf, sizeof buf, &res), ST_NAME_NOT_FOUND);
    n.Buffer = pi; n.Length = sizeof pi - 2; n.MaximumLength = sizeof pi;
    memset(buf, 0xcc, sizeof buf); type = 0xdead; res = 0xdead;
    st = UN(NtQueryLicenseValue)(&n, &type, buf, sizeof buf, &res);
    t_note("Kernel-ProductInfo: %08lx type=%lu res=%lu val=%lu", (unsigned long)st, type, res, *(ULONG *)buf);
    if (st == 0) {
        EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(res, 4);
        { DWORD pt = 0; if (GetProductInfo(10, 0, 0, 0, &pt)) EXPECT_EQ(*(ULONG *)buf, pt); }
        EXPECT_EQ(UN(NtQueryLicenseValue)(&n, &type, buf, 2, &res), S(0xC0000023));   /* STATUS_BUFFER_TOO_SMALL */
        EXPECT_EQ(res, 4);
        EXPECT_EQ(UN(NtQueryLicenseValue)(&n, NULL, buf, sizeof buf, &res), 0);
    } else t_note("license value not present: %08lx", (unsigned long)st);
}

static int is_bios(void)
{
    FIRMWARE_TYPE ft = 0;
    return GetFirmwareType(&ft) && ft == FirmwareTypeBios;
}

TEST(system_environment_value)
{
    UNICODE_STRING n; WCHAR v[64]; USHORT ret = 0; NTSTATUS st; BOOLEAN old = 0; static WCHAR nm[] = L"QibNoSuchVariable";
    GUID g = { 0x8be4df61, 0x93ca, 0x11d2, { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } };   /* EFI global variable GUID */
    BYTE data[64]; ULONG dl = sizeof data, attr = 0;
    REQUIRE(UN(NtQuerySystemEnvironmentValue)); REQUIRE(UN(NtQuerySystemEnvironmentValueEx)); REQUIRE(UN(RtlAdjustPrivilege));
    n.Buffer = nm; n.Length = sizeof nm - 2; n.MaximumLength = sizeof nm;
    st = UN(NtQuerySystemEnvironmentValue)(&n, v, sizeof v, &ret);
    EXPECT_EQ(st, ST_PRIV);            /* SeSystemEnvironmentPrivilege is checked first and is not enabled by default */
    st = UN(NtQuerySystemEnvironmentValueEx)(&n, &g, data, &dl, &attr);
    EXPECT_EQ(st, ST_PRIV);
    if (UN(RtlAdjustPrivilege)(22 /* SeSystemEnvironmentPrivilege */, TRUE, FALSE, &old) != 0) {
        t_skip("SeSystemEnvironmentPrivilege is not held by this token (STATUS_PRIVILEGE_NOT_HELD)");
        return;
    }
    st = UN(NtQuerySystemEnvironmentValue)(&n, v, sizeof v, &ret);
    t_note("env value (priv enabled): %08lx", (unsigned long)st);
    /* BIOS firmware: STATUS_NOT_IMPLEMENTED; UEFI: STATUS_VARIABLE_NOT_FOUND for a variable that does not exist */
    if (is_bios()) EXPECT_EQ(st, S(0xC0000001));          /* observed on legacy BIOS firmware: STATUS_UNSUCCESSFUL */
    else CHECK(st == S(0xC0000001) || st == S(0xC0000002) || st == S(0xC0000100));   /* UEFI: variable-not-found or similar */
    dl = sizeof data;
    st = UN(NtQuerySystemEnvironmentValueEx)(&n, &g, data, &dl, &attr);
    t_note("env value Ex (priv enabled): %08lx", (unsigned long)st);
    if (is_bios()) EXPECT_EQ(st, S(0xC0000002));          /* observed on legacy BIOS firmware: STATUS_NOT_IMPLEMENTED */
    else CHECK(st == S(0xC0000001) || st == S(0xC0000002) || st == S(0xC0000100));
    UN(RtlAdjustPrivilege)(22, old, FALSE, &old);
}

TEST(driver_entry_order)
{
    ULONG ids[64], count; NTSTATUS st; BOOLEAN old;
    REQUIRE(UN(NtQueryDriverEntryOrder)); REQUIRE(UN(RtlAdjustPrivilege));
    /* Firmware boot-entry services: BIOS systems answer STATUS_NOT_IMPLEMENTED, UEFI systems enumerate (privileged). */
    count = 64; memset(ids, 0xcc, sizeof ids);
    st = UN(NtQueryDriverEntryOrder)(ids, &count);
    t_note("driver entry order without privilege: %08lx count=%lu", (unsigned long)st, count);
    if (is_bios()) EXPECT_EQ(st, S(0xC0000002)); else CHECK(st == ST_PRIV || st == 0 || st == S(0xC0000023));
    if (UN(RtlAdjustPrivilege)(10 /* SeLoadDriverPrivilege */, TRUE, FALSE, &old) != 0) { t_skip("SeLoadDriverPrivilege not held (STATUS_PRIVILEGE_NOT_HELD)"); return; }
    count = 64; memset(ids, 0xcc, sizeof ids);
    st = UN(NtQueryDriverEntryOrder)(ids, &count);
    t_note("driver entry order with SeLoadDriverPrivilege: %08lx count=%lu", (unsigned long)st, count);
    if (is_bios()) EXPECT_EQ(st, S(0xC0000002)); else CHECK(st == 0 || st == S(0xC0000023));
    if (st == 0) CHECK(count <= 64);
    UN(RtlAdjustPrivilege)(10, old, FALSE, &old);
}

typedef struct { ULONG a, b; } WNF_NAME;
typedef struct { ULONG Data[2]; } WNF_NAME2;
typedef struct { GUID g; } WNF_TYPE;

TEST(wnf_state)
{
    WNF_NAME name = { 0, 0 }; BYTE sd[64]; NTSTATUS st; ULONG stamp = 0, sz; BYTE buf[64]; int created = 0;
    static const BYTE payload[5] = { 1, 2, 3, 4, 5 };
    REQUIRE(UN(NtQueryWnfStateData)); REQUIRE(UN(NtCreateWnfStateName)); REQUIRE(UN(NtUpdateWnfStateData)); REQUIRE(UN(NtDeleteWnfStateName));
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor));
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, NULL, FALSE);
    st = UN(NtCreateWnfStateName)(&name, 3 /* temporary */, 1 /* session scope */, FALSE, NULL, 0x1000, sd);
    t_note("NtCreateWnfStateName(temporary, session): %08lx name=%08lx:%08lx", (unsigned long)st, name.a, name.b);
    if (st != 0) { t_skip("cannot create a temporary WNF state name: %08lx", (unsigned long)st); return; }
    created = 1;
    sz = sizeof buf; stamp = 0xdead; memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
    t_note("query before publish: %08lx stamp=%lu size=%lu", (unsigned long)st, stamp, sz);
    st = UN(NtUpdateWnfStateData)(&name, (PVOID)payload, sizeof payload, NULL, NULL, 0, 0);
    t_note("update: %08lx", (unsigned long)st);
    if (st == 0) {
        sz = sizeof buf; stamp = 0xdead; memset(buf, 0xcc, sizeof buf);
        EXPECT_EQ(UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz), 0);
        EXPECT_EQ(stamp, 1); EXPECT_EQ(sz, sizeof payload); CHECK(!memcmp(buf, payload, sizeof payload));
        sz = 2; stamp = 0;
        st = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
        EXPECT_EQ(st, S(0xC0000023));          /* STATUS_BUFFER_TOO_SMALL; required size returned */
        EXPECT_EQ(sz, sizeof payload); EXPECT_EQ(stamp, 1);
        EXPECT_EQ(UN(NtUpdateWnfStateData)(&name, (PVOID)payload, 3, NULL, NULL, 0, 0), 0);
        sz = sizeof buf;
        EXPECT_EQ(UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz), 0);
        EXPECT_EQ(stamp, 2); EXPECT_EQ(sz, 3);
        /* name information: existence */
        if (UN(NtQueryWnfStateNameInformation)) {
            ULONG ex = 0xdead;
            st = UN(NtQueryWnfStateNameInformation)(&name, 0 /* WnfInfoStateNameExist */, NULL, &ex, sizeof ex);
            t_note("NameInformation exist: %08lx value=%lu", (unsigned long)st, ex);
            EXPECT_EQ(st, 0); EXPECT_EQ(ex, 1);
            ex = 0xdead;
            st = UN(NtQueryWnfStateNameInformation)(&name, 1 /* WnfInfoSubscribersPresent */, NULL, &ex, sizeof ex);
            t_note("NameInformation subscribers: %08lx value=%lu", (unsigned long)st, ex);
            EXPECT_EQ(st, 0); EXPECT_EQ(ex, 0);
            EXPECT_EQ(UN(NtQueryWnfStateNameInformation)(&name, 0, NULL, &ex, 1), ST_INV_PARAM);
        }
    }
    if (created) UN(NtDeleteWnfStateName)(&name);
    /* a deleted name no longer exists */
    sz = sizeof buf;
    EXPECT_EQ(UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz), ST_NAME_NOT_FOUND);
    if (UN(NtQueryWnfStateNameInformation)) {
        ULONG ex = 0xdead; NTSTATUS s2 = UN(NtQueryWnfStateNameInformation)(&name, 0, NULL, &ex, sizeof ex);
        EXPECT_EQ(s2, 0); EXPECT_EQ(ex, 0);
    }
}

TEST(wnf_invalid_arguments)
{
    WNF_NAME bogus = { 0x41C64E6D, 0x1234567 }; ULONG stamp, sz = 16; BYTE buf[16]; ULONG ex = 0xdead;
    REQUIRE(UN(NtQueryWnfStateData));
    EXPECT_EQ(UN(NtQueryWnfStateData)(&bogus, NULL, NULL, &stamp, buf, &sz), ST_INV_PARAM);
    if (UN(NtQueryWnfStateNameInformation)) {
        EXPECT_EQ(UN(NtQueryWnfStateNameInformation)(&bogus, 0, NULL, &ex, sizeof ex), ST_INV_PARAM);
        EXPECT_EQ(UN(NtQueryWnfStateNameInformation)(&bogus, 0x77, NULL, &ex, sizeof ex), ST_INV_PARAM);
    }
}

TEST(port_queries)
{
    NTSTATUS a, b; BYTE buf[64]; ULONG ret;
    REQUIRE(UN(NtQueryPortInformationProcess));
    a = UN(NtQueryPortInformationProcess)();
    b = UN(NtQueryPortInformationProcess)();
    t_note("NtQueryPortInformationProcess: %08lx", (unsigned long)a);
    EXPECT_EQ(a, b);
    CHECK(a == 0 || a == 1);   /* boolean-style result */
    REQUIRE(UN(NtQueryInformationPort));
    EXPECT_EQ(UN(NtQueryInformationPort)(NULL, 0, buf, sizeof buf, &ret), S(0xC0000003));   /* class 0 is not accepted: checked before the handle */
    EXPECT_EQ(UN(NtQueryInformationPort)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    { ULONG c; for (c = 1; c <= 4; c++) EXPECT_EQ(UN(NtQueryInformationPort)(NULL, c, buf, sizeof buf, &ret), S(0xC0000003)); }
    EXPECT_EQ(UN(NtQueryInformationPort)(CUR_PROC, 0, buf, sizeof buf, &ret), ST_TYPE_MISM);
}

TEST(security_policy)
{
    UNICODE_STRING owner, sub, val; static WCHAR o[] = L"QibNoSuchOwner", k[] = L"SubKey", v[] = L"Value"; ULONG type = 0xdead, size = 64; BYTE buf[64]; NTSTATUS st;
    REQUIRE(UN(NtQuerySecurityPolicy));
    owner.Buffer = o; owner.Length = sizeof o - 2; owner.MaximumLength = sizeof o;
    sub.Buffer = k; sub.Length = sizeof k - 2; sub.MaximumLength = sizeof k;
    val.Buffer = v; val.Length = sizeof v - 2; val.MaximumLength = sizeof v;
    st = UN(NtQuerySecurityPolicy)(&owner, &sub, &val, &type, buf, &size);
    EXPECT_EQ(st, S(0xC0000225));          /* STATUS_NOT_FOUND */
    EXPECT_EQ(type, 0xdead);
    st = UN(NtQuerySecurityPolicy)(&owner, &sub, &val, &type, NULL, &size);
    EXPECT_EQ(st, S(0xC0000225));
}
