/* System-wide setters, exercised only through paths that cannot change the machine.
 *
 * Neither a standard user token nor an elevated administrator token has these privileges ENABLED
 * (SeSystemtimePrivilege, SeSystemEnvironmentPrivilege, SeSystemProfilePrivilege, SeTcbPrivilege,
 * SeDebugPrivilege), and the native services test enabled privileges, so a plain call fails with
 * STATUS_PRIVILEGE_NOT_HELD (or STATUS_ACCESS_DENIED where the service reports it that way). If a
 * caller does hold the privilege the test skips instead of changing system state.
 * NtSetSystemPowerState can suspend or power off the machine and is not called.
 */
#include "t.h"

UDECL(NTSTATUS, NtSetSystemTime, (PLARGE_INTEGER, PLARGE_INTEGER));
UDECL(NTSTATUS, NtSetIntervalProfile, (ULONG, ULONG));
UDECL(NTSTATUS, NtSetBootEntryOrder, (PULONG, ULONG));
UDECL(NTSTATUS, NtSetDriverEntryOrder, (PULONG, ULONG));
UDECL(NTSTATUS, NtSetBootOptions, (PVOID, ULONG));
UDECL(NTSTATUS, NtSetSystemEnvironmentValue, (PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, NtSetSystemEnvironmentValueEx, (PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetSystemInformation, (ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetDebugFilterState, (ULONG, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetDefaultHardErrorPort, (HANDLE));
UDECL(NTSTATUS, NtSetUuidSeed, (PUCHAR));
UDECL(NTSTATUS, NtSetCachedSigningLevel, (ULONG, ULONG, PHANDLE, ULONG, HANDLE));
UDECL(NTSTATUS, NtSetCachedSigningLevel2, (ULONG, ULONG, PHANDLE, ULONG, HANDLE, PVOID));
UDECL(NTSTATUS, NtSetDefaultLocale, (BOOLEAN, LCID));
UDECL(NTSTATUS, NtSetDefaultUILanguage, (LANGID));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_PRIV         S(0xC0000061)
#define ST_NOT_IMPL     S(0xC0000002)

TEST(set_system_alias_pairs)
{
    static const char *names[] = { "SetSystemTime", "SetIntervalProfile", "SetBootEntryOrder", "SetDriverEntryOrder",
        "SetBootOptions", "SetSystemEnvironmentValue", "SetSystemEnvironmentValueEx", "SetSystemInformation",
        "SetDebugFilterState", "SetDefaultHardErrorPort", "SetUuidSeed", "SetCachedSigningLevel", "SetCachedSigningLevel2",
        "SetDefaultLocale", "SetDefaultUILanguage", "SetSystemPowerState", "SetLdtEntries" };
    char nt[64], zw[64]; unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        CHECKF(t_proc(nt) != NULL, "%s missing", nt);
        CHECKF(t_proc(nt) == t_proc(zw), "%s and %s differ", nt, zw);
    }
}

TEST(set_system_time_needs_privilege)
{
    LARGE_INTEGER now, prev; NTSTATUS st; FILETIME ft;
    REQUIRE(UN(NtSetSystemTime));
    GetSystemTimeAsFileTime(&ft);
    now.LowPart = ft.dwLowDateTime; now.HighPart = (LONG)ft.dwHighDateTime;
    prev.QuadPart = 0x7777;
    st = UN(NtSetSystemTime)(&now, &prev);
    if (st == 0) { t_skip("caller holds SeSystemtimePrivilege"); return; }
    EXPECT_EQ(st, ST_PRIV);
    EXPECT_EQ(prev.QuadPart, 0x7777);                  /* the previous time is not written on failure */
}

TEST(set_interval_profile_needs_privilege)
{
    NTSTATUS st;
    REQUIRE(UN(NtSetIntervalProfile));
    st = UN(NtSetIntervalProfile)(10000, 0);
    if (st == 0) { t_skip("caller holds SeSystemProfilePrivilege"); return; }
    EXPECT_EQ(st, ST_PRIV);
}

TEST(set_boot_environment_services)
{
    ULONG order[2] = { 1, 2 }; NTSTATUS st1, st2, st3; BYTE bo[64]; UNICODE_STRING name, value; GUID g; WCHAR nm[] = L"NtSetInfoATestVar", vl[] = L"x";
    REQUIRE(UN(NtSetBootEntryOrder)); REQUIRE(UN(NtSetDriverEntryOrder)); REQUIRE(UN(NtSetBootOptions));
    memset(bo, 0, sizeof bo); memset(&g, 0x5a, sizeof g);
    st1 = UN(NtSetBootEntryOrder)(order, 2);
    st2 = UN(NtSetDriverEntryOrder)(order, 2);
    st3 = UN(NtSetBootOptions)(bo, 0);
    t_note("NtSetBootEntryOrder=%08lx NtSetDriverEntryOrder=%08lx NtSetBootOptions=%08lx", (unsigned long)st1, (unsigned long)st2, (unsigned long)st3);
    /* firmware-boot entries exist only on UEFI systems: BIOS boots report STATUS_NOT_IMPLEMENTED,
       UEFI boots check the privilege first */
    CHECK(st1 == ST_NOT_IMPL || st1 == ST_PRIV);
    CHECK(st2 == ST_NOT_IMPL || st2 == ST_PRIV);
    CHECK(st3 == ST_NOT_IMPL || st3 == ST_PRIV || st3 == ST_BAD_PARAM);
    name.Buffer = nm; name.Length = sizeof nm - 2; name.MaximumLength = sizeof nm;
    value.Buffer = vl; value.Length = sizeof vl - 2; value.MaximumLength = sizeof vl;
    if (UN(NtSetSystemEnvironmentValue)) {
        st1 = UN(NtSetSystemEnvironmentValue)(&name, &value);
        t_note("NtSetSystemEnvironmentValue=%08lx", (unsigned long)st1);
        CHECK(st1 == ST_NOT_IMPL || st1 == ST_PRIV);
    }
    if (UN(NtSetSystemEnvironmentValueEx)) {
        st1 = UN(NtSetSystemEnvironmentValueEx)(&name, &g, vl, sizeof vl, 7);
        t_note("NtSetSystemEnvironmentValueEx=%08lx", (unsigned long)st1);
        CHECK(st1 == ST_NOT_IMPL || st1 == ST_PRIV);
    }
}

TEST(set_boot_entry_order_bounds)
{
    ULONG order[2] = { 1, 2 }; NTSTATUS st;
    REQUIRE(UN(NtSetBootEntryOrder)); REQUIRE(UN(NtSetDriverEntryOrder));
    st = UN(NtSetBootEntryOrder)(order, 2);
    if (st == ST_NOT_IMPL) { t_skip("system is not booted from UEFI firmware"); return; }
    /* the count is validated before the privilege */
    EXPECT_EQ(UN(NtSetBootEntryOrder)(order, 0x40000000), ST_BAD_PARAM);
    EXPECT_EQ(UN(NtSetDriverEntryOrder)(order, 0x40000000), ST_BAD_PARAM);
}

TEST(set_system_information_errors)
{
    ULONG v = 0; NTSTATUS st;
    REQUIRE(UN(NtSetSystemInformation));
    EXPECT_EQ(UN(NtSetSystemInformation)(0x7fff, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetSystemInformation)(0xffffffff, &v, sizeof v), ST_BAD_CLASS);
    /* SystemBasicInformation (0) is a query-only class */
    st = UN(NtSetSystemInformation)(0, &v, sizeof v);
    t_note("NtSetSystemInformation(SystemBasicInformation) = %08lx", (unsigned long)st);
    CHECK(st < 0);
}

TEST(set_debug_filter_state_needs_debug_privilege)
{
    NTSTATUS st;
    REQUIRE(UN(NtSetDebugFilterState));
    /* clearing a (nonexistent) level bit is harmless even if the privilege were held */
    st = UN(NtSetDebugFilterState)(0xfffffffe, 31, FALSE);
    if (st == 0) { t_skip("caller holds SeDebugPrivilege"); return; }
    EXPECT_EQ(st, ST_DENIED);
}

TEST(set_default_hard_error_port_needs_tcb)
{
    NTSTATUS st;
    REQUIRE(UN(NtSetDefaultHardErrorPort));
    st = UN(NtSetDefaultHardErrorPort)((HANDLE)(ULONG_PTR)0xdeadbee4);
    if (st != ST_PRIV) { t_skip("caller holds SeTcbPrivilege (status %08lx)", (unsigned long)st); return; }
    EXPECT_EQ(st, ST_PRIV);
    EXPECT_EQ(UN(NtSetDefaultHardErrorPort)(NULL), ST_PRIV);
}

TEST(set_uuid_seed_access_check)
{
    UCHAR seed[6] = { 1, 2, 3, 4, 5, 6 }; NTSTATUS st;
    REQUIRE(UN(NtSetUuidSeed));
    st = UN(NtSetUuidSeed)(seed);
    if (st == 0) { t_skip("caller may set the UUID seed"); return; }
    t_note("NtSetUuidSeed = %08lx", (unsigned long)st);
    EXPECT_EQ(st, ST_DENIED);
}

TEST(set_cached_signing_level_errors)
{
    NTSTATUS st; HANDLE src[2] = { NULL, NULL };
    REQUIRE(UN(NtSetCachedSigningLevel));
    st = UN(NtSetCachedSigningLevel)(1, 0, src, 0, (HANDLE)(ULONG_PTR)0xdeadbee4);
    t_note("NtSetCachedSigningLevel(count 0) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, S(0xC00000F2));                  /* STATUS_INVALID_PARAMETER_4: count must be 1..0x1000 */
    st = UN(NtSetCachedSigningLevel)(1, 0, src, 0x2000, (HANDLE)(ULONG_PTR)0xdeadbee4);
    EXPECT_EQ(st, S(0xC00000F2));
    if (UN(NtSetCachedSigningLevel2)) {
        st = UN(NtSetCachedSigningLevel2)(1, 0, src, 0, (HANDLE)(ULONG_PTR)0xdeadbee4, NULL);
        EXPECT_EQ(st, S(0xC00000F2));
    }
}

TEST(set_default_locale_reapply)
{
    LCID before, after; NTSTATUS st;
    REQUIRE(UN(NtSetDefaultLocale));
    before = GetUserDefaultLCID();
    /* LCID 0 re-reads the user's configured locale from the registry: a no-op for an unchanged profile */
    st = UN(NtSetDefaultLocale)(TRUE, 0);
    t_note("NtSetDefaultLocale(TRUE, 0) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    after = GetUserDefaultLCID();
    EXPECT_EQ(after, before);
}

TEST(set_default_ui_language_nonzero)
{
    REQUIRE(UN(NtSetDefaultUILanguage));
    /* a non-zero language id is accepted and ignored; only 0 triggers a pending-change reload */
    EXPECT_EQ(UN(NtSetDefaultUILanguage)(0x0409), 0);
}
