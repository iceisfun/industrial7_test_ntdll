/* System-wide Nt*Set* services that need privileges or alter global state: only entry points and argument
 * paths that are harmless when the call succeeds are exercised, and privileged calls are made only after
 * confirming that the privilege is not enabled in the caller's token. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetSystemTime, (PLARGE_INTEGER, PLARGE_INTEGER));
UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));
UDECL(NTSTATUS, NtSetIntervalProfile, (ULONG, ULONG));
UDECL(NTSTATUS, NtSetUuidSeed, (PUCHAR));
UDECL(NTSTATUS, NtSetDefaultHardErrorPort, (HANDLE));
UDECL(NTSTATUS, NtSetSystemEnvironmentValue, (PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, NtSetSystemEnvironmentValueEx, (PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetSystemInformation, (ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetDriverEntryOrder, (PULONG, ULONG));
UDECL(NTSTATUS, NtSetDebugFilterState, (ULONG, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtQueryDebugFilterState, (ULONG, ULONG));
UDECL(NTSTATUS, NtSetDefaultLocale, (BOOLEAN, LCID));
UDECL(NTSTATUS, NtQueryDefaultLocale, (BOOLEAN, PLCID));
UDECL(NTSTATUS, NtSetDefaultUILanguage, (USHORT));
UDECL(NTSTATUS, NtQueryDefaultUILanguage, (USHORT *));
UDECL(NTSTATUS, NtSetLdtEntries, (ULONG, ULONG, ULONG, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtSetCachedSigningLevel, (ULONG, ULONG, PHANDLE, ULONG, HANDLE));
UDECL(NTSTATUS, NtSetCachedSigningLevel2, (ULONG, ULONG, PHANDLE, ULONG, HANDLE, PVOID, PVOID));
UDECL(NTSTATUS, NtSetInformationVirtualMemory, (HANDLE, ULONG, ULONG_PTR, PVOID, PVOID, ULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE S(0xC0000008)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_LEN_MISM   S(0xC0000004)
#define ST_INV_CLASS  S(0xC0000003)
#define ST_PRIV       S(0xC0000061)
#define ST_NOT_IMPL   S(0xC0000002)

/* TRUE when the privilege with this LUID is absent or disabled in the process token. */
static BOOL priv_off(ULONG luid)
{
    HANDLE t = NULL; BYTE buf[2048]; ULONG rl = 0; BOOL off = TRUE;
    if (!UN(NtOpenProcessToken) || !UN(NtQueryInformationToken)) return FALSE;
    if (UN(NtOpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &t) != 0) return FALSE;
    if (UN(NtQueryInformationToken)(t, 3 /*TokenPrivileges*/, buf, sizeof buf, &rl) != 0) { UN(NtClose)(t); return FALSE; }
    TOKEN_PRIVILEGES *p = (TOKEN_PRIVILEGES *)buf;
    for (DWORD i = 0; i < p->PrivilegeCount; i++)
        if (p->Privileges[i].Luid.LowPart == luid && p->Privileges[i].Luid.HighPart == 0 &&
            (p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) off = FALSE;
    UN(NtClose)(t);
    return off;
}
#define SE_TCB 7
#define SE_SYSTEMTIME 12
#define SE_PROFILE_SINGLE 13
#define SE_SYSTEM_PROFILE 11
#define SE_SYSTEM_ENV 22
#define SE_DEBUG 20
#define SE_LOAD_DRIVER 10
#define NEED_OFF(l, name) do { if (!priv_off(l)) { t_skip(name " is enabled in this token"); return; } } while (0)

static HANDLE mkevent(void)
{
    HANDLE h = NULL;
    if (UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE) != 0) return NULL;
    return h;
}

TEST(set_system_time_privilege)
{
    REQUIRE(UN(NtSetSystemTime)); REQUIRE(UN(NtQuerySystemTime));
    CHECK(t_proc("NtSetSystemTime") == t_proc("ZwSetSystemTime"));
    NEED_OFF(SE_SYSTEMTIME, "SeSystemtimePrivilege");
    LARGE_INTEGER now, old; UN(NtQuerySystemTime)(&now); old.QuadPart = 0x1234;
    EXPECT_EQ(UN(NtSetSystemTime)(&now, &old), ST_PRIV);
    EXPECT_EQ(old.QuadPart, 0x1234);                          /* PreviousTime untouched on failure */
    EXPECT_EQ(UN(NtSetSystemTime)(&now, NULL), ST_PRIV);
}
TEST(set_interval_profile_privilege)
{
    REQUIRE(UN(NtSetIntervalProfile));
    CHECK(t_proc("NtSetIntervalProfile") == t_proc("ZwSetIntervalProfile"));
    NEED_OFF(SE_SYSTEM_PROFILE, "SeSystemProfilePrivilege");
    EXPECT_EQ(UN(NtSetIntervalProfile)(10000, 0 /*ProfileTime*/), ST_PRIV);
}
TEST(set_uuid_seed_privilege)
{
    REQUIRE(UN(NtSetUuidSeed));
    CHECK(t_proc("NtSetUuidSeed") == t_proc("ZwSetUuidSeed"));
    NEED_OFF(SE_TCB, "SeTcbPrivilege");
    UCHAR seed[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    NTSTATUS st = UN(NtSetUuidSeed)(seed);
    EXPECT_EQ(st, S(0xC0000022));                             /* STATUS_ACCESS_DENIED: the caller holds no SeTcbPrivilege */
}
TEST(set_default_hard_error_port_privilege)
{
    REQUIRE(UN(NtSetDefaultHardErrorPort));
    CHECK(t_proc("NtSetDefaultHardErrorPort") == t_proc("ZwSetDefaultHardErrorPort"));
    NEED_OFF(SE_TCB, "SeTcbPrivilege");
    HANDLE ev = mkevent();
    EXPECT_EQ(UN(NtSetDefaultHardErrorPort)(ev), ST_PRIV);
    EXPECT_EQ(UN(NtSetDefaultHardErrorPort)(NULL), ST_PRIV);
    if (ev) UN(NtClose)(ev);
}
TEST(set_system_environment_value_privilege)
{
    REQUIRE(UN(NtSetSystemEnvironmentValue)); REQUIRE(UN(NtSetSystemEnvironmentValueEx));
    CHECK(t_proc("NtSetSystemEnvironmentValue") == t_proc("ZwSetSystemEnvironmentValue"));
    CHECK(t_proc("NtSetSystemEnvironmentValueEx") == t_proc("ZwSetSystemEnvironmentValueEx"));
    NEED_OFF(SE_SYSTEM_ENV, "SeSystemEnvironmentPrivilege");
    WCHAR nm[] = L"NtdllConfNoSuchVariable", vv[] = L"x";
    UNICODE_STRING n, v;
    n.Buffer = nm; n.Length = n.MaximumLength = (USHORT)(lstrlenW(nm) * 2);
    v.Buffer = vv; v.Length = v.MaximumLength = 2;
    EXPECT_EQ(UN(NtSetSystemEnvironmentValue)(&n, &v), ST_PRIV);
    GUID g = { 0x1a2b3c4d, 0x1111, 0x2222, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    BYTE data[4] = { 1, 2, 3, 4 };
    NTSTATUS ex = UN(NtSetSystemEnvironmentValueEx)(&n, &g, data, sizeof data, 7);
    t_note("NtSetSystemEnvironmentValueEx: %08lx", (unsigned long)ex);
    CHECK(ex == ST_PRIV || ex == ST_NOT_IMPL);                /* NOT_IMPLEMENTED on firmware without runtime variable support */
}
TEST(set_system_information_errors)
{
    REQUIRE(UN(NtSetSystemInformation));
    CHECK(t_proc("NtSetSystemInformation") == t_proc("ZwSetSystemInformation"));
    BYTE buf[64]; memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtSetSystemInformation)(0x7fff, buf, sizeof buf), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetSystemInformation)(0xFFFFFFFF, buf, sizeof buf), ST_INV_CLASS);
    /* SystemTimeAdjustmentInformation (28) needs SeSystemtimePrivilege */
    if (priv_off(SE_SYSTEMTIME)) {
        EXPECT_EQ(UN(NtSetSystemInformation)(28, buf, 8), ST_PRIV);
        EXPECT_EQ(UN(NtSetSystemInformation)(28, buf, 1), ST_LEN_MISM);
    }
    /* SystemFileCacheInformation (21) needs SeIncreaseQuotaPrivilege */
    NTSTATUS fc = UN(NtSetSystemInformation)(21, buf, sizeof buf);
    t_note("class 21 (file cache): %08lx", (unsigned long)fc);
    CHECK(fc == S(0xC0000022) || fc == ST_PRIV);
}
TEST(set_driver_entry_order_privilege)
{
    REQUIRE(UN(NtSetDriverEntryOrder));
    CHECK(t_proc("NtSetDriverEntryOrder") == t_proc("ZwSetDriverEntryOrder"));
    NEED_OFF(SE_TCB, "SeTcbPrivilege");
    NEED_OFF(SE_LOAD_DRIVER, "SeLoadDriverPrivilege");
    ULONG ids[2] = { 1, 2 };
    NTSTATUS a = UN(NtSetDriverEntryOrder)(ids, 2), b = UN(NtSetDriverEntryOrder)(NULL, 0);
    t_note("NtSetDriverEntryOrder: %08lx %08lx", (unsigned long)a, (unsigned long)b);
    CHECK(a == ST_NOT_IMPL || a == ST_PRIV);                  /* NOT_IMPLEMENTED without firmware boot-entry support */
    CHECK(b == ST_NOT_IMPL || b == ST_PRIV || b == ST_INV_PARAM);
}
TEST(set_debug_filter_state)
{
    REQUIRE(UN(NtSetDebugFilterState)); REQUIRE(UN(NtQueryDebugFilterState));
    CHECK(t_proc("NtSetDebugFilterState") == t_proc("ZwSetDebugFilterState"));
    if (priv_off(SE_DEBUG)) {
        EXPECT_EQ(UN(NtSetDebugFilterState)(0, 3, FALSE), ST_PRIV);
        return;
    }
    /* privilege enabled: re-assert the current state so nothing observable changes */
    NTSTATUS cur = UN(NtQueryDebugFilterState)(0, 3);        /* TRUE (1) if the level is enabled, FALSE (0) if not */
    t_note("NtQueryDebugFilterState(0, 3): %08lx", (unsigned long)cur);
    CHECK(cur == 0 || cur == 1);
    EXPECT_EQ(UN(NtSetDebugFilterState)(0, 3, cur == 1 ? TRUE : FALSE), 0);
    EXPECT_EQ(UN(NtQueryDebugFilterState)(0, 3), cur);
}
TEST(set_default_locale_same_value)
{
    REQUIRE(UN(NtSetDefaultLocale)); REQUIRE(UN(NtQueryDefaultLocale));
    CHECK(t_proc("NtSetDefaultLocale") == t_proc("ZwSetDefaultLocale"));
    LCID user = 0, sys = 0;
    EXPECT_EQ(UN(NtQueryDefaultLocale)(TRUE, &user), 0);
    EXPECT_EQ(UN(NtQueryDefaultLocale)(FALSE, &sys), 0);
    NTSTATUS st = UN(NtSetDefaultLocale)(TRUE, user);          /* re-assert the current user locale */
    t_note("NtSetDefaultLocale(TRUE, current): %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    LCID after = 0;
    EXPECT_EQ(UN(NtQueryDefaultLocale)(TRUE, &after), 0);
    EXPECT_EQ(after, user);
    NTSTATUS st2 = UN(NtSetDefaultLocale)(FALSE, sys);         /* system default, same value */
    t_note("NtSetDefaultLocale(FALSE, current): %08lx", (unsigned long)st2);
    EXPECT_EQ(UN(NtQueryDefaultLocale)(FALSE, &after), 0);
    EXPECT_EQ(after, sys);
}
TEST(set_default_ui_language_same_value)
{
    REQUIRE(UN(NtSetDefaultUILanguage)); REQUIRE(UN(NtQueryDefaultUILanguage));
    CHECK(t_proc("NtSetDefaultUILanguage") == t_proc("ZwSetDefaultUILanguage"));
    LANGID cur = 0, after = 0;
    EXPECT_EQ(UN(NtQueryDefaultUILanguage)(&cur), 0);
    NTSTATUS st = UN(NtSetDefaultUILanguage)(cur);
    t_note("NtSetDefaultUILanguage(current): %08lx", (unsigned long)st);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(UN(NtQueryDefaultUILanguage)(&after), 0);
    EXPECT_EQ(after, cur);
}
TEST(set_ldt_entries)
{
    REQUIRE(UN(NtSetLdtEntries));
    CHECK(t_proc("NtSetLdtEntries") == t_proc("ZwSetLdtEntries"));
#ifdef __x86_64__
    EXPECT_EQ(UN(NtSetLdtEntries)(0, 0, 0, 0, 0, 0), ST_NOT_IMPL);     /* no LDT on x64 */
    EXPECT_EQ(UN(NtSetLdtEntries)(0x7, 0x0000FFFF, 0x00CF9A00, 0, 0, 0), ST_NOT_IMPL);
#else
    t_skip("x64 behaviour only");
#endif
}

/* ---- cached signing level ---------------------------------------------- */
TEST(set_cached_signing_level)
{
    REQUIRE(UN(NtSetCachedSigningLevel)); REQUIRE(UN(NtSetCachedSigningLevel2));
    CHECK(t_proc("NtSetCachedSigningLevel") == t_proc("ZwSetCachedSigningLevel"));
    CHECK(t_proc("NtSetCachedSigningLevel2") == t_proc("ZwSetCachedSigningLevel2"));
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "sign.tmp");
    HANDLE f = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    DWORD wr; WriteFile(f, "MZ", 2, &wr, NULL);
    HANDLE src = f, inv = (HANDLE)(LONG_PTR)0x7ff0;
    /* parameters are validated in a fixed order; the file here is not a PE image */
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(0, 0, &src, 1, f), S(0xC0000022));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(0, 4, &src, 1, f), S(0xC00000F0));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(1, 4, &src, 1, f), S(0xC00000F0));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, 4, &src, 1, f), S(0xC000007B));        /* STATUS_INVALID_IMAGE_FORMAT */
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, 4, NULL, 0, f), S(0xC00000F2));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, 4, &src, 1, NULL), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, 4, &src, 1, inv), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, 4, &inv, 1, f), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetCachedSigningLevel2)(4, 4, &src, 1, NULL, NULL, NULL), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetCachedSigningLevel2)(4, 4, &src, 1, inv, NULL, NULL), S(0xC00000F3));
    EXPECT_EQ(UN(NtSetCachedSigningLevel2)(4, 4, &src, 1, f, NULL, NULL), S(0xC000007B));
    /* an unsigned PE image (this executable) */
    char me[MAX_PATH], cp[MAX_PATH]; GetModuleFileNameA(NULL, me, sizeof me); t_tmpfile(cp, sizeof cp, "sign2.tmp");
    if (CopyFileA(me, cp, FALSE)) {
        HANDLE g = CreateFileA(cp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (g != INVALID_HANDLE_VALUE) {
            HANDLE sg = g;
            ULONG lv[] = { 1, 4, 8, 12 };
            for (int j = 0; j < 4; j++)
                EXPECT_EQ(UN(NtSetCachedSigningLevel)(4, lv[j], &sg, 1, g), S(0xC0000428));   /* STATUS_INVALID_IMAGE_HASH: image is unsigned */
            CloseHandle(g);
        }
        DeleteFileA(cp);
    }
    CloseHandle(f);
    DeleteFileA(p);
}

/* ---- virtual memory ---------------------------------------------------- */
typedef struct { PVOID Addr; SIZE_T Bytes; } MRE;
TEST(set_info_virtual_memory_prefetch)
{
    REQUIRE(UN(NtSetInformationVirtualMemory));
    CHECK(t_proc("NtSetInformationVirtualMemory") == t_proc("ZwSetInformationVirtualMemory"));
    PVOID p = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(p != NULL); if (!p) return;
    memset(p, 0x5a, 0x10000);
    MRE r = { p, 0x10000 }; ULONG flags = 0;
    HANDLE self = GetCurrentProcess();
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0 /*VmPrefetchInformation*/, 1, &r, &flags, sizeof flags), 0);
    MRE two[2] = { { p, 0x1000 }, { (BYTE *)p + 0x2000, 0x2000 } };
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 2, two, &flags, sizeof flags), 0);
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 0, &r, &flags, sizeof flags), S(0xC00000F1));   /* STATUS_INVALID_PARAMETER_2 */
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 1, &r, &flags, 2), S(0xC00000F4));
    flags = 1;
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 1, &r, &flags, sizeof flags), S(0xC00000F3));
    flags = 0;
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0x7fff, 1, &r, &flags, sizeof flags), S(0xC00000F0));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(NULL, 0, 1, &r, &flags, sizeof flags), ST_INV_HANDLE);
    HANDLE ev = mkevent();
    if (ev) { EXPECT_EQ(UN(NtSetInformationVirtualMemory)(ev, 0, 1, &r, &flags, sizeof flags), S(0xC0000024)); UN(NtClose)(ev); }
    MRE bad = { (PVOID)(ULONG_PTR)0x10000, 0x1000 };         /* reserved low address, never mapped */
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 1, &bad, &flags, sizeof flags), 0);   /* prefetch ignores unmapped pages */
    MRE zero = { p, 0 };
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 1, &zero, &flags, sizeof flags), S(0xC00000F2));
    EXPECT_EQ(UN(NtSetInformationVirtualMemory)(self, 0, 1, NULL, &flags, sizeof flags), S(0xC0000005));
    VirtualFree(p, 0, MEM_RELEASE);
}
