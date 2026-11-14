/* Zw-named system services that are privilege gated, stubbed or version dependent:
 * shutdown (argument validation only), boot serialization, VDM, UMS, file path translation,
 * profiling objects, partition replacement, driver unload, debug control, registry/transaction thaw,
 * protocol address registration and WNF subscriptions. */
#include "t.h"

UDECL(NTSTATUS, ZwShutdownSystem, (ULONG));
UDECL(NTSTATUS, ZwSerializeBoot, (VOID));
UDECL(NTSTATUS, ZwVdmControl, (ULONG, PVOID));
UDECL(NTSTATUS, ZwUmsThreadYield, (PVOID));
UDECL(NTSTATUS, ZwTranslateFilePath, (PVOID, ULONG, PVOID, PULONG));
UDECL(NTSTATUS, ZwStartProfile, (HANDLE));
UDECL(NTSTATUS, ZwStopProfile, (HANDLE));
UDECL(NTSTATUS, ZwReplacePartitionUnit, (PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, ZwUnloadDriver, (PUNICODE_STRING));
UDECL(NTSTATUS, ZwSystemDebugControl, (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwThawRegistry, (VOID));
UDECL(NTSTATUS, ZwThawTransactions, (VOID));
UDECL(NTSTATUS, ZwRegisterProtocolAddressInformation, (HANDLE, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwSubscribeWnfStateChange, (PVOID, ULONG, ULONG, PULONGLONG));
UDECL(NTSTATUS, ZwUnsubscribeWnfStateChange, (PVOID));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define NOT_IMPL S(0xc0000002)
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define DENIED S(0xc0000022)
#define WRONG_TYPE S(0xc0000024)
#define NO_PRIV S(0xc0000061)

#define SE_TCB 7
#define SE_LOAD_DRIVER 10
#define SE_BACKUP 17
#define SE_SHUTDOWN 19
#define SE_DEBUG 20

/* Enable a privilege in the process token; returns the RtlAdjustPrivilege status and the previous state. */
static NTSTATUS priv_on(ULONG p, BOOLEAN *was)
{
    BOOLEAN w = 0; NTSTATUS s;
    if (!UN(RtlAdjustPrivilege)) return NOT_IMPL;
    s = UN(RtlAdjustPrivilege)(p, TRUE, FALSE, &w);
    if (was) *was = w;
    return s;
}
static void priv_restore(ULONG p, NTSTATUS s, BOOLEAN was)
{
    BOOLEAN w;
    if (s >= 0 && !was) UN(RtlAdjustPrivilege)(p, FALSE, FALSE, &w);
}

TEST(zw_misc_aliases)
{
    static const char *names[] = { "ShutdownSystem", "SerializeBoot", "VdmControl", "UmsThreadYield", "TranslateFilePath",
        "StartProfile", "StopProfile", "ReplacePartitionUnit", "UnloadDriver", "SystemDebugControl", "ThawRegistry",
        "ThawTransactions", "RegisterProtocolAddressInformation", "SubscribeWnfStateChange", "UnsubscribeWnfStateChange" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[80], zw[80];
        FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

TEST(zw_shutdown_system_invalid_action)
{
    REQUIRE(UN(ZwShutdownSystem));
    /* Only out-of-range actions are exercised: valid actions would power-cycle the machine.
       Action values above 3 are rejected before any privilege check. */
    EXPECT_EQ(UN(ZwShutdownSystem)(4), BAD_PARAM);
    EXPECT_EQ(UN(ZwShutdownSystem)(0x100), BAD_PARAM);
    EXPECT_EQ(UN(ZwShutdownSystem)(0xffffffff), BAD_PARAM);
}

static int token_has_privilege(ULONG p)
{
    /* RtlAdjustPrivilege reports STATUS_PRIVILEGE_NOT_HELD when the token lacks the privilege entirely. */
    BOOLEAN was = 0; NTSTATUS s = priv_on(p, &was);
    if (s >= 0 && !was) { BOOLEAN w; UN(RtlAdjustPrivilege)(p, FALSE, FALSE, &w); }
    return s >= 0;
}

TEST(zw_serialize_boot)
{
    NTSTATUS s;
    REQUIRE(UN(ZwSerializeBoot)); REQUIRE(UN(RtlAdjustPrivilege));
    /* With SeTcbPrivilege the call would act on the boot configuration; only run it without that privilege. */
    if (token_has_privilege(SE_TCB)) { t_skip("token holds SeTcbPrivilege; the call would serialize boot"); return; }
    s = UN(ZwSerializeBoot)();
    t_note("ZwSerializeBoot without SeTcbPrivilege: %08lx", (ULONG)s);
    EXPECT_EQ(s, NO_PRIV);
}

TEST(zw_vdm_control)
{
    char buf[16] = {0};
    REQUIRE(UN(ZwVdmControl));
    EXPECT_EQ(UN(ZwVdmControl)(0, NULL), NOT_IMPL);
    EXPECT_EQ(UN(ZwVdmControl)(0, buf), NOT_IMPL);
    EXPECT_EQ(UN(ZwVdmControl)(0x1234, buf), NOT_IMPL);
}

TEST(zw_ums_thread_yield)
{
    REQUIRE(UN(ZwUmsThreadYield));
    /* the calling thread is not a user-mode-scheduled thread */
    EXPECT_EQ(UN(ZwUmsThreadYield)(NULL), S(0xc00000bb)); /* STATUS_NOT_SUPPORTED */
    EXPECT_EQ(UN(ZwUmsThreadYield)((PVOID)(ULONG_PTR)0x1000), S(0xc00000bb));
}

TEST(zw_translate_file_path)
{
    BYTE in[64]; ULONG outlen = 0; FIRMWARE_TYPE ft = 0; NTSTATUS s;
    REQUIRE(UN(ZwTranslateFilePath));
    memset(in, 0, sizeof in);
    /* FILE_PATH { ULONG Version; ULONG Length; ULONG Type; UCHAR FilePath[1]; } */
    ((ULONG *)in)[0] = 1; ((ULONG *)in)[1] = 12; ((ULONG *)in)[2] = 1;
    s = UN(ZwTranslateFilePath)(in, 1, NULL, &outlen);
    if (!GetFirmwareType(&ft)) { t_skip("firmware type unavailable"); return; }
    if (ft == FirmwareTypeUefi) {
        t_note("UEFI firmware: ZwTranslateFilePath(valid type) = %08lx", (ULONG)s);
        EXPECT_EQ(UN(ZwTranslateFilePath)(in, 0, NULL, &outlen), BAD_PARAM);   /* output type 0 invalid */
        EXPECT_EQ(UN(ZwTranslateFilePath)(in, 6, NULL, &outlen), BAD_PARAM);   /* output type above 5 invalid */
    } else {
        /* legacy BIOS boot: the service is not implemented, whatever the arguments */
        EXPECT_EQ(s, NOT_IMPL);
        EXPECT_EQ(UN(ZwTranslateFilePath)(in, 0, NULL, &outlen), NOT_IMPL);
        EXPECT_EQ(UN(ZwTranslateFilePath)(NULL, 1, NULL, NULL), NOT_IMPL);
    }
}

TEST(zw_profile_objects_errors)
{
    HANDLE ev = NULL;
    REQUIRE(UN(ZwStartProfile)); REQUIRE(UN(ZwStopProfile)); REQUIRE(UN(NtCreateEvent));
    EXPECT_EQ(UN(ZwStartProfile)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwStopProfile)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwStartProfile)((HANDLE)(ULONG_PTR)0x7ffffff4), BAD_HANDLE);
    EXPECT_EQ(UN(ZwStopProfile)((HANDLE)(ULONG_PTR)0x7ffffff4), BAD_HANDLE);
    EXPECT_EQ(UN(ZwStartProfile)(GetCurrentProcess()), WRONG_TYPE);
    EXPECT_EQ(UN(ZwStopProfile)(GetCurrentProcess()), WRONG_TYPE);
    if (UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) >= 0) {
        EXPECT_EQ(UN(ZwStartProfile)(ev), WRONG_TYPE);
        EXPECT_EQ(UN(ZwStopProfile)(ev), WRONG_TYPE);
        UN(NtClose)(ev);
    }
}

TEST(zw_replace_partition_unit)
{
    UNICODE_STRING a, b; NTSTATUS s, ps; BOOLEAN was = 0; static WCHAR n1[] = L"\\Device\\NoSuchPartitionA", n2[] = L"\\Device\\NoSuchPartitionB";
    REQUIRE(UN(ZwReplacePartitionUnit));
    a.Buffer = n1; a.Length = sizeof n1 - 2; a.MaximumLength = sizeof n1;
    b.Buffer = n2; b.Length = sizeof n2 - 2; b.MaximumLength = sizeof n2;
    /* SeShutdownPrivilege must be enabled for the request to be examined at all */
    ps = priv_on(SE_SHUTDOWN, &was);
    if (ps >= 0 && was) { /* privilege was already enabled: still valid for the flags check below */ }
    if (ps < 0) {
        EXPECT_EQ(ps, NO_PRIV);
        EXPECT_EQ(UN(ZwReplacePartitionUnit)(&a, &b, 0), NO_PRIV);
        t_skip("SeShutdownPrivilege absent from the token (standard user)");
        return;
    }
    /* an undefined Flags value is rejected as parameter 3 before the names are touched */
    s = UN(ZwReplacePartitionUnit)(&a, &b, 1);
    EXPECT_EQ(s, S(0xc00000f1)); /* STATUS_INVALID_PARAMETER_3 */
    s = UN(ZwReplacePartitionUnit)(&a, &b, 0x7fffffff);
    EXPECT_EQ(s, S(0xc00000f1));
    priv_restore(SE_SHUTDOWN, ps, was);
    /* with the privilege disabled again the privilege check wins */
    if (!was) EXPECT_EQ(UN(ZwReplacePartitionUnit)(&a, &b, 1), NO_PRIV);
}

TEST(zw_unload_driver)
{
    UNICODE_STRING us; NTSTATUS s, ps; BOOLEAN was = 0;
    static WCHAR svc[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ntdllt_no_such_driver_service";
    REQUIRE(UN(ZwUnloadDriver));
    us.Buffer = svc; us.Length = sizeof svc - 2; us.MaximumLength = sizeof svc;
    ps = priv_on(SE_LOAD_DRIVER, &was);
    if (ps < 0) {
        EXPECT_EQ(ps, NO_PRIV);
        EXPECT_EQ(UN(ZwUnloadDriver)(&us), NO_PRIV);
        t_skip("SeLoadDriverPrivilege absent from the token (standard user)");
        return;
    }
    s = UN(ZwUnloadDriver)(&us);
    EXPECT_EQ(s, S(0xc0000034)); /* STATUS_OBJECT_NAME_NOT_FOUND: no such service key */
    priv_restore(SE_LOAD_DRIVER, ps, was);
    if (!was) EXPECT_EQ(UN(ZwUnloadDriver)(&us), NO_PRIV);
}

TEST(zw_system_debug_control)
{
    NTSTATUS s; ULONG ret = 0; BYTE out[16];
    REQUIRE(UN(ZwSystemDebugControl));
    /* With no kernel debugger on the system the service fails before looking at the command (this is the
       state of a normal boot; any other state is skipped). */
    s = UN(ZwSystemDebugControl)(0x7fff, NULL, 0, NULL, 0, NULL);
    t_note("ZwSystemDebugControl(0x7fff) = %08lx", (ULONG)s);
    if (s != S(0xc0000354)) { t_skip("kernel debugger state differs from a normal boot (status %08lx)", (ULONG)s); return; }
    /* STATUS_DEBUGGER_INACTIVE: no kernel debugger is attached, whatever the command or the token */
    ret = 0x55;
    EXPECT_EQ(UN(ZwSystemDebugControl)(0x7fff, NULL, 0, out, sizeof out, &ret), S(0xc0000354));
    EXPECT_EQ(UN(ZwSystemDebugControl)(0, NULL, 0, NULL, 0, NULL), S(0xc0000354));
    EXPECT_EQ(ret, 0x55);
}

TEST(zw_thaw_registry)
{
    NTSTATUS s, ps; BOOLEAN was = 0;
    REQUIRE(UN(ZwThawRegistry));
    ps = priv_on(SE_BACKUP, &was);
    if (ps < 0) {
        EXPECT_EQ(ps, NO_PRIV);
        EXPECT_EQ(UN(ZwThawRegistry)(), NO_PRIV);
        t_skip("SeBackupPrivilege absent from the token (standard user)");
        return;
    }
    s = UN(ZwThawRegistry)();
    EXPECT_EQ(s, S(0xc0000189)); /* observed: registry is not frozen */
    EXPECT_EQ(UN(ZwThawRegistry)(), S(0xc0000189));
    priv_restore(SE_BACKUP, ps, was);
    if (!was) EXPECT_EQ(UN(ZwThawRegistry)(), NO_PRIV);
}

TEST(zw_thaw_transactions)
{
    NTSTATUS s;
    REQUIRE(UN(ZwThawTransactions));
    /* needs a privilege that is not enabled in a default token (standard user or elevated administrator) */
    s = UN(ZwThawTransactions)();
    EXPECT_EQ(s, NO_PRIV);
}

TEST(zw_register_protocol_address_information)
{
    NTSTATUS s;
    REQUIRE(UN(ZwRegisterProtocolAddressInformation));
    BYTE proto[16] = {0}, info[16] = {0};
    s = UN(ZwRegisterProtocolAddressInformation)(NULL, proto, sizeof info, info, 0);
    EXPECT_EQ(s, BAD_HANDLE);
    s = UN(ZwRegisterProtocolAddressInformation)((HANDLE)(ULONG_PTR)0x7ffffff4, proto, sizeof info, info, 0);
    EXPECT_EQ(s, BAD_HANDLE);
    { HANDLE ev = NULL;
      if (UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) >= 0) {
          EXPECT_EQ(UN(ZwRegisterProtocolAddressInformation)(ev, proto, sizeof info, info, 0), WRONG_TYPE);
          UN(NtClose)(ev); } }
}

TEST(zw_wnf_subscription)
{
    /* A state name that is never subscribed to by this process. */
    ULONGLONG name = 0x0d83063ea3bf1c75ULL, id = 0x55; NTSTATUS s;
    REQUIRE(UN(ZwSubscribeWnfStateChange)); REQUIRE(UN(ZwUnsubscribeWnfStateChange));
    s = UN(ZwUnsubscribeWnfStateChange)(&name);
    EXPECT_EQ(s, S(0xc0000034)); /* nothing subscribed under this name */
    s = UN(ZwSubscribeWnfStateChange)(&name, 0, 0, &id);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        CHECK(id != 0x55);       /* subscription id written */
        EXPECT_EQ(UN(ZwUnsubscribeWnfStateChange)(&name), 0);
        EXPECT_EQ(UN(ZwUnsubscribeWnfStateChange)(&name), S(0xc0000034));
    }
}
