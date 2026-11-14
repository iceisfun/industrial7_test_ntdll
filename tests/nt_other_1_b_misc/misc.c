/* Handle-validation and privilege-gated paths of ports, transactions, registry, power and audit natives.
 * Only side-effect-free calls are made: invalid handles, wrong object types, missing privileges, malformed arguments. */
#include "t.h"

UDECL(NTSTATUS, NtListenPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtImpersonateClientOfPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtReadRequestData, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtPrepareEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtPrePrepareEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtPrepareComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtPrePrepareComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtPropagationComplete, (HANDLE, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtPropagationFailed, (HANDLE, ULONG, NTSTATUS));
UDECL(NTSTATUS, NtReadOnlyEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtRecoverEnlistment, (HANDLE, PVOID));
UDECL(NTSTATUS, NtRecoverResourceManager, (HANDLE));
UDECL(NTSTATUS, NtGetNotificationResourceManager, (HANDLE, PVOID, ULONG, PLARGE_INTEGER, PULONG, ULONG, ULONG_PTR));
UDECL(NTSTATUS, NtLockRegistryKey, (HANDLE));
UDECL(NTSTATUS, NtGetDevicePowerState, (HANDLE, PULONG));
UDECL(NTSTATUS, NtGetCachedSigningLevel, (HANDLE, PULONG, PULONG, PUCHAR, PULONG, PULONG));
UDECL(NTSTATUS, NtLoadKey, (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtLoadKey2, (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtLoadKeyEx, (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, HANDLE, HANDLE, ACCESS_MASK, PHANDLE, PVOID));
UDECL(NTSTATUS, NtLockProductActivationKeys, (PULONG, PULONG));
UDECL(NTSTATUS, NtLoadDriver, (PUNICODE_STRING));
UDECL(NTSTATUS, NtImpersonateAnonymousToken, (HANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define BADH ((HANDLE)(LONG_PTR)0x7777c)
#define S_INVH XS(0xC0000008)

/* returns -1 unknown, 0 not held, 1 held but disabled, 2 held and enabled */
static int has_priv(ULONG luid)
{
    HANDLE t = NULL; BYTE buf[2048]; ULONG got = 0; int r = 0;
    if (!UN(NtOpenProcessToken) || UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &t) != 0) return -1;
    if (UN(NtQueryInformationToken)(t, 3, buf, sizeof buf, &got) == 0) {
        ULONG n = *(ULONG *)buf; LUID_AND_ATTRIBUTES *p = (LUID_AND_ATTRIBUTES *)(buf + 4);
        for (ULONG i = 0; i < n; i++) if (p[i].Luid.LowPart == luid && p[i].Luid.HighPart == 0) r = (p[i].Attributes & 2) ? 2 : 1; /* 2 = enabled */
    }
    UN(NtClose)(t);
    return r;
}

TEST(alias_pairs)
{
    const char *n[] = { "ListenPort", "ImpersonateClientOfPort", "ReadRequestData", "PrepareEnlistment", "PrePrepareEnlistment",
        "PrepareComplete", "PrePrepareComplete", "PropagationComplete", "PropagationFailed", "ReadOnlyEnlistment",
        "RecoverEnlistment", "RecoverResourceManager", "GetNotificationResourceManager", "LockRegistryKey",
        "GetDevicePowerState", "GetCachedSigningLevel", "LoadKey", "LoadKey2", "LoadKeyEx", "LockProductActivationKeys", "LoadDriver" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa || !pb) { t_skip("missing %s", pa ? b : a); return; }
        CHECKF(pa == pb, "%s and %s differ", a, b);
    }
}

TEST(port_invalid_handle)
{
    REQUIRE(UN(NtListenPort));
    BYTE msg[256]; memset(msg, 0, sizeof msg); *(USHORT *)(msg + 2) = 0x28; /* PORT_MESSAGE TotalLength */ SIZE_T got = 0; BYTE out[16];
    EXPECT_EQ(UN(NtListenPort)(BADH, msg), S_INVH);
    EXPECT_EQ(UN(NtListenPort)(NULL, msg), S_INVH);
    /* a handle of the wrong type (the current process) */
    EXPECT_EQ(UN(NtListenPort)((HANDLE)(LONG_PTR)-1, msg), XS(0xC0000024));
}

TEST(transaction_invalid_handle)
{
    REQUIRE(UN(NtPrepareEnlistment)); REQUIRE(UN(NtPrePrepareEnlistment)); REQUIRE(UN(NtPrepareComplete));
    REQUIRE(UN(NtPrePrepareComplete)); REQUIRE(UN(NtReadOnlyEnlistment)); REQUIRE(UN(NtRecoverEnlistment));
    REQUIRE(UN(NtPropagationComplete)); REQUIRE(UN(NtPropagationFailed)); REQUIRE(UN(NtRecoverResourceManager));
    REQUIRE(UN(NtGetNotificationResourceManager));
    LARGE_INTEGER v; v.QuadPart = 0; BYTE buf[256]; ULONG ret = 0;
    EXPECT_EQ(UN(NtPrepareEnlistment)(BADH, &v), S_INVH);
    EXPECT_EQ(UN(NtPrePrepareEnlistment)(BADH, &v), S_INVH);
    EXPECT_EQ(UN(NtPrepareComplete)(BADH, &v), S_INVH);
    EXPECT_EQ(UN(NtPrePrepareComplete)(BADH, &v), S_INVH);
    EXPECT_EQ(UN(NtReadOnlyEnlistment)(BADH, &v), S_INVH);
    EXPECT_EQ(UN(NtRecoverEnlistment)(BADH, NULL), S_INVH);
    EXPECT_EQ(UN(NtPropagationComplete)(BADH, 0, 0, NULL), S_INVH);
    EXPECT_EQ(UN(NtPropagationFailed)(BADH, 0, 0), S_INVH);
    EXPECT_EQ(UN(NtRecoverResourceManager)(BADH), S_INVH);
    EXPECT_EQ(UN(NtGetNotificationResourceManager)(BADH, buf, sizeof buf, NULL, &ret, 0, 0), S_INVH);
    /* wrong type */
    EXPECT_EQ(UN(NtPrepareEnlistment)((HANDLE)(LONG_PTR)-1, &v), XS(0xC0000024));
    EXPECT_EQ(UN(NtRecoverResourceManager)((HANDLE)(LONG_PTR)-1), XS(0xC0000024));
    EXPECT_EQ(UN(NtReadOnlyEnlistment)((HANDLE)(LONG_PTR)-1, &v), XS(0xC0000024));
}

TEST(registry_and_power_handles)
{
    REQUIRE(UN(NtLockRegistryKey)); REQUIRE(UN(NtGetDevicePowerState)); REQUIRE(UN(NtGetCachedSigningLevel));
    ULONG st = 0xcc, f = 0, lvl = 0, tsz = 0, alg = 0; UCHAR tp[64];
    /* SeLockMemory-class privilege (SeTcb) gate comes before the handle lookup */
    EXPECT_EQ(UN(NtLockRegistryKey)(BADH), XS(0xC0000061));
    EXPECT_EQ(UN(NtGetDevicePowerState)(BADH, &st), S_INVH);
    EXPECT_EQ(UN(NtGetDevicePowerState)(NULL, &st), S_INVH);
    EXPECT_EQ(UN(NtGetCachedSigningLevel)(BADH, &f, &lvl, tp, &tsz, &alg), S_INVH);
    /* the signing level of a system file can be queried; its value depends on the SKU/state, so only the call shape is checked */
    char sys[MAX_PATH]; GetSystemDirectoryA(sys, sizeof sys); lstrcatA(sys, "\\kernel32.dll");
    HANDLE h = CreateFileA(sys, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        tsz = sizeof tp; f = 0xcc; lvl = 0xcc; alg = 0;
        NTSTATUS s = UN(NtGetCachedSigningLevel)(h, &f, &lvl, tp, &tsz, &alg);
        t_note("kernel32 cached signing level: status %08lx flags %lx level %lx", s, f, lvl);
        if (s == 0) { CHECK(lvl <= 0xf); CHECK(tsz <= sizeof tp); }
        CloseHandle(h);
    }
}

TEST(load_key_requires_privilege)
{
    REQUIRE(UN(NtLoadKey)); REQUIRE(UN(NtLoadKey2)); REQUIRE(UN(NtLoadKeyEx));
    int restore = has_priv(18); /* SeRestorePrivilege */
    if (restore < 0) { t_skip("cannot read token privileges"); return; }
    UNICODE_STRING kn, fn; OBJECT_ATTRIBUTES ko, fo;
    WCHAR kp[] = L"\\Registry\\Machine\\NtdllConfNoSuchHive", fp[] = L"\\??\\C:\\NtdllConfNoSuchHive.dat";
    kn.Buffer = kp; kn.Length = kn.MaximumLength = sizeof kp - 2;
    fn.Buffer = fp; fn.Length = fn.MaximumLength = sizeof fp - 2;
    InitializeObjectAttributes(&ko, &kn, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&fo, &fn, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS a = UN(NtLoadKey)(&ko, &fo);
    NTSTATUS b = UN(NtLoadKey2)(&ko, &fo, 0);
    HANDLE kh = NULL;
    NTSTATUS c = UN(NtLoadKeyEx)(&ko, &fo, 0, NULL, NULL, 0, &kh, NULL);
    if (kh) UN(NtClose)(kh);
    t_note("restore privilege held=%d: LoadKey %08lx LoadKey2 %08lx LoadKeyEx %08lx", restore, a, b, c);
    if (restore < 2) {
        /* the privilege must be enabled, merely being held is not enough */
        EXPECT_EQ(a, XS(0xC0000061)); EXPECT_EQ(b, XS(0xC0000061)); EXPECT_EQ(c, XS(0xC0000061));
    } else {
        /* the hive file does not exist, nothing is loaded */
        EXPECT_EQ(a, XS(0xC0000034)); EXPECT_EQ(b, XS(0xC0000034)); EXPECT_EQ(c, XS(0xC0000034));
    }
}

TEST(load_driver_privilege)
{
    REQUIRE(UN(NtLoadDriver));
    UNICODE_STRING n; WCHAR p[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NtdllConfNoSuchDriver";
    n.Buffer = p; n.Length = n.MaximumLength = sizeof p - 2;
    NTSTATUS s = UN(NtLoadDriver)(&n);
    int p10 = has_priv(10); /* SeLoadDriverPrivilege */
    t_note("SeLoadDriver held=%d: %08lx", p10, s);
    if (p10 >= 0 && p10 < 2) EXPECT_EQ(s, XS(0xC0000061));
    else if (p10 == 2) EXPECT_EQ(s, XS(0xC0000034));
}

TEST(lock_product_activation_keys)
{
    REQUIRE(UN(NtLockProductActivationKeys));
    ULONG ver = 0xcc, safe = 0xcc;
    NTSTATUS s = UN(NtLockProductActivationKeys)(&ver, &safe);
    t_note("NtLockProductActivationKeys: %08lx ver=%lx safe=%lx", s, ver, safe);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(safe, 0);   /* not booted in safe mode */
}
