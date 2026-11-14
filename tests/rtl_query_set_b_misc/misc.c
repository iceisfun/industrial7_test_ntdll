/* TEB/PEB per-thread and per-process setters, heap user info, stubs and validation-only paths of
 * system-state setters. */
#include "t.h"
#include <stdlib.h>

UDECL(ULONG, RtlSetProxiedProcessId, (ULONG));
UDECL(UCHAR, RtlSetThreadPlaceholderCompatibilityMode, (UCHAR));
UDECL(UCHAR, RtlSetProcessPlaceholderCompatibilityMode, (UCHAR));
UDECL(PVOID, RtlSetThreadSubProcessTag, (PVOID));
UDECL(NTSTATUS, RtlSetThreadWorkOnBehalfTicket, (PVOID));
UDECL(ULONG, RtlSetCurrentTransaction, (HANDLE));
UDECL(HANDLE, RtlGetCurrentTransaction, (void));
UDECL(NTSTATUS, RtlSetUmsThreadInformation, (PVOID, ULONG, PVOID, ULONG));
UDECL(VOID, RtlSetExtendedFeaturesMask, (PVOID, ULONG64));
UDECL(ULONG64, RtlGetExtendedFeaturesMask, (PVOID));
UDECL(NTSTATUS, RtlSetProcessIsCritical, (BOOLEAN, PBOOLEAN, BOOLEAN));
UDECL(NTSTATUS, RtlSetThreadIsCritical, (BOOLEAN, PBOOLEAN, BOOLEAN));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(PVOID, RtlCreateHeap, (ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID));
UDECL(PVOID, RtlDestroyHeap, (PVOID));
UDECL(PVOID, RtlAllocateHeap, (PVOID, ULONG, SIZE_T));
UDECL(BOOLEAN, RtlFreeHeap, (PVOID, ULONG, PVOID));
UDECL(BOOLEAN, RtlSetUserValueHeap, (PVOID, ULONG, PVOID, PVOID));
UDECL(BOOLEAN, RtlSetUserFlagsHeap, (PVOID, ULONG, PVOID, ULONG, ULONG));
UDECL(BOOLEAN, RtlGetUserInfoHeap, (PVOID, ULONG, PVOID, PVOID *, PULONG));
UDECL(NTSTATUS, RtlSetHeapInformation, (PVOID, ULONG, PVOID, SIZE_T));
UDECL(NTSTATUS, RtlQueryHeapInformation, (PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, RtlSetMemoryStreamSize, (PVOID, ULONGLONG));
UDECL(NTSTATUS, RtlReadMemoryStream, (PVOID, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlSetThreadPoolStartFunc, (PVOID, PVOID));
UDECL(NTSTATUS, RtlSetTimeZoneInformation, (PVOID));
UDECL(NTSTATUS, RtlSetDynamicTimeZoneInformation, (PVOID));
UDECL(NTSTATUS, RtlSetFeatureConfigurations, (PVOID, ULONG, PVOID, ULONG64));
UDECL(NTSTATUS, RtlSetSystemBootStatusEx, (PVOID, ULONG, PVOID));
UDECL(NTSTATUS, RtlSetProtectedPolicy, (const GUID *, ULONG_PTR, PULONG_PTR));
UDECL(NTSTATUS, RtlQueryProtectedPolicy, (const GUID *, PULONG_PTR));

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)

TEST(rtl_set_proxied_process_id) {
    REQUIRE(UN(RtlSetProxiedProcessId));
    ULONG a = UN(RtlSetProxiedProcessId)(0x1234);    /* returns the previous value */
    EXPECT_EQ(UN(RtlSetProxiedProcessId)(0x5678), 0x1234);
    EXPECT_EQ(UN(RtlSetProxiedProcessId)(a), 0x5678);
    EXPECT_EQ(UN(RtlSetProxiedProcessId)(a), a);
}

TEST(rtl_set_placeholder_compat_mode) {
    REQUIRE(UN(RtlSetThreadPlaceholderCompatibilityMode)); REQUIRE(UN(RtlSetProcessPlaceholderCompatibilityMode));
    UCHAR t0 = UN(RtlSetThreadPlaceholderCompatibilityMode)(0);
    for (UCHAR m = 1; m <= 3; m++) {
        EXPECT_EQ(UN(RtlSetThreadPlaceholderCompatibilityMode)(m), m - 1);
    }
    EXPECT_EQ(UN(RtlSetThreadPlaceholderCompatibilityMode)(4), 0xff);      /* invalid: nothing changed */
    EXPECT_EQ(UN(RtlSetThreadPlaceholderCompatibilityMode)(0x80), 0xff);
    EXPECT_EQ(UN(RtlSetThreadPlaceholderCompatibilityMode)(2), 3);          /* mode still 3 */
    UN(RtlSetThreadPlaceholderCompatibilityMode)(t0);
    UCHAR p0 = UN(RtlSetProcessPlaceholderCompatibilityMode)(0);
    for (UCHAR m = 1; m <= 3; m++) EXPECT_EQ(UN(RtlSetProcessPlaceholderCompatibilityMode)(m), m - 1);
    EXPECT_EQ(UN(RtlSetProcessPlaceholderCompatibilityMode)(4), 0xff);
    EXPECT_EQ(UN(RtlSetProcessPlaceholderCompatibilityMode)(0xff), 0xff);
    EXPECT_EQ(UN(RtlSetProcessPlaceholderCompatibilityMode)(1), 3);
    UN(RtlSetProcessPlaceholderCompatibilityMode)(p0);
    /* the thread value is per thread */
    t_note("initial modes thread=%u process=%u", t0, p0);
}

TEST(rtl_set_thread_sub_process_tag) {
    REQUIRE(UN(RtlSetThreadSubProcessTag));
    PVOID a = UN(RtlSetThreadSubProcessTag)((PVOID)0x1111);
    EXPECT_EQ(UN(RtlSetThreadSubProcessTag)((PVOID)0x2222), (PVOID)0x1111);
    EXPECT_EQ(UN(RtlSetThreadSubProcessTag)(NULL), (PVOID)0x2222);
    EXPECT_EQ(UN(RtlSetThreadSubProcessTag)(a), NULL);
    /* it is the same TEB slot kernel32 uses for the service tag: SubProcessTag at TEB+0x1720 */
    EXPECT_EQ(*(PVOID *)((BYTE *)NtCurrentTeb() + 0x1720), a);
}

TEST(rtl_set_thread_work_on_behalf_ticket) {
    REQUIRE(UN(RtlSetThreadWorkOnBehalfTicket));
    EXPECT_EQ(UN(RtlSetThreadWorkOnBehalfTicket)(NULL), ST_INVPARAM);
    ULONGLONG t[2] = {0, 0};
    /* a zero ticket equals the thread's current (zero) ticket: no system call, success */
    EXPECT_EQ(UN(RtlSetThreadWorkOnBehalfTicket)(t), 0);
    ULONGLONG bogus[2] = {0x123456789abcdefull, 0};
    NTSTATUS s = UN(RtlSetThreadWorkOnBehalfTicket)(bogus);
    t_note("bogus ticket status 0x%lx", (unsigned long)s);
    CHECK(s < 0);                                                         /* kernel rejects a ticket it did not issue */
    EXPECT_EQ(UN(RtlSetThreadWorkOnBehalfTicket)(t), 0);
}

TEST(rtl_set_current_transaction) {
    REQUIRE(UN(RtlSetCurrentTransaction)); REQUIRE(UN(RtlGetCurrentTransaction));
    HANDLE orig = UN(RtlGetCurrentTransaction)();
    EXPECT_EQ(UN(RtlSetCurrentTransaction)((HANDLE)0x1234), 1);
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), (HANDLE)0x1234);
    EXPECT_EQ(UN(RtlSetCurrentTransaction)(NULL), 1);
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), NULL);
    EXPECT_EQ(UN(RtlSetCurrentTransaction)((HANDLE)0x40), 1);
    EXPECT_EQ(UN(RtlSetCurrentTransaction)(INVALID_HANDLE_VALUE), 0);     /* -1 is rejected, value kept */
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), (HANDLE)0x40);
    EXPECT_EQ(UN(RtlSetCurrentTransaction)(orig), 1);
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), orig);
}

TEST(rtl_set_ums_thread_information) {
    REQUIRE(UN(RtlSetUmsThreadInformation));
    BYTE *ctx = calloc(1, 0x800); ULONGLONG v = 0x1122334455667788ull;
    EXPECT_EQ(UN(RtlSetUmsThreadInformation)(ctx, 1, &v, 8), 0);
    EXPECT_EQ(*(ULONGLONG *)(ctx + 0x4e8), v);                          /* stored in the UMS thread record */
    ULONGLONG v2 = 0;
    EXPECT_EQ(UN(RtlSetUmsThreadInformation)(ctx, 1, &v2, 4), S(0xC0000004));   /* STATUS_INFO_LENGTH_MISMATCH */
    EXPECT_EQ(UN(RtlSetUmsThreadInformation)(ctx, 1, &v2, 16), S(0xC0000004));
    EXPECT_EQ(*(ULONGLONG *)(ctx + 0x4e8), v);
    EXPECT_EQ(UN(RtlSetUmsThreadInformation)(ctx, 0, &v2, 8), S(0xC00000BB));   /* STATUS_NOT_SUPPORTED */
    EXPECT_EQ(UN(RtlSetUmsThreadInformation)(ctx, 2, &v2, 8), S(0xC00000BB));
    EXPECT_EQ(*(ULONGLONG *)(ctx + 0x4e8), v);
    free(ctx);
}

TEST(rtl_set_extended_features_mask) {
    REQUIRE(UN(RtlSetExtendedFeaturesMask)); REQUIRE(UN(RtlGetExtendedFeaturesMask));
    typedef BOOL (WINAPI *init_fn)(PVOID, DWORD, PVOID *, PDWORD);
    typedef DWORD64 (WINAPI *en_fn)(void);
    init_fn ic = (init_fn)t_proc_in("kernel32.dll", "InitializeContext"); en_fn en = (en_fn)t_proc_in("kernel32.dll", "GetEnabledXStateFeatures");
    if (!ic || !en) { t_skip("InitializeContext/GetEnabledXStateFeatures missing"); return; }
    DWORD len = 0; PVOID ctx = NULL;
    ic(NULL, CONTEXT_FULL | 0x00100040 /* CONTEXT_XSTATE */, NULL, &len);
    if (!len) { t_skip("no XSTATE context on this CPU"); return; }
    BYTE *buf = malloc(len);
    if (!ic(buf, CONTEXT_FULL | 0x00100040, &ctx, &len)) { free(buf); t_skip("InitializeContext failed"); return; }
    PVOID cex = (BYTE *)ctx + sizeof(CONTEXT);                 /* CONTEXT_EX follows CONTEXT */
    ULONG64 enabled = en() & ~3ull;
    /* the mask is limited to enabled features and never carries the x87/SSE bits (0 and 1) */
    UN(RtlSetExtendedFeaturesMask)(cex, ~0ull);
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(cex), enabled);
    UN(RtlSetExtendedFeaturesMask)(cex, 0);
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(cex), 0);
    UN(RtlSetExtendedFeaturesMask)(cex, 3);
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(cex), 0);
    UN(RtlSetExtendedFeaturesMask)(cex, 4);
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(cex), enabled & 4);
    UN(RtlSetExtendedFeaturesMask)(cex, 0x8000000000000004ull);
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(cex), enabled & 0x8000000000000004ull);
    free(buf);
}

TEST(rtl_set_process_thread_is_critical) {
    REQUIRE(UN(RtlSetProcessIsCritical)); REQUIRE(UN(RtlSetThreadIsCritical)); REQUIRE(UN(RtlAdjustPrivilege));
    BOOLEAN old;
    /* NeedBreaks=TRUE requires FLG_ENABLE_SYSTEM_CRIT_BREAKS (0x100000) in NtGlobalFlag, absent by default */
    ULONG gf = *(ULONG *)((BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock + 0xBC);
    if (!(gf & 0x100000)) {
        old = 0x7f; EXPECT_EQ(UN(RtlSetProcessIsCritical)(FALSE, &old, TRUE), S(0xC0000001)); EXPECT_EQ(old, 0);
        old = 0x7f; EXPECT_EQ(UN(RtlSetThreadIsCritical)(FALSE, &old, TRUE), S(0xC0000001)); EXPECT_EQ(old, 0);
        EXPECT_EQ(UN(RtlSetProcessIsCritical)(FALSE, NULL, TRUE), S(0xC0000001));
    } else t_skip("system critical breaks enabled in NtGlobalFlag");
    /* clearing the flag on a non-critical process needs SeDebugPrivilege enabled */
    BOOLEAN was = 0;
    NTSTATUS ps = UN(RtlAdjustPrivilege)(20, TRUE, FALSE, &was);
    old = 0x7f;
    NTSTATUS s = UN(RtlSetProcessIsCritical)(FALSE, &old, FALSE);
    EXPECT_EQ(old, 0);
    NTSTATUS s2 = UN(RtlSetThreadIsCritical)(FALSE, &old, FALSE);
    if (ps >= 0) {
        EXPECT_EQ(s, 0); EXPECT_EQ(s2, 0);
        if (!was) UN(RtlAdjustPrivilege)(20, FALSE, FALSE, &was);
    } else {
        EXPECT_EQ(ps, S(0xC0000061));                           /* privilege not in token (standard user) */
        EXPECT_EQ(s, S(0xC0000061)); EXPECT_EQ(s2, S(0xC0000061));
    }
}

/* ---- heap user info ---- */
TEST(rtl_set_heap_user_value_and_flags) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlSetUserValueHeap));
    REQUIRE(UN(RtlSetUserFlagsHeap)); REQUIRE(UN(RtlGetUserInfoHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlFreeHeap));
    PVOID h = UN(RtlCreateHeap)(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (!h) { t_skip("RtlCreateHeap failed"); return; }
    PVOID p = UN(RtlAllocateHeap)(h, 0x100 /* HEAP_SETTABLE_USER_VALUE */, 64);
    PVOID q = UN(RtlAllocateHeap)(h, 0, 64);                          /* no user-value slot */
    if (!p || !q) { t_skip("alloc failed"); UN(RtlDestroyHeap)(h); return; }
    PVOID val = (PVOID)0xdead; ULONG fl = 0xdead;
    EXPECT_EQ(UN(RtlSetUserValueHeap)(h, 0, p, (PVOID)0x1234abcd), TRUE);
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl), TRUE);
    EXPECT_EQ(val, (PVOID)0x1234abcd);
    t_note("user flags after alloc with 0x100: 0x%lx", fl);
    EXPECT_EQ(fl & 0xe00, 0);
    /* user flag bits 0x200/0x400/0x800 set and clear independently */
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0x400), TRUE);
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl), TRUE); EXPECT_EQ(fl & 0xe00, 0x400);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0x200), TRUE);
    UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl); EXPECT_EQ(fl & 0xe00, 0x600);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0x400, 0x800), TRUE);
    UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl); EXPECT_EQ(fl & 0xe00, 0xa00);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0xe00, 0), TRUE);
    UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl); EXPECT_EQ(fl & 0xe00, 0);
    EXPECT_EQ(val, (PVOID)0x1234abcd);                                 /* value unaffected by flag changes */
    /* bits outside the user-flag range are rejected, state unchanged */
    SetLastError(0);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0x1), FALSE);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0x2, 0), FALSE);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0x1000), FALSE);
    UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl); EXPECT_EQ(fl & 0xe00, 0);
    /* a block allocated without HEAP_SETTABLE_USER_VALUE has nowhere to store the value */
    BOOLEAN r = UN(RtlSetUserValueHeap)(h, 0, q, (PVOID)0x77);
    t_note("user value on plain block: %d", r);
    EXPECT_EQ(r, FALSE);
    UN(RtlFreeHeap)(h, 0, p); UN(RtlFreeHeap)(h, 0, q);
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_set_heap_information) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlSetHeapInformation)); REQUIRE(UN(RtlQueryHeapInformation)); REQUIRE(UN(RtlDestroyHeap));
    PVOID h = UN(RtlCreateHeap)(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (!h) { t_skip("RtlCreateHeap failed"); return; }
    ULONG v;
    /* HeapCompatibilityInformation (0): only value 2 (low-fragmentation heap) may be set */
    v = 2;
    EXPECT_EQ(UN(RtlSetHeapInformation)(h, 0, &v, 3), S(0xC0000023));          /* buffer smaller than ULONG */
    v = 1; EXPECT_EQ(UN(RtlSetHeapInformation)(h, 0, &v, 4), S(0xC0000001));   /* STATUS_UNSUCCESSFUL */
    v = 0; EXPECT_EQ(UN(RtlSetHeapInformation)(h, 0, &v, 4), S(0xC0000001));
    v = 2;
    NTSTATUS s = UN(RtlSetHeapInformation)(h, 0, &v, 4);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        ULONG out = 0; SIZE_T rl = 0;
        EXPECT_EQ(UN(RtlQueryHeapInformation)(h, 0, &out, 4, &rl), 0);
        EXPECT_EQ(out, 2); EXPECT_EQ(rl, 4);
    }
    /* HeapOptimizeResources (3): version 1, size 8, flags 0; flushes caches */
    struct { ULONG Version, Flags; } opt = { 1, 0 };
    EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, &opt, 8), 0);
    EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, NULL, 8), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, &opt, 3), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, &opt, 4), ST_INVPARAM);          /* only the full 8-byte form */
    opt.Version = 2; EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, &opt, 8), ST_INVPARAM);
    opt.Version = 1; opt.Flags = 1; EXPECT_EQ(UN(RtlSetHeapInformation)(h, 3, &opt, 8), ST_INVPARAM);
    UN(RtlDestroyHeap)(h);
}

/* ---- stubs shared with other exports ---- */
TEST(rtl_set_memory_stream_size_stub) {
    REQUIRE(UN(RtlSetMemoryStreamSize));
    EXPECT_EQ(UN(RtlSetMemoryStreamSize)(NULL, 0), S(0x80004001));      /* E_NOTIMPL: the whole IStream shim family */
    EXPECT_EQ(UN(RtlSetMemoryStreamSize)((PVOID)0x1000, 0x10000), S(0x80004001));
    FARPROC a = t_proc("RtlSetMemoryStreamSize"), b = t_proc("RtlReadMemoryStream");
    EXPECT_EQ(a, b);                                                     /* same code, identical RVA */
}

TEST(rtl_set_thread_pool_start_func_stub) {
    REQUIRE(UN(RtlSetThreadPoolStartFunc));
    EXPECT_EQ(UN(RtlSetThreadPoolStartFunc)(NULL, NULL), 0);
    EXPECT_EQ(UN(RtlSetThreadPoolStartFunc)((PVOID)0x1000, (PVOID)0x2000), 0);   /* ignored */
}

/* ---- validation-only paths of system-state setters ---- */
TEST(rtl_set_time_zone_information_validation) {
    REQUIRE(UN(RtlSetTimeZoneInformation)); REQUIRE(UN(RtlSetDynamicTimeZoneInformation));
    /* TIME_ZONE_INFORMATION: names are WCHAR[32] at +4 and +0x58 and must be NUL-terminated; the dynamic form adds
       WCHAR TimeZoneKeyName[128] at +0xac. Unterminated names are refused before anything is written. */
    BYTE tz[0x1b0]; memset(tz, 0, sizeof tz);
    WCHAR *std = (WCHAR *)(tz + 4), *dst = (WCHAR *)(tz + 0x58), *key = (WCHAR *)(tz + 0xac);
    for (int i = 0; i < 32; i++) std[i] = L'S';
    EXPECT_EQ(UN(RtlSetTimeZoneInformation)(tz), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetDynamicTimeZoneInformation)(tz), ST_INVPARAM);
    for (int i = 0; i < 31; i++) { std[i] = L'S'; }
    std[31] = 0;
    for (int i = 0; i < 32; i++) dst[i] = L'D';
    EXPECT_EQ(UN(RtlSetTimeZoneInformation)(tz), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetDynamicTimeZoneInformation)(tz), ST_INVPARAM);
    dst[31] = 0;
    for (int i = 0; i < 128; i++) key[i] = L'K';
    EXPECT_EQ(UN(RtlSetDynamicTimeZoneInformation)(tz), ST_INVPARAM);   /* unterminated key name */
}

TEST(rtl_set_feature_configurations_validation) {
    REQUIRE(UN(RtlSetFeatureConfigurations));
    BYTE dummy[32] = {0};
    EXPECT_EQ(UN(RtlSetFeatureConfigurations)(NULL, 0, dummy, 0x100000000ull), ST_INVPARAM);   /* count must fit 32 bits */
    EXPECT_EQ(UN(RtlSetFeatureConfigurations)(NULL, 0, dummy, 0xffffffffffffffffull), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetFeatureConfigurations)(NULL, 0, dummy, 0x8000000ull), S(0xC0000095));    /* count*32 overflows ULONG */
}

TEST(rtl_set_system_boot_status_ex_validation) {
    REQUIRE(UN(RtlSetSystemBootStatusEx));
    ULONG d = 0;
    EXPECT_EQ(UN(RtlSetSystemBootStatusEx)(&d, 0x40000000, &d), S(0xC0000095));   /* size >= 1 GiB: STATUS_INTEGER_OVERFLOW */
    EXPECT_EQ(UN(RtlSetSystemBootStatusEx)(&d, 0xffffffff, &d), S(0xC0000095));
}

/* ---- protected policy ---- */
TEST(rtl_set_protected_policy) {
    REQUIRE(UN(RtlSetProtectedPolicy)); REQUIRE(UN(RtlQueryProtectedPolicy));
    static const GUID g1 = {0x6b2d4f10, 0x1111, 0x4444, {0x80, 1, 2, 3, 4, 5, 6, 7}};
    static const GUID g2 = {0x6b2d4f10, 0x2222, 0x4444, {0x80, 1, 2, 3, 4, 5, 6, 8}};
    ULONG_PTR old = 0xdead, q = 0xdead;
    EXPECT_EQ(UN(RtlSetProtectedPolicy)(&g1, 0x55, &old), 0);
    EXPECT_EQ(old, 0);                                         /* a new policy starts at zero */
    EXPECT_EQ(UN(RtlQueryProtectedPolicy)(&g1, &q), 0); EXPECT_EQ(q, 0x55);
    EXPECT_EQ(UN(RtlSetProtectedPolicy)(&g1, 0x66, &old), 0); EXPECT_EQ(old, 0x55);
    EXPECT_EQ(UN(RtlSetProtectedPolicy)(&g2, 0x77, NULL), 0);   /* old value pointer optional */
    EXPECT_EQ(UN(RtlQueryProtectedPolicy)(&g2, &q), 0); EXPECT_EQ(q, 0x77);
    EXPECT_EQ(UN(RtlQueryProtectedPolicy)(&g1, &q), 0); EXPECT_EQ(q, 0x66);   /* independent per GUID */
    UN(RtlSetProtectedPolicy)(&g1, 0, NULL); UN(RtlSetProtectedPolicy)(&g2, 0, NULL);
}
